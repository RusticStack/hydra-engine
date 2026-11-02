/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.headless.session;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.*;

/**
 * The semantic trace commands (PROTOCOL-3.md, "Trace commands"; TRACE-1.md): {@code trace_open},
 * {@code trace_append}, {@code trace_mark}, {@code trace_query}, {@code trace_explain},
 * {@code trace_diff}, {@code trace_check}, {@code trace_export}, {@code trace_close},
 * {@code trace_list}, {@code trace_info}, {@code trace_resymbolize} and the rest of
 * {@link #COMMANDS}.
 * <p>
 * Java is a pump. The Rust engine ({@link TraceNative}: the {@code hydra-trace} crate's router,
 * {@code hydra_trace_route}) owns the data, the request and reply shapes and everything the daemon
 * used to decide around a command: the validation of the fields the daemon reads, the lane
 * ({@code trace_diff} over {@code trace.quickMB}, the long commands), the <b>writer lease</b>
 * (one owner capability per session), the request the engine sees, the disk-room decision, the
 * wrapping of the replies that carry the lease and the symbol revision, and the cancel flag and
 * progress cell of the call. The reply goes back as it came ({@link ReadPlane.RawJson}).
 * What only the daemon can do stays here:
 * <ul>
 * <li>the <b>symbol table</b> of a program ({@link TraceSymbols}), built under the program's
 * shared lock when the router asks for it ({@code trace_open} or {@code trace_resymbolize} with a
 * {@code program});</li>
 * <li>the <b>disk reserve</b>: the router is told how much room the store's volume has above the
 * reserve and asks for the exact check ({@link Governor#requireDisk}) only when that is not
 * enough;</li>
 * <li>the store root, protocol 3 only, the request monitor (cancel, progress).</li>
 * </ul>
 * No trace request takes a program or project lock except that one walk. Queries, explain, check,
 * diff and info read committed snapshots and wait for nothing.
 */
final class TraceCommands {

	/** The commands, in the order PROTOCOL-3.md lists them. */
	static final List<String> COMMANDS = List.of("trace_open", "trace_append", "trace_mark",
		"trace_query", "trace_explain", "trace_diff", "trace_check", "trace_export", "trace_close",
		"trace_list", "trace_info", "trace_resymbolize", "trace_reprocess", "trace_relations",
		"trace_artifact", "trace_evict", "trace_bundle");

	static boolean isTrace(String cmd) {
		return cmd.startsWith("trace_") && COMMANDS.contains(cmd);
	}

	/** Reads the progress cell of a running engine command into its request monitor. */
	private static final java.util.concurrent.ScheduledExecutorService PROGRESS =
		java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "trace-progress");
			t.setDaemon(true);
			return t;
		});
	/** A diff of sessions whose indexes together exceed {@code trace.quickMB} megabytes runs in the long lane. */
	static final int DEFAULT_QUICK_MB = 64;
	/** How long a measure of the store volume's free room is trusted. */
	private static final long HEADROOM_TTL_NANOS = 20_000_000L;
	/** The commands that can need disk room (the others are given no measure). */
	private static final java.util.Set<String> WRITES = java.util.Set.of("trace_open",
		"trace_append", "trace_mark", "trace_reprocess", "trace_artifact", "trace_relations",
		"trace_resymbolize", "trace_export");

	private record Headroom(long at, long bytes) {
	}

	private static volatile Headroom headroom = new Headroom(0, Long.MAX_VALUE);
	private static volatile Path rootPath;

	private final Session s;

	TraceCommands(Session s) {
		this.s = s;
		TraceNative.builder = this::symbolPayload;
		if (TraceNative.get() != null) {
			Advertised.capability("trace", 1);
		}
		for (String c : COMMANDS) {
			Preflight.register(c, TraceCommands::validate);
		}
	}

	// ---- start-up settings, lanes, the store root ---------------------------------------------

	/** A usage error at start-up for a bad {@code trace.*} setting. */
	static void validateSettings() {
		Settings.bool(TraceNative.SETTING, true);
		Settings.integer("trace.quickMB", DEFAULT_QUICK_MB);
		Settings.integer("trace.quotaMB", 0);
	}

	/**
	 * The lane of a trace command, as the router decides it: quick, except the ones that read or
	 * write everything ({@code trace_resymbolize}, {@code trace_export}, ...) and a
	 * {@code trace_diff} that asks for {@code "background": true} or whose two indexes together are
	 * over {@code trace.quickMB}.
	 */
	static Scheduler.Lane laneOf(String cmd, JsonObject req) {
		TraceNative nat = TraceNative.get();
		if (nat == null) {
			return Scheduler.Lane.QUICK; // the command itself answers native_missing
		}
		try {
			nat.useRoot(root()); // a diff's lane reads the indexes under the store root
		}
		catch (RuntimeException e) {
			// no root: the command reports it
		}
		return nat.laneOf(cmd, req) == 1 ? Scheduler.Lane.LONG : Scheduler.Lane.QUICK;
	}

	/** {@code hydra.trace.root}, else {@code -set trace.root}, else {@code <state>/traces}. */
	static Path root() {
		Path cached = rootPath;
		if (cached != null) {
			return cached;
		}
		String p = System.getProperty("hydra.trace.root");
		if (p == null || p.isBlank()) {
			p = Settings.string("trace.root", null);
		}
		Path r;
		if (p == null || p.isBlank()) {
			String state = Json.str(Identity.paths(), "stateDir", null);
			if (state == null) {
				throw new SessionException(SessionException.FAILED,
					"this session has no state directory: set -Dhydra.trace.root or -set trace.root",
					Json.of("reason", "no_trace_root"));
			}
			r = Path.of(state, "traces").toAbsolutePath().normalize();
		}
		else {
			r = Path.of(p).toAbsolutePath().normalize();
		}
		rootPath = r;
		return r;
	}

	/** The preflight of a queueing request: the router's own checks, before the wait. */
	private static void validate(String cmd, JsonObject req) {
		TraceNative nat = TraceNative.get();
		if (nat == null) {
			return;
		}
		byte[] err = nat.check(cmd, req.toString().getBytes(StandardCharsets.UTF_8));
		if (err != null) {
			throw routerError(err, null);
		}
	}

	// ---- the commands -----------------------------------------------------------------------------

	JsonElement run(Client c, String cmd, JsonObject req, RequestMonitor m) {
		if (!c.v3()) {
			throw new SessionException(SessionException.UNKNOWN_COMMAND,
				"trace commands need protocol 3: send hello with \"protocol\":3 first");
		}
		TraceNative nat = TraceNative.get();
		if (nat == null) {
			throw new SessionException(SessionException.FAILED,
				"the trace engine is not available: hydra_native lacks the trace ABI, or " +
					"-set trace=false",
				Json.of("reason", "native_missing"));
		}
		if (m.isCancelled()) {
			throw Requests.cancelled(m);
		}
		Path root = root();
		nat.useRoot(root);
		byte[] line = m.rawRequest();
		if (line == null) {
			line = req.toString().getBytes(StandardCharsets.UTF_8);
		}
		TraceNative.SymbolJob job = req.has("program") ? new TraceNative.SymbolJob(c, req, m) : null;
		long room = WRITES.contains(cmd) ? headroom(root) : Long.MAX_VALUE;
		while (true) {
			TraceNative.Routed r = routeOnce(nat, c, cmd, line, room, m, job);
			switch (r.kind()) {
				case TraceNative.ROUTE_REPLY:
					return new ReadPlane.RawJson(r.bytes());
				case TraceNative.ROUTE_ERROR:
					throw routerError(r.bytes(), m);
				case TraceNative.ROUTE_DISK: {
					JsonObject d = parse(r.bytes());
					requireDisk(root, d.get("estimate").getAsLong(), d.get("what").getAsString());
					room = Long.MAX_VALUE; // the exact check passed: the measure was stale
					break;
				}
				default: {
					Throwable t = job == null ? null : job.error;
					if (t instanceof RuntimeException e) {
						throw e;
					}
					if (t instanceof Error e) {
						throw e;
					}
					throw new SessionException(SessionException.FAILED,
						"the function table of the program could not be built",
						Json.of("reason", "symbols"), t);
				}
			}
		}
	}

	/**
	 * One router call: the cancel flag and the progress cell are recycled native cells (closing a
	 * shared arena per call is a handshake with every thread of the VM), and progress of the
	 * commands that can be long is read by one poller for all running calls.
	 */
	private TraceNative.Routed routeOnce(TraceNative nat, Client c, String cmd, byte[] line,
			long room, RequestMonitor m, TraceNative.SymbolJob job) {
		MemorySegment cells = TraceNative.takeCells();
		MemorySegment flag = cells.asSlice(0, 4);
		MemorySegment cell = cells.asSlice(8, 16);
		Progress watch = nat.alwaysQuick(cmd) ? null : Progress.watch(cell, m);
		Runnable hook = () -> {
			try {
				flag.set(ValueLayout.JAVA_INT, 0, 1);
			}
			catch (RuntimeException e) {
				// the call already ended
			}
		};
		m.addCancelHook(hook);
		try {
			return nat.route(c, cmd, line, room, flag, cell, job);
		}
		finally {
			m.removeCancelHook(hook);
			if (watch != null) {
				watch.stop();
			}
			TraceNative.giveCells(cells);
		}
	}

	// ---- symbols ---------------------------------------------------------------------------------

	/**
	 * The function table of the request's program at {@code revision}, built under a shared lock
	 * of the program (the one walk), as the router's payload {@code {"symbols":..,"summary":..}}.
	 */
	private byte[] symbolPayload(TraceNative.SymbolJob job, String session, long revision) {
		List<String> modules = Json.strings(job.req, "modules");
		AtomicReference<TraceSymbols.Table> built = new AtomicReference<>();
		s.access.withProgram(job.client, job.req, "trace_symbols", false, false, e -> {
			String name = e.key.contains("/") ? e.key.substring(e.key.lastIndexOf('/') + 1)
					: e.key;
			built.set(TraceSymbols.build(e.program, revision, e.key, modules, name));
			return null;
		});
		TraceSymbols.Table t = built.get();
		JsonObject payload = new JsonObject();
		payload.add("symbols", t.symbols());
		payload.add("summary", t.summary());
		return Json.GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
	}

	// ---- plumbing ----------------------------------------------------------------------------------

	private static JsonObject parse(byte[] bytes) {
		return JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8)).getAsJsonObject();
	}

	/** The refusal the router describes ({@code code}, {@code message}, {@code details}). */
	private static SessionException routerError(byte[] bytes, RequestMonitor m) {
		try {
			JsonObject e = parse(bytes);
			String code = Json.str(e, "code", "failed");
			if (code.equals("cancelled") && m != null) {
				return Requests.cancelled(m);
			}
			JsonElement d = e.get("details");
			return new SessionException(code, Json.str(e, "message", "the trace engine failed"),
				d != null && d.isJsonObject() ? d.getAsJsonObject() : null);
		}
		catch (RuntimeException ex) {
			return new SessionException(SessionException.FAILED,
				"the trace engine gave an unreadable error", Json.of("reason", "engine_reply"), ex);
		}
	}

	/**
	 * The room the store's volume has above the reserve of the governor (bytes; may be negative),
	 * trusted for a few milliseconds. The router compares what a request needs with it; the exact
	 * check, with its error, is {@link Governor#requireDisk}.
	 */
	private static long headroom(Path root) {
		Headroom h = headroom;
		long now = System.nanoTime();
		if (now - h.at < HEADROOM_TTL_NANOS) {
			return h.bytes;
		}
		long bytes;
		try {
			bytes = Governor.diskHeadroom(new File(root.toString()));
		}
		catch (IOException | RuntimeException e) {
			bytes = Long.MAX_VALUE; // the router's own check names the problem
		}
		headroom = new Headroom(now, bytes);
		return bytes;
	}

	/** The disk-reserve rule of the governor, for the trace store's volume. */
	private static void requireDisk(Path root, long estimate, String what) {
		try {
			java.nio.file.Files.createDirectories(root);
			Governor.requireDisk(new File(root.toString()), estimate, what);
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED,
				"cannot check the free space for " + what + " under " + root + ": " + e,
				Json.of("reason", "disk_check"), e);
		}
		finally {
			headroom = new Headroom(0, Long.MAX_VALUE);
		}
	}

	/**
	 * Copies the progress cells of the running engine calls into their request monitors (one
	 * poller, every 100 ms; a call is first read 50 ms after it started, as the per-call task did).
	 */
	private static final class Progress {
		private static final java.util.Set<Progress> ACTIVE =
			java.util.concurrent.ConcurrentHashMap.newKeySet();
		private static boolean polling;

		private final MemorySegment cell;
		private final RequestMonitor m;
		private final long since = System.nanoTime();

		private Progress(MemorySegment cell, RequestMonitor m) {
			this.cell = cell;
			this.m = m;
		}

		static Progress watch(MemorySegment cell, RequestMonitor m) {
			Progress p = new Progress(cell, m);
			ACTIVE.add(p);
			synchronized (Progress.class) {
				if (!polling) {
					polling = true;
					PROGRESS.scheduleWithFixedDelay(Progress::poll, 50, 100,
						java.util.concurrent.TimeUnit.MILLISECONDS);
				}
			}
			return p;
		}

		void stop() {
			ACTIVE.remove(this);
		}

		private static void poll() {
			long now = System.nanoTime();
			for (Progress p : ACTIVE) {
				if (now - p.since < 40_000_000L) {
					continue;
				}
				try {
					long total = p.cell.get(ValueLayout.JAVA_LONG, 8);
					long done = p.cell.get(ValueLayout.JAVA_LONG, 0);
					if (total > 0 && ACTIVE.contains(p)) {
						p.m.setMaximum(total);
						p.m.setProgress(done);
					}
				}
				catch (RuntimeException e) {
					// the call already ended
				}
			}
		}
	}
}
