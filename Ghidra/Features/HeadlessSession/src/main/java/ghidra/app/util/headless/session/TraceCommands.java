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
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;

import com.google.gson.*;

import ghidra.util.Msg;

/**
 * The semantic trace commands (PROTOCOL-3.md, "Trace commands"; TRACE-1.md): {@code trace_open},
 * {@code trace_append}, {@code trace_mark}, {@code trace_query}, {@code trace_explain},
 * {@code trace_diff}, {@code trace_check}, {@code trace_export}, {@code trace_close},
 * {@code trace_list}, {@code trace_info} and {@code trace_resymbolize}.
 * <p>
 * Java is a router. The Rust engine ({@link TraceNative}: the {@code hydra-trace} crate's
 * {@code Service}) owns the data and the request and reply shapes; the engine's replies are
 * deterministic JSON, so the same request gives the same bytes to a Python and to a Rust client,
 * and a read's reply goes back as it came ({@link ReadPlane.RawJson}, the direct-reply path).
 * What Java adds is what only the daemon knows:
 * <ul>
 * <li>the <b>writer lease</b> ({@link TraceLeases}): one owner capability per session, checked
 * before a writing command reaches the engine;</li>
 * <li>the <b>symbol table</b> of a program ({@link TraceSymbols}), built under the program's
 * shared lock for {@code trace_open} and {@code trace_resymbolize} and handed to the engine as
 * data;</li>
 * <li>the <b>disk reserve</b>, the <b>lane</b> ({@link #laneOf}), the <b>cancel</b> flag the
 * engine polls, the store root, and protocol 3 only.</li>
 * </ul>
 * No trace request takes a program or project lock except that one walk. Queries, explain, check,
 * diff and info read committed snapshots and wait for nothing.
 */
final class TraceCommands {

	/** The twelve commands, in the order PROTOCOL-3.md lists them. */
	static final List<String> COMMANDS = List.of("trace_open", "trace_append", "trace_mark",
		"trace_query", "trace_explain", "trace_diff", "trace_check", "trace_export", "trace_close",
		"trace_list", "trace_info", "trace_resymbolize", "trace_reprocess", "trace_relations",
		"trace_artifact", "trace_evict", "trace_bundle");

	static boolean isTrace(String cmd) {
		return cmd.startsWith("trace_") && COMMANDS.contains(cmd);
	}

	private static final Pattern SESSION_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
	private static final Pattern EXPORT_NAME = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}");
	private static final SecureRandom RANDOM = new SecureRandom();
	/** Reads the progress cell of a running engine command into its request monitor. */
	private static final java.util.concurrent.ScheduledExecutorService PROGRESS =
		java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "trace-progress");
			t.setDaemon(true);
			return t;
		});
	/** A diff of sessions whose indexes together exceed {@code trace.quickMB} megabytes runs in the long lane. */
	static final int DEFAULT_QUICK_MB = 64;
	/** The room a new session needs before it is created. */
	static final long NEW_SESSION_BYTES = 16L << 20;
	/** Request fields only Java reads; the engine never sees them. */
	private static final Set<String> JAVA_FIELDS = Set.of("create", "mode", "cap", "takeover",
		"program", "project", "modules", "background", "name");

	private final Session s;

	TraceCommands(Session s) {
		this.s = s;
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
	 * The lane of a trace command: quick, except the ones that read or write everything
	 * ({@code trace_resymbolize}, {@code trace_export}) and a {@code trace_diff} that asks for
	 * {@code "background": true} or whose two indexes together are over {@code trace.quickMB}.
	 */
	static Scheduler.Lane laneOf(String cmd, JsonObject req) {
		switch (cmd) {
			case "trace_resymbolize", "trace_export", "trace_reprocess", "trace_evict":
				return Scheduler.Lane.LONG;
			case "trace_relations":
				return req != null && "status".equals(Json.str(req, "op", null))
						? Scheduler.Lane.QUICK
						: Scheduler.Lane.LONG;
			case "trace_diff": {
				if (req == null) {
					return Scheduler.Lane.QUICK;
				}
				if (req.has("background") && req.get("background").isJsonPrimitive() &&
					req.get("background").getAsJsonPrimitive().isBoolean() &&
					req.get("background").getAsBoolean()) {
					return Scheduler.Lane.LONG;
				}
				try {
					Path root = root();
					long bytes = indexSize(root, req.get("a")) + indexSize(root, req.get("b"));
					if (bytes > ((long) Settings.integer("trace.quickMB", DEFAULT_QUICK_MB) << 20)) {
						return Scheduler.Lane.LONG;
					}
				}
				catch (RuntimeException e) {
					// validate() reports a bad request; no root: the command reports it
				}
				return Scheduler.Lane.QUICK;
			}
			default:
				return Scheduler.Lane.QUICK;
		}
	}

	private static long indexSize(Path root, JsonElement id) {
		if (id == null || !id.isJsonPrimitive() ||
			!SESSION_ID.matcher(id.getAsString()).matches()) {
			return 0;
		}
		try {
			return Files.size(root.resolve(id.getAsString()).resolve("index.db"));
		}
		catch (IOException e) {
			return 0;
		}
	}

	/** {@code hydra.trace.root}, else {@code -set trace.root}, else {@code <state>/traces}. */
	static Path root() {
		String p = System.getProperty("hydra.trace.root");
		if (p == null || p.isBlank()) {
			p = Settings.string("trace.root", null);
		}
		if (p == null || p.isBlank()) {
			String state = Json.str(Identity.paths(), "stateDir", null);
			if (state == null) {
				throw new SessionException(SessionException.FAILED,
					"this session has no state directory: set -Dhydra.trace.root or -set trace.root",
					Json.of("reason", "no_trace_root"));
			}
			return Path.of(state, "traces").toAbsolutePath().normalize();
		}
		return Path.of(p).toAbsolutePath().normalize();
	}

	// ---- validation shared by the preflight and the commands -----------------------------------

	private static void validate(String cmd, JsonObject req) {
		if (cmd.equals("trace_diff")) {
			sessionId(Json.str(req, "a"));
			sessionId(Json.str(req, "b"));
		}
		else if (cmd.equals("trace_evict")) {
			if (Json.has(req, "session")) {
				sessionId(Json.str(req, "session"));
			}
			return;
		}
		else if (cmd.equals("trace_bundle")) {
			Json.str(req, "path");
			return;
		}
		else if (Json.has(req, "session")) {
			sessionId(Json.str(req, "session"));
		}
		else if (!cmd.equals("trace_open") && !cmd.equals("trace_list")) {
			throw new SessionException(SessionException.BAD_REQUEST, "missing field: session");
		}
		switch (cmd) {
			case "trace_open" -> {
				Json.bool(req, "create", false);
				Json.bool(req, "takeover", false);
				String mode = Json.str(req, "mode", null);
				if (mode != null && !mode.equals("read") && !mode.equals("write")) {
					throw SessionException.badRequest(true, "mode must be \"read\" or \"write\"",
						"mode", List.of("read", "write"));
				}
			}
			case "trace_append" -> {
				if (!Json.has(req, "events") || !req.get("events").isJsonArray()) {
					throw SessionException.badRequest(true, "events must be an array", "events",
						null);
				}
				Json.str(req, "cap");
			}
			case "trace_mark" -> {
				Json.str(req, "cap");
				Json.str(req, "label");
			}
			case "trace_close", "trace_resymbolize", "trace_reprocess", "trace_artifact" ->
				Json.str(req, "cap");
			case "trace_export" -> {
				if (Json.has(req, "out")) {
					throw SessionException.badRequest(true,
						"an export goes under the session's export folder: give name, not out",
						"out", null);
				}
				exportName(req);
			}
			default -> {
				// nothing more to check before the engine
			}
		}
	}

	static String sessionId(String id) {
		if (!SESSION_ID.matcher(id).matches()) {
			throw SessionException.badRequest(true,
				"a session id is 1 to 64 letters, digits, _ and -", "session", null);
		}
		return id;
	}

	private static String exportName(JsonObject req) {
		String n = Json.str(req, "name", "export");
		if (!EXPORT_NAME.matcher(n).matches()) {
			throw SessionException.badRequest(true,
				"an export name is 1 to 64 of letters, digits, _ . - and does not start with . or -",
				"name", null);
		}
		return n;
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
		validate(cmd, req);
		if (m.isCancelled()) {
			throw Requests.cancelled(m);
		}
		Path root = root();
		nat.useRoot(root);
		byte[] line = m.rawRequest();
		if (line != null) {
			// a raw trace read (TraceFast): the engine gets the client's own line
			return passBytes(nat, cmd, line, m);
		}
		return switch (cmd) {
			case "trace_open" -> open(c, nat, root, req, m);
			case "trace_list" -> list(nat, root, req, m);
			case "trace_info" -> info(nat, root, req, m);
			case "trace_append", "trace_mark", "trace_reprocess", "trace_artifact" ->
				write(c, nat, root, cmd, req, m, false);
			case "trace_relations" -> "status".equals(Json.str(req, "op", null))
					? pass(nat, cmd, engineRequest(req), m)
					: write(c, nat, root, cmd, req, m, false);
			case "trace_evict" -> evict(nat, root, req, m);
			case "trace_close" -> write(c, nat, root, cmd, req, m, true);
			case "trace_resymbolize" -> resymbolize(c, nat, root, req, m);
			case "trace_check" -> check(c, nat, req, m);
			case "trace_export" -> export(nat, root, req, m);
			default -> pass(nat, cmd, engineRequest(req), m);
		};
	}

	private JsonElement open(Client c, TraceNative nat, Path root, JsonObject req,
			RequestMonitor m) {
		String given = Json.str(req, "session", null);
		boolean create = Json.bool(req, "create", given == null);
		String session = given != null ? given : newId();
		Path dir = root.resolve(session);
		// session.json outlives a lost index, which the writer open rebuilds
		boolean exists = Files.isRegularFile(dir.resolve("session.json"));
		if (create && exists) {
			throw new SessionException(SessionException.CONFLICT,
				"trace session " + session + " already exists; open it without \"create\"",
				Json.of("session", session, "suggest", "open"));
		}
		if (!create && !exists) {
			throw notFound(session);
		}
		String mode = Json.str(req, "mode", create ? "write" : "read");
		boolean write = mode.equals("write");
		if (!write && (Json.has(req, "cap") || Json.bool(req, "takeover", false))) {
			throw SessionException.badRequest(true, "cap and takeover need mode \"write\"", "mode",
				List.of("write"));
		}
		if (create) {
			requireDisk(root, NEW_SESSION_BYTES, "a new trace session");
		}
		if (!write) {
			JsonObject out = parse(pass(nat, "trace_info", sessionOnly(session), m));
			JsonObject lease = TraceLeases.describe(session, dir);
			lease.addProperty("role", "reader");
			return Json.of("session", session, "created", false, "revision",
				out.get("revision"), "events", out.get("events"), "lease", lease);
		}
		TraceLeases.Grant grant = TraceLeases.acquire(dir, session, c, Json.str(req, "cap", null),
			Json.bool(req, "takeover", false));
		try {
			TraceSymbols.Table table = Json.has(req, "program")
					? buildSymbols(c, req, session, dir, m)
					: null;
			JsonObject er = engineRequest(req);
			er.addProperty("session", session);
			long quotaMB = Settings.integer("trace.quotaMB", 0);
			if (quotaMB > 0 && !er.has("quota_bytes")) {
				er.addProperty("quota_bytes", quotaMB << 20);
			}
			if (table != null) {
				er.add("symbols", table.symbols());
				er.addProperty("symbol_revision", table.symbolRevision());
			}
			JsonObject out = parse(pass(nat, "trace_open", er, m));
			out.remove("ok");
			out.addProperty("created", create);
			out.add("lease", leaseJson(grant.lease(), grant));
			if (table != null) {
				out.add("symbols", table.summary());
			}
			return out;
		}
		catch (RuntimeException | Error e) {
			if (create) {
				TraceLeases.forget(session);
				engineClose(nat, session);
				deleteQuietly(dir);
			}
			throw e;
		}
	}

	private JsonElement list(TraceNative nat, Path root, JsonObject req, RequestMonitor m) {
		JsonObject out = parse(pass(nat, "trace_list", engineRequest(req), m));
		out.remove("ok");
		if (out.has("sessions") && out.get("sessions").isJsonArray()) {
			for (JsonElement e : out.getAsJsonArray("sessions")) {
				JsonObject o = e.getAsJsonObject();
				String id = o.get("session").getAsString();
				o.add("lease", TraceLeases.describe(id, root.resolve(id)));
			}
			out.addProperty("count", out.getAsJsonArray("sessions").size());
		}
		return out;
	}

	private JsonElement info(TraceNative nat, Path root, JsonObject req, RequestMonitor m) {
		String session = Json.str(req, "session");
		JsonObject out = parse(pass(nat, "trace_info", engineRequest(req), m));
		out.remove("ok");
		out.add("lease", TraceLeases.describe(session, root.resolve(session)));
		long r = lastRevision(root, session);
		if (r > 0) {
			out.addProperty("symbolRevision", "r" + r);
		}
		return out;
	}

	/** A command of the writer: {@code trace_append}, {@code trace_mark}, {@code trace_close}. */
	private JsonElement write(Client c, TraceNative nat, Path root, String cmd, JsonObject req,
			RequestMonitor m, boolean closing) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		if (!Files.isRegularFile(dir.resolve("index.db"))) {
			throw notFound(session);
		}
		TraceLeases.require(session, c, Json.str(req, "cap"), cmd);
		JsonObject er = engineRequest(req);
		if (!closing) {
			// a rough bound on what the request adds to the segment, the index and the log
			requireDisk(root, 4L * er.toString().length() + (1L << 20), cmd);
		}
		JsonElement out = pass(nat, cmd, er, m);
		if (closing) {
			TraceLeases.release(session, c);
		}
		return out;
	}

	private JsonElement resymbolize(Client c, TraceNative nat, Path root, JsonObject req,
			RequestMonitor m) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		if (!Files.isRegularFile(dir.resolve("index.db"))) {
			throw notFound(session);
		}
		TraceLeases.require(session, c, Json.str(req, "cap"), "trace_resymbolize");
		if (!Json.has(req, "program")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: program (the program to resolve addresses against)");
		}
		requireDisk(root, NEW_SESSION_BYTES, "trace_resymbolize");
		TraceSymbols.Table table = buildSymbols(c, req, session, dir, m);
		JsonObject er = Json.of("session", session, "symbol_revision", table.symbolRevision());
		er.add("symbols", table.symbols());
		JsonObject out = parse(pass(nat, "trace_resymbolize", er, m));
		out.remove("ok");
		out.add("symbols", table.summary());
		return out;
	}

	/**
	 * {@code trace_check} persists its results into the session through the writer, so only the
	 * lease holder may ask for that; anyone else gets the verdicts without them being stored.
	 */
	private JsonElement check(Client c, TraceNative nat, JsonObject req, RequestMonitor m) {
		String session = Json.str(req, "session");
		JsonObject er = engineRequest(req);
		if (Json.bool(req, "persist", true) && Json.has(req, "cap")) {
			TraceLeases.require(session, c, Json.str(req, "cap"), "trace_check with persist");
		}
		else {
			er.addProperty("persist", false);
		}
		return pass(nat, "trace_check", er, m);
	}

	/** Evicts closed sessions (a tombstone each); the leases of the evicted ones are dropped. */
	private JsonElement evict(TraceNative nat, Path root, JsonObject req, RequestMonitor m) {
		String session = Json.str(req, "session", null);
		if (session != null && TraceLeases.describe(session, root.resolve(session))
				.has("holder")) {
			throw new SessionException(SessionException.BUSY,
				"session " + session + " has a writer lease: close it first",
				Json.of("reason", "busy", "session", session));
		}
		JsonElement out = pass(nat, "trace_evict", engineRequest(req), m);
		JsonObject o = parse(out);
		if (o.has("evicted") && o.get("evicted").isJsonArray()) {
			for (JsonElement e : o.getAsJsonArray("evicted")) {
				TraceLeases.forget(e.getAsJsonObject().get("session").getAsString());
			}
		}
		return out;
	}

	private JsonElement export(TraceNative nat, Path root, JsonObject req, RequestMonitor m) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		long index;
		try {
			index = Files.size(dir.resolve("index.db"));
		}
		catch (IOException e) {
			throw notFound(session);
		}
		requireDisk(root, 2 * index + (1L << 20), "trace_export");
		JsonObject er = engineRequest(req);
		er.addProperty("out", dir.resolve("export").resolve(exportName(req)).toString());
		return pass(nat, "trace_export", er, m);
	}

	// ---- symbols ---------------------------------------------------------------------------------

	/**
	 * Builds the symbol table of the request's program at the next symbol revision of the
	 * session, under a shared lock of the program (the one walk), and records the revision.
	 */
	private TraceSymbols.Table buildSymbols(Client c, JsonObject req, String session, Path dir,
			RequestMonitor m) {
		List<String> modules = Json.strings(req, "modules");
		long revision = lastRevision(dir.getParent(), session) + 1;
		TraceSymbols.Table[] built = new TraceSymbols.Table[1];
		s.access.withProgram(c, req, "trace_symbols", false, false, e -> {
			String name = e.key.contains("/") ? e.key.substring(e.key.lastIndexOf('/') + 1)
					: e.key;
			built[0] = TraceSymbols.build(e.program, revision, e.key, modules, name);
			return null;
		});
		recordRevision(dir, built[0].summary());
		return built[0];
	}

	private static long lastRevision(Path root, String session) {
		try {
			Path f = root.resolve(session).resolve("symbols.json");
			if (Files.isRegularFile(f)) {
				return JsonParser.parseString(Files.readString(f)).getAsJsonObject()
						.get("lastRevision").getAsLong();
			}
		}
		catch (IOException | RuntimeException e) {
			// none recorded
		}
		return 0;
	}

	private static synchronized void recordRevision(Path dir, JsonObject block) {
		try {
			Path f = dir.resolve("symbols.json");
			JsonObject o = Files.isRegularFile(f)
					? JsonParser.parseString(Files.readString(f)).getAsJsonObject()
					: Json.of("lastRevision", 0, "revisions", new JsonArray());
			o.addProperty("lastRevision", block.get("revision").getAsLong());
			o.getAsJsonArray("revisions").add(block);
			Path tmp = dir.resolve("symbols.json.tmp");
			Files.writeString(tmp, Json.GSON.toJson(o));
			Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING);
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(TraceCommands.class, "cannot record symbol revision in " + dir + ": " + e);
		}
	}

	// ---- plumbing ----------------------------------------------------------------------------------

	private static JsonObject leaseJson(TraceLeases.Lease l, TraceLeases.Grant g) {
		JsonObject o = Json.of("role", "owner", "producerGen", l.producerGen);
		Json.put(o, "holder", l.ownerLabel);
		if (g.cap() != null) {
			Json.put(o, "cap", g.cap());
		}
		Json.put(o, "reclaimed", g.reclaimed());
		Json.put(o, "tookOver", g.tookOver());
		return o;
	}

	/** The request as the engine takes it: without the fields only Java reads. */
	private static JsonObject engineRequest(JsonObject req) {
		JsonObject copy = new JsonObject();
		for (Map.Entry<String, JsonElement> e : req.entrySet()) {
			if (!JAVA_FIELDS.contains(e.getKey())) {
				copy.add(e.getKey(), e.getValue());
			}
		}
		return copy;
	}

	private static JsonObject sessionOnly(String session) {
		return Json.of("session", session);
	}

	private static JsonObject parse(JsonElement raw) {
		return JsonParser.parseString(
			new String(((ReadPlane.RawJson) raw).bytes, StandardCharsets.UTF_8))
				.getAsJsonObject();
	}

	private static SessionException notFound(String session) {
		return new SessionException(SessionException.NOT_FOUND,
			"no trace session '" + session + "'", Json.of("session", session));
	}

	private void engineClose(TraceNative nat, String session) {
		try {
			nat.call("trace_close",
				sessionOnly(session).toString().getBytes(StandardCharsets.UTF_8), null);
		}
		catch (RuntimeException e) {
			// the engine had not opened it
		}
	}

	/** One engine call: cancellable; success replies are sent as they are. */
	private JsonElement pass(TraceNative nat, String cmd, JsonObject req, RequestMonitor m) {
		return passBytes(nat, cmd, req.toString().getBytes(StandardCharsets.UTF_8), m);
	}

	/**
	 * One engine call from the request's bytes: the cancel flag and the progress cell are recycled
	 * native cells (closing a shared arena per call is a handshake with every thread of the VM),
	 * and progress is read by one poller for all running calls, not a scheduled task per call.
	 */
	private JsonElement passBytes(TraceNative nat, String cmd, byte[] reqBytes,
			RequestMonitor m) {
		byte[] reply;
		MemorySegment cells = TraceNative.takeCells();
		MemorySegment flag = cells.asSlice(0, 4);
		MemorySegment cell = cells.asSlice(8, 16);
		Progress watch = nat.reportsProgress() ? Progress.watch(cell, m) : null;
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
			reply = nat.call(cmd, reqBytes, flag, cell);
		}
		finally {
			m.removeCancelHook(hook);
			if (watch != null) {
				watch.stop();
			}
			TraceNative.giveCells(cells);
		}
		if (isError(reply)) {
			throw engineError(cmd, reply, m);
		}
		return new ReadPlane.RawJson(reply);
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

	/** The engine writes keys sorted, so an error reply starts with {@code {"error":}. */
	private static boolean isError(byte[] reply) {
		byte[] p = "{\"error\":".getBytes(StandardCharsets.UTF_8);
		if (reply.length < p.length) {
			return false;
		}
		for (int i = 0; i < p.length; i++) {
			if (reply[i] != p[i]) {
				return false;
			}
		}
		return true;
	}

	private static SessionException engineError(String cmd, byte[] bytes, RequestMonitor m) {
		try {
			JsonObject e = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8))
					.getAsJsonObject().getAsJsonObject("error");
			String code = Json.str(e, "code", "internal");
			String message = Json.str(e, "message", "the trace engine failed");
			switch (code) {
				case "cancelled":
					return Requests.cancelled(m);
				case "refused":
					if (message.contains("no session")) {
						return new SessionException(SessionException.NOT_FOUND, message);
					}
					return new SessionException(SessionException.BAD_REQUEST, message,
						Json.of("engineCode", code));
				case "bad_request", "too_large":
					return new SessionException(SessionException.BAD_REQUEST, message,
						Json.of("engineCode", code));
				case "busy":
					return new SessionException(SessionException.BUSY, message,
						Json.of("engineCode", code, "reason", "busy"));
				case "not_open":
					return new SessionException(SessionException.CONFLICT, message,
						Json.of("engineCode", code, "suggest", "trace_open"));
				default:
					return new SessionException(SessionException.FAILED, message,
						Json.of("engineCode", code, "command", cmd));
			}
		}
		catch (RuntimeException e) {
			return new SessionException(SessionException.FAILED,
				"the trace engine gave an unreadable error", Json.of("reason", "engine_reply"), e);
		}
	}

	/** The disk-reserve rule of the governor, for the trace store's volume. */
	private static void requireDisk(Path root, long estimate, String what) {
		try {
			Files.createDirectories(root);
			Governor.requireDisk(new File(root.toString()), estimate, what);
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED,
				"cannot check the free space for " + what + " under " + root + ": " + e,
				Json.of("reason", "disk_check"), e);
		}
	}

	private static String newId() {
		byte[] b = new byte[6];
		RANDOM.nextBytes(b);
		return "tr_" + HexFormat.of().formatHex(b);
	}

	private static void deleteQuietly(Path dir) {
		try (var walk = Files.walk(dir)) {
			walk.sorted(Comparator.reverseOrder()).forEach(p -> {
				try {
					Files.deleteIfExists(p);
				}
				catch (IOException e) {
					// left for the next start
				}
			});
		}
		catch (IOException e) {
			// nothing to delete
		}
	}
}
