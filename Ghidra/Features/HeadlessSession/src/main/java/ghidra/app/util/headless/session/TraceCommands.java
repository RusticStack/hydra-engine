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
import java.lang.foreign.Arena;
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
 * Java is a router. It reads only the routing fields of a request (the session, the lease
 * capability, the program to symbolize against), checks the writer lease ({@link TraceLeases}),
 * the disk reserve and the protocol, hands the request bytes to the Rust trace engine
 * ({@link TraceNative}) together with a small context object, and sends the reply bytes back as
 * they are ({@link ReadPlane.RawJson}, the direct-reply path): no trace row is ever a Java
 * object. The engine's answers are deterministic, so the same request gives the same bytes to a
 * Python and to a Rust client.
 * <p>
 * No trace request takes a program or project lock, except the one-time walk of the program a
 * symbolizer is built from ({@code trace_open} and {@code trace_resymbolize} with a
 * {@code program}, a shared lock like {@code functions}); after that the engine resolves
 * addresses from an immutable table ({@link TraceSymbols}) with no lock at all. Queries,
 * explain, check, diff and export read committed snapshots and wait for nothing; they are quick
 * lane work, and {@code trace_resymbolize}, {@code trace_export} and a diff over the quick
 * budget run in the long lane ({@link Scheduler#decide}). A {@code cancel} reaches the engine
 * through a flag it polls.
 */
final class TraceCommands {

	/** The twelve commands, in the order PROTOCOL-3.md lists them. */
	static final List<String> COMMANDS = List.of("trace_open", "trace_append", "trace_mark",
		"trace_query", "trace_explain", "trace_diff", "trace_check", "trace_export", "trace_close",
		"trace_list", "trace_info", "trace_resymbolize");

	static boolean isTrace(String cmd) {
		return cmd.startsWith("trace_") && COMMANDS.contains(cmd);
	}

	/** The error codes the engine may answer; anything else becomes {@code failed}. */
	private static final Set<String> ENGINE_CODES = Set.of(SessionException.BAD_REQUEST,
		SessionException.NOT_FOUND, SessionException.NOT_OWNER, SessionException.CONFLICT,
		SessionException.CANCELLED, SessionException.FAILED);

	private static final Pattern SESSION_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
	private static final SecureRandom RANDOM = new SecureRandom();
	/** A diff asking for more events than this runs in the long lane. */
	static final int DEFAULT_QUICK_EVENTS = 250_000;
	/** The room a new session needs before it is created. */
	static final long NEW_SESSION_BYTES = 16L << 20;

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
		Settings.integer("trace.quickEvents", DEFAULT_QUICK_EVENTS);
	}

	/**
	 * The lane of a trace command: quick, except the ones that read or write everything
	 * ({@code trace_resymbolize}, {@code trace_export}) and a {@code trace_diff} whose
	 * {@code budget.events} is above {@code trace.quickEvents} (or that asks for
	 * {@code "background": true}).
	 */
	static Scheduler.Lane laneOf(String cmd, JsonObject req) {
		switch (cmd) {
			case "trace_resymbolize", "trace_export":
				return Scheduler.Lane.LONG;
			case "trace_diff": {
				if (req != null && req.has("background") && req.get("background").isJsonPrimitive() &&
					req.get("background").getAsJsonPrimitive().isBoolean() &&
					req.get("background").getAsBoolean()) {
					return Scheduler.Lane.LONG;
				}
				JsonElement b = req == null ? null : req.get("budget");
				if (b != null && b.isJsonObject() && b.getAsJsonObject().has("events")) {
					try {
						long events = b.getAsJsonObject().get("events").getAsLong();
						if (events > Settings.integer("trace.quickEvents", DEFAULT_QUICK_EVENTS)) {
							return Scheduler.Lane.LONG;
						}
					}
					catch (RuntimeException e) {
						// validate() reports it
					}
				}
				return Scheduler.Lane.QUICK;
			}
			default:
				return Scheduler.Lane.QUICK;
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
		if (Json.has(req, "session")) {
			sessionId(Json.str(req, "session"));
		}
		else if (!cmd.equals("trace_open") && !cmd.equals("trace_list")) {
			throw new SessionException(SessionException.BAD_REQUEST, "missing field: session");
		}
		if (cmd.equals("trace_diff")) {
			sessionId(Json.str(req, "other"));
		}
		if (Json.has(req, "budget")) {
			JsonObject b = Json.obj(req, "budget");
			Json.num(b, "events", 0, 0, Long.MAX_VALUE);
			Json.num(b, "bytes", 0, 0, Long.MAX_VALUE);
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
			case "trace_close", "trace_resymbolize" -> Json.str(req, "cap");
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
		return switch (cmd) {
			case "trace_open" -> open(c, nat, root, req, m);
			case "trace_list" -> list(c, nat, root, req, m);
			case "trace_append", "trace_mark" -> write(c, nat, root, cmd, req, m, false);
			case "trace_close" -> write(c, nat, root, cmd, req, m, true);
			case "trace_resymbolize" -> resymbolize(c, nat, root, req, m);
			default -> read(c, nat, root, cmd, req, m);
		};
	}

	private JsonElement open(Client c, TraceNative nat, Path root, JsonObject req,
			RequestMonitor m) {
		String given = Json.str(req, "session", null);
		boolean create = Json.bool(req, "create", given == null);
		String session = given != null ? given : newId();
		Path dir = root.resolve(session);
		boolean exists = Files.isRegularFile(dir.resolve("session.json"));
		if (create && exists) {
			throw new SessionException(SessionException.CONFLICT,
				"trace session " + session + " already exists; open it without \"create\"",
				Json.of("session", session, "suggest", "open"));
		}
		if (!create && !exists) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no trace session '" + session + "'", Json.of("session", session));
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
		JsonObject lease = Json.of("role", "reader");
		TraceLeases.Grant grant = null;
		JsonObject symbols = null;
		boolean fresh = false;
		try {
			if (write) {
				grant = TraceLeases.acquire(dir, session, c, Json.str(req, "cap", null),
					Json.bool(req, "takeover", false));
				fresh = create;
				lease = leaseJson(grant.lease(), grant);
				if (Json.has(req, "program")) {
					symbols = buildSymbols(c, req, session, dir, m);
				}
			}
			JsonObject ctx = ctx(root, session, lease, symbols == null ? latest(session) : symbols);
			JsonElement out = call(nat, "trace_open", ctx, req, m);
			if (!write) {
				return out;
			}
			return out;
		}
		catch (RuntimeException | Error e) {
			if (fresh && !exists) {
				TraceLeases.forget(session);
				deleteQuietly(dir);
			}
			throw e;
		}
	}

	private JsonElement list(Client c, TraceNative nat, Path root, JsonObject req,
			RequestMonitor m) {
		JsonObject leases = new JsonObject();
		if (Files.isDirectory(root)) {
			try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
				for (Path d : ds) {
					if (Files.isRegularFile(d.resolve("session.json"))) {
						String id = d.getFileName().toString();
						leases.add(id, TraceLeases.describe(id, d));
					}
				}
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED,
					"cannot list the trace root " + root + ": " + e, null, e);
			}
		}
		JsonObject ctx = new JsonObject();
		Json.put(ctx, "root", root.toString());
		ctx.add("leases", leases);
		return call(nat, "trace_list", ctx, req, m);
	}

	/** A command of the writer: {@code trace_append}, {@code trace_mark}, {@code trace_close}. */
	private JsonElement write(Client c, TraceNative nat, Path root, String cmd, JsonObject req,
			RequestMonitor m, boolean closing) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		if (!Files.isRegularFile(dir.resolve("session.json"))) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no trace session '" + session + "'", Json.of("session", session));
		}
		TraceLeases.Lease l = TraceLeases.require(session, c, Json.str(req, "cap"), cmd);
		if (!closing) {
			// a rough bound on what the request adds to the segment, the index and the log
			requireDisk(root, 4L * req.toString().length() + (1L << 20), cmd);
		}
		JsonObject ctx = ctx(root, session, leaseJson(l, null), latest(session));
		JsonElement out = call(nat, cmd, ctx, withoutCap(req), m);
		if (closing) {
			TraceLeases.release(session, c);
			TraceSymbols.drop(session);
		}
		return out;
	}

	private JsonElement resymbolize(Client c, TraceNative nat, Path root, JsonObject req,
			RequestMonitor m) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		if (!Files.isRegularFile(dir.resolve("session.json"))) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no trace session '" + session + "'", Json.of("session", session));
		}
		TraceLeases.Lease l = TraceLeases.require(session, c, Json.str(req, "cap"),
			"trace_resymbolize");
		if (!Json.has(req, "program")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: program (the program to resolve addresses against)");
		}
		requireDisk(root, NEW_SESSION_BYTES, "trace_resymbolize");
		JsonObject symbols = buildSymbols(c, req, session, dir, m);
		JsonObject ctx = ctx(root, session, leaseJson(l, null), symbols);
		JsonElement out = call(nat, "trace_resymbolize", ctx, withoutCap(req), m);
		return out;
	}

	/** A command that only reads: no lease, no capability. */
	private JsonElement read(Client c, TraceNative nat, Path root, String cmd, JsonObject req,
			RequestMonitor m) {
		String session = Json.str(req, "session");
		Path dir = root.resolve(session);
		if (cmd.equals("trace_export")) {
			long index;
			try {
				index = Files.size(dir.resolve("index.db"));
			}
			catch (IOException e) {
				index = 0;
			}
			requireDisk(root, 2 * index + (1L << 20), cmd);
		}
		JsonObject lease = TraceLeases.describe(session, dir);
		lease.addProperty("role", "reader");
		return call(nat, cmd, ctx(root, session, lease, latest(session)), req, m);
	}

	// ---- symbols ---------------------------------------------------------------------------------

	/**
	 * Builds the symbol map of the request's program at the next symbol revision of the session,
	 * under a shared lock of the program (the one walk), and keeps it. Returns the {@code symbols}
	 * block for the engine's context.
	 */
	private JsonObject buildSymbols(Client c, JsonObject req, String session, Path dir,
			RequestMonitor m) {
		Set<String> modules = new LinkedHashSet<>(Json.strings(req, "modules"));
		long moduleBase = addressField(req, "moduleBase");
		long revision = nextRevision(dir, session);
		JsonObject[] block = new JsonObject[1];
		s.access.withProgram(c, req, "trace_symbols", false, false, e -> {
			TraceSymbols.SymbolMap map = TraceSymbols.build(e.program, revision, e.key, modules,
				moduleBase);
			TraceSymbols.put(session, map);
			block[0] = Json.of("revision", revision, "program", map.program, "modification",
				map.modification, "functions", map.functions(), "moduleBase",
				moduleBase == 0 ? null : "0x" + Long.toHexString(moduleBase), "modules",
				new ArrayList<>(map.modules));
			return null;
		});
		recordRevision(dir, block[0]);
		return block[0];
	}

	private static long addressField(JsonObject req, String key) {
		if (!Json.has(req, key)) {
			return 0;
		}
		String t = Json.str(req, key).trim();
		try {
			return t.startsWith("0x") || t.startsWith("0X")
					? Long.parseUnsignedLong(t.substring(2), 16)
					: Long.parseUnsignedLong(t);
		}
		catch (NumberFormatException e) {
			throw new SessionException(SessionException.BAD_REQUEST,
				key + " must be an address: a number or 0x-prefixed hex");
		}
	}

	private static synchronized long nextRevision(Path dir, String session) {
		long last = TraceSymbols.latest(session);
		try {
			Path f = dir.resolve("symbols.json");
			if (Files.isRegularFile(f)) {
				last = Math.max(last, JsonParser.parseString(Files.readString(f))
						.getAsJsonObject().get("lastRevision").getAsLong());
			}
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(TraceCommands.class, "symbols.json of " + session + " unreadable: " + e);
		}
		return last + 1;
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

	private static JsonObject latest(String session) {
		long r = TraceSymbols.latest(session);
		if (r == 0) {
			return null;
		}
		TraceSymbols.SymbolMap m = TraceSymbols.get(session, r);
		return Json.of("revision", r, "program", m == null ? null : m.program, "modification",
			m == null ? null : m.modification, "functions", m == null ? 0 : m.functions());
	}

	// ---- plumbing ----------------------------------------------------------------------------------

	private static JsonObject leaseJson(TraceLeases.Lease l, TraceLeases.Grant g) {
		JsonObject o = Json.of("role", "owner", "producerGen", l.producerGen);
		if (g != null) {
			Json.put(o, "holder", l.ownerLabel);
			if (g.cap() != null) {
				Json.put(o, "cap", g.cap());
			}
			Json.put(o, "reclaimed", g.reclaimed());
			Json.put(o, "tookOver", g.tookOver());
		}
		return o;
	}

	private static JsonObject ctx(Path root, String session, JsonObject lease,
			JsonObject symbols) {
		JsonObject ctx = Json.of("root", root.toString(), "session", session, "producerGen",
			lease.has("producerGen") ? lease.get("producerGen").getAsInt() : 0, "lease", lease);
		if (symbols != null) {
			ctx.add("symbols", symbols);
			ctx.add("symbolRevision", symbols.get("revision"));
		}
		return ctx;
	}

	private static JsonObject withoutCap(JsonObject req) {
		if (!req.has("cap")) {
			return req;
		}
		JsonObject copy = req.deepCopy();
		copy.remove("cap");
		return copy;
	}

	/** One engine call: cancellable, the reply bytes sent as they are. */
	private JsonElement call(TraceNative nat, String cmd, JsonObject ctx, JsonObject req,
			RequestMonitor m) {
		byte[] ctxBytes = ctx.toString().getBytes(StandardCharsets.UTF_8);
		byte[] reqBytes = req.toString().getBytes(StandardCharsets.UTF_8);
		TraceNative.Reply reply;
		try (Arena arena = Arena.ofShared()) {
			MemorySegment flag = arena.allocate(ValueLayout.JAVA_INT);
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
				reply = nat.call(cmd, ctxBytes, reqBytes, flag);
			}
			finally {
				m.removeCancelHook(hook);
			}
		}
		if (reply.status() != 0) {
			throw engineError(reply.bytes(), m);
		}
		return new ReadPlane.RawJson(reply.bytes());
	}

	private static SessionException engineError(byte[] bytes, RequestMonitor m) {
		try {
			JsonObject o = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8))
					.getAsJsonObject();
			String code = Json.str(o, "code", SessionException.FAILED);
			String message = Json.str(o, "message", "the trace engine failed");
			JsonObject details = Json.has(o, "details") && o.get("details").isJsonObject()
					? o.getAsJsonObject("details")
					: null;
			if (SessionException.CANCELLED.equals(code)) {
				return Requests.cancelled(m);
			}
			if (!ENGINE_CODES.contains(code)) {
				details = details == null ? new JsonObject() : details;
				Json.put(details, "engineCode", code);
				code = SessionException.FAILED;
			}
			return new SessionException(code, message, details);
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
