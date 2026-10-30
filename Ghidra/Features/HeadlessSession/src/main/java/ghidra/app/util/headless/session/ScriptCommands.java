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

import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Addresses.address;
import static ghidra.app.util.headless.session.EditCommands.journal;
import static ghidra.app.util.headless.session.Requests.DEFAULT_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.MAX_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * {@code script}: runs a GhidraScript against a program or a project.
 * <p>
 * Protocol 3 (package E4, PROTOCOL-3.md 3.4 and 3.6) adds, on a protocol 3 connection only: the
 * request fields {@code isolation} ({@code shared}, {@code exclusive}, {@code private}) and
 * {@code scriptSha256}; the reply fields {@code isolation}, {@code lane}, {@code laneNote},
 * {@code attemptedChanges}, {@code attemptedChangesCount}, {@code basedOn} and
 * {@code unsavedIgnored}; and the runaway bounds of {@link Runaway}. A protocol 2 request sees
 * none of it.
 */
final class ScriptCommands {

	private final Session s;

	private static boolean registered;

	ScriptCommands(Session s) {
		this.s = s;
		// the names are declared by Advertised; a client uses a field only if it is present
		// version 2 (E7): isolation:"worker", the killable script worker
		Advertised.capability("scriptIsolation", 2);
		Advertised.capability("scriptSha256", 1);
		Advertised.capability("attemptedChanges", 1);
		synchronized (ScriptCommands.class) {
			if (!registered) {
				registered = true;
				// the request validation the command itself runs (3.5): one method, two callers
				Preflight.register("script", ScriptCommands::validate);
				// H4: the resolved-script cache's figures (an added member of health only)
				Health.contribute("scriptCache", ScriptClassCache::describe);
			}
		}
	}

	private static final Object SCRIPT_COMPILE = new Object();

	/** The values of the protocol 3 request field {@code isolation} (3.4, 3.6). */
	static final List<String> ISOLATIONS = List.of("shared", "exclusive", "private", "worker");

	// ---- the request fields -------------------------------------------------------------------

	/**
	 * The protocol 3 fields of a {@code script} request that have a closed or a fixed shape:
	 * {@code isolation} and {@code scriptSha256}. Run by the command and, through
	 * {@link Preflight}, by the scheduler before a request waits. The {@code lane} hint is E3a's:
	 * a hint that is not honoured is answered with {@code laneNote} and not refused. Throws
	 * {@code bad_request} with {@code details:{field, allowed[]}}.
	 */
	static void validate(String cmd, JsonObject req) {
		String iso = isolationOf(req);
		shaOf(req);
		if ("worker".equals(iso) && Json.bool(req, "save", false)) {
			// nothing a worker does reaches the view, so a save has nothing to save: refused
			// rather than dropped (the owner saves the view itself, before the worker starts)
			throw SessionException.badRequest(true,
				"save cannot be combined with isolation \"worker\": the worker runs on a " +
					"disposable clone and nothing of the run reaches the program",
				"save", null);
		}
	}

	/** The requested {@code isolation}, or null when the request did not name one. */
	static String isolationOf(JsonObject req) {
		JsonElement e = req.get("isolation");
		if (e == null || e.isJsonNull()) {
			return null;
		}
		String v = e.isJsonPrimitive() && e.getAsJsonPrimitive().isString() ? e.getAsString() : null;
		if (v == null || !ISOLATIONS.contains(v)) {
			throw SessionException.badRequest(true, "isolation must be one of " + ISOLATIONS,
				"isolation", ISOLATIONS);
		}
		return v;
	}

	/** The requested {@code scriptSha256} (lower case), or null when absent. */
	private static String shaOf(JsonObject req) {
		JsonElement e = req.get("scriptSha256");
		if (e == null || e.isJsonNull()) {
			return null;
		}
		String v = e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()
				? e.getAsString().strip().toLowerCase(Locale.ROOT)
				: null;
		if (v == null || !v.matches("[0-9a-f]{64}")) {
			throw SessionException.badRequest(true,
				"scriptSha256 must be the SHA-256 of the script file as 64 hex digits",
				"scriptSha256", null);
		}
		return v;
	}

	private record Hashed(long size, long mtime, String sha) {
	}

	/** SHA-256 of a script file by path, size and modification time (3.4). */
	private static final Map<String, Hashed> SHA_CACHE = new ConcurrentHashMap<>();

	/** The SHA-256 of the resolved script file, hex. */
	static String sha256(ResourceFile src) {
		String key = src.getAbsolutePath();
		long size = src.length();
		long mtime = src.lastModified();
		Hashed h = SHA_CACHE.get(key);
		if (h != null && h.size == size && h.mtime == mtime) {
			return h.sha;
		}
		try (InputStream in = src.getInputStream()) {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] buf = new byte[65536];
			int n;
			while ((n = in.read(buf)) > 0) {
				md.update(buf, 0, n);
			}
			String sha = HexFormat.of().formatHex(md.digest());
			if (SHA_CACHE.size() > 512) {
				SHA_CACHE.clear();
			}
			SHA_CACHE.put(key, new Hashed(size, mtime, sha));
			return sha;
		}
		catch (IOException | NoSuchAlgorithmException ex) {
			throw new SessionException(SessionException.FAILED,
				"cannot hash script " + src.getName() + ": " + ex.getMessage(), null, ex);
		}
	}

	/**
	 * Protocol 3: refuses a script file that is not the one the client pinned
	 * ({@code scriptSha256}), whatever program the script runs on. Also run for a script on an
	 * overlay, where {@code isolation} is validated but has no other effect (an overlay is already
	 * its own throwaway program: it is never shared or exclusive, and the reply says
	 * {@code isolation:"overlay"}, a value outside the request enum).
	 */
	static void checkSha(JsonObject req, ResourceFile src) {
		String want = shaOf(req);
		if (want == null) {
			return;
		}
		String actual = sha256(src);
		if (!actual.equals(want)) {
			throw new SessionException(SessionException.SCRIPT_CHANGED,
				"script " + src.getName() + " is not the file the request pinned (SHA-256 " +
					actual + ", expected " + want + ")",
				Json.of("expected", want, "actual", actual, "script", src.getAbsolutePath()));
		}
	}

	// ---- the command --------------------------------------------------------------------------

	/**
	 * Runs a GhidraScript (by name on the script path, or by file path) with a program as
	 * {@code currentProgram}, the way the window's Script Manager does, and returns what it
	 * printed.
	 * <ul>
	 * <li>On a program this client owns writable: exclusive, and its changes stay (unsaved unless
	 * {@code "save":true}).</li>
	 * <li>Otherwise <i>contained</i>: the script runs inside an outer transaction that is always
	 * rolled back, so it cannot change what is saved. Contained scripts share the program lock and
	 * run concurrently unless {@code "exclusive":true}. While one runs on the shared program, its
	 * uncommitted changes are visible to the program's other readers (3.6, measured: 94 of 115
	 * polls); a protocol 3 request can ask for {@code isolation:"exclusive"} (the program's write
	 * lock for the run) or {@code "private"} (a throwaway program object from the stored file,
	 * which nobody else sees and which blocks nobody).</li>
	 * <li>With {@code "program":null} (or no program open) it runs with no current program, with
	 * the client's active project (if any) as its project.</li>
	 * </ul>
	 * This is not a sandbox: a script is Java with the session's rights.
	 */
	JsonElement script(Client c, JsonObject req, RequestMonitor m) {
		String name = Json.str(req, "script");
		ResourceFile src = findScript(name);
		boolean v3 = c.v3();
		String iso = null;
		if (v3) {
			validate("script", req);
			iso = isolationOf(req);
			checkSha(req, src);
		}
		boolean noProgram = req.has("program") && req.get("program").isJsonNull();
		ProgramEntry e = (noProgram || (c.active == null && !req.has("program"))) ? null
				: s.access.selected(c, req);
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		try (Runaway.Flight flight = v3 ? Runaway.enter(c) : null) {
			return scriptIn(c, src, name, req, m, e, iso);
		}
	}

	private JsonElement scriptIn(Client c, ResourceFile src, String name, JsonObject req,
			RequestMonitor m, ProgramEntry e, String iso) {
		if ("worker".equals(iso)) {
			ProjectEntry wp = e != null ? e.project : null;
			if (e == null && (Json.has(req, "project") || c.activeProject != null)) {
				wp = s.access.projectFor(c, req);
			}
			return runWorker(c, src, name, req, wp, e, m);
		}
		if (e == null) {
			ProjectEntry p = null;
			if (Json.has(req, "project") || c.activeProject != null) {
				p = s.access.projectFor(c, req);
			}
			if (p == null) {
				return runScript(c, src, req, null, null, null, "none", "none", null, m);
			}
			ProjectEntry pp = p;
			return s.access.inProject(p, req, "script",
				x -> runScript(c, src, req, pp.project, null, null, "none", "none", null, m));
		}
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), "script");
		try {
			if ("private".equals(iso)) {
				return runPrivate(c, src, name, req, e, m);
			}
			boolean owner = e.isWriter(c);
			boolean exclusive = owner ||
				(iso != null ? iso.equals("exclusive") : Json.bool(req, "exclusive", false));
			Lock l = e.acquire(exclusive, waitMs(req), c, "script " + name);
			try {
				if (e.program == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				owner = e.isWriter(c);
				JsonObject r = runScript(c, src, req, p.project, e.program, e,
					owner ? "owner" : "contained", exclusive ? "exclusive" : "shared", null, m);
				if (owner && Json.bool(r, "changed", false)) {
					journal(c, e, "script", "script", Json.of("script", name));
				}
				if (owner && Json.bool(req, "save", false) && e.program.isChanged()) {
					e.savedSeq = e.journal.seq();
					e.program.save("script " + name, m);
					e.stampRevision();
					p.invalidateRevision();
					Json.put(r, "saved", true);
				}
				return r;
			}
			catch (CancelledException | IOException ex) {
				throw new SessionException(
					ex instanceof CancelledException ? SessionException.CANCELLED
							: SessionException.FAILED,
					ex.getMessage());
			}
			finally {
				e.release(l);
			}
		}
		finally {
			pl.unlock();
		}
	}

	/**
	 * {@code isolation:"private"} (3.6): the script runs on a throwaway program object opened from
	 * the stored file. The program's lock is held only while the file is opened, and not at all
	 * while a script or an analysis holds it exclusively (they do not write the stored file), so
	 * a private script waits for no reader and no reader sees it. Nothing it changes is kept: the
	 * instance is released in a {@code finally}.
	 */
	private JsonObject runPrivate(Client c, ResourceFile src, String name, JsonObject req,
			ProgramEntry e, RequestMonitor m) {
		try (PrivateInstance pi = openPrivate(c, name, req, e, m)) {
			return runScript(c, src, req, e.project.project, pi.program(), e, "private", "private",
				pi, m);
		}
	}

	private PrivateInstance openPrivate(Client c, String name, JsonObject req, ProgramEntry e,
			RequestMonitor m) {
		Lock bl = PrivateInstance.baseLock(e, waitMs(req), c, "script " + name + " (open)");
		try {
			if (e.program == null) {
				throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
			}
			return PrivateInstance.open(s.upgradeCache, e, m);
		}
		finally {
			if (bl != null) {
				e.release(bl);
			}
		}
	}

	// ---- isolation "worker" (E7, D47, D64): a killable child JVM on a disposable clone ----------

	/**
	 * {@code isolation:"worker"}: the script runs in a child JVM ({@link ScriptWorker}) on a
	 * private, writable, <b>disposable clone of the saved project</b>, so nothing it does reaches
	 * the view, {@code attemptedChanges} is measured on the clone, and a script that ignores
	 * cancel is killed with its process.
	 * <p>
	 * The clone is of the <i>saved</i> view and nothing here saves it: a program with unsaved edits
	 * is refused ({@code conflict}, {@code details.reason:"unsaved"}, {@code next:{cmd:"save"}}),
	 * and the view's owner saves once, under the per-view lock, before it asks (D64). The project
	 * lock is held shared, and the program's lock shared (the stored file stays in place), only
	 * while the copy is made; the worker runs holding no lock at all, so the view is usable (and
	 * can be saved or closed) while it runs.
	 */
	private JsonObject runWorker(Client c, ResourceFile src, String name, JsonObject req,
			ProjectEntry p, ProgramEntry e, RequestMonitor m) {
		try (ScriptWorker.Admission adm = ScriptWorker.admit();
				ScriptWorker.Lease lease = ScriptWorker.Lease.create()) {
			String revision = null;
			if (p != null) {
				Lock pl = lockProject(p, false, waitMs(req), "script " + name + " (clone)");
				Lock bl = null;
				try {
					if (e != null) {
						bl = PrivateInstance.baseLock(e, waitMs(req), c, "script " + name + " (clone)");
						if (e.program == null) {
							throw new SessionException(SessionException.NO_PROGRAM,
								e.key + " was closed");
						}
						refuseUnsaved(e);
						revision = e.revision;
					}
					else {
						for (ProgramEntry pe : p.programs.values()) {
							if (pe.program != null) {
								refuseUnsaved(pe);
							}
						}
					}
					lease.cloneProject(p.resolved, s.forkCopyLimitBytes, m);
				}
				finally {
					if (bl != null) {
						e.release(bl);
					}
					p.lastUsed = System.currentTimeMillis();
					pl.unlock();
				}
			}
			int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
			JsonObject wreq = Json.of("op", "run", "script", src.getAbsolutePath(), "args",
				Json.strings(req, "args"), "address", Json.str(req, "address", null));
			wreq.add("scriptDirs", scriptDirs(src));
			if (lease.cloned) {
				wreq.add("project", Json.of("dir", lease.clone.toString(), "name", lease.projectName));
				if (e != null) {
					wreq.addProperty("program", e.path);
				}
			}
			Runaway.Watch watch = Runaway.watch(c, m, src);
			ScriptWorker.Outcome o;
			try {
				// the wall budget (scriptMaxS) cancels through the watch; a worker that is being
				// killed is not a runaway script, so its watch ends in the cancel hook
				o = ScriptWorker.run(lease, wreq, m, () -> Runaway.unwatch(watch));
			}
			finally {
				Runaway.unwatch(watch);
			}
			return workerReply(c, src, req, m, e, revision, lease, o, watch, cap);
		}
	}

	private static void refuseUnsaved(ProgramEntry e) {
		int n = PrivateInstance.unsavedEdits(e);
		if (n > 0) {
			JsonObject d = Json.of("reason", "unsaved", "program", e.key, "unsavedEdits", n,
				"suggest", "save");
			throw new SessionException(SessionException.CONFLICT,
				e.key + " has " + n + " unsaved edit(s); isolation \"worker\" works on a clone of " +
					"the saved program, so save it first (the view's owner saves once before the " +
					"worker starts)",
				d).withNext(Json.of("cmd", "save", "program", e.key));
		}
	}

	/** The script directories the worker compiles from: this daemon's, and the script's own folder. */
	private static JsonArray scriptDirs(ResourceFile src) {
		LinkedHashSet<String> dirs = new LinkedHashSet<>();
		JsonElement sp = Identity.paths().get("scriptPath");
		if (sp != null && sp.isJsonArray()) {
			sp.getAsJsonArray().forEach(x -> dirs.add(x.getAsString()));
		}
		ResourceFile parent = src.getParentFile();
		if (parent != null) {
			dirs.add(parent.getAbsolutePath());
		}
		JsonArray a = new JsonArray();
		dirs.forEach(a::add);
		return a;
	}

	/** Turns what the worker did into the reply (or the error) of the request. */
	private JsonObject workerReply(Client c, ResourceFile src, JsonObject req, RequestMonitor m,
			ProgramEntry e, String revision, ScriptWorker.Lease lease, ScriptWorker.Outcome o,
			Runaway.Watch watch, int cap) {
		JsonObject res = o.result();
		String out = o.output();
		JsonObject w = Json.of("pid", o.pid(), "totalMs", o.totalMs(), "startMs", o.startMs(),
			"startCpuMs", o.startCpuMs(),
			"cloneMs", lease.cloneMs, "cloneBytes", lease.cloneBytes, "killed", o.killed(),
			"clone", lease.clone.toString());
		w.add("marks", o.marks());
		if (res != null && res.has("mem")) {
			w.add("mem", res.get("mem"));
		}
		long attempted = res == null ? 0 : Json.num(res, "attempted", 0, 0, Long.MAX_VALUE);
		double seconds = res != null && res.has("seconds") ? res.get("seconds").getAsDouble()
				: o.totalMs() / 1000.0;
		JsonObject r = Json.of("script", src.getAbsolutePath(), "mode", "worker", "program",
			e == null ? null : e.key, "seconds", seconds, "chars", out.length(), "truncated",
			out.length() > cap || o.outputDropped(), "output",
			out.length() > cap ? out.substring(0, cap) : out, "changed", false, "unsaved",
			e != null && e.program != null && e.program.isChanged());
		Json.put(r, "artifact", Json.str(req, "artifact", null));
		addV3Reply(r, m, "worker", null, null, null, attempted, true, watch);
		if (e != null) {
			Json.put(r, "basedOn", Json.of("saved", true, "programRevision", revision));
			Json.put(r, "unsavedIgnored", 0);
		}
		r.add("worker", w);
		JsonObject failure = res == null ? null : Json.obj(res, "failure");
		if (res != null && failure == null) {
			return r;
		}
		if (res == null) {
			String why = watch == null ? null : watch.reason;
			if (o.killed() || m.isCancelled()) {
				throw new SessionException(SessionException.CANCELLED,
					"script " + (why != null ? "cancelled: " + why
							: m.timedOut() ? "timed out" : "cancelled") +
						"; its worker process was killed",
					r);
			}
			boolean heap = o.exitCode() != null && o.exitCode() == ScriptWorker.OOM_EXIT;
			JsonObject d = r;
			Json.put(d, "reason", heap ? "worker_heap" : "worker_died");
			Json.put(d, "exitCode", o.exitCode());
			Json.put(d, "stderr", o.stderrTail());
			throw new SessionException(SessionException.FAILED,
				heap ? "the script worker ran out of heap (workerHeapMb " +
					Math.max(128, Settings.integer("workerHeapMb", ScriptWorker.DEFAULT_HEAP_MB)) +
					") and ended; the daemon and the view are unaffected"
						: "the script worker ended before it reported (exit code " + o.exitCode() +
							"); the daemon and the view are unaffected",
				d);
		}
		boolean cancelled = Json.bool(failure, "cancelled", false);
		if (cancelled || m.isCancelled()) {
			String why = watch == null ? null : watch.reason;
			throw new SessionException(SessionException.CANCELLED,
				"script " + (why != null ? "cancelled: " + why
						: m.timedOut() ? "timed out" : "cancelled"),
				r);
		}
		throw new SessionException(SessionException.FAILED,
			"script failed: " + Json.str(failure, "type", "") + ": " +
				Json.str(failure, "message", ""),
			r);
	}

	/**
	 * {@code script} on one of the client's overlays: contained, on the overlay's own program. A
	 * protocol 3 request has its {@code isolation} validated and its {@code scriptSha256} checked
	 * (as for any script); the isolation value itself is ignored on purpose (see {@link #checkSha}).
	 */
	JsonObject runOverlayScript(Client c, ResourceFile src, JsonObject req, Project project,
			Program overlayProgram, RequestMonitor m) {
		if (c.v3()) {
			if ("worker".equals(isolationOf(req))) {
				// an overlay is RAM-only: there is no saved file for a worker to clone
				throw new SessionException(SessionException.CONFLICT,
					"isolation \"worker\" runs on a clone of the saved program; an overlay exists " +
						"only in memory and has no saved file",
					Json.of("reason", "overlay", "field", "isolation"));
			}
			checkSha(req, src);
		}
		try (Runaway.Flight flight = c.v3() ? Runaway.enter(c) : null) {
			return runScript(c, src, req, project, overlayProgram, null, "contained", "overlay", null,
				m);
		}
	}

	static ResourceFile findScript(String name) {
		File f = new File(name);
		ResourceFile src = f.isAbsolute() || f.isFile() ? new ResourceFile(f.getAbsoluteFile())
				: GhidraScriptUtil.findScriptByName(name);
		if (src == null || !src.exists()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"script not found: " + name + " (give a file path, or start the session " +
					"with -scriptPath)");
		}
		return src;
	}

	/**
	 * Runs the script. {@code mode} is {@code owner}, {@code contained}, {@code private} or
	 * {@code none} (the reply's {@code mode}); {@code isolation} is what a protocol 3 reply says
	 * about it ({@code shared}, {@code exclusive}, {@code private}, {@code overlay}, {@code none}).
	 * {@code contained} and {@code private} run in an outer transaction that is rolled back.
	 */
	JsonObject runScript(Client c, ResourceFile src, JsonObject req, Project project, Program p,
			ProgramEntry e, String mode, String isolation, PrivateInstance pi,
			RequestMonitor m) {
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw, true);
		ScriptClasses.Lookup look = ScriptClasses.lookup(src);
		GhidraScript s = look.instance();
		if (s == null) {
			// H4: an unchanged script that loaded cleanly before needs no bundle activation; the
			// hit takes no lock (ScriptClassCache says when an entry is valid)
			s = ScriptClassCache.instance(src);
		}
		if (s == null) {
			synchronized (SCRIPT_COMPILE) {
				GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
				if (provider == null) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"no script provider for " + src.getName());
				}
				ScriptClassCache.Before before = ScriptClassCache.before(src, provider);
				try {
					s = provider.getScriptInstance(src, pw);
				}
				catch (Exception ex) {
					pw.flush();
					throw new SessionException(SessionException.FAILED,
						"script did not load: " + ex.getMessage(), Json.of("output", sw.toString()),
						ex);
				}
				look.remember(provider, s);
				pw.flush();
				if (sw.getBuffer().length() == 0) {
					// a load that printed nothing (no build messages): the same on a hit
					ScriptClassCache.remember(src, provider, before, s);
				}
			}
		}
		s.setScriptArgs(Json.strings(req, "args").toArray(new String[0]));
		bindHeadless(s);
		ProgramLocation loc = null;
		if (p != null && Json.has(req, "address")) {
			loc = new ProgramLocation(p, address(p, Json.str(req, "address")));
		}
		GhidraState state = new GhidraState(null, project, p, loc, null, null);
		boolean contained = p != null && (mode.equals("contained") || mode.equals("private"));
		// what this script changed, not whether the program had unsaved changes already (which a
		// shared program usually has): every change fires an event, which moves this number
		long modBefore = p == null ? 0 : p.getModificationNumber();
		boolean savedBefore = p != null && !p.isChanged();
		long modAtEnd = modBefore;
		int outer = -1;
		// H4: soft bound on scripts running at once (taken before any transaction is opened)
		boolean permit = ScriptClassCache.enterRun(m);
		long t0;
		Throwable failure = null;
		Runaway.Watch watch = null;
		try {
			if (contained) {
				outer = p.startTransaction("session: contained script (rolled back)");
			}
			t0 = System.nanoTime();
			watch = c.v3() ? Runaway.watch(c, m, src) : null;
			try {
				s.execute(state, new ScriptControls(pw, pw, false, m));
			}
			catch (Throwable t) {
				failure = t;
			}
			finally {
				Runaway.unwatch(watch);
				if (p != null) {
					// what the script tried, measured before the rollback takes it back (3.4)
					modAtEnd = p.getModificationNumber();
				}
				if (contained) {
					p.endTransaction(outer, false);
				}
				pw.flush();
			}
		}
		finally {
			ScriptClassCache.exitRun(permit);
		}
		String out = sw.toString();
		JsonObject r = Json.of("script", src.getAbsolutePath(), "mode", mode, "program",
			e == null ? null : e.key, "seconds", (System.nanoTime() - t0) / 1e9, "chars",
			out.length(), "truncated", out.length() > cap, "output",
			out.length() > cap ? out.substring(0, cap) : out, "changed",
			p != null && !contained && p.getModificationNumber() != modBefore, "unsaved",
			p != null && p.isChanged());
		Json.put(r, "artifact", Json.str(req, "artifact", null));
		if (c.v3()) {
			addV3Reply(r, m, isolation, p, e, pi, modAtEnd - modBefore, savedBefore, watch);
		}
		if (failure != null) {
			if (m.isCancelled() || failure instanceof CancelledException) {
				String why = watch == null ? null : watch.reason;
				throw new SessionException(SessionException.CANCELLED,
					"script " + (why != null ? "cancelled: " + why
							: m.timedOut() ? "timed out" : "cancelled"),
					r);
			}
			throw new SessionException(SessionException.FAILED,
				"script failed: " + failure.getClass().getSimpleName() + ": " +
					failure.getMessage(),
				r, failure);
		}
		return r;
	}

	/**
	 * The protocol 3 additions of the {@code script} reply (reply conditional C8). {@code lane} and
	 * {@code laneNote} are copied from the request monitor, where the scheduler stored its
	 * decision (E3a); this method decides no lane.
	 */
	private static void addV3Reply(JsonObject r, RequestMonitor m, String isolation, Program p,
			ProgramEntry e, PrivateInstance pi, long delta, boolean savedBefore, Runaway.Watch watch) {
		Json.put(r, "isolation", isolation);
		Json.put(r, "lane", m.lane());
		if (m.laneNote() != null) {
			Json.put(r, "laneNote", m.laneNote());
		}
		long attempted = Math.max(0, delta);
		Json.put(r, "attemptedChanges", attempted > 0);
		Json.put(r, "attemptedChangesCount", attempted);
		if (p != null && e != null) {
			boolean priv = pi != null;
			Json.put(r, "basedOn", Json.of("saved", priv || savedBefore, "programRevision",
				priv ? pi.revision : e.revision));
			Json.put(r, "unsavedIgnored", priv ? pi.unsavedIgnored : 0);
		}
		if (watch != null && watch.reason != null) {
			Json.put(r, "cancelReason", watch.reason);
		}
	}

	/** The number of scripts that ignored their cancel and still run (E5's {@code health}). */
	static int leakedWorkers() {
		return Runaway.leakedTotal();
	}

	/** One entry per quarantined script, for {@code health.leakedWorkers}. */
	static JsonArray leakedList() {
		return Runaway.describeLeaked();
	}

	/**
	 * Lets {@link HeadlessScript} subclasses run here as under {@code analyzeHeadless}
	 * ({@code storeHeadlessValue} and friends). The setter is package-private in Ghidra, so it is
	 * reached reflectively rather than by editing Ghidra's class.
	 */
	static void bindHeadless(GhidraScript s) {
		if (!(s instanceof HeadlessScript hs)) {
			return;
		}
		try {
			Method set = HeadlessScript.class.getDeclaredMethod("setHeadlessInstance",
				HeadlessAnalyzer.class);
			set.setAccessible(true);
			set.invoke(hs, HeadlessAnalyzer.getInstance());
		}
		catch (ReflectiveOperationException | IOException | RuntimeException ex) {
			Msg.warn(Session.class, "HeadlessScript features unavailable: " + ex);
		}
	}

	// ---- runaway scripts (D47, BP13): bounded and quarantined, not killed -----------------------

	/**
	 * What bounds a script that does not stop (protocol 3 only; hydra.4, PROTOCOL-3.md 6.2). Java
	 * cannot kill a thread that ignores cancel, so the bound is: a wall budget {@code scriptMaxS}
	 * (default 600 s; 0 turns it off), optional CPU ({@code scriptCpuS}) and allocated-bytes
	 * ({@code scriptAllocMb}) budgets of the script thread, each of which only sets the request's
	 * cancel flag, and a <b>quarantine</b>: a script that still runs {@code scriptGraceS} seconds
	 * (default 5) after its cancel is counted as leaked ({@link #leakedTotal}), and while its
	 * owner has one, that owner may run one script at a time (the leaked one counts), so a deaf
	 * script costs its owner a slot and not the daemon. The script thread is never interrupted
	 * (an interrupt closes NIO channels under the database). The killable worker that removes the
	 * leak is E7's.
	 */
	static final class Runaway {

		static final int DEFAULT_MAX_S = 600;
		static final int DEFAULT_GRACE_S = 5;
		static final int DEFAULT_SAMPLE_MS = 250;

		private static final Set<Watch> WATCHES = ConcurrentHashMap.newKeySet();
		/** Scripts in flight, by owner key (counted from the start of the command). */
		private static final Map<String, Integer> RUNNING = new ConcurrentHashMap<>();
		/** Leaked (quarantined) scripts, by owner key. */
		private static final Map<String, Integer> LEAKED = new ConcurrentHashMap<>();
		private static ScheduledExecutorService sampler;
		/** Looked up once: the sampler used to look it up on every pass (H4). */
		private static final ThreadMXBean THREAD_MX = ManagementFactory.getThreadMXBean();

		private Runaway() {
		}

		/** The owner of a script: the fair key of the scheduler (connection, plus the label). */
		static String ownerKey(Client c) {
			Caller.Identity id = Caller.current(c);
			String scope = id == null ? null : id.scope();
			return scope == null ? Integer.toString(c.id) : c.id + "/" + scope;
		}

		private static int setting(String key, int dflt) {
			try {
				return Settings.integer(key, dflt);
			}
			catch (IllegalArgumentException ex) {
				return dflt;
			}
		}

		/** A script in flight; closing it ends the count. */
		static final class Flight implements AutoCloseable {
			private final String owner;

			Flight(String owner) {
				this.owner = owner;
			}

			@Override
			public void close() {
				RUNNING.merge(owner, -1, (a, b) -> a + b > 0 ? a + b : null);
			}
		}

		/**
		 * Counts a script of {@code c} in flight. While the owner has a quarantined script, a
		 * second one is refused {@code busy} with {@code reason:"runaway_quarantined"}.
		 */
		static Flight enter(Client c) {
			String owner = ownerKey(c);
			int leaked = LEAKED.getOrDefault(owner, 0);
			if (leaked > 0) {
				// the leaked script is itself in flight, so the owner's cap of 1 is already used
				int running = RUNNING.getOrDefault(owner, 0);
				if (running >= 1) {
					JsonObject d = Json.of("owner", owner, "leakedWorkers", leaked, "running",
						running, "suggest", "retry");
					d = SessionException.busyDetails(true, d, "runaway_quarantined", null, null);
					SessionException ex = new SessionException(SessionException.BUSY,
						"this client has " + leaked + " script(s) that ignored cancel and still " +
							"run; its scripts are limited to one at a time until they end",
						d);
					ex.withRetryAfterMs(5000);
					throw ex;
				}
			}
			RUNNING.merge(owner, 1, Integer::sum);
			return new Flight(owner);
		}

		/** A script thread under watch. */
		static final class Watch {
			final Thread thread;
			final RequestMonitor m;
			final String owner;
			final String script;
			final long startNanos = System.nanoTime();
			final long cpu0;
			final long alloc0;
			final long maxWallNanos;
			final long maxCpuNanos;
			final long maxAllocBytes;
			final long graceNanos;
			volatile String reason;
			volatile long cancelledAtNanos;
			volatile boolean leaked;

			Watch(Client c, RequestMonitor m, String script) {
				this.thread = Thread.currentThread();
				this.m = m;
				this.owner = ownerKey(c);
				this.script = script;
				this.maxWallNanos = TimeUnit.SECONDS.toNanos(
					Math.max(0, setting("scriptMaxS", DEFAULT_MAX_S)));
				this.maxCpuNanos = TimeUnit.SECONDS.toNanos(Math.max(0, setting("scriptCpuS", 0)));
				this.maxAllocBytes = Math.max(0L, setting("scriptAllocMb", 0)) * 1024L * 1024L;
				this.graceNanos = TimeUnit.SECONDS.toNanos(
					Math.max(0, setting("scriptGraceS", DEFAULT_GRACE_S)));
				ThreadMXBean mx = THREAD_MX;
				long cpu = -1;
				long alloc = -1;
				try {
					if (maxCpuNanos > 0 && mx.isThreadCpuTimeSupported()) {
						cpu = mx.getThreadCpuTime(thread.threadId());
					}
					if (maxAllocBytes > 0 && mx instanceof com.sun.management.ThreadMXBean sx &&
						sx.isThreadAllocatedMemorySupported()) {
						alloc = sx.getThreadAllocatedBytes(thread.threadId());
					}
				}
				catch (RuntimeException ex) {
					// not measurable here: that budget is off
				}
				this.cpu0 = cpu;
				this.alloc0 = alloc;
			}

			/** Sets the cancel flag once, saying why. */
			void cancel(String why) {
				if (reason == null) {
					reason = why;
				}
				m.cancel();
			}
		}

		/** Starts watching the calling thread, which is about to run a script. */
		static Watch watch(Client c, RequestMonitor m, ResourceFile src) {
			Watch w = new Watch(c, m, src.getName());
			WATCHES.add(w);
			startSampler();
			return w;
		}

		/** Stops watching; a quarantined script that ended is no longer leaked. */
		static void unwatch(Watch w) {
			if (w == null) {
				return;
			}
			boolean wasLeaked;
			synchronized (LEAK_LOCK) {
				WATCHES.remove(w);
				wasLeaked = w.leaked;
				if (wasLeaked) {
					LEAKED.merge(w.owner, -1, (a, b) -> a + b > 0 ? a + b : null);
				}
			}
			if (wasLeaked) {
				Msg.info(ScriptCommands.class, "quarantined script " + w.script + " of " + w.owner +
					" ended after " + (System.nanoTime() - w.startNanos) / 1_000_000 + " ms");
			}
		}

		private static synchronized void startSampler() {
			if (sampler != null) {
				return;
			}
			sampler = Executors.newSingleThreadScheduledExecutor(r -> {
				Thread t = new Thread(r, "session-script-watch");
				t.setDaemon(true);
				return t;
			});
			long every = Math.max(20, setting("scriptSampleMs", DEFAULT_SAMPLE_MS));
			sampler.scheduleWithFixedDelay(Runaway::sample, every, every, TimeUnit.MILLISECONDS);
		}

		/** One pass over the scripts under watch. Never throws (the executor would stop). */
		static void sample() {
			if (WATCHES.isEmpty()) {
				return;
			}
			try {
				ThreadMXBean mx = THREAD_MX;
				long now = System.nanoTime();
				for (Watch w : WATCHES) {
					if (!w.m.isCancelled()) {
						check(mx, w, now);
					}
					if (w.m.isCancelled()) {
						if (w.cancelledAtNanos == 0) {
							w.cancelledAtNanos = now;
						}
						else if (!w.leaked && now - w.cancelledAtNanos > w.graceNanos) {
							quarantine(w);
						}
					}
				}
			}
			catch (RuntimeException ex) {
				Msg.warn(ScriptCommands.class, "script watch: " + ex);
			}
		}

		private static void check(ThreadMXBean mx, Watch w, long now) {
			if (w.maxWallNanos > 0 && now - w.startNanos > w.maxWallNanos) {
				w.cancel("wall budget scriptMaxS (" + TimeUnit.NANOSECONDS.toSeconds(w.maxWallNanos) +
					" s) exceeded");
				return;
			}
			try {
				if (w.cpu0 >= 0 && w.maxCpuNanos > 0) {
					long cpu = mx.getThreadCpuTime(w.thread.threadId());
					if (cpu >= 0 && cpu - w.cpu0 > w.maxCpuNanos) {
						w.cancel("CPU budget scriptCpuS (" +
							TimeUnit.NANOSECONDS.toSeconds(w.maxCpuNanos) + " s) exceeded");
						return;
					}
				}
				if (w.alloc0 >= 0 && w.maxAllocBytes > 0 &&
					mx instanceof com.sun.management.ThreadMXBean sx) {
					long a = sx.getThreadAllocatedBytes(w.thread.threadId());
					if (a >= 0 && a - w.alloc0 > w.maxAllocBytes) {
						w.cancel("allocation budget scriptAllocMb (" +
							w.maxAllocBytes / (1024 * 1024) + " MB) exceeded");
					}
				}
			}
			catch (RuntimeException ex) {
				// the thread ended meanwhile
			}
		}

		/** Makes quarantine and unwatch mutually exclusive: an ended script is never counted leaked. */
		private static final Object LEAK_LOCK = new Object();

		private static void quarantine(Watch w) {
			synchronized (LEAK_LOCK) {
				if (!WATCHES.contains(w)) {
					return; // the script ended while the sampler was deciding
				}
				w.leaked = true;
				LEAKED.merge(w.owner, 1, Integer::sum);
			}
			Msg.warn(ScriptCommands.class, "script " + w.script + " of " + w.owner +
				" ignored cancel for more than " + TimeUnit.NANOSECONDS.toSeconds(w.graceNanos) +
				" s: quarantined (its owner may run one script at a time until it ends)");
		}

		static int leakedTotal() {
			int n = 0;
			for (int v : LEAKED.values()) {
				n += v;
			}
			return n;
		}

		static JsonArray describeLeaked() {
			JsonArray a = new JsonArray();
			long now = System.nanoTime();
			for (Watch w : WATCHES) {
				if (w.leaked) {
					a.add(Json.of("script", w.script, "owner", w.owner, "runningMs",
						(now - w.startNanos) / 1_000_000, "reason", w.reason));
				}
			}
			return a;
		}
	}
}
