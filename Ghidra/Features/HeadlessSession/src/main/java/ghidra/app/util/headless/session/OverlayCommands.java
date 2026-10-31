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
import static ghidra.app.util.headless.session.Addresses.hex;
import static ghidra.app.util.headless.session.Operations.ops;
import static ghidra.app.util.headless.session.Requests.cancelled;
import static ghidra.app.util.headless.session.Requests.waitMs;
import static ghidra.app.util.headless.session.ScriptCommands.findScript;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.regex.Pattern;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * Overlays: a client's private, replayable changes over a read-only program
 * ({@code open_program} with {@code overlay}, {@code apply_overlay},
 * {@code drop_overlay}, {@code overlays}, {@code promote_overlay}).
 */
final class OverlayCommands {

	private final Session s;

	OverlayCommands(Session s) {
		this.s = s;
	}

	/** Every client's overlays, by {@link Overlay#id}. */
	final Map<String, Overlay> overlays = new ConcurrentHashMap<>();
	private static final Pattern OVERLAY_NAME = Pattern.compile("[A-Za-z0-9_.@-]{1,64}");

	/** Commands that act on an overlay when the request names one. */
	static boolean overlayScoped(String cmd) {
		return switch (cmd) {
			case "open_program", "switch", "info", "functions", "decompile", "rename", "comment",
					"script", "apply_overlay", "drop_overlay" ->
				true;
			default -> false;
		};
	}

	List<Overlay> overlaysOf(ProgramEntry e) {
		List<Overlay> out = new ArrayList<>();
		for (Overlay o : overlays.values()) {
			if (o.base == e) {
				out.add(o);
			}
		}
		return out;
	}

	JsonElement listOverlays(Client c) {
		JsonArray a = new JsonArray();
		for (Overlay o : overlays.values()) {
			if (o.client == c) {
				a.add(o.describe());
			}
		}
		return Json.of("overlays", a);
	}

	private static String overlayName(JsonObject req) {
		String name = Json.str(req, "overlay");
		if (!OVERLAY_NAME.matcher(name).matches()) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"overlay must be 1-64 letters, digits, '.', '_', '-' or '@'");
		}
		return name;
	}

	/**
	 * A command on one of this client's overlays: {@code open_program} (creates or joins it),
	 * {@code info}, {@code functions}, {@code decompile}, {@code script} (contained),
	 * {@code rename}, {@code comment} and {@code apply_overlay} (changes, logged),
	 * {@code drop_overlay}.
	 */
	JsonElement overlayCommand(Client c, String cmd, JsonObject req, RequestMonitor m) {
		String name = overlayName(req);
		if (cmd.equals("open_program") || cmd.equals("switch")) {
			if (Json.bool(req, "writable", false)) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"an overlay is a private view over a read-only use of the program; leave " +
						"out \"writable\" (promote_overlay writes it into a working copy)");
			}
			JsonObject plain = req.deepCopy();
			plain.remove("overlay");
			// BP24: a program this client already uses is not joined again (the join takes the
			// program's shared lock, which an exclusive holder keeps for as long as it runs); the
			// overlay is opened from the stored file and needs no lock of the base then
			ProgramEntry used = alreadyUsed(c, plain);
			JsonObject info;
			if (used != null) {
				c.active = used.key;
				c.activeProject = used.project.id;
				info = s.programCmds.programInfo(used, c);
				Json.put(info, "openMs", 0);
			}
			else {
				info = (JsonObject) s.programCmds.openProgram(c, plain, m);
			}
			ProgramEntry e = s.access.entryByKey(info.get("key").getAsString());
			if (e == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					info.get("key").getAsString() + " was closed meanwhile");
			}
			Overlay o = openOverlay(c, e, name, waitMs(req), m);
			HostDecompileBackend.warm(o.program(), o.snapshotSource());
			info.add("overlay", o.describe());
			return info;
		}
		ProgramEntry e = s.access.selected(c, req);
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), cmd);
		try {
			Overlay o = overlays.get(Overlay.id(c, e.key, name));
			if (o == null) {
				if (cmd.equals("drop_overlay")) {
					return Json.of("dropped", false, "overlay", name, "program", e.key);
				}
				throw new SessionException(SessionException.NOT_FOUND,
					"this client has no overlay '" + name + "' on " + e.key +
						"; open_program with \"overlay\" first",
					Json.of("overlay", name, "program", e.key));
			}
			boolean write = cmd.equals("apply_overlay") || cmd.equals("rename") ||
				cmd.equals("comment") || cmd.equals("drop_overlay");
			// a script may change the program too, so it gets one of its own like a change does
			boolean needsProgram = write || cmd.equals("script");
			if (needsProgram && !cmd.equals("drop_overlay") && o.error == null &&
				o.program == null) {
				// the first change gives the overlay a program of its own, over the stored file:
				// taken with the base's lock (and before the overlay's write lock), the order the
				// overlay's open takes them in (a materialize under the overlay lock alone could
				// deadlock against it)
				Lock bl = PrivateInstance.baseLock(e, waitMs(req), c, cmd);
				try {
					materialize(o, m);
				}
				finally {
					if (bl != null) {
						e.release(bl);
					}
				}
			}
			Lock ol = write ? o.lock.writeLock() : o.lock.readLock();
			Waits.Outcome got = Waits.lock(o.lock, write, waitMs(req), Waits.counter(o));
			if (got != Waits.Outcome.GOT) {
				boolean full = got == Waits.Outcome.QUEUE_FULL;
				boolean v3 = c.v3();
				JsonObject d = e.identity();
				Json.put(d, "overlay", name);
				d.add("holderInfo", c.holder("overlay " + name, 0));
				Json.put(d, "suggest", "retry");
				d = SessionException.busyDetails(v3, d, full ? "lock_queue_full" : "lock_wait", null,
					null);
				SessionException ex = new SessionException(SessionException.BUSY,
					full ? "overlay '" + name + "' already has too many requests waiting for it"
							: "overlay '" + name + "' is busy with another of this client's requests",
					d);
				if (v3) {
					ex.withRetryAfterMs(1000);
				}
				throw ex;
			}
			try {
				if (cmd.equals("drop_overlay")) {
					o.dispose();
					overlays.remove(o.id, o);
					Msg.info(s, c.label() + " dropped overlay " + name + " of " + e.key +
						" (" + o.log.size() + " operations, version " + o.version + ")");
					return Json.of("dropped", true, "overlay", name, "program", e.key, "ops",
						o.log.size(), "overlayVersion", o.version);
				}
				if (o.error != null || o.readProgram() == null) {
					JsonObject d = o.describe();
					d.add("log", o.log.deepCopy());
					throw new SessionException(SessionException.CONFLICT,
						"overlay '" + name + "' is unusable: " + o.error +
							"; drop_overlay it (its log is in details.log)",
						d);
				}
				// an empty overlay over a read-only program reads through that program (no second
				// open: Overlay.shared); its own program is opened by the first change
				Program view = o.readProgram();
				return switch (cmd) {
					case "info" -> overlayInfo(o);
					case "functions" -> withOverlay(o, s.queries.functions(view, req));
					case "decompile" -> withOverlay(o,
						s.queries.decompile(view, o, req, m));
					case "script" -> {
						ResourceFile src = findScript(Json.str(req, "script"));
						m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
						// a script may undo: give it the default undo history (lightOverlays)
						o.bytesChanged = true;	// it may change bytes: snapshot the overlay itself
						PrivateInstance.unlighten(o.program);
						yield withOverlay(o,
							s.scripts.runOverlayScript(c, src, req, p.project, o.program, m));
					}
					case "rename" -> applyOverlay(o, ops(req, "rename"));
					case "comment" -> applyOverlay(o, ops(req, "comment"));
					case "apply_overlay" -> applyOverlay(o, ops(req, null));
					default -> throw new SessionException(SessionException.UNKNOWN_COMMAND,
						cmd + " does not take an overlay");
				};
			}
			finally {
				ol.unlock();
			}
		}
		finally {
			p.lastUsed = System.currentTimeMillis();
			pl.unlock();
		}
	}

	/**
	 * The program {@code req.path} names when this client already uses it, else null (the open
	 * then goes through {@code open_program}).
	 */
	private ProgramEntry alreadyUsed(Client c, JsonObject req) {
		if (!Json.has(req, "path")) {
			return null;
		}
		JsonObject sel = new JsonObject();
		sel.add("program", req.get("path"));
		if (Json.has(req, "project")) {
			sel.add("project", req.get("project"));
		}
		try {
			ProgramEntry e = s.access.selected(c, sel);
			return e.program == null ? null : e;
		}
		catch (SessionException ex) {
			return null;
		}
	}

	private static JsonElement withOverlay(Overlay o, JsonElement r) {
		if (r instanceof JsonObject j) {
			j.add("overlay", o.describe());
		}
		return r;
	}

	/**
	 * Opens (or joins) a client's overlay of {@code e}: its own program object over the stored
	 * file. Held: nothing; takes the project's and the program's shared locks.
	 */
	private Overlay openOverlay(Client c, ProgramEntry e, String name, long wait,
			RequestMonitor m) {
		String id = Overlay.id(c, e.key, name);
		Overlay existing = overlays.get(id);
		if (existing != null && existing.error == null) {
			return existing;
		}
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, wait, "open_program overlay");
		try {
			// BP24: the overlay is opened from the stored file, so a request that holds the base
			// exclusively without writing that file (a script, an analysis) does not block it; any
			// other wait for the base is timed and cancel-aware (Waits)
			Lock l = PrivateInstance.baseLock(e, wait, c, "open_program overlay");
			String revisionAtOpen = e.revision;
			try {
				if (e.program == null || p.programs.get(e.path) != e) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				if (existing != null) {
					// an overlay a refresh could not rebuild: start it over
					existing.lock.writeLock().lock();
					try {
						existing.dispose();
						overlays.remove(id, existing);
					}
					finally {
						existing.lock.writeLock().unlock();
					}
				}
				Overlay o = new Overlay(c, name, e);
				o.lock.writeLock().lock();
				try {
					loadOverlay(o, m);
				}
				catch (RuntimeException ex) {
					o.dispose();
					throw ex;
				}
				finally {
					o.lock.writeLock().unlock();
				}
				Overlay prev = overlays.putIfAbsent(id, o);
				if (prev != null) {
					o.lock.writeLock().lock();
					try {
						o.dispose();
					}
					finally {
						o.lock.writeLock().unlock();
					}
					return prev;
				}
				if (l == null && !Objects.equals(revisionAtOpen, e.revision)) {
					// opened without the base's lock and its stored file changed meanwhile (a
					// refresh or a save): rebuild the overlay from the file as it is now
					rebuildOverlays(e, m);
				}
				Msg.info(s, c.label() + " opened overlay " + name + " of " + e.key + " in " +
					o.openMs + " ms");
				return o;
			}
			finally {
				if (l != null) {
					e.release(l);
				}
			}
		}
		finally {
			pl.unlock();
		}
	}

	/**
	 * An empty overlay of a read-only program <b>is</b> that program: its log is empty, so
	 * replaying it changes nothing, and the program cannot be written. Opening it costs one
	 * reference instead of a whole second {@link ProgramDB} (the measured ~28 ms an overlay open
	 * took, mostly reading the database's metadata), and the first query reads through the shared
	 * program. The entry keeps the program alive for the session; the overlay is a consumer too,
	 * so a later writable open or a refresh cannot pull the snapshot from under it, and it is
	 * given up when the overlay is dropped or gets a program of its own.
	 */
	private boolean shareable(ProgramEntry e) {
		return e.program != null && e.mode == ProgramEntry.Mode.READ_ONLY &&
			!e.program.isChanged() && !e.program.isClosed();
	}

	/**
	 * Makes {@code o} read through {@code e.program} (see {@link #shareable}). Held: the overlay's
	 * write lock.
	 */
	private void share(Overlay o, ProgramEntry e) {
		Program p = e.program;
		p.addConsumer(o);
		o.shared = p;
		o.program = null;
		o.view = null;
		o.lease = null;
		o.openMs = 0;
		o.sha256 = p.getExecutableSHA256();
		o.programRevision = e.revision;
		o.projectRevision = e.project.revision();
		o.generation = e.project.generation;
		o.error = null;
	}

	/**
	 * Opens the overlay's own program object (from the upgrade cache copy when the shared program
	 * came from one) and replays its log, unless an empty overlay over a read-only program can
	 * read through the program ({@link #shareable}). The open is {@link PrivateInstance#load}, the
	 * mechanism a {@code private} script shares. Held: the overlay's write lock, and the program's
	 * lock unless {@link PrivateInstance#baseLock} said it is not needed.
	 */
	private void loadOverlay(Overlay o, RequestMonitor m) {
		ProgramEntry e = o.base;
		if (o.log.isEmpty() && shareable(e)) {
			share(o, e);
			return;
		}
		openPrivate(o, m);
	}

	/**
	 * Gives {@code o} a program of its own over the stored file, replaying its log: before its
	 * first change, or when it cannot read through the shared program. Takes the overlay's write
	 * lock; the caller holds the base program's lock ({@link PrivateInstance#baseLock}), the order
	 * {@link #openOverlay} takes them in.
	 */
	private void materialize(Overlay o, RequestMonitor m) {
		if (o.program != null) {
			return;
		}
		o.lock.writeLock().lock();
		try {
			if (o.program == null) {
				ProgramEntry e = o.base;
				if (e.program == null || e.program.isClosed()) {
					throw new SessionException(SessionException.NO_PROGRAM,
						e.key + " was closed");
				}
				openPrivate(o, m);
			}
		}
		finally {
			o.lock.writeLock().unlock();
		}
	}

	/** {@link #loadOverlay}'s open: the program, its view and lease, and the log applied. */
	private void openPrivate(Overlay o, RequestMonitor m) {
		ProgramEntry e = o.base;
		PrivateInstance.Loaded l = PrivateInstance.load(s.upgradeCache, e, o, m);
		Program prog = l.program();
		if (Settings.bool(PrivateInstance.LIGHT_OVERLAYS, false)) {
			PrivateInstance.lighten(prog);
		}
		Program shared = o.shared;
		o.shared = null;
		if (shared != null) {
			// decompilers built on the shared program would outlive it (Overlay.borrowDecompiler
			// checks too); nothing is kept across the change of program
			o.dropDecompilers();
			shared.release(o);
		}
		o.view = l.view();
		o.lease = l.lease();
		o.program = prog;
		o.openMs = l.openMs();
		o.sha256 = prog.getExecutableSHA256();
		o.programRevision = e.revision;
		o.projectRevision = e.project.revision();
		o.generation = e.project.generation;
		o.error = null;
		if (!o.log.isEmpty()) {
			s.operations.applyOps(prog, o.log);
		}
	}

	/** After a refresh reopened {@code e}: every overlay of it is rebuilt from its log. */
	void rebuildOverlays(ProgramEntry e, RequestMonitor m) {
		for (Overlay o : overlaysOf(e)) {
			o.lock.writeLock().lock();
			try {
				String sha = o.sha256;
				o.dispose();
				try {
					loadOverlay(o, m);
					if (sha != null && !sha.equalsIgnoreCase(o.sha256)) {
						o.dispose();
						o.error = "the program is another build after the refresh (SHA-256 " +
							o.sha256 + ", the overlay was made over " + sha + ")";
						o.sha256 = sha;
					}
				}
				catch (RuntimeException ex) {
					o.dispose();
					o.error = "could not reapply the overlay after a refresh: " + ex.getMessage();
				}
				if (o.error != null) {
					Msg.warn(s, "overlay " + o.name + " of " + e.key + ": " + o.error);
				}
			}
			finally {
				o.lock.writeLock().unlock();
			}
		}
	}

	/** Drops the overlays of {@code e} that belong to {@code c} (all of them when c is null). */
	void dropOverlays(Client c, ProgramEntry e) {
		for (Overlay o : overlaysOf(e)) {
			if (c != null && o.client != c) {
				continue;
			}
			o.lock.writeLock().lock();
			try {
				o.dispose();
				overlays.remove(o.id, o);
			}
			finally {
				o.lock.writeLock().unlock();
			}
		}
	}

	/**
	 * Applies operations to the overlay as one unit, and logs them. Held: its write lock; the
	 * overlay has a program of its own already ({@link #materialize}, before the lock).
	 */
	private JsonObject applyOverlay(Overlay o, JsonArray ops) {
		JsonArray results = s.operations.applyOps(o.program, ops);
		for (JsonElement op : ops) {
			o.log.add(op.deepCopy());
		}
		o.version++;
		// the overlay's generation changed: set the host up for it on a background thread, so the
		// decompile that follows the edit does not pay the store and the byte snapshot
		HostDecompileBackend.warm(o.program, o.snapshotSource());
		return Json.of("overlay", o.describe(), "applied", ops.size(), "results", results);
	}

	/** {@code info} of an overlay: the program as this overlay shows it. */
	private JsonObject overlayInfo(Overlay o) {
		Program p = o.readProgram();
		ProgramEntry e = o.base;
		JsonObject j = Json.of("key", e.key, "project", e.project.id, "path", e.path, "name",
			p.getName(), "mode", "overlay", "language", p.getLanguageID().getIdAsString(),
			"compiler", p.getCompilerSpec().getCompilerSpecID().getIdAsString(), "imageBase",
			hex(p.getImageBase()), "format", p.getExecutableFormat(), "sha256",
			p.getExecutableSHA256(), "functions", p.getFunctionManager().getFunctionCount(),
			"analyzed", GhidraProgramUtilities.isAnalyzed(p), "changed", p.isChanged(),
			"revision", e.revision, "projectRevision", e.project.revision());
		j.add("overlay", o.describe());
		return j;
	}

	/**
	 * {@code promote_overlay}: replays an overlay's log into a writable copy of the program, in
	 * a project this client opened writable ({@code "project"}) or in a new fork of the overlay's
	 * project ({@code "fork": {"path": ..., "mode": ...}}), and saves it. The target must be the
	 * same build (SHA-256). The overlay stays as it is.
	 */
	JsonElement promoteOverlay(Client c, JsonObject req, RequestMonitor m) {
		String name = overlayName(req);
		ProgramEntry e = s.access.selected(c, req);
		Overlay o = overlays.get(Overlay.id(c, e.key, name));
		if (o == null) {
			throw new SessionException(SessionException.NOT_FOUND,
				"this client has no overlay '" + name + "' on " + e.key);
		}
		JsonArray log;
		String sha;
		o.lock.readLock().lock();
		try {
			log = o.log.deepCopy();
			sha = o.sha256;
		}
		finally {
			o.lock.readLock().unlock();
		}
		if (log.isEmpty()) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"overlay '" + name + "' has no changes to promote");
		}
		String target = Json.str(req, "project", null);
		JsonObject fork = null;
		if (target == null) {
			JsonObject f = Json.obj(req, "fork");
			if (f == null) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"pass \"project\" (a project you opened writable, such as a fork) or " +
						"\"fork\": {\"path\": ...} to fork " + e.project.id + " first");
			}
			JsonObject freq = f.deepCopy();
			freq.addProperty("project", e.project.id);
			freq.addProperty("writable", true);
			fork = (JsonObject) s.forkCmds.forkProject(c, freq, m);
			target = fork.get("project").getAsString();
		}
		String path = Json.str(req, "path", e.path);
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		JsonObject info =
			(JsonObject) s.programCmds.openProgram(c,
				Json.of("path", target + ":" + path, "writable", true), m);
		String tsha = info.has("sha256") && !info.get("sha256").isJsonNull()
				? info.get("sha256").getAsString()
				: null;
		if (sha != null && tsha != null && !sha.equalsIgnoreCase(tsha)) {
			throw new SessionException(SessionException.CONFLICT,
				"the target " + info.get("key").getAsString() + " is another build (SHA-256 " +
					tsha + "); the overlay was made over " + sha,
				Json.of("target", info.get("key"), "sha256", tsha, "overlaySha256", sha));
		}
		// 3.12 (E2): overlays are RAM-only, so a killed promote leaves a fork with or without the
		// edits; the fork's sidecar says "promote: in-progress" until this reply is on its way
		ProjectEntry targetProject = s.projectsById.get(target);
		if (targetProject != null) {
			ProjectFork.markPromote(targetProject.resolved);
		}
		JsonObject areq = Json.of("program", info.get("key").getAsString());
		JsonElement results =
			s.access.withProgram(c, areq, "promote_overlay", true, true,
				t -> s.operations.applyOps(t.program, log));
		JsonElement saved = null;
		if (Json.bool(req, "save", true)) {
			saved = s.access.withProgram(c, areq, "save", true, true,
				t -> s.edits.save(t, Json.of("comment", "promote overlay " + name), m));
		}
		if (targetProject != null) {
			ProjectFork.clearPromote(targetProject.resolved);
		}
		Msg.info(s, c.label() + " promoted overlay " + name + " of " + e.key + " (" +
			log.size() + " operations) into " + info.get("key").getAsString());
		JsonObject out = Json.of("promoted", log.size(), "overlay", name, "from", e.key,
			"target", info.get("key"), "project", target, "results", results, "saved", saved);
		out.add("fork", fork);
		return out;
	}
}
