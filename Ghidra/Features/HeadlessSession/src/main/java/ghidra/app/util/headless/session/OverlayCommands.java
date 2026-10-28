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
			JsonObject info = (JsonObject) s.programCmds.openProgram(c, plain, m);
			ProgramEntry e = s.access.entryByKey(info.get("key").getAsString());
			if (e == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					info.get("key").getAsString() + " was closed meanwhile");
			}
			Overlay o = openOverlay(c, e, name, waitMs(req), m);
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
				if (o.error != null || o.program == null) {
					JsonObject d = o.describe();
					d.add("log", o.log.deepCopy());
					throw new SessionException(SessionException.CONFLICT,
						"overlay '" + name + "' is unusable: " + o.error +
							"; drop_overlay it (its log is in details.log)",
						d);
				}
				return switch (cmd) {
					case "info" -> overlayInfo(o);
					case "functions" -> withOverlay(o, s.queries.functions(o.program, req));
					case "decompile" -> withOverlay(o, s.queries.decompile(o.program, o, req, m));
					case "script" -> {
						ResourceFile src = findScript(Json.str(req, "script"));
						m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
						yield withOverlay(o,
							s.scripts.runScript(src, req, p.project, o.program, null, "contained",
								m));
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
			Lock l = e.acquire(false, wait, c, "open_program overlay");
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
				Msg.info(s, c.label() + " opened overlay " + name + " of " + e.key + " in " +
					o.openMs + " ms");
				return o;
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
	 * Opens the overlay's own program object (from the upgrade cache copy when the shared program
	 * came from one) and replays its log. Held: the overlay's write lock and the program's lock.
	 */
	private void loadOverlay(Overlay o, RequestMonitor m) {
		ProgramEntry e = o.base;
		long t0 = System.nanoTime();
		Program prog = null;
		try {
			if (e.cacheView != null && e.cachePlan != null) {
				UpgradeCache.Opened op = s.upgradeCache.openReady(e.cachePlan, o, m);
				if (op != null) {
					prog = op.program();
					o.view = op.view();
					o.lease = op.lease();
				}
			}
			if (prog == null) {
				prog = (Program) e.file.getReadOnlyDomainObject(o, DomainFile.DEFAULT_VERSION, m);
			}
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				e.path + " was saved by another Ghidra version: " + ex.getMessage());
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
		o.program = prog;
		o.openMs = (System.nanoTime() - t0) / 1_000_000;
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

	/** Applies operations to the overlay as one unit, and logs them. Held: its write lock. */
	private JsonObject applyOverlay(Overlay o, JsonArray ops) {
		JsonArray results = s.operations.applyOps(o.program, ops);
		for (JsonElement op : ops) {
			o.log.add(op.deepCopy());
		}
		o.version++;
		return Json.of("overlay", o.describe(), "applied", ops.size(), "results", results);
	}

	/** {@code info} of an overlay: the program as this overlay shows it. */
	private JsonObject overlayInfo(Overlay o) {
		Program p = o.program;
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
