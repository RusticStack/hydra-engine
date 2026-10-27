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

import static ghidra.app.util.headless.session.Access.PROGRAM_KEY;
import static ghidra.app.util.headless.session.EditCommands.journal;
import static ghidra.app.util.headless.session.Operations.ops;
import static ghidra.app.util.headless.session.OverlayCommands.overlayScoped;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.function.Consumer;

import com.google.gson.*;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * The state of a headless session and its commands: any number of projects, each with any number
 * of programs, shared by any number of clients. Thread-safe: each client's requests run on that
 * client's own threads, so clients run concurrently, admitted by the {@link Scheduler}.
 * <p>
 * Lock order, always: a scheduler slot, then {@link #registry} (only to open, upgrade or close a
 * project), then one {@link ProjectEntry#lock}, then one {@link ProgramEntry#lock}. The maps are
 * concurrent and never held across a wait.
 * <p>
 * Session keeps the state, the client life cycle and the dispatch of a request to the
 * command classes; the commands live in {@link ProjectCommands},
 * {@link ProgramCommands} and the other command classes, which receive this session.
 * Adding a command: see {@code ARCHITECTURE.md} in the module directory.
 */
final class Session {

	static final int PROTOCOL_VERSION = 2;
	static final long CLEANUP_WAIT_MS = 600_000;

	private final long startedAt = System.currentTimeMillis();
	/** Guards opening, upgrading and closing projects, and the two project maps. */
	final Object registry = new Object();
	final Map<String, ProjectEntry> projects = new ConcurrentHashMap<>();
	final Map<String, ProjectEntry> projectsById = new ConcurrentHashMap<>();
	final AtomicInteger nextProject = new AtomicInteger(1);
	private final Map<Integer, Client> clients = new ConcurrentHashMap<>();
	private final AtomicInteger nextClient = new AtomicInteger(1);
	volatile boolean shuttingDown;
	final Scheduler scheduler;
	/** How long an unused read-only program or project stays open; 0: close at once. */
	final long keepWarmMs;
	volatile JsonObject listenInfo;
	/** How this JVM was started (mode, AOT, class cache, start-up time), for status. */
	volatile JsonObject launchInfo;

	/** Serves read-only opens of older-format programs from an upgraded copy. */
	final UpgradeCache upgradeCache;

	/**
	 * {@code fork_project} in {@code "auto"} mode refuses a full copy (one the file system cannot
	 * block-clone) larger than this; {@code "full"} copies anyway.
	 */
	volatile long forkCopyLimitBytes = 2048L << 20;

	/** The commands, by area (see the class comments). */
	final Access access = new Access(this);
	final ScriptCommands scripts = new ScriptCommands(this);
	final ImportCommands imports = new ImportCommands(this);
	final Operations operations = new Operations(this);
	final EditCommands edits = new EditCommands(this);
	final QueryCommands queries = new QueryCommands(this);
	final OverlayCommands overlayCmds = new OverlayCommands(this);
	final ProgramCommands programCmds = new ProgramCommands(this);
	final ProjectCommands projectCmds = new ProjectCommands(this);
	final ForkCommands forkCmds = new ForkCommands(this);

	Session(Scheduler scheduler, long keepWarmSeconds, UpgradeCache upgradeCache) {
		this.scheduler = scheduler;
		this.keepWarmMs = Math.max(0, keepWarmSeconds) * 1000;
		this.upgradeCache = upgradeCache;
	}

	// ---- clients ---------------------------------------------------------------------------

	Client connect(String transport, boolean launcher, Consumer<JsonObject> events) {
		Client c = new Client(nextClient.getAndIncrement(), transport, launcher, events);
		clients.put(c.id, c);
		return c;
	}

	/**
	 * Releases everything a client still holds: its requests are cancelled, its unsaved changes
	 * discarded (and logged), and it leaves every project it joined.
	 */
	void disconnect(Client c) {
		c.running.values().forEach(RequestMonitor::cancel);
		List<String> joined;
		synchronized (c.projects) {
			joined = new ArrayList<>(c.projects);
		}
		for (String id : joined) {
			ProjectEntry p = projectsById.get(id);
			if (p == null) {
				continue;
			}
			try {
				projectCmds.leaveProject(c, p, true, CLEANUP_WAIT_MS);
			}
			catch (RuntimeException ex) {
				Msg.error(this, c.label() + " disconnect: could not leave project " + id, ex);
			}
		}
		clients.remove(c.id);
		Msg.info(this, c.label() + " disconnected");
	}

	int clientCount() {
		return clients.size();
	}

	boolean isShuttingDown() {
		return shuttingDown;
	}

	/** Closes everything. Unsaved changes are discarded and logged. Idempotent. */
	void close() {
		synchronized (registry) {
			if (shuttingDown && projectsById.isEmpty()) {
				return;
			}
			shuttingDown = true;
			clients.values().forEach(c -> c.running.values().forEach(RequestMonitor::cancel));
			// a background build is cancelled and deletes its temporary folder, or is left to
			// the exit (the next start removes its folder)
			upgradeCache.shutdown(3_000);
			for (ProjectEntry p : new ArrayList<>(projectsById.values())) {
				try {
					projectCmds.closeProjectEntry(p, 30_000, true);
				}
				catch (RuntimeException e) {
					Msg.error(this, "shutdown: could not close project " + p.id, e);
				}
			}
		}
	}

	/**
	 * Closes read-only programs and projects that nobody has used for {@link #keepWarmMs}, and
	 * programs upgraded in memory that nobody uses once their upgrade cache copy is ready (the
	 * next open takes the copy, and the in-memory upgrade's temporary database is freed). Never
	 * waits: anything in use is left for the next round.
	 */
	void reap() {
		long now = System.currentTimeMillis();
		for (ProjectEntry p : projectsById.values()) {
			for (ProgramEntry e : p.programs.values()) {
				if (e.userCount() == 0 && !e.holdsOrphanedWork() &&
					(now - e.lastUsed >= keepWarmMs || programCmds.swappable(e))) {
					closeIdleProgram(p, e);
				}
			}
			if (p.userCount() == 0 && p.programs.isEmpty() && now - p.lastUsed >= keepWarmMs) {
				synchronized (registry) {
					if (p.userCount() == 0 && p.programs.isEmpty() && !p.closed) {
						try {
							projectCmds.closeProjectEntry(p, 0, true);
							Msg.info(this, "closed idle project " + p.id + " " + p.canonical);
						}
						catch (SessionException e) {
							// in use after all; next round
						}
					}
				}
			}
		}
	}

	private void closeIdleProgram(ProjectEntry p, ProgramEntry e) {
		Lock pl = p.lock.readLock();
		if (!pl.tryLock()) {
			return;
		}
		try {
			if (!e.lock.writeLock().tryLock()) {
				return;
			}
			try {
				if (e.userCount() == 0 && p.programs.get(e.path) == e) {
					programCmds.disposeProgram(e);
					Msg.info(this, "closed idle program " + e.key);
				}
			}
			finally {
				e.lock.writeLock().unlock();
			}
		}
		finally {
			pl.unlock();
		}
	}

	// ---- dispatch --------------------------------------------------------------------------

	/** Commands answered on the connection's reader thread, even while another runs. */
	static boolean isInline(String cmd) {
		return cmd.equals("ping") || cmd.equals("cancel") || cmd.equals("status");
	}

	JsonElement execute(Client c, String cmd, JsonObject req, RequestMonitor m) {
		if (shuttingDown && !cmd.equals("shutdown") && !cmd.equals("ping")) {
			throw new SessionException(SessionException.CONFLICT, "the session is shutting down");
		}
		switch (cmd) {
			case "ping":
				return Json.of("pong", true);
			case "hello":
				return hello(c, req);
			case "status":
				return status(c);
			case "cancel":
				return cancel(c, req);
			case "shutdown":
				return shutdownCheck(c, req);
			case "projects":
				return projectsCmd(c);
			case "programs":
				return programCmds.programs(c);
			default:
				break;
		}
		// An import queues for the import gate (maxImports) first and takes its long slot only
		// when it is its turn (importProgram), so that queued imports do not occupy the slots
		// that analysis and scripts need.
		Scheduler.Ticket slot = cmd.equals("import") ? null : scheduler.admit(c, cmd, m, waitMs(req));
		try {
			if (cmd.equals("script") || cmd.equals("import") || cmd.equals("analyze")) {
				DeferredInit.await(); // the TLS context and the script framework
			}
			if (Json.has(req, "overlay") && overlayScoped(cmd)) {
				return overlayCmds.overlayCommand(c, cmd, req, m);
			}
			return switch (cmd) {
				case "open_project" -> projectCmds.openProject(c, req);
				case "overlays" -> overlayCmds.listOverlays(c);
				case "promote_overlay" -> overlayCmds.promoteOverlay(c, req, m);
				case "apply_overlay", "drop_overlay" -> throw new SessionException(
					SessionException.BAD_REQUEST, "missing field: overlay");
				case "fork_project" -> forkCmds.forkProject(c, req, m);
				case "refresh", "reopen" -> projectCmds.refresh(c, req, m);
				case "close_project" -> projectCmds.closeProject(c, req);
				case "project" -> access.inProject(access.projectFor(c, req), req, cmd,
					ProjectEntry::info);
				case "list" -> {
					ProjectEntry p = access.projectFor(c, req);
					yield access.inProject(p, req, cmd, x -> projectCmds.list(x, req));
				}
				case "open_program", "switch" -> programCmds.openProgram(c, req, m);
				case "info" -> access.withProgram(c, req, cmd, false, false,
					e -> programCmds.programInfo(e, c));
				case "close_program" -> programCmds.closeProgram(c, req);
				case "save" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.save(e, req, m));
				case "functions" -> access.withProgram(c, req, cmd, false, false,
					e -> queries.functions(e.program, req));
				case "decompile" -> access.withProgram(c, req, cmd, false, false,
					e -> queries.decompile(e.program, e, req, m));
				case "rename" -> access.withProgram(c, req, cmd, true, true,
					e -> journal(c, e, cmd, "rename", operations.renameIn(e.program, req)));
				case "edit" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.editProgram(c, e, ops(req, null)));
				case "journal" -> access.withProgram(c, req, cmd, false, false,
					e -> edits.journalOf(e, req));
				case "discard_edits" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.discardEdits(c, e, req));
				case "comment" -> access.withProgram(c, req, cmd, true, true,
					e -> journal(c, e, cmd, "comment", operations.commentIn(e.program, req)));
				case "analyze" -> access.withProgram(c, req, cmd, true, true, e -> {
					JsonObject r = (JsonObject) edits.analyze(e, req, m);
					return journal(c, e, cmd, "analyze", Json.of("functions", r.get("functions")));
				});
				case "import" -> imports.importProgram(c, req, m);
				case "script" -> scripts.script(c, req, m);
				default -> throw new SessionException(SessionException.UNKNOWN_COMMAND,
					"unknown cmd '" + cmd + "'; send status or see the README for the list");
			};
		}
		finally {
			if (slot != null) {
				slot.close();
			}
		}
	}

	// ---- session ---------------------------------------------------------------------------

	private JsonElement hello(Client c, JsonObject req) {
		c.name = Json.str(req, "client", c.name);
		c.harness = Json.str(req, "harness", c.harness);
		c.clientVersion = Json.str(req, "clientVersion", c.clientVersion);
		JsonObject o = info();
		Json.put(o, "client", c.id);
		return o;
	}

	JsonObject info() {
		Runtime rt = Runtime.getRuntime();
		JsonObject o = Json.of("protocol", PROTOCOL_VERSION, "minClient", HydraInfo.minClient(),
			"hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
			Application.getApplicationVersion(), "installId", HydraInfo.installId(), "startedAt",
			startedAt, "ghidra", Application.getApplicationVersion(), "install",
			Application.getInstallationDirectory().getAbsolutePath(), "java",
			System.getProperty("java.version"), "pid", ProcessHandle.current().pid(), "uptimeMs",
			System.currentTimeMillis() - startedAt, "listen", listenInfo, "launch", launchInfo,
			"keepWarmS", keepWarmMs / 1000, "memory",
			Json.of("usedMb", (rt.totalMemory() - rt.freeMemory()) >> 20, "committedMb",
				rt.totalMemory() >> 20, "maxMb", rt.maxMemory() >> 20));
		JsonArray ps = new JsonArray();
		for (ProjectEntry p : projectsById.values()) {
			ps.add(p.info());
		}
		o.add("projects", ps);
		return o;
	}

	private JsonElement status(Client c) {
		JsonObject o = info();
		Json.put(o, "you", c.id);
		JsonArray ps = new JsonArray();
		for (ProjectEntry p : projectsById.values()) {
			for (ProgramEntry e : p.programs.values()) {
				ps.add(e.describeUse(upgradeCache));
			}
		}
		o.add("programs", ps);
		JsonArray cs = new JsonArray();
		for (Client x : clients.values()) {
			cs.add(x.describe());
		}
		o.add("clients", cs);
		JsonArray ovs = new JsonArray();
		for (Overlay x : overlayCmds.overlays.values()) {
			ovs.add(x.describe());
		}
		o.add("overlays", ovs);
		o.add("scheduler", scheduler.describe());
		o.add("imports", ImportGate.GLOBAL.describe());
		Caller.Identity me = Caller.current(c);
		if (me != null) {
			Json.put(o, "youAre", Json.of("client", me.name(), "harness", me.harness(),
				"labelled", me.labelled()));
		}
		o.add("upgradeCache", upgradeCache.describe());
		Json.put(o, "deferredInitMs", DeferredInit.doneMs());
		return o;
	}

	private JsonElement cancel(Client c, JsonObject req) {
		if (Json.has(req, "cacheBuild")) {
			// a background upgrade cache build: by build id, cache key, program path or key, "all"
			String which = Json.str(req, "cacheBuild");
			ProgramEntry e = PROGRAM_KEY.matcher(which).matches() ? access.entryByKey(which) : null;
			if (e != null && e.cachePlan != null) {
				which = e.cachePlan.id();
			}
			return Json.of("cancelled", upgradeCache.cancel(which));
		}
		// A cancel that carries a client/harness label reaches only requests of that same label.
		Caller.Identity who = Caller.current(c);
		String scope = who == null ? null : who.scope();
		if (Json.bool(req, "all", false)) {
			int n = 0;
			for (Map.Entry<String, RequestMonitor> e : c.running.entrySet()) {
				if (req.has("id") && req.get("id").toString().equals(e.getKey())) {
					continue; // not this cancel itself
				}
				if (scope != null && !scope.equals(e.getValue().scope())) {
					continue; // another caller's request on this connection
				}
				e.getValue().cancel();
				n++;
			}
			return Json.of("cancelled", n, "scope", scope == null ? null : who.name() + " / " +
				who.harness());
		}
		if (!req.has("target")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: target (the id of your request), or \"all\":true");
		}
		RequestMonitor m = c.running.get(req.get("target").toString());
		if (m != null && scope != null && m.scope() != null && !scope.equals(m.scope())) {
			return Json.of("cancelled", false, "note",
				"that request belongs to another caller on this connection");
		}
		if (m != null) {
			m.cancel();
		}
		return Json.of("cancelled", m != null);
	}

	private JsonElement shutdownCheck(Client c, JsonObject req) {
		long others = clients.values().stream().filter(x -> x != c && !x.leaving).count();
		if (!c.launcher && others > 0 && !Json.bool(req, "force", false)) {
			throw new SessionException(SessionException.CONFLICT,
				others + " other client(s) are connected; pass \"force\":true to stop anyway",
				Json.of("clients", others));
		}
		return Json.of("stopping", true);
	}

	private JsonElement projectsCmd(Client c) {
		JsonArray a = new JsonArray();
		for (ProjectEntry p : projectsById.values()) {
			JsonObject j = p.info();
			Json.put(j, "joined", c.projects.contains(p.id));
			Json.put(j, "active", p.id.equals(c.activeProject));
			a.add(j);
		}
		return Json.of("activeProject", c.activeProject, "projects", a);
	}

	// ---- revisions -------------------------------------------------------------------------

	/**
	 * Adds to a response what changed under this client: {@code "stale"} lists its read-only
	 * views whose project another process saved since they were opened (send {@code refresh}),
	 * and {@code "refreshed"} the projects someone else refreshed since this client last heard,
	 * once each (answers it kept from before came from the older revision).
	 */
	void annotate(Client c, JsonObject resp) {
		List<String> joined;
		synchronized (c.projects) {
			joined = new ArrayList<>(c.projects);
		}
		JsonArray stale = new JsonArray();
		JsonArray refreshed = new JsonArray();
		for (String id : joined) {
			ProjectEntry p = projectsById.get(id);
			if (p == null || p.closed) {
				continue;
			}
			int gen = p.generation;
			Integer seen = c.seenGeneration.put(id, gen);
			if (seen != null && seen < gen) {
				refreshed.add(Json.of("project", id, "generation", gen, "from", p.previousRevision,
					"revision", p.openRevision));
			}
			if (p.stale()) {
				stale.add(Json.of("project", id, "revision", p.openRevision, "diskRevision",
					p.diskRevision(), "suggest", "refresh"));
			}
		}
		if (!stale.isEmpty()) {
			resp.add("stale", stale);
		}
		if (!refreshed.isEmpty()) {
			resp.add("refreshed", refreshed);
		}
	}
}
