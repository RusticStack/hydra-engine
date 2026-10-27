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
import static ghidra.app.util.headless.session.Access.firstOf;
import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Access.unlockProject;
import static ghidra.app.util.headless.session.EditCommands.journal;
import static ghidra.app.util.headless.session.Operations.ops;
import static ghidra.app.util.headless.session.OverlayCommands.overlayScoped;
import static ghidra.app.util.headless.session.Requests.cancelled;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.function.Consumer;

import com.google.gson.*;

import ghidra.framework.Application;
import ghidra.framework.model.*;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.*;
import utilities.util.FileUtilities;

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
 * Adding a command: see {@code docs/architecture.md}.
 */
final class Session {

	static final int PROTOCOL_VERSION = 2;
	static final long CLEANUP_WAIT_MS = 600_000;

	private final long startedAt = System.currentTimeMillis();
	/** Guards opening, upgrading and closing projects, and the two project maps. */
	private final Object registry = new Object();
	final Map<String, ProjectEntry> projects = new ConcurrentHashMap<>();
	final Map<String, ProjectEntry> projectsById = new ConcurrentHashMap<>();
	private final AtomicInteger nextProject = new AtomicInteger(1);
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
				leaveProject(c, p, true, CLEANUP_WAIT_MS);
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
					closeProjectEntry(p, 30_000, true);
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
							closeProjectEntry(p, 0, true);
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
				case "open_project" -> openProject(c, req);
				case "overlays" -> overlayCmds.listOverlays(c);
				case "promote_overlay" -> overlayCmds.promoteOverlay(c, req, m);
				case "apply_overlay", "drop_overlay" -> throw new SessionException(
					SessionException.BAD_REQUEST, "missing field: overlay");
				case "fork_project" -> forkProject(c, req, m);
				case "refresh", "reopen" -> refresh(c, req, m);
				case "close_project" -> closeProject(c, req);
				case "project" -> access.inProject(access.projectFor(c, req), req, cmd, ProjectEntry::info);
				case "list" -> {
					ProjectEntry p = access.projectFor(c, req);
					yield access.inProject(p, req, cmd, x -> list(x, req));
				}
				case "open_program", "switch" -> programCmds.openProgram(c, req, m);
				case "info" -> access.withProgram(c, req, cmd, false, false, e -> programCmds.programInfo(e, c));
				case "close_program" -> programCmds.closeProgram(c, req);
				case "save" -> access.withProgram(c, req, cmd, true, true, e -> edits.save(e, req, m));
				case "functions" -> access.withProgram(c, req, cmd, false, false,
					e -> queries.functions(e.program, req));
				case "decompile" -> access.withProgram(c, req, cmd, false, false,
					e -> queries.decompile(e.program, e, req, m));
				case "rename" -> access.withProgram(c, req, cmd, true, true,
					e -> journal(c, e, cmd, "rename", operations.renameIn(e.program, req)));
				case "edit" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.editProgram(c, e, ops(req, null)));
				case "journal" -> access.withProgram(c, req, cmd, false, false, e -> edits.journalOf(e, req));
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

	/**
	 * Joins a project, opening it if no client has it open. A writable request on a read-only
	 * view reopens it writable in place, also while other clients use it ({@link #makeWritable});
	 * a writable request on a writable project, and a read-only request on one, join it.
	 */
	private JsonElement openProject(Client c, JsonObject req) {
		ProjectResolver.Resolved r;
		String canonical;
		try {
			r = ProjectResolver.resolve(Json.str(req, "path"));
			canonical = r.gpr().getCanonicalPath();
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		boolean writable = Json.bool(req, "writable", false);
		boolean discard = Json.bool(req, "discard", false);
		long wait = waitMs(req);
		ProjectEntry p;
		boolean opened = false;
		synchronized (registry) {
			if (shuttingDown) {
				throw new SessionException(SessionException.CONFLICT, "the session is shutting down");
			}
			p = projects.get(canonical);
			if (p != null && writable && !p.writable()) {
				// readers keep using it: the view is reopened writable in place, same id
				makeWritable(c, p, wait);
			}
			if (p == null) {
				p = openProjectEntry(c, r, canonical, writable);
				opened = true;
			}
			synchronized (p.users) {
				p.users.add(c);
			}
			p.joinedAt.putIfAbsent(c, System.currentTimeMillis());
			c.seenGeneration.putIfAbsent(p.id, p.generation);
			c.projects.add(p.id);
			c.activeProject = p.id;
			p.lastUsed = System.currentTimeMillis();
		}
		JsonObject info = p.info();
		Json.put(info, "opened", opened);
		return info;
	}

	/**
	 * Reopens a read-only view writable in place, while its clients keep using it: the project
	 * is opened writable (taking its lock), then under the project's exclusive lock (requests
	 * running on it finish first) it replaces the view, and every program clients use is reopened
	 * from it under the same key, read-only, with its overlays rebuilt. The id, the keys and the
	 * clients' joins stay. Held: {@link #registry}.
	 */
	private void makeWritable(Client c, ProjectEntry p, long wait) {
		ProjectLocator locator = new ProjectLocator(p.resolved.dir().getPath(), p.resolved.name());
		String rev;
		try {
			rev = Revision.of(p.resolved);
		}
		catch (IOException e) {
			rev = null;
		}
		SessionProject nv;
		try {
			nv = SessionProject.open(locator, true);
		}
		catch (LockException e) {
			JsonObject d = p.identity();
			Json.put(d, "lockFile", locator.getProjectLockFile().getPath());
			d.add("holderInfo", ProjectLocks.holder(locator));
			Json.put(d, "suggest", "open_read_only");
			throw new SessionException(SessionException.CONFLICT,
				"the project is locked by another process (a Ghidra window, analyzeHeadless or a " +
					"writable session): keep the read-only view, or close that process",
				d, e);
		}
		catch (NotOwnerException e) {
			throw new SessionException(SessionException.CONFLICT, e.getMessage());
		}
		catch (NotFoundException | IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage(), null, e);
		}
		Lock l;
		try {
			l = lockProject(p, true, wait, "open_project writable");
			p.exclusiveClient = c;
		}
		catch (RuntimeException e) {
			nv.close();
			throw e;
		}
		SessionProject old = p.project;
		JsonArray progs;
		try {
			progs = swapView(p, nv, rev, new RequestMonitor(null, null));
		}
		finally {
			unlockProject(p, l);
		}
		try {
			old.close();
		}
		catch (RuntimeException e) {
			Msg.warn(this, "could not close the read-only view of " + p.id, e);
		}
		Msg.info(this, c.label() + " reopened project " + p.id + " writable in place for " +
			p.userCount() + " client(s): " + progs);
	}

	/**
	 * Replaces a project's view with {@code nv} (from revision {@code rev}) and reopens its
	 * programs from it. Held: the project's exclusive lock.
	 */
	private JsonArray swapView(ProjectEntry p, SessionProject nv, String rev, RequestMonitor m) {
		JsonArray progs = new JsonArray();
		p.project = nv;
		p.previousRevision = p.openRevision;
		p.openRevision = rev;
		p.invalidateRevision();
		p.generation++;
		p.refreshedAt = System.currentTimeMillis();
		for (ProgramEntry e : new ArrayList<>(p.programs.values())) {
			progs.add(reopenIn(p, nv, e, m));
		}
		return progs;
	}

	/** Held: {@link #registry}. */
	private ProjectEntry openProjectEntry(Client c, ProjectResolver.Resolved r, String canonical,
			boolean writable) {
		ProjectLocator locator;
		try {
			locator = new ProjectLocator(r.dir().getPath(), r.name());
		}
		catch (IllegalArgumentException e) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"Ghidra cannot open this path: " + e.getMessage());
		}
		long t0 = System.nanoTime();
		String revision;
		try {
			revision = Revision.of(r);
		}
		catch (IOException e) {
			revision = null;
		}
		SessionProject sp;
		try {
			sp = SessionProject.open(locator, writable);
		}
		catch (LockException e) {
			JsonObject d = Json.of("gpr", r.gpr().getPath(), "name", r.name(), "lockFile",
				locator.getProjectLockFile().getPath());
			d.add("holderInfo", ProjectLocks.holder(locator));
			Json.put(d, "suggest", "open_read_only");
			throw new SessionException(SessionException.CONFLICT,
				"the project is locked by another process (a Ghidra window, analyzeHeadless or a " +
					"writable session): open it read-only, or close that process",
				d, e);
		}
		catch (NotOwnerException e) {
			throw new SessionException(SessionException.CONFLICT, e.getMessage());
		}
		catch (NotFoundException | IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage(), null, e);
		}
		String id = "p" + nextProject.getAndIncrement();
		ProjectEntry p = new ProjectEntry(id, r, canonical, sp, (System.nanoTime() - t0) / 1_000_000);
		p.openRevision = revision;
		projects.put(canonical, p);
		projectsById.put(id, p);
		Msg.info(this, c.label() + " opened project " + id + " " + r.gpr() +
			(writable ? " (writable)" : " (read-only view)") + " in " + p.openMs + " ms");
		return p;
	}

	/**
	 * Closes a project for everyone. Held: {@link #registry}. Refused while a program has unsaved
	 * changes, unless {@code discard}.
	 */
	private void closeProjectEntry(ProjectEntry p, long wait, boolean discard) {
		if (!discard) {
			for (ProgramEntry e : p.programs.values()) {
				if (e.program != null && e.program.isChanged()) {
					throw new SessionException(SessionException.UNSAVED_CHANGES,
						"cannot close project " + p.id + ": " + e.path +
							" has unsaved changes; save, or pass \"discard\":true",
						Json.of("program", e.key));
				}
			}
		}
		Lock l = lockProject(p, true, wait, "close_project");
		try {
			for (ProgramEntry e : new ArrayList<>(p.programs.values())) {
				if (e.program != null && e.program.isChanged()) {
					Msg.warn(this, "closing project " + p.id + ": discarding unsaved changes in " +
						e.path);
				}
				programCmds.closeEntry(e);
			}
			p.closed = true;
			p.project.close();
		}
		finally {
			unlockProject(p, l);
			projects.remove(p.canonical, p);
			projectsById.remove(p.id, p);
			List<Client> users;
			synchronized (p.users) {
				users = new ArrayList<>(p.users);
				p.users.clear();
			}
			p.joinedAt.clear();
			for (Client u : users) {
				u.projects.remove(p.id);
				if (p.id.equals(u.activeProject)) {
					u.activeProject = firstOf(u.projects);
				}
			}
		}
	}

	private JsonElement closeProject(Client c, JsonObject req) {
		ProjectEntry p = access.projectFor(c, req);
		boolean closed = leaveProject(c, p, Json.bool(req, "discard", false), waitMs(req));
		return Json.of("project", p.id, "left", true, "closed", closed, "activeProject",
			c.activeProject);
	}

	/**
	 * This client stops using a project: it closes its programs there (see
	 * {@link #releaseUse}), and the project closes when nobody uses it any more, at once when it
	 * is writable (its lock is released for other processes), after {@link #keepWarmMs} when it
	 * is a read-only view. Returns true when the project was closed.
	 */
	private boolean leaveProject(Client c, ProjectEntry p, boolean discard, long wait) {
		List<String> mine;
		synchronized (c.programs) {
			mine = c.programs.stream().filter(k -> k.startsWith(p.id + ":")).toList();
		}
		for (String key : mine) {
			ProgramEntry e = p.programs.get(key.substring(p.id.length() + 1));
			if (e == null) {
				c.programs.remove(key);
				continue;
			}
			Lock pl = lockProject(p, false, wait, "close_project");
			try {
				boolean discarded = programCmds.releaseUse(c, e, discard, wait);
				if (discarded) {
					Msg.warn(this, c.label() + " left " + p.id + ": discarded unsaved changes in " +
						e.path);
				}
			}
			finally {
				pl.unlock();
			}
		}
		synchronized (registry) {
			synchronized (p.users) {
				p.users.remove(c);
			}
			p.joinedAt.remove(c);
			c.seenGeneration.remove(p.id);
			c.projects.remove(p.id);
			if (p.id.equals(c.activeProject)) {
				c.activeProject = firstOf(c.projects);
			}
			p.lastUsed = System.currentTimeMillis();
			if (!p.closed && p.userCount() == 0 && (p.writable() || keepWarmMs == 0) &&
				p.programs.values().stream().noneMatch(ProgramEntry::holdsOrphanedWork)) {
				closeProjectEntry(p, wait, true);
				return true;
			}
		}
		return false;
	}

	// ---- forks -----------------------------------------------------------------------------

	/**
	 * {@code fork_project}: a working copy of a project, made with the platform's copy (a block
	 * clone on ReFS), opened for this client (writable by default) and registered like any other
	 * project. The source is only read: its read-only views stay open and in use. A source that
	 * someone writes (another client here, or another process through the project lock) is
	 * refused, because its saved state may change under the copy; a source this client alone holds
	 * writable is forked when nothing in it is unsaved, under its exclusive lock. The fork records
	 * its source and the source's revision in its sidecar ({@link ProjectFork}).
	 */
	JsonElement forkProject(Client c, JsonObject req, RequestMonitor m) {
		long t0 = System.nanoTime();
		String srcKey = Json.str(req, "project", c.activeProject);
		if (srcKey == null) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: project (an open project's id, or a project path)");
		}
		ProjectEntry src = projectsById.get(srcKey);
		ProjectResolver.Resolved r;
		String canonical;
		try {
			r = src != null ? src.resolved : ProjectResolver.resolve(srcKey);
			canonical = r.gpr().getCanonicalPath();
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		if (src == null) {
			src = projects.get(canonical);
		}
		if (src != null && src.closed) {
			src = null;
		}
		String mode = Json.str(req, "mode", "auto");
		if (!mode.equals("auto") && !mode.equals("copy-on-write") && !mode.equals("full")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"mode must be auto, copy-on-write or full");
		}
		boolean writable = Json.bool(req, "writable", true);
		long limit = Json.has(req, "maxCopyMb")
				? Json.num(req, "maxCopyMb", 0, 0, Long.MAX_VALUE >> 20) << 20
				: forkCopyLimitBytes;
		// the destination: a folder (the fork keeps the source's name, or "name"), or a .gpr path
		File dest = new File(Json.str(req, "path")).getAbsoluteFile();
		File destDir;
		String name;
		if (dest.getName().endsWith(ProjectLocator.getProjectExtension())) {
			destDir = dest.getParentFile();
			name = dest.getName()
					.substring(0,
						dest.getName().length() - ProjectLocator.getProjectExtension().length());
		}
		else {
			destDir = dest;
			name = Json.str(req, "name", r.name());
		}
		if (name.isEmpty() || !name.matches("[^\\\\/:*?\"<>|]+")) {
			throw new SessionException(SessionException.BAD_REQUEST, "bad project name: " + name);
		}
		File destGpr = new File(destDir, name + ProjectLocator.getProjectExtension());
		File destRep = new File(destDir, name + ProjectLocator.getProjectDirExtension());
		try {
			String srcDir = r.dir().getCanonicalPath();
			String rep = new File(r.dir(), r.name() + ProjectLocator.getProjectDirExtension())
					.getCanonicalPath();
			String dd = destDir.getCanonicalPath();
			if (dd.equals(srcDir) && name.equals(r.name()) ||
				(dd + File.separator).startsWith(rep + File.separator)) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"the fork must not be the source or inside its .rep: " + dest);
			}
		}
		catch (IOException e) {
			throw new SessionException(SessionException.BAD_REQUEST, e.getMessage());
		}
		if (destGpr.exists() || destRep.exists() || ProjectFork.sidecar(
			new ProjectResolver.Resolved(destDir, name)).exists()) {
			throw new SessionException(SessionException.CONFLICT,
				"a project named " + name + " already exists in " + destDir +
					"; pick another path (forks are never overwritten)",
				Json.of("path", destGpr.getPath(), "suggest", "another path"));
		}
		ProjectLocator locator = new ProjectLocator(r.dir().getPath(), r.name());
		Lock held = null;
		ProjectFork.Cost cost;
		ProjectFork.Copied copied;
		String baseRevision;
		JsonObject parent = ProjectFork.readSidecar(r);
		try {
			if (src != null && src.writable()) {
				// in this daemon: forkable only by its sole user, with nothing unsaved
				JsonArray others = src.holders(c);
				if (!others.isEmpty()) {
					JsonObject d = src.identity();
					d.add("holders", others);
					Json.put(d, "suggest", "retry");
					throw new SessionException(SessionException.CONFLICT,
						"project " + src.id + " is open writable and used by another client; a " +
							"fork copies the saved state, which its writer may change meanwhile. " +
							"Fork a read-only master instead, or retry once its writer has " +
							"saved and left",
						d);
				}
				for (ProgramEntry e : src.programs.values()) {
					if (e.program != null && e.program.isChanged()) {
						throw new SessionException(SessionException.UNSAVED_CHANGES,
							e.key + " has unsaved changes; save before forking (a fork copies " +
								"what is saved)",
							e.identity());
					}
				}
				held = lockProject(src, true, waitMs(req), "fork_project");
				src.exclusiveClient = c;
			}
			else if (ProjectLocks.held(locator)) {
				JsonObject d = Json.of("gpr", r.gpr().getPath(), "name", r.name());
				d.add("holderInfo", ProjectLocks.holder(locator));
				Json.put(d, "suggest", "retry");
				throw new SessionException(SessionException.CONFLICT,
					"another process holds project " + r.name() + " writable (its lock file is " +
						"held); a fork copies the saved state, which that process may change " +
						"meanwhile. Retry once it has closed the project",
					d);
			}
			try {
				cost = ProjectFork.cost(r, destDir);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED, e.getMessage(), null, e);
			}
			JsonObject costJson = cost.json();
			Json.put(costJson, "limitBytes", limit);
			if (mode.equals("copy-on-write") && !cost.cloneCapable()) {
				Json.put(costJson, "reason", "no_copy_on_write");
				Json.put(costJson, "suggest", "mode full");
				throw new SessionException(SessionException.CONFLICT,
					"a copy-on-write fork needs the destination on the source's volume and a " +
						"file system that block-clones (ReFS on Windows); here it would be a " +
						"full copy of " + cost.bytes() + " bytes. Pass \"mode\":\"full\" to copy",
					costJson);
			}
			if (mode.equals("auto") && !cost.cloneCapable() && cost.bytes() > limit) {
				Json.put(costJson, "reason", "too_large");
				Json.put(costJson, "suggest", "mode full");
				throw new SessionException(SessionException.CONFLICT,
					"this fork would be a full copy of " + cost.bytes() + " bytes, over the " +
						"limit of " + limit + "; pass \"mode\":\"full\" to copy anyway, or fork " +
						"onto the source's volume where it can be block-cloned",
					costJson);
			}
			if (!cost.cloneCapable() && cost.bytes() > cost.destFreeBytes()) {
				throw new SessionException(SessionException.FAILED,
					"not enough free space for a full copy of " + cost.bytes() + " bytes",
					costJson);
			}
			try {
				Map<String, String> filesBefore = Revision.files(r);
				baseRevision = Revision.of(r);
				m.setMessage("forking " + r.name() + " (" + cost.files() + " files)");
				copied = ProjectFork.copy(r, destDir, name, m);
				String after = Revision.of(r);
				if (!after.equals(baseRevision)) {
					List<String> changed = Revision.changed(filesBefore, Revision.files(r));
					FileUtilities.deleteDir(destRep);
					destGpr.delete();
					JsonObject d = Json.of("gpr", r.gpr().getPath(), "suggest", "retry");
					Json.put(d, "changed", changed.subList(0, Math.min(20, changed.size())));
					throw new SessionException(SessionException.CONFLICT,
						"the source changed while it was copied (revision " + baseRevision +
							", now " + after + "); the copy was removed. Retry",
						d);
				}
			}
			catch (CancelledException e) {
				throw cancelled(m);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED,
					"fork failed: " + e.getMessage(), null, e);
			}
		}
		finally {
			if (held != null) {
				unlockProject(src, held);
			}
		}
		// what the copy cost, and whether the measurement shows a clone
		// A clone uses almost no space, a copy its size; other writers on the volume blur the
		// measurement, so it only decides for a fork large enough to stand out.
		long consumed = Math.max(0, copied.freeBefore() - copied.freeAfter());
		boolean measurable = cost.bytes() >= ProjectFork.MEASURABLE_BYTES;
		boolean cloned = cost.cloneCapable() && (!measurable || consumed < cost.bytes() / 2);
		String clonedBy = !cost.cloneCapable() ? "file system (no block clone)"
				: measurable ? "free space (" + consumed + " of " + cost.bytes() + " bytes used)"
						: "file system (under " + (ProjectFork.MEASURABLE_BYTES >> 20) +
							" MiB: too small to measure)";
		ProjectResolver.Resolved fr = new ProjectResolver.Resolved(destDir, name);
		JsonObject source = Json.of("project", src == null ? null : src.id, "gpr",
			r.gpr().getPath(), "canonical", canonical, "name", r.name(), "revision", baseRevision,
			"writable", src != null && src.writable(), "fork", parent != null);
		int depth = parent == null ? 1
				: (parent.has("depth") ? parent.get("depth").getAsInt() : 1) + 1;
		JsonObject sidecar = Json.of("format", ProjectFork.SIDECAR_FORMAT, "kind",
			"ghidra-session-fork", "source", source, "baseRevision", baseRevision, "createdAt",
			System.currentTimeMillis(), "created", java.time.Instant.now().toString(), "by",
			c.identity(), "mode", mode, "method", cost.cloneCapable() ? "clone" : "copy",
			"cloned", cloned, "clonedBy", clonedBy, "bytes", cost.bytes(), "files",
			cost.files(), "copyMs", copied.ms(), "depth", depth, "parent", parent);
		try {
			ProjectFork.writeSidecar(ProjectFork.sidecar(fr), sidecar);
		}
		catch (IOException e) {
			Msg.warn(this, "fork_project: could not write the sidecar of " + destGpr + ": " + e);
		}
		Msg.info(this, c.label() + " forked " + r.gpr() + " (revision " + baseRevision + ") to " +
			destGpr + ": " + cost.bytes() + " bytes, " + cost.files() + " files, " +
			(cost.cloneCapable() ? "clone" : "copy") + " in " + copied.ms() + " ms, " + consumed +
			" bytes of free space used");
		JsonObject open = Json.of("path", destGpr.getPath(), "writable", writable);
		if (req.has("wait")) {
			open.add("wait", req.get("wait"));
		}
		JsonObject info = (JsonObject) openProject(c, open);
		JsonObject out = Json.of("project", info.get("id"), "path", destDir.getPath(), "gpr",
			destGpr.getPath(), "name", name, "writable", writable, "source", source,
			"baseRevision", baseRevision, "mode", mode, "method",
			cost.cloneCapable() ? "clone" : "copy", "cloned", cloned, "clonedBy", clonedBy,
			"bytes", cost.bytes(),
			"files", cost.files(), "copyMs", copied.ms(), "freeSpaceUsedBytes", consumed,
			"depth", depth, "sidecar", ProjectFork.sidecar(fr).getPath(), "ms",
			(System.nanoTime() - t0) / 1_000_000);
		out.add("info", info);
		return out;
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

	/**
	 * {@code refresh} (or {@code reopen}): reopens a read-only view on what is saved now, without
	 * its clients leaving. The new view is opened first, outside every lock; then, under the
	 * project's exclusive lock (so that no request sees half of the switch), every program that
	 * clients use is reopened from it with the same key, programs nobody uses are closed, and the
	 * old view is closed. Programs the new revision no longer has are closed for their users.
	 * A writable project needs none (no other process can write it while this daemon holds its
	 * lock).
	 */
	private JsonElement refresh(Client c, JsonObject req, RequestMonitor m) {
		ProjectEntry p = access.projectFor(c, req);
		long t0 = System.nanoTime();
		boolean force = Json.bool(req, "force", false);
		p.invalidateRevision();
		String disk = p.diskRevision();
		if (p.writable()) {
			return Json.of("project", p.id, "refreshed", false, "reason",
				"writable: this daemon holds the project lock, so it always shows what is saved",
				"revision", disk, "generation", p.generation);
		}
		String from = p.openRevision;
		if (!force && disk != null && disk.equals(from)) {
			c.seenGeneration.put(p.id, p.generation);
			return Json.of("project", p.id, "refreshed", false, "reason", "unchanged",
				"revision", from, "generation", p.generation);
		}
		String rev;
		SessionProject nv;
		try {
			rev = Revision.of(p.resolved);
			nv = SessionProject.open(new ProjectLocator(p.resolved.dir().getPath(),
				p.resolved.name()), false);
		}
		catch (Exception e) {
			throw new SessionException(SessionException.FAILED,
				"could not reopen project " + p.id + ": " + e.getMessage(), null, e);
		}
		Lock l;
		try {
			l = lockProject(p, true, waitMs(req), "refresh");
			p.exclusiveClient = c;
		}
		catch (RuntimeException e) {
			nv.close();
			throw e;
		}
		SessionProject old = p.project;
		JsonArray progs;
		try {
			progs = swapView(p, nv, rev, m);
		}
		finally {
			unlockProject(p, l);
		}
		try {
			old.close();
		}
		catch (RuntimeException e) {
			Msg.warn(this, "refresh: could not close the old view of " + p.id, e);
		}
		c.seenGeneration.put(p.id, p.generation);
		Msg.info(this, c.label() + " refreshed project " + p.id + " from revision " + from +
			" to " + rev + " (generation " + p.generation + ")");
		JsonObject out = Json.of("project", p.id, "refreshed", true, "from", from, "revision",
			rev, "generation", p.generation, "programs", progs, "ms",
			(System.nanoTime() - t0) / 1_000_000);
		out.add("info", p.info());
		return out;
	}

	/**
	 * One program of a refreshed view: reopened from the new view when clients use it, closed
	 * otherwise. Held: the project's exclusive lock (no request runs on it).
	 */
	private JsonObject reopenIn(ProjectEntry p, SessionProject nv, ProgramEntry e,
			RequestMonitor m) {
		JsonObject r = Json.of("program", e.key, "revision", e.revision);
		boolean got = false;
		try {
			got = e.lock.writeLock().tryLock(CLEANUP_WAIT_MS, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
		if (!got) {
			Json.put(r, "action", "kept (still in use: " + e.exclusiveHolder + ")");
			return r;
		}
		boolean unlock = true;
		try {
			if (e.userCount() == 0) {
				programCmds.disposeProgram(e);
				Json.put(r, "action", "closed (nobody used it)");
				return r;
			}
			DomainFile df = nv.getProjectData().getFile(e.path);
			if (df == null || !Program.class.isAssignableFrom(df.getDomainObjectClass())) {
				e.lock.writeLock().unlock();
				unlock = false;
				programCmds.closeEntry(e);
				Json.put(r, "action", "removed (not in the new revision)");
				return r;
			}
			e.disposeDecompilers();
			programCmds.releaseProgramObject(e);
			e.mode = null;
			try {
				e.file = df;
				e.program = programCmds.openReadOnly(e, df, m);
				e.mode = ProgramEntry.Mode.READ_ONLY;
				e.stampRevision();
				Json.put(r, "action", "reopened");
				Json.put(r, "newRevision", e.revision);
				overlayCmds.rebuildOverlays(e, m);
			}
			catch (RuntimeException ex) {
				Msg.error(this, "refresh: could not reopen " + e.key + "; closing it", ex);
				e.lock.writeLock().unlock();
				unlock = false;
				programCmds.closeEntry(e);
				Json.put(r, "action", "closed (reopen failed: " + ex.getMessage() + ")");
			}
			return r;
		}
		finally {
			if (unlock) {
				e.lock.writeLock().unlock();
			}
		}
	}

	private JsonElement list(ProjectEntry p, JsonObject req) {
		String path = Json.str(req, "folder", "/");
		boolean recursive = Json.bool(req, "recursive", true);
		boolean programsOnly = Json.bool(req, "programsOnly", false);
		boolean metadata = Json.bool(req, "metadata", true);
		String sha = Json.str(req, "sha256", null);
		Page page = new Page((int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE),
			(int) Json.num(req, "limit", 1000, 1, 100_000));
		ProjectData d = p.data();
		DomainFolder folder = path.equals("/") ? d.getRootFolder() : d.getFolder(path);
		if (folder == null) {
			throw new SessionException(SessionException.NOT_FOUND, "no such folder: " + path);
		}
		walk(p, folder, recursive, programsOnly || sha != null, metadata || sha != null, sha,
			page);
		return Json.of("project", p.id, "folder", folder.getPathname(), "entries", page.out,
			"offset", page.offset, "returned", page.out.size(), "truncated", page.more);
	}

	/** One page of a listing: skips {@code offset} items, keeps {@code limit}, notes the rest. */
	private static final class Page {
		final int offset;
		final int limit;
		final JsonArray out = new JsonArray();
		int index;
		boolean more;

		Page(int offset, int limit) {
			this.offset = offset;
			this.limit = limit;
		}

		/** True when the walk can stop. */
		boolean offer(java.util.function.Supplier<JsonObject> item) {
			if (index++ < offset) {
				return false;
			}
			if (out.size() >= limit) {
				more = true;
				return true;
			}
			out.add(item.get());
			return false;
		}
	}

	/** Returns true when the page is full and the walk should stop. */
	private boolean walk(ProjectEntry p, DomainFolder folder, boolean recursive,
			boolean programsOnly, boolean metadata, String sha, Page page) {
		for (DomainFolder sub : folder.getFolders()) {
			if (!programsOnly &&
				page.offer(() -> Json.of("path", sub.getPathname(), "kind", "folder"))) {
				return true;
			}
			if (recursive && walk(p, sub, true, programsOnly, metadata, sha, page)) {
				return true;
			}
		}
		for (DomainFile f : folder.getFiles()) {
			boolean isProgram = Program.class.isAssignableFrom(f.getDomainObjectClass());
			if (programsOnly && !isProgram) {
				continue;
			}
			if (sha != null && !sha.equalsIgnoreCase(f.getMetadata().get("Executable SHA256"))) {
				continue;
			}
			if (page.offer(() -> describeFile(p, f, isProgram, metadata))) {
				return true;
			}
		}
		return false;
	}

	private JsonObject describeFile(ProjectEntry p, DomainFile f, boolean isProgram,
			boolean metadata) {
		JsonObject e = Json.of("path", f.getPathname(), "key", p.id + ":" + f.getPathname(),
			"kind", "file", "name", f.getName(), "contentType", f.getContentType(), "program",
			isProgram, "versioned", f.isVersioned(), "readOnly",
			f.isReadOnly() || !f.isInWritableProject());
		try {
			Json.put(e, "bytes", f.length());
		}
		catch (IOException ex) {
			Json.put(e, "bytes", null);
		}
		if (metadata && isProgram) {
			Map<String, String> md = f.getMetadata();
			Json.put(e, "sha256", md.get("Executable SHA256"));
			Json.put(e, "language", md.get("Language ID"));
			Json.put(e, "format", md.get("Executable Format"));
			Json.put(e, "executable", md.get("Executable Location"));
		}
		ProgramEntry pe = p.programs.get(f.getPathname());
		Json.put(e, "open", pe == null ? null : pe.describeUse(upgradeCache));
		return e;
	}

	/**
	 * Finds a file by project path, or by bare name when it is unique in the project (the way
	 * {@code -process name} is used).
	 */
	static DomainFile findFile(ProjectEntry p, String path) {
		ProjectData d = p.data();
		if (path.startsWith("/")) {
			DomainFile f = d.getFile(path);
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no such file in project " + p.id + ": " + path);
			}
			return f;
		}
		List<DomainFile> found = new ArrayList<>();
		collectByName(d.getRootFolder(), path, found);
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no file named " + path + " in project " + p.id);
		}
		List<String> paths = new ArrayList<>();
		found.forEach(f -> paths.add(f.getPathname()));
		JsonObject details = new JsonObject();
		Json.put(details, "candidates", paths);
		throw new SessionException(SessionException.CONFLICT,
			"several files are named " + path + "; pass the project path", details);
	}

	private static void collectByName(DomainFolder folder, String name, List<DomainFile> out) {
		DomainFile f = folder.getFile(name);
		if (f != null) {
			out.add(f);
		}
		for (DomainFolder sub : folder.getFolders()) {
			collectByName(sub, name, out);
		}
	}
}
