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

import java.io.*;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.*;

import generic.hash.HashUtilities;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.*;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.Application;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramLocation;
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
 */
final class Session {

	static final int PROTOCOL_VERSION = 2;

	static final long DEFAULT_WAIT_MS = 10_000;
	private static final long CLEANUP_WAIT_MS = 600_000;
	private static final int DEFAULT_TEXT_CAP = 200_000;
	private static final int MAX_TEXT_CAP = 16_000_000;
	private static final Object SCRIPT_COMPILE = new Object();
	/**
	 * Loaders find libraries through {@code AppInfo.getActiveProject()}, one global, so imports
	 * set it to their own project and run one at a time. Upgrade cache builds open their copies
	 * under it too, restoring the active project afterwards.
	 */
	static final Object IMPORT = new Object();
	private static final Pattern PROGRAM_KEY = Pattern.compile("(p\\d+):(/.*)");

	private final long startedAt = System.currentTimeMillis();
	/** Guards opening, upgrading and closing projects, and the two project maps. */
	private final Object registry = new Object();
	private final Map<String, ProjectEntry> projects = new ConcurrentHashMap<>();
	private final Map<String, ProjectEntry> projectsById = new ConcurrentHashMap<>();
	private final AtomicInteger nextProject = new AtomicInteger(1);
	private final Map<Integer, Client> clients = new ConcurrentHashMap<>();
	private final AtomicInteger nextClient = new AtomicInteger(1);
	private volatile boolean shuttingDown;
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
				if (e.userCount() == 0 && (now - e.lastUsed >= keepWarmMs || swappable(e))) {
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
					disposeProgram(e);
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
				return programs(c);
			default:
				break;
		}
		Scheduler.Ticket slot = scheduler.admit(c, cmd, m, waitMs(req));
		try {
			if (cmd.equals("script") || cmd.equals("import") || cmd.equals("analyze")) {
				DeferredInit.await(); // the TLS context and the script framework
			}
			if (Json.has(req, "overlay") && overlayScoped(cmd)) {
				return overlayCommand(c, cmd, req, m);
			}
			return switch (cmd) {
				case "open_project" -> openProject(c, req);
				case "overlays" -> listOverlays(c);
				case "promote_overlay" -> promoteOverlay(c, req, m);
				case "apply_overlay", "drop_overlay" -> throw new SessionException(
					SessionException.BAD_REQUEST, "missing field: overlay");
				case "fork_project" -> forkProject(c, req, m);
				case "refresh", "reopen" -> refresh(c, req, m);
				case "close_project" -> closeProject(c, req);
				case "project" -> inProject(projectFor(c, req), req, cmd, ProjectEntry::info);
				case "list" -> {
					ProjectEntry p = projectFor(c, req);
					yield inProject(p, req, cmd, x -> list(x, req));
				}
				case "open_program", "switch" -> openProgram(c, req, m);
				case "info" -> withProgram(c, req, cmd, false, false, e -> programInfo(e, c));
				case "close_program" -> closeProgram(c, req);
				case "save" -> withProgram(c, req, cmd, true, true, e -> save(e, req, m));
				case "functions" -> withProgram(c, req, cmd, false, false,
					e -> functions(e.program, req));
				case "decompile" -> withProgram(c, req, cmd, false, false,
					e -> decompile(e.program, e, req, m));
				case "rename" -> withProgram(c, req, cmd, true, true, e -> renameIn(e.program, req));
				case "comment" -> withProgram(c, req, cmd, true, true,
					e -> commentIn(e.program, req));
				case "analyze" -> withProgram(c, req, cmd, true, true, e -> analyze(e, req, m));
				case "import" -> importProgram(c, req, m);
				case "script" -> script(c, req, m);
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

	/**
	 * How long a request may wait for a slot or a lock. {@code "wait": true} (on
	 * {@code open_program}: wait for the upgrade cache copy) or {@code false} keeps the default.
	 */
	private static long waitMs(JsonObject req) {
		if (Json.has(req, "wait") && req.get("wait").isJsonPrimitive() &&
			req.getAsJsonPrimitive("wait").isBoolean()) {
			return DEFAULT_WAIT_MS;
		}
		return Json.num(req, "wait", DEFAULT_WAIT_MS, 0, 86_400_000L);
	}

	private static boolean waitsForCache(JsonObject req) {
		return Json.has(req, "wait") && req.get("wait").isJsonPrimitive() &&
			req.getAsJsonPrimitive("wait").isBoolean() && req.get("wait").getAsBoolean();
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
		for (Overlay x : overlays.values()) {
			ovs.add(x.describe());
		}
		o.add("overlays", ovs);
		o.add("scheduler", scheduler.describe());
		o.add("upgradeCache", upgradeCache.describe());
		Json.put(o, "deferredInitMs", DeferredInit.doneMs());
		return o;
	}

	private JsonElement cancel(Client c, JsonObject req) {
		if (Json.has(req, "cacheBuild")) {
			// a background upgrade cache build: by build id, cache key, program path or key, "all"
			String which = Json.str(req, "cacheBuild");
			ProgramEntry e = PROGRAM_KEY.matcher(which).matches() ? entryByKey(which) : null;
			if (e != null && e.cachePlan != null) {
				which = e.cachePlan.id();
			}
			return Json.of("cancelled", upgradeCache.cancel(which));
		}
		if (Json.bool(req, "all", false)) {
			int n = 0;
			for (Map.Entry<String, RequestMonitor> e : c.running.entrySet()) {
				if (req.has("id") && req.get("id").toString().equals(e.getKey())) {
					continue; // not this cancel itself
				}
				e.getValue().cancel();
				n++;
			}
			return Json.of("cancelled", n);
		}
		if (!req.has("target")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: target (the id of your request), or \"all\":true");
		}
		RequestMonitor m = c.running.get(req.get("target").toString());
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

	// ---- projects --------------------------------------------------------------------------

	/**
	 * The project a command acts on: {@code "project"} (an id like {@code p1}, or a path to the
	 * project), else the project of {@code "program"} when that is a program key, else the
	 * client's active project. The client must have joined it.
	 */
	private ProjectEntry projectFor(Client c, JsonObject req) {
		String key = Json.str(req, "project", null);
		if (key == null && Json.has(req, "program")) {
			java.util.regex.Matcher mk = PROGRAM_KEY.matcher(Json.str(req, "program"));
			if (mk.matches()) {
				key = mk.group(1);
			}
		}
		if (key == null) {
			key = c.activeProject;
		}
		if (key == null) {
			throw new SessionException(SessionException.NO_PROJECT,
				"no project selected; send open_project first");
		}
		ProjectEntry p = projectsById.get(key);
		if (p == null && !key.matches("p\\d+")) {
			try {
				ProjectResolver.Resolved r = ProjectResolver.resolve(key);
				p = projects.get(r.gpr().getCanonicalPath());
			}
			catch (IOException e) {
				throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
			}
		}
		if (p == null || p.closed) {
			throw new SessionException(SessionException.NO_PROJECT,
				"project " + key + " is not open; send open_project", Json.of("project", key));
		}
		if (!c.projects.contains(p.id)) {
			throw new SessionException(SessionException.NO_PROJECT,
				"this client has not joined project " + p.id + "; send open_project",
				Json.of("project", p.id));
		}
		return p;
	}

	private interface ProjectWork<T> {
		T run(ProjectEntry p);
	}

	private <T> T inProject(ProjectEntry p, JsonObject req, String cmd, ProjectWork<T> work) {
		Lock l = lockProject(p, false, waitMs(req), cmd);
		try {
			return work.run(p);
		}
		finally {
			p.lastUsed = System.currentTimeMillis();
			l.unlock();
		}
	}

	private static Lock lockProject(ProjectEntry p, boolean exclusive, long wait, String cmd) {
		Lock l = exclusive ? p.lock.writeLock() : p.lock.readLock();
		boolean got = false;
		try {
			got = l.tryLock(wait, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		if (!got) {
			JsonObject d = p.identity();
			Json.put(d, "wanted", exclusive ? "exclusive" : "shared");
			Json.put(d, "waitedMs", wait);
			String holderCmd = p.exclusiveCmd;
			if (holderCmd != null) {
				Client hc = p.exclusiveClient;
				Json.put(d, "holder", (hc == null ? "the session" : hc.label()) + " " + holderCmd);
				Json.put(d, "holderInfo", hc != null ? hc.holder(holderCmd, p.exclusiveSince)
						: Json.of("label", "the session", "command", holderCmd, "heldMs",
							System.currentTimeMillis() - p.exclusiveSince));
			}
			else {
				Json.put(d, "readers", p.lock.getReadLockCount());
			}
			Json.put(d, "suggest", "retry");
			throw new SessionException(SessionException.BUSY,
				exclusive ? cmd + " needs project " + p.id + " to itself and requests are running"
						: "project " + p.id + " is being " +
							(holderCmd == null ? "opened or closed" : "changed (" + holderCmd + ")"),
				d);
		}
		if (p.closed) {
			l.unlock();
			throw new SessionException(SessionException.NO_PROJECT,
				"project " + p.id + " was closed", Json.of("project", p.id));
		}
		if (exclusive) {
			p.exclusiveCmd = cmd;
			p.exclusiveClient = null;
			p.exclusiveSince = System.currentTimeMillis();
		}
		return l;
	}

	/** Releases a project lock taken with {@link #lockProject}. */
	private static void unlockProject(ProjectEntry p, Lock l) {
		if (l == p.lock.writeLock()) {
			p.exclusiveCmd = null;
			p.exclusiveClient = null;
		}
		l.unlock();
	}

	/**
	 * What a client that cannot write a project or program should do instead: fork the project
	 * into a working copy of its own (see {@code fork_project}). The path is a suggestion, next to
	 * the project's folder.
	 */
	static JsonObject forkSuggestion(ProjectEntry p, Client c) {
		String who = (c == null || c.name.isEmpty() ? "client" + (c == null ? "" : c.id) : c.name)
				.replaceAll("[^A-Za-z0-9_.-]", "_");
		File dir = p.resolved.dir();
		File parent = dir.getAbsoluteFile().getParentFile();
		File dest = new File(parent == null ? dir : parent, dir.getName() + "-fork-" + who);
		return Json.of("cmd", "fork_project", "project", p.id, "path", dest.getPath(), "writable",
			true);
	}

	/** Adds {@code suggest: fork_project} and its {@code suggestion} to error details. */
	static JsonObject suggestFork(JsonObject d, ProjectEntry p, Client c) {
		Json.put(d, "suggest", "fork_project");
		d.add("suggestion", forkSuggestion(p, c));
		return d;
	}

	/**
	 * Joins a project, opening it if no client has it open. A project open read-only is upgraded
	 * to writable only when no other client uses it (and, unless {@code discard}, nothing of this
	 * client's is unsaved). A read-only request on a writable project joins it.
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
				List<String> others = new ArrayList<>();
				synchronized (p.users) {
					p.users.stream().filter(u -> u != c).forEach(u -> others.add(u.label()));
				}
				if (!others.isEmpty()) {
					JsonObject d = p.identity();
					d.add("holders", p.holders(c));
					throw new SessionException(SessionException.CONFLICT,
						"project " + p.id + " is open read-only and used by " +
							String.join(", ", others) + "; it can be reopened writable only " +
							"when no other client uses it. To write while they read, fork it: " +
							"fork_project makes a working copy of your own",
						suggestFork(d, p, c));
				}
				closeProjectEntry(p, wait, discard);
				p = null;
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
				closeEntry(e);
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

	private static String firstOf(Set<String> set) {
		synchronized (set) {
			return set.isEmpty() ? null : set.iterator().next();
		}
	}

	private JsonElement closeProject(Client c, JsonObject req) {
		ProjectEntry p = projectFor(c, req);
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
				boolean discarded = releaseUse(c, e, discard, wait);
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
			if (!p.closed && p.userCount() == 0 && (p.writable() || keepWarmMs == 0)) {
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
	private JsonElement forkProject(Client c, JsonObject req, RequestMonitor m) {
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
		ProjectEntry p = projectFor(c, req);
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
		JsonArray progs = new JsonArray();
		try {
			p.project = nv;
			p.previousRevision = from;
			p.openRevision = rev;
			p.invalidateRevision();
			p.generation++;
			p.refreshedAt = System.currentTimeMillis();
			for (ProgramEntry e : new ArrayList<>(p.programs.values())) {
				progs.add(reopenIn(p, nv, e, m));
			}
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
				disposeProgram(e);
				Json.put(r, "action", "closed (nobody used it)");
				return r;
			}
			DomainFile df = nv.getProjectData().getFile(e.path);
			if (df == null || !Program.class.isAssignableFrom(df.getDomainObjectClass())) {
				e.lock.writeLock().unlock();
				unlock = false;
				closeEntry(e);
				Json.put(r, "action", "removed (not in the new revision)");
				return r;
			}
			e.disposeDecompilers();
			releaseProgramObject(e);
			e.mode = null;
			try {
				e.file = df;
				e.program = openReadOnly(e, df, m);
				e.mode = ProgramEntry.Mode.READ_ONLY;
				e.stampRevision();
				Json.put(r, "action", "reopened");
				Json.put(r, "newRevision", e.revision);
				rebuildOverlays(e, m);
			}
			catch (RuntimeException ex) {
				Msg.error(this, "refresh: could not reopen " + e.key + "; closing it", ex);
				e.lock.writeLock().unlock();
				unlock = false;
				closeEntry(e);
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

	// ---- overlays --------------------------------------------------------------------------

	/** Every client's overlays, by {@link Overlay#id}. */
	private final Map<String, Overlay> overlays = new ConcurrentHashMap<>();
	private static final Pattern OVERLAY_NAME = Pattern.compile("[A-Za-z0-9_.@-]{1,64}");

	/** Commands that act on an overlay when the request names one. */
	private static boolean overlayScoped(String cmd) {
		return switch (cmd) {
			case "open_program", "switch", "info", "functions", "decompile", "rename", "comment",
					"script", "apply_overlay", "drop_overlay" ->
				true;
			default -> false;
		};
	}

	private List<Overlay> overlaysOf(ProgramEntry e) {
		List<Overlay> out = new ArrayList<>();
		for (Overlay o : overlays.values()) {
			if (o.base == e) {
				out.add(o);
			}
		}
		return out;
	}

	private JsonElement listOverlays(Client c) {
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
	private JsonElement overlayCommand(Client c, String cmd, JsonObject req, RequestMonitor m) {
		String name = overlayName(req);
		if (cmd.equals("open_program") || cmd.equals("switch")) {
			if (Json.bool(req, "writable", false)) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"an overlay is a private view over a read-only use of the program; leave " +
						"out \"writable\" (promote_overlay writes it into a working copy)");
			}
			JsonObject plain = req.deepCopy();
			plain.remove("overlay");
			JsonObject info = (JsonObject) openProgram(c, plain, m);
			ProgramEntry e = entryByKey(info.get("key").getAsString());
			if (e == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					info.get("key").getAsString() + " was closed meanwhile");
			}
			Overlay o = openOverlay(c, e, name, waitMs(req), m);
			info.add("overlay", o.describe());
			return info;
		}
		ProgramEntry e = selected(c, req);
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
			boolean got = false;
			try {
				got = ol.tryLock(waitMs(req), TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException ex) {
				Thread.currentThread().interrupt();
			}
			if (!got) {
				JsonObject d = e.identity();
				Json.put(d, "overlay", name);
				d.add("holderInfo", c.holder("overlay " + name, 0));
				Json.put(d, "suggest", "retry");
				throw new SessionException(SessionException.BUSY,
					"overlay '" + name + "' is busy with another of this client's requests", d);
			}
			try {
				if (cmd.equals("drop_overlay")) {
					o.dispose();
					overlays.remove(o.id, o);
					Msg.info(this, c.label() + " dropped overlay " + name + " of " + e.key +
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
					case "functions" -> withOverlay(o, functions(o.program, req));
					case "decompile" -> withOverlay(o, decompile(o.program, o, req, m));
					case "script" -> {
						ResourceFile src = findScript(Json.str(req, "script"));
						m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
						yield withOverlay(o,
							runScript(src, req, p.project, o.program, null, "contained", m));
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

	/** The operations of a request: {@code ops}, or the request itself as one {@code op}. */
	private static JsonArray ops(JsonObject req, String single) {
		if (single != null) {
			JsonObject op = req.deepCopy();
			for (String k : List.of("id", "cmd", "overlay", "program", "project", "wait",
				"parallel")) {
				op.remove(k);
			}
			op.addProperty("op", single);
			JsonArray a = new JsonArray();
			a.add(op);
			return a;
		}
		if (!Json.has(req, "ops") || !req.get("ops").isJsonArray() ||
			req.getAsJsonArray("ops").isEmpty()) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"ops must be a non-empty array of {\"op\": rename|label|comment|signature|" +
					"data_type, ...}");
		}
		return req.getAsJsonArray("ops");
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
				Msg.info(this, c.label() + " opened overlay " + name + " of " + e.key + " in " +
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
				UpgradeCache.Opened op = upgradeCache.openReady(e.cachePlan, o, m);
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
			applyOps(prog, o.log);
		}
	}

	/** After a refresh reopened {@code e}: every overlay of it is rebuilt from its log. */
	private void rebuildOverlays(ProgramEntry e, RequestMonitor m) {
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
					Msg.warn(this, "overlay " + o.name + " of " + e.key + ": " + o.error);
				}
			}
			finally {
				o.lock.writeLock().unlock();
			}
		}
	}

	/** Drops the overlays of {@code e} that belong to {@code c} (all of them when c is null). */
	private void dropOverlays(Client c, ProgramEntry e) {
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
		JsonArray results = applyOps(o.program, ops);
		for (JsonElement op : ops) {
			o.log.add(op.deepCopy());
		}
		o.version++;
		return Json.of("overlay", o.describe(), "applied", ops.size(), "results", results);
	}

	/**
	 * Applies operations in one transaction: all of them, or (on the first failure) none. The
	 * failure names the operation's index.
	 */
	private JsonArray applyOps(Program p, JsonArray ops) {
		JsonArray results = new JsonArray();
		int tx = p.startTransaction("overlay operations");
		boolean ok = false;
		int i = 0;
		try {
			for (JsonElement el : ops) {
				if (!el.isJsonObject()) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"ops[" + i + "] is not an object");
				}
				results.add(applyOp(p, el.getAsJsonObject()));
				i++;
			}
			ok = true;
		}
		catch (SessionException ex) {
			JsonObject d = ex.details() == null ? new JsonObject() : ex.details().deepCopy();
			Json.put(d, "index", i);
			Json.put(d, "rolledBack", true);
			throw new SessionException(ex.code(),
				"ops[" + i + "]: " + ex.getMessage() + " (nothing was applied)", d, ex);
		}
		catch (Exception ex) {
			throw new SessionException(SessionException.FAILED,
				"ops[" + i + "]: " + ex.getClass().getSimpleName() + ": " + ex.getMessage() +
					" (nothing was applied)",
				Json.of("index", i, "rolledBack", true), ex);
		}
		finally {
			p.endTransaction(tx, ok);
		}
		return results;
	}

	/**
	 * One operation: {@code rename} (address, name, kind auto|function|label), {@code label}
	 * (address, name), {@code comment} (address, text, type), {@code signature} (address of a
	 * function, a C prototype), {@code data_type} (address, a data type such as {@code int},
	 * {@code char[16]} or {@code MyStruct *}).
	 */
	private JsonObject applyOp(Program p, JsonObject op) throws Exception {
		String kind = Json.str(op, "op");
		switch (kind) {
			case "rename":
				return Json.of("op", kind, "result", renameIn(p, op));
			case "label": {
				JsonObject r = op.deepCopy();
				r.addProperty("kind", "label");
				return Json.of("op", kind, "result", renameIn(p, r));
			}
			case "comment":
				return Json.of("op", kind, "result", commentIn(p, op));
			case "signature": {
				Address a = address(p, Json.str(op, "address"));
				Function f = p.getFunctionManager().getFunctionContaining(a);
				if (f == null) {
					throw new SessionException(SessionException.NOT_FOUND,
						"no function contains " + hex(a));
				}
				String text = Json.str(op, "signature");
				ghidra.program.model.data.FunctionDefinitionDataType fd;
				try {
					fd = ghidra.app.util.cparser.C.CParserUtils.parseSignature(
						(ghidra.app.services.DataTypeManagerService) null, p, text, false);
				}
				catch (ghidra.app.util.cparser.C.ParseException ex) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad signature '" + text + "': " + ex.getMessage());
				}
				if (fd == null) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad signature '" + text + "'");
				}
				ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
					new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.getEntryPoint(), fd,
						SourceType.USER_DEFINED);
				if (!cmd.applyTo(p)) {
					throw new SessionException(SessionException.FAILED,
						"could not apply the signature: " + cmd.getStatusMsg());
				}
				return Json.of("op", kind, "address", hex(f.getEntryPoint()), "signature",
					f.getSignature().getPrototypeString());
			}
			case "data_type": {
				Address a = address(p, Json.str(op, "address"));
				String text = Json.str(op, "type");
				ghidra.program.model.data.DataType dt;
				try {
					dt = new ghidra.util.data.DataTypeParser(p.getDataTypeManager(),
						p.getDataTypeManager(), null,
						ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL).parse(text);
				}
				catch (ghidra.program.model.data.InvalidDataTypeException ex) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad data type '" + text + "': " + ex.getMessage());
				}
				Data d = ghidra.program.model.data.DataUtilities.createData(p, a, dt, -1,
					ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				return Json.of("op", kind, "address", hex(a), "type",
					d.getDataType().getDisplayName(), "length", d.getLength());
			}
			default:
				throw new SessionException(SessionException.BAD_REQUEST,
					"unknown op '" + kind + "': rename, label, comment, signature or data_type");
		}
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
	private JsonElement promoteOverlay(Client c, JsonObject req, RequestMonitor m) {
		String name = overlayName(req);
		ProgramEntry e = selected(c, req);
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
			fork = (JsonObject) forkProject(c, freq, m);
			target = fork.get("project").getAsString();
		}
		String path = Json.str(req, "path", e.path);
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		JsonObject info =
			(JsonObject) openProgram(c, Json.of("path", target + ":" + path, "writable", true), m);
		String tsha = info.has("sha256") && !info.get("sha256").isJsonNull()
				? info.get("sha256").getAsString()
				: null;
		if (sha != null && tsha != null && !sha.equalsIgnoreCase(tsha)) {
			throw new SessionException(SessionException.CONFLICT,
				"the target " + info.get("key").getAsString() + " is another build (SHA-256 " +
					tsha + "); the overlay was made over " + sha,
				Json.of("target", info.get("key"), "sha256", tsha, "overlaySha256", sha));
		}
		JsonObject areq = Json.of("program", info.get("key").getAsString());
		JsonElement results =
			withProgram(c, areq, "promote_overlay", true, true, t -> applyOps(t.program, log));
		JsonElement saved = null;
		if (Json.bool(req, "save", true)) {
			saved = withProgram(c, areq, "save", true, true,
				t -> save(t, Json.of("comment", "promote overlay " + name), m));
		}
		Msg.info(this, c.label() + " promoted overlay " + name + " of " + e.key + " (" +
			log.size() + " operations) into " + info.get("key").getAsString());
		JsonObject out = Json.of("promoted", log.size(), "overlay", name, "from", e.key,
			"target", info.get("key"), "project", target, "results", results, "saved", saved);
		out.add("fork", fork);
		return out;
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
	private static DomainFile findFile(ProjectEntry p, String path) {
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

	// ---- programs --------------------------------------------------------------------------

	private JsonElement openProgram(Client c, JsonObject req, RequestMonitor m) {
		String path = Json.str(req, "path");
		JsonObject scoped = req;
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(path);
		if (mk.matches()) {
			scoped = req.deepCopy();
			scoped.addProperty("project", mk.group(1));
			path = mk.group(2);
		}
		ProjectEntry p = projectFor(c, scoped);
		String target = path;
		return inProject(p, req, "open_program", x -> openProgramIn(c, x, target, req, m));
	}

	/** Held: the project's shared lock. */
	private JsonObject openProgramIn(Client c, ProjectEntry p, String name, JsonObject req,
			RequestMonitor m) {
		boolean writable = Json.bool(req, "writable", false);
		if (writable && !p.writable()) {
			JsonObject d = suggestFork(p.identity(), p, c);
			Json.put(d, "alternative", "open_project writable");
			throw new SessionException(SessionException.READ_ONLY,
				"project " + p.id + " is open read-only; send open_project with " +
					"\"writable\":true first (this takes the project lock), or fork_project " +
					"to write a working copy while others keep reading",
				d);
		}
		DomainFile df = findFile(p, name);
		if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
			throw new SessionException(SessionException.BAD_REQUEST,
				df.getPathname() + " is not a program (" + df.getContentType() + ")");
		}
		String path = df.getPathname();
		long wait = waitMs(req);
		if (!writable && waitsForCache(req)) {
			awaitCacheCopy(p, df, m); // before any program lock: other opens are not held up
		}
		JsonObject joined = joinOpen(c, p, path, writable, wait);
		if (joined != null) {
			return joined;
		}
		long deadline = System.currentTimeMillis() + wait;
		while (true) {
			ProgramEntry e = p.programs.computeIfAbsent(path, x -> new ProgramEntry(p, x));
			Lock l = e.acquire(true, Math.max(0, deadline - System.currentTimeMillis()), c,
				"open_program");
			boolean retry = false;
			try {
				if (p.programs.get(path) != e) {
					continue; // closed while we waited; open a fresh one
				}
				if (writable && e.mode == ProgramEntry.Mode.WRITABLE && e.owner != c &&
					e.owner.leaving) {
					// Its owner disconnected and its cleanup (cancel, discard) is still running:
					// that is a lock being released, so wait for it like one.
					if (System.currentTimeMillis() >= deadline) {
						JsonObject d = e.identity();
						Json.put(d, "holder", e.owner.label() + " (leaving)");
						JsonObject h = e.ownerHolder();
						Json.put(h, "leaving", true);
						d.add("holderInfo", h);
						Json.put(d, "suggest", "retry");
						throw new SessionException(SessionException.BUSY,
							path + " is being released by " + e.owner.label() +
								", which disconnected; retry, or pass a longer \"wait\"",
							d);
					}
					retry = true;
					continue;
				}
				long t0 = System.nanoTime();
				try {
					if (!writable && e.userCount() == 0 && swappable(e)) {
						// upgraded in memory, nobody uses it, and its cached copy is ready: switch
						e.disposeDecompilers();
						releaseProgramObject(e);
						e.mode = null;
						Msg.info(this, "switching " + e.key + " to its upgrade cache copy");
					}
					if (e.program == null) {
						e.file = df;
						e.program = writable ? openWritable(e, df, req, m) : openReadOnly(e, df, m);
						e.mode = writable ? ProgramEntry.Mode.WRITABLE : ProgramEntry.Mode.READ_ONLY;
						e.stampRevision();
						e.owner = writable ? c : null;
						e.ownedSince = System.currentTimeMillis();
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
					else if (writable && e.mode == ProgramEntry.Mode.WRITABLE && e.owner != c) {
						throw notOwner(e, c, path + " is open writable by " + e.owner.label() +
							"; one writer per program: fork the project to write your own copy");
					}
					else if (writable && e.mode == ProgramEntry.Mode.READ_ONLY) {
						Program np = openWritable(e, df, req, m);
						e.disposeDecompilers();
						releaseProgramObject(e);
						e.program = np;
						e.mode = ProgramEntry.Mode.WRITABLE;
						e.stampRevision();
						e.owner = c;
						e.ownedSince = System.currentTimeMillis();
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
				}
				catch (RuntimeException ex) {
					if (e.program == null) {
						p.programs.remove(path, e);
					}
					throw ex;
				}
				JsonObject info = useProgram(c, e, e.openMs);
				if (e.cacheBuildStarted) {
					e.cacheBuildStarted = false;
					Json.put(info, "cacheBuild", "started");
				}
				return info;
			}
			finally {
				e.release(l);
				if (retry) {
					sleepQuietly(50);
				}
			}
		}
	}

	private static void sleepQuietly(long ms) {
		try {
			Thread.sleep(ms);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	/** Records that {@code c} uses {@code e} and makes it its active program. */
	private JsonObject useProgram(Client c, ProgramEntry e, long openMs) {
		synchronized (e.users) {
			e.users.add(c);
		}
		c.programs.add(e.key);
		c.active = e.key;
		c.activeProject = e.project.id;
		JsonObject info = programInfo(e, c);
		Json.put(info, "openMs", openMs);
		return info;
	}

	/**
	 * Joins a program that is already open (also a warm one nobody uses) in a mode that fits,
	 * under the shared lock, so that a client can start using a program while others run long
	 * reads on it. Returns null when the exclusive path (open, upgrade) is needed.
	 */
	private JsonObject joinOpen(Client c, ProjectEntry p, String path, boolean writable,
			long wait) {
		ProgramEntry e = p.programs.get(path);
		if (e == null) {
			return null;
		}
		Lock l = e.acquire(false, wait, c, "open_program");
		try {
			if (p.programs.get(path) != e || e.program == null ||
				(writable && !(e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c)) ||
				(!writable && e.userCount() == 0 && swappable(e))) {
				return null;
			}
			boolean restarted = !writable && retryCacheBuild(e);
			JsonObject info = useProgram(c, e, 0);
			if (restarted) {
				Json.put(info, "cacheBuild", "started");
			}
			return info;
		}
		finally {
			e.release(l);
		}
	}

	/**
	 * True when {@code e} was upgraded in memory and its upgrade cache copy is now ready, so that
	 * an open with nobody using it can switch to the copy. Unlocked reads; callers recheck under
	 * the program's exclusive lock.
	 */
	private boolean swappable(ProgramEntry e) {
		UpgradeCache.Plan plan = e.cachePlan;
		return plan != null && e.program != null && e.cacheView == null &&
			e.mode == ProgramEntry.Mode.READ_ONLY && upgradeCache.isReady(plan);
	}

	/**
	 * An open that joins a program upgraded in memory whose build failed (or was cancelled)
	 * starts a new one, with a fresh plan in case the source changed. Returns true when it
	 * started one. Held: the program's lock (shared is enough: the plan is only replaced by an
	 * equal or newer one).
	 */
	private boolean retryCacheBuild(ProgramEntry e) {
		UpgradeCache.Plan plan = e.cachePlan;
		if (plan == null || e.cacheView != null) {
			return false;
		}
		UpgradeCache.Build b = upgradeCache.build(plan);
		if (b == null ? upgradeCache.isReady(plan) : b.state != UpgradeCache.State.FAILED) {
			return false;
		}
		try {
			UpgradeCache.Plan fresh = upgradeCache.plan(e.project, e.file);
			if (fresh == null) {
				return false;
			}
			e.cachePlan = fresh;
			UpgradeCache.Start st = upgradeCache.startBuild(fresh);
			return st != null && st.started();
		}
		catch (IOException | RuntimeException ex) {
			Msg.warn(this, "upgrade cache: could not restart the build of " + e.key + ": " + ex);
			return false;
		}
	}

	/**
	 * {@code open_program} with {@code "wait": true}: when the program is in an older format and
	 * its upgrade cache copy is not ready, starts (or joins) its build and waits for it, so that
	 * the open is served from the copy. Holds no program lock while it waits.
	 */
	private void awaitCacheCopy(ProjectEntry p, DomainFile df, RequestMonitor m) {
		UpgradeCache.Plan plan;
		try {
			plan = upgradeCache.plan(p, df);
		}
		catch (IOException ex) {
			Msg.warn(this, "upgrade cache: cannot key " + df.getPathname() + ": " + ex);
			return;
		}
		if (plan == null || upgradeCache.isReady(plan)) {
			return;
		}
		UpgradeCache.Start st = upgradeCache.startBuild(plan);
		if (st == null) {
			return;
		}
		try {
			if (!upgradeCache.await(st.build(), m)) {
				Msg.warn(this, "upgrade cache: the build " + plan.id() + " that an open waited " +
					"for failed (" + st.build().error + "); upgrading in memory");
			}
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
	}

	/**
	 * Opens a program read-only. A program saved in an older database format is served from its
	 * upgrade cache copy when that is ready (see {@link UpgradeCache}); otherwise it is upgraded
	 * in memory, as without the cache, and a background build of the copy is started for later
	 * opens. Held: its exclusive lock.
	 */
	private Program openReadOnly(ProgramEntry e, DomainFile df, RequestMonitor m) {
		try {
			UpgradeCache.Plan plan = null;
			try {
				plan = upgradeCache.plan(e.project, df);
			}
			catch (IOException ex) {
				Msg.warn(this, "upgrade cache: cannot key " + e.key + ": " + ex);
			}
			if (plan != null) {
				UpgradeCache.Opened c = null;
				try {
					c = upgradeCache.openReady(plan, e, m);
				}
				catch (IOException | VersionException ex) {
					Msg.warn(this, "upgrade cache: could not serve " + e.key + " from its copy, " +
						"opening the source (upgraded in memory): " + ex.getMessage(), ex);
				}
				if (c != null) {
					e.cacheView = c.view();
					e.cacheLease = c.lease();
					e.cacheInfo = c.info();
					e.cachePlan = plan;
					Msg.info(this, "opened " + e.key + " from the upgrade cache " + c.info());
					return c.program();
				}
			}
			Program program =
				(Program) df.getReadOnlyDomainObject(e, DomainFile.DEFAULT_VERSION, m);
			if (plan != null) {
				// after the in-memory upgrade, so that the build does not slow this answer
				e.cachePlan = plan;
				UpgradeCache.Start st = upgradeCache.startBuild(plan);
				e.cacheBuildStarted = st != null && st.started();
				Msg.info(this, "opened " + e.key + " upgraded in memory (" + plan.why() +
					"); upgrade cache build " + (st == null ? "not started (shutting down)"
							: st.started() ? "started" : st.build().state.json()));
			}
			return program;
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				df.getPathname() + " was saved by another Ghidra version: " + ex.getMessage());
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
	}

	private Program openWritable(ProgramEntry e, DomainFile df, JsonObject req,
			RequestMonitor m) {
		try {
			if (df.isReadOnly()) {
				throw new SessionException(SessionException.READ_ONLY,
					df.getPathname() + " is marked read-only in the project");
			}
			if (df.isVersioned() && !df.isCheckedOut()) {
				if (!Json.bool(req, "checkout", false)) {
					throw new SessionException(SessionException.READ_ONLY,
						df.getPathname() + " is versioned and not checked out; pass " +
							"\"checkout\":true to check it out");
				}
				if (!df.checkout(false, m)) {
					throw new SessionException(SessionException.FAILED,
						"checkout of " + df.getPathname() + " failed");
				}
			}
			return (Program) df.getDomainObject(e, Json.bool(req, "upgrade", false), false, m);
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				df.getPathname() + " needs a database upgrade (" + ex.getMessage() +
					"); pass \"upgrade\":true to allow it");
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
	}

	private JsonElement programs(Client c) {
		JsonArray a = new JsonArray();
		List<String> mine;
		synchronized (c.programs) {
			mine = new ArrayList<>(c.programs);
		}
		for (String key : mine) {
			ProgramEntry e = entryByKey(key);
			if (e != null && e.program != null) {
				try {
					a.add(programInfo(e, c));
				}
				catch (RuntimeException ex) {
					// closed while we looked
				}
			}
		}
		return Json.of("activeProject", c.activeProject, "active", c.active, "programs", a);
	}

	private ProgramEntry entryByKey(String key) {
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(key);
		if (!mk.matches()) {
			return null;
		}
		ProjectEntry p = projectsById.get(mk.group(1));
		return p == null ? null : p.programs.get(mk.group(2));
	}

	private JsonElement closeProgram(Client c, JsonObject req) {
		ProgramEntry e = selected(c, req);
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), "close_program");
		try {
			boolean discarded = releaseUse(c, e, Json.bool(req, "discard", false), waitMs(req));
			return Json.of("closed", e.key, "discarded", discarded, "active", c.active);
		}
		finally {
			pl.unlock();
		}
	}

	/**
	 * Drops one client's use of a program. When it owned the writable program, the program goes
	 * back to read-only for the other users, and unsaved changes are discarded only if
	 * {@code discard}. A read-only program nobody uses any more stays open (warm) for
	 * {@link #keepWarmMs}. Returns true when changes were discarded. Held: the project's lock.
	 */
	private boolean releaseUse(Client c, ProgramEntry e, boolean discard, long wait) {
		Lock l = e.acquire(true, wait, c, "close_program");
		try {
			dropOverlays(c, e);
			boolean discarded = false;
			boolean others;
			synchronized (e.users) {
				others = e.users.stream().anyMatch(u -> u != c);
			}
			if (e.program != null && e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c) {
				if (e.program.isChanged()) {
					if (!discard) {
						throw new SessionException(SessionException.UNSAVED_CHANGES,
							e.path + " has unsaved changes; send save, or close with " +
								"\"discard\":true",
							Json.of("program", e.key));
					}
					discarded = true;
				}
				e.disposeDecompilers();
				releaseProgramObject(e); // releasing a changed program discards its changes
				e.owner = null;
				e.mode = null;
				if (others) {
					try {
						e.program = openReadOnly(e, e.file, new RequestMonitor(null, null));
						e.mode = ProgramEntry.Mode.READ_ONLY;
						e.stampRevision();
					}
					catch (RuntimeException ex) {
						Msg.error(this, "could not reopen " + e.key + " read-only for its " +
							"other users; closing it for everyone", ex);
						closeEntry(e);
						c.programs.remove(e.key);
						return discarded;
					}
				}
			}
			synchronized (e.users) {
				e.users.remove(c);
				others = !e.users.isEmpty();
			}
			if (!others && (e.program == null || e.mode != ProgramEntry.Mode.READ_ONLY ||
				keepWarmMs == 0 || e.project.closed)) {
				disposeProgram(e);
			}
			c.programs.remove(e.key);
			if (e.key.equals(c.active)) {
				c.active = firstOf(c.programs);
			}
			return discarded;
		}
		finally {
			e.release(l);
		}
	}

	/** Releases a program nobody uses. Held: its exclusive lock. */
	private void disposeProgram(ProgramEntry e) {
		e.disposeDecompilers();
		releaseProgramObject(e);
		e.mode = null;
		e.owner = null;
		e.project.programs.remove(e.path, e);
	}

	/**
	 * Releases {@link ProgramEntry#program} and, when it came from the upgrade cache, closes the
	 * view of the copy it came from. Held: its exclusive lock.
	 */
	private void releaseProgramObject(ProgramEntry e) {
		try {
			if (e.program != null) {
				e.program.release(e);
			}
		}
		finally {
			e.program = null;
			SessionProject view = e.cacheView;
			UpgradeCache.Lease lease = e.cacheLease;
			e.cacheView = null;
			e.cacheLease = null;
			e.cacheInfo = null;
			e.cachePlan = null;
			e.cacheBuildStarted = false;
			if (view != null) {
				try {
					view.close();
				}
				catch (RuntimeException ex) {
					Msg.warn(this, "could not close the upgrade cache view of " + e.key, ex);
				}
			}
			if (lease != null) {
				lease.release();
			}
		}
	}

	/** Closes a program for everyone. Held: its project's exclusive lock. */
	private void closeEntry(ProgramEntry e) {
		boolean got = false;
		try {
			got = e.lock.writeLock().tryLock(CLEANUP_WAIT_MS, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
		if (!got) {
			Msg.error(this, "could not close " + e.key + ": a request still holds it (" +
				e.exclusiveHolder + ")");
			return;
		}
		try {
			dropOverlays(null, e);
			synchronized (e.users) {
				for (Client u : e.users) {
					u.programs.remove(e.key);
					if (e.key.equals(u.active)) {
						u.active = null;
					}
				}
				e.users.clear();
			}
			disposeProgram(e);
		}
		finally {
			e.lock.writeLock().unlock();
		}
	}

	/**
	 * The program a command acts on: {@code "program"} (a key {@code p1:/path}, or a path or
	 * unique name in {@code "project"} or the active project), else the client's active program.
	 */
	private ProgramEntry selected(Client c, JsonObject req) {
		if (!Json.has(req, "program")) {
			String key = c.active;
			if (key == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					"no active program; send open_program first");
			}
			ProgramEntry e = entryByKey(key);
			if (e == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					key + " was closed; send open_program");
			}
			return e;
		}
		String path = Json.str(req, "program");
		ProjectEntry p = projectFor(c, req);
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(path);
		if (mk.matches()) {
			path = mk.group(2);
		}
		if (!path.startsWith("/")) {
			path = findFile(p, path).getPathname();
		}
		ProgramEntry e = p.programs.get(path);
		String key = p.id + ":" + path;
		if (e == null || !c.programs.contains(key)) {
			throw new SessionException(SessionException.NO_PROGRAM,
				key + " is not open for this client; send open_program first",
				Json.of("program", key));
		}
		return e;
	}

	private interface ProgramWork {
		JsonElement run(ProgramEntry e) throws Exception;
	}

	private JsonElement withProgram(Client c, JsonObject req, String cmd, boolean exclusive,
			boolean needOwner, ProgramWork work) {
		ProgramEntry e = selected(c, req);
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), cmd);
		try {
			Lock l = e.acquire(exclusive, waitMs(req), c, cmd);
			try {
				if (e.program == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				if (needOwner) {
					requireOwner(c, e, cmd);
				}
				return work.run(e);
			}
			catch (SessionException ex) {
				throw ex;
			}
			catch (CancelledException ex) {
				throw new SessionException(SessionException.CANCELLED, cmd + " was cancelled");
			}
			catch (Exception ex) {
				throw new SessionException(SessionException.FAILED,
					ex.getClass().getSimpleName() + ": " + ex.getMessage(), null, ex);
			}
			finally {
				e.release(l);
			}
		}
		finally {
			p.lastUsed = System.currentTimeMillis();
			pl.unlock();
		}
	}

	private static void requireOwner(Client c, ProgramEntry e, String cmd) {
		if (e.mode != ProgramEntry.Mode.WRITABLE) {
			throw new SessionException(SessionException.READ_ONLY,
				e.key + " is open read-only; " + cmd + " needs open_program with " +
					"\"writable\":true" + (e.project.writable() ? ""
							: " in a writable project (fork_project makes one)"),
				e.project.writable()
						? Json.of("program", e.key, "suggest", "open_program writable")
						: suggestFork(e.identity(), e.project, c));
		}
		if (e.owner != c) {
			throw notOwner(e, c, e.key + " is owned by " + e.owner.label() +
				"; only the owner may " + cmd + " (fork the project to write your own copy)");
		}
	}

	/** {@code not_owner}, naming the owner and suggesting a fork. */
	private static SessionException notOwner(ProgramEntry e, Client c, String message) {
		JsonObject d = e.identity();
		Client o = e.owner;
		Json.put(d, "owner", o == null ? null : o.id);
		Json.put(d, "holder", o == null ? null : o.label());
		d.add("holderInfo", e.ownerHolder());
		return new SessionException(SessionException.NOT_OWNER, message,
			suggestFork(d, e.project, c));
	}

	private JsonObject programInfo(ProgramEntry e, Client c) {
		Program p = e.program;
		JsonObject j = Json.of("key", e.key, "project", e.project.id, "path", e.path, "name",
			p.getName(), "mode", e.mode.json(), "owner", e.owner == null ? null : e.owner.id,
			"mine", e.owner == c, "active", e.key.equals(c.active), "language",
			p.getLanguageID().getIdAsString(), "compiler",
			p.getCompilerSpec().getCompilerSpecID().getIdAsString(), "imageBase",
			hex(p.getImageBase()), "format", p.getExecutableFormat(), "executable",
			p.getExecutablePath(), "sha256", p.getExecutableSHA256(), "md5",
			p.getExecutableMD5(), "functions", p.getFunctionManager().getFunctionCount(),
			"analyzed", GhidraProgramUtilities.isAnalyzed(p), "changed", p.isChanged(),
			"revision", e.revision, "projectRevision", e.project.revision(), "generation",
			e.project.generation, "cachedUpgrade", e.cacheInfo != null, "upgradeCache",
			e.cacheInfo == null ? null : e.cacheInfo.deepCopy(), "cacheBuild",
			e.cacheBuild(upgradeCache), "cacheBuildInfo", e.cacheBuildInfo(upgradeCache));
		synchronized (e.users) {
			List<Integer> ids = new ArrayList<>();
			e.users.forEach(u -> ids.add(u.id));
			Json.put(j, "users", ids);
		}
		List<String> mine = new ArrayList<>();
		for (Overlay o : overlaysOf(e)) {
			if (o.client == c) {
				mine.add(o.name);
			}
		}
		Json.put(j, "overlays", mine);
		return j;
	}

	private JsonElement save(ProgramEntry e, JsonObject req, RequestMonitor m)
			throws IOException, CancelledException {
		boolean changed = e.program.isChanged();
		if (changed) {
			e.program.save(Json.str(req, "comment", "headless session"), m);
			e.stampRevision();
			e.project.invalidateRevision();
		}
		return Json.of("program", e.key, "saved", changed, "revision", e.revision,
			"projectRevision", e.project.revision());
	}

	// ---- queries ---------------------------------------------------------------------------

	static String hex(Address a) {
		if (a.getAddressSpace().isMemorySpace() &&
			a.getAddressSpace() == a.getAddressSpace().getPhysicalSpace() &&
			!a.getAddressSpace().isOverlaySpace()) {
			return "0x" + Long.toHexString(a.getOffset());
		}
		return a.toString(true);
	}

	/** Accepts {@code 0x140001000}, {@code va:0x...}, {@code rva:0x...} or {@code space:offset}. */
	static Address address(Program p, String text) {
		String t = text.trim();
		try {
			if (t.startsWith("rva:")) {
				return p.getImageBase().add(Long.decode(t.substring(4)));
			}
			if (t.startsWith("va:")) {
				t = t.substring(3);
			}
			if (!t.contains(":")) {
				String h = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
				return p.getAddressFactory()
						.getDefaultAddressSpace()
						.getAddress(Long.parseUnsignedLong(h, 16));
			}
			Address a = p.getAddressFactory().getAddress(t);
			if (a != null) {
				return a;
			}
		}
		catch (NumberFormatException | AddressOutOfBoundsException e) {
			// fall through
		}
		throw new SessionException(SessionException.BAD_REQUEST,
			"bad address '" + text + "': use 0x<hex>, va:0x<hex>, rva:0x<hex> or space:offset");
	}

	private Function function(Program p, JsonObject req) {
		if (Json.has(req, "address")) {
			Address a = address(p, Json.str(req, "address"));
			Function f = p.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function contains " + hex(a), Json.of("address", hex(a)));
			}
			return f;
		}
		String name = Json.str(req, "name");
		List<Function> found = new ArrayList<>();
		for (Symbol s : p.getSymbolTable().getSymbols(name)) {
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				found.add((Function) s.getObject());
			}
		}
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND, "no function named " + name);
		}
		List<String> at = new ArrayList<>();
		found.forEach(f -> at.add(hex(f.getEntryPoint())));
		JsonObject d = new JsonObject();
		Json.put(d, "candidates", at);
		throw new SessionException(SessionException.CONFLICT,
			"several functions are named " + name + "; pass an address", d);
	}

	private JsonElement functions(Program prog, JsonObject req) {
		Pattern pat = null;
		if (Json.has(req, "regex")) {
			try {
				pat = Pattern.compile(Json.str(req, "regex"));
			}
			catch (PatternSyntaxException ex) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"bad regex: " + ex.getMessage());
			}
		}
		String sub = Json.str(req, "contains", null);
		int limit = (int) Json.num(req, "limit", 200, 1, 10_000);
		int offset = (int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE);
		JsonArray a = new JsonArray();
		int seen = 0;
		boolean truncated = false;
		for (Function f : prog.getFunctionManager().getFunctions(true)) {
			String n = f.getName(true);
			if (pat != null && !pat.matcher(n).find()) {
				continue;
			}
			if (sub != null && !n.contains(sub)) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (a.size() >= limit) {
				truncated = true;
				break;
			}
			a.add(Json.of("name", n, "address", hex(f.getEntryPoint()), "size",
				f.getBody().getNumAddresses(), "thunk", f.isThunk(), "external", f.isExternal()));
		}
		return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
			truncated);
	}

	private JsonElement decompile(Program prog, Decompilers e, JsonObject req,
			RequestMonitor m) {
		Function f = function(prog, req);
		int timeout = (int) Json.num(req, "timeout", 60, 1, 3600);
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		DecompInterface d = e.borrowDecompiler();
		boolean healthy = false;
		try {
			DecompileResults res = d.decompileFunction(f, timeout, m);
			if (m.isCancelled()) {
				throw cancelled(m);
			}
			JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
			boolean ok = res != null && res.decompileCompleted();
			Json.put(r, "completed", ok);
			if (!ok) {
				Json.put(r, "error", res == null ? "no result" : res.getErrorMessage());
				Json.put(r, "timedOut", res != null && res.isTimedOut());
				return r;
			}
			healthy = true;
			DecompiledFunction df = res.getDecompiledFunction();
			String c = df.getC();
			Json.put(r, "signature", df.getSignature());
			Json.put(r, "chars", c.length());
			Json.put(r, "truncated", c.length() > cap);
			Json.put(r, "c", c.length() > cap ? c.substring(0, cap) : c);
			return r;
		}
		finally {
			e.returnDecompiler(d, healthy);
		}
	}

	// ---- edits -----------------------------------------------------------------------------

	private JsonObject renameIn(Program p, JsonObject req) throws Exception {
		Address a = address(p, Json.str(req, "address"));
		String name = Json.str(req, "name");
		String kind = Json.str(req, "kind", "auto");
		if (!kind.equals("auto") && !kind.equals("function") && !kind.equals("label")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"kind must be auto, function or label");
		}
		String old = null;
		int tx = p.startTransaction("session rename");
		boolean ok = false;
		try {
			Function f = p.getFunctionManager().getFunctionAt(a);
			if (kind.equals("function") && f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function starts at " + hex(a));
			}
			if (f != null && !kind.equals("label")) {
				old = f.getName();
				f.setName(name, SourceType.USER_DEFINED);
				kind = "function";
			}
			else {
				Symbol s = p.getSymbolTable().getPrimarySymbol(a);
				if (s != null && s.getSymbolType() == SymbolType.LABEL && !s.isDynamic()) {
					old = s.getName();
					s.setName(name, SourceType.USER_DEFINED);
				}
				else {
					old = s == null ? null : s.getName();
					Symbol n = p.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
					n.setPrimary();
				}
				kind = "label";
			}
			ok = true;
		}
		finally {
			p.endTransaction(tx, ok);
		}
		return Json.of("address", hex(a), "name", name, "old", old, "kind", kind);
	}

	private JsonObject commentIn(Program p, JsonObject req) {
		Address a = address(p, Json.str(req, "address"));
		CommentType ct = switch (Json.str(req, "type", "eol")) {
			case "eol" -> CommentType.EOL;
			case "pre" -> CommentType.PRE;
			case "post" -> CommentType.POST;
			case "plate" -> CommentType.PLATE;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> throw new SessionException(SessionException.BAD_REQUEST,
				"type must be eol, pre, post, plate or repeatable");
		};
		String text = Json.has(req, "text") ? Json.str(req, "text") : null;
		int tx = p.startTransaction("session comment");
		try {
			p.getListing().setComment(a, ct, text);
		}
		finally {
			p.endTransaction(tx, true);
		}
		return Json.of("address", hex(a), "type", Json.str(req, "type", "eol"));
	}

	/**
	 * The window's <i>Analysis &gt; Auto Analyze</i>, the same way {@code analyzeHeadless} runs
	 * it: optional analysis options first, then all analyzers (or those triggered by a restricted
	 * address set) in this thread, under one transaction.
	 */
	private JsonElement analyze(ProgramEntry e, JsonObject req, RequestMonitor m) {
		Program p = e.program;
		JsonObject opts = Json.obj(req, "options");
		if (opts != null) {
			setAnalysisOptions(p, opts);
		}
		AddressSet restrict = null;
		if (Json.has(req, "ranges")) {
			restrict = new AddressSet();
			for (JsonElement r : req.getAsJsonArray("ranges")) {
				JsonArray pair = r.getAsJsonArray();
				restrict.add(address(p, pair.get(0).getAsString()),
					address(p, pair.get(1).getAsString()));
			}
		}
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		long t0 = System.nanoTime();
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
		int tx = p.startTransaction("Analysis");
		try {
			mgr.initializeOptions();
			mgr.reAnalyzeAll(restrict);
			mgr.startAnalysis(m);
			if (m.isCancelled()) {
				mgr.cancelQueuedTasks();
			}
			else {
				GhidraProgramUtilities.markProgramAnalyzed(p);
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
		if (m.isCancelled()) {
			throw new SessionException(SessionException.CANCELLED,
				"analysis stopped " + (m.timedOut() ? "at its timeout" : "on cancel") +
					"; what ran so far is kept in memory (unsaved)",
				Json.of("program", e.key));
		}
		return Json.of("program", e.key, "analyzed", true, "seconds",
			(System.nanoTime() - t0) / 1e9, "functions", p.getFunctionManager().getFunctionCount(),
			"changed", p.isChanged());
	}

	private static void setAnalysisOptions(Program p, JsonObject opts) {
		Options options = p.getOptions(Program.ANALYSIS_PROPERTIES);
		int tx = p.startTransaction("session analysis options");
		try {
			for (Map.Entry<String, JsonElement> o : opts.entrySet()) {
				String n = o.getKey();
				if (!options.contains(n)) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"no analysis option named '" + n + "'");
				}
				OptionType t = options.getType(n);
				JsonElement v = o.getValue();
				switch (t) {
					case BOOLEAN_TYPE -> options.setBoolean(n, v.getAsBoolean());
					case INT_TYPE -> options.setInt(n, v.getAsInt());
					case LONG_TYPE -> options.setLong(n, v.getAsLong());
					case DOUBLE_TYPE -> options.setDouble(n, v.getAsDouble());
					case STRING_TYPE -> options.setString(n, v.getAsString());
					default -> throw new SessionException(SessionException.BAD_REQUEST,
						"option '" + n + "' has type " + t + ", which a session cannot set; " +
							"use a script");
				}
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
	}

	// ---- import ----------------------------------------------------------------------------

	/**
	 * Imports a file (any format a Ghidra loader accepts: PE EXE or DLL, ELF, Mach-O, raw, ...)
	 * into a writable project and opens it writable for the caller. A file whose SHA-256 is
	 * already in that project is not imported again unless {@code "duplicate":true}.
	 */
	private JsonElement importProgram(Client c, JsonObject req, RequestMonitor m) {
		ProjectEntry p = projectFor(c, req);
		if (!p.writable()) {
			throw new SessionException(SessionException.READ_ONLY,
				"import needs project " + p.id +
					" open writable (open_project \"writable\":true)");
		}
		File file = new File(Json.str(req, "file")).getAbsoluteFile();
		if (!file.isFile()) {
			throw new SessionException(SessionException.NOT_FOUND, "no such file: " + file);
		}
		String folder = Json.str(req, "folder", "/");
		long t0 = System.nanoTime();
		String sha;
		try {
			sha = HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, file);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
		String saved;
		Lock pl = lockProject(p, false, waitMs(req), "import");
		try {
			if (!Json.bool(req, "duplicate", false)) {
				List<String> same = new ArrayList<>();
				findBySha(p.data().getRootFolder(), sha, same);
				if (!same.isEmpty()) {
					JsonObject r = Json.of("imported", false, "project", p.id, "sha256", sha);
					Json.put(r, "existing", same);
					Json.put(r, "note", "already in the project; open_program it, or pass " +
						"\"duplicate\":true to import again");
					return r;
				}
			}
			MessageLog log = new MessageLog();
			try {
				DomainFolder dest =
					ProjectDataUtils.createDomainFolderPath(p.data().getRootFolder(), folder);
				ProgramLoader.Builder b = ProgramLoader.builder()
						.source(file)
						.project(p.project)
						.projectFolderPath(dest.getPathname())
						.log(log)
						.monitor(m);
				if (Json.has(req, "name")) {
					b.name(Json.str(req, "name"));
				}
				if (Json.has(req, "language")) {
					b.language(Json.str(req, "language"));
				}
				if (Json.has(req, "compiler")) {
					b.compiler(Json.str(req, "compiler"));
				}
				synchronized (IMPORT) {
					AppInfo.setActiveProject(p.project);
					try (LoadResults<Program> results = b.load()) {
						saved = results.getPrimary().save(m).getPathname();
						p.invalidateRevision();
					}
				}
			}
			catch (CancelledException ex) {
				throw cancelled(m);
			}
			catch (SessionException ex) {
				throw ex;
			}
			catch (Exception ex) {
				throw new SessionException(SessionException.FAILED,
					"import failed: " + ex.getMessage(), Json.of("log", log.toString()), ex);
			}
		}
		finally {
			pl.unlock();
		}
		double importS = (System.nanoTime() - t0) / 1e9;
		JsonObject openReq = Json.of("path", saved, "writable", true, "project", p.id);
		if (req.has("wait")) {
			openReq.add("wait", req.get("wait"));
		}
		JsonObject info = (JsonObject) openProgram(c, openReq, m);
		JsonObject r = Json.of("imported", true, "project", p.id, "path", saved, "key",
			p.id + ":" + saved, "sha256", sha, "importSeconds", importS, "program", info);
		if (Json.bool(req, "analyze", false)) {
			JsonObject areq = Json.of("program", p.id + ":" + saved);
			if (req.has("timeout")) {
				areq.add("timeout", req.get("timeout"));
			}
			r.add("analysis", withProgram(c, areq, "analyze", true, true,
				e -> analyze(e, areq, m)));
			r.add("save", withProgram(c, areq, "save", true, true,
				e -> save(e, Json.of("comment", "import + analysis"), m)));
		}
		return r;
	}

	private static void findBySha(DomainFolder folder, String sha, List<String> out) {
		for (DomainFile f : folder.getFiles()) {
			if (sha.equalsIgnoreCase(f.getMetadata().get("Executable SHA256"))) {
				out.add(f.getPathname());
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			findBySha(sub, sha, out);
		}
	}

	// ---- scripts ---------------------------------------------------------------------------

	/**
	 * Runs a GhidraScript (by name on the script path, or by file path) with a program as
	 * {@code currentProgram}, the way the window's Script Manager does, and returns what it
	 * printed.
	 * <ul>
	 * <li>On a program this client owns writable: exclusive, and its changes stay (unsaved unless
	 * {@code "save":true}).</li>
	 * <li>Otherwise <i>contained</i>: the script runs inside an outer transaction that is always
	 * rolled back, so it cannot change what other clients see or what is saved. Contained scripts
	 * share the program lock and run concurrently unless {@code "exclusive":true}.</li>
	 * <li>With {@code "program":null} (or no program open) it runs with no current program, with
	 * the client's active project (if any) as its project.</li>
	 * </ul>
	 * This is not a sandbox: a script is Java with the session's rights.
	 */
	private JsonElement script(Client c, JsonObject req, RequestMonitor m) {
		String name = Json.str(req, "script");
		ResourceFile src = findScript(name);
		boolean noProgram = req.has("program") && req.get("program").isJsonNull();
		ProgramEntry e = (noProgram || (c.active == null && !req.has("program"))) ? null
				: selected(c, req);
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		if (e == null) {
			ProjectEntry p = null;
			if (Json.has(req, "project") || c.activeProject != null) {
				p = projectFor(c, req);
			}
			if (p == null) {
				return runScript(src, req, null, null, null, "none", m);
			}
			ProjectEntry pp = p;
			return inProject(p, req, "script",
				x -> runScript(src, req, pp.project, null, null, "none", m));
		}
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), "script");
		try {
			boolean owner = e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c;
			boolean exclusive = owner || Json.bool(req, "exclusive", false);
			Lock l = e.acquire(exclusive, waitMs(req), c, "script " + name);
			try {
				if (e.program == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				owner = e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c;
				JsonObject r = runScript(src, req, p.project, e.program, e,
					owner ? "owner" : "contained", m);
				if (owner && Json.bool(req, "save", false) && e.program.isChanged()) {
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

	private static ResourceFile findScript(String name) {
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

	private JsonObject runScript(ResourceFile src, JsonObject req, Project project, Program p,
			ProgramEntry e, String mode, RequestMonitor m) {
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw, true);
		GhidraScript s;
		synchronized (SCRIPT_COMPILE) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
			if (provider == null) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"no script provider for " + src.getName());
			}
			try {
				s = provider.getScriptInstance(src, pw);
			}
			catch (Exception ex) {
				pw.flush();
				throw new SessionException(SessionException.FAILED,
					"script did not load: " + ex.getMessage(), Json.of("output", sw.toString()),
					ex);
			}
		}
		s.setScriptArgs(Json.strings(req, "args").toArray(new String[0]));
		bindHeadless(s);
		ProgramLocation loc = null;
		if (p != null && Json.has(req, "address")) {
			loc = new ProgramLocation(p, address(p, Json.str(req, "address")));
		}
		GhidraState state = new GhidraState(null, project, p, loc, null, null);
		boolean contained = p != null && mode.equals("contained");
		int outer = -1;
		if (contained) {
			outer = p.startTransaction("session: contained script (rolled back)");
		}
		long t0 = System.nanoTime();
		Throwable failure = null;
		try {
			s.execute(state, new ScriptControls(pw, pw, false, m));
		}
		catch (Throwable t) {
			failure = t;
		}
		finally {
			if (contained) {
				p.endTransaction(outer, false);
			}
			pw.flush();
		}
		String out = sw.toString();
		JsonObject r = Json.of("script", src.getAbsolutePath(), "mode", mode, "program",
			e == null ? null : e.key, "seconds", (System.nanoTime() - t0) / 1e9, "chars",
			out.length(), "truncated", out.length() > cap, "output",
			out.length() > cap ? out.substring(0, cap) : out, "changed",
			p != null && p.isChanged());
		Json.put(r, "artifact", Json.str(req, "artifact", null));
		if (failure != null) {
			if (m.isCancelled() || failure instanceof CancelledException) {
				throw new SessionException(SessionException.CANCELLED,
					"script " + (m.timedOut() ? "timed out" : "cancelled"), r);
			}
			throw new SessionException(SessionException.FAILED,
				"script failed: " + failure.getClass().getSimpleName() + ": " +
					failure.getMessage(),
				r, failure);
		}
		return r;
	}

	/**
	 * Lets {@link HeadlessScript} subclasses run here as under {@code analyzeHeadless}
	 * ({@code storeHeadlessValue} and friends). The setter is package-private in Ghidra, so it is
	 * reached reflectively rather than by editing Ghidra's class.
	 */
	private static void bindHeadless(GhidraScript s) {
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

	private static SessionException cancelled(RequestMonitor m) {
		return new SessionException(SessionException.CANCELLED,
			m.timedOut() ? "timed out" : "cancelled");
	}
}
