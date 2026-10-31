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
 * Lock order, always: a scheduler slot, then one {@link ProjectRegistry.Slot#transition} (only to
 * open, join or close that one project; it is never held across a command), then one
 * {@link ProjectEntry#lock} (shared as a pin by every command), then one {@link ProgramEntry#lock}.
 * No wait for a lock happens inside a monitor. The maps are concurrent and never held across a
 * wait.
 * <p>
 * Session keeps the state, the client life cycle and the dispatch of a request to the
 * command classes; the commands live in {@link ProjectCommands},
 * {@link ProgramCommands} and the other command classes, which receive this session.
 * Adding a command: see {@code ARCHITECTURE.md} in the module directory.
 */
final class Session {

	/** The default of {@code cleanupGraceS}: how long a dead client's requests may keep running (3.5). */
	static final int DEFAULT_CLEANUP_GRACE_S = 15;
	/** The default of {@code abandonWaitS}: the wait of every cleanup lock wait after that (3.5). */
	static final int DEFAULT_ABANDON_WAIT_S = 5;

	/**
	 * How long a dead client's running requests get to end after their cancel before they are
	 * interrupted ({@code cleanupGraceS}).
	 */
	static long cleanupGraceMs() {
		return Math.max(0, Settings.integer("cleanupGraceS", DEFAULT_CLEANUP_GRACE_S)) * 1000L;
	}

	/**
	 * The longest any wait on behalf of a dead client takes: after the interrupt, and for each lock
	 * its release needs ({@code abandonWaitS}). It replaces the 600 s waits of hydra.3.
	 */
	static long abandonWaitMs() {
		return Math.max(0, Settings.integer("abandonWaitS", DEFAULT_ABANDON_WAIT_S)) * 1000L;
	}

	private final long startedAt = System.currentTimeMillis();
	/** The watchdog thread that publishes the snapshot {@code health} reads (E5), or null. */
	private volatile Watchdog watchdog;
	/**
	 * The life cycle of the projects: a state machine per project path (E3c, BP8). The two maps
	 * below stay as the read indexes of the open projects.
	 */
	final ProjectRegistry registry = new ProjectRegistry();
	/** Serialises {@link #close} only. */
	private final java.util.concurrent.locks.ReentrantLock closeLock =
		new java.util.concurrent.locks.ReentrantLock();
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
		// the capabilities of the features this class and Connection carry (3.1: a package enables
		// its own from a class it owns)
		Advertised.capability("errorNext", 1);
		Advertised.capability("identity", 1);
		// E5: health answers on the reader thread from the watchdog's snapshot (3.4); the figures
		// of other packages join through Health.contribute (the governor, workers: E7, E9)
		Advertised.capability("health", 1);
		Health.contribute("waits", WaitStats::describe);
		Health.contribute("leakedWorkers",
			() -> new com.google.gson.JsonPrimitive(ScriptCommands.leakedWorkers()));
		Health.contribute("leaked", ScriptCommands::leakedList);
		Health.contribute("repairs", Health::repairs);
		Health.contribute("scriptWorkers", ScriptWorker::describe); // E7, after the four E5 pins
		// E3b: a cancel reaches a request in a lock wait (3.5); the dead-client release is bounded
		Advertised.capability("cancelWait", 1);
		// a value that is not an integer is a usage error at start-up, not a failure of the first
		// dead client (Settings.integer names the key)
		cleanupGraceMs();
		abandonWaitMs();
		Settings.integer("orphanKeepS", 0);
		Settings.integer("writeStallMs", 5000);
		Advertised.limit("cleanupGraceS", () -> cleanupGraceMs() / 1000);
		Advertised.limit("abandonWaitS", () -> abandonWaitMs() / 1000);
		Waits.slots(lane -> scheduler.slots(lane.equals("long") ? Scheduler.Lane.LONG
				: lane.equals("maint") ? Scheduler.Lane.MAINT : Scheduler.Lane.QUICK));
		// a lock whose release finished a request that stood in the way of a dead client's leave
		// lets that leave finish at once, off the releasing request's thread
		ProgramEntry.afterRelease = e -> completer.execute(() -> completeLeaves(e));
	}

	/** A reopen that readers kept pending this long gets one short queued attempt from the reap. */
	static final long REOPEN_ESCALATE_MS = 3_000;
	static final long REOPEN_ESCALATE_WAIT_MS = 250;

	/** Finishes pending leaves without ever waiting (one thread, so a burst never piles up). */
	private final java.util.concurrent.ExecutorService completer =
		java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, "session-leave-completer");
			t.setDaemon(true);
			return t;
		});

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
		// the whole release is bounded by abandonWaitS (3.5): what cannot be had in time is flagged
		// abandoned or left pending (ProgramEntry.pendingLeaves), never waited for 10 minutes
		long end = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(abandonWaitMs());
		for (String id : joined) {
			ProjectEntry p = projectsById.get(id);
			if (p == null) {
				continue;
			}
			try {
				long left = Math.max(0, (end - System.nanoTime()) / 1_000_000L);
				projectCmds.leaveProject(c, p, true, left);
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
		closeLock.lock();
		try {
			if (shuttingDown && projectsById.isEmpty()) {
				return;
			}
			shuttingDown = true;
			clients.values().forEach(c -> c.running.values().forEach(RequestMonitor::cancel));
			// a background build is cancelled and deletes its temporary folder, or is left to
			// the exit (the next start removes its folder)
			upgradeCache.shutdown(3_000);
			registry.closeAll(30_000, p -> {
				try {
					projectCmds.closeProjectEntry(p, 30_000, true);
				}
				catch (RuntimeException e) {
					Msg.error(this, "shutdown: could not close project " + p.id, e);
				}
			});
			// a project that never had a slot (nothing opens one outside the registry) is closed too
			for (ProjectEntry p : new ArrayList<>(projectsById.values())) {
				try {
					projectCmds.closeProjectEntry(p, 30_000, true);
				}
				catch (RuntimeException e) {
					Msg.error(this, "shutdown: could not close project " + p.id, e);
				}
			}
		}
		finally {
			closeLock.unlock();
		}
	}

	/**
	 * Closes read-only programs and projects that nobody has used for {@link #keepWarmMs}, and
	 * programs upgraded in memory that nobody uses once their upgrade cache copy is ready (the
	 * next open takes the copy, and the in-memory upgrade's temporary database is freed). Never
	 * waits: anything in use is left for the next round.
	 */
	void reap() {
		reap(keepWarmMs);
	}

	/**
	 * {@link #reap()} with another retention: {@code 0} closes every program and project nobody
	 * uses, which the governor (E9) does before it refuses an open for lack of room.
	 */
	void reap(long warmMs) {
		long now = System.currentTimeMillis();
		long orphanKeepMs = Math.max(0, Settings.integer("orphanKeepS", 0)) * 1000L;
		for (ProjectEntry p : projectsById.values()) {
			for (ProgramEntry e : p.programs.values()) {
				if (e.hasDeferredWork()) {
					completeLeaves(e); // never waits
				}
				if (e.reopenPendingSince > 0 && now - e.reopenPendingSince >= REOPEN_ESCALATE_MS) {
					// steady readers never left the lock free: one short, bounded queued attempt
					projectCmds.completeReopen(e, REOPEN_ESCALATE_WAIT_MS);
				}
				if (orphanKeepMs > 0 && e.orphanedSince > 0 && now - e.orphanedSince >= orphanKeepMs &&
					e.holdsOrphanedWork()) {
					expireOrphan(p, e);
				}
				if (e.userCount() == 0 && !e.holdsOrphanedWork() &&
					(now - e.lastUsed >= warmMs || programCmds.swappable(e))) {
					closeIdleProgram(p, e);
				}
			}
			if (p.closePending) {
				// the last leave could not close it while a request of a gone client still ran
				if (p.closed || p.userCount() > 0) {
					p.closePending = false;
				}
				else if (p.programs.values().stream().noneMatch(ProgramEntry::holdsOrphanedWork) &&
					p.programs.values().stream().allMatch(x -> x.pendingLeaves.isEmpty())) {
					try {
						if (registry.closeIdle(p, x -> projectCmds.closeProjectEntry(x, 0, true))) {
							Msg.info(this, "closed project " + p.id + " " + p.canonical +
								" that its last user left while a request ran");
						}
						p.closePending = false;
					}
					catch (SessionException e) {
						// the request still runs; next round
					}
					continue;
				}
			}
			if (p.userCount() == 0 && p.programs.isEmpty() && now - p.lastUsed >= warmMs) {
				try {
					if (registry.closeIdle(p, x -> projectCmds.closeProjectEntry(x, 0, true))) {
						Msg.info(this, "closed idle project " + p.id + " " + p.canonical);
					}
				}
				catch (SessionException e) {
					// in use after all; next round
				}
			}
		}
	}

	/**
	 * Finishes the leaves of dead clients that could not take the program's exclusive lock in time
	 * (3.5). It only ever tries: the project's shared lock and then the program's exclusive lock
	 * without queueing, so it can neither wait nor make later readers wait; if either is not free
	 * now, the next release or the next reap tries again.
	 */
	void completeLeaves(ProgramEntry e) {
		tryCompleteLeaves(e);
		// the leave that was waiting is done: a writable project that nobody uses any more closes
		// now, as leaveProject would have done (its Ghidra project lock is released)
		ProjectEntry p = e.project;
		if (e.pendingLeaves.isEmpty() && !p.closed && p.userCount() == 0 &&
			(p.writable() || keepWarmMs == 0)) {
			if (p.programs.values().stream().noneMatch(ProgramEntry::holdsOrphanedWork) &&
				p.programs.values().stream().allMatch(x -> x.pendingLeaves.isEmpty())) {
				try {
					// the slot's state machine decides (a join in flight keeps the project open); no
					// monitor is held across the close (BP8)
					registry.closeIdle(p, x -> projectCmds.closeProjectEntry(x, 0, true));
				}
				catch (SessionException ex) {
					// in use after all; the next reap tries again
				}
			}
		}
	}

	private void tryCompleteLeaves(ProgramEntry e) {
		ProjectEntry p = e.project;
		if (e.disposePending) {
			programCmds.tryDisposeNow(e); // the last plain reader left while a request held the lock
		}
		if (e.reopenPendingSince > 0) {
			projectCmds.completeReopen(e, 0); // a refresh could not reopen it while readers ran
		}
		for (Client c : new ArrayList<>(e.pendingLeaves)) {
			Lock pl = p.lock.readLock();
			if (p.closed || !pl.tryLock()) {
				return;
			}
			try {
				Lock wl = e.lock.writeLock();
				if (!wl.tryLock()) {
					return;
				}
				try {
					if (!e.pendingLeaves.remove(c)) {
						continue;
					}
					if (p.programs.get(e.path) == e && e.program != null) {
						programCmds.releaseUseHeld(c, e, true);
						Msg.info(this, c.label() + ": the leave of " + e.key +
							" that was waiting for its lock is done");
					}
				}
				catch (RuntimeException ex) {
					Msg.error(this, c.label() + ": could not finish leaving " + e.key, ex);
				}
				finally {
					wl.unlock();
				}
			}
			finally {
				pl.unlock();
			}
		}
	}

	/**
	 * {@code orphanKeepS > 0}: the unsaved edits of a shared program whose last writer died are
	 * written to {@code <stateDir>/recovery/} and then discarded (3.5). Never waits.
	 */
	private void expireOrphan(ProjectEntry p, ProgramEntry e) {
		String state = Json.str(Identity.paths(), "stateDir", null);
		if (state == null) {
			return; // no state directory: the edits are kept
		}
		Lock pl = p.lock.readLock();
		if (!pl.tryLock()) {
			return;
		}
		try {
			if (!e.lock.writeLock().tryLock()) {
				return;
			}
			try {
				if (!e.holdsOrphanedWork() || p.programs.get(e.path) != e) {
					return;
				}
				JsonObject dump = Json.of("program", e.key, "path", e.path, "project", p.id, "revision",
					e.revision, "sha256", e.program.getExecutableSHA256(), "orphanedSince",
					e.orphanedSince, "savedSeq", e.savedSeq, "journalSeq", e.journal.seq());
				dump.add("entries", e.journal.since(e.savedSeq, null, Integer.MAX_VALUE));
				java.nio.file.Path dir = java.nio.file.Path.of(state, "recovery");
				java.nio.file.Files.createDirectories(dir);
				String name = (p.id + e.path).replaceAll("[^A-Za-z0-9._-]", "_") + "-" +
					System.currentTimeMillis() + ".journal.json";
				java.nio.file.Files.writeString(dir.resolve(name), Json.GSON.toJson(dump));
				Msg.warn(this, e.key + ": the unsaved edits of its dead writer were kept for " +
					(System.currentTimeMillis() - e.orphanedSince) / 1000 + " s; written to " +
					dir.resolve(name) + " and discarded (orphanKeepS)");
				e.orphanedSince = 0;
				e.disposeDecompilers();
				programCmds.releaseProgramObject(e);
				e.savedSeq = e.journal.seq(); // nothing unsaved any more: it was written and discarded
				e.mode = null;
				if (e.userCount() == 0) {
					programCmds.disposeProgram(e);
				}
				else {
					// readers remain: they get the saved program, read-only, as when a writer leaves
					e.program = programCmds.openReadOnly(e, e.file, new RequestMonitor(null, null));
					e.mode = ProgramEntry.Mode.READ_ONLY;
					e.stampRevision();
				}
			}
			catch (java.io.IOException | RuntimeException ex) {
				Msg.error(this, e.key + ": could not write the orphan journal; keeping the edits", ex);
			}
			finally {
				e.lock.writeLock().unlock();
			}
		}
		finally {
			pl.unlock();
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

	/** Epoch ms at which this session started (the base of {@code health.uptimeMs}). */
	long startedAtMs() {
		return startedAt;
	}

	/** Starts the watchdog (once): the first tick is published before this returns (3.4). */
	synchronized void startWatchdog() {
		if (watchdog == null) {
			Watchdog w = new Watchdog(this);
			watchdog = w;
			w.start();
		}
	}

	/** The test hook behind {@code debug_stall what:"watchdog"}. */
	void watchdogStall(long ms) {
		Watchdog w = watchdog;
		if (w == null) {
			throw new SessionException(SessionException.FAILED, "the watchdog is not running");
		}
		w.stall(ms);
	}

	/** Commands answered on the connection's reader thread, even while another runs. */
	static boolean isInline(String cmd) {
		return cmd.equals("ping") || cmd.equals("cancel") || cmd.equals("status") ||
			cmd.equals("health");
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
			case "health": // inline: from the watchdog's snapshot, takes no lock (3.4)
				return Health.reply(startedAt, c);
			case "debug_stall": // registered only with -Dghidra.session.testHooks=true (D22)
				if (Health.testHooks()) {
					return Health.debugStall(this, req);
				}
				break; // otherwise it is an unknown command, below
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
		// E9: the resource governor decides before the request queues for a slot (3.11); a refusal
		// is an immediate structured busy{reason:"capacity"}. The reservation ends with the request.
		Governor.Admission admission = Governor.admit(c, cmd, req);
		Scheduler.Ticket slot;
		try {
			slot = cmd.equals("import") ? null : scheduler.admit(c, cmd, req, m, waitMs(req));
		}
		catch (SessionException ex) {
			admission.close();
			if (SessionException.CANCELLED.equals(ex.code())) {
				m.cancelPhase("queued"); // cancelled.details.phase of a slot wait (3.3)
			}
			throw ex;
		}
		catch (RuntimeException | Error ex) {
			admission.close();
			throw ex;
		}
		Scheduler.bind(slot); // the optional slot yield of a lock wait finds its ticket here (D39)
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
				case "seal_project" -> Seals.sealProject(this, c, req);
				case "prepare_upgrade" -> projectCmds.prepareUpgrade(c, req, m);
				case "refresh", "reopen" -> projectCmds.refresh(c, req, m);
				case "close_project" -> projectCmds.closeProject(c, req);
				case "project" -> access.inProject(access.projectFor(c, req), req, cmd,
					x -> x.info(c));
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
				case "functions" -> {
					// a sealed table of the program's current state answers before any lock
					JsonElement sealed = queries.functionsSealed(access.selected(c, req), req);
					yield sealed != null ? sealed
							: access.withProgram(c, req, cmd, false, false,
								e -> queries.functions(e, e.program, req, true)); // sent as is
				}
				case "decompile" -> {
					// a completed decompile of the same function and state answers before any lock
					JsonElement sealed = req.has("overlay") ? null
							: queries.decompileSealed(access.selected(c, req), req);
					yield sealed != null ? sealed
							: access.withProgram(c, req, cmd, false, false,
								e -> queries.decompile(e.program, e, req, m));
				}
				case "rename" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.single(c, e, cmd, req));
				case "edit" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.editProgram(c, e, ops(req, null), req));
				case "journal" -> access.withProgram(c, req, cmd, false, false,
					e -> edits.journalOf(e, req));
				case "discard_edits" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.discardEdits(c, e, req));
				case "comment" -> access.withProgram(c, req, cmd, true, true,
					e -> edits.single(c, e, cmd, req));
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
			Scheduler.bind(null);
			admission.close();
			if (slot != null) {
				slot.close();
			}
		}
	}

	// ---- session ---------------------------------------------------------------------------

	private JsonElement hello(Client c, JsonObject req) {
		// The connection's reader thread has normally fixed the protocol already, before this runs
		// on the worker pool (Connection.handleLine); this is a no-op then, and a later hello never
		// changes it (PROTOCOL-3.md 3.1).
		c.negotiate(req);
		c.name = Json.str(req, "client", c.name);
		c.harness = Json.str(req, "harness", c.harness);
		c.clientVersion = Json.str(req, "clientVersion", c.clientVersion);
		JsonObject o = info(c);
		Json.put(o, "client", c.id);
		return o;
	}

	/**
	 * The hello result and the head of {@code status}. {@code c} is the asking client (null for the
	 * {@code ready} event, which is a protocol 2 shape).
	 */
	JsonObject info(Client c) {
		Runtime rt = Runtime.getRuntime();
		JsonObject o = Json.of("protocol", c == null ? HydraInfo.PROTOCOL : c.protocol(), "minClient", HydraInfo.minClient(),
			"hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
			Application.getApplicationVersion(), "installId", HydraInfo.installId(), "startedAt",
			startedAt, "ghidra", Application.getApplicationVersion(), "install",
			Application.getInstallationDirectory().getAbsolutePath(), "java",
			System.getProperty("java.version"), "pid", ProcessHandle.current().pid(), "uptimeMs",
			System.currentTimeMillis() - startedAt, "listen", listenInfo, "launch", launchInfo,
				"keepWarmS", keepWarmMs / 1000, "memory",
				Json.of("usedMb", (rt.totalMemory() - rt.freeMemory()) >> 20, "committedMb",
					rt.totalMemory() >> 20, "maxMb", rt.maxMemory() >> 20));
		if (c != null && c.v3()) { // conditional C1: the one place the v3 identity block is built
			Json.put(o, "protocolMin", HydraInfo.PROTOCOL_MIN);
			Json.put(o, "protocolMax", HydraInfo.PROTOCOL_MAX);
			o.add("capabilities", Advertised.capabilities());
			o.add("limits", Advertised.limits());
			o.add("policy", Advertised.policy());
			o.add("paths", Identity.paths());
			o.add("platform", Identity.platform());
			o.add("analysisIdentity", Identity.analysisIdentity());
		}
		JsonArray ps = new JsonArray();
		for (ProjectEntry p : projectsById.values()) {
			ps.add(p.info(c));
		}
		o.add("projects", ps);
		return o;
	}

	private JsonElement status(Client c) {
		JsonObject o = info(c);
		Json.put(o, "you", c.id);
		JsonArray ps = new JsonArray();
		for (ProjectEntry p : projectsById.values()) {
			for (ProgramEntry e : p.programs.values()) {
				ps.add(e.describeUse(upgradeCache, c.v3()));
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
		o.add("scheduler", scheduler.describe(c.v3()));
		o.add("imports", ImportGate.GLOBAL.describe());
		if (c.v3()) {
			// D49: the deterministic evidence that no client blocks another (K13), until E5's health
			// command reports the same block
			o.add("waits", WaitStats.describe());
			o.add("projectStates", registry.describe());
		}
		Caller.Identity me = Caller.current(c);
		if (me != null) {
			Json.put(o, "youAre", Json.of("client", me.name(), "harness", me.harness(),
				"labelled", me.labelled()));
		}
		o.add("upgradeCache", upgradeCache.describe());
		if (HostDecompileBackend.enabled()) {
			// only while the host backend is on, so the default reply is unchanged
			o.add("decompileBackend", HostDecompileBackend.describe());
		}
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
			JsonObject j = p.info(c);
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
