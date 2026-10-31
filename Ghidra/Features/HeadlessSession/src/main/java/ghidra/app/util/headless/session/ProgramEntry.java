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

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.MappedProgramSnapshot;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

/**
 * One program open in the session, shared by every client that opened it.
 * <p>
 * <b>Mode.</b> An entry is either {@link Mode#READ_ONLY} (an unshared read-only instance; nothing
 * can be saved) or {@link Mode#WRITABLE} with exactly one {@link #owner}. Only the owner may edit,
 * analyse or save. Other clients may keep reading a writable program and then see the owner's
 * unsaved changes, as a second tool window would.
 * <p>
 * <b>Warm.</b> A read-only entry whose last user left stays open for the session's
 * {@code keepWarm} time, so the next client opens it at no cost and finds its decompilers warm.
 * <p>
 * <b>Lock.</b> Every command on the program holds {@link #lock}: reads share it, edits, analysis,
 * saves and mode changes hold it exclusively. A request that cannot get it within its
 * {@code wait} fails with {@code busy} and the current holder, instead of queueing forever.
 */
final class ProgramEntry implements Decompilers, DecompilerGate.Pool {

	/**
	 * How the program is open: read-only; writable with one {@link #owner}; or writable and
	 * <b>shared</b> by several {@link #writers}, whose changes are committed one at a time under
	 * the program's exclusive lock and recorded in the {@link #journal}.
	 */
	enum Mode {
		READ_ONLY, WRITABLE, SHARED;

		String json() {
			return switch (this) {
				case READ_ONLY -> "read_only";
				case WRITABLE -> "writable";
				case SHARED -> "shared";
			};
		}
	}

	/** In {@link Mode#SHARED}: the clients that may change it. Guarded by {@link #users}. */
	final Set<Client> writers = new LinkedHashSet<>();
	/** Who changed what, for writable programs (owner and shared mode). */
	final Journal journal = new Journal();
	/** The journal's {@code seq} at the last save here: later entries are unsaved. */
	volatile long savedSeq;
	/**
	 * Set when the last writer of a shared program disconnected with unsaved changes: they are
	 * kept, not discarded, until a client joins and saves or discards them.
	 */
	volatile long orphanedSince;

	/** True when {@code c} may change it: its owner, or one of its shared writers. */
	boolean isWriter(Client c) {
		if (mode == Mode.WRITABLE) {
			return owner == c;
		}
		if (mode == Mode.SHARED) {
			synchronized (users) {
				return writers.contains(c);
			}
		}
		return false;
	}

	List<Integer> writerIds() {
		List<Integer> ids = new ArrayList<>();
		synchronized (users) {
			writers.forEach(w -> ids.add(w.id));
		}
		return ids;
	}

	/** A shared program whose writers all left while it had unsaved changes. */
	boolean holdsOrphanedWork() {
		Program p = program;
		if (mode != Mode.SHARED || p == null) {
			return false;
		}
		synchronized (users) {
			if (!writers.isEmpty()) {
				return false;
			}
		}
		return p.isChanged();
	}

	final ProjectEntry project;
	final String path;
	/** {@code <project id>:<path>}: unique across the session's projects. */
	final String key;
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	/** When the last request on it finished, for warm retention. */
	volatile long lastUsed = System.currentTimeMillis();

	// guarded by lock.writeLock() for writes; read under the read lock
	DomainFile file;
	Program program;
	Mode mode;
	Client owner;
	long openMs;
	/**
	 * The program's saved revision when it was opened (or last saved here): its path and its
	 * stored file's size, time and version ({@link Revision#ofProgram}).
	 */
	volatile String revision;
	/**
	 * When {@link #program} was opened from the upgrade cache: the reference on the read-only view
	 * of the copy that holds it (released with the program; the view closes with its last
	 * reference), the shared locks that keep the copy in place, and what the cache did.
	 */
	UpgradeCache.ViewRef cacheView;
	UpgradeCache.Lease cacheLease;
	JsonObject cacheInfo;
	/**
	 * When {@link #program} is in an older database format: its upgrade cache plan, whether it
	 * came from the cache ({@link #cacheView} set) or was upgraded in memory while a build makes
	 * the copy. Cleared with the program.
	 */
	volatile UpgradeCache.Plan cachePlan;
	/** Set by the open that started the build, for its answer ({@code "cacheBuild":"started"}). */
	boolean cacheBuildStarted;
	/**
	 * H2: the upgrade cache's version this writable open of a fork adopted
	 * ({@link UpgradeCache#adoptForFork}); a close that discards the changes before any save puts
	 * the fork back ({@link UpgradeCache#rollBack}).
	 */
	UpgradeCache.Adopted adopted;
	/**
	 * Hydra ({@code -Dhydra.memory.snapshotReads=true}): the memory-mapped sealed generation that
	 * serves the byte reads of {@link #program} while it is open read-only; closed with it.
	 */
	MappedProgramSnapshot snapshotReads;

	/** Clients using this program. Guarded by itself. */
	final Set<Client> users = new LinkedHashSet<>();

	/** What holds the exclusive lock now, for {@code busy} answers. */
	volatile String exclusiveHolder;
	volatile Client exclusiveClient;
	volatile String exclusiveCmd;
	/** The label the holder's request carried, if any. */
	volatile Caller.Identity exclusiveWho;
	volatile long exclusiveSince;
	/** When {@link #owner} opened it writable, for {@code not_owner} answers. */
	volatile long ownedSince;

	/**
	 * How the owner was named by the request that opened this program writable (its own
	 * {@code client}/{@code harness} labels, if it had any). Ownership itself belongs to the
	 * connection ({@link #owner}); this is what messages call the owner.
	 */
	volatile String ownerLabel;
	/** The identity the opening request carried, for the owner's holder record. */
	volatile Caller.Identity ownerWho;

	void setOwner(Client c) {
		owner = c;
		ownerWho = c == null ? null : Caller.current(c);
		ownerLabel = c == null ? null : Caller.label(c);
	}

	/** The owner as people see it: the opening request's label, else the connection's. */
	String ownerText() {
		Client o = owner;
		String l = ownerLabel;
		return l != null ? l : o == null ? "nobody" : o.label();
	}

	/** A pooled decompiler and when it was put back (E9: idle ones are disposed). */
	private record Pooled(DecompInterface d, long atNanos) {
	}

	/** Decompilers bound to {@link #program}, reused across requests. Guarded by itself. */
	private final Deque<Pooled> decompilers = new ArrayDeque<>();

	ProgramEntry(ProjectEntry project, String path) {
		this.project = project;
		this.path = path;
		this.key = project.id + ":" + path;
		DecompilerGate.track(this);
	}

	// ---- who holds the lock now, abandoned holders and unfinished leaves (3.5, E3b) -----------

	/** Requests waiting for this program's lock: the cap of 3.5 counts them (protocol 3). */
	final AtomicInteger waiters = new AtomicInteger();

	/** One request thread that holds this program's lock (shared or exclusive). */
	static final class Hold {
		final Client client;
		final String cmd;
		final long since = System.currentTimeMillis();
		final boolean exclusive;
		final Caller.Identity who;
		final String thread = Thread.currentThread().getName();
		int depth = 1;
		/** Set by the leave of its client when the lock could not be had: the hold is abandoned. */
		volatile long abandonedSince;

		Hold(Client client, String cmd, boolean exclusive, Caller.Identity who) {
			this.client = client;
			this.cmd = cmd;
			this.exclusive = exclusive;
			this.who = who;
		}
	}

	/** The holders by thread. */
	private final Map<Thread, Hold> holds = new java.util.concurrent.ConcurrentHashMap<>();
	/**
	 * Clients that left (or died) but whose leave could not take the exclusive lock in time: the
	 * leave is finished later, without waiting, when the lock is free ({@link Session#reap} or the
	 * release of the lock that stood in the way). Their ownership bits stay until then: this is
	 * the fallback 3.5 names for the ownership-bits question (E3b's choice; the coordinator
	 * records it as the decision in 3.5, it is not yet recorded there).
	 */
	final Set<Client> pendingLeaves = java.util.concurrent.ConcurrentHashMap.newKeySet();
	/** Run, off the releasing thread, after a release while {@link #pendingLeaves} is not empty. */
	static volatile java.util.function.Consumer<ProgramEntry> afterRelease;

	/** Flags every hold of {@code dead} as abandoned (its client is gone and the leave gave up). */
	void markAbandoned(Client dead) {
		long now = System.currentTimeMillis();
		for (Hold h : holds.values()) {
			if (h.client == dead && h.abandonedSince == 0) {
				h.abandonedSince = now;
			}
		}
	}

	/** True while a request of {@code c} still holds this program's lock. */
	boolean holdsBy(Client c) {
		for (Hold h : holds.values()) {
			if (h.client == c) {
				return true;
			}
		}
		return false;
	}

	private Hold firstAbandoned(boolean exclusiveOnly) {
		Hold best = null;
		for (Hold h : holds.values()) {
			if (h.abandonedSince > 0 && (!exclusiveOnly || h.exclusive) &&
				(best == null || h.abandonedSince < best.abandonedSince)) {
				best = h;
			}
		}
		return best;
	}

	/** The abandoned holds, for {@code status.programs[].abandonedRequests[]} (v3). */
	JsonArray abandonedRequests() {
		JsonArray a = new JsonArray();
		long now = System.currentTimeMillis();
		for (Hold h : holds.values()) {
			if (h.abandonedSince > 0) {
				a.add(Json.of("cmd", h.cmd, "client", h.client.id, "label", h.client.label(),
					"mode", h.exclusive ? "exclusive" : "shared", "since", h.since, "runningMs",
					now - h.since, "abandonedMs", now - h.abandonedSince, "thread", h.thread));
			}
		}
		return a;
	}

	// ---- analysis, deferred work and the project view this program was opened from (E3c) -------

	/** One analysis running on this program: it holds the lock exclusively for its whole run. */
	record Analysis(Client client, RequestMonitor monitor, String cmd, long since,
			Caller.Identity who) {
	}

	/**
	 * The analysis that holds this program now, or null. A protocol 3 reader that would have to wait
	 * for it is told {@code busy{reason:"analyzing"}} at once, with the job's progress (BP5, 3.13).
	 */
	volatile Analysis analysis;
	/**
	 * The read plane's function table holder for the program object this entry holds (see
	 * {@link FunctionTable.Cache#sealed}); a request finds it with one volatile read.
	 */
	volatile FunctionTable.Tag tableTag;
	/** The analyses that hold or wait for this lock, oldest first. Guarded by itself. */
	private final ArrayDeque<Analysis> analyses = new ArrayDeque<>();

	/**
	 * An analysis starts waiting for this program's exclusive lock: from now on a protocol 3 reader is
	 * told {@code analyzing} at once, also while the analysis still queues (on the fair lock a reader
	 * that arrives behind a queued exclusive waits for the whole analysis).
	 */
	void analysisStarts(Analysis a) {
		synchronized (analyses) {
			analyses.add(a);
			analysis = analyses.peekFirst();
		}
	}

	/** An analysis ended (or never got the lock). Idempotent. */
	void analysisEnds(Analysis a) {
		synchronized (analyses) {
			analyses.remove(a);
			analysis = analyses.peekFirst();
		}
	}
	/**
	 * Set when the last user left and the program could not be disposed without waiting for its
	 * lock: {@link Session#completeLeaves} (after the release of the lock that stood in the way, or
	 * the next reap) finishes it. Nobody waits for it.
	 */
	volatile boolean disposePending;
	/**
	 * Set by a refresh that could not reopen this program from the new project view without
	 * waiting for its lock (readers were running): it is reopened when the lock is free, readers
	 * meanwhile keep the program they have (a consistent older revision), nobody queues (BP7).
	 */
	volatile long reopenPendingSince;
	/** The project view {@link #program} (and {@link #file}) came from; one reference is held on it. */
	volatile ProjectEntry.View view;

	/** True when something is waiting to be finished the moment this lock is free. */
	boolean hasDeferredWork() {
		return !pendingLeaves.isEmpty() || disposePending || reopenPendingSince > 0;
	}

	/**
	 * Whose request holds this lock, as seen by a request of {@code waiter} that has to queue
	 * ({@link Waits#HELD_BY_NONE}, {@link Waits#HELD_BY_OTHER}, {@link Waits#HELD_BY_OPENER}). The
	 * wait of a second client for the request that is opening this very program is kept apart: it
	 * is one open per program, not a lock another client could have held back.
	 */
	int heldBy(Client waiter) {
		int result = Waits.HELD_BY_NONE;
		for (Hold h : holds.values()) {
			if (h.client == waiter) {
				continue;
			}
			if (program == null && h.exclusive && "open_program".equals(h.cmd)) {
				result = Math.max(result, Waits.HELD_BY_OPENER);
			}
			else {
				return Waits.HELD_BY_OTHER;
			}
		}
		return result;
	}

	/** Lock acquisition, bounded and cancel-aware ({@link Waits}); records the holder. */
	Lock acquire(boolean exclusive, long waitMs, Client c, String cmd) {
		// a dead client's request still holds the lock and ignores cancel: tell at once (3.5)
		// (not for a thread that already holds this program: a re-entrant acquire by the abandoned
		// holder's own script goes through its own hold)
		Hold ab = holds.containsKey(Thread.currentThread()) ? null : firstAbandoned(!exclusive);
		if (ab != null) {
			throw abandonedBusy(ab, exclusive);
		}
		// a protocol 3 reader of a program under analysis is told at once (BP5); not when its client is
		// gone: that analysis is being cancelled and released (E3b), so the wait is a short one
		Analysis an = analysis;
		if (!exclusive && an != null && !an.client().leaving && Waits.v3() &&
			!lock.isWriteLockedByCurrentThread()) {
			throw analyzingBusy(an);
		}
		Waits.Outcome got = Waits.lock(lock, exclusive, waitMs, waiters, this::heldBy);
		Lock l = exclusive ? lock.writeLock() : lock.readLock();
		if (got != Waits.Outcome.GOT) {
			Analysis late = analysis;
			if (!exclusive && late != null && !late.client().leaving && Waits.v3()) {
				// it queued in the instant before an analysis was marked: say what it waited for
				throw analyzingBusy(late);
			}
			throw busy(exclusive, waitMs, got == Waits.Outcome.QUEUE_FULL);
		}
		Caller.Identity who = Caller.current(c);
		holds.compute(Thread.currentThread(), (t, h) -> {
			if (h != null) {
				h.depth++;
				return h;
			}
			return new Hold(c, cmd, exclusive, who);
		});
		if (exclusive) {
			exclusiveHolder = Caller.label(c) + " " + cmd;
			exclusiveClient = c;
			exclusiveCmd = cmd;
			exclusiveWho = Caller.current(c);
			exclusiveSince = System.currentTimeMillis();
		}
		return l;
	}

	/** The {@code busy} of a lock that could not be had (or that too many requests already wait for). */
	private SessionException busy(boolean exclusive, long waitMs, boolean full) {
		boolean v3 = Waits.v3();
		JsonObject d = identity();
		Json.put(d, "wanted", exclusive ? "exclusive" : "shared");
		Json.put(d, "waitedMs", full ? 0 : waitMs);
		String holder = exclusiveHolder;
		Client hc = exclusiveClient;
		if (holder != null) {
			Json.put(d, "holder", holder);
			Json.put(d, "holderInfo",
				hc != null ? hc.holder(exclusiveCmd, exclusiveSince, exclusiveWho)
						: Json.of("label", holder));
			Json.put(d, "heldMs", System.currentTimeMillis() - exclusiveSince);
		}
		else {
			Json.put(d, "readers", lock.getReadLockCount());
		}
		Json.put(d, "suggest", "retry");
		if (full) {
			Json.put(d, "waiters", waiters.get());
			Json.put(d, "waitersMax", Waits.cap(Caller.monitor()));
		}
		d = SessionException.busyDetails(v3, d, full ? "lock_queue_full" : "lock_wait", null, null);
		SessionException ex = new SessionException(SessionException.BUSY,
			path + (full ? " already has " + waiters.get() + " requests waiting for it; retry later"
					: " is busy" + (holder != null ? " (" + holder + ")" : "") +
						"; retry, or pass a longer \"wait\""),
			d);
		if (v3) {
			ex.withRetryAfterMs(1000);
		}
		return ex;
	}

	/**
	 * The {@code busy} of a read that would wait for an analysis: {@code reason:"analyzing"} and the
	 * job ({@code cmd}, who, how long), its progress and an estimate of the time left when the
	 * progress says enough for one ({@code etaMs} null otherwise).
	 */
	private SessionException analyzingBusy(Analysis a) {
		long elapsed = System.currentTimeMillis() - a.since();
		RequestMonitor m = a.monitor();
		JsonObject progress = Json.of("message", m == null ? "" : m.getMessage(), "progress",
			m == null ? 0 : m.getProgress(), "maximum", m == null ? 0 : m.getMaximum());
		Long eta = null;
		if (m != null && m.getMaximum() > 0 && m.getProgress() > 0) {
			eta = elapsed * Math.max(0, m.getMaximum() - m.getProgress()) / m.getProgress();
		}
		JsonObject d = identity();
		Json.put(d, "wanted", "shared");
		Json.put(d, "holder", Caller.label(a.client()) + " " + a.cmd());
		Json.put(d, "holderInfo", a.client().holder(a.cmd(), a.since(), a.who()));
		Json.put(d, "heldMs", elapsed);
		Json.put(d, "job", Json.of("cmd", a.cmd(), "client", a.client().id, "label",
			a.client().label(), "startedAt", a.since(), "elapsedMs", elapsed));
		d.add("progress", progress);
		Json.put(d, "etaMs", eta);
		Json.put(d, "suggest", "retry");
		d = SessionException.busyDetails(true, d, "analyzing", null, null);
		return new SessionException(SessionException.BUSY,
			path + " is being analysed by " + Caller.label(a.client()) + " (" + elapsed / 1000 +
				" s so far); retry later, or read a generation that is not under analysis",
			d).withRetryAfterMs(eta != null ? Math.max(1000, Math.min(eta, 30_000)) : 5000);
	}

	/** The {@code busy} for a lock whose holder is a request of a client that is gone. */
	private SessionException abandonedBusy(Hold h, boolean exclusive) {
		boolean v3 = Waits.v3();
		long running = (System.currentTimeMillis() - h.since) / 1000;
		String text = "abandoned request " + h.cmd + ", client gone, running " + running + " s";
		JsonObject d = identity();
		Json.put(d, "wanted", exclusive ? "exclusive" : "shared");
		Json.put(d, "holder", text);
		Json.put(d, "holderInfo", h.client.holder(h.cmd, h.since, h.who));
		Json.put(d, "heldMs", System.currentTimeMillis() - h.since);
		Json.put(d, "suggest", "retry");
		d = SessionException.busyDetails(v3, d, "abandoned", null, true);
		SessionException ex = new SessionException(SessionException.BUSY,
			path + " is busy (" + text + "); retry later", d);
		if (v3) {
			ex.withRetryAfterMs(5000);
		}
		return ex;
	}

	/** Records the revision of {@link #file} as stored now. */
	void stampRevision() {
		DomainFile f = file;
		if (f == null) {
			revision = null;
			return;
		}
		try {
			revision = Revision.ofProgram(path, f.length(), f.getLastModifiedTime(),
				f.getVersion());
		}
		catch (java.io.IOException | RuntimeException e) {
			revision = null;
		}
	}

	void release(Lock l) {
		holds.computeIfPresent(Thread.currentThread(), (t, h) -> --h.depth > 0 ? h : null);
		if (l == lock.writeLock()) {
			exclusiveHolder = null;
			exclusiveClient = null;
			exclusiveCmd = null;
			exclusiveWho = null;
		}
		lastUsed = System.currentTimeMillis();
		l.unlock();
		if (hasDeferredWork()) {
			java.util.function.Consumer<ProgramEntry> after = afterRelease;
			if (after != null) {
				after.accept(this);
			}
		}
	}

	/**
	 * This program's identity for error details: {@code program} (its key), {@code path},
	 * {@code project} (id and {@code .gpr}) and, when it is open, its {@code sha256}. Unlocked
	 * reads.
	 */
	JsonObject identity() {
		JsonObject o = Json.of("program", key, "path", path, "project", project.id, "gpr",
			project.resolved.gpr().getPath());
		Program p = program;
		if (p != null) {
			try {
				Json.put(o, "sha256", p.getExecutableSHA256());
			}
			catch (RuntimeException e) {
				// closing meanwhile
			}
		}
		return o;
	}

	/** The owner as a holder record, for {@code not_owner} and {@code conflict} answers. */
	JsonObject ownerHolder() {
		Client o = owner;
		return o == null ? null : o.holder("open_program writable", ownedSince, ownerWho);
	}

	/**
	 * A decompiler for the program, after a permit of the decompiler gate (E9): the permit is held
	 * until {@link #returnDecompiler}. It waits at most {@code decompilerWaitS}, then {@code busy}.
	 */
	@Override
	public DecompInterface borrowDecompiler() {
		DecompilerGate.Permit permit = DecompilerGate.enter();
		try {
			DecompInterface d = null;
			synchronized (decompilers) {
				Pooled p = decompilers.poll();
				if (p != null) {
					d = p.d();
				}
			}
			if (d == null) {
				d = newDecompiler(program, path);
			}
			DecompilerGate.attach(d, permit);
			return d;
		}
		catch (Throwable t) {
			permit.release();
			throw t;
		}
	}

	/**
	 * The hash of the set-up {@link #newDecompiler} gives every decompiler, part of the
	 * {@link DecompileCache} key: change it with the set-up. The program's own decompiler options
	 * ({@code grabFromProgram}) are program state, covered by the modification number.
	 */
	static final boolean DECOMPILER_C_CODE = true;
	/**
	 * Hydra (H5): the pooled decompilers are a text-only profile. Their one consumer, the
	 * {@code decompile} command ({@code QueryCommands.fresh}), answers from
	 * {@code getDecompiledFunction()} (the C text and the signature), which is printed from the C
	 * markup alone. Without the syntax tree the native process does not encode the p-code AST and the
	 * high variables, and Java does not decode them ({@code PcodeSyntaxTree.decode},
	 * {@code decodeHighlist}); the C markup, the local scope and the prototype still come back, so the
	 * text is byte-identical (decomp_identity {@code --tree-b notree}). A request that needs the
	 * {@code HighFunction} (tokens with varnodes and p-code ops, high variables) must not use this
	 * pool: it builds a decompiler with {@code toggleSyntaxTree(true)}.
	 */
	static final boolean DECOMPILER_SYNTAX_TREE = false;
	static final String DECOMPILER_STYLE = "decompile";
	/** The set-up {@link #newDecompiler} applies, made from the very constants it uses. */
	static final String DECOMPILER_SETUP_TEXT = "DecompileOptions.grabFromProgram|toggleCCode=" +
		DECOMPILER_C_CODE + "|toggleSyntaxTree=" + DECOMPILER_SYNTAX_TREE + "|style=" +
		DECOMPILER_STYLE;
	static final int DECOMPILER_SETUP = DECOMPILER_SETUP_TEXT.hashCode();

	/** A decompiler opened on {@code program}, set up the way every session decompile runs. */
	static DecompInterface newDecompiler(Program program, String path) {
		DecompInterface d = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		d.setOptions(options);
		d.toggleCCode(DECOMPILER_C_CODE);
		d.toggleSyntaxTree(DECOMPILER_SYNTAX_TREE);
		d.setSimplificationStyle(DECOMPILER_STYLE);
		if (!d.openProgram(program)) {
			String msg = d.getLastMessage();
			d.dispose();
			throw new SessionException(SessionException.FAILED,
				"the decompiler would not open " + path + ": " + msg);
		}
		DecompilerGate.created();
		return d;
	}

	@Override
	public void returnDecompiler(DecompInterface d, boolean healthy) {
		try {
			if (!healthy || d.getProgram() != program) {
				DecompilerGate.dispose(d);
				return;
			}
			synchronized (decompilers) {
				decompilers.push(new Pooled(d, System.nanoTime()));
			}
		}
		finally {
			DecompilerGate.leave(d);
		}
	}

	@Override
	public int disposeIdle(long cutoffNanos) {
		List<DecompInterface> gone = new ArrayList<>();
		synchronized (decompilers) {
			decompilers.removeIf(p -> {
				if (p.atNanos() - cutoffNanos < 0) {
					gone.add(p.d());
					return true;
				}
				return false;
			});
		}
		gone.forEach(DecompilerGate::dispose);
		return gone.size();
	}

	@Override
	public int idle() {
		synchronized (decompilers) {
			return decompilers.size();
		}
	}

	/** Called with the exclusive lock held, before {@link #program} is released or swapped. */
	void disposeDecompilers() {
		synchronized (decompilers) {
			for (Pooled p : decompilers) {
				DecompilerGate.dispose(p.d());
			}
			decompilers.clear();
		}
	}

	int userCount() {
		synchronized (users) {
			return users.size();
		}
	}

	/**
	 * The state of this program's upgrade cache build: {@code none} (current format, or the
	 * cache is off), {@code building}, {@code ready} or {@code failed}.
	 */
	String cacheBuild(UpgradeCache uc) {
		UpgradeCache.Plan plan = cachePlan;
		if (plan == null) {
			return "none";
		}
		if (cacheView != null) {
			return "ready";
		}
		UpgradeCache.Build b = uc.build(plan);
		if (b != null) {
			return b.state.json();
		}
		return uc.isReady(plan) ? "ready" : "none";
	}

	/** The build's details for {@link #cacheBuild}, or null. */
	JsonObject cacheBuildInfo(UpgradeCache uc) {
		UpgradeCache.Plan plan = cachePlan;
		if (plan == null || cacheView != null) {
			return null;
		}
		UpgradeCache.Build b = uc.build(plan);
		return b == null ? null : b.describe();
	}

	JsonObject describeUse(UpgradeCache uc, boolean v3) {
		JsonObject o = describeUse(uc);
		if (v3) {
			o.add("abandonedRequests", abandonedRequests());
			long since = reopenPendingSince;
			Analysis a = analysis;
			Json.put(o, "reopenPendingMs", since > 0 ? System.currentTimeMillis() - since : null);
			Json.put(o, "analyzing", a != null);
			// the deferred work that waits for this lock (a test and status figure, E3c)
			Json.put(o, "disposePending", disposePending);
			Json.put(o, "pendingLeaves", pendingLeaves.size());
			// the requests counted as waiting for the program lock now, the number the waiter cap
			// (D39) is judged on: a client (or a test) can tell that a wait has queued without a timer.
			// Protocol 3 only: a protocol 2 status keeps the hydra.3 shape (gate 9.8)
			Json.put(o, "lockWaiters", waiters.get());
		}
		return o;
	}

	JsonObject describeUse(UpgradeCache uc) {
		JsonObject o = Json.of("project", project.id, "path", path, "mode",
			mode == null ? null : mode.json(), "owner", owner == null ? null : owner.id,
			"idleMs", System.currentTimeMillis() - lastUsed);
		synchronized (users) {
			List<Integer> ids = new ArrayList<>();
			users.forEach(u -> ids.add(u.id));
			Json.put(o, "users", ids);
		}
		Json.put(o, "ownerLabel", owner == null ? null : ownerLabel);
		Json.put(o, "busy", exclusiveHolder);
		Json.put(o, "writers", writerIds());
		Json.put(o, "journalSeq", journal.seq());
		Json.put(o, "unsavedEdits", Math.max(0, journal.seq() - savedSeq));
		Json.put(o, "orphanedMs",
			orphanedSince > 0 && holdsOrphanedWork() ? System.currentTimeMillis() - orphanedSince
					: null);
		Json.put(o, "revision", revision);
		Json.put(o, "cachedUpgrade", cacheInfo != null);
		Json.put(o, "cacheBuild", cacheBuild(uc));
		return o;
	}
}
