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
final class ProgramEntry implements Decompilers {

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
	 * When {@link #program} was opened from the upgrade cache: the read-only view of the copy
	 * that holds it (closed with the program), the shared locks that keep the copy in place, and
	 * what the cache did.
	 */
	SessionProject cacheView;
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

	/** Decompilers bound to {@link #program}, reused across requests. Guarded by itself. */
	private final Deque<DecompInterface> decompilers = new ArrayDeque<>();

	ProgramEntry(ProjectEntry project, String path) {
		this.project = project;
		this.path = path;
		this.key = project.id + ":" + path;
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

	/** Lock acquisition, bounded and cancel-aware ({@link Waits}); records the holder. */
	Lock acquire(boolean exclusive, long waitMs, Client c, String cmd) {
		// a dead client's request still holds the lock and ignores cancel: tell at once (3.5)
		// (not for a thread that already holds this program: a re-entrant acquire by the abandoned
		// holder's own script goes through its own hold)
		Hold ab = holds.containsKey(Thread.currentThread()) ? null : firstAbandoned(!exclusive);
		if (ab != null) {
			throw abandonedBusy(ab, exclusive);
		}
		Waits.Outcome got = Waits.lock(lock, exclusive, waitMs, waiters);
		Lock l = exclusive ? lock.writeLock() : lock.readLock();
		if (got != Waits.Outcome.GOT) {
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
		if (!pendingLeaves.isEmpty()) {
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

	@Override
	public DecompInterface borrowDecompiler() {
		synchronized (decompilers) {
			DecompInterface d = decompilers.poll();
			if (d != null) {
				return d;
			}
		}
		return newDecompiler(program, path);
	}

	/** A decompiler opened on {@code program}, set up the way every session decompile runs. */
	static DecompInterface newDecompiler(Program program, String path) {
		DecompInterface d = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		d.setOptions(options);
		d.toggleCCode(true);
		d.toggleSyntaxTree(true);
		d.setSimplificationStyle("decompile");
		if (!d.openProgram(program)) {
			String msg = d.getLastMessage();
			d.dispose();
			throw new SessionException(SessionException.FAILED,
				"the decompiler would not open " + path + ": " + msg);
		}
		return d;
	}

	@Override
	public void returnDecompiler(DecompInterface d, boolean healthy) {
		if (!healthy || d.getProgram() != program) {
			d.dispose();
			return;
		}
		synchronized (decompilers) {
			decompilers.push(d);
		}
	}

	/** Called with the exclusive lock held, before {@link #program} is released or swapped. */
	void disposeDecompilers() {
		synchronized (decompilers) {
			for (DecompInterface d : decompilers) {
				d.dispose();
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
