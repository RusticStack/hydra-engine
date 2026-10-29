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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonObject;

import ghidra.framework.model.ProjectData;
import ghidra.util.Msg;

/**
 * One project open in the session, shared by every client that joined it. A session holds any
 * number of these at once, each with its own lock and programs, so work in one project never
 * waits on another.
 * <p>
 * <b>Lock and pins (E3c).</b> Every command in the project holds {@link #lock} shared, as a
 * {@link Pin} that also holds a reference on the project view the command started on. The lock is
 * taken exclusively only by closing the project (nobody is joined then) and by the fork of an open
 * writable project. A {@code refresh} or the reopening of a read-only view as writable does <i>not</i>
 * queue for it: it opens the new view, repoints {@link #view} (under {@link #structure}) and retires
 * the old one, which closes when the last command and the last program opened from it let go (BP7).
 * The project's life cycle is the state machine of {@link ProjectRegistry}.
 */
final class ProjectEntry {

	/** Short, stable for the life of this entry: {@code p1}, {@code p2}, ... */
	final String id;
	final ProjectResolver.Resolved resolved;
	/** The canonical path of the {@code .gpr}: two paths to one project are one entry. */
	final String canonical;
	/** The current project view's project; replaced by {@code refresh} (see {@link #repoint}). */
	volatile SessionProject project;
	/** The current view, with the reference count that lets a retired one close when unused. */
	private volatile View view;
	/** Serialises the structure changes (refresh, reopening writable) of this project. */
	final ReentrantLock structure = new ReentrantLock();
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	final long openedAt = System.currentTimeMillis();
	final long openMs;

	/** Programs open in this project, by project path. */
	final Map<String, ProgramEntry> programs = new ConcurrentHashMap<>();
	/** Clients that joined it. Guarded by itself. */
	final Set<Client> users = new LinkedHashSet<>();
	/** When each user joined it (epoch ms), for holder records. */
	final Map<Client, Long> joinedAt = new ConcurrentHashMap<>();
	volatile long lastUsed = System.currentTimeMillis();
	volatile boolean closed;
	/**
	 * Set when the last user left a project that is to close at once (writable, or {@code keepWarm}
	 * 0) and the close could not have it to itself (a request of a client that is gone still ran):
	 * {@link Session#reap} tries the close again without waiting, until it is done or a user joins.
	 */
	volatile boolean closePending;

	/**
	 * The revision ({@link Revision}) of the files this view was opened from: what its answers
	 * reflect. Null when it could not be read.
	 */
	volatile String openRevision;
	/** Bumped by every {@code refresh}; clients are told once when it moved past what they saw. */
	volatile int generation = 1;
	/** The revision before the last refresh, and when that was. */
	volatile String previousRevision;
	volatile long refreshedAt;
	/** {@link #diskRevision} is recomputed at most this often. */
	static final long REVISION_TTL_MS = 1000;
	private volatile String diskRev;
	private volatile long diskAt;

	/** What holds {@link #lock} exclusively now (closing, refreshing), for {@code busy} answers. */
	volatile String exclusiveCmd;
	volatile Client exclusiveClient;
	volatile long exclusiveSince;

	ProjectEntry(String id, ProjectResolver.Resolved resolved, String canonical,
			SessionProject project, long openMs) {
		this.id = id;
		this.resolved = resolved;
		this.canonical = canonical;
		this.project = project;
		this.view = new View(project);
		this.openMs = openMs;
	}

	// ---- views and pins (E3c) -----------------------------------------------------------------

	/**
	 * One open view of the project (a {@link SessionProject}) with a reference count. It starts with
	 * the reference of being the current view; commands ({@link Pin}) and programs opened from it
	 * add theirs. A retired view (a refresh replaced it) closes when the count reaches 0.
	 */
	static final class View {
		final SessionProject project;
		private final AtomicInteger refs = new AtomicInteger(1);
		private volatile boolean closed;

		View(SessionProject project) {
			this.project = project;
		}

		/** Takes a reference; false when the view is already gone (the caller reads the new current one). */
		boolean retain() {
			for (;;) {
				int n = refs.get();
				if (n <= 0) {
					return false;
				}
				if (refs.compareAndSet(n, n + 1)) {
					return true;
				}
			}
		}

		/** Gives a reference back; the last one closes the view. */
		void release() {
			if (refs.decrementAndGet() == 0) {
				close();
			}
		}

		int refs() {
			return refs.get();
		}

		/** Closes the view now, whatever still holds it (the project is closing). */
		void close() {
			if (closed) {
				return;
			}
			closed = true;
			try {
				project.close();
			}
			catch (RuntimeException e) {
				Msg.warn(this, "could not close a project view", e);
			}
		}
	}

	/** A reference on the current view for the caller: retried until one is held. */
	View retainView() {
		for (;;) {
			View v = view;
			if (v.retain()) {
				return v;
			}
		}
	}

	/** The current view's reference count (a test and status figure). */
	int viewRefs() {
		return view.refs();
	}

	/**
	 * Makes {@code nv} the current view and returns the one it replaced, whose current-view reference
	 * the caller releases once the programs have been moved over (it closes when nothing uses it).
	 * Held: {@link #structure}.
	 */
	View repoint(SessionProject nv) {
		View old = view;
		view = new View(nv);
		project = nv;
		return old;
	}

	private static final ThreadLocal<ArrayList<Pin>> PINS = ThreadLocal.withInitial(ArrayList::new);

	/** The view the innermost pin of this thread holds on {@code p}, else its current view (retained). */
	static View pinnedView(ProjectEntry p) {
		ArrayList<Pin> pins = PINS.get();
		for (int i = pins.size() - 1; i >= 0; i--) {
			if (pins.get(i).p == p && !pins.get(i).released) {
				View v = pins.get(i).view;
				if (v.retain()) {
					return v;
				}
			}
		}
		return p.retainView();
	}

	/**
	 * The shared hold of a command on this project: the shared side of {@link #lock} and a reference
	 * on the view the command started on, released together by {@link #unlock}.
	 */
	static final class Pin implements Lock {
		final ProjectEntry p;
		private final Lock shared;
		final View view;
		/** Set when released, so that a pin released on another thread is not found on this one. */
		volatile boolean released;

		Pin(ProjectEntry p, Lock shared) {
			this.p = p;
			this.shared = shared;
			this.view = p.retainView();
			PINS.get().add(this);
		}

		@Override
		public void unlock() {
			released = true;
			ArrayList<Pin> pins = PINS.get();
			int i = pins.lastIndexOf(this);
			if (i >= 0) {
				pins.remove(i);
			}
			try {
				shared.unlock();
			}
			finally {
				view.release();
			}
		}

		@Override
		public void lock() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void lockInterruptibly() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean tryLock() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean tryLock(long time, TimeUnit unit) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Condition newCondition() {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A pin taken without waiting and without queueing (the barging {@code tryLock}), or null when the
	 * project is being closed or forked. For the work the daemon does on its own.
	 */
	Pin tryPin() {
		Lock rl = lock.readLock();
		if (closed || !rl.tryLock()) {
			return null;
		}
		if (closed) {
			rl.unlock();
			return null;
		}
		return new Pin(this, rl);
	}

	/** Set (under {@link #users}) when the project is being closed: nobody may join it any more. */
	volatile boolean closing;

	/** Closes the current view now: the project is closing and nothing uses it. */
	void closeViews() {
		view.close();
	}

	/**
	 * The revision of the project as saved on disk now (recomputed at most every
	 * {@link #REVISION_TTL_MS}), or null when it cannot be read.
	 */
	String diskRevision() {
		long now = System.currentTimeMillis();
		String d = diskRev;
		if (d != null && now - diskAt < REVISION_TTL_MS) {
			return d;
		}
		try {
			d = Revision.of(resolved);
		}
		catch (java.io.IOException | RuntimeException e) {
			d = null;
		}
		diskRev = d;
		diskAt = now;
		return d;
	}

	/** Forgets the cached disk revision (after a save here). */
	void invalidateRevision() {
		diskAt = 0;
	}

	/**
	 * The revision a client's answers come from: for a writable project (no other process can
	 * write it) what is saved now; for a read-only view, what it was opened from.
	 */
	String revision() {
		return writable() ? diskRevision() : openRevision;
	}

	/**
	 * True when a read-only view no longer shows what is saved: another process saved the project
	 * after the view was opened. {@code refresh} reopens it.
	 */
	boolean stale() {
		if (writable() || closed) {
			return false;
		}
		String o = openRevision;
		String d = diskRevision();
		return o != null && d != null && !o.equals(d);
	}

	boolean writable() {
		return project.isWritable();
	}

	ProjectData data() {
		if (closed) {
			throw new SessionException(SessionException.NO_PROJECT, "project " + id + " was closed");
		}
		// a command works on the view it was pinned on, even if a refresh repointed meanwhile (E3c)
		ArrayList<Pin> pins = PINS.get();
		for (int i = pins.size() - 1; i >= 0; i--) {
			if (pins.get(i).p == this && !pins.get(i).released) {
				return pins.get(i).view.project.getProjectData();
			}
		}
		return project.getProjectData();
	}

	/**
	 * This project's identity for error details: {@code project} (its id), {@code name},
	 * {@code gpr} and {@code writable}.
	 */
	JsonObject identity() {
		return Json.of("project", id, "name", resolved.name(), "gpr", resolved.gpr().getPath(),
			"writable", writable(), "revision", revision());
	}

	/** The clients that use it, other than {@code except}, as holder records. */
	com.google.gson.JsonArray holders(Client except) {
		com.google.gson.JsonArray a = new com.google.gson.JsonArray();
		synchronized (users) {
			for (Client u : users) {
				if (u != except) {
					a.add(u.holder(writable() ? "open_project writable" : "open_project read-only",
						joinedAt.getOrDefault(u, 0L)));
				}
			}
		}
		return a;
	}

	int userCount() {
		synchronized (users) {
			return users.size();
		}
	}

	/**
	 * The project as the answers describe it. {@code client} is the one that asked (null for the
	 * start-up event): the seam of reply conditional C6 (the {@code format} block of protocol 3).
	 * Today the value does not depend on it.
	 */
	JsonObject info(Client client) {
		JsonObject o = Json.of("id", id, "name", resolved.name(), "dir", resolved.dir().getPath(),
			"gpr", resolved.gpr().getPath(), "writable", writable(), "openMs", openMs,
			"idleMs", System.currentTimeMillis() - lastUsed);
		try {
			Json.put(o, "files", project.getProjectData().getFileCount());
		}
		catch (RuntimeException e) {
			Json.put(o, "files", null);
		}
		synchronized (users) {
			List<Integer> ids = new ArrayList<>();
			users.forEach(u -> ids.add(u.id));
			Json.put(o, "users", ids);
		}
		Json.put(o, "programs", programs.size());
		Json.put(o, "revision", revision());
		Json.put(o, "diskRevision", diskRevision());
		Json.put(o, "stale", stale());
		Json.put(o, "generation", generation);
		if (refreshedAt > 0) {
			Json.put(o, "refreshedMsAgo", System.currentTimeMillis() - refreshedAt);
		}
		o.add("fork", ProjectFork.summary(ProjectFork.readSidecar(resolved)));
		if (client != null && client.v3()) { // conditional C6: the format block, nothing else
			o.add("format", ProjectFormat.of(this));
		}
		return o;
	}
}
