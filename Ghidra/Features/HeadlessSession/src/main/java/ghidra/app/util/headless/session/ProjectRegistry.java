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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import com.google.gson.JsonArray;

/**
 * The life cycle of the session's projects as a per-project state machine (PROTOCOL-3.md D57, 3.10
 * BP8, package E3c). It replaces the one monitor ({@code synchronized (registry)}) that every
 * {@code open_project}, leave and reap took, inside which a writable open once waited 9.4 s for a
 * project lock and made an <i>unrelated</i> project's open wait with it.
 * <p>
 * A {@link Slot} per canonical project path lives in a {@link ConcurrentHashMap}; its
 * {@link State} is {@code OPENING} (the first opener is opening the project, followers wait for it:
 * single flight), {@code OPEN}, or {@code CLOSING}. The life-cycle transitions of one project (open,
 * join, close) happen under that slot's own {@link Slot#transition} lock, so two projects never meet:
 * the lock of one slot is the only thing a request for that project can wait for, and the wait is
 * the cancel-aware, bounded {@link Waits#lock(java.util.concurrent.locks.Lock, long)}. The view
 * changes of an open project (a {@code refresh}, the reopening of a read-only view as writable) are
 * <i>not</i> under the slot's lock: they run under the project's {@link ProjectEntry#structure} lock
 * only, so that readers keep joining while they run (BP7). A close and a view change exclude each
 * other: a close takes the slot's lock and then {@code structure}, both without waiting
 * ({@code tryLock}; a structure change in flight means the project is not idle, and the reap or the
 * next leave tries again), and a view change checks {@link ProjectEntry#closed} under
 * {@code structure}. Lock order: slot {@code transition}, then {@code structure}, then the project
 * lock, then a program lock; nothing that holds {@code structure} takes a slot lock, and the close
 * takes {@code structure} only with {@code tryLock}, so the order cannot deadlock. Nothing in this
 * class waits for a project lock, a program lock or a client while holding a monitor (NB3); the one
 * exclusive project lock of a close is taken by the closer passed in, under those two locks only.
 * <p>
 * The maps {@code Session.projects} and {@code Session.projectsById} stay as the read indexes of
 * the open projects; a slot's owner puts a project into them when it is {@code OPEN} and takes it
 * out when it closes it.
 */
final class ProjectRegistry {

	/** Where a project is in its life. */
	enum State {
		OPENING, OPEN, CLOSING;

		String json() {
			return name().toLowerCase();
		}
	}

	/** One project path's life cycle. */
	static final class Slot {
		final String canonical;
		/** Held for every transition of this project (open, join, close); never for a command. */
		final ReentrantLock transition = new ReentrantLock();
		volatile State state = State.OPENING;
		volatile ProjectEntry entry;

		Slot(String canonical) {
			this.canonical = canonical;
		}
	}

	private final Map<String, Slot> slots = new ConcurrentHashMap<>();

	/** The slot of {@code canonical}, created in state {@code OPENING} when there is none. */
	Slot slot(String canonical) {
		return slots.computeIfAbsent(canonical, Slot::new);
	}

	/** The slot now registered for {@code canonical}, or null. */
	Slot current(String canonical) {
		return slots.get(canonical);
	}

	/** Forgets {@code slot} (a failed open, a closed project); a newer slot of the path stays. */
	void drop(Slot slot) {
		slots.remove(slot.canonical, slot);
	}

	int size() {
		return slots.size();
	}

	/** The states for {@code status}: one entry per slot that is not plainly open. */
	JsonArray describe() {
		JsonArray a = new JsonArray();
		for (Slot s : slots.values()) {
			ProjectEntry p = s.entry;
			// viewRefs: the references on the current view (1 for being current, 1 per program opened
			// from it, 1 per running command pinned on it): a leak shows as a count that never returns
			a.add(Json.of("canonical", s.canonical, "state", s.state.json(), "project",
				p == null ? null : p.id, "viewRefs", p == null || p.closed ? null : p.viewRefs()));
		}
		return a;
	}

	/**
	 * Closes {@code p} when nobody has joined it, without waiting for anything but what {@code closer}
	 * waits for. A join, open or close of the same project in flight (its {@code transition} lock is
	 * taken), or a view change ({@code refresh}, a writable reopen: its {@link ProjectEntry#structure}
	 * lock is taken, also by this very thread) means it is not idle after all: nothing happens and
	 * false is returned (the view change would otherwise install a new view on a closed project, and
	 * nothing would ever close it). If the closer refuses (a request still runs there) the project
	 * stays {@code OPEN}.
	 *
	 * @return true when the project was closed
	 */
	boolean closeIdle(ProjectEntry p, Consumer<ProjectEntry> closer) {
		Slot sl = slots.get(p.canonical);
		if (sl == null || sl.entry != p || !sl.transition.tryLock()) {
			return false;
		}
		try {
			if (p.structure.isHeldByCurrentThread() || !p.structure.tryLock()) {
				return false;
			}
			try {
				return closeLocked(sl, p, closer);
			}
			finally {
				p.structure.unlock();
			}
		}
		finally {
			sl.transition.unlock();
		}
	}

	/** Held: {@code sl.transition} and {@code p.structure}. */
	private boolean closeLocked(Slot sl, ProjectEntry p, Consumer<ProjectEntry> closer) {
		if (slots.get(p.canonical) != sl || p.closed) {
			return false;
		}
		synchronized (p.users) {
			if (!p.users.isEmpty()) {
				return false;
			}
			p.closing = true;
		}
		sl.state = State.CLOSING;
		try {
			closer.accept(p);
		}
		catch (RuntimeException e) {
			synchronized (p.users) {
				p.closing = false;
			}
			sl.state = State.OPEN;
			throw e;
		}
		slots.remove(p.canonical, sl);
		return true;
	}

	/**
	 * Closes every project (the session is shutting down), each under its own slot's lock. A slot
	 * whose lock cannot be had within {@code waitMs} (a join or open stuck in a request) is closed
	 * anyway after that: the daemon is going away.
	 */
	void closeAll(long waitMs, Consumer<ProjectEntry> closer) {
		List<Slot> all = new ArrayList<>(slots.values());
		for (Slot sl : all) {
			boolean locked = false;
			try {
				locked = sl.transition.tryLock(waitMs, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			try {
				ProjectEntry p = sl.entry;
				if (p != null && !p.closed) {
					// a view change in flight is waited for the same way (it checks closed under it)
					boolean structure = Waits.tryLock(p.structure, waitMs);
					try {
						sl.state = State.CLOSING;
						synchronized (p.users) {
							p.closing = true;
						}
						closer.accept(p);
					}
					finally {
						if (structure) {
							p.structure.unlock();
						}
					}
				}
				slots.remove(sl.canonical, sl);
			}
			finally {
				if (locked) {
					sl.transition.unlock();
				}
			}
		}
	}
}
