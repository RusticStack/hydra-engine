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

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.ToIntFunction;

/**
 * The one request-bound lock wait of the session (PROTOCOL-3.md 3.5, package E3b): a single timed
 * {@code tryLock} on the request's own thread, so that the thread keeps its place in the fair lock's
 * queue for the whole wait, plus the registration state machine of the request's
 * {@link RequestMonitor} that lets {@code cancel}, a {@code timeout}, a dead client or a
 * stalled socket end the wait from outside.
 * <p>
 * Nothing polls: a polling wait in slices would join the queue's tail every slice and starve an
 * exclusive locker behind steady readers, and an untimed {@code tryLock()} barges past the queue.
 * The outcome of {@link #lock}:
 * <ul>
 * <li>{@link Outcome#GOT}: the lock is held, the request was not cancelled while it waited;</li>
 * <li>{@link Outcome#TIMED_OUT}: today's {@code busy};</li>
 * <li>{@link Outcome#QUEUE_FULL}: protocol 3 only, more than {@link #cap} requests already wait for
 * this lock ({@code busy} with {@code reason:"lock_queue_full"}, answered at once);</li>
 * <li>a {@code cancelled} {@link SessionException}, thrown (a lock that was taken while a cancel
 * raced is released first, so no lock is ever held across the error).</li>
 * </ul>
 * A caller without a request (the cleanup waits of a dead client) gets the plain timed
 * {@code tryLock}.
 */
final class Waits {

	/** The result of {@link #lock} when the request was not cancelled. */
	enum Outcome {
		GOT, TIMED_OUT, QUEUE_FULL
	}

	private static volatile ToIntFunction<String> slotsOfLane = lane -> 8;

	/** The waiter counters of the locks that have no field of their own (project, overlay). */
	private static final Map<Object, AtomicInteger> COUNTERS =
		Collections.synchronizedMap(new WeakHashMap<>());

	private Waits() {
		// static helpers
	}

	/**
	 * The default least waiter cap (setting {@code lockWaitersMin}, PROTOCOL-3.md 8.18; it was 2). A
	 * fixed number, not a share of the CPUs, so that a small host queues as many waiters on one lock
	 * as a big one, bounded by half the lane while a waiter keeps its slot (see {@link #cap(int)}).
	 */
	static final int DEFAULT_LOCK_WAITERS_MIN = 4;

	/** Lets the session say how many slots a lane has (for {@link #cap(int)}). */
	static void slots(ToIntFunction<String> slotsOfLane) {
		Waits.slotsOfLane = slotsOfLane;
	}

	/** The waiter counter of {@code owner} (a lock holder object), created on first use. */
	static AtomicInteger counter(Object owner) {
		return COUNTERS.computeIfAbsent(owner, k -> new AtomicInteger());
	}

	/**
	 * At most this many requests may wait on one lock: {@link #cap(int)} of the request's lane.
	 */
	static int cap(RequestMonitor m) {
		String lane = m == null ? null : m.lane();
		int slots = slotsOfLane.applyAsInt(lane == null ? "quick" : lane);
		return cap(slots);
	}

	/**
	 * The waiter cap of a lane with {@code slots} slots: {@code max(lockWaitersMin, slots / 4)}, and,
	 * while a waiter keeps its lane slot (setting {@code yieldSlots} off), at most half the lane
	 * (at least 2), so that one lock's queue can never take the lane (D39). The bound by the lane
	 * is what the cap was for; the least value no longer shrinks with the CPUs of the host.
	 */
	static int cap(int slots) {
		int least = Math.max(1, Settings.integer("lockWaitersMin", DEFAULT_LOCK_WAITERS_MIN));
		int cap = Math.max(least, slots / 4);
		if (!Settings.bool("yieldSlots", false)) {
			cap = Math.min(cap, Math.max(2, slots / 2));
		}
		return cap;
	}

	/** True when the request this thread executes speaks protocol 3 (the gate of the v3-only keys). */
	static boolean v3() {
		Client c = Caller.client();
		return c != null && c.v3();
	}

	/** The plain timed wait for a caller that has no request (never throws {@code cancelled}). */
	static boolean tryLock(Lock l, long waitMs) {
		try {
			return l.tryLock(waitMs, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	/**
	 * Takes {@code rw}'s shared or exclusive lock within {@code waitMs}, cancel-aware.
	 *
	 * @param waiters the requests waiting on this lock now, for the cap of protocol 3; null: no cap
	 * @throws SessionException {@code cancelled} when the request is (or gets) cancelled, or its
	 *             client is gone
	 */
	static Outcome lock(ReentrantReadWriteLock rw, boolean exclusive, long waitMs,
			AtomicInteger waiters) {
		return lock(exclusive ? rw.writeLock() : rw.readLock(), rw, null, exclusive, waitMs,
			waiters, null);
	}

	/** What {@link WaitStats} is told about a wait: nobody else holds the lock. */
	static final int HELD_BY_NONE = 0;
	/** The lock is held by a request of another client (a foreign wait, D49). */
	static final int HELD_BY_OTHER = 1;
	/** The holder is the request opening the very program the waiter wants (single flight). */
	static final int HELD_BY_OPENER = 2;

	/**
	 * Like {@link #lock(ReentrantReadWriteLock, boolean, long, AtomicInteger)}, and attributes the
	 * wait: {@code holder} says, for a wait that has to queue, whose request holds the lock (the
	 * asking client is passed in), so that {@link WaitStats#foreignBlocked} counts it (E3c, D49).
	 */
	static Outcome lock(ReentrantReadWriteLock rw, boolean exclusive, long waitMs,
			AtomicInteger waiters, ToIntFunction<Client> holder) {
		return lock(exclusive ? rw.writeLock() : rw.readLock(), rw, null, exclusive, waitMs, waiters,
			holder);
	}

	/**
	 * The same wait on any {@link Lock} that has no read/write pair ({@code rw} null: no cap, a
	 * plain lock is never "contended" for the cap).
	 */
	static Outcome lock(Lock l, long waitMs) {
		return lock(l, null, null, true, waitMs, null, null);
	}

	/**
	 * The same wait on a plain {@link ReentrantLock} with the waiter cap of protocol 3 (D39): the
	 * project's slot transition and structure locks. At most {@link #cap} requests of a v3 client
	 * queue for the lock; the next one is answered {@link Outcome#QUEUE_FULL} at once instead of
	 * holding a lane slot until {@code waitMs} runs out.
	 *
	 * @param waiters the requests waiting on this lock now; null: no cap
	 */
	static Outcome lock(ReentrantLock l, long waitMs, AtomicInteger waiters) {
		return lock(l, null, l, true, waitMs, waiters, null);
	}

	private static Outcome lock(Lock l, ReentrantReadWriteLock rw, ReentrantLock plain,
			boolean exclusive, long waitMs, AtomicInteger waiters,
			ToIntFunction<Client> holder) {
		RequestMonitor m = Caller.monitor();
		Client c = Caller.client();
		if (m == null) {
			return tryLock(l, waitMs) ? Outcome.GOT : Outcome.TIMED_OUT;
		}
		// 1. enter: refuse at once when the request is already cancelled
		if (c != null && c.leaving || !m.enterWait()) {
			throw cancelled(m);
		}
		boolean counted = false;
		boolean got = false;
		boolean interrupted = false;
		boolean mine;
		// attribution first: whose request holds the lock the moment this one has to queue
		boolean queued = holder != null && rw != null && contended(rw, exclusive);
		long t0 = System.nanoTime();
		Scheduler.Ticket ticket = queued && Settings.bool("yieldSlots", false) ? Scheduler.bound() : null;
		if (queued) {
			int who = holder.applyAsInt(c);
			if (who == HELD_BY_OTHER) {
				WaitStats.foreign(!exclusive);
			}
			else if (who == HELD_BY_OPENER) {
				WaitStats.singleFlightOpen();
			}
		}
		try {
			if (waiters != null) {
				// reserve first, then judge: requests that arrive together cannot all pass a check
				// made before any of them was counted
				int n = waiters.incrementAndGet();
				counted = true;
				if ((rw != null || plain != null) && c != null && c.v3() && n > cap(m) &&
					(rw != null ? contended(rw, exclusive) : contended(plain))) {
					return Outcome.QUEUE_FULL;
				}
			}
			// 2. wait: one timed tryLock, in the lock's own queue; nothing polls. With the setting
			// yieldSlots (default off, D39; SP9 must show no deadlock before it is switched on) the lane
			// slot is given back for the wait, so that a lock queue cannot hold the lane.
			if (ticket != null) {
				ticket.yieldSlot();
			}
			try {
				got = l.tryLock(waitMs, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				interrupted = true;
			}
		}
		finally {
			if (counted) {
				waiters.decrementAndGet();
			}
			// 4. leave: back to IDLE, our own interrupt cleared before anything else runs
			mine = m.leaveWait();
		}
		if (interrupted && !mine) {
			Thread.currentThread().interrupt(); // not ours (shutdownNow): as before
		}
		if (queued) {
			WaitStats.waited((System.nanoTime() - t0) / 1_000_000L); // feeds lockWaitP99Ms (D49)
		}
		if (ticket != null) {
			// a slot again before anything else runs; the wait is over, so it is not a registered wait
			try {
				ticket.reacquire(m, Math.max(1000, waitMs));
			}
			catch (RuntimeException ex) {
				if (got) {
					l.unlock(); // no slot to go on with: the lock is given back, the request ends with that error
				}
				throw ex;
			}
		}
		// 5. outcome
		if (mine || m.isCancelled() || (c != null && c.leaving)) {
			if (got) {
				l.unlock();
			}
			throw cancelled(m);
		}
		return got ? Outcome.GOT : Outcome.TIMED_OUT;
	}

	/** True when this lock would make the caller queue (a free lock is never "full"). */
	private static boolean contended(ReentrantReadWriteLock rw, boolean exclusive) {
		if (rw.isWriteLockedByCurrentThread() || rw.getReadHoldCount() > 0) {
			return false; // re-entrant: no wait
		}
		return rw.isWriteLocked() || rw.hasQueuedThreads() ||
			(exclusive && rw.getReadLockCount() > 0);
	}

	/** True when this plain lock would make the caller queue. */
	private static boolean contended(ReentrantLock l) {
		return !l.isHeldByCurrentThread() && (l.isLocked() || l.hasQueuedThreads());
	}

	/** The {@code cancelled} of a request that was cancelled during (or before) a lock wait. */
	static SessionException cancelled(RequestMonitor m) {
		m.cancelPhase("lock_wait");
		return new SessionException(SessionException.CANCELLED,
			m.timedOut() ? "timed out while waiting for a lock"
					: "cancelled while waiting for a lock");
	}
}
