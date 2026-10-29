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

	/** Lets the session say how many slots a lane has (the cap is {@code max(2, slots / 4)}). */
	static void slots(ToIntFunction<String> slotsOfLane) {
		Waits.slotsOfLane = slotsOfLane;
	}

	/** The waiter counter of {@code owner} (a lock holder object), created on first use. */
	static AtomicInteger counter(Object owner) {
		return COUNTERS.computeIfAbsent(owner, k -> new AtomicInteger());
	}

	/** At most this many requests may wait on one lock: {@code max(2, slots / 4)} of the request's lane. */
	static int cap(RequestMonitor m) {
		String lane = m == null ? null : m.lane();
		int slots = slotsOfLane.applyAsInt(lane == null ? "quick" : lane);
		return Math.max(2, slots / 4);
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
		return lock(exclusive ? rw.writeLock() : rw.readLock(), rw, exclusive, waitMs, waiters);
	}

	/**
	 * The same wait on any {@link Lock} that has no read/write pair ({@code rw} null: no cap, a
	 * plain lock is never "contended" for the cap).
	 */
	static Outcome lock(Lock l, long waitMs) {
		return lock(l, null, true, waitMs, null);
	}

	private static Outcome lock(Lock l, ReentrantReadWriteLock rw, boolean exclusive, long waitMs,
			AtomicInteger waiters) {
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
		try {
			if (waiters != null) {
				// reserve first, then judge: requests that arrive together cannot all pass a check
				// made before any of them was counted
				int n = waiters.incrementAndGet();
				counted = true;
				if (rw != null && c != null && c.v3() && n > cap(m) && contended(rw, exclusive)) {
					return Outcome.QUEUE_FULL;
				}
			}
			// 2. wait: one timed tryLock, in the lock's own queue; nothing polls
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

	/** The {@code cancelled} of a request that was cancelled during (or before) a lock wait. */
	static SessionException cancelled(RequestMonitor m) {
		m.cancelPhase("lock_wait");
		return new SessionException(SessionException.CANCELLED,
			m.timedOut() ? "timed out while waiting for a lock"
					: "cancelled while waiting for a lock");
	}
}
