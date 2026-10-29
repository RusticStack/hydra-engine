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

import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * The decompiler gate (PROTOCOL-3.md 3.11, package E9): a <b>fair counting semaphore</b> of
 * {@code min(CPUs, nativeBudget / 200 MB)} permits, taken where a decompiler is borrowed
 * ({@code ProgramEntry.borrowDecompiler}, {@code Overlay.borrowDecompiler}) and given back where it
 * is returned, so that no more native decompiler processes run at once than the machine can feed.
 * Measurement A: the first throughput limit is the CPU in the native processes, not heap, disk or
 * a Java lock; twelve clients on twenty-four cores run at the plateau, more only queue.
 * <p>
 * <b>Fair per client.</b> Waiters queue per client and a freed permit goes to the next client in
 * round-robin order, so one client with fifty requests does not starve one with a single request.
 * A wait is bounded ({@code decompilerWaitS}) and ends with a structured {@code busy} (reason
 * {@code capacity}, resource {@code native}); a cancel ends it at once.
 * <p>
 * <b>Faults.</b> A native crash, hang or timeout fails that one request (the caller disposes the
 * decompiler and the next borrow makes a fresh one, SP4); {@link Breaker} counts the failures per
 * function: more than {@code decompilerFailLimit} (3) in a minute trip a negative cache of
 * {@code decompilerNegativeS} (600) seconds, so a client cannot drive a crash loop.
 * <p>
 * <b>Idle decompilers</b> in a pool are disposed after {@code decompilerIdleS} (60) seconds.
 */
final class DecompilerGate {

	/** A pool of decompilers (a program's, an overlay's) whose idle members the gate disposes. */
	interface Pool {
		/** Disposes the pooled decompilers idle since before {@code cutoffNanos}; returns how many. */
		int disposeIdle(long cutoffNanos);

		/** The decompilers waiting in the pool. */
		int idle();
	}

	/** A permit; {@link #release} is idempotent. */
	static final class Permit {
		private final DecompilerGate gate;
		private final Object client;
		private boolean released;

		private Permit(DecompilerGate gate, Object client) {
			this.gate = gate;
			this.client = client;
		}

		void release() {
			synchronized (this) {
				if (released) {
					return;
				}
				released = true;
			}
			gate.giveBack();
		}
	}

	private static final class Waiter {
		final Object client;
		final Condition cv;
		boolean granted;

		Waiter(Object client, Condition cv) {
			this.client = client;
			this.cv = cv;
		}
	}

	/** The daemon's gate. */
	static final DecompilerGate GATE = new DecompilerGate(Budgets.gatePermits());

	private static final Object NO_CLIENT = new Object();
	private static final Map<DecompInterface, Permit> HELD =
		Collections.synchronizedMap(new IdentityHashMap<>());
	private static final List<WeakReference<Pool>> POOLS = new ArrayList<>();
	private static final AtomicInteger LIVE = new AtomicInteger();

	private final ReentrantLock lock = new ReentrantLock();
	private int permits;
	private int inUse;
	/** Waiters by client, in arrival order of the client's first waiter. */
	private final LinkedHashMap<Object, ArrayDeque<Waiter>> queues = new LinkedHashMap<>();
	private Object lastServed;
	private int waiting;
	private final AtomicLong granted = new AtomicLong();
	private final AtomicLong refused = new AtomicLong();
	private final AtomicLong waitedNanos = new AtomicLong();
	private final AtomicLong maxWaitNanos = new AtomicLong();
	private volatile int peakInUse;

	DecompilerGate(int permits) {
		this.permits = Math.max(1, permits);
	}

	// ---- the semaphore --------------------------------------------------------------------------

	void setPermits(int n) {
		lock.lock();
		try {
			permits = Math.max(1, n);
			dispatch();
		}
		finally {
			lock.unlock();
		}
	}

	int permits() {
		lock.lock();
		try {
			return permits;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Takes a permit for {@code client} (null: no client), waiting at most {@code maxWaitMs}.
	 *
	 * @param m the request, whose cancel ends the wait (may be null)
	 * @throws SessionException {@code busy} reason {@code capacity} resource {@code native} after the
	 *             wait, or {@code cancelled}
	 */
	Permit acquire(Object client, RequestMonitor m, long maxWaitMs) {
		Object key = client == null ? NO_CLIENT : client;
		long t0 = System.nanoTime();
		lock.lock();
		try {
			if (waiting == 0 && inUse < permits) {
				return grant(key, 0);
			}
			Waiter w = new Waiter(key, lock.newCondition());
			queues.computeIfAbsent(key, k -> new ArrayDeque<>()).addLast(w);
			waiting++;
			long deadline = t0 + TimeUnit.MILLISECONDS.toNanos(maxWaitMs);
			try {
				while (!w.granted) {
					if (m != null && m.isCancelled()) {
						throw Requests.cancelled(m);
					}
					long left = deadline - System.nanoTime();
					if (left <= 0) {
						refused.incrementAndGet();
						throw Governor.capacity("native", inUse, permits,
							"every native decompiler permit (" + permits + ") is in use; " +
								waiting + " request(s) wait. Retry shortly.",
							1000);
					}
					try {
						w.cv.awaitNanos(Math.min(left, TimeUnit.MILLISECONDS.toNanos(100)));
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new SessionException(SessionException.CANCELLED, "interrupted");
					}
				}
				return grantedPermit(w, System.nanoTime() - t0);
			}
			finally {
				if (!w.granted) {
					dequeue(w);
				}
			}
		}
		finally {
			lock.unlock();
		}
	}

	/** Lock held. */
	private Permit grant(Object key, long waited) {
		inUse++;
		peakInUse = Math.max(peakInUse, inUse);
		granted.incrementAndGet();
		lastServed = key;
		return new Permit(this, key);
	}

	private Permit grantedPermit(Waiter w, long waited) {
		waitedNanos.addAndGet(waited);
		maxWaitNanos.accumulateAndGet(waited, Math::max);
		return new Permit(this, w.client); // inUse was counted when the permit was handed over
	}

	/** Lock held. */
	private void dequeue(Waiter w) {
		ArrayDeque<Waiter> q = queues.get(w.client);
		if (q != null && q.remove(w)) {
			waiting--;
			if (q.isEmpty()) {
				queues.remove(w.client);
			}
		}
	}

	private void giveBack() {
		lock.lock();
		try {
			inUse--;
			dispatch();
		}
		finally {
			lock.unlock();
		}
	}

	/** Lock held: hands free permits to the waiting clients in round-robin order. */
	private void dispatch() {
		while (inUse < permits && waiting > 0) {
			Object next = nextClient();
			ArrayDeque<Waiter> q = queues.get(next);
			Waiter w = q.pollFirst();
			waiting--;
			if (q.isEmpty()) {
				queues.remove(next);
			}
			w.granted = true;
			inUse++;
			peakInUse = Math.max(peakInUse, inUse);
			granted.incrementAndGet();
			lastServed = next;
			w.cv.signal();
		}
	}

	/** The client after the one served last that has a waiter (wraps around). */
	private Object nextClient() {
		boolean passed = lastServed == null || !queues.containsKey(lastServed);
		Object first = null;
		for (Object k : queues.keySet()) {
			if (first == null) {
				first = k;
			}
			if (passed) {
				return k;
			}
			if (k == lastServed) {
				passed = true;
			}
		}
		return first;
	}

	/** In order of service: the clients of the waiters (the fairness test reads this). */
	List<Object> waitingClients() {
		lock.lock();
		try {
			return new ArrayList<>(queues.keySet());
		}
		finally {
			lock.unlock();
		}
	}

	JsonObject describe() {
		lock.lock();
		try {
			long g = granted.get();
			return Json.of("permits", permits, "inUse", inUse, "peakInUse", peakInUse, "waiting",
				waiting, "granted", g, "refused", refused.get(), "avgWaitMs",
				g == 0 ? 0 : waitedNanos.get() / 1_000_000L / g, "maxWaitMs",
				maxWaitNanos.get() / 1_000_000L);
		}
		finally {
			lock.unlock();
		}
	}

	// ---- borrow and return ----------------------------------------------------------------------

	/**
	 * Takes a permit for the current request's client and remembers it for {@code d} once the
	 * caller has the decompiler. Call {@link #attach} with the result, or {@link Permit#release} when
	 * the borrow fails.
	 */
	static Permit enter() {
		Client c = Caller.client();
		return GATE.acquire(c, Caller.monitor(), Budgets.decompilerWaitS() * 1000L);
	}

	static void attach(DecompInterface d, Permit p) {
		HELD.put(d, p);
	}

	/** Gives back the permit held for {@code d}, if any (the decompiler is not touched). */
	static void leave(DecompInterface d) {
		Permit p = HELD.remove(d);
		if (p != null) {
			p.release();
		}
	}

	/** Disposes a decompiler and counts it. Use instead of {@code d.dispose()}. */
	static void dispose(DecompInterface d) {
		try {
			d.dispose();
		}
		finally {
			LIVE.decrementAndGet();
		}
	}

	static void created() {
		LIVE.incrementAndGet();
	}

	/** Native decompilers alive (in use or pooled). */
	static int live() {
		return Math.max(0, LIVE.get());
	}

	// ---- idle pools -----------------------------------------------------------------------------

	static void track(Pool pool) {
		synchronized (POOLS) {
			POOLS.add(new WeakReference<>(pool));
		}
	}

	/** Disposes every decompiler idle for {@code idleMs}; returns the number. */
	static int sweepIdle(long idleMs) {
		long cutoff = System.nanoTime() - TimeUnit.MILLISECONDS.toNanos(idleMs);
		List<Pool> pools = new ArrayList<>();
		synchronized (POOLS) {
			POOLS.removeIf(r -> r.get() == null);
			POOLS.forEach(r -> {
				Pool p = r.get();
				if (p != null) {
					pools.add(p);
				}
			});
		}
		int n = 0;
		for (Pool p : pools) {
			try {
				n += p.disposeIdle(cutoff);
			}
			catch (RuntimeException e) {
				Msg.warn(DecompilerGate.class, "idle decompiler sweep: " + e);
			}
		}
		return n;
	}

	/** The decompilers waiting in all pools. */
	static int idleTotal() {
		int n = 0;
		synchronized (POOLS) {
			for (WeakReference<Pool> r : POOLS) {
				Pool p = r.get();
				if (p != null) {
					n += p.idle();
				}
			}
		}
		return n;
	}

	// ---- the circuit breaker and the negative cache ----------------------------------------------

	/**
	 * Failures per function (D46): a native crash, hang or timeout counts; the 4th within a minute
	 * trips a negative cache for ten minutes. Keyed by program object, so a reopened program starts
	 * clean, and by the function's entry point.
	 */
	static final class Breaker {

		private static final long WINDOW_MS = 60_000;

		private static final class Hist {
			final ArrayDeque<Long> times = new ArrayDeque<>();
			long negativeUntil;
		}

		private static final Map<Program, Map<String, Hist>> BY_PROGRAM =
			Collections.synchronizedMap(new WeakHashMap<>());
		private static final AtomicLong FAILURES = new AtomicLong();
		private static final AtomicLong TRIPS = new AtomicLong();
		private static final AtomicLong NEGATIVE_HITS = new AtomicLong();

		private Breaker() {
		}

		static int failLimit() {
			return Settings.integer("decompilerFailLimit", 3);
		}

		static long negativeMs() {
			return Settings.integer("decompilerNegativeS", 600) * 1000L;
		}

		private static Hist hist(Program p, Function f, boolean create) {
			Map<String, Hist> m;
			synchronized (BY_PROGRAM) {
				m = BY_PROGRAM.get(p);
				if (m == null) {
					if (!create) {
						return null;
					}
					m = new java.util.HashMap<>();
					BY_PROGRAM.put(p, m);
				}
			}
			String k = f.getEntryPoint().toString();
			synchronized (m) {
				Hist h = m.get(k);
				if (h == null && create) {
					h = new Hist();
					m.put(k, h);
				}
				return h;
			}
		}

		/** Milliseconds the function stays in the negative cache, or 0. */
		static long negativeLeftMs(Program p, Function f) {
			Hist h = hist(p, f, false);
			if (h == null) {
				return 0;
			}
			synchronized (h) {
				long left = h.negativeUntil - System.currentTimeMillis();
				if (left > 0) {
					NEGATIVE_HITS.incrementAndGet();
					return left;
				}
				return 0;
			}
		}

		/** Records one failure; returns true when this one tripped the negative cache. */
		static boolean failed(Program p, Function f) {
			FAILURES.incrementAndGet();
			Hist h = hist(p, f, true);
			long now = System.currentTimeMillis();
			synchronized (h) {
				h.times.addLast(now);
				while (!h.times.isEmpty() && now - h.times.peekFirst() > WINDOW_MS) {
					h.times.pollFirst();
				}
				if (h.times.size() > failLimit() && h.negativeUntil <= now) {
					h.negativeUntil = now + negativeMs();
					h.times.clear();
					TRIPS.incrementAndGet();
					Msg.warn(DecompilerGate.class, "decompiler failed more than " + failLimit() +
						" times in a minute on " + f.getName(true) + " (" + f.getEntryPoint() +
						"): refused for " + negativeMs() / 1000 + " s");
					return true;
				}
			}
			return false;
		}

		/** A decompile of the function completed: its history is forgotten. */
		static void succeeded(Program p, Function f) {
			Hist h = hist(p, f, false);
			if (h != null) {
				synchronized (h) {
					h.times.clear();
				}
			}
		}

		static JsonObject describe() {
			int cached = 0;
			long now = System.currentTimeMillis();
			synchronized (BY_PROGRAM) {
				for (Map<String, Hist> m : BY_PROGRAM.values()) {
					synchronized (m) {
						for (Hist h : m.values()) {
							if (h.negativeUntil > now) {
								cached++;
							}
						}
					}
				}
			}
			return Json.of("failures", FAILURES.get(), "trips", TRIPS.get(), "negativeHits",
				NEGATIVE_HITS.get(), "negativeFunctions", cached);
		}

		/** Forgets everything (the self-test). */
		static void clear() {
			BY_PROGRAM.clear();
			FAILURES.set(0);
			TRIPS.set(0);
			NEGATIVE_HITS.set(0);
		}
	}
}
