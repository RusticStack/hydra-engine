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

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.JsonObject;

/**
 * The deterministic evidence of "no client blocks another" (PROTOCOL-3.md D49, K13, package E3c).
 * <p>
 * A lock wait is <b>foreign</b> when it had to queue (the lock was not free for it) and, at the
 * moment it started, a request of <i>another</i> client held the lock. {@link #foreignBlocked}
 * counts those waits when they begin, whatever their outcome, so the number does not depend on how
 * long anything took and is the same on a quiet and on a loaded machine. Two kinds of foreign wait
 * are kept apart because they are not a lock another client could have held back:
 * <ul>
 * <li>{@code singleFlightOpen}: the holder is the request that is opening the very program the
 * waiter wants (one open per program; a second client cannot read what is not open yet);</li>
 * <li>{@code engine}: the waiter is the daemon itself (a deferred reopen), not a client.</li>
 * </ul>
 * The count of {@code foreignBlocked} is what K13 requires to be 0 for reads of a sealed generation
 * and for view operations. It is expected to be non-zero on an open (legacy) program with an
 * owner, a shared writer or an analysis (the residual list of 3.9).
 * <p>
 * The durations of the waits that really waited feed {@code lockWaitP99Ms} (report-only, D49).
 */
final class WaitStats {

	private static final int SAMPLES = 1024;
	private static final long MINUTE_MS = 60_000L;

	private static final AtomicLong FOREIGN = new AtomicLong();
	private static final AtomicLong FOREIGN_SHARED = new AtomicLong();
	private static final AtomicLong SINGLE_FLIGHT = new AtomicLong();
	private static final AtomicLong WAITS = new AtomicLong();
	/** Epoch ms of each foreign wait of the last minute (guarded by itself). */
	private static final ArrayDeque<Long> RECENT = new ArrayDeque<>();
	/** Durations in ms of the last {@link #SAMPLES} contended waits (guarded by itself). */
	private static final long[] RING = new long[SAMPLES];
	private static int ringFill;
	private static int ringNext;

	private WaitStats() {
		// static helpers
	}

	/** A wait that starts while another client's request holds the lock. */
	static void foreign(boolean shared) {
		FOREIGN.incrementAndGet();
		if (shared) {
			FOREIGN_SHARED.incrementAndGet();
		}
		long now = System.currentTimeMillis();
		synchronized (RECENT) {
			RECENT.addLast(now);
			trim(now);
		}
	}

	/** A wait for the program that the holder is opening for the first time. */
	static void singleFlightOpen() {
		SINGLE_FLIGHT.incrementAndGet();
	}

	/** The duration of a contended wait that has ended (any outcome). */
	static void waited(long ms) {
		WAITS.incrementAndGet();
		synchronized (RING) {
			RING[ringNext] = ms;
			ringNext = (ringNext + 1) % SAMPLES;
			if (ringFill < SAMPLES) {
				ringFill++;
			}
		}
	}

	private static void trim(long now) {
		while (!RECENT.isEmpty() && now - RECENT.peekFirst() > MINUTE_MS) {
			RECENT.pollFirst();
		}
	}

	/** Test hook: forget everything (the counters are process-wide, one daemon per process). */
	static void reset() {
		FOREIGN.set(0);
		FOREIGN_SHARED.set(0);
		SINGLE_FLIGHT.set(0);
		WAITS.set(0);
		synchronized (RECENT) {
			RECENT.clear();
		}
		synchronized (RING) {
			ringFill = 0;
			ringNext = 0;
		}
	}

	/** The {@code waits} block of {@code status} (protocol 3). */
	static JsonObject describe() {
		long now = System.currentTimeMillis();
		long last;
		synchronized (RECENT) {
			trim(now);
			last = RECENT.size();
		}
		Long p99 = null;
		synchronized (RING) {
			if (ringFill > 0) {
				long[] a = Arrays.copyOf(RING, ringFill);
				Arrays.sort(a);
				p99 = a[Math.min(a.length - 1, (int) Math.ceil(a.length * 0.99) - 1)];
			}
		}
		JsonObject fb = Json.of("total", FOREIGN.get(), "lastMinute", last, "shared",
			FOREIGN_SHARED.get());
		JsonObject o = Json.of("foreignBlocked", fb, "singleFlightOpen", SINGLE_FLIGHT.get(),
			"contended", WAITS.get());
		Json.put(o, "lockWaitP99Ms", p99);
		return o;
	}
}
