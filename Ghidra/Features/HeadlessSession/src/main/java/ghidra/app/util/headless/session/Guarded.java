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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonObject;

import ghidra.util.Msg;

/**
 * Daemon threads that survive a {@link Throwable} (PROTOCOL-3.md 3.11, "Daemon threads", D46).
 * <p>
 * Measurement A: at {@code -Xmx256m} the session-reaper thread died of an
 * {@code OutOfMemoryError} and the daemon went on without it. A thread started with
 * {@link #start} runs its body again after a {@code Throwable} (log it, wait with a backoff of
 * 250 ms doubling to 10 s, count it) until the body returns normally or the thread is
 * interrupted. The count of restarts per thread name is in {@code health.governor.threads}.
 * <p>
 * <b>The emergency reserve.</b> An 8 MB array is held back from the start (only when the heap is
 * at least 512 MB). On an {@code OutOfMemoryError} in a guarded thread it is released, so that the
 * thread can log and run again; the governor re-arms it when the heap is below the soft watermark.
 */
final class Guarded {

	/** The size of the emergency reserve. */
	static final int RESERVE_BYTES = 8 << 20;
	private static final long BACKOFF_MIN_MS = 250;
	private static final long BACKOFF_MAX_MS = 10_000;
	/** A body that ran this long without failing starts the backoff over. */
	private static final long STABLE_MS = 60_000;

	private static final Map<String, AtomicInteger> RESTARTS = new ConcurrentHashMap<>();
	private static volatile byte[] reserve;
	private static final AtomicInteger RESERVE_RELEASED = new AtomicInteger();

	private Guarded() {
		// static
	}

	/** Allocates the reserve if the heap can afford it (called once at start-up). */
	static void armReserve() {
		if (reserve == null && Runtime.getRuntime().maxMemory() >= (512L << 20)) {
			try {
				reserve = new byte[RESERVE_BYTES];
			}
			catch (OutOfMemoryError e) {
				reserve = null;
			}
		}
	}

	/** True when the reserve is held. */
	static boolean reserveArmed() {
		return reserve != null;
	}

	/** How often the reserve was released by an out-of-memory in a guarded thread. */
	static int reserveReleases() {
		return RESERVE_RELEASED.get();
	}

	/** Gives the reserve back to the heap. Returns true when it held it. */
	static boolean releaseReserve() {
		if (reserve != null) {
			reserve = null;
			RESERVE_RELEASED.incrementAndGet();
			return true;
		}
		return false;
	}

	/** Restarts per guarded thread name. */
	static JsonObject restarts() {
		JsonObject o = new JsonObject();
		new java.util.TreeMap<>(RESTARTS).forEach((k, v) -> o.addProperty(k, v.get()));
		return o;
	}

	static int restartsOf(String name) {
		AtomicInteger n = RESTARTS.get(name);
		return n == null ? 0 : n.get();
	}

	/** Forgets the counts (the self-test). */
	static void clear() {
		RESTARTS.clear();
	}

	/**
	 * Starts a daemon thread named {@code name} that runs {@code body} and runs it again after a
	 * {@link Throwable}. {@code body} returns when the thread's work is over (a shutdown): the
	 * thread then ends too. An interrupt ends it as well.
	 */
	static Thread start(String name, Body body) {
		Thread t = new Thread(() -> loop(name, body), name);
		t.setDaemon(true);
		t.start();
		return t;
	}

	/** What a guarded thread runs. */
	@FunctionalInterface
	interface Body {
		void run() throws Exception;
	}

	/** The loop of a guarded thread, also callable from a test (it runs on the calling thread). */
	static void loop(String name, Body body) {
		RESTARTS.computeIfAbsent(name, k -> new AtomicInteger());
		long backoff = BACKOFF_MIN_MS;
		while (!Thread.currentThread().isInterrupted()) {
			long began = System.nanoTime();
			try {
				body.run();
				return;
			}
			catch (InterruptedException e) {
				return;
			}
			catch (Throwable t) {
				boolean oom = t instanceof OutOfMemoryError;
				if (oom) {
					releaseReserve();
				}
				RESTARTS.get(name).incrementAndGet();
				try {
					Msg.error(Guarded.class, "thread " + name + " failed, restarting in " +
						backoff + " ms: " + t, t);
				}
				catch (Throwable ignored) {
					// logging itself can fail when memory is gone; the restart still happens
				}
			}
			if ((System.nanoTime() - began) / 1_000_000L > STABLE_MS) {
				backoff = BACKOFF_MIN_MS;
			}
			try {
				Thread.sleep(backoff);
			}
			catch (InterruptedException e) {
				return;
			}
			backoff = Math.min(BACKOFF_MAX_MS, backoff * 2);
		}
	}
}
