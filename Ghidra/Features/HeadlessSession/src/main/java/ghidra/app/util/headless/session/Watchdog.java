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

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.util.Msg;

/**
 * The watchdog thread of PROTOCOL-3.md 3.4 (package E5): once a second it counts a tick, records
 * how late it woke, tries the scheduler lock for 200 ms, reads the lane figures, looks for
 * deadlocked threads (every fifth tick) and for abandoned holders, and publishes all of it as one
 * {@link Health.Snapshot}. {@code health} reads that snapshot on the reader thread; it never does
 * this work itself, so it cannot block on what the watchdog finds blocked.
 * <p>
 * The thread is supervised (3.11, "daemon threads"): a {@link Throwable} out of the loop is logged
 * and the loop restarts after a growing pause (1 s, doubling to 30 s), and the restarts are counted
 * in {@code health.tick.restarts}. A tick whose step throws loses that step's figures and
 * publishes the rest.
 */
final class Watchdog {

	private static final long PERIOD_MS = 1000;
	private static final long LOCK_WAIT_MS = 200;
	private static final int DEADLOCK_EVERY = 5;
	private static final int STACK_FRAMES = 8;

	private final Session session;
	private final ThreadMXBean threads = ManagementFactory.getThreadMXBean();
	/** {@code System.nanoTime()} until which the loop sleeps instead of ticking (the test hook). */
	private volatile long stallUntilNanos;
	private volatile int restarts;
	private long n;
	private JsonObject lastLanes = new JsonObject();
	private JsonArray lastDeadlocked = new JsonArray();

	Watchdog(Session session) {
		this.session = session;
	}

	/** Publishes the first tick on the calling thread, then starts the thread. */
	void start() {
		tick(0);
		Thread t = new Thread(this::supervise, "session-watchdog");
		t.setDaemon(true);
		t.start();
	}

	/** The test hook behind {@code debug_stall what:"watchdog"}: no tick for the next {@code ms}. */
	void stall(long ms) {
		stallUntilNanos = System.nanoTime() + ms * 1_000_000L;
	}

	// ---- the thread ------------------------------------------------------------------------

	private void supervise() {
		long pauseMs = 1000;
		while (!session.isShuttingDown()) {
			try {
				loop();
				return;
			}
			catch (InterruptedException e) {
				return;
			}
			catch (Throwable t) { // an OutOfMemoryError too: the watchdog must outlive it
				restarts++;
				try {
					Msg.error(this, "watchdog stopped (restart " + restarts + " in " + pauseMs +
						" ms)", t);
					Thread.sleep(pauseMs);
				}
				catch (InterruptedException e) {
					return;
				}
				catch (Throwable ignored) {
					// logging itself failed (out of memory): go on and try again
				}
				pauseMs = Math.min(30_000, pauseMs * 2);
			}
		}
	}

	private void loop() throws InterruptedException {
		long due = System.nanoTime();
		long lateMs = 0;
		while (!session.isShuttingDown()) {
			due += PERIOD_MS * 1_000_000L;
			sleepUntil(due);
			long stall = stallUntilNanos;
			while (stall - System.nanoTime() > 0) { // the test hook: tick nothing meanwhile
				Thread.sleep(Math.min(100, Math.max(1, (stall - System.nanoTime()) / 1_000_000L)));
				stall = stallUntilNanos;
			}
			long now = System.nanoTime();
			lateMs = Math.max(0, (now - due) / 1_000_000L);
			if (lateMs > PERIOD_MS) {
				due = now; // do not run the missed ticks back to back
			}
			tick(lateMs);
		}
	}

	private static void sleepUntil(long deadlineNanos) throws InterruptedException {
		long left;
		while ((left = deadlineNanos - System.nanoTime()) > 0) {
			Thread.sleep(left / 1_000_000L, (int) (left % 1_000_000L));
		}
	}

	// ---- one tick --------------------------------------------------------------------------

	private void tick(long lateMs) {
		n++;
		boolean lockOk = false;
		try {
			JsonObject lanes = session.scheduler.healthLanes(LOCK_WAIT_MS);
			lockOk = lanes != null;
			if (lanes != null) {
				lastLanes = lanes; // when the lock is held, the last figures that could be read
			}
		}
		catch (RuntimeException e) {
			Msg.warn(this, "watchdog: lane figures: " + e);
		}
		if (n % DEADLOCK_EVERY == 1) {
			try {
				lastDeadlocked = deadlocked();
			}
			catch (RuntimeException e) {
				Msg.warn(this, "watchdog: deadlock check: " + e);
			}
		}
		JsonArray abandoned = new JsonArray();
		try {
			abandoned = abandoned();
		}
		catch (RuntimeException e) {
			Msg.warn(this, "watchdog: abandoned holders: " + e);
		}
		Health.publish(new Health.Snapshot(n, System.currentTimeMillis(), lateMs, lockOk,
			lastLanes, lastDeadlocked, abandoned, restarts));
	}

	/** The names of the threads {@code ThreadMXBean.findDeadlockedThreads()} reports. */
	private JsonArray deadlocked() {
		JsonArray a = new JsonArray();
		long[] ids = threads.findDeadlockedThreads();
		if (ids != null) {
			for (ThreadInfo ti : threads.getThreadInfo(ids)) {
				if (ti != null) {
					a.add(ti.getThreadName());
				}
			}
		}
		return a;
	}

	/**
	 * The requests whose client is gone and which still hold a program's lock (E3b's
	 * {@code abandonedRequests}), each with at most eight frames of the thread that runs it. The
	 * entry knows the thread only by name; when several threads have that name (the parallel
	 * workers of one client do) the stack is left out and {@code stackNote} says why.
	 */
	private JsonArray abandoned() {
		JsonArray a = new JsonArray();
		for (ProjectEntry p : session.projectsById.values()) {
			for (ProgramEntry e : p.programs.values()) {
				JsonArray held = e.abandonedRequests();
				for (int i = 0; i < held.size(); i++) {
					JsonObject h = held.get(i).getAsJsonObject();
					JsonObject x = Json.of("program", p.id + ":" + e.path, "cmd",
						h.get("cmd").getAsString(), "runningMs", h.get("runningMs").getAsLong(),
						"client", h.get("label").getAsString() + " (gone)");
					List<StackTraceElement[]> found = stacksOf(h.get("thread").getAsString());
					if (found.size() == 1) {
						JsonArray st = new JsonArray();
						StackTraceElement[] fr = found.get(0);
						for (int k = 0; k < Math.min(STACK_FRAMES, fr.length); k++) {
							st.add(fr[k].toString());
						}
						x.add("stack", st);
					}
					else {
						x.add("stack", new JsonArray());
						x.addProperty("stackNote", found.isEmpty() ? "the thread has ended"
								: found.size() + " threads share the name " +
									h.get("thread").getAsString());
					}
					a.add(x);
				}
			}
		}
		return a;
	}

	private static List<StackTraceElement[]> stacksOf(String threadName) {
		List<StackTraceElement[]> out = new ArrayList<>();
		for (java.util.Map.Entry<Thread, StackTraceElement[]> e : Thread.getAllStackTraces()
				.entrySet()) {
			if (e.getKey().getName().equals(threadName)) {
				out.add(e.getValue());
			}
		}
		return out;
	}
}
