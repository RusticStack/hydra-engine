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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.*;

/**
 * How many imports run at once, and in what order the others start: a FIFO queue in front of
 * {@code permits} running places ({@code maxImports}), where everyone can see who runs, who waits
 * for whom, and an estimate of how long.
 * <p>
 * Imports in different projects, and of different files into one project, run in parallel: each
 * load is handed its own project, and nothing on the load path reads the process-wide "active
 * project" (see the README, "Parallel imports"). The limit is there for memory and CPU: a load
 * holds its whole program in memory until it is saved. A waiting request can leave the queue
 * (cancel, {@code wait} expiry, disconnect); the durations of finished imports give the estimate.
 * <p>
 * Entries are not reentrant across threads; on the thread of a running entry {@link #enter}
 * returns an inert nested entry.
 */
final class ImportGate {

	/** The daemon's gate; {@link #setPermits} sets its size at start-up. */
	static final ImportGate GLOBAL = new ImportGate(1);

	/** How many finished imports the estimate remembers. */
	private static final int HISTORY = 12;
	private static final long POLL_MS = 100;

	enum Kind {
		/** A real import: long, estimated from the durations of earlier ones. */
		IMPORT
	}

	private final ReentrantLock lock = new ReentrantLock();
	private final Condition changed = lock.newCondition();
	private final LinkedList<Entry> queue = new LinkedList<>();
	/** Running entries, oldest first. */
	private final List<Entry> running = new ArrayList<>();
	private int permits;
	/** Finished imports, newest last: {bytes, ms}. */
	private final ArrayDeque<long[]> history = new ArrayDeque<>();
	private long completed;
	/** The most imports seen running at once. */
	private int peakRunning;

	ImportGate(int permits) {
		this.permits = Math.max(1, permits);
	}

	/** Sets how many imports may run at once (at least 1); queued ones start if places opened. */
	void setPermits(int n) {
		lock.lock();
		try {
			permits = Math.max(1, n);
			changed.signalAll();
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

	/** The heap one running import is given by the default {@code maxImports}. */
	static final long HEAP_PER_IMPORT = 2L << 30;

	/**
	 * The default {@code maxImports}: 4, and one per 2 GB of maximum heap, at least 1. A load holds
	 * its program in memory (about 0.7 GB of heap for a 25 MB PE, measured), so the heap, not the
	 * CPU count, bounds how many run at once (PROTOCOL-3.md 8.18; it was one per four CPUs, which
	 * gave a 4-CPU host one import at a time whatever its heap).
	 */
	static int defaultPermits(long maxHeapBytes) {
		return (int) Math.max(1, Math.min(4, maxHeapBytes / HEAP_PER_IMPORT));
	}

	/** One user of the gate, waiting or running. Closing it leaves the queue or releases it. */
	final class Entry implements AutoCloseable {
		final Kind kind;
		/** Who asked, as {@code busy} answers name them ("client 2 (agent-a, claude-code)"). */
		final String who;
		final int clientId;
		/** True when the client that queued this entry speaks protocol 3 (E3a, C5). */
		final boolean v3;
		final String project;
		/** What is imported (the file), for display. */
		final String what;
		final long bytes;
		final long queuedAt = System.currentTimeMillis();
		volatile long startedAt;
		private final Thread thread = Thread.currentThread();
		private boolean closed;
		private final boolean nested;
		private boolean success;
		/** Place in the queue when it arrived (1: next, or started at once). */
		volatile int positionAtEntry;
		/** Who it waited behind when it arrived (null: it started at once). */
		volatile String behind;
		/** How many imports ran (this one included) when it started. */
		volatile int runningAtStart;

		/** How this entry's wait went, for the import's answer. */
		JsonObject describeWait() {
			return Json.of("waitedMs", waitedMs(), "positionAtEntry", positionAtEntry, "behind",
				behind, "runningAtStart", runningAtStart);
		}

		private Entry(Kind kind, String who, int clientId, boolean v3, String project, String what,
				long bytes, boolean nested) {
			this.kind = kind;
			this.who = who;
			this.clientId = clientId;
			this.v3 = v3;
			this.project = project;
			this.what = what;
			this.bytes = bytes;
			this.nested = nested;
		}

		/** Marks the import as completed normally, so that its duration feeds the estimate. */
		void succeeded() {
			success = true;
		}

		/** Milliseconds this entry waited before it ran. */
		long waitedMs() {
			return startedAt == 0 ? System.currentTimeMillis() - queuedAt : startedAt - queuedAt;
		}

		@Override
		public void close() {
			release(this);
		}
	}

	/**
	 * Waits for a running place in arrival order. While it waits, the request's monitor says so
	 * ("waiting behind ...", with the position and an estimate) and a cancel, the request's own
	 * timeout or {@code waitMs} (negative: no limit) takes it out of the queue.
	 *
	 * @param m the request's monitor, or null for internal uses
	 * @throws SessionException {@code cancelled} on cancel, {@code busy} when {@code waitMs}
	 *             passed
	 */
	Entry enter(Kind kind, String who, Client client, String project, String what, long bytes,
			RequestMonitor m, long waitMs) {
		int clientId = client.id;
		boolean v3 = client.v3();
		lock.lock();
		try {
			for (Entry r : running) {
				if (r.thread == Thread.currentThread() && !r.nested) {
					return new Entry(kind, who, clientId, v3, project, what, bytes, true);
				}
			}
			Entry e = new Entry(kind, who, clientId, v3, project, what, bytes, false);
			queue.add(e);
			boolean free = running.size() < permits && queue.size() == 1;
			e.positionAtEntry = queue.size();
			e.behind = free ? null : holderText();
			long deadline = waitMs < 0 ? Long.MAX_VALUE
					: System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMs);
			try {
				while (!(running.size() < permits && queue.peekFirst() == e)) {
					if (m != null) {
						if (m.isCancelled()) {
							throw new SessionException(SessionException.CANCELLED,
								"cancelled while queued behind " + holderText());
						}
						JsonObject q = queueInfo(e);
						m.queueSeen(q);
						m.waiting("import queue", q);
						m.setMessage("waiting behind " + holderText() + " (position " +
							q.get("position") + " in the import queue" + estimateText(q) + ")");
					}
					if (deadline != Long.MAX_VALUE && System.nanoTime() - deadline >= 0) {
						JsonObject d = queueInfo(e);
						Json.put(d, "waitedMs", waitMs);
						throw new SessionException(SessionException.BUSY,
							"the import queue is busy (" + holderText() + "; position " +
								d.get("position") + "); retry, or pass a longer \"wait\"",
							d);
					}
					try {
						changed.awaitNanos(TimeUnit.MILLISECONDS.toNanos(POLL_MS));
					}
					catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
						throw new SessionException(SessionException.CANCELLED, "interrupted");
					}
				}
			}
			catch (RuntimeException ex) {
				queue.remove(e);
				changed.signalAll();
				if (m != null) {
					m.waiting(null, null);
					m.waited("queue", System.currentTimeMillis() - e.queuedAt);
				}
				throw ex;
			}
			queue.remove(e);
			running.add(e);
			peakRunning = Math.max(peakRunning, running.size());
			e.runningAtStart = running.size();
			e.startedAt = System.currentTimeMillis();
			changed.signalAll(); // the next in line may fit as well
			if (m != null) {
				m.waiting(null, null);
				m.waited("queue", e.startedAt - e.queuedAt);
			}
			return e;
		}
		finally {
			lock.unlock();
		}
	}

	private void release(Entry e) {
		if (e.nested) {
			return;
		}
		lock.lock();
		try {
			if (e.closed) {
				return;
			}
			e.closed = true;
			if (running.remove(e)) {
				if (e.success && e.kind == Kind.IMPORT) {
					history.addLast(new long[] { Math.max(1, e.bytes),
						Math.max(1, System.currentTimeMillis() - e.startedAt) });
					while (history.size() > HISTORY) {
						history.pollFirst();
					}
					completed++;
				}
			}
			else {
				queue.remove(e);
			}
			changed.signalAll();
		}
		finally {
			lock.unlock();
		}
	}

	// ---- estimates -----------------------------------------------------------------------

	/**
	 * Estimated duration of an import of {@code bytes}, or -1 without history: the history's
	 * rate (milliseconds per byte over the remembered imports), never below the shortest import
	 * seen. A guide, not a promise: an import's time depends on the format and on how many
	 * libraries and options the loader runs.
	 */
	private long estimateMs(Entry e) {
		if (history.isEmpty()) {
			return -1;
		}
		long ms = 0;
		long bytes = 0;
		long min = Long.MAX_VALUE;
		for (long[] h : history) {
			bytes += h[0];
			ms += h[1];
			min = Math.min(min, h[1]);
		}
		if (e.bytes <= 1) {
			return ms / history.size();
		}
		return Math.max(min, (long) ((double) ms / bytes * e.bytes));
	}

	/** Called with the lock held: the oldest running import, and how many others run. */
	private String holderText() {
		if (running.isEmpty()) {
			return "an earlier request";
		}
		Entry h = running.get(0);
		String s = h.who + " " + h.kind.name().toLowerCase() +
			(h.what.isEmpty() ? "" : " of " + h.what);
		int others = running.size() - 1;
		return others == 0 ? s : s + " and " + others + " other import" + (others == 1 ? "" : "s");
	}

	private static String estimateText(JsonObject q) {
		return q.has("estimatedWaitMs") && !q.get("estimatedWaitMs").isJsonNull()
				? ", about " + Math.max(1, q.get("estimatedWaitMs").getAsLong() / 1000) + " s"
				: "";
	}

	/** Called with the lock held. */
	private JsonObject queueInfo(Entry e) {
		int pos = queue.indexOf(e) + 1;
		long now = System.currentTimeMillis();
		JsonObject o = Json.of("position", pos, "ahead", pos - 1 + running.size(), "holder",
			running.isEmpty() ? null : describe(running.get(0), now), "running", running.size(),
			"maxImports", permits);
		o.add("estimatedWaitMs", estimateWait(e, pos));
		if (e.v3) {
			// the estimate covers loading the file, not the analysis that may follow (C5)
			o.addProperty("estimateScope", "load");
		}
		return o;
	}

	/**
	 * Called with the lock held; JSON null when there is no history to base it on. Each running
	 * place frees when its import's estimate runs out; each import ahead in the queue takes the
	 * place that frees first; this one starts when a place frees after them.
	 */
	private JsonElement estimateWait(Entry e, int pos) {
		long now = System.currentTimeMillis();
		PriorityQueue<Long> free = new PriorityQueue<>();
		for (Entry r : running) {
			long est = estimateMs(r);
			if (est < 0) {
				return JsonNull.INSTANCE;
			}
			free.add(Math.max(0, est - (now - r.startedAt)));
		}
		while (free.size() < permits) {
			free.add(0L);
		}
		int i = 1;
		for (Entry q : queue) {
			if (i++ >= pos) {
				break;
			}
			long est = estimateMs(q);
			if (est < 0) {
				return JsonNull.INSTANCE;
			}
			free.add(free.poll() + est);
		}
		return new JsonPrimitive(free.peek());
	}

	private JsonObject describe(Entry e, long now) {
		return Json.of("who", e.who, "client", e.clientId, "kind", e.kind.name().toLowerCase(),
			"project", e.project, "file", e.what, "bytes", e.bytes, "queuedMs", now - e.queuedAt,
			"runningMs", e.startedAt == 0 ? null : (Object) (now - e.startedAt));
	}

	/** The gate's state for {@code status}. */
	JsonObject describe() {
		lock.lock();
		try {
			long now = System.currentTimeMillis();
			JsonObject o = new JsonObject();
			Json.put(o, "maxImports", permits);
			o.add("holder", running.isEmpty() ? JsonNull.INSTANCE : describe(running.get(0), now));
			JsonArray run = new JsonArray();
			for (Entry e : running) {
				run.add(describe(e, now));
			}
			o.add("running", run);
			JsonArray q = new JsonArray();
			int pos = 1;
			for (Entry e : queue) {
				JsonObject j = describe(e, now);
				Json.put(j, "position", pos);
				j.add("estimatedWaitMs", estimateWait(e, pos));
				q.add(j);
				pos++;
			}
			o.add("queue", q);
			long ms = 0;
			long bytes = 0;
			for (long[] h : history) {
				ms += h[1];
				bytes += h[0];
			}
			o.add("history", Json.of("count", history.size(), "completed", completed, "meanMs",
				history.isEmpty() ? null : (Object) (ms / history.size()), "msPerMb",
				bytes == 0 ? null : (Object) (long) ((double) ms / bytes * 1_048_576),
				"peakRunning", peakRunning));
			return o;
		}
		finally {
			lock.unlock();
		}
	}
}
