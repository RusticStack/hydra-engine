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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * The one place where the process-wide "active project" may be set: imports (and opening an
 * upgrade cache copy) run one at a time, in arrival order, and everyone can see who waits for
 * whom.
 * <p>
 * Ghidra's loaders find libraries and options through {@code AppInfo.getActiveProject()}, one
 * static field, and through {@code LibrarySearchPathManager}, whose search path set is a static
 * loaded once from whichever project was active then. Two imports into two projects at once would
 * therefore read and write each other's project state (see the README, "Imports are serialized").
 * This class replaces the bare monitor the session used, with the same exclusion and three
 * additions: the wait is a FIFO queue that a waiting request can leave (cancel, {@code wait}
 * expiry, disconnect), every entry knows who it is and what it imports, and the durations of
 * finished imports give an estimate of how long a queued one will wait.
 * <p>
 * Entries are not reentrant across threads; on the holder's own thread {@link #enter} returns an
 * inert nested entry, as the monitor it replaces allowed.
 */
final class ImportGate {

	/** The process-wide gate: the guarded state is process-wide too. */
	static final ImportGate GLOBAL = new ImportGate();

	/** How many finished imports the estimate remembers. */
	private static final int HISTORY = 12;
	private static final long POLL_MS = 100;

	enum Kind {
		/** A real import: long, estimated from the durations of earlier ones. */
		IMPORT,
		/** A short internal use (opening an upgrade cache copy): not estimated. */
		INTERNAL
	}

	private final ReentrantLock lock = new ReentrantLock();
	private final Condition changed = lock.newCondition();
	private final LinkedList<Entry> queue = new LinkedList<>();
	private Entry holder;
	/** Finished imports, newest last: {bytes, ms}. */
	private final ArrayDeque<long[]> history = new ArrayDeque<>();
	private long completed;

	/** One user of the gate, waiting or holding it. Closing it leaves the queue or releases it. */
	final class Entry implements AutoCloseable {
		final Kind kind;
		/** Who asked, as {@code busy} answers name them ("client 2 (agent-a, claude-code)"). */
		final String who;
		final int clientId;
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
		/** Place in the queue when it arrived (1: next), and who held the gate then. */
		volatile int positionAtEntry;
		volatile String behind;

		/** How this entry's wait went, for the import's answer. */
		JsonObject describeWait() {
			return Json.of("waitedMs", waitedMs(), "positionAtEntry", positionAtEntry, "behind",
				behind);
		}

		private Entry(Kind kind, String who, int clientId, String project, String what,
				long bytes, boolean nested) {
			this.kind = kind;
			this.who = who;
			this.clientId = clientId;
			this.project = project;
			this.what = what;
			this.bytes = bytes;
			this.nested = nested;
		}

		/** Marks the import as completed normally, so that its duration feeds the estimate. */
		void succeeded() {
			success = true;
		}

		/** Milliseconds this entry waited before it held the gate. */
		long waitedMs() {
			return startedAt == 0 ? System.currentTimeMillis() - queuedAt : startedAt - queuedAt;
		}

		@Override
		public void close() {
			release(this);
		}
	}

	/**
	 * Waits for the gate in arrival order. While it waits, the request's monitor says so
	 * ("waiting behind ...", with the position and an estimate) and a cancel, the request's own
	 * timeout or {@code waitMs} (negative: no limit) takes it out of the queue.
	 *
	 * @param m the request's monitor, or null for internal uses
	 * @throws SessionException {@code cancelled} on cancel, {@code busy} when {@code waitMs}
	 *             passed
	 */
	Entry enter(Kind kind, String who, int clientId, String project, String what, long bytes,
			RequestMonitor m, long waitMs) {
		lock.lock();
		try {
			if (holder != null && holder.thread == Thread.currentThread() && !holder.nested) {
				return new Entry(kind, who, clientId, project, what, bytes, true);
			}
			Entry e = new Entry(kind, who, clientId, project, what, bytes, false);
			queue.add(e);
			e.positionAtEntry = queue.size();
			e.behind = holder == null ? null : holderText();
			long deadline = waitMs < 0 ? Long.MAX_VALUE
					: System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMs);
			try {
				while (!(holder == null && queue.peekFirst() == e)) {
					if (m != null) {
						if (m.isCancelled()) {
							throw new SessionException(SessionException.CANCELLED,
								"cancelled while queued behind " + holderText());
						}
						JsonObject q = queueInfo(e);
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
				}
				throw ex;
			}
			queue.remove(e);
			holder = e;
			e.startedAt = System.currentTimeMillis();
			if (m != null) {
				m.waiting(null, null);
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
			if (holder == e) {
				holder = null;
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
		if (e.kind != Kind.IMPORT) {
			return 0;
		}
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

	/** Called with the lock held. */
	private String holderText() {
		Entry h = holder;
		return h == null ? "an earlier request" : h.who + " " + h.kind.name().toLowerCase() +
			(h.what.isEmpty() ? "" : " of " + h.what);
	}

	private static String estimateText(JsonObject q) {
		return q.has("estimatedWaitMs") && !q.get("estimatedWaitMs").isJsonNull()
				? ", about " + Math.max(1, q.get("estimatedWaitMs").getAsLong() / 1000) + " s"
				: "";
	}

	/** Called with the lock held. */
	private JsonObject queueInfo(Entry e) {
		int pos = queue.indexOf(e) + 1;
		JsonObject o = Json.of("position", pos, "ahead", pos - 1 + (holder == null ? 0 : 1),
			"holder", holder == null ? null : describe(holder, System.currentTimeMillis()));
		o.add("estimatedWaitMs", estimateWait(e, pos));
		return o;
	}

	/** Called with the lock held; JSON null when there is no history to base it on. */
	private com.google.gson.JsonElement estimateWait(Entry e, int pos) {
		long total = 0;
		long now = System.currentTimeMillis();
		if (holder != null) {
			long est = estimateMs(holder);
			if (est < 0) {
				return com.google.gson.JsonNull.INSTANCE;
			}
			total += Math.max(0, est - (now - holder.startedAt));
		}
		int i = 1;
		for (Entry q : queue) {
			if (i++ >= pos) {
				break;
			}
			long est = estimateMs(q);
			if (est < 0) {
				return com.google.gson.JsonNull.INSTANCE;
			}
			total += est;
		}
		return new com.google.gson.JsonPrimitive(total);
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
			o.add("holder", holder == null ? com.google.gson.JsonNull.INSTANCE
					: describe(holder, now));
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
				bytes == 0 ? null : (Object) (long) ((double) ms / bytes * 1_048_576)));
			return o;
		}
		finally {
			lock.unlock();
		}
	}
}
