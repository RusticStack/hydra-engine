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
import java.util.concurrent.*;
import java.util.function.Consumer;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.util.task.TaskMonitorAdapter;

/**
 * The task monitor of one request: cancellable by {@code cancel}, cancelled by its own
 * {@code timeout}, and reporting progress as throttled {@code progress} events to the caller.
 */
final class RequestMonitor extends TaskMonitorAdapter {

	private static final ScheduledExecutorService TIMER =
		Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "session-timeouts");
			t.setDaemon(true);
			return t;
		});
	private static final long WAITED_MIN_MS = 250;
	private static final long EVENT_INTERVAL_NANOS = 1_000_000_000L;

	private final JsonElement requestId;
	private final Consumer<JsonObject> events;
	private volatile String message = "";
	private volatile long progress;
	private volatile long maximum;
	private volatile boolean timedOut;
	private volatile long lastEvent;
	private ScheduledFuture<?> deadline;
	private final long createdAt = System.currentTimeMillis();
	private volatile String cmd = "";
	private volatile String artifact;

	private volatile Caller.Identity caller;
	/** What the request waits for now (a scheduler slot, the import queue), or null. */
	private volatile String waiting;
	/** Queue details added to this request's progress events while it waits, or null. */
	private volatile JsonObject queue;
	/** Run once when this request is cancelled (by {@code cancel}, its timeout or a dead client). */
	private final List<Runnable> cancelHooks = new ArrayList<>();
	private final Object hookLock = new Object();
	/** Set (under {@code hookLock}) by the one cancel that runs the hooks. */
	private boolean cancelFired;
	/** The lane the scheduler put this request in ({@code quick}, {@code long}, {@code maint}). */
	private volatile String lane;
	/** Why a lane hint was not honoured (E3a's decision, copied into the {@code script} reply). */
	private volatile String laneNote;
	/** How long this request waited for a slot, the import queue and a lock (milliseconds). */
	private volatile long slotWaitedMs;
	private volatile long queueWaitedMs;
	private volatile long lockWaitedMs;
	/** The last queue details a wait of this request saw, or null. */
	private volatile JsonObject lastQueue;

	RequestMonitor(JsonElement requestId, Consumer<JsonObject> events) {
		super(true);
		this.requestId = requestId;
		this.events = events;
	}

	/** Names the command this monitor belongs to (shown in {@code status}). */
	void command(String c) {
		cmd = c == null ? "" : c;
	}

	/** Names the request for label-scoped {@code cancel} and {@code status}. */
	void describeAs(String cmd, Caller.Identity caller) {
		this.cmd = cmd == null ? "" : cmd;
		this.caller = caller;
	}

	Caller.Identity caller() {
		return caller;
	}

	/** The key that scopes cancellation, or null when the request carries no label of its own. */
	String scope() {
		Caller.Identity c = caller;
		return c == null ? null : c.scope();
	}

	/**
	 * The file this request declared it writes outside the project (for example a script's
	 * export); shown in {@code status}. The session never opens or limits it.
	 */
	void artifact(String path) {
		artifact = path;
	}

	void waiting(String what) {
		waiting = what;
	}

	/** Sets (or, with null, clears) what this request waits for and the queue details to report. */
	void waiting(String what, JsonObject queueInfo) {
		waiting = what;
		queue = queueInfo;
	}

	/**
	 * Registers {@code hook} to run when this request is cancelled, whatever cancelled it. It runs
	 * at once, on the calling thread, when the cancel has already started. A hook must be short
	 * and must not throw (an exception is ignored); it runs on the thread that cancels, never
	 * while a scheduler or lock monitor of the hook's owner is required. Each hook runs exactly
	 * once: either in the cancel that takes the hook list, or here, never in both.
	 */
	void addCancelHook(Runnable hook) {
		synchronized (hookLock) {
			if (!cancelFired) {
				cancelHooks.add(hook);
				return;
			}
		}
		runHook(hook);
	}

	void removeCancelHook(Runnable hook) {
		synchronized (hookLock) {
			cancelHooks.remove(hook);
		}
	}

	/**
	 * Cancels this request and runs its cancel hooks once, however many threads cancel at the same
	 * time (the timeout timer, a client's cancel, a dead client): the first one takes the hook list
	 * under {@code hookLock} and runs it outside the lock.
	 */
	@Override
	public void cancel() {
		super.cancel();
		List<Runnable> mine;
		synchronized (hookLock) {
			if (cancelFired) {
				return;
			}
			cancelFired = true;
			mine = new ArrayList<>(cancelHooks);
			cancelHooks.clear();
		}
		for (Runnable h : mine) {
			runHook(h);
		}
	}

	private static void runHook(Runnable h) {
		try {
			h.run();
		}
		catch (RuntimeException ignored) {
			// a hook must not stop the cancel
		}
	}

	/** Records the lane decision of the scheduler: the lane and, if a hint was refused, why. */
	void lane(String lane, String note) {
		this.lane = lane;
		this.laneNote = note;
	}

	/** The lane the scheduler put this request in, or null before it was admitted. */
	String lane() {
		return lane;
	}

	/** Why the {@code lane} hint of this request was not honoured, or null. */
	String laneNote() {
		return laneNote;
	}

	/** Adds time this request spent waiting: {@code kind} is {@code slot}, {@code queue} or {@code lock}. */
	void waited(String kind, long ms) {
		switch (kind) {
			case "slot" -> slotWaitedMs += ms;
			case "queue" -> queueWaitedMs += ms;
			case "lock" -> lockWaitedMs += ms;
			default -> throw new IllegalArgumentException("waited: " + kind);
		}
	}

	/** Remembers the queue details of the latest wait, for the reply's {@code queue} (C9). */
	void queueSeen(JsonObject q) {
		lastQueue = q;
	}

	/**
	 * The {@code waited} object of a protocol 3 reply (D49): present only when this request
	 * waited 250 ms or more for a slot, the import queue or a lock; else null.
	 */
	JsonObject waited() {
		long q = queueWaitedMs;
		long l = lockWaitedMs;
		long s = slotWaitedMs;
		if (Math.max(q, Math.max(l, s)) < WAITED_MIN_MS) {
			return null;
		}
		return Json.of("queueMs", q, "lockMs", l, "slotMs", s);
	}

	/** The queue details of the latest wait when {@link #waited} is present, else null. */
	JsonObject queueSeen() {
		return waited() == null ? null : lastQueue;
	}

	/** Clears the progress message without sending an event. */
	void clearMessage() {
		message = "";
	}

	/** This request as {@code status} shows it. */
	JsonObject describe() {
		Caller.Identity c = caller;
		JsonObject o = Json.of("id", requestId, "cmd", cmd, "artifact", artifact, "ms",
			System.currentTimeMillis() - createdAt, "message", message, "progress", progress,
			"maximum", maximum, "cancelled", isCancelled(), "client", c == null ? null : c.name(),
			"harness", c == null ? null : c.harness(), "labelled", c != null && c.labelled());
		Json.put(o, "waiting", waiting);
		Json.put(o, "queue", queue);
		return o;
	}

	/** Cancels this request after {@code seconds}; 0 means no deadline. */
	void deadline(long seconds) {
		if (seconds > 0) {
			deadline = TIMER.schedule(() -> {
				timedOut = true;
				cancel();
			}, seconds, TimeUnit.SECONDS);
		}
	}

	void done() {
		if (deadline != null) {
			deadline.cancel(false);
		}
	}

	boolean timedOut() {
		return timedOut;
	}

	@Override
	public void setMessage(String m) {
		message = m == null ? "" : m;
		maybeEmit();
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public void initialize(long max) {
		maximum = max;
		progress = 0;
		maybeEmit();
	}

	@Override
	public void setMaximum(long max) {
		maximum = max;
	}

	@Override
	public long getMaximum() {
		return maximum;
	}

	@Override
	public void setProgress(long value) {
		progress = value;
		maybeEmit();
	}

	@Override
	public void incrementProgress(long amount) {
		progress += amount;
		maybeEmit();
	}

	@Override
	public long getProgress() {
		return progress;
	}

	private void maybeEmit() {
		if (events == null || requestId == null) {
			return;
		}
		long now = System.nanoTime();
		if (now - lastEvent < EVENT_INTERVAL_NANOS) {
			return;
		}
		lastEvent = now;
		JsonObject e = Json.of("event", "progress", "id", requestId, "message", message,
			"progress", progress, "maximum", maximum);
		JsonObject q = queue;
		if (q != null) {
			e.add("queue", q);
		}
		try {
			events.accept(e);
		}
		catch (RuntimeException ignored) {
			// the client went away; the request finishes and its cleanup runs
		}
	}
}
