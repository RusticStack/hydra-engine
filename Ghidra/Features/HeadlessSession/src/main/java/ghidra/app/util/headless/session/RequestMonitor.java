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
	private static final long EVENT_INTERVAL_NANOS = 1_000_000_000L;

	private final JsonElement requestId;
	private final Consumer<JsonObject> events;
	private volatile String message = "";
	private volatile long progress;
	private volatile long maximum;
	private volatile boolean timedOut;
	private volatile long lastEvent;
	private ScheduledFuture<?> deadline;

	RequestMonitor(JsonElement requestId, Consumer<JsonObject> events) {
		super(true);
		this.requestId = requestId;
		this.events = events;
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
		try {
			events.accept(e);
		}
		catch (RuntimeException ignored) {
			// the client went away; the request finishes and its cleanup runs
		}
	}
}
