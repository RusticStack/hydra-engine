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

import ghidra.util.Msg;

/**
 * Start-up work that no query needs, run on one background thread once the session is ready:
 * the default TLS context (see {@link SessionApplicationConfiguration}) and the OSGi framework
 * that compiles scripts. Commands that may need it (scripts, imports, analysis) call
 * {@link #await} first, which waits for whatever has not finished yet.
 */
final class DeferredInit {

	private static final List<Runnable> TASKS = new ArrayList<>();
	private static Thread thread;
	private static volatile long doneMs = -1;

	private DeferredInit() {
	}

	/** Adds a task; before {@link #start}, else it runs at once. */
	static synchronized void add(String name, Runnable task) {
		Runnable named = () -> {
			try {
				task.run();
			}
			catch (Throwable t) {
				Msg.error(DeferredInit.class, "deferred start-up task failed: " + name, t);
			}
		};
		if (thread != null) {
			named.run();
			return;
		}
		TASKS.add(named);
	}

	/** Runs the tasks on a background thread. */
	static synchronized void start() {
		if (thread != null) {
			return;
		}
		List<Runnable> tasks = new ArrayList<>(TASKS);
		TASKS.clear();
		thread = new Thread(() -> {
			long t0 = System.nanoTime();
			tasks.forEach(Runnable::run);
			doneMs = (System.nanoTime() - t0) / 1_000_000;
		}, "session-deferred-init");
		thread.setDaemon(true);
		thread.start();
	}

	/** Waits until every deferred task has run; starts them first if nobody did. */
	static void await() {
		Thread t;
		synchronized (DeferredInit.class) {
			if (thread == null) {
				start();
			}
			t = thread;
		}
		try {
			t.join();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	/** How long the tasks took, or -1 while they run. */
	static long doneMs() {
		return doneMs;
	}
}
