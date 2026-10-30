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
package generic.concurrent;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.UnaryOperator;

/**
 * NamedDaemonThreadFactory is a thread factory which forms daemon threads
 * with a specified name prefix for the Java concurrent Executors pools.
 *
 */
public class NamedDaemonThreadFactory implements ThreadFactory {

	private final String name;
	private ThreadFactory threadFactory;
	/** Wraps each thread's runnable before the thread is made (identity unless given). */
	private final UnaryOperator<Runnable> wrap;

	public NamedDaemonThreadFactory(String name) {
		this(name, UnaryOperator.identity());
	}

	/**
	 * A factory whose threads run {@code wrap.apply(r)} instead of {@code r} (GThreadPool: the
	 * Hydra CPU placement of background threads).
	 *
	 * @param name the thread name prefix
	 * @param wrap applied to each runnable before its thread is made
	 */
	NamedDaemonThreadFactory(String name, UnaryOperator<Runnable> wrap) {
		this.name = name;
		this.wrap = wrap;
		threadFactory = Executors.defaultThreadFactory();
	}

	@Override
	public Thread newThread(Runnable r) {
		Thread thread = threadFactory.newThread(wrap.apply(r));
		thread.setName(name + "-" + thread.getName());
		thread.setDaemon(true);
		return thread;
	}
}
