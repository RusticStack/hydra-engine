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
package ghidra.program.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-thread collector of program writes made by an analysis worker.
 * <p>
 * Analyzers that run per-location work on several threads (constant propagation, stack
 * variables) normally write references, data and variables into the program while other
 * workers are still reading it, so each worker's result depends on what the other workers
 * already wrote, which depends on thread timing. When a collector is open on the current
 * thread, {@link #run(Runnable)} records the write instead of performing it. The caller
 * gathers one collector per location and applies them all, in a fixed order, after every
 * worker has finished. Every worker then reads the same program state, so the result does
 * not depend on the thread count or scheduling.
 * <p>
 * With no collector open, {@link #run(Runnable)} performs the write at once, which is the
 * original behaviour.
 */
public final class DeferredProgramWrites {

	private static final ThreadLocal<DeferredProgramWrites> CURRENT = new ThreadLocal<>();

	private final List<Runnable> writes = new ArrayList<>();

	/**
	 * Perform a program write now, or record it if a collector is open on this thread.
	 *
	 * @param write the write
	 */
	public static void run(Runnable write) {
		DeferredProgramWrites current = CURRENT.get();
		if (current == null) {
			write.run();
		}
		else {
			current.writes.add(write);
		}
	}

	/**
	 * @return true if writes on this thread are being collected
	 */
	public static boolean isCollecting() {
		return CURRENT.get() != null;
	}

	/**
	 * Open a new collector on the current thread. Must be paired with {@link #close()}.
	 *
	 * @return the collector
	 * @throws IllegalStateException if a collector is already open on this thread
	 */
	public static DeferredProgramWrites open() {
		if (CURRENT.get() != null) {
			throw new IllegalStateException("deferred program writes already open on this thread");
		}
		DeferredProgramWrites d = new DeferredProgramWrites();
		CURRENT.set(d);
		return d;
	}

	/**
	 * Stop collecting on the current thread. The recorded writes stay in this object.
	 */
	public void close() {
		if (CURRENT.get() == this) {
			CURRENT.remove();
		}
	}

	/**
	 * @return number of recorded writes
	 */
	public int size() {
		return writes.size();
	}

	/**
	 * Perform the recorded writes in the order they were recorded. Must be called with no
	 * collector open on the current thread so that the writes really happen.
	 */
	public void apply() {
		if (CURRENT.get() != null) {
			throw new IllegalStateException("cannot apply while collecting on this thread");
		}
		for (Runnable w : writes) {
			w.run();
		}
		writes.clear();
	}
}
