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
package ghidra.app.services;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import generic.concurrent.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DeferredProgramWrites;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractAnalyzer implements Analyzer {
	private final String name;
	private final AnalyzerType type;
	private final String description;
	private boolean defaultEnablement = false;
	private boolean supportsOneTimeAnalysis;
	private boolean isPrototype = false;
	private AnalysisPriority priority = AnalysisPriority.LOW_PRIORITY;
	
	protected static final AddressSetView EMPTY_ADDRESS_SET = new AddressSetViewAdapter();

	protected AbstractAnalyzer(String name, String description, AnalyzerType type) {
		this.name = name;
		this.type = type;
		this.description = description;
	}

	protected void setPriority(AnalysisPriority priority) {
		this.priority = priority;
	}

	protected void setDefaultEnablement(boolean b) {
		this.defaultEnablement = b;
	}

	protected void setSupportsOneTimeAnalysis() {
		supportsOneTimeAnalysis = true;
	}

	protected void setSupportsOneTimeAnalysis(boolean supportsOneTimeAnalysis) {
		this.supportsOneTimeAnalysis = supportsOneTimeAnalysis;
	}

	protected void setPrototype() {
		isPrototype = true;
	}

	@Override
	public final String getName() {
		return name;
	}

	@Override
	public final AnalyzerType getAnalysisType() {
		return type;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return defaultEnablement;
	}

	@Override
	public final boolean supportsOneTimeAnalysis() {
		return supportsOneTimeAnalysis;
	}

	@Override
	public final String getDescription() {
		return description == null ? "No Description" : description;
	}

	@Override
	public final AnalysisPriority getPriority() {
		return priority;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// do nothing
	}

	@Override
	public void analysisEnded(Program program) {
		// do nothing
	}

	@Override
	public final boolean isPrototype() {
		return isPrototype;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// do nothing
	}
	
	/**
	 * Analyze a single location
	 * 
	 * @param program - program to analyze
	 * @param start - location to start flowing constants
	 * @param set - restriction set of addresses to analyze
	 * @param monitor - monitor to check canceled
	 * 
	 * @return - set of addresses actually flowed to
	 * @throws CancelledException
	 */
	public AddressSetView analyzeLocation(final Program program, Address start, AddressSetView set,
			final TaskMonitor monitor) throws CancelledException {
		return EMPTY_ADDRESS_SET;
	}

	/**
	 * Run constant an analysis at each location in parallel
	 * 
	 * @param program program
	 * @param locations points to analyze
	 * @param restrictedSet set to restrict analysis to, null if none
	 * @param maxThreads maximum number of threads to use
	 * @param monitor to cancel
	 * @return set of addresses covered during analysis
	 * 
	 * @throws CancelledException if cancelled
	 * @throws InterruptedException if interrupted
	 * @throws Exception any exception
	 */
	protected AddressSetView runParallelAddressAnalysis(final Program program, final Set<Address> locations, final AddressSetView restrictedSet, int maxThreads,
			final TaskMonitor monitor) throws CancelledException, InterruptedException, Exception {
			
				monitor.checkCancelled();
			
				final AddressSet analyzedSet = new AddressSet();
				if (locations.isEmpty()) {
					return analyzedSet;
				}
			
				GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
				monitor.setMaximum(locations.size());
			
				QCallback<Address, AddressSetView> callback = new QCallback<Address, AddressSetView>() {
					@Override
					public AddressSetView process(Address loc, TaskMonitor taskMonitor) {
						synchronized (analyzedSet) {
							if (analyzedSet.contains(loc)) {
								taskMonitor.incrementProgress(1);
								return EMPTY_ADDRESS_SET;
							}
						}
			
						try {
							AddressSetView result = analyzeLocation(program, loc, restrictedSet, taskMonitor);
							synchronized (analyzedSet) {
								analyzedSet.add(result);
							}
			
							taskMonitor.incrementProgress(1);
							return result;
						}
						catch (CancelledException e) {
							return null; // monitor was cancelled
						}
					}
				};
				
				// @formatter:off
				ConcurrentQ<Address, AddressSetView> queue = new ConcurrentQBuilder<Address, AddressSetView>()
					.setThreadPool(pool)
					.setMaxInProgress(clampThreadCount(maxThreads, pool.getMaxThreadCount()))
					.setMonitor(monitor)
					.build(callback);
				// @formatter:on
			
				queue.add(locations);

				queue.waitUntilDone();

				return analyzedSet;
			}

	/**
	 * Bounds a requested analysis thread count to what a pool can run: a request above the
	 * pool's size runs with the whole pool, a request below one runs with one thread.
	 * 
	 * @param requested the requested number of threads (an analyzer's Max Threads option)
	 * @param poolMaxThreads the maximum thread count of the pool the work runs on
	 * @return the number of threads to use, between 1 and {@code poolMaxThreads}
	 */
	public static int clampThreadCount(int requested, int poolMaxThreads) {
		return Math.max(1, Math.min(requested, Math.max(1, poolMaxThreads)));
	}

	/**
	 * Name of the analyzer option that turns on {@link #runDeferredParallelAddressAnalysis}.
	 */
	public static final String DEFERRED_WRITES_OPTION_NAME = "Deferred Ordered Writes";
	public static final String DEFERRED_WRITES_OPTION_DESCRIPTION =
		"Workers collect their program writes per location and the writes are applied in " +
			"the order the locations are queued after all workers finish, so results do not depend on " +
			"Max Threads or thread timing (results can differ from the immediate-write mode). " +
			"Offered only by analyzers whose worker writes are all deferred.";

	/**
	 * System property that gives the default of {@link #DEFERRED_WRITES_OPTION_NAME}
	 * (default false: original immediate-write behaviour).
	 */
	public static final String DEFERRED_WRITES_PROPERTY = "hydra.analysis.deferredWrites";

	/**
	 * @return default value of the deferred-writes option
	 */
	public static boolean getDeferredWritesDefault() {
		return Boolean.getBoolean(DEFERRED_WRITES_PROPERTY);
	}

	/**
	 * Deterministic variant of {@link #runParallelAddressAnalysis}.
	 * <p>
	 * Every location is analyzed by a worker with a {@link DeferredProgramWrites} collector
	 * open, so no worker writes to the program while others read it; every worker sees the
	 * program as it was before this call. After all workers finish, the calling thread walks
	 * the locations in the iteration order of {@code locations}, which is the order
	 * {@link #runParallelAddressAnalysis} queues them and so the order in which it processes
	 * them at one thread; a location whose address is already covered by the result of an
	 * earlier applied location is dropped (the ordered form of the "already analyzed" skip),
	 * otherwise its writes are applied and its result added. That order depends only on the
	 * set (for a {@code HashSet<Address>}, on its contents and insertion order), so the
	 * returned set and the program changes are the same for any thread count, and they match
	 * the immediate mode at one thread except where a worker would have read another
	 * location's writes.
	 *
	 * @param program program
	 * @param locations points to analyze
	 * @param restrictedSet set to restrict analysis to, null if none
	 * @param maxThreads maximum number of threads to use
	 * @param monitor to cancel
	 * @return set of addresses covered by the applied locations
	 * @throws CancelledException if cancelled
	 * @throws InterruptedException if interrupted
	 * @throws Exception any exception
	 */
	protected AddressSetView runDeferredParallelAddressAnalysis(final Program program,
			final Set<Address> locations, final AddressSetView restrictedSet, int maxThreads,
			final TaskMonitor monitor) throws CancelledException, InterruptedException, Exception {

		monitor.checkCancelled();

		final AddressSet appliedSet = new AddressSet();
		if (locations.isEmpty()) {
			return appliedSet;
		}

		// the queue order of runParallelAddressAnalysis (not sorted: sorting changed which of two
		// locations writing the same item wins compared with the immediate mode at one thread)
		final List<Address> ordered = new ArrayList<>(locations);

		final ConcurrentHashMap<Address, LocationDelta> deltas = new ConcurrentHashMap<>();

		GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
		monitor.setMaximum(ordered.size());

		QCallback<Address, AddressSetView> callback = (loc, taskMonitor) -> {
			DeferredProgramWrites writes = DeferredProgramWrites.open();
			try {
				AddressSetView result = analyzeLocation(program, loc, restrictedSet, taskMonitor);
				deltas.put(loc, new LocationDelta(result, writes));
				taskMonitor.incrementProgress(1);
				return result;
			}
			catch (CancelledException e) {
				return null; // monitor was cancelled
			}
			finally {
				writes.close();
			}
		};

		maxThreads = Math.max(1, Math.min(maxThreads, pool.getMaxThreadCount()));

		// @formatter:off
		ConcurrentQ<Address, AddressSetView> queue = new ConcurrentQBuilder<Address, AddressSetView>()
			.setThreadPool(pool)
			.setMaxInProgress(maxThreads)
			.setMonitor(monitor)
			.build(callback);
		// @formatter:on

		queue.add(ordered);
		queue.waitUntilDone();

		monitor.checkCancelled();

		// apply in queue order on this (the analysis) thread
		for (Address loc : ordered) {
			monitor.checkCancelled();
			LocationDelta delta = deltas.remove(loc);
			if (delta == null || appliedSet.contains(loc)) {
				continue;
			}
			// a failing write is logged and skipped inside apply; the other writes and
			// locations still run (CancelledException ends the pass)
			int failures = delta.writes.apply(monitor);
			if (failures != 0) {
				Msg.warn(this, getName() + ": " + failures +
					" deferred write(s) failed for location " + loc);
			}
			if (delta.result != null) {
				appliedSet.add(delta.result);
			}
		}
		return appliedSet;
	}

	private static final class LocationDelta {
		final AddressSetView result;
		final DeferredProgramWrites writes;

		LocationDelta(AddressSetView result, DeferredProgramWrites writes) {
			this.result = result;
			this.writes = writes;
		}
	}
}
