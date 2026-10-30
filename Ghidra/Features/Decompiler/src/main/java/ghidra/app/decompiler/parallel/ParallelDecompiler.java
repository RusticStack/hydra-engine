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
package ghidra.app.decompiler.parallel;

import java.util.*;
import java.util.function.Consumer;

import generic.concurrent.*;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.cpu.HydraCpu;
import ghidra.util.task.TaskMonitor;

/**
 * Decompiles many functions at once.
 * <p>
 * <b>Pipeline (Hydra, off by default).</b>  With {@code -Dhydra.decompiler.pipeline=true} the
 * {@code decompileFunctions} methods run through a {@link BoundedPipeline} instead of a
 * {@link DecompilerConcurrentQ}: the calling thread enumerates the functions a bounded window
 * ahead of the workers (instead of queueing all of them first, under the queue lock) and
 * consumes the results while the workers keep decompiling; results are handed to a consumer on
 * the calling thread, one at a time, instead of on the worker threads.  The decompile of each
 * function is the same callback with the same decompiler pool, so every result is the same; the
 * methods that return a list return it in the iterator's order instead of completion order.
 * {@link #decompileFunctionsInOrder} always uses the pipeline and delivers in iterator order.
 * <p>
 * Workers ({@code hydra.decompiler.pipeline.workers}): {@code pool} (the default: the size of
 * the shared pool, i.e. today's concurrency, from the CPUs the OS grants through
 * {@link HydraCpu} and the default pool cap), {@code granted} (every granted CPU,
 * {@link HydraCpu#grantedCpus()}, uncapped), or a number.  Window
 * ({@code hydra.decompiler.pipeline.window}, per worker): {@value #WINDOW_PER_WORKER} by default,
 * {@value #ORDERED_WINDOW_PER_WORKER} for {@link #decompileFunctionsInOrder}.
 */
public class ParallelDecompiler {

	static final String THREAD_POOL_NAME = "Parallel Decompiler";

	/** The system property that turns the pipeline on for the existing methods (default off). */
	public static final String PIPELINE_PROPERTY = "hydra.decompiler.pipeline";
	/** The system property that sizes the pipeline: {@code pool}, {@code granted} or a number. */
	public static final String PIPELINE_WORKERS_PROPERTY = "hydra.decompiler.pipeline.workers";
	/**
	 * The system property that sets the window per worker: how many functions the pipeline may
	 * hold (queued, running, or finished and not yet consumed) for each worker.
	 */
	public static final String PIPELINE_WINDOW_PROPERTY = "hydra.decompiler.pipeline.window";
	/** The default window per worker when results are consumed in completion order. */
	static final int WINDOW_PER_WORKER = 4;
	/**
	 * The default window per worker when results are consumed in iterator order: larger, so one
	 * slow function at the head does not stop the workers once the window fills behind it.  Up
	 * to this many finished results per worker wait for the head, so a callback returning large
	 * objects may want a smaller value.  Measured on 2000 KotOR functions (10 workers): 32 was
	 * about 1.3x the unordered wall time, 128 the same as unordered.
	 */
	static final int ORDERED_WINDOW_PER_WORKER = 128;

	/**
	 * Decompile the given functions using multiple decompilers
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param program the program
	 * @param addresses the addresses restricting which functions to decompile
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback, Program program,
			AddressSetView addresses, TaskMonitor monitor) throws InterruptedException, Exception {

		int functionCount = program.getFunctionManager().getFunctionCount();
		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addresses, true);

		List<R> results = doDecompileFunctions(callback, iterator, functionCount, monitor);
		return results;
	}

	/**
	 * Decompile the given functions using multiple decompilers
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param functions the functions to decompile
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback,
			Collection<Function> functions, TaskMonitor monitor)
			throws InterruptedException, Exception {

		List<R> results =
			doDecompileFunctions(callback, functions.iterator(), functions.size(), monitor);
		return results;
	}

	/**
	 * Decompile the given functions using multiple decompilers.
	 *
	 * <p>Results will be passed to the given consumer as they are produced.  Calling this
	 * method allows you to handle results as they are discovered.
	 *
	 * <p><strong>This method will wait for all processing before returning.</strong>
	 *
	 * @param callback the callback to be called for each that is processed
	 * @param program the program
	 * @param functions the functions to decompile
	 * @param resultsConsumer the consumer to which results will be passed
	 * @param monitor the task monitor
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> void decompileFunctions(QCallback<Function, R> callback, Program program,
			Iterator<Function> functions, Consumer<R> resultsConsumer, TaskMonitor monitor)
			throws InterruptedException, Exception {

		int max = program.getFunctionManager().getFunctionCount();
		if (Boolean.getBoolean(PIPELINE_PROPERTY)) {
			Objects.requireNonNull(resultsConsumer);
			monitor.initialize(max);
			pipeline(callback, false, true).run(functions, (i, f, r) -> {
				if (r != null) {
					resultsConsumer.accept(r);
				}
			}, monitor);
			return;
		}
		boolean collectResults = false; // the client will process results as they arrive
		GThreadPool threadPool = GThreadPool.getSharedThreadPool(THREAD_POOL_NAME);
		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, threadPool, collectResults, monitor);

		monitor.initialize(max);
		queue.process(functions, resultsConsumer);
		queue.waitUntilDone();
	}

	private static <R> List<R> doDecompileFunctions(QCallback<Function, R> callback,
			Iterator<Function> functions, int count, TaskMonitor monitor)
			throws InterruptedException, Exception {

		if (Boolean.getBoolean(PIPELINE_PROPERTY)) {
			monitor.initialize(count);
			return pipelineToList(callback, functions, monitor);
		}

		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, THREAD_POOL_NAME, monitor);

		monitor.initialize(count);

		queue.addAll(functions);

		Collection<QResult<Function, R>> qResults = null;
		try {
			qResults = queue.waitForResults();
		}
		finally {
			queue.dispose();
		}

		List<R> results = new ArrayList<>();
		for (QResult<Function, R> qResult : qResults) {
			results.add(qResult.getResult());
		}

		return results;
	}

	/**
	 * Decompiles the given functions with multiple decompilers and hands each non-null result to
	 * the consumer <b>in the iterator's order</b>, on the calling thread, while the decompiles of
	 * the following functions run.  The functions are read from the iterator on the calling
	 * thread, a bounded window ahead of the consumer, so memory stays bounded however many
	 * functions there are; a slow consumer (or a slow function at the head) holds back the
	 * enumeration, not the workers' queued work.
	 *
	 * <p>The first exception from the callback or the consumer stops the work (no further
	 * function is started) and is thrown once the running decompiles have finished.  A cancelled
	 * monitor stops the work and returns normally.
	 *
	 * <p><strong>This method will wait for all processing before returning.</strong>
	 *
	 * @param callback the callback to be called for each function
	 * @param program the program
	 * @param functions the functions to decompile
	 * @param resultsConsumer the consumer to which results will be passed, in iterator order
	 * @param monitor the task monitor
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> void decompileFunctionsInOrder(QCallback<Function, R> callback,
			Program program, Iterator<Function> functions, Consumer<R> resultsConsumer,
			TaskMonitor monitor) throws InterruptedException, Exception {
		Objects.requireNonNull(resultsConsumer);
		monitor.initialize(program.getFunctionManager().getFunctionCount());
		pipeline(callback, true, true).run(functions, (i, f, r) -> {
			if (r != null) {
				resultsConsumer.accept(r);
			}
		}, monitor);
	}

	/**
	 * Runs the functions through the pipeline and returns the results in the iterator's order.
	 * Like the {@link DecompilerConcurrentQ} path, every function runs even when one fails, and
	 * the failure (here: of the first function in iterator order) is thrown at the end.
	 */
	private static <R> List<R> pipelineToList(QCallback<Function, R> callback,
			Iterator<Function> functions, TaskMonitor monitor)
			throws InterruptedException, Exception {
		// delivered in completion order (no head-of-line wait), placed by index
		Map<Long, R> byIndex = new HashMap<>();
		pipeline(callback, false, false).run(functions, (i, f, r) -> byIndex.put(i, r), monitor);
		Long[] keys = byIndex.keySet().toArray(new Long[0]);
		Arrays.sort(keys);
		List<R> results = new ArrayList<>(keys.length);
		for (Long k : keys) {
			results.add(byIndex.get(k));
		}
		return results;
	}

	static <R> BoundedPipeline<Function, R> pipeline(QCallback<Function, R> callback,
			boolean ordered, boolean stopOnError) {
		GThreadPool pool = pipelinePool();
		int workers = pool.getMaxThreadCount();
		int perWorker = Integer.getInteger(PIPELINE_WINDOW_PROPERTY,
			ordered ? ORDERED_WINDOW_PER_WORKER : WINDOW_PER_WORKER);
		return new BoundedPipeline<>(callback, pool.getExecutor(), workers,
			workers * Math.max(1, perWorker), ordered, stopOnError);
	}

	/**
	 * The pool for the pipeline's workers, sized by {@value #PIPELINE_WORKERS_PROPERTY}.
	 *
	 * @return the shared pool to run on
	 */
	static GThreadPool pipelinePool() {
		int n = pipelineWorkers(System.getProperty(PIPELINE_WORKERS_PROPERTY, "pool"));
		if (n <= 0) {
			return GThreadPool.getSharedThreadPool(THREAD_POOL_NAME);
		}
		GThreadPool pool = GThreadPool.getSharedThreadPool(THREAD_POOL_NAME + " (" + n + ")");
		if (pool.getMaxThreadCount() != n) {
			pool.setMaxThreadCount(n);
		}
		return pool;
	}

	/**
	 * Parses {@value #PIPELINE_WORKERS_PROPERTY}.
	 *
	 * @param value {@code pool}, {@code granted} or a positive number
	 * @return the number of workers, or 0 for the shared pool's size
	 */
	static int pipelineWorkers(String value) {
		String v = value.trim();
		if (v.isEmpty() || v.equalsIgnoreCase("pool")) {
			return 0;
		}
		if (v.equalsIgnoreCase("granted")) {
			return Math.max(1, HydraCpu.grantedCpus());
		}
		try {
			return Math.max(0, Integer.parseInt(v));
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	/**
	 * Creates an object that can be used to perform decompilation of a limited number of
	 * functions at a time, as opposed to working over an entire range of functions at once.
	 * {@link #decompileFunctions(QCallback, Program, AddressSetView, TaskMonitor)} will create
	 * and tear down concurrent data structures on each use, making repeated calls less efficient.
	 * You would use this method when you wish to perform periodic work as results are returned
	 * <b>and when using the callback mechanism is not sufficient</b> such as when ordering of
	 * results is required.
	 *
	 * @param callback the callback required to perform work.
	 * @param monitor the monitor used to report progress and to cancel
	 * @return the parallel decompiler used for decompiling.
	 */
	public static <R> ChunkingParallelDecompiler<R> createChunkingParallelDecompiler(
			QCallback<Function, R> callback, TaskMonitor monitor) {
		return new ChunkingParallelDecompiler<>(callback, monitor);
	}

	private ParallelDecompiler() {
		// only use statically
	}
}
