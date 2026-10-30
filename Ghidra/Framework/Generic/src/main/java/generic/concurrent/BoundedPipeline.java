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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

/**
 * A three-stage pipeline: the calling thread takes items from an {@link Iterator}
 * (enumeration), a fixed number of workers run a {@link QCallback} on them (processing), and the
 * calling thread hands every result to a {@link Sink} (consumption).  The stages overlap: the
 * workers keep processing while the caller enumerates more items and consumes finished ones.
 * <p>
 * <b>Bounded, with back-pressure.</b>  At most {@code window} items are taken from the iterator
 * and not yet handed to the sink.  When the window is full the caller stops enumerating until the
 * sink has taken a result, so a slow sink (or, in ordered mode, a slow item at the head) holds
 * back enumeration instead of growing memory.  The workers never wait for the sink while there is
 * queued work in the window.
 * <p>
 * <b>Order.</b>  Each item gets its index in the iterator (0, 1, 2, ...).  With {@code ordered}
 * the sink sees the results in index order, whatever order the workers finish in; otherwise it
 * sees them in completion order.  The sink is always called on the calling thread, one result at
 * a time, so it needs no synchronization.
 * <p>
 * <b>Errors and cancellation.</b>  An exception from the callback is reported to the sink's
 * caller after the pipeline drains: with {@code stopOnError} no further item is started once it
 * is seen; without it, every item still runs (as {@link ConcurrentQ#waitForResults()} does) and the
 * error of the lowest index is thrown at the end.  An exception from the sink stops the pipeline
 * and is thrown.  A cancelled monitor stops enumeration and starting new items; items already
 * running see the cancel through their monitor; results of items that ran are still handed to
 * the sink (skipped items have none), and {@link #run} returns normally, as {@link ConcurrentQ}
 * does for a cancelled monitor.  No callback is still running when {@link #run} returns.
 * <p>
 * <b>Progress.</b>  The caller's monitor gets the number of finished items as its progress (its
 * maximum is raised when more items than it allows were taken, like {@link ConcurrentQ}).  Each
 * callback gets a monitor that forwards cancellation and messages to the caller's monitor and
 * ignores progress values, so concurrent items do not fight over the progress bar.
 *
 * @param <I> the item type
 * @param <R> the result type
 */
public final class BoundedPipeline<I, R> {

	/**
	 * Receives the results of a {@link BoundedPipeline}, on the thread that called
	 * {@link BoundedPipeline#run}.
	 *
	 * @param <I> the item type
	 * @param <R> the result type
	 */
	@FunctionalInterface
	public interface Sink<I, R> {
		/**
		 * Takes one result.
		 *
		 * @param index the item's position in the iterator, from 0
		 * @param item the item
		 * @param result the callback's result (may be null)
		 * @throws Exception to stop the pipeline; {@link BoundedPipeline#run} throws it
		 */
		void accept(long index, I item, R result) throws Exception;
	}

	/** Counts from one run, for tests and measurements. */
	public record Stats(long taken, long processed, long delivered, int workers, int window,
			long maxOutstanding) {
	}

	private static final long POLL_MS = 50;

	private final QCallback<I, R> callback;
	private final Executor executor;
	private final int workers;
	private final int window;
	private final boolean ordered;
	private final boolean stopOnError;

	/**
	 * Creates a pipeline.
	 *
	 * @param callback the work run on each item by the workers
	 * @param executor runs the worker loops; it must be able to run {@code workers} tasks at once
	 *        for full parallelism (a pool with fewer threads runs fewer workers at a time)
	 * @param workers the number of items processed at the same time (at least 1)
	 * @param window the most items taken and not yet handed to the sink (at least
	 *        {@code workers}; raised to it when lower)
	 * @param ordered true to hand the results to the sink in iterator order
	 * @param stopOnError true to start no further item once a callback has failed
	 */
	public BoundedPipeline(QCallback<I, R> callback, Executor executor, int workers, int window,
			boolean ordered, boolean stopOnError) {
		this.callback = Objects.requireNonNull(callback);
		this.executor = Objects.requireNonNull(executor);
		this.workers = Math.max(1, workers);
		this.window = Math.max(this.workers, window);
		this.ordered = ordered;
		this.stopOnError = stopOnError;
	}

	/**
	 * Runs every item of the iterator through the callback and hands the results to the sink.
	 * Returns when every item taken has finished (or was skipped after a stop) and every
	 * deliverable result was handed to the sink.
	 *
	 * @param items the items; read on the calling thread only, never ahead of the window
	 * @param sink the consumer of the results, called on the calling thread
	 * @param monitor the monitor for cancellation and progress
	 * @return counts from the run
	 * @throws InterruptedException if the calling thread is interrupted (the workers are stopped
	 *         and drained first)
	 * @throws Exception the first callback error (see the class comment) or a sink error
	 */
	public Stats run(Iterator<I> items, Sink<I, R> sink, TaskMonitor monitor)
			throws InterruptedException, Exception {
		Objects.requireNonNull(items);
		Objects.requireNonNull(sink);
		TaskMonitor outer = monitor == null ? TaskMonitor.DUMMY : monitor;

		Queue<Work<I>> input = new ConcurrentLinkedQueue<>();
		BlockingQueue<Done<I, R>> done = new LinkedBlockingQueue<>();
		AtomicBoolean stop = new AtomicBoolean();
		AtomicInteger active = new AtomicInteger();
		TaskMonitor taskMonitor = new TaskScopeMonitor(outer);
		int maxActive = 0;

		long taken = 0;          // items read from the iterator and queued
		long finished = 0;       // items whose Done was taken from 'done'
		long delivered = 0;      // results handed to the sink, or dropped as undeliverable
		long nextIndex = 0;      // ordered: the next index the sink is due
		long maxOutstanding = 0;
		boolean sourceDone = false;
		Exception callbackError = null;
		long callbackErrorIndex = Long.MAX_VALUE;
		Exception sinkError = null;
		InterruptedException interrupted = null;
		Map<Long, Done<I, R>> pending = ordered ? new HashMap<>() : null;

		try {
			while (true) {
				boolean halted = stop.get() || outer.isCancelled();
				// stage 1: enumerate while the window has room
				while (!halted && !sourceDone && taken - delivered < window) {
					if (!items.hasNext()) {
						sourceDone = true;
						break;
					}
					I item = items.next();
					input.add(new Work<>(taken, item));
					taken++;
					startWorkers(input, done, stop, active, taskMonitor);
					maxActive = Math.max(maxActive, active.get());
					if (taken > outer.getMaximum()) {
						outer.setMaximum(taken);
					}
				}
				maxOutstanding = Math.max(maxOutstanding, taken - delivered);
				if (finished == taken && (sourceDone || halted)) {
					break;
				}

				// stage 3: consume what the workers finished
				Done<I, R> d = done.poll(POLL_MS, TimeUnit.MILLISECONDS);
				while (d != null) {
					finished++;
					outer.setProgress(finished);
					if (d.error != null && !(d.error instanceof CancellationException)) {
						if (d.index < callbackErrorIndex) {
							callbackError = d.error;
							callbackErrorIndex = d.index;
						}
						if (stopOnError) {
							stop.set(true);
						}
					}
					if (ordered) {
						pending.put(d.index, d);
					}
					else {
						delivered++;
						if (d.deliverable() && sinkError == null) {
							sinkError = deliver(sink, d, stop);
						}
					}
					d = done.poll();
				}
				if (ordered) {
					Done<I, R> head;
					while ((head = pending.remove(nextIndex)) != null) {
						nextIndex++;
						delivered++;
						if (head.deliverable() && sinkError == null) {
							sinkError = deliver(sink, head, stop);
						}
					}
				}
			}
		}
		catch (InterruptedException e) {
			interrupted = e;
		}
		catch (RuntimeException e) {
			// the executor refused a worker, or the iterator failed
			if (sinkError == null) {
				sinkError = e;
			}
		}
		finally {
			stop.set(true);
			// items still queued are dropped here; the ones a worker holds are waited for, so
			// no callback outlives this call
			boolean wasInterrupted = false;
			while (finished < taken) {
				if (input.poll() != null) {
					finished++;
					continue;
				}
				try {
					if (done.poll(POLL_MS, TimeUnit.MILLISECONDS) != null) {
						finished++;
					}
				}
				catch (InterruptedException e) {
					wasInterrupted = true;
				}
			}
			if (wasInterrupted) {
				Thread.currentThread().interrupt();
			}
		}
		if (interrupted != null) {
			throw interrupted;
		}
		if (sinkError != null) {
			throw sinkError;
		}
		if (callbackError != null && !outer.isCancelled()) {
			throw callbackError;
		}
		return new Stats(taken, finished, delivered, maxActive, window, maxOutstanding);
	}

	private Exception deliver(Sink<I, R> sink, Done<I, R> d, AtomicBoolean stop) {
		try {
			sink.accept(d.index, d.item, d.result);
			return null;
		}
		catch (Exception e) {
			stop.set(true);
			return e;
		}
	}

	/**
	 * Starts worker loops (up to {@code workers}, and no more than there are queued items).  A
	 * loop runs items until the queue is empty and then returns its thread to the pool, so an
	 * idle pipeline holds no pool thread.
	 */
	private void startWorkers(Queue<Work<I>> input, BlockingQueue<Done<I, R>> done,
			AtomicBoolean stop, AtomicInteger active, TaskMonitor taskMonitor) {
		while (true) {
			int a = active.get();
			if (a >= workers || a >= input.size()) {
				return;
			}
			if (active.compareAndSet(a, a + 1)) {
				try {
					executor.execute(() -> workLoop(input, done, stop, active, taskMonitor));
				}
				catch (RuntimeException e) {
					active.decrementAndGet();
					throw e;
				}
			}
		}
	}

	private void workLoop(Queue<Work<I>> input, BlockingQueue<Done<I, R>> done,
			AtomicBoolean stop, AtomicInteger active, TaskMonitor taskMonitor) {
		while (true) {
			Work<I> w = input.poll();
			if (w == null) {
				active.decrementAndGet();
				// an item queued between the poll and the decrement saw this loop as active and
				// started none: take this loop back up if there is room
				if (input.isEmpty()) {
					return;
				}
				int a = active.get();
				if (a >= workers || !active.compareAndSet(a, a + 1)) {
					return;
				}
				continue;
			}
			if (stop.get() || taskMonitor.isCancelled()) {
				done.add(new Done<>(w.index, w.item, null, new CancellationException(), false));
				continue;
			}
			R r = null;
			Exception error = null;
			try {
				r = callback.process(w.item, taskMonitor);
			}
			catch (Exception e) {
				error = e;
			}
			catch (Throwable t) {
				error = new ExecutionException(t);
			}
			done.add(new Done<>(w.index, w.item, r, error, true));
		}
	}

	private record Work<I>(long index, I item) {
	}

	private record Done<I, R>(long index, I item, R result, Exception error, boolean ran) {
		boolean deliverable() {
			return ran && error == null;
		}
	}

	/**
	 * The monitor each callback gets: cancellation, cancel listeners and messages go to the
	 * caller's monitor; progress values are ignored (the pipeline reports progress itself), and
	 * a callback cannot clear the caller's cancel.
	 */
	private static final class TaskScopeMonitor extends WrappingTaskMonitor {
		TaskScopeMonitor(TaskMonitor delegate) {
			super(delegate);
		}

		@Override
		public void setShowProgressValue(boolean showProgressValue) {
			// progress belongs to the pipeline
		}

		@Override
		public void setProgress(long value) {
			// progress belongs to the pipeline
		}

		@Override
		public void initialize(long max) {
			// progress belongs to the pipeline
		}

		@Override
		public synchronized void setMaximum(long max) {
			// progress belongs to the pipeline
		}

		@Override
		public synchronized void setIndeterminate(boolean indeterminate) {
			// progress belongs to the pipeline
		}

		@Override
		public void incrementProgress(long incrementAmount) {
			// progress belongs to the pipeline
		}

		@Override
		public synchronized void clearCancelled() {
			// a callback cannot undo the caller's cancel
		}
	}
}
