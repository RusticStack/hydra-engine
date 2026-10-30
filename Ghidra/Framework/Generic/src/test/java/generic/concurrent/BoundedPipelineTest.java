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

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

import org.junit.*;

import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class BoundedPipelineTest {

	private ExecutorService pool;

	@Before
	public void setUp() {
		pool = Executors.newFixedThreadPool(8);
	}

	@After
	public void tearDown() {
		pool.shutdownNow();
	}

	private static List<Integer> range(int n) {
		return IntStream.range(0, n).boxed().toList();
	}

	/** Later items finish first: a callback that sleeps less for higher items. */
	private static QCallback<Integer, Integer> reverseFinishing(int n) {
		return (item, monitor) -> {
			Thread.sleep(Math.max(0, (n - item) % 7));
			return item * 10;
		};
	}

	@Test
	public void testOrderedDeliversInIteratorOrderOnCallerThread() throws Exception {
		int n = 300;
		Thread caller = Thread.currentThread();
		List<Long> indexes = new ArrayList<>();
		List<Integer> results = new ArrayList<>();
		BoundedPipeline<Integer, Integer> p =
			new BoundedPipeline<>(reverseFinishing(n), pool, 6, 24, true, true);
		BoundedPipeline.Stats st = p.run(range(n).iterator(), (i, item, r) -> {
			assertSame(caller, Thread.currentThread());
			indexes.add(i);
			results.add(r);
			assertEquals(item * 10, (int) r);
		}, TaskMonitor.DUMMY);
		assertEquals(n, results.size());
		for (int i = 0; i < n; i++) {
			assertEquals(i, (long) indexes.get(i));
			assertEquals(i * 10, (int) results.get(i));
		}
		assertEquals(n, st.taken());
		assertEquals(n, st.processed());
		assertTrue("window " + st.maxOutstanding(), st.maxOutstanding() <= 24);
		assertTrue("workers " + st.workers(), st.workers() <= 6 && st.workers() >= 1);
	}

	@Test
	public void testUnorderedDeliversEveryResultOnce() throws Exception {
		int n = 500;
		Thread caller = Thread.currentThread();
		Set<Long> seen = new HashSet<>();
		BoundedPipeline<Integer, Integer> p =
			new BoundedPipeline<>(reverseFinishing(n), pool, 6, 24, false, true);
		p.run(range(n).iterator(), (i, item, r) -> {
			assertSame(caller, Thread.currentThread());
			assertTrue(seen.add(i));
			assertEquals((long) item, (long) i);
			assertEquals(item * 10, (int) r);
		}, TaskMonitor.DUMMY);
		assertEquals(n, seen.size());
	}

	@Test
	public void testBackPressureBoundsEnumerationAheadOfSink() throws Exception {
		int n = 200;
		int window = 10;
		AtomicLong taken = new AtomicLong();
		AtomicLong delivered = new AtomicLong();
		AtomicLong maxAhead = new AtomicLong();
		Iterator<Integer> src = new Iterator<>() {
			int next = 0;

			@Override
			public boolean hasNext() {
				return next < n;
			}

			@Override
			public Integer next() {
				long ahead = taken.incrementAndGet() - delivered.get();
				maxAhead.accumulateAndGet(ahead, Math::max);
				return next++;
			}
		};
		BoundedPipeline<Integer, Integer> p =
			new BoundedPipeline<>((item, m) -> item, pool, 4, window, true, true);
		p.run(src, (i, item, r) -> {
			Thread.sleep(1); // a slow consumer
			delivered.incrementAndGet();
		}, TaskMonitor.DUMMY);
		assertEquals(n, delivered.get());
		assertTrue("ahead " + maxAhead.get(), maxAhead.get() <= window);
	}

	@Test
	public void testStagesOverlap() throws Exception {
		// the first result reaches the sink long before the iterator is exhausted, and the
		// workers run while the caller is still enumerating
		int n = 1000;
		AtomicInteger takenAtFirstResult = new AtomicInteger(-1);
		AtomicInteger takenCount = new AtomicInteger();
		AtomicInteger processedWhileEnumerating = new AtomicInteger();
		Iterator<Integer> src = new Iterator<>() {
			int next = 0;

			@Override
			public boolean hasNext() {
				return next < n;
			}

			@Override
			public Integer next() {
				takenCount.incrementAndGet();
				return next++;
			}
		};
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			if (takenCount.get() < n) {
				processedWhileEnumerating.incrementAndGet();
			}
			return item;
		}, pool, 4, 16, true, true);
		p.run(src, (i, item, r) -> {
			takenAtFirstResult.compareAndSet(-1, takenCount.get());
		}, TaskMonitor.DUMMY);
		assertTrue("taken at first result " + takenAtFirstResult.get(),
			takenAtFirstResult.get() <= 16);
		assertTrue(processedWhileEnumerating.get() > n / 2);
	}

	@Test
	public void testErrorWithoutStopRunsEverythingAndThrowsLowestIndex() throws Exception {
		int n = 100;
		AtomicInteger ran = new AtomicInteger();
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			ran.incrementAndGet();
			if (item == 40 || item == 70) {
				Thread.sleep(item == 40 ? 20 : 0); // 70 fails first in time
				throw new IllegalStateException("bad " + item);
			}
			return item;
		}, pool, 4, 16, false, false);
		List<Integer> got = Collections.synchronizedList(new ArrayList<>());
		try {
			p.run(range(n).iterator(), (i, item, r) -> got.add(r), TaskMonitor.DUMMY);
			fail();
		}
		catch (IllegalStateException e) {
			assertEquals("bad 40", e.getMessage());
		}
		assertEquals(n, ran.get());
		assertEquals(n - 2, got.size());
	}

	@Test
	public void testErrorWithStopStartsNoFurtherItems() throws Exception {
		int n = 10_000;
		AtomicInteger ran = new AtomicInteger();
		AtomicInteger running = new AtomicInteger();
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			running.incrementAndGet();
			try {
				ran.incrementAndGet();
				if (item == 5) {
					throw new IllegalArgumentException("bad");
				}
				Thread.sleep(1);
				return item;
			}
			finally {
				running.decrementAndGet();
			}
		}, pool, 4, 16, true, true);
		try {
			p.run(range(n).iterator(), (i, item, r) -> {
				// consume
			}, TaskMonitor.DUMMY);
			fail();
		}
		catch (IllegalArgumentException e) {
			assertEquals("bad", e.getMessage());
		}
		assertEquals("a callback outlived run()", 0, running.get());
		assertTrue("ran " + ran.get(), ran.get() < 100);
	}

	@Test
	public void testSinkErrorStopsAndIsThrown() throws Exception {
		int n = 10_000;
		AtomicInteger ran = new AtomicInteger();
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			ran.incrementAndGet();
			return item;
		}, pool, 4, 16, false, true);
		try {
			p.run(range(n).iterator(), (i, item, r) -> {
				if (i == 3) {
					throw new java.io.IOException("sink");
				}
			}, TaskMonitor.DUMMY);
			fail();
		}
		catch (java.io.IOException e) {
			assertEquals("sink", e.getMessage());
		}
		assertTrue("ran " + ran.get(), ran.get() < 100);
	}

	@Test
	public void testCancelStopsAndReturnsNormally() throws Exception {
		int n = 10_000;
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		AtomicInteger ran = new AtomicInteger();
		AtomicInteger running = new AtomicInteger();
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			running.incrementAndGet();
			try {
				if (ran.incrementAndGet() == 50) {
					monitor.cancel();
				}
				if (m.isCancelled()) {
					return null;
				}
				Thread.sleep(1);
				return item;
			}
			finally {
				running.decrementAndGet();
			}
		}, pool, 4, 16, true, true);
		List<Integer> got = new ArrayList<>();
		p.run(range(n).iterator(), (i, item, r) -> got.add(r), monitor);
		assertEquals(0, running.get());
		assertTrue("ran " + ran.get(), ran.get() < 100);
		assertTrue(got.size() < 100);
	}

	/** A monitor that keeps its progress values. */
	private static class ProgressMonitor extends TaskMonitorAdapter {
		volatile long max;
		volatile long progress;

		ProgressMonitor() {
			super(true);
		}

		@Override
		public void initialize(long m) {
			max = m;
			progress = 0;
		}

		@Override
		public void setMaximum(long m) {
			max = m;
		}

		@Override
		public long getMaximum() {
			return max;
		}

		@Override
		public void setProgress(long v) {
			progress = v;
		}

		@Override
		public long getProgress() {
			return progress;
		}
	}

	@Test
	public void testTaskMonitorKeepsProgressAndCancelWithPipeline() throws Exception {
		ProgressMonitor monitor = new ProgressMonitor();
		monitor.initialize(5);
		BoundedPipeline<Integer, Integer> p = new BoundedPipeline<>((item, m) -> {
			m.initialize(1000);       // ignored: progress belongs to the pipeline
			m.setProgress(999);
			m.clearCancelled();
			return item;
		}, pool, 2, 4, true, true);
		p.run(range(5).iterator(), (i, item, r) -> {
			// consume
		}, monitor);
		assertEquals(5, monitor.getMaximum());
		assertEquals(5, monitor.getProgress());
	}

	@Test
	public void testNoPoolThreadHeldWhenIdle() throws Exception {
		// a one-thread pool shared by two pipelines run at the same time: both finish, because
		// a worker loop returns its thread as soon as its queue is empty
		ExecutorService one = Executors.newSingleThreadExecutor();
		try {
			CountDownLatch release = new CountDownLatch(1);
			BlockingQueue<Integer> slowSource = new LinkedBlockingQueue<>();
			Iterator<Integer> src = new Iterator<>() {
				int left = 3;

				@Override
				public boolean hasNext() {
					return left > 0;
				}

				@Override
				public Integer next() {
					try {
						left--;
						if (left == 1) {
							release.await(); // pipeline A waits here with its queue empty
						}
						return slowSource.isEmpty() ? left : slowSource.take();
					}
					catch (InterruptedException e) {
						throw new RuntimeException(e);
					}
				}
			};
			BoundedPipeline<Integer, Integer> a =
				new BoundedPipeline<>((item, m) -> item, one, 1, 4, true, true);
			Future<BoundedPipeline.Stats> fa = Executors.newSingleThreadExecutor()
					.submit(() -> a.run(src, (i, item, r) -> {
					}, TaskMonitor.DUMMY));
			Thread.sleep(100); // let A's first item run and its loop go idle
			BoundedPipeline<Integer, Integer> b =
				new BoundedPipeline<>((item, m) -> item, one, 1, 4, true, true);
			List<Integer> got = new ArrayList<>();
			b.run(range(20).iterator(), (i, item, r) -> got.add(r), TaskMonitor.DUMMY);
			assertEquals(range(20), got);
			release.countDown();
			assertEquals(3, fa.get(10, TimeUnit.SECONDS).processed());
		}
		finally {
			one.shutdownNow();
		}
	}

	@Test
	public void testEmptySource() throws Exception {
		BoundedPipeline<Integer, Integer> p =
			new BoundedPipeline<>((item, m) -> item, pool, 4, 16, true, true);
		BoundedPipeline.Stats st = p.run(Collections.emptyIterator(), (i, item, r) -> fail(),
			TaskMonitor.DUMMY);
		assertEquals(0, st.taken());
	}
}
