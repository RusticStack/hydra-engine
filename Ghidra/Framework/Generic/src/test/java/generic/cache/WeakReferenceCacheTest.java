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
package generic.cache;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

public class WeakReferenceCacheTest {

	private static final int THREADS = Math.max(4, Runtime.getRuntime().availableProcessors());

	@Test
	public void testGetDoesNotWaitForTheCacheMonitor() throws Exception {
		WeakReferenceCache<Long, String> cache = new WeakReferenceCache<>(10);
		String value = cache.add(1L, "one");
		CountDownLatch held = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		Thread holder = new Thread(() -> {
			synchronized (cache) {
				held.countDown();
				awaitQuietly(release);
			}
		});
		holder.start();
		ExecutorService reader = Executors.newSingleThreadExecutor();
		try {
			assertTrue(held.await(10, TimeUnit.SECONDS));
			Future<String> hit = reader.submit(() -> cache.get(1L));
			Future<String> miss = reader.submit(() -> cache.get(2L));
			Future<Integer> size = reader.submit(cache::size);
			assertSame(value, hit.get(10, TimeUnit.SECONDS));
			assertNull(miss.get(10, TimeUnit.SECONDS));
			assertEquals(1, (int) size.get(10, TimeUnit.SECONDS));
		}
		finally {
			release.countDown();
			holder.join();
			reader.shutdownNow();
		}
	}

	@Test
	public void testConcurrentGetsSeeOneObjectPerKey() throws Exception {
		WeakReferenceCache<Long, Object> cache = new WeakReferenceCache<>(16);
		int keys = 1000;
		Object[] values = new Object[keys];
		for (int i = 0; i < keys; i++) {
			values[i] = cache.add((long) i, new Object());
		}
		AtomicInteger wrong = new AtomicInteger();
		runOnThreads(t -> {
			Random random = new Random(t);
			for (int i = 0; i < 20000; i++) {
				int k = random.nextInt(keys);
				if (cache.get((long) k) != values[k]) {
					wrong.incrementAndGet();
				}
			}
		});
		assertEquals(0, wrong.get());
		assertEquals(keys, cache.size());
	}

	@Test
	public void testDeleteAndReAddAreVisibleToConcurrentReaders() throws Exception {
		WeakReferenceCache<Long, Object> cache = new WeakReferenceCache<>(16);
		int keys = 64;
		Object[] values = new Object[keys];
		for (int i = 0; i < keys; i++) {
			values[i] = cache.add((long) i, new Object());
		}
		AtomicInteger wrong = new AtomicInteger();
		CountDownLatch done = new CountDownLatch(1);
		Thread writer = new Thread(() -> {
			for (int round = 0; round < 200; round++) {
				for (int i = 0; i < keys; i++) {
					synchronized (cache) {
						Object old = cache.delete((long) i);
						if (old != values[i]) {
							wrong.incrementAndGet();
						}
						cache.add((long) i, old);
					}
				}
			}
			done.countDown();
		});
		writer.start();
		runOnThreads(t -> {
			Random random = new Random(t);
			while (done.getCount() > 0) {
				int k = random.nextInt(keys);
				Object v = cache.get((long) k);
				// a reader may miss while the key is being moved, but never sees another object
				if (v != null && v != values[k]) {
					wrong.incrementAndGet();
				}
			}
		});
		writer.join();
		assertEquals(0, wrong.get());
		for (int i = 0; i < keys; i++) {
			assertSame(values[i], cache.get((long) i));
		}
		cache.delete(3L);
		assertNull(cache.get(3L));
		assertEquals(keys - 1, cache.getCachedObjects().size());
	}

	@Test
	public void testHardCacheKeepsRecentValues() {
		WeakReferenceCache<Long, Object> cache = new WeakReferenceCache<>(4);
		for (long i = 0; i < 4; i++) {
			cache.add(i, new Object());
		}
		System.gc();
		for (long i = 0; i < 4; i++) {
			assertNotNull(cache.get(i));
		}
	}

	private interface ThreadBody {
		void run(int thread) throws Exception;
	}

	private static void runOnThreads(ThreadBody body) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(THREADS);
		try {
			CyclicBarrier start = new CyclicBarrier(THREADS);
			List<Future<?>> futures = new ArrayList<>();
			for (int t = 0; t < THREADS; t++) {
				int thread = t;
				futures.add(pool.submit(() -> {
					start.await();
					body.run(thread);
					return null;
				}));
			}
			for (Future<?> f : futures) {
				f.get(60, TimeUnit.SECONDS);
			}
		}
		finally {
			pool.shutdownNow();
		}
	}

	private static void awaitQuietly(CountDownLatch latch) {
		try {
			latch.await(30, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
