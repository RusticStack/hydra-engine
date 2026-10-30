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
package ghidra.program.database;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import db.DBRecord;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;

public class DbCacheConcurrencyTest {

	private static final int THREADS = Math.max(4, Runtime.getRuntime().availableProcessors());

	private static class TestObject extends DbObject {
		final AtomicInteger refreshes = new AtomicInteger();
		volatile boolean exists = true;

		TestObject(long key) {
			super(key);
		}

		@Override
		protected boolean refresh(DBRecord record) {
			refreshes.incrementAndGet();
			return exists;
		}
	}

	/**
	 * A factory that counts instantiations per key and can hold the instantiation of one key.
	 */
	private static class TestFactory implements DbFactory<TestObject> {
		final ConcurrentHashMap<Long, AtomicInteger> created = new ConcurrentHashMap<>();
		volatile long blockedKey = -1;
		final CountDownLatch blockedEntered = new CountDownLatch(1);
		final CountDownLatch release = new CountDownLatch(1);

		@Override
		public TestObject instantiate(long key) {
			if (key == blockedKey) {
				blockedEntered.countDown();
				try {
					release.await(30, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			created.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
			Thread.yield(); // widen the window in which a second instance could be made
			return new TestObject(key);
		}

		@Override
		public TestObject instantiate(DBRecord record) {
			return instantiate(record.getKey());
		}
	}

	@Test
	public void testMissOnOneKeyDoesNotWaitForAnotherKey() throws Exception {
		TestFactory factory = new TestFactory();
		DbCache<TestObject> cache = new DbCache<>(factory, new Lock("test"), 10);
		factory.blockedKey = 1;
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			Future<TestObject> slow = pool.submit(() -> cache.getCachedInstance(1L));
			assertTrue(factory.blockedEntered.await(10, TimeUnit.SECONDS));
			Future<TestObject> other = pool.submit(() -> cache.getCachedInstance(2L));
			// with one monitor for all keys this waits for key 1 and times out
			TestObject two = other.get(10, TimeUnit.SECONDS);
			assertEquals(2L, two.getKey());
			factory.release.countDown();
			assertEquals(1L, slow.get(10, TimeUnit.SECONDS).getKey());
		}
		finally {
			factory.release.countDown();
			pool.shutdownNow();
		}
	}

	@Test
	public void testConcurrentMissesMakeOneObjectPerKey() throws Exception {
		TestFactory factory = new TestFactory();
		DbCache<TestObject> cache = new DbCache<>(factory, new Lock("test"), 10);
		int keys = 200;
		List<Map<Long, TestObject>> seen = runOnThreads(t -> {
			Map<Long, TestObject> mine = new HashMap<>();
			for (long k = 0; k < keys; k++) {
				mine.put(k, cache.getCachedInstance(k));
			}
			return mine;
		});
		for (long k = 0; k < keys; k++) {
			assertEquals("instances made for key " + k, 1, factory.created.get(k).get());
			TestObject first = seen.get(0).get(k);
			for (Map<Long, TestObject> m : seen) {
				assertSame(first, m.get(k));
			}
		}
		assertTrue(cache.instantiating.isEmpty());
	}

	@Test
	public void testInvalidateIsVisibleAndKeepsIdentity() throws Exception {
		TestFactory factory = new TestFactory();
		Lock lock = new Lock("test");
		DbCache<TestObject> cache = new DbCache<>(factory, lock, 10);
		TestObject obj = cache.getCachedInstance(5L);
		assertTrue(obj.isValid());

		try (Closeable c = lock.write()) {
			cache.invalidate();
		}
		assertFalse(obj.isValid());
		List<TestObject> seen = runOnThreads(t -> cache.getCachedInstance(5L));
		for (TestObject o : seen) {
			assertSame(obj, o);
		}
		assertTrue(obj.isValid());
		assertEquals(1, obj.refreshes.get());
		assertEquals(1, factory.created.get(5L).get());

		// an object that cannot refresh is replaced by a new instance
		obj.exists = false;
		try (Closeable c = lock.write()) {
			cache.invalidate();
		}
		TestObject replaced = cache.getCachedInstance(5L);
		assertNotSame(obj, replaced);
		assertEquals(2, factory.created.get(5L).get());
	}

	@Test
	public void testKeyChangedMovesTheObject() throws Exception {
		TestFactory factory = new TestFactory();
		Lock lock = new Lock("test");
		DbCache<TestObject> cache = new DbCache<>(factory, lock, 10);
		TestObject obj = cache.getCachedInstance(7L);
		try (Closeable c = lock.write()) {
			obj.keyChanged(8L);
		}
		assertSame(obj, cache.getCachedInstance(8L));
		assertNull(cache.getRaw(7L));
		assertEquals(null, factory.created.get(8L));

		cache.delete(8L);
		assertNull(cache.getRaw(8L));
		assertNotSame(obj, cache.getCachedInstance(8L));
	}

	private interface ThreadBody<R> {
		R run(int thread) throws Exception;
	}

	private static <R> List<R> runOnThreads(ThreadBody<R> body) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(THREADS);
		try {
			CyclicBarrier start = new CyclicBarrier(THREADS);
			List<Future<R>> futures = new ArrayList<>();
			for (int t = 0; t < THREADS; t++) {
				int thread = t;
				futures.add(pool.submit(() -> {
					start.await();
					return body.run(thread);
				}));
			}
			List<R> results = new ArrayList<>();
			for (Future<R> f : futures) {
				results.add(f.get(60, TimeUnit.SECONDS));
			}
			return results;
		}
		finally {
			pool.shutdownNow();
		}
	}
}
