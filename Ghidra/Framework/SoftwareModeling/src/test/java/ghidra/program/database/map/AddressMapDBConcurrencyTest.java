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
package ghidra.program.database.map;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.*;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.*;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.task.TaskMonitor;

public class AddressMapDBConcurrencyTest {

	private static final int THREADS = Math.max(4, Runtime.getRuntime().availableProcessors());

	private DBHandle handle;
	private long txId;
	private AddressSpace ram;
	private AddressMapDB map;

	@BeforeClass
	public static void initializeIds() {
		UniversalIdGenerator.initialize();
	}

	@Before
	public void setUp() throws Exception {
		ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
		handle = new DBHandle();
		txId = handle.startTransaction();
		map = new AddressMapDB(handle, OpenMode.CREATE,
			new DefaultAddressFactory(new AddressSpace[] { ram }), 0, TaskMonitor.DUMMY);
	}

	@After
	public void tearDown() throws Exception {
		handle.endTransaction(txId, true);
		handle.close();
	}

	@Test
	public void testReadsDoNotWaitForTheMapMonitor() throws Exception {
		Address addr = ram.getAddress(0x1000);
		long key = map.getKey(addr, true);
		long absolute = map.getAbsoluteEncoding(addr, false);
		CountDownLatch held = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		Thread holder = new Thread(() -> {
			synchronized (map) {
				held.countDown();
				try {
					release.await(30, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		});
		holder.start();
		ExecutorService reader = Executors.newSingleThreadExecutor();
		try {
			assertTrue(held.await(10, TimeUnit.SECONDS));
			// with synchronized reads these wait for the holder and time out
			assertEquals(key, (long) reader.submit(() -> map.getKey(addr, false))
					.get(10, TimeUnit.SECONDS));
			assertEquals(absolute, (long) reader.submit(() -> map.getAbsoluteEncoding(addr, false))
					.get(10, TimeUnit.SECONDS));
			assertEquals(addr, reader.submit(() -> map.decodeAddress(key))
					.get(10, TimeUnit.SECONDS));
		}
		finally {
			release.countDown();
			holder.join();
			reader.shutdownNow();
		}
	}

	@Test
	public void testConcurrentCreateAndReadAgree() throws Exception {
		int bases = 64;
		AtomicInteger wrong = new AtomicInteger();
		List<Map<Long, Long>> keysPerThread = runOnThreads(t -> {
			Map<Long, Long> keys = new HashMap<>();
			Random random = new Random(t);
			for (int i = 0; i < 4000; i++) {
				// one address per 4 GB base segment, so creating keys adds base addresses
				long base = (long) random.nextInt(bases) << 32;
				long offset = base | random.nextInt(0x10000);
				Address addr = ram.getAddress(offset);
				long key = map.getKey(addr, true);
				if (!addr.equals(map.decodeAddress(key))) {
					wrong.incrementAndGet();
				}
				if (map.getKey(addr, false) != key ||
					map.getAbsoluteEncoding(addr, false) == AddressMap.INVALID_ADDRESS_KEY) {
					wrong.incrementAndGet();
				}
				Long previous = keys.put(offset, key);
				if (previous != null && previous != key) {
					wrong.incrementAndGet();
				}
			}
			return keys;
		});
		assertEquals(0, wrong.get());

		// every thread saw the same key for an address, and each base was added once
		Map<Long, Long> all = new HashMap<>();
		for (Map<Long, Long> keys : keysPerThread) {
			for (Map.Entry<Long, Long> e : keys.entrySet()) {
				Long previous = all.put(e.getKey(), e.getValue());
				assertTrue(previous == null || previous.longValue() == e.getValue());
			}
		}
		Set<Long> baseKeys = new HashSet<>();
		for (long key : all.values()) {
			baseKeys.add(key & AddressMapDB.BASE_MASK);
		}
		Set<Long> baseOffsets = new HashSet<>();
		for (long offset : all.keySet()) {
			baseOffsets.add(offset >>> 32);
		}
		assertEquals(baseOffsets.size(), baseKeys.size());
	}

	@Test
	public void testInvalidateCacheKeepsKeys() throws Exception {
		Address a = ram.getAddress(0x5_0000_1234L);
		Address b = ram.getAddress(0x7_0000_0010L);
		long ka = map.getKey(a, true);
		long kb = map.getKey(b, true);
		map.invalidateCache();
		assertEquals(ka, map.getKey(a, false));
		assertEquals(kb, map.getKey(b, false));
		assertEquals(a, map.decodeAddress(ka));
		assertEquals(b, map.decodeAddress(kb));
		assertEquals(AddressMap.INVALID_ADDRESS_KEY,
			map.getKey(ram.getAddress(0x9_0000_0000L), false));
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
				results.add(f.get(120, TimeUnit.SECONDS));
			}
			return results;
		}
		finally {
			pool.shutdownNow();
		}
	}
}
