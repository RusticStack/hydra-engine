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
package ghidra.program.database.data;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.*;

import db.DBHandle;
import generic.test.AbstractGenericTest;

/**
 * Readers of a data type manager hold only its read lock (GP-6679), so the lazily read calling
 * convention cache of {@link CallingConventionDBAdapterV0} is read by several threads at once
 * (concurrent decompiles of one program, Hydra multi-agent daemon). Before the fix a reader could
 * find the name-to-ID map set and the ID-to-name map still null ("this.callingConventionIDToNameMap
 * is null", seen in the multi-agent benchmark) or a map still being filled.
 */
public class CallingConventionDBAdapterV0ConcurrencyTest extends AbstractGenericTest {

	private static final int NAMES = 60;
	private static final int THREADS = 8;
	private static final int ROUNDS = 1500;

	private DBHandle dbh;
	private CallingConventionDBAdapterV0 adapter;
	private final Map<String, Byte> ids = new HashMap<>();

	@Before
	public void setUp() throws Exception {
		dbh = new DBHandle();
		long tx = dbh.startTransaction();
		adapter = new CallingConventionDBAdapterV0(dbh, "", true);
		for (int i = 0; i < NAMES; i++) {
			String n = "__cc" + i;
			ids.put(n, adapter.getCallingConventionId(n, x -> {}));
		}
		dbh.endTransaction(tx, true);
	}

	@After
	public void tearDown() {
		dbh.close();
	}

	@Test
	public void testConcurrentFirstReadsSeeEveryConvention() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(THREADS);
		AtomicInteger wrong = new AtomicInteger();
		List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
		try {
			for (int round = 0; round < ROUNDS && failures.isEmpty() && wrong.get() == 0; round++) {
				adapter.invalidateCache();
				CyclicBarrier start = new CyclicBarrier(THREADS);
				List<Future<?>> fs = new ArrayList<>();
				for (int t = 0; t < THREADS; t++) {
					// the last conventions are read last into the maps: the widest window
					String name = "__cc" + (NAMES - 1 - t);
					byte id = ids.get(name);
					boolean byName = (t & 1) == 0;
					fs.add(pool.submit(() -> {
						try {
							start.await();
							if (byName) {
								if (adapter.getCallingConventionId(name, x -> wrong.incrementAndGet()) != id) {
									wrong.incrementAndGet();
								}
							}
							else if (!name.equals(adapter.getCallingConventionName(id))) {
								wrong.incrementAndGet();
							}
						}
						catch (Throwable e) {
							failures.add(e);
						}
						return null;
					}));
				}
				for (Future<?> f : fs) {
					f.get(30, TimeUnit.SECONDS);
				}
			}
		}
		finally {
			pool.shutdownNow();
		}
		if (!failures.isEmpty()) {
			throw new AssertionError("a concurrent first read failed: " + failures.get(0),
				failures.get(0));
		}
		assertEquals("conventions misread (or re-added) by concurrent first reads", 0, wrong.get());
	}

	@Test
	public void testAddAfterFirstReadAndAfterInvalidate() throws Exception {
		assertEquals("__cc0", adapter.getCallingConventionName(ids.get("__cc0")));
		List<String> added = new ArrayList<>();
		long tx = dbh.startTransaction();
		byte a = adapter.getCallingConventionId("__added", added::add);
		dbh.endTransaction(tx, true);
		assertEquals(List.of("__added"), added);
		assertFalse(ids.containsValue(a));
		assertEquals("__added", adapter.getCallingConventionName(a));
		assertTrue(adapter.getCallingConventionNames().contains("__added"));
		adapter.invalidateCache();
		assertEquals("__added", adapter.getCallingConventionName(a));
		assertEquals(a, adapter.getCallingConventionId("__added", added::add));
		assertEquals(1, added.size());
		assertEquals(NAMES + 1, adapter.getCallingConventionNames().size());
		tx = dbh.startTransaction();
		byte b = adapter.getCallingConventionId("__added2", added::add);
		dbh.endTransaction(tx, true);
		assertEquals(a + 1, b); // the free keys survive the invalidate
		assertNull(adapter.getCallingConventionName((byte) 120));
	}

	/**
	 * Readers hold only the read lock, so several may miss the same new name at once: the name
	 * must get exactly one ID and one record, and different new names different IDs.
	 */
	@Test
	public void testConcurrentAddsOfOneNewNameGetOneId() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(THREADS);
		List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
		long tx = dbh.startTransaction();
		try {
			for (int round = 0; round < 30 && failures.isEmpty(); round++) {
				String name = "__new" + round;
				String other = "__other" + round;
				AtomicInteger added = new AtomicInteger();
				CyclicBarrier start = new CyclicBarrier(THREADS);
				List<Future<Byte>> fs = new ArrayList<>();
				for (int t = 0; t < THREADS; t++) {
					String n = (t & 3) == 3 ? other : name;
					fs.add(pool.submit(() -> {
						try {
							start.await();
							return adapter.getCallingConventionId(n, x -> added.incrementAndGet());
						}
						catch (Throwable e) {
							failures.add(e);
							return (byte) -1;
						}
					}));
				}
				Set<Byte> nameIds = new HashSet<>();
				Set<Byte> otherIds = new HashSet<>();
				for (int t = 0; t < THREADS; t++) {
					((t & 3) == 3 ? otherIds : nameIds).add(fs.get(t).get(30, TimeUnit.SECONDS));
				}
				assertEquals("one new name got several IDs: " + nameIds, 1, nameIds.size());
				assertEquals("one new name got several IDs: " + otherIds, 1, otherIds.size());
				assertNotEquals(nameIds, otherIds);
				assertEquals("a new name was added more than once", 2, added.get());
				byte id = nameIds.iterator().next();
				assertEquals(name, adapter.getCallingConventionName(id));
				adapter.invalidateCache(); // the table holds exactly the same as the cache
				assertEquals(name, adapter.getCallingConventionName(id));
				assertEquals(id, adapter.getCallingConventionId(name, x -> fail("re-added")));
				assertEquals(NAMES + 2 * (round + 1), adapter.getCallingConventionNames().size());
			}
		}
		finally {
			dbh.endTransaction(tx, true);
			pool.shutdownNow();
		}
		if (!failures.isEmpty()) {
			throw new AssertionError("a concurrent add failed: " + failures.get(0),
				failures.get(0));
		}
	}
}
