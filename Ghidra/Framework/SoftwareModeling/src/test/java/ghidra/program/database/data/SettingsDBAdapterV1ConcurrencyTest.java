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
 * Readers of a data type manager hold only its read lock (GP-6679), so the lazily read setting
 * name maps of {@link SettingsDBAdapterV1} are read by several threads at once (the decompiler
 * callbacks of concurrent decompiles of one program, Hydra multi-agent daemon). Before the fix a
 * reader could find the name maps set but still null or still empty while another thread read
 * the name table: a {@link NullPointerException} ("this.nameStringMap is null", seen in the
 * multi-agent benchmark) or a setting silently reported absent.
 */
public class SettingsDBAdapterV1ConcurrencyTest extends AbstractGenericTest {

	private static final int NAMES = 64;
	private static final int THREADS = 8;
	private static final int ROUNDS = 1500;

	private DBHandle dbh;
	private SettingsDBAdapterV1 adapter;

	@Before
	public void setUp() throws Exception {
		dbh = new DBHandle();
		long tx = dbh.startTransaction();
		adapter = new SettingsDBAdapterV1("Test Settings", dbh, true);
		for (int i = 0; i < NAMES; i++) {
			adapter.createSettingsRecord(1, "name" + i, "value" + i, i);
		}
		dbh.endTransaction(tx, true);
	}

	@After
	public void tearDown() {
		dbh.close();
	}

	@Test
	public void testConcurrentFirstReadsSeeEveryName() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(THREADS);
		AtomicInteger missing = new AtomicInteger();
		List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
		try {
			for (int round = 0; round < ROUNDS && failures.isEmpty() && missing.get() == 0; round++) {
				adapter.invalidateNameCache();
				CyclicBarrier start = new CyclicBarrier(THREADS);
				List<Future<?>> fs = new ArrayList<>();
				for (int t = 0; t < THREADS; t++) {
					// the last names are read last into the maps: the widest window
					String name = "name" + (NAMES - 1 - t);
					int r = round;
					fs.add(pool.submit(() -> {
						try {
							start.await();
							if (adapter.getSettingsRecord(1, name) == null) {
								missing.incrementAndGet();
							}
							if ((r & 1) == 0 && !name.equals(adapter.getSettingName(
								adapter.getSettingsRecord(1, name)))) {
								missing.incrementAndGet();
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
		assertEquals("settings reported absent by concurrent first reads", 0, missing.get());
	}

	@Test
	public void testNamesAddedAfterTheFirstReadAreFound() throws Exception {
		assertNotNull(adapter.getSettingsRecord(1, "name0"));
		long tx = dbh.startTransaction();
		adapter.createSettingsRecord(2, "added-later", "v", 0);
		dbh.endTransaction(tx, true);
		assertNotNull(adapter.getSettingsRecord(2, "added-later"));
		adapter.invalidateNameCache();
		assertNotNull(adapter.getSettingsRecord(2, "added-later"));
		assertNull(adapter.getSettingsRecord(1, "never-defined"));
		assertNull(adapter.getSettingsRecord(1, null));
	}
}
