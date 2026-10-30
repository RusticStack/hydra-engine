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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import db.DBHandle;

/**
 * Readers reach {@link CallingConventionDBAdapterV0} under the shared data type manager read
 * lock, so its lazily built cache must be safe for concurrent population. Before the cache was
 * published as one immutable snapshot, a reader arriving while another thread populated the
 * cache could see a non-null name map with a null (or half-filled) id map and fail with a
 * NullPointerException in getCallingConventionName, or get null for a valid id.
 */
public class CallingConventionDBAdapterConcurrencyTest {

	private static final int THREADS =
		Math.max(4, Runtime.getRuntime().availableProcessors());
	private static final int CONVENTIONS = 100;
	private static final long RUN_MILLIS = 3000;

	@Test
	public void testConcurrentReadsAfterInvalidate() throws Exception {
		DBHandle handle = new DBHandle();
		CallingConventionDBAdapterV0 adapter;
		Map<Byte, String> expected = new HashMap<>();
		long tx = handle.startTransaction();
		try {
			adapter = new CallingConventionDBAdapterV0(handle, "", true);
			for (int i = 0; i < CONVENTIONS; i++) {
				String name = "__cc" + i;
				byte id = adapter.getCallingConventionId(name, n -> {
				});
				expected.put(id, name);
			}
		}
		finally {
			handle.endTransaction(tx, true);
		}
		assertEquals(CONVENTIONS, expected.size());
		Byte[] ids = expected.keySet().toArray(new Byte[0]);

		// Readers run continuously while the main thread keeps invalidating the cache, so
		// lookups keep landing while some other reader is populating it.
		AtomicReference<Throwable> failure = new AtomicReference<>();
		AtomicBoolean stop = new AtomicBoolean();
		List<Thread> readers = new ArrayList<>();
		for (int t = 0; t < THREADS; t++) {
			int offset = t;
			Thread r = new Thread(() -> {
				try {
					for (int k = offset; !stop.get(); k++) {
						byte id = ids[k % ids.length];
						String name = adapter.getCallingConventionName(id);
						if (!expected.get(id).equals(name)) {
							throw new AssertionError(
								"id " + id + " gave " + name + ", expected " + expected.get(id));
						}
					}
				}
				catch (Throwable e) {
					failure.compareAndSet(null, e);
				}
			});
			r.setDaemon(true);
			readers.add(r);
			r.start();
		}
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(RUN_MILLIS);
		while (System.nanoTime() < end && failure.get() == null) {
			adapter.invalidateCache();
			Thread.onSpinWait();
		}
		stop.set(true);
		for (Thread r : readers) {
			r.join(10_000);
		}
		handle.close();
		if (failure.get() != null) {
			throw new AssertionError("concurrent calling convention lookup failed",
				failure.get());
		}
	}

	@Test
	public void testAddAfterReadsKeepsAllNames() throws Exception {
		DBHandle handle = new DBHandle();
		long tx = handle.startTransaction();
		try {
			CallingConventionDBAdapterV0 adapter = new CallingConventionDBAdapterV0(handle, "", true);
			byte a = adapter.getCallingConventionId("__a", n -> {
			});
			assertEquals("__a", adapter.getCallingConventionName(a));
			List<String> added = new ArrayList<>();
			byte b = adapter.getCallingConventionId("__b", added::add);
			assertNotEquals(a, b);
			assertEquals(List.of("__b"), added);
			assertEquals(b, adapter.getCallingConventionId("__b", added::add));
			assertEquals(1, added.size());
			assertEquals(Set.of("__a", "__b"), new HashSet<>(adapter.getCallingConventionNames()));
			adapter.invalidateCache();
			assertEquals("__b", adapter.getCallingConventionName(b));
			assertEquals((byte) (b + 1), adapter.getCallingConventionId("__c", n -> {
			}));
		}
		finally {
			handle.endTransaction(tx, true);
			handle.close();
		}
	}
}
