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

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;

import org.junit.*;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.*;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.task.TaskMonitor;

/**
 * Key encodings and key ranges of {@link AddressMapDB} without a program. The key range checks
 * compare with a direct computation over the known base segments, so they cover the
 * match-or-next and match-or-previous lookups used when a range spans several bases.
 */
public class AddressMapDBKeysTest {

	private static final long SEGMENT_MASK = 0xffffffffL;
	private static final long IMAGE_BASE = 0x1000000000L;

	private DBHandle handle;
	private long txId;
	private AddressSpace ram;
	private AddressFactory factory;

	@BeforeClass
	public static void initializeIds() {
		UniversalIdGenerator.initialize();
	}

	@Before
	public void setUp() throws Exception {
		ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
		factory = new DefaultAddressFactory(new AddressSpace[] { ram });
		handle = new DBHandle();
		txId = handle.startTransaction();
	}

	@After
	public void tearDown() throws Exception {
		handle.endTransaction(txId, true);
		handle.close();
	}

	private AddressMapDB createMap(OpenMode mode, long imageBase) throws Exception {
		return new AddressMapDB(handle, mode, factory, imageBase, TaskMonitor.DUMMY);
	}

	private Address addr(long offset) {
		return ram.getAddress(offset);
	}

	/**
	 * Same blocks as AddressMapDB64BitTest: the memory map creates the bases of a block with
	 * getKeyRanges(set, true) and then the key of its start.
	 */
	private AddressMapDB createMapWithBlocks() throws Exception {
		AddressMapDB map = createMap(OpenMode.CREATE, IMAGE_BASE);
		addBlock(map, 0x2000000000L, 0x100000);
		addBlock(map, 0xfffffffffff00000L, 0x100000);
		addBlock(map, 0x7ffffffffff00000L, 0x200000);
		return map;
	}

	private void addBlock(AddressMapDB map, long start, long length) {
		map.getKeyRanges(new AddressSet(addr(start), addr(start + length - 1)), true);
		map.getKey(addr(start), true);
	}

	@Test
	public void testKeyRangesOfBlocks() throws Exception {
		AddressMapDB map = createMapWithBlocks();
		List<KeyRange> keyRanges = map.getKeyRanges(addr(0), addr(0xffffffffffffffffL), false);
		assertEquals(4, keyRanges.size());
		assertRange(map, keyRanges.get(0), 0x2000000000L, 0x20ffffffffL);
		assertRange(map, keyRanges.get(1), 0x7fffffff00000000L, 0x7fffffffffffffffL);
		assertRange(map, keyRanges.get(2), 0x8000000000000000L, 0x80000000ffffffffL);
		assertRange(map, keyRanges.get(3), 0xffffffff00000000L, 0xffffffffffffffffL);
	}

	private void assertRange(AddressMapDB map, KeyRange kr, long min, long max) {
		assertEquals(addr(min), map.decodeAddress(kr.minKey));
		assertEquals(addr(max), map.decodeAddress(kr.maxKey));
	}

	@Test
	public void testRelocatableKeys() throws Exception {
		AddressMapDB map = createMapWithBlocks();
		Address a = addr(0x1000000000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getKey(a, false));
		long key = map.getKey(a, true);
		assertEquals(0x2000000400000000L, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x2000001000L);
		key = map.getKey(a, false);
		assertEquals(0x2000000000000000L + 0x1000, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x7ffffffffff00000L);
		key = map.getKey(a, false);
		assertEquals(0x2000000200000000L + 0x0fff00000L, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x8ffffffffff00000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getKey(a, false));
		key = map.getKey(a, true);
		assertEquals(0x2000000500000000L + 0x0fff00000L, key);
		assertEquals(a, map.decodeAddress(key));
	}

	@Test
	public void testAbsoluteKeys() throws Exception {
		AddressMapDB map = createMapWithBlocks();
		Address a = addr(0x1000000000L);
		long key = map.getAbsoluteEncoding(a, false);
		assertEquals(0x1000000000000000L, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x2000001000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getAbsoluteEncoding(a, false));
		key = map.getAbsoluteEncoding(a, true);
		assertEquals(0x1000000400000000L + 0x1000, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x7fffffeffff00000L);
		key = map.getAbsoluteEncoding(a, false);
		assertEquals(0x1000000200000000L + 0x0fff00000L, key);
		assertEquals(a, map.decodeAddress(key));

		a = addr(0x8ffffffffff00000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getAbsoluteEncoding(a, false));
		key = map.getAbsoluteEncoding(a, true);
		assertEquals(0x1000000500000000L + 0x0fff00000L, key);
		assertEquals(a, map.decodeAddress(key));
	}

	@Test
	public void testKeyRangesAcrossBases() throws Exception {
		long[] segments = { 0x0L, 0x5L, 0x6L, 0x1234L, 0x7fffffffL, 0x80000000L, 0xffffffffL };
		for (long imageBase : new long[] { 0, IMAGE_BASE }) {
			tearDown();
			setUp();
			AddressMapDB map = createMap(OpenMode.CREATE, imageBase);
			// bases are normalized: created in shuffled order so their indexes are not sorted
			List<Long> order = new ArrayList<>();
			for (long segment : segments) {
				order.add(segment);
			}
			Collections.shuffle(order, new Random(imageBase));
			for (long segment : order) {
				assertNotEquals(AddressMap.INVALID_ADDRESS_KEY,
					map.getAbsoluteEncoding(addr(segment << 32), true));
			}
			Random random = new Random(7);
			for (int i = 0; i < 2000; i++) {
				long s = randomOffset(random, segments);
				long e = randomOffset(random, segments);
				if (Long.compareUnsigned(s, e) > 0) {
					long t = s;
					s = e;
					e = t;
				}
				String what = "[" + Long.toHexString(s) + "," + Long.toHexString(e) +
					"] image base " + Long.toHexString(imageBase);
				assertEquals("absolute " + what, expectedRanges(map, segments, s, e, 0, true),
					toList(map.getKeyRanges(addr(s), addr(e), true, false)));
				assertEquals("relative " + what,
					expectedRanges(map, segments, s, e, imageBase, false),
					toList(map.getKeyRanges(addr(s), addr(e), false, false)));
			}
		}
	}

	private static long randomOffset(Random random, long[] segments) {
		long segment = random.nextInt(4) == 0 ? random.nextInt() & SEGMENT_MASK
				: segments[random.nextInt(segments.length)] + random.nextInt(3) - 1;
		long offset;
		switch (random.nextInt(3)) {
			case 0:
				offset = 0;
				break;
			case 1:
				offset = SEGMENT_MASK;
				break;
			default:
				offset = random.nextInt() & SEGMENT_MASK;
		}
		return (segment << 32) | offset;
	}

	/**
	 * Key ranges computed directly: the normalized range (split where it wraps) intersected with
	 * each base segment, in address order.
	 */
	private List<List<Long>> expectedRanges(AddressMapDB map, long[] segments, long start,
			long end, long imageBase, boolean absolute) {
		long ns = start - imageBase;
		long ne = end - imageBase;
		List<long[]> parts = new ArrayList<>();
		if (Long.compareUnsigned(ns, ne) > 0) {
			parts.add(new long[] { ns, -1L });
			parts.add(new long[] { 0, ne });
		}
		else {
			parts.add(new long[] { ns, ne });
		}
		List<List<Long>> ranges = new ArrayList<>();
		for (long[] part : parts) {
			for (long segment : segments) {
				long baseStart = segment << 32;
				long baseEnd = baseStart | SEGMENT_MASK;
				long lo = Long.compareUnsigned(part[0], baseStart) > 0 ? part[0] : baseStart;
				long hi = Long.compareUnsigned(part[1], baseEnd) < 0 ? part[1] : baseEnd;
				if (Long.compareUnsigned(lo, hi) > 0) {
					continue;
				}
				long prefix = absolute ? map.getAbsoluteEncoding(addr(baseStart), false)
						: map.getKey(addr(baseStart + imageBase), false);
				prefix &= AddressMapDB.BASE_MASK;
				ranges.add(List.of(prefix | (lo & SEGMENT_MASK), prefix | (hi & SEGMENT_MASK)));
			}
		}
		return ranges;
	}

	private static List<List<Long>> toList(List<KeyRange> keyRanges) {
		List<List<Long>> list = new ArrayList<>();
		for (KeyRange kr : keyRanges) {
			list.add(List.of(kr.minKey, kr.maxKey));
		}
		return list;
	}

	@Test
	public void testReadOnlyMapCreatesBasesWithoutWriting() throws Exception {
		AddressMapDB map = createMap(OpenMode.CREATE, 0);
		Address a = addr(0x3_0000_1000L);
		long ka = map.getKey(a, true);

		AddressMapDB readOnly = createMap(OpenMode.IMMUTABLE, 0);
		assertEquals(ka, readOnly.getKey(a, false));
		Address b = addr(0x9_0000_0020L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, readOnly.getKey(b, false));
		long kb = readOnly.getKey(b, true);
		assertEquals(ka + (1L << 32) - 0x1000 + 0x20, kb);
		assertEquals(b, readOnly.decodeAddress(kb));
		assertEquals(kb, readOnly.getKey(b, false));

		// the base exists only in the read-only map
		map.invalidateCache();
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getKey(b, false));
	}

	@Test
	public void testFailedBaseAddDoesNotReturnAKey() throws Exception {
		AddressMapDB map = createMap(OpenMode.CREATE, 0);
		Address a = addr(0x3_0000_1000L);
		long ka = map.getKey(a, true);
		setAdapter(map, new FailingAddAdapter(getAdapter(map)));

		Address b = addr(0x9_0000_0020L);
		try {
			long kb = map.getKey(b, true);
			fail("Expected a failure, got key " + Long.toHexString(kb));
		}
		catch (RuntimeException e) {
			// expected: the base could not be stored
		}
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, map.getKey(b, false));
		assertEquals(ka, map.getKey(a, false));
		assertEquals(a, map.decodeAddress(ka));
	}

	private static AddressMapDBAdapter getAdapter(AddressMapDB map) throws Exception {
		Field f = AddressMapDB.class.getDeclaredField("adapter");
		f.setAccessible(true);
		return (AddressMapDBAdapter) f.get(map);
	}

	private static void setAdapter(AddressMapDB map, AddressMapDBAdapter adapter)
			throws Exception {
		Field f = AddressMapDB.class.getDeclaredField("adapter");
		f.setAccessible(true);
		f.set(map, adapter);
	}

	/**
	 * An adapter whose table write fails: like AddressMapDBAdapterV1 on an IOException, it
	 * returns the bases unchanged.
	 */
	private static class FailingAddAdapter extends AddressMapDBAdapter {
		private final AddressMapDBAdapter delegate;

		FailingAddAdapter(AddressMapDBAdapter delegate) {
			this.delegate = delegate;
		}

		@Override
		void deleteTable() throws IOException {
			delegate.deleteTable();
		}

		@Override
		Address[] addBaseAddress(Address addr, long normalizedOffset) {
			try {
				return delegate.getBaseAddresses(false);
			}
			catch (IOException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		Address[] getBaseAddresses(boolean forceRead) throws IOException {
			return delegate.getBaseAddresses(forceRead);
		}

		@Override
		List<AddressMapEntry> getEntries() throws IOException {
			return delegate.getEntries();
		}

		@Override
		void setEntries(List<AddressMapEntry> entries) throws IOException {
			delegate.setEntries(entries);
		}

		@Override
		void clearAll() throws IOException {
			delegate.clearAll();
		}

		@Override
		void setAddressFactory(AddressFactory addrFactory) {
			delegate.setAddressFactory(addrFactory);
		}

		@Override
		void renameOverlaySpace(String oldName, String newName) throws IOException {
			delegate.renameOverlaySpace(oldName, newName);
		}

		@Override
		void deleteOverlaySpace(String name) throws IOException {
			delegate.deleteOverlaySpace(name);
		}
	}
}
