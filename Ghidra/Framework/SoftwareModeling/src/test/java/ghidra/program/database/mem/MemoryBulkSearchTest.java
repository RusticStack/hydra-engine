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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * The bulk {@link MemoryMapDB#findBytes} search ({@link MemoryBulkSearch#bulkFind}) against the
 * former per-address search ({@link MemoryBulkSearch#legacyFind}) on random memory layouts, and
 * the native scanner against the Java scanner. The native part runs when the system property
 * {@code hydra.scan.native.lib} names the built {@code hydra_scan} library (it is skipped, and
 * says so on stderr, otherwise).
 */
public class MemoryBulkSearchTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
	private static final AddressSpace OTHER =
		new GenericAddressSpace("other", 32, AddressSpace.TYPE_RAM, 1);

	/** A memory of blocks; reads cross contiguous blocks like MemoryMapDB.getBytes. */
	static final class FakeMemory implements MemoryBulkSearch.ByteReader {
		final TreeMap<Address, byte[]> blocks = new TreeMap<>();
		final Set<Address> broken = new HashSet<>(); // reads that touch these blocks throw
		boolean stopAtBlockEnd; // reads never cross a block boundary
		final AtomicLong calls = new AtomicLong();

		void add(Address start, byte[] bytes) {
			blocks.put(start, bytes);
		}

		AddressSet all() {
			AddressSet s = new AddressSet();
			for (Map.Entry<Address, byte[]> e : blocks.entrySet()) {
				s.add(e.getKey(), e.getKey().add(e.getValue().length - 1));
			}
			return s;
		}

		@Override
		public int getBytes(Address addr, byte[] dest, int destIndex, int size)
				throws MemoryAccessException {
			calls.incrementAndGet();
			int n = 0;
			Address a = addr;
			while (n < size) {
				Map.Entry<Address, byte[]> e = blocks.floorEntry(a);
				if (e == null || !e.getKey().hasSameAddressSpace(a)) {
					break;
				}
				long off = a.subtract(e.getKey());
				byte[] b = e.getValue();
				if (off >= b.length) {
					break;
				}
				if (broken.contains(e.getKey())) {
					throw new IllegalStateException("broken block " + e.getKey());
				}
				int k = (int) Math.min(size - n, b.length - off);
				System.arraycopy(b, (int) off, dest, destIndex + n, k);
				n += k;
				if (stopAtBlockEnd || n == size) {
					break;
				}
				try {
					a = a.addNoWrap(k);
				}
				catch (AddressOverflowException ex) {
					break;
				}
			}
			if (n == 0 && size > 0) {
				throw new MemoryAccessException("no bytes at " + addr);
			}
			return n;
		}
	}

	private static ByteScanner nativeScanner() {
		String lib = System.getProperty("hydra.scan.native.lib");
		if (lib == null || !Files.isRegularFile(Path.of(lib))) {
			System.err.println("MemoryBulkSearchTest: hydra.scan.native.lib not set, native " +
				"comparisons skipped");
			return null;
		}
		try {
			return NativeByteScanner.load(Path.of(lib));
		}
		catch (Throwable t) {
			throw new AssertionError("native scanner did not load", t);
		}
	}

	private static FakeMemory randomMemory(Random r) {
		FakeMemory m = new FakeMemory();
		int alpha = 1 + r.nextInt(4);
		int nBlocks = 1 + r.nextInt(5);
		long at = r.nextBoolean() ? 0 : r.nextInt(1000);
		for (int i = 0; i < nBlocks; i++) {
			int size = 1 + r.nextInt(r.nextInt(8) == 0 ? 3000 : 60);
			byte[] b = new byte[size];
			for (int j = 0; j < size; j++) {
				b[j] = (byte) r.nextInt(alpha);
			}
			m.add(RAM.getAddress(at), b);
			at += size + (r.nextInt(3) == 0 ? 0 : r.nextInt(20)); // contiguous or a gap
		}
		if (r.nextInt(4) == 0) { // a block that ends at the top of the space
			int size = 1 + r.nextInt(40);
			byte[] b = new byte[size];
			for (int j = 0; j < size; j++) {
				b[j] = (byte) r.nextInt(alpha);
			}
			m.add(RAM.getAddress(0xFFFFFFFFL - size + 1), b);
		}
		if (r.nextInt(3) == 0) { // a second space
			byte[] b = new byte[1 + r.nextInt(50)];
			for (int j = 0; j < b.length; j++) {
				b[j] = (byte) r.nextInt(alpha);
			}
			m.add(OTHER.getAddress(r.nextInt(100)), b);
		}
		if (r.nextInt(6) == 0) {
			List<Address> keys = new ArrayList<>(m.blocks.keySet());
			m.broken.add(keys.get(r.nextInt(keys.size())));
		}
		m.stopAtBlockEnd = r.nextInt(4) == 0;
		return m;
	}

	private static AddressSet searchSet(FakeMemory m, Random r) {
		AddressSet all = m.all();
		if (r.nextInt(3) == 0) {
			// like loaded-and-initialized: some readable bytes are not in the set
			List<Address> keys = new ArrayList<>(m.blocks.keySet());
			Address k = keys.get(r.nextInt(keys.size()));
			all.delete(k, k.add(m.blocks.get(k).length - 1));
		}
		if (r.nextInt(3) == 0 && !all.isEmpty()) {
			Address a = all.getMinAddress().addWrap(r.nextInt(30));
			if (all.contains(a)) {
				all.delete(a, a);
			}
		}
		return all;
	}

	private static byte[] pattern(FakeMemory m, Random r) {
		int len = 1 + r.nextInt(6);
		if (r.nextBoolean()) {
			// cut from memory so matches exist
			List<byte[]> bl = new ArrayList<>(m.blocks.values());
			byte[] b = bl.get(r.nextInt(bl.size()));
			if (b.length >= len) {
				int o = r.nextInt(b.length - len + 1);
				return Arrays.copyOfRange(b, o, o + len);
			}
		}
		byte[] p = new byte[len];
		for (int i = 0; i < len; i++) {
			p[i] = (byte) r.nextInt(3);
		}
		return p;
	}

	private static Address randomAddress(FakeMemory m, Random r) {
		if (r.nextInt(10) == 0) {
			return OTHER.getAddress(r.nextInt(200));
		}
		List<Address> keys = new ArrayList<>(m.blocks.keySet());
		Address k = keys.get(r.nextInt(keys.size()));
		long off = r.nextInt(m.blocks.get(k).length + 30) - 10;
		long o = k.getOffset() + off;
		if (o < 0 || o > k.getAddressSpace().getMaxAddress().getOffset()) {
			o = k.getOffset();
		}
		return k.getAddressSpace().getAddress(o);
	}

	@Test
	public void testBulkFindEqualsLegacyOnRandomLayouts() {
		ByteScanner nat = nativeScanner();
		Random r = new Random(0x5CA45L);
		int compared = 0;
		int found = 0;
		for (int trial = 0; trial < 4000; trial++) {
			FakeMemory m = randomMemory(r);
			AddressSet set = searchSet(m, r);
			byte[] p = pattern(m, r);
			byte[] mask = null;
			if (r.nextInt(3) == 0) {
				mask = new byte[p.length];
				for (int i = 0; i < p.length; i++) {
					mask[i] = new byte[] { (byte) 0xFF, 0x0F, 0x00, (byte) 0xF0, 0x01 }[r.nextInt(5)];
				}
			}
			Address start = randomAddress(m, r);
			Address end = r.nextBoolean() ? null : randomAddress(m, r);
			boolean fwd = r.nextBoolean();
			int chunk = new int[] { 1, 2, 3, 7, 64, MemoryBulkSearch.CHUNK }[r.nextInt(6)];

			Address want = MemoryBulkSearch.legacyFind(set, start, end, p, mask, fwd,
				TaskMonitor.DUMMY, m);
			Address got = MemoryBulkSearch.bulkFind(set, start, end, p, mask, fwd,
				TaskMonitor.DUMMY, m, ByteScanner.JAVA, chunk);
			String ctx = "trial " + trial + " start=" + start + " end=" + end + " fwd=" + fwd +
				" chunk=" + chunk + " pat=" + Arrays.toString(p) + " mask=" +
				Arrays.toString(mask) + " set=" + set;
			assertEquals(ctx, want, got);
			if (nat != null) {
				assertEquals("native " + ctx, want, MemoryBulkSearch.bulkFind(set, start, end, p,
					mask, fwd, TaskMonitor.DUMMY, m, nat, chunk));
			}
			compared++;
			if (want != null) {
				found++;
			}
		}
		assertTrue("too few trials found a match: " + found, found > compared / 4);
	}

	@Test
	public void testBulkFindReadsInChunks() {
		// 1 MB without a match: the per-address search reads once per address, the bulk search
		// once per 64 KB chunk
		FakeMemory m = new FakeMemory();
		byte[] b = new byte[1 << 20];
		m.add(RAM.getAddress(0x1000), b);
		byte[] p = new byte[] { 1, 2, 3, 4 };
		Address got = MemoryBulkSearch.find(m.all(), RAM.getAddress(0), null, p, null, true,
			TaskMonitor.DUMMY, m);
		assertNull(got);
		assertTrue("reads: " + m.calls.get(), m.calls.get() < 64);

		b[0xABCDE] = 1;
		b[0xABCDF] = 2;
		b[0xABCE0] = 3;
		b[0xABCE1] = 4;
		m.calls.set(0);
		assertEquals(RAM.getAddress(0x1000 + 0xABCDE), MemoryBulkSearch.find(m.all(),
			RAM.getAddress(0), null, p, null, true, TaskMonitor.DUMMY, m));
		assertEquals(RAM.getAddress(0x1000 + 0xABCDE), MemoryBulkSearch.find(m.all(),
			RAM.getAddress(0x200000), null, p, null, false, TaskMonitor.DUMMY, m));
		assertTrue("reads: " + m.calls.get(), m.calls.get() < 64);
	}

	@Test
	public void testCancelledMonitorFindsNothing() {
		FakeMemory m = new FakeMemory();
		m.add(RAM.getAddress(0), new byte[] { 1, 2, 3 });
		TaskMonitor cancelled = new ghidra.util.task.TaskMonitorAdapter() {
			@Override
			public boolean isCancelled() {
				return true;
			}
		};
		assertNull(MemoryBulkSearch.bulkFind(m.all(), RAM.getAddress(0), null,
			new byte[] { 2 }, null, true, cancelled, m, ByteScanner.JAVA));
		assertNull(MemoryBulkSearch.legacyFind(m.all(), RAM.getAddress(0), null,
			new byte[] { 2 }, null, true, cancelled, m));
	}

	// ---------------------------------------------------------------------------------------
	// scanner kernels: Java vs native
	// ---------------------------------------------------------------------------------------

	@Test
	public void testJavaFindAgainstNaive() {
		Random r = new Random(7);
		for (int t = 0; t < 5000; t++) {
			int alpha = 1 + r.nextInt(4);
			int plen = 1 + r.nextInt(6);
			int n = plen - 1 + r.nextInt(200);
			byte[] d = new byte[n];
			for (int i = 0; i < n; i++) {
				d[i] = (byte) r.nextInt(alpha);
			}
			byte[] p = new byte[plen];
			for (int i = 0; i < plen; i++) {
				p[i] = (byte) r.nextInt(alpha);
			}
			byte[] mask = r.nextBoolean() ? null : randomMask(r, plen);
			int count = n - plen + 1;
			for (boolean fwd : new boolean[] { true, false }) {
				assertEquals(naiveFind(d, count, p, mask, fwd),
					ByteScanner.JAVA.find(d, count, p, mask, fwd));
			}
		}
	}

	@Test
	public void testNativeFindEqualsJava() {
		ByteScanner nat = nativeScanner();
		if (nat == null) {
			return;
		}
		Random r = new Random(11);
		for (int t = 0; t < 20000; t++) {
			int alpha = 1 + r.nextInt(r.nextBoolean() ? 4 : 256);
			int plen = 1 + r.nextInt(r.nextInt(10) == 0 ? 40 : 6);
			int n = plen - 1 + r.nextInt(r.nextInt(20) == 0 ? 100000 : 300);
			byte[] d = new byte[n];
			for (int i = 0; i < n; i++) {
				d[i] = (byte) r.nextInt(alpha);
			}
			byte[] p = new byte[plen];
			if (n >= plen && r.nextBoolean()) {
				int o = r.nextInt(n - plen + 1);
				System.arraycopy(d, o, p, 0, plen);
			}
			else {
				for (int i = 0; i < plen; i++) {
					p[i] = (byte) r.nextInt(alpha);
				}
			}
			byte[] mask = r.nextBoolean() ? null : randomMask(r, plen);
			int count = Math.max(0, n - plen + 1 - r.nextInt(3));
			for (boolean fwd : new boolean[] { true, false }) {
				assertEquals("t=" + t, ByteScanner.JAVA.find(d, count, p, mask, fwd),
					nat.find(d, count, p, mask, fwd));
			}
		}
	}

	@Test
	public void testNativeFindAllEqualsJava() {
		ByteScanner nat = nativeScanner();
		if (nat == null) {
			return;
		}
		Random r = new Random(13);
		byte[] alphabet = "aAbBzZ\0\u0001".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
		for (int t = 0; t < 3000; t++) {
			int n = r.nextInt(r.nextInt(20) == 0 ? 20000 : 400);
			byte[] d = new byte[n + r.nextInt(5)];
			for (int i = 0; i < d.length; i++) {
				d[i] = alphabet[r.nextInt(alphabet.length)];
			}
			int np = 1 + r.nextInt(r.nextInt(10) == 0 ? 60 : 5);
			byte[][] pats = new byte[np][];
			for (int i = 0; i < np; i++) {
				pats[i] = new byte[1 + r.nextInt(5)];
				for (int j = 0; j < pats[i].length; j++) {
					pats[i][j] = alphabet[r.nextInt(alphabet.length)];
				}
			}
			for (boolean ci : new boolean[] { false, true }) {
				ByteScanner.Matches want = ByteScanner.JAVA.findAll(d, n, pats, ci);
				ByteScanner.Matches got = nat.findAll(d, n, pats, ci);
				assertArrayEquals("t=" + t, want.offsets(), got.offsets());
				assertArrayEquals("t=" + t, want.patterns(), got.patterns());
			}
		}
	}

	/**
	 * Fixture data: the bytes of a real PE file when {@code hydra.scan.fixture} names one (the
	 * KotOR executable copy in measurements), with x86 prologue and string patterns.
	 */
	@Test
	public void testNativeEqualsJavaOnFixture() throws Exception {
		ByteScanner nat = nativeScanner();
		String fx = System.getProperty("hydra.scan.fixture");
		if (nat == null || fx == null || !Files.isRegularFile(Path.of(fx))) {
			System.err.println("MemoryBulkSearchTest: fixture comparison skipped");
			return;
		}
		byte[] d = Files.readAllBytes(Path.of(fx));
		byte[][] pats = { { 0x55, (byte) 0x8B, (byte) 0xEC }, { (byte) 0xCC, (byte) 0xCC },
			"This program".getBytes(), "kernel32".getBytes(), { 0x6A, 0x00 },
			"GetProcAddress".getBytes(), "dll".getBytes() };
		for (byte[] p : pats) {
			for (boolean fwd : new boolean[] { true, false }) {
				int count = d.length - p.length + 1;
				assertEquals(ByteScanner.JAVA.find(d, count, p, null, fwd),
					nat.find(d, count, p, null, fwd));
				byte[] mask = new byte[p.length];
				Arrays.fill(mask, (byte) 0xF0);
				assertEquals(ByteScanner.JAVA.find(d, count, p, mask, fwd),
					nat.find(d, count, p, mask, fwd));
			}
		}
		for (boolean ci : new boolean[] { false, true }) {
			ByteScanner.Matches want = ByteScanner.JAVA.findAll(d, d.length, pats, ci);
			ByteScanner.Matches got = nat.findAll(d, d.length, pats, ci);
			assertTrue(want.size() > 1000);
			assertArrayEquals(want.offsets(), got.offsets());
			assertArrayEquals(want.patterns(), got.patterns());
		}
	}

	private static byte[] randomMask(Random r, int len) {
		byte[] m = new byte[len];
		for (int i = 0; i < len; i++) {
			m[i] = new byte[] { (byte) 0xFF, 0x0F, 0x00, (byte) 0xF0, 0x01 }[r.nextInt(5)];
		}
		return m;
	}

	private static int naiveFind(byte[] d, int count, byte[] p, byte[] mask, boolean fwd) {
		int best = -1;
		for (int k = 0; k < count; k++) {
			boolean ok = true;
			for (int i = 0; i < p.length && ok; i++) {
				int m = mask == null ? 0xFF : mask[i] & 0xFF;
				ok = (d[k + i] & m) == (p[i] & m);
			}
			if (ok) {
				if (fwd) {
					return k;
				}
				best = k;
			}
		}
		return best;
	}
}
