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
package db.buffers;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

/**
 * {@link SharedPages}: views of the same stored database share one copy of each clean page, and
 * a change in one view (copy-on-write) is never seen by another.
 */
public class SharedPagesTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 1024;
	private static final int COUNT = 100; // more than the 64 buffers of the smallest cache

	private File testDir;
	private File file;
	private final List<BufferMgr> mgrs = new ArrayList<>();
	private final Random random = new Random(7);
	private byte[][] content;
	private boolean wasEnabled;

	@Before
	public void setUp() throws Exception {
		wasEnabled = SharedPages.isEnabled();
		SharedPages.setEnabled(true);
		testDir = createTempDirectory(getClass().getSimpleName());
		BufferMgr mgr = new BufferMgr(BUFFER_SIZE, 64 * 1024, 10);
		content = new byte[COUNT][];
		for (int i = 0; i < COUNT; i++) {
			DataBuffer buf = mgr.createBuffer();
			assertEquals(i, buf.getId());
			byte[] b = new byte[mgr.getBufferSize()];
			random.nextBytes(b);
			b[0] = (byte) i;
			content[i] = b;
			buf.put(0, b);
			mgr.releaseBuffer(buf);
		}
		file = new File(testDir, "base.bf");
		mgr.saveAs(new LocalBufferFile(file, mgr.getBufferSize()), true, null);
		mgr.dispose();
	}

	@After
	public void tearDown() throws Exception {
		for (BufferMgr m : mgrs) {
			m.dispose();
		}
		SharedPages.setEnabled(wasEnabled);
		FileUtilities.deleteDir(testDir);
	}

	/** A view: a read-only open of the stored file, as an overlay's program object is. */
	private BufferMgr view() throws IOException {
		BufferMgr m = new BufferMgr(new LocalBufferFile(file, true));
		mgrs.add(m);
		return m;
	}

	private byte[] array(BufferMgr m, int id) throws IOException {
		DataBuffer buf = m.getBuffer(id);
		try {
			return buf.getData();
		}
		finally {
			m.releaseBuffer(buf);
		}
	}

	private byte[] bytes(BufferMgr m, int id) throws IOException {
		DataBuffer buf = m.getBuffer(id);
		try {
			return buf.get(0, buf.length());
		}
		finally {
			m.releaseBuffer(buf);
		}
	}

	@Test
	public void testViewsShareOneCopyOfEachPage() throws IOException {
		readAll(view()); // the first reader keeps private pages; the second publishes them
		BufferMgr a = view();
		BufferMgr b = view();
		BufferMgr c = view();
		long hits0 = SharedPages.hits();
		for (int i = 0; i < COUNT; i++) {
			byte[] pa = array(a, i);
			assertArrayEquals(content[i], pa);
			assertSame("page " + i + " is one array for every view", pa, array(b, i));
			assertSame(pa, array(c, i));
		}
		assertTrue(SharedPages.hits() - hits0 >= 2 * COUNT);
	}

	@Test
	public void testChangeInOneViewIsNotSeenByAnother() throws IOException {
		readAll(view());
		BufferMgr a = view();
		BufferMgr b = view();
		for (int i = 0; i < COUNT; i++) {
			assertSame(array(a, i), array(b, i));
		}
		// change pages 3 and 17 in a (one checkpoint, as a program transaction does)
		for (int id : new int[] { 3, 17 }) {
			DataBuffer buf = a.getBuffer(id);
			buf.putInt(0, 0x11223344);
			buf.putLong(100, -1L);
			buf.put(200, new byte[] { 9, 9, 9 });
			a.releaseBuffer(buf);
		}
		assertTrue(a.checkpoint());
		for (int i = 0; i < COUNT; i++) {
			assertArrayEquals("view b and the file are unchanged, page " + i, content[i], bytes(b, i));
			BufferMgr fresh = view();
			assertArrayEquals(content[i], bytes(fresh, i));
		}
		byte[] changed = bytes(a, 3);
		assertEquals(0x11223344, java.nio.ByteBuffer.wrap(changed).getInt(0));
		assertFalse(Arrays.equals(content[3], changed));
		assertArrayEquals(content[4], bytes(a, 4));
		// undo in a brings the stored page back
		assertTrue(a.undo(false));
		assertArrayEquals(content[3], bytes(a, 3));
		assertArrayEquals(content[17], bytes(a, 17));
	}

	private void readAll(BufferMgr m) throws IOException {
		for (int i = 0; i < COUNT; i++) {
			assertArrayEquals(content[i], bytes(m, i));
		}
	}

	private boolean isShared(BufferMgr m, int id) throws IOException {
		DataBuffer buf = m.getBuffer(id);
		try {
			return buf.isShared();
		}
		finally {
			m.releaseBuffer(buf);
		}
	}

	/**
	 * A page that only one view reads (also after eviction and reload) stays private: no
	 * copy-on-write on its first change and no fresh array when its buffer is recycled. The second
	 * view to read it publishes it and the third takes the published copy.
	 */
	@Test
	public void testSingleReaderKeepsPagesPrivate() throws Exception {
		// content no other test used, so no page published by an earlier test can match
		BufferMgr mgr = new BufferMgr(BUFFER_SIZE, 64 * 1024, 10);
		Random r = new Random(System.nanoTime());
		for (int i = 0; i < COUNT; i++) {
			DataBuffer buf = mgr.createBuffer();
			byte[] b = new byte[mgr.getBufferSize()];
			r.nextBytes(b);
			buf.put(0, b);
			mgr.releaseBuffer(buf);
		}
		File own = new File(testDir, "single.bf");
		mgr.saveAs(new LocalBufferFile(own, mgr.getBufferSize()), true, null);
		mgr.dispose();

		BufferMgr a = new BufferMgr(new LocalBufferFile(own, true), 4 * BUFFER_SIZE, 10);
		mgrs.add(a);
		for (int round = 0; round < 2; round++) { // the small cache evicts: the 2nd round reloads
			for (int i = 0; i < COUNT; i++) {
				assertFalse("single reader, page " + i + " round " + round, isShared(a, i));
			}
		}
		BufferMgr b = new BufferMgr(new LocalBufferFile(own, true));
		mgrs.add(b);
		BufferMgr c = new BufferMgr(new LocalBufferFile(own, true));
		mgrs.add(c);
		long hits0 = SharedPages.hits();
		for (int i = 0; i < COUNT; i++) {
			byte[] pb = array(b, i);
			assertSame("page " + i, pb, array(c, i));
			assertTrue(isShared(b, i));
		}
		assertTrue(SharedPages.hits() - hits0 >= COUNT);
	}

	@Test
	public void testEvictionAndReloadKeepContent() throws IOException {
		// the smallest cache (64 KB: 64 buffers) holds fewer pages than there are: reads evict, and a
		// recycled buffer must never write a shared page
		List<BufferMgr> small = new ArrayList<>();
		for (int v = 0; v < 3; v++) {
			BufferMgr m = new BufferMgr(new LocalBufferFile(file, true), 4 * BUFFER_SIZE, 10);
			mgrs.add(m);
			small.add(m);
		}
		for (int round = 0; round < 3; round++) {
			for (int i = 0; i < COUNT; i++) {
				for (BufferMgr m : small) {
					assertArrayEquals(content[i], bytes(m, i));
				}
			}
			// change something in view 0 and read everything again in every view
			BufferMgr m0 = small.get(0);
			DataBuffer buf = m0.getBuffer(round);
			buf.putByte(5, (byte) 0x5a);
			m0.releaseBuffer(buf);
			assertTrue(m0.checkpoint());
			assertEquals(0x5a, bytes(m0, round)[5]);
			for (int i = 0; i < COUNT; i++) {
				if (i != round) {
					assertArrayEquals(content[i], bytes(m0, i));
				}
			}
			assertEquals(0x5a, bytes(m0, round)[5]);
			assertTrue(m0.undo(false));
		}
		for (int i = 0; i < COUNT; i++) {
			for (BufferMgr m : small) {
				assertArrayEquals(content[i], bytes(m, i));
			}
		}
	}

	@Test
	public void testDisabledKeepsPagesPrivate() throws IOException {
		SharedPages.setEnabled(false);
		BufferMgr a = view();
		BufferMgr b = view();
		for (int i = 0; i < COUNT; i++) {
			byte[] pa = array(a, i);
			byte[] pb = array(b, i);
			assertNotSame(pa, pb);
			assertArrayEquals(pa, pb);
		}
	}

	@Test
	public void testDataBufferCopyOnWrite() {
		byte[] page = new byte[64];
		Arrays.fill(page, (byte) 7);
		DataBuffer x = new DataBuffer(64);
		DataBuffer y = new DataBuffer(64);
		x.shareData(page);
		y.shareData(page);
		x.putInt(0, 42);
		x.putShort(8, (short) 1);
		x.putLong(16, 3);
		x.putByte(30, (byte) 1);
		x.put(40, new byte[] { 1, 2 });
		x.move(40, 50, 2);
		y.clear();
		DataBuffer z = new DataBuffer(64);
		z.shareData(page);
		z.copy(0, x, 0, 4);
		for (byte b : page) {
			assertEquals("the shared page is never written", 7, b);
		}
		assertEquals(42, x.getInt(0));
		assertEquals(0, y.getByte(3));
		assertEquals(42, z.getInt(0));
		assertFalse(x.isShared());
		DataBuffer w = new DataBuffer(64);
		w.shareData(page);
		w.unshareForOverwrite(null);
		assertNotSame(page, w.getData());
	}
}
