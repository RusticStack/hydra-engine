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
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

/**
 * Hydra H3: the pre-save copies the buffer file in chunks. The copy must be byte for byte the one
 * the original get/put loop wrote, and it must make progress while the primary file is read.
 */
public class PreSaveBulkCopyTest extends AbstractGenericTest {

	/** A real database's buffer size: 16 KiB blocks. */
	private static final int BUFFER_SIZE = 16384 - 5;

	private File testDir = new File(getTestDirectoryPath(), "PreSaveBulkCopyTest");

	@Before
	public void setUp() throws Exception {
		FileUtilities.deleteDir(testDir);
		testDir.mkdirs();
	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testDir);
	}

	private class Mgr implements BufferFileManager {
		int currentVersion = 0;

		@Override
		public File getBufferFile(int version) {
			return new File(testDir, "db." + version + ".gbf");
		}

		@Override
		public File getChangeDataFile(int version) {
			return null;
		}

		@Override
		public File getChangeMapFile() {
			return null;
		}

		@Override
		public int getCurrentVersion() {
			return currentVersion;
		}

		@Override
		public File getVersionFile(int version) {
			return null;
		}

		@Override
		public void updateEnded(long checkinId) {
			// nothing
		}

		@Override
		public void versionCreated(int version, String comment, long checkinId) {
			currentVersion = version;
		}
	}

	/**
	 * Write {@code count} buffers: random data, every 7th one empty with a buffer id, and every
	 * 5th one written with data and then freed, so that its block keeps stale data behind an
	 * empty prefix. The last buffer is not empty.
	 */
	private static void fill(LocalBufferFile bf, int count, long seed) throws IOException {
		Random r = new Random(seed);
		List<Integer> free = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			DataBuffer buf = new DataBuffer(BUFFER_SIZE);
			buf.setId(i);
			r.nextBytes(buf.data);
			if (i % 7 == 3 && i != count - 1) {
				buf.setEmpty(true);
			}
			bf.put(buf, i);
			if (i % 5 == 2 && i != count - 1) {
				free.add(i);
			}
		}
		int[] f = new int[free.size()];
		for (int i = 0; i < f.length; i++) {
			f[i] = free.get(i);
		}
		bf.setFreeIndexes(f);
		bf.setParameter("p", 42);
	}

	/** The original pre-save: one get/put per buffer. */
	private static void legacyCopy(LocalBufferFile src, LocalBufferFile dst) throws IOException {
		DataBuffer buf = new DataBuffer(src.getBufferSize());
		int cnt = src.getIndexCount();
		for (int i = 0; i < cnt; i++) {
			src.get(buf, i);
			dst.put(buf, i);
		}
	}

	@Test
	public void testChunkCopyIsByteIdenticalToBufferCopy() throws Exception {
		File srcFile = new File(testDir, "src.gbf");
		LocalBufferFile w = new LocalBufferFile(srcFile, BUFFER_SIZE);
		fill(w, 203, 1);
		w.close();

		for (int chunkBuffers : new int[] { 1, 7, 64, 203, 500 }) {
			LocalBufferFile src = new LocalBufferFile(srcFile, true);
			// stale data behind the empty prefixes of the freed blocks must not be copied
			File a = new File(testDir, "a" + chunkBuffers + ".gbf");
			File b = new File(testDir, "b" + chunkBuffers + ".gbf");
			LocalBufferFile da = new LocalBufferFile(a, BUFFER_SIZE);
			LocalBufferFile db = new LocalBufferFile(b, BUFFER_SIZE);
			legacyCopy(src, da);
			ByteBuffer chunk = ByteBuffer.allocateDirect(chunkBuffers * (BUFFER_SIZE + 5));
			int cnt = src.getIndexCount();
			for (int i = 0; i < cnt; i += chunkBuffers) {
				db.copyBuffersFrom(src, i, Math.min(chunkBuffers, cnt - i), chunk);
			}
			assertEquals(da.getIndexCount(), db.getIndexCount());
			// what the save then adds: the same id, free list and parameters
			db.setFileId(da.getFileId());
			for (LocalBufferFile d : new LocalBufferFile[] { da, db }) {
				d.setFreeIndexes(src.getFreeIndexes());
				d.setParameter("p", 42);
			}
			da.close();
			db.close();
			src.close();
			assertArrayEquals("chunk of " + chunkBuffers + " buffers", Files.readAllBytes(a.toPath()),
				Files.readAllBytes(b.toPath()));
		}
		// and the stale data was really there to be dropped
		byte[] s = Files.readAllBytes(srcFile.toPath());
		byte[] c = Files.readAllBytes(new File(testDir, "a7.gbf").toPath());
		assertEquals(s.length, c.length);
		assertFalse(Arrays.equals(s, c));
	}

	/**
	 * The original pre-save waited for 50 ms without a read of the primary file before each
	 * buffer, so a primary file read without pause kept it from copying anything: the save that
	 * followed did all the copy while it waited. The pre-save must complete while the program is
	 * read.
	 */
	@Test(timeout = 120_000)
	public void testPreSaveProgressesWhilePrimaryIsRead() throws Exception {
		Mgr mgr = new Mgr();
		int count = 256; // 4 MiB, 4 chunks
		LocalManagedBufferFile v1 = new LocalManagedBufferFile(BUFFER_SIZE, mgr, -1);
		fill(v1, count, 2);
		v1.close();
		assertEquals(1, mgr.getCurrentVersion());

		LocalManagedBufferFile primary = new LocalManagedBufferFile(mgr, true, -1, -1);
		boolean saved = false;
		try {
			saved = progressThenSave(mgr, primary, count);
		}
		finally {
			if (!saved) {
				// leave nothing open that would stop the next test's setUp from clearing testDir
				primary.dispose();
			}
		}
	}

	private boolean progressThenSave(Mgr mgr, LocalManagedBufferFile primary, int count)
			throws Exception {
		AtomicBoolean stop = new AtomicBoolean();
		AtomicReference<Throwable> err = new AtomicReference<>();
		Thread reader = new Thread(() -> {
			DataBuffer buf = new DataBuffer(BUFFER_SIZE);
			int i = 0;
			try {
				while (!stop.get()) {
					primary.get(buf, i);
					i = (i + 1) % count;
				}
			}
			catch (Throwable t) {
				err.set(t);
			}
		}, "reader");
		reader.start();
		long expected = (long) (count + 1) * (BUFFER_SIZE + 5);
		// The original copy makes no progress at all while the primary file is read without
		// pause (0 bytes, however long); the bound is generous so a machine loaded with other
		// agents' work does not fail the test.
		long deadline = System.nanoTime() + 60_000_000_000L;
		File ps = null;
		try {
			while (System.nanoTime() < deadline) {
				ps = findPreSave();
				if (ps != null && size(ps) >= expected) {
					break;
				}
				Thread.sleep(20);
			}
		}
		finally {
			stop.set(true);
			reader.join();
		}
		assertNull(err.get());
		assertNotNull("no pre-save file", ps);
		long done = size(ps);
		if (done < expected) {
			StringBuilder sb = new StringBuilder();
			for (Map.Entry<Thread, StackTraceElement[]> t : Thread.getAllStackTraces().entrySet()) {
				if (t.getKey().getName().equals("Pre-Save")) {
					sb.append(t.getKey()).append(" ").append(t.getKey().getState()).append('\n');
					for (StackTraceElement el : t.getValue()) {
						sb.append("  ").append(el).append('\n');
					}
				}
			}
			for (File f : testDir.listFiles()) {
				sb.append(f.getName()).append(' ').append(size(f)).append('\n');
			}
			System.err.println("DEBUG " + ps + "\n" + sb);
		}
		assertTrue("pre-save made no progress while the primary file was read: " + done + " of " +
			expected + " bytes in 60 s", done >= expected);

		// the save takes the copy and commits a version equal to the first
		LocalManagedBufferFile save = primary.getSaveFile(null);
		assertNotNull(save);
		assertEquals(primary.getIndexCount(), save.getIndexCount());
		save.setFreeIndexes(primary.getFreeIndexes());
		save.setParameter("p", 42);
		primary.saveCompleted(true);
		primary.dispose();
		save.close();
		assertEquals(2, mgr.getCurrentVersion());
		verifySameContents(mgr);
		return true;
	}

	private static void verifySameContents(Mgr mgr) throws IOException {

		LocalBufferFile f1 = new LocalBufferFile(mgr.getBufferFile(1), true);
		LocalBufferFile f2 = new LocalBufferFile(mgr.getBufferFile(2), true);
		try {
			assertEquals(f1.getIndexCount(), f2.getIndexCount());
			assertArrayEquals(f1.getFreeIndexes(), f2.getFreeIndexes());
			DataBuffer b1 = new DataBuffer(BUFFER_SIZE);
			DataBuffer b2 = new DataBuffer(BUFFER_SIZE);
			for (int i = 0; i < f1.getIndexCount(); i++) {
				f1.get(b1, i);
				f2.get(b2, i);
				assertEquals(b1.isEmpty(), b2.isEmpty());
				if (!b1.isEmpty()) {
					assertEquals(b1.getId(), b2.getId());
					assertArrayEquals(b1.data, b2.data);
				}
			}
		}
		finally {
			f1.close();
			f2.close();
		}
	}

	/** A saver that waits gets the copy at once: no initial delay, no back-off. */
	@Test(timeout = 120_000)
	public void testSaveRightAfterOpen() throws Exception {
		Mgr mgr = new Mgr();
		LocalManagedBufferFile v1 = new LocalManagedBufferFile(BUFFER_SIZE, mgr, -1);
		fill(v1, 64, 3);
		v1.close();
		// as BufferMgr.save does: the save file becomes the source of the next save
		LocalManagedBufferFile primary = new LocalManagedBufferFile(mgr, true, -1, -1);
		try {
			for (int round = 0; round < 3; round++) {
				long t0 = System.nanoTime();
				LocalManagedBufferFile save = primary.getSaveFile(null);
				long ms = (System.nanoTime() - t0) / 1_000_000L;
				assertNotNull(save);
				// generous: a loaded machine must not fail it; a stuck pre-save still does
				assertTrue("save waited " + ms + " ms for the pre-save", ms < 30_000);
				save.setFreeIndexes(primary.getFreeIndexes());
				save.setParameter("p", 42);
				primary.saveCompleted(true);
				primary.dispose();
				primary = save;
			}
		}
		finally {
			primary.close();
		}
		assertEquals(4, mgr.getCurrentVersion());
		assertNull("pre-save files left behind", findPreSave());
	}

	/**
	 * Closing a program while its pre-save copies is a cancel, not an error. The chunk copy uses
	 * FileChannel I/O, which the cancel's interrupt ends with ClosedByInterruptException; the
	 * per-buffer copy only ever saw InterruptedException. The hook holds the copy just before a
	 * chunk until the interrupt is pending, so the channel I/O always sees it.
	 */
	@Test(timeout = 120_000)
	public void testCloseDuringChunkCopyIsSilent() throws Exception {
		Mgr mgr = new Mgr();
		LocalManagedBufferFile v1 = new LocalManagedBufferFile(BUFFER_SIZE, mgr, -1);
		fill(v1, 256, 4);
		v1.close();

		List<String> errors = Collections.synchronizedList(new ArrayList<>());
		ghidra.util.Msg.setErrorLogger(new ghidra.util.DefaultErrorLogger() {
			@Override
			public void error(Object originator, Object message) {
				errors.add(String.valueOf(message));
				super.error(originator, message);
			}

			@Override
			public void error(Object originator, Object message, Throwable throwable) {
				errors.add(message + " " + throwable);
				super.error(originator, message, throwable);
			}
		});
		java.util.concurrent.CountDownLatch inChunk = new java.util.concurrent.CountDownLatch(1);
		java.util.concurrent.atomic.AtomicInteger chunks =
			new java.util.concurrent.atomic.AtomicInteger();
		LocalManagedBufferFile.preSaveChunkHook = () -> {
			if (chunks.incrementAndGet() < 2) {
				return; // let one chunk through, so the copy is under way
			}
			inChunk.countDown();
			long end = System.nanoTime() + 60_000_000_000L;
			while (!Thread.currentThread().isInterrupted() && System.nanoTime() < end) {
				Thread.onSpinWait();
			}
		};
		try {
			// the hook runs only in the chunk copy (-Dhydra.presave.bulk=false turns it off)
			Assume.assumeTrue(LocalManagedBufferFile.BULK_PRESAVE);
			LocalManagedBufferFile primary = new LocalManagedBufferFile(mgr, true, -1, -1);
			try {
				assertTrue("pre-save never reached its second chunk",
					inChunk.await(60, java.util.concurrent.TimeUnit.SECONDS));
			}
			finally {
				primary.close(); // cancels the pre-save: interrupt, then join
			}
			assertEquals("errors logged by the cancel: " + errors, 0, errors.size());
			assertNull("pre-save files left behind", findPreSave());
			assertEquals(1, mgr.getCurrentVersion());
			verifySameContentsAsWritten(mgr);
		}
		finally {
			LocalManagedBufferFile.preSaveChunkHook = null;
			ghidra.util.Msg.setErrorLogger(new ghidra.util.DefaultErrorLogger());
		}
	}

	/** The primary file is intact after the cancelled pre-save. */
	private static void verifySameContentsAsWritten(Mgr mgr) throws IOException {
		LocalBufferFile f1 = new LocalBufferFile(mgr.getBufferFile(1), true);
		try {
			assertEquals(256, f1.getIndexCount());
			assertEquals(42, f1.getParameter("p"));
		}
		finally {
			f1.close();
		}
	}

	/**
	 * The size of a file open for writing: the size in its directory entry (File.length) is
	 * updated only when the writer closes it on NTFS.
	 */
	private static long size(File f) {
		try (java.nio.channels.FileChannel ch =
			java.nio.channels.FileChannel.open(f.toPath(), java.nio.file.StandardOpenOption.READ)) {
			return ch.size();
		}
		catch (IOException e) {
			return -1;
		}
	}

	private File findPreSave() {
		File[] files = testDir.listFiles((d, n) -> n.endsWith(LocalBufferFile.PRESAVE_FILE_EXT));
		return files == null || files.length == 0 ? null : files[0];
	}
}
