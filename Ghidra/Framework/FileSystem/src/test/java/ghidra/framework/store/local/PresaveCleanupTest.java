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
package ghidra.framework.store.local;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.rules.TemporaryFolder;

import ghidra.framework.store.local.LocalDatabaseItem.PresaveCleanup;

/**
 * Hydra H6: the presave cleanup that every writable file-system open asks for runs on one shared
 * worker, and still removes exactly the files the old per-open thread removed.
 */
public class PresaveCleanupTest {

	private static final long HOUR = 3_600_000L;

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private static File file(File dir, String name, long mtime) throws IOException {
		dir.mkdirs();
		File f = new File(dir, name);
		try (FileOutputStream out = new FileOutputStream(f)) {
			out.write(new byte[] { 1, 2, 3 });
		}
		assertTrue(f.setLastModified(mtime));
		return f;
	}

	private static void idle() throws InterruptedException {
		assertTrue("presave cleanup did not finish", PresaveCleanup.awaitIdle(30_000));
	}

	/** An old presave file is removed at the open of a writable file system; nothing else is. */
	@Test
	public void oldPresaveFileIsRemovedAtFirstOpen() throws Exception {
		File root = tmp.newFolder("proj.rep");
		LocalFileSystem.getLocalFileSystem(root.getPath(), true, false, false, false).dispose();
		idle();

		long old = System.currentTimeMillis() - HOUR;
		File data = new File(root, "00/~00000000.db");
		File ps = file(data, "tmp123.ps", old);
		File fresh = file(data, "tmp124.ps", System.currentTimeMillis() + HOUR);
		File db = file(data, "db.1.gbf", old);

		LocalFileSystem fs =
			LocalFileSystem.getLocalFileSystem(root.getPath(), false, false, false, false);
		try {
			idle();
		}
		finally {
			fs.dispose();
		}
		assertFalse(ps.exists());
		assertTrue(fresh.exists());
		assertTrue(db.exists());
		String[] left = root.list((d, n) -> n.startsWith("tmp") && n.endsWith(".tmp"));
		assertEquals("the clock probe file is left", 0, left.length);
	}

	/** The files the old recursion took are removed; nothing else is touched. */
	@Test
	public void sameFilesAsTheOldRecursion() throws Exception {
		File root = tmp.newFolder("layout.rep");
		long old = System.currentTimeMillis() - HOUR;
		long future = System.currentTimeMillis() + HOUR;
		List<File> removed = new ArrayList<>();
		List<File> kept = new ArrayList<>();
		File data = new File(root, "00/~00000000.db");
		removed.add(file(data, "tmp123.ps", old));
		removed.add(file(data, "x.ps", old)); // the old filter took any *.ps
		removed.add(file(new File(root, "a/b/~00000001.db"), "tmp7.ps", old));
		removed.add(file(new File(root, "~00000002.db"), "tmp8.ps", old));
		removed.add(file(new File(root, "~~notHidden/~00000003.db"), "tmp9.ps", old));
		removed.add(file(new File(root, "~~~hidden.db"), "tmp10.ps", old)); // odd: hidden
		kept.add(file(data, "tmp124.ps", future)); // after the open
		kept.add(file(data, "db.1.gbf", old));
		kept.add(file(data, "tmp125.tmp", old));
		kept.add(file(new File(data, "sub"), "tmp126.ps", old)); // below a database folder
		kept.add(file(new File(data, "~00000009.db"), "tmp131.ps", old)); // below a database folder
		kept.add(file(new File(root, "00"), "tmp127.ps", old)); // not in a database folder
		kept.add(file(root, "tmp132.ps", old)); // the root is not a database folder
		kept.add(file(new File(root, "~hidden/~00000004.db"), "tmp128.ps", old)); // hidden: skipped
		kept.add(file(new File(root, ".dot/~00000006.db"), "tmp133.ps", old)); // hidden: skipped
		kept.add(file(new File(root, "00/~~00000005.db"), "tmp129.ps", old)); // not hidden
		File psDir = new File(data, "tmp130.ps");
		assertTrue(psDir.mkdirs()); // a folder, not a file
		kept.add(psDir);

		LocalDatabaseItem.cleanupOldPresaveFiles(root);
		idle();
		for (File f : removed) {
			assertFalse("not removed: " + f, f.exists());
		}
		for (File f : kept) {
			assertTrue("removed: " + f, f.exists());
		}
		String[] left = root.list((d, n) -> n.startsWith("tmp") && n.endsWith(".tmp"));
		assertEquals("the clock probe file is left", 0, left.length);
	}

	/** A read-only open removes nothing, as before. */
	@Test
	public void readOnlyOpenRemovesNothing() throws Exception {
		File root = tmp.newFolder("ro.rep");
		LocalFileSystem.getLocalFileSystem(root.getPath(), true, false, false, false).dispose();
		idle();
		File ps = file(new File(root, "00/~00000000.db"), "tmp1.ps",
			System.currentTimeMillis() - HOUR);
		LocalFileSystem fs =
			LocalFileSystem.getLocalFileSystem(root.getPath(), false, false, true, false);
		fs.dispose();
		idle();
		assertTrue(ps.exists());
	}

	/**
	 * Many opens share one worker thread (the old code started one thread per open), and a tree
	 * without a presave file is only listed: no temporary file is created in it.
	 */
	@Test
	public void opensShareOneWorkerAndCleanTreesAreOnlyListed() throws Exception {
		List<File> roots = new ArrayList<>();
		for (int i = 0; i < 10; i++) {
			File root = tmp.newFolder("r" + i + ".rep");
			file(new File(root, "00/~00000000.db"), "db.1.gbf", System.currentTimeMillis());
			roots.add(root);
		}
		idle();
		long[] before = PresaveCleanup.counters();
		for (int round = 0; round < 3; round++) {
			for (File root : roots) {
				LocalDatabaseItem.cleanupOldPresaveFiles(root);
			}
		}
		idle();
		long[] after = PresaveCleanup.counters();
		assertEquals(30, after[0] - before[0]);
		long scans = after[1] - before[1];
		assertTrue("scans " + scans, scans >= 10 && scans <= 30);
		assertTrue("threads started " + (after[2] - before[2]), after[2] - before[2] <= 1);
		assertEquals("clock probes", 0, after[3] - before[3]);
	}

	/** A request for a missing root is harmless and the worker keeps serving. */
	@Test
	public void missingRootIsHarmless() throws Exception {
		File gone = new File(tmp.getRoot(), "gone.rep");
		LocalDatabaseItem.cleanupOldPresaveFiles(gone);
		File root = tmp.newFolder("after.rep");
		File ps = file(new File(root, "~00000000.db"), "tmp5.ps", System.currentTimeMillis() - HOUR);
		LocalDatabaseItem.cleanupOldPresaveFiles(root);
		idle();
		assertFalse(ps.exists());
	}
}
