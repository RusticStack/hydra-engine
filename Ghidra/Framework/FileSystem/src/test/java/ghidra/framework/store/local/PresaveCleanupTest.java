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
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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

	/** Idle, and every worker ended, so the next request starts exactly one worker. */
	private static void noWorkers() throws InterruptedException {
		idle();
		long deadline = System.currentTimeMillis() + 30_000;
		while (PresaveCleanup.counters()[4] != 0 && System.currentTimeMillis() < deadline) {
			Thread.sleep(20);
		}
		assertEquals("live workers", 0, PresaveCleanup.counters()[4]);
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

	/** A root that java.nio refuses (java.io accepts it) is scanned by the old recursion. */
	@Test
	public void rootRefusedByNioFallsBackToTheOldRecursion() throws Exception {
		File root = tmp.newFolder("nio.rep");
		long old = System.currentTimeMillis() - HOUR;
		File a = file(new File(root, "00/~00000000.db"), "tmp1.ps", old);
		File b = file(new File(root, "~00000001.db"), "tmp2.ps", old);
		file(new File(root, "~hidden/~00000002.db"), "tmp3.ps", old);
		File refused = new File(root.getPath()) {
			@Override
			public Path toPath() {
				throw new InvalidPathException(getPath(), "refused for the test");
			}
		};
		Set<File> expected = new HashSet<>(List.of(a, b));
		assertEquals(expected, new HashSet<>(PresaveCleanup.findPresaveFiles(root)));
		assertEquals(expected, new HashSet<>(PresaveCleanup.findPresaveFiles(refused)));
	}

	/**
	 * A scan stuck on one root (a hung volume) does not stop the cleanup of other roots: the next
	 * open starts one more worker, which never scans the stuck root a second time. The worker is a
	 * non-daemon thread, as the old per-open thread was.
	 */
	@Test
	public void stalledScanDoesNotBlockOtherRoots() throws Exception {
		noWorkers();
		File slow = tmp.newFolder("slow.rep").getAbsoluteFile();
		File other = tmp.newFolder("other.rep");
		File ps = file(new File(other, "~00000000.db"), "tmp1.ps", System.currentTimeMillis() - HOUR);
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		AtomicInteger slowScans = new AtomicInteger();
		AtomicReference<Boolean> daemon = new AtomicReference<>();
		long oldStall = PresaveCleanup.stallMs;
		PresaveCleanup.stallMs = 200;
		PresaveCleanup.beforeScan = r -> {
			daemon.compareAndSet(null, Thread.currentThread().isDaemon());
			if (r.equals(slow)) {
				slowScans.incrementAndGet();
				entered.countDown();
				try {
					release.await(60, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		};
		try {
			LocalDatabaseItem.cleanupOldPresaveFiles(slow);
			assertTrue(entered.await(10, TimeUnit.SECONDS));
			Thread.sleep(500); // past the stall time
			LocalDatabaseItem.cleanupOldPresaveFiles(slow); // waits: never two scans of a root
			LocalDatabaseItem.cleanupOldPresaveFiles(other);
			long deadline = System.currentTimeMillis() + 10_000;
			while (ps.exists() && System.currentTimeMillis() < deadline) {
				Thread.sleep(20);
			}
			assertFalse("the other root was not cleaned while one scan was stuck", ps.exists());
			assertEquals(1, slowScans.get());
			assertEquals(Boolean.FALSE, daemon.get());
		}
		finally {
			release.countDown();
			idle();
			PresaveCleanup.beforeScan = null;
			PresaveCleanup.stallMs = oldStall;
		}
		assertEquals("the queued request for the stuck root runs after it", 2, slowScans.get());
	}

	/**
	 * The cutoff is the time of the open, not of the scan: a presave file whose time is after the
	 * open is kept even when the scan runs later (Ghidra's thread used the time of its scan).
	 */
	@Test
	public void cutoffIsTheTimeOfTheOpen() throws Exception {
		noWorkers();
		File blocker = tmp.newFolder("blocker.rep").getAbsoluteFile();
		File root = tmp.newFolder("cut.rep");
		File data = new File(root, "~00000000.db");
		File before = file(data, "tmp1.ps", System.currentTimeMillis() - HOUR);
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		long oldStall = PresaveCleanup.stallMs;
		PresaveCleanup.stallMs = 600_000;
		PresaveCleanup.beforeScan = r -> {
			if (r.equals(blocker)) {
				entered.countDown();
				try {
					release.await(60, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		};
		File after;
		try {
			LocalDatabaseItem.cleanupOldPresaveFiles(blocker);
			assertTrue(entered.await(10, TimeUnit.SECONDS));
			long openTime = System.currentTimeMillis();
			LocalDatabaseItem.cleanupOldPresaveFiles(root); // queued behind the blocker
			after = file(data, "tmp2.ps", openTime + 1000); // stale by the scan, not by the open
			while (System.currentTimeMillis() < openTime + 2500) {
				Thread.sleep(50);
			}
			assertTrue(before.exists());
		}
		finally {
			release.countDown();
			idle();
			PresaveCleanup.beforeScan = null;
			PresaveCleanup.stallMs = oldStall;
		}
		assertFalse("a presave file older than the open is removed", before.exists());
		assertTrue("a presave file newer than the open is kept", after.exists());
	}
}
