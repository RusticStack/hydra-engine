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
package ghidra.app.plugin.core.osgi;

import java.io.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * A file-based lock used to protect modifications to OSGi shared resources from other
 * instances of Ghidra running in parallel.
 * <p>
 * A {@link java.nio.channels.FileChannel} lock is held by the whole JVM: a second thread of the
 * same JVM that asks for it while it is held (or while another thread waits for it) gets an
 * {@link java.nio.channels.OverlappingFileLockException} instead of waiting. So the threads of
 * one JVM first take an in-JVM lock keyed by the lock file, and only the outermost holder takes
 * the file lock: threads of one JVM wait for each other, other processes are excluded by the
 * file lock as before, and a thread that already holds it (a script loading a script) may take
 * it again. Must be closed by the thread that made it.
 */
public class OSGiParallelLock implements Closeable {

	private static final String LOCK_NAME = "parallel.lock";

	/** The in-JVM lock of each lock file (one OSGi dir per JVM in practice). */
	private static final Map<String, ReentrantLock> IN_JVM = new ConcurrentHashMap<>();

	private File lockFile;
	private FileOutputStream fos;
	private ReentrantLock inJvm;

	/**
	 * Creates a new OSGi file-based lock
	 */
	public OSGiParallelLock() {
		File osgiDir = BundleHost.getOsgiDir().toFile();
		FileUtilities.mkdirs(osgiDir);
		lockFile = new File(osgiDir, LOCK_NAME);
		ReentrantLock l = IN_JVM.computeIfAbsent(lockFile.getAbsolutePath(),
			k -> new ReentrantLock());
		l.lock();
		inJvm = l;
		if (l.getHoldCount() > 1) {
			return; // this thread holds the file lock already
		}
		try {
			fos = new FileOutputStream(lockFile);
			fos.getChannel().lock();
		}
		catch (IOException e) {
			Msg.error(this, "Failed to open OSGi parallel lock: " + lockFile, e);
		}
		catch (RuntimeException | Error e) {
			close();
			throw e;
		}
	}

	@Override
	public void close() {
		ReentrantLock l = inJvm;
		if (l == null) {
			return;
		}
		inJvm = null;
		try {
			if (fos != null) {
				FSUtilities.uncheckedClose(fos, "Failed to close OSGi parallel lock: " + lockFile);
				fos = null;
			}
		}
		finally {
			l.unlock();
		}
	}
}
