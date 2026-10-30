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
package generic.util;

import java.io.*;
import java.nio.channels.*;

public class FileChannelLock {

	/**
	 * The attempts of this JVM on a channel lock file take turns on this monitor: the attempt of
	 * {@link #lock()}, {@link #release()}, and any other short probe of such a file (a
	 * {@code tryLock} followed by its release, never a wait). A FileChannel lock belongs to the
	 * whole JVM, so two attempts at once on one file make one of them fail with
	 * {@link OverlappingFileLockException}, which reads as "another holder"; in turn, that
	 * exception means a real holder in this JVM.
	 */
	public static final Object JVM_TURN = new Object();

	private final File lockFile;
	private FileOutputStream out;
	private FileChannel fc;
	private FileLock lock;

	/**
	 * A flag to signal that we are locked.  This is needed because we do not want to 'cleanup'
	 * lock files when we can't lock, as they may already be in use by another application 
	 * instance.
	 */
	private boolean isLocked;

	public FileChannelLock(File lockFile) {
		this.lockFile = new File(lockFile.getAbsolutePath() + "~");
	}

	boolean lock() {
		synchronized (JVM_TURN) {
			return lockInTurn();
		}
	}

	private boolean lockInTurn() {
		try {
			out = new FileOutputStream(lockFile, true);
			fc = out.getChannel();
			lock = fc.tryLock();
			isLocked = (lock != null);

			if (!isLocked) {
				release();
			}

			return isLocked;
		}
		catch (IOException | OverlappingFileLockException e) {
			release();
		}
		return false;
	}

	void release() {
		synchronized (JVM_TURN) {
			releaseInTurn();
		}
	}

	private void releaseInTurn() {
		if (lock != null) {
			try {
				lock.release();
			}
			catch (IOException e) {
				// we tried
			}
		}
		if (fc != null) {
			try {
				fc.close();
			}
			catch (IOException e) {
				// we tried
			}
		}
		if (out != null) {
			try {
				out.close();
			}
			catch (IOException e) {
				// we tried
			}
		}

		if (isLocked) {
			// only try to delete the lock file if we were able to lock
			lockFile.delete();
		}
	}
}
