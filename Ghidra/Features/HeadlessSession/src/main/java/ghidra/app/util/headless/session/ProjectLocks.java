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
package ghidra.app.util.headless.session;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.StandardOpenOption;
import java.util.Properties;

import com.google.gson.JsonObject;

import generic.util.FileChannelLock;

import ghidra.framework.model.ProjectLocator;

/**
 * Reads a project's lock the way Ghidra writes it ({@code generic.util.FileLocker} and
 * {@code ChannelLocker}): {@code <name>.lock} is a properties file naming the user, host and time,
 * and the process that holds the project keeps an OS lock on {@code <name>.lock~}. A lock file
 * whose {@code ~} file nobody locks was left by a process that died.
 * <p>
 * Never creates or changes a file: a project is only read here.
 */
final class ProjectLocks {

	private ProjectLocks() {
	}

	/**
	 * True when a live process (another one, or this one through a writable project) holds the
	 * project's lock.
	 */
	static boolean held(ProjectLocator locator) {
		File lock = locator.getProjectLockFile();
		if (!lock.isFile()) {
			return false;
		}
		File channel = new File(lock.getAbsolutePath() + "~");
		if (!channel.isFile()) {
			// a plain file lock (no channel lock support) is held while it exists; a channel lock
			// without its ~ file was left by a process that died
			return !channelType(lock);
		}
		// GATE9: the probe takes its turn with the other attempts of this JVM on channel lock files
		// (Ghidra's own project lock and unlock, FileChannelLock.JVM_TURN). A FileChannel lock
		// belongs to the whole JVM: two attempts at once (two forks of one source, or a fork and a
		// writable open of it) would see each other's lock as an OverlappingFileLockException and
		// answer "held" for a project nobody holds, or fail the open. The probe is a tryLock (it
		// never waits), so the turn is short.
		synchronized (FileChannelLock.JVM_TURN) {
			return probe(channel);
		}
	}

	private static boolean probe(File channel) {
		try (FileChannel ch = FileChannel.open(channel.toPath(), StandardOpenOption.WRITE)) {
			FileLock l = ch.tryLock();
			if (l == null) {
				return true;
			}
			l.release();
			return false;
		}
		catch (OverlappingFileLockException e) {
			return true; // this JVM holds it
		}
		catch (IOException e) {
			return true; // cannot tell: assume a writer, the safe answer
		}
	}

	/** True when the lock file says its holder used a channel lock. */
	private static boolean channelType(File lock) {
		Properties p = read(lock);
		return p != null && "Channel Lock".equalsIgnoreCase(
			p.getProperty("<META> Supports File Channel Locking", "").trim());
	}

	/**
	 * The holder named in the lock file, for {@code conflict} answers: {@code user},
	 * {@code host}, {@code since} (Ghidra's timestamp text), {@code os}, {@code lockFile},
	 * {@code live}.
	 */
	static JsonObject holder(ProjectLocator locator) {
		File lock = locator.getProjectLockFile();
		Properties p = read(lock);
		JsonObject o = Json.of("label", "another process", "lockFile", lock.getPath());
		if (p != null) {
			Json.put(o, "user", p.getProperty("Username"));
			Json.put(o, "host", p.getProperty("Hostname"));
			Json.put(o, "since", p.getProperty("Timestamp"));
			Json.put(o, "os", p.getProperty("OS Name"));
		}
		Json.put(o, "live", held(locator));
		return o;
	}

	private static Properties read(File lock) {
		if (!lock.isFile()) {
			return null;
		}
		Properties p = new Properties();
		try (InputStream in = new FileInputStream(lock)) {
			p.load(in);
			return p;
		}
		catch (IOException e) {
			return null;
		}
	}
}
