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
package ghidra.framework.store.db;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Hydra E8 (storage integrity): validates the header magic of the newest {@code db.N.gbf} of a
 * database directory and, where the caller is allowed to write, quarantines a newest version
 * whose header is invalid so that the previous version becomes the newest again.
 * <p>
 * Background: before the ordering fix in {@code LocalManagedBufferFile.saveCompleted} a process
 * kill during a save could leave the newest {@code db.N.gbf} at full size with an all-zero header
 * (it was renamed to its final name first and had its header written afterwards). Ghidra then
 * fails with "Unrecognized file format" and neither falls back to {@code db.N-1.gbf} nor repairs
 * the file.
 * <p>
 * Rules, all of them deliberate:
 * <ul>
 * <li>Nothing is ever deleted. A bad newest version is moved into
 * {@code <dbDir>/db.N.gbf.quarantine/}, a directory whose name does not end in {@code .gbf}, so
 * the database scan ignores it.</li>
 * <li>Nothing is written unless the repair policy says the directory is a writable disposable
 * tree. The default policy repairs nothing; {@link #REPAIR_ROOTS_PROPERTY} or
 * {@link #setRepairPolicy(Predicate)} name the disposable trees. A sealed, published or
 * read-only-opened tree, and the master, are never in that set, so for them the check only
 * reads and reports {@code corrupt_newest}.</li>
 * <li>Only the header magic (the first eight bytes) is validated. This is a cheap open-time
 * check, not a full file verification. A file whose magic cannot be read because of an I/O
 * error (a sharing violation, a permission error) is neither valid nor invalid: the error
 * propagates and nothing is quarantined.</li>
 * <li>A repair that cannot be done (the file is read-only, is open elsewhere, the quarantine
 * folder cannot be created) is not an exception: the result is {@link Status#CORRUPT_NEWEST}
 * and the open reports {@code corrupt_newest}.</li>
 * </ul>
 */
public final class VersionFileCheck {
	private static final Logger log = LogManager.getLogger(VersionFileCheck.class);

	/**
	 * System property: a list of directory trees (separated by {@link File#pathSeparator}) that
	 * are writable and disposable. A database directory inside one of them is repaired on open.
	 */
	public static final String REPAIR_ROOTS_PROPERTY = "hydra.storage.repairRoots";

	/** Prefix of the message of the exception thrown for an unrepaired corrupt newest version. */
	public static final String CORRUPT_NEWEST = "corrupt_newest";

	/** The first eight bytes of every valid buffer file (LocalBufferFile.MAGIC_NUMBER). */
	private static final byte[] MAGIC =
		{ 0x2f, 0x30, 0x31, 0x2c, 0x34, 0x29, 0x2c, 0x2a };

	private static final Pattern VERSION_FILE = Pattern.compile("db\\.(\\d+)\\.gbf");
	private static final int MAX_REPAIR_LOG = 64;

	public enum Status {
		/** no buffer file in the directory */
		EMPTY,
		/** the newest version has a valid header */
		OK,
		/** the newest version was invalid and was moved to quarantine; the previous one is newest */
		REPAIRED,
		/**
		 * the newest version is invalid, a previous version is intact, and it was not repaired
		 * (nothing was written, or the repair failed: see {@link Result#repairError})
		 */
		CORRUPT_NEWEST,
		/** the newest version is invalid and no previous version is available */
		CORRUPT_NO_FALLBACK
	}

	/** The outcome of one check. */
	public static final class Result {
		public final File dbDir;
		public final Status status;
		/** version number of the newest {@code db.N.gbf} found, 0 if none */
		public final int newest;
		/** the intact previous version that is (or would become) the newest, -1 if none */
		public final int fallback;
		/** the quarantined file, null unless repaired */
		public final File quarantined;
		public final long timeMillis;
		/** why a requested repair could not be done, null if none was requested or it worked */
		public final String repairError;

		Result(File dbDir, Status status, int newest, int fallback, File quarantined) {
			this(dbDir, status, newest, fallback, quarantined, null);
		}

		Result(File dbDir, Status status, int newest, int fallback, File quarantined,
				String repairError) {
			this.repairError = repairError;
			this.dbDir = dbDir;
			this.status = status;
			this.newest = newest;
			this.fallback = fallback;
			this.quarantined = quarantined;
			this.timeMillis = System.currentTimeMillis();
		}

		public boolean isCorrupt() {
			return status == Status.CORRUPT_NEWEST || status == Status.CORRUPT_NO_FALLBACK;
		}

		@Override
		public String toString() {
			return status + " " + dbDir + " newest=" + newest + " fallback=" + fallback +
				(quarantined != null ? " quarantined=" + quarantined : "") +
				(repairError != null ? " repairError=" + repairError : "");
		}
	}

	private static final Deque<Result> REPAIRS = new ConcurrentLinkedDeque<>();
	private static volatile Predicate<File> repairPolicy = null;

	private VersionFileCheck() {
		// static utility
	}

	/**
	 * Replace the repair policy. The predicate receives a database directory and answers whether
	 * it lies in a writable disposable tree. Null restores the default (the
	 * {@link #REPAIR_ROOTS_PROPERTY} property; nothing is repairable without it).
	 */
	public static void setRepairPolicy(Predicate<File> policy) {
		repairPolicy = policy;
	}

	/** True if the policy allows writing (quarantining) in {@code dbDir}. */
	public static boolean mayRepair(File dbDir) {
		Predicate<File> p = repairPolicy;
		if (p != null) {
			return p.test(dbDir);
		}
		String roots = System.getProperty(REPAIR_ROOTS_PROPERTY);
		if (roots == null || roots.isBlank()) {
			return false;
		}
		Path dir = dbDir.toPath().toAbsolutePath().normalize();
		for (String root : roots.split(File.pathSeparator)) {
			if (!root.isBlank() &&
				dir.startsWith(Paths.get(root).toAbsolutePath().normalize())) {
				return true;
			}
		}
		return false;
	}

	/** The repairs done in this process, oldest first (bounded); the source of {@code repairs[]}. */
	public static List<Result> repairs() {
		return new ArrayList<>(REPAIRS);
	}

	/**
	 * First half of an open: when {@code writable} and the repair policy allows it, a newest
	 * version with an invalid header is quarantined so that the previous one is newest again.
	 * Never throws for a corrupt newest version, and a repair that fails (the move into
	 * quarantine) is reported in the result, not thrown (a caller that constructs many items must
	 * not turn one of them into an unreadable file); {@link #requireIntact(File)} reports it when
	 * the database is actually opened. It does throw for an I/O error that stops the header
	 * from being read: that is not a corrupt file, and nothing is moved.
	 * @param writable false for a read-only tree: nothing is written, whatever the policy says
	 */
	public static Result repairOnOpen(File dbDir, boolean writable) throws IOException {
		return check(dbDir, writable && mayRepair(dbDir));
	}

	/**
	 * Second half of an open: reads only. Throws {@code corrupt_newest: ...} when the newest
	 * version has an invalid header (and was not repaired), instead of the "Unrecognized file
	 * format" the buffer file would answer.
	 * @throws IOException {@code corrupt_newest: ...}
	 */
	public static void requireIntact(File dbDir) throws IOException {
		Result r = check(dbDir, false);
		if (r.isCorrupt()) {
			throw new IOException(CORRUPT_NEWEST + ": " + dbDir + ": db." + r.newest +
				".gbf has no valid header (an interrupted save)" +
				(r.fallback > 0 ? "; db." + r.fallback +
					".gbf is intact, open the project as a writable disposable copy to repair it" +
					" (the file is moved to a quarantine folder, never deleted)"
					: "; no earlier version is available"));
		}
	}

	/**
	 * Inspect, and when {@code repair} is true also repair, a database directory.
	 * With {@code repair} false nothing is written.
	 */
	public static Result check(File dbDir, boolean repair) throws IOException {
		TreeMap<Integer, File> versions = listVersions(dbDir);
		if (versions.isEmpty()) {
			return new Result(dbDir, Status.EMPTY, 0, -1, null);
		}
		int newest = versions.lastKey();
		if (hasValidMagic(versions.get(newest))) {
			return new Result(dbDir, Status.OK, newest, -1, null);
		}
		int fallback = -1;
		for (Integer v : versions.descendingKeySet()) {
			if (v < newest && hasValidMagic(versions.get(v))) {
				fallback = v;
				break;
			}
		}
		if (fallback < 0) {
			return new Result(dbDir, Status.CORRUPT_NO_FALLBACK, newest, -1, null);
		}
		if (!repair) {
			return new Result(dbDir, Status.CORRUPT_NEWEST, newest, fallback, null);
		}
		File bad = versions.get(newest);
		File q;
		try {
			if (!Files.isWritable(bad.toPath())) {
				throw new IOException("db." + newest + ".gbf is read-only");
			}
			q = quarantine(bad);
		}
		catch (IOException e) {
			String why = e.getClass().getSimpleName() + ": " + e.getMessage();
			log.error(dbDir + ": db." + newest + ".gbf has no valid header but could not be " +
				"moved to quarantine (" + why + "); not repaired");
			return new Result(dbDir, Status.CORRUPT_NEWEST, newest, fallback, null, why);
		}
		Result r = new Result(dbDir, Status.REPAIRED, newest, fallback, q);
		log.warn(dbDir + ": db." + newest + ".gbf has no valid header (interrupted save); moved to " +
			q + ", db." + fallback + ".gbf is the newest version again");
		REPAIRS.addLast(r);
		while (REPAIRS.size() > MAX_REPAIR_LOG) {
			REPAIRS.pollFirst();
		}
		return r;
	}

	/**
	 * True if the file starts with the buffer file magic; false if it is shorter or starts with
	 * other bytes, or if it no longer exists (another opener quarantined it first).
	 * @throws IOException for any other failure to read the file (a sharing violation, a
	 * permission error): that says nothing about the content, so it is not "invalid"
	 */
	public static boolean hasValidMagic(File f) throws IOException {
		byte[] head = new byte[MAGIC.length];
		try (InputStream in = Files.newInputStream(f.toPath())) {
			int n = in.readNBytes(head, 0, head.length);
			return n == head.length && Arrays.equals(head, MAGIC);
		}
		catch (NoSuchFileException e) {
			return false;
		}
	}

	private static TreeMap<Integer, File> listVersions(File dbDir) throws FileNotFoundException {
		String[] names = dbDir.list();
		if (names == null) {
			throw new FileNotFoundException(dbDir + " not found");
		}
		TreeMap<Integer, File> map = new TreeMap<>();
		for (String name : names) {
			Matcher m = VERSION_FILE.matcher(name);
			if (m.matches()) {
				try {
					map.put(Integer.parseInt(m.group(1)), new File(dbDir, name));
				}
				catch (NumberFormatException e) {
					// not a version number we can hold; ignore
				}
			}
		}
		return map;
	}

	private static File quarantine(File bad) throws IOException {
		File qdir = new File(bad.getParentFile(), bad.getName() + ".quarantine");
		if (!qdir.isDirectory() && !qdir.mkdirs() && !qdir.isDirectory()) {
			throw new IOException("Failed to create quarantine folder " + qdir);
		}
		File target = new File(qdir, bad.getName());
		if (target.exists()) {
			target = new File(qdir, bad.getName() + "." + System.currentTimeMillis());
		}
		try {
			Files.move(bad.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE);
		}
		catch (NoSuchFileException e) {
			// another opener moved it first; the outcome is the same
		}
		return target;
	}
}
