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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import ghidra.framework.model.ProjectLocator;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

/**
 * The file side of {@code fork_project}: what a fork costs, the copy itself, and the
 * <b>sidecar</b> {@code <name>.fork.json} next to the fork's {@code .gpr}, which records where the
 * fork came from. Ghidra never reads the sidecar (it only looks for {@code .gpr} and {@code .rep}).
 * <p>
 * The copy is the one the upgrade cache makes ({@link UpgradeCache#copyProject}): the
 * {@code .gpr} and every file of the {@code .rep}, never the project's lock files, with
 * {@link Files#copy}, which uses the platform's copy. On Windows that is {@code CopyFileEx},
 * which block-clones on ReFS (a Dev Drive) on Windows 11 24H2 and later: the copy shares the
 * source's blocks and costs only metadata until either side writes. Elsewhere it is a full copy.
 */
final class ProjectFork {

	/**
	 * Attempts of a move or a sidecar rewrite against a handle holder. The pauses between them are
	 * 25 ms doubling (25, 50, 100, 200, 400, 800), none after the last attempt, so a holder is
	 * waited for about 1.6 s (1575 ms) in all.
	 */
	static final int RETRIES = 7;
	static final String SIDECAR_SUFFIX = ".fork.json";
	static final int SIDECAR_FORMAT = 1;
	/**
	 * Below this a fork's use of free space is lost in what other writers on the volume do, so
	 * {@code cloned} then rests on the file system alone (a clone of 261 MB measured 36 KB used on
	 * ReFS, a copy 262 MB on NTFS).
	 */
	static final long MEASURABLE_BYTES = 64L << 20;
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting()
			.disableHtmlEscaping()
			.create();

	private ProjectFork() {
	}

	/** The sidecar of a project, whether it exists or not. */
	static File sidecar(ProjectResolver.Resolved r) {
		return new File(r.dir(), r.name() + SIDECAR_SUFFIX);
	}

	/** The project's sidecar, or null when it is not a fork (or the sidecar is unreadable). */
	static JsonObject readSidecar(ProjectResolver.Resolved r) {
		File f = sidecar(r);
		if (!f.isFile()) {
			return null;
		}
		try {
			JsonElement e = JsonParser.parseString(Files.readString(f.toPath()));
			return e.isJsonObject() ? e.getAsJsonObject() : null;
		}
		catch (IOException | JsonParseException e) {
			return null;
		}
	}

	/** The sidecar's {@code kind}. */
	static final String SIDECAR_KIND = "ghidra-session-fork";

	/** The purposes of {@code fork_project} (3.4); {@code fork} is the default. */
	static final List<String> PURPOSES = List.of("fork", "backup", "generation", "view");
	/** The sidecar state of a generation candidate: writable by its publisher until sealed (D38). */
	static final String STATE_CANDIDATE = "candidate";

	/**
	 * D12: a project is <b>disposable</b> when its sidecar exists, parses, has the fork
	 * {@code kind} and does not say {@code disposable:false}. A sidecar without the field (every
	 * hydra.2/3 fork) is therefore disposable. No sidecar, an unparseable one, or any doubt:
	 * canonical (not disposable). An accident guard, not a security boundary.
	 */
	static boolean disposable(ProjectResolver.Resolved r) {
		JsonObject sc = readSidecar(r);
		return disposable(sc);
	}

	static boolean disposable(JsonObject sc) {
		if (sc == null || !SIDECAR_KIND.equals(Json.str(sc, "kind", null))) {
			return false;
		}
		JsonElement d = sc.get("disposable");
		return !(d != null && d.isJsonPrimitive() && d.getAsJsonPrimitive().isBoolean() &&
			!d.getAsBoolean());
	}

	/**
	 * The policy of {@code VersionFileCheck} for this daemon (D42, A10): a newest version file
	 * with an invalid header is quarantined on open only in a project that is a writable
	 * disposable fork (its sidecar says so) and is not sealed (D38). The master, a generation
	 * candidate (non-disposable), a sealed project, a backup and anything without a sidecar are
	 * never in that set: opening them only reads, and a bad newest version answers
	 * {@code corrupt_newest}. {@code -Dhydra.storage.repairRoots} (the tree list the core also
	 * reads) still declares extra disposable trees, for tests and for operators.
	 */
	static boolean repairable(File dbDir) {
		File rep = dbDir.getAbsoluteFile();
		String repExt = ProjectLocator.getProjectDirExtension();
		while (rep != null && !rep.getName().endsWith(repExt)) {
			rep = rep.getParentFile();
		}
		if (rep != null && rep.getParentFile() != null && repairableProject(rep, repExt)) {
			return true;
		}
		String roots = System.getProperty(ghidra.framework.store.db.VersionFileCheck.REPAIR_ROOTS_PROPERTY);
		if (roots == null || roots.isBlank()) {
			return false;
		}
		Path dir = dbDir.toPath().toAbsolutePath().normalize();
		for (String root : roots.split(File.pathSeparator)) {
			if (!root.isBlank() && dir.startsWith(Path.of(root).toAbsolutePath().normalize())) {
				return true;
			}
		}
		return false;
	}

	/** The decision for a project's folder, kept for a moment: a project load asks once per database. */
	private static final Map<String, long[]> REPAIRABLE = new java.util.concurrent.ConcurrentHashMap<>();
	private static final long REPAIRABLE_TTL_MS = 1500;

	private static boolean repairableProject(File rep, String repExt) {
		String key = rep.getPath();
		long now = System.nanoTime() / 1_000_000;
		long[] hit = REPAIRABLE.get(key);
		if (hit != null && now - hit[1] < REPAIRABLE_TTL_MS) {
			return hit[0] == 1;
		}
		String n = rep.getName();
		ProjectResolver.Resolved r = new ProjectResolver.Resolved(rep.getParentFile(),
			n.substring(0, n.length() - repExt.length()));
		boolean yes = disposable(r) && !Seals.isSealed(r).sealed();
		if (REPAIRABLE.size() > 512) {
			REPAIRABLE.clear();
		}
		REPAIRABLE.put(key, new long[] { yes ? 1 : 0, now });
		return yes;
	}

	/** The sidecar field that a {@code promote_overlay} into the fork sets until it is acknowledged. */
	static final String PROMOTE = "promote";
	static final String PROMOTE_IN_PROGRESS = "in-progress";

	/**
	 * Marks the fork's sidecar {@code promote:"in-progress"} (3.12: overlays are RAM-only and a
	 * killed {@code promote_overlay} leaves a fork that may or may not hold the edits, so a fork
	 * with the marker is known to be unverified). No sidecar: nothing to mark. Best effort: a
	 * failure to write is logged, never thrown.
	 */
	static void markPromote(ProjectResolver.Resolved r) {
		setPromote(r, PROMOTE_IN_PROGRESS);
	}

	/** Removes the marker once the promote is acknowledged (saved). */
	static void clearPromote(ProjectResolver.Resolved r) {
		setPromote(r, null);
	}

	private static void setPromote(ProjectResolver.Resolved r, String value) {
		JsonObject sc = readSidecar(r);
		if (sc == null) {
			return;
		}
		if (value == null) {
			if (!sc.has(PROMOTE)) {
				return;
			}
			sc.remove(PROMOTE);
		}
		else {
			sc.addProperty(PROMOTE, value);
		}
		try {
			// a reader holding the sidecar open without delete sharing (a scanner, a status
			// poll) stops the rename over it for a moment: the marker is the record that a
			// killed promote leaves a fork of unknown content, so it is written with the
			// same backoff as the publish (F1: a single attempt could lose the marker)
			writeSidecarRetrying(sidecar(r), sc);
		}
		catch (IOException e) {
			ghidra.util.Msg.warn(ProjectFork.class,
				"fork_project: could not update the promote marker of " + sidecar(r) + ": " + e);
		}
	}

	/** A short form of a sidecar for {@code project}/{@code info}: no nested parents. */
	static JsonObject summary(JsonObject sidecar) {
		if (sidecar == null) {
			return null;
		}
		JsonObject o = new JsonObject();
		for (String k : List.of("source", "baseRevision", "created", "createdAt", "by", "mode",
			"method", "cloned", "bytes", "depth")) {
			if (sidecar.has(k)) {
				o.add(k, sidecar.get(k));
			}
		}
		return o;
	}

	/** The sidecar while the fork is being published: the {@code .rep} is in place, the {@code .gpr} is not. */
	static final String STATE_PUBLISHING = "publishing";
	/** The sidecar of a finished fork: the {@code .gpr} is in place (E2: sealed generations and backups). */
	static final String STATE_COMPLETE = "complete";

	/**
	 * Writes a sidecar atomically and flushed (a temporary file forced to disk, then a rename), so
	 * that a reader sees the old record or the new one and never a torn one.
	 */
	static void writeSidecar(File f, JsonObject o) throws IOException {
		File tmp = new File(f.getPath() + ".tmp");
		try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(tmp.toPath(),
			StandardOpenOption.CREATE, StandardOpenOption.WRITE,
			StandardOpenOption.TRUNCATE_EXISTING)) {
			ch.write(java.nio.ByteBuffer.wrap(GSON.toJson(o).getBytes(StandardCharsets.UTF_8)));
			ch.force(true);
		}
		try {
			Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (IOException e) {
			try {
				Files.deleteIfExists(tmp.toPath()); // best effort: the next attempt writes it again
			}
			catch (IOException cleanup) {
				e.addSuppressed(cleanup); // never mask the failure that matters
			}
			throw e;
		}
	}

	/**
	 * {@link #writeSidecar} against a handle holder: up to {@link #RETRIES} attempts, 25 ms doubling
	 * between them, none after the last (1575 ms in all).
	 *
	 * @throws IOException the last failure when every attempt failed
	 */
	static void writeSidecarRetrying(File f, JsonObject o) throws IOException {
		IOException last = null;
		for (int i = 0; i < RETRIES; i++) {
			try {
				writeSidecar(f, o);
				return;
			}
			catch (IOException e) {
				last = e;
				if (i == RETRIES - 1 || !backoff(i)) {
					break;
				}
			}
		}
		throw last;
	}

	/** Sleeps the pause after attempt {@code i}; false when interrupted (the interrupt is kept). */
	private static boolean backoff(int i) {
		try {
			Thread.sleep(25L << i);
			return true;
		}
		catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	/**
	 * Removes what a failed publish put at the destination (rollback), surviving a handle holder:
	 * the file or folder is deleted again, with the backoff of the moves, until it is gone. It never
	 * throws, so the failure that made the publish roll back is the one the caller sees; a thing that
	 * is still there after the last attempt is logged (the next fork under the folder sweeps it).
	 */
	private static void removeRetrying(Path p) {
		IOException last = null;
		for (int i = 0; i < RETRIES; i++) {
			try {
				if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
					FileUtilities.deleteDir(p.toFile());
				}
				else {
					Files.deleteIfExists(p);
				}
				last = null;
			}
			catch (IOException e) {
				last = e;
			}
			if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) {
				return;
			}
			if (i == RETRIES - 1 || !backoff(i)) {
				break;
			}
		}
		ghidra.util.Msg.warn(ProjectFork.class,
			"fork_project: could not remove " + p + " while rolling back a failed publish" +
				(last == null ? "" : ": " + last));
	}

	/** What a fork of {@code r} into {@code destDir} costs, and how it would be made. */
	record Cost(long bytes, int files, boolean sameVolume, String sourceFs, String destFs,
			boolean cloneCapable, long destFreeBytes) {

		JsonObject json() {
			return Json.of("bytes", bytes, "mb", Math.round(bytes / 1048576.0 * 10) / 10.0,
				"files", files, "sameVolume", sameVolume, "sourceFileSystem", sourceFs,
				"destinationFileSystem", destFs, "cloneCapable", cloneCapable, "destFreeBytes",
				destFreeBytes);
		}
	}

	static Cost cost(ProjectResolver.Resolved r, File destDir) throws IOException {
		long bytes = 0;
		int files = 0;
		for (Path p : UpgradeCache.sourceFiles(r.gpr().toPath(), r.name()).values()) {
			try {
				bytes += Files.size(p);
				files++;
			}
			catch (NoSuchFileException e) {
				// removed while we looked; the revision check catches a change
			}
		}
		FileStore src = Files.getFileStore(r.gpr().toPath());
		FileStore dst = Files.getFileStore(existingAncestor(destDir).toPath());
		boolean same = src.equals(dst);
		return new Cost(bytes, files, same, src.type(), dst.type(),
			same && clones(dst), dst.getUsableSpace());
	}

	/**
	 * True when {@link Files#copy} block-clones on this file store: ReFS on Windows (Windows 11
	 * 24H2 and Windows Server 2025 clone in {@code CopyFileEx}). Other copy-on-write file systems
	 * (Btrfs, XFS, APFS) are not claimed: whether the JDK's copy reflinks there has not been
	 * measured here, so a fork there counts as a full copy (and is measured, see
	 * {@code cloned}).
	 */
	static boolean clones(FileStore fs) {
		String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		return os.startsWith("windows") && "refs".equalsIgnoreCase(fs.type());
	}

	static File existingAncestor(File f) {
		File a = f.getAbsoluteFile();
		while (a != null && !a.exists()) {
			a = a.getParentFile();
		}
		return a == null ? f.getAbsoluteFile() : a;
	}

	/**
	 * The outcome of {@link #stage}: the copy in its staging folder, not yet published.
	 * {@code unfinished} is set by {@link #publish} when the fork is committed (its {@code .gpr}
	 * is in place) but the sidecar could not be rewritten {@code complete} (a handle holder on it,
	 * SP6): the staging folder, whose intent proves the fork is this engine's, is then kept so
	 * that the next sweep of the name finishes the sidecar.
	 */
	record Staged(File dir, String id, ForkIntent intent, String sourceName, long ms,
			long freeBefore, long freeAfter,
			java.util.concurrent.atomic.AtomicBoolean unfinished) {

		boolean keep() {
			return unfinished.get();
		}
	}

	/** The loser of a publish race: the {@code .rep} of the destination is already there. */
	static final class RaceLost extends IOException {
		private static final long serialVersionUID = 1L;

		RaceLost(String message) {
			super(message);
		}
	}

	/**
	 * A fresh publish id: {@code <pid in hex>-<time>-<random>}, unique across processes and across
	 * requests of one process. The process id is in the name of the staging folder so that a
	 * folder whose intent was never written (the publisher was killed between creating the folder
	 * and writing the record) can still be attributed to a dead process ({@link ForkIntent#pidOf}).
	 */
	static String newId() {
		return Long.toHexString(ProcessHandle.current().pid()) + "-" +
			Long.toHexString(System.nanoTime()) + Integer.toHexString(
				java.util.concurrent.ThreadLocalRandom.current().nextInt(0x1000, 0x10000));
	}

	/**
	 * Step 1 of the publish (D41): copies the project {@code r} into a staging folder
	 * {@code .<name>.fork-<id>.tmp} next to the destination, after writing the intent record that
	 * names this process. Nothing of the fork is at the destination yet. {@code destDir} may exist.
	 * On any failure the staging folder is removed by the caller ({@link #discard}).
	 */
	static Staged stage(ProjectResolver.Resolved r, File destDir, String name, String id,
			String rk, RequestMonitor m) throws IOException, CancelledException {
		Files.createDirectories(destDir.toPath());
		FileStore store = Files.getFileStore(destDir.toPath());
		long freeBefore = store.getUsableSpace();
		File tmp = new File(destDir, ForkIntent.stagingName(name, id));
		long t0 = System.nanoTime();
		Files.createDirectory(tmp.toPath());
		ForkIntent intent = ForkIntent.create(id, rk, name);
		intent.write(tmp.toPath());
		UpgradeCache.copyProject(r.dir().toPath(), r.name(), tmp.toPath(), m);
		m.checkCancelled();
		long ms = (System.nanoTime() - t0) / 1_000_000;
		return new Staged(tmp, id, intent, r.name(), ms, freeBefore, store.getUsableSpace(),
			new java.util.concurrent.atomic.AtomicBoolean());
	}

	/** Removes a staging folder (and warns when it cannot). */
	static void discard(Staged st) {
		if (st == null || st.keep()) {
			return;
		}
		FileUtilities.deleteDir(st.dir());
		warnLeft(st.dir());
	}

	/**
	 * Steps 2 to 5 of the publish (D41), in this order, which is the whole point: the {@code .rep}
	 * is moved into place, the sidecar is written with {@code state:"publishing"}, the
	 * {@code .gpr} is moved (the commit point: from here the fork exists, and its {@code .rep} and
	 * sidecar already do), and the sidecar is rewritten {@code state:"complete"} and flushed. A
	 * kill at any point leaves the destination without a {@code .gpr} (and a staging folder whose
	 * intent names the dead process, which the next fork or the sweeper removes) or with a
	 * complete fork whose sidecar may still say {@code publishing} (which they finish).
	 *
	 * @param sidecar the record to write; {@code state} and {@code forkId} are set here
	 * @throws RaceLost when another publisher's {@code .rep} is at the destination; nothing of
	 *             the other publisher was touched
	 */
	static void publish(Staged st, File destDir, String name, JsonObject sidecar,
			String completeState) throws IOException {
		publish(st, destDir, name, sidecar, completeState, List.of());
	}

	/**
	 * Test hook only (launch property {@code ghidra.session.testHooks}): holds the publish between
	 * the move of the {@code .rep} and the move of the {@code .gpr} for
	 * {@code ghidra.session.testForkPauseAfterRepMs} ms, so a test can kill the daemon exactly
	 * there (8.13, {@code e2a_sweep_at_start}). Does nothing without the hooks.
	 */
	private static void pauseBetweenRenames() {
		if (!Health.testHooks()) {
			return;
		}
		long ms = Long.getLong("ghidra.session.testForkPauseAfterRepMs", 0L);
		if (ms > 0) {
			try {
				Thread.sleep(ms);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * {@link #publish(Staged, File, String, JsonObject, String)} for a fork that also carries
	 * files staged next to the project (a backup's {@code backup.json}, the {@code SEALED.json}
	 * marker): each is moved into {@code destDir} after the {@code .rep} and before the
	 * {@code .gpr}, so they are in place at the commit point and are removed with the
	 * {@code .rep} when the publish fails.
	 *
	 * @param extras names of files in the staging folder (not the project's own)
	 */
	static void publish(Staged st, File destDir, String name, JsonObject sidecar,
			String completeState, List<String> extras) throws IOException {
		String ext = ProjectLocator.getProjectExtension();
		String repExt = ProjectLocator.getProjectDirExtension();
		Path stagedRep = st.dir().toPath().resolve(st.sourceName() + repExt);
		Path stagedGpr = st.dir().toPath().resolve(st.sourceName() + ext);
		Path destRep = destDir.toPath().resolve(name + repExt);
		Path destGpr = destDir.toPath().resolve(name + ext);
		File sc = sidecar(new ProjectResolver.Resolved(destDir, name));
		// a folder carries one backup manifest and one seal marker: refuse before anything of
		// ours is moved, and never touch a file we did not move
		for (String extra : extras) {
			if (Files.exists(destDir.toPath().resolve(extra), LinkOption.NOFOLLOW_LINKS)) {
				throw new IOException("the destination folder already holds " + extra +
					" (one backup or sealed project per folder)");
			}
		}
		List<String> moved = new ArrayList<>();
		// E12: every staged byte and name is on the disk before anything is moved, so that the
		// .gpr (the commit point) can never be durable while a file it names is not
		forceTree(st.dir().toPath());
		// the intent says the .rep may be ours from here on, and which one it is
		st.intent().withPhase(ForkIntent.MOVING, ForkSweeper.creationMs(stagedRep))
				.write(st.dir().toPath());
		try {
			moveRetrying(stagedRep, destRep);
		}
		catch (FileAlreadyExistsException e) {
			throw new RaceLost("another publisher holds " + destRep);
		}
		pauseBetweenRenames();
		boolean committed = false;
		try {
			sidecar.addProperty("forkId", st.id());
			sidecar.addProperty("state", STATE_PUBLISHING);
			writeSidecar(sc, sidecar);
			for (String extra : extras) {
				Files.move(st.dir().toPath().resolve(extra), destDir.toPath().resolve(extra));
				moved.add(extra);
			}
			syncDirectory(destDir.toPath()); // the .rep, the sidecar and the extras before the .gpr
			moveRetrying(stagedGpr, destGpr);
			committed = true;
			syncDirectory(destDir.toPath()); // the commit itself
		}
		finally {
			if (!committed) {
				// the rollback must end with nothing of ours at the destination even when a
				// reader holds the sidecar open (F1: one attempt could leave a sidecar alone)
				removeRetrying(destRep);
				removeRetrying(sc.toPath());
				removeRetrying(Path.of(sc.getPath() + ".tmp"));
				for (String extra : moved) {
					removeRetrying(destDir.toPath().resolve(extra));
				}
			}
		}
		sidecar.addProperty("state", completeState);
		IOException last = null;
		for (int i = 0; i < RETRIES; i++) {
			try {
				writeSidecar(sc, sidecar);
				return;
			}
			catch (IOException e) {
				// a handle holder on the sidecar (a scanner reading it) stops the rename over
				// it for a moment: the same backoff as the moves, 25 ms doubling, and no pause
				// after the last attempt (the waits add up to 1575 ms, which is the 1.6 s the
				// tests and the protocol text call the retry budget)
				last = e;
				if (i == RETRIES - 1) {
					break;
				}
				try {
					Thread.sleep(25L << i);
				}
				catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}
		// the fork is committed; a sidecar that still says "publishing" is finished by the next
		// sweep of the name (the staging folder is kept for it: its intent proves the fork ours)
		// or, once this process is gone, by any sweep
		st.unfinished().set(true);
		ghidra.util.Msg.warn(ProjectFork.class,
			"fork_project: could not finish the sidecar of " + destGpr + ": " + last);
	}

	/**
	 * Forces every file of {@code root} to the disk, then every folder of it (deepest first), so
	 * that after a power loss a file of the tree is either absent or has exactly the content that
	 * was copied (E12: {@link Files#copy} does not flush). A read-only file (a Ghidra version file
	 * copied with its attributes) is made writable for the flush and read-only again: on Windows
	 * {@code FlushFileBuffers} needs a handle with write access, and a read-only channel's
	 * {@code force} does nothing there.
	 *
	 * @throws IOException when a file cannot be forced (nothing has been moved yet: the caller
	 *             discards the staging folder)
	 */
	static void forceTree(Path root) throws IOException {
		List<Path> dirs = new ArrayList<>();
		Files.walkFileTree(root, new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult visitFile(Path f, java.nio.file.attribute.BasicFileAttributes a)
					throws IOException {
				if (a.isRegularFile()) {
					forceFile(f);
				}
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path d, IOException e) throws IOException {
				if (e != null) {
					throw e;
				}
				dirs.add(d);
				return FileVisitResult.CONTINUE;
			}
		});
		for (Path d : dirs) {
			syncDirectory(d);
		}
	}

	private static final boolean WINDOWS =
		System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");

	/** Forces one file's content and length to the disk (see {@link #forceTree}). */
	static void forceFile(Path f) throws IOException {
		if (!WINDOWS) {
			try (java.nio.channels.FileChannel ch =
				java.nio.channels.FileChannel.open(f, StandardOpenOption.READ)) {
				ch.force(true); // fsync works on any descriptor
			}
			return;
		}
		java.nio.file.attribute.DosFileAttributeView v = Files.getFileAttributeView(f,
			java.nio.file.attribute.DosFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
		boolean ro = v != null && v.readAttributes().isReadOnly();
		if (ro) {
			v.setReadOnly(false);
		}
		try (java.nio.channels.FileChannel ch =
			java.nio.channels.FileChannel.open(f, StandardOpenOption.WRITE)) {
			ch.force(true);
		}
		finally {
			if (ro) {
				v.setReadOnly(true);
			}
		}
	}

	/**
	 * Forces the entries of a folder (its names) to the disk where the platform allows it: a
	 * folder opened for reading and forced ({@code fsync} of the directory on Linux and macOS).
	 * Windows cannot open a folder as a channel, so there it does nothing and the order of the
	 * names rests on the file system (directory-entry model J of {@code dt_e12.py}, an assumption
	 * nothing measures). Never throws.
	 */
	static void syncDirectory(Path dir) {
		try (java.nio.channels.FileChannel ch =
			java.nio.channels.FileChannel.open(dir, StandardOpenOption.READ)) {
			ch.force(true);
		}
		catch (IOException | RuntimeException e) {
			// not supported here (Windows: AccessDeniedException)
		}
	}

	/**
	 * A move that survives a handle holder (an indexer or antivirus scanner holds a file of the
	 * source for a moment: {@link AccessDeniedException} or a sharing violation) by retrying a few
	 * times with a growing pause. {@link FileAlreadyExistsException} is not retried.
	 */
	private static void moveRetrying(Path from, Path to) throws IOException {
		IOException last = null;
		for (int i = 0; i < RETRIES; i++) {
			try {
				Files.move(from, to);
				return;
			}
			catch (FileAlreadyExistsException | NoSuchFileException e) {
				throw e;
			}
			catch (FileSystemException e) {
				if (Files.exists(to)) {
					throw new FileAlreadyExistsException(to.toString());
				}
				last = e;
				if (i == RETRIES - 1) {
					break; // no pause after the last attempt
				}
				try {
					Thread.sleep(25L << i);
				}
				catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw e;
				}
			}
		}
		throw last;
	}

	private static void warnLeft(File tmp) {
		if (tmp.exists()) {
			ghidra.util.Msg.warn(ProjectFork.class,
				"fork_project: could not remove the temporary folder " + tmp);
		}
	}
}
