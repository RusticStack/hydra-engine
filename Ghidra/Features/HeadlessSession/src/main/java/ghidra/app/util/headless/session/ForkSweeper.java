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

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;

import ghidra.framework.model.ProjectLocator;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * The publishers in this process and the lazy sweeper of {@code fork_project} (PROTOCOL-3.md D41,
 * package E2a).
 * <p>
 * <b>Who is publishing.</b> {@link #admit} decides, under the monitor of the destination (one
 * of {@link #GATES}, so that requests for other destinations never wait for it), whether a
 * request may publish a destination: a destination that another request of this process holds, or that
 * another process's live intent names, answers "in progress"; a destination that exists answers
 * "exists"; otherwise the request holds a {@link Claim} until it releases it. The claim keeps
 * racing requests of one daemon from copying the same project six times; across processes the
 * atomic move of the {@code .rep} is the arbiter and the loser's intent is the staging folder it
 * removes.
 * <p>
 * <b>The sweeper.</b> Removes only what the engine created and can prove dead, and reports the rest:
 * <ul>
 * <li>a staging folder {@code .<name>.fork-<id>.tmp} whose intent names a dead process (or has no
 * intent and is older than {@link #AGE_MS}), and, when that intent says the {@code .rep} was
 * moved ({@link ForkIntent#MOVING}) and the {@code .rep} at the destination is the one it moved
 * (same creation time), with no {@code .gpr} and no live intent for the name, that {@code .rep}
 * and its sidecar;</li>
 * <li>a fork whose {@code .gpr} is in place but whose sidecar still says {@code publishing} and
 * whose intent names a dead process: the sidecar is rewritten {@code complete} (the {@code .gpr} is
 * the commit point, so the fork is complete; this finishes what the dead publisher did);</li>
 * <li>the temporary file {@code <name>.fork.json.<pid>.tmp} (or {@code SEALED.json.<pid>.tmp}) of a
 * sidecar write whose process is gone (8.13, A62);</li>
 * <li>{@code tmp*.tmp}, {@code tmp*.ps} and {@code .ghidra.test.lock~~} older than
 * {@link #AGE_MS} in the parent directory.</li>
 * </ul>
 * Everything else (a {@code .rep} without a {@code .gpr} and without such an intent, a
 * {@code .gpr} without a sidecar) is only reported, in the log. The first {@code fork_project}
 * under a parent directory sweeps the whole directory; every one sweeps the staging folders of its
 * own destination name.
 */
final class ForkSweeper {

	/** The age before a temporary file or an intent-less staging folder is the engine's to remove. */
	static final long AGE_MS = 10L * 60 * 1000;
	private static final Pattern TMP_FILE = Pattern.compile("tmp.*\\.(tmp|ps)");
	private static final String TEST_LOCK = ".ghidra.test.lock~~";

	private static final Map<String, Claim> CLAIMS = new ConcurrentHashMap<>();
	private static final Set<String> SWEPT = ConcurrentHashMap.newKeySet();

	private ForkSweeper() {
	}

	// ---- publishers in this process ----------------------------------------------------

	/** A destination held by one request of this process. */
	static final class Claim {
		final String key;
		final String id;
		final String rk;
		private final CountDownLatch done = new CountDownLatch(1);

		private Claim(String key, String id, String rk) {
			this.key = key;
			this.id = id;
			this.rk = rk;
		}

		/** Gives the destination up (also when the publish failed); wakes the waiters. */
		void release() {
			CLAIMS.remove(key, this);
			done.countDown();
		}
	}

	/** Why a destination cannot be claimed now. */
	enum Kind {
		/** The caller holds the destination ({@link Admission#claim}). */
		CLAIMED,
		/** A complete fork, or a folder that is not the engine's half fork, is there. */
		EXISTS,
		/** Another request of this or of another process is publishing it. */
		IN_PROGRESS
	}

	/**
	 * The outcome of {@link #admit}: {@code rk} is the idempotency key of the publisher in
	 * progress (null for none), {@code owner} describes it for the error details.
	 */
	record Admission(Kind kind, Claim claim, String rk, JsonObject owner) {
	}

	/**
	 * The monitors of {@link #admit}, one per destination by the hash of its key: a request takes
	 * only its destination's, so that an admission that reads a slow folder holds up no fork to
	 * another destination (it was one monitor for the process). Two destinations may share a
	 * monitor, which costs a wait and never a wrong answer. Four to eight per granted CPU, a power
	 * of two.
	 */
	private static final Object[] GATES = new Object[Integer
			.highestOneBit(Math.max(1, Runtime.getRuntime().availableProcessors()) * 8 - 1)];
	static {
		Arrays.setAll(GATES, i -> new Object());
	}

	/** The monitor of {@link #admit} for the destination {@code key}. */
	static Object gate(String key) {
		int h = key.hashCode();
		return GATES[(h ^ (h >>> 16)) & (GATES.length - 1)];
	}

	/**
	 * Decides who publishes {@code <destDir>/<name>}. The in-process claim is taken under the
	 * destination's monitor together with the checks, so that of six racing requests exactly one
	 * claims.
	 */
	static Admission admit(File destDir, String name, String id, String rk) throws IOException {
		String key = destDir.getCanonicalPath() + File.separator + name;
		synchronized (gate(key)) {
			return admit(key, destDir, name, id, rk);
		}
	}

	private static Admission admit(String key, File destDir, String name, String id, String rk) {
		Claim other = CLAIMS.get(key);
		if (other != null) {
			return new Admission(Kind.IN_PROGRESS, null, other.rk,
				Json.of("id", other.id, "pid", ProcessHandle.current().pid(), "scope", "daemon"));
		}
		Optional<ForkIntent> live = livePublisher(destDir, name, id);
		if (live.isPresent()) {
			ForkIntent i = live.get();
			return new Admission(Kind.IN_PROGRESS, null, i.rk(),
				Json.of("id", i.id(), "pid", i.pid(), "scope", "process"));
		}
		if (exists(destDir, name)) {
			return new Admission(Kind.EXISTS, null, null, null);
		}
		Claim mine = new Claim(key, id, rk);
		CLAIMS.put(key, mine);
		return new Admission(Kind.CLAIMED, mine, rk, null);
	}

	/**
	 * Waits (up to {@code ms}, polling every 50 ms) until the destination is no longer held by
	 * a publisher of this process, or its intent in another process is gone. False when the time
	 * ran out.
	 */
	static boolean awaitIdle(File destDir, String name, long ms, RequestMonitor m)
			throws IOException, ghidra.util.exception.CancelledException {
		String key = destDir.getCanonicalPath() + File.separator + name;
		long end = System.nanoTime() + ms * 1_000_000L;
		while (true) {
			m.checkCancelled();
			Claim c = CLAIMS.get(key);
			boolean busy;
			if (c != null) {
				busy = true;
				try {
					c.done.await(50, java.util.concurrent.TimeUnit.MILLISECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return false;
				}
			}
			else {
				busy = livePublisher(destDir, name, null).isPresent();
				if (busy) {
					try {
						Thread.sleep(50);
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						return false;
					}
				}
			}
			if (!busy) {
				return true;
			}
			if (System.nanoTime() > end) {
				return false;
			}
		}
	}

	/** True when the destination holds anything of a project of that name. */
	static boolean exists(File destDir, String name) {
		return new File(destDir, name + ProjectLocator.getProjectExtension()).exists() ||
			new File(destDir, name + ProjectLocator.getProjectDirExtension()).exists() ||
			ProjectFork.sidecar(new ProjectResolver.Resolved(destDir, name)).exists();
	}

	/**
	 * True when {@code i} belongs to a publisher that is running now. Another process's intent
	 * is live while that process runs. An intent of this very process is live only while a
	 * {@link Claim} of this process holds its id: a staging folder this process left behind (its
	 * delete failed, for example against a handle holder) is nobody's work in progress, and must
	 * neither block a retry of the name nor survive the sweeper for as long as the daemon runs
	 * (the same holds for such a folder whose intent the failed delete already removed).
	 */
	static boolean isLive(ForkIntent i) {
		if (!i.ownerAlive()) {
			return false;
		}
		if (i.pid() != ProcessHandle.current().pid()) {
			return true;
		}
		for (Claim c : CLAIMS.values()) {
			if (c.id.equals(i.id())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A live intent for {@code name} in {@code destDir}, written by a running process (this one
	 * included, except the intent {@code exceptId}; see {@link #isLive}).
	 */
	static Optional<ForkIntent> livePublisher(File destDir, String name, String exceptId) {
		File[] kids = destDir.listFiles();
		if (kids == null) {
			return Optional.empty();
		}
		for (File k : kids) {
			if (!k.isDirectory() || !ForkIntent.isStagingName(k.getName())) {
				continue;
			}
			Optional<ForkIntent> i = ForkIntent.read(k.toPath());
			if (i.isPresent() && i.get().name().equals(name) && !i.get().id().equals(exceptId) &&
				isLive(i.get())) {
				return i;
			}
		}
		return Optional.empty();
	}

	// ---- the sweep ----------------------------------------------------------------------

	/** What a sweep did, for the log and for tests. */
	record Report(List<String> removed, List<String> resumed, List<String> reported) {
		boolean empty() {
			return removed.isEmpty() && resumed.isEmpty() && reported.isEmpty();
		}
	}

	/**
	 * The sweep that goes with a {@code fork_project} to {@code <destDir>/<name>}: the whole
	 * directory the first time this process forks under it, afterwards the staging folders of
	 * {@code name} only.
	 */
	static Report sweepFor(File destDir, String name) {
		String parent;
		try {
			parent = destDir.getCanonicalPath();
		}
		catch (IOException e) {
			parent = destDir.getAbsolutePath();
		}
		boolean first = SWEPT.add(parent);
		return sweep(destDir, first ? null : name);
	}

	// ---- 8.13: the sweep also runs at daemon start and at open_project ----------------------

	/** The folder under the state directory that names every directory this engine forked into. */
	static final String PARENTS = "fork-parents";

	/**
	 * Records {@code destDir} under {@code <stateDir>/fork-parents/} before anything is staged in it,
	 * so that the next start of a daemon on this state directory sweeps it even when no other
	 * {@code fork_project} or {@code open_project} ever names it again (8.13). One file per
	 * directory, named by the hash of its canonical path; a daemon without a state directory
	 * records nothing.
	 */
	static void registerParent(File destDir) {
		Path dir = parentsDir();
		if (dir == null) {
			return;
		}
		try {
			String canon = destDir.getCanonicalPath();
			Path f = dir.resolve(key(canon));
			if (!Files.exists(f)) {
				Files.createDirectories(dir);
				Path tmp = dir.resolve(f.getFileName() + "." + ProcessHandle.current().pid() + ".tmp");
				Files.writeString(tmp, canon, java.nio.charset.StandardCharsets.UTF_8);
				Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			}
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(ForkSweeper.class, "fork_project: could not record " + destDir +
				" for the start-up sweep: " + e);
		}
	}

	/**
	 * The start-up sweep (8.13): every directory recorded by {@link #registerParent} is swept as
	 * the first {@code fork_project} under it would sweep it. A record whose directory is gone, or
	 * holds no staging folder after the sweep, is dropped. Never throws.
	 *
	 * @return what was removed, resumed and reported, per directory
	 */
	static JsonObject sweepAtStart() {
		JsonObject out = new JsonObject();
		Path dir = parentsDir();
		if (dir == null || !Files.isDirectory(dir)) {
			return out;
		}
		File[] recs = dir.toFile().listFiles((d, n) -> !n.endsWith(".tmp"));
		if (recs == null) {
			return out;
		}
		for (File rec : recs) {
			try {
				File parent = new File(Files.readString(rec.toPath(),
					java.nio.charset.StandardCharsets.UTF_8).trim());
				if (!parent.isDirectory()) {
					Files.deleteIfExists(rec.toPath());
					continue;
				}
				Report r = sweep(parent, null);
				if (!r.empty()) {
					out.add(parent.getPath(), Json.of("removed", r.removed(), "resumed",
						r.resumed(), "reported", r.reported()));
				}
				File[] staging = parent.listFiles(f -> f.isDirectory() &&
					ForkIntent.isStagingName(f.getName()));
				if (staging != null && staging.length == 0) {
					Files.deleteIfExists(rec.toPath());
				}
			}
			catch (IOException | RuntimeException e) {
				Msg.warn(ForkSweeper.class, "start-up fork sweep of " + rec + ": " + e);
			}
		}
		if (out.size() > 0) {
			Msg.info(ForkSweeper.class, "start-up fork sweep: " + out);
		}
		return out;
	}

	/**
	 * The sweep at {@code open_project} (8.13): the directory that holds the project named by
	 * {@code path} (a {@code .gpr}, a {@code .rep} or a directory) is swept whole. Never throws: an
	 * open never fails because of the sweep.
	 */
	static void sweepForOpen(String path) {
		if (path == null) {
			return;
		}
		try {
			File f = new File(path).getAbsoluteFile();
			String n = f.getName();
			File dir = n.endsWith(ProjectLocator.getProjectExtension()) ||
				n.endsWith(ProjectLocator.getProjectDirExtension()) ? f.getParentFile() : f;
			if (dir != null && dir.isDirectory()) {
				sweep(dir, null);
			}
		}
		catch (RuntimeException e) {
			Msg.warn(ForkSweeper.class, "open_project: fork sweep of " + path + ": " + e);
		}
	}

	private static Path parentsDir() {
		String state = Json.str(Identity.paths(), "stateDir", null);
		return state == null ? null : Path.of(state, PARENTS);
	}

	private static String key(String canon) {
		try {
			byte[] h = java.security.MessageDigest.getInstance("SHA-256")
				.digest(canon.toLowerCase(Locale.ROOT).getBytes(java.nio.charset.StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(h, 0, 16);
		}
		catch (java.security.NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	/** Sweeps {@code destDir}; {@code onlyName} restricts it to the staging folders of one fork. */
	static Report sweep(File destDir, String onlyName) {
		Report r = new Report(new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
		File[] kids = destDir.listFiles();
		if (kids == null) {
			return r;
		}
		long now = System.currentTimeMillis();
		for (File k : kids) {
			try {
				if (k.isDirectory() && ForkIntent.isStagingName(k.getName())) {
					staging(destDir, k, onlyName, now, r);
				}
				else if (k.isFile() && deadWritersTmp(k, onlyName)) {
					// 8.13 (A62): a sidecar or seal marker write whose process is gone
					Files.deleteIfExists(k.toPath());
					r.removed().add(k.getName());
				}
				else if (onlyName == null && k.isFile() && old(k, now) &&
					(TMP_FILE.matcher(k.getName()).matches() || k.getName().equals(TEST_LOCK))) {
					Files.deleteIfExists(k.toPath());
					r.removed().add(k.getName());
				}
			}
			catch (IOException | RuntimeException e) {
				r.reported().add(k.getName() + ": " + e);
			}
		}
		if (onlyName == null) {
			for (File k : kids) {
				String n = k.getName();
				String repExt = ProjectLocator.getProjectDirExtension();
				if (k.isDirectory() && n.endsWith(repExt) && !n.startsWith(".") &&
					!new File(destDir, n.substring(0, n.length() - repExt.length()) +
						ProjectLocator.getProjectExtension()).exists() &&
					k.exists()) {
					r.reported().add(n + ": a .rep without a .gpr (not removed: no dead intent " +
						"of this engine names it)");
				}
			}
		}
		if (!r.empty()) {
			Msg.info(ForkSweeper.class, "fork_project: swept " + destDir + ": removed " +
				r.removed() + ", resumed " + r.resumed() + ", left (reported) " + r.reported());
		}
		return r;
	}

	/** {@code <x>.fork.json.<pid>.tmp} or {@code <seal marker>.<pid>.tmp} ({@link ProjectFork#tmpOf}). */
	private static final Pattern WRITER_TMP = Pattern.compile("(.+)\\.(\\d{1,10})\\.tmp");

	/**
	 * 8.13 (A62): true for the temporary file of a sidecar (or seal marker) write whose writer is
	 * gone: the process its name gives is not running, or started after the file was made (a
	 * reused id). A live writer's file, this process's included, is never one. With
	 * {@code onlyName}, only that fork's sidecar is looked at.
	 */
	static boolean deadWritersTmp(File f, String onlyName) {
		java.util.regex.Matcher m = WRITER_TMP.matcher(f.getName());
		if (!m.matches()) {
			return false;
		}
		String base = m.group(1);
		boolean sidecar = base.endsWith(ProjectFork.SIDECAR_SUFFIX) &&
			(onlyName == null || base.equals(onlyName + ProjectFork.SIDECAR_SUFFIX));
		boolean marker = onlyName == null && base.equals(Seals.MARKER);
		if (!sidecar && !marker) {
			return false;
		}
		long pid;
		try {
			pid = Long.parseLong(m.group(2));
		}
		catch (NumberFormatException e) {
			return false;
		}
		return !pidOwnsFolder(pid, f);
	}

	private static long ownPid() {
		return ProcessHandle.current().pid();
	}

	/**
	 * True for a staging folder of this very process (the pid in its name) that no publish of this
	 * process holds: nobody is working in it, whatever its intent says or lacks.
	 */
	private static boolean ownIdle(String folderName) {
		String id = ForkIntent.idOf(folderName);
		return ForkIntent.pidOf(folderName) == ownPid() && id != null &&
			CLAIMS.values().stream().noneMatch(c -> c.id.equals(id));
	}

	/**
	 * True when process {@code pid} can be the publisher that made {@code folder}: it is running
	 * <b>and started before the folder was created</b> (within {@link ForkIntent#START_TOLERANCE_MS}).
	 * A process id alone proves nothing, because ids are reused: a folder that is older than the
	 * running process with that id was made by a process that is gone (the same rule
	 * {@link ForkIntent#ownerAlive} applies to a folder with an intent, which has the creation time
	 * recorded; here the folder's own creation time stands in for it). A start or creation time
	 * that cannot be read falls back to the id alone, which can only err towards "alive", the safe
	 * side for a sweeper.
	 */
	static boolean pidOwnsFolder(long pid, File folder) {
		Optional<ProcessHandle> h = ProcessHandle.of(pid);
		if (h.isEmpty() || !h.get().isAlive()) {
			return false;
		}
		Optional<java.time.Instant> start = h.get().info().startInstant();
		long created = creationMs(folder.toPath());
		if (start.isEmpty() || created <= 0) {
			return true;
		}
		return start.get().toEpochMilli() <= created + ForkIntent.START_TOLERANCE_MS;
	}

	private static boolean old(File f, long now) {
		return now - f.lastModified() > AGE_MS;
	}

	private static void staging(File destDir, File folder, String onlyName, long now, Report r)
			throws IOException {
		Optional<ForkIntent> oi = ForkIntent.read(folder.toPath());
		if (oi.isEmpty()) {
			// the engine made this folder (the name says so) and was killed before its intent
			// was written, or the record is damaged. The process id in the name settles the first
			// case; a damaged record of a live process is left until it is old
			String fn = folder.getName();
			if (onlyName != null && !onlyName.equals(fn.substring(1, fn.lastIndexOf(".fork-"))) &&
				!ownIdle(fn)) {
				return;
			}
			long pid = ForkIntent.pidOf(folder.getName());
			boolean dead = pid > 0 && !pidOwnsFolder(pid, folder);
			// a folder of this very process that no publish of this process holds: its delete
			// failed part way (against a handle holder, SP6) and took the intent with it. Nobody
			// is working in it, and waiting for it to grow old would block the K6 invariant
			dead |= ownIdle(fn);
			if (dead || old(folder, now)) {
				FileUtilities.deleteDir(folder);
				note(folder, r, "staging folder without an intent");
			}
			else {
				r.reported().add(folder.getName() + ": no intent, owner may be alive, not yet old");
			}
			return;
		}
		ForkIntent i = oi.get();
		if (onlyName != null && !i.name().equals(onlyName) &&
			!(i.pid() == ownPid() && !isLive(i))) {
			// another name's folder: only this process's own idle leftovers are every fork's
			// business
			return;
		}
		if (isLive(i)) {
			return; // a live publisher, this process (a claim holds it) or another: never touched
		}
		String name = i.name();
		Path rep = destDir.toPath().resolve(name + ProjectLocator.getProjectDirExtension());
		Path gpr = destDir.toPath().resolve(name + ProjectLocator.getProjectExtension());
		File sidecar = ProjectFork.sidecar(new ProjectResolver.Resolved(destDir, name));
		boolean liveOther = livePublisher(destDir, name, i.id()).isPresent();
		if (Files.exists(gpr)) {
			// the commit point was passed: the fork is complete, finish what the publisher did
			JsonObject sc = ProjectFork.readSidecar(new ProjectResolver.Resolved(destDir, name));
			boolean mine = sc != null && i.id().equals(Json.str(sc, "forkId", null));
			if (mine && ProjectFork.STATE_PUBLISHING.equals(Json.str(sc, "state", null))) {
				sc.addProperty("state", ProjectFork.STATE_COMPLETE);
				ProjectFork.writeSidecar(sidecar, sc);
				r.resumed().add(name);
			}
			// 8.13: the dead publisher's temporary sidecar (killed between the write of
			// <name>.fork.json.<pid>.tmp, or <name>.fork.json.tmp of an older build, and its
			// rename) is removed with its staging folder
			for (Path scTmp : List.of(Path.of(sidecar.getPath() + ".tmp"),
				ProjectFork.tmpOf(sidecar, i.pid()).toPath())) {
				if (mine && Files.deleteIfExists(scTmp)) {
					r.removed().add(scTmp.getFileName().toString());
				}
			}
		}
		else if (ForkIntent.MOVING.equals(i.phase()) && Files.isDirectory(rep) && !liveOther) {
			if (i.repCreatedMs() > 0 && creationMs(rep) == i.repCreatedMs()) {
				FileUtilities.deleteDir(rep.toFile());
				Files.deleteIfExists(sidecar.toPath());
				Files.deleteIfExists(Path.of(sidecar.getPath() + ".tmp"));
				Files.deleteIfExists(ProjectFork.tmpOf(sidecar, i.pid()).toPath());
				// a backup moves its manifest and seal marker in before the .gpr (E2): with no
				// .gpr they belong to the half fork that is going, if they name it
				removeIfNamed(destDir.toPath().resolve(ProjectBackup.FILE), name, true);
				removeIfNamed(destDir.toPath().resolve(Seals.MARKER), name, false);
				r.removed().add(rep.getFileName().toString());
			}
			else {
				r.reported().add(rep.getFileName() + ": a .rep without a .gpr that the intent " +
					i.id() + " cannot be shown to have made");
			}
		}
		FileUtilities.deleteDir(folder);
		note(folder, r, "staging folder of a dead publisher (pid " + i.pid() + ")");
	}

	/**
	 * Removes {@code backup.json} or {@code SEALED.json} that the half fork {@code name} left. Both
	 * names are per folder, not per project, so a file that another project of the folder wrote is
	 * left alone: the marker must name the project, the manifest must list its files.
	 */
	private static void removeIfNamed(Path f, String name, boolean manifest) throws IOException {
		if (!Files.isRegularFile(f)) {
			return;
		}
		try {
			com.google.gson.JsonObject o = com.google.gson.JsonParser.parseString(
				Files.readString(f, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
			boolean ours;
			if (manifest) {
				ours = false;
				for (com.google.gson.JsonElement e : o.getAsJsonArray("files")) {
					String p = e.getAsJsonObject().get("path").getAsString();
					ours = p.equals(name + ".gpr") || p.startsWith(name + ".rep/");
					break;
				}
			}
			else {
				ours = name.equals(Json.str(o, "name", null));
			}
			if (ours) {
				f.toFile().setWritable(true);
				Files.deleteIfExists(f);
			}
		}
		catch (RuntimeException e) {
			// not ours to judge: left in place
		}
	}

	private static void note(File folder, Report r, String what) {
		if (folder.exists()) {
			r.reported().add(folder.getName() + ": could not remove (" + what + ")");
		}
		else {
			r.removed().add(folder.getName());
		}
	}

	/**
	 * Removes this request's own staging folder by name; the safety net for a copy that failed
	 * before {@link ProjectFork#stage} could return it.
	 */
	static void removeStagingFolder(File destDir, String name, String id) {
		File f = new File(destDir, ForkIntent.stagingName(name, id));
		if (f.exists()) {
			FileUtilities.deleteDir(f);
		}
	}

	/** The creation time of a file or folder in ms, or -1 when it cannot be read. */
	static long creationMs(Path p) {
		try {
			return Files.readAttributes(p, BasicFileAttributes.class).creationTime().toMillis();
		}
		catch (IOException e) {
			return -1;
		}
	}
}
