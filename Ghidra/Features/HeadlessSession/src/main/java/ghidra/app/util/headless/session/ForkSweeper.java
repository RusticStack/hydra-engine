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
 * <b>Who is publishing.</b> {@link #admit} decides, under one monitor, whether a request may
 * publish a destination: a destination that another request of this process holds, or that
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
	 * Decides who publishes {@code <destDir>/<name>}. The in-process claim is taken under a
	 * monitor together with the checks, so that of six racing requests exactly one claims.
	 */
	static synchronized Admission admit(File destDir, String name, String id, String rk)
			throws IOException {
		String key = destDir.getCanonicalPath() + File.separator + name;
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
			boolean dead = pid > 0 && ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true);
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
			if (sc != null && ProjectFork.STATE_PUBLISHING.equals(Json.str(sc, "state", null)) &&
				i.id().equals(Json.str(sc, "forkId", null))) {
				sc.addProperty("state", ProjectFork.STATE_COMPLETE);
				ProjectFork.writeSidecar(sidecar, sc);
				r.resumed().add(name);
			}
		}
		else if (ForkIntent.MOVING.equals(i.phase()) && Files.isDirectory(rep) && !liveOther) {
			if (i.repCreatedMs() > 0 && creationMs(rep) == i.repCreatedMs()) {
				FileUtilities.deleteDir(rep.toFile());
				Files.deleteIfExists(sidecar.toPath());
				Files.deleteIfExists(Path.of(sidecar.getPath() + ".tmp"));
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
