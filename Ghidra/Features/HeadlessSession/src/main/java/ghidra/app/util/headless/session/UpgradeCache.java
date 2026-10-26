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
import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

import com.google.gson.*;

import db.DBHandle;
import ghidra.framework.Application;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.local.LocalDatabaseItem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import utilities.util.FileUtilities;

/**
 * Serves read-only opens of programs saved in an older database format from an upgraded copy,
 * built in the background.
 * <p>
 * Opened read-only, such a program is upgraded in memory on every open, which for a large program
 * takes many times longer than the open itself. The cache does that work once, without making
 * any open wait for it:
 * <ol>
 * <li>The first read-only open upgrades the program in memory, as without the cache, answers, and
 * starts a <b>build</b> ({@link #startBuild}).</li>
 * <li>The build runs on one background thread, in a slot of the scheduler's long lane, admitted
 * only when no client waits for that lane ({@link Scheduler#admitBackground}). It copies the
 * project (a block clone where the file system supports it, as ReFS does) into a temporary folder
 * {@code <root>/<key>/g<n>.tmp}, opens the program there writable, upgrades and saves it, checks
 * that the source did not change meanwhile, renames the folder to {@code <root>/<key>/g<n>} and
 * then names that generation in {@code <root>/<key>/entry.json} (written atomically). Readers only
 * open the generation that {@code entry.json} names, so they never see a half-written copy.</li>
 * <li>Later opens find the generation and open the program read-only from it
 * ({@link #openReady}).</li>
 * </ol>
 * A failed or cancelled build (shutdown, {@code cancel}, a source that changed) deletes its
 * temporary folder and is logged; the next open starts a new one. A build killed with its process
 * leaves its temporary folder, which the next build of that key (or the next start) removes. The
 * source project is only read.
 * <p>
 * <b>Generations.</b> Each further program of the same source is upgraded in a new copy of the
 * current generation (another block clone), so a published generation is never written again;
 * older generations are removed once no daemon reads from them.
 * <p>
 * <b>Key.</b> The source's identity: the canonical path of its {@code .gpr}, this Ghidra's version,
 * build and program database version, and every file of the {@code .gpr} and {@code .rep} with its
 * size and modification time, plus the SHA-256 of the content of every file up to
 * {@link #HASH_LIMIT} (the {@code .gpr}, properties and index files). Large database files are
 * written whole, never in place, so size and time identify them. Any change makes a new key; the
 * entries of older keys for the same source are removed when nobody uses them.
 * <p>
 * <b>Older format.</b> Decided before the program is opened, from the program's stored database
 * version and language version, read from its database without opening the program (a few
 * milliseconds).
 * <p>
 * <b>Several daemons</b> may share a root: a key is built under an exclusive OS lock on
 * {@code <key>.lock}, and a reader holds shared OS locks on {@code <key>.use} and
 * {@code <key>/<generation>.use} while it serves from a copy, so no daemon removes it meanwhile.
 */
final class UpgradeCache {

	/** Files up to this size are keyed by content as well as size and time. */
	static final long HASH_LIMIT = 1 << 20;
	private static final String ENTRY_FILE = "entry.json";
	private static final int ENTRY_FORMAT = 2;
	private static final String TMP_SUFFIX = ".tmp";
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
	/** Finished builds kept for {@code status}. */
	private static final int KEEP_FINISHED = 32;

	/** The current program database version, or -1 when it cannot be read (cache off). */
	private static final int CURRENT_DB_VERSION = currentDbVersion();

	private final File root;
	private final Scheduler scheduler;
	/** The scheduler's client for builds; no request of a real client. */
	private final Client buildClient = new Client(0, "internal", false, null);

	/**
	 * Shared OS locks this process holds, by lock file path relative to {@link #root}
	 * ({@code <key>.use}, {@code <key>/<generation>.use}), each counted.
	 */
	private final Map<String, Use> inUse = new HashMap<>();

	/** Builds by {@link Plan#id()}, oldest first. Guarded by this. */
	private final LinkedHashMap<String, Build> builds = new LinkedHashMap<>();
	private ExecutorService executor;
	private boolean closed;
	private long buildsStarted;

	private static final class Use {
		int count;
		FileChannel channel;
		FileLock lock;
	}

	/**
	 * @param root the cache directory, or null for no cache
	 * @param scheduler the session's scheduler: builds take a background slot of its long lane
	 */
	UpgradeCache(File root, Scheduler scheduler) {
		this.root = root;
		this.scheduler = scheduler;
		buildClient.name = "upgrade-cache";
		if (root != null && CURRENT_DB_VERSION < 0) {
			Msg.warn(this, "upgrade cache off: the program database version is not readable");
		}
		if (enabled() && root.isDirectory()) {
			executor().execute(this::sweep); // what killed builds left behind
		}
	}

	boolean enabled() {
		return root != null && CURRENT_DB_VERSION >= 0;
	}

	JsonObject describe() {
		JsonObject o = Json.of("enabled", enabled(), "dir", root == null ? null : root.getPath());
		JsonArray a = new JsonArray();
		synchronized (this) {
			builds.values().forEach(b -> a.add(b.describe()));
			Json.put(o, "buildsStarted", buildsStarted);
		}
		o.add("builds", a);
		return o;
	}

	// ---- plans ---------------------------------------------------------------------------------

	/** What one older-format program needs: its source, its key, and why. */
	record Plan(ProjectResolver.Resolved resolved, String canonical, String path, String key,
			String why) {
		String id() {
			return key + ":" + path;
		}
	}

	/**
	 * The plan for a read-only open of {@code df}, or null when the cache does not apply: it is
	 * off, the program is current, or it is versioned or a link.
	 */
	Plan plan(ProjectEntry p, DomainFile df) throws IOException {
		if (!enabled() || df.isVersioned() || df.isLink()) {
			return null;
		}
		String why = olderFormat(p.project.getProjectData(), df);
		if (why == null) {
			return null;
		}
		return new Plan(p.resolved, p.canonical, df.getPathname(), key(p.resolved), why);
	}

	// ---- opening from the cache ----------------------------------------------------------------

	/** Releases the shared locks of a program opened from the cache. Idempotent. */
	final class Lease {
		private final String keyUse;
		private final String genUse;
		private boolean keyHeld;
		private boolean genHeld;

		private Lease(String key, String gen) {
			this.keyUse = key + ".use";
			this.genUse = key + "/" + gen + ".use";
		}

		/** Takes both shared locks; false when the generation is being removed. */
		private synchronized boolean acquire() throws IOException {
			acquireUse(keyUse, true);
			keyHeld = true;
			genHeld = acquireUse(genUse, false);
			return genHeld;
		}

		synchronized void release() {
			if (genHeld) {
				genHeld = false;
				releaseUse(genUse);
			}
			if (keyHeld) {
				keyHeld = false;
				releaseUse(keyUse);
			}
		}
	}

	/** A program opened from the cache, with the read-only view of the copy that holds it. */
	record Opened(Program program, SessionProject view, Lease lease, JsonObject info) {}

	/**
	 * True when the cache holds an upgraded copy of the plan's program (built by this daemon or
	 * another), or a build of it in this daemon has just finished.
	 */
	boolean isReady(Plan plan) {
		synchronized (this) {
			Build b = builds.get(plan.id());
			if (b != null && b.state == State.READY) {
				return true;
			}
			if (b != null && b.state == State.BUILDING) {
				return false;
			}
		}
		JsonObject entry = readEntry(new File(root, plan.key()));
		return entry != null && upgraded(entry).contains(plan.path());
	}

	/**
	 * Opens the plan's program read-only from its upgraded copy, or returns null when there is
	 * none yet (the caller then upgrades it in memory and starts a build).
	 */
	Opened openReady(Plan plan, Object consumer, RequestMonitor m)
			throws IOException, CancelledException, VersionException {
		File dir = new File(root, plan.key());
		for (int attempt = 0; attempt < 3; attempt++) {
			JsonObject entry = readEntry(dir);
			if (entry == null || !upgraded(entry).contains(plan.path())) {
				return null;
			}
			String gen = entry.get("generation").getAsString();
			Lease lease = new Lease(plan.key(), gen);
			boolean ok = false;
			try {
				if (!lease.acquire()) {
					continue; // being removed: a newer generation is named meanwhile
				}
				File copyDir = new File(new File(dir, gen), "project");
				if (!copyDir.isDirectory()) {
					continue;
				}
				Opened o = openCopy(plan, copyDir, gen, consumer, lease, m);
				ok = true;
				return o;
			}
			finally {
				if (!ok) {
					lease.release();
				}
			}
		}
		return null;
	}

	private Opened openCopy(Plan plan, File copyDir, String gen, Object consumer, Lease lease,
			RequestMonitor m) throws IOException, CancelledException, VersionException {
		long t0 = System.nanoTime();
		ProjectLocator copy = new ProjectLocator(copyDir.getPath(), plan.resolved().name());
		SessionProject view = openProject(copy, false);
		Program program;
		try {
			DomainFile cdf = view.getProjectData().getFile(plan.path());
			if (cdf == null) {
				throw new IOException(plan.path() + " is missing from the upgrade cache copy " +
					copyDir);
			}
			String still = olderFormat(view.getProjectData(), cdf);
			if (still != null) {
				throw new IOException("the upgrade cache copy of " + plan.path() + " is still in " +
					"an older format (" + still + "): " + copyDir);
			}
			program = (Program) cdf.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, m);
		}
		catch (IOException | CancelledException | VersionException | RuntimeException e) {
			view.close();
			throw e;
		}
		JsonObject info = Json.of("used", true, "reason", plan.why(), "key", plan.key(),
			"generation", gen, "dir", copyDir.getParent(), "openMs",
			(System.nanoTime() - t0) / 1_000_000);
		return new Opened(program, view, lease, info);
	}

	/**
	 * Opens a project and gives the application's active project back to what it was. Nothing
	 * the session runs depends on the active project (imports hand their loader its project), so
	 * this needs no exclusion against imports.
	 */
	private static SessionProject openProject(ProjectLocator locator, boolean writable)
			throws IOException {
		Project previous = AppInfo.getActiveProject();
		try {
			return SessionProject.open(locator, writable);
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException("cannot open the upgrade cache copy " + locator + ": " + e, e);
		}
		finally {
			AppInfo.setActiveProject(previous);
		}
	}

	/** Takes (or counts) a shared lock; false when {@code wait} is false and it is not free. */
	private boolean acquireUse(String name, boolean wait) throws IOException {
		synchronized (inUse) {
			Use u = inUse.get(name);
			if (u == null) {
				Path file = root.toPath().resolve(name);
				Files.createDirectories(file.getParent());
				u = new Use();
				u.channel = FileChannel.open(file, StandardOpenOption.CREATE,
					StandardOpenOption.READ, StandardOpenOption.WRITE);
				try {
					u.lock = wait ? u.channel.lock(0, Long.MAX_VALUE, true)
							: u.channel.tryLock(0, Long.MAX_VALUE, true);
				}
				catch (IOException | RuntimeException e) {
					u.channel.close();
					throw e instanceof IOException io ? io : new IOException(e);
				}
				if (u.lock == null) {
					u.channel.close();
					return false;
				}
				inUse.put(name, u);
			}
			u.count++;
			return true;
		}
	}

	private void releaseUse(String name) {
		if (name == null) {
			return;
		}
		synchronized (inUse) {
			Use u = inUse.get(name);
			if (u == null || --u.count > 0) {
				return;
			}
			inUse.remove(name);
			try {
				if (u.lock != null) {
					u.lock.release();
				}
				u.channel.close();
			}
			catch (IOException e) {
				// closing the channel releases the lock anyway
			}
		}
	}

	private boolean usedHere(String name) {
		synchronized (inUse) {
			return inUse.containsKey(name);
		}
	}

	// ---- builds --------------------------------------------------------------------------------

	enum State {
		BUILDING, READY, FAILED;

		String json() {
			return name().toLowerCase();
		}
	}

	/** One background build of one program's upgraded copy. */
	static final class Build {
		final Plan plan;
		final RequestMonitor monitor = new RequestMonitor(null, null);
		final long createdAt = System.currentTimeMillis();
		final CountDownLatch done = new CountDownLatch(1);
		volatile State state = State.BUILDING;
		volatile String phase = "queued";
		volatile long startedAt;
		volatile long endedAt;
		volatile String error;
		volatile boolean cancelled;
		volatile String generation;
		final Map<String, Long> ms = new ConcurrentHashMap<>();

		Build(Plan plan) {
			this.plan = plan;
		}

		boolean finished() {
			return state != State.BUILDING;
		}

		JsonObject describe() {
			long now = System.currentTimeMillis();
			JsonObject o = Json.of("id", plan.id(), "key", plan.key(), "source", plan.canonical(),
				"program", plan.path(), "state", state.json(), "reason", plan.why());
			if (state == State.BUILDING) {
				Json.put(o, "phase", phase);
				Json.put(o, "message", monitor.getMessage());
				Json.put(o, "progress", monitor.getProgress());
				Json.put(o, "maximum", monitor.getMaximum());
			}
			Json.put(o, "ageMs", now - createdAt);
			if (startedAt > 0) {
				Json.put(o, "ms", (endedAt > 0 ? endedAt : now) - startedAt);
			}
			Json.put(o, "error", error);
			Json.put(o, "cancelled", cancelled);
			Json.put(o, "generation", generation);
			JsonObject phases = new JsonObject();
			ms.forEach(phases::addProperty);
			o.add("phaseMs", phases);
			return o;
		}
	}

	/** The build a request found or started; {@code started} when this call started it. */
	record Start(Build build, boolean started) {}

	/**
	 * Starts a build of the plan's program unless one is already running in this daemon (one
	 * build per key and program) or its copy is ready. Returns null after {@link #shutdown}.
	 */
	Start startBuild(Plan plan) {
		synchronized (this) {
			if (closed) {
				return null;
			}
			Build b = builds.get(plan.id());
			if (b != null && (b.state == State.BUILDING || b.state == State.READY)) {
				return new Start(b, false);
			}
			b = new Build(plan);
			builds.remove(plan.id());
			builds.put(plan.id(), b);
			buildsStarted++;
			trimFinished();
			Build run = b;
			executor().execute(() -> run(run));
			Msg.info(this, "upgrade cache: build of " + plan.canonical() + " " + plan.path() +
				" queued (" + plan.why() + "), key " + plan.key());
			return new Start(b, true);
		}
	}

	/** The build of the plan in this daemon, or null. */
	synchronized Build build(Plan plan) {
		return builds.get(plan.id());
	}

	/**
	 * Waits until the build ends. Returns true when its copy is ready.
	 *
	 * @throws CancelledException when the waiting request is cancelled (the build goes on)
	 */
	boolean await(Build b, RequestMonitor m) throws CancelledException {
		while (true) {
			m.checkCancelled();
			try {
				if (b.done.await(100, TimeUnit.MILLISECONDS)) {
					return b.state == State.READY;
				}
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CancelledException();
			}
		}
	}

	/**
	 * Cancels the running builds that {@code which} names: a build id ({@code <key>:<path>}), a
	 * key, a program path, or {@code all}. Returns how many.
	 */
	int cancel(String which) {
		int n = 0;
		synchronized (this) {
			for (Build b : builds.values()) {
				if (b.finished()) {
					continue;
				}
				if (which.equals("all") || which.equals(b.plan.id()) ||
					which.equals(b.plan.key()) || which.equals(b.plan.path())) {
					b.cancelled = true;
					b.monitor.cancel();
					n++;
				}
			}
		}
		return n;
	}

	/**
	 * Cancels every build and waits up to {@code waitMs} for the running one to delete its
	 * temporary folder. A build that does not stop in time is left to the process exit; its
	 * folder is removed by the next build of its key or the next start.
	 */
	void shutdown(long waitMs) {
		ExecutorService ex;
		synchronized (this) {
			if (closed) {
				return;
			}
			closed = true;
			for (Build b : builds.values()) {
				if (!b.finished()) {
					b.cancelled = true;
					b.monitor.cancel();
				}
			}
			ex = executor;
		}
		if (ex == null) {
			return;
		}
		ex.shutdown();
		try {
			if (!ex.awaitTermination(waitMs, TimeUnit.MILLISECONDS)) {
				Msg.warn(this, "upgrade cache: a build did not stop within " + waitMs +
					" ms; its temporary folder is removed by the next start");
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private synchronized ExecutorService executor() {
		if (executor == null) {
			executor = Executors.newSingleThreadExecutor(r -> {
				Thread t = new Thread(r, "session-upgrade-cache");
				t.setDaemon(true);
				// Normal OS priority: a lower one let other processes' CPU load stall a build for
				// minutes. Its low priority is the scheduler's (Scheduler.admitBackground).
				return t;
			});
		}
		return executor;
	}

	/** Held: this. */
	private void trimFinished() {
		int finished = 0;
		for (Build b : builds.values()) {
			if (b.finished()) {
				finished++;
			}
		}
		Iterator<Build> it = builds.values().iterator();
		while (finished > KEEP_FINISHED && it.hasNext()) {
			if (it.next().finished()) {
				it.remove();
				finished--;
			}
		}
	}

	private static final class SourceChangedException extends IOException {
		SourceChangedException(String m) {
			super(m);
		}
	}

	/** How a build ended; {@link #finish} reports it once its temporary folder is gone. */
	private static final class Outcome {
		State state = State.FAILED;
		String error = "did not finish";
		String note;

		void set(State s, String e, String n) {
			state = s;
			error = e;
			note = n;
		}
	}

	/** The build itself, on the build thread. */
	private void run(Build b) {
		Outcome out = new Outcome();
		try {
			build(b, out);
		}
		catch (CancelledException | SessionException e) {
			if (e instanceof SessionException se && !se.code().equals(SessionException.CANCELLED)) {
				out.set(State.FAILED, se.getMessage(), null);
			}
			else {
				b.cancelled = true;
				out.set(State.FAILED, "cancelled" + (closed ? " (shutdown)" : ""), null);
			}
		}
		catch (SourceChangedException e) {
			out.set(State.FAILED, e.getMessage(), null);
		}
		catch (Throwable e) {
			if (b.cancelled || b.monitor.isCancelled()) {
				b.cancelled = true;
				out.set(State.FAILED, "cancelled" + (closed ? " (shutdown)" : "") + ": " + e,
					null);
			}
			else {
				Msg.error(this, "upgrade cache: build of " + b.plan.path() + " failed", e);
				out.set(State.FAILED, e.getClass().getSimpleName() + ": " + e.getMessage(), null);
			}
		}
		finally {
			finish(b, out.state, out.error, out.note);
		}
	}

	/**
	 * Takes the key's build lock and builds under it; the temporary folder is deleted before the
	 * lock is released, so that no other daemon's build of the key can be touched.
	 */
	private void build(Build b, Outcome out) throws Exception {
		Plan plan = b.plan;
		RequestMonitor m = b.monitor;
		b.startedAt = System.currentTimeMillis();
		File dir = new File(root, plan.key());
		m.checkCancelled();
		Files.createDirectories(dir.toPath());
		b.phase = "waiting for the build lock";
		try (FileChannel ch = FileChannel.open(new File(root, plan.key() + ".lock").toPath(),
			StandardOpenOption.CREATE, StandardOpenOption.WRITE);
				FileLock lock = lockWait(ch, m)) {
			File[] tmp = new File[1];
			try {
				buildLocked(b, dir, tmp, out);
			}
			finally {
				if (tmp[0] != null && tmp[0].exists() && !FileUtilities.deleteDir(tmp[0])) {
					Msg.warn(this, "upgrade cache: could not delete " + tmp[0] + "; the next " +
						"build of this key removes it");
				}
				String[] left = dir.list();
				if (left != null && left.length == 0) {
					dir.delete(); // a key that never got an entry; a builder recreates it
				}
			}
		}
	}

	/**
	 * The build, under the key's lock. {@code tmp[0]} is set to the temporary folder while there
	 * is one to delete.
	 */
	private void buildLocked(Build b, File dir, File[] tmp, Outcome out) throws Exception {
		Plan plan = b.plan;
		RequestMonitor m = b.monitor;
		JsonObject entry = readEntry(dir);
		if (entry != null && upgraded(entry).contains(plan.path())) {
			b.generation = entry.get("generation").getAsString();
			out.set(State.READY, null, "already built (by another daemon)");
			return;
		}
		removeLeftovers(dir, entry);
		b.phase = "waiting for a long slot";
		try (Scheduler.Ticket slot = scheduler.admitBackground(buildClient,
			"upgrade-cache build " + plan.path(), m)) {
			String gen = "g" + (entry == null ? 1 : generationNumber(entry) + 1);
			tmp[0] = new File(dir, gen + TMP_SUFFIX);
			File published = new File(dir, gen);
			if (published.exists()) {
				FileUtilities.deleteDir(published); // never named: a build killed at publish
			}
			// copy: the source, or the current generation (with earlier upgrades)
			b.phase = "copy";
			long t0 = System.nanoTime();
			File copyDir = new File(tmp[0], "project");
			Path from = entry == null ? plan.resolved().gpr().getParentFile().toPath()
					: new File(new File(dir, entry.get("generation").getAsString()), "project")
							.toPath();
			copyProject(from, plan.resolved().name(), copyDir.toPath(), m);
			b.ms.put("copy", (System.nanoTime() - t0) / 1_000_000);
			checkSource(plan);
			upgradeInCopy(b, new ProjectLocator(copyDir.getPath(), plan.resolved().name()));
			checkSource(plan);
			// publish: rename the complete copy, then name it in entry.json
			b.phase = "publish";
			m.checkCancelled();
			moveDir(tmp[0].toPath(), published.toPath(), m);
			tmp[0] = null;
			boolean first = entry == null;
			if (first) {
				entry = Json.of("format", ENTRY_FORMAT, "source", plan.canonical(), "ghidra",
					Application.getApplicationVersion(), "dbVersion", CURRENT_DB_VERSION,
					"created", System.currentTimeMillis(), "upgraded", new JsonArray());
			}
			String previous = first ? null : entry.get("generation").getAsString();
			upgraded(entry); // ensure the array
			entry.getAsJsonArray("upgraded").add(plan.path());
			Json.put(entry, "generation", gen);
			JsonObject stats = new JsonObject();
			b.ms.forEach(stats::addProperty);
			if (!entry.has("builds") || !entry.get("builds").isJsonObject()) {
				entry.add("builds", new JsonObject());
			}
			entry.getAsJsonObject("builds").add(plan.path(), stats);
			writeEntry(dir, entry);
			b.generation = gen;
			if (previous != null) {
				removeGeneration(plan.key(), dir, previous);
			}
			if (first) {
				prune(plan.canonical(), plan.key());
			}
			out.set(State.READY, null, "published " + published);
		}
	}

	private void finish(Build b, State s, String error, String note) {
		b.endedAt = System.currentTimeMillis();
		b.error = error;
		b.state = s;
		b.done.countDown();
		Plan plan = b.plan;
		String what = "upgrade cache: build of " + plan.canonical() + " " + plan.path() + " (key " +
			plan.key() + ") ";
		if (s == State.READY) {
			Msg.info(this, what + "ready in " + (b.endedAt - b.startedAt) + " ms " + b.ms +
				(note == null ? "" : ": " + note));
		}
		else {
			Msg.warn(this, what + "failed after " + (b.endedAt - b.startedAt) + " ms: " + error +
				"; the temporary folder is removed and the next open retries");
		}
	}

	/**
	 * Renames a finished copy into place, atomically. On Windows a folder cannot be renamed while
	 * another process (a virus scanner, an indexer) has a file in it open, so a refused rename is
	 * retried for a few seconds.
	 */
	private static void moveDir(Path from, Path to, RequestMonitor m)
			throws IOException, CancelledException {
		for (int i = 0;; i++) {
			try {
				Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
				return;
			}
			catch (FileSystemException e) {
				if (i >= 50 || e instanceof FileAlreadyExistsException) {
					throw e;
				}
			}
			m.checkCancelled();
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CancelledException();
			}
		}
	}

	/** Fails the build when the source no longer has the plan's key. */
	private static void checkSource(Plan plan) throws IOException {
		String now;
		try {
			now = key(plan.resolved());
		}
		catch (IOException e) {
			throw new SourceChangedException("the source changed during the build (" + e + ")");
		}
		if (!now.equals(plan.key())) {
			throw new SourceChangedException("the source changed during the build (key " +
				plan.key() + ", now " + now + ")");
		}
	}

	private static FileLock lockWait(FileChannel ch, RequestMonitor m)
			throws IOException, CancelledException {
		while (true) {
			FileLock l;
			try {
				l = ch.tryLock();
			}
			catch (OverlappingFileLockException e) {
				l = null; // this daemon builds it on another thread; cannot happen with one
			}
			if (l != null) {
				return l;
			}
			m.checkCancelled();
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CancelledException();
			}
		}
	}

	/**
	 * Copies the {@code .gpr} and the {@code .rep} of the project {@code name} in {@code base}
	 * (not its lock files) into {@code dest}. {@link Files#copy} uses the platform's copy, which
	 * block-clones on ReFS. Checks for cancellation between files.
	 */
	static void copyProject(Path base, String name, Path dest, RequestMonitor m)
			throws IOException, CancelledException {
		Files.createDirectories(dest);
		Path gpr = base.resolve(name + ProjectLocator.getProjectExtension());
		SortedMap<String, Path> files = sourceFiles(gpr, name);
		long total = 0;
		for (Path p : files.values()) {
			total += Files.size(p);
		}
		m.initialize(total);
		m.setMessage("copying " + files.size() + " files");
		for (Path src : files.values()) {
			m.checkCancelled();
			Path to = dest.resolve(base.relativize(src).toString());
			Files.createDirectories(to.getParent());
			Files.copy(src, to, StandardCopyOption.COPY_ATTRIBUTES);
			m.incrementProgress(Files.size(src));
		}
		// empty folders of the .rep matter to the file system's layout
		Path rep = base.resolve(name + ProjectLocator.getProjectDirExtension());
		if (Files.isDirectory(rep)) {
			Files.walkFileTree(rep, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs)
						throws IOException {
					Files.createDirectories(dest.resolve(base.relativize(d).toString()));
					return FileVisitResult.CONTINUE;
				}
			});
		}
	}

	/** Opens the copy writable, upgrades the plan's program, saves it, and checks it. */
	private void upgradeInCopy(Build b, ProjectLocator copy)
			throws IOException, CancelledException, VersionException {
		RequestMonitor m = b.monitor;
		String path = b.plan.path();
		b.phase = "upgrade";
		SessionProject sp = openProject(copy, true);
		try {
			DomainFile df = sp.getProjectData().getFile(path);
			if (df == null) {
				throw new IOException(path + " is missing from the copy " + copy);
			}
			long t0 = System.nanoTime();
			Program program = (Program) df.getDomainObject(this, true, false, m);
			b.ms.put("upgrade", (System.nanoTime() - t0) / 1_000_000);
			try {
				m.checkCancelled();
				b.phase = "save";
				t0 = System.nanoTime();
				if (program.isChanged()) {
					program.save("upgraded to this Ghidra's database format (upgrade cache)", m);
				}
				b.ms.put("save", (System.nanoTime() - t0) / 1_000_000);
			}
			finally {
				program.release(this);
			}
			String still = olderFormat(sp.getProjectData(), df);
			if (still != null) {
				throw new IOException("the copy of " + path + " is still in an older format (" +
					still + ") after the upgrade");
			}
		}
		finally {
			sp.close();
		}
	}

	// ---- housekeeping --------------------------------------------------------------------------

	/**
	 * Removes what interrupted builds of a key left in its folder: temporary folders, and
	 * generations that {@code entry.json} does not name and nobody reads. Held: the key's build
	 * lock.
	 */
	private void removeLeftovers(File dir, JsonObject entry) {
		File[] subs = dir.listFiles(File::isDirectory);
		if (subs == null) {
			return;
		}
		String current = entry == null ? null : entry.get("generation").getAsString();
		for (File d : subs) {
			String n = d.getName();
			if (n.endsWith(TMP_SUFFIX)) {
				if (FileUtilities.deleteDir(d)) {
					Msg.info(this, "upgrade cache: removed " + d + " (an interrupted build)");
				}
			}
			else if (!n.equals(current) && n.matches("g\\d+")) {
				removeGeneration(dir.getName(), dir, n);
			}
		}
	}

	/** Removes an older generation of a key when no daemon reads from it. */
	private void removeGeneration(String key, File dir, String gen) {
		String name = key + "/" + gen + ".use";
		if (usedHere(name)) {
			return; // removed by a later build or sweep
		}
		Path useFile = root.toPath().resolve(name);
		boolean removed = false;
		try (FileChannel use = FileChannel.open(useFile, StandardOpenOption.CREATE,
			StandardOpenOption.READ, StandardOpenOption.WRITE)) {
			FileLock l = use.tryLock();
			if (l == null) {
				return; // another daemon reads from it
			}
			removed = FileUtilities.deleteDir(new File(dir, gen));
		}
		catch (IOException | OverlappingFileLockException e) {
			return;
		}
		if (removed) {
			try {
				Files.deleteIfExists(useFile);
			}
			catch (IOException e) {
				// opened meanwhile by a reader, which finds no copy and moves on
			}
			Msg.info(this, "upgrade cache: removed " + new File(dir, gen) +
				" (an older generation)");
		}
	}

	/** At start, on the build thread: the leftovers of every key nobody builds now. */
	private void sweep() {
		File[] dirs = root.listFiles(File::isDirectory);
		if (dirs == null) {
			return;
		}
		for (File d : dirs) {
			try (FileChannel ch = FileChannel.open(new File(root, d.getName() + ".lock").toPath(),
				StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
				FileLock l = ch.tryLock();
				if (l != null) {
					JsonObject entry = readEntry(d);
					if (entry != null || rawSource(d) == null) {
						removeLeftovers(d, entry);
					}
				}
			}
			catch (IOException | RuntimeException e) {
				// in use; the next build of the key cleans it
			}
		}
	}

	// ---- older format? -------------------------------------------------------------------------

	/**
	 * Why the program needs an upgrade, or null when it is current, read from its database
	 * without opening the program: its stored program database version and language version
	 * (what {@code ProgramDB} checks first; a manager's own schema change comes with a new
	 * program database version).
	 */
	static String olderFormat(ProjectData pd, DomainFile df) {
		if (!(pd instanceof DefaultProjectData dpd) ||
			!(dpd.getPrivateFileSystem() instanceof LocalFileSystem fs)) {
			return null;
		}
		DBHandle dbh = null;
		try {
			FolderItem item = fs.getItem(df.getParent().getPathname(), df.getName());
			if (!(item instanceof LocalDatabaseItem dbItem)) {
				return null;
			}
			dbh = new DBHandle(dbItem.open());
			if (dbh.getTable("Program") == null) {
				return null;
			}
			DBStringMapAdapter map = new DBStringMapAdapter(dbh, "Program", false);
			int stored = parseInt(map.get("DB Version"), 1);
			if (stored < CURRENT_DB_VERSION) {
				return "program database version " + stored + ", this Ghidra " + CURRENT_DB_VERSION;
			}
			String langId = map.get("Language ID");
			if (langId == null) {
				return "old language name format";
			}
			int major = 1;
			int minor = 0;
			String lv = map.get("Language Version");
			if (lv != null) {
				String[] parts = lv.split("\\.");
				major = parseInt(parts[0], 1);
				minor = parts.length > 1 ? parseInt(parts[1], 0) : 0;
			}
			Language lang;
			try {
				lang = DefaultLanguageService.getLanguageService()
						.getLanguage(new LanguageID(langId));
			}
			catch (LanguageNotFoundException e) {
				return null; // a language translation; the normal open reports what it can do
			}
			if (lang.getVersion() != major || lang.getMinorVersion() != minor) {
				return "language " + langId + " version " + major + "." + minor + ", this Ghidra " +
					lang.getVersion() + "." + lang.getMinorVersion();
			}
			return null;
		}
		catch (IOException | RuntimeException e) {
			Msg.debug(UpgradeCache.class, "upgrade cache: cannot read the version of " +
				df.getPathname() + ": " + e);
			return null;
		}
		finally {
			if (dbh != null) {
				dbh.close();
			}
		}
	}

	private static int parseInt(String s, int dflt) {
		if (s == null) {
			return dflt;
		}
		try {
			return Integer.parseInt(s.trim());
		}
		catch (NumberFormatException e) {
			return dflt;
		}
	}

	private static int currentDbVersion() {
		try {
			Field f = ProgramDB.class.getDeclaredField("DB_VERSION");
			f.setAccessible(true);
			return f.getInt(null);
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			return -1;
		}
	}

	// ---- key -----------------------------------------------------------------------------------

	/** The source's identity (see the class comment), as 16 hex digits. */
	static String key(ProjectResolver.Resolved r) throws IOException {
		MessageDigest md = sha256();
		update(md, "v2|" + r.gpr().getCanonicalPath() + "|" + Application.getApplicationVersion() +
			"|" + Application.getBuildDate() + "|" + CURRENT_DB_VERSION);
		for (Map.Entry<String, Path> f : sourceFiles(r.gpr().toPath(), r.name()).entrySet()) {
			BasicFileAttributes a = Files.readAttributes(f.getValue(), BasicFileAttributes.class);
			update(md, "|" + f.getKey() + "|" + a.size() + "|" + a.lastModifiedTime().toMillis());
			if (a.size() <= HASH_LIMIT) {
				md.update(Files.readAllBytes(f.getValue()));
			}
		}
		return HexFormat.of().formatHex(md.digest()).substring(0, 16);
	}

	/**
	 * Ghidra's transient files inside a {@code .rep}: the pre-save copy a program opened for
	 * update keeps next to its database ({@code tmp<n>.ps}, {@code LocalManagedBufferFile}) and
	 * the temporary files of a database item ({@code tmp<n>.tmp}, {@code LocalDatabaseItem}).
	 * They are never part of what is saved: Ghidra deletes or replaces them, and removes old
	 * ones when it next opens the item.
	 */
	private static final java.util.regex.Pattern TRANSIENT =
		java.util.regex.Pattern.compile("tmp\\d+\\.(ps|tmp)");

	/**
	 * The {@code .gpr} and every file below the {@code .rep}, by relative path, sorted; without
	 * Ghidra's {@link #TRANSIENT} files, so that a project open for update elsewhere keeps its
	 * identity until it is saved.
	 */
	static SortedMap<String, Path> sourceFiles(Path gpr, String name) throws IOException {
		SortedMap<String, Path> files = new TreeMap<>();
		files.put(gpr.getFileName().toString(), gpr);
		Path rep = gpr.resolveSibling(name + ProjectLocator.getProjectDirExtension());
		Path base = gpr.getParent();
		if (Files.isDirectory(rep)) {
			Files.walkFileTree(rep, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
					if (attrs.isRegularFile() &&
						!TRANSIENT.matcher(file.getFileName().toString()).matches()) {
						files.put(base.relativize(file).toString().replace('\\', '/'), file);
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path file, IOException e)
						throws IOException {
					if (e instanceof NoSuchFileException) {
						return FileVisitResult.CONTINUE; // a transient file, gone meanwhile
					}
					throw e;
				}
			});
		}
		return files;
	}

	private static MessageDigest sha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	private static void update(MessageDigest md, String s) {
		md.update(s.getBytes(StandardCharsets.UTF_8));
	}

	// ---- entries -------------------------------------------------------------------------------

	private static Set<String> upgraded(JsonObject entry) {
		if (!entry.has("upgraded") || !entry.get("upgraded").isJsonArray()) {
			entry.add("upgraded", new JsonArray());
		}
		Set<String> out = new HashSet<>();
		entry.getAsJsonArray("upgraded").forEach(e -> out.add(e.getAsString()));
		return out;
	}

	private static int generationNumber(JsonObject entry) {
		String g = entry.get("generation").getAsString();
		return parseInt(g.substring(1), 0);
	}

	/**
	 * The key's entry, or null when there is none, it is in an earlier format, or the generation
	 * it names is missing.
	 */
	private static JsonObject readEntry(File dir) {
		JsonObject e = readJson(new File(dir, ENTRY_FILE));
		if (e == null || !e.has("format") || e.get("format").getAsInt() != ENTRY_FORMAT ||
			!e.has("generation") || !e.get("generation").isJsonPrimitive()) {
			return null;
		}
		String gen = e.get("generation").getAsString();
		if (!gen.matches("g\\d+") || !new File(new File(dir, gen), "project").isDirectory()) {
			return null;
		}
		return e;
	}

	/** The source an entry (of any format) belongs to, or null. */
	private static String rawSource(File dir) {
		JsonObject e = readJson(new File(dir, ENTRY_FILE));
		return e != null && e.has("source") ? e.get("source").getAsString() : null;
	}

	private static JsonObject readJson(File f) {
		if (!f.isFile()) {
			return null;
		}
		try (Reader in = new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(in).getAsJsonObject();
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
	}

	private static void writeEntry(File dir, JsonObject entry) throws IOException {
		Path tmp = new File(dir, ENTRY_FILE + ".tmp").toPath();
		Files.writeString(tmp, GSON.toJson(entry), StandardCharsets.UTF_8);
		Files.move(tmp, new File(dir, ENTRY_FILE).toPath(), StandardCopyOption.REPLACE_EXISTING,
			StandardCopyOption.ATOMIC_MOVE);
	}

	/** Removes the entries of older keys of the same source that nobody uses. */
	private void prune(String canonical, String keep) {
		File[] dirs = root.listFiles(File::isDirectory);
		if (dirs == null) {
			return;
		}
		for (File d : dirs) {
			String k = d.getName();
			if (k.equals(keep) || usedHere(k + ".use")) {
				continue;
			}
			if (!canonical.equals(rawSource(d))) {
				continue;
			}
			// exclusive on both: nobody builds it (.lock) and no daemon serves from it (.use)
			try (FileChannel build = FileChannel.open(new File(root, k + ".lock").toPath(),
				StandardOpenOption.CREATE, StandardOpenOption.WRITE);
					FileChannel use = FileChannel.open(new File(root, k + ".use").toPath(),
						StandardOpenOption.CREATE, StandardOpenOption.READ,
						StandardOpenOption.WRITE)) {
				FileLock bl = build.tryLock();
				FileLock ul = bl == null ? null : use.tryLock();
				if (ul == null) {
					continue;
				}
				if (FileUtilities.deleteDir(d)) {
					Msg.info(this, "upgrade cache: removed " + d + " (an older copy of " +
						canonical + ")");
				}
			}
			catch (IOException | OverlappingFileLockException ex) {
				// in use; next time
			}
		}
	}
}
