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
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.*;
import ghidra.app.script.*;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * The killable script worker (package E7, PROTOCOL-3.md D47 and D64): {@code script} with
 * {@code isolation:"worker"} runs the script in a child JVM that works on a <b>private, writable,
 * disposable clone of the saved view</b>, and kills that JVM when the request is cancelled, times
 * out, runs the worker out of heap or its client disconnects. A script that ignores cancel and
 * interrupt therefore costs its owner one worker start-up and nothing else: its long slot, its
 * owner's cap and every lock are released when the request ends, and nothing it did reaches the
 * view.
 * <p>
 * This class has two halves in one file:
 * <ul>
 * <li><b>the daemon side</b> ({@link Admission}, {@link Lease}, {@link #run}, {@link #describe}):
 * counts and admits workers, makes the clone ({@link Lease#cloneProject}: the {@code fork_project}
 * copy, checked for a source that changed meanwhile), starts the child, speaks to it over its
 * stdin and stdout (one JSON object per line), kills it, and deletes the clone after every run;</li>
 * <li><b>the worker side</b> ({@link #launch}, {@code main}): the child JVM. It owns nothing of the
 * daemon's: it opens the clone writable, runs the script in a transaction that it rolls back (the
 * measure of {@code attemptedChanges}), streams the output, reports and exits. It ends at once when
 * its stdin closes (the daemon is gone), which backs up the daemon's own Job Object (E9, D60).</li>
 * </ul>
 * <b>What a worker does not do.</b> It does not see the unsaved edits of the view (the engine
 * refuses the worker while the view has unsaved edits, and the view's owner saves once first), it
 * does not share the daemon's Ghidra settings directory (each worker has its own, so compiled
 * script bundles of two workers never meet), and the CPU and allocation budgets of
 * {@code scriptCpuS} and {@code scriptAllocMb} measure a thread of the daemon, so they do not apply
 * to it: a worker is bounded by the request's wall clock ({@code timeout}, {@code scriptMaxS}) and
 * by its own heap ({@code workerHeapMb}, an out-of-memory error ends the worker JVM).
 * <p>
 * Settings ({@code -set key=value}): {@code maxWorkers} (8), {@code workerHeapMb} (1024),
 * {@code workerGraceMs} (500: the pause between the cancel message and the kill).
 */
public final class ScriptWorker implements GhidraLaunchable {

	static final int DEFAULT_MAX_WORKERS = 8;
	static final int DEFAULT_HEAP_MB = 1024;
	static final int DEFAULT_GRACE_MS = 500;
	/** The exit code of a JVM that ended on {@code -XX:+ExitOnOutOfMemoryError}. */
	static final int OOM_EXIT = 3;
	/** The folder under {@code java.io.tmpdir} that holds the leases. */
	static final String ROOT_NAME = "hydra-script-workers";
	/** The most output text the daemon keeps of one run, in characters (more is dropped, counted). */
	static final int MAX_KEPT_CHARS = 8 << 20;

	private static int setting(String key, int dflt) {
		try {
			return Settings.integer(key, dflt);
		}
		catch (IllegalArgumentException ex) {
			return dflt;
		}
	}

	// =============================================================================================
	// the daemon side
	// =============================================================================================

	private static final AtomicInteger RUNNING = new AtomicInteger();
	private static final AtomicLong STARTED = new AtomicLong();
	private static final AtomicLong KILLED = new AtomicLong();
	private static final AtomicLong DIED = new AtomicLong();
	private static final AtomicLong REFUSED = new AtomicLong();
	private static final AtomicLong CLEANUP_FAILED = new AtomicLong();
	private static final AtomicLong CLONED = new AtomicLong();
	private static final Set<Long> PIDS = ConcurrentHashMap.newKeySet();
	private static final Set<String> ACTIVE = ConcurrentHashMap.newKeySet();
	private static volatile JsonObject last;
	private static final AtomicLong SEQ = new AtomicLong();
	private static volatile long lastSweepMs;

	/** Sends cancel messages and kills, off the thread that cancelled. */
	private static final ScheduledExecutorService KILLER =
		Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "session-script-worker-killer");
			t.setDaemon(true);
			return t;
		});

	/** The figures of {@code health.scriptWorkers} (a contributor, E5): quick, no lock. */
	static JsonElement describe() {
		JsonObject o = Json.of("running", RUNNING.get(), "max",
			Math.max(1, setting("maxWorkers", DEFAULT_MAX_WORKERS)), "started", STARTED.get(),
			"killed", KILLED.get(), "died", DIED.get(), "refused", REFUSED.get(), "cloneFailures",
			CLEANUP_FAILED.get());
		JsonArray pids = new JsonArray();
		for (Long p : PIDS) {
			pids.add(p);
		}
		o.add("pids", pids);
		JsonObject l = last;
		if (l != null) {
			o.add("last", l.deepCopy());
		}
		return o;
	}

	/** A counted place for one worker; closing it gives the place back. */
	static final class Admission implements AutoCloseable {
		private boolean open = true;

		@Override
		public synchronized void close() {
			if (open) {
				open = false;
				RUNNING.decrementAndGet();
			}
		}
	}

	/**
	 * Takes a place for a worker, or refuses {@code busy} with {@code reason:"worker_capacity"}
	 * when {@code maxWorkers} workers already run. Taken before the clone is made, so a refused
	 * request has copied nothing.
	 */
	static Admission admit() {
		int max = Math.max(1, setting("maxWorkers", DEFAULT_MAX_WORKERS));
		for (;;) {
			int n = RUNNING.get();
			if (n >= max) {
				REFUSED.incrementAndGet();
				JsonObject d = Json.of("workers", n, "maxWorkers", max, "suggest", "retry");
				d = SessionException.busyDetails(true, d, "worker_capacity", null, null);
				SessionException ex = new SessionException(SessionException.BUSY,
					n + " script workers already run (maxWorkers " + max + "); retry", d);
				ex.withRetryAfterMs(2000);
				throw ex;
			}
			if (RUNNING.compareAndSet(n, n + 1)) {
				return new Admission();
			}
		}
	}

	private static Path root() {
		return Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().resolve(ROOT_NAME);
	}

	/**
	 * One run's private folder: the clone of the project, the worker's own temp and Ghidra
	 * settings directories, its class path file and its stderr. Closing it deletes all of it.
	 */
	static final class Lease implements AutoCloseable {
		final Path dir;
		final Path clone;
		final Path tmp;
		final Path settings;
		final Path stderr;
		String projectName;
		long cloneMs;
		long cloneBytes;
		int cloneFiles;
		boolean cloned;
		private boolean closed;

		private Lease(Path dir) throws IOException {
			this.dir = dir;
			this.clone = dir.resolve("clone");
			this.tmp = dir.resolve("tmp");
			this.settings = dir.resolve("settings");
			this.stderr = dir.resolve("stderr.log");
			Files.createDirectories(tmp);
			Files.createDirectories(settings);
		}

		static Lease create() {
			sweep();
			String name = "w-" + Long.toHexString(ProcessHandle.current().pid()) + "-" +
				Long.toHexString(SEQ.incrementAndGet()) + "-" + Integer.toHexString(
					ThreadLocalRandom.current().nextInt(0x1000, 0x10000));
			Path d = root().resolve(name);
			try {
				Files.createDirectories(d);
				ACTIVE.add(name);
				return new Lease(d);
			}
			catch (IOException e) {
				ACTIVE.remove(name);
				removeTree(d, false);
				throw new SessionException(SessionException.FAILED,
					"cannot make the worker's folder " + d + ": " + e.getMessage(), null, e);
			}
		}

		/**
		 * Copies the saved project into this lease, the way {@code fork_project} does, and checks
		 * that no file of the source changed meanwhile (a save of another program of the project
		 * does not take the project's exclusive lock). Up to three attempts.
		 *
		 * @throws SessionException {@code conflict} ({@code too_large}, or a source that kept
		 *             changing), {@code failed} (no room, I/O), {@code cancelled}
		 */
		void cloneProject(ProjectResolver.Resolved r, long limitBytes, RequestMonitor m) {
			long t0 = System.nanoTime();
			try {
				Files.createDirectories(clone);
				ProjectFork.Cost cost = ProjectFork.cost(r, clone.toFile());
				if (!cost.cloneCapable() && cost.bytes() > limitBytes) {
					JsonObject d = cost.json();
					Json.put(d, "limitBytes", limitBytes);
					Json.put(d, "reason", "too_large");
					throw new SessionException(SessionException.CONFLICT,
						"the worker's clone of " + r.name() + " would be a full copy of " +
							cost.bytes() + " bytes, over the limit of " + limitBytes +
							" (forkCopyLimitMb); run this script with another isolation, or " +
							"raise the limit",
						d);
				}
				if (!cost.cloneCapable() && cost.bytes() + (cost.bytes() >> 3) > cost.destFreeBytes()) {
					throw new SessionException(SessionException.FAILED,
						"not enough free space for the worker's clone of " + r.name() + " (" +
							cost.bytes() + " bytes)",
						cost.json());
				}
				for (int attempt = 0;; attempt++) {
					Map<String, String> before = Revision.files(r);
					UpgradeCache.copyProject(r.dir().toPath(), r.name(), clone, m);
					m.checkCancelled();
					if (Revision.files(r).equals(before)) {
						break;
					}
					if (attempt == 2) {
						JsonObject d = Json.of("gpr", r.gpr().getPath(), "suggest", "retry");
						Json.put(d, "reason", "source_changed");
						throw new SessionException(SessionException.CONFLICT,
							"project " + r.name() + " kept changing while the worker's clone was " +
								"made; retry",
							d);
					}
					removeTree(clone, false);
					Files.createDirectories(clone);
				}
				projectName = r.name();
				cloneBytes = cost.bytes();
				cloneFiles = cost.files();
				cloned = true;
				CLONED.incrementAndGet();
			}
			catch (CancelledException e) {
				throw Requests.cancelled(m);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED,
					"cannot clone " + r.name() + " for the worker: " + e.getMessage(), null, e);
			}
			finally {
				cloneMs = (System.nanoTime() - t0) / 1_000_000;
			}
		}

		@Override
		public void close() {
			if (closed) {
				return;
			}
			closed = true;
			boolean gone = removeTree(dir, true);
			if (gone) {
				ACTIVE.remove(dir.getFileName().toString());
			}
			else {
				// the sweep removes it later; until then it is not "active" any more
				ACTIVE.remove(dir.getFileName().toString());
				CLEANUP_FAILED.incrementAndGet();
				Msg.warn(ScriptWorker.class, "could not delete the worker folder " + dir);
			}
		}
	}

	/**
	 * Removes a folder tree, surviving a handle holder for a moment (an indexer, a scanner or the
	 * worker's last handle): the pauses are 25 ms doubling, 1575 ms in all. Never throws.
	 *
	 * @return true when nothing is left
	 */
	static boolean removeTree(Path p, boolean retry) {
		int attempts = retry ? 7 : 1;
		for (int i = 0; i < attempts; i++) {
			try {
				if (Files.notExists(p, LinkOption.NOFOLLOW_LINKS)) {
					return true;
				}
				Files.walkFileTree(p, new SimpleFileVisitor<>() {
					@Override
					public FileVisitResult visitFile(Path f, BasicFileAttributes a) throws IOException {
						try {
							Files.deleteIfExists(f);
						}
						catch (AccessDeniedException e) {
							f.toFile().setWritable(true);
							Files.deleteIfExists(f);
						}
						return FileVisitResult.CONTINUE;
					}

					@Override
					public FileVisitResult postVisitDirectory(Path d, IOException e) throws IOException {
						Files.deleteIfExists(d);
						return FileVisitResult.CONTINUE;
					}
				});
			}
			catch (IOException | RuntimeException e) {
				// retried below
			}
			if (Files.notExists(p, LinkOption.NOFOLLOW_LINKS)) {
				return true;
			}
			if (i < attempts - 1) {
				try {
					Thread.sleep(25L << i);
				}
				catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}
		return Files.notExists(p, LinkOption.NOFOLLOW_LINKS);
	}

	/**
	 * Deletes the folders that a run left behind: of a daemon that is gone, or of this one when it
	 * could not delete them at the end of the run. Only folders named {@code w-<pid>-...} under
	 * this engine's own folder are looked at, and the folder of a live process is never touched.
	 * At most once every 30 seconds; never throws.
	 */
	static void sweep() {
		long now = System.currentTimeMillis();
		synchronized (ACTIVE) {
			if (now - lastSweepMs < 30_000) {
				return;
			}
			lastSweepMs = now;
		}
		long me = ProcessHandle.current().pid();
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(root(), "w-*")) {
			for (Path d : ds) {
				String n = d.getFileName().toString();
				String[] parts = n.split("-");
				if (parts.length < 3) {
					continue;
				}
				long pid;
				try {
					pid = Long.parseLong(parts[1], 16);
				}
				catch (NumberFormatException e) {
					continue;
				}
				boolean mine = pid == me;
				if (mine ? ACTIVE.contains(n)
						: ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
					continue;
				}
				removeTree(d, false);
			}
		}
		catch (NoSuchFileException e) {
			// no folder yet: nothing to sweep
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(ScriptWorker.class, "worker folder sweep: " + e);
		}
	}

	/** Parent-side result of one run. */
	record Outcome(JsonObject result, String output, boolean outputDropped, boolean killed,
			Integer exitCode, String stderrTail, long totalMs, long startMs, Long startCpuMs,
			JsonObject marks, long pid) {
	}

	/** The JVM options of this daemon that a worker keeps: system properties and module flags. */
	static boolean keepOption(String a) {
		if (a.startsWith("-D")) {
			return !(a.startsWith("-Dghidra.session.") || a.startsWith("-Dapplication.settingsdir") ||
				a.startsWith("-Djava.io.tmpdir") || a.startsWith("-Djava.class.path"));
		}
		return a.startsWith("--add-opens") || a.startsWith("--add-exports") ||
			a.startsWith("--add-modules") || a.startsWith("--enable-native-access") ||
			a.equals("-Xshare:off");
	}

	private static boolean windows() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
	}

	/** The command line of a worker: this daemon's own JVM, class path and module flags. */
	private static List<String> command(Lease lease) throws IOException {
		List<String> cmd = new ArrayList<>();
		cmd.add(Path.of(System.getProperty("java.home"), "bin", windows() ? "java.exe" : "java")
				.toString());
		for (String a : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
			if (keepOption(a)) {
				cmd.add(a);
			}
		}
		int heap = Math.max(128, setting("workerHeapMb", DEFAULT_HEAP_MB));
		cmd.add("-Xmx" + heap + "m");
		cmd.add("-XX:+ExitOnOutOfMemoryError");
		cmd.add("-Xlog:disable");
		cmd.add("-Xlog:all=warning:stderr");
		cmd.add("-Djava.awt.headless=true");
		cmd.add("-Djava.io.tmpdir=" + lease.tmp);
		cmd.add("-Dapplication.settingsdir=" + lease.settings);
		// the class path goes through an argument file: a full Ghidra class path can pass the
		// length limit of a Windows command line
		Path argfile = lease.dir.resolve("classpath.args");
		String cp = System.getProperty("java.class.path").replace("\\", "\\\\");
		Files.writeString(argfile, "-cp \"" + cp + "\"\n", StandardCharsets.UTF_8);
		cmd.add("@" + argfile);
		if (ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader) {
			cmd.add("ghidra.Ghidra");
		}
		cmd.add(ScriptWorker.class.getName());
		cmd.add("--log");
		cmd.add(lease.dir.resolve("worker.log").toString());
		return cmd;
	}

	/**
	 * Starts a worker for {@code request} (the object the worker side reads, see {@link #work}),
	 * waits for its result and returns what happened. The worker is killed when {@code m} is
	 * cancelled (a client's cancel, the request's timeout, a dead client, the wall budget) after
	 * {@code workerGraceMs}, and always before this method returns. The caller deletes the lease.
	 *
	 * @param onCancel runs first in the cancel hook (the caller ends its runaway watch there, so a
	 *            worker that is being killed is never counted as a quarantined script)
	 */
	static Outcome run(Lease lease, JsonObject request, RequestMonitor m, Runnable onCancel) {
		long t0 = System.nanoTime();
		ProcessBuilder pb;
		try {
			pb = new ProcessBuilder(command(lease));
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED,
				"cannot prepare the worker command: " + e.getMessage(), null, e);
		}
		pb.directory(lease.dir.toFile());
		pb.redirectError(ProcessBuilder.Redirect.to(lease.stderr.toFile()));
		Process p;
		try {
			p = pb.start();
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED,
				"cannot start the script worker: " + e.getMessage(), null, e);
		}
		STARTED.incrementAndGet();
		PIDS.add(p.pid());
		Run run = new Run(p, lease, t0);
		Runnable hook = () -> {
			try {
				onCancel.run();
			}
			finally {
				run.cancelAsync();
			}
		};
		m.addCancelHook(hook);
		try {
			run.send(request);
			run.awaitEnd();
		}
		finally {
			m.removeCancelHook(hook);
			run.finish();
			PIDS.remove(p.pid());
		}
		return run.outcome();
	}

	/** One running worker, as the daemon sees it. */
	private static final class Run {
		final Process p;
		final Lease lease;
		final long t0;
		final long pid;
		private final Object sendLock = new Object();
		private final Writer toWorker;
		private final StringBuilder out = new StringBuilder();
		private boolean dropped;
		private volatile JsonObject result;
		private volatile JsonObject startMarks;
		private volatile long startMs = -1;
		private volatile long startCpuMs = -1;
		private volatile boolean killed;
		private volatile boolean finished;
		private final CompletableFuture<Void> eof = new CompletableFuture<>();
		private final Thread reader;
		private Integer exitCode;
		private long totalMs;

		Run(Process p, Lease lease, long t0) {
			this.p = p;
			this.lease = lease;
			this.t0 = t0;
			this.pid = p.pid();
			this.toWorker = new BufferedWriter(
				new OutputStreamWriter(p.getOutputStream(), StandardCharsets.UTF_8));
			this.reader = new Thread(this::readLoop, "session-script-worker-" + pid);
			this.reader.setDaemon(true);
			this.reader.start();
		}

		void send(JsonObject o) {
			synchronized (sendLock) {
				try {
					toWorker.write(Json.GSON.toJson(o));
					toWorker.write('\n');
					toWorker.flush();
				}
				catch (IOException e) {
					// the worker is gone: awaitEnd reports it
				}
			}
		}

		private void readLoop() {
			try (BufferedReader r = new BufferedReader(
				new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
				String line;
				while ((line = r.readLine()) != null) {
					JsonObject o;
					try {
						JsonElement e = JsonParser.parseString(line);
						if (!e.isJsonObject()) {
							continue;
						}
						o = e.getAsJsonObject();
					}
					catch (JsonParseException e) {
						continue; // not ours: ignore
					}
					String ev = Json.str(o, "ev", "");
					switch (ev) {
						case "out" -> {
							String text = Json.str(o, "text", "");
							synchronized (out) {
								if (out.length() + text.length() <= MAX_KEPT_CHARS) {
									out.append(text);
								}
								else {
									dropped = true;
								}
							}
						}
						case "start" -> {
							startMarks = o;
							startMs = (System.nanoTime() - t0) / 1_000_000;
							startCpuMs = o.has("cpuMs") ? Json.num(o, "cpuMs", -1, -1, Long.MAX_VALUE)
									: parentSeenCpuMs(p);
						}
						case "result" -> result = o;
						default -> {
							// "init", "open": progress only
						}
					}
				}
			}
			catch (IOException e) {
				// the pipe closed: the process ended
			}
			finally {
				eof.complete(null);
			}
		}

		/** The cancel hook: tell the worker, and kill it if it is still there after the grace. */
		void cancelAsync() {
			KILLER.execute(() -> send(Json.of("op", "cancel")));
			long grace = Math.max(0, setting("workerGraceMs", DEFAULT_GRACE_MS));
			KILLER.schedule(this::killNow, grace, TimeUnit.MILLISECONDS);
		}

		void killNow() {
			if (finished || !p.isAlive() || result != null) {
				return;
			}
			killed = true;
			KILLED.incrementAndGet();
			destroyTree();
		}

		private void destroyTree() {
			try {
				p.descendants().forEach(ProcessHandle::destroyForcibly);
			}
			catch (RuntimeException e) {
				// best effort: the daemon's job object covers them
			}
			p.destroyForcibly();
		}

		void awaitEnd() {
			try {
				eof.get();
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				killed = true;
				KILLED.incrementAndGet();
				destroyTree();
			}
			catch (ExecutionException e) {
				// the reader never fails the future
			}
		}

		void finish() {
			finished = true;
			boolean exited = false;
			try {
				// a worker that sent its result ends by itself; one that did not is killed now
				exited = p.waitFor(result != null ? 5 : 0, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			if (!exited) {
				destroyTree();
				try {
					exited = p.waitFor(10, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			try {
				toWorker.close();
			}
			catch (IOException e) {
				// gone
			}
			try {
				reader.join(2000);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			exitCode = exited ? p.exitValue() : null;
			totalMs = (System.nanoTime() - t0) / 1_000_000;
			if (result == null && !killed) {
				DIED.incrementAndGet();
			}
		}

		Outcome outcome() {
			String text;
			boolean drop;
			synchronized (out) {
				text = out.toString();
				drop = dropped;
			}
			String err = null;
			if (result == null) {
				err = tail(lease.stderr, 2000);
				// the JVM's own words on the way out: an out-of-memory error with the worker's heap
				if (exitCode != null && exitCode == OOM_EXIT && (err == null || err.isBlank())) {
					err = "the worker JVM ended on OutOfMemoryError (exit code 3)";
				}
			}
			JsonObject marks = new JsonObject();
			JsonObject sm = startMarks;
			if (sm != null) {
				for (String k : List.of("initMs", "projectMs", "programMs", "compileMs")) {
					if (sm.has(k)) {
						marks.add(k, sm.get(k));
					}
				}
			}
			JsonObject res = result;
			boolean wasKilled = killed;
			JsonObject summary = Json.of("pid", pid, "totalMs", totalMs, "startMs",
				startMs < 0 ? null : startMs, "startCpuMs", startCpuMs < 0 ? null : startCpuMs,
				"cloneMs", lease.cloneMs, "cloneBytes", lease.cloneBytes,
				"killed", wasKilled, "exitCode", exitCode);
			if (res != null && res.has("mem")) {
				summary.add("mem", res.get("mem"));
			}
			last = summary;
			return new Outcome(res, text, drop, wasKilled, exitCode, err, totalMs,
				Math.max(0, startMs), startCpuMs < 0 ? null : startCpuMs, marks, pid);
		}
	}

	/**
	 * The CPU time of a worker as the operating system reports it to this daemon, in ms, or -1: the
	 * fallback when a worker did not report its own at start-up.
	 */
	static long parentSeenCpuMs(Process p) {
		try {
			return p.info().totalCpuDuration().map(java.time.Duration::toMillis).orElse(-1L);
		}
		catch (RuntimeException e) {
			return -1;
		}
	}

	/**
	 * The CPU time this JVM has used so far (all its threads: JIT, GC, class loading), in ms, or -1.
	 * Unlike wall time it does not grow when the machine is busy with other work, so it is the
	 * start-up cost a budget can hold (E7, SP10).
	 */
	static long ownProcessCpuMs() {
		try {
			if (ManagementFactory
					.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean os) {
				long ns = os.getProcessCpuTime();
				if (ns >= 0) {
					return ns / 1_000_000;
				}
			}
			return ProcessHandle.current().info().totalCpuDuration()
					.map(java.time.Duration::toMillis).orElse(-1L);
		}
		catch (RuntimeException | LinkageError e) {
			return -1;
		}
	}

	private static String tail(Path f, int max) {
		try {
			byte[] b = Files.readAllBytes(f);
			String s = new String(b, StandardCharsets.UTF_8);
			return s.length() <= max ? s : s.substring(s.length() - max);
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
	}

	// =============================================================================================
	// the worker side (the child JVM)
	// =============================================================================================

	/** Standard mode: {@code ghidra.Ghidra} loads this class by name. */
	public ScriptWorker() {
		// GhidraLaunchable
	}

	/** Fast mode: the JVM's own application class loader holds the whole class path. */
	public static void main(String[] args) throws Exception {
		if (ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader) {
			String[] all = new String[args.length + 1];
			all[0] = ScriptWorker.class.getName();
			System.arraycopy(args, 0, all, 1, args.length);
			GhidraLauncher.launch(all);
			return;
		}
		new ScriptWorker().launch(new GhidraApplicationLayout(), args);
	}

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		int code = 1;
		try {
			code = work(layout, args);
		}
		catch (Throwable t) {
			System.err.println("script worker: " + t);
			t.printStackTrace();
		}
		finally {
			// no shutdown hooks, no wait for threads: the folder is deleted by the daemon
			Runtime.getRuntime().halt(code);
		}
	}

	/** The channel to the daemon: one JSON object per line. */
	private static final class Pipe {
		private final OutputStream out;

		Pipe(OutputStream out) {
			this.out = out;
		}

		synchronized void send(JsonObject o) {
			try {
				out.write((Json.GSON.toJson(o) + "\n").getBytes(StandardCharsets.UTF_8));
				out.flush();
			}
			catch (IOException e) {
				Runtime.getRuntime().halt(2); // the daemon is gone
			}
		}
	}

	/** The script's output: buffered, and sent to the daemon in chunks, so a kill loses little. */
	private static final class Output extends Writer {
		private final Pipe pipe;
		private final StringBuilder sb = new StringBuilder();

		Output(Pipe pipe) {
			this.pipe = pipe;
			Thread t = new Thread(() -> {
				for (;;) {
					try {
						Thread.sleep(100);
					}
					catch (InterruptedException e) {
						return;
					}
					drain();
				}
			}, "worker-output");
			t.setDaemon(true);
			t.start();
		}

		@Override
		public synchronized void write(char[] c, int off, int len) {
			sb.append(c, off, len);
			if (sb.length() > (1 << 16)) {
				drain();
			}
		}

		synchronized void drain() {
			if (sb.length() > 0) {
				pipe.send(Json.of("ev", "out", "text", sb.toString()));
				sb.setLength(0);
			}
		}

		@Override
		public void flush() {
			// the periodic drain sends; a script's println must not cost a pipe write
		}

		@Override
		public void close() {
			drain();
		}
	}

	private static int work(GhidraApplicationLayout layout, String[] args) throws Exception {
		// stdout is the channel to the daemon: claim it before anything else can print to it
		Pipe pipe = new Pipe(new FileOutputStream(FileDescriptor.out));
		System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true,
			StandardCharsets.UTF_8));
		String logFile = null;
		for (int i = 0; i + 1 < args.length; i++) {
			if (args[i].equals("--log")) {
				logFile = args[i + 1];
			}
		}
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		CompletableFuture<JsonObject> request = new CompletableFuture<>();
		Thread in = new Thread(() -> {
			try (BufferedReader r = new BufferedReader(
				new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
				String line;
				while ((line = r.readLine()) != null) {
					JsonElement e;
					try {
						e = JsonParser.parseString(line);
					}
					catch (JsonParseException ex) {
						continue;
					}
					if (!e.isJsonObject()) {
						continue;
					}
					JsonObject o = e.getAsJsonObject();
					String op = Json.str(o, "op", "");
					if (op.equals("run")) {
						request.complete(o);
					}
					else if (op.equals("cancel")) {
						monitor.cancel();
					}
				}
			}
			catch (IOException e) {
				// treated as the end of input
			}
			// the daemon closed the pipe or died: nobody wants this worker any more
			Runtime.getRuntime().halt(2);
		}, "worker-stdin");
		in.setDaemon(true);
		in.start();

		long t0 = System.nanoTime();
		HeadlessGhidraApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
		if (logFile != null) {
			config.setApplicationLogFile(new File(logFile));
		}
		Application.initializeApplication(layout, config);
		long initMs = (System.nanoTime() - t0) / 1_000_000;
		pipe.send(Json.of("ev", "init", "ms", initMs));

		JsonObject req = request.get();
		return execute(pipe, monitor, req, initMs);
	}

	private static int execute(Pipe pipe, TaskMonitorAdapter monitor, JsonObject req, long initMs) {
		Output output = new Output(pipe);
		PrintWriter pw = new PrintWriter(output, true);
		JsonObject res = Json.of("ev", "result");
		SessionProject project = null;
		Program program = null;
		Object consumer = new Object();
		long attempted = 0;
		double seconds = 0;
		try {
			List<ResourceFile> dirs = new ArrayList<>();
			for (String d : Json.strings(req, "scriptDirs")) {
				dirs.add(new ResourceFile(new File(d)));
			}
			ResourceFile src = new ResourceFile(new File(Json.str(req, "script")));
			long t1 = System.nanoTime();
			GhidraScriptUtil.acquireBundleHostReference().add(dirs, true, true);
			long projectMs = 0;
			long programMs = 0;
			JsonObject pj = Json.obj(req, "project");
			String programPath = Json.str(req, "program", null);
			if (pj != null) {
				long t2 = System.nanoTime();
				ProjectLocator loc = new ProjectLocator(Json.str(pj, "dir"), Json.str(pj, "name"));
				project = SessionProject.open(loc, true);
				projectMs = (System.nanoTime() - t2) / 1_000_000;
				if (programPath != null) {
					long t3 = System.nanoTime();
					DomainFile df = project.getProjectData().getFile(programPath);
					if (df == null) {
						throw new IOException(programPath + " is missing from the clone");
					}
					program = (Program) df.getDomainObject(consumer, true, false, monitor);
					programMs = (System.nanoTime() - t3) / 1_000_000;
				}
			}
			pipe.send(Json.of("ev", "open", "projectMs", projectMs, "programMs", programMs));
			long t4 = System.nanoTime();
			GhidraScript script;
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
			if (provider == null) {
				throw new IllegalStateException("no script provider for " + src.getName());
			}
			script = provider.getScriptInstance(src, pw);
			script.setScriptArgs(Json.strings(req, "args").toArray(new String[0]));
			ScriptCommands.bindHeadless(script);
			ProgramLocation loc = null;
			if (program != null && Json.has(req, "address")) {
				loc = new ProgramLocation(program,
					Addresses.address(program, Json.str(req, "address")));
			}
			GhidraState state = new GhidraState(null, project, program, loc, null, null);
			long compileMs = (System.nanoTime() - t4) / 1_000_000;
			pipe.send(Json.of("ev", "start", "initMs", initMs, "projectMs", projectMs, "programMs",
				programMs, "compileMs", compileMs, "cpuMs", ownProcessCpuMs()));
			long modBefore = program == null ? 0 : program.getModificationNumber();
			int outer = -1;
			if (program != null) {
				outer = program.startTransaction("session: worker script (rolled back)");
			}
			long t5 = System.nanoTime();
			Throwable failure = null;
			try {
				script.execute(state, new ScriptControls(pw, pw, false, monitor));
			}
			catch (Throwable t) {
				failure = t;
			}
			finally {
				seconds = (System.nanoTime() - t5) / 1e9;
				if (program != null) {
					attempted = Math.max(0, program.getModificationNumber() - modBefore);
					program.endTransaction(outer, false);
				}
			}
			pw.flush();
			if (failure != null) {
				boolean cancelled = monitor.isCancelled() || failure instanceof CancelledException;
				res.add("failure", Json.of("type", failure.getClass().getSimpleName(), "message",
					String.valueOf(failure.getMessage()), "cancelled", cancelled));
			}
		}
		catch (Throwable t) {
			res.add("failure", Json.of("type", t.getClass().getSimpleName(), "message",
				String.valueOf(t.getMessage()), "cancelled", false, "setup", true));
		}
		finally {
			output.drain();
			res.addProperty("attempted", attempted);
			res.addProperty("seconds", seconds);
			res.add("mem", memory());
			try {
				if (program != null) {
					program.release(consumer);
				}
				if (project != null) {
					project.close();
				}
			}
			catch (Throwable t) {
				// the clone is deleted anyway
			}
		}
		pipe.send(res);
		return 0;
	}

	/** The worker's own memory figures (the cost recorded for SP10): heap, and the working set on Windows. */
	private static JsonObject memory() {
		Runtime rt = Runtime.getRuntime();
		JsonObject m = Json.of("heapUsedMb", (rt.totalMemory() - rt.freeMemory()) >> 20,
			"heapCommittedMb", rt.totalMemory() >> 20, "heapMaxMb", rt.maxMemory() >> 20);
		Long[] ws = windowsMemory();
		if (ws != null) {
			Json.put(m, "workingSetMb", ws[0] >> 20);
			Json.put(m, "peakWorkingSetMb", ws[1] >> 20);
			Json.put(m, "privateMb", ws[2] >> 20);
		}
		return m;
	}

	/** {working set, peak working set, pagefile usage} of this process in bytes, or null. */
	private static Long[] windowsMemory() {
		if (!windows()) {
			return null;
		}
		try {
			Linker linker = Linker.nativeLinker();
			SymbolLookup k32 = SymbolLookup.libraryLookup("kernel32", Arena.global());
			MethodHandle cur = linker.downcallHandle(k32.find("GetCurrentProcess").orElseThrow(),
				FunctionDescriptor.of(ValueLayout.ADDRESS));
			MethodHandle info = linker.downcallHandle(k32.find("K32GetProcessMemoryInfo").orElseThrow(),
				FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
					ValueLayout.JAVA_INT));
			try (Arena a = Arena.ofConfined()) {
				MemorySegment pmc = a.allocate(72);
				pmc.set(ValueLayout.JAVA_INT, 0, 72);
				MemorySegment h = (MemorySegment) cur.invokeExact();
				int ok = (int) info.invokeExact(h, pmc, 72);
				if (ok == 0) {
					return null;
				}
				return new Long[] { pmc.get(ValueLayout.JAVA_LONG, 16),
					pmc.get(ValueLayout.JAVA_LONG, 8), pmc.get(ValueLayout.JAVA_LONG, 56) };
			}
		}
		catch (Throwable t) {
			return null;
		}
	}
}
