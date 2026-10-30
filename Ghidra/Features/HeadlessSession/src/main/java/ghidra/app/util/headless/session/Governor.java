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
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryType;
import java.lang.management.MemoryUsage;
import java.nio.file.FileStore;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;

import javax.management.Notification;
import javax.management.NotificationEmitter;
import javax.management.NotificationListener;
import javax.management.openmbean.CompositeData;

import com.google.gson.JsonObject;
import com.sun.management.GarbageCollectionNotificationInfo;

import ghidra.framework.model.DomainFile;
import ghidra.util.Msg;

/**
 * The resource governor (PROTOCOL-3.md 3.11, package E9): overload yields an immediate structured
 * {@code busy{reason:"capacity"}}, never an {@code OutOfMemoryError} and never a hang.
 * <p>
 * <b>Admission</b> ({@link #admit}, called by {@code Session.execute} before a request takes a
 * slot) for {@code open_project}, {@code open_program} / {@code switch}, {@code fork_project} and
 * {@code import}:
 * <ul>
 * <li><i>heap</i>: admit iff {@code heapAfterGc + 1.5 x estHeap <= heapSoftPct x Xmx}
 * ({@link Budgets#estHeap}); the heap figure is the one the last collection left (a collection
 * notification, never the current "used", which holds garbage); a refusal re-measures once with a
 * collection of its own (at most one every two seconds), so a stale figure does not refuse;</li>
 * <li><i>views</i>: fewer than {@code maxViews} programs open in the daemon, counting those
 * reserved by requests still in flight, and fewer than {@code maxViewsPerClient} per client; a
 * program another client already has open costs nothing but the per-client share. The checks
 * of a request (client share, view count, heap) and its reservation are one step under one lock
 * ({@link #tryReserveView}), so requests that arrive together cannot all pass the same count;
 * freeing room (idle programs, a collection) happens between two attempts, never under the lock;</li>
 * <li><i>degraded</i>: above {@code heapHardPct} after a collection the daemon refuses opens, forks
 * and imports and keeps serving reads ({@link #degraded}, which {@code health.state} reports);</li>
 * <li><i>disk</i>: a fork or an import needs {@code free >= estimate + max(5 GB, 5%)}, and the view
 * forks this daemon made stay under {@code viewDiskBudget}.</li>
 * </ul>
 * <b>Threads.</b> One guarded thread samples every half second: it releases idle decompilers,
 * re-arms the emergency reserve of {@link Guarded} and measures the heap again when a stale figure
 * says degraded.
 * <p>
 * {@code health.governor} shows all of it.
 */
final class Governor {

	/** Heap state names, in order of severity. */
	static final String OK = "ok";
	static final String SOFT = "soft";
	static final String HARD = "hard";

	private static final long FORCED_GC_MIN_GAP_MS = 2_000;
	private static final Admission NONE = new Admission(null, null, 0, false, null, 0, -1);

	private static volatile Governor instance;
	private static final Map<String, AtomicLong> REFUSED = new ConcurrentHashMap<>();

	private final Session session;
	/** The programs and overlays open now (the daemon's session; a stand-in in the self-test). */
	private final java.util.function.IntSupplier viewCounter;
	private final Set<MemoryPoolMXBean> heapPools = new HashSet<>();
	private volatile long afterGcBytes;
	private volatile long afterGcAtMs;
	private final AtomicLong gcEvents = new AtomicLong();
	private volatile long lastForcedGcMs;
	private final AtomicInteger forcedGcs = new AtomicInteger();

	/**
	 * Guards the reservations. The checks of an admission and its reservation happen under one
	 * acquisition of it ({@link #tryReserveView}); nothing slow (a collection, an eviction, a
	 * disposal) ever runs while it is held, because {@code health.governor} takes it too.
	 */
	private final Object lock = new Object();
	private int reservedViews;
	private long reservedEstBytes;
	private int inFlight;
	/** Per client: the open_program / switch requests in flight that count towards its share. */
	private final Map<Client, Integer> reservedByClient = new java.util.IdentityHashMap<>();
	/** View forks this daemon made that are still on disk: gpr path to estimated bytes. */
	private final Map<String, Long> viewForks = new ConcurrentHashMap<>();
	private volatile long lastEstBytes;

	private Governor(Session session) {
		this(session, null);
	}

	private Governor(Session session, java.util.function.IntSupplier viewCounter) {
		this.session = session;
		this.viewCounter = viewCounter != null ? viewCounter : this::openViews;
		for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
			if (p.getType() == MemoryType.HEAP) {
				heapPools.add(p);
			}
		}
		Runtime rt = Runtime.getRuntime();
		afterGcBytes = rt.totalMemory() - rt.freeMemory();
		afterGcAtMs = System.currentTimeMillis();
	}

	// ---- start -----------------------------------------------------------------------------------

	/**
	 * Starts the governor (after the watchdog, E5): the gate's size, the advertised limits, the
	 * collection listeners, the guarded sampling thread and the {@code health.governor} figures.
	 */
	static synchronized void start(Session session) {
		if (instance != null) {
			return;
		}
		Governor g = new Governor(session);
		instance = g;
		DecompilerGate.GATE.setPermits(Budgets.gatePermits());
		Advertised.capability("admission", 1);
		Advertised.limit("minXmxMb", Budgets::minXmxMb);
		Advertised.limit("maxViews", Budgets::maxViews);
		Advertised.limit("maxViewsPerClient", Budgets::maxViewsPerClient);
		Advertised.limit("heapSoftPct", Budgets::heapSoftPct);
		Advertised.limit("heapHardPct", Budgets::heapHardPct);
		Advertised.limit("nativeBudgetMb", Budgets::nativeBudgetMb);
		// sizes are advertised in megabytes; the permits of the gate are a derived figure that
		// health.governor.gate shows, not a setting
		Advertised.limit("viewDiskBudget", () -> Budgets.viewDiskBudgetBytes() >> 20);
		Advertised.limit("diskReserve", () -> Budgets.size("diskReserve", 5L << 30) >> 20);
		Advertised.limit("decompilerIdleS", Budgets::decompilerIdleS);
		Advertised.limit("decompilerWaitS", Budgets::decompilerWaitS);
		Advertised.limit("decompilerFailLimit", DecompilerGate.Breaker::failLimit);
		Advertised.limit("decompilerNegativeS", () -> DecompilerGate.Breaker.negativeMs() / 1000);
		g.listenForCollections();
		Guarded.armReserve();
		Health.contribute("governor", g::describe);
		Guarded.start("session-governor", g::sampleLoop);
	}

	/** A governor with no session whose view count is {@code viewCounter} (the self-test). */
	static Governor forTest(java.util.function.IntSupplier viewCounter) {
		return new Governor(null, viewCounter);
	}

	/** Forgets the governor (the self-test). */
	static synchronized void stopForTest() {
		instance = null;
	}

	static Governor get() {
		return instance;
	}

	// ---- the heap figure ---------------------------------------------------------------------------

	private void listenForCollections() {
		NotificationListener l = (Notification n, Object hb) -> {
			if (!GarbageCollectionNotificationInfo.GARBAGE_COLLECTION_NOTIFICATION
					.equals(n.getType())) {
				return;
			}
			try {
				GarbageCollectionNotificationInfo info =
					GarbageCollectionNotificationInfo.from((CompositeData) n.getUserData());
				long sum = 0;
				for (Map.Entry<String, MemoryUsage> e : info.getGcInfo()
						.getMemoryUsageAfterGc()
						.entrySet()) {
					if (isHeapPool(e.getKey())) {
						sum += e.getValue().getUsed();
					}
				}
				afterGcBytes = sum;
				afterGcAtMs = System.currentTimeMillis();
				gcEvents.incrementAndGet();
			}
			catch (RuntimeException | LinkageError e) {
				// keep the previous figure
			}
		};
		for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
			if (gc instanceof NotificationEmitter ne) {
				ne.addNotificationListener(l, null, null);
			}
		}
	}

	private boolean isHeapPool(String name) {
		for (MemoryPoolMXBean p : heapPools) {
			if (p.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	/** The heap in use after the last collection, in bytes. */
	long heapAfterGc() {
		return afterGcBytes;
	}

	private String heapState(long bytes) {
		long max = Budgets.maxHeapBytes();
		if (bytes > max / 100 * Budgets.heapHardPct()) {
			return HARD;
		}
		if (bytes > max / 100 * Budgets.heapSoftPct()) {
			return SOFT;
		}
		return OK;
	}

	String heapState() {
		return heapState(afterGcBytes);
	}

	/**
	 * Collects (at most once every two seconds) and records what is left. Only called when a
	 * refusal is about to be made on a figure that might be stale.
	 *
	 * @return true when a collection ran
	 */
	private boolean refreshHeap() {
		return refreshHeap(false);
	}

	/**
	 * True when the governor may force a collection to measure the first open of a program (setting
	 * {@code forcedGc}, default on; PROTOCOL-3.md 8.18): two {@code System.gc()} per first open
	 * stop every thread of the daemon. Turned off, the first open is not measured and the estimate
	 * of 3.11 stays in use; the collection before a refusal is kept either way.
	 */
	static boolean measuringGcs() {
		return Settings.bool("forcedGc", true);
	}

	/**
	 * Like {@link #refreshHeap()}; {@code measuring} is a collection made only to measure (the first
	 * open of a program), which runs only when {@link #measuringGcs()} allows it.
	 */
	private boolean refreshHeap(boolean measuring) {
		if (measuring && !measuringGcs()) {
			return false;
		}
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (now - lastForcedGcMs < FORCED_GC_MIN_GAP_MS) {
				return false;
			}
			lastForcedGcMs = now;
		}
		System.gc();
		forcedGcs.incrementAndGet();
		Runtime rt = Runtime.getRuntime();
		afterGcBytes = rt.totalMemory() - rt.freeMemory();
		afterGcAtMs = System.currentTimeMillis();
		return true;
	}

	/**
	 * Closes the programs and projects nobody uses (they stay open only for {@code keepWarm}), so
	 * that room taken by warm retention is not a reason to refuse. Never waits.
	 *
	 * @return true when something was closed
	 */
	private boolean evictIdle() {
		int before = openViews();
		try {
			session.reap(0);
		}
		catch (RuntimeException e) {
			Msg.warn(this, "evicting idle programs: " + e);
		}
		return openViews() < before;
	}

	/** True above the hard watermark: {@code health.state} is {@code degraded}. */
	static boolean degraded() {
		Governor g = instance;
		return g != null && HARD.equals(g.heapState());
	}

	// ---- the busy answer -------------------------------------------------------------------------------

	/**
	 * {@code busy} with {@code details:{reason:"capacity", resource, have, need, retryAfterMs}}
	 * (3.13); the same details for a protocol 2 client (V8). Counts the refusal.
	 */
	static SessionException capacity(String resource, long have, long need, String message,
			long retryAfterMs) {
		REFUSED.computeIfAbsent(resource, k -> new AtomicLong()).incrementAndGet();
		long retry = Math.max(SessionException.RETRY_MIN_MS,
			Math.min(SessionException.RETRY_MAX_MS, retryAfterMs));
		JsonObject d = Json.of("reason", "capacity", "resource", resource, "have", have, "need",
			need, "retryAfterMs", retry);
		return new SessionException(SessionException.BUSY, message, d).withRetryAfterMs(retry);
	}

	static long refused(String resource) {
		AtomicLong n = REFUSED.get(resource);
		return n == null ? 0 : n.get();
	}

	// ---- admission -------------------------------------------------------------------------------------

	/** A granted admission: its reservation ends with {@link #close}. */
	static final class Admission implements AutoCloseable {
		private final Governor gov;
		private final String key;
		private final long estBytes;
		private final boolean newView;
		private final File viewFork;
		private final long forkBytes;
		/** The heap after a collection when the admission was granted; -1: not measured. */
		private volatile long gcAtAdmission;
		/** The client whose per-client share this admission holds, or null. */
		private final Client client;
		private boolean closed;

		private Admission(Governor gov, String key, long estBytes, boolean newView, File viewFork,
				long forkBytes, long gcAtAdmission) {
			this(gov, key, estBytes, newView, viewFork, forkBytes, gcAtAdmission, null);
		}

		private Admission(Governor gov, String key, long estBytes, boolean newView, File viewFork,
				long forkBytes, long gcAtAdmission, Client client) {
			this.gov = gov;
			this.key = key;
			this.estBytes = estBytes;
			this.newView = newView;
			this.viewFork = viewFork;
			this.forkBytes = forkBytes;
			this.gcAtAdmission = gcAtAdmission;
			this.client = client;
		}

		@Override
		public void close() {
			if (gov == null) {
				return;
			}
			synchronized (this) {
				if (closed) {
					return;
				}
				closed = true;
			}
			gov.release(this);
		}
	}

	/**
	 * Decides whether the daemon takes on {@code cmd}; a no-op for any other command and before
	 * the governor started.
	 *
	 * @return the reservation to close when the request ends
	 * @throws SessionException {@code busy} with {@code details.reason:"capacity"}
	 */
	static Admission admit(Client c, String cmd, JsonObject req) {
		Governor g = instance;
		if (g == null) {
			return NONE;
		}
		switch (cmd) {
			case "open_project":
				return g.admitProject(c);
			case "open_program":
			case "switch":
				return g.admitView(c, req);
			case "fork_project":
				return g.admitFork(c, req);
			case "import":
				return g.admitImport(c, req);
			default:
				return NONE;
		}
	}

	private void refuseIfDegraded(String what) {
		String st = heapState();
		if (HARD.equals(st) && refreshHeap()) {
			st = heapState();
		}
		if (HARD.equals(st)) {
			long max = Budgets.maxHeapBytes();
			throw capacity("heap", afterGcBytes >> 20, (max / 100 * Budgets.heapHardPct()) >> 20,
				"the daemon is degraded: the heap holds " + (afterGcBytes >> 20) + " MB after a " +
					"collection (above " + Budgets.heapHardPct() + "% of " + (max >> 20) +
					" MB); it refuses " + what + " until the heap falls and keeps serving reads",
				5000);
		}
	}

	/** A refusal found under the lock; the exception is made (and counted) only when it is thrown. */
	record Refusal(String resource, long have, long need, String message,
			long retryAfterMs) {
		SessionException toException() {
			return capacity(resource, have, need, message, retryAfterMs);
		}
	}

	/**
	 * The heap rule for {@code estBytes} more plus what requests in flight reserved: null when it
	 * holds. Must be called with {@link #lock} held when the reserved figure has to agree with a
	 * reservation made in the same step.
	 */
	private Refusal heapRefusal(long estBytes, String what) {
		long max = Budgets.maxHeapBytes();
		long limit = max / 100 * Budgets.heapSoftPct();
		long need = (long) (Budgets.EST_FACTOR * (estBytes + reservedEstBytes));
		long after = afterGcBytes;
		if (after + need <= limit) {
			return null;
		}
		return new Refusal("heap", (after + need) >> 20, limit >> 20,
			"the heap cannot take " + what + ": " + (after >> 20) + " MB in use after a " +
				"collection plus " + (need >> 20) + " MB estimated, against " + (limit >> 20) +
				" MB (" + Budgets.heapSoftPct() + "% of " + (max >> 20) + " MB). Close a " +
				"program or retry.",
			3000);
	}

	/**
	 * The heap rule for a request that reserves nothing (a project, a fork, an import). Programs
	 * nobody uses are let go, and the heap figure is refreshed once, before it refuses; neither
	 * happens under the lock.
	 */
	private void requireHeap(long estBytes, String what) {
		Refusal r = heapRefusalLocked(estBytes, what);
		if (r != null) {
			evictIdle();
			refreshHeap();
			r = heapRefusalLocked(estBytes, what);
		}
		if (r != null) {
			throw r.toException();
		}
	}

	private Refusal heapRefusalLocked(long estBytes, String what) {
		synchronized (lock) {
			return heapRefusal(estBytes, what);
		}
	}

	private Admission admitProject(Client c) {
		refuseIfDegraded("opening a project");
		requireHeap(Budgets.FLOOR_EST_HEAP, "this project");
		return NONE;
	}

	private Admission admitView(Client c, JsonObject req) {
		refuseIfDegraded("opening a program");
		String path = Json.str(req, "path", null);
		String projectKey = c.activeProject;
		if (path != null) {
			Matcher mk = Access.PROGRAM_KEY.matcher(path);
			if (mk.matches()) {
				projectKey = mk.group(1);
				path = mk.group(2);
			}
		}
		if (Json.has(req, "project") && req.get("project").isJsonPrimitive()) {
			projectKey = Json.str(req, "project");
		}
		ProgramEntry open = path == null ? null : findOpen(projectKey, path);
		String key = open != null ? open.key : projectKey == null || path == null ? null
				: projectKey + ":" + path;
		boolean mine = open != null && c.programs.contains(open.key);
		if (mine) {
			return NONE; // opening again what the client has: no new share
		}
		// a program already in memory for another client is shared: it costs the per-client share
		// only, no view and no heap
		boolean shared = open != null;
		long est = 0;
		if (!shared) {
			long db = databaseBytes(c, projectKey, path);
			est = Budgets.estHeap(key, db);
		}
		// The checks and the reservation are ONE step under the lock (reserve first, release on
		// failure), so that requests that arrive together cannot all pass the same count. What
		// frees room (idle programs, a collection) runs between two attempts, never under the lock.
		boolean evicted = false;
		boolean refreshed = false;
		boolean[] eligible = new boolean[1];
		while (true) {
			Refusal r = tryReserveView(c, shared, est, key, eligible);
			if (r == null) {
				break;
			}
			if ("views".equals(r.resource()) && !evicted) {
				evicted = true;
				evictIdle();
				continue;
			}
			if ("heap".equals(r.resource()) && !refreshed) {
				refreshed = true;
				if (!evicted) {
					evicted = true;
					evictIdle();
				}
				refreshHeap();
				continue;
			}
			throw r.toException();
		}
		Admission a = new Admission(this, key, est, !shared, null, 0, -1, c);
		if (shared) {
			return a;
		}
		try {
			// the first open of a program teaches its real cost: a collection now and one after the
			// open, only when the heap is small enough for a collection to be cheap
			Runtime rt = Runtime.getRuntime();
			if (eligible[0] && rt.totalMemory() - rt.freeMemory() < (1L << 30) &&
				refreshHeap(true)) {
				a.gcAtAdmission = afterGcBytes;
			}
		}
		catch (RuntimeException | Error e) {
			a.close();
			throw e;
		}
		return a;
	}

	/**
	 * One atomic step: the per-client share, the view count and the heap rule are checked and, when
	 * all hold, the reservation is made. Returns the first rule that does not hold (nothing is
	 * reserved then).
	 *
	 * @param eligible out: true when this is the only request in flight and the program's cost is
	 *            not known yet (the first open is then measured)
	 */
	Refusal tryReserveView(Client c, boolean shared, long est, String key, boolean[] eligible) {
		synchronized (lock) {
			int perClient = Budgets.maxViewsPerClient();
			int held = c.programs.size() + reservedByClient.getOrDefault(c, 0);
			if (held >= perClient) {
				return new Refusal("client_cap", held, perClient,
					"this client has " + held + " programs open or opening; the limit is " +
						perClient + " per client (maxViewsPerClient). Close one first.",
					2000);
			}
			if (!shared) {
				int maxViews = Budgets.maxViews();
				int views = viewCounter.getAsInt() + reservedViews;
				if (views >= maxViews) {
					return new Refusal("views", views, maxViews,
						"the daemon has " + views + " views open or opening; the limit is " +
							maxViews + " (maxViews). Close a program or retry.",
						3000);
				}
				Refusal h = heapRefusal(est, "another view");
				if (h != null) {
					return h;
				}
				eligible[0] = inFlight == 0 && key != null && !Budgets.learned(key);
				reservedViews++;
				reservedEstBytes += est;
				inFlight++;
			}
			reservedByClient.merge(c, 1, Integer::sum);
			return null;
		}
	}

	private Admission admitFork(Client c, JsonObject req) {
		refuseIfDegraded("a fork");
		requireHeap(Budgets.FLOOR_EST_HEAP, "this fork");
		long bytes = 0;
		File gpr = null;
		boolean view = "view".equals(Json.str(req, "purpose", null));
		String srcName = "fork";
		try {
			String srcKey = Json.str(req, "project", c.activeProject);
			ProjectEntry src = srcKey == null ? null : session.projectsById.get(srcKey);
			if (srcKey != null) {
				ProjectResolver.Resolved r =
					src != null ? src.resolved : ProjectResolver.resolve(srcKey);
				srcName = r.name();
				File rep = new File(r.dir(), r.name() + ".rep");
				bytes = folderBytes(rep.toPath());
			}
			String dest = Json.str(req, "path", null);
			if (dest != null) {
				File d = new File(dest).getAbsoluteFile();
				if (d.getName().endsWith(".gpr")) {
					gpr = d;
				}
				else {
					gpr = new File(d, Json.str(req, "name", srcName) + ".gpr");
				}
				requireDisk(d, estimateCopy(d, bytes), "this fork");
			}
		}
		catch (IOException | RuntimeException e) {
			if (e instanceof SessionException se && SessionException.BUSY.equals(se.code())) {
				throw se;
			}
			// anything else (a bad path, an unknown project): the command reports it itself
			return NONE;
		}
		if (view && gpr != null) {
			long budget = Budgets.viewDiskBudgetBytes();
			long held = viewForkBytes();
			if (held + bytes > budget) {
				throw capacity("disk", (held + bytes) >> 20, budget >> 20,
					"the view forks of this daemon hold " + (held >> 20) + " MB; another " +
						(bytes >> 20) + " MB would pass viewDiskBudget (" + (budget >> 20) +
						" MB). Delete a view fork first.",
					5000);
			}
			return new Admission(this, null, 0, false, gpr, bytes, -1);
		}
		return NONE;
	}

	private Admission admitImport(Client c, JsonObject req) {
		refuseIfDegraded("an import");
		long size = 0;
		File f = null;
		String file = Json.str(req, "file", null);
		if (file != null) {
			f = new File(file);
			size = f.isFile() ? f.length() : 0;
		}
		requireHeap(Math.max(Budgets.FLOOR_EST_HEAP, size), "this import");
		if (f != null && f.isFile()) {
			try {
				// the project of the client receives the program: its volume, twice the file
				requireDisk(f.getAbsoluteFile().getParentFile(), size * 2, "this import");
			}
			catch (IOException e) {
				// the command reports a bad path itself
			}
		}
		return NONE;
	}

	private ProgramEntry findOpen(String projectKey, String path) {
		for (ProjectEntry p : session.projects.values()) {
			if (projectKey != null && !projectKey.equals(p.id) && !projectKey.equals(
				p.resolved.gpr().getPath())) {
				continue;
			}
			for (ProgramEntry e : p.programs.values()) {
				if (e.program != null && (e.path.equals(path) || e.path.endsWith("/" + path))) {
					return e;
				}
			}
		}
		return null;
	}

	/** The stored size of the program's database, or 0 when it cannot be had cheaply. */
	private long databaseBytes(Client c, String projectKey, String path) {
		try {
			ProjectEntry p = projectKey == null ? null : session.projectsById.get(projectKey);
			if (p == null || path == null) {
				return 0;
			}
			DomainFile df = ProjectCommands.findFile(p, path);
			return df.length();
		}
		catch (IOException | RuntimeException e) {
			return 0;
		}
	}

	/** Open programs and overlays: the views that hold memory. */
	int openViews() {
		int n = 0;
		for (ProjectEntry p : session.projects.values()) {
			for (ProgramEntry e : p.programs.values()) {
				if (e.program != null) {
					n++;
				}
			}
		}
		return n + session.overlayCmds.overlays.size();
	}

	// ---- disk --------------------------------------------------------------------------------------

	private static long estimateCopy(File dest, long dbBytes) throws IOException {
		FileStore fs = storeOf(dest);
		// a block-cloning volume (ReFS) pays about 5% of the database; NTFS pays all of it
		return "ReFS".equalsIgnoreCase(fs.type()) ? dbBytes / 20 : dbBytes;
	}

	private static FileStore storeOf(File f) throws IOException {
		File p = f.getAbsoluteFile();
		while (p != null && !p.exists()) {
			p = p.getParentFile();
		}
		if (p == null) {
			throw new IOException("no existing parent of " + f);
		}
		return Files.getFileStore(p.toPath());
	}

	private static void requireDisk(File at, long estimate, String what) throws IOException {
		FileStore fs = storeOf(at);
		long usable = fs.getUsableSpace();
		long need = estimate + Budgets.diskReserveBytes(fs.getTotalSpace());
		if (usable < need) {
			throw capacity("disk", usable >> 20, need >> 20,
				"not enough free space for " + what + ": " + (usable >> 20) + " MB free on " + fs +
					", " + (estimate >> 20) + " MB needed plus the reserve of " +
					((need - estimate) >> 20) + " MB (diskReserve)",
				10_000);
		}
	}

	private static long folderBytes(Path dir) throws IOException {
		if (!Files.isDirectory(dir)) {
			return 0;
		}
		long[] sum = new long[1];
		int[] count = new int[1];
		Files.walkFileTree(dir, new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes a) {
				sum[0] += a.size();
				return ++count[0] > 200_000 ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
			}
		});
		return sum[0];
	}

	private long viewForkBytes() {
		long sum = 0;
		for (Map.Entry<String, Long> e : viewForks.entrySet()) {
			if (new File(e.getKey()).exists()) {
				sum += e.getValue();
			}
			else {
				viewForks.remove(e.getKey());
			}
		}
		return sum;
	}

	// ---- the end of a request ------------------------------------------------------------------------

	private void release(Admission a) {
		boolean sole = unreserve(a.client, a.newView, a.estBytes);
		if (a.viewFork != null && a.viewFork.exists()) {
			viewForks.put(a.viewFork.getPath(), a.forkBytes);
		}
		if (a.newView && a.gcAtAdmission >= 0 && sole) {
			learnFirstOpen(a);
		}
	}

	/**
	 * Gives back what {@link #tryReserveView} reserved.
	 *
	 * @return true when no other reservation of a new view is in flight
	 */
	boolean unreserve(Client c, boolean newView, long estBytes) {
		synchronized (lock) {
			if (newView) {
				reservedViews = Math.max(0, reservedViews - 1);
				reservedEstBytes = Math.max(0, reservedEstBytes - estBytes);
				inFlight = Math.max(0, inFlight - 1);
			}
			if (c != null) {
				reservedByClient.merge(c, -1, Integer::sum);
				reservedByClient.remove(c, 0);
			}
			return inFlight == 0;
		}
	}

	/** Views reserved by requests in flight (the self-test). */
	int reservedViewsNow() {
		synchronized (lock) {
			return reservedViews;
		}
	}

	/**
	 * The measured cost of the first open of a program: the heap after a collection now, less the
	 * heap after a collection when the admission was granted. Only when the heap is small (a
	 * collection of a big heap is not free) and the open succeeded.
	 */
	private void learnFirstOpen(Admission a) {
		Runtime rt = Runtime.getRuntime();
		if (rt.totalMemory() - rt.freeMemory() > (1L << 30)) {
			return;
		}
		ProgramEntry open = null;
		for (ProjectEntry p : session.projects.values()) {
			for (ProgramEntry e : p.programs.values()) {
				if (a.key != null && a.key.equals(e.key) && e.program != null) {
					open = e;
				}
			}
		}
		if (open == null) {
			return; // the open did not happen (an error): nothing to learn
		}
		long after = afterGcBytes;
		if (refreshHeap(true)) {
			after = afterGcBytes;
		}
		long cost = after - a.gcAtAdmission;
		if (cost > 0) {
			Budgets.learn(a.key, cost);
			lastEstBytes = cost;
		}
	}

	// ---- the sampling thread ----------------------------------------------------------------------

	private long lastSweepMs;

	private void sampleLoop() throws InterruptedException {
		while (!session.isShuttingDown()) {
			Guarded.beat(500); // proof of life in health.governor.threadState
			Thread.sleep(500);
			long now = System.currentTimeMillis();
			if (now - lastSweepMs >= 5_000) {
				lastSweepMs = now;
				int n = DecompilerGate.sweepIdle(Budgets.decompilerIdleS() * 1000L);
				if (n > 0) {
					Msg.info(this, "disposed " + n + " idle decompiler(s)");
				}
			}
			if (!Guarded.reserveArmed() && OK.equals(heapState())) {
				Guarded.armReserve();
			}
			// degraded is judged on the figure the last collection left: with no collection for a
			// while the figure is stale, so measure again (at most every 5 s, and only above the
			// hard watermark, where the daemon refuses work anyway)
			if (HARD.equals(heapState()) && now - afterGcAtMs > 5_000) {
				refreshHeap();
			}
		}
	}

	// ---- health ------------------------------------------------------------------------------------

	/** {@code health.governor} (3.13): views, limits, the heap figure, the gate and the counters. */
	JsonObject describe() {
		DecompilerGate gate = DecompilerGate.GATE;
		JsonObject gd = gate.describe();
		int permits = gd.get("permits").getAsInt();
		int inUse = gd.get("inUse").getAsInt();
		JsonObject refused = new JsonObject();
		for (String r : new String[] { "views", "client_cap", "heap", "native", "disk" }) {
			refused.addProperty(r, refused(r));
		}
		JsonObject o = Json.of("views", openViews(), "maxViews", Budgets.maxViews(),
			"heapAfterGcMb", afterGcBytes >> 20, "heapState", heapState(), "decompilers",
			DecompilerGate.live(), "tokens", Math.max(0, permits - inUse), "nativeBudgetMb",
			Budgets.nativeBudgetMb());
		Json.put(o, "maxViewsPerClient", Budgets.maxViewsPerClient());
		Json.put(o, "heapSoftPct", Budgets.heapSoftPct());
		Json.put(o, "heapHardPct", Budgets.heapHardPct());
		Json.put(o, "maxHeapMb", Budgets.maxHeapBytes() >> 20);
		Json.put(o, "decompilersIdle", DecompilerGate.idleTotal());
		o.add("gate", gd);
		o.add("failures", DecompilerGate.Breaker.describe());
		o.add("refused", refused);
		synchronized (lock) {
			Json.put(o, "reserved", reservedViews);
		}
		Json.put(o, "learned", Budgets.learnedCount());
		Json.put(o, "lastLearnedMb", lastEstBytes >> 20);
		Json.put(o, "collections", Json.of("seen", gcEvents.get(), "forced", forcedGcs.get(),
			"lastAgoMs", System.currentTimeMillis() - afterGcAtMs));
		Json.put(o, "reserve", Json.of("armed", Guarded.reserveArmed(), "released",
			Guarded.reserveReleases()));
		o.add("threads", Guarded.restarts());
		o.add("threadState", Guarded.states());
		return o;
	}
}
