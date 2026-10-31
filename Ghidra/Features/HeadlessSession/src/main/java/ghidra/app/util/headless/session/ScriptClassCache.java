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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import org.osgi.framework.Bundle;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.app.script.*;

/**
 * Resolved-script cache of the {@code script} command (hotspot H4).
 * <p>
 * {@link JavaScriptProvider#getScriptInstance} runs {@link BundleHost#activateAll} on every
 * call: it builds a dependency graph over every enabled bundle (walking every script directory
 * for its packages), checks the script's source bundle against its compiled classes, and
 * activates it. When nothing changed that is all work without effect, and it ran under the
 * session's global {@code SCRIPT_COMPILE} lock, so every Hydralysis query paid it in series.
 * <p>
 * This cache keeps the loaded {@link Class} of a Java script after a successful load and hands
 * out new instances of it while <i>all</i> of these still hold, checked on every call:
 * <ul>
 * <li>the stat (relative path, size, modification time to the file system's resolution) of
 * every file under the script's source bundle directory is what it was before the load that
 * filled the entry: a changed, added, removed or renamed source (or manifest) misses;</li>
 * <li>the bundle host saw no build that compiled anything, no deactivation, no enablement
 * change and no added or removed bundle since the entry was made (a generation counter, read
 * after the load: the load's own build does not invalidate it, and a rebuild of the bundle by
 * anyone else replaces its OSGi bundle, which the next check sees);</li>
 * <li>the script directory still maps to the same, enabled source bundle, and its OSGi bundle
 * is the same object and active;</li>
 * <li>the compiled bundle's manifest under the OSGi user directory (shared by every process of
 * the same install version) has the stat it had at the load: another process wiping or
 * recompiling it misses, and the usual path rebuilds as before.</li>
 * </ul>
 * A generation bump drops every entry at once, so none keeps an old bundle's class loader. Runs
 * share a soft bound ({@link #enterRun}).
 * Only loads whose activation could not have printed anything or depended on another bundle
 * are cached: the bundle has no build errors (which {@code build} reports on every call) and no
 * requirements (no {@code @importpackage}, no source manifest imports), so its dependency graph
 * is the bundle alone. Anything else, and every miss, takes the unchanged path.
 * <p>
 * The stat snapshot is taken <i>before</i> the load: a file changed during the load leaves an
 * entry that misses at the next call, never one that hides the change.
 * <p>
 * {@code -Dhydra.script.classCache=false} turns it off.
 */
final class ScriptClassCache {

	private static final boolean PROPERTY =
		!"false".equalsIgnoreCase(System.getProperty("hydra.script.classCache", "true"));

	/**
	 * {@code -Dhydra.script.classCache=false} or {@code -set scriptClassCache=false} (the setting
	 * of daemon-async's former second cache, which this class replaced) turns it off.
	 */
	static boolean enabled() {
		return PROPERTY && Settings.bool("scriptClassCache", true);
	}

	private static final int MAX_ENTRIES = 256;
	/** A source directory larger than this is not fingerprinted (its walk would cost too much). */
	private static final int MAX_FILES = 4096;

	private static final AtomicLong GENERATION = new AtomicLong();
	private static final Map<String, Entry> CACHE = new ConcurrentHashMap<>();
	private static final LongAdder HITS = new LongAdder();
	private static final LongAdder MISSES = new LongAdder();
	private static final LongAdder STALE = new LongAdder();
	private static volatile BundleHost listening;

	private ScriptClassCache() {
	}

	/** One file of a source bundle directory. */
	private record Stat(String rel, long size, long mtimeNanos) {
	}

	/** What a load saw before it ran: the files of its source directory. */
	record Before(ResourceFile sourceDir, List<Stat> stats) {
	}

	/**
	 * {@code binManifest}/{@code binStat}: the compiled bundle's manifest under the OSGi user
	 * directory and its stat at load time. Installs with the same version share that directory
	 * across processes; when another process wipes or recompiles it, the usual path rebuilds,
	 * so a hit must miss.
	 */
	private record Entry(ResourceFile sourceDir, List<Stat> stats, long generation,
			GhidraSourceBundle bundle, Bundle osgi, Class<?> clazz, Path binManifest,
			Stat binStat) {
	}

	/**
	 * Soft bound on scripts executing at once. Before the cache, every run queued behind the
	 * global load lock, which staggered them; lock-free hits let any number overlap and the
	 * daemon's peak heap grew with them. A run waits for a permit at most {@link #RUN_WAIT_MS}
	 * (or until its request is cancelled) and then runs anyway, so a long script never blocks
	 * others for more than that. Sized from the CPUs the OS grants the process.
	 * {@code -Dhydra.script.maxConcurrent=0} turns it off.
	 */
	static final int RUN_PERMITS = Integer.getInteger("hydra.script.maxConcurrent",
		Math.max(2, Runtime.getRuntime().availableProcessors() / 4));
	static final long RUN_WAIT_MS = Long.getLong("hydra.script.maxConcurrentWaitMs", 2000L);
	private static final java.util.concurrent.Semaphore RUNS =
		new java.util.concurrent.Semaphore(Math.max(1, RUN_PERMITS), true);
	private static final LongAdder RUN_WAITED = new LongAdder();
	private static final LongAdder RUN_OVERFLOW = new LongAdder();

	/**
	 * Takes a run permit, waiting at most {@link #RUN_WAIT_MS}; true when one was taken (pass it
	 * to {@link #exitRun}). Never throws.
	 */
	static boolean enterRun(RequestMonitor m) {
		if (RUN_PERMITS <= 0) {
			return false;
		}
		if (RUNS.tryAcquire()) {
			return true;
		}
		RUN_WAITED.increment();
		long deadline = System.nanoTime() + RUN_WAIT_MS * 1_000_000L;
		try {
			while (m == null || !m.isCancelled()) {
				long left = deadline - System.nanoTime();
				if (left <= 0) {
					break;
				}
				if (RUNS.tryAcquire(Math.min(left, 50_000_000L),
					java.util.concurrent.TimeUnit.NANOSECONDS)) {
					return true;
				}
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
		RUN_OVERFLOW.increment();
		return false;
	}

	static void exitRun(boolean held) {
		if (held) {
			RUNS.release();
		}
	}

	/** {@code health.scriptCache}: on, hits, misses and entries since start, and the run bound. */
	static com.google.gson.JsonElement describe() {
		return Json.of("enabled", enabled(), "hits", HITS.sum(), "misses", MISSES.sum(), "stale", STALE.sum(), "entries",
			CACHE.size(), "runPermits", RUN_PERMITS, "runWaited", RUN_WAITED.sum(), "runOverflow",
			RUN_OVERFLOW.sum());
	}

	/**
	 * A new instance of the cached class of {@code src}, or null when there is no valid entry
	 * (the caller then loads it the usual way). Never throws: anything unexpected is a miss.
	 */
	static GhidraScript instance(ResourceFile src) {
		if (!enabled()) {
			return null;
		}
		String key = src.getAbsolutePath();
		Entry e = CACHE.get(key);
		if (e == null) {
			MISSES.increment();
			return null;
		}
		try {
			BundleHost host = GhidraScriptUtil.getBundleHost();
			if (host == null || host != listening || e.generation != GENERATION.get() ||
				!valid(host, e) || !e.binStat.equals(statOf(e.binManifest)) ||
				!e.stats.equals(stats(e.sourceDir))) {
				CACHE.remove(key, e);
				STALE.increment();
				MISSES.increment();
				return null;
			}
			GhidraScript s = (GhidraScript) e.clazz.getDeclaredConstructor().newInstance();
			s.setSourceFile(src);
			HITS.increment();
			return s;
		}
		catch (Throwable t) {
			// the usual path reports whatever this was, in its own words
			CACHE.remove(key, e);
			MISSES.increment();
			return null;
		}
	}

	private static boolean valid(BundleHost host, Entry e) {
		GhidraBundle now = host.getGhidraBundle(e.sourceDir);
		if (now != e.bundle || !now.isEnabled()) {
			return false;
		}
		Bundle osgi = now.getOSGiBundle();
		return osgi == e.osgi && osgi.getState() == Bundle.ACTIVE;
	}

	/**
	 * What a load of {@code src} by {@code provider} must remember to be cached afterwards, or
	 * null when it cannot be. Call it before the load.
	 */
	static Before before(ResourceFile src, GhidraScriptProvider provider) {
		if (!enabled() || !(provider instanceof JavaScriptProvider)) {
			return null;
		}
		try {
			BundleHost host = GhidraScriptUtil.getBundleHost();
			if (host == null) {
				return null;
			}
			listen(host);
			ResourceFile dir = GhidraScriptUtil.findSourceDirectoryContaining(src);
			if (dir == null) {
				return null;
			}
			List<Stat> st = stats(dir);
			return st == null ? null : new Before(dir, st);
		}
		catch (Throwable t) {
			return null;
		}
	}

	/**
	 * Remembers the class of {@code script}, which {@code provider} just loaded from {@code src}
	 * after {@link #before}, when the load qualifies (see the class comment).
	 */
	static void remember(ResourceFile src, GhidraScriptProvider provider, Before b,
			GhidraScript script) {
		if (b == null || script == null) {
			return;
		}
		try {
			BundleHost host = GhidraScriptUtil.getBundleHost();
			if (host != listening ||
				!(provider instanceof JavaScriptProvider jp) ||
				!(jp.getBundleForSource(src) instanceof GhidraSourceBundle bundle)) {
				return;
			}
			if (host.getGhidraBundle(b.sourceDir) != bundle || !bundle.isEnabled() ||
				!bundle.getAllErrors().isEmpty() || !bundle.getAllRequirements().isEmpty()) {
				return;
			}
			Bundle osgi = bundle.getOSGiBundle();
			if (osgi == null || osgi.getState() != Bundle.ACTIVE ||
				script.getClass().getClassLoader() != classLoaderOf(osgi)) {
				return;
			}
			Path binManifest = binaryManifestOf(osgi);
			Stat binStat = binManifest == null ? null : statOf(binManifest);
			if (binStat == null || binStat.size() < 0) {
				return;
			}
			long gen = GENERATION.get();
			if (CACHE.size() >= MAX_ENTRIES) {
				CACHE.clear();
			}
			CACHE.put(src.getAbsolutePath(), new Entry(b.sourceDir, b.stats, gen, bundle, osgi,
				script.getClass(), binManifest, binStat));
		}
		catch (Throwable t) {
			// not cached: the next call takes the usual path again
		}
	}

	/**
	 * The compiled manifest of a source bundle, from its OSGi location
	 * ({@code reference:file://<binaryDir>}, see {@link GhidraSourceBundle}), or null.
	 */
	private static Path binaryManifestOf(Bundle osgi) {
		String loc = osgi.getLocation();
		String prefix = "reference:file://";
		if (loc == null || !loc.startsWith(prefix)) {
			return null;
		}
		return Paths.get(loc.substring(prefix.length())).resolve("META-INF").resolve(
			"MANIFEST.MF");
	}

	/** The stat of one file, or a marker stat when it is missing or unreadable. */
	private static Stat statOf(Path p) {
		try {
			BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
			Instant t = a.lastModifiedTime().toInstant();
			return new Stat("", a.size(), t.getEpochSecond() * 1_000_000_000L + t.getNano());
		}
		catch (IOException | RuntimeException ex) {
			return new Stat("", -2, -2);
		}
	}

	private static ClassLoader classLoaderOf(Bundle osgi) {
		org.osgi.framework.wiring.BundleWiring w =
			osgi.adapt(org.osgi.framework.wiring.BundleWiring.class);
		return w == null ? null : w.getClassLoader();
	}

	/** Forgets everything (tests). */
	static void clear() {
		CACHE.clear();
	}

	private static void listen(BundleHost host) {
		if (listening == host) {
			return;
		}
		synchronized (ScriptClassCache.class) {
			if (listening == host) {
				return;
			}
			host.addListener(new BundleHostListener() {
				@Override
				public void bundleBuilt(GhidraBundle bundle, String summary) {
					// a build with nothing to compile reports null; it changes nothing
					if (summary != null) {
						bump();
					}
				}

				@Override
				public void bundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
					bump();
				}

				@Override
				public void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
					if (!newActivation) {
						bump();
					}
				}

				@Override
				public void bundleAdded(GhidraBundle bundle) {
					bump();
				}

				@Override
				public void bundlesAdded(Collection<GhidraBundle> bundles) {
					bump();
				}

				@Override
				public void bundleRemoved(GhidraBundle bundle) {
					bump();
				}

				@Override
				public void bundlesRemoved(Collection<GhidraBundle> bundles) {
					bump();
				}
			});
			CACHE.clear();
			GENERATION.incrementAndGet();
			listening = host;
		}
	}

	private static void bump() {
		GENERATION.incrementAndGet();
		// every entry is invalid now: drop them so that none keeps an old bundle's class loader
		CACHE.clear();
	}

	/**
	 * The stat of every file and directory under {@code dir}, in walk order (sorted per
	 * directory), or null when it cannot be taken.
	 */
	private static List<Stat> stats(ResourceFile dir) {
		File f = dir.getFile(false);
		if (f == null) {
			return null;
		}
		Path root = f.toPath();
		List<Stat> out = new ArrayList<>();
		try {
			Files.walkFileTree(root, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes a)
						throws IOException {
					return add(d, a);
				}

				@Override
				public FileVisitResult visitFile(Path p, BasicFileAttributes a) throws IOException {
					return add(p, a);
				}

				@Override
				public FileVisitResult visitFileFailed(Path p, IOException ex) throws IOException {
					throw ex;
				}

				private FileVisitResult add(Path p, BasicFileAttributes a) throws IOException {
					if (out.size() >= MAX_FILES) {
						throw new IOException("too many files");
					}
					Instant t = a.lastModifiedTime().toInstant();
					out.add(new Stat(root.relativize(p).toString(),
						a.isDirectory() ? -1 : a.size(),
						t.getEpochSecond() * 1_000_000_000L + t.getNano()));
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException | RuntimeException ex) {
			return null;
		}
		// the walk order is the directory listing order: sort so that equal trees compare equal
		out.sort(Comparator.comparing(Stat::rel));
		return out;
	}
}
