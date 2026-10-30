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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.osgi.framework.Bundle;

import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.script.*;

/**
 * The loaded classes of Java scripts whose source bundle did not change (Hydra, daemon-async).
 * <p>
 * {@code JavaScriptProvider.getScriptInstance} takes the OSGi parallel lock (an in-JVM lock plus a
 * file lock that every Ghidra process on the machine shares) and activates the script's source
 * bundle, which walks the bundle's directory and rebuilds the bundle dependency graph, for every
 * script run; the daemon also ran it under its one {@code SCRIPT_COMPILE} monitor. So every
 * {@code script} request of every client queued behind every other one's load (measured: 105 waits,
 * 286 ms on average, up to 1.44 s, in the 16-agent benchmark), and behind other Ghidra processes.
 * <p>
 * Once a script was loaded this way, its class is kept with the OSGi bundle it came from and a
 * fingerprint of the bundle's source directory (every file's relative path, size and modification
 * time, read before the load). A later run of the same source file instantiates the kept class
 * directly, without either lock, when:
 * <ul>
 * <li>the fingerprint is unchanged (no source or resource of the bundle was added, removed or
 * modified: then the bundle activation would rebuild nothing either);</li>
 * <li>the bundle had no build errors at the load (an activation would report them again);</li>
 * <li>the bundle is still {@code ACTIVE} and loading the class name from it still gives the kept
 * class (a bundle another load rebuilt, refreshed or stopped gives a new class or none).</li>
 * </ul>
 * Otherwise the run takes the full path as before and its result replaces the entry. Only Java
 * scripts of a source bundle on the file system are kept; other providers always take the full
 * path. The instance is made the way {@code JavaScriptProvider} makes it (no-argument constructor,
 * {@code setSourceFile}). {@code -set scriptClassCache=false} turns it off.
 */
final class ScriptClasses {

	private record Entry(Class<?> cls, Bundle osgi, String className, long fingerprint) {
	}

	private static final ConcurrentHashMap<String, Entry> ENTRIES = new ConcurrentHashMap<>();
	private static final AtomicLong HITS = new AtomicLong();
	private static final AtomicLong LOADS = new AtomicLong();
	private static final AtomicLong STALE = new AtomicLong();

	static {
		Health.contribute("scriptClasses", ScriptClasses::describe);
	}

	private ScriptClasses() {
	}

	static boolean enabled() {
		return Settings.bool("scriptClassCache", true);
	}

	/** One script run's look-up: the instance from a kept class, or what a full load stores. */
	static final class Lookup {
		private final ResourceFile src;
		private final String key;
		private final File dir;
		private final long fingerprint;
		private final GhidraScript instance;

		private Lookup(ResourceFile src, String key, File dir, long fingerprint,
				GhidraScript instance) {
			this.src = src;
			this.key = key;
			this.dir = dir;
			this.fingerprint = fingerprint;
			this.instance = instance;
		}

		/** A new instance of the kept class, or null: load it the full way. */
		GhidraScript instance() {
			return instance;
		}

		/** After a full load of {@code s} by {@code provider}: keep its class when allowed. */
		void remember(GhidraScriptProvider provider, GhidraScript s) {
			LOADS.incrementAndGet();
			if (key == null || !(provider instanceof JavaScriptProvider jp)) {
				return;
			}
			try {
				GhidraSourceBundle b = jp.getBundleForSource(src);
				if (b == null || !b.getAllErrors().isEmpty()) {
					ENTRIES.remove(key);
					return;
				}
				Bundle osgi = b.getOSGiBundle();
				String cn = b.classNameForScript(src);
				File d = b.getFile().getFile(false);
				if (osgi == null || d == null || !d.equals(dir) ||
					osgi.getState() != Bundle.ACTIVE || osgi.loadClass(cn) != s.getClass()) {
					ENTRIES.remove(key);
					return;
				}
				ENTRIES.put(key, new Entry(s.getClass(), osgi, cn, fingerprint));
			}
			catch (Exception | LinkageError e) {
				ENTRIES.remove(key);
			}
		}
	}

	/** The look-up of {@code src}; never throws. */
	static Lookup lookup(ResourceFile src) {
		if (!enabled()) {
			return new Lookup(src, null, null, 0, null);
		}
		try {
			File f = src.getFile(false);
			if (f == null || !f.getName().endsWith(".java")) {
				return new Lookup(src, null, null, 0, null);
			}
			ResourceFile sd = GhidraScriptUtil.findSourceDirectoryContaining(src);
			File dir = sd == null ? null : sd.getFile(false);
			if (dir == null) {
				return new Lookup(src, null, null, 0, null);
			}
			String key = f.getCanonicalPath();
			long fp = fingerprint(dir.toPath());
			Entry e = ENTRIES.get(key);
			if (e != null) {
				GhidraScript s = instantiate(e, fp, src);
				if (s != null) {
					HITS.incrementAndGet();
					return new Lookup(src, key, dir, fp, s);
				}
				STALE.incrementAndGet();
				ENTRIES.remove(key, e);
			}
			return new Lookup(src, key, dir, fp, null);
		}
		catch (IOException | RuntimeException e) {
			return new Lookup(src, null, null, 0, null);
		}
	}

	private static GhidraScript instantiate(Entry e, long fp, ResourceFile src) {
		if (e.fingerprint() != fp || e.osgi().getState() != Bundle.ACTIVE) {
			return null;
		}
		try {
			if (e.osgi().loadClass(e.className()) != e.cls()) {
				return null;
			}
			GhidraScript s = (GhidraScript) e.cls().getDeclaredConstructor().newInstance();
			s.setSourceFile(src);
			return s;
		}
		catch (Exception | LinkageError x) {
			return null;
		}
	}

	/**
	 * The fingerprint of a source directory: every regular file's relative path, size and
	 * modification time, folded in path order.
	 *
	 * @throws RuntimeException when the directory holds more than {@link #MAX_FILES} files (the
	 *             caller then loads the full way)
	 */
	static final int MAX_FILES = 4096;

	/** A source directory with more than {@link #MAX_FILES} files is not fingerprinted. */
	private static final class TooMany extends RuntimeException {
		TooMany() {
			super(null, null, false, false);
		}
	}

	static long fingerprint(Path dir) throws IOException {
		java.util.TreeMap<String, long[]> files = new java.util.TreeMap<>();
		Files.walkFileTree(dir, new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes a) {
				if (a.isRegularFile()) {
					if (files.size() >= MAX_FILES) {
						throw new TooMany();
					}
					files.put(dir.relativize(file).toString(),
						new long[] { a.size(), a.lastModifiedTime().toMillis() });
				}
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
				throw exc;
			}
		});
		long h = 0xcbf29ce484222325L; // FNV-1a over path characters, sizes and times
		for (var en : files.entrySet()) {
			String k = en.getKey();
			for (int i = 0; i < k.length(); i++) {
				h = (h ^ k.charAt(i)) * 0x100000001b3L;
			}
			h = (h ^ 0xffff) * 0x100000001b3L;
			h = (h ^ en.getValue()[0]) * 0x100000001b3L;
			h = (h ^ en.getValue()[1]) * 0x100000001b3L;
		}
		return h ^ files.size();
	}

	static JsonObject describe() {
		return Json.of("enabled", enabled(), "classes", ENTRIES.size(), "hits", HITS.get(),
			"loads", LOADS.get(), "stale", STALE.get());
	}
}
