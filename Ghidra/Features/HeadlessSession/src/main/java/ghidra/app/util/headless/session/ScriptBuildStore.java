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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.atomic.LongAdder;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;

/**
 * Persistent build cache of Java scripts (JVM lane, round 3).
 * <p>
 * A script is compiled by {@code javac} the first time its source directory is loaded in a
 * daemon, and the compiled classes live under the daemon's own settings directory
 * ({@code <settings>/osgi/compiled-bundles/<hash of the source dir path>}). Both the source path
 * and that settings directory change whenever a harness runs the engine from a new working
 * directory, so a benchmark, a test run or a fresh install pays a full {@code javac} per script
 * again: 5-6 CPU s of the engine's start-up on this machine for the two scripts the benchmark
 * uses, and about 1 s inside the measured workload for the first agent's script call.
 * <p>
 * This store keys the compiled classes by the <b>content</b> of the source directory instead: the
 * fingerprint is a SHA-256 over every file's relative path and bytes plus the install and the
 * Java version, and the classes keep the source directory's relative layout so that a script's
 * other classes (inner classes, sibling files of the same bundle) load from the same directory.
 * On the first call of a script in a new daemon {@link ScriptClassCache} looks the fingerprint up
 * and loads the class from a plain {@link URLClassLoader} whose parent is the engine's own class
 * loader, instead of running the OSGi build. Any failure there falls back to the unchanged OSGi
 * path, so the fast path can only ever <i>skip</i> a compile whose result is already on disk.
 * <p>
 * Only clean bundles are stored — {@link ScriptClassCache#remember} already refuses a bundle with
 * build errors or requirements — and the fingerprint covers the whole source directory, so an
 * edited script, an edited sibling file, an added file or a removed file is a different
 * fingerprint and compiles as before. The store lives next to the shared class-search cache
 * ({@code ghidra.session.classCache}), which is already shared by every daemon of the install;
 * {@code -Dhydra.script.buildCache=false} turns it off.
 */
final class ScriptBuildStore {

	private static final boolean PROPERTY =
		!"false".equalsIgnoreCase(System.getProperty("hydra.script.buildCache", "true"));

	/** At most this many bundles are kept; the oldest (by modification time) go first. */
	static final int MAX_ENTRIES = 256;
	/** At most this many bytes of compiled classes are kept. */
	static final long MAX_BYTES = 64L << 20;
	/** A source directory larger than this is not fingerprinted (its read would cost too much). */
	static final int MAX_FILES = 4096;
	static final long MAX_SOURCE_BYTES = 8L << 20;

	private static final LongAdder HITS = new LongAdder();
	private static final LongAdder MISSES = new LongAdder();
	private static final LongAdder STORES = new LongAdder();
	private static final LongAdder FAILURES = new LongAdder();
	private static final LongAdder LOADED = new LongAdder();

	private ScriptBuildStore() {
	}

	/** Whether the persistent build cache is on ({@code -set scriptBuildCache=false} off). */
	static boolean enabled() {
		return PROPERTY && Settings.bool("scriptBuildCache", true);
	}

	/** {@code health.scriptCache}'s persistent figures (added fields of that member). */
	static void describe(com.google.gson.JsonObject o) {
		o.addProperty("buildHits", HITS.sum());
		o.addProperty("buildMisses", MISSES.sum());
		o.addProperty("buildStores", STORES.sum());
		o.addProperty("buildFailures", FAILURES.sum());
		o.addProperty("buildLoadedClasses", LOADED.sum());
		try {
			Path root = root();
			int entries = 0;
			long bytes = 0;
			if (Files.isDirectory(root)) {
				try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
					for (Path p : ds) {
						if (!Files.isDirectory(p)) {
							continue;
						}
						entries++;
						bytes += sizeOf(p);
					}
				}
			}
			o.addProperty("buildEntries", entries);
			o.addProperty("buildBytes", bytes);
		}
		catch (IOException | RuntimeException e) {
			o.addProperty("buildEntries", -1);
			o.addProperty("buildBytes", -1);
		}
	}

	/** The directory the store lives in: next to the shared class-search cache when given. */
	private static volatile Path root;

	private static Path root() {
		Path r = root;
		if (r != null) {
			return r;
		}
		synchronized (ScriptBuildStore.class) {
			if (root == null) {
				Path p = null;
				String cache = System.getProperty(SessionApplicationConfiguration.CACHE_PROPERTY);
				if (cache != null && !cache.isBlank()) {
					Path file = Path.of(cache).toAbsolutePath();
					Path parent = file.getParent();
					if (parent != null) {
						// <shared state root>/classcache/script-builds: the file itself is shared by
						// every daemon of the install (ghidra_session.py's classCacheDir)
						p = parent.resolve("script-builds");
					}
				}
				if (p == null) {
					p = BundleHost.getOsgiDir().resolve("script-builds");
				}
				root = p;
			}
			return root;
		}
	}

	/**
	 * The fingerprint of a source directory: a SHA-256 over the install, the Java version and
	 * every file's relative path and bytes, in sorted path order; null when the directory cannot
	 * be read or is too large to fingerprint.
	 */
	static String fingerprint(ResourceFile dir) {
		java.io.File f = dir.getFile(false);
		if (f == null) {
			return null;
		}
		Path root = f.toPath();
		List<Path> files = new ArrayList<>();
		try {
			Files.walkFileTree(root, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path p, BasicFileAttributes a)
						throws IOException {
					if (a.isRegularFile()) {
						if (files.size() >= MAX_FILES) {
							throw new IOException("too many files");
						}
						files.add(p);
					}
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
		List<String> rel = new ArrayList<>(files.size());
		long total = 0;
		for (Path p : files) {
			rel.add(root.relativize(p).toString().replace('\\', '/'));
			try {
				total += Files.size(p);
			}
			catch (IOException e) {
				return null;
			}
		}
		if (total > MAX_SOURCE_BYTES) {
			return null;
		}
		// sort paths together with their files: the same directory always fingerprints the same
		Integer[] order = new Integer[files.size()];
		for (int i = 0; i < order.length; i++) {
			order[i] = i;
		}
		Arrays.sort(order, Comparator.comparing(rel::get));
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			update(md, installIdentity());
			byte[] buf = new byte[8192];
			for (int i : order) {
				update(md, rel.get(i));
				try (InputStream in = Files.newInputStream(files.get(i))) {
					int n;
					while ((n = in.read(buf)) > 0) {
						md.update(buf, 0, n);
					}
				}
			}
			return hex(md.digest());
		}
		catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
			return null;
		}
	}

	private static String installIdentity() {
		String install;
		try {
			install = Application.getInstallationDirectory().getAbsolutePath();
		}
		catch (RuntimeException e) {
			install = "";
		}
		String version;
		try {
			version = Application.getApplicationVersion();
		}
		catch (RuntimeException e) {
			version = "";
		}
		return install + '\u0000' + version + '\u0000' + System.getProperty("java.version", "") +
			'\u0000' + System.getProperty("java.home", "");
	}

	private static void update(MessageDigest md, String s) {
		byte[] b = s.getBytes(StandardCharsets.UTF_8);
		md.update(b);
		md.update((byte) 0);
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (byte x : b) {
			sb.append(Character.forDigit((x >> 4) & 15, 16));
			sb.append(Character.forDigit(x & 15, 16));
		}
		return sb.toString();
	}

	/**
	 * The class of {@code src} from the stored build of its source directory {@code dir} at
	 * {@code fingerprint}, or null when the store holds no build for it (or anything goes wrong,
	 * which then takes the unchanged OSGi path).
	 */
	static Class<?> load(ResourceFile src, ResourceFile dir, String fingerprint) {
		try {
			Path build = root().resolve(fingerprint);
			String rel = relative(dir, src);
			if (rel == null || !rel.endsWith(".java")) {
				MISSES.increment();
				return null;
			}
			String classRel = rel.substring(0, rel.length() - ".java".length()) + ".class";
			if (!Files.isRegularFile(build.resolve(classRel.replace('/', java.io.File.separatorChar)))) {
				MISSES.increment();
				return null;
			}
			String className = rel.substring(0, rel.length() - ".java".length())
					.replace('/', '.');
			ClassLoader parent = GhidraScript.class.getClassLoader();
			URLClassLoader loader =
				new URLClassLoader(new URL[] { build.toUri().toURL() }, parent);
			Class<?> c = Class.forName(className, true, loader);
			if (!GhidraScript.class.isAssignableFrom(c)) {
				MISSES.increment();
				return null;
			}
			HITS.increment();
			LOADED.increment();
			return c;
		}
		catch (Throwable t) {
			MISSES.increment();
			FAILURES.increment();
			return null;
		}
	}

	/** The path of {@code src} below {@code dir}, with {@code /} separators, or null. */
	private static String relative(ResourceFile dir, ResourceFile src) {
		String d = dir.getAbsolutePath().replace('\\', '/');
		String s = src.getAbsolutePath().replace('\\', '/');
		if (!s.startsWith(d.endsWith("/") ? d : d + "/")) {
			return null;
		}
		return s.substring(d.endsWith("/") ? d.length() : d.length() + 1);
	}

	/**
	 * Stores the compiled classes of {@code binaryDir} under {@code fingerprint} (once: an
	 * existing build is left as it is). Only class files are copied, with their relative paths.
	 */
	static void store(String fingerprint, Path binaryDir) {
		if (fingerprint == null || binaryDir == null || !Files.isDirectory(binaryDir)) {
			return;
		}
		Path build = root().resolve(fingerprint);
		if (Files.isDirectory(build)) {
			return;
		}
		Path tmp = null;
		try {
			Files.createDirectories(root());
			tmp = Files.createTempDirectory(root(), fingerprint + ".tmp-");
			int copied = 0;
			List<Path> files = new ArrayList<>();
			Files.walkFileTree(binaryDir, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path p, BasicFileAttributes a) {
					if (a.isRegularFile() && p.getFileName().toString().endsWith(".class")) {
						files.add(p);
					}
					return FileVisitResult.CONTINUE;
				}
			});
			for (Path p : files) {
				Path to = tmp.resolve(binaryDir.relativize(p).toString());
				Files.createDirectories(to.getParent());
				Files.copy(p, to, StandardCopyOption.REPLACE_EXISTING);
				copied++;
			}
			if (copied == 0) {
				return;
			}
			try {
				Files.move(tmp, build, StandardCopyOption.ATOMIC_MOVE);
				tmp = null;
				STORES.increment();
			}
			catch (FileAlreadyExistsException | DirectoryNotEmptyException e) {
				// another process stored the same build first: its copy is the same bytes
			}
			prune();
		}
		catch (IOException | RuntimeException e) {
			FAILURES.increment();
		}
		finally {
			if (tmp != null) {
				deleteTree(tmp);
			}
		}
	}

	/** Drops the oldest builds while the store is over its entry or byte bound. */
	private static void prune() {
		try {
			Path root = root();
			List<Path> dirs = new ArrayList<>();
			try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
				for (Path p : ds) {
					if (Files.isDirectory(p) && !p.getFileName().toString().contains(".tmp-")) {
						dirs.add(p);
					}
				}
			}
			if (dirs.size() <= MAX_ENTRIES) {
				long total = 0;
				for (Path p : dirs) {
					total += sizeOf(p);
				}
				if (total <= MAX_BYTES) {
					return;
				}
			}
			dirs.sort(Comparator.comparingLong(ScriptBuildStore::mtime));
			long total = 0;
			for (Path p : dirs) {
				total += sizeOf(p);
			}
			int deleted = 0;
			while (deleted < dirs.size() &&
				(dirs.size() - deleted > MAX_ENTRIES || total > MAX_BYTES)) {
				Path p = dirs.get(deleted++);
				total -= sizeOf(p);
				deleteTree(p);
			}
		}
		catch (IOException | RuntimeException e) {
			// the store is only a cache: a prune that did not run costs disk, never correctness
		}
	}

	private static long mtime(Path p) {
		try {
			return Files.getLastModifiedTime(p).toMillis();
		}
		catch (IOException e) {
			return 0;
		}
	}

	private static long sizeOf(Path dir) {
		long[] total = { 0 };
		try {
			Files.walkFileTree(dir, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path p, BasicFileAttributes a) {
					total[0] += a.size();
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException | RuntimeException e) {
			return 0;
		}
		return total[0];
	}

	private static void deleteTree(Path dir) {
		try {
			Files.walkFileTree(dir, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path p, BasicFileAttributes a)
						throws IOException {
					Files.deleteIfExists(p);
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path d, IOException ex)
						throws IOException {
					Files.deleteIfExists(d);
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException | RuntimeException e) {
			// best effort
		}
	}
}
