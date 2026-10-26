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
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.GhidraClassLoader;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.net.DefaultSSLContextInitializer;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;

/**
 * The headless configuration, plus a class search cache.
 * <p>
 * {@link ClassSearcher#search} walks every jar on the classpath for extension point class names
 * on each start (about 0.6 s for a full install). Its result depends only on the classpath and on
 * the modules' {@code data/ExtensionPoint.manifest} files, so this configuration stores it in the
 * file named by the {@code ghidra.session.classCache} system property, with the size and time of
 * every input. On the next start, when every input is unchanged, it seeds {@link ClassSearcher}
 * with the stored result and the search returns at once; otherwise the normal search runs and the
 * file is rewritten. Classes are still loaded lazily by {@link ClassSearcher} itself, exactly as
 * after a normal search.
 * <p>
 * Seeding uses two private static fields of {@link ClassSearcher} by reflection, so no Ghidra
 * class is changed. If they are missing (another Ghidra version), the cache turns itself off.
 */
final class SessionApplicationConfiguration extends HeadlessGhidraApplicationConfiguration {

	static final String CACHE_PROPERTY = "ghidra.session.classCache";
	/** 2: each class also stores its module ({@link ClassFileInfo#module()}). */
	private static final int CACHE_FORMAT = 2;

	/** "hit", "miss", "off" or "error: ...", for status. */
	static volatile String classCacheState = "off";

	/**
	 * The module initializer that sets up the default TLS context. It loads every trusted CA
	 * certificate from the OS and from Java (on master, about 180 on Windows), which no session
	 * start-up needs: on a cache hit it is left out of the initializers that run before the session
	 * is ready, and run by {@link DeferredInit} instead.
	 */
	static final String SSL_INITIALIZER = "ghidra.net.DefaultSSLContextInitializer";
	private static boolean sslDeferred;

	/**
	 * The module initializer that deletes the buffer cache files a dead Ghidra process left in
	 * the user temp folder. After a process was killed while it held a large program, deleting
	 * its cache file can take a minute on ReFS (the file system writes the file's dirty pages
	 * back first), and the session would not be ready until then. On a cache hit it is left out
	 * of the initializers and its cleanup runs on a background thread of its own while the
	 * session starts (a file another live process uses is not deleted, as before).
	 */
	static final String DB_INITIALIZER = "db.DBInitializer";
	private static boolean dbDeferred;

	@Override
	protected void initializeApplication() {
		String file = System.getProperty(CACHE_PROPERTY);
		boolean seeded = false;
		JsonArray inputs = null;
		if (file != null && !file.isBlank()) {
			try {
				inputs = inputs();
				seeded = seed(Path.of(file), inputs);
				classCacheState = seeded ? "hit" : "miss";
			}
			catch (Exception e) {
				classCacheState = "error: " + e;
			}
		}
		super.initializeApplication();
		if (!"false".equals(System.getProperty("ghidra.session.prewarm"))) {
			// Every program open needs it; reading every language definition takes ~100 ms
			DeferredInit.add("language service", DefaultLanguageService::getLanguageService);
		}
		if (seeded && sslDeferred) {
			DeferredInit.add("SSL context", DefaultSSLContextInitializer::initialize);
		}
		if (seeded && dbDeferred) {
			// not a DeferredInit task: scripts and imports wait for those, and this can be slow
			Thread t = new Thread(() -> {
				long t0 = System.nanoTime();
				try {
					removeOldCacheFiles();
				}
				catch (RuntimeException e) {
					Msg.warn(SessionApplicationConfiguration.class,
						"old buffer cache files not removed: " + e);
				}
				long ms = (System.nanoTime() - t0) / 1_000_000;
				if (ms > 1000) {
					Msg.info(SessionApplicationConfiguration.class,
						"removed old buffer cache files in " + ms + " ms (in the background)");
				}
			}, "session-old-cache-cleanup");
			t.setDaemon(true);
			t.start();
		}
		if (file != null && !file.isBlank() && !seeded && inputs != null) {
			try {
				store(Path.of(file), inputs);
			}
			catch (Exception e) {
				classCacheState = "error: " + e;
				Msg.warn(this, "class search cache not written: " + e);
			}
		}
	}

	/**
	 * What {@code BufferMgr.cleanupOldCacheFiles} does (delete the {@code ghidra*.cache} files
	 * in the user temp folder that no live process uses), without the wait on ReFS: on Windows a
	 * file is first renamed, which fails while any process has it open (Java opens it without
	 * delete sharing), so only a dead process's file is touched; it is then truncated to 0
	 * bytes, which drops its unwritten pages (as {@code LocalBufferFile} does for its own
	 * temporary files), and deleted. Elsewhere it is deleted, as before.
	 */
	static void removeOldCacheFiles() {
		File dir = Application.getUserTempDirectory();
		File[] files = dir.listFiles(f -> f.isFile() && f.getName().startsWith("ghidra") &&
			f.getName().endsWith(".cache"));
		if (files == null) {
			return;
		}
		boolean windows = System.getProperty("os.name", "").startsWith("Windows");
		for (File f : files) {
			if (!windows) {
				f.delete();
				continue;
			}
			File stale = new File(f.getPath() + ".stale");
			if (!f.renameTo(stale)) {
				continue; // in use by a live process
			}
			try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(stale, "rw")) {
				raf.setLength(0);
			}
			catch (java.io.IOException e) {
				// delete it anyway
			}
			stale.delete();
		}
	}

	/** Every file the search result depends on, with its size and modification time. */
	private static JsonArray inputs() {
		List<String> paths = new ArrayList<>();
		paths.addAll(GhidraClassLoader.getClasspath(GhidraClassLoader.CP));
		paths.addAll(GhidraClassLoader.getClasspath(GhidraClassLoader.CP_EXT));
		for (ResourceFile root : Application.getModuleRootDirectories()) {
			paths.add(new File(root.getAbsolutePath(), "data/ExtensionPoint.manifest").getPath());
		}
		JsonArray a = new JsonArray();
		for (String p : paths) {
			File f = new File(p);
			JsonArray e = new JsonArray();
			e.add(f.getAbsolutePath());
			e.add(f.exists() ? f.length() : -1);
			e.add(f.exists() ? f.lastModified() : -1);
			a.add(e);
		}
		return a;
	}

	private static Field field(String name) throws ReflectiveOperationException {
		Field f = ClassSearcher.class.getDeclaredField(name);
		f.setAccessible(true);
		return f;
	}

	private static boolean seed(Path file, JsonArray inputs) throws Exception {
		if (!Files.isRegularFile(file)) {
			return false;
		}
		JsonObject o = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8))
				.getAsJsonObject();
		if (o.get("format").getAsInt() != CACHE_FORMAT ||
			!Application.getApplicationVersion().equals(o.get("ghidra").getAsString()) ||
			!inputs.equals(o.get("inputs"))) {
			return false;
		}
		Map<String, Set<ClassFileInfo>> map = new HashMap<>();
		for (JsonElement el : o.getAsJsonArray("classes")) {
			JsonArray c = el.getAsJsonArray();
			ClassFileInfo info =
				new ClassFileInfo(c.get(0).getAsString(), c.get(1).getAsString(),
					c.get(2).getAsString(), c.get(3).isJsonNull() ? null : c.get(3).getAsString());
			map.computeIfAbsent(info.suffix(), k -> new HashSet<>()).add(info);
		}
		if (map.isEmpty()) {
			return false;
		}
		for (Set<ClassFileInfo> set : map.values()) {
			sslDeferred |= set.removeIf(i -> i.name().equals(SSL_INITIALIZER));
			dbDeferred |= set.removeIf(i -> i.name().equals(DB_INITIALIZER));
		}
		field("extensionPointSuffixToInfoMap").set(null, map);
		field("hasSearched").set(null, true);
		return true;
	}

	@SuppressWarnings("unchecked")
	private static void store(Path file, JsonArray inputs) throws Exception {
		Map<String, Set<ClassFileInfo>> map =
			(Map<String, Set<ClassFileInfo>>) field("extensionPointSuffixToInfoMap").get(null);
		if (map == null || map.isEmpty()) {
			return;
		}
		JsonArray classes = new JsonArray();
		map.values().forEach(set -> set.forEach(i -> {
			JsonArray c = new JsonArray();
			c.add(i.path());
			c.add(i.name());
			c.add(i.suffix());
			c.add(i.module());
			classes.add(c);
		}));
		JsonObject o = new JsonObject();
		o.addProperty("format", CACHE_FORMAT);
		o.addProperty("ghidra", Application.getApplicationVersion());
		o.add("inputs", inputs);
		o.add("classes", classes);
		Path dir = file.toAbsolutePath().getParent();
		Files.createDirectories(dir);
		Path tmp = Files.createTempFile(dir, ".classcache", ".tmp");
		Files.writeString(tmp, Json.GSON.toJson(o), StandardCharsets.UTF_8);
		try {
			Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (IOException e) {
			Files.deleteIfExists(tmp);
			throw e;
		}
	}
}
