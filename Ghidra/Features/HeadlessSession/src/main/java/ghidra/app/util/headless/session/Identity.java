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
import java.io.InputStream;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import com.google.gson.JsonObject;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * What a protocol 3 client can check before it trusts an answer (PROTOCOL-3.md 3.2): where the
 * daemon keeps its state ({@code paths}), what it runs on ({@code platform}), and which build
 * produced the analysis ({@code analysisIdentity}: the release, the database format versions, the
 * decompiler binary). It only reads; nothing here changes the engine's behaviour.
 * <p>
 * The decompiler's SHA-256 is computed once in the background, cached by path, size and modification
 * time, and is {@code null} in {@code hello} until it is ready: {@code hello} never waits for it.
 */
final class Identity {

	private static volatile JsonObject paths = pathsOf(null, null, null, null, List.of(), null);
	private static volatile JsonObject platform;
	private static volatile Hashed hashed;
	private static final Object HASH_LOCK = new Object();

	private Identity() {
	}

	/** The facts the decompiler hash is cached by, and the hash once it is known. */
	private static final class Hashed {
		final String path;
		final long size;
		final long modified;
		volatile String sha256;

		Hashed(File f) {
			this.path = f.getPath();
			this.size = f.length();
			this.modified = f.lastModified();
		}

		boolean matches(File f) {
			return path.equals(f.getPath()) && size == f.length() && modified == f.lastModified();
		}
	}

	// ---- paths ---------------------------------------------------------------------------------

	/**
	 * Records where this daemon keeps things, once, at start-up (any argument may be null: a
	 * stdio session has no state directory or endpoint file).
	 */
	static void setPaths(String stateDir, String instance, String endpointFile, String logFile,
			List<String> scriptPath, String upgradeCacheDir) {
		paths = pathsOf(stateDir, instance, endpointFile, logFile, scriptPath, upgradeCacheDir);
		platform = null; // the file systems it reports depend on these
	}

	private static JsonObject pathsOf(String stateDir, String instance, String endpointFile,
			String logFile, List<String> scriptPath, String upgradeCacheDir) {
		String install;
		try {
			install = Application.getInstallationDirectory().getAbsolutePath();
		}
		catch (RuntimeException e) {
			install = null; // before the application is initialized (the self-test)
		}
		return Json.of("stateDir", stateDir, "instance", instance, "endpointFile", endpointFile,
			"logFile", logFile, "scriptPath", scriptPath, "tmpDir",
			System.getProperty("java.io.tmpdir"), "upgradeCacheDir", upgradeCacheDir, "install",
			install);
	}

	static JsonObject paths() {
		return paths.deepCopy();
	}

	// ---- platform ------------------------------------------------------------------------------

	/**
	 * The machine and file-system facts a client needs to judge a claim such as "a fork is a block
	 * clone": the file system of the state, temporary and upgrade-cache directories, and whether a
	 * copy there is a clone ({@link ProjectFork#clones}: Windows and ReFS only; no other
	 * copy-on-write file system is claimed). A directory that is not set or cannot be read is
	 * {@code null}, never guessed.
	 */
	static JsonObject platform() {
		JsonObject p = platform;
		if (p == null) {
			JsonObject pa = paths;
			String state = str(pa, "stateDir");
			String tmp = str(pa, "tmpDir");
			String cache = str(pa, "upgradeCacheDir");
			FileStore stateFs = store(state);
			FileStore tmpFs = store(tmp);
			FileStore cacheFs = store(cache);
			Runtime rt = Runtime.getRuntime();
			p = Json.of("os", System.getProperty("os.name"), "osVersion",
				System.getProperty("os.version"), "arch", System.getProperty("os.arch"), "cpus",
				rt.availableProcessors(), "javaVendor", System.getProperty("java.vendor"),
				"javaVersion", System.getProperty("java.version"), "maxHeapMb", rt.maxMemory() >> 20,
				"fileSystems", Json.of("stateDir", type(stateFs), "tmpDir", type(tmpFs),
					"upgradeCacheDir", type(cacheFs)),
				"cow", Json.of("stateDir", clones(stateFs), "tmpDir", clones(tmpFs)));
			platform = p;
		}
		return p.deepCopy();
	}

	private static String str(JsonObject o, String k) {
		return Json.has(o, k) ? o.get(k).getAsString() : null;
	}

	private static FileStore store(String dir) {
		if (dir == null) {
			return null;
		}
		try {
			return Files.getFileStore(ProjectFork.existingAncestor(new File(dir)).toPath());
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
	}

	private static String type(FileStore fs) {
		return fs == null ? null : fs.type();
	}

	private static Boolean clones(FileStore fs) {
		return fs == null ? null : ProjectFork.clones(fs);
	}

	// ---- analysis identity -----------------------------------------------------------------------

	/**
	 * Which build produced the analysis: the release, the database format versions
	 * ({@code program} from {@link DbVersions#program()}, reported as {@code null} when it could not
	 * be read; {@code dataTypes} from {@link DbVersions#dataTypes()}) and the decompiler binary.
	 */
	static JsonObject analysisIdentity() {
		int program = DbVersions.program();
		return Json.of("hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
			Application.getApplicationVersion(), "buildDate", Application.getBuildDate(),
			"dbVersions", Json.of("program", program < 0 ? null : program, "dataTypes",
				DbVersions.dataTypes()),
			"decompiler", decompiler());
	}

	private static File decompilerFile() {
		try {
			boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT)
					.startsWith("windows");
			return Application.getOSFile(windows ? "decompile.exe" : "decompile");
		}
		catch (java.io.FileNotFoundException | RuntimeException e) {
			return null;
		}
	}

	/**
	 * The decompiler binary: {@code path}, {@code sizeBytes} and {@code sha256}, which is
	 * {@code null} until the background hash finishes (it is started by the first call, or by
	 * {@link #warm}).
	 */
	static JsonObject decompiler() {
		File f = decompilerFile();
		if (f == null || !f.isFile()) {
			return Json.of("path", f == null ? null : f.getPath(), "sizeBytes", null, "sha256",
				null);
		}
		Hashed h;
		synchronized (HASH_LOCK) {
			h = hashed;
			if (h == null || !h.matches(f)) {
				h = new Hashed(f);
				hashed = h;
				startHash(h, f);
			}
		}
		return Json.of("path", h.path, "sizeBytes", h.size, "sha256", h.sha256);
	}

	/** Starts the decompiler hash now, so that it is usually ready by the first {@code hello}. */
	static void warm() {
		decompiler();
	}

	private static void startHash(Hashed h, File f) {
		Thread t = new Thread(() -> {
			try (InputStream in = Files.newInputStream(f.toPath())) {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] buf = new byte[1 << 16];
				int n;
				while ((n = in.read(buf)) > 0) {
					md.update(buf, 0, n);
				}
				h.sha256 = HexFormat.of().formatHex(md.digest());
			}
			catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
				Msg.warn(Identity.class, "could not hash " + f + ": " + e);
			}
		}, "session-decompiler-hash");
		t.setDaemon(true);
		t.setPriority(Thread.MIN_PRIORITY);
		t.start();
	}
}
