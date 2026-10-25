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
 * Serves read-only opens of programs saved in an older database format from an upgraded copy.
 * <p>
 * Opened read-only, such a program is upgraded in memory on every open, which for a large program
 * takes many times longer than the open itself. The first read-only open copies the project into
 * {@code <root>/<key>/project} (a block clone where the file system supports it, as ReFS does),
 * opens the program there writable, upgrades and saves it once, and opens it read-only from the
 * copy; later opens find the copy and skip both. The source project is only read.
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
 * Several daemons may share a root: an entry is built under an OS file lock.
 */
final class UpgradeCache {

	/** Files up to this size are keyed by content as well as size and time. */
	static final long HASH_LIMIT = 1 << 20;
	private static final String ENTRY_FILE = "entry.json";
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	/** The current program database version, or -1 when it cannot be read (cache off). */
	private static final int CURRENT_DB_VERSION = currentDbVersion();

	private final File root;
	/**
	 * Keys with a view open in this process, each holding a shared OS lock on
	 * {@code <key>.use} so that no daemon prunes an entry another one serves from.
	 */
	private final Map<String, Use> inUse = new HashMap<>();

	private static final class Use {
		int count;
		FileChannel channel;
		FileLock lock;
	}

	/** @param root the cache directory, or null for no cache */
	UpgradeCache(File root) {
		this.root = root;
		if (root != null && CURRENT_DB_VERSION < 0) {
			Msg.warn(this, "upgrade cache off: the program database version is not readable");
		}
	}

	boolean enabled() {
		return root != null && CURRENT_DB_VERSION >= 0;
	}

	JsonObject describe() {
		return Json.of("enabled", enabled(), "dir", root == null ? null : root.getPath());
	}

	/** A program opened from the cache, with the read-only view of the copy that holds it. */
	record Opened(Program program, SessionProject view, String key, JsonObject info) {}

	/**
	 * Opens {@code df} read-only from an upgraded copy when it is in an older format, building
	 * the copy if needed. Returns null when the program is current, or the cache cannot serve it
	 * (the caller then opens the source as usual).
	 */
	Opened open(ProjectEntry p, DomainFile df, Object consumer, RequestMonitor m)
			throws IOException, CancelledException, VersionException {
		if (!enabled() || df.isVersioned() || df.isLink()) {
			return null;
		}
		String path = df.getPathname();
		String why = olderFormat(p.project.getProjectData(), df);
		if (why == null) {
			return null;
		}
		String key = key(p.resolved);
		File dir = new File(root, key);
		Project previous = AppInfo.getActiveProject();
		acquireUse(key);
		boolean ok = false;
		try {
			long t0 = System.nanoTime();
			boolean built = ensure(p, key, dir, path, why, m);
			long buildMs = (System.nanoTime() - t0) / 1_000_000;
			ProjectLocator copy = new ProjectLocator(new File(dir, "project").getPath(),
				p.resolved.name());
			SessionProject view;
			try {
				view = SessionProject.open(copy, false);
			}
			catch (Exception e) {
				throw new IOException("cannot open the upgrade cache copy " + copy + ": " + e, e);
			}
			Program program;
			try {
				DomainFile cdf = view.getProjectData().getFile(path);
				if (cdf == null) {
					throw new IOException(path + " is missing from the upgrade cache copy " + dir);
				}
				String still = olderFormat(view.getProjectData(), cdf);
				if (still != null) {
					throw new IOException("the upgrade cache copy of " + path + " is still in an " +
						"older format (" + still + "): " + dir);
				}
				program = (Program) cdf.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION,
					m);
			}
			catch (IOException | CancelledException | VersionException | RuntimeException e) {
				view.close();
				throw e;
			}
			ok = true;
			JsonObject info = Json.of("used", true, "built", built, "reason", why, "key", key,
				"dir", dir.getPath());
			if (built) {
				Json.put(info, "buildMs", buildMs);
			}
			return new Opened(program, view, key, info);
		}
		finally {
			AppInfo.setActiveProject(previous);
			if (!ok) {
				release(key);
			}
		}
	}

	/** The key of a view opened by {@link #open} is no longer in use. */
	void release(String key) {
		synchronized (inUse) {
			Use u = inUse.get(key);
			if (u == null || --u.count > 0) {
				return;
			}
			inUse.remove(key);
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

	private void acquireUse(String key) throws IOException {
		synchronized (inUse) {
			Use u = inUse.get(key);
			if (u == null) {
				Files.createDirectories(root.toPath());
				u = new Use();
				u.channel = FileChannel.open(new File(root, key + ".use").toPath(),
					StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
				try {
					u.lock = u.channel.lock(0, Long.MAX_VALUE, true);
				}
				catch (IOException | RuntimeException e) {
					u.channel.close();
					throw e instanceof IOException io ? io : new IOException(e);
				}
				inUse.put(key, u);
			}
			u.count++;
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
		update(md, "v1|" + r.gpr().getCanonicalPath() + "|" + Application.getApplicationVersion() +
			"|" + Application.getBuildDate() + "|" + CURRENT_DB_VERSION);
		for (Map.Entry<String, Path> f : sourceFiles(r).entrySet()) {
			BasicFileAttributes a = Files.readAttributes(f.getValue(), BasicFileAttributes.class);
			update(md, "|" + f.getKey() + "|" + a.size() + "|" + a.lastModifiedTime().toMillis());
			if (a.size() <= HASH_LIMIT) {
				md.update(Files.readAllBytes(f.getValue()));
			}
		}
		return HexFormat.of().formatHex(md.digest()).substring(0, 16);
	}

	/** The {@code .gpr} and every file below the {@code .rep}, by relative path, sorted. */
	private static SortedMap<String, Path> sourceFiles(ProjectResolver.Resolved r)
			throws IOException {
		SortedMap<String, Path> files = new TreeMap<>();
		Path gpr = r.gpr().toPath();
		files.put(gpr.getFileName().toString(), gpr);
		Path rep = gpr.resolveSibling(r.name() + ProjectLocator.getProjectDirExtension());
		Path base = gpr.getParent();
		if (Files.isDirectory(rep)) {
			Files.walkFileTree(rep, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
					if (attrs.isRegularFile()) {
						files.put(base.relativize(file).toString().replace('\\', '/'), file);
					}
					return FileVisitResult.CONTINUE;
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

	// ---- building an entry ---------------------------------------------------------------------

	/** Makes {@code dir} hold an upgraded copy of {@code path}. Returns true when it built it. */
	private boolean ensure(ProjectEntry p, String key, File dir, String path, String why,
			RequestMonitor m) throws IOException, CancelledException, VersionException {
		Files.createDirectories(root.toPath());
		try (FileChannel ch = FileChannel.open(new File(root, key + ".lock").toPath(),
			StandardOpenOption.CREATE, StandardOpenOption.WRITE);
				FileLock lock = lockWait(ch, m)) {
			JsonObject entry = readEntry(dir);
			if (entry != null && upgraded(entry).contains(path)) {
				return false;
			}
			Msg.info(this, "upgrade cache: " + p.canonical + " " + path + " (" + why +
				"): building " + dir);
			File copyDir = new File(dir, "project");
			if (entry == null) {
				if (dir.exists()) {
					FileUtilities.deleteDir(dir); // an interrupted build
				}
				long t0 = System.nanoTime();
				copyProject(p.resolved, dir);
				long copyMs = (System.nanoTime() - t0) / 1_000_000;
				entry = Json.of("source", p.canonical, "ghidra", Application.getApplicationVersion(),
					"dbVersion", CURRENT_DB_VERSION, "created", System.currentTimeMillis(),
					"copyMs", copyMs, "upgraded", new JsonArray());
				writeEntry(dir, entry);
				Msg.info(this, "upgrade cache: copied the project in " + copyMs + " ms");
				prune(p.canonical, key);
			}
			long[] ms = upgradeInCopy(new ProjectLocator(copyDir.getPath(), p.resolved.name()),
				path, m);
			upgraded(entry); // ensure the array
			entry.getAsJsonArray("upgraded").add(path);
			Json.put(entry, "upgradeMs:" + path, ms[0]);
			Json.put(entry, "saveMs:" + path, ms[1]);
			writeEntry(dir, entry);
			Msg.info(this, "upgrade cache: " + path + " upgraded in " + ms[0] + " ms and saved in " +
				ms[1] + " ms in " + copyDir);
			return true;
		}
	}

	private static FileLock lockWait(FileChannel ch, RequestMonitor m)
			throws IOException, CancelledException {
		while (true) {
			FileLock l = ch.tryLock();
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
	 * Copies the {@code .gpr} and the {@code .rep} (not the lock files) into
	 * {@code <dir>/project}, through a temporary directory renamed at the end. {@link Files#copy}
	 * uses the platform's copy, which block-clones on ReFS.
	 */
	private static void copyProject(ProjectResolver.Resolved r, File dir) throws IOException {
		Path tmp = new File(dir, "project.copying").toPath();
		Path dest = new File(dir, "project").toPath();
		Files.createDirectories(tmp);
		Path base = r.gpr().toPath().getParent();
		for (Path src : sourceFiles(r).values()) {
			Path to = tmp.resolve(base.relativize(src).toString());
			Files.createDirectories(to.getParent());
			Files.copy(src, to, StandardCopyOption.COPY_ATTRIBUTES);
		}
		// empty folders of the .rep matter to the file system's layout
		Path rep = base.resolve(r.name() + ProjectLocator.getProjectDirExtension());
		if (Files.isDirectory(rep)) {
			Files.walkFileTree(rep, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs)
						throws IOException {
					Files.createDirectories(tmp.resolve(base.relativize(d).toString()));
					return FileVisitResult.CONTINUE;
				}
			});
		}
		Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE);
	}

	/** Opens the copy writable, upgrades {@code path} and saves it. */
	/** Returns {open with upgrade ms, save ms}. */
	private long[] upgradeInCopy(ProjectLocator copy, String path, RequestMonitor m)
			throws IOException, CancelledException, VersionException {
		long[] ms = new long[2];
		SessionProject sp;
		try {
			sp = SessionProject.open(copy, true);
		}
		catch (Exception e) {
			throw new IOException("cannot open the upgrade cache copy " + copy + ": " + e, e);
		}
		try {
			DomainFile df = sp.getProjectData().getFile(path);
			if (df == null) {
				throw new IOException(path + " is missing from the copy " + copy);
			}
			long t0 = System.nanoTime();
			Program program = (Program) df.getDomainObject(this, true, false, m);
			ms[0] = (System.nanoTime() - t0) / 1_000_000;
			try {
				t0 = System.nanoTime();
				if (program.isChanged()) {
					program.save("upgraded to this Ghidra's database format (upgrade cache)", m);
				}
				ms[1] = (System.nanoTime() - t0) / 1_000_000;
			}
			finally {
				program.release(this);
			}
		}
		finally {
			sp.close();
		}
		return ms;
	}

	private static Set<String> upgraded(JsonObject entry) {
		if (!entry.has("upgraded") || !entry.get("upgraded").isJsonArray()) {
			entry.add("upgraded", new JsonArray());
		}
		Set<String> out = new HashSet<>();
		entry.getAsJsonArray("upgraded").forEach(e -> out.add(e.getAsString()));
		return out;
	}

	private static JsonObject readEntry(File dir) {
		File f = new File(dir, ENTRY_FILE);
		if (!f.isFile() || !new File(dir, "project").isDirectory()) {
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
			synchronized (inUse) {
				if (k.equals(keep) || inUse.containsKey(k)) {
					continue;
				}
			}
			JsonObject e = readEntry(d);
			if (e == null || !e.has("source") || !canonical.equals(e.get("source").getAsString())) {
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
