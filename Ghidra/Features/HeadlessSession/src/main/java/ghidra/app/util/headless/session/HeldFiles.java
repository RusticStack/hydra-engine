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
import java.lang.reflect.Method;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;

import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.*;
import ghidra.framework.store.UnknownFolderItem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.Msg;

/**
 * A file of a project that another process holds open for a moment (PROTOCOL-3.md 3.3 and 8.15,
 * amendment A63, {@code w2/GATE10}).
 * <p>
 * On Windows a virus scanner, an indexer, a backup or sync tool, or a soak's handle holder can
 * open a file or folder of a project with no sharing. While it does, the folder cannot be listed
 * and the file cannot be opened, renamed or deleted (a sharing violation). Ghidra reports that in
 * many shapes: a database whose folder cannot be listed becomes an item of content type
 * {@code Unknown-File}, an unreadable property file drops the item from the project, and the I/O
 * exceptions carry the localised text of the system message. None of these is a client mistake,
 * and none is permanent; the engine answers {@code busy} with {@code details.reason:"file_held"}
 * (v3; a protocol 2 connection gets {@code busy} with the same other details), {@code path} (what is
 * held) and {@code error.retryAfterMs} (v3), never {@code bad_request}, {@code not_found} or a bare
 * {@code failed}.
 * <p>
 * Whether something is held is decided by looking, never from the message text (it is localised):
 * a folder that exists and cannot be listed, or a file that exists and cannot be opened for reading,
 * is held ({@link #held}). An access-control denial looks the same and is reported the same way;
 * it is not told apart.
 * <p>
 * The project's own picture of the file is repaired once the hold is gone: an item that was read
 * as {@code Unknown-File} or dropped while it was held is read again by a refresh of its folder
 * ({@link #refreshFolder}), so that the retry the {@code busy} asks for succeeds.
 */
final class HeldFiles {

	/** {@code details.reason} of the {@code busy} (v3). */
	static final String REASON = "file_held";
	/** {@code error.retryAfterMs}: no hold history is kept, so the default of 3.3. */
	static final long RETRY_AFTER_MS = 1000;

	/**
	 * The commands whose failure {@link #translate} may turn into {@code busy}: the ones that read
	 * or write a project's files and whose retry is safe. Not {@code script} or {@code analyze}
	 * (a partly applied script must not be told to run again) nor the edit commands (they change
	 * only the program in memory).
	 */
	static final Set<String> COMMANDS = Set.of("open_project", "project", "list", "open_program",
		"switch", "save", "fork_project", "import", "refresh", "reopen", "prepare_upgrade");

	/** The codes of a failure that a hold can have caused (3.3: never a client mistake). */
	private static final Set<String> CODES = Set.of(SessionException.FAILED,
		SessionException.NOT_FOUND, SessionException.BAD_REQUEST);

	/** A Windows absolute path in a message: a drive, then no character a path cannot hold. */
	private static final Pattern WIN_PATH = Pattern.compile("[A-Za-z]:[\\\\/][^:*?\"<>|\\r\\n]*");

	/** At most this many entries are probed by one {@link #scan} (only on a failure path). */
	private static final int SCAN_CAP = 20_000;

	private HeldFiles() {
	}

	/** A {@code busy} that says a file is held; {@link #isHeld} recognises it. */
	static final class Held extends SessionException {
		final File path;

		Held(String message, JsonObject details, Throwable cause, File path) {
			super(BUSY, message, details, cause);
			this.path = path;
		}
	}

	/** Whether {@code e} is the {@code busy} of a held file. */
	static boolean isHeld(SessionException e) {
		return e instanceof Held;
	}

	// ---- the probe --------------------------------------------------------------------------

	/**
	 * Whether another process holds {@code f} now: it exists and, as a folder, cannot be listed,
	 * or, as a file, cannot be opened for reading. Never throws.
	 */
	static boolean held(File f) {
		try {
			if (f == null || !f.exists()) {
				return false;
			}
			if (f.isDirectory()) {
				return f.list() == null;
			}
			try (InputStream in = new FileInputStream(f)) {
				return false;
			}
			catch (IOException e) {
				return f.exists();
			}
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	/**
	 * {@code f} or the first of its parent folders that is held, up to and including the
	 * project's {@code .rep} folder (or, outside a project, the direct parent only); null if none.
	 */
	static File heldNear(File f) {
		if (f == null) {
			return null;
		}
		boolean inRep = false;
		for (File x = f; x != null; x = x.getParentFile()) {
			if (x.getName().endsWith(".rep")) {
				inRep = true;
				break;
			}
		}
		int left = inRep ? Integer.MAX_VALUE : 1;
		for (File x = f; x != null; x = x.getParentFile()) {
			if (held(x)) {
				return x;
			}
			if (x.getName().endsWith(".rep") || left-- <= 0) {
				break;
			}
		}
		return null;
	}

	/** The first held entry of {@code files} (each with {@link #heldNear}), or null. */
	static File firstHeld(Collection<File> files) {
		for (File f : files) {
			File h = heldNear(f);
			if (h != null) {
				return h;
			}
		}
		return null;
	}

	/**
	 * The first held entry under {@code root} (a folder that cannot be listed, or a property or
	 * index file that cannot be read), at most {@link #SCAN_CAP} entries; null if none. Database
	 * version files are not opened: Ghidra may hold them itself.
	 */
	static File scan(File root) {
		if (root == null || !root.isDirectory()) {
			return held(root) ? root : null;
		}
		Deque<File> todo = new ArrayDeque<>();
		todo.add(root);
		int n = 0;
		while (!todo.isEmpty() && n < SCAN_CAP) {
			File d = todo.poll();
			n++;
			File[] kids = d.listFiles();
			if (kids == null) {
				if (d.isDirectory()) {
					return d;
				}
				continue;
			}
			for (File k : kids) {
				if (++n >= SCAN_CAP) {
					break;
				}
				String name = k.getName();
				if (k.isDirectory()) {
					todo.add(k);
				}
				else if ((name.endsWith(".prp") || name.startsWith("~index")) && held(k)) {
					return k;
				}
			}
		}
		return null;
	}

	/** The {@code idata} folder of the project that holds {@code pd}, or null. */
	static File idataOf(ProjectData pd) {
		try {
			ProjectLocator loc = pd.getProjectLocator();
			return new File(loc.getProjectDir(), "idata");
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	// ---- the files of an item ---------------------------------------------------------------

	/**
	 * The storage of the item {@code name} in folder {@code folderPath} of a local project: its
	 * database folder ({@code ~xxxxxxxx.db}), its property file and the folder that holds both;
	 * empty when it cannot be found. Read through {@code LocalFileSystem.findItemStorage}
	 * (reflection: it is protected; the index is in memory, so a held index file does not stop it).
	 * Never throws.
	 */
	static List<File> storageOf(ProjectData pd, String folderPath, String name) {
		if (!(pd instanceof DefaultProjectData dpd) ||
			!(dpd.getPrivateFileSystem() instanceof LocalFileSystem fs)) {
			return List.of();
		}
		try {
			Method find = LocalFileSystem.class.getDeclaredMethod("findItemStorage", String.class,
				String.class);
			find.setAccessible(true);
			Object st;
			synchronized (fs) {
				st = find.invoke(fs, folderPath, name);
			}
			if (st == null) {
				return List.of();
			}
			Class<?> sc = find.getReturnType();
			Field dirF = sc.getDeclaredField("dir");
			Field nameF = sc.getDeclaredField("storageName");
			dirF.setAccessible(true);
			nameF.setAccessible(true);
			File dir = (File) dirF.get(st);
			String sn = (String) nameF.get(st);
			File data = new File(dir, LocalFileSystem.HIDDEN_DIR_PREFIX +
				LocalFileSystem.escapeHiddenDirPrefixChars(sn) + ".db");
			File prp = new File(dir, sn + ".prp");
			return List.of(data, prp, dir);
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			Msg.debug(HeldFiles.class, "the storage of " + name + " is not known: " + e);
			return List.of();
		}
	}

	/** The storage of {@code df} (see {@link #storageOf(ProjectData, String, String)}). */
	static List<File> storageOf(DomainFile df) {
		try {
			DomainFolder parent = df.getParent();
			return storageOf(parent.getProjectData(), parent.getPathname(), df.getName());
		}
		catch (RuntimeException e) {
			return List.of();
		}
	}

	// ---- the project's picture of an item ---------------------------------------------------

	/**
	 * Lists {@code folder} again (Ghidra's {@code GhidraFolder.refreshFolderData}, a forced refresh
	 * of that one folder, reached by reflection: it is package-private). Its items are read anew, so
	 * one that was read as {@code Unknown-File} or dropped while it was held comes back. Never
	 * throws; false if it could not run.
	 */
	static boolean refreshFolder(DomainFolder folder) {
		for (Class<?> k = folder.getClass(); k != null; k = k.getSuperclass()) {
			try {
				Method m = k.getDeclaredMethod("refreshFolderData");
				m.setAccessible(true);
				m.invoke(folder);
				return true;
			}
			catch (NoSuchMethodException e) {
				// a superclass may declare it
			}
			catch (ReflectiveOperationException | RuntimeException e) {
				Msg.warn(HeldFiles.class, "could not refresh " + folder.getPathname() + ": " + e);
				return false;
			}
		}
		Msg.warn(HeldFiles.class, "could not refresh " + folder.getPathname() +
			": no refreshFolderData in " + folder.getClass().getName());
		return false;
	}

	/**
	 * {@code open_program} found {@code df} but not as a program. If its storage (or anything of
	 * the project's item storage) is held now, the answer is {@code busy} ({@link Held}); if it reads
	 * as {@code Unknown-File} and nothing is held, its folder is listed again (an item read while it
	 * was held) and the file of the fresh listing is returned. Otherwise {@code df} is returned
	 * unchanged and the caller keeps its answer.
	 */
	static DomainFile recheck(String what, DomainFile df) {
		File h = firstHeld(storageOf(df));
		if (h != null) {
			throw busy(what, h, null, df.getPathname() + " cannot be read");
		}
		if (!UnknownFolderItem.UNKNOWN_CONTENT_TYPE.equals(df.getContentType())) {
			return df;
		}
		DomainFolder parent = df.getParent();
		ProjectData pd = parent.getProjectData();
		h = scan(idataOf(pd));
		if (h != null) {
			// another item is held: listing the folder now would read that one as unknown
			throw busy(what, h, null, df.getPathname() + " cannot be read");
		}
		if (!refreshFolder(parent)) {
			return df;
		}
		DomainFile again = pd.getFile(df.getPathname());
		if (again != null) {
			Msg.info(HeldFiles.class, df.getPathname() + " was read while another process held " +
				"its files; read again: " + again.getContentType());
			return again;
		}
		return df;
	}

	/**
	 * {@code name} was not found in folder {@code folderPath} of the project of {@code pd}. When the
	 * file system still lists it (its index names it), the project dropped it while it was held (a
	 * property file that could not be read): if its storage, or another item file of the project,
	 * is held now, the answer is {@code busy} ({@link Held}); otherwise the folder is listed again
	 * and the file is returned. Null when it is really absent, or the folder could not be listed
	 * again: the caller keeps its {@code not_found}. Cheap when the file is absent (the index is in
	 * memory).
	 */
	static DomainFile recheckMissing(String what, ProjectData pd, String folderPath, String name) {
		if (!(pd instanceof DefaultProjectData dpd) ||
			!(dpd.getPrivateFileSystem() instanceof LocalFileSystem fs)) {
			return null;
		}
		String[] names;
		try {
			synchronized (fs) {
				names = fs.getItemNames(folderPath);
			}
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
		if (names == null || !Arrays.asList(names).contains(name)) {
			return null;
		}
		String path = LocalFileSystem.getPath(folderPath, name);
		File h = firstHeld(storageOf(pd, folderPath, name));
		if (h == null) {
			h = scan(idataOf(pd));
		}
		if (h != null) {
			throw busy(what, h, null, path + " cannot be read");
		}
		DomainFolder folder = pd.getFolder(folderPath);
		if (folder == null || !refreshFolder(folder)) {
			return null;
		}
		DomainFile again = pd.getFile(path);
		if (again != null) {
			Msg.info(HeldFiles.class, path + " was dropped from the project while another " +
				"process held its files; listed again");
		}
		return again;
	}

	// ---- the answer -------------------------------------------------------------------------

	/** Whether the current request's connection speaks protocol 3 ({@link Caller#client}). */
	private static boolean v3() {
		Client c = Caller.client();
		return c != null && c.v3();
	}

	/**
	 * The {@code busy} of a held file: {@code details.path} and {@code suggest:"retry"}, plus
	 * {@code reason:"file_held"} for v3 ({@link SessionException#busyDetails}), and
	 * {@code retryAfterMs}. {@code original} (the failure as it was) ends the message.
	 */
	static Held busy(String what, File heldPath, Throwable cause, String original) {
		JsonObject d = Json.of("path", heldPath.getPath(), "suggest", "retry");
		d = SessionException.busyDetails(v3(), d, REASON, null, null);
		String msg = what + ": " + heldPath + " is held open by another process (a virus " +
			"scanner, an indexer, a backup or sync tool) that shares it with nobody; retry when " +
			"it lets go" + (original == null ? "" : " (" + original + ")");
		Held e = new Held(msg, d, cause, heldPath);
		e.withRetryAfterMs(RETRY_AFTER_MS);
		return e;
	}

	/**
	 * The failure of {@code cmd} as the {@code busy} of a held file, or null when it is not one: a
	 * {@code failed}, {@code not_found} or {@code bad_request} with a cause, or any other exception,
	 * whose cause chain names a file or folder that is held now ({@link #fromCause}).
	 */
	static SessionException translate(String cmd, Throwable t) {
		if (!COMMANDS.contains(cmd) || t instanceof Held) {
			return null;
		}
		Throwable cause;
		String original;
		if (t instanceof SessionException se) {
			if (!CODES.contains(se.code()) || se.getCause() == null) {
				return null;
			}
			cause = se.getCause();
			original = se.code() + ": " + se.getMessage();
		}
		else {
			cause = t;
			original = t.getClass().getSimpleName() + ": " + t.getMessage();
		}
		try {
			File h = fromCause(cause);
			return h == null ? null : busy(cmd, h, t, original);
		}
		catch (RuntimeException e) {
			// the answer must still go out: keep the original failure
			Msg.warn(HeldFiles.class, "could not check " + cmd + "'s failure for a held file: " + e);
			return null;
		}
	}

	/**
	 * The held file behind a failure on {@code df}: one {@code t} names ({@link #fromCause}), or
	 * else one of {@code df}'s own storage ({@link #storageOf(DomainFile)}); null if none. Never
	 * throws (the caller rethrows the original failure).
	 */
	static File heldFor(Throwable t, DomainFile df) {
		try {
			File h = fromCause(t);
			if (h == null && df != null) {
				h = firstHeld(storageOf(df));
			}
			return h;
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * The held file or folder that {@code t} or one of its causes names (a
	 * {@link FileSystemException}'s files, or an absolute path in a message), checked now with
	 * {@link #heldNear}; null if none. A missing file is not a hold.
	 */
	static File fromCause(Throwable t) {
		if (t == null) {
			return null;
		}
		Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		Deque<Throwable> todo = new ArrayDeque<>();
		todo.add(t);
		while (!todo.isEmpty() && seen.size() < 16) {
			Throwable x = todo.poll();
			if (x == null || !seen.add(x)) {
				continue;
			}
			for (File cand : candidates(x)) {
				File h = heldNear(cand);
				if (h != null) {
					return h;
				}
			}
			if (x.getCause() != null) {
				todo.add(x.getCause());
			}
			for (Throwable s : x.getSuppressed()) {
				if (s != null) {
					todo.add(s);
				}
			}
		}
		return null;
	}

	private static List<File> candidates(Throwable x) {
		if (x instanceof NoSuchFileException || x instanceof FileAlreadyExistsException ||
			x instanceof DirectoryNotEmptyException || x instanceof NotDirectoryException ||
			x instanceof NotLinkException || x instanceof FileSystemLoopException) {
			return List.of();
		}
		List<File> out = new ArrayList<>();
		if (x instanceof FileSystemException fse) {
			if (fse.getFile() != null) {
				out.add(new File(fse.getFile()));
			}
			if (fse.getOtherFile() != null) {
				out.add(new File(fse.getOtherFile()));
			}
		}
		String msg = x.getMessage();
		if (msg != null) {
			Matcher m = WIN_PATH.matcher(msg);
			while (m.find()) {
				for (String piece : m.group().split(" -> ")) {
					File f = existingPrefix(piece.trim());
					if (f != null) {
						out.add(f);
					}
				}
			}
		}
		return out;
	}

	/**
	 * The longest prefix of {@code s}, cut at spaces, that names an existing file or folder:
	 * {@code "C:\\a\\b.db not found"} gives {@code C:\a\b.db}; null if none.
	 */
	private static File existingPrefix(String s) {
		String p = s;
		while (p.length() > 3) {
			File f = new File(p);
			if (f.exists()) {
				return f;
			}
			int sp = p.lastIndexOf(' ');
			if (sp < 3) {
				return null;
			}
			p = p.substring(0, sp).trim();
		}
		return null;
	}
}
