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
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.*;

import generic.hash.HashUtilities;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.*;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.Application;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.*;

/**
 * The state of a headless session and its commands. Thread-safe: each client's requests run on
 * that client's own thread, so clients run concurrently.
 * <p>
 * Lock order, always: {@link #projectLock}, then one {@link ProgramEntry#lock}. The registry maps
 * are concurrent and never held across a wait.
 */
final class Session {

	static final int PROTOCOL_VERSION = 1;

	static final long DEFAULT_WAIT_MS = 10_000;
	private static final long CLEANUP_WAIT_MS = 600_000;
	private static final int DEFAULT_TEXT_CAP = 200_000;
	private static final int MAX_TEXT_CAP = 16_000_000;
	private static final Object SCRIPT_COMPILE = new Object();

	private final long startedAt = System.currentTimeMillis();
	private final ReentrantReadWriteLock projectLock = new ReentrantReadWriteLock(true);
	private volatile SessionProject project;
	private volatile ProjectResolver.Resolved resolved;
	private final Map<String, ProgramEntry> entries = new ConcurrentHashMap<>();
	private final Map<Integer, Client> clients = new ConcurrentHashMap<>();
	private final AtomicInteger nextClient = new AtomicInteger(1);
	private volatile boolean shuttingDown;
	volatile JsonObject listenInfo;

	// ---- clients ---------------------------------------------------------------------------

	Client connect(String transport, boolean launcher, Consumer<JsonObject> events) {
		Client c = new Client(nextClient.getAndIncrement(), transport, launcher, events);
		clients.put(c.id, c);
		return c;
	}

	/** Releases everything a client still holds. Unsaved changes it owned are discarded. */
	void disconnect(Client c) {
		c.running.values().forEach(RequestMonitor::cancel);
		Lock pl = projectLock.readLock();
		boolean locked = false;
		try {
			locked = pl.tryLock(CLEANUP_WAIT_MS, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		try {
			releaseAll(c);
		}
		finally {
			if (locked) {
				pl.unlock();
			}
		}
		clients.remove(c.id);
		Msg.info(this, c.label() + " disconnected");
	}

	private void releaseAll(Client c) {
		List<String> held;
		synchronized (c.programs) {
			held = new ArrayList<>(c.programs);
		}
		for (String path : held) {
			ProgramEntry e = entries.get(path);
			if (e == null) {
				continue;
			}
			try {
				boolean discarded = releaseUse(c, e, true, CLEANUP_WAIT_MS);
				if (discarded) {
					Msg.warn(this, c.label() + " disconnected: discarded unsaved changes in " +
						path);
				}
			}
			catch (RuntimeException ex) {
				Msg.error(this, c.label() + " disconnect: could not release " + path, ex);
			}
		}
	}

	int clientCount() {
		return clients.size();
	}

	boolean isShuttingDown() {
		return shuttingDown;
	}

	/** Closes everything. Unsaved changes are discarded and logged. Idempotent. */
	synchronized void close() {
		if (shuttingDown && project == null) {
			return;
		}
		shuttingDown = true;
		clients.values().forEach(c -> c.running.values().forEach(RequestMonitor::cancel));
		boolean locked = false;
		try {
			locked = projectLock.writeLock().tryLock(30, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		try {
			for (ProgramEntry e : new ArrayList<>(entries.values())) {
				if (e.program != null && e.program.isChanged()) {
					Msg.warn(this, "shutdown: discarding unsaved changes in " + e.path);
				}
				closeEntry(e);
			}
			if (project != null) {
				project.close();
				project = null;
				resolved = null;
			}
		}
		finally {
			if (locked) {
				projectLock.writeLock().unlock();
			}
		}
	}

	// ---- dispatch --------------------------------------------------------------------------

	/** Commands answered on the connection's reader thread, even while another runs. */
	static boolean isInline(String cmd) {
		return cmd.equals("ping") || cmd.equals("cancel") || cmd.equals("status");
	}

	JsonElement execute(Client c, String cmd, JsonObject req, RequestMonitor m) {
		if (shuttingDown && !cmd.equals("shutdown") && !cmd.equals("ping")) {
			throw new SessionException(SessionException.CONFLICT, "the session is shutting down");
		}
		switch (cmd) {
			case "ping":
				return Json.of("pong", true);
			case "hello":
				return hello(c, req);
			case "status":
				return status(c);
			case "cancel":
				return cancel(c, req);
			case "shutdown":
				return shutdownCheck(c, req);
			case "open_project":
			case "close_project": {
				Lock l = lockProject(true, req, cmd);
				try {
					return cmd.equals("open_project") ? openProject(c, req, m) : closeProject(c, req);
				}
				finally {
					l.unlock();
				}
			}
			default:
				break;
		}
		Lock l = lockProject(false, req, cmd);
		try {
			return switch (cmd) {
				case "project" -> projectInfo();
				case "list" -> list(req);
				case "open_program", "switch" -> openProgram(c, req, m);
				case "programs" -> programs(c);
				case "info" -> withProgram(c, req, cmd, false, false, e -> programInfo(e, c));
				case "close_program" -> closeProgram(c, req);
				case "save" -> withProgram(c, req, cmd, true, true, e -> save(e, req, m));
				case "functions" -> withProgram(c, req, cmd, false, false, e -> functions(e, req));
				case "decompile" -> withProgram(c, req, cmd, false, false,
					e -> decompile(e, req, m));
				case "rename" -> withProgram(c, req, cmd, true, true, e -> rename(e, req));
				case "comment" -> withProgram(c, req, cmd, true, true, e -> comment(e, req));
				case "analyze" -> withProgram(c, req, cmd, true, true, e -> analyze(e, req, m));
				case "import" -> importProgram(c, req, m);
				case "script" -> script(c, req, m);
				default -> throw new SessionException(SessionException.UNKNOWN_COMMAND,
					"unknown cmd '" + cmd + "'; send status or see the README for the list");
			};
		}
		finally {
			l.unlock();
		}
	}

	private Lock lockProject(boolean exclusive, JsonObject req, String cmd) {
		Lock l = exclusive ? projectLock.writeLock() : projectLock.readLock();
		long wait = waitMs(req);
		try {
			if (l.tryLock(wait, TimeUnit.MILLISECONDS)) {
				return l;
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		throw new SessionException(SessionException.BUSY,
			exclusive ? cmd + " needs the project to itself and other requests are running"
					: "the project is being opened or closed",
			Json.of("waitedMs", wait));
	}

	private static long waitMs(JsonObject req) {
		return Json.num(req, "wait", DEFAULT_WAIT_MS, 0, 86_400_000L);
	}

	// ---- session ---------------------------------------------------------------------------

	private JsonElement hello(Client c, JsonObject req) {
		c.name = Json.str(req, "client", c.name);
		c.harness = Json.str(req, "harness", c.harness);
		JsonObject o = info();
		Json.put(o, "client", c.id);
		return o;
	}

	JsonObject info() {
		return Json.of("protocol", PROTOCOL_VERSION, "ghidra",
			Application.getApplicationVersion(), "pid", ProcessHandle.current().pid(), "uptimeMs",
			System.currentTimeMillis() - startedAt, "project", projectInfoOrNull(), "listen",
			listenInfo);
	}

	private JsonObject projectInfoOrNull() {
		try {
			return project == null ? null : projectInfo();
		}
		catch (RuntimeException e) {
			return null; // closed while we looked
		}
	}

	private JsonElement status(Client c) {
		JsonObject o = info();
		Json.put(o, "you", c.id);
		JsonArray ps = new JsonArray();
		for (ProgramEntry e : entries.values()) {
			JsonObject j = e.describeUse();
			Json.put(j, "path", e.path);
			ps.add(j);
		}
		o.add("programs", ps);
		JsonArray cs = new JsonArray();
		for (Client x : clients.values()) {
			cs.add(x.describe());
		}
		o.add("clients", cs);
		return o;
	}

	private JsonElement cancel(Client c, JsonObject req) {
		if (!req.has("target")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: target (the id of your running request)");
		}
		RequestMonitor m = c.running.get(req.get("target").toString());
		if (m != null) {
			m.cancel();
		}
		return Json.of("cancelled", m != null);
	}

	private JsonElement shutdownCheck(Client c, JsonObject req) {
		long others = clients.values().stream().filter(x -> x != c && !x.leaving).count();
		if (!c.launcher && others > 0 && !Json.bool(req, "force", false)) {
			throw new SessionException(SessionException.CONFLICT,
				others + " other client(s) are connected; pass \"force\":true to stop anyway",
				Json.of("clients", others));
		}
		return Json.of("stopping", true);
	}

	// ---- project ---------------------------------------------------------------------------

	private JsonObject projectInfo() {
		SessionProject p = project;
		ProjectResolver.Resolved r = resolved;
		if (p == null || r == null) {
			throw new SessionException(SessionException.NO_PROJECT,
				"no project is open; send open_project");
		}
		return Json.of("name", r.name(), "dir", r.dir().getPath(), "gpr", r.gpr().getPath(),
			"writable", p.isWritable(), "files", p.getProjectData().getFileCount());
	}

	private ProjectData data() {
		SessionProject p = project;
		if (p == null) {
			throw new SessionException(SessionException.NO_PROJECT,
				"no project is open; send open_project");
		}
		return p.getProjectData();
	}

	/** Held: the project write lock. */
	private JsonElement openProject(Client c, JsonObject req, RequestMonitor m) {
		ProjectResolver.Resolved r;
		try {
			r = ProjectResolver.resolve(Json.str(req, "path"));
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		boolean writable = Json.bool(req, "writable", false);
		if (project != null) {
			if (sameProject(r) && (project.isWritable() || !writable)) {
				return projectInfo();
			}
			closeOnlyMine(c, Json.bool(req, "discard", false), "open another project");
			project.close();
			project = null;
			resolved = null;
		}
		ProjectLocator locator;
		try {
			locator = new ProjectLocator(r.dir().getPath(), r.name());
		}
		catch (IllegalArgumentException e) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"Ghidra cannot open this path: " + e.getMessage());
		}
		try {
			project = SessionProject.open(locator, writable);
			resolved = r;
		}
		catch (LockException e) {
			throw new SessionException(SessionException.CONFLICT,
				"the project is locked by another process (a Ghidra window, analyzeHeadless or a " +
					"writable session): open it read-only, or close that process",
				Json.of("lockFile", locator.getProjectLockFile().getPath()), e);
		}
		catch (NotOwnerException e) {
			throw new SessionException(SessionException.CONFLICT, e.getMessage());
		}
		catch (NotFoundException | IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage(), null, e);
		}
		Msg.info(this, c.label() + " opened project " + r.gpr() +
			(writable ? " (writable)" : " (read-only view)"));
		return projectInfo();
	}

	private boolean sameProject(ProjectResolver.Resolved r) {
		try {
			return resolved != null &&
				resolved.gpr().getCanonicalFile().equals(r.gpr().getCanonicalFile());
		}
		catch (IOException e) {
			return false;
		}
	}

	/** Held: the project write lock. */
	private JsonElement closeProject(Client c, JsonObject req) {
		if (project == null) {
			return Json.of("closed", false);
		}
		closeOnlyMine(c, Json.bool(req, "discard", false), "close the project");
		project.close();
		project = null;
		resolved = null;
		return Json.of("closed", true);
	}

	/**
	 * Like the window, which closes its programs when it switches projects: allowed only when no
	 * other client uses a program, and nothing unsaved would be lost unless {@code discard}.
	 */
	private void closeOnlyMine(Client c, boolean discard, String what) {
		for (ProgramEntry e : entries.values()) {
			synchronized (e.users) {
				for (Client u : e.users) {
					if (u != c) {
						throw new SessionException(SessionException.CONFLICT,
							"cannot " + what + ": " + u.label() + " uses " + e.path,
							Json.of("program", e.path, "client", u.id));
					}
				}
			}
			if (!discard && e.program != null && e.program.isChanged()) {
				throw new SessionException(SessionException.UNSAVED_CHANGES,
					"cannot " + what + ": " + e.path +
						" has unsaved changes; save, or pass \"discard\":true",
					Json.of("program", e.path));
			}
		}
		for (ProgramEntry e : new ArrayList<>(entries.values())) {
			closeEntry(e);
		}
		c.programs.clear();
		c.active = null;
	}

	/** Held: the project write lock, so only a disconnect can still hold a program lock. */
	private void closeEntry(ProgramEntry e) {
		boolean got = false;
		try {
			got = e.lock.writeLock().tryLock(CLEANUP_WAIT_MS, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
		if (!got) {
			Msg.error(this, "could not close " + e.path + ": a request still holds it (" +
				e.exclusiveHolder + ")");
			return;
		}
		try {
			e.disposeDecompilers();
			if (e.program != null) {
				e.program.release(e);
				e.program = null;
			}
			synchronized (e.users) {
				for (Client u : e.users) {
					u.programs.remove(e.path);
					if (e.path.equals(u.active)) {
						u.active = null;
					}
				}
				e.users.clear();
			}
			e.mode = null;
			e.owner = null;
			entries.remove(e.path, e);
		}
		finally {
			e.lock.writeLock().unlock();
		}
	}

	private JsonElement list(JsonObject req) {
		String path = Json.str(req, "folder", "/");
		boolean recursive = Json.bool(req, "recursive", true);
		boolean programsOnly = Json.bool(req, "programsOnly", false);
		boolean metadata = Json.bool(req, "metadata", true);
		Page page = new Page((int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE),
			(int) Json.num(req, "limit", 1000, 1, 100_000));
		ProjectData d = data();
		DomainFolder folder = path.equals("/") ? d.getRootFolder() : d.getFolder(path);
		if (folder == null) {
			throw new SessionException(SessionException.NOT_FOUND, "no such folder: " + path);
		}
		walk(folder, recursive, programsOnly, metadata, page);
		return Json.of("folder", folder.getPathname(), "entries", page.out, "offset",
			page.offset, "returned", page.out.size(), "truncated", page.more);
	}

	/** One page of a listing: skips {@code offset} items, keeps {@code limit}, notes the rest. */
	private static final class Page {
		final int offset;
		final int limit;
		final JsonArray out = new JsonArray();
		int index;
		boolean more;

		Page(int offset, int limit) {
			this.offset = offset;
			this.limit = limit;
		}

		/** True when the walk can stop. */
		boolean offer(java.util.function.Supplier<JsonObject> item) {
			if (index++ < offset) {
				return false;
			}
			if (out.size() >= limit) {
				more = true;
				return true;
			}
			out.add(item.get());
			return false;
		}
	}

	/** Returns true when the page is full and the walk should stop. */
	private boolean walk(DomainFolder folder, boolean recursive, boolean programsOnly,
			boolean metadata, Page page) {
		for (DomainFolder sub : folder.getFolders()) {
			if (!programsOnly &&
				page.offer(() -> Json.of("path", sub.getPathname(), "kind", "folder"))) {
				return true;
			}
			if (recursive && walk(sub, true, programsOnly, metadata, page)) {
				return true;
			}
		}
		for (DomainFile f : folder.getFiles()) {
			boolean isProgram = Program.class.isAssignableFrom(f.getDomainObjectClass());
			if (programsOnly && !isProgram) {
				continue;
			}
			if (page.offer(() -> describeFile(f, isProgram, metadata))) {
				return true;
			}
		}
		return false;
	}

	private JsonObject describeFile(DomainFile f, boolean isProgram, boolean metadata) {
		JsonObject e = Json.of("path", f.getPathname(), "kind", "file", "name", f.getName(),
			"contentType", f.getContentType(), "program", isProgram, "versioned",
			f.isVersioned(), "readOnly", f.isReadOnly() || !f.isInWritableProject());
		try {
			Json.put(e, "bytes", f.length());
		}
		catch (IOException ex) {
			Json.put(e, "bytes", null);
		}
		if (metadata && isProgram) {
			Map<String, String> md = f.getMetadata();
			Json.put(e, "sha256", md.get("Executable SHA256"));
			Json.put(e, "language", md.get("Language ID"));
			Json.put(e, "executable", md.get("Executable Location"));
		}
		ProgramEntry pe = entries.get(f.getPathname());
		Json.put(e, "open", pe == null ? null : pe.describeUse());
		return e;
	}

	/**
	 * Finds a file by project path, or by bare name when it is unique in the project (the way
	 * {@code -process name} is used).
	 */
	private DomainFile findFile(String path) {
		ProjectData d = data();
		if (path.startsWith("/")) {
			DomainFile f = d.getFile(path);
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no such file in the project: " + path);
			}
			return f;
		}
		List<DomainFile> found = new ArrayList<>();
		collectByName(d.getRootFolder(), path, found);
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no file named " + path + " in the project");
		}
		List<String> paths = new ArrayList<>();
		found.forEach(f -> paths.add(f.getPathname()));
		JsonObject details = new JsonObject();
		Json.put(details, "candidates", paths);
		throw new SessionException(SessionException.CONFLICT,
			"several files are named " + path + "; pass the project path", details);
	}

	private static void collectByName(DomainFolder folder, String name, List<DomainFile> out) {
		DomainFile f = folder.getFile(name);
		if (f != null) {
			out.add(f);
		}
		for (DomainFolder sub : folder.getFolders()) {
			collectByName(sub, name, out);
		}
	}

	// ---- programs --------------------------------------------------------------------------

	private JsonElement openProgram(Client c, JsonObject req, RequestMonitor m) {
		boolean writable = Json.bool(req, "writable", false);
		if (writable && !project().isWritable()) {
			throw new SessionException(SessionException.READ_ONLY,
				"the project is open read-only; send open_project with \"writable\":true first " +
					"(this takes the project lock)");
		}
		DomainFile df = findFile(Json.str(req, "path"));
		if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
			throw new SessionException(SessionException.BAD_REQUEST,
				df.getPathname() + " is not a program (" + df.getContentType() + ")");
		}
		String path = df.getPathname();
		long wait = waitMs(req);
		JsonObject joined = joinOpen(c, path, writable, wait);
		if (joined != null) {
			return joined;
		}
		while (true) {
			ProgramEntry e = entries.computeIfAbsent(path, ProgramEntry::new);
			Lock l = e.acquire(true, wait, c, "open_program");
			try {
				if (entries.get(path) != e) {
					continue; // closed while we waited; open a fresh one
				}
				long t0 = System.nanoTime();
				try {
					if (e.program == null) {
						e.file = df;
						e.program = writable ? openWritable(e, df, req, m) : openReadOnly(e, df, m);
						e.mode = writable ? ProgramEntry.Mode.WRITABLE : ProgramEntry.Mode.READ_ONLY;
						e.owner = writable ? c : null;
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
					else if (writable && e.mode == ProgramEntry.Mode.WRITABLE && e.owner != c) {
						throw new SessionException(SessionException.NOT_OWNER,
							path + " is open writable by " + e.owner.label(),
							Json.of("program", path, "owner", e.owner.id));
					}
					else if (writable && e.mode == ProgramEntry.Mode.READ_ONLY) {
						Program np = openWritable(e, df, req, m);
						e.disposeDecompilers();
						e.program.release(e);
						e.program = np;
						e.mode = ProgramEntry.Mode.WRITABLE;
						e.owner = c;
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
				}
				catch (RuntimeException ex) {
					if (e.program == null) {
						entries.remove(path, e);
					}
					throw ex;
				}
				synchronized (e.users) {
					e.users.add(c);
				}
				c.programs.add(path);
				c.active = path;
				JsonObject info = programInfo(e, c);
				Json.put(info, "openMs", e.openMs);
				return info;
			}
			finally {
				e.release(l);
			}
		}
	}

	/**
	 * Joins a program that is already open in a mode that fits, under the shared lock, so that a
	 * client can start using a program while others run long reads or contained scripts on it.
	 * Returns null when the exclusive path (open, upgrade) is needed.
	 */
	private JsonObject joinOpen(Client c, String path, boolean writable, long wait) {
		ProgramEntry e = entries.get(path);
		if (e == null) {
			return null;
		}
		Lock l = e.acquire(false, wait, c, "open_program");
		try {
			if (entries.get(path) != e || e.program == null ||
				(writable && !(e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c))) {
				return null;
			}
			synchronized (e.users) {
				e.users.add(c);
			}
			c.programs.add(path);
			c.active = path;
			JsonObject info = programInfo(e, c);
			Json.put(info, "openMs", 0);
			return info;
		}
		finally {
			e.release(l);
		}
	}

	private Program openReadOnly(ProgramEntry e, DomainFile df, RequestMonitor m) {
		try {
			return (Program) df.getReadOnlyDomainObject(e, DomainFile.DEFAULT_VERSION, m);
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				df.getPathname() + " was saved by another Ghidra version: " + ex.getMessage());
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
	}

	private Program openWritable(ProgramEntry e, DomainFile df, JsonObject req,
			RequestMonitor m) {
		try {
			if (df.isReadOnly()) {
				throw new SessionException(SessionException.READ_ONLY,
					df.getPathname() + " is marked read-only in the project");
			}
			if (df.isVersioned() && !df.isCheckedOut()) {
				if (!Json.bool(req, "checkout", false)) {
					throw new SessionException(SessionException.READ_ONLY,
						df.getPathname() + " is versioned and not checked out; pass " +
							"\"checkout\":true to check it out");
				}
				if (!df.checkout(false, m)) {
					throw new SessionException(SessionException.FAILED,
						"checkout of " + df.getPathname() + " failed");
				}
			}
			return (Program) df.getDomainObject(e, Json.bool(req, "upgrade", false), false, m);
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				df.getPathname() + " needs a database upgrade (" + ex.getMessage() +
					"); pass \"upgrade\":true to allow it");
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
	}

	private SessionProject project() {
		SessionProject p = project;
		if (p == null) {
			throw new SessionException(SessionException.NO_PROJECT,
				"no project is open; send open_project");
		}
		return p;
	}

	private JsonElement programs(Client c) {
		JsonArray a = new JsonArray();
		List<String> mine;
		synchronized (c.programs) {
			mine = new ArrayList<>(c.programs);
		}
		for (String path : mine) {
			ProgramEntry e = entries.get(path);
			if (e != null && e.program != null) {
				a.add(programInfo(e, c));
			}
		}
		return Json.of("active", c.active, "programs", a);
	}

	private JsonElement closeProgram(Client c, JsonObject req) {
		ProgramEntry e = selected(c, req);
		boolean discarded = releaseUse(c, e, Json.bool(req, "discard", false), waitMs(req));
		return Json.of("closed", e.path, "discarded", discarded, "active", c.active);
	}

	/**
	 * Drops one client's use of a program. When it owned the writable program, the program goes
	 * back to read-only for the other users, and unsaved changes are discarded only if
	 * {@code discard}. Returns true when changes were discarded.
	 */
	private boolean releaseUse(Client c, ProgramEntry e, boolean discard, long wait) {
		Lock l = e.acquire(true, wait, c, "close_program");
		try {
			boolean discarded = false;
			boolean others;
			synchronized (e.users) {
				others = e.users.stream().anyMatch(u -> u != c);
			}
			if (e.program != null && e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c) {
				if (e.program.isChanged()) {
					if (!discard) {
						throw new SessionException(SessionException.UNSAVED_CHANGES,
							e.path + " has unsaved changes; send save, or close with " +
								"\"discard\":true",
							Json.of("program", e.path));
					}
					discarded = true;
				}
				e.disposeDecompilers();
				e.program.release(e); // releasing a changed program discards its changes
				e.program = null;
				e.owner = null;
				if (others) {
					try {
						e.program = openReadOnly(e, e.file, new RequestMonitor(null, null));
						e.mode = ProgramEntry.Mode.READ_ONLY;
					}
					catch (RuntimeException ex) {
						Msg.error(this, "could not reopen " + e.path + " read-only for its " +
							"other users; closing it for everyone", ex);
						closeEntry(e);
						c.programs.remove(e.path);
						return discarded;
					}
				}
			}
			synchronized (e.users) {
				e.users.remove(c);
				others = !e.users.isEmpty();
			}
			if (!others) {
				e.disposeDecompilers();
				if (e.program != null) {
					e.program.release(e);
					e.program = null;
				}
				e.mode = null;
				entries.remove(e.path, e);
			}
			c.programs.remove(e.path);
			if (e.path.equals(c.active)) {
				synchronized (c.programs) {
					c.active = c.programs.isEmpty() ? null : c.programs.iterator().next();
				}
			}
			return discarded;
		}
		finally {
			e.release(l);
		}
	}

	private ProgramEntry selected(Client c, JsonObject req) {
		String path = Json.str(req, "program", c.active);
		if (path == null) {
			throw new SessionException(SessionException.NO_PROGRAM,
				"no active program; send open_program first");
		}
		if (!path.startsWith("/")) {
			path = findFile(path).getPathname();
		}
		ProgramEntry e = entries.get(path);
		if (e == null || !c.programs.contains(path)) {
			throw new SessionException(SessionException.NO_PROGRAM,
				path + " is not open for this client; send open_program first",
				Json.of("program", path));
		}
		return e;
	}

	private interface ProgramWork {
		JsonElement run(ProgramEntry e) throws Exception;
	}

	private JsonElement withProgram(Client c, JsonObject req, String cmd, boolean exclusive,
			boolean needOwner, ProgramWork work) {
		ProgramEntry e = selected(c, req);
		Lock l = e.acquire(exclusive, waitMs(req), c, cmd);
		try {
			if (e.program == null) {
				throw new SessionException(SessionException.NO_PROGRAM, e.path + " was closed");
			}
			if (needOwner) {
				requireOwner(c, e, cmd);
			}
			return work.run(e);
		}
		catch (SessionException ex) {
			throw ex;
		}
		catch (CancelledException ex) {
			throw new SessionException(SessionException.CANCELLED, cmd + " was cancelled");
		}
		catch (Exception ex) {
			throw new SessionException(SessionException.FAILED,
				ex.getClass().getSimpleName() + ": " + ex.getMessage(), null, ex);
		}
		finally {
			e.release(l);
		}
	}

	private static void requireOwner(Client c, ProgramEntry e, String cmd) {
		if (e.mode != ProgramEntry.Mode.WRITABLE) {
			throw new SessionException(SessionException.READ_ONLY,
				e.path + " is open read-only; " + cmd + " needs open_program with " +
					"\"writable\":true",
				Json.of("program", e.path));
		}
		if (e.owner != c) {
			throw new SessionException(SessionException.NOT_OWNER,
				e.path + " is owned by " + e.owner.label() + "; only the owner may " + cmd,
				Json.of("program", e.path, "owner", e.owner.id));
		}
	}

	private JsonObject programInfo(ProgramEntry e, Client c) {
		Program p = e.program;
		JsonObject j = Json.of("path", e.path, "name", p.getName(), "mode", e.mode.json(),
			"owner", e.owner == null ? null : e.owner.id, "mine", e.owner == c, "active",
			e.path.equals(c.active), "language", p.getLanguageID().getIdAsString(), "compiler",
			p.getCompilerSpec().getCompilerSpecID().getIdAsString(), "imageBase",
			hex(p.getImageBase()), "format", p.getExecutableFormat(), "executable",
			p.getExecutablePath(), "sha256", p.getExecutableSHA256(), "md5",
			p.getExecutableMD5(), "functions", p.getFunctionManager().getFunctionCount(),
			"analyzed", GhidraProgramUtilities.isAnalyzed(p), "changed", p.isChanged());
		synchronized (e.users) {
			List<Integer> ids = new ArrayList<>();
			e.users.forEach(u -> ids.add(u.id));
			Json.put(j, "users", ids);
		}
		return j;
	}

	private JsonElement save(ProgramEntry e, JsonObject req, RequestMonitor m)
			throws IOException, CancelledException {
		boolean changed = e.program.isChanged();
		if (changed) {
			e.program.save(Json.str(req, "comment", "headless session"), m);
		}
		return Json.of("path", e.path, "saved", changed);
	}

	// ---- queries ---------------------------------------------------------------------------

	static String hex(Address a) {
		if (a.getAddressSpace().isMemorySpace() &&
			a.getAddressSpace() == a.getAddressSpace().getPhysicalSpace() &&
			!a.getAddressSpace().isOverlaySpace()) {
			return "0x" + Long.toHexString(a.getOffset());
		}
		return a.toString(true);
	}

	/** Accepts {@code 0x140001000}, {@code va:0x...}, {@code rva:0x...} or {@code space:offset}. */
	static Address address(Program p, String text) {
		String t = text.trim();
		try {
			if (t.startsWith("rva:")) {
				return p.getImageBase().add(Long.decode(t.substring(4)));
			}
			if (t.startsWith("va:")) {
				t = t.substring(3);
			}
			if (!t.contains(":")) {
				String h = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
				return p.getAddressFactory()
						.getDefaultAddressSpace()
						.getAddress(Long.parseUnsignedLong(h, 16));
			}
			Address a = p.getAddressFactory().getAddress(t);
			if (a != null) {
				return a;
			}
		}
		catch (NumberFormatException | AddressOutOfBoundsException e) {
			// fall through
		}
		throw new SessionException(SessionException.BAD_REQUEST,
			"bad address '" + text + "': use 0x<hex>, va:0x<hex>, rva:0x<hex> or space:offset");
	}

	private Function function(Program p, JsonObject req) {
		if (Json.has(req, "address")) {
			Address a = address(p, Json.str(req, "address"));
			Function f = p.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function contains " + hex(a), Json.of("address", hex(a)));
			}
			return f;
		}
		String name = Json.str(req, "name");
		List<Function> found = new ArrayList<>();
		for (Symbol s : p.getSymbolTable().getSymbols(name)) {
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				found.add((Function) s.getObject());
			}
		}
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND, "no function named " + name);
		}
		List<String> at = new ArrayList<>();
		found.forEach(f -> at.add(hex(f.getEntryPoint())));
		JsonObject d = new JsonObject();
		Json.put(d, "candidates", at);
		throw new SessionException(SessionException.CONFLICT,
			"several functions are named " + name + "; pass an address", d);
	}

	private JsonElement functions(ProgramEntry e, JsonObject req) {
		Pattern pat = null;
		if (Json.has(req, "regex")) {
			try {
				pat = Pattern.compile(Json.str(req, "regex"));
			}
			catch (PatternSyntaxException ex) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"bad regex: " + ex.getMessage());
			}
		}
		String sub = Json.str(req, "contains", null);
		int limit = (int) Json.num(req, "limit", 200, 1, 10_000);
		int offset = (int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE);
		JsonArray a = new JsonArray();
		int seen = 0;
		boolean truncated = false;
		for (Function f : e.program.getFunctionManager().getFunctions(true)) {
			String n = f.getName(true);
			if (pat != null && !pat.matcher(n).find()) {
				continue;
			}
			if (sub != null && !n.contains(sub)) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (a.size() >= limit) {
				truncated = true;
				break;
			}
			a.add(Json.of("name", n, "address", hex(f.getEntryPoint()), "size",
				f.getBody().getNumAddresses(), "thunk", f.isThunk(), "external", f.isExternal()));
		}
		return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
			truncated);
	}

	private JsonElement decompile(ProgramEntry e, JsonObject req, RequestMonitor m) {
		Function f = function(e.program, req);
		int timeout = (int) Json.num(req, "timeout", 60, 1, 3600);
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		DecompInterface d = e.borrowDecompiler();
		boolean healthy = false;
		try {
			DecompileResults res = d.decompileFunction(f, timeout, m);
			if (m.isCancelled()) {
				throw cancelled(m);
			}
			JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
			boolean ok = res != null && res.decompileCompleted();
			Json.put(r, "completed", ok);
			if (!ok) {
				Json.put(r, "error", res == null ? "no result" : res.getErrorMessage());
				Json.put(r, "timedOut", res != null && res.isTimedOut());
				return r;
			}
			healthy = true;
			DecompiledFunction df = res.getDecompiledFunction();
			String c = df.getC();
			Json.put(r, "signature", df.getSignature());
			Json.put(r, "chars", c.length());
			Json.put(r, "truncated", c.length() > cap);
			Json.put(r, "c", c.length() > cap ? c.substring(0, cap) : c);
			return r;
		}
		finally {
			e.returnDecompiler(d, healthy);
		}
	}

	// ---- edits -----------------------------------------------------------------------------

	private JsonElement rename(ProgramEntry e, JsonObject req) throws Exception {
		Program p = e.program;
		Address a = address(p, Json.str(req, "address"));
		String name = Json.str(req, "name");
		String kind = Json.str(req, "kind", "auto");
		if (!kind.equals("auto") && !kind.equals("function") && !kind.equals("label")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"kind must be auto, function or label");
		}
		String old = null;
		int tx = p.startTransaction("session rename");
		boolean ok = false;
		try {
			Function f = p.getFunctionManager().getFunctionAt(a);
			if (kind.equals("function") && f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function starts at " + hex(a));
			}
			if (f != null && !kind.equals("label")) {
				old = f.getName();
				f.setName(name, SourceType.USER_DEFINED);
				kind = "function";
			}
			else {
				Symbol s = p.getSymbolTable().getPrimarySymbol(a);
				if (s != null && s.getSymbolType() == SymbolType.LABEL && !s.isDynamic()) {
					old = s.getName();
					s.setName(name, SourceType.USER_DEFINED);
				}
				else {
					old = s == null ? null : s.getName();
					Symbol n = p.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
					n.setPrimary();
				}
				kind = "label";
			}
			ok = true;
		}
		finally {
			p.endTransaction(tx, ok);
		}
		return Json.of("address", hex(a), "name", name, "old", old, "kind", kind);
	}

	private JsonElement comment(ProgramEntry e, JsonObject req) {
		Program p = e.program;
		Address a = address(p, Json.str(req, "address"));
		CommentType ct = switch (Json.str(req, "type", "eol")) {
			case "eol" -> CommentType.EOL;
			case "pre" -> CommentType.PRE;
			case "post" -> CommentType.POST;
			case "plate" -> CommentType.PLATE;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> throw new SessionException(SessionException.BAD_REQUEST,
				"type must be eol, pre, post, plate or repeatable");
		};
		String text = Json.has(req, "text") ? Json.str(req, "text") : null;
		int tx = p.startTransaction("session comment");
		try {
			p.getListing().setComment(a, ct, text);
		}
		finally {
			p.endTransaction(tx, true);
		}
		return Json.of("address", hex(a), "type", Json.str(req, "type", "eol"));
	}

	/**
	 * The window's <i>Analysis &gt; Auto Analyze</i>, the same way {@code analyzeHeadless} runs
	 * it: optional analysis options first, then all analyzers (or those triggered by a restricted
	 * address set) in this thread, under one transaction.
	 */
	private JsonElement analyze(ProgramEntry e, JsonObject req, RequestMonitor m) {
		Program p = e.program;
		JsonObject opts = Json.obj(req, "options");
		if (opts != null) {
			setAnalysisOptions(p, opts);
		}
		AddressSet restrict = null;
		if (Json.has(req, "ranges")) {
			restrict = new AddressSet();
			for (JsonElement r : req.getAsJsonArray("ranges")) {
				JsonArray pair = r.getAsJsonArray();
				restrict.add(address(p, pair.get(0).getAsString()),
					address(p, pair.get(1).getAsString()));
			}
		}
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		long t0 = System.nanoTime();
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
		int tx = p.startTransaction("Analysis");
		try {
			mgr.initializeOptions();
			mgr.reAnalyzeAll(restrict);
			mgr.startAnalysis(m);
			if (m.isCancelled()) {
				mgr.cancelQueuedTasks();
			}
			else {
				GhidraProgramUtilities.markProgramAnalyzed(p);
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
		if (m.isCancelled()) {
			throw new SessionException(SessionException.CANCELLED,
				"analysis stopped " + (m.timedOut() ? "at its timeout" : "on cancel") +
					"; what ran so far is kept in memory (unsaved)",
				Json.of("program", e.path));
		}
		return Json.of("program", e.path, "analyzed", true, "seconds",
			(System.nanoTime() - t0) / 1e9, "functions", p.getFunctionManager().getFunctionCount(),
			"changed", p.isChanged());
	}

	private static void setAnalysisOptions(Program p, JsonObject opts) {
		Options options = p.getOptions(Program.ANALYSIS_PROPERTIES);
		int tx = p.startTransaction("session analysis options");
		try {
			for (Map.Entry<String, JsonElement> o : opts.entrySet()) {
				String n = o.getKey();
				if (!options.contains(n)) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"no analysis option named '" + n + "'");
				}
				OptionType t = options.getType(n);
				JsonElement v = o.getValue();
				switch (t) {
					case BOOLEAN_TYPE -> options.setBoolean(n, v.getAsBoolean());
					case INT_TYPE -> options.setInt(n, v.getAsInt());
					case LONG_TYPE -> options.setLong(n, v.getAsLong());
					case DOUBLE_TYPE -> options.setDouble(n, v.getAsDouble());
					case STRING_TYPE -> options.setString(n, v.getAsString());
					default -> throw new SessionException(SessionException.BAD_REQUEST,
						"option '" + n + "' has type " + t + ", which a session cannot set; " +
							"use a script");
				}
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
	}

	// ---- import ----------------------------------------------------------------------------

	/**
	 * Imports a file into the open (writable) project and opens it writable for the caller. A
	 * file whose SHA-256 is already in the project is not imported again unless
	 * {@code "duplicate":true}.
	 */
	private JsonElement importProgram(Client c, JsonObject req, RequestMonitor m) {
		if (!project().isWritable()) {
			throw new SessionException(SessionException.READ_ONLY,
				"import needs the project open writable (open_project \"writable\":true)");
		}
		File file = new File(Json.str(req, "file")).getAbsoluteFile();
		if (!file.isFile()) {
			throw new SessionException(SessionException.NOT_FOUND, "no such file: " + file);
		}
		String folder = Json.str(req, "folder", "/");
		long t0 = System.nanoTime();
		String sha;
		try {
			sha = HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, file);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
		if (!Json.bool(req, "duplicate", false)) {
			List<String> same = new ArrayList<>();
			findBySha(data().getRootFolder(), sha, same);
			if (!same.isEmpty()) {
				JsonObject r = Json.of("imported", false, "sha256", sha);
				Json.put(r, "existing", same);
				Json.put(r, "note", "already in the project; open_program it, or pass " +
					"\"duplicate\":true to import again");
				return r;
			}
		}
		String saved;
		MessageLog log = new MessageLog();
		try {
			DomainFolder dest =
				ProjectDataUtils.createDomainFolderPath(data().getRootFolder(), folder);
			ProgramLoader.Builder b = ProgramLoader.builder()
					.source(file)
					.project(project())
					.projectFolderPath(dest.getPathname())
					.log(log)
					.monitor(m);
			if (Json.has(req, "name")) {
				b.name(Json.str(req, "name"));
			}
			if (Json.has(req, "language")) {
				b.language(Json.str(req, "language"));
			}
			if (Json.has(req, "compiler")) {
				b.compiler(Json.str(req, "compiler"));
			}
			try (LoadResults<Program> results = b.load()) {
				saved = results.getPrimary().save(m).getPathname();
			}
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
		catch (SessionException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new SessionException(SessionException.FAILED,
				"import failed: " + ex.getMessage(), Json.of("log", log.toString()), ex);
		}
		double importS = (System.nanoTime() - t0) / 1e9;
		JsonObject openReq = Json.of("path", saved, "writable", true);
		if (req.has("wait")) {
			openReq.add("wait", req.get("wait"));
		}
		JsonObject info = (JsonObject) openProgram(c, openReq, m);
		JsonObject r = Json.of("imported", true, "path", saved, "sha256", sha, "importSeconds",
			importS, "program", info);
		if (Json.bool(req, "analyze", false)) {
			JsonObject areq = Json.of("program", saved);
			if (req.has("timeout")) {
				areq.add("timeout", req.get("timeout"));
			}
			r.add("analysis", withProgram(c, areq, "analyze", true, true,
				e -> analyze(e, areq, m)));
			r.add("save", withProgram(c, areq, "save", true, true,
				e -> save(e, Json.of("comment", "import + analysis"), m)));
		}
		return r;
	}

	private static void findBySha(DomainFolder folder, String sha, List<String> out) {
		for (DomainFile f : folder.getFiles()) {
			if (sha.equalsIgnoreCase(f.getMetadata().get("Executable SHA256"))) {
				out.add(f.getPathname());
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			findBySha(sub, sha, out);
		}
	}

	// ---- scripts ---------------------------------------------------------------------------

	/**
	 * Runs a GhidraScript (by name on the script path, or by file path) with a program as
	 * {@code currentProgram}, the way the window's Script Manager does, and returns what it
	 * printed.
	 * <ul>
	 * <li>On a program this client owns writable: exclusive, and its changes stay (unsaved unless
	 * {@code "save":true}).</li>
	 * <li>Otherwise <i>contained</i>: the script runs inside an outer transaction that is always
	 * rolled back, so it cannot change what other clients see or what is saved. Contained scripts
	 * share the program lock and run concurrently unless {@code "exclusive":true}.</li>
	 * <li>With {@code "program":null} (or no program open) it runs with no current program, only
	 * the project.</li>
	 * </ul>
	 * This is not a sandbox: a script is Java with the session's rights.
	 */
	private JsonElement script(Client c, JsonObject req, RequestMonitor m) {
		String name = Json.str(req, "script");
		ResourceFile src = findScript(name);
		boolean noProgram = req.has("program") && req.get("program").isJsonNull();
		ProgramEntry e = (noProgram || (c.active == null && !req.has("program"))) ? null
				: selected(c, req);
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		if (e == null) {
			return runScript(src, req, null, null, "none", m);
		}
		boolean owner = e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c;
		boolean exclusive = owner || Json.bool(req, "exclusive", false);
		Lock l = e.acquire(exclusive, waitMs(req), c, "script " + name);
		try {
			if (e.program == null) {
				throw new SessionException(SessionException.NO_PROGRAM, e.path + " was closed");
			}
			owner = e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c;
			JsonObject r = runScript(src, req, e.program, e, owner ? "owner" : "contained", m);
			if (owner && Json.bool(req, "save", false) && e.program.isChanged()) {
				e.program.save("script " + name, m);
				Json.put(r, "saved", true);
			}
			return r;
		}
		catch (CancelledException | IOException ex) {
			throw new SessionException(
				ex instanceof CancelledException ? SessionException.CANCELLED
						: SessionException.FAILED,
				ex.getMessage());
		}
		finally {
			e.release(l);
		}
	}

	private static ResourceFile findScript(String name) {
		File f = new File(name);
		ResourceFile src = f.isAbsolute() || f.isFile() ? new ResourceFile(f.getAbsoluteFile())
				: GhidraScriptUtil.findScriptByName(name);
		if (src == null || !src.exists()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"script not found: " + name + " (give a file path, or start the session " +
					"with -scriptPath)");
		}
		return src;
	}

	private JsonObject runScript(ResourceFile src, JsonObject req, Program p, ProgramEntry e,
			String mode, RequestMonitor m) {
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw, true);
		GhidraScript s;
		synchronized (SCRIPT_COMPILE) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
			if (provider == null) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"no script provider for " + src.getName());
			}
			try {
				s = provider.getScriptInstance(src, pw);
			}
			catch (Exception ex) {
				pw.flush();
				throw new SessionException(SessionException.FAILED,
					"script did not load: " + ex.getMessage(), Json.of("output", sw.toString()),
					ex);
			}
		}
		s.setScriptArgs(Json.strings(req, "args").toArray(new String[0]));
		bindHeadless(s);
		ProgramLocation loc = null;
		if (p != null && Json.has(req, "address")) {
			loc = new ProgramLocation(p, address(p, Json.str(req, "address")));
		}
		GhidraState state = new GhidraState(null, project, p, loc, null, null);
		boolean contained = p != null && mode.equals("contained");
		int outer = -1;
		if (contained) {
			outer = p.startTransaction("session: contained script (rolled back)");
		}
		long t0 = System.nanoTime();
		Throwable failure = null;
		try {
			s.execute(state, new ScriptControls(pw, pw, false, m));
		}
		catch (Throwable t) {
			failure = t;
		}
		finally {
			if (contained) {
				p.endTransaction(outer, false);
			}
			pw.flush();
		}
		String out = sw.toString();
		JsonObject r = Json.of("script", src.getAbsolutePath(), "mode", mode, "seconds",
			(System.nanoTime() - t0) / 1e9, "chars", out.length(), "truncated", out.length() > cap,
			"output", out.length() > cap ? out.substring(0, cap) : out, "changed",
			p != null && p.isChanged());
		if (failure != null) {
			if (m.isCancelled() || failure instanceof CancelledException) {
				throw new SessionException(SessionException.CANCELLED,
					"script " + (m.timedOut() ? "timed out" : "cancelled"), r);
			}
			throw new SessionException(SessionException.FAILED,
				"script failed: " + failure.getClass().getSimpleName() + ": " +
					failure.getMessage(),
				r, failure);
		}
		return r;
	}

	/**
	 * Lets {@link HeadlessScript} subclasses run here as under {@code analyzeHeadless}
	 * ({@code storeHeadlessValue} and friends). The setter is package-private in Ghidra, so it is
	 * reached reflectively rather than by editing Ghidra's class.
	 */
	private static void bindHeadless(GhidraScript s) {
		if (!(s instanceof HeadlessScript hs)) {
			return;
		}
		try {
			Method set = HeadlessScript.class.getDeclaredMethod("setHeadlessInstance",
				HeadlessAnalyzer.class);
			set.setAccessible(true);
			set.invoke(hs, HeadlessAnalyzer.getInstance());
		}
		catch (ReflectiveOperationException | IOException | RuntimeException ex) {
			Msg.warn(Session.class, "HeadlessScript features unavailable: " + ex);
		}
	}

	private static SessionException cancelled(RequestMonitor m) {
		return new SessionException(SessionException.CANCELLED,
			m.timedOut() ? "timed out" : "cancelled");
	}
}
