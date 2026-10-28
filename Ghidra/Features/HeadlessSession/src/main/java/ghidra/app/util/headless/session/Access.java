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

import static ghidra.app.util.headless.session.EditCommands.withLastEditor;
import static ghidra.app.util.headless.session.ProjectCommands.findFile;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.regex.Pattern;

import com.google.gson.*;

import ghidra.util.exception.*;

/**
 * How a command reaches what it acts on: the project or program a request names
 * (and that this client has joined or opened), the locks it takes there, and the
 * ownership checks of a write. The lock order is the one documented on
 * {@link Session}.
 */
final class Access {

	private final Session s;

	Access(Session s) {
		this.s = s;
	}

	static final Pattern PROGRAM_KEY = Pattern.compile("(p\\d+):(/.*)");

	/**
	 * The project a command acts on: {@code "project"} (an id like {@code p1}, or a path to the
	 * project), else the project of {@code "program"} when that is a program key, else the
	 * client's active project. The client must have joined it.
	 */
	ProjectEntry projectFor(Client c, JsonObject req) {
		String key = Json.str(req, "project", null);
		if (key == null && Json.has(req, "program")) {
			java.util.regex.Matcher mk = PROGRAM_KEY.matcher(Json.str(req, "program"));
			if (mk.matches()) {
				key = mk.group(1);
			}
		}
		if (key == null) {
			key = c.activeProject;
		}
		if (key == null) {
			throw new SessionException(SessionException.NO_PROJECT,
				"no project selected; send open_project first");
		}
		ProjectEntry p = s.projectsById.get(key);
		if (p == null && !key.matches("p\\d+")) {
			try {
				ProjectResolver.Resolved r = ProjectResolver.resolve(key);
				p = s.projects.get(r.gpr().getCanonicalPath());
			}
			catch (IOException e) {
				throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
			}
		}
		if (p == null || p.closed) {
			throw new SessionException(SessionException.NO_PROJECT,
				"project " + key + " is not open; send open_project", Json.of("project", key));
		}
		if (!c.projects.contains(p.id)) {
			throw new SessionException(SessionException.NO_PROJECT,
				"this client has not joined project " + p.id + "; send open_project",
				Json.of("project", p.id));
		}
		return p;
	}

	interface ProjectWork<T> {
		T run(ProjectEntry p);
	}

	<T> T inProject(ProjectEntry p, JsonObject req, String cmd, ProjectWork<T> work) {
		Lock l = lockProject(p, false, waitMs(req), cmd);
		try {
			return work.run(p);
		}
		finally {
			p.lastUsed = System.currentTimeMillis();
			l.unlock();
		}
	}

	static Lock lockProject(ProjectEntry p, boolean exclusive, long wait, String cmd) {
		Lock l = exclusive ? p.lock.writeLock() : p.lock.readLock();
		Waits.Outcome got = Waits.lock(p.lock, exclusive, wait, Waits.counter(p), waiter -> {
			// an exclusive holder is the request that closes or forks the project; shared holders
			// (pins) are not tracked, and the daemon's own holds (client null) are not a client's
			Client hc = p.exclusiveClient;
			return p.exclusiveCmd != null && hc != null && hc != waiter ? Waits.HELD_BY_OTHER
					: Waits.HELD_BY_NONE;
		});
		if (got != Waits.Outcome.GOT) {
			boolean full = got == Waits.Outcome.QUEUE_FULL;
			boolean v3 = Waits.v3();
			JsonObject d = p.identity();
			Json.put(d, "wanted", exclusive ? "exclusive" : "shared");
			Json.put(d, "waitedMs", full ? 0 : wait);
			String holderCmd = p.exclusiveCmd;
			if (holderCmd != null) {
				Client hc = p.exclusiveClient;
				Json.put(d, "holder", (hc == null ? "the session" : hc.label()) + " " + holderCmd);
				Json.put(d, "holderInfo", hc != null ? hc.holder(holderCmd, p.exclusiveSince)
						: Json.of("label", "the session", "command", holderCmd, "heldMs",
							System.currentTimeMillis() - p.exclusiveSince));
			}
			else {
				Json.put(d, "readers", p.lock.getReadLockCount());
			}
			Json.put(d, "suggest", "retry");
			if (full) {
				Json.put(d, "waiters", Waits.counter(p).get());
				Json.put(d, "waitersMax", Waits.cap(Caller.monitor()));
			}
			d = SessionException.busyDetails(v3, d, full ? "lock_queue_full" : "lock_wait", null,
				null);
			SessionException ex = new SessionException(SessionException.BUSY,
				full ? "too many requests already wait for project " + p.id + "; retry"
						: exclusive ? cmd + " needs project " + p.id +
							" to itself and requests are running"
								: "project " + p.id + " is being " +
									(holderCmd == null ? "opened or closed" : "changed (" + holderCmd + ")"),
				d);
			if (v3) {
				ex.withRetryAfterMs(1000);
			}
			throw ex;
		}
		if (p.closed) {
			l.unlock();
			throw new SessionException(SessionException.NO_PROJECT,
				"project " + p.id + " was closed", Json.of("project", p.id));
		}
		if (exclusive) {
			p.exclusiveCmd = cmd;
			p.exclusiveClient = null;
			p.exclusiveSince = System.currentTimeMillis();
			return l;
		}
		// a command pins the project: the shared lock plus a reference on the view it starts on
		return new ProjectEntry.Pin(p, l);
	}

	/** Releases a project lock taken with {@link #lockProject}. */
	static void unlockProject(ProjectEntry p, Lock l) {
		if (l == p.lock.writeLock()) {
			p.exclusiveCmd = null;
			p.exclusiveClient = null;
		}
		l.unlock();
	}

	/**
	 * What a client that cannot write a project or program should do instead: fork the project
	 * into a working copy of its own (see {@code fork_project}). The path is a suggestion, next to
	 * the project's folder.
	 */
	static JsonObject forkSuggestion(ProjectEntry p, Client c) {
		String who = (c == null || c.name.isEmpty() ? "client" + (c == null ? "" : c.id) : c.name)
				.replaceAll("[^A-Za-z0-9_.-]", "_");
		File dir = p.resolved.dir();
		File parent = dir.getAbsoluteFile().getParentFile();
		File dest = new File(parent == null ? dir : parent, dir.getName() + "-fork-" + who);
		return Json.of("cmd", "fork_project", "project", p.id, "path", dest.getPath(), "writable",
			true);
	}

	/** Adds {@code suggest: fork_project} and its {@code suggestion} to error details. */
	static JsonObject suggestFork(JsonObject d, ProjectEntry p, Client c) {
		Json.put(d, "suggest", "fork_project");
		d.add("suggestion", forkSuggestion(p, c));
		return d;
	}

	static String firstOf(Set<String> set) {
		synchronized (set) {
			return set.isEmpty() ? null : set.iterator().next();
		}
	}

	ProgramEntry entryByKey(String key) {
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(key);
		if (!mk.matches()) {
			return null;
		}
		ProjectEntry p = s.projectsById.get(mk.group(1));
		return p == null ? null : p.programs.get(mk.group(2));
	}

	/**
	 * The program a command acts on: {@code "program"} (a key {@code p1:/path}, or a path or
	 * unique name in {@code "project"} or the active project), else the client's active program.
	 */
	ProgramEntry selected(Client c, JsonObject req) {
		if (!Json.has(req, "program")) {
			String key = c.active;
			if (key == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					"no active program; send open_program first");
			}
			ProgramEntry e = entryByKey(key);
			if (e == null) {
				throw new SessionException(SessionException.NO_PROGRAM,
					key + " was closed; send open_program");
			}
			return e;
		}
		String path = Json.str(req, "program");
		ProjectEntry p = projectFor(c, req);
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(path);
		if (mk.matches()) {
			path = mk.group(2);
		}
		if (!path.startsWith("/")) {
			path = findFile(p, path).getPathname();
		}
		ProgramEntry e = p.programs.get(path);
		String key = p.id + ":" + path;
		if (e == null || !c.programs.contains(key)) {
			throw new SessionException(SessionException.NO_PROGRAM,
				key + " is not open for this client; send open_program first",
				Json.of("program", key));
		}
		return e;
	}

	interface ProgramWork {
		JsonElement run(ProgramEntry e) throws Exception;
	}

	JsonElement withProgram(Client c, JsonObject req, String cmd, boolean exclusive,
			boolean needOwner, ProgramWork work) {
		ProgramEntry e = selected(c, req);
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), cmd);
		try {
			Lock l = e.acquire(exclusive, waitMs(req), c, cmd);
			boolean marked = false;
			try {
				if (e.program == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				if (needOwner) {
					requireOwner(c, e, cmd);
				}
				if (exclusive && cmd.equals("analyze")) {
					// while this runs, a protocol 3 reader is told "analyzing" at once (BP5, 3.13)
					e.analysis = new ProgramEntry.Analysis(c, Caller.monitor(), cmd,
						System.currentTimeMillis(), Caller.current(c));
					marked = true;
				}
				return work.run(e);
			}
			catch (SessionException ex) {
				throw withLastEditor(e, ex);
			}
			catch (CancelledException ex) {
				throw new SessionException(SessionException.CANCELLED, cmd + " was cancelled");
			}
			catch (Exception ex) {
				throw new SessionException(SessionException.FAILED,
					ex.getClass().getSimpleName() + ": " + ex.getMessage(), null, ex);
			}
			finally {
				if (marked) {
					e.analysis = null;
				}
				e.release(l);
			}
		}
		finally {
			p.lastUsed = System.currentTimeMillis();
			pl.unlock();
		}
	}

	private static void requireOwner(Client c, ProgramEntry e, String cmd) {
		if (e.mode == ProgramEntry.Mode.SHARED) {
			if (e.isWriter(c)) {
				return;
			}
			JsonObject d = e.identity();
			Json.put(d, "writers", e.writerIds());
			Json.put(d, "suggest", "share");
			throw new SessionException(SessionException.NOT_OWNER,
				e.key + " is shared by writers " + e.writerIds() + "; " + cmd + " needs you to " +
					"join them: open_program with \"writable\":true, \"share\":true",
				d);
		}
		if (e.mode != ProgramEntry.Mode.WRITABLE) {
			// D38/D66 (E2): a sealed project answers every writable command with the seal, not
			// with the read-only hint that it would have to repeat (a fork is the way out)
			Seals.requireNotSealed(c, e.project, cmd);
			throw new SessionException(SessionException.READ_ONLY,
				e.key + " is open read-only; " + cmd + " needs open_program with " +
					"\"writable\":true" + (e.project.writable() ? ""
							: " in a writable project (fork_project makes one)"),
				e.project.writable()
						? Json.of("program", e.key, "suggest", "open_program writable")
						: suggestFork(e.identity(), e.project, c));
		}
		if (e.owner != c) {
			throw notOwner(e, c, e.key + " is owned by " + e.ownerText() +
				"; only the owner may " + cmd + " (fork the project to write your own copy)");
		}
	}

	/** {@code not_owner}, naming the owner and suggesting a fork. */
	static SessionException notOwner(ProgramEntry e, Client c, String message) {
		JsonObject d = e.identity();
		Client o = e.owner;
		Json.put(d, "owner", o == null ? null : o.id);
		Json.put(d, "holder", o == null ? null : e.ownerText());
		d.add("holderInfo", e.ownerHolder());
		suggestFork(d, e.project, c);
		// to annotate the same program at the same time: an overlay; to keep the work: a fork
		JsonArray alt = new JsonArray();
		alt.add("overlay");
		alt.add("fork_project");
		d.add("alternatives", alt);
		d.add("overlaySuggestion", Json.of("cmd", "open_program", "path", e.key, "overlay",
			c.name.isEmpty() ? "client" + c.id : c.name.replaceAll("[^A-Za-z0-9_.@-]", "_")));
		return new SessionException(SessionException.NOT_OWNER, message, d);
	}
}
