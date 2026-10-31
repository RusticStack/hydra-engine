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

import static ghidra.app.util.headless.session.Access.PROGRAM_KEY;
import static ghidra.app.util.headless.session.Access.firstOf;
import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Access.notOwner;
import static ghidra.app.util.headless.session.Access.suggestFork;
import static ghidra.app.util.headless.session.Addresses.hex;
import static ghidra.app.util.headless.session.ProjectCommands.findFile;
import static ghidra.app.util.headless.session.Requests.cancelled;
import static ghidra.app.util.headless.session.Requests.waitMs;
import static ghidra.app.util.headless.session.Requests.waitsForCache;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import ghidra.app.decompiler.MappedProgramSnapshot;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * Opening, sharing and closing programs: {@code open_program},
 * {@code switch}, {@code close_program}, {@code programs} and {@code info},
 * and the program entries' life cycle (read-only, writable, shared, upgrade
 * cache copies).
 */
final class ProgramCommands {

	private final Session s;

	ProgramCommands(Session s) {
		this.s = s;
		// E2: the upgrade gate (3.4) is declared v2-visible, and its switch is a policy value
		Advertised.capability("upgradeGate", 1);
		Advertised.policy("requireBackupForUpgrade",
			() -> Settings.bool("requireBackupForUpgrade", true));
	}

	JsonElement openProgram(Client c, JsonObject req, RequestMonitor m) {
		String path = Json.str(req, "path");
		JsonObject scoped = req;
		java.util.regex.Matcher mk = PROGRAM_KEY.matcher(path);
		if (mk.matches()) {
			scoped = req.deepCopy();
			scoped.addProperty("project", mk.group(1));
			path = mk.group(2);
		}
		ProjectEntry p = s.access.projectFor(c, scoped);
		String target = path;
		return s.access.inProject(p, req, "open_program", x -> openProgramIn(c, x, target, req, m));
	}

	/** Held: the project's shared lock. */
	private JsonObject openProgramIn(Client c, ProjectEntry p, String name, JsonObject req,
			RequestMonitor m) {
		boolean writable = Json.bool(req, "writable", false);
		boolean share = Json.bool(req, "share", false);
		if (share && !writable) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"\"share\":true opens a program writable for several clients; it needs " +
					"\"writable\":true");
		}
		if (writable) {
			// D38/D66: a sealed project takes no writable path, whatever the sidecar says
			Seals.requireNotSealed(c, p, "open_program writable");
		}
		if (writable && !p.writable()) {
			JsonObject d = suggestFork(p.identity(), p, c);
			Json.put(d, "alternative", "open_project writable");
			throw new SessionException(SessionException.READ_ONLY,
				"project " + p.id + " is open read-only; send open_project with " +
					"\"writable\":true first (this takes the project lock), or fork_project " +
					"to write a working copy while others keep reading",
				d);
		}
		DomainFile df = findFile(p, name);
		if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
			// a program whose files another process holds reads as Unknown-File: busy, never a
			// client mistake; read again once the hold is gone (GATE10, A63)
			df = HeldFiles.recheck("open_program", df);
		}
		if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
			throw new SessionException(SessionException.BAD_REQUEST,
				df.getPathname() + " is not a program (" + df.getContentType() + ")");
		}
		String path = df.getPathname();
		long wait = waitMs(req);
		if (!writable && waitsForCache(req)) {
			awaitCacheCopy(p, df, m); // before any program lock: other opens are not held up
		}
		JsonObject joined = share ? null : joinOpen(c, p, path, writable, wait);
		if (joined != null) {
			return joined;
		}
		long deadline = System.currentTimeMillis() + wait;
		while (true) {
			ProgramEntry e = p.programs.computeIfAbsent(path, x -> new ProgramEntry(p, x));
			Lock l = e.acquire(true, Math.max(0, deadline - System.currentTimeMillis()), c,
				"open_program");
			boolean retry = false;
			try {
				if (p.programs.get(path) != e) {
					continue; // closed while we waited; open a fresh one
				}
				if (writable && e.mode == ProgramEntry.Mode.WRITABLE && e.owner != c &&
					e.owner.leaving) {
					// Its owner disconnected and its cleanup (cancel, discard) is still running:
					// that is a lock being released, so wait for it like one.
					if (System.currentTimeMillis() >= deadline) {
						JsonObject d = e.identity();
						Json.put(d, "holder", e.owner.label() + " (leaving)");
						JsonObject h = e.ownerHolder();
						Json.put(h, "leaving", true);
						d.add("holderInfo", h);
						Json.put(d, "suggest", "retry");
						throw new SessionException(SessionException.BUSY,
							path + " is being released by " + e.owner.label() +
								", which disconnected; retry, or pass a longer \"wait\"",
							d);
					}
					retry = true;
					continue;
				}
				long t0 = System.nanoTime();
				try {
					if (!writable && e.userCount() == 0 && swappable(e)) {
						// upgraded in memory, nobody uses it, and its cached copy is ready: switch
						e.disposeDecompilers();
						releaseProgramObject(e);
						e.mode = null;
						Msg.info(s, "switching " + e.key + " to its upgrade cache copy");
					}
					if (e.program == null) {
						e.file = df;
						e.program = writable ? openWritable(c, e, df, req, m) : openReadOnly(e, df, m);
						bindView(e, ProjectEntry.pinnedView(p));
						e.mode = !writable ? ProgramEntry.Mode.READ_ONLY
								: share ? ProgramEntry.Mode.SHARED : ProgramEntry.Mode.WRITABLE;
						e.stampRevision();
						e.setOwner(writable && !share ? c : null);
						e.ownedSince = System.currentTimeMillis();
						e.savedSeq = e.journal.seq();
						if (share) {
							addWriter(e, c);
						}
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
					else if (writable && e.mode == ProgramEntry.Mode.WRITABLE && e.owner != c) {
						throw notOwner(e, c, path + " is open writable by " + e.ownerText() +
							(share ? " in owner mode (owner mode and shared mode do not mix)" : "") +
							"; one writer per program: write in an overlay or a fork");
					}
					else if (writable && share && e.mode == ProgramEntry.Mode.WRITABLE) {
						// its owner opens it to others: owner mode becomes shared mode
						e.setOwner(null);
						e.mode = ProgramEntry.Mode.SHARED;
						addWriter(e, c);
					}
					else if (writable && e.mode == ProgramEntry.Mode.SHARED) {
						if (!share) {
							JsonObject d = e.identity();
							Json.put(d, "writers", e.writerIds());
							Json.put(d, "suggest", "share");
							throw new SessionException(SessionException.CONFLICT,
								path + " is open in shared mode; join it with \"writable\":true, " +
									"\"share\":true (owner mode and shared mode do not mix)",
								d);
						}
						addWriter(e, c);
					}
					else if (writable && e.mode == ProgramEntry.Mode.READ_ONLY) {
						Program np = openWritable(c, e, df, req, m);
						e.disposeDecompilers();
						releaseProgramObject(e);
						e.file = df;
						e.program = np;
						bindView(e, ProjectEntry.pinnedView(p));
						e.mode = share ? ProgramEntry.Mode.SHARED : ProgramEntry.Mode.WRITABLE;
						e.stampRevision();
						e.setOwner(share ? null : c);
						e.ownedSince = System.currentTimeMillis();
						e.savedSeq = e.journal.seq();
						if (share) {
							addWriter(e, c);
						}
						e.openMs = (System.nanoTime() - t0) / 1_000_000;
					}
				}
				catch (RuntimeException ex) {
					if (e.program == null) {
						p.programs.remove(path, e);
					}
					throw corruptNewest(c, p, e, ex);
				}
				JsonObject info = useProgram(c, e, e.openMs, true);
				if (c.v3()) {
					// D42: what the open repaired in this project (a quarantined newest version)
					JsonArray repairs = Seals.repairsSince(p.resolved, p.openedAt - 1000);
					if (!repairs.isEmpty()) {
						info.add("repairs", repairs);
					}
				}
				if (e.cacheBuildStarted) {
					e.cacheBuildStarted = false;
					Json.put(info, "cacheBuild", "started");
				}
				return info;
			}
			finally {
				e.release(l);
				if (retry) {
					sleepQuietly(50);
				}
			}
		}
	}

	/** Adds a writer to a shared program; a program kept for its orphaned work is adopted. */
	private static void addWriter(ProgramEntry e, Client c) {
		synchronized (e.users) {
			e.writers.add(c);
		}
		e.orphanedSince = 0;
	}

	private static void sleepQuietly(long ms) {
		try {
			Thread.sleep(ms);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Records that {@code c} uses {@code e} and makes it its active program.
	 *
	 * @param exclusive true when the caller holds the program's exclusive lock (the open path, which
	 *            may just have made {@code c} the owner or a writer); false for a join under the
	 *            shared lock (which changes nothing but the users)
	 */
	private JsonObject useProgram(Client c, ProgramEntry e, long openMs, boolean exclusive) {
		synchronized (e.users) {
			e.users.add(c);
		}
		if (c.leaving) {
			// the request of a client that is gone finished after its leave: it must not register
			// (the leave removes users without the program lock, E3c; the flag is set before it)
			if (exclusive && !c.programs.contains(e.key)) {
				// what this request set up for c (the program opened for it, c made its owner or a
				// shared writer) was not seen by the leave: undo it here as the leave would have done
				// (the owner and writers released, the program back to read-only for its other users
				// or disposed), so that no dead owner holds the program and no writer waits for it
				abandonOpen(c, e);
			}
			else {
				synchronized (e.users) {
					e.users.remove(c);
				}
			}
			throw new SessionException(SessionException.CANCELLED,
				c.label() + " is gone; " + e.key + " was not joined");
		}
		c.programs.add(e.key);
		c.active = e.key;
		c.activeProject = e.project.id;
		// the host's set-up for a program nobody can edit while it runs, in the background: the
		// first decompile then does not pay the store, the specs and the byte snapshot. A
		// writable program is left out: its bytes are about to change, and writing a snapshot of
		// them would hold its read lock against the edit (and be thrown away)
		if (e.program != null && e.mode == ProgramEntry.Mode.READ_ONLY) {
			HostDecompileBackend.warm(e.program);
		}
		JsonObject info = programInfo(e, c);
		Json.put(info, "openMs", openMs);
		return info;
	}

	/**
	 * The open of a client that is gone ended after its leave: its use of {@code e} is released the
	 * way its leave releases one ({@link #releaseUseHeld} with discard; the unsaved work of other
	 * shared writers is kept as orphaned work there). Held: the project's pin and the program's
	 * exclusive lock.
	 */
	private void abandonOpen(Client c, ProgramEntry e) {
		try {
			releaseUseHeld(c, e, true);
			Msg.info(s, c.label() + " is gone; its open of " + e.key + " was undone");
		}
		catch (RuntimeException ex) {
			Msg.error(s, c.label() + " is gone; could not undo its open of " + e.key, ex);
			synchronized (e.users) {
				e.users.remove(c);
				e.writers.remove(c);
			}
			if (e.owner == c) {
				e.setOwner(null);
			}
			c.programs.remove(e.key);
		}
	}

	/**
	 * Joins a program that is already open (also a warm one nobody uses) in a mode that fits,
	 * under the shared lock, so that a client can start using a program while others run long
	 * reads on it. Returns null when the exclusive path (open, upgrade) is needed.
	 */
	private JsonObject joinOpen(Client c, ProjectEntry p, String path, boolean writable,
			long wait) {
		ProgramEntry e = p.programs.get(path);
		if (e == null) {
			return null;
		}
		Lock l = e.acquire(false, wait, c, "open_program");
		try {
			if (p.programs.get(path) != e || e.program == null ||
				(writable && !(e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c)) ||
				(!writable && e.userCount() == 0 && swappable(e))) {
				return null;
			}
			boolean restarted = !writable && retryCacheBuild(e);
			JsonObject info = useProgram(c, e, 0, false);
			if (restarted) {
				Json.put(info, "cacheBuild", "started");
			}
			return info;
		}
		finally {
			e.release(l);
		}
	}

	/**
	 * True when {@code e} was upgraded in memory and its upgrade cache copy is now ready, so that
	 * an open with nobody using it can switch to the copy. Unlocked reads; callers recheck under
	 * the program's exclusive lock.
	 */
	boolean swappable(ProgramEntry e) {
		UpgradeCache.Plan plan = e.cachePlan;
		return plan != null && e.program != null && e.cacheView == null &&
			e.mode == ProgramEntry.Mode.READ_ONLY && s.upgradeCache.isReady(plan);
	}

	/**
	 * An open that joins a program upgraded in memory whose build failed (or was cancelled)
	 * starts a new one, with a fresh plan in case the source changed. Returns true when it
	 * started one. Held: the program's lock (shared is enough: the plan is only replaced by an
	 * equal or newer one).
	 */
	private boolean retryCacheBuild(ProgramEntry e) {
		UpgradeCache.Plan plan = e.cachePlan;
		if (plan == null || e.cacheView != null) {
			return false;
		}
		UpgradeCache.Build b = s.upgradeCache.build(plan);
		if (b == null ? s.upgradeCache.isReady(plan) : b.state != UpgradeCache.State.FAILED) {
			return false;
		}
		try {
			UpgradeCache.Plan fresh = s.upgradeCache.plan(e.project, e.file);
			if (fresh == null) {
				return false;
			}
			e.cachePlan = fresh;
			UpgradeCache.Start st = s.upgradeCache.startBuild(fresh);
			return st != null && st.started();
		}
		catch (IOException | RuntimeException ex) {
			Msg.warn(s, "upgrade cache: could not restart the build of " + e.key + ": " + ex);
			return false;
		}
	}

	/**
	 * {@code open_program} with {@code "wait": true}: when the program is in an older format and
	 * its upgrade cache copy is not ready, starts (or joins) its build and waits for it, so that
	 * the open is served from the copy. Holds no program lock while it waits.
	 */
	private void awaitCacheCopy(ProjectEntry p, DomainFile df, RequestMonitor m) {
		UpgradeCache.Plan plan;
		try {
			plan = s.upgradeCache.plan(p, df);
		}
		catch (IOException ex) {
			Msg.warn(s, "upgrade cache: cannot key " + df.getPathname() + ": " + ex);
			return;
		}
		if (plan == null || s.upgradeCache.isReady(plan)) {
			return;
		}
		UpgradeCache.Start st = s.upgradeCache.startBuild(plan);
		if (st == null) {
			return;
		}
		try {
			if (!s.upgradeCache.await(st.build(), m)) {
				Msg.warn(s, "upgrade cache: the build " + plan.id() + " that an open waited " +
					"for failed (" + st.build().error + "); upgrading in memory");
			}
		}
		catch (CancelledException ex) {
			throw cancelled(m);
		}
	}

	/**
	 * Opens a program read-only. A program saved in an older database format is served from its
	 * upgrade cache copy when that is ready (see {@link UpgradeCache}); otherwise it is upgraded
	 * in memory, as without the cache, and a background build of the copy is started for later
	 * opens. Held: its exclusive lock.
	 */
	Program openReadOnly(ProgramEntry e, DomainFile df, RequestMonitor m) {
		Program program = openReadOnlyProgram(e, df, m);
		attachSnapshotReads(e, program);
		return program;
	}

	private Program openReadOnlyProgram(ProgramEntry e, DomainFile df, RequestMonitor m) {
		try {
			UpgradeCache.Plan plan = null;
			try {
				plan = s.upgradeCache.plan(e.project, df);
			}
			catch (IOException ex) {
				Msg.warn(s, "upgrade cache: cannot key " + e.key + ": " + ex);
			}
			if (plan != null) {
				UpgradeCache.Opened c = null;
				try {
					c = s.upgradeCache.openReady(plan, e, m);
				}
				catch (IOException | VersionException ex) {
					Msg.warn(s, "upgrade cache: could not serve " + e.key + " from its copy, " +
						"opening the source (upgraded in memory): " + ex.getMessage(), ex);
				}
				if (c != null) {
					e.cacheView = c.view();
					e.cacheLease = c.lease();
					e.cacheInfo = c.info();
					e.cachePlan = plan;
					Msg.info(s, "opened " + e.key + " from the upgrade cache " + c.info());
					return c.program();
				}
			}
			Program program =
				(Program) df.getReadOnlyDomainObject(e, DomainFile.DEFAULT_VERSION, m);
			if (plan != null) {
				// after the in-memory upgrade, so that the build does not slow this answer
				e.cachePlan = plan;
				UpgradeCache.Start st = s.upgradeCache.startBuild(plan);
				e.cacheBuildStarted = st != null && st.started();
				Msg.info(s, "opened " + e.key + " upgraded in memory (" + plan.why() +
					"); upgrade cache build " + (st == null ? "not started (shutting down)"
							: st.started() ? "started" : st.build().state.json()));
			}
			return program;
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

	/**
	 * Opens a program for update. The upgrade gate (3.4, declared v2-visible, 5.1) runs first: an
	 * {@code upgrade:true} open of an older-format program of a project that is not a disposable
	 * fork is refused ({@code backup_required}; {@code conflict} with the reason on protocol 2)
	 * unless {@code backup} names a valid manifest; {@code requireBackupForUpgrade} switches it off.
	 */
	private Program openWritable(Client c, ProgramEntry e, DomainFile df, JsonObject req,
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
			boolean upgrade = Json.bool(req, "upgrade", false);
			ProjectBackup.UpgradeStamp stamp = upgrade ? upgradeGate(c, e, df, req) : null;
			UpgradeCache.Adopted adopted = null;
			e.adopted = null;
			if (upgrade && stamp == null) {
				// H2: a fork of a source the upgrade cache holds gets the upgraded version instead
				// of upgrading in memory (UpgradeCache.adoptForFork: disposable forks only)
				adopted = s.upgradeCache.adoptForFork(e.project, df, m);
			}
			Program program;
			try {
				program = (Program) df.getDomainObject(e, upgrade, false, m);
			}
			catch (IOException | VersionException | CancelledException | RuntimeException ex) {
				UpgradeCache.rollBack(adopted); // the fork as it was before the open
				throw ex;
			}
			if (adopted != null) {
				// opened as an in-memory upgrade leaves it: changed, nothing to undo
				try {
					UpgradeCache.markUpgraded(program);
				}
				catch (IOException | RuntimeException ex) {
					program.release(e);
					UpgradeCache.rollBack(adopted);
					throw ex;
				}
				e.adopted = adopted;
				Msg.info(s, "opened " + e.key + " of a fork from the upgrade cache's upgraded " +
					"version " + adopted.info());
			}
			if (stamp != null) {
				ProjectBackup.remember(e, stamp);
			}
			return program;
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

	/**
	 * The gate. Returns the stamp the next save puts in its comment when a valid backup opened the
	 * way, null when the open needs no backup; throws when it does and none is valid. A fork
	 * ({@code disposable}, D12) and a read-only open are exempt; so is the upgrade cache, which does
	 * not come through here.
	 */
	private ProjectBackup.UpgradeStamp upgradeGate(Client c, ProgramEntry e, DomainFile df,
			JsonObject req) {
		ProjectEntry p = e.project;
		if (!Settings.bool("requireBackupForUpgrade", true) ||
			ProjectFork.disposable(p.resolved)) {
			return null;
		}
		ProjectFormat.Need need = ProjectFormat.need(p.data(), df);
		if (!need.required()) {
			return null;
		}
		String backup = Json.str(req, "backup", null);
		// the project as it was opened and as it is on disk now: Ghidra rewrites the index backups
		// of a project when it opens it writable, which moves the revision before any program opens
		Set<String> revisions = new LinkedHashSet<>();
		if (p.openRevision != null) {
			revisions.add(p.openRevision);
		}
		try {
			revisions.add(Revision.of(p.resolved));
		}
		catch (IOException ex) {
			// the opened revision stands alone
		}
		ProjectBackup.Check chk = backup == null ? null : ProjectBackup.check(backup, revisions);
		if (chk != null && chk.ok()) {
			return new ProjectBackup.UpgradeStamp(chk.id(),
				need.unknown() ? -1 : need.stored().programDb());
		}
		JsonObject format = ProjectFormat.of(p);
		JsonObject d = Json.of("project", p.id, "program", e.key, "format", format, "suggest",
			"fork_project purpose backup");
		String why = need.unknown() ? "its format cannot be read (" + need.stored().error() + ")"
				: "saved by an older Ghidra (program database version " +
					need.stored().programDb() + ", this engine " + DbVersions.program() + ")";
		if (chk != null) {
			Json.put(d, "backup", backup);
			Json.put(d, "backupCheck", Json.of("reason", chk.reason(), "detail", chk.detail()));
		}
		String msg = df.getName() + " in " + p.resolved.dir() + " was " + why + "; upgrading it " +
			"is one-way and the project is not a disposable fork. Make a verified backup first " +
			"(fork_project with \"purpose\":\"backup\") and pass its backup.json as \"backup\"" +
			(chk == null ? "" : " (the backup offered was refused: " + chk.reason() + ": " +
				chk.detail() + ")");
		if (!c.v3()) {
			Json.put(d, "reason", "backup_required");
			return fail(new SessionException(SessionException.CONFLICT, msg, d));
		}
		return fail(new SessionException(SessionException.BACKUP_REQUIRED, msg, d)
				.withNext(Json.of("cmd", "fork_project", "project", p.id, "purpose", "backup",
					"open", false, "path", "<a folder for the backup>", "verify", "hash")));
	}

	private static ProjectBackup.UpgradeStamp fail(SessionException ex) {
		throw ex;
	}

	/**
	 * A failed open as the daemon reports it: an unrepaired corrupt newest version file
	 * ({@code corrupt_newest}, E8) is that code with {@code {project, program, file, repair}} on
	 * protocol 3 and stays {@code failed} on protocol 2; anything else is unchanged.
	 */
	private static RuntimeException corruptNewest(Client c, ProjectEntry p, ProgramEntry e,
			RuntimeException ex) {
		if (ex instanceof SessionException se && SessionException.FAILED.equals(se.code()) &&
			se.getCause() instanceof IOException io) {
			SessionException mapped = Seals.corruptNewest(c.v3(), io, p.id, e.key);
			if (mapped != null) {
				return mapped;
			}
		}
		return ex;
	}

	JsonElement programs(Client c) {
		JsonArray a = new JsonArray();
		List<String> mine;
		synchronized (c.programs) {
			mine = new ArrayList<>(c.programs);
		}
		for (String key : mine) {
			ProgramEntry e = s.access.entryByKey(key);
			if (e != null && e.program != null) {
				try {
					a.add(programInfo(e, c));
				}
				catch (RuntimeException ex) {
					// closed while we looked
				}
			}
		}
		return Json.of("activeProject", c.activeProject, "active", c.active, "programs", a);
	}

	JsonElement closeProgram(Client c, JsonObject req) {
		ProgramEntry e = s.access.selected(c, req);
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), "close_program");
		try {
			boolean discarded = releaseUse(c, e, Json.bool(req, "discard", false), waitMs(req));
			return Json.of("closed", e.key, "discarded", discarded, "active", c.active);
		}
		finally {
			pl.unlock();
		}
	}

	/**
	 * Drops one client's use of a program. When it owned the writable program, the program goes
	 * back to read-only for the other users, and unsaved changes are discarded only if
	 * {@code discard}. A read-only program nobody uses any more stays open (warm) for
	 * {@link #keepWarmMs}. Returns true when changes were discarded. Held: the project's lock.
	 */
	boolean releaseUse(Client c, ProgramEntry e, boolean discard, long wait) {
		if (leavesWithoutLock(c, e)) {
			return false;
		}
		if (c.leaving && e.holdsBy(c)) {
			// its own request ignored cancel and interrupt and still holds the lock: nothing to wait
			// for (3.5); the leave is finished when that request ends
			throw new SessionException(SessionException.BUSY,
				e.path + " is still held by a request of " + c.label() + ", which is gone");
		}
		Lock l = e.acquire(true, wait, c, "close_program");
		try {
			return releaseUseHeld(c, e, discard);
		}
		finally {
			e.release(l);
		}
	}

	/**
	 * The leave of a plain reader (E3c, D63b; the rev5 fast path of 3.5, built once): a client that is
	 * neither the owner nor a shared writer of the program and has no overlay on it has nothing to
	 * dispose, downgrade or discard, so it leaves by changing a counter and takes <b>no program
	 * lock</b>: no reader of the program, running or arriving, waits behind a leave (a queued
	 * exclusive on the fair lock refused every later reader for as long as the running reads lasted).
	 * The check and the removal are one step under {@code synchronized (e.users)}, so two
	 * concurrent leavers can never both conclude that the other remains. The last user is removed the
	 * same way; its program is then disposed (or kept warm) exactly as before, but only when the lock
	 * is free right now ({@link #disposeIdle}): otherwise it is left to the release of the lock that
	 * stood in the way and to the reap. Returns false when {@code c} is not a plain reader (the
	 * owner, writer, overlay holder and {@code discard} paths are unchanged).
	 */
	private boolean leavesWithoutLock(Client c, ProgramEntry e) {
		boolean last;
		synchronized (e.users) {
			if (!e.users.contains(c) || e.owner == c || e.writers.contains(c) ||
				hasOverlay(c, e)) {
				return false;
			}
			e.users.remove(c);
			last = e.users.isEmpty();
		}
		if (c.leaving && e.holdsBy(c)) {
			// its own request ignored cancel and interrupt and still holds the lock (3.5): it stays
			// listed as abandoned, and nobody waits for it
			e.markAbandoned(c);
		}
		c.programs.remove(e.key);
		if (e.key.equals(c.active)) {
			c.active = firstOf(c.programs);
		}
		if (last) {
			disposeIdle(e);
		}
		return true;
	}

	private boolean hasOverlay(Client c, ProgramEntry e) {
		for (Overlay o : s.overlayCmds.overlaysOf(e)) {
			if (o.client == c) {
				return true;
			}
		}
		return false;
	}

	/** True when a program whose last user left is to be disposed now rather than kept warm. */
	boolean disposeNow(ProgramEntry e) {
		return e.userCount() == 0 && !e.holdsOrphanedWork() && (e.program == null ||
			e.mode != ProgramEntry.Mode.READ_ONLY || s.keepWarmMs == 0 || e.project.closed);
	}

	/**
	 * The disposal of a program whose last user left, without waiting for anything (NB2): when it is
	 * to be disposed and its lock is free now it is disposed here, else {@link ProgramEntry#disposePending}
	 * is set and {@link Session#completeLeaves} finishes it when the lock that stood in the way is
	 * released (or at the next reap).
	 */
	void disposeIdle(ProgramEntry e) {
		if (!disposeNow(e)) {
			return;
		}
		e.disposePending = true;
		tryDisposeNow(e);
	}

	/** Disposes {@code e} if it is idle and both locks are free this instant. Never waits. */
	boolean tryDisposeNow(ProgramEntry e) {
		ProjectEntry p = e.project;
		ProjectEntry.Pin pin = p.tryPin();
		if (pin == null) {
			return false;
		}
		try {
			Lock wl = e.lock.writeLock();
			if (!wl.tryLock()) {
				return false;
			}
			try {
				if (p.programs.get(e.path) == e && disposeNow(e)) {
					disposeProgram(e);
					Msg.info(s, "closed idle program " + e.key + " (its last user left)");
				}
				e.disposePending = false;
				return true;
			}
			finally {
				wl.unlock();
			}
		}
		finally {
			pin.unlock();
		}
	}

	/**
	 * Records that {@code e}'s file and program come from {@code v} (one reference on it is held and
	 * the one held for the previous view is given back).
	 */
	void bindView(ProgramEntry e, ProjectEntry.View v) {
		ProjectEntry.View old = e.view;
		e.view = v;
		if (old != null) {
			old.release();
		}
	}

	/**
	 * The body of {@link #releaseUse}. Held: the project's lock (shared) and the program's
	 * exclusive lock, taken by the caller (the leave of a dead client that could not wait for them
	 * finishes here, {@link Session#completeLeaves}).
	 */
	boolean releaseUseHeld(Client c, ProgramEntry e, boolean discard) {
		s.overlayCmds.dropOverlays(c, e);
		boolean discarded = false;
		boolean others;
		synchronized (e.users) {
			others = e.users.stream().anyMatch(u -> u != c);
		}
		boolean downgrade = false;
		if (e.program != null && e.mode == ProgramEntry.Mode.SHARED && e.isWriter(c)) {
			boolean last;
			synchronized (e.users) {
				e.writers.remove(c);
				last = e.writers.isEmpty();
			}
			if (last && e.program.isChanged()) {
				if (c.leaving && !s.shuttingDown) {
					// a writer that died: the others' committed work is kept, unsaved,
					// until a client joins and saves or discards it
					e.orphanedSince = System.currentTimeMillis();
					Msg.warn(s, c.label() + " left " + e.key + " as its last shared " +
						"writer; its " + (e.journal.seq() - e.savedSeq) + " unsaved change(s) " +
						"are kept until a client saves or discards them");
				}
				else if (!discard) {
					synchronized (e.users) {
						e.writers.add(c);
					}
					throw new SessionException(SessionException.UNSAVED_CHANGES,
						e.path + " has unsaved changes and you are its last writer; send " +
							"save, or close with \"discard\":true (discards every writer's " +
							"unsaved changes)",
						Json.of("program", e.key, "unsavedEdits",
							e.journal.seq() - e.savedSeq));
				}
				else {
					discarded = true;
					downgrade = true;
				}
			}
			else if (last) {
				downgrade = true;
			}
		}
		if (e.program != null && e.mode == ProgramEntry.Mode.WRITABLE && e.owner == c) {
			if (e.program.isChanged()) {
				if (!discard) {
					throw new SessionException(SessionException.UNSAVED_CHANGES,
						e.path + " has unsaved changes; send save, or close with " +
							"\"discard\":true",
						Json.of("program", e.key));
				}
				discarded = true;
			}
			downgrade = true;
		}
		if (downgrade) {
			e.disposeDecompilers();
			releaseProgramObject(e); // releasing a changed program discards its changes
			e.setOwner(null);
			e.mode = null;
			if (others) {
				try {
					e.program = openReadOnly(e, e.file, new RequestMonitor(null, null));
					e.mode = ProgramEntry.Mode.READ_ONLY;
					e.stampRevision();
				}
				catch (RuntimeException ex) {
					Msg.error(s, "could not reopen " + e.key + " read-only for its " +
						"other users; closing it for everyone", ex);
					closeEntry(e);
					c.programs.remove(e.key);
					return discarded;
				}
			}
		}
		synchronized (e.users) {
			e.users.remove(c);
			others = !e.users.isEmpty();
		}
		if (!others && !e.holdsOrphanedWork() && (e.program == null ||
			e.mode != ProgramEntry.Mode.READ_ONLY || s.keepWarmMs == 0 || e.project.closed)) {
			disposeProgram(e);
		}
		c.programs.remove(e.key);
		if (e.key.equals(c.active)) {
			c.active = firstOf(c.programs);
		}
		return discarded;
	}

	/** Releases a program nobody uses. Held: its exclusive lock. */
	void disposeProgram(ProgramEntry e) {
		e.disposeDecompilers();
		releaseProgramObject(e);
		e.mode = null;
		e.setOwner(null);
		e.project.programs.remove(e.path, e);
		e.disposePending = false;
		e.reopenPendingSince = 0;
		ProjectEntry.View v = e.view;
		e.view = null;
		if (v != null) {
			v.release(); // the view closes when this was the last thing that used it
		}
	}

	/**
	 * Hydra ({@value MappedProgramSnapshot#ENABLE_PROPERTY}, default off):
	 * serve the byte reads of a program opened read-only from its memory-mapped sealed generation
	 * instead of the database buffers. The bytes are the same (the memory map drops the snapshot on
	 * any change); a program that gets none reads the database as before. Held: its exclusive lock.
	 * Called by every read-only open ({@link #openReadOnly}); undone by {@link #releaseProgramObject}.
	 */
	private void attachSnapshotReads(ProgramEntry e, Program program) {
		detachSnapshotReads(e);
		if (!MappedProgramSnapshot.isEnabled() || program == null) {
			return;
		}
		long t0 = System.nanoTime();
		e.snapshotReads = MappedProgramSnapshot.attach(program);
		if (e.snapshotReads != null) {
			Msg.info(s, "snapshot reads for " + e.key + " from " + e.snapshotReads.getPath() +
				" (generation " + e.snapshotReads.getGeneration() + ", " +
				(System.nanoTime() - t0) / 1_000_000 + " ms)");
		}
	}

	private static void detachSnapshotReads(ProgramEntry e) {
		MappedProgramSnapshot snap = e.snapshotReads;
		e.snapshotReads = null;
		if (snap != null) {
			snap.close();
		}
	}

	/**
	 * Releases {@link ProgramEntry#program} and, when it came from the upgrade cache, closes the
	 * view of the copy it came from. Held: its exclusive lock.
	 */
	void releaseProgramObject(ProgramEntry e) {
		detachSnapshotReads(e);
		// H2: a fork's adopted version (UpgradeCache.adoptForFork) released with its changes
		// unsaved goes with them, as an in-memory upgrade not saved would: the fork is put back
		UpgradeCache.Adopted adopted = e.adopted;
		e.adopted = null;
		boolean unsaved = adopted != null && e.program != null && e.program.isChanged();
		try {
			if (e.program != null) {
				e.program.release(e);
			}
		}
		finally {
			if (unsaved) {
				UpgradeCache.rollBack(adopted);
			}
			e.program = null;
			SessionProject view = e.cacheView;
			UpgradeCache.Lease lease = e.cacheLease;
			e.cacheView = null;
			e.cacheLease = null;
			e.cacheInfo = null;
			e.cachePlan = null;
			e.cacheBuildStarted = false;
			if (view != null) {
				try {
					view.close();
				}
				catch (RuntimeException ex) {
					Msg.warn(s, "could not close the upgrade cache view of " + e.key, ex);
				}
			}
			if (lease != null) {
				lease.release();
			}
		}
	}

	/** Closes a program for everyone. Held: its project's exclusive lock. */
	void closeEntry(ProgramEntry e) {
		boolean got = false;
		try {
			got = e.lock.writeLock().tryLock(Session.abandonWaitMs(), TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
		if (!got) {
			Msg.error(s, "could not close " + e.key + ": a request still holds it (" +
				e.exclusiveHolder + ")");
			return;
		}
		try {
			s.overlayCmds.dropOverlays(null, e);
			synchronized (e.users) {
				for (Client u : e.users) {
					u.programs.remove(e.key);
					if (e.key.equals(u.active)) {
						u.active = null;
					}
				}
				e.users.clear();
			}
			disposeProgram(e);
		}
		finally {
			e.lock.writeLock().unlock();
		}
	}

	JsonObject programInfo(ProgramEntry e, Client c) {
		Program p = e.program;
		JsonObject j = Json.of("key", e.key, "project", e.project.id, "path", e.path, "name",
			p.getName(), "mode", e.mode.json(), "owner", e.owner == null ? null : e.owner.id,
			"mine", e.owner == c, "active", e.key.equals(c.active), "language",
			p.getLanguageID().getIdAsString(), "compiler",
			p.getCompilerSpec().getCompilerSpecID().getIdAsString(), "imageBase",
			hex(p.getImageBase()), "format", p.getExecutableFormat(), "executable",
			p.getExecutablePath(), "sha256", p.getExecutableSHA256(), "md5",
			p.getExecutableMD5(), "functions", p.getFunctionManager().getFunctionCount(),
			"analyzed", GhidraProgramUtilities.isAnalyzed(p), "changed", p.isChanged(),
			"revision", e.revision, "projectRevision", e.project.revision(), "generation",
			e.project.generation, "cachedUpgrade", e.cacheInfo != null, "upgradeCache",
			e.cacheInfo == null ? null : e.cacheInfo.deepCopy(), "cacheBuild",
			e.cacheBuild(s.upgradeCache), "cacheBuildInfo", e.cacheBuildInfo(s.upgradeCache));
		synchronized (e.users) {
			List<Integer> ids = new ArrayList<>();
			e.users.forEach(u -> ids.add(u.id));
			Json.put(j, "users", ids);
		}
		List<String> mine = new ArrayList<>();
		for (Overlay o : s.overlayCmds.overlaysOf(e)) {
			if (o.client == c) {
				mine.add(o.name);
			}
		}
		Json.put(j, "overlays", mine);
		Json.put(j, "writers", e.writerIds());
		Json.put(j, "writer", e.isWriter(c));
		Json.put(j, "journalSeq", e.journal.seq());
		Json.put(j, "unsavedEdits", Math.max(0, e.journal.seq() - e.savedSeq));
		return j;
	}
}
