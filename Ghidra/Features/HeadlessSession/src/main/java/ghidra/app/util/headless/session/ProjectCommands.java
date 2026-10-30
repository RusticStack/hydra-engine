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

import static ghidra.app.util.headless.session.Access.firstOf;
import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Access.unlockProject;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import ghidra.framework.model.*;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.*;

/**
 * Opening, refreshing, listing and closing projects: {@code open_project},
 * {@code close_project}, {@code refresh}, {@code reopen} and {@code list}.
 */
final class ProjectCommands {

	private final Session s;

	ProjectCommands(Session s) {
		this.s = s;
		Advertised.capability("format", 1); // the format block of project and info (3.4)
	}

	/**
	 * Joins a project, opening it if no client has it open. A writable request on a read-only
	 * view reopens it writable in place, also while other clients use it ({@link #makeWritable});
	 * a writable request on a writable project, and a read-only request on one, join it.
	 */
	JsonElement openProject(Client c, JsonObject req) {
		ProjectResolver.Resolved r;
		String canonical;
		try {
			r = ProjectResolver.resolve(Json.str(req, "path"));
			canonical = r.gpr().getCanonicalPath();
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		boolean writable = Json.bool(req, "writable", false);
		boolean discard = Json.bool(req, "discard", false);
		long wait = waitMs(req);
		if (writable) {
			// D38/D66: a sealed project takes no writable path; opening it writable would already
			// take its lock and let Ghidra rewrite its index backups (measurement C)
			Seals.Status sealed = Seals.isSealed(r);
			if (sealed.sealed()) {
				ProjectEntry known = s.projects.get(canonical);
				throw Seals.refusal(c.v3(), known == null ? null : known.id, r, sealed,
					"open_project writable");
			}
		}
		long openedFrom = System.currentTimeMillis();
		ProjectEntry p;
		boolean opened = false;
		while (true) {
			if (s.shuttingDown) {
				throw new SessionException(SessionException.CONFLICT, "the session is shutting down");
			}
			// The project's life cycle is a state machine in ProjectRegistry (BP8): the first request
			// of a path opens it under that slot's own lock, followers wait for that lock (bounded and
			// cancel-aware) and find it OPEN. Only requests for this very project meet here.
			ProjectRegistry.Slot slot = s.registry.slot(canonical);
			Waits.Outcome slotGot = Waits.lock(slot.transition, wait, Waits.counter(slot));
			if (slotGot != Waits.Outcome.GOT) {
				throw slotBusy(c, r, slotGot == Waits.Outcome.QUEUE_FULL, Waits.counter(slot).get());
			}
			boolean reopen = false;
			try {
				if (s.registry.current(canonical) != slot) {
					continue; // closed or replaced while we waited for it
				}
				if (slot.state == ProjectRegistry.State.OPENING) {
					try {
						slot.entry = openProjectEntry(c, r, canonical, writable);
						slot.state = ProjectRegistry.State.OPEN;
						opened = true;
					}
					catch (RuntimeException ex) {
						s.registry.drop(slot);
						throw ex;
					}
				}
				p = slot.entry;
				if (p == null || p.closed || p.closing) {
					s.registry.drop(slot);
					continue;
				}
				if (writable && !p.writable()) {
					reopen = true;
				}
				else {
					synchronized (p.users) {
						p.users.add(c);
					}
					p.joinedAt.putIfAbsent(c, System.currentTimeMillis());
					c.seenGeneration.putIfAbsent(p.id, p.generation);
					c.projects.add(p.id);
					c.activeProject = p.id;
					p.lastUsed = System.currentTimeMillis();
					break;
				}
			}
			finally {
				slot.transition.unlock();
			}
			if (reopen) {
				// Readers keep using the view; it is reopened writable in place, same id, without
				// holding anything but the project's structure lock (BP7, BP8). The loop joins after.
				makeWritable(c, p, wait);
			}
		}
		JsonObject info = p.info(c);
		Json.put(info, "opened", opened);
		if (opened && c.v3()) {
			// D42: a newest version file quarantined while the project loaded (a disposable fork)
			JsonArray repairs = Seals.repairsSince(r, openedFrom - 1000);
			if (!repairs.isEmpty()) {
				info.add("repairs", repairs);
			}
		}
		return info;
	}

	/** The {@code busy} of a structure change (refresh, reopen writable) that could not start. */
	private static SessionException structureBusy(Client c, ProjectEntry p, boolean full,
			String what) {
		JsonObject d = p.identity();
		if (full && c.v3()) {
			Json.put(d, "waiters", Waits.counter(p.structure).get());
			Json.put(d, "waitersMax", Waits.cap(Caller.monitor()));
		}
		d = SessionException.busyDetails(c.v3(), d, full ? "lock_queue_full" : "lock_wait", null,
			null);
		SessionException ex = new SessionException(SessionException.BUSY,
			full ? "too many requests already wait to change project " + p.id + "; retry"
					: "project " + p.id + " " + what + "; retry",
			d);
		return c.v3() ? ex.withRetryAfterMs(1000) : ex;
	}

	/** The {@code busy} of a request that waited for another request's open or close of its project. */
	private static SessionException slotBusy(Client c, ProjectResolver.Resolved r, boolean full,
			int waiters) {
		JsonObject d = Json.of("gpr", r.gpr().getPath(), "name", r.name(), "suggest", "retry");
		if (full && c.v3()) {
			Json.put(d, "waiters", waiters);
			Json.put(d, "waitersMax", Waits.cap(Caller.monitor()));
		}
		d = SessionException.busyDetails(c.v3(), d, full ? "lock_queue_full" : "lock_wait", null,
			null);
		SessionException ex = new SessionException(SessionException.BUSY,
			full ? "too many requests already wait to open project " + r.name() + "; retry"
					: "project " + r.name() + " is being opened or closed by another request; " +
						"retry, or pass a longer \"wait\"",
			d);
		return c.v3() ? ex.withRetryAfterMs(1000) : ex;
	}

	/**
	 * {@code prepare_upgrade} (v3, BP21): finishes the upgrade-cache build of every older-format
	 * program of a project, so that the first fork or view of it does not wait for the 15 to 16.5 s
	 * of a first read-only open. Builds are single-flight per program ({@link UpgradeCache}): a
	 * concurrent call joins the running build. Writes only the upgrade cache, never the project.
	 */
	JsonElement prepareUpgrade(Client c, JsonObject req, RequestMonitor m) {
		if (!c.v3()) {
			throw new SessionException(SessionException.UNKNOWN_COMMAND,
				"unknown cmd 'prepare_upgrade'; it needs protocol 3 (send hello with " +
					"\"protocol\":3)");
		}
		ProjectEntry p = s.access.projectFor(c, req);
		return s.access.inProject(p, req, "prepare_upgrade", x -> s.upgradeCache.prepare(x, m));
	}

	/**
	 * Reopens a read-only view writable in place, while its clients keep using it (a repoint, not a
	 * drain, E3c/BP7): the project is opened writable (taking its OS lock) and becomes the current
	 * view; the programs clients use are reopened from it under the same key, read-only, with their
	 * overlays rebuilt, each as soon as its lock is free (never queueing for it); the read-only view
	 * closes when its last command and program let go. The id, the keys and the clients' joins
	 * stay. Held: {@link ProjectEntry#structure} only (not the project lock, not a registry). A close
	 * of the project cannot run meanwhile: {@link ProjectRegistry#closeIdle} needs {@code structure}
	 * too, so the {@code closed} check below and the repoint are one step against it.
	 */
	private void makeWritable(Client c, ProjectEntry p, long wait) {
		// one structure change per project at a time; a second opener that waited here finds it done
		Waits.Outcome got = Waits.lock(p.structure, wait, Waits.counter(p.structure));
		if (got != Waits.Outcome.GOT) {
			throw structureBusy(c, p, got == Waits.Outcome.QUEUE_FULL,
				"is being reopened writable by another request");
		}
		try {
			if (p.writable() || p.closed) {
				return;
			}
			reopenWritable(c, p, wait);
		}
		finally {
			p.structure.unlock();
		}
	}

	private void reopenWritable(Client c, ProjectEntry p, long wait) {
		ProjectLocator locator = new ProjectLocator(p.resolved.dir().getPath(), p.resolved.name());
		String rev;
		try {
			rev = Revision.of(p.resolved);
		}
		catch (IOException e) {
			rev = null;
		}
		SessionProject nv;
		try {
			nv = SessionProject.open(locator, true);
		}
		catch (LockException e) {
			JsonObject d = p.identity();
			Json.put(d, "lockFile", locator.getProjectLockFile().getPath());
			d.add("holderInfo", ProjectLocks.holder(locator));
			Json.put(d, "suggest", "open_read_only");
			throw new SessionException(SessionException.CONFLICT,
				"the project is locked by another process (a Ghidra window, analyzeHeadless or a " +
					"writable session): keep the read-only view, or close that process",
				d, e);
		}
		catch (NotOwnerException e) {
			throw new SessionException(SessionException.CONFLICT, e.getMessage());
		}
		catch (NotFoundException | IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage(), null, e);
		}
		JsonArray progs;
		try {
			progs = repointTo(p, nv, rev, new RequestMonitor(null, null));
		}
		catch (RuntimeException e) {
			nv.close();
			throw e;
		}
		Msg.info(s, c.label() + " reopened project " + p.id + " writable in place for " +
			p.userCount() + " client(s): " + progs);
	}

	/**
	 * Makes {@code nv} (from revision {@code rev}) the project's view and moves its programs over:
	 * each is reopened from it when its lock is free this instant, else marked for the moment it is
	 * (the readers it has keep reading what they have). The old view closes when nothing uses it.
	 * Held: {@link ProjectEntry#structure}.
	 */
	private JsonArray repointTo(ProjectEntry p, SessionProject nv, String rev, RequestMonitor m) {
		JsonArray progs = new JsonArray();
		ProjectEntry.View old = p.repoint(nv);
		p.previousRevision = p.openRevision;
		p.openRevision = rev;
		p.invalidateRevision();
		p.generation++;
		p.refreshedAt = System.currentTimeMillis();
		try {
			for (ProgramEntry e : new ArrayList<>(p.programs.values())) {
				progs.add(reopenIn(p, e, m, 0));
			}
		}
		finally {
			old.release(); // its current-view reference; commands and programs hold their own
		}
		return progs;
	}

	/** Held: the project's slot ({@link ProjectRegistry.Slot#transition}), state {@code OPENING}. */
	private ProjectEntry openProjectEntry(Client c, ProjectResolver.Resolved r, String canonical,
			boolean writable) {
		ProjectLocator locator;
		try {
			locator = new ProjectLocator(r.dir().getPath(), r.name());
		}
		catch (IllegalArgumentException e) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"Ghidra cannot open this path: " + e.getMessage());
		}
		long t0 = System.nanoTime();
		String revision;
		try {
			revision = Revision.of(r);
		}
		catch (IOException e) {
			revision = null;
		}
		SessionProject sp;
		try {
			sp = SessionProject.open(locator, writable);
		}
		catch (LockException e) {
			JsonObject d = Json.of("gpr", r.gpr().getPath(), "name", r.name(), "lockFile",
				locator.getProjectLockFile().getPath());
			d.add("holderInfo", ProjectLocks.holder(locator));
			Json.put(d, "suggest", "open_read_only");
			throw new SessionException(SessionException.CONFLICT,
				"the project is locked by another process (a Ghidra window, analyzeHeadless or a " +
					"writable session): open it read-only, or close that process",
				d, e);
		}
		catch (NotOwnerException e) {
			throw new SessionException(SessionException.CONFLICT, e.getMessage());
		}
		catch (NotFoundException | IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage(), null, e);
		}
		String id = "p" + s.nextProject.getAndIncrement();
		ProjectEntry p = new ProjectEntry(id, r, canonical, sp, (System.nanoTime() - t0) / 1_000_000);
		p.openRevision = revision;
		s.projects.put(canonical, p);
		s.projectsById.put(id, p);
		Msg.info(s, c.label() + " opened project " + id + " " + r.gpr() +
			(writable ? " (writable)" : " (read-only view)") + " in " + p.openMs + " ms");
		return p;
	}

	/**
	 * Closes a project for everyone. Held: the project's slot ({@link ProjectRegistry}, state
	 * {@code CLOSING}). Refused while a program has unsaved changes, unless {@code discard}. Takes the
	 * project lock exclusively, which is free of commands because nobody has joined the project.
	 */
	void closeProjectEntry(ProjectEntry p, long wait, boolean discard) {
		if (!discard) {
			for (ProgramEntry e : p.programs.values()) {
				if (e.program != null && e.program.isChanged()) {
					throw new SessionException(SessionException.UNSAVED_CHANGES,
						"cannot close project " + p.id + ": " + e.path +
							" has unsaved changes; save, or pass \"discard\":true",
						Json.of("program", e.key));
				}
			}
		}
		Lock l = lockProject(p, true, wait, "close_project");
		try {
			for (ProgramEntry e : new ArrayList<>(p.programs.values())) {
				if (e.program != null && e.program.isChanged()) {
					Msg.warn(s, "closing project " + p.id + ": discarding unsaved changes in " +
						e.path);
				}
				s.programCmds.closeEntry(e);
			}
			p.closed = true;
			p.closeViews();
		}
		finally {
			unlockProject(p, l);
			s.projects.remove(p.canonical, p);
			s.projectsById.remove(p.id, p);
			List<Client> users;
			synchronized (p.users) {
				users = new ArrayList<>(p.users);
				p.users.clear();
			}
			p.joinedAt.clear();
			for (Client u : users) {
				u.projects.remove(p.id);
				if (p.id.equals(u.activeProject)) {
					u.activeProject = firstOf(u.projects);
				}
			}
		}
	}

	JsonElement closeProject(Client c, JsonObject req) {
		ProjectEntry p = s.access.projectFor(c, req);
		boolean closed = leaveProject(c, p, Json.bool(req, "discard", false), waitMs(req));
		return Json.of("project", p.id, "left", true, "closed", closed, "activeProject",
			c.activeProject);
	}

	/**
	 * This client stops using a project: it closes its programs there (see
	 * {@link #releaseUse}), and the project closes when nobody uses it any more, at once when it
	 * is writable (its lock is released for other processes), after {@link #keepWarmMs} when it
	 * is a read-only view. Returns true when the project was closed.
	 */
	boolean leaveProject(Client c, ProjectEntry p, boolean discard, long wait) {
		List<String> mine;
		synchronized (c.programs) {
			mine = c.programs.stream().filter(k -> k.startsWith(p.id + ":")).toList();
		}
		// A client that is gone is released within one budget of `wait` for all its programs
		// (Session.disconnect passes abandonWaitS): what cannot be had in time is flagged abandoned
		// and finished later without waiting (ProgramEntry.pendingLeaves), never waited for 600 s.
		boolean dying = c.leaving;
		List<ProgramEntry> deferred = new ArrayList<>();
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(wait);
		for (String key : mine) {
			ProgramEntry e = p.programs.get(key.substring(p.id.length() + 1));
			if (e == null) {
				c.programs.remove(key);
				continue;
			}
			long w = dying ? Math.max(0, (end - System.nanoTime()) / 1_000_000L) : wait;
			Lock pl;
			try {
				pl = lockProject(p, false, w, "close_project");
			}
			catch (SessionException ex) {
				if (dying && SessionException.BUSY.equals(ex.code())) {
					deferLeave(c, e, ex);
					deferred.add(e);
					continue;
				}
				throw ex;
			}
			try {
				boolean discarded = false;
				try {
					discarded = s.programCmds.releaseUse(c, e, discard, w);
				}
				catch (SessionException ex) {
					if (dying && SessionException.BUSY.equals(ex.code())) {
						deferLeave(c, e, ex);
						deferred.add(e);
						continue;
					}
					throw ex;
				}
				if (discarded) {
					Msg.warn(s, c.label() + " left " + p.id + ": discarded unsaved changes in " +
						e.path);
				}
			}
			finally {
				pl.unlock();
			}
		}
		// the blocking holder may have released between the failed attempt and the registration
		// of the pending leave (then no release saw it): try once more, without waiting
		for (ProgramEntry e : deferred) {
			s.completeLeaves(e);
		}
		synchronized (p.users) {
			p.users.remove(c);
		}
		p.joinedAt.remove(c);
		c.seenGeneration.remove(p.id);
		c.projects.remove(p.id);
		if (p.id.equals(c.activeProject)) {
			c.activeProject = firstOf(c.projects);
		}
		p.lastUsed = System.currentTimeMillis();
		if (!p.closed && p.userCount() == 0 && (p.writable() || s.keepWarmMs == 0) &&
			p.programs.values().stream().noneMatch(ProgramEntry::holdsOrphanedWork) &&
			p.programs.values().stream().noneMatch(x -> !x.pendingLeaves.isEmpty())) {
			long w = dying ? Math.max(0, (end - System.nanoTime()) / 1_000_000L) : wait;
			// the slot's state machine decides (a join in flight keeps the project open); the one
			// exclusive project lock the close needs is taken under that slot's lock only (BP8)
			try {
				if (s.registry.closeIdle(p, x -> closeProjectEntry(x, w, true))) {
					return true;
				}
			}
			catch (SessionException ex) {
				// a request still runs in it (a dead client's, that ignored cancel): the reap
				// closes it once that request has ended, never after keepWarm only
				if (SessionException.BUSY.equals(ex.code())) {
					p.closePending = true;
				}
				throw ex;
			}
		}
		return false;
	}

	/**
	 * The exclusive leave of a dead client could not be had in time: its requests that still hold
	 * the program are flagged abandoned, the leave stays pending and its ownership bits stay until it
	 * is finished (they are guarded by the program lock, which this thread does not hold; 3.5).
	 */
	private void deferLeave(Client c, ProgramEntry e, SessionException why) {
		e.markAbandoned(c);
		e.pendingLeaves.add(c);
		Msg.warn(s, c.label() + " is gone and could not leave " + e.key + " in time (" +
			why.getMessage() + "); the leave is finished when the lock is free" +
			(e.holdsBy(c) ? ", its request " + "still running there is flagged abandoned" : ""));
	}

	/**
	 * {@code refresh} (or {@code reopen}): reopens a read-only view on what is saved now, without
	 * its clients leaving. The new view is opened first, outside every lock; then, under the
	 * project's exclusive lock (so that no request sees half of the switch), every program that
	 * clients use is reopened from it with the same key, programs nobody uses are closed, and the
	 * old view is closed. Programs the new revision no longer has are closed for their users.
	 * A writable project needs none (no other process can write it while this daemon holds its
	 * lock).
	 */
	JsonElement refresh(Client c, JsonObject req, RequestMonitor m) {
		ProjectEntry p = s.access.projectFor(c, req);
		long t0 = System.nanoTime();
		boolean force = Json.bool(req, "force", false);
		p.invalidateRevision();
		String disk = p.diskRevision();
		if (p.writable()) {
			return Json.of("project", p.id, "refreshed", false, "reason",
				"writable: this daemon holds the project lock, so it always shows what is saved",
				"revision", disk, "generation", p.generation);
		}
		String from = p.openRevision;
		if (!force && disk != null && disk.equals(from)) {
			c.seenGeneration.put(p.id, p.generation);
			return Json.of("project", p.id, "refreshed", false, "reason", "unchanged",
				"revision", from, "generation", p.generation);
		}
		String rev;
		SessionProject nv;
		try {
			rev = Revision.of(p.resolved);
			nv = SessionProject.open(new ProjectLocator(p.resolved.dir().getPath(),
				p.resolved.name()), false);
		}
		catch (Exception e) {
			throw new SessionException(SessionException.FAILED,
				"could not reopen project " + p.id + ": " + e.getMessage(), null, e);
		}
		// A refresh is a repoint (E3c, BP7): it does not take the project lock, so it cannot queue
		// behind running requests and refuse every later request of the project. One structure change
		// of a project at a time.
		JsonArray progs;
		Waits.Outcome got = Waits.lock(p.structure, waitMs(req), Waits.counter(p.structure));
		if (got != Waits.Outcome.GOT) {
			nv.close();
			throw structureBusy(c, p, got == Waits.Outcome.QUEUE_FULL,
				"is being refreshed or reopened by another request");
		}
		try {
			if (p.closed) {
				nv.close();
				throw new SessionException(SessionException.NO_PROJECT,
					"project " + p.id + " was closed", Json.of("project", p.id));
			}
			if (p.writable()) {
				nv.close(); // reopened writable while this waited: that view shows what is saved
				return Json.of("project", p.id, "refreshed", false, "reason",
					"writable: this daemon holds the project lock, so it always shows what is saved",
					"revision", p.diskRevision(), "generation", p.generation);
			}
			try {
				progs = repointTo(p, nv, rev, m);
			}
			catch (RuntimeException e) {
				nv.close();
				throw e;
			}
		}
		finally {
			p.structure.unlock();
		}
		c.seenGeneration.put(p.id, p.generation);
		Msg.info(s, c.label() + " refreshed project " + p.id + " from revision " + from +
			" to " + rev + " (generation " + p.generation + ")");
		JsonObject out = Json.of("project", p.id, "refreshed", true, "from", from, "revision",
			rev, "generation", p.generation, "programs", progs, "ms",
			(System.nanoTime() - t0) / 1_000_000);
		out.add("info", p.info(c));
		return out;
	}

	/**
	 * One program of a refreshed view: reopened from the new view when clients use it, closed
	 * otherwise. It never queues for the program's lock: when readers are running ({@code waitMs} 0,
	 * the barging {@code tryLock}) the program keeps what it has, is marked
	 * ({@link ProgramEntry#reopenPendingSince}) and is reopened by {@link #completeReopen} the moment
	 * its lock is free, so no reader is refused because a refresh is waiting (BP7). Held: the
	 * project's structure lock or the project pin of the caller.
	 *
	 * @param waitMs 0, or a short bounded queued wait (the reap's last resort for a program that
	 *            steady readers never leave free)
	 */
	private JsonObject reopenIn(ProjectEntry p, ProgramEntry e, RequestMonitor m, long waitMs) {
		JsonObject r = Json.of("program", e.key, "revision", e.revision);
		Lock wl = e.lock.writeLock();
		boolean got = waitMs <= 0 ? wl.tryLock() : Waits.tryLock(wl, waitMs);
		if (!got) {
			if (e.reopenPendingSince == 0) {
				e.reopenPendingSince = System.currentTimeMillis();
			}
			String why = e.exclusiveHolder != null ? e.exclusiveHolder
					: e.lock.getReadLockCount() + " reader(s)";
			Json.put(r, "action", "kept (still in use: " + why + "); reopened when it is free");
			return r;
		}
		boolean unlock = true;
		// the flag is cleared before the current view is read (both volatile): a refresh that repoints
		// after this read fails its tryLock (we hold the lock) and finds the flag clear, so it marks the
		// program again and it is reopened from that newer view; clearing it after the read could lose
		// that mark and leave the program on the retired view
		e.reopenPendingSince = 0;
		ProjectEntry.View nv = p.retainView();
		boolean bound = false;
		try {
			if (e.userCount() == 0) {
				s.programCmds.disposeProgram(e);
				Json.put(r, "action", "closed (nobody used it)");
				return r;
			}
			DomainFile df = nv.project.getProjectData().getFile(e.path);
			if (df == null || !Program.class.isAssignableFrom(df.getDomainObjectClass())) {
				e.lock.writeLock().unlock();
				unlock = false;
				s.programCmds.closeEntry(e);
				Json.put(r, "action", "removed (not in the new revision)");
				return r;
			}
			e.disposeDecompilers();
			s.programCmds.releaseProgramObject(e);
			e.mode = null;
			try {
				e.file = df;
				e.program = s.programCmds.openReadOnly(e, df, m);
				e.mode = ProgramEntry.Mode.READ_ONLY;
				s.programCmds.bindView(e, nv);
				bound = true;
				e.stampRevision();
				Json.put(r, "action", "reopened");
				Json.put(r, "newRevision", e.revision);
				s.overlayCmds.rebuildOverlays(e, m);
			}
			catch (RuntimeException ex) {
				Msg.error(s, "refresh: could not reopen " + e.key + "; closing it", ex);
				e.lock.writeLock().unlock();
				unlock = false;
				s.programCmds.closeEntry(e);
				Json.put(r, "action", "closed (reopen failed: " + ex.getMessage() + ")");
			}
			return r;
		}
		finally {
			if (!bound) {
				nv.release();
			}
			if (unlock) {
				e.lock.writeLock().unlock();
			}
		}
	}

	/**
	 * Finishes a reopen that a refresh could not do because readers were running ({@link
	 * ProgramEntry#reopenPendingSince}): called when the lock of the program is released and at the
	 * reap. Without waiting (the barging {@code tryLock}) unless {@code waitMs} is positive.
	 */
	void completeReopen(ProgramEntry e, long waitMs) {
		ProjectEntry p = e.project;
		if (e.reopenPendingSince == 0) {
			return;
		}
		ProjectEntry.Pin pin = p.tryPin();
		if (pin == null) {
			return;
		}
		try {
			if (p.programs.get(e.path) != e || p.closed) {
				e.reopenPendingSince = 0;
				return;
			}
			JsonObject r = reopenIn(p, e, new RequestMonitor(null, null), waitMs);
			if (e.reopenPendingSince == 0) {
				Msg.info(s, "refresh: " + e.key + " " + Json.str(r, "action", "?"));
			}
		}
		finally {
			pin.unlock();
		}
	}

	JsonElement list(ProjectEntry p, JsonObject req) {
		String path = Json.str(req, "folder", "/");
		boolean recursive = Json.bool(req, "recursive", true);
		boolean programsOnly = Json.bool(req, "programsOnly", false);
		boolean metadata = Json.bool(req, "metadata", true);
		String sha = Json.str(req, "sha256", null);
		Page page = new Page((int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE),
			(int) Json.num(req, "limit", 1000, 1, 100_000));
		ProjectData d = p.data();
		DomainFolder folder = path.equals("/") ? d.getRootFolder() : d.getFolder(path);
		if (folder == null) {
			throw new SessionException(SessionException.NOT_FOUND, "no such folder: " + path);
		}
		walk(p, folder, recursive, programsOnly || sha != null, metadata || sha != null, sha,
			page);
		return Json.of("project", p.id, "folder", folder.getPathname(), "entries", page.out,
			"offset", page.offset, "returned", page.out.size(), "truncated", page.more);
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
	private boolean walk(ProjectEntry p, DomainFolder folder, boolean recursive,
			boolean programsOnly, boolean metadata, String sha, Page page) {
		for (DomainFolder sub : folder.getFolders()) {
			if (!programsOnly &&
				page.offer(() -> Json.of("path", sub.getPathname(), "kind", "folder"))) {
				return true;
			}
			if (recursive && walk(p, sub, true, programsOnly, metadata, sha, page)) {
				return true;
			}
		}
		for (DomainFile f : folder.getFiles()) {
			boolean isProgram = Program.class.isAssignableFrom(f.getDomainObjectClass());
			if (programsOnly && !isProgram) {
				continue;
			}
			if (sha != null && !sha.equalsIgnoreCase(f.getMetadata().get("Executable SHA256"))) {
				continue;
			}
			if (page.offer(() -> describeFile(p, f, isProgram, metadata))) {
				return true;
			}
		}
		return false;
	}

	private JsonObject describeFile(ProjectEntry p, DomainFile f, boolean isProgram,
			boolean metadata) {
		JsonObject e = Json.of("path", f.getPathname(), "key", p.id + ":" + f.getPathname(),
			"kind", "file", "name", f.getName(), "contentType", f.getContentType(), "program",
			isProgram, "versioned", f.isVersioned(), "readOnly",
			f.isReadOnly() || !f.isInWritableProject());
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
			Json.put(e, "format", md.get("Executable Format"));
			Json.put(e, "executable", md.get("Executable Location"));
		}
		ProgramEntry pe = p.programs.get(f.getPathname());
		Json.put(e, "open", pe == null ? null : pe.describeUse(s.upgradeCache));
		return e;
	}

	/**
	 * Finds a file by project path, or by bare name when it is unique in the project (the way
	 * {@code -process name} is used).
	 */
	static DomainFile findFile(ProjectEntry p, String path) {
		ProjectData d = p.data();
		if (path.startsWith("/")) {
			DomainFile f = d.getFile(path);
			if (f == null) {
				// dropped while another process held its files (GATE10, A63)? busy, or listed again
				int slash = path.lastIndexOf('/');
				f = HeldFiles.recheckMissing("find " + path, d,
					slash == 0 ? "/" : path.substring(0, slash), path.substring(slash + 1));
			}
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no such file in project " + p.id + ": " + path);
			}
			return f;
		}
		List<DomainFile> found = new ArrayList<>();
		collectByName(d.getRootFolder(), path, found);
		if (found.isEmpty() && !path.contains("/")) {
			// a bare name dropped from the root folder while it was held (GATE10, A63)
			DomainFile f = HeldFiles.recheckMissing("find " + path, d, "/", path);
			if (f != null) {
				found.add(f);
			}
		}
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"no file named " + path + " in project " + p.id);
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
}
