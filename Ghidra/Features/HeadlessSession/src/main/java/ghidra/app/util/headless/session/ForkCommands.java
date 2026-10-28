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

import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Access.unlockProject;
import static ghidra.app.util.headless.session.Requests.cancelled;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import utilities.util.FileUtilities;

/**
 * {@code fork_project}: a working copy of a project, opened for the caller.
 */
final class ForkCommands {

	private final Session s;

	ForkCommands(Session s) {
		this.s = s;
		// E2a: the publish is atomic and retryable. The name is declared by Advertised (E1's file);
		// until it is, there is nothing to enable.
		if (Advertised.CAPABILITIES.contains("forkAtomic")) {
			Advertised.capability("forkAtomic", 1);
		}
	}

	/**
	 * {@code fork_project}: a working copy of a project, made with the platform's copy (a block
	 * clone on ReFS), opened for this client (writable by default) and registered like any other
	 * project. The source is only read: its read-only views stay open and in use. A source that
	 * someone writes (another client here, or another process through the project lock) is
	 * refused, because its saved state may change under the copy; a source this client alone holds
	 * writable is forked when nothing in it is unsaved, under its exclusive lock. The fork records
	 * its source and the source's revision in its sidecar ({@link ProjectFork}).
	 */
	JsonElement forkProject(Client c, JsonObject req, RequestMonitor m) {
		long t0 = System.nanoTime();
		String srcKey = Json.str(req, "project", c.activeProject);
		if (srcKey == null) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: project (an open project's id, or a project path)");
		}
		ProjectEntry src = s.projectsById.get(srcKey);
		ProjectResolver.Resolved r;
		String canonical;
		try {
			r = src != null ? src.resolved : ProjectResolver.resolve(srcKey);
			canonical = r.gpr().getCanonicalPath();
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		if (src == null) {
			src = s.projects.get(canonical);
		}
		if (src != null && src.closed) {
			src = null;
		}
		String mode = Json.str(req, "mode", "auto");
		if (!mode.equals("auto") && !mode.equals("copy-on-write") && !mode.equals("full")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"mode must be auto, copy-on-write or full");
		}
		boolean writable = Json.bool(req, "writable", true);
		long limit = Json.has(req, "maxCopyMb")
				? Json.num(req, "maxCopyMb", 0, 0, Long.MAX_VALUE >> 20) << 20
				: s.forkCopyLimitBytes;
		// the destination: a folder (the fork keeps the source's name, or "name"), or a .gpr path
		File dest = new File(Json.str(req, "path")).getAbsoluteFile();
		File destDir;
		String name;
		if (dest.getName().endsWith(ProjectLocator.getProjectExtension())) {
			destDir = dest.getParentFile();
			name = dest.getName()
					.substring(0,
						dest.getName().length() - ProjectLocator.getProjectExtension().length());
		}
		else {
			destDir = dest;
			name = Json.str(req, "name", r.name());
		}
		if (name.isEmpty() || !name.matches("[^\\\\/:*?\"<>|]+")) {
			throw new SessionException(SessionException.BAD_REQUEST, "bad project name: " + name);
		}
		File destGpr = new File(destDir, name + ProjectLocator.getProjectExtension());
		try {
			String srcDir = r.dir().getCanonicalPath();
			String rep = new File(r.dir(), r.name() + ProjectLocator.getProjectDirExtension())
					.getCanonicalPath();
			String dd = destDir.getCanonicalPath();
			if (dd.equals(srcDir) && name.equals(r.name()) ||
				(dd + File.separator).startsWith(rep + File.separator)) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"the fork must not be the source or inside its .rep: " + dest);
			}
		}
		catch (IOException e) {
			throw new SessionException(SessionException.BAD_REQUEST, e.getMessage());
		}
		String rk = c.v3() ? EditCommands.rkOf(req) : null;
		// the lazy sweep: what a dead publisher of this engine left here is removed first, so that
		// its half fork never answers a retry with a bare conflict (D41)
		ForkSweeper.sweepFor(destDir, name);
		String id = ProjectFork.newId();
		ForkSweeper.Claim claim;
		long giveUpAt = System.nanoTime() + waitMs(req) * 1_000_000L;
		while (true) {
			ForkSweeper.Admission a;
			try {
				a = ForkSweeper.admit(destDir, name, id, rk);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.BAD_REQUEST, e.getMessage());
			}
			if (a.kind() == ForkSweeper.Kind.CLAIMED) {
				claim = a.claim();
				break;
			}
			if (a.kind() == ForkSweeper.Kind.EXISTS) {
				JsonObject done = ProjectFork.readSidecar(
					new ProjectResolver.Resolved(destDir, name));
				if (rk != null && done != null && rk.equals(Json.str(done, "rk", null)) &&
					ProjectFork.STATE_COMPLETE.equals(Json.str(done, "state", null)) &&
					destGpr.exists() && done.has("source") &&
					canonical.equals(Json.str(done.getAsJsonObject("source"), "canonical", null))) {
					return replayed(c, req, done, destDir, name, destGpr, writable, t0);
				}
				throw existsConflict(c.v3(), name, destDir, destGpr, null);
			}
			// another request is publishing this destination
			if (rk != null && rk.equals(a.rk())) {
				// the same request again: wait for the winner and return its result
				long left = (giveUpAt - System.nanoTime()) / 1_000_000L;
				try {
					if (left > 0 && ForkSweeper.awaitIdle(destDir, name, left, m)) {
						continue;
					}
				}
				catch (CancelledException e) {
					throw cancelled(m);
				}
				catch (IOException e) {
					throw new SessionException(SessionException.FAILED, e.getMessage(), null, e);
				}
			}
			throw inProgress(destGpr, a.owner());
		}
		try {
			return forkClaimed(c, req, m, t0, r, src, canonical, mode, writable, limit, destDir,
				name, destGpr, id, rk);
		}
		finally {
			claim.release();
		}
	}

	/** The conflict for a destination that is already there. {@code reason} is null for none. */
	private static SessionException existsConflict(boolean v3, String name, File destDir,
			File destGpr, String reason) {
		JsonObject d = Json.of("path", destGpr.getPath(), "suggest", "another path");
		if (reason != null || v3) {
			// a protocol 2 reply to a request that did not race stays byte-identical
			Json.put(d, "reason", reason != null ? reason : "exists");
		}
		return new SessionException(SessionException.CONFLICT,
			"a project named " + name + " already exists in " + destDir +
				"; pick another path (forks are never overwritten)",
			d);
	}

	/** The conflict for a destination that another request is publishing right now (V11). */
	private static SessionException inProgress(File destGpr, JsonObject owner) {
		JsonObject d = Json.of("path", destGpr.getPath(), "reason", "fork_in_progress", "suggest",
			"retry");
		if (owner != null) {
			d.add("publisher", owner);
		}
		return new SessionException(SessionException.CONFLICT,
			"another request is publishing a fork to " + destGpr + " right now; it is not " +
				"disturbed. Retry after it finishes, or pick another path (with the same \"rk\" " +
				"a protocol 3 request waits for it and returns its result)",
			d);
	}

	/**
	 * The result for a request whose {@code rk} and destination are those of a fork that is
	 * already complete (a retry, or the loser of a race with the same key): the project is opened
	 * for this client and the answer is built from the fork's sidecar, with {@code replayed}.
	 */
	private JsonElement replayed(Client c, JsonObject req, JsonObject sc, File destDir,
			String name, File destGpr, boolean writable, long t0) {
		JsonObject open = Json.of("path", destGpr.getPath(), "writable", writable);
		if (req.has("wait")) {
			open.add("wait", req.get("wait"));
		}
		JsonObject info = (JsonObject) s.projectCmds.openProject(c, open);
		JsonObject out = Json.of("project", info.get("id"), "path", destDir.getPath(), "gpr",
			destGpr.getPath(), "name", name, "writable", writable);
		for (String k : List.of("source", "baseRevision", "mode", "method", "cloned", "clonedBy",
			"bytes", "files", "copyMs", "freeSpaceUsedBytes", "depth")) {
			if (sc.has(k)) {
				out.add(k, sc.get(k));
			}
		}
		out.addProperty("sidecar",
			ProjectFork.sidecar(new ProjectResolver.Resolved(destDir, name)).getPath());
		out.addProperty("ms", (System.nanoTime() - t0) / 1_000_000);
		out.addProperty("replayed", true);
		out.add("info", info);
		return out;
	}

	/**
	 * Everything after the destination is claimed: copy into staging, then publish. The staging
	 * folder is removed on every way out (it holds the intent record, and what is left of the
	 * copy after a successful publish).
	 */
	private JsonElement forkClaimed(Client c, JsonObject req, RequestMonitor m, long t0,
			ProjectResolver.Resolved r, ProjectEntry src, String canonical, String mode,
			boolean writable, long limit, File destDir, String name, File destGpr, String id,
			String rk) {
		java.util.concurrent.atomic.AtomicReference<ProjectFork.Staged> staging =
			new java.util.concurrent.atomic.AtomicReference<>();
		try {
			return forkStaged(c, req, m, t0, r, src, canonical, mode, writable, limit, destDir,
				name, destGpr, id, rk, staging);
		}
		finally {
			ProjectFork.Staged st = staging.get();
			ProjectFork.discard(st);
			if (st == null || !st.keep()) {
				ForkSweeper.removeStagingFolder(destDir, name, id);
			}
		}
	}

	private JsonElement forkStaged(Client c, JsonObject req, RequestMonitor m, long t0,
			ProjectResolver.Resolved r, ProjectEntry src, String canonical, String mode,
			boolean writable, long limit, File destDir, String name, File destGpr, String id,
			String rk, java.util.concurrent.atomic.AtomicReference<ProjectFork.Staged> staging) {
		ProjectLocator locator = new ProjectLocator(r.dir().getPath(), r.name());
		Lock held = null;
		ProjectFork.Cost cost;
		ProjectFork.Staged copied;
		String baseRevision;
		JsonObject parent = ProjectFork.readSidecar(r);
		try {
			if (src != null && src.writable()) {
				// in this daemon: forkable only by its sole user, with nothing unsaved
				JsonArray others = src.holders(c);
				if (!others.isEmpty()) {
					JsonObject d = src.identity();
					d.add("holders", others);
					Json.put(d, "suggest", "retry");
					throw new SessionException(SessionException.CONFLICT,
						"project " + src.id + " is open writable and used by another client; a " +
							"fork copies the saved state, which its writer may change meanwhile. " +
							"Fork a read-only master instead, or retry once its writer has " +
							"saved and left",
						d);
				}
				for (ProgramEntry e : src.programs.values()) {
					if (e.program != null && e.program.isChanged()) {
						throw new SessionException(SessionException.UNSAVED_CHANGES,
							e.key + " has unsaved changes; save before forking (a fork copies " +
								"what is saved)",
							e.identity());
					}
				}
				held = lockProject(src, true, waitMs(req), "fork_project");
				src.exclusiveClient = c;
			}
			else if (ProjectLocks.held(locator)) {
				JsonObject d = Json.of("gpr", r.gpr().getPath(), "name", r.name());
				d.add("holderInfo", ProjectLocks.holder(locator));
				Json.put(d, "suggest", "retry");
				throw new SessionException(SessionException.CONFLICT,
					"another process holds project " + r.name() + " writable (its lock file is " +
						"held); a fork copies the saved state, which that process may change " +
						"meanwhile. Retry once it has closed the project",
					d);
			}
			try {
				cost = ProjectFork.cost(r, destDir);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED, e.getMessage(), null, e);
			}
			JsonObject costJson = cost.json();
			Json.put(costJson, "limitBytes", limit);
			if (mode.equals("copy-on-write") && !cost.cloneCapable()) {
				Json.put(costJson, "reason", "no_copy_on_write");
				Json.put(costJson, "suggest", "mode full");
				throw new SessionException(SessionException.CONFLICT,
					"a copy-on-write fork needs the destination on the source's volume and a " +
						"file system that block-clones (ReFS on Windows); here it would be a " +
						"full copy of " + cost.bytes() + " bytes. Pass \"mode\":\"full\" to copy",
					costJson);
			}
			if (mode.equals("auto") && !cost.cloneCapable() && cost.bytes() > limit) {
				Json.put(costJson, "reason", "too_large");
				Json.put(costJson, "suggest", "mode full");
				throw new SessionException(SessionException.CONFLICT,
					"this fork would be a full copy of " + cost.bytes() + " bytes, over the " +
						"limit of " + limit + "; pass \"mode\":\"full\" to copy anyway, or fork " +
						"onto the source's volume where it can be block-cloned",
					costJson);
			}
			if (!cost.cloneCapable() && cost.bytes() > cost.destFreeBytes()) {
				throw new SessionException(SessionException.FAILED,
					"not enough free space for a full copy of " + cost.bytes() + " bytes",
					costJson);
			}
			try {
				Map<String, String> filesBefore = Revision.files(r);
				baseRevision = Revision.of(r);
				m.setMessage("forking " + r.name() + " (" + cost.files() + " files)");
				copied = ProjectFork.stage(r, destDir, name, id, rk, m);
				staging.set(copied);
				String after = Revision.of(r);
				if (!after.equals(baseRevision)) {
					List<String> changed = Revision.changed(filesBefore, Revision.files(r));
					JsonObject d = Json.of("gpr", r.gpr().getPath(), "suggest", "retry");
					Json.put(d, "changed", changed.subList(0, Math.min(20, changed.size())));
					throw new SessionException(SessionException.CONFLICT,
						"the source changed while it was copied (revision " + baseRevision +
							", now " + after + "); the copy was removed. Retry",
						d);
				}
			}
			catch (CancelledException e) {
				throw cancelled(m);
			}
			catch (IOException e) {
				throw new SessionException(SessionException.FAILED,
					"fork failed: " + e.getMessage(), null, e);
			}
		}
		finally {
			if (held != null) {
				unlockProject(src, held);
			}
		}
		// what the copy cost, and whether the measurement shows a clone
		// A clone uses almost no space, a copy its size; other writers on the volume blur the
		// measurement, so it only decides for a fork large enough to stand out.
		long consumed = Math.max(0, copied.freeBefore() - copied.freeAfter());
		boolean measurable = cost.bytes() >= ProjectFork.MEASURABLE_BYTES;
		boolean cloned = cost.cloneCapable() && (!measurable || consumed < cost.bytes() / 2);
		String clonedBy = !cost.cloneCapable() ? "file system (no block clone)"
				: measurable ? "free space (" + consumed + " of " + cost.bytes() + " bytes used)"
						: "file system (under " + (ProjectFork.MEASURABLE_BYTES >> 20) +
							" MiB: too small to measure)";
		ProjectResolver.Resolved fr = new ProjectResolver.Resolved(destDir, name);
		JsonObject source = Json.of("project", src == null ? null : src.id, "gpr",
			r.gpr().getPath(), "canonical", canonical, "name", r.name(), "revision", baseRevision,
			"writable", src != null && src.writable(), "fork", parent != null);
		int depth = parent == null ? 1
				: (parent.has("depth") ? parent.get("depth").getAsInt() : 1) + 1;
		JsonObject sidecar = Json.of("format", ProjectFork.SIDECAR_FORMAT, "kind",
			"ghidra-session-fork", "source", source, "baseRevision", baseRevision, "createdAt",
			System.currentTimeMillis(), "created", java.time.Instant.now().toString(), "by",
			c.identity(), "mode", mode, "method", cost.cloneCapable() ? "clone" : "copy",
			"cloned", cloned, "clonedBy", clonedBy, "bytes", cost.bytes(), "files",
			cost.files(), "copyMs", copied.ms(), "freeSpaceUsedBytes", consumed, "depth", depth,
			"parent", parent);
		if (rk != null) {
			sidecar.addProperty("rk", rk);
		}
		try {
			// the .rep, the sidecar "publishing", the .gpr (the commit point), the sidecar "complete"
			ProjectFork.publish(copied, destDir, name, sidecar, ProjectFork.STATE_COMPLETE);
		}
		catch (ProjectFork.RaceLost e) {
			throw existsConflict(c.v3(), name, destDir, destGpr, "exists");
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED, "fork failed: " + e.getMessage(),
				null, e);
		}
		Msg.info(s, c.label() + " forked " + r.gpr() + " (revision " + baseRevision + ") to " +
			destGpr + ": " + cost.bytes() + " bytes, " + cost.files() + " files, " +
			(cost.cloneCapable() ? "clone" : "copy") + " in " + copied.ms() + " ms, " + consumed +
			" bytes of free space used");
		JsonObject open = Json.of("path", destGpr.getPath(), "writable", writable);
		if (req.has("wait")) {
			open.add("wait", req.get("wait"));
		}
		JsonObject info = (JsonObject) s.projectCmds.openProject(c, open);
		JsonObject out = Json.of("project", info.get("id"), "path", destDir.getPath(), "gpr",
			destGpr.getPath(), "name", name, "writable", writable, "source", source,
			"baseRevision", baseRevision, "mode", mode, "method",
			cost.cloneCapable() ? "clone" : "copy", "cloned", cloned, "clonedBy", clonedBy,
			"bytes", cost.bytes(),
			"files", cost.files(), "copyMs", copied.ms(), "freeSpaceUsedBytes", consumed,
			"depth", depth, "sidecar", ProjectFork.sidecar(fr).getPath(), "ms",
			(System.nanoTime() - t0) / 1_000_000);
		out.add("info", info);
		return out;
	}
}
