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
import java.nio.file.Files;
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

	private static boolean registered;

	ForkCommands(Session s) {
		this.s = s;
		// E2a: the publish is atomic and retryable (the name is declared by Advertised)
		Advertised.capability("forkAtomic", 1);
		// E2: the fork report (cost, warnings, purpose), the backup manifest, the sealing command
		Advertised.capability("forkReport", 1);
		Advertised.capability("backup", 1);
		Advertised.capability("seal", 1);
		synchronized (ForkCommands.class) {
			if (!registered) {
				registered = true;
				// the request validation the command itself runs (3.5): one method, two callers
				Preflight.register("fork_project", ForkCommands::validate);
				// D42/A10: the daemon says which trees are writable disposable forks
				ghidra.framework.store.db.VersionFileCheck.setRepairPolicy(ProjectFork::repairable);
			}
		}
	}

	/** The purposes, verify levels and fields of a protocol 3 {@code fork_project} (3.4). */
	record Spec(String purpose, boolean open, String verify, String owner, String lineage,
			Long generation, Long base) {
		boolean backup() {
			return purpose.equals("backup");
		}

		boolean disposable() {
			return purpose.equals("fork") || purpose.equals("view");
		}

		/** The sidecar state a finished fork of this purpose ends in (D41). */
		String completeState() {
			return purpose.equals("generation") ? ProjectFork.STATE_CANDIDATE
					: ProjectFork.STATE_COMPLETE;
		}

		static final Spec V2 = new Spec("fork", true, "hash", null, null, null, null);
	}

	/**
	 * The validation of a protocol 3 {@code fork_project} request, run by the command and (through
	 * {@link Preflight}) by the scheduler before the request waits. Throws {@code bad_request}
	 * with {@code details:{field, allowed[]}} for a closed field.
	 */
	static void validate(String cmd, JsonObject req) {
		spec(req);
	}

	/** The fields of a request: read only on a protocol 3 connection (3.1), else the defaults. */
	static Spec specOf(Client c, JsonObject req) {
		return c.v3() ? spec(req) : Spec.V2;
	}

	/** Parses and checks the v3 fields; the one place that knows them. */
	static Spec spec(JsonObject req) {
		String purpose = Json.str(req, "purpose", "fork");
		if (!ProjectFork.PURPOSES.contains(purpose)) {
			throw SessionException.badRequest(true,
				"purpose must be one of " + ProjectFork.PURPOSES, "purpose", ProjectFork.PURPOSES);
		}
		String verify = Json.str(req, "verify", "hash");
		if (!List.of("none", "size", "hash").contains(verify)) {
			throw SessionException.badRequest(true, "verify must be none, size or hash", "verify",
				List.of("none", "size", "hash"));
		}
		boolean open = Json.bool(req, "open", true);
		if (purpose.equals("backup") && open) {
			throw SessionException.badRequest(true,
				"a backup is not registered as an open project: pass \"open\":false", "open",
				List.of("false"));
		}
		String owner = Json.str(req, "owner", null);
		if (purpose.equals("view") && (owner == null || owner.isBlank() || owner.length() > 128)) {
			throw SessionException.badRequest(true,
				"a view names the agent that owns it: \"owner\" (1 to 128 characters)", "owner",
				null);
		}
		return new Spec(purpose, open, verify, owner, Json.str(req, "lineage", null),
			Json.has(req, "generation") ? Json.num(req, "generation", 0, 0, 1L << 53) : null,
			Json.has(req, "base") ? Json.num(req, "base", 0, 0, 1L << 53) : null);
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
		ProjectFork.Steps steps = new ProjectFork.Steps();
		Spec spec = specOf(c, req); // before any work: a v3 request with a bad field fails here
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
		// 8.13: recorded before anything is staged, so a daemon start sweeps it after a kill
		ForkSweeper.registerParent(destDir);
		steps.mark("sweep");
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
				steps.mark("admit");
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
				name, destGpr, id, rk, steps);
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
		boolean register = specOf(c, req).open();
		JsonObject info = register ? (JsonObject) s.projectCmds.openProject(c, open) : null;
		JsonObject out = Json.of("project", info == null ? null : info.get("id"), "path",
			destDir.getPath(), "gpr", destGpr.getPath(), "name", name, "writable",
			register && writable);
		for (String k : List.of("source", "baseRevision", "mode", "method", "cloned", "clonedBy",
			"bytes", "files", "copyMs", "freeSpaceUsedBytes", "depth", "linked", "linkedBytes")) {
			if (sc.has(k)) {
				out.add(k, sc.get(k));
			}
		}
		out.addProperty("sidecar",
			ProjectFork.sidecar(new ProjectResolver.Resolved(destDir, name)).getPath());
		out.addProperty("ms", (System.nanoTime() - t0) / 1_000_000);
		out.addProperty("replayed", true);
		if (c.v3()) {
			for (String k : List.of("purpose", "state", "manifest")) {
				if (sc.has(k)) {
					out.add(k, sc.get(k));
				}
			}
		}
		if (info != null) {
			out.add("info", info);
		}
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
			String rk, ProjectFork.Steps steps) {
		java.util.concurrent.atomic.AtomicReference<ProjectFork.Staged> staging =
			new java.util.concurrent.atomic.AtomicReference<>();
		try {
			return forkStaged(c, req, m, t0, r, src, canonical, mode, writable, limit, destDir,
				name, destGpr, id, rk, staging, steps);
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
			String rk, java.util.concurrent.atomic.AtomicReference<ProjectFork.Staged> staging,
			ProjectFork.Steps steps) {
		Spec spec = specOf(c, req);
		ProjectLocator locator = new ProjectLocator(r.dir().getPath(), r.name());
		Lock held = null;
		ProjectFork.Cost cost;
		ProjectFork.Staged copied;
		String baseRevision;
		ProjectBackup.Verified verified = null;
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
				steps.mark("lock");
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
			// one walk of the source gives the cost, the revision and the copy; the check after
			// the copy walks it again, so a file added or changed meanwhile is still seen
			SortedMap<String, java.nio.file.Path> listing;
			try {
				listing = UpgradeCache.sourceFiles(r.gpr().toPath(), r.name());
				cost = ProjectFork.cost(r, destDir, listing);
				steps.mark("cost");
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
			// the stored database versions of a fork on the source's volume are hard links, not
			// copies (ProjectFork.stage): they cost no space and no copy time
			boolean link = !spec.backup() && cost.sameVolume() &&
				Settings.bool("forkHardLinks", true);
			long linkBytes = 0;
			if (link) {
				for (java.nio.file.Path p : listing.values()) {
					try {
						long size = Files.size(p);
						linkBytes += UpgradeCache.linkable(p, size) ? size : 0;
					}
					catch (IOException e) {
						// gone meanwhile: the copy and the revision check see it
					}
				}
			}
			long copyBytes = cost.bytes() - linkBytes;
			if (mode.equals("auto") && !cost.cloneCapable() && copyBytes > limit) {
				Json.put(costJson, "reason", "too_large");
				Json.put(costJson, "suggest", "mode full");
				throw new SessionException(SessionException.CONFLICT,
					"this fork would be a full copy of " + cost.bytes() + " bytes, over the " +
						"limit of " + limit + "; pass \"mode\":\"full\" to copy anyway, or fork " +
						"onto the source's volume where it can be block-cloned",
					costJson);
			}
			if (!cost.cloneCapable() && copyBytes > cost.destFreeBytes()) {
				throw new SessionException(SessionException.FAILED,
					"not enough free space for a full copy of " + cost.bytes() + " bytes",
					costJson);
			}
			try {
				Map<String, String> filesBefore = Revision.files(r, listing);
				baseRevision = Revision.of(r, listing);
				steps.mark("revision");
				m.setMessage("forking " + r.name() + " (" + cost.files() + " files)");
				copied = ProjectFork.stage(r, destDir, name, id, rk, m, listing, steps, link);
				staging.set(copied);
				if (spec.backup()) {
					// a backup is compared with its source after the copy (hash: every file of both
					// sides); a failed verify is a failed backup, and the staged copy is removed
					m.setMessage("verifying the backup of " + r.name() + " (" + spec.verify() + ")");
					verified = ProjectBackup.verifyCopy(r, copied.dir().toPath(), name,
						spec.verify(), m);
					if (!verified.ok()) {
						JsonArray mm = new JsonArray();
						verified.mismatches().forEach(mm::add);
						throw new SessionException(SessionException.FAILED,
							"the backup did not verify: " + mm.size() + " file(s) differ between " +
								"the copy and the source; the copy was removed and no backup.json " +
								"was written",
							Json.of("verify", Json.of("ok", false, "level", spec.verify(),
								"mismatches", mm)));
					}
					steps.mark("verify");
				}
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
				steps.mark("recheck");
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
			ProjectFork.SIDECAR_KIND, "purpose", spec.purpose(), "disposable", spec.disposable(),
			"source", source, "baseRevision", baseRevision, "createdAt",
			System.currentTimeMillis(), "created", java.time.Instant.now().toString(), "by",
			c.identity(), "mode", mode, "method", cost.cloneCapable() ? "clone" : "copy",
			"cloned", cloned, "clonedBy", clonedBy, "bytes", cost.bytes(), "files",
			cost.files(), "copyMs", copied.ms(), "freeSpaceUsedBytes", consumed, "depth", depth,
			"parent", parent);
		long linkedBytes = 0;
		for (java.nio.file.Path p : copied.linked().keySet()) {
			try {
				linkedBytes += Files.size(p);
			}
			catch (IOException e) {
				// removed with the fork meanwhile: only a figure for the report
			}
		}
		if (!copied.linked().isEmpty()) {
			// additive: the stored database versions are hard links to the source's, not copies
			sidecar.addProperty("linked", copied.linked().size());
			sidecar.addProperty("linkedBytes", linkedBytes);
		}
		if (rk != null) {
			sidecar.addProperty("rk", rk);
		}
		if (spec.purpose().equals("view")) {
			sidecar.addProperty("owner", spec.owner());
		}
		if (spec.lineage() != null) {
			sidecar.addProperty("lineage", spec.lineage());
		}
		if (spec.base() != null) {
			sidecar.addProperty("base", spec.base());
		}
		List<String> extras = List.of();
		JsonObject manifestReply = null;
		JsonObject marker = null;
		try {
			if (spec.backup()) {
				// the manifest and the seal marker are staged beside the project and move into
				// place before the .gpr, so that a published backup always has both (3.4)
				JsonObject manifest = backupManifest(c, req, r, src, name, spec, verified, cost,
					copied, baseRevision);
				String sha = ProjectBackup.write(copied.dir().toPath(), manifest);
				marker = Json.of("format", 1, "kind", "ghidra-session-seal", "name", name,
					"revision", baseRevision, "layoutSha256", Seals.layoutOf(verified.files()),
					"manifestSha256", sha, "sealedAt", java.time.Instant.now().toString(), "by",
					Json.of("client", c.name, "harness", c.harness));
				Files.writeString(copied.dir().toPath().resolve(Seals.MARKER),
					Json.GSON.toJson(marker), java.nio.charset.StandardCharsets.UTF_8);
				extras = List.of(ProjectBackup.FILE, Seals.MARKER);
				manifestReply = Json.of("path", new File(destDir, ProjectBackup.FILE).getPath(),
					"sha256", sha, "verified", true, "files", verified.files().size());
				sidecar.add("manifest", manifestReply);
			}
			// the .rep, the sidecar "publishing", the extras, the .gpr (the commit point), the
			// sidecar in its final state
			ProjectFork.publish(copied, destDir, name, sidecar, spec.completeState(), extras);
		}
		catch (ProjectFork.RaceLost e) {
			throw existsConflict(c.v3(), name, destDir, destGpr, "exists");
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED, "fork failed: " + e.getMessage(),
				null, e);
		}
		catch (IllegalArgumentException e) {
			throw new SessionException(SessionException.FAILED,
				"the backup manifest cannot be written: " + e.getMessage(), null, e);
		}
		if (marker != null) {
			ProjectBackup.freeze(new File(destDir, ProjectBackup.FILE).toPath());
			Seals.recordRegistry(fr, marker); // the third record of D66; best effort
		}
		steps.mark("seal");
		Msg.info(s, c.label() + " forked " + r.gpr() + " (revision " + baseRevision + ") to " +
			destGpr + ": " + cost.bytes() + " bytes, " + cost.files() + " files, " +
			(cost.cloneCapable() ? "clone" : "copy") + " in " + copied.ms() + " ms, " + consumed +
			" bytes of free space used, purpose " + spec.purpose() + "; steps: " + steps);
		JsonObject info = null;
		if (spec.open()) {
			JsonObject open = Json.of("path", destGpr.getPath(), "writable", writable);
			if (req.has("wait")) {
				open.add("wait", req.get("wait"));
			}
			info = (JsonObject) s.projectCmds.openProject(c, open);
			steps.mark("open");
		}
		JsonObject out = Json.of("project", info == null ? null : info.get("id"), "path",
			destDir.getPath(), "gpr", destGpr.getPath(), "name", name, "writable",
			info != null && writable, "source", source, "baseRevision", baseRevision, "mode", mode,
			"method", cost.cloneCapable() ? "clone" : "copy", "cloned", cloned, "clonedBy",
			clonedBy, "bytes", cost.bytes(), "files", cost.files(), "copyMs", copied.ms(),
			"freeSpaceUsedBytes", consumed, "depth", depth, "sidecar",
			ProjectFork.sidecar(fr).getPath(), "ms", (System.nanoTime() - t0) / 1_000_000);
		if (c.v3()) { // the fork report (conditional C7, 3.4): additive keys for a v3 client
			if (!copied.linked().isEmpty()) {
				out.addProperty("linked", copied.linked().size());
				out.addProperty("linkedBytes", linkedBytes);
			}
			out.addProperty("purpose", spec.purpose());
			out.add("cost", cost.json());
			out.add("warnings", warnings(spec, cost, copied));
			if (manifestReply != null) {
				out.add("manifest", manifestReply);
			}
			out.addProperty("sidecarState",
				copied.keep() ? ProjectFork.STATE_PUBLISHING : spec.completeState());
		}
		if (info != null) {
			out.add("info", info);
		}
		if (Settings.bool("forkTiming", false)) {
			// diagnostics, off by default: the reply of every client stays as it was
			out.add("stepsMs", steps.json());
		}
		return out;
	}

	/**
	 * What a client should know about the copy it got (3.4): a full copy is not a block clone, a
	 * clone on the same volume shares blocks with its source, and a fork whose sidecar could not
	 * be finished (a handle holder) is complete but still says {@code publishing} until the next
	 * sweep of its folder.
	 */
	private static JsonArray warnings(Spec spec, ProjectFork.Cost cost, ProjectFork.Staged copied) {
		JsonArray w = new JsonArray();
		if (!cost.cloneCapable() && !copied.linked().isEmpty()) {
			w.add(copied.linked().size() + " of " + cost.files() + " files (the stored database " +
				"versions) are hard links to the source's, which are never written in place; " +
				"the others are copies");
		}
		else if (!cost.cloneCapable()) {
			w.add("this is a full copy of " + cost.bytes() + " bytes in " + cost.files() +
				" files, not a block clone (source file system " + cost.sourceFs() +
				", destination " + cost.destFs() + (cost.sameVolume() ? ", one volume"
						: ", another volume") +
				"); forking onto a ReFS volume next to the source clones");
		}
		if (spec.backup()) {
			if (cost.cloneCapable()) {
				w.add("a block clone shares blocks with its source: it protects against a bad " +
					"commit, not against loss of the volume");
			}
			else if (cost.sameVolume()) {
				w.add("this backup is on the same volume as its source: it protects against a " +
					"bad commit, not against loss of the volume");
			}
		}
		if (copied.keep()) {
			w.add("the fork is complete (its .gpr is in place) but its sidecar still says " +
				"\"publishing\": something held the file; the next fork_project under this " +
				"folder finishes it");
		}
		return w;
	}

	/** The manifest {@code backup.json} of a verified backup (3.4), with its {@code selfSha256}. */
	private JsonObject backupManifest(Client c, JsonObject req, ProjectResolver.Resolved r,
			ProjectEntry src, String name, Spec spec, ProjectBackup.Verified verified,
			ProjectFork.Cost cost, ProjectFork.Staged copied, String baseRevision)
			throws IOException {
		JsonObject format = src != null ? ProjectFormat.of(src) : ProjectFormat.ofClosed(r);
		String id = Json.str(req, "id", null);
		if (id == null) {
			id = ProjectBackup.newId(baseRevision, Json.str(req, "reason", "backup"));
		}
		else if (!id.matches("[A-Za-z0-9._-]{1,128}")) {
			throw SessionException.badRequest(true, "id: letters, digits, . _ - (1 to 128)", "id",
				null);
		}
		JsonObject sourceJ = Json.of("gpr", r.gpr().getPath(), "name", r.name(), "revision",
			baseRevision);
		if (spec.lineage() != null) {
			sourceJ.addProperty("lineage", spec.lineage());
		}
		if (spec.generation() != null) {
			sourceJ.addProperty("generation", spec.generation());
		}
		JsonObject dbv = new JsonObject();
		if (DbVersions.program() >= 0) {
			dbv.addProperty("program", DbVersions.program());
		}
		if (DbVersions.dataTypes() != null) {
			dbv.addProperty("dataTypes", DbVersions.dataTypes());
		}
		JsonObject manifest = Json.of("format", ProjectBackup.FORMAT, "kind", ProjectBackup.KIND,
			"writer", "engine", "id", id, "purpose", Json.str(req, "reason", "backup"),
			"createdAt", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
					.toString(),
			"createdBy", Json.of("client", c.name, "harness", c.harness), "source", sourceJ,
			"engine", Json.of("hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
				ghidra.framework.Application.getApplicationVersion(), "dbVersions", dbv),
			"stored", ProjectFormat.stored(format));
		JsonArray files = new JsonArray();
		verified.files().forEach(f -> files.add(f.json()));
		manifest.add("files", files);
		manifest.addProperty("filesetSha256", ProjectBackup.filesetSha(verified.files()));
		manifest.add("copy",
			Json.of("method", cost.cloneCapable() ? "clone" : "copy", "sameVolume",
				cost.sameVolume(), "sourceFileSystem", cost.sourceFs(), "destinationFileSystem",
				cost.destFs(), "independent", !cost.sameVolume(), "ms", copied.ms()));
		manifest.add("verify", Json.of("level", spec.verify(), "ok", true, "at",
			java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString(),
			"sourceRevisionAfter", baseRevision));
		ProjectBackup.seal(manifest);
		return manifest;
	}
}
