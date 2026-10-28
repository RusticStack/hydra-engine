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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import com.google.gson.*;

import ghidra.framework.model.ProjectLocator;
import ghidra.framework.store.db.VersionFileCheck;
import ghidra.util.Msg;

/**
 * Sealing (PROTOCOL-3.md D38 and D66, package E2): the one predicate {@link #isSealed} that says
 * whether a project refuses every writable path, and the command {@code seal_project}.
 * <p>
 * <b>The predicate is the union of three records</b>, so that a torn, hand-edited or lost sidecar
 * cannot unseal a project: (1) the registry {@code <stateDir>/seals/<hash of the .gpr path>.json}
 * (the path and the {@code Revision} it was sealed at), (2) the sidecar of purpose
 * {@code generation} or {@code backup} with {@code state:"complete"}, (3) the marker
 * {@code SEALED.json} in the project's folder. {@code disposable:false} alone is <b>not</b>
 * sealed: it only makes a project non-disposable for the upgrade gate (D12). A project with no
 * sidecar and no record is not sealed (legacy in-place use is unchanged). This is an accident
 * guard, not a security boundary: every record is an ordinary file a local process can edit.
 * <p>
 * A marker that does not belong to the project (copied from another one) is ignored: it carries
 * the {@code layoutSha256} of the sealed project's files (their names and sizes) and its name,
 * and a marker written by another writer without a layout (Hydralysis on hydra.2/3) must carry
 * the project's current {@code Revision}.
 */
final class Seals {

	/** The error code of a refused writable path on a protocol 3 connection (3.13). */
	static final String SEALED = "sealed";
	/** The error code of an unrepaired corrupt newest version file on protocol 3 (D42). */
	static final String CORRUPT_NEWEST = "corrupt_newest";
	/** The marker file in the project folder. */
	static final String MARKER = "SEALED.json";

	private Seals() {
	}

	/** Why a project is sealed: {@code sealed} and the records that say so. */
	record Status(boolean sealed, List<String> witnesses) {
		JsonObject json() {
			return Json.of("sealed", sealed, "witnesses", witnesses);
		}
	}

	private static File registryDir() {
		JsonObject paths = Identity.paths();
		String state = Json.str(paths, "stateDir", null);
		return state == null ? null : new File(state, "seals");
	}

	private static File registryFile(File dir, ProjectResolver.Resolved r) throws IOException {
		return new File(dir, ProjectBackup.sha256Hex(
			r.gpr().getCanonicalPath().getBytes(StandardCharsets.UTF_8)).substring(0, 24) + ".json");
	}

	/** The predicate of D38/D66: the union of the registry record, the sidecar and the marker. */
	static Status isSealed(ProjectResolver.Resolved r) {
		List<String> w = new ArrayList<>();
		try {
			File dir = registryDir();
			if (dir != null) {
				File f = registryFile(dir, r);
				JsonObject rec = readJson(f);
				if (rec != null && r.gpr().getCanonicalPath().equals(Json.str(rec, "path", null))) {
					w.add("registry");
				}
			}
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(Seals.class, "seal registry unreadable for " + r.gpr() + ": " + e);
		}
		JsonObject sc = ProjectFork.readSidecar(r);
		if (sc != null) {
			String purpose = Json.str(sc, "purpose", null);
			if (("generation".equals(purpose) || "backup".equals(purpose)) &&
				ProjectFork.STATE_COMPLETE.equals(Json.str(sc, "state", null))) {
				w.add("sidecar");
			}
		}
		if (markerValid(r)) {
			w.add("marker");
		}
		return new Status(!w.isEmpty(), w);
	}

	static Status isSealed(ProjectEntry p) {
		return isSealed(p.resolved);
	}

	private static boolean markerValid(ProjectResolver.Resolved r) {
		File mf = new File(r.dir(), MARKER);
		if (!mf.isFile()) {
			return false;
		}
		JsonObject m = readJson(mf);
		if (m == null) {
			return false;
		}
		try {
			String name = Json.str(m, "name", null);
			if (name != null && !name.equals(r.name())) {
				return false; // another project's marker
			}
			String layout = Json.str(m, "layoutSha256", null);
			if (layout != null) {
				return layout.equals(layoutSha(r));
			}
			String rev = Json.str(m, "revision", null);
			return rev != null && rev.equals(Revision.of(r));
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	/**
	 * The names and sizes of every file of the project (the {@code .gpr} and the {@code .rep},
	 * without Ghidra's transient files and {@code projectState}), hashed: cheap to recompute, and
	 * equal for a project and an untouched copy of it, different for another project.
	 */
	static String layoutSha(ProjectResolver.Resolved r) throws IOException {
		String state = r.name() + ".rep/projectState";
		SortedMap<String, Long> sizes = new TreeMap<>();
		for (Map.Entry<String, Path> f : UpgradeCache.sourceFiles(r.gpr().toPath(), r.name())
				.entrySet()) {
			if (!f.getKey().equals(state)) {
				sizes.put(f.getKey(), Files.size(f.getValue()));
			}
		}
		return layoutOf(sizes);
	}

	/** The layout hash of a backup's files (named for the destination, as the manifest lists them). */
	static String layoutOf(List<ProjectBackup.FileEntry> files) {
		SortedMap<String, Long> sizes = new TreeMap<>();
		for (ProjectBackup.FileEntry f : files) {
			if (!f.path().endsWith(".rep/projectState")) {
				sizes.put(f.path(), f.size());
			}
		}
		return layoutOf(sizes);
	}

	private static String layoutOf(SortedMap<String, Long> sizes) {
		MessageDigest md = ProjectBackup.sha256();
		sizes.forEach((k, v) -> md.update((k + "|" + v + "\n").getBytes(StandardCharsets.UTF_8)));
		return HexFormat.of().formatHex(md.digest());
	}

	/** Writes the registry record of D66 for a marker; best effort (no state directory: none). */
	static void recordRegistry(ProjectResolver.Resolved r, JsonObject marker) {
		try {
			File dir = registryDir();
			if (dir == null) {
				return;
			}
			Files.createDirectories(dir.toPath());
			JsonObject rec = marker.deepCopy();
			Json.put(rec, "path", r.gpr().getCanonicalPath());
			writeJson(registryFile(dir, r), rec);
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(Seals.class,
				"could not record the seal of " + r.gpr() + " in the registry: " + e);
		}
	}

	/** The refusal of a writable path on a sealed project; v2 gets {@code conflict}. */
	static SessionException refusal(Client c, ProjectEntry p, Status st, String what) {
		return refusal(c.v3(), p.id, p.resolved, st, what);
	}

	static SessionException refusal(boolean v3, String projectId, ProjectResolver.Resolved r,
			Status st, String what) {
		JsonObject d = Json.of("project", projectId, "gpr", r.gpr().getPath(), "witnesses",
			st.witnesses());
		Json.put(d, "suggest", "fork_project");
		JsonObject next = Json.of("cmd", "fork_project", "project",
			projectId != null ? projectId : r.gpr().getPath(), "writable", true, "path",
			new File(r.dir().getParentFile() == null ? r.dir() : r.dir().getParentFile(),
				r.dir().getName() + "-fork").getPath());
		String msg = r.name() + " is sealed (" + String.join(", ", st.witnesses()) + "): it is " +
			"a verified generation or backup, or was sealed with seal_project, and takes no " +
			"writable path (" + what + "); fork_project makes a copy that can be written";
		if (v3) {
			return new SessionException(SEALED, msg, d).withNext(next);
		}
		Json.put(d, "reason", "sealed");
		d.add("suggestion", next);
		return new SessionException(SessionException.CONFLICT, msg, d);
	}

	/** Throws the refusal when the project is sealed. */
	static void requireNotSealed(Client c, ProjectEntry p, String what) {
		Status st = isSealed(p);
		if (st.sealed()) {
			throw refusal(c, p, st, what);
		}
	}

	// ---- seal_project --------------------------------------------------------------------------

	/**
	 * {@code seal_project}: records the seal in the registry, the marker and (for a generation or
	 * backup sidecar) {@code state:"complete"}; with {@code unseal:true, force:true} removes all
	 * three. Refuses a project that is open writable (here or by another process).
	 */
	static JsonElement sealProject(Session s, Client c, JsonObject req) {
		if (!c.v3()) {
			throw new SessionException(SessionException.UNKNOWN_COMMAND,
				"unknown cmd 'seal_project'; it needs protocol 3 (send hello with \"protocol\":3)");
		}
		String key = Json.str(req, "project", c.activeProject);
		if (key == null) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: project (an open project's id, or a project path)");
		}
		ProjectEntry open = s.projectsById.get(key);
		ProjectResolver.Resolved r;
		try {
			r = open != null ? open.resolved : ProjectResolver.resolve(key);
			if (open == null) {
				open = s.projects.get(r.gpr().getCanonicalPath());
			}
		}
		catch (IOException e) {
			throw new SessionException(SessionException.NOT_FOUND, e.getMessage());
		}
		boolean unseal = Json.bool(req, "unseal", false);
		if (unseal && !Json.bool(req, "force", false)) {
			throw SessionException.badRequest(true,
				"unseal is an owner action; pass \"force\":true", "force", null);
		}
		if (open != null && !open.closed && open.writable()) {
			throw new SessionException(SessionException.CONFLICT,
				"project " + open.id + " is open writable; close it before sealing it (the seal " +
					"is the commit point of its immutability)",
				Json.of("project", open.id, "reason", "open_writable"));
		}
		ProjectLocator loc = new ProjectLocator(r.dir().getPath(), r.name());
		if (ProjectLocks.held(loc)) {
			throw new SessionException(SessionException.CONFLICT,
				"another process holds project " + r.name() + " writable (its lock file is held)",
				Json.of("gpr", r.gpr().getPath(), "reason", "open_writable_elsewhere"));
		}
		try {
			return unseal ? unseal(c, r) : seal(c, r, req);
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED, "seal_project: " + e.getMessage(),
				null, e);
		}
	}

	private static JsonElement seal(Client c, ProjectResolver.Resolved r, JsonObject req)
			throws IOException {
		String revision = Revision.of(r);
		JsonObject marker = Json.of("format", 1, "kind", "ghidra-session-seal", "name", r.name(),
			"revision", revision, "layoutSha256", layoutSha(r), "sealedAt",
			Instant.now().toString(), "by", Json.of("client", c.name, "harness", c.harness));
		if (Json.has(req, "manifestSha256")) {
			Json.put(marker, "manifestSha256", Json.str(req, "manifestSha256"));
		}
		if (Json.has(req, "lineage")) {
			Json.put(marker, "lineage", Json.str(req, "lineage"));
		}
		writeMarker(r, marker);
		List<String> done = new ArrayList<>(List.of("marker"));
		if (registryDir() != null) {
			recordRegistry(r, marker);
			done.add("registry");
		}
		JsonObject sc = ProjectFork.readSidecar(r);
		if (sc != null) {
			String purpose = Json.str(sc, "purpose", null);
			if ("generation".equals(purpose) || "backup".equals(purpose)) {
				sc.addProperty("state", ProjectFork.STATE_COMPLETE);
				ProjectFork.writeSidecar(ProjectFork.sidecar(r), sc);
				done.add("sidecar");
			}
		}
		Msg.info(Seals.class, c.label() + " sealed " + r.gpr() + " at revision " + revision + " (" +
			done + ")");
		return Json.of("sealed", true, "revision", revision, "gpr", r.gpr().getPath(),
			"records", done, "witnesses", isSealed(r).witnesses());
	}

	private static JsonElement unseal(Client c, ProjectResolver.Resolved r) throws IOException {
		List<String> removed = new ArrayList<>();
		File dir = registryDir();
		if (dir != null && Files.deleteIfExists(registryFile(dir, r).toPath())) {
			removed.add("registry");
		}
		if (Files.deleteIfExists(new File(r.dir(), MARKER).toPath())) {
			removed.add("marker");
		}
		JsonObject sc = ProjectFork.readSidecar(r);
		if (sc != null && ProjectFork.STATE_COMPLETE.equals(Json.str(sc, "state", null))) {
			String purpose = Json.str(sc, "purpose", null);
			if ("generation".equals(purpose) || "backup".equals(purpose)) {
				sc.addProperty("state", ProjectFork.STATE_CANDIDATE);
				ProjectFork.writeSidecar(ProjectFork.sidecar(r), sc);
				removed.add("sidecar");
			}
		}
		Msg.warn(Seals.class, c.label() + " UNSEALED " + r.gpr() + " (owner action): " + removed);
		return Json.of("sealed", false, "gpr", r.gpr().getPath(), "removed", removed,
			"witnesses", isSealed(r).witnesses());
	}

	/** Writes the marker next to the project, atomically (a temporary file, then a rename). */
	static void writeMarker(ProjectResolver.Resolved r, JsonObject marker) throws IOException {
		writeJson(new File(r.dir(), MARKER), marker);
	}

	private static void writeJson(File f, JsonObject o) throws IOException {
		ProjectFork.writeSidecar(f, o); // the same atomic, flushed write
	}

	private static JsonObject readJson(File f) {
		try {
			if (!f.isFile()) {
				return null;
			}
			JsonElement e = JsonParser.parseString(Files.readString(f.toPath()));
			return e.isJsonObject() ? e.getAsJsonObject() : null;
		}
		catch (IOException | JsonParseException e) {
			return null;
		}
	}

	// ---- repairs and corrupt_newest -------------------------------------------------------------

	/**
	 * The repairs {@code VersionFileCheck} did in the project since {@code sinceMs}, as the
	 * {@code repairs[]} of an open reply (D42): the database folder, the quarantined file and the
	 * versions involved.
	 */
	static JsonArray repairsSince(ProjectResolver.Resolved r, long sinceMs) {
		JsonArray a = new JsonArray();
		Path rep = r.dir().toPath().resolve(r.name() + ProjectLocator.getProjectDirExtension())
				.toAbsolutePath().normalize();
		for (VersionFileCheck.Result x : VersionFileCheck.repairs()) {
			if (x.timeMillis >= sinceMs &&
				x.dbDir.toPath().toAbsolutePath().normalize().startsWith(rep)) {
				a.add(Json.of("dir", x.dbDir.getPath(), "quarantined",
					x.quarantined == null ? null : x.quarantined.getPath(), "newest", x.newest,
					"fallback", x.fallback, "at", Instant.ofEpochMilli(x.timeMillis).toString()));
			}
		}
		return a;
	}

	/**
	 * The exception for an {@link IOException} from opening a program: {@code corrupt_newest}
	 * (E8) becomes the code of that name with {@code {project, program, file, repair}} on a
	 * protocol 3 connection, and stays {@code failed} with the same message on protocol 2. Null
	 * for any other I/O error.
	 */
	static SessionException corruptNewest(boolean v3, IOException ex, String projectId,
			String program) {
		String msg = ex.getMessage();
		if (msg == null || !msg.startsWith(VersionFileCheck.CORRUPT_NEWEST)) {
			return null;
		}
		if (!v3) {
			return new SessionException(SessionException.FAILED, msg, null, ex);
		}
		String file = null;
		java.util.regex.Matcher m =
			java.util.regex.Pattern.compile("(db\\.\\d+\\.gbf)").matcher(msg);
		if (m.find()) {
			file = m.group(1);
		}
		return new SessionException(CORRUPT_NEWEST, msg, Json.of("project", projectId, "program",
			program, "file", file, "repair",
			"fork_project makes a disposable fork, whose open repairs it (the bad file is moved " +
				"to a quarantine folder, never deleted)"),
			ex);
	}
}
