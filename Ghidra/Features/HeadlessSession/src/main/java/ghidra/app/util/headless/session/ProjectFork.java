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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import ghidra.framework.model.ProjectLocator;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

/**
 * The file side of {@code fork_project}: what a fork costs, the copy itself, and the
 * <b>sidecar</b> {@code <name>.fork.json} next to the fork's {@code .gpr}, which records where the
 * fork came from. Ghidra never reads the sidecar (it only looks for {@code .gpr} and {@code .rep}).
 * <p>
 * The copy is the one the upgrade cache makes ({@link UpgradeCache#copyProject}): the
 * {@code .gpr} and every file of the {@code .rep}, never the project's lock files, with
 * {@link Files#copy}, which uses the platform's copy. On Windows that is {@code CopyFileEx},
 * which block-clones on ReFS (a Dev Drive) on Windows 11 24H2 and later: the copy shares the
 * source's blocks and costs only metadata until either side writes. Elsewhere it is a full copy.
 */
final class ProjectFork {

	static final String SIDECAR_SUFFIX = ".fork.json";
	static final int SIDECAR_FORMAT = 1;
	/**
	 * Below this a fork's use of free space is lost in what other writers on the volume do, so
	 * {@code cloned} then rests on the file system alone (a clone of 261 MB measured 36 KB used on
	 * ReFS, a copy 262 MB on NTFS).
	 */
	static final long MEASURABLE_BYTES = 64L << 20;
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting()
			.disableHtmlEscaping()
			.create();

	private ProjectFork() {
	}

	/** The sidecar of a project, whether it exists or not. */
	static File sidecar(ProjectResolver.Resolved r) {
		return new File(r.dir(), r.name() + SIDECAR_SUFFIX);
	}

	/** The project's sidecar, or null when it is not a fork (or the sidecar is unreadable). */
	static JsonObject readSidecar(ProjectResolver.Resolved r) {
		File f = sidecar(r);
		if (!f.isFile()) {
			return null;
		}
		try {
			JsonElement e = JsonParser.parseString(Files.readString(f.toPath()));
			return e.isJsonObject() ? e.getAsJsonObject() : null;
		}
		catch (IOException | JsonParseException e) {
			return null;
		}
	}

	/** A short form of a sidecar for {@code project}/{@code info}: no nested parents. */
	static JsonObject summary(JsonObject sidecar) {
		if (sidecar == null) {
			return null;
		}
		JsonObject o = new JsonObject();
		for (String k : List.of("source", "baseRevision", "created", "createdAt", "by", "mode",
			"method", "cloned", "bytes", "depth")) {
			if (sidecar.has(k)) {
				o.add(k, sidecar.get(k));
			}
		}
		return o;
	}

	/** Writes a sidecar atomically (a temporary file, then a rename). */
	static void writeSidecar(File f, JsonObject o) throws IOException {
		File tmp = new File(f.getPath() + ".tmp");
		Files.writeString(tmp.toPath(), GSON.toJson(o), StandardCharsets.UTF_8);
		Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING,
			StandardCopyOption.ATOMIC_MOVE);
	}

	/** What a fork of {@code r} into {@code destDir} costs, and how it would be made. */
	record Cost(long bytes, int files, boolean sameVolume, String sourceFs, String destFs,
			boolean cloneCapable, long destFreeBytes) {

		JsonObject json() {
			return Json.of("bytes", bytes, "mb", Math.round(bytes / 1048576.0 * 10) / 10.0,
				"files", files, "sameVolume", sameVolume, "sourceFileSystem", sourceFs,
				"destinationFileSystem", destFs, "cloneCapable", cloneCapable, "destFreeBytes",
				destFreeBytes);
		}
	}

	static Cost cost(ProjectResolver.Resolved r, File destDir) throws IOException {
		long bytes = 0;
		int files = 0;
		for (Path p : UpgradeCache.sourceFiles(r.gpr().toPath(), r.name()).values()) {
			try {
				bytes += Files.size(p);
				files++;
			}
			catch (NoSuchFileException e) {
				// removed while we looked; the revision check catches a change
			}
		}
		FileStore src = Files.getFileStore(r.gpr().toPath());
		FileStore dst = Files.getFileStore(existingAncestor(destDir).toPath());
		boolean same = src.equals(dst);
		return new Cost(bytes, files, same, src.type(), dst.type(),
			same && clones(dst), dst.getUsableSpace());
	}

	/**
	 * True when {@link Files#copy} block-clones on this file store: ReFS on Windows (Windows 11
	 * 24H2 and Windows Server 2025 clone in {@code CopyFileEx}). Other copy-on-write file systems
	 * (Btrfs, XFS, APFS) are not claimed: whether the JDK's copy reflinks there has not been
	 * measured here, so a fork there counts as a full copy (and is measured, see
	 * {@code cloned}).
	 */
	static boolean clones(FileStore fs) {
		String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		return os.startsWith("windows") && "refs".equalsIgnoreCase(fs.type());
	}

	static File existingAncestor(File f) {
		File a = f.getAbsoluteFile();
		while (a != null && !a.exists()) {
			a = a.getParentFile();
		}
		return a == null ? f.getAbsoluteFile() : a;
	}

	/** The outcome of {@link #copy}. */
	record Copied(long ms, long freeBefore, long freeAfter) {
	}

	/**
	 * Copies the project {@code r} into {@code destDir} as project {@code name}: first into a
	 * temporary folder next to it, then moved into place, so that a cancelled or failed fork
	 * leaves no half project. {@code destDir} may exist (it must not hold a project of that name).
	 */
	static Copied copy(ProjectResolver.Resolved r, File destDir, String name, RequestMonitor m)
			throws IOException, CancelledException {
		Files.createDirectories(destDir.toPath());
		FileStore store = Files.getFileStore(destDir.toPath());
		long freeBefore = store.getUsableSpace();
		File tmp = new File(destDir,
			"." + name + ".fork-" + Long.toHexString(System.nanoTime()) + ".tmp");
		long t0 = System.nanoTime();
		boolean ok = false;
		try {
			UpgradeCache.copyProject(r.dir().toPath(), r.name(), tmp.toPath(), m);
			// the copy has the source's name; give it the fork's name
			String ext = ProjectLocator.getProjectExtension();
			String repExt = ProjectLocator.getProjectDirExtension();
			Path gpr = tmp.toPath().resolve(r.name() + ext);
			Path rep = tmp.toPath().resolve(r.name() + repExt);
			m.checkCancelled();
			Files.move(rep, destDir.toPath().resolve(name + repExt));
			try {
				Files.move(gpr, destDir.toPath().resolve(name + ext));
			}
			catch (IOException e) {
				FileUtilities.deleteDir(destDir.toPath().resolve(name + repExt).toFile());
				throw e;
			}
			ok = true;
		}
		finally {
			FileUtilities.deleteDir(tmp);
			if (!ok) {
				warnLeft(tmp);
			}
		}
		long ms = (System.nanoTime() - t0) / 1_000_000;
		return new Copied(ms, freeBefore, store.getUsableSpace());
	}

	private static void warnLeft(File tmp) {
		if (tmp.exists()) {
			ghidra.util.Msg.warn(ProjectFork.class,
				"fork_project: could not remove the temporary folder " + tmp);
		}
	}
}
