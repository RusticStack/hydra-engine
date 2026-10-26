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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * A project's <b>revision</b>: a fingerprint of what is saved in it, from the same file identity
 * the upgrade cache keys by ({@link UpgradeCache#sourceFiles}): every file of the {@code .gpr}
 * and the {@code .rep} by relative path, size and modification time, plus the SHA-256 of every
 * file up to {@link UpgradeCache#HASH_LIMIT} (the {@code .gpr}, property and index files). Ghidra
 * writes its large database files whole, as new versions, so their size and time identify them.
 * <p>
 * Unlike the upgrade cache key it leaves out the project's location and this Ghidra's version,
 * and {@code <name>.rep/projectState} (the window layout and tool state Ghidra rewrites whenever
 * a writable project closes, which says nothing about its programs). So a copy made with the
 * files' times kept, as {@code fork_project} makes one, has the revision of its source until one
 * of them is changed, and two daemons agree on a project's revision.
 * <p>
 * A program's revision is the project path and the size and time of its stored version, which
 * changes with every save.
 */
final class Revision {

	/** Files Ghidra rewrites without a change to any program. */
	private static final String PROJECT_STATE = "projectState";

	private Revision() {
	}

	/** The revision of the project as saved on disk now, as 16 hex digits. */
	static String of(ProjectResolver.Resolved r) throws IOException {
		MessageDigest md = sha256();
		String state = r.name() + ".rep/" + PROJECT_STATE;
		for (Map.Entry<String, Path> f : UpgradeCache.sourceFiles(r.gpr().toPath(), r.name())
				.entrySet()) {
			if (f.getKey().equals(state)) {
				continue;
			}
			BasicFileAttributes a;
			try {
				a = Files.readAttributes(f.getValue(), BasicFileAttributes.class);
			}
			catch (NoSuchFileException e) {
				continue; // removed while we walked: the next check sees the new state
			}
			update(md, "|" + f.getKey() + "|" + a.size() + "|" + a.lastModifiedTime().toMillis());
			if (a.size() <= UpgradeCache.HASH_LIMIT) {
				try {
					md.update(Files.readAllBytes(f.getValue()));
				}
				catch (NoSuchFileException e) {
					update(md, "|gone");
				}
			}
		}
		return HexFormat.of().formatHex(md.digest()).substring(0, 16);
	}

	/**
	 * The identity of every file {@link #of} hashes, by relative path: {@code size|mtime}, for
	 * telling what changed between two revisions.
	 */
	static Map<String, String> files(ProjectResolver.Resolved r) throws IOException {
		Map<String, String> out = new java.util.TreeMap<>();
		String state = r.name() + ".rep/" + PROJECT_STATE;
		for (Map.Entry<String, Path> f : UpgradeCache.sourceFiles(r.gpr().toPath(), r.name())
				.entrySet()) {
			if (f.getKey().equals(state)) {
				continue;
			}
			try {
				BasicFileAttributes a = Files.readAttributes(f.getValue(), BasicFileAttributes.class);
				out.put(f.getKey(), a.size() + "|" + a.lastModifiedTime().toMillis());
			}
			catch (NoSuchFileException e) {
				// gone
			}
		}
		return out;
	}

	/** The paths that differ between two {@link #files} maps (added, removed or changed). */
	static List<String> changed(Map<String, String> a, Map<String, String> b) {
		List<String> out = new ArrayList<>();
		Set<String> all = new java.util.TreeSet<>(a.keySet());
		all.addAll(b.keySet());
		for (String k : all) {
			if (!java.util.Objects.equals(a.get(k), b.get(k))) {
				out.add(k);
			}
		}
		return out;
	}

	/** A program's saved revision: its path and its stored file's size and time. */
	static String ofProgram(String path, long length, long lastModified, int version) {
		MessageDigest md = sha256();
		update(md, path + "|" + length + "|" + lastModified + "|" + version);
		return HexFormat.of().formatHex(md.digest()).substring(0, 16);
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
}
