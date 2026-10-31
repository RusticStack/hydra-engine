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
import java.util.*;

/**
 * Resolves what a caller typed (a {@code .gpr} file, a {@code .rep} folder, the folder holding a
 * {@code .gpr}, or a parent folder with exactly one project below it) to the pair that
 * {@code ProjectLocator} needs: the directory and the project name.
 */
public class ProjectResolver {

	public record Resolved(File dir, String name) {
		public File gpr() {
			return new File(dir, name + ".gpr");
		}
	}

	private static final int MAX_DEPTH = 2;

	/**
	 * A resolved path with the canonical {@code .gpr} path, which is how the session keys its
	 * projects: the walk of {@link #resolve} plus one {@code getCanonicalPath} is about 1.4 ms of
	 * a join on this machine, and the same client path is opened again and again.
	 */
	public record Open(Resolved resolved, String canonical) {
	}

	/** Resolved paths by the absolute path text they were asked for (successful resolutions only). */
	private static final java.util.concurrent.ConcurrentHashMap<String, Open> OPEN =
		new java.util.concurrent.ConcurrentHashMap<>();

	/**
	 * {@link #resolve} with the result kept for the next open of the same path. A hit still checks
	 * that the {@code .gpr} exists, so a deleted project is resolved (and refused) again; the
	 * directory and name of an existing project do not change while the daemon runs.
	 */
	public static Open resolveOpen(String path) throws IOException {
		String key = new File(path).getAbsolutePath();
		Open hit = OPEN.get(key);
		if (hit != null && hit.resolved().gpr().isFile()) {
			return hit;
		}
		Resolved r = resolve(path);
		Open o = new Open(r, r.gpr().getCanonicalPath());
		if (OPEN.size() > 1024) {
			OPEN.clear();
		}
		OPEN.put(key, o);
		return o;
	}

	public static Resolved resolve(String path) throws IOException {
		File f = new File(path).getAbsoluteFile();
		if (!f.exists()) {
			throw new IOException("Path does not exist: " + f);
		}
		if (f.isFile()) {
			if (!f.getName().endsWith(".gpr")) {
				throw new IOException("Not a .gpr file: " + f);
			}
			return fromGpr(f);
		}
		if (f.getName().endsWith(".rep")) {
			String name = f.getName().substring(0, f.getName().length() - 4);
			File gpr = new File(f.getParentFile(), name + ".gpr");
			if (gpr.isFile()) {
				return fromGpr(gpr);
			}
		}
		List<File> found = new ArrayList<>();
		search(f, 0, found);
		if (found.size() == 1) {
			return fromGpr(found.get(0));
		}
		if (found.isEmpty()) {
			throw new IOException("No Ghidra project (.gpr) found in or below " + f);
		}
		StringBuilder sb = new StringBuilder("Several Ghidra projects found below " + f +
			"; pass one .gpr path:");
		for (File g : found) {
			sb.append("\n  ").append(g);
		}
		throw new IOException(sb.toString());
	}

	private static Resolved fromGpr(File gpr) throws IOException {
		String n = gpr.getName();
		String name = n.substring(0, n.length() - 4);
		if (!new File(gpr.getParentFile(), name + ".rep").isDirectory()) {
			throw new IOException("Missing " + name + ".rep next to " + gpr);
		}
		return new Resolved(gpr.getParentFile(), name);
	}

	private static void search(File dir, int depth, List<File> found) {
		File[] children = dir.listFiles();
		if (children == null) {
			return;
		}
		Arrays.sort(children);
		for (File c : children) {
			if (c.isFile() && c.getName().endsWith(".gpr")) {
				found.add(c);
			}
		}
		if (!found.isEmpty() || depth >= MAX_DEPTH) {
			return;
		}
		for (File c : children) {
			if (c.isDirectory() && !c.getName().endsWith(".rep")) {
				search(c, depth + 1, found);
			}
		}
	}
}
