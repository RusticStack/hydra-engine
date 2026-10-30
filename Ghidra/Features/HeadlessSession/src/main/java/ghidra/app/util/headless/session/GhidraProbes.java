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
import java.util.regex.Pattern;

import ghidra.framework.model.ProjectLocator;

/**
 * 8.13 (A61): the time probes a killed writable open leaves in a project.
 *
 * <p>Every writable open of a Ghidra project starts {@code LocalDatabaseItem.CleanupRunnable}
 * for each file system root of the {@code .rep} ({@code idata}, {@code user}, {@code versioned}):
 * it creates an empty {@code File.createTempFile("tmp", ".tmp", root)} to read the file
 * system's clock and deletes it at once. A process killed in between leaves that empty file for
 * good: nothing in Ghidra removes it (9.15 fork batch, a kill during the {@code open} of a
 * committed fork). The writable open of the daemon removes such probes first.
 *
 * <p>Only empty files named {@code tmp<digits>.tmp} directly in those roots are removed, and only
 * on a writable open (a read-only open never changes the project). Removing the probe of a
 * process that is alive and inside that window is harmless to it: its {@code lastModified()}
 * then reads 0 and its cleanup removes nothing. This never throws.
 */
final class GhidraProbes {
	private static final Pattern PROBE = Pattern.compile("tmp\\d+\\.tmp");
	private static final String[] ROOTS = { "idata", "user", "versioned" };

	private GhidraProbes() {
	}

	/** Removes the stale probes of project {@code name} in {@code dir}; returns how many. */
	static int removeStale(File dir, String name) {
		int n = 0;
		try {
			File rep = new File(dir, name + ProjectLocator.getProjectDirExtension());
			for (String root : ROOTS) {
				File[] files = new File(rep, root).listFiles();
				if (files == null) {
					continue;
				}
				for (File f : files) {
					if (PROBE.matcher(f.getName()).matches() && f.isFile() && f.length() == 0 &&
						f.delete()) {
						n++;
						ghidra.util.Msg.info(GhidraProbes.class,
							"removed a stale time probe of a killed writable open: " + f);
					}
				}
			}
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(GhidraProbes.class,
				"could not look for stale time probes in " + dir + ": " + e);
		}
		return n;
	}
}
