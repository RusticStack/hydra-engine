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
// Do two imports into two projects at once stay apart?  The session runs imports in parallel
// because each load is handed its project and nothing on the load path reads the process-wide
// "active project"; this script asks that question of the real classes, without the session's
// gate, and prints what it saw.
// Run it only in a throwaway session (daemon_tests.py "import_isolation" does): it changes the
// process-wide active project and the library search paths.
//
// args: <work dir> <file A> <file B> [rounds]
//
// Part 1, shared state: a library search path added while project A is active is, once project B
//   is active, still in the path set, and it is not in B's saved state. The set is a static
//   loaded once, so every import in the process reads the same one, whatever its project.
// Part 2, concurrent loads: for each round, two threads set "their" project active and load a
//   file into it at the same time (what two ungated imports do). It counts failures, programs that
//   landed in the wrong project, and loads during which the active project was not the loader's
//   own.
//
// @category HeadlessSession.Test
import java.io.File;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loader;
import ghidra.base.project.GhidraProject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;

public class ImportIsolationProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		String dir = a[0];
		File fileA = new File(a[1]);
		File fileB = new File(a[2]);
		int rounds = a.length > 3 ? Integer.parseInt(a[3]) : 10;

		GhidraProject ga = GhidraProject.createProject(dir, "IsoA", true);
		GhidraProject gb = GhidraProject.createProject(dir, "IsoB", true);
		Project pa = ga.getProject();
		Project pb = gb.getProject();

		// Part 1
		String marker = "probe-search-path-from-A";
		AppInfo.setActiveProject(pa);
		LibrarySearchPathManager.addPath(marker);
		AppInfo.setActiveProject(pb);
		boolean visibleInB =
			Arrays.asList(LibrarySearchPathManager.getLibraryPaths()).contains(marker);
		SaveState savedB = pb.getSaveableData(Loader.OPTIONS_PROJECT_SAVE_STATE_KEY);
		String[] bPaths = savedB == null ? null
				: savedB.getStrings("Library Search Paths", null);
		boolean inBState = bPaths != null && Arrays.asList(bPaths).contains(marker);
		println("leak.pathVisibleWhileOtherProjectActive=" + visibleInB);
		println("leak.pathInOtherProjectsSavedState=" + inBState);
		AppInfo.setActiveProject(pa);
		List<String> keep = new ArrayList<>(Arrays.asList(LibrarySearchPathManager.getLibraryPaths()));
		keep.remove(marker);
		LibrarySearchPathManager.setLibraryPaths(keep.toArray(new String[0]));

		// Part 2
		AtomicInteger failures = new AtomicInteger();
		AtomicInteger foreignActive = new AtomicInteger();
		AtomicInteger wrongProject = new AtomicInteger();
		List<String> errors = Collections.synchronizedList(new ArrayList<>());
		ExecutorService pool = Executors.newFixedThreadPool(2);
		long t0 = System.currentTimeMillis();
		for (int i = 0; i < rounds; i++) {
			CyclicBarrier go = new CyclicBarrier(2);
			String folder = "/r" + i;
			List<Future<?>> fs = new ArrayList<>();
			for (int k = 0; k < 2; k++) {
				Project mine = k == 0 ? pa : pb;
				File file = k == 0 ? fileA : fileB;
				fs.add(pool.submit(() -> {
					try {
						go.await();
						AppInfo.setActiveProject(mine);
						try (LoadResults<Program> r = ProgramLoader.builder()
								.source(file)
								.project(mine)
								.projectFolderPath(folder)
								.monitor(monitor)
								.load()) {
							if (AppInfo.getActiveProject() != mine) {
								foreignActive.incrementAndGet();
							}
							r.getPrimary().save(monitor);
						}
					}
					catch (Exception e) {
						failures.incrementAndGet();
						errors.add(e.toString());
					}
					return null;
				}));
			}
			for (Future<?> f : fs) {
				f.get(10, TimeUnit.MINUTES);
			}
		}
		pool.shutdown();
		long ms = System.currentTimeMillis() - t0;

		int inA = count(pa.getProjectData().getRootFolder());
		int inB = count(pb.getProjectData().getRootFolder());
		for (DomainFile f : files(pa.getProjectData().getRootFolder())) {
			if (!f.getName().equals(fileA.getName())) {
				wrongProject.incrementAndGet();
			}
		}
		for (DomainFile f : files(pb.getProjectData().getRootFolder())) {
			if (!f.getName().equals(fileB.getName())) {
				wrongProject.incrementAndGet();
			}
		}
		println("race.rounds=" + rounds);
		println("race.ms=" + ms);
		println("race.failures=" + failures.get());
		println("race.activeProjectNotMineAfterLoad=" + foreignActive.get());
		println("race.programsInA=" + inA);
		println("race.programsInB=" + inB);
		println("race.wrongProject=" + wrongProject.get());
		for (String e : errors) {
			println("race.error=" + e);
		}
		ga.close();
		gb.close();
	}

	private static int count(DomainFolder f) {
		return files(f).size();
	}

	private static List<DomainFile> files(DomainFolder f) {
		List<DomainFile> out = new ArrayList<>(Arrays.asList(f.getFiles()));
		for (DomainFolder s : f.getFolders()) {
			out.addAll(files(s));
		}
		return out;
	}
}
