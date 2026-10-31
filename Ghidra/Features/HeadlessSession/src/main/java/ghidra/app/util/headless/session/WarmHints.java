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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;

/**
 * What this state directory's daemons loaded before, loaded again while the next daemon starts.
 * <p>
 * <b>Languages.</b> The first program of a language that a daemon opens spends about a second
 * reading and decoding the language's {@code .sla} file (measured: 20 of 37 CPU samples of the
 * first {@code open_program} of a 8616-function x86 program, JFR). The ids of the languages a
 * daemon loads are kept in {@code <stateDir>/warm-languages.txt}; the next daemon of this state
 * directory loads them on a background thread as soon as it is ready, in parallel with the
 * client's {@code open_project} and with its own idle time, so the first open finds them loaded.
 * Loading is what a request would do (the language service caches the result), so nothing a
 * request sees changes; a missing or unreadable file means no warming. A language that is gone is
 * skipped.
 * <p>
 * <b>Scripts.</b> The first run of a Java script loads and compiles its class through OSGi
 * (3.6 s measured for the first {@code script} of a daemon, 8 ms for every later one: the cold
 * {@code script_read} and {@code hy_functions} audit ops were the only read ops over 1 s). The
 * absolute paths of the Java scripts a daemon ran are kept in {@code <stateDir>/warm-scripts.txt};
 * the next daemon of this state directory loads and keeps their classes on a background thread as
 * it becomes ready ({@link ScriptClasses#warm}), so their first run finds the class loaded and
 * takes milliseconds. Only files that still exist are warmed; one that no longer loads is logged
 * and skipped, as a run of it would report.
 */
final class WarmHints {

	private static final String LANGUAGES = "warm-languages.txt";
	private static final String SCRIPTS = "warm-scripts.txt";
	private static final int MAX = 8;

	private static volatile Path langFile;
	private static volatile Path scriptFile;
	private static final Set<String> IDS = ConcurrentHashMap.newKeySet();
	private static final Set<String> PATHS = ConcurrentHashMap.newKeySet();
	private static volatile long warmedMs = -1;
	private static volatile int warmed;
	private static volatile long scriptsMs = -1;
	private static volatile int scriptsWarmed = -1;

	private WarmHints() {
	}

	/** Reads the hints of {@code stateDir} (null: none) and loads them in the background. */
	static void start(String stateDir) {
		if (stateDir == null) {
			return;
		}
		Health.contribute("warmHints", WarmHints::describe);
		Path dir = Path.of(stateDir);
		if (Settings.bool("warmLanguages", true)) {
			langFile = dir.resolve(LANGUAGES);
			List<String> ids = read(langFile);
			IDS.addAll(ids);
			if (!ids.isEmpty()) {
				Thread t = new Thread(() -> warmLanguages(ids), "session-warm-languages");
				t.setDaemon(true);
				t.start();
			}
		}
		if (Settings.bool("warmScripts", true)) {
			scriptFile = dir.resolve(SCRIPTS);
			List<String> paths = read(scriptFile);
			PATHS.addAll(paths);
			if (!paths.isEmpty()) {
				Thread t = new Thread(() -> warmScripts(paths), "session-warm-scripts");
				t.setDaemon(true);
				t.start();
			}
		}
	}

	private static List<String> read(Path f) {
		try {
			return Files.isRegularFile(f)
					? Files.readAllLines(f, StandardCharsets.UTF_8).stream().map(String::strip)
							.filter(s -> !s.isEmpty()).limit(MAX).toList()
					: List.of();
		}
		catch (IOException e) {
			return List.of();
		}
	}

	private static void warmLanguages(List<String> ids) {
		long t0 = System.nanoTime();
		for (String id : ids) {
			try {
				DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
				warmed++;
			}
			catch (Exception | LinkageError e) {
				Msg.debug(WarmHints.class, "language " + id + " not warmed: " + e);
			}
		}
		warmedMs = (System.nanoTime() - t0) / 1_000_000;
	}

	private static void warmScripts(List<String> paths) {
		DeferredInit.await(); // the OSGi framework that loads script classes
		long t0 = System.nanoTime();
		for (String p : paths) {
			try {
				Path f = Path.of(p);
				if (Files.isRegularFile(f) && ScriptClasses.warm(f)) {
					scriptsWarmed++;
				}
			}
			catch (Exception | LinkageError e) {
				Msg.debug(WarmHints.class, "script " + p + " not warmed: " + e);
			}
		}
		scriptsMs = (System.nanoTime() - t0) / 1_000_000;
	}

	/** A daemon loaded this language: remembered for the next one (once per id). */
	static void loaded(String languageId) {
		remember(langFile, IDS, languageId);
	}

	/** A daemon ran this Java script: remembered for the next one (once per path). */
	static void script(String path) {
		if (path != null && path.endsWith(".java")) {
			remember(scriptFile, PATHS, path);
		}
	}

	private static void remember(Path f, Set<String> known, String value) {
		if (f == null || value == null || !known.add(value)) {
			return;
		}
		synchronized (WarmHints.class) {
			try {
				List<String> all = new ArrayList<>(known);
				Collections.sort(all);
				String name = f.getFileName().toString();
				Path tmp = f.resolveSibling(name + "." + ProcessHandle.current().pid() + ".tmp");
				Files.write(tmp, String.join("\n", all).concat("\n").getBytes(StandardCharsets.UTF_8));
				Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			}
			catch (IOException | RuntimeException e) {
				Msg.debug(WarmHints.class, "warm hints not written: " + e);
			}
		}
	}

	private static com.google.gson.JsonObject describe() {
		return Json.of("languages", new ArrayList<>(new TreeSet<>(IDS)), "warmed", warmed,
			"warmedMs", warmedMs, "scripts", new ArrayList<>(new TreeSet<>(PATHS)),
			"scriptsWarmed", scriptsWarmed, "scriptsMs", scriptsMs);
	}
}
