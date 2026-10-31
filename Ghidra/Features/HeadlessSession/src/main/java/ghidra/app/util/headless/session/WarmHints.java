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
 * What this state directory's daemons opened before, loaded again while the next daemon starts.
 * <p>
 * The first program of a language that a daemon opens spends about a second reading and decoding
 * the language's {@code .sla} file (measured: 20 of 37 CPU samples of the first
 * {@code open_program} of a 8616-function x86 program, JFR). The ids of the languages a daemon
 * loads are kept in {@code <stateDir>/warm-languages.txt}; the next daemon of this state directory
 * loads them on a background thread as soon as it is ready, in parallel with the client's
 * {@code open_project} and with its own idle time, so the first open finds them loaded. Loading is
 * what a request would do (the language service caches the result), so nothing a request sees
 * changes; a missing or unreadable file means no warming. A language that is gone is skipped.
 */
final class WarmHints {

	private static final String FILE = "warm-languages.txt";

	private static volatile Path file;
	private static final Set<String> KNOWN = ConcurrentHashMap.newKeySet();
	private static volatile long warmedMs = -1;
	private static volatile int warmed;

	private WarmHints() {
	}

	/** Reads the hints of {@code stateDir} (null: none) and loads them in the background. */
	static void start(String stateDir) {
		if (stateDir == null || !Settings.bool("warmLanguages", true)) {
			return;
		}
		Path dir = Path.of(stateDir);
		file = dir.resolve(FILE);
		List<String> ids;
		try {
			ids = Files.isRegularFile(file) ? Files.readAllLines(file, StandardCharsets.UTF_8)
					: List.of();
		}
		catch (IOException e) {
			return;
		}
		ids = ids.stream().map(String::strip).filter(s -> !s.isEmpty()).limit(8).toList();
		KNOWN.addAll(ids);
		Health.contribute("warmHints", WarmHints::describe);
		if (ids.isEmpty()) {
			return;
		}
		List<String> load = ids;
		Thread t = new Thread(() -> {
			long t0 = System.nanoTime();
			for (String id : load) {
				try {
					DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
					warmed++;
				}
				catch (Exception | LinkageError e) {
					Msg.debug(WarmHints.class, "language " + id + " not warmed: " + e);
				}
			}
			warmedMs = (System.nanoTime() - t0) / 1_000_000;
		}, "session-warm-languages");
		t.setDaemon(true);
		t.start();
	}

	/** A daemon loaded this language: remembered for the next one (once per id). */
	static void loaded(String languageId) {
		Path f = file;
		if (f == null || languageId == null || !KNOWN.add(languageId)) {
			return;
		}
		synchronized (WarmHints.class) {
			try {
				List<String> all = new ArrayList<>(KNOWN);
				Collections.sort(all);
				Path tmp = f.resolveSibling(FILE + "." + ProcessHandle.current().pid() + ".tmp");
				Files.write(tmp, String.join("\n", all).concat("\n").getBytes(StandardCharsets.UTF_8));
				Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			}
			catch (IOException | RuntimeException e) {
				Msg.debug(WarmHints.class, "warm hints not written: " + e);
			}
		}
	}

	private static com.google.gson.JsonObject describe() {
		return Json.of("languages", new ArrayList<>(new TreeSet<>(KNOWN)), "warmed", warmed,
			"warmedMs", warmedMs);
	}
}
