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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.framework.store.db.VersionFileCheck;
import ghidra.util.Msg;

/**
 * The {@code health} command (PROTOCOL-3.md 3.4, package E5).
 * <p>
 * {@code health} is answered on the connection's reader thread, like {@code ping}, from the
 * snapshot that the {@link Watchdog} thread publishes once a second. It never takes the scheduler
 * lock or a project lock, so a daemon whose scheduler lock is held, whose projects are busy or
 * whose lanes are full still answers it. The engine never says "wedged": it reports facts
 * ({@code tick.ageMs}, {@code schedulerLockOk}, {@code deadlocked}) and the {@code state} they
 * imply, and the client decides (7.2).
 * <p>
 * <b>The contributor list.</b> Classes that have figures for {@code health} register a
 * name-to-supplier pair with {@link #contribute} ({@code waits}, {@code leakedWorkers},
 * {@code repairs} here; {@code governor}, the script worker and the process job in E7 and E9), so
 * that they add their figures without editing this file (D60, D64). A supplier runs on the reader
 * thread of whoever asks: it must be quick, and must not take the scheduler lock or a project
 * lock. One that throws is reported as {@code {"error": ...}} under its name and does not fail
 * the command.
 * <p>
 * <b>Test hooks.</b> {@code -Dghidra.session.testHooks=true} (a launch property of the JVM: it is
 * not a setting, so the {@code engine} object of {@code config.json} cannot turn it on, and no
 * request can) registers {@code debug_stall}, is advertised in {@code hello.platform.testHooks}
 * and makes {@code health.state} {@code degraded}.
 */
final class Health {

	/** The JVM launch property. Read once; there is no way to change it in a running daemon. */
	static final String HOOKS_PROPERTY = "ghidra.session.testHooks";
	private static final boolean TEST_HOOKS = Boolean.getBoolean(HOOKS_PROPERTY);

	/** Keys the command itself writes first; a contributor may not use them. */
	private static final Set<String> CORE = Set.of("state", "pid", "uptimeMs", "protocol", "tick",
		"schedulerLockOk", "lanes", "deadlocked", "abandoned", "memory", "testHooks");

	private static final Map<String, Supplier<JsonElement>> CONTRIBUTORS = new LinkedHashMap<>();

	/** What one watchdog tick saw. Immutable once published (the JSON is never changed). */
	record Snapshot(long n, long atMs, long lateMs, boolean schedulerLockOk, JsonObject lanes,
			JsonArray deadlocked, JsonArray abandoned, int restarts) {
	}

	private static volatile Snapshot snapshot;

	private Health() {
		// static helpers
	}

	/** True only with the launch property {@code -Dghidra.session.testHooks=true}. */
	static boolean testHooks() {
		return TEST_HOOKS;
	}

	/**
	 * Start-up validation of the settings this package reads: a value that is not an integer, and
	 * {@code testHooks} given as a setting (it is a launch property, never a setting).
	 *
	 * @throws IllegalArgumentException with a usage message
	 */
	static void validateSettings() {
		Settings.integer("watchdogStallMs", 15_000);
		Settings.integer("starveMs", 30_000);
		if (Settings.has("testHooks")) {
			throw new IllegalArgumentException("testHooks is a launch property " + "(-D" +
				HOOKS_PROPERTY + "=true on the JVM), not an engine setting; remove it from " +
				"the engine object of config.json");
		}
	}

	/** Called once at start-up: says so in the log when the hook is on. */
	static void announce() {
		if (TEST_HOOKS) {
			Msg.warn(Health.class, "test hooks are ON (-D" + HOOKS_PROPERTY +
				"=true): debug_stall is registered and health.state is degraded");
		}
	}

	// ---- the contributor list --------------------------------------------------------------

	/**
	 * Adds a figure to the {@code health} reply under {@code name}, after the core keys, in the
	 * order of registration. Registering a name again replaces its supplier. A supplier that
	 * returns null leaves its key out.
	 *
	 * @throws IllegalArgumentException when {@code name} is one of the core keys
	 */
	static void contribute(String name, Supplier<JsonElement> supplier) {
		if (name == null || name.isEmpty() || CORE.contains(name)) {
			throw new IllegalArgumentException("health contributor name '" + name +
				"' is empty or a core key");
		}
		synchronized (CONTRIBUTORS) {
			CONTRIBUTORS.put(name, supplier);
		}
	}

	/** The registered names, in reply order. */
	static List<String> contributors() {
		synchronized (CONTRIBUTORS) {
			return List.copyOf(CONTRIBUTORS.keySet());
		}
	}

	// ---- the snapshot ----------------------------------------------------------------------

	static void publish(Snapshot s) {
		snapshot = s;
	}

	static Snapshot snapshot() {
		return snapshot;
	}

	/** Forgets the snapshot (the self-test). */
	static void clearSnapshot() {
		snapshot = null;
	}

	// ---- the state -------------------------------------------------------------------------

	/**
	 * The {@code state} of 3.4. {@code suspect}: the watchdog tick is older than
	 * {@code watchdogStallMs}, or the scheduler lock could not be taken in 200 ms, or deadlocked
	 * threads exist. Else {@code degraded}: an abandoned holder exists, {@code dbVersions.program}
	 * is unreadable, or the test hooks are on. Else {@code ok}.
	 */
	static String state(long tickAgeMs, long stallMs, boolean schedulerLockOk, int deadlocked,
			int abandoned, boolean programVersionKnown, boolean hooks) {
		if (tickAgeMs > stallMs || !schedulerLockOk || deadlocked > 0) {
			return "suspect";
		}
		if (abandoned > 0 || !programVersionKnown || hooks) {
			return "degraded";
		}
		return "ok";
	}

	// ---- the reply -------------------------------------------------------------------------

	/**
	 * The result of {@code health}. Runs on the reader thread: reads the snapshot, the clock and
	 * the contributors, and nothing that can block.
	 */
	static JsonObject reply(long startedAtMs, Client c) {
		long now = System.currentTimeMillis();
		Snapshot s = snapshot;
		long stallMs = Settings.integer("watchdogStallMs", 15_000);
		long upMs = now - startedAtMs;
		long ageMs = s == null ? upMs : Math.max(0, now - s.atMs());
		boolean lockOk = s == null || s.schedulerLockOk(); // before the first tick: not known to be held
		JsonArray dead = s == null ? new JsonArray() : s.deadlocked();
		JsonArray abandoned = s == null ? new JsonArray() : s.abandoned();
		JsonObject lanes = s == null || s.lanes() == null ? new JsonObject() : s.lanes();
		Runtime rt = Runtime.getRuntime();

		JsonObject o = new JsonObject();
		o.addProperty("state", state(ageMs, stallMs, lockOk,
			dead.size(), abandoned.size(), DbVersions.program() >= 0,
			TEST_HOOKS || Governor.degraded())); // E9: above the hard heap watermark
		o.addProperty("pid", ProcessHandle.current().pid());
		o.addProperty("uptimeMs", upMs);
		o.addProperty("protocol", c == null ? HydraInfo.PROTOCOL : c.protocol());
		o.add("tick", Json.of("n", s == null ? 0 : s.n(), "ageMs", ageMs, "lateMs",
			s == null ? 0 : s.lateMs(), "restarts", s == null ? 0 : s.restarts()));
		o.addProperty("schedulerLockOk", lockOk);
		o.add("lanes", lanes.deepCopy());
		o.add("deadlocked", dead.deepCopy());
		o.add("abandoned", abandoned.deepCopy());
		o.add("memory", Json.of("usedMb", (rt.totalMemory() - rt.freeMemory()) >> 20,
			"committedMb", rt.totalMemory() >> 20, "maxMb", rt.maxMemory() >> 20));
		o.addProperty("testHooks", TEST_HOOKS);
		Map<String, Supplier<JsonElement>> copy;
		synchronized (CONTRIBUTORS) {
			copy = new LinkedHashMap<>(CONTRIBUTORS);
		}
		for (Map.Entry<String, Supplier<JsonElement>> e : copy.entrySet()) {
			try {
				JsonElement v = e.getValue().get();
				if (v != null) {
					o.add(e.getKey(), v);
				}
			}
			catch (RuntimeException | LinkageError ex) {
				o.add(e.getKey(), Json.of("error", String.valueOf(ex)));
			}
		}
		return o;
	}

	/**
	 * The repairs the version-file check made in this process ({@code repairs[]}, 3.13): the
	 * database folder, the quarantined file, the versions involved and when. (The fork sweeper's
	 * removals are logged by {@link ForkSweeper} and are not kept as a list.)
	 */
	static JsonElement repairs() {
		JsonArray a = new JsonArray();
		for (VersionFileCheck.Result x : VersionFileCheck.repairs()) {
			a.add(Json.of("dir", x.dbDir.getPath(), "quarantined",
				x.quarantined == null ? null : x.quarantined.getPath(), "newest", x.newest,
				"fallback", x.fallback, "at",
				java.time.Instant.ofEpochMilli(x.timeMillis).toString()));
		}
		return a;
	}

	// ---- debug_stall (D22, behind the launch property) --------------------------------------

	/**
	 * {@code debug_stall}: {@code {"what":"scheduler"|"watchdog","ms":N}} (default
	 * {@code scheduler}, 5000 ms, at most 120000). {@code scheduler} holds the scheduler lock for
	 * {@code ms} (the reply comes once it is held); {@code watchdog} stops the watchdog thread's
	 * ticking for {@code ms} (the reply comes at once; the tick stops within a second). Neither
	 * touches a client's request; both end by themselves. {@code thread} (E9) plants one fault:
	 * {@code {"what":"thread","thread":"session-reaper","error":"runtime"|"oom"}} makes the next lap
	 * of that guarded thread throw, so that its restart can be tested.
	 */
	static JsonElement debugStall(Session session, JsonObject req) {
		if (!TEST_HOOKS) {
			throw new SessionException(SessionException.UNKNOWN_COMMAND,
				"unknown cmd 'debug_stall'; send status or see the README for the list");
		}
		String what = Json.str(req, "what", "scheduler");
		long ms = Json.has(req, "ms") ? req.get("ms").getAsLong() : 5000;
		if (ms < 1 || ms > 120_000) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"ms must be 1 to 120000, not " + ms);
		}
		switch (what) {
			case "scheduler":
				session.scheduler.stallForTest(ms);
				break;
			case "watchdog":
				session.watchdogStall(ms);
				break;
			case "thread": { // E9: the next lap of a guarded thread throws (tests Guarded in a daemon)
				String thread = Json.str(req, "thread");
				String error = Json.str(req, "error", "runtime");
				if (!Guarded.inject(thread, error)) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"no guarded thread named \"" + thread + "\"");
				}
				return Json.of("planted", error, "thread", thread);
			}
			default:
				throw new SessionException(SessionException.BAD_REQUEST,
					"what must be \"scheduler\", \"watchdog\" or \"thread\", not \"" + what + "\"");
		}
		return Json.of("stalling", what, "ms", ms);
	}
}
