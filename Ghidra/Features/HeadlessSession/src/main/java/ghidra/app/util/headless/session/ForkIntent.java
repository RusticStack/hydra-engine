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
import java.time.Instant;
import java.util.Optional;

import com.google.gson.*;

/**
 * The intent record of one {@code fork_project} publish (PROTOCOL-3.md D41, package E2a): a small
 * JSON file {@code intent.json} inside the fork's staging folder
 * ({@code .<name>.fork-<id>.tmp}). It says who is publishing which fork, so that
 * <ul>
 * <li>a second publisher of the same destination can tell a live publisher from a dead one
 * ({@link #ownerAlive()}: the process id <i>and</i> its creation time, so a reused process id does
 * not pass for the owner);</li>
 * <li>a retry, and the lazy sweeper ({@link ForkSweeper}), can recognise the half fork the engine
 * itself made: a {@code .rep} without a {@code .gpr} is the engine's only when the intent of a
 * dead process names it ({@link #phase()} {@value #MOVING}, and the creation time of the
 * {@code .rep} it moved).</li>
 * </ul>
 * The idempotency key {@code rk} (protocol 3) is recorded so that a waiting publisher with the
 * same key knows the winner's request is the one it repeats.
 */
record ForkIntent(String id, long pid, long procStartMs, String rk, String name, String phase,
		long repCreatedMs, long createdMs) {

	static final String FILE = "intent.json";
	/** The copy into the staging folder is under way; nothing of the fork is at the destination. */
	static final String STAGING = "staging";
	/**
	 * The {@code .rep} is about to be, or has been, moved to the destination: a {@code .rep}
	 * there without a {@code .gpr} may be this publisher's.
	 */
	static final String MOVING = "moving";
	static final int FORMAT = 1;
	/** How far apart two readings of a process's creation time may be and still be one process. */
	static final long START_TOLERANCE_MS = 2000;

	/** The intent of this process for a new publish. */
	static ForkIntent create(String id, String rk, String name) {
		ProcessHandle me = ProcessHandle.current();
		long start = me.info().startInstant().map(Instant::toEpochMilli).orElse(0L);
		return new ForkIntent(id, me.pid(), start, rk, name, STAGING, 0, System.currentTimeMillis());
	}

	ForkIntent withPhase(String newPhase, long newRepCreatedMs) {
		return new ForkIntent(id, pid, procStartMs, rk, name, newPhase, newRepCreatedMs, createdMs);
	}

	/** Writes the record into {@code staging} (a temporary file, then a rename). */
	void write(Path staging) throws IOException {
		JsonObject o = new JsonObject();
		o.addProperty("format", FORMAT);
		o.addProperty("kind", "ghidra-session-fork-intent");
		o.addProperty("id", id);
		o.addProperty("pid", pid);
		o.addProperty("procStartMs", procStartMs);
		if (rk != null) {
			o.addProperty("rk", rk);
		}
		o.addProperty("name", name);
		o.addProperty("phase", phase);
		o.addProperty("repCreatedMs", repCreatedMs);
		o.addProperty("createdMs", createdMs);
		Path tmp = staging.resolve(FILE + ".tmp");
		Files.writeString(tmp, new GsonBuilder().disableHtmlEscaping().create().toJson(o),
			StandardCharsets.UTF_8);
		try {
			Files.move(tmp, staging.resolve(FILE), StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (AtomicMoveNotSupportedException e) {
			Files.move(tmp, staging.resolve(FILE), StandardCopyOption.REPLACE_EXISTING);
		}
	}

	/** The intent in {@code staging}, or empty when there is none or it cannot be read. */
	static Optional<ForkIntent> read(Path staging) {
		try {
			JsonElement e = JsonParser.parseString(
				Files.readString(staging.resolve(FILE), StandardCharsets.UTF_8));
			if (!e.isJsonObject()) {
				return Optional.empty();
			}
			JsonObject o = e.getAsJsonObject();
			if (!o.has("id") || !o.has("pid") || !o.has("name")) {
				return Optional.empty();
			}
			return Optional.of(new ForkIntent(o.get("id").getAsString(), o.get("pid").getAsLong(),
				num(o, "procStartMs"), o.has("rk") ? o.get("rk").getAsString() : null,
				o.get("name").getAsString(), o.has("phase") ? o.get("phase").getAsString() : STAGING,
				num(o, "repCreatedMs"), num(o, "createdMs")));
		}
		catch (IOException | RuntimeException e) {
			return Optional.empty();
		}
	}

	private static long num(JsonObject o, String k) {
		return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsLong() : 0;
	}

	/**
	 * True while the process that wrote this record is running. A process id alone is not enough
	 * (ids are reused): when both creation times are known they must agree within
	 * {@link #START_TOLERANCE_MS}; a record without a creation time falls back to the id alone,
	 * which can only err towards "alive", the safe side for a sweeper.
	 */
	boolean ownerAlive() {
		Optional<ProcessHandle> h = ProcessHandle.of(pid);
		if (h.isEmpty() || !h.get().isAlive()) {
			return false;
		}
		if (procStartMs <= 0) {
			return true;
		}
		Optional<Instant> start = h.get().info().startInstant();
		if (start.isEmpty()) {
			return true;
		}
		return Math.abs(start.get().toEpochMilli() - procStartMs) <= START_TOLERANCE_MS;
	}

	/** The staging folder name for {@code name} and {@code id}. */
	static String stagingName(String name, String id) {
		return "." + name + ".fork-" + id + ".tmp";
	}

	/**
	 * The process id in a staging folder's name ({@code .<name>.fork-<pid hex>-<...>.tmp}), or -1
	 * when the name does not carry one. Used only for a folder without a readable intent.
	 */
	static long pidOf(String folder) {
		int i = folder.lastIndexOf(".fork-");
		int j = folder.endsWith(".tmp") ? folder.length() - 4 : -1;
		if (i < 0 || j < 0) {
			return -1;
		}
		String id = folder.substring(i + ".fork-".length(), j);
		int dash = id.indexOf('-');
		if (dash <= 0) {
			return -1;
		}
		try {
			return Long.parseLong(id.substring(0, dash), 16);
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}

	/** The publish id in a staging folder's name, or null when the name does not carry one. */
	static String idOf(String folder) {
		int i = folder.lastIndexOf(".fork-");
		if (i < 0 || !folder.endsWith(".tmp")) {
			return null;
		}
		return folder.substring(i + ".fork-".length(), folder.length() - 4);
	}

	/** True when {@code folder} is named like a staging folder: {@code .<name>.fork-<id>.tmp}. */
	static boolean isStagingName(String folder) {
		return folder.startsWith(".") && folder.endsWith(".tmp") &&
			folder.lastIndexOf(".fork-") > 0;
	}
}
