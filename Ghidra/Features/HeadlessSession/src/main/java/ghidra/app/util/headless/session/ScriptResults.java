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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.gson.*;

import ghidra.program.model.listing.Program;

/**
 * The output of read scripts on unchanged programs, shared by every connection (sealed results
 * of the read plane).
 * <p>
 * A client that knows its script only reads sends {@code "pure":true} on the {@code script}
 * request: the output is a function of the script's bytes, its arguments and the program's
 * state. Such a run on a program the client does not write (a <i>contained</i> run, rolled back)
 * is keyed by the SHA-256 of the script file, the arguments, the address, {@code maxChars}, the
 * program object and its modification number. Every change of a Ghidra program moves the number,
 * so an entry of a changed program is never served again (the same rule as
 * {@link DecompileCache}, which stores and shares these entries: single flight for N callers of
 * one request, a size-based LRU, older numbers dropped).
 * <p>
 * A run is stored only when it ended normally, changed nothing, left the modification number
 * where it found it, printed within the request's {@code maxChars}, took a quarter of its
 * {@code timeout} at most (a script that ran into its own deadline may have cut its output; a
 * quick one cannot have), and its arguments name no file (an argument starting with {@code @} is
 * read by the script). A hit takes neither the project's nor the program's lock and does not
 * start the script: the reply has the fields of a run, with {@code seconds} the time of this
 * request. Off with {@code -set scriptResults=0}.
 */
final class ScriptResults {

	static final long FLOOR_BYTES = 4L << 20;
	static final long CEILING_BYTES = 64L << 20;

	private static volatile ScriptResults instance;

	/** The daemon's results, made on first use from the settings (null when off). */
	static ScriptResults get() {
		ScriptResults r = instance;
		if (r == null) {
			synchronized (ScriptResults.class) {
				r = instance;
				if (r == null) {
					r = new ScriptResults(new DecompileCache(Budgets.scriptResultBytes()));
					instance = r;
					ScriptResults made = r;
					if (made.cache.budget() > 0) {
						Health.contribute("scriptResults", made.cache::describe);
					}
				}
			}
		}
		return r.cache.budget() > 0 ? r : null;
	}

	/** The default budget for a heap of {@code heapBytes}: 1/64, at most 64 MB, 0 below 4 MB. */
	static long defaultBytes(long heapBytes) {
		long b = Math.min(CEILING_BYTES, heapBytes / 64);
		return b < FLOOR_BYTES ? 0 : b;
	}

	private final DecompileCache cache;

	ScriptResults(DecompileCache cache) {
		this.cache = cache;
	}

	DecompileCache cache() {
		return cache;
	}

	/**
	 * Whether this request may be answered from, and stored in, the results: a pure read run as a
	 * contained script (the caller does not write the program).
	 */
	static boolean wanted(Client c, JsonObject req, ProgramEntry e, String isolation) {
		if (e == null || !Json.bool(req, "pure", false) || Json.bool(req, "exclusive", false) ||
			Json.bool(req, "save", false) || e.isWriter(c)) {
			return false;
		}
		if (isolation != null && !isolation.equals("shared")) {
			return false;
		}
		if (req.has("program") && req.get("program").isJsonNull()) {
			return false;
		}
		for (String a : Json.strings(req, "args")) {
			if (a.startsWith("@")) {
				return false; // the script reads this file: not a function of the arguments
			}
		}
		return true;
	}

	/** The key of this request on {@code p} as it stands now. */
	DecompileCache.Key key(Program p, String scriptSha, JsonObject req) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
		md.update(scriptSha.getBytes(StandardCharsets.US_ASCII));
		for (String a : Json.strings(req, "args")) {
			md.update((byte) 0);
			md.update(a.getBytes(StandardCharsets.UTF_8));
		}
		md.update((byte) 1);
		md.update(Json.str(req, "address", "").getBytes(StandardCharsets.UTF_8));
		md.update((byte) 2);
		md.update(Long.toString(Json.num(req, "maxChars", Requests.DEFAULT_TEXT_CAP, 1,
			Requests.MAX_TEXT_CAP)).getBytes(StandardCharsets.US_ASCII));
		byte[] d = md.digest();
		java.nio.ByteBuffer b = java.nio.ByteBuffer.wrap(d);
		return cache.key(p, b.getLong(), b.getInt(), b.getInt());
	}

	/** What a stored run printed: the (clipped) output and whether it was cut. */
	static DecompileCache.Result result(JsonObject reply) {
		String out = Json.str(reply, "output", "");
		long chars = Json.num(reply, "chars", out.length(), 0, Long.MAX_VALUE);
		return new DecompileCache.Result(chars + "|" + Json.bool(reply, "truncated", false), out);
	}

	/** True when a finished run of {@code reply} may be stored. */
	static boolean storable(JsonObject reply, JsonObject req, double seconds) {
		if (Json.bool(reply, "changed", false) || Json.bool(reply, "truncated", false) ||
			Json.bool(reply, "attemptedChanges", false)) {
			return false;
		}
		double timeout = Json.num(req, "timeout", 0, 0, 7 * 86_400);
		return timeout > 0 && seconds <= timeout / 4;
	}

	/** The {@code chars} of a stored run. */
	static long chars(DecompileCache.Result stored) {
		return Long.parseLong(stored.signature().substring(0, stored.signature().indexOf('|')));
	}

	/** The {@code truncated} of a stored run. */
	static boolean truncated(DecompileCache.Result stored) {
		return Boolean.parseBoolean(stored.signature().substring(stored.signature().indexOf('|') + 1));
	}
}
