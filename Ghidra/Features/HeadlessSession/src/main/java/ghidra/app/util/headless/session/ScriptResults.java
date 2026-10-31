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

	/**
	 * The key of this request on {@code p} as it stands now.
	 * <p>
	 * An argument that is a JSON object has its {@code id} field left out: it is the request's
	 * label, echoed by the script but naming nothing, and every client mints a new one per call
	 * (Hydralysis sends a fresh uuid), so a key over the raw text would never repeat. The output
	 * is stored with the id it answered ({@link #result}) and a hit writes the caller's id in its
	 * place ({@link #output}); the rest of the request is hashed as it arrives.
	 */
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
			md.update(withoutId(a).getBytes(StandardCharsets.UTF_8));
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

	/** What a stored run printed: the (clipped) output, whether it was cut, and its request id. */
	static DecompileCache.Result result(JsonObject reply, String id) {
		String out = Json.str(reply, "output", "");
		long chars = Json.num(reply, "chars", out.length(), 0, Long.MAX_VALUE);
		String written = id == null || !plain(id) ? "" : id;
		return new DecompileCache.Result(
			chars + "|" + Json.bool(reply, "truncated", false) + "|" + written, out);
	}

	/**
	 * The stored output of a run as the answer to a request whose id is {@code id} (null or empty:
	 * no id): a script that echoed the request's id (a JSON object starting {@code {"id":"..."}})
	 * gets this request's id where the stored run's was, so the output is the one a run of this
	 * exact request gives. Anything unusual -- an id that needs JSON escaping, an id written
	 * anywhere else than the start, the stored id appearing again -- means the stored output
	 * cannot be reused and null is returned, which runs the script.
	 */
	static String output(DecompileCache.Result stored, String id) {
		String want = id == null ? "" : id;
		String out = stored.c();
		String from = stored.signature().substring(stored.signature().lastIndexOf('|') + 1);
		if (!plain(from) || !plain(want)) {
			return null;
		}
		int at = 0;
		while (at < out.length() && Character.isWhitespace(out.charAt(at))) {
			at++;
		}
		if (!out.startsWith("{\"id\":\"", at)) {
			// no id at the start: the same output for every request, unless the stored id is
			// written elsewhere, which a hit would leave stale
			return from.isEmpty() || !out.contains(from) ? out : null;
		}
		int value = at + 7;
		int end = out.indexOf('"', value);
		if (end < 0 || !out.substring(value, end).equals(from)) {
			return null; // an id this run did not write: not a shape a hit may edit
		}
		if (!from.isEmpty() && out.indexOf(from, end + 1) >= 0) {
			return null; // the id is written more than once: a hit cannot rewrite them all
		}
		return out.substring(0, value) + want + out.substring(end);
	}

	/** True when {@code s} is written by Gson as itself inside a JSON string. */
	private static boolean plain(String s) {
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c < 0x20 || c == '"' || c == '\\' || c == '|' || c > 0x7e) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The request id a script echoes: the {@code id} of the one JSON-object argument that has one
	 * (Hydralysis sends its request, a fresh uuid among its fields, as the only argument), null
	 * when no argument has one or they disagree.
	 */
	static String id(JsonObject req) {
		String found = null;
		for (String a : Json.strings(req, "args")) {
			String id = idOf(a);
			if (id == null) {
				continue;
			}
			if (found != null && !found.equals(id)) {
				return null;
			}
			found = id;
		}
		return found;
	}

	/** The top-level {@code id} of {@code arg} when it is a JSON object with a string id. */
	private static String idOf(String arg) {
		if (!arg.stripLeading().startsWith("{")) {
			return null;
		}
		try {
			JsonElement e = JsonParser.parseString(arg);
			if (!e.isJsonObject()) {
				return null;
			}
			JsonElement id = e.getAsJsonObject().get("id");
			if (id == null || !id.isJsonPrimitive() || !id.getAsJsonPrimitive().isString()) {
				return null;
			}
			return id.getAsString();
		}
		catch (RuntimeException ex) {
			return null; // not JSON after all
		}
	}

	/** {@code arg} with its top-level {@code id} left out when it is a JSON object; else itself. */
	static String withoutId(String arg) {
		String text = arg.stripLeading();
		if (!text.startsWith("{")) {
			return arg;
		}
		try {
			JsonElement e = com.google.gson.JsonParser.parseString(arg);
			if (!e.isJsonObject()) {
				return arg;
			}
			JsonObject o = e.getAsJsonObject();
			if (!o.has("id")) {
				return arg;
			}
			o.remove("id");
			return Json.GSON.toJson(o);
		}
		catch (RuntimeException ex) {
			return arg; // not JSON after all: hash it as it is
		}
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
		String sig = stored.signature();
		return Boolean.parseBoolean(sig.substring(sig.indexOf('|') + 1, sig.lastIndexOf('|')));
	}
}
