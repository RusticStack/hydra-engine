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
import java.util.Set;

import com.google.gson.*;
import com.google.gson.internal.LazilyParsedNumber;

/**
 * The raw request path of the trace reads ({@code trace_query}, {@code trace_explain},
 * {@code trace_diff}, {@code trace_check} with {@code persist:false}): the request line is scanned
 * once, on its bytes, for the few top-level scalar fields the daemon's own stages read (id, cmd,
 * the caller labels, the session ids, the lane and wait fields), and the line itself is what the
 * engine receives. No Gson tree is built for the engine's own fields (the filter, the assertions,
 * the list of kinds), and nothing is copied back out of one.
 * <p>
 * The scan is conservative: any request it does not recognise with certainty (a field only Java
 * handles, a non-string session id, a duplicate key, text that is not strict JSON at the top level)
 * gives {@code null} and the request takes the ordinary path, so every error is the ordinary one.
 */
final class TraceFast {

	/** What the scan found: the light request (top-level scalars only), the id and the command. */
	record Scanned(JsonObject req, JsonElement id, String cmd) {
	}

	private static final Set<String> RAW_COMMANDS =
		Set.of("trace_query", "trace_explain", "trace_diff", "trace_check", "trace_append");
	/**
	 * Fields Java consumes before or instead of the engine: their presence ends the fast path.
	 * ({@code cap} is the writer's own capability: {@code trace_append} carries it, nothing else here.)
	 */
	private static final Set<String> JAVA_FIELDS = Set.of("create", "mode", "takeover",
		"program", "project", "modules", "background", "name");
	/** Fields the daemon's generic stages read: they must be scalars. */
	private static final Set<String> SCALAR_ONLY = Set.of("id", "cmd", "client", "harness",
		"parallel", "ordered", "artifact", "overlay", "wait", "waitMs", "timeout", "lane", "token",
		"session", "a", "b", "persist", "deadline", "deadlineMs", "op", "cap");

	private TraceFast() {
	}

	/** Whether the line can be a raw trace read at all (a cheap test before the scan). */
	static boolean candidate(byte[] line) {
		int n = Math.min(line.length, 320);
		for (int i = 0; i + 6 < n; i++) {
			if (line[i] == 't' && line[i + 1] == 'r' && line[i + 2] == 'a' && line[i + 3] == 'c' &&
				line[i + 4] == 'e' && line[i + 5] == '_') {
				return true;
			}
		}
		return false;
	}

	/** The scan of {@code line}, or null when the request takes the ordinary path. */
	static Scanned scan(byte[] line) {
		try {
			return new Scan(line).run();
		}
		catch (RuntimeException e) {
			return null; // anything unexpected: the ordinary path reports it
		}
	}

	private static final class Scan {
		private final byte[] b;
		private int i;

		Scan(byte[] b) {
			this.b = b;
		}

		private void ws() {
			while (i < b.length && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n')) {
				i++;
			}
		}

		Scanned run() {
			ws();
			if (i >= b.length || b[i] != '{') {
				return null;
			}
			i++;
			JsonObject req = new JsonObject();
			boolean eventsArray = false;
			ws();
			if (i < b.length && b[i] == '}') {
				return null;
			}
			while (true) {
				ws();
				if (i >= b.length || b[i] != '"') {
					return null;
				}
				String key = string();
				if (key == null || req.has(key) || JAVA_FIELDS.contains(key)) {
					return null;
				}
				ws();
				if (i >= b.length || b[i] != ':') {
					return null;
				}
				i++;
				ws();
				if (i >= b.length) {
					return null;
				}
				byte c = b[i];
				if (c == '{' || c == '[') {
					// an engine-only structure is not part of the light request
					eventsArray |= key.equals("events") && c == '[';
					if (SCALAR_ONLY.contains(key) || !skip()) {
						return null;
					}
				}
				else {
					JsonElement v = scalar();
					if (v == null) {
						return null;
					}
					req.add(key, v);
				}
				ws();
				if (i >= b.length) {
					return null;
				}
				if (b[i] == ',') {
					i++;
					continue;
				}
				if (b[i] == '}') {
					i++;
					break;
				}
				return null;
			}
			ws();
			if (i != b.length) {
				return null;
			}
			JsonElement cmdEl = req.get("cmd");
			if (cmdEl == null || !cmdEl.isJsonPrimitive() ||
				!cmdEl.getAsJsonPrimitive().isString()) {
				return null;
			}
			String cmd = cmdEl.getAsString();
			if (!RAW_COMMANDS.contains(cmd)) {
				return null;
			}
			JsonElement id = req.get("id");
			if (id != null && !id.isJsonPrimitive()) {
				return null;
			}
			if (req.has("cap") && !cmd.equals("trace_append")) {
				return null; // a capability on a read: the ordinary path decides
			}
			if (cmd.equals("trace_append")) {
				if (!eventsArray || req.has("events")) {
					return null; // events must be an array: the ordinary path says so otherwise
				}
				req.add("events", new JsonArray()); // stands for the array, which the engine reads
			}
			if (cmd.equals("trace_check")) {
				// the ordinary path tells the engine persist:false; here the client must say so
				JsonElement p = req.get("persist");
				if (p == null || !p.isJsonPrimitive() || !p.getAsJsonPrimitive().isBoolean() ||
					p.getAsBoolean()) {
					return null;
				}
			}
			return new Scanned(req, id, cmd);
		}

		/** A string at {@code i} (on its opening quote), decoded; moves past the closing quote. */
		private String string() {
			int start = ++i;
			boolean escaped = false;
			while (i < b.length) {
				byte c = b[i];
				if (c == '\\') {
					escaped = true;
					i += 2;
					continue;
				}
				if (c == '"') {
					break;
				}
				if (c < 0x20) {
					return null;
				}
				i++;
			}
			if (i >= b.length) {
				return null;
			}
			String raw = new String(b, start, i - start, StandardCharsets.UTF_8);
			i++;
			if (!escaped) {
				return raw;
			}
			return JsonParser.parseString("\"" + raw + "\"").getAsString();
		}

		private JsonElement scalar() {
			byte c = b[i];
			if (c == '"') {
				String s = string();
				return s == null ? null : new JsonPrimitive(s);
			}
			int start = i;
			while (i < b.length && b[i] != ',' && b[i] != '}' && b[i] != ' ' && b[i] != '\t' &&
				b[i] != '\r' && b[i] != '\n') {
				i++;
			}
			String t = new String(b, start, i - start, StandardCharsets.US_ASCII);
			switch (t) {
				case "true":
					return new JsonPrimitive(true);
				case "false":
					return new JsonPrimitive(false);
				case "null":
					return JsonNull.INSTANCE;
				default:
					break;
			}
			if (t.isEmpty()) {
				return null;
			}
			for (int k = 0; k < t.length(); k++) {
				char ch = t.charAt(k);
				if (!(ch >= '0' && ch <= '9') && ch != '-' && ch != '+' && ch != '.' && ch != 'e' &&
					ch != 'E') {
					return null;
				}
			}
			return new JsonPrimitive(new LazilyParsedNumber(t));
		}

		/** Skips one object or array at {@code i}, checking only that the brackets nest. */
		private boolean skip() {
			byte[] stack = new byte[64];
			int depth = 0;
			while (i < b.length) {
				byte c = b[i];
				if (c == '"') {
					i++;
					while (i < b.length && b[i] != '"') {
						i += b[i] == '\\' ? 2 : 1;
					}
					if (i >= b.length) {
						return false;
					}
					i++;
					continue;
				}
				if (c == '{' || c == '[') {
					if (depth == stack.length) {
						return false;
					}
					stack[depth++] = (byte) (c == '{' ? '}' : ']');
				}
				else if (c == '}' || c == ']') {
					if (depth == 0 || stack[--depth] != c) {
						return false;
					}
					if (depth == 0) {
						i++;
						return true;
					}
				}
				i++;
			}
			return false;
		}
	}
}
