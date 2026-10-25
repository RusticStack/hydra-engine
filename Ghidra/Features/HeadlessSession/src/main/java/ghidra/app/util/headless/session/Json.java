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

import java.util.*;

import com.google.gson.*;

/** Small, strict accessors for request fields. Every failure is a {@code bad_request}. */
final class Json {

	static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

	private Json() {
	}

	static boolean has(JsonObject o, String k) {
		return o.has(k) && !o.get(k).isJsonNull();
	}

	static String str(JsonObject o, String k) {
		if (!has(o, k)) {
			throw new SessionException(SessionException.BAD_REQUEST, "missing field: " + k);
		}
		return primitive(o, k).getAsString();
	}

	static String str(JsonObject o, String k, String dflt) {
		return has(o, k) ? primitive(o, k).getAsString() : dflt;
	}

	static boolean bool(JsonObject o, String k, boolean dflt) {
		if (!has(o, k)) {
			return dflt;
		}
		JsonPrimitive p = primitive(o, k);
		if (!p.isBoolean()) {
			throw new SessionException(SessionException.BAD_REQUEST, k + " must be true or false");
		}
		return p.getAsBoolean();
	}

	static long num(JsonObject o, String k, long dflt, long min, long max) {
		if (!has(o, k)) {
			return dflt;
		}
		JsonPrimitive p = primitive(o, k);
		long v;
		try {
			v = p.getAsLong();
		}
		catch (NumberFormatException e) {
			throw new SessionException(SessionException.BAD_REQUEST, k + " must be a number");
		}
		if (v < min || v > max) {
			throw new SessionException(SessionException.BAD_REQUEST,
				k + " must be between " + min + " and " + max);
		}
		return v;
	}

	static List<String> strings(JsonObject o, String k) {
		if (!has(o, k)) {
			return List.of();
		}
		if (!o.get(k).isJsonArray()) {
			throw new SessionException(SessionException.BAD_REQUEST, k + " must be an array");
		}
		List<String> out = new ArrayList<>();
		for (JsonElement e : o.getAsJsonArray(k)) {
			if (!e.isJsonPrimitive()) {
				throw new SessionException(SessionException.BAD_REQUEST,
					k + " must be an array of strings");
			}
			out.add(e.getAsString());
		}
		return out;
	}

	static JsonObject obj(JsonObject o, String k) {
		if (!has(o, k)) {
			return null;
		}
		if (!o.get(k).isJsonObject()) {
			throw new SessionException(SessionException.BAD_REQUEST, k + " must be an object");
		}
		return o.getAsJsonObject(k);
	}

	private static JsonPrimitive primitive(JsonObject o, String k) {
		JsonElement e = o.get(k);
		if (!e.isJsonPrimitive()) {
			throw new SessionException(SessionException.BAD_REQUEST, k + " must be a scalar");
		}
		return e.getAsJsonPrimitive();
	}

	static JsonObject of(Object... kv) {
		JsonObject o = new JsonObject();
		for (int i = 0; i < kv.length; i += 2) {
			put(o, (String) kv[i], kv[i + 1]);
		}
		return o;
	}

	static void put(JsonObject o, String k, Object v) {
		if (v == null) {
			o.add(k, JsonNull.INSTANCE);
		}
		else if (v instanceof JsonElement e) {
			o.add(k, e);
		}
		else if (v instanceof Boolean b) {
			o.addProperty(k, b);
		}
		else if (v instanceof Number n) {
			o.addProperty(k, n);
		}
		else if (v instanceof Collection<?> c) {
			JsonArray a = new JsonArray();
			for (Object x : c) {
				a.add(x == null ? JsonNull.INSTANCE
						: x instanceof Number n ? new JsonPrimitive(n)
								: new JsonPrimitive(String.valueOf(x)));
			}
			o.add(k, a);
		}
		else {
			o.addProperty(k, String.valueOf(v));
		}
	}
}
