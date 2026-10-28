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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The generic engine settings of PROTOCOL-3.md 3.7: every {@code -set key=value} flag of the
 * command line (the launcher passes each entry of the {@code engine} object of {@code config.json}
 * this way) is stored here, and each package reads its own keys in its own classes
 * ({@code Settings.integer("maintSlots", 2)}), so no package adds a flag of its own to the option
 * parser. A repeated key keeps its last value. An unset key reads as the default the reader names.
 * <p>
 * A value that does not parse as the type the reader asked for is an
 * {@link IllegalArgumentException} naming the key and the value, never a silent default.
 */
final class Settings {

	/** What the launcher allows as a key (it validates the same way before it starts the JVM). */
	static final Pattern KEY = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]{0,63}");

	private static final Map<String, String> VALUES =
		Collections.synchronizedMap(new LinkedHashMap<>());

	private Settings() {
	}

	/**
	 * Stores one {@code key=value} (the text after {@code -set}).
	 *
	 * @throws IllegalArgumentException when there is no {@code =} or the key is not an identifier
	 */
	static void set(String keyValue) {
		int eq = keyValue.indexOf('=');
		if (eq < 0) {
			throw new IllegalArgumentException("-set needs key=value, not '" + keyValue + "'");
		}
		set(keyValue.substring(0, eq), keyValue.substring(eq + 1));
	}

	static void set(String key, String value) {
		if (!KEY.matcher(key).matches()) {
			throw new IllegalArgumentException("-set: bad key '" + key +
				"' (letters, digits, . _ -, starting with a letter)");
		}
		VALUES.put(key, value);
	}

	static boolean has(String key) {
		return VALUES.containsKey(key);
	}

	static String string(String key, String dflt) {
		String v = VALUES.get(key);
		return v == null ? dflt : v;
	}

	static int integer(String key, int dflt) {
		String v = VALUES.get(key);
		if (v == null) {
			return dflt;
		}
		try {
			return Integer.parseInt(v.trim());
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("-set " + key + "=" + v + ": not an integer");
		}
	}

	/** {@code true} or {@code false}, exactly as the launcher writes a JSON boolean. */
	static boolean bool(String key, boolean dflt) {
		String v = VALUES.get(key);
		if (v == null) {
			return dflt;
		}
		return switch (v.trim()) {
			case "true" -> true;
			case "false" -> false;
			default -> throw new IllegalArgumentException(
				"-set " + key + "=" + v + ": not true or false");
		};
	}

	/** A copy of every setting, in the order given. */
	static Map<String, String> all() {
		synchronized (VALUES) {
			return new LinkedHashMap<>(VALUES);
		}
	}

	/** Forgets every setting (the self-test). */
	static void clear() {
		VALUES.clear();
	}
}
