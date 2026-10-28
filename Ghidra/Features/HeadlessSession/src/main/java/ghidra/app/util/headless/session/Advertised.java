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

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import com.google.gson.JsonObject;

/**
 * The advertisement registry of PROTOCOL-3.md 3.1 ("Who registers what"): the capabilities,
 * limits and policy values that {@code hello} and {@code status} report to a protocol 3 client.
 * <p>
 * Every <b>name</b> is declared here, up front and in the order the reply lists them, so that the
 * key order of the hello is stable and a typo cannot invent a key: registering a name that is not
 * declared throws. A package <b>enables</b> its own capability (and sets its own limits and
 * policy) from a class it owns, for example {@code Advertised.capability("queueInfo", 1)} in the
 * {@code Scheduler} constructor, and never edits {@code Session.java}. A name nobody registered is
 * absent from the reply, which is what a client must handle anyway (a capability a merged package
 * does not enable does not exist).
 */
final class Advertised {

	/** The capability names, in reply order (3.2). A capability's value is its integer version. */
	static final List<String> CAPABILITIES = List.of("errorNext", "expectAll", "idempotency",
		"laneHint", "maintLane", "queueInfo", "cancelWait", "forkReport", "format", "backup",
		"upgradeGate", "scriptIsolation", "scriptSha256", "attemptedChanges", "health", "identity");

	/** The limit names, in reply order. */
	static final List<String> LIMITS = List.of("maxQuick", "maxLong", "maxMaint", "maxImports",
		"quickScriptMaxS", "cleanupGraceS", "abandonWaitS", "maxRunningPerKey");

	/** The policy names, in reply order. */
	static final List<String> POLICY = List.of("requireBackupForUpgrade", "requireExpect");

	private static final Map<String, Integer> CAPS = new ConcurrentHashMap<>();
	private static final Map<String, Supplier<?>> LIMIT_VALUES = new ConcurrentHashMap<>();
	private static final Map<String, Supplier<?>> POLICY_VALUES = new ConcurrentHashMap<>();

	private Advertised() {
	}

	/**
	 * Enables a capability at an integer version (raise it for a new minor feature; a new protocol
	 * is not needed). Registering the same name again replaces the version.
	 *
	 * @throws IllegalArgumentException when the name is not in {@link #CAPABILITIES}
	 */
	static void capability(String name, int version) {
		declared(CAPABILITIES, "capability", name);
		if (version < 1) {
			throw new IllegalArgumentException("capability " + name + ": version must be >= 1");
		}
		CAPS.put(name, version);
	}

	/**
	 * Sets a limit; the value is read each time a reply is built (a number, a boolean, a string or
	 * a JSON element).
	 *
	 * @throws IllegalArgumentException when the name is not in {@link #LIMITS}
	 */
	static void limit(String name, Supplier<?> value) {
		declared(LIMITS, "limit", name);
		LIMIT_VALUES.put(name, Objects.requireNonNull(value));
	}

	/**
	 * Sets a policy value, read each time a reply is built.
	 *
	 * @throws IllegalArgumentException when the name is not in {@link #POLICY}
	 */
	static void policy(String name, Supplier<?> value) {
		declared(POLICY, "policy", name);
		POLICY_VALUES.put(name, Objects.requireNonNull(value));
	}

	/** The enabled capabilities, in declaration order. */
	static JsonObject capabilities() {
		JsonObject o = new JsonObject();
		for (String n : CAPABILITIES) {
			Integer v = CAPS.get(n);
			if (v != null) {
				o.addProperty(n, v);
			}
		}
		return o;
	}

	/** The limits that were set, in declaration order. */
	static JsonObject limits() {
		return render(LIMITS, LIMIT_VALUES);
	}

	/** The policy values that were set, in declaration order. */
	static JsonObject policy() {
		return render(POLICY, POLICY_VALUES);
	}

	private static JsonObject render(List<String> order, Map<String, Supplier<?>> values) {
		JsonObject o = new JsonObject();
		for (String n : order) {
			Supplier<?> s = values.get(n);
			if (s != null) {
				Json.put(o, n, s.get());
			}
		}
		return o;
	}

	private static void declared(List<String> names, String what, String name) {
		if (!names.contains(name)) {
			throw new IllegalArgumentException("unknown " + what + " '" + name +
				"': it is not declared in Advertised (declared: " + String.join(", ", names) + ")");
		}
	}
}
