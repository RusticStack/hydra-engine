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
import java.util.concurrent.CopyOnWriteArrayList;

import com.google.gson.JsonObject;

/**
 * The request-validation registry of PROTOCOL-3.md 3.5 ("Validate-before-wait"). A command's own
 * validation is extracted into one method that the command and this registry both call, so the
 * two cannot drift; the scheduler runs {@link #run} for a protocol 3 request that would have to
 * queue, before it queues. E3a registers the generic checks under {@link #ALL}, E2 registers
 * {@code fork_project}'s and E4 {@code script}'s, each from a class it owns.
 * <p>
 * This is only the registry (package E1): nothing calls {@link #run} yet, so no request is
 * validated earlier than it is today.
 */
final class Preflight {

	/** The key of the checks that run for every command. */
	static final String ALL = "*";

	/** A validation: throws a {@link SessionException} (normally {@code bad_request}) to refuse. */
	@FunctionalInterface
	interface Check {
		void check(String cmd, JsonObject req);
	}

	private static final Map<String, List<Check>> CHECKS = new ConcurrentHashMap<>();

	private Preflight() {
	}

	/**
	 * Registers a check for a command, or for every command under {@link #ALL}. Checks of one key
	 * run in registration order.
	 */
	static void register(String cmd, Check check) {
		if (cmd == null || cmd.isBlank()) {
			throw new IllegalArgumentException("Preflight: a command name or \"*\" is needed");
		}
		CHECKS.computeIfAbsent(cmd, k -> new CopyOnWriteArrayList<>())
				.add(Objects.requireNonNull(check));
	}

	/** How many checks run for {@code cmd}: its own and those of {@link #ALL}. */
	static int count(String cmd) {
		return CHECKS.getOrDefault(ALL, List.of()).size() +
			CHECKS.getOrDefault(cmd, List.of()).size();
	}

	/**
	 * Runs the checks of {@link #ALL}, then those of {@code cmd}; the first refusal propagates.
	 * With nothing registered it does nothing.
	 */
	static void run(String cmd, JsonObject req) {
		for (Check c : CHECKS.getOrDefault(ALL, List.of())) {
			c.check(cmd, req);
		}
		for (Check c : CHECKS.getOrDefault(cmd, List.of())) {
			c.check(cmd, req);
		}
	}
}
