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
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import com.google.gson.JsonObject;

/**
 * One connected caller. Like a tool window, each client has an <i>active project</i> and an
 * <i>active program</i>: what commands act on when they name neither. Projects and programs
 * themselves are shared by the session: two clients that open the same one use the same instance.
 */
final class Client {

	final int id;
	/** {@code stdio} or {@code socket}. */
	final String transport;
	/** The stdio client is the process that launched the session; it may always shut it down. */
	final boolean launcher;
	final long connectedAt = System.currentTimeMillis();

	volatile String name = "";
	volatile String harness = "";
	volatile boolean authenticated;
	/** Set when its connection reached end of input; its cleanup may still be running. */
	volatile boolean leaving;

	/** Ids of the projects this client has joined, in join order. */
	final Set<String> projects = Collections.synchronizedSet(new LinkedHashSet<>());
	volatile String activeProject;

	/** Keys ({@link ProgramEntry#key}) of the programs this client has open, in open order. */
	final Set<String> programs = Collections.synchronizedSet(new LinkedHashSet<>());
	/** Key of the active program. */
	volatile String active;

	/** Requests of this client not yet answered (queued or running), by request id. */
	final Map<String, RequestMonitor> running = new ConcurrentHashMap<>();

	/** Sends an unsolicited line (progress events) to this client. */
	final Consumer<JsonObject> events;

	Client(int id, String transport, boolean launcher, Consumer<JsonObject> events) {
		this.id = id;
		this.transport = transport;
		this.launcher = launcher;
		this.events = events;
	}

	String label() {
		StringBuilder sb = new StringBuilder("client ").append(id);
		if (!name.isEmpty() || !harness.isEmpty()) {
			sb.append(" (").append(name);
			if (!harness.isEmpty()) {
				sb.append(name.isEmpty() ? "" : ", ").append(harness);
			}
			sb.append(')');
		}
		return sb.toString();
	}

	/**
	 * Who this client is, for the {@code holder} of {@code busy}, {@code conflict} and
	 * {@code not_owner} answers: {@code {client, name, harness, label}}.
	 */
	JsonObject identity() {
		return Json.of("client", id, "name", name, "harness", harness, "label", label());
	}

	/**
	 * A holder record: this client's identity plus what it is doing ({@code command}) and for how
	 * long ({@code heldMs}, from {@code since}, epoch milliseconds; omitted when 0).
	 */
	JsonObject holder(String command, long since) {
		JsonObject o = identity();
		Json.put(o, "command", command);
		if (since > 0) {
			Json.put(o, "heldMs", System.currentTimeMillis() - since);
		}
		return o;
	}

	JsonObject describe() {
		JsonObject o = Json.of("id", id, "name", name, "harness", harness, "transport", transport,
			"launcher", launcher, "activeProject", activeProject, "active", active,
			"connectedMs", System.currentTimeMillis() - connectedAt);
		synchronized (projects) {
			Json.put(o, "projects", new ArrayList<>(projects));
		}
		synchronized (programs) {
			Json.put(o, "programs", new ArrayList<>(programs));
		}
		Json.put(o, "running", new ArrayList<>(running.keySet()));
		return o;
	}
}
