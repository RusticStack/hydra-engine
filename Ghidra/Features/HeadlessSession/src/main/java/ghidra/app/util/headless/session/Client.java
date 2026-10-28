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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

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
	/** The {@code CLIENT_VERSION} the client said in {@code hello}, if it did. */
	volatile String clientVersion = "";
	volatile boolean authenticated;

	/**
	 * The protocol this connection speaks, fixed by its first {@code hello} for its whole life
	 * (PROTOCOL-3.md 3.1): 2 until then, and whatever the first {@code hello} negotiated after.
	 * Written once by {@link #negotiate} before that hello is answered, and read-only afterwards,
	 * so every reply, event and gating decision of the connection sees a final value.
	 */
	private volatile int protocol = HydraInfo.PROTOCOL;
	private boolean protocolFixed; // guarded by this
	/** Set when its connection reached end of input; its cleanup may still be running. */
	volatile boolean leaving;

	/** Ids of the projects this client has joined, in join order. */
	final Set<String> projects = Collections.synchronizedSet(new LinkedHashSet<>());
	volatile String activeProject;

	/** Keys ({@link ProgramEntry#key}) of the programs this client has open, in open order. */
	final Set<String> programs = Collections.synchronizedSet(new LinkedHashSet<>());
	/** Key of the active program. */
	volatile String active;

	/** The {@link ProjectEntry#generation} of each joined project this client last saw. */
	final Map<String, Integer> seenGeneration = new ConcurrentHashMap<>();

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

	/** The protocol of this connection: 2, or 3 when its first {@code hello} asked for it. */
	int protocol() {
		return protocol;
	}

	/** True on a protocol 3 connection: the one test every v3 gate makes. */
	boolean v3() {
		return protocol >= 3;
	}

	/**
	 * Fixes the protocol from a {@code hello} request, if no {@code hello} has fixed it yet; a
	 * later call (a second {@code hello}) changes nothing. Returns the connection's protocol.
	 */
	synchronized int negotiate(JsonObject hello) {
		if (!protocolFixed) {
			protocol = requestedProtocol(hello);
			protocolFixed = true;
		}
		return protocol;
	}

	/**
	 * The protocol a {@code hello} asks for, as the engine answers it: the requested value when it
	 * lies in {@code [PROTOCOL_MIN, PROTOCOL_MAX]}, {@code PROTOCOL_MAX} when it is larger, and
	 * {@code PROTOCOL_MIN} when the field is absent, smaller, or not a JSON integer (a string, a
	 * float, a boolean, {@code null}: such a request is not refused, so no existing client can be
	 * broken by the type of the field).
	 */
	static int requestedProtocol(JsonObject hello) {
		JsonElement e = hello.get("protocol");
		if (e == null || !e.isJsonPrimitive()) {
			return HydraInfo.PROTOCOL_MIN;
		}
		JsonPrimitive p = e.getAsJsonPrimitive();
		if (!p.isNumber() || !p.getAsString().matches("-?[0-9]+")) {
			return HydraInfo.PROTOCOL_MIN;
		}
		java.math.BigInteger v = new java.math.BigInteger(p.getAsString());
		if (v.compareTo(java.math.BigInteger.valueOf(HydraInfo.PROTOCOL_MAX)) >= 0) {
			return HydraInfo.PROTOCOL_MAX;
		}
		if (v.compareTo(java.math.BigInteger.valueOf(HydraInfo.PROTOCOL_MIN)) <= 0) {
			return HydraInfo.PROTOCOL_MIN; // before intValue(), which wraps to the low 32 bits
		}
		return v.intValue();
	}

	String label() {
		return label(name, harness);
	}

	/** This client's label with another name and harness (a request's own labels). */
	String label(String n, String h) {
		StringBuilder sb = new StringBuilder("client ").append(id);
		if (!n.isEmpty() || !h.isEmpty()) {
			sb.append(" (").append(n);
			if (!h.isEmpty()) {
				sb.append(n.isEmpty() ? "" : ", ").append(h);
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
		return identity(null);
	}

	/** Like {@link #identity()}, named as the request that carried {@code who} named itself. */
	JsonObject identity(Caller.Identity who) {
		if (who == null) {
			return Json.of("client", id, "name", name, "harness", harness, "label", label());
		}
		return Json.of("client", id, "name", who.name(), "harness", who.harness(), "label",
			label(who.name(), who.harness()));
	}

	/**
	 * A holder record: this client's identity plus what it is doing ({@code command}) and for how
	 * long ({@code heldMs}, from {@code since}, epoch milliseconds; omitted when 0).
	 */
	JsonObject holder(String command, long since) {
		return holder(command, since, null);
	}

	JsonObject holder(String command, long since, Caller.Identity who) {
		JsonObject o = identity(who);
		Json.put(o, "command", command);
		if (since > 0) {
			Json.put(o, "heldMs", System.currentTimeMillis() - since);
		}
		return o;
	}

	JsonObject describe() {
		JsonObject o = Json.of("id", id, "name", name, "harness", harness, "transport", transport,
			"launcher", launcher, "clientVersion", clientVersion, "activeProject", activeProject, "active", active,
			"connectedMs", System.currentTimeMillis() - connectedAt);
		synchronized (projects) {
			Json.put(o, "projects", new ArrayList<>(projects));
		}
		synchronized (programs) {
			Json.put(o, "programs", new ArrayList<>(programs));
		}
		Json.put(o, "running", new ArrayList<>(running.keySet()));
		JsonArray rq = new JsonArray();
		for (RequestMonitor r : running.values()) {
			rq.add(r.describe());
		}
		o.add("requests", rq);
		return o;
	}
}
