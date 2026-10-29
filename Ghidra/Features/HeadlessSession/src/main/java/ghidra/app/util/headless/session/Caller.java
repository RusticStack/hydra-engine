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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Who a single request speaks for. A connection has one identity ({@link Client#name},
 * {@link Client#harness}, set by {@code hello}), but one connection can carry several callers (an
 * MCP server serving several agents). A request may therefore carry its own {@code client} and/or
 * {@code harness} label, which replaces the connection's value for that request only.
 * <p>
 * The label names the request in everything that tells people who is doing what ({@code busy} and
 * {@code conflict} holders, {@code status}, the import queue) and scopes {@code cancel}: a
 * labelled {@code cancel all} reaches only the requests of that same label. It changes nothing
 * about ownership: a program is still owned by the connection that opened it writable.
 * <p>
 * The identity of the request being executed is kept in a thread local set by
 * {@link Connection} around {@link Session#execute}, so that the many places that describe
 * "who is doing this now" do not each need another parameter.
 */
final class Caller {

	private static final int MAX_LABEL = 128;

	/** The effective identity of one request. */
	record Identity(String name, String harness, boolean labelled) {

		/** The key that scopes cancellation: the effective pair, for labelled requests. */
		String scope() {
			return labelled ? name + '\u0000' + harness : null;
		}
	}

	private static final ThreadLocal<Request> CURRENT = new ThreadLocal<>();

	private record Request(Client client, Identity identity, RequestMonitor monitor) {
	}

	private Caller() {
		// utility class
	}

	/**
	 * The identity a request speaks with: its own {@code client} and {@code harness} fields where
	 * present, else the connection's.
	 */
	static Identity of(Client c, JsonObject req) {
		String name = field(req, "client");
		String harness = field(req, "harness");
		return new Identity(name != null ? name : c.name, harness != null ? harness : c.harness,
			name != null || harness != null);
	}

	private static String field(JsonObject req, String key) {
		JsonElement e = req.get(key);
		if (e == null || e.isJsonNull()) {
			return null;
		}
		if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"\"" + key + "\" is a label: a string");
		}
		String s = e.getAsString().strip();
		if (s.length() > MAX_LABEL) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"\"" + key + "\" is longer than " + MAX_LABEL + " characters");
		}
		return s.isEmpty() ? null : s;
	}

	static void enter(Client c, Identity id) {
		CURRENT.set(new Request(c, id, null));
	}

	/**
	 * Like {@link #enter(Client, Identity)}, and also stores the request's monitor: the lock waits
	 * of the request ({@link Waits}) register with it so that {@code cancel} reaches them.
	 */
	static void enter(Client c, Identity id, RequestMonitor m) {
		CURRENT.set(new Request(c, id, m));
	}

	/** The monitor of the request this thread executes, or null (a cleanup wait has none). */
	static RequestMonitor monitor() {
		Request r = CURRENT.get();
		return r == null ? null : r.monitor;
	}

	/** The client of the request this thread executes, or null. */
	static Client client() {
		Request r = CURRENT.get();
		return r == null ? null : r.client;
	}

	static void leave() {
		CURRENT.remove();
	}

	/** The identity of the request this thread runs for {@code c}, or null. */
	static Identity current(Client c) {
		Request r = CURRENT.get();
		return r != null && r.client == c ? r.identity : null;
	}

	/**
	 * How to name {@code c} for the request this thread executes: the request's label when it is
	 * {@code c}'s own request, else the connection's.
	 */
	static String label(Client c) {
		Identity id = current(c);
		return id == null ? c.label() : c.label(id.name(), id.harness());
	}
}
