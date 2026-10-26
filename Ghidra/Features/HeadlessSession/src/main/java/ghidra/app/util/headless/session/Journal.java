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

/**
 * The author journal of a writable program: one entry per committed change (and per save), in
 * commit order, saying who made it (client id, and the name and harness of the request that
 * made it), when, with which command, and what it changed: the operation, the address, the old
 * and the new value. Entries are numbered by {@code seq}, which only grows.
 * <p>
 * Changes to one program are committed one at a time (each under the program's exclusive lock,
 * in its own transaction), so the journal's order is the order in which the changes reached the
 * program: for any address and kind, the entry with the highest {@code seq} is the value the
 * program holds, until someone reverts it. Keeps the last {@link #CAP} entries.
 */
final class Journal {

	static final int CAP = 200_000;

	private final ArrayDeque<JsonObject> entries = new ArrayDeque<>();
	private long seq;
	private long dropped;

	/** Records a committed change by {@code c}; returns its {@code seq}. */
	synchronized long add(Client c, String cmd, JsonObject change) {
		Caller.Identity who = Caller.current(c);
		JsonObject e = Json.of("seq", ++seq, "at", System.currentTimeMillis(), "client", c.id,
			"name", who != null ? who.name() : c.name, "harness",
			who != null ? who.harness() : c.harness, "cmd", cmd);
		for (Map.Entry<String, JsonElement> f : change.entrySet()) {
			if (!e.has(f.getKey())) {
				e.add(f.getKey(), f.getValue());
			}
		}
		entries.add(e);
		if (entries.size() > CAP) {
			entries.poll();
			dropped++;
		}
		return seq;
	}

	synchronized long seq() {
		return seq;
	}

	synchronized long dropped() {
		return dropped;
	}

	/**
	 * Entries after {@code after}, of one client (or all when {@code client} is null), at most
	 * {@code limit}, oldest first.
	 */
	synchronized JsonArray since(long after, Integer client, int limit) {
		JsonArray a = new JsonArray();
		for (JsonObject e : entries) {
			if (e.get("seq").getAsLong() <= after) {
				continue;
			}
			if (client != null && e.get("client").getAsInt() != client) {
				continue;
			}
			if (a.size() >= limit) {
				break;
			}
			a.add(e.deepCopy());
		}
		return a;
	}

	/** Entries after {@code after}, newest first (for reverting). */
	synchronized List<JsonObject> newestFirst(long after) {
		List<JsonObject> out = new ArrayList<>();
		Iterator<JsonObject> it = entries.descendingIterator();
		while (it.hasNext()) {
			JsonObject e = it.next();
			if (e.get("seq").getAsLong() <= after) {
				break;
			}
			out.add(e);
		}
		return out;
	}

	/** The last change of {@code op} kind (rename/label share one) at an address, or null. */
	synchronized JsonObject lastAt(String address, String field) {
		Iterator<JsonObject> it = entries.descendingIterator();
		while (it.hasNext()) {
			JsonObject e = it.next();
			if (e.has("address") && address.equals(e.get("address").getAsString()) &&
				field.equals(fieldOf(e))) {
				return e;
			}
		}
		return null;
	}

	/** Which value of an address a change touches: {@code name}, {@code comment:<type>}, ... */
	static String fieldOf(JsonObject e) {
		String op = e.has("op") ? e.get("op").getAsString() : "";
		return switch (op) {
			case "rename", "label" -> "name";
			case "comment" -> "comment:" +
				(e.has("type") && !e.get("type").isJsonNull() ? e.get("type").getAsString() : "eol");
			default -> op;
		};
	}
}
