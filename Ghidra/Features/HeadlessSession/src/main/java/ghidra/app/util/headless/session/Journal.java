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

	/*
	 * Indexed (S21): the entries sit in a ring in seq order, and seq only grows by one per add,
	 * so the entry of a seq is found by arithmetic. Three indexes keep every lookup off a scan of
	 * the whole journal: the seqs of each rk, the seqs of each client (both oldest first), and the
	 * seq of the last entry of each address and field. Entries are never changed after add (the
	 * callers read them), so the indexes stay exact; dropping the oldest entry removes it from the
	 * front of its lists and from lastAt when it was still the last of its key.
	 */
	private final int cap;
	private JsonObject[] ring = new JsonObject[16];
	private int head;
	private int size;
	private final Map<String, LongRing> rkSeqs = new HashMap<>();
	private final Map<Integer, LongRing> clientSeqs = new HashMap<>();
	private final Map<String, Long> lastSeq = new HashMap<>();
	private long seq;
	private long dropped;

	Journal() {
		this(CAP);
	}

	/** A journal that keeps the last {@code cap} entries (the self-test uses a small one). */
	Journal(int cap) {
		this.cap = Math.max(1, cap);
	}

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
		append(e);
		return seq;
	}

	/** Appends {@code e}, whose {@code seq} is the next one, and drops the oldest over the cap. */
	private void append(JsonObject e) {
		long s = e.get("seq").getAsLong();
		if (size == ring.length) {
			JsonObject[] n = new JsonObject[Math.min(Math.max(16, ring.length * 2), cap + 1)];
			for (int i = 0; i < size; i++) {
				n[i] = ring[(head + i) % ring.length];
			}
			ring = n;
			head = 0;
		}
		ring[(head + size) % ring.length] = e;
		size++;
		String rk = rkOf(e);
		if (rk != null) {
			rkSeqs.computeIfAbsent(rk, k -> new LongRing()).add(s);
		}
		clientSeqs.computeIfAbsent(clientOf(e), k -> new LongRing()).add(s);
		String key = lastKey(e);
		if (key != null) {
			lastSeq.put(key, s);
		}
		if (size > cap) {
			JsonObject old = ring[head];
			ring[head] = null;
			head = (head + 1) % ring.length;
			size--;
			long os = old.get("seq").getAsLong();
			String ork = rkOf(old);
			if (ork != null) {
				pollFront(rkSeqs, ork);
			}
			pollFront(clientSeqs, clientOf(old));
			String ok = lastKey(old);
			if (ok != null) {
				lastSeq.remove(ok, os);
			}
			dropped++;
		}
	}

	private static <K> void pollFront(Map<K, LongRing> m, K k) {
		LongRing r = m.get(k);
		if (r != null) {
			r.removeFirst();
			if (r.size() == 0) {
				m.remove(k);
			}
		}
	}

	private static String rkOf(JsonObject e) {
		return e.has("rk") ? e.get("rk").getAsString() : null;
	}

	private static Integer clientOf(JsonObject e) {
		return e.get("client").getAsInt();
	}

	/** The lastAt key of an entry: its address and field, or null when it has no address. */
	private static String lastKey(JsonObject e) {
		if (!e.has("address")) {
			return null;
		}
		JsonElement a = e.get("address");
		if (!a.isJsonPrimitive()) {
			return null; // never a lastAt match (the old scan could not read it either)
		}
		return a.getAsString() + '\u0000' + fieldOf(e);
	}

	/** The entry of {@code s}, or null when it was dropped or is not yet written. */
	private JsonObject at(long s) {
		long first = seq - size + 1;
		if (s < first || s > seq) {
			return null;
		}
		return ring[(int) ((head + (s - first)) % ring.length)];
	}

	/**
	 * The entries that carry the idempotency key {@code rk} (v3 {@code edit}, {@code rename} and
	 * {@code comment}), oldest first, as copies. The window is this in-memory journal: an entry
	 * that was dropped is gone, and so is the whole journal after a restart.
	 */
	synchronized List<JsonObject> byRk(String rk) {
		List<JsonObject> out = new ArrayList<>();
		LongRing r = rkSeqs.get(rk);
		if (r == null) {
			return out;
		}
		for (int i = 0; i < r.size(); i++) {
			out.add(at(r.get(i)).deepCopy());
		}
		return out;
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
		if (limit <= 0 || size == 0 || after >= seq) {
			return a;
		}
		if (client == null) {
			long first = seq - size + 1;
			long from = after >= first ? after + 1 : first;
			for (long s = from; s <= seq && a.size() < limit; s++) {
				a.add(at(s).deepCopy());
			}
			return a;
		}
		LongRing r = clientSeqs.get(client);
		if (r == null) {
			return a;
		}
		for (int i = r.firstAbove(after); i < r.size() && a.size() < limit; i++) {
			a.add(at(r.get(i)).deepCopy());
		}
		return a;
	}

	/** Entries after {@code after}, newest first (for reverting). */
	synchronized List<JsonObject> newestFirst(long after) {
		List<JsonObject> out = new ArrayList<>();
		long first = seq - size + 1;
		for (long s = seq; s >= first && s > after; s--) {
			out.add(at(s));
		}
		return out;
	}

	/** The last change of {@code op} kind (rename/label share one) at an address, or null. */
	synchronized JsonObject lastAt(String address, String field) {
		Long s = lastSeq.get(address + '\u0000' + field);
		return s == null ? null : at(s);
	}

	/** A growable ring of seqs, ascending: add at the back, remove at the front. */
	private static final class LongRing {
		private long[] a = new long[4];
		private int head;
		private int size;

		void add(long v) {
			if (size == a.length) {
				long[] n = new long[a.length * 2];
				for (int i = 0; i < size; i++) {
					n[i] = a[(head + i) % a.length];
				}
				a = n;
				head = 0;
			}
			a[(head + size) % a.length] = v;
			size++;
		}

		void removeFirst() {
			head = (head + 1) % a.length;
			size--;
		}

		long get(int i) {
			return a[(head + i) % a.length];
		}

		int size() {
			return size;
		}

		/** The index of the first seq greater than {@code v} ({@code size} when none). */
		int firstAbove(long v) {
			int lo = 0;
			int hi = size;
			while (lo < hi) {
				int mid = (lo + hi) >>> 1;
				if (get(mid) <= v) {
					lo = mid + 1;
				}
				else {
					hi = mid;
				}
			}
			return lo;
		}
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
