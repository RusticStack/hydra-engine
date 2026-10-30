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
import java.util.concurrent.atomic.AtomicReferenceArray;

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
 * <p>
 * <b>Why one ordered log and not one segment per writer.</b> {@code seq} is the program's commit
 * order (README "journal": {@code seq} (commit order); "the journal complete and ordered, the
 * program holding each value's last edit"), and {@code discard_edits} walks it newest first across
 * all clients. The order is made by the program's exclusive lock, which the
 * commit itself holds, so appending here adds no turn among writers: there is never a second
 * writer of one program's journal at a time, and every program has its own journal (its own
 * log). What this class removes is the turn between <i>readers</i> and the writer, and among
 * readers: before, every read ({@code journal}, {@code byRk}, {@code lastAt}, the
 * {@code status} fields) took the journal's monitor and scanned the whole deque (O(N), up to
 * 200,000 entries) while an edit waited for it.
 * <p>
 * Now an entry is immutable once appended and is published by a volatile {@code seq}; readers
 * take no lock. Entries live in a ring of lazily allocated chunks indexed by {@code seq}, so a
 * read of the entries after {@code since} costs what it returns, {@code byRk} and
 * {@code lastAt} are O(1) through indexes kept by the writer, and the dropped prefix is implied
 * by {@code seq - CAP}. A reader that races an eviction checks the slot's {@code seq} and skips
 * an entry that was dropped meanwhile, exactly as if it had read just after the drop.
 */
final class Journal {

	static final int CAP = 200_000;

	/** Entries per ring chunk; chunks are allocated on first use, so a small journal stays small. */
	private static final int CHUNK = 4096;
	/** Ring size in slots: more than {@link #CAP}, so a slot is reused only after its entry was dropped. */
	private static final int CHUNKS = CAP / CHUNK + 2;
	private static final long RING = (long) CHUNKS * CHUNK;

	/** One appended entry with its {@code seq} beside it, so readers never parse it to check. */
	private record Slot(long seq, JsonObject e) {
	}

	private final AtomicReferenceArray<AtomicReferenceArray<Slot>> ring =
		new AtomicReferenceArray<>(CHUNKS);
	/** The last appended {@code seq}: the publication point readers synchronise on. */
	private volatile long seq;
	/**
	 * The {@code seq}s of the held entries of each idempotency key, oldest first. One {@code edit}
	 * journals every op of its batch under one key, so appending and dropping are amortised O(1)
	 * per entry (see {@link SeqRun}), never a copy of the key's whole list.
	 */
	private final ConcurrentHashMap<String, SeqRun> rkIndex = new ConcurrentHashMap<>();
	/** The {@code seq} of the newest entry per (address, field), for {@link #lastAt}. */
	private final ConcurrentHashMap<String, Long> lastIndex = new ConcurrentHashMap<>();
	/**
	 * Appends are one at a time per program anyway (the commit's exclusive lock); this monitor only
	 * keeps that true if a caller ever journals outside it. Readers never take it.
	 */
	private final Object append = new Object();

	/** Records a committed change by {@code c}; returns its {@code seq}. */
	long add(Client c, String cmd, JsonObject change) {
		Caller.Identity who = Caller.current(c);
		synchronized (append) {
			long s = seq + 1;
			JsonObject e = Json.of("seq", s, "at", System.currentTimeMillis(), "client", c.id,
				"name", who != null ? who.name() : c.name, "harness",
				who != null ? who.harness() : c.harness, "cmd", cmd);
			for (Map.Entry<String, JsonElement> f : change.entrySet()) {
				if (!e.has(f.getKey())) {
					e.add(f.getKey(), f.getValue());
				}
			}
			if (s > CAP) {
				evict(s - CAP); // the entry the cap drops now
			}
			put(s, e);
			if (e.has("rk")) {
				String rk = e.get("rk").getAsString();
				SeqRun r = rkIndex.get(rk);
				rkIndex.put(rk, r == null ? SeqRun.of(s) : r.plus(s));
			}
			String k = lastKey(e);
			if (k != null) {
				lastIndex.put(k, s);
			}
			seq = s; // publish: everything above happens-before a reader that sees s
			return s;
		}
	}

	/**
	 * The entries that carry the idempotency key {@code rk} (v3 {@code edit}, {@code rename} and
	 * {@code comment}), oldest first, as copies. The window is this in-memory journal: an entry
	 * that was dropped is gone, and so is the whole journal after a restart.
	 */
	List<JsonObject> byRk(String rk) {
		List<JsonObject> out = new ArrayList<>();
		SeqRun run = rkIndex.get(rk);
		if (run == null) {
			return out;
		}
		long lo = oldest(seq);
		for (int i = run.from; i < run.to; i++) {
			long s = run.seqs[i];
			JsonObject e = s >= lo ? get(s) : null;
			if (e != null) {
				out.add(e.deepCopy());
			}
		}
		return out;
	}

	long seq() {
		return seq;
	}

	long dropped() {
		return Math.max(0, seq - CAP);
	}

	/**
	 * Entries after {@code after}, of one client (or all when {@code client} is null), at most
	 * {@code limit}, oldest first.
	 */
	JsonArray since(long after, Integer client, int limit) {
		JsonArray a = new JsonArray();
		long hi = seq;
		if (after >= hi) {
			return a;
		}
		for (long s = Math.max(after + 1, oldest(hi)); s <= hi && a.size() < limit; s++) {
			JsonObject e = get(s);
			if (e == null || client != null && e.get("client").getAsInt() != client) {
				continue;
			}
			a.add(e.deepCopy());
		}
		return a;
	}

	/** Entries after {@code after}, newest first (for reverting). */
	List<JsonObject> newestFirst(long after) {
		List<JsonObject> out = new ArrayList<>();
		long hi = seq;
		for (long s = hi, lo = Math.max(after + 1, oldest(hi)); s >= lo; s--) {
			JsonObject e = get(s);
			if (e != null) {
				out.add(e);
			}
		}
		return out;
	}

	/** The last change of {@code op} kind (rename/label share one) at an address, or null. */
	JsonObject lastAt(String address, String field) {
		Long s = lastIndex.get(address + '\n' + field);
		return s == null ? null : get(s);
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

	private static String lastKey(JsonObject e) {
		return e.has("address") && e.get("address").isJsonPrimitive()
				? e.get("address").getAsString() + '\n' + fieldOf(e)
				: null;
	}

	/** The oldest {@code seq} still held when the newest is {@code hi}. */
	private static long oldest(long hi) {
		return Math.max(1, hi - CAP + 1);
	}

	/** Drops entry {@code s}: clears its slot and removes it from the indexes. */
	private void evict(long s) {
		long i = (s - 1) % RING;
		AtomicReferenceArray<Slot> chunk = ring.get((int) (i / CHUNK));
		Slot slot = chunk == null ? null : chunk.get((int) (i % CHUNK));
		if (slot == null || slot.seq != s) {
			return;
		}
		// release the entry now rather than RING - CAP appends later; get() reads null as dropped
		chunk.compareAndSet((int) (i % CHUNK), slot, null);
		JsonObject old = slot.e;
		if (old.has("rk")) {
			String rk = old.get("rk").getAsString();
			SeqRun r = rkIndex.get(rk);
			if (r != null && r.seqs[r.from] == s) {
				SeqRun rest = r.minusFirst();
				if (rest == null) {
					rkIndex.remove(rk, r);
				}
				else {
					rkIndex.put(rk, rest);
				}
			}
		}
		String k = lastKey(old);
		if (k != null) {
			lastIndex.remove(k, s); // only while s is still the newest of its field
		}
	}

	private void put(long s, JsonObject e) {
		long i = (s - 1) % RING;
		int c = (int) (i / CHUNK);
		AtomicReferenceArray<Slot> chunk = ring.get(c);
		if (chunk == null) {
			chunk = new AtomicReferenceArray<>(CHUNK);
			ring.set(c, chunk);
		}
		chunk.set((int) (i % CHUNK), new Slot(s, e));
	}

	/** Entry {@code s}, or null when its slot holds another entry (dropped, or not yet written). */
	private JsonObject get(long s) {
		if (s < 1) {
			return null;
		}
		long i = (s - 1) % RING;
		AtomicReferenceArray<Slot> chunk = ring.get((int) (i / CHUNK));
		Slot slot = chunk == null ? null : chunk.get((int) (i % CHUNK));
		return slot != null && slot.seq == s ? slot.e : null;
	}

	/**
	 * An immutable view {@code seqs[from, to)} of one key's held {@code seq}s, oldest first. Only
	 * the writer (under {@code append}) makes new views. Several views share one array: the writer
	 * only ever writes at the newest view's {@code to}, which no published view covers, and drops by
	 * moving {@code from}, so a reader's view never changes under it. When the array is full the
	 * live range is copied once into an array twice its size: appends and drops are amortised O(1).
	 */
	private static final class SeqRun {
		final long[] seqs;
		final int from, to;

		private SeqRun(long[] seqs, int from, int to) {
			this.seqs = seqs;
			this.from = from;
			this.to = to;
		}

		static SeqRun of(long s) {
			long[] a = new long[4];
			a[0] = s;
			return new SeqRun(a, 0, 1);
		}

		SeqRun plus(long s) {
			long[] a = seqs;
			int f = from, t = to;
			if (t == a.length) {
				int n = t - f;
				long[] b = new long[Math.max(4, n * 2)];
				System.arraycopy(a, f, b, 0, n);
				a = b;
				f = 0;
				t = n;
			}
			a[t] = s; // beyond every published view of a: no reader sees it before the new view
			return new SeqRun(a, f, t + 1);
		}

		/** This run without its oldest {@code seq}, or null when that was the last one. */
		SeqRun minusFirst() {
			return from + 1 == to ? null : new SeqRun(seqs, from + 1, to);
		}
	}
}
