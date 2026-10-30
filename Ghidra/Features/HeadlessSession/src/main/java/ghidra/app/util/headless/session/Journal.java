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
 * <b>One ordered log, readers without a lock.</b> {@code seq} is the program's commit order and
 * {@code discard_edits} walks it newest first across all clients, so the journal stays one log.
 * Its order is made by the program's exclusive lock, which the commit already holds, so a writer
 * never waits for another writer here (the {@code append} monitor only keeps that true if a
 * caller ever journals outside the commit lock). Readers ({@code since}, {@code byRk},
 * {@code lastAt}, {@code newestFirst}, {@code seq}, {@code dropped}) take no lock: an entry is
 * immutable once appended and is published by the volatile {@code seq}. The writer fills the
 * indexes before it publishes, so a reader can find the entry being appended in an index before
 * {@code seq} covers it; every read leaves such an entry out, so nothing a read returns runs
 * ahead of {@link #seq()}, as under a lock.
 * <p>
 * Indexed (S21): entries sit in a ring of lazily allocated chunks indexed by {@code seq}, so the
 * entries after {@code since} cost what they return. The writer keeps three indexes so that no
 * lookup scans the journal: the {@code seq}s of each idempotency key and of each client, oldest
 * first (immutable {@link SeqRun} views, amortised O(1) per append and per drop), and the
 * {@code seq} of the last entry of each address and field. Dropping the oldest entry over the cap
 * clears its slot and removes it from the indexes. A reader that finds an entry dropped under it
 * (its slot no longer holds that {@code seq}) discards what it collected and resumes after it:
 * drops go oldest first, so it returns one gap-free window, the one held when it found the drop.
 */
final class Journal {

	static final int CAP = 200_000;

	/** Entries per ring chunk at most; chunks are allocated on first use. */
	private static final int CHUNK = 4096;

	/** One appended entry with its {@code seq} beside it, so readers never parse it to check. */
	private record Slot(long seq, JsonObject e) {
	}

	private final int cap;
	private final int chunk;
	/** Ring size in slots: more than {@link #cap}, so a slot is reused only after its entry was dropped. */
	private final long ringSize;
	private final AtomicReferenceArray<AtomicReferenceArray<Slot>> ring;
	/** The last appended {@code seq}: the publication point readers synchronise on. */
	private volatile long seq;
	private final ConcurrentHashMap<String, SeqRun> rkIndex = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<Integer, SeqRun> clientIndex = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, Last> lastIndex = new ConcurrentHashMap<>();
	/** Serialises appends (the program's commit lock already does); readers never take it. */
	private final Object append = new Object();

	Journal() {
		this(CAP);
	}

	/** A journal that keeps the last {@code cap} entries (the self-test uses a small one). */
	Journal(int cap) {
		this.cap = Math.max(1, cap);
		this.chunk = Math.min(CHUNK, this.cap + 1);
		int chunks = this.cap / chunk + 2;
		this.ringSize = (long) chunks * chunk;
		this.ring = new AtomicReferenceArray<>(chunks);
	}

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
			// the keys first: a malformed entry throws before the journal changes
			String rk = rkOf(e);
			Integer cl = clientOf(e);
			String key = lastKey(e);
			if (s > cap) {
				evict(s - cap); // the entry the cap drops now
			}
			put(s, e);
			if (rk != null) {
				SeqRun r = rkIndex.get(rk);
				rkIndex.put(rk, r == null ? SeqRun.of(s) : r.plus(s));
			}
			SeqRun r = clientIndex.get(cl);
			clientIndex.put(cl, r == null ? SeqRun.of(s) : r.plus(s));
			if (key != null) {
				Last l = lastIndex.get(key);
				lastIndex.put(key, new Last(l == null ? 0 : l.cur, s));
			}
			seq = s; // publish: everything above happens-before a reader that sees s
			return s;
		}
	}

	/** Drops entry {@code s}: clears its slot and removes it from the indexes (writer only). */
	private void evict(long s) {
		long i = (s - 1) % ringSize;
		AtomicReferenceArray<Slot> ch = ring.get((int) (i / chunk));
		Slot slot = ch == null ? null : ch.get((int) (i % chunk));
		if (slot == null || slot.seq != s) {
			return;
		}
		ch.set((int) (i % chunk), null); // release the entry now; get() reads null as dropped
		JsonObject old = slot.e;
		String ork = rkOf(old);
		if (ork != null) {
			dropFirst(rkIndex, ork, s);
		}
		dropFirst(clientIndex, clientOf(old), s);
		String ok = lastKey(old);
		if (ok != null) {
			Last l = lastIndex.get(ok);
			if (l != null && l.cur == s) {
				lastIndex.remove(ok, l); // only while s is still the newest of its field
			}
		}
	}

	private static <K> void dropFirst(ConcurrentHashMap<K, SeqRun> m, K k, long s) {
		SeqRun r = m.get(k);
		if (r != null && r.seqs[r.from] == s) {
			SeqRun rest = r.minusFirst();
			if (rest == null) {
				m.remove(k, r);
			}
			else {
				m.put(k, rest);
			}
		}
	}

	private void put(long s, JsonObject e) {
		long i = (s - 1) % ringSize;
		int c = (int) (i / chunk);
		AtomicReferenceArray<Slot> ch = ring.get(c);
		if (ch == null) {
			ch = new AtomicReferenceArray<>(chunk);
			ring.set(c, ch);
		}
		ch.set((int) (i % chunk), new Slot(s, e));
	}

	/** Entry {@code s}, or null when its slot holds no entry of {@code s} (dropped, or not yet written). */
	private JsonObject get(long s) {
		if (s < 1) {
			return null;
		}
		long i = (s - 1) % ringSize;
		AtomicReferenceArray<Slot> ch = ring.get((int) (i / chunk));
		Slot slot = ch == null ? null : ch.get((int) (i % chunk));
		return slot != null && slot.seq == s ? slot.e : null;
	}

	/** The oldest {@code seq} still held when the newest is {@code hi}. */
	private long oldest(long hi) {
		return Math.max(1, hi - cap + 1);
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
		long hi = seq; // read after the index, so run holds every seq of rk up to hi
		for (int i = run.from; i < run.to; i++) {
			long s = run.seqs[i];
			if (s > hi) {
				break; // being appended: not published yet
			}
			JsonObject e = get(s);
			if (e != null) {
				out.add(e.deepCopy());
			}
			else {
				out.clear(); // dropped while read: so is every older one (see since)
			}
		}
		return out;
	}

	long seq() {
		return seq;
	}

	long dropped() {
		return Math.max(0, seq - cap);
	}

	/**
	 * Entries after {@code after}, of one client (or all when {@code client} is null), at most
	 * {@code limit}, oldest first.
	 * <p>
	 * The answer is the journal as it was at one moment, as under a lock: a writer may drop
	 * entries under a slow reader, oldest first, so when an entry turns out dropped every entry
	 * collected before it was dropped too, and the read starts over after it. What it returns is
	 * then the window as it was when it found that drop (every later entry it reads was held
	 * then, since drops go in order); without a drop, the window when it read its first entry.
	 */
	JsonArray since(long after, Integer client, int limit) {
		JsonArray a = new JsonArray();
		long hi = seq;
		if (limit <= 0 || after >= hi) {
			return a;
		}
		if (client == null) {
			for (long s = Math.max(after + 1, oldest(hi)); s <= hi && a.size() < limit; s++) {
				JsonObject e = get(s);
				if (e != null) {
					a.add(e.deepCopy());
				}
				else {
					a = new JsonArray(); // a drop under this read: see above
				}
			}
			return a;
		}
		SeqRun run = clientIndex.get(client);
		if (run == null) {
			return a;
		}
		for (int i = run.firstAbove(after); i < run.to && a.size() < limit; i++) {
			long s = run.seqs[i];
			if (s > hi) {
				break; // appended after this read began
			}
			JsonObject e = get(s);
			if (e != null) {
				a.add(e.deepCopy());
			}
			else {
				a = new JsonArray(); // a drop under this read: see above
			}
		}
		return a;
	}

	/** Entries after {@code after}, newest first (for reverting). */
	List<JsonObject> newestFirst(long after) {
		List<JsonObject> out = new ArrayList<>();
		long hi = seq;
		for (long s = hi, lo = Math.max(after + 1, oldest(hi)); s >= lo; s--) {
			JsonObject e = get(s);
			if (e == null) {
				break; // dropped meanwhile, and so is every older one
			}
			out.add(e);
		}
		return out;
	}

	/** The last change of {@code op} kind (rename/label share one) at an address, or null. */
	JsonObject lastAt(String address, String field) {
		Last l = lastIndex.get(address + '\u0000' + field);
		if (l == null) {
			return null;
		}
		// seq is read after the index: cur > seq means cur is the one entry being appended now,
		// and prev (published, since appends go one at a time) is the newest as of that seq
		return get(l.cur <= seq ? l.cur : l.prev);
	}

	/**
	 * The newest {@code seq} of one address and field, and the one it replaced ({@code 0} when
	 * none), so a reader that finds {@code cur} not yet published answers with {@code prev}.
	 */
	private record Last(long prev, long cur) {
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

		/** The index of the first seq greater than {@code v} ({@code to} when none). */
		int firstAbove(long v) {
			int lo = from;
			int hi = to;
			while (lo < hi) {
				int mid = (lo + hi) >>> 1;
				if (seqs[mid] <= v) {
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
