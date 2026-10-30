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

import static ghidra.app.util.headless.session.Addresses.hex;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import com.google.gson.*;

import ghidra.program.model.listing.*;

/**
 * The function listing of one program state (hotspot H1 of the Rust plan): every function's full
 * name, entry, body size and flags, in the order {@code getFunctions(true)} gives them, built by
 * one walk of the program and shared by every request and every view of that program object
 * until its modification number moves.
 * <p>
 * Without it, every page of {@code functions} walked the program from its first function and
 * skipped {@code offset} of them, and every returned function computed its body (a walk of its
 * namespace symbols): N agents paging through a program of F functions in pages of P cost
 * {@code N * F^2 / 2P} function records. With it, one walk per program state, then each page is
 * an array slice (no filter) or a scan of names in memory (a {@code regex} or {@code contains}).
 * The reply is the one the walk gives, field for field and in the same order.
 * <p>
 * A table is built only when it is worth it: for a page past the first, or for the second listing
 * of the same program state. The first page of a state never seen before is answered by the walk
 * itself (it stops after {@code limit} functions), so an edit followed by one listing costs no
 * more than before. Concurrent builders of one state share one build (single flight). A table is
 * kept only if the program's modification number did not move while it was built; tables are held
 * weakly by program (never keep a closed program alive) and bounded by {@code functionTable} bytes
 * (default 1/64 of the heap, at most 64 MB; 0 turns it off), the least recently used dropped first.
 */
final class FunctionTable {

	static final byte THUNK = 1;
	static final byte EXTERNAL = 2;

	private final String[] names;
	private final String[] entries;
	private final long[] sizes;
	private final byte[] flags;
	private final long weight;

	private FunctionTable(String[] names, String[] entries, long[] sizes, byte[] flags) {
		this.names = names;
		this.entries = entries;
		this.sizes = sizes;
		this.flags = flags;
		long w = 64 + 24L * 4 + (8L + 8 + 8 + 1) * names.length;
		for (int i = 0; i < names.length; i++) {
			// a String header and its array header, Latin-1 or UTF-16 bytes
			w += 56 + 2L * names[i].length() + 56 + entries[i].length();
		}
		this.weight = w;
	}

	/** The table of {@code p} as it stands now: one walk of its functions. */
	static FunctionTable build(Program p) {
		int cap = Math.max(16, p.getFunctionManager().getFunctionCount());
		String[] n = new String[cap];
		String[] e = new String[cap];
		long[] s = new long[cap];
		byte[] fl = new byte[cap];
		int k = 0;
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			if (k == n.length) {
				int c = n.length * 2;
				n = Arrays.copyOf(n, c);
				e = Arrays.copyOf(e, c);
				s = Arrays.copyOf(s, c);
				fl = Arrays.copyOf(fl, c);
			}
			n[k] = f.getName(true);
			e[k] = hex(f.getEntryPoint());
			s[k] = f.getBody().getNumAddresses();
			fl[k] = (byte) ((f.isThunk() ? THUNK : 0) | (f.isExternal() ? EXTERNAL : 0));
			k++;
		}
		return new FunctionTable(Arrays.copyOf(n, k), Arrays.copyOf(e, k), Arrays.copyOf(s, k),
			Arrays.copyOf(fl, k));
	}

	int size() {
		return names.length;
	}

	long weight() {
		return weight;
	}

	private JsonObject row(int i) {
		return Json.of("name", names[i], "address", entries[i], "size", sizes[i], "thunk",
			(flags[i] & THUNK) != 0, "external", (flags[i] & EXTERNAL) != 0);
	}

	/**
	 * The reply of {@code functions} for these arguments, the same as {@link #walk} gives on the
	 * program state this table was built from.
	 */
	JsonObject page(Pattern pat, String sub, int offset, int limit) {
		JsonArray a = new JsonArray();
		boolean truncated = false;
		int n = names.length;
		if (pat == null && sub == null) {
			int start = Math.min(offset, n);
			int end = (int) Math.min((long) start + limit, n);
			for (int i = start; i < end; i++) {
				a.add(row(i));
			}
			truncated = n - start > limit;
		}
		else {
			int seen = 0;
			for (int i = 0; i < n; i++) {
				String nm = names[i];
				if (pat != null && !pat.matcher(nm).find()) {
					continue;
				}
				if (sub != null && !nm.contains(sub)) {
					continue;
				}
				if (seen++ < offset) {
					continue;
				}
				if (a.size() >= limit) {
					truncated = true;
					break;
				}
				a.add(row(i));
			}
		}
		return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
			truncated);
	}

	/** The reply of {@code functions} by a walk of the program (the reference behaviour). */
	static JsonObject walk(Program prog, Pattern pat, String sub, int offset, int limit) {
		JsonArray a = new JsonArray();
		int seen = 0;
		boolean truncated = false;
		for (Function f : prog.getFunctionManager().getFunctions(true)) {
			String n = f.getName(true);
			if (pat != null && !pat.matcher(n).find()) {
				continue;
			}
			if (sub != null && !n.contains(sub)) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (a.size() >= limit) {
				truncated = true;
				break;
			}
			a.add(Json.of("name", n, "address", hex(f.getEntryPoint()), "size",
				f.getBody().getNumAddresses(), "thunk", f.isThunk(), "external", f.isExternal()));
		}
		return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
			truncated);
	}

	// ---------------------------------------------------------------- the daemon's tables

	static final long CEILING_BYTES = 64L << 20;
	static final long FLOOR_BYTES = 1L << 20;

	/** The default budget for a heap of {@code heapBytes}: 1/64, at most 64 MB, 0 below 1 MB. */
	static long defaultBytes(long heapBytes) {
		long b = Math.min(CEILING_BYTES, heapBytes / 64);
		return b < FLOOR_BYTES ? 0 : b;
	}

	/** One program's newest table and its build lock. */
	private static final class Holder {
		final ReentrantLock build = new ReentrantLock();
		volatile FunctionTable table;
		volatile long tableMod = Long.MIN_VALUE;
		/** The modification number of the last listing answered by a walk. */
		volatile long walkedMod = Long.MIN_VALUE;
		volatile long used;
	}

	/** The tables of the daemon, by program object. */
	static final class Cache {
		private final long budget;
		// guarded by this
		private final Map<Program, Holder> holders = new WeakHashMap<>();
		private final AtomicLong clock = new AtomicLong();
		final AtomicLong hits = new AtomicLong();
		final AtomicLong builds = new AtomicLong();
		final AtomicLong walks = new AtomicLong();
		final AtomicLong joined = new AtomicLong();
		final AtomicLong unstored = new AtomicLong();
		final AtomicLong evicted = new AtomicLong();

		Cache(long budget) {
			this.budget = budget;
		}

		long budget() {
			return budget;
		}

		private synchronized Holder holder(Program p) {
			return holders.computeIfAbsent(p, x -> new Holder());
		}

		/**
		 * The reply of {@code functions} on {@code prog} as it stands now: from its table (built
		 * now if worth it) or by a walk.
		 */
		JsonObject functions(Program prog, Pattern pat, String sub, int offset, int limit) {
			long mod = prog.getModificationNumber();
			Holder h = holder(prog);
			h.used = clock.incrementAndGet();
			FunctionTable t = h.table;
			if (t != null && h.tableMod == mod) {
				hits.incrementAndGet();
				return t.page(pat, sub, offset, limit);
			}
			if (offset == 0 && h.walkedMod != mod) {
				// the first listing of this state: the walk stops after one page
				h.walkedMod = mod;
				walks.incrementAndGet();
				return walk(prog, pat, sub, offset, limit);
			}
			t = table(prog, h, mod);
			if (t == null) {
				walks.incrementAndGet();
				return walk(prog, pat, sub, offset, limit);
			}
			return t.page(pat, sub, offset, limit);
		}

		/** The table of {@code prog} at {@code mod}: one build for concurrent callers. */
		private FunctionTable table(Program prog, Holder h, long mod) {
			boolean waited = h.build.isLocked();
			h.build.lock();
			try {
				FunctionTable t = h.table;
				if (t != null && h.tableMod == mod) {
					(waited ? joined : hits).incrementAndGet();
					return t;
				}
				if (prog.getModificationNumber() != mod) {
					return null;
				}
				builds.incrementAndGet();
				t = FunctionTable.build(prog);
				if (prog.getModificationNumber() != mod) {
					unstored.incrementAndGet();
					return null; // the program moved during the walk: answered by a walk
				}
				if (t.weight() > budget) {
					unstored.incrementAndGet();
					return t;
				}
				h.table = t;
				h.tableMod = mod;
				trim(h);
				return t;
			}
			finally {
				h.build.unlock();
			}
		}

		/** Drops the least recently used tables (never {@code keep}'s) down to the budget. */
		private synchronized void trim(Holder keep) {
			while (true) {
				long total = 0;
				Holder oldest = null;
				for (Holder h : holders.values()) {
					FunctionTable t = h.table;
					if (t == null) {
						continue;
					}
					total += t.weight();
					if (h != keep && (oldest == null || h.used < oldest.used)) {
						oldest = h;
					}
				}
				if (total <= budget || oldest == null) {
					return;
				}
				oldest.table = null;
				oldest.tableMod = Long.MIN_VALUE;
				evicted.incrementAndGet();
			}
		}

		synchronized JsonObject describe() {
			long bytes = 0;
			int tables = 0;
			for (Holder h : holders.values()) {
				FunctionTable t = h.table;
				if (t != null) {
					tables++;
					bytes += t.weight();
				}
			}
			JsonObject o = new JsonObject();
			o.addProperty("budget", budget);
			o.addProperty("tables", tables);
			o.addProperty("bytes", bytes);
			o.addProperty("hits", hits.get());
			o.addProperty("builds", builds.get());
			o.addProperty("walks", walks.get());
			o.addProperty("joined", joined.get());
			o.addProperty("unstored", unstored.get());
			o.addProperty("evicted", evicted.get());
			return o;
		}
	}

	private static volatile Cache instance;

	/** The daemon's tables, made on first use from the settings (null when off). */
	static Cache cache() {
		Cache c = instance;
		if (c == null) {
			synchronized (FunctionTable.class) {
				c = instance;
				if (c == null) {
					c = new Cache(Budgets.functionTableBytes());
					instance = c;
					Cache made = c;
					if (made.budget() > 0) {
						Health.contribute("functionTable", made::describe);
					}
				}
			}
		}
		return c.budget() > 0 ? c : null;
	}
}
