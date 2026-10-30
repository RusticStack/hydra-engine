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
 * A table is built only when it is worth it: for the second listing of the same program state.
 * The first listing of a state never seen before is answered by the walk itself (it stops after
 * {@code offset + limit} functions), so an edit followed by one listing, or a program that keeps
 * changing, costs no more than before. No table is built for a program whose table could not be
 * kept ({@code functionCount} times its last bytes per row over the budget). Concurrent builders
 * of one state share one build (single flight), each waiting at most the request's wait; table
 * and modification number are published together as one {@link Snap}. A table is kept only if
 * the program's modification number did not move while it was built; tables are held
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
	/**
	 * The same rows in the Rust read plane (pages rendered there), or null. Exported only when the
	 * daemon stores this table ({@link #exportNative}), freed when it drops it ({@link #release}).
	 */
	private volatile ReadPlane.NativeFunctions nat;

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
		// the Java rows only: the budget decides what is stored as before the read plane; the
		// Rust copy of a stored table is counted apart (health functionTable.nativeBytes)
		this.weight = w;
	}

	/** A table of these rows, exported to Rust (the self-test's made-up listings). */
	static FunctionTable of(String[] names, String[] entries, long[] sizes, byte[] flags) {
		FunctionTable t = new FunctionTable(names, entries, sizes, flags);
		t.exportNative();
		return t;
	}

	/** Gives this table's rows to the Rust read plane (once; nothing when it is off). */
	void exportNative() {
		ReadPlane rp = ReadPlane.get();
		if (rp != null && nat == null) {
			nat = rp.functions(names, entries, sizes, flags);
		}
	}

	/**
	 * Frees the Rust copy now (the table was dropped by the daemon): pages already reading it
	 * finish first, later pages take the Java path. The Cleaner is only the backstop.
	 */
	void release() {
		ReadPlane.NativeFunctions n = nat;
		if (n != null) {
			nat = null;
			n.close();
		}
	}

	/** Bytes of the Rust copy (0 when there is none). */
	long nativeWeight() {
		ReadPlane.NativeFunctions n = nat;
		return n == null ? 0 : n.weight;
	}

	/** True when this table's pages can come from the Rust read plane. */
	boolean isNative() {
		return nat != null;
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
		return (JsonObject) page(pat, sub, offset, limit, false);
	}

	/**
	 * As {@link #page(Pattern, String, int, int)}; with {@code raw}, a page without {@code regex}
	 * comes from the Rust read plane as the reply's bytes ({@link ReadPlane.RawJson}) when the
	 * table is there.
	 */
	JsonElement page(Pattern pat, String sub, int offset, int limit, boolean raw) {
		ReadPlane.NativeFunctions nf = nat;
		if (raw && nf != null && pat == null) {
			ReadPlane.RawJson r = ReadPlane.get().page(nf, sub, offset, limit);
			if (r != null) {
				return r;
			}
		}
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

	/**
	 * A table with the modification number it was built at, published as one reference so a reader
	 * never pairs one state's table with another state's number.
	 */
	private record Snap(FunctionTable table, long mod) {
	}

	/** The least a row can weigh (see the constructor): the first estimate of a program's table. */
	static final long MIN_ROW_BYTES = 8 + 8 + 8 + 1 + 56 + 56 + 2;

	/** One program's newest table and its build lock. */
	private static final class Holder {
		final ReentrantLock build = new ReentrantLock();
		volatile Snap snap;
		/** The modification number of the last listing answered without a table. */
		volatile long listedMod = Long.MIN_VALUE;
		/** Bytes per row of this program's last build: whether its next table can be kept. */
		volatile long rowBytes = MIN_ROW_BYTES;
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
		final AtomicLong tooBig = new AtomicLong();
		final AtomicLong timedOut = new AtomicLong();

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
		 * now if worth it) or by a walk. A caller waits at most {@code waitMs} for another
		 * caller's build of the same state, then walks.
		 */
		JsonObject functions(Program prog, Pattern pat, String sub, int offset, int limit,
				long waitMs) {
			return (JsonObject) functions(prog, pat, sub, offset, limit, waitMs, false);
		}

		/**
		 * As {@link #functions(Program, Pattern, String, int, int, long)}; with {@code raw} a page
		 * served from a table may be the Rust read plane's bytes ({@link ReadPlane.RawJson}).
		 */
		JsonElement functions(Program prog, Pattern pat, String sub, int offset, int limit,
				long waitMs, boolean raw) {
			long mod = prog.getModificationNumber();
			Holder h = holder(prog);
			h.used = clock.incrementAndGet();
			Snap s = h.snap;
			if (s != null && s.mod() == mod) {
				hits.incrementAndGet();
				return s.table().page(pat, sub, offset, limit, raw);
			}
			if (h.listedMod != mod) {
				// the first listing of this state (an edit, analysis): the walk stops at
				// offset + limit, so a program that keeps changing never pays for full builds
				h.listedMod = mod;
				walks.incrementAndGet();
				return walk(prog, pat, sub, offset, limit);
			}
			if ((long) prog.getFunctionManager().getFunctionCount() * h.rowBytes > budget) {
				// its table could not be kept: no build, no wait on other callers
				tooBig.incrementAndGet();
				walks.incrementAndGet();
				return walk(prog, pat, sub, offset, limit);
			}
			FunctionTable t = table(prog, h, mod, waitMs);
			if (t == null) {
				walks.incrementAndGet();
				return walk(prog, pat, sub, offset, limit);
			}
			return t.page(pat, sub, offset, limit, raw);
		}

		/**
		 * The table of {@code prog} at {@code mod}, one build for concurrent callers; null when
		 * the program has moved past {@code mod} or another caller's build took over
		 * {@code waitMs}.
		 */
		private FunctionTable table(Program prog, Holder h, long mod, long waitMs) {
			boolean waited = !h.build.tryLock();
			if (waited && !Waits.tryLock(h.build, waitMs)) {
				timedOut.incrementAndGet();
				return null;
			}
			try {
				Snap s = h.snap;
				if (s != null && s.mod() == mod) {
					(waited ? joined : hits).incrementAndGet();
					return s.table();
				}
				if (prog.getModificationNumber() != mod) {
					return null;
				}
				builds.incrementAndGet();
				FunctionTable t = FunctionTable.build(prog);
				if (t.size() > 0) {
					h.rowBytes = Math.max(MIN_ROW_BYTES, t.weight() / t.size());
				}
				if (prog.getModificationNumber() != mod || t.weight() > budget) {
					// moved during the build (this answer is as consistent as a walk during the
					// same change) or too big to keep: answer from it, keep nothing
					unstored.incrementAndGet();
					return t; // answered from the Java rows, never exported to Rust
				}
				t.exportNative();
				Snap old = h.snap;
				h.snap = new Snap(t, mod);
				if (old != null && old.table() != t) {
					old.table().release();
				}
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
					Snap s = h.snap;
					if (s == null) {
						continue;
					}
					total += s.table().weight();
					if (h != keep && (oldest == null || h.used < oldest.used)) {
						oldest = h;
					}
				}
				if (total <= budget || oldest == null) {
					return;
				}
				FunctionTable dropped = oldest.snap.table();
				oldest.snap = null;
				dropped.release();
				evicted.incrementAndGet();
			}
		}

		synchronized JsonObject describe() {
			long bytes = 0;
			long nativeBytes = 0;
			int tables = 0;
			for (Holder h : holders.values()) {
				Snap s = h.snap;
				if (s != null) {
					tables++;
					bytes += s.table().weight();
					nativeBytes += s.table().nativeWeight();
				}
			}
			JsonObject o = new JsonObject();
			o.addProperty("budget", budget);
			o.addProperty("tables", tables);
			o.addProperty("bytes", bytes);
			o.addProperty("nativeBytes", nativeBytes);
			o.addProperty("hits", hits.get());
			o.addProperty("builds", builds.get());
			o.addProperty("walks", walks.get());
			o.addProperty("joined", joined.get());
			o.addProperty("unstored", unstored.get());
			o.addProperty("evicted", evicted.get());
			o.addProperty("tooBig", tooBig.get());
			o.addProperty("timedOut", timedOut.get());
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
