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

import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * The {@code functions} listing of a program as the program stands at one modification number
 * (Hydra, daemon-async): the name, entry, size and flags of every function in entry order, read
 * from the program database once and shared by every request of every client until the program
 * changes.
 * <p>
 * Without it each {@code functions} page walked the function table from the first function (an
 * {@code offset} skips functions only after computing their names), so a client that pages a
 * program of {@code n} functions {@code limit} at a time read {@code n * n / (2 * limit)} function
 * records, all under the program database's one monitor ({@code DBHandle}) that every other
 * client's reads of the same program wait for. With it a page is an array slice, and the reads
 * happen once per program state for all clients together.
 * <p>
 * <b>Correctness.</b> An index is used only while {@link Program#getModificationNumber()} equals the
 * number it was built at: every change of a program (a rename, a namespace, a body, an undo)
 * changes that number, so a stale listing is never served. A build stores its index only when the
 * number did not change while it read. Builds of one program are single-flight: concurrent first
 * requests wait for the one build instead of each reading the table.
 * <p>
 * <b>Cost.</b> The first page of a program state ({@code offset 0}, no filter) is read from the
 * database as before when no index of that state exists ({@link #fresh}): a client that edits and
 * then looks at the first page of a large program does not pay for a whole listing; the index is
 * built by the first deeper page or filtered listing of a state.
 * <p>
 * <b>Memory.</b> At most one index per open program object, held weakly (a closed program's index
 * goes with it): two strings and a few primitives per function. A stale index is dropped as soon
 * as a look-up finds the program changed, and the indexes of all programs together keep at most
 * {@code functionIndexMaxRows} rows (default 1,000,000): above it the least recently used
 * indexes are dropped (and rebuilt when needed).
 * <p>
 * The setting {@code functionIndex} ({@code -set functionIndex=false}) turns it off: every page is
 * read from the database as before.
 */
final class FunctionIndex {

	/** One program state: parallel arrays in the order of {@code getFunctions(true)}. */
	static final class Snapshot {
		final long modification;
		final String[] names;
		final String[] addresses;
		final long[] sizes;
		/** bit 0: thunk, bit 1: external */
		final byte[] flags;

		Snapshot(long modification, int n) {
			this.modification = modification;
			names = new String[n];
			addresses = new String[n];
			sizes = new long[n];
			flags = new byte[n];
		}

		int size() {
			return names.length;
		}

		JsonObject row(int i) {
			return Json.of("name", names[i], "address", addresses[i], "size", sizes[i], "thunk",
				(flags[i] & 1) != 0, "external", (flags[i] & 2) != 0);
		}
	}

	/** The build of one program, or its finished snapshot. */
	private static final class Slot {
		Snapshot snapshot; // guarded by this
		long building = -1; // the modification number being read now, -1: none; guarded by this
		long used; // the last use (USE clock), guarded by this
	}

	private static final AtomicLong USE = new AtomicLong();
	private static final AtomicLong EVICTED = new AtomicLong();

	private static final Map<Program, Slot> SLOTS = new WeakHashMap<>();

	private static final AtomicLong HITS = new AtomicLong();
	private static final AtomicLong BUILDS = new AtomicLong();
	private static final AtomicLong JOINED = new AtomicLong();
	private static final AtomicLong RACED = new AtomicLong();
	private static final AtomicLong ROWS = new AtomicLong();

	static {
		Health.contribute("functionIndex", FunctionIndex::describe);
	}

	private FunctionIndex() {
	}

	static boolean enabled() {
		return Settings.bool("functionIndex", true);
	}

	static long maxRows() {
		return Math.max(0, Settings.integer("functionIndexMaxRows", 1_000_000));
	}

	/**
	 * The index of {@code p} as it stands now if one was built, else null (without building one);
	 * a stale index is dropped. The caller holds the program's shared lock.
	 */
	static Snapshot fresh(Program p) {
		Slot slot;
		synchronized (SLOTS) {
			slot = SLOTS.get(p);
		}
		if (slot == null) {
			return null;
		}
		long mod = p.getModificationNumber();
		synchronized (slot) {
			Snapshot s = slot.snapshot;
			if (s != null && s.modification == mod) {
				HITS.incrementAndGet();
				slot.used = USE.incrementAndGet();
				return s;
			}
			slot.snapshot = null; // stale: not kept for a state that is gone
			return null;
		}
	}

	/**
	 * The listing of {@code p} as it stands now. The caller holds the program's shared lock, as for
	 * any read.
	 */
	static Snapshot of(Program p) {
		Slot slot;
		synchronized (SLOTS) {
			slot = SLOTS.computeIfAbsent(p, x -> new Slot());
		}
		long mod = p.getModificationNumber();
		synchronized (slot) {
			while (true) {
				Snapshot s = slot.snapshot;
				if (s != null && s.modification == mod) {
					HITS.incrementAndGet();
					slot.used = USE.incrementAndGet();
					return s;
				}
				slot.snapshot = null; // stale: not kept for a state that is gone
				if (slot.building != mod) {
					break; // nobody reads this state: this caller does
				}
				JOINED.incrementAndGet();
				try {
					slot.wait(50);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new SessionException(SessionException.CANCELLED, "interrupted");
				}
				mod = p.getModificationNumber();
			}
			slot.building = mod;
		}
		Snapshot built = null;
		boolean kept = false;
		try {
			built = build(p, mod);
			return built;
		}
		finally {
			synchronized (slot) {
				if (slot.building == mod) {
					slot.building = -1;
				}
				if (built != null) {
					if (p.getModificationNumber() == mod) {
						slot.snapshot = built;
						slot.used = USE.incrementAndGet();
						kept = true;
					}
					else {
						RACED.incrementAndGet(); // the program changed while it was read: not kept
					}
				}
				slot.notifyAll();
			}
			if (kept) {
				trim(slot);
			}
		}
	}

	/**
	 * Drops the least recently used indexes (other than {@code keep}'s) while all indexes together
	 * hold more than {@link #maxRows()} rows. Takes {@code SLOTS} then each slot, as
	 * {@link #describe} does; no caller holds a slot's monitor here.
	 */
	private static void trim(Slot keep) {
		long max = maxRows();
		synchronized (SLOTS) {
			while (true) {
				long rows = 0;
				Slot oldest = null;
				long oldestUse = Long.MAX_VALUE;
				for (Slot s : SLOTS.values()) {
					synchronized (s) {
						if (s.snapshot == null) {
							continue;
						}
						rows += s.snapshot.size();
						if (s != keep && s.used < oldestUse) {
							oldestUse = s.used;
							oldest = s;
						}
					}
				}
				if (rows <= max || oldest == null) {
					return;
				}
				synchronized (oldest) {
					oldest.snapshot = null;
				}
				EVICTED.incrementAndGet();
			}
		}
	}

	private static Snapshot build(Program p, long mod) {
		BUILDS.incrementAndGet();
		var fm = p.getFunctionManager();
		int n = fm.getFunctionCount();
		String[] names = new String[n];
		String[] addresses = new String[n];
		long[] sizes = new long[n];
		byte[] flags = new byte[n];
		int i = 0;
		for (Function f : fm.getFunctions(true)) {
			if (i == names.length) {
				int m = Math.max(16, names.length * 2);
				names = java.util.Arrays.copyOf(names, m);
				addresses = java.util.Arrays.copyOf(addresses, m);
				sizes = java.util.Arrays.copyOf(sizes, m);
				flags = java.util.Arrays.copyOf(flags, m);
			}
			names[i] = f.getName(true);
			addresses[i] = Addresses.hex(f.getEntryPoint());
			sizes[i] = f.getBody().getNumAddresses();
			flags[i] = (byte) ((f.isThunk() ? 1 : 0) | (f.isExternal() ? 2 : 0));
			i++;
		}
		Snapshot s = new Snapshot(mod, i);
		System.arraycopy(names, 0, s.names, 0, i);
		System.arraycopy(addresses, 0, s.addresses, 0, i);
		System.arraycopy(sizes, 0, s.sizes, 0, i);
		System.arraycopy(flags, 0, s.flags, 0, i);
		ROWS.addAndGet(i);
		return s;
	}

	/** For {@code health.functionIndex}. */
	static JsonObject describe() {
		int programs;
		long rows = 0;
		synchronized (SLOTS) {
			programs = SLOTS.size();
			for (Slot s : SLOTS.values()) {
				synchronized (s) {
					if (s.snapshot != null) {
						rows += s.snapshot.size();
					}
				}
			}
		}
		return Json.of("enabled", enabled(), "programs", programs, "rows", rows, "hits",
			HITS.get(), "builds", BUILDS.get(), "joined", JOINED.get(), "raced", RACED.get(),
			"rowsRead", ROWS.get(), "evicted", EVICTED.get(), "maxRows", maxRows());
	}
}
