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

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * VA to function for the trace ingest (TRACE-1 section 10): the sealed table of one program state.
 * <p>
 * A {@link SymbolMap} is built once from a program at a pinned <b>symbol revision</b> (the
 * session's ordinal, recorded with the program's modification number) in one walk of its
 * functions, like a {@link FunctionTable}, and never changes. The ingest thread asks it through
 * the callback of {@link TraceNative}: a lookup is two binary searches over {@code long} arrays,
 * no program lock, no allocation but the answer. A later edit of the program does not touch a
 * pinned map; re-symbolization builds a new map under a new revision.
 * <p>
 * A code address is resolved as {@code va - moduleBase + imageBase} when the session declared a
 * {@code moduleBase} (a rebased module), else as given. An address inside no executable block is
 * {@code not-code}; inside one but outside every function body, {@code no-symbol}; a module
 * other than the map's is {@code module-unknown}. The original VA is never rewritten.
 */
final class TraceSymbols {

	private TraceSymbols() {
		// static
	}

	/** One answer: {@code code} 1 resolved (json set), 0 no symbol, -1 module unknown, -2 not code, -3 no such map. */
	record Result(int code, String json) {
	}

	private static final Result NO_SYMBOL = new Result(0, null);
	private static final Result MODULE_UNKNOWN = new Result(-1, null);
	private static final Result NOT_CODE = new Result(-2, null);
	private static final Result NO_REVISION = new Result(-3, null);

	/** The immutable symbols of one program state. */
	static final class SymbolMap {
		final long revision;
		final String program;
		final long modification;
		/** Lower-case module names this map answers for; empty: any module. */
		final Set<String> modules;
		final long imageBase;
		final long moduleBase;
		// body ranges of the functions, sorted by start
		private final long[] starts;
		private final long[] ends;
		private final int[] fn;
		private final String[] names;
		private final long[] entries;
		// executable block ranges, sorted
		private final long[] execStart;
		private final long[] execEnd;

		private SymbolMap(long revision, String program, long modification, Set<String> modules,
				long imageBase, long moduleBase, long[] starts, long[] ends, int[] fn,
				String[] names, long[] entries, long[] execStart, long[] execEnd) {
			this.revision = revision;
			this.program = program;
			this.modification = modification;
			this.modules = modules;
			this.imageBase = imageBase;
			this.moduleBase = moduleBase;
			this.starts = starts;
			this.ends = ends;
			this.fn = fn;
			this.names = names;
			this.entries = entries;
			this.execStart = execStart;
			this.execEnd = execEnd;
		}

		int functions() {
			return names.length;
		}

		Result resolve(String module, long va) {
			if (!modules.isEmpty() && !module.isEmpty() &&
				!modules.contains(module.toLowerCase(Locale.ROOT))) {
				return MODULE_UNKNOWN;
			}
			long a = moduleBase != 0 ? va - moduleBase + imageBase : va;
			if (!inside(execStart, execEnd, a)) {
				return NOT_CODE;
			}
			int i = Arrays.binarySearch(starts, a);
			if (i < 0) {
				i = -i - 2;
			}
			// ranges of different functions do not overlap; scan back over adjacent same-start rows
			if (i < 0 || a > ends[i]) {
				return NO_SYMBOL;
			}
			int f = fn[i];
			return new Result(1, "{\"function\":" + Json.GSON.toJson(names[f]) + ",\"entry\":\"" +
				hexOf(entries[f]) + "\",\"offset\":" + (a - entries[f]) + ",\"program\":" +
				Json.GSON.toJson(program) + "}");
		}

		private static boolean inside(long[] s, long[] e, long a) {
			int i = Arrays.binarySearch(s, a);
			if (i < 0) {
				i = -i - 2;
			}
			return i >= 0 && a <= e[i];
		}

		private static String hexOf(long v) {
			return "0x" + Long.toHexString(v);
		}
	}

	/**
	 * Builds the map of {@code p} as it stands now. The caller holds the program shared; the walk
	 * is the one {@link FunctionTable#build} makes.
	 */
	static SymbolMap build(Program p, long revision, String programKey, Set<String> modules,
			long moduleBase) {
		int cap = Math.max(16, p.getFunctionManager().getFunctionCount());
		List<long[]> rows = new ArrayList<>(cap);
		String[] names = new String[cap];
		long[] entries = new long[cap];
		int k = 0;
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			if (f.isExternal()) {
				continue;
			}
			if (k == names.length) {
				names = Arrays.copyOf(names, k * 2);
				entries = Arrays.copyOf(entries, k * 2);
			}
			names[k] = f.getName(true);
			entries[k] = f.getEntryPoint().getOffset();
			for (AddressRange r : f.getBody().getAddressRanges()) {
				rows.add(new long[] { r.getMinAddress().getOffset(), r.getMaxAddress().getOffset(),
					k });
			}
			k++;
		}
		rows.sort((x, y) -> Long.compare(x[0], y[0]));
		long[] starts = new long[rows.size()];
		long[] ends = new long[rows.size()];
		int[] fn = new int[rows.size()];
		for (int i = 0; i < starts.length; i++) {
			starts[i] = rows.get(i)[0];
			ends[i] = rows.get(i)[1];
			fn[i] = (int) rows.get(i)[2];
		}
		List<long[]> ex = new ArrayList<>();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			if (b.isExecute() && b.isInitialized()) {
				ex.add(new long[] { b.getStart().getOffset(), b.getEnd().getOffset() });
			}
		}
		ex.sort((x, y) -> Long.compare(x[0], y[0]));
		long[] es = new long[ex.size()];
		long[] ee = new long[ex.size()];
		for (int i = 0; i < es.length; i++) {
			es[i] = ex.get(i)[0];
			ee[i] = ex.get(i)[1];
		}
		Set<String> mods = new TreeSet<>();
		for (String m : modules) {
			mods.add(m.toLowerCase(Locale.ROOT));
		}
		return new SymbolMap(revision, programKey, p.getModificationNumber(), mods,
			p.getImageBase().getOffset(), moduleBase, starts, ends, fn,
			Arrays.copyOf(names, k), Arrays.copyOf(entries, k), es, ee);
	}

	// ---- the maps of the open sessions ------------------------------------------------------

	private static final Map<String, NavigableMap<Long, SymbolMap>> MAPS = new ConcurrentHashMap<>();

	/** Keeps {@code m} for {@code session} (the revisions of a session are kept until it closes). */
	static void put(String session, SymbolMap m) {
		MAPS.computeIfAbsent(session, k -> new java.util.concurrent.ConcurrentSkipListMap<>())
				.put(m.revision, m);
	}

	static SymbolMap get(String session, long revision) {
		NavigableMap<Long, SymbolMap> by = MAPS.get(session);
		return by == null ? null : by.get(revision);
	}

	static void drop(String session) {
		MAPS.remove(session);
	}

	static long latest(String session) {
		NavigableMap<Long, SymbolMap> by = MAPS.get(session);
		return by == null || by.isEmpty() ? 0 : by.lastKey();
	}

	/** The callback's lookup: no lock, no program access. */
	static Result resolve(String session, long revision, String module, long va) {
		SymbolMap m = get(session, revision);
		return m == null ? NO_REVISION : m.resolve(module, va);
	}
}
