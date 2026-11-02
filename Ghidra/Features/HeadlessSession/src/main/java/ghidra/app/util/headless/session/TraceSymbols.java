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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The function table the trace engine resolves code addresses with (TRACE-1 section 10): one
 * program state, walked once, rendered as the engine's {@code TableSymbolizer} JSON.
 * <p>
 * The engine owns the lookup. For each event it takes the module the event's address falls in
 * and that module's load base (from the trace's own module events), and asks the table for the
 * module-relative address; Java never sees an address. The table is therefore RVA based:
 * {@code rva = VA - imageBase} for a function body range, and the executable blocks are the
 * {@code code} ranges (an address outside them is {@code not-code}; inside one but outside every
 * function, {@code no-symbol}; a module name the table does not list, {@code module-unknown}).
 * <p>
 * A table is built from a program under its shared lock (the one walk {@link FunctionTable#build}
 * also makes), sent with {@code trace_open} or {@code trace_resymbolize} as {@code symbols} and
 * pinned by a {@code symbol_revision} string, and then forgotten by Java: a later edit of the
 * program changes nothing already recorded; re-symbolization sends a new table under a new
 * revision, and the engine keeps every interpretation (a query can pin one with {@code interp}).
 */
final class TraceSymbols {

	private TraceSymbols() {
		// static
	}

	/** What was built: the table and the facts {@code trace_open} reports about it. */
	record Table(long revision, String program, long modification, int functions,
			List<String> modules, JsonObject symbols) {

		String symbolRevision() {
			return "r" + revision;
		}

		/** The {@code symbols} block of a reply (no table body). */
		JsonObject summary() {
			return Json.of("revision", revision, "symbolRevision", symbolRevision(), "program",
				program, "modification", modification, "functions", functions, "modules", modules);
		}
	}

	/**
	 * Builds the table of {@code p} as it stands now for the modules named {@code modules} (the
	 * program is the image of each; when none is named, {@code defaultModule}). The caller holds
	 * the program shared.
	 */
	static Table build(Program p, long revision, String programKey, Collection<String> modules,
			String defaultModule) {
		long imageBase = p.getImageBase().getOffset();
		JsonArray functions = new JsonArray();
		int count = 0;
		List<long[]> bodies = new ArrayList<>();
		List<String> names = new ArrayList<>();
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			if (f.isExternal()) {
				continue;
			}
			String name = f.getName(true);
			for (AddressRange r : f.getBody().getAddressRanges()) {
				bodies.add(new long[] { r.getMinAddress().getOffset() - imageBase,
					r.getMaxAddress().getOffset() + 1 - imageBase, names.size() });
			}
			names.add(name);
			count++;
		}
		bodies.sort((x, y) -> Long.compare(x[0], y[0]));
		for (long[] b : bodies) {
			JsonObject o = new JsonObject();
			o.addProperty("start", b[0]);
			o.addProperty("end", b[1]);
			o.addProperty("name", names.get((int) b[2]));
			functions.add(o);
		}
		List<long[]> code = new ArrayList<>();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			if (b.isExecute() && b.isInitialized()) {
				code.add(new long[] { b.getStart().getOffset() - imageBase,
					b.getEnd().getOffset() + 1 - imageBase });
			}
		}
		code.sort((x, y) -> Long.compare(x[0], y[0]));
		JsonArray ranges = new JsonArray();
		for (long[] r : code) {
			JsonArray pair = new JsonArray();
			pair.add(r[0]);
			pair.add(r[1]);
			ranges.add(pair);
		}
		Set<String> mods = new TreeSet<>(modules);
		if (mods.isEmpty()) {
			mods.add(defaultModule);
		}
		JsonObject table = new JsonObject();
		table.add("code", ranges);
		table.add("functions", functions);
		JsonObject byModule = new JsonObject();
		for (String m : mods) {
			byModule.add(m, table);
		}
		return new Table(revision, programKey, p.getModificationNumber(), count,
			new ArrayList<>(mods), Json.of("modules", byModule));
	}
}
