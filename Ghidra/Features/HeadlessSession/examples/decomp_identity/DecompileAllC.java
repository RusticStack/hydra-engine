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
// Decompile every function and write the C text, sorted by entry address, to the file named by
// the first script argument (at most the number of functions in the optional second, taken in
// address order). The optional third argument is the decompile order: "address" (default) or
// "shuffled:<seed>", which decompiles the same functions in a seeded random order and then decompiles
// every tenth of them again, so state one function leaves in the decompiler would change the text of
// a later one. The optional fourth argument is "tree" (default: toggleSyntaxTree(true)) or "notree"
// (the text-only profile of the session's pooled decompilers). Prints the decompile wall time, the
// native processes used and the accepted flushFunctions commands as DECOMPILE_ALL.
//@category Hydra
import java.io.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class DecompileAllC extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String out = args[0];
		int limit = args.length > 1 ? Integer.parseInt(args[1]) : Integer.MAX_VALUE;
		String order = args.length > 2 ? args[2] : "address";
		String tree = args.length > 3 ? args[3] : "tree";
		if (!tree.equals("tree") && !tree.equals("notree")) {
			throw new IllegalArgumentException("syntax tree is tree or notree: " + tree);
		}
		List<Function> funcs = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (funcs.size() >= limit) {
				break;
			}
			funcs.add(f);
		}
		List<Function> work = new ArrayList<>(funcs);
		if (order.startsWith("shuffled:")) {
			Collections.shuffle(work, new Random(Long.parseLong(order.substring(9))));
			for (int i = 0; i < funcs.size(); i += 10) {
				work.add(work.get(i));
			}
		}
		else if (!order.equals("address")) {
			throw new IllegalArgumentException("order is address or shuffled:<seed>: " + order);
		}
		DecompInterface d = new DecompInterface();
		DecompileOptions o = new DecompileOptions();
		o.grabFromProgram(currentProgram);
		d.setOptions(o);
		d.toggleCCode(true);
		d.toggleSyntaxTree(tree.equals("tree"));
		d.setSimplificationStyle("decompile");
		d.openProgram(currentProgram);
		// distinct native processes used: 1 unless a process was stopped and restarted
		java.lang.reflect.Field pf = DecompInterface.class.getDeclaredField("decompProcess");
		pf.setAccessible(true);
		Set<Object> processes = Collections.newSetFromMap(new IdentityHashMap<>());
		long kept0 = keptTypesFlushes();
		Map<Address, String> text = new TreeMap<>();
		int repeatsDiffering = 0;
		long t0 = System.nanoTime();
		for (Function f : work) {
			DecompileResults r = d.decompileFunction(f, 60, monitor);
			String c = "== " + f.getEntryPoint() + " " + f.getName(true) + "\n" +
				(r.decompileCompleted() ? r.getDecompiledFunction().getC() + "\n"
						: "!! " + r.getErrorMessage() + "\n");
			String first = text.putIfAbsent(f.getEntryPoint(), c);
			if (first != null && !first.equals(c)) {
				repeatsDiffering++;
			}
			processes.add(pf.get(d));
		}
		long ms = (System.nanoTime() - t0) / 1000000;
		try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)))) {
			for (String c : text.values()) {
				w.print(c);
			}
		}
		long kept = kept0 < 0 ? -1 : keptTypesFlushes() - kept0;
		println("DECOMPILE_ALL functions=" + funcs.size() + " ms=" + ms + " processes=" +
			processes.size() + " kept=" + kept + " repeats_differing=" + repeatsDiffering);
		d.dispose();
	}

	/** Accepted flushFunctions commands so far, or -1 on an engine without them. */
	private static long keptTypesFlushes() {
		try {
			return (Long) DecompInterface.class.getMethod("getKeptTypesFlushCount").invoke(null);
		}
		catch (ReflectiveOperationException e) {
			return -1;
		}
	}
}
