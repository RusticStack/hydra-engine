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
// Hydra: A/B check of the decompiler byte snapshot (hydra.decompiler.snapshot). Decompiles every function
// (or the first N) with the snapshot off and on, alternating passes in one JVM, and reports whether the C output
// is identical, the getBytes callbacks per pass and the wall time per pass. Also writes <out.json>.hysnap.
// args: <out.json> [limit=0 (all)] [passes per mode=2]
//@category Hydra
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class SnapshotABScript extends GhidraScript {

	private DecompileOptions options() {
		DecompileOptions options = new DecompileOptions();
		options.setEliminateUnreachable(true);
		options.setSimplifyDoublePrecision(true);
		options.setRespectReadOnly(true);
		options.setIgnoreUnimplemented(false);
		options.setInferConstantPointers(true);
		options.setAnalyzeForLoops(true);
		options.setPredicate(true);
		options.setMaxInstructions(100000);
		options.setMaxPayloadMBytes(50);
		options.setDefaultTimeout(120);
		return options;
	}

	private long[] pass(List<Function> functions, boolean snapshot, List<String> out) {
		System.setProperty(ProgramSnapshotFile.ENABLE_PROPERTY, Boolean.toString(snapshot));
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(options());
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		long callbacks0 = DecompileProcess.getBytesCallbackCount();
		long begin = System.nanoTime();
		try {
			decompiler.openProgram(currentProgram);
			for (Function f : functions) {
				DecompileResults res = decompiler.decompileFunction(f, 120, monitor);
				if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
					out.add(res.getDecompiledFunction().getC());
				}
				else {
					out.add("FAILED: " + res.getErrorMessage());
				}
			}
		}
		finally {
			decompiler.closeProgram();
			decompiler.dispose();
		}
		long wallMs = (System.nanoTime() - begin) / 1_000_000;
		return new long[] { wallMs, DecompileProcess.getBytesCallbackCount() - callbacks0 };
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Path outFile = Path.of(args[0]);
		int limit = args.length > 1 ? Integer.parseInt(args[1]) : 0;
		int passes = args.length > 2 ? Integer.parseInt(args[2]) : 2;
		List<Function> functions = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isExternal() || f.isThunk()) {
				continue;
			}
			functions.add(f);
			if (limit > 0 && functions.size() >= limit) {
				break;
			}
		}
		List<String> reference = null;
		StringBuilder rows = new StringBuilder();
		int mismatches = 0;
		String firstMismatch = "";
		for (int i = 0; i < passes * 2; i++) {
			boolean snapshot = (i % 2) == 1;	// off, on, off, on, ...
			List<String> out = new ArrayList<>();
			long[] r = pass(functions, snapshot, out);
			if (reference == null) {
				reference = out;
			}
			else {
				for (int k = 0; k < out.size(); k++) {
					if (!out.get(k).equals(reference.get(k))) {
						mismatches++;
						if (firstMismatch.isEmpty()) {
							firstMismatch = functions.get(k).getEntryPoint().toString();
						}
					}
				}
			}
			if (rows.length() > 0) {
				rows.append(",");
			}
			rows.append(String.format("{\"snapshot\":%s,\"wall_ms\":%d,\"getbytes_callbacks\":%d}",
				snapshot, r[0], r[1]));
			println(String.format("pass %d snapshot=%s wall_ms=%d getBytes callbacks=%d", i, snapshot,
				r[0], r[1]));
		}
		String json = String.format(
			"{\"program\":\"%s\",\"functions\":%d,\"mismatches\":%d,\"first_mismatch\":\"%s\",\"passes\":[%s]}%n",
			currentProgram.getName(), functions.size(), mismatches, firstMismatch, rows);
		Files.writeString(outFile, json, StandardCharsets.UTF_8);
		ProgramSnapshotFile.export(currentProgram, Path.of(args[0] + ".hysnap"));
		println(json);
	}
}
