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
// Decompile every function in address order and write the C text to the file named by the
// first script argument (at most the number of functions in the optional second). Prints the
// decompile wall time as DECOMPILE_ALL.
//@category Hydra
import java.io.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class DecompileAllC extends GhidraScript {
	@Override
	public void run() throws Exception {
		String out = getScriptArgs()[0];
		int limit = getScriptArgs().length > 1 ? Integer.parseInt(getScriptArgs()[1]) : Integer.MAX_VALUE;
		DecompInterface d = new DecompInterface();
		DecompileOptions o = new DecompileOptions();
		o.grabFromProgram(currentProgram);
		d.setOptions(o);
		d.toggleCCode(true);
		d.toggleSyntaxTree(true);
		d.setSimplificationStyle("decompile");
		d.openProgram(currentProgram);
		int n = 0;
		long t0 = System.nanoTime();
		try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)))) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (n >= limit) {
					break;
				}
				DecompileResults r = d.decompileFunction(f, 60, monitor);
				w.println("== " + f.getEntryPoint() + " " + f.getName(true));
				if (r.decompileCompleted()) {
					w.println(r.getDecompiledFunction().getC());
				}
				else {
					w.println("!! " + r.getErrorMessage());
				}
				n++;
			}
		}
		long ms = (System.nanoTime() - t0) / 1000000;
		println("DECOMPILE_ALL functions=" + n + " ms=" + ms);
		d.dispose();
	}
}
