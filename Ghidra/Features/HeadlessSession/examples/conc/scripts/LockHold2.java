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
// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class LockHold2 extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] a = getScriptArgs();
		String mode = a.length > 0 ? a[0] : "coop";
		double secs = a.length > 1 ? Double.parseDouble(a[1]) : 1;
		long end = System.nanoTime() + (long) (secs * 1e9);
		long t0 = System.nanoTime();
		switch (mode) {
			case "coop":
				while (System.nanoTime() < end) {
					monitor.checkCancelled();
					Thread.sleep(25);
				}
				break;
			case "deaf":
				while (System.nanoTime() < end) {
					try {
						Thread.sleep(25);
					}
					catch (InterruptedException e) {
						// ignore: a script that does not look at cancel
					}
				}
				break;
			case "spin":
				while (System.nanoTime() < end) {
					Math.sqrt(System.nanoTime());
				}
				break;
			case "dirty": {
				// contained script that changes a name and then waits: do concurrent readers see it?
				Function f = currentProgram.getFunctionManager().getFunctions(true).next();
				f.setName("ZZ_DIRTY_" + secs, ghidra.program.model.symbol.SourceType.USER_DEFINED);
				println("renamed " + f.getEntryPoint());
				while (System.nanoTime() < end) {
					Thread.sleep(25);
				}
				break;
			}
			case "scan": {
				// DB-read-bound: comments and symbols for every function, `secs` passes
				int passes = (int) secs;
				long n = 0;
				Listing l = currentProgram.getListing();
				for (int i = 0; i < passes; i++) {
					FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
					int k = 0;
					while (it.hasNext() && k++ < 3000) {
						Function f = it.next();
						String c = l.getComment(CommentType.EOL, f.getEntryPoint());
						if (currentProgram.getSymbolTable().getPrimarySymbol(f.getEntryPoint()) != null) {
							n++;
						}
						if (c != null) {
							n++;
						}
					}
				}
				println("scanned " + n);
				break;
			}
			default:
				throw new IllegalArgumentException(mode);
		}
		println(mode + " held " + (System.nanoTime() - t0) / 1_000_000 + " ms");
	}
}
