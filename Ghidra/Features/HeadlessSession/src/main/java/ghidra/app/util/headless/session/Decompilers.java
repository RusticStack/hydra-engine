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

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;

/** A pool of decompilers bound to one program object: a shared program's, or an overlay's. */
interface Decompilers {

	/**
	 * The program this pool's decompilers are bound to: a program's own, or the one an overlay
	 * reads through ({@link Overlay#readProgram}).
	 * @return the program, or null while an overlay has none
	 */
	Program program();

	/**
	 * A decompiler for the pool's program, warm when one is free.
	 * <p>
	 * Pooled decompilers are the text-only profile ({@link ProgramEntry#newDecompiler}: C code
	 * on, syntax tree off). Their {@code DecompileResults} carry the C markup and the
	 * signature, but {@code getHighFunction()} has no p-code syntax tree and no high
	 * variables. A caller that needs p-code, varnodes, high variables or tokens tied to the
	 * tree must build its own decompiler with {@code toggleSyntaxTree(true)}, not borrow one.
	 */
	DecompInterface borrowDecompiler();

	/** Gives it back; an unhealthy one (an error, a timeout) is disposed instead. */
	void returnDecompiler(DecompInterface d, boolean healthy);
}
