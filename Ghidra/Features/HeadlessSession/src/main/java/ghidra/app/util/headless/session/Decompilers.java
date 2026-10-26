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

/** A pool of decompilers bound to one program object: a shared program's, or an overlay's. */
interface Decompilers {

	/** A decompiler for the pool's program, warm when one is free. */
	DecompInterface borrowDecompiler();

	/** Gives it back; an unhealthy one (an error, a timeout) is disposed instead. */
	void returnDecompiler(DecompInterface d, boolean healthy);
}
