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
package ghidra.program.database.mem;

import ghidra.program.model.address.AddressSpace;

/**
 * An immutable copy of a program's initialized memory at one modification number (a sealed
 * generation), installed on a {@link MemoryMapDB} with {@link MemoryMapDB#setReadSnapshot} so that
 * byte reads are served from it (for example from a memory-mapped file outside the Java heap)
 * instead of the database buffers (Hydra).
 * <p>
 * The memory map consults the snapshot only while the program's modification number equals
 * {@link #getGeneration()}, and drops it on any memory change (bytes, blocks, undo/redo), so a
 * snapshot is never used for a program state it was not written for. A read the snapshot cannot
 * serve whole returns false and the memory map reads the database as before; implementations must
 * therefore hold exactly the bytes {@link MemoryBlockDB#getBytes} returns for every address they
 * claim, and must be safe for concurrent reads from any number of threads.
 */
public interface MemoryReadSnapshot {

	/**
	 * @return the program modification number this snapshot was written at
	 */
	long getGeneration();

	/**
	 * Copy {@code length} bytes at {@code offset} of {@code space} into {@code dest}, only if the
	 * snapshot holds the whole range.
	 * @param space the address space
	 * @param offset the byte offset in the space
	 * @param dest the destination
	 * @param destIndex the first index written in {@code dest}
	 * @param length the number of bytes ({@code > 0})
	 * @return true if all bytes were copied; false if the snapshot does not hold the whole range
	 * or is closed (nothing is guaranteed about {@code dest} then and the caller reads again)
	 */
	boolean read(AddressSpace space, long offset, byte[] dest, int destIndex, int length);

	/**
	 * Called once when the memory map drops this snapshot (a memory change, or a replacement by
	 * {@link MemoryMapDB#setReadSnapshot}); reads already in progress may still complete.
	 */
	default void detached() {
		// nothing by default
	}
}
