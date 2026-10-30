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

import java.util.Arrays;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * The search behind {@link MemoryMapDB#findBytes}.
 * <p>
 * The legacy search ({@link #legacyFind}, the code that was in MemoryMapDB) visits one address at
 * a time and reads {@code pattern.length} bytes through the whole memory lock chain at each one.
 * The bulk search ({@link #bulkFind}) reads 64 KB chunks (plus {@code pattern.length - 1} bytes of
 * overlap) per address range and scans each chunk with a {@link ByteScanner} (native SIMD when
 * its library is loaded, Java otherwise). Its result is the same address: the legacy search
 * returns the first (forward) or last (backward) address of the set, in iteration order, whose
 * {@code pattern.length} bytes can be read in full and match; its skip step never jumps over a
 * match (it skips {@code j} only when the read window rules out every start before {@code j}).
 * Where a chunk read comes back short or fails, the bulk search decides those addresses with the
 * legacy per-address check, so read failures behave the same. Only progress and the moment a
 * cancel is noticed differ (per chunk instead of per address).
 * <p>
 * System property {@code hydra.memory.findBytes.bulk=false} selects the legacy search.
 */
public final class MemoryBulkSearch {

	/** Candidate window starts per chunk. */
	static final int CHUNK = 64 * 1024;

	static final boolean BULK_ENABLED =
		!"false".equalsIgnoreCase(System.getProperty("hydra.memory.findBytes.bulk"));

	/** Reads memory bytes the way {@link MemoryMapDB#getBytes(Address, byte[], int, int)} does. */
	@FunctionalInterface
	public interface ByteReader {
		int getBytes(Address addr, byte[] dest, int destIndex, int size)
				throws MemoryAccessException;
	}

	private MemoryBulkSearch() {
	}

	/**
	 * Search with the configured method ({@link #bulkFind} unless disabled).
	 *
	 * @param set the addresses where a match may start
	 * @param start first address to consider
	 * @param end null, or the last address to consider (inclusive, in search direction)
	 * @param bytes the pattern
	 * @param masks null, or one mask per pattern byte
	 * @param forward search direction
	 * @param monitor the monitor
	 * @param reader the memory reader
	 * @return the matching address or null
	 */
	public static Address find(AddressSetView set, Address start, Address end, byte[] bytes,
			byte[] masks, boolean forward, TaskMonitor monitor, ByteReader reader) {
		if (BULK_ENABLED) {
			return bulkFind(set, start, end, bytes, masks, forward, monitor, reader,
				ByteScanner.preferred());
		}
		return legacyFind(set, start, end, bytes, masks, forward, monitor, reader);
	}

	// ---------------------------------------------------------------------------------------
	// Bulk search
	// ---------------------------------------------------------------------------------------

	/**
	 * Chunked search; see the class comment. Same arguments as {@link #find}.
	 *
	 * @param set the addresses where a match may start
	 * @param start first address to consider
	 * @param end null, or the last address to consider (inclusive, in search direction)
	 * @param bytes the pattern
	 * @param masks null, or one mask per pattern byte
	 * @param forward search direction
	 * @param monitor the monitor
	 * @param reader the memory reader
	 * @param scanner the chunk scanner
	 * @return the matching address or null
	 */
	public static Address bulkFind(AddressSetView set, Address start, Address end, byte[] bytes,
			byte[] masks, boolean forward, TaskMonitor monitor, ByteReader reader,
			ByteScanner scanner) {
		return bulkFind(set, start, end, bytes, masks, forward, monitor, reader, scanner, CHUNK);
	}

	/** {@link #bulkFind} with a chunk size (tests use small chunks to hit chunk edges). */
	static Address bulkFind(AddressSetView set, Address start, Address end, byte[] bytes,
			byte[] masks, boolean forward, TaskMonitor monitor, ByteReader reader,
			ByteScanner scanner, int chunk) {
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		if (bytes.length == 0 || (masks != null && masks.length < bytes.length)) {
			// degenerate patterns keep their exact legacy behaviour
			return legacyFind(set, start, end, bytes, masks, forward, monitor, reader);
		}
		byte[] buf = new byte[chunk + bytes.length - 1];
		byte[] one = new byte[bytes.length];
		AddressRangeIterator ranges = set.getAddressRanges(start, forward);
		while (ranges.hasNext()) {
			if (monitor.isCancelled()) {
				return null;
			}
			AddressRange r = ranges.next();
			Address lo = r.getMinAddress();
			Address hi = r.getMaxAddress();
			Address found;
			if (forward) {
				if (lo.compareTo(start) < 0) {
					lo = start;
				}
				if (end != null) {
					if (lo.compareTo(end) > 0) {
						return null;
					}
					if (hi.compareTo(end) > 0) {
						hi = end;
					}
				}
				if (lo.compareTo(hi) > 0) {
					continue;
				}
				found = scanForward(lo, hi, bytes, masks, monitor, reader, scanner, buf, one,
					chunk);
			}
			else {
				if (hi.compareTo(start) > 0) {
					hi = start;
				}
				if (end != null) {
					if (hi.compareTo(end) < 0) {
						return null;
					}
					if (lo.compareTo(end) < 0) {
						lo = end;
					}
				}
				if (lo.compareTo(hi) > 0) {
					continue;
				}
				found = scanBackward(lo, hi, bytes, masks, monitor, reader, scanner, buf, one,
					chunk);
			}
			if (found != null || monitor.isCancelled()) {
				return found;
			}
		}
		return null;
	}

	/** Bytes read at addr into buf[0, want), or 0 when the read fails. */
	private static int read(ByteReader reader, Address addr, byte[] buf, int want) {
		try {
			int n = reader.getBytes(addr, buf, 0, want);
			return Math.max(0, Math.min(n, want));
		}
		catch (Exception e) {
			return 0;
		}
	}

	/** Candidates left from pos to last inclusive, capped at CHUNK (unsigned arithmetic). */
	private static int chunkCount(long pos, long last, int chunk) {
		long left = last - pos + 1; // 0 means 2^64 candidates
		if (left == 0 || Long.compareUnsigned(left, chunk) > 0) {
			return chunk;
		}
		return (int) left;
	}

	private static Address scanForward(Address lo, Address hi, byte[] bytes, byte[] masks,
			TaskMonitor monitor, ByteReader reader, ByteScanner scanner, byte[] buf, byte[] one,
			int chunk) {
		int len = bytes.length;
		long last = hi.subtract(lo);
		long pos = 0;
		while (Long.compareUnsigned(pos, last) <= 0) {
			if (monitor.isCancelled()) {
				return null;
			}
			int count = chunkCount(pos, last, chunk);
			Address a = lo.add(pos);
			int n = read(reader, a, buf, count + len - 1);
			int full = Math.min(count, n - len + 1);
			if (full > 0) {
				int k = scanner.find(buf, full, bytes, masks, true);
				if (k >= 0) {
					return a.add(k);
				}
				monitor.incrementProgress(full);
				pos += full;
			}
			else {
				// the window at a cannot be read in full in bulk: decide it the legacy way
				if (match(a, bytes, masks, one, true, reader) == 1) {
					return a;
				}
				monitor.incrementProgress(1);
				pos += 1;
			}
			if (pos == 0) {
				break; // wrapped after the last address of a full 64-bit range
			}
		}
		return null;
	}

	private static Address scanBackward(Address lo, Address hi, byte[] bytes, byte[] masks,
			TaskMonitor monitor, ByteReader reader, ByteScanner scanner, byte[] buf, byte[] one,
			int chunk) {
		int len = bytes.length;
		long top = hi.subtract(lo); // highest candidate, relative to lo
		while (true) {
			if (monitor.isCancelled()) {
				return null;
			}
			int count = chunkCount(0, top, chunk);
			long base = top - count + 1;
			Address a = lo.add(base);
			int n = read(reader, a, buf, count + len - 1);
			int full = Math.max(0, Math.min(count, n - len + 1));
			// the highest candidates whose windows were not read in full: legacy check each
			for (int i = count - 1; i >= full; i--) {
				Address c = a.add(i);
				if (match(c, bytes, masks, one, false, reader) == 1) {
					return c;
				}
				if (monitor.isCancelled()) {
					return null;
				}
			}
			if (full > 0) {
				int k = scanner.find(buf, full, bytes, masks, false);
				if (k >= 0) {
					return a.add(k);
				}
			}
			monitor.incrementProgress(count);
			if (base == 0) {
				return null;
			}
			top = base - 1;
		}
	}

	// ---------------------------------------------------------------------------------------
	// Legacy search (moved unchanged from MemoryMapDB.findBytes and MemoryMapDB.match)
	// ---------------------------------------------------------------------------------------

	/**
	 * The per-address search MemoryMapDB used before the bulk search. With {@code end == null}
	 * it is the former {@code findBytes(addr, ...)}, otherwise the former
	 * {@code findBytes(startAddr, endAddr, ...)}.
	 *
	 * @param set the addresses where a match may start
	 * @param addr first address to consider
	 * @param endAddr null, or the last address to consider
	 * @param bytes the pattern
	 * @param masks null, or one mask per pattern byte
	 * @param forward search direction
	 * @param monitor the monitor
	 * @param reader the memory reader
	 * @return the matching address or null
	 */
	public static Address legacyFind(AddressSetView set, Address addr, Address endAddr,
			byte[] bytes, byte[] masks, boolean forward, TaskMonitor monitor, ByteReader reader) {
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		return endAddr == null
				? legacyFindNoEnd(set, addr, bytes, masks, forward, monitor, reader)
				: legacyFindWithEnd(set, addr, endAddr, bytes, masks, forward, monitor, reader);
	}

	private static Address legacyFindNoEnd(AddressSetView set, Address addr, byte[] bytes,
			byte[] masks, boolean forward, TaskMonitor monitor, ByteReader reader) {
		AddressIterator it = set.getAddresses(addr, forward);
		byte[] b = new byte[bytes.length];
		if (forward) {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				int moffset = match(addr2, bytes, masks, b, forward, reader);
				if (moffset < 0) {
					try {
						Address jumpAddr = addr2.addNoWrap(-moffset);
						if (jumpAddr.hasSameAddressSpace(addr2)) {
							it = set.getAddresses(jumpAddr, forward);
						}
						monitor.incrementProgress(-moffset);
					}
					catch (AddressOverflowException e) {
						// ignore
					}
					continue;
				}
				if (moffset == 1) {
					return addr2;
				}

				monitor.incrementProgress(moffset);
			}
		}
		else {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				int moffset = match(addr2, bytes, masks, b, forward, reader);
				if (moffset == 1) {
					return addr2;
				}

				monitor.incrementProgress(moffset);
			}
		}
		return null;
	}

	private static Address legacyFindWithEnd(AddressSetView set, Address startAddr,
			Address endAddr, byte[] bytes, byte[] masks, boolean forward, TaskMonitor monitor,
			ByteReader reader) {
		AddressIterator it = set.getAddresses(startAddr, forward);
		byte[] b = new byte[bytes.length];
		if (forward) {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				if (addr2.compareTo(endAddr) > 0) {
					return null;
				}
				int moffset = match(addr2, bytes, masks, b, forward, reader);
				if (moffset < 0) {
					try {
						Address jumpAddr = addr2.addNoWrap(-moffset);
						if (jumpAddr.hasSameAddressSpace(addr2)) {
							it = set.getAddresses(jumpAddr, forward);
						}
						monitor.incrementProgress(-moffset);
					}
					catch (AddressOverflowException e) {
						moffset = -moffset;
						for (int i = 0; i < moffset; i++) {
							if (it.hasNext()) {
								it.next();
							}
							else {
								break;
							}
						}
						monitor.incrementProgress(moffset);
					}
					continue;
				}
				if (moffset == 1) {
					return addr2;
				}

				// No match, and we're going to move to the next address so increment our
				// progress by 1.
				monitor.incrementProgress(1);
			}
		}
		else {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				if (addr2.compareTo(endAddr) < 0) {
					return null;
				}
				int moffset = match(addr2, bytes, masks, b, forward, reader);
				if (moffset == 1) {
					return addr2;
				}

				// If we're here, then no match was found so just increment to the monitor
				// by 1 (one address).
				monitor.incrementProgress(1);
			}
		}
		return null;
	}

	/**
	 * Tests if the memory contains a sequence of contiguous bytes that match the given byte array
	 * at all bit positions where the mask contains an "on" bit.
	 *
	 * @return 1 if there is a match 0 if there is no match -i if no match is found, this is the
	 *         number of bytes that can be safely skipped
	 */
	static int match(Address addr, byte[] bytes, byte[] masks, byte[] data, boolean forward,
			ByteReader reader) {
		try {
			if (reader.getBytes(addr, data, 0, data.length) < data.length) {
				return 0;
			}

			//
			// if there is no mask, check is simpler
			//
			if (masks == null) {
				// check if the bytes pattern entirely matches the data
				if (Arrays.equals(data, bytes)) {
					return 1;
				}

				if (!forward) {
					return 0;
				}

				// check to see if the first byte of the pattern
				// matches any byte in the buffer
				//  if it does, return it's negative offset
				for (int j = 1; j < bytes.length; j++) {
					int off = 0;
					for (; off < (data.length - j); off++) {
						if (bytes[off] != data[j + off]) {
							break;
						}
					}
					if (off + j == data.length) {
						return -j;
					}
				}
				return -bytes.length;
			}

			// first check if the pattern entirely matches the bytes
			int i;
			for (i = 0; i < bytes.length; i++) {
				if ((data[i] & masks[i]) != (bytes[i] & masks[i])) {
					break;
				}
			}
			if (i == bytes.length) {
				return 1;
			}

			if (!forward) {
				return 0;
			}

			// check to see if the first byte of the pattern
			// matches any byte in the buffer
			//  if it does, return it's negative offset
			for (int j = 1; j < bytes.length; j++) {
				int off = 0;
				for (; off < (data.length - j); off++) {
					if ((bytes[off] & masks[off]) != (data[j + off] & masks[off])) {
						break;
					}
				}
				if (off + j == data.length) {
					return -j;
				}
			}
			return -bytes.length;
		}
		catch (Exception e) {
			return 0;
		}
	}
}
