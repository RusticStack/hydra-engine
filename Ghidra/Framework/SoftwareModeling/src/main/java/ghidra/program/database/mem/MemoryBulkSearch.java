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
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The search behind {@link MemoryMapDB#findBytes}.
 * <p>
 * The legacy search ({@link #legacyFind}, the code that was in MemoryMapDB) visits one address at
 * a time and reads {@code pattern.length} bytes through the whole memory lock chain at each one.
 * The bulk search ({@link #bulkFind}) reads chunks per address range, starting at
 * {@link #FIRST_CHUNK} candidates and doubling up to 64 KB (plus {@code pattern.length - 1} bytes
 * of overlap), and scans each chunk with a {@link ByteScanner} (native SIMD when its library is
 * loaded, Java otherwise; a failing native scanner falls back to Java). It returns the first
 * (forward) or last (backward) address of the set, in iteration order, whose
 * {@code pattern.length} bytes can be read in full and match, which is the legacy result (its
 * skip step never jumps over a match: it skips {@code j} only when the read window rules out
 * every start before {@code j}). Where a chunk read comes back short or fails, the read is
 * retried smaller down to one window, or (backward) the window is decided by the legacy check.
 * <p>
 * Intended differences from the legacy search:
 * <ul>
 * <li>Progress and cancellation are noticed per chunk instead of per address.</li>
 * <li>{@code findBytes(start, end = null, ...)} used to throw a NullPointerException; it now
 * searches without an end.</li>
 * <li>With an end address, forward: when the legacy skip step overflowed at the top of an
 * address space it advanced its address iterator by {@code j} set addresses instead, which could
 * jump past the first addresses of the next space or range and miss a match there. The bulk
 * search does not skip them (the same result as the legacy search without an end address);
 * see {@code MemoryBulkSearchTest#testLegacySkipOverflowQuirk}.</li>
 * </ul>
 * <p>
 * System property {@code hydra.memory.findBytes.bulk=false} selects the legacy search.
 */
public final class MemoryBulkSearch {

	/** Maximum candidate window starts per chunk. */
	static final int CHUNK = 64 * 1024;

	/** Candidate window starts in the first chunk of a range (doubles up to {@link #CHUNK}). */
	static final int FIRST_CHUNK = 32;

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
				scannerFailed ? ByteScanner.JAVA : ByteScanner.preferred());
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

	/** {@link #bulkFind} with a maximum chunk size (tests use small chunks to hit chunk edges). */
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
		Scan s = new Scan(bytes, masks, monitor, reader, scanner, chunk);
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
				found = s.forward(lo, hi);
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
				found = s.backward(lo, hi);
			}
			if (found != null || monitor.isCancelled()) {
				return found;
			}
		}
		return null;
	}

	/**
	 * Set once a scanner other than {@link ByteScanner#JAVA} failed: {@link #find} then uses the
	 * Java one for the rest of the process.
	 */
	private static volatile boolean scannerFailed;

	/** @return whether a scanner failure switched {@link #find} to the Java scanner */
	static boolean scannerFailed() {
		return scannerFailed;
	}

	/** Tests: forget a recorded scanner failure. */
	static void resetScannerFailed() {
		scannerFailed = false;
	}

	/** Candidates left from pos to last inclusive, capped at step (unsigned arithmetic). */
	private static int chunkCount(long pos, long last, int step) {
		long left = last - pos + 1; // 0 means 2^64 candidates
		if (left == 0 || Long.compareUnsigned(left, step) > 0) {
			return step;
		}
		return (int) left;
	}

	/**
	 * One bulk search. The chunk size starts at {@link #FIRST_CHUNK} and doubles after every
	 * chunk read in full up to the maximum, so a match near the start costs about one small
	 * read (dense matches, repeated {@code findBytes(found + 1)}), and a long scan reaches 64 KB
	 * reads after a few chunks. After a chunk read that comes back short or throws, the chunk
	 * size is halved and the read retried, so a range whose end is followed by memory that
	 * throws costs O(log chunk) failed reads, not one failed chunk read per address. A window
	 * that cannot be read on its own (a one-candidate read of {@code pattern.length} bytes, the
	 * same read the legacy check makes) does not match, as in the legacy search.
	 */
	private static final class Scan {
		final byte[] bytes;
		final byte[] masks;
		final TaskMonitor monitor;
		final ByteReader reader;
		ByteScanner scanner;
		final int chunk;
		final int len;
		byte[] buf;
		final byte[] one;

		Scan(byte[] bytes, byte[] masks, TaskMonitor monitor, ByteReader reader,
				ByteScanner scanner, int chunk) {
			this.bytes = bytes;
			this.masks = masks;
			this.monitor = monitor;
			this.reader = reader;
			this.scanner = scanner;
			this.chunk = chunk;
			this.len = bytes.length;
			this.one = new byte[len];
			this.buf = new byte[Math.min(FIRST_CHUNK, chunk) + len - 1];
		}

		/** Bytes read at addr into buf[0, want), or 0 when the read fails. */
		int read(Address addr, int want) {
			if (buf.length < want) {
				buf = new byte[Math.max(want, Math.min(buf.length * 2, chunk + len - 1))];
			}
			try {
				int n = reader.getBytes(addr, buf, 0, want);
				return Math.max(0, Math.min(n, want));
			}
			catch (Exception e) {
				return 0;
			}
		}

		/** The scanner, falling back to the Java one if a native scanner fails. */
		int scan(int count, boolean forward) {
			if (scanner != ByteScanner.JAVA) {
				try {
					return scanner.find(buf, count, bytes, masks, forward);
				}
				catch (RuntimeException e) {
					if (!scannerFailed) {
						scannerFailed = true;
						Msg.warn(MemoryBulkSearch.class, "Byte scanner " + scanner.name() +
							" failed (" + e + "); using the Java scanner from now on", e);
					}
					scanner = ByteScanner.JAVA;
				}
			}
			return ByteScanner.JAVA.find(buf, count, bytes, masks, forward);
		}

		Address forward(Address lo, Address hi) {
			long last = hi.subtract(lo);
			long pos = 0;
			int step = Math.min(FIRST_CHUNK, chunk);
			while (Long.compareUnsigned(pos, last) <= 0) {
				if (monitor.isCancelled()) {
					return null;
				}
				int count = chunkCount(pos, last, step);
				Address a = lo.add(pos);
				int n = read(a, count + len - 1);
				int full = Math.max(0, Math.min(count, n - len + 1));
				if (full > 0) {
					int k = scan(full, true);
					if (k >= 0) {
						return a.add(k);
					}
				}
				int done;
				if (full == count) {
					done = count;
					step = Math.min(chunk, step * 2);
				}
				else if (full > 0) {
					done = full; // retry the rest with a smaller read
					step = Math.max(1, step / 2);
				}
				else if (count > 1) {
					done = 0;
					step = Math.max(1, Math.min(step, count) / 2);
				}
				else {
					// one candidate whose len bytes cannot be read: the legacy check reads the
					// same len bytes at the same address, so it does not match either
					done = 1;
				}
				if (done > 0) {
					monitor.incrementProgress(done);
					pos += done;
					if (pos == 0) {
						break; // wrapped after the last address of a full 64-bit range
					}
				}
			}
			return null;
		}

		Address backward(Address lo, Address hi) {
			long top = hi.subtract(lo); // highest candidate, relative to lo
			int step = Math.min(FIRST_CHUNK, chunk);
			while (true) {
				if (monitor.isCancelled()) {
					return null;
				}
				int count = chunkCount(0, top, step);
				long base = top - count + 1;
				Address a = lo.add(base);
				int n = read(a, count + len - 1);
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
					int k = scan(full, false);
					if (k >= 0) {
						return a.add(k);
					}
				}
				monitor.incrementProgress(count);
				if (base == 0) {
					return null;
				}
				top = base - 1;
				step = full == count ? Math.min(chunk, step * 2) : Math.min(FIRST_CHUNK, chunk);
			}
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
