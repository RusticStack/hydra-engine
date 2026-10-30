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
// Hydra A/B of snapshot reads (MappedProgramSnapshot, hydra.memory.snapshotReads): compares every
// byte of every block read from the database and from the memory-mapped sealed generation, then
// measures read throughput and heap with N concurrent readers, mapping off/on/off/on.
// Script arguments: [threads=8] [opsPerThread=2000000] [maxRead=256]
// Output: one "SNAPAB" line per result, for the A/B report.
//@category Hydra

import java.lang.management.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

import ghidra.app.decompiler.MappedProgramSnapshot;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

public class SnapshotReadsABScript extends GhidraScript {

	private record Range(Address start, long length) {
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int threads = args.length > 0 ? Integer.parseInt(args[0]) : 8;
		int ops = args.length > 1 ? Integer.parseInt(args[1]) : 2_000_000;
		int maxRead = args.length > 2 ? Integer.parseInt(args[2]) : 256;
		Memory memory = currentProgram.getMemory();
		String name = currentProgram.getName();

		// ---- 1. exhaustive compare ----
		long t0 = System.nanoTime();
		List<String> dbRead = readEverything(memory);
		long dbMs = (System.nanoTime() - t0) / 1_000_000;
		t0 = System.nanoTime();
		MappedProgramSnapshot snap = MappedProgramSnapshot.attach(currentProgram);
		long attachMs = (System.nanoTime() - t0) / 1_000_000;
		if (snap == null) {
			println("SNAPAB " + name + " FAIL no snapshot");
			return;
		}
		long fileBytes = java.nio.file.Files.size(snap.getPath());
		t0 = System.nanoTime();
		List<String> mapRead = readEverything(memory);
		long mapMs = (System.nanoTime() - t0) / 1_000_000;
		long served = snap.servedReads();
		snap.close();
		List<String> dbAgain = readEverything(memory);
		boolean same = dbRead.equals(mapRead) && dbRead.equals(dbAgain);
		long bytes = 0;
		int blocks = 0;
		for (MemoryBlock b : memory.getBlocks()) {
			blocks++;
			bytes += b.isInitialized() && !b.isMapped() ? b.getSize() : 0;
		}
		println(String.format(
			"SNAPAB %s compare %s blocks=%d initializedBytes=%d checks=%d served=%d " +
				"fileBytes=%d attachMs=%d exhaustiveMs db=%d map=%d",
			name, same ? "IDENTICAL" : "DIFFERENT", blocks, bytes, dbRead.size(), served,
			fileBytes, attachMs, dbMs, mapMs));
		if (!same) {
			for (int i = 0; i < Math.min(dbRead.size(), mapRead.size()); i++) {
				if (!dbRead.get(i).equals(mapRead.get(i))) {
					println("SNAPAB first difference at check " + i);
					break;
				}
			}
			return;
		}

		// ---- 2. throughput and heap with N concurrent readers ----
		List<Range> ranges = new ArrayList<>();
		for (MemoryBlock b : memory.getBlocks()) {
			if (b.isInitialized() && !b.isMapped() && b.getSize() > 0) {
				ranges.add(new Range(b.getStart(), b.getSize()));
			}
		}
		for (String mode : List.of("off", "on", "off", "on")) {
			MappedProgramSnapshot s = mode.equals("on") ? MappedProgramSnapshot.attach(currentProgram)
					: null;
			if (mode.equals("on") && s == null) {
				println("SNAPAB " + name + " FAIL no snapshot for pass");
				return;
			}
			System.gc();
			long heapBefore = heapUsed();
			resetPeaks();
			ExecutorService pool = Executors.newFixedThreadPool(threads);
			List<Future<long[]>> fs = new ArrayList<>();
			CyclicBarrier barrier = new CyclicBarrier(threads);
			long start = System.nanoTime();
			for (int t = 0; t < threads; t++) {
				int seed = t;
				fs.add(pool.submit(() -> readerLoop(memory, ranges, ops, maxRead, seed, barrier)));
			}
			long totalBytes = 0;
			long allocated = 0;
			long checksum = 0;
			for (Future<long[]> f : fs) {
				long[] r = f.get();
				totalBytes += r[0];
				allocated += r[1];
				checksum += r[2];
			}
			long wallNs = System.nanoTime() - start;
			pool.shutdown();
			long peak = heapPeak();
			long heapAfter = heapUsed();
			System.gc();
			long heapAfterGc = heapUsed();	// what the pass left live (buffer cache, mapping objects)
			long servedPass = s == null ? 0 : s.servedReads();
			if (s != null) {
				s.close();
			}
			double secs = wallNs / 1e9;
			println(String.format(
				"SNAPAB %s pass=%s threads=%d ops=%d wallMs=%d Mops/s=%.3f MB/s=%.1f " +
					"allocMB=%.1f heapPeakMB=%.1f heapBeforeMB=%.1f heapAfterMB=%.1f heapAfterGcMB=%.1f served=%d " +
					"checksum=%d",
				name, mode, threads, (long) threads * ops, wallNs / 1_000_000,
				threads * (double) ops / secs / 1e6, totalBytes / secs / 1e6, allocated / 1e6,
				peak / 1e6, heapBefore / 1e6, heapAfter / 1e6, heapAfterGc / 1e6, servedPass, checksum));
		}
	}

	/** Every byte of every block, through Memory.getBytes, MemoryBlock.getBytes and getByte. */
	private List<String> readEverything(Memory memory) throws Exception {
		List<String> out = new ArrayList<>();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		for (MemoryBlock b : memory.getBlocks()) {
			long size = b.getSize();
			// whole block in 64 KiB chunks through Memory.getBytes
			md.reset();
			byte[] buf = new byte[1 << 16];
			StringBuilder status = new StringBuilder();
			for (long done = 0; done < size;) {
				int n = (int) Math.min(buf.length, size - done);
				try {
					int got = memory.getBytes(b.getStart().add(done), buf, 0, n);
					md.update(buf, 0, got);
					status.append(got).append(',');
				}
				catch (MemoryAccessException e) {
					status.append("E,");
				}
				done += n;
			}
			out.add(b.getName() + " mem " + status.toString().hashCode() + " " +
				HexFormat.of().formatHex(md.digest()));
			// MemoryBlock.getBytes in odd-sized pieces (crosses every 64 KiB boundary differently)
			md.reset();
			status.setLength(0);
			byte[] odd = new byte[4093];
			for (long done = 0; done < size;) {
				int n = (int) Math.min(odd.length, size - done);
				try {
					int got = b.getBytes(b.getStart().add(done), odd, 0, n);
					md.update(odd, 0, got);
					status.append(got).append(',');
				}
				catch (MemoryAccessException e) {
					status.append("E,");
				}
				done += n;
			}
			out.add(b.getName() + " block " + status.toString().hashCode() + " " +
				HexFormat.of().formatHex(md.digest()));
			// every byte through getByte (initialized blocks up to 16 MiB)
			if (b.isInitialized() && size <= (16 << 20)) {
				md.reset();
				Address a = b.getStart();
				for (long i = 0; i < size; i++) {
					try {
						md.update(memory.getByte(a.add(i)));
					}
					catch (MemoryAccessException e) {
						md.update((byte) 0x55);
						md.update((byte) 0xAA);
					}
				}
				out.add(b.getName() + " byte " + HexFormat.of().formatHex(md.digest()));
			}
		}
		// reads that cross block ends and region gaps
		for (MemoryBlock b : memory.getBlocks()) {
			for (long back : new long[] { 1, 7, 255 }) {
				if (b.getSize() <= back) {
					continue;
				}
				Address a = b.getEnd().subtract(back - 1);
				byte[] buf = new byte[512];
				try {
					int got = memory.getBytes(a, buf);
					out.add("cross " + a + " " + got + " " +
						HexFormat.of().formatHex(Arrays.copyOf(buf, got)));
				}
				catch (MemoryAccessException e) {
					out.add("cross " + a + " E");
				}
			}
		}
		return out;
	}

	private static long[] readerLoop(Memory memory, List<Range> ranges, int ops, int maxRead,
			int seed, CyclicBarrier barrier) throws Exception {
		SplittableRandom random = new SplittableRandom(0x5eed + seed);
		long[] weights = new long[ranges.size()];
		long total = 0;
		for (int i = 0; i < ranges.size(); i++) {
			total += ranges.get(i).length();
			weights[i] = total;
		}
		byte[] buf = new byte[maxRead];
		com.sun.management.ThreadMXBean tmx =
			(com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
		long tid = Thread.currentThread().threadId();
		barrier.await();
		long alloc0 = tmx.getThreadAllocatedBytes(tid);
		long bytes = 0;
		long checksum = 0;
		for (int i = 0; i < ops; i++) {
			long pick = random.nextLong(total);
			int r = Arrays.binarySearch(weights, pick + 1);
			r = r >= 0 ? r : -r - 1;
			Range range = ranges.get(r);
			long off = pick - (r == 0 ? 0 : weights[r - 1]);
			int len = 1 + random.nextInt(maxRead);
			try {
				int got = memory.getBytes(range.start().add(off), buf, 0, len);
				bytes += got;
				checksum += buf[0] + buf[got - 1];
			}
			catch (MemoryAccessException e) {
				checksum += 7;
			}
		}
		long alloc = tmx.getThreadAllocatedBytes(tid) - alloc0;
		return new long[] { bytes, alloc, checksum };
	}

	private static long heapUsed() {
		return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
	}

	private static void resetPeaks() {
		for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
			if (pool.getType() == MemoryType.HEAP) {
				pool.resetPeakUsage();
			}
		}
	}

	private static long heapPeak() {
		long sum = 0;
		for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
			if (pool.getType() == MemoryType.HEAP) {
				sum += pool.getPeakUsage().getUsed();
			}
		}
		return sum;
	}
}
