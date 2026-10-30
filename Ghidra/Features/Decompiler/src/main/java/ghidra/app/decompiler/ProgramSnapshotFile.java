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
package ghidra.app.decompiler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

/**
 * A sealed-generation snapshot of a program's initialized memory, written once per program
 * modification number and read by the decompiler process through a memory mapping instead of a
 * {@code getBytes} callback per request (Hydra, prototype).
 * <p>
 * The snapshot is used only when the system property {@value #ENABLE_PROPERTY} is {@code true}
 * (default off). The decompiler serves a request from the snapshot only when the whole range lies in
 * one region; any other request still goes through {@link DecompileCallback#getBytes}, so the bytes
 * the decompiler sees are the same with the snapshot on or off.
 * <p>
 * File format, version 1, little-endian (also read by {@code SnapshotImage} in loadimage_ghidra.cc
 * and by the Rust crate {@code hydra-snapshot}; see docs/hydra-snapshot.md):
 * <pre>
 *   0  magic "HYSNAP01"        8  u32 version (1)     12 u32 space count
 *  16  u32 region count       20  u32 reserved (0)    24 u64 generation (modification number)
 *  32  region table: per region u32 space index, u32 reserved, u64 offset, u64 length, u64 data offset
 *      space table: per space u32 byte length, UTF-8 name
 *      data: the bytes of each region at its data offset
 * </pre>
 * Regions are sorted by space index and offset and never overlap; adjacent initialized blocks of
 * the same space are merged, matching {@link Memory#getBytes} which reads across them.
 * <p>
 * Instances are shared by every {@link DecompInterface} of the same program and generation and are
 * deleted when the last lease is released; files still leased when the JVM exits (an interface
 * that was never disposed) are deleted by a shutdown hook.
 * <p>
 * The generation is best-effort under concurrent edits: {@link Program#getModificationNumber()} is
 * bumped after a change is written and is read here without the program lock, so a decompile that
 * races with a byte edit can see the bytes from before or after the edit, as the callback path can.
 * The file is written outside the per-program lock; while one thread writes it, other interfaces
 * of the program use callbacks instead of waiting.
 */
public final class ProgramSnapshotFile {

	/** System property that turns the snapshot on ({@code true}); default off. */
	public static final String ENABLE_PROPERTY = "hydra.decompiler.snapshot";

	static final byte[] MAGIC = "HYSNAP01".getBytes(StandardCharsets.US_ASCII);
	static final int VERSION = 1;
	static final int HEADER_SIZE = 32;
	static final int REGION_ENTRY_SIZE = 32;

	private static final int COPY_CHUNK = 1 << 20;

	/** Current snapshot per program, keyed by identity; each holder is its own lock. */
	private static final Map<Program, Holder> HOLDERS = new WeakHashMap<>();

	/** Snapshot files written by this JVM and not yet deleted; removed by a shutdown hook. */
	private static final Set<Path> LIVE_FILES = new HashSet<>();
	private static boolean shutdownHookAdded;	// guarded by LIVE_FILES

	private final Holder holder;
	private final Path path;
	private final long generation;
	private int leases;		// guarded by holder

	private ProgramSnapshotFile(Holder holder, Path path, long generation) {
		this.holder = holder;
		this.path = path;
		this.generation = generation;
	}

	/**
	 * @return true if decompiler snapshots are turned on for this JVM
	 */
	public static boolean isEnabled() {
		return Boolean.getBoolean(ENABLE_PROPERTY);
	}

	/**
	 * @return the snapshot file
	 */
	public Path getPath() {
		return path;
	}

	/**
	 * @return the program modification number the snapshot was written at
	 */
	public long getGeneration() {
		return generation;
	}

	private static final class Holder {
		ProgramSnapshotFile current;
		boolean writing;	// a thread is writing a new generation outside the lock
	}

	private static Holder holder(Program program) {
		synchronized (HOLDERS) {
			return HOLDERS.computeIfAbsent(program, p -> new Holder());
		}
	}

	/**
	 * Lease the snapshot of the program's current generation, writing it if no other user has.
	 * The previous lease is released when a different snapshot is returned.
	 * @param program the program
	 * @param previous the caller's current lease, or null
	 * @return the leased snapshot, or null if the program is not a database program, another
	 * thread is writing its snapshot, the program changed while it was written or the file could
	 * not be written (the caller then uses callbacks only)
	 */
	static ProgramSnapshotFile acquire(Program program, ProgramSnapshotFile previous) {
		if (!(program instanceof ProgramDB)) {
			release(previous);	// other Program views may not read their memory like ProgramDB
			return null;
		}
		long generation = program.getModificationNumber();
		if (previous != null && previous.generation == generation) {
			return previous;
		}
		Holder holder = holder(program);
		ProgramSnapshotFile result = null;
		boolean mustWrite = false;
		synchronized (holder) {
			ProgramSnapshotFile current = holder.current;
			if (current != null && current.generation == generation) {
				current.leases++;
				result = current;
			}
			else if (!holder.writing) {
				holder.writing = true;
				mustWrite = true;
			}
		}
		if (mustWrite) {
			ProgramSnapshotFile written = null;
			try {
				written = write(holder, program, generation);
			}
			finally {
				synchronized (holder) {
					holder.writing = false;
					if (written != null) {
						written.leases++;
						holder.current = written;	// the old current is deleted by its last release
					}
				}
			}
			result = written;
		}
		release(previous);
		return result;
	}

	/**
	 * Release a lease; the file is deleted when its last lease is released.
	 * @param snapshot the lease to release, or null
	 */
	static void release(ProgramSnapshotFile snapshot) {
		if (snapshot == null) {
			return;
		}
		synchronized (snapshot.holder) {
			if (--snapshot.leases > 0) {
				return;
			}
			if (snapshot.holder.current == snapshot) {
				snapshot.holder.current = null;
			}
		}
		snapshot.delete();
	}

	private void delete() {
		deleteFile(path);
	}

	private static void deleteFile(Path file) {
		try {
			Files.deleteIfExists(file);
		}
		catch (IOException e) {
			file.toFile().deleteOnExit();
		}
		synchronized (LIVE_FILES) {
			LIVE_FILES.remove(file);
		}
	}

	private static Path createFile() throws IOException {
		Path file = Files.createTempFile(snapshotDirectory(), "prog-", ".hysnap");
		synchronized (LIVE_FILES) {
			LIVE_FILES.add(file);
			if (!shutdownHookAdded) {
				shutdownHookAdded = true;
				Runtime.getRuntime()
						.addShutdownHook(new Thread(ProgramSnapshotFile::deleteLiveFiles,
							"Decompiler snapshot cleanup"));
			}
		}
		return file;
	}

	private static void deleteLiveFiles() {
		List<Path> files;
		synchronized (LIVE_FILES) {
			files = new ArrayList<>(LIVE_FILES);
		}
		for (Path file : files) {
			try {
				Files.deleteIfExists(file);
			}
			catch (IOException e) {
				// the process may still map it; nothing more to do at exit
			}
		}
	}

	/**
	 * @return the snapshot files this JVM has written and not yet deleted (tests)
	 */
	static Set<Path> liveFiles() {
		synchronized (LIVE_FILES) {
			return new HashSet<>(LIVE_FILES);
		}
	}

	private static Path snapshotDirectory() throws IOException {
		Path dir = Paths.get(System.getProperty("java.io.tmpdir"), "hydra-decompiler-snapshots");
		Files.createDirectories(dir);
		return dir;
	}

	/** One contiguous run of initialized bytes, possibly covering several adjacent blocks. */
	record Region(int spaceIndex, long offset, long length, List<MemoryBlock> blocks) {
	}

	/**
	 * Collect the regions the snapshot holds: initialized, unmapped blocks in byte-addressable
	 * loaded memory spaces (not OTHER sections such as .comment or .debug_*, which the decompiler
	 * does not read), with adjacent blocks of one space merged.
	 * @param memory the program memory
	 * @param spaceNames receives the space names in index order
	 * @return the regions sorted by space index and offset
	 */
	static List<Region> collectRegions(Memory memory, List<String> spaceNames) {
		Map<AddressSpace, List<MemoryBlock>> bySpace = new LinkedHashMap<>();
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || block.isMapped() || block.getSize() <= 0) {
				continue;
			}
			AddressSpace space = block.getStart().getAddressSpace();
			if (space.getAddressableUnitSize() != 1 || !space.isLoadedMemorySpace()) {
				continue;
			}
			bySpace.computeIfAbsent(space, s -> new ArrayList<>()).add(block);
		}
		List<Region> regions = new ArrayList<>();
		for (Map.Entry<AddressSpace, List<MemoryBlock>> entry : bySpace.entrySet()) {
			int spaceIndex = spaceNames.size();
			spaceNames.add(entry.getKey().getName());
			List<MemoryBlock> blocks = entry.getValue();
			blocks.sort(Comparator.comparing(MemoryBlock::getStart));
			List<MemoryBlock> run = new ArrayList<>();
			long runStart = 0;
			long runEnd = 0;	// exclusive
			for (MemoryBlock block : blocks) {
				long start = block.getStart().getOffset();
				if (!run.isEmpty() && start != runEnd) {
					regions.add(new Region(spaceIndex, runStart, runEnd - runStart, run));
					run = new ArrayList<>();
				}
				if (run.isEmpty()) {
					runStart = start;
				}
				run.add(block);
				runEnd = start + block.getSize();
			}
			if (!run.isEmpty()) {
				regions.add(new Region(spaceIndex, runStart, runEnd - runStart, run));
			}
		}
		return regions;
	}

	private static ProgramSnapshotFile write(Holder holder, Program program, long generation) {
		Path file = null;
		try {
			file = createFile();
			List<String> spaceNames = new ArrayList<>();
			List<Region> regions = collectRegions(program.getMemory(), spaceNames);
			writeFile(file, generation, spaceNames, regions);
			if (program.getModificationNumber() != generation) {
				deleteFile(file);	// changed while written: not a sealed generation
				return null;
			}
			return new ProgramSnapshotFile(holder, file, generation);
		}
		catch (IOException | MemoryAccessException | RuntimeException e) {
			Msg.warn(ProgramSnapshotFile.class,
				"Decompiler snapshot not written, using callbacks: " + e.getMessage());
			if (file != null) {
				deleteFile(file);
			}
			return null;
		}
	}

	/**
	 * Write the snapshot of the program's current memory to the given file (tools and tests;
	 * the decompiler uses shared leased files instead).
	 * @param program the program
	 * @param file the file to create or replace
	 * @throws IOException if the file cannot be written
	 * @throws MemoryAccessException if a block cannot be read
	 */
	public static void export(Program program, Path file)
			throws IOException, MemoryAccessException {
		List<String> spaceNames = new ArrayList<>();
		List<Region> regions = collectRegions(program.getMemory(), spaceNames);
		Files.write(file, new byte[0]);
		writeFile(file, program.getModificationNumber(), spaceNames, regions);
	}

	static void writeFile(Path file, long generation, List<String> spaceNames,
			List<Region> regions) throws IOException, MemoryAccessException {
		List<byte[]> names = new ArrayList<>();
		long tableEnd = HEADER_SIZE + (long) regions.size() * REGION_ENTRY_SIZE;
		for (String name : spaceNames) {
			byte[] utf8 = name.getBytes(StandardCharsets.UTF_8);
			names.add(utf8);
			tableEnd += 4 + utf8.length;
		}
		long dataOffset = (tableEnd + 7) & ~7L;
		ByteBuffer head = ByteBuffer.allocate((int) dataOffset).order(ByteOrder.LITTLE_ENDIAN);
		head.put(MAGIC);
		head.putInt(VERSION);
		head.putInt(spaceNames.size());
		head.putInt(regions.size());
		head.putInt(0);
		head.putLong(generation);
		long next = dataOffset;
		for (Region region : regions) {
			head.putInt(region.spaceIndex());
			head.putInt(0);
			head.putLong(region.offset());
			head.putLong(region.length());
			head.putLong(next);
			next += region.length();
		}
		for (byte[] utf8 : names) {
			head.putInt(utf8.length);
			head.put(utf8);
		}
		head.rewind();
		try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE,
			StandardOpenOption.TRUNCATE_EXISTING)) {
			while (head.hasRemaining()) {
				channel.write(head);
			}
			byte[] chunk = new byte[COPY_CHUNK];
			for (Region region : regions) {
				for (MemoryBlock block : region.blocks()) {
					long size = block.getSize();
					for (long done = 0; done < size;) {
						int n = (int) Math.min(chunk.length, size - done);
						int read = block.getBytes(block.getStart().add(done), chunk, 0, n);
						if (read != n) {
							throw new IOException("Short read in block " + block.getName());
						}
						ByteBuffer out = ByteBuffer.wrap(chunk, 0, n);
						while (out.hasRemaining()) {
							channel.write(out);
						}
						done += n;
					}
				}
			}
		}
	}
}
