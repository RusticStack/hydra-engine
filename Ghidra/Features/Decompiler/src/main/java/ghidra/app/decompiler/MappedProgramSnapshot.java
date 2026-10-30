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
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.mem.MemoryReadSnapshot;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Serves a program's byte reads ({@code Memory.getBytes}, {@code MemoryBlock.getBytes},
 * {@code getByte} and every reader built on them) from the memory-mapped sealed-generation
 * snapshot file ({@link ProgramSnapshotFile}, the same shared file the decompiler processes map)
 * instead of the database buffers, so that the hot bytes live outside the Java heap and readers
 * take no database lock (Hydra, behind {@value #ENABLE_PROPERTY}, default off).
 * <p>
 * The file is mapped once per generation into a shared {@link Arena}; any number of threads read
 * it at once. Each read holds a reference, so the arena is closed (unmapped) only when the snapshot
 * was detached and no read is in progress; the file lease is released after that, so the file can
 * be deleted on Windows. The memory map uses the snapshot only while the program's modification
 * number equals its generation and drops it on any memory change ({@link MemoryReadSnapshot}); a
 * read the file does not hold whole goes to the database as before, so the bytes are the same with
 * the flag on and off.
 */
public final class MappedProgramSnapshot implements MemoryReadSnapshot {

	/** System property that turns snapshot reads on for read-only programs; default off. */
	public static final String ENABLE_PROPERTY = "hydra.memory.snapshotReads";

	private static final ValueLayout.OfInt U32 =
		ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
	private static final ValueLayout.OfLong U64 =
		ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

	private static final AtomicLong OPEN_MAPPINGS = new AtomicLong();

	private final Program program;
	private final ProgramSnapshotFile lease;
	private final Arena arena;
	private final MemorySegment segment;
	private final long generation;

	/** Resolved address space per space index (null when the program has no such space). */
	private final AddressSpace[] spaces;
	/** Per space index: region starts (sorted, unsigned), lengths and file data offsets. */
	private final long[][] starts;
	private final long[][] lengths;
	private final long[][] dataOffsets;

	/** Twice the number of reads in progress, plus 1 once closed. */
	private final AtomicLong refs = new AtomicLong();
	private final AtomicBoolean unmapped = new AtomicBoolean();
	private final LongAdder served = new LongAdder();
	private DomainObjectClosedListener closeListener;

	private MappedProgramSnapshot(Program program, ProgramSnapshotFile lease, Arena arena,
			MemorySegment segment) throws IOException {
		this.program = program;
		this.lease = lease;
		this.arena = arena;
		this.segment = segment;
		long size = segment.byteSize();
		if (size < ProgramSnapshotFile.HEADER_SIZE) {
			throw new IOException("snapshot file too short");
		}
		for (int i = 0; i < ProgramSnapshotFile.MAGIC.length; i++) {
			if (segment.get(ValueLayout.JAVA_BYTE, i) != ProgramSnapshotFile.MAGIC[i]) {
				throw new IOException("not a snapshot file");
			}
		}
		if (segment.get(U32, 8) != ProgramSnapshotFile.VERSION) {
			throw new IOException("snapshot version " + segment.get(U32, 8));
		}
		int spaceCount = segment.get(U32, 12);
		int regionCount = segment.get(U32, 16);
		generation = segment.get(U64, 24);
		long tableEnd =
			ProgramSnapshotFile.HEADER_SIZE + (long) regionCount * ProgramSnapshotFile.REGION_ENTRY_SIZE;
		if (spaceCount < 0 || regionCount < 0 || tableEnd > size) {
			throw new IOException("bad snapshot tables");
		}
		AddressFactory factory = program.getAddressFactory();
		spaces = new AddressSpace[spaceCount];
		long pos = tableEnd;
		for (int i = 0; i < spaceCount; i++) {
			if (pos + 4 > size) {
				throw new IOException("bad snapshot space table");
			}
			int n = segment.get(U32, pos);
			if (n < 0 || pos + 4 + n > size) {
				throw new IOException("bad snapshot space name");
			}
			byte[] utf8 = segment.asSlice(pos + 4, n).toArray(ValueLayout.JAVA_BYTE);
			spaces[i] = factory.getAddressSpace(new String(utf8, StandardCharsets.UTF_8));
			pos += 4 + n;
		}
		List<List<long[]>> bySpace = new ArrayList<>();
		for (int i = 0; i < spaceCount; i++) {
			bySpace.add(new ArrayList<>());
		}
		long prevSpace = -1;
		long prevEnd = 0;
		for (int r = 0; r < regionCount; r++) {
			long e = ProgramSnapshotFile.HEADER_SIZE + (long) r * ProgramSnapshotFile.REGION_ENTRY_SIZE;
			int space = segment.get(U32, e);
			long offset = segment.get(U64, e + 8);
			long length = segment.get(U64, e + 16);
			long data = segment.get(U64, e + 24);
			if (space < 0 || space >= spaceCount || length <= 0 || data < tableEnd ||
				data > size || length > size - data ||
				Long.compareUnsigned(offset + length - 1, offset) < 0) {
				throw new IOException("bad snapshot region " + r);
			}
			if (space < prevSpace ||
				(space == prevSpace && Long.compareUnsigned(offset, prevEnd) < 0)) {
				throw new IOException("snapshot regions not sorted");
			}
			prevSpace = space;
			prevEnd = offset + length;
			bySpace.get(space).add(new long[] { offset, length, data });
		}
		starts = new long[spaceCount][];
		lengths = new long[spaceCount][];
		dataOffsets = new long[spaceCount][];
		for (int i = 0; i < spaceCount; i++) {
			List<long[]> list = bySpace.get(i);
			starts[i] = new long[list.size()];
			lengths[i] = new long[list.size()];
			dataOffsets[i] = new long[list.size()];
			for (int j = 0; j < list.size(); j++) {
				starts[i][j] = list.get(j)[0];
				lengths[i][j] = list.get(j)[1];
				dataOffsets[i][j] = list.get(j)[2];
			}
		}
	}

	/**
	 * @return true if snapshot reads are turned on for this JVM
	 */
	public static boolean isEnabled() {
		return Boolean.getBoolean(ENABLE_PROPERTY);
	}

	/**
	 * Map the program's current sealed generation and install it on its memory, so that byte
	 * reads are served from the mapping until the program changes or {@link #close()} is called.
	 * @param program the program (a {@link ProgramDB}; other programs get none)
	 * @return the installed snapshot, or null when the program gets none (not a database program,
	 * another thread is writing the file, it changed while the file was written, or the file could
	 * not be mapped); reads then go to the database as before
	 */
	public static MappedProgramSnapshot attach(Program program) {
		if (!(program instanceof ProgramDB db) || program.isClosed()) {
			return null;
		}
		ProgramSnapshotFile lease = ProgramSnapshotFile.lease(program);
		if (lease == null) {
			return null;
		}
		Arena arena = Arena.ofShared();
		MappedProgramSnapshot snapshot;
		try {
			MemorySegment segment;
			try (FileChannel ch = FileChannel.open(lease.getPath(), StandardOpenOption.READ)) {
				segment = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size(), arena);
			}
			snapshot = new MappedProgramSnapshot(program, lease, arena, segment);
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(MappedProgramSnapshot.class,
				"Snapshot reads not used for " + program.getName() + ": " + e.getMessage());
			arena.close();
			lease.releaseLease();
			return null;
		}
		OPEN_MAPPINGS.incrementAndGet();
		if (snapshot.generation != lease.getGeneration() ||
			snapshot.generation != program.getModificationNumber()) {
			snapshot.close();
			return null;
		}
		MemoryMapDB memory = db.getMemory();
		snapshot.closeListener = dobj -> snapshot.close();
		program.addCloseListener(snapshot.closeListener);
		memory.setReadSnapshot(snapshot);
		if (snapshot.generation != program.getModificationNumber()) {
			memory.clearReadSnapshot(snapshot);	// changed meanwhile: never served (generation check)
			snapshot.close();
			return null;
		}
		return snapshot;
	}

	@Override
	public long getGeneration() {
		return generation;
	}

	/**
	 * @return the number of reads served from the mapping (tests, measurements)
	 */
	public long servedReads() {
		return served.sum();
	}

	/**
	 * @return true once the mapping is closed (unmapped) and the file lease released
	 */
	public boolean isUnmapped() {
		return unmapped.get();
	}

	/**
	 * @return the snapshot file this mapping reads
	 */
	public java.nio.file.Path getPath() {
		return lease.getPath();
	}

	/**
	 * @return the number of snapshot mappings open in this JVM (tests)
	 */
	static long openMappings() {
		return OPEN_MAPPINGS.get();
	}

	@Override
	public boolean read(AddressSpace space, long offset, byte[] dest, int destIndex, int length) {
		int s = spaceIndex(space);
		if (s < 0 || length <= 0) {
			return false;
		}
		int found = regionOf(s, offset);
		if (found < 0) {
			return false;
		}
		long rel = offset - starts[s][found];
		if (length > lengths[s][found] - rel) {
			return false;
		}
		if (!acquire()) {
			return false;
		}
		try {
			MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, dataOffsets[s][found] + rel, dest,
				destIndex, length);
		}
		finally {
			releaseRef();
		}
		served.increment();
		return true;
	}

	@Override
	public int readByte(AddressSpace space, long offset) {
		int s = spaceIndex(space);
		if (s < 0) {
			return -1;
		}
		int found = regionOf(s, offset);
		if (found < 0 || !acquire()) {
			return -1;
		}
		int b;
		try {
			b = segment.get(ValueLayout.JAVA_BYTE,
				dataOffsets[s][found] + (offset - starts[s][found])) & 0xff;
		}
		finally {
			releaseRef();
		}
		served.increment();
		return b;
	}

	/**
	 * @return the index of the region of space index {@code s} that holds {@code offset}, or -1
	 */
	private int regionOf(int s, long offset) {
		long[] st = starts[s];
		int lo = 0;
		int hi = st.length - 1;
		int found = -1;
		while (lo <= hi) {	// last region whose start <= offset (unsigned)
			int mid = (lo + hi) >>> 1;
			if (Long.compareUnsigned(st[mid], offset) <= 0) {
				found = mid;
				lo = mid + 1;
			}
			else {
				hi = mid - 1;
			}
		}
		if (found < 0 || Long.compareUnsigned(offset - st[found], lengths[s][found]) >= 0) {
			return -1;
		}
		return found;
	}

	private int spaceIndex(AddressSpace space) {
		AddressSpace[] sp = spaces;
		for (int i = 0; i < sp.length; i++) {
			if (sp[i] == space) {
				return i;
			}
		}
		for (int i = 0; i < sp.length; i++) {
			if (sp[i] != null && sp[i].equals(space)) {
				return i;
			}
		}
		return -1;
	}

	private boolean acquire() {
		while (true) {
			long r = refs.get();
			if ((r & 1) != 0) {
				return false;
			}
			if (refs.compareAndSet(r, r + 2)) {
				return true;
			}
		}
	}

	private void releaseRef() {
		if (refs.addAndGet(-2) == 1) {
			unmap();
		}
	}

	@Override
	public void detached() {
		close();
	}

	/**
	 * Uninstall the snapshot from the program's memory (if still installed) and unmap the file once
	 * no read is in progress; the file lease is released after that. Idempotent.
	 */
	public void close() {
		if (program instanceof ProgramDB db) {
			db.getMemory().clearReadSnapshot(this);	// calls back into detached(), harmless
		}
		long r = refs.getAndUpdate(x -> x | 1);
		if (r == 0) {	// not closed before and no read in progress
			unmap();
		}
	}

	private void unmap() {
		if (!unmapped.compareAndSet(false, true)) {
			return;
		}
		try {
			arena.close();
			OPEN_MAPPINGS.decrementAndGet();
		}
		finally {
			DomainObjectClosedListener l = closeListener;
			if (l != null) {
				try {
					program.removeCloseListener(l);
				}
				catch (RuntimeException e) {
					// program already disposed
				}
			}
			lease.releaseLease();
		}
	}
}
