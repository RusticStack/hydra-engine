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

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.mem.MemoryReadSnapshot;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Tests snapshot reads (Hydra, {@link MappedProgramSnapshot}, {@code hydra.memory.snapshotReads}):
 * byte reads served from the memory-mapped sealed generation are identical to the database's, a
 * memory change drops the snapshot, any other change stops it serving, and closing it while readers
 * run is safe.
 */
public class MappedProgramSnapshotTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private MappedProgramSnapshot snapshot;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("snapreads", ProgramBuilder._X86);
		builder.createMemory(".text", "0x1000", 0x100);
		builder.createMemory(".text2", "0x1100", 0x100);	// adjacent: one region with .text
		builder.createMemory(".rodata", "0x2000", 0x10);
		builder.createUninitializedMemory(".bss", "0x3000", 0x100);
		builder.createMemory(".comment", "OTHER:0x0", 0x20);	// not in the snapshot
		builder.createMappedMemory(".map", "0x5000", 0x10, "0x1000");	// not in the snapshot
		builder.createOverlayMemory("ov", "0x1000", 0x40);
		Random random = new Random(42);
		byte[] fileContent = new byte[0x80];
		random.nextBytes(fileContent);
		FileBytes fileBytes = builder.tx(() -> builder.getProgram()
				.getMemory()
				.createFileBytes("img", 0, fileContent.length,
					new ByteArrayInputStream(fileContent), TaskMonitor.DUMMY));
		builder.createMemory(".file", "0x4000", fileBytes, 0x80);
		builder.tx(() -> {
			Memory memory = builder.getProgram().getMemory();
			for (MemoryBlock block : memory.getBlocks()) {
				if (block.isInitialized() && !block.isMapped() &&
					!block.getName().equals(".file")) {
					byte[] bytes = new byte[(int) block.getSize()];
					random.nextBytes(bytes);
					block.putBytes(block.getStart(), bytes);
				}
			}
			memory.setByte(builder.addr("0x4010"), (byte) 0x5a);	// a modified file byte
		});
		program = (ProgramDB) builder.getProgram();
	}

	@After
	public void tearDown() {
		if (snapshot != null) {
			snapshot.close();
		}
		builder.dispose();
	}

	/** One read of every kind, its result or the exception it threw, in order. */
	private List<String> readAll(Program p) {
		Memory memory = p.getMemory();
		List<String> out = new ArrayList<>();
		for (MemoryBlock block : memory.getBlocks()) {
			int size = (int) block.getSize();
			byte[] whole = new byte[size];
			out.add(attempt(() -> block.getBytes(block.getStart(), whole) + " " +
				HexFormat.of().formatHex(whole)));
			for (int i = 0; i < size; i += 7) {
				Address a = block.getStart().add(i);
				out.add(attempt(() -> Byte.toString(memory.getByte(a))));
				out.add(attempt(() -> Byte.toString(block.getByte(a))));
				byte[] small = new byte[13];
				out.add(attempt(() -> memory.getBytes(a, small) + " " +
					HexFormat.of().formatHex(small)));
				out.add(attempt(() -> Long.toString(memory.getLong(a))));
			}
		}
		// across the merged blocks, past the end of a region, into uninitialized memory
		for (String start : List.of("0x10f8", "0x2008", "0x1ffc", "0x40f0", "0x2fff")) {
			byte[] buf = new byte[0x20];
			out.add(attempt(() -> memory.getBytes(builder.addr(start), buf) + " " +
				HexFormat.of().formatHex(buf)));
		}
		return out;
	}

	private interface Read {
		String get() throws Exception;
	}

	private static String attempt(Read r) {
		try {
			return r.get();
		}
		catch (Exception e) {
			return e.getClass().getSimpleName();
		}
	}

	@Test
	public void testFlagIsOffByDefault() {
		assertNull(System.getProperty(MappedProgramSnapshot.ENABLE_PROPERTY));
		assertFalse(MappedProgramSnapshot.isEnabled());
	}

	@Test
	public void testReadsFromTheMappingAreIdentical() {
		List<String> expected = readAll(program);
		snapshot = MappedProgramSnapshot.attach(program);
		assertNotNull(snapshot);
		assertSame(snapshot, program.getMemory().getReadSnapshot());
		assertTrue(Files.exists(snapshot.getPath()));
		List<String> actual = readAll(program);
		assertEquals(expected, actual);
		assertTrue("reads must be served from the mapping", snapshot.servedReads() > 400);
	}

	@Test
	public void testMemoryChangeDropsTheSnapshot() throws Exception {
		snapshot = MappedProgramSnapshot.attach(program);
		assertNotNull(snapshot);
		java.nio.file.Path file = snapshot.getPath();
		builder.tx(() -> program.getMemory().setByte(builder.addr("0x1004"), (byte) 0x11));
		assertNull(program.getMemory().getReadSnapshot());
		assertTrue(snapshot.isUnmapped());
		assertFalse("the last lease deletes the file", Files.exists(file));
		assertEquals(0x11, program.getMemory().getByte(builder.addr("0x1004")));
		long served = snapshot.servedReads();
		assertEquals(readAll(program), readAll(program));
		assertEquals(served, snapshot.servedReads());
	}

	@Test
	public void testUndoDropsTheSnapshot() throws Exception {
		byte before = program.getMemory().getByte(builder.addr("0x1004"));
		builder.tx(() -> program.getMemory().setByte(builder.addr("0x1004"), (byte) (before + 1)));
		snapshot = MappedProgramSnapshot.attach(program);
		assertNotNull(snapshot);
		program.undo();
		assertNull(program.getMemory().getReadSnapshot());
		assertEquals(before, program.getMemory().getByte(builder.addr("0x1004")));
	}

	@Test
	public void testOtherChangeStopsServing() throws Exception {
		snapshot = MappedProgramSnapshot.attach(program);
		assertNotNull(snapshot);
		builder.tx(() -> program.getSymbolTable()
				.createLabel(builder.addr("0x1000"), "lbl", SourceType.USER_DEFINED));
		long served = snapshot.servedReads();
		java.nio.file.Path file = snapshot.getPath();
		List<String> after = readAll(program);
		assertEquals("a newer generation is never served", served, snapshot.servedReads());
		assertNull("an older generation is dropped on the first read",
			program.getMemory().getReadSnapshot());
		assertTrue("and its mapping and file released", snapshot.isUnmapped());
		assertFalse(Files.exists(file));
		snapshot.close();
		snapshot = null;
		assertEquals(after, readAll(program));
	}

	@Test
	public void testCloseWhileEightReadersRun() throws Exception {
		List<String> expected = readAll(program);
		long mappingsBefore = MappedProgramSnapshot.openMappings();
		snapshot = MappedProgramSnapshot.attach(program);
		assertNotNull(snapshot);
		assertEquals(mappingsBefore + 1, MappedProgramSnapshot.openMappings());
		ExecutorService pool = Executors.newFixedThreadPool(8);
		CountDownLatch started = new CountDownLatch(8);
		AtomicInteger rounds = new AtomicInteger();
		AtomicReference<String> mismatch = new AtomicReference<>();
		List<Future<?>> futures = new ArrayList<>();
		for (int t = 0; t < 8; t++) {
			futures.add(pool.submit(() -> {
				started.countDown();
				for (int i = 0; i < 20; i++) {
					if (!expected.equals(readAll(program))) {
						mismatch.set("round " + i);
					}
					rounds.incrementAndGet();
				}
			}));
		}
		started.await();
		Thread.sleep(20);
		snapshot.close();	// readers in flight finish on the mapping or fall back to the database
		for (Future<?> f : futures) {
			f.get(2, TimeUnit.MINUTES);
		}
		pool.shutdown();
		assertNull(mismatch.get());
		assertEquals(160, rounds.get());
		assertTrue(snapshot.isUnmapped());
		assertNull(program.getMemory().getReadSnapshot());
		assertEquals(mappingsBefore, MappedProgramSnapshot.openMappings());
		assertFalse(Files.exists(snapshot.getPath()));
	}

	@Test
	public void testDecompilerLeaseSharesTheFile() {
		ProgramSnapshotFile decompilerLease = ProgramSnapshotFile.lease(program);
		try {
			snapshot = MappedProgramSnapshot.attach(program);
			assertNotNull(snapshot);
			assertEquals(decompilerLease.getPath(), snapshot.getPath());
			snapshot.close();
			assertTrue("the decompiler still holds it", Files.exists(decompilerLease.getPath()));
		}
		finally {
			decompilerLease.releaseLease();
		}
		assertFalse(Files.exists(snapshot.getPath()));
	}

	/**
	 * A snapshot that serves nothing and records, when it is dropped, what the database held at
	 * that moment: the byte at {@code 0x1004}, whether the {@code .rodata} block still exists and
	 * where the block holding {@code 0x1080} starts.
	 */
	private final class RecordingSnapshot implements MemoryReadSnapshot {
		private final long generation = program.getModificationNumber();
		final AtomicInteger drops = new AtomicInteger();
		volatile String byteSeen;
		volatile Boolean blockSeen;
		volatile String splitSeen;

		@Override
		public long getGeneration() {
			return generation;
		}

		@Override
		public boolean read(AddressSpace space, long offset, byte[] dest, int destIndex,
				int length) {
			return false;
		}

		@Override
		public void detached() {
			if (drops.incrementAndGet() == 1) {
				Memory memory = program.getMemory();
				byteSeen = attempt(() -> Byte.toString(memory.getByte(builder.addr("0x1004"))));
				blockSeen = memory.getBlock(builder.addr("0x2000")) != null;
				splitSeen = memory.getBlock(builder.addr("0x1080")).getStart().toString();
			}
		}
	}

	@Test
	public void testWriteDropsTheSnapshotBeforeTheBytesChange() throws Exception {
		Memory memory = program.getMemory();
		byte before = memory.getByte(builder.addr("0x1004"));
		RecordingSnapshot rec = new RecordingSnapshot();
		program.getMemory().setReadSnapshot(rec);
		builder.tx(() -> memory.setByte(builder.addr("0x1004"), (byte) (before + 1)));
		assertEquals(1, rec.drops.get());
		assertEquals("dropped while the database still held the old byte", Byte.toString(before),
			rec.byteSeen);
		assertNull(program.getMemory().getReadSnapshot());
	}

	@Test
	public void testUndoAndRedoDropTheSnapshotBeforeTheDatabaseChanges() throws Exception {
		Memory memory = program.getMemory();
		byte before = memory.getByte(builder.addr("0x1004"));
		byte changed = (byte) (before + 1);
		builder.tx(() -> memory.setByte(builder.addr("0x1004"), changed));

		RecordingSnapshot rec = new RecordingSnapshot();
		program.getMemory().setReadSnapshot(rec);
		program.undo();
		assertEquals(1, rec.drops.get());
		assertEquals("dropped before the undo changed the database", Byte.toString(changed),
			rec.byteSeen);
		assertEquals(before, memory.getByte(builder.addr("0x1004")));

		RecordingSnapshot rec2 = new RecordingSnapshot();
		program.getMemory().setReadSnapshot(rec2);
		program.redo();
		assertEquals(1, rec2.drops.get());
		assertEquals("dropped before the redo changed the database", Byte.toString(before),
			rec2.byteSeen);
		assertEquals(changed, memory.getByte(builder.addr("0x1004")));
	}

	@Test
	public void testRemoveBlockDropsTheSnapshotBeforeTheBlockGoes() throws Exception {
		Memory memory = program.getMemory();
		MemoryBlock rodata = memory.getBlock(builder.addr("0x2000"));
		RecordingSnapshot rec = new RecordingSnapshot();
		program.getMemory().setReadSnapshot(rec);
		builder.tx(() -> memory.removeBlock(rodata, TaskMonitor.DUMMY));
		assertNull(memory.getBlock(builder.addr("0x2000")));
		assertEquals(1, rec.drops.get());
		assertEquals("dropped while the block still existed", Boolean.TRUE, rec.blockSeen);
	}

	@Test
	public void testSplitDropsTheSnapshotBeforeTheBlockSplits() throws Exception {
		Memory memory = program.getMemory();
		MemoryBlock text = memory.getBlock(builder.addr("0x1000"));
		RecordingSnapshot rec = new RecordingSnapshot();
		program.getMemory().setReadSnapshot(rec);
		builder.tx(() -> memory.split(text, builder.addr("0x1080")));
		assertEquals(builder.addr("0x1080"), memory.getBlock(builder.addr("0x1080")).getStart());
		assertEquals(1, rec.drops.get());
		assertEquals("dropped before the block was split", builder.addr("0x1000").toString(),
			rec.splitSeen);
	}

	/**
	 * Readers run on the mapping while another thread writes: every read returns the bytes of the
	 * previous or the new write, and never the old bytes once the write has returned.
	 */
	@Test
	public void testReadersDuringAWriteNeverSeeOldBytesAfterIt() throws Exception {
		Memory memory = program.getMemory();
		Address at = builder.addr("0x1080");
		int n = 64;
		builder.tx(() -> memory.setBytes(at, new byte[n]));
		ExecutorService pool = Executors.newFixedThreadPool(4);
		try {
			for (int round = 0; round < 20; round++) {
				int value = round;
				snapshot = MappedProgramSnapshot.attach(program);
				assertNotNull("round " + round, snapshot);
				AtomicInteger published = new AtomicInteger(value);
				AtomicBoolean stop = new AtomicBoolean();
				AtomicReference<String> bad = new AtomicReference<>();
				CountDownLatch started = new CountDownLatch(4);
				List<Future<?>> futures = new ArrayList<>();
				for (int t = 0; t < 4; t++) {
					boolean byteByByte = (t & 1) != 0;
					futures.add(pool.submit(() -> {
						started.countDown();
						byte[] buf = new byte[n];
						while (!stop.get()) {
							int p = published.get();
							try {
								if (byteByByte) {
									for (int i = 0; i < n; i++) {
										buf[i] = memory.getByte(at.add(i));
									}
								}
								else {
									memory.getBytes(at, buf);
								}
							}
							catch (MemoryAccessException e) {
								bad.compareAndSet(null, e.toString());
							}
							for (byte b : buf) {
								if ((b & 0xff) < p || (b & 0xff) > value + 1) {
									bad.compareAndSet(null, "read " + (b & 0xff) + " after " + p);
								}
							}
						}
					}));
				}
				started.await();
				byte[] next = new byte[n];
				Arrays.fill(next, (byte) (value + 1));
				builder.tx(() -> memory.setBytes(at, next));
				published.set(value + 1);
				Thread.sleep(5);
				stop.set(true);
				for (Future<?> f : futures) {
					f.get(1, TimeUnit.MINUTES);
				}
				assertNull("round " + round, bad.get());
				assertNull(program.getMemory().getReadSnapshot());
				assertTrue(snapshot.isUnmapped());
				snapshot = null;
			}
		}
		finally {
			pool.shutdownNow();
		}
	}
}
