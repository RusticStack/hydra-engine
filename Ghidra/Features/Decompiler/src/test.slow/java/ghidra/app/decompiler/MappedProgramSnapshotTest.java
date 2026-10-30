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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
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
		List<String> after = readAll(program);
		assertEquals("a newer generation is never served", served, snapshot.servedReads());
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
}
