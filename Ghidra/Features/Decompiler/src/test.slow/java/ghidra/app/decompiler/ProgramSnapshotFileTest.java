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

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Tests the decompiler byte snapshot (Hydra, {@link ProgramSnapshotFile}): the regions it holds, the
 * file format, the lease lifecycle and that decompiling with it gives the same C as callbacks.
 */
public class ProgramSnapshotFileTest extends AbstractGhidraHeadlessIntegrationTest {

	/**
	 * The format conformance vector shared with the Rust crate hydra-snapshot (tests/snapshot.rs,
	 * GOLDEN_V1_HEX): generation 7, space "ram", regions 0x1000 (bytes 0..16) and 0x2000 (eight
	 * 0xAA).
	 */
	private static final String GOLDEN_V1_HEX =
		"4859534e41503031010000000100000002000000000000000700000000000000" +
			"0000000000000000001000000000000010000000000000006800000000000000" +
			"0000000000000000002000000000000008000000000000007800000000000000" +
			"0300000072616d00000102030405060708090a0b0c0d0e0faaaaaaaaaaaaaaaa";

	private ProgramBuilder builder;
	private Program program;
	private String savedProperty;

	@Before
	public void setUp() throws Exception {
		savedProperty = System.getProperty(ProgramSnapshotFile.ENABLE_PROPERTY);
		builder = new ProgramBuilder("snapshot", ProgramBuilder._X86);
		// mov eax,[0x2000]; ret
		builder.createMemory(".text", "0x1000", 0x100);
		builder.createMemory(".text2", "0x1100", 0x100);	// adjacent: merged with .text
		MemoryBlock data = builder.createMemory(".rodata", "0x2000", 0x10);
		builder.createUninitializedMemory(".bss", "0x3000", 0x100);
		builder.createMemory(".comment", "OTHER:0x0", 0x20);
		builder.setBytes("0x1000", "a1 00 20 00 00 c3");
		builder.setBytes("0x2000", "78 56 34 12");
		builder.setWrite(data, false);
		builder.applyDataType("0x2000", DWordDataType.dataType);
		builder.tx(() -> {	// a constant: the decompiler reads its value through getBytes
			Data dword = builder.getProgram().getListing().getDataAt(builder.addr("0x2000"));
			MutabilitySettingsDefinition.DEF.setChoice(dword,
				MutabilitySettingsDefinition.CONSTANT);
		});
		builder.disassemble("0x1000", 6, false);
		builder.createFunction("0x1000");
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		if (savedProperty == null) {
			System.clearProperty(ProgramSnapshotFile.ENABLE_PROPERTY);
		}
		else {
			System.setProperty(ProgramSnapshotFile.ENABLE_PROPERTY, savedProperty);
		}
		builder.dispose();
	}

	@Test
	public void testRegionsMergeAdjacentAndSkipUninitializedAndOther() {
		List<String> spaces = new ArrayList<>();
		List<ProgramSnapshotFile.Region> regions =
			ProgramSnapshotFile.collectRegions(program.getMemory(), spaces);
		assertEquals(List.of("ram"), spaces);
		assertEquals(2, regions.size());
		assertEquals(0x1000, regions.get(0).offset());
		assertEquals(0x200, regions.get(0).length());
		assertEquals(2, regions.get(0).blocks().size());
		assertEquals(0x2000, regions.get(1).offset());
		assertEquals(0x10, regions.get(1).length());
	}

	@Test
	public void testWriterMatchesSharedFormatVector() throws Exception {
		ProgramBuilder golden = new ProgramBuilder("golden", ProgramBuilder._X86);
		try {
			golden.createMemory("a", "0x1000", 16);
			golden.createMemory("b", "0x2000", 8);
			golden.setBytes("0x1000", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
			golden.setBytes("0x2000", "aa aa aa aa aa aa aa aa");
			List<String> spaces = new ArrayList<>();
			List<ProgramSnapshotFile.Region> regions =
				ProgramSnapshotFile.collectRegions(golden.getProgram().getMemory(), spaces);
			Path file = Files.createTempFile("golden-", ".hysnap");
			try {
				ProgramSnapshotFile.writeFile(file, 7, spaces, regions);
				assertEquals(GOLDEN_V1_HEX, HexFormat.of().formatHex(Files.readAllBytes(file)));
			}
			finally {
				Files.deleteIfExists(file);
			}
		}
		finally {
			golden.dispose();
		}
	}

	@Test
	public void testLeasesShareOneFileAndDeleteOnLastRelease() throws Exception {
		ProgramSnapshotFile first = ProgramSnapshotFile.acquire(program, null);
		assertNotNull(first);
		assertSame(first, ProgramSnapshotFile.acquire(program, first));
		ProgramSnapshotFile second = ProgramSnapshotFile.acquire(program, null);
		assertSame("one file per program and generation", first, second);
		assertTrue(Files.exists(first.getPath()));
		assertTrue(ProgramSnapshotFile.liveFiles().contains(first.getPath()));

		builder.setBytes("0x2004", "01 02");	// new generation
		ProgramSnapshotFile next = ProgramSnapshotFile.acquire(program, second);
		assertNotNull(next);
		assertNotSame(first, next);
		assertEquals(program.getModificationNumber(), next.getGeneration());
		assertTrue("still leased by the first user", Files.exists(first.getPath()));

		ProgramSnapshotFile.release(first);
		assertFalse(Files.exists(first.getPath()));
		ProgramSnapshotFile.release(next);
		assertFalse(Files.exists(next.getPath()));
		assertFalse(ProgramSnapshotFile.liveFiles().contains(next.getPath()));
	}

	@Test
	public void testNoSnapshotForProgramsOtherThanProgramDB() {
		Program view = (Program) Proxy.newProxyInstance(getClass().getClassLoader(),
			new Class<?>[] { Program.class }, (proxy, method, args) -> {
				throw new AssertionError("not expected: " + method.getName());
			});
		assertNull(ProgramSnapshotFile.acquire(view, null));
	}

	@Test
	public void testDecompileWithSnapshotIsIdenticalAndSkipsByteCallbacks() throws Exception {
		System.setProperty(ProgramSnapshotFile.ENABLE_PROPERTY, "false");
		long before = DecompileProcess.getBytesCallbackCount();
		String off = decompile();
		long offCallbacks = DecompileProcess.getBytesCallbackCount() - before;

		System.setProperty(ProgramSnapshotFile.ENABLE_PROPERTY, "true");
		before = DecompileProcess.getBytesCallbackCount();
		String on = decompile();
		long onCallbacks = DecompileProcess.getBytesCallbackCount() - before;

		assertEquals(off, on);
		assertTrue(off, off.contains("0x12345678"));
		assertTrue("callbacks without the snapshot: " + offCallbacks, offCallbacks > 0);
		assertEquals("callbacks with the snapshot", 0, onCallbacks);
		assertTrue("files released by closeProgram", ProgramSnapshotFile.liveFiles().isEmpty());
	}

	private String decompile() {
		DecompInterface decompiler = new DecompInterface();
		try {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			decompiler.setOptions(options);	// respect read-only data (the default options)
			assertTrue(decompiler.openProgram(program));
			Function function =
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
			DecompileResults results = decompiler.decompileFunction(function,
				DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
			assertTrue(results.getErrorMessage(), results.decompileCompleted());
			return results.getDecompiledFunction().getC();
		}
		finally {
			decompiler.closeProgram();	// releases the lease now; dispose does it on another thread
			decompiler.dispose();
		}
	}
}
