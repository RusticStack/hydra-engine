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

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/**
 * Memory reads (block lookup and {@link FileBytes} reads) must not wait on the monitors that
 * guard memory changes, and must still return exactly what a synchronized read returns.
 */
public class MemoryReadConcurrencyTest extends AbstractGenericTest {

	private static final int MAX_BUFFER_SIZE_FOR_TESTING = 200;
	private static final long TIMEOUT_SECONDS = 20;

	private ProgramDB program;
	private MemoryMapDB mem;
	private int transactionID;
	private ExecutorService executor;

	@Before
	public void setUp() throws Exception {
		FileBytesAdapter.setMaxBufferSize(MAX_BUFFER_SIZE_FOR_TESTING);
		Language language = getLanguage("Toy:BE:64:default");
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		program = new ProgramDB("Test", language, compilerSpec, this);
		mem = (MemoryMapDB) program.getMemory();
		transactionID = program.startTransaction("Test");
		executor = Executors.newCachedThreadPool();
	}

	@After
	public void tearDown() throws Exception {
		executor.shutdownNow();
		program.endTransaction(transactionID, true);
		program.release(this);
		FileBytesAdapter.setMaxBufferSize(FileBytesAdapter.MAX_BUF_SIZE);
	}

	@Test
	public void testGetBlockDoesNotWaitOnMemoryMapMonitor() throws Exception {
		MemoryBlock block =
			mem.createInitializedBlock("test", addr(0x100), 0x50, (byte) 1, TaskMonitor.DUMMY,
				false);
		Future<MemoryBlock> lookup;
		synchronized (mem) {
			lookup = executor.submit(() -> mem.getBlock(addr(0x120)));
			assertSame(block, lookup.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testFileBytesReadsDoNotWaitOnFileBytesMonitor() throws Exception {
		int size = MAX_BUFFER_SIZE_FOR_TESTING * 2 + 10;
		FileBytes fileBytes = createFileBytes("testFile", size);
		fileBytes.putByte(5, (byte) 99);
		Future<byte[]> reads;
		synchronized (fileBytes) {
			reads = executor.submit(() -> {
				byte[] result = new byte[size * 2 + 2];
				fileBytes.getOriginalBytes(0, result, 0, size);
				fileBytes.getModifiedBytes(0, result, size, size);
				result[size * 2] = fileBytes.getOriginalByte(5);
				result[size * 2 + 1] = fileBytes.getModifiedByte(5);
				return result;
			});
			byte[] result = reads.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
			for (int i = 0; i < size; i++) {
				assertEquals("original[" + i + "]", (byte) i, result[i]);
				assertEquals("modified[" + i + "]", i == 5 ? (byte) 99 : (byte) i,
					result[size + i]);
			}
			assertEquals(5, result[size * 2]);
			assertEquals(99, result[size * 2 + 1]);
		}
	}

	@Test
	public void testReadsDuringPutsAreNeverTorn() throws Exception {
		// spans several DB buffers so one putBytes is several buffer writes
		int size = MAX_BUFFER_SIZE_FOR_TESTING * 3 + 50;
		FileBytes fileBytes = createFileBytes("testFile", size);
		byte[] fillA = filled(size, (byte) 0xaa);
		byte[] fillB = filled(size, (byte) 0x55);
		fileBytes.putBytes(0, fillA);

		int readers = Math.max(2, Runtime.getRuntime().availableProcessors() - 1);
		AtomicBoolean done = new AtomicBoolean();
		List<Future<Integer>> results = new ArrayList<>();
		for (int r = 0; r < readers; r++) {
			results.add(executor.submit(() -> {
				byte[] modified = new byte[size];
				byte[] original = new byte[size];
				int reads = 0;
				while (!done.get()) {
					assertEquals(size, fileBytes.getModifiedBytes(0, modified));
					byte first = modified[0];
					assertTrue(first == fillA[0] || first == fillB[0]);
					for (int i = 1; i < size; i++) {
						if (modified[i] != first) {
							fail("torn read at " + i + ": " + modified[i] + " != " + first);
						}
					}
					byte single = fileBytes.getModifiedByte(size - 1);
					assertTrue(single == fillA[0] || single == fillB[0]);
					assertEquals(size, fileBytes.getOriginalBytes(0, original));
					for (int i = 0; i < size; i++) {
						assertEquals((byte) i, original[i]);
					}
					reads++;
				}
				return reads;
			}));
		}
		for (int i = 0; i < 2000; i++) {
			fileBytes.putBytes(0, (i & 1) == 0 ? fillB : fillA);
		}
		done.set(true);
		for (Future<Integer> f : results) {
			assertTrue(f.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) > 0);
		}
	}

	@Test
	public void testInvalidatedFileBytesStillThrowsOnRead() throws Exception {
		FileBytes fileBytes = createFileBytes("testFile", 10);
		fileBytes.invalidate();
		try {
			fileBytes.getOriginalByte(0);
			fail("expected ConcurrentModificationException");
		}
		catch (ConcurrentModificationException e) {
			// expected
		}
		try {
			fileBytes.getModifiedBytes(0, new byte[4]);
			fail("expected ConcurrentModificationException");
		}
		catch (ConcurrentModificationException e) {
			// expected
		}
	}

	@Test
	public void testBlockLookupFollowsJoinAndSplit() throws Exception {
		MemoryBlock block1 = mem.createInitializedBlock("b1", addr(0x100), 0x10, (byte) 1,
			TaskMonitor.DUMMY, false);
		MemoryBlock block2 = mem.createInitializedBlock("b2", addr(0x110), 0x10, (byte) 2,
			TaskMonitor.DUMMY, false);
		assertSame(block2, mem.getBlock(addr(0x118)));
		assertSame(block1, mem.getBlock(addr(0x108)));

		MemoryBlock joined = mem.join(block1, block2);
		assertSame(joined, mem.getBlock(addr(0x118)));
		assertSame(joined, mem.getBlock(addr(0x110)));
		assertEquals(1, mem.getBlocks().length);

		mem.split(joined, addr(0x110));
		MemoryBlock low = mem.getBlock(addr(0x108));
		MemoryBlock high = mem.getBlock(addr(0x118));
		assertNotSame(low, high);
		assertEquals(addr(0x10f), low.getEnd());
		assertEquals(addr(0x110), high.getStart());
		assertEquals(2, mem.getByte(addr(0x118)));
		assertNull(mem.getBlock(addr(0x120)));
		assertNull(mem.getBlock(addr(0xff)));

		mem.removeBlock(high, TaskMonitor.DUMMY);
		assertNull(mem.getBlock(addr(0x118)));
		assertSame(low, mem.getBlock(addr(0x100)));
	}

	private static byte[] filled(int size, byte value) {
		byte[] bytes = new byte[size];
		Arrays.fill(bytes, value);
		return bytes;
	}

	private FileBytes createFileBytes(String name, int size) throws Exception {
		byte[] bytes = new byte[size];
		for (int i = 0; i < size; i++) {
			bytes[i] = (byte) i;
		}
		try (ByteArrayInputStream is = new ByteArrayInputStream(bytes)) {
			return mem.createFileBytes(name, 0, size, is, TaskMonitor.DUMMY);
		}
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static Language getLanguage(String languageName) throws LanguageNotFoundException {
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		return languageService.getLanguage(new LanguageID(languageName));
	}
}
