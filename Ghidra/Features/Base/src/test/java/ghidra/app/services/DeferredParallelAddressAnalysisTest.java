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
package ghidra.app.services;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DeferredProgramWrites;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Deferred, ordered program writes for the parallel per-location analyzers (constant
 * propagation, stack variables): workers never see each other's writes, the writes are
 * applied in the iteration order of the locations (the queue order of the immediate mode),
 * the "already covered" skip is decided in that order, and the outcome is the same for 1, 2
 * and 8 threads.
 */
public class DeferredParallelAddressAnalysisTest {

	private static final AddressSpace SPACE =
		new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

	private static Address a(long off) {
		return SPACE.getAddress(off);
	}

	/** Analyzer whose "program writes" go into a shared log through DeferredProgramWrites. */
	private static class FakeAnalyzer extends AbstractAnalyzer {
		final List<Long> appliedLog = Collections.synchronizedList(new ArrayList<>());
		final AtomicInteger writesSeenDuringCompute = new AtomicInteger();
		final Random random = new Random(1234);

		FakeAnalyzer() {
			super("fake", "fake", AnalyzerType.FUNCTION_ANALYZER);
		}

		@Override
		public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
				MessageLog log) {
			return true;
		}

		@Override
		public AddressSetView analyzeLocation(Program program, Address start, AddressSetView set,
				TaskMonitor monitor) throws CancelledException {
			// a worker must read the state from before the pass: no write applied yet
			if (!appliedLog.isEmpty()) {
				writesSeenDuringCompute.incrementAndGet();
			}
			int sleep;
			synchronized (random) {
				sleep = random.nextInt(3);
			}
			try {
				Thread.sleep(sleep); // scramble completion order
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			long off = start.getOffset();
			DeferredProgramWrites.run(() -> appliedLog.add(off));
			return new AddressSet(start, start.add(0xf));
		}

		AddressSetView runDeferred(Set<Address> locs, int threads) throws Exception {
			return runDeferredParallelAddressAnalysis(null, locs, null, threads,
				TaskMonitor.DUMMY);
		}
	}

	/** Iteration order deliberately not ascending: writes must follow it, not address order. */
	private static Set<Address> locations() {
		Set<Address> locs = new LinkedHashSet<>();
		for (long off = 0x1000; off >= 0x100; off -= 0x100) {
			locs.add(a(off));
		}
		locs.add(a(0x205)); // inside the result of 0x200 (applied before it): dropped
		locs.add(a(0x50));
		return locs;
	}

	private static List<Long> expectedOrder() {
		List<Long> expected = new ArrayList<>();
		for (long off = 0x1000; off >= 0x100; off -= 0x100) {
			expected.add(off);
		}
		expected.add(0x50L);
		return expected;
	}

	@Test
	public void testWritesAppliedInLocationOrderForAnyThreadCount() throws Exception {
		AddressSetView first = null;
		for (int threads : new int[] { 1, 2, 8 }) {
			for (int repeat = 0; repeat < 5; repeat++) {
				FakeAnalyzer analyzer = new FakeAnalyzer();
				AddressSetView result = analyzer.runDeferred(locations(), threads);
				assertEquals("threads=" + threads, expectedOrder(), analyzer.appliedLog);
				assertEquals("threads=" + threads, 0, analyzer.writesSeenDuringCompute.get());
				if (first == null) {
					first = result;
				}
				assertEquals("threads=" + threads, first, result);
			}
		}
		assertTrue(first.contains(a(0x50)));
		assertTrue(first.contains(a(0x100f)));
	}

	@Test
	public void testImmediateModeOutsideCollector() {
		List<Integer> log = new ArrayList<>();
		DeferredProgramWrites.run(() -> log.add(1));
		assertEquals(List.of(1), log);
		assertFalse(DeferredProgramWrites.isCollecting());
	}

	@Test
	public void testCollectorRecordsThenAppliesInOrder() {
		List<Integer> log = new ArrayList<>();
		DeferredProgramWrites d = DeferredProgramWrites.open();
		try {
			assertTrue(DeferredProgramWrites.isCollecting());
			DeferredProgramWrites.run(() -> log.add(1));
			DeferredProgramWrites.run(() -> log.add(2));
			assertTrue(log.isEmpty());
			assertEquals(2, d.size());
			try {
				d.apply();
				fail("apply while collecting must fail");
			}
			catch (IllegalStateException e) {
				// expected
			}
		}
		finally {
			d.close();
		}
		assertFalse(DeferredProgramWrites.isCollecting());
		d.apply();
		assertEquals(List.of(1, 2), log);
	}

	/** One location records a write that throws: the pass must still apply every other write. */
	@Test
	public void testFailingWriteDoesNotDropRemainingWrites() throws Exception {
		for (int threads : new int[] { 1, 8 }) {
			FakeAnalyzer analyzer = new FakeAnalyzer() {
				@Override
				public AddressSetView analyzeLocation(Program program, Address start,
						AddressSetView set, TaskMonitor monitor) throws CancelledException {
					if (start.getOffset() == 0x300) {
						DeferredProgramWrites.run(() -> {
							throw new IllegalStateException("stale listing");
						});
					}
					return super.analyzeLocation(program, start, set, monitor);
				}
			};
			AddressSetView result = analyzer.runDeferred(locations(), threads);
			assertEquals("threads=" + threads, expectedOrder(), analyzer.appliedLog);
			assertTrue(result.contains(a(0x1000)));
		}
	}

	@Test
	public void testApplyCountsFailuresAndContinues() {
		List<Integer> log = new ArrayList<>();
		DeferredProgramWrites d = DeferredProgramWrites.open();
		try {
			DeferredProgramWrites.run(() -> log.add(1));
			DeferredProgramWrites.run(() -> {
				throw new RuntimeException("boom");
			});
			DeferredProgramWrites.run(() -> log.add(3));
		}
		finally {
			d.close();
		}
		assertEquals(1, d.apply());
		assertEquals(List.of(1, 3), log);
		assertEquals(0, d.size());
	}

	/** Recorded writes must get the apply-time monitor, not the finished worker's monitor. */
	@Test
	public void testRecordedWriteUsesApplyMonitorAndCancelStopsApply() {
		TaskMonitor workerMonitor = new TaskMonitorAdapter(true);
		TaskMonitor applyMonitor = new TaskMonitorAdapter(true);
		List<TaskMonitor> seen = new ArrayList<>();
		DeferredProgramWrites d = DeferredProgramWrites.open();
		try {
			DeferredProgramWrites.run(() -> {
				TaskMonitor m = DeferredProgramWrites.monitor(workerMonitor);
				seen.add(m);
				m.cancel(); // user cancels during the apply
			});
			DeferredProgramWrites.run(() -> seen.add(null));
		}
		finally {
			d.close();
		}
		try {
			d.apply(applyMonitor);
			fail("cancel during apply must throw");
		}
		catch (CancelledException e) {
			// expected
		}
		assertEquals(1, seen.size()); // second write not run after cancel
		assertSame(applyMonitor, seen.get(0));
		// outside apply the record-time monitor is used (immediate mode)
		assertSame(workerMonitor, DeferredProgramWrites.monitor(workerMonitor));
	}

	@Test
	public void testCollectorIsPerThread() throws Exception {
		List<Integer> log = Collections.synchronizedList(new ArrayList<>());
		DeferredProgramWrites d = DeferredProgramWrites.open();
		try {
			Thread t = new Thread(() -> DeferredProgramWrites.run(() -> log.add(7)));
			t.start();
			t.join();
			assertEquals(List.of(7), log); // other thread has no collector: immediate
			assertEquals(0, d.size());
		}
		finally {
			d.close();
		}
	}
}
