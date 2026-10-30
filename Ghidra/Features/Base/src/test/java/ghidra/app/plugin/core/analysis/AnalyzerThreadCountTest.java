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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;

import org.junit.Test;

import generic.concurrent.GThreadPool;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Thread counts of the parallel analysis paths: a requested count is clamped to the pool.
 */
public class AnalyzerThreadCountTest {

	@Test
	public void testClampThreadCount() {
		assertEquals(2, AbstractAnalyzer.clampThreadCount(2, 25));
		assertEquals(4, AbstractAnalyzer.clampThreadCount(8, 4));
		assertEquals(4, AbstractAnalyzer.clampThreadCount(4, 4));
		assertEquals(1, AbstractAnalyzer.clampThreadCount(0, 4));
		assertEquals(1, AbstractAnalyzer.clampThreadCount(-3, 4));
		assertEquals(1, AbstractAnalyzer.clampThreadCount(8, 0));
	}

	/**
	 * A Max Threads value above the pool size used to drop constant propagation to a single
	 * thread.  Two locations meet at a barrier; with one thread the barrier never fills.
	 */
	@Test
	public void testRequestAbovePoolRunsInParallel() throws Exception {
		GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
		assumePoolCanRunTwo(pool);

		CyclicBarrier barrier = new CyclicBarrier(2);
		ConstantPropagationAnalyzer analyzer = new ConstantPropagationAnalyzer("Test") {
			@Override
			public AddressSetView analyzeLocation(Program program, Address start,
					AddressSetView set, TaskMonitor monitor) {
				try {
					barrier.await(10, TimeUnit.SECONDS);
				}
				catch (InterruptedException | BrokenBarrierException | TimeoutException e) {
					fail("locations did not run concurrently: " + e);
				}
				return new AddressSet(start);
			}
		};
		analyzer.maxThreadCount = pool.getMaxThreadCount() + 5;

		AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
		Set<Address> locations = new TreeSet<>(List.of(space.getAddress(0x1000),
			space.getAddress(0x2000)));

		AddressSetView result = analyzer.runAddressAnalysis(null, locations, TaskMonitor.DUMMY);

		assertTrue(result.contains(space.getAddress(0x1000)));
		assertTrue(result.contains(space.getAddress(0x2000)));
		assertFalse(barrier.isBroken());
	}

	private static void assumePoolCanRunTwo(GThreadPool pool) {
		org.junit.Assume.assumeTrue("needs a pool of at least 2 threads",
			pool.getMaxThreadCount() >= 2);
	}
}
