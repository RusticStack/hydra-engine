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
package ghidra.app.decompiler.parallel;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.*;

import org.junit.*;

import generic.concurrent.QCallback;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/**
 * The batch decompile methods with {@code hydra.decompiler.pipeline}: the same results, in the
 * caller's order.  The callback stands in for a decompile (no program or decompiler needed); it
 * makes later functions finish first, so completion order differs from iterator order.
 */
public class ParallelDecompilerPipelineTest {

	private String saved;

	@Before
	public void setUp() {
		saved = System.getProperty(ParallelDecompiler.PIPELINE_PROPERTY);
	}

	@After
	public void tearDown() {
		if (saved == null) {
			System.clearProperty(ParallelDecompiler.PIPELINE_PROPERTY);
		}
		else {
			System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, saved);
		}
	}

	private static List<Function> functions(int n, Map<Function, Integer> ids) {
		List<Function> list = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			int id = i;
			Function f = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
				new Class<?>[] { Function.class }, (proxy, m, args) -> switch (m.getName()) {
					case "hashCode" -> System.identityHashCode(proxy);
					case "equals" -> proxy == args[0];
					case "toString" -> "f" + id;
					default -> null;
				});
			ids.put(f, id);
			list.add(f);
		}
		return list;
	}

	private static QCallback<Function, String> laterFinishesFirst(int n,
			Map<Function, Integer> ids) {
		return (f, monitor) -> {
			int id = ids.get(f);
			Thread.sleep(Math.max(0, (n - id) / 8));
			return "r" + id;
		};
	}

	@Test
	public void testListInIteratorOrderWithPipeline() throws Exception {
		int n = 120;
		Map<Function, Integer> ids = new IdentityHashMap<>();
		List<Function> fs = functions(n, ids);
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "true");
		List<String> got =
			ParallelDecompiler.decompileFunctions(laterFinishesFirst(n, ids), fs, TaskMonitor.DUMMY);
		List<String> expected = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			expected.add("r" + i);
		}
		assertEquals(expected, got);
	}

	@Test
	public void testSameResultSetWithAndWithoutPipeline() throws Exception {
		int n = 120;
		Map<Function, Integer> ids = new IdentityHashMap<>();
		List<Function> fs = functions(n, ids);
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "false");
		List<String> off =
			ParallelDecompiler.decompileFunctions(laterFinishesFirst(n, ids), fs, TaskMonitor.DUMMY);
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "true");
		List<String> on =
			ParallelDecompiler.decompileFunctions(laterFinishesFirst(n, ids), fs, TaskMonitor.DUMMY);
		assertEquals(n, off.size());
		assertEquals(new TreeSet<>(off), new TreeSet<>(on));
	}

	@Test
	public void testListErrorIsTheFirstInIteratorOrderAndEveryFunctionRuns() throws Exception {
		int n = 60;
		Map<Function, Integer> ids = new IdentityHashMap<>();
		List<Function> fs = functions(n, ids);
		Set<Integer> ran = Collections.synchronizedSet(new HashSet<>());
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "true");
		try {
			ParallelDecompiler.decompileFunctions((f, m) -> {
				int id = ids.get(f);
				ran.add(id);
				if (id == 10 || id == 50) {
					Thread.sleep(id == 10 ? 30 : 0);
					throw new IllegalStateException("bad " + id);
				}
				return "r" + id;
			}, fs, TaskMonitor.DUMMY);
			fail();
		}
		catch (IllegalStateException e) {
			assertEquals("bad 10", e.getMessage());
		}
		assertEquals(n, ran.size());
	}

	@Test
	public void testWorkersProperty() {
		assertEquals(0, ParallelDecompiler.pipelineWorkers("pool"));
		assertEquals(0, ParallelDecompiler.pipelineWorkers(""));
		assertEquals(0, ParallelDecompiler.pipelineWorkers("junk"));
		assertEquals(7, ParallelDecompiler.pipelineWorkers("7"));
		assertTrue(ParallelDecompiler.pipelineWorkers("granted") >= 1);
	}
}
