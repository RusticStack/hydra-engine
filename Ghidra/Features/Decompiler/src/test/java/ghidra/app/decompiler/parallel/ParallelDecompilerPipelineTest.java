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
import java.util.concurrent.ExecutionException;

import org.junit.*;

import generic.concurrent.QCallback;
import ghidra.program.model.listing.*;
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
		catch (ExecutionException e) {
			// wrapped as the queue path wraps it
			assertTrue(e.getCause() instanceof IllegalStateException);
			assertEquals("bad 10", e.getCause().getMessage());
		}
		assertEquals(n, ran.size());
	}

	/** A program whose function manager reports {@code n} functions; nothing else is used. */
	private static Program program(int n) {
		FunctionManager fm = (FunctionManager) Proxy.newProxyInstance(
			FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
			(proxy, m, args) -> m.getName().equals("getFunctionCount") ? n : null);
		return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
			new Class<?>[] { Program.class },
			(proxy, m, args) -> m.getName().equals("getFunctionManager") ? fm : null);
	}

	@Test
	public void testConsumerGetsTheSameResultsOnTheCallingThreadWithPipeline() throws Exception {
		int n = 120;
		Map<Function, Integer> ids = new IdentityHashMap<>();
		List<Function> fs = functions(n, ids);
		QCallback<Function, String> cb = (f, m) -> {
			int id = ids.get(f);
			return id % 7 == 0 ? null : laterFinishesFirst(n, ids).process(f, m);
		};
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "false");
		List<String> off = Collections.synchronizedList(new ArrayList<>());
		ParallelDecompiler.decompileFunctions(cb, program(n), fs.iterator(), off::add,
			TaskMonitor.DUMMY);
		System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, "true");
		Thread caller = Thread.currentThread();
		List<String> on = new ArrayList<>();
		List<Thread> threads = new ArrayList<>();
		ParallelDecompiler.decompileFunctions(cb, program(n), fs.iterator(), r -> {
			threads.add(Thread.currentThread());
			on.add(r);
		}, TaskMonitor.DUMMY);
		assertEquals(n - (n + 6) / 7, off.size()); // null results are skipped
		assertEquals(off.size(), on.size());
		assertEquals(new TreeSet<>(off), new TreeSet<>(on));
		for (Thread t : threads) {
			assertSame(caller, t);
		}
	}

	@Test
	public void testInOrderDeliversInIteratorOrder() throws Exception {
		int n = 120;
		Map<Function, Integer> ids = new IdentityHashMap<>();
		List<Function> fs = functions(n, ids);
		List<String> got = new ArrayList<>();
		ParallelDecompiler.decompileFunctionsInOrder(laterFinishesFirst(n, ids), program(n),
			fs.iterator(), got::add, TaskMonitor.DUMMY);
		List<String> expected = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			expected.add("r" + i);
		}
		assertEquals(expected, got);
	}

	@Test
	public void testConsumerExceptionIsLoggedAndStopsWithAndWithoutPipeline() throws Exception {
		// the queue path logs a consumer exception and stops; it does not throw it
		for (String flag : new String[] { "false", "true" }) {
			int n = 2000;
			Map<Function, Integer> ids = new IdentityHashMap<>();
			List<Function> fs = functions(n, ids);
			Set<Integer> ran = Collections.synchronizedSet(new HashSet<>());
			System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, flag);
			ParallelDecompiler.decompileFunctions((f, m) -> {
				ran.add(ids.get(f));
				Thread.sleep(1);
				return "r" + ids.get(f);
			}, program(n), fs.iterator(), r -> {
				throw new IllegalStateException("consumer");
			}, TaskMonitor.DUMMY);
			assertTrue(flag + ": ran " + ran.size(), ran.size() < n);
		}
	}

	@Test
	public void testConsumerCallbackErrorIsThrownWithAndWithoutPipeline() throws Exception {
		for (String flag : new String[] { "false", "true" }) {
			int n = 60;
			Map<Function, Integer> ids = new IdentityHashMap<>();
			List<Function> fs = functions(n, ids);
			System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, flag);
			try {
				ParallelDecompiler.decompileFunctions((f, m) -> {
					if (ids.get(f) == 3) {
						throw new IllegalArgumentException("bad 3");
					}
					return "r" + ids.get(f);
				}, program(n), fs.iterator(), r -> {
					// consume
				}, TaskMonitor.DUMMY);
				fail(flag);
			}
			catch (ExecutionException e) {
				assertTrue(flag, e.getCause() instanceof IllegalArgumentException);
				assertEquals("bad 3", e.getCause().getMessage());
			}
		}
	}

	@Test
	public void testListErrorIsWrappedWithAndWithoutPipeline() throws Exception {
		for (String flag : new String[] { "false", "true" }) {
			int n = 30;
			Map<Function, Integer> ids = new IdentityHashMap<>();
			List<Function> fs = functions(n, ids);
			System.setProperty(ParallelDecompiler.PIPELINE_PROPERTY, flag);
			try {
				ParallelDecompiler.decompileFunctions((f, m) -> {
					if (ids.get(f) == 7) {
						throw new java.io.IOException("io 7");
					}
					return "r" + ids.get(f);
				}, fs, TaskMonitor.DUMMY);
				fail(flag);
			}
			catch (ExecutionException e) {
				assertTrue(flag, e.getCause() instanceof java.io.IOException);
				assertEquals("java.io.IOException: io 7", e.getMessage());
			}
		}
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
