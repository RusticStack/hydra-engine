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
package ghidra.app.util.headless.session;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;

/**
 * H7: a session's project manager no longer parses the user's tool templates on every project
 * open; the tool chest is built, by the base class's own code, only when something asks for it.
 */
public class LazyToolChestTest extends AbstractGenericTest {

	/** Building the session manager (done on every project open) does not build the tool chest. */
	@Test
	public void sessionManagerDoesNotBuildToolChestOnConstruction() {
		ToolChest chest = new SessionProject.Manager().getUserToolChest();
		assertTrue("expected a deferred tool chest, got " + chest.getClass().getName(),
			chest instanceof LazyToolChest);
		assertFalse("tool chest was built by the constructor", ((LazyToolChest) chest).isLoaded());
	}

	/** When asked, the session's chest holds the same tools the base manager's chest holds. */
	@Test
	public void loadedChestMatchesBaseManagerChest() {
		DefaultProjectManager base = new DefaultProjectManager() {
			@Override
			protected void updatePreferences() {
				// do not write preferences from a test
			}
		};
		ToolChest expected = base.getUserToolChest();
		LazyToolChest lazy = (LazyToolChest) new SessionProject.Manager().getUserToolChest();

		assertEquals(expected.getToolCount(), lazy.getToolCount());
		assertTrue(lazy.isLoaded());
		assertEquals(names(expected.getToolTemplates()), names(lazy.getToolTemplates()));
		for (ToolTemplate t : expected.getToolTemplates()) {
			assertNotNull(t.getName(), lazy.getToolTemplate(t.getName()));
		}
	}

	/** The loader runs once, on first use, even when many threads ask at once; calls delegate. */
	@Test
	public void loadsOnceUnderConcurrencyAndDelegates() throws Exception {
		AtomicInteger loads = new AtomicInteger();
		FakeChest fake = new FakeChest();
		LazyToolChest lazy = new LazyToolChest(() -> {
			loads.incrementAndGet();
			return fake;
		});
		assertEquals(0, loads.get());
		assertFalse(lazy.isLoaded());

		int n = 16;
		ExecutorService pool = Executors.newFixedThreadPool(n);
		try {
			CountDownLatch go = new CountDownLatch(1);
			List<Future<Integer>> fs = new ArrayList<>();
			for (int i = 0; i < n; i++) {
				fs.add(pool.submit(() -> {
					go.await();
					return lazy.getToolCount();
				}));
			}
			go.countDown();
			for (Future<Integer> f : fs) {
				assertEquals(Integer.valueOf(7), f.get(30, TimeUnit.SECONDS));
			}
		}
		finally {
			pool.shutdownNow();
		}
		assertEquals(1, loads.get());

		assertNull(lazy.getToolTemplate("x"));
		assertEquals(0, lazy.getToolTemplates().length);
		assertTrue(lazy.remove("x"));
		assertTrue(lazy.addToolTemplate(null));
		assertTrue(lazy.replaceToolTemplate(null));
		ToolChestChangeListener l = new ToolChestChangeListener() {
			@Override
			public void toolTemplateAdded(ToolTemplate tool) {
				// none
			}

			@Override
			public void toolSetAdded(ToolSet toolset) {
				// none
			}

			@Override
			public void toolRemoved(String toolName) {
				// none
			}
		};
		lazy.addToolChestChangeListener(l);
		lazy.removeToolChestChangeListener(l);
		assertEquals(List.of("getToolTemplate", "getToolTemplates", "remove", "addToolTemplate",
			"replaceToolTemplate", "addToolChestChangeListener", "removeToolChestChangeListener"),
			fake.calls.subList(n, fake.calls.size()));
		assertEquals(1, loads.get());
	}

	private static List<String> names(ToolTemplate[] templates) {
		List<String> out = new ArrayList<>();
		for (ToolTemplate t : templates) {
			out.add(t.getName());
		}
		Collections.sort(out);
		return out;
	}

	private static final class FakeChest implements ToolChest {
		final List<String> calls = Collections.synchronizedList(new ArrayList<>());

		@Override
		public ToolTemplate getToolTemplate(String toolName) {
			calls.add("getToolTemplate");
			return null;
		}

		@Override
		public ToolTemplate[] getToolTemplates() {
			calls.add("getToolTemplates");
			return new ToolTemplate[0];
		}

		@Override
		public void addToolChestChangeListener(ToolChestChangeListener l) {
			calls.add("addToolChestChangeListener");
		}

		@Override
		public void removeToolChestChangeListener(ToolChestChangeListener l) {
			calls.add("removeToolChestChangeListener");
		}

		@Override
		public boolean addToolTemplate(ToolTemplate template) {
			calls.add("addToolTemplate");
			return true;
		}

		@Override
		public boolean remove(String toolName) {
			calls.add("remove");
			return true;
		}

		@Override
		public int getToolCount() {
			calls.add("getToolCount");
			return 7;
		}

		@Override
		public boolean replaceToolTemplate(ToolTemplate template) {
			calls.add("replaceToolTemplate");
			return true;
		}
	}
}
