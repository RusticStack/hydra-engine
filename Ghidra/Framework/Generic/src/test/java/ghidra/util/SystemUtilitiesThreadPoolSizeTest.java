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
package ghidra.util;

import static org.junit.Assert.*;

import org.junit.*;

/**
 * Sizing of the default CPU-bound thread pools ({@link SystemUtilities#getDefaultThreadPoolSize()}).
 */
public class SystemUtilitiesThreadPoolSizeTest {

	private String savedOverride;
	private String savedLimit;
	private String savedUncapped;

	@Before
	public void setUp() {
		savedOverride = System.getProperty("cpu.core.override");
		savedLimit = System.getProperty("cpu.core.limit");
		savedUncapped = System.getProperty(SystemUtilities.CPU_CORE_UNCAPPED_PROPERTY);
	}

	@After
	public void tearDown() {
		restore("cpu.core.override", savedOverride);
		restore("cpu.core.limit", savedLimit);
		restore(SystemUtilities.CPU_CORE_UNCAPPED_PROPERTY, savedUncapped);
	}

	private static void restore(String key, String value) {
		if (value == null) {
			System.clearProperty(key);
		}
		else {
			System.setProperty(key, value);
		}
	}

	private static int size(int processors, Integer override, Integer limit, boolean uncapped) {
		return SystemUtilities.getDefaultThreadPoolSize(processors, override, limit, uncapped);
	}

	@Test
	public void testDefaultKeepsFixedCap() {
		assertEquals(5, size(4, null, null, false));
		assertEquals(10, size(9, null, null, false));
		assertEquals(10, size(10, null, null, false));
		assertEquals(10, size(24, null, null, false));
		assertEquals(10, size(128, null, null, false));
	}

	@Test
	public void testUncappedFollowsGrantedProcessors() {
		assertEquals(5, size(4, null, null, true));
		assertEquals(11, size(10, null, null, true));
		assertEquals(25, size(24, null, null, true));
		assertEquals(129, size(128, null, null, true));
	}

	@Test
	public void testSizeIsAtLeastOne() {
		assertEquals(1, size(0, null, null, false));
		assertEquals(2, size(1, null, null, false));
		assertEquals(1, size(0, null, null, true));
	}

	@Test
	public void testOverrideIsExact() {
		assertEquals(10, size(24, 10, null, true));
		assertEquals(40, size(4, 40, null, false));
		assertEquals(3, size(24, 3, 8, false));
	}

	@Test
	public void testLimitOnlyLowers() {
		assertEquals(9, size(24, null, 8, false));
		assertEquals(9, size(24, null, 8, true));
		assertEquals(10, size(24, null, 16, false));
		assertEquals(17, size(24, null, 16, true));
		assertEquals(5, size(4, null, 8, true));
	}

	@Test
	public void testDefaultUsesRuntimeProcessors() {
		System.clearProperty("cpu.core.override");
		System.clearProperty("cpu.core.limit");
		System.clearProperty(SystemUtilities.CPU_CORE_UNCAPPED_PROPERTY);
		int granted = Runtime.getRuntime().availableProcessors() + 1;
		assertEquals(Math.min(granted, 10), SystemUtilities.getDefaultThreadPoolSize());

		System.setProperty(SystemUtilities.CPU_CORE_UNCAPPED_PROPERTY, "true");
		assertEquals(granted, SystemUtilities.getDefaultThreadPoolSize());
	}

	@Test
	public void testSystemPropertiesAreHonoured() {
		System.setProperty("cpu.core.override", "7");
		assertEquals(7, SystemUtilities.getDefaultThreadPoolSize());

		System.setProperty("cpu.core.override", "");
		System.setProperty("cpu.core.limit", "0");
		assertEquals(1, SystemUtilities.getDefaultThreadPoolSize());
	}
}
