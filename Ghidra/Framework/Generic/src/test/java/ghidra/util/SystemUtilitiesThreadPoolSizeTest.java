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

	@Before
	public void setUp() {
		savedOverride = System.getProperty("cpu.core.override");
		savedLimit = System.getProperty("cpu.core.limit");
	}

	@After
	public void tearDown() {
		restore("cpu.core.override", savedOverride);
		restore("cpu.core.limit", savedLimit);
	}

	private static void restore(String key, String value) {
		if (value == null) {
			System.clearProperty(key);
		}
		else {
			System.setProperty(key, value);
		}
	}

	@Test
	public void testSizeFollowsGrantedProcessorsWithoutFixedCap() {
		assertEquals(5, SystemUtilities.getDefaultThreadPoolSize(4, null, null));
		assertEquals(11, SystemUtilities.getDefaultThreadPoolSize(10, null, null));
		assertEquals(25, SystemUtilities.getDefaultThreadPoolSize(24, null, null));
		assertEquals(129, SystemUtilities.getDefaultThreadPoolSize(128, null, null));
	}

	@Test
	public void testSizeIsAtLeastOne() {
		assertEquals(1, SystemUtilities.getDefaultThreadPoolSize(0, null, null));
		assertEquals(2, SystemUtilities.getDefaultThreadPoolSize(1, null, null));
	}

	@Test
	public void testOverrideIsExact() {
		assertEquals(10, SystemUtilities.getDefaultThreadPoolSize(24, 10, null));
		assertEquals(40, SystemUtilities.getDefaultThreadPoolSize(4, 40, null));
		assertEquals(3, SystemUtilities.getDefaultThreadPoolSize(24, 3, 8));
	}

	@Test
	public void testLimitOnlyLowers() {
		assertEquals(9, SystemUtilities.getDefaultThreadPoolSize(24, null, 8));
		assertEquals(5, SystemUtilities.getDefaultThreadPoolSize(4, null, 8));
	}

	@Test
	public void testDefaultUsesRuntimeProcessors() {
		System.clearProperty("cpu.core.override");
		System.clearProperty("cpu.core.limit");
		assertEquals(Runtime.getRuntime().availableProcessors() + 1,
			SystemUtilities.getDefaultThreadPoolSize());
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
