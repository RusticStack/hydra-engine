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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Test;

import ghidra.util.HydraCpu.*;

/**
 * {@link HydraCpu} through the foreign function API, with the library built by module
 * HydraNative (this module's test task builds it first), and without it.
 */
public class HydraCpuTest {

	private static Path library() {
		Path library = HydraCpu.findLibrary();
		assertNotNull("hydra_native not found next to module Utility (build :HydraNative:buildNatives)",
			library);
		return library;
	}

	private static void assertThreads(HydraCpu cpu) {
		for (int n : new int[] { cpu.getLatencyThreads(), cpu.getComputeThreads(),
			cpu.getBackgroundThreads() }) {
			assertTrue(cpu.toString(), n >= 1 && n <= cpu.getGrantedCpus());
		}
	}

	@Test
	public void testNativeValues() {
		HydraCpu cpu = HydraCpu.detect(library(), null);
		assertTrue(cpu.getFallbackReason(), cpu.isNative());
		assertNull(cpu.getFallbackReason());

		assertTrue(cpu.toString(), cpu.getGrantedCpus() >= 1);
		assertTrue(cpu.toString(), cpu.getGrantedCpus() <= cpu.getAffinityCpus());
		assertTrue(cpu.toString(), cpu.getAffinityCpus() <= cpu.getSystemCpus());
		assertEquals(cpu.toString(), cpu.getAffinityCpus(),
			cpu.getPerformanceCpus() + cpu.getEfficiencyCpus());
		assertTrue(cpu.toString(), cpu.getPerformanceCores() >= 1);
		assertTrue(cpu.toString(), cpu.getLastLevelCacheGroups() >= 1);
		assertTrue(cpu.toString(), cpu.getPhysicalMemory() > 0);
		assertTrue(cpu.toString(),
			cpu.getMemoryLimit() > 0 && cpu.getMemoryLimit() <= cpu.getPhysicalMemory());
		if (cpu.getCpuQuotaMilli() == 0 && cpu.getSystemCpus() <= 64) {
			// one processor group and no quota: the JVM counts the same affinity mask
			assertEquals(cpu.toString(), Runtime.getRuntime().availableProcessors(),
				cpu.getGrantedCpus());
		}
		if (System.getProperty("os.arch").equals("amd64")) {
			assertFalse(cpu.toString(), cpu.getVendor().isEmpty());
			assertTrue(cpu.toString(), cpu.getFamily() > 0);
		}
		assertEquals(ProfileSource.AUTO, cpu.getProfileSource());
		assertFalse(cpu.getProfile().isEmpty());
		assertThreads(cpu);
	}

	@Test
	public void testForcedProfiles() {
		Path library = library();
		HydraCpu auto = HydraCpu.detect(library, "auto");
		HydraCpu generic = HydraCpu.detect(library, "generic");
		HydraCpu raptor = HydraCpu.detect(library, "RaptorLake-Hybrid");
		HydraCpu unknown = HydraCpu.detect(library, "no-such-cpu");

		assertEquals(ProfileSource.AUTO, auto.getProfileSource());
		assertEquals(HydraCpu.GENERIC, generic.getProfile());
		assertEquals(ProfileSource.FORCED, generic.getProfileSource());
		assertEquals(Placement.ANY, generic.getPlacement());
		assertEquals(generic.getGrantedCpus(), generic.getComputeThreads());
		assertEquals("raptorlake-hybrid", raptor.getProfile());
		assertEquals(ProfileSource.FORCED, raptor.getProfileSource());
		assertEquals(Placement.LATENCY_ON_PERFORMANCE_CORES, raptor.getPlacement());
		assertEquals(HydraCpu.GENERIC, unknown.getProfile());
		assertEquals(ProfileSource.UNKNOWN_OVERRIDE, unknown.getProfileSource());

		// a profile changes the pools and the placement, never what is detected
		for (HydraCpu cpu : new HydraCpu[] { generic, raptor, unknown }) {
			assertEquals(auto.getGrantedCpus(), cpu.getGrantedCpus());
			assertEquals(auto.getModel(), cpu.getModel());
			assertEquals(auto.getSimdLevel(), cpu.getSimdLevel());
			assertThreads(cpu);
		}
	}

	@Test
	public void testFallbackWithoutLibrary() {
		int processors = Runtime.getRuntime().availableProcessors();
		HydraCpu missing = HydraCpu.detect(null, null);
		HydraCpu forced = HydraCpu.detect(Path.of("no-such-dir", "hydra_native.dll"),
			"raptorlake-hybrid");
		for (HydraCpu cpu : new HydraCpu[] { missing, forced }) {
			assertFalse(cpu.isNative());
			assertTrue(cpu.getFallbackReason(), cpu.getFallbackReason().contains("not found"));
			assertEquals(processors, cpu.getGrantedCpus());
			assertEquals(processors, cpu.getComputeThreads());
			assertEquals(HydraCpu.GENERIC, cpu.getProfile());
			assertEquals(ProfileSource.FALLBACK, cpu.getProfileSource());
			assertEquals(Placement.ANY, cpu.getPlacement());
			assertEquals(SimdLevel.BASELINE, cpu.getSimdLevel());
			assertTrue(cpu.getMemoryLimit() > 0);
		}
	}

	@Test
	public void testFallbackForAFileThatIsNotTheLibrary() throws IOException {
		Path notLibrary = Files.createTempFile("hydra_native", ".dll");
		try {
			HydraCpu cpu = HydraCpu.detect(notLibrary, null);
			assertFalse(cpu.isNative());
			assertTrue(cpu.getFallbackReason(), cpu.getFallbackReason().startsWith(notLibrary.toString()));
			assertEquals(Runtime.getRuntime().availableProcessors(), cpu.getGrantedCpus());
		}
		finally {
			Files.delete(notLibrary);
		}
	}

	@Test
	public void testLibraryProperty() {
		String old = System.getProperty(HydraCpu.LIBRARY_PROPERTY);
		try {
			System.setProperty(HydraCpu.LIBRARY_PROPERTY, "elsewhere/hydra_native.dll");
			assertEquals(Path.of("elsewhere/hydra_native.dll"), HydraCpu.findLibrary());
		}
		finally {
			if (old == null) {
				System.clearProperty(HydraCpu.LIBRARY_PROPERTY);
			}
			else {
				System.setProperty(HydraCpu.LIBRARY_PROPERTY, old);
			}
		}
	}

	@Test
	public void testPlatformDirectory() {
		String os = System.getProperty("os.name").toLowerCase();
		String arch = System.getProperty("os.arch");
		if (os.startsWith("windows") && arch.equals("amd64")) {
			assertEquals("win_x86_64", HydraCpu.platformDirectory());
		}
		else if (os.startsWith("linux") && arch.equals("amd64")) {
			assertEquals("linux_x86_64", HydraCpu.platformDirectory());
		}
	}
}
