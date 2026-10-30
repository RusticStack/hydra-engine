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

import static java.lang.foreign.ValueLayout.*;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.CodeSource;

import ghidra.framework.OperatingSystem;

/**
 * What this process may use and what it runs on, from the Hydra native library
 * ({@code hydra_native}, module HydraNative) through the foreign function API: the logical CPUs
 * the OS grants the process (affinity mask, CPU sets, job object or cgroup CPU quota), its memory
 * limit, the CPU's identification and topology, and the tuning profile chosen for the CPU.
 * <p>
 * A tuning profile only sets performance knobs (pool sizes per core class and a placement hint),
 * never anything that changes a result. It is chosen from the CPU, or forced with the
 * {@code HYDRA_CPU_PROFILE} environment variable or the {@code hydra.cpu.profile} system property
 * ({@code generic}, {@code auto} or a profile name; the property wins).
 * <p>
 * Without the library (not built, another platform, or a library this class does not match),
 * the values are the pure-Java ones: {@link Runtime#availableProcessors()} CPUs, the machine's
 * memory, and the {@code generic} profile; {@link #getFallbackReason()} says why.
 * <p>
 * The values are read once per process ({@link #get()}). Nothing sizes its pools from this class
 * yet.
 */
public final class HydraCpu {

	/** The system property naming the library file, instead of looking in module HydraNative. */
	public static final String LIBRARY_PROPERTY = "hydra.native.library";
	/** The system property that forces a profile; it wins over {@link #PROFILE_ENV}. */
	public static final String PROFILE_PROPERTY = "hydra.cpu.profile";
	/** The environment variable that forces a profile. */
	public static final String PROFILE_ENV = "HYDRA_CPU_PROFILE";
	/** The default profile, for any CPU. */
	public static final String GENERIC = "generic";

	static final String MODULE = "HydraNative";
	static final String LIBRARY = "hydra_native";

	// The C ABI: include/hydra_native.h in module HydraNative
	static final int ABI_VERSION = 1;
	static final long INFO_SIZE = 224;
	private static final int OK = 0;

	/** Where threads should run. */
	public enum Placement {
		/** No preference: the OS schedules every thread. */
		ANY,
		/** Latency-critical work on the performance cores, background work on the others. */
		LATENCY_ON_PERFORMANCE_CORES
	}

	/** The widest SIMD level the CPU and the OS both support. */
	public enum SimdLevel {
		/** SSE2, or not an x86-64 CPU (also the value without the library). */
		BASELINE,
		SSE4_2,
		/** AVX2, FMA, BMI1 and BMI2 (x86-64-v3). */
		AVX2,
		/** AVX-512 F, CD, BW, DQ and VL (x86-64-v4). */
		AVX512
	}

	/** Why the profile was chosen. */
	public enum ProfileSource {
		/** Chosen from the CPU. */
		AUTO,
		/** Named by the override. */
		FORCED,
		/** The override names no profile; {@code generic} is used. */
		UNKNOWN_OVERRIDE,
		/** The library is not loaded; {@code generic} is used. */
		FALLBACK
	}

	private static class Holder {
		private static final HydraCpu CURRENT = detect(findLibrary(), profileOverride());
	}

	private final String fallbackReason;
	private final int systemCpus;
	private final int affinityCpus;
	private final int grantedCpus;
	private final int performanceCpus;
	private final int efficiencyCpus;
	private final int performanceCores;
	private final int efficiencyCores;
	private final int llcGroups;
	private final int l2Groups;
	private final int cpuQuotaMilli;
	private final long memoryLimit;
	private final long physicalMemory;
	private final String vendor;
	private final int family;
	private final int model;
	private final int stepping;
	private final boolean hybrid;
	private final SimdLevel simdLevel;
	private final String brand;
	private final String profile;
	private final ProfileSource profileSource;
	private final Placement placement;
	private final int latencyThreads;
	private final int computeThreads;
	private final int backgroundThreads;

	/** The values the library wrote into {@code info} (a {@code HydraCpuInfo}). */
	private HydraCpu(MemorySegment info) {
		fallbackReason = null;
		physicalMemory = info.get(JAVA_LONG, 16);
		memoryLimit = info.get(JAVA_LONG, 8);
		systemCpus = info.get(JAVA_INT, 24);
		affinityCpus = info.get(JAVA_INT, 28);
		grantedCpus = info.get(JAVA_INT, 32);
		performanceCpus = info.get(JAVA_INT, 36);
		efficiencyCpus = info.get(JAVA_INT, 40);
		performanceCores = info.get(JAVA_INT, 44);
		efficiencyCores = info.get(JAVA_INT, 48);
		llcGroups = info.get(JAVA_INT, 52);
		l2Groups = info.get(JAVA_INT, 56);
		cpuQuotaMilli = info.get(JAVA_INT, 60);
		family = info.get(JAVA_INT, 68);
		model = info.get(JAVA_INT, 72);
		stepping = info.get(JAVA_INT, 76);
		hybrid = info.get(JAVA_INT, 80) != 0;
		simdLevel = constant(SimdLevel.values(), info.get(JAVA_INT, 84), SimdLevel.BASELINE);
		latencyThreads = info.get(JAVA_INT, 88);
		computeThreads = info.get(JAVA_INT, 92);
		backgroundThreads = info.get(JAVA_INT, 96);
		placement = constant(Placement.values(), info.get(JAVA_INT, 100), Placement.ANY);
		profileSource =
			constant(ProfileSource.values(), info.get(JAVA_INT, 104), ProfileSource.AUTO);
		vendor = info.getString(112);
		profile = info.getString(128);
		brand = info.getString(160);
	}

	/** The pure-Java values, used when the library is not loaded. */
	private HydraCpu(String fallbackReason) {
		this.fallbackReason = fallbackReason;
		int cpus = Math.max(1, Runtime.getRuntime().availableProcessors());
		long memory = 0;
		OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
		if (os instanceof com.sun.management.OperatingSystemMXBean bean) {
			memory = bean.getTotalMemorySize();
		}
		systemCpus = affinityCpus = grantedCpus = performanceCpus = performanceCores = cpus;
		efficiencyCpus = efficiencyCores = l2Groups = cpuQuotaMilli = 0;
		llcGroups = 1;
		memoryLimit = physicalMemory = memory;
		vendor = brand = "";
		family = model = stepping = 0;
		hybrid = false;
		simdLevel = SimdLevel.BASELINE;
		profile = GENERIC;
		profileSource = ProfileSource.FALLBACK;
		placement = Placement.ANY;
		latencyThreads = computeThreads = backgroundThreads = cpus;
	}

	private static <E> E constant(E[] values, int ordinal, E unknown) {
		return ordinal >= 0 && ordinal < values.length ? values[ordinal] : unknown;
	}

	/**
	 * Returns the values for this process, detected on first use.
	 * @return the values for this process
	 */
	public static HydraCpu get() {
		return Holder.CURRENT;
	}

	/**
	 * Reads the values through the library at {@code library}, or the pure-Java values when it
	 * is null, missing or does not match this class.
	 * @param library the library file, or null
	 * @param override the profile override ({@code generic}, {@code auto} or a profile name), or
	 * null for automatic selection
	 * @return the values
	 */
	static HydraCpu detect(Path library, String override) {
		if (library == null) {
			return new HydraCpu(System.mapLibraryName(LIBRARY) + " not found");
		}
		if (!Files.isRegularFile(library)) {
			return new HydraCpu(library + " not found");
		}
		try (Arena arena = Arena.ofConfined()) {
			SymbolLookup lookup = SymbolLookup.libraryLookup(library, Arena.global());
			Linker linker = Linker.nativeLinker();
			MethodHandle version = linker.downcallHandle(
				lookup.findOrThrow("hydra_native_abi_version"), FunctionDescriptor.of(JAVA_INT));
			MethodHandle size = linker.downcallHandle(lookup.findOrThrow("hydra_cpu_info_size"),
				FunctionDescriptor.of(JAVA_LONG));
			MethodHandle query = linker.downcallHandle(lookup.findOrThrow("hydra_cpu_query"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));

			int abi = (int) version.invokeExact();
			long infoSize = (long) size.invokeExact();
			if (abi != ABI_VERSION || infoSize != INFO_SIZE) {
				return new HydraCpu(library + ": ABI " + abi + " (" + infoSize +
					" bytes), expected " + ABI_VERSION + " (" + INFO_SIZE + " bytes)");
			}
			byte[] name = (override == null ? "" : override).getBytes(StandardCharsets.UTF_8);
			MemorySegment nameSegment = arena.allocate(Math.max(1, name.length));
			nameSegment.copyFrom(MemorySegment.ofArray(name));
			MemorySegment info = arena.allocate(INFO_SIZE, 8);
			int rc = (int) query.invokeExact(nameSegment, (long) name.length, info, INFO_SIZE);
			if (rc != OK) {
				return new HydraCpu(library + ": hydra_cpu_query returned " + rc);
			}
			return new HydraCpu(info);
		}
		catch (VirtualMachineError e) {
			throw e;
		}
		catch (Throwable t) {
			return new HydraCpu(library + ": " + t);
		}
	}

	/** The override from {@link #PROFILE_PROPERTY}, else {@link #PROFILE_ENV}, else null. */
	static String profileOverride() {
		String value = System.getProperty(PROFILE_PROPERTY);
		return value != null ? value : System.getenv(PROFILE_ENV);
	}

	/**
	 * Finds the library: the {@link #LIBRARY_PROPERTY} file, else {@code os/<platform>} (an
	 * install) or {@code build/os/<platform>} (a source tree) of module HydraNative, next to the
	 * module this class was loaded from.
	 * @return the library file, or null when there is none
	 */
	static Path findLibrary() {
		String explicit = System.getProperty(LIBRARY_PROPERTY);
		if (explicit != null && !explicit.isBlank()) {
			return Path.of(explicit);
		}
		Path module = moduleRoot();
		String platform = platformDirectory();
		if (module == null || platform == null) {
			return null;
		}
		Path natives = module.resolveSibling(MODULE);
		String file = System.mapLibraryName(LIBRARY);
		for (Path dir : new Path[] { natives.resolve("os"), natives.resolve("build/os") }) {
			Path candidate = dir.resolve(platform).resolve(file);
			if (Files.isRegularFile(candidate)) {
				return candidate;
			}
		}
		return null;
	}

	/** The module directory (the one with a Module.manifest) this class was loaded from. */
	private static Path moduleRoot() {
		CodeSource source = HydraCpu.class.getProtectionDomain().getCodeSource();
		if (source == null || source.getLocation() == null) {
			return null;
		}
		try {
			Path dir = Path.of(source.getLocation().toURI());
			for (int i = 0; dir != null && i < 6; i++, dir = dir.getParent()) {
				if (Files.isRegularFile(dir.resolve("Module.manifest"))) {
					return dir;
				}
			}
		}
		catch (URISyntaxException | IllegalArgumentException | FileSystemNotFoundException e) {
			// not a file location (a jar inside a jar, say): no library
		}
		return null;
	}

	/** The platform directory name of the natives ({@code win_x86_64}), or null if unknown. */
	static String platformDirectory() {
		String os = switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case WINDOWS -> "win";
			case LINUX -> "linux";
			case MAC_OS_X -> "mac";
			case FREE_BSD -> "freebsd";
			default -> null;
		};
		String arch = switch (System.getProperty("os.arch")) {
			case "amd64", "x86_64" -> "x86_64";
			case "aarch64", "arm64" -> "arm_64";
			default -> null;
		};
		return os == null || arch == null ? null : os + "_" + arch;
	}

	/**
	 * Returns whether the values come from the library.
	 * @return true when the library was loaded
	 */
	public boolean isNative() {
		return fallbackReason == null;
	}

	/**
	 * Returns why the library was not used.
	 * @return the reason, or null when it was
	 */
	public String getFallbackReason() {
		return fallbackReason;
	}

	/**
	 * Returns the logical CPUs the process can keep busy: those it may run on, lowered to a CPU
	 * quota (job object CPU rate, cgroup {@code cpu.max}) rounded up. Never less than 1.
	 * @return the granted CPUs
	 */
	public int getGrantedCpus() {
		return grantedCpus;
	}

	/**
	 * Returns the logical CPUs the process may run on (affinity mask, CPU sets, cpuset), before
	 * any CPU quota.
	 * @return the CPUs in the affinity
	 */
	public int getAffinityCpus() {
		return affinityCpus;
	}

	/**
	 * Returns the logical CPUs of the machine.
	 * @return the CPUs of the machine
	 */
	public int getSystemCpus() {
		return systemCpus;
	}

	/**
	 * Returns the CPU quota in thousandths of a CPU.
	 * @return the quota, or 0 when none is set
	 */
	public int getCpuQuotaMilli() {
		return cpuQuotaMilli;
	}

	/**
	 * Returns the granted logical CPUs of the highest efficiency class (all of them on a CPU
	 * with one core class).
	 * @return the granted performance CPUs
	 */
	public int getPerformanceCpus() {
		return performanceCpus;
	}

	/**
	 * Returns the granted logical CPUs of a lower efficiency class (E-cores).
	 * @return the granted efficiency CPUs
	 */
	public int getEfficiencyCpus() {
		return efficiencyCpus;
	}

	/**
	 * Returns the physical cores of the granted performance CPUs.
	 * @return the performance cores
	 */
	public int getPerformanceCores() {
		return performanceCores;
	}

	/**
	 * Returns the physical cores of the granted efficiency CPUs.
	 * @return the efficiency cores
	 */
	public int getEfficiencyCores() {
		return efficiencyCores;
	}

	/**
	 * Returns the last-level cache groups with a granted CPU.
	 * @return the last-level cache groups
	 */
	public int getLastLevelCacheGroups() {
		return llcGroups;
	}

	/**
	 * Returns the L2 cache groups with a granted CPU.
	 * @return the L2 groups, or 0 when unknown
	 */
	public int getL2Groups() {
		return l2Groups;
	}

	/**
	 * Returns the memory the process may use: the lower of its job object or cgroup memory limit
	 * and the machine's physical memory.
	 * @return the memory limit in bytes, or 0 when unknown
	 */
	public long getMemoryLimit() {
		return memoryLimit;
	}

	/**
	 * Returns the machine's physical memory.
	 * @return the physical memory in bytes, or 0 when unknown
	 */
	public long getPhysicalMemory() {
		return physicalMemory;
	}

	/**
	 * Returns the CPUID vendor string ({@code GenuineIntel}, {@code AuthenticAMD}).
	 * @return the vendor, or "" when unknown
	 */
	public String getVendor() {
		return vendor;
	}

	/**
	 * Returns the CPU display family.
	 * @return the family, or 0 when unknown
	 */
	public int getFamily() {
		return family;
	}

	/**
	 * Returns the CPU display model.
	 * @return the model, or 0 when unknown
	 */
	public int getModel() {
		return model;
	}

	/**
	 * Returns the CPU stepping.
	 * @return the stepping
	 */
	public int getStepping() {
		return stepping;
	}

	/**
	 * Returns whether the CPU has more than one core class (P- and E-cores).
	 * @return true for a hybrid CPU
	 */
	public boolean isHybrid() {
		return hybrid;
	}

	/**
	 * Returns the widest SIMD level the CPU and the OS support.
	 * @return the SIMD level
	 */
	public SimdLevel getSimdLevel() {
		return simdLevel;
	}

	/**
	 * Returns the CPU brand string.
	 * @return the brand, or "" when unknown
	 */
	public String getBrand() {
		return brand;
	}

	/**
	 * Returns the name of the tuning profile.
	 * @return the profile name ({@link #GENERIC} by default)
	 */
	public String getProfile() {
		return profile;
	}

	/**
	 * Returns why the profile was chosen.
	 * @return the source of the profile
	 */
	public ProfileSource getProfileSource() {
		return profileSource;
	}

	/**
	 * Returns the profile's placement hint.
	 * @return the placement
	 */
	public Placement getPlacement() {
		return placement;
	}

	/**
	 * Returns the profile's thread count for latency-critical work.
	 * @return at least 1 and at most {@link #getGrantedCpus()}
	 */
	public int getLatencyThreads() {
		return latencyThreads;
	}

	/**
	 * Returns the profile's thread count for throughput work.
	 * @return at least 1 and at most {@link #getGrantedCpus()}
	 */
	public int getComputeThreads() {
		return computeThreads;
	}

	/**
	 * Returns the profile's thread count for background work.
	 * @return at least 1 and at most {@link #getGrantedCpus()}
	 */
	public int getBackgroundThreads() {
		return backgroundThreads;
	}

	@Override
	public String toString() {
		return "HydraCpu[" + (isNative() ? "native" : "fallback: " + fallbackReason) +
			", granted " + grantedCpus + " of " + systemCpus + " CPUs (affinity " + affinityCpus +
			(cpuQuotaMilli > 0 ? ", quota " + cpuQuotaMilli / 1000.0 : "") + "), P " +
			performanceCpus + "/" + performanceCores + " E " + efficiencyCpus + "/" +
			efficiencyCores + ", memory " + (memoryLimit >> 20) + " MiB, " +
			(!brand.isEmpty() ? brand : !vendor.isEmpty() ? vendor : "unknown CPU") + " family " +
			family + " model 0x" +
			Integer.toHexString(model) + (hybrid ? " hybrid" : "") + " " + simdLevel +
			", profile " + profile + " (" + profileSource + ", " + placement + ", threads " +
			latencyThreads + "/" + computeThreads + "/" + backgroundThreads + ")]";
	}
}
