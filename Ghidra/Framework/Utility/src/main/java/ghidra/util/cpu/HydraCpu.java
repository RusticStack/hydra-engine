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
package ghidra.util.cpu;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * The CPUs the OS grants this process, the CPU's identity and core classes, and the active tuning
 * profile (Hydra Rust plan, goal 4: "runs well everywhere, tuned where we can measure").
 * <p>
 * <b>Granted CPUs</b> ({@link #grantedCpus()}): the logical CPUs the process may run on (affinity
 * mask; on Linux the JVM already applies cgroup limits), lowered to a Windows job object hard CPU
 * rate cap rounded up, never below one. Every CPU-sized pool uses this instead of a fixed number.
 * <p>
 * <b>Profiles</b> ({@link #profile()}): {@code HYDRA_CPU_PROFILE} (or the system property
 * {@code hydra.cpu.profile}) is {@code generic}, {@code auto} (the default) or a profile name.
 * {@code auto} picks the first entry of {@link #AUTO_PROFILES} whose matcher accepts the detected
 * CPU, else {@code generic}. A profile joins {@link #AUTO_PROFILES} only with measured before/after
 * numbers; until then it is selectable by name only ({@link #PROFILES}). A profile changes performance knobs only (pool size per core class and
 * thread placement), never results. The generic profile places no thread.
 * <p>
 * <b>Placement</b> ({@link #place(Role)}): on a hybrid CPU (more than one efficiency class) under
 * a profile that asks for it, a {@link Role#LATENCY} thread (daemon request handling) selects
 * the performance-class CPU sets and a {@link Role#BACKGROUND} thread (analysis pools) the
 * efficiency-class ones, through {@code SetThreadSelectedCpuSets} (Windows). Background threads
 * are placed only once the live background threads outnumber the performance-class CPUs (the
 * first ones run unplaced, so a small pool is never confined to E-cores while P-cores idle).
 * Each class takes at most as many placed threads as it has granted logical CPUs; a thread past
 * that budget is left unplaced (it may run on any CPU), so placement never makes work wait for a
 * core class. Machines with more than one processor group are never treated as hybrid. Elsewhere (other OS, non-hybrid CPU, no native access, virtual thread) it is a
 * no-op.
 * <p>
 * The native layer is {@code java.lang.foreign} against kernel32 and is used only when this
 * module has native access ({@code --enable-native-access}; every Ghidra launch sets it through
 * {@code support/launch.properties}, so the GUI and analyzeHeadless detect granted CPUs too;
 * {@code -Dhydra.cpu.noNative=true} turns it off); without it every answer comes from the JVM ({@code availableProcessors}, no placement). When
 * the Rust {@code hydra-native} library (rust/p1-native-core) ships a loadable FFM entry point
 * it can replace {@link Native} behind the same methods.
 * <p>
 * Adding a profile: see {@code docs/cpu-profiles.md} (a {@link Profile} entry, a matcher, and
 * before/after numbers from {@code Ghidra/Features/HeadlessSession/examples/cpu_bench.py}).
 */
public final class HydraCpu {

	/** The environment variable that overrides the profile. */
	public static final String ENV = "HYDRA_CPU_PROFILE";
	/** The system property that overrides the profile (wins over the environment). */
	public static final String PROPERTY = "hydra.cpu.profile";

	/** What a thread does, for placement on a hybrid CPU. */
	public enum Role {
		/** Latency-critical: daemon request handling. Prefers performance cores. */
		LATENCY,
		/** Background: analysis pools, sweeps, housekeeping. Prefers efficiency cores. */
		BACKGROUND
	}

	/**
	 * The detected CPU: identity from CPUID as the OS reports it, and its core classes.
	 *
	 * @param vendor "GenuineIntel", "AuthenticAMD", ... or "unknown"
	 * @param family the CPUID display family (0 when unknown)
	 * @param model the CPUID display model (0 when unknown)
	 * @param systemCpus the logical CPUs of the machine
	 * @param grantedCpus the logical CPUs this process may keep busy
	 * @param performanceIds the CPU set ids of the highest efficiency class the process may use
	 *            (all of its CPU sets when they are of one class)
	 * @param efficiencyIds the CPU set ids of the lower efficiency classes the process may use
	 *            (empty when not hybrid)
	 * @param source where the facts came from ("windows-cpusets" or "jvm")
	 */
	public record Cpu(String vendor, int family, int model, int systemCpus, int grantedCpus,
			int[] performanceIds, int[] efficiencyIds, String source) {

		/** @return true when the process may use cores of more than one efficiency class */
		public boolean hybrid() {
			return performanceIds.length > 0 && efficiencyIds.length > 0;
		}
	}

	/**
	 * A tuning profile: performance knobs only.
	 *
	 * @param name the name {@code HYDRA_CPU_PROFILE} selects it by
	 * @param matches whether {@code auto} selects it for a CPU
	 * @param placeThreads whether threads are placed by {@link Role} on a hybrid CPU
	 * @param latencyShare the share (0..1] of the performance-class CPUs that latency threads may
	 *            be placed on at once (the budget); the rest of the latency threads run unplaced
	 * @param backgroundShare the same for background threads on the efficiency-class CPUs
	 * @param description one line for reports
	 */
	public record Profile(String name, Predicate<Cpu> matches, boolean placeThreads,
			double latencyShare, double backgroundShare, String description) {

		/**
		 * The default CPU-bound pool size: granted CPUs + 1 (Java Concurrency in Practice). The
		 * same on every profile: a profile moves threads between core classes, it does not shrink
		 * a pool (the generic path is never made slower to benefit a profile).
		 *
		 * @param cpu the CPU
		 * @return the pool size
		 */
		public int poolSize(Cpu cpu) {
			return Math.max(1, cpu.grantedCpus()) + 1;
		}

		/**
		 * @param cpu the CPU
		 * @return how many latency threads may be placed on performance cores at once
		 */
		public int latencyBudget(Cpu cpu) {
			return placeThreads && cpu.hybrid()
					? Math.max(1, (int) Math.floor(cpu.performanceIds().length * latencyShare))
					: 0;
		}

		/**
		 * @param cpu the CPU
		 * @return how many background threads may be placed on efficiency cores at once
		 */
		public int backgroundBudget(Cpu cpu) {
			return placeThreads && cpu.hybrid()
					? Math.max(1, (int) Math.floor(cpu.efficiencyIds().length * backgroundShare))
					: 0;
		}
	}

	/** The generic profile: no placement, pools from granted CPUs. Used for unknown CPUs. */
	public static final Profile GENERIC =
		new Profile("generic", cpu -> true, false, 0, 0, "any x64 CPU: no thread placement");

	/** Intel Raptor Lake (CPUID family 6, model 0xB7/0xBA/0xBF) with P and E cores. */
	public static final Profile RAPTORLAKE_HYBRID = new Profile("raptorlake-hybrid",
		cpu -> "GenuineIntel".equals(cpu.vendor()) && cpu.family() == 6 &&
			(cpu.model() == 0xB7 || cpu.model() == 0xBA || cpu.model() == 0xBF) && cpu.hybrid(),
		true, 1.0, 1.0,
		"Intel Raptor Lake hybrid: request threads on P-cores, background work on E-cores");

	/**
	 * The profiles selectable by name (the generic profile is always selectable). Contributors add
	 * an entry here through a PR (docs/cpu-profiles.md).
	 */
	public static final List<Profile> PROFILES = List.of(RAPTORLAKE_HYBRID);

	/**
	 * The profiles {@code auto} tries in order (the generic profile is the fallback, not listed).
	 * A profile is added here only with before/after numbers from {@code cpu_bench.py} on a process
	 * granted every core class of the CPU (docs/cpu-profiles.md). {@code raptorlake-hybrid} has none
	 * yet, so it is selectable by name only and {@code auto} is generic everywhere.
	 */
	public static final List<Profile> AUTO_PROFILES = List.of();

	/**
	 * The selected profile and why.
	 *
	 * @param profile the active profile
	 * @param requested the override value ("auto" when none was given)
	 * @param reason why this profile is active
	 */
	public record Selection(Profile profile, String requested, String reason) {
	}

	private static volatile Cpu cpu;
	private static volatile Selection selection;
	private static final AtomicInteger PLACED_LATENCY = new AtomicInteger();
	private static final AtomicInteger PLACED_BACKGROUND = new AtomicInteger();
	private static final AtomicInteger PLACE_FAILURES = new AtomicInteger();
	private static final AtomicInteger TOTAL_LATENCY = new AtomicInteger();
	private static final AtomicInteger TOTAL_BACKGROUND = new AtomicInteger();
	private static final AtomicInteger ACTIVE_BACKGROUND = new AtomicInteger();

	private HydraCpu() {
	}

	/** @return the detected CPU (detected once) */
	public static Cpu cpu() {
		Cpu c = cpu;
		if (c == null) {
			synchronized (HydraCpu.class) {
				if (cpu == null) {
					cpu = detect();
				}
				c = cpu;
			}
		}
		return c;
	}

	/** @return the logical CPUs the OS grants this process (at least 1) */
	public static int grantedCpus() {
		return cpu().grantedCpus();
	}

	/** @return the active profile */
	public static Profile profile() {
		return selection().profile();
	}

	/** @return the active profile with the override and the reason */
	public static Selection selection() {
		Selection s = selection;
		if (s == null) {
			synchronized (HydraCpu.class) {
				if (selection == null) {
					String[] r = requested();
					selection = select(r[0], r[1], cpu());
				}
				s = selection;
			}
		}
		return s;
	}

	/** @return the default CPU-bound pool size of the active profile */
	public static int defaultPoolSize() {
		return profile().poolSize(cpu());
	}

	/** @return {override, source}: the property, else the environment, else {"auto", "default"} */
	static String[] requested() {
		String v = System.getProperty(PROPERTY);
		String src = "-D" + PROPERTY;
		if (v == null || v.isBlank()) {
			v = System.getenv(ENV);
			src = ENV;
		}
		return v == null || v.isBlank() ? new String[] { "auto", "default" }
				: new String[] { v.trim().toLowerCase(Locale.ROOT), src };
	}

	/**
	 * Picks the profile for an override value given through {@link #ENV}.
	 *
	 * @param requested "generic", "auto" or a profile name
	 * @param c the CPU
	 * @return the selection
	 */
	public static Selection select(String requested, Cpu c) {
		return select(requested, ENV, c);
	}

	/**
	 * Picks the profile for an override value and a CPU.
	 *
	 * @param requested "generic", "auto" or a profile name
	 * @param source where the value came from ({@link #ENV}, {@code -Dhydra.cpu.profile})
	 * @param c the CPU
	 * @return the selection
	 */
	public static Selection select(String requested, String source, Cpu c) {
		if ("generic".equals(requested)) {
			return new Selection(GENERIC, requested, source + "=generic");
		}
		if (!"auto".equals(requested)) {
			for (Profile p : PROFILES) {
				if (p.name().equals(requested)) {
					return new Selection(p, requested, source + "=" + requested + " (forced)");
				}
			}
			return new Selection(GENERIC, requested,
				source + ": unknown profile '" + requested + "', using generic");
		}
		for (Profile p : AUTO_PROFILES) {
			if (p.matches().test(c)) {
				return new Selection(p, requested, "auto: the CPU matches " + p.name());
			}
		}
		return new Selection(GENERIC, requested, "auto: no profile for this CPU");
	}

	/**
	 * Places the current thread for its role under the active profile (see the class comment).
	 * The placement holds until {@link #release(Role, boolean)} or the thread's end.
	 *
	 * @param role the thread's role
	 * @return true when the thread was placed (and must be released with the same role)
	 */
	public static boolean place(Role role) {
		Profile p = profile();
		Cpu c = cpu();
		if (!p.placeThreads() || !c.hybrid() || Thread.currentThread().isVirtual() ||
			!Native.available()) {
			return false;
		}
		AtomicInteger placed = role == Role.LATENCY ? PLACED_LATENCY : PLACED_BACKGROUND;
		int budget = role == Role.LATENCY ? p.latencyBudget(c) : p.backgroundBudget(c);
		if (placed.incrementAndGet() > budget) {
			placed.decrementAndGet();
			return false;
		}
		int[] ids = role == Role.LATENCY ? c.performanceIds() : c.efficiencyIds();
		if (!Native.selectCpuSets(ids)) {
			placed.decrementAndGet();
			PLACE_FAILURES.incrementAndGet();
			return false;
		}
		(role == Role.LATENCY ? TOTAL_LATENCY : TOTAL_BACKGROUND).incrementAndGet();
		return true;
	}

	/**
	 * Undoes {@link #place(Role)} on the current thread.
	 *
	 * @param role the role it was placed with
	 * @param placed what {@link #place(Role)} returned
	 */
	public static void release(Role role, boolean placed) {
		if (!placed) {
			return;
		}
		Native.selectCpuSets(new int[0]);
		(role == Role.LATENCY ? PLACED_LATENCY : PLACED_BACKGROUND).decrementAndGet();
	}

	/**
	 * Wraps a thread body so that it runs placed for its role (for thread factories). A
	 * {@link Role#BACKGROUND} thread is placed only when it starts while more live background
	 * threads exist than performance-class CPUs (P-cores are oversubscribed); the first ones run
	 * unplaced.
	 *
	 * @param role the role
	 * @param body the body
	 * @return the wrapped body
	 */
	public static Runnable placed(Role role, Runnable body) {
		return () -> {
			boolean bg = role == Role.BACKGROUND;
			int active = bg ? ACTIVE_BACKGROUND.incrementAndGet() : 0;
			boolean placed = false;
			try {
				placed = !bg || placeBackgroundAt(active, cpu()) ? place(role) : false;
				body.run();
			}
			finally {
				release(role, placed);
				if (bg) {
					ACTIVE_BACKGROUND.decrementAndGet();
				}
			}
		};
	}

	private static Runnable placedNow(Role role, Runnable body) {
		return () -> {
			boolean placed = place(role);
			try {
				body.run();
			}
			finally {
				release(role, placed);
			}
		};
	}

	/**
	 * @param active the live background threads, this one included
	 * @param c the CPU
	 * @return whether a background thread starting now is placed on efficiency cores
	 */
	static boolean placeBackgroundAt(int active, Cpu c) {
		return c.hybrid() && active > c.performanceIds().length;
	}

	/** @return a one-line report: CPU, granted CPUs, classes, profile, placements */
	public static Map<String, Object> report() {
		Cpu c = cpu();
		Selection s = selection();
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("vendor", c.vendor());
		m.put("family", c.family());
		m.put("model", c.model());
		m.put("systemCpus", c.systemCpus());
		m.put("grantedCpus", c.grantedCpus());
		m.put("performanceCpus", c.performanceIds().length);
		m.put("efficiencyCpus", c.efficiencyIds().length);
		m.put("hybrid", c.hybrid());
		m.put("source", c.source());
		m.put("profile", s.profile().name());
		m.put("requested", s.requested());
		m.put("reason", s.reason());
		m.put("poolSize", s.profile().poolSize(c));
		m.put("latencyBudget", s.profile().latencyBudget(c));
		m.put("backgroundBudget", s.profile().backgroundBudget(c));
		m.put("placedLatency", PLACED_LATENCY.get());
		m.put("placedBackground", PLACED_BACKGROUND.get());
		m.put("placedLatencyTotal", TOTAL_LATENCY.get());
		m.put("placedBackgroundTotal", TOTAL_BACKGROUND.get());
		m.put("placeFailures", PLACE_FAILURES.get());
		m.put("nativeAccess", Native.available());
		return m;
	}

	/**
	 * Prints {@link #report()} as {@code key=value} lines, then places one thread of each role
	 * and prints whether that worked (a manual and test probe).
	 *
	 * @param args unused
	 * @throws InterruptedException never in practice
	 */
	public static void main(String[] args) throws InterruptedException {
		if (args.length > 0 && args[0].equals("--selftest")) {
			List<String> failed = selfTest();
			failed.forEach(f -> System.out.println("FAIL " + f));
			System.out.println("selftest: " + (failed.isEmpty() ? "ok" : failed.size() + " failed"));
			System.exit(failed.isEmpty() ? 0 : 1);
		}
		for (Role r : Role.values()) {
			Thread t = new Thread(placedNow(r, () -> System.out.println(
				"probe." + r.name().toLowerCase(Locale.ROOT) + "=" +
					(r == Role.LATENCY ? PLACED_LATENCY : PLACED_BACKGROUND).get())));
			t.start();
			t.join();
		}
		report().forEach((k, v) -> System.out.println(k + "=" + v));
	}

	/**
	 * Checks the selection and budget rules on synthetic CPUs and, when native access is
	 * available, that selecting and clearing CPU sets on this thread works.
	 *
	 * @return the failed checks (empty when all pass)
	 */
	public static List<String> selfTest() {
		List<String> f = new ArrayList<>();
		int[] p16 = new int[16], e8 = new int[8];
		Arrays.setAll(p16, i -> 256 + i);
		Arrays.setAll(e8, i -> 272 + i);
		Cpu rpl = new Cpu("GenuineIntel", 6, 0xB7, 24, 24, p16, e8, "test");
		Cpu rplP = new Cpu("GenuineIntel", 6, 0xB7, 24, 16, p16, new int[0], "test");
		Cpu amd = new Cpu("AuthenticAMD", 0x19, 0x61, 32, 32, new int[0], new int[0], "test");
		Cpu quota = new Cpu("AuthenticAMD", 0x19, 0x61, 32, 4, new int[0], new int[0], "test");
		chk(f, "the raptorlake-hybrid matcher accepts a hybrid Raptor Lake",
			RAPTORLAKE_HYBRID.matches().test(rpl));
		chk(f, "auto stays generic on a hybrid Raptor Lake until the profile is measured",
			select("auto", rpl).profile() == GENERIC && !AUTO_PROFILES.contains(RAPTORLAKE_HYBRID));
		chk(f, "the reason names the property when it chose",
			select("generic", "-D" + PROPERTY, rpl).reason().startsWith("-D" + PROPERTY));
		chk(f, "background threads up to the P-core count run unplaced",
			!placeBackgroundAt(16, rpl) && placeBackgroundAt(17, rpl) && !placeBackgroundAt(99, amd));
		chk(f, "auto falls back to generic when only P-cores are granted",
			select("auto", rplP).profile() == GENERIC);
		chk(f, "auto falls back to generic on an unknown CPU", select("auto", amd).profile() == GENERIC);
		chk(f, "generic override wins over a matching CPU",
			select("generic", rpl).profile() == GENERIC);
		chk(f, "a named override is forced", select("raptorlake-hybrid", amd).profile() == RAPTORLAKE_HYBRID);
		chk(f, "an unknown override is generic", select("nonesuch", rpl).profile() == GENERIC);
		chk(f, "pool size is granted + 1 on every profile",
			GENERIC.poolSize(rpl) == 25 && RAPTORLAKE_HYBRID.poolSize(rpl) == 25 &&
				GENERIC.poolSize(quota) == 5);
		chk(f, "generic places nothing", GENERIC.latencyBudget(rpl) == 0 && GENERIC.backgroundBudget(rpl) == 0);
		chk(f, "raptorlake budgets are the class sizes",
			RAPTORLAKE_HYBRID.latencyBudget(rpl) == 16 && RAPTORLAKE_HYBRID.backgroundBudget(rpl) == 8);
		chk(f, "a forced profile places nothing on a non-hybrid CPU",
			RAPTORLAKE_HYBRID.latencyBudget(amd) == 0 && RAPTORLAKE_HYBRID.backgroundBudget(rplP) == 0);
		Cpu c = cpu();
		chk(f, "granted CPUs are within 1..system", c.grantedCpus() >= 1 && c.grantedCpus() <= c.systemCpus());
		chk(f, "granted CPUs never exceed the JVM's count",
			c.grantedCpus() <= Math.max(1, Runtime.getRuntime().availableProcessors()));
		if (Native.available() && c.source().equals("windows-cpusets")) {
			int[] all = new int[c.performanceIds().length + c.efficiencyIds().length];
			System.arraycopy(c.performanceIds(), 0, all, 0, c.performanceIds().length);
			System.arraycopy(c.efficiencyIds(), 0, all, c.performanceIds().length, c.efficiencyIds().length);
			if (all.length > 0) {
				chk(f, "SetThreadSelectedCpuSets accepts the granted sets", Native.selectCpuSets(all));
			}
			chk(f, "SetThreadSelectedCpuSets clears", Native.selectCpuSets(new int[0]));
		}
		return f;
	}

	private static void chk(List<String> failed, String what, boolean ok) {
		if (!ok) {
			failed.add(what);
		}
	}

	// ---- detection -----------------------------------------------------------------------------

	private static Cpu detect() {
		String[] id = identity();
		String vendor = id[0];
		int family = parseInt(id[1]);
		int model = parseInt(id[2]);
		int jvm = Math.max(1, Runtime.getRuntime().availableProcessors());
		if (Native.available()) {
			try {
				Cpu c = Native.detect(vendor, family, model, jvm);
				if (c != null) {
					return c;
				}
			}
			catch (Throwable t) {
				// fall through to the JVM's answer
			}
		}
		return new Cpu(vendor, family, model, jvm, jvm, new int[0], new int[0], "jvm");
	}

	/** vendor, family, model from the OS (Windows PROCESSOR_IDENTIFIER, Linux /proc/cpuinfo). */
	private static String[] identity() {
		String pid = System.getenv("PROCESSOR_IDENTIFIER");
		if (pid != null) {
			// "Intel64 Family 6 Model 183 Stepping 1, GenuineIntel"
			String fam = token(pid, "Family "), mod = token(pid, "Model ");
			int comma = pid.lastIndexOf(',');
			String vendor = comma >= 0 ? pid.substring(comma + 1).trim() : "unknown";
			return new String[] { vendor, fam, mod };
		}
		try {
			String vendor = "unknown", fam = "0", mod = "0";
			for (String line : Files.readAllLines(Path.of("/proc/cpuinfo"))) {
				int colon = line.indexOf(':');
				if (colon < 0) {
					if (line.isBlank()) {
						break;
					}
					continue;
				}
				String k = line.substring(0, colon).trim(), v = line.substring(colon + 1).trim();
				switch (k) {
					case "vendor_id" -> vendor = v;
					case "cpu family" -> fam = v;
					case "model" -> mod = v;
					default -> {
					}
				}
			}
			return new String[] { vendor, fam, mod };
		}
		catch (IOException | RuntimeException e) {
			return new String[] { "unknown", "0", "0" };
		}
	}

	private static String token(String s, String key) {
		int i = s.indexOf(key);
		if (i < 0) {
			return "0";
		}
		int j = i + key.length(), k = j;
		while (k < s.length() && Character.isDigit(s.charAt(k))) {
			k++;
		}
		return s.substring(j, k);
	}

	private static int parseInt(String s) {
		try {
			return Integer.parseInt(s.trim());
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	// ---- Windows (java.lang.foreign against kernel32) -------------------------------------------

	private static final class Native {
		private static final boolean WINDOWS =
			System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
		private static final boolean ENABLED = WINDOWS &&
			HydraCpu.class.getModule().isNativeAccessEnabled() &&
			!Boolean.getBoolean("hydra.cpu.noNative");
		private static volatile Handles handles;
		private static volatile boolean broken;

		private static final int JOB_CPU_RATE = 15; // JobObjectCpuRateControlInformation
		private static final int RATE_ENABLE = 0x1, RATE_WEIGHT = 0x2, RATE_HARD_CAP = 0x4;

		private Native() {
		}

		static boolean available() {
			return ENABLED && !broken && handles() != null;
		}

		private static final class Handles {
			final MethodHandle getCpuSets, setThreadCpuSets, currentThread, currentProcess,
					affinity, queryJob;

			Handles() {
				Linker l = Linker.nativeLinker();
				SymbolLookup k32 = SymbolLookup.libraryLookup("kernel32", Arena.global());
				ValueLayout.OfInt i = ValueLayout.JAVA_INT;
				AddressLayout p = ValueLayout.ADDRESS;
				getCpuSets = l.downcallHandle(k32.findOrThrow("GetSystemCpuSetInformation"),
					FunctionDescriptor.of(i, p, i, p, p, i));
				setThreadCpuSets = l.downcallHandle(k32.findOrThrow("SetThreadSelectedCpuSets"),
					FunctionDescriptor.of(i, p, p, i));
				currentThread = l.downcallHandle(k32.findOrThrow("GetCurrentThread"),
					FunctionDescriptor.of(p));
				currentProcess = l.downcallHandle(k32.findOrThrow("GetCurrentProcess"),
					FunctionDescriptor.of(p));
				affinity = l.downcallHandle(k32.findOrThrow("GetProcessAffinityMask"),
					FunctionDescriptor.of(i, p, p, p));
				queryJob = l.downcallHandle(k32.findOrThrow("QueryInformationJobObject"),
					FunctionDescriptor.of(i, p, i, p, i, p));
			}
		}

		private static Handles handles() {
			if (!ENABLED || broken) {
				return null;
			}
			Handles h = handles;
			if (h == null) {
				synchronized (Native.class) {
					if (handles == null && !broken) {
						try {
							handles = new Handles();
						}
						catch (Throwable t) {
							broken = true;
						}
					}
					h = handles;
				}
			}
			return h;
		}

		/** The machine's CPU sets, the process affinity and job CPU cap; null on failure. */
		static Cpu detect(String vendor, int family, int model, int jvm) throws Throwable {
			Handles h = handles();
			if (h == null) {
				return null;
			}
			try (Arena a = Arena.ofConfined()) {
				MemorySegment self = (MemorySegment) h.currentProcess.invokeExact();
				MemorySegment needed = a.allocate(ValueLayout.JAVA_INT);
				int ignored = (int) h.getCpuSets.invokeExact(MemorySegment.NULL, 0, needed, self, 0);
				int len = needed.get(ValueLayout.JAVA_INT, 0);
				if (len <= 0) {
					return null;
				}
				MemorySegment buf = a.allocate(len, 8);
				if ((int) h.getCpuSets.invokeExact(buf, len, needed, self, 0) == 0) {
					return null;
				}
				// the process affinity mask (group 0; used only on single-group machines below)
				MemorySegment pm = a.allocate(8), sm = a.allocate(8);
				long procMask = -1L;
				if ((int) h.affinity.invokeExact(self, pm, sm) != 0) {
					procMask = pm.get(ValueLayout.JAVA_LONG, 0);
				}
				// SYSTEM_CPU_SET_INFORMATION: Size@0 Type@4 Id@8 Group@12(u16) LogicalProcessorIndex@14
				// CoreIndex@15 LastLevelCacheIndex@16 NumaNodeIndex@17 EfficiencyClass@18
				List<int[]> sets = new ArrayList<>(); // {id, efficiencyClass}
				List<Integer> allIds = new ArrayList<>();
				Set<Integer> groups = new HashSet<>();
				int system = 0, maxClass = 0, minClass = Integer.MAX_VALUE;
				long off = 0;
				while (off + 20 <= len) {
					int size = buf.get(ValueLayout.JAVA_INT, off);
					if (size <= 0) {
						break;
					}
					if (buf.get(ValueLayout.JAVA_INT, off + 4) == 0) { // CpuSetInformation
						system++;
						int id = buf.get(ValueLayout.JAVA_INT, off + 8);
						int group = Short.toUnsignedInt(buf.get(ValueLayout.JAVA_SHORT, off + 12));
						int lp = Byte.toUnsignedInt(buf.get(ValueLayout.JAVA_BYTE, off + 14));
						int eff = Byte.toUnsignedInt(buf.get(ValueLayout.JAVA_BYTE, off + 18));
						groups.add(group);
						allIds.add(id);
						boolean allowed = group == 0 && lp < 64 && (procMask >>> lp & 1) != 0;
						if (allowed) {
							sets.add(new int[] { id, eff });
							maxClass = Math.max(maxClass, eff);
							minClass = Math.min(minClass, eff);
						}
					}
					off += size;
				}
				if (groups.size() > 1) {
					// several processor groups: GetProcessAffinityMask describes one group only
					// (zero when the process spans groups), so no class split and no placement;
					// the JVM's count, lowered to a job cap
					int granted = Math.max(1, Math.min(jvm, jobCap(h, a, system)));
					return new Cpu(vendor, family, model, system, granted,
						allIds.stream().mapToInt(Integer::intValue).toArray(), new int[0],
						"windows-cpusets-multigroup");
				}
				if (sets.isEmpty()) {
					return null;
				}
				int affinityCpus = Math.min(sets.size(), jvm);
				int granted = Math.max(1, Math.min(affinityCpus, jobCap(h, a, system)));
				int[] perf, effi;
				if (maxClass == minClass) { // one class: all of them, none placed (not hybrid)
					perf = sets.stream().mapToInt(s -> s[0]).toArray();
					effi = new int[0];
				}
				else {
					final int top = maxClass;
					perf = sets.stream().filter(s -> s[1] == top).mapToInt(s -> s[0]).toArray();
					effi = sets.stream().filter(s -> s[1] != top).mapToInt(s -> s[0]).toArray();
				}
				return new Cpu(vendor, family, model, system, granted, perf, effi,
					"windows-cpusets");
			}
		}

		/** A job object hard CPU rate cap as whole CPUs rounded up; MAX_VALUE when none. */
		private static int jobCap(Handles h, Arena a, int systemCpus) throws Throwable {
			MemorySegment info = a.allocate(8);
			int ok = (int) h.queryJob.invokeExact(MemorySegment.NULL, JOB_CPU_RATE, info, 8,
				MemorySegment.NULL);
			if (ok == 0) {
				return Integer.MAX_VALUE;
			}
			int flags = info.get(ValueLayout.JAVA_INT, 0);
			int rate = info.get(ValueLayout.JAVA_INT, 4);
			if ((flags & RATE_ENABLE) == 0 || (flags & RATE_WEIGHT) != 0 ||
				(flags & RATE_HARD_CAP) == 0 || rate <= 0) {
				return Integer.MAX_VALUE;
			}
			// rate: hundredths of a percent of the whole machine -> thousandths of a CPU
			long milli = (long) rate * systemCpus / 10;
			return (int) Math.max(1, (milli + 999) / 1000);
		}

		/** Sets (or with no ids clears) the current thread's selected CPU sets. */
		static boolean selectCpuSets(int[] ids) {
			Handles h = handles();
			if (h == null) {
				return false;
			}
			try (Arena a = Arena.ofConfined()) {
				MemorySegment thread = (MemorySegment) h.currentThread.invokeExact();
				MemorySegment arr = ids.length == 0 ? MemorySegment.NULL
						: a.allocateFrom(ValueLayout.JAVA_INT, ids);
				return (int) h.setThreadCpuSets.invokeExact(thread, arr, ids.length) != 0;
			}
			catch (Throwable t) {
				return false;
			}
		}
	}
}
