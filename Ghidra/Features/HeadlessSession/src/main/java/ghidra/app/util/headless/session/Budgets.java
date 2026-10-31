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

import java.lang.management.ManagementFactory;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.cpu.HydraCpu;

/**
 * The resource budgets of PROTOCOL-3.md 3.11 and 3.7 (package E9): every value is a
 * {@link Settings} key, read here and nowhere else, advertised in {@code hello.limits}, and checked
 * at start-up (a value that is not what it should be is a usage error naming the key).
 *
 * <table>
 * <caption>The keys</caption>
 * <tr><td>{@code minXmxMb}</td><td>512; the daemon refuses to start with a smaller {@code -Xmx}
 * (0 forces it: the squeeze tests)</td></tr>
 * <tr><td>{@code maxViews}</td><td>32 open program views in the daemon</td></tr>
 * <tr><td>{@code maxViewsPerClient}</td><td>4</td></tr>
 * <tr><td>{@code heapSoftPct}, {@code heapHardPct}</td><td>70 and 85: admission and
 * {@code degraded}, as a percentage of {@code -Xmx}, measured after a collection</td></tr>
 * <tr><td>{@code nativeBudgetMb}</td><td>50% of RAM minus {@code -Xmx}: the memory the native
 * decompilers may use (200 MB each)</td></tr>
 * <tr><td>{@code viewDiskBudget}</td><td>20 GB: the databases of the view forks the daemon made
 * and that are still there</td></tr>
 * <tr><td>{@code diskReserve}</td><td>{@code max(5 GB, 5%)} of the volume stays free</td></tr>
 * <tr><td>{@code decompilerIdleS}</td><td>60: an idle pooled decompiler is disposed after
 * this</td></tr>
 * <tr><td>{@code decompileCache}</td><td>1/32 of {@code -Xmx}, at most 256 MB, off below 8 MB: the
 * decompile results of unchanged programs shared by every connection (0 turns it off)</td></tr>
 * <tr><td>{@code functionTable}</td><td>1/64 of {@code -Xmx}, at most 64 MB, off below 1 MB: the
 * function listings of program states shared by every connection (0 turns it off)</td></tr>
 * <tr><td>{@code scriptResults}</td><td>1/64 of {@code -Xmx}, at most 64 MB, off below 4 MB: the
 * output of {@code pure} read scripts on unchanged programs shared by every connection (0 turns it
 * off)</td></tr>
 * <tr><td>{@code decompilerWaitS}</td><td>60: the longest a request waits for a decompiler
 * permit before {@code busy}</td></tr>
 * </table>
 * Sizes (the two disk keys) take {@code 20GB}, {@code 512MB}, {@code 100KB} or a plain number of
 * megabytes.
 */
final class Budgets {

	static final int DEFAULT_MIN_XMX_MB = 512;
	static final int DEFAULT_MAX_VIEWS = 32;
	static final int DEFAULT_MAX_VIEWS_PER_CLIENT = 4;
	static final int DEFAULT_SOFT_PCT = 70;
	static final int DEFAULT_HARD_PCT = 85;
	/** The native memory one busy decompiler is budgeted (measured 161 MB busy, 22.6 idle). */
	static final long DECOMPILER_MB = 200;
	static final long FLOOR_EST_HEAP = 8L << 20;
	static final double EST_FACTOR = 1.5;
	private static final Pattern SIZE =
		Pattern.compile("(\\d+)\\s*(B|KB|MB|GB|TB)?", Pattern.CASE_INSENSITIVE);

	/** The learned heap cost of opening a program, by key (path), in bytes. */
	private static final Map<String, Long> LEARNED = new ConcurrentHashMap<>();

	private Budgets() {
		// static
	}

	static int minXmxMb() {
		return Settings.integer("minXmxMb", DEFAULT_MIN_XMX_MB);
	}

	static int maxViews() {
		return Settings.integer("maxViews", DEFAULT_MAX_VIEWS);
	}

	static int maxViewsPerClient() {
		return Settings.integer("maxViewsPerClient", DEFAULT_MAX_VIEWS_PER_CLIENT);
	}

	static int heapSoftPct() {
		return Settings.integer("heapSoftPct", DEFAULT_SOFT_PCT);
	}

	static int heapHardPct() {
		return Settings.integer("heapHardPct", DEFAULT_HARD_PCT);
	}

	static int decompilerIdleS() {
		return Settings.integer("decompilerIdleS", 60);
	}

	static int decompilerWaitS() {
		return Settings.integer("decompilerWaitS", 60);
	}

	static long maxHeapBytes() {
		return Runtime.getRuntime().maxMemory();
	}

	static long totalRamBytes() {
		try {
			if (ManagementFactory
					.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean os) {
				return os.getTotalMemorySize();
			}
		}
		catch (RuntimeException | LinkageError e) {
			// fall through
		}
		return 0;
	}

	/** {@code nativeBudgetMb}: the setting, else half of the RAM minus the heap (at least 200). */
	static long nativeBudgetMb() {
		if (Settings.has("nativeBudgetMb")) {
			return Settings.integer("nativeBudgetMb", 0);
		}
		long ram = totalRamBytes();
		long mb = (ram / 2 - maxHeapBytes()) >> 20;
		return ram == 0 ? 4096 : Math.max(DECOMPILER_MB, mb);
	}

	/**
	 * The permits of the decompiler gate: {@code min(CPUs, nativeBudget / 200 MB)}, at least 1;
	 * CPUs are the ones the OS grants the process ({@link HydraCpu#grantedCpus()}).
	 */
	static int gatePermits() {
		int cpus = HydraCpu.grantedCpus();
		return (int) Math.max(1, Math.min(cpus, nativeBudgetMb() / DECOMPILER_MB));
	}

	/**
	 * {@code decompileCache}: the bytes of decompile results kept for unchanged programs
	 * ({@link DecompileCache}); default 1/32 of the heap, at most 256 MB, 0 (off) below 8 MB.
	 */
	static long decompileCacheBytes() {
		return size("decompileCache", DecompileCache.defaultBytes(maxHeapBytes()));
	}

	/**
	 * {@code functionTable}: the bytes of function listings kept per program state
	 * ({@link FunctionTable}); default 1/64 of the heap, at most 64 MB, 0 (off) below 1 MB.
	 */
	static long functionTableBytes() {
		return size("functionTable", FunctionTable.defaultBytes(maxHeapBytes()));
	}

	/**
	 * {@code scriptResults}: the bytes of read-script output kept for unchanged programs
	 * ({@link ScriptResults}); default 1/64 of the heap, at most 64 MB, 0 (off) below 4 MB.
	 */
	static long scriptResultBytes() {
		return size("scriptResults", ScriptResults.defaultBytes(maxHeapBytes()));
	}

	static long viewDiskBudgetBytes() {
		return size("viewDiskBudget", 20L << 30);
	}

	/** The reserve of a volume of {@code totalBytes}: {@code diskReserve} or 5%, the larger. */
	static long diskReserveBytes(long totalBytes) {
		long fixed = size("diskReserve", 5L << 30);
		return Settings.has("diskReserve") ? fixed : Math.max(fixed, totalBytes / 20);
	}

	/**
	 * A size setting: digits and an optional unit; a plain number is megabytes.
	 *
	 * @throws IllegalArgumentException naming the key
	 */
	static long size(String key, long dflt) {
		if (!Settings.has(key)) {
			return dflt;
		}
		String v = Settings.string(key, "").trim();
		Matcher m = SIZE.matcher(v);
		if (!m.matches()) {
			throw new IllegalArgumentException("-set " + key + "=" + v +
				": not a size (digits and B, KB, MB, GB or TB; a plain number is megabytes)");
		}
		long n = Long.parseLong(m.group(1));
		String u = m.group(2) == null ? "MB" : m.group(2).toUpperCase(java.util.Locale.ROOT);
		long mul = switch (u) {
			case "B" -> 1L;
			case "KB" -> 1L << 10;
			case "MB" -> 1L << 20;
			case "GB" -> 1L << 30;
			default -> 1L << 40;
		};
		if (n > Long.MAX_VALUE / mul) {
			throw new IllegalArgumentException("-set " + key + "=" + v + ": too large");
		}
		return n * mul;
	}

	/**
	 * Start-up validation: every key parses and makes sense, and {@code -Xmx} is not below
	 * {@code minXmxMb}.
	 *
	 * @throws IllegalArgumentException with a usage message
	 */
	static void validate() {
		int min = minXmxMb();
		int maxViews = maxViews();
		int perClient = maxViewsPerClient();
		int soft = heapSoftPct();
		int hard = heapHardPct();
		if (min < 0) {
			throw new IllegalArgumentException("-set minXmxMb=" + min + ": negative (0 allows any heap)");
		}
		if (maxViews < 1 || perClient < 1) {
			throw new IllegalArgumentException(
				"-set maxViews and maxViewsPerClient must be at least 1");
		}
		if (soft < 10 || hard > 99 || soft >= hard) {
			throw new IllegalArgumentException("-set heapSoftPct=" + soft + " heapHardPct=" + hard +
				": need 10 <= soft < hard <= 99 (percent of -Xmx)");
		}
		if (Settings.has("nativeBudgetMb") && Settings.integer("nativeBudgetMb", 0) < 0) {
			throw new IllegalArgumentException("-set nativeBudgetMb: negative");
		}
		if (decompilerIdleS() < 1 || decompilerWaitS() < 1) {
			throw new IllegalArgumentException(
				"-set decompilerIdleS and decompilerWaitS must be at least 1");
		}
		viewDiskBudgetBytes();
		diskReserveBytes(0);
		// a bad cache size fails the launch, not every later request that uses the cache
		decompileCacheBytes();
		functionTableBytes();
		scriptResultBytes();
		long xmxMb = maxHeapBytes() >> 20;
		// the JVM reports a little less than -Xmx with some collectors; 10% of slack
		if (min > 0 && xmxMb * 10 < (long) min * 9) {
			throw new IllegalArgumentException("the heap is " + xmxMb + " MB (-Xmx); the daemon " +
				"needs at least " + min + " MB (minXmxMb): 128 and 256 MB failed to serve 12 and " +
				"24 views (PROTOCOL-3.md 3.11). Raise -Xmx, or force it with -set minXmxMb=0");
		}
	}

	// ---- estHeap -----------------------------------------------------------------------------------

	/**
	 * What opening a program is expected to cost on the heap, in bytes: the measured delta of the
	 * first open of that program when known, else {@code max(8 MB, 6% of the stored database)}.
	 */
	static long estHeap(String key, long dbBytes) {
		Long learned = key == null ? null : LEARNED.get(key);
		if (learned != null) {
			return learned;
		}
		return Math.max(FLOOR_EST_HEAP, dbBytes <= 0 ? 0 : dbBytes * 6 / 100);
	}

	static boolean learned(String key) {
		return key != null && LEARNED.containsKey(key);
	}

	/** Replaces the estimate by what the first open of {@code key} was seen to cost. */
	static void learn(String key, long deltaBytes) {
		if (key != null && deltaBytes > 0) {
			LEARNED.putIfAbsent(key, Math.max(1L << 20, deltaBytes));
		}
	}

	static int learnedCount() {
		return LEARNED.size();
	}

	/** Forgets what was learned (the self-test). */
	static void clearLearned() {
		LEARNED.clear();
	}
}
