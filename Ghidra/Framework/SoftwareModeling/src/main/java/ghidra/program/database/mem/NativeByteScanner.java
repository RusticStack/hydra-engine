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
package ghidra.program.database.mem;

import static java.lang.foreign.ValueLayout.*;

import java.io.File;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * {@link ByteScanner} backed by the Rust crate {@code hydra_scan} (memchr / aho-corasick SIMD)
 * through FFM. {@link #find} (one chunk of at most 64 KB) is a
 * {@link Linker.Option#critical(boolean) critical} call with heap access, so Java arrays are passed
 * without a copy. {@link #findAll} can scan a whole block, so it is an ordinary downcall (the JVM
 * can reach a safepoint while it runs) on off-heap copies of its arguments.
 * <p>
 * The library is found from, in order: the system property {@code hydra.scan.native.lib} (a
 * file path), then the module's OS directory ({@code os/<platform>/hydra_scan.dll},
 * {@code libhydra_scan.so}, ...) when the Ghidra application is initialized. The system property
 * {@code hydra.scan.native=false} disables it. When it is absent or fails to load,
 * {@link ByteScanner#preferred()} falls back to the Java implementation, with the same results.
 */
public final class NativeByteScanner implements ByteScanner {

	/** ABI version the Java side expects ({@code ABI_VERSION} in lib.rs). */
	static final int ABI_VERSION = 1;

	private static final String LIB = "hydra_scan";

	private static volatile boolean resolved;
	private static NativeByteScanner instance;

	private final MethodHandle find;
	private final MethodHandle findAll;

	private NativeByteScanner(SymbolLookup lookup) throws Throwable {
		Linker linker = Linker.nativeLinker();
		Linker.Option critical = Linker.Option.critical(true);
		MethodHandle version = linker.downcallHandle(
			lookup.find("hydra_scan_abi_version").orElseThrow(), FunctionDescriptor.of(JAVA_INT));
		int v = (int) version.invokeExact();
		if (v != ABI_VERSION) {
			throw new IllegalStateException("hydra_scan ABI " + v + ", expected " + ABI_VERSION);
		}
		find = linker.downcallHandle(lookup.find("hydra_scan_find").orElseThrow(),
			FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS,
				JAVA_LONG, JAVA_INT),
			critical);
		findAll = linker.downcallHandle(lookup.find("hydra_scan_find_all").orElseThrow(),
			FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS,
				JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG));
	}

	/**
	 * Load the scanner from an explicit library file (used by tests and measurements).
	 *
	 * @param library the shared library
	 * @return the scanner
	 * @throws Throwable if it cannot be loaded or has another ABI version
	 */
	public static NativeByteScanner load(Path library) throws Throwable {
		return new NativeByteScanner(SymbolLookup.libraryLookup(library, Arena.global()));
	}

	/**
	 * @return the process-wide native scanner, or null when it is disabled or not available
	 */
	public static NativeByteScanner instance() {
		if (resolved) {
			return instance;
		}
		synchronized (NativeByteScanner.class) {
			if (!resolved) {
				instance = resolve();
				// before Application init the module os/ directory is unknown: decide later
				resolved = instance != null || explicitlyConfigured() ||
					Application.isInitialized();
			}
			return instance;
		}
	}

	/** @return whether the lookup is final (tests) */
	static boolean isResolved() {
		return resolved;
	}

	private static boolean explicitlyConfigured() {
		String path = System.getProperty("hydra.scan.native.lib");
		return (path != null && !path.isBlank()) ||
			"false".equalsIgnoreCase(System.getProperty("hydra.scan.native"));
	}

	private static NativeByteScanner resolve() {
		if ("false".equalsIgnoreCase(System.getProperty("hydra.scan.native"))) {
			return null;
		}
		File file = null;
		String path = System.getProperty("hydra.scan.native.lib");
		if (path != null && !path.isBlank()) {
			file = new File(path);
		}
		else {
			try {
				if (Application.isInitialized()) {
					file = Application.getOSFile(System.mapLibraryName(LIB));
				}
			}
			catch (Exception e) {
				// not shipped with this install: the Java scanner is used
			}
		}
		if (file == null || !file.isFile()) {
			return null;
		}
		try {
			return load(file.toPath());
		}
		catch (Throwable t) {
			Msg.warn(NativeByteScanner.class,
				"Native scanner " + file + " not used (" + t + "); using the Java scanner");
			return null;
		}
	}

	@Override
	public int find(byte[] data, int count, byte[] pattern, byte[] mask, boolean forward) {
		int len = pattern.length;
		if (count <= 0 || len == 0) {
			return -1;
		}
		if (data.length < count + len - 1 || (mask != null && mask.length < len)) {
			throw new IllegalArgumentException("buffer or mask too short");
		}
		MemorySegment maskSeg = mask == null ? MemorySegment.NULL : MemorySegment.ofArray(mask);
		long r;
		try {
			r = (long) find.invokeExact(MemorySegment.ofArray(data), (long) data.length,
				(long) count, MemorySegment.ofArray(pattern), maskSeg, (long) len,
				forward ? 1 : 0);
		}
		catch (Throwable t) {
			throw new IllegalStateException("hydra_scan_find failed", t);
		}
		if (r < -1) {
			throw new IllegalStateException("hydra_scan_find error " + r);
		}
		return (int) r;
	}

	@Override
	public Matches findAll(byte[] data, int dataLen, byte[][] patterns,
			boolean asciiCaseInsensitive) {
		if (patterns.length == 0 || dataLen < 0 || dataLen > data.length) {
			throw new IllegalArgumentException("bad arguments");
		}
		int total = 0;
		int[] lens = new int[patterns.length];
		for (int i = 0; i < patterns.length; i++) {
			if (patterns[i].length == 0) {
				throw new IllegalArgumentException("empty pattern");
			}
			lens[i] = patterns[i].length;
			total += lens[i];
		}
		byte[] concat = new byte[total];
		int at = 0;
		for (byte[] p : patterns) {
			System.arraycopy(p, 0, concat, at, p.length);
			at += p.length;
		}
		long cap = Math.max(1024, dataLen / 64);
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment dataSeg = arena.allocate(Math.max(1, dataLen));
			MemorySegment.copy(data, 0, dataSeg, JAVA_BYTE, 0, dataLen);
			MemorySegment patSeg = arena.allocateFrom(JAVA_BYTE, concat);
			MemorySegment lenSeg = arena.allocateFrom(JAVA_INT, lens);
			while (true) {
				MemorySegment offs = arena.allocate(JAVA_LONG, cap);
				MemorySegment pats = arena.allocate(JAVA_INT, cap);
				long n;
				try {
					n = (long) findAll.invokeExact(dataSeg, (long) dataLen, patSeg,
						(long) concat.length, lenSeg, patterns.length,
						asciiCaseInsensitive ? 1 : 0, offs, pats, cap);
				}
				catch (Throwable t) {
					throw new IllegalStateException("hydra_scan_find_all failed", t);
				}
				if (n < 0) {
					throw new IllegalStateException("hydra_scan_find_all error " + n);
				}
				if (n <= cap) {
					int k = (int) n;
					return new Matches(offs.asSlice(0, k * 8L).toArray(JAVA_LONG),
						pats.asSlice(0, k * 4L).toArray(JAVA_INT));
				}
				if (n > Integer.MAX_VALUE - 8) {
					throw new IllegalStateException("too many matches: " + n);
				}
				cap = n;
			}
		}
	}

	@Override
	public String name() {
		return "native";
	}
}
