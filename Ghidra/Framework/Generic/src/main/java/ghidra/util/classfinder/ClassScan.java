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
package ghidra.util.classfinder;

import java.io.File;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The Rust extension-point class scan ({@code hydra_cs_*} in {@code hydra_native}): which classes
 * in the classpath's jars are extension points, answered by reading the jars' central directories
 * and matching the suffixes in Rust.
 * <p>
 * {@link ClassSearcher#findClasses} asks every class name whether it ends with one of the
 * extension-point suffixes. The Java scan does that with one 76-alternative regular expression
 * ({@code .*(A|B|...)$}) per class name through a backtracking matcher: measured on a full install
 * 34.8 us per name, 1143 ms for the 32 820 names, against 0.7 us with a suffix test. This class
 * also skips the {@code JarFile} per jar (the central directory is read once, no inflation).
 * <p>
 * The scan is optional, exactly like the read plane: when the library is missing, has another
 * ABI, cannot read a jar, finds an entry name that is not UTF-8, or is given a suffix that is a
 * regular expression rather than a literal (the shortest-match equivalence below is only proven
 * for literals), {@link #scanJars} returns {@code null} and the Java scan answers as before.
 * {@code -Dhydra.classScan=false} turns it off.
 * <p>
 * <b>Same answers as the Java scan</b> ({@link ClassJar#getClasses}): entries in central-directory
 * order, names ending in {@code .class}, the class name cut at the first {@code .class} and
 * {@code /} replaced by {@code .}, names with {@code $} or ending in {@code Test} skipped, and the
 * shortest suffix that the simple name ends with (the Java regex backtracks {@code .*} from the
 * longest, so the shortest remainder is tried first).
 */
final class ClassScan {

	/** The {@code hydra_cs_abi_version} this caller understands. */
	static final int ABI = 1;
	/** {@code -Dhydra.classScan=false} keeps the scan on the Java path. */
	static final String PROPERTY = "hydra.classScan";

	private static final Linker LINKER = Linker.nativeLinker();
	/** ASCII-only characters a suffix may not hold and still be treated as a literal. */
	private static final String REGEX_METACHARS = "\\^$.|?*+()[]{}";

	private final MethodHandle scan;
	private final MethodHandle len;
	private final MethodHandle copy;
	private final MethodHandle free;
	final String library;

	private static boolean looked;
	private static ClassScan instance;

	private ClassScan(SymbolLookup l, String library) {
		this.library = library;
		scan = LINKER.downcallHandle(l.findOrThrow("hydra_cs_scan"),
			FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
				ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
		len = LINKER.downcallHandle(l.findOrThrow("hydra_cs_len"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		copy = LINKER.downcallHandle(l.findOrThrow("hydra_cs_copy"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG));
		free = LINKER.downcallHandle(l.findOrThrow("hydra_cs_free"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
	}

	/** The scanner, or null when it is off or unavailable (looked up once). */
	static ClassScan get() {
		if (looked) {
			return instance;
		}
		synchronized (ClassScan.class) {
			if (!looked) {
				instance = load();
				looked = true;
			}
		}
		return instance;
	}

	private static ClassScan load() {
		if ("false".equalsIgnoreCase(System.getProperty(PROPERTY, "true").trim())) {
			return null;
		}
		Path lib = findLibrary();
		if (lib == null) {
			return null;
		}
		try {
			SymbolLookup l = SymbolLookup.libraryLookup(lib, Arena.global());
			MethodHandle abi = LINKER.downcallHandle(l.findOrThrow("hydra_cs_abi_version"),
				FunctionDescriptor.of(ValueLayout.JAVA_INT));
			int v = (int) abi.invokeExact();
			if (v != ABI) {
				Msg.warn(ClassScan.class, "class scan off: " + lib + " has ABI " + v + ", not " + ABI);
				return null;
			}
			return new ClassScan(l, lib.toString());
		}
		catch (Throwable t) {
			Msg.warn(ClassScan.class, "class scan off: " + lib + ": " + t);
			return null;
		}
	}

	private static Path findLibrary() {
		String explicit = System.getProperty("hydra.native.library");
		if (explicit != null && !explicit.isBlank()) {
			Path p = Path.of(explicit);
			return Files.isRegularFile(p) ? p : null;
		}
		String name = System.mapLibraryName("hydra_native");
		try {
			File f = Application.getOSFile("HydraNative", name);
			if (f != null && f.isFile()) {
				return f.toPath();
			}
		}
		catch (Throwable t) {
			// no application (a unit test): look next to this jar below
		}
		try {
			// <install>/Ghidra/Framework/Generic/lib/Generic.jar
			Path jar = Path.of(ClassScan.class.getProtectionDomain().getCodeSource().getLocation()
					.toURI());
			Path ghidra = jar.getParent().getParent().getParent().getParent();
			for (String platform : new String[] { "win_x86_64", "linux_x86_64", "mac_arm_64",
				"linux_arm_64", "mac_x86_64" }) {
				Path p = ghidra.resolve("Framework/HydraNative/os/" + platform + "/" + name);
				if (Files.isRegularFile(p)) {
					return p;
				}
			}
		}
		catch (Throwable t) {
			// not run from an install
		}
		return null;
	}

	/**
	 * The extension-point classes of {@code jars}, in jar order and central-directory order, or
	 * {@code null} when the scan must stay on the Java path.
	 * <p>
	 * {@code suffixes} are the extension-point suffixes of the install; every one must be a
	 * literal (no regular-expression metacharacter) for the shortest-suffix rule to be the same as
	 * the Java pattern's.
	 */
	static List<ClassFileInfo> scanJars(List<ClassJar> jars, TaskMonitor monitor,
			List<String> suffixes) throws CancelledException {
		if (jars.isEmpty()) {
			return null;
		}
		File[] files = new File[jars.size()];
		for (int i = 0; i < files.length; i++) {
			files[i] = jars.get(i).getFile();
		}
		List<String[]> records = scanFiles(files, suffixes, monitor);
		if (records == null) {
			return null;
		}
		Map<String, String> modules = new HashMap<>();
		for (ClassJar jar : jars) {
			modules.put(jar.getFile().getAbsolutePath(), jar.getModulePath());
		}
		List<ClassFileInfo> list = new ArrayList<>(records.size());
		for (String[] r : records) {
			list.add(new ClassFileInfo(r[0], r[1], r[2], modules.getOrDefault(r[0], "")));
		}
		return list;
	}

	/**
	 * The extension-point classes of {@code jars} as {@code {path, name, suffix}} records in jar
	 * order and central-directory order, or {@code null} when the scan must stay on the Java path.
	 */
	static List<String[]> scanFiles(File[] jars, List<String> suffixes, TaskMonitor monitor)
			throws CancelledException {
		ClassScan cs = get();
		if (cs == null || jars.length == 0 || !allLiterals(suffixes)) {
			return null;
		}
		monitor.checkCancelled();
		StringBuilder paths = new StringBuilder();
		for (File jar : jars) {
			paths.append(jar.getAbsolutePath()).append('\0');
		}
		StringBuilder sufs = new StringBuilder();
		for (String s : suffixes) {
			sufs.append(s).append('\0');
		}
		try (Arena arena = Arena.ofConfined()) {
			byte[] pathBytes = paths.toString().getBytes(StandardCharsets.UTF_8);
			byte[] suffixBytes = sufs.toString().getBytes(StandardCharsets.UTF_8);
			MemorySegment p = arena.allocate(pathBytes.length);
			MemorySegment.copy(pathBytes, 0, p, ValueLayout.JAVA_BYTE, 0, pathBytes.length);
			MemorySegment s = arena.allocate(suffixBytes.length);
			MemorySegment.copy(suffixBytes, 0, s, ValueLayout.JAVA_BYTE, 0, suffixBytes.length);
			MemorySegment result = (MemorySegment) cs.scan.invokeExact(p, (long) pathBytes.length, s,
				(long) suffixBytes.length);
			if (result.equals(MemorySegment.NULL)) {
				return null; // a jar or an entry name the native scan cannot reproduce: Java answers
			}
			try {
				long n = (long) cs.len.invokeExact(result);
				MemorySegment out = arena.allocate(Math.max(n, 1L));
				long copied = (long) cs.copy.invokeExact(result, out, n);
				if (copied != n) {
					return null;
				}
				List<String[]> list = decode(out, n, jars);
				monitor.checkCancelled();
				return list;
			}
			finally {
				cs.free.invokeExact(result);
			}
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.warn(ClassScan.class, "class scan fallback: " + t);
			return null;
		}
	}

	/** Whether every suffix is a literal, so the shortest-suffix rule equals the Java pattern's. */
	static boolean allLiterals(List<String> suffixes) {
		for (String s : suffixes) {
			if (s.isEmpty()) {
				return false;
			}
			for (int i = 0; i < s.length(); i++) {
				if (REGEX_METACHARS.indexOf(s.charAt(i)) >= 0) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Records: {@code jar u32 | name_len u32 | suffix_len u32 | name | suffix}, little endian, in
	 * {@code n} bytes of {@code out}.
	 */
	private static List<String[]> decode(MemorySegment out, long n, File[] jars) {
		List<String[]> list = new ArrayList<>();
		long at = 0;
		while (at + 12 <= n) {
			int jar = out.get(ValueLayout.JAVA_INT_UNALIGNED, at);
			int nameLen = out.get(ValueLayout.JAVA_INT_UNALIGNED, at + 4);
			int suffixLen = out.get(ValueLayout.JAVA_INT_UNALIGNED, at + 8);
			if (jar < 0 || jar >= jars.length || nameLen < 0 || suffixLen < 0 ||
				at + 12 + nameLen + suffixLen > n) {
				throw new IllegalStateException("class scan reply out of bounds");
			}
			byte[] name = new byte[nameLen];
			MemorySegment.copy(out, ValueLayout.JAVA_BYTE, at + 12, name, 0, nameLen);
			byte[] suffix = new byte[suffixLen];
			MemorySegment.copy(out, ValueLayout.JAVA_BYTE, at + 12 + nameLen, suffix, 0, suffixLen);
			list.add(new String[] { jars[jar].getAbsolutePath(),
				new String(name, StandardCharsets.UTF_8),
				new String(suffix, StandardCharsets.UTF_8) });
			at += 12L + nameLen + suffixLen;
		}
		return list;
	}
}
