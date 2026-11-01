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

import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.regex.*;

import org.junit.Assume;
import org.junit.Test;

import ghidra.util.task.TaskMonitor;

/**
 * The Rust class scan (ClassScan) against the Java scan it replaces, on the jars this test can
 * reach: the build's own classpath.
 * <p>
 * The point is the answer, not the speed: for every jar, the classes the Java rule finds
 * ({@link ClassSearcher#getExtensionPointSuffix} on every entry, as {@link ClassJar} does) must be
 * exactly the classes the native scan reports, with the same suffix. The Java rule is rebuilt here
 * from the same suffix list because a unit test of this module has no {@code Application} to read
 * the modules' {@code ExtensionPoint.manifest} files from.
 */
public class ClassScanTest {

	/** Stands in for the install's manifests when the test JVM has no Application. */
	private static final List<String> TEST_SUFFIXES =
		List.of("Plugin", "Analyzer", "Loader", "Provider", "Factory", "Exporter");

	/** The jars of the running classpath that exist on disk. */
	private static List<File> classpathJars() {
		List<File> jars = new ArrayList<>();
		for (String entry : System.getProperty("java.class.path", "").split(File.pathSeparator)) {
			if (entry.isEmpty()) {
				continue;
			}
			File f = new File(entry);
			if (f.isFile() && (entry.endsWith(".jar") || entry.endsWith(".zip"))) {
				jars.add(f.getAbsoluteFile());
			}
		}
		return jars;
	}

	/** The suffix list the scan is asked about: the build's when it can be read, else a fixed one. */
	private static List<String> suffixes() {
		try {
			List<String> real = ClassSearcher.extensionPointSuffixes();
			if (!real.isEmpty() && ClassScan.allLiterals(real)) {
				return real;
			}
		}
		catch (Throwable t) {
			// no Application in this test JVM: use the stand-in list
		}
		return TEST_SUFFIXES;
	}

	/**
	 * The Java scan of one jar, as {@link ClassJar#processClassFiles} does it: every entry that
	 * ends in {@code .class}, cut at the first {@code .class}, and the suffix
	 * {@link ClassSearcher#getExtensionPointSuffix} gives it.
	 */
	private static List<String[]> javaScan(File jar, List<String> suffixes) throws IOException {
		Pattern pattern = pattern(suffixes);
		List<String[]> list = new ArrayList<>();
		try (JarFile jarFile = new JarFile(jar)) {
			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				String name = entries.nextElement().getName();
				if (!name.endsWith(".class")) {
					continue;
				}
				name = name.substring(0, name.indexOf(".class"));
				name = name.replace('/', '.');
				String suffix = suffixOf(pattern, name);
				if (suffix != null) {
					list.add(new String[] { name, suffix });
				}
			}
		}
		return list;
	}

	/** {@code .*(a|b|c)$}, built as {@link ClassSearcher} builds it. */
	private static Pattern pattern(List<String> suffixes) {
		return Pattern.compile(".*(" + String.join("|", suffixes) + ")$");
	}

	/** The rules of {@link ClassSearcher#getExtensionPointSuffix}, on a class name. */
	private static String suffixOf(Pattern pattern, String className) {
		if (className.contains("$") || className.endsWith("Test")) {
			return null;
		}
		int packageIndex = className.lastIndexOf('.');
		if (packageIndex > 0) {
			className = className.substring(packageIndex + 1);
		}
		Matcher m = pattern.matcher(className);
		return m.find() && m.groupCount() == 1 ? m.group(1) : null;
	}

	@Test
	public void nativeScanAgreesWithTheJavaScanOnEveryClasspathJar() throws Exception {
		Assume.assumeNotNull("hydra_native is not available", ClassScan.get());
		List<File> jars = classpathJars();
		Assume.assumeTrue("no jars on the classpath", !jars.isEmpty());
		List<String> suffixes = suffixes();
		assertFalse("no suffix to scan for", suffixes.isEmpty());
		assertTrue("the suffixes are not literals", ClassScan.allLiterals(suffixes));

		List<String[]> nativeRecords =
			ClassScan.scanFiles(jars.toArray(new File[0]), suffixes, TaskMonitor.DUMMY);
		assertNotNull("the native scan fell back", nativeRecords);

		// the native records, by jar
		List<List<String[]>> byJar = new ArrayList<>();
		for (int i = 0; i < jars.size(); i++) {
			byJar.add(new ArrayList<>());
		}
		for (String[] r : nativeRecords) {
			int index = jars.indexOf(new File(r[0]));
			assertTrue("record for a jar that was not asked for: " + r[0], index >= 0);
			byJar.get(index).add(new String[] { r[1], r[2] });
		}
		int total = 0;
		for (int i = 0; i < jars.size(); i++) {
			List<String[]> java = javaScan(jars.get(i), suffixes);
			assertEquals("jar " + jars.get(i).getName() + ": different classes",
				names(java), names(byJar.get(i)));
			total += java.size();
		}
		assertTrue("the build found no extension point at all", total > 0);
	}

	@Test
	public void aSuffixWithRegexCharactersIsNotTreatedAsALiteral() {
		assertTrue(ClassScan.allLiterals(List.of("Plugin", "Analyzer")));
		assertFalse(ClassScan.allLiterals(List.of(".*Plugin")));
		assertFalse(ClassScan.allLiterals(List.of("Foo|Bar")));
		assertFalse(ClassScan.allLiterals(List.of("")));
	}

	@Test
	public void anUnreadableJarFallsBackToJava() throws Exception {
		Assume.assumeNotNull("hydra_native is not available", ClassScan.get());
		Path broken = Files.createTempFile("ghidra-classscan-", ".jar");
		try {
			Files.writeString(broken, "not a zip", StandardCharsets.UTF_8);
			List<String[]> records = ClassScan.scanFiles(new File[] { broken.toFile() },
				List.of("Plugin"), TaskMonitor.DUMMY);
			assertNull("a jar the native scan cannot read must fall back", records);
		}
		finally {
			Files.deleteIfExists(broken);
		}
	}

	private static List<String> names(List<String[]> records) {
		List<String> names = new ArrayList<>(records.size());
		for (String[] r : records) {
			names.add(r[0] + "|" + r[1]);
		}
		Collections.sort(names);
		return names;
	}
}
