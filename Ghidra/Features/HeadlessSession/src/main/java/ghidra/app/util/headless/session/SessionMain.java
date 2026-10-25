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

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLauncher;

/**
 * Entry point for a session JVM started with Ghidra's whole classpath on {@code -cp} and the
 * JVM's default application class loader (the Python launcher's {@code fast} mode).
 * <p>
 * {@code ghidra.Ghidra} needs {@link GhidraClassLoader} as the system class loader, because it
 * adds the module jars to the classpath at run time. A loader set with
 * {@code -Djava.system.class.loader} turns off the JVM's class data sharing for every class it
 * loads, which is why {@code launch.properties} passes {@code -Xshare:off}. With the classpath
 * given up front, no custom loader is needed, and an AOT cache ({@code -XX:AOTCache}) can hold
 * Ghidra's classes as well as the JDK's. Everything Ghidra reads from the classpath
 * ({@code java.class.path}: the class searcher, script compilation, the OSGi host) sees the same
 * entries either way.
 * <p>
 * Started the standard way (with {@link GhidraClassLoader}), it defers to {@link GhidraLauncher}.
 */
public final class SessionMain {

	private SessionMain() {
	}

	public static void main(String[] args) throws Exception {
		if (ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader) {
			String[] all = new String[args.length + 1];
			all[0] = HeadlessSession.class.getName();
			System.arraycopy(args, 0, all, 1, args.length);
			GhidraLauncher.launch(all);
			return;
		}
		new HeadlessSession().launch(new GhidraApplicationLayout(), args);
	}
}
