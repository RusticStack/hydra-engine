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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Properties;

import ghidra.framework.Application;

/**
 * The identity a client can check before trusting the session: which Hydra Engine release this is,
 * which oldest client library it still serves, and which installation it runs from.
 * <p>
 * The release version is stamped into {@code hydra.properties} (a resource of this module) by the
 * release workflow; a build from the tree says {@code <Ghidra version>-hydra.dev}.
 * <p>
 * The build tool stamps nothing by itself, and Hydralysis classifies an engine that says
 * {@code -hydra.dev} as a stock Ghidra. A build that must be recognised as a release (a candidate
 * that Hydralysis pins, or runs with {@code hydra_allow_unpinned}) is stamped by writing
 * {@code hydra.version=<release>} to {@code src/main/resources/hydra.properties} before
 * {@code gradle zipHeadless} or {@code buildHeadless}, exactly as the release workflow does, and
 * the file is restored afterwards ({@code git checkout -- <that file>}); see "Stamping a local
 * build" in the module README.
 */
final class HydraInfo {

	/**
	 * The oldest {@code ghidra_session.py} (its {@code CLIENT_VERSION}) this session accepts, as
	 * {@code major.minor.patch}. Raised only when the protocol changes in a way an older client
	 * cannot follow. A test can override it with {@code -Dghidra.session.minClient=...}.
	 */
	static final String MIN_CLIENT = "1.0.0";

	/**
	 * The protocol of the endpoint file and of a hello that does not ask for more: the contract a
	 * client that knows nothing newer can use. It is deliberately the lowest protocol served; the
	 * honest statement of what is served is {@link #PROTOCOL_MIN} to {@link #PROTOCOL_MAX}
	 * (PROTOCOL-3.md 3.1).
	 */
	static final int PROTOCOL = 2;
	/** The lowest protocol this engine serves. */
	static final int PROTOCOL_MIN = 2;
	/** The highest protocol this engine serves. */
	static final int PROTOCOL_MAX = 3;

	private HydraInfo() {
	}

	static String minClient() {
		String o = System.getProperty("ghidra.session.minClient");
		return o == null || o.isBlank() ? MIN_CLIENT : o.trim();
	}

	/**
	 * {@code 12.3-hydra.1} for a release, {@code 12.3-hydra.dev} for a build from the tree.
	 * Hydra: the answer cannot change for the life of the JVM (it is a resource of this module),
	 * and {@code info} asks for it on every call: a {@code getResourceAsStream} here walks the
	 * class loader's 139-entry class path and reads the jar directory (measured in the 16-agent
	 * profile: {@code JarFile.getJarEntry} under {@code Session.info}). Computed once.
	 */
	static String hydraVersion() {
		String v = version;
		if (v == null) {
			try (InputStream in = HydraInfo.class.getResourceAsStream("/hydra.properties")) {
				if (in != null) {
					Properties p = new Properties();
					p.load(in);
					v = p.getProperty("hydra.version");
				}
			}
			catch (IOException e) {
				// fall through to the default
			}
			v = v == null || v.isBlank() ? Application.getApplicationVersion() + "-hydra.dev"
					: v.trim();
			version = v;
		}
		return v;
	}

	private static volatile String version;

	/**
	 * A stable id of this installation: the same for every daemon started from it, different for
	 * another directory, Ghidra build or Hydra release. Cached with the version for the same
	 * reason: it hashes a string of facts that do not change while the JVM runs.
	 */
	static String installId() {
		String id = install;
		if (id == null) {
			try {
				MessageDigest d = MessageDigest.getInstance("SHA-256");
				String s = Application.getInstallationDirectory().getAbsolutePath() + "|" +
					Application.getApplicationVersion() + "|" +
					Application.getApplicationReleaseName() + "|" + hydraVersion();
				id = HexFormat.of().formatHex(d.digest(s.getBytes(StandardCharsets.UTF_8)), 0, 8);
			}
			catch (java.security.NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
			install = id;
		}
		return id;
	}

	private static volatile String install;
}
