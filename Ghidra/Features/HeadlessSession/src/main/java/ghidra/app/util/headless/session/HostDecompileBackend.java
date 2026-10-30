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

import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Hydra: the optional in-process decompile backend (plan rank 12, step 5 of
 * {@code Ghidra/Features/Decompiler/rust/crates/hydra-decomp-host/DESIGN.md}). With
 * {@code -Dhydra.decomp.backend=host} (default {@code process}) a decompile request is first offered
 * to the Rust host (N C++ Architectures on a worker pool, reading the program's sealed snapshot and
 * data the Java side exports once per generation, never per-call upcalls). Any case the host does
 * not cover returns {@code null} here and the caller takes the existing {@code DecompInterface}
 * path, so replies stay byte-for-byte what clients get today.
 *
 * <p>Coverage today: the sealed snapshot ({@code ProgramSnapshotFile}, format v1) holds the
 * program's bytes only. A host decompile also needs the symbol scope, data types, function
 * prototypes, comments, context registers, cpool and inject payloads, none of which is exported per
 * generation yet, and the host has no {@code SnapshotArchitecture}; it reads DecompileDebug dumps
 * only. Every request therefore falls back. The seam, the flag, the fallback count and the
 * identity gate (flag on vs off) are in place so the provider can be filled in section by section.
 */
final class HostDecompileBackend {

	/** {@code host} turns the backend on; anything else (the default {@code process}) keeps it off. */
	static final String PROPERTY = "hydra.decomp.backend";

	private static final AtomicLong HOSTED = new AtomicLong();
	private static final AtomicLong FALLBACKS = new AtomicLong();

	private HostDecompileBackend() {
	}

	static boolean enabled() {
		return "host".equals(System.getProperty(PROPERTY, "process"));
	}

	/**
	 * Why the host cannot decompile {@code f} of {@code prog}, or {@code null} when it can. The
	 * reasons name the first missing piece, in the order DESIGN.md wires them.
	 */
	static String unsupportedReason(Program prog, Function f) {
		if (f.isExternal() || f.isThunk()) {
			return "external or thunk function";
		}
		// snapshot v1: bytes only; scope, types, prototypes, comments, context, cpool and inject
		// payloads are not exported per generation, and there is no SnapshotArchitecture yet
		return "snapshot v1 covers bytes only (no symbol/type/prototype export)";
	}

	/**
	 * The reply for a decompile of {@code f}, in the same format as the process path, or
	 * {@code null} to take the process path (backend off, or a case the host does not cover).
	 */
	static JsonObject tryDecompile(Program prog, Function f, int timeoutS, int cap) {
		if (!enabled()) {
			return null;
		}
		String reason = unsupportedReason(prog, f);
		if (reason != null) {
			if (FALLBACKS.incrementAndGet() == 1) {
				Msg.info(HostDecompileBackend.class,
					"decompile backend host: falling back to the process path (" + reason + ")");
			}
			return null;
		}
		HOSTED.incrementAndGet();
		return null; // unreachable until a provider reports support
	}

	/** Requests answered by the host since start (for the gate and tests). */
	static long hostedCount() {
		return HOSTED.get();
	}

	/** Requests the backend, while on, handed to the process path. */
	static long fallbackCount() {
		return FALLBACKS.get();
	}
}
