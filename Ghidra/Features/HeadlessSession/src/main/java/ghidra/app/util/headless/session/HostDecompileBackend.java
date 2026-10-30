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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Hydra: the optional in-process decompile backend (plan rank 12, steps 5 and 6 of
 * {@code Ghidra/Features/Decompiler/rust/crates/hydra-decomp-host/DESIGN.md}). With
 * {@code -Dhydra.decomp.backend=host} (default {@code process}) a decompile request is first offered
 * to {@link HostDecompiler}: the Rust host's worker pool runs the stock C++ {@code
 * ArchitectureGhidra} over a {@code SnapshotArchitecture} channel, answered from the answers the
 * Java side exports once per program generation ({@link DecompileSnapshot}), with no Java callback
 * during the decompile. Any case the host does not cover returns {@code null} here and the caller
 * takes the existing {@code DecompInterface} path, so replies stay byte-for-byte what clients get
 * today.
 *
 * <p>Only decompiles of a {@link ProgramEntry} (the program's own decompilers, set up by
 * {@code ProgramEntry.newDecompiler}: options from the program, the default action, C code and
 * syntax tree on) are offered; overlays and anything else take the process path.
 */
final class HostDecompileBackend {

	/**
	 * {@code host} turns the backend on; anything else (the default {@code process}) keeps it off.
	 * rust/t-host measured it as the default (KotOR 8,616 identical) and kept it opt-in: on the
	 * multi-agent benchmark a cold host decompile (export + native runs) is slower than the process
	 * path and the in-process Architectures raise peak memory (DESIGN.md, "t-host").
	 */
	static final String PROPERTY = "hydra.decomp.backend";

	/**
	 * The host registers a program as {@code DecompInterface} does with its defaults (no setAction):
	 * only the set-up {@code ProgramEntry.newDecompiler} uses today is offered. The syntax tree
	 * toggle is not part of the match: the pooled decompilers are text-only since H5 (their one
	 * consumer reads the C text and signature, printed from the C markup alone), and the host's
	 * registration (syntax tree on) gives the same C markup plus a tree nobody on this path reads.
	 */
	static final boolean SETUP_MATCHES = ProgramEntry.DECOMPILER_C_CODE &&
		"decompile".equals(ProgramEntry.DECOMPILER_STYLE);

	private static final AtomicLong HOSTED = new AtomicLong();
	private static final AtomicLong FALLBACKS = new AtomicLong();
	private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

	private HostDecompileBackend() {
	}

	static boolean enabled() {
		return "host".equals(System.getProperty(PROPERTY, "process"));
	}

	/**
	 * Why the host cannot be offered {@code f} decompiled by {@code e}, or {@code null} when it can.
	 */
	static String unsupportedReason(Program prog, Decompilers e, Function f) {
		if (!(e instanceof ProgramEntry pe) || pe.program != prog) {
			return "not a program entry's decompiler (overlay or other view)";
		}
		if (!SETUP_MATCHES) {
			return "decompiler set-up differs from the registration the host makes";
		}
		return DecompileSnapshot.hostable(f);
	}

	/**
	 * The results of a host decompile of {@code f}, the same as the process path returns for it, or
	 * {@code null} to take the process path (backend off, a case the host does not cover, or a
	 * host run that did not complete).
	 */
	static DecompileResults tryDecompile(Program prog, Decompilers e, Function f, int timeoutS) {
		if (!enabled()) {
			return null;
		}
		String reason = unsupportedReason(prog, e, f);
		if (reason == null) {
			// the options every ProgramEntry decompiler is opened with (newDecompiler)
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(prog);
			HostDecompiler.Outcome o = HostDecompiler.decompile(prog, f, options, timeoutS);
			if (o.results() != null) {
				HOSTED.incrementAndGet();
				return o.results();
			}
			reason = o.fallback();
		}
		FALLBACKS.incrementAndGet();
		String kind = reason.replaceAll("0x[0-9a-fA-F]+|\\b[0-9a-fA-F]{6,}\\b", "#");
		if (kind.length() > 120) {
			kind = kind.substring(0, 120);
		}
		if (LOGGED.size() < 64 && LOGGED.add(kind)) {
			Msg.info(HostDecompileBackend.class, "decompile backend host: falling back to the " +
				"process path for " + f.getName(true) + " (" + reason + ")");
		}
		return null;
	}

	/** Requests answered by the host since start (for the gate and tests). */
	static long hostedCount() {
		return HOSTED.get();
	}

	/** Requests the backend, while on, handed to the process path. */
	static long fallbackCount() {
		return FALLBACKS.get();
	}

	/** {@code status.decompileBackend} while the backend is on: the counts and the host's figures. */
	static JsonObject describe() {
		JsonObject o = Json.of("backend", "host", "hostedCount", HOSTED.get(), "fallbackCount",
			FALLBACKS.get());
		Map<String, Object> s = HostDecompiler.stats();
		o.add("host", new Gson().toJsonTree(s));
		return o;
	}
}
