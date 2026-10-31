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
 * <p>Offered for a pool bound to the decompiled program, with the set-up
 * {@code ProgramEntry.newDecompiler} gives every session decompiler: a program's own decompilers
 * ({@link ProgramEntry}) and an overlay's ({@link Overlay}, whose decompilers are built by the same
 * {@code newDecompiler} on the overlay's own program object). The host's answers come from the
 * program object the decompile names, so an overlay decompile sees the overlay's names and
 * comments. Anything else takes the process path.
 */
final class HostDecompileBackend {

	/**
	 * {@code process} keeps the backend off; anything else (the default {@code host}) uses it.
	 * rust/t-host measured it as the default (KotOR 8,616 identical) and kept it opt-in for a
	 * slower cold path; rust/o2-decomp removed that cost (the syntax tree is no longer encoded and
	 * decoded, answers are exported in bulk and the store is sharded) and made the host the default:
	 * a hosted decompile no longer starts a native process and is faster than the process path on
	 * both the first call and the repeats.
	 */
	static final String PROPERTY = "hydra.decomp.backend";

	/**
	 * The host registers a program as {@code DecompInterface} does with its defaults (no setAction):
	 * only the set-up {@code ProgramEntry.newDecompiler} uses today is offered. The host sends
	 * {@code notree} exactly as the pooled decompilers do (they are text-only since H5; their one
	 * consumer reads the C text and signature, printed from the C markup alone), so the host's
	 * registration gives the same C markup and the same bytes as the process path.
	 */
	static final boolean SETUP_MATCHES = ProgramEntry.DECOMPILER_C_CODE &&
		"decompile".equals(ProgramEntry.DECOMPILER_STYLE);

	private static final AtomicLong HOSTED = new AtomicLong();
	private static final AtomicLong FALLBACKS = new AtomicLong();
	private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

	private HostDecompileBackend() {
	}

	static boolean enabled() {
		return !"process".equals(System.getProperty(PROPERTY, "host"));
	}

	/**
	 * Why the host cannot be offered {@code f} decompiled by {@code e}, or {@code null} when it can.
	 */
	static String unsupportedReason(Program prog, Decompilers e, Function f) {
		if (!(e instanceof ProgramEntry) && !(e instanceof Overlay)) {
			return "not a session decompiler (overlay or other view)";
		}
		if (e.program() != prog) {
			return "the decompilers are bound to another program object";
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
			Program source = e instanceof Overlay o ? o.snapshotSource() : prog;
			HostDecompiler.Outcome o =
				HostDecompiler.decompile(prog, source == null ? prog : source, f, timeoutS);
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

	/**
	 * Starts the host's set-up for {@code prog} on a background thread, so the first decompile of
	 * the program (or of an overlay over it) does not pay it: the store, the specs, the byte
	 * snapshot and the registration answers. Called when a program or an overlay is opened and
	 * after an overlay changes; a no-op when the backend is off or the program cannot be hosted.
	 * @param prog the program
	 */
	static void warm(Program prog) {
		warm(prog, prog);
	}

	/**
	 * As {@link #warm(Program)}, with the byte snapshot taken from {@code snapshotSource} (an
	 * overlay's memory is its base program's while the overlay only carries annotations).
	 */
	static void warm(Program prog, Program snapshotSource) {
		if (enabled() && SETUP_MATCHES) {
			HostDecompiler.warm(prog, snapshotSource == null ? prog : snapshotSource);
		}
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
