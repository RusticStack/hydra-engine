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

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.util.Msg;

/**
 * The daemon's own Job Object (PROTOCOL-3.md 3.11, D60, package E9).
 * <p>
 * {@link #install} is the first statement of {@code HeadlessSession.launch}: the daemon creates an
 * <b>anonymous</b> job with {@code JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE} and assigns itself to it
 * (through {@code java.lang.foreign}). Every process it starts afterwards (the native decompilers,
 * a script worker) inherits the job, and the operating system closes the daemon's only handle on
 * the job when the daemon dies, however it dies, which kills them: no orphan decompiler, K7. The
 * launcher owns no job. Whether the daemon outlives its harness is the launch sequence of D65, not
 * this class.
 * <p>
 * Rules measured by SP3 and kept here: the job has no name (a named job can be opened by any
 * process of the user, and kill-on-close fires only when the last handle closes); its handle is
 * never closed, duplicated or inherited; the "before" facts ({@code inCallerJob},
 * {@code callerKillOnClose}) are read before the assignment; the first use of this class sits in a
 * {@code try/catch Throwable} (denied native access fails in the static initializer as an
 * {@link ExceptionInInitializerError}, not as a clean return, F2); {@code invokeExact} gets typed
 * locals, never an inline conditional (F3).
 * <p>
 * When the job cannot be made ({@code health.processJob.state} is {@code unavailable}) the fallback
 * is the <b>orphan sweep</b> ({@link #sweep}): a {@code decompile} process whose image is under
 * <i>this install's</i> {@code Ghidra/Features/Decompiler/os/} folder and whose parent no longer
 * exists is killed. Another install's decompiler is never touched.
 * <p>
 * <b>Test control.</b> {@code -Dghidra.session.noProcessJob=true} skips the job (and the sweep), but
 * only together with {@code -Dghidra.session.testHooks=true} (two launch properties, never a
 * setting): the K7 test needs a daemon without the job to show that its decompilers survive.
 * {@code =sweep} reports the job as unavailable and runs the fallback sweep, to test that path.
 */
final class ProcessJob {

	/** The JVM launch property of the no-job control; honoured only with the test hooks on. */
	static final String DISABLE_PROPERTY = "ghidra.session.noProcessJob";

	private static final int JOB_OBJECT_BASIC_LIMIT_INFORMATION = 2;
	private static final int JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3;
	private static final int JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
	private static final int LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
	/** {@code sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)} on x64. */
	private static final long EXT_SIZE = 144;
	/** Offset of {@code BasicLimitInformation.LimitFlags}. */
	private static final long LIMIT_FLAGS_OFF = 16;

	/** What {@link #install} found and did; immutable. */
	record Result(String state, boolean own, boolean inCallerJob, Boolean callerKillOnClose,
			Integer callerLimitFlags, int errCreate, int errSet, int errAssign, String error) {

		static Result of(String state, String error) {
			return new Result(state, false, false, null, null, 0, 0, 0, error);
		}
	}

	private static volatile Result result = Result.of("not_started", null);
	/** What the sweep killed or found, set at most once. */
	private static volatile JsonObject sweepReport;
	/** The daemon's own job; never closed (the OS closes it when the process dies). */
	private static volatile MemorySegment job = MemorySegment.NULL;

	private ProcessJob() {
		// static
	}

	/** True when this launch asked for the no-job control and the test hooks allow it. */
	static boolean disabledForTest() {
		return mode().equals("true");
	}

	/** The no-job control: {@code true} (no job, no sweep) or {@code sweep} (the job "fails" and the sweep runs). */
	private static String mode() {
		return Health.testHooks() ? System.getProperty(DISABLE_PROPERTY, "") : "";
	}

	static Result result() {
		return result;
	}

	/**
	 * First statement of {@code HeadlessSession.launch}. Never throws. Windows only; on another
	 * system the state is {@code unsupported}.
	 *
	 * @param installDir this install's root, for the sweep of the fallback
	 */
	static synchronized Result start(Path installDir) {
		if (disabledForTest()) {
			result = Result.of("disabled", "-D" + DISABLE_PROPERTY + " with the test hooks");
			Msg.warn(ProcessJob.class, "the daemon's own job object is OFF (test control)");
			return result;
		}
		if (mode().equals("sweep")) {
			result = Result.of("unavailable", "simulated by -D" + DISABLE_PROPERTY + "=sweep (test hooks)");
			sweepReport = sweep(installDir, true);
			return result;
		}
		if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")) {
			result = Result.of("unsupported", "not Windows");
			return result;
		}
		Result r;
		try {
			r = Native.install();
		}
		catch (Throwable t) { // ExceptionInInitializerError, UnsatisfiedLinkError, security...
			Throwable cause = t.getCause() != null ? t.getCause() : t;
			r = Result.of("unavailable", cause.getClass().getName() + ": " + cause.getMessage());
		}
		result = r;
		if (r.own()) {
			Msg.info(ProcessJob.class, "the daemon's own job object is in place (kill on close)");
		}
		else {
			Msg.warn(ProcessJob.class,
				"the daemon's own job object is unavailable (" + r.error() + "); sweeping orphan " +
					"decompilers of this install instead");
			sweepReport = sweep(installDir, true);
		}
		return r;
	}

	// ---- the fallback: the orphan sweep ----------------------------------------------------------

	/**
	 * Finds (and when {@code kill} kills) the decompiler processes that belong to <i>this install</i>
	 * and have no parent: the image path is under {@code <install>/Ghidra/Features/Decompiler/os/}
	 * and the parent is gone (or its pid was reused: the parent started after the child).
	 *
	 * @return {@code {checked, orphans:[{pid, image}], killed:[pid]}}
	 */
	static JsonObject sweep(Path installDir, boolean kill) {
		JsonObject o = new JsonObject();
		JsonArray orphans = new JsonArray();
		JsonArray killed = new JsonArray();
		int checked = 0;
		try {
			Path root = installDir.resolve("Ghidra").resolve("Features").resolve("Decompiler")
					.resolve("os").toAbsolutePath().normalize();
			String prefix = root.toString().toLowerCase(Locale.ROOT) + java.io.File.separator;
			for (ProcessHandle ph : (Iterable<ProcessHandle>) ProcessHandle.allProcesses()::iterator) {
				Optional<String> cmd = ph.info().command();
				if (cmd.isEmpty()) {
					continue;
				}
				Path image = Path.of(cmd.get()).toAbsolutePath().normalize();
				String name = image.getFileName() == null ? "" : image.getFileName().toString();
				if (!name.toLowerCase(Locale.ROOT).startsWith("decompile") ||
					!image.toString().toLowerCase(Locale.ROOT).startsWith(prefix)) {
					continue;
				}
				checked++;
				if (!parentGone(ph)) {
					continue;
				}
				orphans.add(Json.of("pid", ph.pid(), "image", image.toString()));
				if (kill && ph.destroyForcibly()) {
					killed.add(ph.pid());
				}
			}
		}
		catch (RuntimeException e) {
			Json.put(o, "error", String.valueOf(e));
		}
		o.addProperty("checked", checked);
		o.add("orphans", orphans);
		o.add("killed", killed);
		return o;
	}

	/** The parent does not exist any more, or its pid belongs to a process started after the child. */
	private static boolean parentGone(ProcessHandle child) {
		Optional<ProcessHandle> parent = child.parent();
		if (parent.isEmpty() || !parent.get().isAlive()) {
			return true;
		}
		Optional<Instant> pt = parent.get().info().startInstant();
		Optional<Instant> ct = child.info().startInstant();
		return pt.isPresent() && ct.isPresent() && pt.get().isAfter(ct.get());
	}

	// ---- health ----------------------------------------------------------------------------------

	/**
	 * {@code health.processJob}: {@code state} ({@code own}, {@code unavailable}, {@code disabled},
	 * {@code unsupported}), {@code own}, the facts read before the assignment, the pids in the job
	 * and, after a fallback, what the sweep found.
	 */
	static JsonElement describe() {
		Result r = result;
		JsonObject o = new JsonObject();
		o.addProperty("state", r.state());
		o.addProperty("own", r.own());
		o.addProperty("inCallerJob", r.inCallerJob());
		Json.put(o, "callerKillOnClose", r.callerKillOnClose());
		if (r.callerLimitFlags() != null) {
			o.addProperty("callerLimitFlags", "0x" + Integer.toHexString(r.callerLimitFlags()));
		}
		Json.put(o, "error", r.error());
		if (r.own()) {
			List<Long> pids = r.own() ? Native.pids() : List.of();
			JsonArray a = new JsonArray();
			pids.forEach(a::add);
			o.add("pids", a);
		}
		if (sweepReport != null) {
			o.add("sweep", sweepReport.deepCopy());
		}
		return o;
	}

	/** The members of the job that are not the daemon itself (test and health use). */
	static List<Long> members() {
		return result.own() ? Native.pids() : List.of();
	}

	// ---- the Win32 calls, loaded on first use ------------------------------------------------------

	/** Loaded only when {@link #start} calls it, inside its {@code try/catch Throwable}. */
	private static final class Native {
		private static final Arena ARENA = Arena.global();
		private static final Linker LINKER = Linker.nativeLinker();
		private static final SymbolLookup K32 = SymbolLookup.libraryLookup("kernel32", ARENA);
		private static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
		private static final VarHandle LAST_ERROR =
			CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));
		private static final Linker.Option CAP = Linker.Option.captureCallState("GetLastError");
		private static final ValueLayout.OfInt I = ValueLayout.JAVA_INT;
		private static final AddressLayout P = ValueLayout.ADDRESS;

		private static MethodHandle h(String name, FunctionDescriptor fd, boolean capture) {
			MemorySegment s = K32.find(name).orElseThrow(() -> new UnsatisfiedLinkError(name));
			return capture ? LINKER.downcallHandle(s, fd, CAP) : LINKER.downcallHandle(s, fd);
		}

		private static final MethodHandle CREATE_JOB =
			h("CreateJobObjectW", FunctionDescriptor.of(P, P, P), true);
		private static final MethodHandle SET_INFO =
			h("SetInformationJobObject", FunctionDescriptor.of(I, P, I, P, I), true);
		private static final MethodHandle ASSIGN =
			h("AssignProcessToJobObject", FunctionDescriptor.of(I, P, P), true);
		private static final MethodHandle QUERY =
			h("QueryInformationJobObject", FunctionDescriptor.of(I, P, I, P, I, P), true);
		private static final MethodHandle IS_IN_JOB =
			h("IsProcessInJob", FunctionDescriptor.of(I, P, P, P), true);
		private static final MethodHandle CURRENT_PROCESS =
			h("GetCurrentProcess", FunctionDescriptor.of(P), false);

		private Native() {
		}

		private static int lastError(MemorySegment cap) {
			return (int) LAST_ERROR.get(cap, 0L);
		}

		static Result install() throws Throwable {
			try (Arena a = Arena.ofConfined()) {
				MemorySegment cap = a.allocate(CAPTURE);
				MemorySegment self = (MemorySegment) CURRENT_PROCESS.invokeExact();
				// 1. the facts about the job the process is already in, read before the assignment
				MemorySegment inJob = a.allocate(4);
				int ok = (int) IS_IN_JOB.invokeExact(cap, self, MemorySegment.NULL, inJob);
				boolean inCallerJob = ok != 0 && inJob.get(I, 0) != 0;
				Boolean callerKill = null;
				Integer callerFlags = null;
				if (inCallerJob) {
					MemorySegment basic = a.allocate(64);
					int q = (int) QUERY.invokeExact(cap, MemorySegment.NULL,
						JOB_OBJECT_BASIC_LIMIT_INFORMATION, basic, 64, MemorySegment.NULL);
					if (q != 0) {
						callerFlags = basic.get(I, LIMIT_FLAGS_OFF);
						callerKill = (callerFlags & LIMIT_KILL_ON_JOB_CLOSE) != 0;
					}
				}
				// 2. our own anonymous job (no name, no inheritable handle)
				MemorySegment noName = MemorySegment.NULL;
				MemorySegment j = (MemorySegment) CREATE_JOB.invokeExact(cap, MemorySegment.NULL,
					noName);
				if (j.equals(MemorySegment.NULL)) {
					return new Result("unavailable", false, inCallerJob, callerKill, callerFlags,
						lastError(cap), 0, 0, "CreateJobObjectW failed");
				}
				MemorySegment ext = a.allocate(EXT_SIZE); // zeroed
				ext.set(I, LIMIT_FLAGS_OFF, LIMIT_KILL_ON_JOB_CLOSE);
				int s = (int) SET_INFO.invokeExact(cap, j, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
					ext, (int) EXT_SIZE);
				if (s == 0) {
					return new Result("unavailable", false, inCallerJob, callerKill, callerFlags,
						0, lastError(cap), 0, "SetInformationJobObject failed");
				}
				// 3. assign ourselves; the children created from now on inherit the job
				int as = (int) ASSIGN.invokeExact(cap, j, self);
				if (as == 0) {
					return new Result("unavailable", false, inCallerJob, callerKill, callerFlags,
						0, 0, lastError(cap), "AssignProcessToJobObject failed");
				}
				job = j.reinterpret(0);
				return new Result("own", true, inCallerJob, callerKill, callerFlags, 0, 0, 0,
					null);
			}
		}

		/** The pids in the job (one {@code conhost.exe} per decompiler too: count image names, F4). */
		static List<Long> pids() {
			List<Long> out = new ArrayList<>();
			MemorySegment j = job;
			if (j.equals(MemorySegment.NULL)) {
				return out;
			}
			try (Arena a = Arena.ofConfined()) {
				MemorySegment cap = a.allocate(CAPTURE);
				int n = 4096;
				MemorySegment buf = a.allocate(16 + 8L * n);
				int q = (int) QUERY.invokeExact(cap, j, JOB_OBJECT_BASIC_PROCESS_ID_LIST, buf,
					(int) buf.byteSize(), MemorySegment.NULL);
				if (q == 0) {
					return out;
				}
				int listed = buf.get(I, 4);
				for (int i = 0; i < listed && i < n; i++) {
					out.add(buf.get(ValueLayout.JAVA_LONG, 8 + 8L * i));
				}
			}
			catch (Throwable t) {
				// reported as an empty list
			}
			return out;
		}
	}
}
