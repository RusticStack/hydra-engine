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
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.util.Msg;

/**
 * The trace C ABI of {@code hydra_native} ({@code hydra_trace_*}, {@code include/hydra_native.h};
 * the engine is the {@code hydra-trace} crate's {@code Service}), called with normal FFM
 * downcalls: request bytes in, reply bytes out, both JSON.
 * <p>
 * Optional, like {@link ReadPlane}: when the library is missing, lacks the trace functions, or
 * {@code -set trace=false} is given, the {@code trace} capability is not advertised and every
 * {@code trace_*} command answers {@code failed} with {@code details.reason:"native_missing"}.
 */
final class TraceNative {

	/** {@code -set trace=false} turns the whole feature off. */
	static final String SETTING = "trace";
	private static final int OK = 0;
	private static final int ERR_BUFFER = -5;
	private static final int FIRST_BUFFER = 64 << 10;

	private static final Linker LINKER = Linker.nativeLinker();

	final AtomicLong calls = new AtomicLong();
	final AtomicLong replyBytes = new AtomicLong();
	/** Time spent inside the engine's request call, in nanoseconds (for the health report). */
	final AtomicLong engineNanos = new AtomicLong();
	final String library;

	private final MethodHandle init;
	private final MethodHandle request;
	private final MethodHandle copy;
	/** Null when the library predates {@code hydra_trace_set_cancel}. */
	private final MethodHandle setCancel;
	/** Null when the library predates {@code hydra_trace_set_progress}. */
	private final MethodHandle setProgress;
	private volatile String root;

	private TraceNative(SymbolLookup l, String library) {
		this.library = library;
		init = LINKER.downcallHandle(l.findOrThrow("hydra_trace_init"),
			FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
		request = LINKER.downcallHandle(l.findOrThrow("hydra_trace_request"),
			FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
				ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		copy = LINKER.downcallHandle(l.findOrThrow("hydra_trace_reply_copy"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG));
		setCancel = l.find("hydra_trace_set_cancel").map(a -> LINKER.downcallHandle(a,
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))).orElse(null);
		setProgress = l.find("hydra_trace_set_progress").map(a -> LINKER.downcallHandle(a,
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))).orElse(null);
	}

	/** Whether long commands report progress. */
	boolean reportsProgress() {
		return setProgress != null;
	}

	private static volatile TraceNative instance;
	private static volatile boolean looked;

	/** The trace library, or null when it is off or unavailable (looked up once). */
	static TraceNative get() {
		if (looked) {
			return instance;
		}
		synchronized (TraceNative.class) {
			if (!looked) {
				instance = load();
				looked = true;
				TraceNative t = instance;
				Health.contribute("trace", () -> t == null
						? Json.of("enabled", false)
						: Json.of("enabled", true, "library", t.library, "root", t.root,
							"calls", t.calls.get(), "replyBytes", t.replyBytes.get(), "engineMs", t.engineNanos.get() / 1_000_000, "sessions",
							TraceLeases.count()));
			}
		}
		return instance;
	}

	private static TraceNative load() {
		if (!Settings.bool(SETTING, true)) {
			return null;
		}
		Path lib = ReadPlane.findLibrary();
		if (lib == null) {
			Msg.info(TraceNative.class, "trace off: hydra_native not found");
			return null;
		}
		try {
			return new TraceNative(SymbolLookup.libraryLookup(lib, Arena.global()),
				lib.toString());
		}
		catch (Throwable t) {
			Msg.info(TraceNative.class, "trace off: " + lib + ": " + t);
			return null;
		}
	}

	/** Whether requests can be cancelled inside the engine. */
	boolean cancellable() {
		return setCancel != null;
	}

	/** Tells the engine where the sessions live (once; a different root later is refused). */
	synchronized void useRoot(Path dir) {
		String r = dir.toString();
		if (r.equals(root)) {
			return;
		}
		try (Arena a = Arena.ofConfined()) {
			byte[] b = r.getBytes(StandardCharsets.UTF_8);
			MemorySegment seg = a.allocate(Math.max(1, b.length));
			MemorySegment.copy(b, 0, seg, ValueLayout.JAVA_BYTE, 0, b.length);
			int rc = (int) init.invokeExact(seg, (long) b.length);
			if (rc != OK) {
				throw new SessionException(SessionException.FAILED,
					"the trace engine refused the store root " + r + " (code " + rc +
						"); it is already using " + root,
					Json.of("reason", "trace_root", "code", rc));
			}
			root = r;
		}
		catch (SessionException e) {
			throw e;
		}
		catch (Throwable t) {
			throw new SessionException(SessionException.FAILED,
				"trace native call failed: " + t, Json.of("reason", "native_call"), t);
		}
	}

	/**
	 * Runs one command and returns the reply bytes ({@code {"ok":true,...}} or
	 * {@code {"error":{...},"ok":false}}). {@code cancel} is a native int the caller sets
	 * non-zero to cancel (null: not cancellable); it must stay valid until this returns.
	 */
	byte[] call(String cmd, byte[] req, MemorySegment cancel) {
		return call(cmd, req, cancel, null);
	}

	/** As above; {@code progress} is two native longs (done, total) or null. */
	byte[] call(String cmd, byte[] req, MemorySegment cancel, MemorySegment progress) {
		try {
			byte[] cb = commandBytes(cmd);
			// one per-thread scratch segment: [reply FIRST_BUFFER][length 8][command][request]
			long need = FIRST_BUFFER + 8L + cb.length + req.length;
			Scratch sc = SCRATCH.get();
			if (sc.seg == null || sc.seg.byteSize() < need) {
				sc.seg = Arena.ofAuto().allocate(Math.max(need, FIRST_BUFFER + 4096L), 8);
				if (need > (4L << 20)) {
					SCRATCH.remove(); // a huge request is not kept
				}
			}
			MemorySegment out = sc.seg.asSlice(0, FIRST_BUFFER);
			MemorySegment len = sc.seg.asSlice(FIRST_BUFFER, 8);
			MemorySegment c = sc.seg.asSlice(FIRST_BUFFER + 8L, cb.length);
			MemorySegment r = sc.seg.asSlice(FIRST_BUFFER + 8L + cb.length, req.length);
			MemorySegment.copy(cb, 0, c, ValueLayout.JAVA_BYTE, 0, cb.length);
			MemorySegment.copy(req, 0, r, ValueLayout.JAVA_BYTE, 0, req.length);
			boolean armed = cancel != null && setCancel != null;
			boolean reporting = progress != null && setProgress != null;
			int rc;
			long t0 = System.nanoTime();
			try {
				if (armed) {
					setCancel.invokeExact(cancel);
				}
				if (reporting) {
					setProgress.invokeExact(progress);
				}
				rc = (int) request.invokeExact(c, (long) cb.length, r, (long) req.length, out,
					(long) FIRST_BUFFER, len);
			}
			finally {
				engineNanos.addAndGet(System.nanoTime() - t0);
				if (armed) {
					setCancel.invokeExact(MemorySegment.NULL);
				}
				if (reporting) {
					setProgress.invokeExact(MemorySegment.NULL);
				}
			}
			long n = len.get(ValueLayout.JAVA_LONG, 0);
			byte[] bytes;
			if (rc == OK) {
				bytes = out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
			}
			else if (rc == ERR_BUFFER) {
				MemorySegment big = Arena.ofAuto().allocate(n);
				long got = (long) copy.invokeExact(big, n);
				if (got != n) {
					throw new IllegalStateException("the kept reply was lost (" + got + ")");
				}
				bytes = big.toArray(ValueLayout.JAVA_BYTE);
			}
			else {
				throw new IllegalStateException("hydra_trace_request returned " + rc);
			}
			calls.incrementAndGet();
			replyBytes.addAndGet(bytes.length);
			return bytes;
		}
		catch (Throwable t) {
			throw new SessionException(SessionException.FAILED,
				"trace native call failed: " + t, Json.of("reason", "native_call"), t);
		}
	}

	private static final class Scratch {
		MemorySegment seg;
	}

	private static final ThreadLocal<Scratch> SCRATCH = ThreadLocal.withInitial(Scratch::new);
	private static final java.util.concurrent.ConcurrentHashMap<String, byte[]> COMMANDS =
		new java.util.concurrent.ConcurrentHashMap<>();
	private static final java.util.concurrent.ConcurrentLinkedQueue<MemorySegment> CELLS =
		new java.util.concurrent.ConcurrentLinkedQueue<>();

	private static byte[] commandBytes(String cmd) {
		byte[] b = COMMANDS.get(cmd);
		if (b == null) {
			b = cmd.getBytes(StandardCharsets.UTF_8);
			if (COMMANDS.size() < 64) {
				COMMANDS.put(cmd, b);
			}
		}
		return b;
	}

	/**
	 * A zeroed native cell for one call, recycled by {@link #giveCells}: the cancel flag (an
	 * {@code int32} at 0) and the progress pair (two {@code int64} at 8). The cells live as long as
	 * the process, so no per-call shared arena has to be closed (that is a handshake with every
	 * thread of the VM).
	 */
	static MemorySegment takeCells() {
		MemorySegment c = CELLS.poll();
		if (c == null) {
			c = Arena.global().allocate(24, 8);
		}
		else {
			c.fill((byte) 0);
		}
		return c;
	}

	static void giveCells(MemorySegment c) {
		CELLS.add(c);
	}
}
