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
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.util.Msg;

/**
 * The trace C ABI of {@code hydra_native} ({@code hydra_trace_*}, {@code include/hydra_native.h}),
 * called with normal FFM downcalls: request bytes in, reply bytes out. It also installs the
 * symbolizer callback ({@link TraceSymbols}) the Rust ingest calls to resolve a code address.
 * <p>
 * Optional, like {@link ReadPlane}: when the library is missing, has another trace ABI, or
 * {@code -set trace=false} is given, the {@code trace} capability is not advertised and every
 * {@code trace_*} command answers {@code failed} with {@code details.reason:"native_missing"}.
 */
final class TraceNative {

	static final int ABI = 1;
	/** {@code -set trace=false} turns the whole feature off. */
	static final String SETTING = "trace";

	/** A reply: status 0 and the result JSON, or the error object's JSON. */
	record Reply(int status, byte[] bytes) {
	}

	private static final Linker LINKER = Linker.nativeLinker();

	final AtomicLong calls = new AtomicLong();
	final AtomicLong replyBytes = new AtomicLong();
	final AtomicLong symbolized = new AtomicLong();
	final AtomicLong unresolved = new AtomicLong();
	final String library;

	private final MethodHandle call;
	private final MethodHandle status;
	private final MethodHandle ptr;
	private final MethodHandle len;
	private final MethodHandle free;

	private TraceNative(SymbolLookup l, String library) throws Throwable {
		this.library = library;
		call = LINKER.downcallHandle(l.findOrThrow("hydra_trace_call"),
			FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
				ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		status = LINKER.downcallHandle(l.findOrThrow("hydra_trace_reply_status"),
			FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
		ptr = LINKER.downcallHandle(l.findOrThrow("hydra_trace_reply_ptr"),
			FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
		len = LINKER.downcallHandle(l.findOrThrow("hydra_trace_reply_len"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		free = LINKER.downcallHandle(l.findOrThrow("hydra_trace_reply_free"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
		MethodHandle set = LINKER.downcallHandle(l.findOrThrow("hydra_trace_set_symbolizer"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
		MethodHandle cb = MethodHandles.lookup().findStatic(TraceNative.class, "symbolize",
			MethodType.methodType(int.class, MemorySegment.class, long.class, long.class,
				MemorySegment.class, long.class, long.class, MemorySegment.class, long.class));
		MemorySegment stub = LINKER.upcallStub(cb,
			FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
			Arena.global());
		set.invokeExact(stub);
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
						: Json.of("enabled", true, "library", t.library, "calls", t.calls.get(),
							"replyBytes", t.replyBytes.get(), "symbolized", t.symbolized.get(),
							"unresolved", t.unresolved.get(), "sessions", TraceLeases.count()));
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
			SymbolLookup l = SymbolLookup.libraryLookup(lib, Arena.global());
			MethodHandle abi = LINKER.downcallHandle(l.findOrThrow("hydra_trace_abi_version"),
				FunctionDescriptor.of(ValueLayout.JAVA_INT));
			int v = (int) abi.invokeExact();
			if (v != ABI) {
				Msg.warn(TraceNative.class, "trace off: " + lib + " has trace ABI " + v + ", not " + ABI);
				return null;
			}
			return new TraceNative(l, lib.toString());
		}
		catch (Throwable t) {
			Msg.info(TraceNative.class, "trace off: " + lib + ": " + t);
			return null;
		}
	}

	/**
	 * Runs one command. {@code cancel} is a native int the caller sets non-zero to cancel (null:
	 * not cancellable); it must stay valid until this returns.
	 */
	Reply call(String cmd, byte[] ctx, byte[] req, MemorySegment cancel) {
		try (Arena a = Arena.ofConfined()) {
			MemorySegment c = a.allocate(Math.max(1, cmd.length()));
			byte[] cb = cmd.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment.copy(cb, 0, c, ValueLayout.JAVA_BYTE, 0, cb.length);
			MemorySegment x = a.allocate(Math.max(1, ctx.length));
			MemorySegment.copy(ctx, 0, x, ValueLayout.JAVA_BYTE, 0, ctx.length);
			MemorySegment r = a.allocate(Math.max(1, req.length));
			MemorySegment.copy(req, 0, r, ValueLayout.JAVA_BYTE, 0, req.length);
			MemorySegment flag = cancel == null ? MemorySegment.NULL : cancel;
			MemorySegment h = (MemorySegment) call.invokeExact(c, (long) cb.length, x,
				(long) ctx.length, r, (long) req.length, flag);
			try {
				int st = (int) status.invokeExact(h);
				long n = (long) len.invokeExact(h);
				MemorySegment p = (MemorySegment) ptr.invokeExact(h);
				byte[] out = n == 0 ? new byte[0]
						: p.reinterpret(n).toArray(ValueLayout.JAVA_BYTE);
				calls.incrementAndGet();
				replyBytes.addAndGet(n);
				return new Reply(st, out);
			}
			finally {
				free.invokeExact(h);
			}
		}
		catch (Throwable t) {
			throw new SessionException(SessionException.FAILED,
				"trace native call failed: " + t, Json.of("reason", "native_call"), t);
		}
	}

	/**
	 * The symbolizer the Rust ingest calls: see {@code hydra_native.h}. Must not throw (an
	 * exception in an upcall ends the JVM): every failure is "no symbol".
	 */
	@SuppressWarnings("unused") // found by name in the constructor
	private static int symbolize(MemorySegment session, long sessionLen, long revision,
			MemorySegment module, long moduleLen, long va, MemorySegment out, long outCap) {
		TraceNative self = instance;
		try {
			String s = new String(session.reinterpret(sessionLen).toArray(ValueLayout.JAVA_BYTE),
				java.nio.charset.StandardCharsets.UTF_8);
			String m = new String(module.reinterpret(moduleLen).toArray(ValueLayout.JAVA_BYTE),
				java.nio.charset.StandardCharsets.UTF_8);
			TraceSymbols.Result r = TraceSymbols.resolve(s, revision, m, va);
			if (self != null) {
				(r.code() > 0 ? self.symbolized : self.unresolved).incrementAndGet();
			}
			if (r.code() <= 0) {
				return r.code();
			}
			byte[] json = r.json().getBytes(java.nio.charset.StandardCharsets.UTF_8);
			if (json.length > outCap) {
				return 0;
			}
			MemorySegment.copy(json, 0, out.reinterpret(outCap), ValueLayout.JAVA_BYTE, 0,
				json.length);
			return json.length;
		}
		catch (Throwable t) {
			return 0;
		}
	}
}
