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

import static java.lang.foreign.ValueLayout.*;

import java.io.File;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.JsonObject;

import ghidra.framework.Application;
import ghidra.util.HydraCpu;

/**
 * Large reply parts encoded in Rust (Hydra reply-encode): the {@code functions} listing page is
 * written as JSON by {@code hydra_reply_function_rows} ({@code hydra_native}, module HydraNative)
 * from off-heap columns of the program state's shared listing ({@link FunctionIndex}), instead
 * of one {@link JsonObject} with five boxed values per row that Gson then walks. The bytes are
 * those Gson writes for the same rows ({@code -selfTest}, {@code dt_re}); a page of an unfiltered
 * listing is encoded once per program state and shared by every client that asks for it.
 * <p>
 * {@code -set nativeReplies=false}, or no library with the entry point, keeps the Java path.
 * {@code health.replyEncode} says which is used and counts the work.
 */
final class ReplyEncoder {

	/** The pooled output buffers kept: at most this many, each at most {@link #POOL_MAX_BYTES}. */
	private static final int POOL_MAX = 8;
	private static final long POOL_MAX_BYTES = 4L << 20;
	/** The bytes of the cached pages of one program state, at most. */
	static final long PAGE_CACHE_BYTES = 16L << 20;

	private static final MethodHandle ROWS;
	private static final String STATUS;

	private static final AtomicLong CALLS = new AtomicLong();
	private static final AtomicLong ROWS_WRITTEN = new AtomicLong();
	private static final AtomicLong BYTES = new AtomicLong();
	private static final AtomicLong PAGE_HITS = new AtomicLong();
	private static final AtomicLong FAILED = new AtomicLong();
	private static final AtomicLong COLUMNS = new AtomicLong();

	private static final ConcurrentLinkedDeque<Buffer> POOL = new ConcurrentLinkedDeque<>();

	static {
		MethodHandle rows = null;
		String status;
		try {
			File lib = library();
			if (lib == null) {
				status = "no " + System.mapLibraryName(HydraNativeName.LIBRARY);
			}
			else {
				SymbolLookup lookup = SymbolLookup.libraryLookup(lib.toPath(), Arena.global());
				var sym = lookup.find("hydra_reply_function_rows");
				if (sym.isEmpty()) {
					status = lib + " has no hydra_reply_function_rows";
				}
				else {
					rows = Linker.nativeLinker()
							.downcallHandle(sym.get(),
								FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS,
									ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG,
									JAVA_LONG, ADDRESS, JAVA_LONG));
					status = lib.toString();
				}
			}
		}
		catch (Throwable t) {
			status = "not loaded: " + t;
		}
		ROWS = rows;
		STATUS = status;
		Health.contribute("replyEncode", ReplyEncoder::describe);
	}

	/** The library names, kept apart so the static block reads plainly. */
	private static final class HydraNativeName {
		static final String LIBRARY = "hydra_native";
	}

	private ReplyEncoder() {
	}

	/** The library: the {@code hydra.native.library} file, else HydraNative's os directory. */
	private static File library() {
		String explicit = System.getProperty(HydraCpu.LIBRARY_PROPERTY);
		if (explicit != null && !explicit.isBlank()) {
			File f = new File(explicit);
			return f.isFile() ? f : null;
		}
		String file = System.mapLibraryName(HydraNativeName.LIBRARY);
		try {
			if (Application.isInitialized()) {
				return Application.getOSFile("HydraNative", file);
			}
		}
		catch (Exception e) {
			// not there: look beside this module as below
		}
		// before the application is up (-selfTest): <Ghidra>/Framework/HydraNative/{os,build/os}
		// next to <Ghidra>/Features/HeadlessSession, found from this class's jar or classes
		try {
			var src = ReplyEncoder.class.getProtectionDomain().getCodeSource();
			File dir = new File(src.getLocation().toURI());
			for (int i = 0; dir != null && i < 6; i++, dir = dir.getParentFile()) {
				if (new File(dir, "Module.manifest").isFile()) {
					break;
				}
			}
			if (dir == null) {
				return null;
			}
			File natives = new File(dir.getParentFile().getParentFile(), "Framework/HydraNative");
			String platform = ghidra.framework.Platform.CURRENT_PLATFORM.getDirectoryName();
			for (String os : new String[] { "os", "build/os" }) {
				File f = new File(natives, os + "/" + platform + "/" + file);
				if (f.isFile()) {
					return f;
				}
			}
		}
		catch (Exception e) {
			// no library
		}
		return null;
	}

	static boolean available() {
		return ROWS != null;
	}

	static boolean enabled() {
		return ROWS != null && Settings.bool("nativeReplies", true);
	}

	/** The off-heap columns of one listing; freed with the snapshot that holds them. */
	static final class Columns {
		final MemorySegment names, nameOff, addrs, addrOff, sizes, flags;
		final int[] nameOffs, addrOffs;
		final int n;

		Columns(FunctionIndex.Snapshot s) {
			n = s.size();
			byte[][] nb = new byte[n][];
			byte[][] ab = new byte[n][];
			nameOffs = new int[n + 1];
			addrOffs = new int[n + 1];
			long nt = 0, at = 0;
			for (int i = 0; i < n; i++) {
				nb[i] = s.names[i].getBytes(StandardCharsets.UTF_8);
				ab[i] = s.addresses[i].getBytes(StandardCharsets.UTF_8);
				nt += nb[i].length;
				at += ab[i].length;
				if (nt > Integer.MAX_VALUE || at > Integer.MAX_VALUE) {
					throw new IllegalStateException("listing too large for the native encoder");
				}
				nameOffs[i + 1] = (int) nt;
				addrOffs[i + 1] = (int) at;
			}
			Arena arena = Arena.ofAuto(); // freed when this object is unreachable
			names = arena.allocate(Math.max(1, nt));
			addrs = arena.allocate(Math.max(1, at));
			for (int i = 0; i < n; i++) {
				MemorySegment.copy(nb[i], 0, names, JAVA_BYTE, nameOffs[i], nb[i].length);
				MemorySegment.copy(ab[i], 0, addrs, JAVA_BYTE, addrOffs[i], ab[i].length);
			}
			nameOff = arena.allocateFrom(JAVA_INT, nameOffs);
			addrOff = arena.allocateFrom(JAVA_INT, addrOffs);
			sizes = arena.allocateFrom(JAVA_LONG, n == 0 ? new long[1] : s.sizes);
			flags = arena.allocateFrom(JAVA_BYTE, n == 0 ? new byte[1] : s.flags);
			COLUMNS.incrementAndGet();
		}

		/** Bytes enough for any row {@code i}: fixed text plus every byte escaped as \\u00xx. */
		long bound(int i) {
			return 96 + 6L * ((nameOffs[i + 1] - nameOffs[i]) + (addrOffs[i + 1] - addrOffs[i]));
		}
	}

	/** A pooled native output buffer. */
	private record Buffer(Arena arena, MemorySegment seg) {
	}

	private static Buffer take(long need) {
		for (var it = POOL.iterator(); it.hasNext();) {
			Buffer b = it.next();
			if (b.seg.byteSize() >= need && POOL.remove(b)) {
				return b;
			}
		}
		long size = Math.max(64L << 10, Long.highestOneBit(Math.max(1, need - 1)) << 1);
		Arena a = Arena.ofShared();
		return new Buffer(a, a.allocate(size, 16));
	}

	private static void give(Buffer b) {
		if (b.seg.byteSize() <= POOL_MAX_BYTES && POOL.size() < POOL_MAX) {
			POOL.addFirst(b);
		}
		else {
			b.arena.close();
		}
	}

	/**
	 * The JSON array of rows {@code from..to} of {@code s} (when {@code idx} is null) or of rows
	 * {@code idx[0..nidx]}, or null when the native encoder failed (the caller uses Java).
	 */
	static byte[] functionRows(FunctionIndex.Snapshot s, int[] idx, int nidx, int from, int to) {
		Columns c = s.columns();
		long need = 2;
		if (idx == null) {
			need += 96L * (to - from) +
				6L * ((c.nameOffs[to] - c.nameOffs[from]) + (c.addrOffs[to] - c.addrOffs[from]));
		}
		else {
			for (int k = 0; k < nidx; k++) {
				need += c.bound(idx[k]);
			}
		}
		Buffer b = take(need);
		long len;
		try (Arena call = Arena.ofConfined()) {
			MemorySegment ix = MemorySegment.NULL;
			if (idx != null) {
				ix = call.allocate(JAVA_INT, Math.max(1, nidx));
				MemorySegment.copy(idx, 0, ix, JAVA_INT, 0, nidx);
			}
			len = (long) ROWS.invokeExact(c.names, c.nameOff, c.addrs, c.addrOff, c.sizes, c.flags,
				(long) c.n, ix, (long) (idx == null ? 0 : nidx), (long) from, (long) to, b.seg,
				b.seg.byteSize());
			if (len < 0) {
				FAILED.incrementAndGet();
				return null;
			}
			byte[] out = new byte[(int) len];
			MemorySegment.copy(b.seg, JAVA_BYTE, 0, out, 0, (int) len);
			CALLS.incrementAndGet();
			ROWS_WRITTEN.addAndGet(idx == null ? to - from : nidx);
			BYTES.addAndGet(len);
			return out;
		}
		catch (Throwable t) {
			FAILED.incrementAndGet();
			return null;
		}
		finally {
			give(b);
		}
	}

	static void pageHit() {
		PAGE_HITS.incrementAndGet();
	}

	/** For {@code health.replyEncode}. */
	static JsonObject describe() {
		return Json.of("native", enabled(), "library", STATUS, "calls", CALLS.get(), "rows",
			ROWS_WRITTEN.get(), "bytes", BYTES.get(), "pageHits", PAGE_HITS.get(), "columns",
			COLUMNS.get(), "failed", FAILED.get());
	}
}
