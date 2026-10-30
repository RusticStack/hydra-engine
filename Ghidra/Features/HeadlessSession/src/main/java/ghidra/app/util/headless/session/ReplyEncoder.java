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

	/**
	 * The bytes of encoded pages cached for the whole daemon, at most (every program state and
	 * overlay together); the least recently used page leaves first.
	 */
	static final long PAGE_CACHE_BYTES = 4L << 20;
	/** A page larger than this is not cached (it would push out many smaller ones). */
	private static final long PAGE_CACHE_ENTRY = PAGE_CACHE_BYTES / 8;

	private record PageKey(long snapshot, int from, int to) {
	}

	/** Guarded by itself; in access order, so the eldest entry is the least recently used. */
	private static final java.util.LinkedHashMap<PageKey, byte[]> PAGES =
		new java.util.LinkedHashMap<>(64, 0.75f, true);
	private static long pageBytes; // guarded by PAGES

	/** Reusable native scratch buffers, so a call neither allocates nor zero-fills one. */
	private static final long SCRATCH_BYTES = 256L << 10;
	private static final int SCRATCH_KEPT = 4;
	private static final java.util.concurrent.ConcurrentLinkedQueue<MemorySegment> SCRATCH =
		new java.util.concurrent.ConcurrentLinkedQueue<>();
	private static final java.util.concurrent.atomic.AtomicInteger SCRATCH_FREE =
		new java.util.concurrent.atomic.AtomicInteger();

	private static final MethodHandle ROWS;
	private static final String STATUS;

	private static final AtomicLong CALLS = new AtomicLong();
	private static final AtomicLong ROWS_WRITTEN = new AtomicLong();
	private static final AtomicLong BYTES = new AtomicLong();
	private static final AtomicLong PAGE_HITS = new AtomicLong();
	private static final AtomicLong FAILED = new AtomicLong();
	private static final AtomicLong COLUMNS = new AtomicLong();
	private static final AtomicLong COLUMN_BYTES = new AtomicLong();
	private static final AtomicLong PAGES_EVICTED = new AtomicLong();

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

	/** Registers {@code health.replyEncode} at start-up, so health has one shape on every run. */
	static void init() {
		// the class initializer does it
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
			COLUMN_BYTES.addAndGet(nt + at + 8L * (n + 1) + 9L * n);
		}

		/** Bytes enough for any row {@code i}: fixed text plus every byte escaped as \\u00xx. */
		long bound(int i) {
			return 96 + 6L * ((nameOffs[i + 1] - nameOffs[i]) + (addrOffs[i + 1] - addrOffs[i]));
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
		long ixBytes = idx == null ? 0 : 4L * Math.max(1, nidx);
		long outAt = (ixBytes + 15) & ~15L;
		long total = outAt + need;
		MemorySegment scratch = total <= SCRATCH_BYTES ? takeScratch() : null;
		// a page too large for a scratch buffer gets one confined arena for this call, freed at
		// once on this thread (a shared arena's close would need a handshake with every thread)
		try (Arena call = scratch == null ? Arena.ofConfined() : null) {
			MemorySegment mem = scratch != null ? scratch : call.allocate(total, 16);
			MemorySegment buf = mem.asSlice(outAt, need);
			MemorySegment ix = MemorySegment.NULL;
			if (idx != null) {
				ix = mem.asSlice(0, ixBytes);
				MemorySegment.copy(idx, 0, ix, JAVA_INT, 0, nidx);
			}
			long len = (long) ROWS.invokeExact(c.names, c.nameOff, c.addrs, c.addrOff, c.sizes,
				c.flags, (long) c.n, ix, (long) (idx == null ? 0 : nidx), (long) from, (long) to,
				buf, buf.byteSize());
			if (len < 0) {
				FAILED.incrementAndGet();
				return null;
			}
			byte[] out = new byte[(int) len];
			MemorySegment.copy(buf, JAVA_BYTE, 0, out, 0, (int) len);
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
			if (scratch != null) {
				giveScratch(scratch);
			}
		}
	}

	/**
	 * A scratch buffer of {@link #SCRATCH_BYTES} (zero-filled once, when it is made; the encoder
	 * only writes into it). Its memory goes with its last reference, so nothing is closed.
	 */
	private static MemorySegment takeScratch() {
		MemorySegment m = SCRATCH.poll();
		if (m != null) {
			SCRATCH_FREE.decrementAndGet();
			return m;
		}
		return Arena.ofAuto().allocate(SCRATCH_BYTES, 16);
	}

	private static void giveScratch(MemorySegment m) {
		if (SCRATCH_FREE.incrementAndGet() <= SCRATCH_KEPT) {
			SCRATCH.offer(m);
		}
		else {
			SCRATCH_FREE.decrementAndGet(); // not kept: the collector frees it
		}
	}

	/** The cached page {@code from..to} of program state {@code snapshot}, or null. */
	static byte[] cachedPage(long snapshot, int from, int to) {
		byte[] b;
		synchronized (PAGES) {
			b = PAGES.get(new PageKey(snapshot, from, to));
		}
		if (b != null) {
			PAGE_HITS.incrementAndGet();
		}
		return b;
	}

	/**
	 * Keeps a page for later requests within the daemon-wide budget, checked and charged under
	 * one lock: the least recently used pages leave to make room (a changed program's old pages
	 * first, since nobody asks for them again).
	 */
	static void cachePage(long snapshot, int from, int to, byte[] b) {
		if (b.length > PAGE_CACHE_ENTRY) {
			return;
		}
		synchronized (PAGES) {
			if (PAGES.putIfAbsent(new PageKey(snapshot, from, to), b) != null) {
				return;
			}
			pageBytes += b.length;
			var it = PAGES.values().iterator();
			while (pageBytes > PAGE_CACHE_BYTES && it.hasNext()) {
				pageBytes -= it.next().length;
				it.remove();
				PAGES_EVICTED.incrementAndGet();
			}
		}
	}

	/** The bytes the page cache holds now. */
	static long pageCacheBytes() {
		synchronized (PAGES) {
			return pageBytes;
		}
	}

	/** For {@code health.replyEncode}. */
	static JsonObject describe() {
		return Json.of("native", enabled(), "library", STATUS, "calls", CALLS.get(), "rows",
			ROWS_WRITTEN.get(), "bytes", BYTES.get(), "pageHits", PAGE_HITS.get(), "pageCacheBytes",
			pageCacheBytes(), "pagesEvicted", PAGES_EVICTED.get(), "columns", COLUMNS.get(),
			"columnBytesBuilt", COLUMN_BYTES.get(), "failed", FAILED.get());
	}
}
