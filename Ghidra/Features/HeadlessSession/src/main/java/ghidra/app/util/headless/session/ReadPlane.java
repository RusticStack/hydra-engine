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

import java.io.File;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.*;

import com.google.gson.JsonElement;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * The Rust read plane ({@code hydra_rp_*} in {@code hydra_native}, module HydraNative): immutable
 * tables of a program state built once in Rust, whose pages come back as the reply's JSON bytes,
 * with no Java object per row (Rust plan, read plane). Called with normal FFM downcalls.
 * <p>
 * The first table is the function listing ({@link FunctionTable}). It is optional: when the
 * library is missing, has another read-plane ABI, or {@code -set readPlane=false} (or
 * {@code -Dhydra.readPlane=false}), every table
 * stays on its Java path and replies are the same.
 */
final class ReadPlane {

	static final int ABI = 1;
	/** {@code -set readPlane=false} keeps every reply on the Java path. */
	static final String SETTING = "readPlane";
	/** {@code -Dhydra.readPlane=false} does the same from the JVM options. */
	static final String PROPERTY = "hydra.readPlane";

	private static final Linker LINKER = Linker.nativeLinker();
	private static final Cleaner CLEANER = Cleaner.create();

	final AtomicLong tables = new AtomicLong();
	final AtomicLong pages = new AtomicLong();
	final AtomicLong pageBytes = new AtomicLong();
	final AtomicLong fallbacks = new AtomicLong();
	/** Rust tables not yet freed (explicitly on eviction, or by the Cleaner backstop). */
	final AtomicLong live = new AtomicLong();

	private final MethodHandle ftNew;
	private final MethodHandle ftPage;
	private final MethodHandle ftWeight;
	private final MethodHandle ftFree;
	final String library;

	private ReadPlane(SymbolLookup l, String library) {
		this.library = library;
		ftNew = LINKER.downcallHandle(l.findOrThrow("hydra_rp_ft_new"),
			FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.ADDRESS));
		ftPage = LINKER.downcallHandle(l.findOrThrow("hydra_rp_ft_page"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
				ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
		ftWeight = LINKER.downcallHandle(l.findOrThrow("hydra_rp_ft_weight"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		ftFree = LINKER.downcallHandle(l.findOrThrow("hydra_rp_ft_free"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
	}

	private static volatile ReadPlane instance;
	private static volatile boolean looked;

	/** The read plane, or null when it is off or unavailable (looked up once). */
	static ReadPlane get() {
		if (looked) {
			return instance;
		}
		synchronized (ReadPlane.class) {
			if (!looked) {
				instance = load();
				looked = true;
				ReadPlane rp = instance;
				Health.contribute("readPlane", () -> rp == null
						? Json.of("enabled", false)
						: Json.of("enabled", true, "library", rp.library, "tables", rp.tables.get(),
							"pages", rp.pages.get(), "pageBytes", rp.pageBytes.get(), "fallbacks",
							rp.fallbacks.get(), "live", rp.live.get()));
			}
		}
		return instance;
	}

	private static ReadPlane load() {
		if (!Settings.bool(SETTING, true) ||
			"false".equals(System.getProperty(PROPERTY, "true").trim())) {
			return null;
		}
		Path lib = findLibrary();
		if (lib == null) {
			Msg.info(ReadPlane.class, "read plane off: hydra_native not found");
			return null;
		}
		try {
			SymbolLookup l = SymbolLookup.libraryLookup(lib, Arena.global());
			MethodHandle abi = LINKER.downcallHandle(l.findOrThrow("hydra_rp_abi_version"),
				FunctionDescriptor.of(ValueLayout.JAVA_INT));
			int v = (int) abi.invokeExact();
			if (v != ABI) {
				Msg.warn(ReadPlane.class, "read plane off: " + lib + " has ABI " + v + ", not " + ABI);
				return null;
			}
			return new ReadPlane(l, lib.toString());
		}
		catch (Throwable t) {
			Msg.warn(ReadPlane.class, "read plane off: " + lib + ": " + t);
			return null;
		}
	}

	private static Path findLibrary() {
		String explicit = System.getProperty("hydra.native.library");
		if (explicit != null && !explicit.isBlank()) {
			Path p = Path.of(explicit);
			return Files.isRegularFile(p) ? p : null;
		}
		String name = System.mapLibraryName("hydra_native");
		try {
			File f = Application.getOSFile("HydraNative", name);
			if (f != null && f.isFile()) {
				return f.toPath();
			}
		}
		catch (Throwable t) {
			// no application (the self-test): look next to this jar below
		}
		try {
			// <install>/Ghidra/Features/HeadlessSession/lib/HeadlessSession.jar
			Path jar = Path.of(ReadPlane.class.getProtectionDomain().getCodeSource().getLocation()
					.toURI());
			Path ghidra = jar.getParent().getParent().getParent().getParent();
			for (String platform : new String[] { "win_x86_64", "linux_x86_64", "mac_arm_64",
				"linux_arm_64", "mac_x86_64" }) {
				Path p = ghidra.resolve("Framework/HydraNative/os/" + platform + "/" + name);
				if (Files.isRegularFile(p)) {
					return p;
				}
			}
		}
		catch (Throwable t) {
			// not run from an install
		}
		return null;
	}

	// ---------------------------------------------------------------- function tables

	/**
	 * A function table held in Rust. Freed by {@link #close} once no page is reading it, or by
	 * the Cleaner when this object becomes unreachable without a close (whichever comes first;
	 * exactly once).
	 */
	static final class NativeFunctions {
		final MemorySegment handle;
		final long weight;
		/** False when a name holds a lone surrogate: {@code contains} stays on the Java path. */
		final boolean utf8Exact;
		/** The owner's reference plus one per page in flight; 0 once freed. */
		private final AtomicInteger refs = new AtomicInteger(1);
		private final AtomicBoolean closed = new AtomicBoolean();
		private final Runnable freer;

		NativeFunctions(MemorySegment handle, long weight, boolean utf8Exact, Runnable freer) {
			this.handle = handle;
			this.weight = weight;
			this.utf8Exact = utf8Exact;
			this.freer = freer;
		}

		/** False when the table is already freed (the caller takes the Java path). */
		boolean acquire() {
			while (true) {
				int r = refs.get();
				if (r <= 0) {
					return false;
				}
				if (refs.compareAndSet(r, r + 1)) {
					return true;
				}
			}
		}

		void releaseRef() {
			if (refs.decrementAndGet() == 0) {
				freer.run();
			}
		}

		/** Drops the owner's reference: freed now, or when the last page in flight ends. */
		void close() {
			if (closed.compareAndSet(false, true)) {
				releaseRef();
			}
		}
	}

	/** Frees one Rust table exactly once (explicit close or the Cleaner). */
	private static final class Freer implements Runnable {
		private final ReadPlane rp;
		private final long addr;
		private final AtomicBoolean done = new AtomicBoolean();

		Freer(ReadPlane rp, long addr) {
			this.rp = rp;
			this.addr = addr;
		}

		@Override
		public void run() {
			if (done.compareAndSet(false, true)) {
				rp.free(addr);
				rp.live.decrementAndGet();
			}
		}
	}

	/**
	 * Exports one table to Rust; null when Rust refuses it (never expected) or a downcall fails.
	 */
	NativeFunctions functions(String[] names, String[] entries, long[] sizes, byte[] flags) {
		int n = names.length;
		boolean exact = true;
		byte[][] nb = new byte[n][];
		byte[][] eb = new byte[n][];
		long nl = 0, el = 0;
		for (int i = 0; i < n; i++) {
			if (exact && hasLoneSurrogate(names[i])) {
				exact = false;
			}
			nb[i] = names[i].getBytes(StandardCharsets.UTF_8);
			eb[i] = entries[i].getBytes(StandardCharsets.UTF_8);
			nl += nb[i].length;
			el += eb[i].length;
		}
		if (nl > 0xFFFF_FFFFL || el > 0xFFFF_FFFFL) {
			return null;
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment na = a.allocate(Math.max(1, nl));
			MemorySegment ea = a.allocate(Math.max(1, el));
			MemorySegment ne = a.allocate(ValueLayout.JAVA_INT, Math.max(1, n));
			MemorySegment ee = a.allocate(ValueLayout.JAVA_INT, Math.max(1, n));
			MemorySegment sz = a.allocate(ValueLayout.JAVA_LONG, Math.max(1, n));
			MemorySegment fl = a.allocate(Math.max(1, n));
			long np = 0, ep = 0;
			for (int i = 0; i < n; i++) {
				MemorySegment.copy(nb[i], 0, na, ValueLayout.JAVA_BYTE, np, nb[i].length);
				np += nb[i].length;
				ne.setAtIndex(ValueLayout.JAVA_INT, i, (int) np);
				MemorySegment.copy(eb[i], 0, ea, ValueLayout.JAVA_BYTE, ep, eb[i].length);
				ep += eb[i].length;
				ee.setAtIndex(ValueLayout.JAVA_INT, i, (int) ep);
				sz.setAtIndex(ValueLayout.JAVA_LONG, i, sizes[i]);
				fl.set(ValueLayout.JAVA_BYTE, i, flags[i]);
			}
			MemorySegment h = (MemorySegment) ftNew.invokeExact(n, na, nl, ne, ea, el, ee, sz, fl);
			if (h.address() == 0) {
				fallbacks.incrementAndGet();
				return null;
			}
			long w = (long) ftWeight.invokeExact(h);
			Freer freer = new Freer(this, h.address());
			NativeFunctions nf = new NativeFunctions(h, w, exact, freer);
			CLEANER.register(nf, freer);
			tables.incrementAndGet();
			live.incrementAndGet();
			return nf;
		}
		catch (Throwable t) {
			Msg.warn(this, "read plane: function table export failed: " + t);
			fallbacks.incrementAndGet();
			return null;
		}
	}

	private void free(long addr) {
		try {
			ftFree.invokeExact(MemorySegment.ofAddress(addr));
		}
		catch (Throwable t) {
			// never thrown by the Rust side; nothing to do on a cleaner thread
		}
	}

	/**
	 * The {@code functions} result of {@code t} as JSON bytes rendered in Rust, or null when this
	 * request stays on the Java path ({@code contains} with a lone surrogate, or a failure).
	 */
	RawJson page(NativeFunctions t, String contains, int offset, int limit) {
		if (contains != null && (!t.utf8Exact || hasLoneSurrogate(contains))) {
			fallbacks.incrementAndGet();
			return null;
		}
		if (!t.acquire()) {
			return null; // dropped by the daemon meanwhile: the Java rows answer
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment needle = MemorySegment.NULL;
			long needleLen = 0;
			if (contains != null) {
				byte[] cb = contains.getBytes(StandardCharsets.UTF_8);
				needle = a.allocate(Math.max(1, cb.length));
				MemorySegment.copy(cb, 0, needle, ValueLayout.JAVA_BYTE, 0, cb.length);
				needleLen = cb.length;
			}
			// a first guess that fits most pages: about 110 bytes a row
			long cap = Math.min(16L << 20, 256 + 112L * Math.min(limit, 20_000));
			MemorySegment out = a.allocate(cap);
			long len = (long) ftPage.invokeExact(t.handle, needle, needleLen, (long) offset,
				(long) limit, out, cap);
			if (len > cap) {
				out = a.allocate(len);
				len = (long) ftPage.invokeExact(t.handle, needle, needleLen, (long) offset,
					(long) limit, out, len);
			}
			if (len < 0 || len > Integer.MAX_VALUE - 64) {
				fallbacks.incrementAndGet();
				return null;
			}
			byte[] bytes = out.asSlice(0, len).toArray(ValueLayout.JAVA_BYTE);
			pages.incrementAndGet();
			pageBytes.addAndGet(len);
			return new RawJson(bytes);
		}
		catch (Throwable th) {
			Msg.warn(this, "read plane: page failed: " + th);
			fallbacks.incrementAndGet();
			return null;
		}
		finally {
			t.releaseRef();
			java.lang.ref.Reference.reachabilityFence(t);
		}
	}

	static boolean hasLoneSurrogate(String s) {
		for (int i = 0, n = s.length(); i < n; i++) {
			char c = s.charAt(i);
			if (Character.isHighSurrogate(c)) {
				if (i + 1 < n && Character.isLowSurrogate(s.charAt(i + 1))) {
					i++;
					continue;
				}
				return true;
			}
			if (Character.isLowSurrogate(c)) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------- raw replies

	/**
	 * A command result that is already JSON (UTF-8 bytes of one value, as Gson would write it).
	 * {@link Connection#send} splices it into the reply line in place of the {@code result}
	 * value; anything else that needs it as a tree calls {@link #tree()}.
	 */
	static final class RawJson extends JsonElement {
		final byte[] bytes;

		@SuppressWarnings("deprecation")
		RawJson(byte[] bytes) {
			this.bytes = bytes;
		}

		/** The value as a Gson tree (the slow path, for a caller that edits the result). */
		JsonElement tree() {
			return com.google.gson.JsonParser
					.parseString(new String(bytes, StandardCharsets.UTF_8));
		}

		/**
		 * The JSON text itself. Gson's own writer cannot write this subclass ({@code Gson.toJson}
		 * of a tree that holds it throws); {@link Connection#encode} splices the bytes, any other
		 * writer must use {@link #tree()}.
		 */
		@Override
		public String toString() {
			return new String(bytes, StandardCharsets.UTF_8);
		}

		@Override
		public JsonElement deepCopy() {
			return this;
		}
	}
}
