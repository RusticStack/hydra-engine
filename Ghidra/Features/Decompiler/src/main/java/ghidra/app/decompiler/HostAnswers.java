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
package ghidra.app.decompiler;

import static java.lang.foreign.ValueLayout.*;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.util.Msg;

/**
 * Hydra: the decompile answer store of the {@code hydra_decomp_host} library, off the Java heap.
 * <p>
 * A decompile whose C text is too large to hold in a tree (the response spilled to disk) is
 * streamed token by token; its text is written here as it is produced, so a later request for
 * another page of it is read from the store instead of decompiling again. The text is kept as
 * UTF-16 code units (little endian), so a character offset maps to a byte offset and a page is
 * the same substring a Java string would give, lone surrogates included. The store bounds its
 * own memory and disk (see {@link #configure}); a refused answer is just not cached.
 * <p>
 * The library is only loaded (never started), so this costs no decompiler workers. Every method
 * is safe on any thread and degrades to "not available / miss" when the library is absent.
 */
public final class HostAnswers {

	/** Characters of a writer's buffer before they go to the store. */
	private static final int FLUSH_CHARS = 32 << 10;
	/** The most bytes of metadata a read returns. */
	private static final int META_CAP = 64 << 10;

	private static final class Lib {
		final MethodHandle configure;
		final MethodHandle begin;
		final MethodHandle append;
		final MethodHandle commit;
		final MethodHandle abort;
		final MethodHandle read;
		final MethodHandle remove;
		final MethodHandle stats;
		final MethodHandle clear;

		Lib(SymbolLookup s) {
			Linker l = Linker.nativeLinker();
			configure = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_configure"),
				FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, ADDRESS,
					JAVA_LONG));
			begin = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_begin"),
				FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG));
			append = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_append"),
				FunctionDescriptor.of(JAVA_INT, JAVA_LONG, ADDRESS, JAVA_LONG));
			commit = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_commit"),
				FunctionDescriptor.of(JAVA_INT, JAVA_LONG, ADDRESS, JAVA_LONG));
			abort = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_abort"),
				FunctionDescriptor.ofVoid(JAVA_LONG));
			read = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_read"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG,
					ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
			remove = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_remove"),
				FunctionDescriptor.ofVoid(ADDRESS, JAVA_LONG));
			stats = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_stats"),
				FunctionDescriptor.ofVoid(ADDRESS));
			clear = l.downcallHandle(s.findOrThrow("hydra_dhost_answer_clear"),
				FunctionDescriptor.ofVoid());
		}
	}

	private static volatile Object lib;	// a Lib, or the String reason it is unavailable
	private static final AtomicBoolean CONFIGURED = new AtomicBoolean();

	private HostAnswers() {
	}

	private static Object lib() {
		Object l = lib;
		if (l == null) {
			synchronized (HostAnswers.class) {
				l = lib;
				if (l == null) {
					l = load();
					lib = l;
				}
			}
		}
		return l;
	}

	private static Object load() {
		try {
			Path file = HostDecompiler.libraryFile();
			if (file == null) {
				return "library not found";
			}
			return new Lib(SymbolLookup.libraryLookup(file, Arena.global()));
		}
		catch (VirtualMachineError e) {
			throw e;
		}
		catch (Throwable t) {
			return t.toString();
		}
	}

	/** True when the library with the answer store is loaded and {@link #configure}d. */
	public static boolean available() {
		return CONFIGURED.get() && lib instanceof Lib;
	}

	/**
	 * True when the library with the answer store can be loaded (the limits may not be set yet).
	 * @return whether {@link #configure} can succeed
	 */
	public static boolean loadable() {
		return lib() instanceof Lib;
	}

	/**
	 * Sets the limits of the store (the first call; later calls change them). Memory and disk are
	 * the library's own: the Java heap holds none of an answer.
	 * @param ramBytes the most bytes held in memory
	 * @param diskBytes the most bytes held in temporary files of {@code dir}
	 * @param entryMax the most bytes of one answer
	 * @param dir where the temporary files go (deleted when closed, also after a crash)
	 * @return whether the store is usable
	 */
	public static boolean configure(long ramBytes, long diskBytes, long entryMax, Path dir) {
		if (!(lib() instanceof Lib l)) {
			return false;
		}
		try (Arena a = Arena.ofConfined()) {
			byte[] d = dir.toString().getBytes(StandardCharsets.UTF_8);
			MemorySegment seg = a.allocate(Math.max(1, d.length));
			MemorySegment.copy(d, 0, seg, JAVA_BYTE, 0, d.length);
			int rc = (int) l.configure.invokeExact(ramBytes, diskBytes, entryMax, seg,
				(long) d.length);
			if (rc == 0) {
				CONFIGURED.set(true);
			}
			return rc == 0;
		}
		catch (Throwable t) {
			Msg.warn(HostAnswers.class, "answer store: configure: " + t);
			return false;
		}
	}

	/** A page of a stored answer: its text from the offset asked, the total and the metadata. */
	public record Page(String text, long totalChars, byte[] meta) {
	}

	/**
	 * Reads {@code maxChars} characters of the stored text of {@code key} from character
	 * {@code offset}.
	 * @return the page, or null on a miss (or when the store is unavailable)
	 */
	public static Page read(byte[] key, long offset, int maxChars) {
		if (!available()) {
			return null;
		}
		Lib l = (Lib) lib;
		try (Arena a = Arena.ofConfined()) {
			MemorySegment k = a.allocate(Math.max(1, key.length));
			MemorySegment.copy(key, 0, k, JAVA_BYTE, 0, key.length);
			MemorySegment total = a.allocate(JAVA_LONG);
			MemorySegment copied = a.allocate(JAVA_LONG);
			MemorySegment metalen = a.allocate(JAVA_LONG);
			// a probe first: a miss (every decompile that is not a stored page) costs no buffers
			int rc = (int) l.read.invokeExact(k, (long) key.length, 2L * offset,
				MemorySegment.NULL, 0L, total, copied, MemorySegment.NULL, 0L, metalen);
			if (rc != 0) {
				return null;
			}
			long ml = metalen.get(JAVA_LONG, 0);
			long left = Math.max(0, total.get(JAVA_LONG, 0) - 2L * offset);
			long cap = Math.min(2L * Math.max(0, maxChars), left);
			if (ml > META_CAP) {
				return null;
			}
			MemorySegment out = a.allocate(Math.max(2, cap));
			MemorySegment meta = a.allocate(Math.max(1, ml));
			rc = (int) l.read.invokeExact(k, (long) key.length, 2L * offset, out, cap, total,
				copied, meta, ml, metalen);
			if (rc != 0 || metalen.get(JAVA_LONG, 0) != ml) {
				return null;	// evicted or replaced in between: the caller decompiles
			}
			long n = copied.get(JAVA_LONG, 0) & ~1L;
			char[] chars = new char[(int) (n / 2)];
			ByteBuffer.wrap(out.asSlice(0, n).toArray(JAVA_BYTE)).order(ByteOrder.LITTLE_ENDIAN)
					.asCharBuffer().get(chars);
			return new Page(new String(chars), total.get(JAVA_LONG, 0) / 2,
				meta.asSlice(0, ml).toArray(JAVA_BYTE));
		}
		catch (Throwable t) {
			Msg.warn(HostAnswers.class, "answer store: read: " + t);
			return null;
		}
	}

	/** Drops the stored answer of {@code key}. */
	public static void remove(byte[] key) {
		if (!available()) {
			return;
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment k = a.allocate(Math.max(1, key.length));
			MemorySegment.copy(key, 0, k, JAVA_BYTE, 0, key.length);
			((Lib) lib).remove.invokeExact(k, (long) key.length);
		}
		catch (Throwable t) {
			Msg.warn(HostAnswers.class, "answer store: remove: " + t);
		}
	}

	/** Drops every stored answer. */
	public static void clear() {
		if (available()) {
			try {
				((Lib) lib).clear.invokeExact();
			}
			catch (Throwable t) {
				Msg.warn(HostAnswers.class, "answer store: clear: " + t);
			}
		}
	}

	/**
	 * The counters: RAM used, disk used, entries, hits, misses, evicted, puts, rejected, RAM
	 * limit, disk limit; null when unavailable.
	 */
	public static long[] stats() {
		if (!available()) {
			return null;
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment s = a.allocate(10 * 8L, 8);
			((Lib) lib).stats.invokeExact(s);
			return s.toArray(JAVA_LONG);
		}
		catch (Throwable t) {
			return null;
		}
	}

	/**
	 * Starts storing an answer.
	 * @param key what the answer is for
	 * @return the writer, or null when the store is unavailable
	 */
	public static Writer begin(byte[] key) {
		if (!available()) {
			return null;
		}
		Lib l = (Lib) lib;
		try (Arena a = Arena.ofConfined()) {
			MemorySegment k = a.allocate(Math.max(1, key.length));
			MemorySegment.copy(key, 0, k, JAVA_BYTE, 0, key.length);
			long t = (long) l.begin.invokeExact(k, (long) key.length);
			return t == 0 ? null : new Writer(l, t);
		}
		catch (Throwable t) {
			Msg.warn(HostAnswers.class, "answer store: begin: " + t);
			return null;
		}
	}

	/**
	 * An answer being written: collects text and passes it to the store in large blocks. After the
	 * store refuses a block (too big, no room) the writer drops everything further and
	 * {@link #commit} returns false.
	 */
	public static final class Writer implements PartialMarkup.Sink {
		private final Lib l;
		private final long ticket;
		private final StringBuilder buf = new StringBuilder(FLUSH_CHARS + 256);
		private boolean dead;
		private boolean done;

		private Writer(Lib l, long ticket) {
			this.l = l;
			this.ticket = ticket;
		}

		@Override
		public void accept(String s) {
			if (dead || done) {
				return;
			}
			buf.append(s);
			if (buf.length() >= FLUSH_CHARS) {
				flush();
			}
		}

		private void flush() {
			if (buf.length() == 0 || dead) {
				buf.setLength(0);
				return;
			}
			char[] c = new char[buf.length()];
			buf.getChars(0, c.length, c, 0);
			buf.setLength(0);
			ByteBuffer bb = ByteBuffer.allocate(c.length * 2).order(ByteOrder.LITTLE_ENDIAN);
			bb.asCharBuffer().put(c);
			try (Arena a = Arena.ofConfined()) {
				MemorySegment seg = a.allocate(bb.capacity());
				MemorySegment.copy(bb.array(), 0, seg, JAVA_BYTE, 0, bb.capacity());
				int rc = (int) l.append.invokeExact(ticket, seg, (long) bb.capacity());
				if (rc != 0) {
					dead = true;	// the store discarded the answer
					done = true;
				}
			}
			catch (Throwable t) {
				dead = true;
				abort();
			}
		}

		/**
		 * Stores the answer.
		 * @param meta bytes kept with it (returned by {@link HostAnswers#read})
		 * @return whether it was stored
		 */
		public boolean commit(byte[] meta) {
			if (done) {
				return false;
			}
			flush();
			if (dead) {
				return false;
			}
			done = true;
			try (Arena a = Arena.ofConfined()) {
				MemorySegment seg = a.allocate(Math.max(1, meta.length));
				MemorySegment.copy(meta, 0, seg, JAVA_BYTE, 0, meta.length);
				return (int) l.commit.invokeExact(ticket, seg, (long) meta.length) == 0;
			}
			catch (Throwable t) {
				return false;
			}
		}

		/** Discards the answer (a no-op after {@link #commit}). */
		public void abort() {
			if (done) {
				return;
			}
			done = true;
			dead = true;
			try {
				l.abort.invokeExact(ticket);
			}
			catch (Throwable t) {
				// nothing to release if the call itself failed
			}
		}
	}
}
