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

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * The Rust byte mover ({@code hydra_io_*} in {@code hydra_native}, module HydraNative): the copy
 * or hard link of the files of a fork and the flush of a staged tree, on native threads. Java
 * decides everything that is Ghidra's (which files are shared by hard link, which flushes the
 * process already did, the order intent, staged copy, flush, rename, intent clear); this class
 * only hands Rust a list and waits for the answer. Called with normal FFM downcalls.
 * <p>
 * Nothing is acknowledged early: {@link #flush} and {@link #copy} return only when the native job
 * has ended, and a job that fails or is cancelled has ended too (Rust finishes every started
 * operation before it reports), so a caller that removes the staging folder afterwards removes it
 * with no operation still running in it.
 * <p>
 * The module is optional, like {@link ReadPlane}: when the library is missing, has another I/O
 * ABI, or {@code -set nativeIo=false} (or {@code -Dhydra.nativeIo=false}), {@link #get} is null
 * and the callers keep their Java path.
 */
final class HydraIo {

	/** The {@code hydra_io_abi_version} this caller understands. */
	static final int ABI = 1;
	static final String SETTING = "nativeIo";
	static final String PROPERTY = "hydra.nativeIo";

	/** The flush kinds of the blob. */
	private static final int FLUSH_OWNED = 0, FLUSH_LINKED = 1, FLUSH_DIR = 2;
	/** The copy modes and flags of the blob. */
	private static final int MODE_COPY = 0, MODE_LINK = 1, MODE_MKDIR = 2;
	private static final int FLAG_FLUSH = 1, FLAG_SKIP_GONE = 2;
	/** The outcome bytes of a copy. */
	static final int OUT_COPIED = 0, OUT_LINKED = 1, OUT_SKIPPED = 2, OUT_COPIED_FLUSHED = 3,
			OUT_DIR = 4;
	private static final int JOB_RUNNING = 0, JOB_OK = 1;
	private static final int KIND_NOT_FOUND = 1, KIND_EXISTS = 2, KIND_CANCELLED = 4;

	/** How long a wait on a job blocks before the caller looks at its monitor again. */
	private static final int SLICE_MS = 25;

	private static final Linker LINKER = Linker.nativeLinker();

	/** Counters for {@code health.nativeIo}. */
	final AtomicLong flushJobs = new AtomicLong();
	final AtomicLong flushedFiles = new AtomicLong();
	final AtomicLong copyJobs = new AtomicLong();
	final AtomicLong copiedFiles = new AtomicLong();
	final AtomicLong failures = new AtomicLong();

	final String library;
	private final MethodHandle flushStart;
	private final MethodHandle copyStart;
	private final MethodHandle waitJob;
	private final MethodHandle progress;
	private final MethodHandle cancel;
	private final MethodHandle error;
	private final MethodHandle outcomes;
	private final MethodHandle free;

	private HydraIo(SymbolLookup l, String library) {
		this.library = library;
		FunctionDescriptor start = FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT);
		flushStart = LINKER.downcallHandle(l.findOrThrow("hydra_io_flush_start"), start);
		copyStart = LINKER.downcallHandle(l.findOrThrow("hydra_io_copy_start"), start);
		waitJob = LINKER.downcallHandle(l.findOrThrow("hydra_io_wait"),
			FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
		progress = LINKER.downcallHandle(l.findOrThrow("hydra_io_progress"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
		cancel = LINKER.downcallHandle(l.findOrThrow("hydra_io_cancel"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
		error = LINKER.downcallHandle(l.findOrThrow("hydra_io_error"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
		outcomes = LINKER.downcallHandle(l.findOrThrow("hydra_io_outcomes"),
			FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
				ValueLayout.JAVA_LONG));
		free = LINKER.downcallHandle(l.findOrThrow("hydra_io_free"),
			FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
	}

	private static volatile HydraIo instance;
	private static volatile boolean looked;

	/** The self-test sets this to run the Java path beside the native one. */
	static volatile boolean suspended;

	/** The module, or null when it is off or not available (the caller keeps its Java path). */
	static HydraIo get() {
		if (suspended) {
			return null;
		}
		if (!looked) {
			synchronized (HydraIo.class) {
				if (!looked) {
					instance = load();
					looked = true;
					HydraIo io = instance;
					Health.contribute("nativeIo", () -> io == null
							? Json.of("enabled", false)
							: Json.of("enabled", true, "library", io.library, "flushJobs",
								io.flushJobs.get(), "flushedFiles", io.flushedFiles.get(),
								"copyJobs", io.copyJobs.get(), "copiedFiles", io.copiedFiles.get(),
								"failures", io.failures.get()));
				}
			}
		}
		return instance;
	}

	private static HydraIo load() {
		if (!Settings.bool(SETTING, true) ||
			"false".equals(System.getProperty(PROPERTY, "true").trim())) {
			return null;
		}
		Path lib = ReadPlane.findLibrary();
		if (lib == null) {
			Msg.info(HydraIo.class, "native I/O off: hydra_native not found");
			return null;
		}
		try {
			SymbolLookup l = SymbolLookup.libraryLookup(lib, Arena.global());
			MethodHandle abi = LINKER.downcallHandle(l.findOrThrow("hydra_io_abi_version"),
				FunctionDescriptor.of(ValueLayout.JAVA_INT));
			int v = (int) abi.invokeExact();
			if (v != ABI) {
				Msg.warn(HydraIo.class, "native I/O off: " + lib + " has I/O ABI " + v + ", not " + ABI);
				return null;
			}
			return new HydraIo(l, lib.toString());
		}
		catch (Throwable t) {
			Msg.info(HydraIo.class, "native I/O off: " + lib + ": " + t);
			return null;
		}
	}

	// ---------------------------------------------------------------- flush

	/**
	 * Forces {@code owned} (copies this process wrote: a read-only one is made writable for the
	 * flush and read-only again), {@code linked} (files shared by hard link: attributes untouched,
	 * a read-only one is skipped) and then {@code dirs} to the disk, side by side on
	 * {@code threads} native threads. Returns true when every one is forced, or throws the first
	 * failure once every flush has ended. False when Rust could not take the list (a name that is
	 * not UTF-8, no thread): nothing was forced and the caller flushes in Java.
	 */
	boolean flush(Collection<Path> owned, Collection<Path> linked, Collection<Path> dirs,
			int threads) throws IOException {
		int n = owned.size() + linked.size() + dirs.size();
		if (n == 0) {
			return true;
		}
		Blob b = new Blob();
		b.u32(n);
		if (!(putFlush(b, FLUSH_OWNED, owned) && putFlush(b, FLUSH_LINKED, linked) &&
			putFlush(b, FLUSH_DIR, dirs))) {
			return false;
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment job = start(flushStart, a, b, threads);
			if (job == null) {
				return false;
			}
			flushJobs.incrementAndGet();
			flushedFiles.addAndGet(n);
			IOException failed;
			try {
				await(job, null);
				failed = failureOf(job, a);
			}
			catch (CancelledException e) {
				throw new IllegalStateException(e); // no monitor: cannot happen
			}
			finally {
				release(job);
			}
			if (failed != null) {
				failures.incrementAndGet();
				throw failed;
			}
			return true;
		}
	}

	private static boolean putFlush(Blob b, int kind, Collection<Path> paths) {
		for (Path p : paths) {
			b.u8(kind);
			if (!b.path(p)) {
				return false;
			}
		}
		return true;
	}

	// ---------------------------------------------------------------- copy

	/** One file of a copy: a link (copy when the file system cannot link) or a copy. */
	record Item(Path src, Path dst, long size, boolean link, boolean skipGone, boolean flush) {}

	/**
	 * Creates {@code folders} (in order), then copies or links {@code items} side by side on
	 * {@code threads} native threads, checking {@code m} while it waits; the files done are added
	 * to the monitor's progress. A cancelled monitor stops the job and throws once every started
	 * operation has ended. An item with {@code flush} is forced to the disk by the thread that
	 * copied it, as soon as it is copied (outcome {@link #OUT_COPIED_FLUSHED}), so the flush of a big
	 * file overlaps the copy of the next. Returns the outcome of each item ({@link #OUT_COPIED} and the others),
	 * or null when Rust could not take the list (nothing was done).
	 */
	byte[] copy(Collection<Path> folders, List<Item> items, int threads, RequestMonitor m)
			throws IOException, CancelledException {
		Blob b = new Blob();
		b.u32(folders.size() + items.size());
		for (Path d : folders) {
			b.u8(MODE_MKDIR);
			b.u8(0);
			b.u64(0);
			if (!b.paths(d, d)) {
				return null;
			}
		}
		for (Item it : items) {
			b.u8(it.link() ? MODE_LINK : MODE_COPY);
			b.u8((it.skipGone() ? FLAG_SKIP_GONE : 0) | (it.flush() ? FLAG_FLUSH : 0));
			b.u64(it.size());
			if (!b.paths(it.src(), it.dst())) {
				return null;
			}
		}
		try (Arena a = Arena.ofConfined()) {
			MemorySegment job = start(copyStart, a, b, threads);
			if (job == null) {
				return null;
			}
			copyJobs.incrementAndGet();
			copiedFiles.addAndGet(items.size());
			try {
				await(job, m);
				IOException failed = failureOf(job, a);
				if (failed != null) {
					throw failed;
				}
				MemorySegment out = a.allocate(Math.max(1, folders.size() + items.size()));
				long got = (long) outcomes.invokeExact(job, out, out.byteSize());
				byte[] all = new byte[(int) Math.min(got, out.byteSize())];
				MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, all, 0, all.length);
				return Arrays.copyOfRange(all, folders.size(), all.length);
			}
			catch (Throwable t) {
				failures.incrementAndGet();
				throw sneaky(t);
			}
			finally {
				release(job);
			}
		}
	}

	// ---------------------------------------------------------------- job plumbing

	private MemorySegment start(MethodHandle h, Arena a, Blob b, int threads) {
		byte[] bytes = b.toArray();
		MemorySegment seg = a.allocate(Math.max(1, bytes.length));
		MemorySegment.copy(bytes, 0, seg, ValueLayout.JAVA_BYTE, 0, bytes.length);
		try {
			MemorySegment job = (MemorySegment) h.invokeExact(seg, (long) bytes.length,
				Math.max(1, threads));
			return job.equals(MemorySegment.NULL) ? null : job;
		}
		catch (Throwable t) {
			Msg.warn(HydraIo.class, "native I/O: could not start a job: " + t);
			return null;
		}
	}

	/**
	 * Waits until the job has ended. With a monitor: it is checked every slice, the bytes done are
	 * added to its progress, and when it is cancelled the job is cancelled and waited for before
	 * the {@link CancelledException} goes up.
	 */
	private void await(MemorySegment job, RequestMonitor m) throws CancelledException {
		long reported = 0;
		try {
			while (true) {
				int st = (int) waitJob.invokeExact(job, m == null ? -1 : SLICE_MS);
				if (m != null) {
					long done = (long) progress.invokeExact(job);
					if (done > reported) {
						m.incrementProgress(done - reported);
						reported = done;
					}
				}
				if (st != JOB_RUNNING) {
					return;
				}
				if (m != null) {
					try {
						m.checkCancelled();
					}
					catch (CancelledException e) {
						cancel.invokeExact(job);
						while ((int) waitJob.invokeExact(job, 1000) == JOB_RUNNING) {
							// started operations end; nothing new starts
						}
						throw e;
					}
				}
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Throwable t) {
			throw sneaky(t);
		}
	}

	private void release(MemorySegment job) {
		try {
			free.invokeExact(job);
		}
		catch (Throwable t) {
			Msg.warn(HydraIo.class, "native I/O: could not free a job: " + t);
		}
	}

	/**
	 * The failure of an ended job as the exception the Java path would have thrown, or null when
	 * it did not fail. The job is still live: the caller frees it after.
	 */
	private IOException failureOf(MemorySegment job, Arena a) {
		try {
			MemorySegment kind = a.allocate(ValueLayout.JAVA_INT);
			MemorySegment msg = a.allocate(1024);
			long len = (long) error.invokeExact(job, kind, msg, msg.byteSize());
			if (len == 0 && kind.get(ValueLayout.JAVA_INT, 0) == 0) {
				return null;
			}
			String text = new String(msg.asSlice(0, Math.min(len, msg.byteSize()))
					.toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
			return switch (kind.get(ValueLayout.JAVA_INT, 0)) {
				case KIND_NOT_FOUND -> new NoSuchFileException(text);
				case KIND_EXISTS -> new FileAlreadyExistsException(text);
				case KIND_CANCELLED -> new IOException("cancelled: " + text);
				default -> new IOException(text);
			};
		}
		catch (Throwable t) {
			return new IOException("native I/O failed and its error could not be read: " + t);
		}
	}

	@SuppressWarnings("unchecked")
	private static <T extends Throwable> RuntimeException sneaky(Throwable t) throws T {
		throw (T) t;
	}

	/** A growing little-endian blob. */
	private static final class Blob {
		private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

		void u8(int v) {
			out.write(v);
		}

		void u32(int v) {
			for (int i = 0; i < 4; i++) {
				out.write(v >>> (8 * i));
			}
		}

		void u64(long v) {
			for (int i = 0; i < 8; i++) {
				out.write((int) (v >>> (8 * i)));
			}
		}

		/** One path with its length; false when its text is not representable in UTF-8. */
		boolean path(Path p) {
			byte[] raw = bytesOf(p);
			if (raw == null) {
				return false;
			}
			u32(raw.length);
			out.write(raw, 0, raw.length);
			return true;
		}

		/** Source and destination of a copy record: both lengths, then both texts. */
		boolean paths(Path src, Path dst) {
			byte[] s = bytesOf(src);
			byte[] d = bytesOf(dst);
			if (s == null || d == null) {
				return false;
			}
			u32(s.length);
			u32(d.length);
			out.write(s, 0, s.length);
			out.write(d, 0, d.length);
			return true;
		}

		private static byte[] bytesOf(Path p) {
			String text = p.toString();
			byte[] raw = text.getBytes(StandardCharsets.UTF_8);
			return new String(raw, StandardCharsets.UTF_8).equals(text) ? raw : null;
		}

		byte[] toArray() {
			return out.toByteArray();
		}
	}
}
