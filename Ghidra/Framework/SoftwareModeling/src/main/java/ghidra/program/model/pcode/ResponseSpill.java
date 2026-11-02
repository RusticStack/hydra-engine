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
package ghidra.program.model.pcode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.function.LongSupplier;

/**
 * Hydra (issue 6): where the pages of a very large decompiler response go instead of the Java
 * heap, and the guard that watches the machine while that response is read.
 * <p>
 * A {@link LinkedByteBuffer} given a spill keeps the first {@link Config#thresholdBytes} bytes of
 * its response on the heap; every full page after that is appended to one temporary file and its
 * heap array is given back, so the response is no longer bounded by {@code -Xmx}. The decoder
 * reads a spilled page back from the file when its position reaches it (sequential reads go
 * through a 256 KB window, so the cost is one read per 256 KB, not one per page).
 * <p>
 * While the response is read the guard checks, about every megabyte, the physical memory still
 * free (a hard floor that is never crossed, so that other agents and projects are not starved),
 * the free space of the volume that holds the file, and the file's own quota. A check that fails
 * ends the read with an {@link IOException} that begins {@code Response buffer size exceeded}, the
 * message the cap itself gives, so the callers' existing structured "truncated" path answers; the
 * limit that tripped is {@link #tripped()}. What was received stays readable until
 * {@link #close()}, so the front of the C text can still be salvaged.
 * <p>
 * The file is opened {@code DELETE_ON_CLOSE}, so the operating system removes it when the
 * owner closes it or the process dies; {@link #sweepStale} also removes the files of a process
 * that is no longer alive (a crash on a system where delete-on-close does not survive it).
 */
public final class ResponseSpill implements AutoCloseable {

	/** What ended a response read early. */
	public enum Limit {
		NONE("none"), CAP("response_cap"), FREE_RAM("free_ram"), DISK_FREE("disk_free"),
		SPILL_QUOTA("spill_quota"), IO("spill_io");

		private final String id;

		Limit(String id) {
			this.id = id;
		}

		/** The name carried in a reply. */
		public String id() {
			return id;
		}
	}

	/**
	 * The settings of one spill.
	 *
	 * @param dir the folder of the temporary file (created on the first spill)
	 * @param thresholdBytes the response bytes kept on the heap before pages go to the file
	 * @param quotaBytes the most the file may hold
	 * @param hardFloorPhysMb the free physical memory, in MB, under which the read stops
	 * @param diskFloorMb the free space, in MB, of the file's volume under which the read stops
	 * @param freePhysMb the free physical memory now, in MB, or null for the operating system's
	 * @param freeDiskMb the free space now, in MB, of the file's volume, or null for the real one
	 * @param onFirstSpill run when the response first leaves the heap (null for nothing)
	 */
	public record Config(Path dir, long thresholdBytes, long quotaBytes, long hardFloorPhysMb,
			long diskFloorMb, LongSupplier freePhysMb, LongSupplier freeDiskMb,
			Runnable onFirstSpill) {
	}

	private static final int WRITE_BUFFER = 128 << 10;
	private static final int WINDOW = 256 << 10;
	private static final long CHECK_MAX = 1 << 20;
	private static final long CHECK_MIN = 16 << 10;
	/** The guard does not look at the machine before the response is this large (or the threshold). */
	private static final long GUARD_FROM = 8L << 20;
	private static final String PREFIX = "spill-";
	private static final String SUFFIX = ".bin";
	private static final java.util.concurrent.atomic.AtomicLong SEQ =
		new java.util.concurrent.atomic.AtomicLong();
	private static volatile boolean swept;

	private final Config cfg;
	private final long checkEvery;
	private final long guardFrom;
	private Path file;
	private FileChannel channel;
	private final byte[] wbuf = new byte[WRITE_BUFFER];
	private int wlen;
	private long flushed;		// bytes in the file
	private long appended;		// bytes handed to append (file plus write buffer)
	private byte[] window;
	private long windowOff = -1;
	private int windowLen;
	private long lastCheck;
	private volatile long ingested;
	private volatile Limit tripped = Limit.NONE;
	private volatile String detail = "";
	private boolean closed;

	public ResponseSpill(Config cfg) {
		this.cfg = cfg;
		this.checkEvery = Math.max(CHECK_MIN, Math.min(CHECK_MAX, cfg.thresholdBytes() / 4));
		this.guardFrom = Math.min(GUARD_FROM, cfg.thresholdBytes());
	}

	/** The bytes the heap keeps before pages go to the file. */
	public long threshold() {
		return cfg.thresholdBytes();
	}

	/** Whether any page of the response is in the file. */
	public boolean spilled() {
		return appended > 0;
	}

	/** The bytes of the response in the file. */
	public long spilledBytes() {
		return appended;
	}

	/** The response bytes seen by the guard so far (to within one check interval). */
	public long ingested() {
		return ingested;
	}

	/** The limit that ended the read, or {@link Limit#NONE}. */
	public Limit tripped() {
		return tripped;
	}

	/** Why it ended, in words. */
	public String detail() {
		return detail;
	}

	/** The settings. */
	public Config config() {
		return cfg;
	}

	/** The file, once the first page has been spilled; else null (for tests and the reply). */
	public Path file() {
		return file;
	}

	private IOException trip(Limit l, String why) {
		tripped = l;
		detail = why;
		return new IOException("Response buffer size exceeded for: spill guard (" + why + ")");
	}

	/**
	 * Appends one full page and returns its position in the file.
	 *
	 * @throws IOException {@code Response buffer size exceeded...} when the quota or the disk would
	 *             be passed, or the file cannot be written
	 */
	long append(byte[] page, int len) throws IOException {
		if (closed) {
			throw new IOException("spill closed");
		}
		if (appended + len > cfg.quotaBytes()) {
			throw trip(Limit.SPILL_QUOTA,
				"the spill file reached its quota of " + (cfg.quotaBytes() >> 20) + " MB");
		}
		try {
			if (channel == null) {
				open();
			}
			if (wlen + len > wbuf.length) {
				flush();
			}
			System.arraycopy(page, 0, wbuf, wlen, len);
			wlen += len;
		}
		catch (IOException | RuntimeException e) {
			if (e instanceof IOException io && tripped != Limit.NONE) {
				throw io;
			}
			throw trip(Limit.IO, "the spill file cannot be written: " + e);
		}
		long at = appended;
		appended += len;
		return at;
	}

	private void open() throws IOException {
		Files.createDirectories(cfg.dir());
		if (!swept) {
			sweepStale(cfg.dir());
		}
		file = cfg.dir().resolve(PREFIX + ProcessHandle.current().pid() + "-" +
			SEQ.incrementAndGet() + "-" + System.nanoTime() + SUFFIX);
		channel = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
			StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE);
		if (cfg.onFirstSpill() != null) {
			try {
				cfg.onFirstSpill().run();
			}
			catch (RuntimeException e) {
				// a failed scheduling hint never fails the response
			}
		}
	}

	private void flush() throws IOException {
		if (wlen > 0) {
			ByteBuffer b = ByteBuffer.wrap(wbuf, 0, wlen);
			while (b.hasRemaining()) {
				channel.write(b, flushed + b.position());
			}
			flushed += wlen;
			wlen = 0;
		}
	}

	/** Reads {@code len} bytes of the page at {@code off} of the file into {@code dst}. */
	void readPage(long off, byte[] dst, int len) throws IOException {
		if (closed) {
			throw new IOException("spill closed");
		}
		if (off + len > flushed) {
			flush();
		}
		if (window == null || off < windowOff || off + len > windowOff + windowLen) {
			if (window == null) {
				window = new byte[WINDOW];
			}
			ByteBuffer b = ByteBuffer.wrap(window);
			long pos = off;
			while (b.hasRemaining()) {
				int n = channel.read(b, pos);
				if (n < 0) {
					break;
				}
				pos += n;
			}
			windowOff = off;
			windowLen = b.position();
			if (windowLen < len) {
				throw new IOException("spill file shorter than expected");
			}
		}
		System.arraycopy(window, (int) (off - windowOff), dst, 0, len);
	}

	/**
	 * Called at every page boundary with the bytes read so far: about every megabyte it looks at
	 * the machine.
	 *
	 * @throws IOException {@code Response buffer size exceeded...} when a limit is passed
	 */
	void pageDone(long byteCount) throws IOException {
		ingested = byteCount;
		if (byteCount < guardFrom || byteCount - lastCheck < checkEvery) {
			return;
		}
		lastCheck = byteCount;
		long ram = cfg.freePhysMb() != null ? cfg.freePhysMb().getAsLong() : osFreeMb();
		if (ram >= 0 && ram < cfg.hardFloorPhysMb()) {
			throw trip(Limit.FREE_RAM, "free physical memory " + ram + " MB is under the safety floor of " +
				cfg.hardFloorPhysMb() + " MB");
		}
		if (appended > 0) {
			long disk = diskFreeMb();
			if (disk >= 0 && disk < cfg.diskFloorMb()) {
				throw trip(Limit.DISK_FREE, "free disk space " + disk + " MB on the spill volume is under the floor of " +
					cfg.diskFloorMb() + " MB");
			}
		}
	}

	private long diskFreeMb() {
		if (cfg.freeDiskMb() != null) {
			return cfg.freeDiskMb().getAsLong();
		}
		try {
			return Files.getFileStore(file != null ? file : cfg.dir()).getUsableSpace() >> 20;
		}
		catch (IOException | RuntimeException e) {
			return -1;
		}
	}

	/** The free physical memory in MB, or -1 when the system cannot say. */
	public static long osFreeMb() {
		try {
			if (java.lang.management.ManagementFactory
					.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean os) {
				return os.getFreeMemorySize() >> 20;
			}
		}
		catch (RuntimeException | LinkageError e) {
			// no figure
		}
		return -1;
	}

	/** The free space in MB of the volume of {@code dir} (or its nearest existing parent); -1 if unknown. */
	public static long usableMb(Path dir) {
		Path p = dir.toAbsolutePath();
		while (p != null && !Files.exists(p)) {
			p = p.getParent();
		}
		try {
			return p == null ? -1 : Files.getFileStore(p).getUsableSpace() >> 20;
		}
		catch (IOException | RuntimeException e) {
			return -1;
		}
	}

	/** Closes and deletes the file; safe to call twice. */
	@Override
	public void close() {
		if (closed) {
			return;
		}
		closed = true;
		window = null;
		try {
			if (channel != null) {
				channel.close();	// DELETE_ON_CLOSE removes the file
			}
		}
		catch (IOException e) {
			// deleted below
		}
		try {
			if (file != null) {
				Files.deleteIfExists(file);
			}
		}
		catch (IOException | RuntimeException e) {
			// the next sweep takes it
		}
	}

	/**
	 * Deletes the spill files of {@code dir} whose process is no longer alive (a crash that left
	 * one behind). Runs once per JVM on the first spill and at daemon start.
	 *
	 * @return how many files were removed
	 */
	public static int sweepStale(Path dir) {
		int n = 0;
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, PREFIX + "*" + SUFFIX)) {
			long me = ProcessHandle.current().pid();
			for (Path p : ds) {
				String name = p.getFileName().toString();
				String[] parts = name.substring(PREFIX.length()).split("-");
				long pid;
				try {
					pid = Long.parseLong(parts[0]);
				}
				catch (NumberFormatException e) {
					continue;
				}
				if (pid == me || ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
					continue;
				}
				try {
					if (Files.deleteIfExists(p)) {
						n++;
					}
				}
				catch (IOException e) {
					// held by something: next time
				}
			}
		}
		catch (IOException | RuntimeException e) {
			// no folder yet
		}
		swept = true;
		return n;
	}

	/** Whether {@link #sweepStale} has run in this JVM. */
	public static boolean swept() {
		return swept;
	}
}
