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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

/**
 * A client's private annotation view of a shared program: names, labels, comments, function
 * signatures and data types that only this client sees, never saved, over the program every
 * other client reads.
 * <p>
 * Ghidra has no per-client view of one {@link Program} object: a change in a program is a change
 * for everyone who holds that object. An overlay is therefore its <b>own</b> program object,
 * opened from the same stored file with {@code DomainFile.getReadOnlyDomainObject}, which Ghidra
 * documents as "a new domain object that is disassociated from its original domain file": it can
 * be changed, never saved back. Its database reads the stored file's buffers and keeps changed
 * buffers in its own temporary file, so it costs one more open of the program (no copy of the
 * project) plus the memory of a second program object; see the README for measurements.
 * <p>
 * Every change goes through {@code apply_overlay} as a list of operations, which is kept as a
 * <b>log</b>: it is what {@code promote_overlay} replays into a writable working copy, and what
 * rebuilds the overlay when its project view is refreshed. An operation that fails rolls back
 * the whole call and leaves the overlay as it was; the shared program is a different object and
 * is never touched.
 */
final class Overlay implements Decompilers, DecompilerGate.Pool {

	final Client client;
	final String name;
	final ProgramEntry base;
	/** {@code <client id>|<program key>|<name>}. */
	final String id;
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	final long createdAt = System.currentTimeMillis();

	// guarded by lock.writeLock() for writes
	Program program;
	/**
	 * The shared read-only program this overlay reads through until it needs a program of its own
	 * (an <b>empty</b> overlay over a read-only program is exactly that program: its log is empty,
	 * so applying it changes nothing, and the base cannot be written). The overlay is a consumer
	 * of it, so the entry may let go of it (a read-only program opened writable, a refresh) while
	 * the overlay keeps its snapshot. Null once {@link #program} is opened, and when the base is
	 * not shareable (a program open writable with unsaved changes) from the start.
	 */
	Program shared;
	/** When the program came from the upgrade cache: the view of the copy and its locks. */
	SessionProject view;
	UpgradeCache.Lease lease;
	/** The operations applied so far, in order (each with its {@code op} name). */
	final JsonArray log = new JsonArray();
	/** Bumped by every successful {@code apply_overlay}. */
	volatile int version;
	/**
	 * Set when something other than the annotation log may have changed the program's memory (an
	 * overlay script; the log's operations are annotations only). Until then the overlay's memory
	 * is the stored image the base program holds, so the decompile host maps the base program's
	 * byte snapshot instead of writing another copy of the same bytes.
	 */
	volatile boolean bytesChanged;
	volatile long openMs;
	/** What the overlay is over: the program's SHA-256, revision and project. */
	volatile String sha256;
	volatile String programRevision;
	volatile String projectRevision;
	volatile int generation;
	/** Set when a rebuild (after a refresh) could not reapply the log; the overlay is unusable. */
	volatile String error;

	/** A pooled decompiler and when it was put back (E9: idle ones are disposed). */
	private record Pooled(DecompInterface d, long atNanos) {
	}

	private final Deque<Pooled> decompilers = new ArrayDeque<>();

	Overlay(Client client, String name, ProgramEntry base) {
		this.client = client;
		this.name = name;
		this.base = base;
		this.id = id(client, base.key, name);
		DecompilerGate.track(this);
	}

	static String id(Client c, String programKey, String name) {
		return c.id + "|" + programKey + "|" + name;
	}

	/**
	 * The program this overlay shows: its own object when it has been opened, else the shared
	 * read-only program it reads through (an empty overlay). Null when the overlay is unusable
	 * (a failed open or a refresh that could not reapply it). Held: the read or write lock.
	 */
	Program readProgram() {
		Program p = program;
		return p != null ? p : shared;
	}

	@Override
	public Program program() {
		return readProgram();
	}

	/**
	 * The program whose memory is this overlay's memory: the base program while the overlay only
	 * carries annotations (its own program reads the same stored file), else the overlay's own.
	 * @return the program to snapshot, or null while the overlay has none
	 */
	Program snapshotSource() {
		if (bytesChanged) {
			return readProgram();
		}
		Program p = base.program;
		return p != null && !p.isClosed() ? p : readProgram();
	}

	/** A decompiler for the overlay's program, after a permit of the decompiler gate (E9). */
	@Override
	public DecompInterface borrowDecompiler() {
		DecompilerGate.Permit permit = DecompilerGate.enter();
		try {
			DecompInterface d = null;
			synchronized (decompilers) {
				Pooled p = decompilers.poll();
				if (p != null) {
					if (p.d().getProgram() == readProgram()) {
						d = p.d();
					}
					else {
						// built on the shared program before this overlay got one of its own
						// (the shared program was then given up: a decompiler on it would fail
						// with "File is closed")
						DecompilerGate.dispose(p.d());
					}
				}
			}
			if (d == null) {
				d = ProgramEntry.newDecompiler(readProgram(), base.path);
			}
			DecompilerGate.attach(d, permit);
			return d;
		}
		catch (Throwable t) {
			permit.release();
			throw t;
		}
	}

	@Override
	public void returnDecompiler(DecompInterface d, boolean healthy) {
		try {
			if (!healthy || d.getProgram() != readProgram()) {
				DecompilerGate.dispose(d);
				return;
			}
			synchronized (decompilers) {
				decompilers.push(new Pooled(d, System.nanoTime()));
			}
		}
		finally {
			DecompilerGate.leave(d);
		}
	}

	@Override
	public int disposeIdle(long cutoffNanos) {
		List<DecompInterface> gone = new ArrayList<>();
		synchronized (decompilers) {
			decompilers.removeIf(p -> {
				if (p.atNanos() - cutoffNanos < 0) {
					gone.add(p.d());
					return true;
				}
				return false;
			});
		}
		gone.forEach(DecompilerGate::dispose);
		return gone.size();
	}

	@Override
	public int idle() {
		synchronized (decompilers) {
			return decompilers.size();
		}
	}

	/**
	 * Disposes the pooled decompilers. Used when the overlay gives up the program they were built
	 * on (the shared program, before it opens its own): a decompiler on a closed program fails
	 * with "File is closed".
	 */
	void dropDecompilers() {
		synchronized (decompilers) {
			decompilers.forEach(p -> DecompilerGate.dispose(p.d()));
			decompilers.clear();
		}
	}

	/** Releases the program object and what holds it. Held: the write lock. */
	void dispose() {
		synchronized (decompilers) {
			decompilers.forEach(p -> DecompilerGate.dispose(p.d()));
			decompilers.clear();
		}
		try {
			if (program != null) {
				program.release(this);
			}
		}
		finally {
			program = null;
			Program s = shared;
			shared = null;
			if (s != null) {
				// one consumer more while the overlay read through it (see OverlayCommands)
				s.release(this);
			}
			if (view != null) {
				try {
					view.close();
				}
				catch (RuntimeException e) {
					// closing anyway
				}
				view = null;
			}
			if (lease != null) {
				lease.release();
				lease = null;
			}
		}
	}

	/** {@code overlay} in answers and {@code status}. */
	JsonObject describe() {
		JsonObject o = Json.of("name", name, "program", base.key, "client", client.id,
			"overlayVersion", version, "ops", log.size(), "sha256", sha256, "programRevision",
			programRevision, "projectRevision", projectRevision, "gpr",
			base.project.resolved.gpr().getPath(), "openMs", openMs, "ageMs",
			System.currentTimeMillis() - createdAt);
		Json.put(o, "stale", generation != base.project.generation);
		Json.put(o, "error", error);
		Json.put(o, "changed", program != null && program.isChanged());
		if (program instanceof ProgramDB db &&
			db.getUndoDepth() != ProgramDB.DEFAULT_UNDO_DEPTH) {
			// lightOverlays (PrivateInstance.lighten): only shown when it differs from the
			// default, so a default overlay's info is identical to before
			Json.put(o, "undoDepth", db.getUndoDepth());
		}
		return o;
	}
}
