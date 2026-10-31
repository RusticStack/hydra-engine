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
import ghidra.util.Msg;

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
	/** When the program came from the upgrade cache: the reference on the copy's view, its locks. */
	UpgradeCache.ViewRef view;
	UpgradeCache.Lease lease;
	/** The operations applied so far, in order (each with its {@code op} name). */
	final JsonArray log = new JsonArray();
	/**
	 * The names and comments the log's operations changed while the overlay still read through
	 * {@link #shared} ({@link OverlayDelta}): the first changes are answered without opening the
	 * overlay's own program. Null once it has one; a later change applies to the program.
	 */
	OverlayDelta delta = new OverlayDelta();
	/** Bumped by every successful {@code apply_overlay}. */
	volatile int version;
	volatile long openMs;
	/** What the overlay is over: the program's SHA-256, revision and project. */
	volatile String sha256;
	volatile String programRevision;
	volatile String projectRevision;
	volatile int generation;
	/** Set when a rebuild (after a refresh) could not reapply the log; the overlay is unusable. */
	volatile String error;
	/** {@code -set overlayTiming=true}: log what opening, applying and disposing cost (a diagnostic). */
	final boolean timing;

	/** A pooled decompiler and when it was put back (E9: idle ones are disposed). */
	private record Pooled(DecompInterface d, long atNanos) {
	}

	private final Deque<Pooled> decompilers = new ArrayDeque<>();

	Overlay(Client client, String name, ProgramEntry base) {
		this.client = client;
		this.name = name;
		this.base = base;
		this.id = id(client, base.key, name);
		this.timing = Settings.bool("overlayTiming", false);
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

	/**
	 * Releases the overlay and what holds its program. Held: the write lock. The overlay is
	 * unusable at once (its program and view are already given up); closing its program object
	 * (the measured 1.5-2 ms of a close: the buffer manager and its scratch file) and its pooled
	 * decompilers happens on {@link #RECLAIM}, so a {@code drop_overlay} does not wait for them:
	 * nothing it answers with depends on them, and the next overlay of the same base opens its own
	 * program object any case.
	 */
	void dispose() {
		List<DecompInterface> gone = new ArrayList<>();
		synchronized (decompilers) {
			decompilers.forEach(pooled -> gone.add(pooled.d()));
			decompilers.clear();
		}
		Program p = program;
		Program s = shared;
		UpgradeCache.ViewRef v = view;
		UpgradeCache.Lease l = lease;
		program = null;
		shared = null;
		view = null;
		lease = null;
		delta = new OverlayDelta();
		if (s != null) {
			// one consumer more while the overlay read through it (see OverlayCommands); the
			// entry keeps it open, so this is a counter
			s.release(this);
		}
		if (timing) {
			Msg.info(this, "overlay " + name + " dispose handed over: " + gone.size() +
				" decompiler(s), program " + (p == null ? "none" : "open") + ", view " +
				(v == null ? "none" : "held") + ", lease " + (l == null ? "none" : "held"));
		}
		RECLAIM.reclaim(this, gone, p, v, l);
	}

	/** The one thread that finishes a disposed overlay: decompilers, program, view, lease. */
	private static final Reclaim RECLAIM = new Reclaim();

	private static final class Reclaim {
		private final java.util.concurrent.ExecutorService one =
			java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
				Thread t = new Thread(r, "session-overlay-reclaim");
				t.setDaemon(true);
				return t;
			});

		void reclaim(Overlay o, List<DecompInterface> gone, Program p, UpgradeCache.ViewRef v,
				UpgradeCache.Lease l) {
			if (gone.isEmpty() && p == null && v == null && l == null) {
				return;
			}
			one.execute(() -> {
				long t0 = System.nanoTime();
				gone.forEach(DecompilerGate::dispose);
				long t1 = System.nanoTime();
				try {
					if (p != null) {
						p.release(o);
					}
				}
				catch (RuntimeException ex) {
					Msg.warn(o, "overlay " + o.name + ": could not release its program", ex);
				}
				finally {
					long t2 = System.nanoTime();
					if (v != null) {
						v.close(); // the last reference closes the copy's project view
					}
					if (l != null) {
						l.release();
					}
					if (o.timing) {
						Msg.info(o, "overlay " + o.name + " reclaim us: decompilers " +
							(t1 - t0) / 1000 + ", program " + (t2 - t1) / 1000 +
							", view+lease " + (System.nanoTime() - t2) / 1000);
					}
				}
			});
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
		// its own program once it has one; before that, the changes its log holds (they are not in
		// the shared program, so nothing else shows them until the overlay opens its own)
		Json.put(o, "changed",
			program != null ? program.isChanged() : shared != null && !log.isEmpty());
		if (program instanceof ProgramDB db &&
			db.getUndoDepth() != ProgramDB.DEFAULT_UNDO_DEPTH) {
			// lightOverlays (PrivateInstance.lighten): only shown when it differs from the
			// default, so a default overlay's info is identical to before
			Json.put(o, "undoDepth", db.getUndoDepth());
		}
		return o;
	}
}
