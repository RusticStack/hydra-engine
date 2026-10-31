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
import java.util.concurrent.locks.Lock;

import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

/**
 * A throwaway {@link Program} object opened from the <b>stored</b> file of a shared program
 * (PROTOCOL-3.md 3.6, package E4): the mechanism of an overlay's program object, extracted so that
 * {@code script} with {@code isolation:"private"} and {@code OverlayCommands.loadOverlay} share
 * one implementation. It reads the stored file only (or the upgrade cache copy when the shared
 * program came from the cache), never the unsaved edits of the shared program, and it is never
 * put into the {@code overlays} map. Its database keeps its changed buffers in its own temporary
 * file, so a script that changes it changes nothing anybody else sees and nothing on disk.
 * <p>
 * This is the read-only instance of revision 8: the writable, disposable clone of a saved view
 * that the killable worker uses (D64) is E7's and is a different object.
 * <p>
 * Use it as a try-with-resources: {@link #close} releases the program (the consumer is this
 * instance) and the upgrade cache view and lease, even when the script failed.
 */
final class PrivateInstance implements AutoCloseable {

	/**
	 * Config key (default false): overlays run light ({@link #lighten}). An overlay program is a
	 * read-only domain object that is never saved, checked in, merged or recovery snapshotted;
	 * promote replays the overlay's operation log on the target; the session never undoes an
	 * overlay (discard edits apply inverse operations), and a failed operation batch still rolls
	 * back. An overlay can run a GhidraScript ({@code script} op), which may undo: before one runs
	 * the overlay goes back to the default undo depth for the rest of its life
	 * ({@link #unlighten}). Off by default until proven identical on a full build.
	 */
	static final String LIGHT_OVERLAYS = "lightOverlays";
	/**
	 * Config key (default false): {@code isolation:"private"} script instances run light. Off by
	 * default because the script is arbitrary code that may undo more than one transaction.
	 */
	static final String LIGHT_PRIVATE_SCRIPTS = "lightPrivateScripts";

	/**
	 * Makes a disposable program object light: one undoable transaction instead of 50, so buffer
	 * pre-images of older transactions are released instead of kept in the disk cache (the
	 * measured gain). Transaction rollback is unaffected. Change recording stays on: scripts read
	 * {@code getChanges()} (RecoverClassesFromRTTIScript does) and turning it off showed no
	 * measured gain. Returns false (and changes nothing) for a program that is not a ProgramDB.
	 * Call it when no transaction is open.
	 */
	static boolean lighten(Program p) {
		if (!(p instanceof ProgramDB db)) {
			return false;
		}
		db.setUndoDepth(1);
		return true;
	}

	/**
	 * Undoes {@link #lighten}: back to the default undo depth (history already released stays
	 * released). No-op for a program that is not light. Call it when no transaction is open.
	 */
	static void unlighten(Program p) {
		if (p instanceof ProgramDB db && db.getUndoDepth() != ProgramDB.DEFAULT_UNDO_DEPTH) {
			db.setUndoDepth(ProgramDB.DEFAULT_UNDO_DEPTH);
		}
	}

	/** What was opened: the program object and what keeps its upgrade cache copy in place. */
	record Loaded(Program program, SessionProject view, UpgradeCache.Lease lease, long openMs) {
	}

	private Loaded loaded;
	/** The saved revision of the program the instance was opened over (may be null). */
	final String revision;
	/** The shared program's unsaved changes the instance does not show (journal entries). */
	final int unsavedIgnored;

	private PrivateInstance(Loaded loaded, String revision, int unsavedIgnored) {
		this.loaded = loaded;
		this.revision = revision;
		this.unsavedIgnored = unsavedIgnored;
	}

	Program program() {
		return loaded.program();
	}

	/** How long the open took, in milliseconds. */
	long openMs() {
		return loaded.openMs();
	}

	/**
	 * Opens the stored file of {@code e} as a new program object whose consumer is {@code consumer}
	 * (the caller releases it with {@code program.release(consumer)} and closes the view and the
	 * lease, as {@link Overlay#dispose} does). Held by the caller: whatever it needs to keep the
	 * shared program's file in place (see {@link #baseLock}).
	 *
	 * @throws SessionException {@code cancelled}, {@code conflict} (another Ghidra version),
	 *             {@code failed} (I/O)
	 */
	static Loaded load(UpgradeCache cache, ProgramEntry e, Object consumer, RequestMonitor m) {
		long t0 = System.nanoTime();
		Program prog = null;
		SessionProject view = null;
		UpgradeCache.Lease lease = null;
		DomainFile file = e.file;
		try {
			UpgradeCache.Plan plan = e.cachePlan;
			if (plan != null) {
				// also when the shared program was upgraded in memory (opened before the copy was
				// ready): the copy is ready now, and an in-memory upgrade costs ~300 ms per open of
				// KotOR (SymbolDatabaseAdapter.upgrade), the copy's open ~25 ms
				UpgradeCache.Opened op = null;
				try {
					op = cache.openReady(plan, consumer, m);
				}
				catch (IOException | VersionException ex) {
					if (e.cacheView != null) {
						throw ex;
					}
					// an instance of a program that was not served from the copy: the source
				}
				if (op != null) {
					prog = op.program();
					view = op.view();
					lease = op.lease();
				}
			}
			if (prog == null) {
				if (file == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				prog = (Program) file.getReadOnlyDomainObject(consumer,
					DomainFile.DEFAULT_VERSION, m);
			}
		}
		catch (CancelledException ex) {
			throw Requests.cancelled(m);
		}
		catch (VersionException ex) {
			throw new SessionException(SessionException.CONFLICT,
				e.path + " was saved by another Ghidra version: " + ex.getMessage());
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
		return new Loaded(prog, view, lease, (System.nanoTime() - t0) / 1_000_000);
	}

	/**
	 * Opens a private instance of {@code e}'s stored file and counts the unsaved edits of the
	 * shared program that it does not show. Held by the caller: whatever {@link #baseLock} gave.
	 */
	static PrivateInstance open(UpgradeCache cache, ProgramEntry e, RequestMonitor m) {
		String rev = e.revision;
		int ignored = unsavedEdits(e);
		PrivateInstance pi = new PrivateInstance(null, rev, ignored);
		pi.loaded = load(cache, e, pi, m);
		if (Settings.bool(LIGHT_PRIVATE_SCRIPTS, false)) {
			lighten(pi.loaded.program());
		}
		return pi;
	}

	/**
	 * The edits of the shared program that are not in its stored file: the journal entries since
	 * the last save here, and at least 1 when the program reports unsaved changes the journal
	 * does not account for. Unlocked reads of volatile and of lock-guarded fields, so a number
	 * taken while the program is being edited is an approximation, never an exception.
	 */
	static int unsavedEdits(ProgramEntry e) {
		long n = Math.max(0, e.journal.seq() - e.savedSeq);
		Program p = e.program;
		boolean changed = false;
		try {
			changed = p != null && p.isChanged();
		}
		catch (RuntimeException ex) {
			// closed meanwhile: nothing unsaved to speak of
		}
		return (int) Math.min(Integer.MAX_VALUE, n == 0 && changed ? 1 : n);
	}

	/**
	 * Whether the stored file of {@code e} is stable now although a request holds the program
	 * exclusively: a script or an analysis changes the program in memory and does not touch the
	 * stored file (a script's {@code save} is the exception, see the README). Any other holder
	 * ({@code save}, {@code reopen}, {@code refresh}, {@code open_program}, ...) may.
	 */
	private static boolean fileStableUnderHolder(ProgramEntry e) {
		String cmd = e.exclusiveCmd;
		return cmd != null && (cmd.startsWith("script") || cmd.equals("analyze"));
	}

	/**
	 * The shared lock that keeps the stored file of {@code e} in place while a private instance
	 * (or an overlay) is opened from it, or {@code null} when it is not needed: the program is
	 * held exclusively by a request that changes only the program in memory (BP24: opening an
	 * overlay used to fail {@code busy} for as long as the owner's script ran). Release a
	 * non-null result with {@link ProgramEntry#release}. A timed, cancel-aware wait otherwise.
	 */
	static Lock baseLock(ProgramEntry e, long waitMs, Client c, String cmd) {
		if (e.lock.isWriteLocked() && !e.lock.isWriteLockedByCurrentThread() &&
			fileStableUnderHolder(e)) {
			return null;
		}
		return e.acquire(false, waitMs, c, cmd);
	}

	@Override
	public void close() {
		Loaded l = loaded;
		loaded = null;
		if (l == null) {
			return;
		}
		try {
			l.program().release(this);
		}
		finally {
			if (l.view() != null) {
				l.view().close();
			}
			if (l.lease() != null) {
				l.lease().release();
			}
		}
	}
}
