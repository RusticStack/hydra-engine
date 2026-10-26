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
import java.util.Deque;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
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
final class Overlay implements Decompilers {

	final Client client;
	final String name;
	final ProgramEntry base;
	/** {@code <client id>|<program key>|<name>}. */
	final String id;
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	final long createdAt = System.currentTimeMillis();

	// guarded by lock.writeLock() for writes
	Program program;
	/** When the program came from the upgrade cache: the view of the copy and its locks. */
	SessionProject view;
	UpgradeCache.Lease lease;
	/** The operations applied so far, in order (each with its {@code op} name). */
	final JsonArray log = new JsonArray();
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

	private final Deque<DecompInterface> decompilers = new ArrayDeque<>();

	Overlay(Client client, String name, ProgramEntry base) {
		this.client = client;
		this.name = name;
		this.base = base;
		this.id = id(client, base.key, name);
	}

	static String id(Client c, String programKey, String name) {
		return c.id + "|" + programKey + "|" + name;
	}

	@Override
	public DecompInterface borrowDecompiler() {
		synchronized (decompilers) {
			DecompInterface d = decompilers.poll();
			if (d != null) {
				return d;
			}
		}
		return ProgramEntry.newDecompiler(program, base.path);
	}

	@Override
	public void returnDecompiler(DecompInterface d, boolean healthy) {
		if (!healthy || d.getProgram() != program) {
			d.dispose();
			return;
		}
		synchronized (decompilers) {
			decompilers.push(d);
		}
	}

	/** Releases the program object and what holds it. Held: the write lock. */
	void dispose() {
		synchronized (decompilers) {
			decompilers.forEach(DecompInterface::dispose);
			decompilers.clear();
		}
		try {
			if (program != null) {
				program.release(this);
			}
		}
		finally {
			program = null;
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
		return o;
	}
}
