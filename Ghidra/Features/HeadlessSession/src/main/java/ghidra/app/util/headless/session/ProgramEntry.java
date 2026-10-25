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

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

/**
 * One program open in the session, shared by every client that opened it.
 * <p>
 * <b>Mode.</b> An entry is either {@link Mode#READ_ONLY} (an unshared read-only instance; nothing
 * can be saved) or {@link Mode#WRITABLE} with exactly one {@link #owner}. Only the owner may edit,
 * analyse or save. Other clients may keep reading a writable program and then see the owner's
 * unsaved changes, as a second tool window would.
 * <p>
 * <b>Warm.</b> A read-only entry whose last user left stays open for the session's
 * {@code keepWarm} time, so the next client opens it at no cost and finds its decompilers warm.
 * <p>
 * <b>Lock.</b> Every command on the program holds {@link #lock}: reads share it, edits, analysis,
 * saves and mode changes hold it exclusively. A request that cannot get it within its
 * {@code wait} fails with {@code busy} and the current holder, instead of queueing forever.
 */
final class ProgramEntry {

	enum Mode {
		READ_ONLY, WRITABLE;

		String json() {
			return this == READ_ONLY ? "read_only" : "writable";
		}
	}

	final ProjectEntry project;
	final String path;
	/** {@code <project id>:<path>}: unique across the session's projects. */
	final String key;
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	/** When the last request on it finished, for warm retention. */
	volatile long lastUsed = System.currentTimeMillis();

	// guarded by lock.writeLock() for writes; read under the read lock
	DomainFile file;
	Program program;
	Mode mode;
	Client owner;
	long openMs;
	/**
	 * When {@link #program} was opened from the upgrade cache: the read-only view of the copy
	 * that holds it (closed with the program), its key, and what the cache did.
	 */
	SessionProject cacheView;
	String cacheKey;
	JsonObject cacheInfo;

	/** Clients using this program. Guarded by itself. */
	final Set<Client> users = new LinkedHashSet<>();

	/** What holds the exclusive lock now, for {@code busy} answers. */
	volatile String exclusiveHolder;
	volatile long exclusiveSince;

	/** Decompilers bound to {@link #program}, reused across requests. Guarded by itself. */
	private final Deque<DecompInterface> decompilers = new ArrayDeque<>();

	ProgramEntry(ProjectEntry project, String path) {
		this.project = project;
		this.path = path;
		this.key = project.id + ":" + path;
	}

	Lock acquire(boolean exclusive, long waitMs, Client c, String cmd) {
		Lock l = exclusive ? lock.writeLock() : lock.readLock();
		boolean got;
		try {
			got = l.tryLock(waitMs, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			got = false;
		}
		if (!got) {
			JsonObject d = Json.of("program", path, "wanted", exclusive ? "exclusive" : "shared",
				"waitedMs", waitMs);
			String holder = exclusiveHolder;
			if (holder != null) {
				Json.put(d, "holder", holder);
				Json.put(d, "heldMs", System.currentTimeMillis() - exclusiveSince);
			}
			else {
				Json.put(d, "readers", lock.getReadLockCount());
			}
			throw new SessionException(SessionException.BUSY,
				path + " is busy" + (holder != null ? " (" + holder + ")" : "") +
					"; retry, or pass a longer \"wait\"",
				d);
		}
		if (exclusive) {
			exclusiveHolder = c.label() + " " + cmd;
			exclusiveSince = System.currentTimeMillis();
		}
		return l;
	}

	void release(Lock l) {
		if (l == lock.writeLock()) {
			exclusiveHolder = null;
		}
		lastUsed = System.currentTimeMillis();
		l.unlock();
	}

	DecompInterface borrowDecompiler() {
		synchronized (decompilers) {
			DecompInterface d = decompilers.poll();
			if (d != null) {
				return d;
			}
		}
		DecompInterface d = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		d.setOptions(options);
		d.toggleCCode(true);
		d.toggleSyntaxTree(true);
		d.setSimplificationStyle("decompile");
		if (!d.openProgram(program)) {
			String msg = d.getLastMessage();
			d.dispose();
			throw new SessionException(SessionException.FAILED,
				"the decompiler would not open " + path + ": " + msg);
		}
		return d;
	}

	void returnDecompiler(DecompInterface d, boolean healthy) {
		if (!healthy || d.getProgram() != program) {
			d.dispose();
			return;
		}
		synchronized (decompilers) {
			decompilers.push(d);
		}
	}

	/** Called with the exclusive lock held, before {@link #program} is released or swapped. */
	void disposeDecompilers() {
		synchronized (decompilers) {
			for (DecompInterface d : decompilers) {
				d.dispose();
			}
			decompilers.clear();
		}
	}

	int userCount() {
		synchronized (users) {
			return users.size();
		}
	}

	JsonObject describeUse() {
		JsonObject o = Json.of("project", project.id, "path", path, "mode",
			mode == null ? null : mode.json(), "owner", owner == null ? null : owner.id,
			"idleMs", System.currentTimeMillis() - lastUsed);
		synchronized (users) {
			List<Integer> ids = new ArrayList<>();
			users.forEach(u -> ids.add(u.id));
			Json.put(o, "users", ids);
		}
		Json.put(o, "busy", exclusiveHolder);
		Json.put(o, "cachedUpgrade", cacheInfo != null);
		return o;
	}
}
