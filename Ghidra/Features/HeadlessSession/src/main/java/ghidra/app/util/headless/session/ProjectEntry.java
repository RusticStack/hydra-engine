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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.JsonObject;

import ghidra.framework.model.ProjectData;

/**
 * One project open in the session, shared by every client that joined it. A session holds any
 * number of these at once, each with its own lock and programs, so work in one project never
 * waits on another.
 * <p>
 * <b>Lock.</b> Every command in the project holds {@link #lock} shared; closing the project or
 * reopening it writable holds it exclusively. The session's registry lock is taken before it.
 */
final class ProjectEntry {

	/** Short, stable for the life of this entry: {@code p1}, {@code p2}, ... */
	final String id;
	final ProjectResolver.Resolved resolved;
	/** The canonical path of the {@code .gpr}: two paths to one project are one entry. */
	final String canonical;
	final SessionProject project;
	final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
	final long openedAt = System.currentTimeMillis();
	final long openMs;

	/** Programs open in this project, by project path. */
	final Map<String, ProgramEntry> programs = new ConcurrentHashMap<>();
	/** Clients that joined it. Guarded by itself. */
	final Set<Client> users = new LinkedHashSet<>();
	/** When each user joined it (epoch ms), for holder records. */
	final Map<Client, Long> joinedAt = new ConcurrentHashMap<>();
	volatile long lastUsed = System.currentTimeMillis();
	volatile boolean closed;

	/** What holds {@link #lock} exclusively now (closing, refreshing), for {@code busy} answers. */
	volatile String exclusiveCmd;
	volatile Client exclusiveClient;
	volatile long exclusiveSince;

	ProjectEntry(String id, ProjectResolver.Resolved resolved, String canonical,
			SessionProject project, long openMs) {
		this.id = id;
		this.resolved = resolved;
		this.canonical = canonical;
		this.project = project;
		this.openMs = openMs;
	}

	boolean writable() {
		return project.isWritable();
	}

	ProjectData data() {
		if (closed) {
			throw new SessionException(SessionException.NO_PROJECT, "project " + id + " was closed");
		}
		return project.getProjectData();
	}

	/**
	 * This project's identity for error details: {@code project} (its id), {@code name},
	 * {@code gpr} and {@code writable}.
	 */
	JsonObject identity() {
		return Json.of("project", id, "name", resolved.name(), "gpr", resolved.gpr().getPath(),
			"writable", writable());
	}

	/** The clients that use it, other than {@code except}, as holder records. */
	com.google.gson.JsonArray holders(Client except) {
		com.google.gson.JsonArray a = new com.google.gson.JsonArray();
		synchronized (users) {
			for (Client u : users) {
				if (u != except) {
					a.add(u.holder(writable() ? "open_project writable" : "open_project read-only",
						joinedAt.getOrDefault(u, 0L)));
				}
			}
		}
		return a;
	}

	int userCount() {
		synchronized (users) {
			return users.size();
		}
	}

	JsonObject info() {
		JsonObject o = Json.of("id", id, "name", resolved.name(), "dir", resolved.dir().getPath(),
			"gpr", resolved.gpr().getPath(), "writable", writable(), "openMs", openMs,
			"idleMs", System.currentTimeMillis() - lastUsed);
		try {
			Json.put(o, "files", project.getProjectData().getFileCount());
		}
		catch (RuntimeException e) {
			Json.put(o, "files", null);
		}
		synchronized (users) {
			List<Integer> ids = new ArrayList<>();
			users.forEach(u -> ids.add(u.id));
			Json.put(o, "users", ids);
		}
		Json.put(o, "programs", programs.size());
		return o;
	}
}
