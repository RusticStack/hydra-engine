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

import static ghidra.app.util.headless.session.Access.lockProject;
import static ghidra.app.util.headless.session.Requests.cancelled;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import generic.hash.HashUtilities;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.*;

/**
 * {@code import}: a file into a writable project, queued by the
 * {@link ImportGate} and deduplicated by SHA-256.
 */
final class ImportCommands {

	private final Session s;

	ImportCommands(Session s) {
		this.s = s;
	}

	/**
	 * Imports a file (any format a Ghidra loader accepts: PE EXE or DLL, ELF, Mach-O, raw, ...)
	 * into a writable project and opens it writable for the caller. A file whose SHA-256 is
	 * already in that project is not imported again unless {@code "duplicate":true}.
	 */
	JsonElement importProgram(Client c, JsonObject req, RequestMonitor m) {
		ProjectEntry p = s.access.projectFor(c, req);
		if (!p.writable()) {
			throw new SessionException(SessionException.READ_ONLY,
				"import needs project " + p.id +
					" open writable (open_project \"writable\":true)");
		}
		File file = new File(Json.str(req, "file")).getAbsoluteFile();
		if (!file.isFile()) {
			throw new SessionException(SessionException.NOT_FOUND, "no such file: " + file);
		}
		String folder = Json.str(req, "folder", "/");
		String sha;
		try {
			sha = HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, file);
		}
		catch (IOException ex) {
			throw new SessionException(SessionException.FAILED, ex.getMessage(), null, ex);
		}
		// Imports run in parallel up to maxImports (each load is handed its project; nothing on
		// the load path reads the process-wide active project). Queue in arrival order without
		// holding a slot (the wait is unlimited unless "wait" is a number), then take the long
		// slot for this import's own work.
		boolean limited = Json.has(req, "wait") && !(req.get("wait").isJsonPrimitive() &&
			req.getAsJsonPrimitive("wait").isBoolean());
		long deadline = limited ? System.nanoTime() + waitMs(req) * 1_000_000L : Long.MAX_VALUE;
		// The same file into the same project at once: the second waits for the first and then
		// finds its result by SHA-256, so the file is imported once.
		InFlightImport mine = null;
		JsonObject sameFile = null;
		if (!Json.bool(req, "duplicate", false)) {
			String key = p.id + ":" + sha.toLowerCase(Locale.ROOT);
			InFlightImport claim = new InFlightImport(Caller.label(c));
			long t0 = System.currentTimeMillis();
			for (InFlightImport other; (other = importsInFlight.putIfAbsent(key, claim)) != null;) {
				sameFile = Json.of("who", other.who, "file", file.getName());
				awaitSameImport(other, sameFile, m, deadline);
				Json.put(sameFile, "waitedMs", System.currentTimeMillis() - t0);
			}
			mine = claim;
			mine.key = key;
		}
		ImportGate.Entry gate;
		try {
			gate = ImportGate.GLOBAL.enter(ImportGate.Kind.IMPORT, Caller.label(c), c.id, p.id,
				file.getName(), file.length(), m,
				limited ? Math.max(0, (deadline - System.nanoTime()) / 1_000_000L) : -1);
		}
		catch (RuntimeException ex) {
			finishInFlight(mine);
			throw ex;
		}
		Scheduler.Ticket slot = null;
		String saved;
		double importS;
		try {
			slot = s.scheduler.admit(c, "import", m, waitMs(req));
			long t0 = System.nanoTime();
			Lock pl = lockProject(p, false, waitMs(req), "import");
			try {
				if (!Json.bool(req, "duplicate", false)) {
					List<String> same = new ArrayList<>();
					findBySha(p.data().getRootFolder(), sha, same);
					if (!same.isEmpty()) {
						JsonObject r = Json.of("imported", false, "project", p.id, "sha256", sha);
						Json.put(r, "existing", same);
						Json.put(r, "note", "already in the project; open_program it, or pass " +
							"\"duplicate\":true to import again");
						Json.put(r, "queue", gate.describeWait());
						if (sameFile != null) {
							Json.put(r, "sameFileImport", sameFile);
						}
						return r;
					}
				}
				MessageLog log = new MessageLog();
				try {
					DomainFolder dest =
						ProjectDataUtils.createDomainFolderPath(p.data().getRootFolder(), folder);
					ProgramLoader.Builder b = ProgramLoader.builder()
							.source(file)
							.project(p.project)
							.projectFolderPath(dest.getPathname())
							.log(log)
							.monitor(m);
					if (Json.has(req, "name")) {
						b.name(Json.str(req, "name"));
					}
					if (Json.has(req, "language")) {
						b.language(Json.str(req, "language"));
					}
					if (Json.has(req, "compiler")) {
						b.compiler(Json.str(req, "compiler"));
					}
					m.setMessage("importing " + file.getName());
					try (LoadResults<Program> results = b.load()) {
						saved = results.getPrimary().save(m).getPathname();
						p.invalidateRevision();
					}
					gate.succeeded();
				}
				catch (CancelledException ex) {
					throw cancelled(m);
				}
				catch (SessionException ex) {
					throw ex;
				}
				catch (Exception ex) {
					throw new SessionException(SessionException.FAILED,
						"import failed: " + ex.getMessage(), Json.of("log", log.toString()), ex);
				}
			}
			finally {
				gate.close(); // the next import may start; this one goes on to open and analyse
				finishInFlight(mine); // saved (or failed): a same-file import may check now
				pl.unlock();
			}
			importS = (System.nanoTime() - t0) / 1e9;
			JsonObject openReq = Json.of("path", saved, "writable", true, "project", p.id);
			if (req.has("wait")) {
				openReq.add("wait", req.get("wait"));
			}
			JsonObject info = (JsonObject) s.programCmds.openProgram(c, openReq, m);
			JsonObject r = Json.of("imported", true, "project", p.id, "path", saved, "key",
				p.id + ":" + saved, "sha256", sha, "importSeconds", importS, "program", info);
			Json.put(r, "queue", gate.describeWait());
			if (Json.bool(req, "analyze", false)) {
				JsonObject areq = Json.of("program", p.id + ":" + saved);
				if (req.has("timeout")) {
					areq.add("timeout", req.get("timeout"));
				}
				r.add("analysis", s.access.withProgram(c, areq, "analyze", true, true,
					e -> s.edits.analyze(e, areq, m)));
				r.add("save", s.access.withProgram(c, areq, "save", true, true,
					e -> s.edits.save(e, Json.of("comment", "import + analysis"), m)));
			}
			return r;
		}
		finally {
			gate.close();
			finishInFlight(mine);
			if (slot != null) {
				slot.close();
			}
		}
	}

	/** An import of one file into one project that has not saved its program yet. */
	private static final class InFlightImport {
		final String who;
		final CountDownLatch done = new CountDownLatch(1);
		String key;

		InFlightImport(String who) {
			this.who = who;
		}
	}

	/** Imports in flight by {@code "<project id>:<sha256>"} (not those with "duplicate"). */
	private final ConcurrentHashMap<String, InFlightImport> importsInFlight =
		new ConcurrentHashMap<>();

	private void finishInFlight(InFlightImport f) {
		if (f != null && f.key != null) {
			importsInFlight.remove(f.key, f);
			f.done.countDown();
		}
	}

	/**
	 * Waits until another import of the same file into the same project has saved (or failed),
	 * saying so in the request's progress; a cancel or the request's numeric {@code wait} ends
	 * the wait.
	 */
	private static void awaitSameImport(InFlightImport other, JsonObject info, RequestMonitor m,
			long deadline) {
		try {
			while (!other.done.await(100, TimeUnit.MILLISECONDS)) {
				if (m.isCancelled()) {
					throw new SessionException(SessionException.CANCELLED,
						"cancelled while waiting for " + other.who + "'s import of the same file");
				}
				if (deadline != Long.MAX_VALUE && System.nanoTime() - deadline >= 0) {
					throw new SessionException(SessionException.BUSY,
						other.who + " is importing the same file into this project; retry, or " +
							"pass a longer \"wait\"",
						info);
				}
				m.waiting("same file import", info);
				m.setMessage("waiting for " + other.who + "'s import of the same file " +
					"(the result is used instead of a second copy)");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new SessionException(SessionException.CANCELLED, "interrupted");
		}
		finally {
			m.waiting(null, null);
		}
	}

	private static void findBySha(DomainFolder folder, String sha, List<String> out) {
		for (DomainFile f : folder.getFiles()) {
			if (sha.equalsIgnoreCase(f.getMetadata().get("Executable SHA256"))) {
				out.add(f.getPathname());
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			findBySha(sub, sha, out);
		}
	}
}
