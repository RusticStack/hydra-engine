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
import static ghidra.app.util.headless.session.Addresses.address;
import static ghidra.app.util.headless.session.EditCommands.journal;
import static ghidra.app.util.headless.session.Requests.DEFAULT_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.MAX_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.waitMs;

import java.io.*;
import java.lang.reflect.Method;
import java.util.concurrent.locks.Lock;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * {@code script}: runs a GhidraScript against a program or a project.
 */
final class ScriptCommands {

	private final Session s;

	ScriptCommands(Session s) {
		this.s = s;
	}

	private static final Object SCRIPT_COMPILE = new Object();

	/**
	 * Runs a GhidraScript (by name on the script path, or by file path) with a program as
	 * {@code currentProgram}, the way the window's Script Manager does, and returns what it
	 * printed.
	 * <ul>
	 * <li>On a program this client owns writable: exclusive, and its changes stay (unsaved unless
	 * {@code "save":true}).</li>
	 * <li>Otherwise <i>contained</i>: the script runs inside an outer transaction that is always
	 * rolled back, so it cannot change what other clients see or what is saved. Contained scripts
	 * share the program lock and run concurrently unless {@code "exclusive":true}.</li>
	 * <li>With {@code "program":null} (or no program open) it runs with no current program, with
	 * the client's active project (if any) as its project.</li>
	 * </ul>
	 * This is not a sandbox: a script is Java with the session's rights.
	 */
	JsonElement script(Client c, JsonObject req, RequestMonitor m) {
		String name = Json.str(req, "script");
		ResourceFile src = findScript(name);
		boolean noProgram = req.has("program") && req.get("program").isJsonNull();
		ProgramEntry e = (noProgram || (c.active == null && !req.has("program"))) ? null
				: s.access.selected(c, req);
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		if (e == null) {
			ProjectEntry p = null;
			if (Json.has(req, "project") || c.activeProject != null) {
				p = s.access.projectFor(c, req);
			}
			if (p == null) {
				return runScript(src, req, null, null, null, "none", m);
			}
			ProjectEntry pp = p;
			return s.access.inProject(p, req, "script",
				x -> runScript(src, req, pp.project, null, null, "none", m));
		}
		ProjectEntry p = e.project;
		Lock pl = lockProject(p, false, waitMs(req), "script");
		try {
			boolean owner = e.isWriter(c);
			boolean exclusive = owner || Json.bool(req, "exclusive", false);
			Lock l = e.acquire(exclusive, waitMs(req), c, "script " + name);
			try {
				if (e.program == null) {
					throw new SessionException(SessionException.NO_PROGRAM, e.key + " was closed");
				}
				owner = e.isWriter(c);
				JsonObject r = runScript(src, req, p.project, e.program, e,
					owner ? "owner" : "contained", m);
				if (owner && Json.bool(r, "changed", false)) {
					journal(c, e, "script", "script", Json.of("script", name));
				}
				if (owner && Json.bool(req, "save", false) && e.program.isChanged()) {
					e.savedSeq = e.journal.seq();
					e.program.save("script " + name, m);
					e.stampRevision();
					p.invalidateRevision();
					Json.put(r, "saved", true);
				}
				return r;
			}
			catch (CancelledException | IOException ex) {
				throw new SessionException(
					ex instanceof CancelledException ? SessionException.CANCELLED
							: SessionException.FAILED,
					ex.getMessage());
			}
			finally {
				e.release(l);
			}
		}
		finally {
			pl.unlock();
		}
	}

	static ResourceFile findScript(String name) {
		File f = new File(name);
		ResourceFile src = f.isAbsolute() || f.isFile() ? new ResourceFile(f.getAbsoluteFile())
				: GhidraScriptUtil.findScriptByName(name);
		if (src == null || !src.exists()) {
			throw new SessionException(SessionException.NOT_FOUND,
				"script not found: " + name + " (give a file path, or start the session " +
					"with -scriptPath)");
		}
		return src;
	}

	JsonObject runScript(ResourceFile src, JsonObject req, Project project, Program p,
			ProgramEntry e, String mode, RequestMonitor m) {
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw, true);
		GhidraScript s;
		synchronized (SCRIPT_COMPILE) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
			if (provider == null) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"no script provider for " + src.getName());
			}
			try {
				s = provider.getScriptInstance(src, pw);
			}
			catch (Exception ex) {
				pw.flush();
				throw new SessionException(SessionException.FAILED,
					"script did not load: " + ex.getMessage(), Json.of("output", sw.toString()),
					ex);
			}
		}
		s.setScriptArgs(Json.strings(req, "args").toArray(new String[0]));
		bindHeadless(s);
		ProgramLocation loc = null;
		if (p != null && Json.has(req, "address")) {
			loc = new ProgramLocation(p, address(p, Json.str(req, "address")));
		}
		GhidraState state = new GhidraState(null, project, p, loc, null, null);
		boolean contained = p != null && mode.equals("contained");
		// what this script changed, not whether the program had unsaved changes already (which a
		// shared program usually has): every change fires an event, which moves this number
		long modBefore = p == null ? 0 : p.getModificationNumber();
		int outer = -1;
		if (contained) {
			outer = p.startTransaction("session: contained script (rolled back)");
		}
		long t0 = System.nanoTime();
		Throwable failure = null;
		try {
			s.execute(state, new ScriptControls(pw, pw, false, m));
		}
		catch (Throwable t) {
			failure = t;
		}
		finally {
			if (contained) {
				p.endTransaction(outer, false);
			}
			pw.flush();
		}
		String out = sw.toString();
		JsonObject r = Json.of("script", src.getAbsolutePath(), "mode", mode, "program",
			e == null ? null : e.key, "seconds", (System.nanoTime() - t0) / 1e9, "chars",
			out.length(), "truncated", out.length() > cap, "output",
			out.length() > cap ? out.substring(0, cap) : out, "changed",
			p != null && !contained && p.getModificationNumber() != modBefore, "unsaved",
			p != null && p.isChanged());
		Json.put(r, "artifact", Json.str(req, "artifact", null));
		if (failure != null) {
			if (m.isCancelled() || failure instanceof CancelledException) {
				throw new SessionException(SessionException.CANCELLED,
					"script " + (m.timedOut() ? "timed out" : "cancelled"), r);
			}
			throw new SessionException(SessionException.FAILED,
				"script failed: " + failure.getClass().getSimpleName() + ": " +
					failure.getMessage(),
				r, failure);
		}
		return r;
	}

	/**
	 * Lets {@link HeadlessScript} subclasses run here as under {@code analyzeHeadless}
	 * ({@code storeHeadlessValue} and friends). The setter is package-private in Ghidra, so it is
	 * reached reflectively rather than by editing Ghidra's class.
	 */
	private static void bindHeadless(GhidraScript s) {
		if (!(s instanceof HeadlessScript hs)) {
			return;
		}
		try {
			Method set = HeadlessScript.class.getDeclaredMethod("setHeadlessInstance",
				HeadlessAnalyzer.class);
			set.setAccessible(true);
			set.invoke(hs, HeadlessAnalyzer.getInstance());
		}
		catch (ReflectiveOperationException | IOException | RuntimeException ex) {
			Msg.warn(Session.class, "HeadlessScript features unavailable: " + ex);
		}
	}
}
