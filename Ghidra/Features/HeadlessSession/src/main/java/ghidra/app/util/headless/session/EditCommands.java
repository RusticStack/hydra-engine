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

import static ghidra.app.util.headless.session.Addresses.address;

import java.io.*;
import java.util.*;

import com.google.gson.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.*;

/**
 * Changes to a program a client owns or shares: {@code edit}, {@code journal},
 * {@code discard_edits}, {@code save} and {@code analyze}, and the journal of
 * who changed what (the commands {@code rename} and {@code comment} are the
 * {@link Operations} journalled by {@link #journal}).
 */
final class EditCommands {

	private final Session s;

	EditCommands(Session s) {
		this.s = s;
		Advertised.capability("idempotency", 1);
	}

	/** Names who last changed the value a {@code changed} conflict is about. */
	static SessionException withLastEditor(ProgramEntry e, SessionException ex) {
		JsonObject d = ex.details();
		if (!ex.code().equals(SessionException.CONFLICT) || d == null || !d.has("reason") ||
			!"changed".equals(d.get("reason").getAsString())) {
			return ex;
		}
		String f = d.get("field").getAsString();
		// the journal's own name for the field (Journal.fieldOf): signature and data_type edits
		// (protocol 3 conflicts) have their own, everything else that conflicts is a name or a comment
		JsonObject last = e.journal.lastAt(d.get("address").getAsString(),
			f.equals("name") ? "name" : f.equals("signature") ? "signature"
					: f.equals("type") ? "data_type"
							: "comment:" + (d.has("type") ? d.get("type").getAsString() : "eol"));
		if (last == null && f.equals("comment")) {
			for (String t : List.of("eol", "pre", "post", "plate", "repeatable")) {
				last = last != null ? last
						: e.journal.lastAt(d.get("address").getAsString(), "comment:" + t);
			}
		}
		if (last != null) {
			d.add("lastEdit", last.deepCopy());
			d.add("holderInfo", Json.of("client", last.get("client"), "name", last.get("name"),
				"harness", last.get("harness"), "command", last.get("cmd"), "seq",
				last.get("seq")));
		}
		Json.put(d, "suggest", "reread");
		return ex;
	}

	/** Journals a committed change by {@code c}; returns the result with its {@code seq}. */
	static JsonObject journal(Client c, ProgramEntry e, String cmd, String op,
			JsonObject result) {
		return journal(c, e, cmd, op, result, null);
	}

	/**
	 * Journals a committed change by {@code c}, carrying the idempotency key {@code rk} of its
	 * request (protocol 3; null for none). The key goes into the journal entry only, never into
	 * the reply.
	 */
	static JsonObject journal(Client c, ProgramEntry e, String cmd, String op, JsonObject result,
			String rk) {
		JsonObject change = result.deepCopy();
		Json.put(change, "op", op);
		if (rk != null) {
			Json.put(change, "rk", rk);
		}
		if (change.has("name") && !change.has("new")) {
			change.add("new", change.get("name"));
		}
		if (change.has("text") && !change.has("new")) {
			change.add("new", change.get("text"));
		}
		long seq = e.journal.add(c, cmd, change);
		Json.put(result, "seq", seq);
		return result;
	}

	/**
	 * {@code edit}: operations on a program this client may change (as owner or shared writer),
	 * applied in one transaction, all or none, and journalled.
	 */
	JsonElement editProgram(Client c, ProgramEntry e, JsonArray ops, JsonObject req) {
		boolean v3 = c.v3();
		String rk = null;
		if (v3) { // behaviour gate 1: rk and requireExpect exist for a protocol 3 connection only
			rk = rkOf(req);
			if (rk != null) {
				List<JsonObject> done = e.journal.byRk(rk);
				if (!done.isEmpty()) {
					return replayed(e, rk, done, ops.size(), true);
				}
			}
			requireExpect(e, ops);
		}
		JsonArray results = s.operations.applyOps(e.program, ops, v3);
		JsonArray seqs = new JsonArray();
		for (JsonElement r : results) {
			JsonObject o = r.getAsJsonObject();
			journal(c, e, "edit", o.get("op").getAsString(), o, rk);
			seqs.add(o.get("seq"));
		}
		return Json.of("program", e.key, "applied", ops.size(), "results", results, "seqs", seqs,
			"unsavedEdits", e.journal.seq() - e.savedSeq);
	}

	/**
	 * {@code rename} and {@code comment}: one operation, journalled. A protocol 3 request may carry
	 * an idempotency key {@code rk} and, when {@code requireExpect} is set, must carry
	 * {@code expect} on a program with shared writers.
	 */
	JsonElement single(Client c, ProgramEntry e, String cmd, JsonObject req) throws Exception {
		String rk = null;
		if (c.v3()) {
			rk = rkOf(req);
			if (rk != null) {
				List<JsonObject> done = e.journal.byRk(rk);
				if (!done.isEmpty()) {
					return replayed(e, rk, done, 1, false);
				}
			}
			JsonArray one = new JsonArray();
			JsonObject op = req.deepCopy();
			op.addProperty("op", cmd);
			one.add(op);
			requireExpect(e, one);
		}
		JsonObject r = cmd.equals("rename") ? s.operations.renameIn(e.program, req)
				: s.operations.commentIn(e.program, req);
		return journal(c, e, cmd, cmd, r, rk);
	}

	/**
	 * The idempotency key of a request: a string of 1 to 64 characters, or null when the request
	 * has none (a JSON null is none). Anything else is {@code bad_request}. Called for protocol 3
	 * requests only.
	 */
	static String rkOf(JsonObject req) {
		if (!Json.has(req, "rk")) {
			return null;
		}
		JsonElement k = req.get("rk");
		if (!k.isJsonPrimitive() || !k.getAsJsonPrimitive().isString() ||
			k.getAsString().isEmpty() || k.getAsString().length() > 64) {
			throw SessionException.badRequest(true,
				"rk must be a string of 1 to 64 characters", "rk", null);
		}
		return k.getAsString();
	}

	/**
	 * A request whose {@code rk} the journal already holds is not applied again: the answer is
	 * <i>reconstructed</i> from the stored per-op results (the journal keeps the entries, not the
	 * reply envelope), so it promises those fields and not byte equality with the first reply. If
	 * fewer entries are held than the request has operations, part of them was evicted, and the
	 * whole key is refused ({@code rk_expired}), never partly replayed.
	 */
	private static JsonElement replayed(ProgramEntry e, String rk, List<JsonObject> done,
			int expectedOf, boolean multi) {
		if (done.size() < expectedOf) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"the idempotency key " + rk + " was applied, but only " + done.size() + " of its " +
					expectedOf + " journal entries are still held (the journal drops the oldest " +
					"entries): it cannot be replayed",
				Json.of("reason", "rk_expired", "rk", rk, "foundOf", done.size(), "expectedOf",
					expectedOf));
		}
		if (!multi) {
			JsonObject first = done.get(0);
			return Json.of("replayed", true, "seq", first.get("seq"), "result", first);
		}
		JsonArray results = new JsonArray();
		JsonArray seqs = new JsonArray();
		for (JsonObject d : done) {
			results.add(d);
			seqs.add(d.get("seq"));
		}
		return Json.of("replayed", true, "program", e.key, "applied", done.size(), "seqs", seqs,
			"results", results, "unsavedEdits", e.journal.seq() - e.savedSeq);
	}

	/**
	 * {@code requireExpect} (the {@code -set requireExpect=true} policy, protocol 3 only): an edit
	 * of a program that has shared writers must say what it expects to replace, on every
	 * {@code rename}, {@code label}, {@code comment}, {@code signature} and {@code data_type}.
	 * A program with one owner needs none: there is nobody to collide with.
	 */
	private static void requireExpect(ProgramEntry e, JsonArray ops) {
		if (e.mode != ProgramEntry.Mode.SHARED || !Settings.bool("requireExpect", false)) {
			return;
		}
		int i = 0;
		for (JsonElement el : ops) {
			if (el.isJsonObject() && !el.getAsJsonObject().has("expect") && el.getAsJsonObject()
					.has("op") && el.getAsJsonObject().get("op").isJsonPrimitive() &&
				List.of("rename", "label", "comment", "signature", "data_type")
						.contains(el.getAsJsonObject().get("op").getAsString())) {
				SessionException ex = SessionException.badRequest(true,
					"ops[" + i + "]: " + e.key + " has shared writers and this daemon requires " +
						"\"expect\" on every edit (requireExpect): say what you expect to replace" +
						" (null for nothing)",
					"expect", null);
				Json.put(ex.details(), "index", i);
				throw ex;
			}
			i++;
		}
	}

	/** {@code journal}: who changed what in a program, oldest first. */
	JsonElement journalOf(ProgramEntry e, JsonObject req) {
		long after = Json.num(req, "since", 0, 0, Long.MAX_VALUE);
		Integer client = Json.has(req, "author") ? (int) Json.num(req, "author", 0, 0,
			Integer.MAX_VALUE) : null;
		int limit = (int) Json.num(req, "limit", 10_000, 1, Journal.CAP);
		JsonArray a = e.journal.since(after, client, limit);
		return Json.of("program", e.key, "seq", e.journal.seq(), "savedSeq", e.savedSeq,
			"dropped", e.journal.dropped(), "entries", a, "returned", a.size());
	}

	/**
	 * {@code discard_edits}: reverts one client's unsaved changes (rename, label, comment), newest
	 * first, each only while the value is still what that client wrote: a value someone changed
	 * since is kept and reported. Analysis and script changes cannot be reverted one by one
	 * (close with {@code discard}, or not at all).
	 */
	JsonElement discardEdits(Client c, ProgramEntry e, JsonObject req) throws Exception {
		if (!Json.has(req, "author")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"missing field: author (the client id whose changes to revert, as in the journal)");
		}
		int who = (int) Json.num(req, "author", 0, 0, Integer.MAX_VALUE);
		Program p = e.program;
		JsonArray reverted = new JsonArray();
		JsonArray skipped = new JsonArray();
		List<JsonObject> todo = e.journal.newestFirst(e.savedSeq);
		Set<String> later = new HashSet<>(); // fields someone else changed after
		for (JsonObject j : todo) {
			String op = j.get("op").getAsString();
			String field = Journal.fieldOf(j);
			String addr = j.has("address") ? j.get("address").getAsString() : null;
			boolean mine = j.get("client").getAsInt() == who;
			if (!mine || op.equals("revert")) {
				if (addr != null) {
					later.add(addr + "|" + field);
				}
				continue;
			}
			long seq = j.get("seq").getAsLong();
			if (addr == null || !(op.equals("rename") || op.equals("label") ||
				op.equals("comment"))) {
				skipped.add(Json.of("seq", seq, "op", op, "reason", "not revertible"));
				continue;
			}
			if (later.contains(addr + "|" + field)) {
				skipped.add(Json.of("seq", seq, "op", op, "address", addr, "reason",
					"changed since by another client"));
				continue;
			}
			later.add(addr + "|" + field);
			Address a = address(p, addr);
			String nv = j.has("new") && !j.get("new").isJsonNull() ? j.get("new").getAsString()
					: null;
			String ov = j.has("old") && !j.get("old").isJsonNull() ? j.get("old").getAsString()
					: null;
			JsonObject undo;
			if (op.equals("comment")) {
				undo = Json.of("address", addr, "type", j.get("type"), "text", ov, "expect", nv);
				journal(c, e, "discard_edits", "comment", s.operations.commentIn(p, undo));
			}
			else if (j.has("created") && j.get("created").getAsBoolean()) {
				int tx = p.startTransaction("discard_edits");
				boolean ok = false;
				try {
					Symbol s = p.getSymbolTable().getPrimarySymbol(a);
					if (s == null || !s.getName().equals(nv)) {
						skipped.add(Json.of("seq", seq, "op", op, "address", addr, "reason",
							"the label is not there any more"));
						ok = true;
						continue;
					}
					s.delete();
					ok = true;
				}
				finally {
					p.endTransaction(tx, ok);
				}
				journal(c, e, "discard_edits", "label",
					Json.of("address", addr, "old", nv, "name", ov, "deleted", true));
			}
			else {
				undo = Json.of("address", addr, "name", ov, "kind", j.get("kind"), "expect", nv);
				journal(c, e, "discard_edits", op, s.operations.renameIn(p, undo));
			}
			reverted.add(seq);
		}
		return Json.of("program", e.key, "author", who, "reverted", reverted, "skipped", skipped,
			"unsavedEdits", e.journal.seq() - e.savedSeq);
	}

	JsonElement save(ProgramEntry e, JsonObject req, RequestMonitor m)
			throws IOException, CancelledException {
		boolean changed = e.program.isChanged();
		long upTo = e.journal.seq();
		if (changed) {
			e.program.save(Json.str(req, "comment", "headless session"), m);
			e.stampRevision();
			e.project.invalidateRevision();
			e.savedSeq = upTo;
		}
		return Json.of("program", e.key, "saved", changed, "revision", e.revision,
			"projectRevision", e.project.revision(), "savedSeq", e.savedSeq);
	}

	/**
	 * The window's <i>Analysis &gt; Auto Analyze</i>, the same way {@code analyzeHeadless} runs
	 * it: optional analysis options first, then all analyzers (or those triggered by a restricted
	 * address set) in this thread, under one transaction.
	 */
	JsonElement analyze(ProgramEntry e, JsonObject req, RequestMonitor m) {
		Program p = e.program;
		JsonObject opts = Json.obj(req, "options");
		if (opts != null) {
			setAnalysisOptions(p, opts);
		}
		AddressSet restrict = null;
		if (Json.has(req, "ranges")) {
			restrict = new AddressSet();
			for (JsonElement r : req.getAsJsonArray("ranges")) {
				JsonArray pair = r.getAsJsonArray();
				restrict.add(address(p, pair.get(0).getAsString()),
					address(p, pair.get(1).getAsString()));
			}
		}
		m.deadline(Json.num(req, "timeout", 0, 0, 7 * 86_400));
		long t0 = System.nanoTime();
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
		int tx = p.startTransaction("Analysis");
		try {
			mgr.initializeOptions();
			mgr.reAnalyzeAll(restrict);
			mgr.startAnalysis(m);
			if (m.isCancelled()) {
				mgr.cancelQueuedTasks();
			}
			else {
				GhidraProgramUtilities.markProgramAnalyzed(p);
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
		if (m.isCancelled()) {
			throw new SessionException(SessionException.CANCELLED,
				"analysis stopped " + (m.timedOut() ? "at its timeout" : "on cancel") +
					"; what ran so far is kept in memory (unsaved)",
				Json.of("program", e.key));
		}
		return Json.of("program", e.key, "analyzed", true, "seconds",
			(System.nanoTime() - t0) / 1e9, "functions", p.getFunctionManager().getFunctionCount(),
			"changed", p.isChanged());
	}

	private static void setAnalysisOptions(Program p, JsonObject opts) {
		Options options = p.getOptions(Program.ANALYSIS_PROPERTIES);
		int tx = p.startTransaction("session analysis options");
		try {
			for (Map.Entry<String, JsonElement> o : opts.entrySet()) {
				String n = o.getKey();
				if (!options.contains(n)) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"no analysis option named '" + n + "'");
				}
				OptionType t = options.getType(n);
				JsonElement v = o.getValue();
				switch (t) {
					case BOOLEAN_TYPE -> options.setBoolean(n, v.getAsBoolean());
					case INT_TYPE -> options.setInt(n, v.getAsInt());
					case LONG_TYPE -> options.setLong(n, v.getAsLong());
					case DOUBLE_TYPE -> options.setDouble(n, v.getAsDouble());
					case STRING_TYPE -> options.setString(n, v.getAsString());
					default -> throw new SessionException(SessionException.BAD_REQUEST,
						"option '" + n + "' has type " + t + ", which a session cannot set; " +
							"use a script");
				}
			}
		}
		finally {
			p.endTransaction(tx, true);
		}
	}
}
