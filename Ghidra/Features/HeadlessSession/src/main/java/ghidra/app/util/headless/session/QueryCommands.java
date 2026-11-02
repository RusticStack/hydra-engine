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
import static ghidra.app.util.headless.session.Addresses.hex;
import static ghidra.app.util.headless.session.Requests.DEFAULT_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.MAX_TEXT_CAP;
import static ghidra.app.util.headless.session.Requests.cancelled;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.UndefinedFunction;

/**
 * Read-only questions about a program: {@code functions} and {@code decompile}.
 */
final class QueryCommands {

	private final Session s;

	QueryCommands(Session s) {
		this.s = s;
	}

	private Function function(Program p, JsonObject req) {
		if (Json.has(req, "address")) {
			Address a = address(p, Json.str(req, "address"));
			Function f = p.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function contains " + hex(a), Json.of("address", hex(a)));
			}
			return f;
		}
		String name = Json.str(req, "name");
		List<Function> found = new ArrayList<>();
		for (Symbol s : p.getSymbolTable().getSymbols(name)) {
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				found.add((Function) s.getObject());
			}
		}
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.isEmpty()) {
			throw new SessionException(SessionException.NOT_FOUND, "no function named " + name);
		}
		List<String> at = new ArrayList<>();
		found.forEach(f -> at.add(hex(f.getEntryPoint())));
		JsonObject d = new JsonObject();
		Json.put(d, "candidates", at);
		throw new SessionException(SessionException.CONFLICT,
			"several functions are named " + name + "; pass an address", d);
	}

	JsonElement functions(Program prog, JsonObject req) {
		return functions(null, prog, req, false);
	}

	/**
	 * {@code functions}; with {@code raw} (the caller sends the result as it is, never edits it) a
	 * page served from a table may come from the Rust read plane as reply bytes
	 * ({@link ReadPlane.RawJson}).
	 */
	JsonElement functions(Program prog, JsonObject req, boolean raw) {
		return functions(null, prog, req, raw);
	}

	/**
	 * The {@code functions} page of {@code e} from a sealed table of the program's current state,
	 * answered before any lock is taken (a program state's listing is immutable once built, so
	 * reads need no lock and wait for no writer or analysis); null when there is none and the
	 * request takes the locked path. The request is validated first, so a bad argument gives the
	 * same error either way.
	 */
	JsonElement functionsSealed(ProgramEntry e, JsonObject req) {
		FunctionTable.Cache tables = FunctionTable.cache();
		if (tables == null || e.program == null || e.analysis != null) {
			return null;
		}
		JsonElement r;
		try {
			r = tables.sealed(e, regex(req), Json.str(req, "contains", null),
				(int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE),
				(int) Json.num(req, "limit", 200, 1, 10_000));
		}
		catch (SessionException bad) {
			return null; // the locked path gives the error, decorated as every command's
		}
		if (r != null) {
			e.project.lastUsed = System.currentTimeMillis();
		}
		return r;
	}

	private static Pattern regex(JsonObject req) {
		if (!Json.has(req, "regex")) {
			return null;
		}
		try {
			return Pattern.compile(Json.str(req, "regex"));
		}
		catch (PatternSyntaxException ex) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"bad regex: " + ex.getMessage());
		}
	}

	JsonElement functions(ProgramEntry e, Program prog, JsonObject req, boolean raw) {
		Pattern pat = regex(req);
		String sub = Json.str(req, "contains", null);
		int limit = (int) Json.num(req, "limit", 200, 1, 10_000);
		int offset = (int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE);
		// H1: one table per program state, shared by every request and view (FunctionTable)
		FunctionTable.Cache tables = FunctionTable.cache();
		if (tables == null) {
			// functionTable off: walk the database
			return FunctionTable.walk(prog, pat, sub, offset, limit);
		}
		return tables.functions(e, prog, pat, sub, offset, limit, Requests.waitMs(req), raw);
	}

	/** The code of a decompile that failed in the native process (E9, 3.11): retryable. */
	static final String DECOMPILER_FAILED = "decompiler_failed";

	/**
	 * The reply of a decompile of an address in the program's current state from
	 * {@link DecompileCache}, answered before any program or project lock is taken and reading
	 * nothing from the database but the modification number; null when there is no stored result
	 * for this exact address and state (the request then takes the locked path unchanged, with the
	 * same validation and errors).
	 * <p>
	 * Only a request that names an {@code address} can be answered so: a {@code name} needs the
	 * symbol table. The stored result is the one an earlier completed decompile of that function
	 * entry produced, rendered exactly as {@link #reply} renders a fresh one, with this request's
	 * {@code maxChars}.
	 */
	JsonElement decompileSealed(ProgramEntry e, JsonObject req) {
		DecompileCache cache = DecompileCache.get();
		Program p = e.program;
		if (cache == null || p == null || e.analysis != null || Json.has(req, "name") ||
			!Json.has(req, "address")) {
			return null;
		}
		int cap;
		Address a;
		try {
			// the locked path's own validation of these fields, so a bad value errors the same way
			Json.num(req, "timeout", 60, 1, 3600);
			cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
			resultCapBytes(req);
			a = address(p, Json.str(req, "address"));
		}
		catch (SessionException bad) {
			return null;
		}
		DecompileCache.Result r = cache.decompile(p, a);
		if (r == null) {
			return null;
		}
		e.project.lastUsed = System.currentTimeMillis();
		return reply(r.name(), hex(a), r, cap);
	}

	JsonElement decompile(Program prog, Decompilers e, JsonObject req,
			RequestMonitor m) {
		Function f = function(prog, req);
		int timeout = (int) Json.num(req, "timeout", 60, 1, 3600);
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		int capBytes = resultCapBytes(req);
		Client caller = Caller.client();
		boolean v3 = caller != null && caller.v3();
		DecompileCache cache = DecompileCache.get();
		if (cache == null) {
			return fresh(prog, e, f, timeout, cap, capBytes, v3, m, null, null);
		}
		// goal 4: an unchanged program's result is served from the cache, and N callers of one
		// function at once share one decompile; the reply is the one a fresh decompile gives
		DecompileCache.Key k = cache.key(prog, f);
		JsonObject[] own = new JsonObject[1];
		boolean[] led = { false };
		// a waiter waits no longer than this request could have taken on its own: a decompiler
		// permit (decompilerWaitS) plus its own timeout
		long waitNanos = TimeUnit.SECONDS.toNanos(timeout + (long) Budgets.decompilerWaitS());
		DecompileCache.Outcome o = cache.compute(k, m::isCancelled, waitNanos,
			prog::getModificationNumber, () -> {
				led[0] = true;
				DecompileCache.Result[] out = new DecompileCache.Result[1];
				boolean[] fault = { false };
				try {
					own[0] = fresh(prog, e, f, timeout, cap, capBytes, v3, m, out, fault);
				}
				catch (RuntimeException ex) {
					if (m.isCancelled()) {
						throw ex; // a cancelled leader: one of its waiters leads again
					}
					return new DecompileCache.Failure(
						new Flight(null, ex, v3, fault[0]));
				}
				if (out[0] != null) {
					return out[0];
				}
				return new DecompileCache.Failure(
					new Flight(own[0], null, v3, fault[0]));
			});
		if (led[0]) {
			if (own[0] != null) {
				return own[0];
			}
			if (o instanceof DecompileCache.Failure fl && fl.payload() instanceof Flight x &&
				x.error() != null) {
				throw x.error();
			}
			throw cancelled(m);
		}
		if (o == null) {
			throw cancelled(m);
		}
		if (o instanceof DecompileCache.Result r) {
			return reply(f, r, cap);
		}
		if (o == DecompileCache.WAIT_EXPIRED) {
			// this request's own budget passed while another request's decompile of the same
			// function ran: answered as a timeout of this request (not a fault of a process)
			String msg = "the decompile of " + f.getName(true) + " by another request did not " +
				"finish within this request's timeout (" + timeout + " s) and decompilerWaitS";
			if (v3) {
				throw failed(f, "timeout", msg + "; retry", 1000, false);
			}
			JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
			Json.put(r, "completed", false);
			Json.put(r, "error", msg);
			Json.put(r, "timedOut", true);
			return r;
		}
		// the leader's decompile did not complete. A deterministic answer (the decompiler
		// declined the function, or the breaker refused it) goes to every waiter of that flight
		// at once. A fault of the leader's process (a crash, a hang, a timeout) or an unexpected
		// error says nothing sure about this request: it decompiles itself, in parallel with the
		// other waiters, as it would without the cache (never N decompiles one after another)
		Flight x = (Flight) ((DecompileCache.Failure) o).payload();
		boolean reusable = x.v3() == v3 && !x.fault() &&
			(x.reply() != null || x.error() instanceof SessionException se &&
				DECOMPILER_FAILED.equals(se.code()));
		if (reusable) {
			if (x.reply() != null) {
				return x.reply().deepCopy();
			}
			SessionException se = (SessionException) x.error();
			throw se.rewrap(se.getMessage(), se.details() == null ? null : se.details().deepCopy());
		}
		DecompileCache.Result[] out = new DecompileCache.Result[1];
		JsonObject rep = fresh(prog, e, f, timeout, cap, capBytes, v3, m, out, null);
		if (out[0] != null) {
			cache.offer(k, out[0], prog::getModificationNumber);
		}
		return rep;
	}

	/**
	 * How the leader's decompile of a flight failed: its non-completed reply or its error, its
	 * protocol and whether it was a fault of the native process, which decide whether a waiter may
	 * answer the same.
	 */
	private record Flight(JsonObject reply, RuntimeException error, boolean v3, boolean fault) {
	}

	/** The reply of a completed decompile, fresh or cached (one shape for both). */
	private static JsonObject reply(Function f, DecompileCache.Result res, int cap) {
		return reply(f.getName(true), hex(f.getEntryPoint()), res, cap);
	}

	/** The reply of a completed decompile of the function called {@code name} at {@code entry}. */
	private static JsonObject reply(String name, String entry, DecompileCache.Result res, int cap) {
		JsonObject r = Json.of("name", name, "entry", entry);
		Json.put(r, "completed", true);
		String c = res.c();
		Json.put(r, "signature", res.signature());
		Json.put(r, "chars", c.length());
		Json.put(r, "truncated", c.length() > cap);
		Json.put(r, "c", c.length() > cap ? c.substring(0, cap) : c);
		return r;
	}

	/**
	 * A decompile by a native decompiler; a completed one also goes to {@code out[0]} (when
	 * {@code out} is given) for the cache.
	 */
	private JsonObject fresh(Program prog, Decompilers e, Function f, int timeout, int cap,
			int capBytes, boolean v3, RequestMonitor m, DecompileCache.Result[] out, boolean[] faultOut) {
		// E9: a function that crashed or hung the native process more than three times in a minute
		// is refused for ten minutes (the circuit breaker), before a permit or a process is spent
		long banned = DecompilerGate.Breaker.negativeLeftMs(prog, f);
		if (banned > 0) {
			String msg = "the decompiler failed on " + f.getName(true) + " repeatedly; it is " +
				"refused for " + (banned + 999) / 1000 + " more seconds";
			if (v3) {
				throw failed(f, "negative_cache", msg, banned, true);
			}
			JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
			Json.put(r, "completed", false);
			Json.put(r, "error", msg);
			Json.put(r, "timedOut", false);
			return r;
		}
		// Hydra: the optional host backend (hydra.decomp.backend=host); null = the process path
		// (a hosted result is a completed one; it then takes the same reply path as a process result)
		// Protocol 2 keeps the hydra.3 process path (its client may kill the decompiler by pid);
		// a protocol 3 client gets the host backend when it is enabled (the round 2 default).
		// A request that names its own response cap takes the process path, which enforces it.
		DecompileResults hosted =
			v3 && capBytes == 0 ? HostDecompileBackend.tryDecompile(prog, e, f, timeout) : null;
		DecompInterface d = hosted != null ? null : e.borrowDecompiler();
		boolean healthy = false;
		try {
			if (d != null && capBytes > 0) {
				d.setMaxResultBytes(capBytes);
			}
			DecompileResults res = hosted != null ? hosted : d.decompileFunction(f, timeout, m);
			if (m.isCancelled()) {
				throw cancelled(m);
			}
			JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
			boolean ok = res != null && res.decompileCompleted();
			Json.put(r, "completed", ok);
			if (!ok) {
				String err = res == null ? "no result" : res.getErrorMessage();
				boolean timedOut = res != null && res.isTimedOut();
				Json.put(r, "error", err);
				Json.put(r, "timedOut", timedOut);
				if (err != null && err.contains(RESPONSE_OVERFLOW)) {
					// the engine's response buffer (not max_characters) filled: a structured partial
					// result, not a fault of the process (the breaker is not tripped)
					int limit = capBytes > 0 ? capBytes
							: (d == null ? 50 : d.getOptions().getMaxPayloadMBytes()) << 20;
					Json.put(r, "truncated", true);
					Json.put(r, "bytes_emitted", limit);
					Json.put(r, "reason", "response_buffer");
					Json.put(r, "max_result_mb", limit % (1 << 20) == 0 ? (Object) (limit >> 20) : (Object) (limit / 1048576.0));
					Json.put(r, "max_result_bytes", limit);
					if (faultOut != null) {
						faultOut[0] = true; // the answer depends on this request's cap: not shared
					}
					return r;
				}
				if (timedOut) {
					Json.put(r, "reason", "timeout");
				}
				if (d != null && fragmentable(f, err)) {
					JsonObject fr = fragments(prog, d, f, timeout, cap, m);
					if (fr != null) {
						return fr;
					}
				}
				// the native process crashed, hung or timed out (not: the decompiler declined this
				// function with a message of its own, which is deterministic and harmless)
				boolean fault = res == null || timedOut || res.failedToStart() ||
					err != null && err.startsWith("Exception while decompiling");
				if (faultOut != null) {
					faultOut[0] = fault;
				}
				if (fault) {
					boolean tripped = DecompilerGate.Breaker.failed(prog, f);
					if (v3) {
						throw failed(f, timedOut ? "timeout" : "crash",
							"the native decompiler " + (timedOut ? "timed out" : "failed") + " on " +
								f.getName(true) + ": " + err + "; this request failed alone, retry",
							tripped ? DecompilerGate.Breaker.negativeMs() : 1000, tripped);
					}
				}
				return r;
			}
			healthy = true;
			DecompilerGate.Breaker.succeeded(prog, f);
			DecompiledFunction df = res.getDecompiledFunction();
			DecompileCache.Result done =
				new DecompileCache.Result(df.getSignature(), df.getC(), f.getName(true));
			if (out != null) {
				out[0] = done;
			}
			return reply(f, done, cap);
		}
		finally {
			if (d != null) {
				if (capBytes > 0) {
					d.setMaxResultBytes(0);
				}
				e.returnDecompiler(d, healthy);
			}
		}
	}

	/** The text of the native decompiler's error when its response buffer is over the cap. */
	static final String RESPONSE_OVERFLOW = "Response buffer size exceeded";
	/** Largest per-query response cap, in MB (the buffer is heap: {@code LinkedByteBuffer}). */
	static final int MAX_RESULT_MB = 512;

	/**
	 * The per-query cap on the native decompiler's response, in bytes, or 0 for the engine's own
	 * (50 MB). {@code maxResultMb} (alias {@code max_result_mb}) is whole megabytes from 1 to
	 * {@value #MAX_RESULT_MB}; {@code maxResultKb} (alias {@code max_result_kb}) is the same in
	 * kilobytes from 1 and wins when both are given. This is not {@code maxChars}, which cuts the
	 * text of an answer that already fit.
	 */
	static int resultCapBytes(JsonObject req) {
		String mb = Json.has(req, "maxResultMb") ? "maxResultMb" : "max_result_mb";
		String kb = Json.has(req, "maxResultKb") ? "maxResultKb" : "max_result_kb";
		if (Json.has(req, kb)) {
			return (int) (Json.num(req, kb, 0, 1, MAX_RESULT_MB * 1024L) << 10);
		}
		if (Json.has(req, mb)) {
			return (int) (Json.num(req, mb, 0, 1, MAX_RESULT_MB) << 20);
		}
		return 0;
	}

	/**
	 * Whether a failed decompile of {@code f} is the one a non-contiguous body gives: the decompiler
	 * flowed from a fragment into the gap between fragments (a pointer table, not code) and gave up.
	 */
	static boolean fragmentable(Function f, String err) {
		return err != null && f.getBody().getNumAddressRanges() > 1 &&
			(err.contains("Bad instruction count exceeded") ||
				err.contains("No pcode could be generated"));
	}

	/**
	 * Classifies one fragment of a function body: {@code code} when the listing has an instruction at
	 * its start; {@code data} when it starts with defined data or is a table of pointers into this
	 * program's memory; else {@code unknown}.
	 */
	static String classify(Program p, AddressRange r) {
		Listing l = p.getListing();
		if (l.getInstructionAt(r.getMinAddress()) != null) {
			return "code";
		}
		if (l.getDefinedDataAt(r.getMinAddress()) != null || pointerTable(p, r)) {
			return "data";
		}
		return "unknown";
	}

	private static boolean pointerTable(Program p, AddressRange r) {
		int ps = p.getDefaultPointerSize();
		if (ps != 4 && ps != 8) {
			return false;
		}
		long n = r.getLength() / ps;
		if (n < 2) {
			return false;
		}
		Memory mem = p.getMemory();
		AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
		try {
			for (long i = 0; i < Math.min(n, 64); i++) {
				Address at = r.getMinAddress().add(i * ps);
				long v = ps == 8 ? mem.getLong(at) : mem.getInt(at) & 0xffffffffL;
				if (!mem.contains(space.getAddress(v))) {
					return false;
				}
			}
		}
		catch (Exception ex) {
			return false;
		}
		return true;
	}

	/**
	 * The answer for a function whose non-contiguous body the whole-function decompile could not
	 * flow over: each fragment is classified and the code ones decompiled on their own (the entry
	 * fragment as the function, the others as undefined functions at their start), with the
	 * decompiler allowed enough bad-data stops to end at the gaps. {@code fragments} lists
	 * {@code {start, end, class, decompiled}} (and {@code chars} or {@code error}); a data
	 * fragment is skipped. Null when no fragment decompiled (the caller then reports the original
	 * failure).
	 */
	private JsonObject fragments(Program prog, DecompInterface d, Function f, int timeout, int cap,
			RequestMonitor m) {
		DecompileOptions o = d.getOptions();
		int oldBad = o.getMaxBadData();
		o.setMaxBadData(Math.max(oldBad, 512));
		d.setOptions(o);
		long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
		StringBuilder text = new StringBuilder();
		String signature = "";
		JsonArray frs = new JsonArray();
		int done = 0;
		try {
			for (AddressRange r : f.getBody()) {
				String cls = classify(prog, r);
				JsonObject fo = Json.of("start", hex(r.getMinAddress()), "end",
					hex(r.getMaxAddress()), "class", cls, "decompiled", false);
				frs.add(fo);
				text.append("/* fragment ").append(hex(r.getMinAddress())).append('-')
						.append(hex(r.getMaxAddress())).append(" (").append(cls).append(")");
				if (cls.equals("data")) {
					text.append(": skipped */\n");
					continue;
				}
				long left = TimeUnit.NANOSECONDS.toSeconds(end - System.nanoTime());
				if (left < 1 || m.isCancelled()) {
					Json.put(fo, "error", "not attempted: out of time");
					text.append(": not attempted */\n");
					continue;
				}
				boolean entry = r.contains(f.getEntryPoint());
				Function target = entry ? f : new UndefinedFunction(prog, r.getMinAddress());
				DecompileResults dr = d.decompileFunction(target, (int) left, m);
				if (dr != null && dr.decompileCompleted()) {
					String c = dr.getDecompiledFunction().getC();
					if (entry) {
						signature = dr.getDecompiledFunction().getSignature();
					}
					Json.put(fo, "decompiled", true);
					Json.put(fo, "chars", c.length());
					if (cls.equals("unknown")) {
						Json.put(fo, "class", "code");
					}
					text.append(" */\n").append(c).append('\n');
					done++;
				}
				else {
					String err = dr == null ? "no result" : dr.getErrorMessage();
					Json.put(fo, "error", err == null ? "failed" : err.strip());
					text.append(": ").append(dr != null && dr.isTimedOut() ? "timed out" : "failed")
							.append(" */\n");
					if (dr == null || dr.isTimedOut() || dr.failedToStart()) {
						break;
					}
				}
			}
		}
		finally {
			o.setMaxBadData(oldBad);
		}
		if (done == 0) {
			return null;
		}
		JsonObject r = reply(f.getName(true), hex(f.getEntryPoint()),
			new DecompileCache.Result(signature, text.toString(), f.getName(true)), cap);
		Json.put(r, "partial", true);
		Json.put(r, "reason", "non_contiguous_body");
		Json.put(r, "fragments", frs);
		return r;
	}

	private static SessionException failed(Function f, String reason, String message,
			long retryAfterMs, boolean negativeCache) {
		JsonObject d = Json.of("function", f.getName(true), "entry", hex(f.getEntryPoint()),
			"reason", reason, "retryable", true, "negativeCache", negativeCache);
		return new SessionException(DECOMPILER_FAILED, message, d).withRetryAfterMs(retryAfterMs);
	}
}
