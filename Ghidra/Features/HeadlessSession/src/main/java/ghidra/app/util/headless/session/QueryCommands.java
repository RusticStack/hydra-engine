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
import ghidra.program.model.symbol.*;

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
		Pattern pat = null;
		if (Json.has(req, "regex")) {
			try {
				pat = Pattern.compile(Json.str(req, "regex"));
			}
			catch (PatternSyntaxException ex) {
				throw new SessionException(SessionException.BAD_REQUEST,
					"bad regex: " + ex.getMessage());
			}
		}
		String sub = Json.str(req, "contains", null);
		int limit = (int) Json.num(req, "limit", 200, 1, 10_000);
		int offset = (int) Json.num(req, "offset", 0, 0, Integer.MAX_VALUE);
		JsonArray a = new JsonArray();
		int seen = 0;
		boolean truncated = false;
		if (FunctionIndex.enabled()) {
			// Hydra (daemon-async): pages are slices of the program state's one shared listing
			FunctionIndex.Snapshot ix = FunctionIndex.of(prog);
			int n = ix.size();
			if (pat == null && sub == null) {
				int from = (int) Math.min(n, (long) offset);
				int to = (int) Math.min(n, (long) from + limit);
				for (int i = from; i < to; i++) {
					a.add(ix.row(i));
				}
				truncated = to < n;
			}
			else {
				for (int i = 0; i < n; i++) {
					String nm = ix.names[i];
					if (pat != null && !pat.matcher(nm).find()) {
						continue;
					}
					if (sub != null && !nm.contains(sub)) {
						continue;
					}
					if (seen++ < offset) {
						continue;
					}
					if (a.size() >= limit) {
						truncated = true;
						break;
					}
					a.add(ix.row(i));
				}
			}
			return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
				truncated);
		}
		for (Function f : prog.getFunctionManager().getFunctions(true)) {
			String n = f.getName(true);
			if (pat != null && !pat.matcher(n).find()) {
				continue;
			}
			if (sub != null && !n.contains(sub)) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (a.size() >= limit) {
				truncated = true;
				break;
			}
			a.add(Json.of("name", n, "address", hex(f.getEntryPoint()), "size",
				f.getBody().getNumAddresses(), "thunk", f.isThunk(), "external", f.isExternal()));
		}
		return Json.of("functions", a, "offset", offset, "returned", a.size(), "truncated",
			truncated);
	}

	/** The code of a decompile that failed in the native process (E9, 3.11): retryable. */
	static final String DECOMPILER_FAILED = "decompiler_failed";

	JsonElement decompile(Program prog, Decompilers e, JsonObject req,
			RequestMonitor m) {
		Function f = function(prog, req);
		int timeout = (int) Json.num(req, "timeout", 60, 1, 3600);
		int cap = (int) Json.num(req, "maxChars", DEFAULT_TEXT_CAP, 1, MAX_TEXT_CAP);
		Client caller = Caller.client();
		boolean v3 = caller != null && caller.v3();
		DecompileCache cache = DecompileCache.get();
		if (cache == null) {
			return fresh(prog, e, f, timeout, cap, v3, m, null, null);
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
					own[0] = fresh(prog, e, f, timeout, cap, v3, m, out, fault);
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
		JsonObject rep = fresh(prog, e, f, timeout, cap, v3, m, out, null);
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
		JsonObject r = Json.of("name", f.getName(true), "entry", hex(f.getEntryPoint()));
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
			boolean v3, RequestMonitor m, DecompileCache.Result[] out, boolean[] faultOut) {
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
		JsonObject hosted = HostDecompileBackend.tryDecompile(prog, f, timeout, cap);
		if (hosted != null) {
			return hosted;
		}
		DecompInterface d = e.borrowDecompiler();
		boolean healthy = false;
		try {
			DecompileResults res = d.decompileFunction(f, timeout, m);
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
			DecompileCache.Result done = new DecompileCache.Result(df.getSignature(), df.getC());
			if (out != null) {
				out[0] = done;
			}
			return reply(f, done, cap);
		}
		finally {
			e.returnDecompiler(d, healthy);
		}
	}

	private static SessionException failed(Function f, String reason, String message,
			long retryAfterMs, boolean negativeCache) {
		JsonObject d = Json.of("function", f.getName(true), "entry", hex(f.getEntryPoint()),
			"reason", reason, "retryable", true, "negativeCache", negativeCache);
		return new SessionException(DECOMPILER_FAILED, message, d).withRetryAfterMs(retryAfterMs);
	}
}
