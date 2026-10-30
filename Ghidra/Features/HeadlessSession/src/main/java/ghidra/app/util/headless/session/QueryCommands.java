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
			String c = df.getC();
			Json.put(r, "signature", df.getSignature());
			Json.put(r, "chars", c.length());
			Json.put(r, "truncated", c.length() > cap);
			Json.put(r, "c", c.length() > cap ? c.substring(0, cap) : c);
			return r;
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
