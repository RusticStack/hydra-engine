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
//Read-only queries for the hydra command line: one JSON line per call (prefix HYDRA-CLI-JSON).
//@category HeadlessSession
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

/**
 * Backs the hydra command line's queries that the session protocol has no command for.
 * Arguments: operation, then key=value pairs. It never writes to a program; create_project makes
 * an empty project and needs no program. The answer is one line, HYDRA-CLI-JSON followed by an
 * object with ok and result, or ok and error.
 */
public class HydraCli extends GhidraScript {
	private static final String PREFIX = "HYDRA-CLI-JSON ";
	private static final int MAX_BYTES = 65536;

	private final Map<String, String> opts = new HashMap<>();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			fail("bad_request", "no operation");
			return;
		}
		for (int i = 1; i < args.length; i++) {
			int eq = args[i].indexOf('=');
			if (eq > 0) {
				opts.put(args[i].substring(0, eq), args[i].substring(eq + 1));
			}
		}
		try {
			switch (args[0]) {
				case "ping" -> emit("{\"pong\":true}");
				case "create_project" -> createProject();
				case "function" -> function();
				case "disasm" -> disasm();
				case "xrefs" -> xrefs();
				case "callers" -> callers();
				case "callees" -> callees();
				case "strings" -> strings();
				case "imports" -> imports();
				case "bytes" -> bytes();
				case "search" -> search();
				default -> fail("bad_request", "unknown operation " + args[0]);
			}
		}
		catch (Failure f) {
			fail(f.code, f.getMessage());
		}
	}

	private static final class Failure extends Exception {
		final String code;

		Failure(String code, String message) {
			super(message);
			this.code = code;
		}
	}

	// ---- operations ----

	private void createProject() throws Exception {
		GhidraProject.createProject(req("dir"), req("name"), false).close();
		emit("{\"created\":true}");
	}

	private void function() throws Exception {
		Function f = resolveFunction();
		StringBuilder sb = new StringBuilder("{");
		sb.append("\"name\":").append(q(f.getName(true)));
		sb.append(",\"entry\":").append(q(fmt(f.getEntryPoint())));
		sb.append(",\"rva\":").append(rva(f.getEntryPoint()));
		sb.append(",\"min\":").append(q(fmt(f.getBody().getMinAddress())));
		sb.append(",\"max\":").append(q(fmt(f.getBody().getMaxAddress())));
		sb.append(",\"size\":").append(f.getBody().getNumAddresses());
		sb.append(",\"signature\":").append(q(f.getPrototypeString(true, false)));
		sb.append(",\"callingConvention\":").append(q(f.getCallingConventionName()));
		sb.append(",\"external\":").append(f.isExternal());
		sb.append(",\"thunk\":").append(f.isThunk());
		sb.append(",\"inline\":").append(f.isInline());
		sb.append(",\"noReturn\":").append(f.hasNoReturn());
		sb.append(",\"varArgs\":").append(f.hasVarArgs());
		sb.append(",\"returnType\":").append(q(f.getReturnType().getDisplayName()));
		sb.append(",\"parameters\":[");
		Parameter[] ps = f.getParameters();
		for (int i = 0; i < ps.length; i++) {
			if (i > 0) {
				sb.append(',');
			}
			sb.append("{\"name\":").append(q(ps[i].getName()));
			sb.append(",\"type\":").append(q(ps[i].getDataType().getDisplayName()));
			sb.append(",\"storage\":").append(q(ps[i].getVariableStorage().toString())).append('}');
		}
		sb.append("],\"stackFrameSize\":").append(f.getStackFrame().getFrameSize());
		String comment = f.getComment();
		sb.append(",\"comment\":").append(comment == null ? "null" : q(comment));
		sb.append(",\"callers\":").append(f.getCallingFunctions(monitor).size());
		sb.append(",\"callees\":").append(f.getCalledFunctions(monitor).size());
		sb.append(",\"references\":").append(
			currentProgram.getReferenceManager().getReferenceCountTo(f.getEntryPoint()));
		sb.append('}');
		emit(sb.toString());
	}

	private void disasm() throws Exception {
		Listing listing = currentProgram.getListing();
		String target = req("target");
		Address start;
		Address end = null;
		Function f = null;
		int count = intOpt("count", 64, 1, 100000);
		if (looksLikeAddress(target)) {
			start = resolveAddress(target);
		}
		else {
			f = resolveFunction();
			start = f.getEntryPoint();
			end = f.getBody().getMaxAddress();
			count = intOpt("count", 100000, 1, 100000);
		}
		StringBuilder sb = new StringBuilder("{\"start\":").append(q(fmt(start)));
		if (f != null) {
			sb.append(",\"function\":").append(q(f.getName(true)));
		}
		sb.append(",\"lines\":[");
		int n = 0;
		boolean truncated = false;
		Address at = start;
		while (at != null) {
			if (n >= count) {
				truncated = true;
				break;
			}
			if (end != null && at.compareTo(end) > 0) {
				break;
			}
			if (n > 0) {
				sb.append(',');
			}
			Instruction ins = listing.getInstructionContaining(at);
			if (ins != null && ins.getAddress().equals(at)) {
				sb.append("{\"address\":").append(q(fmt(at)));
				sb.append(",\"bytes\":").append(q(hex(ins.getBytes())));
				sb.append(",\"mnemonic\":").append(q(ins.getMnemonicString()));
				sb.append(",\"text\":").append(q(ins.toString()));
				sb.append(",\"length\":").append(ins.getLength());
				sb.append(",\"flow\":").append(q(ins.getFlowType().getName())).append('}');
				n++;
				at = ins.getMaxAddress().next();
				continue;
			}
			Data d = listing.getDataContaining(at);
			if (d != null && d.getAddress().equals(at) && !d.isDefined()) {
				d = null;
			}
			if (d != null && d.getAddress().equals(at)) {
				sb.append("{\"address\":").append(q(fmt(at)));
				sb.append(",\"data\":").append(q(d.getDataType().getDisplayName()));
				sb.append(",\"text\":").append(q(d.getDefaultValueRepresentation()));
				sb.append(",\"length\":").append(d.getLength()).append('}');
				n++;
				at = d.getMaxAddress().next();
				continue;
			}
			sb.append("{\"address\":").append(q(fmt(at))).append(",\"undefined\":true,\"length\":1}");
			n++;
			at = at.next();
		}
		sb.append("],\"count\":").append(n).append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	private void xrefs() throws Exception {
		String dir = opts.getOrDefault("direction", "to");
		if (!Set.of("to", "from", "both").contains(dir)) {
			throw new Failure("bad_request", "direction must be to, from or both");
		}
		int limit = intOpt("limit", 200, 1, 100000);
		Address a = resolveTargetAddress();
		ReferenceManager rm = currentProgram.getReferenceManager();
		List<Reference> refs = new ArrayList<>();
		if (dir.equals("to") || dir.equals("both")) {
			rm.getReferencesTo(a).forEachRemaining(refs::add);
		}
		if (dir.equals("from") || dir.equals("both")) {
			refs.addAll(Arrays.asList(rm.getReferencesFrom(a)));
		}
		StringBuilder sb = new StringBuilder("{\"address\":").append(q(fmt(a)));
		sb.append(",\"direction\":").append(q(dir)).append(",\"references\":[");
		int total = 0;
		boolean truncated = false;
		for (Reference r : refs) {
			total++;
			if (total > limit) {
				truncated = true;
				continue;
			}
			if (total > 1) {
				sb.append(',');
			}
			refJson(sb, r);
		}
		sb.append("],\"total\":").append(total).append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	private void refJson(StringBuilder sb, Reference r) {
		Function from = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
		sb.append("{\"from\":").append(q(fmt(r.getFromAddress())));
		sb.append(",\"to\":").append(q(fmt(r.getToAddress())));
		sb.append(",\"type\":").append(q(r.getReferenceType().getName()));
		sb.append(",\"call\":").append(r.getReferenceType().isCall());
		sb.append(",\"source\":").append(q(r.getSource().toString()));
		sb.append(",\"function\":").append(from == null ? "null" : q(from.getName(true)));
		sb.append(",\"functionEntry\":").append(from == null ? "null" : q(fmt(from.getEntryPoint())));
		sb.append('}');
	}

	private void callers() throws Exception {
		Function f = resolveFunction();
		int limit = intOpt("limit", 500, 1, 100000);
		StringBuilder sb = new StringBuilder("{\"function\":").append(q(f.getName(true)));
		sb.append(",\"entry\":").append(q(fmt(f.getEntryPoint()))).append(",\"callers\":[");
		int total = 0;
		boolean truncated = false;
		ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
		while (it.hasNext()) {
			Reference r = it.next();
			if (!r.getReferenceType().isFlow()) {
				continue;
			}
			total++;
			if (total > limit) {
				truncated = true;
				continue;
			}
			if (total > 1) {
				sb.append(',');
			}
			refJson(sb, r);
		}
		sb.append("],\"total\":").append(total).append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	private void callees() throws Exception {
		Function f = resolveFunction();
		StringBuilder sb = new StringBuilder("{\"function\":").append(q(f.getName(true)));
		sb.append(",\"entry\":").append(q(fmt(f.getEntryPoint()))).append(",\"callees\":[");
		List<Function> called = new ArrayList<>(f.getCalledFunctions(monitor));
		called.sort(Comparator.comparing(Function::getEntryPoint));
		boolean first = true;
		for (Function c : called) {
			if (!first) {
				sb.append(',');
			}
			first = false;
			sb.append("{\"name\":").append(q(c.getName(true)));
			sb.append(",\"entry\":").append(q(fmt(c.getEntryPoint())));
			sb.append(",\"external\":").append(c.isExternal());
			sb.append(",\"thunk\":").append(c.isThunk()).append('}');
		}
		sb.append("],\"total\":").append(called.size()).append('}');
		emit(sb.toString());
	}

	private void strings() throws Exception {
		int minLen = intOpt("min", 4, 1, 100000);
		int limit = intOpt("limit", 200, 1, 100000);
		int offset = intOpt("offset", 0, 0, Integer.MAX_VALUE);
		String contains = opts.get("contains");
		StringBuilder sb = new StringBuilder("{\"strings\":[");
		int seen = 0;
		int emitted = 0;
		boolean truncated = false;
		for (Data d : currentProgram.getListing().getDefinedData(true)) {
			if (!d.hasStringValue()) {
				continue;
			}
			Object v = d.getValue();
			if (v == null) {
				continue;
			}
			String s = v.toString();
			if (s.length() < minLen || (contains != null && !s.contains(contains))) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (emitted >= limit) {
				truncated = true;
				break;
			}
			if (emitted++ > 0) {
				sb.append(',');
			}
			MemoryBlock b = currentProgram.getMemory().getBlock(d.getAddress());
			sb.append("{\"address\":").append(q(fmt(d.getAddress())));
			sb.append(",\"value\":").append(q(s));
			sb.append(",\"length\":").append(s.length());
			sb.append(",\"type\":").append(q(d.getDataType().getDisplayName()));
			sb.append(",\"block\":").append(b == null ? "null" : q(b.getName())).append('}');
		}
		sb.append("],\"count\":").append(emitted).append(",\"offset\":").append(offset);
		sb.append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	private void imports() throws Exception {
		int limit = intOpt("limit", 500, 1, 100000);
		int offset = intOpt("offset", 0, 0, Integer.MAX_VALUE);
		String contains = opts.get("contains");
		String lib = opts.get("library");
		ExternalManager em = currentProgram.getExternalManager();
		List<ExternalLocation> locs = new ArrayList<>();
		for (String l : em.getExternalLibraryNames()) {
			if (lib != null && !l.equalsIgnoreCase(lib)) {
				continue;
			}
			ExternalLocationIterator it = em.getExternalLocations(l);
			while (it.hasNext()) {
				locs.add(it.next());
			}
		}
		locs.sort(Comparator.comparing((ExternalLocation e) -> e.getLibraryName().toLowerCase())
			.thenComparing(e -> e.getLabel()));
		StringBuilder sb = new StringBuilder("{\"imports\":[");
		int seen = 0;
		int emitted = 0;
		boolean truncated = false;
		for (ExternalLocation e : locs) {
			if (contains != null && !e.getLabel().toLowerCase().contains(contains.toLowerCase())) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			if (emitted >= limit) {
				truncated = true;
				break;
			}
			if (emitted++ > 0) {
				sb.append(',');
			}
			Symbol s = e.getSymbol();
			sb.append("{\"library\":").append(q(e.getLibraryName()));
			sb.append(",\"name\":").append(q(e.getLabel()));
			sb.append(",\"original\":").append(q(e.getOriginalImportedName()));
			Function ext = e.getFunction();
			sb.append(",\"function\":").append(ext == null ? "null" : q(fmt(ext.getEntryPoint())));
			sb.append(",\"slots\":[");
			int slots = 0;
			if (s != null) {
				for (Reference r : s.getReferences()) {
					if (slots >= 4) {
						break;
					}
					if (slots++ > 0) {
						sb.append(',');
					}
					sb.append(q(fmt(r.getFromAddress())));
				}
			}
			sb.append(']');
			sb.append(",\"references\":").append(s == null ? 0 : s.getReferenceCount()).append('}');
		}
		sb.append("],\"count\":").append(emitted).append(",\"offset\":").append(offset);
		sb.append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	private void bytes() throws Exception {
		int len = intOpt("len", 64, 1, MAX_BYTES);
		Address a = resolveTargetAddress();
		byte[] buf = new byte[len];
		int got;
		try {
			got = currentProgram.getMemory().getBytes(a, buf);
		}
		catch (MemoryAccessException e) {
			throw new Failure("not_found", "unreadable memory at " + fmt(a));
		}
		buf = Arrays.copyOf(buf, got);
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		StringBuilder ascii = new StringBuilder();
		for (byte x : buf) {
			ascii.append(x >= 0x20 && x < 0x7f ? (char) x : '.');
		}
		emit("{\"address\":" + q(fmt(a)) + ",\"length\":" + got + ",\"requested\":" + len +
			",\"block\":" + (b == null ? "null" : q(b.getName())) + ",\"hex\":" + q(hex(buf)) +
			",\"ascii\":" + q(ascii.toString()) + "}");
	}

	private void search() throws Exception {
		int limit = intOpt("limit", 100, 1, 100000);
		byte[] pat;
		byte[] mask = null;
		if (opts.containsKey("hex")) {
			String[] toks = opts.get("hex").trim().split("[\\s,]+");
			pat = new byte[toks.length];
			mask = new byte[toks.length];
			for (int i = 0; i < toks.length; i++) {
				String t = toks[i];
				if (t.equals("??") || t.equals("?")) {
					mask[i] = 0;
					continue;
				}
				try {
					pat[i] = (byte) Integer.parseInt(t.startsWith("0x") ? t.substring(2) : t, 16);
				}
				catch (NumberFormatException e) {
					throw new Failure("bad_request", "bad hex byte " + t);
				}
				mask[i] = (byte) 0xff;
			}
		}
		else if (opts.containsKey("text")) {
			pat = opts.get("text").getBytes(opts.containsKey("wide")
					? java.nio.charset.StandardCharsets.UTF_16LE
					: java.nio.charset.StandardCharsets.UTF_8);
		}
		else {
			throw new Failure("bad_request", "search needs hex= or text=");
		}
		if (pat.length == 0) {
			throw new Failure("bad_request", "empty pattern");
		}
		Address at = currentProgram.getMinAddress();
		StringBuilder sb = new StringBuilder("{\"matches\":[");
		int n = 0;
		boolean truncated = false;
		while (at != null) {
			Address hit = currentProgram.getMemory().findBytes(at, pat, mask, true, monitor);
			if (hit == null) {
				break;
			}
			if (n >= limit) {
				truncated = true;
				break;
			}
			Function f = currentProgram.getFunctionManager().getFunctionContaining(hit);
			MemoryBlock b = currentProgram.getMemory().getBlock(hit);
			if (n++ > 0) {
				sb.append(',');
			}
			sb.append("{\"address\":").append(q(fmt(hit)));
			sb.append(",\"block\":").append(b == null ? "null" : q(b.getName()));
			sb.append(",\"function\":").append(f == null ? "null" : q(f.getName(true))).append('}');
			at = hit.next();
		}
		sb.append("],\"count\":").append(n).append(",\"truncated\":").append(truncated).append('}');
		emit(sb.toString());
	}

	// ---- resolution ----

	private boolean looksLikeAddress(String s) {
		return s.startsWith("0x") || s.startsWith("rva:") || s.startsWith("va:") ||
			s.matches("[A-Za-z_][A-Za-z0-9_]*:[0-9a-fA-F]+");
	}

	private Address resolveTargetAddress() throws Failure {
		String t = req("target");
		if (!looksLikeAddress(t)) {
			return resolveFunction().getEntryPoint();
		}
		return resolveAddress(t);
	}

	private Address resolveAddress(String s) throws Failure {
		try {
			if (s.startsWith("rva:")) {
				return currentProgram.getImageBase().add(parseNumber(s.substring(4)));
			}
			if (s.startsWith("va:")) {
				s = s.substring(3);
			}
			Address a = currentProgram.getAddressFactory().getAddress(s);
			if (a == null) {
				throw new Failure("bad_request", "not an address: " + s);
			}
			return a;
		}
		catch (NumberFormatException | AddressOutOfBoundsException e) {
			throw new Failure("bad_request", "not an address: " + s);
		}
	}

	private static long parseNumber(String s) {
		return s.startsWith("0x") ? Long.parseUnsignedLong(s.substring(2), 16) : Long.parseLong(s);
	}

	private List<Function> findFunctionsByName(String name) {
		List<Function> out = new ArrayList<>();
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) {
			Function f = currentProgram.getFunctionManager().getFunctionAt(s.getAddress());
			if (f != null && !out.contains(f)) {
				out.add(f);
			}
		}
		return out;
	}

	private Function resolveFunction() throws Failure {
		String t = req("target");
		if (looksLikeAddress(t)) {
			Address a = resolveAddress(t);
			Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				throw new Failure("not_found", "no function at " + fmt(a));
			}
			return f;
		}
		List<Function> fs = findFunctionsByName(t);
		if (fs.isEmpty()) {
			throw new Failure("not_found", "no function named " + t);
		}
		if (fs.size() > 1) {
			StringBuilder sb = new StringBuilder("ambiguous name " + t + ":");
			for (Function f : fs) {
				sb.append(' ').append(fmt(f.getEntryPoint()));
			}
			throw new Failure("bad_request", sb.toString());
		}
		return fs.get(0);
	}

	// ---- plumbing ----

	private String req(String key) throws Failure {
		String v = opts.get(key);
		if (v == null) {
			throw new Failure("bad_request", "missing " + key);
		}
		return v;
	}

	private int intOpt(String key, int dflt, int lo, int hi) throws Failure {
		String v = opts.get(key);
		if (v == null) {
			return dflt;
		}
		int n;
		try {
			n = Integer.parseInt(v);
		}
		catch (NumberFormatException e) {
			throw new Failure("bad_request", key + " is not a number");
		}
		if (n < lo || n > hi) {
			throw new Failure("bad_request", key + " must be " + lo + ".." + hi);
		}
		return n;
	}

	private String fmt(Address a) {
		if (a == null) {
			return null;
		}
		if (a.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
			return "0x" + Long.toHexString(a.getOffset());
		}
		return a.toString();
	}

	private String rva(Address a) {
		return Long.toString(a.getOffset() - currentProgram.getImageBase().getOffset());
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (byte x : b) {
			sb.append(String.format("%02x", x & 0xff));
		}
		return sb.toString();
	}

	private static String q(String s) {
		if (s == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20 || c == 0x2028 || c == 0x2029) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.append('"').toString();
	}

	private void emit(String json) {
		println(PREFIX + "{\"ok\":true,\"result\":" + json + "}");
	}

	private void fail(String code, String message) {
		println(PREFIX + "{\"ok\":false,\"error\":{\"code\":" + q(code) + ",\"message\":" +
			q(message) + "}}");
	}
}
