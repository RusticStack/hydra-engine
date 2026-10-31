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

import java.util.*;

import com.google.gson.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * The operations that change a program ({@code rename}, {@code label},
 * {@code comment}, {@code signature}, {@code data_type}), shared by the edit
 * commands, overlays and promotion: each applies to a {@link Program} the caller
 * has already locked.
 */
final class Operations {

	private final Session s;

	Operations(Session s) {
		this.s = s;
		Advertised.capability("expectAll", 1);
	}

	/**
	 * Compare-and-set: when the request carries {@code "expect"}, the value it changes must still
	 * be that (null: none), or the change is refused with {@code conflict} ({@code reason:
	 * "changed"}). Changes to one program are serialized, so the check and the write are one step.
	 * Also used by {@link OverlayDelta}, whose shadow answers the first changes of an empty overlay.
	 */
	static void expect(JsonObject req, Address a, String field, String current) {
		if (!req.has("expect")) {
			return;
		}
		String want = req.get("expect").isJsonNull() ? null : req.get("expect").getAsString();
		if (!Objects.equals(want, current)) {
			throw changed(a, field, want, current);
		}
	}

	/**
	 * The same compare-and-set for {@code signature} and {@code data_type} (protocol 3 only,
	 * behaviour gate 1: a protocol 2 connection never calls this, so an {@code expect} on those two
	 * ops stays ignored for it as it always was). The conflict has the shape of the one for names
	 * and comments; {@code next} (may be null) is the request that rereads the value.
	 */
	private static void expectV3(JsonObject op, Address a, String field, String current,
			JsonObject next) {
		if (!op.has("expect")) {
			return;
		}
		JsonElement e = op.get("expect");
		if (!e.isJsonNull() && !(e.isJsonPrimitive() && e.getAsJsonPrimitive().isString())) {
			throw SessionException.badRequest(true,
				"expect must be a string, or null for \"none\"", "expect", null);
		}
		String want = e.isJsonNull() ? null : e.getAsString();
		if (!Objects.equals(want, current)) {
			throw changed(a, field, want, current).withNext(next);
		}
	}

	private static SessionException changed(Address a, String field, String want, String current) {
		return new SessionException(SessionException.CONFLICT,
			"the " + field + " at " + hex(a) + " is '" + current + "', not the expected '" + want +
				"': someone changed it since you read it",
			Json.of("reason", "changed", "address", hex(a), "field", field, "expected", want,
				"current", current));
	}

	/** The operations of a request: {@code ops}, or the request itself as one {@code op}. */
	static JsonArray ops(JsonObject req, String single) {
		if (single != null) {
			JsonObject op = req.deepCopy();
			for (String k : List.of("id", "cmd", "overlay", "program", "project", "wait",
				"parallel")) {
				op.remove(k);
			}
			op.addProperty("op", single);
			JsonArray a = new JsonArray();
			a.add(op);
			return a;
		}
		if (!Json.has(req, "ops") || !req.get("ops").isJsonArray() ||
			req.getAsJsonArray("ops").isEmpty()) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"ops must be a non-empty array of {\"op\": rename|label|comment|signature|" +
					"data_type, ...}");
		}
		return req.getAsJsonArray("ops");
	}

	/**
	 * Applies operations in one transaction: all of them, or (on the first failure) none. The
	 * failure names the operation's index.
	 */
	JsonArray applyOps(Program p, JsonArray ops) {
		return applyOps(p, ops, false);
	}

	/**
	 * Like {@link #applyOps(Program, JsonArray)}; {@code v3} turns on what only a protocol 3
	 * request may have: {@code expect} on {@code signature} and {@code data_type}.
	 */
	JsonArray applyOps(Program p, JsonArray ops, boolean v3) {
		JsonArray results = new JsonArray();
		int tx = p.startTransaction("overlay operations");
		boolean ok = false;
		int i = 0;
		try {
			for (JsonElement el : ops) {
				if (!el.isJsonObject()) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"ops[" + i + "] is not an object");
				}
				results.add(applyOp(p, el.getAsJsonObject(), v3));
				i++;
			}
			ok = true;
		}
		catch (SessionException ex) {
			JsonObject d = ex.details() == null ? new JsonObject() : ex.details().deepCopy();
			Json.put(d, "index", i);
			Json.put(d, "rolledBack", true);
			throw ex.rewrap("ops[" + i + "]: " + ex.getMessage() + " (nothing was applied)", d);
		}
		catch (Exception ex) {
			throw new SessionException(SessionException.FAILED,
				"ops[" + i + "]: " + ex.getClass().getSimpleName() + ": " + ex.getMessage() +
					" (nothing was applied)",
				Json.of("index", i, "rolledBack", true), ex);
		}
		finally {
			p.endTransaction(tx, ok);
		}
		return results;
	}

	/**
	 * One operation: {@code rename} (address, name, kind auto|function|label), {@code label}
	 * (address, name), {@code comment} (address, text, type), {@code signature} (address of a
	 * function, a C prototype), {@code data_type} (address, a data type such as {@code int},
	 * {@code char[16]} or {@code MyStruct *}).
	 */
	private JsonObject applyOp(Program p, JsonObject op, boolean v3) throws Exception {
		String kind = Json.str(op, "op");
		switch (kind) {
			case "rename": {
				JsonObject r = renameIn(p, op);
				Json.put(r, "op", kind);
				return r;
			}
			case "label": {
				JsonObject req = op.deepCopy();
				req.addProperty("kind", "label");
				JsonObject r = renameIn(p, req);
				Json.put(r, "op", kind);
				return r;
			}
			case "comment": {
				JsonObject r = commentIn(p, op);
				Json.put(r, "op", kind);
				return r;
			}
			case "signature": {
				Address a = address(p, Json.str(op, "address"));
				Function f = p.getFunctionManager().getFunctionContaining(a);
				if (f == null) {
					throw new SessionException(SessionException.NOT_FOUND,
						"no function contains " + hex(a));
				}
				String text = Json.str(op, "signature");
				String oldSig = f.getSignature().getPrototypeString();
				ghidra.program.model.data.FunctionDefinitionDataType fd;
				try {
					fd = ghidra.app.util.cparser.C.CParserUtils.parseSignature(
						(ghidra.app.services.DataTypeManagerService) null, p, text, false);
				}
				catch (ghidra.app.util.cparser.C.ParseException ex) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad signature '" + text + "': " + ex.getMessage());
				}
				if (fd == null) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad signature '" + text + "'");
				}
				if (v3) {
					expectV3(op, f.getEntryPoint(), "signature", oldSig,
						Json.of("cmd", "decompile", "address", hex(f.getEntryPoint())));
				}
				ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
					new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.getEntryPoint(), fd,
						SourceType.USER_DEFINED);
				if (!cmd.applyTo(p)) {
					throw new SessionException(SessionException.FAILED,
						"could not apply the signature: " + cmd.getStatusMsg());
				}
				return Json.of("op", kind, "address", hex(f.getEntryPoint()), "signature",
					f.getSignature().getPrototypeString(), "old", oldSig, "new",
					f.getSignature().getPrototypeString());
			}
			case "data_type": {
				Address a = address(p, Json.str(op, "address"));
				String text = Json.str(op, "type");
				Data before = p.getListing().getDefinedDataAt(a);
				String oldType = before == null ? null : before.getDataType().getDisplayName();
				ghidra.program.model.data.DataType dt;
				try {
					dt = new ghidra.util.data.DataTypeParser(p.getDataTypeManager(),
						p.getDataTypeManager(), null,
						ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL).parse(text);
				}
				catch (ghidra.program.model.data.InvalidDataTypeException ex) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"bad data type '" + text + "': " + ex.getMessage());
				}
				if (v3) {
					expectV3(op, a, "type", oldType, null);
				}
				Data d = ghidra.program.model.data.DataUtilities.createData(p, a, dt, -1,
					ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				return Json.of("op", kind, "address", hex(a), "type",
					d.getDataType().getDisplayName(), "length", d.getLength(), "old", oldType,
					"new", d.getDataType().getDisplayName());
			}
			default:
				throw new SessionException(SessionException.BAD_REQUEST,
					"unknown op '" + kind + "': rename, label, comment, signature or data_type");
		}
	}

	JsonObject renameIn(Program p, JsonObject req) throws Exception {
		Address a = address(p, Json.str(req, "address"));
		String name = Json.str(req, "name");
		String kind = Json.str(req, "kind", "auto");
		if (!kind.equals("auto") && !kind.equals("function") && !kind.equals("label")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"kind must be auto, function or label");
		}
		String old = null;
		boolean created = false;
		int tx = p.startTransaction("session rename");
		boolean ok = false;
		try {
			Function f = p.getFunctionManager().getFunctionAt(a);
			if (kind.equals("function") && f == null) {
				throw new SessionException(SessionException.NOT_FOUND,
					"no function starts at " + hex(a));
			}
			if (f != null && !kind.equals("label")) {
				old = f.getName();
				expect(req, a, "name", old);
				f.setName(name, SourceType.USER_DEFINED);
				kind = "function";
			}
			else {
				Symbol s = p.getSymbolTable().getPrimarySymbol(a);
				if (s != null && s.getSymbolType() == SymbolType.LABEL && !s.isDynamic()) {
					old = s.getName();
					expect(req, a, "name", old);
					s.setName(name, SourceType.USER_DEFINED);
				}
				else {
					old = s == null ? null : s.getName();
					expect(req, a, "name", old);
					Symbol n = p.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
					n.setPrimary();
					created = true;
				}
				kind = "label";
			}
			ok = true;
		}
		finally {
			p.endTransaction(tx, ok);
		}
		return Json.of("address", hex(a), "name", name, "old", old, "kind", kind, "created",
			created);
	}

	JsonObject commentIn(Program p, JsonObject req) {
		Address a = address(p, Json.str(req, "address"));
		CommentType ct = switch (Json.str(req, "type", "eol")) {
			case "eol" -> CommentType.EOL;
			case "pre" -> CommentType.PRE;
			case "post" -> CommentType.POST;
			case "plate" -> CommentType.PLATE;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> throw new SessionException(SessionException.BAD_REQUEST,
				"type must be eol, pre, post, plate or repeatable");
		};
		String text = Json.has(req, "text") ? Json.str(req, "text") : null;
		String old = p.getListing().getComment(ct, a);
		expect(req, a, "comment", old);
		int tx = p.startTransaction("session comment");
		try {
			p.getListing().setComment(a, ct, text);
		}
		finally {
			p.endTransaction(tx, true);
		}
		return Json.of("address", hex(a), "type", Json.str(req, "type", "eol"), "old", old,
			"text", text);
	}
}
