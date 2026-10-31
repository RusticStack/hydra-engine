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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * An empty overlay's first changes, answered without opening the overlay's own program: the
 * values a {@code rename}, {@code label} or {@code comment} reads (the old value, the symbol kind,
 * whether a label is created) and the compare-and-set of its {@code expect} are the base program's,
 * because the overlay's log is still empty and the base cannot be written. So the reply is the one
 * {@link Operations} would produce, computed on a shadow of the touched names and comments, and the
 * overlay's program (the measured ~8 ms a {@link PrivateInstance#load} costs) is opened by the first
 * read that needs it instead of by the first change.
 * <p>
 * Only those three operations can be answered this way: {@code signature} and {@code data_type}
 * report what the program holds after the change (the applied prototype, the created data's length),
 * so they open the overlay's program first, as before. A batch is applied to a copy of the shadow
 * and committed only when all of its operations succeeded, so a failed batch changes nothing, as
 * the single transaction of {@link Operations#applyOps} does.
 */
final class OverlayDelta {

	/**
	 * What a rename of one address reads and how a change moves it: the function there (or none),
	 * whether its symbol still has a {@code DEFAULT} name (a label created at such a function's
	 * entry renames the function instead of adding a label, {@code SymbolManager.createLabel}),
	 * and the primary symbol's name and whether it is a non-dynamic label (the two things
	 * {@link Operations#renameIn} branches on).
	 */
	private record Names(String function, boolean functionDefault, String primary,
			boolean primaryIsLabel) {
	}

	/** The addresses whose name the log's operations changed (by {@code 0x...}). */
	private final Map<String, Names> names;
	/** The comments the log's operations changed, by {@code address\0commentKind}. */
	private final Map<String, String> comments;

	OverlayDelta() {
		this(Map.of(), Map.of());
	}

	private OverlayDelta(Map<String, Names> names, Map<String, String> comments) {
		this.names = names;
		this.comments = comments;
	}

	/** This shadow and its changes, to be applied and committed as one (see the class comment). */
	OverlayDelta copy() {
		return new OverlayDelta(new HashMap<>(names), new HashMap<>(comments));
	}

	/**
	 * True when every operation of the batch is one {@link #applyOps} answers without the overlay's
	 * program. A batch with anything else (or with a malformed operation) is not: the caller opens
	 * the program and lets {@link Operations} report whatever is wrong with it as it always did.
	 */
	static boolean canApply(JsonArray ops) {
		for (JsonElement el : ops) {
			if (!el.isJsonObject()) {
				return false;
			}
			JsonObject op = el.getAsJsonObject();
			if (!Json.has(op, "op") || !op.get("op").isJsonPrimitive() ||
				!op.get("op").getAsJsonPrimitive().isString()) {
				return false;
			}
			String kind = op.get("op").getAsString();
			if (!kind.equals("rename") && !kind.equals("label") && !kind.equals("comment")) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Applies the batch to this shadow, as {@link Operations#applyOps} applies it to a program: the
	 * results in order, or the failure of the first operation with its index and {@code rolledBack}
	 * (this shadow is left half-applied then: the caller works on a {@link #copy} and commits it
	 * only on success).
	 */
	JsonArray applyOps(Program base, JsonArray ops) {
		JsonArray results = new JsonArray();
		int i = 0;
		try {
			for (JsonElement el : ops) {
				if (!el.isJsonObject()) {
					throw new SessionException(SessionException.BAD_REQUEST,
						"ops[" + i + "] is not an object");
				}
				results.add(applyOp(base, el.getAsJsonObject()));
				i++;
			}
			return results;
		}
		catch (SessionException ex) {
			JsonObject d = ex.details() == null ? new JsonObject() : ex.details().deepCopy();
			Json.put(d, "index", i);
			Json.put(d, "rolledBack", true);
			throw ex.rewrap("ops[" + i + "]: " + ex.getMessage() + " (nothing was applied)", d);
		}
		catch (RuntimeException ex) {
			throw new SessionException(SessionException.FAILED,
				"ops[" + i + "]: " + ex.getClass().getSimpleName() + ": " + ex.getMessage() +
					" (nothing was applied)",
				Json.of("index", i, "rolledBack", true), ex);
		}
	}

	private JsonObject applyOp(Program base, JsonObject op) {
		return switch (Json.str(op, "op")) {
			case "rename" -> {
				JsonObject r = renameIn(base, op, null);
				Json.put(r, "op", "rename");
				yield r;
			}
			case "label" -> {
				JsonObject r = renameIn(base, op, "label");
				Json.put(r, "op", "label");
				yield r;
			}
			case "comment" -> {
				JsonObject r = commentIn(base, op);
				Json.put(r, "op", "comment");
				yield r;
			}
			default -> throw new SessionException(SessionException.BAD_REQUEST,
				"unknown op '" + Json.str(op, "op") +
					"': rename, label, comment, signature or data_type");
		};
	}

	/** {@link Operations#renameIn} without the write: the same reads, checks and result. */
	private JsonObject renameIn(Program base, JsonObject req, String forcedKind) {
		Address a = address(base, Json.str(req, "address"));
		String name = Json.str(req, "name");
		String kind = forcedKind != null ? forcedKind : Json.str(req, "kind", "auto");
		if (!kind.equals("auto") && !kind.equals("function") && !kind.equals("label")) {
			throw new SessionException(SessionException.BAD_REQUEST,
				"kind must be auto, function or label");
		}
		String key = hex(a);
		Names n = names.computeIfAbsent(key, k -> namesOf(base, a));
		String old;
		boolean created = false;
		if (n.function != null && !kind.equals("label")) {
			old = n.function;
			Operations.expect(req, a, "name", old);
			// the function's symbol is the primary one at its entry, so it follows the name
			names.put(key, new Names(name, false,
				n.primaryIsLabel ? n.primary : name, n.primaryIsLabel));
			kind = "function";
		}
		else {
			old = n.primary;
			Operations.expect(req, a, "name", old);
			created = !n.primaryIsLabel;
			String function = n.function;
			boolean functionDefault = n.functionDefault;
			String primary = n.primary;
			boolean primaryIsLabel = n.primaryIsLabel;
			if (function != null && functionDefault) {
				// a label at a default-named function's entry renames that function
				function = name;
				functionDefault = false;
				if (!primaryIsLabel) {
					primary = name;
				}
			}
			else if (primaryIsLabel) {
				primary = name; // the primary label is renamed
			}
			else if (primary == null) {
				primary = name; // a label at an address with no primary symbol becomes it
				primaryIsLabel = true;
			}
			// else: a label next to a non-default function (or another primary symbol) is created
			// and does not become primary (SymbolManager.createLabel: makePrimary = primary == null,
			// and setPrimary is refused at a function entry)
			names.put(key, new Names(function, functionDefault, primary, primaryIsLabel));
			kind = "label";
		}
		return Json.of("address", key, "name", name, "old", old, "kind", kind, "created",
			created);
	}

	/** {@link Operations#commentIn} without the write: the same read, check and result. */
	private JsonObject commentIn(Program base, JsonObject req) {
		Address a = address(base, Json.str(req, "address"));
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
		String key = hex(a) + '\u0000' + ct;
		String old = comments.containsKey(key) ? comments.get(key)
				: base.getListing().getComment(ct, a);
		Operations.expect(req, a, "comment", old);
		comments.put(key, text);
		return Json.of("address", hex(a), "type", Json.str(req, "type", "eol"), "old", old,
			"text", text);
	}

	/** The base program's name state of {@code a}, as {@link Operations#renameIn} reads it. */
	private static Names namesOf(Program base, Address a) {
		Function f = base.getFunctionManager().getFunctionAt(a);
		Symbol s = base.getSymbolTable().getPrimarySymbol(a);
		boolean primaryIsLabel =
			s != null && s.getSymbolType() == SymbolType.LABEL && !s.isDynamic();
		boolean functionDefault = f != null &&
			f.getSymbol().getSource() == SourceType.DEFAULT;
		return new Names(f == null ? null : f.getName(), functionDefault,
			s == null ? null : s.getName(), primaryIsLabel);
	}
}
