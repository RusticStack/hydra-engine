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
package ghidra.app.decompiler;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Hydra: the C text that can still be read from the front of a decompiler response that was cut
 * off by the response size cap (issue 6).
 * <p>
 * The response is a packed tree: a document of two {@code function} elements, the first the
 * function's symbols and prototype, the second the C markup (blocks, statements and tokens). A
 * response that passes the cap fails the decode as a whole, but nothing in the tree depends on
 * what follows it: the tokens read before the cut are exactly the first tokens of the C text.
 * This walks the tree token by token, keeping only the text (no node objects, so it needs
 * memory in proportion to the text it keeps, not to the response), and stops at the cut.
 * <p>
 * The text is the one the pretty printer gives for the same tokens, with two differences: the
 * wrapping of a long comment over several lines is not applied, and names are not passed through
 * the name transformer. The last token read in full is the last one in the text; a token the cut
 * fell inside is dropped.
 */
public final class PartialMarkup {

	/** The most nested group the walk follows (the decompiler's own output is far shallower). */
	private static final int MAX_DEPTH = 2000;

	private final StringBuilder text = new StringBuilder();
	private final int keep;
	private long totalChars;
	private long tokens;
	private long lines = 1;
	private boolean markupReached;
	private boolean lineHasToken;
	private boolean sawAny;
	private int lineIndent;
	private int protoDepth = -1;
	private final StringBuilder proto = new StringBuilder();
	private boolean protoDone;
	private String cutReason = "";

	private PartialMarkup(int keep) {
		this.keep = keep;
	}

	/** The recovered C text, at most the {@code keep} characters asked for. */
	public String text() {
		return text.toString();
	}

	/** The characters of C recovered in all (more than {@link #text()} when that was limited). */
	public long chars() {
		return totalChars;
	}

	/** The tokens read in full. */
	public long tokens() {
		return tokens;
	}

	/** The lines of C text recovered, the last of them probably unfinished. */
	public long lines() {
		return lines;
	}

	/** Whether the cut fell in the C markup; false when it fell in the symbols before it. */
	public boolean markupReached() {
		return markupReached;
	}

	/** The function prototype, when the cut came after it; else empty. */
	public String signature() {
		return protoDone ? proto.toString() + ";" : "";
	}

	/** What ended the walk (the decoder's message at the cut). */
	public String cutReason() {
		return cutReason;
	}

	/**
	 * Reads the C text from the front of a response whose end is missing.
	 *
	 * @param decoder the response, ended with {@code endIngest()} at the last byte received
	 * @param keep the most characters of text to hold (the rest is counted, not kept)
	 * @return what was read; never null, empty when the cut fell before the C markup
	 */
	public static PartialMarkup read(Decoder decoder, int keep) {
		PartialMarkup p = new PartialMarkup(Math.max(0, keep));
		try {
			decoder.openElement(ELEM_DOC);
			int functions = 0;
			for (;;) {
				int el = decoder.peekElement();
				if (el == 0) {
					p.cutReason = "end of the document";
					return p;
				}
				if (el == ELEM_FUNCTION.id()) {
					if (++functions == 1) {
						decoder.skipElement(); // the symbols and prototype: not text
						continue;
					}
					decoder.openElement();
					p.markupReached = true;
					p.group(decoder, 0);
					return p;
				}
				decoder.skipElement();
			}
		}
		catch (DecoderException | IndexOutOfBoundsException ex) {
			p.cutReason = String.valueOf(ex.getMessage());
			return p;
		}
	}

	private void group(Decoder decoder, int depth) throws DecoderException {
		if (depth > MAX_DEPTH) {
			throw new DecoderException("markup nested deeper than " + MAX_DEPTH);
		}
		for (;;) {
			int elem = decoder.openElement();
			if (elem == 0) {
				return; // the end of this group, or the pad byte that follows the last byte received
			}
			if (elem == ELEM_RETURN_TYPE.id() || elem == ELEM_VARDECL.id() ||
				elem == ELEM_STATEMENT.id() || elem == ELEM_FUNCPROTO.id() ||
				elem == ELEM_BLOCK.id()) {
				boolean isProto = elem == ELEM_FUNCPROTO.id() && !protoDone && protoDepth < 0;
				if (isProto) {
					protoDepth = depth;
				}
				group(decoder, depth + 1);
				if (isProto) {
					protoDone = true;
				}
			}
			else if (elem == ELEM_BREAK.id()) {
				int indent = (int) decoder.readSignedInteger(ATTRIB_INDENT);
				lineBreak(indent);
			}
			else {
				token(decoder);
			}
			decoder.closeElement(elem);
		}
	}

	private void token(Decoder decoder) throws DecoderException {
		String t = decoder.readString(ATTRIB_CONTENT);
		if (t.indexOf('\0') >= 0) {
			throw new DecoderException("token cut by the end of the response");
		}
		tokens++;
		if (!sawAny) {
			sawAny = true;
		}
		if (!t.isEmpty()) {
			lineHasToken = true;
		}
		if (protoDepth >= 0 && !protoDone) {
			proto.append(t);
		}
		append(t);
	}

	private void lineBreak(int indent) {
		if (!sawAny) { // a break first in the text only sets the indent of the first line
			sawAny = true;
			lineIndent = Math.max(0, indent);
			append(" ".repeat(lineIndent));
			return;
		}
		if (!lineHasToken && lineIndent > 0) {
			// the pretty printer pads an empty line with one indent more of spaces
			append(" ".repeat(lineIndent));
		}
		append(System.lineSeparator());
		lines++;
		lineIndent = Math.max(0, indent);
		lineHasToken = false;
		append(" ".repeat(lineIndent));
	}

	private void append(String s) {
		totalChars += s.length();
		int room = keep - text.length();
		if (room > 0) {
			text.append(s, 0, Math.min(room, s.length()));
		}
	}
}
