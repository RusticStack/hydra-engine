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

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageDescription;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/**
 * Hydra: the Java side of the decompile snapshot, format v2 (the callback-free decompile
 * backend, {@code Decompiler/rust/crates/hydra-decomp-host/DESIGN.md}).
 *
 * <p>For one program generation (its state at one modification number) and one set of decompiler
 * options, this computes what {@link DecompileCallback} answers to the native decompiler, as the
 * exact bytes {@link DecompileProcess} would write to the decompiler's pipe: the registerProgram
 * strings ({@link #specs}), the options ({@link #encodeOptions}) and the answer to any query
 * ({@link #answer}). The host stores each answer once per generation and answers the native
 * {@code ArchitectureGhidra} from the store, with no call back into Java while it decompiles.
 *
 * <p>An answer is classified when it is computed:
 * <ul>
 * <li>{@link #GLOBAL}: the same for every function decompiled in this generation,</li>
 * <li>{@link #SCOPED}: valid only while decompiling the function set with {@link #setFunction}
 * (the mapped symbol or external reference of its own entry, which carries its default names,
 * and code labels in a function namespace, whose names depend on the function decompiled),</li>
 * <li>{@link #UNSTORABLE}: depends on state of one decompilation (p-code of an address the
 * listing has no instruction at, made by pseudo-disassembly; an encoding that handed out a
 * temporary data-type id). The function then takes the process path.</li>
 * </ul>
 * A function whose own body changes the stack depth of a call ({@code CallDepthChangeInfo}
 * overrides) makes the answers about its callees depend on it, so it is not hosted
 * ({@link #hostable}).
 *
 * <p>An instance is used by one thread at a time (it holds a {@link DecompileCallback} and a
 * {@link PcodeDataTypeManager}, neither thread-safe).
 */
public class DecompileSnapshot {

	/** The answer is the same for every function of the generation. */
	public static final int GLOBAL = 0;
	/** The answer holds only while decompiling the current function. */
	public static final int SCOPED = 1;
	/** The answer must not be stored; the function takes the process path. */
	public static final int UNSTORABLE = 2;

	private final static byte[] QUERY_RESPONSE_START = { 0, 0, 1, 8 };
	private final static byte[] QUERY_RESPONSE_END = { 0, 0, 1, 9 };
	private final static byte[] STRING_START = { 0, 0, 1, 14 };
	private final static byte[] STRING_END = { 0, 0, 1, 15 };
	private final static byte[] EXCEPTION_START = { 0, 0, 1, 10 };
	private final static byte[] EXCEPTION_END = { 0, 0, 1, 11 };
	private final static byte[] BYTE_START = { 0, 0, 1, 12 };
	private final static byte[] BYTE_END = { 0, 0, 1, 13 };

	/**
	 * One answer.
	 * @param response the bytes {@link DecompileProcess} writes for the query
	 * @param kind {@link #GLOBAL}, {@link #SCOPED} or {@link #UNSTORABLE}
	 * @param why for an unstorable answer, the reason
	 */
	public record Answer(byte[] response, int kind, String why) {
	}

	/**
	 * The registerProgram strings, as {@code DecompInterface} sends them.
	 * @param pspec the processor spec
	 * @param cspec the compiler spec
	 * @param tspec the translator spec
	 * @param coretypes the core data-types
	 */
	public record Specs(String pspec, String cspec, String tspec, String coretypes) {
	}

	private final Program program;
	private final SleighLanguage language;
	private final CompilerSpec compilerSpec;
	private final PcodeDataTypeManager dtmanage;
	private final DecompileCallback callback;
	private Function function;
	private Address funcEntry;

	/**
	 * @param program the program
	 * @param options the decompiler options (their name transformer shapes the answers)
	 * @throws IllegalArgumentException if the program's language or compiler spec cannot be
	 * decompiled ({@code DecompInterface.openProgram} refuses the same)
	 */
	public DecompileSnapshot(Program program, DecompileOptions options) {
		Language lang = program.getLanguage();
		if (!lang.supportsPcode() || !(lang instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Language does not support PCode.");
		}
		CompilerSpec spec = program.getCompilerSpec();
		if (!(spec instanceof BasicCompilerSpec)) {
			throw new IllegalArgumentException(
				"Language has unsupported compiler spec: " + spec.getClass().getName());
		}
		this.program = program;
		this.language = (SleighLanguage) lang;
		this.compilerSpec = spec;
		this.dtmanage = new PcodeDataTypeManager(program, options.getNameTransformer());
		this.callback = new DecompileCallback(program, language, spec, dtmanage);
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * Make {@code f} the function whose decompile the next answers serve (as
	 * {@code DecompInterface.decompileFunction} does before each decompile).
	 * @param f the function
	 */
	public void setFunction(Function f) {
		function = f;
		funcEntry = f.getEntryPoint();
		dtmanage.clearTemporaryIds();
		callback.setFunction(f, funcEntry, null);
	}

	/**
	 * Why {@code f} cannot be hosted, or null when it can.
	 * @param f the function
	 * @return the reason, or null
	 */
	public static String hostable(Function f) {
		if (f.isExternal()) {
			return "external function";
		}
		if (f instanceof ghidra.util.UndefinedFunction) {
			return "undefined function";
		}
		if (f.getEntryPoint().getAddressSpace().isOverlaySpace()) {
			return "function in an overlay space";
		}
		if (ghidra.app.cmd.function.CallDepthChangeInfo
				.getStackDepthChanges(f.getProgram(), f.getBody())
				.hasNext()) {
			return "stack depth overrides in the function body";
		}
		return null;
	}

	/**
	 * The registerProgram strings for the current state of {@code program}, built as
	 * {@code DecompInterface.getSpecStrings} builds them.
	 * @return the strings
	 * @throws IOException if the processor spec cannot be read
	 */
	public Specs specs() throws IOException {
		XmlEncode xmlEncode = new XmlEncode(false);
		compilerSpec.encode(xmlEncode);
		String cspecxml = xmlEncode.toString();
		long uniqueBase = UniqueLayout.SLEIGH_BASE.getOffset(language);
		xmlEncode.clear();
		language.encodeTranslator(xmlEncode, program.getAddressFactory(), uniqueBase);
		String tspec = xmlEncode.toString();
		xmlEncode.clear();
		dtmanage.encodeCoreTypes(xmlEncode);
		String coretypes = xmlEncode.toString();
		SleighLanguageDescription description = language.getLanguageDescription();
		ResourceFile pspecfile = description.getSpecFile();
		return new Specs(fileToString(pspecfile), cspecxml, tspec, coretypes);
	}

	/** {@code DecompInterface.fileToString}: the lines, concatenated without separators. */
	private static String fileToString(ResourceFile file) throws IOException {
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(file.getInputStream()))) {
			StringBuffer buffer = new StringBuffer();
			String line = null;
			while ((line = reader.readLine()) != null) {
				buffer.append(line);
			}
			return buffer.toString();
		}
	}

	/**
	 * The setOptions payload for {@code options}, as {@code DecompInterface} sends it for a
	 * decompiler with the default action ("decompile").
	 * @param options the options
	 * @return the packed bytes
	 * @throws IOException for encoding errors
	 */
	public static byte[] encodeOptions(DecompileOptions options) throws IOException {
		PatchPackedEncode enc = newEncoder();
		options.encode(enc, new DecompInterface());
		return bytes(enc);
	}

	/**
	 * The decompileAt payload for {@code addr} (also the scope of a {@link #SCOPED} answer).
	 * @param addr the function entry
	 * @return the packed bytes
	 * @throws IOException for encoding errors
	 */
	public static byte[] encodeAddress(Address addr) throws IOException {
		PatchPackedEncode enc = newEncoder();
		AddressXML.encode(enc, addr);
		return bytes(enc);
	}

	/**
	 * The query the native decompiler sends for the p-code of the instruction at {@code addr}
	 * ({@code ArchitectureGhidra::getPcode}).
	 * @param addr the instruction address
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryPcode(Address addr) throws IOException {
		return addressQuery(ELEM_COMMAND_GETPCODE, addr);
	}

	/**
	 * The query for the symbols at {@code addr} ({@code ArchitectureGhidra::getMappedSymbolsXML}).
	 * @param addr the address
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryMappedSymbols(Address addr) throws IOException {
		return addressQuery(ELEM_COMMAND_GETMAPPEDSYMBOLS, addr);
	}

	/**
	 * The query for the call-fixup injection {@code name} at a call site
	 * ({@code ArchitectureGhidra::getPcodeInject} with the {@code InjectContextGhidra} that
	 * {@code FlowInfo::injectSubFunction} fills: base = the call, call = the callee entry).
	 * @param name the fixup name
	 * @param base the call instruction
	 * @param callee the callee entry
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryCallFixup(String name, Address base, Address callee)
			throws IOException {
		PatchPackedEncode enc = newEncoder();
		enc.openElement(ELEM_COMMAND_GETCALLFIXUP);
		enc.writeString(ATTRIB_NAME, name);
		enc.openElement(ELEM_CONTEXT);
		AddressXML.encode(enc, base);
		AddressXML.encode(enc, callee);
		enc.closeElement(ELEM_CONTEXT);
		enc.closeElement(ELEM_COMMAND_GETCALLFIXUP);
		return bytes(enc);
	}

	/**
	 * The address of a getPcode query, or null for any other query.
	 * @param query the packed query payload
	 * @return the address
	 */
	public Address pcodeAddressOf(byte[] query) {
		try {
			PackedDecode dec = decoder(query);
			if (dec.openElement() != COMMAND_GETPCODE) {
				return null;
			}
			return AddressXML.decode(dec);
		}
		catch (IOException | DecoderException | RuntimeException e) {
			return null;
		}
	}

	/**
	 * The query for the code label at {@code addr} ({@code ArchitectureGhidra::getCodeLabel}).
	 * @param addr the address
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryCodeLabel(Address addr) throws IOException {
		return addressQuery(ELEM_COMMAND_GETCODELABEL, addr);
	}

	/**
	 * The query for an external reference at {@code addr}
	 * ({@code ArchitectureGhidra::getExternalRef}).
	 * @param addr the address
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryExternalRef(Address addr) throws IOException {
		return addressQuery(ELEM_COMMAND_GETEXTERNALREF, addr);
	}

	/**
	 * The query for the tracked registers at {@code addr}
	 * ({@code ArchitectureGhidra::getTrackedRegisters}).
	 * @param addr the address
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryTrackedRegisters(Address addr) throws IOException {
		return addressQuery(ELEM_COMMAND_GETTRACKEDREGISTERS, addr);
	}

	/**
	 * The query for the name of user-defined op {@code index} ({@code ArchitectureGhidra::getUserOpName};
	 * registration asks for 0, 1, ... until the name is empty).
	 * @param index the op index
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryUserOpName(int index) throws IOException {
		PatchPackedEncode enc = newEncoder();
		enc.openElement(ELEM_COMMAND_GETUSEROPNAME);
		enc.writeSignedInteger(ATTRIB_INDEX, index);
		enc.closeElement(ELEM_COMMAND_GETUSEROPNAME);
		return bytes(enc);
	}

	/**
	 * The query for the register named {@code name} ({@code GhidraTranslate::getRegister}).
	 * @param name the register name
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryRegister(String name) throws IOException {
		PatchPackedEncode enc = newEncoder();
		enc.openElement(ELEM_COMMAND_GETREGISTER);
		enc.writeString(ATTRIB_NAME, name);
		enc.closeElement(ELEM_COMMAND_GETREGISTER);
		return bytes(enc);
	}

	/**
	 * @return the names of the language's registers (each a possible {@link #queryRegister})
	 */
	public List<String> registerNames() {
		List<String> names = new ArrayList<>();
		for (Register r : language.getRegisters()) {
			names.add(r.getName());
		}
		return names;
	}

	/**
	 * The query for the comments of the function at {@code addr} ({@code ArchitectureGhidra::getComments};
	 * {@code flags} is the comment filter of the options, the same for every function).
	 * @param addr the function entry
	 * @param flags the comment type filter
	 * @return the packed query payload
	 * @throws IOException for encoding errors
	 */
	public static byte[] queryComments(Address addr, long flags) throws IOException {
		PatchPackedEncode enc = newEncoder();
		enc.openElement(ELEM_COMMAND_GETCOMMENTS);
		enc.writeUnsignedInteger(ATTRIB_TYPE, flags);
		AddressXML.encode(enc, addr);
		enc.closeElement(ELEM_COMMAND_GETCOMMENTS);
		return bytes(enc);
	}

	/**
	 * The comment filter of a getComments query, or -1 for any other query.
	 * @param query the packed query payload
	 * @return the filter
	 */
	public long commentFlagsOf(byte[] query) {
		try {
			PackedDecode dec = decoder(query);
			if (dec.openElement() != COMMAND_GETCOMMENTS) {
				return -1;
			}
			return dec.readUnsignedInteger(ATTRIB_TYPE);
		}
		catch (IOException | DecoderException e) {
			return -1;
		}
	}

	/** @return the entry of the function set with {@link #setFunction} */
	public Address getFunctionEntry() {
		return funcEntry;
	}

	/**
	 * A readable form of a query (diagnostics): the command and its address or name.
	 * @param query the packed query payload
	 * @return the description
	 */
	public String describe(byte[] query) {
		try {
			PackedDecode dec = decoder(query);
			int cmd = dec.openElement();
			StringBuilder b = new StringBuilder("command " + cmd);
			switch (cmd) {
				case COMMAND_GETMAPPEDSYMBOLS, COMMAND_GETEXTERNALREF, COMMAND_GETPCODE,
						COMMAND_GETCODELABEL, COMMAND_GETTRACKEDREGISTERS: {
					Address addr = AddressXML.decode(dec);
					b.append(" at ").append(addr);
					Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
					b.append(" symbol ").append(s == null ? "-" : s.getName(true));
					if (addr.isMemoryAddress()) {
						b.append(" refsTo ")
								.append(program.getReferenceManager().getReferenceCountTo(addr));
					}
					CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
					b.append(" cu ").append(cu == null ? "-" : cu.getMinAddress() + " " + cu);
					break;
				}
				case COMMAND_GETDATATYPE, COMMAND_GETREGISTER, COMMAND_GETCALLFIXUP,
						COMMAND_GETCALLOTHERFIXUP, COMMAND_GETCALLMECH:
					b.append(" name ").append(dec.readString(ATTRIB_NAME));
					break;
				default:
					break;
			}
			return b.toString();
		}
		catch (Exception e) {
			return "undecodable query: " + e;
		}
	}

	/**
	 * True if {@code response} is a string answer holding the empty string.
	 * @param response a query response
	 * @return true for an empty string answer
	 */
	public static boolean isEmptyString(byte[] response) {
		return response.length == 16 && response[3] == 8 && response[7] == 14 &&
			response[11] == 15 && response[15] == 9;
	}

	private static byte[] addressQuery(ElementId cmd, Address addr) throws IOException {
		PatchPackedEncode enc = newEncoder();
		enc.openElement(cmd);
		AddressXML.encode(enc, addr);
		enc.closeElement(cmd);
		return bytes(enc);
	}

	/**
	 * The command element id of a packed query (for statistics), or -1 if it cannot be read.
	 * @param query the packed query payload
	 * @return the element id
	 */
	public int commandOf(byte[] query) {
		try {
			return decoder(query).openElement();
		}
		catch (IOException | DecoderException e) {
			return -1;
		}
	}

	/** A ready encoder (a new {@link PatchPackedEncode} has no stream until {@code clear}). */
	private static PatchPackedEncode newEncoder() {
		PatchPackedEncode enc = new PatchPackedEncode();
		enc.clear();
		return enc;
	}

	private static byte[] bytes(CachedEncoder enc) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		enc.writeTo(out);
		return out.toByteArray();
	}

	/**
	 * Answer one query of the native decompiler for the function set with {@link #setFunction},
	 * as {@link DecompileProcess} answers it over the pipe (the response bytes, an exception
	 * included).
	 * @param query the packed query payload
	 * @return the answer and its classification
	 */
	public Answer answer(byte[] query) {
		long t0 = System.nanoTime();
		int costCommand = -1;
		try {
			long tempIds = dtmanage.getTemporaryIdCount();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int kind = GLOBAL;
			String why = null;
			try {
				PackedDecode dec = decoder(query);
				int commandId = dec.openElement();
				costCommand = commandId;
				switch (commandId) {
					case COMMAND_ISNAMEUSED: {
						String name = dec.readString(ATTRIB_NAME);
						long startId = dec.readUnsignedInteger(ATTRIB_FIRST);
						long stopId = dec.readUnsignedInteger(ATTRIB_LAST);
						boolean res = callback.isNameUsed(name, startId, stopId);
						out.write(QUERY_RESPONSE_START);
						out.write(STRING_START);
						out.write(res ? 't' : 'f');
						out.write(STRING_END);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETBYTES: {
						int el = dec.openElement(ELEM_ADDR);
						Address addr = AddressXML.decodeFromAttributes(dec);
						int size = (int) dec.readSignedInteger(ATTRIB_SIZE);
						dec.closeElement(el);
						byte[] res = callback.getBytes(addr, size);
						out.write(QUERY_RESPONSE_START);
						if ((res != null) && (res.length > 0)) {
							out.write(BYTE_START);
							byte[] dblres = new byte[res.length * 2];
							for (int i = 0; i < res.length; i++) {
								dblres[i * 2] = (byte) (((res[i] >> 4) & 0xf) + 65);
								dblres[i * 2 + 1] = (byte) ((res[i] & 0xf) + 65);
							}
							out.write(dblres);
							out.write(BYTE_END);
						}
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETCOMMENTS: {
						PatchPackedEncode enc = newEncoder();
						int types = (int) dec.readUnsignedInteger(ATTRIB_TYPE);
						Address addr = AddressXML.decode(dec);
						callback.getComments(addr, types, enc);
						out.write(QUERY_RESPONSE_START);
						writeString(out, enc);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETCALLFIXUP:
					case COMMAND_GETCALLOTHERFIXUP:
					case COMMAND_GETCALLMECH:
					case COMMAND_GETPCODEEXECUTABLE: {
						int type = injectType(commandId);
						String name = dec.readString(ATTRIB_NAME);
						why = injectUnstorable(query, type);
						PatchPackedEncode enc = newEncoder();
						callback.getPcodeInject(name, dec, type, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETCPOOLREF: {
						PatchPackedEncode enc = newEncoder();
						int size = (int) dec.readSignedInteger(ATTRIB_SIZE);
						long refs[] = new long[size];
						for (int i = 0; i < size; ++i) {
							int el = dec.openElement(ELEM_VALUE);
							refs[i] = dec.readUnsignedInteger(ATTRIB_CONTENT);
							dec.closeElement(el);
						}
						callback.getCPoolRef(refs, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETEXTERNALREF: {
						PatchPackedEncode enc = newEncoder();
						Address addr = AddressXML.decode(dec);
						if (addr.equals(funcEntry)) {
							kind = SCOPED;
						}
						callback.getExternalRef(addr, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETMAPPEDSYMBOLS: {
						PatchPackedEncode enc = newEncoder();
						Address addr = AddressXML.decode(dec);
						if (addr.equals(funcEntry)) {
							kind = SCOPED;	// the function's own symbol carries its default names
						}
						callback.getMappedSymbols(addr, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETNAMESPACEPATH: {
						PatchPackedEncode enc = newEncoder();
						long id = dec.readUnsignedInteger(ATTRIB_ID);
						callback.getNamespacePath(id, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETPCODE: {
						PatchPackedEncode enc = newEncoder();
						Address addr = AddressXML.decode(dec);
						if (program.getListing().getInstructionAt(addr) == null) {
							why = "p-code by pseudo-disassembly at " + addr;
						}
						long tp = COST ? System.nanoTime() : 0;
						callback.getPcode(addr, enc);
						if (COST) {
							PCODE_CALLBACK_NANOS.add(System.nanoTime() - tp);
						}
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETREGISTER: {
						PatchPackedEncode enc = newEncoder();
						String name = dec.readString(ATTRIB_NAME);
						callback.getRegister(name, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETREGISTERNAME: {
						int el = dec.openElement(ELEM_ADDR);
						Address addr = AddressXML.decodeFromAttributes(dec);
						int size = (int) dec.readSignedInteger(ATTRIB_SIZE);
						dec.closeElement(el);
						String res = callback.getRegisterName(addr, size);
						out.write(QUERY_RESPONSE_START);
						writeString(out, res);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETSTRINGDATA: {
						int maxChars = (int) dec.readSignedInteger(ATTRIB_MAXSIZE);
						String dtName = dec.readString(ATTRIB_TYPE);
						long dtId = dec.readUnsignedInteger(ATTRIB_ID);
						Address addr = AddressXML.decode(dec);
						DecompileCallback.StringData stringData =
							callback.getStringData(addr, maxChars, dtName, dtId);
						out.write(QUERY_RESPONSE_START);
						if (stringData != null) {
							byte[] res = stringData.byteData;
							int sz = res.length + 1;		// We add a null terminator character
							int sz1 = (sz & 0x3f) + 0x20;
							sz >>>= 6;
							int sz2 = (sz & 0x3f) + 0x20;
							out.write(BYTE_START);
							out.write(sz1);
							out.write(sz2);
							out.write(stringData.isTruncated ? 1 : 0);
							byte[] dblres = new byte[res.length * 2 + 2];
							for (int i = 0; i < res.length; i++) {
								dblres[i * 2] = (byte) (((res[i] >> 4) & 0xf) + 65);
								dblres[i * 2 + 1] = (byte) ((res[i] & 0xf) + 65);
							}
							dblres[res.length * 2] = 65;		// Adding null terminator
							dblres[res.length * 2 + 1] = 65;
							out.write(dblres);
							out.write(BYTE_END);
						}
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETCODELABEL: {
						Address addr = AddressXML.decode(dec);
						if (inFunctionNamespace(addr)) {
							kind = SCOPED;	// the label's prefix leaves out the decompiled function
						}
						String res = callback.getCodeLabel(addr);
						if (res == null) {
							res = "";
						}
						out.write(QUERY_RESPONSE_START);
						writeString(out, res);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETDATATYPE: {
						PatchPackedEncode enc = newEncoder();
						String name = dec.readString(ATTRIB_NAME);
						long id = dec.readSignedInteger(ATTRIB_ID);
						callback.getDataType(name, id, enc);
						writeOptional(out, enc);
						break;
					}
					case COMMAND_GETTRACKEDREGISTERS: {
						PatchPackedEncode enc = newEncoder();
						Address addr = AddressXML.decode(dec);
						callback.getTrackedRegisters(addr, enc);
						out.write(QUERY_RESPONSE_START);
						writeString(out, enc);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					case COMMAND_GETUSEROPNAME: {
						int index = (int) dec.readSignedInteger(ATTRIB_INDEX);
						String res = callback.getUserOpName(index);
						if (res == null) {
							res = "";
						}
						out.write(QUERY_RESPONSE_START);
						writeString(out, res);
						out.write(QUERY_RESPONSE_END);
						break;
					}
					default:
						throw new Exception("Unsupported decompiler query");
				}
			}
			catch (Exception e) { // DecompileProcess passes ANY exception down to the decompiler
				out.reset();
				try {
					out.write(EXCEPTION_START);
					String msg = e.getMessage();
					writeString(out, e.getClass().getName());
					writeString(out, msg == null ? "" : msg);
					out.write(EXCEPTION_END);
				}
				catch (IOException e1) {
					// a ByteArrayOutputStream does not throw
				}
			}
			if (dtmanage.getTemporaryIdCount() != tempIds) {
				// a temporary data-type id lives for one decompilation only
				why = "temporary data-type id";
				dtmanage.clearTemporaryIds();
			}
			if (why != null) {
				return new Answer(out.toByteArray(), UNSTORABLE, why);
			}
			return new Answer(out.toByteArray(), kind, null);
		}
		finally {
			long dt = System.nanoTime() - t0;
			ANSWER_NANOS.add(dt);
			ANSWER_CALLS.increment();
			if (COST) {
				COST_NANOS[costCommand & 0xff].add(dt);
				COST_CALLS[costCommand & 0xff].increment();
			}
		}
	}

	private static final java.util.concurrent.atomic.LongAdder ANSWER_NANOS =
		new java.util.concurrent.atomic.LongAdder();
	private static final java.util.concurrent.atomic.LongAdder ANSWER_CALLS =
		new java.util.concurrent.atomic.LongAdder();

	/** Per-command answer cost (diagnostics; on with {@code -Dhydra.decomp.host.cost=true}). */
	private static final boolean COST = Boolean.getBoolean("hydra.decomp.host.cost");
	private static final java.util.concurrent.atomic.LongAdder[] COST_NANOS =
		new java.util.concurrent.atomic.LongAdder[256];
	private static final java.util.concurrent.atomic.LongAdder[] COST_CALLS =
		new java.util.concurrent.atomic.LongAdder[256];
	private static final java.util.concurrent.atomic.LongAdder PCODE_CALLBACK_NANOS =
		new java.util.concurrent.atomic.LongAdder();
	static {
		for (int i = 0; i < 256; i++) {
			COST_NANOS[i] = new java.util.concurrent.atomic.LongAdder();
			COST_CALLS[i] = new java.util.concurrent.atomic.LongAdder();
		}
	}

	/** @return the time inside {@code DecompileCallback.getPcode} (diagnostics) */
	public static long pcodeCallbackNanos() {
		return PCODE_CALLBACK_NANOS.sum();
	}

	/** @return per-command answers and their time, as {@code id -> {calls, nanos}} (diagnostics) */
	public static java.util.Map<Integer, long[]> commandCost() {
		java.util.Map<Integer, long[]> m = new java.util.TreeMap<>();
		for (int i = 0; i < 256; i++) {
			long c = COST_CALLS[i].sum();
			if (c > 0) {
				m.put(i, new long[] { c, COST_NANOS[i].sum() });
			}
		}
		return m;
	}

	/** @return the answers computed since start and the time they took (diagnostics) */
	public static long[] answerCost() {
		return new long[] { ANSWER_CALLS.sum(), ANSWER_NANOS.sum() };
	}

	/**
	 * The answer to the p-code query for {@code addr}, computed without decoding the query again:
	 * the prefetch builds the query itself and knows the instruction exists. Same bytes as
	 * {@link #answer} produces for a {@code COMMAND_GETPCODE} query whose address is an
	 * instruction.
	 * @param addr the instruction address (an instruction is in the listing)
	 * @return the answer
	 */
	public Answer answerPcode(Address addr) {
		long t0 = System.nanoTime();
		try {
			long tempIds = dtmanage.getTemporaryIdCount();
			ByteArrayOutputStream out = new ByteArrayOutputStream(64);
			PatchPackedEncode enc = newEncoder();
			try {
				callback.getPcode(addr, enc);
				out.write(QUERY_RESPONSE_START);
				if (!enc.isEmpty()) {
					writeString(out, enc);
				}
				out.write(QUERY_RESPONSE_END);
			}
			catch (Exception e) {	// DecompileProcess passes ANY exception down to the decompiler
				out.reset();
				out.write(EXCEPTION_START);
				String msg = e.getMessage();
				writeString(out, e.getClass().getName());
				writeString(out, msg == null ? "" : msg);
				out.write(EXCEPTION_END);
			}
			boolean temp = dtmanage.getTemporaryIdCount() != tempIds;
			if (temp) {
				dtmanage.clearTemporaryIds();
				return new Answer(out.toByteArray(), UNSTORABLE, "temporary data-type id");
			}
			return new Answer(out.toByteArray(), GLOBAL, null);
		}
		catch (IOException e) {
			return new Answer(new byte[0], UNSTORABLE, "p-code answer: " + e);
		}
		finally {
			long dt = System.nanoTime() - t0;
			ANSWER_NANOS.add(dt);
			ANSWER_CALLS.increment();
			if (COST) {
				COST_NANOS[COMMAND_GETPCODE & 0xff].add(dt);
				COST_CALLS[COMMAND_GETPCODE & 0xff].increment();
			}
		}
	}

	private static int injectType(int commandId) {
		return switch (commandId) {
			case COMMAND_GETCALLFIXUP -> InjectPayload.CALLFIXUP_TYPE;
			case COMMAND_GETCALLOTHERFIXUP -> InjectPayload.CALLOTHERFIXUP_TYPE;
			case COMMAND_GETCALLMECH -> InjectPayload.CALLMECHANISM_TYPE;
			default -> InjectPayload.EXECUTABLEPCODE_TYPE;
		};
	}

	/**
	 * An injection at an address with no instruction in the listing uses pseudo-disassembly,
	 * which keeps state between queries of one decompilation.
	 */
	private String injectUnstorable(byte[] query, int type) {
		if (type == InjectPayload.EXECUTABLEPCODE_TYPE) {
			return null;
		}
		try {
			PackedDecode dec = decoder(query);
			dec.openElement();
			dec.readString(ATTRIB_NAME);
			InjectContext con = compilerSpec.getPcodeInjectLibrary().buildInjectContext();
			con.decode(dec);
			if (con.baseAddr == null || program.getListing().getInstructionAt(con.baseAddr) == null) {
				return "injection at an address with no instruction";
			}
			return null;
		}
		catch (Exception e) {
			return "injection context: " + e.getMessage();
		}
	}

	/** True if the primary symbol at {@code addr} sits in a function's namespace (at any depth). */
	private boolean inFunctionNamespace(Address addr) {
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
		if (sym == null) {
			return false;
		}
		Namespace ns = sym.getParentNamespace();
		while (ns != null && ns.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
			if (ns instanceof Function) {
				return true;
			}
			ns = ns.getParentNamespace();
		}
		return false;
	}

	private PackedDecode decoder(byte[] bytes) throws IOException {
		PackedDecode dec = new PackedDecode(program.getAddressFactory());
		dec.open(Math.max(1 << 16, bytes.length + 16), program.getName());
		dec.ingestBytes(bytes, 0, bytes.length);
		dec.endIngest();
		return dec;
	}

	/** {@code DecompileProcess.writeString(String)}: the platform encoding, as the process path. */
	private static void writeString(ByteArrayOutputStream out, String msg) throws IOException {
		out.write(STRING_START);
		out.write(msg.getBytes());
		out.write(STRING_END);
	}

	private static void writeString(ByteArrayOutputStream out, CachedEncoder enc)
			throws IOException {
		out.write(STRING_START);
		enc.writeTo(out);
		out.write(STRING_END);
	}

	/** A response with an optional encoded body, as most query handlers write it. */
	private static void writeOptional(ByteArrayOutputStream out, CachedEncoder enc)
			throws IOException {
		out.write(QUERY_RESPONSE_START);
		if (!enc.isEmpty()) {
			writeString(out, enc);
		}
		out.write(QUERY_RESPONSE_END);
	}

	/**
	 * Decode the command response of a host decompile ({@code decompile.exe}'s output for
	 * decompileAt) into the results {@code DecompInterface.decompileFunction} returns for the same
	 * bytes, or null when they are not those of a normal completed run (an exception record, a
	 * result over the payload limit, a malformed stream): the caller then takes the process path.
	 * @param f the decompiled function (set with {@link #setFunction})
	 * @param response the command response bytes
	 * @param maxPayloadMBytes the result size limit ({@code DecompileOptions.getMaxPayloadMBytes})
	 * @return the results, or null
	 */
	public DecompileResults decodeResults(Function f, byte[] response, int maxPayloadMBytes) {
		ResponseReader r = new ResponseReader(response);
		int type = r.nextBurst();
		if (type != 6) {
			return null;
		}
		int mainStart = -1;
		int mainEnd = -1;
		boolean mainOpen = false;
		String errorMessage = "";
		for (;;) {
			type = r.nextBurst();
			switch (type) {
				case 7:
					break;
				case 14:
					if (mainStart >= 0) {
						return null;
					}
					mainStart = r.pos;
					mainEnd = r.skipToZero();
					mainOpen = true;
					continue;
				case 15:
					mainOpen = false;
					continue;
				case 16: {
					if (mainOpen) {	// an error before the end of the main response: not parsed
						mainStart = -1;
						mainOpen = false;
					}
					int s = r.pos;
					int e = r.skipToZero();
					if (r.nextBurst() != 17) {
						return null;
					}
					errorMessage = new String(response, s, e - s);
					continue;
				}
				case 18: {
					int s = r.pos;
					int e = r.skipToZero();
					if (r.nextBurst() != 19) {
						return null;
					}
					ghidra.util.Msg.warn(DecompileProcess.class, new String(response, s, e - s));
					continue;
				}
				default:
					return null;	// an exception record, or anything unexpected
			}
			break;
		}
		if (r.pos != response.length) {
			return null;
		}
		try {
			PackedDecode decoder = new PackedDecode(program.getAddressFactory());
			if (mainStart >= 0 && mainEnd > mainStart) {
				long max = ((long) maxPayloadMBytes) << 20;
				if (mainEnd - mainStart > max) {
					return null;
				}
				decoder.open(max, program.getName());
				decoder.ingestBytes(response, mainStart, mainEnd - mainStart);
				decoder.endIngest();
			}
			return new DecompileResults(f, language, compilerSpec, dtmanage, errorMessage, decoder,
				DecompileProcess.DisposeState.NOT_DISPOSED);
		}
		catch (IOException e) {
			return null;
		}
	}

	/** Reads the burst framing of a command response (DecompileProcess.readToBurst). */
	private static final class ResponseReader {
		final byte[] b;
		int pos;

		ResponseReader(byte[] b) {
			this.b = b;
		}

		/** The next burst code, or -1 at the end. */
		int nextBurst() {
			while (pos < b.length && b[pos] != 0) {
				pos++;
			}
			while (pos < b.length && b[pos] == 0) {
				pos++;
			}
			if (pos + 1 < b.length && b[pos] == 1) {
				int code = b[pos + 1] & 0xff;
				pos += 2;
				return code;
			}
			pos = b.length;
			return -1;
		}

		/** Moves to the next zero byte and returns its index. */
		int skipToZero() {
			while (pos < b.length && b[pos] != 0) {
				pos++;
			}
			return pos;
		}
	}
}
