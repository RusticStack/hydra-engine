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
// Shows, with no window, that the "GUI-only" work is plain Java API: bulk C types into a .gdt and
// into the program, enum/union/typedef/function-definition types, typed data with a global label,
// a global rename, a bookmark, auto-create-structure-from-usage, and version tracking from another
// program in the same project (args: [source program path]). Run it as a session script on a
// program you own writable; it prints one "PROBE <capability>: ..." line per capability.
// @category HeadlessSession

import java.io.File;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionParameterFieldLocation;

public class HeadlessApiProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		types();
		dataAndLabels();
		structureFromUsage();
		String[] args = getScriptArgs();
		if (args.length > 0) {
			versionTracking(args[0]);
		}
	}

	/** CParserUtils -> FileDataTypeManager (.gdt) -> program DataTypeManager, plus API types. */
	private void types() throws Exception {
		File dir = Files.createTempDirectory("probe-types").toFile();
		File h = new File(dir, "probe.h");
		Files.writeString(h.toPath(), """
			typedef unsigned int u32;
			enum ProbeKind { PK_NONE = 0, PK_ONE = 1, PK_TWO = 2 };
			struct ProbeNode { struct ProbeNode *next; u32 id; enum ProbeKind kind; void *data; };
			union ProbeValue { u32 u; float f; void *p; };
			typedef int (*ProbeCallback)(struct ProbeNode *node, union ProbeValue v);
			""");
		File gdt = new File(dir, "probe.gdt");
		DataTypeManager[] open = { currentProgram.getDataTypeManager() };
		FileDataTypeManager archive = CParserUtils.parseHeaderFiles(open,
			new String[] { h.getAbsolutePath() }, new String[0], new String[0],
			gdt.getAbsolutePath(), monitor);
		int parsed = archive.getDataTypeCount(true);
		archive.save();
		archive.close();

		FileDataTypeManager reopened = FileDataTypeManager.openFileArchive(gdt, false);
		List<DataType> all = new ArrayList<>();
		reopened.getAllDataTypes(all);
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		dtm.addDataTypes(all, DataTypeConflictHandler.REPLACE_HANDLER, monitor);
		reopened.close();

		CategoryPath cat = new CategoryPath("/probe_api");
		EnumDataType en = new EnumDataType(cat, "ApiEnum", 4);
		en.add("A", 1);
		en.add("B", 2);
		UnionDataType un = new UnionDataType(cat, "ApiUnion");
		un.add(new DWordDataType(), "dw", null);
		un.add(new PointerDataType(), "ptr", null);
		TypedefDataType td = new TypedefDataType(cat, "ApiHandle", new PointerDataType());
		FunctionDefinitionDataType fd = new FunctionDefinitionDataType(cat, "ApiSlot");
		fd.setReturnType(new IntegerDataType());
		fd.setArguments(new ParameterDefinition[] {
			new ParameterDefinitionImpl("self", new PointerDataType(), null) });
		for (DataType t : List.of(en, un, td, fd)) {
			dtm.addDataType(t, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		DataType node = findType(dtm, "ProbeNode");
		println("PROBE types: C parser -> " + gdt.getName() + " with " + parsed +
			" types, reopened and " + all.size() + " applied; ProbeNode " +
			(node == null ? "MISSING" : node.getLength() + " bytes at " + node.getPathName()) +
			"; enum/union/typedef/function-definition " +
			(dtm.getDataType(cat, "ApiSlot") != null ? "created" : "MISSING"));
	}

	private static DataType findType(DataTypeManager dtm, String name) {
		List<DataType> found = new ArrayList<>();
		dtm.findDataTypes(name, found);
		return found.isEmpty() ? null : found.get(0);
	}

	/** Typed data at an address, a global label on it, a global rename, a bookmark. */
	private void dataAndLabels() throws Exception {
		MemoryBlock data = Arrays.stream(currentProgram.getMemory().getBlocks())
				.filter(b -> b.isInitialized() && b.isWrite() && !b.isExecute())
				.findFirst()
				.orElseThrow();
		DataType node = findType(currentProgram.getDataTypeManager(), "ProbeNode");
		Address at = data.getStart().add(0x40);
		Data d = DataUtilities.createData(currentProgram, at, node, -1,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		SymbolTable st = currentProgram.getSymbolTable();
		Symbol label = st.createLabel(at, "g_probeNode", SourceType.USER_DEFINED);
		label.setPrimary();
		Symbol other = null;
		for (Symbol s : st.getAllSymbols(true)) {
			if (s.getSymbolType() == SymbolType.LABEL && s.getSource() != SourceType.DEFAULT &&
				!s.isExternal() && s != label) {
				other = s;
				break;
			}
		}
		String renamed = "none";
		if (other != null) {
			String old = other.getName();
			other.setName("probe_renamed_" + old, SourceType.USER_DEFINED);
			renamed = old + " -> " + other.getName();
		}
		currentProgram.getBookmarkManager()
				.setBookmark(at, BookmarkType.NOTE, "probe", "typed by HeadlessApiProbe");
		println("PROBE data-labels: " + d.getDataType().getName() + " at " + at + " labelled " +
			st.getPrimarySymbol(at).getName() + "; global rename " + renamed + "; bookmarks " +
			currentProgram.getBookmarkManager().getBookmarkCount());
	}

	/** The decompiler's "Auto Create Structure", driven from a parameter location. */
	private void structureFromUsage() {
		int tried = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isThunk() || f.isExternal() || f.getParameterCount() == 0 || tried >= 400) {
				continue;
			}
			Parameter p = f.getParameter(0);
			if (p.getLength() != currentProgram.getDefaultPointerSize() ||
				p.getDataType() instanceof Pointer) {
				continue;
			}
			tried++;
			FillOutStructureCmd cmd = new FillOutStructureCmd(
				new FunctionParameterFieldLocation(currentProgram, f.getEntryPoint(),
					f.getEntryPoint(), 0, f.getSignature().getPrototypeString(), p),
				new DecompileOptions());
			if (cmd.applyTo(currentProgram, monitor)) {
				DataType now = f.getParameter(0).getDataType();
				DataType base = now instanceof Pointer ptr ? ptr.getDataType() : now;
				int fields = base instanceof Structure s ? s.getNumDefinedComponents() : 0;
				println("PROBE structure-from-usage: " + f.getName() + " param 0 is now " +
					now.getName() + " (" + fields + " fields, " + base.getLength() +
					" bytes) after " + tried + " candidate(s)");
				return;
			}
		}
		println("PROBE structure-from-usage: no candidate filled in after " + tried);
	}

	/** Version tracking: a session between two programs of this project, auto-applied. */
	private void versionTracking(String sourcePath) throws Exception {
		DomainFile sf = state.getProject().getProjectData().getFile(sourcePath);
		Program source = (Program) sf.getDomainObject(this, false, false, monitor);
		end(true); // VT takes its own locks; it must not run inside the script's transaction
		VTSessionDB session = new VTSessionDB("probe-vt", source, currentProgram, this);
		try {
			AutoVersionTrackingTask task =
				new AutoVersionTrackingTask(session, new ToolOptions("Version Tracking"));
			task.run(monitor);
			int matches = 0;
			for (VTMatchSet ms : session.getMatchSets()) {
				matches += ms.getMatchCount();
			}
			int carried = 0;
			for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
				if (s.getName().startsWith("session_") || s.getName().startsWith("probe_")) {
					carried++;
				}
			}
			println("PROBE version-tracking: " + sourcePath + " -> " +
				currentProgram.getDomainFile().getPathname() + ": " +
				session.getMatchSets().size() + " match sets, " + matches + " matches, " +
				carried + " user names now in the destination; " + task.getStatusMsg());
		}
		finally {
			session.release(this);
			source.release(this);
			start();
		}
	}
}
