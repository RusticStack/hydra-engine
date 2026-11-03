import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.GhidraApplicationLayout;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.DataType;

/**
 * Program-level oracle for the ghidra-progdb differential tests. Opens a Program database
 * read-only (OpenMode.IMMUTABLE) through the stock ProgramDB and prints the language, address
 * spaces, memory blocks (with their sub blocks) and the symbol table, one line per item, in the
 * format the Rust test reproduces.
 *
 * Usage: java -cp ... OracleProgram installDir db.gbf
 */
public class OracleProgram {

    static String addr(Address a) {
        if (a == null) {
            return "null";
        }
        if (a == Address.NO_ADDRESS) {
            return "NO_ADDRESS";
        }
        if (a == Address.EXT_FROM_ADDRESS) {
            return "EXT_FROM";
        }
        return a.getAddressSpace().getName() + ":" + Long.toHexString(a.getOffset());
    }

    public static void main(String[] a) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(a[0])),
            new HeadlessGhidraApplicationConfiguration());
        DBHandle h = new DBHandle(new File(a[1]));
        ProgramDB p = new ProgramDB(h, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, OracleProgram.class);
        System.out.println("stored_version=" + p.getStoredVersion());
        System.out.println("language=" + p.getLanguageID().getIdAsString());
        System.out.println("compiler=" + p.getCompilerSpec().getCompilerSpecID().getIdAsString());
        System.out.println("image_base=" + addr(p.getImageBase()));
        System.out.println("default_space=" + p.getAddressFactory().getDefaultAddressSpace().getName());
        List<AddressSpace> spaces = new ArrayList<>();
        for (AddressSpace s : p.getAddressFactory().getAllAddressSpaces()) {
            spaces.add(s);
        }
        spaces.sort(Comparator.comparingInt(AddressSpace::getSpaceID));
        for (AddressSpace s : spaces) {
            System.out.println("space name=" + s.getName() + " id=" + s.getSpaceID() + " bits="
                + s.getSize() + " type=" + s.getType());
        }
        MemoryBlock[] blocks = p.getMemory().getBlocks();
        System.out.println("blocks=" + blocks.length);
        for (MemoryBlock b : blocks) {
            System.out.println("block name=" + b.getName() + " start=" + addr(b.getStart())
                + " end=" + addr(b.getEnd()) + " size=" + b.getSize() + " r=" + b.isRead() + " w="
                + b.isWrite() + " x=" + b.isExecute() + " vol=" + b.isVolatile() + " art="
                + b.isArtificial() + " init=" + b.isInitialized() + " overlay=" + b.isOverlay()
                + " mapped=" + b.isMapped() + " comment=[" + b.getComment() + "] source=["
                + b.getSourceName() + "] subs=" + b.getSourceInfos().size());
            for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
                String kind = si.getFileBytes().isPresent() ? "file_bytes"
                    : si.getMappedRange().isPresent() ? "mapped"
                    : b.isInitialized() ? "init" : "uninit";
                System.out.println("  sub kind=" + kind + " len=" + si.getLength() + " off="
                    + (si.getMinAddress().subtract(b.getStart())));
            }
        }
        List<Symbol> syms = new ArrayList<>();
        // every row of the symbol table, by id (getAllSymbols leaves out parameters and locals)
        long maxId = h.getTable("Symbols").getMaxKey();
        for (long id = 1; id <= maxId; id++) {
            Symbol sym = p.getSymbolTable().getSymbol(id);
            if (sym != null) {
                syms.add(sym);
            }
        }
        Collections.sort(syms, Comparator.comparingLong(Symbol::getID));
        System.out.println("symbols=" + syms.size());
        for (Symbol s : syms) {
            SourceType src = s.getSource();
            String name = src == SourceType.DEFAULT ? "" : s.getName();
            System.out.println("sym id=" + s.getID() + " name=[" + name + "] addr="
                + addr(s.getAddress()) + " parent=" + (s.getParentSymbol() == null ? 0 : s.getParentSymbol().getID()) + " type="
                + s.getSymbolType().getID() + " source=" + src.name() + " primary="
                + s.isPrimary() + " pinned=" + s.isPinned());
        }
        dumpListing(p);
        p.release(OracleProgram.class);
        System.exit(0);
    }

    static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r");
    }

    static void emit(List<String[]> rows) {
        rows.sort(Comparator.comparing((String[] r) -> r[0]));
        for (String[] r : rows) {
            System.out.println(r[1]);
        }
    }

    static String refLine(String tag, Reference r) {
        String extra = r instanceof OffsetReference o ? " offset=" + o.getOffset()
            : r instanceof ShiftedReference sh ? " shift=" + sh.getShift() : "";
        return tag + " from=" + addr(r.getFromAddress()) + " to=" + addr(r.getToAddress())
            + " type=" + r.getReferenceType().getName() + " op=" + r.getOperandIndex() + " src="
            + r.getSource().name() + " primary=" + r.isPrimary() + " sym=" + r.getSymbolID()
            + " kind=" + r.getClass().getSimpleName() + extra;
    }

    static void dumpListing(ProgramDB p) throws Exception {
        // functions (thunks print only their link, the rest delegates to the thunked function)
        List<Function> fns = new ArrayList<>();
        for (FunctionIterator it = p.getFunctionManager().getFunctions(true); it.hasNext();) {
            fns.add(it.next());
        }
        // getFunctions leaves out functions in the external space
        for (FunctionIterator it = p.getFunctionManager().getExternalFunctions(); it.hasNext();) {
            fns.add(it.next());
        }
        fns.sort(Comparator.comparingLong(Function::getID));
        System.out.println("functions=" + fns.size());
        for (Function f : fns) {
            if (f.isThunk()) {
                System.out.println("func id=" + f.getID() + " entry=" + addr(f.getEntryPoint())
                    + " thunk=" + f.getThunkedFunction(false).getID());
            }
            else {
                System.out.println("func id=" + f.getID() + " entry=" + addr(f.getEntryPoint())
                    + " thunk=-1 vararg=" + f.hasVarArgs() + " inline=" + f.isInline()
                    + " noreturn=" + f.hasNoReturn() + " custom=" + f.hasCustomVariableStorage()
                    + " cc=" + f.getCallingConventionName() + " purge=" + f.getStackPurgeSize()
                    + " sigsrc=" + f.getSignatureSource().name());
            }
        }
        ghidra.program.model.address.AddressSet all = new ghidra.program.model.address.AddressSet();
        for (AddressSpace sp : p.getAddressFactory().getAllAddressSpaces()) {
            if (sp.isMemorySpace() || sp.isExternalSpace()) {
                all.add(sp.getMinAddress(), sp.getMaxAddress());
            }
        }
        ReferenceManager rm = p.getReferenceManager();
        List<String[]> rows = new ArrayList<>();
        for (AddressIterator it = rm.getReferenceSourceIterator(all, true); it
            .hasNext();) {
            Address from = it.next();
            for (Reference r : rm.getReferencesFrom(from)) {
                rows.add(new String[] { addr(from), refLine("ref", r) });
            }
        }
        for (Reference r : rm.getReferencesFrom(Address.EXT_FROM_ADDRESS)) {
            rows.add(new String[] { addr(Address.EXT_FROM_ADDRESS), refLine("ref", r) });
        }
        System.out.println("ref_sources=" + rows.size());
        emit(rows);
        rows = new ArrayList<>();
        for (AddressIterator it = rm.getReferenceDestinationIterator(all, true); it
            .hasNext();) {
            Address to = it.next();
            if (to.isStackAddress() || to.isRegisterAddress()) {
                continue;
            }
            for (ReferenceIterator ri = rm.getReferencesTo(to); ri.hasNext();) {
                rows.add(new String[] { addr(to), refLine("toref", ri.next()) });
            }
        }
        System.out.println("ref_destinations=" + rows.size());
        emit(rows);
        Listing l = p.getListing();
        rows = new ArrayList<>();
        for (InstructionIterator it = l.getInstructions(true); it.hasNext();) {
            Address at = it.next().getAddress();
            rows.add(new String[] { addr(at), "inst addr=" + addr(at) });
        }
        System.out.println("instructions=" + rows.size());
        emit(rows);
        rows = new ArrayList<>();
        for (DataIterator it = l.getDefinedData(true); it.hasNext();) {
            Data d = it.next();
            rows.add(new String[] { addr(d.getAddress()), "data addr=" + addr(d.getAddress())
                + " type=" + p.getDataTypeManager().getID(d.getDataType()) });
        }
        System.out.println("data=" + rows.size());
        emit(rows);
        rows = new ArrayList<>();
        for (AddressIterator it = l.getCommentAddressIterator(all, true); it
            .hasNext();) {
            Address at = it.next();
            for (CommentType t : CommentType.values()) {
                String c = l.getComment(t, at);
                if (c != null) {
                    rows.add(new String[] { addr(at) + " " + t.ordinal(),
                        "comment addr=" + addr(at) + " kind=" + t.name() + " text=[" + esc(c) + "]" });
                }
            }
        }
        System.out.println("comments=" + rows.size());
        emit(rows);
    }
}
