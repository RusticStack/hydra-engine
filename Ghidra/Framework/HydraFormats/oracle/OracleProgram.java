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
import ghidra.program.model.address.AddressRange;
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
        dumpMemory(p);
        dumpSymbolQueries(p);
        p.release(OracleProgram.class);
        System.exit(0);
    }

    static String sha(byte[] b, int n) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update(b, 0, n);
        StringBuilder sb = new StringBuilder();
        for (byte x : md.digest()) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    static void memRead(ghidra.program.model.mem.Memory mem, Address a, int len) throws Exception {
        byte[] buf = new byte[len];
        try {
            int n = mem.getBytes(a, buf, 0, len);
            System.out.println("memread addr=" + addr(a) + " len=" + len + " n=" + n + " sha256="
                + sha(buf, n));
        }
        catch (ghidra.program.model.mem.MemoryAccessException e) {
            System.out.println("memread addr=" + addr(a) + " len=" + len + " error");
        }
    }

    static void dumpMemory(ProgramDB p) throws Exception {
        ghidra.program.model.mem.Memory mem = p.getMemory();
        for (MemoryBlock b : mem.getBlocks()) {
            Address s = b.getStart();
            int size = (int) b.getSize();
            byte[] buf = new byte[size];
            try {
                int n = mem.getBytes(s, buf, 0, size);
                System.out.println("memblock name=" + b.getName() + " n=" + n + " sha256="
                    + sha(buf, n));
            }
            catch (ghidra.program.model.mem.MemoryAccessException e) {
                System.out.println("memblock name=" + b.getName() + " error");
            }
            memRead(mem, s, 16);
            memRead(mem, b.getEnd().subtract(7), 32);
            memRead(mem, b.getEnd().subtract(3), 4096);
            memRead(mem, s.add(size / 2), 4096);
            try {
                memRead(mem, s.subtract(1), 8);
            }
            catch (Exception e) {
                System.out.println("memread before-start skipped");
            }
        }
    }

    static String ids(java.util.Collection<? extends Symbol> list) {
        StringBuilder sb = new StringBuilder();
        for (Symbol s : list) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(s.getID());
        }
        return sb.toString();
    }

    static void dumpSymbolQueries(ProgramDB p) throws Exception {
        SymbolTable st = p.getSymbolTable();
        long maxId = p.getDBHandle().getTable("Symbols").getMaxKey();
        List<Symbol> syms = new ArrayList<>();
        for (long id = 1; id <= maxId; id++) {
            Symbol s = st.getSymbol(id);
            if (s != null) {
                syms.add(s);
            }
        }
        // names Java computes for default functions and parameters
        List<String[]> rows = new ArrayList<>();
        for (Symbol s : syms) {
            int t = s.getSymbolType().getID();
            if (s.getSource() == SourceType.DEFAULT && (t == 5 || t == 6)) {
                rows.add(new String[] { String.format("%020d", s.getID()),
                    "symname id=" + s.getID() + " name=[" + esc(s.getName()) + "]" });
            }
        }
        System.out.println("symnames=" + rows.size());
        emit(rows);
        // symbols at each distinct symbol address, and the primary symbol there
        rows = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Symbol s : syms) {
            Address at = s.getAddress();
            if (at.isStackAddress() || at.isRegisterAddress() || at.isVariableAddress()
                || !seen.add(addr(at))) {
                continue;
            }
            Symbol[] list = st.getSymbols(at);
            StringBuilder sb = new StringBuilder();
            for (Symbol x : list) {
                if (sb.length() > 0) {
                    sb.append(',');
                }
                sb.append(x.getID());
            }
            Symbol prim = st.getPrimarySymbol(at);
            long pid = prim == null || prim.isDynamic() ? -1 : prim.getID();
            rows.add(new String[] { addr(at), "symat addr=" + addr(at) + " ids=[" + sb
                + "] primary=" + pid });
        }
        System.out.println("symat=" + rows.size());
        emit(rows);
        // by name over all namespaces, and by name within a namespace
        rows = new ArrayList<>();
        java.util.Set<String> names = new java.util.TreeSet<>();
        java.util.Set<String> pairs = new java.util.TreeSet<>();
        for (Symbol s : syms) {
            if (s.getSource() != SourceType.DEFAULT) {
                names.add(s.getName());
                pairs.add(s.getName() + "\u0000" + (s.getParentSymbol() == null ? 0
                    : s.getParentSymbol().getID()));
            }
        }
        for (Symbol s : syms) {
            int t = s.getSymbolType().getID();
            if (s.getSource() == SourceType.DEFAULT && (t == 5 || t == 6)) {
                names.add(s.getName());
                pairs.add(s.getName() + "\u0000" + s.getParentNamespace().getID());
            }
        }
        for (String n : names) {
            List<Symbol> found = new ArrayList<>();
            for (SymbolIterator it = st.getSymbols(n); it.hasNext();) {
                found.add(it.next());
            }
            rows.add(new String[] { n, "symbyname name=[" + esc(n) + "] ids=[" + ids(found) + "]" });
        }
        System.out.println("symbynames=" + rows.size());
        emit(rows);
        rows = new ArrayList<>();
        for (String pr : pairs) {
            String n = pr.substring(0, pr.indexOf('\u0000'));
            long nsId = Long.parseLong(pr.substring(pr.indexOf('\u0000') + 1));
            Namespace ns;
            if (nsId == 0) {
                ns = p.getGlobalNamespace();
            }
            else {
                Object o = st.getSymbol(nsId).getObject();
                if (!(o instanceof Namespace)) {
                    continue;
                }
                ns = (Namespace) o;
            }
            rows.add(new String[] { String.format("%020d", nsId) + n, "symbyns name=[" + esc(n)
                + "] ns=" + nsId + " ids=[" + ids(st.getSymbols(n, ns)) + "]" });
        }
        System.out.println("symbyns=" + rows.size());
        emit(rows);
        // children of every namespace
        rows = new ArrayList<>();
        java.util.Set<Long> nsIds = new java.util.TreeSet<>();
        nsIds.add(0L);
        for (Symbol s : syms) {
            nsIds.add(s.getParentSymbol() == null ? 0L : s.getParentSymbol().getID());
        }
        for (long nsId : nsIds) {
            List<Symbol> kids = new ArrayList<>();
            if (nsId == 0) {
                for (SymbolIterator it = st.getSymbols(p.getGlobalNamespace()); it.hasNext();) {
                    kids.add(it.next());
                }
            }
            else {
                Object o = st.getSymbol(nsId).getObject();
                if (!(o instanceof Namespace)) {
                    continue;
                }
                for (SymbolIterator it = st.getSymbols((Namespace) o); it.hasNext();) {
                    kids.add(it.next());
                }
            }
            rows.add(new String[] { String.format("%020d", nsId), "symchildren ns=" + nsId
                + " ids=[" + ids(kids) + "]" });
        }
        System.out.println("symchildren=" + rows.size());
        emit(rows);
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
        // bodies, stack frame return offset, stored variables
        List<String[]> varRows = new ArrayList<>();
        for (Function f : fns) {
            StringBuilder body = new StringBuilder();
            for (AddressRange r : f.getBody().getAddressRanges()) {
                body.append(addr(r.getMinAddress())).append('-').append(addr(r.getMaxAddress()))
                    .append(';');
            }
            System.out.println("fnbody id=" + f.getID() + " ranges=[" + body + "]");
            if (f.isThunk()) {
                continue;
            }
            System.out.println("fnframe id=" + f.getID() + " retoff="
                + f.getStackFrame().getReturnAddressOffset());
            int autoCount = 0;
            for (Parameter pr : f.getParameters()) {
                if (pr.isAutoParameter()) {
                    autoCount++;
                }
            }
            boolean custom = f.hasCustomVariableStorage();
            List<Variable> vars = new ArrayList<>();
            for (Parameter pr : f.getParameters()) {
                if (!pr.isAutoParameter()) {
                    vars.add(pr);
                }
            }
            for (Variable v : f.getLocalVariables()) {
                vars.add(v);
            }
            for (Variable v : vars) {
                boolean param = v instanceof Parameter;
                Symbol sym = v.getSymbol();
                String name = sym.getSource() == SourceType.DEFAULT ? "" : sym.getName();
                String ord = param ? Integer.toString(((Parameter) v).getOrdinal() - autoCount) : "-";
                String first = param ? "-" : Integer.toString(v.getFirstUseOffset());
                String storage = param && !custom ? "-" : v.getVariableStorage().getSerializationString();
                varRows.add(new String[] {
                    String.format("%020d %s %020d", f.getID(), param ? "param" : "local", sym.getID()),
                    "fnvar fn=" + f.getID() + " sym=" + sym.getID() + " kind=" + (param ? "param" : "local")
                        + " name=[" + name + "] src=" + sym.getSource().name() + " ord=" + ord
                        + " first=" + first + " dt=" + p.getDataTypeManager().getID(v.getDataType())
                        + " storage=[" + storage + "]" });
            }
        }
        System.out.println("fnvars=" + varRows.size());
        emit(varRows);
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
