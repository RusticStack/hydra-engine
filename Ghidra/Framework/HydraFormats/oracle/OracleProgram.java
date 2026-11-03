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
            if (b.isOverlay() || b.isMapped()) {
                // overlay blocks and mapped blocks only (the older fixtures have neither): the
                // space the overlay covers and the source range of every mapped part
                String base = b.getStart().getAddressSpace() instanceof
                    ghidra.program.model.address.OverlayAddressSpace os
                        ? os.getOverlayedSpace().getName() : "-";
                StringBuilder sb = new StringBuilder("blockx name=" + b.getName() + " overlay_base="
                    + base + " init=" + b.isInitialized());
                for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
                    sb.append(" part=");
                    if (si.getMappedRange().isPresent()) {
                        sb.append("mapped:" + addr(si.getMappedRange().get().getMinAddress()) + "-"
                            + addr(si.getMappedRange().get().getMaxAddress()));
                    }
                    else {
                        sb.append("data");
                    }
                }
                System.out.println(sb);
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
        dumpDataTypes(p);
        dumpExtras(p);
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

    static long dtId(ghidra.program.model.data.DataTypeManager dtm, DataType dt) {
        if (dt == null) {
            return -1;
        }
        if (dt == DataType.DEFAULT) {
            return 0;
        }
        return dtm.getID(dt);
    }

    static String dtKind(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Structure) {
            return "STRUCT";
        }
        if (dt instanceof ghidra.program.model.data.Union) {
            return "UNION";
        }
        if (dt instanceof ghidra.program.model.data.Enum) {
            return "ENUM";
        }
        if (dt instanceof ghidra.program.model.data.TypeDef) {
            return "TYPEDEF";
        }
        if (dt instanceof ghidra.program.model.data.Pointer) {
            return "POINTER";
        }
        if (dt instanceof ghidra.program.model.data.Array) {
            return "ARRAY";
        }
        if (dt instanceof ghidra.program.model.data.FunctionDefinition) {
            return "FUNCDEF";
        }
        return "BUILTIN";
    }

    static void walkCategories(ghidra.program.model.data.Category c, List<String[]> rows) {
        rows.add(new String[] { String.format("%020d", c.getID()),
            "category id=" + c.getID() + " path=[" + esc(c.getCategoryPathName()) + "]" });
        for (ghidra.program.model.data.Category sub : c.getCategories()) {
            walkCategories(sub, rows);
        }
    }

    static void dumpDataTypes(ProgramDB p) throws Exception {
        ghidra.program.model.data.DataTypeManager dtm = p.getDataTypeManager();
        DBHandle h = p.getDBHandle();
        List<String[]> rows = new ArrayList<>();
        walkCategories(dtm.getRootCategory(), rows);
        System.out.println("categories=" + rows.size());
        emit(rows);
        String[] tables = { "Built-in datatypes", "Composite Data Types", "Enumeration Data Types",
            "Typedefs", "Pointers", "Arrays", "Function Definitions" };
        rows = new ArrayList<>();
        List<String[]> sub = new ArrayList<>();
        for (String tn : tables) {
            db.Table t = h.getTable(tn);
            if (t == null) {
                continue;
            }
            for (db.RecordIterator it = t.iterator(); it.hasNext();) {
                long id = it.next().getKey();
                DataType dt = dtm.getDataType(id);
                String key = String.format("%020d", id);
                if (dt == null) {
                    rows.add(new String[] { key, "dt id=" + id + " missing" });
                    continue;
                }
                String kind = switch (tn) {
                    case "Built-in datatypes" -> "BUILTIN";
                    case "Composite Data Types" -> dtKind(dt);
                    case "Enumeration Data Types" -> "ENUM";
                    case "Typedefs" -> "TYPEDEF";
                    case "Pointers" -> "POINTER";
                    case "Arrays" -> "ARRAY";
                    default -> "FUNCDEF";
                };
                String base = "";
                if (kind.equals("TYPEDEF")) {
                    base = " base=" + dtId(dtm, ((ghidra.program.model.data.TypeDef) dt).getDataType());
                }
                else if (kind.equals("POINTER")) {
                    base = " base=" + dtId(dtm, ((ghidra.program.model.data.Pointer) dt).getDataType());
                }
                else if (kind.equals("ARRAY")) {
                    ghidra.program.model.data.Array ar = (ghidra.program.model.data.Array) dt;
                    base = " base=" + dtId(dtm, ar.getDataType()) + " n=" + ar.getNumElements();
                }
                String cls = kind.equals("BUILTIN") ? " class=" + dt.getClass().getName() : "";
                rows.add(new String[] { key, "dt id=" + id + " kind=" + kind + " name=["
                    + esc(dt.getName()) + "] path=[" + esc(dt.getPathName()) + "] len="
                    + dt.getLength() + base + cls });
                if (kind.equals("STRUCT") || kind.equals("UNION")) {
                    ghidra.program.model.data.Composite comp = (ghidra.program.model.data.Composite) dt;
                    sub.add(new String[] { key + "000000", "dtcomment id=" + id + " text=["
                        + esc(comp.getDescription()) + "]" });
                    for (ghidra.program.model.data.DataTypeComponent dc : comp
                        .getDefinedComponents()) {
                        sub.add(new String[] { key + String.format("%06d", dc.getOrdinal() + 1),
                            "comp parent=" + id + " ord=" + dc.getOrdinal() + " off="
                                + dc.getOffset() + " type=" + dtId(dtm, dc.getDataType())
                                + " name=[" + esc(dc.getFieldName()) + "] comment=["
                                + esc(dc.getComment()) + "] len=" + dc.getLength() });
                    }
                }
                else if (kind.equals("ENUM")) {
                    ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
                    sub.add(new String[] { key + "000000", "dtcomment id=" + id + " text=["
                        + esc(en.getDescription()) + "]" });
                    int i = 0;
                    for (String n : en.getNames()) {
                        sub.add(new String[] { key + String.format("%06d", ++i),
                            "enumv parent=" + id + " idx=" + i + " name=[" + esc(n) + "] value="
                                + en.getValue(n) + " comment=[" + esc(en.getComment(n)) + "]" });
                    }
                }
                else if (kind.equals("FUNCDEF")) {
                    ghidra.program.model.data.FunctionDefinition fd = (ghidra.program.model.data.FunctionDefinition) dt;
                    sub.add(new String[] { key + "000000", "dtcomment id=" + id + " text=["
                        + esc(fd.getComment()) + "]" });
                    sub.add(new String[] { key + "000001", "funcdef id=" + id + " ret="
                        + dtId(dtm, fd.getReturnType()) + " varargs=" + fd.hasVarArgs()
                        + " noreturn=" + fd.hasNoReturn() + " cc=[" + esc(fd.getCallingConventionName())
                        + "] params=" + fd.getArguments().length });
                    for (ghidra.program.model.data.ParameterDefinition pd : fd.getArguments()) {
                        sub.add(new String[] { key + String.format("%06d", pd.getOrdinal() + 2),
                            "fparam parent=" + id + " ord=" + pd.getOrdinal() + " type="
                                + dtId(dtm, pd.getDataType()) + " name=[" + esc(pd.getName())
                                + "] comment=[" + esc(pd.getComment()) + "]" });
                    }
                }
            }
        }
        System.out.println("datatypes=" + rows.size());
        emit(rows);
        System.out.println("datatype_details=" + sub.size());
        emit(sub);
        // the default type and the kinds the data rows use
        System.out.println("dt_default name=[" + DataType.DEFAULT.getName() + "] len="
            + DataType.DEFAULT.getLength());
    }

    static String hex(byte[] b) {
        if (b == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    static void dumpExtras(ProgramDB p) throws Exception {
        List<String[]> rows = new ArrayList<>();
        // equates
        for (ghidra.program.model.symbol.Equate e : iterable(p.getEquateTable().getEquates())) {
            rows.add(new String[] { e.getName(), "equate name=[" + esc(e.getName()) + "] value="
                + e.getValue() + " refs=" + e.getReferenceCount() });
            List<String[]> refs = new ArrayList<>();
            for (ghidra.program.model.symbol.EquateReference r : e.getReferences()) {
                String line = "equateref name=[" + esc(e.getName()) + "] addr=" + addr(r.getAddress())
                    + " op=" + r.getOpIndex() + " hash=" + r.getDynamicHashValue();
                refs.add(new String[] { String.format("%s %s %08d %020d", e.getName(), addr(r.getAddress()),
                    r.getOpIndex(), r.getDynamicHashValue()), line });
            }
            refs.sort(Comparator.comparing((String[] r) -> r[0]));
            for (String[] r : refs) {
                rows.add(new String[] { e.getName() + "\u0001" + r[0], r[1] });
            }
        }
        System.out.println("equates=" + rows.size());
        emit(rows);

        // bookmarks
        BookmarkManager bm = p.getBookmarkManager();
        rows = new ArrayList<>();
        for (BookmarkType t : bm.getBookmarkTypes()) {
            rows.add(new String[] { t.getTypeString(), "booktype name=[" + esc(t.getTypeString()) + "]" });
        }
        System.out.println("bookmark_types=" + rows.size());
        emit(rows);
        rows = new ArrayList<>();
        for (java.util.Iterator<Bookmark> it = bm.getBookmarksIterator(); it.hasNext();) {
            Bookmark b = it.next();
            rows.add(new String[] { String.format("%020d", b.getId()), "bookmark id=" + b.getId()
                + " addr=" + addr(b.getAddress()) + " type=[" + esc(b.getTypeString()) + "] cat=["
                + esc(b.getCategory()) + "] comment=[" + esc(b.getComment()) + "]" });
        }
        System.out.println("bookmarks=" + rows.size());
        emit(rows);

        // relocations (index order: by address, then stored order)
        rows = new ArrayList<>();
        int n = 0;
        for (java.util.Iterator<ghidra.program.model.reloc.Relocation> it = p.getRelocationTable()
            .getRelocations(); it.hasNext();) {
            ghidra.program.model.reloc.Relocation r = it.next();
            StringBuilder vs = new StringBuilder();
            for (long v : r.getValues() == null ? new long[0] : r.getValues()) {
                if (vs.length() > 0) {
                    vs.append(',');
                }
                vs.append(v);
            }
            rows.add(new String[] { String.format("%08d", n++), "reloc addr=" + addr(r.getAddress())
                + " status=" + r.getStatus().name() + " type=" + r.getType() + " values=[" + vs
                + "]" + (r.getValues() == null ? " valuesnull" : "") + " bytes=" + hex(r.getBytes()) + " symbol=[" + esc(r.getSymbolName()) + "]" });
        }
        System.out.println("relocations=" + rows.size());
        for (String[] r : rows) {
            System.out.println(r[1]);
        }

        // register values stored in "Range Map - Register_*"
        ProgramContext ctx = p.getProgramContext();
        rows = new ArrayList<>();
        for (ghidra.program.model.lang.Register reg : p.getLanguage().getRegisters()) {
            if (!reg.isBaseRegister()) {
                continue;
            }
            int i = 0;
            for (ghidra.program.model.address.AddressRangeIterator it = ctx
                .getRegisterValueAddressRanges(reg); it.hasNext();) {
                AddressRange r = it.next();
                ghidra.program.model.lang.RegisterValue v = ctx.getNonDefaultValue(reg, r.getMinAddress());
                rows.add(new String[] { reg.getName() + " " + String.format("%08d", i++),
                    "regvalue reg=" + reg.getName() + " min=" + addr(r.getMinAddress()) + " max="
                        + addr(r.getMaxAddress()) + " bytes=" + (v == null ? "null" : hex(v.toBytes())) });
            }
        }
        System.out.println("register_values=" + rows.size());
        emit(rows);

        // user / analysis property maps
        ghidra.program.model.util.PropertyMapManager pm = p.getUsrPropertyManager();
        rows = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (java.util.Iterator<String> it = pm.propertyManagers(); it.hasNext();) {
            names.add(it.next());
        }
        Collections.sort(names);
        for (String name : names) {
            ghidra.program.model.util.PropertyMap<?> m = pm.getPropertyMap(name);
            String kind = m instanceof ghidra.program.model.util.IntPropertyMap ? "INT"
                : m instanceof ghidra.program.model.util.LongPropertyMap ? "LONG"
                : m instanceof ghidra.program.model.util.StringPropertyMap ? "STRING"
                : m instanceof ghidra.program.model.util.VoidPropertyMap ? "VOID" : "OBJECT";
            rows.add(new String[] { name, "propmap name=[" + esc(name) + "] kind=" + kind + " size="
                + m.getSize() });
            for (AddressIterator it = m.getPropertyIterator(); it.hasNext();) {
                Address at = it.next();
                String v = m instanceof ghidra.program.model.util.IntPropertyMap im ? "" + im.getInt(at)
                    : m instanceof ghidra.program.model.util.LongPropertyMap lm ? "" + lm.getLong(at)
                    : m instanceof ghidra.program.model.util.StringPropertyMap sm ? esc(sm.getString(at))
                    : "";
                rows.add(new String[] { name + "\u0001" + addr(at), "propval map=[" + esc(name)
                    + "] addr=" + addr(at) + " value=[" + v + "]" });
            }
        }
        System.out.println("property_maps=" + rows.size());
        emit(rows);

        // program options
        rows = new ArrayList<>();
        for (String list : p.getOptionsNames()) {
            ghidra.framework.options.Options o = p.getOptions(list);
            for (String on : o.getOptionNames()) {
                String key = list + "." + on;
                // options Java registers with defaults are not rows of the table; the
                // custom ones have a display form, so print the stored string for all
                db.DBRecord stored = p.getDBHandle().getTable("Property Table")
                    .getRecord(new db.StringField(key));
                if (stored == null) {
                    continue;
                }
                rows.add(new String[] { key, "option key=[" + esc(key) + "] type="
                    + o.getType(on).ordinal() + " value=[" + esc(stored.getString(0)) + "]" });
            }
        }
        System.out.println("options=" + rows.size());
        emit(rows);

        // external manager
        ghidra.program.model.symbol.ExternalManager em = p.getExternalManager();
        rows = new ArrayList<>();
        List<String> libs = new ArrayList<>();
        for (String s : em.getExternalLibraryNames()) {
            libs.add(s);
        }
        Collections.sort(libs);
        for (String lib : libs) {
            rows.add(new String[] { lib, "extlib name=[" + esc(lib) + "] path=["
                + esc(em.getExternalLibraryPath(lib)) + "]" });
            for (java.util.Iterator<ghidra.program.model.symbol.ExternalLocation> it = em
                .getExternalLocations(lib); it.hasNext();) {
                ghidra.program.model.symbol.ExternalLocation x = it.next();
                rows.add(new String[] { lib + "\u0001" + String.format("%020d", x.getSymbol().getID()),
                    "extloc id=" + x.getSymbol().getID() + " lib=[" + esc(x.getLibraryName())
                        + "] label=[" + esc(x.getLabel()) + "] orig=[" + esc(x.getOriginalImportedName())
                        + "] addr=" + addr(x.getAddress()) + " extaddr=" + addr(x.getExternalSpaceAddress())
                        + " src=" + x.getSource().name() + " func=" + x.isFunction() + " ns=["
                        + esc(x.getParentNameSpace().getName(true)) + "]" });
            }
        }
        System.out.println("externals=" + rows.size());
        emit(rows);

        // namespaces, classes, libraries and symbols nested in them
        rows = new ArrayList<>();
        long maxId = p.getDBHandle().getTable("Symbols").getMaxKey();
        for (long id = 1; id <= maxId; id++) {
            Symbol s = p.getSymbolTable().getSymbol(id);
            if (s == null) {
                continue;
            }
            int t = s.getSymbolType().getID();
            Symbol par = s.getParentSymbol();
            long parId = par == null ? 0 : par.getID();
            if (t == 1 || t == 3 || t == 4) {
                rows.add(new String[] { String.format("%020d", id), "namespace id=" + id + " kind="
                    + s.getSymbolType().toString() + " path=[" + esc(s.getName(true)) + "] parent=" + parId
                    + " class=" + (s.getObject() instanceof GhidraClass) });
            }
            else if ((t == 0 || t == 5) && parId != 0) {
                rows.add(new String[] { String.format("%020d", id), "sympath id=" + id + " path=["
                    + esc(s.getName(true)) + "]" });
            }
        }
        System.out.println("namespaces=" + rows.size());
        emit(rows);
    }

    static <T> Iterable<T> iterable(java.util.Iterator<T> it) {
        return () -> it;
    }

    static String esc(String s) {
        if (s == null) {
            return "null";
        }
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
                + " type=" + p.getDataTypeManager().getID(d.getDataType()) + " dt=["
                + esc(d.getDataType().getPathName()) + "]" });
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
