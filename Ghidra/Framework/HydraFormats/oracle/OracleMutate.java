import java.io.File;
import java.math.BigInteger;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.RegisterValue;

/**
 * Builds the synthetic Program database used by the ghidra-progdb differential tests: the stock
 * ProgramDB opens a copy of a fixture for upgrade and adds the things the fixtures lack (equates,
 * bookmark types, relocations, external locations, namespaces and classes, register values,
 * property maps, options), then saves a complete new buffer file.
 *
 * Usage: java -cp ... OracleMutate installDir source.gbf work.gbf out.gbf
 * (work.gbf is a scratch copy of source.gbf that is modified in place.)
 */
public class OracleMutate {

    public static void main(String[] a) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(a[0])),
            new HeadlessGhidraApplicationConfiguration());
        java.nio.file.Files.copy(new File(a[1]).toPath(), new File(a[2]).toPath(),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        db.buffers.LocalBufferFile bf = new db.buffers.LocalBufferFile(new File(a[2]), false);
        DBHandle h = new DBHandle(bf);
        ProgramDB p = new ProgramDB(h, OpenMode.UPGRADE, TaskMonitor.DUMMY, OracleMutate.class);
        int tx = p.startTransaction("synth");
        try {
            mutate(p);
        }
        finally {
            p.endTransaction(tx, true);
        }
        System.out.println("stored_version=" + p.getStoredVersion());
        h.saveAs(new File(a[3]), false, TaskMonitor.DUMMY);
        p.release(OracleMutate.class);
        System.exit(0);
    }

    static void mutate(ProgramDB p) throws Exception {
        Listing l = p.getListing();
        MemoryBlock first = null;
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (b.isInitialized() && b.getSize() > 0x1000) {
                first = b;
                break;
            }
        }
        java.util.List<Address> inst = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            inst.add(first.getStart().add(0x100 + 0x20 * i));
        }
        Address a0 = inst.get(0);
        Address a1 = inst.get(1);
        Address a2 = inst.get(2);
        Address a3 = inst.get(3);

        // equates
        EquateTable et = p.getEquateTable();
        Equate e1 = et.createEquate("EQ_ONE", 1);
        e1.addReference(a0, 0);
        e1.addReference(a1, 1);
        Equate e2 = et.createEquate("EQ_NEG", -5);
        e2.addReference(a2, 0);
        Equate e3 = et.createEquate("EQ_BIG", 0x123456789abcL);
        e3.addReference(a3, 1);
        e3.addReference(0x1122334455667788L, a0);

        // bookmarks
        BookmarkManager bm = p.getBookmarkManager();
        bm.setBookmark(a0, BookmarkType.NOTE, "My Category", "a note");
        bm.setBookmark(a1, BookmarkType.WARNING, "warn cat", "a warning");
        bm.setBookmark(a2, BookmarkType.ERROR, "", "an error");
        bm.defineType("SynthType", new javax.swing.ImageIcon(), java.awt.Color.RED, 5);
        bm.setBookmark(a3, "SynthType", "synth cat", "custom bookmark with \\ backslash");
        bm.setBookmark(a3, BookmarkType.NOTE, "My Category", "second note");

        // relocations
        MemoryBlock init = null;
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (b.isInitialized() && b.getSize() > 64) {
                init = b;
                break;
            }
        }
        Address r0 = init.getStart().add(0x10);
        p.getRelocationTable().add(r0, Status.APPLIED, 7, new long[] { 1, 2, 3 }, 4, "reloc_sym");
        p.getRelocationTable().add(r0.add(8), Status.SKIPPED, 3, new long[] { -1 }, (byte[]) null,
            null);
        p.getRelocationTable().add(r0.add(16), Status.APPLIED_OTHER, 9, new long[0],
            new byte[] { 1, 2, 3, 4, 5 }, "with_bytes");
        p.getRelocationTable().add(r0.add(16), Status.FAILURE, 11, new long[] { 0x123456789L },
            (byte[]) null, "same_addr");

        // namespaces and classes
        SymbolTable st = p.getSymbolTable();
        Namespace global = p.getGlobalNamespace();
        Namespace ns1 = st.createNameSpace(global, "SynthNS", SourceType.USER_DEFINED);
        Namespace ns2 = st.createNameSpace(ns1, "Inner", SourceType.USER_DEFINED);
        GhidraClass c1 = st.createClass(ns1, "SynthClass", SourceType.USER_DEFINED);
        GhidraClass c2 = st.createClass(c1, "NestedClass", SourceType.USER_DEFINED);
        GhidraClass c3 = st.createClass(null, "TopClass", SourceType.ANALYSIS);
        st.createLabel(a1.add(1), "member_label", c2, SourceType.USER_DEFINED);
        st.createLabel(a2.add(1), "inner_label", ns2, SourceType.USER_DEFINED);

        // external locations
        ExternalManager em = p.getExternalManager();
        em.addExternalLibraryName("SYNTHLIB.DLL", SourceType.IMPORTED);
        em.setExternalPath("SYNTHLIB.DLL", "/libs/synth.dll", true);
        em.addExtLocation("SYNTHLIB.DLL", "SynthData", a0, SourceType.USER_DEFINED);
        ExternalLocation f = em.addExtFunction("SYNTHLIB.DLL", "SynthFunc", a1, SourceType.IMPORTED);
        ExternalLocation m = em.addExtLocation("SYNTHLIB.DLL", "_mangled_name", null,
            SourceType.IMPORTED);
        m.setName(m.getParentNameSpace(), "pretty_name", SourceType.USER_DEFINED);
        Namespace extNs = st.createNameSpace(
            st.getLibrarySymbol("SYNTHLIB.DLL").getObject() instanceof Namespace n ? n : global,
            "ExtNs", SourceType.IMPORTED);
        em.addExtLocation(extNs, "NsFunc", null, SourceType.IMPORTED);
        em.addExternalLibraryName("OTHER.DLL", SourceType.USER_DEFINED);
        ReferenceManager rm = p.getReferenceManager();
        rm.addExternalReference(a3, "OTHER.DLL", "OtherSym", null, SourceType.USER_DEFINED, 0,
            RefType.DATA);

        // register values
        ProgramContext ctx = p.getProgramContext();
        Register rax = p.getLanguage().getRegister("RAX");
        Register al = p.getLanguage().getRegister("AL");
        Register gs = p.getLanguage().getRegister("GS_OFFSET");
        ctx.setValue(rax, a0, a1, BigInteger.valueOf(0x1122334455667788L));
        ctx.setValue(al, a2, a3.add(4), BigInteger.valueOf(0x7f));
        ctx.setValue(gs, a3.add(8), a3.add(20), BigInteger.valueOf(0x30));

        // property maps
        PropertyMapManager pm = p.getUsrPropertyManager();
        IntPropertyMap im = pm.createIntPropertyMap("SynthInt");
        im.add(a0, 42);
        im.add(a1, -7);
        LongPropertyMap lm = pm.createLongPropertyMap("SynthLong");
        lm.add(a2, 1L << 40);
        StringPropertyMap sm = pm.createStringPropertyMap("SynthStr");
        sm.add(a0, "hello");
        sm.add(a3, "with\\slash");
        VoidPropertyMap vm = pm.createVoidPropertyMap("SynthVoid");
        vm.add(a1);
        vm.add(a2);

        // options
        Options pi = p.getOptions(Program.PROGRAM_INFO);
        pi.setString("Synth String", "value one");
        pi.setInt("Synth Int", 5);
        pi.setLong("Synth Long", 1L << 41);
        pi.setBoolean("Synth Bool", true);
        pi.setDouble("Synth Double", 1.5);
        Options so = p.getOptions("Synth Options");
        so.setInt("a.b.c", 3);
        so.setString("top", "x");
    }
}
