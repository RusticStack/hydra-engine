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
        p.release(OracleProgram.class);
        System.exit(0);
    }
}
