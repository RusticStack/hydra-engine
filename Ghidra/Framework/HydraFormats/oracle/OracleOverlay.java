import java.io.ByteArrayInputStream;
import java.io.File;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Builds the fixture the ghidra-progdb tests use for overlay and mapped memory blocks
 * (`testdata/synth/progdb-overlay-33.gbf`): a new x86-64 program on the stock ProgramDB with
 * initialized, uninitialized, overlay, byte mapped (1:1 and 2:4) and bit mapped blocks, mapped
 * blocks that point into an overlay, and an overlay block that is itself mapped.
 *
 * Usage: java -cp ... OracleOverlay installDir out.gbf
 */
public class OracleOverlay {

    static byte[] pattern(int n, int seed) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (seed + i * 7 + (i >> 3));
        }
        return b;
    }

    public static void main(String[] a) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(a[0])),
            new HeadlessGhidraApplicationConfiguration());
        LanguageService ls = DefaultLanguageService.getLanguageService();
        Language lang = ls.getLanguage(new LanguageID("x86:LE:64:default"));
        CompilerSpec cs = lang.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID("windows"));
        ProgramDB p = new ProgramDB("overlay-fixture", lang, cs, OracleOverlay.class);
        int tx = p.startTransaction("build");
        try {
            build(p);
        }
        finally {
            p.endTransaction(tx, true);
        }
        System.out.println("stored_version=" + p.getStoredVersion());
        p.getDBHandle().saveAs(new File(a[1]), false, TaskMonitor.DUMMY);
        p.release(OracleOverlay.class);
        System.exit(0);
    }

    static void build(ProgramDB p) throws Exception {
        Memory mem = p.getMemory();
        AddressSpace ram = p.getAddressFactory().getDefaultAddressSpace();
        TaskMonitor m = TaskMonitor.DUMMY;

        // plain blocks: initialized, uninitialized
        MemoryBlock main = mem.createInitializedBlock("main", ram.getAddress(0x1000), 0x200, (byte) 0x11, m, false);
        main.setWrite(true);
        mem.setBytes(ram.getAddress(0x1000), pattern(0x200, 3));
        mem.createUninitializedBlock("bss", ram.getAddress(0x2000), 0x100, false);

        // overlays: initialized (same range as main), uninitialized, and a second initialized
        mem.createInitializedBlock("ovl", ram.getAddress(0x1000),
            new ByteArrayInputStream(pattern(0x100, 90)), 0x100, m, true);
        mem.createUninitializedBlock("ovl_bss", ram.getAddress(0x4000), 0x80, true);
        MemoryBlock ovl2 = mem.createInitializedBlock("ovl2", ram.getAddress(0x6000),
            new ByteArrayInputStream(pattern(0x40, 200)), 0x40, m, true);
        ovl2.setExecute(true);

        Address ovl = mem.getBlock("ovl").getStart();
        Address ovl2start = ovl2.getStart();

        // byte mapped blocks (1:1, 2 of every 4 bytes) onto main, and onto an overlay
        mem.createByteMappedBlock("bm_1_1", ram.getAddress(0x8000), ram.getAddress(0x1010), 0x80, null, false);
        mem.createByteMappedBlock("bm_2_4", ram.getAddress(0x8200), ram.getAddress(0x1020), 0x40,
            new ByteMappingScheme(2, 4), false);
        mem.createByteMappedBlock("bm_ovl", ram.getAddress(0x8400), ovl.add(0x10), 0x20, null, false);
        // a bit mapped block (every source byte gives 8 bytes)
        mem.createBitMappedBlock("bits", ram.getAddress(0x9000), ram.getAddress(0x1000), 0x40, false);
        mem.createBitMappedBlock("bits_ovl", ram.getAddress(0x9400), ovl2start, 0x20, false);
        // mapped onto uninitialized memory
        mem.createByteMappedBlock("bm_bss", ram.getAddress(0xa000), ram.getAddress(0x2000), 0x40, null, false);
        // an overlay block that is a byte mapped block
        mem.createByteMappedBlock("ovl_bm", ram.getAddress(0xc000), ram.getAddress(0x1040), 0x30, null, true);

        // a block whose mapped data was changed afterwards must show the source's new bytes
        mem.setBytes(ram.getAddress(0x1012), new byte[] { (byte) 0xaa, (byte) 0xbb });
    }
}
