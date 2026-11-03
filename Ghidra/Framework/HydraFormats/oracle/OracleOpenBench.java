import java.io.File;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/**
 * Open-cost benchmark for the stock ProgramDB, the counterpart of the Rust
 * `examples/open_bench.rs`: times `new DBHandle` plus `new ProgramDB` (OpenMode.IMMUTABLE) after
 * the Ghidra application is initialized, optionally runs the same queries (function count, the
 * references of the first function's entry, 16 bytes at its entry, symbols at it), and sleeps
 * so that a sampler can read the peak working set.
 *
 * Usage: java -cp ... OracleOpenBench installDir db.gbf [--queries] [--hold-ms N]
 */
public class OracleOpenBench {

    public static void main(String[] a) throws Exception {
        long jvmStart = java.lang.management.ManagementFactory.getRuntimeMXBean().getStartTime();
        boolean queries = false;
        long hold = 0;
        for (int i = 2; i < a.length; i++) {
            if (a[i].equals("--queries")) {
                queries = true;
            }
            else if (a[i].equals("--hold-ms")) {
                hold = Long.parseLong(a[++i]);
            }
        }
        long t0 = System.nanoTime();
        Application.initializeApplication(new GhidraApplicationLayout(new File(a[0])),
            new HeadlessGhidraApplicationConfiguration());
        long t1 = System.nanoTime();
        DBHandle h = new DBHandle(new File(a[1]));
        ProgramDB p = new ProgramDB(h, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, OracleOpenBench.class);
        long t2 = System.nanoTime();
        System.out.println("app_init_ms=" + (t1 - t0) / 1e6);
        System.out.println("open_ms=" + (t2 - t1) / 1e6);
        if (queries) {
            long q0 = System.nanoTime();
            int n = p.getFunctionManager().getFunctionCount();
            Function f = p.getFunctionManager().getFunctions(true).next();
            Address entry = f.getEntryPoint();
            int to = p.getReferenceManager().getReferenceCountTo(entry);
            int from = p.getReferenceManager().getReferencesFrom(entry).length;
            byte[] b = new byte[16];
            int read = p.getMemory().getBytes(entry, b);
            int syms = p.getSymbolTable().getSymbols(entry).length;
            System.out.println("functions=" + n + " xrefs_from=" + from + " xrefs_to=" + to
                + " read_bytes=" + read + " symbols_at=" + syms);
            System.out.println("queries_ms=" + (System.nanoTime() - q0) / 1e6);
        }
        System.out.println("since_jvm_start_ms=" + (System.currentTimeMillis() - jvmStart));
        if (hold > 0) {
            Thread.sleep(hold);
        }
        p.release(OracleOpenBench.class);
        System.exit(0);
    }
}
