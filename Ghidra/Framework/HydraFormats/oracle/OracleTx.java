package db;

import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import ghidra.util.task.TaskMonitor;

/**
 * Transaction, undo and redo oracle. Usage: OracleTx script.txt
 *
 * Reads the grammar of {@link OracleBuildIx} (table, put, del, commit; here "buffer N" does not
 * start a transaction) and adds commands that exercise the write path of DBHandle. Everything the
 * script observes is printed, so the Rust replay can be compared line by line:
 *
 *   begin                      startTransaction
 *   end commit|rollback        endTransaction, prints "end added=BOOL"
 *   terminate commit|rollback  terminateTransaction
 *   commit                     end commit, begin (no output)
 *   undo | redo                prints "undo ok=BOOL" / "redo ok=BOOL"
 *   maxundos N                 setMaxUndos
 *   rename OLD NEW             setTableName, prints "rename ok=BOOL"
 *   deltable NAME              deleteTable
 *   put / del on a missing table print "skip put" / "skip del"; rename copies the key and layout
 *   kinds of the old name to the new one
 *   buffer N [CACHE]           new DBHandle(N [, cache bytes])
 *   status                     prints undo/redo counts, canUndo/canRedo, uncommitted, changed, tx and the free index stack
 *   snap TAG                   saveAs a scratch file (outside a transaction), then prints
 *                              "== TAG" and the output of db.buffers.Oracle and db.OracleDb on it
 *   try CMD...                 runs CMD; prints "try ok" or "try err ExceptionSimpleName"
 *
 * The first line printed is "dbid=N" (after the buffer command).
 */
public class OracleTx {

    static DBHandle h;
    static long tx;
    static boolean active;
    static final java.util.Map<String, String> fixed = new java.util.HashMap<>();
    static final java.util.Map<String, String> keyKind = new java.util.HashMap<>();
    static Path scratch;
    static int snaps;

    /** The free index stack of the buffer manager in stack order (bottom first), by reflection. */
    static String freeStack() throws Exception {
        java.lang.reflect.Field f = DBHandle.class.getDeclaredField("bufferMgr");
        f.setAccessible(true);
        Object bm = f.get(h);
        java.lang.reflect.Field g = bm.getClass().getDeclaredField("indexProvider");
        g.setAccessible(true);
        Object ip = g.get(bm);
        java.lang.reflect.Method m = ip.getClass().getDeclaredMethod("getFreeIndexes");
        m.setAccessible(true);
        return Arrays.toString((int[]) m.invoke(ip));
    }

    static void run(String[] t) throws Exception {
        switch (t[0]) {
            case "buffer":
                h = t.length > 2 ? new DBHandle(Integer.parseInt(t[1]), Long.parseLong(t[2]))
                    : new DBHandle(Integer.parseInt(t[1]));
                System.out.println("dbid=" + h.getDatabaseId());
                break;
            case "begin":
                tx = h.startTransaction();
                active = true;
                break;
            case "end": {
                boolean added = h.endTransaction(tx, t[1].equals("commit"));
                active = false;
                System.out.println("end added=" + added);
                break;
            }
            case "terminate":
                h.terminateTransaction(tx, t[1].equals("commit"));
                active = false;
                break;
            case "commit":
                h.endTransaction(tx, true);
                tx = h.startTransaction();
                break;
            case "undo":
                System.out.println("undo ok=" + h.undo());
                break;
            case "redo":
                System.out.println("redo ok=" + h.redo());
                break;
            case "maxundos":
                h.setMaxUndos(Integer.parseInt(t[1]));
                break;
            case "rename": {
                boolean ok = h.setTableName(t[1], t[2]);
                if (ok) {
                    fixed.put(t[2], fixed.get(t[1]));
                    keyKind.put(t[2], keyKind.get(t[1]));
                }
                System.out.println("rename ok=" + ok);
                break;
            }
            case "deltable":
                h.deleteTable(t[1]);
                break;
            case "dump": {
                java.lang.reflect.Field f = DBHandle.class.getDeclaredField("bufferMgr");
                f.setAccessible(true);
                Object bm = f.get(h);
                java.lang.reflect.Field g = bm.getClass().getDeclaredField("checkpointHeads");
                g.setAccessible(true);
                java.util.List<?> heads = (java.util.List<?>) g.get(bm);
                for (Object head : heads) {
                    StringBuilder sb = new StringBuilder("cp");
                    java.lang.reflect.Field nx = head.getClass().getDeclaredField("nextInCheckpoint");
                    nx.setAccessible(true);
                    java.lang.reflect.Field fid = head.getClass().getDeclaredField("id");
                    fid.setAccessible(true);
                    java.lang.reflect.Field fe = head.getClass().getDeclaredField("empty");
                    fe.setAccessible(true);
                    Object n = nx.get(head);
                    while (n != null && (int) fid.get(n) >= 0) {
                        sb.append(' ').append(fid.get(n)).append(fe.getBoolean(n) ? "e" : "");
                        n = nx.get(n);
                    }
                    System.out.println(sb);
                }
                break;
            }
            case "cachedump": {
                // debugging aid: the memory cache of the buffer manager, newest node first
                java.lang.reflect.Field f = DBHandle.class.getDeclaredField("bufferMgr");
                f.setAccessible(true);
                Object bm = f.get(h);
                Class<?> c = bm.getClass();
                java.lang.reflect.Field ch = c.getDeclaredField("cacheHead");
                ch.setAccessible(true);
                Object n = ch.get(bm);
                java.lang.reflect.Field nc = n.getClass().getDeclaredField("nextCached");
                nc.setAccessible(true);
                java.lang.reflect.Field fid = n.getClass().getDeclaredField("id");
                fid.setAccessible(true);
                java.lang.reflect.Field fcp = n.getClass().getDeclaredField("checkpoint");
                fcp.setAccessible(true);
                StringBuilder sb = new StringBuilder("cache [");
                n = nc.get(n);
                java.lang.reflect.Field fbuf = n.getClass().getDeclaredField("buffer");
                fbuf.setAccessible(true);
                java.lang.reflect.Field fdata = db.buffers.DataBuffer.class.getDeclaredField("data");
                fdata.setAccessible(true);
                while (n != null && (int) fid.get(n) >= 0) {
                    sb.append(fid.get(n)).append('@').append(fcp.get(n)).append(':')
                        .append(Integer.toHexString(
                            Arrays.hashCode((byte[]) fdata.get(fbuf.get(n))))).append(' ');
                    n = nc.get(n);
                }
                java.lang.reflect.Field cs = c.getDeclaredField("cacheSize");
                cs.setAccessible(true);
                java.lang.reflect.Field fb = c.getDeclaredField("freeBuffers");
                fb.setAccessible(true);
                StringBuilder fs = new StringBuilder();
                for (Object b : (java.util.List<?>) fb.get(bm)) {
                    fs.append(Integer.toHexString(Arrays.hashCode((byte[]) fdata.get(b)))).append(' ');
                }
                java.lang.reflect.Field fh = c.getDeclaredField("cacheHits");
                fh.setAccessible(true);
                java.lang.reflect.Field fm = c.getDeclaredField("cacheMisses");
                fm.setAccessible(true);
                System.out.println(sb.toString().trim() + "] size=" + cs.get(bm) + " free=["
                    + fs.toString().trim() + "] misses=" + fm.get(bm));
                break;
            }
            case "status":
                System.out.println("status undo=" + h.getAvailableUndoCount() + " redo="
                    + h.getAvailableRedoCount() + " canUndo=" + h.canUndo() + " canRedo="
                    + h.canRedo() + " uncommitted=" + h.hasUncommittedChanges() + " changed="
                    + h.isChanged() + " tx=" + h.isTransactionActive() + " stack=" + freeStack());
                break;
            case "snap": {
                File f = scratch.resolve("snap" + (snaps++) + ".gbf").toFile();
                f.delete(); // a repeated run (ORACLETX_REPS) writes the same names again
                h.saveAs(f, false, TaskMonitor.DUMMY);
                System.out.println("== " + t[1]);
                db.buffers.Oracle.main(new String[] { f.getPath() });
                try {
                    OracleDb.main(new String[] { f.getPath() });
                }
                catch (Throwable e) {
                    // the file written is not readable as a database (a Java defect seen after
                    // a rollback that cannot undo): record that, the buffers above still compare
                    System.out.println("oracledb err " + e.getClass().getSimpleName());
                }
                break;
            }
            case "try":
                try {
                    run(Arrays.copyOfRange(t, 1, t.length));
                    System.out.println("try ok");
                }
                catch (Throwable e) {
                    System.out.println("try err " + e.getClass().getSimpleName());
                }
                break;
            case "table": {
                Schema s = OracleBuildIx.schema(t[2], t[3]);
                int[] idx = null;
                if (!t[4].equals("-")) {
                    String[] c = t[4].split(",");
                    idx = new int[c.length];
                    for (int i = 0; i < c.length; i++) idx[i] = Integer.parseInt(c[i]);
                }
                h.createTable(t[1], s, idx);
                fixed.put(t[1], t[3]);
                keyKind.put(t[1], t[2]);
                break;
            }
            case "put": {
                Table tb = h.getTable(t[1]);
                if (tb == null) {
                    System.out.println("skip put");
                    break;
                }
                DBRecord rec = tb.getSchema().createRecord(
                    OracleBuildIx.key(keyKind.get(t[1]), t[2]));
                OracleBuildIx.fill(rec, fixed.get(t[1]), t);
                tb.putRecord(rec);
                break;
            }
            case "del": {
                Table tb = h.getTable(t[1]);
                if (tb == null) {
                    System.out.println("skip del");
                    break;
                }
                tb.deleteRecord(OracleBuildIx.key(keyKind.get(t[1]), t[2]));
                break;
            }
            default:
                throw new IllegalArgumentException(String.join(" ", t));
        }
    }

    /** Runs one script; `snap` is skipped when `ORACLETX_NOSNAP` is set (timing runs). */
    static void runScript(String path) throws Exception {
        boolean noSnap = System.getenv("ORACLETX_NOSNAP") != null;
        h = null;
        tx = 0;
        active = false;
        fixed.clear();
        keyKind.clear();
        snaps = 0;
        try (BufferedReader r = Files.newBufferedReader(new File(path).toPath())) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (noSnap && line.startsWith("snap ")) continue;
                try {
                    run(line.split(" "));
                }
                catch (Throwable e) {
                    // an operation outside "try" failed: the database is in a state Java could
                    // not use any more (seen after a rollback that cannot undo). The script
                    // stops here and the transcript says so.
                    System.out.println("fatal");
                    break;
                }
            }
        }
        h.close();
    }

    /**
     * `ORACLETX_REPS=n` runs the script n times in this JVM and prints the time of every run in
     * nanoseconds to stderr (the first is cold, the last warm); only the first run prints a
     * transcript.
     */
    public static void main(String[] a) throws Exception {
        String keep = System.getenv("ORACLETX_KEEP"); // keep the snapshot files for inspection
        scratch = keep != null ? Path.of(keep) : Files.createTempDirectory("oracletx");
        String reps = System.getenv("ORACLETX_REPS");
        if (reps == null) {
            runScript(a[0]);
        }
        else {
            java.io.PrintStream out = System.out;
            StringBuilder times = new StringBuilder("ns");
            for (int i = 0; i < Integer.parseInt(reps); i++) {
                if (i == 1) System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                long t0 = System.nanoTime();
                runScript(a[0]);
                times.append(' ').append(System.nanoTime() - t0);
            }
            System.setOut(out);
            System.err.println(times);
        }
        if (keep != null) return;
        try (var s = Files.walk(scratch)) {
            s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
