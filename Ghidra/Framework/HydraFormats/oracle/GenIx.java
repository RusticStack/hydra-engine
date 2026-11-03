import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates the deterministic field-key / index build scripts in testdata/build (see
 * OracleBuildIx.java). Run: java GenIx.java outdir
 */
public class GenIx {
    static long s;
    static int keyMax = 12;

    static long next() {
        long x = s;
        x ^= x >>> 12;
        x ^= x << 25;
        x ^= x >>> 27;
        s = x;
        return x * 0x2545F4914F6CDD1DL;
    }

    static int below(int n) {
        return (int) Long.remainderUnsigned(next() >>> 11, n);
    }

    static String blob(int n) {
        if (n == 0) return "-";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) b.append(String.format("%02x", below(256)));
        return b.toString();
    }

    static String word(int maxLen) {
        int n = 1 + below(maxLen);
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) b.append((char) ('a' + below(26)));
        return b.toString();
    }

    interface Maker {
        String put(String name, String key);
    }

    /** Random puts (new keys and overwrites) and deletes over a key range. */
    static void ops(List<String> out, String name, String keyType, Maker mk, int n, int range,
            int delPct, int commitEvery) {
        List<String> live = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (!live.isEmpty() && below(100) < delPct) {
                int at = below(live.size());
                out.add("del " + name + " " + live.remove(at));
            } else {
                String k = keyType.equals("string") ? word(keyMax)
                    : Long.toString(below(range) - (keyType.equals("short") || keyType.equals("int") ? range / 2 : 0));
                if (!live.contains(k)) live.add(k);
                out.add(mk.put(name, k));
            }
            if (commitEvery > 0 && i % commitEvery == commitEvery - 1) out.add("commit");
        }
    }

    static String fixedPut(String name, String k) {
        return "put " + name + " " + k + " " + (next() >> (below(2) == 0 ? 0 : 50)) + " "
            + (below(40) - 20) + " " + (below(60000) - 30000);
    }

    static String varPut(String name, String k) {
        int len = below(5) == 0 ? 100 + below(300) : below(30);
        String text = below(3) == 0 ? "-" : word(12);
        return "put " + name + " " + k + " " + (below(50) - 25) + " " + blob(len) + " " + text;
    }

    static String widePut(String name, String k) {
        return "put " + name + " " + k + " " + below(5000);
    }

    static String sparsePut(String name, String k) {
        return "put " + name + " " + k + " " + (below(20) - 10) + " "
            + (below(3) == 0 ? "-" : word(6)) + " " + (below(3) == 0 ? "-" : Integer.toString(below(30) - 15));
    }

    static String binPut(String name, String k) {
        return "put " + name + " " + k + " " + (below(50) - 25) + " " + blob(below(30)) + " " + (below(3) == 0 ? "-" : word(12));
    }

    static void write(File dir, String name, List<String> lines) throws Exception {
        Files.write(new File(dir, name + ".script").toPath(), (String.join("\n", lines) + "\n").getBytes());
    }

    public static void main(String[] a) throws Exception {
        File dir = new File(a[0]);
        List<String> l;

        s = 0x1111;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T int fixed -");
        ops(l, "T", "int", GenIx::fixedPut, 1500, 900, 25, 400);
        write(dir, "fk-int-fixed", l);

        s = 0x2222;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T short var -");
        ops(l, "T", "short", GenIx::varPut, 1200, 700, 25, 300);
        write(dir, "fk-short-var", l);

        s = 0x3333;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T long fixed 1");
        ops(l, "T", "long", GenIx::fixedPut, 1500, 900, 25, 500);
        write(dir, "ix-long-fixed-1", l);

        s = 0x4444;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T long fixed 2,0");
        ops(l, "T", "long", GenIx::fixedPut, 1500, 900, 25, 500);
        write(dir, "ix-long-fixed-2-0", l);

        s = 0x5555;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T int var 0");
        ops(l, "T", "int", GenIx::varPut, 1200, 700, 25, 300);
        write(dir, "ix-int-var-0", l);

        s = 0x6666;
        l = new ArrayList<>();
        l.add("buffer 16379");
        l.add("table A long fixed 0,1,2");
        l.add("table B short fixed 1");
        ops(l, "A", "long", GenIx::fixedPut, 600, 3000, 20, 200);
        ops(l, "B", "short", GenIx::fixedPut, 600, 3000, 20, 200);
        write(dir, "ix-multi", l);

        s = 0x7777;
        keyMax = 12;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T string fixed -");
        ops(l, "T", "string", GenIx::fixedPut, 1500, 0, 25, 400);
        write(dir, "vk-string-fixed", l);

        s = 0x8888;
        keyMax = 40;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T string var -");
        ops(l, "T", "string", GenIx::varPut, 1500, 0, 25, 300);
        write(dir, "vk-string-var", l);

        s = 0x9999;
        keyMax = 12;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T long var 2");
        ops(l, "T", "long", GenIx::varPut, 1500, 900, 25, 400);
        write(dir, "ix-string-column", l);

        s = 0xaaaa;
        keyMax = 12;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T int var 2,0");
        ops(l, "T", "int", GenIx::varPut, 1000, 600, 25, 300);
        write(dir, "ix-all-columns", l);

        s = 0xbbbb;
        keyMax = 46;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T string fixed -");
        ops(l, "T", "string", GenIx::fixedPut, 3000, 0, 45, 600);
        write(dir, "vk-string-stress", l);

        s = 0xcccc;
        keyMax = 46;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T string var -");
        ops(l, "T", "string", GenIx::varPut, 3000, 0, 40, 500);
        write(dir, "vk-string-var-stress", l);

        // 40 column tables: the index tables are visited in IntObjectHashtable order (column % 37,
        // newest first), which only differs from creation order with columns above 36
        s = 0xdddd;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table W long wide 1,38,13,14,0,39,25");
        ops(l, "W", "long", GenIx::widePut, 400, 120, 25, 100);
        write(dir, "ix-wide-order", l);

        s = 0xeeee;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table W int wide 38,1,22,35");
        l.add("table X short wide 37,0");
        ops(l, "W", "int", GenIx::widePut, 300, 100, 20, 100);
        ops(l, "X", "short", GenIx::widePut, 300, 100, 20, 100);
        write(dir, "ix-wide-two-tables", l);

        // indexes on sparse columns skip null values; an index on a binary column
        s = 0xffff;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table S long sparse 1,2");
        l.add("table Q int sparse 2,1,0");
        ops(l, "S", "long", GenIx::sparsePut, 500, 150, 25, 100);
        ops(l, "Q", "int", GenIx::sparsePut, 400, 120, 25, 100);
        write(dir, "ix-sparse", l);

        s = 0x1234;
        keyMax = 12;
        l = new ArrayList<>();
        l.add("buffer 507");
        l.add("table T long var 1");
        ops(l, "T", "long", GenIx::binPut, 600, 300, 25, 200);
        write(dir, "ix-binary-column", l);
    }
}
