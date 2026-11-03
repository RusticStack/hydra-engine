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
        String put(String name, long key);
    }

    /** Random puts (new keys and overwrites) and deletes over a key range. */
    static void ops(List<String> out, String name, String keyType, Maker mk, int n, int range,
            int delPct, int commitEvery) {
        List<Long> live = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (!live.isEmpty() && below(100) < delPct) {
                int at = below(live.size());
                out.add("del " + name + " " + live.remove(at));
            } else {
                long k = below(range) - (keyType.equals("short") || keyType.equals("int") ? range / 2 : 0);
                if (!live.contains(k)) live.add(k);
                out.add(mk.put(name, k));
            }
            if (commitEvery > 0 && i % commitEvery == commitEvery - 1) out.add("commit");
        }
    }

    static String fixedPut(String name, long k) {
        return "put " + name + " " + k + " " + (next() >> (below(2) == 0 ? 0 : 50)) + " "
            + (below(40) - 20) + " " + (below(60000) - 30000);
    }

    static String varPut(String name, long k) {
        int len = below(5) == 0 ? 100 + below(300) : below(30);
        String text = below(3) == 0 ? "-" : word(12);
        return "put " + name + " " + k + " " + (below(50) - 25) + " " + blob(len) + " " + text;
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
    }
}
