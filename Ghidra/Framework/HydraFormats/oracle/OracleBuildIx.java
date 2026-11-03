package db;

import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import ghidra.util.task.TaskMonitor;

/**
 * Like OracleBuild but for tables with field keys and index tables. Usage:
 * OracleBuildIx script.txt out.gbf
 *
 * Script lines (blank lines and # comments ignored):
 *   buffer N                         requested buffer size (must be first)
 *   table NAME KEY LAYOUT IDX        KEY: long|int|short|string; LAYOUT: fixed (Long, Int, Short
 *                                    columns), var (Int, Binary, String columns) or wide (40 Int
 *                                    columns) or sparse; IDX: comma separated indexed columns or -
 *   put NAME KEY LONG INT SHORT      fixed table record
 *   put NAME KEY INT HEX|- TEXT|-    var table record (TEXT - is the empty string)
 *   put NAME KEY INT TEXT|- INT|-    sparse table record (layout sparse: Int, String and Int
 *                                    columns, the last two sparse; - leaves the column null)
 *   put NAME KEY SEED                wide table record: column i = (SEED * 31 + i * 7) % 1000
 *   del NAME KEY
 *   commit                           end the transaction and start a new one
 */
public class OracleBuildIx {

    static byte[] hex(String s) {
        if (s.equals("-")) return new byte[0];
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    /** The schema of a table in the given layout. */
    static Schema schema(String keyKind, String layout) {
        switch (layout) {
            case "fixed":
                return new Schema(1, keyType(keyKind), "Key",
                    new Field[] { LongField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE },
                    new String[] { "A", "B", "C" });
            case "var":
                return new Schema(1, keyType(keyKind), "Key",
                    new Field[] { IntField.INSTANCE, BinaryField.INSTANCE, StringField.INSTANCE },
                    new String[] { "A", "B", "C" });
            case "sparse":
                return new Schema(1, keyType(keyKind), "Key",
                    new Field[] { IntField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE },
                    new String[] { "A", "B", "C" }, new int[] { 1, 2 });
            case "wide": {
                Field[] f = new Field[40];
                String[] n = new String[40];
                for (int i = 0; i < 40; i++) {
                    f[i] = IntField.INSTANCE;
                    n[i] = "C" + i;
                }
                return new Schema(1, keyType(keyKind), "Key", f, n);
            }
        }
        throw new IllegalArgumentException(layout);
    }

    /** Fills the columns of a record from the arguments of a put line (from index 3 on). */
    static void fill(DBRecord rec, String layout, String[] t) {
        switch (layout) {
            case "fixed":
                rec.setLongValue(0, Long.parseLong(t[3]));
                rec.setIntValue(1, Integer.parseInt(t[4]));
                rec.setShortValue(2, Short.parseShort(t[5]));
                return;
            case "var":
                rec.setIntValue(0, Integer.parseInt(t[3]));
                rec.setBinaryData(1, hex(t[4]));
                rec.setString(2, t[5].equals("-") ? "" : t[5]);
                return;
            case "sparse":
                rec.setIntValue(0, Integer.parseInt(t[3]));
                if (!t[4].equals("-")) rec.setString(1, t[4]);
                if (!t[5].equals("-")) rec.setIntValue(2, Integer.parseInt(t[5]));
                return;
            case "wide": {
                int seed = Integer.parseInt(t[3]);
                for (int i = 0; i < 40; i++) {
                    rec.setIntValue(i, (seed * 31 + i * 7) % 1000);
                }
                return;
            }
        }
        throw new IllegalArgumentException(layout);
    }

    static Field keyType(String k) {
        switch (k) {
            case "long": return LongField.INSTANCE;
            case "int": return IntField.INSTANCE;
            case "short": return ShortField.INSTANCE;
            case "string": return StringField.INSTANCE;
        }
        throw new IllegalArgumentException(k);
    }

    static Field key(String k, String v) {
        switch (k) {
            case "long": return new LongField(Long.parseLong(v));
            case "int": return new IntField(Integer.parseInt(v));
            case "short": return new ShortField(Short.parseShort(v));
            case "string": return new StringField(v);
        }
        throw new IllegalArgumentException(k);
    }

    public static void main(String[] a) throws Exception {
        DBHandle h = null;
        long tx = 0;
        Map<String, Table> tables = new HashMap<>();
        Map<String, String> fixed = new HashMap<>();
        Map<String, String> keyKind = new HashMap<>();
        try (BufferedReader r = Files.newBufferedReader(new File(a[0]).toPath())) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] t = line.split(" ");
                switch (t[0]) {
                    case "buffer":
                        h = new DBHandle(Integer.parseInt(t[1]));
                        tx = h.startTransaction();
                        break;
                    case "table": {
                        Schema s = schema(t[2], t[3]);
                        int[] idx = null;
                        if (!t[4].equals("-")) {
                            String[] c = t[4].split(",");
                            idx = new int[c.length];
                            for (int i = 0; i < c.length; i++) idx[i] = Integer.parseInt(c[i]);
                        }
                        tables.put(t[1], h.createTable(t[1], s, idx));
                        fixed.put(t[1], t[3]);
                        keyKind.put(t[1], t[2]);
                        break;
                    }
                    case "put": {
                        Table tb = tables.get(t[1]);
                        DBRecord rec = tb.getSchema().createRecord(key(keyKind.get(t[1]), t[2]));
                        fill(rec, fixed.get(t[1]), t);
                        tb.putRecord(rec);
                        break;
                    }
                    case "del":
                        tables.get(t[1]).deleteRecord(key(keyKind.get(t[1]), t[2]));
                        break;
                    case "commit":
                        h.endTransaction(tx, true);
                        tx = h.startTransaction();
                        break;
                    default:
                        throw new IllegalArgumentException(line);
                }
            }
        }
        h.endTransaction(tx, true);
        h.saveAs(new File(a[1]), false, TaskMonitor.DUMMY);
        System.out.println("dbid=" + h.getDatabaseId());
        h.close();
    }
}
