package db;

import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import ghidra.util.task.TaskMonitor;

/**
 * Builds a database from a script with the repository's DB classes and saves it, so the Rust
 * write path can be compared buffer by buffer. Usage: OracleBuild script.txt out.gbf
 *
 * Script lines (blank lines and # comments ignored):
 *   buffer N                        requested buffer size (must be first)
 *   table NAME var                  long key; columns Int, Binary (variable length records)
 *   table NAME fixed                long key; columns Long, Int, Short (fixed length records)
 *   put NAME KEY INT HEX|-          var table record (HEX is the binary column, - is empty)
 *   put NAME KEY LONG INT SHORT     fixed table record
 *   del NAME KEY
 *   commit                          end the transaction and start a new one
 */
public class OracleBuild {

    static byte[] hex(String s) {
        if (s.equals("-")) return new byte[0];
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    public static void main(String[] a) throws Exception {
        DBHandle h = null;
        long tx = 0;
        Map<String, Table> tables = new HashMap<>();
        Map<String, Boolean> fixed = new HashMap<>();
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
                        boolean fx = t[2].equals("fixed");
                        Schema s = fx
                            ? new Schema(1, "Key", new Field[] { LongField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE },
                                new String[] { "A", "B", "C" })
                            : new Schema(1, "Key", new Field[] { IntField.INSTANCE, BinaryField.INSTANCE },
                                new String[] { "A", "B" });
                        tables.put(t[1], h.createTable(t[1], s));
                        fixed.put(t[1], fx);
                        break;
                    }
                    case "put": {
                        Table tb = tables.get(t[1]);
                        DBRecord rec = tb.getSchema().createRecord(Long.parseLong(t[2]));
                        if (fixed.get(t[1])) {
                            rec.setLongValue(0, Long.parseLong(t[3]));
                            rec.setIntValue(1, Integer.parseInt(t[4]));
                            rec.setShortValue(2, Short.parseShort(t[5]));
                        } else {
                            rec.setIntValue(0, Integer.parseInt(t[3]));
                            rec.setBinaryData(1, hex(t[4]));
                        }
                        tb.putRecord(rec);
                        break;
                    }
                    case "del":
                        tables.get(t[1]).deleteRecord(Long.parseLong(t[2]));
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
