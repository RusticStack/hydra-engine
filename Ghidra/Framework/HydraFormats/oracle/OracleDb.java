package db;

import java.io.File;
import java.security.MessageDigest;

import ghidra.util.task.TaskMonitor;

/**
 * Table-level oracle for the HydraFormats differential tests. Lives in package db to reach the
 * package-private master table API. Prints, for a database file, the master table records and,
 * for every table (index tables included), the record count and a SHA-256 over the stored bytes
 * of every key and record in iteration order.
 */
public class OracleDb {
    public static void main(String[] a) throws Exception {
        DBHandle h = new DBHandle(new File(a[0]));
        System.out.println("dbid=" + h.getDatabaseId());
        for (TableRecord tr : h.getMasterTable().getTableRecords()) {
            Schema s = tr.getSchema();
            System.out.println("tr num=" + tr.getTableNum() + " name=" + tr.getName() + " idx="
                + tr.getIndexedColumn() + " root=" + tr.getRootBufferId() + " keytype="
                + (s.getEncodedKeyFieldType() & 0xff) + " version=" + s.getVersion() + " max="
                + tr.getMaxKey() + " count=" + tr.getRecordCount() + " variable="
                + s.isVariableLength() + " long=" + s.useLongKeyNodes() + " varnodes="
                + s.useVariableKeyNodes() + " fixednodes=" + s.useFixedKeyNodes());
        }
        for (TableRecord tr : h.getMasterTable().getTableRecords()) {
            Table t = new Table(h, tr);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long n = 0;
            RecordIterator it = t.iterator();
            while (it.hasNext()) {
                DBRecord r = it.next();
                Field k = r.getKeyField();
                BinaryDataBuffer kb = new BinaryDataBuffer(k.length());
                k.write(kb, 0);
                md.update(kb.getData());
                BinaryDataBuffer rb = new BinaryDataBuffer(r.length());
                r.write(rb, 0);
                md.update(rb.getData());
                n++;
            }
            StringBuilder sb = new StringBuilder();
            for (byte x : md.digest()) sb.append(String.format("%02x", x));
            System.out.println("tbl num=" + tr.getTableNum() + " name=" + tr.getName() + " idx="
                + tr.getIndexedColumn() + " n=" + n + " sha256=" + sb);
        }
        for (Table t : h.getTables()) {
            System.out.println("consistent name=" + t.getName() + " "
                + t.isConsistent(TaskMonitor.DUMMY));
        }
        h.close();
    }
}
