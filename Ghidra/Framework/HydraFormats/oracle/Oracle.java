package db.buffers;
import db.*;

import java.io.File;
import java.security.MessageDigest;

public class Oracle {
    public static void main(String[] a) throws Exception {
        File f = new File(a[0]);
        LocalBufferFile bf = new LocalBufferFile(f, true);
        System.out.println("bufferSize=" + bf.getBufferSize() + " indexCount=" + bf.getIndexCount()
            + " free=" + java.util.Arrays.toString(bf.getFreeIndexes()));
        for (String n : bf.getParameterNames()) System.out.println("parm " + n + "=" + bf.getParameter(n));
        for (int i = 0; i < bf.getIndexCount(); i++) {
            DataBuffer b = new DataBuffer(bf.getBufferSize());
            bf.get(b, i);
            String hex = "-";
            if (!b.isEmpty()) {
                byte[] d = MessageDigest.getInstance("SHA-256").digest(b.data);
                StringBuilder sb = new StringBuilder();
                for (byte x : d) sb.append(String.format("%02x", x));
                hex = sb.toString();
            }
            System.out.println("buf " + i + " id=" + b.getId() + " empty=" + b.isEmpty() + " sha256=" + hex);
        }
        bf.close();
        DBHandle h = new DBHandle(f);
        Table[] ts = h.getTables();
        java.util.Arrays.sort(ts, (x, y) -> x.getName().compareTo(y.getName()));
        for (Table t : ts) {
            System.out.println("table " + t.getName() + " count=" + t.getRecordCount() + " max=" + t.getMaxKey());
        }
        System.out.println("dbid=" + h.getDatabaseId());
        h.close();
    }
}
