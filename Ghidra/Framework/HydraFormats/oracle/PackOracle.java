import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;

import ghidra.framework.store.local.ItemDeserializer;
import ghidra.framework.store.local.ItemSerializer;

/**
 * Packs a file with ItemSerializer (the writer behind PackedDatabase.packDatabase) and reads
 * it back with ItemDeserializer. Usage: PackOracle pack in out name contentType fileType,
 * or PackOracle unpack in out (prints name, content type, file type, length).
 */
public class PackOracle {
    public static void main(String[] a) throws Exception {
        if (a[0].equals("pack")) {
            File in = new File(a[1]);
            try (InputStream is = new FileInputStream(in)) {
                ItemSerializer.outputItem(a[3], a[4].isEmpty() ? null : a[4],
                    Integer.parseInt(a[5]), in.length(), is, new File(a[2]), null);
            }
        } else {
            try (ItemDeserializer d = new ItemDeserializer(new File(a[1]))) {
                System.out.println("name=" + d.getItemName() + " content=" + d.getContentType()
                    + " type=" + d.getFileType() + " length=" + d.getLength());
                try (OutputStream os = new FileOutputStream(a[2])) {
                    d.saveItem(os, null);
                }
            }
        }
    }
}
