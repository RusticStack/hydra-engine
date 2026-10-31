## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
"""Power-loss simulator for a program save and a fork publish (PROTOCOL-3.md, section 8, package E12).

WHAT THIS IS, AND WHAT IT IS NOT

A process kill (``TerminateProcess``) keeps the operating system's page cache, so it proves nothing
about a power loss (6.1). There is no virtual machine here and none is created. This file is a
**crash simulator**: it records the file operations of a real save, replays them through a model of
what a file system keeps when the power goes out between two of them, builds every crash image the
model allows at every cut point, and runs the real open and repair code of E8
(``LocalDatabaseItem.openPrivate`` with ``VersionFileCheck``, ``VersionedDatabase``) over each image.

What a PASS here shows: *under the stated model*, no cut point of the save leaves a newest version
that cannot be opened, or that opens with content that was never written, and the repair that the
open does is repeatable. What it does **not** show, and no document may say otherwise (6.1):

* that a real disk, controller, USB bridge, ReFS or NTFS behaves like the model (the model is the
  contract the code assumes, not a measurement of any device; a drive that acknowledges a flush it
  has not done defeats it);
* anything about the recovery of an acknowledged edit (the store write-ahead, GR3) or the master;
* anything about the sectors of a file the model does not name (a sector is atomic here; a tear
  inside a 512-byte sector is not modelled).

So no sentence about power loss is made by this file, by the engine or by any document. The only
output is the result of the matrix.

THE MODEL

Trace. The classes that write the files of a save (``LocalBufferFile``, ``LocalManagedBufferFile``,
``ChangeMapFile``, ``VersionFile``, ``Database``: this checkout's source, not the installed jar) are
compiled with every write, ``setLength``, ``sync``, rename, delete and file creation routed through
``hydra.e12.IoTrace`` (a test-only copy in a scratch folder, in the style of ``dt_e8.py``: no test
code is in the release jar, D48). Replaying the trace on the starting tree must give the tree the
real run left (``e12_trace_complete``): an operation the trace misses makes that test fail.

Data. A write reaches the disk in units of 512-byte sectors, in any order and any subset until a
``sync`` of that file (``FileDescriptor.sync``: ``FlushFileBuffers``). After a power loss a sector is
the last synced version or any later version, and the length is the synced length or the length of
the cache (never-written sectors read as zero: the shape of the defect E8 fixed).

Directory entries (the file names). Two models; every matrix is run under both:

* ``J`` (journaled metadata, NTFS and ext4 style): creates, renames and deletes become durable in the
  order they were made; any prefix may be lost, except what a ``sync`` of the file forced (all
  entries up to the last one that touched that file) or a directory sync forced.
* ``U`` (no ordering assumed): each entry operation may be lost or kept alone (an operation that
  depends on an earlier one of the same file needs that one), except what a directory sync forced.
  This is the POSIX contract without ``fsync`` of the directory, which Java cannot ask for on Windows.

The oracle. Every image is opened as a writable disposable tree. ``opened`` must show a version that
was written by the save or that existed before it, with exactly the content written; the open that
failed once must succeed on the retry (``retry_ok``); otherwise the image is ``unopenable`` or
``silent_corrupt``. ``ack_lost``: an image taken at or after the return of ``saveCompleted`` that
opens an older version than the one acknowledged (the save matrices require none; it is a lost
acknowledgement, not an unopenable file). ``history_unreadable`` (versioned databases): an older
version cannot be rebuilt from the newest one and its version file.

Tests
-----
* ``e12_source_guards``     the facts the model rests on, pinned in the sources (order of the
  ``flush``, the rename and the directory sync; the copy of a fork is not forced by ``copyProject``,
  ``ProjectFork.publish`` forces the staged tree before it moves anything; the sidecar is forced).
* ``e12_trace_complete``    replay of the trace equals the real tree (private and versioned item).
* ``e12_control_*``         the simulator can fail: the pre-E8 order, a save without the data sync
  and a save without the directory sync each produce violations (red), the current code none.
* ``e12_failed_commit``     a commit whose rename fails leaves no version file and the next save works;
  ``e12_control_failed_commit_no_cleanup`` is the same scenario without the cleanup (red).
* ``e12_post_commit_failure`` a failure after the commit took effect (``versionCreated`` throws) keeps the
  version file of the previous version; ``e12_commit_data_failure`` a failure after the rename that
  leaves no new version (change data step) removes it, and ``e12_control_commit_data_failure`` (narrow
  condition, no cleanup) is red; ``e12_control_post_commit_unconditional`` is a cleanup that
  runs after every failure (red).
* ``e12_save_private``      the matrix for the save of a private database (what a fork holds).
* ``e12_save_versioned``    the matrix for the save of a versioned database.
* ``e12_fork_publish``      the matrix for the publish of a fork as ``ProjectFork.publish`` now does it
  (modelled from the source, see ``fork_model``; the order is pinned by ``e12_source_guards``): the
  staged tree is forced (files, then folders), the directory is synced before and after the ``.gpr``.
* ``e12_fork_publish_finding`` the control: the same matrix for the publish without those forces (the
  code before E12b) must find violations under both models.
* ``e12_upgrade_publish``   the matrix for the first build of an upgrade-cache entry as ``UpgradeCache.build``
  now does it (``upgrade_model``): the copy is forced before the rename of ``gN.tmp``, entry.json (the commit
  point) is forced before its move; ``e12_upgrade_publish_finding``, the control: the build without them
  (before FIX4) must find violations under both models.

Environment: ``E12_BUFFERS`` (buffers of the test database, default 8), ``E12_BLOCK`` (buffer size, default
1024: a block of 1029 bytes; Ghidra's default is 16384), ``E12_SAVES`` (saves in one
trace, default 2), ``E12_RANDOM`` (random subsets per cut and entry choice, default 6),
``E12_SEED`` (default 12), ``E12_U_ENTRIES`` (random entry subsets tried per cut under U, on top of the systematic ones, default 24),
``GHIDRA_SESSION_JAVA_HOME``/``JAVA_HOME`` name the JDK.
"""
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import subprocess

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]

#: the release the engine sources are compiled at (Ghidra/application.properties): H3's pre-save
#: uses java.lang.foreign.Arena, a preview API under --release 21
JAVA_RELEASE = next((ln.split("=", 1)[1].strip() for ln in (REPO / "Ghidra" / "application.properties")
                     .read_text(encoding="utf-8").splitlines()
                     if ln.startswith("application.java.compiler=")), "21")
DB_REL = "Ghidra/Framework/DB/src/main/java/db/buffers/"
DBDB_REL = "Ghidra/Framework/DB/src/main/java/db/Database.java"
FORK_REL = ("Ghidra/Features/HeadlessSession/src/main/java/ghidra/app/util/headless/session/"
            "ProjectFork.java")
UPG_REL = ("Ghidra/Features/HeadlessSession/src/main/java/ghidra/app/util/headless/session/"
           "UpgradeCache.java")
SECTOR = 512
BUFFERS = int(os.environ.get("E12_BUFFERS", "8"))
BLOCK = int(os.environ.get("E12_BLOCK", "1024"))
SAVES = int(os.environ.get("E12_SAVES", "2"))
NRANDOM = int(os.environ.get("E12_RANDOM", "6"))
SEED = int(os.environ.get("E12_SEED", "12"))
U_ENTRIES = int(os.environ.get("E12_U_ENTRIES", "24"))

IOTRACE = r'''package hydra.e12;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Test-only (dt_e12.py): routes the file operations of a save through a total-order log. */
public final class IoTrace {
    private static final Object LOCK = new Object();
    private static String root;          // lower-case, absolute, normalised, with a trailing '/'
    private static Path rootPath;
    private static PrintWriter out;
    private static final ThreadLocal<Boolean> EXISTED = new ThreadLocal<>();

    public static void start(File dir, File log) throws IOException {
        synchronized (LOCK) {
            rootPath = dir.toPath().toAbsolutePath().normalize();
            root = norm(rootPath.toString()) + "/";
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(log), "UTF-8")), false);
        }
    }

    public static void stop() {
        synchronized (LOCK) {
            if (out != null) { out.flush(); out.close(); out = null; }
            root = null;
        }
    }

    private static String norm(String s) { return s.replace('\\', '/').toLowerCase(Locale.ROOT); }

    /** The path relative to the root, or null if the file is not under it. */
    private static String rel(File f) {
        if (root == null) return null;
        Path p = f.toPath().toAbsolutePath().normalize();
        String n = norm(p.toString());
        if (!(n + "/").startsWith(root)) return null;
        return rootPath.relativize(p).toString().replace('\\', '/');
    }

    private static void log(String line) {
        out.print(line); out.print('\n');
        out.flush();
    }

    public static void mark(String label) {
        synchronized (LOCK) { if (out != null) log("M\t" + label); }
    }

    public static boolean rename(File a, File b) {
        synchronized (LOCK) {
            boolean ok = a.renameTo(b);
            if (ok && out != null) {
                String ra = rel(a), rb = rel(b);
                if (ra != null && rb != null) log("R\t" + ra + "\t" + rb);
                else if (ra != null || rb != null) log("X\trename across the root " + a + " " + b);
            }
            return ok;
        }
    }

    public static boolean delete(File f) {
        synchronized (LOCK) {
            boolean ok = f.delete();
            if (ok && out != null) { String r = rel(f); if (r != null) log("D\t" + r); }
            return ok;
        }
    }

    public static File createTempFile(String prefix, String suffix, File dir) throws IOException {
        synchronized (LOCK) {
            File f = File.createTempFile(prefix, suffix, dir);
            if (out != null) { String r = rel(f); if (r != null) log("C\t" + r); }
            return f;
        }
    }

    /** The directory flush (the call the instrumented LocalManagedBufferFile makes). */
    public static void dirSync(File dir) {
        synchronized (LOCK) {
            if (out != null) { String r = rel(dir); if (r != null) log("DS\t" + (r.isEmpty() ? "." : r)); }
        }
    }

    private static File note(File f, String mode) {
        EXISTED.set(f.exists());
        return f;
    }

    public static final class Raf extends RandomAccessFile {
        private final File f;
        public Raf(File f, String mode) throws IOException {
            super(note(f, mode), mode);
            this.f = f;
            if (mode.indexOf('w') >= 0 && !EXISTED.get()) {
                synchronized (LOCK) { if (out != null) { String r = rel(f); if (r != null) log("C\t" + r); } }
            }
        }
        private void w(long pos, byte[] b, int off, int len) {
            if (out == null) return;
            String r = rel(f);
            if (r == null) return;
            StringBuilder sb = new StringBuilder("W\t").append(r).append('\t').append(pos).append('\t');
            for (int i = 0; i < len; i++) { int v = b[off + i] & 0xff; sb.append(Character.forDigit(v >> 4, 16)).append(Character.forDigit(v & 15, 16)); }
            log(sb.toString());
        }
        @Override public void write(int b) throws IOException {
            synchronized (LOCK) { long p = getFilePointer(); super.write(b); w(p, new byte[] { (byte) b }, 0, 1); }
        }
        @Override public void write(byte[] b) throws IOException {
            synchronized (LOCK) { long p = getFilePointer(); super.write(b); w(p, b, 0, b.length); }
        }
        @Override public void write(byte[] b, int off, int len) throws IOException {
            synchronized (LOCK) { long p = getFilePointer(); super.write(b, off, len); w(p, b, off, len); }
        }
        @Override public void setLength(long n) throws IOException {
            synchronized (LOCK) {
                super.setLength(n);
                if (out != null) { String r = rel(f); if (r != null) log("T\t" + r + "\t" + n); }
            }
        }
        /**
         * Replaces the positional channel write of H3's chunked pre-save
         * ({@code raf.getChannel().write(src, pos)}): a write through the channel does not pass
         * through {@link #write}, so the trace would not see it. Writes the remaining bytes of
         * {@code src} at {@code pos} and logs them as the same {@code W} record a {@code write} gives.
         */
        public void writeAt(java.nio.ByteBuffer src, long pos) throws IOException {
            synchronized (LOCK) {
                java.nio.ByteBuffer seen = src.duplicate();
                java.nio.channels.FileChannel ch = getChannel();
                long p = pos;
                while (src.hasRemaining()) { p += ch.write(src, p); }
                if (out != null && seen.hasRemaining()) {
                    byte[] b = new byte[seen.remaining()];
                    seen.get(b);
                    w(pos, b, 0, b.length);
                }
            }
        }
        /** Replaces {@code raf.getFD().sync()}. */
        public void syncTraced() throws IOException {
            synchronized (LOCK) {
                getFD().sync();
                if (out != null) { String r = rel(f); if (r != null) log("S\t" + r); }
            }
        }
    }
}
'''

PROBE = r'''package db.buffers;

import hydra.e12.IoTrace;
import ghidra.framework.store.db.*;
import ghidra.framework.store.local.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class E12Probe {
    static final int BS = Integer.getInteger("e12.bs", 1024), CHECKOUT = 1;
    static volatile int cur = 0;
    static final VersionedDBListener L = new VersionedDBListener() {
        public void versionsChanged(int min, int c) { }
        public boolean versionCreated(VersionedDatabase db, int v, long t, String c, long id) {
            cur = v; return true; }
        public void versionDeleted(int v) { }
        public int getCheckoutVersion(long id) { return cur; }
        public void checkinCompleted(long id) { }
    };

    static byte[] fill(int index, int ver) {
        byte[] d = new byte[BS];
        for (int i = 0; i < BS; i++) d[i] = (byte) (0x10 * index + ver + (i % 7));
        return d;
    }

    static String hash(BufferFile bf) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DataBuffer buf = new DataBuffer();
        md.update(Integer.toString(bf.getIndexCount()).getBytes());
        int[] fl = bf.getFreeIndexes();
        Arrays.sort(fl);
        md.update(Arrays.toString(fl).getBytes());
        for (int i = 0; i < bf.getIndexCount(); i++) {
            bf.get(buf, i);
            md.update((byte) (buf.isEmpty() ? 1 : 0));
            md.update(Integer.toString(buf.getId()).getBytes());
            if (!buf.isEmpty()) md.update(buf.data);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ").replace("\r", " "); }

    static LocalFileSystem openFs(File dir, boolean create, boolean versioned) throws IOException {
        return LocalFileSystem.getLocalFileSystem(dir.getPath(), create, versioned, false, false);
    }

    static String itemHash() throws Exception { return null; }

    static String privHash(File dir) throws Exception {
        LocalFileSystem fs = openFs(dir, false, false);
        try {
            LocalManagedBufferFile bf = ((LocalDatabaseItem) fs.getItem("/", "x")).open();
            try { return bf.getVersion() + ":" + hash(bf); } finally { bf.close(); }
        } finally { fs.dispose(); }
    }

    static String verHash(VersionedDatabase db, int v) throws Exception {
        LocalManagedBufferFile r = db.openBufferFile(v, -1);
        try { return hash(r); } finally { r.close(); }
    }

    static void putSave(LocalManagedBufferFile sf, int v, int nbuf) throws Exception {
        for (int i : new int[] { v % nbuf, (v + 3) % nbuf }) {
            DataBuffer b = new DataBuffer(fill(i, v));
            b.setId(100 * v + i);
            sf.put(b, i);
        }
        sf.setParameter("E12", v);
    }

    static void copyTree(Path from, Path to) throws IOException {
        try (java.util.stream.Stream<Path> w = Files.walk(from)) {
            for (Path p : (Iterable<Path>) w::iterator) {
                Path t = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(t); else Files.copy(p, t);
            }
        }
    }

    static int abandoned = 0;

    static String one(String kind, File dir, String sub) {
        try {
            File root = sub == null || sub.isEmpty() ? dir : new File(dir, sub);
            if (!root.isDirectory()) return "{\"opened\":false,\"absent\":true}";
            if (kind.equals("private")) {
                LocalFileSystem fs = openFs(root, false, false);
                try {
                    LocalFolderItem it = fs.getItem("/", "x");
                    if (it == null) return "{\"opened\":false,\"error\":\"item_missing\"}";
                    LocalManagedBufferFile bf = ((LocalDatabaseItem) it).open();
                    try {
                        return "{\"opened\":true,\"v\":" + bf.getVersion() + ",\"h\":\"" + hash(bf) + "\"}";
                    } finally { bf.close(); }
                } finally { fs.dispose(); }
            }
            VersionedDatabase db = new VersionedDatabase(root, L);
            int v = db.getCurrentVersion();
            String h = verHash(db, v);
            StringBuilder hist = new StringBuilder("[");
            for (int u = db.getMinimumVersion(); u < v; u++) {
                final int uu = u;
                final VersionedDatabase fdb = db;
                String x;
                if (abandoned >= 3) {
                    x = "SKIPPED";
                } else {
                    // a torn version file can make the reader loop for minutes (a garbage buffer
                    // count): the read gets a time limit, and a thread that outlives it is abandoned
                    java.util.concurrent.atomic.AtomicReference<String> box = new java.util.concurrent.atomic.AtomicReference<>("ERR");
                    Thread th = new Thread(() -> { try { box.set(verHash(fdb, uu)); } catch (Throwable t) { box.set("ERR"); } });
                    th.setDaemon(true);
                    th.start();
                    th.join(8000);
                    if (th.isAlive()) { abandoned++; x = "TIMEOUT"; } else { x = box.get(); }
                }
                hist.append(hist.length() > 1 ? "," : "").append("[").append(u).append(",\"").append(x).append("\"]");
            }
            return "{\"opened\":true,\"v\":" + v + ",\"h\":\"" + h + "\",\"hist\":" + hist + "]}";
        } catch (Throwable t) {
            return "{\"opened\":false,\"error\":\"" + esc(t.getClass().getSimpleName() + ": " + t.getMessage()) + "\"}";
        }
    }

    public static void main(String[] a) throws Exception {
        String mode = a[0], kind = a[1];
        File dir = new File(a[2]);
        if (mode.equals("make")) {
            int nbuf = Integer.parseInt(a[3]);
            if (kind.equals("private")) {
                dir.mkdirs();
                File tmp = new File(dir.getParentFile(), dir.getName() + ".src.gbf");
                tmp.delete();
                LocalBufferFile src = new LocalBufferFile(tmp, BS);
                for (int i = 0; i < nbuf; i++) {
                    DataBuffer buf = new DataBuffer(fill(i, 1));
                    buf.setId(100 + i);
                    src.put(buf, i);
                }
                src.setParameter("E12", 1);
                src.close();
                LocalFileSystem fs = openFs(dir, true, false);
                src = new LocalBufferFile(tmp, true);
                fs.createDatabase("/", "x", "xFILEIDx", src, "c", "PROGRAM", false, TaskMonitor.DUMMY, "u");
                src.close();
                fs.dispose();
                tmp.delete();
                System.out.println("{\"ok\":true,\"expect\":\"1:" + privHash(dir).substring(2) + "\"}");
            } else {
                LocalManagedBufferFile bf = VersionedDatabase.createVersionedDatabase(dir, BS, L, CHECKOUT);
                for (int i = 0; i < nbuf; i++) {
                    DataBuffer buf = new DataBuffer(fill(i, 1));
                    buf.setId(100 + i);
                    bf.put(buf, i);
                }
                bf.setParameter("E12", 1);
                bf.close();
                VersionedDatabase db = new VersionedDatabase(dir, L);
                System.out.println("{\"ok\":true,\"expect\":\"1:" + verHash(db, 1) + "\"}");
            }
        }
        else if (mode.equals("trace")) {
            // a[3] trace log, a[4] saves, a[5] buffers, a[6] folder for a copy of the tree the save left
            File log = new File(a[3]);
            int saves = Integer.parseInt(a[4]), nbuf = Integer.parseInt(a[5]);
            LocalManagedBufferFile src;
            LocalFileSystem fs = null;
            VersionedDatabase vdb = null;
            IoTrace.start(dir, log);   // before the open: the open starts the pre-save file
            if (kind.equals("private")) {
                fs = openFs(dir, false, false);
                src = ((LocalDatabaseItem) fs.getItem("/", "x")).openForUpdate(-1);
            } else {
                cur = 1;
                vdb = new VersionedDatabase(dir, L);
                src = vdb.openBufferFileForUpdate(CHECKOUT);
            }
            try {
                for (int v = 2; v <= saves + 1; v++) {
                    // what BufferMgr.save does: the save file becomes the source of the next save
                    LocalManagedBufferFile out = (LocalManagedBufferFile) src.getSaveFile();
                    putSave(out, v, nbuf);
                    IoTrace.mark("saving:" + v);
                    src.saveCompleted(true);
                    IoTrace.mark("acked:" + v);
                    src.dispose();   // BufferMgr.doSetSourceFile closes the file it saved from
                    src = out;
                }
                src.close();
                IoTrace.mark("closed");
            } finally {
                IoTrace.stop();
            }
            if (fs != null) fs.dispose();
            copyTree(dir.toPath(), new File(a[6]).toPath());   // the tree the save left, before any reader repairs it
            // the expected hash of every version, read after the trace (reads are not traced)
            StringBuilder sb = new StringBuilder("{\"ok\":true,\"expect\":{");
            if (kind.equals("private")) {
                sb.append("\"").append(saves + 1).append("\":\"").append(privHash(dir)).append("\"");
                sb.setLength(sb.length());
            } else {
                VersionedDatabase db = new VersionedDatabase(dir, L);
                for (int v = 1; v <= saves + 1; v++) {
                    sb.append(v > 1 ? "," : "").append("\"").append(v).append("\":\"").append(v).append(":").append(verHash(db, v)).append("\"");
                }
            }
            System.out.println(sb.append("}}").toString());
        }
        else if (mode.equals("openmany")) {
            // a[3] sub folder inside each image ("" for none); one JSON line per image folder
            String sub = a.length > 3 ? a[3] : "";
            String[] names = dir.list();
            Arrays.sort(names);
            ghidra.framework.store.db.VersionFileCheck.setRepairPolicy(f -> true);
            for (String n : names) {
                File img = new File(dir, n);
                if (!img.isDirectory()) continue;
                int r0 = ghidra.framework.store.db.VersionFileCheck.repairs().size();
                String a1 = one(kind, img, sub);
                int r1 = ghidra.framework.store.db.VersionFileCheck.repairs().size();
                String a2 = one(kind, img, sub);
                System.out.println("{\"id\":\"" + n + "\",\"a1\":" + a1 + ",\"a2\":" + a2 + ",\"repairs\":" + (r1 - r0) + "}");
            }
            System.out.println("{\"done\":true}");
        }
        else if (mode.equals("dirsync")) {
            // LocalManagedBufferFile.syncDirectory must not throw and must not change the tree
            java.lang.reflect.Method m = LocalManagedBufferFile.class.getDeclaredMethod("syncDirectory", File.class);
            m.setAccessible(true);
            m.invoke(null, dir);
            m.invoke(null, new File(dir, "does-not-exist"));
            String why = "";
            boolean opens;
            try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(dir.toPath(), StandardOpenOption.READ)) {
                ch.force(true);
                opens = true;
            } catch (Throwable t) {
                opens = false;
                why = t.getClass().getSimpleName();
            }
            System.out.println("{\"ok\":true,\"dirOpens\":" + opens + ",\"why\":\"" + why + "\"}");
        }
    }
}
'''


FAILPROBE = r'''package db.buffers;

import java.io.*;
import java.util.*;

/**
 * A commit that fails after the version file was closed, then a retry. Prints one JSON line.
 * Mode "rename": the rename of the new version fails (the commit does not take effect).
 * Mode "post": the rename succeeds and versionCreated throws FileNotFoundException afterwards
 * (the commit has taken effect; the signature of a database whose files cannot be scanned).
 * Mode "cdfail": the rename succeeds and the change data step that follows it throws
 * IOException "Failed to update change data" (a change data file exists and a non-empty folder
 * has the name of its .bak file); saveFile.delete() then removes the renamed new version, so the
 * commit left no new version behind although the save file had its final name.
 */
public class E12FailProbe {
    static class Mgr implements BufferFileManager {
        final File dir; int cur = 0; boolean boom = false;
        Mgr(File dir) { this.dir = dir; }
        public File getBufferFile(int v) { return new File(dir, "v" + v + ".bf"); }
        public File getChangeDataFile(int v) { return new File(dir, "cd" + v + ".bf"); }
        public File getChangeMapFile() { return null; }
        public int getCurrentVersion() { return cur; }
        public File getVersionFile(int v) { return new File(dir, "v" + v + ".vf"); }
        public void updateEnded(long id) { }
        public void versionCreated(int v, String c, long id) throws FileNotFoundException {
            cur = v;
            if (boom) { throw new FileNotFoundException("Database files not found"); }
        }
    }

    static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ").replace("\r", " "); }

    static void save(LocalManagedBufferFile u, int fill) throws Exception {
        LocalManagedBufferFile s = (LocalManagedBufferFile) u.getSaveFile();
        byte[] d = new byte[1024];
        Arrays.fill(d, (byte) fill);
        DataBuffer b = new DataBuffer(d);
        b.setId(11);
        s.put(b, 1);
        u.saveCompleted(true);
    }

    public static void main(String[] a) throws Exception {
        File dir = new File(a[0]);
        dir.mkdirs();
        Mgr m = new Mgr(dir);
        LocalManagedBufferFile v = new LocalManagedBufferFile(1024, m, 1);
        byte[] d = new byte[1024];
        DataBuffer b = new DataBuffer(d);
        for (int i = 0; i < 3; i++) { Arrays.fill(d, (byte) (0x10 + i)); b.setId(10 + i); v.put(b, i); }
        v.close();
        boolean post = a.length > 1 && a[1].equals("post");
        boolean cdfail = a.length > 1 && a[1].equals("cdfail");
        File blocker = m.getBufferFile(2);
        if (post) {
            m.boom = true;
        } else if (cdfail) {
            // the change data file of the version being replaced exists, and its .bak name is taken
            // by a non-empty folder: comitSaveChangeDataFile cannot move the old file aside
            new File(m.getChangeDataFile(1).getPath()).createNewFile();
            blocker = new File(m.getChangeDataFile(1).getPath() + ".bak");
            blocker.mkdirs();
            new File(blocker, "x").createNewFile();
        } else {
            blocker.mkdirs();
            new File(blocker, "x").createNewFile();
        }
        boolean failed = false;
        String err = "";
        LocalManagedBufferFile u = new LocalManagedBufferFile(m, true, 1, 1);
        try { save(u, 0x55); } catch (IOException e) { failed = true; err = e.toString(); }
        boolean left = m.getVersionFile(1).exists();
        boolean newExists = m.getBufferFile(2).isFile();
        try { u.close(); } catch (Exception e) { }
        if (post) {
            System.out.println("{\"failed\":" + failed + ",\"err\":\"" + esc(err) + "\",\"versionFileLeft\":" + left
                + ",\"newVersionExists\":" + newExists + ",\"cur\":" + m.cur + "}");
            return;
        }
        new File(blocker, "x").delete();
        blocker.delete();
        boolean retryOk = false;
        String retryErr = "";
        LocalManagedBufferFile u2 = new LocalManagedBufferFile(m, true, 1, 1);
        try { save(u2, 0x66); retryOk = true; } catch (Throwable e) { retryErr = e.toString(); }
        try { u2.close(); } catch (Exception e) { }
        System.out.println("{\"failed\":" + failed + ",\"err\":\"" + esc(err) + "\",\"versionFileLeft\":" + left
            + ",\"newVersionExists\":" + newExists
            + ",\"retryOk\":" + retryOk + ",\"retryErr\":\"" + esc(retryErr) + "\",\"cur\":" + m.cur + "}");
    }
}
'''

# ---- helpers ------------------------------------------------------------------------------

def jdk_tool(name):
    for var in ("GHIDRA_SESSION_JAVA_HOME", "JAVA_HOME"):
        home = os.environ.get(var)
        if home:
            for ext in ("", ".exe"):
                p = pathlib.Path(home) / "bin" / (name + ext)
                if p.is_file():
                    return str(p)
    found = shutil.which(name)
    if not found:
        raise dt.Fail(f"{name} not found: set GHIDRA_SESSION_JAVA_HOME to a JDK")
    return found


def install_jars(install):
    root = pathlib.Path(install) / "Ghidra"
    patch = root / "patch"
    jars = [str(patch)] if patch.is_dir() else []
    jars += [str(p) for p in sorted(root.rglob("*.jar")) if patch not in p.parents]
    return os.pathsep.join(jars)


def javac(cp, out, files):
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([jdk_tool("javac"), "-nowarn", "--release", JAVA_RELEASE, "-encoding", "UTF-8",
                        "-cp", cp, "-d", str(out), *map(str, files)], capture_output=True, text=True)
    dt.check(r.returncode == 0, f"javac failed: {r.stdout[-1500:]}{r.stderr[-1500:]}")


def src_text(rel, root=None):
    p = pathlib.Path(root or REPO) / rel
    if not p.is_file():
        raise dt.Fail(f"{p} not found")
    return p.read_text(encoding="utf-8")


def sub_n(text, pattern, repl, n, what, flags=0):
    """Regex substitution that must hit exactly ``n`` times (a drifted source fails loudly)."""
    out, k = re.subn(pattern, repl, text, flags=flags)
    dt.check(k == n, f"instrumenting {what}: {k} matches of {pattern!r}, expected {n}")
    return out


def instrumented(variant):
    """{relative path: text} of the five sources, routed through IoTrace, per variant:

    ``current``      the source as it is;
    ``pre_e8``       the order before E8: no ``flush`` before the rename (and no directory sync);
    ``no_data_sync`` ``LocalBufferFile.flush`` without ``sync()``;
    ``no_dir_sync``  without the directory sync call after the rename;
    ``late_version_close`` the version file of a versioned save closed after the rename (before E12).
    """
    lbf = src_text(DB_REL + "LocalBufferFile.java")
    lmbf = src_text(DB_REL + "LocalManagedBufferFile.java")
    cmf = src_text(DB_REL + "ChangeMapFile.java")
    vf = src_text(DB_REL + "VersionFile.java")
    dbs = src_text(DBDB_REL)
    T = "hydra.e12.IoTrace"
    lbf = sub_n(lbf, r"private RandomAccessFile raf;", f"private {T}.Raf raf;", 1, "LocalBufferFile raf")
    lbf = sub_n(lbf, r"new RandomAccessFile\(", f"new {T}.Raf(", 5, "LocalBufferFile open")
    # H3's chunked pre-save writes whole chunks through the channel of the raf, which bypasses Raf.write;
    # route it through Raf.writeAt so the trace sees it, and fail if any other channel write is left
    lbf = sub_n(lbf, r"java\.nio\.channels\.FileChannel ch = raf\.getChannel\(\);\s*while \(chunk\.hasRemaining\(\)\) \{\s*"
                r"ch\.write\(chunk, pos \+ chunk\.position\(\)\);\s*\}",
                "raf.writeAt(chunk, pos);", 1, "LocalBufferFile chunk write")
    dt.check(not re.search(r"ch\.write\(|\.getChannel\(\)\s*\.write\(|\.transferFrom\(|\.map\(", lbf),
             "LocalBufferFile writes through a channel the trace does not see")
    lbf = sub_n(lbf, r"raf\.getFD\(\)\.sync\(\);",
                "raf.getFD();" if variant == "no_data_sync" else "raf.syncTraced();", 1,
                "LocalBufferFile sync")
    lbf = sub_n(lbf, r"file\.renameTo\(newFile\)", f"{T}.rename(file, newFile)", 1, "LocalBufferFile rename")
    lbf = sub_n(lbf, r"\b(file|oldFile)\.delete\(\)", rf"{T}.delete(\1)", 3, "LocalBufferFile delete")
    lmbf = sub_n(lmbf, r"\b(cfile|changeFile|bakFile)\.renameTo\((\w+)\)", rf"{T}.rename(\1, \2)", 3,
                 "LocalManagedBufferFile rename")
    lmbf = sub_n(lmbf, r"\b(bakFile|changeFile|psFile)\.delete\(\)", rf"{T}.delete(\1)", 3,
                 "LocalManagedBufferFile delete")
    lmbf = sub_n(lmbf, r"File\.createTempFile\(", f"{T}.createTempFile(", 1,
                 "LocalManagedBufferFile createTempFile")
    if variant == "pre_e8":
        lmbf = sub_n(lmbf, r"^[ \t]*saveFile\.flush\(\);[ \t]*\r?\n", "", 1,
                     "LocalManagedBufferFile early flush", flags=re.M)
    if variant == "late_version_close":
        lmbf = sub_n(lmbf, r"^[ \t]*if \(saveFile\.versionOutFile != null\) \{\r?\n[^\n]*\r?\n[^\n]*\r?\n[^\n]*\r?\n[ \t]*\}\r?\n",
                     "", 1, "LocalManagedBufferFile early version file close", flags=re.M)
    if re.search(r"^[ \t]*syncDirectory\(newFile", lmbf, re.M):
        if variant in ("pre_e8", "no_dir_sync"):
            lmbf = sub_n(lmbf, r"^[ \t]*syncDirectory\([^;]*\);[ \t]*\r?\n", "", 1,
                         "LocalManagedBufferFile directory sync", flags=re.M)
        else:
            lmbf = sub_n(lmbf, r"^([ \t]*)syncDirectory\(([^;]*)\);", rf"\1{T}.dirSync(\2);", 1,
                         "LocalManagedBufferFile directory sync", flags=re.M)
    cmf = sub_n(cmf, r"\bfile\.delete\(\)", f"{T}.delete(file)", 1, "ChangeMapFile delete")
    cmf = sub_n(cmf, r"tmpFile\.renameTo\(file\)", f"{T}.rename(tmpFile, file)", 1, "ChangeMapFile rename")
    dbs = sub_n(dbs, r"bfMgr\.get(BufferFile|VersionFile|ChangeDataFile)\(([^()]*)\)\.delete\(\)",
                rf"{T}.delete(bfMgr.get\1(\2))", 3, "Database delete")
    dbs = sub_n(dbs, r"\bgetBufferFile\(version\)\.delete\(\)", f"{T}.delete(getBufferFile(version))", 1,
                "Database delete (unexpected version)")
    dbs = sub_n(dbs, r"^(\s*)f\.delete\(\);", rf"\1{T}.delete(f);", 2, "Database delete (f)", flags=re.M)
    return {"db/buffers/LocalBufferFile.java": lbf, "db/buffers/LocalManagedBufferFile.java": lmbf,
            "db/buffers/ChangeMapFile.java": cmf, "db/buffers/VersionFile.java": vf,
            "db/Database.java": dbs}


class Bench:
    """Compiled probe and instrumented classes for one install, shared by the tests of a run."""
    _cache = {}

    @classmethod
    def get(cls, c, variant):
        key = (str(c.work), variant)
        if key in cls._cache:
            return cls._cache[key]
        base = c.work / "e12"
        jars = install_jars(c.a.ghidra)
        tracedir = base / "trace-classes"
        if not (tracedir / "hydra" / "e12" / "IoTrace.class").is_file():
            f = base / "src" / "hydra" / "e12" / "IoTrace.java"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(IOTRACE, encoding="utf-8")
            javac(jars, tracedir, [f])
        vdir = base / ("variant-" + variant)
        if vdir.exists():
            shutil.rmtree(vdir)
        files = []
        for rel, text in instrumented(variant).items():
            f = vdir / "src" / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
            files.append(f)
        pf = vdir / "src" / "db" / "buffers" / "E12Probe.java"
        pf.write_text(PROBE, encoding="utf-8")
        files.append(pf)
        javac(str(tracedir) + os.pathsep + jars, vdir / "classes", files)
        cls._cache[key] = (str(vdir / "classes") + os.pathsep + str(tracedir) + os.pathsep + jars)
        return cls._cache[key]


def run_probe(cp, *args, timeout=600):
    r = subprocess.run([jdk_tool("java"), f"-De12.bs={BLOCK}", "-cp", cp, "db.buffers.E12Probe", *map(str, args)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout)
    lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
    if r.returncode != 0 or not lines:
        raise dt.Fail(f"probe {args[:2]} exit {r.returncode}: {r.stdout[-500:]} {r.stderr[-1200:]}")
    return [json.loads(x) for x in lines]


def read_tree(root):
    out = {}
    root = pathlib.Path(root)
    for d, _dirs, files in os.walk(root):
        for f in files:
            p = pathlib.Path(d) / f
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def read_dirs(root):
    out = set()
    root = pathlib.Path(root)
    for d, dirs, _files in os.walk(root):
        for x in dirs:
            out.add((pathlib.Path(d) / x).relative_to(root).as_posix())
    return out


# ---- the trace and the model --------------------------------------------------------------

def parse_trace(path):
    """[(kind, ...)]: C path | W path off bytes | T path n | S path | R a b | D path | DS dir | M label.
    Adjacent writes of one file that continue each other are one operation."""
    ops = []
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        f = line.split("\t")
        k = f[0]
        if k == "W":
            off, data = int(f[2]), bytes.fromhex(f[3])
            if ops and ops[-1][0] == "W" and ops[-1][1] == f[1] and ops[-1][2] + len(ops[-1][3]) == off:
                ops[-1] = ("W", f[1], ops[-1][2], ops[-1][3] + data)
            else:
                ops.append(("W", f[1], off, data))
        elif k == "T":
            ops.append(("T", f[1], int(f[2])))
        elif k in ("C", "S", "D", "DS", "M"):
            ops.append((k, f[1]))
        elif k == "R":
            ops.append(("R", f[1], f[2]))
        elif k == "X":
            raise dt.Fail("the trace saw a rename across the traced root: " + f[1])
        else:
            raise dt.Fail("unknown trace line: " + line[:80])
    return ops


class Replay:
    """Volatile and durable state of a tree while a trace is replayed."""

    def __init__(self, base):
        self.n = 0
        self.names = {}
        self.vol = {}
        self.dur = {}
        self.pend = {}
        self.base_names = {}
        for p, b in sorted(base.items()):
            ino = self.new(b)
            self.names[p] = ino
            self.base_names[p] = ino
        self.meta = []            # (kind, ino, a, b)
        self.last_meta = {}       # ino -> index of the last entry operation on it
        self.forced_j = 0
        self.forced_u = 0

    def new(self, content=b""):
        self.n += 1
        self.vol[self.n] = bytearray(content)
        self.dur[self.n] = bytes(content)
        self.pend[self.n] = {}
        return self.n

    def ino(self, p):
        if p not in self.names:
            raise dt.Fail(f"replay: operation on {p}, which has no entry")
        return self.names[p]

    def apply(self, op):
        k = op[0]
        if k == "M":
            return
        if k == "C":
            ino = self.new()
            self.names[op[1]] = ino
            self.meta.append(("link", ino, op[1], None))
            self.last_meta[ino] = len(self.meta) - 1
        elif k == "W":
            ino = self.ino(op[1])
            v, off, data = self.vol[ino], op[2], op[3]
            if len(v) < off:
                v.extend(b"\0" * (off - len(v)))
            v[off:off + len(data)] = data
            for s in range(off // SECTOR, (off + len(data) - 1) // SECTOR + 1):
                sec = bytes(v[s * SECTOR:(s + 1) * SECTOR]).ljust(SECTOR, b"\0")
                self.pend[ino].setdefault(s, []).append(sec)
        elif k == "T":
            ino = self.ino(op[1])
            v = self.vol[ino]
            if op[2] < len(v):
                del v[op[2]:]
                keep = (op[2] + SECTOR - 1) // SECTOR
                for s in [s for s in self.pend[ino] if s >= keep]:
                    del self.pend[ino][s]
            else:
                v.extend(b"\0" * (op[2] - len(v)))
        elif k == "S":
            ino = self.ino(op[1])
            self.dur[ino] = bytes(self.vol[ino])
            self.pend[ino] = {}
            self.forced_j = max(self.forced_j, self.last_meta.get(ino, -1) + 1)
        elif k == "R":
            self.ino(op[1])
            ino = self.names.pop(op[1])
            self.names[op[2]] = ino
            self.meta.append(("rename", ino, op[1], op[2]))
            self.last_meta[ino] = len(self.meta) - 1
        elif k == "D":
            ino = self.names.pop(op[1])
            self.meta.append(("unlink", ino, op[1], None))
        elif k == "DS":
            self.forced_j = self.forced_u = len(self.meta)
        else:
            raise dt.Fail("replay: unknown operation " + k)

    def final_files(self):
        return {p: bytes(self.vol[i]) for p, i in self.names.items()}


def entries_applied(rp, kept):
    names = dict(rp.base_names)
    for idx in kept:
        kind, ino, a, b = rp.meta[idx]
        if kind == "link":
            names[a] = ino
        elif kind == "rename":
            if names.get(a) == ino:
                del names[a]
            names[b] = ino
        elif kind == "unlink":
            if names.get(a) == ino:
                del names[a]
    return names


def entry_choices(rp, model, rng):
    """Index lists of the entry operations that survive, for the model."""
    m = len(rp.meta)
    if model == "J":
        return [list(range(j)) for j in range(rp.forced_j, m + 1)]
    forced = list(range(rp.forced_u))
    rest = list(range(rp.forced_u, m))
    deps = {}
    for i in rest:
        ino = rp.meta[i][1]
        deps[i] = [j for j in range(rp.forced_u, i) if rp.meta[j][1] == ino]
    out = []
    seen = set()

    def add(sel):
        sel = set(sel)
        changed = True
        while changed:        # close under "an operation needs the earlier ones on its file"
            changed = False
            for i in list(sel):
                for j in deps[i]:
                    if j not in sel:
                        sel.add(j)
                        changed = True
        key = tuple(sorted(sel))
        if key not in seen:
            seen.add(key)
            out.append(forced + list(key))
    add([])
    add(rest)
    for i in rest:
        add([i])
        add([j for j in rest if j != i])
    for i in range(1, len(rest)):
        add(rest[i:])          # the later operations kept without the earlier ones
    for _ in range(U_ENTRIES):
        add([i for i in rest if rng.random() < 0.5])
    return out


def compose(rp, ino, pick, size_vol):
    """Content of an inode: its durable bytes plus the pending sector versions ``pick`` selects."""
    dur = rp.dur[ino]
    vol_len = len(rp.vol[ino])
    size = vol_len if size_vol else len(dur)
    data = bytearray(dur)
    if len(data) < size:
        data.extend(b"\0" * (size - len(data)))
    for s, versions in rp.pend[ino].items():
        i = pick(s, len(versions))
        if i is None or i < 0:
            continue
        lo = s * SECTOR
        if len(data) < lo + SECTOR:
            data.extend(b"\0" * (lo + SECTOR - len(data)))
        data[lo:lo + SECTOR] = versions[i]
    return bytes(data[:size])


RELEVANT = re.compile(r"(^|/)(db\.\d+\.gbf|[^/]*\.ver|[^/]*\.cd|[^/]*\.map|[^/]*\.gbf)$")
SCRATCH = re.compile(r"(^|/)(tmp[^/]*\.ps|[^/]*\.tmp)$")


def strategies(rp, names, rng, model):
    """[(label, pick_for(ino, sector, nversions), size_vol_for(ino))] for the current pending state."""
    inos = sorted(set(names.values()))
    has_pending = [i for i in inos if rp.pend[i] or len(rp.vol[i]) != len(rp.dur[i])]
    rel_inos = [i for p, i in names.items() if RELEVANT.search(p) and i in has_pending]
    out = []

    def uniform(label, pick_fn, size_vol):
        out.append((label, lambda ino, s, n, f=pick_fn: f(s, n), lambda ino, v=size_vol: v))
    uniform("none", lambda s, n: -1, False)
    uniform("all", lambda s, n: n - 1, True)
    uniform("zerofill", lambda s, n: -1, True)
    uniform("header_only", lambda s, n: n - 1 if s == 0 else -1, True)
    uniform("body_only", lambda s, n: -1 if s == 0 else n - 1, True)
    if model == "J":
        for ino in rel_inos:
            for s in sorted(rp.pend[ino]):
                out.append((f"only:{ino}:{s}", lambda i, ss, n, ino=ino, s=s: (n - 1) if (i == ino and ss == s) else -1,
                            lambda i: True))
                out.append((f"but:{ino}:{s}", lambda i, ss, n, ino=ino, s=s: -1 if (i == ino and ss == s) else n - 1,
                            lambda i: True))
    for k in range(NRANDOM):
        seed = rng.getrandbits(32)

        def rpick(i, s, n, seed=seed):
            r = random.Random(seed * 1000003 + i * 4099 + s)
            return r.randint(-1, n - 1)

        def rsize(i, seed=seed):
            return random.Random(seed + i).random() < 0.5
        out.append((f"rand:{k}", rpick, rsize))
    return out


def gen_cut(rp, model, rng, cut, images, base_dirs):
    for kept in entry_choices(rp, model, rng):
        names = entries_applied(rp, kept)
        for label, pick, size_vol in strategies(rp, names, rng, model):
            files = {}
            for p, ino in names.items():
                files[p] = compose(rp, ino, lambda s, n, ino=ino: pick(ino, s, n), size_vol(ino))
            key = hashlib.sha256()
            for p in sorted(files):
                key.update(p.encode() + b"\0")
                if SCRATCH.search(p):
                    key.update(b"scratch")
                else:
                    key.update(hashlib.sha256(files[p]).digest())
            k = key.digest()
            rec = images.get(k)
            if rec is None:
                images[k] = {"files": files, "cut": cut, "max_cut": cut, "how": f"{model}/{label}/entries={len(kept)}"}
            else:
                rec["max_cut"] = max(rec["max_cut"], cut)


def simulate(base, ops, model, seed=SEED):
    """{image key: {files, cut, max_cut, how}} over every cut point of the trace, and the replay."""
    rng = random.Random(seed)
    rp = Replay(base)
    images = {}
    gen_cut(rp, model, rng, 0, images, None)
    for i, op in enumerate(ops, 1):
        rp.apply(op)
        if op[0] != "M":
            gen_cut(rp, model, rng, i, images, None)
    return images, rp


def materialize(images, root, base_dirs):
    root = pathlib.Path(root)
    if root.exists():
        shutil.rmtree(root)
    ids = {}
    for n, (k, rec) in enumerate(images.items()):
        d = root / f"i{n:06d}"
        for sd in base_dirs:
            (d / sd).mkdir(parents=True, exist_ok=True)
        d.mkdir(parents=True, exist_ok=True)
        for p, data in rec["files"].items():
            f = d / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        ids[d.name] = rec
    return ids


def classify(ids, results, expect, ops):
    """Counts and the first examples per outcome."""
    marks = {}
    for i, op in enumerate(ops, 1):
        if op[0] == "M":
            marks[op[1]] = i
    ack = [(marks[f"acked:{v}"], v) for v in range(2, SAVES + 2) if f"acked:{v}" in marks]
    exp = set(expect.values())
    count = {}
    examples = {}

    def put(cat, rid):
        count[cat] = count.get(cat, 0) + 1
        examples.setdefault(cat, [])
        if len(examples[cat]) < 4:
            examples[cat].append((rid, ids[rid]["how"], ids[rid]["cut"]))
    by = {r["id"]: r for r in results if "id" in r}
    for rid, rec in ids.items():
        r = by.get(rid)
        if r is None:
            put("no_result", rid)
            continue
        a1, a2 = r["a1"], r["a2"]
        got = lambda a: f"{a['v']}:{a['h']}" if a.get("opened") else None

        if a1.get("opened") and got(a1) in exp:
            cat, ok = "opened", a1
            if r["repairs"]:
                cat = "opened_repaired"
        elif a1.get("opened"):
            put("silent_corrupt", rid)
            continue
        elif a2.get("opened") and got(a2) in exp:
            cat, ok = "retry_ok", a2
        else:
            put("unopenable", rid)
            continue
        put(cat, rid)
        for m, v in ack:
            if rec["max_cut"] >= m and ok["v"] < v:
                put("ack_lost", rid)
                break
        hist = ok.get("hist")
        if hist is not None and any(h in ("ERR", "TIMEOUT") or (h != "SKIPPED" and f"{u}:{h}" != expect.get(str(u))) for u, h in hist):
            put("history_unreadable", rid)
    return count, examples


VIOLATIONS = ("unopenable", "silent_corrupt", "no_result")


def scenario(c, kind, variant, tag):
    """Builds the starting tree, traces SAVES saves with the instrumented classes and returns
    (base files, base dirs, ops, expected hashes, the real final tree)."""
    cp = Bench.get(c, variant)
    d = c.work / "e12" / f"run-{tag}"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    root = d / ("fs" if kind == "private" else "db")
    mk = run_probe(cp, "make", kind, root, BUFFERS)[-1]
    base = read_tree(root)
    base_dirs = read_dirs(root)
    log = d / "trace.log"
    fin = d / "final"
    tr = run_probe(cp, "trace", kind, root, log, SAVES, BUFFERS, fin)[-1]
    final = read_tree(fin)
    ops = parse_trace(log)
    expect = {}
    first = mk["expect"]
    expect["1"] = first
    if kind == "private":
        expect[str(SAVES + 1)] = tr["expect"][str(SAVES + 1)]
        # the intermediate versions of a private database are not kept: derive them by the saves
        # themselves (see the acknowledged-save marks); only the last and the first are compared
    else:
        expect.update(tr["expect"])
    return {"base": base, "dirs": base_dirs, "ops": ops, "expect": expect, "final": final, "cp": cp,
            "dir": d, "kind": kind}


def private_expect_all(c, sc):
    """The expected hash of every version of a private database. A save replaces the file, so the
    content of version n+1 is read from a fresh run of n saves (the content is deterministic)."""
    cp, kind = sc["cp"], sc["kind"]
    d = sc["dir"] / "chain"
    if d.exists():
        shutil.rmtree(d)
    out = {"1": run_probe(cp, "make", kind, d / "fs0", BUFFERS)[-1]["expect"]}
    for n in range(1, SAVES + 1):
        r = d / f"fs{n}"
        run_probe(cp, "make", kind, r, BUFFERS)
        t = run_probe(cp, "trace", kind, r, d / f"t{n}.log", n, BUFFERS, d / f"f{n}")[-1]
        out[str(n + 1)] = t["expect"][str(n + 1)]
    return out


def run_matrix(c, sc, model, tag, sub=""):
    images, rp = simulate(sc["base"], sc["ops"], model)
    root = sc["dir"] / f"img-{model}-{tag}"
    ids = materialize(images, root, sc["dirs"])
    res = run_probe(sc["cp"], "openmany", sc["kind"], root, sub, timeout=1800)
    count, examples = classify(ids, res, sc["expect"], sc["ops"])
    return {"model": model, "cuts": len([o for o in sc["ops"] if o[0] != "M"]) + 1, "images": len(ids),
            "count": count, "examples": examples, "root": str(root)}


def summarize(m):
    return (f"{m['model']}: {m['cuts']} cut points, {m['images']} distinct images, " +
            ", ".join(f"{k}={v}" for k, v in sorted(m["count"].items())))


def violations(m):
    return sum(m["count"].get(k, 0) for k in VIOLATIONS)


# ---- the tests ----------------------------------------------------------------------------

def t_source_guards(c):
    lmbf = src_text(DB_REL + "LocalManagedBufferFile.java")
    body = lmbf[lmbf.index("public synchronized void saveCompleted"):]
    body = body[:body.index("public synchronized boolean canSave")]
    i_flush = body.index("saveFile.flush();")
    i_ren = body.index("saveFile.renameFile(newFile)")
    dt.check(i_flush < i_ren, "saveCompleted: flush() must come before renameFile()")
    m = re.search(r"^\s*syncDirectory\(newFile\.getParentFile\(\)\);", body, re.M)
    dt.check(m is not None and body.index("saveFile.renameFile(newFile)") < m.start() < body.index("saveFile.setReadOnly()"),
             "saveCompleted: the directory sync must follow the rename and precede setReadOnly()")
    lbf = src_text(DB_REL + "LocalBufferFile.java")
    dt.check(len(re.findall(r"raf\.getFD\(\)\.sync\(\)", lbf)) == 1, "LocalBufferFile.flush has exactly one sync")
    fl = lbf[lbf.index("boolean flush()"):]
    fl = fl[:fl.index("public void dispose()")]
    dt.check(fl.index("writeHeader();") < fl.index("sync()"), "flush: header written before the sync")
    dt.check("catch (SyncFailedException" in fl, "flush: SyncFailedException is swallowed (a finding, pinned)")
    pf = src_text(FORK_REL)
    pub = pf[pf.index("static void publish(Staged st, File destDir, String name, JsonObject sidecar,\n\t\t\tString completeState, List<String> extras)"):]
    order = [pub.index(s) for s in ("moveRetrying(stagedRep, destRep)", "writeSidecar(sc, sidecar)",
                                    "moveRetrying(stagedGpr, destGpr)")]
    dt.check(order == sorted(order), "ProjectFork.publish: rep, sidecar, gpr order changed; the model must follow")
    dt.check(pub.rindex("writeSidecar(sc, sidecar)") > order[2], "ProjectFork.publish: final sidecar after the gpr")
    dt.check("ch.force(true)" in pf, "writeSidecar forces its temporary file")
    # E12b: what fork_model("current") assumes of publish
    i_force = pub.index("forceTree(st.dir().toPath()")  # (root) or (root, linked): hard-linked version files are forced once per process
    i_moving = pub.index("withPhase(ForkIntent.MOVING")
    dt.check(i_force < i_moving < order[0], "ProjectFork.publish: forceTree(staging) before the intent and the .rep move")
    pre = pub[order[1]:order[2]]
    dt.check(re.search(r"^\s*syncDirectory\(destDir\.toPath\(\)\);", pre, re.M) is not None and
             pre.rindex("syncDirectory(destDir.toPath())") > pre.rfind("moved.add(extra)"),
             "ProjectFork.publish: syncDirectory(destDir) after the sidecar and the extras, before the .gpr move")
    post = pub[order[2]:pub.rindex("writeSidecar(sc, sidecar)")]
    dt.check(re.search(r"^\s*syncDirectory\(destDir\.toPath\(\)\);", post, re.M) is not None,
             "ProjectFork.publish: syncDirectory(destDir) after the .gpr move, before the final sidecar")
    ft = pf[pf.index("static void forceTree(Path root)"):]
    ft = ft[:ft.index("private static void moveRetrying")]
    dt.check("forceFile(f)" in ft and "syncDirectory(d)" in ft and "postVisitDirectory" in ft,
             "forceTree forces every regular file, then every folder")
    ff = ft[ft.index("static void forceFile(Path f)"):]
    ff = ff[:ff.index("static void syncDirectory(Path dir)")]
    dt.check("StandardOpenOption.WRITE" in ff and "setReadOnly(false)" in ff and "ch.force(true)" in ff,
             "forceFile: on Windows a writable handle (read-only files made writable for the flush) and force(true)")
    fi = src_text(FORK_REL.replace("ProjectFork.java", "ForkIntent.java")).replace("\r\n", "\n")
    fw = fi[fi.index("void write(Path staging)"):]
    fw = fw[:fw.index("\n\t}\n")]
    dt.check(not re.search(r"force\(|getFD\(\)|sync\(", fw), "ForkIntent.write is not forced (the model says so)")
    up = src_text(UPG_REL)
    cp = up[up.index("static void copyProject"):]
    cp = cp[:cp.index("/** Opens the copy writable")]
    dt.check("Files.copy(src, to, StandardCopyOption.COPY_ATTRIBUTES)" in cp, "copyProject copies with Files.copy")
    dt.check(not re.search(r"force\(|getFD\(\)|sync\(", cp), "copyProject does not force the copies (the finding, pinned)")
    # FIX4: what upgrade_model("current") assumes of UpgradeCache.build and writeEntry
    up = up.replace("\r\n", "\n")
    ub = up[up.index("copyProject(from, plan.resolved().name(), copyDir.toPath(), m);"):]
    ub = ub[:ub.index("out.set(State.READY")]
    idx = [ub.index(x) for x in ("upgradeInCopy(", "ProjectFork.forceTree(tmp[0].toPath());",
                                 "moveDir(tmp[0].toPath(), published.toPath(), m);",
                                 "ProjectFork.syncDirectory(dir.toPath());", "writeEntry(dir, entry);")]
    dt.check(idx == sorted(idx), "UpgradeCache.build: upgrade, forceTree(tmp), moveDir, syncDirectory(dir), writeEntry in that order")
    we = up[up.index("private static void writeEntry(File dir, JsonObject entry)"):]
    we = we[:we.index("\n\t}")]
    wi = [we.index(x) for x in ("Files.writeString(tmp", "ProjectFork.forceFile(tmp);", "Files.move(tmp",
                                "ProjectFork.syncDirectory(dir.toPath());")]
    dt.check(wi == sorted(wi), "UpgradeCache.writeEntry: write, forceFile, atomic move, directory sync in that order")
    return ("saveCompleted: flush, rename, directory sync, setReadOnly in that order; fork publish: forceTree, rep, "
            "sidecar, directory sync, gpr, directory sync; copyProject and ForkIntent.write force nothing; "
            "writeSidecar forces its file; upgrade cache build: forceTree, rename, directory sync, entry.json forced, "
            "moved, synced")


def t_trace_complete(c):
    notes = []
    for kind in ("private", "versioned"):
        sc = scenario(c, kind, "current", "tc-" + kind)
        rp = Replay(sc["base"])
        for op in sc["ops"]:
            rp.apply(op)
        replayed = rp.final_files()
        scratch = lambda t: {p: b for p, b in t.items() if not SCRATCH.search(p)}
        real, rep = scratch(sc["final"]), scratch(replayed)
        dt.check(set(real) == set(rep), f"{kind}: files differ: real-only {sorted(set(real) - set(rep))} "
                 f"replay-only {sorted(set(rep) - set(real))}")
        bad = [p for p in real if real[p] != rep[p]]
        dt.check(not bad, f"{kind}: content differs after replay for {bad}")
        kinds = {}
        for op in sc["ops"]:
            kinds[op[0]] = kinds.get(op[0], 0) + 1
        dt.check(kinds.get("S", 0) >= SAVES and kinds.get("R", 0) >= SAVES and kinds.get("W", 0) > 0,
                 f"{kind}: the trace lacks syncs or renames: {kinds}")
        notes.append(f"{kind}: {len(sc['ops'])} operations {dict(sorted(kinds.items()))} replay to the real tree "
                     f"({len(real)} files)")
    return "; ".join(notes)


def save_test(c, kind, tag):
    sc = scenario(c, kind, "current", "sv-" + tag)
    if kind == "private":
        sc["expect"] = private_expect_all(c, sc)
    out = []
    for model in ("J", "U"):
        m = run_matrix(c, sc, model, tag)
        c.timings[f"e12 {tag} {model} images"] = m["images"]
        out.append(m)
        dt.check(violations(m) == 0, f"{kind} save, model {model}: " + summarize(m) + " examples=" +
                 json.dumps({k: v for k, v in m["examples"].items() if k in VIOLATIONS}))
        dt.check(m["count"].get("ack_lost", 0) == 0,
                 f"{kind} save, model {model}: an acknowledged save was lost: " + summarize(m) +
                 json.dumps(m["examples"].get("ack_lost")))
        if kind == "versioned":
            dt.check(m["count"].get("history_unreadable", 0) == 0,
                     f"{kind} save, model {model}: an older version is unreadable: " + summarize(m) +
                     json.dumps(m["examples"].get("history_unreadable")))
    return " | ".join(summarize(m) for m in out)


def t_save_private(c):
    return save_test(c, "private", "priv")


def t_save_versioned(c):
    return save_test(c, "versioned", "ver")


def control(c, kind, variant, model, want):
    sc = scenario(c, kind, variant, f"ctl-{variant}-{kind}")
    if kind == "private":
        sc["expect"] = private_expect_all(c, sc)
    m = run_matrix(c, sc, model, f"ctl-{variant}")
    got = sum(m["count"].get(k, 0) for k in want)
    dt.check(got > 0, f"control {variant}/{kind}/{model}: the simulator found none of {want}: " + summarize(m))
    return f"{variant}/{kind}: {summarize(m)}; red as it must be ({'+'.join(want)}={got})"


def t_control_pre_e8(c):
    """The save before E8 (rename, then flush): under model J a cut leaves a full-size newest version
    with an all-zero header; the simulator must see it (red evidence), the current code must not."""
    a = control(c, "private", "pre_e8", "J", ("unopenable", "silent_corrupt", "retry_ok", "opened_repaired"))
    return a


def t_control_no_data_sync(c):
    """A save whose ``flush`` does not sync: the rename can outrun the data, so a newest version
    opens with a valid header and torn content, or does not open."""
    return control(c, "private", "no_data_sync", "J", ("unopenable", "silent_corrupt"))


def t_control_no_dir_sync(c):
    """Without the directory sync after the rename, model U may keep the delete of the old version
    and lose the rename: no version is left, or the acknowledged save is lost."""
    return control(c, "private", "no_dir_sync", "U", ("unopenable", "ack_lost"))


def t_control_late_version_close(c):
    """A versioned save that closes (syncs) its version file after the rename, as before E12: under
    model J a cut leaves the new newest version with its predecessor unreadable."""
    return control(c, "versioned", "late_version_close", "J", ("history_unreadable",))


# ---- fork publish -------------------------------------------------------------------------

def fork_model(c, variant):
    """The operation list of ``ProjectFork.stage`` and ``publish`` for a fork of a project holding one
    database item, built from the order the source documents (guarded by ``e12_source_guards``; the
    publish is NOT traced from the running code: it is Java NIO, which the trace does not reach).

    Layout: ``dest/F.rep`` (the item), ``dest/F.gpr``, ``dest/F.fork.json``, staging ``dest/.F.fork-ID.tmp``.

    ``variant``: ``"current"`` is the code as it is (``forceTree`` of the staging folder before the
    intent says ``moving``, ``syncDirectory`` of the destination before and after the ``.gpr`` move);
    ``"plain"`` is the publish before E12b, which forced nothing but the sidecar (the control).
    ``ForkIntent.write`` is not forced in either (``Files.writeString`` and a move); the oracle does not
    read the intent."""
    if variant not in ("current", "plain"):
        raise ValueError(variant)
    forced = variant == "current"
    cp = Bench.get(c, "current")
    d = c.work / "e12" / ("forkbase-" + variant)
    if d.exists():
        shutil.rmtree(d)
    src = d / "src" / "F.rep"
    mk = run_probe(cp, "make", "private", src, BUFFERS)[-1]
    gpr = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PROJECT><SAVED_DATA/></PROJECT>\n"
    sidecar = lambda state: json.dumps({"forkId": "ID", "state": state, "source": "F"}).encode()
    tree = read_tree(src)
    stg = ".F.fork-ID.tmp"
    ops = []
    ops += [("C", f"{stg}/intent.json.tmp"), ("W", f"{stg}/intent.json.tmp", 0, b'{"id":"ID","phase":"staging"}'),
            ("R", f"{stg}/intent.json.tmp", f"{stg}/intent.json")]   # ForkIntent.write: not forced
    ops.append(("M", "staged-intent"))
    for p, b in sorted(tree.items()):                        # UpgradeCache.copyProject: Files.copy per file
        ops += [("C", f"{stg}/F.rep/{p}"), ("W", f"{stg}/F.rep/{p}", 0, b)]
    ops += [("C", f"{stg}/F.gpr"), ("W", f"{stg}/F.gpr", 0, gpr)]
    ops.append(("M", "staged"))
    if forced:                                               # publish: forceTree(staging), files then folders
        ops += [("S", f"{stg}/intent.json")] + [("S", f"{stg}/F.rep/{p}") for p in sorted(tree)]
        ops += [("S", f"{stg}/F.gpr"), ("DS", stg)]
        ops.append(("M", "forced"))
    ops += [("C", f"{stg}/intent.json.tmp"), ("W", f"{stg}/intent.json.tmp", 0, b'{"id":"ID","phase":"moving"}'),
            ("R", f"{stg}/intent.json.tmp", f"{stg}/intent.json")]
    # moveRetrying(stagedRep, destRep): a directory rename, every name under it moves
    for p in sorted(tree):
        ops.append(("R", f"{stg}/F.rep/{p}", f"F.rep/{p}"))
    ops.append(("M", "rep-moved"))
    ops += [("C", "F.fork.json.tmp"), ("W", "F.fork.json.tmp", 0, sidecar("publishing")), ("S", "F.fork.json.tmp"),
            ("R", "F.fork.json.tmp", "F.fork.json")]         # writeSidecar: forced, then an atomic move
    if forced:
        ops.append(("DS", "."))                              # syncDirectory(destDir) before the .gpr
    ops.append(("R", f"{stg}/F.gpr", "F.gpr"))               # the commit point
    if forced:
        ops.append(("DS", "."))                              # syncDirectory(destDir) after it
    ops.append(("M", "gpr-moved"))
    ops += [("C", "F.fork.json.tmp"), ("W", "F.fork.json.tmp", 0, sidecar("complete")), ("S", "F.fork.json.tmp"),
            ("R", "F.fork.json.tmp", "F.fork.json")]
    ops.append(("M", "complete"))
    return {"ops": ops, "tree": tree, "gpr": gpr, "expect": {"1": mk["expect"]}, "dir": d, "cp": cp,
            "sidecar": sidecar, "name": variant}


_FORK_CACHE = {}


def fork_matrix(c, fm, model):
    key = (str(fm['dir']), model)
    if key not in _FORK_CACHE:
        _FORK_CACHE[key] = _fork_matrix(c, fm, model)
    return _FORK_CACHE[key]


def _fork_matrix(c, fm, model):
    # directories of the staged tree and of the destination, so that a rename has somewhere to land
    dirs = {".F.fork-ID.tmp"}
    for p in fm["tree"]:
        parts = p.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add(".F.fork-ID.tmp/F.rep/" + "/".join(parts[:i]))
            dirs.add("F.rep/" + "/".join(parts[:i]))
    dirs |= {".F.fork-ID.tmp/F.rep", "F.rep"}
    images, rp = simulate({}, fm["ops"], model)
    root = fm["dir"] / f"img-{model}"
    ids = materialize(images, root, dirs)
    # the oracle: no .gpr -> the fork is absent (retry or sweep, E2a); .gpr -> it must be complete
    res = run_probe(fm["cp"], "openmany", "private", root, "F.rep", timeout=1800)
    by = {r["id"]: r for r in res if "id" in r}
    count, examples = {}, {}
    exp = set(fm["expect"].values())

    def put(cat, rid):
        count[cat] = count.get(cat, 0) + 1
        examples.setdefault(cat, [])
        if len(examples[cat]) < 4:
            examples[cat].append((rid, ids[rid]["how"], ids[rid]["cut"]))
    for rid, rec in ids.items():
        files = rec["files"]
        if "F.gpr" not in files:
            put("absent", rid)
            continue
        r = by[rid]
        a1, a2 = r["a1"], r["a2"]
        g = lambda a: f"{a['v']}:{a['h']}" if a.get("opened") else None
        if files["F.gpr"] != fm["gpr"]:
            put("silent_corrupt", rid)       # a .gpr that is not what was copied
        elif a1.get("opened") and g(a1) in exp:
            put("complete" if _sidecar_ok(files.get("F.fork.json")) else "silent_corrupt", rid)
        elif a1.get("opened"):
            put("silent_corrupt", rid)
        elif a2.get("opened") and g(a2) in exp:
            put("retry_ok", rid)
        else:
            put("unopenable", rid)
    return {"model": model, "cuts": len([o for o in fm["ops"] if o[0] != "M"]) + 1, "images": len(ids),
            "count": count, "examples": examples, "root": str(root)}


def _sidecar_ok(b):
    try:
        return json.loads(b).get("state") in ("publishing", "complete")
    except Exception:  # noqa: BLE001
        return False


def t_fork_publish(c):
    """The fork-publish matrix for the code as it is (``fork_model`` "current", its order pinned by
    ``e12_source_guards``): no cut point may leave a ``.gpr`` whose fork does not open with the
    content copied (``unopenable``, ``silent_corrupt``); a cut before the commit leaves no ``.gpr``
    (``absent``: a staging folder or a ``.rep`` without ``.gpr``, which the sweep removes)."""
    fm = fork_model(c, "current")
    out = []
    bad = 0
    for model in ("J", "U"):
        m = fork_matrix(c, fm, model)
        out.append(summarize(m))
        bad += violations(m)
    dt.check(bad == 0, "fork publish: " + " | ".join(out) + " " +
             json.dumps({mo: {k: v for k, v in fork_matrix(c, fm, mo)["examples"].items() if k in VIOLATIONS}
                         for mo in ("J", "U")}))
    return " | ".join(out)


def t_fork_publish_finding(c):
    """The control of ``e12_fork_publish``: the publish without the forces (the code before E12b) is red
    under both models, and the current one is green, so the simulator can tell them apart."""
    fm = fork_model(c, "plain")
    ff = fork_model(c, "current")
    rows = []
    for model in ("J", "U"):
        m = fork_matrix(c, fm, model)
        dt.check(violations(m) > 0, f"fork publish {model}: the simulator found no violation in the unforced publish: " + summarize(m))
        rows.append("plain " + summarize(m))
        w = fork_matrix(c, ff, model)
        dt.check(violations(w) == 0, f"fork publish {model}: the current publish leaves violations: " + summarize(w) +
                 json.dumps({k: v for k, v in w['examples'].items() if k in VIOLATIONS}))
        rows.append("current " + summarize(w))
    return " | ".join(rows)


# ---- the upgrade cache publish (UpgradeCache.build) ----------------------------------------

def upgrade_model(c, variant):
    """The operation list of a first build of the upgrade cache (``UpgradeCache.build``) of a project
    holding one database item, from the order of the source (pinned by ``e12_source_guards``; Java NIO,
    not traced). Layout of the cache entry: ``g1.tmp/project/F.rep`` and ``F.gpr`` (``copyProject``:
    ``Files.copy`` per file), the rename of ``g1.tmp`` to ``g1`` (``moveDir``), then ``entry.json``
    naming ``g1`` (``writeEntry``: a temporary file and an atomic move), the commit point: a cache
    without an entry.json naming the generation rebuilds it (``removeLeftovers``).

    The upgrade itself (``upgradeInCopy``) rewrites the item through Ghidra's save, which the save
    matrices cover; here the copied item is the content, so a cut can only lose copied sectors.

    ``variant``: ``"current"`` forces the tree before the rename (``ProjectFork.forceTree``), syncs the
    cache folder after it and forces entry.json before its move, then syncs the folder; ``"plain"`` is the
    build before FIX4, which forced nothing (the control)."""
    if variant not in ("current", "plain"):
        raise ValueError(variant)
    forced = variant == "current"
    cp = Bench.get(c, "current")
    d = c.work / "e12" / ("upgbase-" + variant)
    if d.exists():
        shutil.rmtree(d)
    src = d / "src" / "F.rep"
    mk = run_probe(cp, "make", "private", src, BUFFERS)[-1]
    gpr = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PROJECT><SAVED_DATA/></PROJECT>\n"
    entry = json.dumps({"format": 1, "generation": "g1", "upgraded": ["/F"]}).encode()
    tree = read_tree(src)
    stg = "g1.tmp/project"
    ops = []
    for p, b in sorted(tree.items()):                        # copyProject: Files.copy per file
        ops += [("C", f"{stg}/F.rep/{p}"), ("W", f"{stg}/F.rep/{p}", 0, b)]
    ops += [("C", f"{stg}/F.gpr"), ("W", f"{stg}/F.gpr", 0, gpr)]
    ops.append(("M", "copied"))
    if forced:                                               # forceTree(g1.tmp): files, then folders
        ops += [("S", f"{stg}/F.rep/{p}") for p in sorted(tree)] + [("S", f"{stg}/F.gpr"), ("DS", "g1.tmp")]
        ops.append(("M", "forced"))
    for p in sorted(tree):                                   # moveDir: a directory rename
        ops.append(("R", f"{stg}/F.rep/{p}", f"g1/project/F.rep/{p}"))
    ops.append(("R", f"{stg}/F.gpr", "g1/project/F.gpr"))
    if forced:
        ops.append(("DS", "."))                              # syncDirectory(dir) after the rename
    ops.append(("M", "renamed"))
    ops += [("C", "entry.json.tmp"), ("W", "entry.json.tmp", 0, entry)]
    if forced:
        ops.append(("S", "entry.json.tmp"))                  # writeEntry: forceFile(tmp)
    ops.append(("R", "entry.json.tmp", "entry.json"))       # the commit point
    if forced:
        ops.append(("DS", "."))
    ops.append(("M", "published"))
    return {"ops": ops, "tree": tree, "gpr": gpr, "expect": {"1": mk["expect"]}, "dir": d, "cp": cp,
            "name": variant}


_UPG_CACHE = {}


def upgrade_matrix(c, um, model):
    key = (str(um["dir"]), model)
    if key not in _UPG_CACHE:
        _UPG_CACHE[key] = _upgrade_matrix(c, um, model)
    return _UPG_CACHE[key]


def _upgrade_matrix(c, um, model):
    dirs = {"g1.tmp", "g1.tmp/project", "g1.tmp/project/F.rep", "g1", "g1/project", "g1/project/F.rep"}
    for p in um["tree"]:
        parts = p.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("g1.tmp/project/F.rep/" + "/".join(parts[:i]))
            dirs.add("g1/project/F.rep/" + "/".join(parts[:i]))
    images, rp = simulate({}, um["ops"], model)
    root = um["dir"] / f"img-{model}"
    ids = materialize(images, root, dirs)
    # the oracle: no entry.json naming g1 -> the build is absent (rebuilt); named -> it must be complete
    res = run_probe(um["cp"], "openmany", "private", root, "g1/project/F.rep", timeout=1800)
    by = {r["id"]: r for r in res if "id" in r}
    count, examples = {}, {}
    exp = set(um["expect"].values())

    def put(cat, rid):
        count[cat] = count.get(cat, 0) + 1
        examples.setdefault(cat, [])
        if len(examples[cat]) < 4:
            examples[cat].append((rid, ids[rid]["how"], ids[rid]["cut"]))
    for rid, rec in ids.items():
        files = rec["files"]
        try:
            named = json.loads(files["entry.json"]).get("generation") == "g1"
        except Exception:  # noqa: BLE001  (missing or torn: readEntry gives null, the entry is rebuilt)
            named = False
        if not named:
            put("absent", rid)
            continue
        r = by.get(rid)
        if r is None:
            put("no_result", rid)
            continue
        a1, a2 = r["a1"], r["a2"]
        g = lambda a: f"{a['v']}:{a['h']}" if a.get("opened") else None
        if files.get("g1/project/F.gpr") != um["gpr"]:
            put("silent_corrupt", rid)       # a .gpr that is not what was copied (or none)
        elif a1.get("opened") and g(a1) in exp:
            put("complete", rid)
        elif a1.get("opened"):
            put("silent_corrupt", rid)
        elif a2.get("opened") and g(a2) in exp:
            put("retry_ok", rid)
        else:
            put("unopenable", rid)
    return {"model": model, "cuts": len([o for o in um["ops"] if o[0] != "M"]) + 1, "images": len(ids),
            "count": count, "examples": examples, "root": str(root)}


def t_upgrade_publish(c):
    """The upgrade-cache publish matrix for the code as it is (``upgrade_model`` "current", its order pinned
    by ``e12_source_guards``): no cut point may leave an entry.json naming a generation whose project does
    not open with the content copied; a cut before the commit leaves the build absent (rebuilt)."""
    um = upgrade_model(c, "current")
    out, bad = [], 0
    for model in ("J", "U"):
        m = upgrade_matrix(c, um, model)
        out.append(summarize(m))
        bad += violations(m)
    dt.check(bad == 0, "upgrade publish: " + " | ".join(out) + " " +
             json.dumps({mo: {k: v for k, v in upgrade_matrix(c, um, mo)["examples"].items() if k in VIOLATIONS}
                         for mo in ("J", "U")}))
    return " | ".join(out)


def t_upgrade_publish_finding(c):
    """The control of ``e12_upgrade_publish``: the build without the forces (before FIX4: ``Files.copy``, a
    rename and an unforced entry.json) is red under both models, the current one green."""
    um, uf = upgrade_model(c, "plain"), upgrade_model(c, "current")
    rows = []
    for model in ("J", "U"):
        m = upgrade_matrix(c, um, model)
        dt.check(violations(m) > 0, f"upgrade publish {model}: the simulator found no violation in the unforced build: " + summarize(m))
        rows.append("plain " + summarize(m))
        w = upgrade_matrix(c, uf, model)
        dt.check(violations(w) == 0, f"upgrade publish {model}: the current build leaves violations: " + summarize(w) +
                 json.dumps({k: v for k, v in w['examples'].items() if k in VIOLATIONS}))
        rows.append("current " + summarize(w))
    return " | ".join(rows)


def t_installed_jar(c):
    """The installed jar, not the source: in ``saveCompleted`` of the ``LocalManagedBufferFile`` the
    bytecode calls ``flush``, then closes the version file, then ``renameFile``, then
    ``syncDirectory``; the class comes from a jar and not from a ``Ghidra/patch`` folder. The matrices
    above prove the order for the source text; this one ties it to the build under test."""
    inst = pathlib.Path(c.a.ghidra)
    patch = inst / "Ghidra" / "patch"
    dt.check(not patch.is_dir() or not any(patch.rglob("*.class")),
             "the install has class files in Ghidra/patch: the jars are not what is loaded")
    r = subprocess.run([jdk_tool("javap"), "-c", "-p", "-cp", install_jars(inst),
                        "db.buffers.LocalManagedBufferFile"], capture_output=True, text=True)
    dt.check(r.returncode == 0, f"javap: {r.stdout[-200:]}{r.stderr[-300:]}")
    m = re.search(r"\n[^\n]*void saveCompleted\(boolean\)[^\n]*\n(.*?)\n\n", r.stdout, re.S)
    dt.check(m, "saveCompleted(boolean) not found in the installed LocalManagedBufferFile")
    body = m.group(1)

    def at(name, first=True):
        xs = [int(x.group(1)) for x in re.finditer(
            r"(\d+): invoke\w+\s+#\d+\s+// (?:Interface)?Method [^\s:]*" + name, body)]
        dt.check(xs, f"installed saveCompleted: no call of {name}")
        return min(xs) if first else max(xs)
    flush, vclose, ren, dsync = at(r"flush:\(\)Z"), at(r"VersionFile\.close:"), at(r"renameFile:"), \
        at(r"syncDirectory:")
    dt.check(flush < ren and vclose < ren and ren < dsync,
             f"installed saveCompleted order: flush {flush}, version file close {vclose}, "
             f"renameFile {ren}, syncDirectory {dsync}")
    return (f"installed jar: flush at {flush}, version file close at {vclose}, renameFile at {ren}, "
            f"syncDirectory at {dsync} (bytecode offsets)")


def t_dir_sync(c):
    """``syncDirectory`` (E12) on this platform: it never throws and never changes the tree."""
    cp = Bench.get(c, "current")
    d = c.work / "e12" / "dirsync"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    (d / "a.bin").write_bytes(b"x" * 100)
    before = read_tree(d)
    r = run_probe(cp, "dirsync", "private", d)[-1]
    dt.check(read_tree(d) == before, "syncDirectory changed the tree")
    where = ("a directory can be opened and forced here" if r["dirOpens"] else
             f"a directory cannot be opened as a channel here ({r['why']}): the call does nothing on this platform")
    return f"syncDirectory on a folder and on a missing path: no exception, tree unchanged; {where}"


# ---- failure path of a commit ---------------------------------------------------------------

def failed_commit(c, variant, mode="rename"):
    """Runs a versioned database through a commit that fails, with the classes of the installed jars
    (``current``) or with a ``LocalManagedBufferFile`` compiled from the source with the cleanup of
    the version file closed early changed:

    * ``no_cleanup``    the cleanup removed (the version file of a failed commit stays);
    * ``unconditional`` the cleanup runs after every failure, also one after the commit took effect;
    * ``narrow``        the cleanup runs only while the save file still has its temporary name (the
      condition before the change data failure was found: it misses a failure after the rename that
      still leaves no new version).

    ``mode`` ``rename``: the rename of the new version fails (a non-empty folder with its name), then
    a second save runs. ``post``: the rename succeeds and ``versionCreated`` throws
    ``FileNotFoundException`` afterwards (the failure of a commit that has taken effect). ``cdfail``:
    the rename succeeds and the change data step throws ``IOException``; the renamed new version is
    deleted again, then a second save runs."""
    base = c.work / "e12" / ("failcommit-" + mode + "-" + variant)
    if base.exists():
        shutil.rmtree(base)
    jars = install_jars(c.a.ghidra)
    cp = jars
    if variant in ("no_cleanup", "unconditional", "narrow"):
        lmbf = src_text(DB_REL + "LocalManagedBufferFile.java")
        if variant == "no_cleanup":
            lmbf = sub_n(lmbf, r"^[ \t]*if \(closedVersionFile != null[^{]*\{\r?\n[^\n]*\r?\n[ \t]*\}\r?\n", "", 1,
                         "LocalManagedBufferFile cleanup of the closed version file", flags=re.M)
        elif variant == "narrow":
            lmbf = sub_n(lmbf, r"if \(closedVersionFile != null[^{]*\{",
                         "if (closedVersionFile != null && !newFile.equals(saveFile.getFile())) {", 1,
                         "LocalManagedBufferFile condition of the cleanup of the closed version file")
        else:
            lmbf = sub_n(lmbf, r"if \(closedVersionFile != null[^{]*\{", "if (closedVersionFile != null) {", 1,
                         "LocalManagedBufferFile condition of the cleanup of the closed version file")
        f = base / "src" / "db" / "buffers" / "LocalManagedBufferFile.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(lmbf, encoding="utf-8")
        javac(jars, base / "ctl", [f])
        cp = str(base / "ctl") + os.pathsep + jars
    pf = base / "src" / "db" / "buffers" / "E12FailProbe.java"
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(FAILPROBE, encoding="utf-8")
    javac(cp, base / "probe", [pf])
    r = subprocess.run([jdk_tool("java"), "-cp", str(base / "probe") + os.pathsep + cp, "db.buffers.E12FailProbe",
                        str(base / "data"), mode], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=300)
    lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
    dt.check(r.returncode == 0 and lines, f"fail probe exit {r.returncode}: {r.stdout[-400:]} {r.stderr[-800:]}")
    return json.loads(lines[-1])


def t_failed_commit(c):
    """A commit that fails after the version file was closed (E12 closes it before the rename) must
    not leave that file behind, and the next save of the database must work. With the early close
    ``saveFile.delete()`` can no longer abort the file: without the cleanup a complete ``.vf`` stays and
    every later save dies with ``DuplicateFileException``."""
    r = failed_commit(c, "current")
    dt.check(r["failed"], f"the save with a blocked rename did not fail: {r}")
    dt.check(not r["versionFileLeft"], f"a failed commit left its version file: {r}")
    dt.check(r["retryOk"] and r["cur"] == 2, f"the save after a failed commit failed: {r}")
    return f"failed commit ({r['err']}): version file removed, next save ok, current version {r['cur']}"


def t_control_failed_commit_no_cleanup(c):
    """The same scenario without the cleanup of the closed version file must be red: the file stays
    and the next save fails."""
    r = failed_commit(c, "no_cleanup")
    dt.check(r["failed"] and r["versionFileLeft"] and not r["retryOk"],
             f"control no_cleanup: the scenario did not show the defect: {r}")
    return f"no_cleanup: version file left behind, next save fails ({r['retryErr']}); red as it must be"


def t_post_commit_failure(c):
    """A failure after the commit took effect (the rename succeeded, ``versionCreated`` throws
    ``FileNotFoundException``, which is what ``VersionedDatabase`` and ``Database`` throw when the scan
    finds no version) must keep the reverse-delta file of the previous version: it is the only way to
    rebuild that version, and it was kept before E12."""
    r = failed_commit(c, "current", "post")
    dt.check(r["failed"], f"the save with a failing versionCreated did not fail: {r}")
    dt.check(r["newVersionExists"], f"the committed version is missing: {r}")
    dt.check(r["versionFileLeft"], f"a failure after the commit deleted the version file of the previous version: {r}")
    return f"failure after the commit ({r['err']}): new version kept, version file of the previous version kept"


def t_control_post_commit_unconditional(c):
    """The same scenario with a cleanup that runs after every failure must be red: the version file
    of the previous version is deleted while the new version stays."""
    r = failed_commit(c, "unconditional", "post")
    dt.check(r["failed"] and r["newVersionExists"] and not r["versionFileLeft"],
             f"control unconditional: the scenario did not show the defect: {r}")
    return "unconditional cleanup: new version kept, version file of the previous version deleted; red as it must be"


def t_commit_data_failure(c):
    """A failure after the rename that leaves no new version behind (the change data step of a
    check-in throws ``IOException`` "Failed to update change data", then ``saveFile.delete()`` removes
    the renamed new version because it is not read-only yet) must remove the version file closed
    early: the previous version is still the newest and the next save of the database must work."""
    r = failed_commit(c, "current", "cdfail")
    dt.check(r["failed"] and "Failed to update change data" in r["err"],
             f"the save with a failing change data step did not fail as planned: {r}")
    dt.check(not r["newVersionExists"], f"the failed commit left a new version: {r}")
    dt.check(not r["versionFileLeft"], f"a commit that left no new version kept its version file: {r}")
    dt.check(r["retryOk"] and r["cur"] == 2, f"the save after the failed commit failed: {r}")
    return f"change data failure ({r['err']}): no new version, version file removed, next save ok, current version {r['cur']}"


def t_control_commit_data_failure(c):
    """The same scenario with the cleanup limited to a save file that still has its temporary name
    (``narrow``) and without any cleanup must be red: the version file stays and the next save dies
    with ``DuplicateFileException``."""
    out = []
    for variant in ("narrow", "no_cleanup"):
        r = failed_commit(c, variant, "cdfail")
        dt.check(r["failed"] and not r["newVersionExists"] and r["versionFileLeft"] and not r["retryOk"]
                 and "DuplicateFileException" in r["retryErr"],
                 f"control {variant}: the scenario did not show the defect: {r}")
        out.append(variant)
    return f"{' and '.join(out)}: version file left behind, next save fails (DuplicateFileException); red as it must be"


TESTS = {
    "e12_source_guards": t_source_guards,
    "e12_trace_complete": t_trace_complete,
    "e12_dir_sync": t_dir_sync,
    "e12_installed_jar": t_installed_jar,
    "e12_control_pre_e8": t_control_pre_e8,
    "e12_control_no_data_sync": t_control_no_data_sync,
    "e12_control_no_dir_sync": t_control_no_dir_sync,
    "e12_control_late_version_close": t_control_late_version_close,
    "e12_failed_commit": t_failed_commit,
    "e12_control_failed_commit_no_cleanup": t_control_failed_commit_no_cleanup,
    "e12_post_commit_failure": t_post_commit_failure,
    "e12_control_post_commit_unconditional": t_control_post_commit_unconditional,
    "e12_commit_data_failure": t_commit_data_failure,
    "e12_control_commit_data_failure": t_control_commit_data_failure,
    "e12_save_private": t_save_private,
    "e12_save_versioned": t_save_versioned,
    "e12_fork_publish_finding": t_fork_publish_finding,
    "e12_fork_publish": t_fork_publish,
    "e12_upgrade_publish_finding": t_upgrade_publish_finding,
    "e12_upgrade_publish": t_upgrade_publish,
}

BASELINE = {}
