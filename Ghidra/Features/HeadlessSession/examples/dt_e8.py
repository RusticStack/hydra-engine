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
"""Storage integrity in the Ghidra core (PROTOCOL-3.md, section 8, package E8; decision D42).

A hard kill during a program save used to be able to leave the newest ``db.N.gbf`` at full size
with an all-zero header: ``LocalManagedBufferFile.saveCompleted`` renamed the pre-save file to its
final name first and wrote the header (``flush``, with the sync) afterwards. E8 flushes first, and
``VersionFileCheck`` validates the header magic of the newest version when a database is opened.

Tests (all external injection, no test code in the release jar, D48):

* ``e8_flush_before_rename``  deterministic window. A test-only copy of ``LocalManagedBufferFile``
  (this checkout's source, one ``sleep`` added right after the rename) goes into a copy of the
  install under ``Ghidra/patch``; the daemon is killed the moment the final-named version file
  appears, i.e. inside the window. The newest version file must have a valid header and the
  project must reopen. Red on the unfixed source (``E8_LMBF_SOURCE``), green on the fixed one.
* ``e8_window_control``  the same with the ``flush`` line removed: the harness must see the zero
  header (otherwise ``e8_flush_before_rename`` could not fail and proves nothing).
* ``e8_sp5_flush_idempotent``  spike SP5, the daemon half: the second ``flush()`` (in
  ``setReadOnly``) leaves the version file byte-identical.
* ``e8_kill_loop``  the installed, unmodified code: trigger-timed kills (the method of measurement
  C: kill a few ms after the new version file first appears; ``E8_KILL_MODE=send`` starts the
  timer when the save is sent, so kills before the rename are sampled too, ``mixed`` alternates,
  and is the default) of a daemon that saves in a loop; every
  newest version file has its magic and the project reopens, writable, with the last acknowledged
  save or the one in flight. ``E8_KILLS`` sets the count (default 8; the counted batches of 9.15
  run it with 200 on NTFS and on ReFS by pointing ``--work`` at the volume).
* ``e8_save_time``  save latency (median and p95) of the installed build. With ``E8_BASE_INSTALL``
  it is run interleaved against an install without E8 and **fails** if the median is more than
  ``E8_SAVE_TOLERANCE`` (25 %) above the base; ``E8_SAVE_MAX_MS`` is an absolute bound.
* ``e8_installed_jar``  javap of the installed ``LocalManagedBufferFile``: ``flush`` before
  ``renameFile`` in ``saveCompleted``. (``e8_flush_before_rename`` and ``e8_window_control`` build
  a test-only copy from source, so they prove the source text; this one proves the jar.)
* ``e8_check_errors``  a read-only open never repairs; a repair that cannot be done answers
  ``corrupt_newest``; an unreadable version file is an I/O error and is not quarantined.
* ``e8_version_chain``  SP5, the Java half: a versioned database saved several times keeps every
  older version readable and identical to what was written (the version chain and the buffer
  index), with the early flush in place.
* ``e8_repair_open``  the all-zero-header fixture (the state ``crash-C`` kept): a writable
  disposable tree opens at ``N-1``, logs a repair and quarantines (never deletes) the bad file; a
  tree that is not declared disposable answers ``corrupt_newest`` and **is not written** (tree hash
  before and after).
* ``e8_private_open`` and ``e8_private_readonly``: the same fixture through the daemon on a fork. A
  fork is a non-versioned (private) database, which opens through ``LocalDatabaseItem`` and
  ``PrivateDatabase``/``Database``; ``LocalDatabaseItem`` is in E8's files (8.1) and calls
  ``VersionFileCheck.repairOnOpen`` and ``requireIntact`` when an open of the newest version fails
  (E8b: nothing extra is read on the healthy path). A writable fork in a declared disposable tree opens at ``N-1``
  with the bad file in quarantine and a logged repair; a read-only open answers ``corrupt_newest``,
  declared disposable or not, with the tree hash unchanged.

* ``e8_item_readonly`` (E8b): a ``LocalDatabaseItem`` of a read-only file system, versioned or
  private, with a declared-disposable tree and a zero-header newest version, answers
  ``corrupt_newest`` and writes nothing; the writable one repairs and opens at the previous version.

Environment: ``E8_LMBF_SOURCE`` (path of the ``LocalManagedBufferFile.java`` to build the test-only
copy from; default this checkout's), ``E8_KILLS``, ``E8_PAUSE_MS`` (default 3000), ``E8_SEED``.
``GHIDRA_SESSION_JAVA_HOME``/``JAVA_HOME`` name the JDK (``javac`` and ``java``).
"""
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import statistics
import subprocess
import sys
import time

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
LMBF_REL = "Ghidra/Framework/DB/src/main/java/db/buffers/LocalManagedBufferFile.java"
MAGIC = bytes.fromhex("2f30312c34292c2a")
VER = re.compile(r"db\.(\d+)\.gbf$")
PAUSE_MS = int(os.environ.get("E8_PAUSE_MS", "3000"))

PROBE = r'''package db.buffers;

import ghidra.framework.store.db.*;
import ghidra.framework.store.local.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class E8Probe {
    static final int BS = 1024, NBUF = 10, CHECKOUT = 1;
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
        Arrays.fill(d, (byte) (0x10 * index + ver));
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

    static String hv(VersionedDatabase db, int v) throws Exception {
        LocalManagedBufferFile r = db.openBufferFile(v, -1);
        try { return hash(r); } finally { r.close(); }
    }

    static String sha(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest(Files.readAllBytes(f.toPath()))) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " "); }

    public static void main(String[] a) throws Exception {
        String mode = a[0];
        File dir = new File(a[1]);
        if (mode.equals("make")) {
            int saves = Integer.parseInt(a[2]);
            LocalManagedBufferFile bf = VersionedDatabase.createVersionedDatabase(dir, BS, L, CHECKOUT);
            DataBuffer buf;
            for (int i = 0; i < NBUF; i++) {
                buf = new DataBuffer(fill(i, 1));
                buf.setId(100 + i);
                bf.put(buf, i);
            }
            bf.setParameter("E8", 1);
            bf.close();
            List<String> expected = new ArrayList<>();
            List<Long> ms = new ArrayList<>();
            boolean flushIdem = true;
            VersionedDatabase db = new VersionedDatabase(dir, L);
            expected.add(hv(db, 1));
            for (int v = 2; v <= saves + 1; v++) {
                db = new VersionedDatabase(dir, L);
                LocalManagedBufferFile ub = db.openBufferFileForUpdate(CHECKOUT);
                LocalManagedBufferFile sf = (LocalManagedBufferFile) ub.getSaveFile();
                for (int i : new int[] { v % NBUF, (v + 3) % NBUF }) {
                    DataBuffer b = new DataBuffer(fill(i, v));
                    b.setId(100 * v + i);
                    sf.put(b, i);
                }
                sf.setParameter("E8", v);
                if (v == saves + 1) {
                    Files.copy(new File(dir, "db." + (v - 1) + ".gbf").toPath(),
                        new File(dir, "prev.keep").toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
                // SP5, Java half: a second flush() of the save file (the one setReadOnly does
                // after the rename) leaves the file byte-identical
                sf.flush();
                String f1 = sha(sf.getFile());
                sf.flush();
                flushIdem &= f1.equals(sha(sf.getFile()));
                long t0 = System.nanoTime();
                ub.saveCompleted(true);
                ms.add((System.nanoTime() - t0) / 1000);
                ub.close();
                sf.close();
                db = new VersionedDatabase(dir, L);
                expected.add(hv(db, v));
            }
            // every version, from the newest back to the first, through the version chain
            db = new VersionedDatabase(dir, L);
            boolean chain = db.getCurrentVersion() == saves + 1;
            List<String> got = new ArrayList<>();
            for (int v = 1; v <= saves + 1; v++) {
                got.add(hv(db, v));
            }
            chain &= got.equals(expected);
            System.out.println("{\"ok\":true,\"current\":" + db.getCurrentVersion() + ",\"min\":" +
                db.getMinimumVersion() + ",\"chain\":" + chain + ",\"flushIdem\":" + flushIdem + ",\"saveMicros\":" + ms +
                ",\"hashes\":" + quote(expected) + "}");
        }
        else if (mode.equals("open")) {
            try {
                boolean ro = a.length > 2 && a[2].equals("ro");
                VersionedDatabase db;
                try {   // the read-only constructor does not exist in a build without E8
                    db = VersionedDatabase.class.getConstructor(File.class,
                        VersionedDBListener.class, boolean.class).newInstance(dir, L, ro);
                }
                catch (NoSuchMethodException e) {
                    db = new VersionedDatabase(dir, L);
                }
                catch (java.lang.reflect.InvocationTargetException e) {
                    throw e.getCause();
                }
                int v = db.getCurrentVersion();
                String h;
                h = hv(db, v);
                StringBuilder rp = new StringBuilder("[");
                try {   // by reflection: the class does not exist in a build without E8
                    Class<?> k = Class.forName("ghidra.framework.store.db.VersionFileCheck");
                    for (Object x : (List<?>) k.getMethod("repairs").invoke(null)) {
                        rp.append(rp.length() > 1 ? "," : "").append('"').append(esc(x.toString())).append('"');
                    }
                }
                catch (ClassNotFoundException e) { /* none */ }
                System.out.println("{\"opened\":true,\"current\":" + v + ",\"hash\":\"" + h +
                    "\",\"repairs\":" + rp + "]}");
            }
            catch (Throwable t) {
                System.out.println("{\"opened\":false,\"error\":\"" + esc(String.valueOf(t.getMessage())) + "\"}");
            }
        }
        else if (mode.equals("itemmake")) {
            // a versioned local file system with one database item "x" (version 1)
            dir.mkdirs();
            File tmp = new File(dir.getParentFile(), dir.getName() + ".src.gbf");
            tmp.delete();
            LocalBufferFile src = new LocalBufferFile(tmp, BS);
            for (int i = 0; i < NBUF; i++) {
                DataBuffer buf = new DataBuffer(fill(i, 1));
                buf.setId(100 + i);
                src.put(buf, i);
            }
            src.setParameter("E8", 1);
            src.close();
            LocalFileSystem fs = LocalFileSystem.getLocalFileSystem(dir.getPath(), true, !(a.length > 2 && a[2].equals("priv")), false, false);
            src = new LocalBufferFile(tmp, true);
            fs.createDatabase("/", "x", "xFILEIDx", src, "c", "PROGRAM", false, TaskMonitor.DUMMY, "u");
            src.close();
            fs.dispose();
            tmp.delete();
            System.out.println("{\"ok\":true}");
        }
        else if (mode.equals("itemopen")) {
            // opens item "x" of the versioned file system, read-only or writable, and reads its data
            try {
                boolean ro = a[2].equals("ro");
                LocalFileSystem fs = LocalFileSystem.getLocalFileSystem(dir.getPath(), false, !(a.length > 3 && a[3].equals("priv")), ro, false);
                try {
                    LocalFolderItem it = fs.getItem("/", "x");
                    LocalManagedBufferFile bf = ((LocalDatabaseItem) it).open();
                    int v = bf.getVersion();
                    bf.close();
                    System.out.println("{\"opened\":true,\"current\":" + v + "}");
                }
                finally {
                    fs.dispose();
                }
            }
            catch (Throwable t) {
                System.out.println("{\"opened\":false,\"error\":\"" + esc(String.valueOf(t.getMessage())) + "\"}");
            }
        }
    }

    static String quote(List<String> l) {
        StringBuilder sb = new StringBuilder("[");
        for (String s : l) sb.append(sb.length() > 1 ? "," : "").append('"').append(s).append('"');
        return sb.append("]").toString();
    }
}
'''


# ---- low level helpers --------------------------------------------------------------------

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


def has_magic(path):
    try:
        with open(path, "rb") as f:
            return f.read(8) == MAGIC
    except OSError:
        return False


def versions(dbdir):
    out = {}
    for n in os.listdir(dbdir):
        m = VER.fullmatch(n)
        if m:
            out[int(m.group(1))] = pathlib.Path(dbdir) / n
    return out


def program_db_dir(gpr):
    """The ``~*.db`` folder of the largest program database of a project."""
    best, size = None, -1
    for d, dirs, files in os.walk(pathlib.Path(gpr).with_suffix(".rep") / "idata"):
        if d.endswith(".db"):
            tot = sum((pathlib.Path(d) / f).stat().st_size for f in files if VER.fullmatch(f))
            if tot > size:
                best, size = pathlib.Path(d), tot
    if best is None:
        raise dt.Fail(f"no database folder under {gpr}")
    return best


def newest(dbdir):
    v = versions(dbdir)
    return (max(v), v[max(v)]) if v else (0, None)


def tree_hash(root):
    h = hashlib.sha256()
    rows = []
    for d, _dirs, files in os.walk(root):
        for f in files:
            p = pathlib.Path(d) / f
            rows.append((p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()))
    for r in sorted(rows):
        h.update(("%s\t%s\n" % r).encode())
    return h.hexdigest(), len(rows)


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def zero_header(path):
    """The state a kill inside the old window left: full size, the header block all zero."""
    raw = bytearray(pathlib.Path(path).read_bytes())
    block = int.from_bytes(raw[20:24], "big")
    dt.check(raw[:8] == MAGIC and 256 <= block <= 65536, "not a buffer file to take a header from")
    raw[0:block] = b"\x00" * block
    pathlib.Path(path).write_bytes(bytes(raw))


def kill_now(c, d, pid):
    c.gs._kill_pid(pid)
    c.gs._wait_pid_exit(pid, 60)
    return not d.jvm_alive()


def wait_new_version(dbdir, above, timeout=30.0):
    """Busy-polls the folder until ``db.<above+1>.gbf`` is listed; returns the time or None."""
    end = time.perf_counter() + timeout
    want = "db.%d.gbf" % (above + 1)
    lst = os.listdir
    while time.perf_counter() < end:
        if want in lst(dbdir):
            return time.perf_counter()
    return None


def install_daemon(c, install, instance, **cfg):
    d = c.gs.Daemon(str(install), str(c.state), instance, **cfg)
    c.daemons.append(d)
    return d


def clone_install(src, dst):
    """A copy of an install made of hard links (jars are only read), so that ``Ghidra/patch`` of
    the copy can hold a test-only class without touching the install under test."""
    src, dst = pathlib.Path(src), pathlib.Path(dst)
    if dst.exists():
        shutil.rmtree(dst)
    for d, dirs, files in os.walk(src):
        rel = pathlib.Path(d).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for f in files:
            s, t = pathlib.Path(d) / f, dst / rel / f
            try:
                os.link(s, t)
            except OSError:
                shutil.copy2(s, t)
    (dst / "Ghidra" / "patch").mkdir(parents=True, exist_ok=True)


def lmbf_text():
    src = pathlib.Path(os.environ.get("E8_LMBF_SOURCE") or (REPO / LMBF_REL))
    if not src.is_file():
        raise dt.Fail(f"LocalManagedBufferFile.java not found at {src} (set E8_LMBF_SOURCE)")
    return src.read_text(encoding="utf-8")


def mutant_install(c, tag, variant, pause_ms=PAUSE_MS):
    """An install copy whose ``LocalManagedBufferFile`` waits ``pause_ms`` right after the rename.
    ``variant`` "keep": the source as it is; "strip": without the early ``saveFile.flush();``."""
    text = lmbf_text()
    anchor = "if (saveFile.renameFile(newFile)) {"
    dt.check(text.count(anchor) == 1, "the rename anchor is not unique in LocalManagedBufferFile")
    if variant == "strip":
        text = re.sub(r"^[ \t]*saveFile\.flush\(\);[ \t]*\r?\n", "", text, flags=re.M)
    text = text.replace(anchor, anchor + "\n\t\t\t\ttry { Thread.sleep(%d); } "
                        "catch (InterruptedException e) { }" % pause_ms)
    dst = c.work / f"inst-{tag}"
    # a hard-link clone needs the source on the same volume: --prepare (daemon_tests.py) leaves a copy of the install
    # in the seed directory, next to --work, so the clone is links instead of a copy of the whole install per test
    seeded = c.seed / "install" if getattr(c, "seed", None) else None
    clone_install(seeded if seeded and (seeded / "Ghidra").is_dir() else c.a.ghidra, dst)
    srcdir = c.work / f"mut-{tag}"
    if srcdir.exists():
        shutil.rmtree(srcdir)
    (srcdir / "db" / "buffers").mkdir(parents=True)
    f = srcdir / "db" / "buffers" / "LocalManagedBufferFile.java"
    f.write_text(text, encoding="utf-8")
    r = subprocess.run([jdk_tool("javac"), "-nowarn", "--release", "21", "-encoding", "UTF-8",
                        "-cp", install_jars(dst), "-d", str(dst / "Ghidra" / "patch"), str(f)],
                       capture_output=True, text=True)
    dt.check(r.returncode == 0, f"javac of the test-only class failed: {r.stdout}{r.stderr}")
    return dst


def prepare_save(c, install, instance, gpr):
    """Daemon on ``install`` with the fixture program open writable; returns (d, s, exe, fns)."""
    exe = pathlib.Path(c.a.exe).name
    d = install_daemon(c, install, instance, keepWarm=0)
    s = d.connect("e8", "e8-harness")
    s.call("open_project", path=str(gpr), writable=True)
    s.call("open_program", path=exe, writable=True)
    return d, s, exe, dt.code_functions(s, 3)


def reopen(c, install, instance, gpr, writable=False):
    """What a fresh daemon sees of the program: ({"ok", "names", "count"} or {"error"})."""
    exe = pathlib.Path(c.a.exe).name
    d = install_daemon(c, install, instance, keepWarm=0)
    try:
        with d.connect("e8-check", "e8-harness") as s:
            s.call("open_project", path=str(gpr), writable=writable)
            s.call("open_program", path=exe, writable=writable)
            names = dt.names_at(s)
            return {"ok": True, "names": names, "count": len(names)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:400]}
    finally:
        if d.jvm_alive():
            d.stop(force=True)


# ---- the window tests ---------------------------------------------------------------------

def window_case(c, tag, variant):
    inst = mutant_install(c, tag, variant)
    gpr = c.copy_fixture("e8" + tag)
    dbdir = program_db_dir(gpr)
    d, s, exe, fns = prepare_save(c, inst, "e8w" + tag, gpr)
    f0, f1 = fns[0], fns[1]
    before = dt.names_at(s)
    s.call("rename", address=f0, name="e8_acked")
    s.call("save", wait=120000)  # acknowledged (it also waits out the pause once)
    n0, _p = newest(dbdir)
    s.call("rename", address=f1, name="e8_inflight")
    s.send("save", wait=120000)
    t = wait_new_version(dbdir, n0)
    dt.check(t is not None, "the new version file never appeared")
    pid = d.read_endpoint()["pid"]
    kill_now(c, d, pid)
    nn, np_ = newest(dbdir)
    out = {"n0": n0, "newest": nn, "header_valid": has_magic(np_), "size": np_.stat().st_size,
           "first8": open(np_, "rb").read(8).hex()}
    out["reopen"] = reopen(c, inst, "e8r" + tag, gpr)
    out["before_f1"] = before[f1]
    out["f0"], out["f1"] = f0, f1
    return out


def t_flush_before_rename(c):
    """The window is held open (3 s between the rename and the rest of the save) and the daemon is
    killed inside it. Wanted: the newest version file already has its header and the project
    reopens with the acknowledged save and, at most, the one in flight."""
    o = window_case(c, "keep", "keep")
    names = o["reopen"].get("names", {})
    what = f"newest db.{o['newest']}.gbf first8={o['first8']}, reopen={o['reopen'].get('error', 'ok')}"
    dt.check(o["header_valid"], "the final-named version file has no header in the window: " + what)
    dt.check(o["reopen"]["ok"], "the project does not reopen after the kill: " + what)
    dt.check(names.get(o["f0"]) == "e8_acked", f"the acknowledged save is missing: {names.get(o['f0'])}")
    dt.check(names.get(o["f1"]) in (o["before_f1"], "e8_inflight"),
             f"unexpected state of the function in flight: {names.get(o['f1'])}")
    return f"killed in the window; db.{o['newest']}.gbf header valid, reopened, f1={names.get(o['f1'])}"


def t_window_control(c):
    """Control: without the early flush the same kill leaves an all-zero header, and Ghidra cannot
    open the project. If this does not reproduce, e8_flush_before_rename cannot fail."""
    o = window_case(c, "strip", "strip")
    what = f"newest db.{o['newest']}.gbf first8={o['first8']}, reopen={o['reopen'].get('error', 'ok')}"
    dt.check(not o["header_valid"] and o["first8"] == "00" * 8,
             "the harness did not reproduce the zero header: " + what)
    # without E8's open-time check the answer is "Unrecognized file format"; with it (the installed
    # jar) the same state is reported as corrupt_newest. Either way the project does not open.
    err = o["reopen"].get("error", "")
    dt.check(not o["reopen"]["ok"] and ("Unrecognized file format" in err or "corrupt_newest" in err),
             "the zero header did not make the project unopenable: " + what)
    return "reproduced: " + what


def t_sp5_idempotent(c):
    """SP5, daemon half: at the pause the early flush has run and the second one (setReadOnly) has
    not; the finished version file must equal the one seen in the pause, byte for byte.
    Two separate checks: (1) the header is already valid in the pause (this is the window check:
    it is what turns red on the unfixed source, where the first flush comes later); (2) the second
    flush changes nothing. The idempotence of ``flush()`` itself is also checked, independent of any
    window, by e8_version_chain (``flushIdem``)."""
    inst = mutant_install(c, "sp5", "keep", pause_ms=4000)
    gpr = c.copy_fixture("e8sp5")
    dbdir = program_db_dir(gpr)
    d, s, exe, fns = prepare_save(c, inst, "e8sp5", gpr)
    s.call("rename", address=fns[0], name="e8_sp5_a")
    s.call("save", wait=120000)
    n0, _ = newest(dbdir)
    s.call("rename", address=fns[1], name="e8_sp5_b")
    rid = s.send("save", wait=120000)
    t = wait_new_version(dbdir, n0)
    dt.check(t is not None, "the new version file never appeared")
    p = dbdir / ("db.%d.gbf" % (n0 + 1))
    time.sleep(0.5)  # inside the 4 s pause
    h_mid, size_mid = sha(p), p.stat().st_size
    dt.check(has_magic(p), f"window: db.{n0 + 1}.gbf has no header before the second flush "
                           f"({open(p, 'rb').read(8).hex()}); the idempotence cannot be judged")
    s.wait(rid)
    h_end, size_end = sha(p), p.stat().st_size
    dt.check(h_mid == h_end and size_mid == size_end,
             f"the second flush changed the file ({size_mid} -> {size_end} bytes)")
    s.call("rename", address=fns[2], name="e8_sp5_c")
    s.call("save", wait=120000)  # a further save on the saved file still works
    n2, _ = newest(dbdir)
    dt.check(n2 == n0 + 2, f"the version chain did not advance: {n0} -> {n2}")
    d.stop(force=True)
    r = reopen(c, c.a.ghidra, "e8sp5r", gpr)
    dt.check(r["ok"] and r["names"][fns[2]] == "e8_sp5_c", f"reopen after three saves: {r}")
    return f"the second flush left db.{n0 + 1}.gbf identical ({size_end} bytes); saves continue to db.{n2}"


# ---- the kill loop ------------------------------------------------------------------------

KILL_SHARDS = 4     # processes e8_kill_loop is split into by run_parallel.py (the kills add up)


def t_kill_loop(c):
    return _kill_loop(c, int(os.environ.get("E8_KILLS", "8")))


def _kill_shard(j):
    def run(c):
        first, kills = dt.split_n(int(os.environ.get("E8_KILLS", "8")), KILL_SHARDS)[j]
        return _kill_loop(c, kills, first) if kills else "no kill in this shard (E8_KILLS)"
    return run


def _kill_loop(c, kills, first=0):
    """``kills`` kills, numbered from ``first``: the number picks the timing (mixed mode alternates
    trigger- and send-timed by it), so shards that split 0..E8_KILLS-1 sample what the whole loop
    does, each on its own fixture copy, with its own calibration and the same checks."""
    seed = int(os.environ.get("E8_SEED", "8"))
    rnd = random.Random(seed if not first else seed * 7919 + first)
    # "trigger": kill a few ms after the new version file first appears (measurement C's method;
    # every kill is after the rename). "send": the timer starts when the save is sent, over the whole
    # save, so kills before the rename are sampled too. "mixed" (default): alternate.
    mode = os.environ.get("E8_KILL_MODE", "mixed")
    dt.check(mode in ("trigger", "send", "mixed"), f"E8_KILL_MODE {mode!r}")
    gpr = c.copy_fixture("e8loop")
    dbdir = program_db_dir(gpr)
    exe = pathlib.Path(c.a.exe).name
    ledger = None            # (function address, acked name, inflight name)
    stats = {"kills": 0, "no_trigger": 0, "zero_header": 0, "unopenable": 0, "wrong_state": 0,
             "landed": 0, "not_landed": 0, "before_rename": 0, "after_rename": 0}
    notes, gaps, pre_gaps = [], [], []
    # per timing phase: "send" starts the timer when the save request is sent (kills land before and
    # after the rename), "trigger" when db.N+1.gbf first appears (every kill is after the rename)
    phases = {p: {"kills": 0, "before_rename": 0, "after_rename": 0, "zero_header": 0}
              for p in ("send", "trigger")}
    calibrated = None
    base_count = None
    last = first + kills
    for it in range(first, last + 1):
        d = c.gs.Daemon(c.a.ghidra, str(c.state), "e8k%d" % it, keepWarm=0)
        c.daemons.append(d)
        try:
            s = d.connect("e8", "e8-harness")
            s.call("open_project", path=str(gpr), writable=True)
            s.call("open_program", path=exe, writable=True)
        except Exception as e:  # noqa: BLE001
            stats["unopenable"] += 1
            notes.append(f"it{it}: unopenable after the previous kill: {str(e)[:160]}")
            if d.jvm_alive():
                d.kill()
            shutil.rmtree(gpr.parent)
            gpr = c.copy_fixture("e8loop")
            dbdir = program_db_dir(gpr)
            ledger = None
            if it == last:
                break
            d = c.gs.Daemon(c.a.ghidra, str(c.state), "e8k%dr" % it, keepWarm=0)
            c.daemons.append(d)
            s = d.connect("e8", "e8-harness")
            s.call("open_project", path=str(gpr), writable=True)
            s.call("open_program", path=exe, writable=True)
        names = dt.names_at(s)
        base_count = base_count or len(names)
        if len(names) != base_count:
            stats["wrong_state"] += 1
            notes.append(f"it{it}: function count {len(names)} != {base_count}")
        if ledger:
            addr, acked, inflight = ledger
            stats["landed" if names.get(addr) == inflight else "not_landed"] += 1
            if names.get(addr) not in (acked, inflight):
                stats["wrong_state"] += 1
                notes.append(f"it{it}: {addr} is {names.get(addr)}, wanted {acked} or {inflight}")
        if it == last:
            d.stop(force=True)
            break
        addr = dt.code_functions(s, 1)[0]
        acked, inflight = "e8k%d_a" % it, "e8k%d_b" % it
        for _ in range(2 if calibrated is None else 1):
            n0, _p = newest(dbdir)
            s.call("rename", address=addr, name=acked)
            ts = time.perf_counter()
            rid = s.send("save", wait=120000)
            t = wait_new_version(dbdir, n0)
            s.wait(rid)
            if t is not None and calibrated is None:
                gaps.append((time.perf_counter() - t) * 1000)
                pre_gaps.append((t - ts) * 1000)
        if calibrated is None and len(gaps) >= 2:
            calibrated = max(1.0, min(statistics.median(gaps) * 1.5, 80.0))
            pre_cal = max(1.0, min(statistics.median(pre_gaps) * 1.5, 400.0))
        n0, _p = newest(dbdir)
        s.call("rename", address=addr, name=inflight)
        ledger = (addr, acked, inflight)
        pid = d.read_endpoint()["pid"]
        by_send = mode == "send" or (mode == "mixed" and it % 2 == 1)
        phase = phases["send" if by_send and calibrated is not None else "trigger"]
        ts = time.perf_counter()
        rid = s.send("save", wait=120000)
        if by_send and calibrated is not None:
            end = ts + rnd.uniform(0, pre_cal + calibrated) / 1000.0
            while time.perf_counter() < end:
                pass
        else:
            t = wait_new_version(dbdir, n0, timeout=20)
            if t is None:
                stats["no_trigger"] += 1
            else:
                end = t + rnd.uniform(0, calibrated or 5.0) / 1000.0
                while time.perf_counter() < end:
                    pass
        kill_now(c, d, pid)
        stats["kills"] += 1
        side = "after_rename" if (dbdir / ("db.%d.gbf" % (n0 + 1))).exists() else "before_rename"
        stats[side] += 1
        phase["kills"] += 1
        phase[side] += 1
        # the oracle (K2): every final-named version file has its magic
        for n, p in versions(dbdir).items():
            if not has_magic(p):
                stats["zero_header"] += 1
                phase["zero_header"] += 1
                notes.append(f"it{it}: db.{n}.gbf has no valid header "
                             f"({open(p, 'rb').read(8).hex()}, {p.stat().st_size} bytes)")
    c.timings["e8_kill_loop calibration (ms from the version file to the answer)"] = \
        round(calibrated or 0, 2)
    (c.work / ("e8_kill_loop.json" if not first else f"e8_kill_loop-{first}.json")).write_text(json.dumps({"stats": stats, "phases": phases,
                                                         "notes": notes,
                                                         "calibration_ms": calibrated}, indent=1))
    ph = "; ".join("%s-timed: %d kills (%d before, %d after the rename, %d zero headers)" % (
        k, v["kills"], v["before_rename"], v["after_rename"], v["zero_header"])
        for k, v in phases.items() if v["kills"])
    which = f" (#{first}-{last - 1})" if first or kills != int(os.environ.get("E8_KILLS", "8")) else ""
    msg = (f"{stats['kills']} kills{which}, mode {mode} ({stats['before_rename']} before and "
           f"{stats['after_rename']} after the rename; delay 0..{calibrated and round(calibrated, 1)} ms "
           f"after the new version file appeared, or over the save; {stats['no_trigger']} without trigger): "
           f"{stats['zero_header']} zero headers, {stats['unopenable']} unopenable, "
           f"{stats['wrong_state']} wrong states; the save in flight had landed in "
           f"{stats['landed']} and not in {stats['not_landed']} [{ph}]")
    dt.check(stats["zero_header"] == 0 and stats["unopenable"] == 0 and stats["wrong_state"] == 0,
             msg + "; " + "; ".join(notes[:4]))
    return msg


def save_times(c, install, tag, n=25):
    gpr = c.copy_fixture("e8time" + tag)
    d, s, exe, fns = prepare_save(c, install, "e8time" + tag, gpr)
    ms = []
    for i in range(n):
        s.call("rename", address=fns[i % 3], name="e8t_%s_%d" % (tag, i))
        t = time.perf_counter()
        s.call("save", wait=120000)
        ms.append((time.perf_counter() - t) * 1000)
    d.stop(force=True)
    return ms[2:]


def stat(ms):
    return statistics.median(ms), sorted(ms)[max(0, int(len(ms) * 0.95) - 1)]


def t_save_time(c):
    """Save latency (median and p95). With ``E8_BASE_INSTALL`` (an install built without E8) the
    same loop runs on both, interleaved (fixed, base, fixed, base) so drift cancels, and the test
    fails if the median of the installed build is more than ``E8_SAVE_TOLERANCE`` (default 0.25)
    above the base. ``E8_SAVE_MAX_MS`` is an absolute bound on the median. Without either, the
    numbers are recorded only, and the summary says so."""
    base = os.environ.get("E8_BASE_INSTALL")
    fixed, basev = [], []
    for rnd_ in range(2 if base else 1):
        fixed += save_times(c, c.a.ghidra, "f%d" % rnd_)
        if base:
            basev += save_times(c, base, "b%d" % rnd_)
    med, p95 = stat(fixed)
    c.timings["e8 save: median (ms)"] = round(med, 1)
    c.timings["e8 save: p95 (ms)"] = round(p95, 1)
    msg = f"save median {med:.1f} ms, p95 {p95:.1f} ms over {len(fixed)} saves"
    limit = os.environ.get("E8_SAVE_MAX_MS")
    if limit:
        dt.check(med <= float(limit), msg + f"; above the absolute bound {limit} ms")
    if base:
        bmed, bp95 = stat(basev)
        tol = float(os.environ.get("E8_SAVE_TOLERANCE", "0.25"))
        c.timings["e8 save base: median (ms)"] = round(bmed, 1)
        c.timings["e8 save base: p95 (ms)"] = round(bp95, 1)
        msg += f"; base median {bmed:.1f} ms, p95 {bp95:.1f} ms over {len(basev)} saves"
        dt.check(med <= bmed * (1 + tol), msg + f"; the median is more than {tol:.0%} above the base")
        return msg + f"; within {tol:.0%} of the base"
    return msg + "; no baseline given (E8_BASE_INSTALL): recorded, not compared"


# ---- Java probe: the version chain, the repair and the read-only open ------------------------

def probe(c, install, *args, props=()):
    """Runs the Java probe. It lives in package db.buffers (the buffer classes it drives are
    package-private) so it is compiled to a class folder and put on the class path."""
    pd = c.work / "e8probe"
    classes = pd / "classes"
    if not (classes / "db" / "buffers" / "E8Probe.class").is_file():
        src = pd / "src" / "db" / "buffers" / "E8Probe.java"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(PROBE, encoding="utf-8")
        classes.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([jdk_tool("javac"), "-nowarn", "--release", "21", "-encoding", "UTF-8",
                            "-cp", install_jars(install), "-d", str(classes), str(src)],
                           capture_output=True, text=True)
        dt.check(r.returncode == 0, f"javac of the probe failed: {r.stdout}{r.stderr}")
    r = subprocess.run([jdk_tool("java"), *props, "-cp", str(classes) + os.pathsep +
                        install_jars(install), "db.buffers.E8Probe", *map(str, args)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=300)
    line = [x for x in r.stdout.splitlines() if x.startswith("{")]
    if not line:
        raise dt.Fail(f"probe {args[0]} printed no result: {r.stdout[-400:]} {r.stderr[-600:]}")
    return json.loads(line[-1]), r.stderr


def t_version_chain(c):
    d = c.work / "e8chain"
    if d.exists():
        shutil.rmtree(d)
    o, _ = probe(c, c.a.ghidra, "make", d / "db", 5)
    dt.check(o["ok"] and o["chain"] and o["current"] == 6 and o["min"] == 1,
             f"the version chain of 6 versions is not intact: {o}")
    dt.check(o["flushIdem"], "a second flush() of the save file changed the file (SP5)")
    mics = sorted(o["saveMicros"])
    c.timings["e8 versioned saveCompleted: median (us)"] = mics[len(mics) // 2]
    return (f"flush() idempotent on all 5 saves; 6 versions saved, every one readable through the chain and equal to what was "
            f"written; saveCompleted median {mics[len(mics) // 2]} us")


def t_installed_jar(c):
    """The installed jar, not the source: ``saveCompleted`` of the ``LocalManagedBufferFile`` in the
    install under test calls ``flush`` before ``renameFile`` (javap bytecode order), the class comes
    from a jar rather than a ``Ghidra/patch`` folder, and ``VersionFileCheck`` is in the install.
    e8_flush_before_rename proves the same ordering for the source text only."""
    inst = pathlib.Path(c.a.ghidra)
    patch = inst / "Ghidra" / "patch"
    dt.check(not patch.is_dir() or not any(patch.rglob("*.class")),
             "the install has class files in Ghidra/patch: the jars are not what is loaded")
    cp = install_jars(inst)

    def javap(cls):
        r = subprocess.run([jdk_tool("javap"), "-c", "-p", "-cp", cp, cls],
                           capture_output=True, text=True)
        dt.check(r.returncode == 0, f"javap {cls}: {r.stdout[-200:]}{r.stderr[-300:]}")
        return r.stdout

    text = javap("db.buffers.LocalManagedBufferFile")
    m = re.search(r"\n[^\n]*void saveCompleted\(boolean\)[^\n]*\n(.*?)\n\n", text, re.S)
    dt.check(m, "saveCompleted(boolean) not found in the installed LocalManagedBufferFile")
    body = m.group(1)
    flush = [int(x.group(1)) for x in re.finditer(r"(\d+): invoke\w+\s+#\d+\s+// Method [^\s:]*flush:\(\)Z", body)]
    ren = [int(x.group(1)) for x in re.finditer(r"(\d+): invoke\w+\s+#\d+\s+// Method [^\s:]*renameFile:", body)]
    dt.check(flush and ren, f"flush/renameFile calls not found in saveCompleted: flush={flush} rename={ren}")
    dt.check(min(flush) < min(ren),
             f"installed saveCompleted: flush at bytecode {min(flush)} is not before renameFile at {min(ren)}")
    javap("ghidra.framework.store.db.VersionFileCheck")
    return f"installed jar: flush at bytecode {min(flush)} before renameFile at {min(ren)}; VersionFileCheck present"


def t_check_errors(c):
    """Failure handling of the open-time check, each on the all-zero-header fixture with the tree
    declared disposable: (1) a read-only open never repairs; (2) a newest version that cannot be
    quarantined (read-only file, quarantine folder blocked) answers corrupt_newest, not a raw
    IOException, and nothing moves; (3) a version file that cannot be read (Windows: held with no
    sharing) is an I/O error, not a corrupt file: nothing is quarantined."""
    notes = []

    def case(name, setup=None, ro=False, cleanup=None):
        root, db, n, _prev = zero_header_fixture(c, "e8err_" + name)
        bad = db / ("db.%d.gbf" % n)
        held = setup(db, bad, n) if setup else None
        h0 = None if name == "locked" else tree_hash(db)
        args = ["open", db] + (["ro"] if ro else [])
        try:
            o, _ = probe(c, c.a.ghidra, *args, props=[f"-Dhydra.storage.repairRoots={root}"])
        finally:
            if cleanup:
                cleanup(held, bad)
        dt.check(bad.exists() and not (db / (bad.name + ".quarantine") / bad.name).exists(),
                 f"{name}: the bad file was moved: {o}")
        if h0:
            dt.check(tree_hash(db) == h0, f"{name}: the tree changed")
        return o

    o = case("readonly", ro=True)
    dt.check(not o["opened"] and o["error"].startswith("corrupt_newest"), f"read-only open: {o}")
    notes.append("read-only open of a disposable tree: corrupt_newest, nothing moved")

    def make_file_readonly(db, bad, n):
        os.chmod(bad, 0o444)

    def restore(held, bad):
        os.chmod(bad, 0o666)

    o = case("rofile", setup=make_file_readonly, cleanup=restore)
    dt.check(not o["opened"] and o["error"].startswith("corrupt_newest"), f"read-only file: {o}")
    notes.append("read-only newest file: corrupt_newest, not moved")

    def block_quarantine(db, bad, n):
        (db / ("db.%d.gbf.quarantine" % n)).write_text("a file where the folder should be")

    o = case("blocked", setup=block_quarantine)
    dt.check(not o["opened"] and o["error"].startswith("corrupt_newest"), f"blocked quarantine: {o}")
    notes.append("quarantine folder blocked: corrupt_newest, not a raw IOException")

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        def lock(db, bad, n):
            h = k32.CreateFileW(str(bad), 0x80000000, 0, None, 3, 0x80, None)  # read, no sharing
            dt.check(h not in (None, 0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF), "could not lock the file")
            return h

        def unlock(h, bad):
            k32.CloseHandle(h)

        o = case("locked", setup=lock, cleanup=unlock)
        dt.check(not o["opened"] and "corrupt_newest" not in o["error"],
                 f"a file that cannot be read must be an I/O error, not corrupt_newest: {o}")
        notes.append("unreadable (locked) newest file: I/O error propagated, not quarantined")
    return "; ".join(notes)


def zero_header_fixture(c, name, saves=3):
    """A versioned database in the state of a kill inside the old window: db.N.gbf at full size with
    an all-zero header, db.N-1.gbf (the last acknowledged save) still there."""
    root = c.work / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    db = root / "db"
    o, _ = probe(c, c.a.ghidra, "make", db, saves)
    n = o["current"]
    # the probe kept db.N-1.gbf as prev.keep just before its last save; put it back
    shutil.move(str(db / "prev.keep"), str(db / ("db.%d.gbf" % (n - 1))))
    zero_header(db / ("db.%d.gbf" % n))
    return root, db, n, o["hashes"][n - 2]


def t_repair_open(c):
    root, db, n, prev = zero_header_fixture(c, "e8repair")
    ro = c.work / "e8repair_ro"
    if ro.exists():
        shutil.rmtree(ro)
    shutil.copytree(db, ro)
    # (1) a tree that is not declared disposable: corrupt_newest, nothing written
    h0 = tree_hash(ro)
    o, _ = probe(c, c.a.ghidra, "open", ro)
    h1 = tree_hash(ro)
    dt.check(not o["opened"] and o["error"].startswith("corrupt_newest"),
             f"a corrupt newest version in a read-only tree must answer corrupt_newest: {o}")
    dt.check(h0 == h1, f"the read-only open wrote to the tree: {h0} -> {h1}")
    # (2) a writable disposable tree: opens at N-1, logs the repair, quarantines the bad file
    o, err = probe(c, c.a.ghidra, "open", db, props=[f"-Dhydra.storage.repairRoots={root}"])
    dt.check(o.get("opened") and o["current"] == n - 1 and o["hash"] == prev,
             f"the disposable tree did not open at {n - 1} with its content: {o}")
    q = db / ("db.%d.gbf.quarantine" % n) / ("db.%d.gbf" % n)
    dt.check(q.is_file() and not (db / ("db.%d.gbf" % n)).exists(),
             "the bad file was not moved to quarantine")
    dt.check(len(o["repairs"]) == 1 and o["repairs"][0].startswith("REPAIRED") and
             f"newest={n} fallback={n - 1}" in o["repairs"][0],
             f"the repair is not recorded in VersionFileCheck.repairs(): {o}")
    return (f"zero-header db.{n}.gbf: read-only tree answered corrupt_newest with the tree hash "
            f"unchanged ({h0[1]} files); disposable tree opened at {n - 1}, file in quarantine, "
            f"repair logged")


def t_private_open(c):
    """A fork through the daemon: db.N+1.gbf made zero-header next to an intact db.N.gbf. The fork
    is a private database; it opens through LocalDatabaseItem, which carries the VersionFileCheck hook."""
    gpr = c.copy_fixture("e8priv")
    dbdir = program_db_dir(gpr)
    n, p = newest(dbdir)
    bad = dbdir / ("db.%d.gbf" % (n + 1))
    shutil.copy2(p, bad)
    zero_header(bad)
    vm =[f"-Dhydra.storage.repairRoots={c.work}"]
    exe = pathlib.Path(c.a.exe).name
    d = c.gs.Daemon(c.a.ghidra, str(c.state), "e8priv", keepWarm=0, vmargs=vm)
    c.daemons.append(d)
    try:
        with d.connect("e8", "e8-harness") as s:
            s.call("open_project", path=str(gpr), writable=True)
            s.call("open_program", path=exe, writable=True)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "Unrecognized file format" in msg:
            raise dt.PremiseFail("the fork's open path does not check the newest version: " + msg[:200],
                                 {"error": msg[:300]})
        raise dt.Fail(msg)
    finally:
        if d.jvm_alive():
            d.stop(force=True)
    dt.check((dbdir / ("db.%d.gbf.quarantine" % (n + 1))).is_dir(), "no quarantine folder")
    log = pathlib.Path(c.state) / "e8priv.log"
    text = log.read_text(errors="replace") if log.exists() else ""
    dt.check(f"db.{n + 1}.gbf has no valid header (interrupted save); moved to" in text and
             f"db.{n}.gbf is the newest version again" in text,
             f"the repair is not in the daemon log {log}")
    return f"the fork opened at db.{n}.gbf; db.{n + 1}.gbf is in quarantine; repair logged"


def t_private_readonly(c):
    """The same zero-header fork opened read-only writes nothing (tree hash before and after),
    with and without the tree being declared disposable, and answers corrupt_newest."""
    gpr = c.copy_fixture("e8ro")
    dbdir = program_db_dir(gpr)
    n, p = newest(dbdir)
    bad = dbdir / ("db.%d.gbf" % (n + 1))
    shutil.copy2(p, bad)
    zero_header(bad)
    exe = pathlib.Path(c.a.exe).name
    out = []
    for tag, vm in (("plain", []), ("declared disposable", [f"-Dhydra.storage.repairRoots={c.work}"])):
        h0 = tree_hash(gpr.parent)
        d = c.gs.Daemon(c.a.ghidra, str(c.state), "e8ro" + tag[:1], keepWarm=0, vmargs=vm)
        c.daemons.append(d)
        err = ""
        try:
            with d.connect("e8", "e8-harness") as s:
                s.call("open_project", path=str(gpr), writable=False)
                s.call("open_program", path=exe, writable=False)
        except Exception as e:  # noqa: BLE001
            err = str(e)
        finally:
            if d.jvm_alive():
                d.stop(force=True)
        h1 = tree_hash(gpr.parent)
        if "corrupt_newest" not in err:
            if "Unrecognized file format" in err and h0 == h1:
                raise dt.PremiseFail("the read-only open reads the zero header and reports "
                                     "Unrecognized file format: " + err[:160], {"error": err[:300]})
            raise dt.Fail(f"{tag}: read-only open: {err or 'it opened'}")
        dt.check(h0 == h1, f"{tag}: the read-only open wrote to the tree")
        dt.check(bad.exists() and not (dbdir / (bad.name + ".quarantine")).exists(),
                 f"{tag}: the bad file was moved by a read-only open")
        out.append(f"{tag}: corrupt_newest, {h0[1]} files unchanged")
    return "; ".join(out)


def t_item_readonly(c):
    """E8b: a LocalDatabaseItem of a read-only file system never repairs, whatever the repair
    policy says. The tree is declared disposable (the policy would allow a repair), the newest
    version has a zero header: the read-only item must answer corrupt_newest and write nothing;
    the same tree opened writable repairs and opens at version 1. Both kinds of item: versioned
    (the VersionedDatabase got the file system's read-only flag) and private."""
    notes = []
    for kind in ("versioned", "private"):
        root = c.work / ("e8item_" + kind)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        fs = root / "fs"
        extra = ["priv"] if kind == "private" else []
        o, _ = probe(c, c.a.ghidra, "itemmake", fs, *extra)
        dt.check(o["ok"], f"{kind}: itemmake: {o}")
        gbfs = sorted(fs.rglob("db.1.gbf"))
        dt.check(len(gbfs) == 1, f"{kind}: expected one db.1.gbf: {gbfs}")
        db1 = gbfs[0]
        db2 = db1.with_name("db.2.gbf")
        shutil.copy2(db1, db2)
        zero_header(db2)
        props = [f"-Dhydra.storage.repairRoots={root}"]
        h0 = tree_hash(fs)
        o, _ = probe(c, c.a.ghidra, "itemopen", fs, "ro", *(["priv"] if extra else []), props=props)
        dt.check(not o["opened"] and o["error"].startswith("corrupt_newest"),
                 f"{kind}: a read-only item with a bad newest version must answer corrupt_newest: {o}")
        dt.check(tree_hash(fs) == h0, f"{kind}: the read-only item changed the tree")
        dt.check(db2.exists() and not db2.with_name("db.2.gbf.quarantine").exists(),
                 f"{kind}: the bad newest version was moved by a read-only item")
        o, _ = probe(c, c.a.ghidra, "itemopen", fs, "rw", *(["priv"] if extra else []), props=props)
        dt.check(o.get("opened") and o["current"] == 1,
                 f"{kind}: the writable item did not repair and open at 1: {o}")
        dt.check((db2.with_name("db.2.gbf.quarantine") / "db.2.gbf").is_file(),
                 f"{kind}: the writable open did not quarantine")
        notes.append(f"{kind}: read-only item answered corrupt_newest with {h0[1]} files unchanged, "
                     f"the writable item repaired and opened at version 1")
    return "; ".join(notes)


TESTS = {
    "e8_flush_before_rename": t_flush_before_rename,
    "e8_window_control": t_window_control,
    "e8_sp5_flush_idempotent": t_sp5_idempotent,
    "e8_kill_loop": t_kill_loop,
    "e8_save_time": t_save_time,
    "e8_version_chain": t_version_chain,
    "e8_repair_open": t_repair_open,
    "e8_installed_jar": t_installed_jar,
    "e8_check_errors": t_check_errors,
    "e8_private_open": t_private_open,
    "e8_private_readonly": t_private_readonly,
    "e8_item_readonly": t_item_readonly,
}

BASELINE = {}   # e8_private_open and e8_private_readonly are enforced since LocalDatabaseItem is in E8's ownership (8.1)

#: e8_kill_loop as KILL_SHARDS processes for run_parallel.py: the E8_KILLS kills split by number (the
#: shards' kills add up to E8_KILLS; each kill is checked the same way, each shard reopens after its
#: last kill). The window tests hold a designed 3-4 s pause inside the save and are not split.
SHARDS = {"e8_kill_loop": {f"k{j}": _kill_shard(j) for j in range(KILL_SHARDS)}}
