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
  C: kill a few ms after the new version file first appears) of a daemon that saves in a loop; every
  newest version file has its magic and the project reopens, writable, with the last acknowledged
  save or the one in flight. ``E8_KILLS`` sets the count (default 8; the counted batches of 9.15
  run it with 200 on NTFS and on ReFS by pointing ``--work`` at the volume).
* ``e8_save_time``  save latency (median and p95) of the installed build, recorded in the timings.
* ``e8_version_chain``  SP5, the Java half: a versioned database saved several times keeps every
  older version readable and identical to what was written (the version chain and the buffer
  index), with the early flush in place.
* ``e8_repair_open``  the all-zero-header fixture (the state ``crash-C`` kept): a writable
  disposable tree opens at ``N-1``, logs a repair and quarantines (never deletes) the bad file; a
  tree that is not declared disposable answers ``corrupt_newest`` and **is not written** (tree hash
  before and after).
* ``e8_private_open`` and ``e8_private_readonly`` (**baseline**, expected to fail until a hook is
  added outside E8's files): the same fixture through the daemon on a fork. A fork is a
  non-versioned (private) database, which opens through ``LocalDatabaseItem`` and
  ``PrivateDatabase``/``Database``; PROTOCOL-3.md 8.1 gives E8 ``VersionedDatabase`` only, which a
  fork never uses. Today they fail with the signature "Unrecognized file format". With the
  three-line hook in ``LocalDatabaseItem`` (calling ``VersionFileCheck.repairOnOpen`` in the
  constructor and ``requireIntact`` in the three ``open`` methods and ``openForUpdate``) the first
  opens the fork at ``N-1`` and finds the bad file in quarantine, and the second answers
  ``corrupt_newest`` for a read-only open, declared disposable or not, with the tree hash
  unchanged. Both then leave BASELINE.

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
                db.getMinimumVersion() + ",\"chain\":" + chain + ",\"saveMicros\":" + ms +
                ",\"hashes\":" + quote(expected) + "}");
        }
        else if (mode.equals("open")) {
            try {
                VersionedDatabase db = new VersionedDatabase(dir, L);
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
    clone_install(c.a.ghidra, dst)
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
    dt.check(not o["reopen"]["ok"] and "Unrecognized file format" in o["reopen"]["error"],
             "the zero header did not make the project unopenable: " + what)
    return "reproduced: " + what


def t_sp5_idempotent(c):
    """SP5, daemon half: at the pause the early flush has run and the second one (setReadOnly) has
    not; the finished version file must equal the one seen in the pause, byte for byte."""
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

def t_kill_loop(c):
    kills = int(os.environ.get("E8_KILLS", "8"))
    rnd = random.Random(int(os.environ.get("E8_SEED", "8")))
    gpr = c.copy_fixture("e8loop")
    dbdir = program_db_dir(gpr)
    exe = pathlib.Path(c.a.exe).name
    ledger = None            # (function address, acked name, inflight name)
    stats = {"kills": 0, "no_trigger": 0, "zero_header": 0, "unopenable": 0, "wrong_state": 0,
             "landed": 0, "not_landed": 0}
    notes, gaps = [], []
    calibrated = None
    base_count = None
    for it in range(kills + 1):
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
            if it == kills:
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
        if it == kills:
            s.close() if hasattr(s, "close") else None
            d.stop(force=True)
            break
        addr = dt.code_functions(s, 1)[0]
        acked, inflight = "e8k%d_a" % it, "e8k%d_b" % it
        for _ in range(2 if calibrated is None else 1):
            n0, _p = newest(dbdir)
            s.call("rename", address=addr, name=acked)
            rid = s.send("save", wait=120000)
            t = wait_new_version(dbdir, n0)
            s.wait(rid)
            if t is not None and calibrated is None:
                gaps.append((time.perf_counter() - t) * 1000)
        if calibrated is None and len(gaps) >= 2:
            calibrated = max(1.0, min(statistics.median(gaps) * 1.5, 80.0))
        n0, _p = newest(dbdir)
        s.call("rename", address=addr, name=inflight)
        ledger = (addr, acked, inflight)
        rid = s.send("save", wait=120000)
        t = wait_new_version(dbdir, n0, timeout=20)
        pid = d.read_endpoint()["pid"]
        if t is None:
            stats["no_trigger"] += 1
        else:
            delay = rnd.uniform(0, calibrated or 5.0) / 1000.0
            end = t + delay
            while time.perf_counter() < end:
                pass
        kill_now(c, d, pid)
        stats["kills"] += 1
        # the oracle (K2): every final-named version file has its magic
        for n, p in versions(dbdir).items():
            if not has_magic(p):
                stats["zero_header"] += 1
                notes.append(f"it{it}: db.{n}.gbf has no valid header "
                             f"({open(p, 'rb').read(8).hex()}, {p.stat().st_size} bytes)")
    c.timings["e8_kill_loop calibration (ms from the version file to the answer)"] = \
        round(calibrated or 0, 2)
    (c.work / "e8_kill_loop.json").write_text(json.dumps({"stats": stats, "notes": notes,
                                                         "calibration_ms": calibrated}, indent=1))
    msg = (f"{stats['kills']} trigger-timed kills (delay 0..{calibrated and round(calibrated, 1)} ms "
           f"after the new version file appeared; {stats['no_trigger']} without trigger): "
           f"{stats['zero_header']} zero headers, {stats['unopenable']} unopenable, "
           f"{stats['wrong_state']} wrong states; the save in flight had landed in "
           f"{stats['landed']} and not in {stats['not_landed']}")
    dt.check(stats["zero_header"] == 0 and stats["unopenable"] == 0 and stats["wrong_state"] == 0,
             msg + "; " + "; ".join(notes[:4]))
    return msg


def t_save_time(c):
    gpr = c.copy_fixture("e8time")
    d, s, exe, fns = prepare_save(c, c.a.ghidra, "e8time", gpr)
    ms = []
    for i in range(25):
        s.call("rename", address=fns[i % 3], name="e8t_%d" % i)
        t = time.perf_counter()
        s.call("save", wait=120000)
        ms.append((time.perf_counter() - t) * 1000)
    d.stop(force=True)
    ms = ms[2:]
    med, p95 = statistics.median(ms), sorted(ms)[int(len(ms) * 0.95) - 1]
    c.timings["e8 save: median (ms)"] = round(med, 1)
    c.timings["e8 save: p95 (ms)"] = round(p95, 1)
    return f"save median {med:.1f} ms, p95 {p95:.1f} ms over {len(ms)} saves"


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
                       capture_output=True, text=True, timeout=300)
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
    mics = sorted(o["saveMicros"])
    c.timings["e8 versioned saveCompleted: median (us)"] = mics[len(mics) // 2]
    return (f"6 versions saved, every one readable through the chain and equal to what was "
            f"written; saveCompleted median {mics[len(mics) // 2]} us")


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
    is a private database; its open path has no VersionFileCheck hook inside E8's files."""
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
    return f"the fork opened at db.{n}.gbf; db.{n + 1}.gbf is in quarantine"


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


TESTS = {
    "e8_flush_before_rename": t_flush_before_rename,
    "e8_window_control": t_window_control,
    "e8_sp5_flush_idempotent": t_sp5_idempotent,
    "e8_kill_loop": t_kill_loop,
    "e8_save_time": t_save_time,
    "e8_version_chain": t_version_chain,
    "e8_repair_open": t_repair_open,
    "e8_private_open": t_private_open,
    "e8_private_readonly": t_private_readonly,
}

BASELINE = {
    "e8_private_open": "a fork (a private database) opens through PrivateDatabase/Database, which "
                       "have no VersionFileCheck hook (E8 owns VersionedDatabase only, 8.1)",
    "e8_private_readonly": "the same open path: a read-only open of a zero-header fork reports "
                           "Unrecognized file format, not corrupt_newest",
}
