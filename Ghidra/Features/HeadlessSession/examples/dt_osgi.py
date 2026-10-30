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
"""Script loads while an analysis compiles a script (G-SOAK 9.17 pr-vf/pr-vf2 finding B, GATE9).

The finding. During a client's ``analyze`` the Windows resource analyzer loads a script
(``WindowsResourceReferenceAnalyzer.runScript`` -> ``JavaScriptProvider.getScriptInstance``); the
``script`` requests of other clients at that moment failed ``script did not load: Unexpected error:
java.nio.channels.OverlappingFileLockException`` (8 in pr-vf2, 10 in pr-vf).

The mechanism. ``getScriptInstance`` holds ``OSGiParallelLock`` (a FileChannel lock on
``<settings>/osgi/parallel.lock``, against other Ghidra processes) while it builds and loads the
script. A FileChannel lock belongs to the whole JVM: a second thread of the same JVM that asks for
it while it is held, or while another thread waits for it, gets ``OverlappingFileLockException``
at once. The daemon serialises its own script loads (``ScriptCommands.SCRIPT_COMPILE``), but an
analyzer loads outside that. The fix: the threads of one JVM take an in-JVM lock keyed by the lock
file first, and only the outermost holder takes the file lock (``OSGiParallelLock``).

Deterministic, external injection (D22/D48, no test code in the jar): this test process holds the
daemon's ``parallel.lock`` with an OS lock (another Ghidra process, as far as the daemon can tell).
The analysis's script load then waits for it, seen in a thread dump (``jcmd Thread.print``):
analysis frames under ``OSGiParallelLock.<init>``. Then 8 clients load scripts at once. Before the
fix the first of them fails at once with the exception; with it, the load waits (seen in the dump
parked in ``OSGiParallelLock.<init>``). Then the hold is released and everything must complete.

Tests
-----
* ``osgi_lock_analysis``  the installed build: with the analysis's script load waiting for the
  lock, 8 concurrent script loads wait as well; after the release the analysis and every load
  succeed and the daemon log has no ``OverlappingFileLockException``.
* ``osgi_lock_control_unfixed``  a copy of the install whose ``Ghidra/patch`` holds
  ``OSGiParallelLock`` without the in-JVM lock: the same scenario must make a load fail with
  ``OverlappingFileLockException`` (the soak's message). It proves the test above can fail.

Environment: ``GHIDRA_SESSION_JAVA_HOME`` / ``JAVA_HOME`` (the JDK: ``jcmd``, and ``javac`` for the
control's patched copy).
"""
import os
import pathlib
import subprocess
import threading

import daemon_tests as dt
import dt_e8 as e8

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
LOADERS = 8

LOCK_REL = "Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/osgi/OSGiParallelLock.java"
#: the fix, each as (the fixed text, the text that undoes it)
STRIP = [("\t\tl.lock();\n\t\tinJvm = l;\n\t\tif (l.getHoldCount() > 1) {", "\t\tinJvm = l;\n\t\tif (false) {"),
         ("\t\t\tl.unlock();", "\t\t\t// unfixed: no in-JVM lock")]

LOAD = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class OsgiLoad%d extends GhidraScript {
    @Override protected void run() throws Exception {
        println("loaded %d");
    }
}
"""


class OsLock:
    """An OS lock on a file, held by this process (what another Ghidra process holds): Windows
    ``LockFileEx`` through ``msvcrt.locking`` (one byte at 0 overlaps Java's whole-file lock), else
    ``fcntl.lockf``. Never waits: ``acquire`` is True or False."""

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.f = None

    def acquire(self):
        f = open(self.path, "a+b")
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self.f = f
        return True

    def release(self):
        f, self.f = self.f, None
        if f is None:
            return
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.lockf(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def unfixed_install(c, tag):
    """A hard-link copy of the install whose ``Ghidra/patch`` holds this checkout's
    ``OSGiParallelLock`` without the in-JVM lock (the technique of ``dt_hh.unfixed_install``)."""
    dst = c.work / f"inst-{tag}"
    seeded = c.seed / "install" if getattr(c, "seed", None) else None
    e8.clone_install(seeded if seeded and (seeded / "Ghidra").is_dir() else c.a.ghidra, dst)
    text = (REPO / LOCK_REL).read_text(encoding="utf-8")
    for fixed, undone in STRIP:
        dt.check(text.count(fixed) == 1, f"the GATE9 anchor {fixed!r} is not unique in {LOCK_REL}")
        text = text.replace(fixed, undone)
    f = c.work / f"src-{tag}" / LOCK_REL.split("/src/main/java/")[1]
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")
    r = subprocess.run([e8.jdk_tool("javac"), "-nowarn", "--release", "21", "-encoding", "UTF-8",
                        "-cp", e8.install_jars(dst), "-d", str(dst / "Ghidra" / "patch"), str(f)],
                       capture_output=True, text=True, timeout=600)
    dt.check(r.returncode == 0, f"javac of the unfixed class failed: {r.stdout}{r.stderr}")
    return dst


def thread_dump(pid):
    """The daemon JVM's threads, one block of text each."""
    r = subprocess.run([e8.jdk_tool("jcmd"), str(pid), "Thread.print"], capture_output=True,
                       text=True, timeout=60)
    return [b for b in r.stdout.replace("\r\n", "\n").split("\n\n") if b.strip()]


def in_lock(blocks, *marks):
    """The thread blocks under ``OSGiParallelLock.<init>`` that contain every mark."""
    return [b for b in blocks if "OSGiParallelLock.<init>" in b and all(m in b for m in marks)]


def lock_file(c, instance):
    """The daemon's ``osgi/parallel.lock`` (its own settings dir, ``<state>/settings/<instance>``)."""
    root = c.state / "settings" / instance
    found = [p for p in root.rglob("parallel.lock") if p.parent.name == "osgi"]
    dt.check(len(found) == 1, f"no single osgi/parallel.lock under {root}: {found} (settingsDir "
                              f"shared? the test needs the daemon's own)")
    return found[0]


def attempt(fn):
    try:
        return "ok", fn()
    except Exception as ex:  # noqa: BLE001
        return getattr(ex, "code", type(ex).__name__), str(ex)[:300]


def scenario(c, d, instance):
    """The analysis's script load waits for the lock held by this process; LOADERS clients load
    scripts meanwhile; the hold ends. Returns what happened."""
    gpr = c.copy_fixture("osgi" + instance)
    exe = pathlib.Path(c.a.exe).name
    for i in range(LOADERS):
        (c.scripts / f"OsgiLoad{i}.java").write_text(LOAD % (i, i))
    O = d.connect("osgi-owner", "osgi")
    loaders = [d.connect(f"osgi-load{i}", "osgi") for i in range(LOADERS)]
    hold = None
    out = {"loads": [None] * LOADERS}
    try:
        O.call("open_project", path=str(gpr), writable=True)
        O.call("open_program", path=exe, writable=True)
        # the OSGi framework is up and the lock file exists (a load takes the lock)
        loaders[0].call("script", script=c.script("TestSleep.java"), program=None, args=["10"],
                        wait=120000)
        pid = d.read_endpoint()["pid"]
        hold = OsLock(lock_file(c, instance))
        dt.wait_for(hold.acquire, "the OS lock on the daemon's parallel.lock", 30, 0.1)
        aid = O.send("analyze", wait=600000, parallel=True)
        waiting = dt.wait_for(lambda: in_lock(thread_dump(pid), "AutoAnalysisManager"),
                              "the analysis's script load to wait for the held lock", 300, 0.2)
        out["analyzer"] = "FileChannelImpl.lock" in waiting[0] or "FileDispatcherImpl.lock" in waiting[0]
        bar = threading.Barrier(LOADERS)

        def load(i):
            bar.wait()
            out["loads"][i] = attempt(lambda: loaders[i].call(
                "script", script=c.script(f"OsgiLoad{i}.java"), program=None, wait=300000))

        ts = [threading.Thread(target=load, args=(i,), daemon=True) for i in range(LOADERS)]
        for t in ts:
            t.start()
        # a load either answered (before the fix: at once, failed) or waits in the lock (the fix)
        seen = dt.wait_for(
            lambda: ("answered" if any(x is not None for x in out["loads"]) else None) or
                    ("parked" if in_lock(thread_dump(pid), "ScriptCommands.runScript", "ReentrantLock")
                     else None),
            "a script load to answer or to wait in the lock", 120, 0.2)
        out["seen"] = seen
        # still waiting? the analysis must not have got the lock meanwhile (this process holds it)
        out["analyzerStillWaiting"] = bool(in_lock(thread_dump(pid), "AutoAnalysisManager"))
        hold.release()
        hold = None
        for t in ts:
            t.join(300)
        out["analysis"] = attempt(lambda: O.wait(aid))
        out["log"] = dt_log(d)
        return out
    finally:
        if hold is not None:
            hold.release()
        for s in [O, *loaders]:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


def dt_log(d):
    try:
        return d.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---- the tests --------------------------------------------------------------------------------

def t_lock_analysis(c):
    """Script loads during an analysis's script load wait for it instead of failing."""
    d = c.daemon("osgi-a")
    try:
        r = scenario(c, d, "osgi-a")
    finally:
        d.stop(force=True)
    loads = r["loads"]
    bad = [(i, x) for i, x in enumerate(loads) if x is None or x[0] != "ok"]
    dt.check(r["seen"] == "parked" and r["analyzerStillWaiting"],
             f"no load waited in the lock while the analysis waited for it (seen {r['seen']}, "
             f"analysis still waiting {r['analyzerStillWaiting']}): {bad}")
    dt.check(not bad, f"{len(bad)} of {LOADERS} script loads failed during the analysis's script "
                      f"load: {bad[:3]}")
    dt.check(r["analysis"][0] == "ok", f"the analysis failed: {r['analysis']}")
    dt.check("OverlappingFileLockException" not in r["log"],
             "the daemon log has an OverlappingFileLockException")
    dt.check("GhidraScriptLoadException" not in r["log"],
             "the daemon log has a GhidraScriptLoadException (the analyzer's script did not load)")
    return (f"the analysis's script load waited for the held parallel.lock (in the OS lock: "
            f"{r['analyzer']}); {LOADERS} concurrent loads waited in the in-JVM lock, then all "
            f"succeeded, the analysis too; no OverlappingFileLockException in the log")


def t_control_unfixed(c):
    """Without the in-JVM lock a script load during the analysis's script load must fail with
    OverlappingFileLockException (the soak's finding)."""
    inst = unfixed_install(c, "osgiU")
    d = e8.install_daemon(c, inst, "osgi-u")
    try:
        r = scenario(c, d, "osgi-u")
    finally:
        d.stop(force=True)
    failed = [x for x in r["loads"] if x is not None and x[0] != "ok"]
    dt.check(r["seen"] == "answered" and
             any("OverlappingFileLockException" in x[1] for x in failed),
             f"control: no load failed with OverlappingFileLockException (seen {r['seen']}): "
             f"{r['loads']}")
    return (f"unfixed class: {len(failed)} of {LOADERS} loads failed "
            f"({failed[0][1][:90]}); the analysis {r['analysis'][0]}; red as it must be")


TESTS = {
    "osgi_lock_analysis": t_lock_analysis,
    "osgi_lock_control_unfixed": t_control_unfixed,
}
