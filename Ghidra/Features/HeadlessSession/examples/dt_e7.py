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
"""The killable script worker (PROTOCOL-3.md D47 and D64, package E7; the E7 items of gate 9.14).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only e7_edited_view,...

All of these ask for protocol 3. ``script`` with ``isolation:"worker"`` runs the script in a child
JVM on a private, writable, disposable clone of the SAVED view.

* ``e7_edited_view`` (the 9.14 test, on an EDITED view): an edit is applied and left unsaved; the
  engine refuses the worker (``conflict``, ``details.reason:"unsaved"``, ``next:{cmd:"save"}``) and
  starts none; after the owner's one save the script SEES the edit (the unedited name, a stale read,
  fails the test); ``attemptedChanges`` of a mutating run is measured on the clone and the view is
  byte-for-byte unchanged; a deaf script (ignores cancel and interrupt) is killed at its timeout,
  its slot and its owner's long cap are released, the clone is deleted, no worker is left; the save
  is counted (one). The control leg shows the premise (BP13): the same deaf script run in process
  ends long after its timeout.
* ``e7_unedited_view``: the variant on an unedited view must not save; a read-only second client and
  a project-level script (no program) work; ``shared`` runs stay in process (RusticQuery).
* ``e7_kill_by_hand``: a worker killed by hand fails that one request (``worker_died``) and the next
  works.
* ``e7_daemon_kill`` (K7): a daemon kill leaves no worker, also a suspended one (the daemon's Job
  Object, E9); the no-job control leaves the suspended worker alive (so the test proves the job),
  and a running worker of a job-less daemon ends by itself when its pipe closes.
* ``e7_client_disconnect``: the worker of a client that dies is killed and its slot is free.
* ``e7_cancel_cap``: ``maxWorkers`` refuses a further worker ``busy`` (``worker_capacity``); a
  client's ``cancel`` kills the worker.
* ``e7_heap``: a script that runs the worker out of heap ends only the worker (``worker_heap``).
* ``e7_validation``: ``save`` with a worker, an overlay with a worker, a pinned digest, a protocol 2
  client.
* ``e7_sweep``: a folder a dead daemon left is swept, a live process's folder is not.
* ``e7_cost``: the start-up and RAM cost of a worker (SP10) is recorded and held to its budget; four
  workers at once all succeed.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import sys
import threading
import time

import daemon_tests as dt

try:
    import dt_baseline as bl
except ImportError:  # loaded by path (daemon_tests.load_dt) before dt_baseline was registered
    import importlib.util
    _p = pathlib.Path(__file__).resolve().parent / "dt_baseline.py"
    _spec = importlib.util.spec_from_file_location("dt_baseline", _p)
    bl = importlib.util.module_from_spec(_spec)
    sys.modules["dt_baseline"] = bl
    _spec.loader.exec_module(bl)

HERE = pathlib.Path(__file__).resolve().parent
HOOKS = ["-Dghidra.session.testHooks=true"]
NO_JOB = HOOKS + ["-Dghidra.session.noProcessJob=true"]
EDIT = "e7_edited_name"

#: SP10 (D:/Projects/Hydra/_logs/spikes/SP10): single worker to script, small project, loaded 5.7 s and
#: calm 3.2 s; KotOR loaded 6.4 s and calm 4.3 s; 350 to 450 MB resident, peak 557 MB. The budget of the
#: gate is twice the loaded figure for the small fixture and the peak figure plus margin for RAM.
BUDGET_START_MS = 12_000
BUDGET_WORKING_SET_MB = 650

NAME = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E7Name extends GhidraScript {
    @Override protected void run() throws Exception {
        println("name " + currentProgram.getFunctionManager().getFunctions(true).next().getName());
    }
}
"""
MUTATE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
public class E7Mutate extends GhidraScript {
    @Override protected void run() throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctions(true).next();
        String was = f.getName();
        f.setName("e7_mutated", SourceType.USER_DEFINED);
        println("renamed " + was + " to " + f.getName());
    }
}
"""
DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E7Deaf extends GhidraScript {
    @Override protected void run() throws Exception {
        println("deaf-start " + (currentProgram == null ? "none"
            : currentProgram.getFunctionManager().getFunctions(true).next().getName()));
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // ignores cancel and interrupt
            }
        }
        println("deaf-done");
    }
}
"""
PROJECT = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
public class E7Project extends GhidraScript {
    @Override protected void run() throws Exception {
        for (DomainFile f : state.getProject().getProjectData().getRootFolder().getFiles()) {
            println("file " + f.getName());
        }
    }
}
"""
ALLOC = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E7Alloc extends GhidraScript {
    @Override protected void run() throws Exception {
        java.util.ArrayList<byte[]> keep = new java.util.ArrayList<>();
        for (;;) {
            keep.add(new byte[8 << 20]);
            println("allocated " + (keep.size() * 8) + " MB");
        }
    }
}
"""


# ---- helpers --------------------------------------------------------------------------------

def chaos():
    try:
        import chaos_lib
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("chaos_lib", HERE / "chaos_lib.py")
        chaos_lib = importlib.util.module_from_spec(spec)
        sys.modules["chaos_lib"] = chaos_lib
        spec.loader.exec_module(chaos_lib)
    return chaos_lib


def windows_only():
    if os.name != "nt":
        raise dt.Skipped("Windows only (Job Objects, NtSuspendProcess)")


def prepare(c):
    exe = bl.prepare(c)
    for n, text in (("E7Name.java", NAME), ("E7Mutate.java", MUTATE), ("E7Deaf.java", DEAF),
                    ("E7Project.java", PROJECT), ("E7Alloc.java", ALLOC)):
        (c.scripts / n).write_text(text)
    return exe


def session(c, d, gpr, exe, name, writable=False, protocol=3, program=True):
    s = c.connect(d, name, "e7", protocol)
    s.call("open_project", path=str(gpr), writable=writable)
    if program:
        if writable:
            s.call("open_program", path=exe, writable=True)
        else:
            s.call("open_program", path=exe)
    return s


def close_all(*sessions):
    for s in sessions:
        with contextlib.suppress(Exception):
            if s is not None:
                s.close()


def stop(d):
    with contextlib.suppress(Exception):
        d.stop(force=True, timeout=30)
    with contextlib.suppress(Exception):
        if d.jvm_alive():
            d.kill()


def project_hash(gpr):
    """SHA-256 over the program data files (``*.gbf`` and ``*.prp``) of a project's repository."""
    rep = pathlib.Path(gpr).with_suffix(".rep")
    h = hashlib.sha256()
    for f in sorted(rep.rglob("*")):
        if f.is_file() and f.suffix in (".gbf", ".prp"):
            h.update(str(f.relative_to(rep)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def first_function(s):
    return s.call("functions", limit=1)["functions"][0]["address"]


def run_worker(s, c, script, *args, **kw):
    return s.call("script", script=c.script(script), isolation="worker", args=list(args),
                  **kw)


def error_of(c, s, **fields):
    """The SessionError of a script request that must fail, and the whole error object."""
    try:
        s.call("script", **fields)
    except c.gs.SessionError as e:
        return e, (s.last_response or {}).get("error", {})
    raise dt.Fail(f"script {fields} did not fail")


def workers(s):
    return s.call("health")["scriptWorkers"]


def long_in_use(s):
    return s.call("health")["lanes"]["long"]["inUse"]


def pid_alive(pid):
    if os.name == "nt":
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = ctypes.c_void_p
        h = k.OpenProcess(0x100000, 0, pid)  # SYNCHRONIZE
        if not h:
            return False
        try:
            return k.WaitForSingleObject(ctypes.c_void_p(h), 0) == 0x102  # WAIT_TIMEOUT
        finally:
            k.CloseHandle(ctypes.c_void_p(h))
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_gone(pid, secs):
    """Seconds until ``pid`` is gone, or None when it is still there after ``secs``."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < secs:
        if not pid_alive(pid):
            return time.perf_counter() - t0
        time.sleep(0.05)
    return None


def wait_pid(I, secs=60):
    """The pid of the one running worker, once it is listed."""
    return dt.wait_for(lambda: (workers(I)["pids"] or [None])[0], "a worker to be listed", secs, 0.1)


def worker_dirs(tmp):
    root = pathlib.Path(tmp) / "hydra-script-workers"
    return sorted(p.name for p in root.glob("w-*")) if root.is_dir() else []


def tmp_of(s):
    return s.hello["paths"]["tmpDir"]


# ---- e7_edited_view: the 9.14 test --------------------------------------------------------------

def t_edited_view(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Edited")
    d = c.daemon("e7-edited")
    O = I = None
    try:
        O = session(c, d, gpr, exe, "owner", writable=True)
        I = c.connect(d, "observer", "e7", 3)
        tmp = tmp_of(I)
        fn = first_function(O)
        orig = O.call("script", script=c.script("E7Name.java"))["output"].split()[1]
        dt.check(orig != EDIT, f"the first function is already called {orig}")
        O.call("rename", address=fn, name=EDIT)  # an edit, left unsaved
        started0 = workers(I)["started"]
        # (1) the engine refuses a worker on unsaved edits, and starts none
        e, err = error_of(c, O, script=c.script("E7Name.java"), isolation="worker")
        dt.check(e.code == "conflict" and e.details.get("reason") == "unsaved" and
                 e.details.get("unsavedEdits", 0) >= 1, f"unsaved: {e.code} {e.details}")
        dt.check((err.get("next") or {}).get("cmd") == "save", f"error.next {err.get('next')}")
        dt.check(workers(I)["started"] == started0 and not worker_dirs(tmp),
                 f"a refused request started a worker or left a folder: {workers(I)} {worker_dirs(tmp)}")
        # (2) the owner saves once; the script then SEES the edit (a stale read fails the test)
        rev0 = O.call("info")["revision"]
        t = time.perf_counter()
        O.call("save")
        save_ms = round((time.perf_counter() - t) * 1000)
        rev1 = O.call("info")["revision"]
        dt.check(rev1 != rev0, f"the save did not move the revision: {rev0} {rev1}")
        hash1 = project_hash(gpr)
        r = run_worker(O, c, "E7Name.java")
        dt.check(EDIT in r["output"] and orig not in r["output"],
                 f"the worker did not see the saved edit (a stale read): {r['output']!r}")
        dt.check(r["isolation"] == "worker" and r["mode"] == "worker" and r["changed"] is False and
                 r["attemptedChanges"] is False and r["unsavedIgnored"] == 0 and
                 r["basedOn"]["saved"] is True and r["basedOn"]["programRevision"],
                 f"reply {r}")
        start_ms = r["worker"]["startMs"]
        dt.check(dt.wait_for(lambda: not pathlib.Path(r["worker"]["clone"]).exists(),
                             "the clone to be deleted", 10),
                 "the clone is still there")
        # (3) a mutating run: measured on the clone, the view is byte-for-byte unchanged
        r = run_worker(O, c, "E7Mutate.java")
        dt.check("renamed" in r["output"] and r["attemptedChanges"] is True and
                 r["attemptedChangesCount"] >= 1 and r["changed"] is False and r["unsaved"] is False,
                 f"attemptedChanges was not measured on the clone: {r}")
        dt.check(not O.call("functions", contains="e7_mutated")["functions"] and
                 O.call("functions", contains=EDIT)["functions"],
                 "the mutation reached the view, or the edit is gone")
        dt.check(project_hash(gpr) == hash1 and O.call("info")["revision"] == rev1,
                 "the view's files or revision changed under a worker run")
        # the control leg (BP13, the premise): the same deaf script in process runs to its end
        t = time.perf_counter()
        ce, _ = error_of(c, O, script=c.script("E7Deaf.java"), args=["6000"], timeout=1,
                         isolation="exclusive")
        control_s = time.perf_counter() - t
        dt.check(ce.code == "cancelled", f"control: {ce.code} {ce.message}")
        dt.check(control_s > 5, f"the in-process deaf script ended after {control_s:.1f} s")
        # (4) the deaf worker is killed at its timeout; slot, cap and clone are released
        timeout = int(2 * start_ms / 1000) + 8
        t = time.perf_counter()
        e, err = error_of(c, O, script=c.script("E7Deaf.java"), isolation="worker",
                          args=["120000"], timeout=timeout)
        elapsed = time.perf_counter() - t
        w = e.details.get("worker") or {}
        dt.check(e.code == "cancelled" and w.get("killed") is True,
                 f"deaf worker: {e.code} {e.message!r} {w}")
        dt.check(f"deaf-start {EDIT}" in e.details.get("output", ""),
                 f"the killed script's output was lost or stale: {e.details.get('output')!r}")
        dt.check(timeout - 0.5 <= elapsed <= timeout + 4,
                 f"killed after {elapsed:.1f} s for a timeout of {timeout} s")
        dt.check(w.get("pid") and wait_gone(w["pid"], 5) is not None, f"worker {w.get('pid')} still alive")
        dt.check(dt.wait_for(lambda: not pathlib.Path(w["clone"]).exists(), "the clone to go", 10),
                 "the killed worker's clone is still there")
        h = I.call("health")
        dt.check(h["leakedWorkers"] == 0 and h["scriptWorkers"]["running"] == 0 and
                 h["scriptWorkers"]["pids"] == [] and h["scriptWorkers"]["killed"] >= 1,
                 f"health after the kill: {h['scriptWorkers']} leaked {h['leakedWorkers']}")
        dt.wait_for(lambda: long_in_use(I) == 0, "the long slot to be free", 10)
        dt.check(not worker_dirs(tmp), f"folders left: {worker_dirs(tmp)}")
        # the owner's long cap is free: an in-process script and a worker both run at once
        O.call("script", script=c.script("E7Name.java"), wait=2000)
        again = run_worker(O, c, "E7Name.java")
        dt.check(EDIT in again["output"], f"after the kill: {again}")
        # (5) the save was counted: the only save is the owner's; no worker saved
        dt.check(O.call("info")["revision"] == rev1 and project_hash(gpr) == hash1,
                 "the view changed after the owner's single save")
        c.timings["e7_edited_view: save ms / worker start ms / control overrun s / kill s after timeout"] = \
            [save_ms, start_ms, round(control_s - 1, 1), round(elapsed - timeout, 1)]
        return (f"unsaved edit refused (no worker started); after one save ({save_ms} ms) the worker saw "
                f"'{EDIT}' not '{orig}'; attemptedChanges {r['attemptedChangesCount']} on the clone, view "
                f"unchanged; the deaf worker was killed {elapsed - timeout:.1f} s after its {timeout} s "
                f"timeout (in process the same script ran {control_s - 1:.1f} s past it); slot, cap and "
                f"clone released")
    finally:
        close_all(O, I)
        stop(d)


# ---- e7_unedited_view -----------------------------------------------------------------------

def t_unedited_view(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Unedited")
    d = c.daemon("e7-unedited")
    O = R = None
    try:
        O = session(c, d, gpr, exe, "owner", writable=True)
        R = session(c, d, gpr, exe, "reader")
        orig = O.call("script", script=c.script("E7Name.java"))["output"].split()[1]
        rev0 = O.call("info")["revision"]
        hash0 = project_hash(gpr)
        n0 = workers(R)["started"]
        # no edit: the worker starts without anybody saving
        r = run_worker(O, c, "E7Name.java")
        dt.check(orig in r["output"] and r["basedOn"]["saved"] is True, f"unedited: {r}")
        dt.check(O.call("info")["revision"] == rev0 and project_hash(gpr) == hash0,
                 "a worker run on an unedited view saved it")
        # a read-only client of the same project may use a worker too
        r2 = run_worker(R, c, "E7Name.java")
        dt.check(orig in r2["output"] and r2["mode"] == "worker", f"reader: {r2}")
        # a project-level script (no program) runs on the clone of the project
        r3 = O.call("script", script=c.script("E7Project.java"), program=None, isolation="worker")
        dt.check(("file " + exe) in r3["output"] and r3["worker"]["cloneBytes"] > 0, f"project script: {r3}")
        dt.check(workers(R)["started"] == n0 + 3, f"workers started {workers(R)}")
        # shared, exclusive and private stay in process (RusticQuery stays in process)
        for iso in ("shared", "exclusive", "private"):
            x = R.call("script", script=c.script("E7Name.java"), isolation=iso)
            dt.check(x["isolation"] == iso and x["mode"] != "worker" and "worker" not in x, f"{iso}: {x}")
        dt.check(workers(R)["started"] == n0 + 3, "an in-process script started a worker")
        dt.check(O.call("info")["revision"] == rev0 and project_hash(gpr) == hash0, "the view changed")
        return "no save before a worker on an unedited view; a reader and a project-level script run; the other isolations stay in process"
    finally:
        close_all(O, R)
        stop(d)


# ---- e7_kill_by_hand ------------------------------------------------------------------------

def t_kill_by_hand(c):
    windows_only()
    ch = chaos()
    exe = prepare(c)
    gpr = c.copy_fixture("e7Hand")
    d = c.daemon("e7-hand")
    R = I = None
    try:
        R = session(c, d, gpr, exe, "runner")
        I = c.connect(d, "observer", "e7", 3)
        rid = R.send("script", script=c.script("E7Deaf.java"), isolation="worker", args=["120000"],
                     timeout=300, parallel=True)
        pid = wait_pid(I)
        time.sleep(1.0)
        ch.terminate(pid, 10)
        try:
            R.wait(rid)
        except c.gs.SessionError as e:
            dt.check(e.code == "failed" and e.details.get("reason") == "worker_died", f"{e.code} {e.details}")
        else:
            raise dt.Fail("a worker killed by hand did not fail its request")
        w = workers(I)
        dt.check(w["died"] == 1 and w["running"] == 0 and w["pids"] == [], f"health {w}")
        dt.wait_for(lambda: long_in_use(I) == 0, "the slot to be free", 10)
        r = run_worker(R, c, "E7Name.java")
        dt.check("name" in r["output"], f"the next request: {r}")
        return "a worker killed by hand failed that one request (worker_died); the next request ran in a new worker"
    finally:
        close_all(R, I)
        stop(d)


# ---- e7_daemon_kill (K7) --------------------------------------------------------------------

def _daemon_kill(c, name, vmargs, suspend):
    """Starts a deaf worker, kills the daemon (TerminateProcess), optionally with the worker
    suspended first. Returns (worker pid, seconds until it was gone or None)."""
    ch = chaos()
    exe = prepare(c)
    gpr = c.copy_fixture("e7K7" + name)
    d = c.daemon("e7-" + name, vmargs=vmargs) if vmargs else c.daemon("e7-" + name)
    R = I = None
    try:
        R = session(c, d, gpr, exe, "runner")
        I = c.connect(d, "observer", "e7", 3)
        R.send("script", script=c.script("E7Deaf.java"), isolation="worker", args=["300000"],
               timeout=600, parallel=True)
        pid = wait_pid(I)
        time.sleep(1.0)
        dt.check(pid_alive(pid), "the worker is not running")
        if suspend:
            dt.check(ch.suspend(pid), f"cannot suspend {pid}")
        d.kill()
        close_all(R, I)
        R = I = None
        gone = wait_gone(pid, 12)
        return pid, gone
    finally:
        close_all(R, I)
        stop(d)


def t_daemon_kill(c):
    windows_only()
    ch = chaos()
    out = {}
    # the daemon's job: a running worker and a suspended one are gone after TerminateProcess
    for tag, suspend in (("job-running", False), ("job-suspended", True)):
        pid, gone = _daemon_kill(c, tag, None, suspend)
        try:
            dt.check(gone is not None, f"{tag}: worker {pid} survived the daemon kill by 12 s")
        finally:
            if gone is None:
                ch.terminate(pid, 10)
        out[tag] = round(gone, 2)
    # the no-job control: a suspended worker survives (the test would prove nothing otherwise)
    pid, gone = _daemon_kill(c, "nojob-suspended", NO_JOB, True)
    try:
        dt.check(gone is None, f"no-job control: the suspended worker {pid} was gone ({gone}): the job proves nothing")
    finally:
        with contextlib.suppress(Exception):
            ch.resume(pid)
        ch.terminate(pid, 10)
    # without the job a RUNNING worker still ends by itself: its pipe to the daemon closed
    pid, gone = _daemon_kill(c, "nojob-running", NO_JOB, False)
    try:
        dt.check(gone is not None, f"no job: the running worker {pid} outlived its daemon")
    finally:
        if gone is None:
            ch.terminate(pid, 10)
    out["nojob-running"] = round(gone, 2)
    return (f"daemon kill: running worker gone after {out['job-running']} s, suspended after "
            f"{out['job-suspended']} s (job); the no-job control left the suspended worker alive; "
            f"a running worker of a job-less daemon ended after {out['nojob-running']} s (its pipe closed)")


# ---- e7_client_disconnect -------------------------------------------------------------------

def t_client_disconnect(c):
    windows_only()
    exe = prepare(c)
    gpr = c.copy_fixture("e7Disc")
    d = c.daemon("e7-disc")
    I = None
    try:
        I = session(c, d, gpr, exe, "observer")
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='e7-disc',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2])\n"
                "s.call('open_program', path=A[3])\n"
                "s.send('script', script=A[4], isolation='worker', args=['300000'], timeout=600)\n"
                "print(json.dumps({'ok': True}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, c.script("E7Deaf.java"))
        line = p.stdout.readline()
        dt.check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        pid = wait_pid(I)
        time.sleep(1.0)
        t = time.perf_counter()
        p.kill()
        p.wait()
        gone = wait_gone(pid, 20)
        dt.check(gone is not None, f"the worker {pid} of a dead client is still there after 20 s")
        dt.wait_for(lambda: workers(I)["running"] == 0 and long_in_use(I) == 0,
                    "the slot of the dead client's worker", 20)
        dt.check(dt.wait_for(lambda: not worker_dirs(tmp_of(I)), "the folder to go", 20), "folder left")
        return f"the worker of a killed client was gone {time.perf_counter() - t:.1f} s after the client; slot and folder released"
    finally:
        close_all(I)
        stop(d)


# ---- e7_cancel_cap --------------------------------------------------------------------------

def t_cancel_cap(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Cap")
    d = c.daemon("e7-cap", engine={"maxWorkers": 1})
    R = I = None
    try:
        R = session(c, d, gpr, exe, "runner")
        I = session(c, d, gpr, exe, "other")
        rid = R.send("script", script=c.script("E7Deaf.java"), isolation="worker", args=["300000"],
                     timeout=600, parallel=True)
        pid = wait_pid(I)
        e, err = error_of(c, I, script=c.script("E7Name.java"), isolation="worker")
        dt.check(e.code == "busy" and e.details.get("reason") == "worker_capacity" and
                 err.get("retryAfterMs"), f"second worker: {e.code} {e.details} {err}")
        dt.check(workers(I)["refused"] == 1 and workers(I)["max"] == 1, f"health {workers(I)}")
        time.sleep(1.0)
        t = time.perf_counter()
        R.call("cancel", target=rid, parallel=True)
        try:
            R.wait(rid)
        except c.gs.SessionError as ex:
            dt.check(ex.code == "cancelled" and (ex.details.get("worker") or {}).get("killed") is True,
                     f"{ex.code} {ex.message} {ex.details.get('worker')}")
        else:
            raise dt.Fail("a cancelled deaf worker returned normally")
        took = time.perf_counter() - t
        dt.check(took < 6, f"the cancel took {took:.1f} s to end the request")
        dt.check(wait_gone(pid, 5) is not None, f"worker {pid} survived the cancel")
        r = run_worker(I, c, "E7Name.java")
        dt.check("name" in r["output"], f"after the cancel: {r}")
        return f"maxWorkers 1: a second worker was refused busy worker_capacity; cancel killed the worker in {took:.1f} s"
    finally:
        close_all(R, I)
        stop(d)


# ---- e7_heap --------------------------------------------------------------------------------

def t_heap(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Heap")
    d = c.daemon("e7-heap", engine={"workerHeapMb": 256})
    R = None
    try:
        R = session(c, d, gpr, exe, "runner")
        ok = run_worker(R, c, "E7Name.java")
        dt.check("name" in ok["output"], f"a trivial script at -Xmx256m: {ok}")
        e, err = error_of(c, R, script=c.script("E7Alloc.java"), isolation="worker", timeout=120)
        dt.check(e.code == "failed" and e.details.get("reason") == "worker_heap" and
                 e.details.get("exitCode") == 3, f"heap: {e.code} {e.message} {e.details}")
        dt.check(R.call("ping").get("pong") is True, "the daemon stopped answering")
        again = run_worker(R, c, "E7Name.java")
        dt.check("name" in again["output"], f"after the heap breach: {again}")
        w = workers(R)
        dt.check(w["running"] == 0 and w["died"] == 1, f"health {w}")
        return "a script that ran the worker out of heap ended only the worker (worker_heap, exit 3); the daemon and the next worker are fine"
    finally:
        close_all(R)
        stop(d)


# ---- e7_validation --------------------------------------------------------------------------

def t_validation(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Valid")
    d = c.daemon("e7-valid")
    R = V2 = None
    try:
        R = session(c, d, gpr, exe, "runner")
        n0 = workers(R)["started"]
        e, _ = error_of(c, R, script=c.script("E7Name.java"), isolation="worker", save=True)
        dt.check(e.code == "bad_request" and e.details.get("field") == "save", f"save: {e.code} {e.details}")
        e, _ = error_of(c, R, script=c.script("E7Name.java"), isolation="bogus")
        dt.check(e.details.get("allowed") == ["shared", "exclusive", "private", "worker"], f"{e.details}")
        e, _ = error_of(c, R, script=c.script("E7Name.java"), isolation="worker", scriptSha256="0" * 64)
        dt.check(e.code == "script_changed", f"pinned digest: {e.code}")
        R.call("open_program", path=exe, overlay="o1")
        e, _ = error_of(c, R, script=c.script("E7Name.java"), isolation="worker", overlay="o1")
        dt.check(e.code == "conflict" and e.details.get("reason") == "overlay", f"overlay: {e.code} {e.details}")
        dt.check(workers(R)["started"] == n0, "a refused request started a worker")
        sha = hashlib.sha256((c.scripts / "E7Name.java").read_bytes()).hexdigest()
        ok = run_worker(R, c, "E7Name.java", scriptSha256=sha)
        dt.check("name" in ok["output"] and ok["isolation"] == "worker", f"right digest: {ok}")
        hello = R.hello["capabilities"]
        dt.check(hello.get("scriptIsolation", 0) >= 2, f"capabilities {hello}")
        # a protocol 2 client sees none of it: the field is not read, the script runs in process
        V2 = c.connect(d, "old", "e7", 2)
        V2.call("open_project", path=str(gpr))
        V2.call("open_program", path=exe)
        x = V2.call("script", script=c.script("E7Name.java"), isolation="worker")
        dt.check("isolation" not in x and x["mode"] != "worker", f"protocol 2: {x}")
        dt.check(workers(R)["started"] == n0 + 1, "the protocol 2 request started a worker")
        return "save with a worker is bad_request, an overlay is conflict, a pinned digest is checked before a worker starts; protocol 2 is unchanged"
    finally:
        close_all(R, V2)
        stop(d)


# ---- e7_sweep -------------------------------------------------------------------------------

def t_sweep(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e7Sweep")
    d = c.daemon("e7-sweep")
    R = None
    try:
        tmp = pathlib.Path(c.a.tmpdir if c.a.tmpdir and c.a.tmpdir != "default" else c.work / "tmp")
        root = tmp / "hydra-script-workers"
        stale = root / "w-ffffffe-1-abcd"
        live = root / f"w-{os.getpid():x}-1-abcd"
        other = root / "keep-me"
        for p in (stale, live, other):
            (p / "clone").mkdir(parents=True, exist_ok=True)
            (p / "clone" / "x.bin").write_bytes(b"x" * 1000)
        R = session(c, d, gpr, exe, "runner")
        dt.check(tmp_of(R) and pathlib.Path(tmp_of(R)).resolve() == tmp.resolve(), f"tmp {tmp_of(R)} vs {tmp}")
        r = run_worker(R, c, "E7Name.java")
        dt.check("name" in r["output"], f"{r}")
        dt.check(not stale.exists(), "the folder of a dead daemon was not swept")
        dt.check(live.exists() and other.exists(), "the sweep removed a folder that is not a dead daemon's")
        return "the sweep removed the dead daemon's folder and left a live process's and a foreign folder alone"
    finally:
        close_all(R)
        stop(d)
        for p in (root / "w-ffffffe-1-abcd", root / f"w-{os.getpid():x}-1-abcd", root / "keep-me"):
            with contextlib.suppress(Exception):
                import shutil
                shutil.rmtree(p, ignore_errors=True)


# ---- e7_cost (SP10) -------------------------------------------------------------------------

def t_cost(c):
    exe = prepare(c)
    targets = [("fixture", c.copy_fixture("e7Cost"), exe)]
    if c.a.project:
        targets.append(("project", pathlib.Path(c.a.project), None))
    d = c.daemon("e7-cost")
    sessions = []
    out = {}
    try:
        for label, gpr, path in targets:
            R = c.connect(d, "runner-" + label, "e7", 3)
            sessions.append(R)
            R.call("open_project", path=str(gpr))
            if path is None:
                path = R.call("list", programsOnly=True)["entries"][0]["path"]
            R.call("open_program", path=path)
            nfun = R.call("info")["functions"]
            runs = []
            for _ in range(3):
                r = run_worker(R, c, "E7Name.java")
                runs.append(r["worker"])
            starts = [w["startMs"] for w in runs]
            ws = [w["mem"].get("workingSetMb") for w in runs if w.get("mem")]
            marks = runs[-1]["marks"]
            # four at once, each from its own connection
            conc = []
            lock = threading.Lock()

            def one(i):
                s = c.connect(d, f"conc{i}-{label}", "e7", 3)
                with lock:
                    sessions.append(s)
                s.call("open_project", path=str(gpr))
                s.call("open_program", path=path)
                x = bl.timed(c, s, "script", script=c.script("E7Name.java"), isolation="worker", wait=120000)
                with lock:
                    conc.append(x)

            ths = [threading.Thread(target=one, args=(i,)) for i in range(4)]
            t0 = time.perf_counter()
            for th in ths:
                th.start()
            for th in ths:
                th.join(300)
            conc_s = time.perf_counter() - t0
            dt.check(len(conc) == 4 and all(x["ok"] for x in conc), f"{label}: four at once: {conc}")
            cstarts = [x["result"]["worker"]["startMs"] for x in conc]
            cws = [x["result"]["worker"]["mem"].get("workingSetMb") for x in conc if x["result"]["worker"].get("mem")]
            med = statistics.median(starts)
            out[label] = {"functions": nfun, "singleStartMs": starts, "medianStartMs": med,
                          "cloneMs": [w["cloneMs"] for w in runs], "cloneBytes": runs[-1]["cloneBytes"],
                          "workingSetMb": ws, "marks": marks, "concurrent4StartMs": cstarts,
                          "concurrent4WallS": round(conc_s, 1), "concurrent4WorkingSetMb": cws}
            c.timings[f"e7_cost: {label} ({nfun} functions)"] = out[label]
            if label == "fixture":
                dt.check(med <= BUDGET_START_MS, f"median worker start-up {med} ms over the budget {BUDGET_START_MS} ms")
            if ws and None not in ws:
                dt.check(max(ws + cws) <= BUDGET_WORKING_SET_MB,
                         f"working set {max(ws + cws)} MB over the budget {BUDGET_WORKING_SET_MB} MB")
            R.call("close_project")
        return "; ".join(f"{k}: {v['functions']} functions, start-up median {v['medianStartMs']:.0f} ms "
                         f"(clone {v['cloneMs']} ms, {v['cloneBytes'] >> 20} MB), working set {v['workingSetMb']} MB, "
                         f"4 at once {v['concurrent4StartMs']} ms" for k, v in out.items())
    finally:
        close_all(*sessions)
        stop(d)


TESTS = {
    "e7_edited_view": t_edited_view,
    "e7_unedited_view": t_unedited_view,
    "e7_kill_by_hand": t_kill_by_hand,
    "e7_daemon_kill": t_daemon_kill,
    "e7_client_disconnect": t_client_disconnect,
    "e7_cancel_cap": t_cancel_cap,
    "e7_heap": t_heap,
    "e7_validation": t_validation,
    "e7_sweep": t_sweep,
    "e7_cost": t_cost,
}

BASELINE = {}
