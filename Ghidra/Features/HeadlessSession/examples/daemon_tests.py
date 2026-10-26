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
"""Tests of the shared session daemon. Standard library only; any OS.

    python daemon_tests.py --ghidra <install> --work <empty dir> --exe A.exe --dll B.dll
                           [--project <an analysed project, opened read-only>]
                           [--legacy-project <a project saved by an older Ghidra>
                            [--legacy-program <path in it>]] [--only a,b]

Each test starts its own daemon instance in <work>/state and stops it, so the user's daemon is
never touched. --project (optional) adds an existing analysed project, which is only ever opened
read-only, to the multi-project test. --legacy-project (optional) is copied into <work> for the
older-format part of upgrade_cache; the original is only read.

Tests: two_harnesses, two_projects, dll_import, client_kill, daemon_restart, fairness, cancel_all,
import_queue, import_isolation, caller_labels, idle_shutdown, keep_warm, stdio, upgrade_cache,
holders, fork, revisions, overlays, multi_writer, shared,
shared_stress.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

MAKE_PROJECT = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class TestMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
"""
SLEEP = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class TestSleep extends GhidraScript {
    @Override protected void run() throws Exception {
        println("start " + System.currentTimeMillis());
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("end " + System.currentTimeMillis());
    }
}
"""

RESULTS = []


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)


def expect_error(code, fn, *args, **kw):
    """Runs fn, which must fail with the protocol error ``code``; returns the SessionError."""
    try:
        r = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != code:
            raise Fail(f"expected {code}, got {type(e).__name__}: {e} "
                       f"{getattr(e, 'details', '')}") from e
        return e
    raise Fail(f"expected {code}, got a result: {str(r)[:300]}")


class Ctx:
    def __init__(self, a, gs):
        self.a = a
        self.gs = gs
        self.work = pathlib.Path(a.work).absolute()
        self.state = self.work / "state"
        self.scripts = self.work / "scripts"
        self.support = pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / \
            "support"
        self.state.mkdir(parents=True, exist_ok=True)
        self.scripts.mkdir(parents=True, exist_ok=True)
        (self.scripts / "TestMakeProject.java").write_text(MAKE_PROJECT)
        (self.scripts / "TestSleep.java").write_text(SLEEP)
        cfg = {"tmpdir": a.tmpdir or str(self.work / "tmp"), "scriptPath": [str(self.scripts)]}
        if a.tmpdir == "default":
            del cfg["tmpdir"]  # leave java.io.tmpdir to the JVM
        (self.state / "config.json").write_text(json.dumps(cfg))
        self.daemons = []
        self.timings = {}

    def daemon(self, instance, **cfg):
        d = self.gs.Daemon(self.a.ghidra, str(self.state), instance, **cfg)
        self.daemons.append(d)
        return d

    def script(self, name):
        return str(self.scripts / name)

    def make_project(self, s, folder, name):
        folder.mkdir(parents=True, exist_ok=True)
        s.call("script", script=self.script("TestMakeProject.java"), program=None,
               args=[str(folder), name])
        return folder / f"{name}.gpr"

    def fixture(self):
        """An analysed project with the EXE, made once and copied per test."""
        base = self.work / "fixture"
        gpr = base / "Fixture.gpr"
        if not gpr.exists():
            d = self.daemon("fixture")
            with d.connect("fixture", "tests") as s:
                self.make_project(s, base, "Fixture")
                s.call("open_project", path=str(gpr), writable=True)
                t = time.perf_counter()
                s.call("import", file=self.a.exe, analyze=True, timeout=1800, wait=600000)
                self.timings["fixture import+analyze exe"] = time.perf_counter() - t
                s.call("close_project")
            d.stop()
        return base

    def copy_fixture(self, name):
        dst = self.work / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.fixture(), dst)
        return dst / "Fixture.gpr"

    def child(self, code, *args):
        """A separate Python process (a second harness) with ghidra_session importable."""
        prelude = (f"import sys, json, time; sys.path.insert(0, {str(self.support)!r}); "
                   "import ghidra_session as gs; A = sys.argv[1:]\n")
        return subprocess.Popen([sys.executable, "-c", prelude + code, *map(str, args)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                stdin=subprocess.DEVNULL)

    def cleanup(self):
        for d in self.daemons:
            try:
                if d.jvm_alive():
                    d.kill()
            except Exception:  # noqa: BLE001
                pass


# ---- tests ----------------------------------------------------------------------------------

def t_two_harnesses(c: Ctx):
    """Two harness processes start at once with no daemon running: one JVM starts and both use
    it."""
    d = c.daemon("harness")
    check(not d.jvm_alive(), "a daemon is already running")
    code = ("t0 = time.perf_counter()\n"
            "s = gs.connect(client='agent', harness=A[0], state=A[1], instance='harness', "
            "ghidra=A[2])\n"
            "st = s.call('status')\n"
            "print(json.dumps({'pid': s.endpoint['pid'], 'client': s.hello['client'], "
            "'ms': (time.perf_counter() - t0) * 1000}))\n"
            "time.sleep(3); s.close()\n")
    procs = [c.child(code, h, c.state, c.a.ghidra) for h in ("claude-code", "opencode")]
    outs = []
    for p in procs:
        out, err = p.communicate(timeout=300)
        check(p.returncode == 0, f"harness process failed: {err[-2000:]}")
        outs.append(json.loads(out.strip().splitlines()[-1]))
    pids = {o["pid"] for o in outs}
    check(len(pids) == 1, f"two daemons were started: {outs}")
    check(outs[0]["client"] != outs[1]["client"], f"same client id: {outs}")
    c.timings["two harnesses: connect (one starts it)"] = [round(o["ms"]) for o in outs]
    with d.connect("checker", "tests") as s:
        t = time.perf_counter()
        s.call("ping")
        c.timings["warm connect + hello + ping"] = round((time.perf_counter() - t) * 1000, 1)
    d.stop()
    return f"one daemon (pid {pids.pop()}) for both; connect ms {[round(o['ms']) for o in outs]}"


def t_two_projects(c: Ctx):
    """Several projects open in one daemon at once, used by two clients concurrently."""
    a_gpr = c.copy_fixture("projA")
    d = c.daemon("multi")
    with d.connect("x", "tests") as x, d.connect("y", "tests") as y:
        b_gpr = c.make_project(x, c.work / "projB", "ProjB")
        y.call("open_project", path=str(b_gpr), writable=True)
        y.call("import", file=c.a.dll, analyze=True, timeout=1800, wait=600000)
        pa = x.call("open_project", path=str(a_gpr))
        x.call("open_program", path=pathlib.Path(c.a.exe).name)
        pb = y.call("projects")["activeProject"]
        check(pa["id"] != pb, "one project id for two projects")
        analysed = None
        if c.a.project:
            analysed = x.call("open_project", path=c.a.project)
            progs = x.call("list", programsOnly=True)["entries"]
            check(progs, "the read-only project lists no program")
            t = time.perf_counter()
            x.call("open_program", path=progs[0]["path"])
            c.timings["extra project: open_program"] = round((time.perf_counter() - t) * 1000)
        errs = []

        def worker(s, key, n):
            try:
                fns = s.call("functions", program=key, limit=n)["functions"]
                for f in fns:
                    if not f["external"] and not f["thunk"]:
                        s.call("decompile", program=key, address=f["address"])
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        a_key = f"{pa['id']}:/{pathlib.Path(c.a.exe).name}"
        b_key = f"{pb}:/{pathlib.Path(c.a.dll).name}"
        t = time.perf_counter()
        ths = [threading.Thread(target=worker, args=(x, a_key, 15)),
               threading.Thread(target=worker, args=(y, b_key, 15))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check(not errs, f"concurrent work failed: {errs}")
        c.timings["two projects: 15+15 decompiles in parallel"] = round(
            (time.perf_counter() - t) * 1000)
        st = x.call("status")
        open_ids = {p["id"] for p in st["projects"]}
        want = 3 if analysed else 2
        check(len(open_ids) >= want, f"expected {want} projects open, status shows {open_ids}")
    d.stop()
    return f"{want} projects open in one daemon; parallel decompiles in two of them"


def t_dll_import(c: Ctx):
    """A DLL is imported, analysed, recognised as a PE, and never imported twice."""
    d = c.daemon("dll")
    with d.connect("dll", "tests") as s:
        gpr = c.make_project(s, c.work / "projDll", "Dll")
        s.call("open_project", path=str(gpr), writable=True)
        t = time.perf_counter()
        r = s.call("import", file=c.a.dll, folder="/libs", analyze=True, timeout=1800,
                   wait=600000)
        c.timings["dll import+analyze"] = round(time.perf_counter() - t, 1)
        check(r["imported"] and r["path"].startswith("/libs/"), f"bad import: {r}")
        info = s.call("info")
        check("PE" in (info["format"] or "") or "Portable" in (info["format"] or ""),
              f"not a PE: {info['format']}")
        check(info["functions"] > 0 and info["analyzed"], f"not analysed: {info}")
        again = s.call("import", file=c.a.dll)
        check(again["imported"] is False and again["existing"] == [r["path"]],
              f"imported twice: {again}")
        by_sha = s.call("list", sha256=r["sha256"])["entries"]
        check([e["path"] for e in by_sha] == [r["path"]], f"list sha256 filter: {by_sha}")
        s.call("save")
        s.call("close_project")
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=r["path"])  # a program inside a folder, by its path
    d.stop()
    return (f"{pathlib.Path(c.a.dll).name}: {info['format']}, {info['functions']} functions, "
            f"dedup by SHA-256 ok")


def t_client_kill(c: Ctx):
    """A client process that dies while it owns a program, with unsaved edits and an analysis
    running, releases everything: its analysis is cancelled, its edit discarded, its lock freed."""
    gpr = c.copy_fixture("projKill")
    d = c.daemon("kill")
    exe = pathlib.Path(c.a.exe).name
    with d.connect("survivor", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        entry = None
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='kill',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "info = s.call('open_program', path=A[3], writable=True)\n"
                "e = s.call('functions', limit=1)['functions'][0]['address']\n"
                "s.call('rename', address=e, name='doomed_rename')\n"
                "s.send('analyze', timeout=3600)\n"
                "print(json.dumps({'entry': e, 'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe)
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        child = json.loads(line)
        entry = child["entry"]
        time.sleep(1.0)
        st = s.call("status")
        held = [x for x in st["programs"] if x["path"] == "/" + exe]
        check(held and held[0]["owner"] == child["client"], f"child does not own it: {held}")
        check(held[0]["busy"], f"no analysis running: {held}")
        t = time.perf_counter()
        p.kill()
        p.wait()
        r = s.call("open_program", path=exe, writable=True, wait=60000)
        released = (time.perf_counter() - t) * 1000
        c.timings["killed client: lock released after"] = round(released)
        check(r["mine"] and r["mode"] == "writable", f"not released: {r}")
        check(not s.call("functions", contains="doomed_rename")["functions"],
              "the dead client's unsaved rename survived")
        st = s.call("status")
        check(all(cl["name"] != "doomed" for cl in st["clients"]), "dead client still listed")
    d.stop()
    return f"lock free {released:.0f} ms after the kill; unsaved edit discarded"


def t_daemon_restart(c: Ctx):
    """The daemon is killed while it holds a writable project; the next connect starts a fresh
    one, which opens the same project writable again."""
    gpr = c.copy_fixture("projRestart")
    d = c.daemon("restart")
    s = d.connect("before", "tests")
    s.call("open_project", path=str(gpr), writable=True)
    s.call("open_program", path=pathlib.Path(c.a.exe).name, writable=True)
    old_pid = s.endpoint["pid"]
    check(d.kill(), "kill failed")
    check(d.endpoint_file.exists(), "a killed JVM cannot remove its endpoint; expected stale file")
    try:
        s.call("ping")
        raise Fail("the old connection still answers")
    except c.gs.SessionError as e:
        check(e.code == "closed", f"unexpected error on the dead connection: {e}")
    except OSError:
        pass
    s.close()
    t = time.perf_counter()
    s2 = d.connect("after", "tests")
    c.timings["restart after kill (stale endpoint)"] = round((time.perf_counter() - t) * 1000)
    check(s2.endpoint["pid"] != old_pid, "the same pid answered")
    s2.call("open_project", path=str(gpr), writable=True)
    r = s2.call("open_program", path=pathlib.Path(c.a.exe).name, writable=True)
    check(r["functions"] > 0, "program empty after restart")
    s2.close()
    d.stop()
    return f"pid {old_pid} killed, pid {r and s2.endpoint['pid']} took over; project reopened writable"


def t_fairness(c: Ctx):
    """With 2 long slots, A queues 4 long jobs and B 1: B's quick query is not delayed, and B's
    long job is admitted before A's last one (round-robin by client)."""
    d = c.daemon("fair", maxLong=2)
    with d.connect("A", "tests") as A, d.connect("B", "tests") as B:
        gpr = c.copy_fixture("projFair")
        A.call("open_project", path=str(gpr))
        B.call("open_project", path=str(gpr))
        B.call("open_program", path=pathlib.Path(c.a.exe).name)
        fn = B.call("functions", limit=50)["functions"]
        addr = [f["address"] for f in fn if not f["thunk"] and not f["external"]][0]
        B.call("decompile", address=addr)  # warm
        ids = [A.send("script", script=c.script("TestSleep.java"), program=None,
                      args=["3000"], parallel=True, wait=60000) for _ in range(4)]
        time.sleep(0.5)
        bid = B.send("script", script=c.script("TestSleep.java"), program=None, args=["3000"],
                     parallel=True, wait=60000)
        time.sleep(0.3)
        t = time.perf_counter()
        B.call("decompile", address=addr, parallel=True)
        quick = (time.perf_counter() - t) * 1000
        sched = B.call("status")["scheduler"]["long"]
        check(sched["inUse"] == 2 and sched["queued"] == 3, f"long lane: {sched}")

        def start(r):
            return int(r["output"].split()[1])

        a = [start(A.wait(i)) for i in ids]
        b = start(B.wait(bid))
        c.timings["quick decompile while long lane is full"] = round(quick, 1)
        check(quick < 1000, f"quick query waited {quick:.0f} ms behind long work")
        check(b < max(a), f"B started at {b}, after all of A's {a}: not round-robin")
    d.stop()
    return f"quick query {quick:.1f} ms under a full long lane; B admitted before A's 4th"


def t_cancel_all(c: Ctx):
    """cancel {all:true} stops a client's running and queued requests, and only its own."""
    d = c.daemon("cancel", maxLong=1)
    with d.connect("A", "tests") as A, d.connect("B", "tests") as B:
        bid = B.send("script", script=c.script("TestSleep.java"), program=None, args=["4000"],
                     parallel=True, wait=60000)
        time.sleep(0.5)
        ids = [A.send("script", script=c.script("TestSleep.java"), program=None,
                      args=["60000"], parallel=True, wait=120000) for _ in range(3)]
        time.sleep(0.5)
        r = A.call("cancel", all=True)
        check(r["cancelled"] == 3, f"cancel all: {r}")
        codes = []
        for i in ids:
            try:
                A.wait(i)
                codes.append("ok")
            except c.gs.SessionError as e:
                codes.append(e.code)
        check(codes == ["cancelled"] * 3, f"A's requests: {codes}")
        B.wait(bid)  # B's own job was not touched
    d.stop()
    return "3 queued/running requests cancelled; the other client's job finished"


RAW_LANG = {"language": "DATA:LE:64:default", "compiler": "pointer64"}


def raw_file(c: Ctx, name: str, mb: int) -> str:
    """A file of random bytes, imported as a raw binary: an import whose length is set by its
    size, which is how the import queue is tested with a small system binary as the only
    fixture."""
    p = c.work / "raw" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists() or p.stat().st_size != mb << 20:
        with open(p, "wb") as f:
            for _ in range(mb):
                f.write(os.urandom(1 << 20))
    return str(p)


def wait_for(cond, what, timeout=120.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    raise Fail(f"timed out waiting for {what}")


def t_import_queue(c: Ctx):
    """Imports run one at a time; the others queue in arrival order, say who they wait behind
    and for how long, and leave the queue when cancelled without disturbing the running one."""
    mb = c.a.raw_mb
    files = [raw_file(c, "q.bin", mb)] * 5  # one file, imported again each time (duplicate)
    d = c.daemon("iq", maxLong=2)
    with d.connect("A", "agent-a") as A, d.connect("B", "agent-b") as B, \
            d.connect("C", "agent-c") as C:
        gpr = c.make_project(A, c.work / "projQueue", "Queue")
        for s in (A, B, C):
            s.call("open_project", path=str(gpr), writable=True)

        def imports(s=A):
            return s.call("status")["imports"]

        def start(s, i, name):
            return s.send("import", file=files[i], name=name, parallel=True, duplicate=True,
                          **RAW_LANG)

        # 1. A runs; B queues behind it and is cancelled while queued.
        ia = start(A, 0, "qa")
        wait_for(lambda: imports()["holder"], "A's import to hold the gate")
        ib = start(B, 1, "qb")
        st = wait_for(lambda: (imports() if imports()["queue"] else None), "B to queue")
        check(st["holder"]["client"] != st["queue"][0]["client"], f"holder/queue: {st}")
        check("agent-a" in st["holder"]["who"], f"the holder is not named: {st['holder']}")
        check("agent-b" in st["queue"][0]["who"], f"the waiter is not named: {st['queue']}")
        check(st["queue"][0]["position"] == 1, f"position: {st['queue']}")
        full = A.call("status")
        waiting = [r for cl in full["clients"] for r in cl["requests"]
                   if r["waiting"] == "import queue"]
        check(len(waiting) == 1 and waiting[0]["cmd"] == "import" and waiting[0]["queue"]["holder"],
              f"status.clients[].requests does not show the queued import: {waiting}")
        def pumped():  # events are read while the client waits on a response
            B.call("ping")
            return any(e.get("id") == ib and "waiting behind" in e.get("message", "")
                       for e in list(B.events))

        wait_for(pumped, "a 'waiting behind' progress event", 15, 0.2)
        ev = [e for e in B.events if e.get("id") == ib and "waiting behind" in e.get("message", "")][-1]
        check(ev.get("queue", {}).get("position") == 1, f"progress event without a queue: {ev}")
        r = B.call("cancel", target=ib)
        check(r["cancelled"] is True, f"cancel of the queued import: {r}")
        try:
            B.wait(ib)
            raise Fail("the cancelled queued import succeeded")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", f"queued cancel: {e}")
        check(not imports()["queue"], "the cancelled import is still queued")
        ra = A.wait(ia)  # the running import was not touched
        check(ra["imported"] is True, f"A's import: {ra}")
        check(ra["queue"]["behind"] is None, f"A waited behind someone: {ra['queue']}")
        h = imports()["history"]
        check(h["count"] == 1 and h["meanMs"] > 0, f"no duration history: {h}")

        # 2. The running import is cancelled; the queued one runs next. The estimate comes from
        #    the first import's duration.
        ia = start(A, 2, "qc")
        wait_for(lambda: imports()["holder"], "the next import to hold the gate")
        ib = start(B, 1, "qb")
        st = wait_for(lambda: (imports() if imports()["queue"] else None), "B to queue again")
        est = st["queue"][0]["estimatedWaitMs"]
        check(est is not None and est > 0, f"no wait estimate with history: {st['queue']}")
        t_run = time.time()
        check(A.call("cancel", target=ia)["cancelled"] is True, "cancel of the running import")
        try:
            A.wait(ia)
            raise Fail("the cancelled running import succeeded")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", f"running cancel: {e}")
        rb = B.wait(ib)  # the queued import ran next
        check(rb["imported"] is True and rb["queue"]["behind"], f"B's import: {rb}")
        check(rb["queue"]["positionAtEntry"] == 1, f"B's queue place: {rb['queue']}")
        check(not imports()["queue"] and not imports()["holder"], f"gate not free: {imports()}")
        names = {e["name"] for e in A.call("list", programsOnly=True)["entries"]}
        check(names == {"qa", "qb"}, f"programs after the cancels: {names}")
        c.timings["import queue: B waited (ms) / estimate when queued (ms)"] = [
            rb["queue"]["waitedMs"], est]
        c.timings[f"import queue: raw {mb} MB import (s)"] = round(rb["importSeconds"], 2)

        # 3. Two queued; the first is cancelled and the second moves up.
        ia = start(A, 2, "qc")
        wait_for(lambda: imports()["holder"], "the third import to hold the gate")
        ib = start(B, 3, "qd")
        wait_for(lambda: len(imports()["queue"]) == 1, "B to queue")
        ic = start(C, 4, "qe")
        q = wait_for(lambda: (imports()["queue"] if len(imports()["queue"]) == 2 else None),
                     "C to queue")
        check([e["position"] for e in q] == [1, 2] and "agent-b" in q[0]["who"],
              f"arrival order: {q}")
        B.call("cancel", target=ib)
        try:
            B.wait(ib)
        except c.gs.SessionError:
            pass
        q = imports()["queue"]
        check(len(q) == 1 and q[0]["position"] == 1 and "agent-c" in q[0]["who"],
              f"C did not move up: {q}")
        est_c = q[0]["estimatedWaitMs"]
        t_c = time.time()
        A.wait(ia)
        rc = C.wait(ic)
        check(rc["imported"] is True, f"C's import: {rc}")
        # from the estimate to C's start: until its answer, less its own load time (the open
        # that follows the load is small)
        actual = round((time.time() - t_c - rc["importSeconds"]) * 1000)
        c.timings["import queue: C wait estimated / actual (ms), taken once it was next"] = [
            est_c, actual]
    d.stop()
    return (f"one import at a time; queued cancel, running cancel and re-ordering ok "
            f"(B waited {rb['queue']['waitedMs']} ms, estimated {est} ms)")


def t_import_isolation(c: Ctx):
    """Why imports are serialized: two ungated loads into two projects share process-wide state.
    Runs ImportIsolationProbe in a throwaway daemon and records what it saw."""
    a = c.a.exe
    b = c.a.dll
    d = c.daemon("iso")
    shutil.copy(pathlib.Path(__file__).absolute().parent / "ImportIsolationProbe.java",
                c.scripts / "ImportIsolationProbe.java")  # scripts run from the script path
    probe = c.script("ImportIsolationProbe.java")
    with d.connect("iso", "tests") as s:
        folder = c.work / "projIso"
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        out = s.call("script", script=probe, program=None, args=[str(folder), a, b, "6"],
                     timeout=900, wait=600000)["output"]
    d.stop()
    got = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    check(got.get("leak.pathVisibleWhileOtherProjectActive") == "true",
          f"expected the library search path set to be shared between projects: {out}")
    check(got.get("leak.pathInOtherProjectsSavedState") == "false",
          f"the path unexpectedly reached the other project's state: {out}")
    c.timings["import isolation probe"] = got
    return ("search path set is process-wide (leaks between projects); concurrent loads: " +
            f"{got.get('race.failures')} failures, {got.get('race.wrongProject')} misplaced, " +
            f"{got.get('race.activeProjectNotMineAfterLoad')} loads saw a foreign active project")


def t_caller_labels(c: Ctx):
    """One connection, two callers: per-request labels name who holds a program or an import,
    in busy answers, status and ownership messages, and scope cancel."""
    gpr = c.copy_fixture("projLabels")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("labels", maxLong=4)
    with d.connect("mcp", "mcp-server") as S, d.connect("other", "tests") as T:
        a = S.labelled(client="agent-a", harness="claude-code")
        b = S.labelled(client="agent-b", harness="opencode")
        S.call("open_project", path=str(gpr), writable=True)
        T.call("open_project", path=str(gpr), writable=True)
        info = a.call("open_program", path=exe, writable=True)
        key = info["key"]
        # the owner is named as agent-a opened it
        try:
            T.call("open_program", path=exe, writable=True, wait=300)
            raise Fail("a second connection opened the program writable")
        except c.gs.SessionError as e:
            check(e.code == "not_owner" and "agent-a" in e.message, f"owner not named: {e}")
        # agent-a holds the program exclusively; agent-b's writable open is blocked by it
        sleep = a.send("script", script=c.script("TestSleep.java"), args=["6000"], program=key)
        wait_for(lambda: any(p["path"] == "/" + exe and p["busy"]
                             for p in S.call("status")["programs"]), "a's script to run")
        try:
            b.call("open_program", path=exe, writable=True, wait=300)
            raise Fail("agent-b's writable open was not blocked")
        except c.gs.SessionError as e:
            check(e.code == "busy", f"expected busy: {e}")
            check("agent-a" in (e.details.get("holder") or "") and "agent-b" not in e.message,
                  f"the holder is not agent-a: {e.details}")
        try:
            b.call("decompile", address="0x0", program=key, wait=300)
            raise Fail("agent-b's decompile was not blocked")
        except c.gs.SessionError as e:
            check(e.code == "busy" and "agent-a" in e.details.get("holder", ""),
                  f"decompile busy answer: {e} {e.details}")
        st = S.call("status")
        busy = [p for p in st["programs"] if p["path"] == "/" + exe][0]
        check("agent-a" in busy["busy"] and busy["ownerLabel"] and "agent-a" in busy["ownerLabel"],
              f"status does not name the holder: {busy}")
        reqs = [r for cl in st["clients"] for r in cl["requests"]]
        check(any(r["client"] == "agent-a" and r["cmd"] == "script" for r in reqs),
              f"status requests do not carry the label: {reqs}")
        me = b.call("status")["youAre"]
        check(me["client"] == "agent-b" and me["harness"] == "opencode" and me["labelled"],
              f"youAre: {me}")
        # cancel scoping: agent-b's cancel all does not reach agent-a's script or the other
        # label's requests
        sb = b.send("script", script=c.script("TestSleep.java"), args=["60000"], program=None)
        sa2 = a.send("script", script=c.script("TestSleep.java"), args=["60000"], program=None)
        wait_for(lambda: len([r for cl in S.call("status")["clients"] for r in cl["requests"]
                              if r["cmd"] == "script"]) == 3, "three scripts")
        check(b.cancel(sleep)["cancelled"] is False, "agent-b cancelled agent-a's request by id")
        r = b.cancel_all()
        check(r["cancelled"] == 1, f"agent-b's cancel all: {r}")
        try:
            b.wait(sb)
            raise Fail("agent-b's request survived its own cancel all")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", str(e))
        left = {r["id"] for cl in S.call("status")["clients"] for r in cl["requests"]
                if r["cmd"] == "script"}
        check({sleep, sa2} <= left, f"agent-a's requests were cancelled: {left}")
        # an unlabelled cancel all is the connection's: everything that is left
        r = S.call("cancel", all=True)
        check(r["cancelled"] == 2, f"unlabelled cancel all: {r}")
        for rid in (sleep, sa2):
            try:
                a.wait(rid)
            except c.gs.SessionError as e:
                check(e.code == "cancelled", str(e))
    d.stop()
    return "labels named in busy, status and owner messages; cancel scoped per label"


def t_idle_shutdown(c: Ctx):
    """With idleTimeout, the daemon exits on its own once no client is connected."""
    d = c.daemon("idle", idleTimeout=3)
    with d.connect("x", "tests") as s:
        s.call("ping")
    t = time.perf_counter()
    while d.jvm_alive() and time.perf_counter() - t < 60:
        time.sleep(0.2)
    gone = time.perf_counter() - t
    check(not d.jvm_alive(), "daemon still running 60 s after the last client left")
    check(not d.endpoint_file.exists(), "endpoint file left behind after a clean exit")
    return f"exited {gone:.1f} s after the last client left (idleTimeout 3 s)"


def t_keep_warm(c: Ctx):
    """A read-only program stays open after its last user leaves, so the next client gets it at
    no cost; after keepWarm it is closed."""
    gpr = c.copy_fixture("projWarm")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("warm", keepWarm=4)
    with d.connect("first", "tests") as s:
        s.call("open_project", path=str(gpr))
        first = s.call("open_program", path=exe)
    with d.connect("second", "tests") as s:
        s.call("open_project", path=str(gpr))
        t = time.perf_counter()
        second = s.call("open_program", path=exe)
        warm_ms = (time.perf_counter() - t) * 1000
        check(second["openMs"] == 0, f"not warm: {second}")
    with d.connect("watch", "tests") as s:
        t = time.perf_counter()
        while time.perf_counter() - t < 40:
            if not s.call("status")["programs"]:
                break
            time.sleep(0.5)
        st = s.call("status")
        check(not st["programs"], f"still open after keepWarm: {st['programs']}")
    d.stop()
    c.timings["keep_warm: open_program cold / warm"] = [first["openMs"], round(warm_ms, 1)]
    return f"cold {first['openMs']} ms, warm {warm_ms:.1f} ms; closed after keepWarm"


def t_stdio(c: Ctx):
    """A private session over stdin/stdout, started by the launcher (no daemon, no socket)."""
    t = time.perf_counter()
    with c.gs.StdioSession(state=str(c.state), ghidra=c.a.ghidra,
                           stderr_path=str(c.work / "stdio.log")) as s:
        ready = (time.perf_counter() - t) * 1000
        st = s.call("status")
        check(st["listen"] is None and st["launch"]["mode"] in ("fast", "standard"), str(st))
    c.timings["stdio session ready"] = round(ready)
    return f"ready in {ready:.0f} ms ({st['launch']['mode']} mode)"


def clone_tree(src: pathlib.Path, dst: pathlib.Path):
    """Copies a project folder; on Windows through CopyFileW, which block-clones on ReFS."""
    if dst.exists():
        shutil.rmtree(dst)
    copy = shutil.copy2
    if sys.platform == "win32":
        import ctypes

        def copy(a, b):
            if not ctypes.windll.kernel32.CopyFileW(str(a), str(b), False):
                raise OSError(f"CopyFileW {a} -> {b} failed: {ctypes.GetLastError()}")
    shutil.copytree(src, dst, copy_function=copy)


def tree_state(root: pathlib.Path) -> list:
    """Every file under root with size, time and, up to 1 MiB, content: proves nothing wrote."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out.append((str(p.relative_to(root)), st.st_size, st.st_mtime_ns,
                        p.read_bytes() if st.st_size <= 1 << 20 else None))
    return out


def build_of(s, build_id):
    """The upgrade cache build with this id from status, or None."""
    for b in s.call("status")["upgradeCache"]["builds"]:
        if b["id"] == build_id:
            return b
    return None


def wait_build(s, build_id, timeout=1800):
    """Waits until the build is no longer building; returns its status entry."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        b = build_of(s, build_id)
        check(b is not None, f"build {build_id} is not in status")
        if b["state"] != "building":
            return b
        time.sleep(0.1)
    raise Fail(f"build {build_id} still running after {timeout} s")


def wait_phase(s, build_id, phases, timeout=600):
    """Polls status until the build is in one of the phases; returns its entry (or the finished
    entry, when it ended first)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        b = build_of(s, build_id)
        if b is not None and (b["state"] != "building" or b.get("phase") in phases):
            return b
        time.sleep(0.02)
    raise Fail(f"build {build_id} never reached {phases}")


def key_dir_state(cache: pathlib.Path, key: str):
    """(entry.json's upgraded programs or None, published generations, temporary folders)."""
    d = cache / key
    entry = None
    if (d / "entry.json").is_file():
        entry = json.loads((d / "entry.json").read_text(encoding="utf-8")).get("upgraded")
    subs = [p.name for p in d.iterdir() if p.is_dir()] if d.is_dir() else []
    return (entry, sorted(n for n in subs if not n.endswith(".tmp")),
            sorted(n for n in subs if n.endswith(".tmp")))


def t_upgrade_cache(c: Ctx):
    """Read-only opens of a program saved in an older database format: the first open is
    upgraded in memory and answers at once, while a background build makes the upgraded copy
    that later opens use. Checks: current-format programs and an opted-out daemon do not use it;
    the first open takes in-memory time and starts the build; two concurrent opens make one
    build; a reopen after the build comes from the copy and is faster; a daemon killed mid-build
    leaves no entry and the next start builds cleanly; a stop mid-build is prompt; a source that
    changes during a build fails it and the next open retries; a queued build yields to clients'
    long work and can be cancelled; an older key's entry is pruned; the source is never written.
    The older-format part needs --legacy-project (a project saved by an older Ghidra, best a
    small one; the test works on block-cloned copies)."""
    cache = c.work / "upgrade-cache"
    if cache.exists():
        shutil.rmtree(cache)
    exe = pathlib.Path(c.a.exe).name
    cur = c.copy_fixture("projCurrent")
    d = c.daemon("upgrade", keepWarm=0, upgradeCacheDir=str(cache))
    notes = []
    with d.connect("cur", "tests") as s:
        st = s.call("status")["upgradeCache"]
        check(st["enabled"] and pathlib.Path(st["dir"]) == cache, f"cache not enabled: {st}")
        s.call("open_project", path=str(cur))
        r = s.call("open_program", path=exe)
        check(r["cachedUpgrade"] is False and r["cacheBuild"] == "none",
              f"a current-format program used the cache: {r}")
        check(not cache.exists() or not any(p.is_dir() for p in cache.iterdir()),
              "a current-format program made a cache entry")
    d.stop()
    notes.append("current format: not cached")
    if not c.a.legacy_project:
        return "; ".join(notes + ["older format: skipped (no --legacy-project)"])

    src = pathlib.Path(c.a.legacy_project)
    src = src.parent if src.suffix == ".gpr" else src

    def legacy_copy(name):
        dst = c.work / name
        clone_tree(src, dst)
        return dst

    # 1. opted out: the in-memory upgrade, which is also the first open's yardstick
    legacy = legacy_copy("legacy")
    before = tree_state(legacy)
    off = c.daemon("upgrade-off", keepWarm=0, upgradeCache=False)
    with off.connect("off", "tests") as s:
        check(not s.call("status")["upgradeCache"]["enabled"], "opt-out ignored")
        s.call("open_project", path=str(legacy))
        prog = c.a.legacy_program or s.call("list", programsOnly=True)["entries"][0]["path"]
        t = time.perf_counter()
        r = s.call("open_program", path=prog, wait=1800000)
        mem_ms = (time.perf_counter() - t) * 1000
        check(r["cachedUpgrade"] is False and r["cacheBuild"] == "none",
              f"opted out, yet: {r.get('upgradeCache')} {r.get('cacheBuild')}")
    off.stop()
    notes.append(f"opt-out: in memory {mem_ms:.0f} ms")

    # 2. two clients open it at once: one in-memory upgrade answers both, one build starts
    d = c.daemon("upgrade", keepWarm=3600, upgradeCacheDir=str(cache))
    with d.connect("a", "tests") as A, d.connect("b", "tests") as B:
        A.call("open_project", path=str(legacy))
        B.call("open_project", path=str(legacy))
        res, errs = {}, []

        def opener(name, s):
            try:
                t0 = time.perf_counter()
                res[name] = (s.call("open_program", path=prog, wait=1800000),
                             (time.perf_counter() - t0) * 1000)
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        ths = [threading.Thread(target=opener, args=(n, s)) for n, s in (("a", A), ("b", B))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check(not errs, f"concurrent opens failed: {errs}")
        answers = [res["a"][0], res["b"][0]]
        check(all(x["cachedUpgrade"] is False for x in answers),
              f"served from a cache that cannot exist yet: {answers}")
        started = [x for x in answers if x["cacheBuild"] == "started"]
        check(len(started) == 1, f"expected one open to start the build: "
              f"{[x['cacheBuild'] for x in answers]}")
        first_ms = res["a"][1] if res["a"][0] is started[0] else res["b"][1]
        check(first_ms < mem_ms * 1.5 + 2000,
              f"the first open took {first_ms:.0f} ms, the in-memory upgrade {mem_ms:.0f} ms")
        build_id = started[0]["cacheBuildInfo"]["id"]
        key = started[0]["cacheBuildInfo"]["key"]
        st = A.call("status")["upgradeCache"]
        check(st["buildsStarted"] == 1 and [b["id"] for b in st["builds"]] == [build_id],
              f"two opens made more than one build: {st}")
        b = wait_build(A, build_id)
        check(b["state"] == "ready", f"build failed: {b}")
        check(key_dir_state(cache, key) == ([prog], ["g1"], []), f"cache entry: "
              f"{key_dir_state(cache, key)}")
        held = [x for x in A.call("status")["programs"] if x["path"] == prog][0]
        check(held["cachedUpgrade"] is False and held["cacheBuild"] == "ready",
              f"switched while in use, or not ready: {held}")
        A.call("close_program")
        B.call("close_program")
        # nobody uses the in-memory program now: the next open takes the copy
        t = time.perf_counter()
        again = A.call("open_program", path=prog, wait=600000)
        reopen_ms = (time.perf_counter() - t) * 1000
        check(again["cachedUpgrade"] and again["upgradeCache"]["key"] == key and
              again["changed"] is False, f"reopen not from the copy: {again.get('upgradeCache')}")
        check(reopen_ms < first_ms, f"reopen {reopen_ms:.0f} ms, first open {first_ms:.0f} ms")
        fn = next(f for f in A.call("functions", limit=50)["functions"] if not f["external"])
        check(A.call("decompile", address=fn["address"]).get("c"),
              "no decompilation from the cached program")
    d.stop()
    check(tree_state(legacy) == before, "the source project was written")
    notes.append(f"first open {first_ms:.0f} ms (build started; 2 opens, 1 build), build "
                 f"{b['ms']} ms {b['phaseMs']}, reopen from the copy {reopen_ms:.0f} ms")
    c.timings["upgrade cache: in-memory / first open / build / reopen ms"] = [
        round(mem_ms), round(first_ms), b["ms"], round(reopen_ms)]

    # 3. killed mid-build: no entry; the next start builds cleanly
    legacy2 = legacy_copy("legacy2")
    d = c.daemon("upgrade", keepWarm=0, upgradeCacheDir=str(cache))
    s = d.connect("doomed", "tests")
    s.call("open_project", path=str(legacy2))
    r = s.call("open_program", path=prog, wait=1800000)
    check(r["cacheBuild"] == "started", f"no build started: {r.get('cacheBuild')}")
    key2, id2 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
    b = wait_phase(s, id2, ("upgrade", "save"))
    check(b["state"] == "building", f"the build ended before it could be killed: {b}")
    killed_in = b["phase"]
    check(d.kill(), "kill failed")
    s.close()
    entry, gens, tmps = key_dir_state(cache, key2)
    check(entry is None and not gens, f"a killed build left an entry: {entry} {gens}")
    with d.connect("after", "tests") as s:
        s.call("open_project", path=str(legacy2))
        r = s.call("open_program", path=prog, wait=True)  # waits for the build
        check(r["cachedUpgrade"] and r["upgradeCache"]["key"] == key2,
              f"the rebuild after the kill: {r.get('upgradeCache')} {r.get('cacheBuildInfo')}")
    check(key_dir_state(cache, key2) == ([prog], ["g1"], []),
          f"after the rebuild: {key_dir_state(cache, key2)}")
    notes.append(f"killed in {killed_in} ({len(tmps)} temporary folder left), rebuilt cleanly")

    # 4. stopped mid-build: prompt, and the temporary folder goes
    legacy3 = legacy_copy("legacy3")
    with d.connect("stopper", "tests") as s:
        s.call("open_project", path=str(legacy3))
        r = s.call("open_program", path=prog, wait=1800000)
        key3, id3 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        b = wait_phase(s, id3, ("upgrade", "save"))
        stopped_in = b["phase"] if b["state"] == "building" else b["state"]
    t = time.perf_counter()
    d.stop(force=True)
    stop_s = time.perf_counter() - t
    entry, gens, tmps = key_dir_state(cache, key3)
    check(stop_s < 10, f"stop took {stop_s:.1f} s during a build")
    check(stopped_in == "ready" or (entry is None and not gens and not tmps),
          f"a cancelled build left files: {entry} {gens} {tmps}")
    notes.append(f"stopped in {stopped_in} in {stop_s:.1f} s, temporary folder removed")

    # 5. a queued build yields to clients' long work; a source change fails it; cancel; prune
    legacy4 = legacy_copy("legacy4")
    d = c.daemon("upgrade-s", keepWarm=0, maxLong=1, upgradeCacheDir=str(cache))
    with d.connect("long", "tests") as L, d.connect("open", "tests") as s:
        sleep_id = L.send("script", script=c.script("TestSleep.java"), program=None,
                          args=["8000"], parallel=True, wait=60000)
        time.sleep(0.5)
        s.call("open_project", path=str(legacy4))
        r = s.call("open_program", path=prog, wait=1800000)
        key4, id4 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        b = wait_phase(s, id4, ("waiting for a long slot",), timeout=60)
        check(b["state"] == "building", f"the build did not wait for the client's job: {b}")
        gpr = next(legacy4.glob("*.gpr"))
        os.utime(gpr, (time.time(), time.time() + 5))  # the source changes meanwhile
        b = wait_build(s, id4)
        check(b["state"] == "failed" and "source changed" in (b["error"] or ""),
              f"a changed source did not fail the build: {b}")
        check(key_dir_state(cache, key4) == (None, [], []),
              f"the failed build left files: {key_dir_state(cache, key4)}")
        L.wait(sleep_id)
        # the next open, here one that joins the in-memory program, retries with the new key;
        # a queued build is cancellable
        sleep_id = L.send("script", script=c.script("TestSleep.java"), program=None,
                          args=["8000"], parallel=True, wait=60000)
        time.sleep(0.5)
        L.call("open_project", path=str(legacy4))
        r = L.call("open_program", path=prog, wait=1800000)
        check(r["cacheBuild"] == "started" and r["cacheBuildInfo"]["key"] != key4,
              f"the next open did not retry: {r.get('cacheBuild')} {r.get('cacheBuildInfo')}")
        key5, id5 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        n = s.call("cancel", cacheBuild=r["key"])["cancelled"]
        b = wait_build(s, id5)
        check(n == 1 and b["state"] == "failed" and b["cancelled"],
              f"cancel did not stop the build: {n} {b}")
        L.wait(sleep_id)
        L.call("close_program")
        s.call("close_program")
        r = s.call("open_program", path=prog, wait=True)
        check(r["cachedUpgrade"] and r["upgradeCache"]["key"] == key5,
              f"no build after the cancel: {r.get('upgradeCache')} {r.get('cacheBuildInfo')}")
        s.call("close_program")
        # a changed source makes a new key; once that is built, the older entry is removed
        os.utime(gpr, (time.time(), time.time() + 10))
        r = s.call("open_program", path=prog, wait=True)
        key6 = r["upgradeCache"]["key"]
        check(r["cachedUpgrade"] and key6 != key5, f"changed source: {r.get('upgradeCache')}")
        s.call("close_project")
    d.stop()
    check(not (cache / key5).exists(), f"the older entry {key5} was not pruned")
    notes.append("queued build waited for the client's job; source change failed it; next open "
                 "retried; cancel stopped it; older entry pruned")
    return "; ".join(notes)


def t_holders(c: Ctx):
    """busy, conflict and not_owner name the holder (client, harness, command, how long) and the
    project or program, and suggest what to do (a fork where a fork is the answer)."""
    gpr = c.copy_fixture("projHolders")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("holders", keepWarm=0)
    notes = []
    with d.connect("reader-a", "harness-a") as a, d.connect("writer-b", "harness-b") as b:
        # writing to a read-only view: read_only, naming the project, suggesting a fork
        pa = a.call("open_project", path=str(gpr))
        b.call("open_project", path=str(gpr))
        e = expect_error("read_only", b.call, "open_program", path=exe, writable=True)
        dt = e.details
        check(dt.get("project") == pa["id"] and dt.get("gpr"), f"no project identity: {dt}")
        check(dt.get("suggest") == "fork_project" and
              dt.get("suggestion", {}).get("cmd") == "fork_project" and
              dt["suggestion"].get("project") == pa["id"] and dt["suggestion"].get("path") and
              dt.get("alternative") == "open_project writable", f"no fork suggestion: {dt}")
        notes.append("read_only names the project + suggests fork_project")
        a.call("close_project")
        b.call("close_project")
        # one writer per program: not_owner names the owner
        b.call("open_project", path=str(gpr), writable=True)
        b.call("open_program", path=exe, writable=True)
        a.call("open_project", path=str(gpr))   # joins the writable project read-only
        info = a.call("open_program", path=exe)
        e = expect_error("not_owner", a.call, "open_program", path=exe, writable=True)
        dt = e.details
        hi = dt.get("holderInfo") or {}
        check(hi.get("name") == "writer-b" and hi.get("harness") == "harness-b" and
              hi.get("command") == "open_program writable" and isinstance(hi.get("heldMs"), int),
              f"not_owner holder: {dt}")
        check(dt.get("program") == info["key"] and dt.get("sha256") == info["sha256"] and
              dt.get("gpr"), f"not_owner program identity: {dt}")
        check(dt.get("suggest") == "fork_project" and dt.get("owner") == b.hello["client"],
              f"not_owner suggestion/owner: {dt}")
        fn = a.call("functions", limit=1)["functions"][0]["address"]
        e = expect_error("not_owner", a.call, "rename", address=fn, name="x_not_mine")
        check((e.details.get("holderInfo") or {}).get("name") == "writer-b",
              f"rename not_owner: {e.details}")
        notes.append("not_owner names owner + program sha256")
        # busy: the owner's exclusive script holds the program; a reader that cannot wait is told
        # who holds it, doing what, for how long
        rid = b.send("script", script=c.script("TestSleep.java"), args=["4000"], parallel=True,
                     wait=60000)
        time.sleep(1.0)
        e = expect_error("busy", a.call, "decompile", address=fn, wait=200)
        dt = e.details
        hi = dt.get("holderInfo") or {}
        check(hi.get("name") == "writer-b" and "script" in (hi.get("command") or "") and
              hi.get("heldMs", 0) >= 500, f"busy holder: {dt}")
        check(dt.get("program") == info["key"] and dt.get("suggest") == "retry" and
              isinstance(dt.get("holder"), str), f"busy identity: {dt}")
        b.wait(rid)
        notes.append(f"busy names holder ({hi.get('command')}, {hi.get('heldMs')} ms)")
        b.call("close_project", discard=True)
        a.call("close_project")
    # another process holds the project's lock: conflict names it from Ghidra's lock file
    d2 = c.daemon("holders2")
    with d2.connect("other-process", "tests") as o, d.connect("late", "tests") as s:
        o.call("open_project", path=str(gpr), writable=True)
        e = expect_error("conflict", s.call, "open_project", path=str(gpr), writable=True)
        hi = e.details.get("holderInfo") or {}
        check(hi.get("live") is True and hi.get("user") and hi.get("lockFile"),
              f"lock holder: {e.details}")
        check(e.details.get("suggest") == "open_read_only", f"lock suggestion: {e.details}")
        notes.append("project lock of another process named (user, host, since)")
    d2.stop()
    d.stop()
    return "; ".join(notes)


def tree_state(folder):
    """{relative path: (size, mtime_ns)} of every file below a folder."""
    folder = pathlib.Path(folder)
    return {str(f.relative_to(folder)): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in folder.rglob("*") if f.is_file()}


def t_fork(c: Ctx):
    """fork_project makes a working copy while the master's read-only view stays open and in
    use: the fork is writable by its maker, records its source and base revision, and leaves the
    master byte-identical. A source someone else writes is refused, naming the writer."""
    src = c.copy_fixture("projForkSrc")
    exe = pathlib.Path(c.a.exe).name
    forks = c.work / "forks"
    if forks.exists():
        shutil.rmtree(forks)
    before = tree_state(src.parent)
    d = c.daemon("fork", keepWarm=0)
    notes = []
    with d.connect("reader", "harness-a") as a, d.connect("writer", "harness-b") as b:
        pa = a.call("open_project", path=str(src))
        a.call("open_program", path=exe)
        fn = a.call("functions", limit=1)["functions"][0]
        a.call("decompile", address=fn["address"])
        # the reader keeps its view; the writer forks the master it has not even joined
        t = time.perf_counter()
        r = b.call("fork_project", project=pa["id"], path=str(forks / "b1"), wait=600000)
        c.timings["fork_project (small project)"] = round((time.perf_counter() - t) * 1000)
        check(r["project"] != pa["id"] and r["writable"] and r["info"]["writable"],
              f"fork not opened writable: {r}")
        check(r["source"]["project"] == pa["id"] and r["source"]["gpr"] and
              r["source"]["revision"] == r["baseRevision"] and len(r["baseRevision"]) == 16,
              f"fork source: {r['source']}")
        check(r["bytes"] > 0 and r["files"] > 0 and r["method"] in ("clone", "copy") and
              isinstance(r["cloned"], bool) and r["depth"] == 1, f"fork cost: {r}")
        check(pathlib.Path(r["gpr"]).is_file() and pathlib.Path(r["sidecar"]).is_file(),
              f"fork files: {r}")
        side = json.loads(pathlib.Path(r["sidecar"]).read_text())
        check(side["baseRevision"] == r["baseRevision"] and side["source"]["gpr"] and
              side["by"]["name"] == "writer", f"sidecar: {side}")
        check(not list(forks.glob("*/.*.tmp")), "a temporary folder was left")
        notes.append(f"fork {r['bytes']} bytes/{r['files']} files by {r['method']} "
                     f"(cloned {r['cloned']}) in {r['copyMs']} ms")
        # the reader's view is unaffected and still answers
        a.call("decompile", address=fn["address"])
        st = a.call("project")
        check(st["id"] == pa["id"] and a.hello["client"] in st["users"], f"reader view: {st}")
        info = b.call("project", project=r["project"])
        check(info["fork"] and info["fork"]["baseRevision"] == r["baseRevision"] and
              info["fork"]["source"]["gpr"] == r["source"]["gpr"], f"project.fork: {info}")
        # the writer edits and saves its fork; the master and its view do not change
        b.call("open_program", path=exe, writable=True)
        b.call("rename", address=fn["address"], name="fork_only_name")
        b.call("save")
        check(not a.call("functions", contains="fork_only_name")["functions"],
              "the fork's rename shows in the master's view")
        check(b.call("functions", contains="fork_only_name")["functions"],
              "the fork's rename is missing in the fork")
        # fork of a fork: an unsaved change is refused, a saved one is forked
        b.call("rename", address=fn["address"], name="fork_unsaved")
        expect_error("unsaved_changes", b.call, "fork_project", project=r["project"],
                     path=str(forks / "b2"))
        b.call("save")
        r2 = b.call("fork_project", project=r["project"], path=str(forks / "b2" / "Second.gpr"),
                    wait=600000)
        check(r2["depth"] == 2 and r2["name"] == "Second" and r2["source"]["fork"] and
              r2["source"]["project"] == r["project"], f"fork of a fork: {r2}")
        side2 = json.loads(pathlib.Path(r2["sidecar"]).read_text())
        check(side2["parent"]["baseRevision"] == r["baseRevision"], f"lineage: {side2}")
        notes.append("fork of a fork records its lineage")
        # a destination that holds a project is refused
        e = expect_error("conflict", b.call, "fork_project", project=pa["id"],
                         path=str(forks / "b1"))
        check("already exists" in e.message, f"existing destination: {e}")
        # copy-on-write is promised only where the file system clones; auto refuses large
        # full copies; full always copies
        try:
            r3 = b.call("fork_project", project=pa["id"], path=str(forks / "cow"),
                        mode="copy-on-write", wait=600000)
            check(r3["method"] == "clone", f"copy-on-write fork was not a clone: {r3}")
            cow = f"copy-on-write: clone, cloned={r3['cloned']}"
        except c.gs.SessionError as e:
            check(e.code == "conflict" and e.details.get("reason") == "no_copy_on_write" and
                  e.details.get("bytes", 0) > 0, f"copy-on-write refusal: {e} {e.details}")
            cow = f"copy-on-write refused here ({e.details.get('destinationFileSystem')})"
        try:
            r4 = b.call("fork_project", project=pa["id"], path=str(forks / "auto0"),
                        maxCopyMb=0, wait=600000)
            check(r4["method"] == "clone", f"auto over the limit without a clone: {r4}")
        except c.gs.SessionError as e:
            check(e.code == "conflict" and e.details.get("reason") == "too_large" and
                  e.details.get("suggest") == "mode full", f"auto refusal: {e} {e.details}")
        r5 = b.call("fork_project", project=pa["id"], path=str(forks / "full"), mode="full",
                    maxCopyMb=0, writable=False, wait=600000)
        check(not r5["info"]["writable"], f"a read-only fork opened writable: {r5}")
        notes.append(cow)
        # a source that another client writes is refused, naming it
        with d.connect("third", "harness-c") as x:
            x.call("open_project", path=r["gpr"])  # joins b's writable fork
            e = expect_error("conflict", x.call, "fork_project", project=r["project"],
                             path=str(forks / "x1"))
            names = [h.get("name") for h in e.details.get("holders", [])]
            check("writer" in names and e.details.get("suggest") == "retry",
                  f"writer not named: {e.details}")
            x.call("close_project")
        notes.append("a source written by another client is refused, naming it")
        a.call("close_project")
        for pid in (r["project"], r2["project"], r5["project"]):
            b.call("close_project", project=pid, discard=True)
    # another process holds the source writable: refused, naming it from its lock file
    d2 = c.daemon("fork2")
    with d2.connect("other-process", "tests") as o, d.connect("late", "tests") as s:
        o.call("open_project", path=str(forks / "b1" / "Fixture.gpr"), writable=True)
        e = expect_error("conflict", s.call, "fork_project",
                         project=str(forks / "b1" / "Fixture.gpr"), path=str(forks / "y1"))
        check((e.details.get("holderInfo") or {}).get("live") is True,
              f"lock holder: {e.details}")
    d2.stop()
    d.stop()
    check(tree_state(src.parent) == before, "the master project changed")
    notes.append("master byte-identical")
    return "; ".join(notes)


def t_revisions(c: Ctx):
    """Projects and programs carry revisions; a read-only view whose project another process
    saved is marked stale on its clients' next answers; refresh reopens it for all of them at
    once (the others are told once); a fork starts at its source's revision."""
    gpr = c.copy_fixture("projRev")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("rev", keepWarm=0)
    notes = []
    with d.connect("reader-a", "tests") as a, d.connect("reader-b", "tests") as b:
        pa = a.call("open_project", path=str(gpr))
        rev0 = pa["revision"]
        check(isinstance(rev0, str) and len(rev0) == 16 and pa["diskRevision"] == rev0 and
              pa["stale"] is False and pa["generation"] == 1, f"open_project revision: {pa}")
        b.call("open_project", path=str(gpr))
        ia = a.call("open_program", path=exe)
        b.call("open_program", path=exe)
        check(len(ia["revision"]) == 16 and ia["projectRevision"] == rev0 and
              ia["generation"] == 1, f"open_program revision: {ia}")
        st = a.call("status")
        check([p["revision"] for p in st["projects"]] == [rev0] and
              [p["revision"] for p in st["programs"]] == [ia["revision"]],
              f"status revisions: {st['projects']} {st['programs']}")
        fn = a.call("functions", limit=1)["functions"][0]
        # another process saves the project (a second daemon, writable)
        d2 = c.daemon("rev-writer")
        with d2.connect("writer", "tests") as w:
            w.call("open_project", path=str(gpr), writable=True)
            w.call("open_program", path=exe, writable=True)
            w.call("rename", address=fn["address"], name="saved_elsewhere")
            w.call("save")
            w.call("close_project")
        d2.stop()
        # the readers' next answers say their view is stale; their view is unchanged
        r = a.call_raw("functions", contains="saved_elsewhere")
        check(not r["result"]["functions"], "the old view shows the new save")
        stale = r.get("stale") or []
        check(len(stale) == 1 and stale[0]["project"] == pa["id"] and
              stale[0]["revision"] == rev0 and stale[0]["diskRevision"] != rev0 and
              stale[0]["suggest"] == "refresh", f"no stale marker: {r}")
        check(a.call("project")["stale"] is True, "project.stale is not set")
        notes.append("stale marker after another process saved")
        # one reader refreshes; both see the new revision, the other is told once
        t = time.perf_counter()
        rf = b.call("refresh")
        c.timings["refresh (1 program reopened)"] = round((time.perf_counter() - t) * 1000)
        check(rf["refreshed"] and rf["from"] == rev0 and rf["revision"] != rev0 and
              rf["generation"] == 2 and rf["programs"][0]["action"] == "reopened",
              f"refresh: {rf}")
        check(b.call("functions", contains="saved_elsewhere")["functions"],
              "the refreshing reader does not see the save")
        r = a.call_raw("functions", contains="saved_elsewhere")
        check(r["result"]["functions"], "the other reader does not see the save after refresh")
        told = r.get("refreshed") or []
        check(len(told) == 1 and told[0]["project"] == pa["id"] and told[0]["from"] == rev0 and
              told[0]["generation"] == 2 and not r.get("stale"), f"refreshed marker: {r}")
        r = a.call_raw("info")
        check(not r.get("refreshed") and not r.get("stale") and
              r["result"]["projectRevision"] == rf["revision"] and
              r["result"]["generation"] == 2, f"told twice, or info stale: {r}")
        check(a.call("decompile", address=fn["address"])["name"] == "saved_elsewhere",
              "decompile after refresh")
        again = a.call("refresh")
        check(again["refreshed"] is False and again["reason"] == "unchanged", f"again: {again}")
        notes.append(f"refresh switched both readers in {c.timings['refresh (1 program reopened)']}"
                     " ms; the other was told once")
        # a fork starts at its source's revision; a save in the fork moves only the fork
        fk = a.call("fork_project", project=pa["id"], path=str(c.work / "projRevFork"),
                    wait=600000)
        fi = a.call("project", project=fk["project"])
        check(fk["baseRevision"] == rf["revision"] and fi["revision"] == fk["baseRevision"],
              f"fork revision: {fk['baseRevision']} {fi['revision']} {rf['revision']}")
        a.call("open_program", path=f"{fk['project']}:/{exe}", writable=True)
        a.call("rename", address=fn["address"], name="fork_change")
        sv = a.call("save")
        check(sv["projectRevision"] != fk["baseRevision"] and
              a.call("project", project=pa["id"])["revision"] == fk["baseRevision"],
              f"fork save: {sv}")
        notes.append("fork starts at its source's revision")
        # a writable project needs no refresh
        wr = a.call("refresh", project=fk["project"])
        check(wr["refreshed"] is False and "writable" in wr["reason"], f"writable: {wr}")
        a.call("close_project", project=fk["project"])
        a.call("close_project")
        b.call("close_project")
    d.stop()
    shutil.rmtree(c.work / "projRevFork", ignore_errors=True)
    return "; ".join(notes)


def t_overlays(c: Ctx):
    """Client-scoped overlays: two clients with different overlays on one shared program see
    different names, a third (and the owners without an overlay) see the canonical program; an
    operation that fails rolls back its whole call; killing an overlay's owner leaves the shared
    program untouched; promote writes an overlay into a fork; a refresh rebuilds overlays."""
    gpr = c.copy_fixture("projOverlay")
    exe = pathlib.Path(c.a.exe).name
    before = tree_state(gpr.parent)
    d = c.daemon("overlay", keepWarm=0)
    notes = []
    with d.connect("agent-a", "harness-a") as a, d.connect("agent-b", "harness-b") as b, \
            d.connect("plain", "harness-c") as x:
        for s in (a, b, x):
            s.call("open_project", path=str(gpr))
        t = time.perf_counter()
        ia = a.call("open_program", path=exe, overlay="agent-a")
        c.timings["overlay open (small program, shared program already open: no)"] = round(
            (time.perf_counter() - t) * 1000)
        check(ia["overlay"]["name"] == "agent-a" and ia["overlay"]["overlayVersion"] == 0 and
              ia["overlay"]["sha256"] == ia["sha256"] and ia["mode"] == "read_only",
              f"overlay open: {ia}")
        t = time.perf_counter()
        ib = b.call("open_program", path=exe, overlay="agent-b")
        c.timings["overlay open (small program, shared program open)"] = round(
            (time.perf_counter() - t) * 1000)
        x.call("open_program", path=exe)
        fns = [f for f in x.call("functions", limit=50)["functions"]
               if not f["thunk"] and not f["external"]]
        fn, fn2 = fns[0], fns[1]
        canon = x.call("decompile", address=fn["address"])["name"]
        ra = a.call("apply_overlay", overlay="agent-a", ops=[
            {"op": "rename", "address": fn["address"], "name": "a_name"},
            {"op": "comment", "address": fn["address"], "text": "agent a was here", "type": "plate"},
            {"op": "label", "address": fn2["address"], "name": "a_label"}])
        check(ra["applied"] == 3 and ra["overlay"]["overlayVersion"] == 1 and
              ra["overlay"]["ops"] == 3, f"apply_overlay: {ra}")
        rb = b.call("rename", overlay="agent-b", address=fn["address"], name="b_name")
        check(rb["overlay"]["overlayVersion"] == 1, f"overlay rename: {rb}")
        # each sees its own; the plain client and the owners' plain view see the canonical one
        check(a.call("decompile", overlay="agent-a", address=fn["address"])["name"] == "a_name",
              "agent a does not see its name")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name",
              "agent b does not see its name")
        check(x.call("decompile", address=fn["address"])["name"] == canon,
              "the plain client sees an overlay's name")
        check(a.call("decompile", address=fn["address"])["name"] == canon,
              "agent a's plain view sees its overlay")
        check(not x.call("functions", contains="a_name")["functions"] and
              not x.call("functions", contains="b_name")["functions"],
              "an overlay name leaked into the shared program")
        check(a.call("functions", overlay="agent-a", contains="a_name")["functions"] and
              not a.call("functions", overlay="agent-a", contains="b_name")["functions"],
              "overlay functions")
        inf = a.call("info", overlay="agent-a")
        check(inf["mode"] == "overlay" and inf["changed"] and inf["overlay"]["overlayVersion"] == 1
              and x.call("info")["changed"] is False, f"overlay info: {inf}")
        check(a.call("info")["overlays"] == ["agent-a"], "info does not list the overlay")
        notes.append("two overlays, two names; the shared program unchanged")
        # an overlay is private to its client: another client cannot use agent-a's
        expect_error("not_found", b.call, "decompile", overlay="agent-a", address=fn["address"])
        # a failing operation rolls back its whole call
        e = expect_error("bad_request", a.call, "apply_overlay", overlay="agent-a", ops=[
            {"op": "rename", "address": fn2["address"], "name": "never_applied"},
            {"op": "signature", "address": fn["address"], "signature": "this is ( not C"}])
        check(e.details.get("index") == 1 and e.details.get("rolledBack") is True,
              f"failure details: {e.details}")
        check(not a.call("functions", overlay="agent-a", contains="never_applied")["functions"],
              "a failed call left a change")
        check(a.call("info", overlay="agent-a")["overlay"]["overlayVersion"] == 1,
              "a failed call bumped the version")
        r = a.call("apply_overlay", overlay="agent-a", ops=[
            {"op": "signature", "address": fn["address"], "signature": "int a_name(int x)"},
            {"op": "data_type", "address": "rva:0x3c", "type": "dword"}])
        check("a_name(int x)" in r["results"][0]["signature"] and
              r["results"][1]["length"] == 4 and r["overlay"]["overlayVersion"] == 2,
              f"signature/data_type: {r}")
        check("int x" not in x.call("decompile", address=fn["address"])["signature"] or
              "int x" in canon, "the signature leaked")
        notes.append("a failing op rolls back the whole call")
        st = x.call("status")
        ovs = {(o["client"], o["name"]) for o in st["overlays"]}
        check((a.hello["client"], "agent-a") in ovs and (b.hello["client"], "agent-b") in ovs,
              f"status overlays: {st['overlays']}")
        # killing an overlay's owner drops its overlay and leaves the shared program untouched
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='overlay',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2])\n"
                "s.call('open_program', path=A[3], overlay='doomed')\n"
                "s.call('rename', overlay='doomed', address=A[4], name='doomed_name')\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, fn["address"])
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        doomed = json.loads(line)["client"]
        p.kill()
        p.wait()
        for _ in range(100):
            if all(o["client"] != doomed for o in x.call("status")["overlays"]):
                break
            time.sleep(0.1)
        check(all(o["client"] != doomed for o in x.call("status")["overlays"]),
              "the dead client's overlay is still listed")
        check(not x.call("functions", contains="doomed_name")["functions"] and
              x.call("decompile", address=fn["address"])["name"] == canon,
              "the dead client's overlay touched the shared program")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name",
              "another overlay was disturbed")
        notes.append("killed owner: overlay dropped, shared program untouched")
        # promote writes the overlay into a fork; the master stays as it was
        pr = a.call("promote_overlay", overlay="agent-a",
                    fork={"path": str(c.work / "projOverlayFork")}, wait=600000)
        check(pr["promoted"] == 5 and pr["fork"]["project"] == pr["project"] and
              pr["saved"]["saved"], f"promote: {pr}")
        fk = pr["target"]
        check(a.call("decompile", program=fk, address=fn["address"])["name"] == "a_name" and
              a.call("functions", program=fk, contains="a_label")["functions"],
              "the promoted fork lacks the overlay's changes")
        check(x.call("decompile", address=fn["address"])["name"] == canon,
              "promote changed the master")
        a.call("close_project", project=pr["project"])
        notes.append("promote_overlay replayed 5 ops into a fork and saved it")
        # a refresh rebuilds overlays from their logs
        d2 = c.daemon("overlay-writer")
        with d2.connect("writer", "tests") as w:
            w.call("open_project", path=str(gpr), writable=True)
            w.call("open_program", path=exe, writable=True)
            w.call("rename", address=fn2["address"], name="saved_elsewhere")
            w.call("save")
            w.call("close_project")
        d2.stop()
        before = tree_state(gpr.parent)  # the master was changed on purpose by another process
        rf = x.call("refresh")
        check(rf["refreshed"], f"refresh: {rf}")
        ob = b.call("info", overlay="agent-b")["overlay"]
        check(ob["error"] is None and not ob["stale"], f"overlay after refresh: {ob}")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name" and
              b.call("functions", overlay="agent-b", contains="saved_elsewhere")["functions"],
              "the rebuilt overlay lacks its change or the new save")
        notes.append("refresh rebuilt the overlays")
        dr = a.call("drop_overlay", overlay="agent-a")
        check(dr["dropped"] and dr["ops"] == 5, f"drop: {dr}")
        expect_error("not_found", a.call, "info", overlay="agent-a")
        for s in (a, b, x):
            s.call("close_project")
    d.stop()
    check(tree_state(gpr.parent) == before, "the master project changed")
    shutil.rmtree(c.work / "projOverlayFork", ignore_errors=True)
    return "; ".join(notes)


COMMENTS = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
public class TestComments extends GhidraScript {
    @Override protected void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address at = currentProgram.getAddressFactory().getAddress(a);
            String c = currentProgram.getListing().getComment(CommentType.EOL, at);
            println("C|" + a + "|" + (c == null ? "" : c));
        }
    }
}
"""


def comments_at(s, addresses, program=None):
    """{address: EOL comment} through a contained script."""
    path = s_scripts_dir / "TestComments.java"
    if not path.exists():
        path.write_text(COMMENTS)
    kw = {"program": program} if program else {}
    out = s.call("script", script=str(path), args=list(addresses), maxChars=16_000_000,
                 wait=120000, **kw)["output"]
    res = {}
    for line in out.splitlines():
        if line.startswith("C|"):
            _, a, text = line.split("|", 2)
            res[a] = text
    return res


def names_at(s, program=None):
    kw = {"program": program} if program else {}
    return {f["address"]: f["name"] for f in
            s.call("functions", limit=10000, **kw)["functions"]}


def code_functions(s, n, program=None):
    kw = {"program": program} if program else {}
    return [f["address"] for f in s.call("functions", limit=10000, **kw)["functions"]
            if not f["thunk"] and not f["external"]][:n]


def t_multi_writer(c: Ctx):
    """Several writers in one project: a writable open while others hold the read-only view
    reopens it writable in place (the readers keep their keys and go on); a second writable
    open joins; two clients write two different programs of the project at the same time
    (renames, comments, saves) independently; a writer of a program another client owns gets
    not_owner with overlay/fork alternatives; the project reopens with both writers' work."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projMW")
    exe, dll = pathlib.Path(c.a.exe).name, pathlib.Path(c.a.dll).name
    d0 = c.daemon("mw-setup")
    with d0.connect("setup", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("import", file=c.a.dll, analyze=True, timeout=1800, wait=600000)
        s.call("close_project")
    d0.stop()
    d = c.daemon("mw", keepWarm=0)
    notes = []
    with d.connect("reader", "tests") as r, d.connect("w1", "tests") as w1, \
            d.connect("w2", "tests") as w2:
        pr = r.call("open_project", path=str(gpr))
        ri = r.call("open_program", path=exe)
        fn = code_functions(r, 1)[0]
        canon = r.call("decompile", address=fn)["name"]
        p1 = w1.call("open_project", path=str(gpr), writable=True)
        check(p1["id"] == pr["id"] and p1["writable"], f"not reopened writable in place: {p1}")
        check(r.call("decompile", address=fn)["name"] == canon and
              r.call("info")["key"] == ri["key"], "the reader lost its program")
        check(r.call("project")["writable"], "the reader does not see the writable project")
        notes.append("writable open while a reader holds the view: reopened in place")
        p2 = w2.call("open_project", path=str(gpr), writable=True)
        check(p2["id"] == pr["id"], f"second writable open did not join: {p2}")
        k1 = w1.call("open_program", path=exe, writable=True)["key"]
        k2 = w2.call("open_program", path=dll, writable=True)["key"]
        e = expect_error("not_owner", w2.call, "open_program", path=exe, writable=True)
        check(e.details.get("alternatives") == ["overlay", "fork_project"] and
              e.details.get("overlaySuggestion", {}).get("overlay") and
              (e.details.get("holderInfo") or {}).get("name") == "w1",
              f"not_owner alternatives: {e.details}")
        f1 = code_functions(w1, 30, k1)
        f2 = code_functions(w2, 30, k2)
        errs = []
        want = {k1: {}, k2: {}}

        def writer(s, key, fns, tag):
            try:
                for i in range(300):
                    a = fns[i % len(fns)]
                    name = f"{tag}_{i}"
                    s.call("rename", program=key, address=a, name=name, wait=120000)
                    want[key][a] = name
                    s.call("comment", program=key, address=a, text=f"{tag} {i}", wait=120000)
                    if i % 50 == 49:
                        s.call("save", program=key, wait=120000)
                    if i == 150:  # a bounded analysis of each program, at the same time
                        s.call("analyze", program=key, ranges=[[a, a]], timeout=600,
                               wait=600000)
                s.call("save", program=key, wait=120000)
            except Exception as ex:  # noqa: BLE001
                errs.append(f"{tag}: {ex!r}")

        t = time.perf_counter()
        ths = [threading.Thread(target=writer, args=(w1, k1, f1, "w1")),
               threading.Thread(target=writer, args=(w2, k2, f2, "w2"))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        c.timings["two writers, two programs: 2x(300 renames + 300 comments + 7 saves)"] = round(
            time.perf_counter() - t, 1)
        check(not errs, f"concurrent writers failed: {errs}")
        notes.append(f"2 writers x 600 edits + saves on 2 programs in "
                     f"{c.timings['two writers, two programs: 2x(300 renames + 300 comments + 7 saves)']} s")
        for s in (r, w1, w2):
            s.call("close_project")
    d.stop()
    # the project reopens clean, with both writers' work
    d2 = c.daemon("mw-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        for key, prog in ((k1, exe), (k2, dll)):
            s.call("open_program", path=prog)
            names = names_at(s)
            bad = {a: (n, names.get(a)) for a, n in want[key].items() if names.get(a) != n}
            check(not bad, f"{prog}: names lost after reopen: {list(bad.items())[:5]}")
    d2.stop()
    notes.append("project reopened with every saved name of both writers")
    return "; ".join(notes)


def t_shared(c: Ctx):
    """Shared mode: several clients write the same program; every change is journalled with
    its author; expect turns a lost update into a conflict naming the last editor; owner and
    shared mode do not mix; discard_edits reverts one client's changes; a writer that dies
    keeps everyone's committed work, also when it was the last writer (the work waits, unsaved,
    for a client to save it)."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projShared")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("shared", keepWarm=0)
    notes = []
    with d.connect("agent-a", "harness-a") as a, d.connect("agent-b", "harness-b") as b, \
            d.connect("agent-c", "harness-c") as x:
        for s in (a, b, x):
            s.call("open_project", path=str(gpr), writable=True)
        io = a.call("open_program", path=exe, writable=True)      # owner mode first
        check(io["mode"] == "writable" and io["mine"], f"owner open: {io}")
        e = expect_error("not_owner", b.call, "open_program", path=exe, writable=True, share=True)
        check(e.details.get("alternatives") == ["overlay", "fork_project"], f"{e.details}")
        ia = a.call("open_program", path=exe, writable=True, share=True)  # the owner shares it
        ib = b.call("open_program", path=exe, writable=True, share=True)
        check(ia["mode"] == "shared" and ib["writers"] == [a.hello["client"], b.hello["client"]],
              f"shared open: {ib}")
        f = code_functions(a, 6)
        names0 = names_at(a)
        r1 = a.call("rename", address=f[0], name="a_first")
        r2 = b.call("rename", address=f[1], name="b_second")
        b.call("comment", address=f[1], text="b was here")
        check(names_at(b)[f[0]] == "a_first" and names_at(a)[f[1]] == "b_second",
              "writers do not see each other's changes")
        check(r1["seq"] < r2["seq"], f"journal order: {r1} {r2}")
        # owner and shared mode do not mix; a non-writer is told to join
        e = expect_error("conflict", x.call, "open_program", path=exe, writable=True)
        check(e.details.get("suggest") == "share", f"mixing modes: {e.details}")
        x.call("open_program", path=exe)
        e = expect_error("not_owner", x.call, "rename", address=f[0], name="x_nope")
        check(e.details.get("suggest") == "share", f"non-writer: {e.details}")
        # a lost update becomes a conflict naming who changed it
        b.call("rename", address=f[0], name="b_over_a", expect="a_first")
        e = expect_error("conflict", a.call, "rename", address=f[0], name="a_again",
                         expect="a_first")
        check(e.details.get("current") == "b_over_a" and
              (e.details.get("holderInfo") or {}).get("name") == "agent-b" and
              e.details.get("suggest") == "reread", f"expect conflict: {e.details}")
        notes.append("expect: a lost update is a conflict naming the last editor")
        an = b.call("analyze", ranges=[[f[5], f[5]]], timeout=600, wait=600000)
        check(an["seq"] > 0, f"analyze by a shared writer: {an}")
        j = a.call("journal")
        ops = [(x_["op"], x_["name"], x_.get("address")) for x_ in j["entries"]]
        check(("rename", "agent-a", f[0]) in ops and ("comment", "agent-b", f[1]) in ops and
              any(o[0] == "analyze" and o[1] == "agent-b" for o in ops) and
              j["seq"] == len(j["entries"]), f"journal: {j}")
        # discard_edits reverts one client's changes, newest first, and keeps the others'
        dr = a.call("discard_edits", author=b.hello["client"])
        names = names_at(a)
        check(names[f[0]] == "a_first" and names[f[1]] == names0[f[1]] and
              len(dr["reverted"]) == 3, f"discard_edits: {dr} {names[f[0]]} {names[f[1]]}")
        check(comments_at(a, [f[1]])[f[1]] == "", "b's comment was not reverted")
        notes.append("discard_edits reverted b's 3 changes, kept a's")
        # a writer that dies: its committed work stays
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='shared',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "s.call('open_program', path=A[3], writable=True, share=True)\n"
                "s.call('rename', address=A[4], name='doomed_kept')\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, f[2])
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        p.kill()
        p.wait()
        time.sleep(1.0)
        check(names_at(a)[f[2]] == "doomed_kept", "a dead writer's committed change was lost")
        notes.append("a dead writer's committed change stays")
        a.call("save")
        # the last writer dies with unsaved changes: they are kept for a client to save
        b.call("rename", address=f[3], name="b_unsaved")
        a.call("close_program")
        x.call("close_program")
        p = c.child(code.replace("'doomed_kept'", "'last_writer'"), c.state, c.a.ghidra, gpr,
                    exe, f[4])
        line = p.stdout.readline()
        check(line, "second child did not start")
        b.call("close_project")   # not the last writer: leaves fine, its change unsaved
        p.kill()
        p.wait()
        for s in (a, x):
            s.call("close_project")
        time.sleep(2.5)  # past the reaper (keepWarm 0)
        st = a.call("status")
        held = [pg for pg in st["programs"] if pg["path"] == "/" + exe]
        check(held and held[0]["mode"] == "shared" and held[0]["writers"] == [] and
              held[0]["orphanedMs"] is not None and held[0]["unsavedEdits"] >= 2,
              f"orphaned work not kept: {held}")
        notes.append("the last writer died: unsaved work kept, project stays open")
        a.call("open_project", path=str(gpr), writable=True)
        ia = a.call("open_program", path=exe, writable=True, share=True)
        check(ia["unsavedEdits"] >= 2 and names_at(a)[f[3]] == "b_unsaved" and
              names_at(a)[f[4]] == "last_writer", f"adopted work: {ia}")
        a.call("save")
        a.call("close_project")
    d.stop()
    d2 = c.daemon("shared-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        check(names[f[0]] == "a_first" and names[f[2]] == "doomed_kept" and
              names[f[3]] == "b_unsaved" and names[f[4]] == "last_writer",
              f"after reopen: {[names[x_] for x_ in f[:5]]}")
    d2.stop()
    notes.append("reopened: every kept change saved")
    return "; ".join(notes)


def t_shared_stress(c: Ctx):
    """4 clients x 2 threads write one shared program at once: 3200 renames and comments,
    with saves in between. No deadlock, no failed or lost committed edit: the journal has every
    edit once, in commit order; the program holds, per address, the value of the last edit; it
    reopens clean with all of it."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projStress")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("stress", keepWarm=0)
    sessions = [d.connect(f"agent-{i}", f"harness-{i}") for i in range(4)]
    for s in sessions:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("open_program", path=exe, writable=True, share=True)
    fns = code_functions(sessions[0], 40)
    done, errs = [], []
    lock = threading.Lock()

    def worker(s, cid, t):
        try:
            for i in range(400):
                a = fns[(cid * 7 + t * 13 + i) % len(fns)]
                if i % 2 == 0:
                    r = s.call("rename", address=a, name=f"s{cid}_{t}_{i}", parallel=True,
                               wait=300000)
                    item = (r["seq"], a, "name", f"s{cid}_{t}_{i}")
                else:
                    r = s.call("comment", address=a, text=f"c{cid}_{t}_{i}", parallel=True,
                               wait=300000)
                    item = (r["seq"], a, "comment", f"c{cid}_{t}_{i}")
                with lock:
                    done.append(item)
                if i % 50 == 49:
                    s.call("save", parallel=True, wait=300000)
        except Exception as ex:  # noqa: BLE001
            errs.append(f"{cid}/{t}: {ex!r}")

    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(s, cid, t)) for cid, s in enumerate(sessions)
           for t in range(2)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(timeout=1800)
    secs = time.perf_counter() - t0
    check(not any(th.is_alive() for th in ths), "a writer hung (deadlock?)")
    check(not errs, f"edits failed: {errs[:5]}")
    c.timings["shared stress: 3200 edits by 8 writers"] = round(secs, 1)
    check(len(done) == 3200, f"{len(done)} edits done")
    s0 = sessions[0]
    j = s0.call("journal", limit=100000)
    seqs = [e["seq"] for e in j["entries"]]
    check(len(seqs) == 3200 and len(set(seqs)) == 3200 and seqs == sorted(seqs) and
          {x[0] for x in done} == set(seqs), f"journal: {len(seqs)} entries")
    last = {}
    for seq, a, field, value in sorted(done):
        last[(a, field)] = value
    names = names_at(s0)
    comments = comments_at(s0, fns)
    bad = [(k, v) for k, v in last.items()
           if (names.get(k[0]) if k[1] == "name" else comments.get(k[0])) != v]
    check(not bad, f"the program does not hold the last edit: {bad[:5]}")
    s0.call("save", wait=300000)
    for s in sessions:
        s.call("close_project")
        s.close()
    d.stop()
    d2 = c.daemon("stress-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        comments = comments_at(s, fns)
        bad = [(k, v) for k, v in last.items()
               if (names.get(k[0]) if k[1] == "name" else comments.get(k[0])) != v]
        check(not bad, f"after reopen: {bad[:5]}")
    d2.stop()
    return (f"3200 edits by 4 clients x 2 threads with 64 saves in {secs:.1f} s "
            f"({3200 / secs:.0f}/s); journal complete and ordered; reopened with every last "
            f"value")


TESTS = ["two_harnesses", "two_projects", "dll_import", "client_kill", "daemon_restart",
         "fairness", "cancel_all", "import_queue", "import_isolation", "caller_labels",
         "idle_shutdown", "keep_warm", "stdio", "upgrade_cache", "holders", "fork", "revisions",
         "overlays", "multi_writer", "shared", "shared_stress"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--dll", required=True)
    ap.add_argument("--project", help="an analysed project to open read-only (never written)")
    ap.add_argument("--legacy-project", dest="legacy_project",
                    help="a project saved by an older Ghidra, for upgrade_cache (only copied)")
    ap.add_argument("--legacy-program", dest="legacy_program",
                    help="the program in it to open (default: the first one)")
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemons (default: <work>/tmp; "
                    "'default': leave it to the JVM)")
    ap.add_argument("--raw-mb", dest="raw_mb", type=int, default=128,
                    help="size of the random raw binary the import queue test imports "
                    "(default 128): large enough that an import outlasts the polling")
    ap.add_argument("--only")
    a = ap.parse_args()
    sys.path.insert(0, str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import ghidra_session as gs
    c = Ctx(a, gs)
    names = a.only.split(",") if a.only else TESTS
    failed = 0
    try:
        for n in names:
            t = time.perf_counter()
            try:
                note = globals()["t_" + n](c)
                print(f"ok   {n:16s} {time.perf_counter() - t:7.1f} s  {note}", flush=True)
            except Exception as e:  # noqa: BLE001
                failed += 1
                print(f"FAIL {n:16s} {time.perf_counter() - t:7.1f} s  {type(e).__name__}: {e}"
                      f"{' ' + json.dumps(e.details) if getattr(e, 'details', None) else ''}"
                      f" at line {e.__traceback__.tb_next.tb_lineno if e.__traceback__.tb_next else '?'}",
                      flush=True)
                c.cleanup()
    finally:
        c.cleanup()
    print("timings:", json.dumps(c.timings, indent=1))
    print(f"{len(names) - failed}/{len(names)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
