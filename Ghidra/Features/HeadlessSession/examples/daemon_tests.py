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
                           [--project <an analysed project, opened read-only>] [--only a,b]

Each test starts its own daemon instance in <work>/state and stops it, so the user's daemon is
never touched. --project (optional) adds an existing analysed project, which is only ever opened
read-only, to the multi-project test.

Tests: two_harnesses, two_projects, dll_import, client_kill, daemon_restart, fairness, cancel_all,
idle_shutdown, keep_warm, stdio.
"""
import argparse
import json
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
        (self.state / "config.json").write_text(json.dumps(
            {"tmpdir": a.tmpdir or str(self.work / "tmp"), "scriptPath": [str(self.scripts)]}))
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
        nct = None
        if c.a.project:
            nct = x.call("open_project", path=c.a.project)
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
        want = 3 if nct else 2
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


TESTS = ["two_harnesses", "two_projects", "dll_import", "client_kill", "daemon_restart",
         "fairness", "cancel_all", "idle_shutdown", "keep_warm", "stdio"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--dll", required=True)
    ap.add_argument("--project", help="an analysed project to open read-only (never written)")
    ap.add_argument("--tmpdir")
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
                print(f"FAIL {n:16s} {time.perf_counter() - t:7.1f} s  {type(e).__name__}: {e}",
                      flush=True)
                c.cleanup()
    finally:
        c.cleanup()
    print("timings:", json.dumps(c.timings, indent=1))
    print(f"{len(names) - failed}/{len(names)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
