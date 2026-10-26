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
idle_shutdown, keep_warm, stdio, upgrade_cache, holders, fork.
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
        # a read-only view in use: a writable open is refused, naming the reader, suggesting a fork
        pa = a.call("open_project", path=str(gpr))
        e = expect_error("conflict", b.call, "open_project", path=str(gpr), writable=True)
        dt = e.details
        names = [(h.get("name"), h.get("harness")) for h in dt.get("holders", [])]
        check(("reader-a", "harness-a") in names, f"conflict does not name the reader: {dt}")
        check(dt.get("project") == pa["id"] and dt.get("gpr"), f"no project identity: {dt}")
        check(dt.get("suggest") == "fork_project" and
              dt.get("suggestion", {}).get("cmd") == "fork_project" and
              dt["suggestion"].get("project") == pa["id"] and dt["suggestion"].get("path"),
              f"no fork suggestion: {dt}")
        check(all(isinstance(h.get("heldMs"), int) for h in dt["holders"]), f"no heldMs: {dt}")
        notes.append("conflict names reader + suggests fork_project")
        # writing to a read-only view: read_only, with the same suggestion
        b.call("open_project", path=str(gpr))
        e = expect_error("read_only", b.call, "open_program", path=exe, writable=True)
        check(e.details.get("suggest") == "fork_project", f"read_only: {e.details}")
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


TESTS = ["two_harnesses", "two_projects", "dll_import", "client_kill", "daemon_restart",
         "fairness", "cancel_all", "idle_shutdown", "keep_warm", "stdio", "upgrade_cache",
         "holders", "fork"]


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
