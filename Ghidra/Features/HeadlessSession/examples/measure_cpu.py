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
"""Measure the CPU seconds and the wall seconds of every test of the engine suites (virtual-time design, package T0).

    python measure_cpu.py --ghidra <install> --scratch <dir on a fast disk> --logs <dir> [--jobs 3] [--suites a,b]
        [--only t1,t2] [--update-costs] [--fixed-reps 3]
    python measure_cpu.py ... --fixed-only            # just the fixed costs (daemon start/stop, project copy + import)

Each test runs ALONE in its own process (`<suite> --only <test>`, its own --work/--tmpdir under --scratch), at most --jobs
(default 3) at a time so that the numbers stay clean. While it runs, a sampler records the CPU time (user + kernel, from
GetProcessTimes, no psutil) of the whole process tree: the python client, and every JVM that belongs to the run, whether
it is a child (the harness spawns daemons detached) or was started outside the tree (WMI / scheduled-task spawn routes:
those are found by the run's unique scratch directory in their command line). Process handles are kept open until the
run ends, so the CPU of a process that exited between two samples is still counted.

Columns (CSV and ranking):
    cpuS        user + kernel CPU seconds of the run, every process of the tree (python + JVMs), whole process incl. start-up
    jvmCpuS     the part of cpuS spent in java.exe processes (the daemons), pyCpuS the rest (client, harness, helpers)
    wallS       wall seconds of the whole run (process start to the last tree process exit), the same bounds as cpuS
    testS       the seconds the suite itself reports for the test (what suite-costs.json records)
    waitShare   max(0, 1 - cpuS / wallS): the share of wall time the tree spent not on a CPU (cpuPerWall > 1: JVM start-up,
                JIT and GC use several cores at once, so short tests show cpuS above wallS and a wait share of 0)
    peakCores   highest CPU rate over any 1 s window (cores)
    cpuNetS     cpuS minus the cost of the shared fixture import, for the tests that build it themselves (see fixed costs)
Because every test runs alone, a test that uses the lazily built exe fixture (daemon_tests Ctx.fixture) pays its import and
analysis here; in a whole-suite run that is paid once. `fixtureUsed` marks them and cpuNetS removes the measured fixture
cost (fixed probe `fixture_import_analyze`).

The fixed costs (the part that dominates the intrinsic work) are measured by two probes, run in this script's own
subprocesses with the same sampler, and phase boundaries read from the timeline: `daemon_cycle` (start, connect, stop) and
`project_import` (make project, import exe without and with analysis, stop, copy the project, start on the copy, open).

Output in --logs: measure.csv, fixed.csv, ranking.txt, results.json, one log per run. With --update-costs the data are
merged into suite-costs.json next to this file under the key `<suite>#t0` (a sibling of `<suite>`, like
`<suite>#heavy`): run_parallel.py reads only `<suite>` (seconds per test), so these keys are additive:
    {"<suite>#t0": {"<test>": {"cpuS", "wallS", "testS", "kind", "minScale", "peakCores", "waitShare"}},
     "_t0": {"fixed": {...}, "machine": ..., "date": ...}}
`kind` is a placeholder classification from the design (section 2d: "real" = stays real-time, "unclassified" otherwise),
`minScale` is null until the flake check of the design (section 4) sets it.

Run it wrapped:  python heavy.py --cores 6 -- python measure_cpu.py ...
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.wintypes as wt
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COSTS = HERE / "suite-costs.json"
TEST_TIMEOUT_S = 900

# ---- the design's "stays real" list (section 2d), as name patterns: placeholder `kind` data --------------------------
REAL = re.compile(r"^(e8_|run_c|chaos_|backup_fault|e2a_kill_fork|e2a_client_kill|import_kill|import_write_kill|save_time|"
                  r"private_open_cost|import_speed|import_readers|shared_stress|multi_writer|p1b_daemon_survives|"
                  r"p1b_concurrent_launchers|p1b_duplicate_daemon|daemon_restart)")

# ---- Win32 through ctypes ------------------------------------------------------------------------------------------
K32 = ctypes.WinDLL("kernel32", use_last_error=True)
NT = ctypes.WinDLL("ntdll")
INVALID = ctypes.c_void_p(-1).value
K32.OpenProcess.restype = ctypes.c_void_p
K32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
K32.CloseHandle.argtypes = [ctypes.c_void_p]
K32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(wt.FILETIME)] * 4
K32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
K32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
NT.NtQueryInformationProcess.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


K32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
K32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
QUERY_LIMITED, QUERY, VM_READ = 0x1000, 0x0400, 0x0010
STILL_ACTIVE = 259


def ft(f) -> int:
    return (f.dwHighDateTime << 32) | f.dwLowDateTime


def snapshot() -> list[tuple[int, int, str]]:
    """(pid, parent pid, image name) of every process."""
    h = K32.CreateToolhelp32Snapshot(2, 0)
    out = []
    if not h or h == INVALID:
        return out
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = K32.Process32FirstW(h, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.th32ParentProcessID, e.szExeFile))
            ok = K32.Process32NextW(h, ctypes.byref(e))
    finally:
        K32.CloseHandle(h)
    return out


def cmdline_of(h) -> str:
    """The command line of an x64 process from its PEB (empty when unreadable)."""
    try:
        pbi = (ctypes.c_uint64 * 6)()
        if NT.NtQueryInformationProcess(h, 0, pbi, 48, None) != 0:
            return ""

        def rd(addr, n):
            buf = ctypes.create_string_buffer(n)
            got = ctypes.c_size_t()
            if not K32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) or got.value != n:
                raise OSError
            return buf.raw

        peb = pbi[1]
        params = int.from_bytes(rd(peb + 0x20, 8), "little")
        us = rd(params + 0x70, 16)
        length, buf = int.from_bytes(us[0:2], "little"), int.from_bytes(us[8:16], "little")
        return rd(buf, length).decode("utf-16-le", "replace") if length else ""
    except (OSError, ValueError):
        return ""


class Proc:
    def __init__(self, pid, handle, image, created):
        self.pid, self.h, self.image, self.created = pid, handle, image.lower(), created

    def cpu_s(self) -> float:
        c, e, k, u = (wt.FILETIME() for _ in range(4))
        if not K32.GetProcessTimes(self.h, c, e, k, u):
            return 0.0
        return (ft(k) + ft(u)) / 1e7

    def alive(self) -> bool:
        code = wt.DWORD()
        return bool(K32.GetExitCodeProcess(self.h, ctypes.byref(code))) and code.value == STILL_ACTIVE

    def start(self) -> int:
        c, e, k, u = (wt.FILETIME() for _ in range(4))
        K32.GetProcessTimes(self.h, c, e, k, u)
        return ft(c)


class Tracker(threading.Thread):
    """Follows one run: the root process, its descendants and every process whose command line has `token`."""

    TICK = 0.05

    def __init__(self, root_pid: int, token: str):
        super().__init__(daemon=True)
        self.root_pid = root_pid
        self.token = token.lower().replace("/", "\\")
        self.procs: dict[int, Proc] = {}
        self.ignored: set[int] = set()
        self.timeline: list[tuple[float, float]] = []   # (time.time(), cumulative cpu seconds)
        self.stop_flag = threading.Event()
        self.last_alive = time.time()

    def _adopt(self, pid, image, why):
        h = K32.OpenProcess(QUERY_LIMITED | QUERY | VM_READ, False, pid) or K32.OpenProcess(QUERY_LIMITED, False, pid)
        if not h:
            return
        p = Proc(pid, h, image, 0)
        p.created = p.start()
        p.why = why
        self.procs[pid] = p

    def scan(self):
        snap = snapshot()
        alive_pids = {p for p, _, _ in snap}
        self.ignored &= alive_pids      # a reused pid is looked at again
        for pid, ppid, image in snap:
            if pid in self.procs or pid in self.ignored:
                continue
            if pid == self.root_pid:
                self._adopt(pid, image, "root")
                continue
            parent = self.procs.get(ppid)
            if parent is not None:
                self._adopt(pid, image, "child")
                child = self.procs.get(pid)
                if child is not None and child.created < parent.created:    # pid reuse: not really its child
                    K32.CloseHandle(self.procs.pop(pid).h)
                    self.ignored.add(pid)
                continue
            if image.lower() in ("java.exe", "javaw.exe"):
                h = K32.OpenProcess(QUERY_LIMITED | QUERY | VM_READ, False, pid)
                if h:
                    cl = cmdline_of(h).lower().replace("/", "\\")
                    if self.token in cl:
                        p = Proc(pid, h, image, 0)
                        p.created = p.start()
                        p.why = "token"
                        self.procs[pid] = p
                        continue
                    K32.CloseHandle(h)
            self.ignored.add(pid)

    def total(self) -> float:
        return sum(p.cpu_s() for p in self.procs.values())

    def any_alive(self) -> bool:
        return any(p.alive() for p in self.procs.values())

    def run(self):
        while True:
            self.scan()
            self.timeline.append((time.time(), self.total()))
            if self.any_alive():
                self.last_alive = time.time()
            if self.stop_flag.is_set():
                break
            time.sleep(self.TICK)

    def finish(self):
        self.stop_flag.set()
        self.join()
        self.timeline.append((time.time(), self.total()))

    def cpu_at(self, t: float) -> float:
        tl = self.timeline
        if not tl:
            return 0.0
        if t <= tl[0][0]:
            return tl[0][1]
        for (t0, c0), (t1, c1) in zip(tl, tl[1:]):
            if t0 <= t <= t1:
                return c0 + (c1 - c0) * ((t - t0) / (t1 - t0) if t1 > t0 else 0)
        return tl[-1][1]

    def survivors(self) -> list[Proc]:
        return [p for p in self.procs.values() if p.alive() and p.pid != self.root_pid]

    def peak_cores(self, window=1.0) -> float:
        tl, best, j = self.timeline, 0.0, 0
        for i in range(len(tl)):
            while tl[i][0] - tl[j][0] > window:
                j += 1
            span = tl[i][0] - tl[j][0]
            if span >= window * 0.5:
                best = max(best, (tl[i][1] - tl[j][1]) / span)
        return best

    def split(self) -> tuple[float, float]:
        jvm = sum(p.cpu_s() for p in self.procs.values() if p.image in ("java.exe", "javaw.exe"))
        return jvm, self.total() - jvm

    def kill_all(self):
        for p in list(self.procs.values()):
            if p.alive():
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)

    def close(self):
        for p in self.procs.values():
            K32.CloseHandle(p.h)
        self.procs.clear()


# ---- running one measured command ----------------------------------------------------------------------------------
def measure(cmd: list[str], token: str, log: Path, timeout: float = TEST_TIMEOUT_S, cwd: Path = HERE, env=None) -> dict:
    """Run cmd to its end; return wall/CPU numbers of the whole tree plus the tracker (timeline) for phase maths."""
    t0 = time.time()
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
        tr = Tracker(p.pid, token)
        tr.start()
        timed_out = False
        try:
            code = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            tr.kill_all()
            code = p.wait()
        # the run is over when the root exited; wait (bounded) for the daemons it left
        end_root = time.time()
        while tr.any_alive() and time.time() - end_root < 10:
            time.sleep(0.1)
        wall = max(tr.last_alive, end_root) - t0
        leaked = len(tr.survivors())
        tr.finish()
        jvm, py = tr.split()
        res = {"exit": code, "timedOut": timed_out, "wallS": wall, "cpuS": jvm + py, "jvmCpuS": jvm, "pyCpuS": py,
               "peakCores": tr.peak_cores(), "procs": len(tr.procs), "leaked": leaked, "t0": t0, "tracker": tr}
    if leaked:
        tr.kill_all()
    tr.close()
    return res


def suite_args(a, scratch_run: Path) -> list[str]:
    return ["--ghidra", a.ghidra, "--work", str(scratch_run / "w"), "--tmpdir", str(scratch_run / "t")]


def parse_names(out: str) -> list[str]:
    names = []
    for line in out.splitlines():
        m = re.match(r"\s*(\w[\w-]*)", line)
        if m and not line.startswith("FAIL"):
            names.append(m.group(1))
    return names


def tasks_of(a, scratch: Path) -> list[dict]:
    """[{suite, test, cmd (without --only), key}] for every selected suite, names from --list (or fixed lists)."""
    py = sys.executable
    exe, dll = a.exe, a.dll
    leg = a.legacy_project
    only = {x for x in a.only.split(",") if x}
    tasks = []

    def listing(script, extra=()):
        d = scratch / "_list" / script
        r = subprocess.run([py, str(HERE / script), "--ghidra", a.ghidra, "--work", str(d / "w"), "--tmpdir", str(d / "t"),
                            *extra, "--list"], cwd=HERE, capture_output=True, text=True)
        shutil.rmtree(d, ignore_errors=True)
        if not r.stdout.strip():
            sys.exit(f"{script} --list failed: {(r.stdout + r.stderr)[-800:]}")
        return r.stdout

    def add(suite, script, names, extra, rep="--report"):
        for n in names:
            if only and n not in only:
                continue
            tasks.append({"suite": suite, "test": n, "script": script, "extra": list(extra), "report": rep})

    want = set(a.suites.split(","))
    dt_extra = ["--exe", exe, "--dll", dll] + (["--legacy-project", leg] if leg else [])
    if "daemon_tests.py" in want:
        add("daemon_tests.py", "daemon_tests.py", parse_names(listing("daemon_tests.py", dt_extra)), dt_extra)
    if "client_compat_tests.py" in want:
        add("client_compat_tests.py", "client_compat_tests.py", parse_names(listing("client_compat_tests.py", dt_extra)),
            dt_extra)
    if "contract_tests.py" in want:
        src = (HERE / "contract_tests.py").read_text(encoding="utf-8")
        names = re.search(r"^TESTS = \[(.*?)\]", src, re.M | re.S).group(1)
        add("contract_tests.py", "contract_tests.py", re.findall(r'"(\w+)"', names), [], rep=None)
    if "characterization_tests.py" in want:
        for proto in (2, 3):
            lines = listing("characterization_tests.py", ["--protocol", str(proto)]).splitlines()
            names = [l.split()[0] for l in lines if l.strip() and re.search(r"protocols\s+%d\b" % proto, l)]
            suite = "characterization_tests.py" if proto == 2 else "characterization_tests.py@v3"
            add(suite, "characterization_tests.py", names, ["--protocol", str(proto)], rep=None)
    if "session_smoke.py" in want and (not only or "session_smoke" in only):
        tasks.append({"suite": "session_smoke.py", "test": "session_smoke", "script": "session_smoke.py",
                      "extra": ["--binary", exe, "--binary", dll], "report": None, "whole": True})
    return tasks


RESULT_LINE = re.compile(r"^(ok|FAIL|SKIP|PASS)\s+(\S+)\s+([\d.]+) s", re.M)


def run_task(a, t, scratch: Path, logs: Path, slot: int) -> dict:
    name = re.sub(r"[^\w@.-]", "_", t["suite"].replace(".py", "") + "-" + t["test"])
    run = scratch / f"r{slot}-{name}"
    shutil.rmtree(run, ignore_errors=True)
    run.mkdir(parents=True)
    tpl = scratch / "_fixture-template" / "fixture"
    seeded = t["suite"] in ("daemon_tests.py", "client_compat_tests.py") and (tpl / "Fixture.gpr").exists()
    if seeded:      # the exe fixture is built once in the fixed probe (counted there), not by every test run alone
        shutil.copytree(tpl, run / "w" / "fixture")
    cmd = [sys.executable, str(HERE / t["script"]), *suite_args(a, run), *t["extra"]]
    if not t.get("whole"):
        cmd += ["--only", t["test"]]
    rep = run / "report.json"
    if t["report"]:
        cmd += ["--report", str(rep)]
    log = logs / f"{name}.log"
    r = measure(cmd, str(run), log, cwd=HERE)
    text = log.read_text(encoding="utf-8", errors="replace")
    status, testS = None, None
    if rep.exists():
        try:
            rr = json.loads(rep.read_text(encoding="utf-8"))["results"]
            hit = next((x for x in rr if x.get("test") == t["test"]), None)
            if hit:
                status, testS = hit["status"], hit.get("seconds")
        except (ValueError, KeyError):
            pass
    if status is None:
        m = next((m for m in RESULT_LINE.finditer(text) if m.group(2) == t["test"]), None)
        if m:
            status, testS = {"ok": "pass", "PASS": "pass", "FAIL": "fail", "SKIP": "skipped"}[m.group(1)], float(m.group(3))
    if status is None:
        status = "pass" if r["exit"] == 0 else "fail"
    used = seeded and any(g.name != "fixture" for g in (run / "w").glob("*/Fixture.gpr") if g.parent.name != "fixture")
    fx = re.search(r'"fixture import\+analyze exe":\s*([\d.]+)', text)
    r.update(suite=t["suite"], test=t["test"], status=status, testS=testS, fixtureUsed=bool(used or fx), seeded=seeded,
             fixtureWallS=float(fx.group(1)) if fx else None, log=str(log))
    r.pop("tracker", None)
    shutil.rmtree(run, ignore_errors=True) if status in ("pass", "skipped") else None
    return r


# ---- the fixed-cost probes (run as `measure_cpu.py --probe <name> ...` subprocesses) ---------------------------------
def probe_main(a) -> int:
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support"))
    import argparse as ap_
    import daemon_tests as dt
    import ghidra_session as gs
    ns = ap_.Namespace(ghidra=a.ghidra, work=a.work, tmpdir=a.tmpdir)
    c = dt.Ctx(ns, gs)

    def phase(name, t_start):
        print(f"@@PHASE {name} {t_start:.6f} {time.time():.6f}", flush=True)

    def timed(name, fn):
        t = time.time()
        r = fn()
        phase(name, t)
        return r

    try:
        if a.probe == "daemon_cycle":
            d = c.daemon("cyc")
            t = time.time()
            s = d.connect("cyc", "t0")          # starts the JVM, waits for the endpoint, hello
            phase("daemon_start_connect", t)
            timed("hello_roundtrip", lambda: s.call("status") if False else None)
            timed("close_session", s.close)
            timed("daemon_stop", d.stop)
        else:   # project_import
            base = c.work / "pi"
            fx = c.work / "fixture"         # the recipe and place of daemon_tests Ctx.fixture(): kept as the template
            d = c.daemon("pi")
            t = time.time()
            s = d.connect("pi", "t0")
            phase("daemon_start_connect", t)
            gpr = timed("make_project", lambda: c.make_project(s, base / "A", "A"))
            timed("open_project", lambda: s.call("open_project", path=str(gpr), writable=True))
            timed("import_exe_no_analysis", lambda: s.call("import", file=a.exe, analyze=False, timeout=1800, wait=600000))
            timed("close_project_A", lambda: s.call("close_project"))
            gprb = timed("make_project_B", lambda: c.make_project(s, fx, "Fixture"))
            timed("open_project_B", lambda: s.call("open_project", path=str(gprb), writable=True))
            timed("fixture_import_analyze", lambda: s.call("import", file=a.exe, analyze=True, timeout=1800, wait=600000))
            timed("save_close_B", lambda: (s.call("save"), s.call("close_project")))
            s.close()
            timed("daemon_stop", d.stop)
            dst = c.work / "pi-copy"
            timed("copy_fixture_project", lambda: shutil.copytree(fx, dst))
            d2 = c.daemon("pi2")
            t = time.time()
            s2 = d2.connect("pi2", "t0")
            phase("daemon_start_connect_2nd", t)
            timed("open_copied_project", lambda: s2.call("open_project", path=str(dst / "Fixture.gpr"), writable=True))
            timed("open_program", lambda: s2.call("open_program", path="/" + Path(a.exe).name))
            s2.close()
            timed("daemon_stop_2nd", d2.stop)
    finally:
        c.cleanup()
    return 0


def run_probe(a, name: str, rep: int, scratch: Path, logs: Path) -> list[dict]:
    run = scratch / f"probe-{name}-{rep}"
    shutil.rmtree(run, ignore_errors=True)
    run.mkdir(parents=True)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--probe", name, "--ghidra", a.ghidra, "--exe", a.exe,
           "--dll", a.dll, "--work", str(run / "w"), "--tmpdir", str(run / "t")]
    log = logs / f"probe-{name}-{rep}.log"
    r = measure(cmd, str(run), log)
    tr: Tracker = r.pop("tracker")
    rows = []
    for m in re.finditer(r"^@@PHASE (\S+) ([\d.]+) ([\d.]+)$", log.read_text(encoding="utf-8", errors="replace"), re.M):
        t0, t1 = float(m.group(2)), float(m.group(3))
        rows.append({"probe": name, "rep": rep, "phase": m.group(1), "wallS": round(t1 - t0, 3),
                     "cpuS": round(tr.cpu_at(t1) - tr.cpu_at(t0), 3)})
    rows.append({"probe": name, "rep": rep, "phase": "TOTAL_PROCESS", "wallS": round(r["wallS"], 3),
                 "cpuS": round(r["cpuS"], 3), "jvmCpuS": round(r["jvmCpuS"], 3), "pyCpuS": round(r["pyCpuS"], 3),
                 "exit": r["exit"]})
    if name == "project_import" and r["exit"] == 0 and (run / "w" / "fixture" / "Fixture.gpr").exists():
        tpl = scratch / "_fixture-template" / "fixture"
        shutil.rmtree(tpl.parent, ignore_errors=True)
        shutil.copytree(run / "w" / "fixture", tpl)
    shutil.rmtree(run, ignore_errors=True) if r["exit"] == 0 else None
    return rows


def median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else 0.0


def baseline_python(a, scratch, logs) -> dict:
    """CPU of an interpreter that only imports the harness and exits: the part of every run that is not the test."""
    code = ("import sys;sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[2]);import daemon_tests,ghidra_session")
    sup = str(Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support")
    r = measure([sys.executable, "-c", code, str(HERE), sup], str(scratch / "none"), logs / "probe-python-baseline.log")
    r.pop("tracker")
    return {"cpuS": round(r["cpuS"], 3), "wallS": round(r["wallS"], 3)}


# ---- reports -------------------------------------------------------------------------------------------------------
def ranking(rows: list[dict], fixed: dict) -> str:
    ok = [r for r in rows if r["status"] in ("pass", "skipped")]
    out = []
    tc, tw = sum(r["cpuS"] for r in rows), sum(r["wallS"] for r in rows)
    out.append(f"{len(rows)} tests measured alone ({len(ok)} pass/skip, {len(rows) - len(ok)} not passing: still counted); "
               f"total cpuS {tc:.0f}, total wallS {tw:.0f}, aggregate CPU/wall {tc / tw:.2f} cores, "
               f"mean {tc / tw:.2f} cores busy per test")
    nf = sum(r["cpuS"] - (r.get("cpuNetS") if r.get("cpuNetS") is not None else r["cpuS"]) for r in rows)
    out.append(f"fixture cost counted once per test that builds it: {nf:.0f} cpu-seconds could be removed (cpuNetS)")
    by_suite: dict[str, list] = {}
    for r in rows:
        by_suite.setdefault(r["suite"], []).append(r)
    out.append("\nper suite: tests, cpuS, wallS, cpu/wall (cores)")
    for s, rs in sorted(by_suite.items()):
        c, w = sum(r["cpuS"] for r in rs), sum(r["wallS"] for r in rs)
        out.append(f"  {s:34s} {len(rs):4d} {c:9.1f} {w:9.1f} {c / w:6.2f}" if w else f"  {s}")

    def table(title, key, n=20, reverse=True):
        out.append(f"\n{title}")
        out.append(f"  {'suite':26s} {'test':34s} {'cpuS':>8s} {'wallS':>8s} {'wait':>6s} {'jvmCpu':>8s} {'peak':>5s}")
        for r in sorted(rows, key=key, reverse=reverse)[:n]:
            out.append(f"  {r['suite'][:26]:26s} {r['test'][:34]:34s} {r['cpuS']:8.1f} {r['wallS']:8.1f} "
                       f"{r['waitShare']:6.0%} {r['jvmCpuS']:8.1f} {r['peakCores']:5.1f}")

    table("top 20 by cpuS", lambda r: r["cpuS"])
    table("top 20 by wallS", lambda r: r["wallS"])
    table("top 20 by wait share (wallS >= 10 s), 1 - cpuS/wallS", lambda r: r["waitShare"] if r["wallS"] >= 10 else -1)
    table("top 20 by peak cores", lambda r: r["peakCores"])
    if fixed:
        out.append("\nfixed costs (median of the reps)")
        for k, v in fixed.items():
            out.append(f"  {k:30s} wallS {v['wallS']:7.2f}  cpuS {v['cpuS']:7.2f}")
    return "\n".join(out) + "\n"


def write_costs(rows: list[dict], fixed: dict, a):
    allc = json.loads(COSTS.read_text(encoding="utf-8")) if COSTS.exists() else {}
    for suite in sorted({r["suite"] for r in rows}):
        d = {}
        for r in sorted((x for x in rows if x["suite"] == suite), key=lambda x: x["test"]):
            e = {"cpuS": round(r["cpuS"], 1), "wallS": round(r["wallS"], 1)}
            if r.get("testS") is not None:
                e["testS"] = round(r["testS"], 1)
            if r.get("cpuNetS") is not None and r.get("fixtureUsed"):
                e["cpuNetS"] = round(r["cpuNetS"], 1)
            e.update(peakCores=round(r["peakCores"], 1), waitShare=round(r["waitShare"], 2),
                     kind="real" if REAL.match(r["test"]) else "unclassified", minScale=None)
            if r["status"] not in ("pass", "skipped"):
                e["status"] = r["status"]
            d[r["test"]] = e
        allc[suite + "#t0"] = d
    allc["_t0"] = {"what": "T0 of the virtual-time design: per-test cpuS (user+kernel, whole process tree), wallS (whole run) "
                   "measured alone; read-only data, run_parallel.py ignores these keys",
                   "date": datetime.date.today().isoformat(), "machine": os.environ.get("COMPUTERNAME", ""),
                   "engine": a.ghidra, "fixed": fixed}
    text = json.dumps(allc, indent=1)
    # one line per test in the #t0 blocks (the file stays short and its diffs readable)
    text = re.sub(r'\{\n\s+("cpuS".*?)\n\s+\}', lambda m: "{" + re.sub(r"\s*\n\s*", " ", m.group(1)) + "}", text, flags=re.S)
    COSTS.write_text(text + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True, help="the engine install")
    ap.add_argument("--scratch", help="parent of the per-run --work/--tmpdir directories (a fast local disk)")
    ap.add_argument("--logs", help="where the logs, CSVs and the ranking go")
    ap.add_argument("--jobs", type=int, default=3, help="tests at once (at most 3 keeps the numbers clean)")
    ap.add_argument("--suites", default="daemon_tests.py,client_compat_tests.py,contract_tests.py,"
                    "characterization_tests.py,session_smoke.py")
    ap.add_argument("--only", default="", help="comma-separated tests (all of the selected suites by default)")
    ap.add_argument("--exe", default=r"C:\Windows\System32\choice.exe")
    ap.add_argument("--dll", default=r"C:\Windows\System32\version.dll")
    ap.add_argument("--legacy-project", dest="legacy_project",
                    default=str(HERE / "fixtures" / "legacy-12.1.4" / "legacy.gpr"))
    ap.add_argument("--fixed-reps", type=int, default=5, help="repetitions of the daemon start/stop cycle")
    ap.add_argument("--import-reps", type=int, default=1, help="repetitions of the project copy + import probe (about 100 s each)")
    ap.add_argument("--fixed-only", action="store_true")
    ap.add_argument("--no-fixed", action="store_true")
    ap.add_argument("--update-costs", action="store_true", help="merge the data into suite-costs.json (key <suite>#t0)")
    ap.add_argument("--probe", choices=("daemon_cycle", "project_import"), help=argparse.SUPPRESS)
    ap.add_argument("--work", help=argparse.SUPPRESS)
    ap.add_argument("--tmpdir", help=argparse.SUPPRESS)
    a = ap.parse_args()
    a.jobs = max(1, min(a.jobs, 3))
    if a.probe:
        return probe_main(a)
    if not a.scratch or not a.logs:
        ap.error("--scratch and --logs are required")
    scratch, logs = Path(a.scratch), Path(a.logs)
    scratch.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    # 1. fixed costs first, alone on this script's share of the machine
    fixed: dict = {}
    if not a.no_fixed:
        allrows = []
        allrows.append({"probe": "python_baseline", "rep": 0, "phase": "TOTAL_PROCESS", **baseline_python(a, scratch, logs)})
        for name in ("daemon_cycle", "project_import"):
            for rep in range(a.fixed_reps if name == "daemon_cycle" else a.import_reps):
                allrows += run_probe(a, name, rep, scratch, logs)
                print(f"probe {name} #{rep} done", flush=True)
        with open(logs / "fixed.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["probe", "rep", "phase", "wallS", "cpuS", "jvmCpuS", "pyCpuS", "exit"])
            w.writeheader()
            w.writerows(allrows)
        for key in {(r["probe"], r["phase"]) for r in allrows}:
            rs = [r for r in allrows if (r["probe"], r["phase"]) == key]
            fixed[f"{key[0]}.{key[1]}"] = {"wallS": round(median([r["wallS"] for r in rs]), 2),
                                           "cpuS": round(median([r["cpuS"] for r in rs]), 2), "reps": len(rs)}
        fixed = dict(sorted(fixed.items()))
        print(json.dumps(fixed, indent=1), flush=True)
    if a.fixed_only:
        (logs / "fixed.json").write_text(json.dumps(fixed, indent=1), encoding="utf-8")
        return 0

    # 2. every test alone, at most --jobs at a time, the expected long ones first
    tasks = tasks_of(a, scratch)
    old = json.loads(COSTS.read_text(encoding="utf-8")) if COSTS.exists() else {}
    tasks.sort(key=lambda t: -float(old.get(t["suite"], {}).get(t["test"], 25.0)))
    print(f"{len(tasks)} tests, {a.jobs} at a time", flush=True)
    results: list[dict] = []
    lock = threading.Lock()
    queue = list(tasks)
    started = time.time()

    def worker(slot):
        while True:
            with lock:
                if not queue:
                    return
                t = queue.pop(0)
            r = run_task(a, t, scratch, logs, slot)
            r["waitShare"] = max(0.0, 1 - r["cpuS"] / r["wallS"]) if r["wallS"] > 0 else 0.0
            r["cpuPerWall"] = r["cpuS"] / r["wallS"] if r["wallS"] > 0 else 0.0
            with lock:
                results.append(r)
                print(f"[{len(results)}/{len(tasks)} {time.time() - started:5.0f}s] {r['status']:7s} {r['suite']}:{r['test']} "
                      f"cpu {r['cpuS']:.1f} wall {r['wallS']:.1f}" + (" LEAKED" if r["leaked"] else ""), flush=True)

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(a.jobs)]
    [t.start() for t in ths]
    [t.join() for t in ths]

    fx_cpu = fixed.get("project_import.fixture_import_analyze", {}).get("cpuS")
    for r in results:   # seeded runs did not pay the fixture; unseeded ones that built it did
        r["cpuNetS"] = max(0.0, r["cpuS"] - fx_cpu) if (r["fixtureUsed"] and not r.get("seeded") and fx_cpu is not None) else None
    results.sort(key=lambda r: (r["suite"], r["test"]))
    cols = ["suite", "test", "status", "cpuS", "jvmCpuS", "pyCpuS", "wallS", "testS", "waitShare", "cpuPerWall", "peakCores", "fixtureUsed",
            "cpuNetS", "procs", "leaked", "exit", "timedOut"]
    with open(logs / "measure.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items() if k in cols})
    (logs / "results.json").write_text(json.dumps({"fixed": fixed, "tests": results}, indent=1), encoding="utf-8")
    txt = ranking(results, fixed)
    (logs / "ranking.txt").write_text(txt, encoding="utf-8")
    print(txt)
    if a.update_costs:
        write_costs(results, fixed, a)
        print(f"merged into {COSTS}")
    bad = [r for r in results if r["status"] not in ("pass", "skipped")]
    print(f"{len(results)} measured, {len(bad)} not passing: {', '.join(r['test'] for r in bad)}; wall {time.time() - started:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
