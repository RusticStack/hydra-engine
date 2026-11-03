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
"""Measures the Java daemon and hydra-lite on the same project: time from spawn to the first
``hello`` answer and to the first ``functions`` answer, peak working set idle and under N clients,
and p50/p95 latency per command. Standard library only (ctypes for the process figures).

    python lite_bench.py --ghidra <install> --project <dir with Fixture.gpr> --lite <hydra-lite.exe>
        [--clients 16] [--reps 200] [--out result.json]

``--project`` is a project directory built by ``reply_parity.py lite`` (``<work>/java/fixture``);
the script copies it for each side. Both sides run the same requests through the install's own
client (``support/ghidra_session.py``); hydra-lite is started the way the launcher starts it, with
``GHIDRA_SESSION_FRONT``. The figures are wall-clock on whatever machine runs this: report them
with the machine, never as a constant.
"""
import argparse
import contextlib
import ctypes
import json
import os
import pathlib
import shutil
import statistics
import subprocess
import sys
import threading
import time
from ctypes import wintypes

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import characterization_tests as ct  # noqa: E402
import reply_parity as rp  # noqa: E402

COMMANDS = [
    ("ping", {}),
    ("projects", {}),
    ("programs", {}),
    ("project", {}),
    ("list", {}),
    ("list", {"programsOnly": True, "metadata": False}),
    ("info", {}),
    ("functions", {}),
    ("functions", {"limit": 5, "contains": "FUN"}),
]


class Counters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def memory(pid):
    """(working set, peak working set) of a process in MB, and its image name."""
    k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
    k32.OpenProcess.restype = wintypes.HANDLE
    h = k32.OpenProcess(0x1000 | 0x0010, False, pid)  # QUERY_LIMITED_INFORMATION | VM_READ
    if not h:
        h = k32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not h:
        return None
    try:
        c = Counters()
        c.cb = ctypes.sizeof(c)
        psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
        buf = ctypes.create_unicode_buffer(1024)
        n = wintypes.DWORD(1024)
        k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
        return c.WorkingSetSize / 1048576, c.PeakWorkingSetSize / 1048576, pathlib.Path(buf.value).name
    finally:
        k32.CloseHandle(h)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def timed(session, cmd, fields):
    t = time.perf_counter()
    session.call(cmd, **fields)
    return (time.perf_counter() - t) * 1000.0


def client_main(n, lite, install, state, instance, gpr, reps, barrier, phase, results):
    """One client process: connects to the running daemon, opens the program, waits for the
    others, then runs each command ``reps`` times, all clients on the same command at once (a
    barrier between commands), and reports every latency."""
    import characterization_tests as ct2
    import reply_parity as rp2
    gs = rp2.load_repo_client() if lite else ct2.load_client("install", install)
    out = {"lat": {}, "errors": []}
    try:
        s = gs.Daemon(install, state, instance).connect(f"bench-{n}", "bench", start=False)
        s.call("open_project", path=gpr)
        s.call("open_program", path="/alpha.exe")
        barrier.wait(300)
        for cmd, f in COMMANDS:
            key = cmd + ("" if not f else "(" + ",".join(f) + ")")
            phase.wait(300)
            out["lat"][key] = [timed(s, cmd, f) for _ in range(reps)]
        s.close()
    except Exception as e:  # noqa: BLE001
        out["errors"].append(repr(e))
        with contextlib.suppress(Exception):
            barrier.abort()
    results.put(out)


def run_side(name, gs, install, state, project, clients, reps, exe):
    if exe:
        os.environ["GHIDRA_SESSION_FRONT"] = exe
    else:
        os.environ.pop("GHIDRA_SESSION_FRONT", None)
    out = {"side": name}
    d = gs.Daemon(install, str(state), "bench-" + name)  # the lite side uses bench-lite
    sessions = []
    try:
        t0 = time.perf_counter()
        s = d.connect("bench-0", "bench")
        out["first_hello_ms"] = (time.perf_counter() - t0) * 1000.0
        hello = s.hello
        pid = hello.get("pid")
        image = (memory(pid) or (0, 0, ""))[2] if pid else ""
        if bool(exe) != ("hydra-lite" in image):
            raise SystemExit(f"{name}: the daemon that answered is {image!r}, not the one asked for")
        t1 = time.perf_counter()
        s.call("open_project", path=str(project / "Fixture.gpr"))
        s.call("open_program", path="/alpha.exe")
        s.call("functions", limit=5)
        out["first_functions_ms"] = (time.perf_counter() - t1) * 1000.0
        out["spawn_to_first_functions_ms"] = (time.perf_counter() - t0) * 1000.0
        m = memory(pid) if pid else None
        out["pid"] = pid
        if m:
            out["idle_ws_mb"], out["idle_peak_mb"], out["image"] = (round(m[0], 1), round(m[1], 1), m[2])
        # per command latency, one client
        single = {}
        for cmd, f in COMMANDS:
            key = cmd + ("" if not f else "(" + ",".join(f) + ")")
            xs = [timed(s, cmd, f) for _ in range(reps)]
            single[key] = {"p50": round(pct(xs, 50), 3), "p95": round(pct(xs, 95), 3),
                           "max": round(max(xs), 3)}
        out["single"] = single
        # N clients at once, each in its own process: threads of one Python process would queue
        # on the interpreter lock and the figures would measure the client, not the daemon
        import multiprocessing as mp
        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(clients + 1)
        phase = ctx.Barrier(clients)
        results = ctx.Queue()
        procs = [ctx.Process(target=client_main,
                             args=(i + 1, exe is not None, install, str(state), "bench-" + name,
                                   str(project / "Fixture.gpr"), reps, barrier, phase, results))
                 for i in range(clients)]
        for p in procs:
            p.start()
        barrier.wait(300)  # every client is connected and has its program open
        t2 = time.perf_counter()
        parts = [results.get(timeout=600) for _ in procs]
        wall = time.perf_counter() - t2
        for p in procs:
            p.join(60)
        lat, errors = {}, []
        for part in parts:
            errors += part["errors"]
            for k, v in part["lat"].items():
                lat.setdefault(k, []).extend(v)
        out["clients"] = clients
        out["clients_wall_s"] = round(wall, 3)
        out["clients_requests"] = sum(len(v) for v in lat.values())
        out["clients_errors"] = errors[:3]
        out["multi"] = {k: {"p50": round(pct(v, 50), 3), "p95": round(pct(v, 95), 3),
                            "max": round(max(v), 3)} for k, v in lat.items()}
        m = memory(pid) if pid else None
        if m:
            out["clients_ws_mb"], out["clients_peak_mb"] = round(m[0], 1), round(m[1], 1)
    finally:
        for c in sessions:
            with contextlib.suppress(Exception):
                c.close()
        rp.stop(d)
        os.environ.pop("GHIDRA_SESSION_FRONT", None)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--project", required=True, help="a built project directory (Fixture.gpr)")
    ap.add_argument("--lite", required=True)
    ap.add_argument("--work", required=True, help="empty work directory")
    ap.add_argument("--clients", type=int, default=16)
    ap.add_argument("--reps", type=int, default=200)
    ap.add_argument("--out")
    a = ap.parse_args()
    install = str(pathlib.Path(a.ghidra).absolute())
    work = pathlib.Path(a.work).absolute()
    if work.exists() and any(work.iterdir()):
        print(f"error: --work {work} is not empty", file=sys.stderr)
        return 2
    gs = ct.load_client("install", install)
    gl = rp.load_repo_client()
    results = []
    jstate = None
    for side in ("java", "lite"):
        w = work / side
        w.mkdir(parents=True)
        _s, _b, state = rp.write_inputs(w)
        proj = w / "project"
        shutil.copytree(a.project, proj)
        if side == "lite":
            # the identity comes from a Java daemon of the same install
            jd = gs.Daemon(install, str(jstate), "bench-java")
            try:
                jd.connect("bench-learn", "bench").close()
                rp.learn_lite(gl, a.lite, install, state, "bench-lite", jd)
            finally:
                rp.stop(jd)
        else:
            jstate = state
        results.append(run_side(side, gs if side == "java" else gl, install, state, proj,
                                a.clients, a.reps,
                                None if side == "java" else str(pathlib.Path(a.lite).absolute())))
        print(json.dumps({k: v for k, v in results[-1].items() if k not in ("single", "multi")}),
              flush=True)
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(results, indent=1), encoding="utf-8")
    keys = list(results[0]["single"])
    print(f"{'command':34} {'java p50':>9} {'java p95':>9} {'lite p50':>9} {'lite p95':>9}   "
          f"{'java p50':>9} {'java p95':>9} {'lite p50':>9} {'lite p95':>9}  (single | {a.clients} clients, ms)")
    for k in keys:
        j, l = results[0], results[1]
        print(f"{k:34} {j['single'][k]['p50']:9.3f} {j['single'][k]['p95']:9.3f} "
              f"{l['single'][k]['p50']:9.3f} {l['single'][k]['p95']:9.3f}   "
              f"{j['multi'][k]['p50']:9.3f} {j['multi'][k]['p95']:9.3f} "
              f"{l['multi'][k]['p50']:9.3f} {l['multi'][k]['p95']:9.3f}")
    return 0


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
