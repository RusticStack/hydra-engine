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
"""Shared harness of the imported measurement scripts (PROTOCOL-3.md, package X0).

This replaces ``hx.py`` of measurement B (the lock map) and ``common.py`` of measurement A (capacity)
and carries the parameters every script needs, so that no script has a path in it. A script starts
with ``from xc import *``; the options below are read from the command line (and removed from
``sys.argv`` so a script's own positional arguments keep working), with the environment variable of
the same name in capitals as the default:

    --ghidra DIR      the engine install under test (``X0_GHIDRA``)
    --work DIR        working folder: state roots, projects, outputs (``X0_WORK``); never inside a game folder
    --tmpdir DIR      java.io.tmpdir of the daemons (default: <state root>/tmp)
    --project GPR     the program project the scenarios run on, a COPY is made per scenario and the
                      original is never opened (``X0_PROJECT``); the large program of the recorded runs
                      is not part of this repository
    --program PATH    the program inside it, e.g. /app.exe (``X0_PROGRAM``)
    --fixtures DIR    folder with the small fixture projects fx-x64-flow and fx-x64-vcall (``X0_FIXTURES``)
    --import-exe EXE  a small PE the import scenarios import (default: notepad.exe of the system folder)
    --fixture-exe EXE a small public fixture PE for the import scenarios of the crash harness (default: --import-exe)
    --refs-root DIR   a folder on a ReFS volume for the crash harness's "refs" file-system runs (none by default)
    --addr-base HEX   address of a function in --program used where a scenario needs "a function"
    --func-regex RX   function-name regex for the 2000-row reads (default ^FUN_00[4-5])
    --java-home DIR   JDK for the daemons (default: whatever the launcher finds; ``GHIDRA_SESSION_JAVA_HOME``)
    --tag TAG         suffix for state roots, projects and outputs (two runs of one scenario need two tags)

Every output is a JSON file in ``--work``; nothing is written next to the scripts.
"""
import argparse
import csv
import json
import os
import pathlib
import shutil
import statistics  # noqa: F401  (re-exported for the scripts)
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
SCRIPTS = HERE / "scripts"


def _opts():
    ap = argparse.ArgumentParser(add_help=False)
    for name in ("ghidra", "work", "tmpdir", "project", "program", "fixtures", "import-exe", "addr-base",
                 "func-regex", "java-home", "tag", "fixture-exe", "refs-root"):
        ap.add_argument("--" + name, default=os.environ.get("X0_" + name.upper().replace("-", "_")))
    ns, rest = ap.parse_known_args(sys.argv[1:])
    sys.argv[1:] = rest
    return ns


OPTS = _opts()


def _need(name):
    v = getattr(OPTS, name.replace("-", "_"))
    if not v:
        sys.exit(f"{os.path.basename(sys.argv[0])}: --{name} is required (or X0_{name.upper().replace('-', '_')})")
    return v


ENGINE = _need("ghidra").replace("\\", "/")
ROOT = pathlib.Path(_need("work")).absolute()
ROOT.mkdir(parents=True, exist_ok=True)
TAG = OPTS.tag or ""
TMPDIR = OPTS.tmpdir
if OPTS.java_home:
    os.environ["GHIDRA_SESSION_JAVA_HOME"] = OPTS.java_home
JAVA_HOME = os.environ.get("GHIDRA_SESSION_JAVA_HOME")
sys.path.insert(0, ENGINE + "/Ghidra/Features/HeadlessSession/support")
import ghidra_session as gs  # noqa: E402

PROG = OPTS.program or "/app.exe"
FUNRX = OPTS.func_regex or "^FUN_00[4-5]"
ADDR_BASE = int(OPTS.addr_base, 16) if OPTS.addr_base else 0x401000
SYSROOT = os.environ.get("SystemRoot", "C:/Windows")
IMPORT_EXE = OPTS.import_exe or (SYSROOT + "/System32/notepad.exe")
IMPORT_PROG = "/" + os.path.basename(IMPORT_EXE)
IMPORT_DIR = str(pathlib.Path(IMPORT_EXE).parent).replace("\\", "/")
KOTOR_SRC = pathlib.Path(OPTS.project).parent if OPTS.project else None   # name kept by the ported scripts: the base project folder
BASE_GPR = pathlib.Path(OPTS.project) if OPTS.project else None
FIX_SRC = pathlib.Path(OPTS.fixtures) if OPTS.fixtures else None


def ADDR(off=0):
    """``'0x401060'``: the address ``off`` bytes after ``--addr-base``."""
    return "0x%x" % (ADDR_BASE + off)


def prog_key(pid, path=None):
    return "%s:%s" % (pid, path or PROG)


def ms(t):
    return round((time.perf_counter() - t) * 1000, 1)


def fresh(name, cfg=None):
    """A fresh state root and a daemon under it; returns the ``gs.Daemon`` (not started yet)."""
    name = name + TAG
    st = ROOT / "state" / name
    if st.exists():
        shutil.rmtree(st, ignore_errors=True)
    (st / "state").mkdir(parents=True)
    c = {"tmpdir": str(pathlib.Path(TMPDIR) / name) if TMPDIR else str(st / "tmp"), "scriptPath": [str(SCRIPTS)]}
    c.update(cfg or {})
    pathlib.Path(c["tmpdir"]).mkdir(parents=True, exist_ok=True)
    (st / "state" / "config.json").write_text(json.dumps(c))
    return gs.Daemon(ENGINE, str(st / "state"), name)


def copy_project(src: pathlib.Path, dst_name: str, tagged: bool = True) -> pathlib.Path:
    """A copy of the project folder ``src`` under ``<work>/proj``; returns its .gpr."""
    dst = ROOT / "proj" / (dst_name + (TAG if tagged else ""))
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    return [p for p in dst.glob("*.gpr")][0]


def base_project() -> pathlib.Path:
    """The prepared base project folder (``mkbase.py`` makes it from ``--project``)."""
    p = ROOT / "proj" / "base"
    if not p.is_dir():
        sys.exit("the base project is missing: run mkbase.py first (same --work)")
    return p


def timed(fn, *a, **k):
    t = time.perf_counter()
    try:
        r = fn(*a, **k)
        return True, ms(t), r
    except gs.SessionError as e:
        return False, ms(t), {"code": e.code, "message": e.message[:300],
                              "details": {kk: e.details.get(kk) for kk in
                                          ("wanted", "holder", "heldMs", "readers", "lane", "slots", "queued", "running", "waitedMs")
                                          if kk in (e.details or {})}}


def par(fns):
    """Runs callables at once (a barrier first); their results in order."""
    res = [None] * len(fns)
    bar = threading.Barrier(len(fns))

    def w(i):
        bar.wait()
        try:
            res[i] = fns[i]()
        except Exception as e:  # noqa: BLE001
            res[i] = ("EXC", repr(e)[:300])
    ts = [threading.Thread(target=w, args=(i,)) for i in range(len(fns))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return res


def save(name, obj):
    p = ROOT / (name + TAG + ".json")
    p.write_text(json.dumps(obj, indent=1, default=str))
    print(json.dumps(obj, indent=1, default=str))


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


# ---- measurement A (capacity) helpers -------------------------------------------------------------

OUT = ROOT / "out"
OUT.mkdir(parents=True, exist_ok=True)


def stat_dir(name):
    """A state root folder (not the config) for measurement A scripts, fresh per name."""
    p = ROOT / "state" / (name + TAG)
    p.mkdir(parents=True, exist_ok=True)
    return str(p)


def daemon(state, heap=None, instance="default", **cfg):
    kw = dict(cfg)
    if heap:
        kw["maxHeap"] = heap
    return gs.Daemon(ENGINE, state, instance, **kw)


def connect(state, name, heap=None, instance="default", **cfg):
    if os.environ.get("MEAS_MINHEAP"):
        cfg["minHeap"] = os.environ["MEAS_MINHEAP"]
    return daemon(state, heap, instance, **cfg).connect(name, "measA", True)


def pstat(pid):
    """(private MB, working set MB) of a process, via PowerShell."""
    out = subprocess.run(["powershell", "-NoProfile", "-c",
                          f"$p=Get-Process -Id {pid}; '{{0}} {{1}}' -f $p.PrivateMemorySize64,$p.WorkingSet64"],
                         capture_output=True, text=True).stdout.split()
    return round(int(out[0]) / 1048576), round(int(out[1]) / 1048576)


def start_sampler(pid, out, ms_=1000):
    # inline command (no .ps1 launch: the execution policy is left as it is)
    body = (HERE / "sampler.ps1").read_text(encoding="utf-8")
    code = "$DaemonPid=%d; $Out='%s'; $IntervalMs=%d; " % (pid, out, ms_) + body
    return subprocess.Popen(["powershell", "-NoProfile", "-Command", code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_samples(path):
    rows = []
    try:
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                rows.append({k: float(v) for k, v in r.items()})
    except Exception:  # noqa: BLE001
        pass
    return rows


def window(rows, t0, t1):
    return [r for r in rows if t0 <= r["t"] <= t1]


def tree_summary(rows, t0, t1):
    w = window(rows, t0, t1)
    if not w:
        return None
    first, last = w[0], w[-1]
    dt = max(last["t"] - first["t"], 1e-9)
    return {
        "samples": len(w),
        "jvm_priv_mb_max": max(r["jvm_priv_mb"] for r in w),
        "jvm_ws_mb_max": max(r["jvm_ws_mb"] for r in w),
        "nchild_max": max(r["nchild"] for r in w),
        "child_priv_mb_max": max(r["child_priv_mb"] for r in w),
        "child_ws_mb_max": max(r["child_ws_mb"] for r in w),
        "tree_priv_mb_max": max(r["jvm_priv_mb"] + r["child_priv_mb"] for r in w),
        "cpu_cores_avg_jvm": round((last["jvm_cpu_s"] - first["jvm_cpu_s"]) / dt, 2),
        "cpu_cores_avg_children": round((last["child_cpu_s"] - first["child_cpu_s"]) / dt, 2),
        "cpu_total_pct_avg": round(sum(r["cpu_total_pct"] for r in w) / len(w), 1),
        "cpu_total_pct_max": max(r["cpu_total_pct"] for r in w),
    }


def free_bytes(path):
    return shutil.disk_usage(path).free


def dir_bytes(path):
    n = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                n += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return n


def jcmd(pid, *args):
    if not JAVA_HOME:
        return ""
    jc = JAVA_HOME + "/bin/jcmd.exe"
    return subprocess.run([jc, str(pid), *args], capture_output=True, text=True).stdout


def live_heap(s, pid):
    """Forces a full GC, then reports the heap the daemon says is used."""
    jcmd(pid, "GC.run")
    return s.call("status").get("memory")


def work_base() -> str:
    """The folder the capacity scripts create forks under."""
    p = ROOT / "work" / "fork-base"
    p.mkdir(parents=True, exist_ok=True)
    return str(p).replace("\\", "/")


def master_gpr() -> str:
    """The master project the capacity scripts fork from: a copy of the base project, made once."""
    p = ROOT / "work" / "master"
    if not p.is_dir():
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(base_project(), p)
    return str([g for g in p.glob("*.gpr")][0]).replace("\\", "/")


def arg_base(v):
    return work_base() if v in (None, "-") else v


def arg_master(v):
    return master_gpr() if v in (None, "-") else v
