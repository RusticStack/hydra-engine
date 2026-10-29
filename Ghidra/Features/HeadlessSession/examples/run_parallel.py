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
"""Run a daemon_tests-style suite as many processes at once: a work queue of single tests.

    python run_parallel.py --ghidra <install> --scratch <dir on a fast disk> --logs <dir> [--workers 16] \\
        daemon_tests.py -- --exe C:\\Windows\\System32\\choice.exe --dll C:\\Windows\\System32\\version.dll [--legacy-project ...]

The suites wait far more than they compute, so every test is its own `<script> --only <test>` process with its own
--work and --tmpdir under --scratch (its own state dir, so its own daemons), and --workers of them run at once, the
longest first (costs from suite-costs.json next to this file, seconds per test, 25 s when unknown; --record refreshes
them). A new test starts only while the machine has enough commit left and fewer than --max-procs processes (Windows refuses to start
processes, exit 0xC0000142, when the commit runs out; see --min-commit-gb). Any script that takes --ghidra --work
--tmpdir --only --report and reports the way daemon_tests.py does works; --names a,b,c names the tests when the
script has no --list.

Two things are optional, used when the script offers them (daemon_tests.py does):
* shards (--list-shards): a long test that is a loop of independent iterations runs as several processes
  (`name@shard`) whose iterations add up to the whole test's; they are reported under the test's name (the test
  passes when every shard passes) and --no-shards runs the whole tests instead;
* a seed (--prepare / --seed-dir): the fixture project every test copies (an import and analysis of --exe, 20-25 s)
  and the daemon's class search cache (with --seed-aot also its AOT cache) are made once for the run instead of
  once per process; --seed-cache keeps them between runs
  while the install, the script and the arguments are the same (--no-seed: every process makes its own).

The verdict is per test, from each process's --report file:
* a process that exits without a report, or with its test missing from it, is a PROBLEM (tests that did not run
  never pass);
* a test (or shard) that fails is run again ALONE, with nothing else running (--rerun-alone, default 1): if it
  passes it is listed as "failed under load, passed alone" (exit 0 unless --strict); if it fails again it is a real
  failure (exit 1).
Scratch of a passing test is deleted at once; failing ones keep theirs. Put --scratch on the NVMe disk.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COSTS = HERE / "suite-costs.json"
DEFAULT_COST_S = 25.0
DEFAULT_WORKERS = 16
#: processes on the machine above which no new test is started. Measured on the 24-thread, 64 GB Windows 11 machine
#: this was written on: 1,100 small JVMs at once (1,419 processes on the machine) all started, so the process count
#: itself is not what failed earlier runs with 0xC0000142 (STATUS_DLL_INIT_FAILED); this is only a guard.
DEFAULT_MAX_PROCS = 1200
#: available commit (GB) below which no new test is started. A test daemon commits its -Xms (512m) and more at once,
#: a test runs one to three of them, and a process that cannot commit its first pages fails to start with
#: 0xC0000142: the commit limit (RAM + page file, 72 GB here) is the resource the earlier failures ran out of when
#: two suites of 8 groups ran next to each other.
DEFAULT_MIN_COMMIT_GB = 10.0
DEFAULT_HEAVY_SLOTS = 4
GOOD = ("pass", "skipped")


# ---- the plan --------------------------------------------------------------------------------

def task_cost(task: str, costs: dict, shards: dict) -> float:
    if task in costs:
        return float(costs[task])
    test, _, shard = task.partition("@")
    whole = float(costs.get(test, DEFAULT_COST_S))
    return whole / max(1, len(shards.get(test, ()))) if shard else whole


def plan(names: list[str], shards: dict, costs: dict) -> list[str]:
    """The tasks (tests, or the shards of a sharded test), longest first; a test keeps its place among equals."""
    tasks = [t for n in names for t in ([f"{n}@{s}" for s in shards[n]] if n in shards else [n])]
    return sorted(tasks, key=lambda t: -task_cost(t, costs, shards))


def lpt_estimate(costs: list[float], workers: int) -> float:
    """Wall time of a longest-first list schedule on ``workers`` (the bound is the longest task)."""
    load = [0.0] * max(1, workers)
    for c in sorted(costs, reverse=True):
        k = load.index(min(load))
        load[k] += c
    return max(load) if costs else 0.0


def merge(test: str, parts: list[str], results: dict) -> dict:
    """The result of ``test`` from the results of its tasks (itself, or its shards)."""
    if parts == [test]:
        return dict(results[test])
    rs = [results[p] for p in parts]
    bad = [p for p, r in zip(parts, rs) if r["status"] not in GOOD]
    if bad:
        status = results[bad[0]]["status"]
    elif all(r["status"] == "skipped" for r in rs):
        status = "skipped"
    else:
        status = "pass"
    note = "; ".join(f"[{p.partition('@')[2]}] {r.get('note', '')}" for p, r in zip(parts, rs))
    return {"test": test, "status": status, "seconds": round(sum(r.get("seconds", 0) for r in rs), 1),
            "note": note, "shards": {p: {"status": r["status"], "seconds": r.get("seconds")} for p, r in zip(parts, rs)}}


# ---- processes -------------------------------------------------------------------------------

class _MemStatus(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def free_commit_gb() -> float | None:
    """Commit the machine can still hand out (GB): the commit limit minus the commit charge (None off Windows)."""
    if os.name != "nt":
        return None
    m = _MemStatus()
    m.dwLength = ctypes.sizeof(m)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        return None
    return m.ullAvailPageFile / (1 << 30)


def machine_procs() -> int | None:
    """How many processes the machine has now (None when it cannot be read)."""
    if os.name != "nt":
        try:
            return sum(1 for p in os.listdir("/proc") if p.isdigit())
        except OSError:
            return None
    arr = (ctypes.c_ulong * 8192)()
    got = ctypes.c_ulong()
    if not ctypes.windll.psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(got)):
        return None
    return got.value // ctypes.sizeof(ctypes.c_ulong)


def kill_tree(p: subprocess.Popen):
    if p.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
        else:
            p.kill()
        try:
            p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass


def results_of(report: Path) -> dict:
    try:
        return {r["test"]: r for r in json.loads(report.read_text(encoding="utf-8"))["results"]}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def safe(name: str) -> str:
    return re.sub(r"[^\w.-]", "_", name)


class Runner:
    """Starts the processes of one suite script. ``whole``: the script is one task (no --only/--report; it passes
    when it exits 0), for suites that are a single sequence; ``prefix`` names its tasks in a mixed queue."""
    N = 0           # processes started by every runner (their scratch folders are numbered by it)

    def __init__(self, a, script: str, extra: list[str], scratch: Path, logs: Path, prefix: str = "", whole: bool = False,
                 tmpdir: bool = True):
        self.a, self.script, self.extra, self.scratch, self.logs = a, script, extra, scratch, logs
        self.prefix, self.whole, self.tmpdir = prefix, whole, tmpdir
        self.seed: Path | None = None

    def cmd(self, work: Path, tmp: Path, report: Path | None, only: str = "", more=()) -> list[str]:
        c = [sys.executable, str(HERE / self.script), "--ghidra", self.a.ghidra, "--work", str(work)]
        c += ["--tmpdir", str(tmp)] if self.tmpdir else []
        if not self.whole:
            c += ["--report", str(report)] if report else []
            c += ["--only", only] if only else []
            c += ["--seed-dir", str(self.seed)] if self.seed and only else []
        return c + list(more) + self.extra

    def start(self, task: str, tag: str = ""):
        Runner.N += 1
        w = self.scratch / f"t{Runner.N:03d}"          # short: Ghidra projects nest deep under it
        stem = safe(self.prefix + task) + tag
        log, rep = self.logs / f"{stem}.log", self.logs / f"{stem}.json"
        p = subprocess.Popen(self.cmd(w / "w", w / "t", rep, task), cwd=HERE, stdin=subprocess.DEVNULL,
                             stdout=open(log, "w", encoding="utf-8", errors="replace"), stderr=subprocess.STDOUT)
        return {"runner": self, "task": task, "key": self.prefix + task, "proc": p, "work": w, "log": log, "report": rep,
                "t0": time.time()}

    def result(self, j: dict, secs: float) -> dict:
        """{test: result} of a finished process (a task may be a chunk ``a,b,c`` of tests): from its report, or
        (``whole``) from its exit code and last lines. A test without a result is missing."""
        if not self.whole:
            got = results_of(j["report"])
            return {n: got[n] for n in j["task"].split(",") if n in got}
        try:
            tail = j["log"].read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
        except OSError:
            tail = []
        code = j["proc"].returncode
        return {j["task"]: {"test": j["task"], "status": "pass" if code == 0 else "fail", "seconds": round(secs, 1),
                            "note": f"exit {code}: " + " | ".join(tail)[-400:]}}

    def listing(self, flag: str) -> tuple[int, list[str], str]:
        work = self.scratch / "_list"
        out = subprocess.run(self.cmd(work / "w", work / "t", None, more=[flag]), cwd=HERE, capture_output=True, text=True)
        shutil.rmtree(work, ignore_errors=True)
        lines = [m.group(1) for m in (re.match(r"\s*([\w@]+)", l) for l in out.stdout.splitlines()) if m]
        return out.returncode, lines, out.stdout + out.stderr

    def prepare_seed(self) -> str:
        """Makes (or takes from --seed-cache) the seed directory; returns what was done, for the log."""
        if self.a.no_seed:
            return "no seed (--no-seed)"
        key = None
        if self.a.seed_cache:
            h = hashlib.sha256()
            for p in sorted((Path(self.a.ghidra) / "Ghidra").rglob("*.jar")):
                st = p.stat()
                h.update(f"{p.relative_to(self.a.ghidra)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
            h.update((HERE / self.script).read_bytes())
            h.update("\0".join([self.a.ghidra, str(self.a.seed_aot)] + self.extra).encode())
            key = h.hexdigest()[:20]
            entry = Path(self.a.seed_cache) / f"seed-{key}"
            if (entry / "ok").is_file():
                self.seed = entry
                return f"seed from the cache {entry}"
        t = time.time()
        w = self.scratch / "_seed"
        log = self.logs / "_seed.log"
        with open(log, "w", encoding="utf-8", errors="replace") as f:
            code = subprocess.run(self.cmd(w / "w", w / "t", None, more=["--prepare"] + (["--prepare-aot"] if self.a.seed_aot else [])), cwd=HERE, stdin=subprocess.DEVNULL,
                                  stdout=f, stderr=subprocess.STDOUT).returncode
        if code != 0:
            return f"no seed: --prepare exited {code} (see {log}); every process makes its own fixture"
        seed = w / "w"
        if key:
            entry = Path(self.a.seed_cache) / f"seed-{key}"
            entry.parent.mkdir(parents=True, exist_ok=True)
            (seed / "ok").write_text("made by run_parallel.py --prepare\n", encoding="utf-8")
            try:
                os.replace(seed, entry)         # a rename on the same volume (else the seed stays where it is)
                seed = entry
            except OSError:
                seed = entry if (entry / "ok").is_file() else seed
        self.seed = seed
        return f"seed made in {time.time() - t:.0f} s: {seed}"


def is_heavy(r: Runner, task: str, heavy: set) -> bool:
    return any((r.prefix + n.partition("@")[0]) in heavy for n in task.split(","))


def run_queue(items: list[tuple[Runner, str]], workers: int, max_procs: int, min_commit: float, timeout: float,
              results: dict, problems: list, started: float, heavy: set = frozenset(), heavy_slots: int = 0) -> dict:
    """Runs the ``(runner, task)`` items (in order) with at most ``workers`` at once, and a new one only while the
    machine has fewer than ``max_procs`` processes and at least ``min_commit`` GB of commit left; fills ``results``
    {runner prefix + task: result}. Returns what was seen of the machine: peak processes, least free commit, seconds
    held back."""
    queue = list(items)
    running: list[dict] = []
    held_since = None
    seen = {"peak_procs": 0, "min_free_commit_gb": None, "held_s": 0.0}
    last = 0.0
    while queue or running:
        if time.time() - last > 1.0:                  # sample the machine once a second
            last = time.time()
            n, fc = machine_procs(), free_commit_gb()
            if n is not None:
                seen["peak_procs"] = max(seen["peak_procs"], n)
            if fc is not None:
                seen["min_free_commit_gb"] = round(min(fc, seen["min_free_commit_gb"] or fc), 1)
        while queue and len(running) < workers:
            n, fc = machine_procs(), free_commit_gb()
            full = (max_procs and n is not None and n >= max_procs) or (min_commit and fc is not None and fc < min_commit)
            if full and running:
                held_since = held_since or time.time()
                break
            busy = sum(1 for j in running if j["heavy"])
            pick = next((k for k, (r, t) in enumerate(queue) if not (heavy and is_heavy(r, t, heavy) and busy >= heavy_slots)), None)
            if pick is None:
                break
            if pick:
                queue.insert(0, queue.pop(pick))      # the longest light task, while the heavy slots are taken
            if held_since:
                seen["held_s"] += time.time() - held_since
                print(f"   (held {time.time() - held_since:.1f} s: {n} processes, {fc:.1f} GB commit free)", flush=True)
                held_since = None
            r, task = queue.pop(0)
            running.append(dict(r.start(task), heavy=bool(heavy and is_heavy(r, task, heavy))))
        time.sleep(0.2)
        for j in [j for j in running if j["proc"].poll() is not None or time.time() - j["t0"] > timeout]:
            running.remove(j)
            if j["proc"].poll() is None:
                kill_tree(j["proc"])
                problems.append(f"{j['key']}: killed after {timeout:.0f} s (log {j['log']})")
            code = j["proc"].returncode
            secs = time.time() - j["t0"]
            got = j["runner"].result(j, secs)
            lost = [n for n in j["task"].split(",") if n not in got]
            if lost:
                problems.append(f"{j['runner'].prefix}{','.join(lost)}: exit {code}, no result (log {j['log']})")
            for n, x in got.items():
                x["wall"] = round(secs, 1)
                results[j["runner"].prefix + n] = x
            if not lost and code == 0 and all(x["status"] in GOOD for x in got.values()):
                shutil.rmtree(j["work"], ignore_errors=True)
            word = ("NO RESULT" if lost else "pass" if all(x["status"] in GOOD for x in got.values())
                    else next(x["status"] for x in got.values() if x["status"] not in GOOD))
            print(f"{word:7s} {j['key']:40s} {secs:6.1f} s  (at {time.time() - started:4.0f} s, {len(queue)} queued, {len(running)} running)", flush=True)
    seen["held_s"] = round(seen["held_s"], 1)
    return seen


def selftest() -> int:
    """``--selftest``: the plan, the merge and the shards of daemon_tests.py (no engine, under a second)."""
    bad = []

    def check(what, cond):
        print(("ok   " if cond else "FAIL ") + what)
        if not cond:
            bad.append(what)

    names = ["a", "b", "c"]
    shards = {"b": ["x", "y", "z"]}
    costs = {"a": 10, "b": 90, "b@y": 50}
    t = plan(names, shards, costs)
    check("plan: a sharded test is its shards, the others themselves, each once",
          sorted(t) == ["a", "b@x", "b@y", "b@z", "c"])
    check("plan: longest first (recorded shard cost, else the test's cost shared, else 25 s)",
          t == ["b@y", "b@x", "b@z", "c", "a"] and task_cost("b@x", costs, shards) == 30.0 and task_cost("c", costs, shards) == 25.0)
    check("lpt: bound is the longest task", lpt_estimate([50, 30, 30, 25, 10], 16) == 50 and lpt_estimate([3, 3, 3], 1) == 9)
    ok = {"status": "pass", "seconds": 1.0, "note": "n"}
    res = {"b@x": dict(ok, test="b@x"), "b@y": dict(ok, test="b@y"), "b@z": dict(ok, test="b@z")}
    m = merge("b", ["b@x", "b@y", "b@z"], res)
    check("merge: every shard passed -> the test passed, reported under its own name, seconds added",
          m["test"] == "b" and m["status"] == "pass" and m["seconds"] == 3.0 and len(m["shards"]) == 3)
    res["b@y"] = dict(res["b@y"], status="fail", note="broken")
    m = merge("b", ["b@x", "b@y", "b@z"], res)
    check("merge: one shard failed -> the test failed with that shard's note", m["status"] == "fail" and "[y] broken" in m["note"])
    m = merge("b", ["b@x"], {"b@x": dict(ok, status="skipped")})
    check("merge: all shards skipped -> skipped", m["status"] == "skipped")
    # the shards of the real suite: loaded the way daemon_tests.py loads them
    import importlib.util
    spec = importlib.util.spec_from_file_location("daemon_tests", HERE / "daemon_tests.py")
    dt = importlib.util.module_from_spec(spec)
    sys.modules["daemon_tests"] = dt
    spec.loader.exec_module(dt)
    for n in dt.TESTS:
        dt.REGISTRY[n] = getattr(dt, "t_" + n)
    errors = dt.load_dt(HERE)
    check(f"daemon_tests: every dt_*.py loads ({errors or 'none failed'})", not errors)
    check("daemon_tests: shards belong to registered tests and add no test name",
          set(dt.SHARDS) <= set(dt.REGISTRY) and not any("@" in n for n in dt.REGISTRY))
    for n0, k in ((0, 4), (1, 4), (8, 4), (200, 2), (7, 3)):
        sp = dt.split_n(n0, k)
        check(f"split_n({n0}, {k}): {k} parts, contiguous, adding up",
              len(sp) == k and sum(c for _, c in sp) == n0 and all(sp[i][0] + sp[i][1] == sp[i + 1][0] for i in range(k - 1)))
    e3b = sys.modules.get("dt_e3b")
    if e3b:
        sh = dt.SHARDS.get("cancel_while_waiting", {})
        per = {p: sorted(s for s in sh if s.startswith(f"p{p}r")) for p in (2, 3)}
        check("cancel_while_waiting: both protocols, races 0..199 each across the shards",
              all(sum(c for _, c in dt.split_n(e3b.CW_RACES, e3b.CW_SHARDS)) == 200 and len(v) == e3b.CW_SHARDS for v in per.values()))
        check("writer_vs_steady_readers: protocol 3 and 2 halves", set(dt.SHARDS.get("writer_vs_steady_readers", {})) == {"p3", "p2"})
    e8 = sys.modules.get("dt_e8")
    if e8:
        kills = int(os.environ.get("E8_KILLS", "8"))
        check(f"e8_kill_loop: {e8.KILL_SHARDS} shards whose kills add up to E8_KILLS ({kills})",
              len(dt.SHARDS.get("e8_kill_loop", {})) == e8.KILL_SHARDS and sum(c for _, c in dt.split_n(kills, e8.KILL_SHARDS)) == kills)
    print(f"{'FAILED: ' + str(len(bad)) + ' check(s)' if bad else 'all run_parallel checks ok'}")
    return 1 if bad else 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True, help="the engine install")
    ap.add_argument("--scratch", required=True, help="parent of the --work/--tmpdir directories (a fast local disk)")
    ap.add_argument("--logs", required=True, help="where the per-test logs and reports go")
    ap.add_argument("--workers", "--groups", dest="workers", type=int, default=DEFAULT_WORKERS,
                    help=f"tests at once (default {DEFAULT_WORKERS}; --groups is the old name)")
    ap.add_argument("--max-procs", dest="max_procs", type=int, default=DEFAULT_MAX_PROCS,
                    help=f"start no test while the machine has this many processes (default {DEFAULT_MAX_PROCS}; 0: no limit)")
    ap.add_argument("--min-commit-gb", dest="min_commit", type=float, default=DEFAULT_MIN_COMMIT_GB,
                    help=f"start no test while the machine has less commit left (default {DEFAULT_MIN_COMMIT_GB:g} GB; 0: no limit)")
    ap.add_argument("--heavy-slots", dest="heavy_slots", type=int, default=DEFAULT_HEAVY_SLOTS,
                    help=f"at most this many of the CPU- and disk-heavy tests (suite-costs.json '<script>#heavy') at once "
                         f"(default {DEFAULT_HEAVY_SLOTS}; 0: no limit)")
    ap.add_argument("--task-timeout", dest="task_timeout", type=float, default=1200,
                    help="seconds a test process may run before it is killed (a PROBLEM; default 1200)")
    ap.add_argument("--names", default="", help="comma-separated tests instead of asking the script for --list")
    ap.add_argument("--no-shards", dest="no_shards", action="store_true", help="run sharded tests whole")
    ap.add_argument("--no-seed", dest="no_seed", action="store_true", help="no --prepare/--seed-dir")
    ap.add_argument("--seed-aot", dest="seed_aot", action="store_true",
                    help="the seed also has the daemon's AOT cache (about 30 s more to make, little faster)")
    ap.add_argument("--seed-cache", dest="seed_cache", default=None,
                    help="keep the seed here between runs (default: <scratch>-seed-cache; 'none': do not)")
    ap.add_argument("--rerun-alone", type=int, default=1)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--record", action="store_true", help="refresh suite-costs.json from this run")
    ap.add_argument("script", help="daemon_tests.py")
    ap.add_argument("rest", nargs=argparse.REMAINDER, help="-- then the arguments every process gets")
    a = ap.parse_args()
    extra = [x for x in a.rest if x != "--"]
    scratch, logs = Path(a.scratch), Path(a.logs)
    if a.seed_cache is None:
        a.seed_cache = str(scratch.parent / (scratch.name + "-seed-cache"))
    elif a.seed_cache.lower() == "none":
        a.seed_cache = None
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    shutil.rmtree(logs, ignore_errors=True)
    logs.mkdir(parents=True)
    r = Runner(a, a.script, extra, scratch, logs)
    started = time.time()

    allcosts = json.loads(COSTS.read_text(encoding="utf-8")) if COSTS.exists() else {}
    costs = allcosts.get(a.script, {})
    if a.names:
        names = [n for n in a.names.split(",") if n]
    else:
        code, names, text = r.listing("--list")
        if code != 0:
            sys.exit("--list failed:\n" + text[-1500:])
    shards: dict[str, list[str]] = {}
    if not a.no_shards:
        code, lines, _ = r.listing("--list-shards")
        for line in lines if code == 0 else []:
            t, _, s = line.partition("@")
            if t in names and s:
                shards.setdefault(t, []).append(s)
    tasks = plan(names, shards, costs)
    est = lpt_estimate([task_cost(t, costs, shards) for t in tasks], a.workers)
    print(f"{len(names)} tests as {len(tasks)} processes ({sum(len(v) for v in shards.values())} shards of {len(shards)} tests), "
          f"{a.workers} at once (while under {a.max_procs or 'any'} processes and over {a.min_commit:g} GB commit free); estimated {est:.0f} s; scratch {scratch}", flush=True)
    print(r.prepare_seed() + f" ({time.time() - started:.0f} s)", flush=True)

    results: dict[str, dict] = {}
    problems: list[str] = []
    q0 = time.time()
    heavy = set(allcosts.get(a.script + "#heavy", [])) if a.heavy_slots else set()
    machine = run_queue([(r, t) for t in tasks], a.workers, a.max_procs, a.min_commit, a.task_timeout, results, problems, started,
                        heavy, a.heavy_slots)
    queue_s = time.time() - q0

    verdict: dict[str, str] = {}           # task -> "load" | "real"
    for t in sorted(t for t, x in results.items() if x["status"] not in GOOD):
        verdict[t] = "real"
        for i in range(a.rerun_alone):
            j = r.start(t, f"-alone{i}")
            j["proc"].wait()
            again = results_of(j["report"]).get(t)
            print(f"alone   {t:40s} {again['status'] if again else 'NO RESULT'}", flush=True)
            if again and again["status"] in GOOD:
                verdict[t] = "load"
                shutil.rmtree(j["work"], ignore_errors=True)
                break
            if again:
                results[t] = again

    if a.record:
        for t, x in results.items():
            if x["status"] == "pass" and "seconds" in x and verdict.get(t) is None:
                costs[t] = x["seconds"]
        for n, ss in shards.items():
            parts = [f"{n}@{s}" for s in ss]
            if all(p in costs for p in parts):
                costs[n] = round(sum(costs[p] for p in parts), 1)
        allcosts[a.script] = dict(sorted(costs.items()))
        COSTS.write_text(json.dumps(allcosts, indent=1) + "\n", encoding="utf-8")

    seen: dict[str, dict] = {}
    real, load = [], []
    for n in names:
        parts = [f"{n}@{s}" for s in shards[n]] if n in shards else [n]
        if not all(p in results for p in parts):
            continue
        m = merge(n, parts, {p: (dict(results[p], status="pass") if verdict.get(p) == "load" else results[p]) for p in parts})
        if any(verdict.get(p) == "real" for p in parts):
            m = merge(n, parts, results)
            real.append(n)
        elif any(verdict.get(p) == "load" for p in parts):
            load.append(n)
        seen[n] = m
    (logs / "report.json").write_text(json.dumps({"tests": len(names), "processes": len(tasks), "results": list(seen.values()),
                                                  "rerun": verdict, "problems": problems, "machine": machine,
                                                  "wall_s": round(time.time() - started, 1)}, indent=1), encoding="utf-8")

    skipped = sorted(n for n, x in seen.items() if x["status"] == "skipped")
    print()
    for n in real:
        print(f"FAILED ALONE: {n}: {seen[n].get('note', '')[:400]}")
    for n in load:
        print(f"failed under load, passed alone: {n}")
    for line in problems:
        print("PROBLEM:", line)
    ok = sum(1 for n, x in seen.items() if x["status"] == "pass" and n not in load)
    print(f"{len(names)} tests: {ok} passed, {len(skipped)} skipped{' (' + ', '.join(skipped) + ')' if skipped else ''}, {len(real)} failed alone, "
          f"{len(load)} failed only under load, {len(problems)} problems; queue {queue_s:.0f} s, wall {time.time() - started:.0f} s, "
          f"machine: {machine}; logs {logs}")
    bad = bool(real or problems or (a.strict and load) or len(seen) < len(names))
    if len(seen) < len(names):
        print(f"only {len(seen)} of {len(names)} tests have a result")
    if not bad:
        shutil.rmtree(scratch, ignore_errors=True)
    print("FAILED" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
