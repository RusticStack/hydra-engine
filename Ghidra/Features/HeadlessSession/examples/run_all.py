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
"""Every engine suite of this folder in one work queue: the daemon suite, client_compat, session_smoke,
characterization (protocol 2 and 3) and contract.

    python run_all.py --ghidra <install> --scratch <dir on a fast disk> --logs <dir> [--workers 16] [--only daemon,cc,...]
        [--exe C:\\Windows\\System32\\choice.exe --dll C:\\Windows\\System32\\version.dll --legacy-project <.gpr>]

It is run_parallel.py's queue with more suites in it: the daemon suite's tests and shards one process each (with the
seed), client_compat's tests in --cc-chunks processes (each makes its fixture once), and session_smoke,
characterization p2, characterization p3 and contract as one process each (they are single sequences). The queue is
longest first across all of them, under one --workers budget and the same machine limits (commit, processes, heavy
slots). The verdict policy is run_parallel.py's: a failure is run again alone, with nothing else running; it is a real
failure only when it fails again. Suites: daemon, cc, smoke, char2, char3, contract.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

import run_parallel as rp

SUITES = ("daemon", "cc", "smoke", "char2", "char3", "contract")
#: recorded seconds of the suites that run as one process (serial runs on this machine)
WHOLE_COST = {"smoke": 64.0, "char2": 42.0, "char3": 45.0, "contract": 19.0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--logs", required=True)
    ap.add_argument("--exe", default=r"C:\Windows\System32\choice.exe")
    ap.add_argument("--dll", default=r"C:\Windows\System32\version.dll")
    ap.add_argument("--smoke-binary", dest="smoke_binary", action="append", default=None,
                    help=r"session_smoke --binary (default: --exe and C:\Windows\System32\whoami.exe)")
    ap.add_argument("--legacy-project", dest="legacy_project",
                    default=str(rp.HERE / "fixtures" / "legacy-12.1.4" / "legacy.gpr"))
    ap.add_argument("--only", default=",".join(SUITES), help=f"suites to run (default all: {','.join(SUITES)})")
    ap.add_argument("--workers", type=int, default=rp.DEFAULT_WORKERS)
    ap.add_argument("--cc-chunks", dest="cc_chunks", type=int, default=4, help="client_compat processes (default 4)")
    ap.add_argument("--max-procs", dest="max_procs", type=int, default=rp.DEFAULT_MAX_PROCS)
    ap.add_argument("--min-commit-gb", dest="min_commit", type=float, default=rp.DEFAULT_MIN_COMMIT_GB)
    ap.add_argument("--heavy-slots", dest="heavy_slots", type=int, default=rp.DEFAULT_HEAVY_SLOTS)
    ap.add_argument("--task-timeout", dest="task_timeout", type=float, default=1800)
    ap.add_argument("--rerun-alone", type=int, default=1)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--no-shards", dest="no_shards", action="store_true")
    ap.add_argument("--no-seed", dest="no_seed", action="store_true")
    ap.add_argument("--seed-aot", dest="seed_aot", action="store_true")
    ap.add_argument("--seed-cache", dest="seed_cache", default=None)
    ap.add_argument("--shared-settings", dest="isolate_settings", action="store_false")
    a = ap.parse_args()
    want = [s for s in a.only.split(",") if s]
    bad_names = set(want) - set(SUITES)
    if bad_names:
        ap.error(f"unknown suites {sorted(bad_names)}; known: {', '.join(SUITES)}")
    scratch, logs = Path(a.scratch), Path(a.logs)
    if a.seed_cache is None:
        a.seed_cache = str(scratch.parent / "seed-cache")
    elif a.seed_cache.lower() == "none":
        a.seed_cache = None
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    shutil.rmtree(logs, ignore_errors=True)
    logs.mkdir(parents=True)
    started = time.time()
    allcosts = json.loads(rp.COSTS.read_text(encoding="utf-8")) if rp.COSTS.exists() else {}
    pe = ["--exe", a.exe, "--dll", a.dll]
    items: list[tuple[rp.Runner, str, float]] = []      # (runner, task, cost)
    parts: dict[str, list[str]] = {}                    # reported name -> its result keys
    heavy: set[str] = set()

    if "daemon" in want:
        r = rp.Runner(a, "daemon_tests.py", pe + ["--legacy-project", a.legacy_project], scratch, logs, prefix="")
        code, names, text = r.listing("--list")
        if code != 0:
            sys.exit("daemon_tests --list failed:\n" + text[-1500:])
        shards: dict[str, list[str]] = {}
        if not a.no_shards:
            code, lines, _ = r.listing("--list-shards")
            for line in lines if code == 0 else []:
                t, _, s = line.partition("@")
                if t in names and s:
                    shards.setdefault(t, []).append(s)
        costs = allcosts.get("daemon_tests.py", {})
        for t in rp.plan(names, shards, costs):
            items.append((r, t, rp.task_cost(t, costs, shards)))
        for n in names:
            parts[n] = [f"{n}@{s}" for s in shards[n]] if n in shards else [n]
        heavy |= set(allcosts.get("daemon_tests.py#heavy", []))
        print(r.prepare_seed() + f" ({time.time() - started:.0f} s)", flush=True)
    if "cc" in want:
        r = rp.Runner(a, "client_compat_tests.py", pe, scratch, logs, prefix="cc:")
        code, names, text = r.listing("--list")
        if code != 0:
            sys.exit("client_compat --list failed:\n" + text[-1500:])
        costs = allcosts.get("client_compat_tests.py", {})
        chunks = [[] for _ in range(max(1, min(a.cc_chunks, len(names))))]
        load = [0.0] * len(chunks)
        for n in sorted(names, key=lambda n: -costs.get(n, 5.0)):
            k = load.index(min(load))
            chunks[k].append(n)
            load[k] += costs.get(n, 5.0)
        for ch, c in zip(chunks, load):
            items.append((r, ",".join(ch), max(c, 210.0 / len(chunks))))
        for n in names:
            parts["cc:" + n] = ["cc:" + n]
    smoke_bins = a.smoke_binary or [a.exe, r"C:\Windows\System32\whoami.exe"]
    whole = {"smoke": ("session_smoke.py", [x for b in smoke_bins for x in ("--binary", b)]),
             "char2": ("characterization_tests.py", ["--protocol", "2"]),
             "char3": ("characterization_tests.py", ["--protocol", "3", "--require-v3"]),
             "contract": ("contract_tests.py", [])}
    for s in ("smoke", "char2", "char3", "contract"):
        if s in want:
            script, extra = whole[s]
            r = rp.Runner(a, script, extra, scratch, logs, prefix=s + ":", whole=True)
            items.append((r, s, WHOLE_COST[s]))
            parts[f"{s}:{s}"] = [f"{s}:{s}"]
    items.sort(key=lambda x: -x[2])
    est = rp.lpt_estimate([c for _, _, c in items], a.workers)
    print(f"{len(parts)} results from {len(items)} processes of {len(want)} suites, {a.workers} at once; estimated {est:.0f} s", flush=True)

    results: dict[str, dict] = {}
    problems: list[str] = []
    q0 = time.time()
    machine = rp.run_queue([(r, t) for r, t, _ in items], a.workers, a.max_procs, a.min_commit, a.task_timeout, results,
                           problems, started, heavy, a.heavy_slots)
    queue_s = time.time() - q0

    by_key = {r.prefix + n: (r, t) for r, t, _ in items for n in t.split(",")}
    verdict: dict[str, str] = {}
    for key in sorted(k for k, x in results.items() if x["status"] not in rp.GOOD):
        r, _t = by_key[key]
        task = key[len(r.prefix):]
        verdict[key] = "real"
        for i in range(a.rerun_alone):
            j = r.start(task, f"-alone{i}", heavy=rp.is_heavy(r, task, heavy))
            j["proc"].wait()
            again = r.result(j, time.time() - j["t0"]).get(task)
            print(f"alone   {key:40s} {again['status'] if again else 'NO RESULT'}", flush=True)
            if again and again["status"] in rp.GOOD:
                verdict[key] = "load"
                shutil.rmtree(j["work"], ignore_errors=True)
                break
            if again:
                results[key] = again

    real, load, seen = [], [], {}
    for name, ps in parts.items():
        if not all(p in results for p in ps):
            continue
        m = rp.merge(name, ps, {p: (dict(results[p], status="pass") if verdict.get(p) == "load" else results[p]) for p in ps})
        if any(verdict.get(p) == "real" for p in ps):
            m = rp.merge(name, ps, results)
            real.append(name)
        elif any(verdict.get(p) == "load" for p in ps):
            load.append(name)
        seen[name] = m
    per_suite = {}
    for name, m in seen.items():
        s = name.split(":", 1)[0] if ":" in name else "daemon"
        d = per_suite.setdefault(s, {"results": 0, "pass": 0, "skipped": 0})
        d["results"] += 1
        d["pass"] += m["status"] == "pass" and name not in load
        d["skipped"] += m["status"] == "skipped"
    (logs / "report.json").write_text(json.dumps({"suites": want, "per_suite": per_suite, "results": list(seen.values()), "rerun": verdict,
                                                  "problems": problems, "machine": machine, "wall_s": round(time.time() - started, 1)},
                                                 indent=1), encoding="utf-8")
    print()
    for n in real:
        print(f"FAILED ALONE: {n}: {seen[n].get('note', '')[:400]}")
    for n in load:
        print(f"failed under load, passed alone: {n}")
    for line in problems:
        print("PROBLEM:", line)
    for s, d in per_suite.items():
        print(f"  {s:9s} {d['pass']}/{d['results']} passed, {d['skipped']} skipped")
    print(f"{len(parts)} results: {sum(d['pass'] for d in per_suite.values())} passed, {len(real)} failed alone, {len(load)} failed only "
          f"under load, {len(problems)} problems; queue {queue_s:.0f} s, wall {time.time() - started:.0f} s, machine {machine}; logs {logs}")
    bad = bool(real or problems or (a.strict and load) or len(seen) < len(parts))
    if len(seen) < len(parts):
        print(f"only {len(seen)} of {len(parts)} have a result")
    if not bad:
        shutil.rmtree(scratch, ignore_errors=True)
    print("FAILED" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
