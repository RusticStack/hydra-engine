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
"""Run a daemon_tests-style suite as several processes at once.

    python run_parallel.py --ghidra <install> --scratch <dir on a fast disk> --logs <dir> [--groups 6] \\
        daemon_tests.py -- --exe C:\\Windows\\System32\\choice.exe --dll C:\\Windows\\System32\\version.dll [--legacy-project ...]

The suites wait far more than they compute (the CPU is 5-10 % busy during a serial run), so the tests are split into
balanced groups and each group is its own `<script> --only a,b,c` process with its own --work and --tmpdir under
--scratch. Group costs come from suite-costs.json next to this file (seconds per test; 25 s when unknown) and are
refreshed with --record. Any script that takes --ghidra --work --tmpdir --only --report and prints its results the way
daemon_tests.py does works; --names a,b,c names the tests when the script has no --list (red_table.py: BP3,BP7,...).

The verdict is per test, from each group's --report file:
* a group that exits without a report, or with a test missing from it, is a PROBLEM (tests that did not run never pass);
* a test that fails is run again ALONE, on its own, with nothing else running (--rerun-alone, default 1): if it passes
  it is listed as "failed under load, passed alone" (a timing test that needs a quiet machine; exit 0 unless --strict);
  if it fails again it is a real failure (exit 1).
Scratch of a passing group is deleted at once; failing groups keep theirs. Put --scratch on the NVMe disk: these suites
write and fsync a lot.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COSTS = HERE / "suite-costs.json"
DEFAULT_COST_S = 25.0


def run(script, ghidra, work, tmp, extra, report, log, only=""):
    cmd = [sys.executable, str(HERE / script), "--ghidra", ghidra, "--work", str(work), "--tmpdir", str(tmp), "--report", str(report)]
    cmd += ["--only", only] if only else []
    return subprocess.Popen(cmd + extra, cwd=HERE, stdout=open(log, "w", encoding="utf-8", errors="replace"), stderr=subprocess.STDOUT)


def results_of(report: Path) -> dict:
    try:
        return {r["test"]: r for r in json.loads(report.read_text(encoding="utf-8"))["results"]}
    except (OSError, ValueError, KeyError):
        return {}


def names_of(script, ghidra, scratch, extra) -> list[str]:
    work = scratch / "_list"
    out = subprocess.run([sys.executable, str(HERE / script), "--ghidra", ghidra, "--work", str(work / "w"), "--tmpdir", str(work / "t"), "--list"] + extra,
                         cwd=HERE, capture_output=True, text=True)
    shutil.rmtree(work, ignore_errors=True)
    if out.returncode != 0:
        sys.exit("--list failed:\n" + (out.stdout + out.stderr)[-1500:])
    return [m.group(1) for m in (re.match(r"\s*(\w+)", l) for l in out.stdout.splitlines()) if m]


def split(names, costs, groups):
    order = sorted(names, key=lambda n: -costs.get(n, DEFAULT_COST_S))
    parts = [[] for _ in range(max(1, min(groups, len(order))))]
    load = [0.0] * len(parts)
    for n in order:
        k = load.index(min(load))
        parts[k].append(n)
        load[k] += costs.get(n, DEFAULT_COST_S)
    return parts, max(load)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True, help="the engine install")
    ap.add_argument("--scratch", required=True, help="parent of the --work/--tmpdir directories (a fast local disk)")
    ap.add_argument("--logs", required=True, help="where the group logs and reports go")
    ap.add_argument("--groups", type=int, default=6)
    ap.add_argument("--names", default="", help="comma-separated tests instead of asking the script for --list")
    ap.add_argument("--rerun-alone", type=int, default=1)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--record", action="store_true", help="refresh suite-costs.json from this run")
    ap.add_argument("script", help="daemon_tests.py")
    ap.add_argument("rest", nargs=argparse.REMAINDER, help="-- then the arguments every group gets")
    a = ap.parse_args()
    extra = [x for x in a.rest if x != "--"]
    scratch, logs = Path(a.scratch), Path(a.logs)
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    shutil.rmtree(logs, ignore_errors=True)
    logs.mkdir(parents=True)

    allcosts = json.loads(COSTS.read_text(encoding="utf-8")) if COSTS.exists() else {}
    costs = allcosts.get(a.script, {})
    names = [n for n in a.names.split(",") if n] or names_of(a.script, a.ghidra, scratch, extra)
    parts, estimate = split(names, costs, a.groups)
    print(f"{len(names)} tests in {len(parts)} groups, estimated {estimate:.0f} s; scratch {scratch}", flush=True)

    started = time.time()
    procs = [(k, g, run(a.script, a.ghidra, scratch / f"g{k}" / "w", scratch / f"g{k}" / "t", extra, logs / f"g{k}.json", logs / f"g{k}.log", ",".join(g)))
             for k, g in enumerate(parts)]
    seen: dict[str, dict] = {}
    problems: list[str] = []
    for k, g, p in procs:
        code = p.wait()
        got = results_of(logs / f"g{k}.json")
        seen.update(got)
        lost = [n for n in g if n not in got]
        if lost or (code != 0 and not any(r["status"] not in ("pass", "skipped") for r in got.values())):
            problems.append(f"g{k}: exit {code}, no result for {', '.join(lost) or 'nothing missing'} (log {logs / f'g{k}.log'})")
        elif code == 0:
            shutil.rmtree(scratch / f"g{k}", ignore_errors=True)
        print(f"g{k}: exit {code}, {sum(r['status'] == 'pass' for r in got.values())}/{len(g)} passed ({time.time() - started:.0f} s)", flush=True)

    failed = sorted(n for n, r in seen.items() if r["status"] not in ("pass", "skipped"))
    real, load = [], []
    for n in failed:
        verdict = "real"
        for i in range(a.rerun_alone):
            w = scratch / f"alone-{n}-{i}"
            q = run(a.script, a.ghidra, w / "w", w / "t", extra, logs / f"alone-{n}-{i}.json", logs / f"alone-{n}-{i}.log", n)
            q.wait()
            again = results_of(logs / f"alone-{n}-{i}.json").get(n)
            if again and again["status"] in ("pass", "skipped"):
                verdict = "load"
                shutil.rmtree(w, ignore_errors=True)
                break
            seen[n] = again or seen[n]
        (load if verdict == "load" else real).append(n)

    if a.record:
        for n, r in seen.items():
            if r["status"] == "pass" and "seconds" in r:
                costs[n] = r["seconds"]
        allcosts[a.script] = dict(sorted(costs.items()))
        COSTS.write_text(json.dumps(allcosts, indent=1) + "\n", encoding="utf-8")

    skipped = sorted(n for n, r in seen.items() if r["status"] == "skipped")
    print()
    for n in real:
        print(f"FAILED ALONE: {n}: {seen[n].get('note', '')[:400]}")
    for n in load:
        print(f"failed under load, passed alone: {n}")
    for line in problems:
        print("PROBLEM:", line)
    ok = sum(1 for r in seen.values() if r["status"] == "pass")
    print(f"{len(names)} tests: {ok} passed, {len(skipped)} skipped{' (' + ', '.join(skipped) + ')' if skipped else ''}, {len(real)} failed alone, "
          f"{len(load)} failed only under load, {len(problems)} group problems; wall {time.time() - started:.0f} s; logs {logs}")
    bad = bool(real or problems or (a.strict and load) or len(seen) < len(names))
    if len(seen) < len(names):
        print(f"only {len(seen)} of {len(names)} tests have a result")
    if not bad:
        shutil.rmtree(scratch, ignore_errors=True)
    print("FAILED" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
