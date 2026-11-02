# ###
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
"""Daemon-impact rounds of the semantic trace (12.3-hydra.6 WS-I): h5 against the candidate, interleaved.

    python -I trace_bench_rounds.py run  --h5 <install> --cand <install> --out <dir> [--rounds 3] [--readers 4]
                                         [--configs h5-auto,candtr-auto] [--affinity 4] [--vmargs -Xmx1g]
    python -I trace_bench_rounds.py report <result.json> [...]     # medians, digests, waits (markdown on stdout)
    python -I trace_bench_rounds.py mp-report <result.json> [...]  # the same for multiproj_bench.py runs (the soak)

Six configurations per round, each a fresh daemon of `multiagent_bench.py run` (the h5 fixed 825-op, 16-agent workload):

    h5-generic   h5-auto          the h5 release, HYDRA_CPU_PROFILE generic / auto
    cand-generic cand-auto        the candidate, no trace use (regression of everything that existed)
    candtr-generic candtr-auto    the candidate with the live capture and --readers trace readers beside the 16 agents

The order of the six rotates by one position each round (round 1 starts at h5-generic, round 2 at the next, ...), so
no configuration is always first or last on a machine that other jobs share. `report` prints, per configuration, the
median (min-max) of workload wall, process-tree CPU, peak and mean committed memory, ops/s and per-op p50/p99, and, per
run, the reply digest (must be the h5 one), `waits.foreignBlocked.total` (must be 0), the system busy cores, errors and
the trace digest of the closed reference sessions (must be one value).
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE / "multiagent_bench.py"
CONFIGS = ["h5-generic", "h5-auto", "cand-generic", "cand-auto", "candtr-generic", "candtr-auto"]


def run(a) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    engines = {"h5": a.h5, "cand": a.cand, "candtr": a.cand}
    plan = []
    configs = [c for c in CONFIGS if not a.configs or c in a.configs.split(",")]
    for rnd in range(a.rounds):
        order = configs[rnd % len(configs):] + configs[:rnd % len(configs)]
        plan.extend((rnd + 1, c) for c in order)
    for rnd, cfg in plan:
        engine = engines[cfg.split("-")[0]]
        profile = cfg.split("-")[1]
        args = [sys.executable, "-I", str(BENCH), "run", "--engine", engine, "--label", cfg, "--cpu-profile", profile,
                "--out", str(out)]
        if cfg.startswith("candtr"):
            args += ["--trace-readers", str(a.readers)]
        if a.affinity:
            args += ["--affinity", str(a.affinity)]
        if a.vmargs:
            args += ["--vmargs", a.vmargs]
        print(time.strftime("%H:%M:%S"), "round", rnd, cfg, flush=True)
        rc = subprocess.run(args, stdin=subprocess.DEVNULL, timeout=a.timeout).returncode
        print("  rc", rc, flush=True)
    return 0


def med(xs):
    xs = [x for x in xs if x is not None]
    return "%s (%s-%s)" % (round(statistics.median(xs), 2), round(min(xs), 2), round(max(xs), 2)) if xs else "-"


def report(paths) -> int:
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    labels = [c for c in CONFIGS if any(r["label"] == c for r in runs)]
    by = {c: [r for r in runs if r["label"] == c] for c in labels}
    print("Median (min-max) over %s runs per configuration, workload phase.\n" %
          ", ".join("%s %d" % (c, len(by[c])) for c in labels))
    print("| metric | " + " | ".join(labels) + " |")
    print("|---|" + "---|" * len(labels))
    rows = [
        ("workload wall s", lambda r: r["phases"]["workload"]["wall_s"]),
        ("tree CPU s (java+decompile+python)", lambda r: r["phases"]["workload"]["cpu_s"]["total"]),
        ("  java CPU s", lambda r: r["phases"]["workload"]["cpu_s"].get("java")),
        ("  python CPU s (agents; includes the trace agents)", lambda r: r["phases"]["workload"]["cpu_s"].get("python")),
        ("peak committed MB (tree)", lambda r: r["phases"]["workload"]["memory"].get("peak_mb")),
        ("mean committed MB (tree)", lambda r: r["phases"]["workload"]["memory"].get("mean_mb")),
        ("peak java private MB", lambda r: r["phases"]["workload"]["memory"].get("peak_java_mb")),
        ("agent ops ok (the 825-op workload)", lambda r: (r.get("ops_total_core") or r["ops_total"])["ok"]),
        ("agent ops/s", lambda r: round((r.get("ops_total_core") or r["ops_total"])["ok"] / r["phases"]["workload"]["wall_s"], 2)),
        ("trace ops ok", lambda r: r["ops_total"]["ok"] - (r.get("ops_total_core") or r["ops_total"])["ok"]),
        ("setup CPU s", lambda r: r["phases"]["setup"]["cpu_s"]["total"]),
        ("system busy cores (mean over workload)", lambda r: r["phases"]["workload"].get("load", {}).get("mean_busy_cores")),
    ]
    for name, fn in rows:
        cells = []
        for c in labels:
            vals = []
            for r in by[c]:
                try:
                    vals.append(fn(r))
                except (KeyError, TypeError):
                    pass
            cells.append(med(vals))
        print("| %s | %s |" % (name, " | ".join(cells)))
    ops = sorted({op for r in runs for op in r.get("ops", {})})
    print("\nPer op: median over runs of p50 / p99 ms.\n")
    print("| op | " + " | ".join(labels) + " |")
    print("|---|" + "---|" * len(labels))
    for op in ops:
        cells = []
        for c in labels:
            rs = [r["ops"][op] for r in by[c] if op in r.get("ops", {})]
            if not rs:
                cells.append("-")
                continue
            cells.append("%s / %s" % (round(statistics.median(x["p50_ms"] for x in rs if x["p50_ms"] is not None), 2),
                                      round(statistics.median(x["p99_ms"] for x in rs if x["p99_ms"] is not None), 2)))
        print("| %s | %s |" % (op, " | ".join(cells)))
    print("\nPer run correctness and waits.\n")
    print("| run | reply keys | agents digest | foreignBlocked total | contended | op errors (agents) | trace digest | trace keys | trace errors | trace appended |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(runs, key=lambda r: r["started"]):
        w = (r.get("daemon_status") or {}).get("waits") or {}
        fb = (w.get("foreignBlocked") or {}).get("total") if isinstance(w.get("foreignBlocked"), dict) else w.get("foreignBlocked")
        tc = r.get("trace_correctness") or {}
        wr = (r.get("trace_agents") or {}).get("trace-writer") or {}
        print("| %s %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
            r["label"], r["started"][-6:], r["correctness"]["keys"], r["correctness"]["digest"][:16], fb, w.get("contended"),
            (r.get("ops_total_core") or r["ops_total"])["errors"],
            ("`%s`" % tc["digest"][:16]) if tc else "-", tc.get("keys", "-"), len(tc.get("errors") or []) if tc else "-",
            wr.get("accepted", "-")))
    return 0


def mp_label(label: str) -> str:
    """`r2-candtr-a` -> `candtr-a`: the round prefix is not part of the configuration."""
    head, _, rest = label.partition("-")
    return rest if head.startswith("r") and head[1:].isdigit() else label


def mp_report(paths) -> int:
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    for r in runs:
        r["_cfg"] = mp_label(r["label"])
    labels = []
    for r in runs:
        if r["_cfg"] not in labels:
            labels.append(r["_cfg"])
    by = {c: [r for r in runs if r["_cfg"] == c] for c in labels}
    print("Median (min-max) per configuration; workload phase of the 16-agent, three-program run with Empire at War "
          "importing. Runs: %s.\n" % ", ".join("%s %d" % (c, len(by[c])) for c in labels))
    print("| metric | " + " | ".join(labels) + " |")
    print("|---|" + "---|" * len(labels))

    def core(r):
        return r.get("ops_total_core") or r["ops_total"]
    rows = [
        ("workload wall s", lambda r: r["phases"]["workload"]["wall_s"]),
        ("tree CPU s", lambda r: r["phases"]["workload"]["cpu_s"]["total"]),
        ("  java CPU s", lambda r: r["phases"]["workload"]["cpu_s"].get("java")),
        ("peak committed MB", lambda r: r["phases"]["workload"]["memory"].get("peak_mb")),
        ("mean committed MB", lambda r: r["phases"]["workload"]["memory"].get("mean_mb")),
        ("system busy cores", lambda r: r["phases"]["workload"].get("load", {}).get("mean_busy_cores")),
        ("agent ops ok", lambda r: core(r)["ok"]),
        ("agent op errors", lambda r: core(r)["errors"]),
        ("trace ops ok", lambda r: (r.get("trace_ops") or {}).get("ok", 0)),
        ("trace op errors", lambda r: (r.get("trace_ops") or {}).get("errors", 0)),
        ("trace events accepted", lambda r: (r.get("trace_agents", {}).get("trace-writer") or {}).get("accepted", 0)),
        ("replies with `waited` (all ops)", lambda r: (r.get("trace_ops") or {}).get("waited_replies", 0)
         + (r.get("trace_ops") or {}).get("waited_replies_core", 0)),
        ("foreignBlocked delta", lambda r: sum((m.get("waits_delta") or {}).get("foreignBlocked", 0)
                                              for m in r["monitor"].values())),
        ("queued lanes (max queued)", lambda r: max([v for m in r["monitor"].values()
                                                    for v in (m.get("max_queued") or {}).values()] or [0])),
        ("project trees byte-identical (1 = yes)", lambda r: int(r.get("project_hash_before") == r.get("project_hash_after")
                                                                 and bool(r.get("project_hash_before")))),
        ("fork edits re-opened and matching", lambda r: (r.get("verify") or {}).get("ok")),
    ]
    for name, fn in rows:
        cells = []
        for c in labels:
            vals = []
            for r in by[c]:
                try:
                    vals.append(fn(r))
                except (KeyError, TypeError):
                    pass
            cells.append(med(vals))
        print("| %s | %s |" % (name, " | ".join(cells)))
    ops = sorted({op for r in runs for op in r.get("ops", {}) if op.startswith(("trace_", "live_"))})
    if ops:
        print("\nTrace ops, median over runs of p50 / p99 ms.\n")
        print("| op | " + " | ".join(labels) + " |")
        print("|---|" + "---|" * len(labels))
        for op in ops:
            cells = []
            for c in labels:
                rs = [r["ops"][op] for r in by[c] if op in r.get("ops", {})]
                cells.append("%s / %s" % (round(statistics.median(x["p50_ms"] for x in rs if x["p50_ms"] is not None), 2),
                                          round(statistics.median(x["p99_ms"] for x in rs if x["p99_ms"] is not None), 2))
                             if rs else "-")
            print("| %s | %s |" % (op, " | ".join(cells)))
    print("\nPer run.\n")
    print("| run | agents digest (632 keys) | trace digest | wall s | tree CPU s | agent ops ok/err | trace ops ok/err | waited | foreignBlocked | trees identical | forks ok |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(runs, key=lambda r: r["started"]):
        t = r.get("trace_ops") or {}
        tc = r.get("trace_correctness") or {}
        fb = sum((m.get("waits_delta") or {}).get("foreignBlocked", 0) for m in r["monitor"].values())
        print("| %s | `%s` (%s) | %s | %s | %s | %s/%s | %s/%s | %s | %s | %s | %s |" % (
            r["label"], r["correctness"]["digest"][:12], r["correctness"]["keys"],
            ("`%s`" % tc["digest"][:12]) if tc else "-", r["phases"]["workload"]["wall_s"],
            r["phases"]["workload"]["cpu_s"]["total"], core(r)["ok"], core(r)["errors"], t.get("ok", 0), t.get("errors", 0),
            t.get("waited_replies", 0) + t.get("waited_replies_core", 0), fb,
            "yes" if r.get("project_hash_before") == r.get("project_hash_after") else "NO",
            (r.get("verify") or {}).get("ok")))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--h5", required=True)
    r.add_argument("--cand", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--rounds", type=int, default=3)
    r.add_argument("--readers", type=int, default=4)
    r.add_argument("--timeout", type=int, default=900)
    r.add_argument("--configs", default="", help="comma list of configurations to run (default: all six)")
    r.add_argument("--affinity", type=int, default=0, help="resource-constrained: logical CPUs 0..N-1 only")
    r.add_argument("--vmargs", default="", help="GHIDRA_SESSION_VMARGS for the daemon (for example -Xmx1g)")
    p = sub.add_parser("report")
    p.add_argument("results", nargs="+")
    m = sub.add_parser("mp-report")
    m.add_argument("results", nargs="+")
    a = ap.parse_args()
    if a.cmd == "run":
        return run(a)
    return report(a.results) if a.cmd == "report" else mp_report(a.results)


if __name__ == "__main__":
    sys.exit(main())
