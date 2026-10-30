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
"""hydraCpuBench: the contributor benchmark for CPU tuning profiles (docs/cpu-profiles.md).

Runs one fixed workload (import + auto-analysis of one binary, then a decompile of every non-thunk function)
in a fresh daemon per profile and round, once with ``HYDRA_CPU_PROFILE=generic`` and once with the profile
under test (``auto`` by default), and prints the before/after numbers in the format a profile PR quotes.
The decompiled C of every function is hashed: the two profiles must produce identical output (a profile
changes performance knobs only), and the run fails (exit 1) when they do not.

    python cpu_bench.py --ghidra <install> --work <empty dir> [--exe C:/Windows/System32/choice.exe]
                        [--profile auto|<name>] [--rounds 3] [--limit 0]

Standard library only. Nothing is written outside ``--work``. The daemon log line ``cpu: {...}`` (written at
start-up by HeadlessSession) supplies the detected CPU, the granted CPUs and the active profile.

Output (one block; the numbers are medians over the rounds):

    hydra-cpu-bench 1
    cpu       GenuineIntel family 6 model 183 | 24 logical, 16 granted | hybrid false
    workload  choice.exe: import+analyze, decompile 57 functions | 3 rounds
    profile                  analyze_s  decompile_s    total_s  digest
    generic                     12.345        3.210     15.555  0123abcd4567
    auto(raptorlake-hybrid)     11.900        3.050     14.950  0123abcd4567
    change                       -3.6%        -5.0%      -3.9%
    outputs   identical
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import statistics
import sys
import time

MAKE_PROJECT = """// @category HeadlessSession.Bench
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class BenchMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
"""

CPU_LINE = re.compile(r"cpu: \{(.*)\}")


def load_launcher(ghidra):
    sys.path.insert(0, str(pathlib.Path(ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support"))
    import ghidra_session
    return ghidra_session


def parse_cpu(log_text):
    """The last ``cpu: {k=v, ...}`` line of a daemon log as a dict (values are strings)."""
    found = None
    for line in log_text.splitlines():
        m = CPU_LINE.search(line)
        if m:
            found = m.group(1)
    if found is None:
        return None
    out = {}
    for part in found.split(", "):
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    return out


def run_once(gs, ghidra, exe, work, profile, tag, limit):
    """One fresh daemon under ``HYDRA_CPU_PROFILE=profile``: import+analyze, decompile all. Returns a dict."""
    root = work / tag
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    state, scripts = root / "state", root / "scripts"
    state.mkdir(parents=True)
    scripts.mkdir(parents=True)
    (scripts / "BenchMakeProject.java").write_text(MAKE_PROJECT)
    (state / "config.json").write_text(json.dumps({"tmpdir": str(root / "tmp"), "scriptPath": [str(scripts)]}))
    old = os.environ.get("HYDRA_CPU_PROFILE")
    os.environ["HYDRA_CPU_PROFILE"] = profile  # the daemon's JVM inherits it at launch
    d = gs.Daemon(ghidra, str(state), "cpubench")
    try:
        with d.connect("cpubench", "cpubench") as s:
            s.call("script", script=str(scripts / "BenchMakeProject.java"), program=None,
                   args=[str(root), "Bench"])
            s.call("open_project", path=str(root / "Bench.gpr"), writable=True)
            t0 = time.perf_counter()
            s.call("import", file=str(exe), analyze=True, timeout=1800, wait=600000)
            t_an = time.perf_counter() - t0
            fns = [f["address"] for f in s.call("functions", limit=10000)["functions"]
                   if not f["thunk"] and not f["external"]]
            if limit:
                fns = fns[:limit]
            h = hashlib.sha256()
            t1 = time.perf_counter()
            for a in fns:
                r = s.call("decompile", address=a, timeout=300)
                h.update(a.encode() + b"\0" + (r.get("c") or "").encode() + b"\0")
            t_dc = time.perf_counter() - t1
            s.call("close_project")
        log = pathlib.Path(d.log_file).read_text(encoding="utf-8", errors="replace") \
            if pathlib.Path(d.log_file).is_file() else ""
    finally:
        if old is None:
            os.environ.pop("HYDRA_CPU_PROFILE", None)
        else:
            os.environ["HYDRA_CPU_PROFILE"] = old
        d.stop()
    return {"analyze_s": t_an, "decompile_s": t_dc, "total_s": t_an + t_dc, "functions": len(fns),
            "digest": h.hexdigest(), "cpu": parse_cpu(log)}


def bench(ghidra, exe, work, profile="auto", rounds=3, limit=0, out=print):
    gs = load_launcher(ghidra)
    work = pathlib.Path(work).absolute()
    work.mkdir(parents=True, exist_ok=True)
    runs = {"generic": [], profile: []}
    for r in range(rounds):  # interleaved, so drift of the machine hits both sides alike
        for p in ("generic", profile):
            runs[p].append(run_once(gs, ghidra, pathlib.Path(exe), work, p, f"{p}-{r}", limit))
    med = {p: {k: statistics.median(x[k] for x in v) for k in ("analyze_s", "decompile_s", "total_s")}
           for p, v in runs.items()}
    digests = {x["digest"] for v in runs.values() for x in v}
    cpu = runs[profile][-1]["cpu"] or {}
    active = cpu.get("profile", "?")
    label = profile if profile == active else f"{profile}({active})"
    out("hydra-cpu-bench 1")
    out(f"cpu       {cpu.get('vendor', '?')} family {cpu.get('family', '?')} model {cpu.get('model', '?')} | "
        f"{cpu.get('systemCpus', '?')} logical, {cpu.get('grantedCpus', '?')} granted | hybrid {cpu.get('hybrid', '?')}")
    out(f"workload  {pathlib.Path(exe).name}: import+analyze, decompile {runs[profile][0]['functions']} functions | "
        f"{rounds} rounds")
    out(f"{'profile':<24}{'analyze_s':>10}{'decompile_s':>13}{'total_s':>11}  digest")
    for p, name in (("generic", "generic"), (profile, label)):
        m = med[p]
        out(f"{name:<24}{m['analyze_s']:>10.3f}{m['decompile_s']:>13.3f}{m['total_s']:>11.3f}  "
            f"{runs[p][0]['digest'][:12]}")
    ch = [(med[profile][k] - med["generic"][k]) / med["generic"][k] * 100 if med["generic"][k] else 0.0
          for k in ("analyze_s", "decompile_s", "total_s")]
    out(f"{'change':<24}{ch[0]:>+9.1f}%{ch[1]:>+12.1f}%{ch[2]:>+10.1f}%")
    out("outputs   " + ("identical" if len(digests) == 1 else f"DIFFERENT ({len(digests)} digests)"))
    return {"runs": runs, "median": med, "identical": len(digests) == 1, "cpu": cpu,
            "generic_cpu": runs["generic"][-1]["cpu"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--exe", default=r"C:\Windows\System32\choice.exe")
    ap.add_argument("--profile", default="auto")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0, help="decompile only the first N functions (0: all)")
    ap.add_argument("--json", help="also write the raw results here")
    a = ap.parse_args()
    res = bench(a.ghidra, a.exe, a.work, a.profile, a.rounds, a.limit)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, indent=1, default=str))
    return 0 if res["identical"] else 1


if __name__ == "__main__":
    sys.exit(main())
