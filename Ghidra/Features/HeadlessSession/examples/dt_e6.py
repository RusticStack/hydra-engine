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
"""The chaos and soak gate runner (PROTOCOL-3.md 9.17 and 9.15, package E6): is the runner able to fail?

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only soak_runner_selftest,chaos_runner_selftest,soak_planted_run

The release-length runs and the gate numbers are not taken here (D52: no gate number from a short run);
these tests prove that the runner works end to end and that violations planted into it are caught.

* ``soak_runner_selftest``: ``soak_tests.py selftest``, offline: the verdict logic (a run is PASS only when
  nothing is violated, every fault class reached its minimum and nothing is missing; a run that lacks a
  feature is INCOMPLETE with the gap named), the per-agent judgement (K3, K4, K5, K11) and the oracle
  plumbing, each with a planted violation.
* ``chaos_runner_selftest``: ``chaos_tests.py selftest``, offline: the counted kill batches of 9.15 (an
  acknowledged operation is not a kill, a lost acknowledged save, a ``.rep`` without ``.gpr``, a staging
  folder left, a blocked retry, a changed canonical tree and an unkilled control with anomalies are
  violations; a short count is INCOMPLETE; no ReFS volume is a named gap; the Wilson bound).
* ``soak_planted_run``: a live run of two agents on one project against this install, with the violations K2,
  K5, K6, K7, K9, K13, an unexplained ``busy`` and an unexpected error planted into it, both before any fault window and inside an
  all-scope one (``--plant all``): the
  verdict must be FAIL and must name every plant. The run is too short for a gate and says so
  (``smoke_numbers_are_not_gate_numbers``); it proves the pipeline: agents, ledgers, the header watcher, the
  file and process checks, the recovery read and the evidence writer.
"""
import json
import os
import pathlib
import subprocess
import sys

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent


def _run(args, timeout):
    p = subprocess.run([sys.executable, "-I", *map(str, args)], capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def t_soak_runner_selftest(c):
    rc, out = _run([HERE / "soak_tests.py", "selftest", "--work", c.work / "e6-soak-selftest"], 300)
    dt.check(rc == 0, "soak_tests.py selftest failed:\n" + out[-2500:])
    last = [ln for ln in out.splitlines() if ln.startswith("soak selftest:")]
    return last[-1] if last else "soak selftest ok"


def t_chaos_runner_selftest(c):
    rc, out = _run([HERE / "chaos_tests.py", "selftest"], 300)
    dt.check(rc == 0, "chaos_tests.py selftest failed:\n" + out[-2500:])
    last = [ln for ln in out.splitlines() if ln.startswith("chaos selftest:")]
    return last[-1] if last else "chaos selftest ok"


def t_soak_planted_run(c):
    gpr = c.fixture() / "Fixture.gpr"
    program = "/" + os.path.basename(c.a.exe)
    work = c.work / "e6-soak-run"
    ev = c.work / "e6-soak-evidence"
    for d in (work, ev):
        if d.exists():
            import shutil
            shutil.rmtree(d, ignore_errors=True)
    rc, out = _run([HERE / "soak_tests.py", "run", "--ghidra", c.a.ghidra, "--work", work, "--project", gpr,
                    "--program", program, "--profile", "smoke", "--agents", "2", "--projects", "1",
                    "--duration-s", "100", "--no-faults", "--plant", "all", "--evidence", ev], 900)
    verdict_file = ev / "soak-verdict.json"
    dt.check(verdict_file.exists(), "the runner wrote no evidence:\n" + out[-2500:])
    v = json.loads(verdict_file.read_text(encoding="utf-8"))["data"]
    dt.check(v["verdict"] == "FAIL", f"a run with planted violations ended {v['verdict']}:\n{json.dumps(v['violations'])[:1500]}")
    dt.check(v["plants"]["all_caught"], f"planted violations the run did not name: {v['plants']['missing']}; "
             f"violations seen: {v['violations']}")
    dt.check(v["smoke_numbers_are_not_gate_numbers"] and not v["gate_eligible"], "a planted short run claimed to be a gate run")
    dt.check(rc == 0, f"exit {rc} for a planted run that caught every plant:\n{out[-1500:]}")
    return (f"FAIL as planted, {len(v['violations'])} violation kinds named, plants caught: "
            f"{sorted(v['plants']['requested'])}; ops {v['workload_counts']}")


TESTS = {
    "soak_runner_selftest": t_soak_runner_selftest,
    "chaos_runner_selftest": t_chaos_runner_selftest,
    "soak_planted_run": t_soak_planted_run,
}
