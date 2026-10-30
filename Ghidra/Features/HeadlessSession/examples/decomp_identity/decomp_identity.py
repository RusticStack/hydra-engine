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
"""Decompiler output identity between two engines or two settings. Standard library only.

Imports each binary into a throwaway project, decompiles every function in address order with
DecompileAllC.java and compares the C text byte for byte.

    python decomp_identity.py --engine <install> [--ref-engine <install>] [--flag-b -Dx=y] <exe>...

Without --ref-engine both runs use --engine; run A has no extra JVM options, run B has --flag-b
(default -Dhydra.decompiler.keepTypes=true). Exit 0 when every binary decompiles to identical text.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(engine, exe, work, tag, java_opts):
    out = os.path.join(work, tag + "-" + os.path.basename(exe) + ".c")
    env = dict(os.environ, JAVA_TOOL_OPTIONS=java_opts)
    launcher = os.path.join(engine, "support",
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    proj = os.path.join(work, "proj-" + tag)
    os.makedirs(proj, exist_ok=True)
    p = subprocess.run([launcher, proj, "p", "-import", exe, "-scriptPath", HERE, "-postScript",
        "DecompileAllC.java", out, "-deleteProject"], env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, errors="replace", timeout=1800)
    m = re.search(r"DECOMPILE_ALL functions=(\d+) ms=(\d+)", p.stdout + p.stderr)
    if p.returncode != 0 or not m:
        sys.exit("%s on %s failed (exit %d):\n%s" % (tag, exe, p.returncode, p.stdout[-2000:]))
    with open(out, "rb") as f:
        return f.read(), int(m.group(1)), int(m.group(2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--ref-engine")
    ap.add_argument("--flag-b", default="-Dhydra.decompiler.keepTypes=true")
    ap.add_argument("exes", nargs="+")
    a = ap.parse_args()
    ref = a.ref_engine or a.engine
    flag_b = a.flag_b if not a.ref_engine else ""
    bad = 0
    with tempfile.TemporaryDirectory() as work:
        for exe in a.exes:
            ca, n, ms_a = run(ref, exe, work, "a", "")
            cb, _, ms_b = run(a.engine, exe, work, "b", flag_b)
            same = ca == cb
            bad += not same
            print("%-4s %s functions=%d a_ms=%d b_ms=%d" % ("ok" if same else "FAIL",
                os.path.basename(exe), n, ms_a, ms_b))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
