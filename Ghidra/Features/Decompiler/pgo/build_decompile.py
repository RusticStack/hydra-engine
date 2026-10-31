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
# ###
"""Builds decompile.exe outside Gradle with the exact flags of buildNatives.gradle, plus profile-guided
optimisation (PGO) variants. Usage:
  python build_decompile.py base|sym|pgi|pgo [--out DIR] [--pgd FILE] [--jobs N] [--vc vcvars64.bat] [--cl FLAG]...
  base  release flags only (what Gradle builds without a .pgd)
  sym   release flags + /Zi /DEBUG (symbols for samply / WPA)
  pgi   instrumented (/GENPROFILE); run any decompile workload (e.g. a golden capture or the
        benchmark) with the instrumented exe installed, which writes the .pgc profile data, then
  pgo   optimised with /USEPROFILE:PGD=<pgd> (default: decompile.pgd next to this script)
Output: <out>/decompile-<mode>.exe. Objects in <out>/obj-<mode>. The profile data and built
binaries are build output: commit this script, never the .pgd/.pgc/exe files."""
import argparse, os, re, subprocess, sys, time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["base", "sym", "pgi", "pgo"])
ap.add_argument("--out", default="C:/dev-overflow/hydra-perf/o2-decomp/native")
ap.add_argument("--pgd", default=None)
ap.add_argument("--jobs", type=int, default=8)
ap.add_argument("--vc", default="C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Auxiliary/Build/vcvars64.bat")
ap.add_argument("--cl", action="append", default=[])
ap.add_argument("--no-mimalloc", action="store_true")
ap.add_argument("--extra-src", action="append", default=[], help="extra .cc file compiled in (profiling shims)")
a = ap.parse_args()
here = Path(__file__).resolve().parent
dec = here.parent
cpp = dec / "src/decompile/cpp"
pgd = a.pgd or str(here / "decompile.pgd")
names = []
for line in (dec / "buildNatives.gradle").read_text().splitlines():
    if re.match(r"\s*sleigh\(NativeExecutableSpec\)", line):
        break
    m = re.match(r'\s*include\s+"([A-Za-z0-9_]+\.cc)"', line)
    if m:
        names.append(m.group(1))
if a.no_mimalloc:
    names.remove("hydra_alloc.cc")
out = Path(a.out); obj = out / ("obj-" + a.mode); obj.mkdir(parents=True, exist_ok=True)
defs = ["_SECURE_SCL=0", "_HAS_ITERATOR_DEBUGGING=0", "WINDOWS", "_WINDOWS", "WIN32", "_WIN32", "WIN64", "_WIN64", "HYDRA_ALLOC_IDLE"]
cl = ["/nologo", "/c", "/TP", "/EHsc", "/W3", "/O2", "/Oy", "/GL", "/MP%d" % a.jobs, "/I" + str(cpp),
      "/I" + str(dec / "src/decompile/mimalloc/include"), "/Fo" + str(obj) + "/"] + ["/D" + d for d in defs] + a.cl
link = ["/nologo", "/LTCG", "/OUT:%s/decompile-%s.exe" % (out, a.mode)]
if a.mode == "sym":
    cl += ["/Zi", "/FS", "/Fd%s/vc.pdb" % obj]; link += ["/DEBUG", "/OPT:REF", "/OPT:ICF"]
elif a.mode == "pgi":
    link += ["/GENPROFILE:PGD=%s/decompile-pgi.pgd" % out]
elif a.mode == "pgo":
    link += ["/USEPROFILE:PGD=" + pgd]
link.append("advapi32.lib")
q = lambda s: '"%s"' % s if " " in s else s
(obj / "cl.rsp").write_text("\n".join(q(x) for x in cl + [str(cpp / n) for n in names] + a.extra_src))
(obj / "link.rsp").write_text("\n".join(q(x) for x in link + [str(obj / n.replace(".cc", ".obj")) for n in names] + [str(obj / Path(x).stem) + ".obj" for x in a.extra_src]))
bat = obj / "build.cmd"
bat.write_text('@echo off\ncall "%s" >nul\ncl @"%s" || exit /b 1\nlink @"%s" || exit /b 1\n' % (a.vc, obj / "cl.rsp", obj / "link.rsp"))
t = time.time()
r = subprocess.run(["cmd", "/c", str(bat)])
if r.returncode:
    sys.exit("build failed %d" % r.returncode)
print("built %s in %.0f s -> %s" % (a.mode, time.time() - t, out))
