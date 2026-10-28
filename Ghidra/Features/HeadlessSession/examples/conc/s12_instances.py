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
"""S12: does a SEPARATE program instance (overlay: own DBHandle) lift the DB-bound ceiling? N clients loop `functions` (regex, 2000 rows) on (a) the ONE shared program,
(b) each client's OWN overlay. Single run per cell."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
out = {}
d = fresh("s12")
try:
    gpr = copy_project(base_project(), "s12")
    cl = [d.connect("s12-%d" % i, "probe") for i in range(8)]
    for c in cl: o = c.call("open_project", path=str(gpr)); pid = o["id"]; c.call("open_program", path=PROG, project=pid)
    prog = prog_key(pid)
    for c in cl: c.call("open_program", path=PROG, project=pid, overlay="o")
    def run(n, overlay, per=6):
        def w(i):
            kw = dict(program=prog, regex=FUNRX, limit=2000)
            if overlay: kw["overlay"] = "o"
            for _ in range(per): cl[i].call("functions", **kw)
        t = time.perf_counter(); par([(lambda i=i: w(i)) for i in range(n)]); wall = ms(t)
        return {"n": n, "wall_ms": wall, "calls_per_s": round(n * per / (wall / 1000), 1)}
    run(1, False, 2); run(1, True, 2)
    for ov in (False, True):
        out["overlay" if ov else "shared_program"] = [run(n, ov) for n in (1, 2, 4, 8)]
finally:
    d.stop(force=True)
    save("s12_instances", out)
