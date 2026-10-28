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
"""S13: the session REGISTRY monitor. open_project(writable) on a read-only view calls makeWritable (waits for project X up to `wait`) INSIDE synchronized(registry).
While it waits behind a 14 s reader of project P1: how long does open_project of an UNRELATED project P2 (and a leave/disconnect) take?"""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
out = {}
d = fresh("s13")
try:
    g1 = copy_project(base_project(), "s13a"); g2 = copy_project(FIX_SRC / "fx-x64-flow", "s13b"); g3 = copy_project(FIX_SRC / "fx-x64-vcall", "s13c")
    S, Q, V, U = (d.connect("s13-" + n, "probe") for n in "SQVU")
    p1 = S.call("open_project", path=str(g1))["id"]; Q.call("open_project", path=str(g1))      # read-only view P1
    S.call("open_program", path=PROG, project=p1)
    U.call("open_project", path=str(g3)); 
    t0 = time.perf_counter()
    th = threading.Thread(target=lambda: S.call("script", script="LockHold.java", args=["coop", "14"], program=prog_key(p1), wait=60000)); th.start(); time.sleep(1.5)
    qres = {}
    tq = threading.Thread(target=lambda: qres.setdefault("r", timed(Q.call, "open_project", path=str(g1), writable=True, wait=10000)[:2])); tq.start(); time.sleep(0.7)
    r_open = timed(V.call, "open_project", path=str(g2))              # unrelated project, first open
    out["V_open_unrelated_project_while_Q_waits"] = {"ok": r_open[0], "ms": r_open[1], "t_done": round(time.perf_counter() - t0, 1)}
    r_leave = timed(U.call, "close_project", project=U.call("projects")["projects"][0]["id"] if False else "p3")
    out["U_close_own_unrelated_project"] = {"ok": r_leave[0], "ms": r_leave[1], "res": str(r_leave[2])[:150]}
    tq.join(); th.join()
    out["Q_open_writable"] = qres.get("r")
finally:
    d.stop(force=True)
    save("s13_registry", out)
