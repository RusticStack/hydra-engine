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
"""S1: exclusive-queued-refuses-readers. A holds a long shared read (contained coop script, 20 s). B's releaseUse (close_program, or disconnect)
queues an exclusive on the fair program lock. C probes readers meanwhile. Single run per variant."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
SCRIPT = str(SCRIPTS / "LockHold.java")
def variant(name, how):
    d = fresh("s1" + name)
    out = {"variant": name, "events": []}
    try:
        gpr = copy_project(base_project(), "s1" + name)
        A, B, C, D = [d.connect("s1-" + n, "probe") for n in "ABCD"]
        pid = None
        for c in (A, B, C, D):
            o = c.call("open_project", path=str(gpr)); pid = o["id"]
        prog = prog_key(pid)
        for c in (A, B, C):
            c.call("open_program", path=PROG, project=pid)
        t0 = time.perf_counter()
        def ev(k, v): out["events"].append({"t": round(time.perf_counter() - t0, 2), k: v})
        resA = {}
        def runA():
            r = timed(A.call, "script", script=SCRIPT, args=["coop", "20"], program=prog, wait=30000)
            resA["r"] = r[:2] + (str(r[2])[:120],); ev("A script done", resA["r"])
        ta = threading.Thread(target=runA); ta.start()
        time.sleep(2.0)
        resB = {}
        def runB():
            if how == "close":
                r = timed(B.call, "close_program", program=prog)           # default wait 10s
            elif how == "close_short":
                r = timed(B.call, "close_program", program=prog, wait=100)
            else:
                t = time.perf_counter(); B.close(); r = (True, ms(t), "socket closed (cleanup runs async in daemon)")
            resB["r"] = r[:2] + (str(r[2])[:200],); ev("B " + how + " returned", resB["r"])
        tb = threading.Thread(target=runB); tb.start()
        time.sleep(0.5)
        # probes by C every ~2 s until A is done + 3 s; each probe wait=1500 ms
        probes = []
        def probe(label, fn):
            r = timed(fn); probes.append({"t": round(time.perf_counter() - t0, 2), "op": label, "ok": r[0], "ms": r[1],
                                          "code": None if r[0] else r[2]["code"], "detail": None if r[0] else r[2]["message"][:110]})
        t_end = time.perf_counter() + 28
        while time.perf_counter() < t_end:
            probe("C info", lambda: C.call("info", program=prog, wait=1500))
            probe("C functions", lambda: C.call("functions", program=prog, limit=1, wait=1500))
            probe("C decompile", lambda: C.call("decompile", program=prog, name="FUN_%08x" % ADDR_BASE, wait=1500) if False else C.call("functions", program=prog, limit=1, wait=1500))
            probe("D open_program(join)", lambda: D.call("open_program", path=PROG, project=pid, wait=1500))
            probe("D close_program", lambda: D.call("close_program", program=prog, wait=300))
            time.sleep(2.0)
            if not ta.is_alive() and probes and probes[-1]["ok"]:
                break
        ta.join(); tb.join()
        out["probes"] = probes
        st = C.call("status")
        out["status_sched"] = {k: {kk: v[kk] for kk in ("slots","inUse","queued","everQueued")} for k, v in st["scheduler"].items()}
    finally:
        try: d.stop(force=True)
        except Exception as e: print("stop", e)
    return out
res = [variant("a_close_wait10s", "close"), variant("b_disconnect", "disc"), variant("c_close_wait100ms", "close_short")]
save("s1_xqueue", res)
