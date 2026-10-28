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
"""S5: lane slots. (a) quick-lane: 24 waiters blocked on program lock of X (held exclusive by an owner script) each HOLD a quick slot while they wait;
a victim on another project is then refused a slot. (b) long lane saturated by 6 scripts: save/refresh/fork/analyze of an unrelated project queue/busy."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
out = {}
d = fresh("s5")
try:
    gprX = copy_project(base_project(), "s5x")
    gprY = copy_project(FIX_SRC / "fx-x64-flow", "s5y")
    A = d.connect("s5-A", "probe"); V = d.connect("s5-V", "probe")
    W = [d.connect("s5-w%d" % i, "probe") for i in range(26)]
    oX = A.call("open_project", path=str(gprX), writable=True); X = oX["id"]
    oY = V.call("open_project", path=str(gprY), writable=True); Y = oY["id"]
    A.call("open_program", path=PROG, project=X, writable=True)
    ly = V.call("list", project=Y, programsOnly=True)
    out["Y_programs"] = [f.get("path") or f for f in ly.get("files", ly.get("entries", []))][:5] if isinstance(ly, dict) else str(ly)[:300]
    print("Y list:", str(ly)[:400])
    ypath = None
    for k in ("files", "entries", "items"):
        if k in ly and ly[k]: ypath = ly[k][0].get("path") or ly[k][0].get("pathname"); break
    V.call("open_program", path=ypath, project=Y, writable=True)
    progX, progY = prog_key(X), Y + ":" + ypath
    for c in W:
        c.call("open_project", path=str(gprX)); c.call("open_program", path=PROG, project=X)
    # (a)
    t0 = time.perf_counter()
    holder = threading.Thread(target=lambda: A.call("script", script="LockHold.java", args=["coop", "12"], program=progX, wait=60000)); holder.start()
    time.sleep(1.0)
    waiters = []
    def waiter(c):
        waiters.append(timed(c.call, "functions", program=progX, limit=1, wait=20000)[:2])
    wt = [threading.Thread(target=waiter, args=(c,)) for c in W[:24]]
    [t.start() for t in wt]; time.sleep(1.5)
    st = V.call("status")
    out["a_quick_lane_during"] = {kk: st["scheduler"]["quick"][kk] for kk in ("slots", "inUse", "queued")}
    rows = []
    for _ in range(3):
        r = timed(V.call, "functions", program=progY, limit=1, wait=1500)
        rows.append({"t": round(time.perf_counter() - t0, 1), "ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"], "msg": None if r[0] else r[2]["message"][:160]})
        r2 = timed(V.call, "comment", program=progY, address=ADDR(0), type="eol", text="y", wait=800)
        rows.append({"t": round(time.perf_counter() - t0, 1), "op": "comment(Y)", "ok": r2[0], "ms": r2[1], "code": None if r2[0] else r2[2]["code"]})
        time.sleep(1.0)
    out["a_victim_probes"] = rows
    holder.join(); [t.join() for t in wt]
    out["a_waiters"] = {"n": len(waiters), "ok": sum(1 for w in waiters if w[0]), "ms_min": min(w[1] for w in waiters), "ms_max": max(w[1] for w in waiters)}
    # (b) long lane saturation with 6 scripts (no program)
    holders = []
    ths = []
    for i in range(6):
        def run(i=i):
            holders.append(timed(W[24 + (i % 2)].labelled(client="h%d" % i).call, "script", script="LockHold.java", args=["coop", "14"], program=None, wait=60000)[:2])
        ths.append(threading.Thread(target=run))
    # W[24], W[25] are only 2 connections: labelled() views are parallel by default
    [t.start() for t in ths]; time.sleep(1.5)
    st = V.call("status"); out["b_long_lane_during"] = {kk: st["scheduler"]["long"][kk] for kk in ("slots", "inUse", "queued")}
    tb = time.perf_counter(); rows = []
    for cmd, kw in (("functions", dict(program=progY, limit=1)), ("save", dict(program=progY, wait=1500)), ("comment", dict(program=progY, address=ADDR(0), type="eol", text="z")),
                    ("analyze", dict(program=progY, wait=1500)), ("refresh", dict(project=Y, wait=1500)), ("fork_project", dict(project=Y, path=str(ROOT / "proj" / "s5fork"), wait=1500)),
                    ("script", dict(script="LockHold.java", args=["coop", "0.1"], program=progY, wait=1500)), ("status", {})):
        kw = dict(kw); kw.setdefault("wait", 1500) if cmd not in ("status",) else None
        r = timed(V.call, cmd, **kw)
        rows.append({"cmd": cmd, "ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"], "msg": None if r[0] else r[2]["message"][:130]})
    out["b_victim_cmds_while_long_lane_full"] = rows
    [t.join() for t in ths]; out["b_holders"] = holders
finally:
    d.stop(force=True)
    save("s5_lanes", out)
