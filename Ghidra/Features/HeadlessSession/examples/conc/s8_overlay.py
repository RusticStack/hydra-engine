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
"""S8: two clients, one project: ownership/overlay behaviour + second daemon (OS project lock). Overlay = private program instance: does an exclusive
holder on the base program block it? (a) semantics, (b) overlay vs base exclusive script, (c) overlay open cost, (d) second daemon on same .gpr."""
"""S8: two clients, one project: ownership/overlay behaviour + second daemon (OS project lock). Overlay = private program instance: does an exclusive
holder on the base program block it? (a) semantics, (b) overlay vs base exclusive script, (c) overlay open cost, (d) second daemon on same .gpr."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
def pct(l, q):
    l = sorted(l); return round(l[min(len(l) - 1, int(len(l) * q))], 1) if l else None
out = {}
d = fresh("s8"); d2 = fresh("s8b")
try:
    gpr = copy_project(base_project(), "s8")
    A, B, C = (d.connect("s8-" + n, "probe") for n in "ABC")
    o = A.call("open_project", path=str(gpr), writable=True); pid = o["id"]
    for c in (B, C): c.call("open_project", path=str(gpr), writable=True)
    prog = prog_key(pid)
    A.call("open_program", path=PROG, project=pid, writable=True)
    C.call("open_program", path=PROG, project=pid)
    sem = {}
    for nm, kw in (("B open writable (owner mode, A owns)", dict(writable=True)), ("B open writable share (A owns, owner mode)", dict(writable=True, share=True))):
        r = timed(B.call, "open_program", path=PROG, project=pid, **kw)
        sem[nm] = {"ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"], "msg": None if r[0] else r[2]["message"][:160]}
    t = time.perf_counter(); ro = B.call("open_program", path=PROG, project=pid, overlay="b-notes"); sem["B open overlay"] = {"ms": ms(t), "openMs": ro["overlay"]["openMs"], "mode": ro["mode"]}
    fl = A.call("functions", program=prog, limit=500)["functions"]
    f0 = [f for f in fl if not f["thunk"] and not f["external"]][5]; addr = f0["address"]
    r = B.call("comment", program=prog, overlay="b-notes", address=addr, type="eol", text="B PRIVATE")
    sem["B comment in overlay"] = "ok seq-less (overlay)"
    # who sees it? journal of base should be empty; A's functions unaffected
    sem["A journal seq"] = A.call("journal", program=prog)["seq"]
    out["a_semantics"] = sem
    # (b) overlay while A runs an exclusive (owner) script on the base
    th = threading.Thread(target=lambda: A.call("script", script="LockHold.java", args=["coop", "8"], program=prog, wait=60000)); th.start(); time.sleep(1.0)
    rows = []
    t0 = time.perf_counter()
    for _ in range(5):
        r1 = timed(B.call, "decompile", program=prog, overlay="b-notes", address=addr, wait=1000)
        r2 = timed(B.call, "comment", program=prog, overlay="b-notes", address=addr, type="pre", text="more", wait=1000)
        r3 = timed(C.call, "decompile", program=prog, address=addr, wait=1000)
        rows.append({"t": round(time.perf_counter() - t0, 1), "B overlay decompile": (r1[0], r1[1]), "B overlay comment": (r2[0], r2[1]), "C base decompile": (r3[0], r3[1], None if r3[0] else r3[2]["code"])})
        time.sleep(1.0)
    # opening a NEW overlay during the base blackout
    r4 = timed(C.call, "open_program", path=PROG, project=pid, overlay="c-new", wait=1000)
    rows.append({"C open NEW overlay during base exclusive": (r4[0], r4[1], None if r4[0] else r4[2]["code"])})
    th.join(); out["b_overlay_vs_base_exclusive"] = rows
    # (c) overlay costs: open time for N overlays, 4 clients at once
    cs = [d.connect("s8-o%d" % i, "probe") for i in range(4)]
    for c in cs: c.call("open_project", path=str(gpr), writable=True); c.call("open_program", path=PROG, project=pid)
    res = par([(lambda c=c: timed(c.call, "open_program", path=PROG, project=pid, overlay="o")[:2]) for c in cs])
    out["c_four_overlays_open_ms"] = res
    # overlay decompile throughput: 4 overlays, each own program instance, concurrent
    def loop(c, n=30):
        t = time.perf_counter()
        for j in range(n): c.call("decompile", program=prog, overlay="o", address=fl[20 + j]["address"])
        return ms(t)
    c.call("decompile", program=prog, overlay="o", address=addr)
    out["c_overlay_decompile_30_each_x4_ms"] = par([(lambda c=c: loop(c)) for c in cs])
    out["c_overlay_decompile_30_each_x1_ms"] = loop(cs[0])
    # promote the notes into a fork? (not timed here)
    # (d) second daemon on the same project
    d2c = d2.connect("s8-d2", "probe")
    r = timed(d2c.call, "open_project", path=str(gpr), writable=True)
    out["d_second_daemon_open_writable"] = {"ok": r[0], "ms": r[1], "result": str(r[2])[:500]}
    r = timed(d2c.call, "open_project", path=str(gpr))
    out["d_second_daemon_open_readonly"] = {"ok": r[0], "ms": r[1], "result": str(r[2])[:300]}
    if r[0]:
        rp = timed(d2c.call, "open_program", path=PROG, project=r[2]["id"])
        out["d_second_daemon_readonly_program"] = {"ok": rp[0], "ms": rp[1], "result": str(rp[2])[:300]}
finally:
    d.stop(force=True); d2.stop(force=True)
    save("s8_overlay", out)
