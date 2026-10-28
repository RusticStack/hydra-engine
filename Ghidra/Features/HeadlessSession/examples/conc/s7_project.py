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
"""S7: PROJECT-level exclusive acquirers (refresh, open_project writable on a read-only view) vs everyone in that project.
(a) refresh queued behind a long contained script -> new commands in the whole project refused (fair project lock).
(b) blackout while refresh runs (8 readers on 2 programs). (c) HOL on ONE connection. (d) fork of a read-only view while readers run."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
import statistics
out = {}
def pct(l, q):
    l = sorted(l); return round(l[min(len(l) - 1, int(len(l) * q))], 1) if l else None
d = fresh("s7")
try:
    gpr = copy_project(ROOT / "proj" / ("s6" + TAG), "s7")
    cl = {n: d.connect("s7-" + n, "probe") for n in ["Q", "V", "S"] + ["r%d" % i for i in range(8)]}
    for c in cl.values():
        o = c.call("open_project", path=str(gpr)); pid = o["id"]      # read-only view
    out["project_writable"] = o["writable"]
    K, N = prog_key(pid), prog_key(pid, IMPORT_PROG)
    for c in cl.values():
        c.call("open_program", path=PROG, project=pid); c.call("open_program", path=IMPORT_PROG, project=pid)
    # (a)
    t0 = time.perf_counter(); ev = []
    ts = threading.Thread(target=lambda: cl["S"].call("script", script="LockHold.java", args=["coop", "14"], program=K, wait=60000)); ts.start()
    time.sleep(1.5)
    q = {}
    tq = threading.Thread(target=lambda: q.setdefault("r", timed(cl["Q"].call, "refresh", project=pid, force=True, wait=10000)[:2] + ("",)))
    tq.start(); time.sleep(0.7)
    rows = []
    for _ in range(7):
        for nm, fn in (("V functions the base program (same prog as the reader)", lambda: cl["V"].call("functions", program=K, limit=1, wait=800)),
                       ("V functions notepad (OTHER program, same project)", lambda: cl["V"].call("functions", program=N, limit=1, wait=800)),
                       ("V list project", lambda: cl["V"].call("list", project=pid, programsOnly=True, wait=800))):
            r = timed(fn); rows.append({"t": round(time.perf_counter() - t0, 1), "op": nm, "ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"]})
        time.sleep(0.8)
    tq.join(); ts.join()
    out["a_refresh_queued_behind_script"] = {"refresh_result": q.get("r"), "probes": rows}
    # (b) blackout during refresh
    stop = threading.Event(); lat = []
    fl = cl["V"].call("functions", program=K, limit=500)["functions"]; addr = [f for f in fl if not f["thunk"] and not f["external"]][20]["address"]
    def rl(i):
        c = cl["r%d" % i]
        while not stop.is_set():
            r = timed(c.call, "decompile", program=K if i % 2 == 0 else K, address=addr, wait=5000); lat.append((round(time.perf_counter() - T0, 2), r[0], r[1]))
    T0 = time.perf_counter()
    rts = [threading.Thread(target=rl, args=(i,)) for i in range(8)]; [t.start() for t in rts]; time.sleep(2)
    tr = time.perf_counter(); rr = timed(cl["Q"].call, "refresh", project=pid, force=True, wait=30000); tr_end = time.perf_counter()
    time.sleep(2); stop.set(); [t.join() for t in rts]
    during = [x for x in lat if (tr - T0) - 0.05 <= x[0] <= (tr_end - T0) + 1.0]
    out["b_refresh_blackout"] = {"refresh_ms": rr[1], "refresh_ok": rr[0], "refresh_programs": str(rr[2].get("programs") if rr[0] else rr[2])[:400],
                                 "reader_calls_total": len(lat), "reader_max_ms": max(x[2] for x in lat), "reader_p50": pct([x[2] for x in lat], .5),
                                 "reader_errors": sum(1 for x in lat if not x[1]), "stalled_over_200ms": sum(1 for x in lat if x[2] > 200)}
    # (c) HOL on one connection
    X = cl["V"]
    t1 = time.perf_counter(); rid1 = X.send("script", script="LockHold.java", args=["coop", "4"], program=K, wait=30000)
    time.sleep(0.2); t2 = time.perf_counter(); rid2 = X.send("ping" if False else "info", program=K); X.wait(rid2); a2 = ms(t2)
    rid3 = X.send("info", program=K, parallel=True); t3 = time.perf_counter(); X.wait(rid3); a3 = ms(t3)
    X.wait(rid1)
    out["c_hol_one_connection"] = {"info_after_4s_script_serial_ms": a2, "info_parallel_flag_ms": a3}
    # (d) fork of read-only view while readers run
    stop = threading.Event(); lat2 = []
    def rl2(i):
        c = cl["r%d" % i]
        while not stop.is_set():
            r = timed(c.call, "decompile", program=K, address=addr, wait=5000); lat2.append((r[0], r[1]))
    rts = [threading.Thread(target=rl2, args=(i,)) for i in range(4)]; [t.start() for t in rts]; time.sleep(1)
    fr = timed(cl["Q"].call, "fork_project", project=pid, path=str(ROOT / "proj" / "s7-fork"), mode="full", wait=60000)
    time.sleep(1); stop.set(); [t.join() for t in rts]
    out["d_fork_readonly_view"] = {"fork_ms": fr[1], "ok": fr[0], "reader_calls": len(lat2), "reader_errors": sum(1 for x in lat2 if not x[0]), "reader_max_ms": max(x[1] for x in lat2), "reader_p50": pct([x[1] for x in lat2], .5), "info": str(fr[2])[:300] if not fr[0] else {k: fr[2].get(k) for k in ("cost", "mode", "cloned", "bytes")}}
finally:
    d.stop(force=True)
    save("s7_project", out)
