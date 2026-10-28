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
"""S2: writer vs steady readers on ONE program. W owns the program writable; R1..R8 loop decompiles. Variants:
 a) baseline readers only; b) W issues 40 'comment' edits (each an exclusive hold) while readers run;
 c) a 6 s contained read (script coop) is in flight: W's single comment + readers behind it; d) save() with unsaved edits."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
import statistics
SCRIPT_HOLD = "LockHold.java"
def pct(l, q):
    l = sorted(l); return round(l[min(len(l) - 1, int(len(l) * q))], 1) if l else None
def summarize(rows):
    ok = [r[1] for r in rows if r[0]]; bad = [r for r in rows if not r[0]]
    return {"n": len(rows), "ok": len(ok), "busy": len(bad), "p50": pct(ok, .5), "p95": pct(ok, .95), "p99": pct(ok, .99), "max": max(ok) if ok else None,
            "err_codes": sorted({r[2]["code"] for r in bad})}
d = fresh("s2")
out = {}
try:
    gpr = copy_project(base_project(), "s2")
    W = d.connect("s2-writer", "probe")
    R = [d.connect("s2-r%d" % i, "probe") for i in range(8)]
    o = W.call("open_project", path=str(gpr), writable=True); pid = o["id"]
    for r in R: r.call("open_project", path=str(gpr))
    prog = prog_key(pid)
    W.call("open_program", path=PROG, project=pid, writable=True)
    for r in R: r.call("open_program", path=PROG, project=pid)
    fl = W.call("functions", program=prog, limit=3000)["functions"]
    cand = [f for f in fl if not f["thunk"] and not f["external"] and 60 <= f["size"] <= 600]
    addrs = [f["address"] for f in cand[:300]]
    # warm pool
    par([(lambda r=r, a=addrs[i]: r.call("decompile", program=prog, address=a)) for i, r in enumerate(R)])
    def reader_loop(r, stop, rows, i, wait=10000):
        j = 0
        while not stop.is_set():
            a = addrs[(i * 37 + j) % len(addrs)]; j += 1
            rows.append(timed(r.call, "decompile", program=prog, address=a, wait=wait) + ())
    def phase(name, seconds, writer_fn=None, wait=10000):
        stop = threading.Event(); rows = [[] for _ in R]
        ts = [threading.Thread(target=reader_loop, args=(R[i], stop, rows[i], i, wait)) for i in range(8)]
        [t.start() for t in ts]; time.sleep(0.5)
        t0 = time.perf_counter(); wres = writer_fn() if writer_fn else None
        rem = seconds - (time.perf_counter() - t0)
        if rem > 0: time.sleep(rem)
        stop.set(); [t.join() for t in ts]
        allrows = [x for r in rows for x in r]
        out[name] = {"readers": summarize(allrows), "reader_calls_per_s": round(len(allrows) / max(seconds, 0.001), 1), "writer": wres}
        print(name, json.dumps(out[name])[:600], flush=True)
    phase("a_readers_only", 8)
    def write40():
        rows = []
        for k in range(40):
            rows.append(timed(W.call, "comment", program=prog, address=addrs[k], type="eol", text="lockmap s2 %d" % k, wait=10000))
            time.sleep(0.2)
        return summarize(rows)
    phase("b_writer_40_comments_8_readers", 11, write40)
    def write_behind_longread():
        # a contained read of 6 s via another client (R0 is busy; use a 9th connection)
        X = d.connect("s2-x", "probe"); X.call("open_project", path=str(gpr)); X.call("open_program", path=PROG, project=pid)
        th = threading.Thread(target=lambda: X.call("script", script=SCRIPT_HOLD, args=["coop", "6"], program=prog, wait=30000)); th.start()
        time.sleep(1.0)
        r = timed(W.call, "comment", program=prog, address=addrs[100], type="eol", text="behind long read", wait=30000)
        th.join(); return {"comment": r[:2] + (str(r[2])[:80],)}
    phase("c_writer_behind_6s_read_8_readers_wait10s", 9, write_behind_longread, wait=10000)
    def save_phase():
        r = timed(W.call, "save", program=prog, wait=30000); return {"save": r[:2] + (str(r[2])[:100],)}
    phase("d_save_with_unsaved_8_readers", 4, save_phase)
    out["status"] = {k: {kk: v[kk] for kk in ("slots", "inUse", "everQueued")} for k, v in W.call("status")["scheduler"].items()}
finally:
    try: d.stop(force=True)
    except Exception as e: print("stop", e)
    save("s2_writer", out)
