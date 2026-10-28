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
"""S11: write storm. 8 readers decompile ONE program. (a) readers only; (b) +4 SHARED-mode writers looping `comment` flat out (each an exclusive hold);
(c) +4 clients looping `comment` into their private OVERLAYS (no base program lock). Single run each, 8 s."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
def pct(l, q):
    l = sorted(l); return round(l[min(len(l) - 1, int(len(l) * q))], 1) if l else None
out = {}
d = fresh("s11")
try:
    gpr = copy_project(base_project(), "s11")
    cl = [d.connect("s11-%d" % i, "probe") for i in range(12)]
    for c in cl: o = c.call("open_project", path=str(gpr), writable=(c is cl[0])); pid = o["id"]
    prog = prog_key(pid)
    R, Wr = cl[:8], cl[8:]
    for c in Wr: c.call("open_program", path=PROG, project=pid, writable=True, share=True)
    for c in R: c.call("open_program", path=PROG, project=pid)
    fl = R[0].call("functions", program=prog, limit=3000)["functions"]
    cand = [f for f in fl if not f["thunk"] and not f["external"] and 60 <= f["size"] <= 600]; addrs = [f["address"] for f in cand[:300]]
    par([(lambda r=r, a=addrs[i]: r.call("decompile", program=prog, address=a)) for i, r in enumerate(R)])
    def phase(name, writer_kind):
        stop = threading.Event(); rl = [[] for _ in R]; wl = [[] for _ in Wr]
        def reader(i):
            j = 0
            while not stop.is_set():
                rl[i].append(timed(R[i].call, "decompile", program=prog, address=addrs[(i * 31 + j) % len(addrs)], wait=10000)[:2]); j += 1
        def writer(i):
            j = 0
            while not stop.is_set():
                kw = dict(program=prog, address=addrs[(i * 7 + j) % len(addrs)], type="eol", text="w%d-%d" % (i, j), wait=10000)
                if writer_kind == "overlay": kw["overlay"] = "mine"
                wl[i].append(timed(Wr[i].call, "comment", **kw)[:2]); j += 1
        ts = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
        if writer_kind: ts += [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        [t.start() for t in ts]; time.sleep(8); stop.set(); [t.join() for t in ts]
        rr = [x for r in rl for x in r]; ww = [x for w in wl for x in w]
        out[name] = {"reader_calls_per_s": round(len(rr) / 8, 1), "reader_p50": pct([x[1] for x in rr if x[0]], .5), "reader_p99": pct([x[1] for x in rr if x[0]], .99),
                     "reader_max": max(x[1] for x in rr), "reader_errors": sum(1 for x in rr if not x[0]),
                     "writer_calls_per_s": round(len(ww) / 8, 1) if ww else None, "writer_p50": pct([x[1] for x in ww if x[0]], .5) if ww else None, "writer_max": max(x[1] for x in ww) if ww else None,
                     "writer_errors": sum(1 for x in ww if not x[0]) if ww else None}
        print(name, out[name], flush=True)
    phase("a_readers_only", None)
    phase("b_4_shared_writers_flat_out", "shared")
    for c in Wr:
        c.call("close_program", program=prog, discard=True)    # leave shared mode
    for c in Wr: c.call("open_program", path=PROG, project=pid); c.call("open_program", path=PROG, project=pid, overlay="mine")
    phase("c_4_overlay_writers_flat_out", "overlay")
finally:
    d.stop(force=True)
    save("s11_storm", out)
