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
"""(3) One-program scaling: N concurrent decompiles / N concurrent 'functions' reads / mixed, ONE program, N client connections.
Single run per cell. Warm decompiler pool (a first pass creates the native decompilers), then measured pass."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
import statistics
out = {"engine": ENGINE, "cpus": os.cpu_count()}
d = fresh("t3")
try:
    gpr = copy_project(base_project(), "t3")
    clients = [d.connect("t3-%d" % i, "probe") for i in range(24)]
    o = clients[0].call("open_project", path=str(gpr))
    pid = o["id"]
    for c in clients[1:]: c.call("open_project", path=str(gpr))
    for c in clients: c.call("open_program", path=PROG, project=pid)
    prog = prog_key(pid)
    fl = clients[0].call("functions", limit=3000, program=prog)["functions"]
    cand = [f for f in fl if not f["thunk"] and not f["external"] and 60 <= f["size"] <= 600]
    out["candidates"] = len(cand)
    addrs = [f["address"] for f in cand[:600]]
    def dec(c, a):
        return c.call("decompile", program=prog, address=a, timeout=60)
    # warm: serial solo, and make 24 decompilers via a concurrent pass
    par([(lambda c=c, a=addrs[i]: dec(c, a)) for i, c in enumerate(clients)])
    par([(lambda c=c, a=addrs[i+24]: dec(c, a)) for i, c in enumerate(clients)])
    st = clients[0].call("status"); out["scheduler_after_warm"] = {k: {kk: v[kk] for kk in ("slots","inUse","everQueued")} for k, v in st["scheduler"].items()}
    PER = 12
    res = {}
    # serial baseline
    def run_n(n, kind, per=PER, off=100):
        def work(i):
            c = clients[i]; lat = []; okc = 0
            for j in range(per):
                a = addrs[(off + i * per + j) % len(addrs)]
                t = time.perf_counter()
                try:
                    if kind == "decompile": dec(c, a)
                    elif kind == "functions": c.call("functions", program=prog, regex=FUNRX, limit=2000)
                    elif kind == "info": c.call("info", program=prog)
                    okc += 1
                except gs.SessionError as e:
                    lat.append(("ERR", e.code)); continue
                lat.append(ms(t))
            return lat, okc
        t0 = time.perf_counter()
        rs = par([(lambda i=i: work(i)) for i in range(n)])
        wall = ms(t0)
        lats = [x for r in rs for x in r[0] if not isinstance(x, tuple)]
        errs = [x for r in rs for x in r[0] if isinstance(x, tuple)]
        tot = sum(r[1] for r in rs)
        return {"n": n, "calls": tot, "wall_ms": wall, "throughput_per_s": round(tot / (wall / 1000), 2),
                "lat_p50": round(statistics.median(lats), 1) if lats else None, "lat_max": max(lats) if lats else None, "errors": len(errs)}
    for kind in ("decompile", "functions", "info"):
        res[kind] = []
        for n in (1, 2, 4, 8, 16, 24):
            r = run_n(n, kind, per=(PER if kind == "decompile" else 6 if kind == "functions" else 40))
            res[kind].append(r); print(kind, r, flush=True)
    out["scaling"] = res
    # mixed: 8 decompile clients + 8 functions clients simultaneously
    def mixed():
        t0 = time.perf_counter()
        def dwork(i):
            lat = []
            for j in range(PER):
                t = time.perf_counter(); dec(clients[i], addrs[(300 + i * PER + j) % len(addrs)]); lat.append(ms(t))
            return lat
        def fwork(i):
            lat = []
            for j in range(6):
                t = time.perf_counter(); clients[i].call("functions", program=prog, regex=FUNRX, limit=2000); lat.append(ms(t))
            return lat
        rs = par([(lambda i=i: dwork(i)) for i in range(8)] + [(lambda i=i: fwork(i + 8)) for i in range(8)])
        return {"wall_ms": ms(t0), "decompile_lat_p50": round(statistics.median([x for r in rs[:8] for x in r]), 1),
                "functions_lat_p50": round(statistics.median([x for r in rs[8:] for x in r]), 1)}
    out["mixed_8dec_8fn"] = mixed()
    # what each alone looks like at the same parallelism, for comparison
    out["alone_8dec"] = run_n(8, "decompile"); out["alone_8fn"] = run_n(8, "functions", per=6)
finally:
    try: d.stop(force=True)
    except Exception as e: print("stop", e)
    save("t3_scaling", out)
