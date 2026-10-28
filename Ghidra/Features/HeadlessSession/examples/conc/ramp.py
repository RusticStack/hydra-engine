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
"""Measurement A ramp: N writable forks (own client each) on one daemon.
usage: ramp.py <tag> <base_dir> <master_gpr> [heap|-] [phases e.g. 1,4,12] [reps]
Writes out/ramp-<tag>.json (+ sampler csv, gc log)."""
import sys, json, time, threading, shutil, os
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
from concurrent.futures import ThreadPoolExecutor

tag, base, master = sys.argv[1], arg_base(sys.argv[2]), arg_master(sys.argv[3])
heap = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "-" else None
phases = [int(x) for x in (sys.argv[5] if len(sys.argv) > 5 else "1,4,12").split(",")]
REPS = int(sys.argv[6]) if len(sys.argv) > 6 else 3
state = stat_dir(f"ramp-{tag}")
tmpd = stat_dir(f"ramp-{tag}-tmp")
os.makedirs(tmpd, exist_ok=True)
forkroot = f"{base}/forks-{tag}"
gcl = f"{OUT}/ramp-{tag}-gc.log"
VMA = [f"-Xlog:gc*:file={gcl}:time,uptime"]
res = {"tag": tag, "base": base, "heap_arg": heap, "phases": []}

clients = {}


def mk(i):
    clients[i] = connect(state, f"agent-{i:02d}", heap, tmpdir=tmpd, vmargs=VMA)


mk(0)
c0 = clients[0]
hello = c0.call("hello")
pid = hello["pid"]
res["pid"] = pid
res["launch"] = hello.get("launch")
res["maxHeapMb"] = hello["memory"]["maxMb"]
smp = f"{OUT}/ramp-{tag}-samples.csv"
sp = start_sampler(pid, smp, 1000)
time.sleep(3.5)
res["baseline_idle"] = {"status_mem": c0.call("status")["memory"],
                        "tree": tree_summary(read_samples(smp), time.time() - 3, time.time())}


def agent_setup(i):
    if i not in clients:
        mk(i)
    s = clients[i]
    d = f"{forkroot}/agent-{i:02d}"
    r = {"agent": i}
    t = time.time()
    f = s.call("fork_project", project=master, path=d, writable=True, mode="auto")
    r["fork_ms"] = round((time.time() - t) * 1000)
    r["fork_srv_ms"] = f.get("ms")
    r["copyMs"] = f.get("copyMs")
    r["method"] = f.get("method")
    r["cloned"] = f.get("cloned")
    r["clonedBy"] = f.get("clonedBy")
    r["bytes"] = f.get("bytes")
    r["freeSpaceUsedBytes"] = f.get("freeSpaceUsedBytes")
    r["proj"] = f["project"]
    t = time.time()
    o = s.call("open_program", path=PROG, project=f["project"], writable=True, upgrade=True)
    r["open_upgrade_ms"] = round((time.time() - t) * 1000)
    r["functions"] = o.get("functions")
    r["mode"] = o.get("mode")
    t = time.time()
    dd = s.call("decompile", address=ADDR(0x0))
    r["first_decompile_ms"] = round((time.time() - t) * 1000)
    r["first_decompile_ok"] = dd.get("completed")
    r["time_to_first_decompile_ms"] = r["fork_ms"] + r["open_upgrade_ms"] + r["first_decompile_ms"]
    return r


def agent_run(i, funcs, warm):
    s = clients[i]
    lat = []
    srv = []
    fails = 0
    for fobj in warm:
        s.call("decompile", address=fobj["address"])
    t0 = time.time()
    for fobj in funcs:
        a = time.time()
        try:
            rr = s.call_raw("decompile", address=fobj["address"])
            ok = rr.get("ok") and rr["result"].get("completed")
            srv.append(rr.get("ms"))
        except Exception:
            ok = False
        lat.append((time.time() - a) * 1000)
        if not ok:
            fails += 1
    return {"agent": i, "wall_s": time.time() - t0, "lat_ms": lat, "srv_ms": srv, "fails": fails,
            "t0": t0, "t1": time.time()}


active = []
fl = None
warm = None
free0 = free_bytes(base)
for n in phases:
    new = list(range(len(active), n))
    ph = {"n": n, "new_agents": new}
    t_a = time.time()
    with ThreadPoolExecutor(len(new)) as ex:
        setups = list(ex.map(agent_setup, new))
    t_b = time.time()
    ph["setup_wall_ms"] = round((t_b - t_a) * 1000)
    ph["setups"] = setups
    active += new
    if fl is None:
        allf = c0.call("functions", limit=10000)["functions"]
        c = [f for f in allf if not f["thunk"] and not f["external"] and f["size"] >= 32]
        c.sort(key=lambda f: int(f["address"], 16))
        step = len(c) / 210
        sel = [c[int(i * step)] for i in range(210)]
        warm, fl = sel[:10], sel[10:]
        sizes = sorted(f["size"] for f in fl)
        res["funcs"] = {"all": len(allf), "candidates": len(c), "measured": len(fl), "warm": len(warm),
                        "size_min_med_max": [sizes[0], sizes[len(sizes) // 2], sizes[-1]]}
        json.dump({"warm": warm, "funcs": fl}, open(f"{OUT}/funcs200.json", "w"))
    time.sleep(2)
    ph["status_mem_pre_gc"] = c0.call("status")["memory"]
    ph["status_mem_after_gc"] = live_heap(c0, pid)
    ph["tmpdir_mb"] = round(dir_bytes(tmpd) / 1048576, 1)
    ph["fork_dirs_mb"] = round(dir_bytes(forkroot) / 1048576, 1)
    ph["free_bytes_delta_mb"] = round((free0 - free_bytes(base)) / 1048576, 1)
    time.sleep(2)
    ph["tree_idle"] = tree_summary(read_samples(smp), time.time() - 3, time.time())
    ph["throughput"] = []
    for rep in range(REPS):
        with ThreadPoolExecutor(n) as ex:
            rr = list(ex.map(lambda i: agent_run(i, fl, warm[:3]), active))
        allat = [x for r in rr for x in r["lat_ms"]]
        t0 = min(r["t0"] for r in rr)
        t1 = max(r["t1"] for r in rr)
        ph["throughput"].append({
            "rep": rep + 1, "wall_s": round(t1 - t0, 2), "funcs": len(allat),
            "agg_funcs_per_s": round(len(allat) / (t1 - t0), 2),
            "p50_ms": round(pct(allat, .5), 1), "p95_ms": round(pct(allat, .95), 1),
            "p99_ms": round(pct(allat, .99), 1), "mean_ms": round(statistics.mean(allat), 1),
            "fails": sum(r["fails"] for r in rr),
            "per_agent_wall_s": [round(r["wall_s"], 2) for r in rr],
            "tree": tree_summary(read_samples(smp), t0, t1),
        })
        ph["status_mem_after_rep"] = c0.call("status")["memory"]
    ph["status_mem_end"] = c0.call("status")["memory"]
    res["phases"].append(ph)
    json.dump(res, open(f"{OUT}/ramp-{tag}.json", "w"), indent=1, default=str)
    print("phase", n, "agg f/s per rep", [x["agg_funcs_per_s"] for x in ph["throughput"]],
          "live heap", ph["status_mem_after_gc"], flush=True)

for i in list(active):
    try:
        clients[i].call("close_program", discard=True)
    except Exception:
        pass
time.sleep(2)
res["after_close_programs"] = {"status_mem_after_gc": live_heap(c0, pid),
                               "tree": tree_summary(read_samples(smp), time.time() - 3, time.time())}
res["gc_log"] = gcl
json.dump(res, open(f"{OUT}/ramp-{tag}.json", "w"), indent=1, default=str)
for i in list(clients):
    try:
        clients[i].close()
    except Exception:
        pass
sp.terminate()
print("done")
