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
"""Fork cost: time + disk for 1, 4, 12 forks, sequential and concurrent, then edit+save cost.
usage: forkcost.py <tag> <base_dir> <master_gpr> <forkmode auto|full|copy-on-write>
Fresh daemon, stopped by the caller. Output out/forkcost-<tag>.json"""
import sys, json, time, os, threading
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
from concurrent.futures import ThreadPoolExecutor

tag, base, master, fmode = sys.argv[1:5]
base, master = arg_base(base), arg_master(master)
name = f"forkcost-{tag}"
state = stat_dir(f"{name}")
tmpd = stat_dir(f"{name}-tmp")
os.makedirs(tmpd, exist_ok=True)
root = f"{base}/{name}"
res = {"tag": tag, "base": base, "forkmode": fmode, "seq": [], "conc": []}
clients = {}


def cl(i):
    if i not in clients:
        clients[i] = connect(state, f"fc-{i:02d}", None, tmpdir=tmpd)
    return clients[i]


c = cl(0)
pid = c.call("hello")["pid"]
res["pid"] = pid
# warm the JVM / class loading with a read-only look at the master list (no program open)
c.call("open_project", path=master)
c.call("close_project")


def one_fork(i, d, upgrade_open=True, writable=True):
    s = cl(i)
    r = {"agent": i}
    t = time.time()
    try:
        f = s.call("fork_project", project=master, path=d, writable=True, mode=fmode)
    except Exception as e:
        r["fork_error"] = str(e)[:300]
        return r
    r["fork_ms"] = round((time.time() - t) * 1000)
    r["copyMs"] = f.get("copyMs")
    r["method"] = f.get("method")
    r["cloned"] = f.get("cloned")
    r["clonedBy"] = f.get("clonedBy")
    r["freeSpaceUsedBytes"] = f.get("freeSpaceUsedBytes")
    r["bytes"] = f.get("bytes")
    r["proj"] = f["project"]
    t = time.time()
    s.call("open_program", path=PROG, project=f["project"], writable=True, upgrade=True)
    r["open_ms"] = round((time.time() - t) * 1000)
    t = time.time()
    s.call("decompile", address=ADDR(0x0))
    r["first_decompile_ms"] = round((time.time() - t) * 1000)
    r["total_ms"] = r["fork_ms"] + r["open_ms"] + r["first_decompile_ms"]
    return r


def measure_disk(label, free_before, dirs):
    time.sleep(1)
    return {"label": label, "dir_bytes_mb": round(sum(dir_bytes(d) for d in dirs) / 1048576, 1),
            "free_delta_mb": round((free_before - free_bytes(base)) / 1048576, 1)}


# warm solo fork first, not counted (JIT / class loading warm-up), discarded
w = one_fork(0, f"{root}/warmup")
res["warmup_fork_first_ever"] = w
cl(0).call("close_program", discard=True)
cl(0).call("close_project")

# sequential: N forks one after another by one client; timings per fork
for n in (1, 4, 12):
    f0 = free_bytes(base)
    dirs = []
    rows = []
    t0 = time.time()
    for k in range(n):
        d = f"{root}/seq{n}-{k:02d}"
        dirs.append(d)
        rows.append(one_fork(100 + n * 0 + k if False else 0, d))
        # same client forks again: it keeps the earlier forks open (that is what a busy agent would do)
    res["seq"].append({"n": n, "wall_ms": round((time.time() - t0) * 1000), "forks": rows,
                       "disk": measure_disk(f"seq{n}", f0, dirs)})
    print("seq", n, res["seq"][-1]["wall_ms"], res["seq"][-1]["disk"], flush=True)

# concurrent: N clients fork at the same moment
for n in (1, 4, 12):
    f0 = free_bytes(base)
    dirs = [f"{root}/conc{n}-{k:02d}" for k in range(n)]
    for k in range(n):
        cl(10 + k)
    t0 = time.time()
    with ThreadPoolExecutor(n) as ex:
        rows = list(ex.map(lambda k: one_fork(10 + k, dirs[k]), range(n)))
    res["conc"].append({"n": n, "wall_ms": round((time.time() - t0) * 1000), "forks": rows,
                        "disk": measure_disk(f"conc{n}", f0, dirs)})
    print("conc", n, res["conc"][-1]["wall_ms"], res["conc"][-1]["disk"], flush=True)

# edit + save cost on the 12 concurrent forks, one at a time then all at once
fl = cl(10).call("functions", limit=50)["functions"]


def edit_save(k, label):
    s = cl(10 + k)
    a = fl[k]["address"]
    t = time.time()
    s.call("rename", address=a, name=f"agent_{k}_{label}")
    t_r = time.time()
    sv = s.call("save", comment="measA")
    t_s = time.time()
    return {"agent": k, "rename_ms": round((t_r - t) * 1000), "save_ms": round((t_s - t_r) * 1000),
            "save_srv": {kk: sv.get(kk) for kk in ("revision", "projectRevision", "savedSeq")}}


solo = edit_save(0, "solo")
res["save_solo"] = solo
dsz0 = dir_bytes(f"{root}/conc12-00")
res["save_solo"]["fork_dir_mb_after"] = round(dsz0 / 1048576, 1)
t0 = time.time()
with ThreadPoolExecutor(12) as ex:
    rows = list(ex.map(lambda k: edit_save(k, "all"), range(12)))
res["save_12_concurrent"] = {"wall_ms": round((time.time() - t0) * 1000), "rows": rows}
st = cl(0).call("status")
res["scheduler"] = st.get("scheduler")
print("save solo", solo, "12 conc wall", res["save_12_concurrent"]["wall_ms"],
      sorted(r["save_ms"] for r in rows), flush=True)
json.dump(res, open(f"{OUT}/{name}.json", "w"), indent=1, default=str)
for s in clients.values():
    try:
        s.close()
    except Exception:
        pass
print("done")
