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
"""Do long requests of some clients delay other clients? (scheduler lanes: long = analyze/import/script/save/fork)
usage: lanetest.py <tag> <maxLong, 0 = default> """
import sys, os, json, time, threading
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
from concurrent.futures import ThreadPoolExecutor

tag, maxlong = sys.argv[1], int(sys.argv[2])
name = f"lane-{tag}"
state = stat_dir(f"{name}")
tmpd = stat_dir(f"{name}-tmp")
os.makedirs(tmpd, exist_ok=True)
master = master_gpr()
base = work_base()
cfg = {"tmpdir": tmpd, "scriptPath": [str(SCRIPTS)]}
if maxlong:
    cfg["maxLong"] = maxlong
clients = {}


def cl(i):
    if i not in clients:
        clients[i] = connect(state, f"lane-{i:02d}", None, **cfg)
    return clients[i]


res = {"tag": tag, "maxLong_cfg": maxlong, "steps": []}


def step(n, **kw):
    kw["step"] = n
    res["steps"].append(kw)
    print(kw, flush=True)
    json.dump(res, open(f"{OUT}/{name}.json", "w"), indent=1, default=str)


def timed(fn, *a, **k):
    t = time.time()
    try:
        r = fn(*a, **k)
        return round((time.time() - t) * 1000), "ok", r
    except Exception as e:
        return round((time.time() - t) * 1000), repr(e)[:160], None


c0 = cl(0)
hello = c0.call("hello")
res["scheduler_slots"] = c0.call("status")["scheduler"]
step("slots", quick=res["scheduler_slots"]["quick"]["slots"], long=res["scheduler_slots"]["long"]["slots"])
PROBE = 12
p = cl(PROBE)
f = p.call("fork_project", project=master, path=f"{base}/forks-{name}/probe", writable=True)
p.call("open_program", path=PROG, project=f["project"], writable=True, upgrade=True)
p.call("decompile", address=ADDR(0x0))
# baseline latencies for the probe client (no load)
ms, st, _ = timed(p.call, "decompile", address=ADDR(0x10))
b_dec = ms
ms, st, _ = timed(p.call, "script", script="MeasSleep.java", program=None, args=["10"], wait=120000)
b_scr = ms
ms, st, _ = timed(p.call, "rename", address=ADDR(0x60), name="lane_probe_0")
ms2, st, _ = timed(p.call, "save", comment="lane baseline", wait=120000)
b_sav = ms2
ms3, st, fk = timed(p.call, "fork_project", project=master, path=f"{base}/forks-{name}/probe-b0", writable=True, wait=120000)
b_frk = ms3
step("baseline_ms", decompile=b_dec, tiny_script=b_scr, save=b_sav, fork=b_frk, script_status=st)

# wave test: 12 clients each run a 4 s sleeping script at once
for i in range(12):
    cl(i)
t0 = time.time()


def sleeper(i, ms_):
    a = time.time()
    clients[i].call("script", script="MeasSleep.java", program=None, args=[str(ms_)], wait=300000)
    return round(time.time() - a, 2)


with ThreadPoolExecutor(12) as ex:
    done = list(ex.map(lambda i: sleeper(i, 4000), range(12)))
step("wave_12_sleepers_4s", wall_s=round(time.time() - t0, 2), per_client_s=sorted(done))

# long holders vs the probe: 6 clients (0..5) run 12 s scripts; the probe asks for quick and long things meanwhile
holders = 6
t0 = time.time()
ex = ThreadPoolExecutor(holders)
futs = [ex.submit(sleeper, i, 12000) for i in range(holders)]
time.sleep(2.0)
res_probe = {}
probe_ops = {
    "decompile_ms": lambda: p.call("decompile", address=ADDR(0x20)),
    "functions_ms": lambda: p.call("functions", limit=5),
    "rename_ms": lambda: p.call("rename", address=ADDR(0x80), name="lane_probe_1"),
    "open_project_ms": lambda: p.call("open_project", path=master),
    "tiny_script_ms": lambda: p.call("script", script="MeasSleep.java", program=None, args=["10"], wait=300000),
    "save_ms": lambda: p.call("save", comment="lane loaded", wait=300000),
    "fork_ms": lambda: p.call("fork_project", project=master, path=f"{base}/forks-{name}/probe-b1", writable=True, wait=300000),
}
with ThreadPoolExecutor(len(probe_ops)) as pex:
    pf = {k: pex.submit(timed, fn) for k, fn in probe_ops.items()}
    for k, f_ in pf.items():
        ms, st, _ = f_.result()
        res_probe[k] = ms
        if st != "ok":
            res_probe[k + "_status"] = st
sch = c0.call("status")["scheduler"]
res_probe["lanes_snapshot_long"] = {k: sch["long"][k] for k in ("slots", "inUse", "queued", "everQueued")}
for f_ in futs:
    f_.result()
step("probe_while_6_holders_12s", since_start_s=round(time.time() - t0, 1), **res_probe)
sch = c0.call("status")["scheduler"]
step("final_lanes", long={k: sch["long"][k] for k in ("slots", "admitted", "everQueued")}, quick={k: sch["quick"][k] for k in ("slots", "admitted", "everQueued")})
for s in clients.values():
    try:
        s.close()
    except Exception:
        pass
print("done")
