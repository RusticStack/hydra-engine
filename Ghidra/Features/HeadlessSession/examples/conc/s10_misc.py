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
"""S10: (a) deaf script: cancel/timeout do not free the long slot; (b) static SCRIPT_COMPILE lock: 4 first-time script compiles from 4 clients; (c) analyze + save of a small program: reader blackout lengths."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
out = {}
d = fresh("s10")
try:
    gpr = copy_project(ROOT / "proj" / ("s6" + TAG), "s10")
    cl = [d.connect("s10-%d" % i, "probe") for i in range(6)]
    for c in cl: o = c.call("open_project", path=str(gpr), writable=(c is cl[0])); pid = o["id"]
    K = prog_key(pid)
    for c in cl: c.call("open_program", path=PROG, project=pid)
    # (a)
    # times are counted from the script's start (it creates the file when it runs): a slow compile before it
    # (a cold settings dir, a loaded machine) would otherwise put the cancel before the script ran at all
    # the script is compiled first: the timeout counts from the request, and a first compile of 3 s or more
    # would spend it before the script ran
    cl[1].call("script", script="LockHold.java", args=["coop", "0.05"], program=K, wait=60000)
    started = ROOT / "state" / ("s10" + TAG) / "script-running"
    started.unlink(missing_ok=True)
    rid = cl[1].send("script", script="LockHold.java", args=["deaf", "12", str(started)], program=K, timeout=3, wait=60000)
    t0 = wait_file(started)
    time.sleep(0.5)
    st1 = cl[2].call("status")["scheduler"]["long"]
    cl[1].call("cancel", target=rid); time.sleep(0.5)
    st2 = cl[2].call("status")["scheduler"]["long"]
    t_wait = time.perf_counter()
    try:
        cl[1].wait(rid); res = "ok"
    except gs.SessionError as e:
        res = e.code + ": " + e.message[:80]
    out["a_deaf_script"] = {"long_lane_at_1s": {k: st1[k] for k in ("inUse", "running")}, "long_lane_after_cancel_and_timeout_flag": {k: st2[k] for k in ("inUse",)},
                            "response_arrived_after_s": round(time.perf_counter() - t0, 1), "response": res, "timeout_param_s": 3, "script_duration_s": 12}
    # (b) compile lock
    r1 = timed(cl[1].call, "script", script="LockHold1.java", args=["coop", "0.05"], program=None, wait=60000)[:2]
    t = time.perf_counter()
    rs = par([(lambda i=i: timed(cl[i + 1].call, "script", script="LockHold%d.java" % (i + 2), args=["coop", "0.05"], program=None, wait=60000)[:2]) for i in range(3)])
    r2 = par([(lambda i=i: timed(cl[i + 1].call, "script", script="LockHold%d.java" % (i + 2), args=["coop", "0.05"], program=None, wait=60000)[:2]) for i in range(3)])
    out["b_first_compile_solo_ms"] = r1; out["b_3_concurrent_first_compiles"] = {"wall_ms": ms(t), "each": rs}
    # note: 2nd batch (already compiled) after
    # (c) analyze + save on whoami
    W = cl[0]; R = cl[1]
    W.call("open_program", path="/whoami.exe", project=pid, writable=True)
    Wk = prog_key(pid, "/whoami.exe")
    R.call("open_program", path="/whoami.exe", project=pid)
    stop = threading.Event(); rows = []
    T0 = time.perf_counter()
    def rd():
        while not stop.is_set():
            r = timed(R.call, "functions", program=Wk, limit=1, wait=500); rows.append((round(time.perf_counter() - T0, 1), r[0], r[1])); time.sleep(0.2)
    th = threading.Thread(target=rd); th.start(); time.sleep(1)
    ta = time.perf_counter(); an = W.call("analyze", program=Wk, timeout=200, wait=60000); an_ms = ms(ta)
    ts_ = time.perf_counter(); sv = W.call("save", program=Wk, wait=60000); sv_ms = ms(ts_)
    time.sleep(1); stop.set(); th.join()
    ok_during_analysis = [r for r in rows if (ta - T0) < r[0] < (ta - T0) + an_ms / 1000]
    out["c_analyze_save_whoami"] = {"analyze_ms": an_ms, "save_ms": sv_ms, "functions_after": an.get("functions"), "reader_probes_during_analysis": len(ok_during_analysis),
                                    "reader_refused_during_analysis": sum(1 for r in ok_during_analysis if not r[1]), "reader_ok_during_analysis": sum(1 for r in ok_during_analysis if r[1])}
finally:
    d.stop(force=True)
    save("s10_misc", out)
