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
"""S9: (a) does a CONTAINED script's uncommitted change show to concurrent readers (shared program lock)? (b) 'scan' (DB-read) scaling with N concurrent contained scripts
on ONE program; (c) thread dump while 16 clients run `functions` on one program: where do they wait? (d) open a NEW overlay while the base is held exclusively."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
import subprocess, re, collections
JCMD = (JAVA_HOME or "") + "/bin/jcmd.exe"
out = {}
d = fresh("s9")
try:
    gpr = copy_project(base_project(), "s9")
    cl = [d.connect("s9-%d" % i, "probe") for i in range(18)]
    for c in cl: o = c.call("open_project", path=str(gpr), writable=(c is cl[0])); pid = o["id"]
    prog = prog_key(pid)
    cl[0].call("open_program", path=PROG, project=pid, writable=True)       # owner
    for c in cl[1:]: c.call("open_program", path=PROG, project=pid)
    pidj = cl[1].call("hello")["pid"]
    # (a) dirty visibility: a NON-owner contained script renames a function and waits 5 s
    th = threading.Thread(target=lambda: out.__setitem__("a_script_result", str(cl[1].call("script", script="LockHold.java", args=["dirty", "5"], program=prog, wait=30000))[:200])); th.start()
    seen = []
    t0 = time.perf_counter()
    while th.is_alive():
        r = timed(cl[2].call, "functions", program=prog, contains="ZZ_DIRTY", limit=5, wait=2000)
        seen.append({"t": round(time.perf_counter() - t0, 1), "ok": r[0], "hits": [f["name"] for f in r[2]["functions"]] if r[0] else r[2]["code"]})
        time.sleep(0.5)
    th.join()
    after = cl[2].call("functions", program=prog, contains="ZZ_DIRTY", limit=5)
    out["a_dirty_visibility"] = {"during": seen[:14], "after_script_end": [f["name"] for f in after["functions"]], "changed_flag": cl[2].call("info", program=prog)["changed"]}
    # (b) scan scaling
    def scan(c, passes=8):
        t = time.perf_counter(); c.call("script", script="LockHold.java", args=["scan", str(passes)], program=prog, wait=120000); return ms(t)
    base = scan(cl[1]); out["b_scan_1"] = base
    for n in (2, 4, 6):
        t = time.perf_counter(); r = par([(lambda c=c: scan(c)) for c in cl[1:1 + n]]); w = ms(t)
        out["b_scan_%d" % n] = {"wall_ms": w, "each_ms": r, "speedup_vs_serial": round(base * n / w, 2)}
    # (c) thread dump during 16 concurrent `functions`
    stop = threading.Event()
    def fn(c):
        while not stop.is_set(): c.call("functions", program=prog, regex=FUNRX, limit=2000)
    ts = [threading.Thread(target=fn, args=(c,)) for c in cl[1:17]]; [t.start() for t in ts]; time.sleep(1.5)
    dumps = []
    for _ in range(3):
        dumps.append(subprocess.run([JCMD, str(pidj), "Thread.print"], capture_output=True, text=True, timeout=60).stdout if JAVA_HOME else ""); time.sleep(0.4)   # no --java-home: no jcmd, the dump part reports nothing
    stop.set(); [t.join() for t in ts]
    (ROOT / ("s9_threaddump" + TAG + ".txt")).write_text("\n=====DUMP=====\n".join(dumps), encoding="utf-8")
    agg = collections.Counter(); blocked_on = collections.Counter()
    for dmp in dumps:
        for blk in dmp.split("\n\n"):
            if '"session-' not in blk.split("\n")[0] or "-p\"" in blk.split("\n")[0]: continue
            st = re.search(r"java.lang.Thread.State: (\S+)", blk)
            top = [l.strip() for l in blk.split("\n") if l.strip().startswith("at ")][:4]
            state = st.group(1) if st else "?"
            agg[state] += 1
            m = re.search(r"waiting to lock <(0x[0-9a-f]+)> \(a ([\w.$]+)\)", blk)
            if m: blocked_on[m.group(2)] += 1
            m2 = re.search(r"locked <(0x[0-9a-f]+)> \(a ([\w.$]+)\)", blk)
    out["c_thread_states_session_threads_3_dumps"] = dict(agg)
    out["c_blocked_waiting_to_lock_class"] = dict(blocked_on)
    # sample of one blocked stack
    for dmp in dumps:
        for blk in dmp.split("\n\n"):
            if "BLOCKED" in blk and '"session-' in blk:
                out["c_sample_blocked_stack"] = [l.strip() for l in blk.split("\n")][:9]; break
        if "c_sample_blocked_stack" in out: break
    # (d) open NEW overlay while base is held exclusively by the owner script
    th = threading.Thread(target=lambda: cl[0].call("script", script="LockHold.java", args=["coop", "6"], program=prog, wait=30000)); th.start(); time.sleep(1.0)
    r = timed(cl[5].call, "open_program", path=PROG, project=pid, overlay="new", wait=1500)
    out["d_open_new_overlay_during_base_exclusive"] = {"ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"]}
    # an already-open overlay keeps working (client 6 opened one before)
    th.join()
finally:
    d.stop(force=True)
    save("s9_script_db", out)
