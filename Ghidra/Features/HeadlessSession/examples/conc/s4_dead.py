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
"""S3/S4: (a) an OWNER's script (exclusive) vs readers; (b) client killed while waiting for the exclusive lock behind a long read;
(c) owner killed while its non-cooperative (deaf) script runs; cancel of a deaf script."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
def probes(C, D, prog, pid, t0, secs, label, step=1.5, wait=800, extra=None):
    rows = []
    end = time.perf_counter() + secs
    while time.perf_counter() < end:
        for nm, fn in (("C info", lambda: C.call("info", program=prog, wait=wait)),
                       ("D open writable", lambda: D.call("open_program", path=PROG, project=pid, writable=True, wait=wait))):
            r = timed(fn)
            rows.append({"t": round(time.perf_counter() - t0, 1), "op": nm, "ok": r[0], "ms": r[1],
                         "code": None if r[0] else r[2]["code"], "msg": None if r[0] else r[2]["message"][:120]})
        time.sleep(step)
    return rows
def setup(name):
    d = fresh(name)
    gpr = copy_project(base_project(), name)
    cl = {n: d.connect(name + "-" + n, "probe") for n in "ABCD"}
    o = cl["A"].call("open_project", path=str(gpr), writable=True); pid = o["id"]
    for n in "BCD": cl[n].call("open_project", path=str(gpr), writable=True)
    return d, cl, pid, prog_key(pid)
out = {}
# (a) owner script exclusive vs readers
d, cl, pid, prog = setup("s3a")
try:
    A, B, C, D = (cl[n] for n in "ABCD")
    A.call("open_program", path=PROG, project=pid, writable=True)
    C.call("open_program", path=PROG, project=pid)
    t0 = time.perf_counter()
    th = threading.Thread(target=lambda: A.call("script", script="LockHold.java", args=["coop", "8"], program=prog, wait=30000)); th.start()
    time.sleep(0.5)
    rows = []
    for _ in range(6):
        r = timed(C.call, "info", program=prog, wait=1000)
        rows.append({"t": round(time.perf_counter() - t0, 1), "ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"], "holder": None if r[0] else r[2]["details"].get("holder")})
        time.sleep(1.0)
    th.join(); out["a_owner_script_vs_reader"] = rows
finally:
    d.stop(force=True)
# (b) client killed while waiting for the exclusive lock
d, cl, pid, prog = setup("s4b")
try:
    A, B, C, D = (cl[n] for n in "ABCD")
    B.call("open_program", path=PROG, project=pid, writable=True, share=True)
    A.call("open_program", path=PROG, project=pid, writable=True, share=True)
    C.call("open_program", path=PROG, project=pid)
    t0 = time.perf_counter(); ev = []
    ta = threading.Thread(target=lambda: ev.append(("A script ended", round(time.perf_counter() - t0, 1), A.call("script", script="LockHold.java", args=["coop", "16"], program=prog, wait=60000, exclusive=False)["mode"])))
    # A is a shared writer -> script would be exclusive (isWriter). Use C (reader, contained) for the long read instead.
    tc = threading.Thread(target=lambda: ev.append(("C long read ended", round(time.perf_counter() - t0, 1), C.call("script", script="LockHold.java", args=["coop", "16"], program=prog, wait=60000)["mode"])))
    tc.start(); time.sleep(1.5)
    # B sends an edit with a long wait (queues exclusive), then dies
    rid = B.send("comment", program=prog, address=ADDR(0x9630), type="eol", text="DEAD CLIENT WRITE", wait=60000)
    ev.append(("B comment sent", round(time.perf_counter() - t0, 1)))
    time.sleep(1.5); B.close(); ev.append(("B socket closed", round(time.perf_counter() - t0, 1)))
    rows = []
    for _ in range(9):
        r = timed(A.call, "info", program=prog, wait=800)
        rows.append({"t": round(time.perf_counter() - t0, 1), "ok": r[0], "ms": r[1], "code": None if r[0] else r[2]["code"], "readers": None if r[0] else r[2]["details"].get("readers")})
        time.sleep(1.2)
    tc.join()
    time.sleep(1.0)
    after = timed(A.call, "journal", program=prog)
    out["b_dead_waiter"] = {"events": ev, "probes": rows, "journal_after": str(after[2])[:500]}
    st = A.call("status"); out["b_status_clients"] = str(st.get("clients"))[:600]
finally:
    d.stop(force=True)
# (c) owner killed mid deaf script; plus cancel of a deaf script
d, cl, pid, prog = setup("s4c")
try:
    A, B, C, D = (cl[n] for n in "ABCD")
    A.call("open_program", path=PROG, project=pid, writable=True)
    t0 = time.perf_counter(); ev = []
    rid = A.send("script", script="LockHold.java", args=["deaf", "20"], program=prog, wait=60000)
    time.sleep(1.5)
    tcan = time.perf_counter(); A.call("cancel", target=rid); ev.append(("cancel returned", ms(tcan)))
    time.sleep(1.0); A.close(); ev.append(("A closed", round(time.perf_counter() - t0, 1)))
    out["c_owner_deaf_script_killed"] = {"events": ev, "probes": probes(C, D, prog, pid, t0, 24, "c", step=2.0)}
    # slot accounting during/after
    try:
        st = C.call("status"); out["c_sched_end"] = {k: {kk: v[kk] for kk in ("slots", "inUse", "queued")} for k, v in st["scheduler"].items()}
    except Exception as e: out["c_sched_end"] = repr(e)
finally:
    d.stop(force=True)
save("s4_dead", out)
