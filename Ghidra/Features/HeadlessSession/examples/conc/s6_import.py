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
"""S6: import / analyze / save vs other clients. (a) import+analyze of a small PE by W while R reads (i) the base program (other program) and (ii) the new program;
(b) 6 concurrent imports (maxImports default 4) - queue effect on others; list() latency during import."""
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
import statistics
out = {}
d = fresh("s6")
try:
    gpr = copy_project(base_project(), "s6")
    W = d.connect("s6-W", "probe"); R = d.connect("s6-R", "probe")
    o = W.call("open_project", path=str(gpr), writable=True); pid = o["id"]
    R.call("open_project", path=str(gpr), writable=True)
    R.call("open_program", path=PROG, project=pid)
    W.call("open_program", path=PROG, project=pid)
    fl = R.call("functions", program=prog_key(pid), limit=500)["functions"]
    addr = [f for f in fl if not f["thunk"] and not f["external"]][10]["address"]
    stop = threading.Event(); rows = []
    def reader():
        while not stop.is_set():
            t0 = time.perf_counter(); r = timed(R.call, "decompile", program=prog_key(pid), address=addr, wait=3000)
            rows.append((round(time.perf_counter() - T0, 2), r[0], r[1]))
            lr = timed(R.call, "list", project=pid, programsOnly=True, wait=3000)
            rows.append((round(time.perf_counter() - T0, 2), "list" if lr[0] else "list-ERR", lr[1]))
            time.sleep(0.05)
    T0 = time.perf_counter()
    rt = threading.Thread(target=reader); rt.start(); time.sleep(1.0)
    ev = []
    t = time.perf_counter()
    imp = {}
    def do_import():
        t1 = time.perf_counter()
        try:
            r = W.call("import", file=IMPORT_EXE, analyze=True, timeout=300, wait=300000)
            imp["r"] = {"ok": True, "ms": ms(t1), "importSeconds": r.get("importSeconds"), "analysis_s": (r.get("analysis") or {}).get("seconds"), "path": r.get("path"), "save": str(r.get("save"))[:100]}
        except gs.SessionError as e:
            imp["r"] = {"ok": False, "ms": ms(t1), "err": str(e)[:300]}
    it = threading.Thread(target=do_import); it.start()
    time.sleep(3)
    # read the NEW program while it is imported+analyzing (it is owned by W; analysis is exclusive)
    newrows = []
    for _ in range(40):
        if not it.is_alive(): break
        r = timed(R.call, "open_program", path=IMPORT_PROG, project=pid, wait=1000)
        if r[0]:
            r2 = timed(R.call, "functions", program=prog_key(pid, IMPORT_PROG), limit=1, wait=1000)
            newrows.append({"t": round(time.perf_counter() - T0, 1), "op": "open_program+functions", "open_ok": True, "functions_ok": r2[0], "ms": r2[1], "code": None if r2[0] else r2[2]["code"], "msg": None if r2[0] else r2[2]["message"][:100]})
        else:
            newrows.append({"t": round(time.perf_counter() - T0, 1), "op": "open_program", "open_ok": False, "ms": r[1], "code": r[2]["code"]})
        time.sleep(2.0)
    it.join(); stop.set(); rt.join()
    out["a_import_analyze"] = imp.get("r")
    out["a_new_program_reader_probes"] = newrows[:30]
    dec = [r for r in rows if r[1] is True]; lst = [r for r in rows if r[1] == "list"]; errs = [r for r in rows if r[1] in (False, "list-ERR")]
    out["a_base_reader_during"] = {"decompile_calls": len(dec), "decompile_p50": round(statistics.median([r[2] for r in dec]), 1), "decompile_max": max(r[2] for r in dec),
                                    "list_calls": len(lst), "list_p50": round(statistics.median([r[2] for r in lst]), 1), "list_max": max(r[2] for r in lst), "errors": len(errs)}
    print(json.dumps(out, indent=1, default=str)[:1500], flush=True)
    # (b) 6 concurrent imports
    names = ["whoami", "ipconfig", "find", "hostname", "netstat", "tasklist"]
    clients = [d.connect("s6-i%d" % i, "probe") for i in range(6)]
    for c in clients: c.call("open_project", path=str(gpr), writable=True)
    stop2 = threading.Event(); rows2 = []
    T1 = time.perf_counter()
    def reader2():
        while not stop2.is_set():
            r = timed(R.call, "decompile", program=prog_key(pid), address=addr, wait=3000); rows2.append(("dec", round(time.perf_counter() - T1, 2), r[0], r[1]))
            lr = timed(R.call, "list", project=pid, programsOnly=True, wait=3000); rows2.append(("list", round(time.perf_counter() - T1, 2), lr[0], lr[1]))
            sr = timed(W.call, "save", program=prog_key(pid), wait=3000); rows2.append(("save", round(time.perf_counter() - T1, 2), sr[0], sr[1]))
            time.sleep(0.1)
    rt2 = threading.Thread(target=reader2); rt2.start()
    res = []
    def imp1(i):
        t1 = time.perf_counter()
        try:
            r = clients[i].call("import", file=IMPORT_DIR + "/%s.exe" % names[i], wait=300000)
            return {"name": names[i], "ok": True, "ms": ms(t1), "queue": r.get("queue"), "importSeconds": r.get("importSeconds")}
        except gs.SessionError as e:
            return {"name": names[i], "ok": False, "ms": ms(t1), "err": str(e)[:200]}
    out["b_six_imports"] = par([(lambda i=i: imp1(i)) for i in range(6)])
    stop2.set(); rt2.join()
    for kind in ("dec", "list", "save"):
        rr = [r for r in rows2 if r[0] == kind]
        out["b_other_client_" + kind] = {"calls": len(rr), "errors": sum(1 for r in rr if not r[2]), "p50": round(statistics.median([r[3] for r in rr]), 1), "max": max(r[3] for r in rr)}
    out["b_status_imports"] = str(R.call("status").get("imports"))[:500]
finally:
    d.stop(force=True)
    save("s6_import", out)
