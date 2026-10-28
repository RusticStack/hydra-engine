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
"""One simulated harness: its own process, its own connection to the daemon.
Commands arrive as JSON lines on stdin, answers leave as JSON lines on stdout.
argv: state tmpdir heap|- agent_index mode(fork|ro) master_gpr forkdir"""
import sys, json, time, os
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *

state, tmpd, heap, idx, mode, master, forkdir = sys.argv[1:8]
idx = int(idx)
heap = None if heap == "-" else heap
gcl = f"{OUT}/gc-{os.path.basename(state)}.log"
s = connect(state, f"agent-{idx:02d}", heap, tmpdir=tmpd, vmargs=[f"-Xlog:gc*:file={gcl}:time,uptime"])
proj = None


def reply(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    cmd = json.loads(line)
    op = cmd["op"]
    try:
        if op == "pid":
            reply({"pid": s.call("hello")["pid"]})
        elif op == "setup":
            r = {"agent": idx, "mode": mode}
            t = time.time()
            if mode == "fork":
                f = s.call("fork_project", project=master, path=forkdir, writable=True, mode=cmd.get("forkmode", "auto"))
                r["fork_ms"] = round((time.time() - t) * 1000)
                r["fork_srv_ms"] = f.get("ms")
                r["copyMs"] = f.get("copyMs")
                r["method"] = f.get("method")
                r["cloned"] = f.get("cloned")
                r["clonedBy"] = f.get("clonedBy")
                r["bytes"] = f.get("bytes")
                r["freeSpaceUsedBytes"] = f.get("freeSpaceUsedBytes")
                proj = f["project"]
                t = time.time()
                o = s.call("open_program", path=PROG, project=proj, writable=True, upgrade=True)
            else:
                p = s.call("open_project", path=master)
                proj = p["id"]
                r["open_project_ms"] = round((time.time() - t) * 1000)
                t = time.time()
                o = s.call("open_program", path=PROG, project=proj, writable=False)
            r["open_program_ms"] = round((time.time() - t) * 1000)
            r["functions"] = o.get("functions")
            r["program_mode"] = o.get("mode")
            r["cachedUpgrade"] = o.get("cachedUpgrade")
            t = time.time()
            dd = s.call("decompile", address=ADDR(0x0))
            r["first_decompile_ms"] = round((time.time() - t) * 1000)
            r["first_decompile_ok"] = dd.get("completed")
            r["time_to_first_decompile_ms"] = (r.get("fork_ms") or r.get("open_project_ms") or 0) + r["open_program_ms"] + r["first_decompile_ms"]
            reply(r)
        elif op == "funclist":
            allf = s.call("functions", limit=10000)["functions"]
            reply({"all": allf})
        elif op == "run":
            funcs = cmd["funcs"]
            for a in cmd.get("warm", []):
                s.call("decompile", address=a)
            while time.time() < cmd["start_at"]:
                time.sleep(0.001)
            lat = []
            srv = []
            fails = 0
            t0 = time.time()
            c0_ = time.process_time()
            for a in funcs:
                a0 = time.time()
                try:
                    rr = s.call_raw("decompile", address=a)
                    ok = rr.get("ok") and rr["result"].get("completed")
                    srv.append(rr.get("ms"))
                except Exception:
                    ok = False
                lat.append((time.time() - a0) * 1000)
                if not ok:
                    fails += 1
            reply({"agent": idx, "t0": t0, "t1": time.time(), "lat_ms": lat, "srv_ms": srv, "fails": fails, "cpu_s": time.process_time() - c0_})
        elif op == "close":
            try:
                s.call("close_program", discard=True)
            except Exception:
                pass
            reply({"closed": True})
        elif op == "quit":
            break
    except Exception as e:
        reply({"error": repr(e), "op": op, "agent": idx})
s.close()
