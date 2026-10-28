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
import sys, os, json, time
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
from concurrent.futures import ThreadPoolExecutor
base = arg_base(sys.argv[1]); master = arg_master(sys.argv[2]); tag = sys.argv[3]
state = stat_dir(f"save-{tag}"); tmpd = stat_dir(f"save-{tag}-tmp")
cl = {}
def c(i):
    if i not in cl: cl[i] = connect(state, f"sv-{i:02d}", None, tmpdir=tmpd)
    return cl[i]
res = {}
def mkfork(i, d):
    s = c(i); f = s.call("fork_project", project=master, path=d, writable=True)
    s.call("open_program", path=PROG, project=f["project"], writable=True, upgrade=True)
    return s
def timed(fn):
    t = time.time(); fn(); return round((time.time() - t) * 1000)
c(0).call("hello")
# warm JVM with one throwaway fork
s = mkfork(0, f"{base}/sv-{tag}/warm"); s.call("decompile", address=ADDR(0x0)); s.call("close_program", discard=True)
# (a) open upgrade -> save, no edit
s = mkfork(1, f"{base}/sv-{tag}/a"); res["a_save_noedit_ms"] = timed(lambda: s.call("save", comment="x", wait=600000))
# (b) open upgrade -> rename -> save
s = mkfork(2, f"{base}/sv-{tag}/b"); s.call("rename", address=ADDR(0x60), name="svb"); res["b_save_rename_ms"] = timed(lambda: s.call("save", comment="x", wait=600000))
# (c) as Hydralysis does: info (changed?) then save with refresh
s = mkfork(3, f"{base}/sv-{tag}/c"); inf = s.call("info"); res["c_changed_before_save"] = inf.get("changed"); res["c_save_ms"] = timed(lambda: s.call("save", comment="x", wait=600000))
# (d) 4 concurrent: open upgrade then save, no edit
ss = [mkfork(10 + k, f"{base}/sv-{tag}/d{k}") for k in range(4)]
t = time.time()
with ThreadPoolExecutor(4) as ex:
    r = list(ex.map(lambda x: timed(lambda: x.call("save", comment="x", wait=600000)), ss))
res["d_4conc_save_ms"] = sorted(r); res["d_wall_ms"] = round((time.time() - t) * 1000)
print(res)
json.dump(res, open(f"{OUT}/savetest-{tag}.json", "w"))
for x in cl.values(): x.close()
