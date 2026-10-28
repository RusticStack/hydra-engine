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
import sys as _sys, pathlib as _pl
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from xc import *
d = fresh("mkbase")
try:
    c = d.connect("mk","t")
    gpr = copy_project(KOTOR_SRC, "base", tagged=False)   # the one prepared base of this work folder
    o = c.call("open_project", path=str(gpr), writable=True)
    t=time.perf_counter(); p = c.call("open_program", path=PROG, project=o["id"], writable=True, upgrade=True); print("open w", ms(t), p["mode"], p["functions"])
    t=time.perf_counter(); print(c.call("save")); print("save", ms(t))
    c.call("close_project", project=o["id"])
finally:
    try: d.stop(force=True)
    except Exception as e: print("stop", e)
