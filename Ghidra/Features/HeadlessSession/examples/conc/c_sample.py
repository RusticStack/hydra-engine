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
"""Pick the M rename addresses and 50 decompile addresses; verify decompile determinism across two daemon starts."""
import json
import pathlib
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from c_lib import *  # noqa

proj = sys.argv[1]
root = RUN_ROOT / "run" / ("sample-%s" % proj)
if root.exists():
    shutil.rmtree(root)
root.mkdir(parents=True)
b = BASES[proj]
cp = root / "canon"
shutil.copytree(b["base"], cp)
base_hash = tree_hash(b["base"])
rig = Rig(root / "rig", name="sample")
hashes = []
sample = None
for rnd in range(3):
    c, start_ms = rig.start("sample", "c")
    o = c.call("open_project", path=str(cp / b["gpr"]))
    p = c.call("open_program", path=b["prog"], project=o["id"])
    key = p["key"]
    if sample is None:
        madrs, cand = pick_sample(c, key, b["M"], b["S"])
        sample = (madrs, cand)
    dec = {}
    for a in sample[1]:
        d = c.call("decompile", program=key, address=a, timeout=60)
        dec[a] = hashlib.sha256((d.get("c") or "").encode()).hexdigest()[:16] if d.get("completed", True) else "INCOMPLETE"
    hashes.append(dec)
    info = {"functions": p.get("functions"), "analyzed": p.get("analyzed"), "start_ms": start_ms}
    print("round", rnd, info)
    c.close()
    rig.stop()
good = [a for a in sample[1] if all(h[a] == hashes[0][a] and h[a] != "INCOMPLETE" for h in hashes)]
S = good[: b["S"]]
out = {"M_addrs": sample[0], "S_addrs": S, "n_candidates": len(sample[1]), "n_deterministic": len(good)}
# S must be a subset of M so the gen rename changes their decompile text
miss = [a for a in S if a not in sample[0]]
out["S_not_in_M"] = len(miss)
(RUN_ROOT / ("sample-%s.json" % proj)).write_text(json.dumps(out, indent=0))
after = tree_hash(b["base"])
print(json.dumps({"proj": proj, "M": len(sample[0]), "S": len(S), "candidates": len(sample[1]), "deterministic": len(good),
                  "S_not_in_M": len(miss), "base_tree_unchanged": after["tree_sha256"] == base_hash["tree_sha256"],
                  "base_tree": base_hash["tree_sha256"]}))
