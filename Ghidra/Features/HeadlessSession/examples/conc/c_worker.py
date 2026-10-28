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
"""A separate client process (so it can be killed mid-request). params: one JSON argv.

kinds: reader | owner | forker | importer | shared
Progress lines (append, flushed) go to params['progress']."""
import json
import os
import pathlib
import sys
import time

sys.dont_write_bytecode = True
INSTALL = os.environ["X0_GHIDRA"]
sys.path.insert(0, INSTALL + "/Ghidra/Features/HeadlessSession/support")
import ghidra_session as gs  # noqa: E402

P = json.loads(sys.argv[1])
prog = open(P["progress"], "a", buffering=1, encoding="utf-8")


def log(*a):
    prog.write(" ".join(str(x) for x in a) + "\n")
    prog.flush()


def ops(addrs, gen, prefix="cg"):
    o = []
    for i, a in enumerate(addrs):
        o.append({"op": "rename", "address": a, "name": "%s%d_%04d" % (prefix, gen, i)})
        o.append({"op": "comment", "address": a, "type": "plate", "text": "%s%d" % (prefix, gen)})
    return o


c = gs.SocketSession(P["endpoint"], client=P.get("client", "worker"), harness=P.get("harness", "w"), timeout=30)
kind = P["kind"]
M = P.get("M", [])
if kind == "reader":
    o = c.call("open_project", path=P["canon_gpr"])
    p = c.call("open_program", path=P["prog"], project=o["id"])
    key = p["key"]
    log("ready")
    n = 0
    while True:
        for a in P["S"]:
            log("req_start decompile", a)
            c.call("decompile", program=key, address=a, timeout=60)
            n += 1
            log("acked decompile", n)
elif kind == "owner":
    o = c.call("open_project", path=P["canon_gpr"])
    log("req_start fork")
    f = c.call("fork_project", project=o["id"], path=P["fork_dir"], mode=P["mode"])
    log("acked fork", P["fork_dir"])
    p = c.call("open_program", path=P["prog"], project=f["project"], writable=True)
    key = p["key"]
    log("ready")
    g = 0
    while True:
        g += 1
        log("edit_sent", g)
        c.call("edit", program=key, ops=ops(M, g))
        log("edit_ack", g)
        log("save_sent", g)
        c.call("save", program=key)
        log("save_ack", g)
elif kind == "forker":
    o = c.call("open_project", path=P["canon_gpr"])
    log("ready")
    k = 0
    while True:
        k += 1
        dest = P["dest_prefix"] + str(k)
        log("fork_sent", k, dest)
        c.call("fork_project", project=o["id"], path=dest, mode=P["mode"], writable=False)
        log("fork_ack", k)
elif kind == "importer":
    o = c.call("open_project", path=P["canon_gpr"])
    f = c.call("fork_project", project=o["id"], path=P["fork_dir"], mode=P["mode"])
    log("ready")
    log("import_sent")
    c.call("import", file=P["exe"], project=f["project"], analyze=True, timeout=900)
    log("import_ack")
    time.sleep(3600)
elif kind == "shared":
    o = c.call("open_project", path=P["fork_gpr"], writable=True)
    p = c.call("open_program", path=P["prog"], project=o["id"], writable=True, share=True)
    key = p["key"]
    log("ready")
    g = 0
    pre = P["prefix"]
    while True:
        g += 1
        log("edit_sent", g)
        c.call("edit", program=key, ops=ops(M, g, pre))
        log("edit_ack", g)
        log("save_sent", g)
        c.call("save", program=key)
        log("save_ack", g)
