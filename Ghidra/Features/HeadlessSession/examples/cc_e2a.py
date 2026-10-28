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
"""Behaviour of the E2a engine seen by a protocol-2 client (PROTOCOL-3.md 5.1 V11, package E2a),
written against the stock 1.0.0 client. Standard library only; any OS.

    python cc_e2a.py --ghidra <install> --work <empty dir>

Tests:

* ``fork_race_conflict`` (V11): six concurrent ``fork_project`` calls to one destination by the stock
  client give exactly one success and five ``conflict`` (``details.reason`` ``fork_in_progress``
  or ``exists``; a late arrival that finds the finished fork gets the ordinary "already exists"
  conflict), never a bare ``failed`` that names a ``.rep`` path; no staging folder is left; the
  winner's fork is complete (every file of the source, sidecar ``state:"complete"``) and the
  project it returned opens; the source is untouched.
* ``fork_race_rk``: the same race by the 1.1.0 client (protocol 3) with one shared ``rk``: all six
  return the winner's result (same ``gpr``, ``baseRevision`` and ``bytes``; one without
  ``replayed``), and a repeat of the request later returns the completed fork again. A protocol-2
  request ignores ``rk`` (G7): the repeat is the ordinary ``conflict``.
* ``fork_sidecar_state``: the sidecar of a finished fork says ``state:"complete"`` and its
  ``forkId``; the v2 reply of ``fork_project`` has exactly the keys it always had.
"""
import json
import os
import pathlib
import re
import shutil
import threading

import client_compat_tests as cc
from client_compat_tests import Fail, check, expect_error

STAGING = re.compile(r"^\..+\.fork-.+\.tmp$")
BALLAST_FILES = 8
BALLAST_MB = 4
RACERS = 6

#: the keys of a protocol-2 fork_project result, in order (ForkCommands.forkClaimed)
V2_FORK_KEYS = ["project", "path", "gpr", "name", "writable", "source", "baseRevision", "mode",
                "method", "cloned", "clonedBy", "bytes", "files", "copyMs", "freeSpaceUsedBytes",
                "depth", "sidecar", "ms", "info"]


def source(c):
    """A small project with ballast (so that the copies overlap), made once, never written after."""
    base = c.work / "e2a-cc-src"
    gpr = base / "Src.gpr"
    if not gpr.exists():
        d = c.daemon("e2a-cc-mk")
        with d.connect("e2a", "cc-e2a") as s:
            c.make_project(s, base, "Src")
        d.stop()
        ballast = base / "Src.rep" / "ballast"
        ballast.mkdir()
        blob = os.urandom(1 << 20)
        for i in range(BALLAST_FILES):
            (ballast / f"b{i}.bin").write_bytes(blob * BALLAST_MB)
    return gpr


def tree(folder):
    return {str(f.relative_to(folder)): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in pathlib.Path(folder).rglob("*") if f.is_file()}


def rep_files(gpr):
    rep = gpr.parent / (gpr.stem + ".rep")
    return {str(f.relative_to(rep)): f.stat().st_size for f in rep.rglob("*")
            if f.is_file() and not f.name.endswith(".lock")}


def race(connect, src, dest, n=RACERS, **fields):
    """``n`` connections, each making the same fork_project at the same moment. Returns
    ``[(ok, result or error)]`` in thread order."""
    sessions = [connect(f"racer{i}") for i in range(n)]
    gate = threading.Barrier(n)
    out = [None] * n

    def go(i):
        try:
            gate.wait(30)
            out[i] = (True, sessions[i].call("fork_project", project=str(src), path=str(dest),
                                             mode="full", wait=60000, **fields))
        except Exception as e:  # noqa: BLE001
            out[i] = (False, e)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(120)
    return sessions, out


def describe(out):
    return [("ok" if ok else f"{getattr(r, 'code', type(r).__name__)}"
             f"/{(getattr(r, 'details', None) or {}).get('reason')}") for ok, r in out]


def t_fork_race_conflict(c):
    src = source(c)
    before = tree(src.parent)
    base = c.work / "e2a-race"
    if base.exists():
        shutil.rmtree(base)
    d = c.daemon("e2a-race")
    dest = base / "Fork"

    sessions, out = race(lambda n: d.connect(n, "cc-e2a"), src, dest, name="Winner")
    try:
        wins = [r for ok, r in out if ok]
        losers = [r for ok, r in out if not ok]
        check(len(wins) == 1 and len(losers) == RACERS - 1,
              f"{len(wins)} successes and {len(losers)} failures: {describe(out)}")
        for e in losers:
            code = getattr(e, "code", None)
            reason = (getattr(e, "details", None) or {}).get("reason")
            check(code == "conflict" and (reason in ("fork_in_progress", "exists") or
                                          "already exists" in str(e)),
                  f"a losing fork answered {code}/{reason}: {e}")
            check(code != "failed", f"a bare failed: {e}")
        reasons = [(getattr(e, "details", None) or {}).get("reason") for e in losers]
        gpr = pathlib.Path(wins[0]["gpr"])
        names = sorted(os.listdir(base / "Fork"))
        check(not [n for n in names if STAGING.match(n)], f"a staging folder is left: {names}")
        check(sorted(n for n in names if not n.endswith("lock") and not n.endswith("lock~")) ==
              ["Winner.fork.json", "Winner.gpr", "Winner.rep"], f"the folder holds {names}")
        side = json.loads((base / "Fork" / "Winner.fork.json").read_text())
        check(side.get("state") == "complete" and side.get("forkId"), f"sidecar {side}")
        check(rep_files(gpr) == rep_files(src), "the winner's fork is not a complete copy")
        # the winner's project opens, and the winner's client holds it
        info = sessions[[i for i, (ok, _) in enumerate(out) if ok][0]].call("projects")
        check(any(p.get("id") == wins[0]["project"] for p in info.get("projects", [])),
              f"the winner's project is not open: {info}")
    finally:
        for s in sessions:
            s.close()
        d.stop()
    check(tree(src.parent) == before, "the source was written")
    return f"1 success, {RACERS - 1} conflict ({reasons}), no staging folder, fork complete"


def t_fork_race_rk(c):
    c.need_engine()
    src = source(c)
    base = c.work / "e2a-race-rk"
    if base.exists():
        shutil.rmtree(base)
    d = c.new_daemon("e2a-race-rk")
    dest = base / "Fork"
    sessions, out = race(lambda n: d.connect(n, "cc-e2a"), src, dest, name="Winner",
                         rk="e2a-race-key")
    try:
        check(all(ok for ok, _ in out), f"with one rk all six must return a result: "
              f"{describe(out)}")
        res = [r for _, r in out]
        check(len({r["gpr"] for r in res}) == 1 and len({r["baseRevision"] for r in res}) == 1 and
              len({r["bytes"] for r in res}) == 1 and len({r["copyMs"] for r in res}) == 1,
              f"the six results differ: {[(r['gpr'], r['copyMs']) for r in res]}")
        fresh = [r for r in res if not r.get("replayed")]
        check(len(fresh) == 1, f"{len(fresh)} results claim to be the original")
        check(len({r["project"] for r in res}) == 1, "the six clients must share the one fork")
        names = sorted(os.listdir(base / "Fork"))
        check(not [n for n in names if STAGING.match(n)], f"a staging folder is left: {names}")
        # the same request again, later: the completed fork, replayed
        again = d.connect("again", "cc-e2a")
        r = again.call("fork_project", project=str(src), path=str(dest), name="Winner",
                       mode="full", rk="e2a-race-key")
        check(r.get("replayed") is True and r["gpr"] == res[0]["gpr"],
              f"a repeat with the same rk: {r}")
        # another key on the same destination is the ordinary conflict
        e = expect_error("conflict", again.call, "fork_project", project=str(src),
                         path=str(dest), name="Winner", mode="full", rk="e2a-other-key")
        check((e.details or {}).get("reason") == "exists", f"details {e.details}")
        again.close()
        # no key, no race: v3 sees the reason as well
        n = d.connect("plain", "cc-e2a")
        e = expect_error("conflict", n.call, "fork_project", project=str(src), path=str(dest),
                         name="Winner", mode="full")
        check((e.details or {}).get("reason") == "exists", f"details {e.details}")
        n.close()
    finally:
        for s in sessions:
            s.close()
        d.stop()
    # a protocol-2 client ignores rk (G7): the repeat is the ordinary conflict, reply unchanged
    v2 = c.daemon("e2a-race-rk-v2")
    with v2.connect("stock", "cc-e2a") as s:
        a = s.call("fork_project", project=str(src), path=str(base / "V2"), name="One",
                   mode="full", rk="e2a-v2-key")
        check("replayed" not in a, f"a v2 reply has replayed: {list(a)}")
        e = expect_error("conflict", s.call, "fork_project", project=str(src),
                         path=str(base / "V2"), name="One", mode="full", rk="e2a-v2-key")
        check(set(e.details) == {"path", "suggest"}, f"the v2 conflict details changed: {e.details}")
    v2.stop()
    return "six clients, one rk: one result six times, replay later, v2 ignores rk"


def t_fork_sidecar_state(c):
    src = source(c)
    base = c.work / "e2a-sidecar"
    if base.exists():
        shutil.rmtree(base)
    d = c.daemon("e2a-sidecar")
    with d.connect("stock", "cc-e2a") as s:
        r = s.call("fork_project", project=str(src), path=str(base), name="One", mode="full")
        check(list(r) == V2_FORK_KEYS, f"the keys of the v2 reply changed: {list(r)}")
        side = json.loads(pathlib.Path(r["sidecar"]).read_text())
        check(side["state"] == "complete" and side["forkId"] and side["kind"] ==
              "ghidra-session-fork", f"{side}")
        check(not [n for n in os.listdir(base) if STAGING.match(n) or n.endswith(".tmp")],
              f"leftovers: {os.listdir(base)}")
    d.stop()
    return "sidecar state complete, v2 reply keys unchanged"


TESTS = {"fork_race_conflict": t_fork_race_conflict, "fork_race_rk": t_fork_race_rk,
         "fork_sidecar_state": t_fork_sidecar_state}

if __name__ == "__main__":
    cc.run_file(__file__)
