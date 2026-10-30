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
"""Light overlays (Rust plan rank 1, second step; package mem-views).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --only mv_flag,mv_identical

An overlay's program object is disposable (never saved, checked in, merged or snapshotted; promote
replays the overlay's operation log), so with the engine key ``lightOverlays`` (default true) it
records no change set and keeps one undoable transaction instead of 50. ``isolation:"private"``
script instances do the same only with ``lightPrivateScripts`` (default false).

* ``mv_flag``: ``info.overlay`` says ``recordsChanges:false, undoDepth:1`` on a default daemon and
  ``recordsChanges:true, undoDepth:50`` with ``lightOverlays:false``.
* ``mv_identical``: the same operation sequence (one transaction per call, edits of the same
  functions again after more than one transaction, a failing batch that must roll back in the
  middle) on a light and on a heavy overlay gives identical replies, identical decompiles and
  function lists, and an identical promoted fork.
* ``mv_memory`` (a measurement, not a pass/fail gate): 8 overlays, ``MV_OPS`` comment transactions
  each, then heap after a full GC (``GC.heap_info``) and NMT committed totals
  (``VM.native_memory summary``) of the daemon, light and heavy.
"""
import os
import pathlib
import re
import shutil
import subprocess
import time

import daemon_tests as dt

check = dt.check
expect_error = dt.expect_error

N_FUNCS = 12
MV_OPS = int(os.environ.get("MV_OPS", "150"))
VOLATILE = {"ms", "openMs", "ageMs", "waitedMs", "heldMs", "queue", "waited", "uptimeMs",
            "createdAt", "client", "gpr", "tick", "seconds", "recordsChanges", "undoDepth"}


def _scrub(v):
    """A reply without timings, client ids and paths: what must be equal light and heavy."""
    if isinstance(v, dict):
        return {k: _scrub(x) for k, x in sorted(v.items()) if k not in VOLATILE}
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    return v


def _fns(s, **kw):
    return [f for f in s.call("functions", limit=400, **kw)["functions"]
            if not f["thunk"] and not f["external"]]


def t_mv_flag(c):
    exe = pathlib.Path(c.a.exe).name
    seen = {}
    for label, engine in (("light", {}), ("heavy", {"lightOverlays": False})):
        gpr = c.copy_fixture("projMv-" + label)
        d = c.daemon("mv-flag-" + label, keepWarm=0, engine=engine)
        with d.connect("mv", "tests") as s:
            s.call("open_project", path=str(gpr))
            s.call("open_program", path=exe, overlay="v")
            fn = _fns(s)[0]
            s.call("comment", overlay="v", address=fn["address"], text="x", type="eol")
            ov = s.call("info", overlay="v")["overlay"]
            seen[label] = (ov.get("recordsChanges"), ov.get("undoDepth"), ov.get("changed"))
        d.stop()
    check(seen["light"] == (False, 1, True), f"light overlay: {seen['light']}")
    check(seen["heavy"] == (True, 50, True), f"heavy overlay: {seen['heavy']}")
    return f"light {seen['light']}, heavy {seen['heavy']} (recordsChanges, undoDepth, changed)"


def _sequence(c, label, engine):
    """Runs the fixed operation sequence on one overlay and promotes it; returns everything read."""
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("projMvId-" + label)
    fork = c.work / ("projMvIdFork-" + label)
    shutil.rmtree(fork, ignore_errors=True)
    d = c.daemon("mv-id-" + label, keepWarm=0, engine=engine)
    out = {"replies": [], "decompiles": {}, "fork": {}}
    with d.connect("mv", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe, overlay="v")
        fns = _fns(s)[:N_FUNCS]
        check(len(fns) >= 4, f"fixture has too few functions: {len(fns)}")
        rep = out["replies"]
        # one transaction per call: more than undoDepth (1) checkpoints get packed
        for i, f in enumerate(fns):
            rep.append(s.call("comment", overlay="v", address=f["address"],
                              text=f"plate {i}", type="plate"))
            rep.append(s.call("rename", overlay="v", address=f["address"], name=f"mv_fn_{i}"))
        # a failing batch after several commits rolls back as a whole
        e = expect_error("bad_request", s.call, "apply_overlay", overlay="v", ops=[
            {"op": "rename", "address": fns[1]["address"], "name": "never_applied"},
            {"op": "comment", "address": fns[2]["address"], "text": "never", "type": "eol"},
            {"op": "signature", "address": fns[0]["address"], "signature": "this is ( not C"}])
        rep.append({"error": e.code, "details": e.details})
        check(not s.call("functions", overlay="v", contains="never_applied")["functions"],
              f"{label}: the failed batch left a rename")
        # the same functions edited again, buffers rewritten after their checkpoint was packed
        for i, f in enumerate(fns):
            rep.append(s.call("apply_overlay", overlay="v", ops=[
                {"op": "comment", "address": f["address"], "text": f"eol {i}", "type": "eol"},
                {"op": "comment", "address": f["address"], "text": f"plate {i} again",
                 "type": "plate"}]))
        rep.append(s.call("apply_overlay", overlay="v", ops=[
            {"op": "signature", "address": fns[0]["address"], "signature": "int mv_fn_0(int x)"}]))
        for f in fns:
            out["decompiles"][f["address"]] = s.call("decompile", overlay="v",
                                                     address=f["address"])
        out["functions"] = s.call("functions", overlay="v", limit=400)
        inf = s.call("info", overlay="v")
        out["info"] = {k: inf[k] for k in ("mode", "changed")}
        out["info"]["ops"] = inf["overlay"]["ops"]
        out["info"]["overlayVersion"] = inf["overlay"]["overlayVersion"]
        pr = s.call("promote_overlay", overlay="v", fork={"path": str(fork)}, wait=600000)
        out["promote"] = {"promoted": pr["promoted"], "results": pr["results"],
                          "saved": bool(pr["saved"] and pr["saved"].get("saved"))}
        fk = pr["target"]
        for f in fns:
            out["fork"][f["address"]] = s.call("decompile", program=fk, address=f["address"])
        out["fork"]["functions"] = s.call("functions", program=fk, limit=400)
        s.call("close_project", project=pr["project"])
    d.stop()
    shutil.rmtree(fork, ignore_errors=True)
    return _scrub(out)


def t_mv_identical(c):
    light = _sequence(c, "light", {})
    heavy = _sequence(c, "heavy", {"lightOverlays": False})
    for k in ("replies", "decompiles", "functions", "info", "promote", "fork"):
        if light[k] != heavy[k]:
            raise dt.Fail(f"{k} differs light vs heavy:\nlight={str(light[k])[:1500]}\n"
                          f"heavy={str(heavy[k])[:1500]}")
    check(light["promote"]["saved"] and light["promote"]["promoted"] > 0,
          f"promote: {light['promote']}")
    n = len(light["replies"])
    return (f"{n} replies, {len(light['decompiles'])} decompiles, functions, info, promote and the "
            f"promoted fork identical light and heavy")


def _jcmd():
    j = shutil.which("jcmd")
    if j:
        return j
    jh = os.environ.get("JAVA_HOME")
    if jh and (pathlib.Path(jh) / "bin" / "jcmd.exe").exists():
        return str(pathlib.Path(jh) / "bin" / "jcmd.exe")
    raise dt.Fail("jcmd not found (PATH or JAVA_HOME)")


def _jc(pid, *args):
    r = subprocess.run([_jcmd(), str(pid), *args], capture_output=True, text=True, timeout=120)
    return r.stdout


def _measure(pid):
    _jc(pid, "GC.run")
    time.sleep(1)
    _jc(pid, "GC.run")
    heap = _jc(pid, "GC.heap_info")
    m = re.search(r"used (\d+)K", heap)
    nmt = _jc(pid, "VM.native_memory", "summary", "scale=KB")
    tot = re.search(r"Total: reserved=(\d+)KB, committed=(\d+)KB", nmt)
    cls = {}
    for name in ("Java Heap", "Class", "Thread", "Code", "GC", "Internal", "Other", "Symbol",
                 "Native Memory Tracking", "Arena Chunk", "Metaspace"):
        mm = re.search(r"-\s+" + re.escape(name) + r" \(reserved=\d+KB, committed=(\d+)KB\)",
                       nmt)
        if mm:
            cls[name] = int(mm.group(1))
    return {"heapUsedKB": int(m.group(1)) if m else None,
            "nmtCommittedKB": int(tot.group(2)) if tot else None, "nmt": cls,
            "nmtRaw": None if tot else nmt[:400]}


def _tmp_bytes(d):
    total = 0
    for p in pathlib.Path(d).rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _memory(c, label, engine):
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("projMvMem-" + label)
    tmp = c.work / ("mvtmp-" + label)
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    d = c.daemon("mv-mem-" + label, keepWarm=0, engine=engine,
                 vmargs=["-XX:NativeMemoryTracking=summary", f"-Djava.io.tmpdir={tmp}"])
    sessions = []
    try:
        for i in range(8):
            s = d.connect(f"mv{i}", "tests")
            sessions.append(s)
            s.call("open_project", path=str(gpr))
            s.call("open_program", path=exe, overlay=f"v{i}")
        fns = _fns(sessions[0])
        pid = int(d.read_endpoint()["pid"])
        before = _measure(pid)
        before["tmpBytes"] = _tmp_bytes(tmp)
        t = time.perf_counter()
        for k in range(MV_OPS):
            f = fns[k % len(fns)]
            for i, s in enumerate(sessions):
                s.call("comment", overlay=f"v{i}", address=f["address"],
                       text=f"mv {label} {i} {k}", type="eol")
        secs = time.perf_counter() - t
        after = _measure(pid)
        after["tmpBytes"] = _tmp_bytes(tmp)
    finally:
        for s in sessions:
            s.close()
        d.stop()
    return {"before": before, "after": after, "writeSeconds": round(secs, 2),
            "ops": MV_OPS * 8}


def t_mv_memory(c):
    res = {}
    for label, engine in (("heavy", {"lightOverlays": False}), ("light", {})):
        res[label] = _memory(c, label, engine)
    c.timings["mv_memory"] = res
    lines = []
    for label, r in res.items():
        b, a = r["before"], r["after"]
        lines.append(f"{label}: heap {b['heapUsedKB']}->{a['heapUsedKB']} KB, NMT committed "
                     f"{b['nmtCommittedKB']}->{a['nmtCommittedKB']} KB, tmp "
                     f"{b['tmpBytes']}->{a['tmpBytes']} B, {r['ops']} comment tx in "
                     f"{r['writeSeconds']} s")
    print("MV_MEMORY " + repr(res), flush=True)
    return "; ".join(lines)


TESTS = {"mv_flag": t_mv_flag, "mv_identical": t_mv_identical, "mv_memory": t_mv_memory}
