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
"""Protocol-2 behaviour of the E3a engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
package E3a). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e3a.py --ghidra <install> --work <empty dir>

Every test was first run against hydra.3 (``hydra-3-released``) to record what a protocol-2 client sees;
the ones marked (V) are declared v2-visible changes (5.1) and are red there by design.

* ``v2_lane_defaults`` (V9, D62) (V): ``status.scheduler.long.slots`` of a v2 connection is
  ``max(8, CPUs)`` (the CPU count is the engine's: ``quick.slots``); an explicit ``maxLong`` is kept;
  a v2 ``status`` has no ``maint`` lane.
* ``v2_lane_unchanged`` (G2): with the long lane full, a v2 ``save`` and ``fork_project`` wait and
  fail ``busy`` naming the ``long`` lane, with hydra.3's detail keys and without ``retryAfterMs``;
  on the same daemon a v3 ``fork_project`` is admitted (to the ``maint`` lane).
* ``v2_queue_order`` (G3): two labels on one v2 connection share one queue: the older request of
  one label is served before the newer request of the other.
* ``v2_no_preflight`` (G4): a v2 request with a bad field waits for its lane like any other and
  fails ``busy`` when its wait ends; it is not refused at once.
* ``v2_progress_keys`` (G5): a slot wait sends no ``progress`` event at all, as on hydra.3; an
  import wait sends events with exactly hydra.3's keys and ``queue`` keys and no ``estimateScope``.
* ``import_wait`` (V2, no ``wait``) (V): imports queued behind a full long lane all succeed once it
  frees; none fails ``busy`` ten seconds after it reached the front.
* ``import_wait_explicit`` (V2, numeric ``wait``) (V): an import whose ``wait`` was mostly spent in
  the import gate fails ``busy`` when that one budget is used up, where each of its two later waits
  used to get a fresh full ``wait``.
* ``v2_running_cap`` (V9) (V): one v2 connection with a dozen parallel scripts cannot starve a
  second connection's script, and on an idle daemon its first scripts all run at once.
"""
import json
import os
import pathlib
import shutil
import threading
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, expect_error, wait_for

HERE = pathlib.Path(__file__).resolve().parent

#: the keys of a hydra.3 slot ``busy`` (Scheduler.admit)
V2_BUSY_KEYS = ["lane", "slots", "queued", "waitedMs", "running"]
V2_EVENT_KEYS = ["event", "id", "message", "progress", "maximum"]
#: the keys of the ``queue`` object of an import wait (ImportGate.queueInfo)
V2_IMPORT_QUEUE_KEYS = ["position", "ahead", "holder", "running", "maxImports", "estimatedWaitMs"]


def sleep_script(c, s, ms, **extra):
    """Starts a sleeping script (it polls its cancel flag; needs no program) and returns its id."""
    return s.send("script", script=c.script("TestSleep.java"), program=None, args=[str(ms)],
                  parallel=True, wait=300000, **extra)


def warm(c, s):
    s.call("script", script=c.script("TestSleep.java"), program=None, args=["10"])


def lane(s, name):
    return s.call("status")["scheduler"][name]


def occupy(c, s, n, ms):
    ids = [sleep_script(c, s, ms) for _ in range(n)]
    wait_for(lambda: lane(s, "long")["inUse"] >= n, "the long lane to be full", 60)
    return ids


def release(s, ids):
    try:
        s.call("cancel", all=True)
    except Exception:  # noqa: BLE001
        pass
    for i in ids:
        try:
            s.wait(i)
        except Exception:  # noqa: BLE001
            pass


def timed(c, s, cmd, **f):
    t = time.perf_counter()
    try:
        r = s.call(cmd, **f)
        return {"ok": True, "ms": round((time.perf_counter() - t) * 1000), "result": r}
    except c.stock.SessionError as e:
        return {"ok": False, "ms": round((time.perf_counter() - t) * 1000), "code": e.code,
                "details": e.details, "message": e.message}


def make_exe(c):
    exe = c.work / "bin" / "alpha.exe"
    if not exe.exists():
        exe.parent.mkdir(parents=True, exist_ok=True)
        ct = cc._load("characterization_tests_for_cc", HERE / "characterization_tests.py")
        exe.write_bytes(ct.make_pe(7))
    return str(exe)


def cpus_of(s):
    """The engine's CPU count: the default of maxQuick."""
    return lane(s, "quick")["slots"]


# ---- v2_lane_defaults -----------------------------------------------------------------------

def t_v2_lane_defaults(c):
    d = c.daemon("e3a-defaults")
    with d.connect("cc-e3a", "tests") as s:
        st = s.call("status")["scheduler"]
        cpus = st["quick"]["slots"]
        want = max(8, cpus)
        check(st["long"]["slots"] == want,
              f"a v2 status.scheduler.long.slots is {st['long']['slots']}, not max(8, {cpus} CPUs) = "
              f"{want}")
        check(list(st) == ["quick", "long"], f"a v2 scheduler object has lanes {list(st)}")
    d.stop(force=True)
    d = c.daemon("e3a-defaults2", maxLong=3)
    with d.connect("cc-e3a", "tests") as s:
        check(lane(s, "long")["slots"] == 3, "an explicit maxLong must be kept")
    d.stop(force=True)
    return f"{cpus} CPUs: long.slots {want}; explicit maxLong kept; lanes quick, long"


# ---- v2_lane_unchanged ----------------------------------------------------------------------

def t_v2_lane_unchanged(c):
    d = c.daemon("e3a-lane", maxLong=2)
    with d.connect("cc-e3a", "tests") as s, d.connect("cc-e3a-w", "tests") as w:
        ids = occupy(c, s, 2, 25000)
        try:
            for cmd, fields in (("save", {}), ("fork_project", {"path": str(c.work / "e3a-f")})):
                r = timed(c, w, cmd, wait=1200, **fields)
                check(not r["ok"] and r["code"] == "busy",
                      f"a v2 {cmd} with the long lane full should wait and fail busy: {r}")
                check(r["details"].get("lane") == "long" and
                      list(r["details"]) == V2_BUSY_KEYS,
                      f"{cmd} busy details keys {list(r['details'])}")
                check("retryAfterMs" not in w.last_response["error"] and
                      "next" not in w.last_response["error"], f"v3 error keys on a v2 busy")
                check(1100 <= r["ms"] <= 3500, f"{cmd} busy after {r['ms']} ms (wait 1200)")
            check("maint" not in s.call("status")["scheduler"], "a v2 status shows the maint lane")
            # on the same daemon a protocol 3 connection's fork_project is admitted (maint lane)
            n = c.new_daemon("e3a-lane")
            with n.connect("cc-e3a-new", "tests") as s3:
                check(s3.protocol == 3, f"1.1.0 at protocol {s3.protocol}")
                try:
                    s3.call("fork_project", wait=1200, path=str(c.work / "e3a-f3"))
                    raise Fail("a fork_project without a project should be refused")
                except c.new.SessionError as e:
                    check(e.code != "busy", f"a v3 fork_project was {e.code}: not admitted (maint)")
                st = s3.call("status")["scheduler"]
                check(st["maint"]["admitted"] >= 1 and st["long"]["inUse"] == 2,
                      f"a v3 fork_project should be admitted to maint: {st['maint']}")
        finally:
            release(s, ids)
    d.stop(force=True)
    return "v2 save and fork_project: busy on the long lane after the wait, hydra.3 detail keys; v3 fork_project: admitted (maint)"


# ---- v2_queue_order -------------------------------------------------------------------------

def t_v2_queue_order(c):
    """maxLong 2. One v2 connection: label ``a`` sends 2 s, 6 s and a second 2 s script, label ``b``
    then a short one. One connection is one queue: a's third script is served first (at 2 s), b's
    after it (at 4 s). A per-label key would serve b at 2 s."""
    d = c.daemon("e3a-order", maxLong=2)
    with d.connect("cc-e3a", "tests") as s:
        warm(c, s)
        t0 = time.perf_counter()
        a1 = sleep_script(c, s, 2000, client="agent-a", harness="x")
        a2 = sleep_script(c, s, 6000, client="agent-a", harness="x")
        wait_for(lambda: lane(s, "long")["inUse"] >= 2, "both long slots", 30)
        a3 = sleep_script(c, s, 2000, client="agent-a", harness="x")
        wait_for(lambda: lane(s, "long")["queued"] >= 1, "a3 queued", 10)
        tb = time.perf_counter()
        b1 = sleep_script(c, s, 100, client="agent-b", harness="x")
        wait_for(lambda: lane(s, "long")["queued"] >= 2, "b1 queued", 10)
        # two labels, one queue: the waiting list is in the order of arrival
        who = [w["who"] for w in lane(s, "long")["waiting"]]
        check(len(who) == 2 and "agent-a" in who[0] and "agent-b" in who[1],
              f"a v2 connection's waiting requests: {who}")
        s.wait(b1)
        b_ms = (time.perf_counter() - tb) * 1000
        check(b_ms >= 3300, f"b1 was served after {b_ms:.0f} ms: ahead of a3, which arrived first "
              f"on the same connection (hydra.3 serves it after about 4000 ms)")
        for i in (a1, a2, a3):
            s.wait(i)
    d.stop(force=True)
    return f"b1 served {b_ms:.0f} ms after it was sent, after a3 (the same queue)"


# ---- v2_no_preflight ------------------------------------------------------------------------

def t_v2_no_preflight(c):
    d = c.daemon("e3a-nopre", maxLong=1)
    with d.connect("cc-e3a", "tests") as s, d.connect("cc-e3a-b", "tests") as b:
        ids = occupy(c, s, 1, 25000)
        try:
            r = timed(c, b, "script", script="NoSuchScript.java", program=None, timeout="soon",
                      wait=1500)
            check(not r["ok"] and r["code"] == "busy" and r["ms"] >= 1400,
                  f"a v2 request with a bad field must wait for its lane and fail busy at the end "
                  f"of its wait, not be refused at once: {r}")
        finally:
            release(s, ids)
    d.stop(force=True)
    return f"busy after {r['ms']} ms (wait 1500), not bad_request at once"


# ---- v2_progress_keys -----------------------------------------------------------------------

def t_v2_progress_keys(c):
    # a slot wait: hydra.3 sends no progress event for it
    d = c.daemon("e3a-prog", maxLong=1, maxImports=1)
    with d.connect("cc-e3a", "tests") as s, d.connect("cc-e3a-w", "tests") as w:
        warm(c, s)
        ids = occupy(c, s, 1, 3000)
        rid = sleep_script(c, w, 10)
        wait_for(lambda: lane(s, "long")["queued"] >= 1, "the waiter queued", 10)
        w.call("ping")
        time.sleep(1.5)
        w.call("ping")
        waiting_events = [e for e in w.events if e.get("id") == rid]
        # hydra.3 sends no progress event at all for a slot wait (G5): a v2 regression that sent
        # one, with or without the queue key, must fail here
        check(len(waiting_events) == 0,
              f"a v2 slot wait sends no progress event, got {len(waiting_events)}: " +
              json.dumps(waiting_events[:3]))
        w.wait(rid)
        release(s, ids)
        slot_events = len(waiting_events)
        # an import wait: the queue object stays, without estimateScope
        gpr = c.work / "e3a-prog" / "P.gpr"
        c.make_project(s, gpr.parent, "P")
        s.call("open_project", path=str(gpr), writable=True)
        w.call("open_project", path=str(gpr), writable=True)
        raw = cc.dt.raw_file(c, "e3a-prog.bin", 48)
        i1 = s.send("import", file=raw, name="p1", duplicate=True, parallel=True, **cc.dt.RAW_LANG)
        wait_for(lambda: s.call("status")["imports"]["holder"], "the gate held", 30)
        i2 = w.send("import", file=raw, name="p2", duplicate=True, parallel=True, **cc.dt.RAW_LANG)
        wait_for(lambda: s.call("status")["imports"]["queue"], "the second import queued", 30)

        def pumped():
            w.call("ping")
            return [e for e in list(w.events) if e.get("id") == i2 and "waiting behind" in
                    e.get("message", "")]
        evs = wait_for(pumped, "a waiting-behind progress event", 30, 0.3)
        for e in evs:
            check(list(e) == V2_EVENT_KEYS + ["queue"],
                  f"an import-wait progress event has keys {list(e)}")
            check(list(e["queue"]) == V2_IMPORT_QUEUE_KEYS,
                  f"the import queue object has keys {list(e['queue'])}: estimateScope belongs to v3")
        reqs = [r for cl in s.call("status")["clients"] for r in cl["requests"]
                if r.get("waiting") == "import queue"]
        check(reqs and list(reqs[0]["queue"]) == V2_IMPORT_QUEUE_KEYS,
              f"status.requests[].queue of an import wait: {reqs}")
        s.call("cancel", all=True)
        w.call("cancel", all=True)
        for sess, i in ((s, i1), (w, i2)):
            try:
                sess.wait(i)
            except c.stock.SessionError:
                pass
    d.stop(force=True)
    return (f"slot wait: {slot_events} progress events; import wait: events "
            f"with keys {V2_EVENT_KEYS + ['queue']}, queue keys {V2_IMPORT_QUEUE_KEYS}")


# ---- import_wait ----------------------------------------------------------------------------

def t_import_wait(c):
    exe = make_exe(c)
    occupy_ms = 14000
    d = c.daemon("e3a-iw", maxLong=2, maxImports=2)
    with d.connect("cc-e3a-s", "tests") as s, d.connect("cc-e3a-i", "tests") as i:
        gpr = c.make_project(i, c.work / "e3a-iw", "IW")
        i.call("open_project", path=str(gpr), writable=True)
        ids = occupy(c, s, 2, occupy_ms)
        t0 = time.perf_counter()
        rids = [i.send("import", file=exe, name=f"iw{k}", duplicate=True, parallel=True)
                for k in (1, 2, 3)]
        res = []
        for rid in rids:
            try:
                i.wait(rid)
                res.append(("ok", round((time.perf_counter() - t0) * 1000)))
            except c.stock.SessionError as e:
                res.append((e.code, round((time.perf_counter() - t0) * 1000)))
        release(s, ids)
    d.stop(force=True)
    check(all(r[0] == "ok" for r in res),
          f"an import without a wait must wait for the long lane however long it takes: {res} "
          f"(the lane was full for {occupy_ms} ms; hydra.3 fails busy 10 s in)")
    return f"three imports waited {occupy_ms} ms for the long lane and succeeded: {res}"


# ---- import_wait_explicit -------------------------------------------------------------------

def t_import_wait_explicit(c):
    """maxImports 1, maxLong 2, both long slots taken for 5 s. i1 holds the gate (waiting for a slot).
    i2 asks for ``wait`` 4000, sent first, and spends 3 s of it in the gate (i1 is cancelled then).
    Its slot wait gets what is left (about 1 s): busy at about 4 s. On hydra.3 it got a fresh 4 s,
    the slot freed at 5 s and it succeeded."""
    exe = make_exe(c)
    d = c.daemon("e3a-iwe", maxLong=2, maxImports=1)
    with d.connect("cc-e3a-s", "tests") as s, d.connect("cc-e3a-i", "tests") as i:
        gpr = c.make_project(i, c.work / "e3a-iwe", "IWE")
        i.call("open_project", path=str(gpr), writable=True)
        ids = occupy(c, s, 2, 5000)
        t0 = time.perf_counter()
        i1 = i.send("import", file=exe, name="iwe1", duplicate=True, parallel=True)
        wait_for(lambda: s.call("status")["imports"]["holder"], "i1 holding the gate", 30)
        i2 = i.send("import", file=exe, name="iwe2", duplicate=True, parallel=True, wait=4000)
        wait_for(lambda: s.call("status")["imports"]["queue"], "i2 in the gate queue", 30)
        time.sleep(max(0.0, 3.0 - (time.perf_counter() - t0)))
        i.call("cancel", target=i1)
        out = None
        try:
            i.wait(i2)
            out = ("ok", round((time.perf_counter() - t0) * 1000), None)
        except c.stock.SessionError as e:
            out = (e.code, round((time.perf_counter() - t0) * 1000), e.details)
        try:
            i.wait(i1)
        except c.stock.SessionError:
            pass
        release(s, ids)
    d.stop(force=True)
    check(out[0] == "busy" and 3500 <= out[1] <= 4900,
          f"i2 spent 3 s of its 4000 ms wait in the gate: it must fail busy at about 4 s, got {out}")
    wm = (out[2] or {}).get("waitedMs")
    check(wm is not None and wm < 3000, f"the slot wait was given what was left of the wait, not a "
          f"fresh 4000 ms: waitedMs {wm}")
    return f"i2 busy after {out[1]} ms, its slot wait got {wm} ms of the 4000"


# ---- v2_running_cap -------------------------------------------------------------------------

def t_v2_running_cap(c):
    """maxLong 4 (cap 3). Connection A: one 2 s and three 6 s scripts take the idle lane (the cap
    does not apply while nobody waits), then eight more queue. Connection B's script arrives:
    the first freed slot goes to B (A runs 3, its cap) and not to A's older queued request."""
    d = c.daemon("e3a-cap", maxLong=4)
    with d.connect("cc-e3a-a", "tests") as a, d.connect("cc-e3a-b", "tests") as b:
        warm(c, a)
        warm(c, b)
        ids = [sleep_script(c, a, 2000)] + [sleep_script(c, a, 6000) for _ in range(3)]
        wait_for(lambda: lane(a, "long")["inUse"] >= 4, "an idle lane to take A's first four", 10)
        ids += [sleep_script(c, a, 5000) for _ in range(8)]
        wait_for(lambda: lane(a, "long")["queued"] >= 8, "A's queue", 10)
        tb = time.perf_counter()
        rb = sleep_script(c, b, 100)
        wait_for(lambda: lane(a, "long")["queued"] >= 9, "B queued", 10)
        b.wait(rb)
        b_ms = (time.perf_counter() - tb) * 1000
        release(a, ids)
    d.stop(force=True)
    check(b_ms < 4500, f"B's script took {b_ms:.0f} ms: it waited for A's second-oldest request "
          f"(the first slot frees after about 2000 ms, the next ones after 6000 ms)")
    return f"B served {b_ms:.0f} ms after it was sent, behind none of A's older requests"


TESTS = {
    "v2_lane_defaults": t_v2_lane_defaults,
    "v2_lane_unchanged": t_v2_lane_unchanged,
    "v2_queue_order": t_v2_queue_order,
    "v2_no_preflight": t_v2_no_preflight,
    "v2_progress_keys": t_v2_progress_keys,
    "import_wait": t_import_wait,
    "import_wait_explicit": t_import_wait_explicit,
    "v2_running_cap": t_v2_running_cap,
}

if __name__ == "__main__":
    cc.run_file(__file__)
