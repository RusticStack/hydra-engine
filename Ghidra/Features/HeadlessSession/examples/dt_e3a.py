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
"""Lanes, fair key, queue information and validate-before-wait (PROTOCOL-3.md 3.5, package E3a).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only maint_lane,...

The tests that E0 wrote as expected-fail baselines and that E3a fixes live in ``dt_baseline.py`` and
are run by name once this package has landed: ``lane_starvation``, ``fork_save_behind_analysis`` and
``import_wait`` (the red-table rows BP9, BP10 and ``import_wait`` are judged by ``conc/red_table.py``).
The tests here are the ones the spec names for E3a that have no baseline twin. All of them ask for
protocol 3 (``c.connect(..., 3)``); the protocol 2 behaviour is ``cc_e3a.py``'s.

* ``maint_lane``: with the long lane taken, ``save`` and ``fork_project`` of a protocol 3 connection
  start at once and run in the ``maint`` lane (``status.scheduler.maint.admitted``).
* ``fair_key``: two labels on one connection are two keys: a label with a running slot at its cap
  does not delay the other label's request (service order), and ``status`` counts per key.
* ``queue_info``: ``position`` and ``ahead`` while a request waits for a slot (status, ``status.requests``
  and the ``progress`` events), ``estimatedWaitMs`` null until the lane has five completions and a
  number afterwards, ``estimate`` true; a ``busy`` carries ``reason:"slot_wait"``, the ``queue`` object
  and ``error.retryAfterMs``; a request that waited says so in ``queue`` and ``waited``.
* ``preflight_wait``: a bad request fails at once when the lane is full, and keeps its old error when
  it is not. On a full quick lane, the generic checks (``address``/``name`` of ``decompile``,
  ``rename`` and ``comment``, ``rk``, ``expect``) refuse a bad request at once and let every valid
  form queue, among them a ``decompile`` by ``name`` (``Requests.registerPreflight``).
* ``per_key_cap_conserving``: four slots, cap 1, two keys that each run one request and queue another:
  when the other two finish, both queued requests run and no slot idles.
"""
import time

import daemon_tests as dt

try:
    import dt_baseline as bl
except ImportError:  # loaded by path (daemon_tests.load_dt) before dt_baseline was registered
    import importlib.util
    import pathlib
    import sys
    _p = pathlib.Path(__file__).resolve().parent / "dt_baseline.py"
    _spec = importlib.util.spec_from_file_location("dt_baseline", _p)
    bl = importlib.util.module_from_spec(_spec)
    sys.modules["dt_baseline"] = bl
    _spec.loader.exec_module(bl)

def start_sleep(c, view, ms, quick=True, wait=120000, **extra):
    fields = {"script": c.script("TestSleep.java"), "program": None, "args": [str(ms)],
              "parallel": True, "wait": wait}
    if quick:
        fields.update(lane="quick", timeout=60)
    fields.update(extra)
    return view.send("script", **fields)


def warm(c, s):
    """Runs the sleep script once in each lane, so that script compilation is not measured."""
    s.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], lane="quick",
           timeout=60)
    s.call("script", script=c.script("TestSleep.java"), program=None, args=["10"])


def lane_status(s, lane):
    return s.call("status")["scheduler"][lane]


def finish(c, s, ids):
    try:
        s.call("cancel", all=True)
    except Exception:  # noqa: BLE001
        pass
    for i in ids:
        try:
            s.wait(i)
        except Exception:  # noqa: BLE001
            pass


# ---- maint_lane -----------------------------------------------------------------------------

def t_maint_lane(c):
    """The occupiers hold both long slots until the test cancels them (no run time of their own),
    so "the long lane is full" holds for the whole of save and fork_project however slow the
    machine. That save and fork_project did not queue behind it is the scheduler's own account:
    admitted by the maint lane, which queued nothing, and no long slot taken. How long they took
    is reported, not judged: a wall-clock bound measures the machine's load (a save took 16.7 s
    under a full suite, in the maint lane, nothing queued)."""
    exe = bl.prepare(c)
    gpr = c.copy_fixture("e3aMaint")
    forks = c.work / "e3aMaintForks"
    d = c.daemon("e3a-maint", maxLong=2)
    with c.connect(d, "committer", "e3a", 3) as W, c.connect(d, "analysis", "e3a", 3) as S:
        dt.check(W.hello["protocol"] == 3, f"the engine answered protocol {W.hello['protocol']}")
        pid = W.call("open_project", path=str(gpr), writable=True)["id"]
        W.call("open_program", path=exe, writable=True)
        W.call("rename", address=bl.first_function(W), name="e3a_maint_name")
        ids = bl.occupy_long(c, S, 2, 3600000)
        try:
            before = S.call("status")["scheduler"]
            # the wait is the most a queued save could wait before busy: nothing queues here
            save = bl.timed(c, W, "save", wait=5000)
            fork = bl.timed(c, W, "fork_project", project=pid, path=str(forks / "f1"),
                            mode="full", wait=5000)
            after = S.call("status")["scheduler"]
        finally:
            bl.release_long(c, S, ids)
        dt.check(save["ok"] and fork["ok"], f"save {save.get('code')} / fork {fork.get('code')} "
                 f"with the long lane full: {save.get('message')} {fork.get('message')}")
        dt.check(before["maint"]["slots"] == 4, f"maint slots {before['maint']['slots']}, not 4")
        dt.check(after["maint"]["admitted"] - before["maint"]["admitted"] >= 2,
                 f"maint admitted {before['maint']['admitted']} -> {after['maint']['admitted']}")
        dt.check(after["maint"]["everQueued"] == before["maint"]["everQueued"],
                 f"save or fork_project queued in the maint lane: everQueued "
                 f"{before['maint']['everQueued']} -> {after['maint']['everQueued']}")
        dt.check(after["long"]["admitted"] == before["long"]["admitted"],
                 "save or fork_project took a long slot")
        dt.check(after["long"]["inUse"] == 2 and after["long"]["queued"] == 0,
                 f"long lane {after['long']['inUse']} in use, {after['long']['queued']} queued")
        W.call("close_program", discard=True)
        W.call("close_project")
    d.stop(force=True)
    return (f"with 2 of 2 long slots held: save {save['ms']} ms and fork_project {fork['ms']} ms, "
            f"both admitted by the maint lane at once")


# ---- fair_key -------------------------------------------------------------------------------

def t_fair_key(c):
    """maxQuick 2 (cap 1). One connection, two labels: ``a`` has two running (idle lane: the cap
    does not apply) and one queued, ``b`` one queued. The first freed slot goes to ``b`` (under its
    cap) and not to ``a``'s older request; with one key per connection ``b`` would wait for it."""
    d = c.daemon("e3a-fair", maxQuick=2)
    with c.connect(d, "agents", "e3a", 3) as X:
        warm(c, X)
        a = X.labelled(client="agent-a", harness="e3a")
        b = X.labelled(client="agent-b", harness="e3a")
        ids = []
        try:
            t0 = time.perf_counter()
            ids.append(start_sleep(c, a, 2500))
            ids.append(start_sleep(c, a, 9000))
            dt.wait_for(lambda: lane_status(X, "quick")["inUse"] >= 2, "both quick slots busy", 30)
            ids.append(start_sleep(c, a, 2500))      # a3: queued, older than b1
            dt.wait_for(lambda: lane_status(X, "quick")["queued"] >= 1, "a3 queued", 10)
            tb = time.perf_counter()
            b1 = start_sleep(c, b, 100)
            ids.append(b1)
            dt.wait_for(lambda: lane_status(X, "quick")["queued"] >= 2, "b1 queued", 10)
            lane = lane_status(X, "quick")
            keys = lane["perKey"]
            dt.check(len(keys) == 2, f"two labels on one connection must be two keys: {keys}")
            ka = [k for k in keys if "agent-a" in k["who"]]
            kb = [k for k in keys if "agent-b" in k["who"]]
            dt.check(ka and kb and ka[0]["running"] == 2 and ka[0]["queued"] == 1 and
                     kb[0]["running"] == 0 and kb[0]["queued"] == 1,
                     f"per-key counts: {keys}")
            dt.check(lane["perKeyCap"] == 1, f"quick cap {lane['perKeyCap']}, not 1")
            X.wait(b1)
            ids.remove(b1)   # collected: a second wait on it would never return
            b1_ms = (time.perf_counter() - tb) * 1000
            after = lane_status(X, "quick")
            dt.check(b1_ms < 4200,
                     f"b1 took {b1_ms:.0f} ms: it waited behind a's older request (the first slot "
                     f"is freed after about 2500 ms; a2 holds the other for 9000 ms)")
            dt.check(b1_ms > 1500, f"b1 took only {b1_ms:.0f} ms: no slot was taken")
            running = {w["who"] for w in after["running"]}
            dt.check(any("agent-a" in w for w in running),
                     f"a's long sleeper should still run: {after['running']}")
        finally:
            finish(c, X, ids)
    d.stop(force=True)
    return f"b1 served {b1_ms:.0f} ms after it was sent, before a's older request; per key {keys}"


# ---- queue_info -----------------------------------------------------------------------------

def t_queue_info(c):
    out = []
    # (1) no history: the estimate is null, the position is there
    d = c.daemon("e3a-queue0", maxLong=1)
    with c.connect(d, "occupier", "e3a", 3) as S, c.connect(d, "waiter", "e3a", 3) as W:
        ids = [start_sleep(c, S, 20000, quick=False)]
        dt.wait_for(lambda: lane_status(S, "long")["inUse"] >= 1, "the long slot taken", 30)
        try:
            rid = start_sleep(c, W, 100, quick=False)
            dt.wait_for(lambda: lane_status(S, "long")["queued"] >= 1, "the waiter queued", 10)
            w = lane_status(S, "long")["waiting"][0]
            dt.check(w["position"] == 1 and w["estimatedWaitMs"] is None,
                     f"no history: position/estimate {w}")
            reqs = [r for cl in S.call("status")["clients"] for r in cl["requests"]
                    if r.get("waiting") == "long slot"]
            dt.check(reqs and reqs[0]["queue"]["lane"] == "long" and reqs[0]["queue"]["position"] == 1
                     and reqs[0]["queue"]["ahead"] == 0 and reqs[0]["queue"]["estimate"] is True
                     and reqs[0]["queue"]["estimatedWaitMs"] is None,
                     f"status.requests[].queue of a slot wait: {reqs}")
            def pumped():  # events are read while the client talks to the engine
                W.call("ping")
                return any(e.get("queue") for e in list(W.events))
            dt.wait_for(pumped, "a progress event with the queue key", 15, 0.3)
            ev = [e for e in W.events if e.get("queue")][0]
            dt.check(ev["queue"]["lane"] == "long" and "waiting for a long slot" in ev["message"],
                     f"progress event: {ev}")
            # busy: reason, queue, retryAfterMs
            try:
                W.call("script", script=c.script("TestSleep.java"), program=None, args=["10"],
                       wait=400)
                raise dt.Fail("the waiter should have been busy")
            except c.gs.SessionError as e:
                dt.check(e.code == "busy", f"expected busy, got {e.code}")
                err = W.last_response["error"]
                dt.check(e.details.get("reason") == "slot_wait" and e.details["lane"] == "long" and
                         e.details["queue"]["position"] == 2 and e.details["queue"]["ahead"] == 1,
                         f"busy details: {e.details}")
                dt.check(err.get("retryAfterMs") == 1000,
                         f"retryAfterMs without history is 1000: {err.get('retryAfterMs')}")
        finally:
            finish(c, S, ids)
            try:
                W.wait(rid)
            except Exception:  # noqa: BLE001
                pass
        out.append("no history: estimate null, position 1, events and status carry queue; busy has "
                   "reason slot_wait and retryAfterMs 1000")
    d.stop(force=True)

    # (2) with five completions the estimate is a number: ceil((ahead+1)/slots) * median hold
    d = c.daemon("e3a-queue1", maxLong=1)
    with c.connect(d, "occupier", "e3a", 3) as S, c.connect(d, "waiter", "e3a", 3) as W:
        warm(c, S)
        for _ in range(5):
            S.call("script", script=c.script("TestSleep.java"), program=None, args=["1000"])
        ids = [start_sleep(c, S, 30000, quick=False)]
        dt.wait_for(lambda: lane_status(S, "long")["inUse"] >= 1, "the long slot taken", 30)
        rid = None
        try:
            rid = start_sleep(c, W, 100, quick=False)
            dt.wait_for(lambda: lane_status(S, "long")["queued"] >= 1, "the waiter queued", 10)
            w = lane_status(S, "long")["waiting"][0]
            est = w["estimatedWaitMs"]
            dt.check(isinstance(est, int) and 900 <= est <= 4000,
                     f"five 1000 ms completions: the estimate is about one median: {w}")
            try:
                W.call("script", script=c.script("TestSleep.java"), program=None, args=["10"],
                       wait=300)
            except c.gs.SessionError as e:
                ra = W.last_response["error"].get("retryAfterMs")
                dt.check(e.code == "busy" and isinstance(ra, int) and 900 <= ra <= 4000,
                         f"retryAfterMs is the median hold time: {ra}")
            # a lane dominated by one long job: no estimate (the holder runs more than 5 medians)
        finally:
            finish(c, S, ids)
            if rid is not None:
                try:
                    W.wait(rid)
                except Exception:  # noqa: BLE001
                    pass
        out.append(f"five completions: estimate {est} ms, retryAfterMs the median")
    # (3) a request that waited says so in queue and waited (>= 250 ms)
    with c.connect(d, "occupier2", "e3a", 3) as S, c.connect(d, "waiter2", "e3a", 3) as W:
        ids = [start_sleep(c, S, 1500, quick=False)]
        dt.wait_for(lambda: lane_status(S, "long")["inUse"] >= 1, "the long slot taken", 30)
        W.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=20000)
        r = W.last_response
        dt.check("waited" in r and r["waited"]["slotMs"] >= 250 and r["waited"]["queueMs"] == 0
                 and r["queue"]["lane"] == "long", f"waited/queue of a request that queued: {r}")
        W.call("ping")
        dt.check("waited" not in W.last_response and "queue" not in W.last_response,
                 "a request that did not wait carries neither")
        finish(c, S, ids)
        out.append(f"waited {r['waited']}")
    d.stop(force=True)
    return "; ".join(out)


# ---- preflight_wait -------------------------------------------------------------------------

def t_preflight_wait(c):
    d = c.daemon("e3a-pre", maxLong=1)
    bad = {"script": "NoSuchScript.java", "program": None, "timeout": "soon"}
    with c.connect(d, "occupier", "e3a", 3) as S, c.connect(d, "bad", "e3a", 3) as B:
        # lane free: the old order of errors (the script is looked up before the timeout is read)
        free = bl.timed(c, B, "script", wait=20000, **bad)
        dt.check(not free["ok"] and free["code"] == "not_found",
                 f"with the lane free the old error wins: {free}")
        ids = [start_sleep(c, S, 20000, quick=False)]
        dt.wait_for(lambda: lane_status(S, "long")["inUse"] >= 1, "the long slot taken", 30)
        try:
            full = bl.timed(c, B, "script", wait=20000, **bad)
            dt.check(not full["ok"] and full["code"] == "bad_request",
                     f"with the lane full the bad timeout is refused: {full}")
            dt.check(full["ms"] < 1500, f"the refusal took {full['ms']} ms (wait was 20000)")
            dt.check(lane_status(S, "long")["queued"] == 0, "the refused request is not queued")
            # a good request still queues and is not refused
            rid = start_sleep(c, B, 10, quick=False, wait=30000)
            dt.wait_for(lambda: lane_status(S, "long")["queued"] >= 1, "a good request queues", 10)
        finally:
            finish(c, S, ids)
            try:
                B.wait(rid)
            except Exception:  # noqa: BLE001
                pass
    d.stop(force=True)
    fields = preflight_fields(c)
    return (f"lane free: {free['code']} after {free['ms']} ms; lane full: {full['code']} after "
            f"{full['ms']} ms (wait 20000); quick lane full: {fields}")


def preflight_fields(c):
    """The generic checks of ``Requests.registerPreflight`` on a full quick lane: a request with a
    bad field is refused at once and does not queue; every valid form of the same command queues
    (is not refused), in particular ``decompile`` by ``name`` (the command takes an address or a
    name) and ``rename``/``comment`` with ``rk`` and ``expect``."""
    exe = bl.prepare(c)
    gpr = c.copy_fixture("e3aPreflight")
    d = c.daemon("e3a-prefq", maxQuick=1)
    refused, queued = [], []
    with c.connect(d, "occupier", "e3a", 3) as S, c.connect(d, "asker", "e3a", 3) as B:
        B.call("open_project", path=str(gpr))
        B.call("open_program", path=exe)
        fn = B.call("functions", limit=1)["functions"][0]
        addr, name = fn["address"], fn["name"]
        warm(c, S)
        ids = [start_sleep(c, S, 40000)]
        dt.wait_for(lambda: lane_status(S, "quick")["inUse"] >= 1, "the quick slot taken", 30)
        try:
            bad = {
                "decompile with neither address nor name": ("decompile", {}),
                "rename without address": ("rename", {"name": "e3a_x"}),
                "rename without name": ("rename", {"address": addr}),
                "comment without address": ("comment", {"text": "t"}),
                "rename with a numeric rk": ("rename", {"address": addr, "name": "e3a_x", "rk": 5}),
                "comment with an empty rk": ("comment", {"address": addr, "text": "t", "rk": ""}),
                "rename with an object expect": ("rename", {"address": addr, "name": "e3a_x",
                                                            "expect": {"a": 1}}),
                "comment with a list expect": ("comment", {"address": addr, "text": "t",
                                                           "expect": ["a"]}),
            }
            for what, (cmd, f) in bad.items():
                r = bl.timed(c, B, cmd, wait=3000, **f)
                dt.check(not r["ok"] and r["code"] == "bad_request" and r["ms"] < 1500,
                         f"{what}: expected bad_request at once with the lane full: {r}")
                dt.check(lane_status(S, "quick")["queued"] == 0, f"{what}: it was queued")
                refused.append(what)
            good = {
                "decompile by address": ("decompile", {"address": addr}),
                "decompile by name": ("decompile", {"name": name}),
                "decompile with a null address and a name": ("decompile",
                                                             {"address": None, "name": name}),
                "rename with rk and expect": ("rename", {"address": addr, "name": "e3a_y",
                                                         "rk": "e3a-pre-1", "expect": name}),
                "rename with a null expect": ("rename", {"address": addr, "name": "e3a_y",
                                                         "expect": None}),
                "comment with rk and a null expect": ("comment", {"address": addr, "text": "t",
                                                                   "rk": "e3a-pre-2",
                                                                   "expect": None}),
            }
            for what, (cmd, f) in good.items():
                rid = B.send(cmd, wait=30000, **f)
                try:
                    dt.wait_for(lambda: lane_status(S, "quick")["queued"] >= 1,
                                f"{what}: queued behind the full lane (not refused)", 10)
                finally:
                    try:
                        B.call("cancel", target=rid)
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        B.wait(rid)
                    except Exception:  # noqa: BLE001
                        pass
                dt.wait_for(lambda: lane_status(S, "quick")["queued"] == 0,
                            f"{what}: the queue emptied after the cancel", 10)
                queued.append(what)
        finally:
            finish(c, S, ids)
            try:
                B.call("close_program", discard=True)
            except Exception:  # noqa: BLE001
                pass
    d.stop(force=True)
    return f"{len(refused)} bad forms refused at once, {len(queued)} valid forms queued"


# ---- per_key_cap_conserving -----------------------------------------------------------------

def t_per_key_cap_conserving(c):
    """maxQuick 4 and cap 1: keys A and B each run one request (8 s) and queue another (1 s); C and D
    fill the other two slots for 3 s. When C and D end, A's and B's queued requests run although
    their keys are at the cap: no slot idles."""
    d = c.daemon("e3a-cons", maxQuick=4, engine={"maxRunningPerKey": 1})
    with c.connect(d, "agents", "e3a", 3) as X:
        warm(c, X)
        views = {k: X.labelled(client="agent-" + k, harness="e3a") for k in "abcd"}
        ids = []
        try:
            ids.append(start_sleep(c, views["a"], 8000))
            ids.append(start_sleep(c, views["b"], 8000))
            ids.append(start_sleep(c, views["c"], 3000))
            ids.append(start_sleep(c, views["d"], 3000))
            dt.wait_for(lambda: lane_status(X, "quick")["inUse"] >= 4, "all four quick slots", 30)
            t0 = time.perf_counter()
            dt.check(lane_status(X, "quick")["perKeyCap"] == 1, "cap is 1")
            a2 = start_sleep(c, views["a"], 1000)
            b2 = start_sleep(c, views["b"], 1000)
            dt.wait_for(lambda: lane_status(X, "quick")["queued"] >= 2, "a2 and b2 queued", 10)
            # while c and d hold their slots a2 and b2 wait (their keys are at the cap, but no other
            # key waits, so only the full lane holds them)
            def both_run():
                q = lane_status(X, "quick")
                names = [w["who"] for w in q["running"]]
                return q["queued"] == 0 and q["inUse"] == 4 and \
                    sum("agent-a" in n for n in names) == 2 and \
                    sum("agent-b" in n for n in names) == 2
            dt.wait_for(both_run, "a2 and b2 to run beside a1 and b1", 12)
            t_run = time.perf_counter() - t0
            X.wait(a2)
            X.wait(b2)
            t_done = time.perf_counter() - t0
            dt.check(t_done < 7.0, f"a2 and b2 finished {t_done:.1f} s in, after a1/b1 (8 s) would "
                     f"have freed their keys: the cap held slots idle")
        finally:
            finish(c, X, ids)
    d.stop(force=True)
    return (f"a2 and b2 started {t_run:.1f} s after the lane filled (c, d end at 3 s) and finished "
            f"at {t_done:.1f} s, while a1 and b1 ran until 8 s: no idle slot")


TESTS = {
    "maint_lane": t_maint_lane,
    "fair_key": t_fair_key,
    "queue_info": t_queue_info,
    "preflight_wait": t_preflight_wait,
    "per_key_cap_conserving": t_per_key_cap_conserving,
}

BASELINE = {}
