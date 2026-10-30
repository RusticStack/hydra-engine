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
"""Health and watchdog (PROTOCOL-3.md 3.4 ``health``, D21, D22, package E5).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only e5_health_shape,...

* ``e5_health_shape``: ``health`` at protocol 2 and 3 has the keys of 3.4 in order, ``state:"ok"``,
  a tick that advances about once a second and is young, the three lanes with their five figures,
  ``waits`` / ``leakedWorkers`` / ``repairs`` of 3.13; ``hello`` advertises ``capabilities.health``
  and ``platform.testHooks:false``; ``debug_stall`` is an unknown command without the hook.
* ``e5_health_long_request``: ``health`` answers in well under a second, on its own connection and
  on the connection that has a request in flight, while a long script runs; the lane figures show it.
* ``e5_lane_stats``: with one long slot, a second script queues: ``inUse``, ``queued``,
  ``oldestWaitMs``, ``longestRunningMs`` and ``starving`` (``starveMs``) are right and fall back
  when the work ends.
* ``e5_hook_acceptance``: the hook cannot be enabled from ``config.json`` (the daemon refuses to
  start, saying so), from a request field or from ``hello``.
* ``e5_hook_stall``: with ``-Dghidra.session.testHooks=true``: ``hello.platform.testHooks`` and
  ``health.state:"degraded"``; ``debug_stall what:"watchdog"`` makes ``tick.ageMs`` grow past
  ``watchdogStallMs`` (``state:"suspect"``) while ``ping`` and ``health`` answer; ``what:"scheduler"``
  makes ``schedulerLockOk`` false while the tick stays young, ``ping`` answers, a new connection can
  be made and a protocol 3 ``status`` says ``scheduler.unavailable``; both end by themselves.
* ``e5_suspended_probe`` (Windows): a daemon suspended from outside (``NtSuspendProcess``) is seen
  by the Python probe ``Daemon.health()`` as a live pid with no answer; after the resume it answers.
* ``e5_abandoned``: an abandoned holder (a dead client's deaf script) is in ``health.abandoned[]``
  with program, command, running time, client and at most eight stack frames, and makes the state
  ``degraded`` until the script ends.
"""
import contextlib
import json
import os
import pathlib
import sys
import time

import daemon_tests as dt

try:
    import dt_baseline as bl
except ImportError:  # loaded by path (daemon_tests.load_dt) before dt_baseline was registered
    import importlib.util
    _p = pathlib.Path(__file__).resolve().parent / "dt_baseline.py"
    _spec = importlib.util.spec_from_file_location("dt_baseline", _p)
    bl = importlib.util.module_from_spec(_spec)
    sys.modules["dt_baseline"] = bl
    _spec.loader.exec_module(bl)

HOOKS = ["-Dghidra.session.testHooks=true"]
#: the keys of the result, in order (3.4); contributors (3.13) follow
CORE = ["state", "pid", "uptimeMs", "protocol", "tick", "schedulerLockOk", "lanes", "deadlocked",
        "abandoned", "memory", "testHooks"]
LANE_KEYS = ["inUse", "queued", "oldestWaitMs", "longestRunningMs", "starving"]
DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E5Deaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // a script that does not look at cancel and swallows the interrupt
            }
        }
        println("deaf done " + System.currentTimeMillis());
    }
}
"""


# ---- helpers --------------------------------------------------------------------------------

def close_all(*sessions):
    for s in sessions:
        with contextlib.suppress(Exception):
            if s is not None:
                s.close()


def health(s):
    """``health`` and the wall-clock seconds the answer took."""
    t = time.perf_counter()
    h = s.call("health")
    return h, time.perf_counter() - t


def check_shape(h, protocol, what):
    dt.check(list(h)[:len(CORE)] == CORE, f"{what}: keys {list(h)}")
    dt.check(h["protocol"] == protocol, f"{what}: protocol {h['protocol']}")
    dt.check(isinstance(h["pid"], int) and h["pid"] > 0 and h["uptimeMs"] >= 0, f"{what}: {h}")
    t = h["tick"]
    dt.check(list(t)[:3] == ["n", "ageMs", "lateMs"] and t["n"] >= 1 and 0 <= t["ageMs"] < 2500
             and t["lateMs"] >= 0, f"{what}: tick {t}")
    dt.check(isinstance(h["schedulerLockOk"], bool), f"{what}: schedulerLockOk")
    dt.check(list(h["lanes"]) == ["quick", "long", "maint"], f"{what}: lanes {list(h['lanes'])}")
    for n, ln in h["lanes"].items():
        dt.check(list(ln) == LANE_KEYS, f"{what}: lane {n} keys {list(ln)}")
    dt.check(h["deadlocked"] == [] and isinstance(h["abandoned"], list), f"{what}: lists")
    m = h["memory"]
    dt.check(list(m) == ["usedMb", "committedMb", "maxMb"] and m["maxMb"] >= m["usedMb"] > 0,
             f"{what}: memory {m}")
    dt.check(isinstance(h["testHooks"], bool), f"{what}: testHooks")


def tick_n(s):
    return s.call("health")["tick"]["n"]


def exe_name(c):
    return bl.prepare(c)


# ---- e5_health_shape ------------------------------------------------------------------------

def t_health_shape(c):
    d = c.daemon("e5-shape")
    s3 = s2 = None
    try:
        s3 = c.connect(d, "shape3", "e5", 3)
        s2 = c.connect(d, "shape2", "e5", 2)
        dt.check(s3.hello["protocol"] == 3 and s2.hello["protocol"] == 2, "protocols")
        dt.check(s3.hello["capabilities"].get("health") == 1,
                 f"capabilities {s3.hello['capabilities']}")
        dt.check(s3.hello["platform"].get("testHooks") is False,
                 f"hello.platform.testHooks: {s3.hello['platform']}")
        dt.check("capabilities" not in s2.hello and "platform" not in s2.hello,
                 f"a protocol 2 hello got v3 blocks: {list(s2.hello)}")
        n0 = tick_n(s3)
        took = {}
        for proto, s in ((3, s3), (2, s2)):
            h, took[proto] = health(s)
            check_shape(h, proto, f"protocol {proto}")
            dt.check(h["state"] == "ok", f"state {h['state']} on a quiet daemon: {h}")
            dt.check(h["schedulerLockOk"] is True and h["testHooks"] is False, f"{h}")
            for n, ln in h["lanes"].items():
                dt.check(ln["inUse"] == 0 and ln["queued"] == 0 and ln["starving"] is False,
                         f"lane {n} on a quiet daemon: {ln}")
            dt.check(h["pid"] == s.endpoint["pid"], f"pid {h['pid']} vs {s.endpoint['pid']}")
            # 3.13: the figures the other packages' classes contribute
            # contributors keep their registration order; other packages' contributors (H4's
            # scriptCache, which ScriptCommands registers when it loads) may come before these
            contrib = [k for k in list(h)[len(CORE):] if k in ("waits", "leakedWorkers", "leaked", "repairs")]
            dt.check(contrib == ["waits", "leakedWorkers", "leaked", "repairs"], f"contributors {list(h)}")
            fb = h["waits"]["foreignBlocked"]
            dt.check(set(fb) == {"total", "lastMinute", "shared"}, f"waits {h['waits']}")
            dt.check(h["leakedWorkers"] == 0 and h["leaked"] == [] and h["repairs"] == [],
                     f"{h}")
        # the same figures as status.waits (E3c), one source
        st = s3.call("status")
        dt.check(set(st["waits"]) == set(h["waits"]), f"status.waits {st['waits']}")
        # the tick advances about once a second
        time.sleep(3.2)
        n1 = tick_n(s3)
        dt.check(2 <= n1 - n0 <= 5, f"tick.n went {n0} -> {n1} in about 3.2 s")
        # the hook is off: debug_stall is an unknown command at both protocols
        for s in (s3, s2):
            e = dt.expect_error("unknown_command", s.call, "debug_stall", what="scheduler", ms=3000)
            dt.check("debug_stall" in str(e), f"{e}")
        h, _ = health(s3)
        dt.check(h["schedulerLockOk"] and h["state"] == "ok", f"health after debug_stall: {h}")
        return (f"keys, lanes, contributors at protocol 3 and 2 (answers in "
                f"{took[3] * 1000:.0f} / {took[2] * 1000:.0f} ms); tick {n0}->{n1} in 3.2 s; "
                f"capabilities.health 1, platform.testHooks false, debug_stall unknown")
    finally:
        close_all(s3, s2)
        d.stop(force=True)


# ---- e5_health_long_request -----------------------------------------------------------------

def t_health_long_request(c):
    exe = exe_name(c)
    gpr = c.copy_fixture("e5Long")
    d = c.daemon("e5-long")
    A = B = None
    try:
        A = c.connect(d, "runner", "e5", 3)
        B = c.connect(d, "prober", "e5", 3)
        A.call("script", script=c.script("TestSleep.java"), program=None, args=["10"],
               wait=120000)    # the script framework is up
        A.call("open_project", path=str(gpr))
        A.call("open_program", path=exe)
        # an ordinary ordered request (no "parallel"): it occupies the connection's single worker
        # queue, so a "health" that is not answered on the reader thread would wait behind it
        rid = A.send("script", script=c.script("TestSleep.java"), args=["7000"], wait=120000)
        time.sleep(3.2)   # the lane figures are the watchdog's snapshot: up to 1 s old
        seen = []
        for who, s in (("own connection", A), ("other connection", B)):
            for _ in range(3):
                h, took = health(s)
                seen.append(took)
                dt.check(took < 0.5, f"health on the {who} took {took * 1000:.0f} ms")
                check_shape(h, 3, who)
            lg = h["lanes"]["long"]
            dt.check(lg["inUse"] == 1 and lg["queued"] == 0, f"long lane: {lg}")
            dt.check(lg["longestRunningMs"] >= 1500, f"longestRunningMs {lg}")
            dt.check(h["lanes"]["quick"]["inUse"] == 0, f"quick lane: {h['lanes']['quick']}")
            dt.check(h["state"] == "ok", f"a long request is not a fault: {h['state']}")
        r = A.wait(rid)
        dt.check("end" in r["output"], f"the script: {r}")
        end = time.time() + 5   # the figures are the watchdog's snapshot: up to one tick old
        h, _ = health(B)
        while h["lanes"]["long"]["inUse"] != 0 and time.time() < end:
            time.sleep(0.3)
            h, _ = health(B)
        dt.check(h["lanes"]["long"]["inUse"] == 0, f"after the script: {h['lanes']['long']}")
        return (f"health answered in at most {max(seen) * 1000:.0f} ms (6 calls, on the connection "
                f"with the request in flight and on another) during a 7 s script; long lane "
                f"inUse 1, longestRunningMs >= 1500, state ok")
    finally:
        close_all(A, B)
        d.stop(force=True)


# ---- e5_lane_stats --------------------------------------------------------------------------

def t_lane_stats(c):
    d = c.daemon("e5-lanes", maxLong=1, engine={"starveMs": 1500})
    A = B = O = None
    try:
        A = c.connect(d, "first", "e5", 3)
        B = c.connect(d, "second", "e5", 3)
        O = c.connect(d, "observer", "e5", 3)
        # compile/warm without the long lane being busy with it later
        A.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=120000)
        a = A.send("script", script=c.script("TestSleep.java"), program=None, args=["9000"],
                   parallel=True, wait=120000)
        time.sleep(0.8)
        b = B.send("script", script=c.script("TestSleep.java"), program=None, args=["500"],
                   parallel=True, wait=120000)

        def lane():
            return O.call("health")["lanes"]["long"]

        dt.wait_for(lambda: lane()["queued"] == 1, "the second script to queue", 10)
        young = lane()
        dt.check(young["inUse"] == 1 and young["starving"] is False and young["oldestWaitMs"] < 1500,
                 f"a young queue is not starving: {young}")
        dt.wait_for(lambda: lane()["starving"], "starving after starveMs 1500", 10, 0.1)
        old = lane()
        dt.check(old["oldestWaitMs"] > 1500 and old["longestRunningMs"] >= 2000 and
                 old["inUse"] == 1 and old["queued"] == 1, f"starving lane: {old}")
        h = O.call("health")
        dt.check(h["lanes"]["quick"]["queued"] == 0 and h["lanes"]["quick"]["starving"] is False and
                 h["lanes"]["maint"]["starving"] is False, f"other lanes: {h['lanes']}")
        dt.check(h["state"] == "ok", f"a starving lane is information, not a fault: {h['state']}")
        # the same figures as status.scheduler (v3), from the scheduler's own counts
        sch = O.call("status")["scheduler"]["long"]
        dt.check(sch["inUse"] == 1 and sch["queued"] == 1 and sch["starving"] is True,
                 f"status.scheduler.long: {sch}")
        A.wait(a)
        B.wait(b)
        dt.wait_for(lambda: lane()["inUse"] == 0 and lane()["queued"] == 0, "the lane to empty", 10)
        done = lane()
        dt.check(done["starving"] is False and done["oldestWaitMs"] == 0 and
                 done["longestRunningMs"] == 0, f"after the work: {done}")
        return (f"one long slot: queued 1, starving after {old['oldestWaitMs']} ms (starveMs 1500), "
                f"longestRunningMs {old['longestRunningMs']}, state ok; the lane empties")
    finally:
        close_all(A, B, O)
        d.stop(force=True)


# ---- e5_hook_acceptance ---------------------------------------------------------------------

def t_hook_acceptance(c):
    # (a) config.json: ``engine`` entries reach the engine as -set, and testHooks as a setting is a
    #     usage error: the daemon does not start, and the message says what to do
    d = c.daemon("e5-cfg", engine={"testHooks": True})
    err = None
    try:
        d.connect("cfg", "e5", timeout=90)
    except Exception as e:  # noqa: BLE001
        err = e
    text = str(err) + json.dumps(getattr(err, "details", None) or {}, default=str)
    try:
        text += d.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    dt.check(err is not None, "a daemon started with engine.testHooks=true")
    dt.check("testHooks" in text and "launch property" in text,
             f"the refusal does not say why: {str(err)[:400]}")
    dt.check(not d.jvm_alive(), "a JVM is running after the refusal")
    # (b) a request or a hello cannot turn it on either
    d2 = c.daemon("e5-req")
    s3 = s2 = None
    try:
        s3 = c.connect(d2, "req3", "e5", 3)
        s2 = c.connect(d2, "req2", "e5", 2)
        for s in (s3, s2):
            for extra in ({"testHooks": True}, {"testHooks": "true"}, {"ghidra.session.testHooks": True},
                          {"hooks": True}):
                dt.expect_error("unknown_command", s.call, "debug_stall", **extra)
            s.call("hello", testHooks=True, client="x")      # a later hello changes nothing
            dt.expect_error("unknown_command", s.call, "debug_stall")
        dt.check(s3.call("health")["testHooks"] is False, "health.testHooks after the attempts")
        dt.check(s3.call("hello")["platform"]["testHooks"] is False, "hello.platform.testHooks")
        return ("engine.testHooks in config.json refused at start-up (usage error naming the launch "
                "property); debug_stall stays unknown after request and hello fields at both "
                "protocols; hello.platform.testHooks and health.testHooks stay false")
    finally:
        close_all(s3, s2)
        d2.stop(force=True)


# ---- e5_hook_stall --------------------------------------------------------------------------

def t_hook_stall(c):
    d = c.daemon("e5-hooks", vmargs=HOOKS, engine={"watchdogStallMs": 3000})
    s = other = None
    try:
        s = c.connect(d, "hooks", "e5", 3)
        dt.check(s.hello["platform"].get("testHooks") is True,
                 f"hello.platform.testHooks with the hook: {s.hello['platform']}")
        h, _ = health(s)
        check_shape(h, 3, "hook on")
        dt.check(h["testHooks"] is True and h["state"] == "degraded",
                 f"state with the hook on: {h['state']} / {h['testHooks']}")
        # the request is validated
        for bad in ({"what": "reader"}, {"ms": 0}, {"ms": 999999}, {"what": 5}):
            dt.expect_error("bad_request", s.call, "debug_stall", **bad)
        # (a) the watchdog stops ticking
        r = s.call("debug_stall", what="watchdog", ms=7000)
        dt.check(r.get("stalling") == "watchdog", f"{r}")
        t0 = time.perf_counter()
        grew = None
        while time.perf_counter() - t0 < 9:
            h, took = health(s)
            if h["tick"]["ageMs"] > 3200:
                grew = h
                break
            time.sleep(0.25)
        dt.check(grew is not None, "tick.ageMs did not pass watchdogStallMs during the stall")
        dt.check(grew["state"] == "suspect", f"state with an old tick: {grew['state']}")
        dt.check(grew["schedulerLockOk"] is True, "the scheduler lock was not held")
        pong = s.call("ping")
        dt.check(pong.get("pong") is True, f"ping during the stall: {pong}")
        _, took = health(s)
        dt.check(took < 0.5, f"health took {took * 1000:.0f} ms with a stalled watchdog")
        a1 = s.call("health")["tick"]["ageMs"]
        time.sleep(1.0)
        a2 = s.call("health")["tick"]["ageMs"]
        dt.check(a2 > a1, f"tick.ageMs does not grow: {a1} -> {a2}")
        # it recovers by itself, and the first tick after the stall says how late it was
        back = None
        t1 = time.perf_counter()
        while time.perf_counter() - t1 < 12:
            h = s.call("health")
            if h["tick"]["ageMs"] < 1500 and h["state"] != "suspect":
                back = h
                break
            time.sleep(0.1)
        dt.check(back is not None, "the watchdog did not tick again after the stall")
        dt.check(back["tick"]["lateMs"] >= 2500, f"lateMs after the stall: {back['tick']}")
        dt.check(back["state"] == "degraded", f"state after the stall: {back['state']}")
        # (b) the scheduler lock is held
        r = s.call("debug_stall", what="scheduler", ms=5000)
        t_held = time.perf_counter()
        dt.check(r.get("stalling") == "scheduler", f"{r}")
        locked = None
        while time.perf_counter() - t_held < 4:
            h = s.call("health")
            if h["schedulerLockOk"] is False:
                locked = h
                break
            time.sleep(0.2)
        dt.check(locked is not None, "schedulerLockOk never became false")
        dt.check(locked["state"] == "suspect", f"state with a held scheduler lock: {locked['state']}")
        dt.check(locked["tick"]["ageMs"] < 2500, f"the watchdog should keep ticking: {locked['tick']}")
        dt.check(list(locked["lanes"]) == ["quick", "long", "maint"], "lanes lost while held")
        dt.check(s.call("ping").get("pong") is True, "ping while the scheduler lock is held")
        # a new connection can be made while the lock is held, and asks health
        other = c.connect(d, "newcomer", "e5", 3)
        h, took = health(other)
        dt.check(took < 1.0 and h["schedulerLockOk"] is False, f"new connection's health: {h}")
        # v3 status does not hang on it (G6); the scheduler block says so
        t = time.perf_counter()
        st = s.call("status")
        took = time.perf_counter() - t
        dt.check(st["scheduler"] == {"unavailable": True, "waitedMs": 250} and took < 2.0,
                 f"status.scheduler while held: {st['scheduler']} in {took:.2f} s")
        left = 5.0 - (time.perf_counter() - t_held)
        time.sleep(max(0, left) + 1.8)
        h = s.call("health")
        dt.check(h["schedulerLockOk"] is True and h["state"] == "degraded",
                 f"after the hold ended: {h['schedulerLockOk']} / {h['state']}")
        st = s.call("status")
        dt.check("unavailable" not in st["scheduler"] and "quick" in st["scheduler"],
                 f"status.scheduler after: {list(st['scheduler'])}")
        return (f"hook on: platform.testHooks true, state degraded; watchdog stall: ageMs "
                f"{grew['tick']['ageMs']} -> state suspect, ping and health answered, recovered "
                f"with lateMs {back['tick']['lateMs']}; scheduler stall: schedulerLockOk false in "
                f"{time.perf_counter() - t_held:.1f} s of the hold, tick young, new connection and "
                f"v3 status ({took * 1000:.0f} ms) answered, free again")
    finally:
        close_all(s, other)
        d.stop(force=True)


# ---- e5_suspended_probe ---------------------------------------------------------------------

def t_suspended_probe(c):
    if os.name != "nt":
        return "skipped: Windows only (NtSuspendProcess)"
    try:
        import chaos_lib
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "chaos_lib", pathlib.Path(__file__).resolve().parent / "chaos_lib.py")
        chaos_lib = importlib.util.module_from_spec(spec)
        sys.modules["chaos_lib"] = chaos_lib
        spec.loader.exec_module(chaos_lib)
    d = c.daemon("e5-suspend")
    pid = None
    try:
        s = c.connect(d, "susp", "e5", 3)
        pid = s.endpoint["pid"]
        s.close()
        base = d.health(deadline=10)
        dt.check(base["alive"] and base["answers"] and base["source"] == "health" and
                 base["pid"] == pid and base["engine"]["state"] == "ok" and
                 base["engine"]["pid"] == pid, f"the probe on a healthy daemon: {base}")
        n_before = base["engine"]["tick"]["n"]
        dt.check(chaos_lib.suspend(pid), f"could not suspend pid {pid}")
        try:
            t = time.perf_counter()
            h = d.health(deadline=3)
            took = time.perf_counter() - t
            dt.check(h["alive"] is True and h["pid"] == pid and h["answers"] is False and
                     h["source"] is None and h.get("reason"), f"a suspended daemon: {h}")
            dt.check(took < 12, f"the probe took {took:.1f} s with deadline 3")
            time.sleep(2.0)
        finally:
            dt.check(chaos_lib.resume(pid), f"could not resume pid {pid}")
        after = d.health(deadline=15)
        dt.check(after["answers"] and after["source"] == "health" and after["pid"] == pid,
                 f"after the resume: {after}")
        end = time.time() + 10   # the reply can come before the watchdog's first tick after the resume
        while after["engine"]["tick"]["n"] <= n_before and time.time() < end:
            time.sleep(0.5)
            after = d.health(deadline=15)
        dt.check(after["engine"]["tick"]["n"] > n_before,
                 f"the watchdog did not tick again after the resume: {after}")
        return (f"suspended pid {pid}: Daemon.health(deadline=3) = alive, pid, answers false in "
                f"{took:.1f} s ({h['reason']}); after the resume it answers via health "
                f"(tick {n_before} -> {after['engine']['tick']['n']})")
    finally:
        if pid:
            with contextlib.suppress(Exception):
                chaos_lib.resume(pid)
        d.stop(force=True)


# ---- e5_abandoned ---------------------------------------------------------------------------

def t_abandoned(c):
    exe = bl.prepare(c)
    (c.scripts / "E5Deaf.java").write_text(DEAF)
    gpr = c.copy_fixture("e5Ab")
    d = c.daemon("e5-ab", engine={"cleanupGraceS": 2, "abandonWaitS": 2})
    deaf_ms = 14000
    H = O = None
    try:
        H = c.connect(d, "doomed", "e5", 3)
        for n in ("TestSleep.java", "E5Deaf.java"):
            H.call("script", script=c.script(n), program=None, args=["10"], wait=120000)
        H.call("open_project", path=str(gpr), writable=True)
        H.call("open_program", path=exe, writable=True)
        O = c.connect(d, "observer", "e5", 3)
        O.call("open_project", path=str(gpr))
        O.call("open_program", path=exe)
        before = O.call("health")
        dt.check(before["abandoned"] == [] and before["state"] == "ok", f"before: {before}")

        def holds():
            return any(p["path"] == "/" + exe and p["busy"] for p in O.call("status")["programs"])

        H.send("script", script=c.script("E5Deaf.java"), args=[str(deaf_ms)], parallel=True,
               wait=120000)
        dt.wait_for(holds, "the deaf script to hold the program", 30)
        H.close()
        h = dt.wait_for(lambda: (lambda x: x if x["abandoned"] else None)(O.call("health")),
                        "health.abandoned", 20, 0.25)
        ab = h["abandoned"]
        dt.check(len(ab) == 1, f"abandoned: {ab}")
        a = ab[0]
        dt.check(set(a) >= {"program", "cmd", "runningMs", "client", "stack"}, f"entry keys {list(a)}")
        dt.check(a["program"].endswith(":/" + exe), f"program {a['program']}")
        dt.check("script" in a["cmd"] and a["runningMs"] >= 1000, f"cmd / runningMs {a}")
        dt.check(a["client"].endswith("(gone)") and "doomed" in a["client"], f"client {a['client']}")
        dt.check(isinstance(a["stack"], list) and len(a["stack"]) <= 8 and
                 all(isinstance(f, str) for f in a["stack"]), f"stack {a['stack']}")
        if a["stack"]:
            dt.check(any("E5Deaf" in f or "sleep" in f.lower() for f in a["stack"]),
                     f"the stack does not show the script: {a['stack']}")
        else:
            dt.check(bool(a.get("stackNote")), f"no stack and no note: {a}")
        dt.check(h["state"] == "degraded", f"state with an abandoned holder: {h['state']}")
        dt.check(O.call("ping").get("pong") is True, "ping")
        # it ends by itself, and the state returns to ok
        gone = dt.wait_for(lambda: (lambda x: x if not x["abandoned"] else None)(O.call("health")),
                           "the abandoned entry to clear", deaf_ms / 1000 + 20, 0.5)
        dt.check(gone["state"] == "ok", f"state after: {gone['state']}")
        return (f"abandoned[0] = {a['program']} '{a['cmd']}' running {a['runningMs']} ms, client "
                f"'{a['client']}', {len(a['stack'])} frames{' (' + a['stackNote'] + ')' if not a['stack'] else ''}"
                f"; state degraded, then ok when the script ended")
    finally:
        close_all(H, O)
        d.stop(force=True)


TESTS = {
    "e5_health_shape": t_health_shape,
    "e5_health_long_request": t_health_long_request,
    "e5_lane_stats": t_lane_stats,
    "e5_hook_acceptance": t_hook_acceptance,
    "e5_hook_stall": t_hook_stall,
    "e5_suspended_probe": t_suspended_probe,
    "e5_abandoned": t_abandoned,
}

BASELINE = {}
