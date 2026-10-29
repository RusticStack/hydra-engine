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
"""Protocol-2 behaviour of the E5 engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
gate G6, package E5). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e5.py --ghidra <install> --work <empty dir> --exe <small PE>

* ``v2_status_blocks_v3_unavailable`` (G6): with ``-Dghidra.session.testHooks=true`` and
  ``debug_stall`` holding the scheduler lock, a protocol 2 ``status`` blocks until the lock is free
  and answers hydra.3's ``scheduler`` object (``quick`` and ``long`` only, no ``unavailable``),
  while a protocol 3 ``status`` of the same daemon answers ``scheduler.unavailable`` within about a
  second. ``health`` answers to both (``schedulerLockOk:false``) and ``ping`` answers throughout.
* ``v2_health``: ``health`` is available to a protocol 2 client (a new command cannot change an old
  transcript): the keys of 3.4, ``state:"ok"``; a protocol 2 ``hello`` and ``status`` gain no key
  from E5 (no ``capabilities``, ``platform`` or ``testHooks``), and the unknown ``debug_stall`` is
  the hydra.3 error.
* ``hook_visible_to_v3_only``: with the hook on, a protocol 2 ``hello`` still has hydra.3's keys;
  only a protocol 3 ``hello`` says ``platform.testHooks:true``.
"""
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, wait_for

HOOKS = ["-Dghidra.session.testHooks=true"]
#: the keys of ``status.scheduler`` on hydra.3 (protocol 2), in order
V2_SCHEDULER = ["quick", "long"]
CORE = ["state", "pid", "uptimeMs", "protocol", "tick", "schedulerLockOk", "lanes", "deadlocked",
        "abandoned", "memory", "testHooks"]


def close(*sessions):
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def hooked_daemon(c, instance):
    """Starts ``instance`` with the hook through the client under test (the stock 1.0.0 client has
    no ``vmargs`` option) and returns ``(stock daemon, new daemon)`` of that one instance."""
    nd = c.new_daemon(instance, vmargs=HOOKS)
    nd.connect("cc-e5-start", "tests").close()
    return c.daemon(instance), nd


def t_v2_status_blocks_v3_unavailable(c):
    c.need_engine()
    d, nd = hooked_daemon(c, "cc-e5-g6")
    S2 = S3 = None
    try:
        S2 = d.connect("v2", "cc-e5")
        S3 = nd.connect("v3", "cc-e5")
        check(S2.hello["protocol"] == 2 and S3.hello["protocol"] == 3,
              f"protocols {S2.hello['protocol']} / {S3.hello['protocol']}")
        check(S3.hello["platform"]["testHooks"] is True, "the hook is not on")
        hold_s = 7.0
        S3.call("debug_stall", what="scheduler", ms=int(hold_s * 1000))
        t_held = time.perf_counter()
        # protocol 3: status answers, the scheduler block says it could not be read
        t = time.perf_counter()
        st3 = S3.call("status")
        took3 = time.perf_counter() - t
        check(st3["scheduler"] == {"unavailable": True, "waitedMs": 250} and took3 < 2.0,
              f"v3 status.scheduler {st3['scheduler']} after {took3:.2f} s")
        # health and ping answer for both, ping at once
        check(S2.call("ping").get("pong") is True, "v2 ping")
        h = wait_for(lambda: (lambda x: x if x["schedulerLockOk"] is False else None)(
            S2.call("health")), "health.schedulerLockOk false at protocol 2", 4, 0.2)
        check(list(h)[:len(CORE)] == CORE and h["protocol"] == 2 and h["state"] == "suspect",
              f"v2 health during the hold: {h}")
        # protocol 2: status is hydra.3's, so it waits for the lock (G6: the same held lock)
        t = time.perf_counter()
        st2 = S2.call("status")
        took2 = time.perf_counter() - t
        left = hold_s - (t - t_held)
        check(took2 >= left - 1.0,
              f"v2 status returned after {took2:.2f} s, the lock was held for {left:.2f} s more")
        check(list(st2["scheduler"]) == V2_SCHEDULER, f"v2 scheduler keys {list(st2['scheduler'])}")
        check("unavailable" not in st2["scheduler"], "a v2 status says unavailable")
        # once the lock is free, v3 gets the full object again
        st3 = S3.call("status")
        check("unavailable" not in st3["scheduler"] and "maint" in st3["scheduler"],
              f"v3 scheduler after: {list(st3['scheduler'])}")
        return (f"scheduler lock held {hold_s:.0f} s: v3 status unavailable in {took3 * 1000:.0f} ms, "
                f"v2 status blocked {took2:.1f} s and answered hydra.3's quick/long; health and "
                f"ping answered at both")
    finally:
        close(S2, S3)
        d.stop(force=True)


def t_v2_health(c):
    c.need_engine()
    d = c.daemon("cc-e5-health")
    S = None
    try:
        S = d.connect("v2", "cc-e5")
        check(S.hello["protocol"] == 2, f"protocol {S.hello['protocol']}")
        for k in ("capabilities", "limits", "policy", "paths", "platform", "analysisIdentity",
                  "testHooks"):
            check(k not in S.hello, f"a protocol 2 hello has {k!r}")
        st = S.call("status")
        check("capabilities" not in st and "platform" not in st and
              list(st["scheduler"]) == V2_SCHEDULER, f"v2 status keys {list(st)}")
        h = wait_for(lambda: (lambda x: x if x["tick"]["n"] >= 1 else None)(S.call("health")),
                     "a tick", 10)
        check(list(h)[:len(CORE)] == CORE, f"health keys {list(h)}")
        check(h["protocol"] == 2 and h["state"] == "ok" and h["schedulerLockOk"] is True and
              h["testHooks"] is False and h["tick"]["ageMs"] < 2500, f"{h}")
        try:
            S.call("debug_stall", what="scheduler", ms=1000)
        except Exception as e:  # noqa: BLE001
            check(getattr(e, "code", None) == "unknown_command", f"debug_stall: {e}")
        else:
            raise Fail("debug_stall worked without the hook")
        return "health at protocol 2: keys of 3.4, state ok; hello and status unchanged; debug_stall unknown"
    finally:
        close(S)
        d.stop(force=True)


def t_hook_visible_to_v3_only(c):
    c.need_engine()
    d, nd = hooked_daemon(c, "cc-e5-hook")
    S2 = S3 = None
    try:
        S2 = d.connect("v2", "cc-e5")
        S3 = nd.connect("v3", "cc-e5")
        for k in ("capabilities", "platform", "testHooks"):
            check(k not in S2.hello, f"a protocol 2 hello has {k!r} with the hook on")
        check(S3.hello["platform"]["testHooks"] is True, f"v3 hello platform {S3.hello['platform']}")
        h = S2.call("health")
        check(h["testHooks"] is True and h["state"] == "degraded",
              f"health with the hook (protocol 2): {h['testHooks']} / {h['state']}")
        return "with the hook on, only a protocol 3 hello says platform.testHooks; health says degraded to both"
    finally:
        close(S2, S3)
        d.stop(force=True)


TESTS = {
    "v2_status_blocks_v3_unavailable": t_v2_status_blocks_v3_unavailable,
    "v2_health": t_v2_health,
    "hook_visible_to_v3_only": t_hook_visible_to_v3_only,
}

if __name__ == "__main__":
    cc.run_file(__file__)
