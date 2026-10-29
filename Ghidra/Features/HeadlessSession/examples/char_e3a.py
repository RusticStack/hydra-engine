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
"""Characterization scenarios of package E3a (PROTOCOL-3.md 3.1 and 3.5, section 8), protocol 3 only:
their goldens are ``examples/characterization/v3/e3a-<scenario>.json``. Run with

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e3a-lanes,e3a-busy

* ``e3a-lanes``: the v3 ``status.scheduler`` of an idle daemon (the ``maint`` lane, the v3 figures
  of C2: ``oldestWaitMs``, ``longestRunningMs``, ``starving``, ``perKeyCap``, ``perKey``) and the
  names E3a adds to ``capabilities`` (``laneHint``, ``maintLane``, ``queueInfo``) and ``limits``
  (``maxMaint``, ``quickScriptMaxS``, ``maxRunningPerKey``), compared as required subsets like
  ``char_e1.py`` does; the slot counts are masked by ``characterization_tests.py`` (D62).
* ``e3a-busy``: the shape of a v3 ``busy`` on a full long lane: ``details.reason``, ``details.queue``
  (position 1, ahead 0 for the first waiter, a null estimate without history, ``estimate:true``) and ``error.retryAfterMs``
  (1000 without history); a request that waited 250 ms or more answers with a top-level ``queue``
  and ``waited``; the status entry of a waiting request carries ``position`` and ``queue``.
"""
import copy

import characterization_tests as ct
from characterization_tests import Fail

import char_e1 as e1

PROTOCOLS = (3,)

E3A_CAPABILITIES = {"laneHint": 1, "maintLane": 1, "queueInfo": 1}
E3A_LIMITS = {"maxQuick": 4, "maxLong": 2, "maxMaint": 3, "quickScriptMaxS": 60,
              "maxRunningPerKey": {"quick": 2, "long": 1, "maint": 1}}


def status_step(R, who, s):
    """Sends ``status`` and records the scheduler block and the E3a names of the advertised blocks."""
    try:
        s.call("status")
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(s.last_response)
    if not resp.get("ok"):
        raise Fail(f"e3a: status failed: {resp.get('error')}")
    res = resp["result"]
    e1.structure(res)
    cap = e1.subset("capabilities", res["capabilities"], E3A_CAPABILITIES)
    lim = e1.subset("limits", res["limits"], E3A_LIMITS)
    sch = res["scheduler"]
    if list(sch) != ["quick", "long", "maint"]:
        raise Fail(f"e3a: the v3 scheduler has lanes {list(sch)}")
    if sch["maint"]["slots"] != 3 or sch["long"]["slots"] != 2:
        raise Fail(f"e3a: slots {sch['maint']['slots']} / {sch['long']['slots']}")
    out = {"protocol": res["protocol"], "capabilities": cap, "limits": lim, "scheduler": sch}
    step = {"step": len(R.steps) + 1, "who": who, "cmd": "status", "request": R.m.value({}),
            "response": R.m.value({"ok": True, "result": out})}
    R.steps.append(step)


def scheduler_step(R, who, s, note=None):
    """Sends ``status`` and records the scheduler block alone (the rest of a v3 status is machine
    facts that ``char_e1.py`` already pins)."""
    try:
        s.call("status")
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(s.last_response)
    if not resp.get("ok"):
        raise Fail(f"e3a: status failed: {resp.get('error')}")
    out = {"scheduler": resp["result"]["scheduler"]}
    step = {"step": len(R.steps) + 1, "who": who, "cmd": "status", "request": R.m.value({}),
            "response": R.m.value({"ok": True, "result": out})}
    if note:
        step["note"] = note
    R.steps.append(step)
    return out["scheduler"]


def sc_lanes(c, R):
    d = c.daemon("e3a-lanes", maxQuick=4, maxLong=2, engine={"maintSlots": 3})
    a = c.connect(d, "e3a-a", "e3a-h")
    status_step(R, "a", a)
    R.ok("a", a, "ping")
    c.stop(d)


def sc_busy(c, R):
    d = c.daemon("e3a-busy", maxQuick=4, maxLong=1)
    a = c.connect(d, "e3a-a", "e3a-h")
    b = c.connect(d, "e3a-b", "e3a-h")
    sid = a.send("script", script=c.script("CharSleep.java"), args=["1800"], program=None,
                 parallel=True)
    ct_wait_inuse(a)
    err = R.err("b", b, "script", "busy", script="CharPrint.java", program=None, wait=300,
                note="the long lane is full: busy with reason, queue and retryAfterMs")
    d_ = err["details"]
    if (d_.get("reason") != "slot_wait" or d_["queue"]["lane"] != "long" or
            d_["queue"]["position"] != 1 or d_["queue"]["ahead"] != 0 or
            d_["queue"]["estimatedWaitMs"] is not None or d_["queue"]["estimate"] is not True):
        raise Fail(f"e3a: busy details {d_}")
    if b.last_response["error"].get("retryAfterMs") != 1000:
        raise Fail(f"e3a: retryAfterMs {b.last_response['error']}")
    rid = b.send("script", script="CharPrint.java", program=None, wait=20000)
    ct_wait_queued(a)
    sch = scheduler_step(R, "a", a,
                         note="a waiting request: position, ahead, and the per-key figures")
    w = sch["long"]["waiting"]
    if (len(w) != 1 or w[0]["position"] != 1 or w[0]["estimatedWaitMs"] is not None or
            sch["long"]["perKey"][1]["queued"] != 1 or sch["long"]["starving"] is not False):
        raise Fail(f"e3a: the waiting entry of the status: {sch['long']}")
    R.later("a", a, "script", sid, script="CharSleep.java", args=["1800"], program=None)
    R.later("b", b, "script", rid, script="CharPrint.java", program=None, wait=20000,
            note="it waited 250 ms or more: the reply names the queue and the time")
    r = b.last_response
    if "queue" not in r or "waited" not in r or r["waited"]["slotMs"] < 250:
        raise Fail(f"e3a: a waited request has no queue/waited: {list(r)}")
    c.stop(d)


def ct_wait_inuse(s):
    import time
    end = time.time() + 30
    while time.time() < end:
        if s.call("status")["scheduler"]["long"]["inUse"] >= 1:
            return
        time.sleep(0.05)
    raise Fail("e3a: the long slot was not taken")


def ct_wait_queued(s):
    import time
    end = time.time() + 30
    while time.time() < end:
        if s.call("status")["scheduler"]["long"]["queued"] >= 1:
            return
        time.sleep(0.05)
    raise Fail("e3a: the request did not queue")


SCENARIOS = {"e3a-lanes": sc_lanes, "e3a-busy": sc_busy}
