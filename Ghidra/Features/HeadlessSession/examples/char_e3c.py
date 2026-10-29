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
"""Characterization scenarios of package E3c (PROTOCOL-3.md 3.9, 3.13, D49), protocol 3 only: their
goldens are ``examples/characterization/v3/e3c-<scenario>.json``. Run with

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e3c-waits,e3c-analyzing

* ``e3c-waits``: the ``waits`` block and the ``projectStates`` of a v3 ``status`` of a fresh daemon with
  one project open (every counter 0, the p99 null, one slot ``open``); a protocol 2 ``status`` has
  neither (asserted by ``cc_e3c`` ``v2_no_new_keys``).
* ``e3c-analyzing``: the shape of the ``busy`` a protocol 3 reader gets while ``analyze`` holds the
  program: ``details.reason`` ``analyzing``, the job, its progress and ``etaMs``, ``retryAfterMs`` on
  the error. The values that depend on timing are recorded as types.
"""
import copy
import time

import characterization_tests as ct
from characterization_tests import Fail

PROTOCOLS = (3,)


def _status(R, s):
    try:
        s.call("status")
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(s.last_response)
    if not resp.get("ok"):
        raise Fail(f"e3c: status failed: {resp.get('error')}")
    return resp["result"]


def sc_waits(c, R):
    d = c.daemon("e3c-waits")
    a = c.connect(d, "e3c-a", "e3c-h")
    gpr = c.copy_fixture("e3c-waits")
    R.ok("a", a, "open_project", path=str(gpr), note="one project open")
    res = _status(R, a)
    w = res.get("waits")
    ps = res.get("projectStates")
    if w is None or ps is None:
        raise Fail(f"e3c: a v3 status lacks waits/projectStates: {list(res)}")
    fb = w["foreignBlocked"]
    if fb["total"] != 0 or fb["lastMinute"] != 0 or fb["shared"] != 0:
        raise Fail(f"e3c: a fresh daemon counts foreign waits: {w}")
    if len(ps) != 1 or ps[0]["state"] != "open":
        raise Fail(f"e3c: project states {ps}")
    out = {"waits": w, "projectStates": [{"state": x["state"], "project": x["project"]} for x in ps]}
    step = {"step": len(R.steps) + 1, "who": "a", "cmd": "status", "request": R.m.value({}),
            "response": R.m.value({"ok": True, "result": out}),
            "note": "the deterministic evidence of D49 and the project state machine of D57"}
    R.steps.append(step)
    c.stop(d)


def sc_analyzing(c, R):
    d = c.daemon("e3c-analyzing")
    o = c.connect(d, "e3c-owner", "e3c-h")
    r = c.connect(d, "e3c-reader", "e3c-h")
    gpr = c.copy_fixture("e3c-analyzing")
    o.call("open_project", path=str(gpr), writable=True)
    prog = "/alpha.exe"
    o.call("open_program", path=prog, writable=True)
    r.call("open_project", path=str(gpr))
    aid = o.send("analyze", wait=120000, parallel=True)
    end = time.time() + 30
    seen = None
    while time.time() < end:
        try:
            r.call("open_program", path=prog, wait=3000)
            time.sleep(0.05)
        except R.gs.SessionError as e:
            if e.details and e.details.get("reason") == "analyzing":
                seen = (e, copy.deepcopy(r.last_response))
                break
            raise
    try:
        o.wait(aid)
    except R.gs.SessionError:
        pass
    if seen is None:
        raise Fail("e3c: the analysis was too short to meet a reader")
    e, resp = seen
    det = resp["error"]["details"]
    job = det.get("job") or {}
    prog_d = det.get("progress") or {}
    shape = {"code": resp["error"]["code"], "reason": det["reason"], "wanted": det["wanted"],
             "detailKeys": sorted(det), "job": {"cmd": job.get("cmd"), "keys": sorted(job)},
             "progressKeys": sorted(prog_d), "etaMs": "int" if isinstance(det.get("etaMs"), int)
             else ("null" if det.get("etaMs") is None else "other"),
             "retryAfterMs": "int" if isinstance(resp["error"].get("retryAfterMs"), int) else None,
             "suggest": det.get("suggest")}
    step = {"step": len(R.steps) + 1, "who": "reader", "cmd": "open_program", "request": R.m.value({}),
            "response": R.m.value({"ok": False, "error": shape}),
            "note": "busy behind an analysis: at once, with the job and its progress"}
    R.steps.append(step)
    c.stop(d)


SCENARIOS = {"e3c-waits": sc_waits, "e3c-analyzing": sc_analyzing}
