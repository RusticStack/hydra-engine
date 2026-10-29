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
"""Characterization scenario of package E9 (PROTOCOL-3.md 3.1, 3.11), protocol 3 only: its golden is
``examples/characterization/v3/e9-limits.json``. Run with

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e9-limits

* ``e9-limits``: the names E9 adds to ``capabilities`` (``admission``) and ``limits`` (every value of the
  3.11 table that is a ``Settings`` key: ``minXmxMb``, ``maxViews``, ``maxViewsPerClient``, ``heapSoftPct``,
  ``heapHardPct``, ``nativeBudgetMb``, ``viewDiskBudget`` and ``diskReserve`` in MB, ``decompilerIdleS``,
  ``decompilerWaitS``, ``decompilerFailLimit``, ``decompilerNegativeS``), in declaration order, compared as
  required subsets like ``char_e1.py`` does (3.1: each later package asserts its own names here). Two keys
  are set (``maxViews`` 24, ``nativeBudgetMb`` 1600, which is otherwise derived from the machine's RAM), so
  the golden also shows that a setting reaches ``limits``; the rest are the defaults of 3.11. A protocol 2
  ``status`` has none of these (``cc_e9``).
"""
import copy

from characterization_tests import Fail

import char_e1 as e1

PROTOCOLS = (3,)

E9_CAPABILITIES = {"admission": 1}
E9_LIMITS = {"minXmxMb": 512, "maxViews": 24, "maxViewsPerClient": 4, "heapSoftPct": 70,
             "heapHardPct": 85, "nativeBudgetMb": 1600, "viewDiskBudget": 20 * 1024,
             "diskReserve": 5 * 1024, "decompilerIdleS": 60, "decompilerWaitS": 60,
             "decompilerFailLimit": 3, "decompilerNegativeS": 600}


def sc_limits(c, R):
    d = c.daemon("e9-limits", engine={"maxViews": 24, "nativeBudgetMb": 1600})
    a = c.connect(d, "e9-a", "e9-h")
    try:
        a.call("status")
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(a.last_response)
    if not resp.get("ok"):
        raise Fail(f"e9: status failed: {resp.get('error')}")
    res = resp["result"]
    e1.structure(res)
    cap = e1.subset("capabilities", res["capabilities"], E9_CAPABILITIES)
    lim = e1.subset("limits", res["limits"], E9_LIMITS)
    names = [k for k in res["limits"] if k in E9_LIMITS]
    if names != list(E9_LIMITS):
        raise Fail(f"e9: the limit names are not in declaration order: {names}")
    if "decompilerPermits" in res["limits"]:
        raise Fail("e9: decompilerPermits is derived, not a setting, and is not a limit")
    out = {"protocol": res["protocol"], "capabilities": cap, "limits": lim}
    R.steps.append({"step": len(R.steps) + 1, "who": "a", "cmd": "status", "request": R.m.value({}),
                    "response": R.m.value({"ok": True, "result": out}),
                    "note": "the E9 names of capabilities and limits (3.11: every value a Settings key)"})
    R.ok("a", a, "ping")
    c.stop(d)


SCENARIOS = {"e9-limits": sc_limits}
