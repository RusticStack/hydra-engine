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
"""The full protocol 3 hello golden of the hydra.4 release (PROTOCOL-3.md 3.1 and 9.3, package R1).

    HYDRA_RELEASE_GOLDEN=1 python characterization_tests.py --ghidra <install> --work <dir> \
        --protocol 3 --require-v3 --only r1-hello [--record]

``r1-hello`` records the v3 ``hello`` and ``status`` of an engine that has every package of the release
enabled, and fails LOUDLY (it never skips, never passes) when it does not: every capability, limit and policy
name that ``Advertised.java`` declares must be present in the reply. The packages that enable their own names
(E5 ``health``, the governor and budgets of E9, the script worker of E7) land after R1's start, so this check is
run by the integration check (VF) on the finished integration branch; before that it fails with the list of
absent names, which is the information the coordinator needs.

The scenario is registered only when ``HYDRA_RELEASE_GOLDEN=1``: a golden that cannot exist before the last
package landed must not make every other package's characterization run fail with "no golden file". Without the
variable this module contributes no scenario, and ``--only r1-hello`` is an unknown scenario (an error, not a pass).

Masked, as in ``char_e1.py``: ``paths``, ``platform`` and ``analysisIdentity`` (machine facts, hashes, build
date), and ``launch`` (how this daemon happened to start). Limits whose value depends on the machine or the configuration are recorded as ``"<config>"``; the three
that the daemon is started with are recorded with their values. Everything else is recorded as the engine says it.
"""
import copy
import os
import pathlib
import re

import characterization_tests as ct
from characterization_tests import Fail

PROTOCOLS = (3,)
PINNED_LIMITS = {"maxQuick": 4, "maxLong": 2, "maxImports": 2}
ADVERTISED = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main" / "java" / "ghidra" /
              "app" / "util" / "headless" / "session" / "Advertised.java")


def declared():
    """The names ``Advertised.java`` declares: {"CAPABILITIES": [...], "LIMITS": [...], "POLICY": [...]}."""
    text = ADVERTISED.read_text(encoding="utf-8")
    out = {}
    for kind in ("CAPABILITIES", "LIMITS", "POLICY"):
        m = re.search(r"static final List<String> %s = List\.of\((.*?)\);" % kind, text, re.S)
        if not m:
            raise Fail(f"r1: cannot read the declared {kind} from {ADVERTISED}")
        out[kind] = re.findall(r'"([^"]+)"', m.group(1))
        if not out[kind]:
            raise Fail(f"r1: no declared {kind} in {ADVERTISED}")
    return out


def complete(res):
    """Fails (loudly) unless every declared name is in the reply, and says which are absent."""
    want = declared()
    absent = []
    for kind, key in (("CAPABILITIES", "capabilities"), ("LIMITS", "limits"), ("POLICY", "policy")):
        have = res.get(key) or {}
        absent += [f"{key}.{n}" for n in want[kind] if n not in have]
    if absent:
        raise Fail("r1: *** NOT COMPLETE *** NOT VERIFIED: this engine does not advertise "
                   + ", ".join(absent) + " (a package of the release is missing; run this on the finished "
                   "integration branch, VF); nothing was recorded")


def hello(R, who, s, cmd, **f):
    if cmd == "hello":
        f = {**f, "protocol": 3}
    try:
        s.call(cmd, **f)
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(s.last_response)
    if not resp.get("ok"):
        raise Fail(f"r1: {cmd} failed: {resp.get('error')}")
    res = resp["result"]
    if res["protocol"] != 3:
        raise Fail(f"r1: {cmd} was answered protocol {res['protocol']}")
    complete(res)
    for k, v in list(res["limits"].items()):
        if k not in PINNED_LIMITS:
            res["limits"][k] = "<config>"
        elif v != PINNED_LIMITS[k]:
            raise Fail(f"r1: limits.{k} should be {PINNED_LIMITS[k]}, is {v!r}")
    if "launch" in res:  # how this daemon happened to start (class cache hit, AOT): not part of the contract
        res["launch"] = "<masked>"
    for k in ("paths", "platform", "analysisIdentity"):
        if k not in res:
            raise Fail(f"r1: {cmd} has no {k} block")
        res[k] = "<masked>"
    R.steps.append({"step": len(R.steps) + 1, "who": who, "cmd": cmd, "request": R.m.value(f),
                    "response": R.m.value(resp)})
    return res


def sc_hello(c, R):
    d = c.daemon("r1-hello", maxQuick=4, maxLong=2, maxImports=2)
    a = c.connect(d, "r1-a", "r1-h")
    hello(R, "a", a, "hello", client="r1-a", harness="r1-h", clientVersion="9.9.9")
    hello(R, "a", a, "status")
    c.stop(d)


SCENARIOS = {"r1-hello": sc_hello} if os.environ.get("HYDRA_RELEASE_GOLDEN") == "1" else {}
