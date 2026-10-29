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
"""Characterization scenario of package E4 (PROTOCOL-3.md 3.4 and 3.6), protocol 3 only: its golden is
``examples/characterization/v3/e4-script.json``. Run with

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e4-script

* ``e4-script``: the protocol 3 reply of ``script`` in each isolation (``shared``, ``exclusive``,
  ``private`` and the default), with a mutating script (``attemptedChanges`` measured before the
  rollback, ``changed`` false, ``basedOn``, ``unsavedIgnored``), a script with no program
  (``isolation:"none"``), the lane hint and its note copied from the monitor, a pinned script
  (``scriptSha256``), the refusals ``bad_request`` (``details.field`` and ``allowed[]``) and
  ``script_changed`` (``expected``, ``actual``, ``script``). The protocol 2 reply is pinned by the
  unchanged v2 goldens of ``characterization_tests.py``.
"""
import hashlib

import characterization_tests as ct
from characterization_tests import Fail

PROTOCOLS = (3,)

PINNED = "\n".join([
    "// @category HeadlessSession.Characterization",
    "import ghidra.app.script.GhidraScript;",
    "public class E4Pinned extends GhidraScript {",
    "    @Override protected void run() throws Exception {",
    '        println("pinned");',
    "    }",
    "}",
    ""]).encode("ascii")


def sc_script(c, R):
    d = c.daemon("e4-script")
    a = c.connect(d, "e4-a", "e4-h")
    gpr = c.make_project(a, c.work / "e4", "E4")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "import", file=str(c.bin / "alpha.exe"), analyze=True, timeout=600, wait=300000,
         language="x86:LE:64:default", compiler="windows")
    R.ok("a", a, "close_project", discard=True)
    b = c.connect(d, "e4-b", "e4-h")
    R.ok("b", b, "open_project", path=str(gpr))
    R.ok("b", b, "open_program", path="/alpha.exe")
    write = c.script("CharWrite.java")
    pr = c.script("CharPrint.java")
    # the pinned script is written byte for byte, so that its digest is the same on every platform
    pinned = c.scripts / "E4Pinned.java"
    pinned.write_bytes(PINNED)
    sha = hashlib.sha256(PINNED).hexdigest()
    for mode in ("shared", "exclusive", "private"):
        r = R.ok("b", b, "script", script=write, isolation=mode,
                 note=f"a mutating script, {mode}: attempted, rolled back, changed false")
        if (r["isolation"] != mode or r["attemptedChanges"] is not True or
                r["changed"] is not False or r["lane"] != "long"):
            raise Fail(f"e4: {mode} reply {r}")
    r = R.ok("b", b, "script", script=write, note="no isolation: shared, as the default")
    if r["isolation"] != "shared" or r["attemptedChanges"] is not True:
        raise Fail(f"e4: default reply {r}")
    r = R.ok("b", b, "script", script=pr, isolation="private",
             note="a read-only script attempts nothing")
    if r["attemptedChanges"] is not False or r["attemptedChangesCount"] != 0:
        raise Fail(f"e4: read-only reply {r}")
    r = R.ok("b", b, "script", script=pr, program=None, note="no program: isolation none")
    if r["isolation"] != "none" or "basedOn" in r:
        raise Fail(f"e4: no-program reply {r}")
    r = R.ok("b", b, "script", script=pr, lane="quick", timeout=30,
             note="the lane decision of the monitor, copied")
    if r["lane"] != "quick" or "laneNote" in r:
        raise Fail(f"e4: quick lane reply {r}")
    r = R.ok("b", b, "script", script=pr, lane="quick",
             note="a lane hint that is not honoured: long, with laneNote")
    if r["lane"] != "long" or not r.get("laneNote"):
        raise Fail(f"e4: laneNote reply {r}")
    R.ok("b", b, "script", script=str(pinned), scriptSha256=sha, note="pinned: the digest matches")
    err = R.err("b", b, "script", "script_changed", script=str(pinned), scriptSha256="0" * 64,
                note="pinned: the file is not the one the request named")
    if err["details"].get("actual") != sha or err["details"].get("expected") != "0" * 64:
        raise Fail(f"e4: script_changed details {err['details']}")
    err = R.err("b", b, "script", "bad_request", script=pr, isolation="bogus",
                note="a closed field: details.field and allowed[]")
    if err["details"] != {"field": "isolation", "allowed": ["shared", "exclusive", "private", "worker"]}:
        raise Fail(f"e4: bad_request details {err['details']}")
    R.err("b", b, "script", "bad_request", script=pr, scriptSha256="xyz")
    c.stop(d)


SCENARIOS = {"e4-script": sc_script}
