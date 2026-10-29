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
"""Protocol-2 behaviour of the E4 engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
gate G7, package E4). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e4.py --ghidra <install> --work <empty dir> --exe <small PE>

None of these is a declared v2-visible change: a protocol 2 client sees ``script`` exactly as on
hydra.3.

* ``v2_script_fields_ignored`` (G7): a v2 ``script`` that carries ``isolation`` (any value, also
  one that protocol 3 refuses), ``lane``, a wrong ``scriptSha256`` and ``attemptedChanges`` runs as
  today: contained and shared (a mutating script's write is visible to another reader while it
  runs), no ``script_changed``, no ``bad_request``, and the reply has hydra.3's keys and none of
  ``isolation``, ``lane``, ``laneNote``, ``attemptedChanges``, ``attemptedChangesCount``,
  ``basedOn``, ``unsavedIgnored``.
* ``v2_overlay_script``: the same for a script on an overlay.
* ``v2_no_runaway_bounds``: ``scriptMaxS`` does not reach a protocol 2 script (it runs past it).
"""
import json
import pathlib
import threading
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, wait_for

#: the keys of a ``script`` reply on hydra.3 (ScriptCommands.runScript), in order
V2_KEYS = ["script", "mode", "program", "seconds", "chars", "truncated", "output", "changed",
           "unsaved", "artifact"]
V3_ONLY = ["isolation", "lane", "laneNote", "attemptedChanges", "attemptedChangesCount",
           "basedOn", "unsavedIgnored", "cancelReason"]
TRANSIENT = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
public class E4Transient extends GhidraScript {
    @Override protected void run() throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctions(true).next();
        f.setName("e4_cc_transient", SourceType.USER_DEFINED);
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("done");
    }
}
"""


def prepare(c):
    (c.scripts / "E4Transient.java").write_text(TRANSIENT)
    return pathlib.Path(c.a.exe).name


def reader(c, d, gpr, exe, name):
    s = d.connect(name, "cc-e4")
    s.call("open_project", path=str(gpr))
    s.call("open_program", path=exe)
    return s


def close(*sessions):
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def t_v2_script_fields_ignored(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE4Fields")
    d = c.daemon("cc-e4-fields")
    X = Y = None
    try:
        X = reader(c, d, gpr, exe, "runner")
        Y = reader(c, d, gpr, exe, "reader")
        X.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=120000)
        X.call("script", script=c.script("E4Transient.java"), args=["10"])    # compile it once
        plain = X.call("script", script=c.script("TestSleep.java"), args=["10"], program=None)
        check(list(plain) == V2_KEYS, f"the reply keys of a v2 script: {list(plain)}")
        # the v3 fields of any value are ignored, not validated, not honoured
        for extra in ({"isolation": "private"}, {"isolation": "bogus"}, {"isolation": 7},
                      {"lane": "quick", "timeout": 30}, {"lane": "fast"},
                      {"scriptSha256": "0" * 64}, {"scriptSha256": "not a digest"},
                      {"isolation": "private", "lane": "quick", "timeout": 30,
                       "scriptSha256": "0" * 64}):
            r = X.call("script", script=c.script("TestSleep.java"), args=["10"], **extra)
            check(list(r) == V2_KEYS, f"{extra}: reply keys {list(r)}")
            check(not set(r) & set(V3_ONLY), f"{extra}: v3 keys in a v2 reply: {list(r)}")
            check(r["mode"] == "contained", f"{extra}: mode {r['mode']}")
        # isolation:"private" is NOT honoured: the script still runs on the shared program, and a
        # reader sees its uncommitted write (the measured limit, 3.6)
        seen = []
        stop = threading.Event()

        def poll():
            while not stop.is_set():
                try:
                    r = Y.call("functions", contains="e4_cc_transient", limit=3, wait=2000)
                    seen.append(bool(r["functions"]))
                except Exception:  # noqa: BLE001
                    seen.append(None)
                time.sleep(0.05)

        th = threading.Thread(target=poll, daemon=True)
        th.start()
        try:
            r = X.call("script", script=c.script("E4Transient.java"), args=["3000"],
                       isolation="private", wait=60000)
        finally:
            stop.set()
            th.join(10)
        check(list(r) == V2_KEYS and r["changed"] is False, f"the transient run: {r}")
        check(any(x is True for x in seen),
              f"a protocol 2 script with isolation:private was isolated ({len(seen)} polls)")
        check(not Y.call("functions", contains="e4_cc_transient")["functions"],
              "the rename survived the rollback")
        return (f"isolation/lane/scriptSha256 of any value are ignored on protocol 2: reply keys "
                f"{len(V2_KEYS)} as on hydra.3; the shared write was visible in "
                f"{sum(1 for x in seen if x)} of {len(seen)} polls")
    finally:
        close(X, Y)
        d.stop(force=True)


def t_v2_overlay_script(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE4Overlay")
    d = c.daemon("cc-e4-overlay")
    X = None
    try:
        X = reader(c, d, gpr, exe, "runner")
        X.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=120000)
        X.call("open_program", path=exe, overlay="o")
        r = X.call("script", script=c.script("E4Transient.java"), args=["10"], overlay="o",
                   isolation="private", scriptSha256="0" * 64)
        keys = [k for k in r if k != "overlay"]
        check(keys == V2_KEYS and not set(r) & set(V3_ONLY), f"overlay script reply keys {list(r)}")
        check(r["mode"] == "contained" and "overlay" in r, f"overlay script: {r}")
        return "a v2 script on an overlay has hydra.3's reply keys (and the overlay descriptor)"
    finally:
        close(X)
        d.stop(force=True)


def t_v2_no_runaway_bounds(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE4Bounds")
    # the stock 1.0.0 client has no ``engine`` option: the client under test starts the daemon
    c.new_daemon("cc-e4-bounds", engine={"scriptMaxS": 2}).connect("cc-e4-start", "tests").close()
    d = c.daemon("cc-e4-bounds")
    X = None
    try:
        X = reader(c, d, gpr, exe, "runner")
        t = time.perf_counter()
        r = X.call("script", script=c.script("TestSleep.java"), program=None, args=["4500"],
                   wait=120000)
        s = time.perf_counter() - t
        check(s > 4.0 and "end" in r["output"], f"a v2 script ended after {s:.1f} s: {r['output']}")
        return f"a protocol 2 script ran {s:.1f} s with scriptMaxS 2: the bound is protocol 3 only"
    finally:
        close(X)
        d.stop(force=True)


TESTS = {
    "v2_script_fields_ignored": t_v2_script_fields_ignored,
    "v2_overlay_script": t_v2_overlay_script,
    "v2_no_runaway_bounds": t_v2_no_runaway_bounds,
}

if __name__ == "__main__":
    cc.run_file(__file__)
