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
"""Protocol-2 behaviour of the E9 engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
3.11, package E9). Standard library only; Windows for the decompiler part. Loaded by
``client_compat_tests.py``, or alone:

    python cc_e9.py --ghidra <install> --work <empty dir> --exe <small PE>

* ``v2_capacity_busy``: a protocol 2 client over the per-client view cap is answered ``busy`` with
  ``details.reason:"capacity"`` and ``details.resource:"client_cap"`` (V8: the same reason where the
  situation exists in v2), and its ``hello`` has no ``limits`` or ``capabilities``.
* ``v2_decompile_unchanged``: a native decompiler killed under a protocol 2 client fails that one request
  the way hydra.3 does (``completed:false`` in the result, no new error code); the next request works.
* ``v2_health_governor``: ``health`` (available to a protocol 2 client) carries ``processJob`` and
  ``governor``; ``hello`` and ``status`` gain no key.
"""
import os
import pathlib
import sys
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, wait_for

HERE = pathlib.Path(__file__).resolve().parent


def prepare(c):
    return pathlib.Path(c.a.exe).name


def close(*sessions):
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def chaos():
    try:
        import chaos_lib
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("chaos_lib", HERE / "chaos_lib.py")
        chaos_lib = importlib.util.module_from_spec(spec)
        sys.modules["chaos_lib"] = chaos_lib
        spec.loader.exec_module(chaos_lib)
    return chaos_lib


def started(c, instance, **cfg):
    """Starts ``instance`` through the library under test and returns the stock daemon of it."""
    c.new_daemon(instance, **cfg).connect("cc-e9-start", "tests").close()
    return c.daemon(instance)


def t_v2_capacity_busy(c):
    c.need_engine()
    exe = prepare(c)
    g1 = c.copy_fixture("ccE9a")
    g2 = c.copy_fixture("ccE9b")
    d = started(c, "cc-e9-cap", engine={"maxViewsPerClient": 1})
    S = None
    try:
        S = d.connect("v2", "cc-e9")
        check(S.hello["protocol"] == 2, f"protocol {S.hello['protocol']}")
        for k in ("limits", "capabilities", "policy"):
            check(k not in S.hello, f"a protocol 2 hello has {k!r}")
        S.call("open_project", path=str(g1))
        S.call("open_program", path=exe)
        S.call("open_project", path=str(g2))
        try:
            S.call("open_program", path=exe)
        except Exception as e:  # noqa: BLE001
            check(getattr(e, "code", None) == "busy", f"expected busy, got {e!r}")
            det = e.details or {}
            check(det.get("reason") == "capacity" and det.get("resource") == "client_cap", f"{det}")
        else:
            raise Fail("the second view of a client capped at one was admitted")
        return "a protocol 2 client over its view cap gets busy with details.reason capacity; hello has no new key"
    finally:
        close(S)
        d.stop(force=True)


def t_v2_decompile_unchanged(c):
    c.need_engine()
    if os.name != "nt":
        return "skipped: Windows only (the decompiler is killed by pid)"
    ch = chaos()
    exe = prepare(c)
    gpr = c.copy_fixture("ccE9d")
    d = started(c, "cc-e9-dec")
    S = None
    try:
        S = d.connect("v2", "cc-e9")
        S.call("open_project", path=str(gpr))
        S.call("open_program", path=exe)
        fns = [f["address"] for f in S.call("functions", limit=2)["functions"]]
        fn, other = fns[0], fns[-1]
        check(fn != other, f"two functions: {fns}")
        ref = S.call("decompile", address=fn)
        pid = S.call("health")["pid"]
        pids = ch.decompilers_of(pid)
        check(len(pids) == 1, f"decompilers {pids}")
        check(ch.terminate(pids[0], 10).get("terminated"), "kill -9 of the decompiler")
        # a result the engine already has (the decompile cache, on by default) needs no decompiler:
        # the same reply as before the kill, byte for byte (the dead process is not touched)
        rc = S.call("decompile", address=fn)
        check(rc == ref, f"a cached decompile after the kill: {str(rc)[:200]}")
        # the first request that needs the process: the pooled decompiler is dead, it fails alone
        r = S.call("decompile", address=other)
        check(r.get("completed") is False and "error" in r and "timedOut" in r,
              f"hydra.3 answers a dead decompiler in the result, not as an error: {r}")
        r2 = S.call("decompile", address=other)
        check(r2.get("completed") is True and r2.get("c"), f"the next request: {str(r2)[:200]}")
        r3 = S.call("decompile", address=fn)
        check(r3.get("completed") is True and r3["c"] == ref["c"], f"the first function again: {str(r3)[:200]}")
        return ("a killed decompiler fails one protocol 2 request with completed:false (no new code); the "
                "next works; a result already decompiled is answered unchanged without the process")
    finally:
        close(S)
        d.stop(force=True)


def t_v2_health_governor(c):
    c.need_engine()
    d = started(c, "cc-e9-health")
    S = None
    try:
        S = d.connect("v2", "cc-e9")
        for k in ("capabilities", "limits", "policy", "governor", "processJob"):
            check(k not in S.hello, f"a protocol 2 hello has {k!r}")
        st = S.call("status")
        check("governor" not in st and "processJob" not in st and "limits" not in st,
              f"a protocol 2 status grew a key: {list(st)}")
        h = wait_for(lambda: (lambda x: x if x["tick"]["n"] >= 1 else None)(S.call("health")), "a tick", 10)
        check(h["state"] == "ok", f"state {h['state']}")
        check(h["governor"]["heapState"] == "ok" and h["governor"]["maxViews"] >= 1, f"{h['governor']}")
        if os.name == "nt":
            check(h["processJob"]["own"] is True, f"{h['processJob']}")
        return "health at protocol 2 has processJob and governor; hello and status gain no key"
    finally:
        close(S)
        d.stop(force=True)


TESTS = {
    "v2_capacity_busy": t_v2_capacity_busy,
    "v2_decompile_unchanged": t_v2_decompile_unchanged,
    "v2_health_governor": t_v2_health_governor,
}

if __name__ == "__main__":
    cc.run_file(__file__)
