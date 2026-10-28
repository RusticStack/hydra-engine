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
"""Characterization scenarios of package E1 (PROTOCOL-3.md 3.1 to 3.4, section 8), protocol 3 only:
their goldens are ``examples/characterization/v3/e1-<scenario>.json`` (section 8, rule 2). Run with

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e1-hello,...

* ``e1-hello``: the v3 hello and status, with ``paths``, ``platform`` and ``analysisIdentity`` masked
  (hashes, build date, versions and machine facts) and ``capabilities``, ``limits`` and ``policy``
  compared as **required subsets** (every key E1 itself sets must be there with its value; later
  packages add theirs and are asserted in their own ``char_<id>.py``, so they never re-record this
  golden). The structure of the masked blocks is checked here, not recorded.
* ``e1-expect``: ``expect`` on ``signature`` and ``data_type`` conflicts with the key order of the
  one for names, names the last editor, and the signature conflict carries ``error.next``.
* ``e1-rk``: an ``rk`` replays the stored per-op result (the reconstructed reply of 3.4) and adds
  nothing to the journal; a bad ``rk`` is ``bad_request`` with ``details.field``. (``rk_expired``
  needs 200,000 journal entries to evict one; it is not recorded.)
* ``e1-require-expect``: ``-set requireExpect=true``: a program with shared writers refuses an edit
  without ``expect``; an owner's does not.
"""
import copy

import characterization_tests as ct
from characterization_tests import F1, F2, Fail

PROTOCOLS = (3,)
DATA = "0x140001060"

#: what E1 itself advertises; the values of limits are pinned by the daemon's configuration below
E1_CAPABILITIES = {"errorNext": 1, "expectAll": 1, "idempotency": 1, "identity": 1}
E1_LIMITS = {"maxQuick": 4, "maxLong": 2, "maxImports": 2}


def subset(what, actual, required):
    """The keys of ``required`` out of ``actual``, each present with its value (anything else in
    ``actual`` is another package's and is neither compared nor recorded); a ``Fail`` otherwise."""
    for k, v in required.items():
        if k not in actual or actual[k] != v:
            raise Fail(f"e1: {what}.{k} should be {v!r}, is {actual.get(k, '<absent>')!r}")
    return {k: actual[k] for k in actual if k in required}


def structure(res):
    """What the masked blocks must look like (not recorded: machine facts)."""
    paths = res["paths"]
    if list(paths) != ["stateDir", "instance", "endpointFile", "logFile", "scriptPath", "tmpDir",
                       "upgradeCacheDir", "install"]:
        raise Fail(f"e1: paths keys {list(paths)}")
    plat = res["platform"]
    if list(plat) != ["os", "osVersion", "arch", "cpus", "javaVendor", "javaVersion", "maxHeapMb",
                      "fileSystems", "cow"] or "testHooks" in plat:
        raise Fail(f"e1: platform keys {list(plat)}")
    ai = res["analysisIdentity"]
    if list(ai) != ["hydraVersion", "ghidraVersion", "buildDate", "dbVersions", "decompiler"]:
        raise Fail(f"e1: analysisIdentity keys {list(ai)}")
    dbv = ai["dbVersions"]
    if (list(dbv) != ["program", "dataTypes"] or not isinstance(dbv["program"], int) or
            dbv["program"] < 1 or not (dbv["dataTypes"] is None or
                                       isinstance(dbv["dataTypes"], int) and dbv["dataTypes"] > 0)):
        raise Fail(f"e1: dbVersions {dbv}")
    if list(ai["decompiler"]) != ["path", "sizeBytes", "sha256"]:
        raise Fail(f"e1: decompiler {ai['decompiler']}")
    keys = list(res)
    if keys[keys.index("memory") + 1:keys.index("memory") + 9] != [
            "protocolMin", "protocolMax", "capabilities", "limits", "policy", "paths", "platform",
            "analysisIdentity"] or keys.index("projects") != keys.index("analysisIdentity") + 1:
        raise Fail(f"e1: the identity block is not between memory and projects: {keys}")


def head(R, who, s, cmd, policy, note=None, **f):
    """Sends ``hello`` or ``status`` and records it with the machine facts masked and the three
    advertised blocks cut to what E1 sets (``policy`` is the required subset of the policy block)."""
    if cmd == "hello" and "protocol" not in f:
        f = {**f, "protocol": R.protocol}
    try:
        s.call(cmd, **f)
    except R.gs.SessionError:
        pass
    resp = copy.deepcopy(s.last_response)
    if not resp.get("ok"):
        raise Fail(f"e1: {cmd} failed: {resp.get('error')}")
    res = resp["result"]
    if res["protocol"] != 3:
        raise Fail(f"e1: {cmd} was answered protocol {res['protocol']}")
    structure(res)
    res["capabilities"] = subset("capabilities", res["capabilities"], E1_CAPABILITIES)
    res["limits"] = subset("limits", res["limits"], E1_LIMITS)
    res["policy"] = subset("policy", res["policy"], policy)
    for k in ("paths", "platform", "analysisIdentity"):
        res[k] = "<masked>"
    # E3a (amendment): the scheduler block of the status step keeps the shape of the protocol-3
    # base. What E3a added to it is cut: the maint lane, and the keys of a lane that are new
    # (the E3a characterization, char_e3a.py, records them).
    sched = res.get("scheduler")
    if isinstance(sched, dict):
        sched.pop("maint", None)
        for lane in ("quick", "long"):
            for k in ("oldestWaitMs", "longestRunningMs", "starving", "perKeyCap", "perKey"):
                sched.get(lane, {}).pop(k, None)
    step = {"step": len(R.steps) + 1, "who": who, "cmd": cmd, "request": R.m.value(f),
            "response": R.m.value(resp)}
    if note:
        step["note"] = note
    R.steps.append(step)
    return res


def sc_hello(c, R):
    d = c.daemon("e1-hello", maxQuick=4, maxLong=2, maxImports=2)
    a = c.connect(d, "e1-a", "e1-h")
    p = {"requireExpect": False}
    head(R, "a", a, "hello", p, client="e1-a", harness="e1-h", clientVersion="9.9.9")
    head(R, "a", a, "status", p)
    head(R, "a", a, "hello", p, protocol=2,
         note="a second hello that asks for 2 on a protocol-3 connection: answered 3")
    head(R, "a", a, "hello", p, protocol="3", note="a string protocol is not an integer: same")
    R.ok("a", a, "ping")
    R.ok("a", a, "projects")
    b = c.connect(d, "e1-b", "e1-h")
    head(R, "b", b, "status", p)
    c.stop(d)


def sc_expect(c, R):
    gpr = c.copy_fixture("e1expect")
    d = c.daemon("e1-expect")
    a = c.connect(d, "e1-a", "e1-h")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    r = R.ok("a", a, "edit", ops=[{"op": "signature", "address": F1,
                                    "signature": "int e1_f(int a)"}])
    sig = r["results"][0]["new"]
    R.ok("a", a, "edit", note="the right expect on a signature", ops=[
        {"op": "signature", "address": F1, "signature": "int e1_f(int a, int b)", "expect": sig}])
    sig2 = "int e1_f(int a, int b)"
    err_sig = R.err("a", a, "edit", "conflict", note="a wrong expect on a signature", ops=[
        {"op": "signature", "address": F1, "signature": "void e1_g(void)", "expect": sig}])
    if err_sig["details"]["field"] != "signature" or err_sig["details"]["current"] != sig2:
        raise Fail(f"e1: the signature conflict: {err_sig}")
    if list(err_sig) != ["code", "message", "details", "next"] or err_sig["next"] != {
            "cmd": "decompile", "address": F1}:
        raise Fail(f"e1: the signature conflict has no error.next: {err_sig}")
    if "lastEdit" not in err_sig["details"] or err_sig["details"]["lastEdit"]["op"] != "signature":
        raise Fail(f"e1: the signature conflict does not name the last editor: {err_sig}")
    R.ok("a", a, "edit", note="no defined data there yet: expect null is right", ops=[
        {"op": "data_type", "address": DATA, "type": "int", "expect": None}])
    R.ok("a", a, "edit", note="the right expect on a data type", ops=[
        {"op": "data_type", "address": DATA, "type": "short", "expect": "int"}])
    err_type = R.err("a", a, "edit", "conflict", note="a wrong expect on a data type", ops=[
        {"op": "data_type", "address": DATA, "type": "long", "expect": None}])
    if err_type["details"]["field"] != "type" or err_type["details"]["current"] != "short":
        raise Fail(f"e1: the data_type conflict: {err_type}")
    if "next" in err_type:
        raise Fail("e1: the data_type conflict has an error.next the spec does not give it")
    err_name = R.err("a", a, "edit", "conflict", note="the same for a name, for the key order", ops=[
        {"op": "rename", "address": F2, "name": "e1_two", "expect": "not_it"}])
    err_sig_name = [k for k in err_sig["details"] if k not in ("lastEdit", "holderInfo", "suggest")]
    err_name_keys = [k for k in err_name["details"] if k not in ("lastEdit", "holderInfo", "suggest")]
    if err_sig_name != err_name_keys or list(err_type["details"])[:5] != err_sig_name[:5]:
        raise Fail(f"e1: key order: signature {err_sig_name}, name {err_name_keys}, "
                   f"type {list(err_type['details'])}")
    R.err("a", a, "edit", "bad_request", note="expect must be a string or null", ops=[
        {"op": "signature", "address": F1, "signature": "int e1_h(void)", "expect": 5}])
    R.err("a", a, "rename", "conflict", address=F1, name="x", expect="stale",
          note="a single rename: the existing shape")
    R.ok("a", a, "journal", note="the conflicts changed nothing")
    R.ok("a", a, "close_program", discard=True)
    R.ok("a", a, "close_project")
    c.stop(d)


def sc_rk(c, R):
    gpr = c.copy_fixture("e1rk")
    d = c.daemon("e1-rk")
    a = c.connect(d, "e1-a", "e1-h")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    ops = [{"op": "rename", "address": F2, "name": "e1_two"},
           {"op": "comment", "address": F2, "text": "rk comment", "type": "pre"}]
    first = R.ok("a", a, "edit", ops=ops, rk="rk-edit-1")
    again = R.ok("a", a, "edit", ops=ops, rk="rk-edit-1", note="the same rk: replayed, not applied")
    if (again["replayed"] is not True or again["seqs"] != first["seqs"] or
            again["applied"] != 2 or again["unsavedEdits"] != first["unsavedEdits"] or
            [r["op"] for r in again["results"]] != ["rename", "comment"]):
        raise Fail(f"e1: the edit replay: {again}")
    if list(again) != ["replayed", "program", "applied", "seqs", "results", "unsavedEdits"]:
        raise Fail(f"e1: the edit replay keys: {list(again)}")
    one = R.ok("a", a, "rename", address=F1, name="e1_one", rk="rk-ren-1")
    two = R.ok("a", a, "rename", address=F1, name="e1_other", rk="rk-ren-1",
               note="a different name, the same rk: still the first result")
    if (two["replayed"] is not True or two["seq"] != one["seq"] or
            two["result"]["new"] != "e1_one" or list(two) != ["replayed", "seq", "result"]):
        # (a stored result is the journal entry: its "name" is the author's, the new name is "new")
        raise Fail(f"e1: the rename replay: {two}")
    com = R.ok("a", a, "comment", address=F1, text="rk", rk="rk-com-1")
    com2 = R.ok("a", a, "comment", address=F1, text="rk", rk="rk-com-1")
    if com2["replayed"] is not True or com2["seq"] != com["seq"]:
        raise Fail(f"e1: the comment replay: {com2}")
    R.ok("a", a, "rename", address=F1, name="e1_one_b", rk="rk-ren-2",
         note="another rk is applied")
    R.ok("a", a, "edit", ops=ops[:1], note="no rk: applied each time")
    R.ok("a", a, "edit", ops=ops[:1], note="no rk: applied each time")
    R.ok("a", a, "edit", ops=ops[:1], rk=None, note="rk null is no rk")
    R.err("a", a, "edit", "bad_request", ops=ops[:1], rk=7, note="rk must be a string")
    R.err("a", a, "rename", "bad_request", address=F1, name="x", rk="k" * 65,
          note="rk is at most 64 characters")
    R.err("a", a, "comment", "bad_request", address=F1, text="x", rk="")
    R.ok("a", a, "edit", ops=ops[:1], rk="k" * 64, note="64 characters is fine")
    j = R.ok("a", a, "journal", note="one entry per applied op, each with its rk; no replay added")
    rks = [e.get("rk") for e in j["entries"]]
    if rks.count("rk-edit-1") != 2 or rks.count("rk-ren-1") != 1 or rks.count("rk-com-1") != 1:
        raise Fail(f"e1: the journal's rks: {rks}")
    R.ok("a", a, "close_program", discard=True)
    R.ok("a", a, "close_project")
    c.stop(d)


def sc_require_expect(c, R):
    gpr = c.copy_fixture("e1req")
    d = c.daemon("e1-require", engine={"requireExpect": True}, maxQuick=4, maxLong=2,
                 maxImports=2)
    a = c.connect(d, "e1-a", "e1-h")
    b = c.connect(d, "e1-b", "e1-h")
    head(R, "a", a, "hello", {"requireExpect": True}, note="the policy is on")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("b", b, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    r = R.ok("a", a, "rename", address=F1, name="e1_owner",
             note="owner mode: nobody to collide with, no expect needed")
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True, share=True,
         note="the owner opens it to others")
    R.ok("b", b, "open_program", path="/alpha.exe", writable=True, share=True)
    R.err("b", b, "rename", "bad_request", address=F1, name="e1_b", note="shared: needs expect")
    R.err("b", b, "comment", "bad_request", address=F1, text="x")
    R.err("a", a, "edit", "bad_request", ops=[
        {"op": "comment", "address": F1, "text": "ok", "expect": None},
        {"op": "rename", "address": F2, "name": "e1_two"}], note="the second op has no expect")
    R.ok("b", b, "rename", address=F1, name="e1_b", expect="e1_owner")
    R.ok("a", a, "edit", ops=[{"op": "comment", "address": F1, "text": "ok", "expect": None}])
    R.ok("b", b, "journal")
    R.ok("b", b, "close_program")
    R.ok("a", a, "close_program", discard=True)
    R.ok("a", a, "close_project")
    R.ok("b", b, "close_project")
    c.stop(d)


SCENARIOS = {"e1-hello": sc_hello, "e1-expect": sc_expect, "e1-rk": sc_rk,
             "e1-require-expect": sc_require_expect}
