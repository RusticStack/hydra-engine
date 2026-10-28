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
"""Protocol-2 behaviour of the E1 engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
package E1). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e1.py --ghidra <install> --work <empty dir>

Tests (the stock client is a real protocol-2 client; the 1.1.0 client of this tree is the v3 one):

* ``v6_stock_client`` (V6, first): the 1.0.0 client connects to the E1 engine and works; its
  hello has exactly the keys protocol 2 always had, in the same order, and no v3 key; the endpoint
  file says ``protocol:2`` and adds ``protocolMin:2`` and ``protocolMax:3``; ``status`` has no
  identity block; the 1.1.0 client on the same daemon is at protocol 3.
* ``g1_g7_expect_rk`` (G1 and the ``rk`` half of G7): on the stock client a ``edit`` with a wrong
  ``expect`` on ``signature`` and on ``data_type`` succeeds (it is ignored, as on hydra.3), and a
  request with the same ``rk`` twice is applied twice, with no ``replayed`` key and no ``rk`` in
  the journal; the same requests on the 1.1.0 client (protocol 3) conflict and replay.
* ``v2_request_fields``: ``rk`` on ``rename`` and ``comment`` and ``expect`` on a v2 ``edit`` that
  is right still behave as before.
"""
import pathlib
import shutil

import client_compat_tests as cc
from client_compat_tests import Fail, check, expect_error

HERE = pathlib.Path(__file__).resolve().parent

#: the keys of a protocol-2 hello result, in order (Session.info + the client id)
V2_HELLO_KEYS = ["protocol", "minClient", "hydraVersion", "ghidraVersion", "installId", "startedAt",
                 "ghidra", "install", "java", "pid", "uptimeMs", "listen", "launch", "keepWarmS",
                 "memory", "projects", "client"]
V3_ONLY = ["protocolMin", "protocolMax", "capabilities", "limits", "policy", "paths", "platform",
           "analysisIdentity"]

F1 = "0x140001020"   # the fixture's functions (characterization_tests.make_pe)
F2 = "0x140001040"
DATA = "0x140001060"


def _make_pe():
    ct = cc._load("characterization_tests_for_cc", HERE / "characterization_tests.py")
    return ct.make_pe(7)


def fixture(c):
    """A project with one tiny analysed program (the characterization fixture's alpha.exe), made once
    by the stock client and copied per test."""
    base = c.work / "e1-fixture"
    gpr = base / "Fixture.gpr"
    if not gpr.exists():
        exe = c.work / "bin" / "alpha.exe"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(_make_pe())
        d = c.daemon("e1-fixture")
        with d.connect("fixture", "cc-e1") as s:
            c.make_project(s, base, "Fixture")
            s.call("open_project", path=str(gpr), writable=True)
            s.call("import", file=str(exe), analyze=True, timeout=600, wait=300000)
            s.call("close_project")
        d.stop()
    return base


def copy_fixture(c, name):
    dst = c.work / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(fixture(c), dst)
    return dst / "Fixture.gpr"


def t_v6_stock_client(c):
    st = c.stock
    check(st.CLIENT_VERSION == "1.0.0" and st.PROTOCOL == 2, "the stock client is not 1.0.0")
    d = c.daemon("e1-v6")
    with d.connect("cc-e1", "tests") as s:
        h = s.hello
        check(h["protocol"] == 2, f"the 1.0.0 client's hello was answered {h['protocol']}")
        check(list(h) == V2_HELLO_KEYS, f"a protocol-2 hello changed its keys: {list(h)}")
        ep = d.read_endpoint()
        check(ep["protocol"] == 2 and ep["protocolMin"] == 2 and ep["protocolMax"] == 3,
              f"endpoint file: { {k: v for k, v in ep.items() if k != 'token'} }")
        check(isinstance(s.call("projects"), dict) and s.call("ping") == {"pong": True}, "works")
        status = s.call("status")
        check(all(k not in status for k in V3_ONLY), f"a v2 status has a v3 key: {list(status)}")
        check(status["protocol"] == 2, "status.protocol")
        # a protocol-3 client of this tree on the same daemon is at 3, and a v2 reply is unchanged
        n = c.new_daemon("e1-v6")
        with n.connect("cc-e1-new", "tests") as s3:
            check(s3.protocol == 3 and s3.hello["protocol"] == 3, f"1.1.0 at {s3.protocol}")
            check(all(k in s3.hello for k in V3_ONLY), "the v3 hello lacks its identity block")
            check(list(s.call("status")) == list(status),
                  "a v3 client on the daemon changed the stock client's status")
    d.stop()
    return "1.0.0: hello keys unchanged, endpoint protocol 2 (+ protocolMin 2, protocolMax 3); 1.1.0 at 3"


WRONG_SIG = {"op": "signature", "address": F1, "signature": "int e1_sig(int a)",
             "expect": "void not_the_signature(void)"}
WRONG_TYPE = {"op": "data_type", "address": DATA, "type": "int", "expect": "not_the_type"}


def t_g1_g7_expect_rk(c):
    gpr = copy_fixture(c, "e1-g1")
    d = c.daemon("e1-g1")
    # ---- protocol 2: the stock client ----
    with d.connect("cc-e1", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("open_program", path="/alpha.exe", writable=True)
        r = s.call("edit", ops=[WRONG_SIG])
        check(r["applied"] == 1 and "replayed" not in r, f"a v2 edit with a wrong expect on a "
              f"signature: {r}")
        r = s.call("edit", ops=[WRONG_TYPE])
        check(r["applied"] == 1, f"a v2 edit with a wrong expect on a data_type: {r}")
        # rk twice: applied twice (an rk is a v3 field; a v2 request that carries it is as before)
        a = s.call("rename", address=F2, name="e1_rk_a", rk="e1-key")
        b = s.call("rename", address=F2, name="e1_rk_b", rk="e1-key")
        check("replayed" not in a and "replayed" not in b and b["seq"] == a["seq"] + 1 and
              b["old"] == "e1_rk_a", f"v2 rk twice on rename: {a} {b}")
        e1 = s.call("edit", ops=[{"op": "comment", "address": F1, "text": "rk"}], rk="e1-edit")
        e2 = s.call("edit", ops=[{"op": "comment", "address": F1, "text": "rk"}], rk="e1-edit")
        check("replayed" not in e1 and "replayed" not in e2 and e2["seqs"][0] == e1["seqs"][0] + 1,
              f"v2 rk twice on edit: {e1} {e2}")
        entries = s.call("journal")["entries"]
        check(all("rk" not in e for e in entries), "a v2 request left an rk in the journal")
        s.call("close_program", discard=True)
        s.call("close_project")
    # ---- protocol 3: the same requests ----
    n = c.new_daemon("e1-g1")
    with n.connect("cc-e1-new", "tests") as s3:
        check(s3.protocol == 3, f"the 1.1.0 client is at {s3.protocol}")
        s3.call("open_project", path=str(gpr), writable=True)
        s3.call("open_program", path="/alpha.exe", writable=True)
        e = expect_error("conflict", s3.call, "edit", ops=[WRONG_SIG])
        check(e.details["field"] == "signature" and e.details["reason"] == "changed" and
              e.details["expected"] == "void not_the_signature(void)" and e.details["rolledBack"],
              f"v3 signature conflict: {e.details}")
        e = expect_error("conflict", s3.call, "edit", ops=[WRONG_TYPE])
        check(e.details["field"] == "type" and e.details["current"] is None,
              f"v3 data_type conflict: {e.details}")
        a = s3.call("rename", address=F2, name="e1_rk_a", rk="e1-key")
        b = s3.call("rename", address=F2, name="e1_rk_b", rk="e1-key")
        check(b["replayed"] is True and b["seq"] == a["seq"] and b["result"]["new"] == "e1_rk_a",
              f"v3 rk twice on rename: {a} {b}")
        s3.call("close_program", discard=True)
        s3.call("close_project")
    d.stop()
    return "v2: wrong expect on signature and data_type succeeds, rk twice applied twice; v3: conflict and replay"


def t_v2_request_fields(c):
    gpr = copy_fixture(c, "e1-fields")
    d = c.daemon("e1-fields")
    with d.connect("cc-e1", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("open_program", path="/alpha.exe", writable=True)
        r = s.call("edit", ops=[{"op": "rename", "address": F1, "name": "e1_named"}])
        # an expect on a rename or a comment is enforced at every protocol, as it always was
        expect_error("conflict", s.call, "rename", address=F1, name="x", expect="stale")
        r = s.call("rename", address=F1, name="e1_named2", expect="e1_named")
        check(r["old"] == "e1_named", f"a right expect: {r}")
        # fields only a v3 request has are ignored by a v2 one: no bad_request, no effect
        r = s.call("comment", address=F1, text="x", lane="quick", purpose="backup", rk=5)
        check("replayed" not in r and r["text"] == "x", f"v2 comment with v3 fields: {r}")
        s.call("close_program", discard=True)
        s.call("close_project")
    d.stop()
    return "v2: expect on names enforced, v3-only fields ignored"


TESTS = {"v6_stock_client": t_v6_stock_client, "g1_g7_expect_rk": t_g1_g7_expect_rk,
         "v2_request_fields": t_v2_request_fields}

if __name__ == "__main__":
    cc.run_file(__file__)
