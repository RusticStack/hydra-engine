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
"""Behaviour of the E2 engine seen by a protocol-2 client (PROTOCOL-3.md 5.1 G7, G8, V1, V7, V8,
package E2), written against the stock 1.0.0 client. Standard library only; any OS.

    python cc_e2.py --ghidra <install> --work <empty dir>

The older-format project is ``--legacy-project`` or the committed ``examples/fixtures/legacy-12.1.4``.
The 1.1.0 client (protocol 3) makes the backups and the seals, because only it can say ``purpose``.

* ``purpose_open_ignored`` (G7): ``purpose:"backup"``, ``open:false`` and ``verify`` on a protocol-2
  ``fork_project`` are ignored: the fork is registered, the reply has the keys it always had, no
  ``backup.json`` is written.
* ``fork_sidecar`` (V7): the sidecar of a protocol-2 fork gains ``purpose:"fork"`` and
  ``disposable:true``; its ``state`` is ``complete``.
* ``upgrade_gate`` (G8, V1): a canonical older-format project refuses ``upgrade:true`` without a valid
  ``backup`` with ``conflict`` and ``details.reason:"backup_required"`` (the vocabulary of
  protocol 2); a backup made by the 1.1.0 client opens it; a fork is exempt (what Hydralysis
  relies on); a read-only open is never gated.
* ``sealed_refusal`` / ``candidate_then_seal`` (V8, D38): a generation candidate is writable and
  saves for its publisher; after ``seal_project`` (1.1.0 client) every writable path is a
  ``conflict`` with ``details.reason:"sealed"`` and a ``fork_project`` suggestion for the stock
  client, a read-only open works, and the tree hash after the refusals equals the one at the seal. A
  project whose sidecar says ``disposable:false`` and nothing else is not sealed; a project with no
  sidecar behaves as before.
* ``v2_surface``: a protocol-2 hello and ``project`` carry none of the v3 keys (``format``,
  ``sealed``) and ``seal_project``, ``prepare_upgrade`` are ``unknown_command``.
"""
import json
import os
import pathlib
import shutil

import client_compat_tests as cc
from client_compat_tests import Fail, check, expect_error

HERE = pathlib.Path(__file__).resolve().parent
LEGACY_DIR = HERE / "fixtures" / "legacy-12.1.4"
PROGRAM = "/flow_fixture.exe"
V2_FORK_KEYS = ["project", "path", "gpr", "name", "writable", "source", "baseRevision", "mode",
                "method", "cloned", "clonedBy", "bytes", "files", "copyMs", "freeSpaceUsedBytes",
                "depth", "sidecar", "ms", "info"]


def legacy_copy(c, tag):
    src = pathlib.Path(c.a.legacy_project) if c.a.legacy_project else LEGACY_DIR
    src = src.parent if src.suffix == ".gpr" else src
    dst = c.work / tag
    cc.dt.clone_tree(src, dst)
    return next(dst.glob("*.gpr"))


def tree(folder):
    import hashlib
    h = hashlib.sha256()
    for f in sorted(p for p in pathlib.Path(folder).rglob("*") if p.is_file()):
        if f.name.endswith((".lock", ".lock~")):
            continue
        h.update(str(f.relative_to(folder)).encode() + str(f.stat().st_size).encode() +
                 f.read_bytes())
    return h.hexdigest()


def sidecar(gpr):
    p = pathlib.Path(gpr).with_name(pathlib.Path(gpr).stem + ".fork.json")
    return p, json.loads(p.read_text(encoding="utf-8"))


def t_purpose_open_ignored(c):
    c.need_engine()
    gpr = legacy_copy(c, "e2cc-purpose")
    base = c.work / "e2cc-purpose-out"
    if base.exists():
        shutil.rmtree(base)
    d = c.daemon("e2cc-purpose")
    with d.connect("stock", "cc-e2") as s:
        check(s.hello["protocol"] == 2, "the stock client must be at protocol 2")
        r = s.call("fork_project", project=str(gpr), path=str(base), name="One", mode="full",
                   purpose="backup", open=False, verify="hash")
        check(list(r) == V2_FORK_KEYS, f"the keys of the v2 reply changed: {list(r)}")
        check(r["project"] and r["writable"] is True,
              f"open:false must be ignored at protocol 2: {r['project']}")
        check(not (base / "backup.json").exists(), "a protocol-2 request made a backup")
        _, sc = sidecar(r["gpr"])
        check(sc["purpose"] == "fork" and sc["disposable"] is True, f"{sc}")
    d.stop()
    return "purpose, open and verify ignored at protocol 2; reply keys unchanged"


def t_fork_sidecar(c):
    c.need_engine()
    gpr = legacy_copy(c, "e2cc-sidecar")
    base = c.work / "e2cc-sidecar-out"
    if base.exists():
        shutil.rmtree(base)
    d = c.daemon("e2cc-sidecar")
    with d.connect("stock", "cc-e2") as s:
        r = s.call("fork_project", project=str(gpr), path=str(base), name="One", mode="full")
        _, sc = sidecar(r["gpr"])
        check(list(sc)[:4] == ["format", "kind", "purpose", "disposable"] and
              sc["purpose"] == "fork" and sc["disposable"] is True and sc["state"] == "complete",
              f"V7: {list(sc)[:6]}")
    d.stop()
    return "sidecar: purpose fork, disposable true, state complete"


def t_upgrade_gate(c):
    c.need_engine()
    notes = []
    inst = "e2cc-gate"
    stock = c.daemon(inst)
    new = c.new_daemon(inst)
    gpr = legacy_copy(c, "e2cc-gate")
    # the backup: the 1.1.0 client, read-only (a writable open of the project would rewrite its
    # index backups and move its revision)
    with new.connect("new", "cc-e2") as n:
        check(n.hello["protocol"] == 3, f"the 1.1.0 client is at protocol {n.hello['protocol']}")
        pid = n.call("open_project", path=str(gpr))["id"]
        b = n.call("fork_project", project=pid, path=str(c.work / "e2cc-gate-backup"),
                   name="legacy", mode="full", purpose="backup", open=False, verify="hash",
                   wait=120000)
        n.call("close_project")
    with stock.connect("stock", "cc-e2") as s:
        check(s.hello["protocol"] == 2, "stock client protocol")
        s.call("open_project", path=str(gpr), writable=True)
        e = expect_error("conflict", s.call, "open_program", path=PROGRAM, writable=True,
                         upgrade=True)
        check(e.details.get("reason") == "backup_required" and
              e.details["format"]["programDb"]["min"] == 32, f"G8: {e.details}")
        e = expect_error("conflict", s.call, "open_program", path=PROGRAM, writable=True,
                         upgrade=True, backup=str(c.work / "e2cc-gate-backup" / "nope.json"))
        check(e.details.get("reason") == "backup_required", f"{e.details}")
        r = s.call("open_program", path=PROGRAM, writable=True, upgrade=True,
                   backup=b["manifest"]["path"])
        check(r["mode"] == "writable", "a valid backup must open it for the protocol-2 client too")
        s.call("close_program", discard=True)
        s.call("close_project", discard=True)
        notes.append("canonical: conflict reason backup_required; a 1.1.0 backup opens it")
        # a fork is exempt
        s.call("open_project", path=str(legacy_copy(c, "e2cc-gate-ro")))
        f = s.call("fork_project", path=str(c.work / "e2cc-gate-fork"), name="F", mode="full")
        r = s.call("open_program", path=PROGRAM, project=f["project"], writable=True, upgrade=True)
        check(r["mode"] == "writable", "a fork must be exempt (Hydralysis upgrades forks)")
        s.call("close_program", discard=True)
        s.call("close_project", project=f["project"], discard=True)
        # a read-only open is never gated
        ro = s.call("open_program", path=PROGRAM, project=s.call("project")["id"])
        check(ro["mode"] == "read_only", "read-only open")
        notes.append("fork exempt, read-only open ungated")
    stock.stop()
    return "; ".join(notes)


def t_candidate_then_seal(c):
    c.need_engine()
    inst = "e2cc-seal"
    stock = c.daemon(inst)
    new = c.new_daemon(inst)
    src = legacy_copy(c, "e2cc-seal-src")
    gdir = c.work / "e2cc-seal-gen"
    if gdir.exists():
        shutil.rmtree(gdir)
    with new.connect("new", "cc-e2") as n:
        pid = n.call("open_project", path=str(src))["id"]
        b = n.call("fork_project", project=pid, path=str(c.work / "e2cc-seal-backup"),
                   name="legacy", mode="full", purpose="backup", open=False, verify="hash",
                   wait=120000)
        g = n.call("fork_project", project=pid, path=str(gdir), name="legacy",
                   purpose="generation", mode="full", wait=60000, open=False)
        n.call("close_project")
    p, sc = sidecar(g["gpr"])
    check(sc["state"] == "candidate" and sc["disposable"] is False, f"{sc}")
    with stock.connect("stock", "cc-e2") as s:
        # the candidate is writable for its publisher (with the backup of the gate)
        gid = s.call("open_project", path=g["gpr"], writable=True)["id"]
        r = s.call("open_program", path=PROGRAM, writable=True, upgrade=True,
                   backup=b["manifest"]["path"])
        fns = s.call("functions", limit=3)["functions"]
        s.call("rename", address=fns[0]["address"], name="cc_e2_publisher")
        check(s.call("save")["saved"] is True, "the candidate's publisher could not save")
        s.call("close_program")
        s.call("close_project")
        # not sealed by disposable:false alone, nor with no sidecar
        sc2 = dict(sc)
        sc2.pop("state")
        p.write_text(json.dumps(sc2))
        w = s.call("open_project", path=g["gpr"], writable=True)
        check(w["writable"] is True, "a sidecar with disposable:false and no state is not sealed")
        s.call("close_project", discard=True)
        p.write_text(json.dumps(sc))
        bare = legacy_copy(c, "e2cc-seal-bare")
        pathlib.Path(bare).with_name("legacy.fork.json").unlink(missing_ok=True)
        w = s.call("open_project", path=str(bare), writable=True)
        check(w["writable"] is True, "a project with no sidecar and no seal record must be as before")
        s.call("close_project", discard=True)
    with new.connect("new", "cc-e2") as n:
        sealed = n.call("seal_project", project=g["gpr"])
        check(sealed["sealed"] is True and "marker" in sealed["witnesses"], f"{sealed}")
    held = tree(gdir)
    with stock.connect("stock", "cc-e2") as s:
        e = expect_error("conflict", s.call, "open_project", path=g["gpr"], writable=True)
        check(e.details.get("reason") == "sealed" and
              e.details["suggestion"]["cmd"] == "fork_project", f"V8: {e.details}")
        ro = s.call("open_project", path=g["gpr"])
        check(ro["writable"] is False, "a sealed project opens read-only")
        s.call("open_program", path=PROGRAM)
        for cmd, kw in (("save", {}), ("analyze", {}), ("rename", dict(address="0x140001000",
                                                                       name="nope"))):
            e = expect_error("conflict", s.call, cmd, **kw)
            check(e.details.get("reason") == "sealed", f"{cmd}: {e.details}")
        e = expect_error("conflict", s.call, "open_program", path=PROGRAM, writable=True)
        check(e.details.get("reason") == "sealed", f"open_program writable: {e.details}")
        s.call("close_project")
    stock.stop()
    check(tree(gdir) == held, "the refusals changed the sealed tree")
    return ("candidate writable and saved; disposable:false alone and no sidecar not sealed; "
            "sealed: conflict reason sealed with a fork suggestion on every writable path, tree "
            "hash unchanged")


def t_v2_surface(c):
    c.need_engine()
    gpr = legacy_copy(c, "e2cc-surface")
    d = c.daemon("e2cc-surface")
    with d.connect("stock", "cc-e2") as s:
        h = s.hello
        check(not set(h) & {"capabilities", "policy", "limits"}, f"v3 keys in a v2 hello: {list(h)}")
        info = s.call("open_project", path=str(gpr))
        check("format" not in info, f"v3 keys in project info: {list(info)}")
        for cmd in ("seal_project", "prepare_upgrade"):
            expect_error("unknown_command", s.call, cmd, project=info["id"])
    d.stop()
    return "no v3 key in hello or project info; seal_project and prepare_upgrade are unknown_command"


def t_capability_seal(c):
    c.need_engine()
    d = c.new_daemon("e2cc-cap")
    with d.connect("cc-e2-cap", "tests") as s:
        caps = dict(s.hello.get("capabilities", {}))
        pol = s.hello.get("policy", {})
    d.stop()
    names = list(caps)
    for n in ("forkReport", "format", "backup", "upgradeGate", "seal", "forkAtomic"):
        check(caps.get(n) == 1, f"{n} is not advertised at 1: {caps}")
    check(names.index("seal") == names.index("forkAtomic") - 1,
          f"seal is declared just before forkAtomic (A9): {names}")
    check(pol.get("requireBackupForUpgrade") is True, f"policy {pol}")
    return "seal, format, backup, forkReport, upgradeGate advertised; policy requireBackupForUpgrade true"


TESTS = {"purpose_open_ignored": t_purpose_open_ignored, "fork_sidecar": t_fork_sidecar,
         "upgrade_gate": t_upgrade_gate, "candidate_then_seal": t_candidate_then_seal,
         "v2_surface": t_v2_surface, "capability_seal": t_capability_seal}

if __name__ == "__main__":
    cc.run_file(__file__)
