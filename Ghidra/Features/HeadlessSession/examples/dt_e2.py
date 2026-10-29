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
"""Daemon tests of package E2 (PROTOCOL-3.md 3.4, 3.12, 3.13, D12, D38, D41, D42, D66): the format
block, the upgrade gate, backups and their manifest, sealing, the fork report, the repair policy of
the daemon and the sweeper's pid-reuse rule. Standard library only; Windows for the process-start
helper and the ReFS part (those parts skip elsewhere).

Run through ``daemon_tests.py`` (``--only format_readonly,upgrade_gate,...``) on a v3 engine. The
tests that need an older-format project use ``--legacy-project`` or, by default, the committed
``examples/fixtures/legacy-12.1.4`` (stock 12.1.4, program database version 32, made by
``make_legacy_fixture.py``); the ones that need a current-format project use ``--exe`` like the rest.
``E2_KILLS`` (default 6) is how many daemon kills ``backup_fault`` makes.

Tests:

* ``format_readonly``: the ``format`` block on the 12.1.4 fixture (stored 32 against 33, the data
  type manager's stored version, upgrade required, one way) and on a current-format project (not
  required); a protocol 2 reply has no ``format``; the project tree is byte-identical afterwards.
* ``folder_singletons``: one ``backup.json`` / ``SEALED.json`` per folder, never replaced.
* ``format_truncated``: a scan cut at 64 programs says null, not false.
* ``upgrade_gate``: canonical ``upgrade:true`` without ``backup`` is ``backup_required`` (v3) or
  ``conflict`` with ``reason:"backup_required"`` (v2); a stale, unverified, foreign-revision,
  wrong-self-hash, wrong-size or incomplete backup is refused; a good one opens and the next save
  stamps its comment; a fork, a fork whose sidecar has no ``disposable`` field and the upgrade cache
  are exempt; a generation, and a project with a missing, unparseable or ``disposable:false``
  sidecar, are canonical; ``requireBackupForUpgrade=false`` turns it off.
* ``backup_fault``: the daemon killed mid-backup leaves no folder with a verifying manifest and the
  retry succeeds; one corrupted byte is refused by a client re-hash while the engine gate passes it
  (by design: it checks sizes, not content); a failed ``verify`` leaves no project, no manifest, no
  staging folder.
* ``manifest_canonical``: the vector of 3.4 in both languages; the engine writes a manifest with a
  non-ASCII path and U+2028 that Python verifies, and accepts one that Python wrote.
* ``fork_report``: purpose, cost, warnings, manifest in the reply; NTFS gives ``method:"copy"``
  and a warning; on the Dev Drive (ReFS) a fork is a clone and a freshly forked candidate has the
  ``Revision.of`` of its source (the property step 4 of 4.6 relies on).
* ``candidate_then_seal`` / ``seal_union`` / ``sealed_refusal``: D38 and D66.
* ``repair_policy``: a zero-header newest version of a writable disposable fork is repaired at open
  through the daemon, with no property set and ``repairs[]`` in the reply; the master, a generation
  candidate and a sealed project answer ``corrupt_newest`` and are not written.
* ``sweeper_pid_reuse``: an intent-less staging folder named for a live process that started after
  the folder was created is swept; one named for a process that was already running is not.
* ``prepare_upgrade``, ``fork_purposes``, ``promote_marker``.
* ``sidecar_unfinished``: a sidecar held past the retry budget leaves the committed fork saying
  ``publishing`` and the reply says so. The handle holder is a polling thread that must land in a
  window of a few milliseconds, so the case is run again (as ``e2a_handle_holder`` does) while the
  holder arrived too late to hold anything; the assertions are never loosened.
* ``legacy_foreign_owner``: the fixture's ``project.prp`` names its maker as owner, which Ghidra
  refuses for another user (the hosted CI runner: nine tests failed with "Project is owned by"),
  so ``legacy_copy`` rewrites the owner of its copies to the current user.
* ``failed_test_releases``: a test that fails halfway leaves no daemon and no open project behind.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

import daemon_tests as dt
from daemon_tests import Fail, check, expect_error

HERE = pathlib.Path(__file__).resolve().parent
LEGACY_DIR = HERE / "fixtures" / "legacy-12.1.4"
VECTOR = HERE / "vectors" / "canonical-manifest.json"
PROGRAM = "/flow_fixture.exe"
STAGING = re.compile(r"^\..+\.fork-.+\.tmp$")


# ---- helpers -----------------------------------------------------------------------------------

def rmtree(path):
    """``shutil.rmtree`` that also removes read-only files (a published backup.json is read-only)."""
    def onexc(func, p, exc):
        try:
            os.chmod(p, 0o666)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onexc=onexc)


def canon(o):
    """The canonical bytes of PROTOCOL-3.md 3.4, the way Python writes them."""
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def legacy_copy(c, tag):
    """A private copy of the 12.1.4 project; returns its ``.gpr``."""
    src = pathlib.Path(c.a.legacy_project) if c.a.legacy_project else LEGACY_DIR
    src = src.parent if src.suffix == ".gpr" else src
    dst = c.work / tag
    dt.clone_tree(src, dst)
    dt.own_project(dst)  # the fixture names its maker as owner: another user could not open it
    return next(dst.glob("*.gpr"))


def tree_digest(folder, skip=(".lock", ".lock~")):
    """One hash of every file below ``folder`` (path, size, content), lock files left out."""
    folder = pathlib.Path(folder)
    h = hashlib.sha256()
    n = 0
    for f in sorted(p for p in folder.rglob("*") if p.is_file()):
        if f.name.endswith(skip):
            continue
        h.update(str(f.relative_to(folder)).encode("utf-8") + b"|" + str(f.stat().st_size).encode())
        h.update(sha_file(f).encode())
        n += 1
    return h.hexdigest(), n


def v3(c, d, name):
    return c.connect(d, name, "dt_e2", protocol=3)


def v2(c, d, name):
    return c.connect(d, name, "dt_e2", protocol=2)


def need_v3(s):
    check(s.hello.get("protocol") == 3, f"this engine answered protocol {s.hello.get('protocol')}")


def last_error(s):
    r = s.last_response or {}
    return r.get("error") or {}


def manifest_problems(folder, hash_files=True):
    """Everything wrong with the backup in ``folder``, found the way a client would: the manifest
    parses, the canonical self hash and the file set hash match, every file exists with its size
    and (``hash_files``) its SHA-256."""
    folder = pathlib.Path(folder)
    mf = folder / "backup.json"
    if not mf.is_file():
        return ["no backup.json"]
    try:
        m = json.loads(mf.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"backup.json: {e}"]
    probs = []
    claimed = m.pop("selfSha256", None)
    if claimed != sha(canon(m)):
        probs.append("selfSha256 does not match the canonical form")
    if m.get("filesetSha256") != sha(canon(m.get("files", []))):
        probs.append("filesetSha256 does not match the files array")
    if m.get("format") != 1 or m.get("kind") != "ghidra-session-backup":
        probs.append("format or kind")
    if not (m.get("verify") or {}).get("ok"):
        probs.append("verify.ok is not true")
    for f in m.get("files", []):
        p = folder / f["path"]
        if not p.is_file():
            probs.append(f"missing {f['path']}")
        elif p.stat().st_size != f["size"]:
            probs.append(f"size of {f['path']}")
        elif hash_files and sha_file(p) != f["sha256"]:
            probs.append(f"sha256 of {f['path']}")
    return probs


def backup(c, s, project, dest, name="legacy", **kw):
    """A hash-verified backup of ``project`` into ``dest``; returns the reply."""
    fields = dict(project=project, path=str(dest), name=name, purpose="backup", open=False,
                  verify="hash", mode="full", wait=120000)
    fields.update(kw)
    return s.call("fork_project", **fields)


def flip_byte(path, offset=None):
    """Flips one byte of a file, same size."""
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        off = size // 2 if offset is None else offset
        f.seek(off)
        b = f.read(1)
        f.seek(off)
        f.write(bytes([b[0] ^ 0xFF]))


def resign(manifest):
    manifest.pop("selfSha256", None)
    manifest["selfSha256"] = sha(canon(manifest))
    return manifest


def variant(src_backup_dir, dst, edit):
    """A copy of a backup folder whose manifest ``edit`` changed; ``edit`` returns True to re-sign."""
    if dst.exists():
        rmtree(dst)
    shutil.copytree(src_backup_dir, dst)
    mf = dst / "backup.json"
    os.chmod(mf, 0o666)
    m = json.loads(mf.read_text(encoding="utf-8"))
    if edit(m, dst):
        resign(m)
    mf.write_bytes(canon(m) if "selfSha256" in m else json.dumps(m).encode())
    return mf


def sidecar_of(gpr):
    p = pathlib.Path(gpr).with_name(pathlib.Path(gpr).stem + ".fork.json")
    return p, json.loads(p.read_text(encoding="utf-8"))


def open_up(s, backup_path=None, project=None, **kw):
    fields = dict(path=PROGRAM, writable=True, upgrade=True)
    if project:
        fields["project"] = project
    if backup_path:
        fields["backup"] = str(backup_path)
    fields.update(kw)
    return s.call("open_program", **fields)


def make_source(c, tag, files=12, mb=8):
    """A small project with ballast (so that a copy and its verification take a while), made once
    per working directory. It is only ever read."""
    base = c.work / f"e2-src-{tag}"
    gpr = base / "Src.gpr"
    if not gpr.exists():
        d = c.daemon(f"e2-mk-{tag}")
        with d.connect("e2", "tests") as s:
            c.make_project(s, base, "Src")
        d.stop()
        ballast = base / "Src.rep" / "ballast"
        ballast.mkdir()
        blob = os.urandom(1 << 20)
        for i in range(files):
            (ballast / f"b{i:02d}.bin").write_bytes(blob * mb)
    return gpr


# ---- format -----------------------------------------------------------------------------------

def t_format_readonly(c):
    """3.4 ``format``: from the database header, without opening the program, and it writes
    nothing (the tree hash before and after)."""
    gpr = legacy_copy(c, "e2-fmt")
    before = tree_digest(gpr.parent)
    d = c.daemon("e2-fmt", keepWarm=0)
    with v3(c, d, "fmt") as s:
        need_v3(s)
        info = s.call("open_project", path=str(gpr))
        f = info["format"]
        pdb = f["programDb"]
        check(pdb["min"] == 32 and pdb["max"] == 32 and pdb["current"] == 33,
              f"programDb {pdb}: the fixture is a 12.1.4 project (32), this engine 33")
        check(f["upgradeRequired"] is True and f["oneWay"] is True,
              f"an older project must say upgradeRequired and oneWay: {f}")
        check(f["newerThanEngine"] is False and f["programsScanned"] == 1 and
              f["truncated"] is False, f"{f}")
        check(f["engine"]["hydraVersion"] and f["engine"]["ghidraVersion"], f"engine {f}")
        dtdb = f["dataTypeDb"]
        check(dtdb and dtdb["current"] == 3 and dtdb["min"] == dtdb["max"] and
              dtdb["min"] <= 3, f"the data type database version stored by 12.1.4: {dtdb}")
        for cmd in ("project", "projects", "status"):
            r = s.call(cmd)
            blocks = [p.get("format") for p in (r["projects"] if "projects" in r else [r])]
            check(blocks and all(b == f for b in blocks), f"{cmd}: format differs: {blocks}")
        check(info["fork"] is None, f"{info}")
    with v2(c, d, "fmt2") as s2:
        i2 = s2.call("open_project", path=str(gpr))
        check("format" not in i2, f"a protocol 2 reply has v3 keys: {list(i2)}")
        check("format" not in s2.call("status")["projects"][0], "status format at protocol 2")
    d.stop()
    check(tree_digest(gpr.parent) == before, "format wrote to the project")
    note = f"12.1.4 fixture: programDb {pdb['min']}->{pdb['current']}, dataTypeDb {dtdb['min']}->3"
    if c.a.exe:
        cur = c.copy_fixture("e2-fmt-cur")
        d = c.daemon("e2-fmt2", keepWarm=0)
        with v3(c, d, "fmt") as s:
            f2 = s.call("open_project", path=str(cur))["format"]
        d.stop()
        check(f2["upgradeRequired"] is False and f2["programDb"]["min"] == 33 and
              f2["dataTypeDb"]["min"] == 3, f"a current-format project: {f2}")
        note += "; current-format project: upgradeRequired false"
    return note


def t_format_truncated(c):
    """3.4: a scan stops at 64 programs. Then ``upgradeRequired`` and ``oneWay`` are null (unknown,
    never false), because program 65 may be older: only a scan that read every header may say
    false. A project with fewer programs still says false."""
    cap = 64
    d = c.daemon("e2-trunc", keepWarm=0)
    base = c.work / "e2-trunc"
    with v3(c, d, "trunc") as s:
        need_v3(s)
        gpr = c.make_project(s, base, "Many")
        s.call("open_project", path=str(gpr), writable=True)
        blob = base / "tiny.bin"
        blob.write_bytes(os.urandom(256))
        for i in range(cap + 1):
            s.call("import", file=str(blob), name=f"p{i:03d}", duplicate=True, wait=120000,
                   **dt.RAW_LANG)
            if i == cap - 1:
                s.call("save")
                f = s.call("project")["format"]
                check(f["programsScanned"] == cap and f["truncated"] is False and
                      f["upgradeRequired"] is False, f"exactly {cap} programs: {f}")
        s.call("save")
        f = s.call("project")["format"]
        check(f["programsScanned"] == cap and f["truncated"] is True, f"{f}")
        check(f["upgradeRequired"] is None and f["oneWay"] is None,
              f"a truncated scan must not say false: {f}")
        s.call("close_project")
    d.stop()
    return f"{cap + 1} programs: scanned {cap}, truncated, upgradeRequired null (and false at {cap})"


def t_folder_singletons(c):
    """A folder carries one ``backup.json`` and one ``SEALED.json``. A second backup into a folder
    that holds one fails and leaves the first (manifest, marker, project) as it was; sealing a
    second project of that folder is refused and does not replace the first marker; unsealing the
    second does not delete the first's marker."""
    gpr = legacy_copy(c, "e2-single")
    dest = c.work / "e2-single-dest"
    d = c.daemon("e2-single", keepWarm=0)
    with v3(c, d, "single") as s:
        need_v3(s)
        pid = s.call("open_project", path=str(gpr))["id"]
        backup(c, s, pid, dest, name="first")
        mf, mk = dest / "backup.json", dest / "SEALED.json"
        before = (sha_file(mf), sha_file(mk), tree_digest(dest))
        check(not manifest_problems(dest), f"the first backup: {manifest_problems(dest)}")
        e = expect_error("failed", backup, c, s, pid, dest, name="second")
        check("backup.json" in str(e), f"the refusal names the file: {e}")
        left = sorted(os.listdir(dest))
        check(not [n for n in left if STAGING.match(n)] and "second.gpr" not in left and
              "second.rep" not in left, f"a refused second backup left {left}")
        check((sha_file(mf), sha_file(mk), tree_digest(dest)) == before,
              "the first backup changed")
        # a plain fork of another name may share the folder; sealing it must not take the marker
        s.call("fork_project", project=pid, path=str(dest), name="other", purpose="fork",
               open=False, wait=120000)
        e = expect_error("conflict", s.call, "seal_project", project=str(dest / "other.gpr"))
        check((e.details or {}).get("reason") == "marker_foreign", f"details {e.details}")
        check(sha_file(mk) == before[1], "the first project's marker was replaced")
        s.call("seal_project", project=str(dest / "other.gpr"), unseal=True, force=True)
        check(sha_file(mk) == before[1], "unsealing the second project deleted the first's marker")
        # the publish pre-check itself (review round 2): a writable SEALED.json of a plain fork,
        # no backup.json. The read-only backup.json above also refuses a second backup, so only
        # this folder proves that ProjectFork.publish never replaces an existing marker.
        dest2 = c.work / "e2-single-dest2"
        if dest2.exists():
            rmtree(dest2)
        dest2.mkdir(parents=True)
        s.call("fork_project", project=pid, path=str(dest2), name="plain", purpose="fork",
               open=False, wait=120000)
        s.call("seal_project", project=str(dest2 / "plain.gpr"))
        mk2 = dest2 / "SEALED.json"
        check(mk2.is_file() and not (dest2 / "backup.json").exists(),
              f"the setup: a marker and no manifest: {sorted(os.listdir(dest2))}")
        os.chmod(mk2, 0o666)  # the pre-check must hold even when the marker is writable
        before2 = (sha_file(mk2), tree_digest(dest2))
        e = expect_error("failed", backup, c, s, pid, dest2, name="second")
        check("SEALED.json" in str(e), f"the refusal names the marker: {e}")
        left = sorted(os.listdir(dest2))
        check(not [n for n in left if STAGING.match(n)] and
              not [n for n in left if n.startswith("second.")],
              f"a backup refused by a foreign marker left {left}")
        check((sha_file(mk2), tree_digest(dest2)) == before2,
              "the marker (or the folder) changed under a refused backup")
    d.stop()
    return "second backup refused (manifest, and a writable marker alone) and the first untouched; foreign marker refused, kept on unseal"


# ---- the upgrade gate --------------------------------------------------------------------------

def t_upgrade_gate(c):
    notes = []
    # 1. a canonical project, no backup: refused with both vocabularies
    gpr = legacy_copy(c, "e2-gate1")
    d = c.daemon("e2-gate", keepWarm=0)
    with v3(c, d, "g3") as s:
        need_v3(s)
        pid = s.call("open_project", path=str(gpr), writable=True)["id"]
        e = expect_error("backup_required", open_up, s)
        check(e.details["project"] == pid and e.details["program"].endswith(PROGRAM) and
              e.details["format"]["programDb"]["min"] == 32, f"details {e.details}")
        nxt = last_error(s).get("next") or {}
        check(nxt.get("cmd") == "fork_project" and nxt.get("purpose") == "backup" and
              nxt.get("open") is False, f"next {nxt}")
        s.call("close_project", discard=True)
    with v2(c, d, "g2") as s2:
        s2.call("open_project", path=str(gpr), writable=True)
        e = expect_error("conflict", open_up, s2)
        check(e.details.get("reason") == "backup_required", f"v2 details {e.details}")
        s2.call("close_project", discard=True)
    notes.append("canonical: backup_required (v3, with next) / conflict reason backup_required (v2)")

    # 2. a read-only open (and the upgrade cache) needs no backup and writes nothing
    ro = legacy_copy(c, "e2-gate-ro")
    before = tree_digest(ro.parent)
    with v3(c, d, "ro") as s:
        s.call("open_project", path=str(ro))
        r = s.call("open_program", path=PROGRAM, wait=True)
        check(r["mode"] == "read_only", f"{r.get('mode')}")
        s.call("prepare_upgrade")
        s.call("close_project")
    d.stop()
    check(tree_digest(ro.parent) == before, "a read-only path wrote to the source tree")
    notes.append("read-only open + upgrade cache: no backup needed, source tree hash unchanged")

    # 3. a good backup opens; the first save stamps; every defective backup is refused
    canon_gpr = legacy_copy(c, "e2-gate2")
    bdir = c.work / "e2-gate-backups"
    if bdir.exists():
        rmtree(bdir)
    d = c.daemon("e2-gate-b", keepWarm=0)
    with v3(c, d, "b") as s:
        pid = s.call("open_project", path=str(canon_gpr))["id"]
        r = backup(c, s, pid, bdir / "good")
        check(r["purpose"] == "backup" and r["project"] is None and r["manifest"]["verified"],
              f"{r}")
        s.call("close_project")
        good = bdir / "good"
        check(not manifest_problems(good), f"the engine's backup does not verify: "
              f"{manifest_problems(good)}")
        gm = good / "backup.json"
        # the refusals: the same project, a backup that is wrong in one way each
        cases = {
            "unverified": lambda m, dd: m["verify"].update(ok=False) or True,
            "self_hash": lambda m, dd: m.update(purpose="edited after signing") and False,
            "revision": lambda m, dd: m["source"].update(revision="0123456789abcdef") or True,
            "file_size": lambda m, dd: (dd / m["files"][0]["path"]).write_bytes(b"short") and False,
            "file_missing": lambda m, dd: (dd / m["files"][-1]["path"]).unlink() and False,
        }
        if True:
            for reason, edit in cases.items():
                mf = variant(good, bdir / f"bad-{reason}", edit)
                # a fresh copy each time: a writable open rewrites the index backups, so the same
                # project is at another revision the second time
                s.call("open_project", path=str(legacy_copy(c, f"e2-gate-v-{reason}")),
                       writable=True)
                e = expect_error("backup_required", open_up, s, backup_path=mf)
                check((e.details.get("backupCheck") or {}).get("reason") == reason,
                      f"{reason}: {e.details.get('backupCheck')}")
                s.call("close_project", discard=True)
        notes.append("refused: " + ", ".join(cases))
        # stale: the project changed after the backup (a touched file moves its revision)
        stale_gpr = legacy_copy(c, "e2-gate-stale")
        s.call("open_project", path=str(stale_gpr))
        stale_b = backup(c, s, s.call("project")["id"], bdir / "stale")
        s.call("close_project")
        idx = next((stale_gpr.parent / "legacy.rep").rglob("~index.dat"))
        t = idx.stat().st_mtime + 3
        os.utime(idx, (t, t))
        s.call("open_project", path=str(stale_gpr), writable=True)
        e = expect_error("backup_required", open_up, s, backup_path=stale_b["manifest"]["path"])
        check((e.details.get("backupCheck") or {}).get("reason") == "revision",
              f"stale: {e.details.get('backupCheck')}")
        s.call("close_project", discard=True)
        # foreign: a backup of another project (a different revision)
        foreign = legacy_copy(c, "e2-gate-foreign")
        idx = next((foreign.parent / "legacy.rep").rglob("~index.dat"))
        t = idx.stat().st_mtime + 7
        os.utime(idx, (t, t))
        s.call("open_project", path=str(foreign))
        fb = backup(c, s, s.call("project")["id"], bdir / "foreign")
        s.call("close_project")
        s.call("open_project", path=str(legacy_copy(c, "e2-gate-foreign-open")), writable=True)
        e = expect_error("backup_required", open_up, s, backup_path=fb["manifest"]["path"])
        check((e.details.get("backupCheck") or {}).get("reason") == "revision",
              f"foreign: {e.details.get('backupCheck')}")
        notes.append("stale and foreign-revision backups refused")
        # the good one, on a copy that nothing has opened yet
        s.call("open_project", path=str(legacy_copy(c, "e2-gate-good")), writable=True)
        r = open_up(s, gm)
        check(r["mode"] == "writable", f"{r}")
        sv = s.call("save")
        check(sv.get("saved") is True and "upgrade from 32" in sv.get("upgradeStamp", "") and
              "backup " + json.loads(gm.read_text())["id"] in sv["upgradeStamp"],
              f"the save after the upgrade must stamp its comment: {sv}")
        check(s.call("save").get("upgradeStamp") is None, "the stamp repeats")
        s.call("close_project", discard=True)
        notes.append(f"good backup opens; save stamps '{sv['upgradeStamp'][:60]}'")
    d.stop()

    # 4. exemptions and what counts as canonical (D12)
    src = legacy_copy(c, "e2-gate-src")
    d = c.daemon("e2-gate-x", keepWarm=0)
    with v3(c, d, "x") as s:
        pid = s.call("open_project", path=str(src))["id"]
        # a fork is exempt
        f1 = s.call("fork_project", project=pid, path=str(c.work / "e2-gate-forks"), name="F1",
                    mode="full", wait=60000)
        sc_path, sc = sidecar_of(f1["gpr"])
        check(sc["purpose"] == "fork" and sc["disposable"] is True and sc["state"] == "complete",
              f"fork sidecar {sc}")
        r = open_up(s, project=f1["project"])
        check(r["mode"] == "writable", "a disposable fork must open without a backup")
        s.call("close_program", discard=True, program=r["key"])
        s.call("close_project", project=f1["project"], discard=True)
        # a hydra.2/3 fork: a sidecar without the new fields is disposable
        f2 = s.call("fork_project", project=pid, path=str(c.work / "e2-gate-forks"), name="F2",
                    mode="full", wait=60000, open=False)
        p2, sc2 = sidecar_of(f2["gpr"])
        for k in ("purpose", "disposable"):
            sc2.pop(k, None)
        p2.write_text(json.dumps(sc2))
        s.call("open_project", path=f2["gpr"], writable=True)
        r = open_up(s, project=s.call("project")["id"])
        check(r["mode"] == "writable", "a fork without 'disposable' (hydra.2/3) must be exempt")
        s.call("close_project", discard=True)
        # canonical: no sidecar, an unparseable one, disposable:false, a generation
        for tag, mutate in (("nosidecar", lambda p: p.unlink()),
                            ("garbage", lambda p: p.write_text("{not json")),
                            ("notdisposable", lambda p: p.write_text(json.dumps(
                                {"format": 1, "kind": "ghidra-session-fork", "disposable": False})))):
            fk = s.call("fork_project", project=pid, path=str(c.work / "e2-gate-forks"),
                        name="C-" + tag, mode="full", wait=60000, open=False)
            mutate(pathlib.Path(fk["sidecar"]))
            s.call("open_project", path=fk["gpr"], writable=True)
            expect_error("backup_required", open_up, s, project=s.call("project")["id"])
            s.call("close_project", discard=True)
        gen = s.call("fork_project", project=pid, path=str(c.work / "e2-gate-forks"), name="Gen",
                     purpose="generation", mode="full", wait=60000)
        expect_error("backup_required", open_up, s, project=gen["project"])
        s.call("close_project", project=gen["project"], discard=True)
        notes.append("exempt: fork, fork without 'disposable'; canonical: no/torn/disposable:false "
                     "sidecar, generation")
    d.stop()

    # 5. the switch
    off_gpr = legacy_copy(c, "e2-gate-off")
    d = c.daemon("e2-gate-off", keepWarm=0, engine={"requireBackupForUpgrade": False})
    with v3(c, d, "off") as s:
        check(s.hello["policy"].get("requireBackupForUpgrade") is False,
              f"policy {s.hello.get('policy')}")
        s.call("open_project", path=str(off_gpr), writable=True)
        r = open_up(s)
        check(r["mode"] == "writable", "requireBackupForUpgrade=false must turn the gate off")
        s.call("close_project", discard=True)
    d.stop()
    notes.append("requireBackupForUpgrade=false: off")
    return "; ".join(notes)


# ---- backups under fault -----------------------------------------------------------------------

def t_backup_fault(c):
    notes = []
    src = make_source(c, "bk", files=12, mb=8)
    before = tree_digest(src.parent)
    base = c.work / "e2-bkfault"
    if base.exists():
        rmtree(base)
    base.mkdir(parents=True)
    kills = int(os.environ.get("E2_KILLS", "6"))
    rng = random.Random(20261028)

    # 1. the daemon killed mid-backup: never a folder with a verifying manifest and no project
    states = []
    for i in range(kills):
        dest = base / f"k{i}"
        mode = ("staging", "rep", "random")[i % 3]
        d = c.daemon(f"e2-bk-kill{i}", keepWarm=0)
        s = v3(c, d, "k")
        pidn = int(d.read_endpoint()["pid"])
        stop = threading.Event()

        def killer():
            t0 = time.perf_counter()
            if mode == "random":
                time.sleep(rng.uniform(0.0, 0.8))
            else:
                while not stop.is_set() and time.perf_counter() - t0 < 40:
                    try:
                        ents = os.listdir(dest)
                    except OSError:
                        ents = []
                    if (mode == "staging" and any(STAGING.match(e) for e in ents)) or \
                            (mode == "rep" and "B.rep" in ents):
                        break
                if stop.is_set():
                    return
                time.sleep(rng.choice([0, 0.01, 0.03, 0.08, 0.2]))
            c.gs._kill_pid(pidn)

        th = threading.Thread(target=killer, daemon=True)
        th.start()
        try:
            s.call("fork_project", project=str(src), path=str(dest), name="B", purpose="backup",
                   open=False, verify="hash", mode="full", wait=120000)
            answered = True
        except Exception:  # noqa: BLE001
            answered = False
        stop.set()
        if not answered or True:
            c.gs._kill_pid(pidn)
        th.join(5)
        d.kill()
        names = sorted(os.listdir(dest)) if dest.exists() else []
        has_gpr = "B.gpr" in names
        problems = manifest_problems(dest, hash_files=True) if "backup.json" in names else None
        if "backup.json" in names:
            check(has_gpr and not problems,
                  f"kill {i} ({mode}): a backup.json without a verifying backup: gpr={has_gpr} "
                  f"{problems}")
            states.append("complete")
        else:
            check(not has_gpr or "B.fork.json" in names, f"kill {i} ({mode}): {names}")
            states.append("absent" if not has_gpr else "gpr-no-manifest")
            check(not has_gpr, f"kill {i} ({mode}): a .gpr without its backup.json: {names}")
        # the retry on a fresh daemon succeeds (or the backup was complete: the ordinary conflict)
        d2 = c.daemon(f"e2-bk-retry{i}", keepWarm=0)
        with v3(c, d2, "retry") as s2:
            if "backup.json" in names:
                expect_error("conflict", s2.call, "fork_project", project=str(src),
                             path=str(dest), name="B", purpose="backup", open=False, mode="full")
            else:
                r = s2.call("fork_project", project=str(src), path=str(dest), name="B",
                            purpose="backup", open=False, verify="hash", mode="full", wait=120000)
                check(r["manifest"]["verified"], f"retry {i}: {r}")
        d2.stop()
        check(not manifest_problems(dest), f"after the retry {i}: {manifest_problems(dest)}")
        check(not [e for e in os.listdir(dest) if STAGING.match(e)],
              f"kill {i}: staging folder left: {os.listdir(dest)}")
    notes.append(f"{kills} kills ({', '.join(sorted(set(states)))}): no manifest without a "
                 f"complete backup; every retry verified")

    # 2. one corrupted byte: a client re-hash refuses it, the engine's gate passes it by design
    gpr = legacy_copy(c, "e2-bkfault-legacy")
    d = c.daemon("e2-bk-corrupt", keepWarm=0)
    with v3(c, d, "corrupt") as s:
        pid = s.call("open_project", path=str(gpr))["id"]
        r = backup(c, s, pid, base / "corrupt")
        s.call("close_project")
        bdir = base / "corrupt"
        check(not manifest_problems(bdir), "the fresh backup does not verify")
        victim = bdir / "legacy.rep" / "idata" / "00" / "~00000000.db" / "db.1.gbf"
        os.chmod(victim, 0o666)
        flip_byte(victim, 100)
        probs = manifest_problems(bdir)
        check(any("sha256" in p for p in probs), f"a client re-hash must refuse: {probs}")
        s.call("open_project", path=str(gpr), writable=True)
        # the engine checks the manifest, the self hash, the revision and the sizes - not the
        # content. This is the documented limit (3.4): the gate is a guard, the client re-hashes.
        rr = open_up(s, bdir / "backup.json")
        check(rr["mode"] == "writable", "the engine gate was expected to pass a same-size corruption")
        s.call("close_project", discard=True)
    d.stop()
    notes.append("one flipped byte: client re-hash refuses; engine gate passes (documented)")

    # 3. a failed verify leaves no project, no manifest, no staging folder
    fv = base / "failverify"
    d = c.daemon("e2-bk-fv", keepWarm=0)
    fired = threading.Event()
    stop = threading.Event()
    last_name = max((p for p in src.parent.rglob("*") if p.is_file()),
                    key=lambda p: str(p.relative_to(src.parent)).replace("\\", "/"))
    rel_last = last_name.relative_to(src.parent)

    def corrupt_staged():
        t0 = time.perf_counter()
        while not stop.is_set() and time.perf_counter() - t0 < 60:
            try:
                for e in os.listdir(fv):
                    if STAGING.match(e):
                        p = fv / e / rel_last
                        # the copy is complete when the last file is there with its full size
                        if p.is_file() and p.stat().st_size == last_name.stat().st_size and \
                                (fv / e / "Src.rep" / "ballast" / "b11.bin").is_file() and \
                                (fv / e / "Src.rep" / "ballast" / "b11.bin").stat().st_size == \
                                (src.parent / "Src.rep" / "ballast" / "b11.bin").stat().st_size:
                            time.sleep(0.02)
                            flip_byte(p, 0)
                            fired.set()
                            return
            except OSError:
                pass
            time.sleep(0.002)

    th = threading.Thread(target=corrupt_staged, daemon=True)
    th.start()
    with v3(c, d, "fv") as s:
        e = expect_error("failed", s.call, "fork_project", project=str(src), path=str(fv),
                         name="B", purpose="backup", open=False, verify="hash", mode="full",
                         wait=120000)
        stop.set()
        th.join(5)
        check(fired.is_set(), "the staged copy was not corrupted in time (the test is void)")
        v = (e.details or {}).get("verify") or {}
        mism = v.get("mismatches") or []
        want = str(rel_last).replace("\\", "/").replace("Src", "B", 1)
        got = [str(m.get("path", "")).replace("\\", "/") for m in mism]
        check(v.get("ok") is False and 1 <= len(mism) <= 20 and any(g.endswith(want) for g in got),
              f"details.verify {e.details}")
        left = sorted(os.listdir(fv)) if fv.exists() else []
        check(not any(n in left for n in ("B.gpr", "B.rep", "backup.json", "B.fork.json")) and
              not [n for n in left if STAGING.match(n)], f"a failed backup left {left}")
        # and the retry (nothing corrupts it now) succeeds
        r = s.call("fork_project", project=str(src), path=str(fv), name="B", purpose="backup",
                   open=False, verify="hash", mode="full", wait=120000)
        check(r["manifest"]["verified"] and not manifest_problems(fv), "retry after failed verify")
    d.stop()
    notes.append(f"failed verify: {len(v['mismatches'])} mismatch(es) reported "
                 f"(first {v['mismatches'][0]['path']}), nothing left, retry verified")
    check(tree_digest(src.parent) == before, "the backup source was written (K1)")
    return "; ".join(notes)


# ---- the manifest's canonical form -------------------------------------------------------------

def t_manifest_canonical(c):
    vec = json.loads(VECTOR.read_text(encoding="utf-8"))
    obj = vec["object"]
    # the vector, in Python
    check(sha(canon(obj)) == vec["selfSha256"], "the vector's selfSha256 does not reproduce")
    check(sha(canon(obj["files"])) == vec["filesetSha256"], "the vector's filesetSha256")
    notes = ["vector reproduces in Python"]
    gpr = legacy_copy(c, "e2-canon")
    d = c.daemon("e2-canon", keepWarm=0)
    with v3(c, d, "canon") as s:
        # the vector in Java: a manifest the engine can only call 'wrong revision' if its own
        # canonical form gives the vector's hash (the checks run format, kind, verify, self hash,
        # revision in that order); the same with one character changed is a self-hash mismatch
        vdir = c.work / "e2-canon-vector"
        if vdir.exists():
            rmtree(vdir)
        vdir.mkdir(parents=True)
        for variant_name, edit in (("good", None), ("bad", "purpose")):
            m = json.loads(json.dumps(obj))
            m["selfSha256"] = vec["selfSha256"]
            if edit:
                m[edit] = m[edit] + "x"
            (vdir / f"{variant_name}.json").write_bytes(canon(m))
        s.call("open_project", path=str(gpr), writable=True)
        e = expect_error("backup_required", open_up, s, backup_path=vdir / "good.json")
        check((e.details.get("backupCheck") or {}).get("reason") == "revision",
              f"the engine's canonical form differs from the vector: {e.details.get('backupCheck')}")
        e = expect_error("backup_required", open_up, s, backup_path=vdir / "bad.json")
        check((e.details.get("backupCheck") or {}).get("reason") == "self_hash",
              f"{e.details.get('backupCheck')}")
        s.call("close_project", discard=True)
        notes.append("vector reproduces in Java (self hash accepted, a changed character refused)")
        # the engine writes a manifest with awkward paths; Python verifies it
        pid = s.call("open_project", path=str(gpr))["id"]
        awk = gpr.parent / "legacy.rep" / "ballast-\u00e9\u4e2d\u6587\U0001F600 \u2028 \u2029 &'.bin"
        awk.write_bytes(b"canonical form")
        r = backup(c, s, pid, c.work / "e2-canon-backup")
        s.call("close_project")
        bd = c.work / "e2-canon-backup"
        names = [f["path"] for f in json.loads((bd / "backup.json").read_text("utf-8"))["files"]]
        check(any("\u2028" in n and "\U0001F600" in n for n in names), f"awkward name missing: {names}")
        raw = (bd / "backup.json").read_bytes()
        m = json.loads(raw.decode("utf-8"))
        check(raw == canon(m), "backup.json is not written in canonical form")
        check(b"\xe2\x80\xa8" in raw, "U+2028 must be written literally as UTF-8")
        check(not manifest_problems(bd), manifest_problems(bd))
        notes.append("engine-written manifest with U+2028, CJK and U+1F600 verified by Python")
        # Python writes one, the engine accepts it (writer hydralysis)
        pm = json.loads(raw.decode("utf-8"))
        pm["writer"] = "hydralysis"
        pm["id"] = "py-written"
        resign(pm)
        (bd / "py.json").write_bytes(canon(pm))
        s.call("open_project", path=str(gpr), writable=True)
        rr = open_up(s, bd / "py.json")
        check(rr["mode"] == "writable", "the engine refused a manifest that Python wrote")
        s.call("close_project", discard=True)
        notes.append("Python-written manifest accepted by the engine's gate")
    d.stop()
    return "; ".join(notes)


# ---- the fork report ---------------------------------------------------------------------------

def _fs_of(path):
    """The file system of the volume that holds ``path`` (``NTFS``, ``ReFS``, ...), or ``?``."""
    if os.name != "nt":
        return "?"
    import ctypes
    root = os.path.splitdrive(os.path.abspath(str(path)))[0] + "\\"
    buf = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(root, None, 0, None, None, None, buf, 64)
    return buf.value if ok else "?"


def t_fork_report(c):
    src = legacy_copy(c, "e2-report")
    notes = []
    base = c.work / "e2-report-out"
    if base.exists():
        rmtree(base)
    fs = _fs_of(base.parent)
    d = c.daemon("e2-report", keepWarm=0)
    with v3(c, d, "rep") as s:
        need_v3(s)
        pid = s.call("open_project", path=str(src))["id"]
        r = s.call("fork_project", project=pid, path=str(base / "plain"), name="P", mode="full",
                   wait=60000)
        check(r["purpose"] == "fork" and r["cost"]["files"] > 3 and "manifest" not in r and
              isinstance(r["warnings"], list), f"{list(r)}")
        if fs == "NTFS":
            check(r["method"] == "copy" and r["cost"]["cloneCapable"] is False and
                  any("full copy" in w for w in r["warnings"]),
                  f"NTFS: a fork is a copy with a warning: {r['method']} {r['warnings']}")
            notes.append(f"{fs}: method copy + warning")
        b = backup(c, s, pid, base / "bk")
        check(b["manifest"]["verified"] is True and b["cost"]["sameVolume"] is True and
              b["project"] is None and "info" not in b, f"{b}")
        man = json.loads((base / "bk" / "backup.json").read_text("utf-8"))
        check(man["copy"]["independent"] is False and man["writer"] == "engine" and
              man["verify"]["level"] == "hash" and man["source"]["revision"] == r["baseRevision"],
              f"{man['copy']}")
        check(any("volume" in w for w in b["warnings"]), f"backup warnings {b['warnings']}")
        _, sc = sidecar_of(b["gpr"])
        check(sc["purpose"] == "backup" and sc["disposable"] is False and sc["state"] == "complete"
              and sc["manifest"]["sha256"] == sha_file(base / "bk" / "backup.json"), f"{sc}")
        check((base / "bk" / "SEALED.json").is_file(), "a verified backup is sealed (SEALED.json)")
        notes.append("fork reply: purpose, cost, warnings; backup reply: manifest, no project")
        # a sidecar nobody can finish (a handle holder) is said in the reply (Windows)
        s.call("close_project")
    d.stop()

    # a protocol 2 reply keeps its keys; the sidecar gains purpose and disposable (V7)
    d = c.daemon("e2-report-v2", keepWarm=0)
    with v2(c, d, "rep2") as s:
        r2 = s.call("fork_project", path=str(base / "v2"), name="V", project=str(src),
                    mode="full", purpose="backup", open=False, verify="none")
        check("purpose" not in r2 and "cost" not in r2 and "warnings" not in r2 and
              r2["project"] and "info" in r2, f"a v2 reply changed: {list(r2)}")
        _, sc = sidecar_of(r2["gpr"])
        check(sc["purpose"] == "fork" and sc["disposable"] is True and sc["state"] == "complete",
              f"v2 sidecar {sc}")
        check(not (base / "v2" / "backup.json").exists(), "a v2 request must not make a backup")
    d.stop()
    notes.append("v2: reply unchanged, purpose/open ignored, sidecar gains purpose+disposable")

    # ReFS: on the Dev Drive a fork is a clone and a fresh candidate has its source's revision
    refs_root = os.environ.get("HYDRA_REFS_SCRATCH")
    if not refs_root:
        return "; ".join(notes) + "; ReFS part skipped: HYDRA_REFS_SCRATCH (a directory on a ReFS volume) is not set"
    scratch = pathlib.Path(refs_root) / f"E2-{uuid.uuid4().hex[:8]}"
    try:
        scratch.mkdir(parents=True, exist_ok=False)
    except OSError as e:
        return "; ".join(notes) + f"; ReFS part skipped: cannot create {scratch}: {e}"
    try:
        if _fs_of(scratch) != "ReFS":
            return "; ".join(notes) + f"; ReFS part skipped: {scratch} is {_fs_of(scratch)}"
        rsrc = scratch / "src"
        dt.clone_tree(src.parent, rsrc)
        rg = next(rsrc.glob("*.gpr"))
        d = c.daemon("e2-report-refs", keepWarm=0)
        with contextlib.ExitStack() as stack, v3(c, d, "refs") as s:
            stack.callback(d.stop)  # the daemon holds the scratch folder: stop it before the delete
            ri = s.call("open_project", path=str(rg))
            r = s.call("fork_project", project=ri["id"], path=str(scratch / "cand"), name="legacy",
                       purpose="generation", mode="auto", wait=60000)
            check(r["method"] == "clone" and r["cost"]["cloneCapable"] is True and
                  r["cost"]["destinationFileSystem"] == "ReFS", f"ReFS: {r['method']} {r['cost']}")
            cand_rev = r["info"]["revision"]
            check(cand_rev == r["baseRevision"] == ri["revision"],
                  f"a freshly forked candidate must have its source's Revision.of: source "
                  f"{ri['revision']}, base {r['baseRevision']}, candidate {cand_rev}")
            b = backup(c, s, ri["id"], scratch / "bk", mode="auto")
            man = json.loads((scratch / "bk" / "backup.json").read_text("utf-8"))
            check(b["method"] == "clone" and man["copy"]["independent"] is False and
                  man["source"]["revision"] == cand_rev and any("shares blocks" in w
                                                                for w in b["warnings"]),
                  f"ReFS backup {b['method']} {b['warnings']}")
            s.call("close_project", project=r["project"], discard=True)
        d.stop()
        notes.append(f"ReFS ({_fs_of(scratch)}): clone, candidate Revision.of == source "
                     f"({cand_rev}), backup revision equal, 'shares blocks' warning")
    finally:
        # the scratch folder is ours to delete; the daemon's handles may outlive its stop briefly
        for _ in range(40):
            rmtree(scratch)
            if not scratch.exists():
                break
            time.sleep(0.5)
        check(not scratch.exists(), f"could not delete the ReFS scratch folder {scratch}")
    return "; ".join(notes)


# ---- sealing -----------------------------------------------------------------------------------

def _gen(c, s, tag, with_backup=True):
    """A legacy copy, its backup, and a generation candidate of it (open, writable)."""
    gpr = legacy_copy(c, f"e2-{tag}-src")
    pid = s.call("open_project", path=str(gpr))["id"]
    bdir = c.work / f"e2-{tag}-backup"
    if bdir.exists():
        rmtree(bdir)
    b = backup(c, s, pid, bdir) if with_backup else None
    gdir = c.work / f"e2-{tag}-gen"
    if gdir.exists():
        rmtree(gdir)
    # the same name as the source: Revision.of keys the files by name, so a renamed copy is at
    # another revision (the property of 4.6 step 4 is for a fork that keeps its name)
    g = s.call("fork_project", project=pid, path=str(gdir), name="legacy", purpose="generation",
               mode="full", wait=60000)
    return gpr, b, g, gdir


def t_candidate_then_seal(c):
    d = c.daemon("e2-seal", keepWarm=0)
    notes = []
    with v3(c, d, "seal") as s:
        need_v3(s)
        gpr, b, g, gdir = _gen(c, s, "cts")
        _, sc = sidecar_of(g["gpr"])
        check(sc["purpose"] == "generation" and sc["disposable"] is False and
              sc["state"] == "candidate" and g["purpose"] == "generation", f"{sc}")
        # the candidate is writable by its publisher, with the backup of the gate
        r = open_up(s, b["manifest"]["path"], project=g["project"])
        check(r["mode"] == "writable", "the first writable open of a candidate is refused")
        fns = s.call("functions", limit=5, program=r["key"])["functions"]
        s.call("rename", program=r["key"], address=fns[0]["address"], name="renamed_by_publisher")
        sv = s.call("save", program=r["key"])
        check(sv["saved"] is True, f"{sv}")
        # seal refuses an open writable project
        e = expect_error("conflict", s.call, "seal_project", project=g["project"])
        check(e.details.get("reason") == "open_writable", f"{e.details}")
        s.call("close_program", program=r["key"])
        s.call("close_project", project=g["project"])
        # a sidecar with disposable:false and no state: non-disposable, not sealed
        # sealing
        sealed = s.call("seal_project", project=g["gpr"])
        check(sealed["sealed"] is True and set(sealed["witnesses"]) >= {"marker", "sidecar"},
              f"{sealed}")
        _, sc2 = sidecar_of(g["gpr"])
        check(sc2["state"] == "complete", f"the sidecar must say complete: {sc2}")
        check((gdir / "SEALED.json").is_file(), "no SEALED.json")
        held = tree_digest(gdir)
        import oracle  # X0's corruption oracle: K1 (the sealed tree), K1u (the union), K2 (headers)
        snap = oracle.seal_snapshot(gdir)
        w = oracle.seal_witnesses(g["gpr"], c.state)
        check(all(w.values()), f"the three records of D66 must all say sealed: {w}")
        r1u = oracle.check_k1u(g["gpr"], c.state)
        r2 = oracle.check_k2(gdir)
        check(not r1u.findings and not r2.findings, f"oracle: {r1u.findings} {r2.findings}")
        # every writable path is refused
        e = expect_error("sealed", s.call, "open_project", path=g["gpr"], writable=True)
        check(last_error(s).get("next", {}).get("cmd") == "fork_project", f"next {last_error(s)}")
        ro = s.call("open_project", path=g["gpr"])
        check(ro["writable"] is False, f"{ro}")
        rp = s.call("open_program", path=PROGRAM, project=ro["id"])
        expect_error("sealed", s.call, "open_program", path=PROGRAM, project=ro["id"],
                     writable=True)
        expect_error("sealed", s.call, "save", program=rp["key"])
        expect_error("sealed", s.call, "analyze", program=rp["key"])
        expect_error("sealed", s.call, "rename", program=rp["key"], address="0x140001000",
                     name="nope")
        s.call("close_project", project=ro["id"])
        notes.append("candidate writable, replay+save ok, seal refused while open, then sealed")
    with v2(c, d, "seal2") as s2:
        e = expect_error("conflict", s2.call, "open_project", path=g["gpr"], writable=True)
        check(e.details.get("reason") == "sealed" and e.details.get("suggestion", {}).get("cmd") ==
              "fork_project", f"v2: {e.details}")
        ro = s2.call("open_project", path=g["gpr"])
        s2.call("open_program", path=PROGRAM)
        e = expect_error("conflict", s2.call, "save")
        check(e.details.get("reason") == "sealed", f"v2 save: {e.details}")
        s2.call("close_project")
    d.stop()
    check(tree_digest(gdir) == held, "a refused path changed the sealed tree")
    rk1 = oracle.check_k1(gdir, snap, label="sealed generation")
    check(not rk1.findings, f"K1 (the sealed tree is unchanged): {rk1.findings}")
    notes.append("refused (v3 sealed / v2 conflict reason sealed): open_project, open_program, "
                 "save, analyze, rename; read-only works; tree hash equals the one at the seal")

    # disposable:false without a state is non-disposable (an upgrade needs the backup) but not sealed
    d = c.daemon("e2-seal-b", keepWarm=0)
    with v3(c, d, "seal") as s:
        gpr, b, g, gdir = _gen(c, s, "cts2", with_backup=False)
        s.call("close_project", project=g["project"], discard=True)
        p, sc = sidecar_of(g["gpr"])
        sc.pop("state")
        sc["purpose"] = "fork"
        p.write_text(json.dumps(sc))
        s.call("open_project", path=g["gpr"], writable=True)  # allowed: not sealed
        expect_error("backup_required", open_up, s, project=s.call("project")["id"])
        s.call("close_project", discard=True)
    d.stop()
    notes.append("disposable:false without state: upgrade refused (non-disposable), writable open allowed")
    return "; ".join(notes)


def t_seal_union(c):
    """K1u / X11 (D66): the predicate is the union of the registry record, the sidecar and
    SEALED.json."""
    d = c.daemon("e2-union", keepWarm=0)
    notes = []
    registry = pathlib.Path(c.state) / "seals"
    with v3(c, d, "union") as s:
        gpr, b, g, gdir = _gen(c, s, "union")
        s.call("close_project", project=g["project"], discard=True)
        s.call("seal_project", project=g["gpr"])
        sc_path, sc = sidecar_of(g["gpr"])
        recs = list(registry.glob("*.json")) if registry.is_dir() else []
        check(recs, f"no registry record in {registry}")
        digest0 = tree_digest(gdir)

        def refused(what):
            expect_error("sealed", s.call, "open_project", path=g["gpr"], writable=True)
            ro = s.call("open_project", path=g["gpr"])
            rp = s.call("open_program", path=PROGRAM, project=ro["id"])
            for cmd in ("save", "analyze"):
                expect_error("sealed", s.call, cmd, program=rp["key"])
            s.call("close_project", project=ro["id"])
            notes.append(what)

        sc["state"] = "candidate"
        sc_path.write_text(json.dumps(sc))
        refused("sidecar edited back to candidate: still sealed")
        sc_path.unlink()
        refused("sidecar deleted: still sealed")
        sc_path.write_text('{"format": 1, "kind": "ghidra-session-fork", "state": "comp')
        refused("sidecar torn: still sealed")
        marker = gdir / "SEALED.json"
        keep = marker.read_bytes()
        for r in recs:
            r.unlink()
        refused("registry record removed: SEALED.json alone still seals")
        # the registry alone seals when the marker and the sidecar are gone
        marker.unlink()
        s.call("seal_project", project=g["gpr"])  # writes all three again (a torn sidecar is replaced)
        marker.unlink()
        refused("marker and sidecar state gone: the registry record alone seals") \
            if sc_path.exists() else None
        # a SEALED.json copied from another project is ignored
        other = legacy_copy(c, "e2-union-other")
        (other.parent / "SEALED.json").write_bytes(keep)
        w = s.call("open_project", path=str(other), writable=True)
        check(w["writable"] is True, "a copied SEALED.json sealed another project")
        s.call("close_project", discard=True)
        notes.append("SEALED.json copied from another project is ignored")
        # unseal removes all three
        marker.write_bytes(keep)
        e = expect_error("bad_request", s.call, "seal_project", project=g["gpr"], unseal=True)
        un = s.call("seal_project", project=g["gpr"], unseal=True, force=True)
        check(un["sealed"] is False and not (gdir / "SEALED.json").exists() and
              not list(registry.glob("*.json")), f"unseal: {un}")
        w = s.call("open_project", path=g["gpr"], writable=True)
        check(w["writable"] is True, "unseal left the project sealed")
        s.call("close_project", discard=True)
        notes.append("unseal needs force and removes all three")
    d.stop()
    return "; ".join(notes)


# ---- the repair policy of the daemon (E8 wired, D42) -------------------------------------------

def _db_dir(gpr):
    rep = pathlib.Path(gpr).with_suffix(".rep")
    cands = [p for p in (rep / "idata").rglob("*.db") if p.is_dir() and list(p.glob("db.*.gbf"))]
    check(cands, f"no database folder below {rep}")
    return cands[0]


def _newest(dbdir):
    vs = sorted(int(m.group(1)) for p in dbdir.glob("db.*.gbf")
                for m in [re.fullmatch(r"db\.(\d+)\.gbf", p.name)] if m)
    return vs[-1]


def _poison(gpr):
    """db.N+1.gbf at full size with an all-zero header next to the intact db.N.gbf (the state a
    kill inside the old save window left)."""
    dbdir = _db_dir(gpr)
    n = _newest(dbdir)
    bad = dbdir / f"db.{n + 1}.gbf"
    shutil.copy2(dbdir / f"db.{n}.gbf", bad)
    os.chmod(bad, 0o666)
    with open(bad, "r+b") as f:
        f.write(b"\x00" * 512)
    return dbdir, n, bad


def t_repair_policy(c):
    """A zero-header fork end to end through the daemon, no -Dhydra.storage.repairRoots."""
    if not c.a.exe:
        return "skipped: needs --exe for a current-format project"
    notes = []
    base = c.copy_fixture("e2-repair")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("e2-repair", keepWarm=0)
    with v3(c, d, "repair") as s:
        need_v3(s)
        pid = s.call("open_project", path=str(base))["id"]
        # 1. a writable disposable fork: repaired at open, surfaced as repairs[]
        fk = s.call("fork_project", project=pid, path=str(c.work / "e2-repair-forks"), name="Fk",
                    mode="full", wait=60000, open=False)
        dbdir, n, bad = _poison(fk["gpr"])
        before_bytes = (dbdir / f"db.{n}.gbf").read_bytes()
        op = s.call("open_project", path=fk["gpr"], writable=True)
        pr = s.call("open_program", path=exe, project=op["id"], writable=True)
        reps = (op.get("repairs") or []) + (pr.get("repairs") or [])
        check(reps and reps[0]["newest"] == n + 1 and reps[0]["fallback"] == n,
              f"the fork was not repaired / not surfaced: open_project {op.get('repairs')}, "
              f"open_program {pr.get('repairs')}")
        q = dbdir / f"db.{n + 1}.gbf.quarantine" / f"db.{n + 1}.gbf"
        check(q.is_file() and not bad.exists(), "the bad file was not quarantined")
        check((dbdir / f"db.{n}.gbf").read_bytes() == before_bytes, "the intact version changed")
        s.call("close_project", project=op["id"], discard=True)
        notes.append(f"writable fork: db.{n + 1}.gbf quarantined, opened at db.{n}, repairs[] in "
                     f"the reply")
        # 2. the same fork opened read-only (a second poisoned fork): corrupt_newest, tree intact
        fk2 = s.call("fork_project", project=pid, path=str(c.work / "e2-repair-forks"), name="Fk2",
                     mode="full", wait=60000, open=False)
        _poison(fk2["gpr"])
        h0 = tree_digest(pathlib.Path(fk2["gpr"]).parent)
        e = None
        try:
            ro = s.call("open_project", path=fk2["gpr"])
            s.call("open_program", path=exe, project=ro["id"])
        except Exception as ex:  # noqa: BLE001
            e = ex
        check(e is not None and getattr(e, "code", "") == "corrupt_newest",
              f"a read-only open of a poisoned fork must answer corrupt_newest: {e!r}")
        check({"project", "program", "file", "repair"} <= set(e.details), f"{e.details}")
        check(tree_digest(pathlib.Path(fk2["gpr"]).parent) == h0,
              "the read-only open wrote to a poisoned fork")
        with contextlib.suppress(Exception):
            s.call("close_project", discard=True)
        notes.append("read-only open of a poisoned fork: corrupt_newest {project, program, file, "
                     "repair}, tree hash unchanged")
        # 3. the master (no sidecar), a generation candidate and a sealed backup: never written
        for tag, make in (("master", None), ("candidate", "generation"), ("sealed", "backup")):
            if make is None:
                gp = c.copy_fixture("e2-repair-" + tag)
                gp = gp / "Fixture.gpr" if gp.is_dir() else gp
            else:
                kw = dict(purpose=make, mode="full", wait=60000, open=False)
                if make == "backup":
                    kw["verify"] = "size"
                fz = s.call("fork_project", project=pid,
                            path=str(c.work / f"e2-repair-{tag}"), name="T", **kw)
                gp = fz["gpr"]
            _poison(gp)
            h0 = tree_digest(pathlib.Path(gp).parent)
            try:
                op = s.call("open_project", path=str(gp), writable=(tag != "sealed"))
                s.call("open_program", path=exe, project=op["id"], writable=(tag != "sealed"))
                raise Fail(f"{tag}: the poisoned newest version opened")
            except Fail:
                raise
            except Exception as ex:  # noqa: BLE001
                code = getattr(ex, "code", "")
                check(code == "corrupt_newest", f"{tag}: {code}: {ex}")
            check(tree_digest(pathlib.Path(gp).parent) == h0, f"{tag}: the open wrote to the tree")
            with contextlib.suppress(Exception):
                s.call("close_project", discard=True)
        notes.append("master, generation candidate and sealed backup: corrupt_newest, never written")
    with v2(c, d, "repair2") as s2:
        gp = c.copy_fixture("e2-repair-v2")
        _poison(gp)
        op = s2.call("open_project", path=str(gp))
        e = expect_error("failed", s2.call, "open_program", path=exe)
        check(str(e.message).startswith("corrupt_newest"), f"v2 keeps the failed message: {e}")
        notes.append("protocol 2: failed with the corrupt_newest message")
    d.stop()
    return "; ".join(notes)


# ---- the sweeper's pid-reuse rule --------------------------------------------------------------

def t_sweeper_pid_reuse(c):
    """D41 / E2a nit: a staging folder without an intent is attributed to a process by the id in
    its name. An id alone proves nothing (ids are reused): the folder must not be older than the
    running process that has that id."""
    src = legacy_copy(c, "e2-pidreuse-src")
    base = c.work / "e2-pidreuse"
    if base.exists():
        rmtree(base)
    base.mkdir(parents=True)
    # the folder first, the process 2.6 s later (more than the start tolerance), then the name
    tmp = base / "creating"
    tmp.mkdir()
    (tmp / "payload.bin").write_bytes(b"x" * 1000)
    time.sleep(2.6)
    late = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)"])
    c.procs.append(late)
    reused = base / f".R.fork-{late.pid:x}-1abc.tmp"
    os.rename(tmp, reused)
    # the control: a process that was running before its folder was created
    early = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)"])
    c.procs.append(early)
    time.sleep(0.3)
    control = base / f".K.fork-{early.pid:x}-1abc.tmp"
    control.mkdir()
    (control / "payload.bin").write_bytes(b"x" * 1000)
    d = c.daemon("e2-pidreuse", keepWarm=0)
    with v3(c, d, "pid") as s:
        s.call("open_project", path=str(src))
        r = s.call("fork_project", project=str(src), path=str(base), name="Probe", mode="full",
                   wait=60000)
        check(r["name"] == "Probe", f"{r}")
    d.stop()
    left = sorted(os.listdir(base))
    check(reused.name not in left, f"a folder older than the running process with its id was kept "
          f"(pid reuse): {left}")
    check(control.name in left, f"a folder of a process that was already running was swept: {left}")
    for p in (late, early):
        with contextlib.suppress(Exception):
            p.kill()
    return "intent-less folder older than the process with its id: swept; the control: kept"


# ---- prepare_upgrade, purposes, promote marker -------------------------------------------------

def t_prepare_upgrade(c):
    gpr = legacy_copy(c, "e2-prep")
    cache = c.work / "e2-prep-cache"
    d = c.daemon("e2-prep", keepWarm=0, upgradeCacheDir=str(cache))
    n = 3
    sessions = [v3(c, d, f"prep{i}") for i in range(n)]
    try:
        for s in sessions:
            s.call("open_project", path=str(gpr))
        started0 = sessions[0].call("status")["upgradeCache"]["buildsStarted"]
        out = [None] * n
        gate = threading.Barrier(n)

        def go(i):
            gate.wait(30)
            out[i] = sessions[i].call("prepare_upgrade", wait=300000)

        ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(400)
        check(all(o is not None for o in out), "a prepare_upgrade did not return")
        states = [[p["state"] for p in o["programs"]] for o in out]
        check(all(st == ["built"] for st in states) or
              (sum(st == ["built"] for st in states) >= 1 and
               all(st in (["built"], ["ready"]) for st in states)), f"states {states}")
        started = sessions[0].call("status")["upgradeCache"]["buildsStarted"] - started0
        check(started == 1, f"{n} concurrent prepare_upgrade started {started} builds (single flight)")
        again = sessions[0].call("prepare_upgrade")
        check([p["state"] for p in again["programs"]] == ["ready"], f"second call: {again}")
        ms = [o["ms"] for o in out]
    finally:
        for s in sessions:
            s.close()
    with v2(c, d, "prep2") as s2:
        expect_error("unknown_command", s2.call, "prepare_upgrade", project=str(gpr))
    d.stop()
    return f"{n} concurrent calls, 1 build ({ms} ms), then ready; v2: unknown_command"


def t_fork_purposes(c):
    gpr = legacy_copy(c, "e2-purposes")
    d = c.daemon("e2-purposes", keepWarm=0)
    with v3(c, d, "pu") as s:
        pid = s.call("open_project", path=str(gpr))["id"]
        base = c.work / "e2-purposes-out"
        e = expect_error("bad_request", s.call, "fork_project", project=pid, path=str(base),
                         name="X", purpose="bogus")
        check(e.details.get("field") == "purpose" and "backup" in e.details["allowed"], e.details)
        e = expect_error("bad_request", s.call, "fork_project", project=pid, path=str(base),
                         name="X", purpose="backup", verify="md5", open=False)
        check(e.details.get("field") == "verify", e.details)
        e = expect_error("bad_request", s.call, "fork_project", project=pid, path=str(base),
                         name="X", purpose="backup")
        check(e.details.get("field") == "open", e.details)
        e = expect_error("bad_request", s.call, "fork_project", project=pid, path=str(base),
                         name="X", purpose="view")
        check(e.details.get("field") == "owner", e.details)
        check(not base.exists() or not os.listdir(base), "a refused request left something")
        v = s.call("fork_project", project=pid, path=str(base), name="V", purpose="view",
                   owner="agent-7", lineage="L-9c1e", base=3, mode="full", wait=60000)
        _, sc = sidecar_of(v["gpr"])
        check(sc["purpose"] == "view" and sc["disposable"] is True and sc["owner"] == "agent-7"
              and sc["lineage"] == "L-9c1e" and sc["base"] == 3 and sc["state"] == "complete",
              f"view sidecar {sc}")
        # a view is a disposable fork: the upgrade gate does not apply
        r = open_up(s, project=v["project"])
        check(r["mode"] == "writable", "a view is disposable")
        s.call("close_project", project=v["project"], discard=True)
    d.stop()
    return "closed field sets refused with {field, allowed}; a view records owner, lineage, base"


#: how often ``promote_marker`` promotes again when the reader missed the marker's window
PROMOTE_ATTEMPTS = 3


def t_promote_marker(c):
    if not c.a.exe:
        return "skipped: needs --exe"
    import importlib
    read_shared = (sys.modules.get("dt_e2a") or importlib.import_module("dt_e2a")).read_text_shared
    gpr = c.copy_fixture("e2-promote")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("e2-promote", keepWarm=0)
    with v3(c, d, "promote") as a:
        pid = a.call("open_project", path=str(gpr))["id"]
        a.call("open_program", path=exe, overlay="ov")
        x = a.call("open_program", path=exe)
        fns = [f for f in a.call("functions", limit=40)["functions"]
               if not f["thunk"] and not f["external"]]
        ops = [{"op": "rename", "address": f["address"], "name": f"promoted_{i}"}
               for i, f in enumerate(fns[:30])]
        a.call("apply_overlay", overlay="ov", ops=ops)
        # The marker is up for the time the promote replays the ops and saves, and the reader is
        # a polling thread, so on a loaded machine it can miss the window. The reader opens the
        # sidecar with delete sharing (``read_text_shared``): an ordinary Python ``open`` refuses the
        # engine's rename over the file for as long as the loaded process keeps it open (measured:
        # seconds), which lost the marker or its removal (F1); the engine also retries the write. A
        # promote whose marker was not seen is run again into a fresh fork, as long as it was not
        # seen, at most PROMOTE_ATTEMPTS times; every attempt must still end with the marker gone
        # and the right count, and the test fails when no attempt saw the marker.
        for attempt in range(1, PROMOTE_ATTEMPTS + 1):
            seen = []
            stop = threading.Event()
            dest = c.work / f"e2-promote-fork{'' if attempt == 1 else attempt}"
            fork_sidecar = dest / "F.fork.json"

            def watch():
                while not stop.is_set():
                    try:
                        sc = json.loads(read_shared(fork_sidecar))
                        seen.append(sc.get("promote"))
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.001)

            th = threading.Thread(target=watch, daemon=True)
            th.start()
            r = a.call("promote_overlay", overlay="ov", fork={"path": str(dest), "name": "F",
                                                             "mode": "full"})
            stop.set()
            th.join(5)
            check(r["promoted"] == len(ops), f"{r}")
            final = json.loads(read_shared(fork_sidecar))
            check("promote" not in final, f"the marker must be gone once acknowledged: {final}")
            if "in-progress" in seen:
                break
        check("in-progress" in seen,
              f"the marker was never seen during the promote ({len(seen)} reads, "
              f"{attempt} attempts)")
    d.stop()
    return (f"promote:'in-progress' seen while promoting ({seen.count('in-progress')} reads, "
            f"attempt {attempt}), gone after")


def t_sidecar_unfinished(c):
    """E2a review nit, decided: a sidecar held longer than the retry budget (about 1.6 s) ends the
    fork as ok (its .gpr is the commit point) with the sidecar still saying ``publishing``; the
    reply says so (``sidecarState``, a warning) and the next fork under the folder finishes it.

    The holder is a polling thread of this process that has to take its handle in the few
    milliseconds between the sidecar's first write ("publishing") and its final rewrite
    ("complete"). On a slower or busier machine (the hosted Windows runner: the reply said
    ``complete``) it arrives after the engine is done and holds a settled file, which exercises
    nothing. Like ``e2a_handle_holder`` this runs the case again, in a fresh folder, while the
    holder did not hold the rewrite up (the sidecar says ``complete`` and the reply agrees), at most
    ``SP6_ATTEMPTS`` times. The assertions are the same for every attempt and the last is judged;
    a holder that never engaged fails the test, it never passes it."""
    if os.name != "nt":
        return "skipped: the handle holder is a Windows handle without FILE_SHARE_DELETE"
    import importlib
    e2a = sys.modules.get("dt_e2a") or importlib.import_module("dt_e2a")
    src = e2a.make_source(c, "e2sc")
    d = c.daemon("e2-sidecar", keepWarm=0)
    with v3(c, d, "sc") as s:
        for attempt in range(1, e2a.SP6_ATTEMPTS + 1):
            pdir = c.work / ("e2-sidecar-unfinished" if attempt == 1
                             else f"e2-sidecar-unfinished-try{attempt}")
            if pdir.exists():
                rmtree(pdir)
            pdir.mkdir(parents=True)
            rec, stop = {}, threading.Event()
            th = threading.Thread(target=e2a._sp6_holder, args=(pdir, "sidecar", 4.0, rec, stop))
            th.start()
            t0 = time.perf_counter()
            r = s.call("fork_project", project=str(src), path=str(pdir), name="H", mode="full",
                       wait=60000)
            t1 = time.perf_counter()
            took = t1 - t0
            th.join(30)
            stop.set()
            check("error" not in rec, f"holder: {rec}")
            engaged = sidecar_engaged(r, e2a.classify(pdir, "H"))
            if engaged:
                break
        check(engaged, f"the holder arrived after the engine had finished the sidecar in all "
                       f"{attempt} attempts (reply {r.get('sidecarState')}): the premise never "
                       f"held, so nothing was tested")
        check(r["sidecarState"] == "publishing" and any("publishing" in w for w in r["warnings"]),
              f"the reply must say the sidecar is unfinished: {r.get('sidecarState')} "
              f"{r.get('warnings')}")
        # the retries are timed from the moment the holder had its handle, not from the call: the
        # call also copies the project (seconds on a slow disk), which is not what is measured
        retry_s = t1 - rec["t_open"]
        check(1.4 <= retry_s <= 3.9, f"the retries should end about 1.6 s after the holder took "
                                     f"the sidecar, not {retry_s:.2f} s (the call took {took:.2f} s)")
        state = e2a.classify(pdir, "H")
        check(state[0] == "complete" and state[2] == "publishing" and state[1],
              f"a committed fork, sidecar unfinished, staging kept for the sweep: {state}")
        time.sleep(max(0, rec["t_release"] - time.perf_counter()) + 0.1)
        expect_error("conflict", s.call, "fork_project", project=str(src), path=str(pdir),
                     name="H", mode="full")
        state = e2a.classify(pdir, "H")
        check(state[0] == "complete" and state[2] == "complete" and not state[1],
              f"the next fork must finish the sidecar and remove the staging folder: {state}")
    d.stop()
    return (f"held 4 s: ok {took:.2f} s after the call, {retry_s:.2f} s after the hold began, with "
            f"sidecarState publishing + warning; finished by the next fork (attempt {attempt})")


def sidecar_engaged(reply, state):
    """Whether the holder held the sidecar's final rewrite up: the sidecar, read from disk, still
    says ``publishing`` or the reply does. A reply and a file that both say ``complete`` mean the
    holder took its handle on a settled file."""
    return reply.get("sidecarState") == "publishing" or state[2] == "publishing"


def t_legacy_foreign_owner(c):
    """The committed 12.1.4 fixture names its maker as the project owner, and Ghidra refuses a
    writable open for anyone else ("Project is owned by X"). On the hosted CI runner (another user)
    that failed nine tests at once. ``legacy_copy`` must hand out a copy the current user owns, also
    when the project comes from ``--legacy-project``. Here the source is made foreign on purpose."""
    import getpass
    me = getpass.getuser()
    foreign = c.work / "e2-owner-src"
    dt.clone_tree(LEGACY_DIR, foreign)
    check(dt.own_project(foreign, "someone-else-" + me) == 1, "the fixture has no OWNER to change")
    d = c.daemon("e2-owner", keepWarm=0)
    notes = []
    with v3(c, d, "ow") as s:
        raw = c.work / "e2-owner-raw"
        dt.clone_tree(foreign, raw)  # no own_project: what the tests did before
        e = expect_error("conflict", s.call, "open_project", path=str(next(raw.glob("*.gpr"))),
                         writable=True)
        check("owned by someone-else-" in str(e), f"the premise: a foreign owner refuses: {e}")
        notes.append("a foreign owner refuses a writable open")
        old = c.a.legacy_project
        c.a.legacy_project = str(foreign)
        try:
            gpr = legacy_copy(c, "e2-owner-copy")
        finally:
            c.a.legacy_project = old
        r = s.call("open_project", path=str(gpr), writable=True)
        check(r.get("id"), f"the copy must open writable for {me}: {r}")
        s.call("close_project", discard=True)
        notes.append(f"legacy_copy gives a copy {me} can open writable")
    d.stop()
    return "; ".join(notes)


def t_failed_test_releases(c):
    """A test that fails halfway must not leave its daemon or its project behind (the runner's
    ``release`` shuts the daemons down, ``cleanup`` kills what is left): run a throwaway test that
    opens a project writable, leaves a daemon up and fails, then open the same project again."""
    gpr = legacy_copy(c, "e2-release")
    holder = {}

    def failing(cx):
        d = cx.daemon("e2-release", keepWarm=0)
        holder["d"] = d
        s = v3(cx, d, "r1")  # never closed: the test dies with it open
        s.call("open_project", path=str(gpr), writable=True)
        raise Fail("planted failure")

    dt.REGISTRY["_planted_failure"] = failing
    try:
        status, note, _secs, _ev = dt.run_test(c, "_planted_failure", 0)
    finally:
        dt.REGISTRY.pop("_planted_failure", None)
    check(status == "fail" and "planted failure" in note, f"{status} {note}")
    check(not holder["d"].jvm_alive(), "the failed test's daemon is still running")
    d2 = c.daemon("e2-release2", keepWarm=0)
    with v3(c, d2, "r2") as s:
        r = s.call("open_project", path=str(gpr), writable=True)
        check(r.get("id"), f"the project must open again after the failed test: {r}")
        s.call("close_project", discard=True)
    d2.stop()
    return "a failed test left no daemon; its project opened writable again"


TESTS = {
    "sidecar_unfinished": t_sidecar_unfinished,
    "legacy_foreign_owner": t_legacy_foreign_owner,
    "failed_test_releases": t_failed_test_releases,
    "format_readonly": t_format_readonly,
    "format_truncated": t_format_truncated,
    "folder_singletons": t_folder_singletons,
    "upgrade_gate": t_upgrade_gate,
    "backup_fault": t_backup_fault,
    "manifest_canonical": t_manifest_canonical,
    "fork_report": t_fork_report,
    "candidate_then_seal": t_candidate_then_seal,
    "seal_union": t_seal_union,
    "repair_policy": t_repair_policy,
    "sweeper_pid_reuse": t_sweeper_pid_reuse,
    "prepare_upgrade": t_prepare_upgrade,
    "fork_purposes": t_fork_purposes,
    "promote_marker": t_promote_marker,
}
