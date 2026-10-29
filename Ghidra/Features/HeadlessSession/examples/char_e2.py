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
"""Characterization scenarios of package E2 (PROTOCOL-3.md 3.4, 3.12, 3.13, section 8), protocol 3
only: their goldens are ``examples/characterization/v3/e2-<scenario>.json`` (section 8, rule 2).

    python characterization_tests.py --ghidra <install> --work <dir> --protocol 3 --only e2-format-fork,...

* ``e2-format-fork`` (``format_fork`` of the spec): ``format`` on a current-format project; a plain
  fork and a backup fork with their replies (file-system dependent figures, hashes and ids masked,
  key order checked); the sidecars and the manifest as files (masked, key order checked: the
  manifest is in canonical form, so its keys are sorted); the refusals of closed fields.
* ``e2-gate``: the upgrade gate on the committed 12.1.4 fixture: the ``backup_required`` error with
  its ``next``, then a verified backup and the open that it allows.
* ``e2-seal``: a generation candidate, ``seal_project``, the ``sealed`` refusals with their
  ``next``, a read-only open, ``unseal``.
"""
import copy
import json
import pathlib
import shutil

import characterization_tests as ct
from characterization_tests import Fail

PROTOCOLS = (3,)
HERE = pathlib.Path(__file__).resolve().parent
LEGACY = HERE / "fixtures" / "legacy-12.1.4"

#: the values of these keys differ from machine to machine or from run to run
FILE_MASK = {"size", "sha256", "selfSha256", "filesetSha256", "manifestSha256",
             "layoutSha256", "id", "forkId", "bytes", "mb",
             "files", "freeSpaceUsedBytes", "copyMs", "ms", "mode", "method", "cloned", "clonedBy",
             "sourceFileSystem", "destinationFileSystem", "cloneCapable", "sameVolume", "independent",
             "destFreeBytes", "limitBytes", "sourceRevisionAfter"}


def mask_obj(m, v, key=None, keep=()):
    """Masks a file's content: the machine's facts by key, the rest through the run's masker."""
    if isinstance(v, dict):
        return {k: mask_obj(m, x, k, keep) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_obj(m, x, key, keep) for x in v]
    if key in FILE_MASK and key not in keep and v is not None:
        return "<masked>"
    return m.value(v, key)


def masked_reply(R, resp):
    """The reply with the file-system dependent parts of the fork report masked: ``cost`` keeps its
    keys, ``warnings`` keeps its count and shape (their text names file systems)."""
    resp = copy.deepcopy(resp)
    res = resp.get("result")
    if isinstance(res, dict):
        if isinstance(res.get("cost"), dict):
            res["cost"] = {k: ("<masked>" if k in ("bytes", "mb", "sameVolume", "sourceFileSystem",
                                                   "destinationFileSystem", "cloneCapable",
                                                   "destFreeBytes", "limitBytes") else v)
                           for k, v in res["cost"].items()}
        if isinstance(res.get("warnings"), list):
            if not all(isinstance(w, str) and w for w in res["warnings"]):
                raise Fail(f"e2: warnings must be non-empty strings: {res['warnings']}")
            res["warnings"] = [f"<warning {i + 1}>" for i in range(len(res["warnings"]))]
        if isinstance(res.get("manifest"), dict):
            res["manifest"] = {k: ("<masked>" if k in ("sha256",) else v)
                               for k, v in res["manifest"].items()}
    return resp


def call(R, who, s, cmd, note=None, **f):
    """Sends a request and records it with the fork report masked."""
    try:
        s.call(cmd, **f)
    except R.gs.SessionError:
        pass
    resp = masked_reply(R, s.last_response)
    step = {"step": len(R.steps) + 1, "who": who, "cmd": cmd, "request": R.m.value(f),
            "response": R.m.value(resp)}
    if note:
        step["note"] = note
    R.steps.append(step)
    return s.last_response


def ok(R, who, s, cmd, note=None, **f):
    resp = call(R, who, s, cmd, note, **f)
    if not resp.get("ok"):
        raise Fail(f"e2: {who} {cmd} {f} failed: {resp.get('error')}")
    return resp["result"]


def err(R, who, s, cmd, code, note=None, **f):
    resp = call(R, who, s, cmd, note, **f)
    if resp.get("ok") or resp["error"].get("code") != code:
        raise Fail(f"e2: {who} {cmd} {f}: expected {code}, got {resp.get('error') or 'ok'}")
    return resp["error"]


def record_file(R, what, path, keep=()):
    """Records the content of a JSON file the engine wrote, masked."""
    raw = pathlib.Path(path).read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    R.steps.append({"step": len(R.steps) + 1, "who": "file", "cmd": what, "request": None,
                    "response": mask_obj(R.m, obj, None, keep)})
    return obj, raw


def sc_format_fork(c, R):
    gpr = c.copy_fixture("e2fmt")
    d = c.daemon("e2-format-fork")
    a = c.connect(d, "e2-a", "e2-h")
    info = ok(R, "a", a, "open_project", path=str(gpr), note="format of a current-format project")
    f = info["format"]
    if list(f) != ["programDb", "dataTypeDb", "upgradeRequired", "oneWay", "newerThanEngine",
                   "programsScanned", "truncated", "engine"]:
        raise Fail(f"e2: format keys {list(f)}")
    if f["upgradeRequired"] is not False or f["programsScanned"] != 2:
        raise Fail(f"e2: a current project: {f}")
    out = c.work / "e2-out"
    if out.exists():
        shutil.rmtree(out)
    r = ok(R, "a", a, "fork_project", project="p1", path=str(out / "plain"), name="Fixture",
           mode="full", writable=False, note="a plain fork: the v3 report")
    want = ["project", "path", "gpr", "name", "writable", "source", "baseRevision", "mode",
            "method", "cloned", "clonedBy", "bytes", "files", "copyMs", "freeSpaceUsedBytes",
            "depth", "sidecar", "ms", "purpose", "cost", "warnings", "sidecarState", "info"]
    if list(r) != want:
        raise Fail(f"e2: fork reply keys {list(r)}")
    if list(r["cost"]) != ["bytes", "mb", "files", "sameVolume", "sourceFileSystem",
                           "destinationFileSystem", "cloneCapable", "destFreeBytes"]:
        raise Fail(f"e2: cost keys {list(r['cost'])}")
    sc, _ = record_file(R, "sidecar of the plain fork", r["sidecar"])
    if list(sc)[:4] != ["format", "kind", "purpose", "disposable"] or sc["state"] != "complete":
        raise Fail(f"e2: sidecar keys {list(sc)}")
    ok(R, "a", a, "project", project=r["project"], note="the fork summary of a v3 project")
    b = ok(R, "a", a, "fork_project", project="p1", path=str(out / "backup"), name="Fixture",
           mode="full", purpose="backup", open=False, verify="hash", reason="char",
           note="a backup: not registered, verified, sealed")
    want_b = ["project", "path", "gpr", "name", "writable", "source", "baseRevision", "mode",
              "method", "cloned", "clonedBy", "bytes", "files", "copyMs", "freeSpaceUsedBytes",
              "depth", "sidecar", "ms", "purpose", "cost", "warnings", "manifest", "sidecarState"]
    if list(b) != want_b or b["project"] is not None:
        raise Fail(f"e2: backup reply keys {list(b)}")
    bsc, _ = record_file(R, "sidecar of the backup", b["sidecar"])
    if (bsc["purpose"] != "backup" or bsc["disposable"] is not False or
            bsc["state"] != "complete" or list(bsc["manifest"]) != ["path", "sha256", "verified",
                                                                    "files"]):
        raise Fail(f"e2: backup sidecar {bsc}")
    man, raw = record_file(R, "manifest of the backup", b["manifest"]["path"])
    if list(man) != sorted(man):
        raise Fail(f"e2: the manifest is not in canonical key order: {list(man)}")
    if raw != ct.json.dumps(man, ensure_ascii=False, separators=(",", ":"),
                            sort_keys=True).encode("utf-8"):
        raise Fail("e2: backup.json is not byte-identical to the canonical form")
    marker, _ = record_file(R, "SEALED.json of the backup", pathlib.Path(b["path"]) / "SEALED.json")
    err(R, "a", a, "fork_project", "bad_request", project="p1", path=str(out / "x"), name="X",
        purpose="bogus", note="a closed field")
    err(R, "a", a, "fork_project", "bad_request", project="p1", path=str(out / "x"), name="X",
        purpose="backup", note="a backup is never registered")
    err(R, "a", a, "fork_project", "bad_request", project="p1", path=str(out / "x"), name="X",
        purpose="backup", open=False, verify="md5")
    ok(R, "a", a, "close_project", project=r["project"])
    ok(R, "a", a, "close_project")
    c.stop(d)


def legacy_copy(c, tag):
    dst = c.work / tag
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(LEGACY, dst)
    import daemon_tests as dt
    dt.own_project(dst)  # the fixture names its maker as owner: another user could not open it
    return dst / "legacy.gpr"


def sc_gate(c, R):
    gpr = legacy_copy(c, "e2gate")
    d = c.daemon("e2-gate")
    a = c.connect(d, "e2-a", "e2-h")
    info = ok(R, "a", a, "open_project", path=str(gpr), writable=True,
              note="the 12.1.4 fixture: format says one-way")
    if info["format"]["upgradeRequired"] is not True:
        raise Fail(f"e2: {info['format']}")
    e = err(R, "a", a, "open_program", "backup_required", path="/flow_fixture.exe",
            writable=True, upgrade=True, note="a canonical project, no backup")
    if (e.get("next") or {}).get("cmd") != "fork_project":
        raise Fail(f"e2: next {e.get('next')}")
    ok(R, "a", a, "close_project", discard=True)
    ro = ok(R, "a", a, "open_project", path=str(gpr), note="read-only, to take the backup")
    b = ok(R, "a", a, "fork_project", project=ro["id"], path=str(c.work / "e2gate-backup"),
           name="legacy", mode="full", purpose="backup", open=False, verify="hash")
    ok(R, "a", a, "close_project")
    ok(R, "a", a, "open_project", path=str(gpr), writable=True)
    ok(R, "a", a, "open_program", path="/flow_fixture.exe", writable=True, upgrade=True,
       backup=b["manifest"]["path"], note="the backup of the gate")
    r = ok(R, "a", a, "save", note="the first save after the upgrade stamps its comment")
    if "upgradeStamp" not in r:
        raise Fail(f"e2: no upgradeStamp in {r}")
    ok(R, "a", a, "close_program", discard=True)
    ok(R, "a", a, "close_project", discard=True)
    c.stop(d)


def sc_seal(c, R):
    gpr = c.copy_fixture("e2seal")
    d = c.daemon("e2-seal")
    a = c.connect(d, "e2-a", "e2-h")
    ok(R, "a", a, "open_project", path=str(gpr))
    g = ok(R, "a", a, "fork_project", project="p1", path=str(c.work / "e2seal-gen"),
           name="Fixture", mode="full", purpose="generation", lineage="L-char", generation=2,
           note="a generation candidate: non-disposable, writable by its publisher")
    sc, _ = record_file(R, "sidecar of the candidate", g["sidecar"])
    if sc["state"] != "candidate" or sc["disposable"] is not False:
        raise Fail(f"e2: {sc}")
    err(R, "a", a, "seal_project", "conflict", project=g["project"],
        note="a project that is open writable is not sealed")
    ok(R, "a", a, "close_project", project=g["project"])
    s = ok(R, "a", a, "seal_project", project=g["gpr"], lineage="L-char", note="the seal")
    if list(s) != ["sealed", "revision", "gpr", "records", "witnesses"]:
        raise Fail(f"e2: seal reply keys {list(s)}")
    record_file(R, "sidecar after the seal", g["sidecar"])
    record_file(R, "SEALED.json", pathlib.Path(g["path"]) / "SEALED.json")
    e = err(R, "a", a, "open_project", "sealed", path=g["gpr"], writable=True,
            note="every writable path is refused, with a fork_project next")
    if (e.get("next") or {}).get("cmd") != "fork_project":
        raise Fail(f"e2: next {e.get('next')}")
    ro = ok(R, "a", a, "open_project", path=g["gpr"], note="read-only works")
    ok(R, "a", a, "open_program", path="/alpha.exe", project=ro["id"])
    err(R, "a", a, "open_program", "sealed", path="/alpha.exe", project=ro["id"], writable=True)
    err(R, "a", a, "save", "sealed")
    err(R, "a", a, "analyze", "sealed")
    ok(R, "a", a, "close_project", project=ro["id"])
    err(R, "a", a, "seal_project", "bad_request", project=g["gpr"], unseal=True,
        note="unseal is an owner action")
    ok(R, "a", a, "seal_project", project=g["gpr"], unseal=True, force=True)
    ok(R, "a", a, "close_project")
    c.stop(d)


SCENARIOS = {"e2-format-fork": sc_format_fork, "e2-gate": sc_gate, "e2-seal": sc_seal}
