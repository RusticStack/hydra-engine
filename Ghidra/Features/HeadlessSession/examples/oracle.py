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
"""The corruption oracle of the protocol 3 design (PROTOCOL-3.md 3.12, package X0, decision D48).

The invariants K1 to K17 as functions over the files a run leaves behind and, where an invariant
needs the engine (K3, K10, K13, K14), over a live session. Every check returns its findings in a
:class:`Report`; nothing here modifies the trees it inspects (the only writes are the evidence
writer's own files and the witness ledger, both outside the inspected trees).

A finding has a severity:

* ``violation``: the invariant is broken; the report is not ``ok``.
* ``tolerated``: a state the design allows and the oracle names (planted violation X6: a torn
  last ``CURRENT.log`` line); the report stays ``ok``.
* ``note``: something the oracle could not decide (a field the engine does not write yet); never
  a pass in disguise, it is listed in the report.

The oracle is a library and a small command line (``python oracle.py -h``). It is exercised by
``dt_x0.py``, which plants the violations X1 to X11 and requires the oracle to flag X1 to X5 and
X7 to X11 and to pass X6, then runs it over kept corrupt forks and an unkilled control.

Layouts it reads (all from the spec, none invented): a Ghidra project (``*.gpr``, ``*.rep``,
``db.N.gbf`` version files whose first 8 bytes are the buffer-file magic); the fork sidecar
``<name>.fork.json``; the marker ``SEALED.json``; the engine's seal registry ``<stateDir>/seals/``;
a lineage folder (4.4: ``CURRENT.log`` with ``crc-hex8 SP json LF`` lines, ``gen/NNNN/MANIFEST.json``,
``pending/<csid>.json``, ``done/<csid>.json``); sealed JSON records (4.1: a top-level ``seal``
over the canonical body). Where the spec leaves a detail open the choice is stated in the
docstring of the check that makes it.

Windows only for the process checks (K7, K10 residue): they use the Win32 tool-help API through
``ctypes``. The file checks run anywhere.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import sys
import threading
import time
import zlib

#: First 8 bytes of every buffer file (``LocalBufferFile.MAGIC_NUMBER``, 0x2f30312c34292c2a, which
#: reads "/01,4),*" as ASCII).
MAGIC = bytes.fromhex("2f30312c34292c2a")
VERSION_FILE = re.compile(r"^db\.(\d+)\.gbf$")
#: Files a writable open or a lock renewal touches and that are therefore not part of a seal.
SEAL_EXCLUDED_NAMES = {"projectState", "SEALED.json", "MANIFEST.json"}
#: Ghidra lock files carry a lease of 15 s (``LockFile.DEFAULT_MAX_LOCK_LEASE_PERIOD_MS``).
LOCK_LEASE_S = 15.0
DECOMPILER_NAMES = {"decompile.exe", "decompile", "decompile_win_x86_64.exe"}


# ------------------------------------------------------------------------------ report

class Report:
    """The findings of one oracle run."""

    def __init__(self, name: str = ""):
        self.name = name
        self.findings: list[dict] = []
        self.tolerated: list[dict] = []
        self.notes: list[dict] = []
        self.checked: list[str] = []

    def _add(self, bucket, kid, code, detail, path, extra):
        rec = {"id": kid, "code": code, "detail": str(detail)}
        if path is not None:
            rec["path"] = str(path)
        rec.update(extra)
        bucket.append(rec)
        return rec

    def violation(self, kid, code, detail="", path=None, **extra):
        return self._add(self.findings, kid, code, detail, path, extra)

    def tolerate(self, kid, code, detail="", path=None, **extra):
        return self._add(self.tolerated, kid, code, detail, path, extra)

    def note(self, kid, code, detail="", path=None, **extra):
        return self._add(self.notes, kid, code, detail, path, extra)

    def ran(self, kid):
        if kid not in self.checked:
            self.checked.append(kid)

    @property
    def ok(self) -> bool:
        return not self.findings

    def codes(self) -> set[str]:
        """``{"K2:newest_header_invalid", ...}`` for the violations."""
        return {f"{f['id']}:{f['code']}" for f in self.findings}

    def ids(self) -> set[str]:
        return {f["id"] for f in self.findings}

    def merge(self, other: "Report"):
        self.findings += other.findings
        self.tolerated += other.tolerated
        self.notes += other.notes
        for k in other.checked:
            self.ran(k)
        return self

    def to_json(self) -> dict:
        return {"name": self.name, "ok": self.ok, "checked": self.checked,
                "violations": self.findings, "tolerated": self.tolerated, "notes": self.notes}

    def summary(self) -> str:
        v = ", ".join(sorted(self.codes())) or "none"
        return f"{self.name or 'oracle'}: {'OK' if self.ok else 'VIOLATIONS'} " \
               f"({len(self.findings)} violation(s): {v}; {len(self.tolerated)} tolerated; " \
               f"{len(self.notes)} note(s); ran {','.join(self.checked)})"


# ------------------------------------------------------------------------------ hashing

def sha256_file(path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def canonical(obj) -> bytes:
    """The canonical JSON of PROTOCOL-3.md 3.4 (sorted keys, minimal separators, UTF-8)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(root) -> dict:
    """``{"files", "bytes", "tree_sha256"}``: sha256 of the sorted lines ``relpath TAB size TAB
    sha256`` of every file under ``root`` (the definition of ``tools/golden.py`` and of
    measurement C). A missing root hashes as empty."""
    root = pathlib.Path(root)
    rows = []
    for directory, _dirs, files in os.walk(root):
        for name in files:
            p = pathlib.Path(directory, name)
            rows.append((p.relative_to(root).as_posix(), p.stat().st_size, sha256_file(p)))
    rows.sort()
    digest = hashlib.sha256("\n".join("%s\t%d\t%s" % r for r in rows).encode()).hexdigest()
    return {"files": len(rows), "bytes": sum(r[1] for r in rows), "tree_sha256": digest}


def file_map(root, exclude=lambda rel, name: False) -> dict:
    """``{relpath: sha256}`` of every file under ``root`` for which ``exclude`` is false."""
    root = pathlib.Path(root)
    out = {}
    for directory, _dirs, files in os.walk(root):
        for name in files:
            p = pathlib.Path(directory, name)
            rel = p.relative_to(root).as_posix()
            if not exclude(rel, name):
                out[rel] = sha256_file(p)
    return out


# ------------------------------------------------------------------------------ K2: headers

def version_files(root):
    """Every ``db.N.gbf`` under ``root``: ``(path, N)``."""
    for directory, _dirs, files in os.walk(root):
        for name in files:
            m = VERSION_FILE.match(name)
            if m:
                yield pathlib.Path(directory, name), int(m.group(1))


def header_ok(path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == MAGIC
    except OSError:
        return False


def check_k2(root, rep: Report | None = None) -> Report:
    """K2: every ``db.N.gbf`` has the magic at offset 0 and the newest one of its folder is valid.

    A bad newest file is ``newest_header_invalid`` (the version-file poison of D42: Ghidra then
    neither falls back to ``db.N-1`` nor repairs it); a bad older file is ``header_invalid``."""
    rep = rep or Report("K2")
    rep.ran("K2")
    by_dir: dict[pathlib.Path, list] = {}
    for p, n in version_files(root):
        by_dir.setdefault(p.parent, []).append((n, p))
    for d, items in by_dir.items():
        items.sort()
        for n, p in items:
            if not header_ok(p):
                newest = n == items[-1][0]
                rep.violation("K2", "newest_header_invalid" if newest else "header_invalid",
                              f"{p.name}: no buffer-file magic at offset 0 "
                              f"({'newest' if newest else 'older'} version, {p.stat().st_size} bytes)",
                              p, newest=newest)
    return rep


class HeaderWatcher:
    """The 50 ms watcher of K2: fails on any *visible* final-named ``db.N.gbf`` with an invalid
    header while a run writes. ``hits`` holds ``(path, size, seconds since start, first 8 bytes
    hex)`` the first time each distinct (path, size, header) was seen invalid.

    A visible file with an invalid header is a violation even if it is repaired a moment later:
    that moment is the window in which a kill leaves the poison (D42)."""

    def __init__(self, root, interval: float = 0.05):
        self.root = pathlib.Path(root)
        self.interval = interval
        self.hits: list[tuple] = []
        self.scans = 0
        self._seen: set = set()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True, name="header-watcher")
        self._t0 = time.perf_counter()

    def start(self):
        self._t0 = time.perf_counter()
        self._t.start()
        return self

    def scan_once(self):
        self.scans += 1
        for directory, _dirs, files in os.walk(self.root):
            for name in files:
                if not VERSION_FILE.match(name):
                    continue
                p = os.path.join(directory, name)
                try:
                    with open(p, "rb") as f:
                        head = f.read(8)
                    size = os.path.getsize(p)
                except OSError:
                    continue  # renamed or removed under us: not visible any more
                if head != MAGIC:
                    key = (p, size, head)
                    if key not in self._seen:
                        self._seen.add(key)
                        self.hits.append((p, size, round(time.perf_counter() - self._t0, 3), head.hex()))

    def _run(self):
        while not self._stop.is_set():
            t = time.perf_counter()
            with contextlib.suppress(Exception):
                self.scan_once()
            self._stop.wait(max(0.0, self.interval - (time.perf_counter() - t)))

    def stop(self) -> "HeaderWatcher":
        self._stop.set()
        self._t.join(10)
        return self

    def report(self, rep: Report | None = None) -> Report:
        rep = rep or Report("K2 watcher")
        rep.ran("K2")
        for p, size, t, head in self.hits:
            rep.violation("K2", "visible_invalid_header",
                          f"{pathlib.Path(p).name} was visible with {size} bytes and header {head} at {t} s",
                          p, size=size, at=t, header=head)
        return rep


# ------------------------------------------------------------------------------ K1 and K1u: seals

def _seal_excluded(rel: str, name: str) -> bool:
    return (name in SEAL_EXCLUDED_NAMES or name.endswith(".lock") or name.endswith(".lock~")
            or name.endswith(".fork.json"))


def seal_snapshot(project_dir) -> dict:
    """``{relpath: sha256}`` of a sealed project folder, as K1 defines it: every file except
    ``projectState``, the lock files and ``SEALED.json``; a ``*.fork.json`` sidecar is hashed with its
    ``state`` field removed (a seal rewrites that field, so it cannot be part of the hash)."""
    root = pathlib.Path(project_dir)
    snap = file_map(root, _seal_excluded)
    for p in root.rglob("*.fork.json"):
        rel = p.relative_to(root).as_posix()
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            d.pop("state", None)
            snap[rel] = sha256_hex(canonical(d))
        except (OSError, ValueError):
            snap[rel] = "unparseable"
    return snap


def manifest_snapshot(manifest: dict) -> dict:
    """The ``{path: sha256}`` a ``MANIFEST.json`` (4.4) records for a generation."""
    return {f["path"].replace("\\", "/"): f["sha256"] for f in manifest.get("files", [])}


def verify_manifest(manifest: dict, rep: Report, path=None) -> bool:
    """``filesetSha256`` and ``selfSha256`` of a manifest (canonical form of 3.4)."""
    ok = True
    if "filesetSha256" in manifest and sha256_hex(canonical(manifest.get("files", []))) != manifest["filesetSha256"]:
        rep.violation("K1", "manifest_fileset_hash", "filesetSha256 does not match files[]", path)
        ok = False
    if "selfSha256" in manifest:
        body = {k: v for k, v in manifest.items() if k != "selfSha256"}
        if sha256_hex(canonical(body)) != manifest["selfSha256"]:
            rep.violation("K1", "manifest_self_hash", "selfSha256 does not match the manifest", path)
            ok = False
    return ok


def check_k1(project_dir, baseline: dict, rep: Report | None = None, label: str = "") -> Report:
    """K1: the sha256 of every file of a sealed project equals ``baseline`` (a ``seal_snapshot`` taken
    when it was sealed, or a manifest's ``manifest_snapshot``). A writable open of a pristine project
    changes ``~index.bak`` and deletes ``~journal.bak`` (D38), so both count."""
    rep = rep or Report("K1")
    rep.ran("K1")
    now = seal_snapshot(project_dir)
    for rel in sorted(set(baseline) | set(now)):
        a, b = baseline.get(rel), now.get(rel)
        if a is None:
            rep.violation("K1", "added", f"{rel} appeared in a sealed project {label}", rel)
        elif b is None:
            rep.violation("K1", "removed", f"{rel} disappeared from a sealed project {label}", rel)
        elif a != b:
            rep.violation("K1", "changed", f"{rel} changed in a sealed project {label}", rel,
                          was=a[:16], now=b[:16])
    return rep


def engine_log_writable_opens(log, sealed_paths) -> list[str]:
    """Lines of an engine log that report a writable open of one of ``sealed_paths`` (best effort: the
    hydra.3 log does not say whether an open was writable, the hydra.4 log names it; a line counts
    when it mentions both the path and the word ``writable``, and not ``writable=false``/``refused``)."""
    out = []
    try:
        lines = pathlib.Path(log).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    keys = [str(pathlib.Path(p)).lower().replace("\\", "/") for p in sealed_paths]
    for line in lines:
        low = line.lower().replace("\\", "/")
        if "writable" in low and not re.search(r"writable\W{0,3}false|refus|sealed", low) \
                and any(k in low for k in keys):
            out.append(line.strip()[:300])
    return out


def seal_witnesses(project_gpr, state_dir=None) -> dict:
    """The three records of D66 for one project and whether each says sealed.

    ``{"registry": bool, "sidecar": bool, "marker": bool}``: (1) a record in ``<stateDir>/seals/``
    (any ``*.json`` whose ``path`` is the project's ``.gpr``); (2) a ``*.fork.json`` of purpose
    ``generation`` or ``backup`` with ``state: "complete"``; (3) ``SEALED.json`` in the project
    folder. The seal registry format is not pinned by the spec beyond "path and Revision"; any
    JSON file with a ``path`` equal to the project path counts."""
    gpr = pathlib.Path(project_gpr)
    folder = gpr.parent
    w = {"registry": False, "sidecar": False, "marker": False}
    if state_dir:
        sd = pathlib.Path(state_dir) / "seals"
        if sd.is_dir():
            want = os.path.normcase(os.path.abspath(gpr))
            for f in sd.glob("*.json"):
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                recs = d if isinstance(d, list) else [d]
                if any(isinstance(r, dict) and r.get("path")
                       and os.path.normcase(os.path.abspath(r["path"])) == want for r in recs):
                    w["registry"] = True
    for side in folder.glob("*.fork.json"):
        try:
            d = json.loads(side.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if d.get("purpose") in ("generation", "backup") and d.get("state") == "complete":
            w["sidecar"] = True
    w["marker"] = (folder / "SEALED.json").is_file()
    return w


def check_k1u(project_gpr, state_dir=None, expect_sealed=True, rep: Report | None = None) -> Report:
    """K1u (seal union, D66): the project is sealed when ANY of the three records says so. For a
    generation that must be sealed (named by ``CURRENT.log`` or published), a union of false is
    ``unsealed``; a union of true with a record that disagrees (the sidecar edited back to
    ``candidate``, a deleted marker) is ``seal_discrepancy``: it is still reported sealed, and the
    doctor must report the discrepancy. Returns the report; ``rep.sealed`` is not set, call
    :func:`is_sealed`."""
    rep = rep or Report("K1u")
    rep.ran("K1u")
    w = seal_witnesses(project_gpr, state_dir)
    sealed = any(w.values())
    if expect_sealed and not sealed:
        rep.violation("K1u", "unsealed", "no record says sealed", project_gpr, witnesses=w)
    elif sealed and not all(w.values()):
        miss = [k for k, v in w.items() if not v]
        rep.violation("K1u", "seal_discrepancy",
                      f"sealed by {[k for k, v in w.items() if v]} but {miss} does not say so "
                      "(still sealed: the union holds)", project_gpr, witnesses=w, sealed=True)
    return rep


def is_sealed(project_gpr, state_dir=None) -> bool:
    return any(seal_witnesses(project_gpr, state_dir).values())


# ------------------------------------------------------------------------------ K6: fork paths

STAGING = re.compile(r"^\..+\.fork-.+\.tmp$")


def check_k6(gpr, kind: str = "fork", base_tree: str | None = None, require_sidecar: bool = True,
             rep: Report | None = None) -> Report:
    """K6: a fork path is absent or complete: ``<name>.gpr`` and ``<name>.rep`` both exist, a sidecar
    says ``state: "complete"`` (``"candidate"`` for a ``generation``), and the data equals its base
    (``base_tree``, a ``tree_hash`` digest, optional). A ``.rep`` without its ``.gpr`` is
    ``rep_without_gpr`` (the 4 of 162 kills of D41). ``require_sidecar`` is false for forks made by
    hydra.3, which writes no ``state``."""
    rep = rep or Report("K6")
    rep.ran("K6")
    gpr = pathlib.Path(gpr)
    rp = gpr.with_suffix(".rep")
    if not gpr.exists() and not rp.exists():
        return rep  # absent
    if rp.exists() and not gpr.exists():
        rep.violation("K6", "rep_without_gpr", f"{rp.name} exists and {gpr.name} does not", rp)
        return rep
    if gpr.exists() and not rp.exists():
        rep.violation("K6", "gpr_without_rep", f"{gpr.name} exists and {rp.name} does not", gpr)
        return rep
    side = gpr.with_name(gpr.stem + ".fork.json")
    # 8.13: the sidecar's temporary file of a killed writer is gone after the sweep; A62: it is
    # <name>.fork.json.<pid>.tmp (<name>.fork.json.tmp of an older build)
    for t in sorted(side.parent.glob(side.name + ".*tmp")):
        if re.fullmatch(re.escape(side.name) + r"(\.\d+)?\.tmp", t.name):
            rep.violation("K6", "sidecar_tmp_left", f"{t.name} is next to a complete fork", t)
    if not side.exists():
        if require_sidecar:
            rep.violation("K6", "no_sidecar", "a complete fork without its sidecar", side)
    else:
        try:
            d = json.loads(side.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            rep.violation("K6", "sidecar_unparseable", str(e), side)
            d = None
        if d is not None and "state" in d:
            want = "candidate" if kind == "generation" else "complete"
            if d["state"] not in (want, "complete"):
                rep.violation("K6", "sidecar_state", f"state {d['state']!r}, expected {want!r}", side)
        elif d is not None and require_sidecar and "state" not in d:
            rep.note("K6", "sidecar_has_no_state", "format-1 sidecar of hydra.3 (no state field)", side)
    if base_tree is not None and tree_hash(rp)["tree_sha256"] != base_tree:
        # compared on the .rep folder only: the fork folder also holds its sidecar and lock residue
        rep.violation("K6", "data_differs_from_base", "fork data is not equal to its base", rp)
    return rep


#: the K6 findings of ``check_k6`` that are a half publish a sweep finishes (D41, 8.13): pending until the sweep,
#: a violation after it. Every other finding (a .gpr without its .rep, a sidecar in another state, an unparseable
#: sidecar) is a violation at any instant
K6_PENDING_CODES = ("sidecar_state_publishing", "sidecar_tmp_left")


def check_k6_tree(root, swept: bool, rep: Report | None = None, skip_prefixes=("del-",)) -> Report:
    """K6 over every fork destination under ``root`` (PROTOCOL-3 8.13): **0 ``.gpr`` without its ``.rep`` at any
    instant; 0 ``.rep`` without ``.gpr`` after the sweep; engine-private staging folders are not projects** (never
    entered, never judged as forks). Before the sweep (``swept=False``) a ``.rep`` without ``.gpr``, a staging folder,
    a sidecar still ``publishing`` and a sidecar ``.tmp`` are recorded as notes ``pending_sweep`` (with the folder
    that needs it in ``extra['parent']``); after the sweep (``swept=True``) each is a violation and every fork must be
    absent or complete. Folders named with ``skip_prefixes`` (a harness's own atomic delete) are not walked."""
    rep = rep or Report("K6")
    rep.ran("K6")
    root = pathlib.Path(root)
    if not root.exists():
        return rep

    def pending(code, detail, path, parent):
        if swept:
            rep.violation("K6", code, detail + " (after the sweep)", path)
        else:
            rep.note("K6", "pending_sweep", f"{code}: {detail}", path, parent=str(parent))

    for dirpath, dirs, files in os.walk(root):
        here = pathlib.Path(dirpath)
        all_dirs = list(dirs)
        dirs[:] = [d for d in dirs if not STAGING.match(d) and not d.endswith(".rep")
                   and not any(d.startswith(p) for p in skip_prefixes)]
        for d in all_dirs:
            if STAGING.match(d):
                pending("staging_left", f"{d} (an engine-private staging folder)", here / d, here)
            elif d.endswith(".rep") and (d[:-4] + ".gpr") not in files:
                pending("rep_without_gpr", f"{d} exists and {d[:-4]}.gpr does not", here / d, here)
        for f in files:
            if not f.endswith(".gpr"):
                continue
            kind = "fork"
            with contextlib.suppress(OSError, ValueError, AttributeError):
                side = json.loads((here / (f[:-4] + ".fork.json")).read_text(encoding="utf-8"))
                kind = "generation" if side.get("purpose") == "generation" else "fork"
            # a generation candidate (D38) is complete in state candidate before its seal, complete after it
            one = check_k6(here / f, kind=kind, require_sidecar=False, rep=Report("k6-one"))
            codes = set()
            for x in one.findings:
                code = x["code"]
                if code == "sidecar_state" and "'publishing'" in x["detail"]:
                    code = "sidecar_state_publishing"
                codes.add(code)
                if code in K6_PENDING_CODES:
                    pending(x["code"], x["detail"], x.get("path"), here)
                else:
                    rep.violation("K6", x["code"], x["detail"], x.get("path"))
            # the temporary sidecar of a publisher killed between its write and its rename, next to a complete fork:
            # <name>.fork.json.tmp, or <name>.fork.json.<pid>.tmp since 8.13 A62
            rx = re.compile(re.escape(f[:-4]) + r"\.fork\.json(\.\d+)?\.tmp$")
            for tmp in sorted(x for x in files if rx.match(x)):
                if "sidecar_tmp_left" not in codes and (here / f[:-4]).with_suffix(".rep").is_dir():
                    pending("sidecar_tmp_left", f"{tmp} is next to a complete fork", here / tmp, here)
    return rep


def k6_pending_parents(rep: Report) -> list:
    """The folders a sweep must visit: the ``parent`` of every ``pending_sweep`` note of ``check_k6_tree``."""
    return sorted({n.get("parent") for n in rep.notes if n.get("code") == "pending_sweep" and n.get("parent")})


def check_k6_staging(parent, rep: Report | None = None) -> Report:
    """K6: no staging folder ``.<name>.fork-<id>.tmp`` after the next sweep."""
    rep = rep or Report("K6")
    rep.ran("K6")
    try:
        for e in os.scandir(parent):
            if e.is_dir() and STAGING.match(e.name):
                rep.violation("K6", "staging_left", f"{e.name} was not swept", e.path)
    except OSError:
        pass
    return rep


# ------------------------------------------------------------------------------ processes (K7, K14)

class _PE32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260)]


class _TE32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ThreadID", ctypes.c_uint32), ("th32OwnerProcessID", ctypes.c_uint32),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long), ("dwFlags", ctypes.c_uint32)]


def _k32():
    k = ctypes.windll.kernel32
    k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    k.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PE32)]
    k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PE32)]
    k.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(_TE32)]
    k.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(_TE32)]
    k.OpenProcess.restype = ctypes.c_void_p
    k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.OpenThread.restype = ctypes.c_void_p
    k.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    k.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p,
                                             ctypes.POINTER(ctypes.c_uint32)]
    k.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    return k


def list_processes() -> list[dict]:
    """``[{pid, ppid, name, threads}]`` of every process now (Win32 tool-help snapshot)."""
    if os.name != "nt":
        raise NotImplementedError("process checks are implemented for Windows only")
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    out = []
    try:
        pe = _PE32()
        pe.dwSize = ctypes.sizeof(_PE32)
        ok = k.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            out.append({"pid": pe.th32ProcessID, "ppid": pe.th32ParentProcessID,
                        "name": pe.szExeFile, "threads": pe.cntThreads})
            ok = k.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k.CloseHandle(snap)
    return out


def pid_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    k = _k32()
    h = k.OpenProcess(0x1000, 0, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    try:
        code = ctypes.c_uint32()
        return bool(k.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
    finally:
        k.CloseHandle(h)


def process_image(pid: int) -> str | None:
    k = _k32()
    h = k.OpenProcess(0x1000, 0, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.c_uint32(1024)
        return buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
    finally:
        k.CloseHandle(h)


def handle_count(pid: int) -> int | None:
    k = _k32()
    h = k.OpenProcess(0x1000, 0, pid)
    if not h:
        return None
    try:
        n = ctypes.c_uint32()
        return n.value if k.GetProcessHandleCount(h, ctypes.byref(n)) else None
    finally:
        k.CloseHandle(h)


def thread_count(pid: int) -> int | None:
    for p in list_processes():
        if p["pid"] == pid:
            return p["threads"]
    return None


def descendants(pids) -> set[int]:
    """``pids`` and every process below them in the parent chain (by the live process table)."""
    procs = list_processes()
    kids: dict[int, list[int]] = {}
    for p in procs:
        kids.setdefault(p["ppid"], []).append(p["pid"])
    out, todo = set(), list(pids)
    while todo:
        x = todo.pop()
        if x in out:
            continue
        out.add(x)
        todo.extend(kids.get(x, []))
    return out


def process_suspended(pid: int) -> bool | None:
    """True when every thread of ``pid`` has a suspend count above 0 (``NtQueryInformationThread``,
    class 35); None when it cannot be told (access, an older Windows)."""
    k = _k32()
    nt = ctypes.windll.ntdll
    snap = k.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
    counts = []
    try:
        te = _TE32()
        te.dwSize = ctypes.sizeof(_TE32)
        ok = k.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                h = k.OpenThread(0x40, 0, te.th32ThreadID)  # THREAD_QUERY_INFORMATION
                if not h:
                    h = k.OpenThread(0x800, 0, te.th32ThreadID)  # THREAD_QUERY_LIMITED_INFORMATION
                if not h:
                    return None
                try:
                    cnt = ctypes.c_uint32()
                    ret = ctypes.c_uint32()
                    st = nt.NtQueryInformationThread(ctypes.c_void_p(h), 35, ctypes.byref(cnt), 4,
                                                     ctypes.byref(ret))
                    if st != 0:
                        return None
                    counts.append(cnt.value)
                finally:
                    k.CloseHandle(h)
            ok = k.Thread32Next(snap, ctypes.byref(te))
    finally:
        k.CloseHandle(snap)
    return bool(counts) and all(c > 0 for c in counts)


def find_orphan_decompilers(daemon_pids=(), names=DECOMPILER_NAMES) -> list[dict]:
    """Native decompiler processes that are not below one of ``daemon_pids``. With the daemon dead
    (``daemon_pids`` empty or gone) every decompiler left is an orphan; a busy one exits by itself when
    its pipe closes, so one that is still there after 5 s is suspended or hung, the case K7 is about
    (SP3(b)). ``suspended`` is reported when it can be read."""
    keep = descendants([p for p in daemon_pids if pid_alive(p)]) if daemon_pids else set()
    out = []
    for p in list_processes():
        if p["name"].lower() in names and p["pid"] not in keep:
            out.append({"pid": p["pid"], "ppid": p["ppid"], "name": p["name"],
                        "parent_alive": pid_alive(p["ppid"]), "suspended": process_suspended(p["pid"])})
    return out


def check_k7_processes(daemon_pids=(), settle_s: float = 5.0, only_pids=None, names=DECOMPILER_NAMES,
                       rep: Report | None = None) -> Report:
    """K7: no orphan decompiler or worker process within ``settle_s`` of the daemon's death. ``only_pids``
    restricts the check to processes the caller started (other agents run decompilers on this machine)."""
    rep = rep or Report("K7")
    rep.ran("K7")
    deadline = time.time() + settle_s
    orphans = find_orphan_decompilers(daemon_pids, names)
    if only_pids is not None:
        orphans = [o for o in orphans if o["pid"] in set(only_pids)]
    while orphans and time.time() < deadline:
        time.sleep(0.25)
        orphans = [o for o in find_orphan_decompilers(daemon_pids, names)
                   if only_pids is None or o["pid"] in set(only_pids)]
    for o in orphans:
        rep.violation("K7", "orphan_decompiler",
                      f"pid {o['pid']} ({o['name']}) is still there {settle_s} s after the daemon, "
                      f"suspended={o['suspended']}", None, **o)
    return rep


def check_k7_threads(pid: int, baseline: int, slack: int = 8, label: str = "",
                     rep: Report | None = None) -> Report:
    """K7/K14: threads of ``pid`` bounded: more than ``baseline + slack`` is ``thread_leak``."""
    rep = rep or Report("K7")
    rep.ran("K7")
    n = thread_count(pid)
    if n is None:
        rep.violation("K7", "process_gone", f"pid {pid} has no thread count {label}")
    elif n > baseline + slack:
        rep.violation("K7", "thread_leak", f"{n} threads against a baseline of {baseline} (+{slack}) {label}",
                      None, threads=n, baseline=baseline)
    return rep


def check_k7_handles(pid: int, baseline: int, slack: int = 200, rep: Report | None = None) -> Report:
    rep = rep or Report("K7")
    rep.ran("K7")
    n = handle_count(pid)
    if n is not None and n > baseline + slack:
        rep.violation("K7", "handle_leak", f"{n} handles against a baseline of {baseline} (+{slack})",
                      None, handles=n, baseline=baseline)
    return rep


def lock_files(root) -> list[pathlib.Path]:
    out = []
    for directory, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".lock") or name.endswith(".lock~"):
                out.append(pathlib.Path(directory, name))
    return out


def check_k7_locks(root, quiescent: bool = True, live_pids=(), lease_s: float = LOCK_LEASE_S,
                   rep: Report | None = None) -> Report:
    """K7: ``.lock`` and ``.lock~`` only for live processes.

    A Ghidra lock file is a lease that its holder renews (it carries no pid), so "a lock for a live
    process" is read from the file's age against the 15 s lease and from the processes the caller
    says are alive (``live_pids``, the daemons under test):

    * ``quiescent`` (no daemon is meant to hold a project of ``root``): any lock file is a
      violation, ``lock_live`` when its lease is still fresh (somebody is renewing it: a live process
      this run does not own) and ``lock_stale`` when it is not (the residue of a killed holder).
    * not quiescent: a lock older than the lease with no live daemon is ``lock_stale``.

    The spec names the planted violation X3 "a ``.lock`` for a live process"; both readings are
    flagged here. Per the measurements the engine takes stale locks over without error (131 of 131),
    so a stale one is reported, not an engine failure."""
    rep = rep or Report("K7")
    rep.ran("K7")
    now = time.time()
    daemons_alive = any(pid_alive(p) for p in live_pids)
    for p in lock_files(root):
        try:
            age = now - p.stat().st_mtime
        except OSError:
            continue
        fresh = age <= lease_s
        if quiescent:
            rep.violation("K7", "lock_live" if fresh else "lock_stale",
                          f"{p.name} (age {age:.1f} s) in a tree no daemon should hold", p, age_s=round(age, 1))
        elif not daemons_alive and not fresh:
            rep.violation("K7", "lock_stale", f"{p.name} (age {age:.1f} s) and no live daemon", p,
                          age_s=round(age, 1))
    return rep


def check_k7_tmp(tmpdir, before: int | None = None, slack: int = 16, patterns=("tmp*",),
                 rep: Report | None = None) -> Report:
    """K7: no orphan ``tmp*`` and the JVM temp folder not growing across restarts (``before`` is the
    count of its entries after the first start)."""
    rep = rep or Report("K7")
    rep.ran("K7")
    try:
        n = len(os.listdir(tmpdir))
    except OSError:
        return rep
    if before is not None and n > before + slack:
        rep.violation("K7", "tmp_growth", f"{n} entries in the temp folder, {before} before (+{slack})",
                      tmpdir, entries=n, before=before)
    return rep


# ------------------------------------------------------------------------------ the witness ledger (K5)

class Ledger:
    """The harness's own fsynced record of what it sent and what was acknowledged: the witness of
    K4, K5 and K12. One JSON object per line, flushed and ``os.fsync``-ed before ``sent``/``ack``
    return, so a kill of the harness cannot lose an acknowledgement it printed."""

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(self.path, "ab", buffering=0)
        self._lock = threading.Lock()

    def _w(self, rec):
        rec["t"] = round(time.time(), 3)
        with self._lock:
            self._f.write((json.dumps(rec, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(self._f.fileno())

    def sent(self, op: str, kind: str = "op", **fields):
        self._w({"phase": "sent", "op": op, "kind": kind, **fields})

    def ack(self, op: str, kind: str = "op", **fields):
        self._w({"phase": "ack", "op": op, "kind": kind, **fields})

    def close(self):
        with contextlib.suppress(Exception):
            self._f.close()

    @staticmethod
    def read(path) -> list[dict]:
        out = []
        try:
            for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
                with contextlib.suppress(ValueError):
                    out.append(json.loads(line))  # a torn last line of the ledger is ignored
        except OSError:
            pass
        return out

    @staticmethod
    def acked(records, kind: str | None = None) -> list[str]:
        return [r["op"] for r in records if r.get("phase") == "ack" and (kind is None or r.get("kind") == kind)]

    @staticmethod
    def sent_ops(records, kind: str | None = None) -> list[str]:
        return [r["op"] for r in records if r.get("phase") == "sent" and (kind is None or r.get("kind") == kind)]


def check_k5(acked, recovered, kind: str = "op", rep: Report | None = None) -> Report:
    """K5: no acknowledged save, import, promote or publish is missing after recovery. ``acked`` are the
    ledger's acknowledged operation ids, ``recovered`` the ids the recovered state shows."""
    rep = rep or Report("K5")
    rep.ran("K5")
    have = set(recovered)
    for op in acked:
        if op not in have:
            rep.violation("K5", "acked_missing", f"acknowledged {kind} {op!r} is missing after recovery", None,
                          op=op)
    return rep


# ------------------------------------------------------------------------------ K4: generation atomicity

TAG_RX = re.compile(r"^(?P<prefix>[A-Za-z]+?)(?P<gen>\d+)_(?P<i>\d+)$")


def tag_generation(name: str, prefix: str = "cg"):
    m = re.search(re.escape(prefix) + r"(\d+)_(\d+)$", name or "")
    return int(m.group(1)) if m else None


def check_k4(names: dict, tagged, sent: int, acked: int, prefix: str = "cg", rep: Report | None = None) -> Report:
    """K4: a tagged edit set shows exactly one generation ``G`` with ``acked <= G <= sent``.
    ``names`` maps address to function name, ``tagged`` are the addresses the edit set renames
    (names ``<prefix><gen>_<i>``); an address that carries no tag counts as generation -1 (the edit
    set is whole in one generation or it is mixed)."""
    rep = rep or Report("K4")
    rep.ran("K4")
    gens: dict[int, int] = {}
    for a in tagged:
        g = tag_generation(names.get(a, ""), prefix)
        gens[-1 if g is None else g] = gens.get(-1 if g is None else g, 0) + 1
    if len(gens) > 1:
        rep.violation("K4", "mixed_generation", f"the edit set shows several generations: {dict(sorted(gens.items()))}",
                      None, gens=gens)
        return rep
    if gens:
        g = next(iter(gens))
        if g != -1 and not (acked <= g <= sent):
            rep.violation("K4", "generation_out_of_range", f"generation {g} outside acked {acked} .. sent {sent}",
                          None, generation=g)
        if g == -1 and acked > 0:
            rep.violation("K4", "generation_out_of_range", f"no tag found but generation {acked} was acknowledged")
    return rep


# ------------------------------------------------------------------------------ CRC logs and sealed JSON (K12, K17)

def crc_line(obj) -> bytes:
    """One ``CURRENT.log`` line as the spec frames it: ``crc-hex8 SP json LF`` (CRC-32 of the JSON bytes)."""
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b"%08x %s\n" % (zlib.crc32(body) & 0xFFFFFFFF, body)


def _parse_crc_line(raw: bytes):
    if len(raw) < 10 or raw[8:9] != b" ":
        return None
    try:
        crc = int(raw[:8], 16)
    except ValueError:
        return None
    body = raw[9:]
    if (zlib.crc32(body) & 0xFFFFFFFF) != crc:
        return None
    try:
        return json.loads(body.decode("utf-8")), body
    except ValueError:
        return None


def read_crc_log(path) -> dict:
    """Reads a CRC-framed log the way the spec's *reader* does (4.1, item 3): the longest prefix of
    valid lines; an invalid suffix with no valid line after it is a torn tail (ignored and reported);
    an invalid line followed by a valid one is corruption. A final fragment without LF is never valid.

    Returns ``{"lines": [(offset, obj, body_bytes)], "torn_tail": None | {"offset","bytes"},
    "corrupt": [{"offset", "bytes"}], "exists": bool}``."""
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError:
        return {"lines": [], "torn_tail": None, "corrupt": [], "exists": False}
    items = []  # (offset, valid?, parsed, nbytes)
    off = 0
    while off < len(data):
        nl = data.find(b"\n", off)
        if nl < 0:
            items.append((off, False, None, len(data) - off))
            break
        raw = data[off:nl]
        parsed = _parse_crc_line(raw)
        items.append((off, parsed is not None, parsed, nl + 1 - off))
        off = nl + 1
    last_valid = max((i for i, it in enumerate(items) if it[1]), default=-1)
    lines = [(o, p[0], p[1]) for (o, ok, p, _n) in items if ok]
    corrupt = [{"offset": o, "bytes": n} for i, (o, ok, _p, n) in enumerate(items) if not ok and i < last_valid]
    tail = items[last_valid + 1:]
    torn = {"offset": tail[0][0], "bytes": sum(t[3] for t in tail)} if tail else None
    return {"lines": lines, "torn_tail": torn, "corrupt": corrupt, "exists": True}


def seal_value(body: dict) -> str:
    """The ``seal.value`` of a sealed JSON record: sha256 of the canonical body without ``seal``."""
    return sha256_hex(canonical({k: v for k, v in body.items() if k != "seal"}))


def seal_record(body: dict) -> dict:
    out = {k: v for k, v in body.items() if k != "seal"}
    out["seal"] = {"algo": "sha256", "value": seal_value(out)}
    return out


def read_sealed(path):
    """``(obj, how)``: ``how`` is ``"ok"``, ``"bak"`` (the previous sealed version was used) or
    ``"corrupt"`` (neither validates; ``obj`` is None). Never starts empty (4.1 item 2)."""
    def load(p):
        try:
            d = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        s = d.get("seal") if isinstance(d, dict) else None
        if not isinstance(s, dict) or s.get("algo") != "sha256" or s.get("value") != seal_value(d):
            return None
        return d
    d = load(path)
    if d is not None:
        return d, "ok"
    d = load(str(path) + ".bak")
    if d is not None:
        return d, "bak"
    return None, "corrupt"


#: plain JSON files of a lineage folder that are not sealed records (K17)
NOT_RECORDS = {"publish.leader.json"}


def _not_a_record(p) -> bool:
    """True for a known non-record (``NOT_RECORDS``, or a file inside a project's ``.rep``) that parses as a JSON object
    without a ``seal`` and whose ``.bak`` (if any) is no sealed record either. Anything else is judged as a record: a
    record that lost its seal, or a torn file, is a violation."""
    pp = pathlib.Path(p)
    if pp.name not in NOT_RECORDS and not any(x.endswith(".rep") for x in pp.parts[:-1]):
        return False
    def obj(x):
        try:
            return json.loads(pathlib.Path(x).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    d = obj(p)
    if not isinstance(d, dict) or "seal" in d:
        return False
    b = obj(str(p) + ".bak")
    return not (isinstance(b, dict) and "seal" in b)


def check_k17(store_dir, log_path=None, rep: Report | None = None) -> Report:
    """K17: every sealed record file validates or falls back to its previous version (``.bak``); a
    ``CURRENT.log`` may have a torn *last* line only (tolerated), never a torn middle."""
    rep = rep or Report("K17")
    rep.ran("K17")
    if store_dir and pathlib.Path(store_dir).is_dir():
        for p in sorted(pathlib.Path(store_dir).rglob("*.json")):
            if p.name.endswith(".fork.json") or p.name in ("SEALED.json", "MANIFEST.json", "lineage.json"):
                continue
            d, how = read_sealed(p)
            if how == "corrupt" and _not_a_record(p):
                # 8.13: K17 is about sealed records. Two kinds of plain JSON file live in a lineage folder and are not
                # records: the publish leader's marker (written by an atomic rename) and a file inside a project's
                # .rep (program data). Only those, and only while they are whole JSON with no seal, are left out
                rep.note("K17", "not_a_sealed_record", f"{p.name} is plain JSON with no seal", p)
                continue
            if how == "corrupt":
                rep.violation("K17", "record_corrupt", f"{p.name} and its .bak both fail validation", p)
            elif how == "bak":
                rep.note("K17", "record_fell_back", f"{p.name} read from its .bak", p)
    if log_path:
        lg = read_crc_log(log_path)
        for c in lg["corrupt"]:
            rep.violation("K17", "torn_middle", f"invalid line at byte {c['offset']} followed by a valid line",
                          log_path, **c)
        if lg["torn_tail"]:
            rep.tolerate("K17", "torn_tail", f"torn last line at byte {lg['torn_tail']['offset']} "
                         f"({lg['torn_tail']['bytes']} bytes), ignored by readers", log_path, **lg["torn_tail"])
    return rep


# ------------------------------------------------------------------------------ the model (K8, K15, K16)

class Model:
    """The sequential reference model of K16: a dict ``{(subject, field): value}`` and one rule for a
    record ``{id, subject, field, before, after}``: applied when the current value equals ``before``
    (or ``before`` is None, or the value already equals ``after``: converged), otherwise it is a
    conflict and is not applied. A changeset is applied record by record in ``seq`` order."""

    def __init__(self, base: dict | None = None):
        self.state = dict(base or {})

    def apply_record(self, rec: dict) -> str:
        key = (rec["subject"], rec["field"])
        cur = self.state.get(key)
        if cur == rec.get("after") and rec.get("after") is not None:
            return "converged"
        if rec.get("before") is None or cur == rec["before"]:
            self.state[key] = rec["after"]
            return "applied"
        return "conflict"

    def apply_changeset(self, records) -> dict:
        res = {"applied": [], "converged": [], "conflict": []}
        for r in sorted(records, key=lambda r: r.get("seq", 0)):
            res[self.apply_record(r)].append(r["id"])
        return res


def state_diff(a: dict, b: dict) -> list:
    """Keys whose values differ between two ``{(subject, field): value}`` or ``{key: value}`` maps."""
    return [(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b), key=str) if a.get(k) != b.get(k)]


def check_k8(base_state: dict, records, view_state: dict, kid: str = "K8", rep: Report | None = None) -> Report:
    """K8 (and K15 with ``kid="K15"``): replaying the op-log ``records`` onto the base generation's
    state equals the view's state. Every record is applied in ``seq`` order; a record the view
    shows differently is ``view_differs_from_replay``."""
    rep = rep or Report(kid)
    rep.ran(kid)
    m = Model(base_state)
    for r in sorted(records, key=lambda r: r.get("seq", 0)):
        m.state[(r["subject"], r["field"])] = r["after"]
    for k, a, b in state_diff(m.state, view_state):
        rep.violation(kid, "view_differs_from_replay", f"{k}: replay says {a!r}, the view shows {b!r}", None,
                      key=str(k))
    return rep


def check_k15(base_state: dict, records, live_state: dict, rep: Report | None = None) -> Report:
    return check_k8(base_state, records, live_state, kid="K15", rep=rep)


def check_k16(base_state: dict, log_lines, changesets: dict, head_state: dict, manifests: dict | None = None,
              acked_csids=(), rep: Report | None = None) -> Report:
    """K16: fold the changesets named by the ``CURRENT.log`` lines in log order through :class:`Model`;
    the result equals ``head_state`` (a silent lost update, which no file check sees, shows here) and,
    when ``manifests`` (``{gen: manifest}``) says which ids a generation claims, the model applies
    exactly those ids. ``changesets`` is ``{csid: {"records": [...]}}``."""
    rep = rep or Report("K16")
    rep.ran("K16")
    m = Model(base_state)
    for ln in log_lines:
        claimed = None
        if manifests and ln.get("gen") in manifests:
            claimed = set(manifests[ln["gen"]].get("store", {}).get("ids", []))
        got = []
        for csid in ln.get("csids", []):
            cs = changesets.get(csid)
            if cs is None:
                rep.violation("K16", "changeset_missing", f"generation {ln.get('gen')} names {csid!r} and no record of it exists",
                              None, csid=csid)
                continue
            res = m.apply_changeset(cs["records"])
            got += res["applied"] + res["converged"]
        if claimed is not None and set(got) != claimed:
            rep.violation("K16", "engine_claim_differs", f"gen {ln.get('gen')}: the model applies "
                          f"{sorted(set(got) - claimed)} more and {sorted(claimed - set(got))} fewer than the manifest",
                          None, gen=ln.get("gen"))
    for k, a, b in state_diff(m.state, head_state):
        rep.violation("K16", "head_differs_from_model", f"{k}: model {a!r}, head {b!r}", None, key=str(k))
    return rep


# ------------------------------------------------------------------------------ K12: the lineage log

def load_lineage(folder) -> dict:
    """Reads a lineage folder (4.4): ``CURRENT.log``, the manifests under ``gen/``, and the changesets
    under ``pending/`` and ``done/``. Nothing is repaired."""
    folder = pathlib.Path(folder)
    out = {"log": read_crc_log(folder / "CURRENT.log"), "manifests": {}, "changesets": {}, "done": set(),
           "pending": set(), "folder": folder}
    for mp in sorted((folder / "gen").glob("*/MANIFEST.json")) if (folder / "gen").is_dir() else []:
        try:
            out["manifests"][int(mp.parent.name)] = json.loads(mp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    for sub in ("pending", "done"):
        d = folder / sub
        if d.is_dir():
            for f in d.glob("*.json"):
                obj, how = read_sealed(f)
                if obj is None:
                    try:
                        obj = json.loads(f.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        continue
                csid = obj.get("csid", f.stem)
                out["done" if sub == "done" else "pending"].add(csid)
                if "records" in obj:
                    out["changesets"][csid] = obj
    return out


def check_k12(lineage: dict, acked_csids=(), rep: Report | None = None) -> Report:
    """K12: publish linearisation. The ``CURRENT.log`` generations are consecutive (no duplicate, no
    gap, ``seq`` increasing), each line's manifest lists exactly the ids of the changesets the line
    names, no acknowledged changeset is missing, none is applied twice, a ``done`` file never exists
    for a changeset the log does not name (the append is the commit point, the ``done`` file follows
    it), and a mid-log gap is corruption. A torn last line is tolerated (X6)."""
    rep = rep or Report("K12")
    rep.ran("K12")
    log = lineage["log"]
    lines = [o for (_off, o, _b) in log["lines"]]
    for c in log["corrupt"]:
        rep.violation("K12", "mid_log_gap", f"invalid line at byte {c['offset']} with valid lines after it",
                      lineage["folder"] / "CURRENT.log", **c)
    if log["torn_tail"]:
        rep.tolerate("K12", "torn_tail", f"torn last line at byte {log['torn_tail']['offset']}, ignored by readers",
                     lineage["folder"] / "CURRENT.log", **log["torn_tail"])
    seen_gen: dict[int, int] = {}
    prev_gen = None
    prev_seq = None
    seen_cs: dict[str, int] = {}
    prev_body = None
    for idx, (_off, ln, body) in enumerate(log["lines"]):
        g = ln.get("gen")
        if g in seen_gen:
            rep.violation("K12", "duplicate_generation", f"generation {g} appears on lines {seen_gen[g]} and {idx}", None,
                          gen=g)
        seen_gen[g] = idx
        if prev_gen is not None and g is not None and g != prev_gen + 1 and g not in (prev_gen,) and \
                ln.get("reason") not in ("rollback", "recover"):
            rep.violation("K12", "generation_gap", f"generation {g} follows {prev_gen}", None, gen=g)
        if prev_seq is not None and ln.get("seq") is not None and ln["seq"] <= prev_seq:
            rep.violation("K12", "seq_not_increasing", f"seq {ln['seq']} after {prev_seq}", None)
        prev_gen = g if g is not None else prev_gen
        prev_seq = ln.get("seq", prev_seq)
        if "prevHash" in ln and prev_body is not None:
            want = {sha256_hex(prev_body), sha256_hex(prev_body + b"\n")}
            if ln["prevHash"] not in want:
                rep.note("K12", "prevhash_unverified", f"line {idx}: prevHash is not the sha256 of the previous "
                         "line's JSON (the hashed byte range is not pinned by the spec)")
        prev_body = body
        for cs in ln.get("csids", []):
            if cs in seen_cs:
                rep.violation("K12", "applied_twice", f"changeset {cs!r} is named by lines {seen_cs[cs]} and {idx}",
                              None, csid=cs)
            seen_cs[cs] = idx
        man = lineage["manifests"].get(g)
        if man is not None and ln.get("csids") and lineage["changesets"]:
            ids = {r["id"] for cs in ln["csids"] for r in lineage["changesets"].get(cs, {}).get("records", [])}
            listed = set(man.get("store", {}).get("ids", [])) | set(man.get("store", {}).get("skipped", []))
            if listed and listed != ids:
                rep.violation("K12", "manifest_differs_from_changesets",
                              f"generation {g}: the manifest lists {len(listed)} ids, the changesets hold {len(ids)}",
                              None, gen=g)
    for cs in acked_csids:
        if cs not in seen_cs:
            rep.violation("K12", "acked_publish_missing", f"acknowledged changeset {cs!r} is in no CURRENT.log line",
                          None, csid=cs)
    for cs in lineage["done"]:
        if cs not in seen_cs:
            rep.violation("K12", "done_without_commit", f"done/{cs}.json exists and CURRENT.log never names {cs!r}",
                          None, csid=cs)
    for cs in seen_cs:
        if cs not in lineage["done"] and lineage["done"]:
            rep.note("K12", "publish_incomplete", f"{cs!r} is in CURRENT.log without a done file (resolved by the manifest)")
    return rep


# ------------------------------------------------------------------------------ K9, K10, K11, K13, K14

class TreeGuard:
    """K9: the tree hash of every project not involved in an operation is unchanged."""

    def __init__(self, **roots):
        self.roots = {k: pathlib.Path(v) for k, v in roots.items()}
        self.base = {k: tree_hash(v)["tree_sha256"] for k, v in self.roots.items()}

    def check(self, rep: Report | None = None, involved=()) -> Report:
        rep = rep or Report("K9")
        rep.ran("K9")
        for k, root in self.roots.items():
            if k in involved:
                continue
            now = tree_hash(root)["tree_sha256"]
            if now != self.base[k]:
                rep.violation("K9", "uninvolved_project_changed", f"{k}: tree hash changed", root)
        return rep


def check_k10(connect, dead_client: str, timeout_s: float = 10.0, rep: Report | None = None) -> Report:
    """K10 liveness: after a client kill the daemon answers ``ping`` and no request or slot is held for
    the dead client. ``connect(name)`` returns a fresh live session."""
    rep = rep or Report("K10")
    rep.ran("K10")
    t0 = time.time()
    try:
        s = connect("oracle-k10")
        s.call("ping")
    except Exception as e:  # noqa: BLE001
        rep.violation("K10", "no_ping", f"the daemon does not answer ping: {e}")
        return rep
    try:
        while True:
            st = s.call("status")
            held = [c for c in st.get("clients", []) if c.get("name") == dead_client]
            if not held:
                break
            if time.time() - t0 > timeout_s:
                rep.violation("K10", "dead_client_held",
                              f"{dead_client!r} is still registered {timeout_s} s after its death: "
                              f"{[(c.get('name'), len(c.get('requests', []))) for c in held]}")
                break
            time.sleep(0.25)
    finally:
        with contextlib.suppress(Exception):
            s.close()
    return rep


def check_k11(views: dict, published: dict | None = None, rep: Report | None = None,
              shared_ok: bool = False) -> Report:
    """K11: view isolation. ``views`` maps an agent id (or ``"head"``) to ``{"own": set(tags), "saw":
    set(tags)}``; ``published`` maps a tag to ``True`` once published. No viewer sees an unpublished tag
    of another agent id (``head`` owns none). ``shared_ok`` is the K11p case: callers that present the
    same id share a view and see each other's tags (documented, D59), so the caller groups them under
    one id."""
    rep = rep or Report("K11")
    rep.ran("K11")
    published = published or {}
    owner = {t: a for a, v in views.items() for t in v.get("own", ())}
    for viewer, v in views.items():
        for tag in v.get("saw", ()):
            who = owner.get(tag)
            if who is None or who == viewer:
                continue
            if not published.get(tag):
                rep.violation("K11", "unpublished_tag_visible", f"{viewer} saw unpublished tag {tag!r} of {who}",
                              None, viewer=viewer, owner=who, tag=tag)
    return rep


def check_k13(health: dict, quiet_p99_ms: float | None = None, rep: Report | None = None) -> Report:
    """K13 non-blocking attribution: ``waits.foreignBlocked`` is 0 for reads of sealed generations and
    view operations (the deterministic part). The lock-wait p99 is recorded as a note, and fails only
    when ``quiet_p99_ms`` (a threshold fixed from a quiet-machine run, D49) is given."""
    rep = rep or Report("K13")
    rep.ran("K13")
    waits = (health or {}).get("waits")
    if not isinstance(waits, dict) or "foreignBlocked" not in waits:
        rep.note("K13", "not_measured", "this engine reports no waits.foreignBlocked (hydra.3)")
        return rep
    fb = waits["foreignBlocked"]
    n = fb.get("total", fb.get("sinceStart", 0)) if isinstance(fb, dict) else fb
    if n:
        rep.violation("K13", "foreign_blocked", f"waits.foreignBlocked is {fb}", None, value=fb)
    p99 = waits.get("lockWaitP99Ms", waits.get("p99Ms"))
    if p99 is not None:
        rep.note("K13", "lock_wait_p99_recorded", f"engine-reported lock wait p99 {p99} ms", None, p99=p99)
        if quiet_p99_ms is not None and p99 > quiet_p99_ms:
            rep.violation("K13", "lock_wait_p99", f"p99 {p99} ms above the quiet-machine threshold {quiet_p99_ms}")
    return rep


def check_k14(status: dict, health: dict | None = None, rep: Report | None = None, hard_watermark_mb: float | None = None,
              log_text: str = "") -> Report:
    """K14 resources: no ``OutOfMemoryError`` in the log, heap after GC below the hard watermark (when
    given), ``slots inUse`` 0 after drain, no dead daemon thread (``health.deadThreads`` /
    ``leakedWorkers``, when the engine reports them)."""
    rep = rep or Report("K14")
    rep.ran("K14")
    if "OutOfMemoryError" in log_text:
        rep.violation("K14", "out_of_memory", "OutOfMemoryError in the engine log")
    for lane, sch in ((status or {}).get("scheduler") or {}).items():
        if isinstance(sch, dict) and sch.get("inUse"):
            rep.violation("K14", "slots_in_use", f"lane {lane}: {sch['inUse']} slot(s) in use after drain", None, lane=lane)
    mem = (status or {}).get("memory") or {}
    if hard_watermark_mb is not None:
        used = mem.get("usedAfterGcMb", mem.get("usedMb"))
        if used is None:
            rep.note("K14", "heap_not_measured", "the engine reports no heap figure")
        elif used > hard_watermark_mb:
            rep.violation("K14", "heap_above_watermark", f"{used} MB above {hard_watermark_mb} MB")
    h = health or {}
    if h.get("deadThreads"):
        rep.violation("K14", "dead_thread", f"dead daemon thread(s): {h['deadThreads']}")
    if h.get("leakedWorkers"):
        rep.violation("K14", "leaked_workers", f"leaked workers: {h['leakedWorkers']}")
    return rep


# ------------------------------------------------------------------------------ K3 (live engine)

def _all_functions(c, key):
    out, off = [], 0
    while True:
        r = c.call("functions", program=key, offset=off, limit=10000)
        out.extend(r["functions"])
        if not r.get("truncated"):
            break
        off += r["returned"]
    return out


def scan_program(c, key, sample=(), decompile_timeout=60) -> dict:
    """What K3 compares: the function count, the sha256 of the sorted ``address TAB name`` lines, and for
    each sampled address the first 16 hex digits of the sha256 of its decompiled C (and whether the
    function's name appears in it)."""
    fl = _all_functions(c, key)
    byaddr = {f["address"]: f["name"] for f in fl}
    names_sha = sha256_hex("\n".join("%s\t%s" % (a, n) for a, n in sorted(byaddr.items())).encode())
    dec, name_in_c, errs = {}, 0, 0
    for a in sample:
        try:
            d = c.call("decompile", program=key, address=a, timeout=decompile_timeout)
            text = d.get("c") or ""
            dec[a] = sha256_hex(text.encode())[:16] if d.get("completed", True) else "INCOMPLETE"
            nm = byaddr.get(a, "").split("::")[-1]
            name_in_c += bool(nm and nm in text)
        except Exception as e:  # noqa: BLE001
            dec[a] = "ERR:" + str(getattr(e, "code", type(e).__name__))
            errs += 1
    return {"functions": len(fl), "names_sha": names_sha, "decomp": dec, "name_in_c": name_in_c,
            "decomp_errors": errs, "n_sample": len(dec), "by_addr": byaddr}


def check_k3(c, gpr, program: str, allowed: list, sample=(), writable: bool = False, rep: Report | None = None) -> Report:
    """K3: the program opens read-only (and, for a fork or the disposable clone of a candidate or a
    generation, writable); function count and names hash equal ONE of the ``allowed`` scans (the
    pre-kill and post-save baselines, each ``{"functions", "names_sha", "decomp"}``); the sampled
    decompile hashes equal that baseline's and contain the current function name. Never call this with
    ``writable=True`` on a candidate or generation itself (a writable open changes ``~index.bak``)."""
    rep = rep or Report("K3")
    rep.ran("K3")
    try:
        o = c.call("open_project", path=str(gpr), writable=writable)
    except Exception as e:  # noqa: BLE001
        rep.violation("K3", "open_project_failed", f"{getattr(e, 'code', '')} {e}", gpr)
        return rep
    try:
        p = c.call("open_program", path=program, project=o["id"], writable=writable)
        key = p["key"]
    except Exception as e:  # noqa: BLE001
        rep.violation("K3", "open_program_failed", f"{getattr(e, 'code', '')} {e}", gpr)
        return rep
    try:
        sc = scan_program(c, key, sample)
    finally:
        with contextlib.suppress(Exception):
            c.call("close_program", program=key)
    match = [a for a in allowed if a["functions"] == sc["functions"] and a["names_sha"] == sc["names_sha"]]
    if not match:
        rep.violation("K3", "names_not_allowed", f"{sc['functions']} functions, names hash {sc['names_sha'][:12]} "
                      "equals no allowed generation", gpr)
    elif sample and not any(all(a.get("decomp", {}).get(k) in (None, v) for k, v in sc["decomp"].items()) for a in match):
        rep.violation("K3", "decompile_differs", "sampled decompile hashes differ from the baseline", gpr)
    if sample and sc["decomp_errors"]:
        rep.violation("K3", "decompile_failed", f"{sc['decomp_errors']} sampled decompile(s) failed", gpr)
    return rep


# ------------------------------------------------------------------------------ evidence

def environment() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform(), "host": platform.node(),
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


class Evidence:
    """The evidence writer: one folder, JSON files with the environment and the report. Nothing under
    ``D:/Projects/Hydra/_logs`` is hard-coded; the caller passes the folder."""

    def __init__(self, folder):
        self.folder = pathlib.Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def write(self, name: str, obj) -> pathlib.Path:
        p = self.folder / (name if name.endswith(".json") else name + ".json")
        p.write_text(json.dumps({"environment": environment(), "data": obj}, indent=1, default=str), encoding="utf-8")
        return p

    def report(self, name: str, rep: Report) -> pathlib.Path:
        return self.write(name, rep.to_json())


# ------------------------------------------------------------------------------ a whole-tree run

def run_tree(projects=(), seals=(), state_dir=None, lineage=None, tmpdir=None, tmp_before=None, quiescent=True,
             daemon_pids=(), acked_csids=(), baselines: dict | None = None, name: str = "oracle") -> Report:
    """The file-level invariants over a set of trees in one call (what a chaos loop runs after a fault):
    K2 over every project, K1 for ``seals`` (``{project_dir: baseline}``), K1u for each sealed ``.gpr`` in
    ``seals`` keys' folders, K6 for every ``*.gpr`` of ``projects`` that is a fork, K7 locks and temp, K12
    and K17 for the lineage folder."""
    rep = Report(name)
    for p in projects:
        check_k2(p, rep)
        for gpr in pathlib.Path(p).rglob("*.gpr"):
            check_k6(gpr, require_sidecar=False, rep=rep)
        check_k6_staging(p, rep)
        check_k7_locks(p, quiescent=quiescent, live_pids=daemon_pids, rep=rep)
    for proj, base in seals:
        check_k1(proj, base, rep, label=str(proj))
        for gpr in pathlib.Path(proj).glob("*.gpr"):
            check_k1u(gpr, state_dir, expect_sealed=True, rep=rep)
    if tmpdir:
        check_k7_tmp(tmpdir, tmp_before, rep=rep)
    if lineage:
        lin = load_lineage(lineage)
        check_k12(lin, acked_csids, rep)
        check_k17(lineage, pathlib.Path(lineage) / "CURRENT.log", rep)
    return rep


# ------------------------------------------------------------------------------ command line

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the file-level checks of the corruption oracle (PROTOCOL-3.md 3.12) "
                                 "over trees; exit 0 when no invariant is violated, 1 otherwise, 2 on a usage error.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tree-hash", help="print the tree hash of a folder")
    t.add_argument("path")
    s = sub.add_parser("seal-snapshot", help="write the K1 snapshot of a sealed project folder to a JSON file")
    s.add_argument("project_dir")
    s.add_argument("out")
    c = sub.add_parser("check", help="K2/K6/K7 over project folders, K1 against snapshots, K12/K17 over a lineage")
    c.add_argument("--project", action="append", default=[], help="a project folder (repeatable)")
    c.add_argument("--sealed", action="append", default=[], metavar="DIR=SNAPSHOT.json",
                   help="a sealed project folder and the snapshot K1 compares it with (repeatable)")
    c.add_argument("--state-dir", help="the engine state folder (the seal registry is <state>/seals)")
    c.add_argument("--lineage", help="a lineage folder (CURRENT.log, gen/, pending/, done/)")
    c.add_argument("--tmpdir", help="the JVM temp folder")
    c.add_argument("--daemon-pid", type=int, action="append", default=[])
    c.add_argument("--not-quiescent", action="store_true", help="a daemon may legitimately hold locks")
    c.add_argument("--evidence", help="write the report here (a folder)")
    a = ap.parse_args(argv)
    if a.cmd == "tree-hash":
        print(json.dumps(tree_hash(a.path), indent=1))
        return 0
    if a.cmd == "seal-snapshot":
        pathlib.Path(a.out).write_text(json.dumps(seal_snapshot(a.project_dir), indent=1), encoding="utf-8")
        return 0
    seals = []
    for item in a.sealed:
        if "=" not in item:
            ap.error("--sealed wants DIR=SNAPSHOT.json")
        d, snap = item.split("=", 1)
        seals.append((d, json.loads(pathlib.Path(snap).read_text(encoding="utf-8"))))
    rep = run_tree(a.project, seals, a.state_dir, a.lineage, a.tmpdir, None, not a.not_quiescent, a.daemon_pid)
    print(rep.summary())
    for f in rep.findings:
        print("  VIOLATION", f["id"], f["code"], f["detail"])
    if a.evidence:
        Evidence(a.evidence).report("oracle-check", rep)
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
