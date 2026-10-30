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
"""K1-K17 after every kill (gate 9.15): the corruption oracle of X0 (``examples/oracle.py``) run over one
iteration of the crash harness (``run_c.py``, ``run_ef.py``) before its folder is deleted.

``per_kill(run, rec, d)`` returns ``{"K1": result, ..., "K17": result}`` and the anomaly codes of the
violations (``K<n>:<code>``), which the harness adds to the iteration's anomalies, so a finding fails the
batch like any other anomaly. A result is one of

* ``{"ok": true, "how": ...}``: the invariant was checked on this iteration and holds;
* ``{"ok": false, "findings": [...]}``: a violation;
* ``{"na": reason}``: the iteration made no object the invariant is about (named, never silent: K11 and K15
  are about Hydralysis views, K12, K16 and K17 about a lineage's ``CURRENT.log`` and its store; when such an
  object is found in the iteration folder the check runs on it).

What each K runs here, after the kill, the restart of a fresh daemon on the same state directory (the
harness's ``oracle``: the daemon start and its fork sweep, 8.13) and, for ``fork_project``, the retry:

* K1: the canonical (master) project folder, sha256 of every file against the snapshot taken when the
  iteration copied it (``oracle.seal_snapshot``/``check_k1``).
* K2: every ``db.N.gbf`` of the iteration folder (``check_k2``).
* K3: the harness's own read-only and writable open and scan of every program on the fresh daemon
  (function names, decompile sample): its classes ``*CORRUPT_OR_UNOPENABLE``, ``*OPEN_ERROR*``, ``*NO_SCAN``,
  ``RO_W_DIFFER``, ``*NAME_NOT_IN_DECOMPILE*``, ``RO_INSPECT_MUTATED``.
* K4: the generation tags the harness wrote: ``*MIXED*``, ``*GEN_*NOT_IN*``, ``*GEN_OUT_OF_RANGE*``.
* K5: ``*LOSS_OF_ACKED*``, ``ACKED_FORK_MISSING`` (the harness's ledger of acknowledged operations).
* K6: every project folder of the iteration except the canonical (``check_k6``: absent or complete,
  ``.gpr`` never without ``.rep``, sidecar ``complete``, no ``<name>.fork.json.tmp``) and every directory
  that holds one (``check_k6_staging``), after the sweep; plus the harness's ``PARTIAL_*`` and
  ``RETRY_BLOCKED`` classes.
* K7: no ``.lock`` left in the iteration folder (all daemons are stopped: quiescent), the daemon's JVM temp
  folder not growing across restarts, and no process that was below the killed daemon (decompiler,
  script worker) alive after it (``Rig.kill`` records them at the kill).
* K8: the promote harness's classes (``MAIN_*``, ``NEW_*``, ``PARTIAL_FORK_VISIBLE``,
  ``LOSS_OF_ACKED_PROMOTE``): an interrupted ``promote_overlay`` is pre or post, never partial.
* K9: ``CANONICAL_CHANGED``, ``CANON_SCAN_DIFFERS`` and K1's hash of the canonical project.
* K10: the fresh daemon answered ``ping`` and ``status`` shows no client of the killed run; the harness's
  ``DAEMON_DIED``, ``SURVIVOR_PING_ERR``, ``TAKEOVER_FAILED``, ``DRAIN_TIMEOUT``.
* K13: ``health.waits.foreignBlocked`` of the fresh daemon (``check_k13``).
* K14: ``status``/``health`` of the fresh daemon (``check_k14``: no OutOfMemoryError in its log, slots
  drained, no dead thread or leaked worker).
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

_EX = pathlib.Path(__file__).resolve().parent.parent
if str(_EX) not in sys.path:
    sys.path.insert(0, str(_EX))
import oracle as O  # noqa: E402

KS = ["K%d" % i for i in range(1, 18)]

#: harness anomaly classes per invariant (a class may serve two)
CLASS_MAP = {
    "K3": re.compile(r"CORRUPT_OR_UNOPENABLE|OPEN_ERROR|NO_SCAN|RO_W_DIFFER|NAME_NOT_IN_DECOMPILE|RO_INSPECT_MUTATED|B_ERROR"),
    "K4": re.compile(r"MIXED|_GEN_\d+_NOT_IN|GEN_OUT_OF_RANGE"),
    "K5": re.compile(r"LOSS_OF_ACKED|ACKED_FORK_MISSING"),
    "K6": re.compile(r"PARTIAL_|RETRY_BLOCKED|APPLY_LEFT_A_FORK|GPR_WITHOUT_REP|LEFT_AFTER_SWEEP|FORK_TMP_LEFT_AFTER_CLIENT_KILL|COMPLETE_DEST_NOT_EQUAL_CANON"),
    "K8": re.compile(r"^MAIN_|^NEW_|PARTIAL_FORK_VISIBLE|LOSS_OF_ACKED_PROMOTE"),
    "K9": re.compile(r"CANONICAL_CHANGED|CANON_SCAN_DIFFERS"),
    "K10": re.compile(r"DAEMON_DIED|SURVIVOR_PING_ERR|TAKEOVER_FAILED|DRAIN_TIMEOUT"),
}
#: harness classes that are reported and not counted: the state right after the kill, before the sweep (8.13)
PRE_SWEEP = ("ORPHAN_TMP_LEFT", "REP_WITHOUT_GPR_BEFORE_SWEEP", "SIDECAR_TMP_BEFORE_SWEEP")


def snapshot_canon(canon) -> dict:
    """K1's baseline of the canonical project of one iteration (taken when the harness copies it)."""
    return O.seal_snapshot(canon)


def capture_live(c) -> dict:
    """``ping``, ``status`` and ``health`` of the fresh daemon, read by the harness's oracle before it stops
    it (K10, K13, K14)."""
    out = {}
    for cmd in ("ping", "status", "health"):
        try:
            out[cmd] = c.call(cmd)
        except Exception as e:  # noqa: BLE001
            out[cmd + "_error"] = repr(e)[:300]
    return out


def _result(rep: O.Report, kid: str, how: str) -> dict:
    f = [x for x in rep.findings if x["id"] == kid]
    if f:
        return {"ok": False, "findings": [{"code": x["code"], "detail": x["detail"][:200]} for x in f[:5]]}
    notes = [x["code"] for x in rep.notes if x["id"] == kid]
    r = {"ok": True, "how": how}
    if notes:
        r["notes"] = notes
    return r


def _projects(d: pathlib.Path):
    """Every project (``.gpr`` or ``.rep``) below ``d`` except the canonical one: (gpr path, parent dir)."""
    seen = set()
    for p in d.rglob("*"):
        try:
            rel = p.relative_to(d).parts
        except ValueError:
            continue
        if not rel or rel[0] == "canon" or any(x.startswith(".") and ".fork-" in x for x in rel):
            continue
        if p.suffix in (".gpr", ".rep") and not p.name.startswith("."):
            # a project inside another project's .rep is not a project of the iteration
            if any(x.endswith(".rep") for x in rel[:-1]):
                continue
            g = p.with_suffix(".gpr")
            if g not in seen:
                seen.add(g)
                yield g, p.parent


def per_kill(run, rec: dict, d) -> tuple[dict, list]:
    d = pathlib.Path(d)
    rep = O.Report("per-kill")
    res: dict = {}
    anomalies = [a for a in rec.get("anomalies", [])]
    classes = [a.split(":")[0] for a in anomalies if a.split(":")[0] not in PRE_SWEEP]
    kill = rec.get("kill") if isinstance(rec.get("kill"), dict) else {}
    live = getattr(run, "k_live", None) or {}
    # K1 / K9: the canonical project, byte for byte
    snap = getattr(run, "k_canon_snap", None)
    if snap is not None and (d / "canon").is_dir():
        O.check_k1(d / "canon", snap, rep=rep, label="(canonical of this iteration)")
        res["K1"] = _result(rep, "K1", "sha256 of every file of the canonical project against its copy")
    else:
        res["K1"] = {"na": "no canonical project in this iteration"}
    # K2
    O.check_k2(d, rep=rep)
    res["K2"] = _result(rep, "K2", "every db.N.gbf of the iteration folder")
    # K6: projects other than the canonical, after the sweep, and their directories
    n6 = 0
    for gpr, parent in _projects(d):
        n6 += 1
        O.check_k6(gpr, rep=rep)
        O.check_k6_staging(parent, rep=rep)
    # K7: locks (every daemon is stopped), temp growth, processes below the killed daemon
    O.check_k7_locks(d, quiescent=True, rep=rep)
    tmp = getattr(run.rig, "tmp", None)
    if tmp is not None:
        try:
            n = len(os.listdir(tmp))
        except OSError:
            n = None
        if getattr(run, "k_tmp0", None) is None:
            run.k_tmp0 = n
        O.check_k7_tmp(tmp, before=run.k_tmp0, rep=rep)
    below = [p for p in (kill.get("descendants") or []) if p != kill.get("pid")]
    for p in below:
        if O.pid_alive(p) and (O.process_image(p) or "").lower().endswith(
                tuple(n for n in O.DECOMPILER_NAMES) + ("java.exe", "javaw.exe")):
            rep.violation("K7", "orphan_below_killed_daemon",
                          f"pid {p} ({O.process_image(p)}) was below the killed daemon {kill.get('pid')} and is alive")
    res["K7"] = _result(rep, "K7", "locks quiescent, JVM temp not growing, %d process(es) below the killed daemon gone"
                        % len(below))
    # K10, K13, K14: the fresh daemon of the oracle
    if live:
        if "ping_error" in live or "status_error" in live:
            rep.violation("K10", "fresh_daemon_unanswered", str(live.get("ping_error") or live.get("status_error")))
        else:
            mine = {"oracle", "oracle2", "retry"}
            held = [c.get("name") for c in (live.get("status") or {}).get("clients", []) if c.get("name") not in mine]
            if held:
                rep.violation("K10", "dead_client_held", f"clients of the killed run still registered: {held}")
        O.check_k13(live.get("health") or {}, rep=rep)
        log = ""
        try:
            log = run.rig.log.read_text(encoding="utf-8", errors="replace")[-200000:]
        except OSError:
            pass
        O.check_k14(live.get("status") or {}, live.get("health") or {}, rep=rep, log_text=log)
    for kid, rx in CLASS_MAP.items():
        for a in classes:
            if rx.search(a):
                rep.violation(kid, "harness_class", a)
    res["K3"] = _result(rep, "K3", "the harness's RO and writable open and scan of every program on a fresh daemon")
    res["K4"] = _result(rep, "K4", "generation tags against acknowledged and sent")
    res["K5"] = _result(rep, "K5", "acknowledged operations against the harness's ledger")
    res["K6"] = _result(rep, "K6", "%d project folder(s) after the sweep (absent or complete, no staging, no sidecar .tmp)" % n6) \
        if n6 or any(CLASS_MAP["K6"].search(a) for a in classes) else {"ok": True, "how": "no fork path in the iteration (absent)"}
    res["K8"] = _result(rep, "K8", "promote_overlay outcome pre or post") if rec.get("scenario") in ("d1", "d2") or \
        any(CLASS_MAP["K8"].search(a) for a in classes) else {"na": "no overlay or publish record in this scenario"}
    res["K9"] = _result(rep, "K9", "canonical tree hash and scan unchanged")
    if live:
        res["K10"] = _result(rep, "K10", "the fresh daemon answers ping and status, no client of the killed run held")
        res["K13"] = _result(rep, "K13", "health.waits.foreignBlocked of the fresh daemon")
        res["K14"] = _result(rep, "K14", "status and health of the fresh daemon, its log")
    else:
        for k in ("K10", "K13", "K14"):
            res[k] = _result(rep, k, "harness classes only") if any(x["id"] == k for x in rep.findings) else \
                {"na": "this iteration started no fresh daemon"}
    # K12, K16, K17: a lineage, when the iteration made one (the engine scenarios do not)
    logs = [p for p in d.rglob("CURRENT.log")]
    if logs:
        for lg in logs:
            O.check_k17(lg.parent, lg, rep=rep)
            O.check_k12(O.load_lineage(lg.parent), rep=rep)
        res["K12"] = _result(rep, "K12", "CURRENT.log consecutive, manifests")
        res["K17"] = _result(rep, "K17", "sealed records and CURRENT.log")
        res["K16"] = {"na": "the reference model needs the changesets of a Hydralysis publish (run by the publish batch)"}
    else:
        for k in ("K12", "K16", "K17"):
            res[k] = {"na": "no lineage (CURRENT.log) in this scenario"}
    res["K11"] = {"na": "no Hydralysis view in this scenario"}
    res["K15"] = {"na": "no Hydralysis view cache in this scenario"}
    out_anoms = sorted({f"{x['id']}:{x['code']}" for x in rep.findings if x["code"] != "harness_class"})
    return {k: res[k] for k in KS}, out_anoms
