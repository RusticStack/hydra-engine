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
"""The counted kill batches of gate 9.15 (G-CRASH), scheduled on X0's library (PROTOCOL-3.md, package E6).

E6 schedules, X0 injects: the kill scenarios are the crash harness of measurement C (``conc/run_c.py``,
``conc/run_ef.py``, trigger-timed kills: *kill X ms after the version folder listing first changes*, the
method that found the corruption). This file runs them in counted batches, reads their ``results.jsonl``,
judges every iteration (an anomaly is a violation, there is no tolerated class), counts the kills that were
**unanswered** when the process died (an acknowledged operation is not a kill of that operation), reports
the Wilson bound and writes the evidence. It has no kill logic of its own.

    python chaos_tests.py run --ghidra <install> --work <dir> --fixtures <dir with fx-x64-flow> \\
        --fixture-exe <small PE> --profile smoke|gate [--refs-root <folder on a ReFS volume>] [--shards 3]
    python chaos_tests.py plan --profile gate        # the batches and their counts, no run

The program the harness opens in the fixture project is ``X0_FIXTURE_PROGRAM`` (environment, default
``/flow_fixture.exe``; read by ``conc/c_lib.py``). With another ``--fixture-exe`` set it to that program's
path, or ``c_sample`` fails with ``not_found`` (the runner then prints ``c_sample_exit`` and its log).
    python chaos_tests.py selftest                   # offline: verdict logic, Wilson bound, planted violations

Batches of the ``gate`` profile (9.15; counts are unanswered kills): ``save_ntfs`` 200 and ``save_refs`` 200
(at least 400 save kills, 0 unopenable, 0 unrepaired), ``fork`` 300 (0 blocked retries, 0 ``.rep`` without
``.gpr``, 0 leftovers after the sweep), ``promote`` 200 (``promote_overlay``; the **publish** kills are a
Hydralysis process and are run by the VF integration check: listed as a gap here), ``daemon8`` 50 (the daemon
killed with 8 clients). ``control`` runs the harness without a kill and must show 0 anomalies (a harness that
reports a problem on an unkilled run is broken). A ReFS batch needs ``--refs-root`` (a scratch folder on a
ReFS volume): without it the batch is **listed as a gap, not skipped silently**, and the verdict is INCOMPLETE.
The wording "below 0.75% at 95%" is allowed only after 0 failures in at least 200 save kills on NTFS and 200
on ReFS, with no harness error and no unfinished save batch, and not after a count override. A save, fork or
promote kill counts only when its trigger fired (the version folder listing changed) and the operation was
still unanswered when the process died: a kill that fell back to the 120 s timeout or came after the answer is
reported (``unanswered_no_trigger``) but not counted. ``--n BATCH=N`` and ``--only`` change the profile: the
run is then not a gate run, its verdict is capped at ``SMOKE-OK`` and the override is named.

Verdicts: ``PASS`` (gate profile, every minimum reached, 0 anomalies, 0 harness errors, nothing missing),
``SMOKE-OK`` (the same for ``smoke``, whose numbers are never gate numbers), ``FAIL`` (an anomaly, a changed
canonical tree, an oracle finding), ``INCOMPLETE`` (nothing wrong seen, but a minimum was not reached, an
iteration failed in the harness, a batch could not run or belongs to the VF check). Exit 0, 1, 3, 2 (usage).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

import oracle  # noqa: E402

CONC = HERE / "conc"

#: batch id -> how it is run and judged
BATCHES = {
    "save_ntfs": dict(script="run_c.py", argv=["a", "{proj}", "ntfs"], family="save", fs="ntfs",
                      what="save killed (trigger-timed), program reopened read-only and writable"),
    "save_refs": dict(script="run_c.py", argv=["a", "{proj}", "refs"], family="save", fs="refs", needs_refs=True,
                      what="the same on a ReFS volume"),
    "fork": dict(script="run_c.py", argv=["b", "{proj}", "ntfs"], family="fork", fs="ntfs",
                 what="fork_project killed: absent or complete, no .rep without .gpr, no staging left, retry not blocked"),
    "promote": dict(script="run_c.py", argv=["d2", "{proj}", "ntfs"], family="promote", fs="ntfs",
                    what="promote_overlay killed: absent, or a fork without the edits, or with them; never partial"),
    "daemon8": dict(script="run_ef.py", argv=["f", "-", "{proj}", "ntfs"], family="daemon8", fs="ntfs",
                    what="the daemon killed with 8 clients on 8 forks"),
    "control": dict(script="run_c.py", argv=["ctl", "{proj}", "ntfs"], family="control", fs="ntfs",
                    what="no kill: the harness must report 0 anomalies"),
}
#: unanswered kills per batch: the gate (9.15) and the smoke profile. save 200+200, fork 300, daemon8 50 and the 200
#: promote kills are the numbers of 9.15; `control` = 20 is this runner's own choice (the spec sets no number: it only has
#: to be a few unkilled iterations that prove the harness reports 0 anomalies when nothing is killed)
COUNTS = {
    "gate": dict(save_ntfs=200, save_refs=200, fork=300, promote=200, daemon8=50, control=20),
    "smoke": dict(save_ntfs=2, fork=2, promote=1, daemon8=1, control=1),
}
#: how often the daemon8 wrapper retries an open_project answered `busy` (see ef_busy_main)
DAEMON8_OPEN_BUSY_RETRIES = 200
#: the ``details.reason`` of a protocol 3 ``busy`` to open_project that explains it (PROTOCOL-3.md 3.5, 3.13, D39):
#: ``lock_queue_full`` is the waiter cap (at most max(2, slots/4) waiters per project lock or open slot), the
#: designed refusal when eight clients open one project at once; ``lock_wait``/``slot_wait`` a bounded wait that ran
#: out; ``capacity`` the governor. Anything else, or an answer logged without details, is unexplained
OPEN_BUSY_REASONS = ("lock_queue_full", "lock_wait", "slot_wait", "capacity")
#: what the engine-level batches cannot cover and the check that does. A gate profile with any entry here is
#: INCOMPLETE, never PASS: PASS is unreachable until the VF integration check lifts these (it edits these constants
#: when it has run the checks they name; the selftest clears them to prove that a complete clean run would be PASS).
SOFT_GAPS = {
    "publish_kills": "at least 200 publish and promote_overlay kills: the publish half kills a Hydralysis publish leader; "
                     "run by the VF integration check. The 200 promote_overlay kills of the `promote` batch count toward "
                     "that figure but do not satisfy it alone",
    "oracle_per_kill": "gate 9.15 wants K1-K17 after every kill. This runner runs, per batch and not per kill: oracle.check_k2 "
                       "over the iteration directories the harness kept (it keeps only anomalous ones, so for a clean batch "
                       "that check is close to empty) and the K7 orphan-decompiler check (new orphans whose parent is gone). "
                       "Stand-ins are the harness's own per-iteration classes (CORRUPT_OR_UNOPENABLE, LOSS_OF_ACKED_*, "
                       "PARTIAL_DEST_VISIBLE, RETRY_BLOCKED, CANONICAL_CHANGED, staging left) and footer.base_unchanged. "
                       "NOT run after the kills of the save, fork, promote and daemon8 batches: the oracle's K6 and K9 file "
                       "checks, K7 handles/threads/locks/tmp, K3-K5, K8, K10-K17. They need the leftover trees, which the "
                       "harness deletes for clean iterations; run by the VF integration check or by a harness change",
}
#: gate 9.15 wants every kill followed by the oracle; see SOFT_GAPS["oracle_per_kill"] for what runs here
BAD_PREFIX_OK = ()      # no anomaly class is tolerated


def wilson_upper(failures: int, n: int, z: float = 1.6448536) -> float:
    """One-sided upper 95% bound of the Wilson score interval (z = 1.645): 0 of 400 gives 0.67%, the
    "below 0.75% at 95%" of 9.15 (a two-sided z of 1.96 would give 0.95%)."""
    if n <= 0:
        return 1.0
    p = failures / n
    den = 1 + z * z / n
    return min(1.0, (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / den)


# ------------------------------------------------------------------------------ reading results

def read_rows(path) -> list:
    rows = []
    with contextlib.suppress(OSError):
        for line in pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            with contextlib.suppress(ValueError):
                rows.append(json.loads(line))
    return rows


def is_kill(row: dict, family: str) -> bool:
    """An iteration counts as a kill when the process died with the operation unanswered; the daemon
    batch kills the daemon in every iteration; the control kills nothing."""
    if "anomalies" not in row:
        return False
    if family == "control":
        return False
    if family == "daemon8":
        return True       # run_ef.py kills the daemon at a phase of the run, not on a folder trigger
    return not row.get("acked_before_kill") and bool(row.get("trigger_hit"))


def judge_rows(rows: list, family: str) -> dict:
    """Counts and anomaly classes of one batch's rows. Every anomaly is a violation."""
    rec = [r for r in rows if "anomalies" in r]
    errs = [r for r in rows if "harness_error" in r]
    kills = [r for r in rec if is_kill(r, family)]
    classes: dict = {}
    orphans_before_sweep = 0
    for r in rec:
        for a in r.get("anomalies", []):
            k = a.split(":")[0]
            if k in BAD_PREFIX_OK:
                continue
            if k == "ORPHAN_TMP_LEFT":
                # the harness' own class for a staging folder seen right after the kill, before any fork_project ran:
                # the sweeper (E2a) removes it on the first fork_project under the parent. Gate 9.15 counts what is
                # left AFTER that sweep (leftover_fork_tmp_after_retry), so this is reported, not counted.
                orphans_before_sweep += 1
                continue
            classes[k] = classes.get(k, 0) + 1
    answered = len(rec) - len(kills)
    no_trigger = sum(1 for r in rec if family not in ("control", "daemon8") and not r.get("acked_before_kill")
                     and not r.get("trigger_hit"))
    # the failures that gate 9.15 names, read from the same classes
    unopenable = sum(n for k, n in classes.items() if "UNOPENABLE" in k or "OPEN_ERROR" in k)
    rep_no_gpr = sum(1 for r in rec if r.get("dest_state") == "rep_only_NO_GPR")
    blocked = classes.get("RETRY_BLOCKED", 0)
    left_rows = [r for r in rec if r.get("leftover_fork_tmp_after_retry")]
    if left_rows:
        classes["STAGING_LEFT_AFTER_SWEEP"] = len(left_rows)
    leftovers = len(left_rows) + classes.get("FORK_TMP_LEFT_AFTER_CLIENT_KILL", 0)
    loss = sum(n for k, n in classes.items() if k.startswith("LOSS_OF") or k.endswith("LOSS_OF_ACKED") or k == "B_LOSS_OR_MIXED")
    failing_iterations = sum(1 for r in rec if [a for a in r.get("anomalies", []) if a.split(":")[0] not in BAD_PREFIX_OK
                                                 and a.split(":")[0] != "ORPHAN_TMP_LEFT"] or r.get("leftover_fork_tmp_after_retry"))
    return {"iterations": len(rec), "kills": len(kills), "answered_before_kill": answered,
            "unanswered_no_trigger": no_trigger,
            "trigger_hits": sum(1 for r in rec if r.get("trigger_hit")),
            "anomaly_classes": classes, "failing_iterations": failing_iterations,
            "unopenable": unopenable, "rep_without_gpr": rep_no_gpr, "blocked_retries": blocked,
            "leftovers_after_sweep": leftovers, "orphans_before_sweep": orphans_before_sweep, "lost_acknowledged": loss, "harness_errors": len(errs),
            "harness_error_samples": [str(e.get("harness_error"))[-300:] for e in errs[:3]]}


def judge_batch(name: str, spec: dict, want: int, rows: list, footer: dict | None, exit_code, post_rep: oracle.Report,
                gate: bool, busy_answers: int = 0, busy_rows=None) -> dict:
    j = judge_rows(rows, spec["family"])
    if busy_rows is not None:
        # the logged answers (retry_open_busy): an answer is explained when the daemon named a documented reason
        busy_answers = len(busy_rows)
        explained: dict = {}
        for b in busy_rows:
            det = b.get("details")
            reason = det.get("reason") if isinstance(det, dict) else None
            if reason in OPEN_BUSY_REASONS:
                explained[reason] = explained.get(reason, 0) + 1
        unexplained = busy_answers - sum(explained.values())
    else:
        # only a count (no details logged): nothing is explained
        explained, unexplained = {}, int(busy_answers)
    j["open_busy_answers"] = int(busy_answers)
    j["open_busy_explained"] = explained
    j["open_busy_unexplained"] = unexplained
    viol = []
    if j["failing_iterations"]:
        viol.append(f"{j['failing_iterations']} iteration(s) with anomalies: {j['anomaly_classes']}")
    if footer is not None and footer.get("base_unchanged") is False:
        viol.append("the canonical tree changed (K9)")
    for f in post_rep.findings:
        viol.append(f"oracle {f['id']}:{f['code']} {f['detail'][:120]}")
    inc = []
    got = j["iterations"] if spec["family"] == "control" else j["kills"]
    if got < want:
        inc.append(f"{got} of the {want} {'iterations' if spec['family'] == 'control' else 'unanswered kills'}")
    if j["harness_errors"]:
        inc.append(f"{j['harness_errors']} iteration(s) failed in the harness")
    if exit_code not in (0, None):
        inc.append(f"the harness process exited {exit_code}")
    if footer is None:
        inc.append("no footer.json: the batch did not finish")
    verdict = "FAIL" if viol else ("INCOMPLETE" if inc else ("PASS" if gate else "SMOKE-OK"))
    out = {"batch": name, "verdict": verdict, "wanted": want, **j, "violations": viol, "incomplete": inc}
    if unexplained:
        # gate 9.17 wants "no unexplained busy". The retries make the batch run on, they do not explain the answer:
        # an answer without a documented reason keeps a gate profile from PASS (a soft gap). An answer that names the
        # waiter cap (lock_queue_full, 3.5 / D39) or a lock or slot wait is the specified refusal: counted, not a gap
        out["busy_gap"] = (f"{unexplained} unexplained open_project answer(s) `busy` (of {busy_answers}, retried "
                           f"{DAEMON8_OPEN_BUSY_RETRIES} at most per client): 9.17 wants no unexplained busy, so each needs "
                           "an explanation (details.reason: waiter cap or lock wait) before PASS")
    return out


#: the "below 0.75% at 95%" wording needs this many counted save kills on each file system (9.15)
WORDING_MIN_SAVE_KILLS_PER_FS = 200


def attempt_margin(profile: str, family: str, n: int) -> int:
    """Spare attempts handed to a harness process on top of its share of the wanted kills (gate profile; the control
    and the daemon batch have no trigger to miss): 10%, at least 2."""
    return max(2, -(-n // 10)) if profile == "gate" and family not in ("control", "daemon8") else 0


def count_overrides(profile: str, counts: dict, only=()) -> list:
    """What differs from the profile's counts (``--n``) or batches (``--only``)."""
    out = [f"--n {b}={n} (profile {profile}: {COUNTS[profile].get(b, 0)})" for b, n in sorted(counts.items())
           if n != COUNTS[profile].get(b, 0)]
    if only:
        out.append(f"--only {','.join(sorted(only))} (profile {profile}: all batches)")
    return out


def overall(batches: dict, profile: str, missing: dict, overrides=()) -> dict:
    gate = profile == "gate"
    viol = [f"{b}: {x}" for b, r in batches.items() for x in r["violations"]]
    gaps = [f"{b}: {x}" for b, r in batches.items() for x in r["incomplete"]]
    gaps += [f"{b}: {why}" for b, why in missing.items()]
    # a batch of the profile that neither ran nor was named as missing (a harness bug or a bare --only)
    gaps += [f"{b}: not run" for b, n in COUNTS[profile].items() if n > 0 and b not in batches and b not in missing]
    soft = [f"{k}: {v}" for k, v in SOFT_GAPS.items()]
    soft += [f"{b}: {r['busy_gap']}" for b, r in batches.items() if r.get("busy_gap")]
    save_b = {b: r for b, r in batches.items() if BATCHES[b]["family"] == "save"}
    save_kills = sum(r["kills"] for r in save_b.values())
    save_fail = sum(r["failing_iterations"] for r in save_b.values())
    kills_fs = {}
    for b, r in save_b.items():
        kills_fs[BATCHES[b]["fs"]] = kills_fs.get(BATCHES[b]["fs"], 0) + r["kills"]
    save_clean = all(r["harness_errors"] == 0 and not r["incomplete"] for r in save_b.values())
    wording = (not overrides and save_fail == 0 and save_clean
               and kills_fs.get("ntfs", 0) >= WORDING_MIN_SAVE_KILLS_PER_FS
               and kills_fs.get("refs", 0) >= WORDING_MIN_SAVE_KILLS_PER_FS)
    if viol:
        v = "FAIL"
    elif gaps or (gate and soft):
        v = "INCOMPLETE"
    else:
        v = "PASS" if gate else "SMOKE-OK"
    if not gate and v == "INCOMPLETE" and not gaps:
        v = "SMOKE-OK"
    if overrides and v == "PASS":
        v = "SMOKE-OK"        # the ceiling of a run that changed the profile
    if overrides:
        gaps = gaps + [f"profile overridden, not a gate run: {o}" for o in overrides]
    return {"verdict": v, "violations": viol, "gaps": gaps, "soft_gaps": soft, "profile_overrides": list(overrides),
            "save_kills_by_fs": kills_fs,
            "save_kills": save_kills, "save_failures": save_fail,
            "save_wilson_upper_95": round(wilson_upper(save_fail, save_kills), 5) if save_kills else None,
            "wording_below_0_75_percent_allowed": wording}


# ------------------------------------------------------------------------------ running

def daemon_state_roots(work) -> list:
    """The daemon state roots under a run folder, in both harness layouts (see ``Chaos.stop_daemons``)."""
    work = pathlib.Path(work)
    seen, out = set(), []
    cands = []
    st = work / "state"
    if st.is_dir():
        for d in st.iterdir():
            cands += [d, d / "state"]
    run = work / "run"
    if run.is_dir():
        for scen in run.iterdir():
            if scen.is_dir():
                cands += [scen / "state"] + [rig / "state" for rig in scen.iterdir() if rig.is_dir()]
    for c in cands:
        if c.is_dir() and c not in seen:
            seen.add(c)
            out.append(c)
    return out


class Chaos:
    def __init__(self, a):
        self.a = a
        self.work = pathlib.Path(a.work).absolute()
        self.logs = self.work / "logs"
        self.evidence = oracle.Evidence(a.evidence or (self.work / "evidence"))
        self.support = str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support")
        self.procs: list = []
        self.counts = dict(COUNTS[a.profile])
        for kv in a.n or []:
            k, v = kv.split("=")
            self.counts[k] = int(v)
        self.only = set(x for x in (a.only or "").split(",") if x)
        self.overrides = count_overrides(a.profile, self.counts, self.only)
        self.k7_seen: dict = {}

    def common(self) -> list:
        c = ["--ghidra", self.a.ghidra, "--work", str(self.work), "--fixtures", self.a.fixtures,
             "--fixture-exe", self.a.fixture_exe]
        if self.a.project:
            c += ["--project", self.a.project, "--program", self.a.program]
        if self.a.tmpdir:
            c += ["--tmpdir", self.a.tmpdir]
        if self.a.refs_root:
            c += ["--refs-root", self.a.refs_root]
        return c

    def run_proc(self, cmd, log, env, timeout):
        with open(log, "ab") as f:
            f.write(("\n$ " + " ".join(cmd) + "\n").encode())
            f.flush()
            p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, stdin=subprocess.DEVNULL)
            self.procs.append(p)
            try:
                return p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                import chaos_lib as chaos
                chaos.terminate(p.pid, 30)
                return "timeout"

    def stop_daemons(self, make_daemon=None) -> list:
        """Stop every daemon the harness left under ``--work``; returns the state roots where one was alive.

        The harness keeps a daemon's state in two layouts: ``<work>/run/<scenario>/<rig>/state`` (``c_lib.Rig``:
        ``run_c``, ``run_ef``, ``c_sample``) and ``<work>/state/<name>[/state]`` (``xc.fresh``, ``mkbase``). Both
        are scanned. A harness that crashed or ran past ``--batch-timeout-s`` is killed by ``run_proc`` as a
        python process only, so its JVM is found and stopped here, before K7 looks and before the run ends."""
        if make_daemon is None:
            sys.path.insert(0, self.support)
            import ghidra_session as gs  # noqa: PLC0415

            def make_daemon(root, instance):
                return gs.Daemon(None, str(root), instance)
        stopped = []
        for root in daemon_state_roots(self.work):
            for ep in sorted(root.glob("*.json")):
                if ep.name == "config.json":
                    continue
                with contextlib.suppress(Exception):
                    dm = make_daemon(root, ep.stem)
                    if dm.jvm_alive():
                        dm.stop(force=True, timeout=60)
                        stopped.append(str(root))
        return stopped

    def prepare(self):
        self.logs.mkdir(parents=True, exist_ok=True)
        py = [sys.executable, "-I"]
        env = dict(os.environ)
        if self.a.proj == "large":
            base = self.work / "proj" / "base"
            if not base.is_dir():
                self.run_proc(py + [str(CONC / "mkbase.py")] + self.common(), self.logs / "mkbase.log", env, 3600)
                self.stop_daemons()
        rc = self.run_proc(py + [str(CONC / "c_sample.py"), self.a.proj] + self.common(), self.logs / "c_sample.log", env, 1800)
        self.stop_daemons()
        return rc

    def shard_plan(self, name: str, want: int) -> list:
        """(tag, n, seed) per shard; the unanswered kills are split evenly, a shard may need a few more
        attempts than kills (the harness retries up to 3x)."""
        k = max(1, min(self.a.shards, want))
        base, extra = divmod(want, k)
        return [(f"{name}{i}", base + (1 if i < extra else 0), self.a.seed + 1000 * i + sum(map(ord, name)))
                for i in range(k)]

    def k7_orphans(self, name: str, post: oracle.Report, before: set) -> dict:
        """K7 over the batch: no decompiler started during it is left with its parent gone (the daemon was killed
        or stopped). Decompilers that existed before the batch, or whose parent is alive (another run's daemon on
        this machine), are not ours and are not judged. It is vacuous when the batch ran no decompiler. Known limit: the process
        list has no command line, so a decompiler orphaned in the batch window by ANOTHER run's daemon kill on the same
        machine cannot be told apart and would be judged here; the release runs are on a quiet machine, and the evidence
        field `scope` says so."""
        new = [o for o in oracle.find_orphan_decompilers() if o["pid"] not in before]
        mine = {o["pid"] for o in new if not o["parent_alive"]}
        oracle.check_k7_processes([], settle_s=8.0, only_pids=mine, rep=post)
        self.k7_seen[name] = {"new_decompilers_present": len(new), "orphaned": len(mine),
                                "scope": "every new decompiler of the machine whose parent is gone (no command line to narrow it)"}
        return self.k7_seen[name]

    def run_batch(self, name: str) -> dict:
        spec = BATCHES[name]
        want = self.counts.get(name, 0)
        py = [sys.executable, "-I"]
        shards = self.shard_plan(name, want)
        results = []
        outdirs = []

        busy_logs = []

        def one(tag, n, seed):
            argv = [a.replace("{proj}", self.a.proj) for a in spec["argv"]]
            # the harness stops at n unanswered kills, trigger-less ones included, but the runner counts only the
            # trigger-hit ones: on a gate profile a few spare attempts keep one trigger miss (a 120 s fallback) from
            # leaving the batch short of the wanted count. More counted kills than wanted is harmless.
            n_run = n + attempt_margin(self.a.profile, spec["family"], n)
            script = str(CONC / spec["script"])
            lead = [script]
            if spec["family"] == "daemon8":
                # eight clients open one project at once and the daemon may answer `busy` past its waiter cap. The
                # harness (conc/run_ef.py, not E6's file, left untouched) ends a worker on that answer. This runner
                # starts it through ef_busy_main below, which retries an open_project answered `busy` and COUNTS
                # every such answer in a file the runner reads back (open_busy_answers): retried, never hidden.
                blog = self.logs / f"busy-{name}-{tag}.jsonl"
                busy_logs.append(blog)
                lead = [str(pathlib.Path(__file__).resolve()), "_ef-busy", str(DAEMON8_OPEN_BUSY_RETRIES), str(blog), script]
            cmd = py + lead + argv + [str(n_run), str(seed)] + self.common()
            # no ambient value reaches a harness: the retry count is an argument of the wrapper, not an environment variable
            env = dict(os.environ, TRIG="1", RUN_TAG=f"{self.a.tag}{tag}")
            t0 = time.time()
            rc = self.run_proc(cmd, self.logs / f"{name}-{tag}.log", env, self.a.batch_timeout_s)
            results.append((tag, rc, round(time.time() - t0, 1)))
        r_before = {o["pid"] for o in oracle.find_orphan_decompilers()}      # decompilers that exist before the batch
        ths = [threading.Thread(target=one, args=s) for s in shards]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        self.stop_daemons()          # the daemons of the batch are dead before K7 looks for what they left
        rows, footers, codes = [], [], []
        scen = spec["argv"][0]
        for tag, rc, secs in results:
            out = self.work / "run" / (f"{scen}-{self.a.proj}-{spec['fs']}-{self.a.tag}{tag}" if scen != "f"
                                       else f"f-{self.a.proj}-{spec['fs']}-{self.a.tag}{tag}")
            outdirs.append(out)
            rows += read_rows(out / "results.jsonl")
            ft = out / "footer.json"
            footers.append(json.loads(ft.read_text()) if ft.exists() else None)
            codes.append(rc)
        footer = None
        if footers and all(f is not None for f in footers):
            footer = {"base_unchanged": all(f.get("base_unchanged") for f in footers)}
        exit_code = 0 if all(c == 0 for c in codes) else next(c for c in codes if c != 0)
        post = oracle.Report("post:" + name)
        self.k7_orphans(name, post, r_before)
        for out in outdirs:
            if out.is_dir():
                oracle.check_k2(out, post)         # a kept iteration directory must have no bad version file
        if self.a.plant and name == self.a.plant_batch and outdirs:
            plant = outdirs[0] / "planted" / "x.rep" / "idata" / "00" / "~00000000.db"
            plant.mkdir(parents=True, exist_ok=True)
            (plant / "db.1.gbf").write_bytes(oracle.MAGIC + bytes(32))
            (plant / "db.2.gbf").write_bytes(bytes(40))        # X1: the newest version file has a zero header
            oracle.check_k2(outdirs[0] / "planted", post)
        busy_rows = [x for b in busy_logs for x in read_rows(b)]
        r = judge_batch(name, spec, want, rows, footer, exit_code, post, self.a.profile == "gate", busy_rows=busy_rows)
        r["shards"] = [{"tag": t, "exit": rc, "seconds": s} for t, rc, s in results]
        r["what"] = spec["what"]
        r["k7_orphan_check"] = self.k7_seen.get(name)
        r["wilson_upper_95"] = round(wilson_upper(r["failing_iterations"], r["kills"]), 5) if r["kills"] else None
        # keep the evidence of the failing iterations only; the scratch goes (the harness keeps up to 6 anomalous dirs)
        return r

    def run(self) -> dict:
        t0 = time.time()
        batches, missing = {}, {}
        rc = self.prepare()
        order = [b for b in BATCHES if self.counts.get(b, 0) > 0 or (BATCHES[b].get("needs_refs") and self.a.profile == "gate")]
        for b in order:
            if self.only and b not in self.only:
                continue
            spec = BATCHES[b]
            if spec.get("needs_refs") and not self.a.refs_root:
                missing[b] = ("not run: no ReFS volume (--refs-root unset; HYDRA_REFS_SCRATCH is the usual variable). "
                              f"{self.counts.get(b, 0)} kills are missing from the 400 save kills")
                continue
            if self.counts.get(b, 0) <= 0:
                continue
            batches[b] = self.run_batch(b)
            self.stop_daemons()
        for b in order:
            if self.only and b not in self.only:
                missing[b] = f"left out by --only {','.join(sorted(self.only))}"
        res = overall(batches, self.a.profile, missing, self.overrides)
        out = {**res, "profile": self.a.profile, "smoke_numbers_are_not_gate_numbers": self.a.profile != "gate",
               "batches": batches, "counts_requested": self.counts, "proj": self.a.proj, "seed": self.a.seed,
               "c_sample_exit": rc, "elapsed_s": round(time.time() - t0, 1), "engine": {"install": self.a.ghidra},
               "plants": {"requested": self.a.plant, "batch": self.a.plant_batch if self.a.plant else None},
               "runner": {"file": str(pathlib.Path(__file__).resolve())}}
        self.evidence.write("chaos-verdict", out)
        return out


# ------------------------------------------------------------------------------ self-test

def selftest(verbose: bool = True) -> int:
    bad = []

    def check(name, cond, detail=""):
        if verbose:
            print(("ok   " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
        if not cond:
            bad.append(name)

    def rows(n, kills=True, anomalies=None, extra=None):
        out = []
        for i in range(n):
            r = {"i": i, "acked_before_kill": not kills, "anomalies": list(anomalies or []), "trigger_hit": True}
            r.update(extra or {})
            out.append(r)
        return out
    clean = oracle.Report()
    save = BATCHES["save_ntfs"]
    r = judge_batch("save_ntfs", save, 200, rows(200), {"base_unchanged": True}, 0, clean, True)
    check("200 clean unanswered save kills: PASS", r["verdict"] == "PASS" and r["kills"] == 200, r)
    r = judge_batch("save_ntfs", save, 200, rows(150), {"base_unchanged": True}, 0, clean, True)
    check("150 of 200 kills: INCOMPLETE, named", r["verdict"] == "INCOMPLETE" and "150 of the 200" in r["incomplete"][0], r)
    r = judge_batch("save_ntfs", save, 200, rows(199) + rows(1, anomalies=["CORRUPT_OR_UNOPENABLE"]), {"base_unchanged": True},
                    0, clean, True)
    check("planted: one unopenable program after a kill: FAIL", r["verdict"] == "FAIL" and r["unopenable"] == 1, r)
    r = judge_batch("save_ntfs", save, 10, rows(10, anomalies=["LOSS_OF_ACKED_SAVE"]), {"base_unchanged": True}, 0, clean, True)
    check("planted: a lost acknowledged save: FAIL", r["verdict"] == "FAIL" and r["lost_acknowledged"] == 10, r)
    r = judge_batch("save_ntfs", save, 10, rows(10), {"base_unchanged": False}, 0, clean, True)
    check("planted: the canonical tree changed: FAIL", r["verdict"] == "FAIL", r)
    r = judge_batch("save_ntfs", save, 10, rows(10, kills=False), {"base_unchanged": True}, 0, clean, True)
    check("an acknowledged operation is not a kill: 0 kills counted", r["kills"] == 0 and r["verdict"] == "INCOMPLETE", r)
    r = judge_batch("fork", BATCHES["fork"], 5, rows(5, extra={"dest_state": "rep_only_NO_GPR"}, anomalies=["PARTIAL_DEST_VISIBLE:rep_only_NO_GPR"]),
                    {"base_unchanged": True}, 0, clean, True)
    check("planted: a .rep without .gpr after a fork kill is counted", r["rep_without_gpr"] == 5 and r["verdict"] == "FAIL", r)
    r = judge_batch("fork", BATCHES["fork"], 5, rows(5, anomalies=["ORPHAN_TMP_LEFT"], extra={"leftover_fork_tmp_after_retry": []}),
                    {"base_unchanged": True}, 0, clean, True)
    check("a staging folder seen before the sweep and gone after it is reported, not counted",
          r["leftovers_after_sweep"] == 0 and r["orphans_before_sweep"] == 5 and r["verdict"] == "PASS", r)
    r = judge_batch("fork", BATCHES["fork"], 5, rows(5, anomalies=["ORPHAN_TMP_LEFT"],
                                                    extra={"leftover_fork_tmp_after_retry": [".x.fork-1.tmp"]}),
                    {"base_unchanged": True}, 0, clean, True)
    check("planted: a staging folder left after the sweep is a violation (gate 9.15)", r["leftovers_after_sweep"] == 5 and r["verdict"] == "FAIL", r)
    r = judge_batch("fork", BATCHES["fork"], 5, rows(5, anomalies=["RETRY_BLOCKED"]), {"base_unchanged": True}, 0, clean, True)
    check("planted: a blocked retry is counted", r["blocked_retries"] == 5, r)
    r = judge_batch("control", BATCHES["control"], 5, rows(5, kills=False), {"base_unchanged": True}, 0, clean, True)
    check("control with 0 anomalies counts iterations, not kills: PASS", r["verdict"] == "PASS", r)
    r = judge_batch("control", BATCHES["control"], 5, rows(5, kills=False, anomalies=["A_MIXED"]), {"base_unchanged": True}, 0, clean, True)
    check("planted: anomalies on an unkilled control: FAIL (the harness is broken)", r["verdict"] == "FAIL", r)
    r = judge_batch("save_ntfs", save, 5, rows(5) + [{"harness_error": "boom"}], {"base_unchanged": True}, 0, clean, True)
    check("a harness error: INCOMPLETE", r["verdict"] == "INCOMPLETE" and r["harness_errors"] == 1, r)
    r = judge_batch("save_ntfs", save, 5, rows(5), None, 1, clean, True)
    check("a batch that did not finish: INCOMPLETE", r["verdict"] == "INCOMPLETE", r)
    r = judge_batch("save_ntfs", save, 5, rows(5), {"base_unchanged": True}, 1, clean, True)
    check("a non-zero harness exit alone (footer present) is INCOMPLETE and named",
          r["verdict"] == "INCOMPLETE" and any("exited 1" in x for x in r["incomplete"]), r)
    r = judge_batch("save_ntfs", save, 5, rows(5), None, 0, clean, True)
    check("a missing footer alone (exit 0) is INCOMPLETE and named",
          r["verdict"] == "INCOMPLETE" and any("no footer" in x for x in r["incomplete"]), r)
    r = judge_batch("save_ntfs", save, 5, rows(5), None, None, clean, True)
    check("a missing footer with no exit code is INCOMPLETE too", r["verdict"] == "INCOMPLETE", r)
    bad_post = oracle.Report()
    bad_post.violation("K2", "newest_header_invalid", "planted")
    r = judge_batch("save_ntfs", save, 5, rows(5), {"base_unchanged": True}, 0, bad_post, True)
    check("planted: an oracle finding over what the batch left: FAIL", r["verdict"] == "FAIL", r)
    # the oracle on a planted zero-header version file
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="chaos-selftest-"))
    try:
        db = tmp / "x.rep" / "idata" / "00" / "~00000000.db"
        db.mkdir(parents=True)
        (db / "db.1.gbf").write_bytes(oracle.MAGIC + bytes(32))
        (db / "db.2.gbf").write_bytes(bytes(40))
        p = oracle.Report()
        oracle.check_k2(tmp, p)
        check("planted X1 (zero-header newest version file) is flagged by the post-batch check", "K2:newest_header_invalid" in p.codes(), p.codes())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # the K7 orphan check over a batch (the process list is replaced by a stub)
    saved_find, saved_k7 = oracle.find_orphan_decompilers, oracle.check_k7_processes
    ch = Chaos.__new__(Chaos)
    ch.k7_seen = {}
    try:
        def fake(lst):
            return lambda daemon_pids=(), names=None: lst
        seen_args = {}

        def fake_k7(daemon_pids=(), settle_s=5.0, only_pids=None, names=None, rep=None):
            seen_args["only"] = set(only_pids)
            rep = rep or oracle.Report("K7")
            rep.ran("K7")
            for p_ in only_pids:
                rep.violation("K7", "orphan_decompiler", f"pid {p_}", None)
            return rep
        oracle.check_k7_processes = fake_k7
        oracle.find_orphan_decompilers = fake([{"pid": 1, "parent_alive": False}, {"pid": 2, "parent_alive": False},
                                               {"pid": 3, "parent_alive": True}])
        rp = oracle.Report()
        res = ch.k7_orphans("save_ntfs", rp, {1})
        check("K7 per batch: a new decompiler whose parent is gone is an orphan; an older one and one with a live parent are not ours",
              seen_args["only"] == {2} and "K7:orphan_decompiler" in rp.codes() and res["orphaned"] == 1
              and res["new_decompilers_present"] == 2, (seen_args, rp.codes(), res))
        rp = oracle.Report()
        ch.k7_orphans("save_ntfs", rp, {1, 2, 3})
        check("K7 per batch: nothing new, nothing judged", seen_args["only"] == set() and rp.ok, rp.codes())
    finally:
        oracle.find_orphan_decompilers, oracle.check_k7_processes = saved_find, saved_k7
    # the daemons a harness leaves are found where the harness really keeps them (c_lib.Rig and xc.fresh layouts)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="chaos-stop-"))
    try:
        layout = {"run/sample-fixture/rig/state": "sample", "run/d-fixture-ntfs-s1/rig/state": "c",
                  "state/mk/state": "mk", "state/raw": "raw"}
        for rel, inst in layout.items():
            (tmp / rel).mkdir(parents=True)
            (tmp / rel / "config.json").write_text("{}")
            (tmp / rel / (inst + ".json")).write_text('{"pid": 1}')
        (tmp / "run" / "d-fixture-ntfs-s1" / "it-0000" / "x.rep").mkdir(parents=True)   # not a state root
        calls = []

        class _FakeDaemon:
            def __init__(self, root, inst):
                self.root, self.inst = pathlib.Path(root), inst

            def jvm_alive(self):
                return True

            def stop(self, force=False, timeout=None):
                calls.append((self.root.relative_to(tmp).as_posix(), self.inst, force))
        ch = Chaos.__new__(Chaos)
        ch.work = tmp
        ch.stop_daemons(make_daemon=_FakeDaemon)
        got = {(r, i) for r, i, f in calls if f}
        check("stop_daemons finds and force-stops a daemon under <work>/run/<scenario>/rig/state (the harness layout)",
              ("run/sample-fixture/rig/state", "sample") in got and ("run/d-fixture-ntfs-s1/rig/state", "c") in got, calls)
        check("stop_daemons still stops the xc.fresh layouts and never a config.json or a non-state folder",
              ("state/mk/state", "mk") in got and ("state/raw", "raw") in got and len(calls) == 4
              and not any(i == "config" for _r, i, _f in calls), calls)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # the totals
    full = {b: judge_batch(b, BATCHES[b], COUNTS["gate"][b], rows(COUNTS["gate"][b], kills=BATCHES[b]["family"] != "control"),
                           {"base_unchanged": True}, 0, clean, True) for b in COUNTS["gate"]}
    o = overall(full, "gate", {})
    check("every gate batch complete and clean: still INCOMPLETE, the publish kills belong to the VF check",
          o["verdict"] == "INCOMPLETE" and o["wording_below_0_75_percent_allowed"] and any("publish" in s for s in o["soft_gaps"]), o)
    check("0 of 400 save kills: Wilson upper bound 0.67%, below 0.75%", o["save_wilson_upper_95"] is not None and o["save_wilson_upper_95"] < 0.0075, o["save_wilson_upper_95"])
    part = {b: r for b, r in full.items() if b != "save_refs"}
    o = overall(part, "gate", {"save_refs": "not run: no ReFS volume"})
    check("no ReFS volume: the batch is named as missing and the wording is not allowed",
          o["verdict"] == "INCOMPLETE" and not o["wording_below_0_75_percent_allowed"] and any("save_refs" in g for g in o["gaps"]), o)
    bad_full = dict(full)
    bad_full["fork"] = judge_batch("fork", BATCHES["fork"], 300, rows(300, anomalies=["RETRY_BLOCKED"]), {"base_unchanged": True}, 0, clean, True)
    o = overall(bad_full, "gate", {})
    check("a failing batch fails the whole", o["verdict"] == "FAIL", o)
    sm = {b: judge_batch(b, BATCHES[b], COUNTS["smoke"][b], rows(COUNTS["smoke"][b], kills=BATCHES[b]["family"] != "control"),
                         {"base_unchanged": True}, 0, clean, False) for b in COUNTS["smoke"]}
    o = overall(sm, "smoke", {})
    check("smoke with everything clean: SMOKE-OK, never PASS", o["verdict"] == "SMOKE-OK" and not o["wording_below_0_75_percent_allowed"], o)
    check("Wilson: 0 of 3 is wide, 1 of 100 is above 0 of 100", wilson_upper(0, 3) > 0.4 and wilson_upper(1, 100) > wilson_upper(0, 100))
    check("every batch script exists", all((CONC / s["script"]).is_file() for s in BATCHES.values()))
    # a kill whose trigger never fired is not counted
    nt = rows(10) + [dict(r, trigger_hit=False) for r in rows(7)]
    j = judge_rows(nt, "save")
    check("only trigger-timed unanswered kills are counted (7 fallback kills reported, not counted)",
          j["kills"] == 10 and j["unanswered_no_trigger"] == 7, j)
    check("the daemon8 family counts every iteration (no folder trigger there)",
          judge_rows([dict(r, trigger_hit=False) for r in rows(4)], "daemon8")["kills"] == 4)
    # the wording
    def save_pair(n_ntfs, n_refs, harness_errors=0, refs_fail=False):
        a_ = judge_batch("save_ntfs", BATCHES["save_ntfs"], n_ntfs, rows(n_ntfs) + [{"harness_error": "x"}] * harness_errors,
                         {"base_unchanged": True}, 0, clean, True)
        b_ = judge_batch("save_refs", BATCHES["save_refs"], n_refs,
                         rows(n_refs, anomalies=["CORRUPT_OR_UNOPENABLE"] if refs_fail else None),
                         {"base_unchanged": True}, 0, clean, True)
        return {"save_ntfs": a_, "save_refs": b_}
    check("wording allowed: 200 counted kills on each file system, nothing failed",
          overall(save_pair(200, 200), "gate", {})["wording_below_0_75_percent_allowed"])
    check("wording refused: 399 save kills (199 on NTFS)",
          not overall(save_pair(199, 200), "gate", {})["wording_below_0_75_percent_allowed"])
    check("wording refused: 400 kills but 300 on NTFS and 100 on ReFS",
          not overall(save_pair(300, 100), "gate", {})["wording_below_0_75_percent_allowed"])
    check("wording refused: a save batch with a harness error",
          not overall(save_pair(200, 200, harness_errors=1), "gate", {})["wording_below_0_75_percent_allowed"])
    check("wording refused: a failure in a save batch",
          not overall(save_pair(200, 200, refs_fail=True), "gate", {})["wording_below_0_75_percent_allowed"])
    check("wording refused after a count override",
          not overall(save_pair(200, 200), "gate", {}, ["--n control=2"])["wording_below_0_75_percent_allowed"])
    # a count override is not a gate run
    ov = count_overrides("gate", {**COUNTS["gate"], "save_ntfs": 2})
    check("an override of a count is named", len(ov) == 1 and "save_ntfs=2" in ov[0], ov)
    check("no override for the profile's own counts", count_overrides("gate", dict(COUNTS["gate"])) == [])
    sm_ov = overall(sm, "smoke", {}, ["--n control=3"])
    check("smoke with a count override: capped at SMOKE-OK and the override is a gap",
          sm_ov["verdict"] == "SMOKE-OK" and any("overridden" in g for g in sm_ov["gaps"]) , sm_ov)
    saved_soft = dict(SOFT_GAPS)
    SOFT_GAPS.clear()
    try:
        full2 = {b: r for b, r in full.items()}
        check("with the VF gap lifted a complete clean gate run is PASS (so the cap below is meaningful)",
              overall(full2, "gate", {})["verdict"] == "PASS", overall(full2, "gate", {}))
        o = overall(full2, "gate", {}, ["--n save_ntfs=2"])
        check("planted: a gate run with an overridden count is capped at SMOKE-OK, never PASS", o["verdict"] == "SMOKE-OK", o)
        d8 = judge_batch("daemon8", BATCHES["daemon8"], 50, rows(50, extra={"anomalies": []}), {"base_unchanged": True}, 0, clean,
                         True, busy_answers=3)
        o = overall({**full2, "daemon8": d8}, "gate", {})
        check("busy answers of daemon8 are counted, named in the batch and keep a gate run from PASS",
              d8["open_busy_answers"] == 3 and "busy_gap" in d8 and o["verdict"] == "INCOMPLETE"
              and any("daemon8" in g and "busy" in g for g in o["soft_gaps"]), (d8, o))
        d8_0 = judge_batch("daemon8", BATCHES["daemon8"], 50, rows(50), {"base_unchanged": True}, 0, clean, True)
        check("no busy answer: no busy gap", "busy_gap" not in d8_0 and d8_0["open_busy_answers"] == 0, d8_0)
        # the waiter cap of 3.5 / D39: eight v3 clients opening one project at once get busy{reason:lock_queue_full,
        # waiters, waitersMax} beyond max(2, slots/4) waiters. A logged answer with that explanation is an explained busy
        # (counted, not a gap); an answer without a documented reason stays a gap
        qf = {"t": 1.0, "attempt": 1, "message": "too many requests already wait to open project analysis; retry",
              "details": {"reason": "lock_queue_full", "waiters": 2, "waitersMax": 2, "gpr": "x.gpr", "name": "analysis"}}
        d8_x = judge_batch("daemon8", BATCHES["daemon8"], 50, rows(50), {"base_unchanged": True}, 0, clean, True,
                           busy_rows=[qf, dict(qf, details=dict(qf["details"], reason="lock_wait"))])
        o = overall({**full2, "daemon8": d8_x}, "gate", {})
        check("busy answers that carry the waiter-cap explanation are counted as explained and do not keep PASS away",
              d8_x["open_busy_answers"] == 2 and d8_x["open_busy_explained"] == {"lock_queue_full": 1, "lock_wait": 1}
              and "busy_gap" not in d8_x and o["verdict"] == "PASS", (d8_x, o))
        d8_u = judge_batch("daemon8", BATCHES["daemon8"], 50, rows(50), {"base_unchanged": True}, 0, clean, True,
                           busy_rows=[qf, {"t": 2.0, "attempt": 1, "message": "busy", "details": {}},
                                      {"t": 3.0, "attempt": 2}])
        o = overall({**full2, "daemon8": d8_u}, "gate", {})
        check("a busy answer without a documented reason (or logged without details) stays an unexplained gap",
              d8_u["open_busy_unexplained"] == 2 and "busy_gap" in d8_u and o["verdict"] == "INCOMPLETE"
              and any("daemon8" in g and "unexplained" in g for g in o["soft_gaps"]), (d8_u, o))
        o = overall({b: r for b, r in full2.items() if b != "daemon8"}, "gate", {})
        check("a gate batch that neither ran nor was named as missing is a gap", o["verdict"] == "INCOMPLETE"
              and any("daemon8: not run" in g for g in o["gaps"]), o)
    finally:
        SOFT_GAPS.update(saved_soft)
    # the daemon8 busy retry (the wrapper around conc/run_ef.py, which is not E6's file)
    class _Err(Exception):
        def __init__(self, code):
            super().__init__(code)
            self.code = code
            self.message = "queue full" if code == "busy" else code
            self.details = {"reason": "lock_queue_full", "waiters": 2, "waitersMax": 2} if code == "busy" else {}

    import tempfile as _tf  # noqa: PLC0415
    blog = pathlib.Path(_tf.mkdtemp(prefix="chaos-busy-")) / "busy.jsonl"

    def make_orig(script):
        seq = list(script)

        def orig(self, cmd, deadline=None, **f):
            x = seq.pop(0) if seq else "ok"
            if x != "ok":
                raise _Err(x)
            return {"cmd": cmd}
        return orig
    w = retry_open_busy(make_orig(["busy", "busy", "ok"]), _Err, 5, blog, sleep=lambda _s: None)
    check("open_project answered busy twice is retried and counted", w(None, "open_project", path="x") == {"cmd": "open_project"}
          and len(read_rows(blog)) == 2, read_rows(blog))
    check("the busy log keeps the answer's message and details (what classifies it)",
          all(r.get("details") == {"reason": "lock_queue_full", "waiters": 2, "waitersMax": 2}
              and r.get("message") == "queue full" for r in read_rows(blog)), read_rows(blog))
    w = retry_open_busy(make_orig(["busy"] * 9), _Err, 3, blog, sleep=lambda _s: None)
    try:
        w(None, "open_project")
        raised = None
    except _Err as e:
        raised = e.code
    check("busy after the last retry is raised as busy (not hidden)", raised == "busy" and len(read_rows(blog)) == 5, read_rows(blog))
    w = retry_open_busy(make_orig(["busy"]), _Err, 3, blog, sleep=lambda _s: None)
    try:
        w(None, "fork_project")
        raised = None
    except _Err as e:
        raised = e.code
    check("busy on any other command is raised at once", raised == "busy" and len(read_rows(blog)) == 5)
    w = retry_open_busy(make_orig(["failed"]), _Err, 3, blog, sleep=lambda _s: None)
    try:
        w(None, "open_project")
        raised = None
    except _Err as e:
        raised = e.code
    check("another error of open_project is raised at once", raised == "failed" and len(read_rows(blog)) == 5)
    check("spare attempts: gate save/fork/promote get 10% (at least 2), smoke, control and daemon8 get none",
          attempt_margin("gate", "save", 200) == 20 and attempt_margin("gate", "fork", 3) == 2
          and attempt_margin("smoke", "save", 2) == 0 and attempt_margin("gate", "control", 20) == 0
          and attempt_margin("gate", "daemon8", 50) == 0)
    check("gate counts: 400 save kills, 300 fork, 200 promote, 50 daemon",
          COUNTS["gate"]["save_ntfs"] + COUNTS["gate"]["save_refs"] == 400 and COUNTS["gate"]["fork"] == 300
          and COUNTS["gate"]["promote"] == 200 and COUNTS["gate"]["daemon8"] == 50)
    print(f"chaos selftest: {'FAILED: ' + str(bad) if bad else 'all checks ok'}")
    return 1 if bad else 0


# ------------------------------------------------------------------------------ command line

def retry_open_busy(orig, error_cls, retries: int, logp, sleep=time.sleep):
    """Wraps a client ``call(self, cmd, deadline=None, **fields)``: an ``open_project`` answered ``busy`` is retried up to
    ``retries`` times, each such answer appended to ``logp``; any other error, and the answer after the last retry, is
    raised as it was."""
    lock = threading.Lock()

    def call(self, cmd, deadline=None, **fields):
        for attempt in range(1 + retries):
            try:
                return orig(self, cmd, deadline, **fields)
            except error_cls as e:
                if cmd != "open_project" or getattr(e, "code", None) != "busy" or attempt >= retries:
                    raise
                det = getattr(e, "details", None)
                with lock, open(logp, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"t": round(time.time(), 3), "attempt": attempt + 1,
                                        "message": str(getattr(e, "message", "") or "")[:300],
                                        "details": det if isinstance(det, dict) else None}, default=str) + "\n")
                sleep(0.1)
    return call


def ef_busy_main(argv) -> int:
    """``chaos_tests.py _ef-busy RETRIES BUSYLOG RUN_EF.PY <run_ef arguments>``: runs the daemon8 harness (conc/run_ef.py,
    which this package does not own and does not edit) with one change made from outside: an ``open_project`` the daemon
    answers ``busy`` is retried up to RETRIES times and every such answer is appended to BUSYLOG. Nothing else in the
    client changes. It applies to every open_project the harness process makes, not only the eight workers'; the
    other opens run one at a time, so a busy answer there is as unexpected as before and is counted the same way."""
    import runpy  # noqa: PLC0415
    retries, logp, script, rest = int(argv[0]), pathlib.Path(argv[1]), argv[2], argv[3:]
    sys.argv = [script] + rest
    sys.path.insert(0, str(CONC))
    import c_lib  # noqa: PLC0415,F401  (parses and strips --ghidra --work ... from sys.argv, loads ghidra_session)
    gs = c_lib.gs
    gs._Base.call = retry_open_busy(gs._Base.call, gs.SessionError, retries, logp)
    runpy.run_path(script, run_name="__main__")
    return 0


def main(argv=None) -> int:
    if (sys.argv[1:] if argv is None else argv)[:1] == ["_ef-busy"]:
        return ef_busy_main((sys.argv[1:] if argv is None else argv)[1:])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    pl = sub.add_parser("plan")
    pl.add_argument("--profile", choices=sorted(COUNTS), default="gate")
    r = sub.add_parser("run")
    r.add_argument("--ghidra", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--fixtures", required=True, help="folder with fx-x64-flow (public fixture projects)")
    r.add_argument("--fixture-exe", required=True, help="a small public PE the import scenarios use")
    r.add_argument("--profile", choices=sorted(COUNTS), default="smoke")
    r.add_argument("--proj", choices=("fixture", "large"), default="fixture")
    r.add_argument("--project", help="for --proj large: the project to copy (a game copy; never committed)")
    r.add_argument("--program", help="for --proj large: its program")
    r.add_argument("--refs-root", default=os.environ.get("HYDRA_REFS_SCRATCH"))
    r.add_argument("--tmpdir")
    r.add_argument("--tag", default="")
    r.add_argument("--seed", type=int, default=20261101)
    r.add_argument("--shards", type=int, default=1, help="processes per batch (each has its own state root)")
    r.add_argument("--n", action="append", metavar="BATCH=N",
                   help="override a batch's unanswered-kill count (not a gate run: the verdict is capped at SMOKE-OK)")
    r.add_argument("--only", help="comma list of batch ids (not a gate run: the verdict is capped at SMOKE-OK)")
    r.add_argument("--evidence")
    r.add_argument("--batch-timeout-s", type=int, default=6 * 3600)
    r.add_argument("--plant", action="store_true", help="plant a zero-header version file under a batch's output; the verdict must be FAIL")
    r.add_argument("--plant-batch", default="control")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "plan":
        print(json.dumps({"profile": a.profile, "unanswered_kills": COUNTS[a.profile],
                          "batches": {b: {"script": s["script"], "argv": s["argv"], "what": s["what"]} for b, s in BATCHES.items()},
                          "not_here": SOFT_GAPS}, indent=1))
        return 0
    if a.proj == "large" and not (a.project and a.program):
        print("--proj large needs --project and --program", file=sys.stderr)
        return 2
    if sys.platform != "win32":
        print("the crash harness is Windows-only (TerminateProcess)", file=sys.stderr)
        return 2
    if a.plant and a.only and a.plant_batch not in a.only.split(","):
        print(f"--plant plants into the batch {a.plant_batch!r}, which --only leaves out; name it with --plant-batch",
              file=sys.stderr)
        return 2
    ch = Chaos(a)
    try:
        out = ch.run()
    finally:
        with contextlib.suppress(Exception):
            ch.stop_daemons()
    print(json.dumps({k: out[k] for k in ("verdict", "profile", "violations", "gaps", "soft_gaps", "save_kills",
                                          "wording_below_0_75_percent_allowed", "elapsed_s")}, indent=1))
    for b, r_ in out["batches"].items():
        print(f"  {b}: {r_['verdict']} kills={r_['kills']}/{r_['wanted']} iterations={r_['iterations']} "
              f"failing={r_['failing_iterations']} harness_errors={r_['harness_errors']}")
    if out.get("c_sample_exit") not in (0, None):
        print(f"c_sample exited {out['c_sample_exit']}: see {ch.logs / 'c_sample.log'} "
              f"(is X0_FIXTURE_PROGRAM={os.environ.get('X0_FIXTURE_PROGRAM', '/flow_fixture.exe')} in the fixture?)")
    print("evidence:", ch.evidence.folder)
    if a.plant:
        return 0 if out["verdict"] == "FAIL" and any("oracle K2" in v for v in out["violations"]) else 1
    return {"PASS": 0, "SMOKE-OK": 0, "FAIL": 1, "INCOMPLETE": 3}[out["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
