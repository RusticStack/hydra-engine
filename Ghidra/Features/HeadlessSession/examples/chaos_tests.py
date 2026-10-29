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
    python chaos_tests.py selftest                   # offline: verdict logic, Wilson bound, planted violations

Batches of the ``gate`` profile (9.15; counts are unanswered kills): ``save_ntfs`` 200 and ``save_refs`` 200
(at least 400 save kills, 0 unopenable, 0 unrepaired), ``fork`` 300 (0 blocked retries, 0 ``.rep`` without
``.gpr``, 0 leftovers after the sweep), ``promote`` 200 (``promote_overlay``; the **publish** kills are a
Hydralysis process and are run by the VF integration check: listed as a gap here), ``daemon8`` 50 (the daemon
killed with 8 clients). ``control`` runs the harness without a kill and must show 0 anomalies (a harness that
reports a problem on an unkilled run is broken). A ReFS batch needs ``--refs-root`` (a scratch folder on a
ReFS volume): without it the batch is **listed as a gap, not skipped silently**, and the verdict is INCOMPLETE.
The wording "below 0.75% at 95%" is allowed only after 0 failures in at least 400 save kills.

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
#: unanswered kills per batch: the gate (9.15) and the smoke profile
COUNTS = {
    "gate": dict(save_ntfs=200, save_refs=200, fork=300, promote=200, daemon8=50, control=20),
    "smoke": dict(save_ntfs=2, fork=2, promote=1, daemon8=1, control=1),
}
#: what the engine-level batches cannot cover and the check that does
SOFT_GAPS = {
    "publish_kills": "at least 200 publish and promote_overlay kills: the publish half kills a Hydralysis publish leader; "
                     "run by the VF integration check",
}
#: every kill is followed by the oracle; the file-level part (K2, K6, K7, K9) runs here over what is left
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
        return True
    return not row.get("acked_before_kill")


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
            "trigger_hits": sum(1 for r in rec if r.get("trigger_hit")),
            "anomaly_classes": classes, "failing_iterations": failing_iterations,
            "unopenable": unopenable, "rep_without_gpr": rep_no_gpr, "blocked_retries": blocked,
            "leftovers_after_sweep": leftovers, "orphans_before_sweep": orphans_before_sweep, "lost_acknowledged": loss, "harness_errors": len(errs),
            "harness_error_samples": [str(e.get("harness_error"))[-300:] for e in errs[:3]]}


def judge_batch(name: str, spec: dict, want: int, rows: list, footer: dict | None, exit_code, post_rep: oracle.Report,
                gate: bool) -> dict:
    j = judge_rows(rows, spec["family"])
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
    return {"batch": name, "verdict": verdict, "wanted": want, **j, "violations": viol, "incomplete": inc}


def overall(batches: dict, profile: str, missing: dict) -> dict:
    gate = profile == "gate"
    viol = [f"{b}: {x}" for b, r in batches.items() for x in r["violations"]]
    gaps = [f"{b}: {x}" for b, r in batches.items() for x in r["incomplete"]]
    gaps += [f"{b}: {why}" for b, why in missing.items()]
    soft = [f"{k}: {v}" for k, v in SOFT_GAPS.items()]
    save_kills = sum(r["kills"] for b, r in batches.items() if BATCHES[b]["family"] == "save")
    save_fail = sum(r["failing_iterations"] for b, r in batches.items() if BATCHES[b]["family"] == "save")
    save_fs = {BATCHES[b]["fs"] for b, r in batches.items() if BATCHES[b]["family"] == "save"}
    wording = save_fail == 0 and save_kills >= 400 and {"ntfs", "refs"} <= save_fs
    if viol:
        v = "FAIL"
    elif gaps or (gate and soft):
        v = "INCOMPLETE"
    else:
        v = "PASS" if gate else "SMOKE-OK"
    if not gate and v == "INCOMPLETE" and not gaps:
        v = "SMOKE-OK"
    return {"verdict": v, "violations": viol, "gaps": gaps, "soft_gaps": soft,
            "save_kills": save_kills, "save_failures": save_fail,
            "save_wilson_upper_95": round(wilson_upper(save_fail, save_kills), 5) if save_kills else None,
            "wording_below_0_75_percent_allowed": wording}


# ------------------------------------------------------------------------------ running

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

    def stop_daemons(self):
        sys.path.insert(0, self.support)
        import ghidra_session as gs  # noqa: PLC0415
        st = self.work / "state"
        if not st.is_dir():
            return
        for d in st.iterdir():
            for root in (d, d / "state"):
                if not root.is_dir():
                    continue
                for ep in root.glob("*.json"):
                    if ep.name == "config.json":
                        continue
                    with contextlib.suppress(Exception):
                        dm = gs.Daemon(None, str(root), ep.stem)
                        if dm.jvm_alive():
                            dm.stop(force=True, timeout=60)

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

    def run_batch(self, name: str) -> dict:
        spec = BATCHES[name]
        want = self.counts.get(name, 0)
        py = [sys.executable, "-I"]
        shards = self.shard_plan(name, want)
        results = []
        outdirs = []

        def one(tag, n, seed):
            argv = [a.replace("{proj}", self.a.proj) for a in spec["argv"]]
            cmd = py + [str(CONC / spec["script"])] + argv + [str(n), str(seed)] + self.common()
            env = dict(os.environ, TRIG="1", RUN_TAG=f"{self.a.tag}{tag}")
            t0 = time.time()
            rc = self.run_proc(cmd, self.logs / f"{name}-{tag}.log", env, self.a.batch_timeout_s)
            results.append((tag, rc, round(time.time() - t0, 1)))
        ths = [threading.Thread(target=one, args=s) for s in shards]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
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
        for out in outdirs:
            if out.is_dir():
                oracle.check_k2(out, post)         # a kept iteration directory must have no bad version file
        if self.a.plant and name == self.a.plant_batch and outdirs:
            plant = outdirs[0] / "planted" / "x.rep" / "idata" / "00" / "~00000000.db"
            plant.mkdir(parents=True, exist_ok=True)
            (plant / "db.1.gbf").write_bytes(oracle.MAGIC + bytes(32))
            (plant / "db.2.gbf").write_bytes(bytes(40))        # X1: the newest version file has a zero header
            oracle.check_k2(outdirs[0] / "planted", post)
        r = judge_batch(name, spec, want, rows, footer, exit_code, post, self.a.profile == "gate")
        r["shards"] = [{"tag": t, "exit": rc, "seconds": s} for t, rc, s in results]
        r["what"] = spec["what"]
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
        res = overall(batches, self.a.profile, missing)
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
    check("gate counts: 400 save kills, 300 fork, 200 promote, 50 daemon",
          COUNTS["gate"]["save_ntfs"] + COUNTS["gate"]["save_refs"] == 400 and COUNTS["gate"]["fork"] == 300
          and COUNTS["gate"]["promote"] == 200 and COUNTS["gate"]["daemon8"] == 50)
    print(f"chaos selftest: {'FAILED: ' + str(bad) if bad else 'all checks ok'}")
    return 1 if bad else 0


# ------------------------------------------------------------------------------ command line

def main(argv=None) -> int:
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
    r.add_argument("--n", action="append", metavar="BATCH=N", help="override a batch's unanswered-kill count (not a gate run)")
    r.add_argument("--only", help="comma list of batch ids")
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
    print("evidence:", ch.evidence.folder)
    if a.plant:
        return 0 if out["verdict"] == "FAIL" and any("oracle K2" in v for v in out["violations"]) else 1
    return {"PASS": 0, "SMOKE-OK": 0, "FAIL": 1, "INCOMPLETE": 3}[out["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
