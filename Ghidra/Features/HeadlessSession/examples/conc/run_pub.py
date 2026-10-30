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
"""The publish kills of gate 9.15 (8.13): a Hydralysis generation publish killed with TerminateProcess, trigger-timed.

usage: run_pub.py pub PROJ FS N SEED --work DIR [any other option of chaos_tests' common arguments, ignored]
Output: <work>/run/pub-<proj>-<fs>[-RUN_TAG]/results.jsonl, footer.json, calibration.json

"Publish" in 9.15 is the Hydralysis generation publish (3.12 "Kill during publish: nothing published (CURRENT.log
unchanged) or fully published; the changeset is durable; the next leader resumes"; GR4; D50 counts it apart from the
300 fork-publish kills). It is not an engine command, so this harness drives Hydralysis' own fault harness: the publisher
process of ``tests/test_views.py --worker`` (``views.run_publish_job`` of one sealed changeset against Hydralysis' fake
daemon, which keeps every effect on disk), from the Hydralysis checkout named by ``HYDRALYSIS_SRC`` (default
``E:/Projects/Hydra/wt/int-hy``, the hydra.4 candidate; it is only read: no bytecode is written there). The engine is not
involved: the files are Hydralysis' (lineage, ``CURRENT.log``, store records, generation folders).

Each iteration: a fresh world (master project, a view "one" with one rename, the changeset sealed), a publisher process
started, the daemon-free kill *X ms after the lineage folder listing first changes* (X uniform in the calibrated window,
the method of C), then K1-K17 (``k`` of the row): what the kill left (K1 master untouched, K4 one generation, K7 lock
freed, K12 and K17 over ``CURRENT.log`` and the records, nothing partially published), the next leader (``views.drain``:
K5 applied exactly once, K10 a new leader runs, K12 again), K16 (a sequential model of the log equals the head), K6 and
K8 (every generation's manifest verifies, the view settles with its records out of pending), K15 (the healed view answers
the published name). A kill counts when the trigger fired and the publisher had not answered.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.dont_write_bytecode = True
import oracle as O  # noqa: E402

HY = pathlib.Path(os.environ.get("HYDRALYSIS_SRC", "E:/Projects/Hydra/wt/int-hy"))
KS = ["K%d" % i for i in range(1, 18)]


def load_hy():
    for p in (HY / "src", HY / "tests"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    import test_views as tv  # noqa: PLC0415
    return tv


def listing(root: pathlib.Path):
    out = []
    for dp, dn, fn in os.walk(root):
        out.append((dp, tuple(sorted(dn)), tuple(sorted(fn))))
    return out


class Pub:
    def __init__(self, tv, work: pathlib.Path):
        self.tv = tv
        os.environ["HYDRALYSIS_TEST_ROOT"] = str(work)
        (work).mkdir(parents=True, exist_ok=True)

        class W(tv.ViewWorld, tv.unittest.TestCase):
            def runTest(self):  # noqa: N802  (unittest needs a method to instantiate)
                pass
        self.W = W

    def world(self):
        w = self.W()
        w.setUp()
        lazy = self.tv.LazyProjects(w.daemon, {"/owned.exe": {"sha256": w.digest, "functions": 3}})
        lazy.update(w.daemon.projects)
        w.daemon.projects = lazy
        return w

    def spawn(self, w, sealed, view):
        tv = self.tv
        spec = {"settings": w.settings, "target": "owned", "view": view, "csid": sealed["csid"], "lineage": sealed["lineage"],
                "programs": {"/owned.exe": {"sha256": w.digest, "functions": 3}}}
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(HY / "src"), str(HY / "tests")]), PYTHONDONTWRITEBYTECODE="1")
        for name in tv.ENV_FAULT:
            env.pop(name, None)
        return subprocess.Popen([sys.executable, "-B", str(HY / "tests" / "test_views.py"), "--worker", json.dumps(spec)],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def prepare(self):
        w = self.world()
        w.edit("Mine", self.tv.A, view="one")
        sealed = w.seal("one")
        return w, sealed

    def ldir(self, w):
        return self.tv.lineage.lineage_dir(w.settings, w.lineage_id())

    # ---- one iteration
    def iteration(self, delay):
        tv = self.tv
        w, sealed = self.prepare()
        rec = {"scenario": "pub", "delay_s": delay, "csid": sealed["csid"]}
        anomalies: list = []
        ks: dict = {}
        try:
            ld = self.ldir(w)
            master0 = w.master_tree
            log_path = ld / "CURRENT.log"
            log0 = log_path.read_bytes() if log_path.exists() else b""
            name0 = w.name_of(tv.A)
            init = listing(ld)
            t_send = time.perf_counter()
            p = self.spawn(w, sealed, "one")
            t_trig = None
            while p.poll() is None and time.perf_counter() - t_send < 120:
                if listing(ld) != init:
                    t_trig = time.perf_counter()
                    break
            if delay is None:
                p.communicate(timeout=240)
                rec.update(trigger_hit=t_trig is not None, acked_before_kill=True, kill=None)
            else:
                if t_trig is not None:
                    rest = delay - (time.perf_counter() - t_trig)
                    while rest > 0:
                        time.sleep(min(rest, 0.002)) if rest > 0.004 else None
                        rest = delay - (time.perf_counter() - t_trig)
                answered = p.poll() is not None
                if not answered:
                    p.kill()           # TerminateProcess on Windows
                out, err = p.communicate(timeout=60)
                rec.update(trigger_hit=t_trig is not None, acked_before_kill=answered and p.returncode == 0,
                           kill={"pid": p.pid, "answered_first": answered, "returncode": p.returncode},
                           trigger_ms_after_send=round((t_trig - t_send) * 1000, 1) if t_trig else None)
            # ---- what the kill left (before any other leader)
            head = w.head()
            rec["head_after_kill"] = head.get("gen")
            log1 = log_path.read_bytes() if log_path.exists() else b""
            published = head.get("gen") == 1
            if not published and log1 != log0 and not head.get("torn_tail"):
                anomalies.append("PUBLISH_PARTIAL:log_changed_head_old")
            if rec.get("acked_before_kill") and not published:
                anomalies.append("LOSS_OF_ACKED_PUBLISH")
            name_k = w.name_of(tv.A)
            rec["name_after_kill"] = name_k
            want = "Mine" if published else name0
            rep = O.Report("pub")
            if name_k != want:
                rep.violation("K4", "generation_mixed", f"head gen {head.get('gen')} answers {name_k!r}, wanted {want!r}")
            if tv.lineage.tree_hash(w.gpr.parent) != master0:
                rep.violation("K1", "master_changed", "the master project changed")
            if tv.locks.held(str(tv.views.publish_lock_path(w.settings, w.lineage_id()))):
                rep.violation("K7", "publish_lock_held", "the killed publisher's lock is still held")
            O.check_k17(ld, log_path, rep=rep)
            lin = O.load_lineage(ld)
            O.check_k12(lin, acked_csids=[sealed["csid"]] if rec.get("acked_before_kill") else (), rep=rep)
            durable = sealed["csid"] in lin["pending"] or sealed["csid"] in lin["done"] or published
            if not durable:
                rep.violation("K5", "changeset_not_durable", "the sealed changeset is neither pending nor done nor published")
            # ---- the next leader (any process) finishes it, exactly once
            t0 = time.perf_counter()
            try:
                tv.views.drain(w.settings, w.lineage_id(), w.engine())
                rec["next_leader_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            except Exception as e:  # noqa: BLE001
                rep.violation("K10", "next_leader_failed", repr(e)[:300])
            done = tv.views.read_done(w.settings, w.lineage_id(), sealed["csid"])
            rec["outcome_after_drain"] = (done or {}).get("outcome")
            if (done or {}).get("outcome") != "applied":
                rep.violation("K5", "not_applied", f"after the next leader: {done}")
            rows = [r for r in w.rows() if r.get("changesets")]
            order = [it["csid"] for r in rows for it in r["changesets"]]
            if order.count(sealed["csid"]) != 1:
                rep.violation("K12", "applied_not_once", f"the changeset is in {order.count(sealed['csid'])} generations")
            if [r["gen"] for r in w.rows()] != list(range(len(w.rows()))):
                rep.violation("K12", "log_gap", f"generations {[r['gen'] for r in w.rows()]}")
            lin2 = O.load_lineage(ld)
            O.check_k12(lin2, acked_csids=[sealed["csid"]], rep=rep)
            O.check_k17(ld, log_path, rep=rep)
            vh = tv.lineage.verify_head(w.settings, w.lineage_id())
            if not vh.get("ok"):
                rep.violation("K6", "head_does_not_verify", str(vh)[:200])
            for r in w.rows()[1:]:
                vm = tv.lineage.verify_manifest(tv.lineage.project_folder_of(r["gpr"]))
                if not vm.get("ok"):
                    rep.violation("K6", "generation_manifest", f"gen {r['gen']}: {str(vm)[:160]}")
            # K16: a sequential model folds the log's changesets in order and equals the head
            model = name0
            for cs in order:
                if cs == sealed["csid"]:
                    model = "Mine"
            if w.name_of(tv.A) != model:
                rep.violation("K16", "model_differs", f"head answers {w.name_of(tv.A)!r}, the model {model!r}")
            # K8 / K15: the view settles (its record leaves pending, its store names the commit) and answers the head
            try:
                w.settle("one")
                if w.pending_ids("one"):
                    rep.violation("K8", "records_still_pending", str(w.pending_ids("one")))
                if w.name_of(tv.A, view="one") != "Mine":
                    rep.violation("K15", "view_differs", f"view one answers {w.name_of(tv.A, view='one')!r}")
            except Exception as e:  # noqa: BLE001
                rep.violation("K8", "settle_failed", repr(e)[:300])
            if tv.lineage.tree_hash(w.gpr.parent) != master0:
                rep.violation("K9", "master_changed_after_drain", "the master project changed")
            O.check_k2(w.root, rep=rep)
            # results per K
            how = {"K1": "master tree hash after the kill", "K2": "every db.N.gbf under the world (the fake daemon writes none)",
                   "K4": "the head answers one generation's name", "K5": "changeset durable; applied by the next leader",
                   "K6": "head and every generation manifest verify", "K7": "the killed leader's publish.lock is free",
                   "K8": "the view settles, no record left pending", "K9": "master unchanged after the next leader",
                   "K10": "a next leader runs", "K12": "CURRENT.log consecutive, the changeset applied once, before and after",
                   "K15": "the healed view answers the head", "K16": "a sequential model of the log equals the head",
                   "K17": "sealed records and CURRENT.log (torn tail tolerated)"}
            for k in KS:
                f = [x for x in rep.findings if x["id"] == k]
                if k in how:
                    ks[k] = {"ok": not f, "how": how[k]} if not f else {"ok": False, "findings": [x["code"] + ": " + x["detail"][:160] for x in f]}
            ks["K3"] = {"na": "no engine program in a Hydralysis publish (the fake daemon's programs are records)"}
            ks["K11"] = {"na": "one view; view isolation is Y5's K11 suite"}
            ks["K13"] = {"na": "no engine daemon (no waits.foreignBlocked to read)"}
            ks["K14"] = {"na": "no engine daemon (no heap or slot to read)"}
            ks = {k: ks[k] for k in KS}
            anomalies += sorted({f"{x['id']}:{x['code']}" for x in rep.findings})
        finally:
            rec["anomalies"] = anomalies
            rec["k"] = ks
            w.doCleanups()
        return rec


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("scen")
    ap.add_argument("proj")
    ap.add_argument("fs")
    ap.add_argument("n", type=int)
    ap.add_argument("seed", type=int)
    ap.add_argument("--work", required=True)
    a, _rest = ap.parse_known_args(argv)
    name = "pub-%s-%s" % (a.proj, a.fs) + (("-" + os.environ["RUN_TAG"]) if os.environ.get("RUN_TAG") else "")
    out = pathlib.Path(a.work) / "run" / name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tv = load_hy()
    pub = Pub(tv, out / "hy")
    rng = random.Random(a.seed)
    t_start = time.time()
    res = open(out / "results.jsonl", "a", encoding="utf-8")
    (out / "header.json").write_text(json.dumps({"scenario": "pub", "n": a.n, "seed": a.seed, "hydralysis": str(HY),
                                                 "start": time.strftime("%Y-%m-%d %H:%M:%S")}, indent=1))
    # calibration: two unkilled publishes, from the first change of the lineage listing to the answer
    spans = []
    for _ in range(3):
        w, sealed = pub.prepare()
        try:
            ld = pub.ldir(w)
            init = listing(ld)
            p = pub.spawn(w, sealed, "one")
            t_trig = None
            while p.poll() is None:
                if t_trig is None and listing(ld) != init:
                    t_trig = time.perf_counter()
            t_end = time.perf_counter()
            p.communicate()
            if t_trig:
                spans.append(t_end - t_trig)
        finally:
            w.doCleanups()
    window = (sorted(spans)[len(spans) // 2] * 1.3) if spans else 0.5
    (out / "calibration.json").write_text(json.dumps({"spans_s": spans, "window_s": window}, indent=1))
    print("calibrated", name, "window_s=%.3f" % window, flush=True)
    masters_ok = True
    inflight = attempts = 0
    ctl = a.scen == "ctl"
    while (inflight < a.n if not ctl else attempts < a.n) and attempts < a.n * 3:
        i = attempts
        attempts += 1
        delay = None if ctl else rng.uniform(0, window)
        t0 = time.time()
        try:
            rec = pub.iteration(delay)
            rec["i"] = i
            if ctl or not rec.get("acked_before_kill"):
                inflight += 1
            masters_ok &= not any(x.startswith("K1:") for x in rec["anomalies"])
            res.write(json.dumps(rec, default=str) + "\n")
            res.flush()
            print("%s it%03d delay=%s -> head %s %s inflight=%d (%.1fs)" % (name, i, None if delay is None else round(delay, 4),
                                                                          rec.get("head_after_kill"), rec["anomalies"], inflight,
                                                                          time.time() - t0), flush=True)
        except Exception:  # noqa: BLE001
            import traceback
            tb = traceback.format_exc()
            print("ITERATION FAILED", i, tb[-400:], flush=True)
            res.write(json.dumps({"scenario": "pub", "i": i, "delay_s": delay, "harness_error": tb[-1500:]}) + "\n")
            res.flush()
    (out / "footer.json").write_text(json.dumps({"base_unchanged": masters_ok, "elapsed_s": round(time.time() - t_start, 1),
                                                 "note": "base_unchanged: every iteration's master project was untouched (K1)"},
                                                indent=1))
    shutil.rmtree(out / "hy", ignore_errors=True)
    print("done", name, "base_unchanged", masters_ok, flush=True)


if __name__ == "__main__":
    main()
