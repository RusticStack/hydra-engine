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
"""Measurement C: kill -9 (TerminateProcess) scenarios a-d, ctl, f against hydra-3-candidate.

usage: run_c.py SCENARIO PROJ FS N SEED
  SCENARIO a|ctl|b|c|d1|d2|f      PROJ fixture|large      FS ntfs|refs
Output: <work>/run/<scenario>-<proj>-<fs>/results.jsonl (+summary.json)
"""
import json
import pathlib
import random
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from c_lib import *  # noqa



def compact(scan):
    if not scan:
        return scan
    s = {k: v for k, v in scan.items() if k != "decomp"}
    if "decomp" in scan:
        s["decomp_sha"] = hashlib.sha256(json.dumps(scan["decomp"], sort_keys=True).encode()).hexdigest()[:16]
    return s


def compact_insp(r):
    if not r:
        return r
    out = {k: v for k, v in r.items() if k != "programs"}
    if "programs" in r:
        out["programs"] = {}
        for p, v in r["programs"].items():
            v = dict(v)
            if "scan" in v:
                v["scan"] = compact(v["scan"])
            out["programs"][p] = v
    return out


class Run:
    def __init__(s, scen, proj, fs, n, seed):
        s.scen, s.proj, s.fs, s.n, s.seed = scen, proj, fs, n, seed
        s.name = "%s-%s-%s" % (scen, proj, fs) + (("-" + os.environ["RUN_TAG"]) if os.environ.get("RUN_TAG") else "")
        s.out = RUN_ROOT / "run" / s.name
        if s.out.exists():
            shutil.rmtree(s.out)
        s.out.mkdir(parents=True)
        s.data = s.out if fs == "ntfs" else REFS_ROOT / s.name
        if fs != "ntfs":
            if REFS_ROOT is None:
                sys.exit("fs refs needs --refs-root (a folder on a ReFS volume)")
            if s.data.exists():
                shutil.rmtree(s.data)
            s.data.mkdir(parents=True)
        s.ctx = load_ctx(proj, RUN_ROOT)
        s.b = BASES[proj]
        s.prog = s.b["prog"]
        s.rig = Rig(s.out / "rig", instance="c")
        s.rng = random.Random(seed)
        s.fork_mode = "full" if fs == "ntfs" else "auto"
        s.res = open(s.out / "results.jsonl", "a", encoding="utf-8")
        s.keep = 0
        s.trig = os.environ.get("TRIG") == "1"
        s.base_tree = tree_hash(s.b["base"])["tree_sha256"]

    # -- helpers
    def emit(s, rec):
        s.res.write(json.dumps(rec, default=str) + "\n")
        s.res.flush()

    def iter_dir(s, i):
        d = s.data / ("it%s" % (("%03d" % i) if isinstance(i, int) else i))
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
        shutil.copytree(s.b["base"], d / "canon")
        return d, tree_hash(d / "canon")["tree_sha256"]

    def canon_gpr(s, d):
        return d / "canon" / s.b["gpr"]

    def end_iter(s, d, anomalies):
        if anomalies and s.keep < 6:
            s.keep += 1
            return
        shutil.rmtree(d, ignore_errors=True)

    def open_fork(s, c, d, sub="fork", writable_prog=True):
        o = c.call("open_project", path=str(s.canon_gpr(d)))
        f = c.call("fork_project", project=o["id"], path=str(d / sub), mode=s.fork_mode)
        fid = f["project"]
        key = None
        if writable_prog:
            p = c.call("open_program", path=s.prog, project=fid, writable=True, upgrade=s.b.get("upgrade", False))
            key = p["key"]
        return o["id"], fid, key, f

    def oracle(s, d, targets, deep=True, do_w=True, prefix="cg", progs_filter=None):
        """Fresh daemon on the same state; per target {label: (dir, gpr)}: tree hashes, RO scan, writable scan."""
        out = {"targets": {}}
        inv0 = {l: inventory(dr) for l, (dr, g) in targets.items()}
        th0 = {l: tree_hash(dr)["tree_sha256"] if pathlib.Path(dr).exists() else None for l, (dr, g) in targets.items()}
        off = s.rig.log_size()
        s.rig.watchdog(600)
        c, start_ms = s.rig.start("oracle", "c")
        out["restart_ms"] = start_ms
        full = {}
        for l, (dr, g) in targets.items():
            t = {"exists": pathlib.Path(g).exists()}
            if t["exists"]:
                t["ro"] = inspect(c, g, False, s.ctx, deep=deep, prefix=prefix, progs_filter=progs_filter)
                t["th_after_ro"] = tree_hash(dr)["tree_sha256"]
                t["ro_mutated_project"] = t["th_after_ro"] != th0[l]
                t["inv_ro"] = inv_diff(inv0[l], inventory(dr))
            full[l] = t
        if do_w:
            for l, (dr, g) in targets.items():
                if full[l]["exists"] and not l.startswith("canon"):  # the canonical is never opened writable
                    tw0 = now()
                    full[l]["w"] = inspect(c, g, True, s.ctx, deep=deep, prefix=prefix, progs_filter=progs_filter)
                    full[l]["w_total_ms"] = ms(tw0)
        out["log"] = s.rig.log_since(off)
        out["stop"] = s.rig.stop()
        s.rig.cancel_watchdog()
        for l, (dr, g) in targets.items():
            t = full[l]
            t["th_final"] = tree_hash(dr)["tree_sha256"] if pathlib.Path(dr).exists() else None
            inv = inventory(dr)
            t["residue_final"] = residue_tags(inv)
            t["inv_final"] = inv_diff(inv0[l], inv)
        out["targets"] = full
        return out

    def classify_main(s, scan, bases):
        if scan is None:
            return "NO_SCAN"
        for name, b in bases.items():
            if same(scan, b):
                return name
        return "OTHER"

    def tmp_files(s):
        n = 0
        for _dp, _dn, fn in os.walk(s.rig.tmp):
            n += len(fn)
        return n

    def base_rec(s, i, delay):
        return {"scenario": s.scen, "proj": s.proj, "fs": s.fs, "i": i, "seed": s.seed, "delay_s": delay}

    # -- delay window
    def draw(s, window):
        return s.rng.uniform(0, window)

    # ======================================================== scenario a / ctl
    def calib_a(s):
        """Baselines for gen1 / gen2 (via clean shutdown + restart + RO inspect), twice; save timing window."""
        res = {"runs": []}
        M, S = s.ctx["M_addrs"], s.ctx["S_addrs"]
        for r in range(2):
            d, _ = s.iter_dir("cal%d" % r)
            s.rig.watchdog(600)
            c, _ = s.rig.start("cal", "c")
            pid_, fid, key, f = s.open_fork(c, d)
            c.call("edit", program=key, ops=build_ops(M, 1))
            c.call("save", program=key)
            c.close()
            s.rig.stop()
            c, _ = s.rig.start("cal", "c")
            g1 = main_scan(inspect(c, d / "fork" / s.b["gpr"], False, s.ctx), s.ctx)
            o = c.call("open_project", path=str(d / "fork" / s.b["gpr"]), writable=True)
            p = c.call("open_program", path=s.prog, project=o["id"], writable=True, upgrade=s.b.get("upgrade", False))
            key = p["key"]
            c.call("edit", program=key, ops=build_ops(M, 2))
            c.call("save", program=key)
            c.close()
            s.rig.stop()
            c, _ = s.rig.start("cal", "c")
            g2 = main_scan(inspect(c, d / "fork" / s.b["gpr"], False, s.ctx), s.ctx)
            o = c.call("open_project", path=str(d / "fork" / s.b["gpr"]), writable=True)
            p = c.call("open_program", path=s.prog, project=o["id"], writable=True, upgrade=s.b.get("upgrade", False))
            key = p["key"]
            times = []
            trig_ms = []
            dbdir = d / "fork" / s.b["gpr"].replace(".gpr", ".rep") / "idata" / "00" / "~00000000.db"
            for g in range(3, 9):
                t_e = now()
                c.call("edit", program=key, ops=build_ops(M, g))
                te = ms(t_e)
                t = now()
                tr = measure_trigger(c, "save", dbdir, program=key)
                times.append(ms(t))
                trig_ms.append(tr)
            c.close()
            s.rig.stop()
            s.rig.cancel_watchdog()
            res["runs"].append({"g1": g1, "g2": g2, "save_ms": times, "edit_ms_last": te, "trigger_to_ack_ms": trig_ms})
            shutil.rmtree(d, ignore_errors=True)
        r0, r1 = res["runs"]
        res["g1_deterministic"] = same(r0["g1"], r1["g1"])
        res["g2_deterministic"] = same(r0["g2"], r1["g2"])
        res["g1_ne_g2"] = not same(r0["g1"], r0["g2"])
        allt = r0["save_ms"] + r1["save_ms"]
        res["save_ms_max"] = max(allt)
        res["save_ms_median"] = sorted(allt)[len(allt) // 2]
        res["window_s"] = (res["save_ms_median"] * 1.4 + 6) / 1000.0
        tt = sorted(x for r_ in res["runs"] for x in r_["trigger_to_ack_ms"] if x is not None)
        res["trigger_to_ack_ms_median"] = tt[len(tt) // 2] if tt else None
        res["trigger_window_s"] = ((tt[len(tt) // 2] * 1.3 + 2) / 1000.0) if tt else None
        if s.trig:
            res["window_s"] = res["trigger_window_s"]
        s.bases = {"gen1": r0["g1"], "gen2": r0["g2"]}
        return res

    def scen_a(s, i, delay):
        """delay None = control (no kill: ack, then clean stop)."""
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        M = s.ctx["M_addrs"]
        s.rig.watchdog(400)
        c, _ = s.rig.start("agent", "c")
        _pid, fid, key, f = s.open_fork(c, d)
        c.call("edit", program=key, ops=build_ops(M, 1))
        c.call("save", program=key)
        c.call("edit", program=key, ops=build_ops(M, 2))
        fdir = d / "fork"
        inv_pre = inventory(fdir)
        if delay is None:
            r = c.call("save", program=key)
            rec["acked_before_kill"] = True
            rec["clean_stop"] = s.rig.stop()
            rec["kill"] = None
        else:
            if s.trig:
                dbdir = fdir / s.b["gpr"].replace(".gpr", ".rep") / "idata" / "00" / "~00000000.db"
                info, res = kill_after_trigger(s.rig, c, "save", dbdir, delay, program=key)
            else:
                info, res = kill_during(s.rig, c, "save", delay, program=key)
            rec.update(info)
        s.rig.cancel_watchdog()
        inv_post = inventory(fdir)
        rec["residue_after_kill"] = inv_diff(inv_pre, inv_post)
        rec["lock_files_after_kill"] = residue_tags(inv_post)
        rec["jvm_tmp_files_after_kill"] = s.tmp_files()
        o = s.oracle(d, {"fork": (fdir, fdir / s.b["gpr"])})
        t = o["targets"]["fork"]
        ro = main_scan(t.get("ro"), s.ctx) if t.get("ro") else None
        w = main_scan(t.get("w"), s.ctx) if t.get("w") else None
        oc_ro = s.classify_main(ro, s.bases)
        oc_w = s.classify_main(w, s.bases)
        rec.update({"outcome_ro": oc_ro, "outcome_w": oc_w, "restart_ms": o["restart_ms"],
                    "open_project_ro_ms": (t.get("ro") or {}).get("open_project_ms"),
                    "open_project_w_ms": (t.get("w") or {}).get("open_project_ms"),
                    "open_program_ro_ms": ((t.get("ro") or {}).get("programs", {}).get(s.prog) or {}).get("open_program_ms"),
                    "ro_open_error": (t.get("ro") or {}).get("open_project_error"),
                    "w_open_error": (t.get("w") or {}).get("open_project_error"),
                    "prog_error_ro": ((t.get("ro") or {}).get("programs", {}).get(s.prog) or {}).get("error"),
                    "ro_mutated_project": t.get("ro_mutated_project"),
                    "residue_final": t["residue_final"], "inv_after_oracle": t["inv_final"],
                    "oracle_log": o["log"], "oracle_stop": o["stop"]})
        if ro is not None and oc_ro == "OTHER":
            rec["ro_diff_vs_gen1"] = diff_scan(s.bases["gen1"], ro)
            rec["ro_diff_vs_gen2"] = diff_scan(s.bases["gen2"], ro)
            rec["ro_scan"] = compact(ro)
        if oc_ro in ("OTHER", "NO_SCAN") or oc_w in ("OTHER", "NO_SCAN"):
            anomalies.append("CORRUPT_OR_UNOPENABLE")
        if oc_ro == "gen1" and rec.get("acked_before_kill"):
            anomalies.append("LOSS_OF_ACKED_SAVE")
        if oc_ro != oc_w:
            anomalies.append("RO_W_DIFFER")
        if t.get("ro_mutated_project"):
            anomalies.append("RO_INSPECT_MUTATED")
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec

    # ======================================================== scenario b (fork_project copy)
    def calib_b(s):
        times, res = [], {}
        base = None
        for r in range(4):
            d, _ = s.iter_dir("cal%d" % r)
            s.rig.watchdog(300)
            c, _ = s.rig.start("cal", "c")
            o = c.call("open_project", path=str(s.canon_gpr(d)))
            t = now()
            tr = measure_trigger(c, "fork_project", d / "f0", project=o["id"], path=str(d / "f0"), mode=s.fork_mode, writable=False)
            times.append(ms(t))
            res.setdefault("trigger_to_ack_ms", []).append(tr)
            c.close()
            s.rig.stop()
            if r == 0:
                c, _ = s.rig.start("cal", "c")
                base = main_scan(inspect(c, s.canon_gpr(d), False, s.ctx), s.ctx)
                fk = main_scan(inspect(c, d / "f0" / s.b["gpr"], False, s.ctx), s.ctx)
                res["fork_equals_canon"] = same(base, fk)
                c.close()
                s.rig.stop()
            s.rig.cancel_watchdog()
            shutil.rmtree(d, ignore_errors=True)
        s.bases = {"pre": base}
        res["fork_ms_cold"] = times
        res["window_s"] = (sorted(times)[len(times) // 2] * 1.4 + 5) / 1000.0
        tt = sorted(x for x in res.get("trigger_to_ack_ms", []) if x is not None)
        res["trigger_window_s"] = ((tt[len(tt) // 2] * 1.3 + 2) / 1000.0) if tt else None
        if s.trig and tt:
            res["window_s"] = res["trigger_window_s"]
        return res

    def scen_b(s, i, delay):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        s.rig.watchdog(300)
        c, _ = s.rig.start("agent", "c")
        o = c.call("open_project", path=str(s.canon_gpr(d)))
        dest = d / "fork"
        inv_pre = inventory(d)
        if s.trig:
            info, res = kill_after_trigger(s.rig, c, "fork_project", dest, delay, project=o["id"], path=str(dest), mode=s.fork_mode)
        else:
            info, res = kill_during(s.rig, c, "fork_project", delay, project=o["id"], path=str(dest), mode=s.fork_mode)
        rec.update(info)
        s.rig.cancel_watchdog()
        inv_post = inventory(dest)
        rec["dest_after_kill"] = sorted(inv_post)[:30]
        rec["dest_n_files"] = sum(1 for k in inv_post if not k.endswith("/"))
        rec["dest_residue_tags"] = residue_tags(inv_post)
        gpr = dest / s.b["gpr"]
        rec["dest_has_gpr"] = gpr.exists()
        rec["dest_has_rep"] = (dest / s.b["gpr"].replace(".gpr", ".rep")).exists()
        rec["dest_has_sidecar"] = (dest / s.b["gpr"].replace(".gpr", ".fork.json")).exists()
        rec["dest_has_fork_tmp"] = any(".fork-" in k for k in inv_post)
        if rec["dest_has_gpr"] and rec["dest_has_rep"]:
            rec["dest_state"] = "complete" + ("" if rec["dest_has_sidecar"] else "_NO_SIDECAR")
        elif rec["dest_has_rep"]:
            rec["dest_state"] = "rep_only_NO_GPR"
        elif rec["dest_has_fork_tmp"]:
            rec["dest_state"] = "tmp_only"
        elif not inv_post:
            rec["dest_state"] = "none"
        else:
            rec["dest_state"] = "other"
        # complete dest must be byte-identical to canonical (data files)
        if rec["dest_has_gpr"] and rec["dest_has_rep"]:
            cth = {k: v for k, v in _tree_rows(d / "canon").items()}
            # the staging folder (.<name>.fork-<id>.tmp, left until the next sweep) and the test lock are not project data (K6)
            def _scratch(k):
                return k.endswith((".fork.json", ".lock", ".lock~", ".lock~~")) or any(q.startswith(".") and ".fork-" in q and q.endswith(".tmp") for q in k.replace("\\", "/").split("/"))
            dth = {k: v for k, v in _tree_rows(dest).items() if not _scratch(k)}
            rec["dest_files_equal_canon"] = (cth == dth)
            rec["dest_diff_files"] = sorted(set(cth) ^ set(dth))[:10] + [k for k in cth if k in dth and cth[k] != dth[k]][:10]
        o2 = s.oracle(d, {"dest": (dest, gpr), "canon": (d / "canon", s.canon_gpr(d))}, do_w=True)
        t = o2["targets"]["dest"]
        ro = main_scan(t.get("ro"), s.ctx) if t.get("ro") else None
        w = main_scan(t.get("w"), s.ctx) if t.get("w") else None
        rec["dest_outcome_ro"] = s.classify_main(ro, s.bases) if t["exists"] else "ABSENT"
        rec["dest_outcome_w"] = s.classify_main(w, s.bases) if t["exists"] else "ABSENT"
        rec["dest_open_error_ro"] = (t.get("ro") or {}).get("open_project_error")
        rec["restart_ms"] = o2["restart_ms"]
        rec["oracle_log"] = o2["log"]
        rec["residue_final"] = t["residue_final"]
        rec["canon_ro_mutated"] = o2["targets"]["canon"].get("ro_mutated_project")
        cm = main_scan(o2["targets"]["canon"].get("ro"), s.ctx)
        rec["canon_scan_equals_baseline"] = same(cm, s.bases["pre"])
        # can a new fork go to the same destination after the crash?
        s.rig.watchdog(300)
        c, _ = s.rig.start("retry", "c")
        o = c.call("open_project", path=str(s.canon_gpr(d)))
        t0 = now()
        try:
            r = c.call("fork_project", project=o["id"], path=str(dest), mode=s.fork_mode, writable=False)
            rec["retry_same_dest"] = {"ok": True, "ms": ms(t0)}
        except SessionError as e:
            rec["retry_same_dest"] = {"ok": False, "code": e.code, "message": (e.message or "")[:200]}
        try:
            dest2 = d / "fork2"
            r = c.call("fork_project", project=o["id"], path=str(dest2), mode=s.fork_mode, writable=False)
            rec["retry_fresh_dest"] = {"ok": True}
        except SessionError as e:
            rec["retry_fresh_dest"] = {"ok": False, "code": e.code, "message": (e.message or "")[:200]}
        c.close()
        s.rig.stop()
        s.rig.cancel_watchdog()
        rec["leftover_fork_tmp_after_retry"] = [k for k in inventory(d / "fork") if ".fork-" in k][:5] + [k for k in inventory(d / "fork2") if ".fork-" in k][:5]
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        if rec["dest_state"] in ("rep_only_NO_GPR", "other") or rec["dest_state"].endswith("NO_SIDECAR"):
            anomalies.append("PARTIAL_DEST_VISIBLE:" + rec["dest_state"])
        if rec["dest_state"].startswith("complete") and (rec["dest_outcome_ro"] != "pre" or not rec.get("dest_files_equal_canon")):
            anomalies.append("COMPLETE_DEST_NOT_EQUAL_CANON")
        if rec["dest_state"] == "tmp_only":
            anomalies.append("ORPHAN_TMP_LEFT")  # informational class: orphan temp (not corruption)
        if rec["dest_state"] == "none" and rec["dest_has_fork_tmp"]:
            pass
        if not rec["retry_same_dest"]["ok"] and rec["dest_state"] != "complete":
            anomalies.append("RETRY_BLOCKED")
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, [a for a in anomalies if a not in ("ORPHAN_TMP_LEFT",)])
        return rec

    # ======================================================== scenario c (import + analysis)
    def calib_c(s):
        res = {"runs": []}
        for r in range(2):
            d, _ = s.iter_dir("cal%d" % r)
            s.rig.watchdog(900)
            c, _ = s.rig.start("cal", "c")
            _pid, fid, key, f = s.open_fork(c, d, writable_prog=False)
            t = now()
            imp = c.call("import", file=IMPORT_EXE, project=fid, analyze=False, timeout=600)
            t_imp = ms(t)
            c.close()
            s.rig.stop()
            c, _ = s.rig.start("cal", "c")
            imp_only = inspect(c, d / "fork" / s.b["gpr"], False, s.ctx)
            o = c.call("open_project", path=str(d / "fork" / s.b["gpr"]), writable=True)
            t = now()
            a = c.call("import", file=IMPORT_EXE, project=o["id"], analyze=True, duplicate=True, name="diff1b.exe", timeout=900)
            t_ana = ms(t)
            c.close()
            s.rig.stop()
            c, _ = s.rig.start("cal", "c")
            full = inspect(c, d / "fork" / s.b["gpr"], False, s.ctx)
            c.close()
            s.rig.stop()
            s.rig.cancel_watchdog()
            res["runs"].append({"import_only_ms": t_imp, "import_analyze_ms": t_ana, "imp_only": compact_insp(imp_only), "full": compact_insp(full),
                                "imp_keys": [k for k in imp.keys()][:10], "import_result_brief": json.dumps(imp)[:300], "analyze_result_brief": json.dumps(a)[:300]})
            shutil.rmtree(d, ignore_errors=True)
        res["window_s"] = max(r["import_analyze_ms"] for r in res["runs"]) * 1.05 / 1000.0
        s.cal_c = res
        d0 = res["runs"][0]
        s.base_main_pre = None
        return res

    def prog_summary(s, insp, path):
        p = (insp.get("programs") or {}).get(path)
        if not p:
            return None
        if "error" in p:
            return {"error": p["error"]}
        sc = p.get("scan") or {}
        return {"functions": sc.get("functions"), "names_sha": sc.get("names_sha"), "analyzed": p.get("analyzed")}

    def scen_c(s, i, delay):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        s.rig.watchdog(900)
        c, _ = s.rig.start("agent", "c")
        _pid, fid, key, f = s.open_fork(c, d, writable_prog=False)
        fdir = d / "fork"
        inv_pre = inventory(fdir)
        info, res = kill_during(s.rig, c, "import", delay, file=IMPORT_EXE, project=fid, analyze=True, timeout=900)
        rec.update(info)
        s.rig.cancel_watchdog()
        inv_post = inventory(fdir)
        rec["residue_after_kill"] = inv_diff(inv_pre, inv_post)
        rec["lock_files_after_kill"] = residue_tags(inv_post)
        rec["jvm_tmp_files_after_kill"] = s.tmp_files()
        o = s.oracle(d, {"fork": (fdir, fdir / s.b["gpr"])}, deep=True)
        t = o["targets"]["fork"]
        rec["restart_ms"] = o["restart_ms"]
        rec["oracle_log"] = o["log"]
        rec["residue_final"] = t["residue_final"]
        rec["ro_mutated_project"] = t.get("ro_mutated_project")
        # the original program must equal the pristine baseline
        base_main = s.base_main
        for mode in ("ro", "w"):
            insp = t.get(mode)
            if not insp:
                rec["main_" + mode] = "NO_INSPECT"
                rec["new_" + mode] = "NO_INSPECT"
                continue
            if "open_project_error" in insp:
                rec["main_" + mode] = "OPEN_ERROR"
                rec["new_" + mode] = "OPEN_ERROR"
                rec["open_error_" + mode] = insp["open_project_error"]
                continue
            m = main_scan(insp, s.ctx)
            rec["main_" + mode] = "pristine" if same(m, base_main) else "CHANGED"
            progs = insp.get("programs") or {}
            newp = [p for p in progs if p != s.prog]
            if not newp:
                rec["new_" + mode] = "ABSENT"
            else:
                ps = s.prog_summary(insp, newp[0])
                rec["new_" + mode + "_summary"] = ps
                if ps is None or "error" in (ps or {}):
                    rec["new_" + mode] = "UNREADABLE"
                else:
                    cal = s.cal_c["runs"][0]
                    full = s.prog_summary_c(cal["full"], "/diff1b.exe")
                    only = s.prog_summary_c(cal["imp_only"], "/diff1.exe")
                    if ps["names_sha"] == only["names_sha"] and not ps["analyzed"]:
                        rec["new_" + mode] = "IMPORTED_UNANALYZED"
                    elif ps["names_sha"] == full["names_sha"] and ps["analyzed"]:
                        rec["new_" + mode] = "COMPLETE"
                    elif ps["analyzed"] and ps["functions"] == full["functions"]:
                        rec["new_" + mode] = "COMPLETE_NAMES_DIFFER"
                    else:
                        rec["new_" + mode] = "OTHER"
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        for mode in ("ro", "w"):
            if rec.get("main_" + mode) != "pristine":
                anomalies.append("MAIN_" + mode.upper() + ":" + str(rec.get("main_" + mode)))
            if rec.get("new_" + mode) in ("OTHER", "UNREADABLE", "OPEN_ERROR", "NO_INSPECT"):
                anomalies.append("NEW_" + mode.upper() + ":" + str(rec.get("new_" + mode)))
        if rec.get("new_ro") == "IMPORTED_UNANALYZED":
            rec["note"] = "import saved, analysis not saved"
        if rec.get("acked_before_kill") and rec.get("new_ro") != "COMPLETE":
            anomalies.append("LOSS_OF_ACKED_IMPORT")
        if rec.get("ro_mutated_project"):
            anomalies.append("RO_INSPECT_MUTATED")
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec

    def prog_summary_c(s, insp, path):
        p = (insp.get("programs") or {}).get(path)
        if not p:
            # name chosen at import: first run imports as diff1.exe
            for k, v in (insp.get("programs") or {}).items():
                if k != s.prog:
                    p = v
        sc = p.get("scan") or {}
        return {"functions": sc.get("functions"), "names_sha": sc.get("names_sha"), "analyzed": p.get("analyzed")}

    # ======================================================== scenario d1/d2 (overlay)
    def calib_d(s, promote):
        M = s.ctx["M_addrs"]
        res = {"runs": []}
        for r in range(4):
            d, _ = s.iter_dir("cal%d" % r)
            s.rig.watchdog(600)
            c, _ = s.rig.start("cal", "c")
            o = c.call("open_project", path=str(s.canon_gpr(d)))
            p = c.call("open_program", path=s.prog, project=o["id"], overlay="ov")
            key = p["key"]
            t = now()
            c.call("apply_overlay", program=key, overlay="ov", ops=build_ops(M, 1))
            t_apply = ms(t)
            run = {"apply_ms_cold": t_apply}
            if r < 2 or promote:
                t = now()
                trg = measure_trigger(c, "promote_overlay", d / "fork", program=key, overlay="ov", fork={"path": str(d / "fork"), "mode": s.fork_mode}, save=True)
                run["promote_ms_cold"] = ms(t)
                run["trigger_to_ack_ms"] = trg
            c.close()
            s.rig.stop()
            if r < 2:
                c, _ = s.rig.start("cal", "c")
                run["post"] = main_scan(inspect(c, d / "fork" / s.b["gpr"], False, s.ctx), s.ctx)
                run["pre"] = main_scan(inspect(c, s.canon_gpr(d), False, s.ctx), s.ctx)
                c.close()
                s.rig.stop()
            s.rig.cancel_watchdog()
            res["runs"].append(run)
            shutil.rmtree(d, ignore_errors=True)
        r0, r1 = res["runs"][0], res["runs"][1]
        res["post_deterministic"] = same(r0["post"], r1["post"])
        res["post_ne_pre"] = not same(r0["post"], r0["pre"])
        s.bases = {"pre": r0["pre"], "post": r0["post"]}
        ap = sorted(r["apply_ms_cold"] for r in res["runs"])
        pm = sorted(r["promote_ms_cold"] for r in res["runs"] if "promote_ms_cold" in r)
        res["window_apply_s"] = ap[len(ap) // 2] * 1.4 / 1000.0
        res["window_promote_s"] = pm[len(pm) // 2] * 1.4 / 1000.0
        res["window_s"] = res["window_promote_s"] if promote else res["window_apply_s"]
        tt = sorted(r["trigger_to_ack_ms"] for r in res["runs"] if r.get("trigger_to_ack_ms") is not None)
        res["trigger_window_s"] = ((tt[len(tt) // 2] * 1.3 + 2) / 1000.0) if tt else None
        if s.trig and promote and tt:
            res["window_s"] = res["trigger_window_s"]
        return res

    def scen_d(s, i, delay, promote):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        M = s.ctx["M_addrs"]
        s.rig.watchdog(400)
        c, _ = s.rig.start("agent", "c")
        o = c.call("open_project", path=str(s.canon_gpr(d)))
        p = c.call("open_program", path=s.prog, project=o["id"], overlay="ov")
        key = p["key"]
        dest = d / "fork"
        inv_pre = inventory(d)
        if promote:
            c.call("apply_overlay", program=key, overlay="ov", ops=build_ops(M, 1))
            if s.trig:
                info, res = kill_after_trigger(s.rig, c, "promote_overlay", dest, delay, program=key, overlay="ov",
                                               fork={"path": str(dest), "mode": s.fork_mode}, save=True)
            else:
                info, res = kill_during(s.rig, c, "promote_overlay", delay, program=key, overlay="ov",
                                        fork={"path": str(dest), "mode": s.fork_mode}, save=True)
        else:
            info, res = kill_during(s.rig, c, "apply_overlay", delay, program=key, overlay="ov", ops=build_ops(M, 1))
        rec.update(info)
        s.rig.cancel_watchdog()
        inv_post = inventory(d)
        rec["residue_after_kill"] = inv_diff(inv_pre, inv_post)
        rec["dest_residue_tags"] = residue_tags(inventory(dest))
        gpr = dest / s.b["gpr"]
        rec["dest_has_gpr"] = gpr.exists()
        rec["dest_has_rep"] = (dest / s.b["gpr"].replace(".gpr", ".rep")).exists()
        rec["dest_has_fork_tmp"] = any(".fork-" in k for k in inventory(dest))
        o2 = s.oracle(d, {"dest": (dest, gpr), "canon": (d / "canon", s.canon_gpr(d))}, do_w=True)
        t = o2["targets"]["dest"]
        rec["restart_ms"] = o2["restart_ms"]
        rec["oracle_log"] = o2["log"]
        for mode in ("ro", "w"):
            sc = main_scan(t.get(mode), s.ctx) if t.get(mode) else None
            rec["dest_" + mode] = s.classify_main(sc, s.bases) if t["exists"] else "ABSENT"
            if sc is not None and rec["dest_" + mode] == "OTHER":
                rec["dest_%s_scan" % mode] = compact(sc)
                rec["dest_%s_diff_post" % mode] = diff_scan(s.bases["post"], sc)
        rec["dest_open_error"] = (t.get("ro") or {}).get("open_project_error")
        rec["dest_residue_final"] = t["residue_final"]
        cm = main_scan(o2["targets"]["canon"].get("ro"), s.ctx)
        rec["canon_scan_equals_baseline"] = same(cm, s.bases["pre"])
        rec["canon_ro_mutated"] = o2["targets"]["canon"].get("ro_mutated_project")
        # is the overlay still there after the restart? (it should not be: overlays are not durable)
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        if not rec["canon_scan_equals_baseline"]:
            anomalies.append("CANON_SCAN_DIFFERS")
        if promote:
            if rec["dest_ro"] in ("OTHER", "NO_SCAN") or rec["dest_w"] in ("OTHER", "NO_SCAN"):
                anomalies.append("DEST_CORRUPT_OR_UNOPENABLE")
            if rec.get("acked_before_kill") and rec["dest_ro"] != "post":
                anomalies.append("LOSS_OF_ACKED_PROMOTE")
            if rec["dest_has_rep"] != rec["dest_has_gpr"]:
                anomalies.append("PARTIAL_DEST_VISIBLE")
            if rec["dest_ro"] == "pre":
                rec["note"] = "fork complete but overlay edits not applied/saved"
        else:
            if rec["dest_ro"] != "ABSENT":
                anomalies.append("APPLY_LEFT_A_FORK")
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec


def _tree_rows(root):
    rows = {}
    root = pathlib.Path(root)
    for dp, _dn, files in os.walk(root):
        for n in files:
            p = pathlib.Path(dp, n)
            rows[p.relative_to(root).as_posix()] = sha256_file(p)
    return rows


def main():
    scen, proj, fs, n, seed = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
    s = Run(scen, proj, fs, n, seed)
    t_start = time.time()
    hdr = {"scenario": scen, "proj": proj, "fs": fs, "n": n, "seed": seed, "start": time.strftime("%Y-%m-%d %H:%M:%S"),
           "engine": INSTALL, "base_tree": s.base_tree, "data_root": str(s.data)}
    (s.out / "header.json").write_text(json.dumps(hdr, indent=1))
    if scen in ("a", "ctl"):
        cal = s.calib_a()
        f = lambda i, dl: s.scen_a(i, dl)
    elif scen == "b":
        cal = s.calib_b()
        f = lambda i, dl: s.scen_b(i, dl)
    elif scen == "c":
        cal = s.calib_c()
        # pristine baseline of the original program
        d, _ = s.iter_dir("calm")
        s.rig.watchdog(300)
        c, _ = s.rig.start("cal", "c")
        s.base_main = main_scan(inspect(c, s.canon_gpr(d), False, s.ctx), s.ctx)
        c.close()
        s.rig.stop()
        s.rig.cancel_watchdog()
        shutil.rmtree(d, ignore_errors=True)
        f = lambda i, dl: s.scen_c(i, dl)
    elif scen in ("d1", "d2"):
        cal = s.calib_d(scen == "d2")
        f = lambda i, dl: s.scen_d(i, dl, scen == "d2")
    else:
        raise SystemExit("unknown scenario")
    (s.out / "calibration.json").write_text(json.dumps(cal, indent=1, default=str))
    print("calibrated", s.name, "window_s=%.3f" % cal.get("window_s", -1), flush=True)
    window = cal["window_s"]
    if os.environ.get("WINDOW_S"):
        window = float(os.environ["WINDOW_S"])
        print("window overridden to", window, flush=True)
    inflight, attempts = 0, 0
    max_attempts = n if scen == "ctl" else int(n * 3)
    while (inflight < n if scen != "ctl" else attempts < n) and attempts < max_attempts:
        i = attempts
        attempts += 1
        delay = None if scen == "ctl" else s.draw(window)
        t0 = time.time()
        try:
            rec = f(i, delay)
            if scen == "ctl" or not rec.get("acked_before_kill"):
                inflight += 1
            print("%s it%03d delay=%s -> %s %s inflight=%d (%.0fs)" % (s.name, i, None if delay is None else round(delay, 3),
                                                                      rec.get("outcome_ro") or rec.get("dest_outcome_ro") or rec.get("dest_ro") or rec.get("new_ro"),
                                                                      rec["anomalies"], inflight, time.time() - t0), flush=True)
        except Exception as e:  # noqa: BLE001
            import traceback
            tb = traceback.format_exc()
            print("ITERATION FAILED", i, repr(e)[:300], flush=True)
            s.emit({"scenario": scen, "proj": proj, "fs": fs, "i": i, "seed": seed, "delay_s": delay, "harness_error": tb[-1500:]})
            pid = s.rig.pid()
            if pid:
                terminate(pid, 20)
    end_tree = tree_hash(s.b["base"])["tree_sha256"]
    (s.out / "footer.json").write_text(json.dumps({"base_tree_start": s.base_tree, "base_tree_end": end_tree,
                                                     "base_unchanged": end_tree == s.base_tree, "elapsed_s": round(time.time() - t_start, 1)}, indent=1))
    print("done", s.name, "base_unchanged", end_tree == s.base_tree, flush=True)


if __name__ == "__main__":
    main()
