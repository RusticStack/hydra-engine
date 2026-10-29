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
"""Measurement C scenarios e (client killed, daemon survives) and f (daemon killed with 8 clients on 8 forks).

usage: run_ef.py e KIND PROJ FS N SEED      KIND reader|owner|forker|importer|shared
       run_ef.py f - PROJ FS N SEED
"""
import json
import pathlib
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from c_lib import *  # noqa
from run_c import Run, compact, compact_insp, _tree_rows  # noqa

PY = sys.executable
WORKER = str(pathlib.Path(__file__).parent / "c_worker.py")
HARNESSES = ["claude-code", "codex", "opencode", "qodercli"]


def parse_progress(path):
    out = {"lines": 0}
    try:
        for ln in pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            out["lines"] += 1
            parts = ln.split()
            if not parts:
                continue
            if parts[0] in ("edit_sent", "edit_ack", "save_sent", "save_ack", "fork_sent", "fork_ack") and len(parts) >= 2:
                try:
                    out[parts[0]] = int(parts[1])
                except ValueError:
                    pass
            elif parts[0] == "acked" and len(parts) >= 3:
                try:
                    out["acked_" + parts[1]] = int(parts[2])
                except ValueError:
                    pass
            else:
                out[parts[0]] = True
    except OSError:
        pass
    return out


class RunEF(Run):
    # ---------------------------------------------------------------- e
    def wait_ready(s, prog_file, proc, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            if proc.poll() is not None:
                return False
            try:
                if "ready" in pathlib.Path(prog_file).read_text(encoding="utf-8", errors="replace").split():
                    return True
            except OSError:
                pass
            time.sleep(0.02)
        return False

    def window_e(s, kind):
        k = s.proj
        return {"reader": {"fixture": 2.0, "large": 3.0},
                "owner": {"fixture": 1.5, "large": 8.0},
                "forker": {"fixture": 0.4, "large": 3.0},
                "importer": {"fixture": 7.0, "large": 9.0},
                "shared": {"fixture": 1.5, "large": 8.0}}[kind][k]

    def drain_wait(s, c, victim="victim", timeout=60):
        """Poll status until the victim is gone and nothing runs. Returns ms or None."""
        t0 = now()
        last = None
        while now() - t0 < timeout:
            try:
                st = c.call("status")
            except SessionError as e:
                return {"error": [e.code, str(e.message)[:100]]}
            names = [x.get("name") for x in st.get("clients", [])]
            sch = st.get("scheduler", {})
            busy = sum(sch.get(l, {}).get("inUse", 0) for l in ("quick", "long"))
            imp = st.get("imports", {}).get("running", [])
            last = {"victim_present": victim in names, "busy_slots": busy, "imports_running": len(imp)}
            if not last["victim_present"] and busy == 0 and not imp:
                return {"drain_ms": ms(t0), **last}
            time.sleep(0.05)
        return {"drain_ms": None, "timeout": True, **(last or {})}

    def scen_e(s, i, kind, delay):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        rec["kind"] = kind
        anomalies = []
        M, S = s.ctx["M_addrs"], s.ctx["S_addrs"]
        s.rig.watchdog(600)
        c, _ = s.rig.start("survivor", "c")
        ep = str(s.rig.state / "c.json")
        pf = d / "victim.progress"
        pf.write_text("")
        wlog = open(d / "victim.log", "wb")
        params = dict(endpoint=ep, kind=kind, progress=str(pf), canon_gpr=str(s.canon_gpr(d)), prog=s.prog, M=M, S=S,
                      fork_dir=str(d / "fork"), mode=s.fork_mode, dest_prefix=str(d / "fk"), exe=IMPORT_EXE,
                      client="victim", harness="claude-code")
        stop_b = threading.Event()
        b_lat = []
        b_thread = None
        o = c.call("open_project", path=str(s.canon_gpr(d)))
        if kind == "shared":
            f = c.call("fork_project", project=o["id"], path=str(d / "fork"), mode=s.fork_mode)
            fgpr = d / "fork" / s.b["gpr"]
            MA, MB = M[0::2], M[1::2]
            params.update(fork_gpr=str(fgpr), prefix="ca", M=MA)
        proc = subprocess.Popen([PY, "-I", WORKER, json.dumps(params)], stdout=wlog, stderr=wlog)
        if not s.wait_ready(pf, proc):
            rec["harness_error"] = "worker not ready"
            terminate(proc.pid, 10)
            s.emit(rec)
            return rec
        bst = {"gen": 0, "acked": 0, "err": None}
        if kind == "shared":
            def b_run():
                try:
                    cb = s.rig.daemon.connect("survivor-B", "codex")
                    ob = cb.call("open_project", path=str(fgpr), writable=True)
                    pb = cb.call("open_program", path=s.prog, project=ob["id"], writable=True, share=True)
                    kb = pb["key"]
                    g = 0
                    while not stop_b.is_set():
                        g += 1
                        t = now()
                        cb.call("edit", program=kb, ops=build_ops(MB, g, "cb"))
                        b_lat.append((t, now(), "edit"))
                        bst["gen"] = g
                        t = now()
                        cb.call("save", program=kb)
                        b_lat.append((t, now(), "save"))
                        bst["acked"] = g
                    # final save after the loop (covers the dead writer's committed edits)
                    cb.call("save", program=kb)
                    bst["final_save"] = True
                    cb.close()
                except Exception as e:  # noqa: BLE001
                    bst["err"] = repr(e)[:300]
            b_thread = threading.Thread(target=b_run, daemon=True)
            b_thread.start()
        sleep_precise(delay)
        st_before = None
        try:
            st_before = c.call("status")
            rec["victim_requests_at_kill"] = [{k: r.get(k) for k in ("cmd", "ms")} for cl in st_before.get("clients", []) if cl.get("name") == "victim" for r in cl.get("requests", [])]
        except SessionError:
            pass
        t_kill = now()
        kr = terminate(proc.pid, 30)
        rec["kill"] = kr
        pg0 = parse_progress(pf)
        # survivor responsiveness right after
        pings = []
        for _ in range(5):
            t = now()
            try:
                c.call("ping")
                pings.append(ms(t))
            except SessionError as e:
                pings.append("ERR:" + str(e.code))
        rec["survivor_ping_ms_after_kill"] = pings
        rec["daemon_alive_after_client_kill"] = s.rig.daemon.jvm_alive()
        rec["drain"] = s.drain_wait(c)
        prog = parse_progress(pf)
        rec["progress"] = prog
        if kind == "shared":
            time.sleep(2.0)
            stop_b.set()
            b_thread.join(60)
            rec["B"] = dict(bst)
            before = [(e - st) * 1000 for st, e, _ in b_lat if e < t_kill]
            after = [(e - st) * 1000 for st, e, _ in b_lat if st >= t_kill]
            straddle = [(e - st) * 1000 for st, e, _ in b_lat if st < t_kill <= e]
            rec["B_latency_ms"] = {"before_median": round(sorted(before)[len(before) // 2], 1) if before else None,
                                   "before_max": round(max(before), 1) if before else None,
                                   "after_max": round(max(after), 1) if after else None,
                                   "straddling_kill_max": round(max(straddle), 1) if straddle else None,
                                   "n_before": len(before), "n_after": len(after)}
            try:
                stx = c.call("status")
                rec["program_after"] = [{k: p.get(k) for k in ("mode", "writers", "owner", "unsavedEdits", "orphanedMs")} for p in stx.get("programs", []) if p.get("project") and p["path"] == s.prog and "fork" in str(p.get("project", ""))] or [{k: p.get(k) for k in ("mode", "writers", "owner", "unsavedEdits", "orphanedMs", "project")} for p in stx.get("programs", [])]
            except SessionError:
                pass
        # takeover: a second client can use what the dead client held?
        fdir = d / "fork"
        fgpr = fdir / s.b["gpr"]
        if kind == "owner":
            t = now()
            try:
                ow = c.call("open_project", path=str(fgpr), writable=True)
                pw = c.call("open_program", path=s.prog, project=ow["id"], writable=True)
                rec["takeover"] = {"ok": True, "ms": ms(t), "mode": pw.get("mode"), "unsaved": pw.get("changed")}
                sc = scan_program(c, pw["key"], M, [], deep=False)
                rec["takeover"]["state"] = sc["state"]
                c.call("close_program", program=pw["key"], discard=True)
            except SessionError as e:
                rec["takeover"] = {"ok": False, "code": e.code, "message": (e.message or "")[:240], "details": e.details}
        elif kind == "reader":
            try:
                p = c.call("open_program", path=s.prog, project=o["id"])
                d1 = c.call("decompile", program=p["key"], address=S[0])
                rec["takeover"] = {"ok": True, "decompiled": bool(d1.get("c"))}
            except SessionError as e:
                rec["takeover"] = {"ok": False, "code": e.code}
        c.close()
        rec["clean_stop"] = s.rig.stop()
        s.rig.cancel_watchdog()
        rec["lock_files_before_oracle"] = residue_tags(inventory(d))
        rec["jvm_tmp_files"] = s.tmp_files()
        # ---- on-disk oracle, fresh daemon
        targets = {"canon": (d / "canon", s.canon_gpr(d))}
        if kind in ("owner", "shared", "importer"):
            targets["fork"] = (fdir, fgpr)
        o2 = s.oracle(d, targets, deep=True)
        rec["restart_ms"] = o2["restart_ms"]
        rec["oracle_log"] = o2["log"]
        tf = o2["targets"].get("fork")
        canon_scan = main_scan(o2["targets"]["canon"].get("ro"), s.ctx)
        rec["canon_ro_mutated"] = o2["targets"]["canon"].get("ro_mutated_project")
        if kind == "owner":
            for mode in ("ro", "w"):
                sc = main_scan(tf.get(mode), s.ctx) if tf and tf.get(mode) else None
                if sc is None:
                    rec["disk_" + mode] = "NO_SCAN"
                    continue
                gens = sc["gens"]
                rec["disk_%s_gens" % mode] = gens
                if len(gens) == 1:
                    G = int(next(iter(gens)))
                    rec["disk_" + mode] = "gen:%d" % G
                    lo, hi = prog.get("save_ack", 0), prog.get("save_sent", 0)
                    rec["allowed_gen_range"] = [lo, hi]
                    if not (lo <= G <= hi):
                        anomalies.append("GEN_OUT_OF_RANGE_%s:%d not in [%d,%d]" % (mode, G, lo, hi))
                    if sc.get("name_in_c") != sc.get("n_sample"):
                        anomalies.append("NAME_NOT_IN_DECOMPILE_%s" % mode)
                else:
                    rec["disk_" + mode] = "MIXED"
                    anomalies.append("MIXED_GENS_" + mode)
        elif kind == "importer":
            for mode in ("ro", "w"):
                insp = tf.get(mode) if tf else None
                if not insp or "open_project_error" in (insp or {}):
                    rec["disk_" + mode] = "OPEN_ERROR"
                    anomalies.append("OPEN_ERROR_" + mode)
                    continue
                progs = insp.get("programs") or {}
                newp = [p for p in progs if p != s.prog]
                if not newp:
                    rec["disk_" + mode] = "NEW_ABSENT"
                else:
                    pr = progs[newp[0]]
                    rec["disk_" + mode] = "NEW_ANALYZED" if pr.get("analyzed") else "NEW_UNANALYZED"
                    rec["disk_%s_fn_count" % mode] = pr.get("fn_count")
                if not same(main_scan(insp, s.ctx), s.base_main):
                    anomalies.append("MAIN_CHANGED_" + mode)
        elif kind == "shared":
            for mode in ("ro", "w"):
                insp = tf.get(mode) if tf else None
                if not insp or "open_project_error" in (insp or {}):
                    anomalies.append("OPEN_ERROR_" + mode)
                    continue
            # custom scan: A (prefix ca) and B (cb) tags
            s.rig.watchdog(300)
            c2, _ = s.rig.start("oracle2", "c")
            o3 = c2.call("open_project", path=str(fgpr))
            p3 = c2.call("open_program", path=s.prog, project=o3["id"])
            fl = {x["address"]: x["name"] for x in all_functions(c2, p3["key"])}
            gA = Counter(parse_gen(fl.get(a, ""), "ca") for a in M[0::2])
            gB = Counter(parse_gen(fl.get(a, ""), "cb") for a in M[1::2])
            c2.close()
            s.rig.stop()
            s.rig.cancel_watchdog()
            rec["disk_A_gens"], rec["disk_B_gens"] = dict(gA), dict(gB)
            lo, hi = prog.get("edit_ack", 0), prog.get("edit_sent", 0)
            rec["A_allowed_range"] = [lo, hi]
            if len(gA) != 1:
                anomalies.append("A_MIXED")
            else:
                GA = next(iter(gA))
                if not (lo <= GA <= hi):
                    anomalies.append("A_GEN_OUT_OF_RANGE:%d not in [%d,%d]" % (GA, lo, hi))
            if len(gB) != 1 or next(iter(gB)) < bst.get("acked", 0):
                anomalies.append("B_LOSS_OR_MIXED")
            if bst.get("err"):
                anomalies.append("B_ERROR")
        elif kind == "forker":
            pass
        # forker: every fkN dir
        if kind == "forker":
            comp, tmpleft, partial = 0, [], []
            cth = _tree_rows(d / "canon")
            for dd in sorted(d.glob("fk*")):
                inv = inventory(dd)
                if any(".fork-" in k for k in inv):
                    tmpleft.append(dd.name)
                if (dd / s.b["gpr"]).exists() and (dd / s.b["gpr"].replace(".gpr", ".rep")).exists():
                    dth = {k: v for k, v in _tree_rows(dd).items() if not k.endswith(".fork.json") and not k.endswith((".lock", ".lock~"))}
                    if dth == cth:
                        comp += 1
                    else:
                        partial.append(dd.name)
                else:
                    partial.append(dd.name + ":no_gpr_rep") if inv else None
            rec["forks_complete"] = comp
            rec["forks_partial"] = partial
            rec["forks_tmp_left"] = tmpleft
            rec["fork_acked"] = prog.get("fork_ack", 0)
            if comp < prog.get("fork_ack", 0):
                anomalies.append("ACKED_FORK_MISSING")
            if partial:
                anomalies.append("PARTIAL_FORK_VISIBLE")
            if tmpleft:
                anomalies.append("FORK_TMP_LEFT_AFTER_CLIENT_KILL")
        rec["canon_scan_equals_baseline"] = same(canon_scan, s.base_main)
        if not rec["canon_scan_equals_baseline"]:
            anomalies.append("CANON_SCAN_DIFFERS")
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        if not rec["daemon_alive_after_client_kill"]:
            anomalies.append("DAEMON_DIED")
        if rec["drain"].get("timeout") or rec["drain"].get("drain_ms") is None:
            anomalies.append("DRAIN_TIMEOUT")
        if any(isinstance(p, str) for p in pings):
            anomalies.append("SURVIVOR_PING_ERR")
        if kind == "owner" and not (rec.get("takeover") or {}).get("ok"):
            anomalies.append("TAKEOVER_FAILED:" + str((rec.get("takeover") or {}).get("code")))
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec

    # ---------------------------------------------------------------- f
    def scen_f(s, i, delay):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        M, S = s.ctx["M_addrs"], s.ctx["S_addrs"]
        N = 8
        s.rig.watchdog(900)
        c0, _ = s.rig.start("coordinator", "c")
        st = [{"acked": 0, "save_sent": 0, "edit_sent": 0, "phase": "init", "err": None, "fork_ms": None} for _ in range(N)]
        barrier = threading.Barrier(N + 1, timeout=300)
        stop = threading.Event()

        def worker(k):
            try:
                ck = s.rig.daemon.connect("agent-%d" % k, HARNESSES[k % 4])
                o = ck.call("open_project", path=str(s.canon_gpr(d)))
                st[k]["phase"] = "fork"
                t = now()
                f = ck.call("fork_project", project=o["id"], path=str(d / ("fork%d" % k)), mode=s.fork_mode)
                st[k]["fork_ms"] = ms(t)
                p = ck.call("open_program", path=s.prog, project=f["project"], writable=True)
                key = p["key"]
                st[k]["phase"] = "ready"
                barrier.wait()
                g = 0
                while not stop.is_set():
                    g += 1
                    st[k]["phase"] = "edit"
                    ck.call("edit", program=key, ops=build_ops(M, g))
                    st[k]["edit_sent"] = g
                    st[k]["phase"] = "save"
                    st[k]["save_sent"] = g
                    ck.call("save", program=key)
                    st[k]["acked"] = g
                st[k]["phase"] = "stopped"
            except threading.BrokenBarrierError:
                st[k]["err"] = "barrier"
            except Exception as e:  # noqa: BLE001
                st[k]["err"] = repr(e)[:160]
        ths = [threading.Thread(target=worker, args=(k,), daemon=True) for k in range(N)]
        [t.start() for t in ths]
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            rec["harness_error"] = "setup barrier broke: " + json.dumps([x["err"] for x in st])
            s.rig.cancel_watchdog()
            pid = s.rig.pid()
            if pid:
                terminate(pid, 20)
            s.emit(rec)
            return rec
        t0 = now()
        sleep_precise(delay)
        phases = [x["phase"] for x in st]
        kr = s.rig.kill()
        rec["kill"] = kr
        rec["phases_at_kill"] = phases
        stop.set()
        [t.join(30) for t in ths]
        s.rig.cancel_watchdog()
        rec["clients"] = [{"acked": x["acked"], "save_sent": x["save_sent"], "edit_sent": x["edit_sent"], "err": x["err"], "fork_ms": x["fork_ms"]} for x in st]
        targets = {"canon": (d / "canon", s.canon_gpr(d))}
        for k in range(N):
            targets["fork%d" % k] = (d / ("fork%d" % k), d / ("fork%d" % k) / s.b["gpr"])
        inv_lock = {k: residue_tags(inventory(v[0])) for k, v in targets.items()}
        rec["lock_files_after_kill"] = {k: {t: len(v) for t, v in d_.items()} for k, d_ in inv_lock.items() if d_}
        o2 = s.oracle(d, targets, deep=True)
        rec["restart_ms"] = o2["restart_ms"]
        rec["oracle_log"] = o2["log"]
        rec["oracle_stop"] = o2["stop"]
        per = []
        for k in range(N):
            t = o2["targets"]["fork%d" % k]
            row = {"fork": k, "acked": st[k]["acked"], "save_sent": st[k]["save_sent"], "phase": phases[k]}
            for mode in ("ro", "w"):
                insp = t.get(mode)
                if not insp or "open_project_error" in insp:
                    row[mode] = "OPEN_ERROR"
                    anomalies.append("F%d_%s_OPEN_ERROR" % (k, mode))
                    continue
                sc = main_scan(insp, s.ctx)
                if sc is None:
                    row[mode] = "NO_SCAN"
                    anomalies.append("F%d_%s_NO_SCAN" % (k, mode))
                    continue
                gens = sc["gens"]
                if len(gens) != 1:
                    row[mode] = "MIXED:" + json.dumps(gens)
                    anomalies.append("F%d_%s_MIXED" % (k, mode))
                    continue
                G = int(next(iter(gens)))
                row[mode] = G
                if not (st[k]["acked"] <= G <= st[k]["save_sent"]):
                    anomalies.append("F%d_%s_GEN_%d_NOT_IN_[%d,%d]" % (k, mode, G, st[k]["acked"], st[k]["save_sent"]))
                if st[k]["acked"] > G:
                    anomalies.append("F%d_%s_LOSS_OF_ACKED" % (k, mode))
                if sc.get("name_in_c") != sc.get("n_sample"):
                    anomalies.append("F%d_%s_NAME_NOT_IN_DECOMPILE" % (k, mode))
            row["ro_mutated"] = t.get("ro_mutated_project")
            row["residue_final"] = {a: len(b) for a, b in t["residue_final"].items()}
            per.append(row)
        rec["forks"] = per
        canon_scan = main_scan(o2["targets"]["canon"].get("ro"), s.ctx)
        rec["canon_scan_equals_baseline"] = same(canon_scan, s.base_main)
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        rec["n_saves_inflight"] = sum(1 for p in phases if p == "save")
        rec["total_acked_saves"] = sum(x["acked"] for x in st)
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec

    # ---------------------------------------------------------------- f2: 4 forks x 2 shared writers each, daemon killed
    def scen_f2(s, i, delay):
        d, th0 = s.iter_dir(i)
        rec = s.base_rec(i, delay)
        anomalies = []
        M = s.ctx["M_addrs"]
        MA, MB = M[0::2], M[1::2]
        NF = 4
        s.rig.watchdog(900)
        c0, _ = s.rig.start("coordinator", "c")
        o = c0.call("open_project", path=str(s.canon_gpr(d)))
        fids = []
        for k in range(NF):
            f = c0.call("fork_project", project=o["id"], path=str(d / ("fork%d" % k)), mode=s.fork_mode)
            fids.append(f["project"])
        st = [{"edit_ack": 0, "edit_sent": 0, "save_sent": 0, "save_ack": 0, "phase": "init", "err": None} for _ in range(2 * NF)]
        barrier = threading.Barrier(2 * NF + 1, timeout=300)
        stop = threading.Event()

        def worker(w):
            k, side = divmod(w, 2)
            addrs, pre = (MA, "ca") if side == 0 else (MB, "cb")
            try:
                ck = s.rig.daemon.connect("agent-%d%s" % (k, "ab"[side]), HARNESSES[w % 4])
                gpr = d / ("fork%d" % k) / s.b["gpr"]
                ow = ck.call("open_project", path=str(gpr), writable=True)
                st[w]["busy_retries"] = 0
                while True:
                    try:
                        p = ck.call("open_program", path=s.prog, project=ow["id"], writable=True, share=True)
                        break
                    except SessionError as e:
                        if e.code != "busy" or st[w]["busy_retries"] > 100:
                            raise
                        st[w]["busy_retries"] += 1
                        time.sleep(0.1)
                key = p["key"]
                st[w]["phase"] = "ready"
                barrier.wait()
                g = 0
                while not stop.is_set():
                    g += 1
                    st[w]["phase"] = "edit"
                    st[w]["edit_sent"] = g
                    ck.call("edit", program=key, ops=build_ops(addrs, g, pre))
                    st[w]["edit_ack"] = g
                    st[w]["phase"] = "save"
                    st[w]["save_sent"] = g
                    ck.call("save", program=key)
                    st[w]["save_ack"] = g
                st[w]["phase"] = "stopped"
            except threading.BrokenBarrierError:
                st[w]["err"] = "barrier"
            except Exception as e:  # noqa: BLE001
                st[w]["err"] = repr(e)[:160]
        ths = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(2 * NF)]
        [t.start() for t in ths]
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            rec["harness_error"] = "setup barrier broke: " + json.dumps([x["err"] for x in st])
            s.rig.cancel_watchdog()
            pid = s.rig.pid()
            if pid:
                terminate(pid, 20)
            s.emit(rec)
            return rec
        sleep_precise(delay)
        phases = [x["phase"] for x in st]
        rec["kill"] = s.rig.kill()
        rec["phases_at_kill"] = phases
        stop.set()
        [t.join(30) for t in ths]
        s.rig.cancel_watchdog()
        rec["writers"] = [dict(x) for x in st]
        targets = {"canon": (d / "canon", s.canon_gpr(d))}
        o2 = s.oracle(d, targets, deep=True, do_w=False)
        rec["restart_ms"] = o2["restart_ms"]
        rec["oracle_log"] = o2["log"]
        # custom scan per fork: A tags (ca) over MA, B tags (cb) over MB
        s.rig.watchdog(600)
        c2, _ = s.rig.start("oracle2", "c")
        per = []
        for k in range(NF):
            gpr = d / ("fork%d" % k) / s.b["gpr"]
            row = {"fork": k}
            try:
                ow = c2.call("open_project", path=str(gpr), writable=True)
                pp = c2.call("open_program", path=s.prog, project=ow["id"], writable=False)
                fl = {x["address"]: x["name"] for x in all_functions(c2, pp["key"])}
                gA = Counter(parse_gen(fl.get(a, ""), "ca") for a in MA)
                gB = Counter(parse_gen(fl.get(a, ""), "cb") for a in MB)
                row["gA"], row["gB"] = dict(gA), dict(gB)
                for side, gc, nm in ((0, gA, "A"), (1, gB, "B")):
                    w = 2 * k + side
                    if len(gc) != 1:
                        anomalies.append("F2_%d%s_MIXED" % (k, nm))
                        continue
                    G = next(iter(gc))
                    lo, hi = st[w]["save_ack"], st[w]["edit_sent"]
                    if not (lo <= G <= hi):
                        anomalies.append("F2_%d%s_GEN_%d_NOT_IN_[%d,%d]" % (k, nm, G, lo, hi))
                    row[nm + "_range"] = [lo, hi]
            except SessionError as e:
                row["error"] = [e.code, (e.message or "")[:200]]
                anomalies.append("F2_%d_OPEN_ERROR" % k)
            per.append(row)
        c2.close()
        s.rig.stop()
        s.rig.cancel_watchdog()
        rec["forks"] = per
        canon_scan = main_scan(o2["targets"]["canon"].get("ro"), s.ctx)
        rec["canon_scan_equals_baseline"] = same(canon_scan, s.base_main)
        rec["canonical_unchanged"] = tree_hash(d / "canon")["tree_sha256"] == th0
        if not rec["canonical_unchanged"]:
            anomalies.append("CANONICAL_CHANGED")
        rec["anomalies"] = anomalies
        s.emit(rec)
        s.end_iter(d, anomalies)
        return rec


def main():
    scen, kind, proj, fs, n, seed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
    name_scen = scen if scen in ("f", "f2") else "e-" + kind
    s = RunEF(name_scen, proj, fs, n, seed)
    t_start = time.time()
    (s.out / "header.json").write_text(json.dumps({"scenario": name_scen, "proj": proj, "fs": fs, "n": n, "seed": seed, "start": time.strftime("%Y-%m-%d %H:%M:%S"),
                                                   "engine": INSTALL, "base_tree": s.base_tree, "data_root": str(s.data)}, indent=1))
    # pristine baseline of the original program (for CANON/MAIN checks)
    d, _ = s.iter_dir("calm")
    s.rig.watchdog(300)
    c, _ = s.rig.start("cal", "c")
    s.base_main = main_scan(inspect(c, s.canon_gpr(d), False, s.ctx), s.ctx)
    c.close()
    s.rig.stop()
    s.rig.cancel_watchdog()
    shutil.rmtree(d, ignore_errors=True)
    if scen == "e":
        window = s.window_e(kind)
    else:
        window = {"fixture": 8.0, "large": 14.0}[proj]
    for i in range(n):
        if scen in ("f", "f2"):
            delay = 1.0 + s.draw(window)  # after every client is in its edit/save loop
        else:
            delay = s.draw(window)
        t0 = time.time()
        try:
            rec = s.scen_e(i, kind, delay) if scen == "e" else (s.scen_f(i, delay) if scen == "f" else s.scen_f2(i, delay))
            print("%s it%03d delay=%.3f -> %s (%.0fs)" % (s.name, i, delay, rec.get("anomalies"), time.time() - t0), flush=True)
        except Exception:  # noqa: BLE001
            import traceback
            tb = traceback.format_exc()
            print("ITERATION FAILED", i, tb[-600:], flush=True)
            s.emit({"scenario": s.scen, "proj": proj, "fs": fs, "i": i, "seed": seed, "delay_s": delay, "harness_error": tb[-1500:]})
            pid = s.rig.pid()
            if pid:
                terminate(pid, 20)
    end_tree = tree_hash(s.b["base"])["tree_sha256"]
    (s.out / "footer.json").write_text(json.dumps({"base_tree_start": s.base_tree, "base_tree_end": end_tree, "base_unchanged": end_tree == s.base_tree,
                                                     "elapsed_s": round(time.time() - t_start, 1)}, indent=1))
    print("done", s.name, "base_unchanged", end_tree == s.base_tree, flush=True)


if __name__ == "__main__":
    main()
