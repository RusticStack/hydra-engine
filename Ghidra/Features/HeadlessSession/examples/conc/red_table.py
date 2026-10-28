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
"""The red table of PROTOCOL-3.md 9.12: every recorded defect, run again on the engine under test.

For each row a measurement script of this folder is run on a fresh state root of the engine named by
``--ghidra`` (hydra.3 or the extracted refactor build), its output is reduced to the few numbers the
design recorded, and the row is judged: ``RED`` when the defect reproduces within the accepted range,
``GREEN`` when the behaviour the design wants is there, ``NOT RUN`` when the row cannot run here (and why).
A row that does not reproduce is reported as it is; its range is never widened to fit.

    python red_table.py --ghidra <install> --work <dir> --project <game or other project .gpr> --program /x.exe \\
        --fixtures <dir with fx-x64-flow> --fixture-exe <small PE> [--tag run1] [--only BP3,BP7] [--crash-n 40]

``--project`` is a project folder this script only COPIES (the original is never opened); the recorded
numbers are from a 122 MB program of 8,966 functions, so a different program gives different absolute
times and the accepted ranges are those of the design, not tuned. Run it twice (``--tag run1``,
``--tag run2`` with the same ``--work`` is fine: tags separate every output) to see determinism.

Output: ``<work>/red-table<TAG>.json`` and a text table on stdout; the exit code is 0 when every row
ran (RED, GREEN or NOT RUN with a reason are all valid results of an honest run), 1 when a script failed
to produce output, 2 on a usage error.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
NL = chr(10)


# ---- metrics and judgements -------------------------------------------------------------------

def _first(items, pred):
    return next((x for x in items if pred(x)), None)


def m_bp3(d):
    out = {}
    for v in d:
        key = v["variant"][0]
        reads = [p for p in v["probes"] if p["op"] in ("C info", "C functions", "C decompile", "D open_program(join)")]
        ref = [p for p in reads if not p["ok"] and p["code"] == "busy"]
        ev = {k: val for e in v["events"] for k, val in e.items() if k != "t"}
        close = next((val for k, val in ev.items() if k.startswith("B close") or k.startswith("B disc")), None)
        out[key] = {"reads": len(reads), "refused": len(ref),
                    "first_refused_s": min((p["t"] for p in ref), default=None),
                    "last_refused_end_s": round(max((p["t"] + p["ms"] / 1000 for p in ref), default=0), 1) or None,
                    "leave_returned_ms": close[1] if close else None}
    return out


def j_bp3(m):
    a, b = m.get("a", {}), m.get("b", {})
    ok_a = a.get("refused", 0) >= 3 and 8.0 <= (a.get("last_refused_end_s") or 0) <= 12.6 and (a.get("leave_returned_ms") or 0) >= 9500
    ok_b = b.get("refused", 0) >= 6 and (b.get("last_refused_end_s") or 0) >= 18.0
    return ok_a and ok_b, f"a: {a.get('refused')} reader probes refused until {a.get('last_refused_end_s')} s, leave busy after {a.get('leave_returned_ms')} ms; " \
                          f"b (socket close): {b.get('refused')} refused until {b.get('last_refused_end_s')} s; c (wait 100 ms): {m.get('c', {}).get('refused')} refused"


def m_bp4(d):
    c = d["c_writer_behind_6s_read_8_readers_wait10s"]
    return {"reader_max_ms": c["readers"]["max"], "reader_busy": c["readers"]["busy"], "writer_comment_ms": c["writer"]["comment"][1]}


def j_bp4(m):
    return 3000 <= m["reader_max_ms"] <= 7000, f"the slowest reader waited {m['reader_max_ms']} ms behind one queued comment (writer {m['writer_comment_ms']} ms)"


def m_bp5(d):
    c = d["c_analyze_save_whoami"]
    return {"probes": c["reader_probes_during_analysis"], "refused": c["reader_refused_during_analysis"], "analyze_ms": c["analyze_ms"]}


def j_bp5(m):
    return m["probes"] >= 10 and m["refused"] == m["probes"], f"{m['refused']} of {m['probes']} reader probes refused during a {m['analyze_ms']} ms analysis"


def m_bp6(d):
    pr = d["a_owner_script_vs_reader"]
    during = [p for p in pr if p["t"] < 8.0]
    return {"probes_during_script": len(during), "refused": sum(1 for p in during if not p["ok"] and p["code"] == "busy")}


def j_bp6(m):
    return m["probes_during_script"] >= 3 and m["refused"] == m["probes_during_script"], f"{m['refused']} of {m['probes_during_script']} reader probes refused by an 8 s owner script"


def m_bp7(d):
    a = d["a_refresh_queued_behind_script"]
    end = a["refresh_result"][1] / 1000
    during = [p for p in a["probes"] if p["t"] + p["ms"] / 1000 < end + 0.3]
    return {"refresh_ms": a["refresh_result"][1], "probes": len(during), "refused": sum(1 for p in during if not p["ok"]),
            "other_program_refused": sum(1 for p in during if "OTHER" in p["op"] and not p["ok"]),
            "info_serial_ms": d["c_hol_one_connection"]["info_after_4s_script_serial_ms"],
            "info_parallel_ms": d["c_hol_one_connection"]["info_parallel_flag_ms"]}


def j_bp7(m):
    return (m["probes"] >= 6 and m["refused"] == m["probes"] and 9000 <= m["refresh_ms"] <= 11000), \
        f"{m['refused']} of {m['probes']} probes refused (other program: {m['other_program_refused']}) while a refresh was queued {m['refresh_ms']} ms"


def m_bp8(d):
    return {"unrelated_open_ms": d["V_open_unrelated_project_while_Q_waits"]["ms"], "ok": d["V_open_unrelated_project_while_Q_waits"]["ok"]}


def j_bp8(m):
    return 7000 <= m["unrelated_open_ms"] <= 10500, f"open_project of an UNRELATED project took {m['unrelated_open_ms']} ms"


def m_bp9(d):
    pr = d["a_victim_probes"]
    return {"quick_in_use": d["a_quick_lane_during"]["inUse"], "quick_slots": d["a_quick_lane_during"]["slots"],
            "victim_probes": len(pr), "victim_busy": sum(1 for p in pr if not p["ok"] and p["code"] == "busy"),
            "long_lane_full_busy": sum(1 for p in d["b_victim_cmds_while_long_lane_full"] if not p["ok"] and p["code"] == "busy")}


def j_bp9(m):
    return (m["quick_in_use"] == m["quick_slots"] and m["victim_probes"] >= 6 and m["victim_busy"] == m["victim_probes"]), \
        f"{m['quick_in_use']} of {m['quick_slots']} quick slots held by waiters; a client on another project busy {m['victim_busy']} of {m['victim_probes']}; long lane full: {m['long_lane_full_busy']} commands busy"


def m_bp10(d):
    s = next(x for x in d["steps"] if x["step"] == "probe_while_6_holders_12s")
    return {k: s[k] for k in ("decompile_ms", "functions_ms", "rename_ms", "tiny_script_ms", "save_ms", "fork_ms")}


def j_bp10(m):
    slow = [m[k] for k in ("tiny_script_ms", "save_ms", "fork_ms")]
    return all(9500 <= x <= 12500 for x in slow) and m["decompile_ms"] < 500, \
        f"script/save/fork waited {slow} ms behind six long scripts; decompile {m['decompile_ms']} ms"


def m_bp11(d):
    b = d["b_dead_waiter"]
    pr = b["probes"]
    ref = [p for p in pr if not p["ok"] and p["code"] == "busy"]
    return {"readers_busy": len(ref), "probes": len(pr), "first_busy_s": min((p["t"] for p in ref), default=None),
            "last_busy_end_s": round(max((p["t"] + p["ms"] / 1000 for p in ref), default=0), 1),
            "dead_client_write_applied": "DEAD CLIENT WRITE" in str(b.get("journal_after"))}


def j_bp11(m):
    return (m["readers_busy"] >= 5 and m["dead_client_write_applied"]), \
        f"readers busy {m['readers_busy']} of {m['probes']} probes (to {m['last_busy_end_s']} s); the write of the dead client was applied: {m['dead_client_write_applied']}"


def m_bp13(d):
    a = d["a_deaf_script"]
    return {"response_after_s": a["response_arrived_after_s"], "script_s": a["script_duration_s"], "timeout_s": a["timeout_param_s"],
            "long_slot_held_after_cancel": a["long_lane_after_cancel_and_timeout_flag"]["inUse"]}


def j_bp13(m):
    return (12 <= m["response_after_s"] <= 22 and m["long_slot_held_after_cancel"] >= 1), \
        f"a deaf script with a {m['timeout_s']} s timeout answered after {m['response_after_s']} s (it runs {m['script_s']} s); long slot held after cancel: {m['long_slot_held_after_cancel']}"


def m_bp14(d):
    during = d["a_dirty_visibility"]["during"]
    return {"polls": len(during), "polls_seeing_uncommitted_rename": sum(1 for p in during if p["hits"])}


def j_bp14(m):
    return m["polls"] >= 5 and m["polls_seeing_uncommitted_rename"] >= m["polls"] // 2, \
        f"{m['polls_seeing_uncommitted_rename']} of {m['polls']} polls by another client saw a contained script's uncommitted rename"


def m_crash_poison(res):
    return res


def j_crash_poison(m):
    return m["corrupt"] >= 1, f"{m['corrupt']} of {m['unanswered_kills']} unanswered trigger-timed kills (of {m['records']} iterations) left a zero-header newest version file"


def j_crash_fork(m):
    return m["partial_dest_visible"] >= 1, \
        f"{m['partial_dest_visible']} of {m['records']} kills during fork_project left a partial destination (.rep without .gpr: {m['rep_only']}, complete without sidecar: {m['no_sidecar']}); orphan staging folders {m['orphan_tmp']}"


# ---- the rows -------------------------------------------------------------------------------------

#: id, script, extra args, output json (relative to --work, without the tag), metrics, judge, recorded text
LOCKMAP = [
    ("BP3", "s1_xqueue.py", "s1_xqueue", m_bp3, j_bp3,
     "readers and joins refused 2.5-12.0 s behind one 20 s read; on a socket close until the read ended (20.1 s)"),
    ("BP4", "s2_writer.py", "s2_writer", m_bp4, j_bp4, "a comment queued behind a 6 s read stalled every reader up to 5,131 ms"),
    ("BP6", "s4_dead.py", "s4_dead", m_bp6, j_bp6, "an 8 s owner script refused 4 of 4 reader probes"),
    ("BP11", "s4_dead.py", "s4_dead", m_bp11, j_bp11, "readers busy 3.8-15.8 s; journal seq 1 written by the dead client"),
    ("BP7", "s7_project.py", "s7_project", m_bp7, j_bp7, "all 9 probes (other program and list included) refused 10 s; one connection is serial: info behind a 4 s script took 3.85 s, 1.1 ms with parallel:true"),
    ("BP14", "s9_script_db.py", "s9_script_db", m_bp14, j_bp14, "the rename was visible to another client in 94 of 114 polls"),
    ("BP13", "s10_misc.py", "s10_misc", m_bp13, j_bp13, "a deaf script ran to its end 22 s after cancel; the timeout answered 16.7 s late"),
    ("BP5", "s10_misc.py", "s10_misc", m_bp5, j_bp5, "analyze holds the program exclusive 19.8-162.8 s: 28 of 28 probes refused"),
    ("BP8", "s13_registry.py", "s13_registry", m_bp8, j_bp8, "an unrelated project's open_project took 9,421 ms"),
    ("BP9", "s5_lanes.py", "s5_lanes", m_bp9, j_bp9, "24 waiters took 24 of 24 quick slots; a client on another project was busy 6 of 6"),
]
#: scripts run once and shared by several rows, in the order the files depend on one another (s6 makes the project s7 and s10 copy)
ORDER = ["s6_import.py", "s1_xqueue.py", "s2_writer.py", "s4_dead.py", "s7_project.py", "s9_script_db.py", "s10_misc.py",
         "s13_registry.py", "s5_lanes.py"]
REGRESSION_ONLY = ["s8_overlay.py", "s11_storm.py", "s12_instances.py", "t3_scaling.py"]
RECORDED = {"BP10": "script, save and fork waited 10.2-10.5 s behind six long scripts; decompile 9-15 ms",
            "C-poison": "version-file poison: 12 of 363 kills (7 of 95 NTFS trigger-timed; fixture trigger-timed 4 of 51)",
            "C-fork": "fork_project kills: 12 of 162 left a partial destination (8 of 112 on NTFS); 4 had .rep without .gpr (not reproduced in review, D41)",
            "HL-no_project": "Hydralysis no_project error with 4 threads (A hl_multi.py; one reproduction)"}


def run(cmd, log, env=None, timeout=3600):
    t = time.time()
    with open(log, "ab") as f:
        f.write(("\n$ " + " ".join(cmd) + "\n").encode())
        f.flush()
        try:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, timeout=timeout, stdin=subprocess.DEVNULL)
            code = p.returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
    return {"exit": code, "seconds": round(time.time() - t, 1)}


def stop_daemons(support, work, tag):
    """Stops the daemons this run started (their state roots are under <work>/state)."""
    sys.path.insert(0, support)
    import ghidra_session as gs
    stopped = []
    st = pathlib.Path(work) / "state"
    if not st.is_dir():
        return stopped
    for d in st.iterdir():
        for inst_root in (d, d / "state"):
            for ep in inst_root.glob("*.json"):
                if ep.name == "config.json":
                    continue
                try:
                    dm = gs.Daemon(None, str(inst_root), ep.stem)
                    if dm.jvm_alive():
                        dm.stop(force=True, timeout=60)
                        stopped.append(str(ep))
                except Exception as e:  # noqa: BLE001
                    stopped.append(f"{ep}: {e}")
    return stopped


def merge(paths, out):
    """``--merge A.json B.json ... --out report.md``: one table, a row per defect, the recorded numbers and the verdict
    and note of every report given (engine and tag in the column heads), plus whether the verdicts agree between the
    runs of one engine (the determinism the gate asks for)."""
    reps = [json.loads(pathlib.Path(p).read_text(encoding="utf-8")) for p in paths]
    heads = [f"{pathlib.Path(r['engine']).name if pathlib.Path(r['engine']).name != 'ghidra_12.3_DEV' else pathlib.Path(r['engine']).parent.parent.name} {r['tag'] or '-'}" for r in reps]
    rows = []
    for rep in reps:
        for r in rep["results"]:
            if r["row"] not in [x[0] for x in rows]:
                rows.append((r["row"], r["recorded"]))
    lines = ["| row | recorded | " + " | ".join(heads) + " | verdicts agree per engine |", "|---|---|" + "---|" * (len(heads) + 1)]
    for rid, recorded in rows:
        cells, byeng = [], {}
        for rep, h in zip(reps, heads):
            r = next((x for x in rep["results"] if x["row"] == rid), None)
            cells.append(f"**{r['verdict']}** {r.get('note', '')}".replace("|", "/") if r else "-")
            if r:
                byeng.setdefault(rep["engine"], set()).add(r["verdict"])
        agree = "yes" if all(len(v) == 1 for v in byeng.values()) else "NO: " + "; ".join(f"{pathlib.Path(k).name}: {sorted(v)}" for k, v in byeng.items() if len(v) > 1)
        lines.append(f"| {rid} | {recorded} | " + " | ".join(cells) + f" | {agree} |")
    pathlib.Path(out).write_text(NL.join(lines) + NL, encoding="utf-8")
    print(NL.join(lines))


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--merge":
        i = sys.argv.index("--out")
        merge(sys.argv[2:i], sys.argv[i + 1])
        return
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--project", required=True, help="the .gpr of a project to copy for the scenarios")
    ap.add_argument("--program", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--fixture-exe", required=True)
    ap.add_argument("--tmpdir")
    ap.add_argument("--tag", default="")
    ap.add_argument("--only", help="comma-separated row ids (BP3,BP7,...,BP10,C-poison,C-fork,HL-no_project, regression)")
    ap.add_argument("--crash-n", type=int, default=40, help="unanswered kills of the poison scenario (default 40)")
    ap.add_argument("--fork-n", type=int, default=30, help="kills of the fork scenario (default 30)")
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--java-home")
    ap.add_argument("--addr-base")
    ap.add_argument("--no-crash", action="store_true")
    a = ap.parse_args()
    work = pathlib.Path(a.work).absolute()
    work.mkdir(parents=True, exist_ok=True)
    logs = work / "logs"
    logs.mkdir(exist_ok=True)
    support = str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support")
    only = set(x for x in (a.only or "").split(",") if x)

    def want(row):
        return not only or row in only
    notag = ["--ghidra", a.ghidra, "--work", str(work), "--project", a.project, "--program", a.program,
             "--fixtures", a.fixtures, "--fixture-exe", a.fixture_exe]
    if a.tmpdir:
        notag += ["--tmpdir", a.tmpdir]
    if a.java_home:
        notag += ["--java-home", a.java_home]
    if a.addr_base:
        notag += ["--addr-base", a.addr_base]
    common = notag + ["--tag", a.tag]
    py = [sys.executable, "-I"]
    results, runs, failed = [], {}, False
    t_all = time.time()
    # the base project (an upgraded, saved copy of --project); made once per work folder
    base = work / "proj" / "base"
    if not base.is_dir():
        runs["mkbase"] = run(py + [str(HERE / "mkbase.py")] + notag, logs / "mkbase.log")   # untagged: the base is shared by every tag
        stop_daemons(support, work, a.tag)
    needed = {r[1] for r in LOCKMAP if want(r[0])}
    if "s6_import.py" not in needed and ({"s7_project.py", "s10_misc.py"} & needed):
        needed.add("s6_import.py")
    if not only or "regression" in only:
        needed |= set(REGRESSION_ONLY)
    for script in ORDER + REGRESSION_ONLY:
        if script not in needed:
            continue
        runs[script] = run(py + [str(HERE / script)] + common, logs / (script[:-3] + a.tag + ".log"))
        runs[script]["stopped"] = stop_daemons(support, work, a.tag)
    if want("BP10"):
        runs["lanetest.py"] = run(py + [str(HERE / "lanetest.py")] + common + ["def" + a.tag, "0"], logs / ("lanetest" + a.tag + ".log"))
        runs["lanetest.py"]["stopped"] = stop_daemons(support, work, a.tag)
    # judge the lock map rows
    for rid, script, outname, metrics, judge, recorded in LOCKMAP:
        if not want(rid):
            continue
        out = work / (outname + a.tag + ".json")
        rec = {"row": rid, "script": script, "recorded": recorded}
        if not out.exists():
            rec.update(verdict="NO OUTPUT", note=f"{out.name} was not written (exit {runs.get(script, {}).get('exit')}); see {logs}")
            failed = True
        else:
            try:
                m = metrics(json.loads(out.read_text(encoding="utf-8")))
                red, note = judge(m)
                rec.update(verdict="RED" if red else "NOT REPRODUCED", metrics=m, note=note)
            except Exception as e:  # noqa: BLE001
                rec.update(verdict="NO OUTPUT", note=f"could not read {out.name}: {type(e).__name__}: {e}")
                failed = True
        results.append(rec)
    if want("BP10"):
        out = work / "out" / ("lane-def" + a.tag + ".json")
        rec = {"row": "BP10", "script": "lanetest.py", "recorded": RECORDED["BP10"]}
        try:
            m = m_bp10(json.loads(out.read_text(encoding="utf-8")))
            red, note = j_bp10(m)
            rec.update(verdict="RED" if red else "NOT REPRODUCED", metrics=m, note=note)
        except Exception as e:  # noqa: BLE001
            rec.update(verdict="NO OUTPUT", note=f"could not read {out}: {type(e).__name__}: {e}")
            failed = True
        results.append(rec)
    # the crash scenarios (the fixture project; each scenario starts and stops its own daemons)
    if not a.no_crash and (want("C-poison") or want("C-fork")):
        env = dict(os.environ)
        runs["c_sample"] = run(py + [str(HERE / "c_sample.py"), "fixture"] + common, logs / ("c_sample" + a.tag + ".log"), env)
        if want("C-poison"):
            e = dict(env, TRIG="1", RUN_TAG="red" + a.tag)
            runs["run_c a"] = run(py + [str(HERE / "run_c.py"), "a", "fixture", "ntfs", str(a.crash_n), str(a.seed)] + common,
                                  logs / ("run_c_a" + a.tag + ".log"), e, timeout=4 * 3600)
            res = work / "run" / ("a-fixture-ntfs-red" + a.tag) / "results.jsonl"
            rows = [json.loads(x) for x in res.read_text().splitlines() if x.strip()] if res.exists() else []
            rows = [r for r in rows if "anomalies" in r]
            m = {"records": len(rows), "unanswered_kills": sum(1 for r in rows if not r.get("acked_before_kill")),
                 "corrupt": sum(1 for r in rows if "CORRUPT_OR_UNOPENABLE" in r.get("anomalies", [])),
                 "trigger_hits": sum(1 for r in rows if r.get("trigger_hit")),
                 "canonical_changed": sum(1 for r in rows if "CANONICAL_CHANGED" in r.get("anomalies", []))}
            red, note = j_crash_poison(m) if rows else (False, "no results.jsonl")
            results.append({"row": "C-poison", "script": "run_c.py a (TRIG=1)", "recorded": RECORDED["C-poison"],
                            "verdict": ("RED" if red else "NOT REPRODUCED") if rows else "NO OUTPUT", "metrics": m, "note": note})
            failed |= not rows
        if want("C-fork"):
            e = dict(env, RUN_TAG="red" + a.tag)
            runs["run_c b"] = run(py + [str(HERE / "run_c.py"), "b", "fixture", "ntfs", str(a.fork_n), str(a.seed + 2)] + common,
                                  logs / ("run_c_b" + a.tag + ".log"), e, timeout=3 * 3600)
            res = work / "run" / ("b-fixture-ntfs-red" + a.tag) / "results.jsonl"
            rows = [json.loads(x) for x in res.read_text().splitlines() if x.strip()] if res.exists() else []
            rows = [r for r in rows if "anomalies" in r]
            m = {"records": len(rows),
                 "partial_dest_visible": sum(1 for r in rows if any(x.startswith("PARTIAL_DEST_VISIBLE") for x in r["anomalies"])),
                 "rep_only": sum(1 for r in rows if r.get("dest_state") == "rep_only_NO_GPR"),
                 "no_sidecar": sum(1 for r in rows if r.get("dest_state") == "complete_NO_SIDECAR"),
                 "orphan_tmp": sum(1 for r in rows if "ORPHAN_TMP_LEFT" in r["anomalies"]),
                 "retry_blocked": sum(1 for r in rows if "RETRY_BLOCKED" in r["anomalies"])}
            red, note = j_crash_fork(m) if rows else (False, "no results.jsonl")
            results.append({"row": "C-fork", "script": "run_c.py b", "recorded": RECORDED["C-fork"],
                            "verdict": ("RED" if red else "NOT REPRODUCED") if rows else "NO OUTPUT", "metrics": m, "note": note})
            failed |= not rows
        stop_daemons(support, work, a.tag)
    if want("HL-no_project"):
        results.append({"row": "HL-no_project", "script": "hl_multi.py (measurement A)", "recorded": RECORDED["HL-no_project"],
                        "verdict": "NOT RUN", "note": "the scenario drives Hydralysis (src/hydralysis) with a program executable; it is not part of the engine repository "
                                                       "and belongs to the Hydralysis stream (Z1, known-issue until Y2)"})
    for s in ("s8_overlay.py", "s11_storm.py", "s12_instances.py", "t3_scaling.py"):
        if s in runs:
            results.append({"row": s[:-3] + " (regression only)", "script": s, "recorded": "no red criterion (BP17/BP18/BP2/BP1 controls)",
                            "verdict": "RAN" if runs[s]["exit"] == 0 else "FAILED", "note": f"exit {runs[s]['exit']} in {runs[s]['seconds']} s"})
            failed |= runs[s]["exit"] != 0
    report = {"engine": a.ghidra, "tag": a.tag, "project_copy_of": a.project, "program": a.program, "runs": runs, "results": results,
              "seconds": round(time.time() - t_all, 1)}
    (work / f"red-table{a.tag}.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print(f"engine {a.ghidra}  tag {a.tag!r}  {report['seconds']} s")
    for r in results:
        print(f"{r['verdict']:14s} {r['row']:22s} {r.get('note', '')}")
        print(f"{'':14s} {'':22s} recorded: {r['recorded']}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
