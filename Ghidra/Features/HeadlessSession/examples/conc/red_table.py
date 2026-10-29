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
        --fixtures <dir with fx-x64-flow> --fixture-exe <small PE> [--tag run1] [--only BP3,BP7] [--crash-n 40] [--serial]

``--project`` is a project folder this script only COPIES (the original is never opened); the recorded
numbers are from a 122 MB program of 8,966 functions, so a different program gives different absolute
times and the accepted ranges are those of the design, not tuned. Run it twice (``--tag run1``,
``--tag run2`` with the same ``--work`` is fine: tags separate every output) to see determinism.

By default the scripts run at once (``--jobs``, s1 and s4 split in their parts, the poison scenario in
``--crash-shards`` and the fork scenario in ``--fork-shards`` shards whose kill counts add up to
``--crash-n``/``--fork-n``; the shards' results.jsonl are merged before the rows are judged), and the s6 project
(which has no row; s7 and s10 copy it) and the crash sample come from a content-keyed cache (``--cache``, default
``<work>/cache``) when the engine, the project and the scripts are the same. The crash shards start after the
lock-map scripts: with 16 shards at once an iteration took 20 s instead of 6-7 s, the calibrated fork window grew
from 0.2 s to 0.6-0.9 s and the outcome mix changed (no partial destination left, complete destinations that differ
from the canonical one instead), so the shards are few (3 and 2), and the first shard of a scenario calibrates once
for all of them (the others wait for its calibration and use it; ``--own-calibration`` makes each calibrate under
its own load, as before). ``--shard-cores N`` pins each crash shard to N logical processors of its own (its daemons
inherit the mask); it is off by default: pinned to 2, the crash phase took 921 s instead of about 350 s (one run
on a shared machine; C-fork RED with 55 records, the verdicts otherwise those of the unpinned runs).
``--crash-overlap`` is only for a quick look, and ``--fast`` runs the lock-map and regression scripts only (the
counted crash rows are NOT RUN; not for a release). ``--serial`` is the original one-at-a-time order with none of
this (it reproduces the recorded numbers); the rows and their ranges are the same in every mode.

Output: ``<work>/red-table<TAG>.json`` and a text table on stdout; the exit code is 0 when every row
ran (RED, GREEN or NOT RUN with a reason are all valid results of an honest run), 1 when a script failed
to produce output, 2 on a usage error.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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


#: parallel mode: the scripts split into independent parts (``--parts``, one process per part, outputs merged); every part
#: has its own state root and project copy, so the parts run at once and the merged output is the serial one
PARTS = {"s1_xqueue.py": "abc", "s4_dead.py": "abc"}
#: the state roots (without the tag) each script makes under <work>/state, per part: a parallel run stops only these
STATES = {"s6_import.py": ["s6"], "s1_xqueue.py": {"a": ["s1a_close_wait10s"], "b": ["s1b_disconnect"], "c": ["s1c_close_wait100ms"]},
          "s2_writer.py": ["s2"], "s4_dead.py": {"a": ["s3a"], "b": ["s4b"], "c": ["s4c"]}, "s7_project.py": ["s7"],
          "s9_script_db.py": ["s9"], "s10_misc.py": ["s10"], "s13_registry.py": ["s13"], "s5_lanes.py": ["s5"],
          "s8_overlay.py": ["s8", "s8b"], "s11_storm.py": ["s11"], "s12_instances.py": ["s12"], "t3_scaling.py": ["t3"]}
#: scripts that copy the project another script leaves behind
DEPENDS = {"s7_project.py": "s6_import.py", "s10_misc.py": "s6_import.py"}
#: longest first, so the pool ends together (seconds of the serial record of int-V3, E: drive)
COST = {"s6_import.py": 175, "s1_xqueue.py": 79, "s4_dead.py": 65, "s2_writer.py": 38, "s5_lanes.py": 29, "s7_project.py": 29,
        "s10_misc.py": 29, "s11_storm.py": 28, "lanetest.py": 21, "s9_script_db.py": 19, "s8_overlay.py": 18, "s13_registry.py": 17,
        "t3_scaling.py": 16, "s12_instances.py": 7}


def set_affinity(proc, mask):
    """Pins a just-started process to the logical processors of ``mask`` (Windows; its children, the daemons it starts
    with a direct spawn, inherit the mask). Returns False when it could not."""
    if not mask or os.name != "nt":
        return False
    import ctypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    return bool(k.SetProcessAffinityMask(ctypes.c_void_p(int(proc._handle)), mask))


def cpu_masks(total, per, k):
    """``k`` disjoint masks of ``per`` logical processors from the top of ``total`` down (processor 0 and its sibling,
    where the system and the harness are, are the last ones handed out), and the mask of what is left."""
    masks = []
    hi = total
    for _ in range(k):
        lo = hi - per
        if lo < 0:
            break
        masks.append(((1 << per) - 1) << lo)
        hi = lo
    rest = (1 << hi) - 1 if hi > 0 else 0
    return masks, rest


def _wait_file(path, timeout, stop):
    """Until ``path`` exists, ``stop`` is set or ``timeout`` s passed; True when the file is there."""
    end = time.time() + timeout
    while not path.exists() and not stop.is_set() and time.time() < end:
        time.sleep(0.2)
    return path.exists()


#: parallel defaults, chosen by measurement (see the docstring)
CRASH_SHARDS, FORK_SHARDS, SHARD_CORES = 3, 2, 0


def run(cmd, log, env=None, timeout=3600, mask=None):
    t = time.time()
    with open(log, "ab") as f:
        f.write(("\n$ " + " ".join(cmd) + (f"   [affinity {mask:#x}]" if mask else "") + "\n").encode())
        f.flush()
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, stdin=subprocess.DEVNULL)
        pinned = set_affinity(p, mask) if mask else None
        try:
            code = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            code = "timeout"
    r = {"exit": code, "seconds": round(time.time() - t, 1)}
    if mask:
        r["affinity"] = hex(mask) if pinned else f"{mask:#x} NOT SET"
    return r


def stop_daemons(support, work, tag, names=None):
    """Stops the daemons this run started (their state roots are under <work>/state); with ``names`` only the daemons of
    those state-root folders (a parallel run must not stop the daemons of the scripts still running)."""
    sys.path.insert(0, support)
    import ghidra_session as gs
    stopped = []
    st = pathlib.Path(work) / "state"
    if not st.is_dir():
        return stopped
    for d in st.iterdir():
        if names is not None and d.name not in names:
            continue
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


def state_names(script, part, tag):
    s = STATES.get(script, [])
    if isinstance(s, dict):
        s = [n for p, ns in s.items() if part is None or p == part for n in ns]
    return {n + tag for n in s}


def merge_parts(outs, dst):
    """The output of a script run in parts: lists are concatenated in part order, dicts merged. Nothing is written when
    a part wrote no output (the row is then NO OUTPUT, as a failed serial run would be)."""
    if not all(o.exists() for o in outs):
        return False
    data = [json.loads(o.read_text(encoding="utf-8")) for o in outs]
    if all(isinstance(d, list) for d in data):
        merged = [x for d in data for x in d]
    else:
        merged = {}
        for d in data:
            merged.update(d)
    dst.write_text(json.dumps(merged, indent=1, default=str), encoding="utf-8")
    return True


def split_n(n, k):
    """``n`` kills over ``k`` shards: the shard counts add up to ``n`` exactly (empty shards dropped)."""
    k = max(1, min(k, n)) if n > 0 else 1
    return [c for c in (n // k + (1 if j < n % k else 0) for j in range(k)) if c > 0]


def merge_shards(shard_dirs, dst):
    """Concatenates the results.jsonl of the shards into ``dst/results.jsonl`` (every record keeps its seed and i)."""
    lines, info = [], []
    for sd in shard_dirs:
        f = sd / "results.jsonl"
        rows = [x for x in f.read_text(encoding="utf-8").splitlines() if x.strip()] if f.exists() else []
        cal = sd / "calibration.json"
        info.append({"shard": sd.name, "records": len(rows),
                     "window_s": json.loads(cal.read_text(encoding="utf-8")).get("window_s") if cal.exists() else None})
        lines += rows
    if dst not in shard_dirs:
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True)
        (dst / "results.jsonl").write_text("".join(x + NL for x in lines), encoding="utf-8")
        (dst / "shards.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
    return info


def wilson(k, n, z=1.96):
    """95 % Wilson score interval of k successes in n trials (informational; the verdicts use the counts)."""
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return [round(max(0.0, mid - half), 4), round(min(1.0, mid + half), 4)]


def tree_sig(root, pattern="*"):
    """(relpath, size, mtime) of the files under ``root`` matching ``pattern``: what a cache key needs of a folder that is
    never written (an engine install, the --project original, a fixture)."""
    root = pathlib.Path(root)
    rows = []
    for p in sorted(root.rglob(pattern)):
        if p.is_file():
            s = p.stat()
            rows.append(f"{p.relative_to(root).as_posix()}\t{s.st_size}\t{s.st_mtime_ns}")
    return NL.join(rows)


def file_sig(paths):
    h = hashlib.sha256()
    for p in paths:
        p = pathlib.Path(p)
        h.update(str(p.name).encode())
        h.update(p.read_bytes() if p.is_file() else b"<missing>")
    return h.hexdigest()


def cache_key(*parts):
    return hashlib.sha256(NL.join(str(x) for x in parts).encode()).hexdigest()[:24]


def cache_put(src, entry):
    """Stores the folder ``src`` as the cache entry ``entry``: copied next to it, then renamed (a reader sees a whole
    entry or none; a concurrent writer of the same key loses the rename and drops its copy)."""
    entry.parent.mkdir(parents=True, exist_ok=True)
    tmp = entry.parent / f".tmp-{entry.name}-{os.getpid()}-{threading.get_ident()}"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    if src.is_dir():
        shutil.copytree(src, tmp)
    else:
        tmp.mkdir()
        shutil.copy2(src, tmp / src.name)
    try:
        os.replace(tmp, entry)
    except OSError:
        shutil.rmtree(tmp, ignore_errors=True)


def judge_rows(work, tag, runs, want, crash):
    """The rows of the report from the outputs in ``work`` (same for the serial and the parallel run)."""
    results, failed = [], False
    logs = work / "logs"
    for rid, script, outname, metrics, judge, recorded in LOCKMAP:
        if not want(rid):
            continue
        out = work / (outname + tag + ".json")
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
        out = work / "out" / ("lane-def" + tag + ".json")
        rec = {"row": "BP10", "script": "lanetest.py", "recorded": RECORDED["BP10"]}
        try:
            m = m_bp10(json.loads(out.read_text(encoding="utf-8")))
            red, note = j_bp10(m)
            rec.update(verdict="RED" if red else "NOT REPRODUCED", metrics=m, note=note)
        except Exception as e:  # noqa: BLE001
            rec.update(verdict="NO OUTPUT", note=f"could not read {out}: {type(e).__name__}: {e}")
            failed = True
        results.append(rec)
    if crash:
        if want("C-poison"):
            res = work / "run" / ("a-fixture-ntfs-red" + tag) / "results.jsonl"
            rows = [json.loads(x) for x in res.read_text().splitlines() if x.strip()] if res.exists() else []
            rows = [r for r in rows if "anomalies" in r]
            m = {"records": len(rows), "unanswered_kills": sum(1 for r in rows if not r.get("acked_before_kill")),
                 "corrupt": sum(1 for r in rows if "CORRUPT_OR_UNOPENABLE" in r.get("anomalies", [])),
                 "trigger_hits": sum(1 for r in rows if r.get("trigger_hit")),
                 "canonical_changed": sum(1 for r in rows if "CANONICAL_CHANGED" in r.get("anomalies", []))}
            m["corrupt_wilson95"] = wilson(m["corrupt"], m["unanswered_kills"])
            red, note = j_crash_poison(m) if rows else (False, "no results.jsonl")
            results.append({"row": "C-poison", "script": "run_c.py a (TRIG=1)", "recorded": RECORDED["C-poison"],
                            "verdict": ("RED" if red else "NOT REPRODUCED") if rows else "NO OUTPUT", "metrics": m, "note": note})
            failed |= not rows
        if want("C-fork"):
            res = work / "run" / ("b-fixture-ntfs-red" + tag) / "results.jsonl"
            rows = [json.loads(x) for x in res.read_text().splitlines() if x.strip()] if res.exists() else []
            rows = [r for r in rows if "anomalies" in r]
            m = {"records": len(rows),
                 "partial_dest_visible": sum(1 for r in rows if any(x.startswith("PARTIAL_DEST_VISIBLE") for x in r["anomalies"])),
                 "rep_only": sum(1 for r in rows if r.get("dest_state") == "rep_only_NO_GPR"),
                 "no_sidecar": sum(1 for r in rows if r.get("dest_state") == "complete_NO_SIDECAR"),
                 "orphan_tmp": sum(1 for r in rows if "ORPHAN_TMP_LEFT" in r["anomalies"]),
                 "retry_blocked": sum(1 for r in rows if "RETRY_BLOCKED" in r["anomalies"])}
            m["partial_wilson95"] = wilson(m["partial_dest_visible"], m["records"])
            red, note = j_crash_fork(m) if rows else (False, "no results.jsonl")
            results.append({"row": "C-fork", "script": "run_c.py b", "recorded": RECORDED["C-fork"],
                            "verdict": ("RED" if red else "NOT REPRODUCED") if rows else "NO OUTPUT", "metrics": m, "note": note})
            failed |= not rows
    if want("HL-no_project"):
        results.append({"row": "HL-no_project", "script": "hl_multi.py (measurement A)", "recorded": RECORDED["HL-no_project"],
                        "verdict": "NOT RUN", "note": "the scenario drives Hydralysis (src/hydralysis) with a program executable; it is not part of the engine repository "
                                                       "and belongs to the Hydralysis stream (Z1, known-issue until Y2)"})
    for s in REGRESSION_ONLY:
        if s in runs:
            results.append({"row": s[:-3] + " (regression only)", "script": s, "recorded": "no red criterion (BP17/BP18/BP2/BP1 controls)",
                            "verdict": "RAN" if runs[s]["exit"] == 0 else "FAILED", "note": f"exit {runs[s]['exit']} in {runs[s]['seconds']} s"})
            failed |= runs[s]["exit"] != 0
    return results, failed


def needed_scripts(want, only):
    needed = {r[1] for r in LOCKMAP if want(r[0])}
    if "s6_import.py" not in needed and ({"s7_project.py", "s10_misc.py"} & needed):
        needed.add("s6_import.py")
    if not only or "regression" in only:
        needed |= set(REGRESSION_ONLY)
    return [s for s in ORDER + REGRESSION_ONLY if s in needed]


def run_serial(ctx):
    """The original order, one script at a time (``--serial``: reproduces the recorded numbers)."""
    a, work, logs, py, common, support, runs = ctx["a"], ctx["work"], ctx["logs"], ctx["py"], ctx["common"], ctx["support"], ctx["runs"]
    t0 = time.time()
    for script in ctx["scripts"]:
        runs[script] = run(py + [str(HERE / script)] + common, logs / (script[:-3] + a.tag + ".log"))
        runs[script]["stopped"] = stop_daemons(support, work, a.tag)
    if ctx["want"]("BP10"):
        runs["lanetest.py"] = run(py + [str(HERE / "lanetest.py")] + common + ["def" + a.tag, "0"], logs / ("lanetest" + a.tag + ".log"))
        runs["lanetest.py"]["stopped"] = stop_daemons(support, work, a.tag)
    ctx["phases"]["lock"] = round(time.time() - t0, 1)
    if ctx["crash"]:
        t0 = time.time()
        env = dict(os.environ)
        runs["c_sample"] = run(py + [str(HERE / "c_sample.py"), "fixture"] + common, logs / ("c_sample" + a.tag + ".log"), env)
        if ctx["want"]("C-poison"):
            e = dict(env, TRIG="1", RUN_TAG="red" + a.tag)
            runs["run_c a"] = run(py + [str(HERE / "run_c.py"), "a", "fixture", "ntfs", str(a.crash_n), str(a.seed)] + common,
                                  logs / ("run_c_a" + a.tag + ".log"), e, timeout=4 * 3600)
        if ctx["want"]("C-fork"):
            e = dict(env, RUN_TAG="red" + a.tag)
            runs["run_c b"] = run(py + [str(HERE / "run_c.py"), "b", "fixture", "ntfs", str(a.fork_n), str(a.seed + 2)] + common,
                                  logs / ("run_c_b" + a.tag + ".log"), e, timeout=3 * 3600)
        stop_daemons(support, work, a.tag)
        ctx["phases"]["crash"] = round(time.time() - t0, 1)


def run_parallel(ctx):
    """Independent scripts at once: a pool of ``--jobs`` for the lock-map and regression scripts (s1/s4 in parts), the
    crash scenarios in ``--crash-shards`` shards each (own seed and run folder; results merged, same N). s7 and s10 wait
    for the s6 project (or take it from the cache); the crash shards wait for the sample file of c_sample."""
    a, work, logs, py, notag, support, runs = ctx["a"], ctx["work"], ctx["logs"], ctx["py"], ctx["notag"], ctx["support"], ctx["runs"]
    lock = threading.Lock()
    cache = pathlib.Path(a.cache).absolute() if a.cache else work / "cache"
    engine_sig = hashlib.sha256((tree_sig(pathlib.Path(a.ghidra) / "Ghidra", "*.jar") + tree_sig(pathlib.Path(a.ghidra) / "Ghidra", "application.properties")).encode()).hexdigest()
    sysdir = pathlib.Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"
    imports = [sysdir / (n + ".exe") for n in ("notepad", "whoami", "ipconfig", "find", "hostname", "netstat", "tasklist")]

    def script_task(script, part=None, extra=()):
        tg = a.tag + ("-p" + part if part else "")
        cmd = py + [str(HERE / script)] + notag + ["--tag", tg] + (["--parts", part] if part else []) + list(extra)
        r = run(cmd, logs / (script[:-3] + tg + ".log"), mask=ctx["lock_mask"])
        r["stopped"] = stop_daemons(support, work, a.tag, state_names(script, part, tg))
        return r

    def whole_script(script):
        if script not in PARTS:
            return script_task(script)
        t = time.time()
        with ThreadPoolExecutor(len(PARTS[script])) as ex:
            rs = dict(zip(PARTS[script], ex.map(lambda p: script_task(script, p), PARTS[script])))
        outs = [work / f"{script[:-3]}{a.tag}-p{p}.json" for p in PARTS[script]]
        merged = merge_parts(outs, work / f"{script[:-3]}{a.tag}.json")
        bad = [r["exit"] for r in rs.values() if r["exit"] != 0]
        return {"exit": bad[0] if bad else 0, "seconds": round(time.time() - t, 1), "parts": rs, "merged": merged}

    s6_done = threading.Event()

    def s6_task():
        try:
            key = cache_key("s6", engine_sig, tree_sig(pathlib.Path(a.project).parent), a.program,
                            file_sig([HERE / "s6_import.py", HERE / "xc.py", HERE / "mkbase.py"] + imports))
            entry = cache / ("s6-" + key)
            dst = work / "proj" / ("s6" + a.tag)
            if not a.no_cache and entry.is_dir():
                t = time.time()
                if dst.exists():
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(entry, dst)
                return {"exit": 0, "seconds": round(time.time() - t, 1), "cached": str(entry),
                        "note": "s6 has no row; its project (base + notepad, analyzed, + six imports) came from the cache"}
            r = script_task("s6_import.py")
            out = work / f"s6_import{a.tag}.json"
            try:
                o = json.loads(out.read_text(encoding="utf-8"))
                good = r["exit"] == 0 and (o.get("a_import_analyze") or {}).get("ok") and all(x.get("ok") for x in o.get("b_six_imports", []))
            except Exception:  # noqa: BLE001
                good = False
            if good and not a.no_cache:
                cache_put(dst, entry)
                r["cache_stored"] = str(entry)
            return r
        finally:
            s6_done.set()

    def dependent(script):
        s6_done.wait()
        return whole_script(script)

    sample_done = threading.Event()

    def sample_task():
        try:
            fix = pathlib.Path(a.fixtures) / "fx-x64-flow"
            key = cache_key("sample", engine_sig, tree_sig(fix), file_sig([HERE / "c_sample.py", HERE / "c_lib.py"]),
                            os.environ.get("X0_FIXTURE_PROGRAM", ""))
            entry = cache / ("sample-" + key)
            dst = work / "sample-fixture.json"
            if not a.no_cache and (entry / dst.name).is_file():
                shutil.copy2(entry / dst.name, dst)
                return {"exit": 0, "seconds": 0.0, "cached": str(entry)}
            if dst.exists():
                dst.unlink()
            r = run(py + [str(HERE / "c_sample.py"), "fixture"] + ctx["common"], logs / ("c_sample" + a.tag + ".log"), dict(os.environ))
            if r["exit"] == 0 and dst.is_file() and not a.no_cache:
                cache_put(dst, entry)
                r["cache_stored"] = str(entry)
            return r
        finally:
            sample_done.set()

    cal_done = {}       # scenario -> Event: its first shard has written the shared calibration (or ended)

    def shard_task(scen, j, k, n, seed, mask=None):
        sample_done.wait()
        rt = "red" + a.tag + (f"-k{j}" if k > 1 else "")
        env = dict(os.environ, RUN_TAG=rt)
        if scen == "a":
            env["TRIG"] = "1"
        cal = work / "run" / f"{scen}-fixture-ntfs-red{a.tag}-calibration.json"
        shared = None
        if k > 1 and not a.own_calibration:
            if j == 0:
                if cal.exists():
                    cal.unlink()
                env["CALIB_OUT"] = str(cal)
                watch = threading.Thread(target=lambda: (_wait_file(cal, 4 * 3600, cal_done[scen]), cal_done[scen].set()), daemon=True)
                watch.start()
            else:
                cal_done[scen].wait()
                if cal.exists():
                    env["CALIB_IN"] = shared = str(cal)
        r = run(py + [str(HERE / "run_c.py"), scen, "fixture", "ntfs", str(n), str(seed)] + ctx["common"],
                logs / (f"run_c_{scen}{a.tag}" + (f"-k{j}" if k > 1 else "") + ".log"), env, timeout=4 * 3600, mask=mask)
        if j == 0 and scen in cal_done:
            cal_done[scen].set()           # also when it ended without a calibration: the others then make their own
        r.update(n=n, seed=seed, run_tag=rt, calibration=("shared " + shared) if shared else ("written for the others" if j == 0 and k > 1 and not a.own_calibration else "own"))
        return r

    t_start = time.time()
    lock_jobs, crash_jobs = [], []
    lock_ex = ThreadPoolExecutor(max(1, a.jobs))
    crash_ex = ThreadPoolExecutor(max(1, a.crash_jobs)) if ctx["crash"] else None
    phase_end = {}

    def timed_job(phase, name, fn, *args):
        def w():
            r = fn(*args)
            with lock:
                runs[name] = r
                phase_end[phase] = time.time()
            return r
        return w

    scripts = list(ctx["scripts"])
    if ctx["want"]("BP10"):
        scripts.append("lanetest.py")
    if "s6_import.py" not in scripts:
        s6_done.set()
    for script in sorted(scripts, key=lambda s: -COST.get(s, 30)):
        if script == "s6_import.py":
            fn = timed_job("lock", script, s6_task)
        elif script == "lanetest.py":
            fn = timed_job("lock", script, script_task, script, None, ("def" + a.tag, "0"))
        elif script in DEPENDS:
            fn = timed_job("lock", script, dependent, script)
        else:
            fn = timed_job("lock", script, whole_script, script)
        lock_jobs.append(lock_ex.submit(fn))
    if ctx["crash"]:
        if not a.crash_overlap:
            [f.result() for f in lock_jobs]
        t_crash = time.time()
        crash_jobs.append(crash_ex.submit(timed_job("crash", "c_sample", sample_task)))
        plan = []
        if ctx["want"]("C-poison"):
            plan.append(("a", a.crash_n, a.seed, a.crash_shards))
        if ctx["want"]("C-fork"):
            plan.append(("b", a.fork_n, a.seed + 2, a.fork_shards or a.crash_shards))
        shards = {}
        splits = [(scen, n, seed, split_n(n, k)) for scen, n, seed, k in plan]
        masks = ctx["masks"]
        m = 0
        for scen, n, seed, ns in splits:
            shards[scen] = ns
            cal_done[scen] = threading.Event()
            for j, nj in enumerate(ns):
                mask = masks[m] if m < len(masks) else None
                m += 1
                # shard 0 keeps the seed of the serial run; the others draw their delays from their own stream
                crash_jobs.append(crash_ex.submit(timed_job("crash", f"run_c {scen}" + (f" k{j}" if len(ns) > 1 else ""),
                                                            shard_task, scen, j, len(ns), nj, seed + 7919 * j, mask)))
    [f.result() for f in lock_jobs]
    lock_ex.shutdown()
    ctx["phases"]["lock"] = round(phase_end.get("lock", time.time()) - t_start, 1)
    if ctx["crash"]:
        [f.result() for f in crash_jobs]
        crash_ex.shutdown()
        for scen, ns in shards.items():
            name = f"{scen}-fixture-ntfs-red{a.tag}"
            dirs = [work / "run" / (name + (f"-k{j}" if len(ns) > 1 else "")) for j in range(len(ns))]
            runs[f"run_c {scen} shards"] = {"n": ns, "merged": merge_shards(dirs, work / "run" / name)}
        stop_daemons(support, work, a.tag)
        ctx["phases"]["crash"] = round(phase_end.get("crash", time.time()) - t_crash, 1)
    runs["final_stop"] = stop_daemons(support, work, a.tag)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) > 1 and argv[0] == "--merge":
        i = argv.index("--out")
        merge(argv[1:i], argv[i + 1])
        return 0
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
    ap.add_argument("--serial", action="store_true", help="one script at a time in the original order, no cache, no shards")
    ap.add_argument("--jobs", type=int, default=6, help="parallel: lock-map/regression scripts at once (default 6; s1/s4 parts inside)")
    ap.add_argument("--crash-shards", type=int, default=CRASH_SHARDS, help=f"parallel: shards of the poison scenario (default {CRASH_SHARDS}; the kill counts add up to --crash-n)")
    ap.add_argument("--fork-shards", type=int, default=FORK_SHARDS, help=f"parallel: shards of the fork scenario (default {FORK_SHARDS}; the kill counts add up to --fork-n)")
    ap.add_argument("--crash-jobs", type=int, default=0, help="parallel: crash shards at once (default: every shard of both scenarios)")
    ap.add_argument("--shard-cores", type=int, default=SHARD_CORES, help=f"parallel: logical processors each crash shard is pinned to (default {SHARD_CORES}; "
                                                                    "0: no pinning). The shards get disjoint sets from the top; the lock-map scripts the rest when they overlap")
    ap.add_argument("--own-calibration", dest="own_calibration", action="store_true",
                    help="parallel: every crash shard calibrates its own window (default: the first shard of a scenario calibrates, the others take its window and baselines)")
    ap.add_argument("--fast", action="store_true", help="the lock-map and regression scripts only: the counted crash rows are NOT RUN (use the full mode for a release or a nightly)")
    ap.add_argument("--crash-overlap", action="store_true", help="parallel: run the crash shards together with the lock-map scripts (default: after them; "
                                                                  "the kill timing is load-sensitive, see the docstring)")
    ap.add_argument("--cache", help="parallel: cache folder of the s6 project and the crash sample (default <work>/cache; keep it on an SSD)")
    ap.add_argument("--no-cache", action="store_true", help="parallel: run s6 and c_sample even when the cache has their result")
    a = ap.parse_args(argv)
    if a.fast:
        a.no_crash = True
    if not a.crash_jobs:
        a.crash_jobs = 1 + max(1, a.crash_shards) + max(1, a.fork_shards or a.crash_shards)
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
    runs, phases = {}, {}
    t_all = time.time()
    # the base project (an upgraded, saved copy of --project); made once per work folder
    base = work / "proj" / "base"
    if not base.is_dir():
        t0 = time.time()
        runs["mkbase"] = run(py + [str(HERE / "mkbase.py")] + notag, logs / "mkbase.log")   # untagged: the base is shared by every tag
        stop_daemons(support, work, a.tag)
        phases["mkbase"] = round(time.time() - t0, 1)
    crash = not a.no_crash and (want("C-poison") or want("C-fork"))
    n_shards = (max(1, a.crash_shards) if want("C-poison") else 0) + (max(1, a.fork_shards or a.crash_shards) if want("C-fork") else 0)
    masks, rest = cpu_masks(os.cpu_count() or 1, a.shard_cores, n_shards) if crash and a.shard_cores > 0 and not a.serial else ([], 0)
    if crash and a.shard_cores > 0 and len(masks) < n_shards and not a.serial:
        print(f"only {len(masks)} of {n_shards} crash shards can have {a.shard_cores} processors of their own; the others are not pinned", flush=True)
    lock_mask = rest if (a.crash_overlap and masks and rest) else None
    ctx = {"a": a, "work": work, "logs": logs, "py": py, "notag": notag, "common": common, "support": support, "runs": runs,
           "phases": phases, "want": want, "crash": crash, "scripts": needed_scripts(want, only), "masks": masks, "lock_mask": lock_mask}
    (run_serial if a.serial else run_parallel)(ctx)
    results, failed = judge_rows(work, a.tag, runs, want, crash)
    if a.fast:
        for row in ("C-poison", "C-fork"):
            if want(row):
                results.append({"row": row, "script": "run_c.py", "recorded": RECORDED[row], "verdict": "NOT RUN",
                                "note": "--fast: the counted crash scenarios run only in the full mode (release, nightly)"})
    report = {"engine": a.ghidra, "tag": a.tag, "project_copy_of": a.project, "program": a.program,
              "mode": "serial" if a.serial else {"parallel": True, "fast": a.fast, "jobs": a.jobs, "crash_shards": a.crash_shards,
                                                  "fork_shards": a.fork_shards or a.crash_shards, "shard_cores": a.shard_cores,
                                                  "crash_masks": [hex(x) for x in masks], "lock_mask": hex(lock_mask) if lock_mask else None,
                                                  "shared_calibration": not a.own_calibration,
                                                  "crash_jobs": a.crash_jobs, "crash_overlap": a.crash_overlap, "cache": not a.no_cache},
              "phases": phases, "runs": runs, "results": results, "seconds": round(time.time() - t_all, 1)}
    (work / f"red-table{a.tag}.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print(f"engine {a.ghidra}  tag {a.tag!r}  {report['seconds']} s  phases {phases}")
    for r in results:
        print(f"{r['verdict']:14s} {r['row']:22s} {r.get('note', '')}")
        print(f"{'':14s} {'':22s} recorded: {r['recorded']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
