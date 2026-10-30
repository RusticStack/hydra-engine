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
"""The chaos and soak gate runner of the protocol 3 design (PROTOCOL-3.md 9.17, package E6).

Agents (client processes with distinct labels) work on forks of read-only master projects while a
supervisor injects faults from outside (no test code in the engine, D22) and judges the run with the
corruption oracle K1-K17 of X0 (``oracle.py``, ``chaos_lib.py``). The ground truth is a ledger that
each agent flushes and fsyncs itself (``oracle.Ledger``); the verdict never relies on what the engine
says about itself.

    python soak_tests.py run --ghidra <install> --work <dir> --project <analysed .gpr> --program /x.exe \\
        --profile smoke|pr|nightly|release [--seed N] [--evidence <dir>] [--plant K2,K6,...]
    python soak_tests.py selftest            # offline: the verdict logic and the planted violations, no engine

Profiles (9.17): ``pr`` 4 agents x 2 projects, 10 minutes; ``nightly`` 16 x 4, 2 hours, at least 150
kills; ``release`` 24 x 6, at least 4 hours (the three green nightly runs on NTFS and the one on ReFS are
separate invocations; for the latter ``--master-root`` puts the masters and the agents' trees, so the saves and
fork publishes, on the ReFS volume and deletes them at the end). A run that shrinks a profile with
``--agents``, ``--projects``, ``--duration-s`` or ``--ops`` is not a gate run: its verdict is capped at
``SMOKE-OK`` and the override is named in the gaps. ``smoke`` is
for proving the runner: it never yields ``PASS`` and its numbers are not gate numbers.

The verdict is one of ``PASS`` (a gate profile, nothing violated, every required fault class fired its
minimum count, every check the profile needs was run), ``SMOKE-OK`` (the same for ``smoke``), ``FAIL``
(an oracle violation or another broken pass criterion) and ``INCOMPLETE`` (nothing was violated, but a
fault class fired less than its minimum, a feature or check this engine does not have yet could not be
run, or the run was cut short: **never** reported as a pass). Exit codes: 0 PASS or SMOKE-OK, 1 FAIL, 3
INCOMPLETE, 2 usage error. Every gap is listed by name in the evidence (``gaps``), so a run that needs the
packages that landed later (health, script worker, views, publish) says so instead of passing quietly.

Workload per agent (engine level): reads (decompile, functions), edits with a unique tag per generation
and saves, quick scripts, long cooperative scripts, cancels, forks, bulk opens and, rarely, deaf and
runaway scripts. The Hydralysis-side workload (publish, rebase, analysis in a candidate, Hydralysis
queries) and the faults that need it (kill of a publish leader, the 100-view probe) are run by the VF
integration check; here they are listed as ``unavailable``.

Faults, each with a minimum count per profile (``MIN_FAULTS``; the spec fixes only "at least 150 kills"
for the nightly lane, the per-class split is this runner's choice and is recorded in the evidence):
kill -9 of a random client, of the daemon at a random time and trigger-timed (the method that found the
corruption), of a native decompiler; suspend of the daemon and of a client; a client that stops reading
its socket; a handle holder during saves. The combined check of E2 and E3a (a backup started while the
long lane is saturated runs in the ``maint`` lane) is a scheduled scenario.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

import oracle  # noqa: E402

# ------------------------------------------------------------------------------ profiles

#: agents, projects, duration (s), whether numbers from it may be quoted as gate numbers
PROFILES = {
    "smoke": dict(agents=3, projects=2, duration_s=240, gate=False, watcher_s=0.05, round_s=45),
    "pr": dict(agents=4, projects=2, duration_s=600, gate=True, watcher_s=0.05, round_s=60),
    "nightly": dict(agents=16, projects=4, duration_s=7200, gate=True, watcher_s=0.1, round_s=120),
    "release": dict(agents=24, projects=6, duration_s=14400, gate=True, watcher_s=0.1, round_s=180),
}

#: fault classes, in the order of the spec (9.17); ``needs`` names what must be present to run one
FAULT_CLASSES = ["kill_client", "kill_daemon_random", "kill_daemon_trigger", "kill_decompiler",
                 "suspend_daemon", "suspend_client", "stalled_reader", "handle_holder",
                 "kill_publish_leader", "oom_probe_100_views"]
#: classes that count as a "kill" for the nightly "at least 150 kills"
KILL_CLASSES = ["kill_client", "kill_daemon_random", "kill_daemon_trigger", "kill_decompiler"]
#: minimum number of hits per class and profile: a class below its minimum makes the run INCOMPLETE
MIN_FAULTS = {
    "smoke": dict(kill_client=2, kill_daemon_random=1, kill_daemon_trigger=1, kill_decompiler=1,
                  suspend_daemon=1, suspend_client=1, stalled_reader=1, handle_holder=1, backup_lane=1),
    "pr": dict(kill_client=8, kill_daemon_random=2, kill_daemon_trigger=2, kill_decompiler=4,
               suspend_daemon=2, suspend_client=2, stalled_reader=2, handle_holder=2, backup_lane=1),
    "nightly": dict(kill_client=100, kill_daemon_random=15, kill_daemon_trigger=15, kill_decompiler=30,
                    suspend_daemon=12, suspend_client=12, stalled_reader=8, handle_holder=10, backup_lane=4),
    "release": dict(kill_client=250, kill_daemon_random=40, kill_daemon_trigger=40, kill_decompiler=80,
                    suspend_daemon=30, suspend_client=30, stalled_reader=20, handle_holder=24, backup_lane=8),
}
#: what the engine-level runner cannot do and the packages that provide it (listed, never faked)
UNAVAILABLE_FAULTS = {
    "kill_publish_leader": "a publish leader is a Hydralysis process (Y3 publish queue); run by the VF integration check",
    "oom_probe_100_views": "needs views and maxViews (E4/E9 governor with Hydralysis views); run by the VF integration check",
}
UNAVAILABLE_WORKLOAD = {
    "publish": "Hydralysis publish (Y3); VF integration check",
    "rebase": "Hydralysis rebase (Y3); VF integration check",
    "candidate_analysis": "analysis in a candidate (Hydralysis); VF integration check",
    "hydralysis_queries": "Hydralysis queries; VF integration check",
}
#: oracle checks that need views, lineage stores or sealed generations (Hydralysis publish) and so cannot run here
UNEXERCISED_CHECKS = {
    "K1": "no sealed generation exists at engine level",
    "K8": "needs the op-log store of views",
    "K11p": "needs two sub-agents in one MCP server process (Hydralysis)",
    "K12": "needs CURRENT.log lineage (publish)",
    "K15": "needs a view rebuilt from base + store",
    "K16": "needs the changeset fold of published views",
    "K17": "needs the sealed record store of views",
}

# ------------------------------------------------------------------------------ small helpers


def load_gs(ghidra: str):
    sup = str(pathlib.Path(ghidra) / "Ghidra" / "Features" / "HeadlessSession" / "support")
    if sup not in sys.path:
        sys.path.insert(0, sup)
    import ghidra_session as gs  # noqa: PLC0415
    return gs


def rmtree(path, tries: int = 4):
    """``shutil.rmtree`` that clears read-only attributes and retries (Windows)."""
    path = pathlib.Path(path)

    def onerr(func, p, _exc):
        with contextlib.suppress(OSError):
            os.chmod(p, 0o700)
            func(p)
    for i in range(tries):
        if not path.exists():
            return True
        shutil.rmtree(path, onerror=onerr)
        if not path.exists():
            return True
        time.sleep(0.5 * (i + 1))
    return not path.exists()


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return round(xs[f] + (xs[c] - xs[f]) * (k - f), 1)


def now_s() -> float:
    return time.time()


def sha_of_file(path) -> str | None:
    with contextlib.suppress(OSError):
        return oracle.sha256_file(path)
    return None


def git_head(path) -> str | None:
    with contextlib.suppress(Exception):
        return subprocess.run(["git", "-C", str(path), "rev-parse", "--short=10", "HEAD"], capture_output=True,
                              text=True, timeout=20).stdout.strip() or None
    return None


# ------------------------------------------------------------------------------ the scripts the agents run

SCRIPTS = {
    "SoakQuick": """// @category Soak
import ghidra.app.script.GhidraScript;
public class SoakQuick extends GhidraScript {
    @Override protected void run() throws Exception {
        if (currentProgram == null) { println("no program"); return; }
        println("functions " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
""",
    "SoakSleep": """// @category Soak
import ghidra.app.script.GhidraScript;
public class SoakSleep extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("slept");
    }
}
""",
    # deaf: sleeps and swallows the interrupt, never looks at the monitor (the BP13 shape, bounded)
    "SoakDeaf": """// @category Soak
import ghidra.app.script.GhidraScript;
public class SoakDeaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try { Thread.sleep(50); } catch (InterruptedException e) { /* ignored on purpose */ }
        }
        println("deaf done");
    }
}
""",
    # runaway: burns a core and never looks at the monitor (bounded)
    "SoakBurn": """// @category Soak
import ghidra.app.script.GhidraScript;
public class SoakBurn extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        long x = 1;
        while (System.currentTimeMillis() < end) { x = x * 31 + 7; }
        println("burn done " + x);
    }
}
""",
}

#: which workload operations an agent can run at engine level, with their lane (for the latency table)
OPS = {
    "read": "quick", "edit_save": "edit", "quick_script": "quick", "long_script": "long", "cancel": "long",
    "fork": "maint", "bulk_open": "quick", "deaf": "long", "burn": "long",
}
OP_WEIGHTS = {"read": 30, "edit_save": 24, "quick_script": 9, "long_script": 9, "cancel": 6, "fork": 6,
              "bulk_open": 5, "deaf": 1, "burn": 1}
BUSY_EXPLAINERS = ("reason", "holder", "lane", "queue", "queued", "wanted", "resource", "slots", "running",
                   "readers", "heldMs", "waitedMs")
TAG_RX = re.compile(r"^sk(\d\d)x(\d+)_(\d+)$")
EXIT_CONN_LOST = 75
EXIT_FORK_BAD = 76


def tag_prefix(idx: int) -> str:
    return f"sk{idx:02d}x"


# ================================================================================ the agent process

class ConnLost(Exception):
    pass


def agent_main(spec_path: str) -> int:
    """One agent: its own process and connection, a fork of its project, mixed work, a ledger."""
    spec = json.loads(pathlib.Path(spec_path).read_text(encoding="utf-8"))
    gs = load_gs(spec["ghidra"])
    idx = spec["index"]
    adir = pathlib.Path(spec["dir"])
    rng = random.Random(spec["seed"])
    led = oracle.Ledger(adir / "ledger.jsonl")
    res = open(adir / "results.jsonl", "a", encoding="utf-8", buffering=1)
    label = spec["label"]
    prog = spec["program"]
    stop_file = pathlib.Path(spec["stop_file"])
    deadline = spec["deadline"]
    caps = spec.get("caps", {})
    scripts = spec["scripts"]
    pfx = tag_prefix(idx)

    def row(op, lane, t0, ok, code=None, details=None, **extra):
        rec = {"t": round(time.time(), 3), "agent": idx, "op": op, "lane": lane,
               "ms": round((time.perf_counter() - t0) * 1000, 1), "ok": ok}
        if code:
            rec["code"] = code
        if details:
            rec["details"] = details
        rec.update(extra)
        res.write(json.dumps(rec, default=str) + "\n")

    d = gs.Daemon(spec["ghidra"], spec["state"], spec["instance"])
    try:
        s = d.connect(label, "soak", start=False, timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"agent {idx}: cannot connect: {e!r}", flush=True)
        return EXIT_CONN_LOST

    def call(op, lane_, cmd, expect=(), **fields):
        t0 = time.perf_counter()
        try:
            r = s.call(cmd, **fields)
            row(op, lane_, t0, True)
            return r
        except gs.SessionError as e:
            if e.code in ("closed",):
                row(op, lane_, t0, False, "closed")
                raise ConnLost() from e
            row(op, lane_, t0, False, e.code, (e.details if e.code == "busy" else None) or None,
                expected=e.code in expect, message=(e.message or "")[:200])
            if e.code in expect:
                return None
            raise
        except (OSError, EOFError) as e:
            row(op, lane_, t0, False, "conn:" + type(e).__name__)
            raise ConnLost() from e

    try:
        # ---- setup: the master read-only, my fork writable
        master = call("setup_open_master", "quick", "open_project", path=spec["master"])
        fork_dir = adir / "fork"
        fork_gpr = None
        if fork_dir.is_dir() and list(fork_dir.glob("*.gpr")):
            fork_gpr = next(fork_dir.glob("*.gpr"))
        if fork_gpr is not None:
            o = call("setup_open_fork", "quick", "open_project", path=str(fork_gpr), writable=True)
            pid = o["id"]
        else:
            if fork_dir.exists():
                rmtree(fork_dir)
            f = call("setup_fork", "maint", "fork_project", project=master["id"], path=str(fork_dir), mode="auto",
                     writable=True)
            pid = f["project"]
        p = call("setup_open_program", "quick", "open_program", path=prog, project=pid, writable=True)
        key = p["key"]
        meta_path = adir / "meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        else:
            fl = []
            while True:
                r = call("setup_functions", "quick", "functions", program=key, offset=len(fl), limit=10000)
                fl += r["functions"]
                if not r.get("truncated"):
                    break
            addrs = sorted(f["address"] for f in fl if not f.get("external") and not f.get("thunk"))
            m = min(spec["edit_m"], max(2, len(addrs) // max(1, spec["agents"])))
            start = (idx * m) % max(1, len(addrs) - m)
            meta = {"addrs": addrs[start:start + m], "prefix": pfx, "functions": len(fl)}
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
        recs = oracle.Ledger.read(adir / "ledger.jsonl")
        gen = max([r.get("gen", 0) for r in recs if r.get("kind") in ("edit", "save")] or [0])
        fork_n = max([r.get("n", 0) for r in recs if r.get("kind") == "fork"] or [0])
        # the generation THIS incarnation has edited and not yet saved. An agent that was killed (or whose daemon
        # was) loses its unsaved edit: the ledger's last acknowledged edit is not in the re-opened program, so a
        # respawned agent must not "save generation g" for an edit it never made (found in the review: save 39 was
        # acknowledged after a respawn with only generation 38 on disk, a false K4/K5 violation)
        pending = None
        fk_dir = adir / "fk"
        fk_dir.mkdir(exist_ok=True)
        funcs = None

        def pick_func():
            nonlocal funcs
            if funcs is None:
                funcs = call("functions_list", "quick", "functions", program=key, offset=0, limit=2000)["functions"]
            return rng.choice(funcs)["address"]

        # ---- the operations
        def op_read():
            if rng.random() < 0.7:
                call("read_decompile", "quick", "decompile", program=key, address=pick_func(), timeout=60)
            else:
                call("read_functions", "quick", "functions", program=key, offset=rng.randrange(0, 50), limit=200)

        def op_edit_save():
            nonlocal gen, pending
            gen += 1
            g = gen
            ops = [{"op": "rename", "address": a, "name": f"{pfx}{g}_{i:03d}"} for i, a in enumerate(meta["addrs"])]
            opid = f"{idx}:{g}"
            led.sent(opid, kind="edit", gen=g)
            call("edit", "edit", "edit", program=key, ops=ops)
            led.ack(opid, kind="edit", gen=g)
            pending = g
            if rng.random() < 0.75:
                led.sent(opid, kind="save", gen=g)
                try:
                    call("save", "maint", "save", program=key)
                except gs.SessionError as e:
                    if e.code != "failed":
                        raise
                    pending = None          # the failed save's edit is discarded below
                    # a client's answer to a failed save: close the program without its unsaved edits and open
                    # it again (what a harness does after a file error). Whether that cures a program that the
                    # failed save left read-only is recorded, not assumed.
                    t0 = time.perf_counter()
                    try:
                        s.call("close_program", program=key, discard=True)
                        again = s.call("open_program", path=prog, project=pid, writable=True)
                        row("save_recover", "quick", t0, True, after=(e.message or "")[:80],
                            same_key=again.get("key") == key)
                    except gs.SessionError as e2:
                        row("save_recover", "quick", t0, False, e2.code, message=(e2.message or "")[:200])
                    raise
                led.ack(opid, kind="save", gen=g)
                pending = None

        def op_quick_script():
            fields = dict(script=scripts["SoakQuick"], program=key)
            if caps.get("laneHint"):
                fields.update(lane="quick", timeout=60)
            call("quick_script", "quick", "script", **fields)

        def op_long_script():
            call("long_script", "long", "script", script=scripts["SoakSleep"], program=None,
                 args=[str(rng.randrange(1500, 6000))])

        def op_cancel():
            t0 = time.perf_counter()
            rid = s.send("script", script=scripts["SoakSleep"], program=None, args=["60000"])
            time.sleep(rng.uniform(0.3, 1.0))
            try:
                s.call("cancel", target=rid)
            except gs.SessionError as e:
                row("cancel_request", "long", t0, False, e.code)
            try:
                s.wait(rid, 45)
                row("cancel", "long", t0, True, note="finished before the cancel")
            except gs.SessionError as e:
                if e.code == "closed":
                    raise ConnLost() from e
                row("cancel", "long", t0, e.code == "cancelled", None if e.code == "cancelled" else e.code,
                    expected=e.code == "cancelled")
                if e.code not in ("cancelled",):
                    raise

        def op_fork():
            nonlocal fork_n, pending
            if pending is not None:     # a fork copies what is saved: the engine refuses one with unsaved changes (unsaved_changes)
                pg = pending
                led.sent(f"{idx}:{pg}", kind="save", gen=pg)
                call("save", "maint", "save", program=key)
                led.ack(f"{idx}:{pg}", kind="save", gen=pg)
                pending = None
            fork_n += 1
            n = fork_n
            dest = fk_dir / f"f{n}"
            opid = f"{idx}:fork:{n}"
            led.sent(opid, kind="fork", n=n, path=str(dest))
            f = call("fork", "maint", "fork_project", project=pid, path=str(dest), mode="auto", writable=False)
            led.ack(opid, kind="fork", n=n, path=str(dest))
            with contextlib.suppress(Exception):
                s.call("close_project", project=f["project"])
            # keep the newest fork only; the older ones are deleted and the ledger says so
            for old in sorted(fk_dir.glob("f*"), key=lambda q: int(q.name[1:]) if q.name[1:].isdigit() else 0)[:-1]:
                oid = f"{idx}:fork:{old.name[1:]}"
                led.sent(oid, kind="forkdel", n=int(old.name[1:]))
                gone = fk_dir / ("del-" + old.name)
                with contextlib.suppress(OSError):
                    old.rename(gone)      # atomic: a half-deleted fork is never visible under its own name
                    rmtree(gone)
            for stale in fk_dir.glob("del-*"):
                rmtree(stale)

        def op_bulk_open():
            ids = []
            for _ in range(rng.randrange(2, 5)):
                o = call("bulk_open", "quick", "open_project", path=spec["master"])
                ids.append(o["id"])
            for i in ids[:-1]:
                with contextlib.suppress(Exception):
                    s.call("close_project", project=i)

        def op_deaf():
            ms_ = rng.randrange(4000, 8000)
            t0 = time.perf_counter()
            try:
                call("deaf", "long", "script", expect=("cancelled", "timeout"), script=scripts["SoakDeaf"],
                     program=None, args=[str(ms_)], timeout=2)
            finally:
                row("deaf_wall", "long", t0, True, natural_ms=ms_)

        def op_burn():
            ms_ = rng.randrange(3000, 6000)
            t0 = time.perf_counter()
            try:
                call("burn", "long", "script", expect=("cancelled", "timeout"), script=scripts["SoakBurn"],
                     program=None, args=[str(ms_)], timeout=2)
            finally:
                row("burn_wall", "long", t0, True, natural_ms=ms_)

        table = {"read": op_read, "edit_save": op_edit_save, "quick_script": op_quick_script,
                 "long_script": op_long_script, "cancel": op_cancel, "fork": op_fork, "bulk_open": op_bulk_open,
                 "deaf": op_deaf, "burn": op_burn}
        names = [k for k in table if k in spec["ops"]]
        weights = [OP_WEIGHTS[k] for k in names]
        led.sent(f"{idx}:ready", kind="meta")
        row("ready", "quick", time.perf_counter(), True)
        nops = 0
        forced = {5 + idx: "deaf" if idx % 2 == 0 else "burn"}
        while time.time() < deadline and not stop_file.exists():
            nops += 1
            name = forced.get(nops) if forced.get(nops) in names else rng.choices(names, weights)[0]
            try:
                table[name]()
            except ConnLost:
                raise
            except gs.SessionError:
                pass  # recorded as a row by call(); the supervisor judges it against the fault windows
            time.sleep(rng.uniform(0.02, 0.25))
        return 0
    except ConnLost:
        print(f"agent {idx}: connection lost", flush=True)
        return EXIT_CONN_LOST
    except gs.SessionError as e:
        print(f"agent {idx}: setup failed: {e.code} {e}", flush=True)
        row("agent_setup", "quick", time.perf_counter(), False, e.code, message=str(e)[:300])
        return EXIT_FORK_BAD
    finally:
        with contextlib.suppress(Exception):
            s.close()
        led.close()
        res.close()


# ================================================================================ pure judgement functions
# (no engine needed: they are what the self-test plants violations into)

def wilson_upper(failures: int, n: int, z: float = 1.6448536) -> float:
    """One-sided upper 95% bound of the Wilson score interval of a failure rate (z = 1.645): after 0 failures
    in 400 trials it is 0.67%, the "below 0.75% at 95%" of gate 9.15 (the two-sided z of 1.96 would give 0.95%)."""
    if n <= 0:
        return 1.0
    p = failures / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return min(1.0, (centre + half) / den)


def ledger_summary(records) -> dict:
    sent = max([r.get("gen", 0) for r in records if r.get("phase") == "sent" and r.get("kind") == "edit"] or [0])
    acked_edit = max([r.get("gen", 0) for r in records if r.get("phase") == "ack" and r.get("kind") == "edit"] or [0])
    acked_save = max([r.get("gen", 0) for r in records if r.get("phase") == "ack" and r.get("kind") == "save"] or [0])
    forks_acked = {r["n"] for r in records if r.get("phase") == "ack" and r.get("kind") == "fork"}
    forks_del = {r["n"] for r in records if r.get("phase") == "sent" and r.get("kind") == "forkdel"}
    return {"sent": sent, "acked_edit": acked_edit, "acked_save": acked_save,
            "forks_live": sorted(forks_acked - forks_del), "save_ops": oracle.Ledger.acked(records, "save")}


def judge_agent(idx: int, records, meta: dict, names: dict, baseline: dict, rep: oracle.Report,
                by_addr_sample: dict | None = None) -> dict:
    """K3 (names), K4 and K5 for one agent's recovered fork. ``names`` maps address to function name in
    the recovered fork, ``baseline`` the same for the master. Returns what was recovered."""
    pfx = tag_prefix(idx)
    summ = ledger_summary(records)
    addrs = meta["addrs"]
    # K3: the function set equals the master's; names outside the agent's edit set are the master's
    if set(names) != set(baseline):
        rep.violation("K3", "function_set_differs", f"agent {idx}: {len(names)} functions, the master has "
                      f"{len(baseline)}", None, agent=idx)
    gens_set = {oracle.tag_generation(names.get(a, ""), pfx) for a in addrs}
    g_set = next(iter(gens_set)) if len(gens_set) == 1 else None

    def follows_target(a):
        # Ghidra gives a thunk the name of the function it thunks: a thunk of an edited function carries the
        # edit set's own tag of the same generation. That is the program model, not a stray change.
        m = TAG_RX.match(names[a] or "")
        return bool(m) and int(m.group(1)) == idx and g_set is not None and int(m.group(2)) == g_set
    foreign = [a for a in names if a not in set(addrs) and names[a] != baseline.get(a) and not follows_target(a)]
    if foreign:
        # names of a game-derived program are not written to the evidence: their kind and length are
        def kind(n):
            m = TAG_RX.match(n or "")
            return (f"tag of agent {m.group(1)}" if m else "FUN_ name" if (n or "").startswith(("FUN_", "SUB_")) else "other name")                 + f", {len(n or '')} chars"
        rep.violation("K3", "names_not_allowed", f"agent {idx}: {len(foreign)} function(s) outside its edit set "
                      f"differ from the master", None, agent=idx, sample=foreign[:3],
                      kinds=[(kind(names[a]), kind(baseline.get(a))) for a in foreign[:3]],
                      debug_names=([(a, names[a], baseline.get(a)) for a in foreign[:3]] if os.environ.get("HYDRA_SOAK_DEBUG_NAMES") else None))
    # K4: one generation G with acked <= G <= sent
    oracle.check_k4(names, addrs, summ["sent"], summ["acked_save"], prefix=pfx, rep=rep)
    # K5: every acknowledged save is in the recovered state (a later generation contains it)
    gens = {oracle.tag_generation(names.get(a, ""), pfx) for a in addrs}
    g = next(iter(gens)) if len(gens) == 1 else None
    recovered = {f"{idx}:{k}" for k in range(1, (g or 0) + 1)}
    oracle.check_k5([f"{idx}:{k}" for k in range(1, summ["acked_save"] + 1) if f"{idx}:{k}" in set(summ["save_ops"])],
                    recovered, kind="save", rep=rep)
    return {"agent": idx, "recovered_generation": g, **{k: summ[k] for k in ("sent", "acked_edit", "acked_save")}}


def unbounded_script_violations(rows) -> list:
    """A deaf or runaway script must end within its natural time plus 20 s (a killable script worker would end
    it at its timeout)."""
    return [("script_unbounded", f"{r['op']} took {r['ms']} ms for a {r.get('natural_ms', 0)} ms script")
            for r in rows if r["op"] in ("deaf_wall", "burn_wall") and r["ms"] > r.get("natural_ms", 0) + 20000]


def judge_program_owners(programs, me, rep: oracle.Report):
    """K7 after the clients are gone: no program keeps an owner (whatever its ``users`` say: an owner with
    no users is exactly the leaked state), and no program keeps a user other than the supervisor itself
    (``me``, the status ``you`` id) without an owner (a leaked read-only opening)."""
    for p in programs:
        owner, users = p.get("owner"), [u for u in (p.get("users") or []) if u != me]
        if owner is not None:
            rep.violation("K7", "program_owner_left", f"{p.get('path')} still has owner {owner} after the agents exited "
                          f"(users: {users})", None)
        elif owner is None and users:
            rep.violation("K7", "program_user_left", f"{p.get('path')} still has user(s) {users} and no owner after the "
                          f"agents exited", None)


def judge_k11(views: dict, rep: oracle.Report):
    """K11: no view shows a tag another agent wrote. ``views`` maps agent index to the tag names seen in it."""
    own = {i: set() for i in views}
    seen = {}
    for i, tags in views.items():
        seen[i] = set(tags)
    for i, tags in views.items():
        for t in tags:
            m = TAG_RX.match(t)
            if m:
                own.setdefault(int(m.group(1)), set()).add(t)
    oracle.check_k11({f"a{i}": {"own": own.get(i, set()), "saw": seen.get(i, set())} for i in own}, {}, rep)


#: what a fault window tolerates, per fault class: the error codes the fault can cause, and where a rule is
#: narrower, the operations and the message. ``busy`` is never in the list: a ``busy`` is judged by its
#: explanation (BUSY_EXPLAINERS) whatever the windows say, and any other code is an unexpected error.
#: A daemon that is killed or suspended shows to a client as a closed connection or a timeout; a killed
#: decompiler fails the one decompile that used it; a handle on the version folder fails a save (the engine
#: answers ``failed`` with the IOException, and ``failed``/``read_only`` with ReadOnlyException until the
#: agent re-opens the program).
FAULT_TOLERATES = {
    "kill_client": dict(codes=("closed", "conn:*")),
    "kill_daemon_random": dict(codes=("closed", "conn:*", "timeout")),
    "kill_daemon_trigger": dict(codes=("closed", "conn:*", "timeout")),
    # decompiler_failed{function, entry, reason, retryable} is the protocol 3 answer of the one decompile whose native
    # decompiler died (3.11 "Decompiler faults", E9 A36); ``failed`` is the older answer
    "kill_decompiler": dict(codes=("failed", "decompiler_failed", "timeout"), ops=("read_decompile",)),
    "suspend_daemon": dict(codes=("closed", "conn:*", "timeout")),
    "suspend_client": dict(codes=("timeout",)),
    "stalled_reader": dict(codes=("timeout",)),
    "handle_holder": dict(codes=("failed", "read_only"), ops=("save", "edit"),
                          msg=re.compile(r"IOException|ReadOnlyException|File error|read-only", re.I)),
}


def _window_tolerates(w: dict, r: dict) -> bool:
    rule = FAULT_TOLERATES.get(w.get("cls"))
    if rule is None:
        return False
    code = r.get("code") or ""
    if not any(code == c or (c.endswith("*") and code.startswith(c[:-1])) for c in rule["codes"]):
        return False
    if rule.get("ops") and r["op"] not in rule["ops"]:
        return False
    if rule.get("msg") is not None and not rule["msg"].search(r.get("message") or ""):
        return False
    return True


def window_share(windows, tolerated_after_s: float, t_span, scope_all_only: bool = True) -> float:
    """The share of ``t_span`` covered by the (union of the) windows, with the margins classify_rows uses."""
    t0, t1 = t_span
    if t1 <= t0:
        return 0.0
    iv = sorted((max(t0, w["t0"] - 2), min(t1, w["t1"] + tolerated_after_s)) for w in windows
                if not scope_all_only or w.get("scope") == "all")
    cov, cur_a, cur_b = 0.0, None, None
    for a_, b_ in iv:
        if b_ <= a_:
            continue
        if cur_b is None or a_ > cur_b:
            if cur_b is not None:
                cov += cur_b - cur_a
            cur_a, cur_b = a_, b_
        else:
            cur_b = max(cur_b, b_)
    if cur_b is not None:
        cov += cur_b - cur_a
    return round(cov / (t1 - t0), 4)


def classify_rows(rows, windows, tolerated_after_s: float = 0.0, t_span=None):
    """Judges the agents' result rows. Returns ``(violations, summary)``; ``violations`` is a list of
    ``(code, detail)``. An error is tolerated only when it falls inside a fault window that covers its agent
    AND is an error that fault class can cause (``FAULT_TOLERATES``); every tolerated error is counted by
    class, operation and code in the summary, with the share of the run the all-scope windows cover, so
    that a window cannot hide errors without that showing in the evidence."""
    def tolerating(r):
        for w in windows:
            if w["t0"] - 2 <= r["t"] <= w["t1"] + tolerated_after_s and w["scope"] in ("all", r["agent"]) \
                    and _window_tolerates(w, r):
                return w
        return None
    viol, unexpected, busy_ok, busy_bad = {}, 0, 0, 0
    tolerated = {}
    for r in rows:
        if r.get("ok") or r.get("expected") or r["op"] in ("deaf_wall", "burn_wall", "ready"):
            continue
        code = r.get("code") or ""
        if code == "busy":
            det = r.get("details") or {}
            if any(k in det for k in BUSY_EXPLAINERS):
                busy_ok += 1
                continue
            busy_bad += 1
            viol.setdefault(("unexplained_busy", r["op"]), []).append(r)
            continue
        w = tolerating(r)
        if w is not None:
            key = f"{w.get('cls')}/{r['op']}:{code}"
            tolerated[key] = tolerated.get(key, 0) + 1
            continue
        if code == "closed" or code.startswith("conn:"):
            continue  # judged through the agent's exit (an agent that loses its daemon outside a fault is a violation there)
        unexpected += 1
        viol.setdefault(("unexpected_error", f"{r['op']}:{code}"), []).append(r)
    out = []
    for (kind, what), rs in sorted(viol.items()):
        out.append((kind, f"{what}: {len(rs)} time(s); first: {json.dumps(rs[0], default=str)[:300]}"))
    summary = {"unexpected": unexpected, "busy_explained": busy_ok, "busy_unexplained": busy_bad,
               "tolerated_in_windows": tolerated, "tolerated_total": sum(tolerated.values())}
    if t_span is not None:
        summary["all_scope_window_share_of_run"] = window_share(windows, tolerated_after_s, t_span)
    return out, summary


def latency_table(rows, windows):
    """p50/p99 of the successful operations per lane, outside the fault windows (a window is a time the
    machine was being hurt on purpose, so its latencies are recorded apart)."""
    def inside(r):
        return any(w["t0"] - 2 <= r["t"] <= w["t1"] + 5 for w in windows)
    out = {}
    for lane in ("quick", "edit", "long", "maint"):
        calm = [r["ms"] for r in rows if r.get("ok") and r.get("lane") == lane and not inside(r)
                and r["op"] not in ("long_script", "cancel", "deaf", "burn", "deaf_wall", "burn_wall", "ready")]
        hurt = [r["ms"] for r in rows if r.get("ok") and r.get("lane") == lane and inside(r)]
        out[lane] = {"n_calm": len(calm), "p50_ms": pct(calm, 0.5), "p99_ms": pct(calm, 0.99),
                     "n_in_fault_window": len(hurt), "p99_in_fault_window_ms": pct(hurt, 0.99)}
    return out


def profile_overrides(profile: str, agents: int, projects: int, duration_s: float, ops) -> list:
    """What differs from the profile's fixed definition (9.17: pr 4x2 / 10 min, nightly 16x4 / 2 h, release
    24x6 / 4 h): a run that shrinks any of it is not a gate run, whatever else it did."""
    prof = PROFILES[profile]
    out = []
    if agents != prof["agents"]:
        out.append(f"--agents {agents} (profile {profile}: {prof['agents']})")
    if projects != prof["projects"]:
        out.append(f"--projects {projects} (profile {profile}: {prof['projects']})")
    if duration_s != prof["duration_s"]:
        out.append(f"--duration-s {duration_s} (profile {profile}: {prof['duration_s']})")
    if set(ops) != set(OPS):
        out.append(f"--ops {','.join(sorted(ops))} (profile {profile}: all of {','.join(sorted(OPS))})")
    return out


def verdict_of(profile: str, rep: oracle.Report, hits: dict, workload: dict, features: dict, extra_viol: list,
               cut_short: str | None, setup_error: str | None, ran_checks: set, plants_expected=(),
               overrides=()) -> dict:
    """The verdict from the facts of a run. ``extra_viol`` are (code, detail) pairs of the runner's own
    criteria (unexpected errors, a lost agent, ...), ``hits`` the fault classes fired.

    ``hard`` gaps (a setup error, a run cut short, a fault class below its minimum, an operation that never
    ran) make any profile INCOMPLETE. ``soft`` gaps (a feature or a check that belongs to a package that has
    not landed, or to the Hydralysis side) make a gate profile INCOMPLETE and are only listed for ``smoke``."""
    gate = PROFILES[profile]["gate"]
    mins = MIN_FAULTS[profile]
    hard, soft = [], []
    if setup_error:
        hard.append(f"setup: {setup_error}")
    if cut_short:
        hard.append(f"run cut short: {cut_short}")
    for cls, need in mins.items():
        got = hits.get(cls, 0)
        if got < need:
            hard.append(f"fault class {cls}: {got} of the minimum {need}")
    kills = sum(hits.get(c, 0) for c in KILL_CLASSES)
    if profile == "nightly" and kills < 150:
        hard.append(f"nightly kills: {kills} of the minimum 150")
    for cls, why in UNAVAILABLE_FAULTS.items():
        soft.append(f"fault class {cls}: not run here ({why})")
    for op, why in UNAVAILABLE_WORKLOAD.items():
        soft.append(f"workload {op}: not run here ({why})")
    for k, why in UNEXERCISED_CHECKS.items():
        soft.append(f"oracle {k}: not exercised ({why})")
    for feat, present in sorted(features.items()):
        if not present.get("present") and present.get("needed_for_gate"):
            soft.append(f"feature {feat} absent: {present.get('why')}")
    for op, n in workload.items():
        if n == 0 and op in OPS:
            hard.append(f"workload {op}: never ran")
    gaps = hard + soft
    viol = [f"{v['id']}:{v['code']}" for v in rep.findings] + [c for c, _ in extra_viol]
    if viol:
        v = "FAIL"
    elif hard or (gate and soft):
        v = "INCOMPLETE"
    else:
        # a run that shrank the profile (agents, projects, duration, operations) is not a gate run: its
        # ceiling is SMOKE-OK, never PASS
        v = "PASS" if gate and not overrides else "SMOKE-OK"
    missing = None
    if plants_expected:
        found = set(viol)
        missing = [p for p in plants_expected if not any(f.startswith(p) for f in found)]
    if overrides:
        gaps = gaps + [f"profile overridden, not a gate run: {o}" for o in overrides]
    return {"verdict": v, "gate_eligible": gate and not gaps and not viol and not overrides, "violations": viol,
            "gaps": gaps, "overrides": list(overrides),
            "hard_gaps": hard, "soft_gaps": soft, "plants_missing": missing or [],
            "plants_all_caught": None if missing is None else not missing}


# ================================================================================ the supervisor

class Soak:
    def __init__(self, a):
        self.a = a
        self.profile = a.profile
        prof = PROFILES[a.profile]
        self.agents = a.agents or prof["agents"]
        self.nproj = a.projects or prof["projects"]
        self.duration = a.duration_s or prof["duration_s"]
        self.overrides = profile_overrides(a.profile, self.agents, self.nproj, self.duration, a.ops)
        self.work = pathlib.Path(a.work).absolute()
        self.gs = load_gs(a.ghidra)
        self.rng = random.Random(a.seed)
        self.t_start = None
        self.evidence_dir = pathlib.Path(a.evidence) if a.evidence else self.work / "evidence"
        self.evidence = None      # created at the end (an --work that is not empty is refused at the start)
        self.state = self.work / "state"
        self.tmpdir = self.work / "tmp"
        self.scripts_dir = self.work / "scripts"
        # --master-root moves the masters AND the agents' trees (forks, saves, ledgers) to that volume: the
        # ReFS lane exercises saves and fork publishes there, so they must not stay on the --work volume
        self.tree_root = pathlib.Path(a.master_root).absolute() if a.master_root else self.work
        self.masters_dir = self.tree_root / "masters"
        self.agents_dir = self.tree_root / "agents"
        self.canary = self.work / "canary"
        self.instance = "soak"
        self.report = oracle.Report("soak")
        self.extra_viol: list = []
        self.hits = {c: 0 for c in FAULT_CLASSES + ["backup_lane"]}
        self.attempts = {c: 0 for c in FAULT_CLASSES + ["backup_lane"]}
        self.windows: list = []
        self.fault_log: list = []
        self.procs: dict = {}
        self.proc_started: dict = {}
        self.rc_log: list = []
        self.daemon = None
        self.daemon_pid = None
        self.daemon_down = threading.Event()
        self.stopping = threading.Event()
        self.lock = threading.RLock()
        self.sess = None            # the supervisor's own session
        self.features: dict = {}
        self.health_samples: list = []
        self.status_samples: list = []
        self.pings: list = []
        self.incarnation = 0
        self.baseline_threads = None
        self.baseline_handles = None
        self.tmp_before = None
        self.k13_final: list = []
        self.cut_short = None
        self.setup_error = None
        self.decompilers_seen: set = set()
        self.planted_pids: list = []
        self.holders: list = []
        self.baseline = None
        self.master_trees = None
        self.watchers: list = []
        self.sample_stats = {"scheduler_max_queued": {}, "abandoned_max": 0, "clients_max": 0}
        self.plant = [p for p in (a.plant or "").split(",") if p]
        self.agent_caps: dict = {}
        self.t_plant = None
        self.no_respawn = set()      # agents whose setup failed three times: never respawned
        self.killed_agents = set()   # agents f_kill_client is working on: the monitor must not respawn them
        self.reap_lock = threading.RLock()
        self.setup_failures = {}
        self.baseline_taken_at = None
        self.plant_foreign_blocked = 0
        self.guard = None

    # ---------------------------------------------------------------------------- layout
    def master_gpr(self, p: int) -> pathlib.Path:
        return next((self.masters_dir / f"p{p}").glob("*.gpr"))

    def agent_dir(self, i: int) -> pathlib.Path:
        return self.agents_dir / f"a{i:02d}"

    def agent_project(self, i: int) -> int:
        return i % self.nproj

    def fork_gpr(self, i: int):
        f = self.agent_dir(i) / "fork"
        return next(f.glob("*.gpr"), None) if f.is_dir() else None

    def all_project_trees(self) -> list:
        t = [self.masters_dir / f"p{p}" for p in range(self.nproj)]
        for i in range(self.agents):
            t += [self.agent_dir(i) / "fork"]
            fk = self.agent_dir(i) / "fk"
            if fk.is_dir():
                t += [q for q in fk.iterdir() if q.is_dir() and not q.name.startswith('del-')]
        if self.canary.is_dir():
            t.append(self.canary)
        return [x for x in t if x.exists()]

    def t(self) -> float:
        return time.time() - self.t_start

    # ---------------------------------------------------------------------------- daemon
    def make_daemon(self):
        cfg = {"maxLong": max(8, 2 * self.agents), "maxQuick": max(8, 2 * self.agents)}
        cfg.update(getattr(self.a, "daemon_cfg", None) or {})
        self.daemon = self.gs.Daemon(self.a.ghidra, str(self.state), self.instance, **cfg)

    def start_daemon(self):
        self.sess = self.daemon.connect("soak-supervisor", "soak", timeout=120)
        ep = self.daemon.read_endpoint()
        self.daemon_pid = int(ep["pid"]) if ep and ep.get("pid") else self.sess.hello.get("pid")
        self.incarnation += 1
        self.decompilers_seen = set()
        return self.sess

    def sup_call(self, cmd, **fields):
        with self.lock:
            return self.sess.call(cmd, **fields)

    def reconnect_sup(self):
        with self.lock:
            with contextlib.suppress(Exception):
                self.sess.close()
            self.sess = self.daemon.connect("soak-supervisor", "soak", start=False, timeout=60)
        return self.sess

    def warm_scripts(self):
        for name in SCRIPTS:
            path = str(self.scripts_dir / f"{name}.java")
            try:
                self.sup_call("script", script=path, program=None, args=["1"], timeout=300)
            except Exception as e:  # noqa: BLE001
                self.note_gap(f"script {name} could not be compiled in the warm-up: {e}")

    def probe_features(self):
        caps = self.sess.hello.get("capabilities", {}) or {}
        limits = self.sess.hello.get("limits", {}) or {}
        f = {}
        f["laneHint"] = {"present": bool(caps.get("laneHint")), "needed_for_gate": True,
                         "why": "quick-lane scripts need the laneHint capability"}
        f["maintLane"] = {"present": bool(caps.get("maintLane")), "needed_for_gate": True,
                          "why": "the backup-in-maint check needs the maintLane capability"}
        h = None
        try:
            h = self.sup_call("health")
            f["health"] = {"present": True, "needed_for_gate": True}
        except self.gs.SessionError as e:
            f["health"] = {"present": False, "needed_for_gate": True, "code": e.code,
                           "why": "waits.foreignBlocked and the lane figures of the gate are read from the health command (E5); "
                                  "this engine has none, so the gate cannot pass and the check is skipped, not passed"}
        st = self.sup_call("status")
        f["status.waits"] = {"present": isinstance(st.get("waits"), dict), "needed_for_gate": False}
        f["scheduler.maint"] = {"present": "maint" in (st.get("scheduler") or {}), "needed_for_gate": True,
                                "why": "the maint lane is not reported"}
        f["script_worker"] = {"present": script_worker_present(caps, h),
                              "needed_for_gate": False,
                              "why": "E7 (killable script worker): deaf scripts are only bounded and quarantined without it"}
        f["governor"] = {"present": "maxViews" in limits or "governor" in caps, "needed_for_gate": False,
                         "why": "the memory governor and view limits (E9)"}
        self.features = f
        self.agent_caps = {"laneHint": bool(caps.get("laneHint"))}
        return h

    def note_gap(self, text):
        self.fault_log.append({"t": round(self.t() if self.t_start else 0, 1), "gap": text})

    # ---------------------------------------------------------------------------- setup
    def setup(self):
        if self.work.exists() and any(self.work.iterdir()) and not self.a.reuse_work:
            raise SystemExit(f"{self.work} is not empty; pass an empty --work (fresh state roots are the rule)")
        if self.a.master_root and self.tree_root.exists() and any(self.tree_root.iterdir()) and not self.a.reuse_work:
            # the end of the run removes <master-root>/masters and <master-root>/agents: never in a folder that has content
            raise SystemExit(f"{self.tree_root} (--master-root) is not empty; pass an empty folder: the run deletes "
                             "its masters and agents folders at the end")
        for d in (self.state, self.tmpdir, self.scripts_dir, self.agents_dir, self.masters_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text(json.dumps({"tmpdir": str(self.tmpdir),
                                                            "scriptPath": [str(self.scripts_dir)]}))
        for name, src in SCRIPTS.items():
            (self.scripts_dir / f"{name}.java").write_text(src)
        self.make_daemon()
        self.start_daemon()
        try:
            self.prepare_masters()
        except Exception as e:  # noqa: BLE001
            self.setup_error = f"masters: {type(e).__name__}: {e}"
            raise
        h = self.probe_features()
        self.warm_scripts()
        # the baseline of the master (K3) and the tree hashes of everything that must not change (K9)
        mgpr = self.master_gpr(0)
        o = self.sup_call("open_project", path=str(mgpr))
        pr = self.sup_call("open_program", path=self.a.program, project=o["id"])
        sc = oracle.scan_program(self.sess, pr["key"], sample=[])
        self.baseline = sc["by_addr"]
        self.sup_call("close_program", program=pr["key"])
        self.sup_call("close_project", project=o["id"])
        if len(self.baseline) < 4:
            raise SystemExit(f"the program {self.a.program} has {len(self.baseline)} functions: too few for the edit sets")
        if self.plant:
            shutil.copytree(self.masters_dir / "p0", self.canary)   # a project no agent and no daemon touches
        self.guard = oracle.TreeGuard(**{f"p{p}": self.masters_dir / f"p{p}" for p in range(self.nproj)},
                                      **({"canary": self.canary} if self.canary.is_dir() else {}))
        return h

    def prepare_masters(self):
        """Master 0 is a disposable fork of --project (an upgrade, when the program needs one, happens in a
        fork, E2); the other masters are copies of it. The original is never opened writable."""
        src = pathlib.Path(self.a.project)
        stage = self.work / "stage-src"
        if stage.exists():
            rmtree(stage)
        shutil.copytree(src.parent, stage)
        so = self.sup_call("open_project", path=str(stage / src.name))
        fk = self.sup_call("fork_project", project=so["id"], path=str(self.masters_dir / "p0"), mode="full",
                           open=False, wait=600000)
        self.sup_call("close_project", project=so["id"])
        o = self.sup_call("open_project", path=fk["gpr"], writable=True)
        self.sup_call("open_program", path=self.a.program, project=o["id"], writable=True, upgrade=True)
        self.sup_call("save")
        self.sup_call("close_project", project=o["id"])
        rmtree(stage)
        for p in range(1, self.nproj):
            shutil.copytree(self.masters_dir / "p0", self.masters_dir / f"p{p}")

    # ---------------------------------------------------------------------------- agents
    def spawn_agent(self, i: int):
        adir = self.agent_dir(i)
        adir.mkdir(parents=True, exist_ok=True)
        spec = {"ghidra": self.a.ghidra, "state": str(self.state), "instance": self.instance, "index": i,
                "agents": self.agents, "label": f"soak-a{i:02d}", "dir": str(adir),
                "master": str(self.master_gpr(self.agent_project(i))), "program": self.a.program,
                "seed": self.rng.randrange(1 << 30), "stop_file": str(self.work / "STOP"),
                "deadline": self.t_start + self.duration + 60, "edit_m": self.a.edit_m,
                "caps": self.agent_caps, "ops": self.a.ops,
                "scripts": {n: str(self.scripts_dir / f"{n}.java") for n in SCRIPTS}}
        sp = adir / f"spec-{int(time.time() * 1000)}.json"
        sp.write_text(json.dumps(spec), encoding="utf-8")
        log = open(adir / "agent.log", "ab")
        p = subprocess.Popen([sys.executable, "-I", str(pathlib.Path(__file__).resolve()), "--agent", str(sp)],
                             stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        log.close()
        self.procs[i] = p
        self.proc_started[i] = time.time()
        return p

    def live_agents(self) -> list:
        return [i for i, p in list(self.procs.items()) if p.poll() is None]

    def reap_agents(self, respawn: bool = True):
        """Notes exits; respawns an agent that ended while the daemon is up and the run is going."""
        with self.reap_lock:
            self._reap_agents(respawn)

    def _reap_agents(self, respawn: bool):
        for i, p in list(self.procs.items()):
            rc = p.poll()
            if rc is None:
                continue
            ev = {"agent": i, "rc": rc, "t": round(self.t(), 1)}
            if rc == EXIT_FORK_BAD:       # the agent could not set up; three in a row end its respawns
                self.setup_failures[i] = self.setup_failures.get(i, 0) + 1
                if self.setup_failures[i] >= 3 and i not in self.no_respawn:
                    self.no_respawn.add(i)
                    tail = ""
                    with contextlib.suppress(OSError):
                        tail = (self.agent_dir(i) / "agent.log").read_text(errors="replace")[-300:]
                    self.extra_viol.append(("agent_setup_failed", f"agent {i} could not set up three times: {tail!r}"))
            if not self.stopping.is_set() and rc != 0:
                covered = any(w["t0"] - 2 <= time.time() <= w["t1"] + 30 and w["scope"] in ("all", i) for w in self.windows)
                ev["covered_by_fault"] = covered
                if not covered and not self.daemon_down.is_set():
                    tail = ""
                    with contextlib.suppress(OSError):
                        tail = (self.agent_dir(i) / "agent.log").read_text(errors="replace")[-400:]
                    self.extra_viol.append(("agent_lost", f"agent {i} exited {rc} with no fault active: {tail!r}"))
            self.rc_log.append(ev)
            self.procs.pop(i, None)
            if respawn and i not in self.no_respawn and i not in self.killed_agents \
                    and not self.stopping.is_set() and not self.daemon_down.is_set() \
                    and time.time() < self.t_start + self.duration:
                self.spawn_agent(i)

    # ---------------------------------------------------------------------------- windows and faults
    @contextlib.contextmanager
    def fault_window(self, cls: str, scope="all", extra_s: float = 0.0):
        w = {"cls": cls, "scope": scope, "t0": time.time(), "t1": time.time() + 3600}
        self.windows.append(w)
        try:
            yield w
        finally:
            w["t1"] = time.time() + extra_s

    def k10(self, dead_label: str, timeout_s: float = 45.0, phase=""):
        rep = oracle.Report("K10")
        oracle.check_k10(lambda name: self.daemon.connect(name, "soak", start=False, timeout=60), dead_label,
                         timeout_s, rep)
        self.merge(rep, phase)
        return rep.ok

    def merge(self, rep: oracle.Report, phase: str = ""):
        for f in rep.findings:
            f["phase"] = phase
        for f in rep.tolerated:
            f["phase"] = phase
        self.report.merge(rep)

    def file_round(self, phase: str, *, quiescent: bool = False, daemon_alive: bool = True, locks: bool = True):
        """The file-level invariants over every tree: K2 (version-file headers), K6 (a fork is absent or
        complete; no staging folder left), K9 (nothing involved changes in a project no agent works on),
        K7 (locks; temp folder growth)."""
        rep = oracle.Report("round:" + phase)
        trees = self.all_project_trees()
        for p in trees:
            oracle.check_k2(p, rep)
        for p in trees:
            if p.name == "canary":
                continue
            for gpr in p.rglob("*.gpr"):
                oracle.check_k6(gpr, require_sidecar=False, rep=rep)
        for i in range(self.agents):
            for parent in (self.agent_dir(i), self.agent_dir(i) / "fk"):
                if parent.is_dir():
                    oracle.check_k6_staging(parent, rep)
        # canary parents (a planted .rep without .gpr lives next to it)
        if self.canary_forks().is_dir():
            for rp in self.canary_forks().glob("*.rep"):
                oracle.check_k6(rp.with_suffix(".gpr"), require_sidecar=False, rep=rep)
        self.guard.check(rep)
        if locks:
            oracle.check_k7_locks(self.masters_dir, quiescent=quiescent,
                                  live_pids=[self.daemon_pid] if daemon_alive else [], rep=rep)
            for i in range(self.agents):
                if self.agent_dir(i).is_dir():
                    oracle.check_k7_locks(self.agent_dir(i), quiescent=quiescent,
                                          live_pids=[self.daemon_pid] if daemon_alive else [], rep=rep)
        self.merge(rep, phase)
        return rep

    def canary_forks(self) -> pathlib.Path:
        return self.work / "canary-forks"

    def tmp_round(self, phase: str):
        rep = oracle.Report("tmp:" + phase)
        n = len(list(self.tmpdir.glob("tmp*"))) if self.tmpdir.is_dir() else 0
        if self.tmp_before is None:
            self.tmp_before = n
        else:
            oracle.check_k7_tmp(self.tmpdir, self.tmp_before, slack=16 + 2 * self.agents, rep=rep)
        self.merge(rep, phase)

    # -- reading recovered state
    def read_fork(self, gpr, sample_n: int = 3):
        s = self.sess
        last = None
        for attempt in range(3):
            try:
                o = s.call("open_project", path=str(gpr))
                try:
                    p = s.call("open_program", path=self.a.program, project=o["id"])
                    try:
                        base_addrs = sorted(self.baseline)
                        sc = oracle.scan_program(s, p["key"], sample=base_addrs[:sample_n])
                    finally:
                        with contextlib.suppress(Exception):
                            s.call("close_program", program=p["key"])
                finally:
                    with contextlib.suppress(Exception):
                        s.call("close_project", project=o["id"])
                return sc
            except self.gs.SessionError as e:
                last = e
                time.sleep(3)
        raise last

    def recovery_read(self, ids, phase: str):
        """K3, K4, K5, K11 and the fork part of K6/K5 for the given agents, from the recovered files."""
        rep = oracle.Report("recovery:" + phase)
        views = {}
        for i in ids:
            adir = self.agent_dir(i)
            gpr = self.fork_gpr(i)
            meta_p = adir / "meta.json"
            if gpr is None or not meta_p.exists():
                continue  # the agent never got as far as its first edit set
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            recs = oracle.Ledger.read(adir / "ledger.jsonl")
            try:
                sc = self.read_fork(gpr)
            except Exception as e:  # noqa: BLE001
                rep.violation("K3", "open_failed", f"agent {i}: the recovered fork does not open: {e}", gpr, agent=i)
                continue
            judge_agent(i, recs, meta, sc["by_addr"], self.baseline, rep)
            if sc["decomp_errors"]:
                rep.violation("K3", "decompile_failed", f"agent {i}: {sc['decomp_errors']} sampled decompile(s) failed",
                              gpr, agent=i)
            views[i] = [n for n in sc["by_addr"].values() if TAG_RX.match(n)]
            # forks: every acknowledged and not deleted fork exists and is complete (K5, K6)
            summ = ledger_summary(recs)
            for n in summ["forks_live"]:
                d = adir / "fk" / f"f{n}"
                g = next(d.glob("*.gpr"), None) if d.is_dir() else None
                if g is None:
                    rep.violation("K5", "acked_fork_missing", f"agent {i}: acknowledged fork f{n} is missing", d, agent=i)
                else:
                    oracle.check_k6(g, require_sidecar=False, rep=rep)
        if views:
            judge_k11(views, rep)
        self.merge(rep, phase)
        return rep

    # ---------------------------------------------------------------------------- fault bodies
    def pick_agent(self):
        live = self.live_agents()
        return self.rng.choice(live) if live else None

    def f_kill_client(self):
        import chaos_lib as chaos
        i = self.pick_agent()
        if i is None:
            return False
        label = f"soak-a{i:02d}"
        r, ok = {}, None
        try:
            with self.fault_window("kill_client", scope=i, extra_s=45):
                # the kill and the pop are one step under reap_lock, and the agent is marked as being
                # killed first: the monitor thread must not see the exit and respawn it (two processes on
                # one ledger and one fork)
                with self.reap_lock:
                    self.killed_agents.add(i)
                    p = self.procs.get(i)
                    if p is None or p.poll() is not None:
                        return False        # the agent went away on its own: nothing was killed (the monitor judges its exit)
                    r = chaos.kill_client_proc(p)
                    if not (r or {}).get("terminated"):
                        # not killed: the process is still the agent. Popping and respawning it would put two
                        # processes on one ledger. Leave it where it is and count nothing.
                        self.fault_log.append({"t": round(self.t(), 1), "fault": "kill_client", "agent": i, "kill": r,
                                               "counted": False})
                        return False        # i is still in procs, so the finally block does not respawn it
                    self.rc_log.append({"agent": i, "rc": "killed", "t": round(self.t(), 1)})
                    self.procs.pop(i, None)
                ok = self.k10(label, phase=f"kill_client a{i:02d}")
                self.file_round(f"kill_client a{i:02d}", locks=False)
                self.recovery_read([i], f"kill_client a{i:02d}")
        finally:
            with self.reap_lock:
                if r and not self.stopping.is_set() and i not in self.procs:
                    self.spawn_agent(i)
                self.killed_agents.discard(i)
        self.fault_log.append({"t": round(self.t(), 1), "fault": "kill_client", "agent": i, "kill": r, "k10": ok})
        return bool(r.get("terminated"))

    def f_kill_daemon(self, trigger: bool):
        import chaos_lib as chaos
        cls = "kill_daemon_trigger" if trigger else "kill_daemon_random"
        pid = self.daemon_pid
        before_dec = set(chaos.decompilers_of(pid))
        watch = None
        if trigger:
            i = self.pick_agent()
            gpr = self.fork_gpr(i) if i is not None else None
            if gpr is not None:
                watch = next((p.parent for p, _n in oracle.version_files(gpr.with_suffix(".rep"))), None)
        with self.fault_window(cls, extra_s=0) as w:
            self.daemon_down.set()
            delay = chaos.random_delay(self.rng, 0.0, 0.25 if trigger else 3.0)
            r = chaos.timed_kill(pid, lambda: None, delay_s=delay, watch=str(watch) if watch else None,
                                 max_wait_s=60.0, kill=lambda p: chaos.terminate(p, 120))
            counted = bool(r["kill"].get("terminated")) and (not trigger or bool(r.get("trigger_hit")))
            self.k13_note_incarnation()
            self.recover_daemon(cls, before_dec, w)
        self.fault_log.append({"t": round(self.t(), 1), "fault": cls, **r, "counted": counted})
        return counted

    def recover_daemon(self, cls: str, before_dec: set, window: dict):
        """After a daemon kill: wait for the agents to notice, check the files the dead daemon left, start a
        daemon on the same state root, check liveness and the recovered state, then let the agents back."""
        import chaos_lib as chaos
        t0 = time.time()
        end = t0 + 60
        while self.live_agents() and time.time() < end:
            time.sleep(0.5)
        for i in self.live_agents():  # an agent that did not notice the dead socket within 60 s
            p = self.procs.get(i)
            if p is not None:
                chaos.kill_client_proc(p)
        self.reap_agents(respawn=False)
        rep = oracle.Report("post-kill:" + cls)
        oracle.check_k7_processes([], settle_s=8.0, only_pids=before_dec, rep=rep)
        self.merge(rep, "post-kill " + cls)
        self.file_round("post-kill " + cls, quiescent=False, daemon_alive=False, locks=False)
        # restart on the same state root
        try:
            self.start_daemon()
        except Exception as e:  # noqa: BLE001
            self.extra_viol.append(("daemon_restart_failed", f"{cls}: {type(e).__name__}: {e}"))
            self.cut_short = f"the daemon did not come back after {cls}"
            self.stopping.set()
            return
        try:
            self.sess.call("ping")
        except Exception as e:  # noqa: BLE001
            self.report.violation("K10", "no_ping", f"after {cls}: {e}")
        time.sleep(3)  # the fork sweeper of the new daemon
        self.tmp_round("post-restart " + cls)
        self.file_round("after-restart " + cls, quiescent=False, daemon_alive=True)
        self.recovery_read(range(self.agents), "after-restart " + cls)
        self.warm_after_restart()
        window["t1"] = time.time() + 20
        self.daemon_down.clear()
        for i in range(self.agents):
            if i not in self.procs and i not in self.no_respawn and i not in self.killed_agents \
                    and time.time() < self.t_start + self.duration:
                self.spawn_agent(i)

    def warm_after_restart(self):
        with contextlib.suppress(Exception):
            self.warm_scripts()
        self.baseline_threads = None  # re-taken in the monitor, 20 s after the restart
        self.baseline_taken_at = time.time() + 20

    def f_kill_decompiler(self):
        import chaos_lib as chaos
        pid = self.daemon_pid
        end = time.time() + 20
        pids = []
        while not pids and time.time() < end:
            pids = chaos.decompilers_of(pid)
            time.sleep(0.2)
        if not pids:
            return False
        with self.fault_window("kill_decompiler", extra_s=30):
            r = chaos.terminate(pids[0], 10)
            self.fault_log.append({"t": round(self.t(), 1), "fault": "kill_decompiler", "pid": pids[0], **r})
            # GR9: the request that used it fails alone, the next one works
            ok = False
            gpr = self.master_gpr(0)
            try:
                o = self.sup_call("open_project", path=str(gpr))
                p = self.sup_call("open_program", path=self.a.program, project=o["id"])
                addr = sorted(self.baseline)[0]
                for _ in range(3):
                    with contextlib.suppress(self.gs.SessionError):
                        d = self.sup_call("decompile", program=p["key"], address=addr, timeout=60)
                        ok = bool(d.get("c"))
                        if ok:
                            break
                with contextlib.suppress(Exception):
                    self.sup_call("close_program", program=p["key"])
                    self.sup_call("close_project", project=o["id"])
            except Exception as e:  # noqa: BLE001
                self.report.violation("K14", "decompiler_pool_dead", f"after killing a decompiler: {e}")
            if not ok:
                self.report.violation("K14", "decompiler_pool_dead",
                                      "no decompile worked within three tries after a decompiler was killed")
            try:
                self.sess.call("ping")
            except Exception as e:  # noqa: BLE001
                self.report.violation("K10", "no_ping", f"after a decompiler kill: {e}")
        return bool(r.get("terminated"))

    def f_suspend_daemon(self):
        import chaos_lib as chaos
        secs = self.rng.uniform(2.0, 6.0)
        with self.fault_window("suspend_daemon", extra_s=30):
            with chaos.Suspended(self.daemon_pid):
                time.sleep(secs)
            t0 = time.time()
            try:
                self.sess.call("ping")
                lat = round((time.time() - t0) * 1000)
            except Exception as e:  # noqa: BLE001
                self.report.violation("K10", "no_ping", f"after a {secs:.1f} s suspend of the daemon: {e}")
                lat = None
            self.fault_log.append({"t": round(self.t(), 1), "fault": "suspend_daemon", "seconds": round(secs, 1),
                                   "ping_ms_after": lat})
        return True

    def f_suspend_client(self):
        import chaos_lib as chaos
        i = self.pick_agent()
        if i is None:
            return False
        secs = self.rng.uniform(3.0, 10.0)
        lats = []
        proc = self.procs.get(i)
        if proc is None:
            return False                    # the agent went away between the pick and now
        with self.fault_window("suspend_client", scope=i, extra_s=30):
            with chaos.Suspended(proc.pid):
                end = time.time() + secs
                while time.time() < end:
                    t0 = time.time()
                    try:
                        self.sess.call("ping")
                        lats.append(round((time.time() - t0) * 1000))
                    except Exception as e:  # noqa: BLE001
                        self.report.violation("K10", "no_ping", f"while a client was suspended: {e}")
                        break
                    time.sleep(0.5)
        self.fault_log.append({"t": round(self.t(), 1), "fault": "suspend_client", "agent": i,
                               "seconds": round(secs, 1), "supervisor_ping_ms_max": max(lats) if lats else None})
        return True

    def f_stalled_reader(self):
        """A client that sends requests and never reads the answers: the daemon must go on serving the
        others (the supervisor's ping and a decompile stay fast) and drop it when it disconnects."""
        import chaos_lib as chaos
        label = "soak-stalled"
        with self.fault_window("stalled_reader", extra_s=30):
            c = self.daemon.connect(label, "soak", start=False, timeout=60)
            o = c.call("open_project", path=str(self.master_gpr(0)))
            p = c.call("open_program", path=self.a.program, project=o["id"])
            addrs = sorted(self.baseline)[:20]
            for k in range(60):
                c.send("decompile", program=p["key"], address=addrs[k % len(addrs)], timeout=60)
            lats = []
            end = time.time() + 8
            while time.time() < end:
                t0 = time.time()
                try:
                    self.sess.call("ping")
                    lats.append(round((time.time() - t0) * 1000))
                except Exception as e:  # noqa: BLE001
                    self.report.violation("K10", "no_ping", f"while a client did not read its socket: {e}")
                    break
                time.sleep(0.4)
            chaos.abort_connection(c)
            ok = self.k10(label, phase="stalled_reader")
            if lats and max(lats) > 5000:
                self.report.violation("K10", "ping_blocked", f"a client that stopped reading made ping take {max(lats)} ms")
        self.fault_log.append({"t": round(self.t(), 1), "fault": "stalled_reader", "ping_ms_max": max(lats) if lats else None,
                               "k10": ok})
        return True

    def f_handle_holder(self):
        import chaos_lib as chaos
        i = self.pick_agent()
        if i is None:
            return False
        gpr = self.fork_gpr(i)
        if gpr is None:
            return False
        folder = next((p.parent for p, _n in oracle.version_files(gpr.with_suffix(".rep"))), None)
        if folder is None:
            return False
        secs = self.rng.uniform(1.0, 3.0)
        with self.fault_window("handle_holder", scope=i, extra_s=30):
            try:
                with chaos.HandleHolder(folder):
                    time.sleep(secs)
            except OSError as e:
                self.fault_log.append({"t": round(self.t(), 1), "fault": "handle_holder", "agent": i, "error": str(e)})
                return False
            self.file_round(f"handle_holder a{i:02d}", locks=False)
        self.fault_log.append({"t": round(self.t(), 1), "fault": "handle_holder", "agent": i, "seconds": round(secs, 1)})
        return True

    def f_backup_lane(self):
        """A backup started while the long lane is saturated runs in the maint lane (E2 + E3a, which share no
        code). Judged by what a client sees: with every long slot taken (before and after), the backup finishes
        at once and does not queue behind the long lane; the maint lane is read from ``status`` as evidence."""
        label = "soak-backup"
        sat = []
        try:
            slots = self.sup_call("status")["scheduler"]["long"]["slots"]
            for k in range(slots + 6):   # distinct clients: the per-client running cap is slots - 1
                if self.sup_call("status")["scheduler"]["long"]["inUse"] >= slots:
                    break
                c = self.daemon.connect(f"{label}-{k}", "soak", start=False, timeout=60)
                rid = c.send("script", script=str(self.scripts_dir / "SoakSleep.java"), program=None, args=["40000"])
                sat.append((c, rid))
                time.sleep(0.4)
            end = time.time() + 6
            while time.time() < end and self.sup_call("status")["scheduler"]["long"]["inUse"] < slots:
                time.sleep(0.3)
            before = self.sup_call("status")["scheduler"]
            full = before["long"]["inUse"] >= before["long"]["slots"]
            dest = self.work / "backup-test" / f"b{int(time.time())}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            o = self.sup_call("open_project", path=str(self.master_gpr(0)))
            seen = {"maint": False, "long": False}
            stop = threading.Event()

            def poll():
                while not stop.is_set():
                    with contextlib.suppress(Exception):
                        sch = self.sess.call("status")["scheduler"]
                        for lane in ("maint", "long"):
                            if any(r.get("cmd") == "fork_project" and "soak-supervisor" in str(r.get("who", ""))
                                   for r in sch[lane].get("running", [])):
                                seen[lane] = True
                    time.sleep(0.05)
            th = threading.Thread(target=poll, daemon=True)
            th.start()
            t0 = time.time()
            try:
                self.sess.call("fork_project", project=o["id"], path=str(dest), name="backup", purpose="backup",
                               open=False, verify="hash", mode="full", wait=20000)
                ms = round((time.time() - t0) * 1000)
                err = None
            except self.gs.SessionError as e:
                ms, err = round((time.time() - t0) * 1000), f"{e.code}: {e}"
            stop.set()
            th.join(2)
            after = self.sup_call("status")["scheduler"]
            with contextlib.suppress(Exception):
                self.sup_call("close_project", project=o["id"])
            still_full = after["long"]["inUse"] >= after["long"]["slots"]
            self.fault_log.append({"t": round(self.t(), 1), "fault": "backup_lane", "long_full_before": full,
                                   "long_before": {k: before["long"].get(k) for k in ("slots", "inUse", "queued")},
                                   "saturating_clients": len(sat),
                                   "long_full_after": still_full, "backup_ms": ms, "error": err,
                                   "seen_running_in": [k for k, v in seen.items() if v],
                                   "maint_admitted": [before["maint"]["admitted"], after["maint"]["admitted"]]})
            if not (full and still_full):
                self.note_gap("backup_lane: the long lane could not be kept saturated; the combined check did not run")
                return False
            if err:
                self.report.violation("E2E3a", "backup_refused", f"a backup with the long lane saturated: {err}")
            elif ms > 15000 or seen["long"]:
                self.report.violation("E2E3a", "backup_waited_for_long_lane",
                                      f"the backup took {ms} ms with the long lane saturated (seen in long: {seen['long']})")
            rmtree(dest.parent)
            return True
        finally:
            for c, rid in sat:
                with contextlib.suppress(Exception):
                    c.call("cancel", target=rid)
                with contextlib.suppress(Exception):
                    c.close()

    FAULT_FUNCS = {
        "kill_client": lambda s: s.f_kill_client(),
        "kill_daemon_random": lambda s: s.f_kill_daemon(False),
        "kill_daemon_trigger": lambda s: s.f_kill_daemon(True),
        "kill_decompiler": lambda s: s.f_kill_decompiler(),
        "suspend_daemon": lambda s: s.f_suspend_daemon(),
        "suspend_client": lambda s: s.f_suspend_client(),
        "stalled_reader": lambda s: s.f_stalled_reader(),
        "handle_holder": lambda s: s.f_handle_holder(),
        "backup_lane": lambda s: s.f_backup_lane(),
    }

    def schedule(self) -> list:
        """The deck of fault events: each class its minimum (plus a fifth more, rounded up, where a hit can
        miss), shuffled with the seed, spread over the run after a warm-up and before a cool-down."""
        mins = MIN_FAULTS[self.profile]
        deck = []
        for cls, n in mins.items():
            extra = 0 if self.profile == "smoke" else -(-n // 5)
            deck += [cls] * (n + extra)
        self.rng.shuffle(deck)
        warm = min(60.0, self.duration * 0.15)
        cool = min(60.0, self.duration * 0.15)
        span = max(1.0, self.duration - warm - cool)
        return [(warm + (k + 0.5) * span / len(deck), cls) for k, cls in enumerate(deck)]

    # ---------------------------------------------------------------------------- monitor
    def k13_note_incarnation(self):
        if self.health_samples:
            self.k13_final.append(self.health_samples[-1])
        elif self.status_samples and isinstance(self.status_samples[-1].get("waits"), dict):
            self.k13_final.append({"waits": self.status_samples[-1]["waits"]})

    def monitor_loop(self):
        last_status = 0.0
        while not self.stopping.is_set():
            time.sleep(1.0)
            if self.daemon_down.is_set() or self.sess is None:
                continue
            with contextlib.suppress(Exception):
                self.reap_agents()
            now = time.time()
            if now - last_status >= 5.0:
                last_status = now
                try:
                    with self.lock:
                        st = self.sess.call("status")
                        h = self.sess.call("health") if self.features.get("health", {}).get("present") else None
                    self.sample(st, h)
                except Exception:  # noqa: BLE001
                    pass  # a fault is going on; the fault windows and K10 judge the outage
            if self.baseline_threads is None and getattr(self, "baseline_taken_at", None) and now >= self.baseline_taken_at:
                self.take_baselines()

    def take_baselines(self):
        pid = self.daemon_pid
        self.baseline_threads = oracle.thread_count(pid)
        self.baseline_handles = oracle.handle_count(pid)

    def sample(self, st, h):
        sch = st.get("scheduler") or {}
        for lane, v in sch.items():
            if isinstance(v, dict):
                self.sample_stats["scheduler_max_queued"][lane] = max(self.sample_stats["scheduler_max_queued"].get(lane, 0),
                                                                      v.get("queued", 0))
        ab = sum(len(p.get("abandonedRequests") or []) for p in st.get("programs", []))
        self.sample_stats["abandoned_max"] = max(self.sample_stats["abandoned_max"], ab)
        self.sample_stats["clients_max"] = max(self.sample_stats["clients_max"], len(st.get("clients", [])))
        self.status_samples.append({"t": round(self.t(), 1), "waits": st.get("waits"), "memory": st.get("memory")})
        self.status_samples = self.status_samples[-200:]
        if h is not None:
            self.health_samples.append({"t": round(self.t(), 1), **h})
            self.health_samples = self.health_samples[-200:]
        for c in st.get("clients", []):
            for r in c.get("requests", []) or []:
                pass
        for pid in oracle_decompilers(self.daemon_pid):
            self.decompilers_seen.add(pid)

    # ---------------------------------------------------------------------------- plants
    def do_plants(self):
        """Violations planted into the live run (``--plant``): the run must flag every one of them."""
        plants = self.plant
        allp = plants == ["all"]
        done = []
        if allp or "K2" in plants:
            vf = next(oracle.version_files(self.canary))[0]
            (vf.parent / "db.9999.gbf").write_bytes(bytes(64))
            done.append("K2")
        if allp or "K6" in plants:
            self.canary_forks().mkdir(parents=True, exist_ok=True)
            (self.canary_forks() / "orphan.rep").mkdir(exist_ok=True)
            (self.canary_forks() / "orphan.rep" / "x").write_text("x")
            done.append("K6")
        if allp or "K9" in plants:
            f = next(self.canary.glob("*.gpr"))
            with open(f, "ab") as fh:
                fh.write(b"\n<!-- planted -->\n")
            done.append("K9")
        if allp or "K5" in plants:
            i = 0
            with open(self.agent_dir(i) / "ledger.jsonl", "ab", buffering=0) as fh:
                fh.write((json.dumps({"phase": "ack", "op": f"{i}:99999", "kind": "save", "gen": 99999, "t": time.time()})
                          + "\n").encode())
                fh.write((json.dumps({"phase": "sent", "op": f"{i}:99999", "kind": "edit", "gen": 99999, "t": time.time()})
                          + "\n").encode())
            done.append("K5")
        if allp or "BUSY" in plants:
            with open(self.agent_dir(0) / "results.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"t": round(self.t_start + 1, 3), "agent": 0, "op": "read_decompile", "lane": "quick",
                                     "ms": 1.0, "ok": False, "code": "busy", "message": "planted"}) + "\n")
            done.append("BUSY")
        if allp or "K13" in plants:
            # This replaces the health dict the drain hands to check_k13: it proves the K13 wiring (the verdict
            # names the violation), NOT that a real waits.foreignBlocked counter is read from the engine's health
            # command. That read is exercised only on an engine that has the command (VF integration check).
            self.plant_foreign_blocked = 3
            done.append("K13")
        if allp or "K7" in plants:
            import chaos_lib as chaos
            pr = chaos.spawn_decompiler(self.a.ghidra)
            chaos.suspend(pr.pid)
            self.planted_pids.append(pr)
            done.append("K7")
        if allp or "ERR" in plants:
            with open(self.agent_dir(0) / "results.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"t": round(self.t_start + 1, 3), "agent": 0, "op": "save", "lane": "maint",
                                     "ms": 1.0, "ok": False, "code": "failed", "message": "planted"}) + "\n")
            done.append("ERR")
        if allp or "WINDOW" in plants:
            # rows inside a fault window that covers every agent: an unexplained busy and an error the fault
            # cannot cause must still be flagged; a timeout is what a killed daemon causes and must be tolerated,
            # by the explicit rule of FAULT_TOLERATES, and counted
            now = time.time()
            self.windows.append({"cls": "kill_daemon_random", "scope": "all", "t0": now - 1, "t1": now + 30,
                                 "planted": True})
            with open(self.agent_dir(0) / "results.jsonl", "a", encoding="utf-8") as fh:
                for rec in (
                        {"op": "read_functions", "lane": "quick", "code": "busy", "message": "planted-window-busy"},
                        {"op": "edit", "lane": "edit", "code": "failed", "message": "IOException: planted-window-error"},
                        {"op": "read_decompile", "lane": "quick", "code": "timeout", "message": "planted-window-tolerated"}):
                    fh.write(json.dumps({"t": round(now + 0.5, 3), "agent": 0, "ms": 1.0, "ok": False, **rec}) + "\n")
            done.append("WINDOW")
        self.fault_log.append({"t": round(self.t(), 1), "planted": done})
        return done

    @staticmethod
    def window_plants_missing(viol, summ) -> list:
        """The in-window plants the classification must have flagged (busy, an error the fault cannot cause) or
        tolerated by rule (a timeout in a daemon-kill window)."""
        miss = []
        if not any(k == "unexplained_busy" and "read_functions" in d for k, d in viol):
            miss.append("WINDOW:busy_in_window_not_flagged")
        if not any(k == "unexpected_error" and d.startswith("edit:failed") for k, d in viol):
            miss.append("WINDOW:wrong_error_in_window_not_flagged")
        if not (summ.get("tolerated_in_windows") or {}).get("kill_daemon_random/read_decompile:timeout"):
            miss.append("WINDOW:timeout_in_daemon_kill_window_not_tolerated")
        if any("planted-window-tolerated" in d for _k, d in viol):
            miss.append("WINDOW:tolerated_row_was_flagged")
        return miss

    PLANT_CODES = {"K2": "K2:", "K6": "K6:", "K9": "K9:", "K5": "K5:", "BUSY": "unexplained_busy", "K13": "K13:",
                   "K7": "K7:orphan_decompiler", "ERR": "unexpected_error"}

    # ---------------------------------------------------------------------------- run
    def run(self) -> dict:
        self.t_start = time.time()
        a = self.a
        try:
            self.setup()
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            self.setup_error = self.setup_error or f"{type(e).__name__}: {e}"
            return self.finish(early=True)
        self.t_start = time.time()
        prof = PROFILES[self.profile]
        self.baseline_taken_at = time.time() + 30   # taken by the monitor, once the agents are working
        self.baseline_threads = None
        self.tmp_round("start")
        for d in (self.work / "STOP",):
            if d.exists():
                d.unlink()
        w1 = oracle.HeaderWatcher(self.agents_dir, prof["watcher_s"]).start()
        w2 = oracle.HeaderWatcher(self.masters_dir, max(0.5, prof["watcher_s"] * 5)).start()
        self.watchers = [w1, w2]
        for i in range(self.agents):
            self.spawn_agent(i)
        mon = threading.Thread(target=self.monitor_loop, daemon=True, name="monitor")
        mon.start()
        deck = [] if self.a.no_faults else self.schedule()
        t_round = time.time() + prof["round_s"]
        t_plant = self.t_start + self.duration * 0.55 if self.plant else None
        planted = False
        try:
            while not self.stopping.is_set() and self.t() < self.duration:
                if deck and self.t() >= deck[0][0]:
                    _when, cls = deck.pop(0)
                    self.attempts[cls] += 1
                    try:
                        hit = bool(self.FAULT_FUNCS[cls](self))
                    except Exception as e:  # noqa: BLE001
                        hit = False
                        self.fault_log.append({"t": round(self.t(), 1), "fault": cls, "harness_error": f"{type(e).__name__}: {e}"})
                        self.extra_viol.append(("fault_harness_error", f"{cls}: {type(e).__name__}: {e}"))
                    if hit:
                        self.hits[cls] += 1
                    continue
                if t_plant and not planted and time.time() >= t_plant:
                    self.do_plants()
                    planted = True
                if time.time() >= t_round and not self.daemon_down.is_set():
                    t_round = time.time() + prof["round_s"]
                    self.periodic_round()
                time.sleep(0.5)
            if deck:
                self.cut_short = self.cut_short or f"{len(deck)} scheduled fault(s) did not start before the run ended"
        except KeyboardInterrupt:
            self.cut_short = "interrupted"
        except Exception as e:  # noqa: BLE001
            self.cut_short = f"supervisor error: {type(e).__name__}: {e}"
            self.extra_viol.append(("supervisor_error", f"{type(e).__name__}: {e}"))
        return self.finish()

    def periodic_round(self):
        rep = oracle.Report("periodic")
        self.guard.check(rep)
        try:
            self.sess.call("ping")
        except Exception as e:  # noqa: BLE001
            rep.violation("K10", "no_ping", f"periodic: {e}")
        self.merge(rep, "periodic")
        self.tmp_round("periodic")

    def finish(self, early: bool = False) -> dict:
        """Drain, the quiescent oracle, the verdict, the evidence, the clean-up."""
        self.stopping.set()
        (self.work / "STOP").write_text("stop")
        if not early:
            end = time.time() + 90
            while self.live_agents() and time.time() < end:
                time.sleep(0.5)
                self.reap_agents(respawn=False)
            import chaos_lib as chaos
            for i in self.live_agents():
                self.extra_viol.append(("agent_did_not_stop", f"agent {i} still running 90 s after the stop request"))
                chaos.kill_client_proc(self.procs[i]) if i in self.procs else None
            self.reap_agents(respawn=False)
        for w in self.watchers:
            w.stop()
        for w in self.watchers:
            w.report(self.report)
        rows = self.load_rows()
        if not early and self.sess is not None and not self.daemon_down.is_set():
            self.drain_checks()
        viol, summ = classify_rows(rows, self.windows, tolerated_after_s=5.0,
                                   t_span=(self.t_start, time.time()))
        self.extra_viol += viol
        # deaf and runaway scripts: bounded (a script worker of E7 would end them at their timeout)
        self.extra_viol += unbounded_script_violations(rows)
        lat = latency_table(rows, self.windows)
        if self.a.quick_p99_ms and lat["quick"]["p99_ms"] and lat["quick"]["p99_ms"] > self.a.quick_p99_ms:
            self.extra_viol.append(("quick_lane_p99", f"{lat['quick']['p99_ms']} ms above the bound {self.a.quick_p99_ms}"))
        workload = {op: sum(1 for r in rows if r["op"] == self.WORKLOAD_ROW.get(op, op) and (r.get("ok") or r.get("expected")))
                    for op in OPS if op in self.a.ops}
        res = verdict_of(self.profile, self.report, self.hits, workload, self.features, self.extra_viol,
                         self.cut_short, self.setup_error, set(self.report.checked),
                         plants_expected=[self.PLANT_CODES[p] for p in (list(self.PLANT_CODES) if self.plant == ["all"]
                                                                       else self.plant) if p in self.PLANT_CODES],
                         overrides=self.overrides)
        if self.plant and ("all" in self.plant or "WINDOW" in self.plant):
            wm = self.window_plants_missing(viol, summ)
            res["plants_missing"] = list(res["plants_missing"]) + wm
            res["plants_all_caught"] = not res["plants_missing"]
        out = {"verdict": res["verdict"], "gate_eligible": res["gate_eligible"] and self.profile != "smoke" and not self.plant,
               "profile": self.profile, "smoke_numbers_are_not_gate_numbers": self.profile == "smoke",
               "seed": self.a.seed, "agents": self.agents, "projects": self.nproj, "duration_s": round(self.t() if self.t_start else 0, 1),
               "requested_duration_s": self.duration, "profile_overrides": res["overrides"], "gaps": res["gaps"], "violations": res["violations"],
               "violation_details": self.report.findings, "runner_violations": [{"code": c, "detail": d} for c, d in self.extra_viol],
               "tolerated": self.report.tolerated, "notes": self.report.notes,
               "oracle_checks_ran": sorted(self.report.checked), "oracle_not_exercised": UNEXERCISED_CHECKS,
               "fault_hits": self.hits, "fault_attempts": self.attempts, "fault_minimums": MIN_FAULTS[self.profile],
               "fault_unavailable": UNAVAILABLE_FAULTS, "workload_unavailable": UNAVAILABLE_WORKLOAD,
               "workload_counts": workload, "row_summary": summ, "latency_ms": lat,
               "workload_counts_note": "an operation counts as run when it succeeded or failed with an EXPECTED code "
                                       "(cancelled, timeout): the deaf and burn counts include timeout/cancel results by design",
               "evidence_note": "agent.log and daemon.log can carry program and function names of a game copy (engine "
                                "error messages, up to 200 chars): keep the evidence folder off the repository",
               "features": self.features, "sample_stats": self.sample_stats, "k13_final_health": self.k13_final[-3:] +
               (self.health_samples[-1:] if self.health_samples else []),
               "agent_exits": self.rc_log[-200:], "fault_log": self.fault_log[-400:], "fault_windows": self.windows[-400:],
               "plants": {"requested": self.plant, "missing": res["plants_missing"], "all_caught": res["plants_all_caught"]},
               "engine": {"install": self.a.ghidra, "hello": self.engine_hello()},
               "runner": {"file": str(pathlib.Path(__file__).resolve()), "sha256": sha_of_file(pathlib.Path(__file__).resolve()),
                          "git": git_head(HERE)}}
        self.evidence = oracle.Evidence(self.evidence_dir)
        self.evidence.write("soak-verdict", out)
        with contextlib.suppress(Exception):
            self.evidence.report("soak-oracle-report", self.report)
        self.cleanup()
        return out

    WORKLOAD_ROW = {"edit_save": "save", "quick_script": "quick_script", "long_script": "long_script",
                    "read": "read_decompile", "cancel": "cancel", "fork": "fork", "bulk_open": "bulk_open",
                    "deaf": "deaf", "burn": "burn"}

    def engine_hello(self):
        h = (self.sess.hello if self.sess is not None else {}) or {}
        return {k: h.get(k) for k in ("hydraVersion", "ghidraVersion", "protocol", "installId", "limits")}

    def load_rows(self) -> list:
        rows = []
        for i in range(self.agents):
            p = self.agent_dir(i) / "results.jsonl"
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    with contextlib.suppress(ValueError):
                        rows.append(json.loads(line))
        return rows

    def drain_checks(self):
        """After the agents are gone: queues empty, no program owner left, no abandoned holder after
        cooperative scripts, K13, K14, bounded threads and handles, then the recovered state of every fork."""
        time.sleep(3)
        try:
            st = self.sess.call("status")
            h = self.sess.call("health") if self.features.get("health", {}).get("present") else None
        except Exception as e:  # noqa: BLE001
            self.report.violation("K10", "no_ping", f"at drain: {e}")
            return
        others = [c for c in st.get("clients", []) if c.get("id") != st.get("you")]
        for c in others:
            if c.get("requests"):
                self.report.violation("K10", "request_held", f"client {c.get('name')} still has {len(c['requests'])} request(s) after the agents exited")
        rep = oracle.Report("drain")
        oracle.check_k14(st, h, rep)
        for lane, v in (st.get("scheduler") or {}).items():
            if isinstance(v, dict) and v.get("queued"):
                rep.violation("K14", "queue_not_empty", f"lane {lane}: {v['queued']} queued after drain", None, lane=lane)
        judge_program_owners(st.get("programs", []), st.get("you"), rep)
        ab = [x for p in st.get("programs", []) for x in (p.get("abandonedRequests") or [])]
        if ab:
            rep.violation("K14", "abandoned_holder", f"{len(ab)} abandoned holder(s) after the cooperative scripts: "
                          f"{[(x.get('cmd'), x.get('abandonedMs')) for x in ab][:3]}")
        health = dict(h or {})
        if h is None:
            # no health command: the same counter is in status.waits (E3c); that is what is judged, the
            # missing command stays a named gap
            health = {"waits": st["waits"]} if isinstance(st.get("waits"), dict) else {}
        if getattr(self, "plant_foreign_blocked", 0):
            health = {"waits": {"foreignBlocked": self.plant_foreign_blocked}}
        for hs in self.k13_final + [health]:
            oracle.check_k13(hs, None, rep)
        if h is None:
            rep.note("K13", "no_health_command", "waits.foreignBlocked was read from status.waits (this engine has no health "
                     "command, E5); the gate wants the health figure, so the feature stays a named gap", None)
        # status.waits, when the engine has no health command yet, is the only place a foreign wait shows
        w = st.get("waits")
        if isinstance(w, dict):
            rep.note("K13", "status_waits_recorded", json.dumps(w)[:400], None)
        pid = self.daemon_pid
        if self.baseline_threads is not None:
            oracle.check_k7_threads(pid, self.baseline_threads, slack=16 + 4 * self.agents, rep=rep)
            oracle.check_k7_handles(pid, self.baseline_handles or 0, slack=200 + 50 * self.agents, rep=rep)
        else:
            rep.note("K7", "baseline_missing", "no thread/handle baseline was taken after the last restart", None)
        self.merge(rep, "drain")
        self.recovery_read(range(self.agents), "drain")
        for pr in self.planted_pids:
            self.holders.append(pr.pid)
        # clean stop of the daemon, then the quiescent oracle: no lock may be left
        self.k13_note_incarnation()
        with contextlib.suppress(Exception):
            self.sess.close()
        stopped = False
        with contextlib.suppress(Exception):
            stopped = self.daemon.stop(timeout=120)
        if not stopped:
            with contextlib.suppress(Exception):
                self.daemon.stop(force=True, timeout=120)
        rep2 = oracle.Report("quiescent")
        oracle.check_k7_processes([pid], settle_s=8.0, only_pids=set(self.decompilers_seen) | {p.pid for p in self.planted_pids},
                                  rep=rep2)
        self.merge(rep2, "quiescent")
        self.file_round("quiescent", quiescent=True, daemon_alive=False)
        self.tmp_round("end")

    def cleanup(self):
        import chaos_lib as chaos
        for pr in self.planted_pids:
            with contextlib.suppress(Exception):
                chaos.resume(pr.pid)
                chaos.terminate(pr.pid, 5)
        for p in list(self.procs.values()):
            if p.poll() is None:
                chaos.kill_client_proc(p)
        with contextlib.suppress(Exception):
            if self.daemon is not None and self.daemon.jvm_alive():
                self.daemon.stop(force=True, timeout=120)
        if self.a.keep_scratch:
            return
        # keep ledgers, results and logs in the evidence folder (gzip); delete the heavy trees (projects,
        # forks, backups, tmp, the daemon's state root)
        import gzip
        for i in range(self.agents):
            ad = self.agent_dir(i)
            kd = self.evidence_dir / "agents" / ad.name
            kd.mkdir(parents=True, exist_ok=True)
            for n in ("ledger.jsonl", "results.jsonl"):
                if (ad / n).exists():
                    with open(ad / n, "rb") as src, gzip.open(kd / (n + ".gz"), "wb") as dst:
                        shutil.copyfileobj(src, dst)
            for n in ("meta.json", "agent.log"):
                if (ad / n).exists():
                    shutil.copy2(ad / n, kd / n)
        with contextlib.suppress(OSError):
            shutil.copy2(self.state / f"{self.instance}.log", self.evidence_dir / "daemon.log")
        for n in ("agents", "masters", "state", "tmp", "canary", "canary-forks", "stage-src", "backup-test"):
            rmtree(self.work / n)
        if self.tree_root != self.work:
            # the masters and the agents' trees live on another volume (--master-root): "a fixture under
            # 10 GB on the volume, cleaned up" (9.17) means they go too; the folder itself only if empty
            rmtree(self.masters_dir)
            rmtree(self.agents_dir)
            with contextlib.suppress(OSError):
                self.tree_root.rmdir()


def oracle_decompilers(daemon_pid):
    try:
        import chaos_lib as chaos
        return chaos.decompilers_of(daemon_pid)
    except Exception:  # noqa: BLE001
        return []


# ================================================================================ self-test (offline)

def script_worker_present(caps, health):
    """Whether the engine has E7's killable script worker, from the names it actually advertises: the capability
    ``scriptIsolation`` at version 2 or more (``isolation:"worker"``; version 1 has no worker) or the
    ``scriptWorkers`` member of the ``health`` reply (E7's contributor). No engine advertises a capability named
    ``scriptWorker``, ``scriptWorkers`` or ``killableScripts`` (PROTOCOL-3, revision 8.6 of E6)."""
    caps = caps or {}
    try:
        iso = int(caps.get("scriptIsolation") or 0)
    except (TypeError, ValueError):
        iso = 0
    return iso >= 2 or isinstance((health or {}).get("scriptWorkers"), dict)


def selftest(work: pathlib.Path | None = None, verbose: bool = True) -> int:
    """The runner's verdict logic and the pure checks, with planted violations, no engine. Every case must
    behave as stated or the self-test fails: a runner that cannot fail is worth nothing (D48)."""
    import tempfile
    import chaos_lib as chaos  # noqa: F401  (import check)
    base = pathlib.Path(work) if work else pathlib.Path(tempfile.mkdtemp(prefix="soak-selftest-"))
    base.mkdir(parents=True, exist_ok=True)
    bad = []
    log = []

    def check(name, cond, detail=""):
        log.append((name, bool(cond)))
        if verbose:
            print(("ok   " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
        if not cond:
            bad.append(name)

    # ---- the script worker probe reads the names the engine advertises (Advertised.java, E7)
    e7_caps = {"laneHint": 1, "scriptIsolation": 2, "health": 1}
    e7_health = {"scriptWorkers": {"running": 0, "max": 4, "pids": []}}
    check("script worker: present on an E7 engine (scriptIsolation 2 and health.scriptWorkers)",
          script_worker_present(e7_caps, e7_health) and script_worker_present(e7_caps, None)
          and script_worker_present({"scriptIsolation": 1}, e7_health))
    check("script worker: absent before E7 (scriptIsolation 1, no health.scriptWorkers) and under names nobody advertises",
          not script_worker_present({"scriptIsolation": 1, "health": 1}, {"lanes": {}})
          and not script_worker_present({"scriptWorker": 1, "scriptWorkers": 1, "killableScripts": 1}, None)
          and not script_worker_present(None, None))
    adv = (HERE.parent / "src" / "main" / "java" / "ghidra" / "app" / "util" / "headless" / "session" / "Advertised.java")
    if adv.is_file():
        src = adv.read_text(encoding="utf-8")
        check("script worker: the probe's capability name is declared in Advertised.java, the names it dropped are not",
              '"scriptIsolation"' in src and not any(f'"{n}"' in src for n in ("scriptWorker", "killableScripts")))

    # ---- the pure per-agent judgement (K3, K4, K5)
    addrs = [f"0x{0x1000 + 16 * k:x}" for k in range(6)]
    baseline = {a: f"FUN_{a[2:]}" for a in addrs + ["0x9000"]}
    meta = {"addrs": addrs}

    def names_at(gen, extra=None):
        n = dict(baseline)
        for i, a in enumerate(addrs):
            n[a] = f"{tag_prefix(3)}{gen}_{i:03d}"
        n.update(extra or {})
        return n

    def ledger(gens_sent, gens_saved):
        recs = []
        for g in range(1, gens_sent + 1):
            recs.append({"phase": "sent", "op": f"3:{g}", "kind": "edit", "gen": g})
            recs.append({"phase": "ack", "op": f"3:{g}", "kind": "edit", "gen": g})
        for g in gens_saved:
            recs.append({"phase": "sent", "op": f"3:{g}", "kind": "save", "gen": g})
            recs.append({"phase": "ack", "op": f"3:{g}", "kind": "save", "gen": g})
        return recs
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, names_at(4), baseline, r)
    check("clean agent: no finding", r.ok, r.codes())
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4, 5]), meta, names_at(4), baseline, r)
    check("planted K4/K5: an acknowledged save is missing after recovery", {"K4", "K5"} <= r.ids(), r.codes())
    n = names_at(4)
    n[addrs[2]] = f"{tag_prefix(3)}3_002"
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, n, baseline, r)
    check("planted K4: an edit set from two generations", "K4:mixed_generation" in r.codes(), r.codes())
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, names_at(4, {"0x9000": "oops"}), baseline, r)
    check("planted K3: a function outside the edit set changed", "K3:names_not_allowed" in r.codes(), r.codes())
    r = oracle.Report()
    nm = names_at(4)
    del nm["0x9000"]
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, nm, baseline, r)
    check("planted K3: a function is gone", "K3:function_set_differs" in r.codes(), r.codes())
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, names_at(4, {"0x9000": f"{tag_prefix(3)}4_005"}), baseline, r)
    check("a thunk that took the name of its edited target is not a stray change", r.ok, r.codes())
    r = oracle.Report()
    judge_agent(3, ledger(5, [1, 2, 3, 4]), meta, names_at(4, {"0x9000": f"{tag_prefix(4)}4_005"}), baseline, r)
    check("planted: another agent's tag on a function outside the edit set", "K3:names_not_allowed" in r.codes(), r.codes())
    r = oracle.Report()
    judge_agent(3, ledger(6, [1, 2, 3]), meta, names_at(5), baseline, r)
    check("an unsaved generation that was persisted is allowed (acked <= G <= sent)", r.ok, r.codes())
    r = oracle.Report()
    judge_k11({3: [f"{tag_prefix(3)}4_000"], 5: [f"{tag_prefix(3)}4_000"]}, r)
    check("planted K11: another agent's tag visible in a view", "K11:unpublished_tag_visible" in r.codes(), r.codes())

    # ---- the rows
    t = time.time()
    rows = [{"t": t, "agent": 1, "op": "read_decompile", "lane": "quick", "ms": 5.0, "ok": True},
            {"t": t, "agent": 1, "op": "cancel", "lane": "long", "ms": 5.0, "ok": False, "code": "cancelled", "expected": True},
            {"t": t, "agent": 1, "op": "save", "lane": "maint", "ms": 5.0, "ok": False, "code": "busy",
             "details": {"holder": {"client": "x"}}}]
    viol, summ = classify_rows(rows, [])
    check("rows: expected cancel and explained busy are no violation", not viol and summ["busy_explained"] == 1, viol)
    rows2 = rows + [{"t": t, "agent": 1, "op": "save", "lane": "maint", "ms": 5.0, "ok": False, "code": "busy"}]
    viol, summ = classify_rows(rows2, [])
    check("planted: an unexplained busy is a violation", any(k == "unexplained_busy" for k, _ in viol), viol)
    rows3 = rows + [{"t": t, "agent": 1, "op": "save", "lane": "maint", "ms": 5.0, "ok": False, "code": "failed",
                     "message": "IOException: File error during save"}]
    viol, _ = classify_rows(rows3, [])
    check("planted: an unexpected error outside a fault window is a violation", any(k == "unexpected_error" for k, _ in viol), viol)
    viol, _ = classify_rows(rows3, [{"t0": t - 1, "t1": t + 1, "scope": 1, "cls": "handle_holder"}])
    check("the same error inside a window that covers its agent is tolerated", not viol, viol)
    viol, _ = classify_rows(rows3, [{"t0": t - 1, "t1": t + 1, "scope": 2, "cls": "kill_client"}])
    check("a window of another agent does not cover it", bool(viol), viol)
    lat = latency_table(rows + [{"t": t, "agent": 1, "op": "read_functions", "lane": "quick", "ms": 9.0, "ok": True}], [])
    check("latency table: p99 of the quick lane", lat["quick"]["p99_ms"] == 9.0 or lat["quick"]["p99_ms"] is not None)

    # ---- the verdict
    rep_ok = oracle.Report()
    full_pr = {c: MIN_FAULTS["pr"][c] for c in MIN_FAULTS["pr"]}
    feats_ok = {"health": {"present": True, "needed_for_gate": True}}
    wl = {op: 5 for op in OPS}
    v = verdict_of("smoke", rep_ok, dict(MIN_FAULTS["smoke"]), wl, feats_ok, [], None, None, set())
    check("smoke with every minimum hit and no violation: SMOKE-OK, never PASS", v["verdict"] == "SMOKE-OK" and not v["gate_eligible"], v)
    v = verdict_of("smoke", rep_ok, {}, wl, feats_ok, [], None, None, set())
    check("smoke with no fault fired: INCOMPLETE", v["verdict"] == "INCOMPLETE", v)
    v = verdict_of("pr", rep_ok, full_pr, wl, feats_ok, [], None, None, set())
    check("a gate profile that cannot run the Hydralysis side is INCOMPLETE, not PASS (gaps are named)",
          v["verdict"] == "INCOMPLETE" and any("publish" in g for g in v["gaps"]), v["verdict"])
    r = oracle.Report()
    r.violation("K2", "newest_header_invalid", "x")
    v = verdict_of("pr", r, full_pr, wl, feats_ok, [], None, None, set())
    check("a violation: FAIL", v["verdict"] == "FAIL", v)
    v = verdict_of("smoke", rep_ok, dict(MIN_FAULTS["smoke"]), wl, feats_ok, [("agent_lost", "x")], None, None, set())
    check("a runner criterion broken (a lost agent): FAIL", v["verdict"] == "FAIL", v)
    v = verdict_of("smoke", rep_ok, dict(MIN_FAULTS["smoke"]), wl,
                   {"health": {"present": False, "needed_for_gate": True, "why": "no health"}}, [], None, None, set())
    check("smoke without the health command: still SMOKE-OK but the feature is listed as a gap",
          v["verdict"] == "SMOKE-OK" and any("health" in g for g in v["gaps"]), v)
    v = verdict_of("pr", rep_ok, full_pr, wl, {"health": {"present": False, "needed_for_gate": True, "why": "no health"}},
                   [], None, None, set())
    check("pr without the health command: gap named, never PASS", v["verdict"] != "PASS" and any("health" in g for g in v["gaps"]), v)
    v = verdict_of("smoke", rep_ok, dict(MIN_FAULTS["smoke"]), wl, feats_ok, [], "interrupted", None, set())
    check("a run cut short: INCOMPLETE", v["verdict"] == "INCOMPLETE", v)
    v = verdict_of("smoke", rep_ok, dict(MIN_FAULTS["smoke"]), {**wl, "fork": 0}, feats_ok, [], None, None, set())
    check("an operation that never ran: INCOMPLETE and named", v["verdict"] == "INCOMPLETE" and any("fork" in g for g in v["gaps"]), v)
    nightly_hits = {c: n for c, n in MIN_FAULTS["nightly"].items()}
    kills = sum(nightly_hits.get(c, 0) for c in KILL_CLASSES)
    check("nightly minimums sum to at least 150 kills", kills >= 150, kills)
    check("release minimums are not below the nightly ones", all(MIN_FAULTS["release"][c] >= MIN_FAULTS["nightly"][c] for c in MIN_FAULTS["nightly"]))
    v = verdict_of("smoke", r, dict(MIN_FAULTS["smoke"]), wl, feats_ok, [], None, None, set(), plants_expected=["K2:", "K9:"])
    check("planted violations: a plant the run did not catch is named", v["plants_missing"] == ["K9:"] and v["plants_all_caught"] is False, v)

    # ---- the fault windows tolerate only what the fault can cause
    wall = {"t0": t - 1, "t1": t + 1, "scope": "all", "cls": "kill_daemon_random"}
    brow = {"t": t, "agent": 2, "op": "read_decompile", "lane": "quick", "ms": 5.0, "ok": False, "code": "busy"}
    viol, _ = classify_rows(rows + [brow], [wall])
    check("planted: an unexplained busy INSIDE an all-scope window is still a violation",
          any(k == "unexplained_busy" for k, _ in viol), viol)
    frow = {"t": t, "agent": 2, "op": "edit", "lane": "edit", "ms": 5.0, "ok": False, "code": "failed", "message": "boom"}
    viol, _ = classify_rows(rows + [frow], [wall])
    check("planted: an error a daemon kill cannot cause is a violation inside its window",
          any(k == "unexpected_error" for k, _ in viol), viol)
    trow = {"t": t, "agent": 2, "op": "read_decompile", "lane": "quick", "ms": 5.0, "ok": False, "code": "timeout"}
    viol, summ = classify_rows(rows + [trow], [wall])
    check("a timeout inside a daemon-kill window is tolerated by rule and counted",
          not viol and summ["tolerated_in_windows"] == {"kill_daemon_random/read_decompile:timeout": 1}, (viol, summ))
    # a killed native decompiler fails the one decompile that used it with decompiler_failed (3.11, E9 A36; a protocol 3
    # client): tolerated inside a kill_decompiler window, an unexpected error outside it and for any other fault class
    wdec = {"t0": t - 1, "t1": t + 1, "scope": "all", "cls": "kill_decompiler"}
    drow = {"t": t, "agent": 2, "op": "read_decompile", "lane": "quick", "ms": 3.0, "ok": False, "code": "decompiler_failed",
            "message": "the native decompiler failed on FUN_1: Exception while decompiling 1: pipe is being closed; "
                       "this request failed alone, retry"}
    viol, summ = classify_rows(rows + [drow], [wdec])
    check("decompiler_failed of read_decompile inside a kill_decompiler window is tolerated and counted",
          not viol and summ["tolerated_in_windows"] == {"kill_decompiler/read_decompile:decompiler_failed": 1}, (viol, summ))
    viol, _ = classify_rows(rows + [drow], [])
    check("planted: decompiler_failed outside any window is an unexpected error",
          any(k == "unexpected_error" and "decompiler_failed" in d for k, d in viol), viol)
    viol, _ = classify_rows(rows + [drow], [wall])
    check("planted: decompiler_failed inside a daemon-kill window (not a decompiler kill) is an unexpected error",
          any(k == "unexpected_error" for k, _ in viol), viol)
    viol, _ = classify_rows(rows + [dict(trow, t=t + 100)], [wall])
    check("the same timeout after the window is a violation", bool(viol), viol)
    viol, _ = classify_rows(rows + [dict(frow, message="IOException: File error during save", op="save")],
                            [dict(wall, cls="handle_holder")])
    check("a failed save with an IOException in a handle-holder window is tolerated", not viol, viol)
    viol, _ = classify_rows(rows + [dict(frow, message="IOException: x", op="read_decompile")], [dict(wall, cls="handle_holder")])
    check("a handle holder does not excuse a failed read", bool(viol), viol)
    viol, _ = classify_rows(rows + [dict(frow, message="boom", op="save")], [dict(wall, cls="handle_holder")])
    check("a handle holder does not excuse a failed save whose message is not a file error", bool(viol), viol)
    sh = window_share([{"t0": 10, "t1": 20, "scope": "all"}, {"t0": 15, "t1": 30, "scope": "all"},
                       {"t0": 50, "t1": 60, "scope": 3}], 0.0, (0, 100))
    check("window share: union of the all-scope windows over the run (the scope-agent window excluded)",
          abs(sh - 0.22) < 1e-6, sh)  # 8..30 = 22 s of 100
    wl2 = [{"cls": "kill_daemon_random", "scope": "all", "t0": 100 * k, "t1": 100 * k + 30} for k in range(3)]
    check("window share of three 30 s windows with a 45 s margin in 600 s is 3 x 77 s / 600 s",
          abs(window_share(wl2, 45.0, (0, 600)) - 0.385) < 0.01, window_share(wl2, 45.0, (0, 600)))
    pr_sched = Soak.__new__(Soak)
    pr_sched.profile, pr_sched.duration, pr_sched.rng = "pr", 600, random.Random(1)
    check("the pr schedule fires at least the minimum of every class",
          len(pr_sched.schedule()) >= sum(MIN_FAULTS["pr"].values()))

    # ---- program owners at the drain (K7)
    r = oracle.Report()
    judge_program_owners([{"path": "/a.exe", "owner": 7, "users": []}], 1, r)
    check("planted K7: an owner with an empty users list is a leaked owner", "K7:program_owner_left" in r.codes(), r.codes())
    r = oracle.Report()
    judge_program_owners([{"path": "/a.exe", "owner": None, "users": [9]}], 1, r)
    check("planted K7: users and no owner is a separate leak", "K7:program_user_left" in r.codes(), r.codes())
    r = oracle.Report()
    judge_program_owners([{"path": "/a.exe", "owner": None, "users": [1]}, {"path": "/b.exe", "owner": None, "users": []},
                          {"path": "/c.exe"}], 1, r)
    check("no owner and nobody but the supervisor: clean", r.ok, r.codes())

    # ---- a profile that was shrunk is not a gate run
    check("no override for the profile's own numbers", profile_overrides("pr", 4, 2, 600, list(OPS)) == [])
    check("every override is named", len(profile_overrides("pr", 1, 1, 60, ["read"])) == 4)
    saved = (dict(UNAVAILABLE_FAULTS), dict(UNAVAILABLE_WORKLOAD), dict(UNEXERCISED_CHECKS))
    UNAVAILABLE_FAULTS.clear(), UNAVAILABLE_WORKLOAD.clear(), UNEXERCISED_CHECKS.clear()
    try:
        v = verdict_of("pr", rep_ok, full_pr, wl, feats_ok, [], None, None, set())
        check("with no gap left a full pr run can PASS (so the override tests below are meaningful)",
              v["verdict"] == "PASS" and v["gate_eligible"], v)
        for ov in (profile_overrides("pr", 1, 2, 600, list(OPS)), profile_overrides("pr", 4, 1, 600, list(OPS)),
                   profile_overrides("pr", 4, 2, 60, list(OPS)), profile_overrides("pr", 4, 2, 600, ["read"])):
            v = verdict_of("pr", rep_ok, full_pr, wl, feats_ok, [], None, None, set(), overrides=ov)
            check(f"planted: a shrunk gate run ({ov[0][:14]}) is SMOKE-OK, never PASS, and not gate eligible",
                  v["verdict"] == "SMOKE-OK" and not v["gate_eligible"] and any("overridden" in g for g in v["gaps"]), v)
        v = verdict_of("pr", rep_ok, full_pr, wl, feats_ok, [("agent_lost", "x")], None, None, set(),
                       overrides=["--agents 1"])
        check("a shrunk run with a violation is still FAIL", v["verdict"] == "FAIL", v)
        # the nightly "at least 150 kills" rule on its own (the per-class minimums lowered so that they allow fewer)
        saved_min = dict(MIN_FAULTS["nightly"])
        MIN_FAULTS["nightly"] = {c: 1 for c in saved_min}
        try:
            v = verdict_of("nightly", rep_ok, {c: 30 for c in saved_min}, wl, feats_ok, [], None, None, set())
            check("nightly: fewer than 150 kills in all is INCOMPLETE on that rule alone",
                  v["verdict"] == "INCOMPLETE" and any("nightly kills" in g for g in v["hard_gaps"]), v)
            v = verdict_of("nightly", rep_ok, {**{c: 30 for c in saved_min}, "kill_client": 100, "kill_decompiler": 30},
                           wl, feats_ok, [], None, None, set())
            check("nightly: 150 or more kills lift that rule", not any("nightly kills" in g for g in v["hard_gaps"]), v)
        finally:
            MIN_FAULTS["nightly"] = saved_min
    finally:
        UNAVAILABLE_FAULTS.update(saved[0]), UNAVAILABLE_WORKLOAD.update(saved[1]), UNEXERCISED_CHECKS.update(saved[2])
    check("planted: a deaf script that ran 60 s for a 1 s script is unbounded",
          [c for c, _ in unbounded_script_violations([{"op": "deaf_wall", "ms": 61000, "natural_ms": 1000}])] == ["script_unbounded"])
    check("a script inside its bound is not",
          not unbounded_script_violations([{"op": "burn_wall", "ms": 5000, "natural_ms": 1000}, {"op": "save", "ms": 99999}]))

    # ---- the agent monitor must not respawn an agent the fault thread is killing (a race found in review)
    class _Dead:
        pid = 0

        def poll(self):
            time.sleep(0)       # lets the churn thread run in the middle of an iteration
            return 137

    def stub_soak():
        sk = Soak.__new__(Soak)
        sk.procs, sk.no_respawn, sk.killed_agents = {1: _Dead()}, set(), set()
        sk.reap_lock, sk.stopping, sk.daemon_down = threading.RLock(), threading.Event(), threading.Event()
        sk.rc_log, sk.setup_failures, sk.windows, sk.extra_viol = [], {}, [], []
        sk.t_start, sk.duration, sk.spawned, sk.agents_dir = time.time(), 600, [], base / "agents"
        sk.spawn_agent = lambda i: sk.spawned.append(i)
        return sk
    sk = stub_soak()
    sk._reap_agents(True)
    check("an exited agent nobody is killing is respawned (control)", sk.spawned == [1], sk.spawned)
    sk = stub_soak()
    sk.killed_agents.add(1)
    sk._reap_agents(True)
    check("planted race: an agent that f_kill_client is killing is NOT respawned by the monitor", sk.spawned == [], sk.spawned)
    sk = stub_soak()
    sk.no_respawn.add(1)
    sk._reap_agents(True)
    check("an agent whose setup failed three times is not respawned", sk.spawned == [], sk.spawned)
    sk = stub_soak()
    sk.procs = {k: _Dead() for k in range(40)}
    stop_flag = threading.Event()

    def churn():
        k = 1000
        while not stop_flag.is_set():
            for j in range(20):
                sk.procs[k + j] = _Dead()
            for j in range(20):
                sk.procs.pop(k + j, None)
            k += 100
    th = threading.Thread(target=churn, daemon=True)
    th.start()
    live_ok = True
    old_si = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    t_end = time.time() + 0.5
    try:
        while time.time() < t_end:
            sk.live_agents()
    except RuntimeError:
        live_ok = False
    finally:
        sys.setswitchinterval(old_si)
    stop_flag.set()
    th.join(2)
    check("live_agents iterates a snapshot (no 'dict changed size' while another thread mutates procs)", live_ok)

    # ---- f_kill_client: a kill that did not terminate the process leaves the agent alone (no second process on its ledger)
    import chaos_lib as _chaos  # noqa: PLC0415

    class _Alive:
        pid = 0

        def poll(self):
            return None
    saved_kill = _chaos.kill_client_proc
    try:
        for answer, label, want_spawn in (({"terminated": False}, "not terminated", []),
                                          ({"terminated": True}, "terminated", [1])):
            _chaos.kill_client_proc = lambda _p, _a=answer: dict(_a)
            sk = stub_soak()
            p_alive = _Alive()
            sk.procs = {1: p_alive}
            sk.fault_log, sk.tolerated = [], []
            sk.pick_agent = lambda: 1
            sk.k10 = lambda *a, **k: True
            sk.file_round = lambda *a, **k: None
            sk.recovery_read = lambda *a, **k: None
            got = sk.f_kill_client()
            if label == "not terminated":
                check("a kill_client that did not terminate the process: not counted, the agent is neither popped nor respawned",
                      got is False and sk.procs.get(1) is p_alive and sk.spawned == [], (got, sk.procs, sk.spawned))
            else:
                check("control: a kill_client that terminated the process is counted and the agent respawned",
                      got is True and sk.spawned == want_spawn, (got, sk.spawned))
    finally:
        _chaos.kill_client_proc = saved_kill

    # ---- --master-root: the run removes <root>/masters and <root>/agents at its end, so a folder with content is refused
    import argparse as _ap  # noqa: PLC0415
    mr = base / "master-root-full"
    (mr / "masters").mkdir(parents=True, exist_ok=True)
    (mr / "masters" / "keep.txt").write_text("x")
    emp = base / "work-empty"
    emp.mkdir(exist_ok=True)
    sk = Soak.__new__(Soak)
    sk.work, sk.tree_root, sk.a = emp, mr, _ap.Namespace(master_root=str(mr), reuse_work=False)
    try:
        sk.setup()
        refused = False
    except SystemExit as e:
        refused = "--master-root" in str(e)
    check("a --master-root with content is refused before anything is written, and nothing in it is touched",
          refused and (mr / "masters" / "keep.txt").exists())

    # ---- agent_main and the generation it saves (found live: a respawned agent saved an edit it never made)
    global load_gs
    real_load_gs = load_gs

    class _FakeErr(Exception):
        def __init__(self, code, message="", details=None):
            super().__init__(code)
            self.code, self.message, self.details = code, message, details or {}

    class _FakeSession:
        def __init__(self, log):
            self.log = log

        def call(self, cmd, **f):
            self.log.append((cmd, f))
            return {"open_project": {"id": "m1"}, "fork_project": {"project": "p1"}, "open_program": {"key": "k1"},
                    "functions": {"functions": [], "truncated": False}}.get(cmd, {})

        def close(self):
            pass

    class _FakeDaemon:
        log: list = []

        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return _FakeSession(_FakeDaemon.log)

    class _FakeGs:
        SessionError = _FakeErr
        Daemon = _FakeDaemon
    load_gs = lambda _g: _FakeGs  # noqa: E731

    def run_agent(tag, ledger_rows, ops, seconds, seed):
        ad = base / f"agent-{tag}"
        if ad.exists():
            rmtree(ad)
        ad.mkdir(parents=True)
        (ad / "meta.json").write_text(json.dumps({"addrs": ["0x1000", "0x1010"], "prefix": tag_prefix(0), "functions": 2}))
        led_ = oracle.Ledger(ad / "ledger.jsonl")
        for kind, g, ph in ledger_rows:
            (led_.sent if ph == "sent" else led_.ack)(f"0:{g}", kind=kind, gen=g)
        led_.close()
        _FakeDaemon.log = []
        spec = {"ghidra": "-", "state": "-", "instance": "-", "index": 0, "dir": str(ad), "seed": seed, "label": "soak-a00",
                "program": "/p.exe", "stop_file": str(ad / "stop"), "deadline": time.time() + seconds, "caps": {}, "scripts": {},
                "master": "m", "ops": ops, "agents": 1, "edit_m": 2}
        (ad / "spec.json").write_text(json.dumps(spec))
        rc = agent_main(str(ad / "spec.json"))
        return rc, oracle.Ledger.read(ad / "ledger.jsonl"), list(_FakeDaemon.log)
    try:
        # a respawned agent: gens 1-3 were edited, 1-2 saved, the 3rd edit died with the killed client
        prior = [("edit", 1, "ack"), ("save", 1, "ack"), ("edit", 2, "ack"), ("save", 2, "ack"), ("edit", 3, "ack")]
        rc, recs, cmds = run_agent("respawn-fork", prior, ["fork"], 0.6, 1)
        saves = [r for r in recs if r.get("kind") == "save" and r.get("gen") == 3]
        check("a respawned agent that forks does not save the edit its dead incarnation made (no false K4/K5)",
              rc == 0 and not saves and not any(c == "save" for c, _f in cmds) and any(c == "fork_project" for c, _f in cmds),
              (rc, saves, [c for c, _f in cmds][:12]))
        rc, recs, cmds = run_agent("respawn-edit", prior, ["edit_save", "fork"], 1.5, 2)
        edited = {r["gen"] for r in recs if r.get("kind") == "edit" and r.get("phase") == "ack"} - {1, 2, 3}
        saved = {r["gen"] for r in recs if r.get("kind") == "save" and r.get("phase") == "ack"}
        check("every generation this incarnation saves is one it edited itself (control: it edited and saved some)",
              rc == 0 and bool(edited) and bool(saved - {1, 2}) and (saved - {1, 2}) <= edited, (rc, edited, saved))
    finally:
        load_gs = real_load_gs

    # ---- the oracle plumbing the runner uses, on a synthetic tree (clean, then planted)
    root = base / "tree"
    if root.exists():
        rmtree(root)
    db = root / "p0" / "x.rep" / "idata" / "00" / "~00000000.db"
    db.mkdir(parents=True)
    (root / "p0" / "x.gpr").write_text("<PROJECT/>")
    for n in (1, 2):
        (db / f"db.{n}.gbf").write_bytes(oracle.MAGIC + bytes(64))
    guard = oracle.TreeGuard(p0=root / "p0")
    rep = oracle.Report()
    oracle.check_k2(root / "p0", rep)
    oracle.check_k6(root / "p0" / "x.gpr", require_sidecar=False, rep=rep)
    guard.check(rep)
    check("clean tree: K2, K6, K9 pass", rep.ok, rep.codes())
    (db / "db.3.gbf").write_bytes(bytes(72))
    rep = oracle.Report()
    oracle.check_k2(root / "p0", rep)
    check("planted X1: a zero-header newest version file", "K2:newest_header_invalid" in rep.codes(), rep.codes())
    (db / "db.3.gbf").unlink()
    (root / "orphan.rep").mkdir()
    rep = oracle.Report()
    oracle.check_k6(root / "orphan.gpr", require_sidecar=False, rep=rep)
    check("planted X7: a .rep without its .gpr", "K6:rep_without_gpr" in rep.codes(), rep.codes())
    (root / "p0" / "x.gpr").write_text("<PROJECT/>\n<!-- changed -->")
    rep = oracle.Report()
    guard.check(rep)
    check("planted K9: an uninvolved project changed", "K9:uninvolved_project_changed" in rep.codes(), rep.codes())
    w = oracle.HeaderWatcher(root, 0.02).start()
    time.sleep(0.2)
    (db / "db.4.gbf").write_bytes(bytes(40))
    time.sleep(0.3)
    w.stop()
    rep = w.report()
    check("planted: a visible invalid final-named version file is caught by the watcher", "K2:visible_invalid_header" in rep.codes(), rep.codes())
    pr = chaos.spawn_decompiler  # not started here: needs an install; the live plant K7 covers it
    check("the injectors are importable", callable(pr))
    # ---- helpers
    check("Wilson bound after 0 of 400 is below 0.75% at 95%", wilson_upper(0, 400) < 0.0095 and wilson_upper(0, 400) > 0.0, wilson_upper(0, 400))
    check("Wilson bound after 0 of 3 is wide", wilson_upper(0, 3) > 0.4)
    check("every fault class has a function or is listed unavailable",
          all(c in Soak.FAULT_FUNCS or c in UNAVAILABLE_FAULTS for c in FAULT_CLASSES))
    check("the scripts compile as text (class names match file names)", all(f"class {n} " in s for n, s in SCRIPTS.items()))
    n_fail = len(bad)
    print(f"soak selftest: {len(log) - n_fail} of {len(log)} checks ok" + (f"; FAILED: {bad}" if bad else ""))
    if not work:
        rmtree(base)
    return 1 if bad else 0


# ================================================================================ command line

def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--agent"]:
        return agent_main(argv[1])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("selftest", help="offline: the verdict logic and the planted violations (no engine)")
    st.add_argument("--work")
    r = sub.add_parser("run", help="run a soak profile against an engine install")
    r.add_argument("--ghidra", required=True, help="the engine install under test")
    r.add_argument("--work", required=True, help="an EMPTY scratch folder (NVMe); fresh state roots are the rule")
    r.add_argument("--project", required=True, help="an analysed project (.gpr) to copy; never opened writable")
    r.add_argument("--program", required=True, help="the program inside it, e.g. /flow_fixture.exe")
    r.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    r.add_argument("--seed", type=int, default=20261101)
    r.add_argument("--agents", type=int, default=0)
    r.add_argument("--projects", type=int, default=0)
    r.add_argument("--duration-s", type=int, default=0, help="override the profile's duration (the run is then not a gate run)")
    r.add_argument("--edit-m", type=int, default=12, help="functions renamed by one edit set")
    r.add_argument("--evidence", help="folder for the evidence (default <work>/evidence; give one on E:)")
    r.add_argument("--master-root", help="put the master projects AND the agents' trees (forks, saves, ledgers) under "
                                         "this folder (a ReFS volume for the ReFS nightly run); both are deleted at "
                                         "the end. --work (state root, temp, scripts) stays where it is")
    r.add_argument("--plant", help="comma list of violations to plant into the live run and require the verdict to "
                                   "flag: K2,K6,K9,K5,K7,K13,BUSY,ERR,WINDOW or all")
    r.add_argument("--quick-p99-ms", type=float, default=0.0,
                   help="fail the run when the quick-lane p99 outside fault windows exceeds this bound "
                        "(fixed from a quiet-machine run; report-only when 0)")
    r.add_argument("--ops", default=",".join(k for k in OP_WEIGHTS), help="comma list of workload operations")
    r.add_argument("--no-faults", action="store_true",
                   help="schedule no faults (a run to prove the plumbing; the verdict then lists every fault class as missing)")
    r.add_argument("--keep-scratch", action="store_true")
    r.add_argument("--reuse-work", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest(pathlib.Path(a.work) if a.work else None)
    a.ops = [o for o in a.ops.split(",") if o]
    a.daemon_cfg = {}
    ov = profile_overrides(a.profile, a.agents or PROFILES[a.profile]["agents"], a.projects or PROFILES[a.profile]["projects"],
                           a.duration_s or PROFILES[a.profile]["duration_s"], a.ops)
    if ov and PROFILES[a.profile]["gate"]:
        print("note: this run changes the profile (" + "; ".join(ov) + "): it is not a gate run, the verdict is capped at "
              "SMOKE-OK and the overrides are listed in the gaps", file=sys.stderr)
    if not pathlib.Path(a.project).is_file():
        print(f"--project {a.project} is not a file", file=sys.stderr)
        return 2
    if sys.platform != "win32":
        print("the fault injectors are Windows-only (ctypes, NtSuspendProcess)", file=sys.stderr)
        return 2
    soak = Soak(a)
    out = soak.run()
    print(json.dumps({k: out[k] for k in ("verdict", "profile", "duration_s", "fault_hits", "gaps", "violations",
                                          "runner_violations", "plants", "latency_ms")}, indent=1, default=str))
    print("evidence:", soak.evidence.folder)
    if a.plant:
        # a planted run must be FAIL and must flag every plant: that is its success
        return 0 if (out["verdict"] == "FAIL" and out["plants"]["all_caught"]) else 1
    return {"PASS": 0, "SMOKE-OK": 0, "FAIL": 1, "INCOMPLETE": 3}[out["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
