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
and saves, quick scripts, long cooperative scripts, cancels, forks, bulk opens, analysis in a generation
candidate that is then sealed (``fork_project purpose:"generation"``, ``analyze``, ``save``, ``seal_project``;
K1 judges every seal at the end) and, rarely, deaf and runaway scripts. The 100-view out-of-memory probe
runs against the same daemon (GR8: a structured ``busy`` at ``maxViews``, never an out-of-memory error).

The Hydralysis lane (the VF integration items; on when ``--hy-binary``, ``--hy-src`` and ``--hy-python``
are given, ``soak_hy.py``): H-agents in their own processes run Hydralysis queries (decompile, xrefs,
functions), renames in their own views (``options.as``), publish, rebase and K15 rebuild probes against the
candidate engine, while the supervisor kills publish leaders mid-build and runs K11p (two sub-agents in one
real MCP server process). After the run the publish queue is drained and K1 (every sealed generation equals
its manifest), K8 (each view = its store replayed onto its base generation), K12 (``CURRENT.log``
linearisation), K15, K16 (the sequential model equals the head) and K17 (sealed records, torn log lines)
judge the Hydralysis root. Without the lane its items stay named gaps and a gate profile cannot PASS.

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
                  suspend_daemon=1, suspend_client=1, stalled_reader=1, handle_holder=1, backup_lane=1,
                  oom_probe_100_views=1),
    "pr": dict(kill_client=8, kill_daemon_random=2, kill_daemon_trigger=2, kill_decompiler=4,
               suspend_daemon=2, suspend_client=2, stalled_reader=2, handle_holder=2, backup_lane=1,
               oom_probe_100_views=1),
    "nightly": dict(kill_client=100, kill_daemon_random=15, kill_daemon_trigger=15, kill_decompiler=30,
                    suspend_daemon=12, suspend_client=12, stalled_reader=8, handle_holder=10, backup_lane=4,
                    oom_probe_100_views=3),
    "release": dict(kill_client=250, kill_daemon_random=40, kill_daemon_trigger=40, kill_decompiler=80,
                    suspend_daemon=30, suspend_client=30, stalled_reader=20, handle_holder=24, backup_lane=8,
                    oom_probe_100_views=6),
}
#: the minimums the Hydralysis lane adds (``--hy-binary``): publish leaders killed mid-build and K11p probes (two
#: sub-agents in one MCP server process)
VF_MIN_FAULTS = {
    "smoke": dict(kill_publish_leader=1, k11p_probe=1),
    "pr": dict(kill_publish_leader=2, k11p_probe=1),
    "nightly": dict(kill_publish_leader=10, k11p_probe=3),
    "release": dict(kill_publish_leader=20, k11p_probe=4),
}
#: H-agents (Hydralysis processes) per profile
HY_AGENTS = {"smoke": 2, "pr": 2, "nightly": 4, "release": 6}
#: what the engine-level runner cannot do and the packages that provide it (listed, never faked)
#: (each is run by the Hydralysis lane when it is on; without it they are named gaps)
UNAVAILABLE_FAULTS = {
    "kill_publish_leader": "a publish leader is a Hydralysis process (Y3 publish queue); needs the Hydralysis lane (--hy-binary)",
}
UNAVAILABLE_WORKLOAD = {
    "publish": "Hydralysis publish (Y3); needs the Hydralysis lane (--hy-binary)",
    "rebase": "Hydralysis rebase (Y3); needs the Hydralysis lane (--hy-binary)",
    "hydralysis_queries": "Hydralysis queries; needs the Hydralysis lane (--hy-binary)",
}
#: oracle checks that need views, lineage stores or sealed generations; a check counts as exercised when it ran
#: (``Report.checked``): K1 also runs on the engine-level sealed candidates
UNEXERCISED_CHECKS = {
    "K1": "no sealed generation was judged",
    "K8": "needs the op-log store of views (Hydralysis lane)",
    "K11p": "needs two sub-agents in one MCP server process (Hydralysis lane)",
    "K12": "needs CURRENT.log lineage (publish, Hydralysis lane)",
    "K15": "needs a view rebuilt from base + store (Hydralysis lane)",
    "K16": "needs the changeset fold of published views (Hydralysis lane)",
    "K17": "needs the sealed record store of views (Hydralysis lane)",
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
    "fork": "maint", "bulk_open": "quick", "deaf": "long", "burn": "long", "candidate": "maint",
}
OP_WEIGHTS = {"read": 30, "edit_save": 24, "quick_script": 9, "long_script": 9, "cancel": 6, "fork": 6,
              "bulk_open": 5, "deaf": 1, "burn": 1, "candidate": 2}
#: sealed candidates per agent incarnation (each is a full fork that stays until the end for K1)
CANDIDATES_MAX = 4
BUSY_EXPLAINERS = ("reason", "holder", "lane", "queue", "queued", "wanted", "resource", "slots", "running",
                   "readers", "heldMs", "waitedMs")
TAG_RX = re.compile(r"^sk(\d\d)x(\d+)_(\d+)$")
EXIT_CONN_LOST = 75
EXIT_FORK_BAD = 76


def held_retryable(details) -> bool:
    """A63 (8.15): another process holds a project file or folder: ``busy`` with ``details.reason:"file_held"`` and
    ``suggest:"retry"`` (``retryAfterMs`` 1000). The structured, retryable answer of coordinator rule 2."""
    d = details if isinstance(details, dict) else {}
    return d.get("reason") == "file_held" and (d.get("suggest") == "retry" or d.get("retryable") is True)


#: how long an agent's setup retries a file_held open (a handle-holder window is about 30-40 s)
HELD_RETRY_S = 90.0


def source_signature(folder) -> list:
    """The version files of the project(s) under ``folder``: ``[(relative path, size, mtime_ns)]``. A fork only reads
    its source, so the signature before and after a failed fork must be equal (the handle-holder excuse, rule 2)."""
    folder = pathlib.Path(folder)
    out = []
    for p, _n in oracle.version_files(folder):
        with contextlib.suppress(OSError):
            st = p.stat()
            out.append((str(p.relative_to(folder)), st.st_size, st.st_mtime_ns))
    return sorted(out)


def fork_dest_state(dest) -> str:
    """``absent`` when the destination folder holds no project (no ``.gpr``, no ``.rep``) and no staging folder;
    otherwise a short description of what is there."""
    dest = pathlib.Path(dest)
    if not dest.exists():
        return "absent"
    left = sorted(e.name for e in dest.iterdir() if e.name.endswith((".gpr", ".rep")) or oracle.STAGING.match(e.name))
    return "absent" if not left else "present: " + ",".join(left)[:200]


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
            row(op, lane_, t0, False, e.code, (e.details if isinstance(e.details, dict) else None) or None,
                expected=e.code in expect, message=(e.message or "")[:200])
            if e.code in expect:
                return None
            raise
        except (OSError, EOFError) as e:
            row(op, lane_, t0, False, "conn:" + type(e).__name__)
            raise ConnLost() from e

    def call_held(op, lane_, cmd, **fields):
        """``call`` that retries the A63 answer ``busy``/``file_held`` (another process holds a file of the project,
        retry after ``retryAfterMs`` 1000) for up to HELD_RETRY_S: the documented client reaction. Every refusal is a
        row, judged by classify_rows (explained only inside a handle_holder window of this agent)."""
        end = time.time() + HELD_RETRY_S
        while True:
            try:
                return call(op, lane_, cmd, **fields)
            except gs.SessionError as e:
                if not (e.code == "busy" and held_retryable(e.details)) or time.time() > end:
                    raise
            time.sleep(1.0)

    try:
        # ---- setup: the master read-only, my fork writable
        master = call("setup_open_master", "quick", "open_project", path=spec["master"])
        fork_dir = adir / "fork"
        fork_gpr = None
        if fork_dir.is_dir() and list(fork_dir.glob("*.gpr")):
            fork_gpr = next(fork_dir.glob("*.gpr"))
        if fork_gpr is not None:
            o = call_held("setup_open_fork", "quick", "open_project", path=str(fork_gpr), writable=True)
            pid = o["id"]
        else:
            if fork_dir.exists():
                rmtree(fork_dir)
            f = call("setup_fork", "maint", "fork_project", project=master["id"], path=str(fork_dir), mode="auto",
                     writable=True)
            pid = f["project"]
        p = call_held("setup_open_program", "quick", "open_program", path=prog, project=pid, writable=True)
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
                    expected=e.code == "cancelled", message=(e.message or "")[:200])
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
            src_before = source_signature(adir / "fork")
            try:
                f = call("fork", "maint", "fork_project", project=pid, path=str(dest), mode="auto", writable=False)
            except gs.SessionError as e:
                # what rule 2 of the handle-holder excuse needs (classify_rows): the source unchanged, the destination
                # absent, the error structured and retryable. Recorded for every failed fork, judged there
                det = e.details if isinstance(e.details, dict) else {}
                row("fork_fail_check", "maint", time.perf_counter(), True, failed_code=e.code,
                    src_unchanged=source_signature(adir / "fork") == src_before, dest_state=fork_dest_state(dest),
                    structured=bool(det), retryable=det.get("retryable") is True or held_retryable(det))
                raise
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

        cand_dir = adir / "cand"
        cand_n = max([r.get("n", 0) for r in recs if r.get("kind") == "cand"] or [0])
        cand_here = [0]
        # a candidate an earlier incarnation left unsealed (its client or daemon was killed mid-way) is opened writable
        # once, so that the engine takes over the lock the killed holder left (as a respawned agent does for its fork),
        # and then deleted (atomic rename first); a sealed one keeps its snapshot for K1
        for c in sorted(cand_dir.glob("c*")) if cand_dir.is_dir() else []:
            if not c.is_dir() or (cand_dir / f"{c.name}.seal.json").exists():
                continue
            gp = next(c.glob("*.gpr"), None)
            if gp is not None:
                t0 = time.perf_counter()
                try:
                    o = s.call("open_project", path=str(gp), writable=True)
                    s.call("close_project", project=o["id"])
                    row("cand_abandoned", "quick", t0, True, path=str(c))
                except gs.SessionError as e:
                    row("cand_abandoned", "quick", t0, True, path=str(c), note=e.code)
            gone = cand_dir / ("del-" + c.name)
            with contextlib.suppress(OSError):
                c.rename(gone)
                rmtree(gone)

        def op_candidate():
            """Analysis in a generation candidate (D38): fork the master with purpose generation, open its program
            writable, analyze, rename one function with a tag, save, close, seal. The seal is then checked from
            outside: a writable open is refused ``sealed``; the snapshot of every file taken now is what K1
            compares at the end."""
            nonlocal cand_n
            if cand_here[0] >= CANDIDATES_MAX:
                return op_read()
            cand_here[0] += 1
            cand_n += 1
            n = cand_n
            dest = cand_dir / f"c{n}"
            opid = f"{idx}:cand:{n}"
            lineage = f"L-soak{idx:02d}"
            led.sent(opid, kind="cand", n=n, path=str(dest))
            t0 = time.perf_counter()
            # the master is opened again here: bulk_open's close of the same shared project id closes this
            # agent's earlier handle of it
            mo = call("cand_master", "quick", "open_project", path=spec["master"])
            g = call("cand_fork", "maint", "fork_project", project=mo["id"], path=str(dest), name="Cand",
                     mode="auto", purpose="generation", lineage=lineage, generation=n, wait=600000)
            cp = g.get("project")
            k2 = call("cand_open", "quick", "open_program", path=prog, project=cp, writable=True)["key"]
            call("cand_analyze", "long", "analyze", program=k2, timeout=600, wait=600000)
            call("cand_edit", "edit", "edit", program=k2,
                 ops=[{"op": "rename", "address": meta["addrs"][0], "name": f"{pfx}c{n}"}])
            call("cand_save", "maint", "save", program=k2)
            call("cand_close", "quick", "close_program", program=k2)
            call("cand_close_project", "quick", "close_project", project=cp)
            sealed = call("cand_seal", "maint", "seal_project", project=g["gpr"], lineage=lineage)
            refused = None
            try:
                s.call("open_project", path=g["gpr"], writable=True)
                refused = "opened"
            except gs.SessionError as e:
                refused = e.code
            snap = oracle.seal_snapshot(dest)
            (cand_dir / f"c{n}.seal.json").write_text(json.dumps({"gpr": g["gpr"], "dir": str(dest), "snapshot": snap,
                                                                 "revision": sealed.get("revision")}), encoding="utf-8")
            led.ack(opid, kind="cand", n=n, path=str(dest))
            row("candidate", "maint", t0, refused == "sealed", None if refused == "sealed" else "writable_open_not_refused",
                refused=refused)

        table = {"read": op_read, "edit_save": op_edit_save, "quick_script": op_quick_script,
                 "long_script": op_long_script, "cancel": op_cancel, "fork": op_fork, "bulk_open": op_bulk_open,
                 "deaf": op_deaf, "burn": op_burn, "candidate": op_candidate}
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


def fork_holder_excused(w: dict, r: dict, check) -> bool:
    """Coordinator rule 2 (9.17): a ``fork`` that fails because the handle-holder fault holds its source is excused
    only when the failure is a structured, retryable error, it happened inside that fault window (the caller checks
    the window and the agent), the source is unchanged and the destination is absent (or swept). ``check`` is the
    agent's ``fork_fail_check`` row for this failure (None when it has none: then nothing is excused)."""
    if w.get("cls") != "handle_holder" or r.get("op") != "fork" or not check:
        return False
    return bool(check.get("structured") and check.get("retryable") and check.get("src_unchanged")
                and check.get("dest_state") == "absent")


def _window_tolerates(w: dict, r: dict, check=None) -> bool:
    if fork_holder_excused(w, r, check):
        return True
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
    checks = {}
    for r in rows:
        if r.get("op") == "fork_fail_check":
            checks.setdefault(r["agent"], []).append(r)

    def check_of(r):
        if r.get("op") != "fork":
            return None
        return next((c for c in checks.get(r["agent"], []) if 0 <= c["t"] - r["t"] <= 5), None)

    def held_window(r):
        if not held_retryable(r.get("details")):
            return None
        for w in windows:
            if w.get("cls") == "handle_holder" and w["t0"] - 2 <= r["t"] <= w["t1"] + tolerated_after_s                     and w["scope"] in ("all", r["agent"]):
                if r.get("op") == "fork" and not fork_holder_excused(w, r, check_of(r)):
                    continue
                return w
        return None

    def tolerating(r):
        for w in windows:
            if w["t0"] - 2 <= r["t"] <= w["t1"] + tolerated_after_s and w["scope"] in ("all", r["agent"]) \
                    and _window_tolerates(w, r, check_of(r)):
                return w
        return None
    viol, unexpected, busy_ok, busy_bad = {}, 0, 0, 0
    tolerated = {}
    for r in rows:
        if r.get("ok") or r.get("expected") or r["op"] in ("deaf_wall", "burn_wall", "ready"):
            continue
        code = r.get("code") or ""
        if code == "busy" and (r.get("details") or {}).get("reason") == "file_held":
            # A63: a held file is excused only as coordinator rule 2 says: structured and retryable, inside a
            # handle_holder window of this agent, and for a fork the source unchanged and the destination absent
            w = held_window(r)
            if w is not None:
                key = f"handle_holder/{r['op']}:busy:file_held"
                tolerated[key] = tolerated.get(key, 0) + 1
            else:
                unexpected += 1
                viol.setdefault(("unexpected_error", f"{r['op']}:busy:file_held"), []).append(r)
            continue
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


def profile_minimums(profile: str, hy_enabled: bool) -> dict:
    """The fault minimums of a profile, with the Hydralysis lane's when it runs."""
    return {**MIN_FAULTS[profile], **(VF_MIN_FAULTS[profile] if hy_enabled else {})}


def verdict_of(profile: str, rep: oracle.Report, hits: dict, workload: dict, features: dict, extra_viol: list,
               cut_short: str | None, setup_error: str | None, ran_checks: set, plants_expected=(),
               overrides=(), hy_enabled: bool = False) -> dict:
    """The verdict from the facts of a run. ``extra_viol`` are (code, detail) pairs of the runner's own
    criteria (unexpected errors, a lost agent, ...), ``hits`` the fault classes fired.

    ``hard`` gaps (a setup error, a run cut short, a fault class below its minimum, an operation that never
    ran) make any profile INCOMPLETE. ``soft`` gaps (a feature or a check that belongs to a package that has
    not landed, or to the Hydralysis side) make a gate profile INCOMPLETE and are only listed for ``smoke``."""
    gate = PROFILES[profile]["gate"]
    mins = profile_minimums(profile, hy_enabled)
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
    # the VF items: with the Hydralysis lane on, each must have run (a hard gap otherwise); without it, each is a
    # named soft gap that keeps a gate profile from PASS
    for cls, why in UNAVAILABLE_FAULTS.items():
        if not hy_enabled:
            soft.append(f"fault class {cls}: not run here ({why})")
    for op, why in UNAVAILABLE_WORKLOAD.items():
        if hy_enabled:
            if not workload.get(op):
                hard.append(f"workload {op}: never ran")
        else:
            soft.append(f"workload {op}: not run here ({why})")
    for k, why in UNEXERCISED_CHECKS.items():
        if k in ran_checks:
            continue
        if hy_enabled:
            hard.append(f"oracle {k}: never ran")
        else:
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


# ================================================================================ the Hydralysis lane (VF items): judgement
# (pure functions over files and rows, so the self-test can plant violations into them)

#: the outcomes of a decided changeset that keep its records (``soak_hy.PUBLISH_DONE``)
HY_PUBLISH_DONE = ("applied", "rebased", "converged", "skipped")
#: H-agent operations, by workload item
HY_QUERY_OPS = ("hy_decompile", "hy_xrefs", "hy_functions")
GEN_DIR_RX = re.compile(r"^\d{4}$")


def hy_default_name(subject: str, base_names: dict) -> str | None:
    addr = subject.split(":", 1)[1] if subject.startswith("address:") else subject
    return base_names.get(addr)


def hy_model_records(changeset: dict) -> list:
    """A Hydralysis changeset (``pending/<csid>.json``) as model records ``{id, seq, subject, field, before, after}``:
    one per effect of each record (store v3)."""
    out = []
    for r in changeset.get("records", []):
        for e in r.get("effects") or []:
            out.append({"id": r["id"], "seq": r.get("seq", 0), "subject": e["subject"], "field": e["field"],
                        "before": e.get("before"), "after": e.get("after")})
    return out


def hy_effective_chain(lines) -> list:
    """The ``CURRENT.log`` lines that the head rests on: a ``rollback`` line returns to an earlier generation, so the
    lines after that generation are dropped from the chain (``views.reconcile``)."""
    chain = []
    for ln in lines:
        if ln.get("reason") == "rollback":
            chain = [c for c in chain if (c.get("gen") or 0) <= (ln.get("gen") or 0)]
            continue
        chain.append(ln)
    return chain


def hy_state_at(chain, changesets: dict, base_state: dict, gen=None) -> dict:
    """The model state after folding the chain's changesets up to generation ``gen`` (all when None)."""
    m = oracle.Model(base_state)
    for ln in chain:
        if gen is not None and (ln.get("gen") or 0) > gen:
            break
        for cs in ln.get("csids", []):
            if cs in changesets:
                m.apply_changeset(changesets[cs]["records"])
    return m.state


def hy_lineages(root) -> list:
    lr = pathlib.Path(root) / "lineages"
    return sorted(p for p in lr.glob("L-*") if p.is_dir()) if lr.is_dir() else []


def judge_hy_store(root, base_names: dict, acked_csids, views: dict, head_names: dict | None,
                   engine_logs=(), rep: oracle.Report | None = None) -> oracle.Report:
    """K1, K8, K12, K16 and K17 over a Hydralysis root after the run.

    ``views`` is ``{agent id: {"view_key", "base": {"generation"}, "names": {addr: name}}}`` (``soak_hy facts``),
    ``head_names`` the head as a view without edits shows it, ``acked_csids`` the changesets the H-agents' ledgers
    acknowledged with a generation, ``base_names`` the names of generation 0 (``soak_hy setup``)."""
    rep = rep or oracle.Report("hy")
    root = pathlib.Path(root)
    acked = set(acked_csids)
    known = set()
    sealed_gprs = []
    for lin in hy_lineages(root):
        lg = oracle.load_lineage(lin)
        lines = [o for (_off, o, _b) in lg["log"]["lines"]]
        mine = {cs for ln in lines for cs in ln.get("csids", [])}
        here = {c for c in acked if c in mine or c in lg["pending"] or c in lg["done"]}
        known |= here
        oracle.check_k12(lg, sorted(here), rep)
        # K17: every sealed record of the lineage (the leader label publish.leader.json is not one) and its log
        for sub in ("pending", "done", "declined", "failures", "views"):
            if (lin / sub).is_dir():
                oracle.check_k17(lin / sub, None, rep)
        oracle.check_k17(None, lin / "CURRENT.log", rep)
        # K1: every sealed generation equals its manifest (abandoned candidates, gen/NNNN.abandoned-*, are not)
        for g in sorted(p for p in (lin / "gen").glob("*") if p.is_dir() and GEN_DIR_RX.match(p.name)) \
                if (lin / "gen").is_dir() else []:
            mp = g / "MANIFEST.json"
            if not mp.is_file():
                if any(ln.get("gen") == int(g.name) for ln in lines):
                    rep.violation("K1", "generation_without_manifest", f"{lin.name}/gen/{g.name} is named by CURRENT.log "
                                  "and has no MANIFEST.json", g)
                continue
            try:
                man = json.loads(mp.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                rep.violation("K1", "manifest_unreadable", f"{mp}: {e}", mp)
                continue
            oracle.verify_manifest(man, rep, mp)
            oracle.check_k1(g, oracle.manifest_snapshot(man), rep, label=f"{lin.name}/gen/{g.name}")
            sealed_gprs += [str(x) for x in g.glob("*.gpr")]
        # K16: the model folds the chain's changesets in log order and equals the head
        changesets = {cs: {"records": hy_model_records(body)} for cs, body in lg["changesets"].items()}
        chain = hy_effective_chain(lines)
        subjects = {r["subject"] for c in changesets.values() for r in c["records"]}
        base_state = {(s, "name"): hy_default_name(s, base_names) for s in subjects}
        if head_names is not None:
            head_state = {(s, "name"): hy_default_name(s, head_names) for s in subjects}
            oracle.check_k16(base_state, chain, changesets, head_state,
                             manifests={g: m for g, m in lg["manifests"].items()}, rep=rep)
        # K8: each H-agent view = its store replayed onto its base generation, over every subject any changeset or
        # any view's store names (a view that shows another view's unpublished name differs from its replay)
        stores = {}
        for who, v in views.items():
            if v.get("view_key"):
                stores[who] = oracle.read_sealed(root / "overlays" / f"{v['view_key']}.json")[0]
        all_subjects = subjects | {r["subject"] for st_ in stores.values() if st_
                                   for r in hy_model_records({"records": st_.get("edits", [])})}
        for who, v in views.items():
            vk = v.get("view_key")
            if not vk or (v.get("base") or {}).get("lineage") not in (None, lin.name):
                continue
            store = stores.get(who)
            if store is None:
                rep.violation("K8", "store_unreadable", f"{who}: overlays/{vk}.json and its .bak fail validation")
                continue
            # the store replayed as Hydralysis replays it (workcopy.pending_of): every record not in a live commit, in
            # store order (a committed record is already in the base generation)
            committed = {i for c in store.get("commits") or [] if not c.get("reverted") for i in c.get("ids", [])}
            pend = [r for r in store.get("edits", []) if r.get("id") not in committed]
            recs = [{**r, "seq": k} for k, r in enumerate(hy_model_records({"records": pend}))]
            keys = all_subjects
            base_v = {(s, "name"): hy_default_name(s, base_names) for s in keys}
            # a view with no pending record has nothing of its own: Hydralysis reads the head for it (workcopy.reader,
            # expected_state None), whatever generation its store last rebased onto
            gen_v = None if v.get("pending") == 0 and not recs else (v.get("base") or {}).get("generation", 0)
            at = hy_state_at(chain, changesets, base_v, gen_v)
            view_state = {(s, "name"): hy_default_name(s, v.get("names") or {}) for s in keys}
            oracle.check_k8(at, recs, view_state, kid="K8", rep=rep)
    # K1 (engine side): no writable open of a sealed generation in the Hydralysis engine's logs
    if sealed_gprs:
        for log in engine_logs:
            for line in oracle.engine_log_writable_opens(log, sealed_gprs):
                rep.violation("K1", "writable_open_of_sealed", line, log)
    oracle.check_k17(root / "overlays", None, rep) if (root / "overlays").is_dir() else None
    for cs in sorted(acked - known):
        rep.ran("K12")
        rep.violation("K12", "acked_publish_missing", f"acknowledged changeset {cs!r} is in no lineage", None, csid=cs)
    return rep


def judge_hy_rows(rows, windows=()) -> tuple:
    """The H-agents' rows: ``(violations, summary)``. A failed call is an unexpected error unless it is an explained
    ``busy``; a ``hy_k15`` row with a difference is a K15 violation (a view rebuilt from base + store differs from
    the live view); a publish that ended in another outcome than the four that keep the records is a violation."""
    viol, k15 = [], {"probes": 0, "rebuilt": 0, "differ": 0}
    unexpected = {}
    stale_explained = 0
    redos = [r for r in rows if r.get("op") == "hy_stale_redo" and r.get("ok")]
    for r in rows:
        if r.get("op") == "hy_k15":
            k15["probes"] += 1
            k15["rebuilt"] += bool(r.get("rebuilt"))
            if r.get("diff"):
                k15["differ"] += 1
                viol.append(("K15:view_rebuilt_differs", f"{r.get('agent')}: {json.dumps(r.get('diff'))[:300]}"))
            continue
        if r.get("ok") or r.get("op") == "ready":
            continue
        code = r.get("code") or ""
        if code == "busy" and any(k in (r.get("details") or {}) for k in BUSY_EXPLAINERS):
            continue
        if hy_stale_explained(r, redos):
            stale_explained += 1
            continue
        unexpected.setdefault(f"{r.get('op')}:{code}", []).append(r)
    for k, rs in sorted(unexpected.items()):
        viol.append(("hy_unexpected_error", f"{k}: {len(rs)} time(s); first: {json.dumps(rs[0], default=str)[:300]}"))
    counts = {"publish": sum(1 for r in rows if r.get("op") == "hy_publish" and r.get("ok")),
              "rebase": sum(1 for r in rows if r.get("op") == "hy_rebase" and r.get("ok")),
              "hydralysis_queries": sum(1 for r in rows if r.get("op") in HY_QUERY_OPS and r.get("ok"))}
    return viol, {"unexpected": sum(len(v) for v in unexpected.values()), "k15": k15, "counts": counts,
                  "stale_redone": stale_explained}


def hy_stale_explained(r, redos) -> bool:
    """An edit that raced a publish answers ``stale_view`` (``stale: master_generation_changed``): the documented
    contract. It is explained only when the same agent then rebased successfully and redid that same edit: a
    ``hy_stale_redo`` row of the same agent, edit ``n`` and attempt, at or after the stale row."""
    if r.get("op") != "hy_edit" or r.get("code") != "stale_view":
        return False
    if (r.get("details") or {}).get("stale") != "master_generation_changed" or r.get("n") is None:
        return False
    return any(d.get("agent") == r.get("agent") and d.get("n") == r.get("n") and d.get("attempt") == r.get("attempt")
               and d.get("t", 0) >= r.get("t", 0) for d in redos)


def judge_k11p(facts: dict, rep: oracle.Report | None = None) -> oracle.Report:
    """K11p (D59, Y5 ``subagents_one_process``): two sub-agents of one MCP server process; without ``as`` they share
    one view (Q sees P's unpublished tag: documented, D59); with distinct ``options.as`` they do not, and P sees its
    own."""
    rep = rep or oracle.Report("K11p")
    rep.ran("K11p")
    if facts.get("errors"):
        rep.violation("K11p", "probe_failed", json.dumps(facts["errors"])[:300])
        return rep
    sh, iso = facts.get("shared") or {}, facts.get("isolated") or {}
    if sh.get("q_saw") != sh.get("tag"):
        rep.violation("K11p", "shared_id_not_shared", f"without as, Q saw {sh.get('q_saw')!r}, not P's {sh.get('tag')!r}")
    if iso.get("q_saw") == iso.get("tag"):
        rep.violation("K11p", "unpublished_tag_visible", f"as Q saw P's unpublished tag {iso.get('tag')!r}")
    if iso.get("p_saw") != iso.get("tag"):
        rep.violation("K11p", "own_edit_missing", f"as P saw {iso.get('p_saw')!r}, not its own {iso.get('tag')!r}")
    return rep


def judge_view_probe(res: dict, rep: oracle.Report | None = None) -> oracle.Report:
    """GR8, the 100-view probe of 9.14/9.17 inside the soak: opening up to 100 programs ends in a structured
    ``busy`` (reason ``capacity``) at ``maxViews``, never an out-of-memory error or a dead daemon; the governor never
    holds more than ``maxViews`` views. ``res``: ``{"max_views", "opened", "governor_views_max", "refusals":
    [{code, details}], "errors": [...], "daemon_alive", "oom_lines"}``."""
    rep = rep or oracle.Report("GR8")
    rep.ran("GR8")
    mx = res.get("max_views")
    if not res.get("daemon_alive", True):
        rep.violation("GR8", "daemon_died", "the daemon did not survive the 100-view probe")
    for line in res.get("oom_lines") or []:
        rep.violation("GR8", "out_of_memory", line[:300])
    for e in res.get("errors") or []:
        rep.violation("GR8", "unstructured_refusal", json.dumps(e, default=str)[:300])
    for f in res.get("refusals") or []:
        det = f.get("details") or {}
        if f.get("code") != "busy" or det.get("reason") != "capacity":
            rep.violation("GR8", "unstructured_refusal", json.dumps(f, default=str)[:300])
    if mx is not None:
        if (res.get("governor_views_max") or 0) > mx:
            rep.violation("GR8", "views_above_max", f"governor views {res.get('governor_views_max')} > maxViews {mx}")
        if res.get("opened", 0) + res.get("held_by_others", 0) < 100 and not res.get("refusals"):
            rep.violation("GR8", "not_refused", f"{res.get('opened')} opened, no refusal before 100")
    return rep


def judge_leader_kill(ev: dict, rep: oracle.Report | None = None) -> oracle.Report:
    """A publish leader killed mid-build: the lock is free again (the OS released it) and the queue moves on (the
    killed changeset is decided later, judged by K12 and K16 at the end)."""
    rep = rep or oracle.Report("leader")
    if ev.get("killed") and ev.get("lock_held_after"):
        rep.violation("K12", "leader_lock_stuck", f"publish.lock still held {ev.get('waited_s')} s after the leader "
                      f"{ev.get('pid')} was killed", None)
    return rep


def hy_engine_facts(status: dict, health: dict | None) -> dict:
    """What a client sees of the Hydralysis engine daemon: the governor's views and the programs nobody uses that still
    hold unsaved edits (an orphan with work is kept until ``orphanKeepS``, 0 = for ever, and counts as a view)."""
    pr = {p.get("id"): p for p in status.get("projects", [])}
    orphans = [{"project": p.get("project"), "gpr": (pr.get(p.get("project")) or {}).get("gpr"),
                "unsaved": p.get("unsavedEdits"), "orphanedMs": p.get("orphanedMs")}
               for p in status.get("programs", []) if not p.get("users") and (p.get("unsavedEdits") or 0) > 0]
    g = (health or {}).get("governor") or {}
    return {"views": g.get("views"), "max_views": g.get("maxViews"), "refused": g.get("refused"),
            "programs": len(status.get("programs", [])), "orphans": orphans}


def judge_hy_engine(facts: dict, rep: oracle.Report | None = None) -> oracle.Report:
    """No leak (9.17) on the Hydralysis side, once every H-agent has ended: no program that nobody uses holds unsaved
    edits (each one is a view the daemon keeps for ever and counts against ``maxViews``)."""
    rep = rep or oracle.Report("hy-engine")
    rep.ran("K7")
    orph = facts.get("orphans") or []
    if orph:
        rep.violation("K7", "orphaned_unsaved_programs",
                      f"{len(orph)} program(s) nobody uses hold unsaved edits and stay open as views "
                      f"({facts.get('views')} of maxViews {facts.get('max_views')}); first: "
                      f"{[(o.get('gpr'), o.get('unsaved')) for o in orph[:3]]}", None, count=len(orph))
    return rep


def writable_opens_after_seal(log_lines, gprs) -> list:
    """Daemon log lines that open one of ``gprs`` writable after the line that sealed it (``Seals``: "<client> sealed
    <gpr> at revision ..."; ``Session``: "opened project pN <gpr> (writable)"). The candidate's own writable open
    before its seal is not one."""
    keys = {str(pathlib.Path(g)).lower().replace("\\", "/") for g in gprs}
    sealed, out = set(), []
    for line in log_lines:
        low = line.lower().replace("\\", "/")
        for k in keys:
            if k not in low:
                continue
            if " sealed " + k in low:
                sealed.add(k)
            elif k in sealed and "opened project" in low and "(writable)" in low:
                out.append(line.strip())
    return out


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
        self.hits = {c: 0 for c in FAULT_CLASSES + ["backup_lane", "k11p_probe"]}
        self.attempts = {c: 0 for c in FAULT_CLASSES + ["backup_lane", "k11p_probe"]}
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
        self.k6_sweep_log = None
        self.daemon_logs = self.work / "daemon-logs"   # every incarnation's log (rotate_daemon_log)
        # the Hydralysis lane (VF items)
        self.hy_enabled = bool(getattr(a, "hy_binary", None) and getattr(a, "hy_src", None) and getattr(a, "hy_python", None))
        self.hy_root = self.work / "hy"
        self.hy_dir = self.work / "hy-agents"
        self.hy_n = (getattr(a, "hy_agents", 0) or HY_AGENTS[a.profile]) if self.hy_enabled else 0
        self.hy_procs: dict = {}
        self.hy_setup = None
        self.hy_error = None
        self.hy_rc: list = []
        self.hy_log: list = []
        self.k11p_round = 0
        self.probe_copies = self.work / "probe-views"

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
        # keep the log of the incarnation that ended (killed or stopped) before the next one appends to the file:
        # the client rotates the file only past 32 MB and overwrites its one .1, so without this a long run kept the
        # last incarnation's log only (nightly-1)
        rotate_daemon_log(self.state / f"{self.instance}.log", self.daemon_logs, self.incarnation)
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
        if self.hy_enabled:
            self.hy_prepare()
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

    def k6_roots(self) -> list:
        """Every folder that holds fork destinations: the masters and each agent's folder (its fork and fk/fN)."""
        out = [self.masters_dir / f"p{p}" for p in range(self.nproj)]
        out += [self.agent_dir(i) for i in range(self.agents)]
        return [x for x in out if x.exists()]

    def file_round(self, phase: str, *, quiescent: bool = False, daemon_alive: bool = True, locks: bool = True,
                   swept: bool = False):
        """The file-level invariants over every tree: K2 (version-file headers), K6 (8.13: 0 .gpr without its .rep
        at any instant; a half publish is ``pending_sweep`` until ``swept``, after which every fork destination is
        absent or complete and no staging folder is left; staging folders are not projects), K9 (nothing involved
        changes in a project no agent works on), K7 (locks; temp folder growth)."""
        rep = oracle.Report("round:" + phase)
        trees = self.all_project_trees()
        for p in trees:
            oracle.check_k2(p, rep)
        for root in self.k6_roots():
            oracle.check_k6_tree(root, swept=swept, rep=rep)
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
        "oom_probe_100_views": lambda s: s.f_oom_probe(),
        "kill_publish_leader": lambda s: s.f_kill_publish_leader(),
        "k11p_probe": lambda s: s.f_k11p_probe(),
    }

    def schedule(self) -> list:
        """The deck of fault events: each class its minimum (plus a fifth more, rounded up, where a hit can
        miss), shuffled with the seed, spread over the run after a warm-up and before a cool-down."""
        mins = profile_minimums(self.profile, getattr(self, "hy_enabled", False))
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
            if self.hy_enabled:
                with contextlib.suppress(Exception):
                    self.hy_reap()
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
        if self.hy_enabled:
            self.hy_start()
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
        if self.hy_ready():
            self.hy_engine_sample("periodic")

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
        hy_counts = {}
        if self.hy_enabled and not early:
            hy_counts = self.hy_finish()
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
        workload["candidate_analysis"] = workload.get("candidate", 0)
        workload.update(hy_counts)
        if self.hy_error:
            self.setup_error = self.setup_error or f"hydralysis lane: {self.hy_error}"
        res = verdict_of(self.profile, self.report, self.hits, workload, self.features, self.extra_viol,
                         self.cut_short, self.setup_error, set(self.report.checked),
                         plants_expected=[self.PLANT_CODES[p] for p in (list(self.PLANT_CODES) if self.plant == ["all"]
                                                                       else self.plant) if p in self.PLANT_CODES],
                         overrides=self.overrides, hy_enabled=self.hy_enabled)
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
               "fault_hits": self.hits, "fault_attempts": self.attempts,
               "fault_minimums": profile_minimums(self.profile, self.hy_enabled),
               "hydralysis_lane": {"enabled": self.hy_enabled, "agents": self.hy_n, "error": self.hy_error,
                                   "setup": {k: v for k, v in (self.hy_setup or {}).items() if k not in ("functions",)},
                                   "exits": self.hy_rc, "log": self.hy_log[-200:]},
               "fault_unavailable": UNAVAILABLE_FAULTS, "workload_unavailable": UNAVAILABLE_WORKLOAD,
               "workload_counts": workload, "row_summary": summ, "latency_ms": lat,
               "workload_counts_note": "an operation counts as run when it succeeded or failed with an EXPECTED code "
                                       "(cancelled, timeout): the deaf and burn counts include timeout/cancel results by design",
               "evidence_note": "agent.log and daemon.log can carry program and function names of a game copy (engine "
                                "error messages, up to 200 chars): keep the evidence folder off the repository",
               "k6_sweep": self.k6_sweep_log,
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
                    "deaf": "deaf", "burn": "burn", "candidate": "candidate"}

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
        self.k6_sweep()
        self.file_round("quiescent", quiescent=True, daemon_alive=False, swept=True)
        self.candidate_round()
        self.tmp_round("end")

    def k6_sweep(self):
        """The sweep that K6 is judged after (8.13). What a killed publisher left (a staging folder, a ``.rep`` without
        its ``.gpr``, a sidecar still ``publishing`` or its ``.tmp``) is pending until a sweep has run. Trigger 1 is a
        daemon start on the same state root (8.13 sweeps every recorded fork parent at start, and ``open_project``
        sweeps the folder it opens). An engine without the start-up sweep is given trigger 2, the lazy sweep of D41:
        one ``fork_project`` of master 0 into each folder that is still pending (the first fork under a folder sweeps
        it whole; the fork it then makes is complete or refused, and is judged like any other). Which trigger cleared
        which folder is recorded; the daemon is stopped again at the end. The strict K6 round follows."""
        before = oracle.Report("k6-pending")
        for root in self.k6_roots():
            oracle.check_k6_tree(root, swept=False, rep=before)
        pend = oracle.k6_pending_parents(before)
        out = {"pending_before": pend, "cleared_by_restart": [], "probe_forks": [], "trigger": None}
        self.k6_sweep_log = out
        if not pend:
            out["trigger"] = "nothing pending"
            return out
        try:
            self.start_daemon()
            time.sleep(3)
            after = oracle.Report("k6-after-restart")
            for root in self.k6_roots():
                oracle.check_k6_tree(root, swept=False, rep=after)
            left = oracle.k6_pending_parents(after)
            out["cleared_by_restart"] = [p for p in pend if p not in left]
            out["trigger"] = "daemon start (8.13)" if not left else "daemon start, then open_project, then fork_project (8.13)"
            # 8.13 (2): open_project sweeps the folder of the project it opens (a record dropped at the start, the case of
            # a sidecar temporary file next to a complete fork, waits for this or for a fork_project)
            out["opened"] = []
            for parent in left:
                for gpr in sorted(pathlib.Path(parent).glob("*.gpr"))[:1]:
                    try:
                        o2 = self.sup_call("open_project", path=str(gpr))
                        out["opened"].append({"parent": parent, "gpr": str(gpr)})
                        with contextlib.suppress(Exception):
                            self.sup_call("close_project", project=o2["id"])
                    except self.gs.SessionError as e:
                        out["opened"].append({"parent": parent, "gpr": str(gpr), "result": e.code})
            if left:
                again = oracle.Report("k6-after-open")
                for root in self.k6_roots():
                    oracle.check_k6_tree(root, swept=False, rep=again)
                left = oracle.k6_pending_parents(again)
            # 8.13 (3): fork_project sweeps its destination name before staging (D41)
            if left:
                o = self.sup_call("open_project", path=str(self.master_gpr(0)))
                for parent in left:
                    try:
                        r = self.sup_call("fork_project", project=o["id"], path=parent, mode="auto", open=False, wait=600000)
                        out["probe_forks"].append({"parent": parent, "result": "forked", "gpr": r.get("gpr")})
                    except self.gs.SessionError as e:
                        out["probe_forks"].append({"parent": parent, "result": e.code, "message": (e.message or "")[:200]})
                with contextlib.suppress(Exception):
                    self.sup_call("close_project", project=o["id"])
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e}"
            self.extra_viol.append(("k6_sweep_failed", out["error"]))
        finally:
            with contextlib.suppress(Exception):
                self.sess.close()
            stopped = False
            with contextlib.suppress(Exception):
                stopped = self.daemon.stop(timeout=120)
            if not stopped:
                with contextlib.suppress(Exception):
                    self.daemon.stop(force=True, timeout=120)
        return out

    # ---------------------------------------------------------------------------- the Hydralysis lane (VF items)
    def hy_spec(self) -> dict:
        return {"hy_src": str(pathlib.Path(self.a.hy_src).absolute()), "root": str(self.hy_root),
                "config": str(self.hy_dir / "config.json")}

    def hy_run(self, cmd: str, spec: dict, timeout: float) -> int | None:
        """One ``soak_hy.py`` command under the Hydralysis Python; its output goes to ``hy-agents/<cmd>.log``."""
        sp = self.hy_dir / f"{cmd}-{int(time.time() * 1000)}.json"
        sp.write_text(json.dumps(spec), encoding="utf-8")
        with open(self.hy_dir / f"{cmd}.log", "ab") as lf:
            try:
                return subprocess.run([self.a.hy_python, "-I", str(HERE / "soak_hy.py"), cmd, str(sp)], stdout=lf,
                                      stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                self.hy_log.append({"t": round(self.t(), 1), "cmd": cmd, "error": f"timed out after {timeout} s"})
                return None

    def hy_prepare(self):
        """Prepares the Hydralysis target (a copy of ``--hy-binary``) on a fresh Hydralysis root and picks each H-agent's
        subjects: functions no CALL or JUMP reaches (a rename of one changes no other function's decompile)."""
        self.hy_dir.mkdir(parents=True, exist_ok=True)
        self.hy_root.mkdir(parents=True, exist_ok=True)
        eng = pathlib.Path(self.a.ghidra)
        cfg = {"root": str(self.hy_root), "hydra_dir": str(eng),
               "hydra_client": str(eng / "Ghidra" / "Features" / "HeadlessSession" / "support" / "ghidra_session.py"),
               "hydra_idle_s": 1800}
        (self.hy_dir / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        tdir = self.work / "hy-target"
        tdir.mkdir(parents=True, exist_ok=True)
        target = tdir / pathlib.Path(self.a.hy_binary).name
        shutil.copy2(self.a.hy_binary, target)
        out = self.hy_dir / "setup.json"
        t0 = time.time()
        rc = self.hy_run("setup", {**self.hy_spec(), "binary": str(target), "out": str(out)}, 1800)
        try:
            st = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            st = {"ok": False}
        if not st.get("ok"):
            self.hy_error = f"setup failed (rc {rc}): {json.dumps(st)[:300]}"
            return
        free, called = st.get("free", []), st.get("called", [])
        per = 2 if len(free) >= 2 * self.hy_n else 1
        if len(free) < self.hy_n * per or len(called) < 2:
            self.hy_error = f"too few subjects: {len(free)} functions no call reaches for {self.hy_n} H-agents"
            return
        st["subjects"] = {i: free[i * per:(i + 1) * per] for i in range(self.hy_n)}
        st["k11p_subjects"] = called[:2]
        st["setup_s"] = round(time.time() - t0, 1)
        self.hy_setup = st

    def hy_ready(self) -> bool:
        return self.hy_enabled and self.hy_setup is not None and not self.hy_error

    def hy_start(self):
        if not self.hy_ready():
            return
        for i in range(self.hy_n):
            self.hy_spawn(i)

    def hy_spawn(self, i: int):
        d = self.hy_dir / f"h{i}"
        d.mkdir(parents=True, exist_ok=True)
        spec = {**self.hy_spec(), "index": i, "as": f"h{i:02d}", "dir": str(d), "seed": self.rng.randrange(1 << 30),
                "stop_file": str(self.work / "STOP"), "subjects": self.hy_setup["subjects"][i],
                "all_functions": sorted(self.hy_setup["functions"]), "deadline": self.t_start + self.duration + 30}
        sp = d / f"spec-{int(time.time() * 1000)}.json"
        sp.write_text(json.dumps(spec), encoding="utf-8")
        with open(d / "agent.log", "ab") as lf:
            self.hy_procs[i] = subprocess.Popen([self.a.hy_python, "-I", str(HERE / "soak_hy.py"), "agent", str(sp)],
                                                stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)

    def hy_reap(self):
        """An H-agent that ends before the stop is a violation (no fault of this runner targets it); it is restarted
        so that the lane keeps its load."""
        for i, p in list(self.hy_procs.items()):
            rc = p.poll()
            if rc is None or self.stopping.is_set():
                continue
            self.hy_rc.append({"agent": i, "rc": rc, "t": round(self.t(), 1)})
            tail = ""
            with contextlib.suppress(OSError):
                tail = (self.hy_dir / f"h{i}" / "agent.log").read_text(errors="replace")[-400:]
            self.extra_viol.append(("hy_agent_lost", f"H-agent {i} exited {rc} during the run: {tail!r}"))
            if time.time() < self.t_start + self.duration - 30:
                self.hy_spawn(i)
            else:
                self.hy_procs.pop(i, None)

    def hy_rows(self) -> list:
        rows = []
        for i in range(self.hy_n):
            p = self.hy_dir / f"h{i}" / "results.jsonl"
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    with contextlib.suppress(ValueError):
                        rows.append(json.loads(line))
        return rows

    def hy_daemon(self):
        return self.gs.Daemon(self.a.ghidra, str(self.hy_root / "hydra" / "state"), "rusticre")

    def hy_engine_sample(self, phase: str):
        """The Hydralysis engine daemon as a client sees it: the governor's views and every program nobody uses that
        still holds unsaved edits (``judge_hy_engine``)."""
        s = None
        try:
            s = self.hy_daemon().connect("soak-hy-inspect", "soak", start=False, timeout=30)
            st, h = s.call("status"), s.call("health")
            res = hy_engine_facts(st, h)
            res["phase"], res["t"] = phase, round(self.t(), 1)
            self.hy_log.append({k: v for k, v in res.items() if k != "orphans"} | {"orphans": res["orphans"][:5]})
            return res
        except Exception as e:  # noqa: BLE001
            self.hy_log.append({"t": round(self.t(), 1), "phase": phase, "inspect_error": f"{type(e).__name__}: {e}"})
            return None
        finally:
            if s is not None:
                with contextlib.suppress(Exception):
                    s.close()

    def hy_locks(self):
        src = str(pathlib.Path(self.a.hy_src).absolute())
        if src not in sys.path:
            sys.path.append(src)
        from hydralysis import locks  # noqa: PLC0415  (only os, time and pathlib; no Hydralysis state)
        return locks

    def f_kill_publish_leader(self):
        """kill -9 of a publish leader mid-build (9.17): the process that holds a lineage's ``publish.lock`` (its pid is
        the label ``publish.leader.json``), killed 0.2 to 1.2 s into its drain. The OS releases the lock; the killed
        changeset stays queued and the next leader settles it (``views.reconcile``); K12 and K16 judge the result at
        the end. Waits up to 120 s for a leader."""
        import chaos_lib as chaos
        if not self.hy_ready():
            return False
        locks = self.hy_locks()
        end = time.time() + 120
        with self.fault_window("kill_publish_leader", scope="hy", extra_s=30):
            while time.time() < end and not self.stopping.is_set():
                for lin in hy_lineages(self.hy_root):
                    lk = lin / "publish.lock"
                    try:
                        if not lk.is_file() or not locks.held(str(lk)):
                            continue
                        pid = int(json.loads((lin / "publish.leader.json").read_text(encoding="utf-8")).get("pid") or 0)
                    except (OSError, ValueError):
                        continue
                    if not pid or not oracle.pid_alive(pid):
                        continue
                    time.sleep(self.rng.uniform(0.2, 1.2))
                    try:
                        still = locks.held(str(lk)) and int(json.loads((lin / "publish.leader.json").read_text(
                            encoding="utf-8")).get("pid") or 0) == pid
                    except (OSError, ValueError):
                        still = False
                    if not still:
                        continue
                    k = chaos.terminate(pid, 10)
                    t_kill = time.time()
                    while time.time() - t_kill < 30 and locks.held(str(lk)):
                        time.sleep(0.25)
                    ev = {"t": round(self.t(), 1), "fault": "kill_publish_leader", "lineage": lin.name, "pid": pid,
                          "killed": bool(k.get("terminated", True)) if isinstance(k, dict) else True,
                          "lock_held_after": locks.held(str(lk)), "waited_s": round(time.time() - t_kill, 1)}
                    self.fault_log.append(ev)
                    self.merge(judge_leader_kill(ev), "kill_publish_leader")
                    return True
                time.sleep(0.25)
        self.fault_log.append({"t": round(self.t(), 1), "fault": "kill_publish_leader", "missed": "no leader in 120 s"})
        return False

    def probe_copy(self, k: int) -> pathlib.Path:
        d = self.probe_copies / f"v{k:03d}"
        if not d.is_dir():
            shutil.copytree(self.masters_dir / "p0", d, ignore=shutil.ignore_patterns("*.lock", "*.lock~", "projectState"))
        return next(d.glob("*.gpr"))

    def f_oom_probe(self):
        """GR8's 100-view probe against the soak daemon while the agents work: up to 100 programs (copies of master 0)
        opened read-only by clients of ``maxViewsPerClient`` each, until the governor refuses. Judged by
        ``judge_view_probe``: a structured ``busy``/``capacity`` at ``maxViews``, no out-of-memory error in the daemon
        log, the daemon alive, never more than ``maxViews`` views. Every probe client then leaves."""
        res = {"max_views": None, "opened": 0, "refusals": [], "errors": [], "governor_views_max": 0,
               "daemon_alive": True, "oom_lines": [], "held_by_others": 0}
        per = 4
        try:
            g = self.sup_call("health")["governor"]
            res["max_views"], per, res["held_by_others"] = g.get("maxViews"), g.get("maxViewsPerClient") or 4, g.get("views", 0)
        except Exception:  # noqa: BLE001
            res["max_views"] = ((self.sess.hello or {}).get("limits") or {}).get("maxViews")
        log = self.state / f"{self.instance}.log"
        off = log.stat().st_size if log.exists() else 0
        clients = []
        with self.fault_window("oom_probe_100_views", scope="all", extra_s=10):
            try:
                for k in range(100):
                    gpr = self.probe_copy(k)
                    if k % per == 0:
                        clients.append(self.daemon.connect(f"soak-probe-{len(clients):02d}", "soak", start=False, timeout=60))
                    c = clients[-1]
                    try:
                        c.call("open_project", path=str(gpr))
                        c.call("open_program", path=self.a.program)
                        res["opened"] += 1
                    except self.gs.SessionError as e:
                        det = e.details if isinstance(e.details, dict) else None
                        if e.code == "busy":
                            res["refusals"].append({"view": k, "code": e.code, "details": det})
                        else:
                            res["errors"].append({"view": k, "code": e.code, "message": (e.message or "")[:200]})
                        break
                    if k % 8 == 7:
                        with contextlib.suppress(Exception):
                            res["governor_views_max"] = max(res["governor_views_max"], self.sup_call("health")["governor"]["views"])
                with contextlib.suppress(Exception):
                    res["governor_views_max"] = max(res["governor_views_max"], self.sup_call("health")["governor"]["views"])
            finally:
                for c in clients:
                    with contextlib.suppress(Exception):
                        c.close()
            try:
                self.sup_call("ping")
            except Exception:  # noqa: BLE001
                res["daemon_alive"] = False
        with contextlib.suppress(OSError):
            with open(log, "rb") as f:
                f.seek(off)
                res["oom_lines"] = [ln.strip()[:300] for ln in f.read().decode("utf-8", "replace").splitlines()
                                    if "OutOfMemoryError" in ln][:5]
        self.fault_log.append({"t": round(self.t(), 1), "fault": "oom_probe_100_views",
                               **{k: v for k, v in res.items() if k != "refusals"}, "refusals": res["refusals"][:2]})
        self.merge(judge_view_probe(res), "oom_probe_100_views")
        return bool(res["opened"] or res["refusals"] or res["errors"])

    def f_k11p_probe(self):
        """K11p: two sub-agents of one real stdio MCP server process (``soak_hy k11p``), judged by ``judge_k11p``."""
        if not self.hy_ready():
            return False
        self.k11p_round += 1
        out = self.hy_dir / f"k11p-{self.k11p_round}.json"
        with self.fault_window("k11p_probe", scope="k11p"):
            rc = self.hy_run("k11p", {**self.hy_spec(), "round": self.k11p_round, "subjects": self.hy_setup["k11p_subjects"],
                                      "out": str(out)}, 900)
        try:
            facts = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.extra_viol.append(("k11p_probe_failed", f"round {self.k11p_round}: rc {rc}, no facts"))
            return False
        self.hy_log.append({"t": round(self.t(), 1), "k11p": {k: facts.get(k) for k in ("shared", "isolated", "errors")}})
        self.merge(judge_k11p(facts), "k11p")
        return True

    def hy_finish(self) -> dict:
        """After the stop: the H-agents end (their publish wait is bounded by the run's end), their rows are judged
        (K15 and every error), the Hydralysis daemon is inspected for leaked views, the publish queue is drained and
        the root judged (K1, K8, K12, K16, K17). Returns the lane's workload counts."""
        import chaos_lib as chaos
        if not self.hy_ready():
            return {}
        end = time.time() + 240
        while any(p.poll() is None for p in self.hy_procs.values()) and time.time() < end:
            time.sleep(0.5)
        for i, p in self.hy_procs.items():
            if p.poll() is None:
                self.extra_viol.append(("hy_agent_did_not_stop", f"H-agent {i} still running 240 s after the stop"))
                chaos.kill_client_proc(p)
            self.hy_rc.append({"agent": i, "rc": p.returncode, "t": round(self.t(), 1), "final": True})
            if p.returncode not in (0, None):
                self.extra_viol.append(("hy_agent_failed", f"H-agent {i} exited {p.returncode}"))
        rows = self.hy_rows()
        viol, summ = judge_hy_rows(rows, self.windows)
        self.extra_viol += viol
        self.hy_log.append({"t": round(self.t(), 1), "rows": summ})
        rep = oracle.Report("hydralysis")
        if summ["k15"]["rebuilt"]:
            rep.ran("K15")
        eng = self.hy_engine_sample("after the H-agents")
        if eng is not None:
            judge_hy_engine(eng, rep)
        views = {}
        acked = []
        for i in range(self.hy_n):
            recs = oracle.Ledger.read(self.hy_dir / f"h{i}" / "ledger.jsonl")
            vk = [r.get("view_key") for r in recs if r.get("view_key")]
            views[f"h{i:02d}"] = vk[-1] if vk else None
            acked += [r["csid"] for r in recs if r.get("kind") == "hypublish" and r.get("phase") == "ack"
                      and r.get("generation") is not None and r.get("csid")]
        out = self.hy_dir / "facts.json"
        rc = self.hy_run("facts", {**self.hy_spec(), "views": views, "out": str(out)}, 1800)
        try:
            facts = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.extra_viol.append(("hy_facts_failed", f"soak_hy facts: rc {rc}, no facts"))
            self.merge(rep, "hydralysis")
            return summ["counts"]
        for e in facts.get("errors") or []:
            self.extra_viol.append(("hy_facts_error", json.dumps(e)[:300]))
        for d in facts.get("drain") or []:
            if d.get("failure"):
                self.extra_viol.append(("hy_drain_failed", json.dumps(d)[:300]))
        vf = {who: {**v, "view_key": views.get(who)} for who, v in (facts.get("views") or {}).items()}
        judge_hy_store(self.hy_root, self.hy_setup["functions"], acked, vf, (facts.get("head") or {}).get("names"), rep=rep)
        for who, k in (facts.get("k15") or {}).items():
            if k.get("rebuilt"):
                rep.ran("K15")
            if k.get("diff"):
                rep.violation("K15", "view_rebuilt_differs", f"{who} at the end: {json.dumps(k['diff'])[:300]}")
        self.hy_log.append({"t": round(self.t(), 1), "facts": {"drain": facts.get("drain"), "k15": facts.get("k15"),
                                                               "acked": len(acked)}})
        self.merge(rep, "hydralysis")
        return summ["counts"]

    def hy_stop_all(self):
        """No Hydralysis process and no Hydralysis daemon outlives the run."""
        import chaos_lib as chaos
        for p in list(self.hy_procs.values()):
            if p.poll() is None:
                chaos.kill_client_proc(p)
        if not self.hy_root.is_dir():
            return
        with contextlib.suppress(Exception):
            self.hy_run("stop", self.hy_spec(), 180)
        with contextlib.suppress(Exception):
            d = self.hy_daemon()
            if d.jvm_alive():
                d.stop(force=True, timeout=120)

    def hy_keep_evidence(self):
        """The lane's evidence: rows, ledgers and logs of the H-agents, setup, facts and K11p results, the Hydralysis
        daemon log, and each lineage's records and log (the generations' projects are not kept)."""
        import gzip
        kd = self.evidence_dir / "hy"
        kd.mkdir(parents=True, exist_ok=True)
        for f in sorted(self.hy_dir.rglob("*")) if self.hy_dir.is_dir() else []:
            if f.is_file() and f.suffix in (".jsonl", ".json", ".log") and not f.name.startswith("spec-"):
                dst = kd / "lane" / f.relative_to(self.hy_dir)
                dst.parent.mkdir(parents=True, exist_ok=True)
                with open(f, "rb") as src, gzip.open(str(dst) + ".gz", "wb") as out:
                    shutil.copyfileobj(src, out)
        st = self.hy_root / "hydra" / "state"
        for f in sorted(st.glob("*.log*")) if st.is_dir() else []:
            with open(f, "rb") as src, gzip.open(kd / (f.name + ".gz"), "wb") as out:
                shutil.copyfileobj(src, out)
        for lin in hy_lineages(self.hy_root):
            dst = kd / "lineages" / lin.name
            dst.mkdir(parents=True, exist_ok=True)
            for f in lin.iterdir():
                if f.is_file():
                    shutil.copy2(f, dst / f.name)
            for sub in ("pending", "done", "declined", "failures"):
                if (lin / sub).is_dir():
                    shutil.copytree(lin / sub, dst / sub, dirs_exist_ok=True)
            for g in sorted((lin / "gen").glob("*/MANIFEST.json")) if (lin / "gen").is_dir() else []:
                (dst / "manifests").mkdir(exist_ok=True)
                shutil.copy2(g, dst / "manifests" / f"{g.parent.name}.json")

    def candidate_round(self):
        """K1 of the engine-level candidates: every sealed candidate's files equal the snapshot taken at its seal, the
        seal union holds (K1u), and no daemon log of the run shows a writable open of it after its seal line."""
        rep = oracle.Report("candidates")
        gprs = []
        logs = sorted(self.daemon_logs.glob("daemon.*.log")) if self.daemon_logs.is_dir() else []
        cur = self.state / f"{self.instance}.log"
        lines = []
        for f in logs + ([cur] if cur.exists() else []):
            with contextlib.suppress(OSError):
                lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
        for i in range(self.agents):
            for sj in sorted((self.agent_dir(i) / "cand").glob("c*.seal.json")) if (self.agent_dir(i) / "cand").is_dir() else []:
                try:
                    d = json.loads(sj.read_text(encoding="utf-8"))
                except (OSError, ValueError) as e:
                    rep.violation("K1", "seal_snapshot_unreadable", f"{sj}: {e}", sj)
                    continue
                oracle.check_k1(d["dir"], d["snapshot"], rep, label=f"a{i:02d}/{pathlib.Path(d['dir']).name}")
                oracle.check_k1u(d["gpr"], self.state, rep=rep)
                gprs.append(d["gpr"])
        for line in writable_opens_after_seal(lines, gprs):
            rep.violation("K1", "writable_open_of_sealed", line[:300])
        self.fault_log.append({"t": round(self.t(), 1), "candidates_judged": len(gprs)})
        self.merge(rep, "candidates")

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
        if self.hy_enabled:
            self.hy_stop_all()
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
        # every incarnation's log, gzipped: daemon-logs/daemon.<incarnation>.log.gz (the last one is daemon.log too)
        rotate_daemon_log(self.state / f"{self.instance}.log", self.daemon_logs, self.incarnation)
        kd = self.evidence_dir / "daemon-logs"
        kd.mkdir(parents=True, exist_ok=True)
        for f in sorted(self.daemon_logs.glob("daemon.*.log")) if self.daemon_logs.is_dir() else []:
            with open(f, "rb") as src, gzip.open(kd / (f.name + ".gz"), "wb") as dst:
                shutil.copyfileobj(src, dst)
        if self.hy_enabled:
            self.hy_keep_evidence()
        for n in ("agents", "masters", "state", "tmp", "canary", "canary-forks", "stage-src", "backup-test", "daemon-logs",
                  "hy", "hy-agents", "hy-target", "probe-views"):
            rmtree(self.work / n)
        if self.tree_root != self.work:
            # the masters and the agents' trees live on another volume (--master-root): "a fixture under
            # 10 GB on the volume, cleaned up" (9.17) means they go too; the folder itself only if empty
            rmtree(self.masters_dir)
            rmtree(self.agents_dir)
            with contextlib.suppress(OSError):
                self.tree_root.rmdir()


def rotate_daemon_log(log, keep_dir, generation: int):
    """Moves the daemon log ``log`` (and the client's own rotation ``<log>.1``, if any) to
    ``keep_dir/daemon.<generation>.log`` before the next incarnation starts, so that every daemon of a run keeps its
    log. Generation 0 (before the first start) and a missing log are nothing to do. Returns the kept path or None."""
    log = pathlib.Path(log)
    if generation <= 0 or not log.exists():
        return None
    keep_dir = pathlib.Path(keep_dir)
    keep_dir.mkdir(parents=True, exist_ok=True)
    dst = keep_dir / f"daemon.{generation:03d}.log"
    with open(dst, "ab") as out:
        for src in (log.with_suffix(log.suffix + ".1"), log):
            if src.exists():
                with open(src, "rb") as f:
                    shutil.copyfileobj(f, out)
    for src in (log.with_suffix(log.suffix + ".1"), log):
        with contextlib.suppress(OSError):
            src.unlink()
    return dst


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

    # ---- coordinator rule 2: a fork under the handle holder is excused only when structured, retryable, in the
    # window, source unchanged and destination absent
    whh = {"t0": t - 1, "t1": t + 1, "scope": 2, "cls": "handle_holder"}
    frk = {"t": t, "agent": 2, "op": "fork", "lane": "maint", "ms": 6.0, "ok": False, "code": "failed",
           "message": "~00000000.db: being used by another process"}
    good = {"t": t + 0.1, "agent": 2, "op": "fork_fail_check", "lane": "maint", "ms": 0.0, "ok": True,
            "failed_code": "failed", "src_unchanged": True, "dest_state": "absent", "structured": True, "retryable": True}
    viol, summ = classify_rows(rows + [frk, good], [whh])
    check("rule 2: a structured retryable fork failure in its holder window, source unchanged, destination absent: excused",
          not viol and summ["tolerated_in_windows"] == {"handle_holder/fork:failed": 1}, (viol, summ))
    for what, bad_check in (("unstructured (the hydra.4 answer of nightly-1)", dict(good, structured=False, retryable=False)),
                            ("not retryable", dict(good, retryable=False)),
                            ("source changed", dict(good, src_unchanged=False)),
                            ("destination left", dict(good, dest_state="present: analysis.rep")),
                            ("no fork_fail_check row", None)):
        viol, _ = classify_rows(rows + [frk] + ([bad_check] if bad_check else []), [whh])
        check(f"planted rule 2: a fork failure in the holder window that is {what} stays a violation",
              any(k == "unexpected_error" and "fork:failed" in d for k, d in viol), viol)
    viol, _ = classify_rows(rows + [dict(frk, t=t + 100), dict(good, t=t + 100.1)], [whh])
    check("planted rule 2: the same fork failure outside the holder window is a violation", bool(viol), viol)
    viol, _ = classify_rows(rows + [dict(frk, agent=3), dict(good, agent=3)], [whh])
    check("planted rule 2: a fork failure of another agent than the held one is a violation", bool(viol), viol)
    # A63: the engine's structured answer to a held file is busy/file_held, suggest retry
    held = {"reason": "file_held", "path": "x/~00000000.db", "suggest": "retry"}
    hrow = {"t": t, "agent": 2, "op": "setup_open_program", "lane": "quick", "ms": 2.0, "ok": False, "code": "busy",
            "details": held}
    hfrk = dict(frk, code="busy", details=held)
    viol, summ = classify_rows(rows + [hrow, hfrk, dict(good, failed_code="busy")], [whh])
    check("rule 2 (A63): busy/file_held of an open and a fork in the agent's holder window: excused and counted",
          not viol and summ["tolerated_in_windows"].get("handle_holder/setup_open_program:busy:file_held") == 1
          and summ["tolerated_in_windows"].get("handle_holder/fork:busy:file_held") == 1, (viol, summ))
    for what, extra, wins in (("outside any holder window", dict(hrow, t=t + 100), [whh]),
                              ("of another agent than the held one", dict(hrow, agent=3), [whh]),
                              ("in a window of another fault class", hrow, [dict(whh, cls="kill_decompiler")]),
                              ("without suggest retry", dict(hrow, details={"reason": "file_held"}), [whh])):
        viol, _ = classify_rows(rows + [extra], wins)
        check(f"planted rule 2 (A63): busy/file_held {what} is a violation",
              any(k == "unexpected_error" and "busy:file_held" in d for k, d in viol), viol)
    viol, _ = classify_rows(rows + [hfrk, dict(good, failed_code="busy", src_unchanged=False)], [whh])
    check("planted rule 2 (A63): a busy/file_held fork whose source changed is a violation",
          any(k == "unexpected_error" and "fork:busy:file_held" in d for k, d in viol), viol)
    viol, _ = classify_rows(rows + [hfrk, dict(good, failed_code="busy", dest_state="present: x.rep")], [whh])
    check("planted rule 2 (A63): a busy/file_held fork that left its destination is a violation",
          any(k == "unexpected_error" and "fork:busy:file_held" in d for k, d in viol), viol)

    # ---- K6 per 8.13: staging folders are not projects; a half publish is pending until the sweep
    k6 = base / "k6"
    rmtree(k6)
    stg = k6 / "a00" / "fk" / "f3" / ".analysis.fork-1a2b-cafe.tmp"
    stg.mkdir(parents=True)
    (stg / "analysis.gpr").write_text("x")             # an in-flight staging folder: .gpr moved in before .rep
    done = k6 / "a00" / "fork"
    (done / "analysis.rep").mkdir(parents=True)
    (done / "analysis.gpr").write_text("x")
    (done / "analysis.fork.json").write_text(json.dumps({"state": "complete"}))
    r6 = oracle.check_k6_tree(k6, swept=False)
    check("K6: a .gpr inside a staging folder is not judged as a fork; the staging folder is pending before the sweep",
          not r6.findings and oracle.k6_pending_parents(r6) == [str(stg.parent)], (r6.findings, r6.notes))
    r6 = oracle.check_k6_tree(k6, swept=True)
    check("planted K6: a staging folder still there after the sweep is a violation",
          "K6:staging_left" in r6.codes(), r6.findings)
    rmtree(stg)
    half = k6 / "a00" / "fk" / "f4"
    (half / "analysis.rep").mkdir(parents=True)          # killed between the .rep move and the .gpr move
    pub = k6 / "a00" / "fk" / "f5"
    (pub / "analysis.rep").mkdir(parents=True)
    (pub / "analysis.gpr").write_text("x")
    (pub / "analysis.fork.json").write_text(json.dumps({"state": "publishing"}))   # killed before the sidecar rewrite
    r6 = oracle.check_k6_tree(k6, swept=False)
    check("K6: a .rep without .gpr and a 'publishing' sidecar are pending (not violations) before the sweep",
          not r6.findings and set(oracle.k6_pending_parents(r6)) == {str(half), str(pub)}, (r6.findings, r6.notes))
    r6 = oracle.check_k6_tree(k6, swept=True)
    check("planted K6: after the sweep a .rep without .gpr and a 'publishing' sidecar are violations",
          {"K6:rep_without_gpr", "K6:sidecar_state"} <= r6.codes(), r6.findings)
    lone = k6 / "a01" / "fk" / "f1"
    lone.mkdir(parents=True)
    (lone / "analysis.gpr").write_text("x")
    r6 = oracle.check_k6_tree(k6 / "a01", swept=False)
    check("planted K6: a destination .gpr without its .rep is a violation at any instant (before the sweep too)",
          "K6:gpr_without_rep" in r6.codes(), r6.findings)
    (pub / "analysis.fork.json").write_text(json.dumps({"state": "complete"}))
    rmtree(half)
    r6 = oracle.check_k6_tree(k6 / "a00", swept=True)
    check("K6: after a sweep that finished everything, absent or complete forks give no finding",
          not r6.findings, r6.findings)
    (k6 / "a00" / "del-f2" / "analysis.rep").mkdir(parents=True)
    check("K6: the harness's own atomic delete (del-*) is not walked",
          not oracle.check_k6_tree(k6 / "a00", swept=True).findings)

    # ---- every daemon incarnation keeps its log (coordinator item 3)
    lg = base / "logs"
    rmtree(lg)
    lg.mkdir()
    dlog = lg / "soak.log"
    keep = lg / "keep"
    check("rotate: nothing to keep before the first start", rotate_daemon_log(dlog, keep, 0) is None)
    for gen in (1, 2, 3):
        dlog.write_text(f"incarnation {gen}\n")
        if gen == 2:
            dlog.with_suffix(".log.1").write_text("rotated part of 2\n")
        rotate_daemon_log(dlog, keep, gen)
    kept = sorted(p.name for p in keep.glob("daemon.*.log"))
    check("rotate: every incarnation's log is kept by generation, the client's .1 included",
          kept == ["daemon.001.log", "daemon.002.log", "daemon.003.log"]
          and "rotated part of 2" in (keep / "daemon.002.log").read_text()
          and (keep / "daemon.003.log").read_text() == "incarnation 3\n" and not dlog.exists(), kept)
    dlog.write_text("incarnation 4\n")
    shutil.copy2(dlog, lg / "only-last.log")             # what the runner kept before: the file as it is at the end
    check("planted rotate: keeping only the final file loses the earlier incarnations",
          "incarnation 1" not in (lg / "only-last.log").read_text())
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
    check("every VF minimum has a function", all(c in Soak.FAULT_FUNCS for p in VF_MIN_FAULTS.values() for c in p))

    # ---- the VF items: the Hydralysis lane's judgement on a synthetic Hydralysis root, then one planted violation each
    def hy_make(root, *, head=None, view=None, corrupt_done=False, extra_line=None, tamper_gen=False, acked=("c-1",)):
        """A lineage with generation 1 = changeset c-1 (FUN_100 -> hy00x1) and a view h00 based on it with one pending
        record (hy00x1 -> hy00x2); returns the arguments of judge_hy_store."""
        root = pathlib.Path(root)
        lin = root / "lineages" / "L-t"
        for sub in ("pending", "done", "gen/0001/analysis.rep"):
            (lin / sub).mkdir(parents=True, exist_ok=True)
        r1 = {"id": "r1", "seq": 1, "address": "0x100", "effects": [{"subject": "address:0x100", "field": "name",
                                                                       "before": "FUN_100", "after": "hy00x1"}]}
        r2 = {"id": "r2", "seq": 2, "address": "0x100", "effects": [{"subject": "address:0x100", "field": "name",
                                                                       "before": "hy00x1", "after": "hy00x2"}]}
        (lin / "pending" / "c-1.json").write_text(json.dumps(oracle.seal_record({"csid": "c-1", "records": [r1], "ids": ["r1"]})))
        done = oracle.seal_record({"csid": "c-1", "outcome": "applied", "generation": 1})
        if corrupt_done:
            done["outcome"] = "tampered"
        (lin / "done" / "c-1.json").write_text(json.dumps(done))
        g = lin / "gen" / "0001"
        (g / "analysis.gpr").write_text("")
        (g / "analysis.rep" / "data.bin").write_bytes(b"x" * 10)
        files = [{"path": rel, "sha256": sha} for rel, sha in sorted(oracle.seal_snapshot(g).items())]
        man = {"files": files, "store": {"ids": ["r1"]}}
        man["filesetSha256"] = oracle.sha256_hex(oracle.canonical(files))
        man["selfSha256"] = oracle.sha256_hex(oracle.canonical(man))
        (g / "MANIFEST.json").write_text(json.dumps(man))
        if tamper_gen:
            (g / "analysis.rep" / "data.bin").write_bytes(b"y" * 10)
        lines = [{"seq": 1, "gen": 0, "reason": "register"}, {"seq": 2, "gen": 1, "reason": "commit", "csids": ["c-1"]}]
        if extra_line:
            lines.append(extra_line)
        (lin / "CURRENT.log").write_bytes(b"".join(oracle.crc_line(x) for x in lines))
        (root / "overlays").mkdir(parents=True, exist_ok=True)
        (root / "overlays" / "vk0.json").write_text(json.dumps(oracle.seal_record({"edits": [r1, r2], "revision": 2})))
        r3 = {"id": "r3", "seq": 1, "address": "0x200", "effects": [{"subject": "address:0x200", "field": "name",
                                                                       "before": "FUN_200", "after": "hy01x9"}]}
        (root / "overlays" / "vk1.json").write_text(json.dumps(oracle.seal_record({"edits": [r3], "revision": 1})))
        base_names = {"0x100": "FUN_100", "0x200": "FUN_200"}
        views = {"h00": {"view_key": "vk0", "base": {"lineage": "L-t", "generation": 1},
                         "names": view or {"0x100": "hy00x2", "0x200": "FUN_200"}},
                 "h01": {"view_key": "vk1", "base": {"lineage": "L-t", "generation": 1},
                         "names": {"0x100": "hy00x1", "0x200": "hy01x9"}}}
        return root, base_names, list(acked), views, head or {"0x100": "hy00x1", "0x200": "FUN_200"}

    def hy_judge(tag, **kw):
        root = base / "hy" / tag
        if root.exists():
            rmtree(root)
        r, bn, ack, vw, hd = hy_make(root, **kw)
        return judge_hy_store(r, bn, ack, vw, hd)

    rep = hy_judge("clean")
    check("Hydralysis root: a consistent lineage, view and head pass K1, K8, K12, K16 and K17",
          rep.ok and {"K1", "K8", "K12", "K16", "K17"} <= set(rep.checked), (rep.codes(), rep.checked))
    rep = hy_judge("k1", tamper_gen=True)
    check("planted K1: a file of a sealed generation changed after its manifest", "K1:changed" in rep.codes(), rep.codes())
    rep = hy_judge("k8", view={"0x100": "hy00x1", "0x200": "FUN_200"})
    check("planted K8: a view that lost its pending record differs from its store's replay",
          "K8:view_differs_from_replay" in rep.codes(), rep.codes())
    rep = hy_judge("k8b", view={"0x100": "hy00x2", "0x200": "hy01x9"})
    check("planted K8: a view that shows another view's unpublished name differs from its replay",
          "K8:view_differs_from_replay" in rep.codes(), rep.codes())
    r_, bn, ack, vw, hd = hy_make(base / "hy" / "k8c")
    (r_ / "overlays" / "vk1.json").write_text(json.dumps(oracle.seal_record({"edits": [], "revision": 3})))
    vw["h01"] = {"view_key": "vk1", "base": {"lineage": "L-t", "generation": 0}, "pending": 0,
                 "names": {"0x100": "hy00x1", "0x200": "FUN_200"}}
    rep = judge_hy_store(r_, bn, ack, vw, hd)
    check("K8: a view with no pending record, based behind the head, reads the head: clean", rep.ok, rep.codes())
    vw["h01"]["names"] = {"0x100": "FUN_100", "0x200": "FUN_200"}
    rep = judge_hy_store(r_, bn, ack, vw, hd)
    check("planted K8: such a view that shows an older generation than the head",
          "K8:view_differs_from_replay" in rep.codes(), rep.codes())
    rep = hy_judge("k12", acked=("c-1", "c-9"))
    check("planted K12: an acknowledged publish no CURRENT.log line names", "K12:acked_publish_missing" in rep.codes(), rep.codes())
    rep = hy_judge("k12b", extra_line={"seq": 3, "gen": 2, "reason": "commit", "csids": ["c-1"]})
    check("planted K12: a changeset applied twice", "K12:applied_twice" in rep.codes(), rep.codes())
    rep = hy_judge("k16", head={"0x100": "FUN_100", "0x200": "FUN_200"})
    check("planted K16: a head that lost a published rename (a silent lost update)",
          "K16:head_differs_from_model" in rep.codes(), rep.codes())
    rep = hy_judge("k17", corrupt_done=True)
    check("planted K17: a sealed record whose seal does not match (and no .bak)", "K17:record_corrupt" in rep.codes(), rep.codes())
    r_, bn, ack, vw, hd = hy_make(base / "hy" / "k17b")
    with open(r_ / "lineages" / "L-t" / "CURRENT.log", "r+b") as f:
        f.seek(12)
        f.write(b"#")
    rep = judge_hy_store(r_, bn, ack, vw, hd)
    check("planted K17: a torn middle line of CURRENT.log", "K17:torn_middle" in rep.codes(), rep.codes())
    check("K16 model: a rollback line drops the generations after it from the chain",
          [x["gen"] for x in hy_effective_chain([{"gen": 1}, {"gen": 2}, {"gen": 1, "reason": "rollback"}, {"gen": 2}])] == [1, 2])

    t = time.time()
    hrows = [{"t": t, "agent": "h00", "op": "hy_decompile", "ok": True}, {"t": t, "agent": "h00", "op": "hy_publish", "ok": True},
             {"t": t, "agent": "h00", "op": "hy_rebase", "ok": True},
             {"t": t, "agent": "h00", "op": "hy_k15", "ok": True, "rebuilt": True, "diff": []}]
    viol, summ = judge_hy_rows(hrows)
    check("H-agent rows: clean rows give no violation and count publish, rebase and queries",
          not viol and summ["counts"] == {"publish": 1, "rebase": 1, "hydralysis_queries": 1} and summ["k15"]["rebuilt"] == 1,
          (viol, summ))
    viol, _ = judge_hy_rows(hrows + [{"t": t, "agent": "h00", "op": "hy_k15", "ok": True, "rebuilt": True,
                                      "diff": [["0x100", "hy00x2", "hy00x1"]]}])
    check("planted K15: a view rebuilt from base + store that differs from the live view",
          any(k == "K15:view_rebuilt_differs" for k, _ in viol), viol)
    viol, _ = judge_hy_rows(hrows + [{"t": t, "agent": "h00", "op": "hy_publish", "ok": False, "code": "candidate_failed"}])
    check("planted: a publish that ended candidate_failed is an unexpected error", any(k == "hy_unexpected_error" for k, _ in viol), viol)
    viol, _ = judge_hy_rows(hrows + [{"t": t, "agent": "h00", "op": "hy_edit", "ok": False, "code": "busy",
                                      "details": {"reason": "capacity"}}])
    check("an explained busy of an H-agent is not a violation", not viol, viol)
    stale = {"t": t, "agent": "h00", "op": "hy_edit", "ok": False, "code": "stale_view", "n": 4, "attempt": 1,
             "details": {"stale": "master_generation_changed"}}
    redo = {"t": t + 0.2, "agent": "h00", "op": "hy_stale_redo", "ok": True, "n": 4, "attempt": 1}
    viol, summ = judge_hy_rows(hrows + [stale, {"t": t + 0.1, "agent": "h00", "op": "hy_rebase", "ok": True}, redo])
    check("stale_view (master_generation_changed) followed by rebase + redo is explained, not a violation",
          not viol and summ["stale_redone"] == 1, (viol, summ))
    viol, _ = judge_hy_rows(hrows + [stale])
    check("planted: a stale_view edit with no rebase + redo is a violation", any(k == "hy_unexpected_error" for k, _ in viol), viol)
    viol, _ = judge_hy_rows(hrows + [stale, {**redo, "agent": "h01"}])
    check("planted: another agent's redo does not explain a stale_view", any(k == "hy_unexpected_error" for k, _ in viol), viol)
    viol, _ = judge_hy_rows(hrows + [stale, {**redo, "n": 5}])
    check("planted: a redo of another edit does not explain a stale_view", any(k == "hy_unexpected_error" for k, _ in viol), viol)
    viol, _ = judge_hy_rows(hrows + [{**stale, "details": {"stale": "base_missing"}}, redo])
    check("planted: a stale_view for another reason is still a violation", any(k == "hy_unexpected_error" for k, _ in viol), viol)
    import soak_hy  # stdlib + oracle only at import time
    sk = base / "hy-storekey"
    rmtree(sk)
    (sk / "overlays").mkdir(parents=True)
    (sk / "working" / "abc123r" / "w-1").mkdir(parents=True)      # the rebased copy's folder: no store of that name
    (sk / "overlays" / "abc123.json").write_text(json.dumps(oracle.seal_record({"edits": [{"id": "o-7"}], "revision": 1})))
    (sk / "overlays" / "zzz.json").write_text(json.dumps(oracle.seal_record({"edits": [{"id": "o-1"}], "revision": 1})))
    check("H-agent view key: the store that holds the acknowledged record, not the rebased copy's <key>r folder",
          soak_hy.store_key_of(sk, "o-7") == "abc123" and soak_hy.store_key_of(sk, "o-9") is None)
    E = soak_hy.HyError
    nxt = {"error": "stale_view", "stale": "master_generation_changed",
           "next": {"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "rebase", "expect_revision": 7}}}
    check("H-agent rebases with the call the stale_view refusal names in next, else at the current revision",
          soak_hy.rebase_options(E("stale_view", "x", nxt), lambda: 99) == {"kind": "rebase", "expect_revision": 7}
          and soak_hy.rebase_options(E("stale_view", "x", {"stale": "master_generation_changed"}), lambda: 99)
          == {"kind": "rebase", "expect_revision": 99})
    viol, _ = judge_hy_rows(hrows + [{**stale, "op": "hy_decompile"}, {**redo}])
    check("planted: stale_view on a read is a violation (reads answer from the working copy; only mutations are refused)",
          any(k == "hy_unexpected_error" and "hy_decompile:stale_view" in d for k, d in viol), viol)
    class Clock:
        def __init__(self):
            self.t = 1000.0

        def now(self):
            return self.t

        def sleep(self, d):
            self.t += d
    ck = Clock()
    done_at = 1003.0          # decided 3 s after the stop (the GATE11 soak-pr2 case: decided after the agents gave up)
    poll = lambda c: ({"changeset": {"state": "done", "outcome": "applied", "generation": 9}} if ck.t >= done_at  # noqa: E731
                      else {"changeset": {"state": "publish_pending"}, "queue": {"leader": "x"}})
    w = soak_hy.await_decision(poll, lambda c: c, "c-1", 2000.0, lambda: True, clock=ck.now, sleep=ck.sleep)
    check("H-agent: a publish in flight at the stop is awaited until decided, not reported publish_undecided",
          w["outcome"] == "applied" and w["past_stop"] and w["generation"] == 9, w)
    ck.t, done_at = 1000.0, 1e9
    w = soak_hy.await_decision(poll, lambda c: c, "c-1", 2000.0, lambda: True, clock=ck.now, sleep=ck.sleep, grace_s=10)
    check("planted: a publish never decided within the stop grace is still undecided (a violation)",
          w["outcome"] is None and w["past_stop"] and 1009.0 <= ck.t <= 1011.0, (w, ck.t))
    ck.t, n_re = 1000.0, []
    lpoll = lambda c: {"changeset": {"state": "publish_pending"}, "queue": {}} if not n_re else         {"changeset": {"state": "done", "outcome": "applied", "generation": 2}}  # noqa: E731
    w = soak_hy.await_decision(lpoll, lambda c: n_re.append(c) or c, "c-2", 1100.0, lambda: False, clock=ck.now,
                               sleep=ck.sleep)
    check("H-agent: a leaderless changeset is published again (same csid) and then decided",
          w["outcome"] == "applied" and w["restarts"] == 1 and n_re == ["c-2"] and not w["past_stop"], w)
    check("H-agent redoes an edit on stale_view (master_generation_changed) only",
          soak_hy.is_stale_master(E("stale_view", "x", {"error": "stale_view", "stale": "master_generation_changed"}))
          and not soak_hy.is_stale_master(E("stale_view", "x", {"stale": "base_missing"}))
          and not soak_hy.is_stale_master(E("busy", "x", {"stale": "master_generation_changed"})))

    k11 = {"shared": {"tag": "k11s1", "q_saw": "k11s1"}, "isolated": {"tag": "k11P1", "q_saw": "FUN_1", "p_saw": "k11P1"},
           "errors": []}
    check("K11p: shared id shares, distinct as isolates: clean", judge_k11p(k11).ok and "K11p" in judge_k11p(k11).checked)
    check("planted K11p: Q with its own as sees P's unpublished tag",
          "K11p:unpublished_tag_visible" in judge_k11p({**k11, "isolated": {**k11["isolated"], "q_saw": "k11P1"}}).codes())
    check("planted K11p: two sub-agents without as do not share a view",
          "K11p:shared_id_not_shared" in judge_k11p({**k11, "shared": {"tag": "k11s1", "q_saw": "FUN_1"}}).codes())
    check("planted K11p: a probe that could not run is a violation, not a pass",
          "K11p:probe_failed" in judge_k11p({**k11, "errors": [["mcp_no_reply", "x"]]}).codes())

    vp = {"max_views": 32, "opened": 20, "held_by_others": 12, "governor_views_max": 32,
          "refusals": [{"code": "busy", "details": {"reason": "capacity", "resource": "views"}}], "errors": [],
          "daemon_alive": True, "oom_lines": []}
    check("100-view probe: refused busy/capacity at maxViews: clean", judge_view_probe(vp).ok)
    check("planted GR8: an OutOfMemoryError in the daemon log",
          "GR8:out_of_memory" in judge_view_probe({**vp, "oom_lines": ["java.lang.OutOfMemoryError: Java heap space"]}).codes())
    check("planted GR8: a dead daemon", "GR8:daemon_died" in judge_view_probe({**vp, "daemon_alive": False}).codes())
    check("planted GR8: more views than maxViews", "GR8:views_above_max" in judge_view_probe({**vp, "governor_views_max": 40}).codes())
    check("planted GR8: 100 views opened, never refused",
          "GR8:not_refused" in judge_view_probe({**vp, "opened": 30, "held_by_others": 0, "refusals": []}).codes())
    check("planted GR8: a refusal that is not a structured busy",
          "GR8:unstructured_refusal" in judge_view_probe({**vp, "refusals": [], "errors": [{"code": "failed"}]}).codes())
    check("publish leader kill: the lock freed after the kill is clean",
          judge_leader_kill({"killed": True, "lock_held_after": False}).ok)
    check("planted: a publish lock still held after its leader was killed",
          "K12:leader_lock_stuck" in judge_leader_kill({"killed": True, "lock_held_after": True, "pid": 1}).codes())

    st_ok = {"projects": [{"id": "p1", "gpr": "C:/w/w-1/analysis.gpr"}],
             "programs": [{"project": "p1", "users": [3], "unsavedEdits": 2}, {"project": "p1", "users": [], "unsavedEdits": 0}]}
    check("Hydralysis engine: programs in use, or unused without edits: no leak",
          judge_hy_engine(hy_engine_facts(st_ok, {"governor": {"views": 2, "maxViews": 32}})).ok)
    st_bad = {"projects": st_ok["projects"], "programs": st_ok["programs"] + [{"project": "p1", "users": [], "unsavedEdits": 3}]}
    check("planted K7: a program nobody uses that holds unsaved edits (a view kept for ever)",
          "K7:orphaned_unsaved_programs" in judge_hy_engine(hy_engine_facts(st_bad, None)).codes())

    sl = ["INFO  client 3 (soak-a01, soak) opened project p8 C:\\w\\cand\\c1\\Cand.gpr (writable) in 10 ms (Session)",
          "INFO  client 3 (soak-a01, soak) sealed C:\\w\\cand\\c1\\Cand.gpr at revision 1 (Seals)",
          "INFO  client 4 (x, soak) opened project p9 C:\\w\\cand\\c1\\Cand.gpr (read-only view) in 5 ms (Session)"]
    check("K1 log: the candidate's own writable open before its seal and a read-only open after it are not violations",
          writable_opens_after_seal(sl, ["C:\\w\\cand\\c1\\Cand.gpr"]) == [])
    check("planted K1: a writable open of a sealed candidate after its seal line",
          len(writable_opens_after_seal(sl + ["INFO  client 5 (y, soak) opened project p10 C:\\w\\cand\\c1\\Cand.gpr (writable) "
                                              "in 3 ms (Session)"], ["C:\\w\\cand\\c1\\Cand.gpr"])) == 1)

    # K6 of a generation candidate: complete in state candidate (before its seal), a violation in another state
    cdir = base / "k6cand"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "Cand.gpr").write_text("")
    (cdir / "Cand.rep").mkdir(exist_ok=True)
    (cdir / "Cand.fork.json").write_text(json.dumps({"purpose": "generation", "state": "candidate"}))
    rep = oracle.check_k6_tree(base / "k6cand", swept=True)
    check("K6: an unsealed generation candidate (state candidate) is a complete fork", rep.ok, rep.codes())
    (cdir / "Cand.fork.json").write_text(json.dumps({"purpose": "fork", "state": "candidate"}))
    rep = oracle.check_k6_tree(base / "k6cand", swept=True)
    check("planted K6: a plain fork left in state candidate", "K6:sidecar_state" in rep.codes(), rep.codes())
    (cdir / "Cand.fork.json").write_text(json.dumps({"purpose": "fork", "state": "complete"}))
    (cdir / "Cand.fork.json.4242.tmp").write_text("{}")
    rep = oracle.check_k6_tree(base / "k6cand", swept=False)
    check("K6: a pid-named sidecar temporary (8.13 A62) next to a complete fork is pending before the sweep",
          rep.ok and oracle.k6_pending_parents(rep) == [str(cdir)], (rep.codes(), rep.notes))
    rep = oracle.check_k6_tree(base / "k6cand", swept=True)
    check("planted K6: a pid-named sidecar temporary left after the sweep", "K6:sidecar_tmp_left" in rep.codes(), rep.codes())

    # the verdict with the lane: every VF item must have run
    full_hy = profile_minimums("pr", True)
    wl_hy = {**{op: 5 for op in OPS}, "publish": 3, "rebase": 3, "hydralysis_queries": 9, "candidate_analysis": 2}
    vf_checks = set(UNEXERCISED_CHECKS)
    v = verdict_of("pr", rep_ok, full_hy, wl_hy, feats_ok, [], None, None, vf_checks, hy_enabled=True)
    check("with the Hydralysis lane and every VF item run, a full pr run is PASS by itself",
          v["verdict"] == "PASS" and v["gate_eligible"], v["gaps"])
    v = verdict_of("pr", rep_ok, {**full_hy, "kill_publish_leader": 1}, wl_hy, feats_ok, [], None, None, vf_checks,
                   hy_enabled=True)
    check("planted: one publish-leader kill short of the minimum: INCOMPLETE and named",
          v["verdict"] == "INCOMPLETE" and any("kill_publish_leader" in g for g in v["hard_gaps"]), v["gaps"])
    v = verdict_of("pr", rep_ok, full_hy, {**wl_hy, "rebase": 0}, feats_ok, [], None, None, vf_checks, hy_enabled=True)
    check("planted: no rebase ran: INCOMPLETE and named", v["verdict"] == "INCOMPLETE" and any("rebase" in g for g in v["hard_gaps"]))
    v = verdict_of("pr", rep_ok, full_hy, wl_hy, feats_ok, [], None, None, vf_checks - {"K16"}, hy_enabled=True)
    check("planted: K16 never ran: INCOMPLETE and named", v["verdict"] == "INCOMPLETE" and any("K16" in g for g in v["hard_gaps"]))
    v = verdict_of("pr", rep_ok, full_hy, {**wl_hy, "candidate": 0}, feats_ok, [], None, None, vf_checks, hy_enabled=True)
    check("planted: no analysis in a candidate ran: INCOMPLETE and named",
          v["verdict"] == "INCOMPLETE" and any("candidate" in g for g in v["hard_gaps"]))
    v = verdict_of("pr", rep_ok, full_hy, wl_hy, feats_ok, [], None, None, vf_checks, hy_enabled=False)
    check("without the lane the Hydralysis items stay named gaps (never PASS)",
          v["verdict"] == "INCOMPLETE" and any("kill_publish_leader" in g for g in v["soft_gaps"]))
    v = verdict_of("pr", rep_ok, {**full_hy, "oom_probe_100_views": 0}, wl_hy, feats_ok, [], None, None, vf_checks,
                   hy_enabled=True)
    check("planted: the 100-view probe never ran: INCOMPLETE and named",
          v["verdict"] == "INCOMPLETE" and any("oom_probe_100_views" in g for g in v["hard_gaps"]))

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
    r.add_argument("--hy-binary", help="the Hydralysis lane (VF items): the executable Hydralysis prepares as its target "
                                       "(copied into --work; never written in place)")
    r.add_argument("--hy-src", help="the Hydralysis source folder to import (e.g. <worktree>/src)")
    r.add_argument("--hy-python", help="the Python that runs Hydralysis (its virtual environment)")
    r.add_argument("--hy-agents", type=int, default=0, help="H-agents (default per profile: " +
                   ", ".join(f"{k} {v}" for k, v in HY_AGENTS.items()) + ")")
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
