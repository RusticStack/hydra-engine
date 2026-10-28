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
"""Daemon tests of package E2a (PROTOCOL-3.md D41, 9.15 and GR10): the fork publish is atomic and
retryable, and the sweeper removes only what the engine made and can prove dead. Standard library
only; Windows for the process-start-time helper (the tests that need it skip elsewhere).

Run through ``daemon_tests.py`` (``--only e2a_kill_fork,...``). Environment:

* ``E2A_KILLS``    how many daemon kills ``e2a_kill_fork`` makes (default 24; the 9.15 batch is 300
                   or more: ``E2A_KILLS=300``)
* ``E2A_WORKERS``  daemons killed at once (default 4)
* ``E2A_CLIENT_KILLS`` client kills of ``e2a_client_kill`` (default 18, the C measurement)
* ``E2A_REPORT``   a file the kill batch writes its per-iteration table to (JSON)

Tests:

* ``e2a_kill_fork`` (GR10, 9.15): the daemon is killed at a random time, when the staging folder
  first appears, or when the ``.rep`` first appears (the trigger-timed recipe of D48), during
  ``fork_project``. The state of the destination is read before anything restarts: it must be
  absent (no ``.gpr``) or complete, never a ``.gpr`` without its ``.rep`` or its sidecar, and a
  ``.rep`` without ``.gpr`` only when the intent of the dead publisher names it. A retry to the same
  path then succeeds (or, for a fork that was already complete, answers the ordinary ``conflict``
  and the fork is finished and complete); and no staging folder is left after that fork.
* ``e2a_client_kill``: a client killed during ``fork_project`` leaves nothing (0 of 18 measured).
* ``e2a_handle_holder`` (SP6): a handle without delete sharing on the staged ``.rep``, ``.gpr`` or
  staging folder during the publish moves: retried and complete when brief, an error with nothing
  published when long, a clean retry afterwards (``E2A_SP6_REPORT`` names the per-case table).
* ``e2a_rollback_holder`` (F1): a failed publish (the staged ``.gpr`` held) rolls back while a second
  holder has the sidecar: the rollback waits it out and leaves nothing at the destination, where a
  single delete attempt left the sidecar alone (``sidecar_only``) and blocked the name.
* ``e2a_sweeper``: the planted states of D41: the sweeper removes the staging folders and ``.rep`` of
  dead owners, the temporary files older than 10 minutes, finishes a ``publishing`` sidecar, and
  never touches a path whose intent names a live process; the rest is only reported.
"""
import contextlib
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

import daemon_tests as dt
from daemon_tests import Fail, check, expect_error

STAGING = re.compile(r"^\..+\.fork-.+\.tmp$")
BALLAST_FILES = 8
BALLAST_MB = 4
_SOURCES = {}


def make_source(c, tag="main"):
    """A small project with some ballast (so that the copy takes a few tens of milliseconds),
    made once per working directory. The source is only ever read."""
    key = (str(c.work), tag)
    if key not in _SOURCES:
        base = c.work / f"e2a-src-{tag}"
        if base.exists():
            shutil.rmtree(base)
        d = c.daemon("e2a-mk")
        with d.connect("e2a", "tests") as s:
            gpr = c.make_project(s, base, "Src")
        d.stop()
        ballast = base / "Src.rep" / "ballast"
        ballast.mkdir()
        blob = os.urandom(1 << 20)
        for i in range(BALLAST_FILES):
            (ballast / f"b{i}.bin").write_bytes(blob * BALLAST_MB)
        _SOURCES[key] = gpr
    return _SOURCES[key]


def tree(folder):
    """{relative path: (size, mtime_ns)} of every file below ``folder`` (the K1 tree hash's input)."""
    folder = pathlib.Path(folder)
    return {str(f.relative_to(folder)): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in folder.rglob("*") if f.is_file()}


def read_text_shared(path):
    """``path.read_text`` through a handle that shares delete (``FILE_SHARE_DELETE``), which an
    ordinary Python ``open`` does not: while a Python reader has the sidecar open, the engine's
    rename over it is refused, and a reader that a loaded machine stalls inside ``read`` holds the
    engine up for longer than its retry budget. A tool that only watches the file (the observers of
    these tests) must not be a handle holder: the holders are the explicit ``Holder`` objects."""
    path = pathlib.Path(path)
    if os.name != "nt":
        return path.read_text(encoding="utf-8")
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    # GENERIC_READ; share read, write and delete; OPEN_EXISTING
    h = k.CreateFileW(str(path), 0x80000000, 0x7, None, 3, 0x80, None)
    if h is None or h == wintypes.HANDLE(-1).value or h == 2 ** 64 - 1 or h == 0xFFFFFFFF:
        err = ctypes.get_last_error()
        raise OSError(err, f"cannot open {path} (Windows error {err})")
    fd = msvcrt.open_osfhandle(h, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        return f.read()


def classify(pdir, name, read_sidecar=True):
    """What the destination looks like on disk: ``(state, staging folders, sidecar state)``.
    ``read_sidecar=False`` (the observers) leaves the sidecar state ``None`` and does not open the
    file at all."""
    pdir = pathlib.Path(pdir)
    ents = set(os.listdir(pdir)) if pdir.is_dir() else set()
    gpr, rep, sc = f"{name}.gpr" in ents, f"{name}.rep" in ents, f"{name}.fork.json" in ents
    staging = sorted(e for e in ents if STAGING.match(e))
    sc_state = None
    if sc and read_sidecar:
        try:
            sc_state = json.loads(read_text_shared(pdir / f"{name}.fork.json")).get("state", "none")
        except (OSError, ValueError):
            sc_state = "unreadable"
    if gpr:
        state = "complete" if rep and sc else ("gpr_no_rep" if not rep else "gpr_no_sidecar")
    elif rep:
        state = "rep_only"
    elif sc:
        state = "sidecar_only"
    else:
        state = "absent"
    return state, staging, sc_state


def proc_start_ms(pid):
    """The creation time of a process in ms since the epoch (what Java's ProcessHandle reports)."""
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes
    k = ctypes.windll.kernel32
    k.OpenProcess.restype = wintypes.HANDLE
    h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return 0
    try:
        t = [wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(h, *[ctypes.byref(x) for x in t]):
            return 0
        v = (t[0].dwHighDateTime << 32) | t[0].dwLowDateTime
        return (v - 116444736000000000) // 10000
    finally:
        k.CloseHandle(h)


def check_fork_matches_source(src_gpr, fork_gpr):
    """The fork has every file of the source (the K-oracle's 'complete')."""
    sd, fd = src_gpr.parent, fork_gpr.parent
    sname, fname = src_gpr.stem, fork_gpr.stem
    want = {str(f.relative_to(sd / f"{sname}.rep")): f.stat().st_size
            for f in (sd / f"{sname}.rep").rglob("*") if f.is_file() and not f.name.endswith(".lock")
            and not re.match(r"tmp\d+\.(ps|tmp)", f.name)}
    got = {str(f.relative_to(fd / f"{fname}.rep")): f.stat().st_size
           for f in (fd / f"{fname}.rep").rglob("*") if f.is_file() and not f.name.endswith(".lock")
           and not re.match(r"tmp\d+\.(ps|tmp)", f.name)}
    missing = sorted(set(want) - set(got))
    wrong = sorted(k for k in want if k in got and want[k] != got[k])
    check(not missing and not wrong, f"{fork_gpr} is not a complete copy: missing {missing[:3]}, "
          f"wrong size {wrong[:3]}")


def leftovers(pdir):
    """Entries of ``pdir`` that are neither a fork's three files nor a lock file."""
    return sorted(e for e in os.listdir(pdir)
                  if not re.fullmatch(r".+\.(gpr|rep|fork\.json|lock|lock~)|\.ghidra\.test\.lock~+", e)
                  or STAGING.match(e) or e.endswith(".fork.json.tmp"))


# ---- the kill batch -------------------------------------------------------------------------

def _kill_pid(c, d):
    ep = d.read_endpoint()
    c.gs._kill_pid(int(ep["pid"]))


def _one_kill(c, src, d, s, pdir, name, mode, rng):
    """Sends fork_project and kills the daemon at the moment ``mode`` says. Returns the delay used
    and whether the reply arrived before the kill."""
    pdir = str(pdir)
    ep_pid = int(d.read_endpoint()["pid"])
    delay = {"random": rng.uniform(0, 0.35),
             "staging": rng.choice([0, 0, 0.002, 0.005, 0.01, 0.02, 0.04, 0.08, 0.12]),
             "rep": rng.choice([0, 0, 0, 0.0005, 0.001, 0.002, 0.004])}[mode]
    fired = threading.Event()
    stop = threading.Event()

    def killer():
        t0 = time.perf_counter()
        if mode == "random":
            time.sleep(delay)
        else:
            want_rep = f"{name}.rep"
            while not stop.is_set() and time.perf_counter() - t0 < 30:
                try:
                    ents = os.listdir(pdir)
                except OSError:
                    ents = []
                if (mode == "staging" and any(STAGING.match(e) for e in ents)) or \
                        (mode == "rep" and want_rep in ents):
                    break
            if stop.is_set():
                return
            time.sleep(delay)
        c.gs._kill_pid(ep_pid)
        fired.set()

    th = threading.Thread(target=killer, daemon=True)
    th.start()
    answered = False
    try:
        s.call("fork_project", project=str(src), path=pdir, name=name, mode="full", wait=60000)
        answered = True
    except Exception:  # noqa: BLE001  (the connection ends when the daemon is killed)
        pass
    stop.set()
    if not fired.is_set():
        c.gs._kill_pid(ep_pid)  # the fork ended first: still kill, so every iteration restarts
    th.join(5)
    d.kill()
    return delay, answered


def _kill_worker(c, src, wid, iters, seed, base, out):
    rng = random.Random(seed)
    d = c.daemon(f"e2a-kill-{wid}")
    pending = None  # (pdir, name, before, report) of the previous iteration
    modes = ["staging", "rep", "random"]
    try:
        for k in range(iters):
            mode = modes[(k + wid) % 3]
            pdir = base / f"w{wid}-{k}"
            name = f"F{k}"
            s = d.connect(f"e2a-kill-{wid}", "tests")
            if pending:
                p_pdir, p_name, p_before, p_rep = pending
                _retry_on(c, src, s, p_pdir, p_name, p_before, p_rep)
                out.append(p_rep)
                pending = None
            delay, answered = _one_kill(c, src, d, s, pdir, name, mode, rng)
            before = classify(pdir, name)
            rep = {"worker": wid, "iter": k, "mode": mode, "delay_ms": round(delay * 1000, 2),
                   "answered": answered, "before": before[0], "before_staging": before[1],
                   "before_sidecar": before[2],
                   "before_intent": any((pdir / st / "intent.json").is_file()
                                        for st in before[1])}
            pending = (pdir, name, before, rep)
            with contextlib.suppress(Exception):
                s.close()
        if pending:
            p_pdir, p_name, p_before, p_rep = pending
            s = d.connect(f"e2a-kill-{wid}", "tests")
            _retry_on(c, src, s, p_pdir, p_name, p_before, p_rep)
            s.close()
            out.append(p_rep)
    except Exception as e:  # noqa: BLE001
        out.append({"worker": wid, "error": f"{type(e).__name__}: {e}"})
    finally:
        with contextlib.suppress(Exception):
            d.stop(force=True)


def _retry_on(c, src, s, pdir, name, before, rep):
    try:
        s.call("fork_project", project=str(src), path=str(pdir), name=name, mode="full",
               wait=60000)
        rep["retry"] = "ok"
    except Exception as e:  # noqa: BLE001
        rep["retry"] = getattr(e, "code", type(e).__name__)
        rep["retry_error"] = str(e)[:200]
    after = classify(pdir, name)
    rep["after"], rep["after_staging"], rep["after_state"] = after
    rep["leftovers_after"] = leftovers(pdir)
    if after[0] == "complete":
        with contextlib.suppress(Exception):
            check_fork_matches_source(src, pdir / f"{name}.gpr")
            rep["matches_source"] = True
        rep.setdefault("matches_source", False)


def t_e2a_kill_fork(c):
    """See the module docstring: kills of the daemon during fork_project, state read before restart."""
    kills = int(os.environ.get("E2A_KILLS", "24"))
    workers = max(1, int(os.environ.get("E2A_WORKERS", "4")))
    src = make_source(c, "kill")
    before_tree = tree(src.parent)
    base = c.work / "e2a-kill"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    out, threads = [], []
    per = [kills // workers + (1 if w < kills % workers else 0) for w in range(workers)]
    seed = int(os.environ.get("E2A_SEED", "20261028"))
    t0 = time.perf_counter()
    for w, n in enumerate(per):
        th = threading.Thread(target=_kill_worker, args=(c, src, w, n, seed + w, base, out))
        th.start()
        threads.append(th)
    for th in threads:
        th.join()
    secs = time.perf_counter() - t0
    errors = [r for r in out if "error" in r]
    rows = [r for r in out if "error" not in r]
    check(not errors, f"worker errors: {errors[:2]}")
    check(len(rows) == kills, f"{len(rows)} iterations ran, {kills} wanted")
    from collections import Counter
    pre = Counter(r["before"] for r in rows)
    orphans = sum(1 for r in rows if r["before_staging"])
    pub_state = sum(1 for r in rows if r["before_sidecar"] == "publishing")
    unrecognised_rep = sum(1 for r in rows
                           if r["before"] == "rep_only" and not r["before_intent"])
    blocked = sum(1 for r in rows if r["before"] != "complete" and r["retry"] != "ok")
    staging_after = sum(1 for r in rows if r["after_staging"])
    left_after = sum(1 for r in rows if r["leftovers_after"])
    incomplete_after = sum(1 for r in rows if r["after"] != "complete")
    unfinished = sum(1 for r in rows if r["after_state"] != "complete")
    not_matching = sum(1 for r in rows if r["after"] == "complete" and not r.get("matches_source"))
    bad_pre = pre.get("gpr_no_rep", 0) + pre.get("gpr_no_sidecar", 0)
    summary = {"kills": kills, "seconds": round(secs), "before": dict(pre),
               "orphan_staging_before_retry": orphans, "sidecar_publishing_before_retry": pub_state,
               "rep_only_without_dead_intent": unrecognised_rep,
               "gpr_without_rep_or_sidecar": bad_pre, "retry_blocked": blocked,
               "staging_after_next_fork": staging_after, "leftovers_after": left_after,
               "not_complete_after": incomplete_after, "sidecar_not_complete_after": unfinished,
               "fork_differs_from_source": not_matching,
               "modes": dict(Counter(r["mode"] for r in rows)),
               "answered_before_kill": sum(1 for r in rows if r["answered"])}
    rp = os.environ.get("E2A_REPORT")
    if rp:
        pathlib.Path(rp).write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    c.timings["e2a_kill_fork summary"] = summary
    check(tree(src.parent) == before_tree, "the source project was written (K1)")
    problems = []
    if bad_pre:
        problems.append(f"{bad_pre} forks with a .gpr but no .rep or no sidecar")
    if unrecognised_rep:
        problems.append(f"{unrecognised_rep} .rep without .gpr that no intent names")
    if blocked:
        problems.append(f"{blocked} retries blocked: " + "; ".join(
            f"{r['before']}/{r['retry']}: {r.get('retry_error', '')}"[:120]
            for r in rows if r["before"] != "complete" and r["retry"] != "ok")[:400])
    if staging_after or left_after:
        problems.append(f"{staging_after} staging folders and {left_after} leftovers after the "
                        f"next fork: " + "; ".join(str(r["leftovers_after"]) for r in rows
                                                   if r["leftovers_after"])[:300])
    if incomplete_after or unfinished or not_matching:
        problems.append(f"after the retry: {incomplete_after} not complete, {unfinished} sidecars "
                        f"not 'complete', {not_matching} differing from the source")
    check(not problems, json.dumps(summary) + " :: " + " | ".join(problems))
    return json.dumps(summary)


# ---- the client kill ------------------------------------------------------------------------

def t_e2a_client_kill(c):
    kills = int(os.environ.get("E2A_CLIENT_KILLS", "18"))
    src = make_source(c, "ck")
    base = c.work / "e2a-ckill"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    d = c.daemon("e2a-ckill")
    rng = random.Random(7)
    bad = []
    states = {}
    with d.connect("e2a-watch", "tests") as w:
        for k in range(kills):
            pdir, name = base / f"c{k}", f"C{k}"
            p = c.child("""
s = gs.Daemon(A[0], A[1], A[2]).connect('doomed', 'tests')
s.call('fork_project', project=A[3], path=A[4], name=A[5], mode='full', wait=60000)
""", c.a.ghidra, c.state, "e2a-ckill", src, pdir, name)
            time.sleep(rng.uniform(0.35, 1.2))
            p.kill()
            p.wait(10)
            # the daemon either finishes or abandons the fork; wait until it is quiet
            killed_at = time.time()
            end = killed_at + 30
            while time.time() < end:
                if pdir.exists():
                    st = classify(pdir, name)
                    if st[0] in ("complete", "absent") and not st[1] and not leftovers(pdir):
                        break
                elif time.time() > killed_at + 3:
                    break  # nothing was ever created
                time.sleep(0.2)
            st = classify(pdir, name) if pdir.exists() else ("absent", [], None)
            states[st[0]] = states.get(st[0], 0) + 1
            if st[0] not in ("complete", "absent") or st[1] or (pdir.exists() and leftovers(pdir)):
                bad.append((k, st, leftovers(pdir) if pdir.exists() else []))
            w.call("ping")
    d.stop()
    check(not bad, f"{len(bad)} of {kills} client kills left something: {bad[:3]}")
    return f"{kills} client kills, nothing left: {states}"


# ---- the sweeper ----------------------------------------------------------------------------

def _plant_intent(folder, **kw):
    folder.mkdir(parents=True, exist_ok=True)
    rec = {"format": 1, "kind": "ghidra-session-fork-intent", "phase": "staging",
           "repCreatedMs": 0, "createdMs": int(time.time() * 1000)}
    rec.update(kw)
    (folder / "intent.json").write_text(json.dumps(rec))
    (folder / "payload.bin").write_bytes(b"x" * 1000)


def t_e2a_sweeper(c):
    if os.name != "nt":
        return "skipped: the planted live process needs the Windows start-time helper"
    src = make_source(c, "sw")
    base = c.work / "e2a-sweep"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    done = subprocess.Popen([sys.executable, "-c", "pass"])
    dead_start = proc_start_ms(done.pid)
    done.wait()
    live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)"])
    c.procs.append(live)
    live_start = proc_start_ms(live.pid)
    check(live_start > 0, "cannot read the start time of the live process")
    dead = dict(pid=done.pid, procStartMs=dead_start)
    alive = dict(pid=live.pid, procStartMs=live_start)
    reused = dict(pid=live.pid, procStartMs=live_start - 3_600_000)  # same pid, another process
    # 1. staging of a dead owner, copy under way
    _plant_intent(base / ".A.fork-dead1.tmp", id="dead1", name="A", **dead)
    # 2. staging of a live owner, with a .rep at the destination: untouched
    _plant_intent(base / ".B.fork-live1.tmp", id="live1", name="B", phase="moving",
                  repCreatedMs=1, **alive)
    (base / "B.rep").mkdir()
    (base / "B.rep" / "f").write_bytes(b"live publisher's")
    # 3. dead owner that moved its .rep (the intent says which one): .rep and staging go
    (base / "C.rep").mkdir()
    (base / "C.rep" / "f").write_bytes(b"half fork")
    born = int(os.stat(base / "C.rep").st_birthtime_ns // 1_000_000)
    _plant_intent(base / ".C.fork-dead3.tmp", id="dead3", name="C", phase="moving",
                  repCreatedMs=born, **dead)
    # 4. a dead intent that never moved a .rep, and a .rep nobody can show is the engine's: reported
    (base / "D.rep").mkdir()
    (base / "D.rep" / "f").write_bytes(b"foreign")
    _plant_intent(base / ".D.fork-dead4.tmp", id="dead4", name="D", **dead)
    # 5. the pid of a live process with another start time (pid reuse): dead
    _plant_intent(base / ".G.fork-reuse.tmp", id="reuse", name="G", **reused)
    # 6. a fork committed (.gpr in place) whose sidecar still says publishing: finished
    (base / "E.rep").mkdir()
    (base / "E.gpr").write_text("<gpr/>")
    (base / "E.fork.json").write_text(json.dumps({"format": 1, "state": "publishing",
                                                  "forkId": "dead6"}))
    _plant_intent(base / ".E.fork-dead6.tmp", id="dead6", name="E", phase="moving",
                  repCreatedMs=1, **dead)
    # 7. temporary files: old ones go, new ones and other files stay
    old = time.time() - 20 * 60
    for n in ("tmp123.tmp", "tmp456.ps", ".ghidra.test.lock~~", "keep-me.txt", "tmpx.dat"):
        (base / n).write_text("x")
        os.utime(base / n, (old, old))
    (base / "tmp789.tmp").write_text("fresh")
    # 8. a staging-named folder without an intent: only old ones go
    (base / ".H.fork-noint.tmp").mkdir()
    (base / ".H.fork-noint.tmp" / "f").write_bytes(b"x")
    (base / ".I.fork-noint.tmp").mkdir()
    os.utime(base / ".I.fork-noint.tmp", (old, old))
    # ... or whose name carries the process id of a dead publisher (killed before its intent)
    (base / f".J.fork-{done.pid:x}-1.tmp").mkdir()
    (base / f".J.fork-{done.pid:x}-1.tmp" / "f").write_bytes(b"x")
    before_live = tree(base / ".B.fork-live1.tmp"), tree(base / "B.rep")

    d = c.daemon("e2a-sweep")
    with d.connect("e2a-sweep", "tests") as s:
        # the first fork under the directory sweeps it; B is a live publisher's: refused, untouched
        e = expect_error("conflict", s.call, "fork_project", project=str(src), path=str(base),
                         name="B", mode="full", wait=30000)
        check(e.details and e.details.get("reason") == "fork_in_progress",
              f"a live publisher's destination answered {e.details}")
        left = sorted(os.listdir(base))
        gone = [".A.fork-dead1.tmp", ".C.fork-dead3.tmp", "C.rep", ".D.fork-dead4.tmp",
                ".G.fork-reuse.tmp", ".E.fork-dead6.tmp", "tmp123.tmp", "tmp456.ps",
                ".ghidra.test.lock~~", ".I.fork-noint.tmp", f".J.fork-{done.pid:x}-1.tmp"]
        stay = [".B.fork-live1.tmp", "B.rep", "D.rep", "E.rep", "E.gpr", "E.fork.json",
                "keep-me.txt", "tmpx.dat", "tmp789.tmp", ".H.fork-noint.tmp"]
        check(not [g for g in gone if g in left], f"not swept: {[g for g in gone if g in left]}")
        check(not [x for x in stay if x not in left], f"swept: {[x for x in stay if x not in left]}")
        check((tree(base / ".B.fork-live1.tmp"), tree(base / "B.rep")) == before_live,
              "the live publisher's staging folder or .rep was touched")
        sc = json.loads((base / "E.fork.json").read_text())
        check(sc["state"] == "complete", f"the publishing sidecar was not finished: {sc}")
        # the retries of the swept names succeed
        for n in ("A", "C", "G"):
            r = s.call("fork_project", project=str(src), path=str(base), name=n, mode="full",
                       wait=60000)
            check(r["name"] == n, f"fork {n}: {r}")
            check_fork_matches_source(src, base / f"{n}.gpr")
        # D has a foreign .rep: the ordinary conflict, and it was not removed
        e = expect_error("conflict", s.call, "fork_project", project=str(src), path=str(base),
                         name="D", mode="full", wait=30000)
        check((base / "D.rep" / "f").read_bytes() == b"foreign", "a foreign .rep was removed")
        check(not [x for x in os.listdir(base) if STAGING.match(x) and "live1" not in x
                   and "noint" not in x], "a staging folder is left after the forks")
    d.stop()
    return "dead owners swept, live owner and foreign folders untouched, publishing sidecar finished"


def t_e2a_self_leftover(c):
    """A staging folder that THIS daemon left behind (its delete failed, e.g. against a handle
    holder) carries the daemon's own pid and start time in its intent. It is nobody's work in
    progress: a retry of the name must not be answered ``fork_in_progress`` for as long as the
    daemon runs, and the sweeper must remove it (review of E2a, blocking defect 1)."""
    if os.name != "nt":
        return "skipped: the daemon's start time needs the Windows helper"
    src = make_source(c, "self")
    base = c.work / "e2a-self"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    d = c.daemon("e2a-self")
    with d.connect("e2a-self", "tests") as s:
        pid = int(d.read_endpoint()["pid"])
        mine = dict(pid=pid, procStartMs=proc_start_ms(pid))
        check(mine["procStartMs"] > 0, "cannot read the start time of the daemon")
        # K: only a staging folder (a fork that failed or finished, its delete failed)
        _plant_intent(base / ".K.fork-self1.tmp", id="self1", name="K", **mine)
        # L: the same after the .rep move, with the half fork the intent made
        (base / "L.rep").mkdir()
        (base / "L.rep" / "f").write_bytes(b"half fork")
        born = int(os.stat(base / "L.rep").st_birthtime_ns // 1_000_000)
        _plant_intent(base / ".L.fork-self2.tmp", id="self2", name="L", phase="moving",
                      repCreatedMs=born, **mine)
        # M: planted after the daemon swept this directory (the sweep of the first fork is past):
        # only the retry's own admission and per-name sweep can see it
        r = s.call("fork_project", project=str(src), path=str(base), name="First", mode="full",
                   wait=60000)
        check(r["name"] == "First", f"first fork: {r}")
        _plant_intent(base / ".M.fork-self3.tmp", id="self3", name="M", **mine)
        # P: the daemon's own folder after a delete that failed part way (SP6): its intent is
        # gone and only the process id in the name says whose it was
        ghost = base / f".P.fork-{pid:x}-1abc.tmp"
        ghost.mkdir()
        (ghost / "payload.bin").write_bytes(b"x" * 1000)
        for n in ("K", "L", "M", "P"):
            try:
                r = s.call("fork_project", project=str(src), path=str(base), name=n, mode="full",
                           wait=60000)
            except Exception as e:  # noqa: BLE001
                raise Fail(f"retry of {n} after the daemon's own leftover: {e}") from e
            check(r["name"] == n, f"fork {n}: {r}")
            check_fork_matches_source(src, base / f"{n}.gpr")
        left = [x for x in os.listdir(base) if STAGING.match(x)]
        check(not left, f"a staging folder of the daemon's own is left: {left}")
    d.stop()
    return "a leftover of the daemon's own pid never blocks a retry and is swept"


# ---- SP6: a handle holder on the staged files during the publish moves ------------------------

class Holder:
    """A handle without ``FILE_SHARE_DELETE`` (what an indexer or a scanner may hold): reads and
    writes of the file are still allowed to others, a rename or a delete of it, or of a folder above
    it for a directory, is not."""

    def __init__(self, path, is_dir):
        import ctypes
        from ctypes import wintypes
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.CreateFileW.restype = wintypes.HANDLE
        self.k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.HANDLE]
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        access = 0x1 if is_dir else 0x80000000   # FILE_LIST_DIRECTORY / GENERIC_READ
        # share read and write, not delete; FILE_FLAG_BACKUP_SEMANTICS opens a folder
        h = self.k.CreateFileW(str(path), access, 0x3, None, 3, 0x02000000, None)
        self.ok = h is not None and h != wintypes.HANDLE(-1).value and h != 2 ** 64 - 1 \
            and h != 0xFFFFFFFF
        self.h = h
        self.err = ctypes.get_last_error()

    def close(self):
        if self.ok:
            self.k.CloseHandle(self.h)
            self.ok = False


#: (case, what is held, seconds held): the brief holds are shorter than the engine's retry budget
#: (6 attempts, 25 ms doubling: about 1.6 s), the long ones longer than it
SP6_CASES = [("rep_dir_brief", "rep_dir", 0.4), ("rep_dir_long", "rep_dir", 5.0),
             ("rep_file_brief", "rep_file", 0.4), ("rep_file_long", "rep_file", 5.0),
             ("gpr_file_brief", "gpr_file", 0.4), ("gpr_file_long", "gpr_file", 5.0),
             ("staging_dir_long", "staging_dir", 5.0),
             ("sidecar_brief", "sidecar", 0.4), ("sidecar_long", "sidecar", 5.0)]


def _sp6_holder(pdir, what, hold_s, rec, stop):
    """Waits for the staging folder, takes the handle as soon as the thing to hold exists, holds it
    ``hold_s`` seconds, releases it, and records the times (perf_counter seconds)."""
    t_end = time.perf_counter() + 60
    stg = None
    while not stop.is_set() and time.perf_counter() < t_end:
        try:
            stg = next((e for e in os.listdir(pdir) if STAGING.match(e)), None)
        except OSError:
            stg = None
        if stg:
            break
    if not stg:
        rec["error"] = "no staging folder seen"
        return
    base = pdir / stg
    target, is_dir = {"sidecar": (pdir / "H.fork.json", False),"rep_dir": (base / "Src.rep", True),
                      "rep_file": (base / "Src.rep" / "ballast" / "b0.bin", False),
                      "gpr_file": (base / "Src.gpr", False),
                      "staging_dir": (base, True)}[what]
    h = None
    while not stop.is_set() and time.perf_counter() < t_end:
        if target.exists():
            h = Holder(target, is_dir)
            if h.ok:
                break
            h = None
    if h is None:
        rec["error"] = f"could not take a handle on {target}"
        return
    rec["t_open"] = time.perf_counter()
    time.sleep(hold_s)
    h.close()
    rec["t_release"] = time.perf_counter()


#: how often a case is run again when its holder arrived too late to hold anything up
SP6_ATTEMPTS = 5


def _sp6_engaged(pdir, name, what, rec, outcome, t1):
    """Whether the holder held up the fork: it had its handle before the fork answered, and the
    fork either failed or answered no earlier than the release. For the sidecar the fork is
    committed while it is held and answers ok either way: the hold shows as a late answer (brief)
    or as a sidecar still saying "publishing"."""
    if "t_open" not in rec or "t_release" not in rec:
        return False
    if what == "sidecar":
        return t1 >= rec["t_release"] - 0.05 or classify(pdir, name)[2] == "publishing"
    return rec["t_open"] < t1 and (outcome == "error" or t1 >= rec["t_release"] - 0.05)


def _sp6_observer(pdir, name, seen, stop):
    """Every state of the destination, sampled as fast as the file system answers."""
    while not stop.is_set():
        try:
            st = classify(pdir, name, read_sidecar=False)[0]
        except OSError:
            continue
        seen[st] = seen.get(st, 0) + 1
        time.sleep(0.002)   # a scanner or indexer, not a spin loop


def _volume_fs(path):
    """The file system name of the volume of ``path`` ("NTFS", "ReFS"), or "" when unknown."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            pathlib.Path(path).drive + "\\", None, 0, None, None, None, buf, 64)
        return buf.value if ok else ""
    except Exception:  # noqa: BLE001
        return ""


def t_e2a_handle_holder(c):
    """SP6 (PROTOCOL-3.md 9.20): the fork publish against a handle holder, on the file system of
    ``--work`` (run it once on NTFS and once on ReFS). For each case a holder without delete sharing
    sits on the staged ``.rep`` (the folder itself, and a file inside it), on the staged ``.gpr``, or
    on the staging folder, from the moment it exists. A hold shorter than the retry budget must end in
    a complete fork after the retries; a longer one in an error with nothing published (no ``.gpr``,
    no ``.rep``, no sidecar) and a retry that succeeds once the holder is gone, with no staging
    folder or leftover after it. Throughout, no state with a ``.gpr`` but without its ``.rep`` or
    sidecar is ever seen. ``E2A_SP6_REPORT`` names a file the per-case table is written to."""
    if os.name != "nt":
        return "skipped: the handle holder is a Windows handle without FILE_SHARE_DELETE"
    src = make_source(c, "sp6")
    before_tree = tree(src.parent)
    base = c.work / "e2a-sp6"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    fs = _volume_fs(base)
    d = c.daemon("e2a-sp6")
    rows, problems = [], []
    with d.connect("e2a-sp6", "tests") as s:
        for case, what, hold_s in SP6_CASES:
            name = "H"
            # The holder is a polling thread of this process that has to catch a window of a few
            # milliseconds (the sidecar between "publishing" and the final rewrite), so on a loaded
            # machine it can arrive after the engine is done and hold a settled file: that attempt
            # exercised nothing. It is run again in a fresh folder, as long as the observed state
            # says the holder did not hold anything up (``_sp6_engaged``), at most SP6_ATTEMPTS
            # times. The assertions below are the same for every attempt; the last one is judged.
            for attempt in range(1, SP6_ATTEMPTS + 1):
                pdir = base / (case if attempt == 1 else f"{case}-try{attempt}")
                rec, seen, stop = {}, {}, threading.Event()
                th = threading.Thread(target=_sp6_holder, args=(pdir, what, hold_s, rec, stop))
                ob = threading.Thread(target=_sp6_observer, args=(pdir, name, seen, stop))
                pdir.mkdir()
                th.start()
                ob.start()
                t0 = time.perf_counter()
                outcome, err = "ok", ""
                try:
                    s.call("fork_project", project=str(src), path=str(pdir), name=name,
                           mode="full", wait=60000)
                except Exception as e:  # noqa: BLE001
                    outcome, err = "error", f"{getattr(e, 'code', type(e).__name__)}: {e}"[:200]
                t1 = time.perf_counter()
                th.join(30)
                stop.set()
                ob.join(5)
                # (a hold on the staging folder itself only delays its delete: nothing to engage)
                if ("error" in rec or what == "staging_dir" or
                        _sp6_engaged(pdir, name, what, rec, outcome, t1)):
                    break
            row = {"case": case, "attempts": attempt, "held": what, "hold_s": hold_s, "fs": fs,
                   "outcome": outcome, "error": err, "fork_s": round(t1 - t0, 3),
                   "holder_open_after_s": round(rec["t_open"] - t0, 3) if "t_open" in rec else None,
                   "released_after_s": round(rec["t_release"] - t0, 3) if "t_release" in rec else None,
                   "states_seen": seen}
            rows.append(row)
            if "error" in rec:
                problems.append(f"{case}: holder: {rec['error']}")
                continue
            blocked = _sp6_engaged(pdir, name, what, rec, outcome, t1)
            row["blocked_the_move"] = blocked
            row["fork_ended_before_release"] = t1 < rec["t_release"]
            # a sidecar alone (no .gpr) is the rollback in progress: the fork does not exist yet
            bad_states = [k for k in seen if k in ("gpr_no_rep", "gpr_no_sidecar")]
            if bad_states:
                problems.append(f"{case}: half-published states seen: {bad_states}")
            after = classify(pdir, name)
            row["after_fork_call"] = {"state": after[0], "staging": after[1],
                                      "sidecar_state": after[2]}
            long_hold = hold_s > 2
            if what == "sidecar":
                if outcome != "ok" or after[0] != "complete":
                    problems.append(f"{case}: expected a committed fork, got {outcome}/{after[0]}")
                if not long_hold and after[2] != "complete":
                    problems.append(f"{case}: a {hold_s}s hold on the sidecar was not survived: "
                                    f"{after[2]}")
                if not blocked:
                    problems.append(f"{case}: the holder did not hold up the sidecar rewrite")
                if long_hold and after[2] == "publishing" and not after[1]:
                    problems.append(f"{case}: sidecar unfinished and its staging folder (the "
                                    f"intent that lets the sweep finish it) is gone")
            elif what == "staging_dir":
                # moves out of a held folder are allowed; only its delete is held up
                if outcome != "ok" or after[0] != "complete":
                    problems.append(f"{case}: expected a complete fork, got {outcome}/{after[0]}")
            elif long_hold:
                if outcome != "error":
                    problems.append(f"{case}: the fork succeeded against a {hold_s}s hold "
                                    f"(blocked={blocked}); expected the retries to give up")
                if after[0] != "absent":
                    problems.append(f"{case}: a failed fork left {after[0]} at the destination")
            else:
                if outcome != "ok" or after[0] != "complete":
                    problems.append(f"{case}: a {hold_s}s hold was not survived: {outcome} "
                                    f"{err} / {after[0]}")
                if not blocked:
                    problems.append(f"{case}: the holder did not block the move, so the retry "
                                    f"was not exercised (fork {t1 - t0:.2f}s, released at "
                                    f"{rec['t_release'] - t0:.2f}s)")
            # the holder is gone: a retry completes the fork and leaves nothing behind
            if long_hold or what == "staging_dir":
                time.sleep(0.05)
                try:
                    if what == "sidecar":
                        # the fork exists: a repeat is the ordinary conflict, and its sweep
                        # finishes the sidecar that the holder kept at "publishing"
                        try:
                            s.call("fork_project", project=str(src), path=str(pdir), name=name,
                                   mode="full", wait=60000)
                            row["retry"] = "ok (unexpected: the fork exists)"
                            problems.append(f"{case}: a repeat over a complete fork succeeded")
                        except Exception as e:  # noqa: BLE001
                            row["retry"] = f"{getattr(e, 'code', type(e).__name__)} (the fork exists)"
                            if getattr(e, "code", "") != "conflict":
                                problems.append(f"{case}: the repeat answered {row['retry']}")
                    elif after[0] == "complete":
                        # staging_dir: the next fork (another name) sweeps the folder that was held
                        s.call("fork_project", project=str(src), path=str(pdir), name="H2",
                               mode="full", wait=60000)
                        row["retry"] = "ok (another name: the sweep removes the held folder)"
                    else:
                        s.call("fork_project", project=str(src), path=str(pdir), name=name,
                               mode="full", wait=60000)
                        row["retry"] = "ok"
                except Exception as e:  # noqa: BLE001
                    row["retry"] = f"{getattr(e, 'code', type(e).__name__)}: {e}"[:200]
                    problems.append(f"{case}: the retry after the release failed: {row['retry']}")
            fin = classify(pdir, name)
            row["final"] = {"state": fin[0], "staging": fin[1], "sidecar_state": fin[2],
                            "leftovers": leftovers(pdir)}
            if fin[0] != "complete" or fin[2] != "complete":
                problems.append(f"{case}: final state {fin[0]}/{fin[2]}")
            else:
                try:
                    check_fork_matches_source(src, pdir / f"{name}.gpr")
                    row["matches_source"] = True
                except Fail as e:
                    problems.append(f"{case}: {e}")
            if fin[1] or row["final"]["leftovers"]:
                problems.append(f"{case}: left after the retry: {fin[1]} {row['final']['leftovers']}")
    d.stop()
    rp = os.environ.get("E2A_SP6_REPORT")
    if rp:
        pathlib.Path(rp).write_text(json.dumps(rows, indent=1))
    c.timings["e2a_handle_holder"] = rows
    check(tree(src.parent) == before_tree, "the source project was written (K1)")
    check(not problems, " | ".join(problems) + " :: " + json.dumps(rows)[:1500])
    return f"{fs or '?'}: " + "; ".join(
        f"{r['case']}={r['outcome']} {r['fork_s']}s" for r in rows)


def _sp6_late_holder(pdir, delay_s, hold_s, rec, stop):
    """Takes a handle on the sidecar ``H.fork.json`` ``delay_s`` seconds after it first exists and
    holds it ``hold_s`` seconds (perf_counter times in ``rec``)."""
    target = pathlib.Path(pdir) / "H.fork.json"
    t_end = time.perf_counter() + 60
    while not stop.is_set() and time.perf_counter() < t_end and not target.exists():
        time.sleep(0.0005)
    if not target.exists():
        rec["error"] = "the sidecar never appeared"
        return
    rec["t_seen"] = time.perf_counter()
    time.sleep(delay_s)
    h = Holder(target, False)
    if not h.ok:
        rec["error"] = f"could not take a handle on {target} (error {h.err})"
        return
    rec["t_open"] = time.perf_counter()
    time.sleep(hold_s)
    h.close()
    rec["t_release"] = time.perf_counter()


#: how often the rollback case is run again when its sidecar holder did not hold the rollback up
ROLLBACK_ATTEMPTS = 3


def t_e2a_rollback_holder(c):
    """F1: the rollback of a failed publish against a handle holder on the sidecar. The staged
    ``.gpr`` is held for 6 s, so the move of the ``.gpr`` gives up after its retries (about 1.6 s
    after the sidecar was written) and the publish rolls back: the ``.rep`` and the sidecar it
    already put at the destination are removed. A second holder takes the sidecar 1.0 s after it
    appears and keeps it 1.2 s, which covers the first removal of the sidecar and ends inside the
    removal's own retries. The rollback must wait it out and end with nothing at the destination
    (a single attempt left ``H.fork.json`` alone, which then blocked the name: ``sidecar_only``); the
    fork call answers the error after that, so no earlier than the sidecar holder's release. A
    holder that arrived after the fork had answered is run again (the same rule as
    ``e2a_handle_holder``)."""
    if os.name != "nt":
        return "skipped: the handle holder is a Windows handle without FILE_SHARE_DELETE"
    src = make_source(c, "sp6rb")
    before_tree = tree(src.parent)
    base = c.work / "e2a-rollback"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    d = c.daemon("e2a-rollback")
    with d.connect("e2a-rollback", "tests") as s:
        for attempt in range(1, ROLLBACK_ATTEMPTS + 1):
            pdir = base / f"try{attempt}"
            pdir.mkdir()
            gpr_rec, sc_rec, stop = {}, {}, threading.Event()
            th_gpr = threading.Thread(target=_sp6_holder, args=(pdir, "gpr_file", 6.0, gpr_rec, stop))
            th_sc = threading.Thread(target=_sp6_late_holder, args=(pdir, 1.0, 1.2, sc_rec, stop))
            th_gpr.start()
            th_sc.start()
            outcome, err = "ok", ""
            try:
                s.call("fork_project", project=str(src), path=str(pdir), name="H", mode="full",
                       wait=60000)
            except Exception as e:  # noqa: BLE001
                outcome, err = "error", f"{getattr(e, 'code', type(e).__name__)}: {e}"[:200]
            t1 = time.perf_counter()
            th_sc.join(30)
            th_gpr.join(30)
            stop.set()
            check("error" not in gpr_rec and "error" not in sc_rec,
                  f"holders: {gpr_rec} {sc_rec}")
            # engaged: the holder had the sidecar before the fork answered (an engine that gives
            # up on the first refused delete answers while it is still held: that is the failure
            # to find, not a reason to run again)
            if sc_rec["t_open"] < t1:
                break
        after = classify(pdir, "H")
        check(sc_rec["t_open"] < t1, f"the sidecar holder arrived after the fork answered in "
                                     f"{attempt} attempts (opened {sc_rec['t_open'] - t1:+.2f} s)")
        check(outcome == "error", f"the fork succeeded against a 6 s hold on its .gpr: {err}")
        check(t1 >= sc_rec["t_release"] - 0.05,
              f"the fork answered {sc_rec['t_release'] - t1:.2f} s before the sidecar holder "
              f"released: the rollback gave up on a held sidecar ({err}); destination {after[0]}")
        check(after[0] == "absent",
              f"a rolled-back publish left {after[0]} at the destination ({err})")
        time.sleep(max(0.0, gpr_rec["t_release"] - time.perf_counter()) + 0.05)
        s.call("fork_project", project=str(src), path=str(pdir), name="H", mode="full", wait=60000)
        fin = classify(pdir, "H")
        check(fin[0] == "complete" and fin[2] == "complete" and not fin[1] and
              not leftovers(pdir), f"the retry after the release: {fin} {leftovers(pdir)}")
    d.stop()
    check(tree(src.parent) == before_tree, "the source project was written (K1)")
    return (f"rollback held up until the sidecar was released ({attempt} attempt(s)): nothing "
            f"left, and the retry completes")


TESTS = {"e2a_kill_fork": t_e2a_kill_fork, "e2a_client_kill": t_e2a_client_kill,
         "e2a_sweeper": t_e2a_sweeper, "e2a_self_leftover": t_e2a_self_leftover,
         "e2a_handle_holder": t_e2a_handle_holder,
         "e2a_rollback_holder": t_e2a_rollback_holder}
