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
"""The non-blocking core (PROTOCOL-3.md 3.5, 3.9, 3.10, D49, D57, D63, package E3c).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only reader_leave_no_freeze,...

* ``reader_leave_no_freeze`` (D63b, all protocols): the three scenarios of 3.5 as assertions. A long
  read runs on a program; a joined client leaves by a clean ``close_program``, by a FIN, or by the end
  of an abandoned request; during the read the next ``open_program`` (a join) of another client and the
  next ``script`` of an already joined client are answered within their ``wait``. RED on hydra.3.
* ``last_user_leave_disposes``: N concurrent leavers (the last user included): nobody is registered
  afterwards, the program is disposed (``keepWarm`` 0) or kept warm as before, a last user whose
  request still holds the program is disposed when that request ends, and the next join works.
* ``deferred_leave_closes_project``: the last user of a writable project dies under its own deaf
  request (``keepWarm`` 600 s). As the program's owner its leave is left pending and
  ``Session.completeLeaves`` closes the project when the request ends; as a plain reader it leaves at
  once and the reap closes the project once the request has ended (``ProjectEntry.closePending``),
  not after ``keepWarm``. A writable reopen then works.
* ``reader_leave_all`` (protocol 2 and 3): every reader leaves at once, some by ``close_program``,
  some by closing the socket, while one read runs: no leave waits for it, the read is unharmed.
* ``refcount_leak``: users return to zero after 200 cancels raced against release, 40 of them by a
  cut connection (10 with a refresh racing it); the current view's reference count returns to 1 + its
  programs, no deferred work (reopen, disposal, leave) stays pending, no stray interrupt, the daemon
  log has no ``ClosedByInterruptException``.
* ``lock_matrix_rows``: every row of the lock map (``lock_matrix.json`` next to this file, 19 rows, the
  count 3.10 states) is mapped to blocking points whose row in 3.10 has a decision and a package; a
  missing file, a row the test does not know, or another count in 3.10 fails.
* ``analyzing_join`` (BP5): while ``analyze`` runs, a protocol 3 join, read and script of another
  client are answered at once with ``busy{reason:"analyzing"}`` and the job's progress; a protocol 2
  client waits as before.
* ``refresh_no_blackout`` (BP7): a ``refresh`` and a writable ``open_project`` of a read-only view
  while a long read runs refuse no other request of the project (the same program, another program,
  ``list``), and the program is reopened from the new view when the read ends.
* ``registry_state_machine`` (BP8, D57): concurrent first opens of one project are single-flight, a
  failed open leaves no slot, join and leave churn ends with the right states, and an open of an
  unrelated project is not held up by a close of another.
* ``foreign_blocked_counter`` (D49, K13): ``status.waits.foreignBlocked`` is 0 over reads, joins,
  leaves and a refresh of a read-only view, and is not 0 when a reader waits behind an owner's script
  (the counter can fail).
* ``project_waiter_caps`` (D39, BP4/BP9): the cap on the lock queues. In the engine's own ``-selfTest`` the
  plain locks E3c added waits on (the project's slot transition and structure change) answer the
  third protocol 3 waiter ``QUEUE_FULL`` at once and never cap protocol 2; in a daemon, a program
  held by a long exclusive request answers the third waiter ``busy{lock_queue_full}`` at once, the
  two that queued are served, and a protocol 2 waiter is not capped.
* ``yield_slots_stress`` (SP9): with ``yieldSlots`` on, a lock queue does not hold the lane and
  nothing deadlocks. The setting stays off by default; this is the evidence it needs.
* ``close_vs_view_change``: in the engine's ``-selfTest``, a close of an idle project cannot run while a
  refresh or writable reopen of it holds its structure lock (the forced interleaving of review finding 1).
* ``abandoned_open_writable``: a client cut off inside its writable ``open_program`` leaves no dead
  owner: another client opens the program writable at once (review finding 2).
"""
import contextlib
import json
import pathlib
import random
import shutil
import threading
import time

import daemon_tests as dt

try:
    import dt_baseline as bl
except ImportError:  # loaded by path (daemon_tests.load_dt) before dt_baseline was registered
    import importlib.util
    import sys
    _p = pathlib.Path(__file__).resolve().parent / "dt_baseline.py"
    _spec = importlib.util.spec_from_file_location("dt_baseline", _p)
    bl = importlib.util.module_from_spec(_spec)
    sys.modules["dt_baseline"] = bl
    _spec.loader.exec_module(bl)

HERE = pathlib.Path(__file__).resolve().parent

DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E3cDeaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // a script that does not look at cancel and swallows the interrupt
            }
        }
    }
}
"""


# ---- helpers --------------------------------------------------------------------------------

def prepare(c):
    exe = bl.prepare(c)
    (c.scripts / "E3cDeaf.java").write_text(DEAF)
    return exe


def warm(c, s, *names):
    """Runs each script once on no program, so that a later run needs no compile."""
    for n in names or ("TestSleep.java",):
        s.call("script", script=c.script(n), program=None, args=["10"], wait=120000)


def reader(c, d, gpr, exe, name, protocol=3, open_program=True):
    s = c.connect(d, name, "e3c", protocol)
    s.call("open_project", path=str(gpr))
    if open_program:
        s.call("open_program", path=exe)
    return s


def me(s):
    return s.call("status")["you"]


def program(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return pg
    return None


def users(s, exe):
    pg = program(s, exe)
    return None if pg is None else sorted(pg["users"])


def holds(s, exe, project=None):
    """True while a request holds the program exclusively (``busy``); ``project`` picks one of
    several projects that all contain ``exe``."""
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe and (project is None or pg["project"] == project):
            return bool(pg["busy"])
    return False


def running(s, name):
    """True while the client called ``name`` has a request running (a shared read holds no ``busy``)."""
    return any(cl["name"] == name and cl["requests"] for cl in s.call("status")["clients"])


def sleeper(c, s, ms, name="TestSleep.java", **extra):
    """A script on the active program (a contained script shares the program lock) for ``ms``."""
    return s.send("script", script=c.script(name), args=[str(ms)], parallel=True,
                  wait=ms + 120000, **extra)


def attempt(c, s, rid):
    try:
        return "ok", {}, s.wait(rid)
    except c.gs.SessionError as e:
        return e.code, e.details or {}, None


def finish(s, *ids):
    with contextlib.suppress(Exception):
        s.call("cancel", all=True)
    for i in ids:
        with contextlib.suppress(Exception):
            s.wait(i)


def close_all(*sessions):
    for s in sessions:
        if s is not None:
            with contextlib.suppress(Exception):
                s.close()


def log_text(d):
    try:
        return d.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def copy_project(src_gpr, dst):
    """A copy of a project folder (the original is never opened); returns the new .gpr."""
    src = pathlib.Path(src_gpr)
    dst = pathlib.Path(dst)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src.parent, dst)
    return dst / src.name


def waits(s):
    return s.call("status")["waits"]


def foreign_total(s):
    """waits.foreignBlocked.total of the daemon, or None on an engine that does not report it."""
    try:
        return s.call("status")["waits"]["foreignBlocked"]["total"]
    except (KeyError, TypeError):
        return None


# ---- reader_leave_no_freeze -----------------------------------------------------------------

def _leave_scenario(c, protocol, how):
    exe = prepare(c)
    gpr = c.copy_fixture(f"e3cLn{protocol}{how}")
    # the abandoned request is deaf and ends on its own after 3 s: the leave comes when it ends
    d = c.daemon(f"e3c-ln{protocol}{how}", engine={"cleanupGraceS": 8, "abandonWaitS": 4})
    A = B = J = D = M = None
    read_ms = 8000
    try:
        A = reader(c, d, gpr, exe, "A", protocol)
        B = reader(c, d, gpr, exe, "B", protocol)
        J = reader(c, d, gpr, exe, "J", protocol)
        D = reader(c, d, gpr, exe, "D", protocol, open_program=False)
        M = reader(c, d, gpr, exe, "M", 3, open_program=False)   # reads the daemon's wait counters
        warm(c, A, "TestSleep.java", "E3cDeaf.java")
        warm(c, B, "E3cDeaf.java")
        J.call("script", script=c.script("BaselineQuick.java"), wait=60000)
        hold = sleeper(c, A, read_ms)
        dt.wait_for(lambda: running(J, "A"), "A's long read to run", 30)
        f0 = foreign_total(M)
        t0 = time.perf_counter()
        time.sleep(0.5)
        left = {}
        threads = []
        if how == "close":
            def leave():
                left["r"] = bl.timed(c, B, "close_program")        # the default wait: 10 s
            th = threading.Thread(target=leave, daemon=True)
            th.start()
            threads.append(th)
        elif how == "fin":
            B.close()
        else:
            B.send("script", script=c.script("E3cDeaf.java"), args=["3000"], wait=60000)
            time.sleep(0.3)
            B.close()
        probes = []
        stop_at = t0 + read_ms / 1000.0 - 1.0
        while time.perf_counter() < stop_at:
            probes.append(("J script", bl.timed(c, J, "script", script=c.script("BaselineQuick.java"),
                                                wait=1500)))
            probes.append(("D open_program", bl.timed(c, D, "open_program", path=exe, wait=1500)))
            time.sleep(0.25)
        for th in threads:
            th.join(15)
        # A probe is bad when it was refused, or when it was an open_program that took a lock wait's
        # time. A script probe that was answered ok but ran long is the script's own run time (the
        # unleaving control shows the same, from the unfixed base too); what a lock stall would show
        # is a refusal (every wait is capped at 1500 ms) and the daemon's counter of waits that queued
        # behind another client's request (D49), which must not move.
        bad = [(n, p.get("code", "ok"), p["ms"], p.get("message", "")[:80]) for n, p in probes
               if not p["ok"] or (n != "J script" and p["ms"] >= 1500)]
        dt.check(not bad, f"protocol {protocol}, leave by {how}: {len(bad)} of {len(probes)} "
                          f"probes were refused or slow while the read ran (D63b): {bad[:4]}")
        f1 = foreign_total(M)
        dt.check(f1 == f0, f"protocol {protocol}, leave by {how}: waits.foreignBlocked moved from {f0} "
                           f"to {f1}: a probe queued behind another client's request")
        dt.check(len(probes) >= 10, f"only {len(probes)} probes ran")
        if how == "close":
            dt.check(left.get("r", {}).get("ok") and left["r"]["ms"] < 1500,
                     f"the clean close_program took {left.get('r')}")
        finish(A, hold)
        # the leaver is out of the users; the others stay
        want = sorted([me(A), me(J), me(D)])
        got = users(J, exe)
        dt.check(got == want, f"users after the leave: {got}, expected {want}")
        sn, sp = max(probes, key=lambda x: x[1]["ms"])
        return (f"protocol {protocol}, leave by {how}: {len(probes)} probes during an {read_ms // 1000} s "
                f"read, none refused (slowest {sp['ms']} ms: {sn})")
    finally:
        close_all(A, B, J, D, M)
        d.stop(force=True)


def t_reader_leave_no_freeze(c):
    out = []
    for protocol in (3, 2):
        for how in ("close", "fin", "abandoned"):
            out.append(_leave_scenario(c, protocol, how))
    return "; ".join(out)


# ---- last_user_leave_disposes ---------------------------------------------------------------

def t_last_user_leave_disposes(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3cLu")
    # keepWarm 0: a program whose last user left is closed at once, as before
    d = c.daemon("e3c-lu", keepWarm=0)
    obs = None
    notes = []
    try:
        obs = reader(c, d, gpr, exe, "obs", open_program=False)
        # (1) N concurrent leavers, the last user among them
        n = 8
        rs = [reader(c, d, gpr, exe, f"r{i}") for i in range(n)]
        dt.check(len(users(obs, exe)) == n, f"users before: {users(obs, exe)}")
        res = [None] * n

        def leave(i):
            res[i] = bl.timed(c, rs[i], "close_program")
        ths = [threading.Thread(target=leave, args=(i,), daemon=True) for i in range(n)]
        t = time.perf_counter()
        for th in ths:
            th.start()
        for th in ths:
            th.join(30)
        took = (time.perf_counter() - t) * 1000
        dt.check(all(r and r["ok"] for r in res), f"a leave failed: {[r for r in res if not r or not r['ok']]}")
        dt.wait_for(lambda: program(obs, exe) is None, "the program to be disposed after the last "
                    "leave (keepWarm 0)", 20, 0.2)
        notes.append(f"{n} concurrent leaves in {took:.0f} ms, program disposed")
        # (2) the next join opens it again and works
        j = reader(c, d, gpr, exe, "again")
        pg = program(obs, exe)
        dt.check(pg and users(obs, exe) == [me(j)], f"after the rejoin: {pg}")
        dt.check(bl.timed(c, j, "info", wait=3000)["ok"], "the rejoined program does not answer")
        # (3) the last user leaves while its own request holds the program: disposal waits for the end
        #     of that request and nobody waits for it
        hold = sleeper(c, j, 6000)
        dt.wait_for(lambda: running(obs, "again"), "the read to run", 20)
        j.close()                     # a FIN with the request running: cancelled, then released
        dt.wait_for(lambda: program(obs, exe) is None, "the program to be disposed once the request "
                    "of the last user ended", 30, 0.2)
        notes.append("a last user that left under a running request: disposed when it ended")
        # (4) a new client joins and reads
        k = reader(c, d, gpr, exe, "after")
        dt.check(bl.timed(c, k, "info", wait=3000)["ok"], "the program does not answer after that")
        close_all(k)
    finally:
        close_all(obs)
        d.stop(force=True)
    # (5) kept warm (the default keepWarm): users 0, the program stays open for the next client
    d = c.daemon("e3c-lu-warm", keepWarm=60)
    try:
        obs = reader(c, d, gpr, exe, "obs", open_program=False)
        rs = [reader(c, d, gpr, exe, f"w{i}") for i in range(4)]
        ths = [threading.Thread(target=lambda r=r: r.call("close_program"), daemon=True) for r in rs]
        for th in ths:
            th.start()
        for th in ths:
            th.join(20)
        pg = program(obs, exe)
        dt.check(pg is not None and pg["users"] == [], f"warm program after the leaves: {pg}")
        j = reader(c, d, gpr, exe, "warm-join")
        dt.check(program(obs, exe)["users"] == [me(j)], "the warm program was not rejoined")
        notes.append("kept warm when keepWarm is positive")
        close_all(j)
    finally:
        close_all(obs)
        d.stop(force=True)
    return "; ".join(notes)


# ---- deferred_leave_closes_project ----------------------------------------------------------

REAP_TICK_S = 15  # HeadlessSession: the reaper runs every min(15 s, max(1 s, keepWarm / 4))


def _deferred_close(c, how):
    """The last user of a writable project dies (FIN) while its own deaf request runs there.

    ``owner``: it owns the program writable, so its leave needs the program's exclusive lock, cannot
    have it within ``abandonWaitS`` and is left pending (``ProgramEntry.pendingLeaves``); when the
    request ends ``Session.completeLeaves`` finishes the leave and closes the project at once.
    ``reader``: a plain reader leaves at once (D63b), but the close of the project cannot have the
    project to itself while the request runs (``ProjectEntry.closePending``); the reap closes it once
    the request has ended. ``keepWarm`` is 600 s in both, so the keep-warm expiry is not what closes it.
    """
    exe = prepare(c)
    gpr = c.copy_fixture(f"e3cDl{how}")
    deaf_ms = 7000
    d = c.daemon(f"e3c-dl-{how}", keepWarm=600, engine={"cleanupGraceS": 1, "abandonWaitS": 1})
    obs = B = again = None
    try:
        obs = c.connect(d, "obs", "e3c", 3)          # joins no project: it does not keep one open
        B = c.connect(d, "B", "e3c", 3)
        pid = B.call("open_project", path=str(gpr), writable=True)["id"]
        if how == "owner":
            B.call("open_program", path=exe, writable=True)
        else:
            B.call("open_program", path=exe)
        warm(c, B, "E3cDeaf.java")

        def listed():
            return any(p["id"] == pid for p in obs.call("status")["projects"])
        dt.check(listed(), "the project is not listed after the open")
        B.send("script", script=c.script("E3cDeaf.java"), args=[str(deaf_ms)], parallel=True,
               wait=deaf_ms + 60000)
        dt.wait_for(lambda: running(obs, "B"), "B's deaf request to run", 30)
        t0 = time.perf_counter()
        B.close()                                    # a FIN while the deaf request runs
        B = None
        dt.wait_for(lambda: "(B, e3c) disconnected" in log_text(d), "B's release to end", 15, 0.1)
        released_s = time.perf_counter() - t0
        dt.check(released_s < deaf_ms / 1000.0 - 1.0,
                 f"{how}: B's release ended only after {released_s:.1f} s (abandonWaitS is 1 s)")
        log = log_text(d)
        if how == "owner":
            dt.check("is gone and could not leave" in log,
                     "owner: the leave was not left pending (the scenario did not exercise completeLeaves)")
        dt.check(listed(), f"{how}: the project closed while the deaf request still ran")
        bound = deaf_ms / 1000.0 + (5 if how == "owner" else REAP_TICK_S + 5)
        dt.wait_for(lambda: not listed(), f"{how}: the project to be closed once the deaf request ended",
                    bound + 10, 0.2)
        closed_s = time.perf_counter() - t0
        dt.check(closed_s >= deaf_ms / 1000.0 - 1.5,
                 f"{how}: the project closed after {closed_s:.1f} s, before the deaf request ended")
        dt.check(closed_s <= bound, f"{how}: the project closed {closed_s:.1f} s after the FIN (bound "
                                    f"{bound:.0f} s)")
        if how == "owner":
            dt.check("that was waiting for its lock is done" in log_text(d),
                     "owner: the log does not show the pending leave being finished")
        # the next client opens it writable again and reads
        again = c.connect(d, "again", "e3c", 3)
        r = bl.timed(c, again, "open_project", path=str(gpr), writable=True, wait=10000)
        dt.check(r["ok"], f"{how}: a writable open after the close: {r}")
        return (f"{how}: released in {released_s:.1f} s, project closed {closed_s:.1f} s after the FIN "
                f"(deaf request {deaf_ms // 1000} s, keepWarm 600 s)")
    finally:
        close_all(obs, B, again)
        d.stop(force=True)


def t_deferred_leave_closes_project(c):
    return "; ".join(_deferred_close(c, how) for how in ("owner", "reader"))


# ---- reader_leave_all -----------------------------------------------------------------------

def _leave_all(c, protocol):
    exe = prepare(c)
    gpr = c.copy_fixture(f"e3cLa{protocol}")
    d = c.daemon(f"e3c-la{protocol}")
    A = None
    rs = []
    try:
        A = reader(c, d, gpr, exe, "A", protocol)
        warm(c, A)
        rs = [reader(c, d, gpr, exe, f"r{i}", protocol) for i in range(6)]
        hold = sleeper(c, A, 7000)
        dt.wait_for(lambda: running(rs[0], "A"), "the read to run", 20)
        time.sleep(0.4)
        res = {}

        def leave(i, r):
            t = time.perf_counter()
            try:
                if i % 2 == 0:
                    r.call("close_program")
                else:
                    r.close()
                res[i] = (True, (time.perf_counter() - t) * 1000)
            except Exception as e:  # noqa: BLE001
                res[i] = (False, str(e))
        ths = [threading.Thread(target=leave, args=(i, r), daemon=True) for i, r in enumerate(rs)]
        t0 = time.perf_counter()
        for th in ths:
            th.start()
        for th in ths:
            th.join(20)
        leaves_ms = (time.perf_counter() - t0) * 1000
        dt.check(all(v[0] and v[1] < 1500 for v in res.values()) and len(res) == len(rs),
                 f"protocol {protocol}: leaves {res}")
        # a fresh client can join and read at once, while the read still runs
        late = reader(c, d, gpr, exe, "late", protocol)
        r = bl.timed(c, late, "info", wait=1500)
        dt.check(r["ok"] and r["ms"] < 1500, f"a read after the leaves: {r}")
        dt.check(users(late, exe) == sorted([me(A), me(late)]), f"users: {users(late, exe)}")
        code, det, _ = attempt(c, A, hold)
        dt.check(code == "ok", f"the read that ran during the leaves ended with {code} {det}")
        close_all(late)
        return (f"protocol {protocol}: {len(rs)} leaves (close_program and socket close) in "
                f"{leaves_ms:.0f} ms during a 7 s read; the read ended ok")
    finally:
        close_all(A, *rs)
        d.stop(force=True)


def t_reader_leave_all(c):
    return "; ".join(_leave_all(c, p) for p in (3, 2))


# ---- refcount_leak --------------------------------------------------------------------------

def t_refcount_leak(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3cRl")
    d = c.daemon("e3c-rl", keepWarm=60)
    obs = None
    rs = []
    keep = []
    try:
        obs = reader(c, d, gpr, exe, "obs", open_program=False)
        rs = [reader(c, d, gpr, exe, f"x{i}", 3, open_program=False) for i in range(4)]
        probe = reader(c, d, gpr, exe, "probe")
        keep.append(probe)
        fn = bl.first_function(probe)
        import chaos_lib as chaos
        pid = obs.call("project")["id"]
        rnd = random.Random(20261030)
        counts = {"ok": 0, "cancelled": 0, "other": {}, "cut": 0, "refresh": 0}
        names = [f"x{i}" for i in range(len(rs))]
        cut = set()
        for i in range(200):
            k = i % len(rs)
            x = rs[k]
            x.call("open_program", path=exe)
            rid = x.send("decompile", address=fn, wait=20000, parallel=True)
            order = rnd.random()
            if i % 5 == 4:
                # the disconnect path: the client is cut off (a reset) while its decompile runs or
                # ends, its leave runs in Session.disconnect, and a fresh client takes its place
                time.sleep(rnd.random() * 0.02)
                chaos.abort_connection(x)
                cut.add(names[k])
                names[k] = f"x{i}n"
                rs[k] = reader(c, d, gpr, exe, names[k], 3, open_program=False)
                counts["cut"] += 1
                if i % 20 == 19:
                    # and a refresh races the cut: the programs move to a new view, the old one is
                    # released by the last program and command that held it
                    obs.call("refresh", project=pid, force=True)
                    counts["refresh"] += 1
                continue
            if order < 0.5:
                x.call("cancel", target=rid)
                code, det, _ = attempt(c, x, rid)
                x.call("close_program")
            else:
                time.sleep(rnd.random() * 0.01)
                x.call("cancel", target=rid)
                with contextlib.suppress(c.gs.SessionError):
                    x.call("close_program")
                code, det, _ = attempt(c, x, rid)
            if code in ("ok", "cancelled"):
                counts[code] += 1
            else:
                counts["other"][code] = counts["other"].get(code, 0) + 1
        dt.check(not counts["other"], f"requests ended with {counts['other']}")
        # the probe session joined once; everybody else left 200 times, 40 of them by a cut
        for x in rs:
            with contextlib.suppress(c.gs.SessionError):
                x.call("close_program")
        dt.wait_for(lambda: not any(cl["name"] in cut for cl in obs.call("status")["clients"]),
                    "the cut clients to be released", 60)

        def settled():
            st = obs.call("status")
            pgs = [pg for pg in st["programs"] if pg["project"] == pid]
            slot = [x for x in st["projectStates"] if x["project"] == pid]
            return st, pgs, slot
        # deferred work (a pending reopen, disposal or leave) finishes at the next release or reap
        dt.wait_for(lambda: all(pg.get("reopenPendingMs") is None and not pg.get("disposePending") and
                                not pg.get("pendingLeaves") for pg in settled()[1]),
                    "the deferred work of the program to finish", 30)
        st, pgs, slot = settled()
        pg = program(obs, exe)
        dt.check(pg is not None, "the warm program is gone")
        ids = pg["users"]
        dt.check(len(ids) == 1, f"users did not return to zero (only the probe stays): {ids}")
        dt.check(not pg.get("abandonedRequests"), f"abandoned requests stay listed: {pg}")
        # the current view: 1 reference for being current and 1 per program opened from it; a pin
        # of a cancelled or cut command that was never released, or a program left on a retired
        # view, shows as a different count
        end = time.time() + 20   # a cut client's cancelled request may still be ending
        while time.time() < end and not (len(slot) == 1 and slot[0].get("viewRefs") == 1 + len(pgs)):
            time.sleep(0.5)
            st, pgs, slot = settled()
        dt.check(len(slot) == 1 and slot[0].get("viewRefs") == 1 + len(pgs),
                 f"view references did not return to 1 + {len(pgs)} program(s): {slot}")
        dt.check(bl.timed(c, obs, "status")["ok"], "status")
        # nothing is stuck: shared, exclusive acquirers and an interrupt-free channel
        j = reader(c, d, gpr, exe, "after")
        dt.check(bl.timed(c, j, "decompile", address=fn, wait=3000)["ok"], "decompile after the loop")
        log = log_text(d)
        dt.check("ClosedByInterruptException" not in log, "ClosedByInterruptException in the log")
        close_all(j)
        return (f"200 join/cancel/leave rounds: {counts['ok']} completed, {counts['cancelled']} "
                f"cancelled, {counts['cut']} cut off ({counts['refresh']} with a refresh); users back "
                f"to {len(ids)} (the probe), viewRefs {slot[0]['viewRefs']} = 1 + {len(pgs)} program(s), "
                f"no deferred work left, no stray interrupt")
    finally:
        close_all(obs, *rs, *keep)
        d.stop(force=True)


# ---- lock_matrix_rows -----------------------------------------------------------------------

#: the 19 rows of the lock map (``lock_matrix.json`` next to this file, a copy of measurement B's
#: ``lockmap/lock_matrix.json``) and the blocking points of 3.10 that decide each one
MATRIX = {
    "L1": ("Program read/write lock, fair", ["BP1", "BP4"]),
    "L2a": ("releaseUse: every leave takes the program exclusive", ["BP3"]),
    "L2b": ("edits: rename, comment, edit, discard_edits, save, analyze", ["BP4", "BP5", "BP18"]),
    "L2c": ("script as owner/writer, or exclusive:true", ["BP6"]),
    "L2d": ("contained script shares the READ lock but changes the live program", ["BP14"]),
    "L2e": ("open_program: first open and READ_ONLY->writable swap hold program X", ["BP6", "BP21"]),
    "L2f": ("closeEntry / reopenIn / reap", ["BP7"]),
    "L2g": ("promote_overlay, import+analyze", ["BP5"]),
    "L3": ("Project read/write lock, fair, held for the whole command", ["BP7"]),
    "L3x": ("project EXCLUSIVE acquirers", ["BP7"]),
    "L4": ("session REGISTRY monitor held while makeWritable waits for project X", ["BP8"]),
    "L5": ("Overlay lock (per client, per overlay), fair", ["BP24"]),
    "L6": ("Scheduler lane slots", ["BP9", "BP10"]),
    "L7": ("ImportGate (global, 4 permits)", ["BP16"]),
    "L8": ("Per-connection single worker (head-of-line)", ["BP15"]),
    "L9": ("cancel does not wake lock waits; a dead client's queued write still runs",
           ["BP11", "BP12", "BP23"]),
    "L10": ("non-cooperative script", ["BP13"]),
    "L11": ("Ghidra: program Lock and DBHandle monitor", ["BP2"]),
    "L12": ("minor / bounded", ["BP17"]),
}
MATRIX_FILE = HERE / "lock_matrix.json"


def _spec_rows():
    text = (HERE.parent / "PROTOCOL-3.md").read_text(encoding="utf-8")
    rows = {}
    for ln in text.splitlines():
        if ln.startswith("| BP") and ln.count("|") >= 7:
            cells = [x.strip() for x in ln.strip().strip("|").split("|")]
            rows[cells[0]] = cells
    return rows


def t_lock_matrix_rows(c):
    rows = _spec_rows()
    dt.check(len(rows) >= 25, f"section 3.10 has {len(rows)} blocking-point rows, expected BP1..BP25")
    missing = []
    for rid, (_, bps) in MATRIX.items():
        for bp in bps:
            r = rows.get(bp)
            if r is None:
                missing.append(f"{rid}->{bp}: no row in 3.10")
                continue
            # columns: #, blocking point, measured, decision, package, test
            if len(r) < 6 or not r[3] or not r[3].split()[0].isupper():
                missing.append(f"{rid}->{bp}: no decision ({r[3] if len(r) > 3 else '?'})")
            if len(r) >= 6 and bp not in ("BP1", "BP17") and not r[4]:
                missing.append(f"{rid}->{bp}: no package")
    dt.check(not missing, "rows of the lock map without a decision in 3.10: " + "; ".join(missing))
    # the matrix is part of the repository: a missing file fails, it is never skipped
    dt.check(MATRIX_FILE.is_file(), f"the lock map {MATRIX_FILE} is missing: the rows cannot be compared")
    ids = [r["id"] for r in json.loads(MATRIX_FILE.read_text(encoding="utf-8"))["rows"]]
    dt.check(len(ids) == len(set(ids)) and sorted(ids) == sorted(MATRIX),
             f"the lock map file has rows {ids}, this test knows {list(MATRIX)}")
    # and 3.10 states the count the file has
    text = (HERE.parent / "PROTOCOL-3.md").read_text(encoding="utf-8")
    dt.check(f"`lockmap/lock_matrix.json` has {len(ids)} rows" in text,
             f"PROTOCOL-3.md 3.10 does not say the matrix has {len(ids)} rows")
    return (f"{len(ids)} rows of {MATRIX_FILE.name} (as 3.10 states) map to "
            f"{len({b for _, v in MATRIX.values() for b in v})} decided blocking points")


# ---- analyzing_join -------------------------------------------------------------------------

def _analysis_project(c, name):
    """A copy of ``--project`` (an analysed project, large enough for a long analysis) when it is
    given, else the fixture: the analysis of the small fixture is short and the test says so."""
    if getattr(c.a, "project", None):
        gpr = copy_project(c.a.project, c.work / name)
        s = c.gs.Daemon  # noqa: F841
        return gpr, None
    return c.copy_fixture(name), pathlib.Path(c.a.exe).name


def t_analyzing_join(c):
    exe0 = prepare(c)
    gpr, exe = _analysis_project(c, "e3cAn")
    d = c.daemon("e3c-an")
    O = R2 = R3 = X = None
    try:
        O = c.connect(d, "owner", "e3c", 3)
        O.call("open_project", path=str(gpr), writable=True)
        if exe is None:
            exe = O.call("list", programsOnly=True)["entries"][0]["path"].lstrip("/")
        O.call("open_program", path=exe, writable=True)
        R3 = reader(c, d, gpr, exe, "r3", 3)
        R2 = reader(c, d, gpr, exe, "r2", 2, open_program=False)
        X = c.connect(d, "x3", "e3c", 3)
        X.call("open_project", path=str(gpr))
        aid = O.send("analyze", wait=600000, parallel=True)
        dt.wait_for(lambda: holds(O, exe), "the analysis to hold the program", 30, 0.02)
        took = []
        seen = None
        end = time.time() + 20
        while time.time() < end and holds(O, exe):
            for what, fn in (("join", lambda: X.call("open_program", path=exe, wait=5000)),
                             ("read", lambda: R3.call("info", wait=5000))):
                t = time.perf_counter()
                try:
                    fn()
                    ok = True
                    det = {}
                except c.gs.SessionError as e:
                    ok = False
                    det = e.details or {}
                    code = e.code
                ms = (time.perf_counter() - t) * 1000
                if ok:
                    # answered: either the analysis ended between the probes, or the request WAITED
                    # for it (hydra.3: a join waits for its wait, BP5)
                    dt.check(ms < 1000,
                             f"a {what} during the analysis waited {ms:.0f} ms behind it instead of "
                             f"answering analyzing at once (BP5)")
                    break
                dt.check(code == "busy" and det.get("reason") == "analyzing",
                         f"a {what} during the analysis answered {code} {det.get('reason')}")
                took.append(ms)
                seen = det
            time.sleep(0.15)
        attempt(c, O, aid)
        dt.check(seen is not None and len(took) >= 2,
                 f"the analysis was too short to probe ({len(took)} probes; use --project with a "
                 f"larger program): {took}")
        dt.check(max(took) < 1000, f"analyzing answers took {max(took):.0f} ms, not at once")
        job = seen.get("job") or {}
        dt.check(job.get("cmd") == "analyze" and "progress" in seen and "etaMs" in seen,
                 f"the analyzing details lack the job: {seen}")
        # protocol 2: waits like hydra.3 (no new reason)
        aid = O.send("analyze", wait=600000, parallel=True)
        dt.wait_for(lambda: holds(O, exe), "the second analysis to hold the program", 30, 0.02)
        r = bl.timed(c, R2, "open_program", path=exe, wait=700)
        attempt(c, O, aid)
        if not r["ok"]:
            dt.check(r["code"] == "busy" and "reason" not in (r["details"] or {}) and r["ms"] >= 600,
                     f"a protocol 2 join during an analysis: {r}")
            v2 = f"protocol 2 waited {r['ms']} ms and got busy without a reason"
        else:
            v2 = "protocol 2: the analysis ended before the probe"
        return (f"{len(took)} joins/reads of a protocol 3 client during the analysis answered "
                f"analyzing in {max(took):.0f} ms at most (job {job.get('cmd')}, "
                f"progress {seen['progress']}, etaMs {seen['etaMs']}); {v2}")
    finally:
        close_all(O, R2, R3, X)
        d.stop(force=True)


# ---- refresh_no_blackout --------------------------------------------------------------------

def _two_program_project(c, name):
    """The fixture with a second program (the dll) imported."""
    exe = prepare(c)
    gpr = c.copy_fixture(name)
    d = c.daemon(name.lower() + "-mk")
    w = c.connect(d, "mk", "e3c", 3)
    try:
        w.call("open_project", path=str(gpr), writable=True)
        w.call("import", file=c.a.dll, wait=600000, timeout=600)
        w.call("close_project")
    finally:
        close_all(w)
        d.stop(force=True)
    return gpr, exe, pathlib.Path(c.a.dll).name


def t_refresh_no_blackout(c):
    gpr, exe, other = _two_program_project(c, "e3cRf")
    d = c.daemon("e3c-rf")
    S = Q = V = U = None
    try:
        S = reader(c, d, gpr, exe, "S", open_program=False)
        S.call("open_program", path=other)
        S.call("open_program", path=exe)          # the active program, so the read below holds it
        warm(c, S)
        Q = reader(c, d, gpr, exe, "Q", open_program=False)
        V = reader(c, d, gpr, exe, "V")
        V.call("open_program", path=other)
        # (a) refresh queued behind a long read
        hold = sleeper(c, S, 9000)
        dt.wait_for(lambda: running(V, "S"), "the read to run", 20)
        pid = V.call("project")["id"]
        time.sleep(0.5)
        res = {}

        def refresh():
            res["r"] = bl.timed(c, Q, "refresh", project=pid, force=True, wait=20000)
        th = threading.Thread(target=refresh, daemon=True)
        t0 = time.perf_counter()
        th.start()
        time.sleep(0.4)
        probes = []
        while th.is_alive() or len(probes) < 6:
            for what, fn in (("same program", lambda: bl.timed(c, V, "info", program=f"{pid}:/{exe}", wait=800)),
                             ("other program", lambda: bl.timed(c, V, "info", program=f"{pid}:/{other}", wait=800)),
                             ("list", lambda: bl.timed(c, V, "list", project=pid, programsOnly=True, wait=800))):
                p = fn()
                probes.append((what, p))
            time.sleep(0.5)
            if time.perf_counter() - t0 > 8.5:
                break
        th.join(30)
        r = res["r"]
        bad = [(w, p["code"], p["ms"]) for w, p in probes if not p["ok"] or p["ms"] >= 800]
        dt.check(not bad, f"{len(bad)} of {len(probes)} probes were refused while the refresh was "
                          f"queued (BP7: all of them): {bad[:4]}")
        dt.check(r["ok"], f"the refresh ended with {r}")
        dt.check(r["ms"] < 3000, f"the refresh took {r['ms']} ms (it must not wait for the read)")
        acts = {p["program"]: p["action"] for p in r["result"]["programs"]}
        dt.check(acts.get(f"{pid}:/{exe}", "").startswith("kept"),
                 f"the program under the read should be pending, not {acts}")
        code, det, _ = attempt(c, S, hold)
        dt.check(code == "ok", f"the read that ran under the refresh ended with {code} {det}")
        # the pending reopen happens at the release of the read, nobody waited for it
        time.sleep(1.5)
        dt.check("refresh: " + f"{pid}:/{exe}" + " reopened" in log_text(d),
                 "the pending reopen was not completed after the read ended")
        a_note = f"refresh {r['ms']} ms, {len(probes)} probes none refused (slowest {max(p['ms'] for _, p in probes)} ms)"
        # (b) a writable open_project of the read-only view behind a long read (the s13 shape)
        close_all(Q)
        Q = reader(c, d, gpr, exe, "Q2", open_program=False)
        U = c.connect(d, "U", "e3c", 3)
        hold = sleeper(c, S, 7000)
        dt.wait_for(lambda: running(V, "S"), "the second read to run", 20)
        time.sleep(0.4)
        res = {}

        def upgrade():
            res["r"] = bl.timed(c, Q, "open_project", path=str(gpr), writable=True, wait=20000)
        th = threading.Thread(target=upgrade, daemon=True)
        th.start()
        time.sleep(0.5)
        probes = []
        for _ in range(6):
            probes.append(bl.timed(c, V, "info", program=f"{pid}:/{exe}", wait=800))
            probes.append(bl.timed(c, V, "list", project=pid, programsOnly=True, wait=800))
            time.sleep(0.4)
        th.join(30)
        r = res["r"]
        bad = [(p["code"], p["ms"]) for p in probes if not p["ok"] or p["ms"] >= 800]
        dt.check(not bad, f"{len(bad)} of {len(probes)} probes refused behind the queued writable open: {bad[:4]}")
        dt.check(r["ok"], f"the writable open_project ended with {r}")
        dt.check(r["ms"] < 3000, f"the writable open_project took {r['ms']} ms behind a read")
        finish(S, hold)
        return f"(a) {a_note}; (b) writable open_project {r['ms']} ms, {len(probes)} probes none refused"
    finally:
        close_all(S, Q, V, U)
        d.stop(force=True)


# ---- registry_state_machine -----------------------------------------------------------------

def t_registry_state_machine(c):
    exe = prepare(c)
    g1 = c.copy_fixture("e3cRg1")
    g2 = c.copy_fixture("e3cRg2")
    d = c.daemon("e3c-rg")
    clients = []
    try:
        # (1) eight first opens of one project at once: single flight, one project, all joined
        n = 8
        clients = [c.connect(d, f"o{i}", "e3c", 3) for i in range(n)]
        out = [None] * n

        refused = []

        def open_(i):
            # beyond the waiter cap (D39: max(2, slots / 4) = 6 on a quick lane) a request is told
            # busy{lock_queue_full} at once and retries, as 3.5 says a client does
            while True:
                out[i] = bl.timed(c, clients[i], "open_project", path=str(g1), wait=60000)
                if out[i]["ok"] or (out[i].get("details") or {}).get("reason") != "lock_queue_full":
                    return
                refused.append(out[i])
                time.sleep(0.3)
        ths = [threading.Thread(target=open_, args=(i,), daemon=True) for i in range(n)]
        for th in ths:
            th.start()
        for th in ths:
            th.join(60)
        dt.check(all(o and o["ok"] for o in out), f"an open failed: {[o for o in out if not o or not o['ok']]}")
        dt.check(all((r.get("details") or {}).get("waitersMax") for r in refused),
                 f"a refusal without the cap in its details: {refused[:1]}")
        ids = {o["result"]["id"] for o in out}
        dt.check(len(ids) == 1, f"one project opened under {len(ids)} ids: {ids}")
        dt.check(sum(1 for o in out if o["result"]["opened"]) == 1,
                 f"{sum(1 for o in out if o['result']['opened'])} requests claim to have opened it")
        st = clients[0].call("status")
        dt.check(len(st["projects"]) == 1, f"status lists {len(st['projects'])} projects")
        states = {x["state"] for x in st["projectStates"]}
        dt.check(states == {"open"}, f"project states {states}")
        # (2) a failed open leaves no slot and does not block a later good one
        bad = bl.timed(c, clients[0], "open_project", path=str(g1.parent / "nope" / "x.gpr"))
        dt.check(not bad["ok"], "opening a missing project worked")
        st = clients[0].call("status")
        dt.check(len(st["projectStates"]) == 1, f"a failed open left a slot: {st['projectStates']}")
        # (3) an open of an unrelated project is not held up by the churn of another
        for cl in clients:
            cl.call("open_program", path=exe)
        stop = threading.Event()
        errs = []

        def churn(cl):
            while not stop.is_set():
                try:
                    cl.call("close_project")
                    cl.call("open_project", path=str(g1), wait=30000)
                    cl.call("open_program", path=exe, wait=30000)
                except c.gs.SessionError as e:
                    errs.append(e.code)
        chs = [threading.Thread(target=churn, args=(cl,), daemon=True) for cl in clients[:6]]
        for th in chs:
            th.start()
        v = c.connect(d, "other", "e3c", 3)
        clients.append(v)
        t = time.perf_counter()
        r = bl.timed(c, v, "open_project", path=str(g2), wait=30000)
        dt.check(r["ok"], f"the unrelated open ended with {r}")
        unrelated_ms = r["ms"]
        time.sleep(3)
        stop.set()
        for th in chs:
            th.join(60)
        dt.check(not [e for e in errs if e not in ("busy",)], f"churn errors: {sorted(set(errs))}")
        # (4) consistent at the end
        for cl in clients[:6]:
            with contextlib.suppress(c.gs.SessionError):
                cl.call("close_project")
        st = v.call("status")
        by_id = {p["id"]: p for p in st["projects"]}
        for p in st["projects"]:
            dt.check(all(u in {x["id"] for x in st["clients"]} for u in p["users"]),
                     f"project {p['id']} lists users that are not clients: {p['users']}")
        sl = {x["project"]: x["state"] for x in st["projectStates"]}
        dt.check(set(sl) == set(by_id) and set(sl.values()) <= {"open"},
                 f"slots {sl} against projects {list(by_id)}")
        return (f"8 concurrent first opens ({len(refused)} told lock_queue_full once, then joined): "
                f"one project, one opener; a failed open left no slot; "
                f"{unrelated_ms} ms for an unrelated open during open/close churn of another; "
                f"final states {sorted(sl.values())}")
    finally:
        close_all(*clients)
        d.stop(force=True)


# ---- project_waiter_caps ----------------------------------------------------------------------------

def t_project_waiter_caps(c):
    import contract_tests as ct
    code, lines, err = ct.self_test(c)
    bad = [ln for ln in lines if ln.startswith("FAIL")]
    dt.check(code == 0 and not bad, f"-selfTest exit {code}: {bad} {err[-800:]}")
    want = ("ok   two protocol 3 requests queue for a held lock",
            "ok   the third protocol 3 waiter is answered QUEUE_FULL at once",
            "ok   a protocol 2 waiter is never capped",
            "ok   the two waiters that queued get the lock when it is released")
    for w in want:
        dt.check(any(ln.startswith(w) for ln in lines), f"the self-test check did not run or failed: {w}")
    exe = prepare(c)
    gpr = c.copy_fixture("e3cQf")
    d = c.daemon("e3c-qf", maxQuick=4)       # max(2, 4 / 4) = 2 waiters
    H = None
    rs = []
    try:
        H = c.connect(d, "owner", "e3c", 3)
        warm(c, H)
        H.call("open_project", path=str(gpr), writable=True)
        H.call("open_program", path=exe, writable=True)
        rs = [reader(c, d, gpr, exe, f"w{i}") for i in range(4)]
        old = reader(c, d, gpr, exe, "old", protocol=2)
        rs.append(old)
        fn = bl.first_function(H)
        hold = H.send("script", script=c.script("TestSleep.java"), args=["25000"], parallel=True,
                      wait=145000)
        dt.wait_for(lambda: holds(rs[0], exe), "the owner's script to hold the program", 30)
        waiting = [rs[i].send("decompile", address=fn, wait=40000, parallel=True) for i in range(2)]
        time.sleep(1.0)
        t = time.perf_counter()
        r3 = bl.timed(c, rs[2], "decompile", address=fn, wait=40000)
        ms = (time.perf_counter() - t) * 1000
        dt.check(not r3["ok"] and r3["code"] == "busy" and
                 (r3["details"] or {}).get("reason") == "lock_queue_full",
                 f"third waiter: {r3.get('code')} {r3.get('details')}")
        dt.check(ms < 800, f"it was told after {ms:.0f} ms")
        dt.check((r3["details"] or {}).get("waitersMax") == 2, f"details: {r3['details']}")
        # the open_program of a client joining the held program is a lock wait too: also capped
        r4 = bl.timed(c, rs[3], "decompile", address=fn, wait=600)
        dt.check(not r4["ok"] and (r4["details"] or {}).get("reason") == "lock_queue_full",
                 f"a fourth waiter: {r4.get('code')} {r4.get('details')}")
        # protocol 2: no cap, it waits its own time and ends busy as before
        r5 = bl.timed(c, old, "decompile", address=fn, wait=1200)
        dt.check(not r5["ok"] and r5["code"] == "busy" and r5["ms"] >= 1000 and
                 "reason" not in (r5["details"] or {}), f"protocol 2 waiter: {r5}")
        finish(H, hold)
        out = [attempt(c, rs[i], waiting[i])[0] for i in range(2)]
        dt.check(out == ["ok", "ok"], f"the two waiters ended with {out}")
        return ("selftest: the plain-lock cap holds; daemon: 2 waiters wait, the 3rd and 4th get "
                "busy{lock_queue_full} in %.0f ms, a protocol 2 waiter is not capped" % ms)
    finally:
        close_all(H, *rs)
        d.stop(force=True)


# ---- foreign_blocked_counter ----------------------------------------------------------------

def t_foreign_blocked_counter(c):
    gpr, exe, other = _two_program_project(c, "e3cFb")
    d = c.daemon("e3c-fb", keepWarm=60)
    rs = []
    O = None
    try:
        rs = [reader(c, d, gpr, exe, f"r{i}") for i in range(6)]
        pid = rs[0].call("project")["id"]
        warm(c, rs[0])
        base = waits(rs[0])
        dt.check(base["foreignBlocked"]["total"] == 0, f"a fresh daemon: {base}")
        fn = bl.first_function(rs[0])
        # reads, joins, leaves, a long read with churn around it, and a refresh of the view
        hold = sleeper(c, rs[0], 4000)
        dt.wait_for(lambda: running(rs[1], "r0"), "the read to run", 20)
        for i in range(1, 6):
            rs[i].call("open_program", path=other)
            rs[i].call("decompile", address=fn, program=f"{pid}:/{exe}", wait=3000)
            rs[i].call("close_program", program=f"{pid}:/{other}")
        rs[1].close()
        rs[2].call("refresh", project=pid, force=True)
        for i in (3, 4, 5):
            rs[i].call("list", project=pid, programsOnly=True)
            rs[i].call("close_program", program=f"{pid}:/{exe}")
        finish(rs[0], hold)
        after = waits(rs[3])
        dt.check(after["foreignBlocked"]["total"] == 0 and after["foreignBlocked"]["lastMinute"] == 0,
                 f"foreignBlocked after reads, joins, leaves and a refresh: {after}")
        # the control: a reader that waits behind an owner's script is counted
        gpr2 = c.copy_fixture("e3cFb2")
        O = c.connect(d, "owner", "e3c", 3)
        O.call("open_project", path=str(gpr2), writable=True)
        O.call("open_program", path=exe, writable=True)
        W = reader(c, d, gpr2, exe, "waiter")
        rs.append(W)
        hold = sleeper(c, O, 2500)
        wp = W.call("project")["id"]
        dt.wait_for(lambda: holds(W, exe, wp), "the owner's script to hold the program", 20)
        r = bl.timed(c, W, "info", wait=700)
        dt.check(not r["ok"], f"a reader behind an owner's script was served: {r}")
        ctl = waits(W)
        dt.check(ctl["foreignBlocked"]["total"] >= 1 and ctl["foreignBlocked"]["shared"] >= 1,
                 f"the control wait was not counted: {ctl}")
        finish(O, hold)
        return (f"foreignBlocked 0 over 6 readers' reads, joins, leaves, a FIN and a refresh "
                f"(singleFlightOpen {after['singleFlightOpen']}, contended waits {after['contended']}); "
                f"the control (a reader behind an owner's script) counted {ctl['foreignBlocked']['total']}")
    finally:
        close_all(O, *rs)
        d.stop(force=True)


# ---- yield_slots_stress ---------------------------------------------------------------------

def t_yield_slots_stress(c):
    """SP9 (D39): with ``yieldSlots`` on, waiters for a lock give their lane slot back. A stress of
    mixed holders and waiters on a small lane must end with every request answered (no deadlock
    between a lock holder that waits for a slot and slot holders that wait for the lock), and a
    client on another project must be served while the waiters wait.

    The lane has 2 quick slots, so the waiter cap (``max(2, 2 / 4)`` = 2 per lock, Waits.cap) lets
    the two queued waiters hold every quick slot: without the yield the victim's quick request (a
    ``list``, a quick-lane command) finds no slot until the hold ends (1.5 s after it is sent) and
    is refused after its 1 s wait; with the yield it is served at once. The cap alone cannot save
    the victim here (with 3 slots it did, and the test passed without the yield)."""
    gpr, exe, other = _two_program_project(c, "e3cYs")
    gpr2 = c.copy_fixture("e3cYs2")
    d = c.daemon("e3c-ys", maxQuick=2, engine={"yieldSlots": True})
    O = V = None
    ws = []
    try:
        O = c.connect(d, "owner", "e3c", 3)
        O.call("open_project", path=str(gpr), writable=True)
        O.call("open_program", path=exe, writable=True)
        warm(c, O)
        V = c.connect(d, "victim", "e3c", 3)
        V.call("open_project", path=str(gpr2))
        V.call("open_program", path=exe)
        vp = V.call("project")["id"]
        V.call("list", project=vp, programsOnly=True)   # warm
        ws = [reader(c, d, gpr, exe, f"w{i}") for i in range(12)]
        fn = bl.first_function(O)
        deadline = time.time() + 40
        results = []
        lock = threading.Lock()

        def waiter(i, w):
            while time.time() < deadline - 5:
                r = bl.timed(c, w, "decompile", address=fn, wait=15000)
                with lock:
                    results.append((i, r["ok"], r["code"] if not r["ok"] else None, r["ms"]))
                time.sleep(0.05)
        ths = [threading.Thread(target=waiter, args=(i, w), daemon=True) for i, w in enumerate(ws)]
        for th in ths:
            th.start()
        victims = []
        for round_ in range(6):
            hid = sleeper(c, O, 2000, "TestSleep.java", exclusive=True)
            time.sleep(0.5)
            # both quick slots are held by lock waiters now unless they yielded them
            victims.append(bl.timed(c, V, "list", project=vp, programsOnly=True, wait=1000))
            attempt(c, O, hid)
        for th in ths:
            th.join(60)
        stuck = [th for th in ths if th.is_alive()]
        dt.check(not stuck, f"{len(stuck)} waiters never ended: a deadlock")
        codes = {}
        for _, ok, code, _ in results:
            codes[code or "ok"] = codes.get(code or "ok", 0) + 1
        dt.check(set(codes) <= {"ok", "busy", "cancelled"}, f"unexpected codes {codes}")
        dt.check(codes.get("ok", 0) >= 20, f"too few completed requests {codes}")
        slow = [v for v in victims if not v["ok"] or v["ms"] >= 1000]
        dt.check(not slow, f"the quick request of a client of another project was refused or slow while "
                           f"the waiters waited: {[(v.get('code'), v['ms']) for v in slow]}")
        st = O.call("status")["scheduler"]["quick"]
        dt.check(st["inUse"] == 0, f"quick slots still held after the stress: {st}")
        return (f"yieldSlots on, 2 quick slots, 12 waiters on one program under 6 exclusive holds: "
                f"{codes}, no deadlock, the victim on another project served {len(victims)} of "
                f"{len(victims)} (slowest {max(v['ms'] for v in victims)} ms)")
    finally:
        close_all(O, V, *ws)
        d.stop(force=True)


# ---- chaos_oracle ---------------------------------------------------------------------------

def t_chaos_oracle(c):
    """The oracle of X0 over a run with the injectors of ``chaos_lib.py`` on the E3c engine: readers
    (plain, then joined and leaving) read steadily while clients are cut off without a goodbye
    (reset), the daemon is suspended for a moment, a refresh repoints the view, and an owner is
    killed under its own script; then the daemon is killed under load. K10 (a dead client holds
    nothing), K13 (``foreignBlocked`` is 0 for the readers' part and is not 0 for the control), K2
    (headers of every version file) and K6 (the project tree) must hold; the control must be flagged
    (an oracle that cannot fail proves nothing)."""
    import sys
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import chaos_lib as chaos
    import oracle
    exe = prepare(c)
    gpr = c.copy_fixture("e3cCh")
    proj = gpr.parent
    d = c.daemon("e3c-ch", keepWarm=60, engine={"cleanupGraceS": 3, "abandonWaitS": 3})
    rs = []
    O = None
    try:
        rs = [reader(c, d, gpr, exe, f"cr{i}") for i in range(8)]
        pid = rs[0].call("project")["id"]
        fn = bl.first_function(rs[0])
        stop = threading.Event()
        results = []
        lock = threading.Lock()

        def loop(i):
            while not stop.is_set():
                try:
                    r = bl.timed(c, rs[i], "decompile", address=fn, wait=4000)
                except Exception as e:  # noqa: BLE001 - the connection of a cut-off client
                    return
                with lock:
                    results.append((i, r["ok"], r.get("code"), r["ms"]))
                time.sleep(0.01)
        ths = [threading.Thread(target=loop, args=(i,), daemon=True) for i in range(len(rs))]
        for th in ths:
            th.start()
        time.sleep(1.5)
        dead = []
        # 1. two clients are cut off without a goodbye while their requests run
        for i in (1, 5):
            dead.append(f"cr{i}")
            chaos.abort_connection(rs[i])
        time.sleep(0.5)
        # 2. the daemon is suspended for a moment under load
        dpid = d.read_endpoint()["pid"]
        with chaos.Suspended(dpid):
            time.sleep(1.2)
        # 3. a refresh repoints the view while the others read; a client leaves, another joins
        q = c.connect(d, "refresher", "e3c", 3)
        q.call("open_project", path=str(gpr))
        q.call("refresh", project=pid, force=True, wait=10000)
        rs[2].call("close_program")
        late = reader(c, d, gpr, exe, "late")
        rs.append(late)
        time.sleep(2.0)
        stop.set()
        for th in ths:
            th.join(15)
        # K10 for each dead client, K13 over the readers' part
        rep = oracle.Report("e3c-chaos")
        for name in dead:
            oracle.check_k10(lambda n: d.connect(n, "oracle"), name, timeout_s=15, rep=rep)
        st = late.call("status")
        oracle.check_k13(st, rep=rep)
        served = sum(1 for _, ok, _, _ in results if ok)
        refused = [r for r in results if not r[1] and r[2] not in (None,)]
        dt.check(rep.ok, f"the oracle flags the readers' run: {rep.findings}")
        dt.check(served > 200, f"only {served} reads were served")
        dt.check(not [r for r in refused if r[2] == "busy"],
                 f"readers were refused busy during the chaos: {refused[:3]}")
        fb = st["waits"]["foreignBlocked"]
        # the control: an owner is killed under its own script; its readers wait and are counted
        gpr2 = c.copy_fixture("e3cCh2")
        O = c.connect(d, "ctl-owner", "e3c", 3)
        O.call("open_project", path=str(gpr2), writable=True)
        O.call("open_program", path=exe, writable=True)
        warm(c, O)
        W = reader(c, d, gpr2, exe, "ctl-waiter")
        rs.append(W)
        sleeper(c, O, 8000)
        wp = W.call("project")["id"]
        dt.wait_for(lambda: holds(W, exe, wp), "the owner's script to hold the program", 20)
        bl.timed(c, W, "info", wait=600)
        ctl = oracle.Report("control")
        oracle.check_k13(W.call("status"), rep=ctl)
        dt.check(not ctl.ok and any(f["code"] == "foreign_blocked" for f in ctl.findings),
                 f"the oracle did not flag the control: {ctl.findings}")
        chaos.abort_connection(O)
        t = time.perf_counter()
        r = None
        while time.perf_counter() - t < 12:
            r = bl.timed(c, W, "info", wait=1500)
            if r["ok"]:
                break
            time.sleep(0.25)
        dt.check(r and r["ok"], f"readers were still refused {time.perf_counter() - t:.1f} s after the owner's kill")
        rep10 = oracle.Report("k10-owner")
        oracle.check_k10(lambda n: d.connect(n, "oracle"), "ctl-owner", timeout_s=15, rep=rep10)
        dt.check(rep10.ok, f"K10 for the dead owner: {rep10.findings}")
        # 4. the daemon is killed under load; the project is intact and opens again
        for i in range(len(ths)):
            if i not in (1, 5):
                with contextlib.suppress(Exception):
                    rs[i].send("decompile", address=fn, wait=4000, parallel=True)
        chaos.terminate(dpid)
        k2 = oracle.Report("k2")
        oracle.check_k2(proj, k2)
        dt.check(k2.ok, f"K2 after the daemon kill: {k2.findings}")
        d2 = c.daemon("e3c-ch2")
        s2 = reader(c, d2, gpr, exe, "again")
        dt.check(bl.timed(c, s2, "decompile", address=fn, wait=5000)["ok"], "the project does not read after the kill")
        close_all(s2)
        d2.stop(force=True)
        return (f"{served} reads served during 2 cut-off clients, a daemon suspend, a refresh and a leave "
                f"(K10 for both dead clients, foreignBlocked {fb['total']}, none refused); the control owner "
                f"was flagged by K13 ({ctl.findings[0]['detail'][:60]}) and its readers were served "
                f"{time.perf_counter() - t:.1f} s after its kill; K2 held after the daemon kill")
    finally:
        close_all(O, *rs)
        d.stop(force=True)


# ---- close_vs_view_change -------------------------------------------------------------------

def t_close_vs_view_change(c):
    """The close of an idle project and a view change of it (``refresh``, the writable reopen of a
    read-only view) exclude each other (ProjectRegistry.closeIdle takes the project's structure lock).
    The interleaving is forced in the engine's own ``-selfTest`` with latches (no test code in a
    daemon): a thread holds the structure lock past its ``closed`` check, the reap's ``closeIdle`` runs
    meanwhile. Before the fix the close ran and the view change installed a writable view on a closed
    project that nothing ever closed (the daemon kept the project's OS lock)."""
    import contract_tests as ct
    code, lines, err = ct.self_test(c)
    want = "ok   a close of an idle project does not run while a view change of it"
    hit = [ln for ln in lines if "a close of an idle project does not run" in ln]
    dt.check(any(ln.startswith(want) for ln in hit),
             f"the self-test check failed or did not run: {hit or 'absent'} (exit {code}) {err[-400:]}")
    return "selftest: a close waits out a view change of the project and runs once after it"


# ---- abandoned_open_writable ----------------------------------------------------------------

def t_abandoned_open_writable(c):
    """A client cut off while its writable ``open_program`` runs (after its leave, before the open
    registers it): the open must undo what it set up (the owner, a shared writer, the program), so that
    another client opens the program writable at once. Before the fix the program stayed open WRITABLE
    with the dead client as owner, and every writable open spun on ``owner.leaving`` until its wait
    ran out (``busy``). The cuts are placed across the measured time of a writable open; the daemon
    log counts the ones that landed inside it, and at least one must have."""
    import chaos_lib as chaos
    exe = prepare(c)
    gpr = c.copy_fixture("e3cAo")
    # keepWarm 60: the reap's closeIdleProgram (keepWarm 0 makes it dispose an unused program every
    # second) must not be what clears a dead owner within B's wait
    d = c.daemon("e3c-ao", keepWarm=60)
    B = None
    try:
        B = c.connect(d, "B", "e3c", 3)
        B.call("open_project", path=str(gpr), writable=True)
        spans = []
        for _ in range(3):
            t0 = time.perf_counter()
            B.call("open_program", path=exe, writable=True)
            spans.append((time.perf_counter() - t0) * 1000)
            B.call("close_program")
        open_ms = sorted(spans)[1]
        # The cut is steered to the end of the open (a stochastic search): a cut that comes too early is
        # seen by the open's own cancel checks (the request ends cancelled, the next cut comes later), one
        # that comes after the answer changes nothing (the next comes earlier). The window that matters,
        # after the last cancel check and before the open registers the client, is at that edge.
        import re
        delay = open_ms * 0.4
        step = max(0.3, open_ms / 25)
        bad = []
        tries = 0
        hits = 0
        outcomes = {"ok": 0, "cancelled": 0}
        while tries < 120 and hits < 3:
            name = f"A{tries}"
            tries += 1
            A = c.connect(d, name, "e3c", 3)
            A.call("open_project", path=str(gpr), writable=True)
            # parallel: the connection's reader goes on reading and sees the cut while the open
            # runs (a request that is not parallel holds the reader until it is answered)
            A.send("open_program", path=exe, writable=True, wait=10000, parallel=True)
            chaos.sleep_precise(delay / 1000.0)
            chaos.abort_connection(A)
            dt.wait_for(lambda: not any(cl["name"] == name for cl in B.call("status")["clients"]),
                        f"{name} to be released", 30)
            pat = re.compile(r"\(" + name + r", e3c\) open_program \d+ ms (\w+)")
            m = dt.wait_for(lambda: pat.search(log_text(d)), f"the end of {name}'s open", 30)
            outcome = m.group(1)
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            r = bl.timed(c, B, "open_program", path=exe, writable=True, wait=2000)
            if r["ok"]:
                B.call("close_program")
            else:
                bad.append((name, round(delay, 1), r.get("code"), (r.get("message") or "")[:90]))
                break   # a dead owner stays: every later try would only repeat it
            delay = delay + step if outcome != "ok" else max(0.0, delay - step)
            hits = log_text(d).count("its open of")
        dt.check(not bad, f"after a cut inside a writable open, another client could not open the program "
                          f"writable: {bad[:3]}")
        dt.check(hits >= 1, f"none of the {tries} cuts landed inside the writable open (about {open_ms:.0f} ms): "
                            f"the path was not exercised")
        return (f"{tries} cuts steered to the end of a writable open of about {open_ms:.0f} ms ({outcomes}), "
                f"{hits} inside the window (undone); after each, another client opened the program writable "
                f"at once")
    finally:
        close_all(B)
        d.stop(force=True)


TESTS = {
    "reader_leave_no_freeze": t_reader_leave_no_freeze,
    "last_user_leave_disposes": t_last_user_leave_disposes,
    "deferred_leave_closes_project": t_deferred_leave_closes_project,
    "reader_leave_all": t_reader_leave_all,
    "refcount_leak": t_refcount_leak,
    "lock_matrix_rows": t_lock_matrix_rows,
    "analyzing_join": t_analyzing_join,
    "refresh_no_blackout": t_refresh_no_blackout,
    "registry_state_machine": t_registry_state_machine,
    "foreign_blocked_counter": t_foreign_blocked_counter,
    "yield_slots_stress": t_yield_slots_stress,
    "chaos_oracle": t_chaos_oracle,
    "project_waiter_caps": t_project_waiter_caps,
    "close_vs_view_change": t_close_vs_view_change,
    "abandoned_open_writable": t_abandoned_open_writable,
}

BASELINE = {}
