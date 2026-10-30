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
"""Cancel-aware lock waits, bounded release, abandoned holders and ``applied`` (PROTOCOL-3.md 3.5,
package E3b).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --only cancel_queued,...

The tests that E0 wrote as expected-fail baselines and that E3b fixes live in ``dt_baseline.py`` and
run by name on this engine: ``dead_client_lock_wait`` and ``cancel_lock_wait``. The tests here are
the others the spec names for E3b (all ask for protocol 3 unless the name says otherwise; the
protocol 2 behaviour is ``cc_e3b.py``'s):

* ``cancel_queued``: a request waiting for a slot and a request waiting for a program lock both
  answer ``cancelled`` within 1 s of the cancel, ``details.phase`` says which.
* ``cancel_while_waiting`` (protocol 2 and 3): the cancel of a request queued behind an exclusive
  holder; the requests behind it keep their order and run when the holder ends, the holder is
  unaffected; 200 cancels sent around the instant the holder releases end only in ``cancelled`` or
  success, leak no lock and leave no ``ClosedByInterruptException`` in the log. (The races show that no
  lock leaks and no request is lost; they are not a proof of "no stray interrupt": that flag is
  cleared by ``tryLock`` itself, and a mutation that stopped clearing it in ``leaveWait`` stays green.)
* ``deadline_in_lock_wait``: a ``timeout`` shorter than the lock wait answers ``cancelled`` at the
  deadline.
* ``writer_vs_steady_readers`` (protocol 2 and 3): an exclusive request among eight steady readers
  acquires in bounded time and keeps its place in the queue.
* ``dead_client_released``: the bound ``cleanupGraceS + abandonWaitS + 2 s`` of a client killed in a
  lock wait (the baseline ``dead_client_lock_wait`` allows 40 s), and ``dead_write_not_applied``
  (the write a dead client queued is never applied, BP11).
* ``abandoned_holder``: a non-cooperative script of a dead client: ``abandonedRequests``,
  ``busy{reason:abandoned}`` at once, the program is not disposed, nothing waits 600 s, and the leave
  finishes when the script ends.
* ``owner_leave_bounded`` (D63a): an owner or writer killed while another client reads the program:
  the exclusive leave waits at most ``cleanupGraceS + abandonWaitS``, readers wait no longer.
* ``lock_queue_full``: more than ``max(2, slots/4)`` waiters on one lock are answered ``busy`` at
  once with ``reason:"lock_queue_full"`` and ``retryAfterMs``.
* ``v2_program_shape`` (protocol 2 and 3): a protocol 2 ``status.programs[]`` and ``list`` ``open`` have
  hydra.3's keys exactly (no ``lockWaiters``); a protocol 3 ``status`` adds ``lockWaiters``.
* ``applied_flag``: ``cancelled.details.applied`` for ``rename``, ``comment``, ``save`` and an owner
  script.
* ``stalled_socket`` (BP23): a client that stops reading holds no lock of anyone else for longer than
  its request and is disconnected after ``writeStallMs``.
* ``parallel_reads`` (BP15): on protocol 3 a read-class command runs beside a long request of the same
  connection unless it says ``ordered``.
* ``registry_unnested`` (BP8): an unrelated project's ``open_project`` does not wait for a writable
  ``open_project`` that waits for its project lock.
* ``orphan_ttl`` (optional, default off): ``orphanKeepS`` writes the unsaved edits of a dead shared
  writer to ``<stateDir>/recovery/`` and discards them.
"""
import contextlib
import json
import pathlib
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

DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E3bDeaf extends GhidraScript {
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
        println("deaf done " + System.currentTimeMillis());
    }
}
"""
PROGRESS = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E3bProgress extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        int i = 0;
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            monitor.setMessage("tick " + (i++));
            Thread.sleep(50);
        }
        println("progress done");
    }
}
"""
BIG = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E3bBig extends GhidraScript {
    @Override protected void run() throws Exception {
        String line = "x".repeat(999);
        int n = Integer.parseInt(getScriptArgs()[0]);
        for (int i = 0; i < n; i++) {
            println(line);
        }
    }
}
"""
#: a quick dead-client release: the defaults (15 s and 5 s) would make every test wait for them
FAST = {"engine": {"cleanupGraceS": 2, "abandonWaitS": 2}}
GRACE_S, ABANDON_S = 2, 2


# ---- helpers --------------------------------------------------------------------------------

def prepare(c):
    exe = bl.prepare(c)
    (c.scripts / "E3bDeaf.java").write_text(DEAF)
    (c.scripts / "E3bProgress.java").write_text(PROGRESS)
    (c.scripts / "E3bBig.java").write_text(BIG)
    return exe


def warm(c, s, *names):
    """Runs each script once on no program: the script framework is up and the script compiled, so
    that a later script takes its lock at once and runs for as long as it was asked to (a first
    run compiles inside the request, after the lock is taken, and is not interruptible)."""
    for n in names or ("TestSleep.java",):
        s.call("script", script=c.script(n), program=None, args=["10"], wait=120000)


def owner(c, d, gpr, exe, name="owner", protocol=3, share=False, scripts=()):
    s = c.connect(d, name, "e3b", protocol)
    warm(c, s, "TestSleep.java", *scripts)
    s.call("open_project", path=str(gpr), writable=True)
    if share:
        s.call("open_program", path=exe, writable=True, share=True)
    else:
        s.call("open_program", path=exe, writable=True)
    return s


def reader(c, d, gpr, exe, name, protocol=3):
    s = c.connect(d, name, "e3b", protocol)
    s.call("open_project", path=str(gpr))
    s.call("open_program", path=exe)
    return s


def program(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return pg
    return None


def holds(s, exe):
    pg = program(s, exe)
    return bool(pg and pg["busy"])


def script(c, s, ms, name="TestSleep.java", **extra):
    """Starts a script on the active program (an owner script holds the lock exclusively)."""
    return s.send("script", script=c.script(name), args=[str(ms)], parallel=True,
                  wait=ms + 120000, **extra)


def attempt(c, s, rid):
    """The outcome of a request that was sent: ``(code or "ok", details, seconds-agnostic result)``."""
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
        with contextlib.suppress(Exception):
            s.close()


def log_text(d):
    try:
        return d.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def times(out):
    """``(start, end)`` ms of a TestSleep reply output."""
    st = en = None
    for ln in out.splitlines():
        if ln.startswith("start "):
            st = int(ln.split()[1])
        elif ln.startswith("end "):
            en = int(ln.split()[1])
    return st, en


# ---- cancel_queued --------------------------------------------------------------------------

def t_cancel_queued(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bCq")
    d = c.daemon("e3b-cq", maxQuick=1)
    H = R = None
    try:
        H = owner(c, d, gpr, exe)
        R = reader(c, d, gpr, exe, "waiter")
        fn = bl.first_function(H)
        # (1) a slot wait: the one quick slot is taken by a quick script
        occ = H.send("script", script=c.script("TestSleep.java"), program=None, args=["60000"],
                     lane="quick", timeout=60, parallel=True, wait=120000)
        dt.wait_for(lambda: H.call("status")["scheduler"]["quick"]["inUse"] >= 1,
                    "the quick slot to be taken", 30)
        rid = R.send("decompile", address=fn, wait=60000, parallel=True)
        dt.wait_for(lambda: H.call("status")["scheduler"]["quick"]["queued"] >= 1,
                    "the decompile to queue for the slot", 10)
        t = time.perf_counter()
        R.call("cancel", target=rid)
        code, det, _ = attempt(c, R, rid)
        slot_ms = (time.perf_counter() - t) * 1000
        dt.check(code == "cancelled", f"a queued request answered {code}, not cancelled")
        dt.check(slot_ms < 1000, f"the slot wait answered cancelled after {slot_ms:.0f} ms")
        dt.check(det.get("phase") == "queued" and det.get("applied") is None,
                 f"details of a cancelled slot wait: {det}")
        finish(H, occ)
        dt.wait_for(lambda: H.call("status")["scheduler"]["quick"]["inUse"] == 0,
                    "the quick slot to be free", 30)
        # (2) a lock wait: the owner's script holds the program exclusively
        hold = script(c, H, 60000)
        dt.wait_for(lambda: holds(R, exe), "the holder's script to hold the program", 30)
        rid = R.send("decompile", address=fn, wait=60000, parallel=True)
        dt.wait_for(lambda: (program(H, exe) or {}).get("lockWaiters") == 1,
                    "the decompile to wait for the program lock", 30)
        t = time.perf_counter()
        R.call("cancel", target=rid)
        code, det, _ = attempt(c, R, rid)
        lock_ms = (time.perf_counter() - t) * 1000
        dt.check(code == "cancelled", f"a request in a lock wait answered {code}, not cancelled")
        dt.check(lock_ms < 1000, f"the lock wait answered cancelled after {lock_ms:.0f} ms")
        dt.check(det.get("phase") == "lock_wait", f"details of a cancelled lock wait: {det}")
        dt.check(holds(R, exe), "the holder lost the program because a waiter was cancelled")
        c.timings["cancel_queued: slot wait (ms)"] = round(slot_ms)
        c.timings["cancel_queued: lock wait (ms)"] = round(lock_ms)
        finish(H, hold)
        return (f"cancelled after {slot_ms:.0f} ms in the slot wait (phase queued) and "
                f"{lock_ms:.0f} ms in the lock wait (phase lock_wait), the holder undisturbed")
    finally:
        close_all(H, R)
        d.stop(force=True)


# ---- cancel_while_waiting -------------------------------------------------------------------

def _cancel_while_waiting(c, protocol, races, first=0):
    """Part (a) and ``races`` races of part (b), numbered from ``first`` (the race number picks the
    offset of the cancel against the release, so shards that split 0..199 cover the same offsets)."""
    exe = prepare(c)
    tag = f"{protocol}-{first}" if first else f"{protocol}"
    gpr = c.copy_fixture(f"e3bCw{tag}")
    # three requests wait on one lock: the protocol 3 cap must admit them. The defaults derive the
    # slots from the CPUs (quick = CPUs, long = max(8, CPUs)), and the cap is at most half the lane
    # (PROTOCOL-3.md 8.18), so a 4-CPU host has a cap of 2 and refuses the third with
    # lock_queue_full; 12 slots per lane give a cap of 4
    d = c.daemon(f"e3b-cw{tag}", maxQuick=12, maxLong=12)
    H = R = X = M = None
    try:
        H = owner(c, d, gpr, exe, protocol=protocol)
        R = reader(c, d, gpr, exe, "waiter", protocol)
        X = reader(c, d, gpr, exe, "waiter2", protocol)
        M = c.connect(d, "M", "e3b", 3)       # reads the daemon's wait counters, joins nothing
        fn = bl.first_function(H)
        if protocol == 3:
            sched = H.call("status")["scheduler"]
            cap = max(2, min(sched[k]["slots"] for k in ("quick", "long")) // 4)
            if cap < 3:
                raise dt.Fail(f"the daemon reports slots {[sched[k]['slots'] for k in ('quick', 'long')]}"
                              f": a lock admits {cap} waiters, the test needs 3")
        # (a) three exclusive scripts queue behind the owner's script; the first is cancelled. The
        # holder holds until the test cancels it (no fixed run time), and each waiter is sent once
        # the daemon counts the one before it on the program lock (``lockWaiters``), so the order
        # and the cancel's phase do not depend on how fast a loaded host gets there
        hold = script(c, H, 3600000)
        dt.wait_for(lambda: holds(R, exe), "the holder's script to hold the program", 120)

        def queued():
            pg = program(M, exe)
            return pg.get("lockWaiters") if pg else None
        q = []
        for s_, ms in ((R, 50), (X, 50), (R, 50)):
            q.append((s_, s_.send("script", script=c.script("TestSleep.java"), args=[str(ms)],
                                  exclusive=True, parallel=True, wait=3600000)))
            dt.wait_for(lambda: queued() == len(q), f"waiter {len(q)} to queue behind the holder", 120)
        t = time.perf_counter()
        q[0][0].call("cancel", target=q[0][1])
        code, det, _ = attempt(c, q[0][0], q[0][1])
        ms_cancel = (time.perf_counter() - t) * 1000
        dt.check(code == "cancelled", f"the first queued request answered {code}")
        dt.check(ms_cancel < 1000, f"protocol {protocol}: cancelled after {ms_cancel:.0f} ms")
        if protocol == 3:
            dt.check(det.get("phase") == "lock_wait", f"details: {det}")
        else:
            dt.check("phase" not in det and "applied" not in det,
                     f"a protocol 2 cancelled grew keys: {det}")
        dt.check(holds(R, exe), "the holder lost the lock")
        dt.wait_for(lambda: queued() == 2, "the two requests behind it to stay queued", 30)
        dt.check(holds(R, exe), "the holder was affected by the cancel")
        H.call("cancel", target=hold)                   # the release the two waiters queue for
        oh = attempt(c, H, hold)
        dt.check(oh[0] == "cancelled", f"the holder ended with {oh[0]}, not with its own cancel")
        o2 = attempt(c, q[1][0], q[1][1])
        o3 = attempt(c, q[2][0], q[2][1])
        dt.check(o2[0] == "ok" and o3[0] == "ok", f"the requests behind it: {o2[0]} {o3[0]}")
        s2, e2 = times(o2[2]["output"])
        s3, e3 = times(o3[2]["output"])
        dt.check(s2 and s3 and s2 < s3 and e2 <= s3 + 5,
                 f"the order behind the cancelled request changed: {s2}-{e2}, {s3}-{e3}")
        # (b) cancels raced against the release
        durs = []
        for _ in range(5):
            t = time.perf_counter()
            H.call("script", script=c.script("TestSleep.java"), args=["40"])
            durs.append(time.perf_counter() - t)
        dur = sorted(durs)[len(durs) // 2]
        counts = {"ok": 0, "cancelled": 0}
        phases = {}
        for i in range(first, first + races):
            off = ((i % 41) - 20) / 1000.0
            t0 = time.perf_counter()
            hid = H.send("script", script=c.script("TestSleep.java"), args=["40"], parallel=True)
            time.sleep(0.02)
            rid = R.send("info", wait=20000, parallel=True)      # a read that takes ~1 ms
            lag = t0 + dur + off - time.perf_counter()
            if lag > 0:
                time.sleep(lag)
            R.call("cancel", target=rid)
            code, det, _ = attempt(c, R, rid)
            dt.check(code in ("ok", "cancelled"),
                     f"race {i}: the waiting request ended with {code} {det}")
            counts[code] += 1
            if code == "cancelled" and protocol == 3:
                phases[det.get("phase")] = phases.get(det.get("phase"), 0) + 1
            dt.check(attempt(c, H, hid)[0] == "ok", f"race {i}: the holder did not finish ok")
        # nothing leaked: exclusive and shared acquirers get in (a stray interrupt that closed a
        # channel under the next request would show here only if it landed in that window)
        H.call("comment", address=fn, type="eol", text="e3b cw", wait=3000)
        R.call("decompile", address=fn, wait=3000)
        H.call("save", wait=3000)
        pg = program(R, exe)
        dt.check(pg and not pg["busy"], f"status.programs shows the program held: {pg}")
        log = log_text(d)
        dt.check("ClosedByInterruptException" not in log,
                 "the daemon log has ClosedByInterruptException")
        which = f" (#{first}-{first + races - 1})" if first or races != CW_RACES else ""
        return (f"protocol {protocol}: cancelled in {ms_cancel:.0f} ms, order behind it kept; "
                f"{races} races{which}: {counts['cancelled']} cancelled {phases or ''}, "
                f"{counts['ok']} completed, no leak")
    finally:
        close_all(H, R, X, M)
        d.stop(force=True)


CW_RACES = 200      # races per protocol
CW_SHARDS = 4       # shards per protocol when run as shards (each also runs part (a))


def t_cancel_while_waiting(c):
    notes = [_cancel_while_waiting(c, 3, CW_RACES), _cancel_while_waiting(c, 2, CW_RACES)]
    return "; ".join(notes)


def _cw_shard(protocol, first, count):
    return lambda c: _cancel_while_waiting(c, protocol, count, first)


# ---- deadline_in_lock_wait ------------------------------------------------------------------

def t_deadline_in_lock_wait(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bDl")
    d = c.daemon("e3b-dl")
    H = R = None
    try:
        H = owner(c, d, gpr, exe)
        R = reader(c, d, gpr, exe, "waiter")
        hold = script(c, H, 60000)
        dt.wait_for(lambda: holds(R, exe), "the holder's script to hold the program", 30)
        t = time.perf_counter()
        rid = R.send("script", script=c.script("TestSleep.java"), args=["10"], timeout=2,
                     wait=60000, parallel=True)
        code, det, _ = attempt(c, R, rid)
        ms = (time.perf_counter() - t) * 1000
        dt.check(code == "cancelled", f"a request whose timeout (2 s) ran out in a lock wait "
                 f"answered {code} after {ms:.0f} ms")
        dt.check(1700 <= ms <= 3500, f"it answered after {ms:.0f} ms, the deadline was 2000")
        dt.check(det.get("phase") == "lock_wait", f"details: {det}")
        finish(H, hold)
        return f"timeout 2 s in a lock wait of 60 s: cancelled after {ms:.0f} ms"
    finally:
        close_all(H, R)
        d.stop(force=True)


# ---- writer_vs_steady_readers ---------------------------------------------------------------

def _steady(c, protocol, run_after_s=25.0, n_readers=8, hold_ms=50):
    """Eight readers loop on ~50 ms shared holds (a contained script each); after 2 s an exclusive
    script arrives and the readers keep looping for ``run_after_s`` more seconds. A correct wait
    gets the lock after the readers that are ahead of it (about one reader cycle); a wait that
    re-joins the queue's tail does not get it before the readers stop."""
    exe = prepare(c)
    gpr = c.copy_fixture(f"e3bWr{protocol}")
    d = c.daemon(f"e3b-wr{protocol}")
    H = None
    sessions = []
    try:
        H = owner(c, d, gpr, exe, protocol=protocol)
        sessions = [reader(c, d, gpr, exe, f"r{i}", protocol) for i in range(n_readers)]
        W = reader(c, d, gpr, exe, "writer", protocol)
        sessions.append(W)
        stop = threading.Event()
        log = []          # (sent, start, end, replied) of every reader hold, wall clock ms
        lock = threading.Lock()

        def loop(s):
            while not stop.is_set():
                sent = time.time() * 1000
                try:
                    r = s.call("script", script=c.script("TestSleep.java"), args=[str(hold_ms)],
                               wait=60000)
                except Exception:  # noqa: BLE001
                    return
                st, en = times(r["output"])
                with lock:
                    log.append((sent, st, en, time.time() * 1000))

        ths = [threading.Thread(target=loop, args=(s,), daemon=True) for s in sessions[:n_readers]]
        for th in ths:
            th.start()
        time.sleep(2.5)
        w_sent = time.time() * 1000
        threading.Timer(run_after_s, stop.set).start()
        r = W.call("script", script=c.script("TestSleep.java"), args=[str(hold_ms)],
                   exclusive=True, wait=60000)
        w_start, w_end = times(r["output"])
        stop.wait(run_after_s + 5)
        for th in ths:
            th.join(60)
        waited = w_start - w_sent
        with lock:
            pre = [x[3] - x[0] for x in log if w_sent - 2000 <= x[3] <= w_sent]
            late = [x for x in log if x[0] >= w_sent + 300]
        cycle = max(pre) if pre else 1000.0
        # The wait is the rest of the holds that are ahead of it: measured 1 to 4 reader cycles on a
        # loaded machine (the holds serialise on the script framework's instance creation). A wait
        # that re-joins the queue's tail waits until the readers stop (run_after_s), several times that.
        bound = 5 * cycle + 2000
        dt.check(late, "no reader arrived after the writer")
        before = [x for x in late if x[1] < w_end - 10]
        if waited > bound:
            raise dt.PremiseFail(f"the exclusive script waited {waited:.0f} ms among {n_readers} "
                                 f"steady readers (their cycle {cycle:.0f} ms, bound {bound:.0f}); "
                                 f"the readers ran another {run_after_s:.0f} s",
                                 {"waitedMs": waited, "cycleMs": cycle})
        dt.check(not before, f"{len(before)} reader(s) that arrived 300 ms after the writer "
                 f"started before it ended (FIFO broken): {before[:3]} writer {w_start}-{w_end}")
        return (f"protocol {protocol}: the exclusive script acquired {waited:.0f} ms after it was "
                f"sent among {n_readers} readers looping on {hold_ms} ms holds (a reader cycle "
                f"takes {cycle:.0f} ms, bound {bound:.0f}); {len(late)} later readers all started "
                f"after it ended")
    finally:
        close_all(H, *sessions)
        d.stop(force=True)


def t_writer_vs_steady_readers(c):
    # each half keeps the readers looping run_after_s = 25 s after the writer arrives (a designed
    # wait: a wait that re-joins the queue's tail must have the time to show)
    return "; ".join([_steady(c, 3), _steady(c, 2)])


# ---- dead_client_released / dead_write_not_applied ------------------------------------------

def t_dead_client_released(c):
    """A client killed while it waits for a program lock with ``wait`` 3600000 is gone within
    ``cleanupGraceS + abandonWaitS + 2 s`` (default 15 + 5 + 2) with the holder still holding."""
    exe = prepare(c)
    gpr = c.copy_fixture("e3bDr")
    d = c.daemon("e3b-dr")
    bound = 15 + 5 + 2
    H = O = D = None
    try:
        H = owner(c, d, gpr, exe)
        O = reader(c, d, gpr, exe, "observer")
        D = reader(c, d, gpr, exe, "doomed")
        fn = bl.first_function(H)
        hold = script(c, H, 120000)
        dt.wait_for(lambda: holds(O, exe), "the holder's script to hold the program", 30)
        D.send("decompile", address=fn, wait=3600000, parallel=True)
        dt.wait_for(lambda: any(cl["name"] == "doomed" and cl["requests"]
                                for cl in O.call("status")["clients"]),
                    "the doomed request to be registered", 30)
        time.sleep(1.0)
        t = time.perf_counter()
        D.close()
        gone = None
        while time.perf_counter() - t < bound + 5:
            if "doomed" not in bl.client_names(O):
                gone = time.perf_counter() - t
                break
            time.sleep(0.1)
        dt.check(gone is not None and gone <= bound,
                 f"the killed client was still registered {bound + 5} s after its kill")
        dt.check(holds(O, exe), "the holder lost the program")
        c.timings["dead_client_released: gone after (ms)"] = round(gone * 1000)
        finish(H, hold)
        return f"the client killed in a 3600000 ms lock wait was gone after {gone:.2f} s (bound {bound})"
    finally:
        close_all(H, O, D)
        d.stop(force=True)


def t_dead_write_not_applied(c):
    """BP11: a shared writer queues a ``comment`` (exclusive) behind a long read and dies. Its queued
    write leaves the lock queue at once and is never applied. The only thing that can still refuse
    readers is the exclusive leave of the dead writer itself (D63a), which waits at most
    ``abandonWaitS`` (2 s here) behind the long read."""
    exe = prepare(c)
    gpr = c.copy_fixture("e3bDw")
    d = c.daemon("e3b-dw", **FAST)
    A = B = C = None
    try:
        A = owner(c, d, gpr, exe, "writerA", share=True)
        B = owner(c, d, gpr, exe, "writerB", share=True)
        C = reader(c, d, gpr, exe, "reader")
        fn = bl.first_function(A)
        long_read = script(c, C, 9000)          # a contained script: the shared lock
        dt.wait_for(lambda: any(cl["name"] == "reader" and cl["requests"]
                                for cl in A.call("status")["clients"]), "the long read", 30)
        time.sleep(0.8)
        B.send("comment", address=fn, type="eol", text="DEAD CLIENT WRITE", wait=60000, parallel=True)
        time.sleep(1.0)
        B.close()
        t = time.perf_counter()
        slow = []
        while time.perf_counter() - t < 6:
            r = bl.timed(c, A, "info", wait=800)
            if not r["ok"]:
                slow.append((round(time.perf_counter() - t + r["ms"] / 1000, 1), r["code"], r["ms"]))
            time.sleep(0.4)
        last = max((x[0] for x in slow), default=0)
        dt.check(last <= ABANDON_S + 1.5, f"readers were refused for {last} s after the dead "
                 f"client's queued write (bound {ABANDON_S} s of its leave + 1.5): {slow}")
        bl_ = attempt(c, C, long_read)
        dt.check(bl_[0] == "ok", f"the long read ended with {bl_[0]}")
        time.sleep(1.0)
        j = A.call("journal")
        dt.check("DEAD CLIENT WRITE" not in json.dumps(j),
                 f"the dead client's queued write was applied: {json.dumps(j)[:300]}")
        cm = A.call("script", script=c.script("TestSleep.java"), args=["10"])  # the lock is free
        return (f"readers were refused for {last} s at most (the writer's leave, bound {ABANDON_S} s); "
                f"its queued write is not in the journal")
    finally:
        close_all(A, B, C)
        d.stop(force=True)


# ---- abandoned_holder -----------------------------------------------------------------------

def t_abandoned_holder(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bAb")
    d = c.daemon("e3b-ab", **FAST)
    deaf_ms = 14000
    H = O = None
    try:
        H = owner(c, d, gpr, exe, scripts=("E3bDeaf.java",))
        O = reader(c, d, gpr, exe, "observer")
        fn = bl.first_function(O)
        H.send("script", script=c.script("E3bDeaf.java"), args=[str(deaf_ms)], parallel=True,
               wait=120000)
        dt.wait_for(lambda: holds(O, exe), "the deaf script to hold the program", 30)
        t = time.perf_counter()
        H.close()
        flagged = None
        pg = None
        while time.perf_counter() - t < GRACE_S + ABANDON_S + 6:
            pg = program(O, exe)
            if pg and pg.get("abandonedRequests"):
                flagged = time.perf_counter() - t
                break
            time.sleep(0.1)
        dt.check(flagged is not None,
                 f"no abandonedRequests {GRACE_S + ABANDON_S + 6} s after the owner died: {pg}")
        dt.check(flagged <= GRACE_S + ABANDON_S + 2.5,
                 f"flagged after {flagged:.1f} s, bound {GRACE_S + ABANDON_S + 2}")
        ab = pg["abandonedRequests"][0]
        dt.check("script" in ab["cmd"] and ab["runningMs"] >= 1000, f"abandoned entry: {ab}")
        dt.check("doomed" not in bl.client_names(O) and "owner" not in bl.client_names(O),
                 "the dead owner is still listed as a client")
        # other requests: busy at once, naming the abandoned request
        r = bl.timed(c, O, "decompile", address=fn, wait=20000)
        dt.check(not r["ok"] and r["code"] == "busy", f"a request on the abandoned program: {r}")
        dt.check(r["ms"] < 1500, f"it took {r['ms']} ms to be told busy")
        det = r["details"]
        dt.check(det.get("reason") == "abandoned" and det.get("abandoned") is True,
                 f"busy details: {det}")
        dt.check("abandoned request" in det.get("holder", "") and "client gone" in det["holder"],
                 f"holder text: {det.get('holder')}")
        dt.check(isinstance(det.get("holderInfo"), dict), f"holderInfo: {det}")
        # the program object is not disposed: it is still there and its entry has its users
        pg = program(O, exe)
        dt.check(pg is not None and O.call("status")["you"] in pg["users"],
                 f"the abandoned program is gone from status: {pg}")
        # nothing waits for minutes: the script ends, the flag goes, the leave finishes
        dt.wait_for(lambda: not (program(O, exe) or {}).get("abandonedRequests"),
                    "the abandoned flag to clear", deaf_ms / 1000 + 20)
        info = None

        def readable():
            nonlocal info
            r = bl.timed(c, O, "info", wait=2000)
            info = r
            return r["ok"]

        dt.wait_for(readable, "the program to be readable again", 15, 0.3)
        dt.wait_for(lambda: (program(O, exe) or {}).get("owner") is None,
                    "the dead owner's leave to finish", 20, 0.3)
        pg = program(O, exe)
        dt.check(pg["mode"] == "read_only", f"after the leave the program is {pg['mode']}")
        total = time.perf_counter() - t
        return (f"flagged {flagged:.1f} s after the owner died (grace {GRACE_S} + abandon "
                f"{ABANDON_S}); busy(abandoned) in {r['ms']} ms; the leave finished when the "
                f"script ended ({total:.1f} s in)")
    finally:
        close_all(H, O)
        d.stop(force=True)


# ---- owner_leave_bounded --------------------------------------------------------------------

def t_owner_leave_bounded(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bOl")
    d = c.daemon("e3b-ol", **FAST)
    read_ms = 24000
    bound = GRACE_S + ABANDON_S
    H = O = N = None
    try:
        H = owner(c, d, gpr, exe)
        O = reader(c, d, gpr, exe, "reader")
        N = reader(c, d, gpr, exe, "newcomer")
        read = script(c, O, read_ms)             # contained: the shared lock for 24 s
        dt.wait_for(lambda: any(cl["name"] == "reader" and cl["requests"]
                                for cl in N.call("status")["clients"]), "the long read", 30)
        time.sleep(0.5)
        t = time.perf_counter()
        H.close()
        refused = []
        last_busy_end = 0.0
        ok_after = None
        while time.perf_counter() - t < bound + 8:
            t1 = time.perf_counter()
            r = bl.timed(c, N, "info", wait=1500)
            now = time.perf_counter() - t
            if not r["ok"]:
                refused.append((round(t1 - t, 1), r["code"], r["ms"]))
                last_busy_end = now
            elif ok_after is None and last_busy_end:
                ok_after = now
            time.sleep(0.25)
        dt.check(last_busy_end <= bound + 1.5,
                 f"readers were refused until {last_busy_end:.1f} s after the owner died "
                 f"(bound {bound} + 1.5): {refused[:6]}")
        r = bl.timed(c, N, "info", wait=1500)
        dt.check(r["ok"], f"a reader is still refused {time.perf_counter() - t:.1f} s after the "
                 f"owner died, while the read runs: {r}")
        pg = program(N, exe)
        dt.check(pg is not None and pg["owner"] is not None,
                 "the leave finished although the reader still holds the lock")
        # the leave is finished when the read ends, without anybody waiting for it
        dt.check(attempt(c, O, read)[0] == "ok", "the long read did not end ok")
        dt.wait_for(lambda: (program(N, exe) or {}).get("owner") is None,
                    "the dead owner's pending leave to finish", 20, 0.3)
        c.timings["owner_leave_bounded: last refusal (s)"] = round(last_busy_end, 1)
        return (f"owner killed during a {read_ms // 1000} s read: readers refused for "
                f"{last_busy_end:.1f} s (bound {bound}), served from then on; the leave finished "
                f"when the read ended")
    finally:
        close_all(H, O, N)
        d.stop(force=True)


# ---- lock_queue_full ------------------------------------------------------------------------

def t_lock_queue_full(c):
    """The holder holds until the test cancels it (no fixed run time), the third waiter is sent
    once the daemon counts both earlier waits on the program lock (``lockWaiters``), and "at once"
    is the daemon's own ``waitedMs: 0``, not a wall-clock bound. The waiters read with
    ``functions`` (a shared program read that queues behind the exclusive holder like any other):
    the native decompiler is not what this test is about (E9 owns its failures)."""
    exe = prepare(c)
    gpr = c.copy_fixture("e3bQf")
    d = c.daemon("e3b-qf", maxQuick=4)       # max(2, 4 / 4) = 2 waiters
    H = M = None
    rs = []
    try:
        H = owner(c, d, gpr, exe)
        rs = [reader(c, d, gpr, exe, f"w{i}") for i in range(5)]
        M = c.connect(d, "M", "e3b", 3)       # reads the daemon's wait counters, joins nothing
        hold = script(c, H, 3600000)
        dt.wait_for(lambda: holds(rs[0], exe), "the holder's script to hold the program", 120)

        def queued():
            pg = program(M, exe)
            return pg.get("lockWaiters") if pg else None
        dt.check(queued() == 0, f"lockWaiters before the waiters: {program(M, exe)}")
        waiting = [rs[i].send("functions", limit=1, wait=3600000, parallel=True) for i in range(2)]
        dt.wait_for(lambda: queued() == 2, "both waiters to queue behind the holder", 120)
        t = time.perf_counter()
        try:
            rs[2].call("functions", limit=1, wait=3600000)
            raise dt.Fail("the third waiter waited instead of being refused")
        except c.gs.SessionError as e:
            ms = (time.perf_counter() - t) * 1000
            dt.check(e.code == "busy" and (e.details or {}).get("reason") == "lock_queue_full",
                     f"third waiter: {e.code} {e.details}")
            dt.check((e.details or {}).get("waitedMs") == 0, f"it waited before the refusal: {e.details}")
            err = rs[2].last_response["error"]
            dt.check(err.get("retryAfterMs") == 1000, f"retryAfterMs: {err.get('retryAfterMs')}")
            dt.check((e.details or {}).get("waitersMax") == 2, f"details: {e.details}")
        # a request on another lock of the same connection is not affected
        dt.check(bl.timed(c, rs[2], "projects")["ok"], "an unrelated request was refused")
        dt.check(holds(rs[0], exe), "the holder ended before the cancel: the scenario did not hold")
        # the first two keep waiting and are served when the holder ends
        finish(H, hold)
        out = [attempt(c, rs[i], waiting[i])[0] for i in range(2)]
        dt.check(out == ["ok", "ok"], f"the two waiters ended with {out}")
        # when the lock is free the cap is not a limit on callers
        dt.check(all(bl.timed(c, s, "functions", limit=1)["ok"] for s in rs[2:]),
                 "readers were refused on a free lock")
        return "2 waiters wait, the 3rd gets busy{lock_queue_full} in %.0f ms with retryAfterMs 1000" % ms
    finally:
        close_all(H, M, *rs)
        d.stop(force=True)


# ---- v2_program_shape -----------------------------------------------------------------------

#: the keys of a ``status.programs[]`` entry and of a ``list`` entry's ``open`` on hydra.3, in order:
#: what a protocol 2 connection must see (the protocol-2 characterization goldens, gate 9.8)
V2_PROGRAM_KEYS = ["project", "path", "mode", "owner", "idleMs", "users", "ownerLabel", "busy",
                   "writers", "journalSeq", "unsavedEdits", "orphanedMs", "revision",
                   "cachedUpgrade", "cacheBuild"]


def t_v2_program_shape(c):
    """A protocol 2 connection gets hydra.3's ``status.programs[]`` and ``list`` ``open`` keys,
    exactly and in order; the protocol 3 figures (``lockWaiters``, ``abandonedRequests``, ...)
    are on a protocol 3 connection's ``status`` only."""
    exe = prepare(c)
    gpr = c.copy_fixture("e3bShape")
    d = c.daemon("e3b-shape")
    P = Q = None
    try:
        P = reader(c, d, gpr, exe, "p2", protocol=2)
        Q = reader(c, d, gpr, exe, "p3", protocol=3)
        dt.check(P.hello.get("protocol", 2) == 2 and Q.hello.get("protocol") == 3,
                 f"protocols: {P.hello.get('protocol')} / {Q.hello.get('protocol')}")
        v2 = program(P, exe)
        dt.check(v2 is not None and list(v2) == V2_PROGRAM_KEYS,
                 f"a protocol 2 status.programs[] is not hydra.3's: {list(v2 or {})}")
        opened = [e["open"] for e in P.call("list", programsOnly=True, metadata=False)["entries"]
                  if e["path"] == "/" + exe]
        dt.check(len(opened) == 1 and list(opened[0]) == V2_PROGRAM_KEYS,
                 f"a protocol 2 list entry's open is not hydra.3's: {[list(o or {}) for o in opened]}")
        v3 = program(Q, exe)
        dt.check(v3 is not None and v3.get("lockWaiters") == 0
                 and list(v3)[:len(V2_PROGRAM_KEYS)] == V2_PROGRAM_KEYS,
                 f"a protocol 3 status.programs[]: {v3}")
        extra = [k for k in v3 if k not in V2_PROGRAM_KEYS]
        return f"protocol 2: hydra.3's {len(V2_PROGRAM_KEYS)} keys; protocol 3 adds {extra}"
    finally:
        close_all(P, Q)
        d.stop(force=True)


# ---- applied_flag ---------------------------------------------------------------------------

RENAMER = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
public class E3bRenamer extends GhidraScript {
    @Override protected void run() throws Exception {
        // args: [hold ms, the name to give]; every run must really change the program, so a
        // second run with another name is a change too (a rename to the same name is a no-op)
        Function f = currentProgram.getFunctionManager().getFunctions(true).next();
        f.setName(getScriptArgs()[1], SourceType.USER_DEFINED);
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
    }
}
"""


def t_applied_flag(c):
    exe = prepare(c)
    (c.scripts / "E3bRenamer.java").write_text(RENAMER)
    gpr = c.copy_fixture("e3bAp")
    d = c.daemon("e3b-ap", maxQuick=2)
    H = X = None
    try:
        H = owner(c, d, gpr, exe)
        H.call("script", script=c.script("E3bRenamer.java"), args=["10", "e3b_warm"], wait=120000)
        X = reader(c, d, gpr, exe, "x")
        fn = bl.first_function(H)
        seen = {}
        hold = script(c, H, 60000)
        dt.wait_for(lambda: holds(X, exe), "the holder's script to hold the program", 30)
        # rename, comment, save of a client that is not the owner wait for the lock (they take it
        # before the ownership check): cancelled in the lock wait, nothing applied
        for cmd, fields in (("rename", {"address": fn, "name": "e3b_applied"}),
                            ("comment", {"address": fn, "type": "eol", "text": "e3b"}),
                            ("save", {})):
            rid = X.send(cmd, wait=60000, parallel=True, **fields)
            time.sleep(0.6)
            X.call("cancel", target=rid)
            code, det, _ = attempt(c, X, rid)
            dt.check(code == "cancelled", f"{cmd}: {code}")
            dt.check(det.get("applied") is False and det.get("phase") == "lock_wait",
                     f"{cmd}: details {det}")
            seen[cmd] = det
        rid = X.send("decompile", address=fn, wait=60000, parallel=True)
        time.sleep(0.6)
        X.call("cancel", target=rid)
        code, det, _ = attempt(c, X, rid)
        dt.check(code == "cancelled" and "applied" not in det,
                 f"decompile has no applied key (not guessed): {code} {det}")
        finish(H, hold)
        # a rename queued for a slot: nothing applied either
        occ = [H.send("script", script=c.script("TestSleep.java"), program=None, args=["60000"],
                      lane="quick", timeout=60, parallel=True, wait=120000) for _ in range(2)]
        dt.wait_for(lambda: H.call("status")["scheduler"]["quick"]["inUse"] >= 2,
                    "both quick slots to be taken", 30)
        rid = H.send("rename", address=fn, name="e3b_queued", wait=60000, parallel=True)
        time.sleep(0.6)
        H.call("cancel", target=rid)
        code, det, _ = attempt(c, H, rid)
        dt.check(code == "cancelled" and det.get("applied") is False and det.get("phase") == "queued",
                 f"rename queued for a slot: {code} {det}")
        finish(H, *occ)
        # an owner script: applied is the script's `changed`
        for n, (name, args) in enumerate((("TestSleep.java", ["60000"]),
                                          ("E3bRenamer.java", ["60000", "e3b_owner_a"]),
                                          ("E3bRenamer.java", ["60000", "e3b_owner_b"]))):
            rid = H.send("script", script=c.script(name), args=args, parallel=True, wait=120000)
            time.sleep(2.5)
            H.call("cancel", target=rid)
            code, det, _ = attempt(c, H, rid)
            dt.check(code == "cancelled" and det.get("mode") == "owner",
                     f"{name}: {code} {det}")
            dt.check(isinstance(det.get("applied"), bool) and det["applied"] == det.get("changed"),
                     f"{name}: applied {det.get('applied')} must be the script's changed "
                     f"{det.get('changed')}")
            seen[n] = (det["applied"], det.get("changed"))
        dt.check(seen[0][0] is False, f"a script that changes nothing: applied {seen[0]}")
        dt.check(seen[1][0] is True and seen[2][0] is True,
                 f"a script that renames a function must report applied true each run: {seen}")
        return f"applied false for rename/comment/save in a lock wait and a slot wait, absent for decompile; owner scripts (applied, changed): no-op {seen[0]}, renamers {seen[1]} / {seen[2]}"
    finally:
        close_all(H, X)
        d.stop(force=True)


# ---- stalled_socket -------------------------------------------------------------------------

def t_stalled_socket(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bSs")
    d = c.daemon("e3b-ss", engine={"writeStallMs": 3000})
    S = O = None
    hold_ms = 6000
    try:
        S = owner(c, d, gpr, exe, "stalled", scripts=("E3bBig.java", "E3bProgress.java"))
        O = reader(c, d, gpr, exe, "observer")
        # a 16 MB reply that the client never reads fills the socket buffers
        S.send("script", script=c.script("E3bBig.java"), program=None, args=["16100"],
               maxChars=16000000, parallel=True, wait=120000)
        dt.wait_for(lambda: not any(cl["name"] == "stalled" and cl["requests"]
                                    for cl in O.call("status")["clients"]),
                    "the big script to end", 60, 0.2)
        # a request that holds the program and reports progress to the client that does not read
        S.send("script", script=c.script("E3bProgress.java"), args=[str(hold_ms)], parallel=True,
               wait=120000)
        dt.wait_for(lambda: holds(O, exe), "the progress script to hold the program", 30)
        t = time.perf_counter()
        freed = None
        while time.perf_counter() - t < hold_ms / 1000 + 12:
            if not holds(O, exe):
                freed = time.perf_counter() - t
                break
            time.sleep(0.1)
        dt.check(freed is not None, "the lock of a request that reports progress to a client that "
                 "does not read is still held (the event write blocks the request thread)")
        # the lock is let go when the script ends or when the unread client is dropped (writeStallMs
        # 3 s after its write stopped), whichever is first; the margin is for a loaded machine
        dt.check(freed <= hold_ms / 1000 + 7, f"the script held the lock {freed:.1f} s, it runs "
                 f"{hold_ms / 1000:.0f} s")
        gone = None
        while time.perf_counter() - t < hold_ms / 1000 + 20:
            if "stalled" not in bl.client_names(O):
                gone = time.perf_counter() - t
                break
            time.sleep(0.2)
        dt.check(gone is not None, "the client that does not read is still connected")
        r = bl.timed(c, O, "decompile", address=bl.first_function(O), wait=3000)
        dt.check(r["ok"], f"the observer cannot read after the stalled client was dropped: {r}")
        return (f"the lock was free {freed:.1f} s after the script started ({hold_ms / 1000:.0f} s "
                f"run) although its client never read; the client was disconnected after {gone:.1f} s")
    finally:
        close_all(S, O)
        d.stop(force=True)


# ---- parallel_reads -------------------------------------------------------------------------

def t_parallel_reads(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bPr")
    d = c.daemon("e3b-pr")
    X = None
    try:
        X = owner(c, d, gpr, exe)
        # the long request: a script without a program (no lock), 4 s, on the connection's own lane
        rid = X.send("script", script=c.script("TestSleep.java"), program=None, args=["4000"])
        time.sleep(0.5)
        t = time.perf_counter()
        X.call("info")
        free_ms = (time.perf_counter() - t) * 1000
        t = time.perf_counter()
        X.call("info", ordered=True)
        ordered_ms = (time.perf_counter() - t) * 1000
        X.wait(rid)
        dt.check(free_ms < 1000, f"a read-class command waited {free_ms:.0f} ms behind a 4 s script")
        dt.check(ordered_ms > 2000, f"ordered:true did not keep the connection's order "
                 f"({ordered_ms:.0f} ms)")
        return f"info beside a 4 s script took {free_ms:.0f} ms; with ordered:true {ordered_ms:.0f} ms"
    finally:
        close_all(X)
        d.stop(force=True)


# ---- scope_order ----------------------------------------------------------------------------

def t_scope_order(c):
    """``orderPerScope`` (PROTOCOL-3.md 8.18). One protocol 3 connection, two labels: ``a`` sends a 4 s
    script and then a short one, ``b`` a short one. With the setting, ``b`` runs beside ``a``'s long
    script and ``a``'s short script still starts only after its long one ended (the order of a label is
    kept; the default since Hydra daemon-async); with ``orderPerScope=false`` ``b`` waits behind ``a`` on
    the connection's one ordered lane."""
    prepare(c)
    notes = []
    for on in (False, True):
        d = c.daemon(f"e3b-so{int(on)}", engine={"orderPerScope": on})
        X = None
        try:
            X = c.connect(d, "multi", "e3b", 3)
            warm(c, X)
            # ordered labelled views (the library's labelled() sends parallel:true, which has no order)
            a = c.gs.Labelled(X, "agent-a", "e3b", parallel=False)
            b = c.gs.Labelled(X, "agent-b", "e3b", parallel=False)
            sleep = c.script("TestSleep.java")
            a1 = a.send("script", script=sleep, program=None, args=["4000"], wait=120000)
            a2 = a.send("script", script=sleep, program=None, args=["10"], wait=120000)
            time.sleep(0.5)
            t = time.perf_counter()
            b.call("script", script=sleep, program=None, args=["10"], wait=120000)
            b_ms = (time.perf_counter() - t) * 1000
            _, e1 = times(a.wait(a1)["output"])
            s2, _ = times(a.wait(a2)["output"])
            dt.check(e1 is not None and s2 is not None and s2 + 5 >= e1,
                     f"orderPerScope={on}: a label's second request started at {s2}, before its first "
                     f"ended at {e1}")
            if on:
                dt.check(b_ms < 2000, f"with orderPerScope another label waited {b_ms:.0f} ms behind a 4 s "
                         f"script")
            else:
                dt.check(b_ms > 2000, f"without orderPerScope the connection's order was not kept "
                         f"({b_ms:.0f} ms)")
            notes.append(f"{'on' if on else 'off'}: b {b_ms:.0f} ms")
        finally:
            close_all(X)
            d.stop(force=True)
    return "beside a 4 s script of another label, " + "; ".join(notes) + "; a label's order kept both ways"


# ---- registry_unnested ----------------------------------------------------------------------

def t_registry_unnested(c):
    exe = prepare(c)
    g1 = c.copy_fixture("e3bRg1")
    g2 = c.copy_fixture("e3bRg2")
    d = c.daemon("e3b-rg")
    S = Q = V = None
    try:
        S = c.connect(d, "reader", "e3b", 3)
        S.call("open_project", path=str(g1))
        S.call("open_program", path=exe)
        Q = c.connect(d, "upgrader", "e3b", 3)
        Q.call("open_project", path=str(g1))
        V = c.connect(d, "other", "e3b", 3)
        hold = S.send("script", script=c.script("TestSleep.java"), args=["9000"], parallel=True,
                      wait=60000)
        time.sleep(1.0)
        res = {}

        def up():
            res["r"] = bl.timed(c, Q, "open_project", path=str(g1), writable=True, wait=20000)
        th = threading.Thread(target=up, daemon=True)
        th.start()
        time.sleep(1.0)
        r = bl.timed(c, V, "open_project", path=str(g2))
        dt.check(r["ok"], f"the unrelated open_project failed: {r}")
        dt.check(r["ms"] < 2500,
                 f"open_project of an unrelated project took {r['ms']} ms while a writable open "
                 f"waited for its project lock (BP8: 9.4 s)")
        th.join(40)
        attempt(c, S, hold)
        dt.check(res.get("r", {}).get("ok"), f"the waiting writable open ended with {res.get('r')}")
        return f"unrelated open_project {r['ms']} ms while a writable open waited; that open succeeded in {res['r']['ms']} ms"
    finally:
        close_all(S, Q, V)
        d.stop(force=True)


# ---- waiter_caps ----------------------------------------------------------------------------

def t_waiter_caps(c):
    """BP9(a): without a cap, waiters for one program lock each keep a quick slot, and a client of
    another project gets ``busy`` for a slot. With ``maxQuick`` 8 and ``lockWaitersMin`` 2 (the least cap
    was 2 before PROTOCOL-3.md 8.18) the cap is 2: two waiters hold two slots, the other six are told
    ``busy{lock_queue_full}`` at once and keep none, and a client of another project is served
    immediately."""
    exe = prepare(c)
    g1 = c.copy_fixture("e3bWc1")
    g2 = c.copy_fixture("e3bWc2")
    d = c.daemon("e3b-wc", maxQuick=8, engine={"lockWaitersMin": 2})
    H = V = None
    rs = []
    try:
        H = owner(c, d, g1, exe)
        V = owner(c, d, g2, exe, "victim")
        rs = [reader(c, d, g1, exe, f"w{i}") for i in range(8)]
        fn = bl.first_function(H)
        hold = script(c, H, 25000)
        dt.wait_for(lambda: holds(rs[0], exe), "the holder's script to hold the program", 30)
        ids = [r.send("decompile", address=fn, wait=30000, parallel=True) for r in rs]
        time.sleep(2.0)
        st = V.call("status")["scheduler"]["quick"]
        refused = 0
        for r, i in zip(rs, ids):
            if r.call("ping") and i in r._pending:      # an answer already arrived
                refused += 1
        victim = [bl.timed(c, V, "functions", limit=1, wait=1500) for _ in range(3)]
        dt.check(all(v["ok"] for v in victim),
                 f"a client of another project was refused while waiters wait: {victim}")
        dt.check(st["inUse"] <= 2, f"{st['inUse']} of {st['slots']} quick slots are held by waiters "
                 f"(cap 2)")
        dt.check(refused >= 6, f"{refused} of 8 waiters were refused at once, expected 6")
        finish(H, hold)
        out = [attempt(c, r, i)[1].get("reason") or "ok" for r, i in zip(rs, ids)]
        dt.check(out.count("lock_queue_full") == 6 and out.count("ok") == 2, f"outcomes {out}")
        return (f"8 waiters: 2 wait ({st['inUse']} of {st['slots']} quick slots in use), 6 told "
                f"lock_queue_full at once; the client of another project was served "
                f"({max(v['ms'] for v in victim)} ms at most)")
    finally:
        close_all(H, V, *rs)
        d.stop(force=True)


# ---- orphan_ttl -----------------------------------------------------------------------------

def t_orphan_ttl(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e3bOt")
    d = c.daemon("e3b-ot", engine={"orphanKeepS": 3})
    A = R = None
    try:
        A = owner(c, d, gpr, exe, "writer", share=True)
        R = reader(c, d, gpr, exe, "reader")
        fn = bl.first_function(A)
        A.call("comment", address=fn, type="eol", text="ORPHAN EDIT")
        A.close()
        dt.wait_for(lambda: (program(R, exe) or {}).get("orphanedMs") is not None,
                    "the work of the dead writer to be orphaned", 20)
        rec = pathlib.Path(c.state) / "recovery"
        dt.wait_for(lambda: list(rec.glob("*.journal.json")), "the orphan journal to be written", 40, 0.5)
        f = list(rec.glob("*.journal.json"))[0]
        data = json.loads(f.read_text(encoding="utf-8"))
        dt.check("ORPHAN EDIT" in json.dumps(data["entries"]), f"the journal lacks the edit: {data}")
        dt.check(data.get("sha256") and data.get("revision") is not None, f"identity: {list(data)}")
        dt.wait_for(lambda: (program(R, exe) or {}).get("mode") == "read_only",
                    "the program to be reopened read-only for its reader", 20, 0.3)
        pg = program(R, exe)
        dt.check(not pg["unsavedEdits"] and pg["orphanedMs"] is None,
                 f"after the expiry the program is {pg}")
        dt.check(bl.timed(c, R, "info", wait=2000)["ok"], "the reader cannot read the program")
        return f"the dead writer's edit was written to {f.name} and discarded after orphanKeepS 3"
    finally:
        close_all(A, R)
        d.stop(force=True)


# ---- shared_stress_v3 -----------------------------------------------------------------------

def t_shared_stress_v3(c):
    """The protocol 3 half of ``shared_stress`` (which runs on protocol 2 since E3b: eight writers
    waiting for one program lock are more than the waiter cap max(2, slots/4) allows). Eight
    writers on four protocol 3 connections write one shared program; a writer that is told
    ``busy{lock_queue_full}`` waits and asks again, as a client does. Every edit is
    applied once and the journal has each once, in commit order (refusals are counted in the note,
    not asserted: how many there are depends on timing)."""
    exe = prepare(c)
    gpr = c.copy_fixture("e3bStress")
    # the slots are pinned so the waiter cap, max(2, slots/4) = 6, and so the refusals are the same on any CPU count
    d = c.daemon("e3b-stress", keepWarm=0, maxQuick=24, maxLong=24)
    sessions = []
    try:
        sessions = [c.connect(d, f"agent-{i}", f"harness-{i}", 3) for i in range(4)]
        for s in sessions:
            s.call("open_project", path=str(gpr), writable=True)
            s.call("open_program", path=exe, writable=True, share=True)
        fns = dt.code_functions(sessions[0], 20)
        done, errs, refused = [], [], []
        lock = threading.Lock()
        per = 60

        def edit(s, cmd, **kw):
            end = time.time() + 240
            while True:
                try:
                    return s.call(cmd, parallel=True, wait=60000, **kw)
                except c.gs.SessionError as e:
                    d3 = e.details or {}
                    if (e.code != "busy" or d3.get("reason") != "lock_queue_full" or
                            time.time() > end):
                        raise
                    with lock:
                        refused.append(d3.get("waitersMax"))
                    time.sleep(0.25)  # retryAfterMs is 1000; a quarter keeps the test short

        def worker(s, cid, t):
            try:
                for i in range(per):
                    a = fns[(cid * 7 + t * 13 + i) % len(fns)]
                    if i % 2 == 0:
                        r = edit(s, "rename", address=a, name=f"v{cid}_{t}_{i}")
                    else:
                        r = edit(s, "comment", address=a, text=f"c{cid}_{t}_{i}")
                    with lock:
                        done.append(r["seq"])
            except Exception as ex:  # noqa: BLE001
                errs.append(f"{cid}/{t}: {ex!r}")

        ths = [threading.Thread(target=worker, args=(s, cid, t))
               for cid, s in enumerate(sessions) for t in range(2)]
        for th in ths:
            th.start()
        for th in ths:
            th.join(timeout=600)
        dt.check(not any(th.is_alive() for th in ths), "a writer hung (deadlock?)")
        dt.check(not errs, f"edits failed: {errs[:5]}")
        dt.check(len(done) == 8 * per, f"{len(done)} edits done of {8 * per}")
        j = sessions[0].call("journal", limit=100000)
        seqs = [e["seq"] for e in j["entries"]]
        dt.check(len(seqs) == 8 * per and len(set(seqs)) == 8 * per and seqs == sorted(seqs) and
                 set(done) == set(seqs), f"journal: {len(seqs)} entries for {len(done)} edits")
        return f"{8 * per} edits by 8 writers on protocol 3, journal exact, {len(refused)} refusals retried"
    finally:
        close_all(*sessions)
        d.stop(force=True)


TESTS = {
    "cancel_queued": t_cancel_queued,
    "cancel_while_waiting": t_cancel_while_waiting,
    "deadline_in_lock_wait": t_deadline_in_lock_wait,
    "writer_vs_steady_readers": t_writer_vs_steady_readers,
    "dead_client_released": t_dead_client_released,
    "dead_write_not_applied": t_dead_write_not_applied,
    "abandoned_holder": t_abandoned_holder,
    "owner_leave_bounded": t_owner_leave_bounded,
    "lock_queue_full": t_lock_queue_full,
    "v2_program_shape": t_v2_program_shape,
    "applied_flag": t_applied_flag,
    "stalled_socket": t_stalled_socket,
    "parallel_reads": t_parallel_reads,
    "scope_order": t_scope_order,
    "registry_unnested": t_registry_unnested,
    "orphan_ttl": t_orphan_ttl,
    "waiter_caps": t_waiter_caps,
    "shared_stress_v3": t_shared_stress_v3,
}

BASELINE = {}

#: the shards run_parallel.py runs at once: cancel_while_waiting as its two protocol halves, each with
#: its 200 races split over CW_SHARDS processes (same race numbers, part (a) in every shard), and
#: writer_vs_steady_readers as its two protocol halves.
SHARDS = {
    "cancel_while_waiting": {f"p{p}r{first}": _cw_shard(p, first, cnt)
                             for p in (3, 2) for first, cnt in dt.split_n(CW_RACES, CW_SHARDS)},
    "writer_vs_steady_readers": {"p3": lambda c: _steady(c, 3), "p2": lambda c: _steady(c, 2)},
}
