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
"""Expected-fail baseline of the protocol 3 design (PROTOCOL-3.md, section 8, package E0).

Six tests, each written against the behaviour the design wants and each expected to **fail on
hydra.3 for the reason stated in its premise**. They are not part of the default run of
``daemon_tests.py`` (that run would be red by design); ``--baseline`` runs them and checks, per test,
that the failure carries the premise's signature:

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --baseline

A test that does not fail on its premise is a finding and is dropped from the design, never weakened
(``REFUTED`` in the report). The signature is what makes a failure "as premised": every test raises
``PremiseFail`` only when the wanted behaviour is absent *and* the observation shows the cause the
design names (``busy`` naming the long lane, a dead client still registered, a reader that saw an
uncommitted write, ...); any other way of failing is a plain ``Fail`` (``OTHER``).

The tests ask for protocol 3 in ``hello`` (hydra.3 answers 2) and send the v3 request fields the
later packages will honour (``lane``, ``isolation``); an engine that ignores them behaves as hydra.3.
Every test bounds its waits (the worst case is about 70 s), cancels what it started, and leaves no
daemon behind. After the package that fixes a premise lands, the same test is run by name
(``--only lane_starvation``), where it must pass.

Where a premise names a long analysis (a four-hour analysis in the design) the tests use a
``TestSleep.java`` script that polls its cancel flag: the same occupant of a long slot, with a known
length and an exit that is certain. The fixture is whatever ``--exe`` is (a small PE is enough).
"""
import contextlib
import pathlib
import threading
import time

import daemon_tests as dt

SLEEP = 8000          # ms: how long the long-lane occupiers of lane_starvation run
QUICK_BOUND_MS = 3000  # a quick script must start and finish within this, long lane or not
TRANSIENT_NAME = "baseline_transient"
# import_wait signature, all in ms. The slowest import waited 10 s for the import gate and then the
# default 10 s for the scheduler: it fails 20 s in, so inside [LAST_MIN, LAST_MAX]. The imports
# admitted at once fail 10 s in, so the slowest one ends 10 s (SPREAD_MIN..SPREAD_MAX) after the
# fastest. A failure at 24 s, or all failures at the same instant, is a different behaviour.
DEFAULT_WAIT_MS = 10000   # the default ``wait`` of a request, which the premise is about
SLOWEST_IMPORT_MIN_MS = 19000
SLOWEST_IMPORT_MAX_MS = 23000
SPREAD_MIN_MS = 8000
SPREAD_MAX_MS = 12000

QUICK = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class BaselineQuick extends GhidraScript {
    @Override protected void run() throws Exception {
        monitor.checkCancelled();
        println("functions " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
"""
TRANSIENT = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
public class BaselineTransient extends GhidraScript {
    @Override protected void run() throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctions(true).next();
        f.setName("baseline_transient", SourceType.USER_DEFINED);
        println("renamed " + f.getEntryPoint() + " " + System.currentTimeMillis());
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("done " + System.currentTimeMillis());
    }
}
"""


# ---- helpers --------------------------------------------------------------------------------

def prepare(c):
    (c.scripts / "BaselineQuick.java").write_text(QUICK)
    (c.scripts / "BaselineTransient.java").write_text(TRANSIENT)
    return pathlib.Path(c.a.exe).name


def timed(c, s, cmd, **f):
    """One request, ending whichever way: {"ok", "ms", "code", "message", "details", "result"}."""
    t = time.perf_counter()
    try:
        r = s.call(cmd, **f)
        return {"ok": True, "ms": round((time.perf_counter() - t) * 1000), "result": r}
    except c.gs.SessionError as e:
        return {"ok": False, "ms": round((time.perf_counter() - t) * 1000), "code": e.code,
                "message": e.message, "details": e.details}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ms": round((time.perf_counter() - t) * 1000),
                "code": type(e).__name__, "message": str(e), "details": {}}


def in_parallel(c, calls, join_s):
    """Runs ``(session, cmd, fields)`` requests at once, one thread each; their ``timed``
    outcomes, in order. Raises Fail if one does not end within ``join_s``."""
    out = [None] * len(calls)

    def run(i, s, cmd, f):
        out[i] = timed(c, s, cmd, **f)

    ths = [threading.Thread(target=run, args=(i, s, cmd, f), daemon=True)
           for i, (s, cmd, f) in enumerate(calls)]
    for th in ths:
        th.start()
    end = time.time() + join_s
    for th in ths:
        th.join(max(0.0, end - time.time()))
    if any(o is None for o in out):
        raise dt.Fail(f"{sum(o is None for o in out)} of {len(out)} requests did not end "
                      f"within {join_s} s")
    return out


def occupy_long(c, s, n, ms):
    """Starts ``n`` sleep scripts (no program: no lock) from ``s``, which take every long slot of a
    daemon with ``maxLong=n``; waits until the long lane shows them running. Returns their ids."""
    ids = [s.send("script", script=c.script("TestSleep.java"), program=None, args=[str(ms)],
                  parallel=True, wait=ms + 120000) for _ in range(n)]
    dt.wait_for(lambda: s.call("status")["scheduler"]["long"]["inUse"] >= n,
                "the long lane to be full", 60)
    return ids


def release_long(c, s, ids):
    """Cancels the occupiers and collects them (their answers are not the test's business)."""
    try:
        s.call("cancel", all=True)
    except Exception:  # noqa: BLE001
        pass
    for i in ids:
        try:
            s.wait(i)
        except Exception:  # noqa: BLE001
            pass


def busy_long(o):
    return (not o["ok"] and o["code"] == "busy" and
            (o.get("details") or {}).get("lane") == "long")


def first_function(s):
    return s.call("functions", limit=1)["functions"][0]["address"]


def client_names(s):
    return [cl["name"] for cl in s.call("status")["clients"]]


# ---- the six tests --------------------------------------------------------------------------

def t_lane_starvation(c):
    """Premise (Scheduler.java:61, laneOf): every ``script`` is in the long lane, so with the long
    lane taken ten short RusticQuery-style scripts (``lane:"quick"`` and a ``timeout``, the v3
    hint) wait behind the long ones. Wanted: each starts and ends within QUICK_BOUND_MS."""
    exe = prepare(c)
    gpr = c.copy_fixture("blLane")
    d = c.daemon("bl-lane", maxLong=2)
    with c.connect(d, "occupier", "baseline", 3) as S, \
            c.connect(d, "rusticquery", "baseline", 3) as Q:
        Q.call("open_project", path=str(gpr))
        Q.call("open_program", path=exe)
        Q.call("script", script=c.script("BaselineQuick.java"), lane="quick", timeout=30)  # warm
        ids = occupy_long(c, S, 2, SLEEP)
        try:
            calls = [(Q, "script", {"script": c.script("BaselineQuick.java"), "lane": "quick",
                                    "timeout": 30, "wait": 30000, "parallel": True})] * 10
            snap = {}

            def look():
                time.sleep(0.7)
                snap.update(S.call("status")["scheduler"]["long"])

            th = threading.Thread(target=look, daemon=True)
            th.start()
            res = in_parallel(c, calls, 60)
            th.join(5)
        finally:
            release_long(c, S, ids)
        lat = sorted(r["ms"] for r in res)
        ok = sum(r["ok"] for r in res)
        queued_cmds = sorted({w.get("cmd") for w in snap.get("waiting", [])})
        ev = {"protocol": Q.hello.get("protocol"), "ok": ok, "latencyMs": lat,
              "boundMs": QUICK_BOUND_MS, "sleepMs": SLEEP,
              "longLane": {k: snap.get(k) for k in ("slots", "inUse", "queued")},
              "queuedCmds": queued_cmds,
              "failures": [(r["code"], (r.get("details") or {}).get("lane")) for r in res
                           if not r["ok"]]}
        c.timings["lane_starvation: ten quick scripts under a full long lane (ms)"] = lat
        if ok == 10 and lat[-1] < QUICK_BOUND_MS:
            d.stop(force=True)
            return f"ten quick scripts took {lat[0]}..{lat[-1]} ms with the long lane full"
        signature = (all((r["ok"] and r["ms"] >= SLEEP // 2) or busy_long(r) for r in res) and
                     snap.get("queued", 0) >= 1 and "script" in queued_cmds)
        what = (f"{ok}/10 quick scripts ok, latency {lat[0]}..{lat[-1]} ms (bound "
                f"{QUICK_BOUND_MS}); long lane {ev['longLane']}, waiting: {queued_cmds}")
        raise (dt.PremiseFail(what + ": they queued behind the long scripts", ev) if signature
               else dt.Fail(what))


def t_dead_client_lock_wait(c):
    """Premise (Connection.java:101): a client killed while blocked in a program lock wait
    (``wait`` 3600000) stays registered until the lock frees, because the disconnect waits for its
    blocked request thread (``awaitTermination(1, HOURS)``). Wanted: it is gone within
    DEAD_S seconds, the holder still holding."""
    dead_s = 40
    exe = prepare(c)
    gpr = c.copy_fixture("blDead")
    go = c.work / "blDead.go"
    go.unlink(missing_ok=True)
    d = c.daemon("bl-dead")
    with c.connect(d, "holder", "baseline", 3) as H, c.connect(d, "observer", "baseline", 3) as O:
        H.call("open_project", path=str(gpr), writable=True)
        H.call("open_program", path=exe, writable=True)
        fn = first_function(H)
        code = ("import os\n"
                "s = gs.connect(client='doomed', harness='baseline', state=A[0], instance=A[1],"
                " ghidra=A[2])\n"
                "s.call('open_project', path=A[3])\n"
                "s.call('open_program', path=A[4])\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "while not os.path.exists(A[5]):\n"
                "    time.sleep(0.05)\n"
                "s.send('decompile', address=A[6], wait=3600000)\n"
                "print('sent', flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, "bl-dead", c.a.ghidra, gpr, exe, go, fn)
        line = p.stdout.readline()
        dt.check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        hold = H.send("script", script=c.script("TestSleep.java"), args=["180000"], parallel=True,
                      wait=60000)
        try:
            dt.wait_for(lambda: [pg for pg in O.call("status")["programs"]
                                 if pg["path"] == "/" + exe and pg["busy"]],
                        "the holder's script to hold the program", 30)
            go.write_text("go")
            assert p.stdout.readline().strip() == "sent"

            def doomed_waits():
                for cl in O.call("status")["clients"]:
                    if cl["name"] == "doomed" and cl["requests"]:
                        return cl["requests"]
                return None

            reqs = dt.wait_for(doomed_waits, "the doomed client's request to be running", 30)
            time.sleep(1.0)
            p.kill()
            p.wait()
            t_kill = time.perf_counter()
            gone_in = None
            while time.perf_counter() - t_kill < dead_s:
                if "doomed" not in client_names(O):
                    gone_in = time.perf_counter() - t_kill
                    break
                time.sleep(0.5)
            held = [pg for pg in O.call("status")["programs"]
                    if pg["path"] == "/" + exe and pg["busy"]]
            ev = {"protocol": H.hello.get("protocol"), "blockedRequest": reqs[0].get("cmd"),
                  "boundS": dead_s, "goneAfterS": gone_in, "lockStillHeld": bool(held)}
            if gone_in is not None:
                note = f"the dead client was released {gone_in:.1f} s after its kill, lock held"
                H.call("cancel", target=hold)
                with contextlib.suppress(c.gs.SessionError):
                    H.wait(hold)
                d.stop(force=True)
                return note
            # the premise's second half: it goes as soon as the lock frees
            H.call("cancel", target=hold)
            t_free = time.perf_counter()
            try:
                H.wait(hold)
            except c.gs.SessionError:
                pass
            freed_in = None
            while time.perf_counter() - t_free < 30:
                if "doomed" not in client_names(O):
                    freed_in = time.perf_counter() - t_free
                    break
                time.sleep(0.25)
            ev["goneAfterLockFreeS"] = freed_in
            what = (f"the killed client was still registered {dead_s} s after its kill with "
                    f"the lock held ({ev['lockStillHeld']}); ")
            if freed_in is not None:
                raise dt.PremiseFail(what + f"gone {freed_in:.1f} s after the lock freed", ev)
            raise dt.Fail(what + "and 30 s after the lock freed too: not the stated cause")
        finally:
            go.write_text("go")
            if p.poll() is None:
                p.kill()
            try:
                H.call("cancel", all=True)
            except Exception:  # noqa: BLE001
                pass


def t_import_wait(c):
    """Premise (ImportCommands.java:112): an import queues for the import gate without a deadline
    but then asks the scheduler and the project lock for the default 10 s ``wait``; reaching the
    front with the long lane taken, it fails ``busy`` 10 s later. Wanted: with no ``wait`` an
    import waits for its turn however long it takes (all three succeed once the occupiers end)."""
    exe = prepare(c)
    # The occupiers hold the long lane until the test releases them: on the old engine the
    # imports fail busy at their default 10 s wait while it is held; on the new one they wait.
    # The release comes when the daemon shows all three imports still waiting (for the lane or
    # the gate) with the lane waits past that default by the daemon's own waitedMs, or when all
    # three have ended (old engine: busy), never after a fixed time of the test's.
    occupy_ms = 3600000
    d = c.daemon("bl-import", maxLong=2, maxImports=2)
    with c.connect(d, "occupier", "baseline", 3) as S, c.connect(d, "importer", "baseline", 3) as I:
        gpr = c.make_project(I, c.work / "projImportWait", "ImportWait")
        I.call("open_project", path=str(gpr), writable=True)
        ids = occupy_long(c, S, 2, occupy_ms)
        t0 = time.perf_counter()
        res = [None] * 3

        def run(i):
            res[i] = timed(c, I, "import", file=c.a.exe, name=f"iw{i + 1}", duplicate=True,
                           parallel=True)
        ths = [threading.Thread(target=run, args=(i,), daemon=True) for i in range(3)]
        try:
            for th in ths:
                th.start()

            def waiting():
                if all(r is not None for r in res):
                    return True
                st = S.call("status")
                lane = [w for w in st["scheduler"]["long"]["waiting"] if w.get("cmd") == "import"]
                gate = len(st["imports"].get("queue") or [])
                return (len(lane) + gate >= 3 and bool(lane) and
                        min(w["waitedMs"] for w in lane) > DEFAULT_WAIT_MS + 1000)
            dt.wait_for(waiting, "the three imports to wait behind the held long lane", 600, 0.1)
            waited_all = all(r is None for r in res)
        finally:
            release_long(c, S, ids)
        for th in ths:
            th.join(1200)
        if any(r is None for r in res):
            raise dt.Fail("an import did not end within 1200 s of the release")
        total = time.perf_counter() - t0
        ev = {"protocol": I.hello.get("protocol"), "occupiedS": occupy_ms / 1000,
              "importsMs": [r["ms"] for r in res], "codes": [r.get("code", "ok") for r in res],
              "lanes": [(r.get("details") or {}).get("lane") for r in res],
              "waitedMs": [(r.get("details") or {}).get("waitedMs") for r in res]}
        if all(r["ok"] for r in res) and waited_all:
            d.stop(force=True)
            return (f"three imports waited for the held long lane and succeeded once it was "
                    f"released ({ev['importsMs']} ms)")
        # Two observations are told apart. The weaker one: each failing import is busy on the long
        # lane after the 10 s default wait. The premise needs the stronger one: the import that
        # queued for the gate (admitted only when an earlier one left it, 10 s in) fails busy about
        # 10 s *after* that, so about 20 s in total (10 s gate wait + 10 s scheduler wait), and
        # about 10 s after the fastest one. The signature is bounded on both sides: the slowest
        # import ends within [SLOWEST_IMPORT_MIN_MS, SLOWEST_IMPORT_MAX_MS] and the spread between
        # the slowest and the fastest within [SPREAD_MIN_MS, SPREAD_MAX_MS]. Imports failing at
        # 10 s alone only show that they were admitted at once.
        ms = sorted(r["ms"] for r in res)
        spread = ms[-1] - ms[0]
        busy10 = all(r["ok"] or (busy_long(r) and r["details"].get("waitedMs") == 10000)
                     for r in res) and any(not r["ok"] for r in res)
        queued = (busy10 and SLOWEST_IMPORT_MIN_MS <= ms[-1] <= SLOWEST_IMPORT_MAX_MS
                  and SPREAD_MIN_MS <= spread <= SPREAD_MAX_MS)
        ev["observation"] = ("the slowest import failed busy ~10 s after the fastest, ~20 s in "
                             "(gate wait + scheduler wait)" if queued else
                             "failures busy at the 10 s default wait, but outside the bounded "
                             "signature of a queued import" if busy10 else
                             "no busy/long/10000 signature")
        ev["slowestImportMs"] = ms[-1]
        ev["earlierImportsMs"] = ms[:-1]
        ev["spreadMs"] = spread
        ev["slowestImportBoundsMs"] = [SLOWEST_IMPORT_MIN_MS, SLOWEST_IMPORT_MAX_MS]
        ev["spreadBoundsMs"] = [SPREAD_MIN_MS, SPREAD_MAX_MS]
        what = (f"imports ended {ev['codes']} after {ev['importsMs']} ms (occupiers hold the lane "
                f"{occupy_ms} ms; total {total:.1f} s)")
        if queued:
            raise dt.PremiseFail(what + f": the slowest import failed busy {ms[-1]} ms in, "
                                 f"{spread} ms after the fastest (10 s gate wait + the default "
                                 "10 s scheduler wait), not the wait of the queue", ev)
        if busy10:
            raise dt.Fail(what + f": busy at the 10 s default wait but not the signature: the "
                          f"premise needs the slowest import in {SLOWEST_IMPORT_MIN_MS}.."
                          f"{SLOWEST_IMPORT_MAX_MS} ms and {SPREAD_MIN_MS}..{SPREAD_MAX_MS} ms "
                          f"after the fastest; saw {ms[-1]} ms, spread {spread} ms")
        raise dt.Fail(what)


def t_script_shared_visibility(c):
    """Premise (PROTOCOL-3.md 3.6): a contained script that mutates runs on the shared Program, so a
    concurrent reader can observe its transient write before the rollback. Wanted (``isolation:
    "private"``, the v3 field): the reader never sees it. If the reader does not see it on hydra.3,
    the premise is refuted and the sentence is dropped from 3.6."""
    exe = prepare(c)
    gpr = c.copy_fixture("blShared")
    hold_ms = 5000
    d = c.daemon("bl-shared")
    with c.connect(d, "script-runner", "baseline", 3) as X, \
            c.connect(d, "reader", "baseline", 3) as Y:
        for s in (X, Y):
            s.call("open_project", path=str(gpr))
            s.call("open_program", path=exe)
        polls = []
        stop = threading.Event()

        def poll():
            while not stop.is_set():
                t = time.perf_counter()
                r = timed(c, Y, "functions", contains=TRANSIENT_NAME, limit=5)
                polls.append((t, time.perf_counter(), r))
                time.sleep(0.05)

        th = threading.Thread(target=poll, daemon=True)
        th.start()
        t_start = time.perf_counter()
        try:
            r = X.call("script", script=c.script("BaselineTransient.java"), args=[str(hold_ms)],
                       isolation="private", wait=60000)
        finally:
            t_done = time.perf_counter()
            stop.set()
            th.join(10)
        during = [p for p in polls if p[1] < t_done - 0.1]
        seen = [p for p in during if p[2]["ok"] and p[2]["result"]["functions"]]
        errors = [p[2] for p in during if not p[2]["ok"]]
        after = Y.call("functions", contains=TRANSIENT_NAME)["functions"]
        dt.check("renamed" in r["output"], f"the script did not run: {r}")
        dt.check(not after, f"the script's write survived its rollback: {after}")
        dt.check(not errors, f"the reader's requests failed: {errors[:2]}")
        dt.check(len(during) >= 10, f"the reader made only {len(during)} polls in "
                 f"{t_done - t_start:.1f} s (was it blocked?)")
        ev = {"protocol": X.hello.get("protocol"), "polls": len(during), "sawTransient": len(seen),
              "firstSeenAfterS": round(seen[0][0] - t_start, 2) if seen else None,
              "scriptMode": r.get("mode"), "replyHasIsolation": "isolation" in r,
              "maxPollMs": max(p[2]["ms"] for p in during)}
        if not seen:
            d.stop(force=True)
            return f"the reader saw no transient write in {len(during)} polls"
        raise dt.PremiseFail(
            f"the reader saw the script's uncommitted rename in {len(seen)} of {len(during)} polls "
            f"(first {ev['firstSeenAfterS']} s into a {hold_ms / 1000:.0f} s script; mode "
            f"{r.get('mode')!r}, no isolation key in the reply), and it was rolled back after", ev)


def t_fork_save_behind_analysis(c):
    """Premise (Scheduler.java:61): ``save`` and ``fork_project`` are long-lane commands, so with the
    long lane taken (by analyses, here by sleeping scripts) they wait and fail ``busy``; a commit
    must not queue behind a four-hour analysis. Wanted (the v3 ``maint`` lane): both start at once.

    The occupiers hold the long lane until the test cancels them, so a save that queued behind
    them could only end ``busy`` (its ``wait`` runs out): both answered ok means neither queued
    there, and on a v3 engine the scheduler's counters say so too (the maint lane admitted them
    and queued nothing). Their time is recorded, not judged against a wall-clock bound."""
    exe = prepare(c)
    gpr = c.copy_fixture("blMaint")
    forks = c.work / "blMaintForks"
    d = c.daemon("bl-maint", maxLong=2)
    with c.connect(d, "committer", "baseline", 3) as W,             c.connect(d, "analysis", "baseline", 3) as S:
        pid = W.call("open_project", path=str(gpr), writable=True)["id"]
        W.call("open_program", path=exe, writable=True)
        W.call("rename", address=first_function(W), name="baseline_commit_name")
        ids = occupy_long(c, S, 2, 3600000)
        try:
            before = S.call("status")["scheduler"]
            save = timed(c, W, "save", wait=5000)
            fork = timed(c, W, "fork_project", project=pid, path=str(forks / "f1"), mode="full",
                         wait=5000)
            after = S.call("status")["scheduler"]
        finally:
            release_long(c, S, ids)
        ev = {"protocol": W.hello.get("protocol"), "saveMs": save["ms"],
              "saveCode": save.get("code", "ok"), "forkMs": fork["ms"],
              "forkCode": fork.get("code", "ok"),
              "lanes": [(o.get("details") or {}).get("lane") for o in (save, fork)]}
        c.timings["fork/save while the long lane is full (ms)"] = [save["ms"], fork["ms"]]
        maint_b, maint_a = before.get("maint"), after.get("maint")
        not_queued = (after["long"]["admitted"] == before["long"]["admitted"] and
                      (maint_a is None or maint_a["everQueued"] == maint_b["everQueued"]))
        if save["ok"] and fork["ok"] and not_queued:
            d.stop(force=True)
            return f"save {save['ms']} ms and fork {fork['ms']} ms with the long lane full, not queued"
        what = (f"save ended {ev['saveCode']} after {save['ms']} ms and fork_project "
                f"{ev['forkCode']} after {fork['ms']} ms with the long lane full (scheduler "
                f"before {before.get('maint')}/{before['long'].get('admitted')}, after "
                f"{after.get('maint')}/{after['long'].get('admitted')})")
        raise (dt.PremiseFail(what + " (busy naming the long lane)", ev)
               if busy_long(save) and busy_long(fork) else dt.Fail(what))


def t_cancel_lock_wait(c):
    """Premise (ProgramEntry.java:195): a request waiting for a program lock is one timed
    ``tryLock(wait)`` that ``cancel`` cannot end: it keeps waiting and answers ``busy`` when its
    ``wait`` ends. Wanted (V5): it answers ``cancelled`` within 1.5 s of the cancel."""
    exe = prepare(c)
    gpr = c.copy_fixture("blCancel")
    wait_ms = 8000
    d = c.daemon("bl-cancel")
    with c.connect(d, "holder", "baseline", 3) as H, c.connect(d, "waiter", "baseline", 3) as R:
        H.call("open_project", path=str(gpr), writable=True)
        H.call("open_program", path=exe, writable=True)
        fn = first_function(H)
        R.call("open_project", path=str(gpr))
        R.call("open_program", path=exe)
        hold = H.send("script", script=c.script("TestSleep.java"), args=["60000"], parallel=True,
                      wait=60000)
        try:
            dt.wait_for(lambda: [pg for pg in R.call("status")["programs"]
                                 if pg["path"] == "/" + exe and pg["busy"]],
                        "the holder's script to hold the program", 30)
            t_send = time.perf_counter()
            rid = R.send("decompile", address=fn, wait=wait_ms, parallel=True)
            time.sleep(1.5)
            dt.check("decompile" in [r["cmd"] for cl in R.call("status")["clients"]
                                     for r in cl["requests"] if cl["name"] == "waiter"],
                     "the waiting request is not listed in status")
            t_cancel = time.perf_counter()
            ack = R.call("cancel", target=rid)
            out = {"ok": True}
            try:
                R.wait(rid)
            except c.gs.SessionError as e:
                out = {"ok": False, "code": e.code, "details": e.details}
            after_cancel = (time.perf_counter() - t_cancel) * 1000
            since_send = (time.perf_counter() - t_send) * 1000
        finally:
            try:
                H.call("cancel", all=True)
                H.wait(hold)
            except Exception:  # noqa: BLE001
                pass
        ev = {"protocol": R.hello.get("protocol"), "waitMs": wait_ms, "cancelAck": ack,
              "answer": out.get("code", "ok"), "afterCancelMs": round(after_cancel),
              "sinceSendMs": round(since_send),
              "holder": (out.get("details") or {}).get("holder")}
        c.timings["cancel of a lock wait: answered after (ms)"] = round(after_cancel)
        if not out["ok"] and out["code"] == "cancelled" and after_cancel < 1500:
            d.stop(force=True)
            return f"the lock wait answered cancelled {after_cancel:.0f} ms after the cancel"
        what = (f"after cancel the waiting request answered {ev['answer']} {after_cancel:.0f} ms "
                f"later ({since_send:.0f} ms after it was sent; its wait was {wait_ms} ms)")
        sig = (not out["ok"] and out["code"] == "busy" and
               (out.get("details") or {}).get("waitedMs") == wait_ms and
               since_send >= wait_ms * 0.9 and ack.get("cancelled") is True)
        raise (dt.PremiseFail(what + ": the cancel was acknowledged but the wait ran out", ev)
               if sig else dt.Fail(what))


TESTS = {
    "lane_starvation": t_lane_starvation,
    "dead_client_lock_wait": t_dead_client_lock_wait,
    "import_wait": t_import_wait,
    "script_shared_visibility": t_script_shared_visibility,
    "fork_save_behind_analysis": t_fork_save_behind_analysis,
    "cancel_lock_wait": t_cancel_lock_wait,
}

BASELINE = {
    "lane_starvation": "scripts queue in the long lane behind long scripts (Scheduler.java:61)",
    "dead_client_lock_wait": "a client killed in a lock wait stays registered until the lock "
                             "frees (Connection.java:101)",
    "import_wait": "a queued import that reaches the front fails busy after the default 10 s "
                   "(ImportCommands.java:112)",
    "script_shared_visibility": "a reader can observe a contained script's transient write "
                                "(PROTOCOL-3.md 3.6)",
    "fork_save_behind_analysis": "save and fork_project queue in the long lane "
                                 "(Scheduler.java:61)",
    "cancel_lock_wait": "cancel does not end a program lock wait (ProgramEntry.java:195)",
}
