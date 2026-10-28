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
"""Script isolation (PROTOCOL-3.md 3.4 and 3.6, package E4).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only script_modes,...

All of these ask for protocol 3 (the protocol 2 behaviour is ``cc_e4.py``'s). The spec's list:

* ``script_modes`` (BP14, the fix of ``script_shared_visibility``): a mutating user script with a
  concurrent decompile and function-list reader in each mode. ``shared``: the write is attempted
  (``attemptedChanges``), rolled back, and readers may see it meanwhile (the documented limit);
  ``exclusive`` and ``private``: readers never see it. The stored program file's hash and the
  program revision are the same before and after. ``private`` is not blocked by readers and blocks
  none.
* ``script_reply``: the reply of each mode (``isolation``, ``lane`` and ``laneNote`` copied from the
  monitor, ``attemptedChanges``, ``basedOn``, ``unsavedIgnored``); the request validation
  (``bad_request`` with ``details.field`` and ``allowed[]``, also for a request that would queue).
* ``script_changed``: ``scriptSha256``; a wrong digest is refused ``script_changed``, a file edited
  after it was hashed is refused, the right digest runs.
* ``unsaved_ignored``: a program with an unsaved edit: ``shared`` sees it, ``private`` does not and
  says how many edits it missed.
* ``rusticquery_read``: the RusticQuery read actions (the real script of Hydralysis, when it is
  there) report ``attemptedChanges:false`` in ``shared`` and ``private`` mode.
* ``private_beside_holder`` (BP24): a ``private`` script and a new overlay open while the base is
  held exclusively by a script; the overlay's base wait is timed.
* ``private_open_cost``: the open cost of ``private`` on the project given with ``--project`` (KotOR
  in the gate), written to the timings.
* ``program_lock_spike``: does ``Program.lock(reason)`` turn a mutation attempt into an exception
  without disturbing concurrent readers? The answer is recorded either way.
* ``runaway_bounds``: ``scriptMaxS``, ``scriptCpuS`` and ``scriptAllocMb`` set the cancel flag; a
  script that ignores cancel is quarantined and its owner may run one script at a time.
"""
import contextlib
import hashlib
import json
import os
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

TRANSIENT_NAME = bl.TRANSIENT_NAME
#: the real RusticQuery of Hydralysis (it is only read); override with HYDRA_RUSTICQUERY
RUSTICQUERY = os.environ.get(
    "HYDRA_RUSTICQUERY",
    "D:/Projects/Hydra/RusticRE/src/hydralysis/scripts/RusticQuery.java")

NAME = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E4Name extends GhidraScript {
    @Override protected void run() throws Exception {
        println("name " + currentProgram.getFunctionManager().getFunctions(true).next().getName());
    }
}
"""
# lock(reason) spike. Run A: what lock() answers inside a script on the shared program. Run B: on a
# scratch program object (the same class, so the same rules) what a held lock does to a mutation
# attempt, to a reader thread and to a transaction that was open when lock() was asked.
SPIKE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E4LockSpike extends GhidraScript {
    @Override protected void run() throws Exception {
        boolean locked = currentProgram.lock("e4 spike");
        println("A lock() inside the script returned " + locked);
        if (locked) {
            currentProgram.unlock();
        }
    }
}
"""
SPIKE_B = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.*;
import java.nio.file.*;
public class E4LockSpikeB extends GhidraScript {
    private void note(String s) throws Exception {
        println(s);
        Files.writeString(Path.of(getScriptArgs()[0]), s + "\\n", StandardOpenOption.CREATE,
            StandardOpenOption.APPEND);
    }
    @Override protected void run() throws Exception {
        Language lang = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        ProgramDB p = new ProgramDB("e4spike", lang, lang.getDefaultCompilerSpec(), this);
        try {
            int tx = p.startTransaction("setup");
            boolean whileOpen = p.lock("e4 spike while a transaction is open");
            note("B lock() while a transaction is open: " + whileOpen);
            p.endTransaction(tx, true);
            boolean locked = p.lock("e4 spike");
            note("B lock() with no transaction open: " + locked);
            final String[] outcome = {"no exception"};
            final String[] read = {"read not run"};
            Thread t = new Thread(() -> {
                try {
                    read[0] = "reader thread read " + p.getFunctionManager().getFunctionCount() +
                        " functions while locked";
                    int id = p.startTransaction("e4 spike mutation");
                    p.endTransaction(id, false);
                    outcome[0] = "startTransaction returned " + id;
                }
                catch (Throwable ex) {
                    outcome[0] = ex.getClass().getName();
                }
            });
            t.start();
            t.join(5000);
            note("B " + read[0]);
            note("B mutation attempt while locked: " + (t.isAlive() ? "blocked" : outcome[0]));
            p.unlock();
            int id = p.startTransaction("after unlock");
            p.endTransaction(id, false);
            note("B after unlock a transaction starts again: " + id);
        }
        finally {
            p.release(this);
        }
    }
}
"""
DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E4Deaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // ignores cancel and interrupt
            }
        }
        println("deaf done");
    }
}
"""
SPIN = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E4Spin extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        long x = 1;
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            for (int i = 0; i < 200000; i++) {
                x = x * 31 + i;
            }
        }
        println("spin done " + x);
    }
}
"""
ALLOC = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E4Alloc extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        long sum = 0;
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            byte[] b = new byte[1 << 20];
            sum += b.length;
            Thread.sleep(2);
        }
        println("alloc done " + sum);
    }
}
"""
FAST_RUNAWAY = {"scriptGraceS": 1, "scriptSampleMs": 100}


# ---- helpers --------------------------------------------------------------------------------

def prepare(c):
    exe = bl.prepare(c)
    for n, text in (("E4Name.java", NAME), ("E4LockSpike.java", SPIKE), ("E4Deaf.java", DEAF),
                    ("E4Spin.java", SPIN), ("E4Alloc.java", ALLOC), ("E4LockSpikeB.java", SPIKE_B)):
        (c.scripts / n).write_text(text)
    return exe


def warm(c, s, *names):
    """Runs each script once on no program: the script framework is up and the script compiled."""
    for n in names or ("TestSleep.java",):
        s.call("script", script=c.script(n), program=None, args=["10"], wait=120000)


def session(c, d, gpr, exe, name, writable=False, protocol=3, warm_up=("TestSleep.java",)):
    s = c.connect(d, name, "e4", protocol)
    if warm_up:
        warm(c, s, *warm_up)
    s.call("open_project", path=str(gpr), writable=writable)
    if writable:
        s.call("open_program", path=exe, writable=True)
    else:
        s.call("open_program", path=exe)
    return s


def close_all(*sessions):
    for s in sessions:
        with contextlib.suppress(Exception):
            s.close()


def project_hash(gpr):
    """SHA-256 over the program data files (``*.gbf`` and ``*.prp``) of a project's repository,
    by relative path: what 'the master file' is on disk. Lock and index files are left out."""
    rep = pathlib.Path(gpr).with_suffix(".rep")
    h = hashlib.sha256()
    n = 0
    for f in sorted(rep.rglob("*")):
        if f.is_file() and f.suffix in (".gbf", ".prp"):
            h.update(str(f.relative_to(rep)).encode())
            h.update(f.read_bytes())
            n += 1
    return h.hexdigest(), n


def first_function(s):
    return s.call("functions", limit=1)["functions"][0]["address"]


def seen_in(result):
    return TRANSIENT_NAME in json.dumps(result)


def poll_reader(c, Y, fn, stop, polls, wait_ms, decompile_every=4):
    """A reader loop: ``functions`` by the transient name, and every few polls a ``decompile`` of
    the renamed function. Appends ``{"t", "ok", "code", "saw", "ms"}`` to ``polls``."""
    i = 0
    while not stop.is_set():
        t = time.perf_counter()
        if i % decompile_every == decompile_every - 1:
            r = bl.timed(c, Y, "decompile", address=fn, wait=wait_ms)
        else:
            r = bl.timed(c, Y, "functions", contains=TRANSIENT_NAME, limit=5, wait=wait_ms)
        polls.append({"t": t, "ok": r["ok"], "code": r.get("code"), "ms": r["ms"],
                      "saw": r["ok"] and seen_in(r["result"])})
        i += 1
        time.sleep(0.05)


def run_with_reader(c, X, Y, fn, hold_ms, wait_ms, **fields):
    """Runs the transient (mutating) script from X while Y polls. Returns ``(reply, polls, t0, t1)``."""
    polls = []
    stop = threading.Event()
    th = threading.Thread(target=poll_reader, args=(c, Y, fn, stop, polls, wait_ms), daemon=True)
    th.start()
    t0 = time.perf_counter()
    try:
        r = X.call("script", script=c.script("BaselineTransient.java"), args=[str(hold_ms)],
                   wait=60000, **fields)
    finally:
        t1 = time.perf_counter()
        stop.set()
        th.join(30)
    # the script takes its lock a moment after it was sent: judge the polls from 0.8 s in
    # and that ended before the script did (a read that waited for the lock ends when it is released)
    during = [p for p in polls if t0 + 0.8 < p["t"] and p["t"] + p["ms"] / 1000 < t1 - 0.1]
    return r, during, t0, t1


# ---- script_modes ---------------------------------------------------------------------------

def t_script_modes(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Modes")
    d = c.daemon("e4-modes")
    X = Y = None
    try:
        X = session(c, d, gpr, exe, "runner")
        Y = session(c, d, gpr, exe, "reader")
        fn = first_function(Y)
        # compile the scripts once, outside the measured window (a first run compiles in the request)
        X.call("script", script=c.script("BaselineTransient.java"), args=["10"], isolation="private")
        rev0 = Y.call("info")["revision"]
        hash0, nfiles = project_hash(gpr)
        out = {}
        for mode in ("shared", "exclusive", "private"):
            r, during, t0, t1 = run_with_reader(c, X, Y, fn, 4000, 400, isolation=mode)
            ok = [p for p in during if p["ok"]]
            busy = [p for p in during if p["code"] == "busy"]
            saw = [p for p in during if p["saw"]]
            dt.check("renamed" in r["output"], f"{mode}: the script did not run: {r}")
            dt.check(r["isolation"] == mode, f"{mode}: reply isolation {r.get('isolation')}")
            dt.check(r["attemptedChanges"] is True and r["attemptedChangesCount"] >= 1,
                     f"{mode}: the attempted rename was not measured: {r}")
            dt.check(r["changed"] is False, f"{mode}: a contained script reported changed: {r}")
            after = Y.call("functions", contains=TRANSIENT_NAME)["functions"]
            dt.check(not after, f"{mode}: the script's write survived its rollback: {after}")
            dt.check(not [p for p in during if not p["ok"] and p["code"] != "busy"],
                     f"{mode}: a reader failed: {[p for p in during if not p['ok']][:2]}")
            if mode == "shared":
                dt.check(len(ok) >= 10, f"shared: only {len(ok)} reads in {t1 - t0:.1f} s")
                out["shared"] = {"polls": len(during), "sawTransient": len(saw)}
                # the documented limit (3.6): readers may see the write. It is measured, not asserted:
                # a run that sees none is reported as it is
            elif mode == "exclusive":
                dt.check(not saw, f"exclusive: a reader saw the transient write {len(saw)} times")
                dt.check(len(busy) >= 3 and not ok,
                         f"exclusive: readers were not held off ({len(ok)} ok, {len(busy)} busy)")
                out["exclusive"] = {"polls": len(during), "busy": len(busy), "saw": 0}
            else:
                dt.check(not saw, f"private: a reader saw the transient write {len(saw)} times")
                dt.check(len(ok) >= 10 and not busy,
                         f"private: readers were held off ({len(ok)} ok, {len(busy)} busy)")
                dt.check(r["basedOn"]["saved"] is True and r["unsavedIgnored"] == 0,
                         f"private: basedOn/unsavedIgnored {r.get('basedOn')} {r.get('unsavedIgnored')}")
                out["private"] = {"polls": len(during), "saw": 0, "openAndRunSeconds":
                                  round(t1 - t0, 2)}
        dt.check(project_hash(gpr) == (hash0, nfiles),
                 "the stored program files changed (hash before/after)")
        dt.check(Y.call("info")["revision"] == rev0, "the program revision changed")
        c.timings["script_modes: shared polls that saw the uncommitted write"] = \
            f"{out['shared']['sawTransient']} of {out['shared']['polls']}"
        return (f"shared: reader saw the write in {out['shared']['sawTransient']} of "
                f"{out['shared']['polls']} polls (the documented limit); exclusive: "
                f"{out['exclusive']['busy']} reads held off, none saw it; private: "
                f"{out['private']['polls']} reads served, none saw it; all three rolled back, "
                f"attemptedChanges true, master hash ({nfiles} files) and revision unchanged")
    finally:
        close_all(X, Y)
        d.stop(force=True)


# ---- script_reply ---------------------------------------------------------------------------

def t_script_reply(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Reply")
    d = c.daemon("e4-reply", maxLong=1)
    X = Y = None
    try:
        X = session(c, d, gpr, exe, "runner", warm_up=("TestSleep.java",))
        # reply fields of a program script in each mode, and of a script with no program
        for mode in ("shared", "exclusive", "private"):
            r = X.call("script", script=c.script("BaselineQuick.java"), isolation=mode)
            dt.check(r["isolation"] == mode and r["attemptedChanges"] is False and
                     r["attemptedChangesCount"] == 0 and r["lane"] == "long" and
                     "laneNote" not in r, f"{mode}: {r}")
            dt.check(r["basedOn"]["saved"] is True and "programRevision" in r["basedOn"] and
                     r["unsavedIgnored"] == 0, f"{mode}: basedOn {r.get('basedOn')}")
        r = X.call("script", script=c.script("TestSleep.java"), program=None, args=["10"])
        dt.check(r["isolation"] == "none" and "basedOn" not in r and
                 r["attemptedChanges"] is False, f"no program: {r}")
        r = X.call("script", script=c.script("BaselineQuick.java"))
        dt.check(r["isolation"] == "shared", f"the default isolation is shared: {r}")
        # the lane and its note are copied from the request monitor (E3a decided them)
        r = X.call("script", script=c.script("BaselineQuick.java"), lane="quick", timeout=30)
        dt.check(r["lane"] == "quick" and "laneNote" not in r, f"quick: {r}")
        r = X.call("script", script=c.script("BaselineQuick.java"), lane="quick")
        dt.check(r["lane"] == "long" and "quick" in r["laneNote"], f"quick without timeout: {r}")
        r = X.call("script", script=c.script("BaselineQuick.java"), lane="fast", timeout=30)
        dt.check(r["lane"] == "long" and r["laneNote"], f"unknown lane: {r}")
        # the validation: bad_request with details.field and allowed[]
        for bad in ("bogus", "Private", 5, ["private"], "worker"):
            e = _error(c, X, script=c.script("BaselineQuick.java"), isolation=bad)
            dt.check(e.code == "bad_request" and e.details.get("field") == "isolation" and
                     e.details.get("allowed") == ["shared", "exclusive", "private"],
                     f"isolation {bad!r}: {e.code} {e.details}")
        e = _error(c, X, script=c.script("BaselineQuick.java"), scriptSha256="not-a-digest")
        dt.check(e.code == "bad_request" and e.details.get("field") == "scriptSha256",
                 f"a malformed digest: {e.code} {e.details}")
        # validate-before-wait (3.5): with the one long slot taken, a bad request fails at once
        hold = X.send("script", script=c.script("TestSleep.java"), program=None, args=["8000"],
                      parallel=True, wait=60000)
        dt.wait_for(lambda: X.call("status")["scheduler"]["long"]["inUse"] >= 1,
                    "the long slot to be taken", 30)
        Y = session(c, d, gpr, exe, "queued", warm_up=())
        t = time.perf_counter()
        e = _error(c, Y, script=c.script("BaselineQuick.java"), isolation="bogus", wait=20000)
        ms = (time.perf_counter() - t) * 1000
        dt.check(e.code == "bad_request" and e.details.get("field") == "isolation" and ms < 2000,
                 f"a queueing request with a bad isolation answered {e.code} after {ms:.0f} ms")
        with contextlib.suppress(Exception):
            X.wait(hold)
        c.timings["script_reply: bad isolation of a request that would queue (ms)"] = round(ms)
        return ("replies carry isolation, lane, laneNote, attemptedChanges, basedOn, "
                f"unsavedIgnored in every mode; bad isolation/digest -> bad_request with field and "
                f"allowed[], also before a slot wait ({ms:.0f} ms)")
    finally:
        close_all(X, Y)
        d.stop(force=True)


def _error(c, s, **fields):
    """The SessionError of a script request that must fail."""
    try:
        s.call("script", **fields)
    except c.gs.SessionError as e:
        return e
    raise dt.Fail(f"script {fields} did not fail")


# ---- script_changed -------------------------------------------------------------------------

def t_script_changed(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Sha")
    d = c.daemon("e4-sha")
    X = None
    try:
        X = session(c, d, gpr, exe, "runner", warm_up=("TestSleep.java",))
        path = c.scripts / "BaselineQuick.java"
        good = hashlib.sha256(path.read_bytes()).hexdigest()
        r = X.call("script", script=str(path), scriptSha256=good)
        dt.check("functions" in r["output"], f"the pinned script did not run: {r}")
        r = X.call("script", script=str(path), scriptSha256=good.upper())
        dt.check("functions" in r["output"], "an upper-case digest is the same digest")
        bad = "0" * 64
        e = _error(c, X, script=str(path), scriptSha256=bad)
        dt.check(e.code == "script_changed" and e.details["expected"] == bad and
                 e.details["actual"] == good and e.details["script"].endswith("BaselineQuick.java"),
                 f"wrong digest: {e.code} {e.details}")
        # the file is edited after it was hashed once (the cache is keyed on size and mtime)
        path.write_text(path.read_text() + "\n// edited after the hash was pinned\n")
        os.utime(path, (time.time() + 5, time.time() + 5))
        e = _error(c, X, script=str(path), scriptSha256=good)
        new = hashlib.sha256(path.read_bytes()).hexdigest()
        dt.check(e.code == "script_changed" and e.details["actual"] == new and new != good,
                 f"edited file: {e.code} {e.details}")
        r = X.call("script", script=str(path), scriptSha256=new)
        dt.check("functions" in r["output"], "the new digest runs")
        # a script that is not found is still not_found (the digest does not hide it)
        e = _error(c, X, script=str(c.scripts / "NoSuchScript.java"), scriptSha256=good)
        dt.check(e.code == "not_found", f"missing script: {e.code}")
        return ("a wrong digest, an upper-case one, an edited file and the right digest: "
                "script_changed carries expected, actual and script")
    finally:
        close_all(X)
        d.stop(force=True)


def t_overlay_script_changed(c):
    """Review round 1: a protocol 3 script on an overlay is pinned by scriptSha256 like any script."""
    exe = prepare(c)
    gpr = c.copy_fixture("e4OvSha")
    d = c.daemon("e4-ovsha")
    X = None
    try:
        X = session(c, d, gpr, exe, "runner", warm_up=("TestSleep.java",))
        X.call("open_program", path=exe, overlay="o")
        path = c.scripts / "BaselineQuick.java"
        good = hashlib.sha256(path.read_bytes()).hexdigest()
        bad = "0" * 64
        e = _error(c, X, script=str(path), overlay="o", scriptSha256=bad)
        dt.check(e.code == "script_changed" and e.details["expected"] == bad and
                 e.details["actual"] == good, f"overlay, wrong digest: {e.code} {e.details}")
        e = _error(c, X, script=str(path), overlay="o", scriptSha256="xyz")
        dt.check(e.code == "bad_request", f"overlay, malformed digest: {e.code}")
        e = _error(c, X, script=str(path), overlay="o", isolation="bogus")
        dt.check(e.code == "bad_request", f"overlay, bad isolation: {e.code}")
        r = X.call("script", script=str(path), overlay="o", scriptSha256=good)
        dt.check(r["mode"] == "contained" and r.get("isolation") == "overlay",
                 f"overlay, right digest: {r}")
        return "a v3 overlay script: a wrong digest is script_changed, the right one runs"
    finally:
        close_all(X)
        d.stop(force=True)


# ---- unsaved_ignored ------------------------------------------------------------------------

def t_unsaved_ignored(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Unsaved")
    d = c.daemon("e4-unsaved")
    O = R = None
    try:
        O = session(c, d, gpr, exe, "owner", writable=True,
                    warm_up=("TestSleep.java",))
        R = session(c, d, gpr, exe, "reader", warm_up=("TestSleep.java",))
        fn = first_function(O)
        before = R.call("script", script=c.script("E4Name.java"), isolation="private")
        orig = before["output"].split()[1]
        dt.check(before["unsavedIgnored"] == 0 and before["basedOn"]["saved"] is True,
                 f"nothing unsaved yet: {before}")
        O.call("rename", address=fn, name="e4_unsaved_edit")
        O.call("comment", address=fn, type="eol", text="e4 unsaved comment")
        shared = R.call("script", script=c.script("E4Name.java"), isolation="shared")
        dt.check("e4_unsaved_edit" in shared["output"] and shared["unsavedIgnored"] == 0 and
                 shared["basedOn"]["saved"] is False,
                 f"a shared script must see the unsaved edit: {shared}")
        priv = R.call("script", script=c.script("E4Name.java"), isolation="private")
        dt.check(orig in priv["output"] and "e4_unsaved_edit" not in priv["output"],
                 f"a private script saw the unsaved edit: {priv['output']}")
        dt.check(priv["unsavedIgnored"] >= 2 and priv["basedOn"]["saved"] is True and
                 priv["basedOn"]["programRevision"],
                 f"unsavedIgnored {priv['unsavedIgnored']} basedOn {priv['basedOn']}")
        # the owner's own private script also runs on the stored file
        mine = O.call("script", script=c.script("E4Name.java"), isolation="private")
        dt.check(orig in mine["output"] and mine["mode"] == "private" and
                 mine["unsavedIgnored"] >= 2, f"owner, private: {mine}")
        # without isolation the owner runs in owner mode as before and sees its edit
        own = O.call("script", script=c.script("E4Name.java"))
        dt.check("e4_unsaved_edit" in own["output"] and own["mode"] == "owner" and
                 own["isolation"] == "exclusive", f"owner mode: {own}")
        O.call("save")
        saved = R.call("script", script=c.script("E4Name.java"), isolation="private")
        dt.check("e4_unsaved_edit" in saved["output"] and saved["unsavedIgnored"] == 0 and
                 saved["basedOn"]["programRevision"] != priv["basedOn"]["programRevision"],
                 f"after the save a private script sees the edit and a new revision: {saved}")
        return (f"private ignored {priv['unsavedIgnored']} unsaved edits (basedOn saved) and saw "
                f"'{orig}'; shared saw the edit; after save private sees it on a new revision")
    finally:
        close_all(O, R)
        d.stop(force=True)


# ---- rusticquery_read -----------------------------------------------------------------------

def t_rusticquery_read(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Rq")
    d = c.daemon("e4-rq")
    X = None
    try:
        X = session(c, d, gpr, exe, "runner")
        src = pathlib.Path(RUSTICQUERY)
        if not src.is_file():
            return f"skipped: {src} (RusticQuery of Hydralysis) is not there"
        script = c.scripts / "RusticQuery.java"
        script.write_bytes(src.read_bytes())
        sha = hashlib.sha256(script.read_bytes()).hexdigest()
        fn = first_function(X)
        base = {"timeout_s": 30, "expected_sha256": "", "contains": "", "cursor": "", "limit": 20,
                "options": {}}
        seen = []
        for iso in ("shared", "private"):
            for action, extra in (("functions", {}), ("xrefs", {"address": fn}),
                                  ("decompile", {"address": fn})):
                req = dict(base, id=f"e4-{iso}-{action}", action=action, **extra)
                r = X.call("script", script=str(script), args=[json.dumps(req)], isolation=iso,
                           scriptSha256=sha, lane="quick", timeout=60, wait=120000)
                body = json.loads(r["output"].strip().splitlines()[-1])
                dt.check(body.get("ok") is True, f"{iso} {action}: {r['output'][:300]}")
                dt.check(r["attemptedChanges"] is False and r["attemptedChangesCount"] == 0,
                         f"{iso} {action}: a read action attempted changes: "
                         f"{r['attemptedChangesCount']}")
                dt.check(r["isolation"] == iso and r["lane"] == "quick", f"{iso} {action}: {r}")
                seen.append(f"{iso}/{action}")
        return f"RusticQuery read actions attempted no change: {', '.join(seen)}"
    finally:
        close_all(X)
        d.stop(force=True)


# ---- private_beside_holder (BP24) -----------------------------------------------------------

def t_private_beside_holder(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Beside")
    d = c.daemon("e4-beside")
    O = P = Q = None
    try:
        O = session(c, d, gpr, exe, "owner", writable=True,
                    warm_up=("TestSleep.java",))
        P = session(c, d, gpr, exe, "private", warm_up=("TestSleep.java",))
        Q = session(c, d, gpr, exe, "overlayer", warm_up=("TestSleep.java",))
        # an overlay that exists before the hold keeps working during it
        P.call("open_program", path=exe, overlay="before")
        hold = O.send("script", script=c.script("TestSleep.java"), args=["9000"], parallel=True,
                      wait=60000)
        dt.wait_for(lambda: bl_busy(O, exe), "the owner's script to hold the program", 30)
        # (a) a private script is not blocked by the exclusive hold
        t = time.perf_counter()
        r = P.call("script", script=c.script("E4Name.java"), isolation="private", wait=3000)
        priv_ms = (time.perf_counter() - t) * 1000
        dt.check(priv_ms < 3000 and "name" in r["output"],
                 f"the private script waited {priv_ms:.0f} ms behind the holder")
        # a shared script is held off, as before
        sh = bl.timed(c, P, "script", script=c.script("E4Name.java"), isolation="shared", wait=500)
        dt.check(not sh["ok"] and sh["code"] == "busy", f"a shared script beside the holder: {sh}")
        # (b) BP24: a new overlay opens during the hold (hydra.3 and the base: busy)
        t = time.perf_counter()
        Q.call("open_program", path=exe, overlay="during", wait=3000)
        ov_ms = (time.perf_counter() - t) * 1000
        dt.check(ov_ms < 3000, f"the overlay opened after {ov_ms:.0f} ms")
        names = [o["name"] for o in Q.call("overlays")["overlays"]]
        dt.check("during" in names, f"overlays {names}")
        dt.check(bl_busy(O, exe), "the holder lost the program")
        # an overlay that exists before the hold keeps working during it
        before = P.call("info", overlay="before", wait=3000)
        dt.check(before["mode"] == "overlay", f"the overlay of before the hold: {before}")
        with contextlib.suppress(Exception):
            O.wait(hold)
        c.timings["private_beside_holder: private script beside an exclusive hold (ms)"] = \
            round(priv_ms)
        c.timings["private_beside_holder: new overlay beside an exclusive hold (ms)"] = round(ov_ms)
        return (f"beside a 9 s exclusive script a private script ran in {priv_ms:.0f} ms and a new "
                f"overlay opened in {ov_ms:.0f} ms; a shared script was still refused busy")
    finally:
        close_all(O, P, Q)
        d.stop(force=True)


def bl_busy(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return bool(pg["busy"])
    return False


# ---- private_open_cost ----------------------------------------------------------------------

def t_private_open_cost(c):
    """The cost of opening the private instance: the request time of a trivial script in
    ``private`` mode less the same script in ``shared`` mode, median of five. On the project given
    with ``--project`` (KotOR in the gate; only copied by the caller) and on the test fixture."""
    exe = prepare(c)
    results = {}
    targets = [("fixture", c.copy_fixture("e4Cost"), None)]
    if c.a.project:
        targets.append(("project", pathlib.Path(c.a.project), "first"))
    d = c.daemon("e4-cost")
    X = None
    try:
        X = c.connect(d, "runner", "e4", 3)
        warm(c, X, "TestSleep.java")
        for label, gpr, which in targets:
            X.call("open_project", path=str(gpr))
            if which == "first":
                path = X.call("list", programsOnly=True)["entries"][0]["path"]
            else:
                path = exe
            info = X.call("open_program", path=path)
            nfun = X.call("info")["functions"]
            med = {}
            for mode in ("shared", "private"):
                X.call("script", script=c.script("BaselineQuick.java"), isolation=mode)  # warm
                ts = []
                for _ in range(5):
                    t = time.perf_counter()
                    r = X.call("script", script=c.script("BaselineQuick.java"), isolation=mode)
                    ts.append((time.perf_counter() - t) * 1000)
                    dt.check(r["isolation"] == mode and r["attemptedChanges"] is False,
                             f"{label} {mode}: {r}")
                med[mode] = sorted(ts)[2]
            results[label] = {"path": path, "functions": nfun, "sharedMs": round(med["shared"]),
                              "privateMs": round(med["private"]),
                              "openCostMs": round(med["private"] - med["shared"])}
            c.timings[f"private_open_cost: {label} {path} ({nfun} functions) shared/private/"
                      "cost (ms)"] = [results[label]["sharedMs"], results[label]["privateMs"],
                                      results[label]["openCostMs"]]
            X.call("close_project")
        return "; ".join(f"{k}: {v['functions']} functions, shared {v['sharedMs']} ms, private "
                         f"{v['privateMs']} ms, open cost {v['openCostMs']} ms"
                         for k, v in results.items())
    finally:
        close_all(X)
        d.stop(force=True)


# ---- program_lock_spike ---------------------------------------------------------------------

def t_program_lock_spike(c):
    """The spike of 3.6: does ``Program.lock(reason)`` on the shared program turn a mutation attempt
    into an exception without disturbing concurrent readers? Run A: ``lock()`` inside a contained
    script and inside an owner script. Run B: on a scratch program object, what a held lock does.
    The result is written to the timings either way, and the test asserts the facts it recorded,
    so a change of Ghidra's behaviour shows up."""
    exe = prepare(c)
    gpr = c.copy_fixture("e4Spike")
    d = c.daemon("e4-spike")
    O = R = None
    try:
        O = session(c, d, gpr, exe, "owner", writable=True)
        R = session(c, d, gpr, exe, "reader")
        contained = R.call("script", script=c.script("E4LockSpike.java"), isolation="shared")
        owner = O.call("script", script=c.script("E4LockSpike.java"))
        b = O.call("script", script=c.script("E4LockSpikeB.java"), program=None,
                   args=[str(c.work / "spikeB.txt")], timeout=60)
        ca = contained["output"].strip()
        oa = owner["output"].strip()
        lines = [ln for ln in b["output"].splitlines() if ln.startswith("B ")]
        dt.check("returned false" in ca and "returned false" in oa,
                 f"A: lock() inside a script: contained {ca!r}, owner {oa!r}")
        dt.check(len(lines) == 5, f"B: {b['output']}")
        dt.check("while a transaction is open: false" in lines[0], f"B: {lines}")
        dt.check("no transaction open: true" in lines[1], f"B: {lines}")
        mutation = lines[3].split(": ",1)[1]
        dt.check(mutation != "no exception" and "startTransaction returned" not in mutation,
                 f"B: a mutation attempt on a locked program went through: {lines}")
        dt.check("reader thread read" in lines[2], f"B: a reader thread: {lines}")
        dt.check("starts again" in lines[4], f"B: {lines}")
        # nothing of the spike survived on the shared program
        after = R.call("functions", limit=3)["functions"]
        dt.check(after, "the shared program is unreadable after the spike")
        c.timings["program_lock_spike"] = {
            "A contained script on the shared program": ca,
            "A owner script on the shared program": oa,
            "B lock() while a transaction is open": lines[0][2:],
            "B lock() with none open": lines[1][2:],
            "B reader thread while locked": lines[2][2:],
            "B mutation attempt while locked": lines[3][2:],
            "B after unlock": lines[4][2:],
            "decision": ("lock() is refused inside every script (a script with a program runs in "
                         "its own transaction, and a contained one in the engine's outer "
                         "transaction). Held by the engine before the script, a mutation attempt "
                         f"({mutation}) does not become an exception for the caller and would stall "
                         "the script's own startTransaction and that of every concurrent contained "
                         "script. Not adopted: shared stays 'rolled back, measured, and "
                         "RusticQuery is source-controlled and hash-pinned'"),
        }
        return ("lock() inside a script (contained or owner): false, because a transaction is "
                "open; on a scratch program lock() is refused while a transaction is open and "
                f"granted otherwise, and a mutation attempt then {mutation} (no exception for "
                "the caller; the transaction of every contained script would stall too); not "
                "adopted for shared (see the timings)")
    finally:
        close_all(O, R)
        d.stop(force=True)


# ---- runaway_bounds -------------------------------------------------------------------------

def t_runaway_bounds(c):
    exe = prepare(c)
    gpr = c.copy_fixture("e4Run")
    d = c.daemon("e4-run", engine=dict(FAST_RUNAWAY, scriptMaxS=6, scriptCpuS=1, scriptAllocMb=100))
    A = B = None
    try:
        A = session(c, d, gpr, exe, "runaway", warm_up=("TestSleep.java", "E4Deaf.java",
                                                         "E4Spin.java", "E4Alloc.java"))
        B = session(c, d, gpr, exe, "other", warm_up=("TestSleep.java",))
        # (1) the wall budget: a script that checks cancel is cancelled at scriptMaxS
        t = time.perf_counter()
        e = _error(c, A, script=c.script("TestSleep.java"), args=["60000"], program=None, wait=60000)
        wall = time.perf_counter() - t
        dt.check(e.code == "cancelled" and "scriptMaxS" in e.message and 5.5 < wall < 14,
                 f"wall budget: {e.code} {e.message!r} after {wall:.1f} s")
        dt.check((e.details or {}).get("cancelReason", "").startswith("wall budget"),
                 f"wall budget details {e.details}")
        # (2) the CPU budget
        t = time.perf_counter()
        e = _error(c, A, script=c.script("E4Spin.java"), args=["60000"], program=None, wait=60000)
        cpu = time.perf_counter() - t
        dt.check(e.code == "cancelled" and "scriptCpuS" in e.message and 0.8 < cpu < 5,
                 f"cpu budget: {e.code} {e.message!r} after {cpu:.1f} s")
        # (3) the allocation budget
        t = time.perf_counter()
        e = _error(c, A, script=c.script("E4Alloc.java"), args=["60000"], program=None, wait=60000)
        alloc = time.perf_counter() - t
        dt.check(e.code == "cancelled" and "scriptAllocMb" in e.message and alloc < 5,
                 f"alloc budget: {e.code} {e.message!r} after {alloc:.1f} s")
        # (4) a script that ignores cancel is quarantined; its owner runs one script at a time
        deaf = A.send("script", script=c.script("E4Deaf.java"), args=["9000"], program=None,
                      parallel=True, wait=60000, timeout=1)
        time.sleep(0.6)
        # cancel was set at 1 s, the grace is 1 s: from about 2 s the deaf script is leaked
        dt.wait_for(lambda: not bl.timed(c, A, "script", script=c.script("TestSleep.java"),
                                         args=["10"], program=None, wait=2000)["ok"],
                    "the owner to be limited to one script", 12, 0.3)
        t = time.perf_counter()
        r = bl.timed(c, A, "script", script=c.script("TestSleep.java"), args=["10"], program=None,
                     wait=60000)
        ms = (time.perf_counter() - t) * 1000
        dt.check(not r["ok"] and r["code"] == "busy" and
                 r["details"].get("reason") == "runaway_quarantined" and ms < 2000,
                 f"a second script of the quarantined owner: {r}")
        dt.check(r["details"].get("leakedWorkers") == 1, f"details {r['details']}")
        # another client is not affected
        other = bl.timed(c, B, "script", script=c.script("TestSleep.java"), args=["10"],
                         program=None, wait=5000)
        dt.check(other["ok"], f"another client was refused: {other}")
        # when the deaf script ends, the owner is free again
        try:
            A.wait(deaf)
        except c.gs.SessionError:
            pass
        free = bl.timed(c, A, "script", script=c.script("TestSleep.java"), args=["10"],
                        program=None, wait=5000)
        dt.check(free["ok"], f"the owner is still limited after the deaf script ended: {free}")
        c.timings["runaway_bounds: wall/cpu/alloc cancel after (s)"] = \
            [round(wall, 1), round(cpu, 1), round(alloc, 1)]
        return (f"scriptMaxS 6 cancelled a polling script after {wall:.1f} s, scriptCpuS 1 a "
                f"spinning one after {cpu:.1f} s, scriptAllocMb 100 an allocating one after "
                f"{alloc:.1f} s; a deaf script was quarantined (its owner refused busy "
                f"runaway_quarantined at once, another client served, the owner free after it ended)")
    finally:
        close_all(A, B)
        d.stop(force=True)


TESTS = {
    "script_modes": t_script_modes,
    "script_reply": t_script_reply,
    "script_changed": t_script_changed,
    "overlay_script_changed": t_overlay_script_changed,
    "unsaved_ignored": t_unsaved_ignored,
    "rusticquery_read": t_rusticquery_read,
    "private_beside_holder": t_private_beside_holder,
    "private_open_cost": t_private_open_cost,
    "program_lock_spike": t_program_lock_spike,
    "runaway_bounds": t_runaway_bounds,
}

BASELINE = {}
