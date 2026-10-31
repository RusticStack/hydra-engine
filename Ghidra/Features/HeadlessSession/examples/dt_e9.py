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
"""The resource governor (PROTOCOL-3.md 3.11, D46, D60, gate 9.14, package E9).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only e9_selftest,...

* ``e9_selftest``: the engine's own ``-selfTest`` (budgets, the gate's fairness, a guarded thread
  that survives an ``OutOfMemoryError``, 64 reservations racing for 4 views, the sweep's path rule).
* ``e9_limits_job``: ``hello.limits`` and ``capabilities.admission`` (protocol 3 only); ``health.governor``
  and ``health.processJob`` (``own:true``, the daemon is in its own job, its decompiler is in the job).
* ``e9_job_containment`` (Windows; SP3(b), K7, D60, X9): decompilers are **suspended**, then the daemon is
  ended with ``TerminateProcess``: none is left within 5 s. The **no-job control** (the same daemon with
  ``ProcessJob`` disabled by two launch properties) must show the survivors, so the test is red without the
  job. The third phase is the fallback: with the job unavailable the start-up sweep kills an orphan
  decompiler of this install and leaves another install's decompiler and one with a live parent alone.
* ``e9_decompiler_faults`` (GR9, SP4): a killed native decompiler fails exactly one request
  (``decompiler_failed``, deterministic: the only pooled decompiler is killed, the next request is the one that
  fails) and the request after it works (dispose and recreate); under a 12-client load ``kill -9`` of one
  decompiler fails at most one request, ``kill -9`` of every decompiler fails between one and as many requests
  as decompilers were killed, and every other request returns the reference text.
* ``e9_decompiler_hang`` (GR9): a **suspended** decompiler is a hang that ends at the request's timeout
  (``decompiler_failed``, retryable) while a request of another client, made during the hang, is answered at
  once by a fresh decompiler.
* ``e9_guarded_threads`` (3.11 "Daemon threads", D46): ``health.governor.threadState`` shows the accept,
  reaper and governor threads alive and beating; a Throwable planted in a lap of each (``debug_stall
  what:"thread"``, behind the test-hooks launch property) restarts it and counts it; an
  ``OutOfMemoryError`` also releases the emergency reserve, which the governor arms again.
* ``e9_concurrent_open``: 16 clients open a program at the same moment with ``maxViews`` 4: exactly 4 are
  admitted (the check and the reservation are one step); one client sending 6 opens at once with
  ``maxViewsPerClient`` 2 gets exactly 2.
* ``e9_gate``: with room for two native decompilers a third request waits and then gets
  ``busy{reason:"capacity", resource:"native"}`` instead of hanging; the gate never holds more than its
  permits; waits are served per client.
* ``e9_idle_dispose``: an idle pooled decompiler is disposed after ``decompilerIdleS``.
* ``e9_admission_256``: ``-Xmx256m``: 12 views are admitted with room; with the live heap forced over the soft
  limit (ballast, not the views' own footprint) the next 12 end in structured ``busy`` (capacity, heap), 0
  ``OutOfMemoryError``, the reaper and every guarded thread alive, ``health`` answering (red on hydra.3).
* ``e9_admission_512``: ``-Xmx512m`` and 24 views run.
* ``e9_view_probe``: a 100-view probe is refused at ``maxViews``; the per-client cap refuses a fifth view
  of one client (``client_cap``); a program another client has open is shared, not counted again.
* ``e9_degraded``: above the hard watermark the daemon is ``degraded``, refuses opens, keeps serving reads.
* ``e9_minxmx``: a heap below ``minXmxMb`` is refused at start-up unless forced.
* ``e9_disk``: a fork needs ``estimate + reserve`` free; ``viewDiskBudget`` bounds the view forks.
* ``e9_runaway``: a script that ignores cancel is quarantined and counted (``leakedWorkers``).
"""
import contextlib
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

import daemon_tests as dt

try:
    import dt_baseline as bl
except ImportError:  # loaded by path before dt_baseline was registered
    import importlib.util
    _p = pathlib.Path(__file__).resolve().parent / "dt_baseline.py"
    _spec = importlib.util.spec_from_file_location("dt_baseline", _p)
    bl = importlib.util.module_from_spec(_spec)
    sys.modules["dt_baseline"] = bl
    _spec.loader.exec_module(bl)

HERE = pathlib.Path(__file__).resolve().parent
HOOKS = ["-Dghidra.session.testHooks=true"]
NO_JOB = HOOKS + ["-Dghidra.session.noProcessJob=true"]
SWEEP = HOOKS + ["-Dghidra.session.noProcessJob=sweep"]
# these tests are about the native decompiler processes (faults, hangs, the breaker, the gate): a repeated
# decompile of an unchanged program must reach a process, so the decompile cache (goal 4) is off for them
NO_DCACHE = {"decompileCache": 0}

DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E9Deaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // ignores cancel and swallows the interrupt
            }
        }
    }
}
"""

BALLAST = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E9Ballast extends GhidraScript {
    @Override protected void run() throws Exception {
        Runtime rt = Runtime.getRuntime();
        System.gc();
        long used = rt.totalMemory() - rt.freeMemory();
        long want = Long.parseLong(getScriptArgs()[0]) << 20;
        if (want > used) {
            // the system properties table is a root of the JVM: this array stays until the daemon ends (one key per
            // target, so a second call adds to the first)
            System.getProperties().put("e9.ballast." + want, new byte[(int) (want - used)]);
        }
        System.gc();
        println("heap after the ballast: " + ((rt.totalMemory() - rt.freeMemory()) >> 20) + " MB");
    }
}
"""


# ---- helpers --------------------------------------------------------------------------------

def chaos():
    try:
        import chaos_lib
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("chaos_lib", HERE / "chaos_lib.py")
        chaos_lib = importlib.util.module_from_spec(spec)
        sys.modules["chaos_lib"] = chaos_lib
        spec.loader.exec_module(chaos_lib)
    return chaos_lib


def windows_only():
    if os.name != "nt":
        raise dt.Skipped("Windows only (Job Objects, NtSuspendProcess)")


def close_all(*sessions):
    for s in sessions:
        with contextlib.suppress(Exception):
            if s is not None:
                s.close()


def stop(d):
    with contextlib.suppress(Exception):
        d.stop(force=True, timeout=30)
    with contextlib.suppress(Exception):
        if d.jvm_alive():
            d.kill()


def alive_of(pids):
    ch = chaos()
    now = {p["pid"] for p in ch.oracle.list_processes()}
    return [p for p in pids if p in now]


def wait_gone(pids, secs):
    """Seconds until none of ``pids`` is alive, or None when some still are after ``secs``."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < secs:
        if not alive_of(pids):
            return time.perf_counter() - t0
        time.sleep(0.05)
    return None


def decompiler_pids(pid):
    return chaos().decompilers_of(pid)


def open_view(c, s, gpr, exe, writable=False):
    s.call("open_project", path=str(gpr), writable=writable)
    return s.call("open_program", path=exe, writable=writable)


def refusal(fn, *args, **kw):
    """The SessionError of a call that must be refused with busy/capacity; returns its details."""
    try:
        fn(*args, **kw)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "busy" and (e.details or {}).get("reason") == "capacity":
            return e.details
        raise
    return None


def warm_decompilers(c, d, gpr, exe, n, protocol=3):
    """``n`` clients decompile one function each at the same moment, so that ``n`` native decompilers exist
    (idle in the pool afterwards). Returns the sessions and the function addresses."""
    ss = [c.connect(d, f"w{i}", "e9", protocol) for i in range(n)]
    for s in ss:
        open_view(c, s, gpr, exe)
    fns = [f["address"] for f in ss[0].call("functions", limit=max(n, 4))["functions"]]
    errs = []

    def one(i):
        try:
            ss[i].call("decompile", address=fns[i % len(fns)], wait=60000)
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(120)
    dt.check(not errs, f"warm-up decompiles failed: {errs[:2]}")
    return ss, fns


def ballast(c, s, target_mb):
    """Raises the live heap of the daemon to about ``target_mb`` (a squeeze: the fixture is a small
    program, so its views cost little; the heap rule is the same whatever fills the heap)."""
    (c.scripts / "E9Ballast.java").write_text(BALLAST)
    s.call("script", script=c.script("E9Ballast.java"), program=None, args=[str(target_mb)], wait=60000)


def fixture_args(c):
    exe = bl.prepare(c)
    return exe


# ---- e9_selftest ----------------------------------------------------------------------------

def t_selftest(c):
    import contract_tests as ct
    code, lines, err = ct.self_test(c)
    bad = [ln for ln in lines if ln.startswith("FAIL")]
    dt.check(code == 0 and not bad, f"-selfTest exit {code}: {bad} {err[-800:]}")
    want = ("ok   viewDiskBudget and diskReserve take sizes",
            "ok   a heap below minXmxMb is refused at start-up",
            "ok   the gate serves clients in turn",
            "ok   a wait for a permit that never comes ends in busy capacity native",
            "ok   a guarded body that threw an OutOfMemoryError twice ran a third time",
            "ok   64 concurrent reservations against maxViews 4 grant exactly 4",
            "ok   64 concurrent requests of one client against maxViewsPerClient 2 grant exactly 2",
            "ok   the liveness figure of a guarded thread",
            "ok   a capacity refusal is busy with reason",
            "ok   the orphan sweep of an install with no decompiler finds none",
            "ok   decompileCache default: 1/32 of the heap",
            "ok   decompileCache: 8 callers of one key at once run one decompile",
            "ok   decompileCache: a later caller of an unchanged program is a hit",
            "ok   decompileCache: a decompile that did not complete is not stored",
            "ok   decompileCache: a result whose program changed during the decompile is not stored",
            "ok   decompileCache: a changed program is decompiled again",
            "ok   decompileCache: a cancelled waiter stops waiting",
            "ok   decompileCache: the LRU stays within its budget",
            "ok   decompileCache: 8 callers of a failing decompile get its failure at once",
            "ok   decompileCache: a waiter stops waiting at its own budget",
            "ok   decompileCache: the per-program bookkeeping is bounded by the entries",
            "ok   decompileCache: the set-up hash is made from the constants")
    for w in want:
        dt.check(any(ln.startswith(w) for ln in lines), f"self-test check missing or failed: {w}")
    n = sum(1 for ln in lines if ln.startswith("ok"))
    return f"{n} self-test checks held, the E9 ones among them"


# ---- e9_limits_job --------------------------------------------------------------------------

def t_limits_job(c):
    windows_only()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Lim")
    d = c.daemon("e9-lim")
    s3 = s2 = None
    try:
        s3 = c.connect(d, "lim3", "e9", 3)
        s2 = c.connect(d, "lim2", "e9", 2)
        lim = s3.hello["limits"]
        for k, v in (("minXmxMb", 512), ("maxViews", 32), ("maxViewsPerClient", 4),
                     ("heapSoftPct", 70), ("heapHardPct", 85)):
            dt.check(lim.get(k) == v, f"hello.limits.{k} = {lim.get(k)}, expected {v}: {lim}")
        dt.check(lim.get("nativeBudgetMb", 0) > 0, f"{lim}")
        # 3.11: every value of the table is a Settings key and advertised in hello.limits (sizes in MB)
        for k, v in (("viewDiskBudget", 20 * 1024), ("diskReserve", 5 * 1024), ("decompilerIdleS", 60),
                     ("decompilerWaitS", 60), ("decompilerFailLimit", 3), ("decompilerNegativeS", 600)):
            dt.check(lim.get(k) == v, f"hello.limits.{k} = {lim.get(k)}, expected {v}: {lim}")
        dt.check("decompilerPermits" not in lim, "decompilerPermits is derived, not a setting")
        dt.check(s3.hello["capabilities"].get("admission") == 1, f"{s3.hello['capabilities']}")
        dt.check("limits" not in s2.hello and "capabilities" not in s2.hello,
                 "a protocol 2 hello gained keys")
        h = s3.call("health")
        pj = h["processJob"]
        dt.check(pj["own"] is True and pj["state"] == "own", f"health.processJob: {pj}")
        dt.check(isinstance(pj["inCallerJob"], bool) and h["pid"] in pj["pids"], f"{pj}")
        g = h["governor"]
        for k in ("views", "maxViews", "heapAfterGcMb", "heapState", "decompilers", "tokens",
                  "nativeBudgetMb"):
            dt.check(k in g, f"health.governor.{k} missing: {list(g)}")
        dt.check(g["heapState"] == "ok" and g["maxViews"] == 32 and g["views"] == 0, f"{g}")
        dt.check(h["state"] == "ok", f"state {h['state']}")
        h2 = s2.call("health")
        dt.check("governor" in h2 and h2["processJob"]["own"] is True,
                 "health at protocol 2 lost the E9 figures")
        # a decompiler spawned later is in the job (children inherit it, F4: count image names)
        open_view(c, s3, gpr, exe)
        s3.call("decompile", address=bl.first_function(s3))
        pids = decompiler_pids(h["pid"])
        dt.check(len(pids) == 1, f"decompilers below the daemon: {pids}")
        pj = s3.call("health")["processJob"]
        dt.check(pids[0] in pj["pids"], f"the decompiler {pids[0]} is not in the daemon's job {pj['pids']}")
        g = s3.call("health")["governor"]
        dt.check(g["views"] == 1 and g["decompilers"] == 1 and g["decompilersIdle"] == 1, f"{g}")
        return (f"limits {lim}; processJob own, {len(pj['pids'])} members incl. the daemon and its "
                f"decompiler; governor figures present at both protocols")
    finally:
        close_all(s3, s2)
        stop(d)


# ---- e9_job_containment ---------------------------------------------------------------------

def _suspend_and_kill(c, name, vmargs, gpr, exe):
    """Starts a daemon, makes 4 native decompilers, suspends them, TerminateProcess the daemon.
    Returns ``(decompiler pids, seconds until they were gone or None, survivors, processJob, K7 report)``."""
    ch = chaos()
    d = c.daemon(name, vmargs=vmargs)
    sessions = []
    try:
        sessions, fns = warm_decompilers(c, d, gpr, exe, 4)
        h = sessions[0].call("health")
        pid = h["pid"]
        pj = h.get("processJob")          # absent before E9
        pids = decompiler_pids(pid)
        dt.check(len(pids) >= 2, f"{name}: only {len(pids)} decompilers exist: {pids}")
        susp = ch.suspend_decompilers(pid)
        dt.check(sorted(susp) == sorted(pids), f"{name}: suspended {susp} of {pids}")
        for s in sessions:
            with contextlib.suppress(Exception):
                s.close()
        sessions = []
        r = ch.terminate(pid, 20)
        dt.check(r.get("terminated"), f"{name}: TerminateProcess of the daemon: {r}")
        gone = wait_gone(pids, 5.0)
        left = alive_of(pids)
        # X0's oracle (K7, the shape of its planted violation X9): an orphan decompiler after the daemon's death
        k7 = ch.oracle.check_k7_processes(daemon_pids=(), settle_s=0.5, only_pids=pids)
        return pids, gone, left, pj, k7
    finally:
        close_all(*sessions)
        stop(d)


def t_job_containment(c):
    windows_only()
    ch = chaos()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Job")
    # 1. the daemon's own job: suspended decompilers are gone within 5 s of TerminateProcess
    pids, gone, left, pj, k7 = _suspend_and_kill(c, "e9-job", [], gpr, exe)
    try:
        dt.check(gone is not None and not left,
                 f"decompilers {left} of {pids} (suspended) survived TerminateProcess of the daemon by 5 s")
        dt.check(k7.ok, f"the K7 oracle flags the daemon's decompilers: {sorted(k7.codes())}")
    finally:
        for p in left:
            ch.terminate(p, 10)
    dt.check(pj and pj.get("own") is True, f"health.processJob of the daemon: {pj}")
    # 2. the no-job control: the same steps, ProcessJob off: the survivors must be there (the test is RED
    #    without the job), and are ended here
    gpr2 = c.copy_fixture("e9Job2")
    cpids, cgone, cleft, cpj, ck7 = _suspend_and_kill(c, "e9-nojob", NO_JOB, gpr2, exe)
    try:
        dt.check(cgone is None and len(cleft) == len(cpids),
                 f"the no-job control left {len(cleft)} of {len(cpids)} suspended decompilers: it must "
                 f"leave them all, or the containment test proves nothing")
        dt.check("K7:orphan_decompiler" in ck7.codes(),
                 f"X9: the K7 oracle must flag the no-job survivors as orphan_decompiler, it flagged "
                 f"{sorted(ck7.codes())}")
    finally:
        for p in cleft:
            ch.terminate(p, 10)
    # 3. the fallback sweep (the job unavailable): an orphan of THIS install dies, a foreign copy and a
    #    decompiler with a live parent do not
    install = pathlib.Path(c.a.ghidra)
    real = install / "Ghidra" / "Features" / "Decompiler" / "os" / "win_x86_64" / "decompile.exe"
    dt.check(real.is_file(), f"no decompiler at {real}")
    foreign_dir = c.work / "foreign-install" / "Ghidra" / "Features" / "Decompiler" / "os" / "win_x86_64"
    foreign_dir.mkdir(parents=True, exist_ok=True)
    foreign_exe = foreign_dir / "decompile.exe"
    shutil.copy2(real, foreign_exe)
    # an intermediate Python starts two decompilers; both are suspended (a busy or idle one would exit when
    # its pipe closes) and the intermediate is ended: both are parentless afterwards
    child_code = "\n".join([
        "import subprocess, sys, time",
        "kw = dict(stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
        "p = subprocess.Popen([sys.argv[1]], **kw)",
        "q = subprocess.Popen([sys.argv[2]], **kw)",
        "print(p.pid, q.pid, flush=True)",
        "time.sleep(600)", ""])
    mid = subprocess.Popen([sys.executable, "-I", "-c", child_code, str(real), str(foreign_exe)],
                           stdout=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
    ours_orphan, foreign_orphan = (int(x) for x in mid.stdout.readline().split())
    dt.check(ch.suspend(ours_orphan) and ch.suspend(foreign_orphan), "cannot suspend the planted decompilers")
    ch.terminate(mid.pid, 10)
    mid.wait(10)
    live_parent = ch.spawn_decompiler(c.a.ghidra)          # its parent is this process: alive
    dt.check(ch.suspend(live_parent.pid), "cannot suspend the live-parent decompiler")
    planted = [ours_orphan, foreign_orphan, live_parent.pid]
    d = c.daemon("e9-sweep", vmargs=SWEEP)
    s = None
    try:
        time.sleep(0.5)
        s = c.connect(d, "sweep", "e9", 3)
        pj = s.call("health")["processJob"]
        dt.check(pj["state"] == "unavailable" and pj["own"] is False, f"processJob {pj}")
        sw = pj.get("sweep")
        dt.check(sw and ours_orphan in sw["killed"], f"the sweep did not kill the orphan {ours_orphan}: {sw}")
        dt.check(foreign_orphan not in sw["killed"] and live_parent.pid not in sw["killed"],
                 f"the sweep touched a decompiler it must not: {sw}")
        time.sleep(0.5)
        left = alive_of(planted)
        dt.check(ours_orphan not in left, "the orphan of this install is still alive")
        dt.check(foreign_orphan in left, "another install's decompiler was killed (path match broken)")
        dt.check(live_parent.pid in left, "a decompiler with a live parent was killed")
        sweep_note = f"sweep killed {sw['killed']} of {sw['checked']} decompilers of this install"
    finally:
        close_all(s)
        stop(d)
        for p in (foreign_orphan, live_parent.pid, ours_orphan):
            with contextlib.suppress(Exception):
                ch.terminate(p, 5)
        with contextlib.suppress(Exception):
            live_parent.kill()
    return (f"with the job: {len(pids)} suspended decompilers gone {gone * 1000:.0f} ms after "
            f"TerminateProcess (K7 oracle clean); no-job control: all {len(cpids)} survived 5 s and the K7 oracle "
            f"flagged them orphan_decompiler (X9 shape; red without the job); "
            f"{sweep_note}; foreign copy and live-parent decompiler untouched")


# ---- e9_decompiler_faults -------------------------------------------------------------------

def _load(ss, fns, ref, seconds, results, lock):
    """12 clients decompile in a loop for ``seconds``; each result is recorded as ``("ok"|"wrong"|"err", code)``."""
    stopat = time.time() + seconds

    def load(i):
        n = 0
        while time.time() < stopat:
            a = fns[(i + n) % len(fns)]
            n += 1
            try:
                r = ss[i].call("decompile", address=a, wait=60000)
                ok = r.get("completed") is True and r.get("c") == ref[a]
                rec = ("ok" if ok else "wrong", None)
            except Exception as e:  # noqa: BLE001
                rec = ("err", getattr(e, "code", type(e).__name__))
            with lock:
                results.append(rec)

    ts = [threading.Thread(target=load, args=(i,)) for i in range(len(ss))]
    for t in ts:
        t.start()
    return ts


def t_decompiler_faults(c):
    windows_only()
    ch = chaos()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Flt")
    # the breaker (e9_negative_cache) is out of the way: a function that failed more than three times in a minute
    # would be refused at once and the load would count refusals instead of decompiles
    d = c.daemon("e9-flt", engine={"decompilerFailLimit": 100000, **NO_DCACHE})
    ss = []
    try:
        ss = [c.connect(d, f"load{i}", "e9", 3) for i in range(12)]
        for s in ss:
            open_view(c, s, gpr, exe)
        pid = ss[0].call("health")["pid"]
        fns = [f["address"] for f in ss[0].call("functions", limit=12)["functions"]]
        dt.check(len(fns) >= 4, f"only {len(fns)} functions in the fixture")
        ref = {a: ss[0].call("decompile", address=a)["c"] for a in fns}
        # (a) deterministic: ONE pooled decompiler exists; it is killed; the next request is the one that
        #     fails (exactly one decompiler_failed, retryable), the one after it works with the same text
        pooled = decompiler_pids(pid)
        dt.check(len(pooled) == 1, f"expected one pooled decompiler after the serial warm-up: {pooled}")
        k = ch.terminate(pooled[0], 10)
        dt.check(k.get("terminated"), f"kill -9 of the pooled decompiler: {k}")
        e = dt.expect_error("decompiler_failed", ss[1].call, "decompile", address=fns[0])
        det = e.details or {}
        dt.check(det.get("reason") == "crash" and det.get("retryable") is True, f"details {det}")
        for a in fns[:4]:
            r = ss[1].call("decompile", address=a)
            dt.check(r["c"] == ref[a], f"after the kill {a} decompiles differently")
        fl = ss[0].call("health")["governor"]["failures"]
        dt.check(fl["failures"] == 1, f"one killed decompiler counted as {fl}")
        # (b) 12 clients under load, kill -9 of ONE decompiler (which one is not controlled: a pooled idle
        #     one may never be used again): at most one request fails, with decompiler_failed, and every
        #     other request returns the reference text
        results, lock = [], threading.Lock()
        ts = _load(ss, fns, ref, 7, results, lock)
        time.sleep(3.0)
        victims = decompiler_pids(pid)
        dt.check(len(victims) >= 4, f"under load only {len(victims)} decompilers exist")
        k = ch.terminate(victims[len(victims) // 2], 10)
        dt.check(k.get("terminated"), f"kill -9 of a decompiler: {k}")
        for t in ts:
            t.join(60)
        errs = [r for r in results if r[0] != "ok"]
        dt.check(len(results) > 60, f"only {len(results)} requests under load")
        dt.check(len(errs) <= 1 and all(r == ("err", "decompiler_failed") for r in errs),
                 f"kill -9 of one decompiler during the load: {len(errs)} requests failed, expected at most "
                 f"one decompiler_failed: {errs}")
        one = len(errs)
        # (c) the same load, kill -9 of EVERY decompiler at once: each request that used a dead one fails
        #     alone (decompiler_failed); at least one does (everything that exists is dead: a request
        #     that comes after the kill finds a dead pooled decompiler or waits for a busy one that
        #     dies), at most as many as were killed; nothing else fails or differs
        results, lock = [], threading.Lock()
        ts = _load(ss, fns, ref, 7, results, lock)
        time.sleep(3.0)
        victims = decompiler_pids(pid)
        dt.check(len(victims) >= 4, f"under load only {len(victims)} decompilers exist")
        for p in victims:
            ch.terminate(p, 10)
        for t in ts:
            t.join(60)
        errs = [r for r in results if r[0] != "ok"]
        dt.check(len(results) > 60, f"only {len(results)} requests under load")
        dt.check(1 <= len(errs) <= len(victims) and all(r == ("err", "decompiler_failed") for r in errs),
                 f"kill -9 of all {len(victims)} decompilers during the load: {len(errs)} requests failed, "
                 f"expected 1 to {len(victims)} decompiler_failed: {errs}")
        # SP4: the next requests work, same text (the failed decompilers were disposed, fresh ones made)
        for a in fns[:4]:
            r = ss[1].call("decompile", address=a)
            dt.check(r["c"] == ref[a], f"after the kills {a} decompiles differently")
        h = ss[0].call("health")
        dt.check(h["state"] == "ok", f"state {h['state']}")
        return (f"one pooled decompiler killed: exactly 1 decompiler_failed, then the same text; 12 clients, "
                f"kill -9 of one decompiler: {one} failed (at most 1); of all {len(victims)}: {len(errs)} "
                f"failed (1 to {len(victims)}); every other request identical to the reference")
    finally:
        close_all(*ss)
        stop(d)


def t_decompiler_hang(c):
    windows_only()
    ch = chaos()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Hang")
    d = c.daemon("e9-hang", engine=NO_DCACHE)
    A = B = None
    try:
        A = c.connect(d, "hangA", "e9", 3)
        B = c.connect(d, "hangB", "e9", 3)
        open_view(c, A, gpr, exe)
        open_view(c, B, gpr, exe)
        pid = A.call("health")["pid"]
        fns = [f["address"] for f in A.call("functions", limit=4)["functions"]]
        ref = {a: A.call("decompile", address=a)["c"] for a in fns[:2]}
        pooled = decompiler_pids(pid)
        dt.check(len(pooled) == 1, f"expected exactly one pooled decompiler: {pooled}")
        # the only decompiler is suspended; A borrows it and hangs until its own timeout (6 s)
        susp = ch.suspend_decompilers(pid)
        dt.check(sorted(susp) == sorted(pooled), f"suspended {susp} of {pooled}")
        t0 = time.perf_counter()
        rid = A.send("decompile", address=fns[0], timeout=6, wait=60000, parallel=True)
        time.sleep(1.0)
        # B asks during the hang: the suspended decompiler is borrowed, so B gets a fresh one at once
        tb = time.perf_counter()
        rb = B.call("decompile", address=fns[1], wait=60000)
        took_b = time.perf_counter() - tb
        at = time.perf_counter() - t0
        dt.check(rb["c"] == ref[fns[1]], "the request of the other client differs from the reference")
        dt.check(took_b < 4.0 and at < 5.5,
                 f"the other client's request took {took_b:.1f} s and ended at {at:.1f} s of the 6 s hang: "
                 f"the hang delayed it")
        dt.check(len(decompiler_pids(pid)) == 2, "the other client's request did not get a fresh decompiler")
        e = None
        try:
            A.wait(rid, 60)
        except Exception as ex:  # noqa: BLE001
            e = ex
        took = time.perf_counter() - t0
        dt.check(e is not None and getattr(e, "code", None) == "decompiler_failed",
                 f"the hung decompile ended with {e!r}, expected decompiler_failed")
        det = e.details or {}
        dt.check(det.get("reason") in ("timeout", "crash") and det.get("retryable") is True, f"details {det}")
        dt.check(5.0 <= took < 20, f"the hung decompile took {took:.1f} s for a 6 s timeout")
        for p in susp:
            with contextlib.suppress(Exception):
                ch.terminate(p, 10)
        r = A.call("decompile", address=fns[0])
        dt.check(r["c"] == ref[fns[0]], "the request after the hang differs")
        return (f"a suspended decompiler: the request that borrowed it ended decompiler_failed after "
                f"{took:.1f} s (timeout 6); another client's request made during the hang was answered "
                f"in {took_b:.1f} s by a fresh decompiler; the next request worked")
    finally:
        close_all(A, B)
        stop(d)


# ---- e9_negative_cache ----------------------------------------------------------------------

def t_negative_cache(c):
    windows_only()
    ch = chaos()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Neg")
    d = c.daemon("e9-neg", engine={"decompilerNegativeS": 6, **NO_DCACHE})
    s = None
    try:
        s = c.connect(d, "neg", "e9", 3)
        open_view(c, s, gpr, exe)
        pid = s.call("health")["pid"]
        fns = [f["address"] for f in s.call("functions", limit=4)["functions"]]
        bad, other = fns[0], fns[1]
        ref = s.call("decompile", address=other)["c"]
        codes = []
        for i in range(5):
            s.call("decompile", address=other)                  # one warm decompiler in the pool
            if i < 4:
                for p in decompiler_pids(pid):
                    ch.terminate(p, 10)
            try:
                s.call("decompile", address=bad)
                codes.append("ok")
            except Exception as e:  # noqa: BLE001
                codes.append((e.details or {}).get("reason") if e.code == "decompiler_failed" else e.code)
        dt.check(codes == ["crash", "crash", "crash", "crash", "negative_cache"],
                 f"the 4th failure in a minute must trip the cache and the 5th be refused: {codes}")
        # refused at once, no process spent, other functions fine
        n0 = len(decompiler_pids(pid))
        t0 = time.perf_counter()
        e = dt.expect_error("decompiler_failed", s.call, "decompile", address=bad)
        dt.check(time.perf_counter() - t0 < 1.0 and (e.details or {}).get("negativeCache") is True,
                 f"{e.details}")
        dt.check(len(decompiler_pids(pid)) == n0, "the refused request spawned a decompiler")
        dt.check(s.call("decompile", address=other)["c"] == ref, "another function was affected")
        g = s.call("health")["governor"]["failures"]
        dt.check(g["trips"] == 1 and g["negativeFunctions"] == 1, f"{g}")
        time.sleep(6.5)
        r = s.call("decompile", address=bad)
        dt.check(r.get("completed") is True, "the negative cache did not expire")
        return f"{codes}; refused without a process; expired after decompilerNegativeS; breaker {g}"
    finally:
        close_all(s)
        stop(d)


# ---- e9_gate --------------------------------------------------------------------------------

def t_gate(c):
    windows_only()
    ch = chaos()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Gate")
    # nativeBudgetMb 400 = two permits of 200 MB
    d = c.daemon("e9-gate", engine={"nativeBudgetMb": 400, "decompilerWaitS": 3, **NO_DCACHE})
    ss = []
    try:
        ss = [c.connect(d, f"g{i}", "e9", 3) for i in range(6)]
        for s in ss:
            open_view(c, s, gpr, exe)
        pid = ss[0].call("health")["pid"]
        g = ss[0].call("health")["governor"]
        dt.check(g["gate"]["permits"] == 2 and g["tokens"] == 2, f"gate {g['gate']} tokens {g['tokens']}")
        fns = [f["address"] for f in ss[0].call("functions", limit=6)["functions"]]
        # six clients decompile together: all succeed, never more than two at a time
        errs = []

        def one(i):
            try:
                for n in range(3):
                    ss[i].call("decompile", address=fns[(i + n) % len(fns)], wait=60000)
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        ts = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(120)
        dt.check(not errs, f"{errs[:2]}")
        gate = ss[0].call("health")["governor"]["gate"]
        dt.check(gate["peakInUse"] <= 2 and gate["granted"] >= 18, f"gate {gate}")
        # two hung decompilers take both permits; the third request is refused at decompilerWaitS
        for p in ch.suspend_decompilers(pid):
            pass
        hung = [ss[i].send("decompile", address=fns[i], timeout=120, parallel=True) for i in range(2)]
        time.sleep(1.5)
        t0 = time.perf_counter()
        e = dt.expect_error("busy", ss[2].call, "decompile", address=fns[2], wait=60000)
        took = time.perf_counter() - t0
        dt.check((e.details or {}).get("reason") == "capacity" and e.details.get("resource") == "native",
                 f"details {e.details}")
        dt.check(2.5 < took < 10, f"the wait for a permit took {took:.1f} s (decompilerWaitS 3)")
        gate = ss[3].call("health")["governor"]
        dt.check(gate["gate"]["inUse"] == 2 and gate["tokens"] == 0, f"{gate['gate']}")
        # the hung requests are ended by killing their decompilers; the permits come back
        for p in decompiler_pids(pid):
            ch.terminate(p, 10)
        for i, rid in enumerate(hung):
            with contextlib.suppress(Exception):
                ss[i].wait(rid)
        r = ss[4].call("decompile", address=fns[4], wait=20000)
        dt.check(r.get("completed") is True, "the gate did not recover after the hung requests ended")
        dt.check(ss[4].call("health")["governor"]["gate"]["inUse"] == 0, "a permit leaked")
        return (f"2 permits: peak in use {gate['gate']['peakInUse'] if 'peakInUse' in gate['gate'] else 2}, "
                f"third request refused busy/capacity/native after {took:.1f} s, gate recovered, no permit leaked")
    finally:
        close_all(*ss)
        stop(d)


# ---- e9_idle_dispose ------------------------------------------------------------------------

def t_idle_dispose(c):
    windows_only()
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Idle")
    d = c.daemon("e9-idle", engine={"decompilerIdleS": 3})
    s = None
    try:
        s = c.connect(d, "idle", "e9", 3)
        open_view(c, s, gpr, exe)
        s.call("decompile", address=bl.first_function(s))
        pid = s.call("health")["pid"]
        dt.check(len(decompiler_pids(pid)) == 1, "no pooled decompiler after a decompile")
        dt.check(s.call("health")["governor"]["decompilersIdle"] == 1, "decompilersIdle")
        gone = dt.wait_for(lambda: not decompiler_pids(pid), "the idle decompiler to be disposed", 30, 0.25)
        dt.check(gone and s.call("health")["governor"]["decompilersIdle"] == 0, "pool not empty")
        r = s.call("decompile", address=bl.first_function(s))
        dt.check(r.get("completed") is True, "the next decompile after disposal failed")
        return "an idle pooled decompiler was disposed after decompilerIdleS; the next decompile worked"
    finally:
        close_all(s)
        stop(d)


# ---- admission ------------------------------------------------------------------------------

def _views(c, d, n_clients, per_client, exe, tag):
    """``n_clients`` clients each open ``per_client`` copies of the fixture, one after the other.
    Returns ``(sessions, opened, refused details list, other errors)``."""
    ss = [c.connect(d, f"{tag}{i}", "e9", 3) for i in range(n_clients)]
    opened, refused, other = 0, [], []
    for i, s in enumerate(ss):
        for j in range(per_client):
            gpr = c.copy_fixture(f"{tag}-{i}-{j}")
            try:
                open_view(c, s, gpr, exe)
                opened += 1
            except Exception as e:  # noqa: BLE001
                det = getattr(e, "details", None) or {}
                if getattr(e, "code", None) == "busy" and det.get("reason") == "capacity":
                    refused.append(det)
                else:
                    other.append(f"{type(e).__name__}: {e}")
    return ss, opened, refused, other


def _daemon_log(d):
    try:
        return d.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def t_admission_256(c):
    exe = fixture_args(c)
    d = c.daemon("e9-a256", maxHeap="256m", minHeap="128m", keepWarm=2,
                 engine={"minXmxMb": 0, "maxViewsPerClient": 8})
    ss = []
    try:
        pre = c.connect(d, "ballast", "e9", 3)
        # The heap rule admits a view iff heapAfterGc + 1.5 x estimate (8 MB) <= 70% of 256 MB = 179 MB, so a view
        # is admitted up to a live heap of about 167 MB. What a view really costs is not the test's business
        # (shared pages, off-heap tables and lazy structures made it a few hundred KB, where it was once 6 MB or
        # more: 24 views no longer fill a 256 MB heap by themselves). The pressure is therefore forced, in two
        # phases that do not depend on that footprint:
        #   A. with a live heap of 100 MB there is room, and 12 views are admitted (a refusal here would be a
        #      false positive of the rule);
        #   B. the ballast is raised to 190 MB, which is over the limit whatever the 12 views cost (190 + 12 > 179
        #      and 190 < 217 MB, the hard watermark, so the daemon is not degraded): the next 12 views must all be
        #      refused busy/capacity/heap, with nothing worse than that.
        ballast(c, pre, 100)
        ss, opened, refused, other = _views(c, d, 3, 4, exe, "a256a")
        dt.check(not other and not refused and opened == 12,
                 f"-Xmx256m with room (live heap 100 MB): {opened} of 12 views opened, refused {refused[:2]}, "
                 f"errors {other[:3]}")
        ballast(c, pre, 190)
        pre.close()
        ss_b, opened_b, refused, other = _views(c, d, 3, 4, exe, "a256b")
        ss += ss_b
        opened += opened_b
        h = ss[0].call("health")
        log = _daemon_log(d)
        dt.check(not other, f"errors other than busy/capacity: {other[:3]}")
        dt.check(opened_b == 0 and len(refused) == 12,
                 f"24 views at -Xmx256m with the live heap at 190 MB: {opened_b} of the last 12 opened, "
                 f"{len(refused)} refused; governor {h.get('governor')}")
        dt.check(all(r.get("resource") in ("heap", "views") for r in refused), f"{refused[:2]}")
        dt.check(h["governor"]["refused"]["heap"] >= 12, f"refusals not counted: {h['governor']['refused']}")
        dt.check("OutOfMemoryError" not in log, "OutOfMemoryError in the daemon log")
        dt.check(h["memory"]["maxMb"] <= 260, f"heap {h['memory']}")
        # the guarded threads are alive and beating (alive is the thread object, the beat a lap of its body;
        # that a Throwable restarts them is e9_guarded_threads' claim, with a planted fault)
        th = h["governor"]["threads"]
        ts = h["governor"]["threadState"]
        for name in GUARDED:
            dt.check(name in ts and ts[name]["alive"] is True and ts[name]["stale"] is False,
                     f"guarded thread {name} not alive and beating: {ts.get(name)}")
        dt.check(h["state"] in ("ok", "degraded"), f"state {h['state']}")
        return (f"-Xmx256m: {opened} of 24 views opened (12 with room, 0 of 12 once the live heap is 190 MB), "
                f"{len(refused)} refused busy/capacity ({sorted({r['resource'] for r in refused})}); 0 "
                f"OutOfMemoryError; guarded threads {th}; heapAfterGc {h['governor']['heapAfterGcMb']} MB, "
                f"state {h['state']}")
    finally:
        close_all(*ss)
        stop(d)


def t_admission_512(c):
    exe = fixture_args(c)
    d = c.daemon("e9-a512", maxHeap="512m", minHeap="256m", engine={"maxViewsPerClient": 8})
    ss = []
    try:
        ss, opened, refused, other = _views(c, d, 6, 4, exe, "a512")
        h = ss[0].call("health")
        dt.check(not other and not refused and opened == 24,
                 f"-Xmx512m with 24 views: {opened} opened, refused {refused[:2]}, errors {other[:3]}; "
                 f"governor {h['governor']}")
        dt.check("OutOfMemoryError" not in _daemon_log(d), "OutOfMemoryError in the log")
        # all 24 views answer
        for s in ss:
            dt.check(s.call("info").get("name"), "info on a view")
        return (f"-Xmx512m: 24 of 24 views open and answer; heapAfterGc {h['governor']['heapAfterGcMb']} MB, "
                f"state {h['state']}, learned {h['governor'].get('learned')}")
    finally:
        close_all(*ss)
        stop(d)


def t_view_probe(c):
    exe = fixture_args(c)
    base = c.copy_fixture("probeBase")
    d = c.daemon("e9-probe", engine={"maxViewsPerClient": 200})
    ss = []
    try:
        s = c.connect(d, "probe", "e9", 3)
        ss.append(s)
        opened, refused = 0, None
        for i in range(100):
            gpr = base if i == 0 else c.copy_fixture(f"probe-{i}")
            try:
                open_view(c, s, gpr, exe)
                opened += 1
            except Exception as e:  # noqa: BLE001
                det = getattr(e, "details", None) or {}
                dt.check(getattr(e, "code", None) == "busy" and det.get("reason") == "capacity",
                         f"view {i}: {type(e).__name__}: {e}")
                refused = det
                break
        dt.check(opened == 32 and refused and refused.get("resource") == "views" and
                 refused.get("have") == 32 and refused.get("need") == 32,
                 f"opened {opened}, refused {refused}")
        dt.check(refused.get("retryAfterMs", 0) >= 250, f"{refused}")
        g = s.call("health")["governor"]
        dt.check(g["views"] == 32 and g["refused"]["views"] >= 1, f"{g}")
        # closing one makes room
        s.call("close_program")
        gpr = c.copy_fixture("probe-after")
        open_view(c, s, gpr, exe)
    finally:
        close_all(*ss)
        stop(d)
    # the per-client cap, and sharing
    d = c.daemon("e9-cap")
    A = B = None
    try:
        A = c.connect(d, "capA", "e9", 3)
        B = c.connect(d, "capB", "e9", 3)
        gprs = [c.copy_fixture(f"cap-{i}") for i in range(5)]
        for g in gprs[:4]:
            open_view(c, A, g, exe)
        e = dt.expect_error("busy", open_view, c, A, gprs[4], exe)
        det = e.details or {}
        dt.check(det.get("reason") == "capacity" and det.get("resource") == "client_cap" and
                 det.get("have") == 4 and det.get("need") == 4, f"{det}")
        # another client has room, and joining a program A already holds costs no view
        open_view(c, B, gprs[4], exe)
        before = B.call("health")["governor"]["views"]
        B.call("open_project", path=str(gprs[0]))
        B.call("open_program", path=exe)
        after = B.call("health")["governor"]["views"]
        dt.check(before == after == 5, f"sharing counted a view again: {before} -> {after}")
        return ("100-view probe: 32 opened, the 33rd refused busy/capacity/views (have 32, need 32), one close "
                "made room; client_cap refused the 5th view of one client at 4; a shared program counted once")
    finally:
        close_all(A, B)
        stop(d)


def t_degraded(c):
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Deg")
    gpr2 = c.copy_fixture("e9Deg2")
    d = c.daemon("e9-deg", maxHeap="512m", minHeap="256m", engine={"heapSoftPct": 10, "heapHardPct": 11})
    s = None
    try:
        s = c.connect(d, "deg", "e9", 3)
        ballast(c, s, 100)
        h = dt.wait_for(lambda: (lambda x: x if x["governor"]["heapState"] == "hard" else None)(s.call("health")),
                        "heapState hard (a 512 MB heap holds more than 11% after a collection)", 30, 0.5)
        dt.check(h["state"] == "degraded", f"state {h['state']}")
        e = dt.expect_error("busy", s.call, "open_project", path=str(gpr))
        dt.check((e.details or {}).get("reason") == "capacity" and e.details.get("resource") == "heap" and
                 "degraded" in str(e), f"{e.details} {e}")
        dt.expect_error("busy", s.call, "fork_project", project=str(gpr), path=str(gpr2.parent / "forked"))
        # reads and ping keep working
        dt.check(s.call("ping").get("pong") is True and s.call("status") is not None, "status/ping")
        dt.check(s.call("health")["governor"]["refused"]["heap"] >= 2, "refusals not counted")
        return f"degraded above the hard watermark: opens and forks refused busy/capacity/heap; ping, status, health answer"
    finally:
        close_all(s)
        stop(d)


def t_minxmx(c):
    d = c.daemon("e9-minx", maxHeap="256m", minHeap="128m")
    try:
        try:
            d.connect("minx", "e9").close()
        except Exception as e:  # noqa: BLE001
            msg = str(e) + _daemon_log(d)
            dt.check("minXmxMb" in msg, f"the refusal does not name minXmxMb: {msg[-600:]}")
        else:
            raise dt.Fail("a daemon with -Xmx256m started although minXmxMb is 512")
        dt.check(not d.jvm_alive(), "a JVM is running after the refusal")
    finally:
        stop(d)
    d = c.daemon("e9-minx2", maxHeap="256m", minHeap="128m", engine={"minXmxMb": 0})
    s = None
    try:
        s = c.connect(d, "minx2", "e9", 3)
        dt.check(s.call("health")["memory"]["maxMb"] <= 260, "forced small heap")
        return "-Xmx256m refused at start-up naming minXmxMb; minXmxMb=0 forces it"
    finally:
        close_all(s)
        stop(d)


def _tree_bytes(p):
    return sum(f.stat().st_size for f in pathlib.Path(p).rglob("*") if f.is_file())


def t_disk(c):
    exe = fixture_args(c)
    gpr = c.copy_fixture("e9Disk")
    size = _tree_bytes(gpr.parent / "Fixture.rep")
    out = c.work / "forks"
    out.mkdir(exist_ok=True)
    # a reserve nothing can meet: the fork is refused before any copy is made
    d = c.daemon("e9-disk1", engine={"diskReserve": "9000000GB"})
    s = None
    try:
        s = c.connect(d, "disk1", "e9", 3)
        e = dt.expect_error("busy", s.call, "fork_project", project=str(gpr), path=str(out / "nofit"),
                            purpose="view", owner="agent-e9")
        det = e.details or {}
        dt.check(det.get("reason") == "capacity" and det.get("resource") == "disk" and
                 det.get("need", 0) > det.get("have", 1), f"{det}")
        dt.check(not (out / "nofit").exists(), "the refused fork left a folder")
    finally:
        close_all(s)
        stop(d)
    # a view budget of 1.5 forks: the first fits, the second is refused
    budget = int(size * 1.5)
    d = c.daemon("e9-disk2", engine={"viewDiskBudget": f"{budget}B"})
    try:
        s = c.connect(d, "disk2", "e9", 3)
        r = s.call("fork_project", project=str(gpr), path=str(out / "v1"), purpose="view", owner="agent-e9")
        e = dt.expect_error("busy", s.call, "fork_project", project=str(gpr), path=str(out / "v2"),
                            purpose="view", owner="agent-e9")
        det = e.details or {}
        dt.check(det.get("reason") == "capacity" and det.get("resource") == "disk", f"{det}")
        # deleting the first fork makes room again
        shutil.rmtree(out / "v1", ignore_errors=True)
        s.call("fork_project", project=str(gpr), path=str(out / "v3"), purpose="view", owner="agent-e9")
        return (f"a reserve that cannot be met refuses the fork (need {det.get('need')} MB); viewDiskBudget "
                f"{budget} B: second view fork refused, room again after the first was deleted")
    finally:
        close_all(s)
        stop(d)


# ---- e9_guarded_threads ---------------------------------------------------------------------

GUARDED = ("session-accept", "session-reaper", "session-governor")


def _thread_states(s):
    return s.call("health")["governor"]["threadState"]


def t_guarded_threads(c):
    # keepWarm 2 s: the reaper's lap is 1 s (a quarter of keepWarm, at least 1 s)
    d = c.daemon("e9-thr", keepWarm=2, vmargs=HOOKS)
    s = None
    try:
        s = c.connect(d, "thr", "e9", 3)
        st = _thread_states(s)
        for name in GUARDED:
            dt.check(name in st, f"health.governor.threadState has no {name}: {sorted(st)}")
            dt.check(st[name]["alive"] is True and st[name]["stale"] is False and st[name]["restarts"] == 0,
                     f"{name} at start: {st[name]}")
        # the reaper and the governor beat once per lap: the figure moves
        for name in ("session-reaper", "session-governor"):
            dt.check(st[name]["beatEveryMs"] > 0, f"{name} gives no lap period: {st[name]}")
        dt.wait_for(lambda: all(_thread_states(s)[n]["lastBeatAgoMs"] <= 2500 and
                                _thread_states(s)[n]["lastBeatAgoMs"] < st[n]["lastBeatAgoMs"] + 1
                                for n in ("session-reaper", "session-governor")) or None,
                    "the reaper and the governor to beat", 20, 0.3)
        # an unknown thread is refused
        dt.expect_error("bad_request", s.call, "debug_stall", what="thread", thread="no-such-thread")
        # a Throwable in one lap of each thread: it is restarted, counted, alive, and keeps working
        for name in ("session-reaper", "session-governor"):
            before = _thread_states(s)[name]["restarts"]
            r = s.call("debug_stall", what="thread", thread=name, error="runtime")
            dt.check(r.get("planted") == "runtime", f"{r}")
            now = dt.wait_for(lambda: (lambda x: x if x[name]["restarts"] > before else None)(_thread_states(s)),
                              f"{name} to be restarted after a planted RuntimeException", 30, 0.25)
            dt.check(now[name]["alive"] is True and now[name]["restarts"] == before + 1,
                     f"{name} after the planted fault: {now[name]}")
            # it must go on beating well after the restart (a thread that ran once more and ended would
            # still show a fresh beat for a moment)
            time.sleep(3.5)
            st = _thread_states(s)[name]
            dt.check(st["alive"] is True and st["lastBeatAgoMs"] <= 2500 and not st["stale"],
                     f"{name} 3.5 s after its restart is not alive and beating: {st}")
            dt.check(s.call("health")["governor"]["threads"][name] == before + 1, "threads counter disagrees")
        # an OutOfMemoryError in the reaper: the emergency reserve is released, the thread runs again,
        # the governor arms the reserve again (the heap is far below the soft watermark)
        g0 = s.call("health")["governor"]
        if g0["reserve"]["armed"]:
            before = g0["threads"]["session-reaper"]
            s.call("debug_stall", what="thread", thread="session-reaper", error="oom")
            dt.wait_for(lambda: s.call("health")["governor"]["threads"]["session-reaper"] > before or None,
                        "the reaper to be restarted after a planted OutOfMemoryError", 30, 0.25)
            g1 = s.call("health")["governor"]
            dt.check(g1["reserve"]["released"] == g0["reserve"]["released"] + 1, f"reserve {g1['reserve']}")
            dt.wait_for(lambda: s.call("health")["governor"]["reserve"]["armed"] or None,
                        "the governor to arm the emergency reserve again", 30, 0.25)
            dt.check(_thread_states(s)["session-reaper"]["alive"] is True, "the reaper is gone after the OOM")
        # the acceptor: the next connection is dropped by the planted fault, the thread restarts, a new
        # connection works
        before = _thread_states(s)["session-accept"]["restarts"]
        s.call("debug_stall", what="thread", thread="session-accept", error="runtime")
        dropped = None
        try:
            dropped = c.connect(d, "dropped", "e9", 3)
            dropped.call("ping")
        except Exception as e:  # noqa: BLE001
            dropped = None
            note = type(e).__name__
        else:
            note = "served"
        if dropped is not None:
            close_all(dropped)
        now = dt.wait_for(lambda: (lambda x: x if x["session-accept"]["restarts"] > before else None)(_thread_states(s)),
                          "the acceptor to be restarted after a planted fault", 30, 0.25)
        dt.check(now["session-accept"]["alive"] is True, f"{now['session-accept']}")
        again = None
        for i in range(10):
            try:
                again = c.connect(d, f"again{i}", "e9", 3)
                again.call("ping")
                break
            except Exception:  # noqa: BLE001
                again = None
                time.sleep(0.5)
        dt.check(again is not None, "no new connection was accepted after the acceptor restarted")
        close_all(again)
        final = _thread_states(s)
        dt.check(all(final[n]["alive"] and not final[n]["stale"] for n in GUARDED), f"{final}")
        return (f"accept, reaper and governor threads alive and beating; a planted RuntimeException restarted "
                f"each (restarts {[final[n]['restarts'] for n in GUARDED]}); an OutOfMemoryError released the "
                f"reserve and the governor armed it again; the acceptor served a new connection "
                f"(the one hit by the fault: {note})")
    finally:
        close_all(s)
        stop(d)


# ---- e9_concurrent_open ---------------------------------------------------------------------

def _together(fns):
    """Runs the callables at the same moment (a barrier); returns their results or exceptions."""
    bar = threading.Barrier(len(fns))
    out = [None] * len(fns)

    def run(i):
        bar.wait()
        try:
            out[i] = ("ok", fns[i]())
        except Exception as e:  # noqa: BLE001
            out[i] = ("err", e)

    ts = [threading.Thread(target=run, args=(i,)) for i in range(len(fns))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(180)
    return out


def t_concurrent_open(c):
    exe = fixture_args(c)
    # 16 clients, one program each, all at once, room for 4 views
    d = c.daemon("e9-cv", engine={"maxViews": 4, "maxViewsPerClient": 4})
    ss = []
    try:
        n = 16
        ss = [c.connect(d, f"cv{i}", "e9", 3) for i in range(n)]
        for i, s in enumerate(ss):
            s.call("open_project", path=str(c.copy_fixture(f"cv{i}")))
        res = _together([(lambda s=s: s.call("open_program", path=exe)) for s in ss])
        ok = [r for r in res if r[0] == "ok"]
        errs = [r[1] for r in res if r[0] == "err"]
        codes = sorted({(getattr(e, "code", None), (getattr(e, "details", None) or {}).get("resource")) for e in errs})
        g = ss[0].call("health")["governor"]
        dt.check(len(ok) == 4 and all(e.code == "busy" for e in errs),
                 f"maxViews 4, {n} clients opening at once: {len(ok)} opened, refusals {codes}; governor {g}")
        dt.check(g["views"] == 4 and g["reserved"] == 0, f"governor after the opens: {g}")
        dt.check(all(r.details.get("reason") == "capacity" for r in errs), "a refusal without reason capacity")
    finally:
        close_all(*ss)
        stop(d)
    # one client, 6 projects, 6 open_program requests in flight together, room for 2 per client
    d = c.daemon("e9-cc", engine={"maxViews": 32, "maxViewsPerClient": 2})
    s = None
    try:
        s = c.connect(d, "cc", "e9", 3)
        gprs = [c.copy_fixture(f"cc{i}") for i in range(6)]
        for g in gprs:
            s.call("open_project", path=str(g))
        rids = [s.send("open_program", path=exe, project=str(g), parallel=True) for g in gprs]
        out = []
        for rid in rids:
            try:
                out.append(("ok", s.wait(rid, 120)))
            except Exception as e:  # noqa: BLE001
                out.append(("err", e))
        ok = [r for r in out if r[0] == "ok"]
        errs = [r[1] for r in out if r[0] == "err"]
        held = len(s.call("programs").get("programs", []))
        dt.check(len(ok) == 2 and all(getattr(e, "code", None) == "busy" and
                                      (e.details or {}).get("resource") == "client_cap" for e in errs),
                 f"maxViewsPerClient 2, 6 opens at once: {len(ok)} opened ({held} listed), "
                 f"{[(getattr(e, 'code', None), (getattr(e, 'details', None) or {}).get('resource')) for e in errs]}")
        return ("maxViews 4: 16 clients opening at once, exactly 4 admitted, 12 busy/capacity, governor.views 4 and "
                "no reservation left; maxViewsPerClient 2: 6 opens in flight, exactly 2 admitted (client_cap)")
    finally:
        close_all(s)
        stop(d)


# ---- e9_runaway -----------------------------------------------------------------------------

def t_runaway(c):
    exe = fixture_args(c)
    (c.scripts / "E9Deaf.java").write_text(DEAF)
    d = c.daemon("e9-run", engine={"scriptMaxS": 2, "scriptGraceS": 1})
    s = None
    try:
        s = c.connect(d, "runaway", "e9", 3)
        s.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=60000)
        rid = s.send("script", script=c.script("E9Deaf.java"), program=None, args=["9000"], parallel=True,
                     wait=60000)
        h = dt.wait_for(lambda: (lambda x: x if x["leakedWorkers"] >= 1 else None)(s.call("health")),
                        "the deaf script to be quarantined", 30, 0.25)
        dt.check(h["leakedWorkers"] == 1, f"leakedWorkers {h['leakedWorkers']}")
        e = dt.expect_error("busy", s.call, "script", script=c.script("TestSleep.java"), program=None,
                            args=["1"], wait=2000)
        dt.check((e.details or {}).get("reason") == "runaway_quarantined", f"{e.details}")
        dt.check(s.call("ping").get("pong") is True, "ping")
        with contextlib.suppress(Exception):
            s.wait(rid)
        gone = dt.wait_for(lambda: s.call("health")["leakedWorkers"] == 0, "the count to fall", 30, 0.25)
        return "a script that ignores cancel: leakedWorkers 1, its owner's next script runaway_quarantined, count back to 0 when it ended"
    finally:
        close_all(s)
        stop(d)


TESTS = {
    "e9_selftest": t_selftest,
    "e9_limits_job": t_limits_job,
    "e9_job_containment": t_job_containment,
    "e9_decompiler_faults": t_decompiler_faults,
    "e9_decompiler_hang": t_decompiler_hang,
    "e9_guarded_threads": t_guarded_threads,
    "e9_concurrent_open": t_concurrent_open,
    "e9_negative_cache": t_negative_cache,
    "e9_gate": t_gate,
    "e9_idle_dispose": t_idle_dispose,
    "e9_admission_256": t_admission_256,
    "e9_admission_512": t_admission_512,
    "e9_view_probe": t_view_probe,
    "e9_degraded": t_degraded,
    "e9_minxmx": t_minxmx,
    "e9_disk": t_disk,
    "e9_runaway": t_runaway,
}

BASELINE = {}
