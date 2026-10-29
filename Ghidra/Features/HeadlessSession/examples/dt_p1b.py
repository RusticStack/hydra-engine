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
"""The launcher (PROTOCOL-3.md, section 8, package P1b; decisions D60 and D65; spike SP3 (a)).

``support/ghidra_session.py`` gets structured launch errors, a client-side deadline, a registry of
daemons with a singleton policy, ``Daemon.health()`` and ``Daemon.attach()``, the
``--enable-native-access`` JVM flag, and a launch sequence that makes the daemon outlive the harness
that started it even when that harness runs in a kill-on-close Job Object (D65). P1b owns no Job
Object: containment is the daemon's own (E9).

Tests:

* ``p1b_launch_errors``  each failure of a start is a ``LaunchError`` with a ``code`` and
  ``details``: ``no_jdk``, ``jdk_too_old`` (a JDK below the install's Java range), ``bad_install``,
  ``heap_too_large`` (an explicit ``maxHeap`` above the free memory), ``lock_held`` (the start lock
  is held), ``exited_early`` (the JVM ends at once; the log tail is in the details) and
  ``no_answer`` (the daemon is not up within the timeout).
* ``p1b_duplicate_daemon``  a second daemon of the same install under another state dir: the
  default policy ``warn`` starts it and puts a ``duplicate_daemon`` warning in the connect result;
  ``singleton: "per-install"`` raises ``DuplicateDaemonError`` (holder, three ways out) and starts
  nothing. The registry entry has the documented name and fields, a stopped daemon is not live,
  and the same state dir is never a duplicate. Also ``Daemon.health()`` and ``Daemon.attach()``.
* ``p1b_call_deadline``  against a fake engine that never answers: ``call(deadline=)`` sends
  ``cancel target=<id>``, raises ``deadline_exceeded``, drops the late answers, survives a
  timeout in the middle of a line, and the connection keeps working. Against the real engine: a
  hung script is cancelled (it ends long before it would have) and the connection survives.
* ``p1b_concurrent_launchers``  N processes call ``connect`` at once on one root: exactly one
  starts the daemon, all get the same pid, one JVM per root (two roots in parallel).
* ``p1b_wedged_connect``  a real daemon is suspended (NtSuspendProcess): ``connect(timeout=3)``
  and ``attach`` raise ``no_answer`` in well under 15 s, ``connect(timeout=12)`` ends as
  ``no_answer`` in about 12 s (covers ``_wait_ready``), ``status()`` returns ``None`` and
  ``stop(timeout=3)`` returns ``False`` in about 5 s, instead of waiting for a ``hello`` that
  never comes; resumed, ``stop(force=True)`` ends the daemon.
* ``p1b_stop_shutdown_deadline``  a fake engine answers ``hello`` and never ``shutdown``:
  ``stop()`` does not block on the call (it ends in ``LaunchError`` after the deadline and the
  wait for the exit).
* ``p1b_children_of_threads``  ``_children_of`` (the WMI route's lookup of the JVM under ``cmd.exe``)
  called from several threads at once never fails with ``expected LP_PE32 instance instead of
  pointer to PE32`` (the structure class is made once, not per call; integration check V3,
  ``e2a_kill_fork``: two workers restart daemons at the same time).
* ``p1b_breakaway_probe``  the rule that skips case D below: ``breakaway_blocked`` is True only for
  the access-denied answer (WinError 5) of a job that refuses ``CREATE_BREAKAWAY_FROM_JOB``.
* ``p1b_native_access_flag``  the JVM command line carries ``--enable-native-access=ALL-UNNAMED``
  once, also when launch.properties or ``vmargs`` already carry it, and not for
  ``--enable-native-access=java.base``.
* ``p1b_daemon_survives_launcher_exit``  SP3 (a), with the real launcher and the real daemon: the
  launcher runs in a kill-on-close job (A) with breakaway rights: ``spawn:"breakaway"``; (B) without:
  breakaway fails with WinError 5, ``spawn:"wmi"``; (C) negative control, B with the WMI and task
  routes switched off: ``spawn:"stayed"``, ``survival:"bound_to_harness"``, the warning
  ``daemon_dies_with_harness``, and the daemon is **dead** after the job is closed (a daemon that
  survives fails the test: the job, not luck, decides); (D) no job: ``spawn:"detached"``; (E) B
  with the WMI route off: ``spawn:"task"``; (N) the revision 6 design, a launcher-owned job, kills
  the daemon. A, B, D, E: the daemon answers after the harness is gone and was never in the
  harness's job. Windows only.

Cases D and N need a launcher that may break away from the job the test runs in. In a job that
refuses breakaway (WinError 5 on a probe: a restricted harness, the hosted CI runner) they are
SKIPPED with that reason and the test ends as SKIP, never as ok (the cases that ran are named in the
note); they are never loosened.

Environment: ``P1B_SURVIVAL`` (comma list of case letters, default ``A,B,C,D,E,N``).
"""
import contextlib
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent
IS_WINDOWS = os.name == "nt"
Fail = dt.Fail
check = dt.check


# ---- helpers ----------------------------------------------------------------------------------

@contextlib.contextmanager
def user_root(path):
    """GHIDRA_SESSION_HOME for this block: the launcher's default state root, where the registry
    lives. The registry of the real user is never touched."""
    old = os.environ.get("GHIDRA_SESSION_HOME")
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    os.environ["GHIDRA_SESSION_HOME"] = str(path)
    try:
        yield pathlib.Path(path)
    finally:
        if old is None:
            os.environ.pop("GHIDRA_SESSION_HOME", None)
        else:
            os.environ["GHIDRA_SESSION_HOME"] = old


@contextlib.contextmanager
def patched(obj, **attrs):
    old = {k: getattr(obj, k) for k in attrs}
    for k, v in attrs.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(obj, k, v)


def fresh_dir(c, name):
    d = c.work / f"p1b-{name}-{os.getpid()}-{int(time.time())}"
    if d.exists():
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


def fresh_state(c, base, name="state"):
    """A state dir with its own config.json (tmpdir in the test's work dir)."""
    st = base / name
    st.mkdir(parents=True, exist_ok=True)
    tmp = base / "tmp"
    tmp.mkdir(exist_ok=True)
    (st / "config.json").write_text(json.dumps({"tmpdir": str(tmp), "keepWarm": 60}))
    return st


def raises_launch(code, fn, what):
    try:
        fn()
    except c_launch_error() as e:
        check(getattr(e, "code", None) == code, f"{what}: code {getattr(e, 'code', None)!r}, "
                                                 f"expected {code!r}: {e}")
        return e
    except Exception as e:  # noqa: BLE001
        raise Fail(f"{what}: expected LaunchError {code}, got {type(e).__name__}: {e}") from e
    raise Fail(f"{what}: expected LaunchError {code}, nothing was raised")


_GS = {}


def c_launch_error():
    return _GS["gs"].LaunchError


def stop_quietly(d):
    with contextlib.suppress(Exception):
        if d.jvm_alive():
            d.stop(force=True, timeout=60)
    with contextlib.suppress(Exception):
        if d.jvm_alive():
            d.kill()


def fake_jdk(base, major):
    """A directory that find_jdk accepts as a JDK of the given major version (it reads only the
    ``release`` file and looks for java and javac)."""
    home = base / f"fake-jdk-{major}"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    (home / "release").write_text(f'JAVA_VERSION="{major}.0.1"\n')
    for exe in ("java.exe", "javac.exe", "java", "javac"):
        (home / "bin" / exe).write_text("")
    return home


# ---- p1b_launch_errors ------------------------------------------------------------------------

def t_launch_errors(c):
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "errors")
    inst = gs.Install.locate(c.a.ghidra)
    seen = {}
    check(hasattr(gs, "LAUNCH_CODES"), "ghidra_session.LAUNCH_CODES is missing")
    for code in ("no_jdk", "jdk_too_old", "bad_install", "lock_held", "heap_too_large",
                 "exited_early", "no_answer", "duplicate_daemon"):
        check(code in gs.LAUNCH_CODES, f"{code} is not in LAUNCH_CODES")
    check(issubclass(gs.LaunchError, RuntimeError), "LaunchError must stay a RuntimeError")

    # no_jdk: nothing to find (no env, nothing on PATH, no saved JDK)
    empty = base / "empty-settings"
    empty.mkdir()
    saved = {k: os.environ.pop(k, None) for k in ("JAVA_HOME", "GHIDRA_SESSION_JAVA_HOME")}
    try:
        with patched(gs.shutil, which=lambda *a, **k: None), \
                patched(gs.Install, settings_dir=lambda self, vm: empty):
            e = raises_launch("no_jdk", lambda: gs.find_jdk(
                inst, None, {"vmargs": [], "java_home_override": ""}), "no JDK at all")
            check(e.details.get("javaMin") == inst.java_min and e.details.get("tried") == [],
                  f"no_jdk details: {e.details}")
            not_jdk = base / "not-a-jdk"
            not_jdk.mkdir()
            e = raises_launch("no_jdk", lambda: gs.find_jdk(
                inst, str(not_jdk), {"vmargs": [], "java_home_override": ""}), "not a JDK")
            check(len(e.details.get("tried", [])) == 1 and "not a JDK" in e.details["tried"][0],
                  f"no_jdk tried[]: {e.details}")
            seen["no_jdk"] = e.details["javaMin"]

            # jdk_too_old: a real-looking JDK below the install's range ("JDK 21 against 25")
            old = fake_jdk(base, inst.java_min - 1)
            e = raises_launch("jdk_too_old", lambda: gs.find_jdk(
                inst, str(old), {"vmargs": [], "java_home_override": ""}), "JDK below range")
            check(e.details.get("javaMin") == inst.java_min
                  and f"Java {inst.java_min - 1}.0.1" in " ".join(e.details.get("tried", [])),
                  f"jdk_too_old details: {e.details}")
            check(e.details.get("found") and e.details["found"][0]["version"].startswith(
                str(inst.java_min - 1)), f"jdk_too_old found[]: {e.details}")
            seen["jdk_too_old"] = f"{inst.java_min - 1} < {inst.java_min}"

            # the same through a start (no other JDK to fall back on): nothing is spawned
            st = fresh_state(c, base)
            d = gs.Daemon(c.a.ghidra, str(st), "p1b-jdk", java=str(old))
            c.daemons.append(d)
            raises_launch("jdk_too_old", lambda: d.connect("t", "p1b", timeout=30),
                          "connect, old JDK")
            check(not d.jvm_alive() and not d.read_endpoint(),
                  "a daemon was started in spite of the error")
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    # bad_install
    bad = base / "no-install"
    bad.mkdir()
    e = raises_launch("bad_install", lambda: gs.Install(bad), "empty directory as an install")
    check(e.details.get("path") == str(bad.resolve()) and e.details.get("missing"),
          f"bad_install details: {e.details}")
    seen["bad_install"] = "ok"

    # heap_too_large: an explicit maxHeap above the free memory
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-heap", maxHeap="4096g")
    c.daemons.append(d)
    e = raises_launch("heap_too_large", lambda: d.connect("t", "p1b", timeout=30), "4096g heap")
    dd = e.details
    check(dd.get("heapBytes", 0) > dd.get("freeBytes", 1 << 62) and dd.get("totalBytes")
          and dd.get("maxHeap") == "4096g", f"heap_too_large details: {dd}")
    check(not d.jvm_alive() and not d.read_endpoint(), "a daemon was started in spite of the error")
    cfg = gs.load_config(st, {"maxHeap": "4096g", "heapCheck": False})
    gs.Launch(inst, cfg, st).check_heap()  # switched off: no error
    cfg = gs.load_config(st, {"maxHeap": "1m"})
    gs.Launch(inst, cfg, st).check_heap()  # a small explicit heap is fine
    gs.Launch(inst, gs.load_config(st, {}), st).check_heap()  # the default heap is never checked
    seen["heap_too_large"] = f"{dd['heapBytes'] >> 30} GiB > {dd['freeBytes'] >> 20} MiB free"

    # lock_held: someone holds the start lock for longer than the caller waits
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-lock")
    c.daemons.append(d)
    gs.ensure_state(st)
    with gs.FileLock(d.start_lock_file) as lk:
        check(lk.try_acquire(), "could not take the start lock for the test")
        t0 = time.monotonic()
        e = raises_launch("lock_held", lambda: d.connect("t", "p1b", timeout=1.5), "start lock held")
        waited = time.monotonic() - t0
    check(1.3 <= waited < 8 and e.details.get("lock") == str(d.start_lock_file)
          and e.details.get("waitedS") == 1.5, f"lock_held: waited {waited:.1f} s, {e.details}")
    check(not d.jvm_alive(), "a daemon was started while the start lock was held")
    seen["lock_held"] = f"{waited:.1f} s"

    # exited_early: the JVM refuses an option and ends at once; the log tail says why
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-early", vmargs=["-XX:+NoSuchFlagForP1b"])
    c.daemons.append(d)
    t0 = time.monotonic()
    e = raises_launch("exited_early", lambda: d.connect("t", "p1b", timeout=60), "bad JVM option")
    took = time.monotonic() - t0
    tail = "\n".join(e.details.get("logTail", []))
    check(e.details.get("exitCode") not in (None, 0) and "NoSuchFlagForP1b" in tail
          and e.details.get("log") == str(d.log_file),
          f"exited_early details: {json.dumps(e.details)[:600]}")
    check(took < 30, f"exited_early took {took:.1f} s: the early exit was not seen at once")
    seen["exited_early"] = f"exit {e.details['exitCode']} after {took:.1f} s"

    # no_answer: the timeout passes before the JVM is up. The JVM goes on starting: stop it.
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-noans")
    c.daemons.append(d)
    e = raises_launch("no_answer", lambda: d.connect("t", "p1b", timeout=0.3), "0.3 s timeout")
    check(e.details.get("timeoutS") == 0.3 and isinstance(e.details.get("logTail"), list)
          and e.details.get("log") == str(d.log_file), f"no_answer details: {e.details}")
    try:
        dt.wait_for(lambda: d.read_endpoint() and d.jvm_alive(), "the late daemon to come up", 120)
    finally:
        stop_quietly(d)
    check(not d.jvm_alive(), "the daemon of the no_answer case is still running")
    seen["no_answer"] = "ok"

    # no_answer on a daemon that is alive but wedged: its lock is held, a log exists; the logTail
    # must hold the log's lines (it was empty when the tail started at the end of the file)
    d2 = gs.Daemon(c.a.ghidra, str(fresh_state(c, base, "wedged")), "p1b-wedged")
    d2.log_file.parent.mkdir(parents=True, exist_ok=True)
    d2.log_file.write_text("line one\nline two\nline three\n", encoding="utf-8")
    d2.lock_file.parent.mkdir(parents=True, exist_ok=True)
    lk = gs.FileLock(d2.lock_file)
    check(lk.try_acquire(), "could not take the wedged daemon's instance lock")
    try:
        e = raises_launch("no_answer", lambda: d2.connect("t", "p1b", timeout=1.0), "wedged daemon")
        check(e.details.get("logTail") == ["line one", "line two", "line three"],
              f"wedged no_answer logTail: {e.details.get('logTail')}")
    finally:
        lk.close()
    seen["no_answer_wedged"] = "ok"
    return "; ".join(f"{k}: {v}" for k, v in seen.items())


# ---- p1b_duplicate_daemon ---------------------------------------------------------------------

def t_duplicate_daemon(c):
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "dup")
    inst = gs.Install.locate(c.a.ghidra)
    with user_root(base / "userroot") as ur:
        sa, sb, sc = (fresh_state(c, base, n) for n in ("sa", "sb", "sc"))
        a = gs.Daemon(c.a.ghidra, str(sa), "dupa")
        b = gs.Daemon(c.a.ghidra, str(sb), "dupb")
        c.daemons += [a, b]
        d3 = gs.Daemon(c.a.ghidra, str(sc), "dupc", singleton="per-install")
        d_dflt = gs.Daemon(c.a.ghidra, str(sb), "dupb")
        c.daemons.append(d3)
        try:
            # --- the first daemon: no warning, a registry entry
            with a.connect("t", "p1b") as s:
                check(s.started and s.warnings == [], f"first daemon: warnings {s.warnings}")
                pid_a = s.endpoint["pid"]
                check(s.launch and s.launch.get("spawn") in ("detached", "breakaway", "wmi", "task"),
                      f"launch outcome: {s.launch}")
            key = hashlib.sha256(
                f"{os.path.normcase(str(inst.dir))}|{os.path.normcase(str(sa.resolve()))}|dupa"
                .encode()).hexdigest()
            entry_file = ur / "registry" / f"{key}.json"
            check(entry_file.is_file(), f"no registry entry {entry_file.name} in {ur / 'registry'}: "
                  f"{[p.name for p in (ur / 'registry').glob('*')]}")
            ent = json.loads(entry_file.read_text())
            for k in ("pid", "stateDir", "instance", "install", "hydraVersion", "startedAt"):
                check(k in ent, f"registry entry has no {k}: {ent}")
            check(ent["pid"] == pid_a and ent["instance"] == "dupa"
                  and os.path.normcase(ent["stateDir"]) == os.path.normcase(str(sa.resolve())),
                  f"registry entry: {ent}")
            # same state dir, another instance: never a duplicate; another state dir: one
            check(gs.find_duplicate(inst, sa.resolve(), "other") is None,
                  "the same state dir counted as a duplicate")
            dup = gs.find_duplicate(inst, sb.resolve(), "dupb")
            check(dup and dup["pid"] == pid_a, f"find_duplicate: {dup}")

            # --- singleton per-install: refused, nothing started
            e = raises_launch("duplicate_daemon", lambda: d3.connect("t", "p1b", timeout=60),
                              "per-install")
            check(isinstance(e, gs.DuplicateDaemonError), f"not a DuplicateDaemonError: {e!r}")
            h = e.details.get("holder") or {}
            check(h.get("pid") == pid_a and h.get("instance") == "dupa"
                  and os.path.normcase(h.get("stateDir", "")) == os.path.normcase(str(sa.resolve())),
                  f"holder: {h}")
            check(len(e.ways_out) == 3 and e.details.get("suggest") == e.ways_out,
                  f"three ways out: {e.ways_out}")
            check(not d3.jvm_alive() and not d3.read_endpoint(), "per-install still started a daemon")
            check(e.holder == h, "holder attribute differs from details")

            # --- default policy: warn, and start
            with d_dflt.connect("t", "p1b") as s2:
                w = [x for x in s2.warnings if x.get("code") == "duplicate_daemon"]
                check(s2.started and len(w) == 1 and w[0]["holder"]["pid"] == pid_a,
                      f"default policy warnings: {s2.warnings}")
                pid_b = s2.endpoint["pid"]
            check(pid_b != pid_a, "the second daemon is the first")

            # --- health and attach
            ha = a.health()
            check(ha["alive"] and ha["answers"] and ha["pid"] == pid_a
                  and ha["source"] in ("health", "ping"), f"health: {ha}")
            check(ha["launch"] and ha["launch"].get("spawn") and ha["warnings"] == [],
                  f"health launch record: {ha}")
            with a.attach("t", "p1b") as s3:
                check(not s3.started and s3.launch and s3.launch.get("spawn") == ha["launch"]["spawn"]
                      and s3.endpoint["pid"] == pid_a, f"attach: started {s3.started} {s3.launch}")
            idle = gs.Daemon(c.a.ghidra, str(sc), "nobody")
            raises_launch("not_running", lambda: idle.attach("t", "p1b"), "attach, no daemon")
            hn = idle.health()
            check(not hn["alive"] and not hn["answers"] and hn.get("reason"), f"health of none: {hn}")
            check(not idle.jvm_alive() and not idle.read_endpoint(), "attach started a daemon")
        finally:
            stop_quietly(a)
            stop_quietly(b)
        # a stopped daemon is not live: its entry stays but is ignored
        check(entry_file.is_file(), "the registry entry of a stopped daemon was deleted")
        check(gs.find_duplicate(inst, sb.resolve(), "dupb") is None
              and gs.find_duplicate(inst, sc.resolve(), "dupc") is None,
              "a stopped daemon still counts as live")
        hs = a.health()
        check(not hs["alive"] and not hs["answers"], f"health after stop: {hs}")
        # nothing was written to the real user root by this test's launches (they used ur)
    return f"pids {pid_a}/{pid_b}; entry {key[:12]}; per-install refused with 3 ways out"


# ---- p1b_call_deadline ------------------------------------------------------------------------

class FakeEngine:
    """A loopback server: ``hello`` answers; ``echo`` answers; ``slow`` never answers until its
    ``cancel`` arrives (then it answers the cancel and, late, the slow request); ``split`` sends
    half of its answer line at once and the rest after ``split_gap`` s."""

    def __init__(self, split_gap=0.5):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.requests = []
        self.split_gap = split_gap
        self.endpoint = {"host": "127.0.0.1", "port": self.port, "token": "t"}
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        f = conn.makefile("rwb")

        wlock = threading.Lock()  # one line at a time, also while a split answer waits

        def send(obj, part=None):
            line = (json.dumps(obj) + "\n").encode()
            with wlock:
                if part:
                    f.write(line[:part])
                    f.flush()
                    time.sleep(self.split_gap)
                    f.write(line[part:])
                else:
                    f.write(line)
                f.flush()

        answered = set()
        try:
            self._loop(f, send, answered)
        except (OSError, ValueError):
            pass  # the client closed the connection (stop() abandons a silent shutdown)

    def _loop(self, f, send, answered):
        for raw in f:
            m = json.loads(raw)
            self.requests.append(m)
            cmd, rid = m["cmd"], m["id"]
            if cmd == "hello":
                send({"id": rid, "ok": True, "result": {"protocol": 3, "protocolMin": 2,
                                                         "protocolMax": 3, "minClient": "1.0.0"}})
            elif cmd == "echo":
                send({"id": rid, "ok": True, "result": {"echo": True}})
            elif cmd == "split":
                answered.add(rid)  # the split answer is the only one this request gets
                threading.Thread(target=send, args=({"id": rid, "ok": True,
                                                     "result": {"split": True}}, 12),
                                 daemon=True).start()
            elif cmd == "cancel":
                send({"id": rid, "ok": True, "result": {"cancelled": 1}})
                if m["target"] not in answered:  # a cancelled request ends with one late answer
                    send({"id": m["target"], "ok": False,
                          "error": {"code": "cancelled", "message": "late answer"}})

    def close(self):
        self.srv.close()


def t_call_deadline(c):
    gs = c.gs
    _GS["gs"] = gs
    notes = []
    # --- a fake engine that does not answer
    fe = FakeEngine()
    try:
        s = gs.SocketSession(fe.endpoint, client="t", check=False, timeout=5)
        t0 = time.monotonic()
        try:
            s.call("slow", deadline=0.6)
        except gs.SessionError as e:
            took = time.monotonic() - t0
            check(e.code == "deadline_exceeded", f"code {e.code}")
            check(e.details.get("deadlineS") == 0.6 and e.details.get("target"), f"details {e.details}")
        else:
            raise Fail("a call without an answer did not raise")
        check(0.55 <= took < 2.5, f"deadline 0.6 s took {took:.2f} s")
        dt.wait_for(lambda: any(r["cmd"] == "cancel" for r in fe.requests), "the cancel request", 5)
        slow_id = [r for r in fe.requests if r["cmd"] == "slow"][0]["id"]
        cancel = [r for r in fe.requests if r["cmd"] == "cancel"][0]
        check(cancel["target"] == slow_id, f"cancel target {cancel['target']} != {slow_id}")
        check(cancel.get("parallel") is True, "the cancel must be parallel: on a connection that "
              "runs requests in order it would queue behind the request it ends")
        check("deadline" not in fe.requests[1], "the deadline was sent to the engine")
        # the connection survives; the late answers (cancel's and slow's) are dropped
        check(s.call("echo", deadline=5) == {"echo": True}, "echo after a deadline")
        check(not s._pending and not s._abandoned,
              f"late answers kept: pending {s._pending} abandoned {s._abandoned}")
        # a timeout in the middle of a line keeps the line: the reader's buffer survives it
        t0 = time.monotonic()
        try:
            s.call("split", deadline=0.2)
            raise Fail("split: no deadline_exceeded")
        except gs.SessionError as e:
            check(e.code == "deadline_exceeded", f"split code {e.code}")
        check(s.call("echo", deadline=5) == {"echo": True}, "echo after a timeout inside a line")
        check(not s._pending and not s._abandoned,
              f"after split: pending {s._pending} abandoned {s._abandoned}")
        # labelled views pass the deadline on; bad deadlines are refused before anything is sent
        n = len(fe.requests)
        for bad in (0, -1, "x", True):
            try:
                s.call("echo", deadline=bad)
                raise Fail(f"deadline {bad!r} was accepted")
            except ValueError:
                pass
        check(len(fe.requests) == n, "a refused deadline still sent a request")
        check(s.labelled(client="x").call("echo", deadline=5) == {"echo": True}, "labelled deadline")
        s.close()
        notes.append(f"fake engine: deadline_exceeded in {took:.2f} s, cancel target {slow_id}")
    finally:
        fe.close()

    # --- the real engine: a hung script is cancelled, the connection survives
    base = fresh_dir(c, "deadline")
    d = gs.Daemon(c.a.ghidra, str(fresh_state(c, base)), "p1b-deadline",
                  scriptPath=[str(c.scripts)])
    c.daemons.append(d)
    try:
        with d.connect("t", "p1b") as s:
            t0 = time.monotonic()
            try:
                s.call("script", script=c.script("TestSleep.java"), program=None, args=["30000"],
                       wait=60000, deadline=1.0)
                raise Fail("the 30 s script finished inside a 1 s deadline")
            except gs.SessionError as e:
                took = time.monotonic() - t0
                check(e.code == "deadline_exceeded", f"real engine: {e.code}: {e}")
            check(0.9 <= took < 3.5, f"deadline 1 s took {took:.2f} s")
            check(s.call("ping", deadline=10) == {"pong": True}, "ping after the deadline")
            # both late answers (the cancel's and the script's) arrive and are dropped; the
            # script ends long before its 8 s because the cancel reached it
            dt.wait_for(lambda: s.call("ping", deadline=10) and not s._abandoned,
                        "the late answers", 30)
            ended = time.monotonic() - t0
            check(ended < 15.0, f"the script ran {ended:.1f} s: the cancel did not reach it")
            check(not s._pending, f"pending: {s._pending}")
            r = s.call("script", script=c.script("TestSleep.java"), program=None, args=["100"],
                       wait=60000, deadline=60)
            check(r is not None, "a script after the deadline")
            notes.append(f"real engine: deadline in {took:.2f} s, script gone after {ended:.1f} s")
    finally:
        stop_quietly(d)
    return "; ".join(notes)


# ---- p1b_concurrent_launchers -----------------------------------------------------------------

def _java_count(token):
    """Number of java.exe processes whose command line contains ``token`` (None: unknown)."""
    if not IS_WINDOWS:
        return None
    ps = ("(Get-CimInstance Win32_Process -Filter \"Name='java.exe'\" | "
          f"Where-Object {{ $_.CommandLine -like '*{token}*' }} | Measure-Object).Count")
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=120)
        return int(r.stdout.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def t_concurrent_launchers(c, n=6, roots=2):
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "conc")
    code = ("d = gs.Daemon(A[0], A[1], 'conc'); s = d.connect('conc', 'p1b', timeout=170)\n"
            "print(json.dumps({'pid': d.read_endpoint()['pid'], 'started': s.started, "
            "'spawn': (s.launch or {}).get('spawn')})); s.close()\n")
    notes = []
    with user_root(base / "userroot"):
        states = [fresh_state(c, base, f"root{i}") for i in range(roots)]
        daemons = [gs.Daemon(c.a.ghidra, str(st), "conc") for st in states]
        c.daemons += daemons
        try:
            procs = [(i, c.child(code, c.a.ghidra, str(states[i]))) for i in range(roots)
                     for _ in range(n)]
            results = {i: [] for i in range(roots)}
            for i, p in procs:
                out, err = p.communicate(timeout=240)
                check(p.returncode == 0, f"a launcher failed (root {i}): {err[-800:]}")
                results[i].append(json.loads(out.strip().splitlines()[-1]))
            for i in range(roots):
                rs = results[i]
                pids = {r["pid"] for r in rs}
                starters = [r for r in rs if r["started"]]
                check(len(rs) == n and len(pids) == 1, f"root {i}: pids {pids}")
                check(len(starters) == 1, f"root {i}: {len(starters)} launchers started the daemon")
                check(pids != {r["pid"] for r in results[1 - i]} if roots == 2 else True,
                      "two roots share one daemon")
                cnt = _java_count(states[i].name)
                check(cnt in (None, 1), f"root {i}: {cnt} JVMs carry its state dir")
                notes.append(f"root {i}: 1 of {n} started pid {pids.pop()} ({starters[0]['spawn']}),"
                             f" JVMs {cnt}")
        finally:
            for d in daemons:
                stop_quietly(d)
    return "; ".join(notes)


# ---- p1b_native_access_flag -------------------------------------------------------------------

def t_native_access_flag(c):
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "flag")
    st = fresh_state(c, base)
    inst = gs.Install.locate(c.a.ghidra)
    flag = "--enable-native-access=ALL-UNNAMED"

    def argv_of(vmargs=None, props_vm=None):
        launch = gs.Launch(inst, gs.load_config(st, {"vmargs": vmargs} if vmargs else {}), st)
        if props_vm is not None:
            launch.props["vmargs"] = list(props_vm)
        argv, _ = launch.command(["-daemon"])
        return argv

    # launch.properties without the flag (a Ghidra that does not ship it): added, once
    base_props = [a for a in gs.Launch(inst, gs.load_config(st, {}), st).props["vmargs"]
                  if not a.startswith("--enable-native-access")]
    a1 = argv_of(props_vm=base_props)
    check(a1.count(flag) == 1, f"flag absent from the command line: {a1.count(flag)} times")
    java_main = [i for i, a in enumerate(a1) if a.endswith("SessionMain") or a == "ghidra.Ghidra"]
    check(java_main and a1.index(flag) < java_main[0], "the flag is not before the main class")
    check(a1.index(flag) > 0, "the flag came before the java executable")
    # already there, in any spelling: nothing is added
    for pv, what in (([*base_props, flag], "launch.properties"),
                     ([*base_props, "--enable-native-access=java.base,ALL-UNNAMED"], "list"),
                     ([*base_props, "--enable-native-access", "ALL-UNNAMED"], "two tokens")):
        a2 = argv_of(props_vm=pv)
        n = sum(1 for a in a2 if a.startswith("--enable-native-access"))
        check(n == 1, f"{what}: {n} native-access arguments, expected the one that was there")
    a3 = argv_of(vmargs=[flag], props_vm=base_props)
    check(a3.count(flag) == 1, f"vmargs carrying the flag: {a3.count(flag)} copies")
    # a flag for another module does not count
    a4 = argv_of(props_vm=[*base_props, "--enable-native-access=java.base"])
    check(a4.count(flag) == 1 and "--enable-native-access=java.base" in a4,
          "--enable-native-access=java.base does not cover unnamed code")
    # the real, unmodified command line carries it exactly once
    a5 = argv_of()
    check(sum(1 for a in a5 if a.startswith("--enable-native-access")) == 1
          and a5.count(flag) == 1, f"default command line: {[a for a in a5 if 'native' in a]}")
    return "added once, idempotent for launch.properties/vmargs/list/two-token forms"


# ---- p1b_daemon_survives_launcher_exit (SP3 (a)) ----------------------------------------------

JOB_KILL_ON_CLOSE, JOB_BREAKAWAY_OK = 0x2000, 0x800

CASES = {
    "A": dict(name="A_breakaway", job=JOB_KILL_ON_CLOSE | JOB_BREAKAWAY_OK, routes="default",
              spawn="breakaway", survival="independent", survives=True),
    "B": dict(name="B_wmi", job=JOB_KILL_ON_CLOSE, routes="default",
              spawn="wmi", survival="independent", survives=True),
    "C": dict(name="C_stayed", job=JOB_KILL_ON_CLOSE, routes="breakaway",
              spawn="stayed", survival="bound_to_harness", survives=False,
              warning="daemon_dies_with_harness"),
    "D": dict(name="D_detached", job=None, routes="default",
              spawn="detached", survival="independent", survives=True),
    "E": dict(name="E_task", job=JOB_KILL_ON_CLOSE, routes="breakaway,task",
              spawn="task", survival="independent", survives=True),
    "N": dict(name="N_owned_job", job=None, routes="default", mode="owned_job",
              spawn="owned_job", survival="bound_to_launcher", survives=False),
}

#: the cases whose set-up is a plain ``Popen`` that must be allowed to break away from the job the
#: test itself runs in (D: the detached route; N: the launcher with its own job, outside the harness's)
NEEDS_BREAKAWAY = ("D", "N")

_K = {}


def _win():
    """kernel32/ntdll with signatures (Windows only), made once."""
    if _K:
        return _K["k"], _K["nt"]
    import ctypes
    import ctypes.wintypes as wt
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    nt = ctypes.WinDLL("ntdll")
    H = ctypes.c_void_p
    k.OpenProcess.restype = H
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.CloseHandle.argtypes = [H]
    k.CreateJobObjectW.restype = H
    k.CreateJobObjectW.argtypes = [H, wt.LPCWSTR]
    k.SetInformationJobObject.argtypes = [H, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    k.AssignProcessToJobObject.argtypes = [H, H]
    k.IsProcessInJob.argtypes = [H, H, ctypes.POINTER(wt.BOOL)]
    k.GetExitCodeProcess.argtypes = [H, ctypes.POINTER(wt.DWORD)]
    nt.NtResumeProcess.argtypes = [H]
    nt.NtSuspendProcess.argtypes = [H]
    _K.update(k=k, nt=nt)
    return k, nt


def create_job(flags):
    import ctypes
    k, _ = _win()
    j = k.CreateJobObjectW(None, None)
    if not j:
        raise ctypes.WinError(ctypes.get_last_error())
    buf = (ctypes.c_ubyte * 144)()  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION (x64)
    ctypes.c_uint32.from_buffer(buf, 16).value = flags
    if not k.SetInformationJobObject(j, 9, buf, 144):
        raise ctypes.WinError(ctypes.get_last_error())
    return j


def spawn_in_job(argv, job, **kw):
    """Starts ``argv`` suspended, assigns it to ``job``, resumes it: it and what it starts are in
    the job from the first instruction."""
    import ctypes
    k, nt = _win()
    kw["creationflags"] = kw.get("creationflags", 0) | 0x4  # CREATE_SUSPENDED
    p = subprocess.Popen(argv, **kw)
    h = k.OpenProcess(0x1 | 0x100 | 0x800, False, p.pid)  # TERMINATE | SET_QUOTA | SUSPEND_RESUME
    try:
        if not k.AssignProcessToJobObject(job, h):
            err = ctypes.get_last_error()
            p.kill()
            raise ctypes.WinError(err)
        nt.NtResumeProcess(h)
    finally:
        k.CloseHandle(h)
    return p


def pid_in_job(pid, job):
    import ctypes
    import ctypes.wintypes as wt
    k, _ = _win()
    h = k.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        b = wt.BOOL()
        return bool(b.value) if k.IsProcessInJob(h, job, ctypes.byref(b)) else None
    finally:
        k.CloseHandle(h)


def pid_alive(pid):
    import ctypes
    import ctypes.wintypes as wt
    k, _ = _win()
    h = k.OpenProcess(0x1000, False, pid)
    if not h:
        return False
    try:
        code = wt.DWORD()
        return bool(k.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
    finally:
        k.CloseHandle(h)


def harness_main(argv):
    """The launcher of a survival case (runs inside the job the test made for it): starts the real
    daemon through the real ghidra_session.py, writes result.json, then waits to be ended."""
    support, ghidra, state, instance, outdir, routes, mode = argv[:7]
    sys.path.insert(0, support)
    import ghidra_session as gs
    out = pathlib.Path(outdir)
    res = {"pid": os.getpid()}
    if routes != "default":
        gs.SPAWN_ROUTES = tuple(x for x in routes.split(",") if x)
    if mode == "owned_job":  # the revision 6 design: this launcher owns a kill-on-close job
        def owned(self, install):
            cfg = gs.load_config(self.state, self.cfg_overrides)
            launch = gs.Launch(install, cfg, self.state)
            args = ["-daemon", "-stateDir", str(self.state), "-instance", self.instance,
                    "-idleTimeout", "0", "-keepWarm", str(cfg["keepWarm"]), "-maxQuick", "0",
                    "-maxLong", "0"]
            cmd, _info = launch.command(args)
            job = create_job(JOB_KILL_ON_CLOSE)  # never closed here: the OS does it at exit
            self._owned_job = job
            with open(self.log_file, "ab") as lf:
                p = spawn_in_job(cmd, job, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                                 env=launch.env, creationflags=0x8 | 0x200 | 0x01000000,
                                 close_fds=True)
            self.last_launch = {"spawn": "owned_job", "survival": "bound_to_launcher",
                                "warnings": [], "caller_in_job": False}
            return p
        gs.Daemon._spawn = owned
    d = gs.Daemon(ghidra, state, instance)
    try:
        s = d.connect("p1b-harness", "dt_p1b", timeout=170)
        res.update(daemon_pid=s.endpoint["pid"], started=s.started, launch=s.launch,
                   warnings=s.warnings, caller=gs.caller_job())
    except Exception:  # noqa: BLE001
        res["error"] = traceback.format_exc()[-2000:]
    tmp = out / "result.json.tmp"
    tmp.write_text(json.dumps(res))
    os.replace(tmp, out / "result.json")
    time.sleep(600)


def run_survival_case(c, key):
    gs = c.gs
    _GS["gs"] = gs
    cs = CASES[key]
    base = fresh_dir(c, "surv-" + cs["name"])
    st = fresh_state(c, base)
    inst = "p1b-surv"
    d = gs.Daemon(c.a.ghidra, str(st), inst)
    c.daemons.append(d)
    k, _ = _win()
    job = create_job(cs["job"]) if cs["job"] is not None else None
    cmd = [sys.executable, str(HERE / "dt_p1b.py"), "--harness", str(c.support), c.a.ghidra,
           str(st), inst, str(base), cs["routes"], cs.get("mode", "real")]
    harness_out = open(base / "harness.out", "wb")
    kw = dict(stdin=subprocess.DEVNULL, stdout=harness_out,
              stderr=subprocess.STDOUT, creationflags=0x08000000)  # CREATE_NO_WINDOW
    if job:
        hp = spawn_in_job(cmd, job, **kw)
    else:
        # D and N want a launcher that is in NO job. This process may itself run in one (a harness,
        # an agent session) that allows breakaway: without the flag the launcher would inherit it,
        # see a job and take the breakaway route instead of "detached". Not in a job: the flag does nothing.
        if key in NEEDS_BREAKAWAY and breakaway_blocked() is False:
            kw["creationflags"] |= 0x01000000   # CREATE_BREAKAWAY_FROM_JOB
        hp = subprocess.Popen(cmd, **kw)
    harness_out.close()  # the child has its own handle
    r = {"case": cs["name"]}
    dp = None
    try:
        t0 = time.monotonic()
        while time.monotonic() - t0 < 200 and not (base / "result.json").exists() \
                and hp.poll() is None:
            time.sleep(0.2)
        if not (base / "result.json").exists():
            raise Fail(f"{cs['name']}: the launcher left no result: "
                       f"{(base / 'harness.out').read_text(errors='replace')[-600:]}")
        res = json.loads((base / "result.json").read_text())
        if res.get("error"):
            raise Fail(f"{cs['name']}: the launcher failed: {res['error']}")
        dp = res["daemon_pid"]
        o = res["launch"] or {}
        r["spawn"], r["survival"] = o.get("spawn"), o.get("survival")
        check(res["started"], f"{cs['name']}: the launcher did not start the daemon")
        check(o.get("spawn") == cs["spawn"] and o.get("survival") == cs["survival"],
              f"{cs['name']}: spawn/survival {o.get('spawn')}/{o.get('survival')}, expected "
              f"{cs['spawn']}/{cs['survival']}; attempts {o.get('attempts')}")
        if job is not None:
            check(res["caller"]["in_job"] and res["caller"]["kill_on_close"] is True,
                  f"{cs['name']}: the launcher did not see its kill-on-close job: {res['caller']}")
            check(o.get("caller_in_job") is True, f"{cs['name']}: caller_in_job {o}")
        if cs["spawn"] == "breakaway":
            check(res["caller"]["limit_flags"] and int(res["caller"]["limit_flags"], 16)
                  & JOB_BREAKAWAY_OK, f"{cs['name']}: breakaway rights not seen")
        if cs["spawn"] in ("wmi", "task"):  # breakaway was tried and denied first, with WinError 5
            att = {a["route"]: a for a in o["attempts"]}
            check("breakaway" in att and not att["breakaway"]["ok"]
                  and ("5" in att["breakaway"]["error"] or "denied" in att["breakaway"]["error"].lower()),
                  f"{cs['name']}: breakaway should fail with WinError 5: {att.get('breakaway')}")
        if cs["spawn"] == "task":
            att = {a["route"]: a for a in o["attempts"]}
            check(att.get("task", {}).get("ok"), f"task route: {o['attempts']}")
        if cs.get("warning"):
            codes = [w.get("code") for w in res["warnings"]]
            check(cs["warning"] in codes, f"{cs['name']}: warning {cs['warning']} missing: {codes}")
            hw = [w.get("code") for w in d.health()["warnings"]]
            check(cs["warning"] in hw, f"{cs['name']}: health() lacks the warning: {hw}")
        else:
            check(not res["warnings"], f"{cs['name']}: unexpected warnings {res['warnings']}")
        if job is not None:
            ij = pid_in_job(dp, job)
            r["daemon_in_harness_job"] = ij
            check(ij is (not cs["survives"]), f"{cs['name']}: daemon in the harness's job: {ij}, "
                                              f"expected {not cs['survives']}")
        h0 = d.health()
        check(h0["answers"] and h0["pid"] == dp, f"{cs['name']}: no answer before the exit: {h0}")
        check(h0["launch"] and h0["launch"].get("spawn") == cs["spawn"],
              f"{cs['name']}: health() launch record: {h0['launch']}")

        # --- the launcher exits: its job closes (the only handle), or it is terminated
        if job is not None:
            k.CloseHandle(job)
            job = None
        else:
            hp.terminate()
        t1 = time.monotonic()
        while hp.poll() is None and time.monotonic() - t1 < 15:
            time.sleep(0.1)
        check(hp.poll() is not None, f"{cs['name']}: the launcher is still running")
        time.sleep(3.0)  # a kill by the job would have happened by now (measured: < 150 ms)
        alive = pid_alive(dp)
        hh = d.health()
        survives = bool(alive and hh["answers"])
        r["survives"] = survives
        if cs["survives"]:
            check(survives, f"{cs['name']}: the daemon did not outlive the launcher "
                            f"(alive {alive}, health {hh.get('reason')})")
        else:
            check(not survives, f"{cs['name']}: the control FAILED: the daemon survived the "
                                "launcher's job, so the job does not decide and the test proves "
                                "nothing")
        return r
    finally:
        if job is not None:
            k.CloseHandle(job)
        if hp.poll() is None:
            hp.kill()
        stop_quietly(d)
        if dp and pid_alive(dp):  # ours: we started it
            with contextlib.suppress(Exception):
                d.kill()
        if cs["spawn"] == "task":
            left = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                                   "-Command",
                                   "(Get-ScheduledTask -TaskName 'HydraDaemon-*' "
                                   "-ErrorAction SilentlyContinue | Measure-Object).Count"],
                                  capture_output=True, text=True, timeout=120)
            r["tasks_left"] = left.stdout.strip()


def breakaway_blocked(spawn=None):
    """Whether THIS process is in a job object that refuses ``CREATE_BREAKAWAY_FROM_JOB``: it tries,
    with a process that does nothing, exactly what the launcher's breakaway route does. True when
    the job answers ``WinError 5`` (access denied), False when the process starts (not in a job, or
    in one that allows breakaway), None when the probe cannot tell (any other failure). ``spawn``
    replaces ``subprocess.Popen`` in the unit test."""
    spawn = spawn or subprocess.Popen
    try:
        p = spawn([sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  creationflags=0x01000000 | 0x08000000)   # CREATE_BREAKAWAY_FROM_JOB | NO_WINDOW
    except PermissionError as e:
        return True if getattr(e, "winerror", None) == 5 else None
    except OSError:
        return None
    with contextlib.suppress(Exception):
        p.wait(30)
    return False


def t_breakaway_probe(c):
    """The rule that turns case D into a SKIP: ``breakaway_blocked`` says True only for the
    access-denied answer of a job that forbids breakaway, False when the process starts, and None
    (undecided: case D then runs and can fail) for every other failure. Then the real answer for
    this process is shown in the note."""
    if not IS_WINDOWS:
        return "skipped: Windows only (Job Objects)"

    def refuses(exc):
        def spawn(*a, **kw):
            raise exc
        return spawn

    class _P:
        def wait(self, t=None):
            return 0

    denied = PermissionError(13, "Access is denied")
    denied.winerror = 5
    check(breakaway_blocked(refuses(denied)) is True, "WinError 5 must mean blocked")
    check(breakaway_blocked(lambda *a, **kw: _P()) is False, "a started process must mean allowed")
    check(breakaway_blocked(refuses(OSError(2, "nope"))) is None,
          "another failure must be undecided, not blocked")
    check(breakaway_blocked(refuses(PermissionError(13, "x"))) is None,
          "a PermissionError that is not WinError 5 must be undecided")
    real = breakaway_blocked()
    return f"probe rule ok; this process: breakaway blocked={real}, job={c.gs.caller_job()}"


def t_daemon_survives_launcher_exit(c):
    if not IS_WINDOWS:
        return "skipped: Windows only (Job Objects)"
    want = [x for x in os.environ.get("P1B_SURVIVAL", "A,B,C,D,E,N").split(",") if x]
    rows, skipped = [], []
    for key in want:
        if key in NEEDS_BREAKAWAY:
            # Case D asks for a daemon that is *detached* because the launcher may break away from
            # its job, and case N starts its launcher outside the harness's job the same way. In a
            # job that refuses breakaway (a restricted harness, the hosted CI runner) the
            # launcher's own answer to D is "wmi", which is right, and neither case has anything
            # to show: they are SKIPPED with the reason. They never pass there and no assertion is
            # changed; they run wherever the probe says breakaway works (or cannot tell).
            if breakaway_blocked() is True:
                skipped.append(f"{CASES[key]['name']}: this process runs in a job object that "
                               f"refuses CREATE_BREAKAWAY_FROM_JOB (WinError 5; job "
                               f"{c.gs.caller_job()}), so the case cannot be set up here")
                continue
        r = run_survival_case(c, key)
        rows.append(r)
        if r.get("tasks_left") not in (None, "0"):
            raise Fail(f"{r['case']}: scheduled tasks left behind: {r['tasks_left']}")
    c.timings["p1b_survival"] = rows
    note = "; ".join(f"{r['case']}: {r.get('spawn')}/{r.get('survival')} survives={r.get('survives')}"
                     for r in rows)
    if skipped:
        # not a pass: the cases that ran passed (they raised nothing), the others did not run
        raise dt.Skipped(f"{'; '.join(skipped)}. Cases that ran and passed: {note}")
    return note


# ---- p1b_wedged_connect -----------------------------------------------------------------------

def t_wedged_connect(c):
    """A real daemon whose process is suspended (NtSuspendProcess): its endpoint file is there, its
    instance lock is held, the kernel accepts the connection, and nobody answers ``hello``. Before
    the fix ``connect(timeout=3)`` stayed blocked until the daemon was resumed."""
    if not IS_WINDOWS:
        return "skipped: Windows only (NtSuspendProcess)"
    import ctypes
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "wedged")
    st = fresh_state(c, base)
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-wedge")
    c.daemons.append(d)
    k, nt = _win()
    h = None
    try:
        s = d.connect("t", "p1b", timeout=180)
        pid = s.endpoint["pid"]
        s.close()
        h = k.OpenProcess(0x800, False, pid)  # PROCESS_SUSPEND_RESUME
        check(h, f"could not open the daemon process {pid}")
        check(nt.NtSuspendProcess(h) == 0, "NtSuspendProcess failed")
        res = {}
        for what, fn in (("connect", lambda: d.connect("t", "p1b", timeout=3)),
                         ("attach", lambda: d.connect("t", "p1b", start=False, timeout=3))):
            t0 = time.monotonic()
            e = raises_launch("no_answer", fn, f"{what} on a suspended daemon")
            took = time.monotonic() - t0
            check(took < 15, f"{what} took {took:.1f} s on a suspended daemon (timeout 3 s)")
            check(e.details.get("holder", {}).get("pid") == pid, f"{what} holder: {e.details}")
            res[what] = f"{took:.1f} s"
        t0 = time.monotonic()
        st_ = d.status()
        check(st_ is None and time.monotonic() - t0 < 15, "status() of a suspended daemon hung")
        res["status"] = f"{time.monotonic() - t0:.1f} s"
        # _wait_ready: with a timeout of 12 s the two first dials (5 s each) leave about 2 s for
        # _wait_ready, whose own dial needs the hello deadline. Without it the call hangs.
        t0 = time.monotonic()
        e = raises_launch("no_answer", lambda: d.connect("t", "p1b", timeout=12),
                          "connect(timeout=12) on a suspended daemon")
        took = time.monotonic() - t0
        check(11 <= took < 20, f"connect(timeout=12) took {took:.1f} s on a suspended daemon")
        check("within 12 s" in str(e) and e.details.get("timeoutS") == 12,
              f"the error names the caller's timeout: {e} / {e.details}")
        res["connect12"] = f"{took:.1f} s"
        # stop on a wedged daemon: hello is not answered, stop gives up (False), the JVM lives
        t0 = time.monotonic()
        r = d.stop(timeout=3)
        took = time.monotonic() - t0
        check(r is False and took < 15 and d.jvm_alive(),
              f"stop() on a suspended daemon returned {r!r} after {took:.1f} s")
        res["stop"] = f"{took:.1f} s"
        nt.NtResumeProcess(h)
        check(d.stop(force=True, timeout=60) is True and not d.jvm_alive(),
              "force-stop after the resume did not end the daemon")
        h2, h = h, None
        k.CloseHandle(h2)
        return ("no_answer on a suspended daemon: "
                + ", ".join(f"{a} {b}" for a, b in res.items()) + "; force-stop after resume ok")
    finally:
        if h:
            nt.NtResumeProcess(h)  # a suspended JVM cannot be stopped politely
            k.CloseHandle(h)
        stop_quietly(d)


def t_stop_shutdown_deadline(c):
    """A daemon that answers ``hello`` and then wedges: ``stop()`` must not block on the
    ``shutdown`` call. The daemon is a fake engine that never answers ``shutdown``; the instance
    lock is held by the test, so the Daemon sees a live JVM."""
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "stopdl")
    st = fresh_state(c, base)
    d = gs.Daemon(c.a.ghidra, str(st), "p1b-stopdl")
    fe = FakeEngine()
    lk = gs.FileLock(d.lock_file)
    try:
        check(lk.acquire(5), "could not take the instance lock")
        d.endpoint_file.write_text(json.dumps(fe.endpoint), encoding="utf-8")
        check(d.jvm_alive(), "the fake daemon does not look alive")
        out = {}

        def run():
            t0 = time.monotonic()
            try:
                out["r"] = d.stop(timeout=3)
            except Exception as e:  # noqa: BLE001
                out["e"] = e
            out["t"] = time.monotonic() - t0
        th = threading.Thread(target=run, daemon=True)
        th.start()
        th.join(40)
        check(not th.is_alive(), "stop() is blocked on a shutdown that is never answered")
        check(isinstance(out.get("e"), c_launch_error()) and "did not exit" in str(out["e"]),
              f"stop() on a daemon that wedged after hello: {out}")
        check(5 <= out["t"] < 15, f"stop() took {out['t']:.1f} s (deadline 5 s + timeout 3 s)")
        check(any(r["cmd"] == "shutdown" for r in fe.requests), "no shutdown request was sent")
        return f"stop() after a hello and a silent shutdown ended in {out['t']:.1f} s"
    finally:
        lk.close()
        fe.close()


def t_children_of_threads(c):
    """Four threads call ``_children_of`` on this process 200 times each: ctypes checks ``argtypes``
    by class identity and ``_kernel32()`` is shared, so a structure class made per call made the
    threads overwrite each other's ``argtypes`` (an ``ArgumentError``)."""
    if not IS_WINDOWS:
        return "skipped: Windows only (Toolhelp)"
    gs = c.gs
    errs = []
    gate = threading.Barrier(4)

    def work():
        try:
            gate.wait(30)
            for _ in range(200):
                gs._children_of(os.getpid())
        except Exception as e:  # noqa: BLE001 - the failure is the finding
            errs.append(f"{type(e).__name__}: {e}")

    ths = [threading.Thread(target=work, daemon=True) for _ in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(120)
    check(not any(t.is_alive() for t in ths), "a _children_of thread did not end")
    check(not errs, f"_children_of failed under threads: {errs[:2]}")
    return "4 threads x 200 calls of _children_of, no error"

# ---- p1b_settings_dir -------------------------------------------------------------------------

def t_settings_dir(c):
    """Every daemon has its own Ghidra settings dir (``<state>/settings/<instance>``): the OSGi felixcache
    and the compiled script bundles of two daemons of one user are not shared. The command line carries
    ``-Dapplication.settingsdir`` (so also the routes without an environment); ``settingsDir: shared``, a
    JVM option that already names one, and a JVM that is not a daemon keep Ghidra's own choice. Live: two
    daemons run a script each and each has its own ``osgi/felixcache`` below its own dir."""
    gs = c.gs
    _GS["gs"] = gs
    base = fresh_dir(c, "settings")
    st = fresh_state(c, base)
    inst = gs.Install.locate(c.a.ghidra)
    opt = "-Dapplication.settingsdir="

    def argv_of(instance, over=None, props_vm=None):
        launch = gs.Launch(inst, gs.load_config(st, over or {}), st, instance)
        if props_vm is not None:
            launch.props["vmargs"] = list(props_vm)
        return launch.command(["-daemon"])[0]

    def dirs_of(argv):
        return [a[len(opt):] for a in argv if a.startswith(opt)]

    a, b = dirs_of(argv_of("one")), dirs_of(argv_of("two"))
    check(len(a) == 1 and len(b) == 1 and a != b, f"two instances: {a} {b}")
    check(pathlib.Path(a[0]) == st / "settings" / "one" and pathlib.Path(a[0]).is_dir(),
          f"not <state>/settings/<instance>: {a}")
    check(not dirs_of(argv_of(None)), "a JVM that is not a daemon got a settings dir")
    check(not dirs_of(argv_of("one", {"settingsDir": "shared"})), "settingsDir shared still set one")
    mine = str(base / "mine")
    check(dirs_of(argv_of("one", {"settingsDir": mine})) == [mine], "an explicit settingsDir not used")
    own = [opt + str(base / "own")]
    check(dirs_of(argv_of("one", {"vmargs": own})) == [str(base / "own")],
          "a vmargs settings dir was not the only one")
    check(dirs_of(argv_of("one", props_vm=own)) == [str(base / "own")],
          "a launch.properties settings dir was not the only one")
    # live: two daemons of one state dir, a script each (it starts the OSGi framework)
    scripts = c.scripts
    da, db = (gs.Daemon(c.a.ghidra, str(st), n, scriptPath=[str(scripts)]) for n in ("seta", "setb"))
    c.daemons += [da, db]
    try:
        errs = []

        def run_script(d):
            try:
                with d.connect("t", "p1b") as s:
                    s.call("script", script=str(scripts / "TestSleep.java"), program=None, args=["10"])
            except Exception as ex:  # noqa: BLE001
                errs.append(f"{d.instance}: {ex!r}")

        ths = [threading.Thread(target=run_script, args=(d,)) for d in (da, db)]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check(not errs, f"a script failed: {errs}")
        for name in ("seta", "setb"):
            felix = [p for p in (st / "settings" / name).rglob("felixcache") if p.is_dir()]
            check(felix, f"{name}: no osgi/felixcache below {st / 'settings' / name}")
        check(not (st / "settings" / "default").exists(), "a daemon used the default instance's dir")
    finally:
        stop_quietly(da)
        stop_quietly(db)
    return "own settings dir per daemon instance; felixcache of two daemons apart; shared/explicit honoured"


def isolated(fn):
    """Runs a test with its own user state root (GHIDRA_SESSION_HOME, inherited by every child
    process): the registry of the real user, and the daemons of other agents, never take part."""
    def run(c):
        with user_root(fresh_dir(c, fn.__name__ + "-home")):
            return fn(c)
    run.__name__ = fn.__name__
    return run


TESTS = {
    "p1b_launch_errors": isolated(t_launch_errors),
    "p1b_duplicate_daemon": isolated(t_duplicate_daemon),
    "p1b_call_deadline": isolated(t_call_deadline),
    "p1b_concurrent_launchers": isolated(t_concurrent_launchers),
    "p1b_children_of_threads": isolated(t_children_of_threads),
    "p1b_breakaway_probe": isolated(t_breakaway_probe),
    "p1b_native_access_flag": isolated(t_native_access_flag),
    "p1b_settings_dir": isolated(t_settings_dir),
    "p1b_wedged_connect": isolated(t_wedged_connect),
    "p1b_stop_shutdown_deadline": isolated(t_stop_shutdown_deadline),
    "p1b_daemon_survives_launcher_exit": isolated(t_daemon_survives_launcher_exit),
}

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--harness":
    harness_main(sys.argv[2:])
