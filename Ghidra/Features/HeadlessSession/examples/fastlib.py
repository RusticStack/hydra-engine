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
"""Test-side waiting library of the virtual-time design (``_logs/vtime/design.md``, package T1).

Every wait in a test is one of three things, in this order of preference:

1. an **event**: block on something that really happens (a process exits, a file appears, a flag is set);
2. a **scaled duration**: the thing under test is itself a timer, so hold and bounds shrink by one factor;
3. a **condition poll** that starts at 1 ms and backs off to 20 ms, never a fixed sleep.

Standard library only (``ctypes`` for the Windows calls), Python 3.13+. On a platform without the Windows
calls the event waits fall back to the poll, so the module still imports and the unit tests still run.

Scale (``HYDRA_TEST_SCALE``, default 1.0, clamped to [0.02, 1], an unparsable value means 1.0)
    ``ms(x)`` / ``sec(x)``  a duration the test uses (hold, ``wait=``, timeout): ``x`` is the value it had at
                            scale 1; the result is rounded **up** and never below ``floor``.
    ``bound_lo(x, minimum)`` a lower bound ("it took at least x"). Scaled by the same factor, never loosened:
                            the result is ``>= x * SCALE`` and ``>= minimum`` (the stated minimum, default 0),
                            and ``<= x``. A hold made with ``ms(x)`` is always ``>= bound_lo(x)``.
                            ``minimum > x`` is refused (it would tighten the bound at scale 1).
    ``bound_hi(x, slack)``  an upper bound: ``x * SCALE`` plus a jitter slack that does not scale. At scale 1 the
                            slack is 0 (the assertion is the original one); below 1 it is ``slack_ms`` (default
                            300 ms, doubled when ``HYDRA_TEST_LOADED`` is set, for runs beside a CPU hog).
    ``hang_s(expected_s)``  the timeout of a wait that must not time out: ``max(30, 10 * expected_s)``
                            (``HYDRA_TEST_HANG_S`` overrides the 30). A timeout is a hang detector, not a bound.
    ``real_wait(x)``        a deliberate real wait of ``ms(x)`` (a negative check "nothing arrives in x"), by
                            ``precise_delay``. The only sleep a test may keep, and it is visibly scaled.

Waits (each returns a ``Waited(value, elapsed_s, polls)``, raises ``WaitTimeout`` on timeout)
    ``until(predicate, timeout, interval, what=, notify=, ignore=, describe=)``
                            the condition poll. The predicate is evaluated first, before any sleep, so a
                            condition that is already true returns in microseconds. ``notify`` (a
                            ``threading.Event`` fed by a reader thread or a status push) wakes the wait at once;
                            ``interval`` is then only the cap on a lost wakeup. ``ignore`` lists exceptions the
                            predicate may raise while the state is not there yet (kept as the last state).
    ``wait_exit(proc, timeout)``
                            ``WaitForSingleObject`` on the process (a ``Popen`` or a pid); value is the exit code.
    ``wait_change(path, pred, timeout, cap_s=, subtree=)``
                            ``ReadDirectoryChangesW`` on the directory (or on the nearest existing ancestor if it
                            does not exist yet) is armed **before** ``pred()`` is evaluated, so no change is lost;
                            then it blocks until the OS reports a change and evaluates ``pred`` again.
                            Without ``pred`` it returns on the first change. Windows may defer the size and
                            time notification of a file that is still open for writing, so each block is capped
                            at ``cap_s`` (0.25 s) and the predicate is re-evaluated then: a deferred notification
                            costs at most the cap, a created, renamed or deleted entry is immediate.
    ``wait_file(path)`` / ``wait_gone(path)``  ``wait_change`` with an existence predicate.

Other
    ``precise_delay(ms)``   a high-resolution waitable timer (``CREATE_WAITABLE_TIMER_HIGH_RESOLUTION``), no spin;
                            replaces ``sleep_precise``. Returns the elapsed milliseconds. Not scaled: a kill
                            window chosen to hit a crash is real time.
    ``backdate(path, age_s)`` sets the modification (and access) time of a file or folder to ``age_s`` seconds
                            ago; replaces "sleep until it is old enough" for mtime based sweeps.

Measured latencies (Windows 11 24-core idle machine, Python 3.15, ``python test_fastlib.py --bench``; medians):
    until(), condition already true             0.002 ms   (one predicate call, no sleep)
    until(), turns true, poll 1..20 ms backoff  8.9 ms     (p95 19.7, the cap; use ``notify`` or an event wait)
    until(), turns true, ``notify`` set         0.09 ms    (p95 0.2)
    wait_exit(), process already gone           0.03 ms
    wait_exit(), after the child's last act     3.4 ms     (p95 4.9; the kernel's process teardown)
    wait_change(), condition already true       0.26 ms    (opens and closes the watch; p95 2.0)
    wait_change(), file appears                 0.75 ms    (p95 1.5; 0.57 ms when its folders do not exist yet)
    precise_delay(1 ms .. 5 ms) overshoot       0.5 ms     (time.sleep(0.001) overshoots 5.1 ms here)
"""
import ctypes
import math
import os
import subprocess
import sys
import threading
import time
from collections import namedtuple

_WIN = sys.platform == "win32"
_pc = time.perf_counter

SCALE_MIN = 0.02
HANG_MIN_S = 30.0
SLACK_MS = 300.0


def _parse_scale(text):
    try:
        v = float(text)
    except (TypeError, ValueError):
        return 1.0
    if math.isnan(v):
        return 1.0
    return min(1.0, max(SCALE_MIN, v))


SCALE = _parse_scale(os.environ.get("HYDRA_TEST_SCALE", "1"))


def set_scale(x):
    """Sets the factor (clamped like the environment value) and returns the previous one. For the unit tests
    and for a harness that decides the factor after import."""
    global SCALE
    old, SCALE = SCALE, _parse_scale(x)
    return old


def _loaded():
    return os.environ.get("HYDRA_TEST_LOADED", "").lower() not in ("", "0", "false", "no")


def _scaled(x):
    # round(.., 6) removes float noise (14000 * 0.1 = 1400.0000000000002) so ceil() does not add a millisecond
    return round(float(x) * SCALE, 6)


def ms(x_ms, floor=1):
    """A duration in milliseconds, scaled, rounded up, at least ``floor``. Returns an int."""
    return int(max(floor, math.ceil(_scaled(x_ms))))


def sec(x_s, floor=0.001):
    """A duration in seconds, scaled, at least ``floor``. Returns a float."""
    return max(floor, _scaled(x_s))


def bound_lo(x_ms, minimum=0):
    """Lower bound in milliseconds: scaled, never loosened (see the module docstring)."""
    if minimum > x_ms:
        raise ValueError(f"minimum {minimum} above the bound {x_ms} would tighten it at scale 1")
    return max(float(minimum), _scaled(x_ms))


def bound_hi(x_ms, slack_ms=None):
    """Upper bound in milliseconds: scaled plus a jitter slack that does not scale (0 at scale 1)."""
    if slack_ms is None:
        slack_ms = 0.0 if SCALE >= 1.0 else SLACK_MS * (2 if _loaded() else 1)
    return _scaled(x_ms) + slack_ms


def hang_s(expected_s=0.0):
    """The timeout of a wait that is only a hang detector: ``max(30, 10 * expected_s)`` seconds."""
    base = float(os.environ.get("HYDRA_TEST_HANG_S", HANG_MIN_S))
    return max(base, 10.0 * expected_s)


Waited = namedtuple("Waited", "value elapsed_s polls")
Waited.elapsed_ms = property(lambda self: self.elapsed_s * 1000.0)


class WaitTimeout(AssertionError, TimeoutError):
    """A wait ran out. It is an ``AssertionError`` (a test failure) and a ``TimeoutError``; the message names
    what was awaited, the elapsed time and the last state seen."""


def _timeout(what, t0, limit, polls, last, exc, describe):
    parts = [f"timed out after {_pc() - t0:.3f}s (limit {limit:.3f}s) waiting for {what}; polls={polls}"]
    if last is not _NOTHING:
        parts.append(f"last value={last!r}"[:300])
    if exc is not None:
        parts.append(f"last error={exc!r}"[:300])
    if describe is not None:
        try:
            parts.append(f"state: {describe()}"[:600])
        except Exception as e:  # the description must never hide the timeout
            parts.append(f"state: describe() raised {e!r}")
    return WaitTimeout("; ".join(parts))


_NOTHING = object()


def until(predicate, timeout=None, interval=0.02, *, what="condition", notify=None, ignore=(), describe=None):
    """Blocks until ``predicate()`` is truthy. Timeout in seconds (default ``hang_s()``). The first evaluation
    is immediate; then the wait is 1, 2, 4, ... ms up to ``interval`` seconds, or until ``notify`` is set."""
    limit = hang_s() if timeout is None else float(timeout)
    t0 = _pc()
    deadline = t0 + limit
    step, polls, last, exc = 0.001, 0, _NOTHING, None
    while True:
        if notify is not None:
            notify.clear()  # before the check: a set() between check and wait is not lost
        polls += 1
        try:
            last, exc = predicate(), None
            if last:
                return Waited(last, _pc() - t0, polls)
        except ignore as e:
            exc = e
        left = deadline - _pc()
        if left <= 0:
            raise _timeout(what, t0, limit, polls, last, exc, describe)
        if notify is not None:
            notify.wait(min(step, left))
        else:
            time.sleep(min(step, left))
        step = min(step * 2, max(interval, 0.001))


# --------------------------------------------------------------------------------------------- Windows calls

_k = None
_SYNCHRONIZE = 0x100000
_QUERY_LIMITED = 0x1000
_WAIT_OBJECT_0, _WAIT_TIMEOUT = 0, 0x102
_INFINITE = 0xFFFFFFFF


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p), ("Offset", ctypes.c_uint32),
                ("OffsetHigh", ctypes.c_uint32), ("hEvent", ctypes.c_void_p)]


def _kernel():
    global _k
    if _k is None:
        from ctypes import wintypes as w
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        H, P, D, B = ctypes.c_void_p, ctypes.c_void_p, w.DWORD, w.BOOL
        for name, res, args in [
            ("OpenProcess", H, [D, B, D]), ("CloseHandle", B, [H]),
            ("WaitForSingleObject", D, [H, D]), ("GetExitCodeProcess", B, [H, ctypes.POINTER(D)]),
            ("CreateWaitableTimerExW", H, [P, w.LPCWSTR, D, D]),
            ("SetWaitableTimer", B, [H, ctypes.POINTER(ctypes.c_longlong), w.LONG, P, P, B]),
            ("CreateFileW", H, [w.LPCWSTR, D, D, P, D, D, H]),
            ("CreateEventW", H, [P, B, B, w.LPCWSTR]), ("ResetEvent", B, [H]),
            ("ReadDirectoryChangesW", B, [H, P, D, B, D, ctypes.POINTER(D), ctypes.POINTER(_OVERLAPPED), P]),
            ("GetOverlappedResult", B, [H, ctypes.POINTER(_OVERLAPPED), ctypes.POINTER(D), B]),
            ("CancelIoEx", B, [H, ctypes.POINTER(_OVERLAPPED)]),
        ]:
            f = getattr(k, name)
            f.restype, f.argtypes = res, args
        _k = k
    return _k


def _ms_arg(seconds):
    return _INFINITE if seconds is None else max(0, min(int(math.ceil(seconds * 1000.0)), 0xFFFFFFFE))


# --------------------------------------------------------------------------------------------------- processes

def wait_exit(proc, timeout=None, *, what=None):
    """Waits for a process to end with ``WaitForSingleObject`` (no poll). ``proc`` is a ``subprocess.Popen``
    (reaped afterwards) or a pid (the exit code is read if the process can be opened, else the value is
    None: it was already gone). Returns ``Waited(exit_code, ...)``."""
    popen = isinstance(proc, subprocess.Popen)
    pid = proc.pid if popen else int(proc)
    what = what or f"process {pid} to exit"
    limit = hang_s() if timeout is None else float(timeout)
    t0 = _pc()
    if popen and proc.poll() is not None:
        return Waited(proc.returncode, _pc() - t0, 0)
    if not _WIN:
        if not popen:
            raise NotImplementedError("wait_exit(pid) needs Windows")
        try:
            proc.wait(limit)
        except subprocess.TimeoutExpired:
            raise _timeout(what, t0, limit, 1, _NOTHING, None, None) from None
        return Waited(proc.returncode, _pc() - t0, 1)
    k = _kernel()
    h = k.OpenProcess(_SYNCHRONIZE | _QUERY_LIMITED, False, pid)
    if not h:
        return Waited(proc.wait() if popen else None, _pc() - t0, 0)
    try:
        r = k.WaitForSingleObject(h, _ms_arg(limit))
        if r != _WAIT_OBJECT_0:
            raise _timeout(what, t0, limit, 1, "still running", None, None)
        code = ctypes.c_uint32()
        k.GetExitCodeProcess(h, ctypes.byref(code))
    finally:
        k.CloseHandle(h)
    rc = proc.wait() if popen else code.value  # reaps the Popen; its handle is signalled, so this is instant
    return Waited(rc, _pc() - t0, 1)


# ------------------------------------------------------------------------------------------- directory changes

_FILTER_ALL = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40  # file/dir names, attributes, size, last write, creation


class _DirWatch:
    """A ReadDirectoryChangesW watch with one outstanding request (the buffer is never read: a change is only
    a reason to evaluate the predicate again, so an overflowed buffer loses nothing)."""

    def __init__(self, directory, subtree):
        k = _kernel()
        self.k, self.subtree, self.pending, self.broken = k, bool(subtree), False, False
        # FILE_LIST_DIRECTORY, share all, OPEN_EXISTING, BACKUP_SEMANTICS | OVERLAPPED
        self.h = k.CreateFileW(directory, 0x1, 0x7, None, 3, 0x02000000 | 0x40000000, None)
        if self.h in (None, ctypes.c_void_p(-1).value):
            self.h, self.broken = None, True
            return
        self.ev = k.CreateEventW(None, True, False, None)
        self.ov = _OVERLAPPED()
        self.ov.hEvent = self.ev
        self.buf = ctypes.create_string_buffer(65536)
        self.n = ctypes.c_uint32()

    def arm(self):
        if self.pending or self.broken:
            return
        self.k.ResetEvent(self.ev)
        ok = self.k.ReadDirectoryChangesW(self.h, self.buf, len(self.buf), self.subtree, _FILTER_ALL,
                                          None, ctypes.byref(self.ov), None)
        if ok:
            self.pending = True
        else:
            self.broken = True  # the folder went away or the handle is unusable: the caller polls instead

    def wait(self, seconds):
        """True if a change was reported. Falls back to a short sleep when the watch is unusable."""
        if self.broken or not self.pending:
            time.sleep(min(seconds, 0.01))
            return False
        r = self.k.WaitForSingleObject(self.ev, _ms_arg(seconds))
        if r == _WAIT_OBJECT_0:
            self.k.GetOverlappedResult(self.h, ctypes.byref(self.ov), ctypes.byref(self.n), False)
            self.pending = False
            return True
        return False

    def close(self):
        if self.h is None:
            return
        if self.pending:  # the kernel owns buf/ov until the request is complete
            self.k.CancelIoEx(self.h, ctypes.byref(self.ov))
            self.k.GetOverlappedResult(self.h, ctypes.byref(self.ov), ctypes.byref(self.n), True)
        self.k.CloseHandle(self.ev)
        self.k.CloseHandle(self.h)
        self.h = None


def _watch_target(path, subtree):
    """The folder to watch: ``path`` itself if it is a folder, else its nearest existing ancestor (watched with
    its subtree, because the entry may appear several levels down)."""
    p = os.path.abspath(path)
    if os.path.isdir(p):
        return p, subtree
    q = os.path.dirname(p)
    while not os.path.isdir(q) and os.path.dirname(q) != q:
        q = os.path.dirname(q)
    return q, subtree or q != os.path.dirname(p)


def wait_change(path, pred=None, timeout=None, *, what=None, subtree=False, cap_s=0.25, describe=None):
    """Blocks until ``pred()`` is truthy, re-evaluating it after every change the OS reports under ``path``
    (see the module docstring). With ``pred=None`` returns after the first change. ``Waited.value`` is the
    predicate's value (True for a bare change)."""
    what = what or f"a change at {path}"
    limit = hang_s() if timeout is None else float(timeout)
    t0 = _pc()
    deadline = t0 + limit
    polls, last = 0, _NOTHING
    watch = None
    if _WIN:
        target, sub = _watch_target(path, subtree)
        watch = _DirWatch(target, sub)
    try:
        while True:
            if watch is not None:
                watch.arm()  # armed before the check: a change after the check completes the request
            polls += 1
            if pred is not None:
                last = pred()
                if last:
                    return Waited(last, _pc() - t0, polls)
            left = deadline - _pc()
            if left <= 0:
                raise _timeout(what, t0, limit, polls, last, None, describe)
            if watch is None:
                time.sleep(min(0.005, left))
            elif watch.wait(min(cap_s, left)) and pred is None:
                return Waited(True, _pc() - t0, polls)
    finally:
        if watch is not None:
            watch.close()


def wait_file(path, timeout=None, **kw):
    """Waits until ``path`` exists."""
    return wait_change(path, lambda: os.path.exists(path), timeout, what=f"{path} to exist", **kw)


def wait_gone(path, timeout=None, **kw):
    """Waits until ``path`` does not exist."""
    return wait_change(path, lambda: not os.path.exists(path), timeout, what=f"{path} to be gone", **kw)


# ------------------------------------------------------------------------------------------------ time helpers

def precise_delay(delay_ms):
    """Waits ``delay_ms`` (float) on a high-resolution waitable timer, without spinning. Returns the elapsed
    milliseconds. Not scaled."""
    t0 = _pc()
    if delay_ms > 0:
        h = None
        if _WIN:
            k = _kernel()
            h = k.CreateWaitableTimerExW(None, None, 0x2, 0x1F0003)  # HIGH_RESOLUTION, TIMER_ALL_ACCESS
        if h:
            try:
                due = ctypes.c_longlong(-max(1, int(delay_ms * 10000)))  # relative, 100 ns units
                if k.SetWaitableTimer(h, ctypes.byref(due), 0, None, None, False):
                    k.WaitForSingleObject(h, _INFINITE)
                else:
                    time.sleep(delay_ms / 1000.0)
            finally:
                k.CloseHandle(h)
        else:
            time.sleep(delay_ms / 1000.0)
    return (_pc() - t0) * 1000.0


def real_wait(x_ms, floor=1):
    """A deliberate real wait of ``ms(x_ms)`` (a negative check). Returns the elapsed milliseconds."""
    return precise_delay(ms(x_ms, floor))


def backdate(path, age_s):
    """Sets the access and modification time of a file or folder to ``age_s`` seconds ago; returns that time
    (epoch seconds). ``age_s`` must not be negative."""
    if age_s < 0:
        raise ValueError("age_s must be >= 0")
    ts = time.time() - age_s
    os.utime(path, (ts, ts))
    return ts
