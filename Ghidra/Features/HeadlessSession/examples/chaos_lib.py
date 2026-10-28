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
"""The fault injectors of the protocol 3 design (PROTOCOL-3.md 3.12, package X0, decision D48).

Injection is external: no test code lives in the release jar. The injectors:

* :func:`terminate` kills a process (``TerminateProcess``, what ``Stop-Process -Force`` does) and waits
  for it to be gone; :func:`kill_client_proc` and :func:`abort_connection` kill a client;
* :func:`timed_kill` kills the daemon at a random time (:func:`random_delay`) or **trigger-timed**:
  *kill X ms after the version folder listing first changes*, the method that found the corruption
  (2 of 131 kills at random times against 7 of 95 trigger-timed); :func:`measure_trigger` calibrates it;
* :func:`suspend` / :func:`resume` (and the :class:`Suspended` context manager) freeze a process;
* :func:`decompilers_of` / :func:`kill_decompilers` / :func:`suspend_decompilers` act on the native
  decompiler processes below a daemon;
* :class:`HandleHolder` keeps a file or folder open with no sharing, the way an indexer or a virus
  scanner does (a rename or delete of it then fails);
* the disk-full seam of decision OD13 (no quota volume): :class:`Enospc` patches the write path of the
  *Python* side so that a write under a path raises ``ENOSPC``, and :func:`disk_reserve_config` builds
  the engine configuration whose ``diskReserve`` is above the free space (the engine must then answer
  ``busy{resource:"disk"}``). A real ``ENOSPC`` inside a Ghidra save is neither tested nor claimed.

Everything here is Windows-specific where it touches processes (``ctypes`` and ``ntdll``); the
Enospc seam and the random delay are portable.
"""
from __future__ import annotations

import builtins
import contextlib
import ctypes
import errno
import io
import os
import pathlib
import random
import shutil
import subprocess
import sys
import threading
import time

import oracle

# ------------------------------------------------------------------------------ processes

_k = None


def _kernel():
    global _k
    if _k is None:
        k = ctypes.windll.kernel32
        k.OpenProcess.restype = ctypes.c_void_p
        k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CreateFileW.restype = ctypes.c_void_p
        k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        _k = k
    return _k


def now() -> float:
    return time.perf_counter()


def ms_since(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def sleep_precise(sec: float):
    """Sleeps ``sec`` seconds, spinning for the last 3 ms (the trigger-timed delays are milliseconds)."""
    if sec <= 0:
        return
    end = now() + sec
    if sec > 0.004:
        time.sleep(sec - 0.003)
    while now() < end:
        pass


def terminate(pid: int, wait_s: float = 120) -> dict:
    """``TerminateProcess`` on ``pid`` and a wait (up to ``wait_s``) for the process to be gone.
    Returns ``{"terminated", "terminate_call_ms", "exit_wait_ms", "wait_result"}`` or an ``error``.
    Only call it with a pid this run started."""
    k = _kernel()
    h = k.OpenProcess(0x100001, 0, pid)  # PROCESS_TERMINATE | SYNCHRONIZE
    if not h:
        return {"terminated": False, "error": "OpenProcess failed (already gone, or not ours)"}
    t0 = now()
    ok = k.TerminateProcess(h, 1)
    t_term = ms_since(t0)
    w = k.WaitForSingleObject(h, int(wait_s * 1000))
    k.CloseHandle(h)
    return {"terminated": bool(ok), "terminate_call_ms": t_term, "exit_wait_ms": ms_since(t0), "wait_result": w}


def _nt_process(fn: str, pid: int) -> bool:
    k = _kernel()
    h = k.OpenProcess(0x800, 0, pid)  # PROCESS_SUSPEND_RESUME
    if not h:
        return False
    try:
        return getattr(ctypes.windll.ntdll, fn)(ctypes.c_void_p(h)) == 0
    finally:
        k.CloseHandle(h)


def suspend(pid: int) -> bool:
    """``NtSuspendProcess``: every thread of ``pid`` stops (the suspended decompiler of SP3(b) and K7)."""
    return _nt_process("NtSuspendProcess", pid)


def resume(pid: int) -> bool:
    return _nt_process("NtResumeProcess", pid)


@contextlib.contextmanager
def Suspended(pid: int):
    """Suspends ``pid`` for the block and always resumes it."""
    if not suspend(pid):
        raise OSError(f"cannot suspend pid {pid}")
    try:
        yield pid
    finally:
        resume(pid)


def decompilers_of(daemon_pid: int, names=oracle.DECOMPILER_NAMES) -> list[int]:
    """Pids of the native decompiler processes below ``daemon_pid`` (it is their job object's owner)."""
    below = oracle.descendants([daemon_pid]) - {daemon_pid}
    return [p["pid"] for p in oracle.list_processes() if p["pid"] in below and p["name"].lower() in names]


def kill_decompilers(daemon_pid: int) -> list[dict]:
    """Kills every native decompiler below the daemon; the request that used it must fail alone
    (GR9), the pool respawns."""
    return [{"pid": p, **terminate(p, 10)} for p in decompilers_of(daemon_pid)]


def suspend_decompilers(daemon_pid: int) -> list[int]:
    """Suspends every native decompiler below the daemon; returns the pids (the caller resumes or
    kills them: a suspended decompiler never exits by itself, which is why K7 needs this case)."""
    done = []
    for p in decompilers_of(daemon_pid):
        if suspend(p):
            done.append(p)
    return done


def spawn_decompiler(ghidra: str) -> subprocess.Popen:
    """Starts the install's own native decompiler as a child of *this* process, reading its stdin: the
    planted orphan of X9 (suspend it with :func:`suspend`; kill it with :func:`terminate` when done)."""
    exe = pathlib.Path(ghidra) / "Ghidra" / "Features" / "Decompiler" / "os" / "win_x86_64" / "decompile.exe"
    if not exe.is_file():
        raise FileNotFoundError(exe)
    return subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def spawn_idle(seconds: float = 600.0, extra_threads: int = 0) -> subprocess.Popen:
    """A Python child that sleeps (and holds ``extra_threads`` sleeping threads, the planted leak of X10).
    The caller terminates it."""
    code = ("import threading, time\n"
            f"ts=[threading.Thread(target=time.sleep, args=({seconds},), daemon=True) for _ in range({extra_threads})]\n"
            "[t.start() for t in ts]\n"
            f"time.sleep({seconds})\n")
    return subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def kill_client_proc(proc: subprocess.Popen, wait_s: float = 10) -> dict:
    """Kills a client process (a harness started with ``subprocess``); its connection drops with it."""
    r = terminate(proc.pid, wait_s)
    with contextlib.suppress(Exception):
        proc.wait(timeout=wait_s)
    return r


def abort_connection(session) -> bool:
    """Drops a ``SocketSession``'s connection without a goodbye (a reset, as when its process dies):
    the daemon sees a dead client. The session object is unusable afterwards."""
    import socket
    import struct
    sock = getattr(session, "sock", None)
    if sock is None:
        return False
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    for name in ("_w", "_r"):
        with contextlib.suppress(Exception):
            getattr(session, name).close()
    with contextlib.suppress(OSError):
        sock.close()
    return True


# ------------------------------------------------------------------------------ timed kills

def random_delay(rng: random.Random, lo_s: float, hi_s: float) -> float:
    """A kill delay drawn uniformly in ``[lo_s, hi_s]`` from a seeded generator (so a run is repeatable)."""
    return lo_s + (hi_s - lo_s) * rng.random()


def _listing(path):
    try:
        return frozenset(os.listdir(path))
    except OSError:
        return frozenset()


def timed_kill(pid: int, start, delay_s: float = 0.0, watch=None, max_wait_s: float = 120.0,
               kill=terminate) -> dict:
    """Runs ``start()`` (which must return at once, e.g. start a thread that sends the request) and kills
    ``pid`` ``delay_s`` seconds later.

    *Random-time kill*: ``watch`` is None, the delay counts from the start.
    *Trigger-timed kill*: ``watch`` is a folder (the version folder of the program being saved); the
    delay counts from the first change of its listing. If the listing never changes within
    ``max_wait_s`` the process is killed anyway and ``trigger_hit`` is false (the iteration says so).

    Returns ``{"delay_s", "trigger_hit", "trigger_ms_after_start", "kill"}``."""
    init = _listing(watch) if watch else None
    t_start = now()
    start()
    t_trig = None
    if watch:
        while now() - t_start < max_wait_s:
            if _listing(watch) != init:
                t_trig = now()
                break
        base = t_trig if t_trig is not None else now()
    else:
        base = t_start
    sleep_precise(delay_s - (now() - base))
    kr = kill(pid)
    return {"delay_s": round(delay_s, 5), "trigger_hit": t_trig is not None if watch else None,
            "trigger_ms_after_start": round((t_trig - t_start) * 1000, 1) if t_trig else None, "kill": kr}


def measure_trigger(run, watch, timeout_s: float = 120.0):
    """Calibrates a trigger-timed kill: ``run()`` performs the operation (blocking); a thread watches
    ``watch``. Returns milliseconds from the first listing change to the end of ``run()`` (the window a
    kill delay must fall in), or None when no change was seen."""
    init = _listing(watch)
    done = {}

    def go():
        run()
        done["t"] = now()
    th = threading.Thread(target=go, daemon=True)
    t0 = now()
    th.start()
    t_trig = None
    while "t" not in done and now() - t0 < timeout_s:
        if t_trig is None and _listing(watch) != init:
            t_trig = now()
    th.join(timeout_s)
    return None if t_trig is None or "t" not in done else round((done["t"] - t_trig) * 1000, 2)


# ------------------------------------------------------------------------------ handle holder

class HandleHolder:
    """Keeps ``path`` (a file, or a folder) open with the given sharing until released. With the default
    ``share=0`` nothing else can open it for write, rename or delete it: the effect of an indexer or a
    scanner that grabbed a file (Hydralysis retries ``PermissionError`` with a backoff, 4.1).

    ``with HandleHolder(path): ...`` or ``h = HandleHolder(path).acquire() ... h.release()``."""

    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a folder

    def __init__(self, path, share: int = 0):
        self.path = str(path)
        self.share = share
        self.handle = None

    def acquire(self) -> "HandleHolder":
        k = _kernel()
        flags = self.FILE_FLAG_BACKUP_SEMANTICS if os.path.isdir(self.path) else 0
        h = k.CreateFileW(self.path, self.GENERIC_READ, self.share, None, self.OPEN_EXISTING, flags, None)
        if h in (None, ctypes.c_void_p(-1).value):
            raise OSError(ctypes.get_last_error() or ctypes.GetLastError(), f"cannot hold {self.path}")
        self.handle = h
        return self

    def release(self):
        if self.handle:
            _kernel().CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


# ------------------------------------------------------------------------------ the disk-full seam (OD13)

class Enospc:
    """Python-side disk-full seam: while active, a write to a path for which ``match(path)`` is true
    raises ``OSError(ENOSPC)`` after ``allow_bytes`` bytes have been written under it.

    It patches ``builtins.open`` / ``io.open`` (the returned file's ``write`` and ``flush``), ``os.open``
    (to remember which descriptor is which path), ``os.write`` and ``os.fsync``. A patched write that
    fails leaves whatever it had already written, as a full disk would; code under test must remove its
    staging. ``hits`` counts the failures. No quota volume is needed (OD13); a real ENOSPC inside a
    Ghidra save is not tested.

        with Enospc(lambda p: "lineages" in p) as e:
            ...
        assert e.hits"""

    def __init__(self, match=lambda path: True, allow_bytes: int = 0):
        self.match = match
        self.allow = allow_bytes
        self.hits = 0
        self._fd_path: dict[int, str] = {}
        self._written = 0
        self._orig = {}
        self._lock = threading.Lock()

    def _fail(self, path):
        self.hits += 1
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)

    def _charge(self, path, n):
        with self._lock:
            if self._written + n > self.allow:
                self._fail(path)
            self._written += n

    def __enter__(self):
        me = self
        self._orig = {"open": builtins.open, "io_open": io.open, "os_open": os.open, "os_write": os.write,
                      "os_fsync": os.fsync}
        o_open, o_os_open, o_write, o_fsync = builtins.open, os.open, os.write, os.fsync

        class _F:
            def __init__(self, f, path):
                self._f, self._p = f, path

            def write(self, data):
                me._charge(self._p, len(data))
                return self._f.write(data)

            def __getattr__(self, name):
                return getattr(self._f, name)

            def __enter__(self):
                self._f.__enter__()
                return self

            def __exit__(self, *a):
                return self._f.__exit__(*a)

            def __iter__(self):
                return iter(self._f)

        def patched_open(file, mode="r", *a, **k):
            f = o_open(file, mode, *a, **k)
            if isinstance(file, (str, bytes, os.PathLike)) and any(c in mode for c in "wax+") and me.match(os.fspath(file)):
                return _F(f, os.fspath(file))
            return f

        def patched_os_open(path, flags, *a, **k):
            fd = o_os_open(path, flags, *a, **k)
            if isinstance(path, (str, os.PathLike)) and me.match(os.fspath(path)):
                me._fd_path[fd] = os.fspath(path)
            return fd

        def patched_write(fd, data):
            p = me._fd_path.get(fd)
            if p is not None:
                me._charge(p, len(data))
            return o_write(fd, data)

        def patched_fsync(fd):
            p = me._fd_path.get(fd if isinstance(fd, int) else getattr(fd, "fileno", lambda: -1)())
            if p is not None and me._written >= me.allow and me.hits:
                me._fail(p)
            return o_fsync(fd)

        builtins.open = patched_open
        io.open = patched_open
        os.open = patched_os_open
        os.write = patched_write
        os.fsync = patched_fsync
        return self

    def __exit__(self, *exc):
        builtins.open = self._orig["open"]
        io.open = self._orig["io_open"]
        os.open = self._orig["os_open"]
        os.write = self._orig["os_write"]
        os.fsync = self._orig["os_fsync"]
        self._fd_path.clear()


def free_bytes(path) -> int:
    return shutil.disk_usage(path).free


def disk_reserve_config(path, above: int = 1 << 30) -> dict:
    """The engine side of OD13: a daemon configuration (``config.json`` entries) whose ``diskReserve`` is
    ``above`` bytes more than the free space of ``path``'s volume, so that admission must refuse a new
    fork or view with ``busy{resource:"disk"}``. The engine that does this is E9 (hydra.4); on hydra.3
    the key is ignored and a fork is admitted (the red result the red table records)."""
    return {"diskReserve": free_bytes(path) + above}


# ------------------------------------------------------------------------------ cleanup helper

def terminate_all(procs, wait_s: float = 10):
    """Kills the Popen objects the caller started (never anything else) and reaps them."""
    for p in procs:
        with contextlib.suppress(Exception):
            if p.poll() is None:
                resume(p.pid)  # a suspended process cannot be reaped cleanly
                terminate(p.pid, wait_s)
            p.wait(timeout=wait_s)
