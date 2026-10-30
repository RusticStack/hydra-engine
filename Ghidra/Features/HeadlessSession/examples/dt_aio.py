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
"""Async connection I/O (Hydra Rust plan, goal 2): an idle client costs the daemon no OS thread.

* ``aio_idle_clients``: ``AIO_N`` socket clients connect, authenticate and then wait. Before the
  change every client held two platform threads for as long as it stayed (its reader and its
  writer), plus its ordered-lane thread for ever once it had sent one ordered request. Now the reader
  and the writer of a socket client are virtual threads (``-set connectionThreads``, default
  ``virtual``) and the lane thread ends after ``laneIdleMs``. The test counts the daemon's OS threads
  (Toolhelp32, Windows) with the clients connected and again after they each pipelined ordered
  requests and went idle: both deltas must stay far below one thread per client. It also checks
  that each client's pipelined ordered requests are answered in the order sent, and that every client
  is released when it closes.

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only aio_idle_clients
"""
import ctypes
import json
import os
import socket
import sys
import time

import daemon_tests as dt

AIO_N = 300          # idle clients
AIO_PIPE = 20        # ordered requests each of AIO_ORDER_N clients pipelines
AIO_ORDER_N = 60
LANE_IDLE_MS = 2000


def os_threads(pid: int) -> int:
    """The number of OS threads of process ``pid`` (Windows Toolhelp32)."""
    if sys.platform != "win32":
        return len(os.listdir(f"/proc/{pid}/task"))

    class TE32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ThreadID", ctypes.c_ulong), ("th32OwnerProcessID", ctypes.c_ulong),
                    ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    snap = k32.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
    if not snap or snap == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot")
    try:
        te = TE32()
        te.dwSize = ctypes.sizeof(TE32)
        n = 0
        ok = k32.Thread32First(ctypes.c_void_p(snap), ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                n += 1
            ok = k32.Thread32Next(ctypes.c_void_p(snap), ctypes.byref(te))
        return n
    finally:
        k32.CloseHandle(ctypes.c_void_p(snap))


def settled_threads(pid: int, secs: float = 3.0) -> int:
    """The thread count after it stopped moving (the lowest of a few samples over ``secs``)."""
    best = None
    end = time.monotonic() + secs
    while time.monotonic() < end:
        n = os_threads(pid)
        best = n if best is None else min(best, n)
        time.sleep(0.25)
    return best


class Raw:
    """A bare JSON-lines socket client (no library reader thread: the point is many of them)."""

    def __init__(self, ep, name):
        self.sock = socket.create_connection((ep["host"], ep["port"]), timeout=60)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        self.send({"id": "h", "cmd": "hello", "token": ep["token"], "client": name,
                   "harness": "aio", "protocol": 2})
        r = self.recv()
        dt.check(r.get("ok"), f"hello of {name} failed: {r}")

    def send(self, o):
        self.sock.sendall((json.dumps(o) + "\n").encode())

    def recv(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(1 << 16)
            if not chunk:
                raise dt.Fail("the daemon closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def reply(self):
        while True:
            r = self.recv()
            if "ok" in r:
                return r

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def t_aio_idle_clients(c):
    d = c.daemon("aio-idle", engine={"laneIdleMs": LANE_IDLE_MS})
    clients = []
    with d.connect("anchor", "tests") as s:
        ep = d.read_endpoint()
        pid = int(ep["pid"])
        base = settled_threads(pid)
        try:
            for i in range(AIO_N):
                clients.append(Raw(ep, f"idle-{i}"))
            connected = settled_threads(pid)
            n_cl = len(s.call("status")["clients"])
            dt.check(n_cl == AIO_N + 1, f"{n_cl} clients listed, {AIO_N + 1} connected")
            # ordered requests, pipelined: answered in the order sent on every connection
            for r in clients[:AIO_ORDER_N]:
                for k in range(AIO_PIPE):
                    r.send({"id": k, "cmd": "projects"})
            for j, r in enumerate(clients[:AIO_ORDER_N]):
                ids = [r.reply().get("id") for _ in range(AIO_PIPE)]
                dt.check(ids == list(range(AIO_PIPE)), f"client {j}: replies out of order: {ids}")
            for r in clients:
                r.send({"id": "p", "cmd": "ping"})
            for r in clients:
                p = r.reply()
                dt.check(p.get("ok") and p.get("id") == "p", f"an idle client's ping failed: {p}")
            time.sleep(LANE_IDLE_MS / 1000 + 2)
            idle = settled_threads(pid)
        finally:
            for r in clients:
                r.close()
        dt.wait_for(lambda: len(s.call("status")["clients"]) == 1,
                    "every closed client to be released", 60, 0.2)
        after = settled_threads(pid)
    d.stop()
    c.timings["aio: OS threads before/connected/idle/after"] = [base, connected, idle, after]
    # far below one thread per client; the slack is for virtual-thread carriers and pollers
    bound = AIO_N // 4
    dt.check(connected - base < bound,
             f"{AIO_N} idle clients added {connected - base} OS threads (bound {bound}): "
             f"base {base}, connected {connected}")
    dt.check(idle - base < bound,
             f"{AIO_N} clients that sent ordered requests and went idle hold {idle - base} OS threads "
             f"(bound {bound}; lane threads end after laneIdleMs): base {base}, idle {idle}")
    return (f"{AIO_N} idle socket clients: daemon OS threads {base} -> {connected} (connected) -> "
            f"{idle} (after {AIO_ORDER_N} pipelined {AIO_PIPE} ordered requests each, in order, and "
            f"went idle) -> {after} (closed)")


TESTS = {
    "aio_idle_clients": t_aio_idle_clients,
}

BASELINE = {}
