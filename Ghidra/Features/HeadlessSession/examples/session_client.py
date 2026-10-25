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
"""Minimal client for the Ghidra headless session (protocol 1, see ../README.md).

Launch one and drive it over its stdio:

    with StdioSession("<ghidra>/support/headlessSession.bat", "-project", "C:/re/Game") as s:
        s.call("open_program", path="game.exe")
        print(s.call("decompile", address="0x140001000")["c"])

Or join a session that serves a loopback socket (``-listen 0 -endpoint <file>``):

    with SocketSession("<endpoint file>", client="my-agent", harness="cli") as s:
        print(s.call("status"))

Standard library only. Thread-safe enough for one caller thread per session object.
"""
import json
import socket
import subprocess
import time


class SessionError(Exception):
    def __init__(self, code, message, details=None, trace=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.trace = trace


class _Base:
    def __init__(self):
        self._id = 0
        self._pending = {}       # responses received while waiting for another id
        self.events = []        # progress events received, oldest first
        self.on_event = None    # optional callback(event_dict)
        self.last_ms = 0        # server time of the last call
        self.last_wall = 0.0    # wall time of the last call, transport included

    def _send(self, line):
        raise NotImplementedError

    def _recv(self):
        raise NotImplementedError

    def call(self, cmd, **fields):
        """Sends one request and waits for its response. Raises SessionError on ok:false."""
        rid = self.send(cmd, **fields)
        return self.wait(rid)

    def send(self, cmd, **fields):
        """Sends a request without waiting; returns its id (for cancel, or a later wait)."""
        self._id += 1
        req = {"id": self._id, "cmd": cmd, **fields}
        self._t0 = time.perf_counter()
        self._send(json.dumps(req) + "\n")
        return self._id

    def wait(self, rid):
        """Waits for the response to request ``rid``; other responses are kept for their own wait."""
        while rid not in self._pending:
            line = self._recv()
            if not line:
                raise SessionError("closed", "the session ended")
            msg = json.loads(line)
            if "event" in msg:
                self.events.append(msg)
                if self.on_event:
                    self.on_event(msg)
                continue
            self._pending[msg.get("id")] = msg
        msg = self._pending.pop(rid)
        self.last_wall = time.perf_counter() - self._t0
        self.last_ms = msg.get("ms", 0)
        if not msg.get("ok"):
            e = msg.get("error", {})
            raise SessionError(e.get("code"), e.get("message"), e.get("details"),
                               e.get("trace"))
        return msg["result"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class StdioSession(_Base):
    """Starts headlessSession and speaks to it over stdin/stdout."""

    def __init__(self, launcher, *args, stderr_path=None, env=None):
        super().__init__()
        self._stderr = open(stderr_path, "ab") if stderr_path else subprocess.DEVNULL
        self.proc = subprocess.Popen([launcher, *args], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self._stderr, env=env,
                                     text=True, encoding="utf-8", bufsize=1)
        t0 = time.perf_counter()
        first = json.loads(self.proc.stdout.readline() or '{"event":"fatal"}')
        self.startup_wall = time.perf_counter() - t0
        if first.get("event") != "ready":
            raise SessionError(first.get("error", {}).get("code", "fatal"),
                               first.get("error", {}).get("message", "did not start"))
        self.ready = first

    def _send(self, line):
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self):
        return self.proc.stdout.readline()

    def close(self):
        if self.proc.poll() is None:
            try:
                self.call("shutdown")
            except Exception:
                pass
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._stderr is not subprocess.DEVNULL:
            self._stderr.close()


class SocketSession(_Base):
    """Joins a running session through its endpoint file (port + token)."""

    def __init__(self, endpoint_file, client="", harness="", timeout=None):
        super().__init__()
        with open(endpoint_file, encoding="utf-8") as f:
            ep = json.load(f)
        self.endpoint = ep
        self.sock = socket.create_connection((ep["host"], ep["port"]), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._r = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self._w = self.sock.makefile("w", encoding="utf-8", newline="\n")
        self.hello = self.call("hello", token=ep["token"], client=client, harness=harness)

    def _send(self, line):
        self._w.write(line)
        self._w.flush()

    def _recv(self):
        return self._r.readline()

    def close(self):
        # makefile() objects keep the socket open: close them, then shut the socket down, so the
        # session sees the disconnect (and releases what this client held) at once.
        for f in (self._w, self._r):
            try:
                f.close()
            except OSError:
                pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
