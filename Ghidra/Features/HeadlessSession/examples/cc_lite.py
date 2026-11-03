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
"""The Python client against a hydra-lite daemon (HYDRA-LITE.md, "Clients"). Standard library only.
Loaded by ``client_compat_tests.py``, or alone:

    python cc_lite.py --offline                      # the tests with fake daemons
    python cc_lite.py --ghidra <install> --work <empty dir>     # also the end-to-end test

Offline, with a fake lite daemon and a fake full daemon (loopback servers that speak the protocol
lines the real ones do, written from HYDRA-LITE.md):

* ``lite_key``: the identity-cache key of a command line is the FNV-1a function of ``hydra-front``
  and ``hydra-lite``, with their known value.
* ``lite_launcher``: ``HYDRA_LITE`` off / auto / only decide whether the command is hydra-lite in
  front of the JVM line, the JVM line (and a detached ``learn`` afterwards), or an error; an invalid
  value is refused; the full daemon never gets a front.
* ``lite_failover``: a request answered ``use_full_daemon`` is sent again to the full daemon with
  its own id; what the session had opened is opened there first, in order; every later request goes
  to the full daemon; the lite daemon sees nothing more.
* ``lite_failover_ids``: when the full daemon numbers the replayed projects differently, requests
  that name the old ids are rewritten.
* ``lite_failover_inflight``: two requests in flight when the first is refused both get the full
  daemon's answer.
* ``lite_failover_failed``: when the full daemon cannot be reached the caller gets the refusal,
  with ``details.failover`` saying why, and the lite connection is not touched further.
* ``lite_only``: a session that is not armed (``HYDRA_LITE=only``) raises ``use_full_daemon``.
* ``lite_capacity``: a lite daemon with all its workers busy answers ``hello`` with
  ``use_full_daemon`` and no id: ``connect`` returns a session of the full daemon.

Online (``--ghidra`` and ``HYDRA_LITE_EXE``): ``lite_e2e`` is ``reply_parity.py auto``: the parity
corpus against a Java daemon and against hydra-lite with a full daemon behind it, same final replies.
"""
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

import client_compat_tests as cc
from client_compat_tests import Fail, check, raised

HERE = pathlib.Path(__file__).resolve().parent

HELLO = {"protocol": 3, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.6", "ghidraVersion": "12.3",
         "ghidra": "12.3", "protocolMin": 2, "protocolMax": 3, "capabilities": {}, "limits": {},
         "policy": {}}


class Server:
    """A loopback server. ``handler(conn, req)`` returns the reply object for a request (``id``
    is filled in), or None for no answer. ``requests`` keeps every request in order."""

    def __init__(self, handler, lite=False):
        self.handler = handler
        self.requests = []
        self.connections = 0
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.endpoint = {"host": "127.0.0.1", "port": self._srv.getsockname()[1], "token": "t",
                         "protocol": 3, "protocolMin": 2, "protocolMax": 3, "pid": os.getpid()}
        if lite:
            self.endpoint["lite"] = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                sock, _ = self._srv.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(sock, {}), daemon=True).start()

    def _serve(self, sock, conn):
        try:
            with sock, sock.makefile("rw", encoding="utf-8", newline="\n") as f:
                for line in f:
                    req = json.loads(line)
                    with self._lock:
                        self.requests.append(req)
                    reply = self.handler(conn, req)
                    if reply is not None:
                        reply = {"id": req.get("id"), **reply}
                        f.write(json.dumps(reply) + "\n")
                        f.flush()
        except (OSError, ValueError):
            pass

    def cmds(self):
        return [r["cmd"] for r in self.requests]

    def stop(self):
        with contextlib.suppress(OSError):
            self._srv.close()


def ok(result):
    return {"ok": True, "result": result, "ms": 0}


def refusal(reason, cmd):
    return {"ok": False, "error": {"code": "use_full_daemon", "message": f"{cmd} is for the full daemon",
                                   "details": {"reason": reason, "cmd": cmd}}, "ms": 0}


def lite_handler(first_project="p1"):
    """What hydra-lite does: answers hello, open_project, open_program and functions; refuses
    decompile and everything else; after a refusal only ping and hello are answered."""
    def handle(conn, req):
        cmd = req["cmd"]
        if cmd == "hello":
            return ok(dict(HELLO, source="lite"))
        if conn.get("diverged") and cmd != "ping":
            return refusal("diverged_connection", cmd)
        if cmd == "ping":
            return ok({"pong": True})
        if cmd == "open_project":
            return ok({"id": first_project, "source": "lite"})
        if cmd == "open_program":
            return ok({"path": req.get("path"), "source": "lite"})
        if cmd == "functions":
            return ok({"source": "lite", "functions": []})
        conn["diverged"] = True
        return refusal("unsupported_command", cmd)
    return handle


def full_handler(project_ids):
    """The full daemon: answers everything; open_project hands out ``project_ids`` in turn."""
    ids = iter(project_ids)

    def handle(_conn, req):
        cmd = req["cmd"]
        if cmd == "hello":
            return ok(dict(HELLO, source="full"))
        if cmd == "open_project":
            return ok({"id": next(ids), "source": "full"})
        return ok({"source": "full", "cmd": cmd, "echo": {k: v for k, v in req.items()
                                                          if k not in ("id", "cmd")}})
    return handle


class StubDaemon:
    """The part of ``Daemon`` a ``_Failover`` uses: ``full().connect(client, harness)``."""

    def __init__(self, gs, full_server=None, error=None):
        self.gs, self.full_server, self.error, self.connects = gs, full_server, error, []

    def full(self):
        return self

    def connect(self, client, harness):
        self.connects.append((client, harness))
        if self.error:
            raise self.error
        return self.gs.SocketSession(self.full_server.endpoint, client=client, harness=harness,
                                     check=False)


def armed(gs, lite, stub, client="agent", harness="h"):
    s = gs.SocketSession(lite.endpoint, client=client, harness=harness, check=False)
    s._arm_failover(gs._Failover(stub, client, harness))
    return s


# ---- the tests -------------------------------------------------------------------------------

def t_lite_key(c):
    gs = c.new
    check(gs.lite_command_key([]) == "cbf29ce484222325", "the key of no arguments is the FNV offset")
    a = gs.lite_command_key(["-stateDir", "S", "-instance", "x"])
    check(len(a) == 16 and a != gs.lite_command_key(["-stateDir", "T", "-instance", "x"]), a)
    # FNV-1a 64 of "a" followed by NUL, computed by hand: ((offset ^ 0x61) * prime) ^ 0) * prime
    h = 0xcbf29ce484222325
    for b in b"a\0":
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    check(gs.lite_command_key(["a"]) == f"{h:016x}", "FNV-1a over the bytes and a NUL")
    return f"key of ['a'] is {h:016x}"


def t_lite_launcher(c):
    gs = c.new
    with tempfile.TemporaryDirectory() as td:
        state = pathlib.Path(td) / "state"
        state.mkdir()
        fake_exe = pathlib.Path(td) / ("hydra-lite.exe" if os.name == "nt" else "hydra-lite")
        fake_exe.write_bytes(b"")
        argv = ["java", "-cp", "x", "SessionMain", "-daemon", "-stateDir", str(state), "-instance", "i1"]
        saved = {k: os.environ.pop(k, None) for k in ("HYDRA_LITE", "HYDRA_LITE_EXE", "HYDRA_LITE_OPTS",
                                                      "GHIDRA_SESSION_FRONT")}
        try:
            def pick(mode, exe=None):
                d = gs.Daemon(None, str(state), "i1", lite=mode)
                if exe:
                    os.environ["HYDRA_LITE_EXE"] = str(exe)
                else:
                    os.environ.pop("HYDRA_LITE_EXE", None)
                info = {}
                out = d._lite_argv(list(argv), info, gs.load_config(state, {"lite": mode}))
                return d, out, info
            _d, out, info = pick("off", fake_exe)
            check(out == argv and not info, "off leaves the command alone")
            _d, out, info = pick("auto", None)
            check(out == argv, "auto without hydra-lite installed starts the JVM")
            d, out, info = pick("auto", fake_exe)
            check(out == argv and info.get("lite") == "learning" and d._teach is not None,
                  f"auto without an identity starts the JVM and teaches: {info}")
            err = raised(lambda: pick("only", fake_exe), gs.LaunchError)
            check(err.code == "lite_unavailable", err.code)
            err = raised(lambda: pick("only", None), gs.LaunchError)
            check(err.code == "lite_unavailable", err.code)
            ident = state / "i1.front-identity.json"
            ident.write_text(json.dumps({"key": "0" * 16, "hello": {}, "endpoint": {}}))
            _d, out, info = pick("auto", fake_exe)
            check(out == argv, "an identity for another command line does not count")
            ident.write_text(json.dumps({"key": gs.lite_command_key(argv), "hello": {}, "endpoint": {}}))
            os.environ["HYDRA_LITE_OPTS"] = "--workers 8"
            for mode in ("auto", "only"):
                _d, out, info = pick(mode, fake_exe)
                check(out == [str(fake_exe), "--workers", "8", "--", *argv] and info["lite"] == mode
                      and info["front"] == str(fake_exe), f"{mode}: {out}")
            full = gs.Daemon(None, str(state), "i1", lite="auto").full()
            check(full.instance == "i1.full" and full._full_daemon and full.lite_mode() == "off",
                  f"{full.instance}")
            check(gs.full_instance("x" * 64) == "x" * 59 + ".full", "long instance names are cut")
            os.environ["HYDRA_LITE"] = "sometimes"
            err = raised(lambda: gs.load_config(state), gs.LaunchError)
            check("off, auto or only" in str(err), str(err))
            os.environ["HYDRA_LITE"] = " AUTO "
            check(gs.load_config(state)["lite"] == "auto", "the value is trimmed and lower-cased")
            os.environ.pop("HYDRA_LITE")
            check(gs.load_config(state)["lite"] == "off", "the default is off")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    return "off, auto, only, learning, identity key, full instance, bad value"


def t_lite_failover(c):
    gs = c.new
    lite, full = Server(lite_handler(), lite=True), Server(full_handler(["p1"]))
    stub = StubDaemon(gs, full)
    try:
        s = armed(gs, lite, stub)
        p = s.call("open_project", path="C:/p/a.gpr")
        check(p["source"] == "lite", "open_project is the lite daemon's")
        s.call("open_program", path="/a.exe")
        check(s.call("functions")["source"] == "lite", "functions is the lite daemon's")
        check(not s.failed_over and not stub.connects, "no failover yet")
        d = s.call("decompile", name="entry")
        check(d["source"] == "full" and d["cmd"] == "decompile" and d["echo"] == {"name": "entry"},
              f"decompile answered by the full daemon: {d}")
        check(s.failed_over, "the session moved")
        check(stub.connects == [("agent", "h")], f"the full daemon was asked for once: {stub.connects}")
        replay = [(r["cmd"], r.get("path")) for r in full.requests]
        check(replay == [("hello", None), ("open_project", "C:/p/a.gpr"), ("open_program", "/a.exe"),
                         ("decompile", None)], f"replay, then the request: {replay}")
        check("token" not in full.requests[1], "the replay carries no token")
        before = list(lite.cmds())
        check(s.call("functions")["source"] == "full", "later requests go to the full daemon")
        check(s.call("info")["source"] == "full", "and so do the commands lite also refuses")
        check(lite.cmds() == before, f"the lite daemon saw nothing more: {lite.cmds()}")
        check(s.endpoint is full.endpoint or s.endpoint["port"] == full.endpoint["port"],
              "the session's endpoint is the full daemon's now")
        ids = [r["id"] for r in full.requests if r["cmd"] == "decompile"]
        check(ids == [5], f"the request kept the id the caller got (hello 1 .. functions 4): {ids}")
        s.close()
    finally:
        lite.stop()
        full.stop()
    return "request resent with its id after the replay of hello, open_project, open_program"


def t_lite_failover_ids(c):
    gs = c.new
    lite, full = Server(lite_handler("p1"), lite=True), Server(full_handler(["p7"]))
    stub = StubDaemon(gs, full)
    try:
        s = armed(gs, lite, stub)
        s.call("open_project", path="a.gpr")
        s.call("open_program", path="/a.exe")
        s.call("decompile", program="p1:/a.exe", project="p1")
        sent = [r for r in full.requests if r["cmd"] == "decompile"][0]
        check(sent["program"] == "p7:/a.exe" and sent["project"] == "p7", f"ids rewritten: {sent}")
        s.call("info", program="p1:/a.exe")
        last = full.requests[-1]
        check(last["program"] == "p7:/a.exe", f"later requests too: {last}")
        s.call("info", program="p2:/b.exe")
        check(full.requests[-1]["program"] == "p2:/b.exe", "other ids are left alone")
        s.close()
    finally:
        lite.stop()
        full.stop()
    return "p1 -> p7 on the full daemon, in program and project fields"


def t_lite_failover_inflight(c):
    gs = c.new
    lite, full = Server(lite_handler(), lite=True), Server(full_handler(["p1"]))
    stub = StubDaemon(gs, full)
    try:
        s = armed(gs, lite, stub)
        s.call("open_project", path="a.gpr")
        a = s.send("decompile", name="x")
        b = s.send("journal")
        ra, rb = s.wait(a), s.wait(b)
        check(ra["cmd"] == "decompile" and rb["cmd"] == "journal", f"{ra} {rb}")
        check(len(stub.connects) == 1, "one failover for both")
        cmds = [r["cmd"] for r in full.requests]
        check(cmds == ["hello", "open_project", "decompile", "journal"], f"in id order: {cmds}")
        s.close()
    finally:
        lite.stop()
        full.stop()
    return "both requests answered by the full daemon, once connected"


def t_lite_failover_failed(c):
    gs = c.new
    lite = Server(lite_handler(), lite=True)
    stub = StubDaemon(gs, error=gs.LaunchError("no JVM", "exited_early"))
    try:
        s = armed(gs, lite, stub)
        s.call("open_project", path="a.gpr")
        e = raised(lambda: s.call("decompile", name="x"), gs.SessionError)
        check(e.code == "use_full_daemon" and "no JVM" in e.details.get("failover", ""),
              f"{e.code} {e.details}")
        check(not s.failed_over, "the session did not move")
        e = raised(lambda: s.call("decompile", name="x"), gs.SessionError)
        check(e.code == "use_full_daemon" and e.details.get("reason") == "diverged_connection",
              f"a second try sees the lite daemon's own refusal: {e.details}")
        check(len(stub.connects) == 1, "no second attempt: the failover is tried once")
        s.close()
    finally:
        lite.stop()
    return "the refusal is the answer, details.failover = the launch error"


def t_lite_only(c):
    gs = c.new
    lite = Server(lite_handler(), lite=True)
    try:
        s = gs.SocketSession(lite.endpoint, client="a", harness="h", check=False)
        e = raised(lambda: s.call("decompile", name="x"), gs.SessionError)
        check(e.code == "use_full_daemon" and e.details["reason"] == "unsupported_command"
              and e.details["cmd"] == "decompile", f"{e.code} {e.details}")
        s.close()
    finally:
        lite.stop()
    return "an unarmed session raises SessionError use_full_daemon with the reason"


def t_lite_capacity(c):
    gs = c.new
    full = Server(full_handler(["p1"]))

    def busy(_conn, _req):
        return None
    # a lite daemon that is full answers the first line with no id and closes
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def acceptor():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall((json.dumps({"ok": False, "error": {
                "code": "use_full_daemon", "message": "64 connections are served already",
                "details": {"reason": "capacity"}}, "ms": 0}) + "\n").encode())
    threading.Thread(target=acceptor, daemon=True).start()
    with tempfile.TemporaryDirectory() as td:
        state = pathlib.Path(td)
        try:
            d = gs.Daemon(None, str(state), "cap", lite="auto")
            (state / "cap.json").write_text(json.dumps(
                {"host": "127.0.0.1", "port": port, "token": "t", "protocol": 3, "lite": True}))
            d.jvm_alive = lambda: True
            stub = StubDaemon(gs, full)
            d.full = lambda: stub
            s = d._try_connect("a", "h", fallback=True)
            check(s is not None and s.hello["source"] == "full", f"the full daemon's session: {s}")
            check(stub.connects == [("a", "h")], f"{stub.connects}")
            s.close()
        finally:
            srv.close()
            full.stop()
    return "the capacity refusal at hello turns into a full-daemon session"


TESTS = {n: globals()["t_" + n] for n in (
    "lite_key", "lite_launcher", "lite_failover", "lite_failover_ids", "lite_failover_inflight",
    "lite_failover_failed", "lite_only", "lite_capacity")}
OFFLINE = set(TESTS)


def t_lite_e2e(c):
    """The parity corpus against a Java daemon (HYDRA_LITE=off) and against hydra-lite with the
    full daemon behind it (HYDRA_LITE=auto): the same final reply for every request."""
    c.need_engine()
    exe = os.environ.get("HYDRA_LITE_EXE")
    if not exe or not pathlib.Path(exe).is_file():
        raise Fail("set HYDRA_LITE_EXE to the hydra-lite executable for the end-to-end test")
    import reply_parity as rp
    work = pathlib.Path(tempfile.mkdtemp(prefix="lite-e2e-", dir=str(c.state)))
    argv = [sys.executable, str(HERE / "reply_parity.py"), "auto", "--ghidra", c.a.ghidra,
            "--work", str(work), "--lite", exe]
    agent = os.environ.get("HYDRA_AGENT_EXE")  # also drive the Rust client (hydra-agent call)
    if agent:
        argv += ["--agent", agent]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=1500, check=False)
    del rp
    tail = "\n".join((out.stdout + out.stderr).strip().splitlines()[-12:])
    if out.returncode != 0:
        raise Fail(f"reply_parity.py auto exited {out.returncode}:\n{tail}")
    return tail.splitlines()[-1] if tail else "passed"


TESTS["lite_e2e"] = t_lite_e2e

if __name__ == "__main__":
    cc.run_file(__file__)
