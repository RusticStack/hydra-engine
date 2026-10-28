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
"""Compatibility tests of the Python client library and the protocol-2 behaviour tests of
PROTOCOL-3.md 5.1 (package P1a). Standard library only; any OS.

    python client_compat_tests.py --ghidra <install> --work <empty dir>
                                  [--exe A.exe --dll B.dll] [--only a,b] [--list]
                                  [--tests-dir <dir>] [--report <file.json>] [--test-timeout S]
    python client_compat_tests.py --offline [--only a,b]       # the tests that need no engine

Two client libraries are under test, and neither is the one inside ``--ghidra``:

* ``stock``: ``stock/ghidra_session_1_0_0.py``, the 1.0.0 client at ``b6df709e1e`` vendored byte
  for byte (the ``stock_vendored`` test proves it). It speaks protocol 2 only, so a test written
  against it is a real protocol-2 client, which is what every ``cc_<package>.py`` needs.
* ``new``: ``../support/ghidra_session.py`` of this tree, the 1.1.0 client (protocols 2 to 3).

``--ghidra`` is the engine under test (an install directory: hydra.3 today, the hydra.4 candidate
later); each library starts and drives that engine's JVM through its own launcher. Tests start
their own daemon instances in ``<work>/state`` and stop them, so the user's daemon is never touched.

Tests that run here (``--list`` names them): the 1.1.0 client against fake protocol-2 and
protocol-3 servers, the range and endpoint-overlap rules, the ``engine`` pass-through of
``config.json``, the vendored file's identity, and, against the real engine, both libraries at
once on one daemon. An engine that serves only protocol 2 (hydra.3) must give the 1.1.0 client
``session.protocol == 2``; an engine that advertises ``protocolMax`` 3 must give it 3; the stock
client is at 2 against either (the V6 row of 5.1). The fake protocol-3 server is written from
3.1 of the spec: it stands in for the hydra.4 candidate until E1 exists and proves only what the
client does with such an answer.

More tests live in ``cc_<package>.py`` files next to this one (5.1; section 8: the loader is this
file's, ``dt_*.py`` and ``char_*.py`` are E0's): each exposes ``TESTS = {name: fn}`` (``fn(ctx)``
returns a note, or raises ``Fail``) and may expose ``OFFLINE = {names}`` for tests that need no
engine. They import this file by name (``import client_compat_tests as cc``; under ``python -I`` the file puts its own
directory on ``sys.path`` first), which gives them
``Fail``, ``check``, ``expect_error``, ``wait_for(cond, what, timeout)``, ``Ctx`` (``ctx.stock`` and ``ctx.new`` are the
two libraries; ``ctx.daemon(instance)`` is a **stock** daemon, ``ctx.new_daemon(instance)`` a 1.1.0
one; ``ctx.fixture()``, ``ctx.make_project`` and the rest are those of ``daemon_tests.Ctx``, which
this file loads by path), ``FakeEngine`` and the two libraries as ``stock_client()`` and
``new_client()``. A file that does not import is reported as a failure; an empty set is fine. Each
file also runs on its own, with the same options, when it ends with
``if __name__ == "__main__": cc.run_file(__file__)``: ``python cc_e1.py --ghidra ... --work ...``.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
SUPPORT = HERE.parent / "support"
STOCK_FILE = HERE / "stock" / "ghidra_session_1_0_0.py"
#: Git blob id of ``support/ghidra_session.py`` at ``b6df709e1e`` (``git rev-parse
#: b6df709e1e:Ghidra/Features/HeadlessSession/support/ghidra_session.py``): the 1.0.0 client.
STOCK_BLOB = "5bfce81b3eed9082bc24f8a9778f526990fdc0a5"


def _load(name, path):
    """Imports ``path`` as module ``name`` (without putting its directory on sys.path)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# daemon_tests is E0's file: its Ctx (fixtures, projects, cleanup) is reused, not copied.
# cc_*.py files and daemon_tests' own dt_*.py loader both import it by this name.
dt = sys.modules.get("daemon_tests") or _load("daemon_tests", HERE / "daemon_tests.py")
Fail = dt.Fail
check = dt.check
expect_error = dt.expect_error
wait_for = dt.wait_for

_LIBS = {}


def stock_client():
    """The vendored 1.0.0 client, as a module (loaded once)."""
    if "stock" not in _LIBS:
        _LIBS["stock"] = _load("ghidra_session_1_0_0", STOCK_FILE)
    return _LIBS["stock"]


def new_client(path=None):
    """The client under test, as a module (loaded once): ``../support/ghidra_session.py`` unless
    ``--client`` named another file."""
    key = str(path or SUPPORT / "ghidra_session.py")
    if key not in _LIBS:
        _LIBS[key] = _load("ghidra_session_under_test", key)
    return _LIBS[key]


class Ctx(dt.Ctx):
    """``daemon_tests.Ctx`` whose library (``self.gs``, so ``self.daemon()``) is the **stock**
    1.0.0 client; ``self.new`` is the client under test."""

    def __init__(self, a, stock, new):
        super().__init__(a, stock)
        self.stock = stock
        self.new = new

    def new_daemon(self, instance, **cfg):
        d = self.new.Daemon(self.a.ghidra, str(self.state), instance, **cfg)
        self.daemons.append(d)
        return d

    def need_engine(self):
        if self.a.offline:
            raise Fail("this test needs --ghidra (it was selected with --offline)")


# ---- a fake engine --------------------------------------------------------------------------

class FakeEngine:
    """A loopback server that answers ``hello`` with ``hello(request)`` (a result dict) and any
    other command with ``{"cmd": <name>}``. ``requests`` keeps every request in order; ``closed``
    counts the connections the client has closed."""

    def __init__(self, hello):
        self._hello = hello
        self.requests = []
        self.closed = 0
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.endpoint = {"host": "127.0.0.1", "port": self._srv.getsockname()[1], "token": "x"}
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            with conn, conn.makefile("rw", encoding="utf-8", newline="\n") as f:
                for line in f:
                    req = json.loads(line)
                    with self._lock:
                        self.requests.append(req)
                    result = self._hello(req) if req["cmd"] == "hello" else {"cmd": req["cmd"]}
                    f.write(json.dumps({"id": req["id"], "ok": True, "result": result, "ms": 0})
                            + "\n")
                    f.flush()
        except (OSError, ValueError):
            pass
        finally:
            with self._lock:
                self.closed += 1

    def hellos(self):
        return [r for r in self.requests if r["cmd"] == "hello"]

    def stop(self):
        with contextlib.suppress(OSError):
            self._srv.close()


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def v2_answer(_req):
    """What a hydra.2 or hydra.3 engine answers to any ``hello``: protocol 2, whatever was asked
    (``Session.java`` reads no ``protocol`` field)."""
    return {"protocol": 2, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.3",
            "ghidraVersion": "12.3", "ghidra": "12.3"}


def v3_answer(req):
    """The hello rule of 3.1: the requested protocol when it is in [2,3]; 3 when larger; 2 when
    absent, smaller or not an integer. A protocol 3 answer carries the v3 keys (C1)."""
    p = req.get("protocol")
    n = min(p, 3) if _is_int(p) and p >= 2 else 2
    out = {"protocol": n, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.4",
           "ghidraVersion": "12.3", "ghidra": "12.3"}
    if n == 3:
        out.update(protocolMin=2, protocolMax=3, capabilities={}, limits={}, policy={})
    return out


@contextlib.contextmanager
def fake(hello):
    srv = FakeEngine(hello)
    try:
        yield srv
    finally:
        srv.stop()


def raised(fn, exc):
    """The exception ``fn`` raises (which must be an ``exc``), else ``Fail``."""
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:  # noqa: BLE001
        raise Fail(f"expected {exc.__name__}, got {type(e).__name__}: {e}") from e
    raise Fail(f"expected {exc.__name__}, nothing was raised")


# ---- tests that need no engine --------------------------------------------------------------

def t_stock_vendored(c: Ctx):
    """The stock client is the 1.0.0 file of ``b6df709e1e``, byte for byte (a git blob id, so
    the checkout's line endings do not matter), and a protocol-2 client."""
    data = STOCK_FILE.read_bytes().replace(b"\r\n", b"\n")
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    check(blob == STOCK_BLOB, f"blob {blob} is not the 1.0.0 client {STOCK_BLOB}")
    s = c.stock
    check((s.CLIENT_VERSION, s.PROTOCOL) == ("1.0.0", 2),
          f"stock is {s.CLIENT_VERSION} / protocol {s.PROTOCOL}")
    check(not hasattr(s, "PROTOCOL_MIN"), "the stock client already has a protocol range")
    return f"blob {blob[:10]}, client {s.CLIENT_VERSION}, protocol {s.PROTOCOL}"


def t_new_client_identity(c: Ctx):
    n = c.new
    check((n.PROTOCOL, n.PROTOCOL_MIN) == (3, 2), f"range {n.PROTOCOL_MIN}..{n.PROTOCOL}")
    check(n.parse_version(n.CLIENT_VERSION) > n.parse_version("1.0.0"), n.CLIENT_VERSION)
    return f"client {n.CLIENT_VERSION} speaks {n.PROTOCOL_MIN}..{n.PROTOCOL}"


def t_fake_v2_server(c: Ctx):
    """The 1.1.0 client against a fake protocol-2 server (what hydra.2 and hydra.3 are): its hello
    asks for 3 and sends the client's identity, the answer 2 is accepted, and the session says 2."""
    n = c.new
    with fake(v2_answer) as srv:
        with n.SocketSession(srv.endpoint, client="cc", harness="tests") as s:
            h = srv.hellos()
            check(len(h) == 1, f"{len(h)} hello requests")
            check(h[0]["protocol"] == 3 and _is_int(h[0]["protocol"]), f"hello {h[0]}")
            check(h[0]["clientVersion"] == n.CLIENT_VERSION and h[0]["client"] == "cc" and
                  h[0]["harness"] == "tests" and h[0]["token"] == "x", f"hello {h[0]}")
            check(s.protocol == 2, f"session.protocol {s.protocol}")
            check(s.hello["protocol"] == 2, f"hello {s.hello}")
            check(s.call("ping") == {"cmd": "ping"}, "a call after the hello")
            check(s.labelled(client="a").protocol == 2, "a labelled view hides the protocol")
        wait_for(lambda: srv.closed == 1, "the fake engine saw the close", 5)
        # the daemon path: the endpoint of a protocol-2 daemon passes the check
        d = n.Daemon.__new__(n.Daemon)
        d.instance = "cc"
        inst = type("_Inst", (), {"dir": HERE})()
        n.Daemon._check_install(d, {"protocol": 2, "install": str(HERE)}, inst)
        n.check_compatible({"protocol": 2, "minClient": "1.0.0"})
    return "asked 3, answered 2, session.protocol 2"


def t_fake_v3_server(c: Ctx):
    """A fake protocol-3 server written from 3.1 (a stand-in for the hydra.4 candidate): the
    1.1.0 client gets 3 and keeps the v3 keys; the stock client against the same server asks 2,
    gets 2 and a reply without any v3 key (V6: ``protocol`` stays 2 for it)."""
    n, st = c.new, c.stock
    with fake(v3_answer) as srv:
        with n.SocketSession(srv.endpoint, client="cc", harness="tests") as s:
            check(s.protocol == 3, f"session.protocol {s.protocol}")
            check(s.hello["protocolMin"] == 2 and s.hello["protocolMax"] == 3, f"{s.hello}")
            check(s.call("ping") == {"cmd": "ping"}, "a call at protocol 3")
        with st.SocketSession(srv.endpoint, client="stock", harness="tests") as s:
            check(not hasattr(s, "protocol"), "the stock client has no session.protocol")
            check(s.hello["protocol"] == 2, f"stock hello {s.hello}")
            check(not {"protocolMin", "protocolMax", "capabilities", "limits", "policy"} &
                  set(s.hello), f"a v3 key reached a protocol-2 client: {s.hello}")
            check(s.call("ping") == {"cmd": "ping"}, "a stock call")
        asked = [h["protocol"] for h in srv.hellos()]
        check(asked == [3, 2], f"hello asked {asked}")
        # a client pinned to 2 (the E0 shim's way) gets 2 as well
        with dt.client_protocol(n, 2):
            with n.SocketSession(srv.endpoint, client="pinned", harness="tests") as s:
                check(s.protocol == 2, f"pinned session.protocol {s.protocol}")
    # an engine of a later protocol that answers 4 to a request for 3 is refused
    with fake(lambda req: dict(v3_answer(req), protocol=4, protocolMin=4, protocolMax=5)) as srv:
        e = raised(lambda: n.SocketSession(srv.endpoint, client="cc"), n.IncompatibleError)
        check("protocol 4" in str(e) and "2..3" in str(e), f"message: {e}")
        wait_for(lambda: srv.closed == 1, "the refused connection to be closed", 5)
    return "3 for 1.1.0, 2 and no v3 key for 1.0.0, 4 refused"


def t_protocol_below_range(c: Ctx):
    """An engine that sends ``protocolMax`` below 2 is refused with both versions named, in the
    hello answer (the connection is closed) and in the endpoint file."""
    n = c.new
    answers = [{"protocol": 1, "protocolMin": 1, "protocolMax": 1},
               {"protocol": 2, "protocolMin": 1, "protocolMax": 1},   # it contradicts itself
               {"protocol": 3, "protocolMax": 1}]
    for extra in answers:
        with fake(lambda req, extra=extra: dict(v2_answer(req), hydraVersion="9.9-hydra.1",
                                                **extra)) as srv:
            e = raised(lambda: n.SocketSession(srv.endpoint, client="cc"), n.IncompatibleError)
            msg = str(e)
            check("9.9-hydra.1" in msg and "ghidra_session.py " + n.CLIENT_VERSION in msg,
                  f"the versions are not named: {msg}")
            check("speaks protocol" in msg and "1" in msg and "2..3" in msg,
                  f"the protocol ranges are not named: {msg}")
            wait_for(lambda: srv.closed == 1, f"the refused connection {extra} to be closed", 5)
    ep = {"protocol": 2, "protocolMin": 1, "protocolMax": 1, "install": str(HERE)}
    d = n.Daemon.__new__(n.Daemon)
    d.instance = "cc"
    e = raised(lambda: n.Daemon._check_install(d, ep, type("_I", (), {"dir": HERE})()),
               n.LaunchError)
    check("protocol 1" in str(e) and "2..3" in str(e) and n.CLIENT_VERSION in str(e),
          f"endpoint message: {e}")
    return str(e)


def t_check_compatible(c: Ctx):
    """``check_compatible`` as a table: the range, the exact-protocol form the E0 shim relies on,
    the advertised range, and ``minClient`` still enforced."""
    n = c.new
    inc = n.IncompatibleError
    ok = [{"protocol": 2}, {"protocol": 3}, {"protocol": 2, "minClient": "1.0.0"},
          {"protocol": 3, "minClient": n.CLIENT_VERSION},
          {"protocol": 3, "protocolMin": 2, "protocolMax": 3},
          {"protocol": 2, "protocolMin": 2, "protocolMax": 3},   # a newer engine, asked for 2
          {"protocol": 3, "protocolMin": 2, "protocolMax": 9}]
    for info in ok:
        n.check_compatible(info)
    bad = [{}, {"protocol": 1}, {"protocol": 4}, {"protocol": None}, {"protocol": True},
           {"protocol": "3"}, {"protocol": 2.0}, {"protocol": 2, "protocolMax": 1},
           {"protocol": 3, "protocolMin": 4, "protocolMax": 5},
           {"protocol": 3, "protocolMin": 2, "protocolMax": 2},   # answered above its own range
           {"protocol": 2, "protocolMax": "x"}, {"protocol": 2, "protocolMin": 3, "protocolMax": 3},
           {"protocol": 3, "minClient": "99.0.0"}, {"protocol": 2, "minClient": "x"}]
    for info in bad:
        raised(lambda info=info: n.check_compatible(info), inc)
    # the exact-protocol form: ``protocol=`` alone is that one protocol
    n.check_compatible({"protocol": 2}, protocol=2)
    raised(lambda: n.check_compatible({"protocol": 3}, protocol=2), inc)
    raised(lambda: n.check_compatible({"protocol": 2}, protocol=3), inc)
    n.check_compatible({"protocol": 2}, protocol=3, protocol_min=2)
    # the answer of a version the client does not know names both sides
    e = raised(lambda: n.check_compatible({"protocol": 4, "hydraVersion": "9.9-hydra.1",
                                           "ghidraVersion": "9.9"}), inc)
    check("9.9-hydra.1" in str(e) and "speaks protocol 4" in str(e) and "speaks 2..3" in str(e) and
          n.CLIENT_VERSION in str(e), f"message: {e}")
    # a protocol-2 engine against the stock client is what it always was
    c.stock.check_compatible({"protocol": 2, "minClient": "1.0.0"})
    raised(lambda: c.stock.check_compatible({"protocol": 3}), c.stock.IncompatibleError)
    return f"{len(ok)} accepted, {len(bad)} refused"


def t_endpoint_overlap(c: Ctx):
    """The endpoint check accepts any overlap of 2..3 with ``protocolMin``..``protocolMax``
    (absent: the single ``protocol``) and still checks the install."""
    n = c.new
    d = n.Daemon.__new__(n.Daemon)
    d.instance = "cc"
    inst = type("_I", (), {"dir": HERE})()
    ok = [{"protocol": 2}, {"protocol": 3}, {"protocol": 2, "protocolMin": 2, "protocolMax": 3},
          {"protocol": 3, "protocolMin": 3, "protocolMax": 4},
          {"protocol": 1, "protocolMin": 1, "protocolMax": 2},
          {"protocol": 2, "protocolMin": 2, "protocolMax": 9, "install": str(HERE)}]
    for ep in ok:
        n.Daemon._check_install(d, ep, inst)
    bad = [{}, {"protocol": 1}, {"protocol": 4}, {"protocol": "2"}, {"protocol": True},
           {"protocol": 2, "protocolMax": 1}, {"protocol": 4, "protocolMin": 4, "protocolMax": 5},
           {"protocol": 2, "protocolMin": 2, "protocolMax": 3, "install": str(HERE) + "-other"}]
    for ep in bad:
        raised(lambda ep=ep: n.Daemon._check_install(d, ep, inst), n.LaunchError)
    return f"{len(ok)} endpoints accepted, {len(bad)} refused"


def t_engine_config(c: Ctx):
    """The ``engine`` object of ``config.json`` becomes repeatable ``-set key=value`` flags;
    nothing else is added when it is empty, and an unusable value fails at load time."""
    n = c.new
    check(n.engine_flags({}) == [] and n.engine_flags(None) == [], "an empty engine adds flags")
    flags = n.engine_flags({"maintSlots": 2, "requireExpect": True, "ratio": 0.5,
                            "name": "a b=c", "off": False})
    check(flags == ["-set", "maintSlots=2", "-set", "requireExpect=true", "-set", "ratio=0.5",
                    "-set", "name=a b=c", "-set", "off=false"], f"{flags}")
    for bad in ({"a": None}, {"a": [1]}, {"a": {"b": 1}}, {"1a": 1}, {"a b": 1}, {"a=b": 1},
                {"a": "x\ny"}, {"a": float("nan")}, {"a": float("inf")}, [1], "x"):
        raised(lambda bad=bad: n.engine_flags(bad), n.LaunchError)
    with tempfile.TemporaryDirectory(dir=c.work) as tmp:
        st = pathlib.Path(tmp)
        check(n.load_config(st)["engine"] == {}, "the default engine is not empty")
        (st / "config.json").write_text(json.dumps({"engine": {"maintSlots": 2, "keep": 1}}))
        cfg = n.load_config(st)
        check(cfg["engine"] == {"maintSlots": 2, "keep": 1}, f"{cfg['engine']}")
        cfg = n.load_config(st, {"engine": {"maintSlots": 4, "extra": "x"}})
        check(cfg["engine"] == {"maintSlots": 4, "keep": 1, "extra": "x"},
              f"the caller's settings must win key by key: {cfg['engine']}")
        check(n.load_config(st, {"engine": None})["engine"] == {"maintSlots": 2, "keep": 1},
              "an engine=None override changed the file's settings")
        check(n.DEFAULTS["engine"] == {}, "load_config changed the shared default")
        for text in ('{"engine": [1]}', '{"engine": {"a": null}}', '{"engine": {"bad key": 1}}'):
            (st / "config.json").write_text(text)
            e = raised(lambda: n.load_config(st), n.LaunchError)
            check("config.json" in str(e), f"the error does not name the file: {e}")
        (st / "config.json").write_text('{"engines": {}}')
        e = raised(lambda: n.load_config(st), n.LaunchError)
        check("unknown keys" in str(e), f"unknown keys are still refused: {e}")
    return "flags, merge, validation"


def t_loader(c: Ctx):
    """The ``cc_*.py`` loader: an empty directory is fine, a good file registers its tests, a file
    that does not import, a name already taken and a bad ``OFFLINE`` are each reported without
    stopping the others."""
    saved = (dict(REGISTRY), set(ONLINE_OK), dict(LOADED))
    try:
        with tempfile.TemporaryDirectory(dir=c.work) as tmp:
            d = pathlib.Path(tmp)
            check(load_cc(d) == [], "an empty directory is not fine")
            (d / "cc_a1.py").write_text(
                "import client_compat_tests as cc\n"
                "TESTS = {'loader_probe_a': lambda c: 'a', 'loader_probe_b': lambda c: 'b'}\n"
                "OFFLINE = {'loader_probe_a'}\n")
            (d / "cc_b1.py").write_text("raise RuntimeError('does not import')\n")
            (d / "cc_c1.py").write_text("TESTS = {'stock_vendored': lambda c: 'again'}\n")
            (d / "cc_d1.py").write_text("TESTS = {'loader_probe_d': lambda c: 'd'}\n"
                                        "OFFLINE = {'nope'}\n")
            (d / "cc_e1.py").write_text("TESTS = [1]\n")
            (d / "notcc.py").write_text("raise RuntimeError('never loaded')\n")
            errs = dict(load_cc(d))
            check(sorted(errs) == ["cc_b1.py", "cc_c1.py", "cc_d1.py", "cc_e1.py"], f"{errs}")
            check("does not import" in errs["cc_b1.py"] and "already taken" in errs["cc_c1.py"] and
                  "OFFLINE" in errs["cc_d1.py"] and "TESTS" in errs["cc_e1.py"], f"{errs}")
            check(LOADED == {**saved[2], "cc_a1.py": ["loader_probe_a", "loader_probe_b"]},
                  f"{LOADED}")
            check(REGISTRY["loader_probe_a"](c) == "a" and "loader_probe_a" in ONLINE_OK and
                  "loader_probe_b" not in ONLINE_OK, "registration")
            check(REGISTRY["stock_vendored"] is t_stock_vendored, "a built-in was replaced")
    finally:
        REGISTRY.clear()
        REGISTRY.update(saved[0])
        ONLINE_OK.clear()
        ONLINE_OK.update(saved[1])
        LOADED.clear()
        LOADED.update(saved[2])
        for m in ("cc_a1", "cc_b1", "cc_c1", "cc_d1", "cc_e1"):
            sys.modules.pop(m, None)
    return "empty, good, broken, taken, bad OFFLINE, bad TESTS"


OFFLINE = {"stock_vendored", "new_client_identity", "fake_v2_server", "fake_v3_server",
           "protocol_below_range", "check_compatible", "endpoint_overlap", "engine_config",
           "loader"}


# ---- tests against the real engine ----------------------------------------------------------

def _engine_max(ep):
    """The highest protocol the running engine serves, from its endpoint file."""
    m = ep.get("protocolMax", ep.get("protocol"))
    check(_is_int(m), f"the endpoint names no protocol: { {k: v for k, v in ep.items() if k != 'token'} }")
    return m


def _mixed(c: Ctx, first):
    """One daemon started by the ``first`` library ("new" or "stock"), joined by both: each
    connection runs at the protocol its library and the engine agree on, both are served, and
    the engine records each client's own version."""
    c.need_engine()
    n, st = c.new, c.stock
    d = c.new_daemon("mixed-" + first) if first == "new" else c.daemon("mixed-" + first)
    other = c.daemon("mixed-" + first) if first == "new" else c.new_daemon("mixed-" + first)
    with d.connect("cc-" + first, "tests") as a, other.connect("cc-other", "tests") as b:
        s_new, s_stock = (a, b) if first == "new" else (b, a)
        ep = d.read_endpoint()
        top = _engine_max(ep)
        want = min(n.PROTOCOL, top)
        check(s_new.protocol == want == s_new.hello["protocol"],
              f"1.1.0: protocol {s_new.protocol}, hello {s_new.hello.get('protocol')}, "
              f"engine serves up to {top}, expected {want}")
        # V6: whatever the engine serves, a protocol-2 client is at 2 and the endpoint file says 2
        check(s_stock.hello["protocol"] == 2, f"1.0.0 hello answered {s_stock.hello['protocol']}")
        check(ep["protocol"] == 2, f"the endpoint file says protocol {ep['protocol']}")
        check(s_stock.hello["minClient"] == "1.0.0", f"minClient {s_stock.hello['minClient']}")
        for s in (s_new, s_stock):
            s.call("ping")
            check(isinstance(s.call("projects"), dict), "projects")
        st_ = s_stock.call("status")
        versions = {x["name"]: x["clientVersion"] for x in st_["clients"]}
        check(versions.get("cc-" + first) == (n if first == "new" else st).CLIENT_VERSION and
              versions.get("cc-other") == (st if first == "new" else n).CLIENT_VERSION,
              f"client versions in status: {versions}")
        top_note = f"engine {s_new.hello['hydraVersion']} serves up to {top}"
    d.stop()
    return f"{top_note}: 1.1.0 at {want}, 1.0.0 at 2"


def t_real_engine_new_starts(c: Ctx):
    """The 1.1.0 client starts the daemon of the real engine; the stock 1.0.0 client joins it."""
    return _mixed(c, "new")


def t_real_engine_stock_starts(c: Ctx):
    """The stock 1.0.0 client starts the daemon of the real engine; the 1.1.0 client joins it."""
    return _mixed(c, "stock")


def t_engine_setting_command(c: Ctx):
    """The real JVM command line of the 1.1.0 launcher carries ``-set key=value`` for the
    ``engine`` object, after the launcher's own flags, and carries none without it. (Only the
    command is built here: a hydra.2 or hydra.3 JVM refuses ``-set`` with ``unknown option``.)"""
    c.need_engine()
    n = c.new
    st = c.state / "cmd"
    st.mkdir(parents=True, exist_ok=True)
    inst = n.Install.locate(c.a.ghidra)
    plain, _ = n.Launch(inst, n.load_config(st), st).command(["-daemon"])
    check("-set" not in plain, "-set without an engine object")
    argv, _ = n.Launch(inst, n.load_config(st, {"engine": {"maintSlots": 2, "requireExpect": True}}),
                       st).command(["-daemon"])
    tail = argv[argv.index("-forkCopyLimitMb"):]
    check(tail[2:] == ["-set", "maintSlots=2", "-set", "requireExpect=true"], f"{tail}")
    check(argv.index("-daemon") < argv.index("-set"), "-set before the daemon's own arguments")
    return " ".join(tail[2:])


# ---- registry, loader, runner ---------------------------------------------------------------

TESTS = {n: globals()["t_" + n] for n in (
    "stock_vendored", "new_client_identity", "fake_v2_server", "fake_v3_server",
    "protocol_below_range", "check_compatible", "endpoint_overlap", "engine_config", "loader",
    "real_engine_new_starts", "real_engine_stock_starts", "engine_setting_command")}
REGISTRY = dict(TESTS)   # test name -> fn(ctx): the tests above and those of the cc_*.py files
ONLINE_OK = set(OFFLINE)  # names that may run with --offline
LOADED = {}               # cc_*.py file name -> its test names, in order


def load_cc(tests_dir):
    """Imports every ``cc_*.py`` of ``tests_dir`` (sorted) and registers its ``TESTS`` (and
    ``OFFLINE``). Returns ``[(file name, what went wrong)]`` for the files that did not load; the
    other files still load. An empty set is fine."""
    errors = []
    for f in sorted(pathlib.Path(tests_dir).glob("cc_*.py")):
        try:
            mod = _load(f.stem, f)
            tests = getattr(mod, "TESTS", None)
            if not isinstance(tests, dict) or not all(callable(v) for v in tests.values()):
                raise TypeError("TESTS must be a dict {name: fn}")
            off = getattr(mod, "OFFLINE", set())
            if not isinstance(off, (set, frozenset, list, tuple)) or set(off) - set(tests):
                raise TypeError("OFFLINE must be a set of names in TESTS")
            for n, fn in tests.items():
                if n in REGISTRY and REGISTRY[n] is not fn:
                    raise ValueError(f"test name {n!r} is already taken")
            for n, fn in tests.items():
                REGISTRY[n] = fn
            ONLINE_OK.update(off)
            LOADED[f.name] = list(tests)
        except Exception as e:  # noqa: BLE001
            errors.append((f.name, f"{type(e).__name__}: {e}"))
    return errors


def run_test(c, n, secs):
    """Runs one test; returns (status, note, seconds): status is "pass" or "fail"."""
    t = time.perf_counter()
    wd = dt.watchdog(c, n, secs) if secs else None
    try:
        status, note = "pass", REGISTRY[n](c)
    except Exception as e:  # noqa: BLE001
        tb = e.__traceback__
        while tb and tb.tb_next:
            tb = tb.tb_next
        det = getattr(e, "details", None)
        status = "fail"
        note = (f"{type(e).__name__}: {e}{' ' + json.dumps(det) if det else ''} at line "
                f"{tb.tb_lineno if tb else '?'}")
    finally:
        if wd:
            wd.cancel()
    if status != "pass":
        c.cleanup()  # nothing a failed test started may outlive it
    return status, note, time.perf_counter() - t


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", help="the engine under test: an install directory "
                    "(required except with --offline or --list)")
    ap.add_argument("--work", help="an empty working directory (default with --offline: a "
                    "temporary one)")
    ap.add_argument("--offline", action="store_true",
                    help="run only the tests that need no engine (no JVM is started)")
    ap.add_argument("--client", help="the client library under test (default: "
                    "../support/ghidra_session.py of this tree)")
    ap.add_argument("--exe", help="a PE file, for cc_*.py tests that import one")
    ap.add_argument("--dll", help="a second PE file")
    ap.add_argument("--project", help="an analysed project to open read-only (never written)")
    ap.add_argument("--legacy-project", dest="legacy_project",
                    help="a project saved by an older Ghidra, for tests of the upgrade gate")
    ap.add_argument("--legacy-program", dest="legacy_program")
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemons (default: <work>/tmp; "
                    "'default': leave it to the JVM)")
    ap.add_argument("--only", help="comma-separated test names (built in or from cc_*.py)")
    ap.add_argument("--list", action="store_true", help="list the tests and exit")
    ap.add_argument("--tests-dir", dest="tests_dir", default=str(HERE),
                    help="where the cc_*.py files are (default: next to this script)")
    ap.add_argument("--test-timeout", dest="test_timeout", type=int, default=900,
                    help="seconds one test may take before the run is ended with its daemons "
                    "killed (default 900; 0: none)")
    ap.add_argument("--report", help="also write the results here, as JSON")
    return ap


def main(argv=None, only_files=None):
    """Runs the tests. ``only_files`` (the ``cc_*.py`` file names of ``run_file``) restricts the
    default selection to those files' tests."""
    ap = build_parser()
    a = ap.parse_args(argv)
    sys.modules.setdefault("client_compat_tests", sys.modules[__name__])  # cc_*.py import this
    load_errors = load_cc(a.tests_dir)
    default = list(REGISTRY)
    if only_files is not None:
        default = [n for f in only_files for n in LOADED.get(f, [])]
    only = [x for x in (a.only or "").split(",") if x]
    for n in only:
        if n not in REGISTRY:
            ap.error(f"unknown test {n}; known: {', '.join(REGISTRY)}")
    names = only or default
    if a.offline:
        if only and set(only) - ONLINE_OK:
            ap.error(f"--offline cannot run: {', '.join(sorted(set(only) - ONLINE_OK))}")
        names = [n for n in names if n in ONLINE_OK]
    if a.list:
        for n in REGISTRY:
            print(n + ("" if n in ONLINE_OK else "  [needs --ghidra]"))
        for f, why in load_errors:
            print(f"FAIL load {f}: {why}")
        return 1 if load_errors else 0
    if not a.offline and not (a.ghidra and a.work):
        ap.error("--ghidra and --work are required (except with --offline or --list)")
    tmp = None
    if a.offline:
        if not a.work:
            tmp = tempfile.TemporaryDirectory(prefix="cc-offline-")
            a.work = tmp.name
        a.ghidra = a.ghidra or str(HERE)  # only used to name a support dir no offline test reads
    stock, new = stock_client(), new_client(a.client)
    c = Ctx(a, stock, new)
    results = []
    bad = len(load_errors)
    for f, why in load_errors:
        print(f"FAIL load {f}: {why}", flush=True)
        results.append({"test": f, "status": "load_error", "note": why})
    try:
        for n in names:
            status, note, secs = run_test(c, n, a.test_timeout)
            bad += status != "pass"
            print(f"{'ok  ' if status == 'pass' else 'FAIL'} {n:28s} {secs:7.1f} s  {note}",
                  flush=True)
            results.append({"test": n, "status": status, "seconds": round(secs, 1),
                            "note": note})
    finally:
        c.cleanup()
        if tmp:
            with contextlib.suppress(OSError):
                tmp.cleanup()
    if a.report:
        pathlib.Path(a.report).write_text(
            json.dumps({"client": new.CLIENT_VERSION, "results": results}, indent=1),
            encoding="utf-8")
    n_ok = sum(r["status"] == "pass" for r in results)
    miss = f"; {len(load_errors)} cc file(s) did not load" if load_errors else ""
    print(f"{n_ok}/{len(names)} passed{miss}")
    return 1 if bad else 0


def run_file(file, argv=None):
    """The ``__main__`` block of a ``cc_<package>.py``: runs that file's tests alone with the same
    options as this script (``python cc_e1.py --ghidra ... --work ...``)."""
    sys.exit(main(argv, only_files=[pathlib.Path(file).name]))


if __name__ == "__main__":
    sys.exit(main())
