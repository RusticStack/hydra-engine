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
"""Tests of the integration contract: what a client may rely on. Standard library only; any OS.

    python contract_tests.py --ghidra <install> --work <empty dir> [--only a,b] [--lines N]
                             [--tmpdir default]

Each test starts its own daemon instance in <work>/state and stops it, so the user's daemon is
never touched. No binary is needed.

Tests:
- hello: ``hello`` and the endpoint file carry protocol, minClient, hydraVersion, ghidraVersion
  and a stable installId; ``status`` lists the client with its harness and client version.
- compat: the client refuses a session whose protocol differs or whose ``minClient`` is newer than
  the client (a daemon started with ``-Dghidra.session.minClient=99.0.0`` is the test hook), with
  a clear ``IncompatibleError``; ``status`` and ``stop`` still work on such a daemon.
- protocol (package E1, PROTOCOL-3.md 3.1, 3.2): the protocol a ``hello`` asks for is answered as the
  spec says (absent, 1, a string, a float, a boolean, ``null``: 2; 3: 3; 9: 3); a protocol-2 hello
  has exactly today's key order and no v3 key, a protocol-3 hello has the identity block between
  ``memory`` and ``projects``; the first ``hello`` fixes the protocol of the connection (a second
  ``hello`` asking for the other protocol is answered with the connection's own, a ``status``
  pipelined behind a protocol-3 ``hello`` is a protocol-3 ``status``); the endpoint file says
  ``protocol:2`` with ``protocolMin:2`` and ``protocolMax:3``; ``-set`` reaches the policy block; the
  decompiler hash arrives in the background and is right.
- registries (package E1): ``-selfTest``, the engine's own seam checks, run in a real JVM: an
  unknown capability, limit or policy name throws; ``laneOf(cmd, req, v3)`` and ``describe(false)``
  are today's values for every command; ``-set key=value`` reaches ``Settings`` (and a bad key or a
  bad ``requireExpect`` is a usage error, exit 2).
- export: a ``script`` writes a large JSONL file (default 600,000 lines, about 55 MB) outside the
  project while sending throttled progress; ``maxChars`` does not cap the file; the running job
  and its declared ``artifact`` are visible in ``status``.
- export_cancel: ``cancel`` leaves a partial, valid ``<path>.part`` and no final file.
- export_shutdown: stopping the daemon while the export runs leaves a partial, valid file.
"""
import argparse
import contextlib
import hashlib
import json
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)


class Ctx:
    def __init__(self, a, gs):
        self.a = a
        self.gs = gs
        self.work = pathlib.Path(a.work).absolute()
        self.state = self.work / "state"
        self.state.mkdir(parents=True, exist_ok=True)
        self.out = self.work / "out"
        self.out.mkdir(parents=True, exist_ok=True)
        scripts = pathlib.Path(__file__).resolve().parent / "scripts"
        self.script = str(scripts / "ExportJsonl.java")
        cfg = {"tmpdir": a.tmpdir or str(self.work / "tmp"), "scriptPath": [str(scripts)]}
        if a.tmpdir == "default":
            del cfg["tmpdir"]  # leave java.io.tmpdir to the JVM
        (self.state / "config.json").write_text(json.dumps(cfg))
        self.daemons = []

    def daemon(self, instance, **cfg):
        d = self.gs.Daemon(self.a.ghidra, str(self.state), instance, **cfg)
        self.daemons.append(d)
        return d

    def cleanup(self):
        for d in self.daemons:
            try:
                if d.jvm_alive():
                    d.kill()
            except Exception:  # noqa: BLE001
                pass


def read_jsonl(path):
    """(lines, torn): counts the lines of a JSONL file, checking that each parses and that ``i``
    counts up; a last line without its newline (a torn write) is reported, not parsed."""
    n = 0
    torn = False
    with open(path, "rb") as f:
        for raw in f:
            if not raw.endswith(b"\n"):
                torn = True
                break
            o = json.loads(raw)
            check(o["i"] == n, f"{path}: line {n} has i={o['i']}")
            n += 1
    return n, torn


def wait_for(cond, timeout, what):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    raise Fail(f"timed out: {what}")


def my_requests(status, name):
    for cl in status["clients"]:
        if cl["name"] == name:
            return cl["requests"]
    return []


# ---- tests ----------------------------------------------------------------------------------

def t_hello(c: Ctx):
    gs = c.gs
    d = c.daemon("hello")
    with d.connect("contract", "tests") as s:
        h = s.hello
        check(h["protocol"] == gs.PROTOCOL, f"protocol {h['protocol']}")
        check(isinstance(h["minClient"], str) and gs.parse_version(h["minClient"]) <=
              gs.parse_version(gs.CLIENT_VERSION), f"minClient {h['minClient']}")
        check(h["ghidraVersion"] == h["ghidra"] and h["ghidraVersion"], f"ghidraVersion {h}")
        check(h["hydraVersion"].startswith(h["ghidraVersion"] + "-hydra."),
              f"hydraVersion {h['hydraVersion']}")
        check(len(h["installId"]) == 16 and int(h["installId"], 16) >= 0, f"installId {h}")
        check(h["startedAt"] > 0 and h["pid"] > 0, "startedAt/pid")
        ep = {k: v for k, v in s.endpoint.items() if k != "token"}
        for k in ("minClient", "hydraVersion", "ghidraVersion", "installId"):
            check(ep.get(k) == h[k], f"endpoint file {k}: {ep.get(k)} != {h[k]}")
        # the endpoint file says the lowest protocol served; the hello answers the one asked for
        check(ep.get("protocol") == 2 and ep.get("protocolMin") == 2 and ep.get("protocolMax") == 3,
              f"endpoint file protocol range: {ep}")
        check(list(ep)[:3] == ["protocol", "protocolMin", "protocolMax"],
              f"endpoint file key order: {list(ep)}")
        with d.connect("second", "other-harness") as s2:
            check(s2.hello["installId"] == h["installId"], "installId differs between clients")
            st = s.call("status")
            by = {x["name"]: x for x in st["clients"]}
            check(by["second"]["harness"] == "other-harness", f"harness: {by['second']}")
            check(by["second"]["clientVersion"] == gs.CLIENT_VERSION, f"clientVersion: {by}")
            check(by["second"]["requests"] == [], f"requests: {by['second']}")
            check(st["installId"] == h["installId"] and st["hydraVersion"] == h["hydraVersion"],
                  "status lacks the identity")
        install_id = h["installId"]
    d.stop()
    with d.connect("again", "tests") as s:
        check(s.hello["installId"] == install_id, "installId changed over a restart")
    d.stop()
    # the CLI prints the client's own version without a daemon
    out = subprocess.run([sys.executable, gs.__file__, "version"], capture_output=True, text=True,
                         check=True).stdout
    check(json.loads(out) == {"client": gs.CLIENT_VERSION, "protocol": gs.PROTOCOL,
                              "release": gs.HYDRA_RELEASE}, out)
    return f"{h['hydraVersion']} installId {install_id} minClient {h['minClient']}"


V2_HELLO_KEYS = ["protocol", "minClient", "hydraVersion", "ghidraVersion", "installId", "startedAt",
                 "ghidra", "install", "java", "pid", "uptimeMs", "listen", "launch", "keepWarmS",
                 "memory", "projects", "client"]
V3_NEW_KEYS = ["protocolMin", "protocolMax", "capabilities", "limits", "policy", "paths",
               "platform", "analysisIdentity"]
V3_HELLO_KEYS = (V2_HELLO_KEYS[:V2_HELLO_KEYS.index("projects")] + V3_NEW_KEYS +
                 V2_HELLO_KEYS[V2_HELLO_KEYS.index("projects"):])
#: what package E1 itself advertises (3.1): the other packages add theirs, so these are compared as
#: required subsets (this file does not know the later packages)
E1_CAPABILITIES = ["errorNext", "expectAll", "idempotency", "identity"]


class Raw:
    """A raw JSON-lines client on the daemon's socket: no library, so the request goes out exactly
    as written (a protocol of any JSON type, two requests in one write)."""

    def __init__(self, ep):
        self.ep = ep
        self.sock = socket.create_connection((ep["host"], ep["port"]), timeout=120)
        self.f = self.sock.makefile("rwb")
        self.n = 0

    def line(self, cmd, **fields):
        self.n += 1
        fields = {"id": self.n, "cmd": cmd, **fields}
        return (json.dumps(fields) + "\n").encode()

    def send(self, cmd, **fields):
        self.f.write(self.line(cmd, **fields))
        self.f.flush()
        return self.n

    def read(self):
        raw = self.f.readline()
        if not raw:
            raise Fail("the daemon closed the connection")
        return json.loads(raw)

    def call(self, cmd, **fields):
        rid = self.send(cmd, **fields)
        while True:
            r = self.read()
            if r.get("id") == rid:
                return r

    def hello(self, protocol="<absent>", **extra):
        f = dict(extra)
        if protocol != "<absent>":
            f["protocol"] = protocol
        return self.call("hello", token=self.ep["token"], client="raw", harness="contract", **f)

    def close(self):
        with contextlib.suppress(OSError):
            self.f.close()
            self.sock.close()


def fake_server(answer):
    """A loopback server that answers a hello with ``answer``; returns (endpoint, server)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            with conn, conn.makefile("rw", encoding="utf-8", newline="\n") as f:
                req = json.loads(f.readline())
                f.write(json.dumps({"id": req["id"], "ok": True, "result": answer, "ms": 0}) +
                        "\n")
                f.flush()
                f.readline()  # until the client closes
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return {"host": "127.0.0.1", "port": port, "token": "x"}, srv


def t_compat(c: Ctx):
    gs = c.gs
    # check_compatible, as a table
    gs.check_compatible({"protocol": gs.PROTOCOL, "minClient": gs.CLIENT_VERSION})
    gs.check_compatible({"protocol": gs.PROTOCOL})  # a session from before the contract
    cases = [({"protocol": gs.PROTOCOL + 1, "minClient": "1.0.0", "hydraVersion": "9.9-hydra.1"},
              "speaks protocol"),
             ({"protocol": gs.PROTOCOL, "minClient": "99.0.0", "hydraVersion": "9.9-hydra.1"},
              "requires a client of at least 99.0.0"),
             ({"protocol": gs.PROTOCOL, "minClient": "abc"}, "unreadable minClient")]
    for info, needle in cases:
        try:
            gs.check_compatible(info)
        except gs.IncompatibleError as e:
            check(needle in str(e), f"message {e} lacks {needle!r}")
        else:
            raise Fail(f"{info} was accepted")
    # end to end against a fake server: the connection is closed and the error is clear
    ep, srv = fake_server({"protocol": gs.PROTOCOL + 1, "minClient": "1.0.0",
                           "hydraVersion": "9.9-hydra.1", "ghidraVersion": "9.9"})
    try:
        gs.SocketSession(ep, client="t")
    except gs.IncompatibleError as e:
        check("speaks protocol" in str(e) and "9.9-hydra.1" in str(e), f"message: {e}")
    else:
        raise Fail("a session of another protocol was accepted")
    finally:
        srv.close()
    # the real daemon, started with a minClient above this client (the test hook)
    d = c.daemon("minclient", vmargs=["-Dghidra.session.minClient=99.0.0"])
    try:
        d.connect("compat", "tests")
    except gs.IncompatibleError as e:
        check("99.0.0" in str(e) and gs.CLIENT_VERSION in str(e), f"message: {e}")
        msg = str(e)
    else:
        raise Fail("a client older than minClient was accepted")
    st = d.status()  # an incompatible client can still look
    check(st and st["minClient"] == "99.0.0", f"status of the strict daemon: {st}")
    check(d.stop(), "the strict daemon could not be stopped")
    return msg


def t_protocol(c: Ctx):
    gs = c.gs
    d = c.daemon("protocol")
    with d.connect("contract", "tests") as keep:
        ep = d.read_endpoint()
        check(ep["protocol"] == 2 and ep["protocolMin"] == 2 and ep["protocolMax"] == 3,
              f"endpoint: {ep}")
        # the protocol a hello asks for, answered as 3.1 says (JSON integers only; anything else
        # is "absent": the request is not refused)
        want = [("<absent>", 2), (2, 2), (3, 3), (9, 3), (1, 2), (0, 2), (-5, 2), ("3", 2),
                (3.0, 2), (True, 2), (None, 2), ([3], 2), (10 ** 20, 3), (-10 ** 20, 2),
                # negative values whose low 32 bits are 3 or 4 (a wrapped intValue() would answer them)
                (-4294967293, 2), (-4294967292, 2), (-9223372036854775805, 2)]
        for ask, got in want:
            r = Raw(ep)
            try:
                h = r.hello(ask)
            finally:
                r.close()
            check(h["ok"], f"hello protocol={ask!r}: {h}")
            check(h["result"]["protocol"] == got, f"hello protocol={ask!r} answered "
                  f"{h['result']['protocol']}, want {got}")
            keys = list(h["result"])
            check(keys == (V3_HELLO_KEYS if got == 3 else V2_HELLO_KEYS),
                  f"hello protocol={ask!r}: keys {keys}")
        # a protocol-2 hello is the committed shape, and so is a protocol-2 status header
        r = Raw(ep)
        h2 = r.hello()["result"]
        check(list(h2) == V2_HELLO_KEYS, f"protocol-2 hello keys: {list(h2)}")
        st = r.call("status")["result"]
        check(all(k not in st for k in V3_NEW_KEYS), f"a v2 status carries a v3 key: {list(st)}")
        # the first hello fixes the protocol: a second hello asking 3 is answered 2, and adds no key
        again = r.hello(3)["result"]
        check(again["protocol"] == 2 and list(again) == V2_HELLO_KEYS,
              f"a second hello asking 3 on a protocol-2 connection: {again['protocol']} "
              f"{list(again)}")
        again = r.hello("3")["result"]
        check(again["protocol"] == 2 and list(again) == V2_HELLO_KEYS, "a string protocol")
        st = r.call("status")["result"]
        check(all(k not in st for k in V3_NEW_KEYS), "status after a second hello asking 3")
        r.close()
        # ... and the other way round
        r = Raw(ep)
        h3 = r.hello(3)["result"]
        again = r.hello(2)["result"]
        check(again["protocol"] == 3 and list(again) == V3_HELLO_KEYS,
              f"a second hello asking 2 on a protocol-3 connection: {again['protocol']}")
        st3 = r.call("status")["result"]
        check(all(k in st3 for k in V3_NEW_KEYS) and st3["protocol"] == 3,
              f"a v3 status lacks the identity block: {list(st3)}")
        check(list(st3)[list(st3).index("memory") + 1:][:len(V3_NEW_KEYS)] == V3_NEW_KEYS,
              f"v3 keys sit between memory and projects: {list(st3)}")
        r.close()
        # the connection's protocol is fixed before the next line is read: a status written in the
        # same breath as the hello is a protocol-3 status
        r = Raw(ep)
        r.f.write(r.line("hello", token=ep["token"], client="raw", harness="contract", protocol=3) +
                  r.line("status"))
        r.f.flush()
        got = {}
        while len(got) < 2:
            m = r.read()
            got[m["id"]] = m
        check(got[1]["result"]["protocol"] == 3 and "capabilities" in got[2]["result"],
              f"a status pipelined behind a protocol-3 hello: {list(got[2]['result'])}")
        r.close()
        # the identity block of the v3 hello
        r = Raw(ep)
        h = r.hello(3)["result"]
        caps = h["capabilities"]
        check(all(caps.get(k) == 1 for k in E1_CAPABILITIES) and all(
            isinstance(v, int) and v >= 1 for v in caps.values()), f"capabilities: {caps}")
        check(list(caps) == [k for k in gs_capability_order() if k in caps],
              f"capabilities are not in declaration order: {list(caps)}")
        lim = h["limits"]
        check(all(isinstance(lim.get(k), int) and lim[k] >= 1
                  for k in ("maxQuick", "maxLong", "maxImports")), f"limits: {lim}")
        check(h["policy"].get("requireExpect") is False, f"policy: {h['policy']}")
        paths = h["paths"]
        check(list(paths) == ["stateDir", "instance", "endpointFile", "logFile", "scriptPath",
                              "tmpDir", "upgradeCacheDir", "install"], f"paths: {list(paths)}")
        check(pathlib.Path(paths["stateDir"]).resolve() == c.state.resolve() and
              paths["instance"] == "protocol" and
              pathlib.Path(paths["endpointFile"]).resolve() == pathlib.Path(d.endpoint_file).resolve(),
              f"paths: {paths}")
        plat = h["platform"]
        check([k for k in plat if k != "testHooks"] == [
            "os", "osVersion", "arch", "cpus", "javaVendor", "javaVersion", "maxHeapMb",
            "fileSystems", "cow"], f"platform: {list(plat)}")  # testHooks (E5): dt_e5/cc_e5 assert it
        check(list(plat["fileSystems"]) == ["stateDir", "tmpDir", "upgradeCacheDir"] and
              list(plat["cow"]) == ["stateDir", "tmpDir"] and
              all(isinstance(v, str) for v in plat["fileSystems"].values()), f"platform: {plat}")
        ai = h["analysisIdentity"]
        check(list(ai) == ["hydraVersion", "ghidraVersion", "buildDate", "dbVersions",
                           "decompiler"], f"analysisIdentity: {list(ai)}")
        check(ai["hydraVersion"] == h["hydraVersion"] and ai["ghidraVersion"] == h["ghidraVersion"]
              and ai["buildDate"], f"analysisIdentity: {ai}")
        dbv = ai["dbVersions"]
        check(list(dbv) == ["program", "dataTypes"] and isinstance(dbv["program"], int) and
              dbv["program"] > 0 and (dbv["dataTypes"] is None or
                                      isinstance(dbv["dataTypes"], int) and dbv["dataTypes"] > 0),
              f"dbVersions: {dbv}")  # E2 fills dataTypes (null only when unreadable)
        # equal to the constant itself, when this test runs from the source tree
        src = pathlib.Path(__file__).resolve().parents[4] / "Ghidra" / "Framework" /             "SoftwareModeling" / "src" / "main" / "java" / "ghidra" / "program" / "database" /             "ProgramDB.java"
        if src.is_file():
            m = re.search(r"static final int DB_VERSION = (\d+);", src.read_text(encoding="utf-8"))
            check(m and int(m.group(1)) == dbv["program"],
                  f"dbVersions.program {dbv['program']} is not ProgramDB.DB_VERSION in {src}")
        dec = ai["decompiler"]
        check(list(dec) == ["path", "sizeBytes", "sha256"] and dec["sizeBytes"] > 0 and
              pathlib.Path(dec["path"]).is_file(), f"decompiler: {dec}")
        # the background hash: null or right, and right within a while
        want_sha = hashlib.sha256(pathlib.Path(dec["path"]).read_bytes()).hexdigest()
        t0 = time.monotonic()
        while dec["sha256"] is None and time.monotonic() - t0 < 60:
            time.sleep(0.2)
            dec = r.hello(3)["result"]["analysisIdentity"]["decompiler"]
        check(dec["sha256"] == want_sha, f"decompiler sha256 {dec['sha256']}, want {want_sha}")
        r.close()
        note = (f"db {dbv['program']}, {plat['os']} {plat['fileSystems']['stateDir']}, "
                f"decompiler sha256 after {time.monotonic() - t0:.1f} s")
        keep.call("ping")
    d.stop()
    # -set reaches the policy: a daemon started with engine.requireExpect
    d2 = c.daemon("protocol-set", engine={"requireExpect": True})
    with d2.connect("contract", "tests"):
        r = Raw(d2.read_endpoint())
        pol = r.hello(3)["result"]["policy"]
        r.close()
        check(pol.get("requireExpect") is True, f"policy after -set requireExpect=true: {pol}")
    d2.stop()
    return note


def gs_capability_order():
    """The declaration order of 3.2 (Advertised.CAPABILITIES)."""
    return ["errorNext", "expectAll", "idempotency", "laneHint", "maintLane", "queueInfo",
            "cancelWait", "forkReport", "format", "backup", "upgradeGate", "scriptIsolation",
            "scriptSha256", "attemptedChanges", "health", "identity", "seal",
            "forkAtomic"]


def self_test(c, *flags, engine=None):
    """Runs the engine's ``-selfTest`` in a real JVM, with the launcher's own command line:
    ``(exit code, stdout lines, stderr)``."""
    gs = c.gs
    st = c.state / "selftest"
    st.mkdir(parents=True, exist_ok=True)
    inst = gs.Install.locate(c.a.ghidra)
    cfg = gs.load_config(st, {"engine": engine} if engine else None)
    argv, _ = gs.Launch(inst, cfg, st).command(["-selfTest", *flags])
    p = subprocess.run(argv, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout.splitlines(), p.stderr


def t_registries(c: Ctx):
    code, lines, err = self_test(c, engine={"maintSlots": 7, "requireExpect": True, "name": "a=b"})
    bad = [ln for ln in lines if ln.startswith("FAIL")]
    check(code == 0 and not bad, f"-selfTest exit {code}: {bad} {err[-1500:]}")
    n_ok = sum(1 for ln in lines if ln.startswith("ok"))
    check(n_ok >= 25, f"only {n_ok} self-test checks ran: {lines}")
    check(any(ln.startswith("ok   registering an unknown capability throws") for ln in lines) and
          any(ln.startswith("ok   registering an unknown limit throws") for ln in lines) and
          any(ln.startswith("ok   registering an unknown policy throws") for ln in lines),
          "the unknown-name checks did not run")
    check(any(ln.startswith("ok   laneOf(cmd, req, v3)") for ln in lines) and
          any(ln.startswith("ok   describe(false)") for ln in lines),
          "the laneOf and describe(false) checks did not run")
    sett = [json.loads(ln[len("SETTINGS "):]) for ln in lines if ln.startswith("SETTINGS ")]
    check(sett == [{"set": {"maintSlots": "7", "requireExpect": "true", "name": "a=b"},
                    "requireExpect": True, "maintSlots": 7}], f"the -set flag did not reach "
          f"Settings: {sett}")
    # a bad key, no =, and a bad requireExpect are usage errors (exit 2), not silent defaults
    for flags, why in ((["-set", "1x=2"], "a key that is not an identifier"),
                       (["-set", "novalue"], "no ="),
                       (["-set", "requireExpect=maybe"], "requireExpect is not true or false")):
        code2, _, err2 = self_test(c, *flags)
        check(code2 == 2 and ("-set" in err2), f"{why}: exit {code2}, stderr {err2[-300:]}")
    return f"{n_ok} checks ok; settings {sett[0]['set']}"


def start_export(c, s, name, lines, throttle=0, **extra):
    path = c.out / name
    for p in (path, path.with_name(name + ".part")):
        p.unlink(missing_ok=True)
    rid = s.send("script", script=c.script, program=None, args=[str(path), lines, throttle],
                 artifact=str(path), parallel=True, **extra)
    return path, rid


def t_export(c: Ctx):
    lines = c.a.lines
    d = c.daemon("export")
    with d.connect("exporter", "tests") as s, d.connect("watcher", "tests") as w:
        t0 = time.perf_counter()
        # a small maxChars: the script's printed result is cut, the file is not
        path, rid = start_export(c, s, "big.jsonl", lines, 4, maxChars=20)
        seen = {}

        def look():
            rq = my_requests(w.call("status"), "exporter")
            if rq:
                seen.update(rq[0])
            return rq

        wait_for(look, 120, "the script in status")
        check(seen["cmd"] == "script" and seen["artifact"] == str(path), f"status: {seen}")
        r = s.wait(rid)
        secs = time.perf_counter() - t0
        check(r["artifact"] == str(path), f"result lacks the artifact: {r}")
        check(r["truncated"] and len(r["output"]) == 20 and r["chars"] > 20,
              f"maxChars did not cut the printed output: {r}")
        size = path.stat().st_size
        n, torn = read_jsonl(path)
        check(n == lines and not torn, f"{n} lines (torn {torn}), wanted {lines}")
        check(size >= 50 << 20 or n >= 500_000, f"only {size} bytes, {n} lines")
        check(not path.with_name("big.jsonl.part").exists(), "the .part file was left behind")
        progress = [e for e in s.events if e.get("event") == "progress" and e.get("id") == rid]
        check(len(progress) >= 2, f"{len(progress)} progress events in {secs:.1f} s")
        pv = [e["progress"] for e in progress]
        check(pv == sorted(pv), f"progress not rising: {pv[:5]}")
        check(len(progress) <= secs + 2, f"{len(progress)} events in {secs:.1f} s: not throttled")
        check(all(e["maximum"] == lines for e in progress), "progress maximum")
        left = my_requests(w.call("status"), "exporter")
        check(not left, f"the finished job is still in status: {left}")
    d.stop()
    return (f"{n} lines, {size / (1 << 20):.0f} MiB in {secs:.1f} s; {len(progress)} progress "
            f"events; printed output cut to 20 chars, file complete")


def t_export_cancel(c: Ctx):
    d = c.daemon("excancel")
    with d.connect("exporter", "tests") as s:
        path, rid = start_export(c, s, "cancel.jsonl", 100_000_000, 5)
        part = path.with_name("cancel.jsonl.part")
        wait_for(lambda: part.exists() and part.stat().st_size > 1 << 20, 120, "partial output")
        s.call("cancel", target=rid)
        try:
            s.wait(rid)
        except c.gs.SessionError as e:
            check(e.code == "cancelled", f"code {e.code}")
        else:
            raise Fail("the cancelled export finished")
        size = part.stat().st_size
        n, torn = read_jsonl(part)
        check(n >= 1000 and not torn, f"partial file: {n} lines, torn {torn}")
        check(not path.exists(), "a cancelled export left the final file")
        check(not my_requests(s.call("status"), "exporter"), "cancelled job still in status")
    d.stop()
    return f"partial file kept: {n} lines, {size >> 10} KiB, no final file"


def t_export_shutdown(c: Ctx):
    d = c.daemon("exstop")
    s = d.connect("exporter", "tests")
    path, rid = start_export(c, s, "stop.jsonl", 100_000_000, 5)
    part = path.with_name("stop.jsonl.part")
    wait_for(lambda: part.exists() and part.stat().st_size > 1 << 20, 120, "partial output")
    check(d.stop(force=True), "the daemon did not stop")
    s.close()
    size = part.stat().st_size
    n, torn = read_jsonl(part)
    check(n >= 1000, f"partial file: {n} lines")
    check(not path.exists(), "a stopped export left the final file")
    return f"partial file kept after shutdown: {n} lines, {size >> 10} KiB, torn last line: {torn}"


TESTS = ["hello", "compat", "protocol", "registries", "export", "export_cancel", "export_shutdown"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--lines", type=int, default=600_000,
                    help="lines the export test writes (about 95 bytes each)")
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemons (default: <work>/tmp; "
                    "'default': leave it to the JVM)")
    ap.add_argument("--only")
    a = ap.parse_args()
    sys.path.insert(0, str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import ghidra_session as gs
    c = Ctx(a, gs)
    names = a.only.split(",") if a.only else TESTS
    failed = 0
    try:
        for n in names:
            t = time.perf_counter()
            try:
                note = globals()["t_" + n](c)
                print(f"ok   {n:16s} {time.perf_counter() - t:7.1f} s  {note}", flush=True)
            except Exception as e:  # noqa: BLE001
                failed += 1
                print(f"FAIL {n:16s} {time.perf_counter() - t:7.1f} s  {type(e).__name__}: {e}",
                      flush=True)
                c.cleanup()
    finally:
        c.cleanup()
    print(f"{len(names) - failed}/{len(names)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
