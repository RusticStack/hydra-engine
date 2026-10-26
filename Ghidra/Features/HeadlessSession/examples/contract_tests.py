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
- export: a ``script`` writes a large JSONL file (default 600,000 lines, about 55 MB) outside the
  project while sending throttled progress; ``maxChars`` does not cap the file; the running job
  and its declared ``artifact`` are visible in ``status``.
- export_cancel: ``cancel`` leaves a partial, valid ``<path>.part`` and no final file.
- export_shutdown: stopping the daemon while the export runs leaves a partial, valid file.
"""
import argparse
import json
import pathlib
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
        for k in ("protocol", "minClient", "hydraVersion", "ghidraVersion", "installId"):
            check(ep.get(k) == h[k], f"endpoint file {k}: {ep.get(k)} != {h[k]}")
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


TESTS = ["hello", "compat", "export", "export_cancel", "export_shutdown"]


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
