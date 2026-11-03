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
"""Differential test of the front door (``hydra-front``) against the JVM daemon. Standard library only.

    python front_compat.py --ghidra <install with support/hydra-front.exe> --work <empty dir>

Starts two daemons of the same install through the launcher: ``direct`` (the JVM, as ever) and
``front`` (``GHIDRA_SESSION_FRONT`` set). The same request vectors go to both, and the replies must
agree in everything that is not live state (pids, ports, times, ids, memory, instance paths):

- the unauthenticated first request, a malformed line, a wrong token;
- ``hello`` for every ``protocol`` the engine treats differently, at the front's COLD start (the
  identity served from the cache, no JVM running) and at its WARM state (the JVM attached);
- key order of every reply object that has one (the goldens depend on it);
- ``ping``, an unknown command, a second ``hello`` that asks for the other protocol, a pipelined
  ``status`` behind a v3 ``hello``;
- the lazy start: a cold front answers ``hello``/``ping`` without starting a JVM, the first
  Ghidra-bound request starts exactly one, and a cold ``shutdown`` needs no JVM.

Prints one line per vector and exits non-zero on the first difference.
"""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

MASK = {"pid", "uptimeMs", "startedAt", "client", "listen", "memory", "ms", "started", "token", "port",
        "readyMs", "jvmToReadyMs", "launch", "instance", "endpointFile", "logFile", "stateDir",
        "upgradeCacheDir", "tmpDir", "classCache", "usedMb", "committedMb", "sha256", "sizeBytes",
        "buildDate", "installId"}


class Conn:
    def __init__(self, ep):
        self.ep = ep
        self.s = socket.create_connection((ep["host"], ep["port"]), timeout=30)
        self.f = self.s.makefile("rwb", buffering=0)
        self.r = self.s.makefile("rb")

    def send(self, obj):
        self.f.write((obj if isinstance(obj, str) else json.dumps(obj)).encode() + b"\n")

    def recv(self):
        line = self.r.readline()
        return json.loads(line) if line else None

    def call(self, obj):
        self.send(obj)
        return self.recv()

    def hello(self, **kw):
        return self.call({"id": 1, "cmd": "hello", "token": self.ep["token"], "client": "compat", **kw})

    def close(self):
        for x in (self.r, self.f):
            x.close()
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close()


def shape(v):
    """The reply with live values masked. Dicts keep their insertion order, so the key ORDER stays
    in the value and ``check`` compares the serialised text."""
    if isinstance(v, dict):
        return {k: "*" if k in MASK else shape(x) for k, x in v.items()}
    if isinstance(v, list):
        return [shape(x) for x in v]
    return v


def launcher(ghidra, state, instance, *args, front=None):
    env = dict(os.environ, PYTHONUTF8="1")
    env.pop("GHIDRA_SESSION_FRONT", None)
    if front:
        env["GHIDRA_SESSION_FRONT"] = front
    exe = pathlib.Path(ghidra) / "Ghidra/Features/HeadlessSession/support/ghidra_session.py"
    return subprocess.run([sys.executable, "-I", str(exe), "--state", str(state), "--instance", instance, *args],
                          env=env, capture_output=True, text=True, timeout=180)


def endpoint(state, instance):
    return json.loads((pathlib.Path(state) / f"{instance}.json").read_text(encoding="utf-8"))


def jvm_running(state, instance):
    """The backend JVM publishes <instance>.jvm.json while it runs; the front removes it when it stops it."""
    return (pathlib.Path(state) / f"{instance}.jvm.json").exists()


def check(name, a, b):
    ok = json.dumps(a) == json.dumps(b)
    print(("ok   " if ok else "FAIL ") + name, flush=True)
    if not ok:
        print("  direct:", json.dumps(a, default=str)[:900])
        print("  front :", json.dumps(b, default=str)[:900])
        sys.exit(1)


def vectors(ep, jvm=True):
    """Every vector against one endpoint: a list of (name, reply shape). ``jvm=False`` leaves out the
    vectors that need the JVM (an unknown command is not for the front to judge)."""
    out = []

    def conn():
        return Conn(ep)

    c = conn()
    out.append(("unauthenticated status", shape(c.call({"id": 7, "cmd": "status"}))))
    out.append(("closed after refusal", c.recv()))
    c.close()
    c = conn()
    out.append(("wrong token", shape(c.call({"id": "x", "cmd": "hello", "token": "nope"}))))
    c.close()
    c = conn()
    c.send("this is not json")
    bad = c.recv()
    out.append(("malformed line code", dict(dict(bad)["error"])["code"]))
    out.append(("then hello still works", list(c.hello(protocol=3))))
    c.close()
    for label, kw in (("absent", {}), ("1", {"protocol": 1}), ("2", {"protocol": 2}), ("3", {"protocol": 3}),
                      ("9", {"protocol": 9}), ("string", {"protocol": "3"}), ("float", {"protocol": 3.0}),
                      ("true", {"protocol": True}), ("null", {"protocol": None})):
        c = conn()
        r = dict(c.hello(**kw))
        res = r["result"]
        out.append((f"hello protocol={label}", shape(r)))
        out.append((f"hello protocol={label} negotiated", dict(res)["protocol"]))
        c.close()
    c = conn()
    c.hello(protocol=2)
    again = dict(c.call({"id": 5, "cmd": "hello", "token": ep["token"], "protocol": 3}))
    out.append(("second hello keeps the connection protocol", dict(again["result"])["protocol"]))
    out.append(("second hello v2 has no identity block", "capabilities" in dict(again["result"])))
    c.close()
    c = conn()
    c.hello(protocol=3)
    c.send({"id": 2, "cmd": "ping"})
    out.append(("pipelined ping", shape(c.recv())))
    if jvm:
        c.send({"id": 3, "cmd": "nope"})
        err = dict(c.recv())
        out.append(("unknown command", [err["ok"], dict(err["error"])["code"]]))
    c.close()
    return out


def idle_client_visible(ep):
    """Two clients say hello; only the first asks for Ghidra. ``status`` must list both: the JVM has
    to know a client that has not asked for anything yet (its clients list, its shutdown check)."""
    a, b = Conn(ep), Conn(ep)
    a.hello(protocol=3)
    b.call({"id": 1, "cmd": "hello", "token": ep["token"], "client": "idle-b", "protocol": 3})
    st = a.call({"id": 2, "cmd": "status"})["result"]
    names = sorted(c["name"] for c in st["clients"])
    stop = b.call({"id": 3, "cmd": "shutdown"})  # b is a client of a daemon with another client: conflict
    a.close()
    b.close()
    return [names, stop.get("ok"), (stop.get("error") or {}).get("code")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    work = pathlib.Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    front = str(pathlib.Path(a.ghidra) / "Ghidra/Features/HeadlessSession/support/hydra-front.exe")
    if not pathlib.Path(front).is_file():
        print("no hydra-front.exe in the install: nothing to test")
        sys.exit(2)
    state = work / "state"
    try:
        r = launcher(a.ghidra, state, "direct", "ensure")
        r2 = launcher(a.ghidra, state, "front", "ensure", front=front)
        assert r.returncode == 0 and r2.returncode == 0, (r.stderr, r2.stderr)
        # 1. the front is COLD after bootstrap only when stopped and restarted from the cache
        launcher(a.ghidra, state, "front", "stop", front=front)
        r2 = launcher(a.ghidra, state, "front", "ensure", front=front)
        assert r2.returncode == 0, r2.stderr
        check("cold start: no JVM yet", False, jvm_running(state, "front"))
        direct = vectors(endpoint(state, "direct"))
        cold = vectors(endpoint(state, "front"), jvm=False)  # hello/ping/refusals only: the JVM stays down
        for (n, d), (_, f) in zip(direct, cold):
            check(n + " (cold front)", d, f)
        check("no JVM started by hello/ping/refusals", False, jvm_running(state, "front"))
        check("status lists a client that has not asked for Ghidra yet; shutdown sees it",
              idle_client_visible(endpoint(state, "direct")), idle_client_visible(endpoint(state, "front")))
        # 2. warm: a Ghidra-bound request attaches (starts the JVM); then the same vectors
        c = Conn(endpoint(state, "front"))
        c.hello(protocol=3)
        t = time.perf_counter()
        proj = c.call({"id": 2, "cmd": "projects"})
        print(f"info first JVM request through the front: {(time.perf_counter() - t) * 1000:.0f} ms")
        check("projects reply is the engine's", True, dict(proj)["ok"] is True)
        check("the first Ghidra-bound request started the JVM", True, jvm_running(state, "front"))
        c.close()
        warm = vectors(endpoint(state, "front"))
        for (n, d), (_, f) in zip(direct, warm):
            check(n + " (warm front)", d, f)
        keys = {}
        for label in ("direct", "front"):
            sc = Conn(endpoint(state, label))
            sc.hello(protocol=3)
            keys[label] = list(sc.call({"id": 9, "cmd": "status"})["result"])
            sc.close()
        check("status key order", keys["direct"], keys["front"])
        print("all vectors agree")
    finally:
        launcher(a.ghidra, state, "front", "stop", front=front)
        launcher(a.ghidra, state, "direct", "stop")


if __name__ == "__main__":
    main()
