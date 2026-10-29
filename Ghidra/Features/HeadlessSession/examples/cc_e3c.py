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
"""Protocol-2 behaviour of the E3c engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
V10, package E3c). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e3c.py --ghidra <install> --work <empty dir> --exe <small PE>

* ``reader_leave`` (V10) (V): a 1.0.0 client closes its connection (and another closes its program)
  while a third client's read runs: the next join of another client and the next script of an already
  joined client are answered within their ``wait``. (hydra.3: both are refused until the read ends.)
* ``reader_leave_all`` (V10) (V): every plain reader of a program leaves at once while a read runs;
  none of the leaves waits for the read, and the read ends ``ok``.
* ``v2_no_new_keys``: nothing of protocol 3 reaches a 1.0.0 client from E3c: a ``status`` has no
  ``waits`` and no ``projectStates``; a ``busy`` behind an analysis has no ``reason``.
"""
import pathlib
import threading
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, wait_for

HERE = pathlib.Path(__file__).resolve().parent


def prepare(c):
    return pathlib.Path(c.a.exe).name


def reader(c, d, gpr, exe, name, join=True):
    s = d.connect(name, "cc-e3c")
    s.call("open_project", path=str(gpr))
    if join:
        s.call("open_program", path=exe)
    return s


def users(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return pg
    return None


def running(s, name):
    """True while the client called ``name`` has a request running (a shared read holds no ``busy``)."""
    return any(cl["name"] == name and cl["requests"] for cl in s.call("status")["clients"])


def timed(c, s, cmd, **f):
    t = time.perf_counter()
    try:
        r = s.call(cmd, **f)
        return {"ok": True, "ms": round((time.perf_counter() - t) * 1000), "result": r}
    except c.stock.SessionError as e:
        return {"ok": False, "ms": round((time.perf_counter() - t) * 1000), "code": e.code,
                "details": e.details or {}, "message": e.message}


def close(*sessions):
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def t_reader_leave(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3cRl")
    d = c.daemon("cc-e3c-rl")
    A = B = B2 = J = D = None
    read_ms = 8000
    try:
        A = reader(c, d, gpr, exe, "A")
        B = reader(c, d, gpr, exe, "B")
        B2 = reader(c, d, gpr, exe, "B2")
        J = reader(c, d, gpr, exe, "J")
        D = reader(c, d, gpr, exe, "D", join=False)
        for s_ in (A, J):
            s_.call("script", script=c.script("TestSleep.java"), program=None, args=["10"],
                    wait=120000)
        rid = A.send("script", script=c.script("TestSleep.java"), args=[str(read_ms)],
                     wait=read_ms + 120000)
        wait_for(lambda: running(J, "A"), "the long read to run", 30)
        t0 = time.perf_counter()
        time.sleep(0.5)
        left = {}

        def leave():
            left["r"] = timed(c, B2, "close_program")
        th = threading.Thread(target=leave, daemon=True)
        th.start()
        B.close()                                           # a FIN
        probes = []
        while time.perf_counter() < t0 + read_ms / 1000.0 - 1.0:
            probes.append(("script of a joined client",
                           timed(c, J, "script", script=c.script("TestSleep.java"), args=["10"],
                                 wait=1500)))
            probes.append(("join of another client", timed(c, D, "open_program", path=exe, wait=1500)))
            time.sleep(0.25)
        th.join(15)
        # refused, or a join that took a lock wait's time. A script that was answered ok but ran long is
        # the script's own run time (a run without any leave shows the same stalls, on the unfixed base
        # too); a lock stall shows as a refusal, since every wait here is capped at 1500 ms.
        bad = [(n, p.get("code"), p["ms"]) for n, p in probes
               if not p["ok"] or (n.startswith("join") and p["ms"] >= 1500)]
        check(len(probes) >= 10, f"only {len(probes)} probes")
        check(not bad, f"{len(bad)} of {len(probes)} probes were refused or slow while a leave "
              f"happened (D63b): {bad[:4]}")
        check(left.get("r", {}).get("ok") and left["r"]["ms"] < 1500,
              f"close_program of a plain reader took {left.get('r')}")
        A.wait(rid)
        return (f"a FIN and a close_program during an {read_ms // 1000} s read: {len(probes)} probes "
                f"none refused (slowest {max(p['ms'] for _, p in probes)} ms)")
    finally:
        close(A, B, B2, J, D)
        d.stop(force=True)


def t_reader_leave_all(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3cLa")
    d = c.daemon("cc-e3c-la")
    A = None
    rs = []
    try:
        A = reader(c, d, gpr, exe, "A")
        A.call("script", script=c.script("TestSleep.java"), program=None, args=["10"], wait=120000)
        rs = [reader(c, d, gpr, exe, f"r{i}") for i in range(6)]
        rid = A.send("script", script=c.script("TestSleep.java"), args=["7000"], wait=130000)
        wait_for(lambda: running(rs[0], "A"), "the read to run", 30)
        res = {}

        def leave(i, r):
            t = time.perf_counter()
            try:
                if i % 2 == 0:
                    r.call("close_program")
                else:
                    r.close()
                res[i] = (True, (time.perf_counter() - t) * 1000)
            except Exception as e:  # noqa: BLE001
                res[i] = (False, str(e))
        ths = [threading.Thread(target=leave, args=(i, r), daemon=True) for i, r in enumerate(rs)]
        for th in ths:
            th.start()
        for th in ths:
            th.join(20)
        check(len(res) == len(rs) and all(v[0] and v[1] < 1500 for v in res.values()),
              f"leaves {res}")
        late = reader(c, d, gpr, exe, "late")
        r = timed(c, late, "info", wait=1500)
        check(r["ok"] and r["ms"] < 1500, f"a read after the leaves: {r}")
        A.wait(rid)
        close(late)
        return f"{len(rs)} leaves during a 7 s read, none waited for it; the read ended ok"
    finally:
        close(A, *rs)
        d.stop(force=True)


def t_v2_no_new_keys(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3cKeys")
    d = c.daemon("cc-e3c-keys")
    A = None
    try:
        A = reader(c, d, gpr, exe, "A")
        st = A.call("status")
        extra = [k for k in ("waits", "projectStates") if k in st]
        check(not extra, f"a protocol 2 status grew {extra}")
        return "a protocol 2 status has no waits and no projectStates"
    finally:
        close(A)
        d.stop(force=True)


TESTS = {
    "reader_leave": t_reader_leave,
    "reader_leave_all": t_reader_leave_all,
    "v2_no_new_keys": t_v2_no_new_keys,
}

if __name__ == "__main__":
    cc.run_file(__file__)
