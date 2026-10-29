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
"""Protocol-2 behaviour of the E3b engine, written against the stock 1.0.0 client (PROTOCOL-3.md 5.1,
package E3b). Standard library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_e3b.py --ghidra <install> --work <empty dir> --exe <small PE>

The ones marked (V) are declared v2-visible changes (5.1) and are red on hydra.3 by design; the
others pin what a protocol-2 client must see unchanged.

* ``dead_client_lock_wait`` (V3) (V): a 1.0.0 client killed while blocked in a program lock wait of
  ``wait`` 3600000 is gone within ``cleanupGraceS + abandonWaitS + 2 s`` (22 s), the holder still
  holding. (hydra.3: until the lock frees.)
* ``abandoned_holder`` (V4) (V): a 1.0.0 owner killed while its script ignores cancel: the program
  stays in use, another 1.0.0 client gets ``busy`` at once with hydra.3's detail keys (``holder`` and
  ``holderInfo`` name the abandoned request) and none of the protocol 3 keys; ``status`` has no
  ``abandonedRequests``. (hydra.3: a silent wait for ``wait``.)
* ``cancel_while_waiting`` (V5) (V): ``cancel`` of a request in a lock wait answers ``cancelled``
  within 1 s, with no ``phase`` and no ``applied``. (hydra.3: ``busy`` when the wait runs out.)
* ``owner_leave_bounded`` (V3) (V): a 1.0.0 client that owns a program is killed while another client
  reads it: readers are refused no longer than ``cleanupGraceS + abandonWaitS`` after the kill.
  (hydra.3: until the read ends.)
* ``v2_lock_busy_keys``: a lock ``busy`` has hydra.3's detail keys and none of ``reason``, ``queue``,
  ``abandoned``; the error has no ``retryAfterMs``.
* ``v2_no_lock_cap``: more waiters than ``max(2, slots/4)`` on one lock all wait; no ``lock_queue_full``.
* ``v2_connection_serial``: a protocol 2 connection stays serial: an ``info`` sent behind a long
  script waits for it (a v3 connection runs it beside the script).
"""
import pathlib
import threading
import time

import client_compat_tests as cc
from client_compat_tests import Fail, check, wait_for

HERE = pathlib.Path(__file__).resolve().parent
#: the keys of a lock ``busy`` on hydra.3 (ProgramEntry.acquire): identity, then these
V2_LOCK_BUSY = ["wanted", "waitedMs", "holder", "holderInfo", "heldMs", "suggest"]
DEAF = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class E3bDeaf extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try {
                Thread.sleep(20);
            }
            catch (InterruptedException e) {
                // ignores cancel and interrupt
            }
        }
    }
}
"""


def prepare(c):
    (c.scripts / "E3bDeaf.java").write_text(DEAF)
    return pathlib.Path(c.a.exe).name


def start(c, instance, **engine):
    """A daemon for the stock client; with ``engine`` settings it is started by the client under
    test (the stock 1.0.0 client has no ``engine`` option) and joined by the stock client."""
    if engine:
        c.new_daemon(instance, engine=engine).connect("cc-e3b-start", "tests").close()
    return c.daemon(instance)


def owner(c, d, gpr, exe, name="owner"):
    s = d.connect(name, "cc-e3b")
    s.call("open_project", path=str(gpr), writable=True)
    s.call("open_program", path=exe, writable=True)
    return s


def reader(c, d, gpr, exe, name):
    s = d.connect(name, "cc-e3b")
    s.call("open_project", path=str(gpr))
    s.call("open_program", path=exe)
    return s


def warm(c, s, *names):
    for n in names or ("TestSleep.java",):
        s.call("script", script=c.script(n), program=None, args=["10"], wait=120000)


def holds(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return bool(pg["busy"])
    return False


def users_busy(s, exe):
    for pg in s.call("status")["programs"]:
        if pg["path"] == "/" + exe:
            return pg
    return None


def sleeper(c, s, ms, name="TestSleep.java"):
    return s.send("script", script=c.script(name), args=[str(ms)], parallel=True, wait=ms + 120000)


def timed(c, s, cmd, **f):
    t = time.perf_counter()
    try:
        r = s.call(cmd, **f)
        return {"ok": True, "ms": round((time.perf_counter() - t) * 1000), "result": r}
    except c.stock.SessionError as e:
        return {"ok": False, "ms": round((time.perf_counter() - t) * 1000), "code": e.code,
                "details": e.details or {}, "message": e.message}


def names(s):
    return [cl["name"] for cl in s.call("status")["clients"]]


def stop(s, hold=None):
    try:
        s.call("cancel", all=True)
    except Exception:  # noqa: BLE001
        pass
    if hold is not None:
        try:
            s.wait(hold)
        except Exception:  # noqa: BLE001
            pass


def close(*sessions):
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


# ---- dead_client_lock_wait ------------------------------------------------------------------

def t_dead_client_lock_wait(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bDr")
    d = c.daemon("cc-e3b-dr")
    bound = 15 + 5 + 2
    H = O = D = None
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H)
        O = reader(c, d, gpr, exe, "observer")
        D = reader(c, d, gpr, exe, "doomed")
        fn = H.call("functions", limit=1)["functions"][0]["address"]
        hold = sleeper(c, H, 120000)
        wait_for(lambda: holds(O, exe), "the holder to hold the program", 30)
        D.send("decompile", address=fn, wait=3600000)
        wait_for(lambda: any(cl["name"] == "doomed" and cl["requests"]
                             for cl in O.call("status")["clients"]), "the doomed request", 30)
        time.sleep(1.0)
        t = time.perf_counter()
        D.close()
        gone = None
        while time.perf_counter() - t < bound + 8:
            if "doomed" not in names(O):
                gone = time.perf_counter() - t
                break
            time.sleep(0.2)
        check(gone is not None, f"the killed 1.0.0 client was still registered {bound + 8} s later")
        check(gone <= bound, f"gone after {gone:.1f} s, bound {bound}")
        check(holds(O, exe), "the holder lost the program")
        stop(H, hold)
        return f"the 1.0.0 client killed in a 3600000 ms lock wait was gone after {gone:.1f} s (bound {bound})"
    finally:
        close(H, O, D)
        d.stop(force=True)


# ---- abandoned_holder -----------------------------------------------------------------------

def t_abandoned_holder(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bAb")
    d = start(c, "cc-e3b-ab", cleanupGraceS=2, abandonWaitS=2)
    deaf_ms = 14000
    H = O = None
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H, "TestSleep.java", "E3bDeaf.java")
        O = reader(c, d, gpr, exe, "observer")
        fn = H.call("functions", limit=1)["functions"][0]["address"]
        H.send("script", script=c.script("E3bDeaf.java"), args=[str(deaf_ms)], parallel=True,
               wait=120000)
        wait_for(lambda: holds(O, exe), "the deaf script to hold the program", 30)
        t = time.perf_counter()
        H.close()
        wait_for(lambda: "owner" not in names(O), "the dead owner to leave the client list", 30, 0.2)
        gone = time.perf_counter() - t
        pg = users_busy(O, exe)
        check(pg is not None and pg["owner"] is not None,
              f"the program of the abandoned script was released: {pg}")
        check("abandonedRequests" not in pg, f"a v2 status.programs[] grew abandonedRequests: {pg}")
        r = timed(c, O, "decompile", address=fn, wait=20000)
        check(not r["ok"] and r["code"] == "busy", f"another client on the abandoned program: {r}")
        check(r["ms"] < 1500, f"it was told busy after {r['ms']} ms (hydra.3: after its whole wait)")
        det = r["details"]
        check(all(k in det for k in ("wanted", "holder", "holderInfo", "suggest")),
              f"busy lacks hydra.3's keys: {list(det)}")
        check(not ({"reason", "queue", "abandoned"} & set(det)),
              f"a protocol 2 busy carries protocol 3 keys: {list(det)}")
        check("abandoned request" in det["holder"] and "client gone" in det["holder"],
              f"holder: {det['holder']}")
        check("retryAfterMs" not in O.last_response["error"], "retryAfterMs on a protocol 2 busy")
        # it ends with the script, nobody waited for minutes
        wait_for(lambda: timed(c, O, "info", wait=1000)["ok"], "the program to be readable again",
                 deaf_ms / 1000 + 20, 0.5)
        return (f"the dead owner left the client list {gone:.1f} s after the kill; busy in {r['ms']} ms "
                f"with hydra.3's keys and 'abandoned request' in holder; readable when the script ended")
    finally:
        close(H, O)
        d.stop(force=True)


# ---- cancel_while_waiting -------------------------------------------------------------------

def t_cancel_while_waiting(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bCw")
    d = c.daemon("cc-e3b-cw")
    H = R = None
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H)
        R = reader(c, d, gpr, exe, "waiter")
        fn = H.call("functions", limit=1)["functions"][0]["address"]
        hold = sleeper(c, H, 30000)
        wait_for(lambda: holds(R, exe), "the holder to hold the program", 30)
        rid = R.send("decompile", address=fn, wait=60000, parallel=True)
        time.sleep(1.0)
        t = time.perf_counter()
        ack = R.call("cancel", target=rid)
        try:
            R.wait(rid)
            raise Fail("the cancelled request succeeded")
        except c.stock.SessionError as e:
            ms = (time.perf_counter() - t) * 1000
            check(ack.get("cancelled") is True, f"cancel ack {ack}")
            check(e.code == "cancelled", f"the cancelled lock wait answered {e.code} after {ms:.0f} ms")
            check(ms < 1000, f"cancelled after {ms:.0f} ms")
            check(not ({"phase", "applied"} & set(e.details or {})),
                  f"a protocol 2 cancelled carries protocol 3 keys: {e.details}")
        check(holds(R, exe), "the holder lost the program")
        stop(H, hold)
        return f"a lock wait of a 1.0.0 client answered cancelled {ms:.0f} ms after the cancel, no v3 keys"
    finally:
        close(H, R)
        d.stop(force=True)


# ---- owner_leave_bounded --------------------------------------------------------------------

def t_owner_leave_bounded(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bOl")
    d = start(c, "cc-e3b-ol", cleanupGraceS=2, abandonWaitS=2)
    bound = 4
    read_ms = 24000
    H = O = N = None
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H)
        O = reader(c, d, gpr, exe, "reader")
        N = reader(c, d, gpr, exe, "newcomer")
        read = sleeper(c, O, read_ms)
        wait_for(lambda: any(cl["name"] == "reader" and cl["requests"]
                             for cl in N.call("status")["clients"]), "the long read", 30)
        time.sleep(0.5)
        t = time.perf_counter()
        H.close()
        last = 0.0
        while time.perf_counter() - t < bound + 6:
            r = timed(c, N, "info", wait=1500)
            if not r["ok"]:
                last = time.perf_counter() - t
            time.sleep(0.25)
        check(last <= bound + 1.5, f"readers were refused until {last:.1f} s after the owner died "
              f"(bound {bound} + 1.5)")
        r = timed(c, N, "info", wait=1500)
        check(r["ok"], f"a reader is refused {time.perf_counter() - t:.1f} s after the kill, "
              f"while the read runs: {r}")
        stop(O, read)
        return f"readers were refused for {last:.1f} s after the owner's kill (bound {bound}), then served"
    finally:
        close(H, O, N)
        d.stop(force=True)


# ---- v2_lock_busy_keys ----------------------------------------------------------------------

def t_v2_lock_busy_keys(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bKeys")
    d = c.daemon("cc-e3b-keys")
    H = R = None
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H)
        R = reader(c, d, gpr, exe, "waiter")
        fn = H.call("functions", limit=1)["functions"][0]["address"]
        hold = sleeper(c, H, 20000)
        wait_for(lambda: holds(R, exe), "the holder to hold the program", 30)
        r = timed(c, R, "decompile", address=fn, wait=700)
        check(not r["ok"] and r["code"] == "busy", f"a lock timeout: {r}")
        det = r["details"]
        check(all(k in det for k in V2_LOCK_BUSY), f"busy lacks hydra.3's keys {V2_LOCK_BUSY}: {list(det)}")
        check(not ({"reason", "queue", "abandoned"} & set(det)), f"v3 keys on a v2 busy: {list(det)}")
        check(det["waitedMs"] == 700 and det["wanted"] == "shared", f"details: {det}")
        err = R.last_response["error"]
        check(set(err) <= {"code", "message", "details", "trace"}, f"error keys {list(err)}")
        check(700 <= r["ms"] < 2500, f"busy after {r['ms']} ms (wait 700)")
        stop(H, hold)
        return "a lock timeout is busy with hydra.3's keys, no reason/queue/abandoned, no retryAfterMs"
    finally:
        close(H, R)
        d.stop(force=True)


# ---- v2_no_lock_cap -------------------------------------------------------------------------

def t_v2_no_lock_cap(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bCap")
    d = c.daemon("cc-e3b-cap", maxQuick=4)
    H = None
    rs = []
    try:
        H = owner(c, d, gpr, exe)
        warm(c, H)
        rs = [reader(c, d, gpr, exe, f"w{i}") for i in range(4)]
        fn = H.call("functions", limit=1)["functions"][0]["address"]
        hold = sleeper(c, H, 6000)
        wait_for(lambda: holds(rs[0], exe), "the holder to hold the program", 30)
        ids = [r.send("decompile", address=fn, wait=40000, parallel=True) for r in rs]
        time.sleep(1.5)
        stop(H, hold)
        out = []
        for r, i in zip(rs, ids):
            try:
                r.wait(i)
                out.append("ok")
            except c.stock.SessionError as e:
                out.append(e.code)
        check(out == ["ok"] * 4, f"4 waiters (cap would be 2) on a protocol 2 connection: {out}")
        return "4 waiters on one lock all waited and were served: the cap is protocol 3 only"
    finally:
        close(H, *rs)
        d.stop(force=True)


# ---- v2_connection_serial -------------------------------------------------------------------

def t_v2_connection_serial(c):
    exe = prepare(c)
    gpr = c.copy_fixture("ccE3bSer")
    d = c.daemon("cc-e3b-ser")
    X = None
    try:
        X = owner(c, d, gpr, exe)
        warm(c, X)
        rid = X.send("script", script=c.script("TestSleep.java"), program=None, args=["3000"])
        time.sleep(0.4)
        t = time.perf_counter()
        X.call("info")
        ms = (time.perf_counter() - t) * 1000
        X.wait(rid)
        check(ms > 1800, f"an info sent behind a 3 s script on a protocol 2 connection took {ms:.0f} ms")
        return f"info behind a 3 s script took {ms:.0f} ms: a protocol 2 connection stays serial"
    finally:
        close(X)
        d.stop(force=True)


TESTS = {
    "dead_client_lock_wait": t_dead_client_lock_wait,
    "abandoned_holder": t_abandoned_holder,
    "cancel_while_waiting": t_cancel_while_waiting,
    "owner_leave_bounded": t_owner_leave_bounded,
    "v2_lock_busy_keys": t_v2_lock_busy_keys,
    "v2_no_lock_cap": t_v2_no_lock_cap,
    "v2_connection_serial": t_v2_connection_serial,
}

if __name__ == "__main__":
    cc.run_file(__file__)
