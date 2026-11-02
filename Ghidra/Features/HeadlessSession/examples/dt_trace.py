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
"""The semantic trace commands (``TraceCommands.java``, PROTOCOL-3.md "Trace commands", TRACE-1.md).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only trace_basic,...

* ``trace_basic``: the twelve commands on one session; the capability and ``minClient``; a protocol 2
  connection is refused; repeated reads give the same reply lines.
* ``trace_readers_writer``: two readers and one writer; a reader sees whole batches only, never a
  partial row, and no request waits on another (``waits.foreignBlocked`` stays 0).
* ``trace_writer_kill``: the writer's connection ends; the committed rows stay readable; the lease is
  an orphan; a takeover bumps the producer generation and the old capability is worthless.
* ``trace_lease``: a live writer is never taken over; reconnecting with the capability moves the
  lease and bumps the generation; a stale writer gets ``not_owner``.
* ``trace_recovery``: a daemon kill leaves a torn segment tail and a lost index; the next owner's
  open cuts the tail and indexes the segment again, and the rows are the same.
* ``trace_cancel``: a ``cancel`` reaches the engine in a long-lane export; no partial file is left
  and a query is answered meanwhile.
* ``trace_cursor``: a pinned cursor (``upTo``) pages through the same rows while the writer appends.
* ``trace_disk_reserve``: ``diskReserve`` above the free space refuses a new session and an append
  with ``busy``/``capacity``/``disk``, and creates nothing.
* ``trace_symbolize``: addresses resolve to functions at a pinned revision; unresolved ones keep a
  reason; a rename plus ``trace_resymbolize`` is a new revision and the observations are unchanged.
* ``trace_agent_workload``: four ``hydra-agent`` processes run the ``trace_read`` workload while a
  writer appends; every row is ok and no request waited on another (needs ``HYDRA_AGENT``).
* ``trace_client_identity``: the Python and the Rust client send and receive the same bytes
  (needs ``HYDRA_AGENT``, the path of ``hydra-agent.exe``).
"""
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

import daemon_tests as dt

from pathlib import Path

HERE = Path(__file__).resolve().parent


def _mod(name):
    if name in sys.modules:
        return sys.modules[name]
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


e9 = _mod("dt_e9")
_MS = re.compile(r',"ms":\d+')
_ID = re.compile(r'^\{"id":\d+,')


def blocked(st):
    """Requests that had to wait behind another client's request (``waits.foreignBlocked.total``)."""
    fb = st["waits"].get("foreignBlocked", 0)
    return fb.get("total", 0) if isinstance(fb, dict) else fb


def sid(tag):
    return f"t{tag}{uuid.uuid4().hex[:8]}"


def ev(i, kind="core.marker", **extra):
    return {"kind": kind, "payload": {"i": i, "corr": f"c{i}"}, **extra}


def writer(c, d, who, session, **kw):
    """A protocol 3 connection that created ``session`` and holds its lease."""
    s = c.connect(d, who, "trace", 3)
    res = s.trace_open(session, create=True, **kw)
    return s, res["lease"]["cap"], res


def root_of(c):
    return Path(str(c.state)) / "traces"


def record(s):
    """Keeps every raw reply line of ``s`` (the bytes before json.loads)."""
    lines = []
    orig = s._recv

    def rec(*a, **k):
        line = orig(*a, **k)
        if line:
            lines.append(line)
        return line

    s._recv = rec
    return lines


def line_of(lines, rid):
    for ln in reversed(lines):
        if ln.startswith('{"id":%d,' % rid):
            return _MS.sub("", _ID.sub("{", ln.rstrip("\r\n")))
    raise dt.Fail(f"no reply line for id {rid}")


# ------------------------------------------------------------------------------------------------

def t_basic(c):
    d = c.daemon("tr-basic")
    s = a = b = None
    try:
        s = c.connect(d, "w", "trace", 3)
        caps = s.hello.get("capabilities", {})
        dt.check(caps.get("trace") == 1, f"the trace capability is not advertised at 1: {caps}")
        dt.check(s.hello.get("minClient") == "1.0.0", f"minClient moved: {s.hello.get('minClient')}")
        names = list(caps)
        dt.check(names.index("trace") > names.index("admission"), f"trace is declared last: {names}")
        # protocol 2 sees no change: the commands are refused, nothing else differs
        p2 = c.connect(d, "p2", "trace", 2)
        try:
            e = dt.expect_error("unknown_command", p2.call, "trace_list")
            dt.check("protocol 3" in e.message, f"the refusal does not say why: {e.message}")
        finally:
            p2.close()
        session = sid("basic")
        o = s.trace_open(session, create=True, name="basic")
        cap = o["lease"]["cap"]
        dt.check(o["created"] is True and o["lease"]["producerGen"] == 1 and o["events"] == 0, f"{o}")
        dt.expect_error("conflict", s.trace_open, session, create=True)
        dt.expect_error("not_found", s.trace_open, sid("none"))
        dt.expect_error("bad_request", s.trace_open, "../escape", create=True)
        events = [ev(i, "core.resource.open" if i % 2 else "core.resource.read",
                     va=0x401000 + i, module="x.exe") for i in range(30)]
        ap = s.trace_append(session, cap, events)
        dt.check(ap["appended"] == 30 and ap["events"] == 30 and ap["rejected"] == 0, f"{ap}")
        bad = s.trace_append(session, cap, [{"kind": "core.nope"}, {"kind": "app.fine"}])
        dt.check(bad["appended"] == 1 and bad["rejected"] == 1, f"{bad}")
        dt.expect_error("bad_request", s.trace_append, session, cap,
                        [{"kind": "core.marker", "payload": {"ratio": 0.5}}])
        mk = s.trace_mark(session, cap, "phase-1")
        dt.check(mk["appended"] == 1 and mk["label"] == "phase-1", f"{mk}")
        a = c.connect(d, "r1", "trace", 3)
        b = c.connect(d, "r2", "trace", 3)
        la, lb = record(a), record(b)
        q = a.trace_query(session, limit=100)
        dt.check(q["returned"] == 32 and q["rows"][0]["seq"] == 1, f"{q['returned']}")
        g = a.trace_query(session, group_by="kind")
        dt.check({x["key"]: x["count"] for x in g["groups"]}["core.resource.open"] == 15, f"{g}")
        dt.expect_error("bad_request", a.trace_query, session, group_by="pid")
        one = a.trace_query(session, kinds=["core.marker"])
        dt.check(one["returned"] == 1, f"{one}")
        ck = a.trace_check(session, {"type": "cardinality", "kind": "core.resource.open", "min": 15,
                                     "max": 15, "name": "opens"})
        dt.check(ck["verdict"] == "pass" and ck["checked"] == 15, f"{ck}")
        ck2 = a.trace_check(session, {"type": "forbidden", "kind": "core.error", "name": "no-errors"})
        dt.check(ck2["verdict"] == "pass", f"{ck2}")
        dt.expect_error("bad_request", a.trace_check, session, {"type": "nope"})
        ex = a.trace_explain(session, one["rows"][0]["event_id"])
        dt.check(ex["unresolved"] == ["no-correlation"] or ex["events"] == [], f"{ex}")
        info = a.trace_info(session)
        dt.check(info["events"] == 32 and info["lease"]["state"] == "held"
                 and "cap" not in info["lease"], f"{info}")
        dt.check(info["segments"][0]["clean"] is True, f"{info['segments']}")
        lst = b.trace_list()
        dt.check(any(r["session"] == session and r["events"] == 32 for r in lst["sessions"]), f"{lst}")
        xp = a.trace_export(session, name="all")
        dt.check(xp["events"] == 32 and len(xp["sha256"]) == 64, f"{xp}")
        dt.check(Path(xp["file"]).is_file(), f"no export file {xp['file']}")
        # the same read gives the same bytes, on either connection
        rids = []
        for s_, ln in ((a, la), (b, lb), (a, la), (b, lb)):
            s_.trace_query(session, limit=50, kinds=["core.resource.open"])
            rids.append((ln, s_.last_response["id"]))
        lines = [line_of(ln, rid) for ln, rid in rids]
        dt.check(len(set(lines)) == 1, f"repeated reads differ: {lines[:2]}")
        cl = s.trace_close(session, cap)
        dt.check(cl["closed"] is True and cl["events"] == 32, f"{cl}")
        dt.expect_error("not_owner", s.trace_append, session, cap, [ev(99)])
        st = s.call("status")
        dt.check(blocked(st) == 0, f"waits: {st['waits']}")
        h = s.call("health").get("trace") or {}
        dt.check(h.get("enabled") is True and h.get("calls", 0) > 10, f"health.trace: {h}")
        return f"12 commands on {session}: 32 events, capability trace=1, minClient 1.0.0, protocol 2 refused; {h}"
    finally:
        e9.close_all(s, a, b)
        e9.stop(d)


def t_readers_writer(c):
    batch, rounds = 25, 60
    d = c.daemon("tr-rw")
    session = sid("rw")
    w, cap, _ = writer(c, d, "writer", session)
    r1, r2 = c.connect(d, "r1", "trace", 3), c.connect(d, "r2", "trace", 3)
    stop = threading.Event()
    problems, seen = [], [0, 0]

    def reader(i, s):
        last = 0
        try:
            while not stop.is_set():
                q = s.trace_query(session, limit=1000)
                hw, rows = q["highWater"], q["rows"]
                seen[i] += 1
                if hw % batch:
                    problems.append(f"r{i}: a partial batch is visible, highWater {hw}")
                if hw < last:
                    problems.append(f"r{i}: highWater went back {last} -> {hw}")
                seqs = [r["seq"] for r in rows]
                if seqs != list(range(1, len(seqs) + 1)):
                    problems.append(f"r{i}: rows are not contiguous: {seqs[:5]}..")
                if len(rows) != min(hw, 1000):
                    problems.append(f"r{i}: {len(rows)} rows for highWater {hw}")
                if [r["payload"]["i"] for r in rows] != list(range(len(rows))):
                    problems.append(f"r{i}: a row is missing or torn")
                last = hw
        except Exception as e:  # noqa: BLE001
            problems.append(f"r{i}: {type(e).__name__}: {e}")

    ths = [threading.Thread(target=reader, args=(i, s), daemon=True) for i, s in enumerate((r1, r2))]
    try:
        for th in ths:
            th.start()
        for k in range(rounds):
            w.trace_append(session, cap, [ev(k * batch + j) for j in range(batch)])
        time.sleep(0.2)
        stop.set()
        for th in ths:
            th.join(30)
        dt.check(not problems, f"{problems[:5]}")
        dt.check(min(seen) > 5, f"the readers hardly ran: {seen}")
        final = r1.trace_query(session, limit=1000)
        dt.check(final["highWater"] == batch * rounds, f"{final['highWater']}")
        st = w.call("status")
        dt.check(blocked(st) == 0, f"a request waited on another: {st['waits']}")
        return f"{rounds} batches of {batch}; readers made {seen} reads, whole batches only; foreignBlocked 0"
    finally:
        stop.set()
        e9.close_all(w, r1, r2)
        e9.stop(d)


def t_writer_kill(c):
    d = c.daemon("tr-kill")
    session = sid("kill")
    a, cap, _ = writer(c, d, "w-a", session)
    r = c.connect(d, "reader", "trace", 3)
    b = a2 = None
    try:
        a.trace_append(session, cap, [ev(i) for i in range(30)])
        a.close()    # the writer dies without trace_close
        dt.wait_for(lambda: r.trace_info(session)["lease"]["state"] == "orphan", "the lease to be orphaned", 20)
        info = r.trace_info(session)
        dt.check(info["events"] == 30, f"committed rows lost: {info['events']}")
        q = r.trace_query(session, limit=100)
        dt.check([x["payload"]["i"] for x in q["rows"]] == list(range(30)), "rows differ after the writer died")
        b = c.connect(d, "w-b", "trace", 3)
        e = dt.expect_error("not_owner", b.trace_open, session, mode="write")
        dt.check(e.details.get("orphan") is True and e.details.get("suggest") == "takeover", f"{e.details}")
        got = b.trace_open(session, mode="write", takeover=True)
        lease = got["lease"]
        dt.check(lease["producerGen"] == 2 and lease["tookOver"] is True and lease["cap"] != cap, f"{lease}")
        dt.expect_error("not_owner", b.trace_append, session, cap, [ev(99)])      # the old capability
        ap = b.trace_append(session, lease["cap"], [ev(30 + i) for i in range(30)])
        dt.check(ap["appended"] == 30 and ap["producerGen"] == 2 and ap["gapsFound"] == 0, f"{ap}")
        a2 = c.connect(d, "w-a2", "trace", 3)
        dt.expect_error("not_owner", a2.trace_open, session, mode="write", cap=cap)   # the dead writer's cap
        q = r.trace_query(session, limit=100)
        dt.check([x["payload"]["i"] for x in q["rows"]] == list(range(60)), "rows differ after the takeover")
        return "killed writer: 30 rows kept, orphan lease, takeover gen 2, old capability refused, 30 more rows"
    finally:
        e9.close_all(a, b, a2, r)
        e9.stop(d)


def t_lease(c):
    d = c.daemon("tr-lease")
    session = sid("lease")
    w1, cap, _ = writer(c, d, "w1", session)
    w2 = c.connect(d, "w2", "trace", 3)
    try:
        w1.trace_append(session, cap, [ev(0)])
        e = dt.expect_error("not_owner", w2.trace_open, session, mode="write")
        dt.check(e.details.get("orphan") is False and "w1" in str(e.details.get("holder")), f"{e.details}")
        dt.expect_error("not_owner", w2.trace_open, session, mode="write", takeover=True)   # a live writer
        ro = w2.trace_open(session, mode="read")
        dt.check(ro["lease"]["role"] == "reader" and ro["events"] == 1, f"{ro}")
        dt.expect_error("not_owner", w2.trace_append, session, cap, [ev(1)])     # not the owner connection
        dt.expect_error("bad_request", w2.trace_open, session, mode="read", takeover=True)
        again = w1.trace_open(session, mode="write", cap=cap)
        dt.check(again["lease"]["producerGen"] == 1 and again["lease"]["reclaimed"] is False, f"{again}")
        moved = w2.trace_open(session, mode="write", cap=cap)       # the producer reconnected
        dt.check(moved["lease"]["producerGen"] == 2 and moved["lease"]["reclaimed"] is True, f"{moved}")
        dt.expect_error("not_owner", w1.trace_append, session, cap, [ev(2)])    # the old connection is stale
        ap = w2.trace_append(session, cap, [ev(2)])
        dt.check(ap["producerGen"] == 2 and ap["appended"] == 1, f"{ap}")
        dt.expect_error("not_owner", w1.trace_mark, session, cap, "late")
        stale = w2.trace_append(session, cap, [dict(ev(3), producer_gen=1)])
        dt.check(stale["appended"] == 0 and stale["rejected"] == 1, f"a stale generation was accepted: {stale}")
        info = w1.trace_info(session)
        dt.check(info["lease"]["state"] == "held" and info["lease"]["producerGen"] == 2, f"{info['lease']}")
        lease_file = root_of(c) / session / "lease.json"
        dt.check(lease_file.is_file(), "no lease.json")
        dt.check("cap_" not in lease_file.read_text(), "the capability itself is stored")
        return "live writer not taken over; reconnect with the capability moved the lease (gen 2); the stale writer is not_owner"
    finally:
        e9.close_all(w1, w2)
        e9.stop(d)


def t_recovery(c):
    d = c.daemon("tr-rec")
    s = s2 = None
    torn, lost = sid("torn"), sid("lost")
    try:
        s = c.connect(d, "w", "trace", 3)
        caps = {}
        for name in (torn, lost):
            caps[name] = s.trace_open(name, create=True)["lease"]["cap"]
            s.trace_append(name, caps[name], [ev(i) for i in range(6)])
            s.trace_append(name, caps[name], [ev(6 + i) for i in range(6)])
        before = {n: [(x["event_id"], x["kind"], json.dumps(x["payload"], sort_keys=True))
                      for x in s.trace_query(n, limit=100)["rows"]] for n in (torn, lost)}
        d.kill()
        s.close()
        s = None
        root = root_of(c)
        seg = root / torn / "seg-api.trace"
        with open(seg, "ab") as f:
            f.write(b'deadbeef {"half')                 # the writer died inside a line
        for suffix in ("", "-wal", "-shm"):             # and the other session lost its index
            with contextlib.suppress(FileNotFoundError):
                os.remove(root / lost / f"index.db{suffix}")
        d2 = c.daemon("tr-rec")
        s2 = c.connect(d2, "w2", "trace", 3)
        # the lease is an orphan after a restart: the capability reclaims it
        got = s2.trace_open(torn, mode="write", cap=caps[torn])
        rec = got["recovered"]
        dt.check(got["lease"]["producerGen"] == 2 and got["lease"]["reclaimed"] is True, f"{got['lease']}")
        dt.check(rec["tornTailBytes"] > 0 and rec["reindexed"] == 0 and rec["records"] == 12, f"{rec}")
        dt.check(got["events"] == 12, f"{got}")
        got2 = s2.trace_open(lost, mode="write", cap=caps[lost])
        rec2 = got2["recovered"]
        dt.check(rec2["reindexed"] == 12 and rec2["tornTailBytes"] == 0 and rec2["damaged"] == [], f"{rec2}")
        for n in (torn, lost):
            q = s2.trace_query(n, limit=100)
            now = [(x["event_id"], x["kind"], json.dumps(x["payload"], sort_keys=True)) for x in q["rows"]]
            dt.check(now == before[n], f"{n}: the recovered index differs from the original")
        ap = s2.trace_append(torn, caps[torn], [ev(12)])
        dt.check(ap["appended"] == 1 and ap["producerGen"] == 2, f"{ap}")
        info = s2.trace_info(torn)
        dt.check(info["segments"][0]["clean"] is True and info["segments"][0]["records"] == 13, f"{info['segments']}")
        return f"torn tail cut ({rec['tornTailBytes']} bytes), lost index rebuilt from the segment ({rec2['reindexed']} rows), rows identical"
    finally:
        e9.close_all(s, s2)
        e9.stop(d)


def t_cancel(c):
    d = c.daemon("tr-cancel")
    session = sid("cancel")
    w, cap, _ = writer(c, d, "w", session)
    r = c.connect(d, "r", "trace", 3)
    x = c.connect(d, "x", "trace", 3)
    try:
        pad = "p" * 200
        for k in range(30):
            w.trace_append(session, cap, [{"kind": "core.marker", "payload": {"i": k * 10_000 + i, "pad": pad}}
                                          for i in range(10_000)])
        total = w.trace_info(session)["events"]
        dt.check(total == 300_000, f"{total}")
        cancelled = 0
        for delay in (0.03, 0.06, 0.1):
            rid = x.send("trace_export", session=session, name=f"big{int(delay * 1000)}")
            time.sleep(delay)
            # while it runs in the long lane, a query is answered at once
            t = time.perf_counter()
            q = r.trace_query(session, limit=5)
            quick_ms = (time.perf_counter() - t) * 1000
            dt.check(q["returned"] == 5 and quick_ms < 3000, f"a query waited {quick_ms:.0f} ms behind an export")
            x.call("cancel", target=rid)
            try:
                x.wait(rid)
            except Exception as e:  # noqa: BLE001
                dt.check(getattr(e, "code", None) == "cancelled", f"{type(e).__name__}: {e}")
                cancelled += 1
                out = root_of(c) / session / "export"
                dt.check(not (out / f"big{int(delay * 1000)}.jsonl").exists(), "a cancelled export left a file")
                dt.check(not list(out.glob("*.tmp")), "a cancelled export left a temporary file")
        dt.check(cancelled >= 1, "no export was cancelled: the cancel did not reach the engine")
        done = x.trace_export(session, name="whole")
        dt.check(done["events"] == total and Path(done["file"]).is_file(), f"{done}")
        return f"{cancelled} of 3 exports of {total} events cancelled in the engine, none left a file, a query took {quick_ms:.0f} ms meanwhile"
    finally:
        e9.close_all(w, r, x)
        e9.stop(d)


def t_cursor(c):
    d = c.daemon("tr-cursor")
    session = sid("cursor")
    w, cap, _ = writer(c, d, "w", session)
    r = c.connect(d, "r", "trace", 3)
    try:
        w.trace_append(session, cap, [ev(i) for i in range(500)])
        first = r.trace_query(session, limit=100)
        up_to, seen, nxt = first["upTo"], [x["payload"]["i"] for x in first["rows"]], first["next"]
        pages = 1
        while nxt is not None:
            # the writer keeps appending between the pages
            w.trace_append(session, cap, [ev(10_000 + pages * 10 + i) for i in range(10)])
            q = r.trace_query(session, limit=100, after=nxt, upTo=up_to)
            seen += [x["payload"]["i"] for x in q["rows"]]
            nxt = q["next"]
            pages += 1
        dt.check(seen == list(range(500)), f"the pinned cursor saw other rows: {len(seen)}")
        dt.check(pages == 5, f"{pages} pages")
        fresh = r.trace_query(session, limit=1000)
        dt.check(fresh["highWater"] == 500 + 10 * (pages - 1), f"{fresh['highWater']}")
        again = r.trace_query(session, limit=100, upTo=up_to)
        dt.check([x["payload"]["i"] for x in again["rows"]] == list(range(100)), "the first page changed")
        return f"a cursor pinned at {up_to} paged {pages} pages over the same 500 rows while 40 more arrived"
    finally:
        e9.close_all(w, r)
        e9.stop(d)


def t_disk_reserve(c):
    ok = c.daemon("tr-disk-ok")
    tight = c.daemon("tr-disk-tight", engine={"diskReserve": "900000000"})      # about 860 TB (MB)
    session = sid("disk")
    w = t = None
    try:
        w, cap, _ = writer(c, ok, "w", session)
        w.trace_append(session, cap, [ev(0)])
        t = c.connect(tight, "t", "trace", 3)
        before = sorted(p.name for p in root_of(c).iterdir())
        refusal = e9.refusal(t.trace_open, sid("refused"), create=True)
        dt.check(refusal is not None and refusal.get("resource") == "disk", f"a new session was not refused: {refusal}")
        dt.check(refusal.get("retryAfterMs", 0) > 0 and refusal.get("need", 0) > refusal.get("have", 1), f"{refusal}")
        dt.check(sorted(p.name for p in root_of(c).iterdir()) == before, "a refused session left files behind")
        got = t.trace_open(session, mode="write", cap=cap)          # reclaiming a lease writes nothing
        dt.check(got["lease"]["producerGen"] == 2, f"{got['lease']}")
        ref2 = e9.refusal(t.trace_append, session, cap, [ev(1)])
        dt.check(ref2 is not None and ref2.get("resource") == "disk", f"an append was not refused: {ref2}")
        dt.check(t.trace_query(session)["highWater"] == 1, "a read was refused or the refused append wrote")
        dt.check(t.trace_list()["count"] >= 1, "list failed on a full disk")
        return f"new session and append refused with busy/capacity/disk (have {refusal['have']} MB, need {refusal['need']} MB); reads served"
    finally:
        e9.close_all(w, t)
        e9.stop(ok)
        e9.stop(tight)


def _fn_addresses(s, n=3):
    fns = s.call("functions", offset=10, limit=40)["functions"]
    fns = [f for f in fns if f["size"] >= 4 and not f["external"] and not f["thunk"]]
    return [(f["name"], int(f["address"].replace("0x", ""), 16), f["size"]) for f in fns[:n]]


def t_symbolize(c):
    exe = e9.fixture_args(c)
    g = c.copy_fixture("trSym")
    d = c.daemon("tr-sym")
    s = None
    try:
        s = c.connect(d, "w", "trace", 3)
        e9.open_view(c, s, g, exe, writable=True)
        fns = _fn_addresses(s)
        dt.check(len(fns) == 3, f"{fns}")
        session = sid("sym")
        o = s.trace_open(session, create=True, program=exe, modules=[exe])
        cap = o["lease"]["cap"]
        sym = o["symbols"]
        dt.check(sym["revision"] == 1 and sym["functions"] > 0, f"{sym}")
        (n0, a0, _), (n1, a1, _), (n2, a2, _) = fns
        events = [
            ev(0, "core.function.enter", va=a0, module=exe),            # the entry
            ev(1, "core.function.enter", va=a1 + 2, module=exe),        # inside a function
            ev(2, "core.function.enter", va=a2, module="other.dll"),   # a module the map is not for
            ev(3, "core.function.enter", va=0x10, module=exe),         # not code
            ev(4, "core.marker"),                                       # no address: not counted
        ]
        ap = s.trace_append(session, cap, events)
        dt.check(ap["symbolized"] == 2 and ap["unresolved"] == 2, f"{ap}")
        # an address inside the executable block but outside every function body keeps a reason
        before = s.trace_info(session)
        seg0 = before["segments"][0]
        rs = s.trace_resymbolize(session, cap, exe, sample=10, modules=[exe])
        dt.check(rs["symbolRevision"] == 2 and rs["events"] == 4 and rs["resolved"] == 2, f"{rs}")
        dt.check(rs["reasons"] == {"module-unknown": 1, "not-code": 1}, f"{rs['reasons']}")
        by_va = {x["va"]: x for x in rs["sample"]}
        dt.check(by_va[a0]["function"] == n0 and by_va[a0]["offset"] == 0, f"{by_va[a0]}")
        dt.check(by_va[a1 + 2]["function"] == n1 and by_va[a1 + 2]["offset"] == 2, f"{by_va[a1 + 2]}")
        dt.check(by_va[0x10]["function"] is None and by_va[0x10]["reason"] == "not-code", f"{by_va[0x10]}")
        dt.check(by_va[a2]["function"] is None and by_va[a2]["reason"] == "module-unknown", f"{by_va[a2]}")
        # the observations did not change; a new interpretation revision appeared
        after = s.trace_info(session)
        dt.check(after["segments"][0] == seg0, "re-symbolization changed the raw segment")
        revs = {x["symbolRevision"]: x["rows"] for x in after["interpretations"]}
        dt.check(revs == {1: 4, 2: 4}, f"{revs}")
        # the program changes: a rename is a new state, so a new revision with the new name
        s.call("rename", address=hex(a0), name="trace_renamed_fn")
        rs3 = s.trace_resymbolize(session, cap, exe, sample=10, modules=[exe])
        dt.check(rs3["symbolRevision"] == 3, f"{rs3}")
        names = {x["va"]: x["function"] for x in rs3["sample"]}
        dt.check(names[a0] == "trace_renamed_fn", f"the rename is not in revision 3: {names}")
        rs4 = s.trace_resymbolize(session, cap, exe, sample=10, modules=[exe])
        dt.check(rs4["symbolRevision"] == 4 and rs4["resolved"] == rs3["resolved"], f"{rs4}")
        old = json.loads((root_of(c) / session / "interp-2.jsonl").read_text().splitlines()[0])
        dt.check(old["function"] == n0, "revision 2 was rewritten by a later revision")
        # no program, no symbolizer
        dt.expect_error("bad_request", s.call, "trace_resymbolize", session=session, cap=cap)
        return f"2 of 4 resolved at revision 1 (not-code and module-unknown kept their reason); rename then revision 3 names {names[a0]}; raw segment unchanged"
    finally:
        e9.close_all(s)
        e9.stop(d)


def t_agent_workload(c):
    agent = _agent()
    if not agent:
        return "skipped: HYDRA_AGENT (the path of hydra-agent.exe) is not set"
    exe = e9.fixture_args(c)
    g = c.copy_fixture("trAgent")
    d = c.daemon("tr-agent")
    session = sid("agent")
    w, cap, _ = writer(c, d, "w", session)
    procs = []
    try:
        w.trace_append(session, cap, [ev(i, "core.resource.open") for i in range(200)])
        w.trace_close(session, cap)
        w2 = c.connect(d, "w2", "trace", 3)
        live = sid("agentlive")
        cap2 = w2.trace_open(live, create=True)["lease"]["cap"]
        rows = []
        for i in range(4):
            spec = {"name": f"trace-agent-{i}", "endpoint": str(Path(str(c.state)) / "tr-agent.json"),
                    "rows": str(c.work / f"trace-agent-{i}.jsonl"),
                    "project": {"name": "fx", "gpr": str(g), "program": "/" + exe},
                    "hot": [], "fresh": [], "reads": [], "harness": "trace-bench",
                    "plan": [{"op": "info"}, {"op": "trace_read", "arg": session},
                             {"op": "trace_read", "arg": live}, {"op": "trace_read", "arg": session}]}
            sp = c.work / f"trace-agent-{i}.json"
            sp.write_text(json.dumps(spec))
            rows.append(Path(spec["rows"]))
            procs.append(subprocess.Popen([agent, "agent", "--spec", str(sp)], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True))
        k = 0
        while any(p.poll() is None for p in procs) and k < 400:
            w2.trace_append(live, cap2, [ev(k * 10 + j) for j in range(10)])
            k += 1
            time.sleep(0.01)
        outs = [p.communicate(timeout=120) for p in procs]
        dt.check(all(p.returncode == 0 for p in procs), f"agent exit codes {[p.returncode for p in procs]}: {outs[0][1][-300:]}")
        done = {}
        for r in rows:
            for ln in r.read_text().splitlines():
                row = json.loads(ln)
                if row["op"].startswith("trace_"):
                    dt.check(row["ok"] is True, f"{row}")
                    done[row["op"]] = done.get(row["op"], 0) + 1
        dt.check(done.get("trace_query") == 8 * 1 + 0 or done.get("trace_query", 0) >= 12, f"{done}")
        shas = {}
        for r in rows:
            for ln in r.read_text().splitlines():
                row = json.loads(ln)
                if row.get("key", "").endswith(f"trace|{session}|page"):
                    shas.setdefault(row["key"], set()).add(row["sha"])
        dt.check(all(len(v) == 1 for v in shas.values()) and shas, f"the closed session's page differs between agents: {shas}")
        st = w.call("status")
        dt.check(blocked(st) == 0, f"a request waited on another: {st['waits']}")
        return f"4 agents x 3 trace_read rounds while a writer appended {k} batches: {done}; one digest per page; foreignBlocked 0"
    finally:
        for p in procs:
            with contextlib.suppress(Exception):
                if p.poll() is None:
                    p.kill()
        e9.close_all(w)
        e9.stop(d)


def _agent():
    p = os.environ.get("HYDRA_AGENT")
    return p if p and Path(p).is_file() else None


def t_client_identity(c):
    agent = _agent()
    if not agent:
        return "skipped: HYDRA_AGENT (the path of hydra-agent.exe) is not set"
    d = c.daemon("tr-ident")
    session, other = sid("ident"), sid("identb")
    py = c.connect(d, "py", "trace", 3)
    lines = record(py)
    proc = None
    try:
        cap = py.trace_open(session, create=True)["lease"]["cap"]
        py.trace_append(session, cap, [ev(i, "core.resource.open", payload={"i": i, "corr": f"c{i % 5}", "key": f"k{i % 3}"})
                                       for i in range(40)])
        cap2 = py.trace_open(other, create=True)["lease"]["cap"]
        py.trace_append(other, cap2, [ev(i) for i in range(10)])
        requests = [
            ("trace_list", {}),
            ("trace_info", {"session": session}),
            ("trace_query", {"session": session, "limit": 7}),
            ("trace_query", {"session": session, "group_by": "resource"}),
            ("trace_query", {"session": session, "limit": 5, "after": 3, "upTo": 30, "kinds": ["core.resource.open"]}),
            ("trace_explain", {"session": session, "event": f"ev_{session}_20", "direction": "downstream"}),
            ("trace_diff", {"session": session, "other": other, "by": "kind"}),
            ("trace_check", {"session": session, "assertion": {"type": "cardinality", "kind": "core.resource.open",
                                                                 "min": 1, "max": 99, "name": "n"}}),
            ("trace_query", {"session": "nope"}),
            ("trace_open", {"session": other, "mode": "read"}),
            ("trace_append", {"session": session, "cap": "wrong", "events": []}),
        ]
        py_lines = []
        for cmd, f in requests:
            try:
                py.call(cmd, **f)
            except Exception as e:  # noqa: BLE001
                if getattr(e, "code", None) is None:
                    raise
            py_lines.append(line_of(lines, py.last_response["id"]))
        ep = Path(str(c.state)) / "tr-ident.json"
        proc = subprocess.Popen([agent, "call", "--endpoint", str(ep), "--keep-raw"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True, encoding="utf-8")
        rs_lines = []
        for cmd, f in requests:
            proc.stdin.write(json.dumps({"cmd": cmd, **f}) + "\n")
            proc.stdin.flush()
            rs_lines.append(_MS.sub("", _ID.sub("{", proc.stdout.readline().rstrip("\r\n"))))
        diff = [(i, requests[i][0]) for i in range(len(requests)) if py_lines[i] != rs_lines[i]]
        if diff:
            dt.check(False, f"Python and Rust replies differ for {diff}: {py_lines[diff[0][0]][:300]} | {rs_lines[diff[0][0]][:300]}")
        return f"{len(requests)} trace requests: reply lines byte-identical between the Python and the Rust client"
    finally:
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.stdin.close()
                proc.wait(10)
        e9.close_all(py)
        e9.stop(d)


TESTS = {
    "trace_basic": t_basic,
    "trace_readers_writer": t_readers_writer,
    "trace_writer_kill": t_writer_kill,
    "trace_lease": t_lease,
    "trace_recovery": t_recovery,
    "trace_cancel": t_cancel,
    "trace_cursor": t_cursor,
    "trace_disk_reserve": t_disk_reserve,
    "trace_symbolize": t_symbolize,
    "trace_agent_workload": t_agent_workload,
    "trace_client_identity": t_client_identity,
}

BASELINE = {}
