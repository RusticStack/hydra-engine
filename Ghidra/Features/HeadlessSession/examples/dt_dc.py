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
"""The decompile cache of unchanged programs (Rust plan goal 4, ``DecompileCache.java``).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only dc_identical,...

* ``dc_identical``: 50 functions of the fixture decompiled by a daemon with the cache off and twice by a
  daemon with it on (the second time from the cache: ``health.decompileCache.hits``); every reply is
  byte-identical to the fresh one, also with a small ``maxChars`` (the cut is made per request).
* ``dc_invalidate``: a rename of a function in a writable view changes the program's modification number;
  the next decompile is a miss and shows the new name, the same text a cache-off daemon gives after the same
  rename; a function the rename did not touch is decompiled again too (its entry was of the older state).
* ``dc_single_flight``: 8 clients ask for the same function at the same moment: one decompile (one miss),
  the other 7 joined it or hit, and all 8 replies are identical.
* ``dc_ab``: 8 concurrent clients decompile the same 50 functions (each from its own offset), two passes, cache
  off and on: wall time of each pass (reported), every reply equal to the reference, and with the cache on at
  most 50 decompiles in all.
"""
import contextlib
import pathlib
import sys
import threading
import time

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent


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
OFF = {"decompileCache": 0}
ON = {"decompileCache": "64MB"}


def _fns(s, n):
    fs = [f for f in s.call("functions", limit=4 * n)["functions"]
          if not f["external"] and not f["thunk"]]
    return [f["address"] for f in fs[:n]]


def _stats(s):
    return s.call("health").get("decompileCache") or {}


def t_identical(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("dcIdA"), c.copy_fixture("dcIdB")
    da, db = c.daemon("dc-id-off", engine=OFF), c.daemon("dc-id-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(da, "a", "dc", 3), c.connect(db, "b", "dc", 3)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        fns = _fns(a, 50)
        dt.check(len(fns) >= 20, f"only {len(fns)} functions in the fixture")
        dt.check(_fns(b, 50) == fns, "the two copies list different functions")
        dt.check(not _stats(a), "a daemon with decompileCache 0 reports a cache")
        fresh = {x: a.call("decompile", address=x) for x in fns}
        first = {x: b.call("decompile", address=x) for x in fns}
        st1 = _stats(b)
        second = {x: b.call("decompile", address=x) for x in fns}
        st2 = _stats(b)
        cut = {x: b.call("decompile", address=x, maxChars=40) for x in fns}
        cut_fresh = {x: a.call("decompile", address=x, maxChars=40) for x in fns}
        done = sum(1 for x in fns if fresh[x].get("completed"))
        dt.check(done >= len(fns) - 2, f"only {done} of {len(fns)} decompiles completed")
        bad = [x for x in fns if first[x] != fresh[x] or second[x] != fresh[x]]
        dt.check(not bad, f"replies differ from a fresh decompile at {bad[:5]}")
        badc = [x for x in fns if cut[x] != cut_fresh[x]]
        dt.check(not badc, f"maxChars replies differ at {badc[:5]}")
        hits = st2.get("hits", 0) - st1.get("hits", 0)
        dt.check(hits >= done, f"the second pass hit {hits} times for {done} completed functions: {st2}")
        dt.check(st2.get("misses") == st1.get("misses"), f"the second pass missed: {st1} -> {st2}")
        return (f"{len(fns)} functions ({done} completed): cached replies byte-identical to fresh ones "
                f"(also maxChars 40); second pass {hits} hits, 0 misses; {st2.get('entries')} entries, "
                f"{st2.get('bytes')} bytes")
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_invalidate(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("dcInvA"), c.copy_fixture("dcInvB")
    da, db = c.daemon("dc-inv-off", engine=OFF), c.daemon("dc-inv-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(da, "a", "dc", 3), c.connect(db, "b", "dc", 3)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        fns = _fns(b, 5)
        x, y = fns[0], fns[1]
        before = b.call("decompile", address=x)
        b.call("decompile", address=y)
        dt.check(b.call("decompile", address=x) == before, "a repeat differs")
        m0 = _stats(b)["misses"]
        for s in (a, b):
            s.call("rename", address=x, name="dc_renamed_fn")
        after = b.call("decompile", address=x)
        m1 = _stats(b)["misses"]
        dt.check(m1 == m0 + 1, f"the decompile after the rename was not a miss ({m0} -> {m1})")
        dt.check(after["name"].endswith("dc_renamed_fn") and "dc_renamed_fn" in after["c"],
                 f"the reply after the rename shows the old function: {after['name']}")
        dt.check(after == a.call("decompile", address=x),
                 "after the rename the cached daemon differs from a cache-off daemon")
        # the other function was cached before the change; after it, it is decompiled again
        b.call("decompile", address=y)
        dt.check(_stats(b)["misses"] == m1 + 1, "a function untouched by the rename was served from "
                 "the entry of the older program state")
        return (f"rename: the next decompile missed and equals the cache-off daemon's reply; the other "
                f"function's older entry was not served; {_stats(b)}")
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_single_flight(c):
    exe = e9.fixture_args(c)
    g = c.copy_fixture("dcSf")
    d = c.daemon("dc-sf", engine=ON)
    ss = []
    try:
        ss = [c.connect(d, f"sf{i}", "dc", 3) for i in range(8)]
        for s in ss:
            e9.open_view(c, s, g, exe)
        fns = _fns(ss[0], 50)
        # the biggest function: its decompile lasts long enough for all 8 to arrive while it runs
        sizes = {f["address"]: f["size"] for f in ss[0].call("functions", limit=400)["functions"]}
        x = max(fns, key=lambda a: sizes.get(a, 0))
        st0 = _stats(ss[0])
        out, go = [None] * 8, threading.Barrier(8)

        def run(i):
            go.wait()
            out[i] = ss[i].call("decompile", address=x)

        ts = [threading.Thread(target=run, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(300)
        st1 = _stats(ss[0])
        misses = st1.get("misses", 0) - st0.get("misses", 0)
        joined = st1.get("joined", 0) - st0.get("joined", 0)
        hits = st1.get("hits", 0) - st0.get("hits", 0)
        dt.check(all(o is not None and o == out[0] for o in out), "the 8 replies differ")
        dt.check(misses == 1, f"8 callers of one function ran {misses} decompiles: {st1}")
        return f"8 simultaneous callers of {x} ({sizes.get(x)} bytes): 1 decompile, {joined} joined, {hits} hits"
    finally:
        e9.close_all(*ss)
        e9.stop(d)


def _ab_round(c, tag, engine, fns_ref=None):
    """Two passes of 8 concurrent clients over the same functions, each client starting at its own
    offset in the list (agents do not march in step): (fns, texts, errors, [wall1, wall2], stats)."""
    exe = e9.fixture_args(c)
    g = c.copy_fixture(f"dcAb{tag}")
    d = c.daemon(f"dc-ab-{tag}", engine=engine)
    ss = []
    try:
        ss = [c.connect(d, f"ab{i}", "dc", 3) for i in range(8)]
        for s in ss:
            e9.open_view(c, s, g, exe)
        fns = fns_ref[0] if fns_ref else _fns(ss[0], 50)
        results, errs, retries, walls = [dict() for _ in range(8)], [], [], []
        for _ in range(2):
            go = threading.Barrier(8)

            def run(i):
                go.wait()
                k = i * len(fns) // 8
                try:
                    for x in fns[k:] + fns[:k]:
                        try:
                            txt = ss[i].call("decompile", address=x)["c"]
                        except c.gs.SessionError as e:
                            # decompiler_failed is retryable by contract ("this request failed alone, retry")
                            if e.code != "decompiler_failed":
                                raise
                            retries.append(f"{x}: {str(e)[:160]}")
                            txt = ss[i].call("decompile", address=x)["c"]
                        if results[i].setdefault(x, txt) != txt:
                            errs.append(f"client {i} got two texts for {x}")
                except Exception as e:  # noqa: BLE001
                    errs.append(repr(e))

            ts = [threading.Thread(target=run, args=(i,)) for i in range(8)]
            t0 = time.perf_counter()
            for t in ts:
                t.start()
            for t in ts:
                t.join(1800)
            walls.append(time.perf_counter() - t0)
        return fns, results, errs, walls, dict(_stats(ss[0]), retries=retries)
    finally:
        e9.close_all(*ss)
        e9.stop(d)


def t_ab(c):
    fns, off, errs_off, w_off, st_off = _ab_round(c, "off", OFF)
    _, on, errs_on, w_on, st = _ab_round(c, "on", ON, (fns,))
    dt.check(not errs_off and not errs_on, f"errors: off {errs_off[:3]} on {errs_on[:3]}")
    ref = off[0]
    dt.check(all(r == ref for r in off + on), "a client got a different text")
    dt.check(st.get("misses", 999) <= len(fns), f"cache on: {st}")
    return (f"8 clients x {len(fns)} functions, 2 passes: cache off {w_off[0]:.2f} s + {w_off[1]:.2f} s "
            f"({16 * len(fns)} decompiles), on {w_on[0]:.2f} s + {w_on[1]:.2f} s ({st.get('misses')} decompiles; "
            f"pass 1 {w_off[0] / max(w_on[0], 1e-9):.1f}x, pass 2 {w_off[1] / max(w_on[1], 1e-9):.1f}x); "
            f"retried decompiler_failed: off {st_off['retries'][:2]} on {st['retries'][:2]}; on: {st}")


TESTS = {
    "dc_identical": t_identical,
    "dc_invalidate": t_invalidate,
    "dc_single_flight": t_single_flight,
    "dc_ab": t_ab,
}

BASELINE = {}
