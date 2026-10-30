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
"""The function table of a program state (Rust plan hotspot H1, ``FunctionTable.java``).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only ft_identical,...

* ``ft_identical``: every page of ``functions`` (offsets 0..past the end, limits 1..10000, ``regex``,
  ``contains``, both, filters that match nothing) from a daemon with the table off and twice from a daemon with
  it on (the first listing of the state is a walk, the rest come from one table: ``health.functionTable``);
  every reply byte-identical.
* ``ft_invalidate``: a rename and a function created in a writable view change the program's modification
  number; the next listings show the new name / the new function, the same pages a table-off daemon gives.
* ``ft_single_flight``: 8 clients page through the same program at the same moment: one table build, all
  replies equal to the table-off reference.
"""
import json
import sys
import threading

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
OFF = {"functionTable": 0}
ON = {"functionTable": "16MB"}


def _stats(s):
    return s.call("health").get("functionTable") or {}


def _canon(r):
    # the reply as the client received it, in its order (a reordered or retyped field differs)
    return json.dumps(r, sort_keys=False, separators=(",", ":"))


def _queries(total, names):
    qs = []
    for lim in (1, 7, 200, 1000, 10000):
        for off in sorted({0, 1, lim, total - 1, total, total + 5, max(0, total - lim), total // 2}):
            if off >= 0:
                qs.append({"offset": off, "limit": lim})
    some = names[len(names) // 3] if names else "x"
    frag = some[: max(1, len(some) // 2)]
    for flt in ({"contains": "FUN_"}, {"contains": frag}, {"regex": "^FUN_.*[0-9a-f]{2}$"},
                {"regex": "(?i)" + frag}, {"regex": "thunk|entry", "contains": "e"},
                {"contains": "no_such_name_ft"}, {"regex": "^$"}):
        for off, lim in ((0, 200), (0, 3), (2, 3), (10, 50), (100000, 5)):
            qs.append(dict(flt, offset=off, limit=lim))
    qs.append({})                        # the defaults
    qs.append({"limit": 5})
    qs.append({"offset": 3})
    return qs


def _total(s):
    return len(s.call("functions", limit=10000)["functions"])


def t_identical(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("ftIdA"), c.copy_fixture("ftIdB")
    da, db = c.daemon("ft-id-off", engine=OFF), c.daemon("ft-id-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(da, "a", "ft", 3), c.connect(db, "b", "ft", 3)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        dt.check(not _stats(a), "a daemon with functionTable 0 reports a table")
        whole = a.call("functions", limit=10000)["functions"]
        total = len(whole)
        dt.check(total >= 20, f"only {total} functions in the fixture")
        qs = _queries(total, [f["name"] for f in whole])
        ref = [_canon(a.call("functions", **q)) for q in qs]
        first = [_canon(b.call("functions", **q)) for q in qs]
        st1 = _stats(b)
        second = [_canon(b.call("functions", **q)) for q in qs]
        st2 = _stats(b)
        bad = [qs[i] for i in range(len(qs)) if first[i] != ref[i] or second[i] != ref[i]]
        dt.check(not bad, f"{len(bad)} replies differ from the walk, e.g. {bad[:3]}")
        dt.check(st1.get("builds") == 1, f"one program state built {st1.get('builds')} tables: {st1}")
        dt.check(st2.get("builds") == 1 and st2.get("hits", 0) - st1.get("hits", 0) == len(qs),
                 f"the second pass was not served from the table: {st1} -> {st2}")
        return (f"{len(qs)} listings of {total} functions (offsets, limits, regex, contains): byte-identical "
                f"to the walk on both passes; 1 build, {st2.get('hits')} hits; {st2.get('bytes')} bytes")
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_invalidate(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("ftInvA"), c.copy_fixture("ftInvB")
    da, db = c.daemon("ft-inv-off", engine=OFF), c.daemon("ft-inv-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(da, "a", "ft", 3), c.connect(db, "b", "ft", 3)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        pages = [{"offset": 0, "limit": 1000}, {"offset": 5, "limit": 10}, {"contains": "ft_renamed"},
                 {"regex": "ft_renamed_fn$", "offset": 0, "limit": 5}]
        for q in pages:
            b.call("functions", **q)
        b0 = _stats(b).get("builds", 0)
        dt.check(b0 >= 1, f"no table was built: {_stats(b)}")
        x = b.call("functions", offset=3, limit=1)["functions"][0]["address"]
        for s in (a, b):
            s.call("rename", address=x, name="ft_renamed_fn")
        got = [_canon(b.call("functions", **q)) for q in pages]
        want = [_canon(a.call("functions", **q)) for q in pages]
        dt.check(got == want, "after the rename the table daemon lists differently from the walk")
        row = b.call("functions", offset=3, limit=1)["functions"][0]
        dt.check(row["name"].endswith("ft_renamed_fn"), f"the listing after the rename shows {row}")
        dt.check(b.call("functions", contains="ft_renamed")["returned"] == 1,
                 "contains finds no renamed function after the rename")
        st = _stats(b)
        dt.check(st.get("builds", 0) > b0, f"the rename did not lead to a new table: {st}")
        # a second change, then a deep page first (built at once, never the older state)
        for s in (a, b):
            s.call("rename", address=x, name="ft_renamed_again")
        g2 = _canon(b.call("functions", offset=2, limit=3))
        dt.check(g2 == _canon(a.call("functions", offset=2, limit=3)) and "ft_renamed_again" in g2,
                 f"a deep page after the second rename differs or is stale: {g2[:300]}")
        return f"rename x2: the next listings equal the walk's, the older table was never served; {_stats(b)}"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_single_flight(c):
    exe = e9.fixture_args(c)
    gr, g = c.copy_fixture("ftSfRef"), c.copy_fixture("ftSf")
    dr, d = c.daemon("ft-sf-off", engine=OFF), c.daemon("ft-sf", engine=ON)
    r, ss = None, []
    try:
        r = c.connect(dr, "ref", "ft", 3)
        e9.open_view(c, r, gr, exe)
        total = _total(r)
        step = max(1, total // 6)
        offs = list(range(0, total + step, step))
        ref = {o: _canon(r.call("functions", offset=o, limit=step)) for o in offs}
        ss = [c.connect(d, f"sf{i}", "ft", 3) for i in range(8)]
        for s in ss:
            e9.open_view(c, s, g, exe)
        out, go = [None] * 8, threading.Barrier(8)

        def run(i):
            go.wait()
            # every client pages from its own place (agents do not march in step); none starts at 0
            mine = offs[1 + i % (len(offs) - 1):] + offs[:1 + i % (len(offs) - 1)]
            out[i] = {o: _canon(ss[i].call("functions", offset=o, limit=step)) for o in mine}

        ts = [threading.Thread(target=run, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(300)
        st = _stats(ss[0])
        dt.check(all(o == ref for o in out), "a concurrent listing differs from the reference walk")
        dt.check(st.get("builds") == 1, f"8 concurrent clients of one state built {st.get('builds')} tables: {st}")
        return f"8 clients x {len(offs)} pages of {total} functions at once: 1 build, all equal the walk; {st}"
    finally:
        e9.close_all(r, *ss)
        e9.stop(dr)
        e9.stop(d)


TESTS = {
    "ft_identical": t_identical,
    "ft_invalidate": t_invalidate,
    "ft_single_flight": t_single_flight,
}

BASELINE = {}
