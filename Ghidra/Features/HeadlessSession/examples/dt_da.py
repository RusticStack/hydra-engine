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
"""The daemon request path for many agents (Hydra rust/t-daemon-async).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only da_fn_index,...

* ``da_fn_index``: the ``functions`` listing served from the shared per-program index
  (``FunctionIndex.java``) is identical to the listing read from the database (``-set
  functionIndex=false``) for every page shape (offset/limit pages to past the end, ``regex``, ``contains``,
  both at once, a filter that matches nothing), and 8 clients paging at once build the index once
  (``health.functionIndex.builds``); a daemon with the setting off reports no builds.
* ``da_fn_index_invalidate``: the first page after an edit is read from the database (no build, the stale
  index is dropped: ``rows`` 0); after a rename (and after a plate comment, which does not change the listing
  but does change the program) in a writable view the next listing shows the new name, equal to the
  database daemon's listing after the same rename: the index of the older program state is never served.
* ``da_script_cache``: a Java script run again from an unchanged source bundle is instantiated from its kept
  class (``health.scriptClasses.hits``) with output identical to a daemon with ``-set
  scriptClassCache=false``; after its source is edited the next run prints the new text on both daemons
  (the kept class is stale and loaded again); 8 clients running it at once all get the same output.
* ``da_script_cache_dep``: a script that imports another script directory's package (``@importpackage``)
  prints the dependency's new text after the dependency is edited, as with the cache off.
"""
import concurrent.futures
import pathlib
import sys

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
OFF = {"functionIndex": "false"}
ON = {}

#: (offset, limit, filters) shapes compared between the two daemons
SHAPES = [
    (0, 200, {}), (0, 1, {}), (3, 7, {}), (0, 10000, {}), (50, 25, {}), (99999, 10, {}),
    (0, 50, {"regex": "^FUN_"}), (5, 5, {"regex": "[0-9]$"}), (0, 20, {"contains": "_1"}),
    (2, 3, {"regex": "FUN", "contains": "0"}), (0, 10, {"regex": "^no_such_function_zz$"}),
    (0, 10, {"contains": "entry"}),
]


def _stats(s):
    return s.call("health").get("functionIndex") or {}


def _pages(s, total, limit):
    out, off = [], 0
    while True:
        r = s.call("functions", offset=off, limit=limit)
        out.append(r)
        off += limit
        if not r["truncated"]:
            break
        dt.check(off <= total + limit, f"paging did not end at {off}")
    return out


def _listing(s):
    return [(r["offset"], r["returned"], r["truncated"], r["functions"])
            for r in [s.call("functions", offset=o, limit=l, **f) for o, l, f in SHAPES]]


def t_fn_index(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("daFiA"), c.copy_fixture("daFiB")
    da, db = c.daemon("da-fi-off", engine=OFF), c.daemon("da-fi-on", engine=ON)
    a = b = None
    clients = []
    try:
        a, b = c.connect(da, "a", "da", 3), c.connect(db, "b", "da", 3)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        la, lb = _listing(a), _listing(b)
        bad = [SHAPES[i] for i in range(len(SHAPES)) if la[i] != lb[i]]
        dt.check(not bad, f"the indexed listing differs from the database listing for {bad}")
        total = len(a.call("functions", limit=10000)["functions"])
        dt.check(total >= 20, f"only {total} functions in the fixture")
        dt.check(_pages(a, total, 7) == _pages(b, total, 7), "paging 7 at a time differs")
        st_off = _stats(a)
        dt.check(st_off.get("builds", 0) == 0, f"a daemon with functionIndex=false built an index: {st_off}")
        st0 = _stats(b)
        dt.check(st0.get("builds") == 1, f"one program state was indexed {st0.get('builds')} times: {st0}")
        # 8 clients page the program at once: no new build (the state did not change), all equal
        for i in range(8):
            s = c.connect(db, f"p{i}", "da", 3)
            clients.append(s)
            e9.open_view(c, s, gb, exe)
        ref = _pages(a, total, 11)
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            got = list(ex.map(lambda s: _pages(s, total, 11), clients))
        dt.check(all(g == ref for g in got), "a concurrent client's pages differ from the database listing")
        st1 = _stats(b)
        dt.check(st1.get("builds") == 1, f"concurrent paging rebuilt the index: {st0} -> {st1}")
        dt.check(st1.get("hits", 0) > st0.get("hits", 0), f"no hits: {st1}")
        return (f"{total} functions; {len(SHAPES)} page shapes and paging 7 at a time identical to the database "
                f"listing; 8 concurrent pagers equal; 1 build, {st1.get('hits')} hits")
    finally:
        e9.close_all(a, b, *clients)
        e9.stop(da)
        e9.stop(db)


def t_fn_index_invalidate(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("daFvA"), c.copy_fixture("daFvB")
    da, db = c.daemon("da-fv-off", engine=OFF), c.daemon("da-fv-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(da, "a", "da", 3), c.connect(db, "b", "da", 3)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        fs = [f for f in b.call("functions", limit=50)["functions"] if not f["thunk"]]
        x = fs[3]["address"]
        dt.check(_listing(a) == _listing(b), "the listings differ before the edits")
        builds0 = _stats(b)["builds"]
        for s in (a, b):
            s.call("rename", address=x, name="da_renamed_fn")
        after = b.call("functions", limit=50)["functions"]
        st_first = _stats(b)
        # the first page of the new state is read from the database: no build, the stale index dropped
        dt.check(st_first["builds"] == builds0 and st_first.get("rows") == 0,
                 f"the first page after the rename built an index or kept the stale one: {st_first}")
        dt.check(any(f["address"] == x and f["name"].endswith("da_renamed_fn") for f in after),
                 f"the listing after the rename shows the old name at {x}")
        dt.check(_listing(a) == _listing(b), "after the rename the indexed listing differs from the database's")
        dt.check(_stats(b)["builds"] == builds0 + 1, f"the rename did not rebuild the index: {_stats(b)}")
        for s in (a, b):
            s.call("comment", address=x, type="plate", text="da plate")
        dt.check(_listing(a) == _listing(b), "after the comment the indexed listing differs from the database's")
        dt.check(_stats(b)["builds"] == builds0 + 2, f"the comment did not rebuild the index: {_stats(b)}")
        return f"rename and comment: each rebuilt the index once; listings equal to the database's ({_stats(b)})"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


PROBE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class DaCacheProbe extends GhidraScript {
    @Override protected void run() throws Exception {
        println("%s " + String.join(",", getScriptArgs()));
    }
}
"""


def _out(r):
    return r.get("output")


def _sc(s):
    return s.call("health").get("scriptClasses") or {}


def t_script_cache(c):
    import time
    e9.fixture_args(c)
    path = c.scripts / "DaCacheProbe.java"
    path.write_text(PROBE % "probe-v1")
    da, db = c.daemon("da-sc-off", engine={"scriptClassCache": "false"}), c.daemon("da-sc-on", engine=ON)
    a = b = None
    clients = []
    try:
        a, b = c.connect(da, "a", "da", 3), c.connect(db, "b", "da", 3)

        def run(s, *args):
            return s.call("script", script=str(path), program=None, args=list(args), wait=120000)

        ra1, rb1 = run(a, "x"), run(b, "x")
        st1 = _sc(b)
        ra2, rb2 = run(a, "y", "z"), run(b, "y", "z")
        st2 = _sc(b)
        dt.check("probe-v1 x" in _out(rb1) and _out(ra1) == _out(rb1), f"first runs differ: {ra1} / {rb1}")
        dt.check("probe-v1 y,z" in _out(rb2) and _out(ra2) == _out(rb2), f"second runs differ: {ra2} / {rb2}")
        dt.check(st2.get("hits", 0) == st1.get("hits", 0) + 1, f"the second run was not a hit: {st1} -> {st2}")
        dt.check(not _sc(a).get("hits"), f"a daemon with scriptClassCache=false hit: {_sc(a)}")
        time.sleep(1.1)  # a new modification time on any file system
        path.write_text(PROBE % "probe-v2-edited")
        ra3, rb3 = run(a, "w"), run(b, "w")
        st3 = _sc(b)
        dt.check("probe-v2-edited w" in _out(rb3) and _out(ra3) == _out(rb3),
                 f"after the edit the runs differ or show the old text: {ra3} / {rb3}")
        dt.check(st3.get("stale", 0) == st2.get("stale", 0) + 1, f"the edit did not make the class stale: {st3}")
        rb4 = run(b, "v")
        dt.check("probe-v2-edited v" in _out(rb4), f"the run after the reload shows {rb4}")
        dt.check(_sc(b).get("hits") == st3.get("hits", 0) + 1, f"the reloaded class was not kept: {_sc(b)}")
        for i in range(8):
            clients.append(c.connect(db, f"p{i}", "da", 3))
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            outs = list(ex.map(lambda s: _out(run(s, "par")), clients))
        dt.check(all(o == outs[0] and "probe-v2-edited par" in o for o in outs), f"parallel runs differ: {outs}")
        return f"kept class hits with identical output; edit -> stale + reload; 8 parallel runs equal ({_sc(b)})"
    finally:
        e9.close_all(a, b, *clients)
        e9.stop(da)
        e9.stop(db)
        with __import__("contextlib").suppress(OSError):
            path.unlink()


DEP_LIB = """package dalib;
public class DaLib {
    public static String v() { return "%s"; }
}
"""

DEP_SCRIPT = """// @category HeadlessSession.Test
// @importpackage dalib
import ghidra.app.script.GhidraScript;
import dalib.DaLib;
public class DaDepProbe extends GhidraScript {
    @Override protected void run() throws Exception {
        println("dep " + DaLib.v());
    }
}
"""


def t_script_cache_dep(c):
    """A script whose bundle imports another script directory's package (``@importpackage``): after the
    dependency's source is edited the next run prints the dependency's new text, equal to a daemon with
    ``scriptClassCache=false`` (the kept-class path would skip the activation that rebuilds the dependency,
    so such a bundle is never kept)."""
    import time
    e9.fixture_args(c)
    lib = c.work / "da-dep-lib"
    sdir = c.work / "da-dep-scripts"
    (lib / "dalib").mkdir(parents=True, exist_ok=True)
    sdir.mkdir(parents=True, exist_ok=True)
    libf = lib / "dalib" / "DaLib.java"
    libf.write_text(DEP_LIB % "lib-v1")
    path = sdir / "DaDepProbe.java"
    path.write_text(DEP_SCRIPT)
    sp = [str(c.scripts), str(lib), str(sdir)]
    da = c.daemon("da-dep-off", engine={"scriptClassCache": "false"}, scriptPath=sp)
    db = c.daemon("da-dep-on", engine=ON, scriptPath=sp)
    a = b = None
    try:
        a, b = c.connect(da, "a", "da", 3), c.connect(db, "b", "da", 3)

        def run(s):
            return _out(s.call("script", script=str(path), program=None, args=[], wait=120000))

        oa1, ob1 = run(a), run(b)
        ob2 = run(b)
        dt.check("dep lib-v1" in ob1 and oa1 == ob1 == ob2, f"first runs differ: {oa1} / {ob1} / {ob2}")
        time.sleep(1.1)  # a new modification time on any file system
        libf.write_text(DEP_LIB % "lib-v2-edited")
        oa3, ob3 = run(a), run(b)
        dt.check("dep lib-v2-edited" in oa3, f"the cache-off daemon did not pick up the dependency edit: {oa3}")
        dt.check(oa3 == ob3, f"after the dependency edit the cached daemon prints {ob3!r}, the full path {oa3!r}")
        return f"dependency edit seen by both daemons ({_sc(b)})"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


TESTS = {
    "da_script_cache": t_script_cache,
    "da_script_cache_dep": t_script_cache_dep,
    "da_fn_index": t_fn_index,
    "da_fn_index_invalidate": t_fn_index_invalidate,
}

BASELINE = {}
