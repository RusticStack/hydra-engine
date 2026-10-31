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

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only da_script_cache,...

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
ON = {}

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
}

BASELINE = {}
