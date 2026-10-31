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
"""Sealed results of pure read scripts (``ScriptResults.java``).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only sr_results,sr_invalidate

The probe script counts its runs in a system property and prints the count with the first function's name, so a
repeat answered from the stored output shows the old count and a run shows a new one.

* ``sr_results``: a ``pure`` script by a client that does not write the program is run once and then answered from
  its stored output (same count, same reply fields as a run, ``health.scriptResults.hits``); without ``pure``,
  for other arguments, with an argument naming a file (``@...``) and for the program's writer it runs every time;
  8 clients asking the same new request at once run it once.
* ``sr_invalidate``: after the writer renames the first function the same request runs again and shows the new
  name (never the stored one), and is stored again for the new state.
"""
import concurrent.futures
import sys
import time

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

PROBE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
public class SrProbe extends GhidraScript {
    @Override protected void run() throws Exception {
        long n = Long.getLong("sr.runs", 0) + 1;
        System.setProperty("sr.runs", Long.toString(n));
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctions(true).next();
        println("probe " + String.join(",", getScriptArgs()) + " run=" + n + " first=" + f.getName()
            + " count=" + fm.getFunctionCount());
    }
}
"""


def _sr(s):
    return s.call("health").get("scriptResults") or {}


def _run(s, path, *args, pure=True):
    extra = {"pure": True} if pure else {}
    return s.call("script", script=str(path), args=list(args), timeout=60, wait=120000, **extra)


def _runs(r):
    return int(r["output"].split("run=")[1].split()[0])


def _shape(r):
    """The reply without the fields that differ between two requests by nature."""
    return {k: v for k, v in r.items() if k not in ("seconds", "output", "chars", "ms", "id")}


def _open_reader(c, d, name, g, exe):
    s = c.connect(d, name, "sr", 3)
    s.call("open_project", path=str(g), writable=False)
    s.call("open_program", path=exe, writable=False)
    return s


def t_results(c):
    exe = e9.fixture_args(c)
    g = c.copy_fixture("srRes")
    path = c.scripts / "SrProbe.java"
    path.write_text(PROBE)
    d = c.daemon("sr-res")
    w = r = None
    readers = []
    try:
        r = _open_reader(c, d, "r", g, exe)
        a = _run(r, path, "one")
        st1 = _sr(r)
        b = _run(r, path, "one")
        st2 = _sr(r)
        dt.check(a["output"] == b["output"] and _runs(a) == _runs(b),
                 f"the repeat was run again, not answered from the stored output: {a['output']!r} / {b['output']!r}")
        dt.check(st2.get("hits", 0) == st1.get("hits", 0) + 1, f"the repeat was not a hit: {st1} -> {st2}")
        dt.check(_shape(a) == _shape(b), f"a hit's fields differ from a run's: {_shape(a)} / {_shape(b)}")
        dt.check(a["mode"] == "contained" and a["changed"] is False, f"unexpected mode/changed: {a}")
        # not pure: always run
        x, y = _run(r, path, "one", pure=False), _run(r, path, "one", pure=False)
        dt.check(_runs(y) == _runs(x) + 1 and _runs(x) > _runs(b), f"a request without pure was stored: {x} / {y}")
        # another argument is another request
        z = _run(r, path, "two")
        dt.check("probe two " in z["output"] and _runs(z) > _runs(y), f"other arguments were answered from 'one': {z}")
        # a file argument is read by the script: never stored
        f1, f2 = _run(r, path, "@none"), _run(r, path, "@none")
        dt.check(_runs(f2) == _runs(f1) + 1, f"an argument naming a file was stored: {f1} / {f2}")
        # the same request at once: one run
        before = _runs(_run(r, path, "probe-count", pure=False))
        readers = [_open_reader(c, d, f"p{i}", g, exe) for i in range(8)]
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            outs = list(ex.map(lambda s: _run(s, path, "par")["output"], readers))
        after = _runs(_run(r, path, "probe-count2", pure=False))
        dt.check(len(set(outs)) == 1, f"parallel callers of one request got different outputs: {outs}")
        dt.check(after - before == 2, f"8 callers of one request ran it {after - before - 1} times, not once")
        st = _sr(r)
        return f"stored run answered {st.get('hits')} times with a run's fields; not-pure, other-args, @file always run; 8 at once ran once ({st})"
    finally:
        e9.close_all(r, w, *readers)
        e9.stop(d)
        with __import__("contextlib").suppress(OSError):
            path.unlink()


def t_invalidate(c):
    exe = e9.fixture_args(c)
    g = c.copy_fixture("srInv")
    path = c.scripts / "SrProbe.java"
    path.write_text(PROBE)
    d = c.daemon("sr-inv")
    w = r = None
    try:
        w = c.connect(d, "w", "sr", 3)
        e9.open_view(c, w, g, exe, writable=True)
        r = c.connect(d, "r", "sr", 3)
        r.call("open_project", path=str(g), writable=False)
        r.call("open_program", path=exe, writable=False)
        a = _run(r, path, "inv")
        b = _run(r, path, "inv")
        dt.check(_runs(a) == _runs(b), f"no hit before the rename: {a['output']!r} / {b['output']!r}")
        first = a["output"].split("first=")[1].split()[0]
        addr = w.call("functions", limit=1)["functions"][0]["address"]
        w.call("rename", address=addr, name="sr_renamed_first")
        c1 = _run(r, path, "inv")
        dt.check("sr_renamed_first" in c1["output"] and first not in c1["output"].split("first=")[1].split()[0],
                 f"after the rename the stored output was served: {c1['output']!r}")
        dt.check(_runs(c1) > _runs(b), f"the request was not run again after the rename: {c1}")
        c2 = _run(r, path, "inv")
        dt.check(_runs(c2) == _runs(c1), f"the new state's output was not stored: {c1['output']!r} / {c2['output']!r}")
        # the writer itself is never answered from a stored output
        w1, w2 = _run(w, path, "owner"), _run(w, path, "owner")
        dt.check(_runs(w2) == _runs(w1) + 1 and w1["mode"] == "owner", f"the owner was served a stored output: {w1} / {w2}")
        return f"rename -> run again with the new name ({first} -> sr_renamed_first), stored again; owner always runs; {_sr(r)}"
    finally:
        e9.close_all(w, r)
        e9.stop(d)
        with __import__("contextlib").suppress(OSError):
            path.unlink()


TESTS = {
    "sr_results": t_results,
    "sr_invalidate": t_invalidate,
}

BASELINE = {}
