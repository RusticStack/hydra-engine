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
"""The callback-free decompile backend (Rust plan goal 1, step 6: ``HostDecompiler.java`` and the
snapshot Architecture of ``hydra-decomp-host``), switched on with ``-Dhydra.decomp.backend=host``
(default off). Runs are submitted asynchronously (bounded queue, one completion thread) unless
``-Dhydra.decomp.host.async=false``.

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only host_identical,...

* ``host_identical``: 50 functions of the fixture decompiled by a daemon with the host backend and by one
  without (the decompile process): every reply is byte-identical, also with a small ``maxChars``; the
  backend hosted some of them (``status.decompileBackend.hostedCount`` > 0) and every function is counted
  once as hosted or as fallen back.
* ``host_invalidate``: a rename in a writable view starts a new program generation: the next decompile
  shows the new name and equals the process daemon's reply after the same rename.
* ``host_concurrent``: 8 clients decompile the same 30 functions at once on the host daemon: every reply
  equals the process daemon's.
* ``host_default``: a daemon with no settings reports no backend; with ``-Dhydra.decomp.backend=host`` it
  runs the host with asynchronous submission (the default submission), replies equal to the process.
* ``host_concurrent_blocking``: ``host_concurrent`` with ``-Dhydra.decomp.host.async=false`` (the step 6
  path: one platform thread per request, blocking downcall).
"""
import pathlib
import sys
import threading

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
ENGINE = {"decompileCache": 0}
HOST = ["-Dhydra.decomp.backend=host"]
PROC = []                                   # the default: the decompile process


def _fns(s, n):
    fs = [f for f in s.call("functions", limit=4 * n)["functions"]
          if not f["external"] and not f["thunk"]]
    return [f["address"] for f in fs[:n]]


def _backend(s):
    return s.call("status").get("decompileBackend") or {}


def _pair(c, tag, writable=False, host=None):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture(f"host{tag}A"), c.copy_fixture(f"host{tag}B")
    da = c.daemon(f"host-{tag}-proc", engine=ENGINE, vmargs=PROC)
    db = c.daemon(f"host-{tag}-host", engine=ENGINE, vmargs=HOST if host is None else host)
    return exe, ga, gb, da, db


def t_identical(c):
    exe, ga, gb, da, db = _pair(c, "id")
    a = b = None
    try:
        a, b = c.connect(da, "a", "host", 3), c.connect(db, "b", "host", 3)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        dt.check(not _backend(a), "a daemon without the host backend reports one")
        fns = _fns(a, 50)
        dt.check(len(fns) >= 20, f"only {len(fns)} functions in the fixture")
        dt.check(_fns(b, 50) == fns, "the two copies list different functions")
        proc = {x: a.call("decompile", address=x) for x in fns}
        host = {x: b.call("decompile", address=x) for x in fns}
        bad = [x for x in fns if proc[x] != host[x]]
        dt.check(not bad, f"host replies differ from the process at {bad[:5]}")
        cut_p = {x: a.call("decompile", address=x, maxChars=40) for x in fns}
        cut_h = {x: b.call("decompile", address=x, maxChars=40) for x in fns}
        badc = [x for x in fns if cut_p[x] != cut_h[x]]
        dt.check(not badc, f"maxChars replies differ at {badc[:5]}")
        st = _backend(b)
        dt.check(st.get("backend") == "host", f"status.decompileBackend: {st}")
        dt.check(st.get("hostedCount", 0) > 0, f"nothing was hosted: {st}")
        dt.check(st.get("hostedCount", 0) + st.get("fallbackCount", 0) == 2 * len(fns),
                 f"not every decompile was counted once: {st}")
        return (f"{len(fns)} functions x2 (also maxChars 40) byte-identical to the process; hosted "
                f"{st.get('hostedCount')}, fell back {st.get('fallbackCount')} "
                f"({(st.get('host') or {}).get('fallbackReasons')})")
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_invalidate(c):
    exe, ga, gb, da, db = _pair(c, "inv")
    a = b = None
    try:
        a, b = c.connect(da, "a", "host", 3), c.connect(db, "b", "host", 3)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        fns = _fns(b, 5)
        x, y = fns[0], fns[1]
        dt.check(b.call("decompile", address=x) == a.call("decompile", address=x), "first replies differ")
        b.call("decompile", address=y)
        for s in (a, b):
            s.call("rename", address=x, name="host_renamed_fn")
        after = b.call("decompile", address=x)
        dt.check(after["name"].endswith("host_renamed_fn") and "host_renamed_fn" in after["c"],
                 f"the reply after the rename shows the old function: {after['name']}")
        dt.check(after == a.call("decompile", address=x), "after the rename the host differs from the process")
        dt.check(b.call("decompile", address=y) == a.call("decompile", address=y),
                 "a function untouched by the rename differs after it")
        return f"rename: new generation, replies equal the process daemon's; {_backend(b)}"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_concurrent(c, tag="cc", host=None, submission="async"):
    exe, ga, gb, da, db = _pair(c, tag, host=host)
    a = None
    ss = []
    try:
        a = c.connect(da, "a", "host", 3)
        e9.open_view(c, a, ga, exe)
        fns = _fns(a, 30)
        ref = {x: a.call("decompile", address=x) for x in fns}
        ss = [c.connect(db, f"h{i}", "host", 3) for i in range(8)]
        for s in ss:
            e9.open_view(c, s, gb, exe)
        out = [None] * 8
        go = threading.Barrier(8)

        def run(i):
            go.wait()
            order = fns[i:] + fns[:i]
            out[i] = {x: ss[i].call("decompile", address=x) for x in order}

        ts = [threading.Thread(target=run, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(600)
        dt.check(all(o is not None for o in out), "a client did not finish")
        bad = sorted({x for o in out for x in fns if o[x] != ref[x]})
        dt.check(not bad, f"concurrent host replies differ from the process at {bad[:5]}")
        st = _backend(ss[0])
        dt.check(st.get("hostedCount", 0) > 0, f"nothing was hosted: {st}")
        sub = (st.get("host") or {}).get("submission")
        dt.check(sub == submission, f"submission {sub}, expected {submission}")
        return (f"{submission}: 8 clients x {len(fns)} functions equal the process; hosted {st.get('hostedCount')}, "
                f"fell back {st.get('fallbackCount')}")
    finally:
        e9.close_all(a, *ss)
        e9.stop(da)
        e9.stop(db)


def t_default(c):
    exe, ga, gb, da, db = _pair(c, "def")
    a = b = None
    try:
        a, b = c.connect(da, "a", "host", 3), c.connect(db, "b", "host", 3)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        dt.check(not _backend(a), "a daemon with no settings reports a decompile backend")
        fns = _fns(b, 5)
        dt.check(all(b.call("decompile", address=x) == a.call("decompile", address=x) for x in fns),
                 "default replies differ from the process path")
        st = _backend(b)
        dt.check(st.get("backend") == "host", f"-Dhydra.decomp.backend=host has no host backend: {st}")
        host = st.get("host") or {}
        dt.check(host.get("submission") == "async", f"the default submission is not async: {host}")
        dt.check(st.get("hostedCount", 0) > 0, f"nothing was hosted: {st}")
        return f"default off; host on: async submission; hosted {st.get('hostedCount')} of {len(fns)}"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_concurrent_blocking(c):
    return t_concurrent(c, "ccb", HOST + ["-Dhydra.decomp.host.async=false"], "blocking")


TESTS = {
    "host_default": t_default,
    "host_concurrent_blocking": t_concurrent_blocking,
    "host_identical": t_identical,
    "host_invalidate": t_invalidate,
    "host_concurrent": t_concurrent,
}
