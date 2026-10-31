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
"""The Rust read plane (``ReadPlane.java``, ``hydra_native`` ``readplane.rs``): ``functions`` pages rendered in Rust.

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only rp_bytes,rp_invalidate

* ``rp_bytes``: every query of ``ft_identical`` (offsets, limits, ``contains``, ``regex``, defaults), sent to a
  daemon with ``readPlane=false`` and twice to one with the read plane on; the reply LINES as they arrive on the
  socket (only ``"ms"`` taken out) are byte-identical, and ``health.readPlane`` shows the pages came from Rust.
* ``rp_invalidate``: in a writable view, a rename changes the program state; the lines after it are those of the
  Java path, and the renamed function is listed (a stale Rust table would show the old name).
"""
import re
import sys
import time

import daemon_tests as dt

from pathlib import Path

HERE = Path(__file__).resolve().parent

SLEEP = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class RpSleep extends GhidraScript {
    @Override protected void run() throws Exception { Thread.sleep(Long.parseLong(getScriptArgs()[0])); }
}
"""


def _dc(s):
    return s.call("health").get("decompileCache") or {}


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
ft = _mod("dt_ft")
JAVA = {"functionTable": "16MB", "readPlane": "false"}
RUST = {"functionTable": "16MB"}
_MS = re.compile(r',"ms":\d+')


def _record(s):
    """Keeps every raw line the client reads (the reply bytes before json.loads)."""
    lines = []
    orig = s._recv

    def rec(*a, **k):
        line = orig(*a, **k)
        if line:
            lines.append(line)
        return line

    s._recv = rec
    return lines


def _line(lines, rid):
    for ln in reversed(lines):
        if ln.startswith('{"id":%d,' % rid):
            return _MS.sub("", ln.rstrip("\r\n"))
    raise AssertionError(f"no reply line for id {rid}")


def _rp(s):
    return s.call("health").get("readPlane") or {}


def _raw_calls(s, lines, qs):
    out = []
    for q in qs:
        s.call("functions", **q)
        rid = s.last_response.get("id")
        out.append(_line(lines, rid))
    return out


def t_bytes(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("rpA"), c.copy_fixture("rpB")
    da, db = c.daemon("rp-java", engine=JAVA), c.daemon("rp-rust", engine=RUST)
    a = b = None
    try:
        a, b = c.connect(da, "a", "rp", 3), c.connect(db, "a", "rp", 3)
        la, lb = _record(a), _record(b)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        dt.check(_rp(a).get("enabled") is not True, f"readPlane=false still reports the read plane: {_rp(a)}")
        whole = a.call("functions", limit=10000)["functions"]
        b.call("functions", limit=10000)
        total = len(whole)
        qs = ft._queries(total, [f["name"] for f in whole])
        # the same request ids on both sides: the lines must match whole, id included
        ref = _raw_calls(a, la, qs)
        p0 = _rp(b).get("pages", 0)
        first = _raw_calls(b, lb, qs)
        second = _raw_calls(b, lb, qs)
        ref2 = _raw_calls(a, la, qs)
        st = _rp(b)
        strip_id = re.compile(r'^\{"id":\d+,')
        bad = [qs[i] for i in range(len(qs))
               if strip_id.sub("", first[i]) != strip_id.sub("", ref[i])
               or strip_id.sub("", second[i]) != strip_id.sub("", ref2[i])]
        dt.check(not bad, f"{len(bad)} reply lines differ from the Java path, e.g. {bad[:3]}")
        served = st.get("pages", 0) - p0
        no_regex = sum(1 for q in qs if "regex" not in q)
        dt.check(st.get("enabled") is True and served >= no_regex,
                 f"only {served} of {no_regex} non-regex pages came from Rust: {st}")
        return (f"{len(qs)} listings x2 of {total} functions: reply lines byte-identical to the Java path; "
                f"{served} pages rendered in Rust; {st}")
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


def t_decompile(c):
    exe = e9.fixture_args(c)
    g = c.copy_fixture("rpDec")
    d = c.daemon("rp-dec")
    w = r = None
    try:
        w = c.connect(d, "w", "rp", 3)
        e9.open_view(c, w, g, exe, writable=True)
        r = c.connect(d, "r", "rp", 3)
        r.call("open_project", path=str(g), writable=False)
        r.call("open_program", path=exe, writable=False)
        fns = r.call("functions", offset=10, limit=2)["functions"]
        fn0, fn1 = fns[0]["address"], fns[1]["address"]
        a = r.call("decompile", address=fn0, timeout=120, maxChars=10000)
        h0 = _dc(r)
        b = r.call("decompile", address=fn0, timeout=120, maxChars=10000)
        h1 = _dc(r)
        dt.check(a.get("completed") is True, f"the first decompile did not complete: {a}")
        dt.check({k: v for k, v in a.items() if k != "ms"} == {k: v for k, v in b.items() if k != "ms"},
                 "a stored decompile differs from a run's")
        dt.check(h1.get("hits", 0) == h0.get("hits", 0) + 1, f"the repeat was not a cache hit: {h0} -> {h1}")
        clipped = r.call("decompile", address=fn0, timeout=120, maxChars=100)
        dt.check(clipped.get("truncated") is True and len(clipped["c"]) == 100 and
                 clipped["chars"] == a["chars"], f"maxChars was not applied to a hit: {clipped}")
        h2 = _dc(r)
        dt.check(h2.get("hits", 0) == h1.get("hits", 0) + 1,
                 f"the clipped repeat was not a hit: {h1} -> {h2}")
        # a hit takes no program lock: while an exclusive script holds the program, the stored
        # function answers at once and a function never decompiled is refused as busy
        path = Path(c.script("RpSleep.java"))
        path.write_text(SLEEP)
        w.send("script", script=str(path), args=["4000"], isolation="exclusive", parallel=True, wait=120000)
        dt.wait_for(lambda: any(p["path"] == "/" + exe and p.get("busy") for p in r.call("status")["programs"]),
                    "the exclusive script to hold the program", 30)
        t = time.perf_counter()
        hit = r.call("decompile", address=fn0, timeout=120, maxChars=10000, wait=300)
        ms = (time.perf_counter() - t) * 1000
        dt.check(hit.get("completed") is True and ms < 500, f"a stored decompile waited for the writer: {hit} after {ms:.0f} ms")
        dt.expect_error("busy", r.call, "decompile", address=fn1, timeout=120, maxChars=10000, wait=300)
        dt.check(_dc(r).get("hits", 0) == h2.get("hits", 0) + 1, "the hit behind the writer was not counted")
        return f"stored decompile identical to a run, served without the program lock behind a writer ({ms:.0f} ms); {_dc(r)}"
    finally:
        e9.close_all(w, r)
        e9.stop(d)
        with __import__("contextlib").suppress(OSError):
            (c.scripts / "RpSleep.java").unlink()


def t_invalidate(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("rpInvA"), c.copy_fixture("rpInvB")
    da, db = c.daemon("rp-inv-java", engine=JAVA), c.daemon("rp-inv-rust", engine=RUST)
    a = b = None
    try:
        a, b = c.connect(da, "a", "rp", 3), c.connect(db, "a", "rp", 3)
        la, lb = _record(a), _record(b)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        qs = [{"offset": 0, "limit": 1000}, {"offset": 5, "limit": 10}, {"contains": "rp_renamed"},
              {"offset": 2, "limit": 3}]
        for s, ln in ((a, la), (b, lb)):
            _raw_calls(s, ln, qs + qs)    # the second pass is served from a table (Rust on b)
        p0 = _rp(b).get("pages", 0)
        dt.check(p0 > 0, f"no page came from Rust before the rename: {_rp(b)}")
        x = a.call("functions", offset=3, limit=1)["functions"][0]["address"]
        b.call("functions", offset=3, limit=1)
        for s in (a, b):
            s.call("rename", address=x, name="rp_renamed_fn")
        strip_id = re.compile(r'^\{"id":\d+,')
        got = [strip_id.sub("", g) for g in _raw_calls(b, lb, qs + qs)]
        want = [strip_id.sub("", w) for w in _raw_calls(a, la, qs + qs)]
        dt.check(got == want, "after the rename the read plane's lines differ from the Java path")
        dt.check(any("rp_renamed_fn" in g for g in got[4:]), "the renamed function is not listed after the rename")
        # edit-then-page cycles: each new program state stores a new table and frees the replaced
        # one's Rust rows at once (no GC), so the live native tables stay at one for this program
        for i in range(4):
            for s, ln in ((a, la), (b, lb)):
                s.call("rename", address=x, name=f"rp_cycle_{i}")
                _raw_calls(s, ln, qs[:2] + qs[:2])
        st = _rp(b)
        dt.check(st.get("live", 99) <= 1, f"replaced tables still hold Rust rows (live > 1): {st}")
        return f"rename (parity with the Java path) and 4 edit-then-page cycles, live tables {st.get('live')}; {st}"
    finally:
        e9.close_all(a, b)
        e9.stop(da)
        e9.stop(db)


TESTS = {
    "rp_bytes": t_bytes,
    "rp_decompile": t_decompile,
    "rp_invalidate": t_invalidate,
}

BASELINE = {}
