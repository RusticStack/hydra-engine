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
"""Replies encoded in Rust (Hydra rust/t-reply-encode).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only re_fn_bytes,...

* ``re_fn_bytes``: the ``functions`` reply lines of a daemon whose pages are written by the native encoder
  (``ReplyEncoder.java``, ``hydra_native`` ``reply.rs``) are byte-identical to those of a daemon with
  ``-set nativeReplies=false`` (the Gson tree) for every page shape of ``dt_da`` and paging 7 at a time, with
  only ``id`` and ``ms`` masked; ``health.replyEncode`` says native on one and off on the other; a page asked
  again is served from the program state's page cache; 8 clients paging at once get the same bytes.
* ``re_fn_rename``: after renames to names with characters JSON escapes or keeps as UTF-8 (a quote, a
  backslash, non-ASCII), every page shape is still byte-identical to the Gson daemon's, and the renamed
  names are in the listing (the page cache of the older program state is not served).
"""
import concurrent.futures
import pathlib
import re
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
da = _mod("dt_da")
OFF = {"nativeReplies": "false"}
ON = {}
SHAPES = da.SHAPES + [(0, 1000, {}), (1000, 1000, {}), (7, 0x7fff, {})]
_MASK = re.compile(rb'"(id|ms)":-?\d+')


class Lines:
    """Records the raw reply lines a session reads (the bytes the daemon sent, decoded as UTF-8)."""

    def __init__(self, s):
        self.lines = []
        orig = s._recv

        def rec(*a, **k):
            line = orig(*a, **k)
            if line and '"ok"' in line:
                self.lines.append(line)
            return line

        s._recv = rec

    def last(self):
        return _MASK.sub(rb'"\1":0', self.lines[-1].encode("utf-8"))


def _shape_lines(s, rec):
    out = []
    for o, lim, f in SHAPES:
        s.call("functions", offset=o, limit=min(lim, 10000), **f)
        out.append(rec.last())
    return out


def _paged_lines(s, rec, limit):
    out, off = [], 0
    while True:
        r = s.call("functions", offset=off, limit=limit)
        out.append(rec.last())
        off += limit
        if not r["truncated"]:
            return out


def _enc(s):
    return s.call("health").get("replyEncode") or {}


def _diff(la, lb):
    bad = [SHAPES[i] for i in range(len(SHAPES)) if la[i] != lb[i]]
    if bad:
        i = SHAPES.index(bad[0])
        return f"{bad}; first: {la[i][:300]!r} vs {lb[i][:300]!r}"
    return None


def t_fn_bytes(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("reFbA"), c.copy_fixture("reFbB")
    dof, don = c.daemon("re-fb-off", engine=OFF), c.daemon("re-fb-on", engine=ON)
    a = b = None
    clients = []
    try:
        a, b = c.connect(dof, "a", "re", 3), c.connect(don, "b", "re", 3)
        ra, rb = Lines(a), Lines(b)
        e9.open_view(c, a, ga, exe)
        e9.open_view(c, b, gb, exe)
        la, lb = _shape_lines(a, ra), _shape_lines(b, rb)
        d = _diff(la, lb)
        dt.check(d is None, f"native functions lines differ from the Gson lines for {d}")
        dt.check(_paged_lines(a, ra, 7) == _paged_lines(b, rb, 7), "paging 7 at a time: the lines differ")
        eon, eoff = _enc(b), _enc(a)
        dt.check(eon.get("native") is True and eon.get("calls", 0) > 0 and not eon.get("failed"),
                 f"the native encoder did not write the pages: {eon}")
        dt.check(eoff.get("native") is False and not eoff.get("calls"),
                 f"a daemon with nativeReplies=false used the native encoder: {eoff}")
        h0 = eon.get("pageHits", 0)
        b.call("functions", offset=0, limit=200)
        dt.check(_enc(b).get("pageHits", 0) == h0 + 1, f"a page asked again was encoded again: {_enc(b)}")
        for i in range(8):
            s = c.connect(don, f"p{i}", "re", 3)
            clients.append((s, Lines(s)))
            e9.open_view(c, s, gb, exe)
        ref = _paged_lines(a, ra, 11)
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            got = list(ex.map(lambda sr: _paged_lines(sr[0], sr[1], 11), clients))
        dt.check(all(g == ref for g in got), "a concurrent client's page lines differ from the Gson lines")
        total = len(a.call("functions", limit=10000)["functions"])
        return (f"{total} functions; {len(SHAPES)} page shapes, paging 7 and 11 (8 clients at once) "
                f"byte-identical to nativeReplies=false; {_enc(b)}")
    finally:
        e9.close_all(a, b, *[s for s, _ in clients])
        e9.stop(dof)
        e9.stop(don)


NAMES = ['re_q"uote', 're_back\\slash', "re_é中_name", "re_plain_after"]


def t_fn_rename(c):
    exe = e9.fixture_args(c)
    ga, gb = c.copy_fixture("reFrA"), c.copy_fixture("reFrB")
    dof, don = c.daemon("re-fr-off", engine=OFF), c.daemon("re-fr-on", engine=ON)
    a = b = None
    try:
        a, b = c.connect(dof, "a", "re", 3), c.connect(don, "b", "re", 3)
        ra, rb = Lines(a), Lines(b)
        e9.open_view(c, a, ga, exe, writable=True)
        e9.open_view(c, b, gb, exe, writable=True)
        d = _diff(_shape_lines(a, ra), _shape_lines(b, rb))
        dt.check(d is None, f"before the renames the lines differ: {d}")
        fs = [f for f in b.call("functions", limit=60)["functions"] if not f["thunk"] and not f["external"]]
        done = []
        for k, name in enumerate(NAMES):
            x = fs[2 + k]["address"]
            res = []
            for s in (a, b):
                try:
                    s.call("rename", address=x, name=name)
                    res.append(True)
                except Exception as e:  # a name the engine refuses is refused by both
                    res.append(str(e))
            dt.check(res[0] == res[1] or (res[0] is not True and res[1] is not True),
                     f"rename to {name!r}: the daemons disagree: {res}")
            if res[1] is True:
                done.append((x, name))
            d = _diff(_shape_lines(a, ra), _shape_lines(b, rb))
            dt.check(d is None, f"after renaming {x} to {name!r} the lines differ: {d}")
        after = {f["address"]: f["name"] for f in b.call("functions", limit=10000)["functions"]}
        stale = [(x, n) for x, n in done if not after.get(x, "").endswith(n)]
        dt.check(not stale, f"the listing does not show the new names {stale}")
        dt.check(len(done) >= 2, f"only {done} of {NAMES} could be renamed")
        e = _enc(b)
        dt.check(e.get("native") is True and e.get("columns", 0) >= len(done) + 1 and not e.get("failed"),
                 f"the native encoder did not write the listing of every program state: {e}")
        return f"renamed {[n for _, n in done]}; every page shape byte-identical after each; {_enc(b)}"
    finally:
        e9.close_all(a, b)
        e9.stop(dof)
        e9.stop(don)


TESTS = {
    "re_fn_bytes": t_fn_bytes,
    "re_fn_rename": t_fn_rename,
}

BASELINE = {}
