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
"""The resolved-script cache of the ``script`` command (hotspot H4, ``ScriptClassCache``).

Before it, every ``script`` call (every Hydralysis query runs as ``RusticQuery``) ran
``BundleHost.activateAll`` under the session's global script lock: a dependency graph over every
enabled bundle, a walk of the script's bundle against its classes, an activation. The cache keeps
the loaded class of a script that loaded cleanly and hands out new instances while the stat of
every file of its source directory, the bundle host's generation and the OSGi bundle are unchanged.

Tests
-----
* ``script_cache_fresh``  one daemon with the cache: a repeated call is a hit
  (``health.scriptCache.hits`` grows; red before H4, which has no such member); an edited script
  of the same size, an edited sibling class it calls, an added file that does not compile (its
  error reported on every call, as before), and its removal are all seen at the next call.
* ``script_cache_identical``  the same sequence of edits and calls on a daemon with the cache and
  on one with ``-Dhydra.script.classCache=false``: every reply's ``output`` (and ``ok``/``code``)
  is the same.
"""
import os
import re
import time

import daemon_tests as dt

PROBE = """import ghidra.app.script.GhidraScript;

public class H4Probe$SFX extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("probe %s helper " + H4Helper$SFX.value());
    }
}
"""

HELPER = """public class H4Helper$SFX {
    public static String value() {
        return "%s";
    }
}
"""

BROKEN = """public class H4Broken$SFX {
    this does not compile
}
"""


def _write(path, text):
    """Writes ``text`` and makes sure the modification time moves (a coarse clock could leave an
    edit within the same tick as the compile)."""
    before = path.stat().st_mtime_ns if path.exists() else 0
    path.write_text(text)
    st = path.stat()
    if st.st_mtime_ns <= before:
        os.utime(path, ns=(st.st_atime_ns, before + 1_000_000))
    time.sleep(0.05)


def _run(s, c, sfx):
    try:
        r = s.call("script", script=str(c.scripts / f"H4Probe{sfx}.java"), program=None)
        return {"ok": True, "output": r["output"]}
    except Exception as ex:  # noqa: BLE001 - the reply's code and message are what is compared
        return {"ok": False, "code": getattr(ex, "code", type(ex).__name__),
                "output": (getattr(ex, "details", None) or {}).get("output")
                if isinstance(getattr(ex, "details", None), dict) else str(ex)}


def _sequence(c, s, sfx, health=None):
    """The edits and calls on the classes H4Probe<sfx>, H4Helper<sfx>, H4Broken<sfx> in the
    script directory (a source bundle: they must sit at its root, in the default package); returns
    the replies (and the cache figures along the way). The files are removed at the end."""
    d = c.scripts
    probe, helper, broken = (d / f"H4{n}{sfx}.java" for n in ("Probe", "Helper", "Broken"))
    P, H, B = (x.replace("$SFX", sfx) for x in (PROBE, HELPER, BROKEN))
    try:
        return _steps(c, s, sfx, health, probe, helper, broken, P, H, B)
    finally:
        for f in (probe, helper, broken):
            if f.exists():
                f.unlink()


def _steps(c, s, sfx, health, probe, helper, broken, P, H, B):
    _write(helper, H % "h1")
    _write(probe, P % "v1")
    out, figs = [], []

    def step(name):
        out.append((name, _run(s, c, sfx)))
        if health:
            figs.append((name, health()))

    step("first")            # compiles
    step("second")           # no change
    step("third")            # no change: a hit
    _write(probe, P % "v2")   # same size as v1
    step("edited probe")
    step("edited probe again")
    _write(helper, H % "h2")
    step("edited helper")
    step("edited helper again")
    _write(broken, B)
    step("broken added")
    step("broken unchanged")
    step("broken unchanged again")
    broken.unlink()
    time.sleep(0.05)
    step("broken removed")
    step("clean again")
    step("clean again 2")
    return out, figs


def _cache(s):
    return s.call("health").get("scriptCache")


def t_script_cache_fresh(c):
    d = c.daemon("h4-cache")
    s = None
    try:
        s = c.connect(d, "h4", "dt_h4", protocol=3)
        out, figs = _sequence(c, s, "A", lambda: _cache(s))
        got = {n: r for n, r in out}
        dt.check(all(f is not None for _, f in figs),
                 "health has no scriptCache member (no resolved-script cache)")
        hits = {n: f["hits"] for n, f in figs}
        for n, want in (("first", "probe v1 helper h1"), ("second", "probe v1 helper h1"),
                        ("third", "probe v1 helper h1"), ("edited probe", "probe v2 helper h1"),
                        ("edited probe again", "probe v2 helper h1"),
                        ("edited helper", "probe v2 helper h2"),
                        ("edited helper again", "probe v2 helper h2"),
                        ("broken removed", "probe v2 helper h2"),
                        ("clean again", "probe v2 helper h2"),
                        ("clean again 2", "probe v2 helper h2")):
            dt.check(got[n]["ok"] and want in got[n]["output"], f"{n}: {got[n]}")
        dt.check(hits["third"] > hits["second"], f"a repeated unchanged script was no hit: {figs}")
        dt.check(hits["edited probe again"] > hits["edited probe"],
                 f"no hit after the edit was loaded: {figs}")
        dt.check(hits["clean again 2"] > hits["clean again"], f"no hit once clean again: {figs}")
        for n in ("broken unchanged", "broken unchanged again"):
            dt.check(hits[n] == hits["broken added"],
                     f"{n}: a bundle with a failing file was served from the cache: {figs}")
            o = got[n]["output"] or ""
            dt.check("H4BrokenA" in o and "probe v2 helper h2" in o,
                     f"{n}: the previous build's error is not reported with the output: {got[n]}")
        return (f"hits {figs[-1][1]['hits']} misses {figs[-1][1]['misses']}; edits of the script, "
                f"its sibling class and an added failing file all seen at the next call")
    finally:
        if s:
            s.close()
        d.stop(force=True)


def _norm(out):
    return [(n, r["ok"], r.get("code"), r["output"]) for n, r in out]


def t_script_cache_identical(c):
    seqs = {}
    for tag, sfx, vm in (("on", "On", None), ("off", "Off", ["-Dhydra.script.classCache=false"])):
        d = c.daemon("h4-" + tag, vmargs=vm) if vm else c.daemon("h4-" + tag)
        s = None
        try:
            s = c.connect(d, "h4" + tag, "dt_h4", protocol=3)
            out, _ = _sequence(c, s, sfx)
            # the two sequences use different class names: they differ, nothing else
            seqs[tag] = [(n, ok, code, re.sub(r"(H4(?:Probe|Helper|Broken))" + sfx + r"\b", r"\1",
                                              o or ""))
                         for n, ok, code, o in _norm(out)]
            if tag == "off":
                f = _cache(s)
                dt.check(f is not None and f["enabled"] is False and f["hits"] == 0,
                         f"the cache was not off: {f}")
        finally:
            if s:
                s.close()
            d.stop(force=True)
    diff = [(a, b) for a, b in zip(seqs["on"], seqs["off"]) if a != b]
    dt.check(not diff, f"replies differ with and without the cache: {diff[:2]}")
    return f"{len(seqs['on'])} replies identical with the cache on and off"


TESTS = {
    "script_cache_fresh": t_script_cache_fresh,
    "script_cache_identical": t_script_cache_identical,
}
