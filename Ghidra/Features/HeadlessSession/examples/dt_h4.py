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


#: there is one script class cache now (daemon-async's ScriptClasses was folded into
#: ScriptClassCache); the default engine settings are what these tests measure
H4 = {}

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
    d = c.daemon("h4-cache", engine=H4)
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
        d = c.daemon("h4-" + tag, vmargs=vm, engine=H4) if vm else c.daemon("h4-" + tag, engine=H4)
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


def _two_probes(c, sfx):
    """H4Probe<sfx>, H4Helper<sfx> and a second probe H4Other<sfx> in the script directory."""
    d = c.scripts
    probe, helper, other = (d / f"H4{n}{sfx}.java" for n in ("Probe", "Helper", "Other"))
    _write(helper, HELPER.replace("$SFX", sfx) % "h1")
    _write(probe, PROBE.replace("$SFX", sfx) % "v1")
    _write(other, OTHER.replace("$SFX", sfx))
    return probe, helper, other


OTHER = """import ghidra.app.script.GhidraScript;

public class H4Other$SFX extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("other");
    }
}
"""


# These two tests are about the compiled OSGi bundle behind the H4 cache: one edits a sibling
# to force a rebuild and checks the old class loaders are dropped, the other wipes the compiled
# bundle from another process. The persistent build store (ScriptBuildStore) serves a script whose
# source directory was compiled before without an OSGi bundle at all, so the OSGi artifacts these
# tests inspect would not exist; they pin the OSGi path with the store off (as dt_osgi does).
NO_BUILD_STORE = ["-Dhydra.script.buildCache=false"]


def t_script_cache_rebuild_frees(c):
    """A rebuild of a bundle drops every cache entry: none keeps an old bundle's class loader."""
    d = c.daemon("h4-frees", engine=H4, vmargs=NO_BUILD_STORE)
    s = None
    files = _two_probes(c, "F")
    try:
        s = c.connect(d, "h4f", "dt_h4", protocol=3)
        for _ in range(2):
            s.call("script", script=str(files[2]), program=None)
            _run(s, c, "F")
        before = _cache(s)
        dt.check(before["entries"] >= 2, f"both scripts not cached: {before}")
        _write(files[1], HELPER.replace("$SFX", "F") % "h2")
        r = _run(s, c, "F")   # rebuilds the bundle; H4OtherF is not called again
        dt.check(r["ok"] and "probe v1 helper h2" in r["output"], f"edit not seen: {r}")
        after = _cache(s)
        dt.check(after["entries"] <= 1,
                 f"stale entries kept after the rebuild (old class loaders alive): {after}")
        return f"entries {before['entries']} -> {after['entries']} after a rebuild"
    finally:
        for f in files:
            if f.exists():
                f.unlink()
        if s:
            s.close()
        d.stop(force=True)


def _compiled_manifests(c, name):
    """The compiled bundle manifests whose bundle holds class ``name`` (OSGi user dirs)."""
    out = []
    for cls in c.state.glob(f"settings/*/*/*/osgi/compiled-bundles/*/{name}.class"):
        m = cls.parent / "META-INF" / "MANIFEST.MF"
        if m.exists():
            out.append(m)
    for root in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"),
                 os.path.expanduser("~/.config"), os.path.expanduser("~/.ghidra")):
        if not root:
            continue
        base = dt.pathlib.Path(root) / "ghidra"
        for cls in base.glob(f"*/osgi/compiled-bundles/*/{name}.class"):
            m = cls.parent / "META-INF" / "MANIFEST.MF"
            if m.exists():
                out.append(m)
    return out


def t_script_cache_binary_wiped(c):
    """Another process wiping the shared compiled bundle makes the next call a miss (the usual
    path recompiles it), with the same output."""
    d = c.daemon("h4-wiped", engine=H4, vmargs=NO_BUILD_STORE)
    s = None
    files = _two_probes(c, "W")
    try:
        s = c.connect(d, "h4w", "dt_h4", protocol=3)
        for _ in range(3):
            r = _run(s, c, "W")
        dt.check(r["ok"] and "probe v1 helper h1" in r["output"], f"{r}")
        mans = _compiled_manifests(c, "H4ProbeW")
        dt.check(mans, "compiled bundle of H4ProbeW not found under the OSGi user directories")
        h0 = _cache(s)["hits"]
        for m in mans:
            dt.shutil.rmtree(m.parent.parent)  # the whole compiled bundle, as another process would
        r = _run(s, c, "W")
        h1 = _cache(s)["hits"]
        dt.check(r["ok"] and "probe v1 helper h1" in r["output"], f"after the wipe: {r}")
        dt.check(h1 == h0, f"a call after the compiled bundle was wiped was a cache hit ({h0}->{h1})")
        r = _run(s, c, "W")
        dt.check(r["ok"] and "probe v1 helper h1" in r["output"], f"after the reload: {r}")
        return f"wiped {len(mans)} manifest(s): miss, recompiled, same output"
    finally:
        for f in files:
            if f.exists():
                f.unlink()
        if s:
            s.close()
        d.stop(force=True)


def t_script_cache_parallel_edit(c):
    """Parallel hits on four sessions while the sibling class is edited: every reply is the old
    output or the new one, never an error."""
    import threading
    d = c.daemon("h4-par", engine=H4)
    files = _two_probes(c, "P")
    sessions = []
    try:
        for i in range(4):
            sessions.append(c.connect(d, f"h4p{i}", "dt_h4", protocol=3))
        _run(sessions[0], c, "P")
        results, stop = [], threading.Event()

        def worker(s):
            while not stop.is_set():
                results.append(_run(s, c, "P"))

        ts = [threading.Thread(target=worker, args=(s,)) for s in sessions]
        for t in ts:
            t.start()
        time.sleep(1.5)
        _write(files[1], HELPER.replace("$SFX", "P") % "h2")
        time.sleep(4)
        stop.set()
        for t in ts:
            t.join(120)
        last = _run(sessions[0], c, "P")
        bad = [r for r in results if not (r["ok"] and any(
            w in (r["output"] or "") for w in ("probe v1 helper h1", "probe v1 helper h2")))]
        dt.check(not bad, f"{len(bad)} of {len(results)} replies neither old nor new: {bad[:2]}")
        dt.check(last["ok"] and "probe v1 helper h2" in last["output"], f"edit not seen: {last}")
        return f"{len(results)} parallel replies, all old or new output; edit seen"
    finally:
        for f in files:
            if f.exists():
                f.unlink()
        for s in sessions:
            s.close()
        d.stop(force=True)


def t_script_run_bound(c):
    """With one run permit (and a long wait), two parallel sleeping scripts run one after the
    other; health counts the wait; both succeed."""
    import threading
    d = c.daemon("h4-bound", engine=H4, vmargs=["-Dhydra.script.maxConcurrent=1",
                                     "-Dhydra.script.maxConcurrentWaitMs=60000"])
    sessions = []
    try:
        for i in range(2):
            sessions.append(c.connect(d, f"h4b{i}", "dt_h4", protocol=3))
        sessions[0].call("script", script=c.script("TestSleep.java"), program=None, args=["10"])
        out = []

        def go(s):
            try:
                s.call("script", script=c.script("TestSleep.java"), program=None, args=["1500"])
                out.append(True)
            except Exception as ex:  # noqa: BLE001
                out.append(ex)

        t0 = time.perf_counter()
        ts = [threading.Thread(target=go, args=(s,)) for s in sessions]
        for t in ts:
            t.start()
        for t in ts:
            t.join(120)
        took = time.perf_counter() - t0
        f = _cache(sessions[0])
        dt.check(out == [True, True], f"a bounded run failed: {out}")
        dt.check(f.get("runPermits") == 1 and f.get("runWaited", 0) >= 1,
                 f"no run waited for the permit: {f}")
        dt.check(took >= 2.9, f"two 1.5 s scripts with one permit took only {took:.1f} s")
        return f"two runs serialised in {took:.1f} s; {f}"
    finally:
        for s in sessions:
            s.close()
        d.stop(force=True)


TESTS = {
    "script_cache_fresh": t_script_cache_fresh,
    "script_cache_identical": t_script_cache_identical,
    "script_cache_rebuild_frees": t_script_cache_rebuild_frees,
    "script_cache_binary_wiped": t_script_cache_binary_wiped,
    "script_cache_parallel_edit": t_script_cache_parallel_edit,
    "script_run_bound": t_script_run_bound,
}
