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
"""The persistent script build cache (JVM lane, round 3, ``ScriptBuildStore``).

A script is compiled by javac the first time its source directory is loaded in a daemon, and the
compiled classes belonged to that daemon's settings directory only. This store keys the compiled
classes by the content of the source directory (a SHA-256 over every file's path and bytes plus
the install and the Java version) and lives next to the shared class-search cache, so a second
daemon — a new benchmark run, a restarted engine, a new checkout of a harness — loads the classes
instead of running javac again. The tests prove both halves:

* ``r3_script_build_reuse``  daemon A compiles a script; daemon B (fresh state, fresh source path,
  same content) runs it with identical output and reports the persistent hit
  (``health.scriptCache.buildHits``); the OSGi build of B's source path never ran.
* ``r3_script_build_edit``  after the script is edited, B runs the new text (a new fingerprint, no
  stale class), and a source file that does not compile is not served from the store: its error is
  reported, as with the store off.
"""
import json
import pathlib
import uuid

import daemon_tests as dt

PROBE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class %s extends GhidraScript {
    @Override protected void run() throws Exception {
        println("%s " + getScriptName());
    }
}
"""

BROKEN = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class %s extends GhidraScript {
    @Override protected void run() throws Exception {
        this is not java
    }
}
"""


def _cache(s):
    return s.call("health").get("scriptCache") or {}


def _private_daemon(c, tag, script_dir, shared):
    """A daemon of its own state dir with exactly one script directory (so its source dirs are
    deterministic) and the shared class/build cache dir the test passes to both daemons."""
    state = c.work / ("r3state-" + tag)
    state.mkdir(parents=True, exist_ok=True)
    script_dir.mkdir(parents=True, exist_ok=True)
    cfg = {"scriptPath": [str(script_dir)], "classCacheDir": str(shared), "aot": "off"}
    (state / "config.json").write_text(json.dumps(cfg))
    return c.gs.Daemon(c.a.ghidra, str(state), tag, **cfg)


def _compiled_bundles(d, tag):
    return list((pathlib.Path(str(d.state)) / "settings" / tag).glob("*/osgi/compiled-bundles/**/*"))


def t_script_build_reuse(c):
    """A second daemon runs the same script content from a new source path without compiling it."""
    shared = c.work / "cc-r3-reuse"
    da = _private_daemon(c, "r3reuse-a", c.work / "r3scripts-a", shared)
    db = _private_daemon(c, "r3reuse-b", c.work / "r3scripts-b", shared)
    a = b = None
    try:
        # unique per run: daemon A's run compiles and stores, daemon B's reuses (a store left by
        # an earlier run of this test would otherwise make A a hit and hide the store)
        token = "reuse-" + uuid.uuid4().hex[:12]
        path_a = c.work / "r3scripts-a" / "ProbeReuse.java"
        path_a.write_text(PROBE % ("ProbeReuse", token))
        # a distinct source directory with the same bytes: different path, same content
        path_b = c.work / "r3scripts-b" / "ProbeReuse.java"
        path_b.write_text(PROBE % ("ProbeReuse", token))
        a = c.connect(da, "a", "r3", 3)
        ra = a.call("script", script=str(path_a), program=None, args=[], wait=120000)
        fa = _cache(a)
        dt.check(token + " ProbeReuse.java" in ra.get("output", ""),
                 f"the first daemon's run failed: {ra}")
        dt.check(fa.get("buildStores", 0) >= 1, f"nothing was stored for the first daemon: {fa}")

        b = c.connect(db, "b", "r3", 3)
        before = _cache(b)
        rb = b.call("script", script=str(path_b), program=None, args=[], wait=120000)
        after = _cache(b)
        dt.check(ra.get("output") == rb.get("output"),
                 f"the second daemon's output differs: {ra} / {rb}")
        dt.check(after.get("buildHits", 0) >= before.get("buildHits", 0) + 1,
                 f"the second daemon did not load the stored build: {before} -> {after}")
        # the OSGi build of B's source path never ran: no compiled class of it exists
        built = [p for p in _compiled_bundles(db, "r3reuse-b") if p.name.endswith(".class")]
        dt.check(not built, f"the second daemon compiled the script again: {built}")
        return (f"second daemon loaded the stored build "
                f"({before.get('buildHits')} -> {after.get('buildHits')} hits)")
    finally:
        if b is not None:
            b.close()
        if a is not None:
            a.close()
        db.stop(force=True)
        da.stop(force=True)


def t_script_build_edit(c):
    """An edited script and a failing one are never served from the stored build."""
    shared = c.work / "cc-r3-edit"
    da = _private_daemon(c, "r3edit-a", c.work / "r3editscripts-a", shared)
    db = _private_daemon(c, "r3edit-b", c.work / "r3editscripts-b", shared)
    a = b = None
    try:
        path_a = c.work / "r3editscripts-a" / "ProbeEdit.java"
        path_a.write_text(PROBE % ("ProbeEdit", "edit v1"))
        a = c.connect(da, "a", "r3", 3)
        ra = a.call("script", script=str(path_a), program=None, args=[], wait=120000)
        dt.check("edit v1" in ra.get("output", ""), f"first run failed: {ra}")

        path_b = c.work / "r3editscripts-b" / "ProbeEdit.java"
        path_b.write_text(PROBE % ("ProbeEdit", "edit v2"))
        b = c.connect(db, "b", "r3", 3)
        rb = b.call("script", script=str(path_b), program=None, args=[], wait=120000)
        out = rb.get("output", "")
        dt.check("edit v2" in out,
                 f"the edited script did not run, or the stored build of v1 was served: {rb}")
        dt.check("edit v1" not in out, f"the old text was served: {rb}")

        broken = c.work / "r3editscripts-b" / "BrokenProbe.java"
        broken.write_text(BROKEN % "BrokenProbe")
        try:
            rb2 = b.call("script", script=str(broken), program=None, args=[], wait=120000)
        except Exception as e:  # noqa: BLE001 - the failure is the expected outcome
            rb2 = e
        dt.check(isinstance(rb2, Exception), f"a script that does not compile ran: {rb2}")
        dt.check("BrokenProbe" in str(rb2), f"no compile error naming the script: {rb2}")
        return "an edited script and a failing one bypass the stored build"
    finally:
        if b is not None:
            b.close()
        if a is not None:
            a.close()
        db.stop(force=True)
        da.stop(force=True)


TESTS = {
    "r3_script_build_reuse": t_script_build_reuse,
    "r3_script_build_edit": t_script_build_edit,
}
