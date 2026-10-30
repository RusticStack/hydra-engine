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
"""Unit tests of the lean daemon JVM options in ``support/ghidra_session.py`` (light: no JVM, no
daemon, no install; a few ms): the shared class search cache and the C2 exclusion of one-shot code.

    python test_launcher_lean.py [-v]

``JvmDirectiveAccepted`` also starts ``java -version`` with the directives file when a JDK 25 is at
``GHIDRA_SESSION_JAVA_HOME``/``JAVA_HOME`` (skipped otherwise).
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "ghidra_session_under_test", HERE.parent / "support" / "ghidra_session.py")
gs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gs)


class FakeInstall:
    def __init__(self, root: pathlib.Path):
        self.dir = root / "install"
        self.version = "12.3-test"
        self.utility_jar = self.dir / "Utility.jar"
        self.jars = [str(self.dir / f"lib{i}.jar") for i in range(3)]

    def classpath(self, _vm):
        return list(self.jars)


def make_launch(root: pathlib.Path, state="state", **cfg) -> "gs.Launch":
    st = root / state
    st.mkdir(parents=True, exist_ok=True)
    la = object.__new__(gs.Launch)
    la.install, la.state, la.instance = FakeInstall(root), st, None
    la.cfg = dict(gs.DEFAULTS, maxHeap="1g", upgradeCache=False, settingsDir="shared")
    la.cfg.update(cfg)
    la.props = {"vmargs": [], "envvars": {}}
    la.jdk, la.jdk_version, la.java = pathlib.Path("jdk"), "25", pathlib.Path("java")
    la.env = {}
    return la


def opt(argv, prefix):
    """The values of every ``prefix...`` option of ``argv``."""
    return [a[len(prefix):] for a in argv if a.startswith(prefix)]


class SharedClassCache(unittest.TestCase):
    """The class search result depends only on the install and classpath, and the daemon checks
    every input before it trusts the file: a daemon in a new state dir uses the shared one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.user = self.root / "user-root"
        p = mock.patch.object(gs, "user_state_root", lambda: self.user)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def cache(self, la):
        argv, info = la.command([])
        files = opt(argv, "-Dghidra.session.classCache=")
        self.assertEqual(len(files), 1)
        self.assertEqual(info["classCacheFile"], files[0])
        return pathlib.Path(files[0]), info["key"]

    def test_new_state_dir_uses_the_shared_store(self):
        f, key = self.cache(make_launch(self.root))
        self.assertEqual(f, self.user / "classcache" / f"{key}.json")

    def test_two_state_dirs_share_one_file(self):
        a, _ = self.cache(make_launch(self.root, "s1"))
        b, _ = self.cache(make_launch(self.root, "s2"))
        self.assertEqual(a, b)

    def test_own_file_wins(self):
        la = make_launch(self.root)
        _, key = self.cache(la)
        own = la.state / "classcache" / f"{key}.json"
        own.parent.mkdir(parents=True)
        own.write_text("{}")
        self.assertEqual(self.cache(la)[0], own)

    def test_explicit_dir_and_none(self):
        d = self.root / "elsewhere"
        f, key = self.cache(make_launch(self.root, classCacheDir=str(d)))
        self.assertEqual(f, d / f"{key}.json")
        la = make_launch(self.root, classCacheDir="none")
        self.assertEqual(self.cache(la)[0], la.state / "classcache" / f"{key}.json")

    def test_off(self):
        argv, _ = make_launch(self.root, classCache=False).command([])
        self.assertEqual(opt(argv, "-Dghidra.session.classCache="), [])

    def test_env(self):
        with mock.patch.dict(os.environ, {"GHIDRA_SESSION_CLASS_CACHE_DIR": "none",
                                          "GHIDRA_SESSION_JIT_ONE_SHOT": "off"}):
            cfg = gs.load_config(self.root / "nothing.json") if hasattr(gs, "load_config") \
                else None
        if cfg is not None:
            self.assertEqual(cfg["classCacheDir"], "none")
            self.assertFalse(cfg["jitOneShot"])
        self.assertEqual(gs.ENV_MAP["GHIDRA_SESSION_CLASS_CACHE_DIR"][0], "classCacheDir")
        name, conv = gs.ENV_MAP["GHIDRA_SESSION_JIT_ONE_SHOT"]
        self.assertEqual(name, "jitOneShot")
        self.assertFalse(conv("off"))
        self.assertTrue(conv("1"))


class JitOneShot(unittest.TestCase):
    """javac, the XML parser and validator and the Sleigh preprocessor run once or rarely in a
    daemon: they are kept out of C2 by a compiler directives file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def directive(self, la):
        argv, _ = la.command([])
        files = opt(argv, "-XX:CompilerDirectivesFile=")
        return argv, files

    def test_default_on(self):
        argv, files = self.directive(make_launch(self.root))
        self.assertEqual(len(files), 1)
        i = argv.index(f"-XX:CompilerDirectivesFile={files[0]}")
        self.assertIn("-XX:+UnlockDiagnosticVMOptions", argv[:i])
        d = json.loads(pathlib.Path(files[0]).read_text())
        self.assertEqual(d, [{"match": gs.JIT_ONE_SHOT, "c2": {"Exclude": True}}])
        for pkg in ("com/sun/tools/", "com/sun/msv/", "ghidra/sleigh/grammar/"):
            self.assertIn(pkg + "*.*", d[0]["match"])
        # nothing of Ghidra's program, database or decompiler code is excluded, nor the XML
        # parser (every project open parses XML) or gson (every reply)
        self.assertFalse([m for m in d[0]["match"] if m.startswith((
            "ghidra/program", "ghidra/app", "db/", "com/sun/org/", "com/google/", "java/util/"))])

    def test_off(self):
        _, files = self.directive(make_launch(self.root, jitOneShot=False))
        self.assertEqual(files, [])

    def test_user_directives_win(self):
        la = make_launch(self.root, vmargs=["-XX:CompilerDirectivesFile=mine.json"])
        _, files = self.directive(la)
        self.assertEqual(files, ["mine.json"])

    def test_stable_file(self):
        _, a = self.directive(make_launch(self.root))
        _, b = self.directive(make_launch(self.root))
        self.assertEqual(a, b)


@unittest.skipUnless(os.environ.get("GHIDRA_SESSION_JAVA_HOME") or os.environ.get("JAVA_HOME"),
                     "no JDK")
class JvmDirectiveAccepted(unittest.TestCase):
    """The JVM parses the directives file (a file it rejects stops the JVM at start)."""

    def test_java_version(self):
        with tempfile.TemporaryDirectory() as t:
            la = make_launch(pathlib.Path(t))
            argv, _ = la.command([])
            jit = [a for a in argv if a.startswith(("-XX:+UnlockDiagnosticVMOptions",
                                                    "-XX:CompilerDirectivesFile="))]
            home = os.environ.get("GHIDRA_SESSION_JAVA_HOME") or os.environ["JAVA_HOME"]
            java = pathlib.Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
            r = subprocess.run([str(java), *jit, "-XX:+CompilerDirectivesPrint", "-version"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("1 compiler directives added", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *sys.argv[1:]])
