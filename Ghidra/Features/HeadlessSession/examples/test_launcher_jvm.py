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
"""Unit tests of the daemon JVM's command line in ``support/ghidra_session.py`` (light: no JVM, no
daemon, no install; a few ms): the shared AOT store and the JVM options the launcher chooses.

    python test_launcher_jvm.py [-v]
"""
import importlib.util
import os
import pathlib
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


def make_launch(root: pathlib.Path, **cfg) -> "gs.Launch":
    st = root / "state"
    st.mkdir(parents=True, exist_ok=True)
    la = object.__new__(gs.Launch)
    la.install, la.state, la.instance = FakeInstall(root), st, None
    la.cfg = dict(gs.DEFAULTS, maxHeap="1g", upgradeCache=False, settingsDir="shared",
                  classCache=False)
    la.cfg.update(cfg)
    la.props = {"vmargs": ["-XX:+UseCompactObjectHeaders"], "envvars": {}}
    la.jdk, la.jdk_version, la.java = pathlib.Path("jdk"), "25", pathlib.Path("java")
    la.env = {}
    return la


def opt(argv, prefix):
    """The values of every ``prefix...`` option of ``argv``."""
    return [a[len(prefix):] for a in argv if a.startswith(prefix)]


class SharedAotStore(unittest.TestCase):
    """An AOT cache is keyed by JDK, install, classpath and shaping options, not by state dir:
    a daemon of any state dir finds one trained once per install in the shared store."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.shared = self.root / "shared-aot"
        self.shared.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def key(self, la):
        return la.command([], use_aot=False)[1]["aotKey"]

    def test_state_without_cache_uses_the_shared_one(self):
        la = make_launch(self.root, aotDir=str(self.shared))
        f = self.shared / f"{self.key(la)}.aot"
        f.write_bytes(b"x")
        argv, info = la.command([])
        self.assertEqual(opt(argv, "-XX:AOTCache="), [str(f)])
        self.assertEqual(info["aot"], str(f))

    def test_state_cache_wins_over_the_shared_one(self):
        la = make_launch(self.root, aotDir=str(self.shared))
        k = self.key(la)
        (self.shared / f"{k}.aot").write_bytes(b"x")
        own = la.state / "aot" / f"{k}.aot"
        own.parent.mkdir()
        own.write_bytes(b"y")
        argv, _ = la.command([])
        self.assertEqual(opt(argv, "-XX:AOTCache="), [str(own)])

    def test_aot_dir_none_and_aot_off_ignore_the_shared_store(self):
        for cfg in ({"aotDir": "none"}, {"aotDir": str(self.shared), "aot": "off"}):
            la = make_launch(self.root, **cfg)
            (self.shared / f"{self.key(la)}.aot").write_bytes(b"x")
            argv, info = la.command([])
            self.assertEqual(opt(argv, "-XX:AOTCache="), [], cfg)
            self.assertIsNone(info["aot"], cfg)

    def test_other_key_is_not_used(self):
        la = make_launch(self.root, aotDir=str(self.shared))
        (self.shared / "0123456789abcdef-00000000.aot").write_bytes(b"x")
        argv, _ = la.command([])
        self.assertEqual(opt(argv, "-XX:AOTCache="), [])

    def test_default_shared_store_is_the_per_user_state_dir(self):
        la = make_launch(self.root)
        with mock.patch.object(gs, "user_state_dir", return_value=self.root / "user"):
            self.assertEqual(la.aot_dirs(), [la.state / "aot", self.root / "user" / "aot"])

    def test_shared_store_equal_to_state_is_listed_once(self):
        la = make_launch(self.root, aotDir=str(self.root / "state" / "aot"))
        self.assertEqual(la.aot_dirs(), [la.state / "aot"])

    def test_env_sets_the_store(self):
        with mock.patch.dict(os.environ, {"GHIDRA_SESSION_AOT_DIR": str(self.shared)}):
            cfg = gs.load_config(self.root / "nostate")
        self.assertEqual(cfg["aotDir"], str(self.shared))


class DaemonJvmOptions(unittest.TestCase):
    """The heap, GC and JIT options of the daemon JVM (measured with the multi-agent bench)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def argv(self, **cfg):
        return make_launch(self.root, aotDir="none", **cfg).command([])[0]

    def test_small_initial_heap_by_default(self):
        self.assertEqual(opt(self.argv(), "-Xms"), ["64m"])
        self.assertEqual(opt(self.argv(minHeap="1g"), "-Xms"), ["1g"])

    def test_g1_time_ratio_is_opt_in(self):
        self.assertEqual(opt(self.argv(), "-XX:GCTimeRatio="), [])
        self.assertEqual(opt(self.argv(gcTimeRatio=4), "-XX:GCTimeRatio="), ["4"])
        self.assertEqual(opt(self.argv(gc="zgc"), "-XX:GCTimeRatio="), [])

    def test_jit_threads_default_is_the_jdks(self):
        with mock.patch.object(gs, "granted_cpus", return_value=24):
            self.assertEqual(opt(self.argv(), "-XX:CICompilerCount="), [])

    def test_jit_threads_follow_the_granted_cpus(self):
        for cpus, want in ((1, "2"), (8, "2"), (12, "3"), (16, "4"), (64, "4")):
            with mock.patch.object(gs, "granted_cpus", return_value=cpus):
                self.assertEqual(opt(self.argv(jitThreads=0), "-XX:CICompilerCount="), [want], cpus)
        self.assertEqual(opt(self.argv(jitThreads=6), "-XX:CICompilerCount="), ["6"])
        self.assertEqual(opt(self.argv(jitThreads=-1), "-XX:CICompilerCount="), [])

    def test_caller_vmargs_come_last(self):
        argv = self.argv(vmargs=["-XX:CICompilerCount=8", "-Xms2g"])
        self.assertEqual(opt(argv, "-XX:CICompilerCount=")[-1], "8")
        self.assertEqual(opt(argv, "-Xms")[-1], "2g")

    def test_granted_cpus_is_positive(self):
        self.assertGreaterEqual(gs.granted_cpus(), 1)

    @unittest.skipUnless(os.name == "nt", "Windows affinity mask")
    def test_granted_cpus_follows_the_affinity_mask_on_windows(self):
        import subprocess
        code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('g',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.granted_cpus())")
        # "start /affinity 3" runs the child on 2 CPUs (its affinity mask), as a job scheduler would.
        out = subprocess.run(["cmd.exe", "/d", "/c", "start", "/b", "/wait", "/affinity", "3",
                              sys.executable, "-I", "-c", code,
                              str(HERE.parent / "support" / "ghidra_session.py")],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "2", out.stderr)


class AotStoreUpkeep(unittest.TestCase):
    """The shared store does not fill with caches no install matches any more, and a cache that a
    running JVM has mapped (Windows: cannot be replaced) does not fail a retrain or leak its temp."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def cache(self, name, age_s, now):
        f = self.store / f"{name}.aot"
        f.write_bytes(b"x")
        (self.store / f"{name}.log").write_bytes(b"")
        os.utime(f, (now - age_s, now - age_s))
        return f

    def test_prune_keeps_current_and_recent_removes_old_and_excess(self):
        now = 2_000_000_000.0
        cur = self.cache("cur", 90 * 86400, now)
        old = self.cache("old", 30 * 86400, now)
        recent = [self.cache(f"r{i}", i * 60, now) for i in range(gs.AOT_STORE_KEEP + 2)]
        bld = self.store / "x.123-abc.building"
        bld.write_bytes(b"x")
        os.utime(bld, (now - 2 * 86400, now - 2 * 86400))
        removed = gs.prune_aot_store(self.store, keep={"cur"}, log=lambda *_: None, now=now)
        self.assertTrue(cur.exists())
        self.assertFalse(old.exists())
        self.assertFalse((self.store / "old.log").exists())
        self.assertFalse(bld.exists())
        self.assertEqual([f.exists() for f in recent],
                         [True] * gs.AOT_STORE_KEEP + [False, False])
        self.assertEqual(len(removed), 4)

    def test_cache_in_use_is_kept_and_new_one_dropped(self):
        out = self.store / "k.aot"
        out.write_bytes(b"old")
        tmp = self.store / "k.1-x.building"
        tmp.write_bytes(b"new")
        with mock.patch.object(gs.os, "replace", side_effect=PermissionError(5, "denied")):
            gs.install_aot(tmp, out, log=lambda *_: None)
        self.assertEqual(out.read_bytes(), b"old")

    def test_permission_error_without_a_cache_is_raised(self):
        tmp = self.store / "k.1-x.building"
        tmp.write_bytes(b"new")
        with mock.patch.object(gs.os, "replace", side_effect=PermissionError(5, "denied")):
            with self.assertRaises(PermissionError):
                gs.install_aot(tmp, self.store / "k.aot", log=lambda *_: None)


class LaunchPropertiesHeap(unittest.TestCase):
    """Every launch.properties JVM (analyzeHeadless, the GUI, pyghidra) starts with a small heap:
    without -Xms the JVM commits 1/64 of physical memory at start (1 GiB of a 64 GiB machine)."""

    def vmargs(self):
        f = HERE.parents[2] / "RuntimeScripts" / "support" / "launch.properties"
        if not f.is_file():
            self.skipTest(f"{f} is not in this tree (an install)")
        return [v for k, v in gs._read_properties(f) if k == "VMARGS"]

    def test_small_initial_heap(self):
        pct = [float(v.split("=", 1)[1]) for v in self.vmargs()
               if v.startswith("-XX:InitialRAMPercentage=")]
        self.assertTrue(pct, "launch.properties sets no -XX:InitialRAMPercentage")
        self.assertLessEqual(pct[-1], 0.2, pct)   # 128 MB of 64 GiB

    def test_no_fixed_initial_heap(self):
        """A fixed -Xms above a launcher's smaller MAXMEM (-Xmx) makes the JVM refuse to start;
        an initial-heap percentage is lowered to the maximum instead."""
        self.assertEqual([v for v in self.vmargs()
                          if v.startswith(("-Xms", "-XX:InitialHeapSize"))], [])


if __name__ == "__main__":
    unittest.main()
