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
"""Tests of the shared session daemon. Standard library only; any OS.

    python daemon_tests.py --ghidra <install> --work <empty dir> --exe A.exe --dll B.dll
                           [--project <an analysed project, opened read-only>]
                           [--legacy-project <a project saved by an older Ghidra>
                            [--legacy-program <path in it>]] [--only a,b]
                           [--baseline] [--list] [--tests-dir <dir>] [--report <file.json>]

Each test starts its own daemon instance in <work>/state and stops it, so the user's daemon is
never touched. --project (optional) adds an existing analysed project, which is only ever opened
read-only, to the multi-project test. --legacy-project (optional) is copied into <work> for the
older-format part of upgrade_cache; the original is only read.

Tests: two_harnesses, two_projects, dll_import, client_kill, daemon_restart, fairness, cancel_all,
import_queue, import_isolation, parallel_imports, import_kill, import_readers, import_speed,
caller_labels, idle_shutdown, keep_warm, stdio, upgrade_cache, holders, fork, revisions,
refresh_force, overlays, overlay_owned, legacy_overlay, multi_writer, shared, edit,
orphan_shutdown, import_write_kill, shared_stress. import_speed takes --big <binary> (repeat)
and --big-analyze.

More tests live in ``dt_<package>.py`` files next to this one (PROTOCOL-3.md, section 8): each
exposes ``TESTS = {name: fn}`` (``fn(ctx)`` returns a note, or raises ``Fail``) and may expose
``BASELINE = {name: premise}``. They are imported by name (``import daemon_tests as dt`` gives
them ``Fail``, ``check``, ``expect_error``, ``wait_for``, ``PremiseFail`` and the ``Ctx``), run after
the tests above and selected by ``--only`` like them. A test that cannot exercise its premise in
this environment raises ``Skipped(reason)`` (or returns a note starting with "skipped"): it is
printed as SKIP, counted apart from the passes, and does not fail the run. A failed test has its
daemons asked to shut down (``Ctx.release``) and then killed, so it leaves no project open. A directory without any ``dt_*.py`` is fine
(``--tests-dir`` names another one); a file that does not import is reported as a failure.

Expected-fail baseline. A test named in a module's ``BASELINE`` is written against the behaviour
the design wants, and is *expected to fail* on the engine it is a baseline of (hydra.3). It is not
part of the default run (which would be red by design). ``--baseline`` runs them and checks that each
fails **for its stated reason**: the test raises ``PremiseFail`` only when the desired behaviour is
absent *and* the observation carries the premise's signature (for example ``busy`` naming the long
lane). Each test is then CONFIRMED (``PremiseFail``), REFUTED (it passed: the premise is not true of
this engine, and the test is recorded as a finding and dropped, never weakened) or OTHER (it failed
without the signature: the test is wrong, or the engine is). ``--baseline`` exits 0 only when every
test is CONFIRMED. Name a baseline test with ``--only`` to run it with ordinary semantics, which is
how it is used on an engine that is supposed to have fixed it.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import inspect
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent

MAKE_PROJECT = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class TestMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
"""
SLEEP = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class TestSleep extends GhidraScript {
    @Override protected void run() throws Exception {
        println("start " + System.currentTimeMillis());
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("end " + System.currentTimeMillis());
    }
}
"""

RESULTS = []


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)


def expect_error(code, fn, *args, **kw):
    """Runs fn, which must fail with the protocol error ``code``; returns the SessionError."""
    try:
        r = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != code:
            raise Fail(f"expected {code}, got {type(e).__name__}: {e} "
                       f"{getattr(e, 'details', '')}") from e
        return e
    raise Fail(f"expected {code}, got a result: {str(r)[:300]}")


class PremiseFail(Fail):
    """A baseline test failed *as premised*: the behaviour the design wants is absent and the
    observation carries the premise's signature. ``evidence`` is a dict of what was seen."""

    def __init__(self, what, evidence=None):
        super().__init__(what)
        self.evidence = evidence or {}


class Skipped(Exception):
    """A test could not exercise its premise here (an environment limit, such as a job object that
    refuses breakaway). The run reports it as SKIPPED with this reason, never as ok, and it does not
    fail the run. Raise it only after proving the limit; a test that merely cannot decide fails."""


_SHIM = threading.RLock()


@contextlib.contextmanager
def client_protocol(gs, n):
    """Makes the launcher library send ``protocol: n`` in ``hello`` and accept an engine that
    answers any protocol from 2 to ``n`` (an engine without v3 answers 2 to a request for 3: the
    spec's rule, PROTOCOL-3.md 3.1). The library file is not edited; this works for the 1.0.0
    client (``PROTOCOL = 2``) and for one that already ranges over 2..3.

    Only the protocol *equality* is relaxed to the range 2..n. Everything else the library checks
    stays in force by delegation to the original functions: ``check_compatible`` still enforces
    ``minClient`` (a future bump is visible to every ``Ctx.connect`` test) and its error messages;
    ``_check_install`` still enforces the install directory and, for a protocol outside 2..n, the
    protocol too. The patch is process-wide, so it holds ``_SHIM`` for the whole ``with`` body
    (re-entrant: nesting restores the outer values) and puts back exactly what it replaced, also
    when the body raises."""
    def in_range(p):
        return isinstance(p, int) and not isinstance(p, bool) and 2 <= p <= n

    with _SHIM:
        saved = (gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install)
        orig_check, orig_install = saved[1], saved[2]

        def check(info, client_version=None, protocol=None):
            kw = {} if client_version is None else {"client_version": client_version}
            if protocol is None:
                # an answer inside 2..n is compared with itself, so the original keeps its
                # minClient check; anything else is compared with n and fails with its message
                p = info.get("protocol")
                protocol = p if in_range(p) else n
            return orig_check(info, protocol=protocol, **kw)

        def check_install(self, ep, install):
            if in_range(ep.get("protocol")):
                ep = dict(ep, protocol=gs.PROTOCOL)  # the original compares with PROTOCOL == n
            return orig_install(self, ep, install)

        gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install = n, check, check_install
        try:
            yield
        finally:
            gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install = saved


def selftest(gs):
    """Regression test of ``client_protocol`` (no daemon, no project, a few ms): what the shim
    relaxes and what it must leave in force, on the launcher library ``gs`` of the engine under
    test. Prints one line per check; returns the exit code (0 only when every check held)."""
    bad = []

    def check(what, cond):
        print(("ok   " if cond else "FAIL ") + what)
        if not cond:
            bad.append(what)

    def raises(fn, exc):
        try:
            fn()
        except exc:
            return True
        except Exception as e:  # noqa: BLE001
            print(f"     raised {type(e).__name__}, expected {exc.__name__}: {e}")
            return False
        return False

    def accepts(fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            print(f"     raised {type(e).__name__}: {e}")
            return False
        return True

    class _D:
        instance = "selftest"

    inst = type("_Inst", (), {"dir": pathlib.Path(__file__).resolve().parent})()
    here = str(inst.dir)
    orig = (gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install)
    cur = gs.CLIENT_VERSION
    inc, lau = gs.IncompatibleError, gs.LaunchError

    def compat(info, **kw):
        return lambda: gs.check_compatible(info, **kw)

    def install(ep):
        return lambda: gs.Daemon._check_install(_D(), ep, inst)

    with client_protocol(gs, 3):
        check("n=3: PROTOCOL is 3 inside", gs.PROTOCOL == 3)
        check("n=3: an engine answering 2 or 3 is accepted",
              accepts(compat({"protocol": 2})) and accepts(compat({"protocol": 3, "minClient": cur})))
        check("n=3: a minClient above this client is still rejected",
              raises(compat({"protocol": 3, "minClient": "99.0.0"}), inc)
              and raises(compat({"protocol": 2, "minClient": "99.0.0"}), inc))
        check("n=3: an unreadable minClient is still rejected",
              raises(compat({"protocol": 2, "minClient": "x"}), inc))
        check("n=3: protocols 1, 4, None, True and '3' are rejected",
              all(raises(compat(i), inc) for i in ({"protocol": 1}, {"protocol": 4}, {},
                                                   {"protocol": True}, {"protocol": "3"})))
        check("n=3: an explicit protocol=3 call with an answer of 2 is rejected",
              raises(compat({"protocol": 2}, protocol=3), inc))
        check("n=3: install check accepts protocol 2 and 3 of this install",
              accepts(install({"protocol": 2})) and accepts(install({"protocol": 3,
                                                                    "install": here})))
        check("n=3: an install mismatch raises LaunchError",
              raises(install({"protocol": 2, "install": here + "-other"}), lau))
        check("n=3: an endpoint protocol outside 2..3 raises LaunchError",
              raises(install({"protocol": 4}), lau) and raises(install({"protocol": 1}), lau))
        with client_protocol(gs, 2):
            check("nested n=2: PROTOCOL is 2 inside", gs.PROTOCOL == 2)
            check("nested n=2: an answer of 3 is rejected",
                  raises(compat({"protocol": 3}), inc))
        check("nested: the outer n=3 is back after the inner block",
              gs.PROTOCOL == 3 and accepts(compat({"protocol": 3})))
    check("after the block the original three are back",
          (gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install) == orig)
    try:
        with client_protocol(gs, 3):
            raise RuntimeError("inside")
    except RuntimeError:
        pass
    check("after a raise inside the block the original three are back",
          (gs.PROTOCOL, gs.check_compatible, gs.Daemon._check_install) == orig)
    check("outside the block the original rejects an answer of 3 (when PROTOCOL is 2)",
          gs.PROTOCOL != 2 or raises(compat({"protocol": 3}), inc))
    print(f"{'FAILED: ' + str(len(bad)) + ' check(s)' if bad else 'all client_protocol checks ok'}")
    return 1 if bad else 0


def _link_or_copy(src: pathlib.Path, dst: pathlib.Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)        # the AOT cache is only read (memory-mapped) by the JVMs
    except OSError:
        shutil.copy2(src, dst)


def seed_state(seed: pathlib.Path, state: pathlib.Path):
    """Puts what ``--prepare`` made into a fresh state dir: the class search cache and the AOT
    cache (if one was made; hard-linked) of this install's daemon JVM, so that a daemon of the test
    starts the way a user's second start does (measured: connect 0.7-1.0 s instead of 1.6-2.5 s). Neither changes what the daemon does, only how fast it starts; a test
    that runs a daemon with other JVM options (another heap, collector, install) gets another cache
    key and starts cold, as before."""
    for f in sorted((seed / "state" / "aot").glob("*.aot")):
        _link_or_copy(f, state / "aot" / f.name)
    for f in sorted((seed / "state" / "classcache").glob("*.json")):
        (state / "classcache").mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, state / "classcache" / f.name)   # small, and a daemon may rewrite it


def install_key(ghidra) -> str:
    """The install, for the keys of the projects cached in a seed dir: every jar's path, size and
    mtime, and the bytes of HeadlessSession's support files (the launcher)."""
    root = pathlib.Path(ghidra)
    h = hashlib.sha256(str(root.absolute()).encode())
    for p in sorted((root / "Ghidra").rglob("*.jar")):
        st = p.stat()
        h.update(f"{p.relative_to(root)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    sup = root / "Ghidra" / "Features" / "HeadlessSession" / "support"
    for p in sorted(sup.rglob("*.py")) if sup.is_dir() else ():
        h.update(p.name.encode() + p.read_bytes())
    return h.hexdigest()


def prepare_seed(a, gs, aot=False):
    """``--prepare``: makes ``--work`` a seed directory for ``--seed-dir``: the analysed fixture
    project (what ``Ctx.fixture`` makes, once instead of once per test process), the class search
    cache its daemon wrote, a copy of the install (``install``: a test that clones the install with
    hard links needs a source on the same volume as its --work) and, with ``aot``, the AOT cache of the daemon JVM trained on a copy of
    it. Returns the exit code."""
    c = Ctx(a, gs)
    t = time.perf_counter()
    try:
        (c.work / "install.key").write_text(install_key(a.ghidra), encoding="utf-8")
        base = c.fixture()
        print(f"fixture {base} in {time.perf_counter() - t:.1f} s", flush=True)
        t = time.perf_counter()
        inst = c.work / "install"       # for the tests that clone the install with hard links (dt_e8.py)
        if inst.exists():
            shutil.rmtree(inst)
        shutil.copytree(a.ghidra, inst)
        print(f"install copy {inst} in {time.perf_counter() - t:.1f} s", flush=True)
        if aot:
            t = time.perf_counter()
            train = c.work / "aot-train"
            if train.exists():
                shutil.rmtree(train)
            shutil.copytree(base, train)
            gs.build_aot(a.ghidra, str(c.state), str(train / "Fixture.gpr"), None)
            shutil.rmtree(train, ignore_errors=True)
            print(f"aot cache in {time.perf_counter() - t:.1f} s", flush=True)
    finally:
        c.cleanup()
    return 0


#: The setup projects of ``Ctx.cached_project`` that run_parallel.py makes in its seed phase, before its
#: queue starts (``--prebuild TAG``), so that every test that needs one copies it and none makes it: tests
#: that missed together each made their own. ``tag -> (users, make)``: ``make(c, name)`` is the function the
#: tests call (so the cache key, made from the builder's source, is the same), ``users`` the test names (or
#: ``dt_*.py`` file names: all its tests) that need it. run_parallel.py --selftest checks that every function
#: that calls ``cached_project`` is registered here and that every test calling one directly is a user.
PREBUILT = {}


def prebuilt(tag, users):
    """Registers ``make(c, name)`` as the maker of the cached project ``tag`` (see PREBUILT)."""
    def deco(make):
        PREBUILT[tag] = (tuple(users), make)
        return make
    return deco


def prebuild(a, gs, tags):
    """``--prebuild``: makes the cached projects ``tags`` in ``--seed-dir`` (those already there are only
    copied once more, to check them). Returns the exit code."""
    c = Ctx(a, gs)
    bad = 0
    try:
        for tag in tags:
            if tag not in PREBUILT:
                print(f"FAIL {tag}: no such cached project; known: {', '.join(PREBUILT)}", flush=True)
                bad += 1
                continue
            t = time.perf_counter()
            name = "pre-" + tag
            try:
                gpr = PREBUILT[tag][1](c, name)
                gpr = gpr[0] if isinstance(gpr, tuple) else gpr
                ok = pathlib.Path(gpr).is_file()
            except Exception as e:      # reported; the tests then make it themselves
                ok, gpr = False, f"{type(e).__name__}: {e}"
            how = "copied" if any(k.startswith(f"project {tag} copied") for k in c.timings) else "made"
            print(f"{'ok  ' if ok else 'FAIL'} {tag}: {how} in {time.perf_counter() - t:.1f} s ({gpr})", flush=True)
            bad += not ok
            shutil.rmtree(c.work / name, ignore_errors=True)
    finally:
        c.cleanup()
    print("timings:", json.dumps(c.timings, indent=1))
    return 1 if bad else 0


class Ctx:
    def __init__(self, a, gs):
        self.a = a
        self.gs = gs
        self.procs = []
        self.work = pathlib.Path(a.work).absolute()
        self.state = self.work / "state"
        self.scripts = self.work / "scripts"
        self.support = pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" / \
            "support"
        self.state.mkdir(parents=True, exist_ok=True)
        self.scripts.mkdir(parents=True, exist_ok=True)
        (self.scripts / "TestMakeProject.java").write_text(MAKE_PROJECT)
        (self.scripts / "TestSleep.java").write_text(SLEEP)
        cfg = {"tmpdir": a.tmpdir or str(self.work / "tmp"), "scriptPath": [str(self.scripts)]}
        if a.tmpdir == "default":
            del cfg["tmpdir"]  # leave java.io.tmpdir to the JVM
        (self.state / "config.json").write_text(json.dumps(cfg))
        self.daemons = []
        self.timings = {}
        self.seed = pathlib.Path(a.seed_dir).absolute() if getattr(a, "seed_dir", None) else None
        if self.seed:
            seed_state(self.seed, self.state)

    def daemon(self, instance, **cfg):
        d = self.gs.Daemon(self.a.ghidra, str(self.state), instance, **cfg)
        self.daemons.append(d)
        return d

    def connect(self, d, client, harness, protocol=2):
        """A session on daemon ``d`` (started if need be) that asks for ``protocol`` in ``hello``.
        The engine's answer is ``s.hello["protocol"]`` (2 when it serves no v3)."""
        with client_protocol(self.gs, protocol):
            return d.connect(client, harness)

    def script(self, name):
        return str(self.scripts / name)

    def make_project(self, s, folder, name):
        folder.mkdir(parents=True, exist_ok=True)
        s.call("script", script=self.script("TestMakeProject.java"), program=None,
               args=[str(folder), name])
        return folder / f"{name}.gpr"

    def fixture(self):
        """An analysed project with the EXE, made once and copied per test."""
        base = self.work / "fixture"
        gpr = base / "Fixture.gpr"
        seeded = self.seed / "fixture" if self.seed else None
        if not gpr.exists() and seeded and (seeded / "Fixture.gpr").is_file():
            # the same project, made once by --prepare for the whole run (import+analyze of --exe)
            t = time.perf_counter()
            shutil.copytree(seeded, base)
            self.timings["fixture copied from --seed-dir (s)"] = round(time.perf_counter() - t, 2)
        if not gpr.exists():
            d = self.daemon("fixture")
            with d.connect("fixture", "tests") as s:
                self.make_project(s, base, "Fixture")
                s.call("open_project", path=str(gpr), writable=True)
                t = time.perf_counter()
                s.call("import", file=self.a.exe, analyze=True, timeout=1800, wait=600000)
                self.timings["fixture import+analyze exe"] = time.perf_counter() - t
                s.call("close_project")
            d.stop()
        return base

    def cached_project(self, name, tag, build, inputs=()):
        """A project that ``build(dst)`` makes in the fresh directory ``dst`` (``work/name``) and
        whose .gpr it returns. With a ``--seed-dir`` (run_parallel.py) it is made once per run
        and every test copies it (a full copy). run_parallel.py makes the registered ones
        (PREBUILT) in its seed phase, so tests find them; otherwise the first test that needs it
        makes it in its own ``dst``, copies that into the seed dir under a temporary name and renames it to
        ``proj-<tag>-<key>`` (atomic; a test that lost the race drops its copy, the winner's is
        the same project). The key is the install (``install.key`` of --prepare), ``tag``, the
        source of ``build`` and of its whole file, and the bytes of every file in ``inputs``: another engine, another
        builder or another input makes another project. Only for setup the test does not check:
        a builder makes the project the way the test made it before, in a daemon of its own."""
        dst = self.work / name
        if dst.exists():
            shutil.rmtree(dst)
        cached = None
        if self.seed:
            h = hashlib.sha256(tag.encode())
            ik = self.seed / "install.key"
            h.update(ik.read_bytes() if ik.is_file() else install_key(self.a.ghidra).encode())
            # the builder and the whole file it is in (the helpers it calls)
            h.update(inspect.getsource(build).encode() + pathlib.Path(inspect.getsourcefile(build)).read_bytes())
            for f in inputs:
                f = pathlib.Path(f)
                h.update(f.name.encode() + b"\0" + f.read_bytes())
            cached = self.seed / f"proj-{tag}-{h.hexdigest()[:16]}"
            rel = cached / "gpr.txt"
            if rel.is_file():
                t = time.perf_counter()
                shutil.copytree(cached / "p", dst)
                self.timings[f"project {tag} copied from the --seed-dir cache (s)"] = round(time.perf_counter() - t, 2)
                return dst / rel.read_text(encoding="utf-8").strip()
        t = time.perf_counter()
        gpr = pathlib.Path(build(dst))
        self.timings[f"project {tag} made (s)"] = round(time.perf_counter() - t, 2)
        if cached is not None:
            tmp = cached.parent / f"{cached.name}.{os.getpid()}.tmp"
            with contextlib.suppress(OSError):
                if tmp.exists():
                    shutil.rmtree(tmp)
                shutil.copytree(dst, tmp / "p")
                (tmp / "gpr.txt").write_text(str(gpr.relative_to(dst)), encoding="utf-8")
                os.rename(tmp, cached)      # fails if another test cached it first: theirs is the same
            shutil.rmtree(tmp, ignore_errors=True)
        return gpr

    @prebuilt("empty-Src", users=("dt_e2.py", "dt_e2a.py"))
    def _empty_src(self, name):
        return self.empty_project(name, "Src")

    def empty_project(self, name, project):
        """An empty project ``project`` in ``work/name`` (made by TestMakeProject.java in a daemon
        of its own, or copied from the seed dir)."""
        def build(dst):
            d = self.daemon(f"mk-{project.lower()}")
            with d.connect("mk", "tests") as s:
                gpr = self.make_project(s, dst, project)
            d.stop()
            return gpr
        return self.cached_project(name, f"empty-{project}", build)

    def copy_fixture(self, name):
        dst = self.work / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.fixture(), dst)
        return dst / "Fixture.gpr"

    def child(self, code, *args):
        """A separate Python process (a second harness) with ghidra_session importable."""
        prelude = (f"import sys, json, time; sys.path.insert(0, {str(self.support)!r}); "
                   "import ghidra_session as gs; A = sys.argv[1:]\n")
        p = subprocess.Popen([sys.executable, "-c", prelude + code, *map(str, args)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             stdin=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    def release(self, timeout=20.0):
        """Asks every daemon this run started that is still up to shut down (``force``: a failed
        test leaves open projects, unsaved work and clients behind), all at once, and waits at most
        ``timeout`` seconds. That closes the projects and drops their locks the way a stopped
        daemon does, which a kill does not; ``cleanup`` then kills whatever did not answer. Never
        raises: a daemon that is wedged is left to ``cleanup``."""
        def stop(d):
            with contextlib.suppress(Exception):
                if d.jvm_alive():
                    d.stop(force=True, timeout=timeout)
        threads = [threading.Thread(target=stop, args=(d,), daemon=True) for d in self.daemons]
        for t in threads:
            t.start()
        end = time.monotonic() + timeout + 10
        for t in threads:
            t.join(max(0.0, end - time.monotonic()))

    def cleanup(self):
        for p in self.procs:
            with contextlib.suppress(Exception):
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=10)
        self.procs.clear()
        for d in self.daemons:
            try:
                if d.jvm_alive():
                    d.kill()
            except Exception:  # noqa: BLE001
                pass


# ---- tests ----------------------------------------------------------------------------------

def t_two_harnesses(c: Ctx):
    """Two harness processes start at once with no daemon running: one JVM starts and both use
    it."""
    d = c.daemon("harness")
    check(not d.jvm_alive(), "a daemon is already running")
    code = ("t0 = time.perf_counter()\n"
            "s = gs.connect(client='agent', harness=A[0], state=A[1], instance='harness', "
            "ghidra=A[2])\n"
            "st = s.call('status')\n"
            "print(json.dumps({'pid': s.endpoint['pid'], 'client': s.hello['client'], "
            "'ms': (time.perf_counter() - t0) * 1000}))\n"
            "time.sleep(3); s.close()\n")
    procs = [c.child(code, h, c.state, c.a.ghidra) for h in ("claude-code", "opencode")]
    outs = []
    for p in procs:
        out, err = p.communicate(timeout=300)
        check(p.returncode == 0, f"harness process failed: {err[-2000:]}")
        outs.append(json.loads(out.strip().splitlines()[-1]))
    pids = {o["pid"] for o in outs}
    check(len(pids) == 1, f"two daemons were started: {outs}")
    check(outs[0]["client"] != outs[1]["client"], f"same client id: {outs}")
    c.timings["two harnesses: connect (one starts it)"] = [round(o["ms"]) for o in outs]
    with d.connect("checker", "tests") as s:
        t = time.perf_counter()
        s.call("ping")
        c.timings["warm connect + hello + ping"] = round((time.perf_counter() - t) * 1000, 1)
    d.stop()
    return f"one daemon (pid {pids.pop()}) for both; connect ms {[round(o['ms']) for o in outs]}"


@prebuilt("projB-dll-analysed", users=("two_projects",))
def proj_b(c, name):
    """Project B of two_projects: the dll imported and analysed (made once per run with a seed dir)."""
    def build(dst):
        d0 = c.daemon("multi-mk")
        with d0.connect("y", "tests") as y:
            gpr = c.make_project(y, dst, "ProjB")
            y.call("open_project", path=str(gpr), writable=True)
            y.call("import", file=c.a.dll, analyze=True, timeout=1800, wait=600000)
            y.call("close_project")
        d0.stop()
        return gpr
    return c.cached_project(name, "projB-dll-analysed", build, inputs=(c.a.dll,))


def t_two_projects(c: Ctx):
    """Several projects open in one daemon at once, used by two clients concurrently."""
    a_gpr = c.copy_fixture("projA")
    b_gpr = proj_b(c, "projB")
    d = c.daemon("multi")
    with d.connect("x", "tests") as x, d.connect("y", "tests") as y:
        y.call("open_project", path=str(b_gpr), writable=True)
        y.call("open_program", path=pathlib.Path(c.a.dll).name, writable=True)    # as the import left it
        pa = x.call("open_project", path=str(a_gpr))
        x.call("open_program", path=pathlib.Path(c.a.exe).name)
        pb = y.call("projects")["activeProject"]
        check(pa["id"] != pb, "one project id for two projects")
        analysed = None
        if c.a.project:
            analysed = x.call("open_project", path=c.a.project)
            progs = x.call("list", programsOnly=True)["entries"]
            check(progs, "the read-only project lists no program")
            t = time.perf_counter()
            x.call("open_program", path=progs[0]["path"])
            c.timings["extra project: open_program"] = round((time.perf_counter() - t) * 1000)
        errs = []

        def worker(s, key, n):
            try:
                fns = s.call("functions", program=key, limit=n)["functions"]
                for f in fns:
                    if not f["external"] and not f["thunk"]:
                        s.call("decompile", program=key, address=f["address"])
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        a_key = f"{pa['id']}:/{pathlib.Path(c.a.exe).name}"
        b_key = f"{pb}:/{pathlib.Path(c.a.dll).name}"
        t = time.perf_counter()
        ths = [threading.Thread(target=worker, args=(x, a_key, 15)),
               threading.Thread(target=worker, args=(y, b_key, 15))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check(not errs, f"concurrent work failed: {errs}")
        c.timings["two projects: 15+15 decompiles in parallel"] = round(
            (time.perf_counter() - t) * 1000)
        st = x.call("status")
        open_ids = {p["id"] for p in st["projects"]}
        want = 3 if analysed else 2
        check(len(open_ids) >= want, f"expected {want} projects open, status shows {open_ids}")
    d.stop()
    return f"{want} projects open in one daemon; parallel decompiles in two of them"


def t_dll_import(c: Ctx):
    """A DLL is imported, analysed, recognised as a PE, and never imported twice."""
    d = c.daemon("dll")
    with d.connect("dll", "tests") as s:
        gpr = c.make_project(s, c.work / "projDll", "Dll")
        s.call("open_project", path=str(gpr), writable=True)
        t = time.perf_counter()
        r = s.call("import", file=c.a.dll, folder="/libs", analyze=True, timeout=1800,
                   wait=600000)
        c.timings["dll import+analyze"] = round(time.perf_counter() - t, 1)
        check(r["imported"] and r["path"].startswith("/libs/"), f"bad import: {r}")
        info = s.call("info")
        check("PE" in (info["format"] or "") or "Portable" in (info["format"] or ""),
              f"not a PE: {info['format']}")
        check(info["functions"] > 0 and info["analyzed"], f"not analysed: {info}")
        again = s.call("import", file=c.a.dll)
        check(again["imported"] is False and again["existing"] == [r["path"]],
              f"imported twice: {again}")
        by_sha = s.call("list", sha256=r["sha256"])["entries"]
        check([e["path"] for e in by_sha] == [r["path"]], f"list sha256 filter: {by_sha}")
        s.call("save")
        s.call("close_project")
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=r["path"])  # a program inside a folder, by its path
    d.stop()
    return (f"{pathlib.Path(c.a.dll).name}: {info['format']}, {info['functions']} functions, "
            f"dedup by SHA-256 ok")


def t_client_kill(c: Ctx):
    """A client process that dies while it owns a program, with unsaved edits and an analysis
    running, releases everything: its analysis is cancelled, its edit discarded, its lock freed."""
    gpr = c.copy_fixture("projKill")
    d = c.daemon("kill")
    exe = pathlib.Path(c.a.exe).name
    with d.connect("survivor", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        entry = None
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='kill',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "info = s.call('open_program', path=A[3], writable=True)\n"
                "e = s.call('functions', limit=1)['functions'][0]['address']\n"
                "s.call('rename', address=e, name='doomed_rename')\n"
                "s.send('analyze', timeout=3600)\n"
                "print(json.dumps({'entry': e, 'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe)
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        child = json.loads(line)
        entry = child["entry"]
        time.sleep(1.0)
        st = s.call("status")
        held = [x for x in st["programs"] if x["path"] == "/" + exe]
        check(held and held[0]["owner"] == child["client"], f"child does not own it: {held}")
        check(held[0]["busy"], f"no analysis running: {held}")
        t = time.perf_counter()
        p.kill()
        p.wait()
        r = s.call("open_program", path=exe, writable=True, wait=60000)
        released = (time.perf_counter() - t) * 1000
        c.timings["killed client: lock released after"] = round(released)
        check(r["mine"] and r["mode"] == "writable", f"not released: {r}")
        check(not s.call("functions", contains="doomed_rename")["functions"],
              "the dead client's unsaved rename survived")
        st = s.call("status")
        check(all(cl["name"] != "doomed" for cl in st["clients"]), "dead client still listed")
    d.stop()
    return f"lock free {released:.0f} ms after the kill; unsaved edit discarded"


def t_daemon_restart(c: Ctx):
    """The daemon is killed while it holds a writable project; the next connect starts a fresh
    one, which opens the same project writable again."""
    gpr = c.copy_fixture("projRestart")
    d = c.daemon("restart")
    s = d.connect("before", "tests")
    s.call("open_project", path=str(gpr), writable=True)
    s.call("open_program", path=pathlib.Path(c.a.exe).name, writable=True)
    old_pid = s.endpoint["pid"]
    check(d.kill(), "kill failed")
    check(d.endpoint_file.exists(), "a killed JVM cannot remove its endpoint; expected stale file")
    try:
        s.call("ping")
        raise Fail("the old connection still answers")
    except c.gs.SessionError as e:
        check(e.code == "closed", f"unexpected error on the dead connection: {e}")
    except OSError:
        pass
    s.close()
    t = time.perf_counter()
    s2 = d.connect("after", "tests")
    c.timings["restart after kill (stale endpoint)"] = round((time.perf_counter() - t) * 1000)
    check(s2.endpoint["pid"] != old_pid, "the same pid answered")
    s2.call("open_project", path=str(gpr), writable=True)
    r = s2.call("open_program", path=pathlib.Path(c.a.exe).name, writable=True)
    check(r["functions"] > 0, "program empty after restart")
    s2.close()
    d.stop()
    return f"pid {old_pid} killed, pid {r and s2.endpoint['pid']} took over; project reopened writable"


def t_fairness(c: Ctx):
    """With 2 long slots, A queues 4 long jobs and B 1: B's quick query is not delayed, and B's
    long job is admitted before A's last one (round-robin by client)."""
    d = c.daemon("fair", maxLong=2)
    with d.connect("A", "tests") as A, d.connect("B", "tests") as B:
        gpr = c.copy_fixture("projFair")
        A.call("open_project", path=str(gpr))
        B.call("open_project", path=str(gpr))
        B.call("open_program", path=pathlib.Path(c.a.exe).name)
        fn = B.call("functions", limit=50)["functions"]
        addr = [f["address"] for f in fn if not f["thunk"] and not f["external"]][0]
        B.call("decompile", address=addr)  # warm
        ids = [A.send("script", script=c.script("TestSleep.java"), program=None,
                      args=["3000"], parallel=True, wait=60000) for _ in range(4)]
        time.sleep(0.5)
        bid = B.send("script", script=c.script("TestSleep.java"), program=None, args=["3000"],
                     parallel=True, wait=60000)
        time.sleep(0.3)
        t = time.perf_counter()
        B.call("decompile", address=addr, parallel=True)
        quick = (time.perf_counter() - t) * 1000
        sched = B.call("status")["scheduler"]["long"]
        check(sched["inUse"] == 2 and sched["queued"] == 3, f"long lane: {sched}")

        def start(r):
            return int(r["output"].split()[1])

        a = [start(A.wait(i)) for i in ids]
        b = start(B.wait(bid))
        c.timings["quick decompile while long lane is full"] = round(quick, 1)
        check(quick < 1000, f"quick query waited {quick:.0f} ms behind long work")
        check(b < max(a), f"B started at {b}, after all of A's {a}: not round-robin")
    d.stop()
    return f"quick query {quick:.1f} ms under a full long lane; B admitted before A's 4th"


def t_cancel_all(c: Ctx):
    """cancel {all:true} stops a client's running and queued requests, and only its own."""
    d = c.daemon("cancel", maxLong=1)
    with d.connect("A", "tests") as A, d.connect("B", "tests") as B:
        bid = B.send("script", script=c.script("TestSleep.java"), program=None, args=["4000"],
                     parallel=True, wait=60000)
        time.sleep(0.5)
        ids = [A.send("script", script=c.script("TestSleep.java"), program=None,
                      args=["60000"], parallel=True, wait=120000) for _ in range(3)]
        time.sleep(0.5)
        r = A.call("cancel", all=True)
        check(r["cancelled"] == 3, f"cancel all: {r}")
        codes = []
        for i in ids:
            try:
                A.wait(i)
                codes.append("ok")
            except c.gs.SessionError as e:
                codes.append(e.code)
        check(codes == ["cancelled"] * 3, f"A's requests: {codes}")
        B.wait(bid)  # B's own job was not touched
    d.stop()
    return "3 queued/running requests cancelled; the other client's job finished"


RAW_LANG = {"language": "DATA:LE:64:default", "compiler": "pointer64"}


def raw_file(c: Ctx, name: str, mb: int) -> str:
    """A file of random bytes, imported as a raw binary: an import whose length is set by its
    size, which is how the import queue is tested with a small system binary as the only
    fixture."""
    p = c.work / "raw" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists() or p.stat().st_size != mb << 20:
        with open(p, "wb") as f:
            for _ in range(mb):
                f.write(os.urandom(1 << 20))
    return str(p)


def wait_for(cond, what, timeout=120.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    raise Fail(f"timed out waiting for {what}")


def t_import_queue(c: Ctx):
    """With maxImports=1, imports run one at a time; the others queue in arrival order, say who
    they wait behind and for how long, and leave the queue when cancelled without disturbing the
    running one. (With more places the same queue forms behind maxImports running imports.)"""
    mb = c.a.raw_mb
    files = [raw_file(c, "q.bin", mb)] * 5  # one file, imported again each time (duplicate)
    d = c.daemon("iq", maxLong=2, maxImports=1)
    with d.connect("A", "agent-a") as A, d.connect("B", "agent-b") as B, \
            d.connect("C", "agent-c") as C:
        gpr = c.make_project(A, c.work / "projQueue", "Queue")
        for s in (A, B, C):
            s.call("open_project", path=str(gpr), writable=True)

        def imports(s=A):
            return s.call("status")["imports"]

        def start(s, i, name):
            return s.send("import", file=files[i], name=name, parallel=True, duplicate=True,
                          **RAW_LANG)

        # 1. A runs; B queues behind it and is cancelled while queued.
        ia = start(A, 0, "qa")
        wait_for(lambda: imports()["holder"], "A's import to hold the gate")
        ib = start(B, 1, "qb")
        st = wait_for(lambda: (imports() if imports()["queue"] else None), "B to queue")
        check(st["holder"]["client"] != st["queue"][0]["client"], f"holder/queue: {st}")
        check("agent-a" in st["holder"]["who"], f"the holder is not named: {st['holder']}")
        check("agent-b" in st["queue"][0]["who"], f"the waiter is not named: {st['queue']}")
        check(st["queue"][0]["position"] == 1, f"position: {st['queue']}")
        full = A.call("status")
        waiting = [r for cl in full["clients"] for r in cl["requests"]
                   if r["waiting"] == "import queue"]
        check(len(waiting) == 1 and waiting[0]["cmd"] == "import" and waiting[0]["queue"]["holder"],
              f"status.clients[].requests does not show the queued import: {waiting}")
        def pumped():  # events are read while the client waits on a response
            B.call("ping")
            return any(e.get("id") == ib and "waiting behind" in e.get("message", "")
                       for e in list(B.events))

        wait_for(pumped, "a 'waiting behind' progress event", 15, 0.2)
        ev = [e for e in B.events if e.get("id") == ib and "waiting behind" in e.get("message", "")][-1]
        check(ev.get("queue", {}).get("position") == 1, f"progress event without a queue: {ev}")
        r = B.call("cancel", target=ib)
        check(r["cancelled"] is True, f"cancel of the queued import: {r}")
        try:
            B.wait(ib)
            raise Fail("the cancelled queued import succeeded")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", f"queued cancel: {e}")
        check(not imports()["queue"], "the cancelled import is still queued")
        ra = A.wait(ia)  # the running import was not touched
        check(ra["imported"] is True, f"A's import: {ra}")
        check(ra["queue"]["behind"] is None, f"A waited behind someone: {ra['queue']}")
        h = imports()["history"]
        check(h["count"] == 1 and h["meanMs"] > 0, f"no duration history: {h}")

        # 2. The running import is cancelled; the queued one runs next. The estimate comes from
        #    the first import's duration.
        ia = start(A, 2, "qc")
        wait_for(lambda: imports()["holder"], "the next import to hold the gate")
        ib = start(B, 1, "qb")
        st = wait_for(lambda: (imports() if imports()["queue"] else None), "B to queue again")
        est = st["queue"][0]["estimatedWaitMs"]
        check(est is not None and est > 0, f"no wait estimate with history: {st['queue']}")
        t_run = time.time()
        check(A.call("cancel", target=ia)["cancelled"] is True, "cancel of the running import")
        try:
            A.wait(ia)
            raise Fail("the cancelled running import succeeded")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", f"running cancel: {e}")
        rb = B.wait(ib)  # the queued import ran next
        check(rb["imported"] is True and rb["queue"]["behind"], f"B's import: {rb}")
        check(rb["queue"]["positionAtEntry"] == 1, f"B's queue place: {rb['queue']}")
        check(not imports()["queue"] and not imports()["holder"], f"gate not free: {imports()}")
        names = {e["name"] for e in A.call("list", programsOnly=True)["entries"]}
        check(names == {"qa", "qb"}, f"programs after the cancels: {names}")
        c.timings["import queue: B waited (ms) / estimate when queued (ms)"] = [
            rb["queue"]["waitedMs"], est]
        c.timings[f"import queue: raw {mb} MB import (s)"] = round(rb["importSeconds"], 2)

        # 3. Two queued; the first is cancelled and the second moves up.
        ia = start(A, 2, "qc")
        wait_for(lambda: imports()["holder"], "the third import to hold the gate")
        ib = start(B, 3, "qd")
        wait_for(lambda: len(imports()["queue"]) == 1, "B to queue")
        ic = start(C, 4, "qe")
        q = wait_for(lambda: (imports()["queue"] if len(imports()["queue"]) == 2 else None),
                     "C to queue")
        check([e["position"] for e in q] == [1, 2] and "agent-b" in q[0]["who"],
              f"arrival order: {q}")
        B.call("cancel", target=ib)
        try:
            B.wait(ib)
        except c.gs.SessionError:
            pass
        q = imports()["queue"]
        check(len(q) == 1 and q[0]["position"] == 1 and "agent-c" in q[0]["who"],
              f"C did not move up: {q}")
        est_c = q[0]["estimatedWaitMs"]
        t_c = time.time()
        A.wait(ia)
        rc = C.wait(ic)
        check(rc["imported"] is True, f"C's import: {rc}")
        # from the estimate to C's start: until its answer, less its own load time (the open
        # that follows the load is small)
        actual = round((time.time() - t_c - rc["importSeconds"]) * 1000)
        c.timings["import queue: C wait estimated / actual (ms), taken once it was next"] = [
            est_c, actual]
    d.stop()
    return (f"one import at a time; queued cancel, running cancel and re-ordering ok "
            f"(B waited {rb['queue']['waitedMs']} ms, estimated {est} ms)")


def t_import_isolation(c: Ctx):
    """What two loads at once share: the library search path set is process-wide (whatever the
    project), and concurrent loads each handed their own project land in it. Runs
    ImportIsolationProbe in a throwaway daemon and records what it saw (README, "Parallel
    imports")."""
    return _import_isolation(c, ISO_ROUNDS)


ISO_ROUNDS, ISO_SHARDS = 6, 3     # concurrent-load rounds of import_isolation; its shards split them


def _import_isolation(c: Ctx, rounds: int):
    """import_isolation with ``rounds`` concurrent-load rounds (each shard repeats the search-path check)."""
    a = c.a.exe
    b = c.a.dll
    d = c.daemon("iso")
    shutil.copy(pathlib.Path(__file__).absolute().parent / "ImportIsolationProbe.java",
                c.scripts / "ImportIsolationProbe.java")  # scripts run from the script path
    probe = c.script("ImportIsolationProbe.java")
    with d.connect("iso", "tests") as s:
        folder = c.work / "projIso"
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        out = s.call("script", script=probe, program=None, args=[str(folder), a, b, str(rounds)],
                     timeout=900, wait=600000)["output"]
    d.stop()
    got = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    check(got.get("leak.pathVisibleWhileOtherProjectActive") == "true",
          f"expected the library search path set to be shared between projects: {out}")
    check(got.get("leak.pathInOtherProjectsSavedState") == "false",
          f"the path unexpectedly reached the other project's state: {out}")
    c.timings["import isolation probe"] = got
    return ("search path set is process-wide (leaks between projects); concurrent loads: " +
            f"{got.get('race.failures')} failures, {got.get('race.wrongProject')} misplaced, " +
            f"{got.get('race.activeProjectNotMineAfterLoad')} loads saw a foreign active project")


def program_paths(s, project=None):
    kw = {"project": project} if project else {}
    return sorted(e["path"] for e in s.call("list", programsOnly=True, metadata=False,
                                             **kw)["entries"])


def heap_sampler(s, stop, out):
    """Samples the daemon's used heap (status memory) every 0.25 s into out (MB values)."""
    while not stop.is_set():
        try:
            out.append(s.call("status")["memory"]["usedMb"])
        except Exception:  # noqa: BLE001
            return
        stop.wait(0.25)


def run_imports(c: Ctx, maxi: int, files: list, analyze: bool, tag: str, lang: dict):
    """Imports each file into its own new project, from its own client, all sent at once, in a
    daemon with maxImports=maxi; returns (wall s, [answers], peak used heap MB)."""
    d = c.daemon(f"speed{maxi}{tag}", maxImports=maxi, maxLong=max(2, len(files)))
    sessions = [d.connect(f"imp{i}", "tests") for i in range(len(files))]
    mon = None
    try:
        for i, s in enumerate(sessions):
            folder = c.work / f"projSpeed{maxi}{tag}{i}"
            if folder.exists():
                shutil.rmtree(folder)
            gpr = c.make_project(s, folder, f"Speed{i}")
            s.call("open_project", path=str(gpr), writable=True)
        stop, heap = threading.Event(), []
        mon = d.connect("heap", "tests")
        th = threading.Thread(target=heap_sampler, args=(mon, stop, heap))
        th.start()
        t = time.perf_counter()
        ids = [s.send("import", file=f, analyze=analyze, timeout=7200, wait=7_200_000,
                      parallel=True, **lang) for s, f in zip(sessions, files)]
        res = [s.wait(i) for s, i in zip(sessions, ids)]
        wall = time.perf_counter() - t
        peak_running = mon.call("status")["imports"]["history"]["peakRunning"]
        stop.set()
        th.join()
        return wall, res, (max(heap) if heap else None), peak_running
    finally:
        for s in sessions + ([mon] if mon else []):
            s.close()
        d.stop(force=True)


def t_import_speed(c: Ctx):
    """Several different binaries imported at once (maxImports = their count) against one at
    a time (maxImports=1): wall time, peak heap, and identical programs either way."""
    files = c.a.big or [raw_file(c, f"speed{i}.bin", c.a.raw_mb) for i in range(2)]
    analyze = bool(c.a.big_analyze)
    lang = {} if c.a.big else RAW_LANG
    seq = run_imports(c, 1, files, analyze, "s", lang)
    par = run_imports(c, len(files), files, analyze, "p", lang)
    check(seq[3] == 1, f"maxImports=1 ran {seq[3]} imports at once")
    check(par[3] == len(files), f"maxImports={len(files)} ran at most {par[3]} at once")

    def shape(r):
        p = r["program"]
        return (pathlib.Path(r["path"]).name, p.get("functions"), p.get("language"))

    check(sorted(map(shape, seq[1])) == sorted(map(shape, par[1])),
          f"programs differ: {[shape(r) for r in seq[1]]} vs {[shape(r) for r in par[1]]}")
    names = ", ".join(pathlib.Path(f).name for f in files)
    key = f"import speed ({names}{', analyze' if analyze else ''})"
    c.timings[key] = {"sequential s": round(seq[0], 1), "parallel s": round(par[0], 1),
                      "each s (parallel)": [round(r["importSeconds"], 1) for r in par[1]],
                      "peak heap MB seq/par": [seq[2], par[2]]}
    # Real binaries: loading is CPU work and must scale. Random raw files are mostly disk
    # writes, whose speed-up depends on the disk (reported, not checked). With analysis, the
    # gate covers the load and save only, so analyses overlap even with maxImports=1 (bounded
    # by maxLong) and the gain is the loads': checked not to be slower.
    if c.a.big and not analyze:
        check(par[0] < seq[0] * 0.85,
              f"parallel ({par[0]:.1f} s) not faster than sequential ({seq[0]:.1f} s)")
    elif c.a.big:
        check(par[0] <= seq[0] * 1.05,
              f"parallel ({par[0]:.1f} s) slower than sequential ({seq[0]:.1f} s)")
    return (f"{len(files)} imports: sequential {seq[0]:.1f} s, parallel {par[0]:.1f} s; "
            f"peak heap {seq[2]} / {par[2]} MB")


def t_parallel_imports(c: Ctx):
    """Imports run at once: into two projects, two files into one project (one new folder), the
    same file twice into one project (imported once), and a cancel that leaves the other one
    running."""
    mb = c.a.raw_mb
    f1, f2, f3 = (raw_file(c, f"par{i}.bin", mb) for i in range(3))
    d = c.daemon("par", maxImports=3, maxLong=4)
    notes = []
    with d.connect("A", "agent-a") as A, d.connect("B", "agent-b") as B:
        ga = c.make_project(A, c.work / "projParA", "ParA")
        gb = c.make_project(A, c.work / "projParB", "ParB")
        pa = A.call("open_project", path=str(ga), writable=True)["id"]
        pb = B.call("open_project", path=str(gb), writable=True)["id"]

        def imports():
            return A.call("status")["imports"]

        # 1. Two projects at once.
        ia = A.send("import", file=f1, name="a1", parallel=True, **RAW_LANG)
        ib = B.send("import", file=f2, name="b1", parallel=True, **RAW_LANG)
        st = wait_for(lambda: (imports() if len(imports()["running"]) == 2 else None),
                      "both imports to run at once", 60)
        check(not st["queue"] and st["maxImports"] == 3, f"import gate: {st}")
        check({r["project"] for r in st["running"]} == {pa, pb}, f"running: {st['running']}")
        ra, rb = A.wait(ia), B.wait(ib)
        check(ra["imported"] and rb["imported"], f"answers: {ra} {rb}")
        check(ra["queue"]["behind"] is None and rb["queue"]["behind"] is None,
              f"one waited for the other: {ra['queue']} {rb['queue']}")
        check(program_paths(A, pa) == ["/a1"] and program_paths(B, pb) == ["/b1"],
              "a program landed in the wrong project")
        notes.append(f"2 projects: {ra['importSeconds']:.1f}+{rb['importSeconds']:.1f} s overlapped")

        # 2. Two files into one project, into the same new folder, at once.
        B.call("open_project", path=str(ga), writable=True)
        ia = A.send("import", file=f2, folder="/new/sub", name="x", parallel=True, **RAW_LANG)
        ib = B.send("import", file=f3, folder="/new/sub", name="x", parallel=True, project=pa,
                    **RAW_LANG)
        wait_for(lambda: len(imports()["running"]) == 2, "two imports into one project", 60)
        ra, rb = A.wait(ia), B.wait(ib)
        paths = program_paths(A, pa)
        check(ra["imported"] and rb["imported"] and ra["path"] != rb["path"],
              f"same name, two files: {ra['path']} {rb['path']}")
        check(paths == sorted(["/a1", ra["path"], rb["path"]]), f"project content: {paths}")
        notes.append(f"1 project, 1 new folder: {ra['path']} + {rb['path']}")

        # 3. The same file twice into one project at once: imported once.
        ia = A.send("import", file=f3, parallel=True, **RAW_LANG)
        ib = B.send("import", file=f3, parallel=True, project=pa, **RAW_LANG)
        ra, rb = A.wait(ia), B.wait(ib)
        sha_paths = [e["path"] for e in A.call("list", sha256=ra["sha256"], project=pa)["entries"]]
        check(sha_paths == [rb["existing"][0]], f"SHA-256 matches: {sha_paths}")  # step 2's
        both = [ra, rb]
        check(all(r["imported"] is False for r in both), f"the same file again: {both}")
        # with a fresh file: one imports, the other waits for it and answers existing
        f4 = raw_file(c, "par3.bin", mb)
        ia = A.send("import", file=f4, name="once", parallel=True, **RAW_LANG)
        wait_for(lambda: imports()["running"], "the first import to run", 60)
        ib = B.send("import", file=f4, name="twice", parallel=True, project=pa, **RAW_LANG)
        ra, rb = A.wait(ia), B.wait(ib)
        check(ra["imported"] is True and rb["imported"] is False and
              rb["existing"] == [ra["path"]], f"same file at once: {ra} / {rb}")
        check(rb.get("sameFileImport", {}).get("who", "").find("agent-a") >= 0,
              f"the second did not wait for the first: {rb}")
        check("/twice" not in program_paths(A, pa), "the same file was imported twice")
        notes.append(f"same file at once: one import, the other waited "
                     f"{rb['sameFileImport']['waitedMs']} ms and answered existing")

        # 4. Cancel one of two running imports; the other completes. The cancel must land
        # during the load: once the import writes its program into the project it is no longer
        # cancellable (a fast machine loaded a 128 MB file in about 1.5 s), so the files are
        # larger and the cancel is sent soon after both run.
        f5, f6 = raw_file(c, "par4.bin", mb * 4), raw_file(c, "par5.bin", mb)
        ia = A.send("import", file=f5, name="cancelme", parallel=True, **RAW_LANG)
        ib = B.send("import", file=f6, name="keep", parallel=True, project=pa, **RAW_LANG)
        wait_for(lambda: len(imports()["running"]) == 2, "two imports running", 60)
        time.sleep(0.3)
        check(A.call("cancel", target=ia)["cancelled"] is True, "cancel")
        expect_error("cancelled", A.wait, ia)
        rb = B.wait(ib)
        check(rb["imported"] is True, f"the other import: {rb}")
        paths = program_paths(A, pa)
        check("/cancelme" not in paths and "/keep" in paths, f"after the cancel: {paths}")
        check(not imports()["running"] and not imports()["queue"], f"gate: {imports()}")
        notes.append("cancel of one running import left the other running to completion")
    d.stop()
    return "; ".join(notes)


def tmp_files(c: Ctx):
    tmp = c.work / "tmp"
    return {p for p in tmp.rglob("*") if p.is_file()} if tmp.exists() else set()


def t_import_kill(c: Ctx):
    """A client killed while its import runs (next to another client's import): its import is
    cancelled, leaves no program and no temporary file, the other completes. The daemon killed
    while two imports run: the next daemon opens the project, which holds no partial program,
    and the same files import again."""
    mb = c.a.raw_mb * 4  # long enough that the kills land while the imports run
    f1, f2 = raw_file(c, "kill0.bin", mb), raw_file(c, "kill1.bin", mb)
    d = c.daemon("ikill", maxImports=2, maxLong=4)
    folder = c.work / "projImpKill"
    if folder.exists():
        shutil.rmtree(folder)
    with d.connect("survivor", "tests") as s:
        gpr = c.make_project(s, folder, "ImpKill")
        pid = s.call("open_project", path=str(gpr), writable=True)["id"]
        before_tmp = tmp_files(c)
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='ikill',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "s.send('import', file=A[3], name='doomed', language='DATA:LE:64:default',"
                " compiler='pointer64', parallel=True)\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, f1)
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        child = json.loads(line)["client"]
        mine = s.send("import", file=f2, name="survives", parallel=True, **RAW_LANG)
        wait_for(lambda: len(s.call("status")["imports"]["running"]) == 2, "both imports", 60)
        time.sleep(0.5)
        t = time.perf_counter()
        p.kill()
        p.wait()
        wait_for(lambda: all(r["client"] != child for r in s.call("status")["imports"]["running"]),
                 "the dead client's import to stop", 60)
        gone = (time.perf_counter() - t) * 1000
        r = s.wait(mine)
        check(r["imported"] is True, f"the other import: {r}")
        paths = program_paths(s, pid)
        check(paths == ["/survives"], f"project after the kill: {paths}")
        s.call("close_program", program=r["key"])
        if c.a.tmpdir != "default":  # the dead import's temporary database files are gone
            wait_for(lambda: not (tmp_files(c) - before_tmp),
                     "the dead import's temporary files to go", 30)
        c.timings["killed client mid-import: its import stopped after (ms)"] = round(gone)
        # 2. the daemon dies while two imports run
        a = s.send("import", file=f1, name="k1", parallel=True, **RAW_LANG)
        b = s.send("import", file=f2, name="k2", parallel=True, duplicate=True, **RAW_LANG)
        wait_for(lambda: len(s.call("status")["imports"]["running"]) == 2, "two imports", 60)
        time.sleep(0.5)
        check(len(s.call("status")["imports"]["running"]) == 2, "an import ended before the kill")
        check(d.kill(), "kill failed")
    with d.connect("after", "tests") as s2:
        pid = s2.call("open_project", path=str(gpr), writable=True)["id"]
        paths = program_paths(s2, pid)
        check(paths == ["/survives"], f"a partial program survived the daemon's death: {paths}")
        r1 = s2.call("import", file=f1, name="k1", **RAW_LANG)
        check(r1["imported"] is True and r1["path"] == "/k1", f"re-import after restart: {r1}")
        s2.call("open_program", path="/survives")
    d.stop()
    return (f"killed client's import stopped {gone:.0f} ms after the kill, no program or temp "
            f"file left; killed daemon left no partial program, re-import ok")


def t_import_readers(c: Ctx):
    """A reader decompiles in a project while two imports run into that same project: its
    latency stays within the noise of the same reads without imports."""
    mb = c.a.raw_mb
    f1, f2 = raw_file(c, "rd0.bin", mb), raw_file(c, "rd1.bin", mb)
    gpr = c.copy_fixture("projReaders")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("readers", maxImports=2, maxLong=4)
    with d.connect("reader", "tests") as R, d.connect("importer", "tests") as W:
        W.call("open_project", path=str(gpr), writable=True)
        R.call("open_project", path=str(gpr), writable=True)
        R.call("open_program", path=exe)
        fns = [f["address"] for f in R.call("functions", limit=400)["functions"]
               if not f["external"] and not f["thunk"]][:60]
        check(fns, "no functions to decompile")
        for a in fns:  # warm
            R.call("decompile", address=a)

        def pass_ms():
            out = []
            for a in fns:
                t = time.perf_counter()
                R.call("decompile", address=a)
                out.append((time.perf_counter() - t) * 1000)
            return out

        base = pass_ms() + pass_ms()
        ids = [W.send("import", file=f, name=f"r{i}", parallel=True, **RAW_LANG)
               for i, f in enumerate((f1, f2))]
        wait_for(lambda: len(W.call("status")["imports"]["running"]) == 2, "imports", 60)
        during = []
        while len(W.call("status")["imports"]["running"]) == 2 and len(during) < 2000:
            during += pass_ms()
        for i in ids:
            W.wait(i)
        after = pass_ms() + pass_ms()

    def med(x):
        return sorted(x)[len(x) // 2]

    def p90(x):
        return sorted(x)[int(len(x) * 0.9)]

    noise = abs(med(after) - med(base))
    c.timings["decompile ms median/p90: before, during 2 imports, after"] = [
        [round(med(base), 1), round(p90(base), 1)], [round(med(during), 1), round(p90(during), 1)],
        [round(med(after), 1), round(p90(after), 1)], len(during)]
    check(len(during) >= len(fns), f"only {len(during)} decompiles while the imports ran")
    check(med(during) <= max(med(base), med(after)) * 1.5 + noise + 5,
          f"decompile median {med(during):.1f} ms during imports vs {med(base):.1f} before")
    d.stop()
    return (f"decompile median {med(base):.1f} ms before, {med(during):.1f} ms during two "
            f"imports into the same project, {med(after):.1f} ms after ({len(during)} during)")


def t_caller_labels(c: Ctx):
    """One connection, two callers: per-request labels name who holds a program or an import,
    in busy answers, status and ownership messages, and scope cancel."""
    gpr = c.copy_fixture("projLabels")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("labels", maxLong=4)
    with d.connect("mcp", "mcp-server") as S, d.connect("other", "tests") as T:
        a = S.labelled(client="agent-a", harness="claude-code")
        b = S.labelled(client="agent-b", harness="opencode")
        S.call("open_project", path=str(gpr), writable=True)
        T.call("open_project", path=str(gpr), writable=True)
        info = a.call("open_program", path=exe, writable=True)
        key = info["key"]
        # the owner is named as agent-a opened it
        try:
            T.call("open_program", path=exe, writable=True, wait=300)
            raise Fail("a second connection opened the program writable")
        except c.gs.SessionError as e:
            check(e.code == "not_owner" and "agent-a" in e.message, f"owner not named: {e}")
        # agent-a holds the program exclusively; agent-b's writable open is blocked by it
        sleep = a.send("script", script=c.script("TestSleep.java"), args=["6000"], program=key)
        wait_for(lambda: any(p["path"] == "/" + exe and p["busy"]
                             for p in S.call("status")["programs"]), "a's script to run")
        try:
            b.call("open_program", path=exe, writable=True, wait=300)
            raise Fail("agent-b's writable open was not blocked")
        except c.gs.SessionError as e:
            check(e.code == "busy", f"expected busy: {e}")
            check("agent-a" in (e.details.get("holder") or "") and "agent-b" not in e.message,
                  f"the holder is not agent-a: {e.details}")
        try:
            b.call("decompile", address="0x0", program=key, wait=300)
            raise Fail("agent-b's decompile was not blocked")
        except c.gs.SessionError as e:
            check(e.code == "busy" and "agent-a" in e.details.get("holder", ""),
                  f"decompile busy answer: {e} {e.details}")
        st = S.call("status")
        busy = [p for p in st["programs"] if p["path"] == "/" + exe][0]
        check("agent-a" in busy["busy"] and busy["ownerLabel"] and "agent-a" in busy["ownerLabel"],
              f"status does not name the holder: {busy}")
        reqs = [r for cl in st["clients"] for r in cl["requests"]]
        check(any(r["client"] == "agent-a" and r["cmd"] == "script" for r in reqs),
              f"status requests do not carry the label: {reqs}")
        me = b.call("status")["youAre"]
        check(me["client"] == "agent-b" and me["harness"] == "opencode" and me["labelled"],
              f"youAre: {me}")
        # cancel scoping: agent-b's cancel all does not reach agent-a's script or the other
        # label's requests
        sb = b.send("script", script=c.script("TestSleep.java"), args=["60000"], program=None)
        sa2 = a.send("script", script=c.script("TestSleep.java"), args=["60000"], program=None)
        wait_for(lambda: len([r for cl in S.call("status")["clients"] for r in cl["requests"]
                              if r["cmd"] == "script"]) == 3, "three scripts")
        check(b.cancel(sleep)["cancelled"] is False, "agent-b cancelled agent-a's request by id")
        r = b.cancel_all()
        check(r["cancelled"] == 1, f"agent-b's cancel all: {r}")
        try:
            b.wait(sb)
            raise Fail("agent-b's request survived its own cancel all")
        except c.gs.SessionError as e:
            check(e.code == "cancelled", str(e))
        left = {r["id"] for cl in S.call("status")["clients"] for r in cl["requests"]
                if r["cmd"] == "script"}
        check({sleep, sa2} <= left, f"agent-a's requests were cancelled: {left}")
        # an unlabelled cancel all is the connection's: everything that is left
        r = S.call("cancel", all=True)
        check(r["cancelled"] == 2, f"unlabelled cancel all: {r}")
        for rid in (sleep, sa2):
            try:
                a.wait(rid)
            except c.gs.SessionError as e:
                check(e.code == "cancelled", str(e))
    d.stop()
    return "labels named in busy, status and owner messages; cancel scoped per label"


def t_idle_shutdown(c: Ctx):
    """With idleTimeout, the daemon exits on its own once no client is connected."""
    d = c.daemon("idle", idleTimeout=3)
    with d.connect("x", "tests") as s:
        s.call("ping")
    t = time.perf_counter()
    while d.jvm_alive() and time.perf_counter() - t < 60:
        time.sleep(0.2)
    gone = time.perf_counter() - t
    check(not d.jvm_alive(), "daemon still running 60 s after the last client left")
    check(not d.endpoint_file.exists(), "endpoint file left behind after a clean exit")
    return f"exited {gone:.1f} s after the last client left (idleTimeout 3 s)"


def t_keep_warm(c: Ctx):
    """A read-only program stays open after its last user leaves, so the next client gets it at
    no cost; after keepWarm it is closed."""
    gpr = c.copy_fixture("projWarm")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("warm", keepWarm=4)
    with d.connect("first", "tests") as s:
        s.call("open_project", path=str(gpr))
        first = s.call("open_program", path=exe)
    with d.connect("second", "tests") as s:
        s.call("open_project", path=str(gpr))
        t = time.perf_counter()
        second = s.call("open_program", path=exe)
        warm_ms = (time.perf_counter() - t) * 1000
        check(second["openMs"] == 0, f"not warm: {second}")
    with d.connect("watch", "tests") as s:
        t = time.perf_counter()
        while time.perf_counter() - t < 40:
            if not s.call("status")["programs"]:
                break
            time.sleep(0.5)
        st = s.call("status")
        check(not st["programs"], f"still open after keepWarm: {st['programs']}")
    d.stop()
    c.timings["keep_warm: open_program cold / warm"] = [first["openMs"], round(warm_ms, 1)]
    return f"cold {first['openMs']} ms, warm {warm_ms:.1f} ms; closed after keepWarm"


def t_stdio(c: Ctx):
    """A private session over stdin/stdout, started by the launcher (no daemon, no socket)."""
    t = time.perf_counter()
    with c.gs.StdioSession(state=str(c.state), ghidra=c.a.ghidra,
                           stderr_path=str(c.work / "stdio.log")) as s:
        ready = (time.perf_counter() - t) * 1000
        st = s.call("status")
        check(st["listen"] is None and st["launch"]["mode"] in ("fast", "standard"), str(st))
    c.timings["stdio session ready"] = round(ready)
    return f"ready in {ready:.0f} ms ({st['launch']['mode']} mode)"


def own_project(folder: pathlib.Path, user: str = None):
    """Makes the copy of a project below ``folder`` owned by ``user`` (default: the user running
    the tests, which is the user of the daemon). Ghidra refuses a writable open of a project whose
    ``project.prp`` names another owner ("Project is owned by ..."), and a committed fixture names
    whoever made it: on another machine or a CI runner every test that opens a copy of it writable
    would fail. Only the OWNER value is rewritten, in copies, and the file keeps its modification
    time; returns how many files it changed."""
    if user is None:
        import getpass
        user = getpass.getuser()
    from xml.sax.saxutils import quoteattr
    xml_user = quoteattr(user)[1:-1].encode("utf-8")
    n = 0
    for prp in pathlib.Path(folder).glob("*.rep/project.prp"):
        data = prp.read_bytes()
        new = re.sub(rb'(<STATE NAME="OWNER" TYPE="string" VALUE=")[^"]*(")',
                     lambda m: m.group(1) + xml_user + m.group(2), data)
        if new != data:
            st = prp.stat()
            prp.write_bytes(new)
            # a project's revision includes the times of its files ("a touched file moves its
            # revision"), and every copy must have the revision of its source: keep the time
            os.utime(prp, ns=(st.st_atime_ns, st.st_mtime_ns))
            n += 1
    return n


def clone_tree(src: pathlib.Path, dst: pathlib.Path):
    """Copies a project folder; on Windows through CopyFileW, which block-clones on ReFS."""
    if dst.exists():
        shutil.rmtree(dst)
    copy = shutil.copy2
    if sys.platform == "win32":
        import ctypes

        def copy(a, b):
            if not ctypes.windll.kernel32.CopyFileW(str(a), str(b), False):
                raise OSError(f"CopyFileW {a} -> {b} failed: {ctypes.GetLastError()}")
    shutil.copytree(src, dst, copy_function=copy)


def tree_state(root: pathlib.Path) -> list:
    """Every file under root with size, time and, up to 1 MiB, content: proves nothing wrote."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out.append((str(p.relative_to(root)), st.st_size, st.st_mtime_ns,
                        p.read_bytes() if st.st_size <= 1 << 20 else None))
    return out


def build_of(s, build_id):
    """The upgrade cache build with this id from status, or None."""
    for b in s.call("status")["upgradeCache"]["builds"]:
        if b["id"] == build_id:
            return b
    return None


def wait_build(s, build_id, timeout=1800):
    """Waits until the build is no longer building; returns its status entry."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        b = build_of(s, build_id)
        check(b is not None, f"build {build_id} is not in status")
        if b["state"] != "building":
            return b
        time.sleep(0.1)
    raise Fail(f"build {build_id} still running after {timeout} s")


def wait_phase(s, build_id, phases, timeout=600):
    """Polls status until the build is in one of the phases; returns its entry (or the finished
    entry, when it ended first)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        b = build_of(s, build_id)
        if b is not None and (b["state"] != "building" or b.get("phase") in phases):
            return b
        time.sleep(0.02)
    raise Fail(f"build {build_id} never reached {phases}")


def key_dir_state(cache: pathlib.Path, key: str):
    """(entry.json's upgraded programs or None, published generations, temporary folders)."""
    d = cache / key
    entry = None
    if (d / "entry.json").is_file():
        entry = json.loads((d / "entry.json").read_text(encoding="utf-8")).get("upgraded")
    subs = [p.name for p in d.iterdir() if p.is_dir()] if d.is_dir() else []
    return (entry, sorted(n for n in subs if not n.endswith(".tmp")),
            sorted(n for n in subs if n.endswith(".tmp")))


def t_upgrade_cache(c: Ctx):
    """Read-only opens of a program saved in an older database format: the first open is
    upgraded in memory and answers at once, while a background build makes the upgraded copy
    that later opens use. Checks: current-format programs and an opted-out daemon do not use it;
    the first open takes in-memory time and starts the build; two concurrent opens make one
    build; a reopen after the build comes from the copy and is faster; a daemon killed mid-build
    leaves no entry and the next start builds cleanly; a stop mid-build is prompt; a source that
    changes during a build fails it and the next open retries; a queued build yields to clients'
    long work and can be cancelled; an older key's entry is pruned; the source is never written.
    The older-format part needs --legacy-project (a project saved by an older Ghidra, best a
    small one; the test works on block-cloned copies)."""
    cache = c.work / "upgrade-cache"
    if cache.exists():
        shutil.rmtree(cache)
    exe = pathlib.Path(c.a.exe).name
    cur = c.copy_fixture("projCurrent")
    d = c.daemon("upgrade", keepWarm=0, upgradeCacheDir=str(cache))
    notes = []
    with d.connect("cur", "tests") as s:
        st = s.call("status")["upgradeCache"]
        check(st["enabled"] and pathlib.Path(st["dir"]) == cache, f"cache not enabled: {st}")
        s.call("open_project", path=str(cur))
        r = s.call("open_program", path=exe)
        check(r["cachedUpgrade"] is False and r["cacheBuild"] == "none",
              f"a current-format program used the cache: {r}")
        check(not cache.exists() or not any(p.is_dir() for p in cache.iterdir()),
              "a current-format program made a cache entry")
    d.stop()
    notes.append("current format: not cached")
    if not c.a.legacy_project:
        return "; ".join(notes + ["older format: skipped (no --legacy-project)"])

    src = pathlib.Path(c.a.legacy_project)
    src = src.parent if src.suffix == ".gpr" else src

    def legacy_copy(name):
        dst = c.work / name
        clone_tree(src, dst)
        return dst

    # 1. opted out: the in-memory upgrade, which is also the first open's yardstick
    legacy = legacy_copy("legacy")
    before = tree_state(legacy)
    off = c.daemon("upgrade-off", keepWarm=0, upgradeCache=False)
    with off.connect("off", "tests") as s:
        check(not s.call("status")["upgradeCache"]["enabled"], "opt-out ignored")
        s.call("open_project", path=str(legacy))
        prog = c.a.legacy_program or s.call("list", programsOnly=True)["entries"][0]["path"]
        t = time.perf_counter()
        r = s.call("open_program", path=prog, wait=1800000)
        mem_ms = (time.perf_counter() - t) * 1000
        check(r["cachedUpgrade"] is False and r["cacheBuild"] == "none",
              f"opted out, yet: {r.get('upgradeCache')} {r.get('cacheBuild')}")
    off.stop()
    notes.append(f"opt-out: in memory {mem_ms:.0f} ms")

    # 2. two clients open it at once: one in-memory upgrade answers both, one build starts
    d = c.daemon("upgrade", keepWarm=3600, upgradeCacheDir=str(cache))
    with d.connect("a", "tests") as A, d.connect("b", "tests") as B:
        A.call("open_project", path=str(legacy))
        B.call("open_project", path=str(legacy))
        res, errs = {}, []

        def opener(name, s):
            try:
                t0 = time.perf_counter()
                res[name] = (s.call("open_program", path=prog, wait=1800000),
                             (time.perf_counter() - t0) * 1000)
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        ths = [threading.Thread(target=opener, args=(n, s)) for n, s in (("a", A), ("b", B))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check(not errs, f"concurrent opens failed: {errs}")
        answers = [res["a"][0], res["b"][0]]
        check(all(x["cachedUpgrade"] is False for x in answers),
              f"served from a cache that cannot exist yet: {answers}")
        started = [x for x in answers if x["cacheBuild"] == "started"]
        check(len(started) == 1, f"expected one open to start the build: "
              f"{[x['cacheBuild'] for x in answers]}")
        first_ms = res["a"][1] if res["a"][0] is started[0] else res["b"][1]
        check(first_ms < mem_ms * 1.5 + 2000,
              f"the first open took {first_ms:.0f} ms, the in-memory upgrade {mem_ms:.0f} ms")
        build_id = started[0]["cacheBuildInfo"]["id"]
        key = started[0]["cacheBuildInfo"]["key"]
        st = A.call("status")["upgradeCache"]
        check(st["buildsStarted"] == 1 and [b["id"] for b in st["builds"]] == [build_id],
              f"two opens made more than one build: {st}")
        b = wait_build(A, build_id)
        check(b["state"] == "ready", f"build failed: {b}")
        check(key_dir_state(cache, key) == ([prog], ["g1"], []), f"cache entry: "
              f"{key_dir_state(cache, key)}")
        held = [x for x in A.call("status")["programs"] if x["path"] == prog][0]
        check(held["cachedUpgrade"] is False and held["cacheBuild"] == "ready",
              f"switched while in use, or not ready: {held}")
        A.call("close_program")
        B.call("close_program")
        # nobody uses the in-memory program now: the next open takes the copy
        t = time.perf_counter()
        again = A.call("open_program", path=prog, wait=600000)
        reopen_ms = (time.perf_counter() - t) * 1000
        check(again["cachedUpgrade"] and again["upgradeCache"]["key"] == key and
              again["changed"] is False, f"reopen not from the copy: {again.get('upgradeCache')}")
        check(reopen_ms < first_ms, f"reopen {reopen_ms:.0f} ms, first open {first_ms:.0f} ms")
        fn = next(f for f in A.call("functions", limit=50)["functions"] if not f["external"])
        check(A.call("decompile", address=fn["address"]).get("c"),
              "no decompilation from the cached program")
    d.stop()
    check(tree_state(legacy) == before, "the source project was written")
    notes.append(f"first open {first_ms:.0f} ms (build started; 2 opens, 1 build), build "
                 f"{b['ms']} ms {b['phaseMs']}, reopen from the copy {reopen_ms:.0f} ms")
    c.timings["upgrade cache: in-memory / first open / build / reopen ms"] = [
        round(mem_ms), round(first_ms), b["ms"], round(reopen_ms)]

    # 3. killed mid-build: no entry; the next start builds cleanly
    legacy2 = legacy_copy("legacy2")
    d = c.daemon("upgrade", keepWarm=0, upgradeCacheDir=str(cache))
    s = d.connect("doomed", "tests")
    s.call("open_project", path=str(legacy2))
    r = s.call("open_program", path=prog, wait=1800000)
    check(r["cacheBuild"] == "started", f"no build started: {r.get('cacheBuild')}")
    key2, id2 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
    b = wait_phase(s, id2, ("upgrade", "save"))
    check(b["state"] == "building", f"the build ended before it could be killed: {b}")
    killed_in = b["phase"]
    check(d.kill(), "kill failed")
    s.close()
    entry, gens, tmps = key_dir_state(cache, key2)
    check(entry is None and not gens, f"a killed build left an entry: {entry} {gens}")
    with d.connect("after", "tests") as s:
        s.call("open_project", path=str(legacy2))
        r = s.call("open_program", path=prog, wait=True)  # waits for the build
        check(r["cachedUpgrade"] and r["upgradeCache"]["key"] == key2,
              f"the rebuild after the kill: {r.get('upgradeCache')} {r.get('cacheBuildInfo')}")
    check(key_dir_state(cache, key2) == ([prog], ["g1"], []),
          f"after the rebuild: {key_dir_state(cache, key2)}")
    notes.append(f"killed in {killed_in} ({len(tmps)} temporary folder left), rebuilt cleanly")

    # 4. stopped mid-build: prompt, and the temporary folder goes
    legacy3 = legacy_copy("legacy3")
    with d.connect("stopper", "tests") as s:
        s.call("open_project", path=str(legacy3))
        r = s.call("open_program", path=prog, wait=1800000)
        key3, id3 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        b = wait_phase(s, id3, ("upgrade", "save"))
        stopped_in = b["phase"] if b["state"] == "building" else b["state"]
    t = time.perf_counter()
    d.stop(force=True)
    stop_s = time.perf_counter() - t
    entry, gens, tmps = key_dir_state(cache, key3)
    check(stop_s < 10, f"stop took {stop_s:.1f} s during a build")
    check(stopped_in == "ready" or (entry is None and not gens and not tmps),
          f"a cancelled build left files: {entry} {gens} {tmps}")
    notes.append(f"stopped in {stopped_in} in {stop_s:.1f} s, temporary folder removed")

    # 5. a queued build yields to clients' long work; a source change fails it; cancel; prune
    legacy4 = legacy_copy("legacy4")
    d = c.daemon("upgrade-s", keepWarm=0, maxLong=1, upgradeCacheDir=str(cache))
    with d.connect("long", "tests") as L, d.connect("open", "tests") as s:
        sleep_id = L.send("script", script=c.script("TestSleep.java"), program=None,
                          args=["8000"], parallel=True, wait=60000)
        time.sleep(0.5)
        s.call("open_project", path=str(legacy4))
        r = s.call("open_program", path=prog, wait=1800000)
        key4, id4 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        b = wait_phase(s, id4, ("waiting for a long slot",), timeout=60)
        check(b["state"] == "building", f"the build did not wait for the client's job: {b}")
        gpr = next(legacy4.glob("*.gpr"))
        os.utime(gpr, (time.time(), time.time() + 5))  # the source changes meanwhile
        b = wait_build(s, id4)
        check(b["state"] == "failed" and "source changed" in (b["error"] or ""),
              f"a changed source did not fail the build: {b}")
        check(key_dir_state(cache, key4) == (None, [], []),
              f"the failed build left files: {key_dir_state(cache, key4)}")
        L.wait(sleep_id)
        # the next open, here one that joins the in-memory program, retries with the new key;
        # a queued build is cancellable
        sleep_id = L.send("script", script=c.script("TestSleep.java"), program=None,
                          args=["8000"], parallel=True, wait=60000)
        time.sleep(0.5)
        L.call("open_project", path=str(legacy4))
        r = L.call("open_program", path=prog, wait=1800000)
        check(r["cacheBuild"] == "started" and r["cacheBuildInfo"]["key"] != key4,
              f"the next open did not retry: {r.get('cacheBuild')} {r.get('cacheBuildInfo')}")
        key5, id5 = r["cacheBuildInfo"]["key"], r["cacheBuildInfo"]["id"]
        n = s.call("cancel", cacheBuild=r["key"])["cancelled"]
        b = wait_build(s, id5)
        check(n == 1 and b["state"] == "failed" and b["cancelled"],
              f"cancel did not stop the build: {n} {b}")
        L.wait(sleep_id)
        L.call("close_program")
        s.call("close_program")
        r = s.call("open_program", path=prog, wait=True)
        check(r["cachedUpgrade"] and r["upgradeCache"]["key"] == key5,
              f"no build after the cancel: {r.get('upgradeCache')} {r.get('cacheBuildInfo')}")
        s.call("close_program")
        # a changed source makes a new key; once that is built, the older entry is removed
        os.utime(gpr, (time.time(), time.time() + 10))
        r = s.call("open_program", path=prog, wait=True)
        key6 = r["upgradeCache"]["key"]
        check(r["cachedUpgrade"] and key6 != key5, f"changed source: {r.get('upgradeCache')}")
        s.call("close_project")
    d.stop()
    check(not (cache / key5).exists(), f"the older entry {key5} was not pruned")
    notes.append("queued build waited for the client's job; source change failed it; next open "
                 "retried; cancel stopped it; older entry pruned")
    return "; ".join(notes)


def t_holders(c: Ctx):
    """busy, conflict and not_owner name the holder (client, harness, command, how long) and the
    project or program, and suggest what to do (a fork where a fork is the answer)."""
    gpr = c.copy_fixture("projHolders")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("holders", keepWarm=0)
    notes = []
    with d.connect("reader-a", "harness-a") as a, d.connect("writer-b", "harness-b") as b:
        # writing to a read-only view: read_only, naming the project, suggesting a fork
        pa = a.call("open_project", path=str(gpr))
        b.call("open_project", path=str(gpr))
        e = expect_error("read_only", b.call, "open_program", path=exe, writable=True)
        dt = e.details
        check(dt.get("project") == pa["id"] and dt.get("gpr"), f"no project identity: {dt}")
        check(dt.get("suggest") == "fork_project" and
              dt.get("suggestion", {}).get("cmd") == "fork_project" and
              dt["suggestion"].get("project") == pa["id"] and dt["suggestion"].get("path") and
              dt.get("alternative") == "open_project writable", f"no fork suggestion: {dt}")
        notes.append("read_only names the project + suggests fork_project")
        a.call("close_project")
        b.call("close_project")
        # one writer per program: not_owner names the owner
        b.call("open_project", path=str(gpr), writable=True)
        b.call("open_program", path=exe, writable=True)
        a.call("open_project", path=str(gpr))   # joins the writable project read-only
        info = a.call("open_program", path=exe)
        e = expect_error("not_owner", a.call, "open_program", path=exe, writable=True)
        dt = e.details
        hi = dt.get("holderInfo") or {}
        check(hi.get("name") == "writer-b" and hi.get("harness") == "harness-b" and
              hi.get("command") == "open_program writable" and isinstance(hi.get("heldMs"), int),
              f"not_owner holder: {dt}")
        check(dt.get("program") == info["key"] and dt.get("sha256") == info["sha256"] and
              dt.get("gpr"), f"not_owner program identity: {dt}")
        check(dt.get("suggest") == "fork_project" and dt.get("owner") == b.hello["client"],
              f"not_owner suggestion/owner: {dt}")
        fn = a.call("functions", limit=1)["functions"][0]["address"]
        e = expect_error("not_owner", a.call, "rename", address=fn, name="x_not_mine")
        check((e.details.get("holderInfo") or {}).get("name") == "writer-b",
              f"rename not_owner: {e.details}")
        notes.append("not_owner names owner + program sha256")
        # busy: the owner's exclusive script holds the program; a reader that cannot wait is told
        # who holds it, doing what, for how long
        rid = b.send("script", script=c.script("TestSleep.java"), args=["4000"], parallel=True,
                     wait=60000)
        time.sleep(1.0)
        e = expect_error("busy", a.call, "decompile", address=fn, wait=200)
        dt = e.details
        hi = dt.get("holderInfo") or {}
        check(hi.get("name") == "writer-b" and "script" in (hi.get("command") or "") and
              hi.get("heldMs", 0) >= 500, f"busy holder: {dt}")
        check(dt.get("program") == info["key"] and dt.get("suggest") == "retry" and
              isinstance(dt.get("holder"), str), f"busy identity: {dt}")
        b.wait(rid)
        notes.append(f"busy names holder ({hi.get('command')}, {hi.get('heldMs')} ms)")
        b.call("close_project", discard=True)
        a.call("close_project")
    # another process holds the project's lock: conflict names it from Ghidra's lock file
    d2 = c.daemon("holders2")
    with d2.connect("other-process", "tests") as o, d.connect("late", "tests") as s:
        o.call("open_project", path=str(gpr), writable=True)
        e = expect_error("conflict", s.call, "open_project", path=str(gpr), writable=True)
        hi = e.details.get("holderInfo") or {}
        check(hi.get("live") is True and hi.get("user") and hi.get("lockFile"),
              f"lock holder: {e.details}")
        check(e.details.get("suggest") == "open_read_only", f"lock suggestion: {e.details}")
        notes.append("project lock of another process named (user, host, since)")
    d2.stop()
    d.stop()
    return "; ".join(notes)


def tree_state(folder):
    """{relative path: (size, mtime_ns)} of every file below a folder."""
    folder = pathlib.Path(folder)
    return {str(f.relative_to(folder)): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in folder.rglob("*") if f.is_file()}


def t_fork_timing(c: Ctx):
    """With the engine setting forkTiming (PROTOCOL-3.md A67 a) a fork's reply carries stepsMs:
    the time of each step, in the order the steps ran. The reply is otherwise the reply of a
    fork without it (t_fork checks that the default reply has no stepsMs)."""
    src = c.copy_fixture("projForkSrc")
    forks = c.work / "forks-timing"
    if forks.exists():
        shutil.rmtree(forks)
    d = c.daemon("fork-timing", keepWarm=0, engine={"forkTiming": True})
    with d.connect("timer", "harness-a") as a:
        pa = a.call("open_project", path=str(src))
        r = a.call("fork_project", project=pa["id"], path=str(forks / "t1"), mode="full",
                   open=False, wait=600000)
        steps = r.get("stepsMs")
        check(isinstance(steps, dict), f"no stepsMs with forkTiming: {sorted(r)}")
        names = list(steps)
        want = ["cost", "revision", "copy", "recheck", "force", "commit", "complete"]
        order = [names.index(k) for k in want if k in names]
        check(all(k in names for k in want) and order == sorted(order),
              f"stepsMs steps {names}, want {want} in that order")
        check(all(isinstance(v, (int, float)) and v >= 0 for v in steps.values()),
              f"stepsMs values: {steps}")
        a.call("close_project")
    d.stop(force=True)
    return "stepsMs " + ", ".join(f"{k} {v}" for k, v in steps.items())


def t_fork(c: Ctx):
    """fork_project makes a working copy while the master's read-only view stays open and in
    use: the fork is writable by its maker, records its source and base revision, and leaves the
    master byte-identical. A source someone else writes is refused, naming the writer."""
    src = c.copy_fixture("projForkSrc")
    exe = pathlib.Path(c.a.exe).name
    forks = c.work / "forks"
    if forks.exists():
        shutil.rmtree(forks)
    before = tree_state(src.parent)
    d = c.daemon("fork", keepWarm=0)
    notes = []
    with d.connect("reader", "harness-a") as a, d.connect("writer", "harness-b") as b:
        pa = a.call("open_project", path=str(src))
        a.call("open_program", path=exe)
        fn = a.call("functions", limit=1)["functions"][0]
        a.call("decompile", address=fn["address"])
        # the reader keeps its view; the writer forks the master it has not even joined
        t = time.perf_counter()
        r = b.call("fork_project", project=pa["id"], path=str(forks / "b1"), wait=600000)
        c.timings["fork_project (small project)"] = round((time.perf_counter() - t) * 1000)
        check(r["project"] != pa["id"] and r["writable"] and r["info"]["writable"],
              f"fork not opened writable: {r}")
        check(r["source"]["project"] == pa["id"] and r["source"]["gpr"] and
              r["source"]["revision"] == r["baseRevision"] and len(r["baseRevision"]) == 16,
              f"fork source: {r['source']}")
        check(r["bytes"] > 0 and r["files"] > 0 and r["method"] in ("clone", "copy") and
              isinstance(r["cloned"], bool) and r["depth"] == 1, f"fork cost: {r}")
        check(pathlib.Path(r["gpr"]).is_file() and pathlib.Path(r["sidecar"]).is_file(),
              f"fork files: {r}")
        side = json.loads(pathlib.Path(r["sidecar"]).read_text())
        check(side["baseRevision"] == r["baseRevision"] and side["source"]["gpr"] and
              side["by"]["name"] == "writer", f"sidecar: {side}")
        check(not list(forks.glob("*/.*.tmp")), "a temporary folder was left")
        check("stepsMs" not in r, f"stepsMs in a reply without forkTiming: {sorted(r)}")
        notes.append(f"fork {r['bytes']} bytes/{r['files']} files by {r['method']} "
                     f"(cloned {r['cloned']}) in {r['copyMs']} ms")
        # the reader's view is unaffected and still answers
        a.call("decompile", address=fn["address"])
        st = a.call("project")
        check(st["id"] == pa["id"] and a.hello["client"] in st["users"], f"reader view: {st}")
        info = b.call("project", project=r["project"])
        check(info["fork"] and info["fork"]["baseRevision"] == r["baseRevision"] and
              info["fork"]["source"]["gpr"] == r["source"]["gpr"], f"project.fork: {info}")
        # the writer edits and saves its fork; the master and its view do not change
        b.call("open_program", path=exe, writable=True)
        b.call("rename", address=fn["address"], name="fork_only_name")
        b.call("save")
        check(not a.call("functions", contains="fork_only_name")["functions"],
              "the fork's rename shows in the master's view")
        check(b.call("functions", contains="fork_only_name")["functions"],
              "the fork's rename is missing in the fork")
        # fork of a fork: an unsaved change is refused, a saved one is forked
        b.call("rename", address=fn["address"], name="fork_unsaved")
        expect_error("unsaved_changes", b.call, "fork_project", project=r["project"],
                     path=str(forks / "b2"))
        b.call("save")
        r2 = b.call("fork_project", project=r["project"], path=str(forks / "b2" / "Second.gpr"),
                    wait=600000)
        check(r2["depth"] == 2 and r2["name"] == "Second" and r2["source"]["fork"] and
              r2["source"]["project"] == r["project"], f"fork of a fork: {r2}")
        side2 = json.loads(pathlib.Path(r2["sidecar"]).read_text())
        check(side2["parent"]["baseRevision"] == r["baseRevision"], f"lineage: {side2}")
        notes.append("fork of a fork records its lineage")
        # a destination that holds a project is refused
        e = expect_error("conflict", b.call, "fork_project", project=pa["id"],
                         path=str(forks / "b1"))
        check("already exists" in e.message, f"existing destination: {e}")
        # copy-on-write is promised only where the file system clones; auto refuses large
        # full copies; full always copies
        try:
            r3 = b.call("fork_project", project=pa["id"], path=str(forks / "cow"),
                        mode="copy-on-write", wait=600000)
            check(r3["method"] == "clone", f"copy-on-write fork was not a clone: {r3}")
            cow = f"copy-on-write: clone, cloned={r3['cloned']}"
        except c.gs.SessionError as e:
            check(e.code == "conflict" and e.details.get("reason") == "no_copy_on_write" and
                  e.details.get("bytes", 0) > 0, f"copy-on-write refusal: {e} {e.details}")
            cow = f"copy-on-write refused here ({e.details.get('destinationFileSystem')})"
        try:
            r4 = b.call("fork_project", project=pa["id"], path=str(forks / "auto0"),
                        maxCopyMb=0, wait=600000)
            check(r4["method"] == "clone", f"auto over the limit without a clone: {r4}")
        except c.gs.SessionError as e:
            check(e.code == "conflict" and e.details.get("reason") == "too_large" and
                  e.details.get("suggest") == "mode full", f"auto refusal: {e} {e.details}")
        r5 = b.call("fork_project", project=pa["id"], path=str(forks / "full"), mode="full",
                    maxCopyMb=0, writable=False, wait=600000)
        check(not r5["info"]["writable"], f"a read-only fork opened writable: {r5}")
        notes.append(cow)
        # a source that another client writes is refused, naming it
        with d.connect("third", "harness-c") as x:
            x.call("open_project", path=r["gpr"])  # joins b's writable fork
            e = expect_error("conflict", x.call, "fork_project", project=r["project"],
                             path=str(forks / "x1"))
            names = [h.get("name") for h in e.details.get("holders", [])]
            check("writer" in names and e.details.get("suggest") == "retry",
                  f"writer not named: {e.details}")
            x.call("close_project")
        notes.append("a source written by another client is refused, naming it")
        a.call("close_project")
        for pid in (r["project"], r2["project"], r5["project"]):
            b.call("close_project", project=pid, discard=True)
    # another process holds the source writable: refused, naming it from its lock file
    d2 = c.daemon("fork2")
    with d2.connect("other-process", "tests") as o, d.connect("late", "tests") as s:
        o.call("open_project", path=str(forks / "b1" / "Fixture.gpr"), writable=True)
        e = expect_error("conflict", s.call, "fork_project",
                         project=str(forks / "b1" / "Fixture.gpr"), path=str(forks / "y1"))
        check((e.details.get("holderInfo") or {}).get("live") is True,
              f"lock holder: {e.details}")
    d2.stop()
    d.stop()
    check(tree_state(src.parent) == before, "the master project changed")
    notes.append("master byte-identical")
    return "; ".join(notes)


def t_revisions(c: Ctx):
    """Projects and programs carry revisions; a read-only view whose project another process
    saved is marked stale on its clients' next answers; refresh reopens it for all of them at
    once (the others are told once); a fork starts at its source's revision."""
    gpr = c.copy_fixture("projRev")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("rev", keepWarm=0)
    notes = []
    with d.connect("reader-a", "tests") as a, d.connect("reader-b", "tests") as b:
        pa = a.call("open_project", path=str(gpr))
        rev0 = pa["revision"]
        check(isinstance(rev0, str) and len(rev0) == 16 and pa["diskRevision"] == rev0 and
              pa["stale"] is False and pa["generation"] == 1, f"open_project revision: {pa}")
        b.call("open_project", path=str(gpr))
        ia = a.call("open_program", path=exe)
        b.call("open_program", path=exe)
        check(len(ia["revision"]) == 16 and ia["projectRevision"] == rev0 and
              ia["generation"] == 1, f"open_program revision: {ia}")
        st = a.call("status")
        check([p["revision"] for p in st["projects"]] == [rev0] and
              [p["revision"] for p in st["programs"]] == [ia["revision"]],
              f"status revisions: {st['projects']} {st['programs']}")
        fn = a.call("functions", limit=1)["functions"][0]
        # another process saves the project (a second daemon, writable)
        d2 = c.daemon("rev-writer")
        with d2.connect("writer", "tests") as w:
            w.call("open_project", path=str(gpr), writable=True)
            w.call("open_program", path=exe, writable=True)
            w.call("rename", address=fn["address"], name="saved_elsewhere")
            w.call("save")
            w.call("close_project")
        d2.stop()
        # the readers' next answers say their view is stale; their view is unchanged
        r = a.call_raw("functions", contains="saved_elsewhere")
        check(not r["result"]["functions"], "the old view shows the new save")
        stale = r.get("stale") or []
        check(len(stale) == 1 and stale[0]["project"] == pa["id"] and
              stale[0]["revision"] == rev0 and stale[0]["diskRevision"] != rev0 and
              stale[0]["suggest"] == "refresh", f"no stale marker: {r}")
        check(a.call("project")["stale"] is True, "project.stale is not set")
        notes.append("stale marker after another process saved")
        # one reader refreshes; both see the new revision, the other is told once
        t = time.perf_counter()
        rf = b.call("refresh")
        c.timings["refresh (1 program reopened)"] = round((time.perf_counter() - t) * 1000)
        check(rf["refreshed"] and rf["from"] == rev0 and rf["revision"] != rev0 and
              rf["generation"] == 2 and rf["programs"][0]["action"] == "reopened",
              f"refresh: {rf}")
        check(b.call("functions", contains="saved_elsewhere")["functions"],
              "the refreshing reader does not see the save")
        r = a.call_raw("functions", contains="saved_elsewhere")
        check(r["result"]["functions"], "the other reader does not see the save after refresh")
        told = r.get("refreshed") or []
        check(len(told) == 1 and told[0]["project"] == pa["id"] and told[0]["from"] == rev0 and
              told[0]["generation"] == 2 and not r.get("stale"), f"refreshed marker: {r}")
        r = a.call_raw("info")
        check(not r.get("refreshed") and not r.get("stale") and
              r["result"]["projectRevision"] == rf["revision"] and
              r["result"]["generation"] == 2, f"told twice, or info stale: {r}")
        check(a.call("decompile", address=fn["address"])["name"] == "saved_elsewhere",
              "decompile after refresh")
        again = a.call("refresh")
        check(again["refreshed"] is False and again["reason"] == "unchanged", f"again: {again}")
        notes.append(f"refresh switched both readers in {c.timings['refresh (1 program reopened)']}"
                     " ms; the other was told once")
        # a fork starts at its source's revision; a save in the fork moves only the fork
        fk = a.call("fork_project", project=pa["id"], path=str(c.work / "projRevFork"),
                    wait=600000)
        fi = a.call("project", project=fk["project"])
        check(fk["baseRevision"] == rf["revision"] and fi["revision"] == fk["baseRevision"],
              f"fork revision: {fk['baseRevision']} {fi['revision']} {rf['revision']}")
        a.call("open_program", path=f"{fk['project']}:/{exe}", writable=True)
        a.call("rename", address=fn["address"], name="fork_change")
        sv = a.call("save")
        check(sv["projectRevision"] != fk["baseRevision"] and
              a.call("project", project=pa["id"])["revision"] == fk["baseRevision"],
              f"fork save: {sv}")
        notes.append("fork starts at its source's revision")
        # a writable project needs no refresh
        wr = a.call("refresh", project=fk["project"])
        check(wr["refreshed"] is False and "writable" in wr["reason"], f"writable: {wr}")
        a.call("close_project", project=fk["project"])
        a.call("close_project")
        b.call("close_project")
    d.stop()
    shutil.rmtree(c.work / "projRevFork", ignore_errors=True)
    return "; ".join(notes)


def t_overlays(c: Ctx):
    """Client-scoped overlays: two clients with different overlays on one shared program see
    different names, a third (and the owners without an overlay) see the canonical program; an
    operation that fails rolls back its whole call; killing an overlay's owner leaves the shared
    program untouched; promote writes an overlay into a fork; a refresh rebuilds overlays."""
    gpr = c.copy_fixture("projOverlay")
    exe = pathlib.Path(c.a.exe).name
    before = tree_state(gpr.parent)
    d = c.daemon("overlay", keepWarm=0)
    notes = []
    with d.connect("agent-a", "harness-a") as a, d.connect("agent-b", "harness-b") as b, \
            d.connect("plain", "harness-c") as x:
        for s in (a, b, x):
            s.call("open_project", path=str(gpr))
        t = time.perf_counter()
        ia = a.call("open_program", path=exe, overlay="agent-a")
        c.timings["overlay open (small program, shared program already open: no)"] = round(
            (time.perf_counter() - t) * 1000)
        check(ia["overlay"]["name"] == "agent-a" and ia["overlay"]["overlayVersion"] == 0 and
              ia["overlay"]["sha256"] == ia["sha256"] and ia["mode"] == "read_only",
              f"overlay open: {ia}")
        t = time.perf_counter()
        ib = b.call("open_program", path=exe, overlay="agent-b")
        c.timings["overlay open (small program, shared program open)"] = round(
            (time.perf_counter() - t) * 1000)
        x.call("open_program", path=exe)
        fns = [f for f in x.call("functions", limit=50)["functions"]
               if not f["thunk"] and not f["external"]]
        fn, fn2 = fns[0], fns[1]
        canon = x.call("decompile", address=fn["address"])["name"]
        ra = a.call("apply_overlay", overlay="agent-a", ops=[
            {"op": "rename", "address": fn["address"], "name": "a_name"},
            {"op": "comment", "address": fn["address"], "text": "agent a was here", "type": "plate"},
            {"op": "label", "address": fn2["address"], "name": "a_label"}])
        check(ra["applied"] == 3 and ra["overlay"]["overlayVersion"] == 1 and
              ra["overlay"]["ops"] == 3, f"apply_overlay: {ra}")
        rb = b.call("rename", overlay="agent-b", address=fn["address"], name="b_name")
        check(rb["overlay"]["overlayVersion"] == 1, f"overlay rename: {rb}")
        # each sees its own; the plain client and the owners' plain view see the canonical one
        check(a.call("decompile", overlay="agent-a", address=fn["address"])["name"] == "a_name",
              "agent a does not see its name")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name",
              "agent b does not see its name")
        check(x.call("decompile", address=fn["address"])["name"] == canon,
              "the plain client sees an overlay's name")
        check(a.call("decompile", address=fn["address"])["name"] == canon,
              "agent a's plain view sees its overlay")
        check(not x.call("functions", contains="a_name")["functions"] and
              not x.call("functions", contains="b_name")["functions"],
              "an overlay name leaked into the shared program")
        check(a.call("functions", overlay="agent-a", contains="a_name")["functions"] and
              not a.call("functions", overlay="agent-a", contains="b_name")["functions"],
              "overlay functions")
        inf = a.call("info", overlay="agent-a")
        check(inf["mode"] == "overlay" and inf["changed"] and inf["overlay"]["overlayVersion"] == 1
              and x.call("info")["changed"] is False, f"overlay info: {inf}")
        check(a.call("info")["overlays"] == ["agent-a"], "info does not list the overlay")
        notes.append("two overlays, two names; the shared program unchanged")
        # an overlay is private to its client: another client cannot use agent-a's
        expect_error("not_found", b.call, "decompile", overlay="agent-a", address=fn["address"])
        # a failing operation rolls back its whole call
        e = expect_error("bad_request", a.call, "apply_overlay", overlay="agent-a", ops=[
            {"op": "rename", "address": fn2["address"], "name": "never_applied"},
            {"op": "signature", "address": fn["address"], "signature": "this is ( not C"}])
        check(e.details.get("index") == 1 and e.details.get("rolledBack") is True,
              f"failure details: {e.details}")
        check(not a.call("functions", overlay="agent-a", contains="never_applied")["functions"],
              "a failed call left a change")
        check(a.call("info", overlay="agent-a")["overlay"]["overlayVersion"] == 1,
              "a failed call bumped the version")
        r = a.call("apply_overlay", overlay="agent-a", ops=[
            {"op": "signature", "address": fn["address"], "signature": "int a_name(int x)"},
            {"op": "data_type", "address": "rva:0x3c", "type": "dword"}])
        check("a_name(int x)" in r["results"][0]["signature"] and
              r["results"][1]["length"] == 4 and r["overlay"]["overlayVersion"] == 2,
              f"signature/data_type: {r}")
        check("int x" not in x.call("decompile", address=fn["address"])["signature"] or
              "int x" in canon, "the signature leaked")
        notes.append("a failing op rolls back the whole call")
        st = x.call("status")
        ovs = {(o["client"], o["name"]) for o in st["overlays"]}
        check((a.hello["client"], "agent-a") in ovs and (b.hello["client"], "agent-b") in ovs,
              f"status overlays: {st['overlays']}")
        # killing an overlay's owner drops its overlay and leaves the shared program untouched
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='overlay',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2])\n"
                "s.call('open_program', path=A[3], overlay='doomed')\n"
                "s.call('rename', overlay='doomed', address=A[4], name='doomed_name')\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, fn["address"])
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        doomed = json.loads(line)["client"]
        p.kill()
        p.wait()
        for _ in range(100):
            if all(o["client"] != doomed for o in x.call("status")["overlays"]):
                break
            time.sleep(0.1)
        check(all(o["client"] != doomed for o in x.call("status")["overlays"]),
              "the dead client's overlay is still listed")
        check(not x.call("functions", contains="doomed_name")["functions"] and
              x.call("decompile", address=fn["address"])["name"] == canon,
              "the dead client's overlay touched the shared program")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name",
              "another overlay was disturbed")
        notes.append("killed owner: overlay dropped, shared program untouched")
        # promote writes the overlay into a fork; the master stays as it was
        pr = a.call("promote_overlay", overlay="agent-a",
                    fork={"path": str(c.work / "projOverlayFork")}, wait=600000)
        check(pr["promoted"] == 5 and pr["fork"]["project"] == pr["project"] and
              pr["saved"]["saved"], f"promote: {pr}")
        fk = pr["target"]
        check(a.call("decompile", program=fk, address=fn["address"])["name"] == "a_name" and
              a.call("functions", program=fk, contains="a_label")["functions"],
              "the promoted fork lacks the overlay's changes")
        check(x.call("decompile", address=fn["address"])["name"] == canon,
              "promote changed the master")
        a.call("close_project", project=pr["project"])
        notes.append("promote_overlay replayed 5 ops into a fork and saved it")
        # a refresh rebuilds overlays from their logs
        d2 = c.daemon("overlay-writer")
        with d2.connect("writer", "tests") as w:
            w.call("open_project", path=str(gpr), writable=True)
            w.call("open_program", path=exe, writable=True)
            w.call("rename", address=fn2["address"], name="saved_elsewhere")
            w.call("save")
            w.call("close_project")
        d2.stop()
        before = tree_state(gpr.parent)  # the master was changed on purpose by another process
        rf = x.call("refresh")
        check(rf["refreshed"], f"refresh: {rf}")
        ob = b.call("info", overlay="agent-b")["overlay"]
        check(ob["error"] is None and not ob["stale"], f"overlay after refresh: {ob}")
        check(b.call("decompile", overlay="agent-b", address=fn["address"])["name"] == "b_name" and
              b.call("functions", overlay="agent-b", contains="saved_elsewhere")["functions"],
              "the rebuilt overlay lacks its change or the new save")
        notes.append("refresh rebuilt the overlays")
        dr = a.call("drop_overlay", overlay="agent-a")
        check(dr["dropped"] and dr["ops"] == 5, f"drop: {dr}")
        expect_error("not_found", a.call, "info", overlay="agent-a")
        for s in (a, b, x):
            s.call("close_project")
    d.stop()
    check(tree_state(gpr.parent) == before, "the master project changed")
    shutil.rmtree(c.work / "projOverlayFork", ignore_errors=True)
    return "; ".join(notes)


COMMENTS = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
public class TestComments extends GhidraScript {
    @Override protected void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address at = currentProgram.getAddressFactory().getAddress(a);
            String c = currentProgram.getListing().getComment(CommentType.EOL, at);
            println("C|" + a + "|" + (c == null ? "" : c));
        }
    }
}
"""


def comments_at(s, addresses, program=None):
    """{address: EOL comment} through a contained script."""
    path = s_scripts_dir / "TestComments.java"
    if not path.exists():
        path.write_text(COMMENTS)
    kw = {"program": program} if program else {}
    out = s.call("script", script=str(path), args=list(addresses), maxChars=16_000_000,
                 wait=120000, **kw)["output"]
    res = {}
    for line in out.splitlines():
        if line.startswith("C|"):
            _, a, text = line.split("|", 2)
            res[a] = text
    return res


def names_at(s, program=None):
    kw = {"program": program} if program else {}
    return {f["address"]: f["name"] for f in
            s.call("functions", limit=10000, **kw)["functions"]}


def code_functions(s, n, program=None):
    kw = {"program": program} if program else {}
    return [f["address"] for f in s.call("functions", limit=10000, **kw)["functions"]
            if not f["thunk"] and not f["external"]][:n]


MW_ITERS, MW_SHARDS = 300, 3     # edit rounds of each writer in multi_writer; its shards split them


@prebuilt("fixture-dll-analysed", users=("multi_writer",))
def proj_mw(c, name):
    """multi_writer's project: the fixture with the dll imported and analysed (made once per run with a seed dir)."""
    def build(dst):
        gpr = c.copy_fixture(dst.name)
        d0 = c.daemon("mw-setup")
        with d0.connect("setup", "tests") as s:
            s.call("open_project", path=str(gpr), writable=True)
            s.call("import", file=c.a.dll, analyze=True, timeout=1800, wait=600000)
            s.call("close_project")
        d0.stop()
        return gpr
    return c.cached_project(name, "fixture-dll-analysed", build, inputs=(c.a.exe, c.a.dll))


def t_multi_writer(c: Ctx):
    return _multi_writer(c, 0, MW_ITERS)


def _multi_writer(c: Ctx, first: int, count: int):
    """Several writers in one project: a writable open while others hold the read-only view
    reopens it writable in place (the readers keep their keys and go on); a second writable
    open joins; two clients write two different programs of the project at the same time
    (renames, comments, saves) independently; a writer of a program another client owns gets
    not_owner with overlay/fork alternatives; the project reopens with both writers' work."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    exe, dll = pathlib.Path(c.a.exe).name, pathlib.Path(c.a.dll).name

    gpr = proj_mw(c, "projMW")
    d = c.daemon("mw", keepWarm=0)
    notes = []
    with d.connect("reader", "tests") as r, d.connect("w1", "tests") as w1, \
            d.connect("w2", "tests") as w2:
        pr = r.call("open_project", path=str(gpr))
        ri = r.call("open_program", path=exe)
        fn = code_functions(r, 1)[0]
        canon = r.call("decompile", address=fn)["name"]
        p1 = w1.call("open_project", path=str(gpr), writable=True)
        check(p1["id"] == pr["id"] and p1["writable"], f"not reopened writable in place: {p1}")
        check(r.call("decompile", address=fn)["name"] == canon and
              r.call("info")["key"] == ri["key"], "the reader lost its program")
        check(r.call("project")["writable"], "the reader does not see the writable project")
        notes.append("writable open while a reader holds the view: reopened in place")
        p2 = w2.call("open_project", path=str(gpr), writable=True)
        check(p2["id"] == pr["id"], f"second writable open did not join: {p2}")
        k1 = w1.call("open_program", path=exe, writable=True)["key"]
        k2 = w2.call("open_program", path=dll, writable=True)["key"]
        e = expect_error("not_owner", w2.call, "open_program", path=exe, writable=True)
        check(e.details.get("alternatives") == ["overlay", "fork_project"] and
              e.details.get("overlaySuggestion", {}).get("overlay") and
              (e.details.get("holderInfo") or {}).get("name") == "w1",
              f"not_owner alternatives: {e.details}")
        f1 = code_functions(w1, 30, k1)
        f2 = code_functions(w2, 30, k2)
        errs = []
        want = {k1: {}, k2: {}}

        def writer(s, key, fns, tag):
            try:
                for i in range(first, first + count):
                    a = fns[i % len(fns)]
                    name = f"{tag}_{i}"
                    s.call("rename", program=key, address=a, name=name, wait=120000)
                    want[key][a] = name
                    s.call("comment", program=key, address=a, text=f"{tag} {i}", wait=120000)
                    if i % 50 == 49:
                        s.call("save", program=key, wait=120000)
                    if i == 150:  # a bounded analysis of each program, at the same time
                        s.call("analyze", program=key, ranges=[[a, a]], timeout=600,
                               wait=600000)
                s.call("save", program=key, wait=120000)
            except Exception as ex:  # noqa: BLE001
                errs.append(f"{tag}: {ex!r}")

        t = time.perf_counter()
        ths = [threading.Thread(target=writer, args=(w1, k1, f1, "w1")),
               threading.Thread(target=writer, args=(w2, k2, f2, "w2"))]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        c.timings["two writers, two programs: 2x(300 renames + 300 comments + 7 saves)"] = round(
            time.perf_counter() - t, 1)      # the whole test; a shard has its share
        check(not errs, f"concurrent writers failed: {errs}")
        notes.append(f"2 writers x {2 * count} edits + saves on 2 programs in "
                     f"{c.timings['two writers, two programs: 2x(300 renames + 300 comments + 7 saves)']} s")
        for s in (r, w1, w2):
            s.call("close_project")
    d.stop()
    # the project reopens clean, with both writers' work
    d2 = c.daemon("mw-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        for key, prog in ((k1, exe), (k2, dll)):
            s.call("open_program", path=prog)
            names = names_at(s)
            bad = {a: (n, names.get(a)) for a, n in want[key].items() if names.get(a) != n}
            check(not bad, f"{prog}: names lost after reopen: {list(bad.items())[:5]}")
    d2.stop()
    notes.append("project reopened with every saved name of both writers")
    return "; ".join(notes)


def t_shared(c: Ctx):
    """Shared mode: several clients write the same program; every change is journalled with
    its author; expect turns a lost update into a conflict naming the last editor; owner and
    shared mode do not mix; discard_edits reverts one client's changes; a writer that dies
    keeps everyone's committed work, also when it was the last writer (the work waits, unsaved,
    for a client to save it)."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projShared")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("shared", keepWarm=0)
    notes = []
    with d.connect("agent-a", "harness-a") as a, d.connect("agent-b", "harness-b") as b, \
            d.connect("agent-c", "harness-c") as x:
        for s in (a, b, x):
            s.call("open_project", path=str(gpr), writable=True)
        io = a.call("open_program", path=exe, writable=True)      # owner mode first
        check(io["mode"] == "writable" and io["mine"], f"owner open: {io}")
        e = expect_error("not_owner", b.call, "open_program", path=exe, writable=True, share=True)
        check(e.details.get("alternatives") == ["overlay", "fork_project"], f"{e.details}")
        ia = a.call("open_program", path=exe, writable=True, share=True)  # the owner shares it
        ib = b.call("open_program", path=exe, writable=True, share=True)
        check(ia["mode"] == "shared" and ib["writers"] == [a.hello["client"], b.hello["client"]],
              f"shared open: {ib}")
        f = code_functions(a, 6)
        names0 = names_at(a)
        r1 = a.call("rename", address=f[0], name="a_first")
        r2 = b.call("rename", address=f[1], name="b_second")
        b.call("comment", address=f[1], text="b was here")
        check(names_at(b)[f[0]] == "a_first" and names_at(a)[f[1]] == "b_second",
              "writers do not see each other's changes")
        check(r1["seq"] < r2["seq"], f"journal order: {r1} {r2}")
        # owner and shared mode do not mix; a non-writer is told to join
        e = expect_error("conflict", x.call, "open_program", path=exe, writable=True)
        check(e.details.get("suggest") == "share", f"mixing modes: {e.details}")
        x.call("open_program", path=exe)
        e = expect_error("not_owner", x.call, "rename", address=f[0], name="x_nope")
        check(e.details.get("suggest") == "share", f"non-writer: {e.details}")
        # a lost update becomes a conflict naming who changed it
        b.call("rename", address=f[0], name="b_over_a", expect="a_first")
        e = expect_error("conflict", a.call, "rename", address=f[0], name="a_again",
                         expect="a_first")
        check(e.details.get("current") == "b_over_a" and
              (e.details.get("holderInfo") or {}).get("name") == "agent-b" and
              e.details.get("suggest") == "reread", f"expect conflict: {e.details}")
        notes.append("expect: a lost update is a conflict naming the last editor")
        an = b.call("analyze", ranges=[[f[5], f[5]]], timeout=600, wait=600000)
        check(an["seq"] > 0, f"analyze by a shared writer: {an}")
        j = a.call("journal")
        ops = [(x_["op"], x_["name"], x_.get("address")) for x_ in j["entries"]]
        check(("rename", "agent-a", f[0]) in ops and ("comment", "agent-b", f[1]) in ops and
              any(o[0] == "analyze" and o[1] == "agent-b" for o in ops) and
              j["seq"] == len(j["entries"]), f"journal: {j}")
        # discard_edits reverts one client's changes, newest first, and keeps the others'
        dr = a.call("discard_edits", author=b.hello["client"])
        names = names_at(a)
        check(names[f[0]] == "a_first" and names[f[1]] == names0[f[1]] and
              len(dr["reverted"]) == 3, f"discard_edits: {dr} {names[f[0]]} {names[f[1]]}")
        check(comments_at(a, [f[1]])[f[1]] == "", "b's comment was not reverted")
        notes.append("discard_edits reverted b's 3 changes, kept a's")
        # a writer that dies: its committed work stays
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='shared',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "s.call('open_program', path=A[3], writable=True, share=True)\n"
                "s.call('rename', address=A[4], name='doomed_kept')\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, f[2])
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        p.kill()
        p.wait()
        time.sleep(1.0)
        check(names_at(a)[f[2]] == "doomed_kept", "a dead writer's committed change was lost")
        notes.append("a dead writer's committed change stays")
        a.call("save")
        # the last writer dies with unsaved changes: they are kept for a client to save
        b.call("rename", address=f[3], name="b_unsaved")
        a.call("close_program")
        x.call("close_program")
        p = c.child(code.replace("'doomed_kept'", "'last_writer'"), c.state, c.a.ghidra, gpr,
                    exe, f[4])
        line = p.stdout.readline()
        check(line, "second child did not start")
        b.call("close_project")   # not the last writer: leaves fine, its change unsaved
        p.kill()
        p.wait()
        for s in (a, x):
            s.call("close_project")
        time.sleep(2.5)  # past the reaper (keepWarm 0)
        st = a.call("status")
        held = [pg for pg in st["programs"] if pg["path"] == "/" + exe]
        check(held and held[0]["mode"] == "shared" and held[0]["writers"] == [] and
              held[0]["orphanedMs"] is not None and held[0]["unsavedEdits"] >= 2,
              f"orphaned work not kept: {held}")
        notes.append("the last writer died: unsaved work kept, project stays open")
        a.call("open_project", path=str(gpr), writable=True)
        ia = a.call("open_program", path=exe, writable=True, share=True)
        check(ia["unsavedEdits"] >= 2 and names_at(a)[f[3]] == "b_unsaved" and
              names_at(a)[f[4]] == "last_writer", f"adopted work: {ia}")
        a.call("save")
        a.call("close_project")
    d.stop()
    d2 = c.daemon("shared-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        check(names[f[0]] == "a_first" and names[f[2]] == "doomed_kept" and
              names[f[3]] == "b_unsaved" and names[f[4]] == "last_writer",
              f"after reopen: {[names[x_] for x_ in f[:5]]}")
    d2.stop()
    notes.append("reopened: every kept change saved")
    return "; ".join(notes)


def t_shared_stress(c: Ctx):
    """4 clients x 2 threads write one shared program at once: 3200 renames and comments,
    with saves in between. No deadlock, no failed or lost committed edit: the journal has every
    edit once, in commit order; the program holds, per address, the value of the last edit; it
    reopens clean with all of it."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projStress")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("stress", keepWarm=0)
    # protocol 2 on purpose (E3b, amendment A-E3b-1): eight writers wait at once for one program
    # lock with a wait of 300 s, and a protocol 3 connection is refused beyond max(2, slots/4)
    # waiters (busy lock_queue_full, PROTOCOL-3.md 3.5, 3.10); this test does not retry, and it is
    # about the shared mode's journal and order. The protocol 3 half, with the retry a client does,
    # is dt_e3b.shared_stress_v3.
    sessions = [c.connect(d, f"agent-{i}", f"harness-{i}", 2) for i in range(4)]
    for s in sessions:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("open_program", path=exe, writable=True, share=True)
    fns = code_functions(sessions[0], 40)
    done, errs = [], []
    lock = threading.Lock()

    def worker(s, cid, t):
        try:
            for i in range(400):
                a = fns[(cid * 7 + t * 13 + i) % len(fns)]
                if i % 2 == 0:
                    r = s.call("rename", address=a, name=f"s{cid}_{t}_{i}", parallel=True,
                               wait=300000)
                    item = (r["seq"], a, "name", f"s{cid}_{t}_{i}")
                else:
                    r = s.call("comment", address=a, text=f"c{cid}_{t}_{i}", parallel=True,
                               wait=300000)
                    item = (r["seq"], a, "comment", f"c{cid}_{t}_{i}")
                with lock:
                    done.append(item)
                if i % 50 == 49:
                    s.call("save", parallel=True, wait=300000)
        except Exception as ex:  # noqa: BLE001
            errs.append(f"{cid}/{t}: {ex!r}")

    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(s, cid, t)) for cid, s in enumerate(sessions)
           for t in range(2)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(timeout=1800)
    secs = time.perf_counter() - t0
    check(not any(th.is_alive() for th in ths), "a writer hung (deadlock?)")
    check(not errs, f"edits failed: {errs[:5]}")
    c.timings["shared stress: 3200 edits by 8 writers"] = round(secs, 1)
    check(len(done) == 3200, f"{len(done)} edits done")
    s0 = sessions[0]
    j = s0.call("journal", limit=100000)
    seqs = [e["seq"] for e in j["entries"]]
    check(len(seqs) == 3200 and len(set(seqs)) == 3200 and seqs == sorted(seqs) and
          {x[0] for x in done} == set(seqs), f"journal: {len(seqs)} entries")
    last = {}
    for seq, a, field, value in sorted(done):
        last[(a, field)] = value
    names = names_at(s0)
    comments = comments_at(s0, fns)
    bad = [(k, v) for k, v in last.items()
           if (names.get(k[0]) if k[1] == "name" else comments.get(k[0])) != v]
    check(not bad, f"the program does not hold the last edit: {bad[:5]}")
    s0.call("save", wait=300000)
    for s in sessions:
        s.call("close_project")
        s.close()
    d.stop()
    d2 = c.daemon("stress-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        comments = comments_at(s, fns)
        bad = [(k, v) for k, v in last.items()
               if (names.get(k[0]) if k[1] == "name" else comments.get(k[0])) != v]
        check(not bad, f"after reopen: {bad[:5]}")
    d2.stop()
    return (f"3200 edits by 4 clients x 2 threads with 64 saves in {secs:.1f} s "
            f"({3200 / secs:.0f}/s); journal complete and ordered; reopened with every last "
            f"value")


SYMBOLS = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
public class TestSymbols extends GhidraScript {
    @Override protected void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address at = currentProgram.getAddressFactory().getAddress(a);
            StringBuilder b = new StringBuilder();
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(at)) {
                if (s.isDynamic()) continue;
                b.append(b.length() > 0 ? "," : "").append(s.getName());
            }
            println("S|" + a + "|" + b);
        }
    }
}
"""


def symbols_at(s, addresses, program=None):
    """{address: [names of the non-dynamic symbols there]} through a contained script."""
    path = s_scripts_dir / "TestSymbols.java"
    if not path.exists():
        path.write_text(SYMBOLS)
    kw = {"program": program} if program else {}
    out = s.call("script", script=str(path), args=list(addresses), maxChars=16_000_000,
                 wait=120000, **kw)["output"]
    res = {}
    for line in out.splitlines():
        if line.startswith("S|"):
            _, a, names = line.split("|", 2)
            res[a] = [n for n in names.split(",") if n]
    return res


def free_addresses(s, fns, n, program=None):
    """n addresses inside functions (not entries) with no symbol: places for new labels."""
    cands = []
    for f in fns:
        base = int(f, 16)
        cands += [hex(base + k) for k in (1, 2, 3)]
    syms = symbols_at(s, cands, program)
    free = [a for a in cands if not syms.get(a)]
    check(len(free) >= n, f"not enough free addresses: {syms}")
    return free[:n]


def t_edit(c: Ctx):
    """The edit command: several operations in one call, all or none; expect turns a lost
    update into a conflict naming who made the change; a non-writer is refused. discard_edits
    reverts one author's renames, comments and newly created labels (the label is deleted) and
    keeps everyone else's; the project reopens with exactly the kept changes."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projEdit")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("edit", keepWarm=0)
    notes = []
    with d.connect("agent-a", "harness-a") as a, d.connect("agent-b", "harness-b") as b, \
            d.connect("reader", "harness-r") as x:
        for s in (a, b):
            s.call("open_project", path=str(gpr), writable=True)
            s.call("open_program", path=exe, writable=True, share=True)
        x.call("open_project", path=str(gpr))
        x.call("open_program", path=exe)
        f = code_functions(a, 6)
        names0 = names_at(a)
        lab_a, lab_b, lab_b2 = free_addresses(a, f, 3)
        # several operations, one call, each journalled
        r = a.call("edit", ops=[
            {"op": "rename", "address": f[0], "name": "ed_a0"},
            {"op": "comment", "address": f[1], "text": "a note"},
            {"op": "label", "address": lab_a, "name": "ed_label_a"}])
        check(r["applied"] == 3 and len(r["seqs"]) == 3 and r["seqs"] == sorted(r["seqs"]) and
              r["unsavedEdits"] == 3 and r["results"][2]["created"] is True, f"edit: {r}")
        check(names_at(b)[f[0]] == "ed_a0" and symbols_at(b, [lab_a])[lab_a] == ["ed_label_a"] and
              comments_at(b, [f[1]])[f[1]] == "a note", "the other writer does not see the edit")
        notes.append("3 ops in one edit, journalled")
        # b changes f0 after a; a's edit that expects its own old value fails as a whole
        b.call("rename", address=f[0], name="b_over_a", expect="ed_a0")
        seq0 = a.call("journal")["seq"]
        e = expect_error("conflict", a.call, "edit", ops=[
            {"op": "rename", "address": f[2], "name": "never_applied"},
            {"op": "comment", "address": f[3], "text": "never applied either"},
            {"op": "rename", "address": f[0], "name": "a_again", "expect": "ed_a0"}])
        dt = e.details
        check(dt.get("index") == 2 and dt.get("rolledBack") is True and
              dt.get("reason") == "changed" and dt.get("current") == "b_over_a" and
              (dt.get("holderInfo") or {}).get("name") == "agent-b" and
              (dt.get("holderInfo") or {}).get("harness") == "harness-b" and
              (dt.get("lastEdit") or {}).get("client") == b.hello["client"] and
              dt.get("suggest") == "reread", f"edit expect conflict: {dt}")
        check(names_at(a)[f[2]] == names0[f[2]] and comments_at(a, [f[3]])[f[3]] == "" and
              names_at(a)[f[0]] == "b_over_a", "a refused edit left a change")
        check(a.call("journal")["seq"] == seq0, "a refused edit was journalled")
        # a writer's script that changes nothing is not a change (the program has unsaved
        # changes from before: they are not the script's)
        rs = a.call("script", script=str(s_scripts_dir / "TestComments.java"), args=[f[0]])
        check(rs["changed"] is False and rs["unsaved"] is True and
              a.call("journal")["seq"] == seq0, f"a read-only script was a change: {rs}")
        # a comment's expect names its author too
        e = expect_error("conflict", b.call, "edit", ops=[
            {"op": "comment", "address": f[1], "text": "b's", "expect": None}])
        check(e.details.get("current") == "a note" and
              (e.details.get("holderInfo") or {}).get("name") == "agent-a",
              f"comment expect: {e.details}")
        # an operation that fails for another reason also undoes the call
        e = expect_error("bad_request", a.call, "edit", ops=[
            {"op": "label", "address": lab_b2, "name": "never_label"},
            {"op": "signature", "address": f[4], "signature": "this is ( not C"}])
        check(e.details.get("index") == 1 and not symbols_at(a, [lab_b2])[lab_b2],
              f"a failing op left its call's label: {e.details}")
        notes.append("all or none: a stale expect or a bad op refuses the whole call, naming "
                     "the last editor")
        # a client that is not a writer of the shared program
        e = expect_error("not_owner", x.call, "edit", ops=[
            {"op": "rename", "address": f[5], "name": "x_nope"}])
        check(e.details.get("suggest") == "share", f"non-writer edit: {e.details}")
        # discard_edits: b's rename, comment, a label b created with edit and one with rename
        rb = b.call("edit", ops=[
            {"op": "label", "address": lab_b, "name": "b_new_label"},
            {"op": "comment", "address": f[5], "text": "b comment"}])
        check(rb["results"][0]["created"] is True, f"label not created: {rb}")
        rr = b.call("rename", address=lab_b2, name="b_label_by_rename", kind="label")
        check(rr["created"] is True, f"rename kind label: {rr}")
        check(symbols_at(a, [lab_b, lab_b2]) == {lab_b: ["b_new_label"],
                                                 lab_b2: ["b_label_by_rename"]},
              "b's labels are not there")
        dr = a.call("discard_edits", author=b.hello["client"])
        syms = symbols_at(a, [lab_a, lab_b, lab_b2])
        check(syms[lab_b] == [] and syms[lab_b2] == [],
              f"discard_edits left b's new labels: {syms} {dr}")
        check(syms[lab_a] == ["ed_label_a"], f"discard_edits touched a's label: {syms}")
        names = names_at(a)
        check(names[f[0]] == "ed_a0" and comments_at(a, [f[5]])[f[5]] == "" and
              comments_at(a, [f[1]])[f[1]] == "a note",
              f"discard_edits: {dr} {names[f[0]]}")
        check(len(dr["reverted"]) == 4 and not dr["skipped"], f"discard_edits answer: {dr}")
        j = a.call("journal", author=a.hello["client"])["entries"]
        check(any(x_["op"] == "label" and x_.get("deleted") for x_ in j),
              f"the label's deletion is not journalled: {j[-5:]}")
        notes.append("discard_edits deleted b's 2 new labels and reverted its rename and "
                     "comment; a's kept")
        a.call("save")
        for s in (a, b, x):
            s.call("close_project")
    d.stop()
    d2 = c.daemon("edit-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        syms = symbols_at(s, [lab_a, lab_b, lab_b2])
        check(names[f[0]] == "ed_a0" and names[f[2]] == names0[f[2]] and
              syms == {lab_a: ["ed_label_a"], lab_b: [], lab_b2: []} and
              comments_at(s, [f[1], f[5]]) == {f[1]: "a note", f[5]: ""},
              f"after reopen: {names[f[0]]} {syms}")
    d2.stop()
    notes.append("reopened with exactly the kept changes")
    return "; ".join(notes)


def t_overlay_owned(c: Ctx):
    """An overlay of a program another client owns writable: a client refused with not_owner
    takes the suggested overlay; its changes stay in the overlay while the owner keeps
    writing; the overlay is over the stored program (not the owner's unsaved changes); the
    owner saves while the overlay is open (twice) and the overlay keeps working; nothing of the
    overlay reaches the owner's program or the saved project."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projOvOwned")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("ovowned", keepWarm=0)
    notes = []
    with d.connect("owner", "harness-o") as o, d.connect("guest", "harness-g") as g:
        o.call("open_project", path=str(gpr), writable=True)
        key = o.call("open_program", path=exe, writable=True)["key"]
        f = code_functions(o, 4)
        canon = names_at(o)
        o.call("rename", address=f[0], name="owner_unsaved")
        g.call("open_project", path=str(gpr))
        e = expect_error("not_owner", g.call, "open_program", path=exe, writable=True)
        sug = e.details.get("overlaySuggestion") or {}
        check(sug.get("cmd") == "open_program" and sug.get("overlay"), f"no overlay: {e.details}")
        t = time.perf_counter()
        gi = g.call("open_program", path=sug["path"], overlay=sug["overlay"])
        open_ms = (time.perf_counter() - t) * 1000
        ov = sug["overlay"]
        check(gi["overlay"]["name"] == ov and gi["mine"] is False, f"overlay open: {gi}")
        r = g.call("apply_overlay", overlay=ov, ops=[
            {"op": "rename", "address": f[1], "name": "guest_idea"},
            {"op": "comment", "address": f[1], "text": "guest's hypothesis", "type": "plate"}])
        check(r["applied"] == 2, f"apply_overlay: {r}")
        check(g.call("decompile", overlay=ov, address=f[1])["name"] == "guest_idea",
              "the overlay does not show its change")
        check(names_at(o)[f[1]] == canon[f[1]], "the overlay reached the owner's program")
        check(g.call("decompile", overlay=ov, address=f[0])["name"] == canon[f[0]],
              "the overlay shows the owner's unsaved change (it is over the stored program)")
        check(names_at(g)[f[0]] == "owner_unsaved", "the guest's plain view lost the owner's work")
        expect_error("not_owner", g.call, "rename", program=key, address=f[2], name="nope")
        notes.append(f"not_owner -> overlay ({open_ms:.0f} ms); private; over the stored file")
        # the owner saves while the overlay is open: both go on
        sv = o.call("save")
        check(sv["saved"], f"save: {sv}")
        g.call("rename", overlay=ov, address=f[3], name="guest_second")
        check(g.call("decompile", overlay=ov, address=f[1])["name"] == "guest_idea" and
              g.call("decompile", overlay=ov, address=f[3])["name"] == "guest_second",
              "the overlay broke when the owner saved")
        o.call("rename", address=f[2], name="owner_saved_twice")
        check(o.call("save")["saved"], "second save")
        oi = g.call("info", overlay=ov)
        check(oi["overlay"]["error"] is None and oi["overlay"]["overlayVersion"] == 2,
              f"overlay after two saves: {oi['overlay']}")
        # the overlay keeps the program as it was stored when the overlay opened
        snap = g.call("decompile", overlay=ov, address=f[0])["name"]
        notes.append(f"after the owner's saves the overlay shows f0 as "
                     f"{'its snapshot' if snap == canon[f[0]] else 'saved since'}")
        check(snap in (canon[f[0]], "owner_unsaved"), f"overlay f0: {snap}")
        check(o.call("info")["changed"] is False and
              names_at(o)[f[1]] == canon[f[1]] and names_at(o)[f[3]] == canon[f[3]],
              "the overlay reached the owner's program")
        notes.append("owner saved twice with the overlay open; overlay intact")
        # the owner leaves: the guest keeps its read-only use and its overlay
        o.call("close_project")
        check(g.call("decompile", overlay=ov, address=f[1])["name"] == "guest_idea",
              "the overlay died with the owner's close")
        check(g.call("drop_overlay", overlay=ov)["dropped"], "drop")
        g.call("close_project")
    d.stop()
    d2 = c.daemon("ovowned-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr))
        s.call("open_program", path=exe)
        names = names_at(s)
        check(names[f[0]] == "owner_unsaved" and names[f[2]] == "owner_saved_twice" and
              names[f[1]] == canon[f[1]] and names[f[3]] == canon[f[3]],
              f"after reopen: {[names[a_] for a_ in f]}")
    d2.stop()
    notes.append("reopened: the owner's saves, nothing of the overlay")
    return "; ".join(notes)


def t_refresh_force(c: Ctx):
    """refresh of an unchanged view is a no-op unless force: force reopens it anyway, for all
    its clients (same keys, generation bumped, the others told once with refreshed), and
    rebuilds their overlays from their logs; the project is not written."""
    gpr = c.copy_fixture("projForce")
    exe = pathlib.Path(c.a.exe).name
    before = tree_state(gpr.parent)
    d = c.daemon("force", keepWarm=0)
    with d.connect("a", "tests") as a, d.connect("b", "tests") as b:
        pa = a.call("open_project", path=str(gpr))
        b.call("open_project", path=str(gpr))
        ka = a.call("open_program", path=exe)["key"]
        b.call("open_program", path=exe, overlay="bo")
        fn = code_functions(a, 1)[0]
        b.call("rename", overlay="bo", address=fn, name="bo_name")
        r = a.call("refresh")
        check(r["refreshed"] is False and r["reason"] == "unchanged" and
              r["generation"] == pa["generation"], f"unforced refresh: {r}")
        r = a.call("refresh", force=True)
        check(r["refreshed"] is True and r["from"] == r["revision"] == pa["revision"] and
              r["generation"] == pa["generation"] + 1 and
              [p_["action"] for p_ in r["programs"]] == ["reopened"] and
              r["programs"][0]["program"] == ka, f"forced refresh: {r}")
        told = b.call_raw("info", overlay="bo")
        check([t_["generation"] for t_ in told.get("refreshed") or []] == [r["generation"]],
              f"the other client was not told: {told.get('refreshed')}")
        ov = told["result"]["overlay"]
        check(ov["error"] is None and ov["stale"] is False and ov["ops"] == 1,
              f"overlay after a forced refresh: {ov}")
        check(b.call("decompile", overlay="bo", address=fn)["name"] == "bo_name",
              "the overlay was not rebuilt")
        check(a.call("info")["key"] == ka and a.call("info")["generation"] == r["generation"],
              "the key or generation moved")
        r2 = b.call("refresh", force=True)
        check(r2["refreshed"] and r2["generation"] == r["generation"] + 1, f"second: {r2}")
        for s in (a, b):
            s.call("close_project")
    d.stop()
    check(tree_state(gpr.parent) == before, "a forced refresh wrote the project")
    return (f"unforced: unchanged; forced: reopened (generation {pa['generation']} -> "
            f"{r2['generation']}), other client told once, overlay rebuilt; project unwritten")


def t_legacy_overlay(c: Ctx):
    """Overlays of a program saved by an older Ghidra (needs --legacy-project): an overlay
    opened while the first open's upgrade cache build is still running is upgraded in memory and
    works; once the copy is ready and the program reopens from it, a new overlay opens from the
    copy (faster, asserted when the in-memory open took 200 ms or more; the median of 5 opens);
    both overlays stay private; the source is never written."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    if not c.a.legacy_project:
        return "skipped (no --legacy-project)"
    src = pathlib.Path(c.a.legacy_project)
    src = src.parent if src.suffix == ".gpr" else src
    legacy = c.work / "legacyOverlay"
    clone_tree(src, legacy)
    before = tree_state(legacy)
    cache = c.work / "upgrade-cache-ov"
    if cache.exists():
        shutil.rmtree(cache)
    d = c.daemon("legacy-ov", keepWarm=0, maxLong=1, upgradeCacheDir=str(cache))
    notes = []
    with d.connect("owner", "tests") as s, d.connect("hold", "tests") as h, \
            d.connect("other", "tests") as x:
        # a long job holds the only long slot, so the build is still waiting when the overlay
        # opens: the overlay is made while the build is in progress
        sleep_id = h.send("script", script=c.script("TestSleep.java"), program=None,
                          args=["30000"], parallel=True, wait=60000)
        time.sleep(0.5)
        for s_ in (s, x):
            s_.call("open_project", path=str(legacy))
        prog = c.a.legacy_program or s.call("list", programsOnly=True)["entries"][0]["path"]
        r = s.call("open_program", path=prog, wait=1800000)
        check(r["cacheBuild"] == "started" and r["cachedUpgrade"] is False, f"first open: {r}")
        build_id = r["cacheBuildInfo"]["id"]
        x.call("open_program", path=prog)
        fn = code_functions(s, 1)[0]
        canon = s.call("decompile", address=fn)["name"]
        t = time.perf_counter()
        o1 = s.call("open_program", path=prog, overlay="during-build", wait=1800000)
        mem_ms = (time.perf_counter() - t) * 1000
        b = build_of(s, build_id)
        check(b is not None and b["state"] == "building", f"the build is not in progress: {b}")
        check(o1["overlay"]["error"] is None, f"overlay during the build: {o1['overlay']}")
        s.call("rename", overlay="during-build", address=fn, name="ov_during_build")
        check(s.call("decompile", overlay="during-build", address=fn)["name"] ==
              "ov_during_build", "the in-memory overlay does not show its change")
        check(x.call("decompile", address=fn)["name"] == canon, "the overlay leaked")
        notes.append(f"overlay during the build: {mem_ms:.0f} ms (in-memory upgrade)")
        h.call("cancel", target=sleep_id)
        b = wait_build(s, build_id)
        check(b["state"] == "ready", f"build: {b}")
        check(s.call("decompile", overlay="during-build", address=fn)["name"] ==
              "ov_during_build", "the overlay was disturbed by the build finishing")
        s.call("drop_overlay", overlay="during-build")
        s.call("close_program")
        x.call("close_program")
        time.sleep(2.5)  # the reaper closes the in-memory program (its copy is ready)
        r = s.call("open_program", path=prog, wait=600000)
        check(r["cachedUpgrade"] is True, f"reopen not from the copy: {r.get('upgradeCache')}")
        # the speed of an overlay from the copy: the median of 5 opens. On a small fixture both
        # opens take a few ms and their order is noise, so the order is asserted only when the
        # in-memory upgrade took long enough to measure (200 ms); the copy itself is asserted above
        # (cachedUpgrade) and below (the overlay works and stays private)
        copy_times = []
        for _ in range(4):
            t = time.perf_counter()
            s.call("open_program", path=prog, overlay="from-copy-probe", wait=600000)
            copy_times.append((time.perf_counter() - t) * 1000)
            s.call("drop_overlay", overlay="from-copy-probe")
        t = time.perf_counter()
        o2 = s.call("open_program", path=prog, overlay="from-copy", wait=600000)
        copy_times.append((time.perf_counter() - t) * 1000)
        copy_ms = sorted(copy_times)[len(copy_times) // 2]
        check(o2["overlay"]["error"] is None, f"overlay from the copy: {o2['overlay']}")
        s.call("rename", overlay="from-copy", address=fn, name="ov_from_copy")
        check(s.call("decompile", overlay="from-copy", address=fn)["name"] == "ov_from_copy" and
              s.call("decompile", address=fn)["name"] == canon, "overlay from the copy")
        if mem_ms >= 200:
            check(copy_ms < mem_ms, f"overlay from the copy {copy_ms:.0f} ms (median of 5), in "
                  f"memory {mem_ms:.0f} ms")
            notes.append(f"overlay from the cache copy: {copy_ms:.0f} ms (median of 5)")
        else:
            notes.append(f"overlay from the cache copy: {copy_ms:.0f} ms (median of 5; order not "
                         f"asserted, the in-memory open took {mem_ms:.0f} ms < 200 ms)")
        c.timings["legacy overlay: in-memory / from the copy ms"] = [round(mem_ms),
                                                                     round(copy_ms)]
        s.call("drop_overlay", overlay="from-copy")
        for s_ in (s, x):
            s_.call("close_project")
    d.stop()
    check(tree_state(legacy) == before, "the legacy source was written")
    notes.append("source byte-identical")
    return "; ".join(notes)


def t_orphan_shutdown(c: Ctx):
    """Shared-write work orphaned by its last writer's death is kept (program and project stay
    open, status shows it) until a client adopts it; a daemon shutdown before that discards it,
    says so in the log, and leaves the project clean: it reopens writable without the orphaned
    changes."""
    global s_scripts_dir
    s_scripts_dir = c.scripts
    gpr = c.copy_fixture("projOrphan")
    exe = pathlib.Path(c.a.exe).name
    d = c.daemon("orphan", keepWarm=0)
    with d.connect("watcher", "tests") as w:
        w.call("open_project", path=str(gpr))
        w.call("open_program", path=exe)
        f = code_functions(w, 2)
        canon = names_at(w)
        w.call("close_project")
        code = ("s = gs.connect(client='doomed', harness='crashy', state=A[0], instance='orphan',"
                " ghidra=A[1])\n"
                "s.call('open_project', path=A[2], writable=True)\n"
                "s.call('open_program', path=A[3], writable=True, share=True)\n"
                "s.call('rename', address=A[4], name='orphaned_name')\n"
                "s.call('comment', address=A[5], text='orphaned comment')\n"
                "print(json.dumps({'client': s.hello['client']}), flush=True)\n"
                "time.sleep(3600)\n")
        p = c.child(code, c.state, c.a.ghidra, gpr, exe, f[0], f[1])
        line = p.stdout.readline()
        check(line, f"child did not start: {p.stderr.read()[-2000:] if p.poll() is not None else ''}")
        p.kill()
        p.wait()
        held = wait_for(lambda: [pg for pg in w.call("status")["programs"]
                                 if pg["path"] == "/" + exe and pg.get("orphanedMs") is not None],
                        "the orphaned program in status", 30)
        time.sleep(2.5)  # past the reaper (keepWarm 0): still held
        held = [pg for pg in w.call("status")["programs"] if pg["path"] == "/" + exe]
        check(held and held[0]["writers"] == [] and held[0]["unsavedEdits"] == 2,
              f"orphaned work not kept: {held}")
    log = d.log_file
    mark = log.stat().st_size if log.exists() else 0
    t = time.perf_counter()
    check(d.stop(), "stop failed")
    stop_s = time.perf_counter() - t
    text = log.read_text(encoding="utf-8", errors="replace")[mark:] if log.exists() else ""
    check(f"discarding unsaved changes in /{exe}" in text,
          f"the shutdown did not log the discarded work: {text[-1500:]}")
    d2 = c.daemon("orphan-check")
    with d2.connect("check", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        s.call("open_program", path=exe, writable=True)
        check(names_at(s)[f[0]] == canon[f[0]] and comments_at(s, [f[1]])[f[1]] == "",
              "orphaned work reached the saved project")
        s.call("close_project")
    d2.stop()
    return (f"orphaned work kept (2 unsaved edits, no writers) until the shutdown "
            f"({stop_s:.1f} s), which discarded and logged it; project reopened writable, clean")


MEM_SIZE = """// @category HeadlessSession.Test
import ghidra.app.script.GhidraScript;
public class TestMemSize extends GhidraScript {
    @Override protected void run() throws Exception {
        println("MEM|" + currentProgram.getMemory().getAllInitializedAddressSet().getNumAddresses());
    }
}
"""


def rep_state(gpr: pathlib.Path):
    """(item property files, database folders) under the project's .rep."""
    rep = gpr.with_suffix(".rep")
    prp = {p for p in rep.rglob("*.prp")}
    dbs = {p for p in rep.rglob("*.db") if p.is_dir()}
    return prp, dbs


def t_import_write_kill(c: Ctx):
    return _import_write_kill(c, WRITE_KILL_FRACS)


WRITE_KILL_FRACS = (0.0, 0.3, 0.7)   # when the daemon is killed: at the first sight of the database, then part-way


def _import_write_kill(c: Ctx, fracs, tag=""):
    """The daemon killed while an import writes its program into the project (Ghidra's final
    createFile, after the load): at the first sight of the new database folder, and part-way
    through the write. Each time the next daemon opens the project clean, and the program is
    either absent or complete (it opens, with the whole file in memory), never half; the file
    then imports again."""
    mb = c.a.raw_mb * 4
    f1 = raw_file(c, "wkill.bin", mb)
    size = os.path.getsize(f1)
    folder = c.work / ("projWriteKill" + tag)
    if folder.exists():
        shutil.rmtree(folder)
    d = c.daemon("wkill" + tag, maxImports=1)
    with d.connect("calib", "tests") as s:
        gpr = c.make_project(s, folder, "WriteKill")
        s.call("open_project", path=str(gpr), writable=True)
        # calibration: how long the write into the project takes
        dbs0 = rep_state(gpr)[1]
        rid = s.send("import", file=f1, name="calib", parallel=True, **RAW_LANG)
        wait_for(lambda: rep_state(gpr)[1] - dbs0, "the database folder", 600, 0.005)
        t0 = time.perf_counter()
        s.wait(rid)  # the write, then the open for this client (small next to the write)
        write_s = time.perf_counter() - t0
        s.call("close_project")
    d.stop()
    c.timings["import write into the project (s)"] = round(write_s, 2)
    notes = [f"write of {mb} MB takes {write_s:.2f} s"]
    outcomes = []
    kept = {"/calib"}
    teardown, restart = [], []
    (c.scripts / "TestMemSize.java").write_text(MEM_SIZE)
    for frac in fracs:
        name = f"k{WRITE_KILL_FRACS.index(frac)}"
        with d.connect("doomed", "tests") as s:
            s.call("open_project", path=str(gpr), writable=True)
            dbs0 = rep_state(gpr)[1]
            rid = s.send("import", file=f1, name=name, duplicate=True, parallel=True,
                         **RAW_LANG)
            wait_for(lambda: rep_state(gpr)[1] - dbs0, "the database folder", 600, 0.002)
            if frac:
                time.sleep(write_s * frac)
            pid = d.read_endpoint()["pid"]
            check(d.kill(), "kill failed")
            # The OS may need long to tear the killed JVM down: with tmpdir on ReFS it writes
            # back the dirty pages of its temporary database (README, "Limits"). Measure it, and
            # start the next daemon only once it is gone.
            t = time.perf_counter()
            check(c.gs._wait_pid_exit(int(pid), 900), "the killed JVM did not exit in 900 s")
            teardown.append(round(time.perf_counter() - t, 1))
        t = time.perf_counter()
        with d.connect("after", "tests") as s:
            restart.append(round(time.perf_counter() - t, 1))
            # the dead JVM's buffer cache file is removed in the background, not before ready
            check(restart[-1] < 30, f"the daemon after the kill took {restart[-1]} s to answer")
            pid = s.call("open_project", path=str(gpr), writable=True)["id"]
            paths = program_paths(s, pid)
            check(set(paths) - {f"/{name}"} == kept, f"unexpected programs: {paths} {kept}")
            if f"/{name}" in paths:
                info = s.call("open_program", path=f"/{name}", wait=600000)
                st = s.call("script", script=c.script("TestMemSize.java"), args=[])["output"]
                check(f"MEM|{size}" in st, f"{name}: listed but not complete: {st} {info}")
                s.call("close_program")
                kept.add(f"/{name}")
                outcomes.append(f"{frac:.1f}: complete")
            else:
                outcomes.append(f"{frac:.1f}: absent")
            stray = len(rep_state(gpr)[1]) - len(kept)
            if stray:
                outcomes[-1] += f" ({stray} unused database folder(s) left on disk)"
            s.call("close_project")
        d.stop()
    with d.connect("again", "tests") as s:
        s.call("open_project", path=str(gpr), writable=True)
        r = s.call("import", file=f1, name="again", duplicate=True, **RAW_LANG)
        check(r["imported"] is True and r["path"] == "/again", f"re-import: {r}")
        s.call("close_project")
    d.stop()
    notes.append("killed at " + ", ".join(outcomes) + "; reopened clean each time; re-import ok")
    notes.append(f"killed JVM gone after (s): {teardown}; next daemon answered after (s): "
                 f"{restart}")
    c.timings["killed JVM mid-write: process gone after (s)"] = teardown
    return "; ".join(notes)


TESTS = ["two_harnesses", "two_projects", "dll_import", "client_kill", "daemon_restart",
         "fairness", "cancel_all", "import_queue", "import_isolation", "parallel_imports",
         "import_kill", "import_write_kill", "import_readers", "import_speed", "caller_labels",
         "idle_shutdown", "keep_warm", "stdio", "upgrade_cache", "holders", "fork", "fork_timing",
         "revisions",
         "refresh_force", "overlays", "overlay_owned", "legacy_overlay", "multi_writer",
         "shared", "edit", "orphan_shutdown", "shared_stress"]

REGISTRY = {}   # test name -> fn(ctx): the tests above and those of the dt_*.py files
BASELINE = {}   # test name -> the premise it is a baseline of (expected to fail, see --baseline)
LOADED = {}     # dt_*.py file name -> its test names, in order
# test name -> {shard: fn(ctx)}: a test that is a loop of independent iterations (or of protocol
# halves) may also be run as shards, ``name@shard``, each in its own process (run_parallel.py runs
# them at once and reports them under ``name``). The shards together do everything the whole test
# does (the same counts, the same checks per iteration); ``--only name`` still runs the whole test.
SHARDS = {
    # each kill point in its own process (each with its own calibration import and the re-import after it)
    "import_write_kill": {f"k{i}": (lambda f: lambda c: _import_write_kill(c, (f,), f"-{WRITE_KILL_FRACS.index(f)}"))(f)
                          for i, f in enumerate(WRITE_KILL_FRACS)},
}


def split_n(n, k):
    """``n`` iterations over ``k`` shards as ``[(first, count)]``: the counts add up to ``n``."""
    out, first = [], 0
    for j in range(k):
        cnt = n // k + (1 if j < n % k else 0)
        out.append((first, cnt))
        first += cnt
    return out


# multi_writer's edit rounds split over shards (each: its own setup, both writers concurrent on their own programs,
# the saves and the reopen check; the one bounded analysis, at round 150, is in the shard that has that round)
SHARDS["multi_writer"] = {f"i{j}": (lambda f, n: lambda c: _multi_writer(c, f, n))(f, n)
                          for j, (f, n) in enumerate(split_n(MW_ITERS, MW_SHARDS))}


# import_isolation's concurrent-load rounds split over shards (each its own daemon and projects, each repeating the
# search-path check); the rounds add up to ISO_ROUNDS
SHARDS["import_isolation"] = {f"r{j}": (lambda n: lambda c: _import_isolation(c, n))(n)
                              for j, (_, n) in enumerate(split_n(ISO_ROUNDS, ISO_SHARDS))}


def test_fn(name):
    """The function of a test name or of a shard ``name@shard``."""
    if "@" in name:
        t, s = name.split("@", 1)
        return SHARDS[t][s]
    return REGISTRY[name]


def load_dt(tests_dir):
    """Imports every ``dt_*.py`` of ``tests_dir`` (sorted) and registers its ``TESTS`` (and
    ``BASELINE``). Returns ``[(file name, what went wrong)]`` for the files that did not load; the
    other files still load. An empty set is fine."""
    errors = []
    for f in sorted(pathlib.Path(tests_dir).glob("dt_*.py")):
        try:
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f.stem] = mod
            spec.loader.exec_module(mod)
            tests = getattr(mod, "TESTS", None)
            if not isinstance(tests, dict) or not all(callable(v) for v in tests.values()):
                raise TypeError("TESTS must be a dict {name: fn}")
            base = getattr(mod, "BASELINE", {})
            if not isinstance(base, dict) or set(base) - set(tests):
                raise TypeError("BASELINE must be a dict {name: premise} of names in TESTS")
            shards = getattr(mod, "SHARDS", {})
            if not isinstance(shards, dict) or set(shards) - set(tests) or not all(
                    isinstance(v, dict) and v and all(callable(x) and "@" not in k
                                                      for k, x in v.items())
                    for v in shards.values()):
                raise TypeError("SHARDS must be a dict {name in TESTS: {shard: fn}}")
            for n, fn in tests.items():
                if n in REGISTRY and REGISTRY[n] is not fn:
                    raise ValueError(f"test name {n!r} is already taken")
            SHARDS.update(shards)
            for n, fn in tests.items():
                REGISTRY[n] = fn
                if n in base:
                    BASELINE[n] = base[n]
            LOADED[f.name] = list(tests)
        except Exception as e:  # noqa: BLE001
            errors.append((f.name, f"{type(e).__name__}: {e}"))
    return errors


def watchdog(c, name, secs):
    """Ends the run, with every daemon and child killed, when one test outlives ``secs``."""
    def fire():
        print(f"FAIL {name} did not end within {secs} s; killing its daemons and children",
              flush=True)
        c.cleanup()
        os._exit(4)
    t = threading.Timer(secs, fire)
    t.daemon = True
    t.start()
    return t


def run_test(c, n, secs):
    """Runs one test; returns (status, note, seconds, evidence): status is "pass", "premise"
    (a PremiseFail), "skipped" (``Skipped`` raised, or a note starting with "skipped") or "fail"."""
    t = time.perf_counter()
    wd = watchdog(c, n, secs) if secs else None
    ev = {}
    try:
        status, note = "pass", test_fn(n)(c)
        if str(note).startswith("skipped"):
            status = "skipped"
    except Skipped as e:
        status, note = "skipped", f"skipped: {e}"
    except PremiseFail as e:
        status, note, ev = "premise", str(e), e.evidence
    except Exception as e:  # noqa: BLE001
        tb = e.__traceback__
        where = tb.tb_next.tb_lineno if tb and tb.tb_next else "?"
        det = getattr(e, "details", None)
        status = "fail"
        note = f"{type(e).__name__}: {e}{' ' + json.dumps(det) if det else ''} at line {where}"
    finally:
        if wd:
            wd.cancel()
    if status in ("fail", "premise"):
        # nothing a failed test started may outlive it, and its projects are closed (the daemons
        # are asked to shut down) before they are killed, so the next test starts on a clean slate
        c.release()
        c.cleanup()
    return status, note, time.perf_counter() - t, ev


def main():
    # The tests' state dirs are fresh: keep the user's shared AOT store (Launch.aot_dirs) out of
    # them, so a daemon starts with the cache the test seeded or with none, never with whatever
    # this machine's user trained. A caller that tests the shared store sets it explicitly.
    os.environ.setdefault("GHIDRA_SESSION_AOT_DIR", "none")
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--selftest", action="store_true",
                    help="check the client_protocol shim against this install's launcher library "
                    "(needs only --ghidra: no --work, --exe, --dll, no daemon) and exit")
    ap.add_argument("--work", help="an empty working directory (required except with --selftest)")
    ap.add_argument("--exe", help="a PE file to import (required except with --selftest)")
    ap.add_argument("--dll", help="a second PE file (required except with --selftest)")
    ap.add_argument("--project", help="an analysed project to open read-only (never written)")
    ap.add_argument("--legacy-project", dest="legacy_project",
                    help="a project saved by an older Ghidra, for upgrade_cache (only copied)")
    ap.add_argument("--legacy-program", dest="legacy_program",
                    help="the program in it to open (default: the first one)")
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemons (default: <work>/tmp; "
                    "'default': leave it to the JVM)")
    ap.add_argument("--raw-mb", dest="raw_mb", type=int, default=128,
                    help="size of the random raw binary the import queue test imports "
                    "(default 128): large enough that an import outlasts the polling")
    ap.add_argument("--big", action="append", default=[],
                    help="a binary for import_speed (repeat; default: two random raw files)")
    ap.add_argument("--big-analyze", dest="big_analyze", action="store_true",
                    help="import_speed also analyses (import with analyze:true)")
    ap.add_argument("--only", help="comma-separated test names (built in or from dt_*.py)")
    ap.add_argument("--baseline", action="store_true",
                    help="run the expected-fail baseline tests (BASELINE of the dt_*.py files) and "
                    "check that each fails for its stated reason; exit 0 only if all do")
    ap.add_argument("--list", action="store_true", help="list the tests and exit")
    ap.add_argument("--tests-dir", dest="tests_dir", default=str(HERE),
                    help="where the dt_*.py files are (default: next to this script)")
    ap.add_argument("--test-timeout", dest="test_timeout", type=int, default=None,
                    help="seconds one test may take before the run is ended with its daemons and "
                    "children killed (default: 600 with --baseline, else none)")
    ap.add_argument("--report", help="also write the results here, as JSON")
    ap.add_argument("--list-shards", dest="list_shards", action="store_true",
                    help="list the shards (name@shard) of the tests that have them, and exit")
    ap.add_argument("--prepare", action="store_true",
                    help="make --work a seed directory (the analysed fixture project and the "
                    "daemon's AOT cache) for --seed-dir, and exit")
    ap.add_argument("--prepare-aot", dest="prepare_aot", action="store_true",
                    help="with --prepare: also train the daemon's AOT cache (about 30 s; measured "
                    "0.1-0.3 s faster per daemon start than the class cache alone)")
    ap.add_argument("--list-prebuild", dest="list_prebuild", action="store_true",
                    help="list the cached setup projects (PREBUILT) as 'tag user,user,...' and exit")
    ap.add_argument("--prebuild", default=None,
                    help="comma-separated PREBUILT tags: make them in --seed-dir and exit (run_parallel.py "
                    "does it in its seed phase, before its queue starts)")
    ap.add_argument("--seed-dir", dest="seed_dir",
                    help="a directory made by --prepare: the fixture is copied from it instead "
                    "of being imported and analysed in this process, and the daemons start "
                    "with its AOT cache (only read)")
    a = ap.parse_args()
    if a.selftest:
        sys.path.insert(0, str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                               "support"))
        import ghidra_session as gs
        sys.exit(selftest(gs))
    for opt in ("work", "exe", "dll"):
        if not getattr(a, opt):
            ap.error(f"--{opt} is required (except with --selftest)")
    sys.modules.setdefault("daemon_tests", sys.modules[__name__])  # dt_*.py import this file
    for n in TESTS:
        REGISTRY[n] = globals()["t_" + n]
    load_errors = load_dt(a.tests_dir)
    default = list(TESTS) + [n for fl in LOADED.values() for n in fl if n not in BASELINE]
    only = [x for x in (a.only or "").split(",") if x]
    for n in only:
        t, _, s = n.partition("@")
        if t not in REGISTRY:
            ap.error(f"unknown test {n}; known: {', '.join(REGISTRY)}")
        if s and s not in SHARDS.get(t, {}):
            ap.error(f"unknown shard {n}; the shards of {t}: "
                     f"{', '.join(SHARDS.get(t, {})) or 'none'}")
    if a.list_shards:
        for t in REGISTRY:
            for s in SHARDS.get(t, {}):
                print(f"{t}@{s}")
        for f, why in load_errors:
            print(f"FAIL load {f}: {why}")
        sys.exit(1 if load_errors else 0)
    if a.baseline:
        for n in only:
            if n not in BASELINE:
                ap.error(f"{n} is not a baseline test; baseline tests: {', '.join(BASELINE)}")
        names = only or list(BASELINE)
    else:
        names = only or default
    if a.list_prebuild:
        for tag, (users, _) in PREBUILT.items():
            print(tag, ",".join(users))
        sys.exit(1 if load_errors else 0)
    if a.list:
        for n in REGISTRY:
            print(n + ("  [baseline: " + BASELINE[n] + "]" if n in BASELINE else ""))
        for f, why in load_errors:
            print(f"FAIL load {f}: {why}")
        sys.exit(1 if load_errors else 0)
    if a.baseline and not names and not load_errors:
        print("no baseline tests to run")
    sys.path.insert(0, str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import ghidra_session as gs
    if a.prepare:
        sys.exit(prepare_seed(a, gs, aot=a.prepare_aot))
    if a.prebuild is not None:
        if not a.seed_dir:
            ap.error("--prebuild needs --seed-dir")
        sys.exit(prebuild(a, gs, [x for x in a.prebuild.split(",") if x]))
    c = Ctx(a, gs)
    secs =a.test_timeout if a.test_timeout is not None else (600 if a.baseline else 0)
    results = []
    bad = len(load_errors)
    for f, why in load_errors:
        print(f"FAIL load {f}: {why}", flush=True)
        results.append({"test": f, "status": "load_error", "note": why})
    skipped = [n for n in BASELINE if not a.baseline and n not in only]
    try:
        for n in names:
            status, note, secs_n, ev = run_test(c, n, secs)
            if a.baseline:
                word = {"premise": "CONFIRMED", "pass": "REFUTED", "fail": "OTHER",
                        "skipped": "SKIPPED"}[status]
                bad += status != "premise"
                print(f"{word:9s} {n:24s} {secs_n:7.1f} s  {note}", flush=True)
            else:
                bad += status not in ("pass", "skipped")
                word = {"pass": "ok  ", "premise": "FAIL", "fail": "FAIL",
                        "skipped": "SKIP"}[status]
                tag = " (as premised)" if status == "premise" else ""
                print(f"{word} {n:16s} {secs_n:7.1f} s  {note}{tag}", flush=True)
            results.append({"test": n, "status": status, "seconds": round(secs_n, 1),
                            "note": note, "evidence": ev})
    finally:
        c.cleanup()
    if skipped:
        print(f"not run: {len(skipped)} expected-fail baseline test(s) ({', '.join(skipped)}); "
              "--baseline runs them")
    if a.report:
        pathlib.Path(a.report).write_text(
            json.dumps({"mode": "baseline" if a.baseline else "run", "results": results},
                       indent=1), encoding="utf-8")
    print("timings:", json.dumps(c.timings, indent=1))
    miss = f"; {len(load_errors)} dt file(s) did not load" if load_errors else ""
    if a.baseline:
        n_ok = sum(r["status"] == "premise" for r in results)
        print(f"{n_ok}/{len(names)} baseline tests fail as premised{miss}")
    else:
        n_ok = sum(r["status"] == "pass" for r in results)
        n_skip = [r["test"] for r in results if r["status"] == "skipped"]
        # a skipped test did not pass: it is counted apart, with its name, and does not fail the run
        sk = f", {len(n_skip)} SKIPPED ({', '.join(n_skip)})" if n_skip else ""
        print(f"{n_ok}/{len(names)} passed{sk}{miss}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
