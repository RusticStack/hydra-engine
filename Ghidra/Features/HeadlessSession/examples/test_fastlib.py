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
"""Unit tests of ``fastlib.py`` (light: no daemon, no heavy.py).

    python test_fastlib.py            # run the tests
    python test_fastlib.py --bench    # print the measured latencies of until / wait_exit / wait_change

Timing assertions are one-sided where it matters: a lower bound ("it did not return early") is exact, an upper
bound ("it returned promptly") is loose enough for a loaded machine and tight enough to tell an event wait
(milliseconds) from a fixed sleep (100 ms and more).
"""
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fastlib as fl  # noqa: E402

WIN = sys.platform == "win32"
PY = sys.executable
SCALES = [0.02, 0.05, 0.1, 0.25, 0.5, 1.0]
XS = [1, 7, 10, 250, 1400, 14000, 123456]


class ScaleCase(unittest.TestCase):
    def setUp(self):
        self._old = fl.set_scale(1.0)
        self._env = os.environ.pop("HYDRA_TEST_LOADED", None)

    def tearDown(self):
        fl.set_scale(self._old)
        if self._env is not None:
            os.environ["HYDRA_TEST_LOADED"] = self._env


class TestScale(ScaleCase):
    def test_parse(self):
        p = fl._parse_scale
        self.assertEqual(p("0.1"), 0.1)
        self.assertEqual(p("1"), 1.0)
        self.assertEqual(p("5"), 1.0)  # never slower than real
        self.assertEqual(p("0"), fl.SCALE_MIN)
        self.assertEqual(p("-3"), fl.SCALE_MIN)
        for bad in ("", "abc", None, "nan"):
            self.assertEqual(p(bad), 1.0, bad)

    def test_set_scale_returns_previous_and_clamps(self):
        self.assertEqual(fl.set_scale(0.1), 1.0)
        self.assertEqual(fl.set_scale(0.0001), 0.1)
        self.assertEqual(fl.SCALE, fl.SCALE_MIN)

    def test_ms_sec_identity_at_scale_1(self):
        for x in XS:
            self.assertEqual(fl.ms(x), x)
            self.assertEqual(fl.sec(x / 1000.0), x / 1000.0)

    def test_ms_scaled_rounded_up_with_floor(self):
        fl.set_scale(0.1)
        self.assertEqual(fl.ms(14000), 1400)  # float noise (1400.0000000000002) must not add a millisecond
        self.assertEqual(fl.ms(15), 2)  # up, never down
        self.assertEqual(fl.ms(1), 1)  # floor 1
        self.assertEqual(fl.ms(1, floor=50), 50)
        self.assertEqual(fl.ms(0, floor=0), 0)
        self.assertAlmostEqual(fl.sec(2.0), 0.2)
        self.assertEqual(fl.sec(0.001, floor=0.005), 0.005)

    def test_lower_bound_is_never_loosened(self):
        prev = {}
        for s in SCALES:
            fl.set_scale(s)
            for x in XS:
                lo = fl.bound_lo(x)
                self.assertGreaterEqual(lo, x * s - 1e-6, (s, x))  # never below the scaled value
                self.assertLessEqual(lo, x, (s, x))  # never tightened above the original
                self.assertLessEqual(lo, fl.ms(x), (s, x))  # a hold made with ms() always satisfies it
                self.assertGreaterEqual(lo, prev.get(x, 0), (s, x))  # monotone in the scale
                prev[x] = lo
                m = x / 2
                self.assertGreaterEqual(fl.bound_lo(x, minimum=m), m)  # the stated minimum is kept
        fl.set_scale(1.0)
        for x in XS:
            self.assertEqual(fl.bound_lo(x), x)

    def test_lower_bound_minimum_above_bound_is_refused(self):
        with self.assertRaises(ValueError):
            fl.bound_lo(100, minimum=101)

    def test_lower_bound_minimum_floors_the_scaled_value(self):
        fl.set_scale(0.02)
        self.assertEqual(fl.bound_lo(1000), 20)
        self.assertEqual(fl.bound_lo(1000, minimum=200), 200)

    def test_upper_bound(self):
        self.assertEqual(fl.bound_hi(1000), 1000)  # scale 1: the original assertion, no slack
        fl.set_scale(0.1)
        self.assertAlmostEqual(fl.bound_hi(1000), 100 + fl.SLACK_MS)
        self.assertAlmostEqual(fl.bound_hi(1000, slack_ms=50), 150)
        os.environ["HYDRA_TEST_LOADED"] = "1"
        self.assertAlmostEqual(fl.bound_hi(1000), 100 + 2 * fl.SLACK_MS)
        for s in SCALES:
            fl.set_scale(s)
            for x in XS:
                self.assertGreaterEqual(fl.bound_hi(x), fl.ms(x))  # a scaled hold fits its own upper bound

    def test_hang_timeout(self):
        self.assertEqual(fl.hang_s(), 30.0)
        self.assertEqual(fl.hang_s(1.0), 30.0)
        self.assertEqual(fl.hang_s(10.0), 100.0)


class TestUntil(unittest.TestCase):
    def test_already_true_returns_in_microseconds(self):
        times = []
        for _ in range(300):
            t0 = time.perf_counter()
            w = fl.until(lambda: "yes")
            times.append(time.perf_counter() - t0)
            self.assertEqual((w.value, w.polls), ("yes", 1))
        self.assertLess(statistics.median(times), 0.001)
        self.assertLess(max(times), 0.05)

    def test_becomes_true_not_early_and_prompt(self):
        flag = []
        threading.Timer(0.06, lambda: flag.append(1)).start()
        t0 = time.perf_counter()
        w = fl.until(lambda: bool(flag), 5)
        took = time.perf_counter() - t0
        self.assertGreaterEqual(took, 0.059)
        self.assertLess(took, 0.06 + 0.5)
        self.assertGreater(w.polls, 3)
        self.assertAlmostEqual(w.elapsed_s, took, delta=0.01)

    def test_timeout_reports_what_elapsed_and_last_state(self):
        state = {"n": 0}

        def pred():
            state["n"] += 1
            return {"n": state["n"], "ready": False}["ready"] or None

        t0 = time.perf_counter()
        with self.assertRaises(fl.WaitTimeout) as cm:
            fl.until(pred, 0.1, what="the lane to drain", describe=lambda: "inUse=2")
        took = time.perf_counter() - t0
        self.assertGreaterEqual(took, 0.1)  # never returns early
        self.assertLess(took, 1.0)
        msg = str(cm.exception)
        for part in ("the lane to drain", "limit 0.100s", "last value=None", "inUse=2", f"polls={state['n']}"):
            self.assertIn(part, msg)
        self.assertIsInstance(cm.exception, AssertionError)  # a timeout is a test failure
        self.assertIsInstance(cm.exception, TimeoutError)

    def test_timeout_reports_last_exception_and_ignore(self):
        def pred():
            raise KeyError("scheduler")

        with self.assertRaises(fl.WaitTimeout) as cm:
            fl.until(pred, 0.05, ignore=(KeyError,))
        self.assertIn("KeyError('scheduler')", str(cm.exception))
        with self.assertRaises(KeyError):  # not ignored: propagates at once
            fl.until(pred, 5)

    def test_describe_failure_does_not_hide_the_timeout(self):
        def bad():
            raise RuntimeError("boom")

        with self.assertRaises(fl.WaitTimeout) as cm:
            fl.until(lambda: False, 0.02, describe=bad)
        self.assertIn("describe() raised", str(cm.exception))

    def test_timeout_zero_evaluates_once(self):
        calls = []
        with self.assertRaises(fl.WaitTimeout):
            fl.until(lambda: calls.append(1) and False, 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(fl.until(lambda: True, 0).value)

    def test_notify_wakes_the_wait_at_once(self):
        ev, flag = threading.Event(), []

        def later():
            time.sleep(0.05)
            flag.append(1)
            ev.set()

        threading.Thread(target=later).start()
        t0 = time.perf_counter()
        fl.until(lambda: bool(flag), 5, interval=3.0, notify=ev)  # a 3 s cap: only the event can end it early
        took = time.perf_counter() - t0
        self.assertGreaterEqual(took, 0.049)
        self.assertLess(took, 0.5)

    def test_notify_set_before_the_check_is_not_lost(self):
        ev, flag = threading.Event(), [1]
        ev.set()
        self.assertTrue(fl.until(lambda: bool(flag), 1, interval=3.0, notify=ev).value)

    def test_backoff_is_capped_by_interval(self):
        flag = []
        threading.Timer(0.3, lambda: flag.append(1)).start()
        w = fl.until(lambda: bool(flag), 5, interval=0.01)
        self.assertGreater(w.polls, 25)  # polls at most every 10 ms, not exponentially sparser

    def test_default_timeout_is_the_hang_detector(self):
        old = os.environ.get("HYDRA_TEST_HANG_S")
        os.environ["HYDRA_TEST_HANG_S"] = "0.05"
        try:
            with self.assertRaises(fl.WaitTimeout) as cm:
                fl.until(lambda: False)
            self.assertIn("limit 0.050s", str(cm.exception))
        finally:
            if old is None:
                del os.environ["HYDRA_TEST_HANG_S"]
            else:
                os.environ["HYDRA_TEST_HANG_S"] = old


def spawn(code):
    return subprocess.Popen([PY, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


class TestWaitExit(unittest.TestCase):
    def test_already_exited_returns_at_once(self):
        p = spawn("import sys; sys.exit(3)")
        p.wait()
        p.stdout.close()
        t0 = time.perf_counter()
        w = fl.wait_exit(p)
        self.assertEqual(w.value, 3)
        self.assertLess(time.perf_counter() - t0, 0.01)

    def test_waits_for_exit_code_and_reaps(self):
        p = spawn("import time, sys; time.sleep(0.4); sys.exit(7)")
        t0 = time.perf_counter()
        w = fl.wait_exit(p, 20)
        took = time.perf_counter() - t0
        self.assertEqual(w.value, 7)
        self.assertGreaterEqual(took, 0.35)
        self.assertEqual(p.returncode, 7)  # reaped
        p.stdout.close()

    @unittest.skipUnless(WIN, "pid wait needs Windows")
    def test_pid_and_running_timeout(self):
        p = spawn("import time; time.sleep(30)")
        try:
            t0 = time.perf_counter()
            with self.assertRaises(fl.WaitTimeout) as cm:
                fl.wait_exit(p, 0.15)
            took = time.perf_counter() - t0
            self.assertGreaterEqual(took, 0.15)
            self.assertLess(took, 1.5)
            self.assertIn(f"process {p.pid}", str(cm.exception))
            self.assertIn("still running", str(cm.exception))
            threading.Timer(0.1, p.kill).start()
            w = fl.wait_exit(p.pid, 20)  # by pid: the exit code comes from the handle
            self.assertNotEqual(w.value, 0)
        finally:
            p.kill()
            p.wait()
            p.stdout.close()

    @unittest.skipUnless(WIN, "pid wait needs Windows")
    def test_unknown_pid_is_gone(self):
        p = spawn("pass")
        pid = p.pid
        p.wait()
        p.stdout.close()
        del p
        self.assertIsNone(fl.wait_exit(pid, 5).value)  # either unopenable (None) or the real code


@unittest.skipUnless(WIN, "ReadDirectoryChangesW")
class TestWaitChange(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fastlib_")
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_already_true_returns_at_once(self):
        p = os.path.join(self.d, "a")
        open(p, "w").close()
        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            w = fl.wait_file(p)
            times.append(time.perf_counter() - t0)
            self.assertEqual(w.polls, 1)
        self.assertLess(statistics.median(times), 0.005)

    def test_file_created_wakes_without_the_cap(self):
        p = os.path.join(self.d, "ready")
        threading.Timer(0.1, lambda: open(p, "w").close()).start()
        t0 = time.perf_counter()
        fl.wait_file(p, 10, cap_s=5.0)  # a 5 s cap: only the OS notification can end it early
        took = time.perf_counter() - t0
        self.assertGreaterEqual(took, 0.09)
        self.assertLess(took, 1.0)

    def test_nested_missing_folder(self):
        p = os.path.join(self.d, "inst", "sub", "endpoint.json")

        def make():
            os.makedirs(os.path.dirname(p))
            time.sleep(0.05)
            open(p, "w").close()

        threading.Thread(target=make).start()
        t0 = time.perf_counter()
        fl.wait_file(p, 10, cap_s=5.0)
        self.assertLess(time.perf_counter() - t0, 1.5)

    def test_wait_gone_and_rename(self):
        p, q = os.path.join(self.d, "x"), os.path.join(self.d, "y")
        open(p, "w").close()
        threading.Timer(0.05, lambda: os.rename(p, q)).start()
        t0 = time.perf_counter()
        fl.wait_gone(p, 10, cap_s=5.0)
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_bare_change(self):
        threading.Timer(0.05, lambda: open(os.path.join(self.d, "n"), "w").close()).start()
        w = fl.wait_change(self.d, None, 10, cap_s=5.0)
        self.assertIs(w.value, True)
        self.assertLess(w.elapsed_s, 1.0)

    def test_predicate_on_content_via_cap(self):
        p = os.path.join(self.d, "log")
        f = open(p, "w")
        try:
            def write():
                time.sleep(0.05)
                f.write("phase=2\n")
                f.flush()

            threading.Thread(target=write).start()
            fl.wait_change(p, lambda: "phase=2" in pathlib.Path(p).read_text(), 10)  # the cap bounds a deferred event
        finally:
            f.close()

    def test_timeout_names_target_and_state(self):
        t0 = time.perf_counter()
        with self.assertRaises(fl.WaitTimeout) as cm:
            fl.wait_file(os.path.join(self.d, "never"), 0.2)
        self.assertGreaterEqual(time.perf_counter() - t0, 0.2)
        self.assertIn("never", str(cm.exception))
        self.assertIn("last value=False", str(cm.exception))

    def test_watch_is_released(self):
        # a folder with an outstanding watch handle could not be removed; repeat to catch leaks
        for i in range(20):
            sub = os.path.join(self.d, f"s{i}")
            os.mkdir(sub)
            with self.assertRaises(fl.WaitTimeout):
                fl.wait_change(sub, lambda: False, 0.01)
            os.rmdir(sub)


class TestTime(unittest.TestCase):
    def test_precise_delay_never_early_and_prompt(self):
        for want in (0, 0.3, 1, 5, 20):
            got = [fl.precise_delay(want) for _ in range(5)]
            self.assertGreaterEqual(min(got), want - 0.1, want)
            self.assertLess(statistics.median(got), want + 8.0, want)

    def test_real_wait_is_scaled(self):
        old = fl.set_scale(0.1)
        try:
            took = fl.real_wait(500)
        finally:
            fl.set_scale(old)
        self.assertGreaterEqual(took, 49.9)
        self.assertLess(took, 250)

    def test_backdate_file_and_folder(self):
        with tempfile.TemporaryDirectory(prefix="fastlib_") as d:
            f = os.path.join(d, "f")
            open(f, "w").close()
            for p in (f, d):
                ts = fl.backdate(p, 600)
                age = time.time() - os.stat(p).st_mtime
                self.assertAlmostEqual(age, 600, delta=5)
                self.assertAlmostEqual(os.stat(p).st_mtime, ts, delta=1)
            with self.assertRaises(ValueError):
                fl.backdate(f, -1)


class TestLintSleeps(unittest.TestCase):
    SRC = """
import time
import time as t
from time import sleep as nap
import fastlib
from fastlib import until

def a():
    time.sleep(0.5)
    t.sleep(2)
    nap(delay)
    time.sleep(1)  # lint: sleep-ok an occupier hold
    while not ready():
        time.sleep(0.01)
    for i in range(3):
        time.sleep(0.1)
    while now() < end:
        pass
    sleep_precise(0.002)
    fastlib.until(x)
    until(y)
    fastlib.wait_exit(p)
    def inner():
        time.sleep(3)
"""

    def test_classes_and_progress_and_exit_code(self):
        import lint_sleeps as ls
        with tempfile.TemporaryDirectory(prefix="fastlib_") as d:
            p = os.path.join(d, "dt_x.py")
            pathlib.Path(p).write_text(self.SRC)
            found, fl_calls = ls.scan_file(p)
            self.assertEqual([(c) for _, c, _ in found],
                             ["fixed-short", "fixed-long", "variable", "waived", "poll", "fixed-short", "spin",
                              "spin", "fixed-long"])
            self.assertEqual(fl_calls, 3)
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(ls.main(["--root", d, "--summary", p]), 0)
            self.assertIn("9 sleeps in 1 files", buf.getvalue())
            pathlib.Path(p).write_text("def broken(:\n")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ls.main(["--root", d, p]), 0)  # a syntax error is reported, never fatal


# --------------------------------------------------------------------------------------------------- benchmark

def _row(name, samples_s):
    s = sorted(x * 1000.0 for x in samples_s)
    p95 = s[min(len(s) - 1, int(len(s) * 0.95))]
    print(f"{name:<52} n={len(s):<4} median {statistics.median(s):8.3f} ms   p95 {p95:8.3f} ms   max {s[-1]:8.3f} ms")


def bench():
    print(f"python {sys.version.split()[0]}  platform {sys.platform}  scale {fl.SCALE}")
    n = 500
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fl.until(lambda: True)
        out.append(time.perf_counter() - t0)
    _row("until(), condition already true", out)

    for label, kw in (("poll", {}), ("notify", {"notify": threading.Event(), "interval": 1.0})):
        out = []
        for _ in range(60):
            box = []
            t_set = []

            def set_it():
                t_set.append(time.perf_counter())
                box.append(1)
                if "notify" in kw:
                    kw["notify"].set()

            threading.Timer(0.02 + (len(out) % 7) * 0.003, set_it).start()
            fl.until(lambda: bool(box), 10, **kw)
            out.append(time.perf_counter() - t_set[0])
        _row(f"until(), latency after the condition turns true ({label})", out)

    out = []
    for _ in range(40):
        p = spawn("import sys; sys.exit(0)")
        p.wait()
        t0 = time.perf_counter()
        fl.wait_exit(p)
        out.append(time.perf_counter() - t0)
        p.stdout.close()
    _row("wait_exit(), process already exited", out)

    out = []
    code = ("import os, time; time.sleep(0.15); print(repr(time.perf_counter()), flush=True); os._exit(0)")
    for _ in range(30):
        p = spawn(code)
        fl.wait_exit(p, 30)
        t1 = time.perf_counter()
        t_child = float(p.stdout.read().decode().strip())  # perf_counter (QPC) is system-wide on Windows
        out.append(t1 - t_child)
        p.stdout.close()
    _row("wait_exit(), latency from the child's last act to return", out)

    if WIN:
        with tempfile.TemporaryDirectory(prefix="fastlib_") as d:
            p = os.path.join(d, "ready")
            open(p, "w").close()
            out = []
            for _ in range(n):
                t0 = time.perf_counter()
                fl.wait_file(p)
                out.append(time.perf_counter() - t0)
            _row("wait_change(), condition already true", out)
            os.remove(p)

            for label, sub in (("same folder", False), ("missing nested folder", True)):
                out = []
                for i in range(60):
                    q = os.path.join(d, f"i{i}", "x", "ready") if sub else os.path.join(d, f"f{i}")
                    t_set = []

                    def make():
                        time.sleep(0.02 + (i % 7) * 0.003)
                        if sub:
                            os.makedirs(os.path.dirname(q))
                        t_set.append(time.perf_counter())
                        open(q, "w").close()

                    th = threading.Thread(target=make)
                    th.start()
                    fl.wait_file(q, 10, cap_s=5.0)
                    out.append(time.perf_counter() - t_set[0])
                    th.join()
                _row(f"wait_change(), latency after a file appears ({label})", out)

    for want in (0.5, 1, 5, 20):
        _row(f"precise_delay({want} ms), overshoot", [(fl.precise_delay(want) - want) / 1000.0 for _ in range(100)])
    base = []
    for _ in range(100):
        t0 = time.perf_counter()
        time.sleep(0.001)
        base.append(time.perf_counter() - t0 - 0.001)
    _row("time.sleep(1 ms), overshoot (reference)", base)


if __name__ == "__main__":
    if "--bench" in sys.argv:
        bench()
    else:
        unittest.main(verbosity=2)
