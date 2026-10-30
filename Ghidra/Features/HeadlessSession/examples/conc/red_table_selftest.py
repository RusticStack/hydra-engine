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
"""Self-check of red_table.py's parallel mode with fake scripts (no engine, a few seconds).

    python red_table_selftest.py

The scripts are replaced by a fake ``run`` that writes the outputs a script would write (s1/s4 per part, the
crash shards' results.jsonl, the s6 project, the sample file). The checks: the parallel report has exactly the
rows of the serial report, in the same order and with the same verdicts; the parts are merged into the output
the serial script writes; the crash shards add up to --crash-n/--fork-n unanswered kills and their records are
all counted; a second parallel run takes s6 and the sample from the cache and still has the same rows.
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import red_table as rt  # noqa: E402


def arg(cmd, name, default=None):
    return cmd[cmd.index(name) + 1] if name in cmd else default


class Fake:
    """Stands in for ``red_table.run``: records the calls and writes a script's outputs."""

    def __init__(self):
        self.calls = []
        self.detail = []

    def __call__(self, cmd, log, env=None, timeout=3600, mask=None):
        script = pathlib.Path(cmd[2]).name
        work = pathlib.Path(arg(cmd, "--work"))
        tag = arg(cmd, "--tag", "")
        self.calls.append((script, tag, arg(cmd, "--parts")))
        self.detail.append({"script": script, "tag": tag, "mask": mask, "scen": cmd[3] if script == "run_c.py" else None,
                            "calib_in": (env or {}).get("CALIB_IN"), "calib_out": (env or {}).get("CALIB_OUT")})
        pathlib.Path(log).parent.mkdir(parents=True, exist_ok=True)
        if script == "mkbase.py":
            (work / "proj" / "base").mkdir(parents=True, exist_ok=True)
        elif script == "s6_import.py":
            (work / "proj" / ("s6" + tag)).mkdir(parents=True, exist_ok=True)
            (work / "proj" / ("s6" + tag) / "p.gpr").write_text("x")
            (work / f"s6_import{tag}.json").write_text(json.dumps({"a_import_analyze": {"ok": True}, "b_six_imports": [{"ok": True}]}))
        elif script == "s1_xqueue.py":
            parts = arg(cmd, "--parts") or "abc"
            (work / f"s1_xqueue{tag}.json").write_text(json.dumps([{"variant": p, "probes": [], "events": []} for p in parts]))
        elif script == "s4_dead.py":
            parts = arg(cmd, "--parts") or "abc"
            (work / f"s4_dead{tag}.json").write_text(json.dumps({"part_" + p: 1 for p in parts}))
        elif script == "c_sample.py":
            (work / "sample-fixture.json").write_text("{}")
        elif script == "run_c.py":
            scen, n, seed = cmd[3], int(cmd[6]), int(cmd[7])
            d = work / "run" / f"{scen}-fixture-ntfs-{env['RUN_TAG']}"
            d.mkdir(parents=True, exist_ok=True)
            # n unanswered kills (one of them a corrupt / partial one) plus seed-dependent answered ones
            recs = [{"i": i, "seed": seed, "acked_before_kill": False, "anomalies": []} for i in range(n)]
            recs[0]["anomalies"] = ["CORRUPT_OR_UNOPENABLE"] if scen == "a" else ["PARTIAL_DEST_VISIBLE:rep_only_NO_GPR"]
            recs += [{"i": n + i, "seed": seed, "acked_before_kill": True, "anomalies": []} for i in range(seed % 3)]
            (d / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
            (d / "calibration.json").write_text(json.dumps({"window_s": 0.1}))
            if env.get("CALIB_OUT"):
                pathlib.Path(env["CALIB_OUT"]).write_text(json.dumps({"window_s": 0.1, "bases": {}}))
        return {"exit": 0, "seconds": 0.0}


class RedTableParallel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "eng" / "Ghidra").mkdir(parents=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "x.gpr").write_text("")
        self.fake = Fake()
        self._run, self._stop = rt.run, rt.stop_daemons
        rt.run = self.fake
        rt.stop_daemons = lambda *a, **k: []

    def tearDown(self):
        rt.run, rt.stop_daemons = self._run, self._stop
        self.tmp.cleanup()

    def table(self, tag, *extra):
        work = self.root / "work"
        args = ["--ghidra", str(self.root / "eng"), "--work", str(work), "--project", str(self.root / "src" / "x.gpr"),
                "--program", "/x.exe", "--fixtures", str(self.root / "fix"), "--fixture-exe", "x.exe", "--tag", tag,
                "--crash-n", "40", "--fork-n", "30"] + list(extra)
        rt.main(args)
        return json.loads((work / f"red-table{tag}.json").read_text(encoding="utf-8")), work

    def test_same_rows_serial_and_parallel(self):
        ser, work = self.table("S", "--serial")
        par, _ = self.table("P", "--crash-shards", "8", "--fork-shards", "8")
        rows = lambda r: [(x["row"], x["verdict"]) for x in r["results"]]   # noqa: E731
        self.assertEqual(rows(ser), rows(par))
        self.assertEqual(len(ser["results"]), len(rt.LOCKMAP) + 1 + 2 + 1 + len(rt.REGRESSION_ONLY))
        # parts: three processes each for s1 and s4, merged into the output the serial script writes
        self.assertEqual(sorted(p for s, t, p in self.fake.calls if s == "s1_xqueue.py" and t.startswith("P")), ["a", "b", "c"])
        self.assertEqual([v["variant"] for v in json.loads((work / "s1_xqueueP.json").read_text())], ["a", "b", "c"])
        self.assertEqual(json.loads((work / "s4_deadP.json").read_text()), {"part_a": 1, "part_b": 1, "part_c": 1})
        # crash shards: the kill counts add up to N, every record of every shard is counted
        crash = {x["row"]: x["metrics"] for x in par["results"] if x["row"].startswith("C-")}
        crash_s = {x["row"]: x["metrics"] for x in ser["results"] if x["row"].startswith("C-")}
        self.assertEqual(crash["C-poison"]["unanswered_kills"], 40)
        self.assertEqual(crash_s["C-poison"]["unanswered_kills"], 40)
        self.assertEqual(crash["C-poison"]["corrupt"], 8)          # one per shard
        self.assertEqual(sum(1 for s, t, p in self.fake.calls if s == "run_c.py" and t == "P"), 16)
        shard_recs = sum(m["records"] for m in par["runs"]["run_c b shards"]["merged"])
        self.assertEqual(crash["C-fork"]["records"], shard_recs)
        self.assertEqual(sum(par["runs"]["run_c a shards"]["n"]), 40)
        self.assertEqual(sum(par["runs"]["run_c b shards"]["n"]), 30)

    def test_cache_second_run(self):
        self.table("P1")
        n6 = sum(1 for s, t, p in self.fake.calls if s == "s6_import.py")
        second, work = self.table("P2")
        self.assertEqual(sum(1 for s, t, p in self.fake.calls if s == "s6_import.py"), n6)   # not run again
        self.assertIn("cached", second["runs"]["s6_import.py"])
        self.assertTrue((work / "proj" / "s6P2" / "p.gpr").is_file())
        self.assertIn("cached", second["runs"]["c_sample"])
        third, _ = self.table("P3", "--no-cache")
        self.assertNotIn("cached", third["runs"]["s6_import.py"])
        self.assertEqual([x["row"] for x in second["results"]], [x["row"] for x in third["results"]])

    def test_shared_calibration(self):
        self.table("C", "--crash-shards", "4", "--fork-shards", "3")
        for scen, k in (("a", 4), ("b", 3)):
            sh = [d for d in self.fake.detail if d["scen"] == scen]
            self.assertEqual(len(sh), k)
            outs = [d["calib_out"] for d in sh if d["calib_out"]]
            ins = [d["calib_in"] for d in sh if d["calib_in"]]
            self.assertEqual(len(outs), 1)                     # one shard calibrates ...
            self.assertEqual(ins, outs * (k - 1))              # ... the others take its window
        self.fake.detail.clear()
        self.table("O", "--crash-shards", "4", "--own-calibration")
        self.assertFalse(any(d["calib_in"] or d["calib_out"] for d in self.fake.detail))

    def test_pinning(self):
        cores = __import__("os").cpu_count() or 1
        r, _ = self.table("Q", "--crash-shards", "3", "--fork-shards", "2", "--shard-cores", "2")
        masks = [d["mask"] for d in self.fake.detail if d["script"] == "run_c.py"]
        pinned = [m for m in masks if m]
        self.assertEqual(len(pinned), min(5, cores // 2))
        for i, m in enumerate(pinned):
            self.assertEqual(bin(m).count("1"), 2)
            self.assertTrue(all(m & o == 0 for o in pinned[i + 1:]))   # disjoint
        self.assertTrue(all(d["mask"] is None for d in self.fake.detail if d["script"].startswith("s")))  # not overlapped: unpinned
        self.fake.detail.clear()
        self.table("R", "--crash-shards", "3", "--fork-shards", "2", "--shard-cores", "2", "--crash-overlap")
        lock = {d["mask"] for d in self.fake.detail if d["script"].startswith("s1_")}
        crash = [d["mask"] for d in self.fake.detail if d["script"] == "run_c.py" and d["mask"]]
        if cores > 10:
            self.assertEqual(len(lock), 1)
            lm = lock.pop()
            self.assertTrue(lm and all(lm & m == 0 for m in crash))
        self.fake.detail.clear()
        self.table("U", "--shard-cores", "0")
        self.assertTrue(all(d["mask"] is None for d in self.fake.detail))

    def test_fast(self):
        r, _ = self.table("F", "--fast")
        self.assertFalse(any(s == "run_c.py" for s, t, p in self.fake.calls if t == "F"))
        rows = {x["row"]: x["verdict"] for x in r["results"]}
        self.assertEqual((rows["C-poison"], rows["C-fork"]), ("NOT RUN", "NOT RUN"))

    def test_cpu_masks(self):
        m, rest = rt.cpu_masks(24, 2, 3)
        self.assertEqual(m, [0b11 << 22, 0b11 << 20, 0b11 << 18])
        self.assertEqual(rest, (1 << 18) - 1)
        m, rest = rt.cpu_masks(4, 2, 5)
        self.assertEqual((len(m), rest), (2, 0))

    def test_split(self):
        for n in (0, 1, 7, 30, 40):
            for k in (1, 3, 8, 50):
                parts = rt.split_n(n, k)
                self.assertEqual(sum(parts), n)
                self.assertTrue(all(p > 0 for p in parts) or n == 0)
                self.assertLessEqual(max(parts, default=0) - min(parts, default=0), 1)
        self.assertEqual(rt.wilson(0, 40)[0], 0.0)


if __name__ == "__main__":
    unittest.main()
