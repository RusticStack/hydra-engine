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
"""Self-test of the corruption oracle and of the fault injectors (PROTOCOL-3.md, section 8, package X0).

The oracle (``oracle.py``, invariants K1-K17 of 3.12) is only worth its verdicts if it can fail. This
file plants the violations X1-X11 into a clean environment and requires the oracle to flag X1-X5 and
X7-X11 and to pass X6 (a torn *last* ``CURRENT.log`` line is tolerated); it also requires the clean
environment to pass every check (no false positive), runs the checks that need no planting through
their failing inputs, runs the oracle over the kept corrupt forks of measurement C and over an
unkilled control, and exercises the injectors of ``chaos_lib.py``.

Run through the engine suite (the tests are in the default run; none needs a build):

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only oracle_selftest

Optional inputs: ``--project <analysed project .gpr>`` is used as the base of the planted trees (a
synthetic project is built when it is absent) and, with the environment variable
``HYDRA_X0_CRASH_C`` pointing at the folder of measurement C (the one holding ``run/``), the kept
corrupt forks are checked. Nothing here is written outside ``--work``; no game-derived data is
read except the 8-byte headers of the kept forks, and none is copied except a few-MB fixture fork.
"""
import json
import os
import pathlib
import random
import shutil
import sys
import threading
import time

import daemon_tests as dt

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import chaos_lib as chaos  # noqa: E402
import oracle  # noqa: E402

CORPUS_ENV = "HYDRA_X0_CRASH_C"
#: forks with the poisoned newest version file that survive in the measurement-C folder (the spec
#: counts 12 kills; 3 of them were ReFS runs whose folders were not kept, and 9 were kept)
CORPUS_EXPECT = 9


# ---- a clean environment -------------------------------------------------------------------------

def make_project(dst: pathlib.Path, name: str = "proj", src_gpr=None, purpose="fork", state="complete",
                 rng=None) -> pathlib.Path:
    """A project folder: a copy of ``src_gpr``'s folder, or a synthetic one with version files that carry
    the buffer-file magic. Writes the fork sidecar. Returns the ``.gpr`` path."""
    rng = rng or random.Random(7)
    if dst.exists():
        shutil.rmtree(dst)
    if src_gpr:
        src = pathlib.Path(src_gpr)
        shutil.copytree(src.parent, dst)
        gpr = dst / src.name
        shutil.rmtree(dst / "__pycache__", ignore_errors=True)
    else:
        gpr = dst / f"{name}.gpr"
        db = dst / f"{name}.rep" / "idata" / "00" / "~00000000.db"
        db.mkdir(parents=True)
        gpr.write_text("<?xml version=\"1.0\"?>\n<PROJECT/>\n")
        for n in (1, 2, 3):
            (db / f"db.{n}.gbf").write_bytes(oracle.MAGIC + bytes(rng.getrandbits(8) for _ in range(2048)))
        (dst / f"{name}.rep" / "idata" / "~index.dat").write_text("index")
        (dst / f"{name}.rep" / "idata" / "~index.bak").write_text("index-bak")
        (dst / f"{name}.rep" / "project.prp").write_text("<STATE/>")
    side = gpr.with_name(gpr.stem + ".fork.json")
    side.write_text(json.dumps({"format": 1, "kind": "ghidra-session-fork", "purpose": purpose,
                                "disposable": purpose == "fork", "state": state, "mode": "full"}, indent=1))
    return gpr


def newest_version(proj: pathlib.Path) -> pathlib.Path:
    return max(((n, p) for p, n in oracle.version_files(proj)), key=lambda t: t[0])[1]


class Env:
    """A clean set of trees on which every file-level invariant of the oracle holds."""

    def __init__(self, root: pathlib.Path, src_gpr=None):
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        self.root = root
        self.state_dir = root / "state"
        (self.state_dir / "seals").mkdir(parents=True)
        self.tmpdir = root / "tmp"
        self.tmpdir.mkdir()
        # a fork (K2, K6, K7), a sealed generation (K1, K1u), an uninvolved project (K9)
        self.fork_gpr = make_project(root / "forks" / "f1", "f1", src_gpr)
        self.proj = self.fork_gpr.parent
        self.lineage = root / "lineages" / "L-0001"
        gen_dir = self.lineage / "gen" / "0002"
        self.gen_gpr = make_project(gen_dir, "g2", src_gpr, purpose="generation", state="complete")
        self.gen = self.gen_gpr.parent
        self.other = make_project(root / "other" / "o1", "o1", src_gpr).parent
        self.guard = oracle.TreeGuard(other=self.other)
        # seal records: the three of D66
        (self.gen / "SEALED.json").write_text(json.dumps({"revision": "r1", "manifestSha256": "m", "sealedAt": "t", "by": "x0"}))
        (self.state_dir / "seals" / "g2.json").write_text(json.dumps({"path": str(self.gen_gpr), "revision": "r1"}))
        self.baseline = oracle.seal_snapshot(self.gen)
        files = [{"path": k, "size": (self.gen / k).stat().st_size if (self.gen / k).exists() else 0, "sha256": v}
                 for k, v in sorted(self.baseline.items())]
        self.manifest = {"format": 1, "cid": "c-2", "base": {"generation": 1, "revision": 1}, "files": files,
                         "filesetSha256": oracle.sha256_hex(oracle.canonical(files)),
                         "store": {"view": "v", "revision": 3, "ids": ["r3"], "skipped": []}}
        self.manifest["selfSha256"] = oracle.sha256_hex(oracle.canonical(self.manifest))
        (self.gen / "MANIFEST.json").write_text(json.dumps(self.manifest, indent=1))
        # the lineage: three generations, two changesets, one conflict-free history
        self.base_state = {("address:0x401000", "name"): "FUN_00401000", ("address:0x402000", "name"): "FUN_00402000"}
        cs1 = {"csid": "cs1", "view": "a1", "records": [
            {"id": "r1", "seq": 1, "subject": "address:0x401000", "field": "name", "before": "FUN_00401000", "after": "Foo"},
            {"id": "r2", "seq": 2, "subject": "address:0x401000", "field": "name", "before": "Foo", "after": "Foo2"}]}
        cs2 = {"csid": "cs2", "view": "a2", "records": [
            {"id": "r3", "seq": 1, "subject": "address:0x402000", "field": "name", "before": "FUN_00402000", "after": "Bar"}]}
        self.changesets = {"cs1": cs1, "cs2": cs2}
        for sub in ("done", "pending"):
            (self.lineage / sub).mkdir(parents=True, exist_ok=True)
        for cs in (cs1, cs2):
            (self.lineage / "done" / f"{cs['csid']}.json").write_text(json.dumps(oracle.seal_record(cs)))
        lines = [{"seq": 1, "gen": 0, "reason": "register", "csids": []},
                 {"seq": 2, "gen": 1, "reason": "commit", "cid": "c-1", "csids": ["cs1"]},
                 {"seq": 3, "gen": 2, "reason": "commit", "cid": "c-2", "csids": ["cs2"]}]
        (self.lineage / "CURRENT.log").write_bytes(b"".join(oracle.crc_line(x) for x in lines))
        (self.lineage / "gen" / "0001").mkdir(parents=True, exist_ok=True)
        (self.lineage / "gen" / "0001" / "MANIFEST.json").write_text(json.dumps(
            {"format": 1, "store": {"ids": ["r1", "r2"], "skipped": []}}))
        self.head_state = {("address:0x401000", "name"): "Foo2", ("address:0x402000", "name"): "Bar"}
        self.acked_csids = ["cs1", "cs2"]
        # the witness ledger and the recovered state (K5), the tagged edit set (K4), views (K11)
        self.ledger = oracle.Ledger(root / "ledger.jsonl")
        for op in ("op1", "op2", "op3"):
            self.ledger.sent(op, kind="save")
            self.ledger.ack(op, kind="save")
        self.ledger.close()
        self.recovered = {"op1", "op2", "op3"}
        self.tagged = [f"0x4{i:05x}" for i in range(20)]
        self.names = {a: f"cg2_{i:04d}" for i, a in enumerate(self.tagged)}
        self.views = {"a1": {"own": {"t1"}, "saw": {"t1"}}, "a2": {"own": {"t2"}, "saw": {"t2"}},
                      "head": {"own": set(), "saw": set()}}
        self.published = {}
        self.tmp_before = len(os.listdir(self.tmpdir))
        self.extra = oracle.Report("extra")  # plants that need a process add their findings here

    def write_log(self, lines, tail=b""):
        (self.lineage / "CURRENT.log").write_bytes(b"".join(oracle.crc_line(x) for x in lines) + tail)


def full_check(env: Env, name: str = "oracle") -> oracle.Report:
    """Every file-level invariant of the oracle over ``env``."""
    rep = oracle.Report(name)
    oracle.check_k2(env.proj, rep)
    oracle.check_k2(env.gen, rep)
    oracle.check_k6(env.fork_gpr, require_sidecar=True, rep=rep)
    oracle.check_k6_staging(env.root / "forks", rep)
    man_path = env.gen / "MANIFEST.json"
    oracle.verify_manifest(json.loads(man_path.read_text()), rep, man_path)
    oracle.check_k1(env.gen, oracle.manifest_snapshot(json.loads(man_path.read_text())), rep, label="gen 2")
    oracle.check_k1u(env.gen_gpr, env.state_dir, True, rep)
    oracle.check_k7_locks(env.root / "forks", quiescent=True, rep=rep)
    oracle.check_k7_locks(env.gen, quiescent=True, rep=rep)
    oracle.check_k7_tmp(env.tmpdir, env.tmp_before, rep=rep)
    lin = oracle.load_lineage(env.lineage)
    oracle.check_k12(lin, env.acked_csids, rep)
    oracle.check_k17(env.lineage / "done", env.lineage / "CURRENT.log", rep)
    oracle.check_k16(env.base_state, [ln for (_o, ln, _b) in lin["log"]["lines"]], env.changesets, env.head_state,
                     lin["manifests"], env.acked_csids, rep)
    oracle.check_k8(env.base_state, [r for cs in env.changesets.values() for r in cs["records"]], env.head_state, rep=rep)
    oracle.check_k5(oracle.Ledger.acked(oracle.Ledger.read(env.root / "ledger.jsonl"), "save"), env.recovered, "save", rep)
    oracle.check_k4(env.names, env.tagged, sent=2, acked=2, rep=rep)
    env.guard.check(rep)
    oracle.check_k11(env.views, env.published, rep)
    rep.merge(env.extra)
    return rep


def src_project(c):
    p = getattr(c.a, "project", None)
    return pathlib.Path(p) if p else None


# ---- the planted violations ----------------------------------------------------------------------

def plant_x1(env, c):   # a zero-header newest version
    p = newest_version(env.proj)
    with open(p, "r+b") as f:
        f.write(b"\0" * 8)
    return "K2:newest_header_invalid"


def plant_x2(env, c):   # one flipped byte in a sealed file
    p = newest_version(env.gen)
    with open(p, "r+b") as f:
        f.seek(100)
        b = f.read(1)
        f.seek(100)
        f.write(bytes([b[0] ^ 0x01]))
    return "K1:changed"


def plant_x3(env, c):   # a .lock whose holder is alive (fresh lease, no daemon holds this tree)
    (env.proj / (env.fork_gpr.stem + ".lock")).write_text("held")
    return "K7:lock_live"


def plant_x3_stale(env, c):   # the same lock, left by a holder that died (lease long expired)
    p = env.proj / (env.fork_gpr.stem + ".lock~")
    p.write_text("held")
    old = time.time() - 600
    os.utime(p, (old, old))
    return "K7:lock_stale"


def plant_x4(env, c):   # a duplicate generation line
    log = oracle.read_crc_log(env.lineage / "CURRENT.log")
    lines = [ln for (_o, ln, _b) in log["lines"]]
    lines.append(dict(lines[-1], seq=4))
    env.write_log(lines)
    return "K12:duplicate_generation"


def plant_x5(env, c):   # an acknowledged op missing after recovery
    env.recovered = {"op1", "op3"}
    return "K5:acked_missing"


def plant_x6(env, c):   # a torn last CURRENT.log line: must be tolerated
    log = (env.lineage / "CURRENT.log").read_bytes()
    full = oracle.crc_line({"seq": 4, "gen": 3, "reason": "commit", "cid": "c-3", "csids": ["cs3"]})
    (env.lineage / "CURRENT.log").write_bytes(log + full[: len(full) // 2])
    return None


def plant_x7(env, c):   # .rep without .gpr
    env.fork_gpr.unlink()
    return "K6:rep_without_gpr"


def plant_x8(env, c):   # mixed generation tags in one tagged edit set
    for a in env.tagged[:10]:
        env.names[a] = env.names[a].replace("cg2_", "cg1_")
    return "K4:mixed_generation"


def plant_x9(env, c):   # an orphan native decompiler that is suspended
    p = chaos.spawn_decompiler(c.a.ghidra)
    c.procs.append(p)
    time.sleep(0.5)
    if not chaos.suspend(p.pid):
        raise dt.Fail("could not suspend the planted decompiler")
    state = oracle.process_suspended(p.pid)
    dt.check(state in (True, None), f"the planted decompiler is not seen as suspended ({state})")
    env.extra.merge(oracle.check_k7_processes(daemon_pids=(), settle_s=1.0, only_pids=[p.pid]))
    env.cleanup = lambda: chaos.terminate_all([p])
    return "K7:orphan_decompiler"


def plant_x10(env, c):   # a leaked thread
    clean = chaos.spawn_idle(60, 0)
    leaky = chaos.spawn_idle(60, 48)
    c.procs += [clean, leaky]
    time.sleep(1.5)
    base = oracle.thread_count(clean.pid)
    env.extra.merge(oracle.check_k7_threads(leaky.pid, base, slack=8, label="(planted)"))
    dt.check(oracle.check_k7_threads(clean.pid, base, slack=8).ok, "the clean child was flagged")
    env.cleanup = lambda: chaos.terminate_all([clean, leaky])
    return "K7:thread_leak"


def plant_x11(env, c):  # sidecar edited back to candidate while the registry and SEALED.json say sealed
    side = env.gen_gpr.with_name(env.gen_gpr.stem + ".fork.json")
    d = json.loads(side.read_text())
    d["state"] = "candidate"
    side.write_text(json.dumps(d, indent=1))
    dt.check(oracle.is_sealed(env.gen_gpr, env.state_dir), "a sealed generation is no longer reported sealed")
    return "K1u:seal_discrepancy"


PLANTS = {"X1": plant_x1, "X2": plant_x2, "X3": plant_x3, "X3b": plant_x3_stale, "X4": plant_x4, "X5": plant_x5,
          "X6": plant_x6, "X7": plant_x7, "X8": plant_x8, "X9": plant_x9, "X10": plant_x10, "X11": plant_x11}


def t_oracle_selftest(c):
    """X1-X5 and X7-X11 are flagged, X6 is tolerated, the clean environment passes every check."""
    src = src_project(c)
    work = c.work / "x0-selftest"
    work.mkdir(parents=True, exist_ok=True)
    env = Env(work / "clean", src)
    clean = full_check(env, "clean")
    dt.check(clean.ok, "false positive on the clean environment: " + "; ".join(sorted(clean.codes())))
    dt.check(not clean.tolerated, f"the clean environment tolerated something: {clean.tolerated}")
    out = {"clean_checked": clean.checked}
    for name, plant in PLANTS.items():
        env = Env(work / name, src)
        expect = plant(env, c)
        rep = full_check(env, name)
        cleanup = getattr(env, "cleanup", None)
        if cleanup:
            cleanup()
        if name == "X6":
            dt.check(rep.ok, f"X6 (torn last line) must pass, got {sorted(rep.codes())}")
            dt.check(any(t["code"] == "torn_tail" for t in rep.tolerated), "X6 was passed but not reported as tolerated")
            out[name] = "tolerated"
            continue
        dt.check(expect in rep.codes(), f"{name}: the oracle did not flag {expect}; it flagged {sorted(rep.codes())}")
        out[name] = sorted(rep.codes())
    return f"{len(PLANTS)} planted variants: " + json.dumps(out, sort_keys=True)


# ---- the invariants that need a different failing input ------------------------------------------

def t_oracle_invariants_fail(c):
    """K1 (added/removed file, hash), K1u (unsealed), K4, K5, K6, K8/K15, K9, K10, K11, K11p, K12, K13, K14, K16 and
    K17 each flag a violation of their own."""
    work = c.work / "x0-invariants"
    work.mkdir(parents=True, exist_ok=True)
    src = src_project(c)
    seen = {}

    def case(label, plant, expect):
        env = Env(work / label, src)
        plant(env)
        rep = full_check(env, label)
        dt.check(expect in rep.codes(), f"{label}: expected {expect}, got {sorted(rep.codes())}")
        seen[label] = expect

    # K1: a file added to / removed from a sealed generation (a writable open: ~journal.bak deleted, ~index.bak changed)
    def add_file(env):
        (env.gen / "extra.bin").write_bytes(b"x")
    case("k1_added", add_file, "K1:added")

    def rm_file(env):
        victim = next(p for p in env.gen.rglob("*") if p.is_file() and p.suffix not in (".json",) and p.name != "SEALED.json")
        victim.unlink()
    case("k1_removed", rm_file, "K1:removed")

    # the sidecar's state field is NOT part of the hash: flipping it alone must not be a K1 change
    env = Env(work / "k1_state_field", src)
    side = env.gen_gpr.with_name(env.gen_gpr.stem + ".fork.json")
    d = json.loads(side.read_text())
    d["state"] = "candidate"
    side.write_text(json.dumps(d))
    dt.check(oracle.check_k1(env.gen, oracle.manifest_snapshot(json.loads((env.gen / "MANIFEST.json").read_text()))).ok,
             "K1 counted the sidecar state field")

    # K1u: nothing says sealed
    def unseal_all(env):
        (env.gen / "SEALED.json").unlink()
        (env.state_dir / "seals" / "g2.json").unlink()
        side = env.gen_gpr.with_name(env.gen_gpr.stem + ".fork.json")
        d = json.loads(side.read_text())
        d["state"] = "candidate"
        side.write_text(json.dumps(d))
    case("k1u_unsealed", unseal_all, "K1u:unsealed")

    # K1u: only one record left (the registry); the union still says sealed
    env = Env(work / "k1u_one", src)
    (env.gen / "SEALED.json").unlink()
    side = env.gen_gpr.with_name(env.gen_gpr.stem + ".fork.json")
    side.write_text(json.dumps({"format": 1, "purpose": "generation", "state": "candidate"}))
    dt.check(oracle.is_sealed(env.gen_gpr, env.state_dir), "registry alone no longer seals")
    dt.check("K1u:seal_discrepancy" in oracle.check_k1u(env.gen_gpr, env.state_dir).codes(), "K1u did not report the discrepancy")
    # a manifest whose self hash is wrong
    env = Env(work / "k1_manifest", src)
    m = json.loads((env.gen / "MANIFEST.json").read_text())
    m["cid"] = "c-evil"
    rp = oracle.Report()
    oracle.verify_manifest(m, rp)
    dt.check("K1:manifest_self_hash" in rp.codes(), "a changed manifest passed its self hash")

    # K4: a generation outside acked..sent
    def old_gen(env):
        env.names = {a: n.replace("cg2_", "cg0_") for a, n in env.names.items()}
    case("k4_range", old_gen, "K4:generation_out_of_range")

    # K5: also through the ledger reader (a torn last ledger line is ignored, an ack is not lost)
    def lose(env):
        env.recovered = set()
    case("k5_all", lose, "K5:acked_missing")

    # K6: a gpr without a rep; a sidecar in the wrong state; a staging folder
    def gpr_only(env):
        shutil.rmtree(env.fork_gpr.with_suffix(".rep"))
    case("k6_gpr_only", gpr_only, "K6:gpr_without_rep")

    def bad_state(env):
        s = env.fork_gpr.with_name(env.fork_gpr.stem + ".fork.json")
        d = json.loads(s.read_text())
        d["state"] = "publishing"
        s.write_text(json.dumps(d))
    case("k6_state", bad_state, "K6:sidecar_state")

    def no_sidecar(env):
        env.fork_gpr.with_name(env.fork_gpr.stem + ".fork.json").unlink()
    case("k6_no_sidecar", no_sidecar, "K6:no_sidecar")

    def staging(env):
        (env.root / "forks" / ".f1.fork-abc.tmp").mkdir()
    case("k6_staging", staging, "K6:staging_left")

    def sidecar_tmp(env):    # 8.13: a killed publisher's sidecar .tmp left after the sweep
        side = env.fork_gpr.with_name(env.fork_gpr.stem + ".fork.json")
        side.with_name(side.name + ".tmp").write_text(side.read_text())
    case("k6_sidecar_tmp", sidecar_tmp, "K6:sidecar_tmp_left")

    # K7: temp growth
    def grow(env):
        for i in range(40):
            (env.tmpdir / f"tmp{i}.ps").write_text("x")
    case("k7_tmp", grow, "K7:tmp_growth")

    # K8 / K15: a view that differs from the replay
    def bad_view(env):
        env.head_state = dict(env.head_state)
        env.head_state[("address:0x402000", "name")] = "Wrong"
    case("k8_view", bad_view, "K8:view_differs_from_replay")
    rp = oracle.check_k15(env.base_state, [r for cs in env.changesets.values() for r in cs["records"]],
                          {("address:0x401000", "name"): "stale"})
    dt.check("K15:view_differs_from_replay" in rp.codes(), "K15 passed a view that differs from a rebuild")

    # K9: an uninvolved project changed
    def touch_other(env):
        (env.other / "intruder.txt").write_text("x")
    case("k9_other", touch_other, "K9:uninvolved_project_changed")

    # K11 / K11p
    def leak(env):
        env.views["a2"]["saw"] = {"t2", "t1"}
    case("k11_leak", leak, "K11:unpublished_tag_visible")
    def head_leak(env):
        env.views["head"]["saw"] = {"t1"}
    case("k11_head", head_leak, "K11:unpublished_tag_visible")
    # K11p: two sub-agents of one process without `as` share one view (same id): they see each other's tag
    # and that is not a violation; with distinct ids it is
    shared = {"mcp@boot1": {"own": {"t1", "t2"}, "saw": {"t1", "t2"}}}
    dt.check(oracle.check_k11(shared, {}, shared_ok=True).ok, "K11p: a shared view was flagged")
    split = {"mcp@boot1": {"own": {"t1"}, "saw": {"t1", "t2"}}, "agent-b": {"own": {"t2"}, "saw": {"t2"}}}
    dt.check("K11:unpublished_tag_visible" in oracle.check_k11(split, {}).codes(), "K11p: distinct ids saw each other")

    # K12: an acknowledged changeset missing; a changeset applied twice; a mid-log gap; a done file with no commit
    def ack_missing(env):
        env.acked_csids = env.acked_csids + ["cs9"]
    case("k12_acked", ack_missing, "K12:acked_publish_missing")

    def twice(env):
        log = oracle.read_crc_log(env.lineage / "CURRENT.log")
        lines = [ln for (_o, ln, _b) in log["lines"]]
        lines.append({"seq": 4, "gen": 3, "reason": "commit", "csids": ["cs1"]})
        env.write_log(lines)
    case("k12_twice", twice, "K12:applied_twice")

    def gap(env):
        data = (env.lineage / "CURRENT.log").read_bytes().split(b"\n")
        data[1] = b"deadbeef " + data[1][9:]  # a bad CRC in the middle
        (env.lineage / "CURRENT.log").write_bytes(b"\n".join(data))
    case("k12_gap", gap, "K12:mid_log_gap")
    case("k17_gap", gap, "K17:torn_middle")

    def done_only(env):
        (env.lineage / "done" / "cs7.json").write_text(json.dumps(oracle.seal_record({"csid": "cs7", "records": []})))
    case("k12_done", done_only, "K12:done_without_commit")

    # K16: a silent lost update (the head misses a record the log claims) and an engine claim that differs
    def lost(env):
        env.head_state = dict(env.head_state)
        env.head_state[("address:0x401000", "name")] = "Foo"   # r2 lost
    case("k16_lost", lost, "K16:head_differs_from_model")

    def claim(env):
        m = json.loads((env.lineage / "gen" / "0001" / "MANIFEST.json").read_text())
        m["store"]["ids"] = ["r1"]
        (env.lineage / "gen" / "0001" / "MANIFEST.json").write_text(json.dumps(m))
    case("k16_claim", claim, "K16:engine_claim_differs")

    # K17: a corrupt sealed record without a usable .bak; a record that falls back to its .bak (a note, not a violation)
    def corrupt_rec(env):
        p = env.lineage / "done" / "cs1.json"
        p.write_text(p.read_text()[:-5])
    case("k17_record", corrupt_rec, "K17:record_corrupt")
    env = Env(work / "k17_bak", src)
    p = env.lineage / "done" / "cs1.json"
    shutil.copy(p, str(p) + ".bak")
    p.write_text("")
    rp = oracle.check_k17(env.lineage / "done")
    dt.check(rp.ok and any(n["code"] == "record_fell_back" for n in rp.notes), "K17: the .bak fallback was not accepted")
    # 8.13: the publish leader's marker and a .rep's program data are plain JSON, not records; a record that lost its
    # seal is still a violation
    env = Env(work / "k17_plain", src)
    (env.lineage / "publish.leader.json").write_text(json.dumps({"pid": 1, "at": "x"}))
    (env.lineage / "gen" / "Owned.rep").mkdir(parents=True, exist_ok=True)
    (env.lineage / "gen" / "Owned.rep" / "programs.json").write_text("{}")
    rp = oracle.check_k17(env.lineage)
    dt.check(rp.ok and sum(n["code"] == "not_a_sealed_record" for n in rp.notes) == 2,
             f"K17: a leader marker or program data judged as a record: {rp.codes()}")
    p = env.lineage / "done" / "cs1.json"
    d = json.loads(p.read_text())
    d.pop("seal", None)
    p.write_text(json.dumps(d))
    rp = oracle.check_k17(env.lineage)
    dt.check("K17:record_corrupt" in rp.codes(), "K17: a record that lost its seal was not flagged")

    # K13, K14, K10 (no engine needed for the verdicts of the first two)
    dt.check("K13:foreign_blocked" in oracle.check_k13({"waits": {"foreignBlocked": 3}}).codes(), "K13 passed foreignBlocked 3")
    dt.check(oracle.check_k13({"waits": {"foreignBlocked": 0, "lockWaitP99Ms": 40}}).ok, "K13 failed on p99 alone (report-only)")
    dt.check(any(n["code"] == "not_measured" for n in oracle.check_k13({}).notes), "K13 hid that hydra.3 reports nothing")
    dt.check("K14:slots_in_use" in oracle.check_k14({"scheduler": {"long": {"inUse": 2}}}).codes(), "K14 passed slots in use")
    dt.check("K14:out_of_memory" in oracle.check_k14({}, log_text="x java.lang.OutOfMemoryError y").codes(), "K14 passed an OOM")
    dt.check("K14:dead_thread" in oracle.check_k14({}, {"deadThreads": ["reaper"]}).codes(), "K14 passed a dead thread")

    class Dead:
        def __call__(self, name):
            raise ConnectionRefusedError("no daemon")
    dt.check("K10:no_ping" in oracle.check_k10(Dead(), "gone").codes(), "K10 passed a daemon that does not answer")
    return f"{len(seen)} planted cases flagged and 14 direct checks: " + ", ".join(sorted(set(seen.values())))


# ---- the 50 ms watcher ----------------------------------------------------------------------------

def t_oracle_header_watcher(c):
    """The 50 ms watcher sees a visible final-named version file with a zero header, even one that is
    repaired 300 ms later, and sees nothing when the file is written under a temporary name and renamed."""
    d = c.work / "x0-watch"
    if d.exists():
        shutil.rmtree(d)
    db = d / "p.rep" / "idata" / "00" / "~00000000.db"
    db.mkdir(parents=True)
    (db / "db.1.gbf").write_bytes(oracle.MAGIC + b"\0" * 64)
    w = oracle.HeaderWatcher(d, 0.05).start()
    time.sleep(0.2)
    # the safe order: written complete under a temporary name, renamed into place
    tmp = db / "tmp123.ps"
    tmp.write_bytes(oracle.MAGIC + b"x" * 64)
    os.replace(tmp, db / "db.2.gbf")
    time.sleep(0.3)
    dt.check(not w.hits, f"the watcher flagged a file that was never visible without its header: {w.hits}")
    # the hydra.3 order: renamed to its final name first, header written afterwards
    (db / "db.3.gbf").write_bytes(b"\0" * 8 + b"x" * 64)
    time.sleep(0.3)
    with open(db / "db.3.gbf", "r+b") as f:
        f.write(oracle.MAGIC)
    time.sleep(0.2)
    w.stop()
    rep = w.report()
    dt.check(len(w.hits) == 1 and "K2:visible_invalid_header" in rep.codes(), f"the watcher hits: {w.hits}")
    dt.check(w.scans >= 8, f"the watcher scanned only {w.scans} times in about 1 s")
    return f"{w.scans} scans in about 1 s; one visible invalid header seen, none for the rename-into-place order"


# ---- the kept corrupt forks of measurement C --------------------------------------------------------

def corrupt_forks(corpus: pathlib.Path):
    """``(fork folder, canon folder)`` of every kept iteration whose fork has a zero-header version file."""
    out = []
    for it in sorted(corpus.glob("run/*/it*")):
        fork = it / "fork"
        if not fork.is_dir():
            continue
        zero = [p for p, _n in oracle.version_files(fork) if not oracle.header_ok(p)]
        if zero:
            out.append((fork, it / "canon"))
    return out


def t_oracle_crash_c_forks(c):
    """The oracle flags every kept corrupt fork of measurement C (the zero-header newest version file) and passes the
    unkilled canon of the same iteration; a corrupt fixture fork really fails to open in the engine."""
    corpus = os.environ.get(CORPUS_ENV)
    if not corpus:
        return (f"NOT RUN: {CORPUS_ENV} is not set (the folder of measurement C that holds run/); "
                "set it to run the kept corrupt forks")
    corpus = pathlib.Path(corpus)
    pairs = corrupt_forks(corpus)
    dt.check(len(pairs) >= CORPUS_EXPECT, f"only {len(pairs)} corrupt forks kept under {corpus}, expected {CORPUS_EXPECT}")
    flagged = controls = 0
    for fork, canon in pairs:
        rep = oracle.check_k2(fork)
        dt.check("K2:newest_header_invalid" in rep.codes(), f"{fork} was not flagged: {sorted(rep.codes())}")
        flagged += 1
        if canon.is_dir():
            dt.check(oracle.check_k2(canon).ok, f"the unkilled canon {canon} was flagged")
            controls += 1
    # the engine agrees: open a copy of a small (fixture) fork; the control copy opens
    fixture = [(f, k) for f, k in pairs if "fixture" in f.parts[-3]]
    engine = "no fixture fork kept"
    if fixture:
        fork, canon = fixture[0]
        bad = c.work / "x0-corpus" / "bad"
        good = c.work / "x0-corpus" / "good"
        for d in (bad, good):
            if d.exists():
                shutil.rmtree(d)
        shutil.copytree(fork, bad)
        shutil.copytree(canon, good)
        gpr_bad = next(bad.glob("*.gpr"))
        gpr_good = next(good.glob("*.gpr"))
        d = c.daemon("x0-corpus")
        with d.connect("x0", "dt_x0") as s:
            ok_good = s.call("open_project", path=str(gpr_good))["id"]
            progs = [e["path"] for e in s.call("list", project=ok_good, programsOnly=True, recursive=True)["entries"]]
            dt.check(progs, "the control project lists no program")
            s.call("open_program", path=progs[0], project=ok_good)
            bp = s.call("open_project", path=str(gpr_bad))["id"]
            try:
                s.call("open_program", path=progs[0], project=bp)
                engine = "the engine opened the corrupt fork (the oracle flagged it; that is a finding)"
                raise dt.Fail(engine)
            except c.gs.SessionError as e:
                engine = f"engine refuses the corrupt fork ({e.code}: {str(e.message)[:80]}); the control opens"
        d.stop(force=True)
    return f"{flagged} kept corrupt forks flagged (spec: 12 kills, {CORPUS_EXPECT} kept on disk), {controls} unkilled controls pass; {engine}"


# ---- the injectors ------------------------------------------------------------------------------------

def t_chaos_injectors(c):
    """suspend/resume and terminate on a child, the trigger-timed kill (order and delay), the handle holder (a rename fails while
    held), the ENOSPC seam (matching paths only) and the disk-reserve configuration."""
    out = {}
    # suspend / resume / terminate
    p = chaos.spawn_idle(120, 0)
    c.procs.append(p)
    time.sleep(1.0)
    dt.check(oracle.process_suspended(p.pid) is False, "a running child is reported suspended")
    with chaos.Suspended(p.pid):
        s = oracle.process_suspended(p.pid)
        dt.check(s in (True, None), "a suspended child is not reported suspended")
        out["suspended_read"] = s
    dt.check(oracle.process_suspended(p.pid) is False, "the child stayed suspended after the block")
    r = chaos.terminate(p.pid, 10)
    dt.check(r.get("terminated") and not oracle.pid_alive(p.pid), f"terminate failed: {r}")
    # trigger-timed kill: the child's pid is killed `delay` after the watched listing first changes
    watch = c.work / "x0-trigger"
    if watch.exists():
        shutil.rmtree(watch)
    watch.mkdir(parents=True)
    victim = chaos.spawn_idle(120, 0)
    c.procs.append(victim)
    marks = {}

    def start():
        def go():
            time.sleep(0.4)
            marks["change"] = chaos.now()
            (watch / "db.3.gbf").write_bytes(b"x")
        threading.Thread(target=go, daemon=True).start()
    delay = 0.150
    res = chaos.timed_kill(victim.pid, start, delay, watch=watch, max_wait_s=10)
    t_dead = chaos.now()
    dt.check(res["trigger_hit"] and res["kill"].get("terminated"), f"trigger-timed kill: {res}")
    gap = (t_dead - marks["change"]) * 1000
    dt.check(gap >= delay * 1000 - 20, f"the kill came {gap:.0f} ms after the change, wanted at least {delay * 1000:.0f}")
    out["trigger_kill_gap_ms"] = round(gap)
    # random delay is repeatable
    a = [chaos.random_delay(random.Random(5), 0.0, 1.0) for _ in range(3)]
    dt.check(len(set(a)) == 1, "random_delay is not deterministic for a seed")
    # handle holder
    f = c.work / "x0-held.txt"
    f.write_text("x")
    with chaos.HandleHolder(f):
        try:
            os.replace(f, c.work / "x0-held2.txt")
            raise dt.Fail("a held file could be renamed")
        except PermissionError:
            out["held_rename"] = "refused"
    os.replace(f, c.work / "x0-held2.txt")
    # ENOSPC seam
    tgt = c.work / "x0-enospc" / "lineages"
    other = c.work / "x0-enospc" / "other"
    tgt.mkdir(parents=True, exist_ok=True)
    other.mkdir(parents=True, exist_ok=True)
    with chaos.Enospc(lambda path: "lineages" in str(path)) as e:
        try:
            with open(tgt / "x.json", "w") as fh:
                fh.write("hello")
            raise dt.Fail("write under the seam did not raise")
        except OSError as ex:
            dt.check(ex.errno == 28, f"wrong errno {ex.errno}")
        fd = os.open(str(tgt / "y.bin"), os.O_WRONLY | os.O_CREAT)
        try:
            os.write(fd, b"abc")
            raise dt.Fail("os.write under the seam did not raise")
        except OSError as ex:
            dt.check(ex.errno == 28, "wrong errno on os.write")
        finally:
            os.close(fd)
        with open(other / "z.json", "w") as fh:
            fh.write("fine")
    dt.check(e.hits == 2, f"seam hits {e.hits}")
    with open(tgt / "after.json", "w") as fh:   # restored
        fh.write("ok")
    out["enospc_hits"] = e.hits
    cfg = chaos.disk_reserve_config(c.work)
    dt.check(cfg["diskReserve"] > chaos.free_bytes(c.work), "diskReserve is not above the free space")
    chaos.terminate_all([victim])
    return json.dumps(out, sort_keys=True)


# ---- the oracle against a live engine ----------------------------------------------------------------------

def t_oracle_live_engine(c):
    """K3 on a copy of an analysed project (a scan equals itself, a different allowed list is flagged), K10 after a
    client is killed (the daemon answers ping, nothing is held for the dead client), K13/K14 on the engine's own
    answers, and K2/K6/K7/K9 over the copy; needs ``--project``."""
    src = src_project(c)
    if not src or not src.is_file():
        return "NOT RUN: no --project (an analysed project .gpr)"
    work = c.work / "x0-live"
    if work.exists():
        shutil.rmtree(work)
    gpr = make_project_copy(src, work / "proj")
    guard = oracle.TreeGuard(src=src.parent)
    d = c.daemon("x0live")
    with d.connect("x0", "dt_x0") as s:
        o = s.call("open_project", path=str(gpr))
        progs = [e["path"] for e in s.call("list", project=o["id"], programsOnly=True, recursive=True)["entries"]]
        dt.check(progs, "the project lists no program")
        prog = progs[0]
        key = s.call("open_program", path=prog, project=o["id"])["key"]
        fl = oracle._all_functions(s, key)
        sample = [f["address"] for f in fl[:5]]
        base = oracle.scan_program(s, key, sample)
        s.call("close_program", program=key)
        allowed = [{k: base[k] for k in ("functions", "names_sha", "decomp")}]
        rep = oracle.check_k3(s, gpr, prog, allowed, sample)
        dt.check(rep.ok, f"K3 flagged an unchanged project: {sorted(rep.codes())}")
        wrong = [{"functions": base["functions"] + 1, "names_sha": "0" * 64, "decomp": {}}]
        dt.check("K3:names_not_allowed" in oracle.check_k3(s, gpr, prog, wrong, sample).codes(), "K3 passed names that match no allowed generation")
        try:
            h = s.call("health")
        except c.gs.SessionError:   # hydra.3 has no health command (a capability name only)
            h = {}
        dt.check(oracle.check_k13(h).ok, "K13 flagged the live engine")
        st = s.call("status")
        dt.check(oracle.check_k14(st, h).ok, f"K14: {sorted(oracle.check_k14(st, h).codes())}")
    # a second client, in its own process, is killed while it holds a read
    child = c.child("s = gs.Daemon(A[0], A[1], A[2]).connect('x0-victim', 'dt_x0')\n"
                    "o = s.call('open_project', path=A[3]); print('ready', flush=True); time.sleep(600)\n",
                    c.a.ghidra, str(c.state), "x0live", str(gpr))
    line = child.stdout.readline()
    dt.check("ready" in line, f"the victim client did not start: {line!r} {child.poll()}")
    chaos.kill_client_proc(child)
    rep = oracle.check_k10(lambda name: d.connect(name, "dt_x0"), "x0-victim", timeout_s=20)
    dt.check(rep.ok, f"K10: {rep.findings}")
    d.stop(force=True)
    full = oracle.run_tree([work / "proj"], quiescent=True)
    dt.check(not [f for f in full.findings if f["code"] not in ("lock_stale",)],
             f"oracle over the copy after the run: {sorted(full.codes())}")
    guard_rep = guard.check()
    dt.check(guard_rep.ok, "K9: the source project changed")
    return "K3 (match and mismatch), K10 (client kill), K13, K14, K2/K6/K7/K9 over the copy; stale locks of the stopped daemon reported: " + \
        str(sorted(f["code"] for f in full.findings))


def t_chaos_engine_injectors(c):
    """On a live daemon: the native decompiler below it can be found, suspended and killed (the request
    that used it fails alone and the pool respawns), a dropped connection (a reset, no goodbye) is a dead
    client the daemon forgets, and a suspended decompiler is seen as an orphan by K7 once the daemon is dead."""
    src = src_project(c)
    if not src or not src.is_file():
        return "NOT RUN: no --project (an analysed project .gpr)"
    work = c.work / "x0-chaos-live"
    if work.exists():
        shutil.rmtree(work)
    gpr = make_project_copy(src, work / "proj")
    d = c.daemon("x0chaos")
    out = {}
    with d.connect("x0", "dt_x0") as s:
        pid = s.hello["pid"]
        o = s.call("open_project", path=str(gpr))
        prog = [e["path"] for e in s.call("list", project=o["id"], programsOnly=True, recursive=True)["entries"]][0]
        key = s.call("open_program", path=prog, project=o["id"])["key"]
        fl = oracle._all_functions(s, key)
        addrs = [f["address"] for f in fl if not f.get("thunk") and not f.get("external") and f.get("size", 0) >= 16]
        dt.check(len(addrs) >= 3, "the project has fewer than 3 decompilable functions")
        dt.check(s.call("decompile", program=key, address=addrs[0], timeout=60).get("completed", True), "first decompile failed")
        dec = chaos.decompilers_of(pid)
        dt.check(dec, "no native decompiler below the daemon after a decompile")
        out["decompilers_before"] = len(dec)
        # suspend: a decompile now would hang; resume and it completes (nothing is lost)
        sus = chaos.suspend_decompilers(pid)
        dt.check(sus and all(oracle.process_suspended(p) in (True, None) for p in sus), "suspend_decompilers")
        for p in sus:
            chaos.resume(p)
        # kill: the next request works (the pool respawns), the daemon is untouched
        killed = chaos.kill_decompilers(pid)
        dt.check(killed and all(k.get("terminated") for k in killed), f"kill_decompilers: {killed}")
        try:
            r = s.call("decompile", program=key, address=addrs[1], timeout=60)
            out["after_kill"] = "completed" if r.get("completed", True) else "incomplete"
        except c.gs.SessionError as e:
            out["after_kill"] = f"failed alone: {e.code}"
        r2 = s.call("decompile", program=key, address=addrs[2], timeout=60)
        dt.check(r2.get("completed", True), "the pool did not respawn: the second decompile after the kill failed")
        dt.check(oracle.pid_alive(pid), "the daemon died with its decompiler")
        # a dropped connection is a dead client
        victim = d.connect("x0-dropped", "dt_x0")
        victim.call("open_project", path=str(gpr))
        dt.check(chaos.abort_connection(victim), "abort_connection found no socket")
        rep = oracle.check_k10(lambda name: d.connect(name, "dt_x0"), "x0-dropped", timeout_s=20)
        dt.check(rep.ok, f"K10 after a dropped connection: {rep.findings}")
        # leave one suspended decompiler behind and kill the daemon: K7 must see the orphan, and only ours
        s.call("decompile", program=key, address=addrs[0], timeout=60)
        left = chaos.decompilers_of(pid)
    dt.check(left, "no decompiler to leave behind")
    chaos.suspend(left[0])
    chaos.terminate(pid, 60)
    rep = oracle.check_k7_processes(daemon_pids=[pid], settle_s=2.0, only_pids=left[:1])
    for p in left:
        chaos.resume(p)
        chaos.terminate(p, 10)
    dt.check("K7:orphan_decompiler" in rep.codes(), f"K7 did not see the suspended orphan: {rep.findings}")
    out["orphan_seen"] = True
    d.stop(force=True)
    return json.dumps(out, sort_keys=True)


def make_project_copy(src_gpr: pathlib.Path, dst: pathlib.Path) -> pathlib.Path:
    shutil.copytree(src_gpr.parent, dst)
    return dst / src_gpr.name


TESTS = {
    "oracle_selftest": t_oracle_selftest,
    "oracle_invariants_fail": t_oracle_invariants_fail,
    "oracle_header_watcher": t_oracle_header_watcher,
    "oracle_crash_c_forks": t_oracle_crash_c_forks,
    "chaos_injectors": t_chaos_injectors,
    "oracle_live_engine": t_oracle_live_engine,
    "chaos_engine_injectors": t_chaos_engine_injectors,
}
