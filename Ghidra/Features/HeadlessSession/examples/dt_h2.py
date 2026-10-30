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
"""H2: a writable ``upgrade:true`` open of an older-format program in a disposable fork takes the upgrade cache's
upgraded version of the fork's source instead of upgrading in memory (``UpgradeCache.adoptForFork``).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll \
        --legacy-project <older-format project> --only fork_upgrade_from_cache

* ``fork_upgrade_from_cache``: with the source's copy ready, a fork's writable open finds the current format: its
  database folder holds the adopted next version and the one before it, no temporary file, and the program is
  changed, as after an in-memory upgrade (``save`` answers ``saved``; the protocol has no undo, so the cleared
  undo of ``markUpgraded`` is not observable here). A writable open that adopts and then closes with
  ``discard`` leaves the fork as it was: an open without ``upgrade`` fails with ``conflict`` again and a
  reopen with it is changed again. A daemon with ``forkUpgradeFromCache=false``
  upgrades a second fork in memory. Both forks get the same edits; the function list and the decompilation of
  every function (edited one included) must be identical, before and after save, and after a read-only reopen of
  the saved forks. A fork whose source has no ready copy upgrades in memory; the first such fork starts no build,
  the second starts the source's build. The source is never written.
"""
import hashlib
import json
import pathlib
import shutil

import daemon_tests as dt


def _pid(r):
    pj = r.get("project")
    return r.get("id") or (pj.get("id") if isinstance(pj, dict) else pj)


def _db_dirs(fork: pathlib.Path):
    return sorted(p for p in fork.rglob("~*.db") if p.is_dir())


def _state(s, key, funcs):
    """Function list and the hash of every listed function's decompilation."""
    fl, off = [], 0
    while True:
        r = s.call("functions", program=key, offset=off, limit=1000)
        fl += r["functions"]
        if not r.get("truncated"):
            break
        off += r["returned"]
    names = [(f["address"], f.get("name")) for f in fl]
    dec = {}
    for a in funcs:
        r = s.call("decompile", program=key, address=a, timeout=300, maxChars=10 ** 7)
        dec[a] = hashlib.sha256(json.dumps([r.get("c"), r.get("signature"), r.get("name")],
                                           sort_keys=True).encode()).hexdigest()
    return names, dec


def t_fork_upgrade_from_cache(c):
    if not c.a.legacy_project:
        return "skipped (no --legacy-project)"
    src = pathlib.Path(c.a.legacy_project)
    src = src.parent if src.suffix == ".gpr" else src
    legacy = c.work / "h2-legacy"
    dt.clone_tree(src, legacy)
    before = dt.tree_state(legacy)
    cache = c.work / "h2-upgrade-cache"
    if cache.exists():
        shutil.rmtree(cache)
    notes = []

    # 0. no ready copy: a fork's open upgrades in memory and starts the source's build
    d = c.daemon("h2", keepWarm=0, upgradeCacheDir=str(cache))
    with d.connect("h2", "tests") as s:
        o = s.call("open_project", path=str(legacy))
        prog = c.a.legacy_program or s.call("list", programsOnly=True)["entries"][0]["path"]
        # a source forked once is not also built (its fork pays only its own in-memory upgrade)
        f1 = s.call("fork_project", project=o["id"], path=str(c.work / "h2-fork-1"), writable=True, timeout=600)
        p1 = s.call("open_program", path=prog, project=_pid(f1), writable=True, upgrade=True, wait=1800000)
        dt.check(p1["changed"] is True, f"an upgrade:true open of an older-format fork is not changed: {p1}")
        st = s.call("status")["upgradeCache"]
        dt.check(st["buildsStarted"] == 0, f"the first fork's open started a build of its source: {st}")
        s.call("close_project", project=_pid(f1), discard=True)
        # the second fork of the same source starts it, for the forks after it
        f0 = s.call("fork_project", project=o["id"], path=str(c.work / "h2-fork-0"), writable=True, timeout=600)
        p0 = s.call("open_program", path=prog, project=_pid(f0), writable=True, upgrade=True, wait=1800000)
        dt.check(p0["changed"] is True, f"an upgrade:true open of an older-format fork is not changed: {p0}")
        st = s.call("status")["upgradeCache"]
        dt.check(st["buildsStarted"] == 1 and st["builds"], f"the fork's open started no build of its source: {st}")
        b = dt.wait_build(s, st["builds"][0]["id"])
        dt.check(b["state"] == "ready", f"build failed: {b}")
        dt.check(pathlib.Path(b["source"]).parent.resolve() == legacy.resolve(),
                 f"the build is not of the fork's source: {b}")
        s.call("close_project", project=_pid(f0), discard=True)
        notes.append("no copy: in memory, build of the source started from its second fork")

        # 1a. an adopted version closed without a save goes, as an unsaved in-memory upgrade does
        fc_dir = c.work / "h2-fork-c"
        fc = s.call("fork_project", project=o["id"], path=str(fc_dir), writable=True, timeout=600)
        fc_before = {p: sorted(x.name for x in p.iterdir()) for p in _db_dirs(fc_dir)}
        pc = s.call("open_program", path=prog, project=_pid(fc), writable=True, upgrade=True, wait=1800000)
        dt.check(pc["changed"] is True, f"the adopted fork's program is not changed after the open: {pc}")
        fc_open = {p: sorted(x.name for x in p.iterdir()) for p in fc_before}
        dt.check(fc_open != fc_before, f"fork C did not adopt the upgraded version: {fc_open}")
        s.call("close_program", program=pc["key"], discard=True)
        fc_after = {p: sorted(x.name for x in p.iterdir()) for p in fc_before}
        dt.check(fc_after == fc_before, f"a discarded adoption left the fork changed: {fc_before} -> {fc_after}")
        dt.expect_error("conflict", s.call, "open_program", path=prog, project=_pid(fc), writable=True)
        pc2 = s.call("open_program", path=prog, project=_pid(fc), writable=True, upgrade=True, wait=1800000)
        dt.check(pc2["changed"] is True, f"a reopen after a discarded adoption is not changed: {pc2}")
        s.call("close_project", project=_pid(fc), discard=True)
        notes.append("discarded adoption: the fork is back in its older format")

        # 1. copy ready: fork A adopts the upgraded version
        fa_dir = c.work / "h2-fork-a"
        fa = s.call("fork_project", project=o["id"], path=str(fa_dir), writable=True, timeout=600)
        dbs = _db_dirs(fa_dir)
        vers_before = {p: sorted(x.name for x in p.glob("db.*.gbf")) for p in dbs}
        pa = s.call("open_program", path=prog, project=_pid(fa), writable=True, upgrade=True, wait=1800000)
        # as after an in-memory upgrade: changed, nothing to undo
        dt.check(pa["changed"] is True, f"the adopted fork's program is not changed after the open: {pa}")
        after = {p: sorted(x.name for x in p.iterdir()) for p in dbs}
        grown = [p for p in dbs if after[p] != vers_before[p]]
        dt.check(len(grown) == 1, f"expected one database folder with an adopted version: {vers_before} -> {after}")
        g = grown[0]
        nums = sorted(int(n.split(".")[1]) for n in after[g] if n.startswith("db.") and n.endswith(".gbf"))
        old = max(int(n.split(".")[1]) for n in vers_before[g])
        dt.check(nums == [old, old + 1], f"the fork's versions are not the source's and the next one: {after[g]}")
        dt.check(not [n for n in after[g] if n.endswith(".tmp")], f"a temporary file was left: {after[g]}")
        key_a = pa["key"]

        # the same edits and reads on fork A and on fork B (upgraded in memory by an opted-out daemon)
        funcs = [f for f in s.call("functions", program=key_a, limit=1000)["functions"]
                 if not f.get("external") and not f.get("thunk")]
        subj = funcs[len(funcs) // 2]["address"]
        sample = [f["address"] for f in funcs[:: max(1, len(funcs) // 40)]] + [subj]
        ops = [{"op": "rename", "address": subj, "name": "h2_renamed"},
               {"op": "comment", "address": subj, "text": "h2 fork", "type": "plate"}]
        s.call("edit", program=key_a, ops=ops)
        a_edit = _state(s, key_a, sample)
        sa = s.call("save", program=key_a, comment="h2")
        dt.check(sa["saved"] is True, f"save of the adopted fork: {sa}")
        a_saved = _state(s, key_a, sample)
        s.call("close_project", project=_pid(fa))
    d.stop()

    off = c.daemon("h2-off", keepWarm=0, upgradeCacheDir=str(cache), engine={"forkUpgradeFromCache": False})
    with off.connect("h2-off", "tests") as s:
        o = s.call("open_project", path=str(legacy))
        fb_dir = c.work / "h2-fork-b"
        fb = s.call("fork_project", project=o["id"], path=str(fb_dir), writable=True, timeout=600)
        fb_before = {p: sorted(x.name for x in p.iterdir()) for p in _db_dirs(fb_dir)}
        pb = s.call("open_program", path=prog, project=_pid(fb), writable=True, upgrade=True, wait=1800000)
        dt.check(pb["changed"] is True, f"forkUpgradeFromCache=false did not upgrade in memory: {pb}")
        key_b = pb["key"]
        s.call("edit", program=key_b, ops=ops)
        fb_after = {p: sorted(x.name for x in p.glob("db.*.gbf")) for p in fb_before}
        dt.check(fb_after == {p: [n for n in v if n.startswith("db.") and n.endswith(".gbf")]
                              for p, v in fb_before.items()},
                 f"the opted-out fork's versions changed at open: {fb_before} -> {fb_after}")
        b_edit = _state(s, key_b, sample)
        sb = s.call("save", program=key_b, comment="h2")
        dt.check(sb["saved"] is True, f"save of the in-memory fork: {sb}")
        b_saved = _state(s, key_b, sample)
        s.call("close_project", project=_pid(fb))
    off.stop()
    dt.check(a_edit == b_edit, "adopted and in-memory forks differ after the same edits: "
             f"{[k for k in a_edit[1] if a_edit[1][k] != b_edit[1].get(k)]} names equal: {a_edit[0] == b_edit[0]}")
    dt.check(a_saved == b_saved and a_saved == a_edit, "the forks differ after save")

    # 2. the saved forks, reopened read-only, are the same programs
    d2 = c.daemon("h2-r", keepWarm=0, upgradeCacheDir=str(cache))
    with d2.connect("h2-r", "tests") as s:
        got = []
        for fdir in (fa_dir, fb_dir):
            o = s.call("open_project", path=str(next(fdir.glob("*.gpr"))))
            p = s.call("open_program", path=prog, project=o["id"])
            dt.check(p["changed"] is False and p["cachedUpgrade"] is False,
                     f"a saved fork is not in the current format: {p}")
            got.append(_state(s, p["key"], sample))
            s.call("close_project", project=o["id"])
        dt.check(got[0] == got[1] == a_saved, "the saved forks differ when reopened")
    d2.stop()
    dt.check(dt.tree_state(legacy) == before, "the source project was written")
    notes.append(f"copy ready: fork adopted version {old + 1}; {len(sample)} decompilations and "
                 f"{len(a_edit[0])} functions identical to the in-memory fork (edited, saved, reopened)")
    return "; ".join(notes)


TESTS = {
    "fork_upgrade_from_cache": t_fork_upgrade_from_cache,
}
