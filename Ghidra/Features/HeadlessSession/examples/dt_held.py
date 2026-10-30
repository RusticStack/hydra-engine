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
"""A file of a project held open by another process is ``busy``, never a client mistake (soak 9.17 pr-vf2 finding C,
GATE10, PROTOCOL-3.md 3.3 and 8.15, amendment A63).

The finding. In soak pr-vf2 the handle-holder fault (another process holds the ``~00000000.db`` folder of an agent's
fork with no sharing) made ``open_program`` answer ``bad_request "/flow_fixture.exe is not a program (Unknown-File)"``
three times in 1.5 s, 0.2 s into the hold: Ghidra could not list the folder, so it read the database item as an
unknown item. A ``fork_project`` whose source is held failed with a bare ``failed`` carrying the localised system
message. Measured on the unfixed build (hydra.4 candidate ``bc4004d366``, ``D:/Projects/Hydra/_logs/gate10/``), with
the program's files held:

========================  =====================================================================================
hold                      unfixed answers
========================  =====================================================================================
``~00000000.db`` folder   ``open_program`` bad_request Unknown-File, **still** after the release (the project kept
                          the unknown item); ``save`` failed "IOException: File error during save"; ``fork_project``
                          failed (localised message)
its ``.prp`` file         ``open_program`` not_found, still after the release (the item was dropped); a save under
                          the hold succeeds and every later save fails "File is read-only" (the refresh after the save
                          dropped the item); ``fork_project`` failed
the ``idata/~index.dat``  ``open_project`` not_found
a version file            ``open_program`` failed (localised message)
========================  =====================================================================================

What must hold now: every one of these answers ``busy`` with ``details.path`` (the held file or folder) and
``suggest:"retry"``; a protocol 3 connection also gets ``details.reason:"file_held"`` and ``error.retryAfterMs``, a
protocol 2 connection gets neither (3.3, C12). After the release the same request succeeds **without** closing or
reopening anything (the project lists the folder again), the source of a refused fork is unchanged and its
destination holds nothing of the fork.

The holds are made by ``chaos_lib.HandleHolder`` from this process (external injection, D22/D48): taken before the
request, released after its answer, so no test waits for a time. Each test checks that its hold does what it claims
(the folder cannot be listed, the file cannot be opened) before it relies on it.

Tests
-----
* ``held_open_program``  (finding C) the database folder held: open_program busy (v3 and v2 shapes), the same
  request on the same open project succeeds after the release, and ``list`` shows a program again.
* ``held_property_file``  the item's ``.prp`` held: open_program busy, not not_found, then ok after the release;
  a save under the hold, and the save after the release, succeed (the item is not dropped).
* ``held_fork_source``  the source's database folder, ``.prp`` and index each held in turn: fork_project busy with the
  structured shape, the source tree unchanged, no fork, staging folder or sidecar at the destination; the retry after
  the release forks and opens.
* ``held_save``  the database folder held across a save: busy (was ``failed`` "File error during save"); after the
  release the same open program saves without a reopen, and a fresh daemon shows the name.
* ``held_open_project``  the project's ``idata/~index.dat`` held: open_project busy (was not_found), then ok.
* ``held_version_file``  the program's newest version file held while it is opened: busy (was a bare failed), then ok.
* ``held_import``  the item folder (``idata/00``) held while an import saves and opens its program: busy with
  ``details.imported`` (was bad_request "is not a program (Unknown-File)"); the program opens after the release.
"""
import os
import pathlib

import chaos_lib as chaos
import daemon_tests as dt
import dt_e8 as e8

HH = chaos.HandleHolder
REASON = "file_held"


def _windows():
    if os.name != "nt":
        raise dt.Skipped("the hold is a Windows sharing-mode handle")


def error_of(s, cmd, **kw):
    """The whole ``error`` object of a failed request (with ``retryAfterMs``), or None if it succeeded."""
    try:
        s.call(cmd, **kw)
        return None
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            raise
        r = s.last_response or {}
        dt.check(not r.get("ok"), f"{cmd}: the error {e} has no failed response behind it")
        return dict(r["error"])


def storage(gpr):
    """The program's database folder, its property file and the project's index file."""
    dbdir = e8.program_db_dir(gpr)
    prp = dbdir.parent / (dbdir.name[1:-3] + ".prp")
    dt.check(prp.is_file(), f"no property file {prp}")
    index = pathlib.Path(gpr).with_suffix(".rep") / "idata" / "~index.dat"
    dt.check(index.is_file(), f"no index file {index}")
    return dbdir, prp, index


def hold(path, listing_only=False):
    """Holds ``path`` (no sharing; or, for a folder, ``listing_only``: only its listing is blocked) and checks the
    premise: a held folder cannot be listed, a held file cannot be opened."""
    h = (HH(path, share=HH.FILE_SHARE_WRITE, access=HH.FILE_ADD_FILE) if listing_only else HH(path)).acquire()
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            open(path, "rb").close()
    except PermissionError:
        return h
    h.release()
    raise dt.Fail(f"the hold of {path} does not block it here: the test cannot exercise the premise")


def check_held(err, what, path, v3=True):
    """``err`` is the busy of a held file at ``path`` (v3 or v2 shape)."""
    dt.check(err is not None, f"{what}: succeeded while {path} was held (the hold did not reach it)")
    d = err.get("details") or {}
    dt.check(err.get("code") == "busy",
             f"{what}: answered {err.get('code')} ({str(err.get('message'))[:200]}) while {path} was held by another "
             f"process; a hold is busy, never a client mistake or a bare failure (3.3, A63)")
    dt.check(d.get("suggest") == "retry", f"{what}: busy without suggest:retry: {d}")
    held = pathlib.Path(d.get("path") or "")
    p = pathlib.Path(path)
    dt.check(held == p or p in held.parents or held in p.parents,
             f"{what}: details.path {held} is not the held {p} (or a folder of it)")
    if v3:
        dt.check(d.get("reason") == REASON, f"{what}: v3 busy without reason {REASON}: {d}")
        ra = err.get("retryAfterMs")
        dt.check(isinstance(ra, int) and 250 <= ra <= 10000, f"{what}: v3 busy without retryAfterMs in 250..10000: {err}")
    else:
        dt.check("reason" not in d and "retryAfterMs" not in err,
                 f"{what}: a protocol 2 busy carries v3 keys: {err}")


def _list_rows(s):
    return s.call("list").get("entries") or []


def program_row(s, exe):
    return next((r for r in _list_rows(s) if r.get("name") == exe), None)


# ---- the tests -------------------------------------------------------------------------------

def t_open_program(c):
    """Finding C: the database folder held while a client opens the program."""
    _windows()
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("held-op")
    dbdir, _prp, _idx = storage(gpr)
    d = c.daemon("held-op", keepWarm=0)
    s3 = c.connect(d, "held-v3", "held", protocol=3)
    s2 = c.connect(d, "held-v2", "held", protocol=2)
    seen = []
    for listing_only in (False, True):
        for s, v3 in ((s3, True), (s2, False)):
            # the soak's order: the hold comes first, then the project is opened and read (0.2 s in pr-vf2)
            h = hold(dbdir, listing_only)
            try:
                opened = error_of(s, "open_project", path=str(gpr))
                err = error_of(s, "open_program", path=exe)
            finally:
                h.release()
            dt.check(opened is None, f"open_project under the hold of the database folder failed: {opened}")
            check_held(err, f"open_program (hold {'listing only' if listing_only else 'default'}, "
                            f"protocol {3 if v3 else 2})", dbdir, v3)
            seen.append(err["code"])
            # the same request, the same open project: the hold is gone, the item is read again
            again = error_of(s, "open_program", path=exe)
            dt.check(again is None, f"open_program after the release failed: {again} (the project kept the item it "
                                    f"read while the folder was held)")
            row = program_row(s, exe)
            dt.check(row and row.get("program") is True, f"list after the release: {row}")
            s.call("close_program")
            s.call("close_project")
    d.stop(force=True)
    return f"open_program under the held database folder: {seen} (v3 and v2, default and listing-only holds); ok " \
           f"after each release without a reopen"


def t_property_file(c):
    """The item's property file held: busy instead of not_found; the item survives a save under the hold."""
    _windows()
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("held-prp")
    _dbdir, prp, _idx = storage(gpr)
    d = c.daemon("held-prp", keepWarm=0)
    s = c.connect(d, "held-prp", "held", protocol=3)
    h = hold(prp)
    try:
        opened = error_of(s, "open_project", path=str(gpr), writable=True)
        err = error_of(s, "open_program", path=exe, writable=True)
    finally:
        h.release()
    dt.check(opened is None, f"open_project under the hold of the .prp failed: {opened}")
    check_held(err, "open_program (.prp held)", prp)
    dt.check(error_of(s, "open_program", path=exe, writable=True) is None,
             "open_program after the release of the .prp failed (the project dropped the item)")
    fns = dt.code_functions(s, 2)
    s.call("rename", address=fns[0], name="held_prp_a")
    h = hold(prp)
    try:
        under = error_of(s, "save")
    finally:
        h.release()
    if under is not None:
        check_held(under, "save (.prp held)", prp)
    s.call("rename", address=fns[1], name="held_prp_b")
    after = error_of(s, "save")
    dt.check(after is None, f"the save after the release of the .prp failed: {after} (the refresh after the save "
                            f"under the hold dropped the item: every later save is read-only)")
    names = dt.names_at(s)
    s.close()
    d.stop(force=True)
    seen = e8.reopen(c, c.a.ghidra, "held-prp-f", gpr)
    dt.check(seen.get("ok"), f"a fresh daemon cannot open the program: {seen}")
    want = {fns[1]: "held_prp_b"} if under is not None else {fns[0]: "held_prp_a", fns[1]: "held_prp_b"}
    lost = {a: n for a, n in want.items() if seen["names"].get(a) != n}
    dt.check(not lost, f"acknowledged names missing after a restart: {lost}")
    dt.check(all(names.get(a) == n for a, n in want.items()), "the open program lost a name")
    return (f"open_program with the .prp held: busy; ok after the release; save under the hold: "
            f"{'ok' if under is None else under['code']}, the next save ok, names intact after a restart")


def t_fork_source(c):
    """The source of a fork held: busy, the source unchanged, nothing at the destination, the retry forks."""
    _windows()
    gpr = c.copy_fixture("held-fk")
    dbdir, prp, idx = storage(gpr)
    d = c.daemon("held-fk", keepWarm=0)
    s = c.connect(d, "held-fk", "held", protocol=3)
    src = pathlib.Path(gpr).with_suffix(".rep")
    out = []
    for i, (what, path) in enumerate((("database folder", dbdir), ("property file", prp), ("index", idx))):
        before = e8.tree_hash(src)
        dest = c.work / f"held-fk-dest{i}"
        h = hold(path)
        try:
            err = error_of(s, "fork_project", project=str(gpr), path=str(dest), open=False)
        finally:
            h.release()
        check_held(err, f"fork_project ({what} of the source held)", path)
        dt.check(e8.tree_hash(src) == before, f"the source changed under a refused fork ({what})")
        left = sorted(os.listdir(dest)) if dest.exists() else []
        dt.check(not left, f"a refused fork left {left} at its destination {dest} ({what})")
        r = s.call("fork_project", project=str(gpr), path=str(dest), open=True)
        dt.check((dest / "Fixture.gpr").is_file() and (dest / "Fixture.rep").is_dir(),
                 f"the retry after the release did not fork ({what}): {r}")
        s.call("close_project")
        out.append(what)
    s.close()
    d.stop(force=True)
    return f"fork_project with the source's {', '.join(out)} held: busy, source unchanged, destination empty; " \
           f"the retry forked each time"


def t_save(c):
    """The database folder held across a save: busy; the same open program saves after the release."""
    _windows()
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("held-sv")
    dbdir, _prp, _idx = storage(gpr)
    d = c.daemon("held-sv", keepWarm=0)
    s = c.connect(d, "held-sv", "held", protocol=3)
    s.call("open_project", path=str(gpr), writable=True)
    s.call("open_program", path=exe, writable=True)
    fn = dt.code_functions(s, 1)[0]
    s.call("rename", address=fn, name="held_save")
    h = hold(dbdir)
    try:
        err = error_of(s, "save")
    finally:
        h.release()
    check_held(err, "save (database folder held)", dbdir)
    again = error_of(s, "save")
    dt.check(again is None, f"the save after the release failed: {again}")
    s.close()
    d.stop(force=True)
    seen = e8.reopen(c, c.a.ghidra, "held-sv-f", gpr)
    dt.check(seen.get("ok") and seen["names"].get(fn) == "held_save",
             f"a fresh daemon does not show the saved name: {seen}")
    return f"save under the held database folder: busy ({err['message'][:80]}...); saved after the release"


def t_open_project(c):
    """The project's index held: open_project busy, not not_found."""
    _windows()
    gpr = c.copy_fixture("held-pj")
    _dbdir, _prp, idx = storage(gpr)
    d = c.daemon("held-pj", keepWarm=0)
    s3 = c.connect(d, "held-pj3", "held", protocol=3)
    s2 = c.connect(d, "held-pj2", "held", protocol=2)
    for s, v3 in ((s3, True), (s2, False)):
        h = hold(idx)
        try:
            err = error_of(s, "open_project", path=str(gpr))
        finally:
            h.release()
        check_held(err, f"open_project (index held, protocol {3 if v3 else 2})", idx, v3)
        dt.check(error_of(s, "open_project", path=str(gpr)) is None, "open_project after the release failed")
        s.call("close_project")
    d.stop(force=True)
    return "open_project with the index held: busy (v3 and v2); ok after the release"


def t_version_file(c):
    """The newest version file of the program held while it is opened: busy, then ok."""
    _windows()
    exe = pathlib.Path(c.a.exe).name
    gpr = c.copy_fixture("held-vf")
    dbdir, _prp, _idx = storage(gpr)
    _n, newest = e8.newest(dbdir)
    d = c.daemon("held-vf", keepWarm=0)
    s = c.connect(d, "held-vf", "held", protocol=3)
    s.call("open_project", path=str(gpr))
    h = hold(newest)
    try:
        err = error_of(s, "open_program", path=exe)
    finally:
        h.release()
    check_held(err, "open_program (version file held)", newest)
    dt.check(error_of(s, "open_program", path=exe) is None, "open_program after the release of the version file failed")
    s.close()
    d.stop(force=True)
    return "open_program with the newest version file held: busy; ok after the release"


def t_import(c):
    """The project's item folder held while an import saves and opens its program: busy with ``imported``, and the
    program opens after the release."""
    _windows()
    gpr = c.copy_fixture("held-im")
    dbdir, _prp, _idx = storage(gpr)
    folder = dbdir.parent
    d = c.daemon("held-im", keepWarm=0)
    s = c.connect(d, "held-im", "held", protocol=3)
    s.call("open_project", path=str(gpr), writable=True)
    h = hold(folder)
    try:
        err = error_of(s, "import", file=c.a.dll, wait=120000)
    finally:
        h.release()
    if err is None:
        # the import's item went to another folder: nothing was held for it
        s.close()
        d.stop(force=True)
        raise dt.Fail(f"the import succeeded while {folder} was held: its item is not in that folder, so the test "
                      f"exercised nothing")
    check_held(err, "import (item folder held)", folder)
    imported = (err.get("details") or {}).get("imported")
    dt.check(imported, f"the busy of an import that saved its program has no details.imported: {err}")
    dt.check(error_of(s, "open_program", path=imported, writable=True) is None,
             f"the imported program {imported} does not open after the release")
    s.close()
    d.stop(force=True)
    return f"import with the item folder held: busy, imported {imported}; it opens after the release"


TESTS = {
    "held_open_program": t_open_program,
    "held_property_file": t_property_file,
    "held_fork_source": t_fork_source,
    "held_save": t_save,
    "held_open_project": t_open_project,
    "held_version_file": t_version_file,
    "held_import": t_import,
}
