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
"""A save against a handle holder on the program's database folder (G-SOAK 9.17 nightly-1, GATE8).

The finding. In soak nightly-1 a 2.5 s handle-holder fault (another process holds the program's
``~00000000.db`` folder with no sharing) made one save fail with ``FileNotFoundException: ...
~00000000.db not found``, and then **every** save of that program failed for 190 s (``File error
during save``, ``File is read-only``), although the agent closed it with ``discard`` and opened it
again after each failure; only a daemon restart cured it.

The mechanism (Windows): a folder held without read sharing cannot be *listed* (``FindFirstFile``:
sharing violation, ``File.list()`` answers null), and without write sharing nothing can be renamed
into it. A default hold (``GENERIC_READ``, share 0) that arrives between the rename of the new version
(``db.N+1.gbf``) and the scan in ``Database.versionCreated`` lets the rename through and fails the
scan: the commit has taken effect on disk, but ``versionCreated`` throws, so (1) the database of the
item keeps version N as current, (2) the program keeps its old buffer file, whose pre-save was used
up by the failed save, and (3) nothing refreshes the item (a successful save does, through
``GhidraFile.fileChanged``). Every later save of the open program has no pre-save (``File is
read-only``); every reopen opens version N again from the stale item and its save renames to the
existing ``db.N+1.gbf`` (``File error during save``); a restart builds a new item, which scans the
folder. The 48 focused trials of gates-3.md grabbed the folder before the rename (the rename then
fails, nothing changes on disk, one close/reopen cures it) and never hit that window.

Deterministic, external injection (D22/D48, no test code in the jar): a hold with
``FILE_ADD_FILE`` access and ``FILE_SHARE_WRITE`` blocks only the listing; renames, creates and
deletes in the folder work (``chaos_lib.HandleHolder``, checked by every test before it relies on
it). Held across a save, it produces exactly the state of the window: the rename succeeds and the
scan fails.

Tests
-----
* ``hh_listing_hold``  the installed build. The save during the listing-only hold must succeed (the
  scan after the commit records the committed version when the folder cannot be listed,
  ``Database.scanAfterCommit``), the save after the hold must succeed without a reopen (the refresh
  of the item after the save, which cannot list the folder either, keeps the item instead of making
  the project drop the file, ``LocalDatabaseItem.refresh``; without it every later save answers
  ``File is read-only``, found by this test), and a fresh daemon must show every acknowledged name.
* ``hh_rename_hold``  the installed build, the default hold (the rename fails, the soak holder before
  the rename): the save fails; after the release the same open program must save again without a
  reopen (a new pre-save is started after a failed commit that left no new version,
  ``LocalManagedBufferFile.saveCompleted``).
* ``hh_reopen_after_failed_commit``  a copy of the install whose ``Database`` has the scan without the
  fallback (``Ghidra/patch``), so the commit still fails after the rename: after the release one
  close (discard) and reopen must give a program that saves, opened from the newest version on disk
  (what a restart shows: ``LocalDatabaseItem.openPrivate`` scans again when a newer version file than
  the recorded one exists).
* ``hh_control_unfixed``  a copy with all four changes stripped (the classes of hydra.4 in effect):
  the listing hold must leave the program stuck (the save fails with ``FileNotFoundException``, then
  every save fails, after close/reopen too), and after the rename hold the retry must fail with
  ``File is read-only``. It proves the tests above can fail; it fails if the defect is not shown.

Every test keeps a second client reading the program (the soak's other lanes), so the owner's close
downgrades the entry and reopens it read-only for that reader, the path of the soak.

Environment: ``HH_HOLD_S`` (hold time, default 2.5, as the soak fault), ``GHIDRA_SESSION_JAVA_HOME`` /
``JAVA_HOME`` (the JDK, for the patched copies).
"""
import os
import pathlib
import subprocess
import time

import chaos_lib as chaos
import daemon_tests as dt
import dt_e8 as e8

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
HOLD_S = float(os.environ.get("HH_HOLD_S", "2.5"))
ATTEMPTS = 3

DB_REL = "Ghidra/Framework/DB/src/main/java/db/Database.java"
LMBF_REL = "Ghidra/Framework/DB/src/main/java/db/buffers/LocalManagedBufferFile.java"
LDI_REL = "Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/local/LocalDatabaseItem.java"

#: the four changes, each as (file, the fixed text, the text that undoes it)
STRIP = {
    "scan": (DB_REL, "scanAfterCommit(version);", "scanFiles(true);"),
    "presave": (LMBF_REL, "if (restartPreSave) {", "if (false) {"),
    "reopen": (LDI_REL, 'if (new File(getDataDir(), "db." + (recorded + 1) + ".gbf").isFile()) {',
               "if (false) {"),
    "refresh": (LDI_REL, "if (!getDataDir().isDirectory() ||", "if (true || !getDataDir().isDirectory() ||"),
}


#: the release the engine sources are compiled at (Ghidra/application.properties): H3's pre-save
#: uses java.lang.foreign.Arena, a preview API under --release 21
JAVA_RELEASE = next((ln.split("=", 1)[1].strip() for ln in (REPO / "Ghidra" / "application.properties")
                     .read_text(encoding="utf-8").splitlines()
                     if ln.startswith("application.java.compiler=")), "21")

def _windows():
    if os.name != "nt":
        raise dt.Skipped("the hold is a Windows sharing-mode handle")


def unfixed_install(c, tag, parts):
    """A hard-link copy of the install whose ``Ghidra/patch`` holds this checkout's classes with the
    named GATE8 changes undone (the technique of ``dt_e8.mutant_install``)."""
    dst = c.work / f"inst-{tag}"
    seeded = c.seed / "install" if getattr(c, "seed", None) else None
    e8.clone_install(seeded if seeded and (seeded / "Ghidra").is_dir() else c.a.ghidra, dst)
    srcdir = c.work / f"src-{tag}"
    files = []
    by_file = {}
    for p in parts:
        rel, fixed, undone = STRIP[p]
        by_file.setdefault(rel, []).append((fixed, undone))
    for rel, subs in by_file.items():
        text = (REPO / rel).read_text(encoding="utf-8")
        for fixed, undone in subs:
            dt.check(text.count(fixed) == 1, f"the GATE8 anchor {fixed!r} is not unique in {rel}")
            text = text.replace(fixed, undone)
        pkg = rel.split("/src/main/java/")[1]
        f = srcdir / pkg
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        files.append(str(f))
    r = subprocess.run([e8.jdk_tool("javac"), "-nowarn", "--release", JAVA_RELEASE, "-encoding", "UTF-8",
                        "-cp", e8.install_jars(dst), "-d", str(dst / "Ghidra" / "patch"), *files],
                       capture_output=True, text=True, timeout=600)
    dt.check(r.returncode == 0, f"javac of the unfixed classes failed: {r.stdout}{r.stderr}")
    return dst


def attempt(fn, *a, **kw):
    """("ok", result) or (error code, message)."""
    try:
        return "ok", fn(*a, **kw)
    except Exception as ex:  # noqa: BLE001
        return getattr(ex, "code", type(ex).__name__), str(ex)[:300]


class Case:
    """The fixture open writable by an owner and read by a second client, on ``install``."""

    def __init__(self, c, install, tag):
        self.c, self.install, self.tag = c, install, tag
        self.gpr = c.copy_fixture("hh" + tag)
        self.dbdir = e8.program_db_dir(self.gpr)
        self.exe = pathlib.Path(c.a.exe).name
        self.d = e8.install_daemon(c, install, "hh" + tag, keepWarm=0)
        self.s = self.d.connect("hh-owner", "hh")
        self.s.call("open_project", path=str(self.gpr), writable=True)
        self.s.call("open_program", path=self.exe, writable=True)
        self.r = self.d.connect("hh-reader", "hh")
        self.r.call("open_project", path=str(self.gpr))
        self.r.call("open_program", path=self.exe)
        self.fns = dt.code_functions(self.s, 4)
        self.acked = {}
        self.events = []
        self.reopens = 0
        self.edit(0, "hh_base")
        dt.check(self.save()[0] == "ok", "the first save (no hold) failed")

    def edit(self, i, name):
        self.s.call("rename", address=self.fns[i], name=name)
        self.pending = (self.fns[i], name)

    def save(self, what="save"):
        out = attempt(self.s.call, "save", wait=120000)
        try:
            newest = e8.newest(self.dbdir)[0]
        except OSError:
            newest = None   # the folder is held: it cannot be listed
        self.events.append({"what": what, "code": out[0],
                            "message": out[1] if out[0] != "ok" else None, "newest": newest})
        if out[0] == "ok":
            self.acked[self.pending[0]] = self.pending[1]
        return out

    def reopen(self):
        """What the soak agent did after a failed save: close with discard, open writable again."""
        self.reopens += 1
        a = attempt(self.s.call, "close_program", discard=True)
        b = attempt(self.s.call, "open_program", path=self.exe, writable=True)
        self.events.append({"what": "reopen", "close": a[0], "open": b[0],
                            "message": None if b[0] == "ok" else b[1]})
        return b[0] == "ok"

    def hold(self, listing_only):
        """Holds the database folder: listing only (the rename passes), or the soak's default hold."""
        h = (chaos.HandleHolder(self.dbdir, share=chaos.HandleHolder.FILE_SHARE_WRITE,
                                access=chaos.HandleHolder.FILE_ADD_FILE)
             if listing_only else chaos.HandleHolder(self.dbdir)).acquire()
        try:
            os.listdir(self.dbdir)
            listed = True
        except PermissionError:
            listed = False
        if listed:
            h.release()
            raise dt.Fail("the hold does not block the listing of the folder here: the test "
                          "cannot reproduce the window")
        return h

    def held_save(self, listing_only, i, name):
        """Edits, saves while the folder is held, keeps the hold HOLD_S seconds, releases."""
        self.edit(i, name)
        t0 = time.perf_counter()
        h = self.hold(listing_only)
        try:
            out = self.save("save during hold")
        finally:
            time.sleep(max(0.0, HOLD_S - (time.perf_counter() - t0)))
            h.release()
        return out

    def saves_after(self, i, reopen):
        """Up to ATTEMPTS edit+save rounds after the release; with ``reopen`` a failure is followed
        by close (discard) and reopen, as the soak agent did. Returns the attempt that succeeded
        (0-based) or None."""
        for k in range(ATTEMPTS):
            self.edit(i, f"hh_after{k}")
            if self.save(f"save after release #{k}")[0] == "ok":
                return k
            if reopen:
                self.reopen()
        return None

    def names(self):
        return dt.names_at(self.s)

    def fresh(self):
        """Stops this daemon; what a fresh daemon sees of the program."""
        for x in (self.r, self.s):
            try:
                x.close()
            except Exception:  # noqa: BLE001
                pass
        if self.d.jvm_alive():
            self.d.stop(force=True)
        return e8.reopen(self.c, self.install, "hh" + self.tag + "f", self.gpr)

    def check_acked(self, seen):
        dt.check(seen.get("ok"), f"a fresh daemon cannot open the program: {seen}")
        lost = {a: n for a, n in self.acked.items() if seen["names"].get(a) != n}
        dt.check(not lost, f"acknowledged names missing after a restart: {lost} "
                           f"(seen {[seen['names'].get(a) for a in lost]}); events {self.events}")
        n, p = e8.newest(self.dbdir)
        dt.check(e8.has_magic(p), f"the newest version db.{n}.gbf has no valid header")


# ---- the tests --------------------------------------------------------------------------------

def t_listing_hold(c):
    """The save during a hold that blocks only the folder listing succeeds; so does the next one,
    without a reopen; nothing acknowledged is lost."""
    _windows()
    k = Case(c, c.a.ghidra, "L")
    held = k.held_save(True, 1, "hh_held")
    dt.check(held[0] == "ok", f"the save during the listing-only hold failed: {held}; "
                              f"events {k.events}")
    ok_at = k.saves_after(2, reopen=False)
    dt.check(ok_at == 0, f"the save after the hold did not succeed at once: events {k.events}")
    dt.check(k.names().get(k.fns[1]) == "hh_held", "the program lost the name saved under the hold")
    vers = sorted(e8.versions(k.dbdir))
    k.check_acked(k.fresh())
    return (f"save under a listing-only hold of {HOLD_S}s: ok; next save ok without reopen; "
            f"versions on disk after it {vers}; a fresh daemon shows all {len(k.acked)} acked names")


def t_rename_hold(c):
    """The default hold (the soak's) makes the rename fail; after the release the same open program
    saves again, without a reopen."""
    _windows()
    k = Case(c, c.a.ghidra, "R")
    held = k.held_save(False, 1, "hh_rheld")
    dt.check(held[0] != "ok", f"the save during the default hold succeeded: the hold did not block "
                              f"the rename, nothing was exercised: {k.events}")
    retry = k.save("retry of the same edit, no reopen")
    dt.check(retry[0] == "ok", f"the retry of the failed save after the release failed: {retry}; "
                               f"events {k.events}")
    ok_at = k.saves_after(2, reopen=False)
    dt.check(ok_at == 0, f"a later save failed: events {k.events}")
    k.check_acked(k.fresh())
    return (f"save under the default hold: {held[0]} ({held[1][:80]}); retry after the release ok "
            f"without reopen; acked names intact after a restart")


def t_reopen_after_failed_commit(c):
    """With the commit failing after the rename (the fallback of the scan undone), one close and
    reopen gives a program that saves, opened from the newest version on disk."""
    _windows()
    inst = unfixed_install(c, "hhC", ["scan"])
    k = Case(c, inst, "C")
    held = k.held_save(True, 1, "hh_committed")
    dt.check(held[0] != "ok" and "FileNotFoundException" in (held[1] or ""),
             f"the commit did not fail after the rename as planned (the premise): {held}")
    n_after, _p = e8.newest(k.dbdir)
    ok_at = k.saves_after(2, reopen=True)
    dt.check(ok_at is not None and k.reopens <= 1,
             f"the program stayed unsaveable after the release ({k.reopens} reopens): "
             f"events {k.events}")
    # the version committed by the failed save is the newest on disk: the reopen opens it, as a
    # restart would (its name is there), and the later save is on top of it
    dt.check(k.names().get(k.fns[1]) == "hh_committed",
             f"the reopen did not open the newest version on disk (db.{n_after}.gbf): "
             f"{k.names().get(k.fns[1])!r}")
    k.acked[k.fns[1]] = "hh_committed"
    k.check_acked(k.fresh())
    return (f"commit failed after the rename ({held[1][:70]}); saveable again after "
            f"{k.reopens} reopen(s), attempt {ok_at}; the reopen opened db.{n_after}.gbf, "
            f"as a restart does")


def t_control_unfixed(c):
    """The classes without the four changes must show the defect: stuck after the listing hold
    (also after close/reopen), and read-only after the rename hold."""
    _windows()
    inst = unfixed_install(c, "hhU", list(STRIP))
    k = Case(c, inst, "U")
    held = k.held_save(True, 1, "hh_held")
    ok_at = k.saves_after(2, reopen=True)
    stuck = (held[0] != "ok" and "FileNotFoundException" in (held[1] or "") and ok_at is None
             and k.reopens == ATTEMPTS)
    codes = [(e["what"], e.get("code") or e.get("open"), (e.get("message") or "")[:60])
             for e in k.events]
    dt.check(stuck, f"control: the listing hold did not leave the program stuck: {codes}")
    k.fresh()
    k2 = Case(c, inst, "U2")
    held2 = k2.held_save(False, 1, "hh_rheld")
    retry = k2.save("retry of the same edit, no reopen")
    dt.check(held2[0] != "ok" and retry[0] != "ok" and "read-only" in (retry[1] or ""),
             f"control: the retry after the rename hold did not fail read-only: {held2} {retry}")
    k2.fresh()
    return (f"unfixed classes: stuck after the listing hold ({ATTEMPTS} reopens, every save failed: "
            f"{[x[2] for x in codes if x[0].startswith('save')][:4]}); after the rename hold the "
            f"retry failed ({retry[1][:60]}); red as it must be")


TESTS = {
    "hh_listing_hold": t_listing_hold,
    "hh_rename_hold": t_rename_hold,
    "hh_reopen_after_failed_commit": t_reopen_after_failed_commit,
    "hh_control_unfixed": t_control_unfixed,
}
