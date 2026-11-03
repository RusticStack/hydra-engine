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
"""Reply-parity harness for the Hydra Engine daemon: record a fixed corpus of requests against one
install, keep every reply line (masked), and compare two recordings. Standard library only.

    python reply_parity.py record --ghidra <install dir> --work <empty dir> --out <file.jsonl>
    python reply_parity.py compare <a.jsonl> <b.jsonl>        # exit 0 same, 1 differs, 2 bad input
    python reply_parity.py --selftest                          # the masks and compare, offline
    python reply_parity.py lite --ghidra <install dir> --work <empty dir> --lite <hydra-lite.exe>
                                                               # Java daemon vs hydra-lite (HYDRA-LITE.md)
    python reply_parity.py auto --ghidra <install dir> --work <empty dir> --lite <hydra-lite.exe>
                               [--agent <hydra-agent.exe>]
                                                               # HYDRA_LITE=auto vs off, same final replies

``--ghidra`` is the install root (the directory that holds ``Ghidra/``, for example
``C:\\dev-overflow\\hydra-engines\\final2b\\ghidra_12.3_DEV``). The client is the install's own
``support/ghidra_session.py`` (protocol 3); the protocol-2 section uses the vendored stock 1.0.0
client, as the characterization suite does. ``--work`` must be empty or absent: every run builds
its own fixtures there. ``--kotor <Project.gpr>`` adds the KotOR project (default: the golden 9.1
project ``D:/Projects/Hydra/_golden/kotor-src-copy/kotor.gpr`` when it exists; ``--no-kotor``
leaves it out). A missing KotOR project is recorded as a ``skipped`` line, so two recordings
compare only if they both had it or both lacked it.

The corpus (sections, in the order they run; each request is one record):

* ``session`` (daemon ``v3``): ping, hello, status, health, projects, programs, overlays; the
  ``no_project`` and ``no_program`` errors of every command that needs one; ``bad_request``,
  ``not_found`` and ``unknown_command``; ``ping`` with a bad label; ``cancel`` with a target and
  with ``all``.
* ``read``: open a project read-only, open it again (joins), ``project``/``projects``/``list``
  variants (folder, paging, programsOnly, not_found, bad limit); ``info``, ``programs``, ``status``,
  ``journal``, ``overlays``; ``functions`` (paging, ``contains``, ``regex``, a bad regex); decompile
  fresh and hot (the same request twice), by name, by address, by ``rva:`` and ``va:`` address,
  with ``maxChars``, with ``timeout``, and their errors; the synthetic non-contiguous function
  (``fragments``), a contiguous large one, ``maxResultKb`` 1 (the response cap, truncated and
  partial), the same again after the cap, ``maxResultMb`` out of range; ``switch``.
* ``multi-client``: a second client joins the read-only project, reads it, closes; the first
  client closes it last.
* ``overlay``: overlay programs (open, info, rename, comment, decompile, functions, script-free),
  ``drop_overlay``, ``promote_overlay`` into a fork (the overlay publish path), and its errors.
* ``edit-fork-publish``: a writable project: rename (with ``expect``), comment, ``edit`` batches
  (one applied, one refused with nothing applied), ``journal`` (since, limit, author), ``analyze``
  options error, ``script`` (a write, a read), ``save`` (and "nothing to save"), ``close_program``
  refused with unsaved changes and ``discard``, ``fork_project`` (full, read-only, named ``.gpr``,
  the conflict on an existing fork, bad mode and bad name), refresh, a fork of a fork, and the
  publish of one fork (the ``.gpr``-last fork publish protocol).
* ``trace`` (daemon ``v3``, protocol 3): ``trace_open`` (create, conflict, not_found, bad path),
  ``trace_append`` (30 synthetic TRACE-1 envelopes from ``dt_trace.ev``, rejected kinds, a
  non-list), ``trace_mark``, ``trace_query`` (paging, ``group_by`` kind and an invalid key,
  ``kinds``), ``trace_explain``, ``trace_check`` (cardinality, forbidden, an unknown type),
  ``trace_info``, ``trace_diff`` between two synthetic sessions, ``trace_list``.
* ``kotor`` (daemon ``v3``): the golden 9.1 project, read-only, its first function decompiled
  fresh and hot; or ``skipped``.
* ``trace-busy`` (daemon ``tight``, ``engine.diskReserve`` above the free space): ``trace_open``
  refused with ``busy`` (resource ``disk``), as in ``dt_trace.t_disk_reserve``.
* ``protocol2`` (daemon ``v2``, the vendored stock 1.0.0 client): ping, status, projects, open,
  info, functions, decompile fresh and hot, a decompile by address, ``trace_list`` answered
  ``unknown_command``, close.

Masks (applied to every reply and to every request's fields, in this order; each is a rule of
``characterization_tests.Masker`` unless marked *new*):

1. Top-level ``id`` of a reply -> ``<id>`` (the request counter; *new*, the id is volatile by
   definition).
2. Keys in ``characterization_tests.VOLATILE`` (``ms``, ``pid``, ``startedAt``, ``port``,
   ``token``, ``install``, ``hydraVersion``, ``time``, ``host``, ``method``, ``trace`` ...) and
   keys ending ``Ms``, ``MsAgo``, ``Mb``, ``PerMb``, ``Seconds`` or ``Bytes`` -> ``<masked>``
   (their key and type stay).
3. *new* keys whose scalar value is masked: ``cap`` (a trace lease capability, random per
   session), ``elapsed``, ``ts``, ``cid``, ``t_mono_ns`` (a trace mark's monotonic time), ``have``
   (free disk space in the ``busy`` reason; ``need`` stays), ``cacheBuild`` and ``progress`` (the
   KotOR upgrade-cache build state and its copy progress, which are timing-dependent), and
   ``store_bytes`` (the size of the trace store, which moves by a byte between runs; not yet
   explained, so it is masked and listed as a blind spot). The list key ``pids`` keeps its length and masks each
   item. ``seen`` (GC collections), ``phase`` (cache-build phase) and the whole ``tick`` object
   (the daemon heartbeat) are wall-clock driven and masked too. Under ``scheduler`` the capacity keys ``slots``/``cap``/``perKeyCap`` are masked and
   must stay positive ints (rule 4 below handles them).
3a. *new* text rules: a 16-hex host-derived file ID before a program path (``<fid>:/x.exe``)
   -> ``<fid>:``; ``N MB free`` in a message -> ``<n> MB free``.
4. The copied project's total size (``bytes`` next to ``mode``) -> ``<masked>``; anything but a
   positive int is a harness error, not a mask.
5. Release stamps ``12.3-hydra.6`` and the like inside text -> ``<hydra-version>``.
6. ``N ms`` inside text -> ``<n>ms``; numbers of 10 or more digits inside text -> ``<n>``.
7. ISO timestamps (``2026-11-02T10:00:00Z``) -> ``<time>``.
8. 16-hex-digit revision fingerprints -> ``<revN>``, numbered by first appearance in the run, so
   equal and different revisions stay distinguishable.
9. Paths: the work directory -> ``<WORK>`` and the install -> ``<INSTALL>`` (both slash styles).
   A project path under the work directory is therefore ``<WORK>/...``.

The masked reply is stored in canonical form (``json.dumps`` with no spaces, ASCII escapes, keys
in the order the daemon wrote them). Each record of the JSONL output holds ``n`` (1-based),
``section``, ``daemon``, ``who`` (the client), ``cmd``, ``request`` (the masked fields) and
``reply`` (the masked reply object), or ``skipped`` (a section that did not run), or a
``<no reply: ...>`` string when the daemon sent no answer within the deadline.

Deadlines: every request waits at most ``DEADLINE`` seconds (``SCRIPT_DEADLINE`` for scripts).
The engine-client sessions use the client's own ``deadline`` (which sends ``cancel``); the stock
1.0.0 client has no deadline, so its reads are bounded by a watchdog that shuts the socket.

Not covered (see the report that goes with the lane): timing of replies and progress events (not
replies), the start-up banner, ``shutdown``, the ``busy`` on a project lock (needs a project-exclusive
request of a known duration), file-system dependent forks (``copy-on-write``, ``maxCopyMb``),
``import`` of new programs beyond the fixture, ``sealed``/``seal_project``, the protocol-3
``hello`` capability values (masked by the ``trace`` and ``method`` rules), multi-process
races, and the Hydralysis client. Any byte the masks hide is a blind spot; ``--selftest`` lists them.
"""
import argparse
import contextlib
import difflib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import characterization_tests as ct  # noqa: E402  (Masker, fixture PEs, scripts, client loader)
import cc_issues_eng as ie  # noqa: E402  (the synthetic non-contiguous PE and its script)
import dt_trace as dtt  # noqa: E402  (ev(): the TRACE-1 envelope of the trace tests)

#: Seconds a request may wait for its reply, and for a script (the JVM starts inside it).
DEADLINE = 90.0
SCRIPT_DEADLINE = 180.0
DEFAULT_KOTOR = "D:/Projects/Hydra/_golden/kotor-src-copy/kotor.gpr"
#: Masked on top of ``characterization_tests.VOLATILE`` (scalars only; see the docstring, rule 3).
EXTRA_VOLATILE = {"cap", "elapsed", "ts", "cid",
                  # trace mark time (monotonic clock), free disk space, KotOR cache-build state
                  "t_mono_ns", "have", "cacheBuild", "progress", "store_bytes",
                  # daemon heartbeat, GC collection count, cache-build phase (wall-clock driven)
                  "seen", "phase"}
#: Whole objects masked: the daemon heartbeat (its counters move with wall-clock time).
#: ``cacheBuildInfo``: the KotOR upgrade-cache build in flight when the program opens (a background job
#: whose message and copy progress depend on timing; the build's result is not masked, only its state).
EXTRA_OBJECT = {"tick", "cacheBuildInfo"}
#: Lists masked item by item (their length stays): daemon process ids.
EXTRA_LIST = {"pids"}
#: A 16-hex host-derived file ID before a program path (``<fid>:/swkotor.exe``).
FID = re.compile(r"\b[0-9a-f]{16}:")
FREE = re.compile(r"\d+ MB free")

F1, F2, ENTRY = ct.F1, ct.F2, ct.ENTRY
ENTRY_FRAG, BIG = ie.ENTRY, ie.BIG
NOWHERE = "nowhere/Nothing.gpr"


class Harness(Exception):
    """The corpus cannot be recorded: a step the rest depends on failed, or a fixture did not build."""


class ParityMasker(ct.Masker):
    """The characterization masker, plus the harness keys of rule 3."""

    def value(self, v, key=None):
        if key in EXTRA_LIST and isinstance(v, list):
            return ["<masked>" for _ in v]
        if key in EXTRA_OBJECT and isinstance(v, dict):
            return "<masked>"
        if key in EXTRA_VOLATILE and v is not None and not isinstance(v, (dict, list)):
            return "<masked>"
        out = super().value(v, key)
        if isinstance(out, str):
            out = FREE.sub("<n> MB free", FID.sub("<fid>:", out))
        return out


def canon(masker, line):
    """The masked, canonical form of one raw reply line (rules 1 to 9)."""
    out = masker.value(json.loads(line))
    if isinstance(out, dict) and "id" in out:
        out["id"] = "<id>"
    return out


def stop(d):
    try:
        d.stop(force=True)
    except Exception:  # noqa: BLE001
        with contextlib.suppress(Exception):
            d.kill()


def watchdog(session, seconds):
    """Shuts the socket of a stock-client session after ``seconds``, so its blocking read returns."""
    def fire():
        with contextlib.suppress(Exception):
            session.sock.shutdown(socket.SHUT_RDWR)
    t = threading.Timer(seconds, fire)
    t.daemon = True
    t.start()
    return t


class Recorder:
    def __init__(self, masker, fh, log):
        self.masker = masker
        self.fh = fh
        self.log = log
        self.n = 0
        self.section = ""
        self.daemon = ""
        self.mask_errors = []

    def start(self, section, daemon):
        self.section, self.daemon = section, daemon
        self.log(f"section {section} (daemon {daemon})")

    def skip(self, reason):
        self.n += 1
        self._emit({"n": self.n, "section": self.section, "skipped": reason})
        self.log(f"  skipped: {reason}")

    def _emit(self, rec):
        self.fh.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=True) + "\n")

    def write(self, who, cmd, fields, reply):
        self.n += 1
        try:
            req = self.masker.value(dict(fields))
        except ct.Fail as e:
            self.mask_errors.append(f"request {self.n} {cmd}: {e}")
            req = "<mask error>"
        self._emit({"n": self.n, "section": self.section, "daemon": self.daemon, "who": who,
                    "cmd": cmd, "request": req, "reply": reply})


class Conn:
    """One client session of a run. Every request goes through ``q``, which records it and returns
    the raw (unmasked) reply object, or ``None`` when no reply came."""

    def __init__(self, rec, session, who, exc, stock=False):
        self.rec, self.s, self.who, self.exc, self.stock = rec, session, who, exc, stock
        self.replies = {}
        orig = session._recv

        def tapped(*a, **k):
            line = orig(*a, **k)
            if line:
                try:
                    obj = json.loads(line)
                except ValueError:
                    return line
                if isinstance(obj, dict) and "id" in obj and "ok" in obj:
                    self.replies[obj["id"]] = line.rstrip("\r\n")
            return line
        session._recv = tapped

    def q(self, cmd, deadline=DEADLINE, **f):
        rid = self.s.send(cmd, **f)
        code = None
        dog = watchdog(self.s, deadline) if self.stock else None
        try:
            if self.stock:
                self.s.wait(rid)
            else:
                self.s.wait(rid, deadline)
        except self.exc as e:
            code = getattr(e, "code", None) or "error"
        finally:
            if dog is not None:
                dog.cancel()
        line = self.replies.pop(rid, None)
        if line is not None and getattr(self.rec, "raws", None) is not None:
            self.rec.raws.append((self.who, cmd, line))
        if line is None:
            reply = f"<no reply: {code or 'missing'}>"
            obj = None
        else:
            obj = json.loads(line)
            try:
                reply = canon(self.rec.masker, line)
            except ct.Fail as e:
                self.rec.mask_errors.append(f"{cmd}: {e}")
                reply = "<mask error>"
        self.rec.write(self.who, cmd, f, reply)
        return obj

    def ok(self, cmd, deadline=DEADLINE, **f):
        obj = self.q(cmd, deadline, **f)
        if obj is None or not obj.get("ok"):
            raise Harness(f"{self.who}: {cmd} {f} must succeed here: "
                          f"{(obj or {}).get('error') or 'no reply'}")
        return obj["result"]

    def close(self):
        with contextlib.suppress(Exception):
            self.s.close()


# ---- fixtures ------------------------------------------------------------------------------

def write_inputs(work):
    """The scripts and the synthetic PEs of the run (the same ones the other suites write)."""
    scripts, bins = work / "scripts", work / "bin"
    scripts.mkdir(parents=True, exist_ok=True)
    bins.mkdir(parents=True, exist_ok=True)
    for name, text in ct.SCRIPTS.items():
        (scripts / name).write_text(text)
    (scripts / "FragFixture.java").write_text(ie.FIX_SCRIPT)
    (bins / "alpha.exe").write_bytes(ct.make_pe(7))
    (bins / "beta.exe").write_bytes(ct.make_pe(9))
    (bins / "frag.exe").write_bytes(ie.make_pe())
    state = work / "state"
    state.mkdir(parents=True, exist_ok=True)
    cfg = {"tmpdir": str(work / "tmp"), "scriptPath": [str(scripts)], "keepWarm": 600}
    (work / "tmp").mkdir(parents=True, exist_ok=True)
    (state / "config.json").write_text(json.dumps(cfg))
    return scripts, bins, state


def build_fixture(gs, install, work, state, scripts, bins, log):
    """Alpha, beta and the non-contiguous frag.exe in one project, analysed; frag's function at
    ``ENTRY`` edited by FragFixture.java and saved. Built once per run, outside the recording."""
    base = work / "fixture"
    base.mkdir(parents=True, exist_ok=True)
    gpr = base / "Fixture.gpr"
    d = gs.Daemon(install, str(state), "rp-fix")
    s = d.connect("rp-fixture", "parity")
    t0 = time.monotonic()
    try:
        s.call("script", script=str(scripts / "CharMakeProject.java"), program=None,
               args=[str(base), "Fixture"], timeout=SCRIPT_DEADLINE)
        s.call("open_project", path=str(gpr), writable=True)
        for n in ("alpha.exe", "beta.exe", "frag.exe"):
            s.call("import", file=str(bins / n), analyze=True, timeout=600, wait=300000)
        s.call("open_program", path="/frag.exe", writable=True)
        s.call("script", script=str(scripts / "FragFixture.java"), save=True,
               timeout=SCRIPT_DEADLINE)
        s.call("close_program", discard=True)
        s.call("close_project")
    finally:
        with contextlib.suppress(Exception):
            s.close()
        stop(d)
    log(f"fixture built in {time.monotonic() - t0:.1f} s")
    return base


def copy_project(base, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(base, dst)
    return dst / "Fixture.gpr"


# ---- the corpus ----------------------------------------------------------------------------

def sec_session(a, rec, P, work):
    rec.start("session", "v3")
    a.ok("ping")
    a.ok("hello", client="rp-a", harness="rp-h", clientVersion="1.1.0", protocol=3)
    for cmd in ("status", "health", "projects", "programs", "overlays"):
        a.ok(cmd)
    for cmd, extra in (("list", {}), ("project", {}), ("refresh", {}), ("reopen", {}),
                       ("close_project", {}), ("import", {"file": "x"}),
                       ("open_program", {"path": "/alpha.exe"}), ("switch", {"path": "/alpha.exe"})):
        a.q(cmd, **extra)
    for cmd, extra in (("info", {}), ("save", {}), ("functions", {}),
                       ("decompile", {"name": "x"}), ("rename", {"address": ENTRY, "name": "x"}),
                       ("edit", {"ops": [{"op": "rename", "address": ENTRY, "name": "x"}]}),
                       ("journal", {}), ("discard_edits", {"author": 1}),
                       ("comment", {"address": ENTRY, "text": "x"}), ("analyze", {}),
                       ("close_program", {}), ("promote_overlay", {"overlay": "o"})):
        a.q(cmd, **extra)
    a.q("fork_project", path="x")
    a.q("script")
    a.q("script", script="NoSuchScript.java")
    a.q("apply_overlay")
    a.q("open_project")
    a.q("open_project", path=str(work / NOWHERE))
    a.q("bogus")
    a.q("ping", client=5)
    a.ok("ping", client="labelled", harness="other")
    a.q("cancel")
    a.ok("cancel", target=999)
    a.ok("cancel", all=True)


def sec_read(a, rec, P):
    rec.start("read", "v3")
    a.ok("open_project", path=P)
    a.q("open_project", path=P)  # joins
    a.ok("project")
    a.ok("projects")
    a.ok("list")
    a.ok("list", programsOnly=True, metadata=False)
    a.ok("list", folder="/", recursive=False, offset=0, limit=10)
    a.q("list", folder="/nope")
    a.q("list", limit="many")
    a.ok("open_program", path="/alpha.exe")
    a.ok("info")
    a.ok("info", program="p1:/alpha.exe")
    a.ok("programs")
    a.ok("status")
    a.ok("journal")
    a.ok("functions")
    a.ok("functions", limit=2, offset=1)
    a.ok("functions", contains="FUN")
    a.ok("functions", regex="^entry$")
    a.q("functions", regex="(")
    a.ok("decompile", name="entry")          # fresh
    a.ok("decompile", name="entry")          # hot: the same request again
    a.ok("decompile", address=F2, maxChars=40)
    a.ok("decompile", address="rva:0x1020", timeout=30)
    a.q("decompile", address="va:0x140001040")  # the va: form may be refused: recorded either way
    a.q("decompile", name="nothing_here")
    a.q("decompile", address="0x140001ff0")
    a.q("decompile", address="zz")
    a.q("decompile")
    a.ok("overlays")
    # the synthetic functions of cc_issues_eng: non-contiguous, large, and the response cap
    a.ok("open_program", path="/frag.exe")
    a.ok("info")
    a.ok("decompile", address=ENTRY_FRAG)           # fragments: the data piece is skipped
    a.ok("decompile", address=BIG)                  # contiguous, large
    a.ok("decompile", address=BIG, maxResultKb=1)   # the response cap: truncated, partial
    a.ok("decompile", address=BIG)                  # complete again after the cap
    a.ok("decompile", address=ENTRY_FRAG, maxResultKb=1)
    a.q("decompile", address=BIG, maxResultMb=999)  # out of range
    a.ok("switch", path="p1:/alpha.exe")


def sec_multi(a, b, rec, P):
    rec.start("multi-client", "v3")
    b.ok("projects")
    b.ok("open_project", path=P)
    b.ok("open_program", path="/alpha.exe")
    b.ok("info")
    b.ok("functions", limit=2)
    b.ok("decompile", name="entry")
    a.ok("status")
    b.ok("close_project")
    a.ok("close_project")                      # last user of a read-only view: stays warm


def sec_overlay(a, rec, P):
    rec.start("overlay", "v3")
    a.ok("open_project", path=P)
    a.ok("open_program", path="/alpha.exe")
    a.ok("overlays")
    a.q("open_program", path="/alpha.exe", overlay="bad name!")
    a.ok("open_program", path="/alpha.exe", overlay="rp")
    a.ok("open_program", path="/alpha.exe", overlay="rp")  # joins the same overlay
    a.ok("info", overlay="rp")
    a.ok("rename", overlay="rp", address=F1, name="rp_ov")
    a.ok("comment", overlay="rp", address=F1, text="overlay comment")
    a.ok("decompile", overlay="rp", address=F2, maxChars=80)
    a.ok("functions", overlay="rp", contains="rp_")
    a.ok("functions", contains="rp_")
    a.q("info", overlay="nope")
    a.ok("drop_overlay", overlay="nope")
    a.ok("overlays")
    pr = a.ok("promote_overlay", overlay="rp", fork={"path": str(a.work / "forks" / "ov-fork"),
                                                     "mode": "full"})
    a.ok("info", program=pr["target"])
    a.ok("functions", program=pr["target"], contains="rp_")
    a.ok("drop_overlay", overlay="rp")
    a.ok("close_project")


def sec_edit(a, rec, P):
    rec.start("edit-fork-publish", "v3")
    a.ok("open_project", path=P, writable=True)
    a.ok("open_program", path="/alpha.exe", writable=True)
    a.ok("info")
    a.ok("journal")
    a.ok("rename", address=F1, name="rp_helper")
    a.ok("rename", address=F1, name="rp_helper2", expect="rp_helper")
    a.q("rename", address=F1, name="rp_helper3", expect="not_it")
    a.q("rename", address=F1, name="x", kind="other")
    a.ok("rename", address="0x140001010", name="rp_label", kind="label")
    a.ok("comment", address=F1, text="first")
    a.ok("comment", address=F1, text="plate text", type="plate")
    a.q("comment", address=F1, text="third", expect="first")
    a.q("comment", address=F1, text="x", type="bogus")
    a.ok("edit", ops=[{"op": "rename", "address": F2, "name": "rp_f2"},
                      {"op": "comment", "address": F2, "text": "two", "type": "plate"}])
    a.q("edit", ops=[{"op": "rename", "address": F2, "name": "never"},
                     {"op": "rename", "address": F1, "name": "z", "expect": "wrong"}])
    a.q("edit", ops=[])
    a.q("edit", ops=[{"op": "unknown"}])
    a.ok("journal")
    a.ok("journal", since=3, limit=2)
    a.ok("journal", author=1)
    a.q("analyze", options={"No Such Option": True})
    a.ok("script", script="CharPrint.java", args=["one", "two"])
    a.ok("script", script="CharWrite.java")
    a.ok("save", comment="rp-parity")
    a.ok("save")                               # nothing to save
    a.ok("rename", address=F1, name="rp_after_save")
    a.q("close_program")                       # unsaved changes: refused
    a.ok("save")
    a.ok("close_program")
    a.ok("open_program", path="/alpha.exe", writable=True)
    a.ok("functions")
    # publish: fork_project writes a complete fork (staging, then .gpr last)
    fk = a.ok("fork_project", path=str(a.work / "forks" / "fork1"), mode="full", project="p1")
    a.q("fork_project", path=str(a.work / "forks" / "fork1"), mode="full", project="p1")
    a.q("fork_project", path=str(a.work / "forks" / "f0"), mode="bogus")
    a.q("fork_project", path=str(a.work / "forks" / "f0"), name="bad/name")
    a.ok("fork_project", path=str(a.work / "forks" / "fork2" / "Named.gpr"), mode="full",
         writable=False)
    a.ok("projects")
    fid = fk["project"]
    a.ok("open_program", path=f"{fid}:/alpha.exe", writable=True)
    a.ok("rename", address=F1, name="forked_name")
    a.ok("save")
    a.ok("refresh", project=fid)
    a.ok("fork_project", project=fid, path=str(a.work / "forks" / "fork3"), mode="full")
    a.ok("info", program="p1:/alpha.exe")
    a.ok("close_project", project=fid)
    a.ok("close_project")


def sec_trace(a, rec):
    rec.start("trace", "v3")
    sess, sess2 = "rp-trace-a", "rp-trace-b"
    o = a.ok("trace_open", session=sess, create=True)
    cap = o["lease"]["cap"]
    evs = [dtt.ev(i, "core.resource.open" if i % 2 else "core.resource.read",
                  va=0x401000 + i, module="x.exe") for i in range(30)]
    a.ok("trace_append", session=sess, cap=cap, events=evs)
    a.q("trace_append", session=sess, cap=cap, events=[{"kind": "core.nope"}, dtt.ev(30, "app.fine")])
    a.ok("trace_mark", session=sess, cap=cap, label="phase-1")
    a.q("trace_append", session=sess, cap=cap, events="not-a-list")
    qr = a.ok("trace_query", session=sess, limit=100)
    a.ok("trace_query", session=sess, group_by="kind")
    a.q("trace_query", session=sess, group_by="pid")
    a.ok("trace_query", session=sess, kinds=["core.resource.open"], limit=5)
    a.ok("trace_explain", session=sess, event_id=qr["rows"][0]["event_id"])
    a.q("trace_check", session=sess, cap=cap,
        assertions=[{"type": "cardinality", "kind": "core.resource.open", "min": 15}])
    a.q("trace_check", session=sess, cap=cap,
        assertions=[{"type": "forbidden", "kind": "core.error", "name": "no-errors"}])
    a.q("trace_check", session=sess, assertions=[{"type": "nope"}])
    a.ok("trace_info", session=sess)
    a.q("trace_open", session=sess, create=True)           # conflict
    a.q("trace_open", session="rp-trace-none")              # not_found
    a.q("trace_open", session="../escape", create=True)     # bad_request
    o2 = a.ok("trace_open", session=sess2, create=True)
    a.ok("trace_append", session=sess2, cap=o2["lease"]["cap"],
         events=[dtt.ev(i, "core.marker") for i in range(5)])
    a.ok("trace_diff", a=sess, b=sess2)
    a.ok("trace_list")


def sec_kotor(a, rec, work, kotor):
    rec.start("kotor", "v3")
    if not kotor or not pathlib.Path(kotor).exists():
        rec.skip(f"no KotOR project at {kotor}: the golden 9.1 project is not on this machine")
        return
    src = pathlib.Path(kotor)
    dst = work / "kotor"
    shutil.copytree(src.parent, dst)
    a.ok("open_project", path=str(dst / src.name))
    a.ok("open_program", path="/swkotor.exe")
    a.ok("info")
    fns = a.ok("functions", limit=20)["functions"]
    pick = next((f for f in fns if f["size"] >= 4 and not f["external"] and not f["thunk"]), None)
    if pick is None:
        raise Harness("no decompilable function among the first 20 KotOR functions")
    a.ok("decompile", address=pick["address"])
    a.ok("decompile", address=pick["address"])
    a.ok("close_project")


def sec_busy(gs, install, state, rec, work, log):
    rec.start("trace-busy", "tight")
    d = gs.Daemon(install, str(state), "rp-tight", engine={"diskReserve": "900000000"})
    s = d.connect("rp-t", "trace")
    t = None
    try:
        t = Conn(rec, s, "t", gs.SessionError)
        t.q("trace_open", session="rp-trace-full", create=True)
    finally:
        if t is not None:
            t.close()
        stop(d)


def sec_protocol2(stock, install, state, rec, P2, log):
    rec.start("protocol2", "v2")
    d = stock.Daemon(install, str(state), "rp-v2")
    s = d.connect("rp-a2", "rp-h")
    a = Conn(rec, s, "a2", stock.SessionError, stock=True)
    try:
        a.ok("ping")
        a.ok("status")
        a.ok("projects")
        a.ok("open_project", path=P2)
        a.ok("open_program", path="/alpha.exe")
        a.ok("info")
        a.ok("functions", limit=2)
        a.ok("decompile", name="entry")
        a.ok("decompile", name="entry")
        a.ok("decompile", address=F2, maxChars=40)
        a.q("trace_list")
        a.ok("close_project")
    finally:
        a.close()
        stop(d)


def run_record(a):
    install = str(pathlib.Path(a.ghidra).absolute())
    work = pathlib.Path(a.work).absolute()
    if work.exists() and any(work.iterdir()):
        print(f"error: --work {work} is not empty", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    out = pathlib.Path(a.out).absolute()
    out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()

    def log(msg):
        print(f"[{time.monotonic() - t0:7.1f}s] {msg}", file=sys.stderr, flush=True)

    gs = ct.load_client("install", install)
    stock = ct.load_client("stock", install)
    scripts, bins, state = write_inputs(work)
    masker = ParityMasker([(str(work), "<WORK>"), (install, "<INSTALL>"),
                           (str(work.resolve()), "<WORK>")])
    kotor = None if a.no_kotor else (a.kotor or DEFAULT_KOTOR)
    base = build_fixture(gs, install, work, state, scripts, bins, log)
    try:
        with out.open("w", encoding="utf-8", newline="\n") as fh:
            rec = Recorder(masker, fh, log)
            # daemon v3: session, reads, multi-client, overlays, edits, trace, KotOR
            d = gs.Daemon(install, str(state), "rp-v3")
            a = Conn(rec, d.connect("rp-a", "rp-h"), "a", gs.SessionError)
            a.work = work
            try:
                P = str(copy_project(base, work / "project"))
                sec_session(a, rec, P, work)
                sec_read(a, rec, P)
                b = Conn(rec, d.connect("rp-b", "rp-h"), "b", gs.SessionError)
                try:
                    sec_multi(a, b, rec, P)
                finally:
                    b.close()
                log("sections session, read, multi-client done")
                sec_overlay(a, rec, P)
                sec_edit(a, rec, P)
                sec_trace(a, rec)
                sec_kotor(a, rec, work, kotor)
                log("daemon v3 sections done")
            finally:
                a.close()
                stop(d)
            # daemon tight: busy from the disk reserve
            sec_busy(gs, install, state, rec, work, log)
            log("trace-busy done")
            # protocol 2: the stock 1.0.0 client against its own copy of the project
            P2 = str(copy_project(base, work / "project-v2"))
            sec_protocol2(stock, install, state, rec, P2, log)
            log("protocol2 done")
    except (Harness, ct.Fail) as e:
        print(f"HARNESS ERROR: {e}", file=sys.stderr)
        out.unlink(missing_ok=True)
        return 2
    except Exception as e:  # noqa: BLE001  (a daemon or client failure: never exit 1 here)
        import traceback
        traceback.print_exc()
        print(f"HARNESS ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        out.unlink(missing_ok=True)
        return 2
    if rec.mask_errors:
        for m in rec.mask_errors:
            print(f"MASK ERROR: {m}", file=sys.stderr)
        return 2
    log(f"recorded {rec.n} records to {out} in {time.monotonic() - t0:.1f} s")
    return 0


# ---- compare -------------------------------------------------------------------------------

def load(path):
    recs = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            if line.strip():
                recs.append(json.loads(line))
    return recs


def _block(rec):
    body = {k: rec[k] for k in ("cmd", "request", "reply", "skipped") if k in rec}
    return json.dumps(body, indent=1, ensure_ascii=True).splitlines()


def compare(pa, pb, out=sys.stdout):
    ra, rb = load(pa), load(pb)
    diffs = 0
    for i in range(max(len(ra), len(rb))):
        x = ra[i] if i < len(ra) else None
        y = rb[i] if i < len(rb) else None
        if x is not None and y is not None:
            if {k: v for k, v in x.items() if k != "n"} == {k: v for k, v in y.items() if k != "n"}:
                continue
        diffs += 1
        label = (x or y).get("cmd", "?")
        sect = (x or y).get("section", "?")
        out.write(f"--- request {i + 1}: {label} [{sect}]\n")
        if x is None or y is None:
            out.write(f"    only in {'B' if x is None else 'A'}\n")
            continue
        out.writelines(line + "\n" for line in difflib.unified_diff(
            _block(x), _block(y), fromfile=f"A:{pa}", tofile=f"B:{pb}", lineterm=""))
    same = len(ra) == len(rb) and diffs == 0
    out.write(f"{len(ra)} records in A, {len(rb)} in B; "
              f"{'identical' if same else str(diffs) + ' differ'}\n")
    return 0 if same else 1


# ---- hydra-lite: the same corpus against the Java daemon and the JVM-free one --------------

#: Reasons ``error.details.reason`` may carry in a ``use_full_daemon`` refusal (HYDRA-LITE.md).
LITE_REASONS = {"unsupported_command", "unsupported_request", "unparsable_request", "inexact_value",
                "diverged_connection", "no_identity", "unsupported_project", "unsupported_program",
                "capacity", "unsupported_engine"}


def sec_lite(a, b, rec, P, P2):
    """What hydra-lite answers: every request here must get the Java daemon's bytes."""
    rec.start("lite-session", "v3")
    a.ok("ping")
    a.ok("hello", client="rp-a", harness="rp-h", clientVersion="1.1.0", protocol=3)
    a.ok("projects")
    a.ok("programs")
    for cmd, extra in (("list", {}), ("project", {}), ("close_project", {}),
                       ("open_program", {"path": "/alpha.exe"}), ("switch", {"path": "/alpha.exe"}),
                       ("info", {}), ("functions", {}), ("close_program", {})):
        a.q(cmd, **extra)
    a.q("open_project")
    a.q("open_project", path=str(a.work / NOWHERE))
    a.q("ping", client=5)
    a.ok("ping", client="labelled", harness="other")
    a.q("hello", client=5)
    rec.start("lite-read", "v3")
    a.ok("open_project", path=P)
    a.ok("open_project", path=P)  # joins
    a.ok("project")
    a.ok("projects")
    a.ok("list")
    a.ok("list", programsOnly=True, metadata=False)
    a.ok("list", folder="/", recursive=False, offset=0, limit=10)
    a.ok("list", folder="/", recursive=True, limit=1)
    a.q("list", folder="/nope")
    a.q("list", limit="many")
    a.q("list", offset=-1)
    a.q("info")
    a.q("functions")
    a.ok("programs")
    a.ok("open_program", path="/alpha.exe")
    a.ok("info")
    a.ok("info", program="p1:/alpha.exe")
    a.q("info", program="p1:/nothing.exe")
    a.ok("programs")
    a.ok("functions")
    a.ok("functions", limit=2, offset=1)
    a.ok("functions", contains="FUN")
    a.ok("functions", contains="entry", limit=1)
    a.ok("functions", contains="zzzz")
    a.q("functions", limit=0)
    a.q("functions", limit=10001)
    a.q("functions", offset=-1)
    a.q("functions", limit="x")
    a.ok("open_program", path="/frag.exe")
    a.ok("info")
    a.ok("functions")
    a.ok("switch", path="p1:/alpha.exe")
    a.ok("info")
    a.ok("programs")
    a.q("open_program", path="/nothing.exe")
    a.ok("open_project", path=P2)
    a.ok("projects")
    a.ok("project")
    a.ok("list")
    a.ok("open_program", path="/beta.exe")
    a.ok("info")
    a.ok("functions", limit=3)
    a.ok("programs")
    a.ok("close_program")
    a.ok("programs")
    a.ok("projects")
    rec.start("lite-multi-client", "v3")
    b.ok("projects")
    b.ok("open_project", path=P)
    b.ok("project")
    b.ok("open_program", path="/alpha.exe")
    b.ok("info")
    b.ok("functions", limit=2)
    a.ok("projects")
    a.ok("programs")
    b.ok("close_project")
    a.ok("projects")
    a.ok("close_program")
    a.ok("close_project")
    a.ok("projects")
    a.ok("close_project")
    a.ok("projects")


#: (name, setup, command, fields): each runs on its own connection to hydra-lite and must be
#: refused with ``use_full_daemon``; the Java daemon's answer is recorded alongside for reference.
LITE_REFUSALS = [
    ("unknown command", "none", "bogus", {}),
    ("status", "none", "status", {}),
    ("health", "none", "health", {}),
    ("cancel", "none", "cancel", {"all": True}),
    ("overlays", "none", "overlays", {}),
    ("import", "none", "import", {"file": "x"}),
    ("decompile", "program", "decompile", {"name": "entry"}),
    ("journal", "project", "journal", {}),
    ("script", "none", "script", {"script": "x.java"}),
    ("trace_list", "none", "trace_list", {}),
    ("writable project", "none", "open_project", {"writable": True}),
    ("older program format", "none", "open_project", {}),
    ("regex functions", "program", "functions", {"regex": "^entry$"}),
    ("overlay info", "program", "info", {"overlay": "o"}),
    ("parallel", "none", "projects", {"parallel": True}),
    ("writable program", "project", "open_program", {"path": "/alpha.exe", "writable": True}),
]


def lite_refusals(gs, daemon, rec, P, legacy):
    """Runs LITE_REFUSALS against ``daemon``; returns (name, reason or problem) pairs."""
    seen = []
    for name, setup, cmd, fields in LITE_REFUSALS:
        c = Conn(rec, daemon.connect("rp-r", "rp-h"), "r", gs.SessionError)
        rec.start("lite-refusal " + name, "v3")
        try:
            if setup in ("project", "program"):
                c.ok("open_project", path=P)
            if setup == "program":
                c.ok("open_program", path="/alpha.exe")
            fields = dict(fields)
            if name == "writable project":
                fields["path"] = P
            if name == "older program format":
                fields["path"] = legacy
            obj = c.q(cmd, **fields)
            err = (obj or {}).get("error") or {}
            reason = (err.get("details") or {}).get("reason")
            if err.get("code") != "use_full_daemon" or reason not in LITE_REASONS:
                seen.append((name, f"not refused: {json.dumps(obj)[:200]}"))
                continue
            seen.append((name, reason))
            after = c.q("info")  # a refused connection is diverged: everything but ping is refused
            err = (after or {}).get("error") or {}
            if (err.get("details") or {}).get("reason") != "diverged_connection":
                seen.append((name + " (after)", f"not diverged: {json.dumps(after)[:200]}"))
            pong = c.q("ping")
            if not (pong or {}).get("ok"):
                seen.append((name + " (ping)", f"ping refused: {json.dumps(pong)[:200]}"))
        finally:
            c.close()
    return seen


NARROW = [(re.compile(r'^\{"id":\d+,'), '{"id":0,'),
          (re.compile(r'"(ms|openMs|idleMs|uptimeMs)":\d+'), r'"\1":0')]


def narrow(line, subs):
    """A raw reply line with only the ids, the timings and the work directory replaced."""
    for needle, token in subs:
        for n in {needle, needle.replace("\\", "\\\\"), needle.replace("\\", "/"),
                  needle.replace("/", "\\\\")}:
            line = line.replace(n, token)
    for rx, to in NARROW:
        line = rx.sub(to, line)
    return line


def compare_lite(jrec, lrec, jraw, lraw, jwork, lwork, out=sys.stdout, describes_daemon=()):
    """Java records against lite records of the same corpus: the masked reply with the key order
    kept, and the raw line with only ids, timings and the work directory replaced. Returns the
    number of differences. The replies of the commands in ``describes_daemon`` (``status``: the
    instance name, the other clients, the scheduler counters of one particular daemon) only have
    to agree on ``ok``."""
    diffs = 0
    if len(jrec) != len(lrec) or len(jraw) != len(lraw):
        out.write(f"record counts differ: java {len(jrec)}/{len(jraw)}, "
                  f"lite {len(lrec)}/{len(lraw)}\n")
        return 1
    for i, (x, y) in enumerate(zip(jrec, lrec), 1):
        if x.get("cmd") in describes_daemon and y.get("cmd") == x.get("cmd"):
            if (x.get("reply") or {}).get("ok") != (y.get("reply") or {}).get("ok"):
                diffs += 1
                out.write(f"--- request {i}: {x.get('cmd')} ok differs\n")
            continue
        sx = json.dumps({k: v for k, v in x.items() if k != "n"}, ensure_ascii=True)
        sy = json.dumps({k: v for k, v in y.items() if k != "n"}, ensure_ascii=True)
        if sx != sy:
            diffs += 1
            out.write(f"--- request {i}: {x.get('cmd')} [{x.get('section')}] masked reply differs\n")
            out.writelines(line + "\n" for line in difflib.unified_diff(
                _block(x), _block(y), fromfile="java", tofile="lite", lineterm=""))
    # the raw lines: hello carries per-process figures the mask hides, so it is compared masked only
    for i, ((_w, cj, lj), (_w2, _cl, ll)) in enumerate(zip(jraw, lraw), 1):
        if cj == "hello" or cj in describes_daemon:
            continue
        x = narrow(lj, [(str(jwork), "<WORK>")])
        y = narrow(ll, [(str(lwork), "<WORK>"), (str(jwork), "<WORK>")])
        if x != y:
            diffs += 1
            out.write(f"--- raw line {i}: {cj}\n  java: {x[:600]}\n  lite: {y[:600]}\n")
    return diffs


def process_name(pid):
    """The image name of a process on Windows (None when it cannot be asked)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = wintypes.HANDLE
    h = k32.OpenProcess(0x1000, False, int(pid))
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = wintypes.DWORD(1024)
        k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
        return pathlib.Path(buf.value).name.lower()
    finally:
        k32.CloseHandle(h)


def legacy_copy(work):
    """A copy of the Ghidra 12.1.4 project fixture (program databases of version 32, which Java
    upgrades on open and hydra-lite refuses)."""
    dst = work / "legacy"
    shutil.copytree(HERE / "fixtures" / "legacy-12.1.4", dst)
    return dst / "legacy.gpr"


def load_repo_client():
    """The client of this source tree (``../support/ghidra_session.py``), under its own module
    name. It knows ``GHIDRA_SESSION_FRONT``; an older install's own copy does not, and would start
    the JVM instead of hydra-lite without saying so."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ghidra_session_repo",
                                                  HERE.parent / "support" / "ghidra_session.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    if not hasattr(mod, "front_door_argv"):
        raise Harness("the client of this tree has no GHIDRA_SESSION_FRONT support")
    return mod


def learn_lite(gl, exe, install, state, instance, java_daemon):
    """Teaches hydra-lite who the install is. The launcher starts it once without an identity (it
    refuses to start); the command line it used is what `hydra-lite learn` needs, and a running
    Java daemon of the same install is what it learns from: the deployment recipe of
    HYDRA-LITE.md."""
    argvs = []
    orig_front = gl.front_door_argv

    def spy(argv, info, environ=None):
        argvs.append(list(argv))
        return orig_front(argv, info, environ)

    gl.front_door_argv = spy
    os.environ["GHIDRA_SESSION_FRONT"] = str(exe)
    try:
        gl.Daemon(install, str(state), instance).connect("rp-probe", "rp-h")
        raise Harness("hydra-lite started without a learned identity")
    except gl.LaunchError:
        pass
    finally:
        gl.front_door_argv = orig_front
        os.environ.pop("GHIDRA_SESSION_FRONT", None)
    if not argvs:
        raise Harness("the launcher did not run the front door")
    learn = subprocess.run([str(exe), "learn", "--from", str(java_daemon.endpoint_file), "--",
                            *argvs[0]], capture_output=True, text=True, timeout=60, check=False)
    if learn.returncode != 0:
        raise Harness(f"hydra-lite learn failed: {learn.stderr.strip()}")


def run_lite(a):
    install = str(pathlib.Path(a.ghidra).absolute())
    work = pathlib.Path(a.work).absolute()
    exe = pathlib.Path(a.lite).absolute()
    if work.exists() and any(work.iterdir()):
        print(f"error: --work {work} is not empty", file=sys.stderr)
        return 2
    if not exe.is_file():
        print(f"error: --lite {exe} is not a file", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()

    def log(msg):
        print(f"[{time.monotonic() - t0:7.1f}s] {msg}", file=sys.stderr, flush=True)

    gs = ct.load_client("install", install)
    gl = load_repo_client()
    side = {n: work / n for n in ("java", "lite")}
    for w in side.values():
        w.mkdir()
    scripts, bins, jstate = write_inputs(side["java"])
    _scripts, _bins, lstate = write_inputs(side["lite"])
    base = build_fixture(gs, install, side["java"], jstate, scripts, bins, log)
    outs = {}
    jd = ld = None
    try:
        for n, w in side.items():
            # the fixture was built under the Java side's directory: its programs remember the
            # path they were imported from, for both sides
            masker = ParityMasker([(str(w), "<WORK>"), (install, "<INSTALL>"),
                                   (str(w.resolve()), "<WORK>"), (str(side["java"]), "<WORK>")])
            path = pathlib.Path(a.out_dir or work) / f"lite-{n}.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            outs[n] = (masker, path)
        jd = gs.Daemon(install, str(jstate), "rp-lite")
        jfh = outs["java"][1].open("w", encoding="utf-8", newline="\n")
        jrec = Recorder(outs["java"][0], jfh, log)
        jrec.raws = []
        ja = Conn(jrec, jd.connect("rp-a", "rp-h"), "a", gs.SessionError)
        ja.work = side["java"]
        jb = Conn(jrec, jd.connect("rp-b", "rp-h"), "b", gs.SessionError)
        learn_lite(gl, exe, install, lstate, "rp-lite", jd)
        log("identity learned from the Java daemon")
        jp = copy_project(base, side["java"] / "project")
        jp2 = copy_project(base, side["java"] / "project2")
        sec_lite(ja, jb, jrec, str(jp), str(jp2))
        n_java_flow, flow_java_records = len(jrec.raws), jrec.n
        ja.close()
        jb.close()
        lite_refusals(gs, jd, jrec, str(copy_project(base, side["java"] / "project-r")),
                      str(legacy_copy(side["java"])))
        jfh.close()
        log("java side done")
        stop(jd)
        jd = None
        os.environ["GHIDRA_SESSION_FRONT"] = str(exe)
        # mode "only": a refusal is the answer, the session must not move to the full daemon
        ld = gl.Daemon(install, str(lstate), "rp-lite", lite="only")
        lfh = outs["lite"][1].open("w", encoding="utf-8", newline="\n")
        lrec = Recorder(outs["lite"][0], lfh, log)
        lrec.raws = []
        la = Conn(lrec, ld.connect("rp-a", "rp-h"), "a", gl.SessionError)
        la.work = side["lite"]
        lpid = la.s.hello.get("pid")
        if not lpid or "hydra-lite" not in (process_name(lpid) or ""):
            raise Harness(f"the daemon that answered is not hydra-lite: pid {lpid}, "
                          f"{process_name(lpid)}")
        lb = Conn(lrec, ld.connect("rp-b", "rp-h"), "b", gl.SessionError)
        lp = copy_project(base, side["lite"] / "project")
        lp2 = copy_project(base, side["lite"] / "project2")
        sec_lite(la, lb, lrec, str(lp), str(lp2))
        n_lite_flow, flow_lite_records = len(lrec.raws), lrec.n
        la.close()
        lb.close()
        refusals = lite_refusals(gl, ld, lrec, str(copy_project(base, side["lite"] / "project-r")),
                                 str(legacy_copy(side["lite"])))
        lfh.close()
        log("lite side done")
    except (Harness, ct.Fail) as e:
        print(f"HARNESS ERROR: {e}", file=sys.stderr)
        return 2
    finally:
        os.environ.pop("GHIDRA_SESSION_FRONT", None)
        for d in (jd, ld):
            if d is not None:
                stop(d)
    jr, lr = load(outs["java"][1]), load(outs["lite"][1])
    jflow, lflow = jr[:flow_java_records], lr[:flow_lite_records]
    refused = [r for r in lflow if isinstance(r.get("reply"), dict)
               and (r["reply"].get("error") or {}).get("code") == "use_full_daemon"]
    diffs = compare_lite(jflow, lflow, jrec.raws[:n_java_flow], lrec.raws[:n_lite_flow],
                         side["java"], side["lite"])
    print(f"flow: {len(lflow)} requests, {len(refused)} refused by lite, {diffs} differences")
    for r in refused:
        print(f"  refused where Java answers: {r['cmd']} {r['request']} -> {r['reply']['error']}")
    problems = diffs + len(refused)
    print(f"refusal probes: {len(refusals)} checks")
    for name, what in refusals:
        ok = what in LITE_REASONS or what == "diverged_connection"
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {what}")
        problems += 0 if ok else 1
    log(f"{'PASS' if problems == 0 else 'FAIL'}: {problems} problems; "
        f"records in {outs['java'][1]} and {outs['lite'][1]}")
    return 0 if problems == 0 else 1


# ---- HYDRA_LITE=auto against HYDRA_LITE=off ------------------------------------------------

def sec_auto(a, b, rec, P, P2):
    """The corpus of the auto test: what hydra-lite answers (its sections), then the read corpus
    of this file, whose first ``status`` / ``decompile`` the lite daemon refuses: the sessions move
    to the full daemon there and everything after runs on it."""
    sec_lite(a, b, rec, P, P2)
    rec.lite_records = rec.n
    # Two sessions of one lite daemon that move to the full daemon one after the other would, in
    # between, see the same projects through two different daemons (the `users` lists, `joined`):
    # that split is real and documented (HYDRA-LITE.md), so the corpus moves both here, with a
    # command lite refuses and whose answer does not depend on the daemon.
    a.ok("overlays")
    b.ok("overlays")
    sec_read(a, rec, P)
    sec_multi(a, b, rec, P)


RUST_REQUESTS = [
    ("open_project", {"path": "@PROJECT@"}),
    ("open_program", {"path": "/alpha.exe"}),
    ("functions", {}),
    ("functions", {"limit": 2, "offset": 1}),
    ("info", {}),
    ("decompile", {"name": "entry"}),
    ("decompile", {"name": "nothing_here"}),
    ("functions", {"contains": "FUN"}),
    ("decompile", {"address": "rva:0x1020", "timeout": 30}),
]


def rust_phase(a, mode, state, instance, project, install, log):
    """The requests of RUST_REQUESTS through ``hydra-agent call`` (the Rust client) against the
    daemon of ``instance``; the raw reply lines. With HYDRA_LITE=auto that daemon is hydra-lite, and
    the first ``info`` moves the session to the full daemon."""
    lines = []
    for cmd, f in RUST_REQUESTS:
        f = {k: (project if v == "@PROJECT@" else v) for k, v in f.items()}
        lines.append(json.dumps({"cmd": cmd, **f}))
    env = dict(os.environ)
    env["HYDRA_LITE"] = mode
    env["HYDRA_PYTHON"] = sys.executable
    argv = [str(a.agent), "call", "--endpoint", str(pathlib.Path(state) / f"{instance}.json"),
            "--client", "rp-rust", "--harness", "rp-h", "--keep-raw", "--session-py",
            str(HERE.parent / "support" / "ghidra_session.py"), "--ghidra", install]
    out = subprocess.run(argv, input="\n".join(lines) + "\n", capture_output=True, text=True,
                         env=env, timeout=600, check=False)
    got = [ln for ln in out.stdout.splitlines() if ln.strip()]
    if out.returncode != 0 or len(got) != len(lines):
        raise Harness(f"hydra-agent call ({mode}) exited {out.returncode} with {len(got)} of "
                      f"{len(lines)} answers: {out.stderr.strip()[-600:]}")
    log(f"rust client, HYDRA_LITE={mode}: {len(got)} answers")
    return got


def run_auto(a):
    install = str(pathlib.Path(a.ghidra).absolute())
    work = pathlib.Path(a.work).absolute()
    exe = pathlib.Path(a.lite).absolute()
    if work.exists() and any(work.iterdir()):
        print(f"error: --work {work} is not empty", file=sys.stderr)
        return 2
    if not exe.is_file():
        print(f"error: --lite {exe} is not a file", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()

    def log(msg):
        print(f"[{time.monotonic() - t0:7.1f}s] {msg}", file=sys.stderr, flush=True)

    gs = ct.load_client("install", install)  # builds the fixture, as the other modes do
    gl = load_repo_client()                  # both runs use the client under test
    side = {n: work / n for n in ("off", "auto")}
    for w in side.values():
        w.mkdir()
    scripts, bins, ostate = write_inputs(side["off"])
    _s, _b, astate = write_inputs(side["auto"])
    base = build_fixture(gs, install, side["off"], ostate, scripts, bins, log)
    saved = {k: os.environ.pop(k, None) for k in ("HYDRA_LITE", "HYDRA_LITE_EXE", "HYDRA_LITE_OPTS",
                                                  "GHIDRA_SESSION_FRONT")}
    outs, runs, daemons, rust = {}, {}, [], {}
    try:
        for n, w in side.items():
            masker = ParityMasker([(str(w), "<WORK>"), (install, "<INSTALL>"),
                                   (str(w.resolve()), "<WORK>"), (str(side["off"]), "<WORK>")])
            path = pathlib.Path(a.out_dir or work) / f"auto-{n}.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            outs[n] = (masker, path)
        os.environ["HYDRA_LITE_EXE"] = str(exe)
        for n, state, mode in (("off", ostate, "off"), ("auto", astate, "auto")):
            d = gl.Daemon(install, str(state), "rp-auto", lite=mode)
            daemons.append(d)
            if n == "auto":
                # the first start of an instance is the JVM, and teaches hydra-lite; the second is lite
                s = d.connect("rp-teach", "rp-h")
                if s.endpoint.get("lite"):
                    raise Harness("the first auto start was lite: it had nothing to learn from")
                s.close()
                end = time.monotonic() + 120
                while not gl.lite_has_identity(d._last_argv):
                    if time.monotonic() > end:
                        raise Harness("hydra-lite did not learn the identity within 120 s")
                    time.sleep(0.2)
                log("hydra-lite learned the identity from the JVM daemon the launcher started")
                if not d.stop():
                    raise Harness("the teaching JVM daemon did not stop")
            fh = outs[n][1].open("w", encoding="utf-8", newline="\n")
            rec = Recorder(outs[n][0], fh, log)
            rec.raws = []
            rec.lite_records = 0
            ca = Conn(rec, d.connect("rp-a", "rp-h"), "a", gl.SessionError)
            ca.work = side[n]
            cb = None
            try:
                if n == "auto":
                    pid = ca.s.endpoint.get("pid")
                    if not ca.s.endpoint.get("lite") or "hydra-lite" not in (process_name(pid) or ""):
                        raise Harness(f"the auto daemon is not hydra-lite: pid {pid}")
                cb = Conn(rec, d.connect("rp-b", "rp-h"), "b", gl.SessionError)
                p1 = str(copy_project(base, side[n] / "project"))
                p2 = str(copy_project(base, side[n] / "project2"))
                sec_auto(ca, cb, rec, p1, p2)
                runs[n] = (rec, ca.s.failed_over, cb.s.failed_over)
            finally:
                for cc_ in (ca, cb):
                    if cc_ is not None:
                        cc_.close()
                fh.close()
            log(f"{n} side done: {rec.n} requests")
            if a.agent:
                p3 = str(copy_project(base, side[n] / "project3"))
                rust[n] = rust_phase(a, n, state, "rp-auto", p3, install, log)
        full_ep = pathlib.Path(astate) / f"{gl.full_instance('rp-auto')}.json"
        if not (runs["auto"][1] and runs["auto"][2] and full_ep.is_file()):
            raise Harness(f"the auto sessions did not both move to the full daemon: {runs['auto'][1:]}, "
                          f"{full_ep.is_file()}")
        if runs["off"][1] or runs["off"][2]:
            raise Harness("the off sessions moved")
    except (Harness, ct.Fail) as e:
        print(f"HARNESS ERROR: {e}", file=sys.stderr)
        return 2
    finally:
        os.environ.pop("HYDRA_LITE_EXE", None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        for d in daemons:
            stop(d)
            with contextlib.suppress(Exception):
                stop(d.full())
    off_rec, auto_rec = runs["off"][0], runs["auto"][0]
    diffs = compare_lite(load(outs["off"][1]), load(outs["auto"][1]), off_rec.raws, auto_rec.raws,
                         side["off"], side["auto"], describes_daemon=("status", "health"))
    if a.agent:
        subs = {n: [(str(side[n]), "<WORK>"), (str(side["off"]), "<WORK>")] for n in side}
        for i, (x, y) in enumerate(zip(rust["off"], rust["auto"]), 1):
            nx, ny = narrow(x, subs["off"]), narrow(y, subs["auto"])
            if nx != ny:
                diffs += 1
                print(f"--- rust request {i}: {RUST_REQUESTS[i - 1][0]}\n  off:  {nx[:600]}\n"
                      f"  auto: {ny[:600]}")
        print(f"rust client: {len(rust['auto'])} requests through hydra-agent call, compared with "
              f"HYDRA_LITE=off")
    print(f"auto: {auto_rec.n} requests; the first {auto_rec.lite_records} were lite's, the rest "
          f"the full daemon's after the sessions moved; {diffs} differences from HYDRA_LITE=off")
    log(f"{'PASS' if diffs == 0 else 'FAIL'}: records in {outs['off'][1]} and {outs['auto'][1]}")
    return 0 if diffs == 0 else 1


# ---- selftest ------------------------------------------------------------------------------

def selftest():
    import tempfile
    bad = []

    def check(name, cond):
        if not cond:
            bad.append(name)
    work = pathlib.Path("C:/dev-overflow/h7-parity/selftest-masks")
    m = ParityMasker([(str(work), "<WORK>"), ("C:/inst", "<INSTALL>")])
    raw = ('{"id":7,"ok":true,"result":{"ms":12,"pid":99,"lease":{"cap":"abc123","producerGen":1},'
           '"path":"C:/inst/x","note":"took 12 ms","release":"12.3-hydra.6","rev":"0123456789abcdef",'
           '"when":"2026-11-02T10:00:00Z","scheduler":{"quick":{"slots":4,"inUse":0}}}}')
    got = canon(m, raw)
    check("id masked at top", got["id"] == "<id>")
    check("ms masked", got["result"]["ms"] == "<masked>")
    check("pid masked", got["result"]["pid"] == "<masked>")
    check("cap masked", got["result"]["lease"]["cap"] == "<masked>")
    check("producerGen kept", got["result"]["lease"]["producerGen"] == 1)
    check("install path masked", got["result"]["path"] == "<INSTALL>/x")
    check("text ms masked", "<n>ms" in got["result"]["note"])
    check("release stamp masked", got["result"]["release"] == "<hydra-version>")
    check("rev renumbered", got["result"]["rev"] == "<rev1>")
    check("iso time masked", got["result"]["when"] == "<time>")
    check("scheduler slots masked", got["result"]["scheduler"]["quick"]["slots"] == "<masked>")
    check("scheduler inUse kept", got["result"]["scheduler"]["quick"]["inUse"] == 0)
    raw2 = raw.replace('"abc123"', '"zzz999"').replace('"ms":12', '"ms":40')
    check("two runs mask to the same line",
          json.dumps(canon(m, raw), sort_keys=False) == json.dumps(canon(m, raw2), sort_keys=False))
    bad_total = '{"id":1,"ok":true,"result":{"bytes":0,"mode":"full"}}'
    try:
        canon(m, bad_total)
        check("bytes 0 is a harness error", False)
    except ct.Fail:
        pass
    with tempfile.TemporaryDirectory(prefix="rp-selftest-", dir=None) as td:
        pa, pb = pathlib.Path(td) / "a.jsonl", pathlib.Path(td) / "b.jsonl"
        recs = [{"n": 1, "section": "s", "daemon": "v3", "who": "a", "cmd": "ping",
                 "request": {}, "reply": {"ok": True}}]
        pa.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
        pb.write_text(pa.read_text(encoding="utf-8"), encoding="utf-8")
        import io
        buf = io.StringIO()
        check("identical files compare equal", compare(str(pa), str(pb), buf) == 0)
        recs[0]["reply"] = {"ok": False}
        pb.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
        buf = io.StringIO()
        check("a changed reply compares unequal", compare(str(pa), str(pb), buf) == 1)
        check("the diff names the request", "request 1: ping" in buf.getvalue())
    blind = ["hello capability values under the masked keys trace and method (VOLATILE)",
             "key order and string escapes are canonical, not the daemon's raw bytes",
             "timing, progress events and the start-up banner are not replies"]
    if bad:
        print("selftest FAILED: " + ", ".join(bad))
        return 1
    print("selftest ok")
    print("blind spots (masked or not recorded):")
    for b in blind:
        print("  - " + b)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true", help="check the masks and compare offline")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("record", help="run the corpus against one install")
    r.add_argument("--ghidra", required=True, help="install root (holds Ghidra/)")
    r.add_argument("--work", required=True, help="empty work directory")
    r.add_argument("--out", required=True, help="JSON-lines corpus to write")
    r.add_argument("--kotor", help=f"KotOR project (default {DEFAULT_KOTOR})")
    r.add_argument("--no-kotor", action="store_true", help="leave the KotOR section out")
    lt = sub.add_parser("lite", help="the lite corpus against the Java daemon and hydra-lite")
    lt.add_argument("--ghidra", required=True, help="install root (holds Ghidra/)")
    lt.add_argument("--work", required=True, help="empty work directory")
    lt.add_argument("--lite", required=True, help="the hydra-lite executable")
    lt.add_argument("--out-dir", help="where lite-java.jsonl and lite-lite.jsonl go (default: work)")
    au = sub.add_parser("auto", help="the same corpus with HYDRA_LITE=off and HYDRA_LITE=auto")
    au.add_argument("--ghidra", required=True, help="install root (holds Ghidra/)")
    au.add_argument("--work", required=True, help="empty work directory")
    au.add_argument("--lite", required=True, help="the hydra-lite executable")
    au.add_argument("--agent", help="hydra-agent executable: also run requests through the Rust client")
    au.add_argument("--out-dir", help="where auto-off.jsonl and auto-auto.jsonl go (default: work)")
    c = sub.add_parser("compare", help="diff two corpora; exit 1 on any difference")
    c.add_argument("a")
    c.add_argument("b")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if a.cmd == "record":
        return run_record(a)
    if a.cmd == "lite":
        return run_lite(a)
    if a.cmd == "auto":
        return run_auto(a)
    if a.cmd == "compare":
        try:
            return compare(a.a, a.b)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
