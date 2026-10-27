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
"""Characterization of the session protocol: the exact JSON replies of every command, recorded
once as golden files and compared byte for byte afterwards. Standard library only; any OS.

    python characterization_tests.py --ghidra <install> --work <empty dir>          # verify
    python characterization_tests.py --ghidra <install> --work <empty dir> --record # (re)record

It is the safety net for refactoring ``Session.java``: a change that must not alter behaviour or
the wire format must leave every golden file identical. Each scenario starts its own daemon
instance (so client ids and project ids start at 1 and are the same on every run), plays a fixed
script of requests, and stores request and whole response (``ok``, ``result`` or ``error`` with
``code``, ``message`` and ``details``, and the ``stale``/``refreshed`` markers), in the order
the daemon wrote the keys. Only what differs between two runs of the same build is masked:
timings, pids, ports, paths (as ``<WORK>``, ``<INSTALL>``), file-system dependent copy figures,
and revision fingerprints (renumbered by first appearance, so equal and different revisions stay
visible as such). The fixture is two tiny x64 PE files this script writes itself, so the golden
files carry nothing derived from any real program and do not depend on the Windows version.

Golden files: ``examples/characterization/<scenario>.json`` (``--golden`` to use another
directory). Scenarios: see ``SCENARIOS``; run some with ``--only session,edits``. With ``--out
<dir>`` the masked replies of this run are also written there, whatever the mode.

Not characterized (see ``docs/architecture.md``): requests that depend on the file system
(``fork_project`` ``mode`` ``copy-on-write`` and ``maxCopyMb``, whose answer differs between
ReFS and NTFS), on other processes (the project lock's holder details beyond their keys), on
an older-format project (``legacy_overlay`` and ``upgrade_cache`` in ``daemon_tests.py``), the
timing of the upgrade cache build, ``busy`` on a project lock (needs a project-exclusive request
of a known duration), and the progress events and the start-up banner (not replies).
"""
import argparse
import difflib
import json
import pathlib
import re
import shutil
import struct
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent

# ---- the fixture: two tiny x64 PE files ----------------------------------------------------

IMAGE_BASE = 0x140000000


def make_pe(k: int) -> bytes:
    """A console x64 PE with three functions: ``entry`` calls ``f1`` and ``f2``, ``f2`` calls
    ``f1``. ``k`` is a constant in ``f1``, so two files differ (SHA-256) and nothing else."""
    code = bytearray()
    code += bytes([0x48, 0x83, 0xEC, 0x28])                       # 1000 sub rsp,28h
    code += b"\xE8" + struct.pack("<i", 0x20 - (len(code) + 5))    # call f1 (1020)
    code += b"\xE8" + struct.pack("<i", 0x40 - (len(code) + 5))    # call f2 (1040)
    code += bytes([0x48, 0x83, 0xC4, 0x28, 0xC3])                  # add rsp,28h ; ret
    code += b"\xCC" * (0x20 - len(code))
    code += bytes([0x89, 0xC8, 0x83, 0xC0, k, 0xC3])               # 1020 f1: mov eax,ecx ; add eax,k
    code += b"\xCC" * (0x40 - len(code))
    code += bytes([0x48, 0x83, 0xEC, 0x28])                        # 1040 f2: sub rsp,28h
    code += b"\xE8" + struct.pack("<i", 0x20 - (len(code) + 5))    # call f1
    code += bytes([0x83, 0xC0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3])  # add eax,1 ; add rsp,28h ; ret
    code += b"\xCC" * (0x200 - len(code))
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x5F000000, 0, 0, 0xF0, 0x0022)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 2, 0, 0x200, 0, 0, 0x1000, 0x1000,
                      IMAGE_BASE, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x0100,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0,
                       0x60000020)
    hdr = bytes(dos) + b"PE\0\0" + coff + opt + sect
    assert len(opt) == 0xF0, len(opt)
    return hdr + b"\x00" * (0x200 - len(hdr)) + bytes(code)


SCRIPTS = {
    "CharMakeProject.java": """// @category HeadlessSession.Characterization
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class CharMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
""",
    "CharPrint.java": """// @category HeadlessSession.Characterization
import ghidra.app.script.GhidraScript;
public class CharPrint extends GhidraScript {
    @Override protected void run() throws Exception {
        println("program " + (currentProgram == null ? "none" : currentProgram.getName()));
        if (currentProgram != null) {
            println("functions " + currentProgram.getFunctionManager().getFunctionCount());
            println("entry " + getFunctionContaining(currentAddress == null ?
                currentProgram.getImageBase().add(0x1000) : currentAddress));
        }
        println("args " + String.join(",", getScriptArgs()));
    }
}
""",
    "CharWrite.java": """// @category HeadlessSession.Characterization
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CharWrite extends GhidraScript {
    @Override protected void run() throws Exception {
        currentProgram.getSymbolTable().createLabel(
            currentProgram.getImageBase().add(0x1050), "char_script_label", SourceType.USER_DEFINED);
        println("labelled");
    }
}
""",
    "CharFail.java": """// @category HeadlessSession.Characterization
import ghidra.app.script.GhidraScript;
public class CharFail extends GhidraScript {
    @Override protected void run() throws Exception {
        println("before failure");
        throw new IllegalStateException("characterization failure");
    }
}
""",
    "CharSleep.java": """// @category HeadlessSession.Characterization
import ghidra.app.script.GhidraScript;
public class CharSleep extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            monitor.checkCancelled();
            Thread.sleep(20);
        }
        println("slept");
    }
}
""",
}

# ---- masking -------------------------------------------------------------------------------

# Values that differ from run to run (time, process, machine). Their key stays; a null stays null.
VOLATILE = {
    "ms", "pid", "uptimeMs", "startedAt", "heldMs", "waitedMs", "openMs", "seconds",
    "importSeconds", "copyMs", "deferredInitMs", "createdAt", "connectedMs",
    "idleMs", "sinceMs", "since", "ageMs", "lastUsed", "joinedAt", "openedAt", "ownedSince",
    "elapsedMs", "port", "token", "listen", "launch", "memory", "install", "installId", "java",
    "ghidra", "ghidraVersion", "hydraVersion", "minClient", "refreshedAt", "tookMs",
    "lockedMs", "freeSpaceUsedBytes", "clonedBy", "cloned", "method", "trace",
    "startedMs", "runningMs", "queuedMs", "waitMs", "durationMs", "limitBytes",
    "freeBytes", "destFreeBytes", "lockFile", "user", "host", "machine", "time", "timestamp",
}
VOLATILE.add("at")
VOLATILE_SUFFIX = re.compile(r"(Ms|MsAgo|Mb|PerMb|Seconds|Bytes)$")
REV = re.compile(r"^[0-9a-f]{16}$")
ISO_TIME = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z$")


class Masker:
    def __init__(self, subs):
        self.subs = sorted(subs, key=lambda s: -len(s[0]))
        self.revs = {}

    def text(self, s):
        for needle, token in self.subs:
            for n in {needle, needle.replace("\\", "/"), needle.replace("/", "\\")}:
                if n and n in s:
                    s = s.replace(n, token)
                    if "\\" in s:
                        s = re.sub(re.escape(token) + r"[^\s'\",)]*",
                                   lambda m: m.group(0).replace("\\", "/"), s)
        s = re.sub(r"(\d+(?:\.\d+)?) ?ms\b", "<n>ms", s)
        s = re.sub(r"\b\d{10,}\b", "<n>", s)
        return s

    def value(self, v, key=None):
        if isinstance(v, dict):
            return {k: self.value(x, k) for k, x in v.items()}
        if isinstance(v, list):
            return [self.value(x, key) for x in v]
        if v is not None and key is not None and (key in VOLATILE or VOLATILE_SUFFIX.search(key)):
            return "<masked>"
        if isinstance(v, str):
            if ISO_TIME.match(v):
                return "<time>"
            if REV.match(v):
                return "<rev%d>" % self.revs.setdefault(v, len(self.revs) + 1)
            return self.text(v)
        return v


# ---- recording -----------------------------------------------------------------------------

class Fail(Exception):
    pass


class Rec:
    """One scenario's record: every request with its masked response, in order."""

    def __init__(self, name, gs, masker):
        self.name = name
        self.gs = gs
        self.m = masker
        self.steps = []

    def _record(self, who, s, cmd, fields, note=None):
        resp = s.last_response
        step = {"step": len(self.steps) + 1, "who": who, "cmd": cmd,
                "request": self.m.value(fields), "response": self.m.value(resp)}
        if note:
            step["note"] = note
        self.steps.append(step)
        return resp

    def any(self, who, s, cmd, note=None, **f):
        """Sends a request, records it whatever the answer; returns the whole response."""
        try:
            s.call(cmd, **f)
        except self.gs.SessionError:
            pass
        return self._record(who, s, cmd, f, note)

    def ok(self, who, s, cmd, note=None, **f):
        resp = self.any(who, s, cmd, note, **f)
        if not resp.get("ok"):
            raise Fail(f"{self.name}: {who} {cmd} {f} failed: {resp.get('error')}")
        return resp["result"]

    def err(self, who, s, cmd, code, note=None, **f):
        resp = self.any(who, s, cmd, note, **f)
        if resp.get("ok") or resp["error"].get("code") != code:
            raise Fail(f"{self.name}: {who} {cmd} {f}: expected {code}, got "
                       f"{resp.get('error') or 'ok'}")
        return resp["error"]

    def later(self, who, s, cmd, rid, note=None, **f):
        """Waits for a request sent earlier with ``s.send`` and records its answer."""
        try:
            s.wait(rid)
        except self.gs.SessionError:
            pass
        return self._record(who, s, cmd, f, note)


class Ctx:
    def __init__(self, a, gs):
        self.a = a
        self.gs = gs
        self.work = pathlib.Path(a.work).absolute()
        self.state = self.work / "state"
        self.scripts = self.work / "scripts"
        self.bin = self.work / "bin"
        for d in (self.state, self.scripts, self.bin):
            d.mkdir(parents=True, exist_ok=True)
        for n, text in SCRIPTS.items():
            (self.scripts / n).write_text(text)
        for n, k in (("alpha.exe", 7), ("beta.exe", 9)):
            (self.bin / n).write_bytes(make_pe(k))
        cfg = {"tmpdir": a.tmpdir or str(self.work / "tmp"), "scriptPath": [str(self.scripts)],
               "keepWarm": 600}
        if a.tmpdir == "default":
            del cfg["tmpdir"]
        (self.state / "config.json").write_text(json.dumps(cfg))
        self.daemons = []
        self.sessions = []
        self.golden = pathlib.Path(a.golden)
        self.install = str(pathlib.Path(a.ghidra).absolute())

    def masker(self):
        return Masker([(str(self.work), "<WORK>"), (self.install, "<INSTALL>"),
                       (str(pathlib.Path(self.work).resolve()), "<WORK>")])

    def daemon(self, instance, **cfg):
        d = self.gs.Daemon(self.a.ghidra, str(self.state), instance, **cfg)
        self.daemons.append(d)
        return d

    def connect(self, d, client, harness):
        s = d.connect(client, harness)
        self.sessions.append((d, s))
        return s

    def stop(self, d):
        """Disconnects every client of this run, then stops the daemon."""
        for owner, s in [x for x in self.sessions if x[0] is d]:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        self.sessions = [x for x in self.sessions if x[0] is not d]
        time.sleep(0.3)
        d.stop(force=True)

    def script(self, name):
        return str(self.scripts / name)

    def make_project(self, s, folder, name):
        folder.mkdir(parents=True, exist_ok=True)
        s.call("script", script=self.script("CharMakeProject.java"), program=None,
               args=[str(folder), name])
        return folder / f"{name}.gpr"

    def fixture(self):
        """A project with both programs imported and analysed, made once, copied per scenario."""
        base = self.work / "fixture"
        gpr = base / "Fixture.gpr"
        if not gpr.exists():
            d = self.daemon("c-fixture")
            with d.connect("fixture", "characterization") as s:
                self.make_project(s, base, "Fixture")
                s.call("open_project", path=str(gpr), writable=True)
                for n in ("alpha.exe", "beta.exe"):
                    s.call("import", file=str(self.bin / n), analyze=True, timeout=600,
                           wait=300000)
                s.call("close_project")
            d.stop()
        return base

    def copy_fixture(self, name):
        dst = self.work / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.fixture(), dst)
        return dst / "Fixture.gpr"

    def clean(self):
        """Removes what an earlier scenario (or run) left in the work directory."""
        keep = {"state", "scripts", "bin", "tmp", "fixture", "actual"}
        for p in self.work.iterdir():
            if p.name not in keep:
                shutil.rmtree(p, ignore_errors=True)

    def cleanup(self):
        for d in self.daemons:
            try:
                if d.jvm_alive():
                    d.kill()
            except Exception:  # noqa: BLE001
                pass


ENTRY = "0x140001000"
F1 = "0x140001020"
F2 = "0x140001040"


# ---- scenarios -----------------------------------------------------------------------------

def sc_session(c, R):
    """Session commands with nothing open: ping, hello, status, projects, programs, cancel,
    shutdown, and the errors of every command that needs a project or a program."""
    d = c.daemon("c-session")
    a = c.connect(d, "char-a", "char-h")
    b = c.connect(d, "char-b", "char-h")
    R.ok("a", a, "ping")
    R.ok("a", a, "hello", client="char-a", harness="char-h", clientVersion="9.9.9")
    R.ok("a", a, "status")
    R.ok("b", b, "status")
    R.ok("a", a, "projects")
    R.ok("a", a, "programs")
    R.ok("a", a, "overlays")
    # nothing open
    for cmd, extra in (("list", {}), ("project", {}), ("refresh", {}), ("reopen", {}),
                       ("close_project", {}),
                       ("import", {"file": "x"}), ("open_program", {"path": "/alpha.exe"}),
                       ("switch", {"path": "/alpha.exe"})):
        R.err("a", a, cmd, "no_project", **extra)
    for cmd, extra in (("info", {}), ("save", {}), ("functions", {}), ("decompile", {"name": "x"}),
                       ("rename", {"address": ENTRY, "name": "x"}),
                       ("edit", {"ops": [{"op": "rename", "address": ENTRY, "name": "x"}]}),
                       ("journal", {}), ("discard_edits", {"author": 1}),
                       ("comment", {"address": ENTRY, "text": "x"}), ("analyze", {}),
                       ("close_program", {}), ("promote_overlay", {"overlay": "o"})):
        R.err("a", a, cmd, "no_program", **extra)
    R.err("a", a, "fork_project", "bad_request", path="x")
    R.err("a", a, "script", "bad_request")
    R.err("a", a, "script", "not_found", script="NoSuchScript.java")
    R.err("a", a, "apply_overlay", "bad_request")
    R.err("a", a, "drop_overlay", "bad_request")
    R.err("a", a, "bogus", "unknown_command")
    R.err("a", a, "open_project", "bad_request")
    R.err("a", a, "open_project", "not_found", path=str(c.work / "nowhere" / "Nothing.gpr"))
    R.err("a", a, "ping", "bad_request", client=5, note="a label is a string")
    R.ok("a", a, "ping", client="labelled", harness="other")
    # cancel
    R.err("a", a, "cancel", "bad_request")
    R.ok("a", a, "cancel", target=999)
    R.ok("a", a, "cancel", all=True)
    R.ok("a", a, "cancel", cacheBuild="all")
    R.ok("a", a, "cancel", all=True, client="lab", harness="lab-h")
    # shutdown: refused while another client is connected, then forced
    R.err("a", a, "shutdown", "conflict")
    R.ok("b", b, "status")
    b.close()
    a2 = c.connect(d, "char-a2", "char-h")
    R.err("a", a, "shutdown", "conflict")
    a2.close()
    time.sleep(0.5)  # the session notices the disconnect
    R.ok("a", a, "shutdown")
    c.stop(d)


def sc_readonly(c, R):
    """Read-only use of a project: open, list, open and switch programs, queries, refresh,
    and everything a read-only program refuses."""
    gpr = c.copy_fixture("ro")
    d = c.daemon("c-readonly")
    a = c.connect(d, "char-a", "char-h")
    b = c.connect(d, "char-b", "char-h")
    R.ok("a", a, "open_project", path=str(gpr))
    R.ok("a", a, "open_project", path=str(gpr), note="again: joins, opened false")
    R.ok("b", b, "open_project", path=str(gpr))
    R.ok("a", a, "project")
    R.ok("a", a, "projects")
    R.ok("b", b, "projects")
    R.ok("a", a, "list")
    R.ok("a", a, "list", programsOnly=True, metadata=False)
    R.ok("a", a, "list", folder="/", recursive=False, offset=1, limit=1)
    R.ok("a", a, "list", sha256=hashlib_sha(c.bin / "beta.exe"))
    R.err("a", a, "list", "not_found", folder="/nope")
    R.err("a", a, "list", "bad_request", limit="many")
    R.ok("a", a, "project", project="p1")
    R.err("a", a, "project", "no_project", project="p9")
    R.ok("a", a, "open_program", path="alpha.exe")
    R.ok("a", a, "programs")
    R.ok("a", a, "info")
    R.ok("a", a, "info", program="p1:/alpha.exe")
    R.ok("a", a, "functions")
    R.ok("a", a, "functions", limit=2, offset=1)
    R.ok("a", a, "functions", contains="FUN")
    R.ok("a", a, "functions", regex="^entry$")
    R.err("a", a, "functions", "bad_request", regex="(")
    R.ok("a", a, "decompile", name="entry")
    R.ok("a", a, "decompile", address=F2, maxChars=40)
    R.ok("a", a, "decompile", address="rva:0x1020", timeout=30)
    R.err("a", a, "decompile", "not_found", name="nothing_here")
    R.err("a", a, "decompile", "not_found", address="0x140001ff0")
    R.err("a", a, "decompile", "bad_request", address="zz")
    R.err("a", a, "decompile", "bad_request")
    R.ok("a", a, "open_program", path="/beta.exe", note="second program, becomes active")
    R.ok("a", a, "switch", path="p1:/alpha.exe")
    R.ok("b", b, "open_program", path="/alpha.exe", note="second user of a read-only program")
    R.ok("a", a, "programs")
    R.ok("a", a, "status")
    R.ok("a", a, "journal")
    R.err("a", a, "open_program", "not_found", path="/missing.exe")
    R.err("a", a, "open_program", "not_found", path="missing.exe")
    R.err("a", a, "open_program", "bad_request", path="/alpha.exe", share=True)
    R.err("a", a, "open_program", "bad_request")
    R.err("a", a, "open_program", "read_only", path="/alpha.exe", writable=True)
    R.err("a", a, "info", "no_program", program="p1:/beta2.exe")
    # everything that writes is refused on a read-only program
    for cmd, extra in (("save", {}), ("rename", {"address": F1, "name": "x"}),
                       ("comment", {"address": F1, "text": "x"}),
                       ("edit", {"ops": [{"op": "comment", "address": F1, "text": "x"}]}),
                       ("discard_edits", {"author": 1}), ("analyze", {})):
        R.err("a", a, cmd, "read_only", **extra)
    R.err("a", a, "import", "read_only", file=str(c.bin / "alpha.exe"))
    R.ok("a", a, "refresh", note="unchanged")
    R.ok("a", a, "refresh", force=True)
    R.ok("a", a, "reopen")
    R.ok("b", b, "info")
    R.ok("a", a, "close_program", program="p1:/beta.exe")
    R.ok("a", a, "close_program")
    R.err("a", a, "close_program", "no_program")
    R.ok("a", a, "open_program", path="/alpha.exe")
    R.ok("b", b, "close_project")
    R.ok("a", a, "status")
    R.ok("a", a, "close_project", note="last user of a read-only view: stays warm")
    R.ok("a", a, "projects")
    R.err("a", a, "list", "no_project")
    R.ok("a", a, "open_project", path=str(gpr), note="the warm view is reused")
    c.stop(d)


def sc_edits(c, R):
    """Writing: rename, comment, edit (all or none), journal, discard_edits, save, close with
    unsaved changes, analyze, and a script that changes the program."""
    gpr = c.copy_fixture("edits")
    d = c.daemon("c-edits")
    a = c.connect(d, "char-a", "char-h")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    R.ok("a", a, "info")
    R.ok("a", a, "journal")
    R.ok("a", a, "rename", address=F1, name="char_helper")
    R.ok("a", a, "rename", address=F1, name="char_helper2", expect="char_helper")
    R.err("a", a, "rename", "conflict", address=F1, name="char_helper3", expect="not_it")
    R.ok("a", a, "rename", address="0x140001010", name="char_label", kind="label")
    R.err("a", a, "rename", "not_found", address="0x140001011", name="x", kind="function")
    R.err("a", a, "rename", "bad_request", address=F1, name="x", kind="other")
    R.err("a", a, "rename", "bad_request", address="nonsense", name="x")
    R.err("a", a, "rename", "bad_request", address=F1)
    R.ok("a", a, "comment", address=F1, text="first")
    R.ok("a", a, "comment", address=F1, text="plate text", type="plate")
    R.ok("a", a, "comment", address=F1, text="second", expect="first")
    R.err("a", a, "comment", "conflict", address=F1, text="third", expect="first")
    R.err("a", a, "comment", "bad_request", address=F1, text="x", type="bogus")
    R.ok("a", a, "comment", address=F2, text=None, note="no comment there: still an edit")
    R.ok("a", a, "edit", ops=[
        {"op": "rename", "address": F2, "name": "char_two"},
        {"op": "label", "address": "0x140001018", "name": "char_pad"},
        {"op": "comment", "address": F2, "text": "edit comment", "type": "pre"},
        {"op": "signature", "address": F1, "signature": "int char_helper2(int a)"},
        {"op": "data_type", "address": "0x140001060", "type": "int"}])
    R.err("a", a, "edit", "conflict", note="the second operation fails: nothing is applied", ops=[
        {"op": "rename", "address": F2, "name": "must_not_stick"},
        {"op": "rename", "address": F1, "name": "x", "expect": "wrong"}])
    R.err("a", a, "edit", "bad_request", ops=[{"op": "unknown"}])
    R.err("a", a, "edit", "bad_request", ops=[])
    R.err("a", a, "edit", "bad_request", ops=["not an object"])
    R.err("a", a, "edit", "bad_request", ops=[{"op": "data_type", "address": F1, "type": "no_type"}])
    R.err("a", a, "edit", "bad_request", ops=[{"op": "signature", "address": F1, "signature": "((("}])
    R.err("a", a, "edit", "not_found", ops=[{"op": "signature", "address": "0x140001018",
                                             "signature": "int f(int a)"}])
    R.ok("a", a, "functions")
    R.ok("a", a, "decompile", address=F2)
    R.ok("a", a, "journal")
    R.ok("a", a, "journal", since=3, limit=2)
    R.ok("a", a, "journal", author=1)
    R.ok("a", a, "journal", author=2)
    R.ok("a", a, "info")
    R.err("a", a, "discard_edits", "bad_request")
    R.ok("a", a, "discard_edits", author=1)
    R.ok("a", a, "journal")
    R.ok("a", a, "functions")
    R.err("a", a, "analyze", "bad_request", options={"No Such Option": True})
    R.ok("a", a, "analyze", timeout=300)
    R.ok("a", a, "script", script="CharPrint.java", args=["one", "two"])
    R.ok("a", a, "script", script="CharWrite.java", note="owner: the change stays")
    R.ok("a", a, "journal", since=0, limit=1000)
    R.err("a", a, "close_program", "unsaved_changes")
    R.err("a", a, "close_project", "unsaved_changes")
    R.ok("a", a, "save", comment="characterization")
    R.ok("a", a, "save", note="nothing to save")
    R.ok("a", a, "script", script="CharWrite.java", save=True)
    R.ok("a", a, "rename", address=F1, name="char_after_save")
    R.ok("a", a, "close_program", discard=True)
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    R.ok("a", a, "info")
    R.ok("a", a, "functions")
    R.ok("a", a, "close_project")
    c.stop(d)


def sc_clients(c, R):
    """Two clients on one project: not_owner, busy, conflict with the holder named, shared
    writers, expect conflicts that name the last editor, and a project held by another process."""
    gpr = c.copy_fixture("clients")
    d = c.daemon("c-clients")
    a = c.connect(d, "char-a", "harness-a")
    b = c.connect(d, "char-b", "harness-b")
    key = "p1:/alpha.exe"
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("b", b, "open_project", path=str(gpr), writable=True, note="joins the writable project")
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True)
    R.ok("b", b, "open_program", path="/alpha.exe", note="reads what a writes")
    R.ok("b", b, "info")
    R.err("b", b, "open_program", "not_owner", path="/alpha.exe", writable=True)
    R.err("b", b, "open_program", "not_owner", path="/alpha.exe", writable=True, share=True)
    R.err("b", b, "rename", "not_owner", address=F1, name="x")
    R.err("b", b, "comment", "not_owner", address=F1, text="x")
    R.err("b", b, "edit", "not_owner", ops=[{"op": "rename", "address": F1, "name": "x"}])
    R.err("b", b, "save", "not_owner")
    R.err("b", b, "discard_edits", "not_owner", author=1)
    R.err("b", b, "analyze", "not_owner")
    R.ok("a", a, "rename", address=F1, name="by_a")
    R.ok("b", b, "functions", contains="by_a")
    R.err("b", b, "fork_project", "conflict", path=str(c.work / "clients-fork"),
          note="the writable project is used by another client")
    # busy: a's script holds the program for a while
    sid = a.send("script", script=c.script("CharSleep.java"), args=["1500"], program=key)
    time.sleep(0.4)
    R.err("b", b, "decompile", "busy", name="entry", wait=150, program=key,
          note="the holder is named")
    R.later("a", a, "script", sid, script="CharSleep.java", args=["1500"], program=key)
    R.err("a", a, "open_project", "bad_request", path=str(gpr), writable="yes")
    # another process: a second daemon cannot take the writable project
    d2 = c.daemon("c-clients-2")
    x = c.connect(d2, "char-x", "harness-x")
    R.err("x", x, "open_project", "conflict", path=str(gpr), writable=True,
          note="locked by another process")
    R.ok("x", x, "open_project", path=str(gpr), note="read-only is allowed")
    R.err("x", x, "fork_project", "conflict", path=str(c.work / "clients-fork-x"),
          note="another process holds the project writable")
    x.close()
    c.stop(d2)
    # shared writers
    R.ok("a", a, "open_program", path="/alpha.exe", writable=True, share=True,
         note="the owner opens it to others")
    R.err("b", b, "open_program", "conflict", path="/alpha.exe", writable=True,
          note="owner mode and shared mode do not mix")
    R.ok("b", b, "open_program", path="/alpha.exe", writable=True, share=True)
    R.ok("b", b, "info")
    R.ok("a", a, "rename", address=F2, name="shared_by_a")
    R.ok("b", b, "comment", address=F1, text="by b")
    R.err("b", b, "rename", "conflict", address=F2, name="shared_by_b", expect="stale_name",
          note="names who last changed it")
    R.err("b", b, "comment", "conflict", address=F2, text="x", expect="nothing there",
          note="a comment conflict")
    R.ok("b", b, "edit", ops=[{"op": "rename", "address": F2, "name": "shared_by_b",
                               "expect": "shared_by_a"}])
    R.ok("a", a, "journal")
    R.ok("a", a, "journal", author=2)
    R.ok("a", a, "status")
    R.ok("a", a, "discard_edits", author=2)
    R.ok("b", b, "journal", since=0)
    R.ok("b", b, "close_program", note="not the last writer")
    R.err("a", a, "close_program", "unsaved_changes", note="the last writer")
    R.ok("a", a, "save", comment="shared")
    R.ok("a", a, "close_program")
    R.ok("a", a, "projects")
    R.ok("a", a, "close_project")
    R.ok("b", b, "projects")
    R.ok("b", b, "close_project")
    c.stop(d)


def sc_fork_refresh(c, R):
    """fork_project, project revisions, stale and refreshed markers, refresh and reopen."""
    src = c.copy_fixture("src")
    d = c.daemon("c-fork")
    a = c.connect(d, "char-a", "harness-a")
    b = c.connect(d, "char-b", "harness-b")
    R.ok("a", a, "open_project", path=str(src))
    R.ok("b", b, "open_project", path=str(src))
    R.ok("a", a, "open_program", path="/alpha.exe")
    R.ok("b", b, "open_program", path="/alpha.exe")
    R.err("a", a, "fork_project", "bad_request", path=str(c.work / "f0"), mode="bogus")
    R.err("a", a, "fork_project", "bad_request", path=str(c.work / "f0"), name="bad/name")
    R.err("a", a, "fork_project", "bad_request", path=str(c.work / "src" / "Fixture.rep" / "f"),
          note="inside the source's .rep")
    R.err("a", a, "fork_project", "bad_request", path=str(c.work / "src"), note="the source itself")
    R.err("a", a, "fork_project", "bad_request", project="p1", note="no path")
    fk = R.ok("a", a, "fork_project", path=str(c.work / "fork1"), mode="full", project="p1")
    R.err("a", a, "fork_project", "conflict", path=str(c.work / "fork1"), mode="full",
          project="p1", note="forks are never overwritten")
    R.ok("a", a, "fork_project", path=str(c.work / "fork2" / "Named.gpr"), mode="full",
         writable=False, note="a read-only fork, named by its .gpr")
    R.ok("a", a, "projects")
    fid = fk["project"]
    R.ok("a", a, "open_program", path=f"{fid}:/alpha.exe", writable=True)
    R.ok("a", a, "rename", address=F1, name="forked_name")
    R.ok("a", a, "save")
    R.ok("a", a, "refresh", project=fid, note="writable: always current")
    R.ok("a", a, "fork_project", project=fid, path=str(c.work / "fork3"), mode="full",
         note="a fork of a fork: depth 2, no other user")
    R.ok("a", a, "info", program="p1:/alpha.exe", note="the source is untouched")
    R.ok("a", a, "refresh", project="p1")
    # another process saves the source
    d2 = c.daemon("c-fork-writer")
    w = c.connect(d2, "writer", "harness-w")
    R.ok("w", w, "open_project", path=str(src), writable=True)
    R.ok("w", w, "open_program", path="/alpha.exe", writable=True)
    R.ok("w", w, "rename", address=F1, name="saved_elsewhere")
    R.ok("w", w, "save")
    R.ok("w", w, "close_project")
    w.close()
    c.stop(d2)
    R.ok("a", a, "functions", contains="saved_elsewhere", note="the old view; marked stale")
    R.ok("a", a, "project", project="p1")
    R.ok("a", a, "status")
    R.ok("b", b, "refresh", project="p1", note="b refreshes; a is told once")
    R.ok("b", b, "functions", contains="saved_elsewhere")
    R.ok("a", a, "functions", contains="saved_elsewhere", note="a is told it was refreshed")
    R.ok("a", a, "info", program="p1:/alpha.exe", note="and only once")
    R.ok("a", a, "decompile", address=F1, maxChars=60)
    R.ok("a", a, "refresh", project="p1", note="unchanged now")
    R.ok("a", a, "reopen", project="p1", force=True)
    R.ok("a", a, "close_project", project=fid)
    c.stop(d)


def sc_overlays(c, R):
    """Overlays: a private view over a read-only program, apply/drop, promotion into a fork."""
    src = c.copy_fixture("ov")
    d = c.daemon("c-overlays")
    a = c.connect(d, "char-a", "harness-a")
    b = c.connect(d, "char-b", "harness-b")
    R.ok("a", a, "open_project", path=str(src))
    R.ok("b", b, "open_project", path=str(src))
    R.ok("a", a, "open_program", path="/alpha.exe")
    R.ok("a", a, "overlays")
    R.err("a", a, "open_program", "bad_request", path="/alpha.exe", overlay="bad name!")
    R.err("a", a, "open_program", "bad_request", path="/alpha.exe", overlay="mine",
          writable=True)
    R.ok("a", a, "open_program", path="/alpha.exe", overlay="mine")
    R.ok("a", a, "open_program", path="/alpha.exe", overlay="mine", note="joins the same overlay")
    R.ok("a", a, "info", overlay="mine")
    R.ok("a", a, "info", note="the shared program, with its overlay names")
    R.ok("a", a, "rename", overlay="mine", address=F1, name="ov_helper")
    R.ok("a", a, "comment", overlay="mine", address=F1, text="overlay comment")
    R.ok("a", a, "apply_overlay", overlay="mine", ops=[
        {"op": "rename", "address": F2, "name": "ov_two"},
        {"op": "comment", "address": F2, "text": "two", "type": "plate"}])
    R.err("a", a, "apply_overlay", "bad_request", overlay="mine", ops=[])
    R.err("a", a, "apply_overlay", "conflict", overlay="mine",
          ops=[{"op": "rename", "address": F1, "name": "z", "expect": "wrong"}],
          note="nothing applied")
    R.ok("a", a, "functions", overlay="mine", contains="ov_")
    R.ok("a", a, "functions", contains="ov_", note="the shared program is unchanged")
    R.ok("a", a, "decompile", overlay="mine", address=F2, maxChars=80)
    R.ok("a", a, "script", overlay="mine", script="CharPrint.java", args=["ov"])
    R.ok("a", a, "script", overlay="mine", script="CharWrite.java",
         note="contained: rolled back")
    R.ok("a", a, "overlays")
    R.ok("a", a, "status")
    R.err("a", a, "info", "not_found", overlay="nope")
    R.err("a", a, "rename", "not_found", overlay="nope", address=F1, name="x")
    R.ok("a", a, "drop_overlay", overlay="nope", note="nothing to drop")
    R.err("b", b, "info", "no_program", overlay="mine", program="p1:/alpha.exe",
          note="b has not opened the program")
    R.ok("b", b, "open_program", path="/alpha.exe", overlay="mine", note="b's own overlay")
    R.ok("b", b, "overlays")
    R.err("a", a, "promote_overlay", "bad_request", overlay="mine",
          note="neither project nor fork")
    R.err("a", a, "promote_overlay", "not_found", overlay="unknown")
    R.err("b", b, "promote_overlay", "bad_request", overlay="mine", note="b's overlay is empty")
    R.err("a", a, "promote_overlay", "no_project", overlay="mine", project="p9")
    pr = R.ok("a", a, "promote_overlay", overlay="mine",
              fork={"path": str(c.work / "ov-fork"), "mode": "full"})
    R.ok("a", a, "info", program=pr["target"], note="the promoted program in the fork")
    R.ok("a", a, "functions", program=pr["target"], contains="ov_")
    R.ok("a", a, "projects")
    R.ok("a", a, "drop_overlay", overlay="mine")
    R.ok("a", a, "overlays")
    R.ok("a", a, "info")
    R.ok("a", a, "open_program", path="/alpha.exe", overlay="again")
    R.ok("a", a, "rename", overlay="again", address=F1, name="again_name")
    R.ok("a", a, "close_program", note="drops the client's overlays with it")
    R.ok("a", a, "overlays")
    c.stop(d)


def sc_import_script(c, R):
    """import (dedupe, duplicate, queue), analyze, scripts (none, contained, owner, failing),
    cancel of a running request."""
    d = c.daemon("c-import")
    a = c.connect(d, "char-a", "harness-a")
    folder = c.work / "imp"
    gpr = c.make_project(a, folder, "Imp")
    R.ok("a", a, "open_project", path=str(gpr), writable=True)
    R.ok("a", a, "import", file=str(c.bin / "alpha.exe"), wait=300000)
    R.ok("a", a, "import", file=str(c.bin / "alpha.exe"), note="deduplicated by SHA-256")
    R.ok("a", a, "import", file=str(c.bin / "alpha.exe"), duplicate=True, name="alpha2.exe",
         folder="/copies", note="imported again on request")
    R.ok("a", a, "import", file=str(c.bin / "beta.exe"), analyze=True, timeout=600,
         wait=300000, language="x86:LE:64:default", compiler="windows")
    R.err("a", a, "import", "not_found", file=str(c.bin / "missing.exe"))
    R.err("a", a, "import", "bad_request")
    R.ok("a", a, "list", programsOnly=True)
    R.ok("a", a, "status")
    R.ok("a", a, "programs")
    R.ok("a", a, "analyze", note="again, on the active program", timeout=300)
    R.ok("a", a, "functions")
    # scripts
    R.ok("a", a, "script", script="CharPrint.java", args=["x"], note="on the owned program")
    R.ok("a", a, "script", script="CharPrint.java", program=None, note="no program")
    R.ok("a", a, "script", script=c.script("CharPrint.java"), address=F2, maxChars=20)
    R.ok("a", a, "script", script="CharPrint.java", exclusive=True, artifact="char-artifact")
    R.err("a", a, "script", "failed", script="CharFail.java")
    R.err("a", a, "script", "bad_request", script="CharPrint.java", maxChars=0)
    R.ok("a", a, "script", script="CharWrite.java")
    R.ok("a", a, "journal")
    R.ok("a", a, "close_program", discard=True)
    R.ok("a", a, "open_program", path="/alpha.exe")
    R.ok("a", a, "script", script="CharWrite.java", note="read-only: contained, rolled back")
    R.ok("a", a, "functions")
    # cancel
    sid = a.send("script", script=c.script("CharSleep.java"), args=["20000"], program=None)
    time.sleep(0.5)
    R.ok("a", a, "status", note="the running script is listed")
    R.ok("a", a, "cancel", target=sid)
    R.later("a", a, "script", sid, script="CharSleep.java", args=["20000"], program=None)
    sid = a.send("script", script=c.script("CharSleep.java"), args=["20000"], program=None)
    time.sleep(0.5)
    R.ok("a", a, "cancel", all=True)
    R.later("a", a, "script", sid, script="CharSleep.java", args=["20000"], program=None)
    R.err("a", a, "script", "cancelled", script="CharSleep.java", args=["20000"], program=None,
          timeout=1, note="its own timeout")
    R.err("a", a, "close_project", "unsaved_changes", note="the opened imports have changes")
    R.ok("a", a, "close_project", discard=True)
    c.stop(d)


def hashlib_sha(path):
    import hashlib
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


SCENARIOS = {
    "session": sc_session,
    "readonly": sc_readonly,
    "edits": sc_edits,
    "clients": sc_clients,
    "fork_refresh": sc_fork_refresh,
    "overlays": sc_overlays,
    "import_script": sc_import_script,
}


# ---- driver --------------------------------------------------------------------------------

def render(R):
    return json.dumps({"scenario": R.name, "steps": R.steps}, indent=1, ensure_ascii=False) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", required=True, help="the install to test")
    ap.add_argument("--work", required=True, help="an empty working directory")
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemon (default: <work>/tmp)")
    ap.add_argument("--golden", default=str(HERE / "characterization"),
                    help="the golden directory (default: examples/characterization)")
    ap.add_argument("--record", action="store_true", help="write the golden files")
    ap.add_argument("--out", help="also write this run's masked replies here")
    ap.add_argument("--only", help="comma-separated scenario names")
    a = ap.parse_args()
    sys.path.insert(0, str(pathlib.Path(a.ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import ghidra_session as gs
    c = Ctx(a, gs)
    names = a.only.split(",") if a.only else list(SCENARIOS)
    for n in names:
        if n not in SCENARIOS:
            ap.error(f"unknown scenario {n}; known: {', '.join(SCENARIOS)}")
    c.golden.mkdir(parents=True, exist_ok=True)
    failed = []
    t_all = time.perf_counter()
    try:
        for n in names:
            t = time.perf_counter()
            R = Rec(n, gs, c.masker())
            c.clean()
            try:
                SCENARIOS[n](c, R)
            except Exception as e:  # noqa: BLE001
                print(f"FAIL {n}: {type(e).__name__}: {e}")
                failed.append(n)
                continue
            finally:
                c.cleanup()
            text = render(R)
            if a.out:
                out = pathlib.Path(a.out)
                out.mkdir(parents=True, exist_ok=True)
                (out / f"{n}.json").write_text(text, encoding="utf-8", newline="\n")
            g = c.golden / f"{n}.json"
            if a.record:
                g.write_text(text, encoding="utf-8", newline="\n")
                print(f"rec  {n:14s} {len(R.steps):4d} requests -> {g}")
            elif not g.exists():
                print(f"FAIL {n}: no golden file {g}; run with --record")
                failed.append(n)
            else:
                want = g.read_text(encoding="utf-8")
                if want == text:
                    print(f"ok   {n:14s} {len(R.steps):4d} requests identical "
                          f"({time.perf_counter() - t:.0f} s)")
                else:
                    actual = c.work / "actual"
                    actual.mkdir(exist_ok=True)
                    (actual / f"{n}.json").write_text(text, encoding="utf-8", newline="\n")
                    diff = list(difflib.unified_diff(want.splitlines(), text.splitlines(),
                                                     "golden", "actual", lineterm="", n=2))
                    print(f"FAIL {n}: replies differ from {g} ({len(diff)} diff lines; actual in "
                          f"{actual / (n + '.json')})")
                    print("\n".join(diff[:60]))
                    failed.append(n)
    finally:
        c.cleanup()
    print(f"{len(names) - len(failed)}/{len(names)} scenarios "
          f"{'recorded' if a.record else 'identical'} in {time.perf_counter() - t_all:.0f} s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
