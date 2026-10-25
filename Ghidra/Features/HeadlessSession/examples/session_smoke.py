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
"""End-to-end check of a headless session install. Standard library only.

    python session_smoke.py --ghidra <install> --work <empty dir> --binary A.exe --binary B.exe

It creates a project in <work>, imports and analyses both binaries through the session, switches
between them, renames on a writable program, saves, reopens it in a new process read-only and
checks the name, runs a contained script and checks that it was rolled back, then runs two socket
clients at once and checks ownership, busy and disconnect handling. Prints one line per step with
its timing; exits non-zero on the first failure.
"""
import argparse
import os
import pathlib
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_client import SessionError, SocketSession, StdioSession  # noqa: E402

TRY_WRITE = """// @category HeadlessSession.Smoke
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class SmokeTryWrite extends GhidraScript {
    @Override protected void run() throws Exception {
        getFunctionContaining(currentAddress).setName(getScriptArgs()[0], SourceType.USER_DEFINED);
        println("renamed to " + getFunctionContaining(currentAddress).getName());
    }
}
"""
MAKE_PROJECT = """// @category HeadlessSession.Smoke
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class SmokeMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
"""


def step(label, fn):
    t = time.perf_counter()
    try:
        r = fn()
    except SessionError as e:
        print(f"FAIL {label}: {e}")
        sys.exit(1)
    print(f"ok   {label:46s} {1000 * (time.perf_counter() - t):9.1f} ms")
    return r


def expect_error(label, code, fn):
    try:
        fn()
    except SessionError as e:
        if e.code != code:
            print(f"FAIL {label}: expected {code}, got {e.code}: {e.message}")
            sys.exit(1)
        print(f"ok   {label:46s} -> {code}")
        return e
    print(f"FAIL {label}: expected {code}, it was allowed")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--binary", action="append", required=True)
    a = ap.parse_args()
    if len(a.binary) != 2:
        ap.error("give --binary twice")
    launcher = str(pathlib.Path(a.ghidra) / "support" /
                   ("headlessSession.bat" if os.name == "nt" else "headlessSession"))
    work = pathlib.Path(a.work).absolute()
    scripts = work / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "SmokeTryWrite.java").write_text(TRY_WRITE)
    (scripts / "SmokeMakeProject.java").write_text(MAKE_PROJECT)
    proj = work / "Smoke.gpr"
    log = str(work / "session.log")
    names = [pathlib.Path(b).name for b in a.binary]

    with StdioSession(launcher, "-scriptPath", str(scripts), stderr_path=log) as s:
        step("create project (script, no program)",
             lambda: s.call("script", script="SmokeMakeProject.java", program=None,
                            args=[str(work), "Smoke"]))

    with StdioSession(launcher, "-project", str(proj), "-writable", "-scriptPath", str(scripts),
                      stderr_path=log) as s:
        print(f"ok   {'start writable session':46s} {1000 * s.startup_wall:9.1f} ms")
        for b in a.binary:
            step(f"import + analyze {pathlib.Path(b).name}",
                 lambda b=b: s.call("import", file=b, analyze=True, timeout=1800))
        r = step("import again (deduplicated)", lambda: s.call("import", file=a.binary[0]))
        assert r["imported"] is False, r
        step(f"switch to /{names[0]}", lambda: s.call("switch", path="/" + names[0]))
        c0 = step("decompile entry", lambda: s.call("decompile", name="entry"))
        step(f"switch to /{names[1]}", lambda: s.call("switch", path="/" + names[1]))
        entry = step("decompile entry", lambda: s.call("decompile", name="entry"))["entry"]
        step("rename entry", lambda: s.call("rename", address=entry, name="smoke_entry"))
        expect_error("close with unsaved changes", "unsaved_changes", lambda: s.call("close_program"))
        step("save", lambda: s.call("save"))
        assert c0["c"]

    with StdioSession(launcher, "-project", str(proj), "-scriptPath", str(scripts),
                      stderr_path=log) as s:
        step(f"reopen /{names[1]} read-only", lambda: s.call("open_program", path=names[1]))
        f = step("find smoke_entry", lambda: s.call("functions", contains="smoke_entry"))
        assert f["functions"], "rename did not persist"
        expect_error("rename on a read-only program", "read_only",
                     lambda: s.call("rename", address=entry, name="x"))
        r = step("contained script", lambda: s.call("script", script="SmokeTryWrite.java",
                                                    args=["smoke_contained"], address=entry))
        assert r["mode"] == "contained" and not r["changed"], r
        assert not s.call("functions", contains="smoke_contained")["functions"], "not rolled back"

    endpoint = work / "endpoint.json"
    if endpoint.exists():
        endpoint.unlink()
    with open(log, "ab") as lf:
        daemon = subprocess.Popen([launcher, "-project", str(proj), "-writable", "-listen", "0",
                                   "-endpoint", str(endpoint), "-noStdio", "-idleTimeout", "60"],
                                  stdin=subprocess.DEVNULL, stdout=lf, stderr=lf)
    try:
        while not endpoint.exists():
            if daemon.poll() is not None:
                print("FAIL daemon exited")
                sys.exit(1)
            time.sleep(0.1)
        A = SocketSession(str(endpoint), client="smoke-A", harness="smoke")
        B = SocketSession(str(endpoint), client="smoke-B", harness="smoke")
        step("A opens writable", lambda: A.call("open_program", path=names[1], writable=True))
        step("B joins read-only", lambda: B.call("open_program", path=names[1]))
        expect_error("B renames A's program", "not_owner",
                     lambda: B.call("rename", address=entry, name="b"))
        step("A renames (unsaved)", lambda: A.call("rename", address=entry, name="smoke_unsaved"))
        rid = A.send("analyze", timeout=1800)
        time.sleep(1.0)
        expect_error("B reads while A analyses (wait 200 ms)", "busy",
                     lambda: B.call("decompile", address=entry, wait=200))
        step("A cancels its analysis", lambda: A.wait(A.send("cancel", target=rid)))
        expect_error("A's analysis ends cancelled", "cancelled", lambda: A.wait(rid))
        A.close()
        time.sleep(1.0)
        p = step("B after A disconnected", lambda: B.call("info"))
        assert p["mode"] == "read_only" and not p["changed"], p
        assert not B.call("functions", contains="smoke_unsaved")["functions"], "unsaved kept"
        step("B shuts the session down", lambda: B.call("shutdown"))
        B.close()
        daemon.wait(timeout=60)
    finally:
        if daemon.poll() is None:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(daemon.pid)] if os.name == "nt"
                           else ["kill", str(daemon.pid)], capture_output=True)
    print("all smoke checks passed")


if __name__ == "__main__":
    main()
