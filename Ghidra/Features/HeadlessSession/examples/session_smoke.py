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
"""End-to-end check of a headless session install, through the shared daemon. Standard library
only; any OS.

    python session_smoke.py --ghidra <install> --work <empty dir> --binary A.exe --binary B.exe

It uses its own state dir (<work>/state) and daemon instance ("smoke"), so it never touches the
user's daemon. Through support/ghidra_session.py it starts the daemon, creates a project, imports
and analyses both binaries, switches between them, renames on a writable program, saves, reopens
the project read-only and checks the name, runs a contained script and checks that it was rolled
back, then runs two clients at once and checks ownership, busy, cancel and disconnect handling.
Prints one line per step with its timing; exits non-zero on the first failure.
"""
import argparse
import json
import pathlib
import sys
import time

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


def load_launcher(ghidra):
    sys.path.insert(0, str(pathlib.Path(ghidra) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import ghidra_session
    return ghidra_session


def step(label, fn):
    t = time.perf_counter()
    try:
        r = fn()
    except Exception as e:  # noqa: BLE001 - report any failure as a failed step
        print(f"FAIL {label}: {type(e).__name__}: {e}")
        sys.exit(1)
    print(f"ok   {label:52s} {1000 * (time.perf_counter() - t):9.1f} ms", flush=True)
    return r


def expect_error(gs, label, code, fn):
    try:
        fn()
    except gs.SessionError as e:
        if e.code != code:
            print(f"FAIL {label}: expected {code}, got {e.code}: {e.message}")
            sys.exit(1)
        print(f"ok   {label:52s} -> {code}", flush=True)
        return e
    print(f"FAIL {label}: expected {code}, it was allowed")
    sys.exit(1)


def check(cond, what):
    if not cond:
        print(f"FAIL {what}")
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--binary", action="append", required=True)
    ap.add_argument("--tmpdir", help="java.io.tmpdir for the daemon (default: <work>/tmp)")
    a = ap.parse_args()
    if len(a.binary) != 2:
        ap.error("give --binary twice")
    gs = load_launcher(a.ghidra)
    work = pathlib.Path(a.work).absolute()
    state = work / "state"
    scripts = work / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    (scripts / "SmokeTryWrite.java").write_text(TRY_WRITE)
    (scripts / "SmokeMakeProject.java").write_text(MAKE_PROJECT)
    (state / "config.json").write_text(json.dumps({
        "tmpdir": a.tmpdir or str(work / "tmp"), "scriptPath": [str(scripts)],
        "keepWarm": 600}))
    proj = work / "Smoke.gpr"
    names = [pathlib.Path(b).name for b in a.binary]
    daemon = gs.Daemon(a.ghidra, str(state), "smoke")

    def connect(name):
        return daemon.connect(client=name, harness="smoke")

    try:
        s = step("start the daemon and connect (cold)", lambda: connect("smoke-main"))
        print(f"     launch: {json.dumps(s.endpoint.get('launch'))}")
        step("create project (script, no program)",
             lambda: s.call("script", script="SmokeMakeProject.java", program=None,
                            args=[str(work), "Smoke"]))
        p = step("open project writable", lambda: s.call("open_project", path=str(proj),
                                                         writable=True))
        pid = p["id"]
        for b in a.binary:
            step(f"import + analyze {pathlib.Path(b).name}",
                 lambda b=b: s.call("import", file=b, analyze=True, timeout=1800, wait=600000))
        r = step("import again (deduplicated)", lambda: s.call("import", file=a.binary[0]))
        check(r["imported"] is False and r["existing"], f"not deduplicated: {r}")
        step(f"switch to /{names[0]}", lambda: s.call("switch", path="/" + names[0]))
        c0 = step("decompile entry", lambda: s.call("decompile", name="entry"))
        step(f"switch to {pid}:/{names[1]} (by key)",
             lambda: s.call("switch", path=f"{pid}:/{names[1]}"))
        entry = step("decompile entry", lambda: s.call("decompile", name="entry"))["entry"]
        step("rename entry", lambda: s.call("rename", address=entry, name="smoke_entry"))
        expect_error(gs, "close with unsaved changes", "unsaved_changes",
                     lambda: s.call("close_program"))
        step("save", lambda: s.call("save"))
        check(c0["c"], "empty decompilation")
        r = step("leave the writable project", lambda: s.call("close_project"))
        check(r["closed"], f"writable project still open after its last user left: {r}")

        step("open project read-only", lambda: s.call("open_project", path=str(proj)))
        step(f"reopen /{names[1]} read-only", lambda: s.call("open_program", path=names[1]))
        f = step("find smoke_entry", lambda: s.call("functions", contains="smoke_entry"))
        check(f["functions"], "rename did not persist")
        expect_error(gs, "rename on a read-only program", "read_only",
                     lambda: s.call("rename", address=entry, name="x"))
        r = step("contained script", lambda: s.call("script", script="SmokeTryWrite.java",
                                                    args=["smoke_contained"], address=entry))
        check(r["mode"] == "contained" and not r["changed"], f"not contained: {r}")
        check(not s.call("functions", contains="smoke_contained")["functions"],
              "contained script not rolled back")
        step("leave the read-only project", lambda: s.call("close_project"))

        A = step("A connects (warm daemon)", lambda: connect("smoke-A"))
        B = step("B connects (warm daemon)", lambda: connect("smoke-B"))
        step("A opens the project writable", lambda: A.call("open_project", path=str(proj),
                                                            writable=True))
        step("B joins the project", lambda: B.call("open_project", path=str(proj)))
        step("A opens writable", lambda: A.call("open_program", path=names[1], writable=True))
        step("B joins read-only", lambda: B.call("open_program", path=names[1]))
        expect_error(gs, "B renames A's program", "not_owner",
                     lambda: B.call("rename", address=entry, name="b"))
        step("A renames (unsaved)", lambda: A.call("rename", address=entry, name="smoke_unsaved"))
        rid = A.send("analyze", timeout=1800)
        time.sleep(1.0)
        expect_error(gs, "B reads while A analyses (wait 200 ms)", "busy",
                     lambda: B.call("decompile", address=entry, wait=200))
        step("A cancels its analysis", lambda: A.wait(A.send("cancel", target=rid)))
        expect_error(gs, "A's analysis ends cancelled", "cancelled", lambda: A.wait(rid))
        A.close()
        time.sleep(1.0)
        info = step("B after A disconnected", lambda: B.call("info"))
        check(info["mode"] == "read_only" and not info["changed"], f"not released: {info}")
        check(not B.call("functions", contains="smoke_unsaved")["functions"],
              "A's unsaved change survived its disconnect")
        expect_error(gs, "B shuts down while main is connected", "conflict",
                     lambda: B.call("shutdown"))
        s.close()
        B.close()
        step("stop the daemon", lambda: daemon.stop())
        check(not daemon.jvm_alive(), "daemon JVM still alive")
    finally:
        if daemon.jvm_alive():
            daemon.kill()
    print("all smoke checks passed")


if __name__ == "__main__":
    main()
