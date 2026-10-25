"""Records a real Python session against the daemon, the way a REPL shows it: each statement is
executed for real, its printed output and (for expressions) its repr are kept, with its wall time.
Writes a transcript JSON for render_terminal.py.

usage: record_session.py <install> <state dir> <work dir> <demo.exe> <out.json>
"""
import contextlib, io, json, os, pathlib, sys, time

install, state, work, exe, out = sys.argv[1:6]
os.environ["GHIDRA_SESSION_HOME"] = state
os.chdir(work)
sys.path.insert(0, str(pathlib.Path(install) / "Ghidra/Features/HeadlessSession/support"))

MAKE = """// @category Demo
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class DemoMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
"""
pathlib.Path("scripts").mkdir(exist_ok=True)
pathlib.Path("scripts/DemoMakeProject.java").write_text(MAKE)
pathlib.Path(state).mkdir(parents=True, exist_ok=True)
(pathlib.Path(state) / "config.json").write_text(json.dumps({"scriptPath": [str(pathlib.Path("scripts").resolve())]}))
pathlib.Path("hydra_demo.exe").write_bytes(pathlib.Path(exe).read_bytes())
pathlib.Path("hydra_demo.pdb").write_bytes(pathlib.Path(exe).with_suffix(".pdb").read_bytes())

ns = {}
hidden = [
    "import ghidra_session as gs",
    "_s = gs.connect(client='setup')",
    "_s.call('script', script='DemoMakeProject.java', args=[os.getcwd(), 'demo'], program=None)",
    "_s.close()",
    "gs.Daemon(None, os.environ['GHIDRA_SESSION_HOME'], 'default').stop(force=True)",
]
shown = [
    "import ghidra_session as gs",
    "s = gs.connect(client='demo', harness='readme')",
    "s.call('open_project', path='demo.gpr', writable=True)['id']",
    "s.call('import', file='hydra_demo.exe', analyze=True)['imported']",
    "s.call('import', file='hydra_demo.exe')['imported']   # same SHA-256: never twice",
    "{k: s.call('info')[k] for k in ('format', 'language', 'functions')}",
    "print(s.call('decompile', name='grow_heads')['c'])",
    "s.call('decompile', name='grow_heads')['signature']",
]
ns["os"] = os
for h in hidden:
    exec(h, ns)

lines = []
for stmt in shown:
    buf = io.StringIO()
    t = time.perf_counter()
    with contextlib.redirect_stdout(buf):
        try:
            code = compile(stmt, "<demo>", "eval")
            val = eval(code, ns)
            if val is not None:
                print(repr(val))
        except SyntaxError:
            exec(compile(stmt, "<demo>", "exec"), ns)
    ms = (time.perf_counter() - t) * 1000
    lines.append({"in": stmt, "out": buf.getvalue().rstrip("\n"), "ms": round(ms, 1),
                  "daemonMs": ns["s"].last_ms if "s" in ns and hasattr(ns["s"], "last_ms") else None})
    print(f"{ms:9.1f} ms  >>> {stmt}", file=sys.stderr)
    print(buf.getvalue(), file=sys.stderr)

ns["s"].close()
ns["gs"].Daemon(None, state, "default").stop(force=True)
pathlib.Path(out).write_text(json.dumps(lines, indent=1), encoding="utf-8")


