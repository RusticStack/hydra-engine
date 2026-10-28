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
"""The DB-version gate (PROTOCOL-3.md 9.7, package E2). Standard library only; any OS.

    python format_gate.py                       # the source constants against format-matrix.json
    python format_gate.py --engine <install>    # ... and hello.analysisIdentity.dbVersions of a
                                                # daemon started from that install
    python format_gate.py --selftest            # the gate catches a planted change (exit 0)

Exit 0 when ``ProgramDB.DB_VERSION``, ``DataTypeManagerDB.DB_VERSION``,
``DataTypeArchiveDB.DB_VERSION``, ``ProgramUserDataDB.DB_VERSION`` and ``SlaFormat.FORMAT_VERSION``
read from the Java sources equal ``format-matrix.json`` (values on the sync branch: 33, 3, 5, 1,
4). A constant changed without a matrix entry (and a release note) fails the merge, and fails any
future upstream sync that brings one. With ``--engine`` the running engine's
``analysisIdentity.dbVersions`` must equal the matrix and must not be null (-1 in the engine).
"""
import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
MODULE = HERE.parent
REPO = MODULE.parents[2]
MATRIX = MODULE / "format-matrix.json"


def read_constant(path, name):
    """The integer assigned to ``static final int <name>`` in a Java source, or None."""
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    m = re.search(r"\bstatic\s+final\s+int\s+" + re.escape(name) + r"\s*=\s*(-?\d+)\s*;", text)
    return int(m.group(1)) if m else None


def check_sources(matrix, repo=REPO):
    """Returns a list of problems (empty: the gate passes)."""
    problems = []
    for key, entry in matrix["current"].items():
        cls, name = key.split(".", 1)
        src = repo / entry["file"]
        if not src.is_file():
            problems.append(f"{key}: {entry['file']} does not exist")
            continue
        got = read_constant(src, name)
        if got is None:
            problems.append(f"{key}: no 'static final int {name} = <n>;' in {entry['file']}")
        elif got != entry["value"]:
            problems.append(f"{key} is {got} in the source, format-matrix.json says "
                            f"{entry['value']}: add a matrix entry and a release note")
    return problems


def check_engine(matrix, install):
    sys.path.insert(0, str(pathlib.Path(install) / "Ghidra" / "Features" / "HeadlessSession" /
                           "support"))
    import tempfile
    import ghidra_session as gs  # noqa: E402
    state = tempfile.mkdtemp(prefix="format-gate-")
    d = gs.Daemon(install, state, "format-gate")
    problems = []
    try:
        s = d.connect("format-gate", "format_gate")
        ident = s.hello.get("analysisIdentity") or {}
        got = ident.get("dbVersions") or {}
        want = {"program": matrix["current"]["ProgramDB.DB_VERSION"]["value"],
                "dataTypes": matrix["current"]["DataTypeManagerDB.DB_VERSION"]["value"]}
        for k, v in want.items():
            if got.get(k) is None:
                problems.append(f"hello.analysisIdentity.dbVersions.{k} is {got.get(k)!r} "
                                f"(unreadable), the matrix says {v}")
            elif got[k] != v:
                problems.append(f"hello.analysisIdentity.dbVersions.{k} is {got[k]}, the matrix "
                                f"says {v}")
        s.close()
    finally:
        try:
            d.stop()
        except Exception:  # noqa: BLE001
            pass
    return problems


def selftest(matrix):
    """The gate must fail on a changed constant, on a missing constant and on a missing file."""
    import copy
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as t:
        repo = pathlib.Path(t)
        for key, entry in matrix["current"].items():
            cls, name = key.split(".", 1)
            f = repo / entry["file"]
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(f"class {cls} {{ static final int {name} = {entry['value']}; }}\n")
        if check_sources(matrix, repo):
            print("selftest: the gate fails on a consistent tree:", check_sources(matrix, repo))
            ok = False
        bumped = copy.deepcopy(matrix)
        first = next(iter(bumped["current"].values()))
        first["value"] += 1
        if not check_sources(bumped, repo):
            print("selftest: a changed constant was not caught")
            ok = False
        k0 = next(iter(matrix["current"]))
        (repo / matrix["current"][k0]["file"]).write_text("class X {}\n")
        if not check_sources(matrix, repo):
            print("selftest: a missing constant was not caught")
            ok = False
        (repo / matrix["current"][k0]["file"]).unlink()
        if not check_sources(matrix, repo):
            print("selftest: a missing file was not caught")
            ok = False
    print("selftest ok" if ok else "selftest FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--engine", help="an install to start and read hello.analysisIdentity from")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--matrix", default=str(MATRIX))
    a = ap.parse_args(argv)
    matrix = json.loads(pathlib.Path(a.matrix).read_text(encoding="utf-8"))
    if a.selftest:
        return selftest(matrix)
    problems = check_sources(matrix)
    if a.engine:
        problems += check_engine(matrix, a.engine)
    for p in problems:
        print("FAIL:", p)
    if not problems:
        vals = ", ".join(f"{k}={v['value']}" for k, v in matrix["current"].items())
        print(f"format gate ok: {vals}" + (" (engine checked)" if a.engine else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
