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
"""Lists every sleep in the test files, to track the conversion to ``fastlib`` (vtime design, package T1).

    python lint_sleeps.py [--root DIR] [--summary] [--json] [FILE ...]

Scans ``dt_*.py``, ``cc_*.py`` and ``conc/*.py`` under ``--root`` (default: this folder), or the files named.
One line per finding, ``file:line  class  source``, then the counts per class and per file. It is a progress
meter, not a gate: the exit code is 0 whatever it finds (2 only for a usage error).

Classes (a sleep is ``time.sleep``, ``sleep`` imported from ``time``, or ``sleep_precise``):
    poll        a sleep inside a ``while`` loop: sleep based polling, convert to ``fastlib.until`` / ``wait_change``
    fixed-long  a sleep of a constant 1 s or more outside a loop: a hold or a "wait and hope"
    fixed-short a sleep of a constant under 1 s outside a loop
    variable    a sleep outside a loop whose duration is computed
    spin        ``sleep_precise`` (a sleep plus a busy spin) or a ``while ...: pass`` busy loop
    waived      the line (or the one above) carries ``# lint: sleep-ok`` followed by the reason
A ``for`` loop around a sleep is not a poll by itself (it is a repeat), so it counts by its constant. Progress is
shown by the ``fastlib`` column: the number of calls into ``fastlib`` in the file (``fastlib.until(...)`` or a name
imported from it).
"""
import argparse
import ast
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATTERNS = ["dt_*.py", "cc_*.py", os.path.join("conc", "*.py")]
CLASSES = ["poll", "fixed-long", "fixed-short", "variable", "spin", "waived"]
WAIVER = "lint: sleep-ok"


class Scan(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines, self.found, self.fastlib_calls = lines, [], 0
        self.time_mods, self.sleep_names, self.fl_mods, self.fl_names = {"time"}, {"sleep"}, set(), set()
        self.loops = []  # stack of "while" / "for", reset at a function boundary

    # imports decide what a name means
    def visit_Import(self, n):
        for a in n.names:
            if a.name == "time":
                self.time_mods.add(a.asname or "time")
            if a.name == "fastlib":
                self.fl_mods.add(a.asname or "fastlib")

    def visit_ImportFrom(self, n):
        for a in n.names:
            if n.module == "time" and a.name == "sleep":
                self.sleep_names.add(a.asname or "sleep")
            if n.module == "fastlib":
                self.fl_names.add(a.asname or a.name)

    def _scoped(self, n):
        saved, self.loops = self.loops, []
        self.generic_visit(n)
        self.loops = saved

    visit_FunctionDef = visit_AsyncFunctionDef = visit_Lambda = _scoped

    def visit_While(self, n):
        if all(isinstance(s, ast.Pass) for s in n.body):
            self._add(n, "spin")
        self.visit(n.test)
        self.loops.append("while")
        for s in n.body + n.orelse:
            self.visit(s)
        self.loops.pop()

    def visit_For(self, n):
        self.visit(n.iter)
        self.loops.append("for")
        for s in n.body + n.orelse:
            self.visit(s)
        self.loops.pop()

    def visit_Call(self, n):
        f = n.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
        base = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else None
        if base in self.fl_mods or (isinstance(f, ast.Name) and name in self.fl_names):
            self.fastlib_calls += 1
        if name == "sleep_precise":
            self._add(n, "spin")
        elif (base in self.time_mods and name == "sleep") or (isinstance(f, ast.Name) and name in self.sleep_names):
            self._add(n, self._classify(n))
        self.generic_visit(n)

    def _classify(self, n):
        if "while" in self.loops:
            return "poll"
        a = n.args[0] if n.args else None
        if isinstance(a, ast.Constant) and isinstance(a.value, (int, float)):
            return "fixed-long" if a.value >= 1 else "fixed-short"
        return "variable"

    def _add(self, n, cls):
        i = n.lineno - 1
        for k in (i, i - 1):
            if 0 <= k < len(self.lines) and WAIVER in self.lines[k]:
                cls = "waived"
        self.found.append((n.lineno, cls, self.lines[i].strip()))


def scan_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    s = Scan(text.splitlines())
    s.visit(ast.parse(text, path))
    return sorted(set(s.found)), s.fastlib_calls


def find_files(root):
    out = []
    for pat in PATTERNS:
        out += glob.glob(os.path.join(root, pat))
    return sorted(set(out))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*", help="files to scan (default: dt_*, cc_*, conc/* under --root)")
    ap.add_argument("--root", default=HERE)
    ap.add_argument("--summary", action="store_true", help="counts only")
    ap.add_argument("--json", action="store_true", help="machine readable result on stdout")
    args = ap.parse_args(argv)
    files = args.files or find_files(args.root)
    rows, per_file, notes = [], {}, []
    for p in files:
        rel = os.path.relpath(p, args.root).replace(os.sep, "/")
        try:
            found, fl_calls = scan_file(p)
        except (OSError, SyntaxError, ValueError) as e:
            notes.append(f"{rel}: not scanned ({type(e).__name__}: {e})")
            continue
        per_file[rel] = {"fastlib": fl_calls, **{c: 0 for c in CLASSES}}
        for line, cls, src in found:
            rows.append((rel, line, cls, src))
            per_file[rel][cls] += 1
    totals = {c: sum(1 for r in rows if r[2] == c) for c in CLASSES}
    total_fl = sum(v["fastlib"] for v in per_file.values())
    if args.json:
        print(json.dumps({"findings": [dict(file=r[0], line=r[1], cls=r[2], source=r[3]) for r in rows],
                          "totals": totals, "sleeps": len(rows), "fastlib_calls": total_fl,
                          "per_file": per_file, "not_scanned": notes}, indent=1))
        return 0
    if not args.summary:
        for rel, line, cls, src in rows:
            print(f"{rel}:{line}  {cls:<11} {src[:110]}")
        print()
    for n in notes:
        print(n)
    print(f"{'file':<22}" + "".join(f"{c:>12}" for c in CLASSES) + f"{'fastlib':>9}")
    for rel, v in sorted(per_file.items()):
        if any(v[c] for c in CLASSES) or v["fastlib"]:
            print(f"{rel:<22}" + "".join(f"{v[c]:>12}" for c in CLASSES) + f"{v['fastlib']:>9}")
    print(f"{'TOTAL':<22}" + "".join(f"{totals[c]:>12}" for c in CLASSES) + f"{total_fl:>9}")
    print(f"{len(rows)} sleeps in {len(per_file)} files "
          f"({totals['poll']} poll, {totals['fixed-long'] + totals['fixed-short']} fixed, {totals['variable']} variable, "
          f"{totals['spin']} spin, {totals['waived']} waived); {total_fl} fastlib calls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
