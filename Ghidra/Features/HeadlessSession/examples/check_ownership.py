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
"""The file-ownership assertion of PROTOCOL-3.md, section 8.1. Standard library only; any OS.

    python check_ownership.py                          # the matrix itself
    python check_ownership.py --package E0 --base design/protocol-3 [--repo <worktree>]
    python check_ownership.py --selftest               # the checker against synthetic matrices

It reads the matrix and the wave plan from the spec (``../PROTOCOL-3.md``, or ``--spec``) and fails
(exit 1, every violation named) when

* a wave cell of the matrix names two packages (the disjointness assertion), or names a package the
  wave plan does not put in that wave, or the plan puts one package in two waves;
* with ``--package``: a file changed on the branch (``git diff --name-only`` of ``<base>...HEAD``,
  plus the working tree and untracked files unless ``--committed-only``) is not in that package's
  rows of the matrix.

Besides its matrix rows a package may change, without a row (8.1: "Tests: ``dt_*``, ``char_*`` and
``cc_*`` files, vectors and fixtures belong to the package whose name they carry and appear in its
package text"): its own ``examples/dt_<id>.py``, ``examples/char_<id>.py`` and
``examples/cc_<id>.py``; the test and fixture files, and directories, its package text in section 8
names (a backticked path under ``examples/``, ``tests/`` or ``characterization/``); and
``certification.manifest``, which every package appends to (the one stated exception). A file that
is a row of the matrix is changed only by the packages of its cells, whatever the package text says.
The spec itself is not a package file: nobody edits it.

Hydra paths are relative to ``Ghidra/Features/HeadlessSession`` (``S/`` is the session source
directory), Hydralysis paths to ``src/hydralysis`` (``tests/`` and ``tools/`` to the repository
root). ``--repo`` is the worktree to check (default: this script's repository); it is Hydralysis
when it has ``src/hydralysis``. Exit codes: 0 holds, 1 violated, 2 usage or an unreadable spec.
"""
import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
MODULE = "Ghidra/Features/HeadlessSession"
SESSION = MODULE + "/src/main/java/ghidra/app/util/headless/session/"
PKG = re.compile(r"\b[EPYR]\d+[a-d]?\b")
ROOT_DOCS = {"README.md", "CHANGELOG.md"}


class SpecError(Exception):
    pass


def strip_parens(s):
    out, depth = [], 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def packages_in(cell):
    """The package ids a cell names (what is in parentheses is explanation, not ownership)."""
    return sorted(set(PKG.findall(strip_parens(cell))))


def cells_of(line):
    line = line.strip()
    return [c.strip() for c in line.strip("|").split("|")]


def is_rule(line):
    return bool(re.fullmatch(r"\|?[\s|:-]+\|?", line.strip())) and "-" in line


def section(lines, start, stop):
    """The lines from the heading matching ``start`` up to the next heading matching ``stop``."""
    out, on = [], False
    for ln in lines:
        if not on:
            on = bool(re.match(start, ln))
            continue
        if re.match(stop, ln):
            break
        out.append(ln)
    if not on:
        raise SpecError(f"no heading matching {start!r}")
    return out


class Spec:
    def __init__(self):
        self.plan = {}      # wave -> set of package ids
        self.rows = []      # (kind, [file tokens], {wave: cell text})
        self.text = {}      # package id -> its section-8 paragraph


def parse_spec(text):
    lines = text.splitlines()
    spec = Spec()
    # the wave plan: | W0 ... | Hydra packages | Hydralysis packages | notes |
    for ln in section(lines, r"### Wave plan", r"#{2,3} "):
        if re.match(r"\|\s*W\d", ln):
            c = cells_of(ln)
            wave = re.match(r"W\d", c[0]).group(0)
            spec.plan[wave] = set(packages_in(c[1]) + packages_in(c[2]))
    if not spec.plan:
        raise SpecError("the wave plan table has no rows")
    # the matrix: two tables, each after its bold title
    kind, waves = None, None
    for ln in section(lines, r"### 8\.1 ", r"### "):
        if ln.startswith("**Hydralysis"):
            kind, waves = "hydralysis", None
        elif ln.startswith("**Hydra"):
            kind, waves = "hydra", None
        elif ln.startswith("|") and kind:
            c = cells_of(ln)
            if c[0] == "File":
                waves = c[1:]
            elif waves and not is_rule(ln):
                files = re.findall(r"`([^`]+)`", c[0])
                if "release workflow" in c[0]:
                    files.append("release workflow")
                spec.rows.append((kind, files, dict(zip(waves, c[1:]))))
    if not spec.rows:
        raise SpecError("the 8.1 matrix has no rows")
    # the package paragraphs of section 8
    cur = None
    for ln in section(lines, r"## 8\. ", r"## 9\. "):
        m = re.match(r"\*\*([EPYR]\d+[a-d]?) \(", ln)
        if m:
            cur = m.group(1)
            spec.text[cur] = []
        elif re.match(r"#{2,4} |---", ln):
            cur = None
        if cur:
            spec.text[cur].append(ln)
    spec.text = {k: "\n".join(v) for k, v in spec.text.items()}
    return spec


def resolve(kind, tok):
    """The repository-relative paths a matrix or package-text token may mean."""
    tok = re.sub(r":\d+(-\d+)?$", "", tok.strip())
    if kind == "hydralysis":
        if tok.startswith(("tests/", "tools/")):
            return {tok}
        return {"src/hydralysis/" + tok}
    if tok == "release workflow":
        return {".github/workflows/release.yml"}
    if tok.startswith("S/"):
        return {SESSION + tok[2:]}
    out = {MODULE + "/" + tok}
    if tok in ROOT_DOCS:
        out.add(tok)
    return out


def check_matrix(spec):
    """Violations of the assertion in the matrix itself."""
    bad = []
    wave_of = {}
    for w, pkgs in spec.plan.items():
        for p in pkgs:
            if p in wave_of:
                bad.append(f"plan: {p} is in both {wave_of[p]} and {w}")
            wave_of[p] = w
    for kind, files, cells in spec.rows:
        name = ", ".join(files)
        for w, cell in cells.items():
            pk = packages_in(cell)
            if len(pk) > 1:
                bad.append(f"matrix: {name} in {w} names {len(pk)} packages: {', '.join(pk)}")
            for p in pk:
                if wave_of.get(p) != w:
                    bad.append(f"matrix: {name} in {w} names {p}, which the plan puts in "
                               f"{wave_of.get(p)}")
    return bad


def ownership(spec):
    """{repository-relative path: set of packages of its cells}."""
    owners = {}
    for kind, files, cells in spec.rows:
        pk = {p for cell in cells.values() for p in packages_in(cell)}
        for tok in files:
            for path in resolve(kind, tok):
                owners.setdefault(path, set()).update(pk)
    return owners


def package_text_files(spec, kind, pkg):
    """(files, directory prefixes) the package's own paragraph names under examples/, tests/ or
    characterization/ (test and fixture files)."""
    files, dirs = set(), set()
    for tok in re.findall(r"`([^`]+)`", spec.text.get(pkg, "")):
        if re.search(r"[\s*<>(){}]", tok):
            continue
        t = re.sub(r":\d+(-\d+)?$", "", tok)
        if not t.startswith(("examples/", "tests/", "characterization/")):
            continue
        if kind == "hydra" and t.startswith("characterization/"):
            t = "examples/" + t
        for path in resolve(kind, t):
            (dirs if path.endswith("/") else files).add(path)
    return files, dirs


def check_changes(spec, kind, pkg, changed):
    """Violations among the repository-relative ``changed`` paths of package ``pkg``."""
    if pkg not in {p for ps in spec.plan.values() for p in ps}:
        return [f"{pkg} is not a package of the wave plan"]
    owners = ownership(spec)
    tfiles, tdirs = package_text_files(spec, kind, pkg)
    own_test = re.compile(rf"{re.escape(MODULE)}/examples/(dt|char|cc)_{pkg.lower()}\.py")
    bad = []
    for path in changed:
        if path.endswith("certification.manifest"):
            continue
        if path in owners:
            if pkg not in owners[path]:
                bad.append(f"{path}: a row of 8.1 owned by {', '.join(sorted(owners[path])) or 'nobody'}, "
                           f"not {pkg}")
            continue
        if kind == "hydra" and own_test.fullmatch(path):
            continue
        if path in tfiles or any(path.startswith(d) for d in tdirs):
            continue
        bad.append(f"{path}: in no row of 8.1 for {pkg} and not a test or fixture file its "
                   "package text names")
    return bad


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       encoding="utf-8")
    if r.returncode:
        raise SpecError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return [x for x in r.stdout.splitlines() if x.strip()]


def changed_files(repo, base, committed_only):
    files = set(git(repo, "diff", "--name-only", "--no-renames", f"{base}...HEAD"))
    if not committed_only:
        files |= set(git(repo, "diff", "--name-only", "--no-renames", "HEAD"))
        files |= set(git(repo, "ls-files", "--others", "--exclude-standard"))
    return sorted(files)


# ---- self-test ------------------------------------------------------------------------------

SYNTHETIC = """
### Wave plan (compact)

| Wave | Hydra (engine) | Hydralysis | Notes |
|---|---|---|---|
| W0 first | E0 | Y0a | n |
| W1 second | E1 | | n |

### 8.1 File-ownership matrix (the disjointness assertion)

**Hydra (engine repo)**

| File | W0 | W1 |
|---|---|---|
| `S/Session.java` | | E1 (hello) |
| `examples/runner.py`, **`examples/check.py`** | E0 | |
| `S/Both.java` | E0 | E1 |
| `README.md` | | E1 |

**Hydralysis (`src/hydralysis`, `tests/`)**

| File | W0 | W1 |
|---|---|---|
| **`durable.py`** | Y0a | |

## 8. Work packages

### W0

**E0 (Hydra, M): tests.** Files: `examples/runner.py`, new `examples/dt_base.py`, goldens `characterization/v3/`.

**Y0a (Hydralysis, M): durable.** Files: new `durable.py`, new `tests/test_durable.py`.

## 9. Release gates
"""


def selftest():
    spec = parse_spec(SYNTHETIC)
    ok = True

    def expect(what, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print(("ok   " if good else "FAIL ") + what + ("" if good else f": got {got}, want {want}"))

    expect("a clean matrix has no violation", check_matrix(spec), [])
    expect("E0 changes its rows and its test files",
           check_changes(spec, "hydra", "E0", [
               MODULE + "/examples/runner.py", MODULE + "/examples/check.py",
               MODULE + "/examples/dt_base.py", MODULE + "/examples/dt_e0.py",
               MODULE + "/examples/characterization/v3/x.json",
               MODULE + "/certification.manifest"]), [])
    expect("E0 changes another package's row",
           len(check_changes(spec, "hydra", "E0", [SESSION + "Session.java"])), 1)
    expect("E0 changes a file in no row",
           len(check_changes(spec, "hydra", "E0", [MODULE + "/examples/other.py"])), 1)
    expect("E0 changes another package's test file",
           len(check_changes(spec, "hydra", "E0", [MODULE + "/examples/dt_e1.py"])), 1)
    expect("a root README is E1's",
           len(check_changes(spec, "hydra", "E0", ["README.md"])), 1)
    expect("Y0a changes its rows and test",
           check_changes(spec, "hydralysis", "Y0a", ["src/hydralysis/durable.py",
                                                      "tests/test_durable.py"]), [])
    expect("Y0a changes a file in no row",
           len(check_changes(spec, "hydralysis", "Y0a", ["src/hydralysis/hydra.py"])), 1)
    expect("an unknown package", len(check_changes(spec, "hydra", "E9", ["x"])), 1)
    two = parse_spec(SYNTHETIC.replace("| `S/Session.java` | | E1 (hello) |",
                                       "| `S/Session.java` | E0, Y0a | E1 (hello) |"))
    expect("a cell with two packages fails", len(check_matrix(two)), 1)
    misplaced = parse_spec(SYNTHETIC.replace("| `S/Session.java` | | E1 (hello) |",
                                             "| `S/Session.java` | E1 | |"))
    expect("a package in a wave the plan does not give it fails", len(check_matrix(misplaced)), 1)
    twice = parse_spec(SYNTHETIC.replace("| W1 second | E1 | | n |", "| W1 second | E1, E0 | | n |"))
    expect("a package in two plan waves fails",
           any(v.startswith("plan:") for v in check_matrix(twice)), True)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--spec", default=str(HERE.parent / "PROTOCOL-3.md"))
    ap.add_argument("--package", help="a package id (E0, Y0a, ...): also check its branch")
    ap.add_argument("--base", help="the branch point of the package branch (a revision)")
    ap.add_argument("--repo", help="the worktree to check (default: this script's repository)")
    ap.add_argument("--kind", choices=("hydra", "hydralysis"), help="the repository's table")
    ap.add_argument("--committed-only", dest="committed_only", action="store_true",
                    help="ignore uncommitted and untracked files")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if bool(a.package) != bool(a.base):
        ap.error("--package and --base go together")
    try:
        spec = parse_spec(pathlib.Path(a.spec).read_text(encoding="utf-8"))
        bad = check_matrix(spec)
        n_rows = len(spec.rows)
        print(f"matrix: {n_rows} rows, {sum(len(p) for p in spec.plan.values())} packages in "
              f"{len(spec.plan)} waves, {len(bad)} violation(s)")
        if a.package:
            repo = pathlib.Path(a.repo).resolve() if a.repo else HERE
            kind = a.kind or ("hydralysis" if (repo / "src" / "hydralysis").is_dir() else "hydra")
            top = pathlib.Path(git(repo, "rev-parse", "--show-toplevel")[0])
            changed = changed_files(top, a.base, a.committed_only)
            more = check_changes(spec, kind, a.package, changed)
            print(f"{a.package} ({kind}, {top}): {len(changed)} changed file(s) against {a.base}, "
                  f"{len(more)} outside its rows")
            bad += more
    except (SpecError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for b in bad:
        print("VIOLATION " + b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
