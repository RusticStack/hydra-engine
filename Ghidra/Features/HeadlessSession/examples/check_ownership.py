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

* a wave cell of the matrix names two packages (the disjointness assertion) unless the cell is the
  declared in-wave sequence ``A **then** B`` (revision 8.1, amendment A2: ``S/HeadlessSession.java``
  E5 then E9, ``S/Advertised.java`` E1 then E2a), or names a package the wave plan does not put in
  that wave, or the plan puts one package in two waves;
* with ``--package``: a file changed on the branch (``git diff --name-only`` of ``<base>...HEAD``,
  plus the working tree and untracked files unless ``--committed-only``) is not in that package's
  rows of the matrix.

Besides its matrix rows a package may change, without a row (8.1: "Tests: ``dt_*``, ``char_*`` and
``cc_*`` files, vectors and fixtures belong to the package whose name they carry and appear in its
package text"): its own ``examples/dt_<id>.py``, ``examples/char_<id>.py`` and
``examples/cc_<id>.py``, and the goldens its ``char_<id>.py`` records, which carry the id
(``examples/characterization/v3/<id>-<scenario>.json``, section 8 rule 2); the test and fixture paths its own package paragraph in section 8 names in
backticks, and only these three kinds: ``examples/(dt|char|cc)_*.py`` (Hydra), ``characterization/v3/**``
(Hydra, also written ``examples/characterization/v3/...``) and ``tests/**``; and
``certification.manifest``, which every package appends to (the one stated exception). Any other
path the paragraph names (another example or tool, the v2 goldens in ``characterization/``, a
source file) is not accepted by being named: it must be a row of the matrix. A file that is a row of
the matrix is changed only by the packages of its cells, whatever the package text says.
The spec itself is not a package file: nobody edits it.

Hydra paths are relative to ``Ghidra/Features/HeadlessSession`` (``S/`` is the session source
directory), Hydralysis paths to ``src/hydralysis`` (the root documents ``README.md``, ``THIRD_PARTY.md``,
``CHANGELOG.md``, ``config.example.json``, and ``tests/``, ``tools/``, ``docs/``, ``skills/``,
``benchmarks/`` and ``.github/`` to the repository root, amendment A1), site paths to the root of the website repository. The package ids are every id the wave plan
of revision 8 uses: ``E<n>[a-c]``, ``X0``, ``P1a``/``P1b``, ``Y0a-e``, ``Y1``-``Y3``, ``Y4a/b/d/e``, ``Y5``, ``R0``/``R1``, ``S1``/``S2``
and ``Z<n>[ab]`` (revision 8.1, amendment A2: the pattern did not see ``X0``, ``S1``, ``S2`` or any ``Z``).
``--repo`` is the worktree to check (default: this script's repository); it is Hydralysis
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
#: The package ids of the plan of revision 8 (52): E0-E12 with E2a/E3a-c, X0, P1a/P1b, Y0a-e, Y1-Y3,
#: Y4a/b/d/e, Y5, R0/R1, S1/S2, Z1-Z15 with Z13a/b. Amendment A2 of revision 8.1: the pattern was
#: ``[EPYR]\d+[a-e]?``, which cannot see X0, S1, S2 or any Z package.
ID = r"(?:E\d+[a-c]?|X0|P1[ab]|Y(?:0[a-e]|[1235]|4[abde])|R[01]|S[12]|Z\d+[ab]?)"
PKG = re.compile(r"\b" + ID + r"\b")
#: Anything that looks like a package id in the wave plan (a letter, digits, an optional letter):
#: ``parse_spec`` fails when ``PKG`` does not see every one of them, so that an id such as ``Y0e``
#: or ``Y4e`` can never again be invisible to the checker (it was, with ``[a-d]``).
ANY_ID = re.compile(r"\b[A-Z]\d+[a-z]?\b")
THEN = "**then**"
HEADER = re.compile(r"\*\*(" + ID + r") \(")
ROOT_DOCS = {"README.md", "CHANGELOG.md"}
#: The Hydralysis repository-root documents and trees (amendment A1/E1's first commit, 8.1): rows of
#: the Hydralysis table that live at the repository root, not under ``src/hydralysis/``.
HY_ROOT_FILES = {"README.md", "THIRD_PARTY.md", "CHANGELOG.md", "LICENSE", "config.example.json",
                 "pyproject.toml", ".gitignore"}
HY_ROOT_DIRS = ("tests/", "tools/", "docs/", "skills/", "benchmarks/", ".github/")


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
    # the wave plan: | W0 ... | Hydra | Hydralysis | docs, site, policy | notes |
    for ln in section(lines, r"### Wave plan", r"#{2,3} "):
        if re.match(r"\|\s*W\d", ln):
            c = cells_of(ln)
            wave = re.match(r"W\d", c[0]).group(0)
            spec.plan[wave] = set(packages_in(" ".join(c[1:4])))
            seen = set(ANY_ID.findall(strip_parens(" ".join(c[1:4]))))
            if seen - spec.plan[wave]:
                raise SpecError(f"wave plan {wave}: the package id(s) "
                                f"{', '.join(sorted(seen - spec.plan[wave]))} are not parsed by PKG")
    if not spec.plan:
        raise SpecError("the wave plan table has no rows")
    # the matrix: two tables, each after its bold title
    kind, waves = None, None
    for ln in section(lines, r"### 8\.1 ", r"### "):
        if ln.startswith("**Hydralysis"):
            kind, waves = "hydralysis", None
        elif ln.startswith("**Site"):
            kind, waves = "site", None
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
        m = HEADER.match(ln)
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
    if kind == "site":
        return {tok}
    if kind == "hydralysis":
        if tok in HY_ROOT_FILES or tok.startswith(HY_ROOT_DIRS):
            return {tok}      # README.md, THIRD_PARTY.md, docs/..., config.example.json: the root
        return {"src/hydralysis/" + tok}
    if tok == "release workflow":
        return {".github/workflows/release.yml"}
    if tok.startswith("/"):
        return {tok[1:]}      # a repository-root path (the Ghidra core, /NOTICE-HYDRA, /README.md, .github)
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
            # a cell may be a declared sequence ``A **then** B`` (each part names one package)
            pk = []
            for part in cell.split(THEN):
                one = packages_in(part)
                if len(one) > 1:
                    bad.append(f"matrix: {name} in {w} names {len(one)} packages: {', '.join(one)}")
                pk += one
            for p in pk:
                if wave_of.get(p) != w:
                    bad.append(f"matrix: {name} in {w} names {p}, which the plan puts in "
                               f"{wave_of.get(p)}")
    return bad


def ownership(spec, kind=None):
    """{repository-relative path: set of packages of its cells}, from the rows of ``kind``'s table
    (all tables when None). The tables are per repository: a root path such as ``README.md`` or
    ``.github/workflows/release.yml`` is a different file in the Hydra and in the Hydralysis
    repository, so a row of one table never owns a file of the other (8.14, `w2/GATE6`)."""
    owners = {}
    for k, files, cells in spec.rows:
        if kind is not None and k != kind:
            continue
        pk = {p for cell in cells.values() for p in packages_in(cell)}
        for tok in files:
            for path in resolve(k, tok):
                owners.setdefault(path, set()).update(pk)
    return owners


TEST_FILE = re.compile(r"examples/(dt|char|cc)_[A-Za-z0-9_]+\.py")


def accepted_text_token(kind, t):
    """The repository-relative form (inside the module for Hydra) of a backticked path of a package
    paragraph when it is one of the three kinds the paragraph may name without a matrix row, else
    None: ``examples/(dt|char|cc)_*.py`` (Hydra), ``characterization/v3/**`` (Hydra; also written
    ``examples/characterization/v3/...``) and ``tests/**``. Anything else it names (another example
    or tool, the v2 goldens, a Java file) must be a row of the matrix."""
    if ".." in t.split("/"):
        return None
    if kind == "hydra":
        t = re.sub(r"^examples/(?=characterization/)", "", t)
        if TEST_FILE.fullmatch(t):
            return t
        if t.startswith("characterization/v3/"):
            return "examples/" + t
    return t if kind != "site" and t.startswith("tests/") else None


def package_text_files(spec, kind, pkg):
    """(files, directory prefixes) the package's own paragraph names as test and fixture files
    (see ``accepted_text_token``); every other path it names is left to the matrix rows."""
    files, dirs = set(), set()
    for tok in re.findall(r"`([^`]+)`", spec.text.get(pkg, "")):
        if re.search(r"[\s*<>(){}]", tok):
            continue
        t = accepted_text_token(kind, re.sub(r":\d+(-\d+)?$", "", tok))
        if t is None:
            continue
        for path in resolve(kind, t):
            (dirs if path.endswith("/") else files).add(path)
    return files, dirs


def check_changes(spec, kind, pkg, changed):
    """Violations among the repository-relative ``changed`` paths of package ``pkg``."""
    if pkg not in {p for ps in spec.plan.values() for p in ps}:
        return [f"{pkg} is not a package of the wave plan"]
    owners = ownership(spec, kind)
    tfiles, tdirs = package_text_files(spec, kind, pkg)
    own_test = re.compile(rf"{re.escape(MODULE)}/examples/(dt|char|cc)_{pkg.lower()}\.py")
    # rule 2 of section 8: the goldens a package's char_<id>.py records carry the package id
    own_golden = re.compile(
        rf"{re.escape(MODULE)}/examples/characterization/v3/{pkg.lower()}-[A-Za-z0-9_.-]+\.json")
    # a row that names a directory (``examples/conc/``) owns every file under it, except the directory
    # of the v3 goldens, which rule 2 gives to the package whose id the file name carries
    v3 = MODULE + "/examples/characterization/v3/"
    dir_rows = {d: o for d, o in owners.items() if d.endswith("/") and not d.startswith(v3)}
    bad = []
    for path in changed:
        if path.endswith("certification.manifest"):
            continue
        if path in owners:
            if pkg not in owners[path]:
                bad.append(f"{path}: a row of 8.1 owned by {', '.join(sorted(owners[path])) or 'nobody'}, "
                           f"not {pkg}")
            continue
        under = [d for d in dir_rows if path.startswith(d)]
        if under:
            who = set().union(*(dir_rows[d] for d in under))
            if pkg not in who:
                bad.append(f"{path}: under a directory row of 8.1 owned by {', '.join(sorted(who))}, "
                           f"not {pkg}")
            continue
        if kind == "hydra" and (own_test.fullmatch(path) or own_golden.fullmatch(path)):
            continue
        if path in tfiles or any(path.startswith(d) for d in tdirs):
            continue
        bad.append(f"{path}: in no row of 8.1 for {pkg} and not an examples/(dt|char|cc)_*.py, "
                   "characterization/v3/** or tests/** path its package text names")
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
| **`examples/conc/`** | E0 | |
| `/NOTICE-HYDRA` | | E1 |
| `examples/characterization/v3/` | E0 | |

**Hydralysis (`src/hydralysis`, `tests/`)**

| File | W0 | W1 |
|---|---|---|
| **`durable.py`** | Y0a | |
| `README.md`, `THIRD_PARTY.md` | Y0a | |
| `docs/upstream-setup.md` | | E1 |
| `config.example.json` | | E1 |

## 8. Work packages

### W0

**E0 (Hydra, M): tests.** Files: `examples/runner.py`, new `examples/dt_base.py`, goldens `characterization/v3/`.
Also named: `examples/helper.py`, `examples/dt_named.py`, `characterization/old.json`, `tests/t.py`,
`examples/characterization/v3/deep/`, `characterization/v3/../old.json`, `examples/dt_a/b.py`.

**Y0a (Hydralysis, M): durable.** Files: new `durable.py`, new `tests/test_durable.py`, `tests/data/`,
`examples/dt_y.py`, `hydra.py`.

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
    expect("Hydralysis root documents resolve to the repository root",
           [sorted(resolve("hydralysis", t)) for t in
            ("README.md", "THIRD_PARTY.md", "docs/upstream-setup.md", "config.example.json",
             "skills/hydralysis/SKILL.md", ".github/workflows/release.yml", "tools/x.py",
             "durable.py", "scripts/RusticQuery.java", "config.py")],
           [["README.md"], ["THIRD_PARTY.md"], ["docs/upstream-setup.md"], ["config.example.json"],
            ["skills/hydralysis/SKILL.md"], [".github/workflows/release.yml"], ["tools/x.py"],
            ["src/hydralysis/durable.py"], ["src/hydralysis/scripts/RusticQuery.java"],
            ["src/hydralysis/config.py"]])
    expect("the Hydra table keeps README.md at the module and the root",
           sorted(resolve("hydra", "README.md")), sorted({"README.md", MODULE + "/README.md"}))
    expect("Y0a changes the root README.md and docs/ row of E1: only the first is its row",
           check_changes(spec, "hydralysis", "Y0a", ["README.md", "THIRD_PARTY.md"]) == []
           and len(check_changes(spec, "hydralysis", "Y0a", ["docs/upstream-setup.md"])) == 1, True)
    expect("a row of one repository's table never owns a file of the other (README.md is a root "
           "document of both)",
           [len(check_changes(spec, "hydra", "E1", ["README.md"])),
            len(check_changes(spec, "hydralysis", "E1", ["README.md"])),
            len(check_changes(spec, "hydralysis", "Y0a", ["README.md"])),
            len(check_changes(spec, "hydra", "Y0a", ["README.md"]))], [0, 1, 0, 1])
    expect("a root config.example.json is E1's, src/hydralysis/README.md is in no row",
           len(check_changes(spec, "hydralysis", "Y0a", ["config.example.json",
                                                         "src/hydralysis/README.md"])), 2)
    expect("an unknown package", len(check_changes(spec, "hydra", "E9", ["x"])), 1)
    E = MODULE + "/"
    expect("E0 changes a named dt_*.py and a named v3 directory's file",
           check_changes(spec, "hydra", "E0", [E + "examples/dt_named.py",
                                               E + "examples/characterization/v3/deep/a.json"]), [])
    expect("E0 changes an examples/ file its paragraph names that is not dt|char|cc_*.py",
           len(check_changes(spec, "hydra", "E0", [E + "examples/helper.py"])), 1)
    expect("E0 changes a v2 golden its paragraph names (characterization/ outside v3/)",
           len(check_changes(spec, "hydra", "E0", [E + "examples/characterization/old.json"])), 1)
    expect("E0 changes a dt_*.py its paragraph does not name",
           len(check_changes(spec, "hydra", "E0", [E + "examples/dt_unnamed.py"])), 1)
    expect("E0 changes a tests/ file its paragraph names",
           check_changes(spec, "hydra", "E0", [E + "tests/t.py"]), [])
    expect("a '..' path or a nested name in the paragraph accepts nothing",
           len(check_changes(spec, "hydra", "E0", [E + "examples/characterization/old.json",
                                                   E + "examples/dt_a/b.py"])), 2)
    expect("Y0a changes tests/ under a named directory",
           check_changes(spec, "hydralysis", "Y0a", ["tests/data/x.bin"]), [])
    expect("Y0a: a named examples/dt_y.py or a named non-tests file is not accepted",
           len(check_changes(spec, "hydralysis", "Y0a", ["src/hydralysis/examples/dt_y.py",
                                                         "src/hydralysis/hydra.py"])), 2)
    expect("accepted_text_token: the three kinds only",
           [accepted_text_token("hydra", t) for t in
            ("examples/dt_x.py", "examples/char_x.py", "examples/cc_x.py", "examples/x.py",
             "characterization/v3/", "examples/characterization/v3/a.json", "characterization/",
             "characterization/v3/../a", "tests/a/b.py", "S/Session.java")],
           ["examples/dt_x.py", "examples/char_x.py", "examples/cc_x.py", None,
            "examples/characterization/v3/", "examples/characterization/v3/a.json", None, None,
            "tests/a/b.py", None])
    expect("E1 changes its own v3 goldens (the <id>- prefix of rule 2), not another package's or an unprefixed one",
           [len(check_changes(spec, "hydra", "E1", [E + "examples/characterization/v3/" + n]))
            for n in ("e1-hello.json", "e1-expect_conflicts.json", "e0-hello.json", "session.json",
                      "e10-x.json", "e1x.json", "sub/e1-a.json")], [0, 0, 1, 1, 1, 1, 1])
    expect("a directory row owns the files under it (examples/conc/), for its package only",
           [len(check_changes(spec, "hydra", p, [E + "examples/conc/a/b.py"])) for p in ("E0", "E1")], [0, 1])
    expect("a root path of the Hydra table (/NOTICE-HYDRA) resolves to the repository root",
           [len(check_changes(spec, "hydra", p, ["NOTICE-HYDRA"])) for p in ("E1", "E0")], [0, 1])
    expect("the v3 directory row (E0's) grants E1 nothing: a golden follows rule 2 (its id prefix)",
           [len(check_changes(spec, "hydra", "E1", [E + "examples/characterization/v3/" + n]))
            for n in ("e1-x.json", "e0-x.json")], [0, 1])
    plan = SYNTHETIC.replace("| W1 second | E1 | | n |", "| W1 second | E1 | Y0e | n |").replace(
        "| W0 first | E0 | Y0a | n |", "| W0 first | E0 | Y0a, Y4e | n |")
    expect("the ids Y0e and Y4e are seen (they were not with [a-d])",
           sorted(parse_spec(plan).plan["W1"]) == ["E1", "Y0e"] and
           sorted(parse_spec(plan).plan["W0"]) == ["E0", "Y0a", "Y4e"], True)
    try:
        parse_spec(SYNTHETIC.replace("| W1 second | E1 | | n |", "| W1 second | E1 | Y0f | n |"))
        expect("a plan id that PKG cannot see is an error, not a silent omission", False, True)
    except SpecError:
        expect("a plan id that PKG cannot see is an error, not a silent omission", True, True)
    # amendment A2 (revision 8.1): every id of the plan of revision 8 is seen, and the real spec parses
    rev8_ids = ("E0 E1 E2 E2a E3a E3b E3c E4 E5 E6 E7 E8 E9 E10 E11 E12 X0 P1a P1b Y0a Y0b Y0c Y0d Y0e "
                "Y1 Y2 Y3 Y4a Y4b Y4d Y4e Y5 R0 R1 S1 S2 Z1 Z2 Z3 Z4 Z5 Z6 Z7 Z8 Z9 Z10 Z11 Z12 Z13a "
                "Z13b Z14 Z15").split()
    expect("PKG sees all 52 package ids of the plan of revision 8 (X0, S1, S2, Z.. included)",
           [i for i in rev8_ids if not PKG.fullmatch(i)] + [len(rev8_ids)], [52])
    expect("PKG does not see ids that are not packages",
           [i for i in ("Y0f", "Y4c", "D60", "E13x", "Z", "W1", "X1", "S3", "R2", "P2a") if PKG.fullmatch(i)], [])
    allids = SYNTHETIC.replace("| W0 first | E0 | Y0a | n |", "| W0 first | E0, X0 | Y0a, Z13a | R0, S1 | n |"
                               ).replace("| Wave | Hydra (engine) | Hydralysis | Notes |\n|---|---|---|---|",
                                         "| Wave | Hydra (engine) | Hydralysis | Docs | Notes |\n|---|---|---|---|---|"
                                         ).replace("| W1 second | E1 | | n |", "| W1 second | E1 | | S2 | n |")
    sp = parse_spec(allids)
    expect("the plan parses X0, Z13a, R0, S1 and S2 (the docs column is read)",
           sorted(sp.plan["W0"]) == ["E0", "R0", "S1", "X0", "Y0a", "Z13a"] and sorted(sp.plan["W1"]) == ["E1", "S2"], True)
    hdr = parse_spec(SYNTHETIC.replace("**E0 (Hydra, M): tests.**", "**X0 (Hydra, L): oracle.**"
                                       ).replace("**Y0a (Hydralysis, M): durable.**", "**Z13a (Hydralysis, S): claims.**"))
    expect("a package paragraph of X0 and of Z13a is found by its header",
           sorted(hdr.text) == ["X0", "Z13a"], True)
    seq = parse_spec(SYNTHETIC.replace("| W1 second | E1 | | n |", "| W1 second | E1, E2a | | n |"
                                                 ).replace("| `README.md` | | E1 |", "| `README.md` | | E1 (x) **then** E2a (y) |"))
    expect("a declared sequence A **then** B in one cell is not a violation", check_matrix(seq), [])
    expect("a cell with two packages and no then is still a violation",
           len(check_matrix(parse_spec(SYNTHETIC.replace("| `README.md` | | E1 |", "| `README.md` | | E1, E2a |"
                                                         ).replace("| W1 second | E1 | | n |", "| W1 second | E1, E2a | | n |")))), 1)
    expect("a sequence part that names a package of another wave is a violation",
           len(check_matrix(parse_spec(SYNTHETIC.replace("| `README.md` | | E1 |", "| `README.md` | | E1 **then** E0 |")))), 1)
    site = parse_spec(SYNTHETIC.replace("## 8. Work packages", "**Site (`F:/site`)**\n\n| File | W0 | W1 |\n|---|---|---|\n"
                                        "| `src/routes/embed/how-it-works.tsx` | E0 | E1 |\n\n## 8. Work packages"))
    expect("a site row is read as a site path (its own repository root)",
           check_changes(site, "site", "E0", ["src/routes/embed/how-it-works.tsx"]), [])
    spec_path = HERE.parent / "PROTOCOL-3.md"
    if spec_path.is_file():
        try:
            real = parse_spec(spec_path.read_text(encoding="utf-8"))
            expect("the spec next to this script parses and its matrix names no wave twice",
                   (len(real.rows) > 100, check_matrix(real)), (True, []))
        except SpecError as e:
            expect("the spec next to this script parses", str(e), "")
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
    ap.add_argument("--kind", choices=("hydra", "hydralysis", "site"), help="the repository's table")
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
