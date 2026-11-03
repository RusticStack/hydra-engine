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
"""Fast standalone IP/licence certification check for the Hydra engine.

Reproduces the checks of gradle/support/ip.gradle and
gradle/support/moduleManifest.gradle without starting Gradle, so a bad
header, a missing certification.manifest entry or a Module.manifest licence
name fails in seconds instead of in the release build.

For every module directory (a directory holding a Module.manifest):
  * every file in the module tree (Gradle's exclude list applied, relative to
    the module) must carry an IP, from its header (first 4 lines) or from a
    matching certification.manifest entry, and that IP must be allowed;
  * every "MODULE FILE INFO:" entry in Module.manifest must be well formed and
    its licence must be allowed.

Allowed IPs are the file stems of the licenses/ directories next to the root
(the root's parent holds the sibling checkouts), plus the fixed names Gradle
adds. Modules under a GPL/ path use Gradle's hard-coded GPL set instead.

Only checks Gradle's file-level IP rules. Checks that need resolved Gradle
configurations (external jar and wheel entries) are not reproduced here; the
Gradle ip task still covers them.

Usage:
  python tools/ip_check.py                       full check of the repo
  python tools/ip_check.py --changed-since main  fast path: changed files only
  python tools/ip_check.py --module HydraNative  one module (name or path tail)

Exit status: 0 pass, 1 violations found, 2 usage or environment error.
Violations are printed as: module | file | reason
"""

import argparse
import os
import re
import subprocess
import sys

MODULE_MANIFEST = "Module.manifest"
CERT = "certification.manifest"
FILE_INFO = "MODULE FILE INFO:"

# Gradle's exclude list (ip.gradle getIpForModule), relative to the module root.
EXCLUDES = [
    "bin/**", "**/build/**", "certification.manifest", "certification.local.manifest",
    "**/.project", "**/.classpath", "**/.pydevproject", "Module.manifest", "build.gradle",
    "buildNatives.gradle", "**/Misc/Tips.htm", "**/*.sla", "**/*.sla.lock", "**/.gradle/**",
    "**/.settings/**", "**/data/build.xml", "**/.vs/**", "**/*.vcxproj.user",
    "**/__pycache__", "**/*.egg-info",
]

# Gradle's hard-coded allowed set for GPL modules (ip.gradle getAllowedIP).
GPL_IPS = {"GPL_3", "GPL_3_Linking_Permitted", "GPL_2_With_Classpath_Exception",
           "Public_Domain", "LGPL_3.0", "LGPL_2.1"}
# Allowed for every module (ip.gradle getAllowedIP).
COMMON_IPS = {"GHIDRA", "LICENSE", "Copyright_Distribution_Permitted"}

# Extension tables (ip.gradle isCSourceFile / isBashSourceFile / isBatchSourceFile).
C_EXT = (".java", ".c", ".gradle", ".gradle.kts", ".groovy", ".cpp", ".cc", ".h", ".y",
         ".l", ".hh", ".css", ".jj", ".proto", ".rs")
BASH_EXT = (".py", ".sh", ".ps1", ".bash", ".command", ".toml", ".md")
BAT_EXT = (".bat",)

# Java String.trim() removes every char <= U+0020.
JAVA_TRIM = "".join(chr(c) for c in range(0x21))
# Java String.split("\\s+", n) whitespace (ASCII only).
JAVA_WS = re.compile(r"[ \t\n\x0b\f\r]+")
HASH_RE = re.compile(r"[0-9a-f]{64}")


def ant_to_regex(pattern):
    """Translates an Ant-style pattern (as Gradle's fileTree uses) to a regex."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


EXCLUDE_RES = [ant_to_regex(p) for p in EXCLUDES]


def excluded(rel):
    """True if a module-relative path (or directory path) is excluded by Gradle's list."""
    return any(rx.fullmatch(rel) for rx in EXCLUDE_RES)


def excluded_path(rel):
    """True if the path or any of its parent directories is excluded (Gradle prunes them)."""
    parts = rel.split("/")
    return any(excluded("/".join(parts[:k])) for k in range(1, len(parts) + 1))


def java_trim(s):
    return s.strip(JAVA_TRIM)


def java_split_pipe(s):
    """Java String.split("\\\\|"): trailing empty fields are dropped when there is a match."""
    parts = s.split("|")
    if len(parts) > 1:
        while parts and parts[-1] == "":
            parts.pop()
    return parts


def ip_name(filename):
    """ip.gradle getIpName: strips the licence-file extension."""
    if filename.endswith(".txt"):
        filename = filename[:-4]
    if filename.endswith(".htm"):
        filename = filename[:-4]
    if filename.endswith(".html"):
        filename = filename[:-5]
    return filename


def rel_module(root, mdir):
    rel = os.path.relpath(mdir, root).replace(os.sep, "/")
    return "." if rel == "." else rel


def allowed_ips(root, mdir, cache):
    """ip.gradle getAllowedIP."""
    is_gpl = "/GPL/" in os.path.abspath(mdir).replace(os.sep, "/")
    key = "gpl" if is_gpl else "common"
    if key not in cache:
        if is_gpl:
            allowed = set(GPL_IPS)
        else:
            allowed = set()
            parent = os.path.dirname(os.path.abspath(root))
            for name in os.listdir(parent):
                lic = os.path.join(parent, name, "licenses")
                if os.path.isdir(lic):
                    allowed.update(ip_name(f) for f in os.listdir(lic))
        cache[key] = allowed | COMMON_IPS
    return cache[key]


def parse_module_info(mdir):
    """moduleManifest.gradle parseModuleFileInfo. Returns (entries, errors).

    entries maps path -> (path, hash, licence). errors lists malformed lines.
    """
    entries, errors = {}, []
    path = os.path.join(mdir, MODULE_MANIFEST)
    if not os.path.isfile(path):
        return entries, errors
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            if not line.startswith(FILE_INFO):
                continue
            parts = JAVA_WS.split(java_trim(line[len(FILE_INFO):]), maxsplit=2)
            if len(parts) != 3:
                errors.append("MODULE FILE INFO line is not '<path> <sha256> <licence>': " + line)
                continue
            p, h, lic = parts
            if h != "NO_HASH" and not HASH_RE.fullmatch(h):
                errors.append("MODULE FILE INFO %s has invalid sha256 '%s'" % (p, h))
            prev = entries.get(p)
            if prev is not None and prev != (p, h, lic):
                errors.append("MODULE FILE INFO %s is listed twice with different values" % p)
            entries[p] = (p, h, lic)
    return entries, errors


def parse_cert(mdir):
    """ip.gradle getIpForNonSourceFile input: list of split certification.manifest lines."""
    path = os.path.join(mdir, CERT)
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            rows.append(java_split_pipe(java_trim(raw.rstrip("\r\n"))))
    return rows


def cert_ip(abspath, rows):
    """Last matching certification.manifest entry wins, as in ip.gradle."""
    ip = None
    norm = abspath.replace(os.sep, "/")
    for parts in rows:
        if len(parts) > 2 and norm.endswith(parts[0]):
            ip = parts[2]
    return ip


def header_ip(abspath, prefix):
    """ip.gradle getIpForSourceFile: IP line within the first 4 lines."""
    with open(abspath, encoding="utf-8", errors="replace") as f:
        for _ in range(4):
            line = f.readline()
            if not line:
                break
            line = line.rstrip("\r\n")
            if line.startswith(prefix):
                return java_trim(line[len(prefix):])
    return None


def file_ip(abspath, rel, rows):
    """ip.gradle getIp: header first (by extension), then certification.manifest."""
    name = rel.rsplit("/", 1)[-1].lower()
    ip = None
    if name.endswith(C_EXT):
        ip = header_ip(abspath, " * IP:")
    elif name.endswith(BASH_EXT):
        ip = header_ip(abspath, "#  IP:")
        if ip is None:
            ip = header_ip(abspath, "# IP:")
    elif name.endswith(BAT_EXT):
        ip = header_ip(abspath, ":: IP:")
    if ip is None:
        ip = cert_ip(abspath, rows)
    return ip


def module_files(mdir):
    """Module-relative file paths in Gradle's fileTree(".") with the excludes applied.

    Excluded directories are pruned, as Gradle does.
    """
    found = []
    stack = [""]
    while stack:
        rel = stack.pop()
        absdir = os.path.join(mdir, rel) if rel else mdir
        with os.scandir(absdir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for e in entries:
            r = rel + "/" + e.name if rel else e.name
            if excluded(r):
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(r)
            elif e.is_file():
                found.append(r)
    return found


def discover_modules(root):
    """Every directory under root that holds a Module.manifest."""
    mods = []
    stack = [os.path.abspath(root)]
    prune = {".git", "build", ".gradle", ".vs", ".settings"}
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        if any(e.name == MODULE_MANIFEST and e.is_file() for e in entries):
            mods.append(d)
        for e in entries:
            if e.is_dir(follow_symlinks=False) and e.name not in prune:
                stack.append(e.path)
    return sorted(mods)


def check_module(root, mdir, cache, files=None, check_licences=True, check_files=True):
    """Returns (violations, files_checked) for one module directory.

    A violation is a (module, file, reason) tuple. files, when given, restricts the
    file scan to those module-relative paths (the fast path).
    """
    mod = rel_module(root, mdir)
    allowed = allowed_ips(root, mdir, cache)
    out = []
    entries, errors = parse_module_info(mdir)
    for err in errors:
        out.append((mod, MODULE_MANIFEST, err))
    if check_licences:
        for p, h, lic in entries.values():
            if lic.replace(" ", "_") not in allowed:
                out.append((mod, MODULE_MANIFEST,
                            "licence '%s' for %s is not allowed (needs a licenses/ file named %s)"
                            % (lic, p, lic.replace(" ", "_"))))
    checked = 0
    # Gradle only checks module files when certification.manifest exists.
    if check_files and os.path.exists(os.path.join(mdir, CERT)):
        rows = parse_cert(mdir)
        rels = module_files(mdir) if files is None else files
        checked = len(rels)
        for rel in rels:
            absp = os.path.join(mdir, rel)
            try:
                ip = file_ip(absp, rel, rows)
            except OSError as e:
                out.append((mod, rel, "cannot be read: %s" % e.strerror))
                continue
            if ip is None:
                out.append((mod, rel, "no IP: add an 'IP:' header or a certification.manifest entry"))
            elif ip.replace(" ", "_") not in allowed:
                out.append((mod, rel, "IP '%s' is not allowed (no licenses/ file named %s)"
                            % (ip, ip.replace(" ", "_"))))
    return out, checked


def git(root, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    res = subprocess.run(["git", "-C", root] + list(args), capture_output=True, env=env)
    if res.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args),
                                                  res.stderr.decode("utf-8", "replace").strip()))
    return res.stdout.decode("utf-8", "replace")


def changed_files(root, ref):
    """Files changed against ref (tracked diff plus new, non-ignored files), absolute paths."""
    top = git(root, "rev-parse", "--show-toplevel").strip()
    names = set()
    for p in git(root, "diff", "--name-only", "-z", "--diff-filter=ACMR", ref).split("\0"):
        if p:
            names.add(os.path.join(top, p))
    for p in git(root, "ls-files", "-z", "--others", "--exclude-standard").split("\0"):
        if p:
            names.add(os.path.join(os.path.abspath(root), p))
    return sorted(n for n in names if os.path.isfile(n))


def modules_above(root, path):
    """Module directories that contain path (nearest first), as Gradle would see it."""
    root = os.path.abspath(root)
    d = os.path.dirname(os.path.abspath(path))
    mods = []
    while d.startswith(root):
        if os.path.isfile(os.path.join(d, MODULE_MANIFEST)):
            mods.append(d)
        if d == root:
            break
        d = os.path.dirname(d)
    return mods


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="repository root (default: the parent of this script's directory)")
    ap.add_argument("--changed-since", metavar="GIT_REF",
                    help="check only files changed against GIT_REF (plus new untracked files)")
    ap.add_argument("--module", action="append", default=[],
                    help="only this module: a relative path, or a tail such as HydraNative")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("ip_check: no such root: " + root, file=sys.stderr)
        return 2
    cache = {}
    violations = []
    modules_checked = 0
    files_checked = 0

    def wanted(mdir):
        if not args.module:
            return True
        rel = rel_module(root, mdir)
        return any(rel == m.replace("\\", "/").strip("/") or rel.endswith("/" + m.replace("\\", "/").strip("/"))
                   for m in args.module)

    try:
        if args.changed_since:
            # Fast path: only the modules and files touched since the ref.
            todo = {}
            for f in changed_files(root, args.changed_since):
                rel_root = os.path.relpath(f, root).replace(os.sep, "/")
                if rel_root.startswith(".."):
                    continue
                for mdir in modules_above(root, f):
                    if not wanted(mdir):
                        continue
                    rel = os.path.relpath(f, mdir).replace(os.sep, "/")
                    entry = todo.setdefault(mdir, {"files": [], "manifest": False, "cert": False})
                    name = os.path.basename(f)
                    if name == MODULE_MANIFEST and os.path.dirname(f) == mdir:
                        entry["manifest"] = True
                    if name == CERT and os.path.dirname(f) == mdir:
                        entry["cert"] = True
                    if not excluded_path(rel):
                        entry["files"].append(rel)
            for mdir in sorted(todo):
                e = todo[mdir]
                modules_checked += 1
                # A changed certification.manifest can affect every file in the module.
                files = None if e["cert"] else sorted(set(e["files"]))
                if files is None or files:
                    v, n = check_module(root, mdir, cache, files=files,
                                        check_licences=e["manifest"])
                    violations += v
                    files_checked += n
                elif e["manifest"]:
                    v, n = check_module(root, mdir, cache, files=[], check_licences=True)
                    violations += v
        else:
            for mdir in discover_modules(root):
                if not wanted(mdir):
                    continue
                modules_checked += 1
                v, n = check_module(root, mdir, cache)
                violations += v
                files_checked += n
    except (OSError, RuntimeError) as e:
        print("ip_check: " + str(e), file=sys.stderr)
        return 2

    if args.module and modules_checked == 0:
        print("ip_check: no module matches " + ", ".join(args.module), file=sys.stderr)
        return 2

    for mod, f, reason in sorted(set(violations)):
        print("%s | %s | %s" % (mod, f, reason))
    status = "FAIL" if violations else "PASS"
    print("ip_check %s: %d modules, %d files, %d violations" %
          (status, modules_checked, files_checked, len(set(violations))))
    return 1 if violations else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    sys.exit(main())
