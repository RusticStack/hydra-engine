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
"""Build the Rust client and put it where an install can ship it.

    python -I build-install.py [--out DIR] [--target-dir DIR] [--install DIR] [--no-build]
    python -I build-install.py --check --install DIR

The engine build never requires the Rust client: with no cargo on PATH (and no CARGO set) this
script prints why it skipped and exits 0. With cargo it runs a locked release build, copies
`hydra-agent.exe` and a provenance marker (`hydra-agent.provenance.json`) to `--out`, and, with
`--install`, into `<install>/Ghidra/Features/HeadlessSession/support/`.

The build is `cargo build --release --locked`: `Cargo.lock` pins the one dependency
(serde_json), `CARGO_INCREMENTAL=0` and a build-directory target keep the source tree clean
(the ip task scans it), and the marker records the commit, the toolchain and the binary's
SHA-256 so an installed client can be traced to the build that produced it.

The Python client stays the default: the Rust binary is an optional second client, and
`--check` reports whether the installed copy matches its marker.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent
BINARY = "hydra-agent.exe" if os.name == "nt" else "hydra-agent"
MARKER = "hydra-agent.provenance.json"


def find_cargo():
    """cargo from CARGO, PATH or CARGO_HOME; None when this machine has none."""
    explicit = os.environ.get("CARGO")
    if explicit and Path(explicit).is_file():
        return str(Path(explicit))
    found = shutil.which("cargo")
    if found:
        return found
    home = os.environ.get("CARGO_HOME")
    candidates = [Path(home) / "bin" / "cargo.exe"] if home else []
    candidates.append(Path.home() / ".cargo" / "bin" / "cargo.exe")
    candidates.append(Path.home() / ".cargo" / "bin" / "cargo")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def find_rustc(cargo):
    """rustc beside cargo, or on PATH."""
    if cargo:
        beside = Path(cargo).with_name("rustc.exe" if os.name == "nt" else "rustc")
        if beside.is_file():
            return str(beside)
    return shutil.which("rustc")


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kwargs)


def version_line(binary, *args):
    result = run([str(binary), *args])
    return (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr) else ""


def git(*args):
    try:
        result = run(["git", "-C", str(MODULE), *args])
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def marker_for(binary, cargo, rustc):
    text = version_line(binary, "version")
    match = re.search(r"hydra-agent (\S+) \(client (\S+), protocol (\d+)\)", text)
    version, client_version, protocol = (match.group(1), match.group(2), match.group(3)) if match else ("", "", "")
    dirty = git("status", "--porcelain", "--", str(HERE))
    return {
        "name": "hydra-agent",
        "version": version,
        "clientVersion": client_version,
        "protocol": int(protocol) if protocol.isdigit() else None,
        "versionLine": text,
        "binary": BINARY,
        "bytes": binary.stat().st_size,
        "sha256": sha256(binary),
        "built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gitCommit": git("rev-parse", "HEAD"),
        "gitDirty": bool(dirty),
        "cargo": cargo,
        "rustc": rustc,
    }


def check_install(install):
    support = Path(install) / "Ghidra/Features/HeadlessSession/support"
    binary, marker_path = support / BINARY, support / MARKER
    if not binary.is_file() or not marker_path.is_file():
        print("hydra-agent: not installed in %s (the Python client is the default)" % support)
        return 1
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    actual = sha256(binary)
    ok = actual == marker.get("sha256")
    print("hydra-agent: %s, %s bytes, sha256 %s (%s)" % (
        marker.get("versionLine") or marker.get("version"), binary.stat().st_size, actual[:16],
        "matches the marker" if ok else "DOES NOT match the marker"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(MODULE / "build/rust/support"),
                    help="where the binary and the marker go (default: the module's build/rust/support)")
    ap.add_argument("--target-dir", default=str(MODULE / "build/rust-target"),
                    help="cargo's target directory (default: the module's build/rust-target)")
    ap.add_argument("--install", help="an existing install: also copy into its HeadlessSession support/")
    ap.add_argument("--no-build", action="store_true", help="only copy, do not run cargo")
    ap.add_argument("--check", action="store_true", help="verify an installed copy against its marker")
    a = ap.parse_args(argv)
    if a.check:
        if not a.install:
            ap.error("--check needs --install")
        return check_install(a.install)

    cargo = find_cargo()
    out = Path(a.out)
    if not a.no_build and cargo is None:
        print("hydra-agent: cargo not found (set CARGO or put cargo on PATH): the Rust client is "
              "not built; the Python client remains the default")
        return 0

    binary = Path(a.target_dir) / "release" / BINARY
    if not a.no_build:
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = str(a.target_dir)
        env["CARGO_INCREMENTAL"] = "0"
        try:
            built = run([cargo, "build", "--release", "--locked", "--manifest-path", str(HERE / "Cargo.toml")],
                        env=env, cwd=str(HERE))
        except OSError as e:
            print("hydra-agent: could not run cargo (%s): %s" % (cargo, e))
            return 1
        if built.returncode != 0:
            sys.stderr.write(built.stdout + built.stderr)
            return built.returncode
        if not binary.is_file():
            print("hydra-agent: cargo succeeded but %s is missing" % binary)
            return 1
    elif not binary.is_file():
        print("hydra-agent: --no-build and no binary at %s" % binary)
        return 1

    rustc = find_rustc(cargo)
    marker = marker_for(
        binary,
        version_line(cargo, "--version") if cargo else "",
        version_line(rustc, "--version") if rustc else "",
    )
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, out / BINARY)
    (out / MARKER).write_text(json.dumps(marker, indent=1) + "\n", encoding="utf-8")
    if a.install:
        support = Path(a.install) / "Ghidra/Features/HeadlessSession/support"
        if not (Path(a.install) / "Ghidra/application.properties").is_file():
            print("hydra-agent: %s is not an install (no Ghidra/application.properties)" % a.install)
            return 1
        support.mkdir(parents=True, exist_ok=True)
        shutil.copy2(out / BINARY, support / BINARY)
        shutil.copy2(out / MARKER, support / MARKER)
    print("hydra-agent: %s %s bytes sha256 %s -> %s%s" % (
        marker["version"], marker["bytes"], marker["sha256"][:16], out,
        (" and " + str(Path(a.install) / "Ghidra/Features/HeadlessSession/support")) if a.install else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
