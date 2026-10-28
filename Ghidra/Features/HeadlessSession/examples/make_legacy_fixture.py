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
"""Builds the small 12.1.4-format project that the upgrade-gate tests need (PROTOCOL-3.md, package
E2): ``examples/fixtures/legacy-12.1.4/legacy.gpr`` and ``legacy.rep``. Stock Ghidra 12.1.4
imports one of our own generated PE files (an x64 executable compiled from a few lines of C by us;
it contains nothing derived from a game), without analysis, so the project is small
(about 1.5 MB) and holds one program saved with program database version 32 (this
engine writes 33).

The output is committed; run this only to regenerate it. Standard library only.

    python make_legacy_fixture.py --stock C:/.../ghidra_12.1.4_PUBLIC --exe flow_fixture.exe
                                  [--out <dir>]

"""
import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "fixtures" / "legacy-12.1.4"
NAME = "legacy"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def build(stock, exe, out):
    stock = pathlib.Path(stock)
    props = (stock / "Ghidra" / "application.properties").read_text()
    if "application.version=12.1.4" not in props:
        sys.exit(f"{stock} is not Ghidra 12.1.4 (application.properties says "
                 f"{[l for l in props.splitlines() if 'application.version' in l]})")
    if (stock / "Ghidra" / "Features" / "HeadlessSession").exists() or "hydra" in props.lower():
        sys.exit(f"{stock} is not a stock install")
    launcher = stock / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    work = pathlib.Path(tempfile.mkdtemp(prefix="legacy-fixture-"))
    try:
        cmd = [str(launcher), str(work), NAME, "-import", str(exe), "-noanalysis", "-overwrite"]
        print("running", " ".join(cmd))
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        sys.stdout.write(r.stdout[-1500:])
        if r.returncode != 0:
            sys.exit(f"analyzeHeadless exited {r.returncode}: {r.stderr[-1500:]}")
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        shutil.copy2(work / f"{NAME}.gpr", out / f"{NAME}.gpr")
        # no lock files, no transient files: only what Ghidra keeps
        shutil.copytree(work / f"{NAME}.rep", out / f"{NAME}.rep",
                        ignore=shutil.ignore_patterns("*.lock", "*.lock~", "tmp*.ps", "tmp*.tmp"))
        (out / "README.txt").write_text(
            "A Ghidra 12.1.4 project (program database version 32), made by make_legacy_fixture.py\n"
            f"from {pathlib.Path(exe).name} (sha256 {sha256(exe)}), a PE compiled by us from a few\n"
            "lines of C. It holds nothing derived from a game. Never open it writable in place:\n"
            "the tests copy it first.\n")
        size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
        print(f"wrote {out} ({size} bytes)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stock", required=True, help="a stock Ghidra 12.1.4 install")
    ap.add_argument("--exe", required=True, help="one of our own generated PE files")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    a = ap.parse_args()
    build(a.stock, a.exe, pathlib.Path(a.out))


if __name__ == "__main__":
    main()
