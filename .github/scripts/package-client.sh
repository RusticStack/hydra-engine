#!/usr/bin/env bash
# Packages the Python client of the headless session as hydra-client-<version>.zip:
#
#   .github/scripts/package-client.sh <version> <output dir>
#
# The zip holds one folder, hydra-client-<version>/, with ghidra_session.py (standard library only,
# its HYDRA_RELEASE stamped with <version>), LICENSE and a short README.txt. The release workflow
# runs it; it can be run locally with the same arguments.
set -euo pipefail

version=${1:?usage: package-client.sh <version> <output dir>}
out=${2:?usage: package-client.sh <version> <output dir>}
root=$(cd "$(dirname "$0")/../.." && pwd)
src="$root/Ghidra/Features/HeadlessSession/support/ghidra_session.py"
name="hydra-client-$version"

case "$version" in
  *[!A-Za-z0-9._-]*|"") echo "bad version: $version" >&2; exit 1 ;;
esac

# python3 on Linux and macOS, python on Windows
PY=python3
"$PY" -c '' 2>/dev/null || PY=python

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/$name" "$out"

# Stamp the release into the file (exactly one line to replace)
if [ "$(grep -c '^HYDRA_RELEASE = ' "$src")" -ne 1 ]; then
  echo "expected exactly one HYDRA_RELEASE line in $src" >&2; exit 1
fi
sed "s/^HYDRA_RELEASE = .*/HYDRA_RELEASE = \"$version\"/" "$src" > "$work/$name/ghidra_session.py"
cp "$root/LICENSE" "$work/$name/LICENSE"

client=$(sed -n 's/^CLIENT_VERSION = "\(.*\)"/\1/p' "$work/$name/ghidra_session.py")
protocol=$(sed -n 's/^PROTOCOL = \([0-9]*\)/\1/p' "$work/$name/ghidra_session.py")
cat > "$work/$name/README.txt" <<TXT
Hydra Engine client $version

ghidra_session.py is the Python client of the Hydra Engine headless session. Python 3.10 or
later, standard library only. It starts the engine's daemon when it is not running and talks to
it in JSON lines.

  client version  $client
  protocol        $protocol
  released with   Hydra Engine $version (use the engine of the same release)

Use it with the engine zip of the same release:

  python ghidra_session.py --ghidra <the unzipped engine> ensure
  python ghidra_session.py version

On connect the client checks the engine's hello: it refuses an engine that speaks another
protocol, or that requires a newer client than $client (minClient), with a clear error. Pin a
release, and upgrade the client and the engine together. Details: the "Pinning and upgrading"
section of Ghidra/Features/HeadlessSession/README.md in the Hydra Engine repository.

Apache License 2.0 (LICENSE). Verify the zip against SHA256SUMS of the release.
TXT

# A zip with a fixed layout and modification times, so the same inputs give the same file
"$PY" - "$work" "$name" "$out/$name.zip" <<'PY'
import os, sys, zipfile
work, name, dest = sys.argv[1:4]
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
    for fn in sorted(os.listdir(os.path.join(work, name))):
        info = zipfile.ZipInfo(f"{name}/{fn}", date_time=(2026, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(os.path.join(work, name, fn), "rb") as f:
            z.writestr(info, f.read())
PY

# Test what ships: unzip it elsewhere and ask the client for its version
check=$(mktemp -d)
"$PY" -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$out/$name.zip" "$check"
got=$("$PY" -I "$check/$name/ghidra_session.py" version)
rm -rf "$check"
got=${got%$''}   # Python on Windows ends its lines with CR LF
want="{\"client\": \"$client\", \"protocol\": $protocol, \"release\": \"$version\"}"
if [ "$got" != "$want" ]; then
  echo "the packaged client reports $got, expected $want" >&2; exit 1
fi
echo "$out/$name.zip: $got"
