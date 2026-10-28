#!/usr/bin/env bash
# Test of check-archive-notices.sh, including the real client zip made by package-client.sh.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
chk="$here/check-archive-notices.sh"
PY=python3; "$PY" -c '' 2>/dev/null || PY=python
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0; check() { if [ "$2" != "$3" ]; then echo "FAIL $1: expected $2, got $3"; fail=1; else echo "ok   $1"; fi; }

bash "$here/package-client.sh" 0.0.0-test "$tmp/out" >/dev/null
set +e; bash "$chk" "$tmp"/out/hydra-client-*.zip >/dev/null; rc=$?; set -e
check "real client zip: exit 0" 0 "$rc"

"$PY" - "$tmp" <<'PYEOF'
import sys, zipfile
d = sys.argv[1]
with zipfile.ZipFile(d + "/bad.zip", "w") as z:
    for n in ("LICENSE", "NOTICE"): z.writestr("pkg/" + n, "x")
with zipfile.ZipFile(d + "/good.zip", "w") as z:
    for n in ("LICENSE", "NOTICE", "NOTICE-HYDRA"): z.writestr("pkg/" + n, "x")
PYEOF
set +e; bash "$chk" "$tmp/bad.zip" >/dev/null; rc=$?; set -e
check "zip without NOTICE-HYDRA: exit 1" 1 "$rc"
set +e; bash "$chk" "$tmp/good.zip" "$tmp/bad.zip" >/dev/null; rc=$?; set -e
check "one bad of two: exit 1" 1 "$rc"
set +e; bash "$chk" "$tmp/nosuch.zip" >/dev/null; rc=$?; set -e
check "missing file: exit 1" 1 "$rc"
exit $fail
