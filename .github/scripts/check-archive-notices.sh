#!/usr/bin/env bash
# Fails unless every given release zip holds LICENSE, NOTICE and NOTICE-HYDRA in its top folder.
#
#   check-archive-notices.sh <zip>...
#
# release.yml checks the engine zip after unpacking it; this also covers the client zip.
set -u
[ $# -ge 1 ] || { echo "usage: check-archive-notices.sh <zip>..." >&2; exit 2; }
PY=python3
"$PY" -c '' 2>/dev/null || PY=python
rc=0
for z in "$@"; do
  "$PY" - "$z" <<'PYEOF' || rc=1
import sys, zipfile
z = sys.argv[1]
try:
    names = zipfile.ZipFile(z).namelist()
except (OSError, zipfile.BadZipFile) as e:
    print(f"FAIL {z}: {e}"); sys.exit(1)
tops = {n.split("/")[0] for n in names if n.strip("/")}
if len(tops) != 1:
    print(f"FAIL {z}: expected one top folder, found {sorted(tops)}"); sys.exit(1)
top = tops.pop()
missing = [n for n in ("LICENSE", "NOTICE", "NOTICE-HYDRA") if f"{top}/{n}" not in names]
if missing:
    print(f"FAIL {z}: missing {', '.join(missing)}"); sys.exit(1)
print(f"ok   {z}: LICENSE, NOTICE and NOTICE-HYDRA present")
PYEOF
done
exit $rc
