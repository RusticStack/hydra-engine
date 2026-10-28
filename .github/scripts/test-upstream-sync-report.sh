#!/usr/bin/env bash
# Test of upstream-sync-report.sh on a throwaway repository: the guard must fail when upstream
# changes a listed file, pass when it changes another file, and the overlap must be reported.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script="$here/upstream-sync-report.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main .
git config user.name test; git config user.email test@example.invalid
mkdir -p core other
echo a > core/Patched.java; echo b > other/Free.java; echo c > other/Both.java
printf '# comment\ncore/Patched.java\n' > list.txt
git add . && git commit -qm base
git branch base
fail=0; check() { if [ "$2" != "$3" ]; then echo "FAIL $1: expected $2, got $3"; fail=1; else echo "ok   $1"; fi; }

# upstream changes only a free file: guard passes
git checkout -q -b up1 base; echo x >> other/Free.java; git commit -qam up1
git checkout -q -b ours1 base; echo y >> other/Both.java; git commit -qam ours
git checkout -q -b up1b up1; echo z >> other/Both.java; git commit -qam up1b
git checkout -q ours1
set +e; out=$(bash "$script" base up1b list.txt); rc=$?; set -e
check "free file only: exit 0" 0 "$rc"
check "overlap reports Both.java" 1 "$(printf '%s' "$out" | grep -c 'other/Both.java')"

# upstream changes a patched file: guard fails and names it
git checkout -q -b up2 base; echo x >> core/Patched.java; git commit -qam up2
git checkout -q ours1
set +e; out=$(bash "$script" base up2 list.txt); rc=$?; set -e
check "patched file changed: exit 1" 1 "$rc"
check "guard names Patched.java" 1 "$(printf '%s' "$out" | grep -c 'core/Patched.java')"

# upstream deletes a patched file: also a change
git checkout -q -b up3 base; git rm -q core/Patched.java; git commit -qm up3
git checkout -q ours1
set +e; bash "$script" base up3 list.txt >/dev/null; rc=$?; set -e
check "patched file deleted: exit 1" 1 "$rc"

# upstream renames a patched file: the old path must still be caught
git checkout -q -b up4 base; git mv core/Patched.java core/Renamed.java; git commit -qm up4
git checkout -q ours1
set +e; out=$(bash "$script" base up4 list.txt); rc=$?; set -e
check "patched file renamed: exit 1" 1 "$rc"
check "guard names the old path" 1 "$(printf '%s' "$out" | grep -c 'core/Patched.java')"

# bad use
set +e; bash "$script" base nosuchref list.txt >/dev/null 2>&1; rc=$?; set -e
check "unknown ref: exit 2" 2 "$rc"
exit $fail
