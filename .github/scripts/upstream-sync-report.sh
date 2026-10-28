#!/usr/bin/env bash
# Report for an upstream sync: the guard on the patched core files, the file overlap between
# upstream's changes and ours, the upstream shortlog and the database format constants.
#
#   upstream-sync-report.sh <base> <upstream> [touched-files-list]
#
# <base>     the previous sync point (normally `git merge-base HEAD upstream/master`)
# <upstream> the upstream commit being merged (normally upstream/master)
# The list defaults to .github/hydra-touched-files.txt. Markdown goes to stdout.
# Exit 0: no patched core file changed upstream. Exit 1: at least one did (listed). Exit 2: bad use.
set -u
base=${1:-}; up=${2:-}; list=${3:-.github/hydra-touched-files.txt}
if [ -z "$base" ] || [ -z "$up" ] || [ ! -f "$list" ]; then
  echo "usage: upstream-sync-report.sh <base> <upstream> [list]" >&2; exit 2
fi
git rev-parse --verify -q "$base^{commit}" >/dev/null && git rev-parse --verify -q "$up^{commit}" >/dev/null \
  || { echo "unknown commit: $base or $up" >&2; exit 2; }

changed=$(git diff --name-only "$base" "$up")
ours=$(git diff --name-only "$base" HEAD)
touched=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$list")

hits=$(printf '%s\n' "$changed" | grep -Fxf <(printf '%s\n' "$touched") || true)
overlap=$(comm -12 <(printf '%s\n' "$changed" | sort -u) <(printf '%s\n' "$ours" | sort -u) | sed '/^$/d')

echo "## Upstream sync report"
echo
echo "Base \`$(git rev-parse --short "$base")\`, upstream \`$(git rev-parse --short "$up")\`."
echo
echo "### Patched core files changed upstream (guard)"
if [ -n "$hits" ]; then
  echo
  echo "**FAIL.** Upstream changed a file Hydra Engine patches. Merge it by hand, keep both changes and the"
  echo "Hydra comment above \`package\`, and rerun the suites (CONTRIBUTING.md, \"What conflicts\"):"
  echo
  printf '%s\n' "$hits" | sed 's/^/- `/; s/$/`/'
else
  echo; echo "None of the $(printf '%s\n' "$touched" | wc -l | tr -d ' ') patched core files changed upstream."
fi
echo
echo "### Files changed on both sides (overlap)"
echo
if [ -n "$overlap" ]; then printf '%s\n' "$overlap" | sed 's/^/- `/; s/$/`/'; else echo "None."; fi
echo
echo "### Database format constants"
echo
for f in Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/ProgramDB.java \
         Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/DataTypeManagerDB.java; do
  v0=$(git show "$base:$f" 2>/dev/null | grep -E 'static final int DB_VERSION' | head -1 | tr -s ' \t' ' ')
  v1=$(git show "$up:$f" 2>/dev/null | grep -E 'static final int DB_VERSION' | head -1 | tr -s ' \t' ' ')
  if [ "$v0" = "$v1" ]; then s="unchanged"; else s="**CHANGED** (state it in the next release's compatibility statement)"; fi
  echo "- \`${f##*/}\`: ${v1:-not found}, $s"
done
echo
echo "### Upstream commits ($(git rev-list --count "$base..$up"))"
echo
echo '```'
git shortlog --no-merges -s -n "$base..$up" | head -20
echo '```'
echo
echo '```'
git log --no-merges --format='%h %s' "$base..$up" | head -50
echo '```'
[ -z "$hits" ]
