#!/usr/bin/env bash
# Fold changelog.d/ fragments into CHANGELOG.md under `## Unreleased`.
#
# Feature PRs never touch CHANGELOG.md — they add one fragment each, because two
# PRs inserting a section at the same anchor conflict every time and git has no
# way to order them (see changelog.d/README.md). This script is the other half:
# run once when a release is cut, as one commit by one author, so there is
# nothing to conflict with.
#
# Fragments are concatenated VERBATIM, newest PR number first, matching the
# newest-at-top order CHANGELOG.md already uses. Nothing is reformatted — what
# the author wrote is what ships.
#
# Usage:
#   scripts/collate-changelog.sh            # rewrite CHANGELOG.md, delete fragments
#   scripts/collate-changelog.sh --check    # dry run: print the plan, change nothing
#
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

CHECK_ONLY=0
case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  "") ;;
  *) echo "usage: $(basename "$0") [--check]" >&2; exit 2 ;;
esac

# `pwd -P` for the same reason as the sibling guards: a worktree reached through a
# symlink (/tmp on macOS) otherwise disagrees with resolved paths.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; CYAN=''; NC=''
fi

CHANGELOG="CHANGELOG.md"
FRAGMENT_DIR="changelog.d"
UNRELEASED_HEADING="## Unreleased"

[ -f "$CHANGELOG" ] || { echo "${RED}error:${NC} $CHANGELOG not found at $ROOT" >&2; exit 2; }

if ! grep -qx "$UNRELEASED_HEADING" "$CHANGELOG"; then
  echo "${RED}error:${NC} no '$UNRELEASED_HEADING' heading in $CHANGELOG — don't know where to insert." >&2
  exit 2
fi

# Collect fragments, sorted by leading PR number DESCENDING so the newest lands at
# the top of the section. `sort -t- -k1,1nr` on the basename: numeric on the first
# dash-delimited field, reversed.
list_fragments() {
  [ -d "$FRAGMENT_DIR" ] || return 0
  for frag in "$FRAGMENT_DIR"/*.md; do
    [ -f "$frag" ] || continue
    base_name="$(basename "$frag")"
    if [ "$base_name" = "README.md" ]; then
      continue
    fi
    echo "$base_name"
  done
}
fragments=$(list_fragments | sort -t- -k1,1nr | sed "s|^|$FRAGMENT_DIR/|")

if [ -z "$fragments" ]; then
  echo "${GREEN}No fragments in $FRAGMENT_DIR/ — $CHANGELOG is already current.${NC}"
  exit 0
fi

count=$(printf '%s\n' "$fragments" | wc -l | tr -d ' ')
echo "=== Collating $count fragment(s) into $UNRELEASED_HEADING ==="
echo
printf '%s\n' "$fragments" | sed 's/^/  /'
echo

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "${CYAN}--check: nothing written.${NC}"
  exit 0
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/collate-changelog.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

{
  # Head: everything through the `## Unreleased` line.
  awk -v h="$UNRELEASED_HEADING" '{ print } $0 == h { exit }' "$CHANGELOG"
  echo

  # Fragments, verbatim, each followed by exactly one blank line. `sed '$d'`-free:
  # awk strips trailing blank lines per fragment so the spacing is uniform whether
  # or not the author left a trailing newline.
  while IFS= read -r frag; do
    [ -n "$frag" ] || continue
    awk 'BEGIN { blanks = 0 }
         /^[[:space:]]*$/ { blanks++; next }
         { while (blanks-- > 0) print ""; blanks = 0; print }' "$frag"
    echo
  done <<EOF
$fragments
EOF

  # Tail: everything after the `## Unreleased` line, with its leading blank lines
  # dropped so we don't accumulate a growing gap on each release.
  awk -v h="$UNRELEASED_HEADING" '
    seen && started { print; next }
    seen && !/^[[:space:]]*$/ { started = 1; print; next }
    $0 == h { seen = 1 }
  ' "$CHANGELOG"
} >"$tmp"

mv "$tmp" "$CHANGELOG"
trap - EXIT

# Remove the fragments. `git rm` when tracked so the deletion is staged with the
# rewrite; plain rm otherwise (a fragment added but not yet committed).
while IFS= read -r frag; do
  [ -n "$frag" ] || continue
  if git ls-files --error-unmatch "$frag" >/dev/null 2>&1; then
    git rm -q "$frag"
  else
    rm -f "$frag"
  fi
done <<EOF
$fragments
EOF

echo "${GREEN}Folded $count fragment(s) into $CHANGELOG and removed them.${NC}"
echo "Review the diff, then commit — one commit, one author, no conflicts."
