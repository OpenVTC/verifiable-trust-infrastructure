#!/usr/bin/env bash
# Guard: a published version with no changelog entry.
#
# Sibling to check-version-bumps.sh, which enforces the other half of the same
# convention. That script already tells you to bump the version; nothing ever
# checked that the change was written down. It stopped being written down —
# vta-sdk 0.19.21 and 0.19.22 and vta-service 0.12.10 through 0.12.13 all shipped
# with no entry, including a `vta-sdk` behavioural change and a release-process
# change.
#
# This matters beyond tidiness. Sibling repos (openvtc, the mediator, webvh)
# pin these crates loosely, so a behavioural change is breaking for them even
# when no signature changes, and CHANGELOG.md is where they find out.
#
# The rule: if a publishable crate's VERSION changed in this PR, the root
# CHANGELOG.md must MENTION THE NEW VERSION.
#
# Deliberately not the weaker "the changelog was touched": a PR that edits the
# changelog for one reason and bumps a version for another would satisfy that
# and still ship an undocumented release.
#
# Not circular with check-version-bumps.sh — that script excludes CHANGELOG*
# from "source changes", so a changelog-only PR needs no bump and a bump needs a
# changelog. The two guards meet in the middle.
#
# Usage: scripts/check-changelogs.sh [base-ref]
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

BASE="${1:-origin/main}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; CYAN=''; NC=''
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "${RED}error:${NC} base ref '$BASE' not found. Pass a reachable ref, e.g. origin/main." >&2
  exit 2
fi

CHANGELOG="CHANGELOG.md"

echo "=== Changelog guard (base: $BASE) ==="
echo

changed=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$changed" ]; then
  echo "${GREEN}No changes vs $BASE — nothing to check.${NC}"
  exit 0
fi

if [ ! -f "$CHANGELOG" ]; then
  echo "${RED}error:${NC} $CHANGELOG not found at $ROOT" >&2
  exit 2
fi

# Publishable crates as  name<TAB>relative-crate-dir. Non-publishable crates are
# irrelevant: nothing reaches a consumer, so there is no contract to record.
crates=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | select(.publish == null or .publish == ["crates.io"])
      | "\(.name)\t\(.manifest_path)"' \
  | sed "s|\t$ROOT/|\t|; s|/Cargo.toml\$||")

version_of() {
  awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }'
}

fail=0
found=0

while IFS="$(printf '\t')" read -r name dir; do
  [ -n "$name" ] || continue
  manifest="$dir/Cargo.toml"

  old_version=$(git show "$BASE:$manifest" 2>/dev/null | version_of)
  new_version=$(version_of < "$manifest" 2>/dev/null)

  [ -n "$new_version" ] || continue
  [ "$old_version" != "$new_version" ] || continue

  found=1
  # Match the version as a whole token: a plain substring search would let
  # `0.1.30`'s entry satisfy a bump to `0.1.3`.
  escaped=$(printf '%s' "$new_version" | sed 's/\./\\./g')
  if grep -qE "(^|[^0-9.])$escaped([^0-9.]|\$)" "$CHANGELOG"; then
    echo "  ${GREEN}ok${NC}   $name: ${old_version:-<new>} -> $new_version (documented)"
  else
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version, but $new_version does not appear in $CHANGELOG"
    fail=1
  fi
done <<EOF
$crates
EOF

echo
if [ "$found" -eq 0 ]; then
  echo "${GREEN}No publishable crate versions changed — nothing to check.${NC}"
  exit 0
fi

if [ "$fail" -ne 0 ]; then
  echo "${RED}A crate is being published with no record of what changed.${NC}"
  echo "Sibling repos pin these crates loosely, so a behavioural change is breaking"
  echo "for them even when no signature changes — ${CYAN}$CHANGELOG${NC} is where they find out."
  echo "Add an entry naming the new version, e.g. '### $name <version> — <summary>'."
  exit 1
fi

echo "${GREEN}Every version bump in this PR has a changelog entry.${NC}"
