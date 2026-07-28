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

# `pwd -P` (physical path), not `pwd`: `cargo metadata` reports symlink-resolved
# manifest paths, and ROOT is used to strip that prefix. On macOS a worktree
# under /tmp (a symlink to /private/tmp) made the two disagree, so the prefix
# never matched, every file failed attribution, and the guard passed vacuously.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
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

# Guard the guard. Every dir above must now be workspace-relative; an absolute one
# means the ROOT prefix did not strip, so every changed file fails attribution and
# this script reports "nothing to check" and exits 0 — passing vacuously on a PR it
# should have failed. That is the worst outcome available to a release guard, so it
# fails loudly instead of silently.
if printf '%s\n' "$crates" | cut -f3 | grep -q '^/'; then
  echo "${RED}error:${NC} crate paths did not resolve relative to $ROOT." >&2
  echo "Cannot attribute changed files; refusing to pass without checking." >&2
  printf '%s\n' "$crates" | cut -f3 | grep '^/' | head -3 | sed 's/^/  /' >&2
  exit 2
fi

version_of() {
  awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }'
}

fail=0
found=0

while IFS="$(printf '\t')" read -r name dir; do
  [ -n "$name" ] || continue
  manifest="$dir/Cargo.toml"

  # `|| true` so a crate that does not exist at BASE (a NEW publishable crate)
  # yields an empty old_version instead of a `git show` exit-128 that
  # `pipefail`+`set -e` would turn into a spurious guard failure. Matches the
  # sibling handling in check-version-bumps.sh.
  old_version=$(git show "$BASE:$manifest" 2>/dev/null | version_of || true)
  new_version=$(version_of < "$manifest" 2>/dev/null)

  [ -n "$new_version" ] || continue
  [ "$old_version" != "$new_version" ] || continue

  found=1
  # Match the crate NAME immediately followed by the version, as whole tokens.
  #
  # Version-alone was not enough. The workspace carries a dozen subsystem crates
  # all sitting in the 0.1.x range, so a patch number is routinely shared: a
  # `vta-tee` 0.1.0 -> 0.1.1 bump passed this guard with no `vta-tee` entry at
  # all, because `0.1.1` already appeared for `vta-audit`, `vta-backup`,
  # `vta-vault` and `vta-webvh` (PR #819). A guard that green-lights an
  # undocumented release is worse than no guard, because it is trusted.
  #
  # Both heading shapes in CHANGELOG.md are accepted, backticks optional:
  #   ### vta-service 0.12.43 — summary
  #   ### vti-secrets 0.1.7 / vta-config 0.1.1 — summary
  #   - `vta-audit` 0.1.1
  # The version stays token-boundaried on the right so a `0.1.30` entry cannot
  # satisfy a bump to `0.1.3`.
  escaped=$(printf '%s' "$new_version" | sed 's/\./\\./g')
  escaped_name=$(printf '%s' "$name" | sed 's/[.[\*^$]/\\&/g')
  if grep -qE "(^|[^A-Za-z0-9_-])\`?$escaped_name\`?[[:space:]]+$escaped([^0-9.]|\$)" "$CHANGELOG"; then
    echo "  ${GREEN}ok${NC}   $name: ${old_version:-<new>} -> $new_version (documented)"
  else
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version, but no \"$name $new_version\" entry appears in $CHANGELOG"
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
