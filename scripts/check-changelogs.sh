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
# The rules, in the order they are checked:
#
#   1. Fragment filenames are <PR-number>-<slug>.md.
#   2. A fragment this PR ADDS names this PR — in the filename and in the `###`
#      heading. (Needs $PR_NUMBER; skipped locally.)
#   3. A PR does not edit CHANGELOG.md. The release collation is exempt, and is
#      recognised by its own diff: it deletes the fragments it folds in.
#      $ALLOW_CHANGELOG_EDIT=1 is the escape hatch for the rest.
#   4. If a publishable crate's VERSION changed, a changelog entry must MENTION
#      THE NEW VERSION — in the root CHANGELOG.md, or in a fragment.
#
# Rules 2 and 3 exist because rule 4 alone left the convention documented in
# four places and enforced in none: an entry in either location satisfied it, so
# nothing ever stopped a PR from editing the shared file and handing a conflict
# to every other open PR.
#
# Fragments exist because a shared CHANGELOG.md conflicted on every pair of
# concurrent PRs: each one inserts a section at the same anchor (the top of
# `## Unreleased`), which git cannot order. One file per PR never conflicts.
# `scripts/collate-changelog.sh` folds them in at release time. See
# changelog.d/README.md. Both locations are accepted here so the rule is about
# the record existing, not about which file it currently lives in.
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
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "${RED}error:${NC} base ref '$BASE' not found. Pass a reachable ref, e.g. origin/main." >&2
  exit 2
fi

CHANGELOG="CHANGELOG.md"
FRAGMENT_DIR="changelog.d"

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

# Every place an entry may live. Fragments are searched alongside CHANGELOG.md so
# a PR satisfies the rule by writing a fragment, and a release that has already
# collated its fragments still satisfies it from CHANGELOG.md.
#
# Built as an array rather than a glob expanded at grep time: with `nullglob`
# unset an empty changelog.d/ would pass the literal string `changelog.d/*.md` to
# grep, which then reads *stdin* and hangs the CI job.
set -- "$CHANGELOG"
if [ -d "$FRAGMENT_DIR" ]; then
  for frag in "$FRAGMENT_DIR"/*.md; do
    [ -f "$frag" ] || continue
    case "$(basename "$frag")" in
      README.md) continue ;;
    esac
    set -- "$@" "$frag"
  done
fi
ENTRY_FILES="$*"

# Fragment filenames carry the PR number, which is what makes them collision-free.
# A fragment named otherwise still *works* here (it is just a file to grep), but it
# defeats the convention, so reject it while the author is still looking.
bad_names=0
if [ -d "$FRAGMENT_DIR" ]; then
  for frag in "$FRAGMENT_DIR"/*.md; do
    [ -f "$frag" ] || continue
    base_name="$(basename "$frag")"
    case "$base_name" in
      README.md) continue ;;
    esac
    if ! printf '%s' "$base_name" | grep -qE '^[0-9]+-[a-z0-9][a-z0-9-]*\.md$'; then
      echo "  ${RED}BAD NAME${NC} $FRAGMENT_DIR/$base_name — expected <PR-number>-<slug>.md"
      bad_names=1
    fi
  done
fi
if [ "$bad_names" -ne 0 ]; then
  echo
  echo "${RED}Fragment filenames must be <PR-number>-<slug>.md${NC} (lowercase slug)."
  echo "The PR number is what guarantees two concurrent PRs cannot collide."
  exit 1
fi

# The fragment a PR adds must carry THAT PR's number — in the filename and in
# the heading.
#
# `changelog.d/` holds every open PR's fragment at once, so this inspects only
# the files this PR *adds*; anyone else's are not its business. Skipped when
# `PR_NUMBER` is unset (a local run, a push build) — there is no number to check
# against, and a guard that guessed one would fail every local invocation.
#
# Both halves are worth checking. A wrong filename defeats the collision-freedom
# the number exists for; a wrong number in the heading is worse, because it
# survives collation into CHANGELOG.md and permanently points readers at an
# unrelated PR. The heading one is easy to get wrong: you write the fragment
# before the PR exists, guess the next number, and lose the race.
#
# Note this reads the COMMITTED diff, like every check here — an uncommitted
# fragment is invisible to it, which is what you want in CI and worth knowing
# when running it by hand.
if [ -n "${PR_NUMBER:-}" ]; then
  wrong_number=0
  added_frags=$(git diff --name-only --diff-filter=A "$BASE"...HEAD -- "$FRAGMENT_DIR" 2>/dev/null || true)
  for frag in $added_frags; do
    [ -f "$frag" ] || continue
    base_name="$(basename "$frag")"
    case "$base_name" in
      README.md) continue ;;
    esac
    frag_pr="${base_name%%-*}"
    if [ "$frag_pr" != "$PR_NUMBER" ]; then
      echo "  ${RED}WRONG PR${NC} $frag names PR #$frag_pr, but this is PR #$PR_NUMBER"
      wrong_number=1
      continue
    fi
    if ! grep -qE "^### .*\(#$PR_NUMBER\)[[:space:]]*$" "$frag"; then
      echo "  ${RED}WRONG PR${NC} $frag — its \`###\` heading does not end with (#$PR_NUMBER)"
      wrong_number=1
    fi
  done
  if [ "$wrong_number" -ne 0 ]; then
    echo
    echo "${RED}A fragment must name the PR that adds it.${NC}"
    echo "The number is what keeps fragments collision-free, and what lets a reader"
    echo "get from a changelog entry back to the discussion behind it."
    echo
    echo "  ${CYAN}git mv $FRAGMENT_DIR/<wrong>-<slug>.md $FRAGMENT_DIR/$PR_NUMBER-<slug>.md${NC}"
    echo "  ${CYAN}# and make the heading end with (#$PR_NUMBER)${NC}"
    exit 1
  fi
fi

# CHANGELOG.md is not a feature PR's file to edit.
#
# This guard accepts an entry in either location, because a repo that has just
# collated has them in CHANGELOG.md — which meant "add a file, don't edit the
# file" was documented in four places and enforced in none. The cost of ignoring
# it does not land on the author: it lands on every OTHER open PR, as a conflict
# they did not cause and cannot avoid.
#
# The one PR that legitimately rewrites CHANGELOG.md is the release collation,
# and it is recognisable from its own diff: it DELETES fragments (that is what
# collate-changelog.sh does). `ALLOW_CHANGELOG_EDIT=1` covers the remainder — a
# release PR that only stamps a version heading, or a genuine correction to an
# already-released entry. CI sets it from the `release` label.
if printf '%s\n' "$changed" | grep -qx "$CHANGELOG"; then
  deleted_frags=$(git diff --name-only --diff-filter=D "$BASE"...HEAD -- "$FRAGMENT_DIR" 2>/dev/null || true)
  if [ -z "$deleted_frags" ] && [ "${ALLOW_CHANGELOG_EDIT:-0}" != "1" ]; then
    echo "  ${RED}EDITED${NC} $CHANGELOG — feature PRs add a fragment instead"
    echo
    echo "${RED}$CHANGELOG is shared; a fragment is not.${NC}"
    echo "Every PR that edits this file inserts at the same anchor, so any two open"
    echo "PRs conflict — structurally, every time, with the same mechanical"
    echo "resolution. Two PRs adding two different files never conflict."
    echo
    echo "Move your entry to ${CYAN}$FRAGMENT_DIR/${PR_NUMBER:-<PR-number>}-<slug>.md${NC} and revert"
    echo "the change to $CHANGELOG. It is folded back in, verbatim, at release."
    echo
    echo "Cutting a release? ${CYAN}scripts/collate-changelog.sh${NC} deletes the fragments it"
    echo "folds in, which is how this check recognises the collation. For a release PR"
    echo "that only stamps a heading, add the ${CYAN}release${NC} label."
    echo
    echo "See ${CYAN}$FRAGMENT_DIR/README.md${NC}."
    exit 1
  fi
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
# `cut -f2` — the crate dir. This read `-f3` and so inspected a field that does
# not exist in this script's two-column data (check-version-bumps.sh emits three).
# Every line was empty, nothing ever matched `^/`, and the check that exists to
# stop a vacuous pass could not fire. It is the one check that must not be
# decorative.
if printf '%s\n' "$crates" | cut -f2 | grep -q '^/'; then
  echo "${RED}error:${NC} crate paths did not resolve relative to $ROOT." >&2
  echo "Cannot attribute changed files; refusing to pass without checking." >&2
  printf '%s\n' "$crates" | cut -f2 | grep '^/' | head -3 | sed 's/^/  /' >&2
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
  # $ENTRY_FILES is intentionally unquoted: it is a whitespace-joined file list,
  # and every path in this repo is space-free (enforced by the fragment filename
  # check above and by CHANGELOG.md being a fixed name).
  # shellcheck disable=SC2086
  if grep -qE "(^|[^A-Za-z0-9_-])\`?$escaped_name\`?[[:space:]]+$escaped([^0-9.]|\$)" $ENTRY_FILES; then
    echo "  ${GREEN}ok${NC}   $name: ${old_version:-<new>} -> $new_version (documented)"
  else
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version, but no \"$name $new_version\" entry appears in $CHANGELOG or $FRAGMENT_DIR/"
    fail=1
  fi
done <<EOF
$crates
EOF

echo
if [ "$found" -eq 0 ]; then
  echo "${GREEN}No publishable crate versions changed — nothing to check.${NC}"
  # A PR that bumps nothing needs no entry, and most genuinely need none. But
  # release-process changes, CI contracts and docs restructures have shipped
  # unrecorded precisely because nothing mentioned it at the one moment the
  # author was looking. So: a notice, never a failure. Failing would tax every
  # typo fix to catch the few that matter, and a guard people learn to route
  # around is worse than one that only advises.
  added_any=$(git diff --name-only --diff-filter=A "$BASE"...HEAD -- "$FRAGMENT_DIR" 2>/dev/null || true)
  if [ -z "$added_any" ] && ! printf '%s\n' "$changed" | grep -qx "$CHANGELOG"; then
    echo
    echo "${YELLOW}note:${NC} this PR records nothing in the changelog."
    echo "Fine for a typo or a test-only change. If it alters how the project is"
    echo "released, built, or contributed to, add ${CYAN}$FRAGMENT_DIR/${PR_NUMBER:-<PR-number>}-<slug>.md${NC}"
    echo "— those are exactly the changes that have shipped unrecorded before."
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
      echo "::notice title=No changelog entry::This PR bumps no crate version and adds no changelog fragment. Fine for typo/test-only changes; add one if it changes how the project is released, built, or contributed to."
    fi
  fi
  exit 0
fi

if [ "$fail" -ne 0 ]; then
  echo "${RED}A crate is being published with no record of what changed.${NC}"
  echo "Sibling repos pin these crates loosely, so a behavioural change is breaking"
  echo "for them even when no signature changes — the changelog is where they find out."
  echo
  echo "Add a fragment (${CYAN}not${NC} an edit to $CHANGELOG — that conflicts with every"
  echo "other open PR). Create ${CYAN}$FRAGMENT_DIR/<PR-number>-<slug>.md${NC} containing:"
  echo
  echo "  ### $name <version> — <summary> (#<PR-number>)"
  echo
  echo "  <what changed and why>"
  echo
  echo "See ${CYAN}$FRAGMENT_DIR/README.md${NC}."
  exit 1
fi

echo "${GREEN}Every version bump in this PR has a changelog entry.${NC}"
