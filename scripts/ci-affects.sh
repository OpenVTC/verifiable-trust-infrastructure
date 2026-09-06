#!/usr/bin/env bash
# Decide whether a package-scoped CI job needs to run for the change in hand.
#
#   scripts/ci-affects.sh vta-mobile-core
#
# Prints a short explanation and, under Actions, writes `run=true|false` to
# $GITHUB_OUTPUT for the caller to gate its job on.
#
# # Why
#
# Some jobs build exactly one package. `Mobile build` cross-compiles
# `vta-mobile-core` for iOS and Android and takes ~22 minutes; its workspace
# dependency closure is *two crates*, `vta-mobile-core` and `vta-sdk`. Every PR
# that touches neither waits for it anyway — which on this repo is most of them,
# including every VTC-only change, since nothing under `vtc-*` is in any of these
# closures.
#
# # The closure is derived, never listed
#
# `cargo metadata` knows what a package depends on. A hand-written list of
# "paths that affect mobile" would be a second description of that, and this repo
# has now paid three times over for two lists of the same thing drifting apart
# (#1252, #1256, #1259). So the closure is computed on every run and a crate
# added to the graph tomorrow is covered with no edit here.
#
# # Fail-safe, in the direction that costs minutes rather than correctness
#
# A skipped job is a check that did not run, and this repo has already been
# bitten by checks that silently covered less than they claimed. So every
# uncertainty resolves to RUN:
#
#   - not a pull request (a push to main / nightly) -> run
#   - the workflow, the toolchain, the lockfile or a root manifest changed -> run
#   - a changed file cannot be attributed to a workspace crate -> run
#   - the diff cannot be computed at all -> run
#
# Only a change whose every file belongs to a crate demonstrably outside the
# closure is skipped. The cost of being wrong in that direction is a job that
# runs unnecessarily; the cost of being wrong the other way is a break that ships.
set -euo pipefail

PKG="${1:?usage: ci-affects.sh <package> [base-ref]}"

# Resolving the base is where a filter like this quietly stops working. On a
# pull_request event Actions checks out the MERGE commit, and `origin/main` is
# often not a named ref in that checkout — so the obvious `git diff origin/main`
# fails, the fail-safe fires, and every job runs forever while the filter looks
# installed. Try in order, and say which one was used.
resolve_base() {
  if [ -n "${1:-}" ]; then echo "$1"; return; fi
  if [ -n "${GITHUB_BASE_REF:-}" ] && git rev-parse --verify -q "origin/$GITHUB_BASE_REF" >/dev/null; then
    echo "origin/$GITHUB_BASE_REF"; return
  fi
  # First parent of a merge commit is the base branch tip, which is exactly what
  # refs/pull/N/merge gives us.
  if git rev-parse --verify -q "HEAD^2" >/dev/null; then echo "HEAD^1"; return; fi
  if git rev-parse --verify -q origin/main >/dev/null; then echo "origin/main"; return; fi
  echo ""
}
BASE=$(resolve_base "${2:-}")
[ -z "$BASE" ] && BASE_NOTE="no base ref could be resolved"

emit() {
  # $1 = true|false, $2 = why
  echo "$2"
  [ -n "${GITHUB_OUTPUT:-}" ] && echo "run=$1" >> "$GITHUB_OUTPUT"
  # Visible in the job list without opening the log.
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "**$PKG**: run=\`$1\` — $2" >> "$GITHUB_STEP_SUMMARY"
  exit 0
}

# A push builds the branch as a whole; only a pull request has a diff to reason
# about, and main must never be gated on one.
if [ "${GITHUB_EVENT_NAME:-pull_request}" != "pull_request" ]; then
  emit true "not a pull request — always builds"
fi

if [ -z "$BASE" ]; then
  emit true "${BASE_NOTE:-no base ref} — running rather than guessing"
fi
# Two dots, not three: against a merge commit's first parent the two-dot form is
# the PR's actual effect on the base. Three dots would ask for the merge base of
# the merge commit and its own parent, which is the parent — same answer here,
# but only by accident, and wrong the moment the base ref is a branch tip.
if ! CHANGED=$(git diff --name-only "$BASE" HEAD 2>/dev/null); then
  emit true "could not diff against $BASE — running rather than guessing"
fi
if [ -z "$CHANGED" ]; then
  emit true "no files changed against $BASE — running rather than guessing"
fi
echo "base: $BASE" >&2

# Files that can change any build regardless of which crate they sit in.
GLOBAL='^(Cargo\.lock|Cargo\.toml|rust-toolchain(\.toml)?|deny\.toml|\.cargo/|\.github/|scripts/)'
if global_hit=$(echo "$CHANGED" | grep -E "$GLOBAL" | head -3); then
  emit true "global file changed: $(echo "$global_hit" | tr '\n' ' ')"
fi

# Paths that cannot affect any compilation, dropped before attribution. Without
# this every docs-only change would hit the unattributable fail-safe and rebuild
# the world — correct, but for no reason. Kept deliberately narrow: prose, and
# nothing that any build step reads.
INERT='^(docs/|[^/]*\.md$|LICENSE|\.gitignore$|\.editorconfig$|\.gitattributes$)'
CHANGED=$(echo "$CHANGED" | grep -Ev "$INERT" || true)
if [ -z "$CHANGED" ]; then
  emit false "only prose and non-build files changed"
fi

# crate directory -> crate name, tagged IN/OUT of $PKG's closure. The graph walk
# lives in scripts/ci-closure.py; see its docstring for why it is not inline.
if ! CLOSURE=$(cargo metadata --format-version 1 2>/dev/null | python3 scripts/ci-closure.py "$PKG"); then
  emit true "could not resolve the closure of $PKG — running rather than guessing"
fi
if [ -z "$CLOSURE" ]; then
  emit true "empty closure for $PKG — running rather than guessing"
fi

reasons=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
  owner=""
  best=0
  while IFS=$'\t' read -r dir name state; do
    case "$f" in
      "$dir"/*)
        # Longest matching directory wins, so a nested crate is attributed to
        # itself rather than to an ancestor.
        if [ "${#dir}" -gt "$best" ]; then best=${#dir}; owner="$name $state"; fi
        ;;
    esac
  done <<< "$CLOSURE"

  if [ -z "$owner" ]; then
    emit true "unattributable path '$f' — running rather than guessing"
  fi
  set -- $owner
  if [ "$2" = "IN" ]; then
    reasons="$1"
    break
  fi
done <<< "$CHANGED"

if [ -n "$reasons" ]; then
  emit true "$reasons is in $PKG's dependency closure"
fi

n=$(echo "$CHANGED" | grep -c . || true)
emit false "none of the $n changed files touch $PKG's dependency closure"
