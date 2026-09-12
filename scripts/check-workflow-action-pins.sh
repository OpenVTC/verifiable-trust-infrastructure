#!/usr/bin/env bash
# Every `uses:` in this repository must name a 40-hex commit SHA.
#
# ## What this is protecting
#
# A third-party action runs with the job's token and the job's secrets. `@v4`,
# `@stable` and `@cargo-llvm-cov` are all MOVABLE names: a tag can be deleted
# and recreated on new code, and a branch moves whenever its author pushes. So
# a green CI run says nothing about what will run on the next one, and the
# repository has already been on the wrong side of that — `dtolnay/rust-
# toolchain@stable` resolved to 4360b525 on 2026-09-02 and to 6bed0761 nine
# days later, on jobs that included `publish.yml`, which holds `id-token:
# write` and mints a crates.io token.
#
# A SHA cannot be repointed. Pinning is not a nicety here: crates.io Trusted
# Publishing means this repository's workflows ARE the publishing credential.
#
# ## What it checks
#
# 1. Every `uses:` ref is `owner/repo@<40 hex>` (or a local `./` action, which
#    is part of this commit and so already pinned by definition).
# 2. Each pin carries a trailing `# vX.Y.Z` comment. That comment is not
#    decoration — it is what makes the pin legible to a human reviewer, and
#    Dependabot reads and rewrites it when it moves the SHA. A pin with no
#    comment is a pin nobody will ever update.
#
# The org-level "require actions to be pinned to a full-length commit SHA"
# policy enforces (1) for real, once it is enabled. This runs in the meantime,
# it also enforces (2), and it fails the PR that introduces the problem rather
# than the run after it.
set -euo pipefail

# Filled with a read loop rather than `mapfile`, which is bash 4 and therefore
# absent on a macOS developer machine. This guard is meant to be runnable
# before it is pushed.
files=()
while IFS= read -r f; do
  files+=("$f")
done < <(git ls-files -- \
  '.github/workflows/*.yml' '.github/workflows/*.yaml' \
  '.github/actions/**/action.yml' '.github/actions/**/action.yaml')

if [ "${#files[@]}" -eq 0 ]; then
  echo "::error::no workflow files found — this guard is looking in the wrong place"
  exit 1
fi

bad=0
checked=0

while IFS= read -r hit; do
  file=${hit%%:*}
  rest=${hit#*:}
  lineno=${rest%%:*}
  text=${rest#*:}

  # The ref is the first whitespace-delimited token after `uses:`.
  ref=$(printf '%s\n' "$text" | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]].*//')
  # The version comment, if any, is what follows a `#` after that token.
  comment=$(printf '%s\n' "$text" \
    | sed -nE 's/.*uses:[[:space:]]*[^[:space:]]+[[:space:]]+#[[:space:]]*(.+)$/\1/p')

  case "$ref" in
    # A local action or reusable workflow is this commit's own content.
    ./* | docker://*) continue ;;
  esac

  checked=$((checked + 1))

  if [[ ! "$ref" =~ ^[^@]+@[0-9a-f]{40}$ ]]; then
    printf '%s:%s: not pinned to a 40-hex commit SHA: %s\n' "$file" "$lineno" "$ref"
    bad=1
    continue
  fi

  if [ -z "$comment" ]; then
    printf '%s:%s: pinned, but with no `# vX.Y.Z` comment: %s\n' "$file" "$lineno" "$ref"
    bad=1
  fi
done < <(grep -HnE '^[[:space:]]*(-[[:space:]]+)?uses:' "${files[@]}")

if [ "$bad" -ne 0 ]; then
  echo "::error::every \`uses:\` must be pinned to a 40-hex commit SHA with a \`# vX.Y.Z\` comment"
  cat <<'MSG'

Resolve the tag to a commit and write both, for example:

  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

To find the SHA a tag points at (dereferencing an annotated tag):

  gh api repos/actions/checkout/git/ref/tags/v7 --jq .object

If the only refs an action publishes are BRANCHES, do not pin the branch tip:
there is nothing for Dependabot to bump afterwards. Either inline what the
action does (this repo installs Rust with `rustup` for exactly that reason) or
use the action's versioned entry point with the tool named in `with:`.
MSG
  exit 1
fi

echo "all $checked external \`uses:\` refs are pinned to a commit SHA with a version comment"
