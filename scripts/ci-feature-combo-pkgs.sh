#!/usr/bin/env bash
# The packages the `Feature combos` job builds, as a comma-separated list for
# scripts/ci-affects.sh.
#
# Derived from the job itself, never listed. A hand-written "these are the
# crates Feature combos covers" would be a second description of what the job's
# own steps say, and ci-affects.sh's docstring records that two descriptions of
# one thing have already drifted apart three times in this repo (#1252, #1256,
# #1259). A step added tomorrow for a new package is covered with no edit here.
#
# # The --workspace guard
#
# This only works while every step is package-scoped. One `--workspace`
# invocation in the job means it builds crates no `-p` flag names, and a gate
# computed from the `-p` flags would then be narrower than the job — skipping
# it for a change it would actually have caught. That is the one failure this
# filter must not have, so it is refused rather than approximated: a
# `--workspace` step belongs in a job of its own (see `features-all`).
set -euo pipefail

WORKFLOW="${1:-.github/workflows/ci.yml}"

# The `features:` job block: from its key to the next top-level job key.
block=$(awk '/^  features:$/{f=1} f{print} f && /^  [a-z][a-z0-9_-]*:$/ && !/^  features:$/{exit}' "$WORKFLOW")

if [ -z "$block" ]; then
  echo "could not find the 'features:' job in $WORKFLOW" >&2
  exit 1
fi

# Ignore comment lines: the prose in this job discusses `cargo test --workspace`
# at length, and matching that would refuse a job that is perfectly fine.
commands=$(echo "$block" | grep -vE '^\s*#')

if echo "$commands" | grep -qE 'cargo [a-z]+([^#]*)--workspace'; then
  echo "refusing: the Feature combos job has a --workspace step, so the packages" >&2
  echo "its -p flags name are not the full set it builds. Move that step to the" >&2
  echo "features-all job, or this filter will under-cover it:" >&2
  echo "$commands" | grep -nE 'cargo [a-z]+([^#]*)--workspace' >&2
  exit 1
fi

pkgs=$(echo "$commands" | grep -oE '\-p [a-z0-9_-]+' | awk '{print $2}' | sort -u)

if [ -z "$pkgs" ]; then
  echo "no -p flags found in the features job — refusing to emit an empty scope" >&2
  exit 1
fi

echo "$pkgs" | paste -sd, -
