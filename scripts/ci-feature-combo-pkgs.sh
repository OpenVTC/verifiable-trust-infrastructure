#!/usr/bin/env bash
# The packages one `Feature combos (<group>)` job builds, as a comma-separated
# list for scripts/ci-affects.sh.
#
#   scripts/ci-feature-combo-pkgs.sh features-rooms [workflow]
#   scripts/ci-feature-combo-pkgs.sh --list [workflow]
#
# The argument is the group's job KEY in ci.yml. `--list` prints every group's
# key, one per line: every job whose `name:` starts with `Feature combos (`,
# except `Feature combos (all-features)`, which is workspace-wide by design and
# gated separately.
#
# Derived from the job itself, never listed. A hand-written "these are the
# crates Feature combos covers" would be a second description of what the job's
# own steps say, and ci-affects.sh's docstring records that two descriptions of
# one thing have already drifted apart three times in this repo (#1252, #1256,
# #1259). A step added tomorrow for a new package is covered with no edit here.
#
# `Feature combos` used to be one job, and this script read its one block. It is
# now several parallel groups, and each group is gated on its OWN packages, so a
# vti-rooms change does not wait for the vta-service tests.
#
# # The --workspace guard
#
# This only works while every step is package-scoped. One `--workspace`
# invocation in a group means it builds crates no `-p` flag names, and a gate
# computed from the `-p` flags would then be narrower than the job — skipping
# it for a change it would actually have caught. That is the one failure this
# filter must not have, so it is refused rather than approximated: a
# `--workspace` step belongs in a job of its own (see `features-all`).
# `--list` applies the guard to every group, so one call checks them all.
set -euo pipefail

usage() {
  echo "usage: ci-feature-combo-pkgs.sh <job-key> [workflow] | --list [workflow]" >&2
  exit 2
}

KEY="${1:-}"
[ -n "$KEY" ] || usage
WORKFLOW="${2:-.github/workflows/ci.yml}"

# Every job key whose name is `Feature combos (...)`, minus the all-features one.
group_keys() {
  awk '
    /^  [a-z][a-z0-9_-]*:$/ { key = substr($1, 1, length($1) - 1) }
    /^    name: Feature combos \(/ && !/\(all-features\)/ { print key }
  ' "$WORKFLOW"
}

# One job block: from its key to the next top-level job key.
job_block() {
  awk -v k="  $1:" '
    $0 == k { f = 1; print; next }
    f && /^  [a-z][a-z0-9_-]*:$/ { exit }
    f { print }
  ' "$WORKFLOW"
}

pkgs_for() {
  local key="$1" block commands pkgs
  block=$(job_block "$key")
  if [ -z "$block" ]; then
    echo "could not find the '$key:' job in $WORKFLOW" >&2
    return 1
  fi
  if ! echo "$block" | grep -qE '^    name: Feature combos \('; then
    echo "'$key' is not a Feature combos group job in $WORKFLOW" >&2
    return 1
  fi

  # Ignore comment lines: the prose in these jobs discusses `cargo test
  # --workspace` at length, and matching that would refuse a job that is
  # perfectly fine.
  commands=$(echo "$block" | grep -vE '^\s*#')

  if echo "$commands" | grep -qE 'cargo [a-z]+([^#]*)--workspace'; then
    echo "refusing: Feature combos job '$key' has a --workspace step, so the" >&2
    echo "packages its -p flags name are not the full set it builds. Move that" >&2
    echo "step to the features-all job, or this filter will under-cover it:" >&2
    echo "$commands" | grep -nE 'cargo [a-z]+([^#]*)--workspace' >&2
    return 1
  fi

  pkgs=$(echo "$commands" | grep -oE '\-p [a-z0-9_-]+' | awk '{print $2}' | sort -u)
  if [ -z "$pkgs" ]; then
    echo "no -p flags found in the '$key' job — refusing to emit an empty scope" >&2
    return 1
  fi
  echo "$pkgs" | paste -sd, -
}

if [ "$KEY" = "--list" ]; then
  keys=$(group_keys)
  if [ -z "$keys" ]; then
    echo "no 'Feature combos (...)' group jobs found in $WORKFLOW" >&2
    exit 1
  fi
  for k in $keys; do
    pkgs_for "$k" >/dev/null
  done
  echo "$keys"
  exit 0
fi

pkgs_for "$KEY"
