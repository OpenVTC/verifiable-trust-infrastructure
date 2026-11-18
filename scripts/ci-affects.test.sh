#!/usr/bin/env bash
# Table tests for scripts/ci-affects.sh: changed paths -> the answer (#2659).
#
#   bash scripts/ci-affects.test.sh
#
# ci-affects.sh decides which CI jobs a pull request skips. A regression there
# does not fail anything: it produces a green run that tested nothing, or a run
# that builds everything for a typo. So its answers are pinned here, one row per
# rule, and checked in the `affects` job before that job gives any answers.
#
# Each row feeds a fixed file list through CI_AFFECTS_TEST_CHANGED (no git
# diff), as a pull request from an ordinary branch. The closure modes need
# `cargo metadata` of this checkout, as the real ones do.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

pass=0
fail=0
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# check <expected run> <head ref> <changed files, newline-separated> <ci-affects args...>
check() {
  local want=$1 head=$2 files=$3
  shift 3
  : > "$out"
  local why
  why=$(GITHUB_EVENT_NAME=pull_request GITHUB_HEAD_REF=$head GITHUB_OUTPUT=$out \
    GITHUB_STEP_SUMMARY='' CI_AFFECTS_TEST_CHANGED=$files \
    bash scripts/ci-affects.sh "$@" HEAD 2>/dev/null)
  local got
  got=$(sed -n 's/^run=//p' "$out")
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    printf 'FAIL  ci-affects.sh %s  [%s]\n      want run=%s, got run=%s: %s\n' \
      "$*" "$(tr '\n' ' ' <<< "$files")" "$want" "${got:-<none>}" "$why"
  fi
}

br=feat/x

# ── Fail-safes and global files ──────────────────────────────────────────
check true  "$br" "Cargo.lock"                          vta-mobile-core
check true  "$br" "Cargo.toml"                          --own vta-mobile-core
check true  "$br" "rust-toolchain.toml"                 vta-enclave
check true  "$br" ".github/workflows/ci.yml"            vtc-service,vtc-client
check true  "$br" "scripts/ci-affects.sh"               --any
check true  "$br" "not-a-crate/file.rs"                 vta-mobile-core
check false release-plz-2026-11-13T00-00-00Z "vta-sdk/src/lib.rs" vta-mobile-core

# ── Prose ────────────────────────────────────────────────────────────────
check false "$br" "docs/x.md"                           --any
check false "$br" $'README.md\ndocs/02-vta/a.md'        vta-enclave
check true  "$br" $'docs/x.md\nvta-sdk/src/lib.rs'      --any

# ── Closures ─────────────────────────────────────────────────────────────
check true  "$br" "vta-sdk/src/lib.rs"                  vta-enclave
check false "$br" "vtc-service/src/main.rs"             vta-enclave
check false "$br" "vtc-service/src/main.rs"             --except vtc-service
check true  "$br" "vtc-client/src/lib.rs"               --except vtc-service
check true  "$br" "vtc-client/src/lib.rs"               vtc-service,vtc-client
check false "$br" "vta-sdk/src/lib.rs"                  --own vta-mobile-core
check true  "$br" "vta-mobile-core/src/lib.rs"          --own vta-mobile-core

# ── MSRV (--toolchain) ───────────────────────────────────────────────────
check true  "$br" "vta-sdk/Cargo.toml"                  --toolchain
check true  "$br" "rust-toolchain.toml"                 --toolchain
check false "$br" "vta-sdk/src/lib.rs"                  --toolchain

# ── --paths ──────────────────────────────────────────────────────────────
check true  "$br" "deploy/nitro/enclave-proxy/src/main.rs" --paths '^deploy/nitro/enclave-proxy/'
check false "$br" "vta-sdk/src/lib.rs"                  --paths '^deploy/nitro/enclave-proxy/'

echo "ci-affects.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
