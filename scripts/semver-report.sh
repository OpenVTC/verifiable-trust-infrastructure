#!/usr/bin/env bash
# Run cargo-semver-checks over the published workspace crates, and — the part
# that matters — make it impossible for the report to cover less than it claims.
#
# # The failure this exists to stop
#
# `cargo semver-checks --workspace` does not skip a crate that has never been
# published. It aborts the entire run:
#
#     error: failed to retrieve index of crate versions from registry
#     Caused by:
#         vti-rooms not found in registry (crates.io).
#
# exit code 101, on the first such crate it reaches. Every crate ordered after
# it is never checked — and the job's exit status is non-zero either way, which
# is exactly what a declared API break produces. So the report silently shrank
# to a subset of the workspace and looked identical to a report that had run in
# full and found a break.
#
# That happened when `vti-rooms` entered the workspace. From that commit until
# this script, the semver report had checked `vti-common` and `vti-secrets` and
# then stopped, and nothing said so. The job comment in ci.yml already warns
# about this shape of bug twice — "a dead check sat unnoticed", "one red looked
# like another" — and the third instance still got in, because both existing
# guards ask *why did it stop* and neither asks *did it cover everything*.
#
# # What this does instead
#
# It derives the expected coverage rather than trusting a hand-written list:
#
#   1. every publishable workspace member that has a LIBRARY target, from
#      `cargo metadata` — a binary-only crate (pnm-cli, cnm-cli) exposes no API
#      to a consumer, so cargo-semver-checks analyses nothing and prints
#      nothing for it. Expecting those was this assertion's own first bug,
#      caught by running it locally before pushing;
#   2. minus the ones deliberately excluded for runtime (see EXCLUDED below);
#   3. minus the ones with no crates.io baseline yet, looked up in the sparse
#      index — those genuinely cannot be checked, and are NAMED in the output
#      rather than passed over;
#
# then runs the tool and asserts it actually reported on that set. A crate that
# should have been checked and was not is a hard error, whatever the reason.
#
# A crate appearing in (3) is normal exactly once in its life: between merging
# and its first release. If one sits there across several releases, something is
# wrong with the release, not with this script.
#
# # Two modes
#
# `SEMVER_MODE=report` (default) — on an ordinary PR. A break is EXPECTED and
# allowed; the job reports it so the release can move the compatibility field.
#
# `SEMVER_MODE=enforce` — on a release-plz branch, where the manifest already
# carries the version about to be published. cargo-semver-checks derives the
# release type from the real delta (0.16.1 -> 0.16.2 is a patch), so a break
# under that delta means the PROPOSED BUMP IS TOO SMALL and the release is about
# to ship a breaking change as a compatible one. That is the one place this must
# block rather than report.
#
# Why the guard exists: release-plz runs cargo-semver-checks itself and is meant
# to raise the bump on its own. On 2026-09-05 it reported `vti-common: next
# version is 0.16.2 (✓ API compatible changes)` for a release where the same
# tool, on the same baseline, failed `enum_variant_added` on two exhaustive
# enums — and `vta-sdk: 0.32.4` where 16 public wire structs had gained a field.
# Both would have gone out as patch releases that `^0.16` and `^0.32` consumers
# take automatically. Nothing reconciled release-plz's verdict against the
# report's; this is that reconciliation.
set -euo pipefail

MODE="${SEMVER_MODE:-report}"
case "$MODE" in
  report | enforce) ;;
  *)
    echo "::error::SEMVER_MODE must be 'report' or 'enforce', got '$MODE'"
    exit 1
    ;;
esac

# Excluded for RUNTIME, not because a break there is acceptable. This job builds
# rustdoc JSON for every crate twice, current and baseline; including these took
# it from ~17 minutes to over 35, on every pull request, for a signal no
# consumer can act on. `release-plz.toml` carries the matching
# `semver_check = false` so the release decides bumps the same way.
#
# These twelve are the subsystem crates. They are on crates.io only because a
# published crate's whole dependency closure must be published and `vta-service`
# is published (for OpenVTC's `MockVta` harness — see RELEASING.md). Nothing
# consumes their APIs directly, here or outside.
#
# `vta-service` is deliberately NOT here: it has a real consumer (openvtc-core
# dev-depends on it for MockVta), so a silent break there reaches somebody.
# Which is why the truncation mattered — `vta-service` sorts after `vti-rooms`
# in the tool's ordering, so the one crate kept in the check for having a real
# consumer was among those the abort skipped.
EXCLUDED=(
  vta-audit
  vta-backup
  vta-config
  vta-keys
  vta-keyspaces
  vta-policy
  vta-support
  vta-sweepers
  vta-tee
  vta-vault
  vta-webvh
  vti-webauthn
)

# The sparse-index path for a crate name, per the registry layout.
index_path() {
  local c="$1"
  case ${#c} in
    1) printf '1/%s' "$c" ;;
    2) printf '2/%s' "$c" ;;
    3) printf '3/%s/%s' "${c:0:1}" "$c" ;;
    *) printf '%s/%s/%s' "${c:0:2}" "${c:2:2}" "$c" ;;
  esac
}

# Is this crate on crates.io at all? Any answer other than a clean 200 or 404 is
# treated as "unknown" and fails loudly further down: a network blip must not
# quietly become "unpublished, skip it", because that is the same silent
# shrinking this script exists to prevent.
published_status() {
  local c="$1" code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 --retry 3 \
    "https://index.crates.io/$(index_path "$c")" 2>/dev/null || echo 000)
  case "$code" in
    200) echo published ;;
    404) echo absent ;;
    *) echo "unknown:$code" ;;
  esac
}

# Read with `while read` rather than `mapfile`: mapfile is bash 4+, macOS ships
# 3.2, and a guard script that only runs in CI cannot be tried before it is
# pushed. This one was worth being able to run locally.
PUBLISHABLE=()
while IFS= read -r line; do
  [ -n "$line" ] && PUBLISHABLE+=("$line")
done < <(
  cargo metadata --no-deps --format-version 1 \
    | python3 -c '
import json, sys

LIB = {"lib", "rlib", "proc-macro", "dylib", "cdylib"}
for p in json.load(sys.stdin)["packages"]:
    # `publish` is null when unrestricted, [] when `publish = false`.
    if p.get("publish") is not None:
        continue
    # A binary has no public API a downstream crate can depend on, so
    # cargo-semver-checks has nothing to compare and emits no line for it.
    if not any(k in LIB for t in p["targets"] for k in t["kind"]):
        continue
    print(p["name"])
' \
    | sort
)

if [ ${#PUBLISHABLE[@]} -eq 0 ]; then
  echo "::error::no publishable library crates found — cargo metadata changed shape"
  exit 1
fi

expected=()
unpublished=()
unknown=()
for crate in "${PUBLISHABLE[@]}"; do
  skip=false
  for e in "${EXCLUDED[@]}"; do
    [ "$crate" = "$e" ] && skip=true && break
  done
  $skip && continue

  case "$(published_status "$crate")" in
    published) expected+=("$crate") ;;
    absent) unpublished+=("$crate") ;;
    unknown:*) unknown+=("$crate") ;;
  esac
done

if [ ${#unknown[@]} -gt 0 ]; then
  echo "::error::could not determine whether these crates are published: ${unknown[*]}. \
The registry did not answer 200 or 404. Treating that as 'unpublished' would shrink this \
report without saying so, which is the exact failure this script exists to prevent."
  exit 1
fi

echo "publishable libraries: ${#PUBLISHABLE[@]}   excluded for runtime: ${#EXCLUDED[@]}"
if [ ${#unpublished[@]} -gt 0 ]; then
  echo
  echo "NOT CHECKED — no crates.io baseline yet: ${unpublished[*]}"
  echo "  A crate has no baseline between merging and its first release, so this is"
  echo "  expected once. If one of these is still here after a release has gone out,"
  echo "  the release did not publish it and that is the thing to look at."
fi
if [ ${#expected[@]} -eq 0 ]; then
  echo "::error::nothing to check — every publishable library is either excluded or \
unpublished. That is not a pass; it is the report covering nothing."
  exit 1
fi

echo
echo "checking: ${expected[*]}"
echo

# `${arr[@]+"${arr[@]}"}` rather than a plain `"${arr[@]}"`: expanding an EMPTY
# array under `set -u` is an unbound-variable error in bash 3.2, and `unpublished`
# is empty exactly when every crate has a baseline — the normal, healthy state
# this script is meant to reach. It failed the first time it got there.
#
# Bash 4.4+ made the plain form safe, so CI (bash 5) would never have shown this.
# The portability that let the script run on a laptop is also what found it.
args=(--workspace)
for c in "${EXCLUDED[@]}" ${unpublished[@]+"${unpublished[@]}"}; do
  args+=(--exclude "$c")
done

# ANSI is stripped rather than left in. GitHub's runner makes cargo emit colour
# even though stdout is a pipe, so the log this script greps carries escapes
# locally-absent and CI-present — which is the worst kind of difference, one
# that makes a check pass on a laptop and silently match nothing in CI. The
# coverage assertion below greps for `Finished [..] <crate>`, and in CI the
# reset sequence sits between `Finished` and the bracket.
#
# The escape is built with printf rather than written as `\x1b`, which BSD sed
# does not understand — the same laptop-versus-CI split, one layer down.
ESC=$(printf '\033')
set +e
cargo semver-checks "${args[@]}" 2>&1 \
  | sed -E "s/${ESC}\[[0-9;]*[mK]//g" \
  | tee semver.log
status=${PIPESTATUS[0]}
set -e

# A failed baseline is NOT a CI inconvenience — it is a production defect, and
# this check is the only thing in the repo that resolves like a consumer does
# (cargo add into a fresh crate, no lockfile), so it is the only thing that can
# notice when a *published* artifact stops building.
if grep -qE 'failed to build rustdoc|running cargo-doc on crate' semver.log; then
  broken="$(grep -oE 'failed to build rustdoc for crate [a-z0-9-]+' semver.log \
    | sed 's/failed to build rustdoc for crate //' | sort -u | tr '\n' ' ')"
  echo "::error::PUBLISHED CRATE DOES NOT BUILD: ${broken}-- the semver \
baseline is the published crate as a consumer receives it, so a baseline that \
fails to build means consumers cannot build it either. This is not 'the check \
could not run'; it is the check reporting a broken artifact on crates.io. \
Reproduce: cargo new --lib x && cd x && echo '[workspace]' >> Cargo.toml && \
cargo add ${broken%% *} && cargo build"
  exit 1
fi

# The coverage assertion, and the reason this script exists. Every crate that
# should have been checked must appear in the log as one the tool finished. If
# the run aborted part-way — for the unpublished-crate reason, or any future one
# nobody has met yet — the missing names are printed instead of the shortfall
# passing as an ordinary red.
missing=()
for crate in ${expected[@]+"${expected[@]}"}; do
  grep -qE "Finished \[[^]]*\] ${crate}\$" semver.log || missing+=("$crate")
done

if [ ${#missing[@]} -gt 0 ]; then
  echo
  echo "::error::THE REPORT IS INCOMPLETE — these crates were never checked: ${missing[*]}. \
The run stopped before reaching them, so their public APIs were compared against nothing. \
A truncated report exits non-zero exactly like a declared API break, which is how this went \
unnoticed once already: check the log above for the abort, do not read the red as 'a break \
was found'."
  exit 1
fi

echo
echo "coverage: all ${#expected[@]} expected crates were checked"

if [ "$status" -eq 0 ]; then
  echo "all baselines built; no API breaks reported"
  exit 0
fi

if [ "$MODE" = "enforce" ]; then
  echo "::error::THE PROPOSED RELEASE UNDER-BUMPS A BREAKING CHANGE. Each version above \
is the one about to be published, so cargo-semver-checks derived the release type from the \
real delta — and a failure means that delta is too small, not that breaking is forbidden. \
Shipping this would hand consumers a compile break on a version their caret requirement \
picks up automatically. Raise each failing crate to its breaking slot: for a 0.x crate that \
is the MINOR field (0.16.1 -> 0.17.0), not the patch. Alternatively make the change \
non-breaking (\`#[non_exhaustive]\` on a struct or enum that should never have been \
exhaustively constructible) and re-run."
  exit "$status"
fi

echo "::warning::API breaks reported — expected on a PR marked '!'; the \
release moves the compatibility field accordingly."
exit "$status"
