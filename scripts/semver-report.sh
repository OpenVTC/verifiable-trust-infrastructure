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
# report's; this is that reconciliation — and since release-plz's own check was
# switched off (release-plz.toml), it is the only API check a release gets.
#
# In enforce mode a crate whose proposed version is ALREADY a compatibility-
# breaking bump over its newest crates.io version (0.16.x -> 0.17.0, or
# 1.x -> 2.0.0) is not checked: no finding can demand a bigger bump than that,
# so the check cannot change the verdict, and each one costs two cold rustdoc
# builds of the crate's whole dependency tree. Those crates leave the expected
# set and are NAMED in the output with both versions, the same way the excluded
# and unpublished crates are. Report mode checks them as before.
#
# When enforce mode does find an under-bump it names each crate with the
# version it needs, and writes the crate names to `semver-raise.txt` for
# `scripts/fix-release-bump-sizes.py --raise`, which applies the raise and its
# cascade in one step (ci.yml's guard runs exactly that and pushes it).
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
# consumer can act on. Their bumps come from conventional commits, as every
# crate's proposal does now (`semver_check = false` in release-plz.toml); this
# list is the one place that decides which APIs are checked.
#
# These twelve are the subsystem crates. They are on crates.io only because a
# published crate's whole dependency closure must be published and `vta-service`
# is published (for OpenVTC's `MockVta` harness — see RELEASING.md). Nothing
# consumes their APIs directly, here or outside.
#
# `vtc-service` is here for the same reason by a different route: it is
# published as a binary (`cargo install vtc-service`), and nothing consumes its
# library API.
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
  vtc-service
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
#
# The index file is kept in $INDEX_DIR: enforce mode reads the published
# versions from it (see already_breaking).
INDEX_DIR=$(mktemp -d)
trap 'rm -rf "$INDEX_DIR"' EXIT
published_status() {
  local c="$1" code
  code=$(curl -sS -o "$INDEX_DIR/$c" -w '%{http_code}' --max-time 20 --retry 3 \
    "https://index.crates.io/$(index_path "$c")" 2>/dev/null || echo 000)
  case "$code" in
    200) echo published ;;
    404) echo absent ;;
    *) echo "unknown:$code" ;;
  esac
}

# Is PROPOSED in a newer compatibility range than EVERY version of the crate
# on crates.io? Compared on the field cargo's caret treats as the boundary: the
# major at 1.0 and above, the minor below it (the patch for 0.0.x). Taken over
# all published versions, yanked and prerelease included, so it can only err
# towards checking: a crate is skipped only when it is breaking over the newest
# of them, and so over whichever one cargo-semver-checks takes as the baseline.
# Prints the newest published version. Exit 0: already a breaking bump, skip.
# Exit 1: check it — including when the index cannot be read or parsed.
already_breaking() {
  python3 -c '
import json, re, sys

def line(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    if not m:
        return None
    ma, mi, pa = (int(x) for x in m.groups())
    return (ma,) if ma > 0 else (0, mi) if mi > 0 else (0, 0, pa)

try:
    with open(sys.argv[2]) as f:
        versions = [json.loads(l)["vers"] for l in f if l.strip()]
except (OSError, ValueError, KeyError):
    sys.exit(1)
proposed = line(sys.argv[1])
lines = [(line(v), v) for v in versions]
if proposed is None or not lines or any(l is None for l, _ in lines):
    sys.exit(1)
newest = max(lines)
print(newest[1])
sys.exit(0 if proposed > newest[0] else 1)
' "$1" "$INDEX_DIR/$2"
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
    print(p["name"], p["version"])
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
already=()   # enforce mode: "crate latest -> proposed", not checked
for entry in "${PUBLISHABLE[@]}"; do
  crate=${entry% *}
  version=${entry#* }
  skip=false
  for e in "${EXCLUDED[@]}"; do
    [ "$crate" = "$e" ] && skip=true && break
  done
  $skip && continue

  case "$(published_status "$crate")" in
    published)
      if [ "$MODE" = enforce ] && latest=$(already_breaking "$version" "$crate"); then
        already+=("$crate $latest -> $version")
      else
        expected+=("$crate")
      fi
      ;;
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
if [ ${#already[@]} -gt 0 ]; then
  echo
  echo "NOT CHECKED — the proposed version is already a breaking bump over crates.io:"
  for a in "${already[@]}"; do echo "  $a"; done
  echo "  No API change can require more than a breaking bump, so checking these"
  echo "  cannot change the verdict. Enforce mode only; report mode checks them."
fi
if [ ${#expected[@]} -eq 0 ] && [ ${#already[@]} -gt 0 ]; then
  echo
  echo "nothing left to check: every other publishable library is excluded or unpublished"
  exit 0
fi
if [ ${#expected[@]} -eq 0 ]; then
  echo "::error::nothing to check — every publishable library is either excluded or \
unpublished. That is not a pass; it is the report covering nothing."
  exit 1
fi

echo
echo "checking: ${expected[*]}"
echo

# For trying the selection without the hours of rustdoc behind it.
if [ "${SEMVER_DRY_RUN:-}" = 1 ]; then
  echo "SEMVER_DRY_RUN=1: stopping before cargo semver-checks"
  exit 0
fi

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
for a in ${already[@]+"${already[@]}"}; do
  args+=(--exclude "${a%% *}")
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
#
# But "rustdoc failed" covers three defects with three different owners — the
# published crate, the workspace copy, or a DEPENDENCY at the version this
# lockfile-free resolution picked — and this block used to call all three the
# first. That is what #1667 was: `vta-service` 0.39.0 built fine, and
# `affinidi-messaging-mediator` 0.28.33 (reached only through the optional
# `transport-harness` feature) did not. The report named our crate, and the
# reproduction it printed used default features, so it did not reach the
# dependency and did not reproduce. Attribution now lives in its own file,
# with fixtures, because getting it wrong costs the next reader the whole
# diagnosis again.
if ! python3 "$(dirname "$0")/semver-build-failure.py" semver.log; then
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
  # Same principle as the build-failure classifier above: name the cause where
  # the red is displayed. A registry fetch that fails on DNS looks, in the
  # coverage assertion's output, exactly like the unpublished-crate abort it was
  # written for — and it is not that, it is a runner network blip that a re-run
  # clears. This happened on the very PR that added the classifier (#1670),
  # which is as good an argument for saying it out loud as any.
  if grep -qE 'failed to retrieve index of crate versions from registry' semver.log; then
    echo "::error::THE REPORT IS INCOMPLETE — these crates were never checked: ${missing[*]}. \
The run aborted on a REGISTRY FETCH FAILURE (see 'failed to retrieve index of crate versions \
from registry' above, usually a DNS or connect error on the runner), not on anything in this \
branch and not on an API break. Re-run the job. If it fails the same way twice, crates.io or \
the runner's network is the thing to look at."
    exit 1
  fi
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
  # Name each under-bumped crate and the version it needs, from the tool's own
  # lines: `Checking <crate> v<baseline> -> v<proposed>` opens a crate, and a
  # `Summary semver requires new <major|minor> version` inside it is the
  # finding. Checks run one crate at a time, so the lines do not interleave.
  # The crate names go to semver-raise.txt for fix-release-bump-sizes.py.
  : > semver-raise.txt
  python3 -c '
import re, sys
cur = None
seen = []
for l in open("semver.log"):
    m = re.search(r"Checking (\S+) v(\S+) -> v(\S+) ", l)
    if m:
        cur = m.groups()
        continue
    m = re.search(r"Summary semver requires new (major|minor) version", l)
    if m and cur:
        name, base, prop = cur
        ma, mi, pa = (int(x) for x in re.match(r"(\d+)\.(\d+)\.(\d+)", base).groups())
        if m.group(1) == "major":
            need = f"{ma + 1}.0.0" if ma > 0 else f"0.{mi + 1}.0" if mi > 0 else f"0.0.{pa + 1}"
            # Only a breaking finding: --raise applies exactly that bump.
            seen.append(name)
        else:
            need = f"{ma}.{mi + 1}.0"
        print(f"::error::{name}: proposed {prop} is too small — the API change since {base} needs {need} or later")
with open("semver-raise.txt", "w") as f:
    f.write("".join(n + "\n" for n in seen))
'
  if [ -s semver-raise.txt ]; then
    echo "To fix, on the Release PR branch: python3 scripts/fix-release-bump-sizes.py --raise $(tr '\n' ' ' < semver-raise.txt)"
    echo "(it raises each crate to its next breaking version, moves its dependents' requirements, and converges the cascade)"
  fi
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
