#!/usr/bin/env bash
# Guard against the "Cargo.lock pins a STALE crates.io copy of one of our own
# workspace crates" trap that kept the Publish job red on main.
#
# This is the sibling failure to the one check-version-bumps.sh catches. There,
# the version bump was *missing*. Here the bump is present and correct, and the
# release still breaks.
#
# What happened: a transitive DEV-dependency pulls one of our own crates back in
# from crates.io —
#
#   vtc-service [dev-dependencies]
#     -> affinidi-messaging-test-mediator
#       -> affinidi-messaging-mediator
#         -> vta-sdk   (registry, NOT the workspace path copy)
#
# so Cargo.lock carries TWO vta-sdk nodes: the workspace path copy at the local
# version, and a registry copy pinned at whatever was current when that
# dependency was last resolved.
#
# The publish workflow runs `cargo publish --locked`. For a dependent crate
# (pnm-cli), cargo's verification build swaps the workspace path dep for a
# registry one — and `--locked` makes it reuse the lockfile's already-pinned
# registry node rather than resolving the newest match. So pnm-cli 0.11.2 was
# verified against vta-sdk 0.19.11 even though the same run had just published
# vta-sdk 0.19.12, and the build failed with E0599 on `TspPingSession::
# probe_send` — an API that only exists in 0.19.12. pnm-cli then sat unpublished
# for three releases while the workspace build stayed green the whole time,
# because the path deps always saw the new source.
#
# Dropping `--locked` would "fix" this by making releases non-reproducible.
# Instead this guard keeps the lockfile honest: whenever a publishable workspace
# crate also appears in Cargo.lock as a registry package, the two versions must
# agree. Refreshing the pin is a one-line `cargo update` that the PR author runs
# alongside the version bump.
#
# One case is NOT a failure: a PR that bumps a workspace crate sets the local
# version to something not yet on crates.io, so the pin CANNOT be refreshed —
# `cargo update --precise <new>` fails with "no matching package". Demanding
# equality there makes this guard and check-version-bumps.sh mutually
# unsatisfiable: one requires the bump, the other forbids its consequence. So
# an unpublished local version is reported and allowed; the publish workflow
# refreshes the pin immediately after publishing the crate, which is the only
# moment the refresh is actually possible.
#
# STATUS: the workspace now carries a `[patch.crates-io]` entry for every crate
# that was being pulled back in (see the root Cargo.toml), so the registry
# copies no longer exist and this guard passes with "nothing to check". That is
# the expected steady state, not a sign the check has been defeated.
#
# Keep it anyway. It is the tripwire that says a NEW self-pin has appeared —
# a fresh dev-dependency chain reaching one of our crates — and needs its own
# patch entry. Without it, the first sign would be a dependent published against
# stale source.
#
# Usage: scripts/check-lockfile-self-pins.sh
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; CYAN=''; NC=''
fi

if [ ! -f Cargo.lock ]; then
  echo "${RED}error:${NC} Cargo.lock not found at $ROOT" >&2
  exit 2
fi

REGISTRY='https://github.com/rust-lang/crates.io-index'
UA='vti-lockfile-guard (https://github.com/OpenVTC/verifiable-trust-infrastructure)'

# Is $1@$2 already on crates.io?  0 = published, 1 = not, 2 = undeterminable.
# Mirrors the check the publish workflow uses to skip already-published crates.
crate_is_published() {
  local name="$1" version="$2" status
  status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -H "User-Agent: $UA" \
    "https://crates.io/api/v1/crates/${name}/${version}" 2>/dev/null) || return 2
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *) return 2 ;;
  esac
}

# Publishable workspace members as  name<TAB>version.
members=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | select(.publish == null or .publish == ["crates.io"])
      | "\(.name)\t\(.version)"')

if [ -z "$members" ]; then
  echo "${RED}error:${NC} could not read workspace members" >&2
  exit 2
fi

# Registry-sourced packages in Cargo.lock as  name<TAB>version. Only entries
# carrying a `source = "registry+..."` line are registry copies; the workspace
# path copies have no source field.
locked=$(awk '
  /^\[\[package\]\]/ { name=""; version=""; src=""; next }
  /^name = / { gsub(/^name = "|"$/, ""); name=$0; next }
  /^version = / { gsub(/^version = "|"$/, ""); version=$0; next }
  /^source = "registry\+/ { src=1;
    if (name != "" && version != "") print name "\t" version;
    next }
' Cargo.lock)

echo "${CYAN}=== Lockfile self-pin guard ===${NC}"
echo ""

fail=0
found=0
bumping=0
while IFS=$'\t' read -r name version; do
  [ -z "$name" ] && continue
  # Is this workspace crate also present as a registry package?
  pinned=$(printf '%s\n' "$locked" | awk -F'\t' -v n="$name" '$1 == n { print $2 }' | head -1)
  [ -z "$pinned" ] && continue
  found=1
  if [ "$pinned" = "$version" ]; then
    echo "  ${GREEN}ok${NC}   $name: workspace $version == locked registry copy $pinned"
  else
    # `|| published=$?` is required: under `set -e` a bare call returning
    # non-zero would abort the script before the case statement runs.
    published=0
    crate_is_published "$name" "$version" || published=$?
    case "$published" in
      1)
        # Bump in flight: the local version does not exist on crates.io, so the
        # pin cannot point at it yet. publish.yml refreshes it after publishing.
        echo "  ${CYAN}bump${NC} $name: workspace $version not yet on crates.io (registry copy pinned at $pinned)"
        echo "         no action — the publish workflow refreshes this pin once $version is published"
        bumping=1
        ;;
      2)
        # Could not reach crates.io. Fail closed: a guard that passes when it
        # cannot verify is not a guard, and this ran green on every other job
        # in the same workflow, so the network is normally fine.
        echo "  ${RED}ERROR${NC} $name: could not reach crates.io to check whether $version is published"
        echo "         re-run the job; if crates.io is down, merge on the other checks"
        fail=1
        ;;
      *)
        echo "  ${RED}STALE${NC} $name: workspace $version but Cargo.lock pins registry copy at $pinned"
        echo "         fix: cargo update -p '$REGISTRY#$name@$pinned' --precise $version"
        fail=1
        ;;
    esac
  fi
done <<EOF
$members
EOF

echo ""
if [ "$found" -eq 0 ]; then
  echo "${GREEN}No workspace crate is pulled back in from crates.io — nothing to check.${NC}"
  exit 0
fi

if [ "$fail" -eq 0 ]; then
  if [ "$bumping" -eq 1 ]; then
    echo "${GREEN}No stale self-pins.${NC} A pending version bump is awaiting publish (see above)."
  else
    echo "${GREEN}All self-pins match the workspace versions.${NC}"
  fi
else
  echo "${RED}Cargo.lock pins a stale crates.io copy of a workspace crate.${NC}"
  echo "\`cargo publish --locked\` verifies dependent crates against that pinned copy,"
  echo "so a dependent will be built against the OLD source and fail to compile —"
  echo "silently, since the workspace's own path-dep build stays green."
  echo "Run the cargo update shown above and commit the Cargo.lock change."
  exit 1
fi
