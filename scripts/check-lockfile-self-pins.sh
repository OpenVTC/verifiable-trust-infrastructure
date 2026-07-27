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
# ── The second failure mode: the patch itself stops applying ──────────────────
#
# Everything above treats a stale pin as REFRESHABLE — publish the new version,
# run `cargo update --precise`, done. That holds for a PATCH bump (0.19.11 ->
# 0.19.12): a dependent requiring `^0.19` accepts the new version, so the patch
# keeps applying and the pin can be moved.
#
# It does NOT hold for a MINOR bump. Under 0.x semver `^0.19` excludes 0.20, so
# the moment a patched crate goes 0.19 -> 0.20, an external dependent pinning
# `^0.19` can no longer be satisfied by the patched path copy — cargo silently
# stops applying the patch and reinstates the registry node the patch existed to
# delete. No local `cargo update` can fix that; it needs the DEPENDENT's
# requirement bumped and re-released upstream.
#
# The published-or-not test above cannot distinguish the two. At PR time the new
# version is unpublished either way, so both take the "bump in flight" branch and
# pass. That is exactly how vta-sdk 0.20.0 (#797) merged 12/12 and broke main
# ~52s later, when the publish workflow closed the escape hatch.
#
# So ask the question that IS answerable locally, with no network and no
# dependence on publish state: **is each `[patch.crates-io]` entry still
# applying?** A patched crate must have NO registry-sourced node in Cargo.lock —
# deleting that node is the entire point of the patch. If one is present, the
# patch has broken. That check runs before the version comparison below and
# fails hard, because there is no in-flight state where it is legitimately true.
#
# Usage: scripts/check-lockfile-self-pins.sh
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

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

# Crate names listed under `[patch.crates-io]` in the root manifest. Reads the
# section between that header and the next `[`, taking the key from each
# `name = ...` line. Table-syntax entries (`[patch.crates-io.foo]`) are matched
# too, since a bare `[` would otherwise end the section at one.
patched=$(awk '
  /^\[patch\.crates-io\.[A-Za-z0-9_-]+\]/ {
    line=$0; sub(/^\[patch\.crates-io\./, "", line); sub(/\]$/, "", line);
    print line; next }
  /^\[patch\.crates-io\]/ { inpatch=1; next }
  /^\[/ { inpatch=0 }
  inpatch && /^[A-Za-z0-9_-]+ *=/ { sub(/ *=.*$/, ""); print }
' Cargo.toml)

echo "${CYAN}=== Lockfile self-pin guard ===${NC}"
echo ""

fail=0
found=0
bumping=0

# ── 1. Is every `[patch.crates-io]` entry still applying? ─────────────────────
#
# Checked first: a broken patch makes the version comparison below report the
# right crate for the wrong reason, and suggest a `cargo update` that cannot
# work. No crates.io call — the answer is in the lockfile.
for p in $patched; do
  [ -z "$p" ] && continue
  pinned=$(printf '%s\n' "$locked" | awk -F'\t' -v n="$p" '$1 == n { print $2 }' | head -1)
  [ -z "$pinned" ] && continue   # no registry node: the patch is applying

  workspace_version=$(printf '%s\n' "$members" \
    | awk -F'\t' -v n="$p" '$1 == n { print $2 }' | head -1)

  echo "  ${RED}PATCH BROKEN${NC} $p: patched to the workspace copy${workspace_version:+ ($workspace_version)}, but Cargo.lock still carries a registry copy at $pinned"
  echo "         An external dependent's semver requirement excludes the workspace"
  echo "         version, so \`[patch.crates-io] $p\` no longer applies and the"
  echo "         registry node it exists to delete is back."
  echo ""
  echo "         ${CYAN}cargo update cannot fix this${NC} — no published version satisfies both"
  echo "         sides. Find the dependent still requiring the old range:"
  echo "           cargo tree -i '$p@$pinned'"
  echo "         then bump ITS requirement upstream, release it, and move that pin"
  echo "         here first (the dependent's own lock entry constrains the update):"
  echo "           cargo update -p <dependent> --precise <new-version>"
  fail=1
  found=1
done

# ── 2. Where a self-pin legitimately exists, does it match the workspace? ─────
while IFS=$'\t' read -r name version; do
  [ -z "$name" ] && continue
  # Already reported by the patch check above. Reporting it twice would offer
  # a `cargo update --precise` that cannot work, which is the advice that sent
  # the 0.20 incident down a dead end.
  if printf '%s\n' "$patched" | grep -qx -- "$name"; then
    continue
  fi
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
  echo "${RED}Cargo.lock carries a crates.io copy of a workspace crate.${NC}"
  echo "\`cargo publish --locked\` verifies dependent crates against that pinned copy,"
  echo "so a dependent will be built against the OLD source and fail to compile —"
  echo "silently, since the workspace's own path-dep build stays green."
  echo ""
  echo "For a ${CYAN}STALE${NC} pin: run the cargo update shown above and commit Cargo.lock."
  echo "For a ${CYAN}PATCH BROKEN${NC} entry: the fix is upstream, not here — bump the"
  echo "dependent's requirement, release it, then move its pin. See the note at the"
  echo "top of this script for why no local update can resolve it."
  exit 1
fi
