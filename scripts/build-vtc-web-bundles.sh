#!/usr/bin/env bash
# Build vtc-service's two web bundles into the source tree, where the crates.io
# package picks them up:
#
#   vtc-service/admin-ui/dist          the admin console   (`npm run build`)
#   vtc-service/admin-ui/dist-members  the member portal   (`npm run build:members`)
#
# Run before `cargo package` / `cargo publish -p vtc-service`. publish.yml runs
# it in the release job, ahead of release-plz, whose `cargo publish` runs in this
# checkout. Not in the Release PR job: release-plz copies the project to a temp
# directory there honouring .gitignore, so the bundles would not reach its
# package comparison anyway. That comparison then never finds vtc-service equal
# to its crates.io copy, which is harmless — release-plz stops walking history
# at the commit the published package records (`.cargo_vcs_info.json`), so it
# still counts only the commits since.
#
# Why the package carries built output rather than the npm project: a crate
# built from crates.io has no business running npm. It would need Node on every
# `cargo install` machine and network access at build time, and it would write
# `node_modules` into the registry source directory — which `cargo publish`'s
# verify build refuses. So `include` in vtc-service/Cargo.toml lists the two
# bundles (both gitignored, so only `include` brings them in) and leaves the npm
# project out, and build.rs, finding no `package.json`, bakes the bundles it was
# given. In a source checkout nothing changes: build.rs still runs npm itself,
# into OUT_DIR, and ignores these directories unless VTC_SKIP_ADMIN_UI_BUILD is
# set.
set -euo pipefail

ui="$(cd "$(dirname "$0")/../vtc-service/admin-ui" && pwd)"
cd "$ui"

# `npm ci`: exactly the lockfile, or fail — never a quiet re-resolve.
npm ci --no-audit --no-fund
# Absolute paths: the member build's vite root is `members/`, so a relative
# --outDir would land under it.
npm run build -- --outDir "$ui/dist" --emptyOutDir
npm run build:members -- --outDir "$ui/dist-members" --emptyOutDir

for bundle in dist dist-members; do
  [ -f "$bundle/index.html" ] || {
    echo "::error::$ui/$bundle/index.html was not produced"
    exit 1
  }
done
du -sh dist dist-members
