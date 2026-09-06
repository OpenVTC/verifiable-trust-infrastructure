#!/usr/bin/env bash
# System packages cargo-semver-checks needs to build rustdoc for this workspace.
#
# `vta-cli-common` pulls `libdbus-sys`, whose build script shells out to
# pkg-config. Without the dbus headers rustdoc fails to build, and the semver
# script reads a failed baseline build as "a PUBLISHED CRATE DOES NOT BUILD" —
# a deliberately loud error, because that genuinely is a production defect when
# it is real. A missing build dependency on the runner produces the identical
# message, so the two must not be allowed to look alike.
#
# They already did once: the release-bump guard shipped without this step and
# failed its first real run on `libdbus-sys ... pkg_config failed`, reported as
# a broken published artifact. The fix is not a second copy of the apt logic in
# the second job — that is how two lists of the same thing drift — so it lives
# here and both jobs call it.
#
# # Why this is not just `apt-get update && apt-get install`
#
# `apt-get update` is the operation that hangs. Three runs stalled on it, and
# once each attempt was bounded the timings showed every failure landing on the
# 90s `update` ceiling, never on the install. The mirror is unresponsive;
# retrying it harder does not help.
#
# So it is not run unless actually needed. The runner image ships a usable
# package index, and pkg-config is already present on ubuntu-24.04, so the fast
# path checks what is missing and installs straight from the shipped index.
# Refreshing the index is the fallback — still bounded, still retried — for the
# case where the package genuinely is not in it.
set -euo pipefail

pkgs=""
for p in libdbus-1-dev pkg-config; do
  dpkg -s "$p" >/dev/null 2>&1 || pkgs="$pkgs $p"
done

if [ -z "$pkgs" ]; then
  echo "libdbus-1-dev and pkg-config already present; nothing to do"
  exit 0
fi

echo "missing:$pkgs"
if sudo timeout 120 apt-get install -y $pkgs; then
  exit 0
fi

echo "::warning::install from the shipped index failed; refreshing"
for attempt in 1 2 3; do
  if sudo timeout 120 apt-get -o Acquire::Retries=3 update \
    && sudo timeout 120 apt-get -o Acquire::Retries=3 install -y $pkgs; then
    exit 0
  fi
  echo "::warning::apt attempt $attempt failed or timed out; retrying in 10s"
  sleep 10
done

echo "::error::apt-get failed after the shipped index and 3 bounded refreshes"
exit 1
