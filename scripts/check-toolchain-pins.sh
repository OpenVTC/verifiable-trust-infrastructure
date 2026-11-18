#!/usr/bin/env bash
# The three places that name a Rust compiler agree (#2658, #2653).
#
#   rust-toolchain.toml   `channel`: what every CI job builds and lints with
#   Cargo.toml            `rust-version`: the MSRV, which the MSRV job builds with
#   Dockerfile*           `FROM rust:<version>-…`: what the shipped images build with
#
# A pin below the MSRV is an error: CI would build with a compiler the
# workspace says it does not support, and every green run would be meaningless
# for the declared floor.
#
# A Dockerfile on another version than the pin is a warning, not an error.
# Dependabot proposes the toolchain file and the Docker base image in separate
# pull requests, and failing each of them on the other's absence would leave
# both red. The warning says which line to move in the same PR.
set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root"

channel=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml)
msrv=$(sed -nE 's/^rust-version *= *"([^"]+)".*/\1/p' Cargo.toml | head -1)
echo "rust-toolchain.toml channel: ${channel:-<none>}"
echo "workspace rust-version:      ${msrv:-<none>}"

if ! [[ "$channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error file=rust-toolchain.toml::channel must be an exact release (x.y.z), not '$channel': a floating channel is what this file exists to replace"
  exit 1
fi

# Version comparison without sort -V's locale quirks: pad each part.
key() { awk -F. '{ printf "%05d%05d%05d", $1, $2, ($3 == "" ? 0 : $3) }' <<< "$1"; }
if [ -n "$msrv" ] && [ "$(key "$channel")" \< "$(key "$msrv")" ]; then
  echo "::error file=rust-toolchain.toml::channel $channel is below the workspace rust-version $msrv"
  exit 1
fi

status=0
for f in Dockerfile Dockerfile.nitro; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    v=$(sed -nE 's/^FROM +rust:([0-9.]+)-.*/\1/p' <<< "$line")
    [ -n "$v" ] || continue
    echo "$f: rust $v"
    if [ "$v" != "$channel" ]; then
      echo "::warning file=$f::builds with rust $v while rust-toolchain.toml pins $channel; move both in one PR"
    fi
  done < <(grep -E '^FROM +rust:' "$f")
  if grep -qE '^FROM +rust:\$' "$f"; then
    echo "::error file=$f::the Rust image version is an ARG; Dependabot cannot see it there, so inline it in the FROM line"
    status=1
  fi
done
exit "$status"
