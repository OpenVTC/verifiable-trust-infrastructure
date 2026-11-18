#!/usr/bin/env bash
# Install the toolchain `rust-toolchain.toml` pins, for a CI job.
#
#   scripts/install-rust-toolchain.sh [--target <triple>[,<triple>...]]
#
# Every job used to run `rustup toolchain install stable` + `rustup default
# stable`, so CI built with whatever stable was current that day (#2658). The
# toolchain file now names the compiler, and rustup selects it by itself
# anywhere in this checkout. This installs it up front, with the components the
# file lists, so the first `cargo` call does not do it implicitly (rustup
# 1.28.0 refused to, later versions do it silently), and so a job that needs a
# cross target can name it.
#
# A job that deliberately builds with another compiler says so with
# `RUSTUP_TOOLCHAIN` (MSRV, the semver jobs) or `cargo +nightly` (fuzz). Both
# take precedence over the file.
set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
file="$root/rust-toolchain.toml"
channel=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' "$file")
if [ -z "$channel" ]; then
  echo "::error::no channel in $file"
  exit 1
fi

args=(--profile minimal --no-self-update --component rustfmt --component clippy)
case "${1:-}" in
  --target) args+=(--target "${2:?--target needs a value}") ;;
  "") ;;
  *) echo "usage: $0 [--target <triple>[,<triple>...]]" >&2; exit 2 ;;
esac

rustup toolchain install "$channel" "${args[@]}"
rustc -V
cargo -V
