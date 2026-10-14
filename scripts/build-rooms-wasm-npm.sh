#!/usr/bin/env bash
# Build `@openvtc/vti-rooms-wasm`, the npm package of `vti-rooms-wasm`, into a
# directory ready for `npm publish`.
#
#   scripts/build-rooms-wasm-npm.sh [out-dir]     # default target/npm/vti-rooms-wasm
#
# The crate is `publish = false` on crates.io: its artifact is a `.wasm` module
# and the JS glue beside it, and npm is where a browser consumer (the wallet
# extension) takes it from. CI runs this on every change to the crate and packs
# the result, so the package a maintainer publishes is the one CI built.
#
# `wasm-bindgen --target bundler`: the consumer is a Vite build with
# `vite-plugin-wasm`, which imports the module as ESM. The CLI must be the
# version `Cargo.lock` pins for the `wasm-bindgen` crate — the glue and the
# module are generated as a pair, and a mismatch fails at load in the browser,
# not here — so this refuses any other.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/target/npm/vti-rooms-wasm}"
cd "$root"

locked=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)
have=$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)
if [ "$have" != "$locked" ]; then
  echo "wasm-bindgen CLI ${have:-missing}, but Cargo.lock pins the crate at $locked." >&2
  echo "Install the matching CLI: cargo install wasm-bindgen-cli --version $locked --locked" >&2
  exit 1
fi

cargo build -p vti-rooms-wasm --profile wasm-release --target wasm32-unknown-unknown --locked

rm -rf "$out"
mkdir -p "$out"
wasm-bindgen --target bundler --out-dir "$out" --out-name vti_rooms_wasm \
  target/wasm32-unknown-unknown/wasm-release/vti_rooms_wasm.wasm

# The package's identity comes from the crate's manifest, so the two cannot
# disagree about version, licence or repository.
cargo metadata --format-version 1 --no-deps --locked |
  python3 -c '
import json, sys
meta = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "vti-rooms-wasm")
print(json.dumps({
    "name": "@openvtc/vti-rooms-wasm",
    "version": meta["version"],
    "description": meta["description"],
    "license": meta["license"],
    "repository": {
        "type": "git",
        "url": "git+" + meta["repository"] + ".git",
        "directory": "vti-rooms-wasm",
    },
    "type": "module",
    "module": "./vti_rooms_wasm.js",
    "types": "./vti_rooms_wasm.d.ts",
    "exports": {
        ".": {
            "types": "./vti_rooms_wasm.d.ts",
            "import": "./vti_rooms_wasm.js",
        },
    },
    "files": [
        "vti_rooms_wasm_bg.wasm",
        "vti_rooms_wasm_bg.wasm.d.ts",
        "vti_rooms_wasm.js",
        "vti_rooms_wasm_bg.js",
        "vti_rooms_wasm.d.ts",
        "README.md",
    ],
    # The entry module instantiates the wasm on import.
    "sideEffects": ["./vti_rooms_wasm.js"],
}, indent=2))
' > "$out/package.json"

cp vti-rooms-wasm/README.md "$out/README.md"
echo "Built $(jq -r '.name + "@" + .version' "$out/package.json" 2>/dev/null || echo package) in $out"
