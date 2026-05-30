#!/usr/bin/env bash
#
# Cross-compile vta-mobile-core for the mobile targets and generate the
# Kotlin/Swift bindings. This is the buildability gate: it proves the engine
# links into the artifacts the app repos consume (Android .so via the NDK, iOS
# static/dylib for the xcframework) and that the UniFFI surface still generates.
# It does NOT package or publish the AAR / xcframework — that is a later slice.
#
# Run locally:
#   vta-mobile-core/scripts/build-mobile.sh            # all platforms
#   vta-mobile-core/scripts/build-mobile.sh ios        # iOS + bindgen only (no NDK needed)
#   vta-mobile-core/scripts/build-mobile.sh android    # Android only (needs the NDK)
#
# Requirements:
#   - iOS    : a macOS host with Xcode CLT; rust targets below.
#   - Android: cargo-ndk + an Android NDK (ANDROID_NDK_HOME / ANDROID_NDK_ROOT /
#              ANDROID_NDK_LATEST_HOME); rust targets below.
#
# ── Deployment / API floor (load-bearing — do not lower without re-checking the
#    link) ─────────────────────────────────────────────────────────────────────
# IPHONEOS_DEPLOYMENT_TARGET is pinned to 16.0 on purpose. The dependency tree
# pulls aws-lc-sys (transitively, via the resolver/DIDComm rustls stack), whose
# assembly references `___chkstk_darwin`. Rust's default iOS deployment target
# (10.0) predates that runtime symbol, so the device link fails with
# "Undefined symbols for architecture arm64: ___chkstk_darwin". 16.0 resolves it
# and is a sane modern floor for the passkey/AAL2 APIs the agent needs. If you
# must lower it, re-run `… ios` and confirm the link before merging.
set -euo pipefail

PLATFORMS="${1:-all}"
PROFILE="${PROFILE:-debug}"
IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
ANDROID_API="${ANDROID_API:-24}"
export IPHONEOS_DEPLOYMENT_TARGET

# Resolve to the workspace root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE_ROOT"

CARGO_PROFILE_FLAG=""
PROFILE_DIR="debug"
if [ "$PROFILE" = "release" ]; then
  CARGO_PROFILE_FLAG="--release"
  PROFILE_DIR="release"
fi

IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
# cargo-ndk ABI names (it maps these to the android triples + NDK toolchain).
ANDROID_ABIS=(arm64-v8a armeabi-v7a x86_64)

build_ios() {
  echo "── iOS (deployment target $IPHONEOS_DEPLOYMENT_TARGET, $PROFILE) ──"
  for target in "${IOS_TARGETS[@]}"; do
    echo "  • $target"
    cargo build -p vta-mobile-core --lib --target "$target" $CARGO_PROFILE_FLAG
  done
}

build_android() {
  echo "── Android (min API $ANDROID_API, $PROFILE) ──"
  if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "  cargo-ndk not found. Install with: cargo install cargo-ndk --locked" >&2
    exit 1
  fi
  local ndk_args=()
  for abi in "${ANDROID_ABIS[@]}"; do ndk_args+=(-t "$abi"); done
  # NOTE: `--platform` (the API level), spelled in full on purpose. cargo-ndk's
  # short `-p` was dropped in v4; `-p 24` is forwarded to cargo as `--package 24`
  # and panics with "unknown package: 24".
  cargo ndk "${ndk_args[@]}" --platform "$ANDROID_API" -o "target/mobile/jniLibs" \
    build -p vta-mobile-core --lib $CARGO_PROFILE_FLAG
}

# Generate the foreign-language bindings from the host build and assert the
# expected entry-point files exist — this is what catches an FFI surface that
# no longer generates (e.g. an unsupported type slipped into an exported fn).
check_bindings() {
  echo "── UniFFI bindings (kotlin + swift) ──"
  cargo build -p vta-mobile-core --lib $CARGO_PROFILE_FLAG
  local lib=""
  for cand in "target/$PROFILE_DIR/libvta_mobile_core.dylib" \
              "target/$PROFILE_DIR/libvta_mobile_core.so"; do
    if [ -f "$cand" ]; then lib="$cand"; break; fi
  done
  if [ -z "$lib" ]; then
    echo "  could not find the built libvta_mobile_core dynamic library" >&2
    exit 1
  fi
  local out="target/bindings"
  rm -rf "$out"
  for lang in kotlin swift; do
    cargo run -p vta-mobile-core --bin uniffi-bindgen -- \
      generate --library "$lib" --language "$lang" --out-dir "$out/$lang"
  done
  # Kotlin lands under org/openvtc/vta/mobilecore/, Swift as VtaMobileCore.swift
  # (see uniffi.toml). Assert each language produced output.
  test -n "$(find "$out/kotlin" -name '*.kt' -print -quit)" \
    || { echo "  no Kotlin bindings generated" >&2; exit 1; }
  test -n "$(find "$out/swift" -name '*.swift' -print -quit)" \
    || { echo "  no Swift bindings generated" >&2; exit 1; }
  echo "  bindings generated under $out/{kotlin,swift}"
}

case "$PLATFORMS" in
  ios)     build_ios; check_bindings ;;
  android) build_android; check_bindings ;;
  all)     build_ios; build_android; check_bindings ;;
  *) echo "usage: $0 [ios|android|all]" >&2; exit 2 ;;
esac

echo "mobile build gate: OK"
