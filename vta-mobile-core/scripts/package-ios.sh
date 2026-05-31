#!/usr/bin/env bash
#
# Assemble the iOS distribution artifacts for vta-mobile-core:
#
#   target/mobile/ios/VtaMobileCore.xcframework       — device + simulator static libs
#   target/mobile/ios/VtaMobileCore.xcframework.zip   — the binaryTarget payload
#   target/mobile/ios/VtaMobileCore.xcframework.zip.sha256  — SwiftPM checksum
#   target/mobile/ios/Sources/VtaMobileCore.swift     — the Swift API wrapper (compiled by the consumer)
#
# Distribution (decided): the .zip is uploaded to a GitHub Release and consumed
# from the vta-mobile-agent-ios SwiftPM package via
#   .binaryTarget(url: "…/VtaMobileCore.xcframework.zip", checksum: "<sha256>")
# alongside the VtaMobileCore.swift source. This script only *produces* the
# artifacts + checksum; the tag-triggered release workflow publishes them.
#
# macOS + Xcode only. Run: vta-mobile-core/scripts/package-ios.sh
#
# IPHONEOS_DEPLOYMENT_TARGET is pinned to 16.0 for the same reason as
# build-mobile.sh: aws-lc-sys's assembly references `___chkstk_darwin`, absent
# at Rust's default iOS target (10.0), so the device link fails below 16.0.
set -euo pipefail

PROFILE="${PROFILE:-release}"
IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
export IPHONEOS_DEPLOYMENT_TARGET

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE_ROOT"

# Where cargo writes build output. Honor a caller/CI-provided CARGO_TARGET_DIR;
# otherwise pin to the workspace ./target. Export it so cargo and this script
# agree even when a global cargo config sets `build.target-dir` (the env var
# overrides config) — otherwise cargo writes elsewhere and the lipo / bindgen /
# xcframework steps below can't find the static libraries.
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}"
export CARGO_TARGET_DIR="$TARGET_DIR"

CARGO_PROFILE_FLAG=""
PROFILE_DIR="debug"
if [ "$PROFILE" = "release" ]; then
  CARGO_PROFILE_FLAG="--release"
  PROFILE_DIR="release"
fi

DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)
LIB="libvta_mobile_core.a"
OUT="$TARGET_DIR/mobile/ios"
STAGE="$OUT/staging"

rm -rf "$OUT"
mkdir -p "$STAGE/headers" "$OUT/Sources"

echo "── Building static libs (deployment target $IPHONEOS_DEPLOYMENT_TARGET, $PROFILE) ──"
for target in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
  echo "  • $target"
  cargo build -p vta-mobile-core --lib --target "$target" $CARGO_PROFILE_FLAG
done

# A static-library xcframework needs one slice per platform. The device slice
# is a single arch; the simulator slice fuses the arm64 + x86_64 sim libs with
# lipo (one xcframework slice cannot list two libraries for the same platform).
echo "── Fusing simulator slice (arm64 + x86_64) ──"
SIM_FAT="$STAGE/sim/$LIB"
mkdir -p "$STAGE/sim"
lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB" \
  "$TARGET_DIR/x86_64-apple-ios/$PROFILE_DIR/$LIB" \
  -output "$SIM_FAT"

# Generate the Swift bindings from a host build (the generated source + C header
# + modulemap are target-independent). The .swift is the consumer-compiled API;
# the header + modulemap travel *inside* the xcframework so the static lib's
# C symbols are importable.
echo "── Generating Swift bindings ──"
cargo build -p vta-mobile-core --lib $CARGO_PROFILE_FLAG
HOST_LIB=""
for cand in "$TARGET_DIR/$PROFILE_DIR/libvta_mobile_core.dylib" \
            "$TARGET_DIR/$PROFILE_DIR/libvta_mobile_core.so"; do
  [ -f "$cand" ] && HOST_LIB="$cand" && break
done
[ -n "$HOST_LIB" ] || { echo "  host library not found for bindgen" >&2; exit 1; }
BIND="$STAGE/bindings"
cargo run -p vta-mobile-core --bin uniffi-bindgen -- \
  generate --library "$HOST_LIB" --language swift --out-dir "$BIND"

cp "$BIND/VtaMobileCore.swift" "$OUT/Sources/VtaMobileCore.swift"
# xcframework -headers wants the C header plus a `module.modulemap` (exact name).
cp "$BIND/VtaMobileCoreFFI.h" "$STAGE/headers/"
cp "$BIND/VtaMobileCoreFFI.modulemap" "$STAGE/headers/module.modulemap"

echo "── Assembling VtaMobileCore.xcframework ──"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/$DEVICE_TARGET/$PROFILE_DIR/$LIB" -headers "$STAGE/headers" \
  -library "$SIM_FAT" -headers "$STAGE/headers" \
  -output "$OUT/VtaMobileCore.xcframework" >/dev/null

echo "── Zipping + checksum ──"
ZIP="$OUT/VtaMobileCore.xcframework.zip"
# `ditto --keepParent` preserves the .xcframework dir at the zip root, as
# SwiftPM's binaryTarget unpacking expects.
ditto -c -k --keepParent "$OUT/VtaMobileCore.xcframework" "$ZIP"

# SwiftPM's own checksum (sha256 of the zip) — the value a binaryTarget pins.
# `swift package compute-checksum` must run inside a package, so use a throwaway.
CK_DIR="$STAGE/checksum-pkg"
mkdir -p "$CK_DIR"
cat > "$CK_DIR/Package.swift" <<'SWIFT'
// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "checksum")
SWIFT
CHECKSUM="$(cd "$CK_DIR" && swift package compute-checksum "$WORKSPACE_ROOT/$ZIP")"
echo "$CHECKSUM" > "$ZIP.sha256"

rm -rf "$STAGE"

echo ""
echo "iOS artifacts ready under $OUT/:"
echo "  VtaMobileCore.xcframework(.zip)"
echo "  Sources/VtaMobileCore.swift"
echo "  checksum (sha256): $CHECKSUM"
