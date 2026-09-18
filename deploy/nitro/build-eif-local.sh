#!/usr/bin/env bash
# =============================================================================
# Local EIF build — produces vta.eif + PCR0/PCR8 with NO IAM/KMS side effects.
#
# Runs a containerized nitro-cli against the host docker daemon, so it works on
# macOS (Docker Desktop, Apple Silicon) without a Nitro-enabled EC2 instance.
# This is the "just the EIF + measurements" path — it deliberately skips the
# IAM-role and KMS-policy steps that build-vta.sh performs.
#
# Keys and outputs live OUTSIDE the repo (~/.vta-eif-build) so the signing
# private key can never be committed by accident.
#
# Env overrides:
#   FEATURES      cargo features    (default: rest,didcomm,vsock-store,vsock-log)
#   BAKE_CONFIG   true|false        (default: true)
#   VTA_EIF_WORK  key/output dir    (default: ~/.vta-eif-build)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BUILDER_IMAGE="${BUILDER_IMAGE:-vta-eif-builder}"
FEATURES="${FEATURES:-rest,didcomm,vsock-store,vsock-log}"
BAKE_CONFIG="${BAKE_CONFIG:-true}"
WORK="${VTA_EIF_WORK:-$HOME/.vta-eif-build}"

mkdir -p "$WORK/signing" "$WORK/out"

# 1) Builder image (arm64 to match the VTA target — native on Apple Silicon).
docker build --platform linux/arm64 \
  -t "$BUILDER_IMAGE" \
  -f "$SCRIPT_DIR/Dockerfile.builder" "$SCRIPT_DIR"

# 2) Build inside it. The mounted docker socket lets `docker build` and
#    `nitro-cli build-enclave` share the host daemon's image store.
# Resolve the real host docker socket (Docker Desktop on macOS often uses
# ~/.docker/run/docker.sock, not /var/run/docker.sock).
HOST_SOCK="${DOCKER_HOST#unix://}"
[ -S "$HOST_SOCK" ] || HOST_SOCK="/var/run/docker.sock"
[ -S "$HOST_SOCK" ] || HOST_SOCK="$HOME/.docker/run/docker.sock"
[ -S "$HOST_SOCK" ] || { echo "No docker socket found (is Docker running?)" >&2; exit 1; }
echo "Using host docker socket: $HOST_SOCK"

# KMS-backed signing (optional): when VTA_SIGNING_KEY_ARN is set, the EIF is built
# UNSIGNED in the container and signed on the host, so the private key never
# leaves KMS. A dedicated kms/ signing dir keeps the local signing/ dir untouched.
SIGNING_KEY_ARN="${VTA_SIGNING_KEY_ARN:-}"
SIGN_MODE=local
SIGN_DIR_CONTAINER=/build/signing
KMS_SIGNER_BIN=""
if [ -n "$SIGNING_KEY_ARN" ]; then
  SIGN_MODE=kms
  SIGN_DIR_CONTAINER=/build/kms
  mkdir -p "$WORK/kms"
  SIGNER_DIR="$SCRIPT_DIR/kms-signer"
  if [ -x "$SIGNER_DIR/target/release/kms-signer" ]; then
    KMS_SIGNER_BIN="$SIGNER_DIR/target/release/kms-signer"
  else
    echo "Building kms-signer (release)..."
    ( cd "$SIGNER_DIR" && cargo build --release )
    KMS_SIGNER_BIN="$SIGNER_DIR/target/release/kms-signer"
  fi
  if [ ! -f "$WORK/kms/signing-cert.pem" ]; then
    echo "Minting PCR8 certificate from KMS key..."
    "$KMS_SIGNER_BIN" mint-cert \
      --key-arn "$SIGNING_KEY_ARN" \
      ${AWS_REGION:+--region "$AWS_REGION"} \
      --out "$WORK/kms/signing-cert.pem"
  else
    echo "Reusing KMS cert: $WORK/kms/signing-cert.pem (PCR8 pinned)"
  fi
  echo "KMS signing enabled (key: $SIGNING_KEY_ARN)"
fi

TTY_FLAGS="-i"; [ -t 1 ] && TTY_FLAGS="-it"
docker run --rm $TTY_FLAGS \
  --platform linux/arm64 \
  -v "$HOST_SOCK":/var/run/docker.sock \
  -v "$REPO_ROOT":/workspace \
  -v "$WORK":/build \
  -w /workspace \
  -e FEATURES="$FEATURES" \
  -e BAKE_CONFIG="$BAKE_CONFIG" \
  "$BUILDER_IMAGE" -c '
    set -euo pipefail
    SIGN="${SIGN_DIR:-/build/signing}"
    OUT=/build/out

    if [ "${SIGN_MODE:-local}" = "kms" ]; then
      # KMS mode: host supplies the cert; private key stays in KMS. PCR8 comes
      # from the cert; the EIF is built unsigned and signed on the host after.
      PCR8=$(nitro-cli pcr --signing-certificate "$SIGN/signing-cert.pem" | jq -r .PCR8)
    else
      # Local mode: self-signed key/cert (idempotent); PCR8 derives from the cert.
      if [ ! -f "$SIGN/signing-cert.pem" ]; then
        bash deploy/nitro/generate-signing-key.sh "$SIGN"
      fi
      PCR8=$(cat "$SIGN/pcr8.txt")
    fi

    # Source image for the EIF (built on the host daemon via the mounted socket).
    docker build -f Dockerfile.nitro \
      --build-arg FEATURES="$FEATURES" \
      --build-arg BAKE_CONFIG="$BAKE_CONFIG" \
      -t vta-nitro .

    # Build the EIF and capture measurements. KMS mode builds unsigned.
    if [ "${SIGN_MODE:-local}" = "kms" ]; then
      OUTJSON=$(nitro-cli build-enclave \
        --docker-uri vta-nitro \
        --output-file "$OUT/vta.eif")
    else
      OUTJSON=$(nitro-cli build-enclave \
        --docker-uri vta-nitro \
        --output-file "$OUT/vta.eif" \
        --signing-certificate "$SIGN/signing-cert.pem" \
        --private-key "$SIGN/signing-key.pem")
    fi
    echo "$OUTJSON" | jq .

    PCR0=$(echo "$OUTJSON" | jq -r .Measurements.PCR0)
    printf "%s\n" "$PCR0" > "$OUT/pcr0.txt"
    printf "%s\n" "$PCR8" > "$OUT/pcr8.txt"
    sha256sum "$OUT/vta.eif" | tee "$OUT/vta.eif.sha256"
    echo
    echo "PCR0: $PCR0"
    echo "PCR8: $PCR8"
  '

if [ "$SIGN_MODE" = "kms" ]; then
  echo "Signing EIF with KMS key (private key never leaves KMS)..."
  "$KMS_SIGNER_BIN" sign-eif \
    --key "$SIGNING_KEY_ARN" \
    --cert "$WORK/kms/signing-cert.pem" \
    --eif "$WORK/out/vta.eif"
  # EIF bytes changed after signing — recompute the digest over the signed image.
  ( cd "$WORK/out" && shasum -a 256 vta.eif > vta.eif.sha256 && cat vta.eif.sha256 )
fi

echo
echo "Done. Artifacts (on host):"
echo "  EIF   : $WORK/out/vta.eif"
echo "  SHA256: $WORK/out/vta.eif.sha256"
echo "  PCR0  : $(cat "$WORK/out/pcr0.txt" 2>/dev/null || echo '?')"
echo "  PCR8  : $(cat "$WORK/out/pcr8.txt" 2>/dev/null || echo '?')"
if [ "$SIGN_MODE" = "kms" ]; then
  echo "  Signer: KMS $SIGNING_KEY_ARN (private key non-exportable)"
  echo "  Cert  : $WORK/kms/signing-cert.pem"
else
  echo "  Key   : $WORK/signing/  (keep secret; NOT the KMS-held prod key)"
fi
