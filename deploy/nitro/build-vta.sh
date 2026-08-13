#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Build Script (runs on build host / CI)
# =============================================================================
#
# Produces a signed Enclave Image File (EIF) and the KMS infrastructure that
# gates its secrets. This script assumes it's running on a Linux host with
# docker + nitro-cli + openssl + aws + jq and admin-level AWS credentials
# (for IAM role creation and KMS key management).
#
# Steps:
#   1. Prerequisite checks
#   2. Build profile selection
#   3. Configuration inputs (region, mediator, etc.)
#   4. EIF signing key (generate or reuse)
#   5. IAM role for the parent EC2 instance (optional)
#   6. Generate config.toml
#   7. Initial Docker build
#   8. Build and sign EIF (captures PCR0)
#   9. KMS key creation / policy update (PCR0 + PCR8 + role ARN)
#  10. Rebuild Docker + EIF with final config baked in (new PCR0)
#  11. Write deployable bundle (EIF, config, PCR values, manifest)
#
# The bundle written to $BUILD_DIR can be shipped to the parent EC2 instance
# and handed to `deploy-enclave.sh`.
#
# Usage:
#   ./build-vta.sh                       # Interactive
#   ./build-vta.sh --non-interactive     # Reads from env vars (for CI/CD)
#
# Environment variables (for non-interactive mode):
#   VTA_PROFILE         Build profile: hardened, full, rest-only (default: full)
#   VTA_REGION          AWS region (default: us-east-1)
#   VTA_ROLE_NAME       IAM role name (default: vta-enclave-role)
#   VTA_SIGNING_DIR     Signing key directory (default: ./signing)
#   VTA_MEDIATOR_DID    DIDComm mediator DID (optional)
#   VTA_ENCLAVE_CPU     Enclave CPU count (default: 1)
#   VTA_ENCLAVE_MEM     Enclave memory MiB (default: 512)
#   VTA_KEY_ARN         Existing KMS key ARN (skip creation if set)
#   VTA_BUILD_ADMIN     ARN of build role to grant KMS admin (optional)
#   VTA_SKIP_IAM        Set to "true" to skip IAM role creation
#   VTA_BUILD_DIR       Output directory for the bundle (default: .deploy-nitro)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=deploy-common.sh
source "$SCRIPT_DIR/deploy-common.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
INTERACTIVE=true
for arg in "$@"; do
    case "$arg" in
        --non-interactive) INTERACTIVE=false ;;
        --help|-h)
            sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

BUILD_DIR="${VTA_BUILD_DIR:-$REPO_ROOT/.deploy-nitro}"

# Config mode (see Dockerfile.nitro "CONFIG MODES"):
#   true  (DEFAULT) — bake config.toml into the image (single-tenant / self-host;
#          config committed to PCR0, no runtime overlay). The binary has no
#          vsock config-fetch code.
#   false — bake config.fleet-base.toml (fleet policy + placeholders) so one
#          image / one PCR0 serves every tenant; the enclave fetches a typed,
#          allowlisted tenant overlay over vsock:5800 at boot. This script emits
#          a tenant-overlay-template.json for that path (a per-tenant file is
#          produced by render-tenant-overlay.sh).
BAKE_CONFIG="${VTA_BAKE_CONFIG:-true}"

# =============================================================================
# Step 1: Prerequisites
# =============================================================================
step 1 "Checking build-host prerequisites"

MISSING=()
check_cmd docker  || MISSING+=("docker")
check_cmd aws     || MISSING+=("aws")
check_cmd openssl || MISSING+=("openssl")
check_cmd jq      || MISSING+=("jq")

if command -v nitro-cli &>/dev/null; then
    ok "nitro-cli found"
else
    err "nitro-cli not found — required on the build host to produce the EIF"
    err "Install aws-nitro-enclaves-cli on an Amazon Linux 2023 / Ubuntu host."
    MISSING+=("nitro-cli")
fi

if aws sts get-caller-identity &>/dev/null; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)
    ok "AWS credentials valid — account $ACCOUNT_ID"
    ok "Caller: $CALLER_ARN"
else
    err "AWS credentials not configured. Run 'aws configure' or set AWS_* env vars."
    MISSING+=("aws credentials")
fi

check_group "docker" "Run: sudo usermod -aG docker $(id -un)" \
    || MISSING+=("docker group membership")

if docker info &>/dev/null; then
    ok "Docker daemon is running"
else
    err "Docker daemon is not running. Start it with: sudo systemctl start docker"
    MISSING+=("docker daemon")
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    err "Missing requirements: ${MISSING[*]}"
    err "Fix the above issues and re-run this script."
    exit 1
fi

# =============================================================================
# Step 2: Build profile
# =============================================================================
step 2 "Build profile selection"

echo "Available profiles:"
echo ""
echo "  A) Hardened (DIDComm only) — smallest attack surface"
echo "     Features: didcomm,vsock-store,vsock-log"
echo ""
echo "  B) Full API (REST + DIDComm)"
echo "     Features: rest,didcomm,vsock-store,vsock-log"
echo ""
echo "  C) REST only — no DIDComm mediator needed"
echo "     Features: rest,vsock-store,vsock-log"
echo ""

DEFAULT_PROFILE="${VTA_PROFILE:-full}"

if [ "$INTERACTIVE" = true ]; then
    read -r -p "$(echo -e "${BOLD}Select profile (A/B/C)${NC} [B]: ")" PROFILE_CHOICE
    PROFILE_CHOICE="${PROFILE_CHOICE:-B}"
else
    case "$DEFAULT_PROFILE" in
        hardened) PROFILE_CHOICE="A" ;;
        rest-only) PROFILE_CHOICE="C" ;;
        *) PROFILE_CHOICE="B" ;;
    esac
fi

case "${PROFILE_CHOICE^^}" in
    A)
        FEATURES="didcomm,vsock-store,vsock-log"
        PROFILE_NAME="Hardened (DIDComm only)"
        NEEDS_MEDIATOR=true
        ;;
    C)
        FEATURES="rest,vsock-store,vsock-log"
        PROFILE_NAME="REST only"
        NEEDS_MEDIATOR=false
        ;;
    *)
        FEATURES="rest,didcomm,vsock-store,vsock-log"
        PROFILE_NAME="Full API (REST + DIDComm)"
        NEEDS_MEDIATOR=true
        ;;
esac

ok "Profile: $PROFILE_NAME"
ok "Features: $FEATURES"

# =============================================================================
# Step 3: Configuration inputs
# =============================================================================
step 3 "Configuration"

ask "AWS region" "${VTA_REGION:-us-east-1}" REGION
ask "IAM role name for EC2 instance" "${VTA_ROLE_NAME:-vta-enclave-role}" ROLE_NAME
ask "Enclave CPU count" "${VTA_ENCLAVE_CPU:-1}" ENCLAVE_CPU
ask "Enclave memory (MiB)" "${VTA_ENCLAVE_MEM:-512}" ENCLAVE_MEM

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

MEDIATOR_DID="${VTA_MEDIATOR_DID:-}"
MEDIATOR_URL=""
if [ "$NEEDS_MEDIATOR" = true ]; then
    echo ""
    info "This profile uses DIDComm — a mediator is required."
    ask "DIDComm mediator DID (e.g., did:web:mediator.example.com)" "${MEDIATOR_DID}" MEDIATOR_DID
    if [ -n "$MEDIATOR_DID" ]; then
        MEDIATOR_URL="ws://127.0.0.1:4443"
        ok "Mediator DID: $MEDIATOR_DID"
    else
        warn "No mediator DID provided — DIDComm will be disabled at runtime"
    fi
fi

BUILD_ADMIN="${VTA_BUILD_ADMIN:-}"
if [ "$INTERACTIVE" = true ]; then
    echo ""
    info "Optional: grant a build role KMS admin access for CI/CD PCR0 rotation."
    ask "Build admin role ARN (optional)" "$BUILD_ADMIN" BUILD_ADMIN
fi
[ -n "$BUILD_ADMIN" ] && ok "Build admin: $BUILD_ADMIN"

ask "Signing key directory" "${VTA_SIGNING_DIR:-./signing}" SIGNING_DIR

# =============================================================================
# Step 4: EIF signing key
# =============================================================================
step 4 "EIF signing key"

if [ -f "$SIGNING_DIR/signing-key.pem" ] && [ -f "$SIGNING_DIR/signing-cert.pem" ]; then
    ok "Existing signing key found in $SIGNING_DIR"
    if [ -f "$SIGNING_DIR/pcr8.txt" ]; then
        PCR8=$(cat "$SIGNING_DIR/pcr8.txt")
        ok "PCR8: ${PCR8:0:32}..."
    else
        warn "pcr8.txt not found — recomputing"
        PCR8=$(nitro-cli pcr --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['PCR8'])")
        echo "$PCR8" > "$SIGNING_DIR/pcr8.txt"
        ok "PCR8 computed: ${PCR8:0:32}..."
    fi
else
    info "Generating new EIF signing key..."
    bash "$SCRIPT_DIR/generate-signing-key.sh" "$SIGNING_DIR"
    PCR8=$(cat "$SIGNING_DIR/pcr8.txt")
    ok "Signing key generated"
fi

# =============================================================================
# Step 5: IAM role
# =============================================================================
step 5 "IAM role setup"

SKIP_IAM="${VTA_SKIP_IAM:-false}"

if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    ok "IAM role '$ROLE_NAME' already exists"
    ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
    ok "Role ARN: $ROLE_ARN"
elif [ "$SKIP_IAM" = "true" ]; then
    warn "Skipping IAM role creation (VTA_SKIP_IAM=true)"
else
    if ask_yn "Create IAM role '$ROLE_NAME'?" "Y"; then
        info "Creating IAM role..."
        ROLE_ARN=$(aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document '{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }' \
            --query 'Role.Arn' --output text)
        ok "Created role: $ROLE_ARN"

        PROFILE_NAME_IAM="${ROLE_NAME}-profile"
        if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME_IAM" &>/dev/null; then
            aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME_IAM" >/dev/null
            aws iam add-role-to-instance-profile \
                --instance-profile-name "$PROFILE_NAME_IAM" \
                --role-name "$ROLE_NAME" >/dev/null
            ok "Created instance profile: $PROFILE_NAME_IAM"
        fi
    else
        warn "Skipping IAM role creation — you must create it manually"
    fi
fi

# =============================================================================
# Step 6: Generate config.toml
# =============================================================================
step 6 "Generate config.toml"

mkdir -p "$BUILD_DIR"
CONFIG_PATH="$BUILD_DIR/config.toml"

info "Writing config to $CONFIG_PATH"

cat > "$CONFIG_PATH" <<TOML
# =============================================================================
# VTA Configuration — AWS Nitro Enclave
# =============================================================================
# Generated by build-vta.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Profile: $PROFILE_NAME (features: $FEATURES)
# =============================================================================

[services]
rest = true
didcomm = true

[server]
host = "127.0.0.1"
port = 8100

[log]
level = "info"
format = "json"

[store]
data_dir = "/var/lib/vta/data"

[tee]
mode = "required"
embed_in_did = true
attestation_cache_ttl = 300
storage_key_salt = "vta-tee-storage-v1"

[tee.kms]
region = "$REGION"
key_arn = "PLACEHOLDER"
seed_ciphertext_path = "/mnt/vta-data/secrets/seed.enc"
jwt_ciphertext_path = "/mnt/vta-data/secrets/jwt.enc"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400
challenge_ttl = 300
session_cleanup_interval = 600

[secrets]
# Seed is provided by KMS bootstrap — do NOT set it here
TOML

if [ -n "$MEDIATOR_DID" ]; then
    cat >> "$CONFIG_PATH" <<TOML

[messaging]
mediator_url = "$MEDIATOR_URL"
mediator_did = "$MEDIATOR_DID"
TOML
fi

ok "Config written"

# =============================================================================
# Step 7: Initial Docker build (to get PCR0)
# =============================================================================
step 7 "Build Docker image"

cp "$CONFIG_PATH" "$SCRIPT_DIR/config.toml"

docker build -f "$REPO_ROOT/Dockerfile.nitro" \
    --build-arg FEATURES="$FEATURES" \
    --build-arg BAKE_CONFIG="$BAKE_CONFIG" \
    -t vta-nitro \
    "$REPO_ROOT"

ok "Docker image built: vta-nitro"

# =============================================================================
# Step 8: Build and sign EIF
# =============================================================================
step 8 "Build and sign Enclave Image File"

EIF_PATH="$BUILD_DIR/vta.eif"

BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file "$EIF_PATH" \
    --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
    --private-key "$SIGNING_DIR/signing-key.pem")

echo "$BUILD_OUTPUT" | jq .

PCR0=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR0')
BUILD_PCR8=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR8')

ok "EIF built: $EIF_PATH"
ok "PCR0: ${PCR0:0:32}..."
if [ "$BUILD_PCR8" = "$PCR8" ]; then
    ok "PCR8 matches signing key"
else
    warn "PCR8 mismatch! Build=$BUILD_PCR8, Expected=$PCR8"
fi
echo "$PCR0" > "$BUILD_DIR/pcr0.txt"

# =============================================================================
# Step 9: KMS key
# =============================================================================
step 9 "KMS key setup"

KEY_ARN="${VTA_KEY_ARN:-}"

BUILD_ADMIN_FLAG=()
[ -n "$BUILD_ADMIN" ] && BUILD_ADMIN_FLAG=(--build-admin "$BUILD_ADMIN")

if [ -n "$KEY_ARN" ]; then
    info "Updating existing KMS key: $KEY_ARN"
    bash "$SCRIPT_DIR/setup-kms-policy.sh" \
        --pcr0 "$PCR0" --pcr8 "$PCR8" \
        --role "$ROLE_ARN" --key-arn "$KEY_ARN" \
        --region "$REGION" "${BUILD_ADMIN_FLAG[@]}"
    ok "KMS key policy updated"
else
    info "Creating new KMS key with attestation policy..."
    KMS_OUTPUT=$(bash "$SCRIPT_DIR/setup-kms-policy.sh" \
        --pcr0 "$PCR0" --pcr8 "$PCR8" \
        --role "$ROLE_ARN" --region "$REGION" \
        "${BUILD_ADMIN_FLAG[@]}" 2>&1)
    echo "$KMS_OUTPUT"

    KEY_ARN=$(echo "$KMS_OUTPUT" | grep "Key ARN:" | awk '{print $NF}')
    if [ -z "$KEY_ARN" ]; then
        KEY_ARN=$(aws kms describe-key --key-id "alias/vta-enclave-secrets" \
            --region "$REGION" --query 'KeyMetadata.Arn' --output text 2>/dev/null || true)
    fi
    if [ -z "$KEY_ARN" ]; then
        err "Failed to extract KMS key ARN from output"
        exit 1
    fi
    ok "KMS key created: $KEY_ARN"
fi

# =============================================================================
# Step 10: Rebuild with final config
# =============================================================================
step 10 "Rebuild with final config"

if [ "$BAKE_CONFIG" = "false" ]; then
    # ── FLEET (BAKE_CONFIG=false): do NOT bake tenant values ──
    # The image bakes config.fleet-base.toml (fleet policy + placeholders). Bake
    # ONLY the account allowlist (PCR0-committed); the tenant key_arn / mediator /
    # DID template are delivered at runtime as a typed overlay, never baked.
    ACCOUNT_ID="$(printf '%s\n' "$KEY_ARN" | cut -d: -f5)"
    FLEET_BASE="$SCRIPT_DIR/config.fleet-base.toml"
    sed -i.bak \
        "s|allowed_kms_accounts = \[\"REPLACE_WITH_ALLOWED_ACCOUNT_ID\"\]|allowed_kms_accounts = [\"$ACCOUNT_ID\"]|" \
        "$FLEET_BASE"
    rm -f "$FLEET_BASE.bak"
    ok "Fleet base tee.allowed_kms_accounts set to [\"$ACCOUNT_ID\"]"

    # Emit a tenant OVERLAY TEMPLATE (the allowlisted wire shape — see
    # docs/05-design-notes/tenant-config-allowlist.md §3.4). A real per-tenant
    # overlay is produced by render-tenant-overlay.sh and served by
    # deploy-enclave.sh over vsock:5800.
    OVERLAY_TEMPLATE_PATH="$BUILD_DIR/tenant-overlay-template.json"
    cat > "$OVERLAY_TEMPLATE_PATH" <<JSON
{
  "version": 1,
  "overlay": {
    "vta_name": "REPLACE_tenant_short_name",
    "public_url": "https://vta.REPLACE.example.com",
    "tee_kms": {
      "key_arn": "$KEY_ARN",
      "vta_did_template": "did:webvh:{SCID}:REPLACE.example.com:vta"
    },
    "messaging": { "mediator_did": "REPLACE_mediator_did" }
  },
  "integrity": null
}
JSON
    ok "Tenant overlay TEMPLATE written: $OVERLAY_TEMPLATE_PATH"
    info "Render a per-tenant overlay, e.g.:"
    info "  deploy/nitro/render-tenant-overlay.sh --key-arn $KEY_ARN \\"
    info "    --mediator-did <did> --vta-did-template <tmpl> > tenant-overlay.json"
    info "Then serve it: deploy-enclave.sh --config-envelope tenant-overlay.json"
else
    # ── SELF-HOST (BAKE_CONFIG=true): bake the tenant config into the EIF ──
    sed -i.bak "s|key_arn = \"PLACEHOLDER\"|key_arn = \"$KEY_ARN\"|" "$CONFIG_PATH"
    rm -f "$CONFIG_PATH.bak"
    ok "Config updated with KMS key ARN"
    cp "$CONFIG_PATH" "$SCRIPT_DIR/config.toml"
fi

info "Rebuilding Docker image..."
docker build -f "$REPO_ROOT/Dockerfile.nitro" \
    --build-arg FEATURES="$FEATURES" \
    --build-arg BAKE_CONFIG="$BAKE_CONFIG" \
    -t vta-nitro \
    "$REPO_ROOT"
ok "Docker image rebuilt"

info "Rebuilding EIF..."
BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file "$EIF_PATH" \
    --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
    --private-key "$SIGNING_DIR/signing-key.pem")
NEW_PCR0=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR0')
ok "EIF rebuilt"

if [ "$NEW_PCR0" != "$PCR0" ]; then
    # PCR0 changed. With BAKE_CONFIG=true (default) the config is baked, so
    # editing config.toml (e.g. inserting the KMS ARN) legitimately changes PCR0.
    # With BAKE_CONFIG=false the config is NOT in the image, so a change here
    # instead means code/deps/Dockerfile moved. Either way, update the KMS policy.
    info "PCR0 changed — updating KMS policy..."
    PCR0="$NEW_PCR0"
    echo "$PCR0" > "$BUILD_DIR/pcr0.txt"
    bash "$SCRIPT_DIR/setup-kms-policy.sh" \
        --pcr0 "$PCR0" --pcr8 "$PCR8" \
        --role "$ROLE_ARN" --key-arn "$KEY_ARN" \
        --region "$REGION" "${BUILD_ADMIN_FLAG[@]}"
    ok "KMS policy updated with new PCR0: ${PCR0:0:32}..."
fi

# =============================================================================
# Step 11: Write manifest
# =============================================================================
step 11 "Write bundle manifest"

MANIFEST="$BUILD_DIR/manifest.json"
cat > "$MANIFEST" <<JSON
{
  "built_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "profile": "$PROFILE_NAME",
  "features": "$FEATURES",
  "region": "$REGION",
  "role_arn": "$ROLE_ARN",
  "kms_key_arn": "$KEY_ARN",
  "pcr0": "$PCR0",
  "pcr8": "$PCR8",
  "enclave_cpu": $ENCLAVE_CPU,
  "enclave_mem_mib": $ENCLAVE_MEM,
  "mediator_did": "$MEDIATOR_DID"
}
JSON
ok "Manifest written: $MANIFEST"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}==============================================================================${NC}"
echo -e "${BOLD}  Build Summary${NC}"
echo -e "${BOLD}==============================================================================${NC}"
echo ""
echo "  Profile:    $PROFILE_NAME"
echo "  Features:   $FEATURES"
echo "  Region:     $REGION"
echo "  KMS Key:    $KEY_ARN"
echo "  PCR0:       ${PCR0:0:32}..."
echo "  PCR8:       ${PCR8:0:32}..."
echo ""
echo -e "  ${GREEN}Bundle ready at: $BUILD_DIR/${NC}"
echo "    - vta.eif"
if [ "$BAKE_CONFIG" = "false" ]; then
    echo "    - tenant-overlay-template.json  (fleet: render per-tenant, serve over vsock)"
else
    echo "    - config.toml                   (baked into the EIF)"
fi
echo "    - pcr0.txt, pcr8.txt"
echo "    - manifest.json"
echo ""
echo "  Next: ship the bundle to the parent EC2 instance and run:"
echo "    ./deploy/nitro/deploy-enclave.sh --bundle <path-to-bundle>"
echo ""
