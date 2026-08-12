#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Deploy Script (runs on parent EC2 instance)
# =============================================================================
#
# Takes a bundle produced by build-vta.sh (EIF + finalized config.toml +
# PCR values + manifest) and brings it up on the parent EC2 instance:
#
#   1. Prerequisite checks (nitro-cli, ne group, allocator, cargo, IMDS)
#   2. DID resolver sidecar install + start
#   3. Enclave-proxy build + start
#   4. nitro-cli run-enclave
#
# This script does NOT need docker, openssl, or admin AWS credentials.
# The signing key must NOT be present on this host — it lives in CI/KMS.
#
# Usage:
#   ./deploy-enclave.sh --bundle <dir>
#   ./deploy-enclave.sh --eif <path> --config <path> [--pcr0 <hash> --pcr8 <hash>]
#
# If --bundle is provided, the script reads manifest.json for cpu/mem/etc.
# Otherwise pass --cpu and --mem explicitly (or set VTA_ENCLAVE_CPU / VTA_ENCLAVE_MEM).
#
# Environment variables:
#   VTA_BUNDLE_DIR       Bundle location (default: .deploy-nitro)
#   VTA_ENCLAVE_CPU      Enclave CPU count (default: from manifest, else 1)
#   VTA_ENCLAVE_MEM      Enclave memory MiB (default: from manifest, else 512)
#   VTA_RESOLVER_LISTEN  DID resolver sidecar bind address (default: 127.0.0.1:8080)
#   VTA_RUNTIME_DIR      Pidfiles/logs directory (default: bundle dir)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=deploy-common.sh
source "$SCRIPT_DIR/deploy-common.sh"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
INTERACTIVE=true
BUNDLE_DIR="${VTA_BUNDLE_DIR:-}"
EIF_PATH=""
CONFIG_PATH=""
PCR0_OVERRIDE=""
PCR8_OVERRIDE=""
CPU_OVERRIDE=""
MEM_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --non-interactive) INTERACTIVE=false; shift ;;
        --bundle)          BUNDLE_DIR="$2"; shift 2 ;;
        --eif)             EIF_PATH="$2"; shift 2 ;;
        --config)          CONFIG_PATH="$2"; shift 2 ;;
        --pcr0)            PCR0_OVERRIDE="$2"; shift 2 ;;
        --pcr8)            PCR8_OVERRIDE="$2"; shift 2 ;;
        --cpu)             CPU_OVERRIDE="$2"; shift 2 ;;
        --mem)             MEM_OVERRIDE="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

# Default bundle dir if nothing supplied
if [ -z "$BUNDLE_DIR" ] && [ -z "$EIF_PATH" ]; then
    BUNDLE_DIR="$REPO_ROOT/.deploy-nitro"
fi

# Resolve EIF/config from bundle if not overridden
if [ -n "$BUNDLE_DIR" ]; then
    [ -z "$EIF_PATH" ]    && EIF_PATH="$BUNDLE_DIR/vta.eif"
    [ -z "$CONFIG_PATH" ] && CONFIG_PATH="$BUNDLE_DIR/config.toml"
    # Un-baked config: the enclave fetches its tenant config from the parent
    # proxy over vsock instead of a baked EIF. Served when present in the bundle.
    [ -z "${CONFIG_ENVELOPE_PATH:-}" ] && CONFIG_ENVELOPE_PATH="$BUNDLE_DIR/config-envelope.json"
fi

RUNTIME_DIR="${VTA_RUNTIME_DIR:-${BUNDLE_DIR:-$REPO_ROOT/.deploy-nitro}}"
mkdir -p "$RUNTIME_DIR"

# =============================================================================
# Step 1: Prerequisites
# =============================================================================
step 1 "Checking deploy-host prerequisites"

MISSING=()
check_cmd nitro-cli || MISSING+=("nitro-cli")
check_cmd cargo     || MISSING+=("cargo")
check_cmd jq        || MISSING+=("jq")

if [ -d /sys/module/nitro_enclaves ]; then
    ok "nitro_enclaves kernel module loaded"
else
    err "nitro_enclaves kernel module NOT loaded — enclave support not enabled"
    err "Stop the instance, modify-instance-attribute --enclave-options Enabled=true, then start."
    MISSING+=("nitro_enclaves kernel module")
fi

check_group "ne" "Run: sudo usermod -aG ne $(id -un)" || MISSING+=("ne group membership")

# Allocator resource check
ALLOCATOR_YAML="/etc/nitro_enclaves/allocator.yaml"
REQ_CPU="${CPU_OVERRIDE:-${VTA_ENCLAVE_CPU:-1}}"
REQ_MEM="${MEM_OVERRIDE:-${VTA_ENCLAVE_MEM:-512}}"

if [ -f "$ALLOCATOR_YAML" ]; then
    ALLOC_CPU=$(grep -E '^\s*cpu_count\s*:' "$ALLOCATOR_YAML" | awk '{print $2}')
    ALLOC_MEM=$(grep -E '^\s*memory_mib\s*:' "$ALLOCATOR_YAML" | awk '{print $2}')
    ALLOC_CPU="${ALLOC_CPU:-0}"
    ALLOC_MEM="${ALLOC_MEM:-0}"

    if [ "$ALLOC_CPU" -ge "$REQ_CPU" ] 2>/dev/null; then
        ok "Allocator: ${ALLOC_CPU} CPUs reserved (need ${REQ_CPU})"
    else
        err "Allocator has ${ALLOC_CPU} CPUs but ${REQ_CPU} required"
        err "Edit $ALLOCATOR_YAML (cpu_count: $REQ_CPU) and restart nitro-enclaves-allocator."
        MISSING+=("allocator CPU")
    fi
    if [ "$ALLOC_MEM" -ge "$REQ_MEM" ] 2>/dev/null; then
        ok "Allocator: ${ALLOC_MEM} MiB reserved (need ${REQ_MEM})"
    else
        err "Allocator has ${ALLOC_MEM} MiB but ${REQ_MEM} required"
        err "Edit $ALLOCATOR_YAML (memory_mib: $REQ_MEM) and restart nitro-enclaves-allocator."
        MISSING+=("allocator memory")
    fi
else
    warn "$ALLOCATOR_YAML not found — cannot verify enclave resource allocation"
fi

# IMDS hop limit needs to be 2 so the enclave can reach IMDS through the
# vsock proxy. We can't verify the setting without admin creds, so just
# remind the operator.
warn "IMDS hop limit must be 2. Verify with:"
warn "  aws ec2 describe-instances --instance-ids <id> --query \\"
warn "    'Reservations[].Instances[].MetadataOptions.HttpPutResponseHopLimit'"

if [ ${#MISSING[@]} -gt 0 ]; then
    err "Missing requirements: ${MISSING[*]}"
    exit 1
fi

# Validate bundle inputs
if [ ! -f "$EIF_PATH" ]; then
    err "EIF not found: $EIF_PATH"
    err "Supply --eif <path> or --bundle <dir> (containing vta.eif)."
    exit 1
fi
if [ ! -f "$CONFIG_PATH" ]; then
    err "config.toml not found: $CONFIG_PATH"
    err "Supply --config <path> or --bundle <dir> (containing config.toml)."
    exit 1
fi
ok "EIF:    $EIF_PATH"
ok "Config: $CONFIG_PATH"

# Read manifest if present
MANIFEST="${BUNDLE_DIR:+$BUNDLE_DIR/manifest.json}"
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
    ok "Manifest: $MANIFEST"
    [ -z "$CPU_OVERRIDE" ] && CPU_OVERRIDE=$(jq -r '.enclave_cpu // empty' "$MANIFEST")
    [ -z "$MEM_OVERRIDE" ] && MEM_OVERRIDE=$(jq -r '.enclave_mem_mib // empty' "$MANIFEST")
fi

ENCLAVE_CPU="${CPU_OVERRIDE:-${VTA_ENCLAVE_CPU:-1}}"
ENCLAVE_MEM="${MEM_OVERRIDE:-${VTA_ENCLAVE_MEM:-512}}"

# =============================================================================
# Step 2: DID resolver sidecar
# =============================================================================
step 2 "DID resolver sidecar"

RESOLVER_RUNTIME_DIR="$RUNTIME_DIR/resolver"
RESOLVER_CONF="$RESOLVER_RUNTIME_DIR/conf/cache-conf.toml"
RESOLVER_PID_FILE="$RUNTIME_DIR/resolver.pid"
RESOLVER_LOG="$RUNTIME_DIR/resolver.log"
RESOLVER_LISTEN="${VTA_RESOLVER_LISTEN:-127.0.0.1:8080}"

if ! command -v affinidi-did-resolver-cache-server &>/dev/null; then
    info "Installing affinidi-did-resolver-cache-server from crates.io..."
    info "(first install takes several minutes — compiles from source)"
    cargo install affinidi-did-resolver-cache-server
    ok "Resolver sidecar installed: $(command -v affinidi-did-resolver-cache-server)"
else
    ok "Resolver sidecar already installed: $(command -v affinidi-did-resolver-cache-server)"
fi

mkdir -p "$RESOLVER_RUNTIME_DIR/conf"
if [ ! -f "$RESOLVER_CONF" ]; then
    info "Writing minimal resolver config to $RESOLVER_CONF"
    cat > "$RESOLVER_CONF" <<TOML
# =============================================================================
# Generated by deploy-enclave.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

log_level = "info"
listen_address = "\${LISTEN_ADDRESS:${RESOLVER_LISTEN}}"
statistics_interval = "\${STATISTICS_INTERVAL:60}"
enable_http_endpoint = "\${ENABLE_HTTP_ENDPOINT:true}"
enable_websocket_endpoint = "\${ENABLE_WEBSOCKET_ENDPOINT:true}"

[cache]
capacity_count = "\${CACHE_CAPACITY_COUNT:1000}"
expire = "\${EXPIRE:300}"
TOML
    ok "Resolver config written (listen: $RESOLVER_LISTEN)"
else
    ok "Resolver config already present: $RESOLVER_CONF"
fi

if pid_alive "$RESOLVER_PID_FILE"; then
    ok "Resolver sidecar already running (PID $(cat "$RESOLVER_PID_FILE"))"
elif pgrep -f "affinidi-did-resolver-cache-server" >/dev/null 2>&1; then
    EXISTING_PID=$(pgrep -f "affinidi-did-resolver-cache-server" | head -1)
    ok "Resolver sidecar already running outside this script (PID $EXISTING_PID)"
    echo "$EXISTING_PID" > "$RESOLVER_PID_FILE"
else
    info "Starting resolver sidecar from $RESOLVER_RUNTIME_DIR..."
    (
        cd "$RESOLVER_RUNTIME_DIR"
        nohup affinidi-did-resolver-cache-server > "$RESOLVER_LOG" 2>&1 &
        echo $! > "$RESOLVER_PID_FILE"
    )
    sleep 2
    RESOLVER_PID=$(cat "$RESOLVER_PID_FILE")
    if kill -0 "$RESOLVER_PID" 2>/dev/null; then
        ok "Resolver sidecar started (PID $RESOLVER_PID, listen $RESOLVER_LISTEN)"
    else
        err "Resolver sidecar failed to start — check $RESOLVER_LOG"
        exit 1
    fi
fi

# =============================================================================
# Step 3: Parent enclave-proxy
# =============================================================================
step 3 "Parent enclave-proxy"

PROXY_BIN="$SCRIPT_DIR/enclave-proxy/target/release/enclave-proxy"
PROXY_PID_FILE="$RUNTIME_DIR/proxy.pid"
PROXY_LOG="$RUNTIME_DIR/proxy.log"

if [ -f "$PROXY_BIN" ]; then
    ok "Enclave proxy binary found: $PROXY_BIN"
else
    info "Building enclave proxy..."
    (cd "$SCRIPT_DIR/enclave-proxy" && cargo build --release)
    ok "Enclave proxy built"
fi

if pid_alive "$PROXY_PID_FILE"; then
    ok "Enclave proxy already running (PID $(cat "$PROXY_PID_FILE"))"
else
    rm -f "$PROXY_PID_FILE"
    info "Starting enclave proxy in background..."
    # Serve the un-baked tenant config envelope over vsock when present. A
    # rebuilt (un-baked) EIF has no config inside and REQUIRES this; warn loudly
    # if it is missing so the failure is obvious, not a 60 s enclave timeout.
    PROXY_ENVELOPE_ARGS=()
    if [ -f "${CONFIG_ENVELOPE_PATH:-}" ]; then
        ok "Config envelope: $CONFIG_ENVELOPE_PATH (served over vsock:5800)"
        PROXY_ENVELOPE_ARGS=(--config-envelope "$CONFIG_ENVELOPE_PATH")
    else
        warn "No config-envelope.json in bundle — an un-baked EIF will fail to boot."
        warn "Generate it from config.toml:"
        warn "  jq -Rs '{version:1, config_toml:., integrity:null}' config.toml > config-envelope.json"
    fi
    nohup "$PROXY_BIN" --config "$CONFIG_PATH" --enclave-cid 16 \
        "${PROXY_ENVELOPE_ARGS[@]}" \
        > "$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$PROXY_PID_FILE"
    sleep 2
    if kill -0 "$PROXY_PID" 2>/dev/null; then
        ok "Enclave proxy started (PID $PROXY_PID, log: $PROXY_LOG)"
    else
        err "Enclave proxy failed to start — check $PROXY_LOG"
        exit 1
    fi
fi

# =============================================================================
# Step 4: Launch enclave
# =============================================================================
step 4 "Launch enclave"

EXISTING=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
if [ -n "$EXISTING" ]; then
    if ask_yn "An enclave is already running ($EXISTING). Terminate it?" "Y"; then
        nitro-cli terminate-enclave --enclave-id "$EXISTING" >/dev/null
        ok "Terminated existing enclave"
        sleep 2
    else
        warn "Skipping enclave launch — existing enclave still running"
        SKIP_LAUNCH=true
    fi
fi

if [ "${SKIP_LAUNCH:-false}" != true ]; then
    info "Launching enclave (CPU=$ENCLAVE_CPU, MEM=${ENCLAVE_MEM}MiB)..."
    nitro-cli run-enclave \
        --eif-path "$EIF_PATH" \
        --cpu-count "$ENCLAVE_CPU" \
        --memory "$ENCLAVE_MEM" \
        --enclave-cid 16

    ok "Enclave launched"
    echo ""
    nitro-cli describe-enclaves | jq '.[0] | {EnclaveID, State, EnclaveCID}'
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}==============================================================================${NC}"
echo -e "${BOLD}  Deploy Summary${NC}"
echo -e "${BOLD}==============================================================================${NC}"
echo ""
echo "  EIF:      $EIF_PATH"
echo "  Config:   $CONFIG_PATH"
echo "  Enclave:  CPU=$ENCLAVE_CPU, MEM=${ENCLAVE_MEM}MiB, CID=16"
echo ""
echo "  Runtime state:"
echo "    $RESOLVER_PID_FILE / $RESOLVER_LOG"
echo "    $PROXY_PID_FILE / $PROXY_LOG"
echo ""
echo -e "  ${GREEN}Deployment complete.${NC}"
echo ""
echo "  Verify:"
echo "    curl http://localhost:8443/health"
echo "    curl http://localhost:8443/attestation/status"
echo ""
