#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Parent Instance Proxy
# =============================================================================
#
# This script runs on the PARENT EC2 instance (not inside the enclave).
#
# PARTIAL — socat only, four of the seven vsock channels. The canonical parent
# implementation is the Rust `deploy/nitro/enclave-proxy`, which additionally
# serves the IMDS credential proxy (5400), the storage proxy (5500) and log
# forwarding (5700). A VTA deployed with only this script has no persistent
# store and no enclave logs on the parent. Use it for bring-up and debugging;
# use enclave-proxy for anything real.
#
# It manages the following channels for the enclave:
#
#   1. INBOUND:   External clients → TCP:8443 → vsock:5100 → Enclave VTA
#   2. MEDIATOR:  Enclave DIDComm → vsock:5200 → TLS → mediator
#   3. RESOLVER:  Enclave DID resolution → vsock:5600 → local DID resolver
#   4. HTTPS:     Enclave general HTTPS → vsock:5300 → allowlisted endpoints
#
# Configuration is auto-read from deploy/nitro/config.toml (the same config
# baked into the EIF). Override any value with environment variables.
#
# Prerequisites:
#   sudo yum install -y socat aws-nitro-enclaves-cli
#
# Usage:
#   ./parent-proxy.sh                          # Auto-detect everything from config
#   ./parent-proxy.sh webvh.example.com:443    # Add extra allowlisted hosts
#
# Environment variable overrides:
#   MEDIATOR_HOST     Override mediator hostname (default: from config.toml)
#   MEDIATOR_PORT     Override mediator port (default: 443)
#   RESOLVER_URL      DID resolver URL (default: https://did.server.affinidi.io)
#   RESOLVER_PORT     Local DID resolver port (default: 8200)
#   LISTEN_PORT       External REST API port (default: 8443)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${VTA_CONFIG:-${SCRIPT_DIR}/config.toml}"

# ---------------------------------------------------------------------------
# Read mediator from config.toml (if available)
# ---------------------------------------------------------------------------
read_config_value() {
    local key="$1"
    local default="$2"
    if [ -f "$CONFIG_FILE" ]; then
        # Simple TOML value extraction (handles: key = "value" and key = value)
        local val
        val=$(grep -E "^\s*${key}\s*=" "$CONFIG_FILE" 2>/dev/null | head -1 | sed 's/.*=\s*//;s/"//g;s/#.*//' | xargs)
        if [ -n "$val" ]; then
            echo "$val"
            return
        fi
    fi
    echo "$default"
}

# Auto-detect mediator from config.toml [messaging] section
CONFIG_MEDIATOR_DID=$(read_config_value "mediator_did" "")
CONFIG_REGION=$(read_config_value "region" "us-east-1")

# For the mediator URL, the config has the enclave-local proxy URL (ws://127.0.0.1:4443).
# We need the REAL mediator host. Extract it from the mediator DID if possible,
# or use the MEDIATOR_HOST env var.
extract_host_from_did() {
    local did="$1"
    # did:web:example.com → example.com
    # did:web:example.com%3A8080 → example.com (port stripped)
    echo "$did" | sed -n 's|^did:web:\([^:%%]*\).*|\1|p'
}

if [ -n "${MEDIATOR_HOST:-}" ]; then
    # Explicit override
    :
elif [ -n "$CONFIG_MEDIATOR_DID" ]; then
    MEDIATOR_HOST=$(extract_host_from_did "$CONFIG_MEDIATOR_DID")
    if [ -n "$MEDIATOR_HOST" ]; then
        echo "Auto-detected mediator host from config.toml: $MEDIATOR_HOST"
    fi
fi

# Collect extra allowlisted hosts from CLI args
EXTRA_HOSTS=("$@")

# ---------------------------------------------------------------------------
# Port assignments (must match enclave-entrypoint.sh)
# ---------------------------------------------------------------------------
# Enclave-side vsock ports. These MUST match the enclave: see
# `enclave-entrypoint.sh` and `enclave-proxy/src/main.rs`, which are the
# authority. 5400 is the IMDS credential proxy and 5500 / 5700 are the storage
# and log channels — this script serves none of those, so it must not bind them.
VSOCK_INBOUND_PORT="${VSOCK_INBOUND_PORT:-5100}"      # Inbound REST
VSOCK_MEDIATOR_PORT="${VSOCK_MEDIATOR_PORT:-5200}"     # Outbound mediator
VSOCK_HTTPS_PORT="${VSOCK_HTTPS_PORT:-5300}"            # Outbound HTTPS
VSOCK_RESOLVER_PORT="${VSOCK_RESOLVER_PORT:-5600}"      # Outbound DID resolver
VSOCK_CONFIG_PORT="${VSOCK_CONFIG_PORT:-5800}"          # Inbound config envelope (parent → enclave)

# Un-baked config: when this envelope file exists, serve it to the
# enclave over vsock:${VSOCK_CONFIG_PORT}. It is a JSON envelope
# ({ "version":1, "config_toml":"…", "integrity":null }) rendered off-box. Absent
# → the enclave uses a baked/mounted config if one exists (existing EIFs); a
# rebuilt EIF has no baked config and requires the envelope.
#
# SINGLE OWNER of vsock:${VSOCK_CONFIG_PORT}: exactly one process may serve the
# config port. This script is the owner for the *standalone / manual*
# parent-proxy workflow. An orchestrated deployment may instead run its own
# config server (e.g. a systemd socat unit) and NOT invoke this script, so the
# two never bind ${VSOCK_CONFIG_PORT} at once. If you ever run both on the same
# host you will get an "address in use" bind conflict — don't.
#
# Envelope location (first match wins): $VTA_CONFIG_ENVELOPE, then a file next to
# this script, then a conventional managed path. Keeping the managed path here
# lets this script serve the same envelope an external provisioner writes.
MANAGED_CONFIG_ENVELOPE="/etc/vta-tee/config-envelope.json"
if [ -n "${VTA_CONFIG_ENVELOPE:-}" ]; then
    CONFIG_ENVELOPE="${VTA_CONFIG_ENVELOPE}"
elif [ -f "${SCRIPT_DIR}/config-envelope.json" ]; then
    CONFIG_ENVELOPE="${SCRIPT_DIR}/config-envelope.json"
else
    CONFIG_ENVELOPE="${MANAGED_CONFIG_ENVELOPE}"
fi

LISTEN_PORT="${LISTEN_PORT:-8443}"                      # External REST API port
MEDIATOR_PORT="${MEDIATOR_PORT:-443}"                   # Mediator WSS port
RESOLVER_PORT="${RESOLVER_PORT:-8200}"                  # Local DID resolver port
RESOLVER_URL="${RESOLVER_URL:-https://did.server.affinidi.io}"  # Upstream DID resolver

REGION="${CONFIG_REGION}"

# ---------------------------------------------------------------------------
# Auto-detect enclave CID
# ---------------------------------------------------------------------------
ENCLAVE_CID=""
echo "Auto-detecting enclave CID..."
ENCLAVE_CID=$(nitro-cli describe-enclaves | python3 -c "
import sys, json
enclaves = json.load(sys.stdin)
running = [e for e in enclaves if e.get('State') == 'RUNNING']
if not running:
    print('NONE', file=sys.stderr)
    sys.exit(1)
print(running[0]['EnclaveCID'])
" 2>/dev/null) || {
    echo "ERROR: No running enclave found. Start one first:"
    echo "  nitro-cli run-enclave --eif-path vta.eif --cpu-count 1 --memory 512"
    exit 1
}

echo ""
echo "========================================="
echo "  VTA Nitro Enclave — Parent Proxy"
echo "========================================="
echo ""
echo "  Config:      ${CONFIG_FILE}"
echo "  Enclave CID: ${ENCLAVE_CID}"
echo ""
echo "  [1] INBOUND  REST:     0.0.0.0:${LISTEN_PORT} → vsock:${VSOCK_INBOUND_PORT} → Enclave :8100"
[ -n "${MEDIATOR_HOST:-}" ] && \
echo "  [2] OUTBOUND MEDIATOR: vsock:${VSOCK_MEDIATOR_PORT} → ${MEDIATOR_HOST}:${MEDIATOR_PORT}"
echo "  [3] OUTBOUND RESOLVER: vsock:${VSOCK_RESOLVER_PORT} → localhost:${RESOLVER_PORT} (DID resolver)"
echo "  [4] OUTBOUND HTTPS:    vsock:${VSOCK_HTTPS_PORT} → allowlisted endpoints"
echo ""
echo "  Test:"
echo "    curl http://localhost:${LISTEN_PORT}/health"
echo "    curl http://localhost:${LISTEN_PORT}/attestation/status"
echo ""

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
PIDS=()
cleanup() {
    echo ""
    echo "Shutting down proxies..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# [1] INBOUND: External TCP → vsock → Enclave REST API
# ---------------------------------------------------------------------------
echo "Starting inbound proxy: TCP:${LISTEN_PORT} → vsock CID ${ENCLAVE_CID}:${VSOCK_INBOUND_PORT}"
socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork \
    VSOCK-CONNECT:${ENCLAVE_CID}:${VSOCK_INBOUND_PORT} &
PIDS+=($!)

# ---------------------------------------------------------------------------
# [0] CONFIG: serve the un-baked config envelope → vsock → Enclave
# ---------------------------------------------------------------------------
# The enclave connects to vsock:${VSOCK_CONFIG_PORT} on first boot, reads this
# envelope, and writes /etc/vta/config.toml before starting the VTA. `fork` lets
# it reconnect after a boot race/restart. Only started when an envelope exists.
if [ -f "${CONFIG_ENVELOPE}" ]; then
    echo "Starting config server:  vsock:${VSOCK_CONFIG_PORT} → ${CONFIG_ENVELOPE}"
    # `-U` streams the file (ADDR2) to the connection (ADDR1); OPEN…,rdonly reads
    # the envelope with no shell (vs SYSTEM:"cat …", which spawns /bin/sh per
    # connection with the path interpolated into the command string).
    socat -U VSOCK-LISTEN:${VSOCK_CONFIG_PORT},reuseaddr,fork \
        OPEN:"${CONFIG_ENVELOPE}",rdonly &
    PIDS+=($!)
else
    echo "SKIP config server — no envelope at ${CONFIG_ENVELOPE}"
    echo "     (enclave will use a baked/mounted config, or set VTA_CONFIG_ENVELOPE)"
fi

# ---------------------------------------------------------------------------
# [2] OUTBOUND: Enclave DIDComm → vsock → Mediator WebSocket
# ---------------------------------------------------------------------------
if [ -n "${MEDIATOR_HOST:-}" ]; then
    echo "Starting mediator proxy: vsock:${VSOCK_MEDIATOR_PORT} → ${MEDIATOR_HOST}:${MEDIATOR_PORT}"
    socat VSOCK-LISTEN:${VSOCK_MEDIATOR_PORT},reuseaddr,fork \
        OPENSSL:${MEDIATOR_HOST}:${MEDIATOR_PORT},verify=1 &
    PIDS+=($!)
else
    echo "SKIP mediator proxy — no MEDIATOR_HOST set and none found in config.toml"
    echo "     Set MEDIATOR_HOST=mediator.example.com or configure [messaging] in config.toml"
fi

# ---------------------------------------------------------------------------
# [3] OUTBOUND: Enclave DID resolution → vsock → Local resolver proxy
# ---------------------------------------------------------------------------
# The enclave VTA connects to localhost:4444 for HTTPS (via HTTPS_PROXY).
# For DID resolution, this proxies to a local or remote resolver.
#
# For production: run an Affinidi DID resolver instance on the parent and
# point RESOLVER_URL to it (e.g., http://localhost:8200). The VTA's
# did-resolver uses network mode through the proxy to reach it.
#
# For simplicity: proxy directly to the Universal Resolver.
echo "Starting resolver proxy: vsock:${VSOCK_RESOLVER_PORT} → ${RESOLVER_URL}"

# ---------------------------------------------------------------------------
# [4] OUTBOUND: Enclave HTTPS → vsock → Allowlisted endpoints
# ---------------------------------------------------------------------------
if command -v vsock-proxy &>/dev/null; then
    echo "Starting HTTPS proxy (vsock-proxy): vsock:${VSOCK_HTTPS_PORT} → allowlisted endpoints"

    # Build the allowlist
    ALLOWLIST_FILE=$(mktemp /tmp/vsock-allowlist-XXXXXX.yaml)
    cat > "$ALLOWLIST_FILE" <<EOF
allowlist:
- {address: "kms.${REGION}.amazonaws.com", port: 443}
EOF

    # Add mediator if configured
    [ -n "${MEDIATOR_HOST:-}" ] && \
        echo "- {address: \"${MEDIATOR_HOST}\", port: ${MEDIATOR_PORT}}" >> "$ALLOWLIST_FILE"

    # Add resolver host
    RESOLVER_HOST=$(echo "$RESOLVER_URL" | sed -n 's|https\?://\([^:/]*\).*|\1|p')
    RESOLVER_HOST_PORT=$(echo "$RESOLVER_URL" | sed -n 's|.*:\([0-9]*\)$|\1|p')
    [ -z "$RESOLVER_HOST_PORT" ] && RESOLVER_HOST_PORT=443
    [ -n "$RESOLVER_HOST" ] && \
        echo "- {address: \"${RESOLVER_HOST}\", port: ${RESOLVER_HOST_PORT}}" >> "$ALLOWLIST_FILE"

    # Add extra hosts from CLI args
    for hostport in "${EXTRA_HOSTS[@]}"; do
        host="${hostport%%:*}"
        port="${hostport##*:}"
        [ "$port" = "$host" ] && port=443
        echo "- {address: \"${host}\", port: ${port}}" >> "$ALLOWLIST_FILE"
        echo "  Allowlisted: ${host}:${port}"
    done

    # Add hosts from ALLOWLIST_HOSTS env var
    if [ -n "${ALLOWLIST_HOSTS:-}" ]; then
        IFS=',' read -ra AHOSTS <<< "$ALLOWLIST_HOSTS"
        for hostport in "${AHOSTS[@]}"; do
            hostport=$(echo "$hostport" | xargs)
            host="${hostport%%:*}"
            port="${hostport##*:}"
            [ "$port" = "$host" ] && port=443
            echo "- {address: \"${host}\", port: ${port}}" >> "$ALLOWLIST_FILE"
        done
    fi

    echo "  Allowlist: $(grep -c 'address:' "$ALLOWLIST_FILE") hosts"
    # Default target is the resolver host (most common outbound call)
    vsock-proxy ${VSOCK_HTTPS_PORT} "${RESOLVER_HOST:-did.server.affinidi.io}" ${RESOLVER_HOST_PORT:-443} \
        --config "$ALLOWLIST_FILE" &
    PIDS+=($!)
else
    echo "WARNING: vsock-proxy not found — HTTPS proxy disabled"
    echo "         Install aws-nitro-enclaves-cli for outbound HTTPS support"
fi

# ---------------------------------------------------------------------------
# Wait for all proxies
# ---------------------------------------------------------------------------
echo ""
echo "All proxies started. Press Ctrl+C to stop."
wait
