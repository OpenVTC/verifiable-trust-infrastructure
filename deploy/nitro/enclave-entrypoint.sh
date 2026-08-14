#!/bin/sh
# =============================================================================
# VTA Nitro Enclave Entrypoint
# =============================================================================
#
# This script runs INSIDE the Nitro Enclave. It:
# 1. Brings up the loopback network interface
# 2. Starts vsock↔TCP proxy processes for outbound connectivity
# 3. Configures the VTA for enclave operation (REST + DIDComm)
# 4. Starts the VTA service
#
# The parent EC2 instance must run parent-proxy.sh to forward traffic.
#
# Network Architecture (inside enclave):
#
#   Inbound (clients → VTA):
#     vsock listen :5100 → socat → VTA REST :8100
#
#   Outbound (VTA → mediator):
#     VTA → localhost:4443 → socat → vsock connect parent:5200
#     Parent: vsock listen :5200 → wss://mediator.example.com
#
#   Outbound (VTA → DID resolver / general HTTPS):
#     VTA → localhost:4444 → socat → vsock connect parent:5300
#     Parent: vsock listen :5300 → https://resolver endpoint
#
# =============================================================================

set -eu

# ---------------------------------------------------------------------------
# Port assignments (must match parent-proxy.sh)
# ---------------------------------------------------------------------------
PARENT_CID="${PARENT_CID:-3}"          # CID 3 = parent instance

VSOCK_INBOUND_PORT="${VSOCK_INBOUND_PORT:-5100}"     # Inbound REST (vsock → VTA)
VSOCK_MEDIATOR_PORT="${VSOCK_MEDIATOR_PORT:-5200}"    # Outbound mediator (VTA → vsock)
VSOCK_HTTPS_PORT="${VSOCK_HTTPS_PORT:-5300}"           # Outbound HTTPS (VTA → vsock)
VSOCK_IMDS_PORT="${VSOCK_IMDS_PORT:-5400}"             # Outbound IMDS (AWS credentials)
VSOCK_RESOLVER_PORT="${VSOCK_RESOLVER_PORT:-5600}"     # Outbound DID resolver (WebSocket)

VTA_PORT="${VTA_PORT:-8100}"
LOCAL_MEDIATOR_PORT="${LOCAL_MEDIATOR_PORT:-4443}"     # VTA connects here for mediator
LOCAL_HTTPS_PORT="${LOCAL_HTTPS_PORT:-4444}"            # VTA connects here for HTTPS
LOCAL_RESOLVER_PORT="${LOCAL_RESOLVER_PORT:-4445}"      # VTA connects here for DID resolver

echo "=== VTA Nitro Enclave ==="
echo "VTA version:  $(vta-enclave --version 2>/dev/null || echo unknown)"
echo "NSM device:   $(ls -la /dev/nsm 2>/dev/null || echo 'NOT FOUND')"
echo "Parent CID:   ${PARENT_CID}"
echo ""

# ---------------------------------------------------------------------------
# Verify NSM device
# ---------------------------------------------------------------------------
if [ ! -e /dev/nsm ]; then
    echo "ERROR: /dev/nsm not found — this must run inside a Nitro Enclave"
    echo "       Use 'nitro-cli build-enclave' + 'nitro-cli run-enclave'"
    exit 1
fi

# ---------------------------------------------------------------------------
# Bring up loopback interface (enclaves start with no network)
# ---------------------------------------------------------------------------
echo "Configuring loopback interface..."
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
# Add the IMDS link-local address so the AWS SDK can reach 169.254.169.254.
# Traffic to this address is proxied through vsock to the parent's real IMDS.
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
ip link set lo up 2>/dev/null || true

# ---------------------------------------------------------------------------
# Start inbound proxy: vsock → VTA REST API
# ---------------------------------------------------------------------------
echo "Starting inbound proxy: vsock:${VSOCK_INBOUND_PORT} → localhost:${VTA_PORT}"
socat VSOCK-LISTEN:${VSOCK_INBOUND_PORT},reuseaddr,fork \
    TCP-CONNECT:127.0.0.1:${VTA_PORT} &
INBOUND_PID=$!

# ---------------------------------------------------------------------------
# Start outbound proxy: VTA mediator → parent (for DIDComm WebSocket)
# ---------------------------------------------------------------------------
echo "Starting mediator proxy: localhost:${LOCAL_MEDIATOR_PORT} → vsock:${PARENT_CID}:${VSOCK_MEDIATOR_PORT}"
socat TCP-LISTEN:${LOCAL_MEDIATOR_PORT},reuseaddr,fork,bind=127.0.0.1 \
    VSOCK-CONNECT:${PARENT_CID}:${VSOCK_MEDIATOR_PORT} &
MEDIATOR_PID=$!

# ---------------------------------------------------------------------------
# Start outbound proxy: VTA HTTPS → parent (for DID resolution, WebVH, etc.)
# ---------------------------------------------------------------------------
# The parent runs vsock-proxy which implements an HTTP CONNECT proxy.
# socat bridges localhost:4444 → vsock:5300, so from the VTA's perspective
# localhost:4444 is an HTTP CONNECT proxy to the internet.
# We set HTTPS_PROXY so that reqwest/hyper (used by the DID resolver and
# WebVH client) route all HTTPS traffic through this proxy.
echo "Starting HTTPS proxy: localhost:${LOCAL_HTTPS_PORT} → vsock:${PARENT_CID}:${VSOCK_HTTPS_PORT}"
socat TCP-LISTEN:${LOCAL_HTTPS_PORT},reuseaddr,fork,bind=127.0.0.1 \
    VSOCK-CONNECT:${PARENT_CID}:${VSOCK_HTTPS_PORT} &
HTTPS_PID=$!

# ---------------------------------------------------------------------------
# Start IMDS proxy: 169.254.169.254:80 → parent (for AWS IAM credentials)
# ---------------------------------------------------------------------------
# The AWS SDK inside the enclave fetches IAM credentials from the Instance
# Metadata Service (IMDS) at 169.254.169.254:80. Since the enclave has no
# network, we proxy this through vsock to the parent, which can reach the
# real IMDS endpoint.
echo "Starting IMDS proxy: 169.254.169.254:80 → vsock:${PARENT_CID}:${VSOCK_IMDS_PORT}"
socat TCP-LISTEN:80,reuseaddr,fork,bind=169.254.169.254 \
    VSOCK-CONNECT:${PARENT_CID}:${VSOCK_IMDS_PORT} &
IMDS_PID=$!

# ---------------------------------------------------------------------------
# Start DID resolver proxy: VTA WebSocket → parent (resolver sidecar)
# ---------------------------------------------------------------------------
# The VTA's DID resolver SDK connects via WebSocket to a remote resolver
# server. The parent runs the affinidi-did-resolver-cache-server sidecar.
echo "Starting DID resolver proxy: localhost:${LOCAL_RESOLVER_PORT} → vsock:${PARENT_CID}:${VSOCK_RESOLVER_PORT}"
socat TCP-LISTEN:${LOCAL_RESOLVER_PORT},reuseaddr,fork,bind=127.0.0.1 \
    VSOCK-CONNECT:${PARENT_CID}:${VSOCK_RESOLVER_PORT} &
RESOLVER_PID=$!

# Set HTTPS_PROXY so that reqwest/hyper route HTTPS traffic (KMS, WebVH)
# through the CONNECT proxy.
# Do NOT set HTTP_PROXY — plain HTTP traffic (IMDS, resolver WebSocket)
# must go directly through the dedicated socat bridges.
export HTTPS_PROXY="http://127.0.0.1:${LOCAL_HTTPS_PORT}"
export NO_PROXY="127.0.0.1,localhost,169.254.169.254"

echo ""
echo "Proxy PIDs: inbound=${INBOUND_PID} mediator=${MEDIATOR_PID} https=${HTTPS_PID} imds=${IMDS_PID} resolver=${RESOLVER_PID}"
echo "HTTPS_PROXY=http://127.0.0.1:${LOCAL_HTTPS_PORT}"

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
cleanup() {
    echo "Shutting down proxies..."
    kill $INBOUND_PID $MEDIATOR_PID $HTTPS_PID $IMDS_PID $RESOLVER_PID 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Config: the image bakes config.toml at $CONFIG_PATH.
# ---------------------------------------------------------------------------
# WHY UN-BAKED (fleet): so ONE enclave image (one PCR0) can be shared across
# every tenant, instead of building and attesting a separate EIF per tenant.
#
#   BAKE_CONFIG=true  (self-host, default): config.toml is fully baked into the
#     EIF (committed to PCR0). Nothing to fetch; the binary has no vsock
#     config-fetch code path at all.
#   BAKE_CONFIG=false (fleet): config.toml is a baked fleet-policy BASE with
#     placeholders for the tenant-scoped fields (key_arn, mediator_did,
#     vta_did_template, public_url, …). The vta-enclave binary (built with the
#     `tenant-overlay` feature) fetches a typed, allowlisted overlay from the
#     parent over vsock:5800 and applies it IN-PROCESS before it reads those
#     fields. The entrypoint no longer touches config — the fetch/parse/apply,
#     size-cap, timeouts, and deny_unknown_fields validation all live in Rust
#     (auditable + unit-tested). See
#     docs/05-design-notes/tenant-config-allowlist.md §3.8.
#
# Either way a config.toml MUST be present: refuse to boot without one rather
# than silently start with a wrong/empty config (fail-closed).
CONFIG_PATH="${VTA_CONFIG_PATH:-/etc/vta/config.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "FATAL: no config at $CONFIG_PATH — the enclave image must bake a config.toml" >&2
    echo "       (self-host: the full config; fleet: a fleet-policy base with placeholders)." >&2
    exit 1
fi
echo "Using config at $CONFIG_PATH"

# ---------------------------------------------------------------------------
# Start VTA
# ---------------------------------------------------------------------------
echo ""
echo "Starting VTA on 127.0.0.1:${VTA_PORT} (TEE mode: required)"
echo ""

# Run VTA (not exec, so we can capture crash output). Call in an `if` so `set -eu`
# does not abort on a non-zero exit before we log it and keep the console alive
# (the new config-floor hard-exits make a crashed/rejected boot common).
if vta-enclave --config "$CONFIG_PATH" 2>&1; then
    VTA_EXIT=0
else
    VTA_EXIT=$?
fi
echo "VTA exited with code ${VTA_EXIT}"
# Keep the enclave alive briefly so console output can be read
sleep 10
