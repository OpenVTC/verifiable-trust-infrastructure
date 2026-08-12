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
VSOCK_CONFIG_PORT="${VSOCK_CONFIG_PORT:-5800}"         # Inbound config envelope (parent → VTA)

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
# Config: baked-in / mounted config wins; otherwise fetch it over vsock.
# ---------------------------------------------------------------------------
# WHY UN-BAKED: so ONE enclave image (one PCR0) can be shared across every
# tenant, instead of building and attesting a separate Docker image / EIF per
# tenant. Tenant-specific values (key_arn, mediator_did, vta_did_template,
# public_url, resolver_url) are therefore delivered at runtime rather than baked
# in. The trade-off is deliberate and bounded: those values leave PCR0's cover,
# but the properties that matter are still protected independently of this
# channel — secret custody by KMS+attestation, TEE enforcement by the compiled-in
# floor check (in PCR0), admin by the attested Mode B flow, and the whole config
# by the attestation-digest anchor. See docs + the floor checks in vta-enclave.
#
# UN-BAKED CONFIG: the image carries no tenant config. The parent
# serves a versioned envelope over vsock:${VSOCK_CONFIG_PORT}:
#     { "version": 1, "config_toml": "…", "integrity": null }
# We connect, read it, and write config_toml to $CONFIG_PATH before starting the
# VTA. A pre-existing config at $CONFIG_PATH (mounted/baked for local dev) is used
# as-is and short-circuits the fetch.
CONFIG_PATH="${VTA_CONFIG_PATH:-/etc/vta/config.toml}"

# Envelope wire version this entrypoint understands. The parent stamps a
# `version` on the envelope; we refuse anything else so a future breaking
# envelope shape fails loudly instead of being mis-parsed.
SUPPORTED_CONFIG_ENVELOPE_VERSION="${SUPPORTED_CONFIG_ENVELOPE_VERSION:-1}"

# Fail-closed by default: in production the tenant config MUST arrive over vsock.
# Set VTA_ALLOW_DEFAULT_CONFIG=true ONLY for local/dev runs to permit the
# env-var-derived fallback config below.
ALLOW_DEFAULT_CONFIG="${VTA_ALLOW_DEFAULT_CONFIG:-false}"

# Hard cap on the envelope read from the (untrusted) parent. The enclave rootfs
# is RAM carved from its fixed allocation, so an unbounded read is a
# memory-exhaustion vector — mirror the service's 1 MB request-body cap.
MAX_CONFIG_ENVELOPE_BYTES="${MAX_CONFIG_ENVELOPE_BYTES:-1048576}"
# Per-attempt connect + overall read timeouts, so a parent that accepts the
# connection and then hangs cannot block boot forever (the retry loop must
# actually advance — the "give up after ~60s" guarantee depends on this).
CONFIG_FETCH_CONNECT_TIMEOUT="${CONFIG_FETCH_CONNECT_TIMEOUT:-5}"
CONFIG_FETCH_READ_TIMEOUT="${CONFIG_FETCH_READ_TIMEOUT:-10}"

fetch_config_over_vsock() {
    # Retry with bounded backoff: on a cold boot the enclave and the parent's
    # config server start concurrently, so a single attempt could race ahead of
    # the parent binding vsock:${VSOCK_CONFIG_PORT}. Give up after ~60s.
    # Return: 0 = config written, 1 = unreachable after retries, 2 = unsupported version.
    envelope_tmp="$(mktemp)"
    attempt=1
    max_attempts=30
    while [ "$attempt" -le "$max_attempts" ]; do
        # Bounded read from an untrusted source: connect-timeout guards a parent
        # that never accepts; the outer `timeout` guards one that accepts then
        # hangs; `head -c` caps the bytes pulled into enclave RAM.
        if timeout "${CONFIG_FETCH_READ_TIMEOUT}" socat -u \
                "VSOCK-CONNECT:${PARENT_CID}:${VSOCK_CONFIG_PORT},connect-timeout=${CONFIG_FETCH_CONNECT_TIMEOUT}" - 2>/dev/null \
                | head -c "${MAX_CONFIG_ENVELOPE_BYTES}" > "$envelope_tmp" \
            && [ -s "$envelope_tmp" ] \
            && jq -e '.config_toml' "$envelope_tmp" >/dev/null 2>&1; then
            # Reject an envelope whose wire version we do not understand rather
            # than blindly consuming `.config_toml` from an incompatible shape.
            version="$(jq -r '.version // "missing"' "$envelope_tmp" 2>/dev/null)"
            if [ "$version" != "$SUPPORTED_CONFIG_ENVELOPE_VERSION" ]; then
                rm -f "$envelope_tmp"
                echo "FATAL: config envelope version '${version}' is unsupported (this enclave speaks v${SUPPORTED_CONFIG_ENVELOPE_VERSION})" >&2
                return 2
            fi
            mkdir -p "$(dirname "$CONFIG_PATH")"
            jq -r '.config_toml' "$envelope_tmp" > "$CONFIG_PATH"
            rm -f "$envelope_tmp"
            echo "Fetched tenant config over vsock (attempt ${attempt}) → $CONFIG_PATH"
            return 0
        fi
        # Distinguish "envelope too big" (hit the read cap, so jq saw truncated
        # JSON) from "server not ready" — otherwise an oversized envelope just
        # looks like 30 failed connects for 60s.
        if [ -s "$envelope_tmp" ] \
            && [ "$(wc -c < "$envelope_tmp")" -ge "${MAX_CONFIG_ENVELOPE_BYTES}" ]; then
            echo "config envelope hit the ${MAX_CONFIG_ENVELOPE_BYTES}-byte read cap and was truncated — refusing (check the parent's config-envelope.json size); attempt ${attempt}/${max_attempts}" >&2
        else
            echo "config server not ready on vsock:${VSOCK_CONFIG_PORT} (attempt ${attempt}/${max_attempts}); retrying in 2s..."
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    rm -f "$envelope_tmp"
    return 1
}

fetch_rc=0
# Config provenance for the enclave's security floor (see vta-enclave). The
# entrypoint is baked into the image (measured into PCR0), so the value it sets
# here is trustworthy — the parent cannot forge it. Default to the untrusted
# value up front (overriding anything the parent tried to inject), then refine:
#   baked   = config already in the image / mounted (in PCR0 when baked → trusted)
#   vsock   = config fetched from the parent at runtime (parent-authored)
#   default = env-var dev fallback (parent-influenced)
# The Rust floor enforces only on the non-`baked` (parent-influenced) sources, so
# a legitimately baked config may carry admin_did / its own settings.
export VTA_CONFIG_SOURCE=vsock
if [ -f "$CONFIG_PATH" ]; then
    echo "Using existing config at $CONFIG_PATH"
    export VTA_CONFIG_SOURCE=baked
else
    # Call in an `if` condition so `set -eu` (line 29) does NOT abort on the
    # fetch's non-zero return (1 = unreachable after retries, 2 = bad version).
    # A BARE `fetch_config_over_vsock` here would exit the shell immediately,
    # making the fail-closed diagnostics and VTA_ALLOW_DEFAULT_CONFIG fallback
    # below unreachable dead code. Keep this in condition context.
    if fetch_config_over_vsock; then
        fetch_rc=0
        export VTA_CONFIG_SOURCE=vsock
    else
        fetch_rc=$?
    fi
fi

if [ ! -f "$CONFIG_PATH" ] && [ "$fetch_rc" -ne 0 ]; then
    if [ "$fetch_rc" -eq 2 ]; then
        # Version mismatch is a hard, non-recoverable error — never fall through
        # to a default config that would silently mask a broken deploy.
        echo "FATAL: refusing to start with an unsupported config envelope version" >&2
        exit 1
    elif [ "$ALLOW_DEFAULT_CONFIG" != "true" ]; then
        # Fail-closed: production always delivers config over vsock. Booting a TEE
        # VTA with an env-var-derived default here would mask a config-delivery
        # failure, so we exit non-zero instead.
        echo "FATAL: no config at $CONFIG_PATH and vsock fetch failed after retries." >&2
        echo "       Tenant config must be delivered over vsock:${VSOCK_CONFIG_PORT}." >&2
        echo "       For local/dev only, set VTA_ALLOW_DEFAULT_CONFIG=true to allow an env-var fallback." >&2
        exit 1
    fi

    # Opt-in local/dev fallback: generate a minimal config from env vars so a run
    # without a parent config server still boots. NEVER enabled in production.
    MEDIATOR_URL="${VTA_MEDIATOR_URL:-}"
    MEDIATOR_DID="${VTA_MEDIATOR_DID:-}"

    echo "VTA_ALLOW_DEFAULT_CONFIG=true — generating dev fallback config at $CONFIG_PATH"
    export VTA_CONFIG_SOURCE=default
    mkdir -p "$(dirname "$CONFIG_PATH")"
    cat > "$CONFIG_PATH" <<TOML
# VTA Configuration — Nitro Enclave (auto-generated fallback)

[services]
rest = true
didcomm = true

[server]
host = "127.0.0.1"
port = ${VTA_PORT}

[log]
level = "info"
format = "json"

[store]
data_dir = "/var/lib/vta/data"

[tee]
mode = "required"
embed_in_did = true
attestation_cache_ttl = 300

[secrets]
# Set VTA_SECRETS_SEED env var

[auth]
# Set VTA_AUTH_JWT_SIGNING_KEY env var
TOML

    # Add messaging section if mediator is configured
    if [ -n "$MEDIATOR_URL" ] && [ -n "$MEDIATOR_DID" ]; then
        # The TDK resolves mediator_did to discover the WebSocket endpoint,
        # then routes the connection through HTTPS_PROXY (set below) which
        # tunnels via vsock to the parent's HTTPS CONNECT proxy.
        cat >> "$CONFIG_PATH" <<TOML

[messaging]
mediator_url = "${MEDIATOR_URL}"
mediator_did = "${MEDIATOR_DID}"
TOML
        echo "DIDComm enabled: mediator=${MEDIATOR_URL} (WebSocket proxied via HTTPS_PROXY)"
    else
        echo "WARNING: VTA_MEDIATOR_URL / VTA_MEDIATOR_DID not set — DIDComm disabled"
        # Disable DIDComm if no mediator configured
        sed -i 's/didcomm = true/didcomm = false/' "$CONFIG_PATH"
    fi

    echo "Config written to $CONFIG_PATH"
fi

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
