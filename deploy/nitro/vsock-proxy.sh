#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Parent Instance Vsock Proxy
# =============================================================================
#
# This script runs on the PARENT EC2 instance (not inside the enclave).
# It forwards TCP traffic between the outside world and the enclave via vsock.
#
# Traffic flow:
#   Client → TCP :8443 → [this proxy] → vsock CID:PORT → Enclave VTA :8100
#
# Prerequisites:
#   - socat installed (sudo yum install -y socat  OR  sudo apt install -y socat)
#   - Nitro Enclave running (nitro-cli run-enclave ...)
#
# Usage:
#   ./vsock-proxy.sh                    # Defaults: listen 0.0.0.0:8443, enclave CID auto-detected
#   ./vsock-proxy.sh 8080               # Custom listen port
#   ./vsock-proxy.sh 8080 16            # Custom listen port + enclave CID
# =============================================================================

set -euo pipefail

LISTEN_PORT="${1:-8443}"
ENCLAVE_CID="${2:-}"
ENCLAVE_PORT="${3:-8100}"

# ---------------------------------------------------------------------------
# Auto-detect enclave CID if not provided
# ---------------------------------------------------------------------------
if [ -z "$ENCLAVE_CID" ]; then
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
    echo "Detected enclave CID: $ENCLAVE_CID"
fi

echo ""
echo "=== VTA Vsock Proxy ==="
echo "  Listen:  0.0.0.0:${LISTEN_PORT} (TCP)"
echo "  Forward: CID ${ENCLAVE_CID}:${ENCLAVE_PORT} (vsock)"
echo ""
echo "Test with:"
echo "  curl http://localhost:${LISTEN_PORT}/health"
echo "  curl http://localhost:${LISTEN_PORT}/health"
echo ""

# ---------------------------------------------------------------------------
# Run socat proxy (TCP → vsock)
# ---------------------------------------------------------------------------
# socat forwards each incoming TCP connection to the enclave via vsock.
# VSOCK-CONNECT requires CID:PORT format.
exec socat \
    TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork \
    VSOCK-CONNECT:${ENCLAVE_CID}:${ENCLAVE_PORT}
