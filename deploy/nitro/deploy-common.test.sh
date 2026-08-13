#!/usr/bin/env bash
# =============================================================================
# deploy-common.test.sh — focused regression tests for the pure helpers in
# deploy-common.sh: proxy_routing_signature (proxy-restart decision) and the
# pid_alive PID-reuse guard.
#
# Run: deploy/nitro/deploy-common.test.sh   (exit 0 = all passed)
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Only the function definitions are needed; suppress any incidental output.
# shellcheck source=deploy/nitro/deploy-common.sh
source "$SCRIPT_DIR/deploy-common.sh" >/dev/null 2>&1

PASS=0
FAIL=0
check() { # check <description> <actual> <expected>
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $1 — expected [$3], got [$2]" >&2
    fi
}
check_true()  { if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL: expected success: $*" >&2; fi; }
check_false() { if "$@" >/dev/null 2>&1; then FAIL=$((FAIL + 1)); echo "FAIL: expected failure: $*" >&2; else PASS=$((PASS + 1)); fi; }

# ── proxy_routing_signature: determinism + change detection ──────────────────
SIG_A="$(proxy_routing_signature /run/env.json us-east-1 did:webvh:x)"
SIG_A2="$(proxy_routing_signature /run/env.json us-east-1 did:webvh:x)"
check "signature is deterministic" "$SIG_A" "$SIG_A2"

SIG_REGION="$(proxy_routing_signature /run/env.json us-west-2 did:webvh:x)"
check_false test "$SIG_A" = "$SIG_REGION"   # different region ⇒ restart

SIG_MED="$(proxy_routing_signature /run/env.json us-east-1 did:webvh:y)"
check_false test "$SIG_A" = "$SIG_MED"      # different mediator ⇒ restart

SIG_ENV="$(proxy_routing_signature /run/other.json us-east-1 did:webvh:x)"
check_false test "$SIG_A" = "$SIG_ENV"      # different envelope ⇒ restart

# Empty fields are handled (no unbound-variable failure) and stable.
SIG_EMPTY="$(proxy_routing_signature '' '' '')"
check "empty signature is stable" "$SIG_EMPTY" "envelope= region= mediator="

# ── pid_alive: liveness + PID-reuse guard ────────────────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PIDFILE="$TMP/proc.pid"

# Missing pidfile ⇒ not alive.
check_false pid_alive "$PIDFILE"

# Live process, no match ⇒ alive.
sleep 30 &
LIVE_PID=$!
echo "$LIVE_PID" > "$PIDFILE"
check_true pid_alive "$PIDFILE"

# Live process, matching command substring ⇒ alive.
check_true pid_alive "$PIDFILE" "sleep"

# Live process, NON-matching substring ⇒ treated as dead (PID-reuse guard):
# the PID exists but is not our expected process.
check_false pid_alive "$PIDFILE" "enclave-proxy-not-this-process"

# Dead PID (killed) ⇒ not alive.
kill "$LIVE_PID" 2>/dev/null || true
wait "$LIVE_PID" 2>/dev/null || true
check_false pid_alive "$PIDFILE"
check_false pid_alive "$PIDFILE" "sleep"

echo "deploy-common.test.sh: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

