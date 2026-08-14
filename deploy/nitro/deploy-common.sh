# =============================================================================
# Shared helpers for build-vta.sh, deploy-enclave.sh, and deploy-vta.sh
# =============================================================================
# This file is sourced, not executed. It defines logging, prompting, and
# process-management helpers used by the build and deploy scripts.
# =============================================================================

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -z "${_DEPLOY_COMMON_LOADED:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'

    _DEPLOY_COMMON_LOADED=1
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${BOLD}=== Step $1: $2 ===${NC}\n"; }

# ---------------------------------------------------------------------------
# Prompting — require callers to set INTERACTIVE=true|false before use
# ---------------------------------------------------------------------------
ask() {
    local prompt="$1" default="$2" var="$3"
    if [ "${INTERACTIVE:-true}" = true ]; then
        read -r -p "$(echo -e "${BOLD}${prompt}${NC} [${default}]: ")" input
        eval "$var=\"${input:-$default}\""
    else
        eval "$var=\"$default\""
    fi
}

ask_yn() {
    local prompt="$1" default="$2"
    if [ "${INTERACTIVE:-true}" = true ]; then
        read -r -p "$(echo -e "${BOLD}${prompt}${NC} [${default}]: ")" input
        input="${input:-$default}"
    else
        input="$default"
    fi
    [[ "$input" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------
# Return 0 if the pid stored in $1 is still alive.
pid_alive() {
    local pidfile="$1"
    # Optional PID-reuse guard: a substring the live process's command line must
    # contain to be accepted as "ours". Without it, a stale PID file whose PID has
    # been recycled to an unrelated process would look alive (and could be
    # signalled). Callers managing a long-lived daemon should pass it.
    local match="${2:-}"
    [ -f "$pidfile" ] || return 1
    local pid
    pid=$(cat "$pidfile" 2>/dev/null || true)
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -n "$match" ]; then
        local cmd=""
        if [ -r "/proc/$pid/cmdline" ]; then
            # Linux: argv is NUL-separated; render to spaces for matching.
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
        else
            # macOS / no procfs: fall back to ps.
            cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
        fi
        case "$cmd" in
            *"$match"*) : ;;
            *) return 1 ;;  # PID reused by an unrelated process — treat as dead.
        esac
    fi
    return 0
}

# Compose the parent-proxy routing signature from the effective envelope path,
# KMS region, and mediator DID. Recorded when the proxy starts; a change in any
# field on a later deploy means the running proxy is on stale routing and must be
# restarted (its process env + egress allowlist are fixed at launch). Kept as a
# pure function so it can be unit-tested (see deploy-common.test.sh).
proxy_routing_signature() {
    printf 'envelope=%s region=%s mediator=%s' "${1:-}" "${2:-}" "${3:-}"
}

# ---------------------------------------------------------------------------
# Tool presence
# ---------------------------------------------------------------------------
check_cmd() {
    if command -v "$1" &>/dev/null; then
        ok "$1 found: $(command -v "$1")"
        return 0
    else
        err "$1 not found"
        return 1
    fi
}

# Verify the current user is a member of a unix group.
check_group() {
    local group="$1" hint="$2"
    local current_user user_groups
    current_user=$(id -un)
    user_groups=$(id -Gn)
    if echo "$user_groups" | grep -qw "$group"; then
        ok "User '$current_user' is in the '$group' group"
        return 0
    else
        err "User '$current_user' is NOT in the '$group' group"
        err "$hint"
        err ""
        err "IMPORTANT: After adding the group, you MUST log out and log back in"
        err "(or start a new SSH session) for the change to take effect."
        err "Alternatively, run 'newgrp $group' in your current shell."
        return 1
    fi
}
