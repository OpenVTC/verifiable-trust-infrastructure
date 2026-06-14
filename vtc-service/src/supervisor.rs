//! Supervisor-handshake detection for `POST /v1/admin/config/restart`.
//!
//! Implements **M0.8.3** of the VTC MVP Phase 0 plan. The restart
//! endpoint refuses to trigger graceful shutdown unless the daemon
//! is running under a process supervisor that will start it back up
//! — without that, "restart" is just "kill the only process".
//!
//! ## Detection sources
//!
//! Probed in priority order. The first match wins; the result is
//! reported back so the audit log records *why* the restart was
//! allowed.
//!
//! 1. **`VTC_SUPERVISED=1`** — explicit operator opt-in. Use when
//!    the daemon is wrapped by something this module doesn't natively
//!    recognise (e.g., a custom shell loop, an init system without a
//!    notify socket, a process-supervisor harness in tests).
//! 2. **`NOTIFY_SOCKET`** — set by systemd for `Type=notify` units.
//!    Presence is sufficient; we don't need to actually talk to
//!    the socket for the supervisor check.
//! 3. **`KUBERNETES_SERVICE_HOST`** — Kubernetes injects this into
//!    every pod; if it's present we trust kubelet to restart the
//!    container per its `restartPolicy`.
//!
//! ## What this module deliberately does NOT do
//!
//! - We don't probe for the kubelet downward-API marker file
//!   (`/etc/podinfo/...`). Operators wanting that pattern can set
//!   `VTC_SUPERVISED=1` via the downward API instead — keeps the
//!   detection surface tiny.
//! - We don't authenticate the supervisor. The env var family is an
//!   inherited-from-launcher fact; an attacker who can set
//!   `VTC_SUPERVISED=1` already has process-level control.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub enum SupervisorKind {
    /// `VTC_SUPERVISED=1` env var present.
    Manual,
    /// `NOTIFY_SOCKET` env var present (systemd Type=notify or
    /// any shim that sets the same variable).
    Systemd,
    /// `KUBERNETES_SERVICE_HOST` env var present (running in a pod).
    Kubernetes,
}

/// Probe the process environment. Returns `Some(SupervisorKind)` if
/// any supported supervisor is detected; `None` otherwise.
pub fn detect_supervisor() -> Option<SupervisorKind> {
    detect_supervisor_in(&std::env::vars().collect::<std::collections::HashMap<_, _>>())
}

/// Same as [`detect_supervisor`] but reads from a caller-supplied
/// env map. Lets tests drive every branch deterministically without
/// mutating the process-wide env, which would race other tests.
pub fn detect_supervisor_in(
    env: &std::collections::HashMap<String, String>,
) -> Option<SupervisorKind> {
    if env.get("VTC_SUPERVISED").map(|v| v.as_str()) == Some("1") {
        return Some(SupervisorKind::Manual);
    }
    if env.get("NOTIFY_SOCKET").is_some_and(|v| !v.is_empty()) {
        return Some(SupervisorKind::Systemd);
    }
    if env
        .get("KUBERNETES_SERVICE_HOST")
        .is_some_and(|v| !v.is_empty())
    {
        return Some(SupervisorKind::Kubernetes);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn empty_env_returns_none() {
        assert_eq!(detect_supervisor_in(&HashMap::new()), None);
    }

    #[test]
    fn vtc_supervised_1_wins_first() {
        let env = env_with(&[
            ("VTC_SUPERVISED", "1"),
            ("NOTIFY_SOCKET", "/run/systemd/notify"),
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
        ]);
        assert_eq!(detect_supervisor_in(&env), Some(SupervisorKind::Manual));
    }

    #[test]
    fn vtc_supervised_other_values_dont_match() {
        // We require the literal string "1". "true", "yes", "0" all
        // miss — operators who fat-finger the value shouldn't get a
        // surprise-restart capability.
        for v in ["0", "true", "yes", "TRUE", " 1", "1 "] {
            let env = env_with(&[("VTC_SUPERVISED", v)]);
            assert_eq!(
                detect_supervisor_in(&env),
                None,
                "VTC_SUPERVISED={v:?} must not enable",
            );
        }
    }

    #[test]
    fn notify_socket_detects_systemd() {
        let env = env_with(&[("NOTIFY_SOCKET", "/run/systemd/notify")]);
        assert_eq!(detect_supervisor_in(&env), Some(SupervisorKind::Systemd));
    }

    #[test]
    fn empty_notify_socket_does_not_match() {
        // systemd never sets it to empty; a stale shell export could,
        // and we treat that as "no supervisor".
        let env = env_with(&[("NOTIFY_SOCKET", "")]);
        assert_eq!(detect_supervisor_in(&env), None);
    }

    #[test]
    fn kubernetes_service_host_detects_pod() {
        let env = env_with(&[("KUBERNETES_SERVICE_HOST", "10.0.0.1")]);
        assert_eq!(detect_supervisor_in(&env), Some(SupervisorKind::Kubernetes));
    }

    #[test]
    fn detection_priority_systemd_over_kubernetes() {
        let env = env_with(&[
            ("NOTIFY_SOCKET", "/run/systemd/notify"),
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
        ]);
        assert_eq!(detect_supervisor_in(&env), Some(SupervisorKind::Systemd));
    }
}
