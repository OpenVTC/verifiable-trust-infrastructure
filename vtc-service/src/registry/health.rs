//! `RegistryHealth` — live reachability state for the trust
//! registry. Spec §8.1 + Phase 3 M3.2.
//!
//! The state flips between `Active` and `Degraded` as the
//! `health()` probe succeeds or fails. The `Arc<RwLock<...>>`
//! is shared on `AppState` so:
//!
//! - the boot-time probe sets the initial value,
//! - the periodic probe task updates it,
//! - the community-profile + diagnostics handlers read it,
//! - the syncer task reads it to gate dispatches (open
//!   breaker → enqueue + retry).
//!
//! Every flip emits a `RegistryStatusChanged` audit envelope.
//! The flip helper takes the audit writer + actor DID so the
//! emission stays adjacent to the state mutation.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};
use vti_common::audit::{AuditEvent, AuditWriter, RegistryStatusChangedData};

/// Wire-form reachability state. Mirrors what `GET
/// /v1/community/profile` surfaces in `registryStatus`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum HealthStatus {
    /// Last probe succeeded — the registry is reachable.
    Active,
    /// Last probe failed, the daemon hasn't probed yet, or
    /// the daemon is configured without a registry URL. The
    /// syncer keeps queuing jobs; sync-failure rates surface
    /// in diagnostics.
    #[default]
    Degraded,
}

impl HealthStatus {
    /// Wire-form string. Matches what
    /// `serde_json::to_value(self)` produces; surfaced here so
    /// the audit envelope's `from`/`to` fields don't need to
    /// round-trip through serde.
    pub fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Active => "active",
            HealthStatus::Degraded => "degraded",
        }
    }
}

/// Cheap-to-clone handle wrapping the live registry health
/// state + the last-success / last-failure timestamps.
/// `diagnostics` reads all three.
#[derive(Debug, Clone, Default)]
pub struct RegistryHealth {
    inner: Arc<RwLock<RegistryHealthInner>>,
}

#[derive(Debug, Default)]
struct RegistryHealthInner {
    status: HealthStatus,
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl RegistryHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current status. Cheap — single read-lock
    /// acquisition.
    pub async fn status(&self) -> HealthStatus {
        self.inner.read().await.status
    }

    /// Snapshot every field for the `/v1/health/diagnostics`
    /// endpoint (M3.8).
    pub async fn snapshot(&self) -> RegistryHealthSnapshot {
        let s = self.inner.read().await;
        RegistryHealthSnapshot {
            status: s.status,
            last_success_at: s.last_success_at,
            last_failure_at: s.last_failure_at,
            last_error: s.last_error.clone(),
        }
    }

    /// Record a successful probe + flip to `Active` if the
    /// previous state was `Degraded`. Emits a
    /// `RegistryStatusChanged` audit envelope on flip.
    pub async fn record_success(&self, audit_writer: Option<&AuditWriter>, actor_did: &str) {
        let mut guard = self.inner.write().await;
        let prior = guard.status;
        guard.status = HealthStatus::Active;
        guard.last_success_at = Some(Utc::now());
        guard.last_error = None;
        drop(guard);

        if prior != HealthStatus::Active {
            info!("trust-registry health probe recovered — flipping to active");
            emit_changed(audit_writer, actor_did, prior, HealthStatus::Active, None).await;
        }
    }

    /// Record a failed probe + flip to `Degraded` if the
    /// previous state was `Active`. Emits a
    /// `RegistryStatusChanged` audit envelope on flip.
    pub async fn record_failure(
        &self,
        error: impl Into<String>,
        audit_writer: Option<&AuditWriter>,
        actor_did: &str,
    ) {
        let error = error.into();
        let mut guard = self.inner.write().await;
        let prior = guard.status;
        guard.status = HealthStatus::Degraded;
        guard.last_failure_at = Some(Utc::now());
        guard.last_error = Some(error.clone());
        drop(guard);

        if prior != HealthStatus::Degraded {
            warn!(error = %error, "trust-registry health probe failed — flipping to degraded");
            emit_changed(
                audit_writer,
                actor_did,
                prior,
                HealthStatus::Degraded,
                Some(error),
            )
            .await;
        }
    }
}

/// Snapshot of every health-tracked field. Returned by
/// [`RegistryHealth::snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryHealthSnapshot {
    pub status: HealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

async fn emit_changed(
    audit_writer: Option<&AuditWriter>,
    actor_did: &str,
    from: HealthStatus,
    to: HealthStatus,
    reason: Option<String>,
) {
    let Some(writer) = audit_writer else {
        return;
    };
    let payload = AuditEvent::RegistryStatusChanged(RegistryStatusChangedData {
        from: from.as_str().to_string(),
        to: to.as_str().to_string(),
        reason,
    });
    if let Err(e) = writer.write(actor_did, None, payload).await {
        warn!(error = %e, "failed to emit RegistryStatusChanged");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_status_is_degraded() {
        let h = RegistryHealth::new();
        assert_eq!(h.status().await, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn record_success_flips_to_active() {
        let h = RegistryHealth::new();
        h.record_success(None, "did:key:zVtc").await;
        let snap = h.snapshot().await;
        assert_eq!(snap.status, HealthStatus::Active);
        assert!(snap.last_success_at.is_some());
        assert!(snap.last_error.is_none());
    }

    #[tokio::test]
    async fn record_failure_flips_to_degraded() {
        let h = RegistryHealth::new();
        h.record_success(None, "did:key:zVtc").await;
        h.record_failure("connection refused", None, "did:key:zVtc")
            .await;
        let snap = h.snapshot().await;
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert!(snap.last_failure_at.is_some());
        assert_eq!(snap.last_error.as_deref(), Some("connection refused"));
    }

    #[tokio::test]
    async fn consecutive_successes_dont_re_emit() {
        // We can't observe the audit emission from here without
        // a writer, but the smoke test confirms repeat calls
        // don't panic + the state stays Active.
        let h = RegistryHealth::new();
        h.record_success(None, "did:key:zVtc").await;
        h.record_success(None, "did:key:zVtc").await;
        h.record_success(None, "did:key:zVtc").await;
        assert_eq!(h.status().await, HealthStatus::Active);
    }

    #[test]
    fn health_status_wire_form() {
        assert_eq!(HealthStatus::Active.as_str(), "active");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        let v = serde_json::to_value(HealthStatus::Active).unwrap();
        assert_eq!(v, serde_json::json!("active"));
    }
}
