//! Runtime service-management operations.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md`.
//!
//! Orchestrates the post-setup state changes for both REST and
//! DIDComm transports (enable / update / disable / rollback / list)
//! plus the DIDComm-only drain set (cancel / list / report).

pub mod disable_didcomm;
pub mod disable_rest;
pub mod disable_webauthn;
pub mod document;
pub mod drain_cancel;
pub mod enable_didcomm;
pub mod enable_rest;
pub mod enable_webauthn;
pub mod invariant;
pub mod list;
pub mod list_drain;
pub mod passkey_vm_cleanup;
pub mod preconditions;
pub mod report;
pub mod rollback_didcomm;
pub mod rollback_rest;
pub mod rollback_webauthn;
pub mod runtime_state;
pub(crate) mod service_lifecycle;
pub mod snapshot;
pub mod update_didcomm;
pub mod update_rest;
pub mod update_webauthn;

/// Process-wide lock serializing every service-management mutation
/// (enable / update / disable / rollback / drain-cancel). Modeled
/// on `MODE_B_LOCK` in `routes/bootstrap.rs`. Held across the entire
/// op (handshake → publish → registry update), not per-step.
///
/// Read paths (`services list`, `services report`) do not need the
/// lock and intentionally do not take it. Mutation paths take it
/// unconditionally.
pub static PROTOCOL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Drain-TTL bounds violation, returned by [`validate_drain_ttl`].
/// All values are seconds. Each per-op error type wraps this into
/// its own variant so the route layer can map to the typed
/// `VtaError::DrainTtlOutOfBounds` wire shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainTtlBoundsError {
    pub min: u64,
    pub max: u64,
    pub requested: u64,
}

impl std::fmt::Display for DrainTtlBoundsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "drain ttl {}s outside allowed range [{}s, {}s]",
            self.requested, self.min, self.max
        )
    }
}

impl std::error::Error for DrainTtlBoundsError {}

/// Validate a drain TTL against the [§3.6 bounds].
///
/// Lower bound depends on the transport the command was delivered
/// over: 1h floor for DIDComm (so the listener that's *carrying* the
/// disable command isn't torn down before the response lands), 0s
/// for REST. Upper bound is the workspace-wide
/// [`crate::messaging::registry::MAX_DRAIN_TTL`] (30 days).
///
/// Centralised here so all three op layers — `disable_didcomm`,
/// `update_didcomm`, `rollback_didcomm` — enforce the same bounds.
/// Mirrors the spec §7a.4 "drain-ttl 31d" / "drain-ttl 30s over
/// DIDComm" matrix cells.
pub fn validate_drain_ttl(
    transport: crate::operations::protocol::disable_didcomm::DisableTransport,
    ttl: std::time::Duration,
) -> Result<(), DrainTtlBoundsError> {
    use crate::messaging::registry::MAX_DRAIN_TTL;
    use crate::operations::protocol::disable_didcomm::{
        DisableTransport, MIN_DRAIN_TTL_OVER_DIDCOMM,
    };

    let min: u64 = match transport {
        DisableTransport::Didcomm => MIN_DRAIN_TTL_OVER_DIDCOMM.as_secs(),
        DisableTransport::Rest => 0,
    };
    let max: u64 = MAX_DRAIN_TTL.num_seconds() as u64;
    let requested = ttl.as_secs();

    if requested < min || requested > max {
        return Err(DrainTtlBoundsError {
            min,
            max,
            requested,
        });
    }
    Ok(())
}

/// Whether a forward operation was invoked directly by the
/// operator or as the fail-forward dispatch from a rollback.
///
/// Threaded through every forward op (enable / update / disable
/// for both REST and DIDComm) so the emitted telemetry event can
/// carry a `triggered_by: "rollback"` field per spec §3.5a. The
/// rollback layer (T3.1 / T3.2) reads the per-kind snapshot,
/// computes the equivalent forward operation, and dispatches into
/// it with [`OpContext::Rollback`]; the forward op runs unchanged
/// modulo this telemetry tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpContext {
    Direct,
    Rollback,
}

impl OpContext {
    /// JSON value to surface in the `triggered_by` telemetry field
    /// for this context. Returns `None` for [`OpContext::Direct`]
    /// — direct operations don't carry the field at all (omitted
    /// rather than serialized as `"direct"`, since the absence is
    /// the conventional signal).
    #[must_use]
    pub fn telemetry_triggered_by(self) -> Option<&'static str> {
        match self {
            OpContext::Direct => None,
            OpContext::Rollback => Some("rollback"),
        }
    }
}

/// Ambient dependencies shared by every service-management operation
/// (`enable` / `update` / `disable` / `rollback`, across REST, WebAuthn, and
/// DIDComm).
///
/// Before P2.5 each op took the same long run of positional arguments (config,
/// keyspaces, seed-store, resolver, bridge, telemetry, auth-locks, and — for the
/// DIDComm family — the mediator registry, drain sweeper, and drain keyspace),
/// tripping `clippy::too_many_arguments` (the worst topped out at 25 args).
/// Bundling them into one borrowed struct — built once at the transport boundary
/// via [`ServiceOpDeps::from_app_state`] / [`ServiceOpDeps::from_vta_state`] (or
/// directly by the offline CLI) and threaded through unchanged — drops every op
/// to ≤6 args and lets the rollback dispatcher hand its forward op the deps
/// verbatim instead of re-listing every keyspace.
///
/// All fields are borrows: the struct is cheap to build per request and never
/// outlives the state it borrows from. Each op reads the subset it needs — the
/// REST/WebAuthn ops ignore `drains_ks` / `registry` / `sweeper`; the lifecycle
/// engine ([`service_lifecycle`]) additionally ignores `service_state_ks` (the
/// REST persist step's concern). The per-call mediator handshake `prover` is
/// **not** here — it's constructed per invocation (transient vs live), so the
/// DIDComm ops still take it as a separate argument.
pub struct ServiceOpDeps<'a> {
    pub config: &'a std::sync::Arc<tokio::sync::RwLock<crate::config::AppConfig>>,
    pub keys_ks: &'a crate::store::KeyspaceHandle,
    pub imported_ks: &'a crate::store::KeyspaceHandle,
    pub contexts_ks: &'a crate::store::KeyspaceHandle,
    pub webvh_ks: &'a crate::store::KeyspaceHandle,
    pub audit_ks: &'a crate::store::KeyspaceHandle,
    pub snapshot_ks: &'a crate::store::KeyspaceHandle,
    pub service_state_ks: &'a crate::store::KeyspaceHandle,
    /// Persisted drain set — read only by the DIDComm family (mediator
    /// changes go through a drain window; REST/WebAuthn have no drain
    /// semantics).
    pub drains_ks: &'a crate::store::KeyspaceHandle,
    pub seed_store: &'a dyn vti_common::seed_store::SeedStore,
    pub did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    pub didcomm_bridge: &'a std::sync::Arc<crate::didcomm_bridge::DIDCommBridge>,
    pub telemetry: &'a vti_common::telemetry::SharedTelemetrySink,
    pub webvh_auth_locks: &'a crate::operations::did_webvh::WebvhAuthLocks,
    /// Active + draining mediator listener registry — DIDComm family only.
    #[cfg(feature = "webvh")]
    pub registry: &'a crate::messaging::registry::MediatorListenerRegistry,
    /// Per-mediator drain-TTL sweeper — DIDComm family only.
    #[cfg(feature = "webvh")]
    pub sweeper: &'a crate::messaging::drain_sweeper::DrainSweeper,
}

impl<'a> ServiceOpDeps<'a> {
    /// Borrow the service-op dependencies from an [`AppState`](crate::server::AppState)
    /// (REST transport).
    ///
    /// `did_resolver` is threaded separately because `AppState` holds it as an
    /// `Option` — the caller unwraps it (surfacing the typed
    /// `DidResolverUnavailable` reject) before building the deps.
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_app_state(
        s: &'a crate::server::AppState,
        did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    ) -> Self {
        Self {
            config: &s.config,
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            audit_ks: &s.audit_ks,
            snapshot_ks: &s.snapshot_ks,
            service_state_ks: &s.service_state_ks,
            drains_ks: &s.drains_ks,
            seed_store: &*s.seed_store,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            telemetry: &s.telemetry,
            webvh_auth_locks: &s.webvh_auth_locks,
            registry: &s.mediator_registry,
            sweeper: &s.drain_sweeper,
        }
    }

    /// Borrow the service-op dependencies from a
    /// [`VtaState`](crate::messaging::router::VtaState) (DIDComm transport).
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_vta_state(
        s: &'a crate::messaging::router::VtaState,
        did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    ) -> Self {
        Self {
            config: &s.config,
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            audit_ks: &s.audit_ks,
            snapshot_ks: &s.snapshot_ks,
            service_state_ks: &s.service_state_ks,
            drains_ks: &s.drains_ks,
            seed_store: &*s.seed_store,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            telemetry: &s.telemetry,
            webvh_auth_locks: &s.webvh_auth_locks,
            registry: &s.mediator_registry,
            sweeper: &s.drain_sweeper,
        }
    }

    /// Borrow the [`WebvhDeps`](crate::operations::did_webvh::WebvhDeps) subset —
    /// the keyspaces + seed-store + resolver + bridge + auth-locks the WebVH
    /// publish path (`update_did_webvh`) needs. Lets the protocol ops hand their
    /// `update_did_webvh` call a `WebvhDeps` without re-listing every field.
    pub fn webvh(&self) -> crate::operations::did_webvh::WebvhDeps<'a> {
        crate::operations::did_webvh::WebvhDeps {
            keys_ks: self.keys_ks,
            imported_ks: self.imported_ks,
            contexts_ks: self.contexts_ks,
            webvh_ks: self.webvh_ks,
            audit_ks: self.audit_ks,
            seed_store: self.seed_store,
            did_resolver: self.did_resolver,
            didcomm_bridge: self.didcomm_bridge,
            auth_locks: self.webvh_auth_locks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PROTOCOL_LOCK;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Two tasks contending for `PROTOCOL_LOCK` execute serially: the
    /// second cannot enter its critical section until the first has
    /// released. Detected via an `in_critical_section` counter that
    /// must never exceed 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn protocol_lock_serializes_concurrent_mutations() {
        let in_section = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        async fn critical(in_section: Arc<AtomicUsize>, max_observed: Arc<AtomicUsize>) {
            let _guard = PROTOCOL_LOCK.lock().await;
            let n = in_section.fetch_add(1, Ordering::SeqCst) + 1;
            max_observed.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            in_section.fetch_sub(1, Ordering::SeqCst);
        }

        let a = tokio::spawn(critical(Arc::clone(&in_section), Arc::clone(&max_observed)));
        let b = tokio::spawn(critical(Arc::clone(&in_section), Arc::clone(&max_observed)));
        let (ra, rb) = tokio::join!(a, b);
        ra.unwrap();
        rb.unwrap();

        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            1,
            "PROTOCOL_LOCK must serialize: at most one task in the critical section at a time"
        );
    }
}
