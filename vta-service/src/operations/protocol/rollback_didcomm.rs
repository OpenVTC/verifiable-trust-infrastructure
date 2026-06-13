//! `rollback_didcomm` operation — fail-forward dispatch.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.5a.
//!
//! Reads the per-kind snapshot store for `didcomm` and dispatches
//! into the equivalent forward operation that returns the VTA's
//! DIDComm service entry to the pre-mutation state. WebVH is
//! append-only; rollback never rewinds the chain — it appends a
//! new LogEntry plus, where the prior state involved an active
//! mediator, drains the just-departed mediator with the supplied
//! TTL.
//!
//! Dispatch table:
//!
//! | snapshot              | current state         | dispatched op            |
//! |-----------------------|-----------------------|--------------------------|
//! | `Disabled`            | enabled (mediator Y)  | `disable_didcomm`        |
//! | `Enabled { X }`       | disabled              | `enable_didcomm` with X  |
//! | `Enabled { X }`       | enabled (Y), X != Y   | `update_didcomm` X→Y     |
//! | `Disabled`            | disabled              | no-op (snapshot≡current) |
//! | `Enabled { X }`       | enabled (X)           | no-op (snapshot≡current) |
//!
//! The `update_didcomm` arm is the most common case in practice:
//! rolling back a `services didcomm update A→B` re-promotes A
//! and drains B. Spec §3.5a explicitly notes that drain is
//! re-fed via the same forward path, so the new drain entry uses
//! the operator-supplied `drain_ttl` (default 24h).
//!
//! Brick-prevention is enforced by the dispatched forward op
//! (the `disable_didcomm` arm goes through
//! `would_violate_last_service`). Rolling back a `services
//! didcomm enable` when REST is also off surfaces
//! `LastServiceRefused` verbatim per §7a.5.

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::messaging::handshake::{HandshakeError, ListenerProver};
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommError, DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::document::{DocumentPatchError, current_didcomm_service};
use crate::operations::protocol::enable_didcomm::{
    EnableDidcommError, EnableDidcommParams, enable_didcomm,
};
use crate::operations::protocol::snapshot::{
    self, DidcommSnapshot, ServiceConfigSnapshot, ServiceKind,
};
use crate::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommError, UpdateDidcommParams, update_didcomm,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::store::KeyspaceHandle;

/// Handshake timeout when re-promoting a prior mediator. Matches
/// the default that the route layer applies for forward
/// operations.
const DEFAULT_ROLLBACK_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct RollbackDidcommParams {
    /// Drain window applied to the mediator being demoted by this
    /// rollback. Used by the `update_didcomm` arm (drains the
    /// currently-active mediator while promoting the prior one)
    /// and by the `disable_didcomm` arm (drains the
    /// currently-active mediator on the way to "DIDComm off").
    /// Spec §3.6 default: 24h.
    pub drain_ttl: Duration,
    /// Transport over which the rollback request was delivered.
    /// Drives the same `MIN_DRAIN_TTL_OVER_DIDCOMM` floor that
    /// applies to direct disable: a rollback that disables
    /// DIDComm over the DIDComm transport with `drain_ttl < 1h`
    /// is refused so the listener doesn't drop the response
    /// mid-flight.
    pub transport: DisableTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackKind {
    /// Snapshot was `Disabled`; rollback re-disabled DIDComm.
    Disabled,
    /// Snapshot was `Enabled { mediator: X }`; rollback re-enabled
    /// DIDComm with X (forward operation: enable_didcomm).
    Enabled,
    /// Snapshot was `Enabled { mediator: X }`; current was Y;
    /// rollback updated the mediator from Y back to X (forward
    /// operation: update_didcomm).
    Updated,
    /// Snapshot ≡ current state. No LogEntry was published.
    NoOp,
}

#[derive(Debug, Clone)]
pub struct RollbackDidcommResult {
    /// `Some(version_id)` when a LogEntry was published, `None`
    /// when the rollback was a no-op (snapshot ≡ current).
    pub new_version_id: Option<String>,
    pub kind: RollbackKind,
    /// Mediator being drained as part of this rollback (the
    /// previously-active one), or `None` for `Enabled` /
    /// `NoOp` arms where no drain is scheduled.
    pub draining_mediator: Option<String>,
    /// The VTA's own DID. Empty for no-op rollbacks. See
    /// [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. `false` on no-op
    /// rollbacks.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum RollbackDidcommError {
    #[error(
        "no prior mutation for `services didcomm` to roll back from. \
         Use `services didcomm enable / update / disable` directly instead."
    )]
    NoPriorMutation,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,

    #[error(transparent)]
    EnableForward(#[from] EnableDidcommError),
    #[error(transparent)]
    UpdateForward(#[from] UpdateDidcommError),
    #[error(transparent)]
    DisableForward(#[from] DisableDidcommError),

    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for RollbackDidcommError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for RollbackDidcommError
{
    fn from(value: crate::operations::protocol::preconditions::ProtocolPreconditionError) -> Self {
        use crate::operations::protocol::preconditions::ProtocolPreconditionError as E;
        match value {
            E::VtaDidNotConfigured => Self::VtaDidNotConfigured,
            E::VtaDidRecordMissing(s) => Self::VtaDidRecordMissing(s),
            E::VtaDidLogMissing(s) => Self::VtaDidLogMissing(s),
            E::EmptyLog => Self::EmptyLog,
            E::Storage(s) | E::DocumentParse(s) => Self::Storage(s),
        }
    }
}

pub async fn rollback_didcomm(
    deps: &ServiceOpDeps<'_>,
    prover: &(dyn ListenerProver + Send + Sync),
    auth: &AuthClaims,
    params: RollbackDidcommParams,
    channel: &str,
) -> Result<RollbackDidcommResult, RollbackDidcommError> {
    auth.require_super_admin()
        .map_err(|e| RollbackDidcommError::Auth(e.to_string()))?;

    // PROTOCOL_LOCK is taken by the dispatched forward op —
    // holding it twice would deadlock. The snapshot read is
    // atomic via fjall.
    let snap = snapshot::read(deps.snapshot_ks, ServiceKind::Didcomm)
        .await
        .map_err(|e| RollbackDidcommError::Storage(format!("snapshot read: {e}")))?
        .ok_or(RollbackDidcommError::NoPriorMutation)?;
    let didcomm_snap = match snap {
        ServiceConfigSnapshot::Didcomm(s) => s,
        other => {
            return Err(RollbackDidcommError::Storage(format!(
                "snapshot kind mismatch: stored {other:?}, requested Didcomm",
            )));
        }
    };

    let current_mediator = read_current_didcomm_mediator(deps.config, deps.webvh_ks).await?;

    info!(
        channel,
        snapshot = ?didcomm_snap,
        current = ?current_mediator,
        "rollback_didcomm dispatching",
    );

    match (didcomm_snap, current_mediator.as_deref()) {
        // Snapshot says off, currently on → disable.
        (DidcommSnapshot::Disabled, Some(prior)) => {
            let result = disable_didcomm(
                deps,
                auth,
                DisableDidcommParams {
                    drain_ttl: params.drain_ttl,
                    transport: params.transport,
                },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackDidcommResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Disabled,
                draining_mediator: Some(prior.to_string()),
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with mediator X, currently off →
        // enable with X. No drain (nothing is currently active
        // to demote).
        (
            DidcommSnapshot::Enabled {
                mediator_did,
                routing_keys: _,
            },
            None,
        ) => {
            let result = enable_didcomm(
                deps,
                prover,
                auth,
                EnableDidcommParams {
                    mediator_did: mediator_did.clone(),
                    force: false,
                    handshake_timeout: DEFAULT_ROLLBACK_HANDSHAKE_TIMEOUT,
                },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackDidcommResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Enabled,
                draining_mediator: None,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with mediator X, currently on with Y
        // where X != Y → update Y→X. Drains Y for the supplied
        // TTL.
        (
            DidcommSnapshot::Enabled {
                mediator_did,
                routing_keys: _,
            },
            Some(current),
        ) if mediator_did != current => {
            let result = update_didcomm(
                deps,
                prover,
                auth,
                UpdateDidcommParams {
                    new_mediator_did: mediator_did.clone(),
                    drain_ttl: params.drain_ttl,
                    force: false,
                    handshake_timeout: DEFAULT_ROLLBACK_HANDSHAKE_TIMEOUT,
                    audit_kind: MigrateAuditKind::Rollback,
                    transport: params.transport,
                },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackDidcommResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Updated,
                draining_mediator: Some(result.prior_mediator_did),
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot ≡ current state — no-op.
        _ => {
            info!(
                channel,
                "rollback_didcomm: snapshot matches current state — no-op"
            );
            Ok(RollbackDidcommResult {
                new_version_id: None,
                kind: RollbackKind::NoOp,
                draining_mediator: None,
                // No LogEntry written — empty `vta_did` + `false`
                // are the "no follow-up needed" sentinel for the
                // CLI hint path.
                vta_did: String::new(),
                serverless: false,
            })
        }
    }
}

async fn read_current_didcomm_mediator(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<Option<String>, RollbackDidcommError> {
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    Ok(current_didcomm_service(&state.current_doc).map(|svc| svc.mediator_did))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn empty_keyspace(name: &str) -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(name).unwrap();
        (dir, ks)
    }

    /// Empty snapshot keyspace yields the typed
    /// NoPriorMutation error path. Pin the error message for
    /// the CLI's suggested-fix string.
    #[tokio::test]
    async fn no_prior_mutation_error_message_is_actionable() {
        let (_dir, ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        let snap = snapshot::read(&ks, ServiceKind::Didcomm).await.unwrap();
        assert!(snap.is_none());

        let err = RollbackDidcommError::NoPriorMutation;
        let msg = err.to_string();
        assert!(
            msg.contains("no prior mutation"),
            "error message must point operator at the right next step, got: {msg}",
        );
        assert!(msg.contains("services didcomm enable"));
    }

    #[tokio::test]
    async fn snapshot_disabled_round_trips() {
        let (_dir, ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        snapshot::write(
            &ks,
            ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled),
        )
        .await
        .unwrap();
        let read = snapshot::read(&ks, ServiceKind::Didcomm)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled) => {}
            other => panic!("expected Didcomm(Disabled), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snapshot_enabled_with_mediator_round_trips() {
        let (_dir, ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        snapshot::write(
            &ks,
            ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
                mediator_did: "did:peer:2.M".into(),
                routing_keys: vec![],
            }),
        )
        .await
        .unwrap();
        let read = snapshot::read(&ks, ServiceKind::Didcomm)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled { mediator_did, .. }) => {
                assert_eq!(mediator_did, "did:peer:2.M");
            }
            other => panic!("expected Didcomm(Enabled), got {other:?}"),
        }
    }

    #[test]
    fn rollback_kind_variants_are_distinct() {
        assert_ne!(RollbackKind::Disabled, RollbackKind::Enabled);
        assert_ne!(RollbackKind::Enabled, RollbackKind::Updated);
        assert_ne!(RollbackKind::Updated, RollbackKind::NoOp);
    }

    /// `RollbackDidcommParams` carries both drain_ttl and transport
    /// — the transport drives the MIN_DRAIN_TTL_OVER_DIDCOMM floor
    /// when the dispatched op is `disable_didcomm` over DIDComm
    /// transport.
    #[test]
    fn params_carry_transport_and_ttl() {
        let p = RollbackDidcommParams {
            drain_ttl: Duration::from_secs(86_400),
            transport: DisableTransport::Rest,
        };
        assert_eq!(p.drain_ttl.as_secs(), 86_400);
        assert_eq!(p.transport, DisableTransport::Rest);
    }
}
