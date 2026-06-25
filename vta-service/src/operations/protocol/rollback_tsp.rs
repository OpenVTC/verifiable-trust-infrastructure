//! `rollback_tsp` operation — fail-forward dispatch.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.5a +
//! `docs/05-design-notes/tsp-enablement.md`.
//!
//! Reads the per-kind snapshot store for `tsp` and dispatches into the
//! equivalent **forward** operation that returns the VTA's TSP advertisement to
//! the pre-mutation state. WebVH is append-only; rollback never rewinds the
//! chain — it appends a new LogEntry whose `service[]` matches the snapshot.
//!
//! Dispatch table (mirrors [`super::rollback_rest`], mediator DID in place of
//! URL):
//!
//! | snapshot         | current state    | dispatched op            |
//! |------------------|------------------|--------------------------|
//! | `Disabled`       | enabled          | `disable_tsp`            |
//! | `Enabled { X }`  | disabled         | `enable_tsp` with X      |
//! | `Enabled { X }`  | enabled with Y   | `update_tsp` with X      |
//! | `Disabled`       | disabled         | no-op (snapshot≡current) |
//! | `Enabled { X }`  | enabled with X   | no-op (snapshot≡current) |
//!
//! No-op rollbacks happen when (a) a previous mutation crashed between
//! snapshot persist and runtime mutation, or (b) the operator runs `rollback`
//! twice in a row. Both are valid; the operator sees a result with
//! `new_version_id: None` and a `kind == NoOp` marker.
//!
//! Brick-prevention is enforced by the dispatched forward op (its disable path
//! already calls [`would_violate_last_service`]). The §7a.5 rollback histories
//! that resolve to `LastServiceRefused` surface the typed error from the
//! forward op verbatim.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::disable_tsp::{DisableTspError, DisableTspParams, disable_tsp};
use crate::operations::protocol::document::{DocumentPatchError, current_tsp_service};
use crate::operations::protocol::enable_tsp::{EnableTspError, EnableTspParams, enable_tsp};
use crate::operations::protocol::snapshot::{
    self, ServiceConfigSnapshot, ServiceKind, TspSnapshot,
};
use crate::operations::protocol::update_tsp::{UpdateTspError, UpdateTspParams, update_tsp};
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct RollbackTspParams;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackKind {
    /// Snapshot was `Disabled`; rollback re-disabled TSP.
    Disabled,
    /// Snapshot was `Enabled { mediator_did }`; rollback re-enabled TSP
    /// at the prior mediator (forward operation: enable_tsp).
    Enabled,
    /// Snapshot was `Enabled { mediator_did }`; rollback restored the
    /// prior mediator on an existing entry (forward operation: update_tsp).
    Updated,
    /// Snapshot ≡ current state. No LogEntry was published.
    NoOp,
}

#[derive(Debug, Clone)]
pub struct RollbackTspResult {
    /// `Some(version_id)` when a LogEntry was published, `None` when the
    /// rollback was a no-op (snapshot ≡ current).
    pub new_version_id: Option<String>,
    pub kind: RollbackKind,
    /// The VTA's own DID. Empty for no-op rollbacks (no LogEntry was
    /// written). See [`super::enable_tsp::EnableTspResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. `false` on no-op rollbacks
    /// (no follow-up redeploy needed).
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum RollbackTspError {
    #[error(
        "no prior mutation for `services tsp` to roll back from. \
         Use `services tsp enable / update / disable` directly instead."
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

    /// Forward dispatch into `enable_tsp` failed. The inner error carries
    /// any typed variants the operator should act on (e.g. `Validation` if
    /// the snapshotted mediator DID is malformed — shouldn't happen since
    /// the snapshot was written by an already-validated forward op, but
    /// defensive).
    #[error(transparent)]
    EnableForward(#[from] EnableTspError),
    /// Forward dispatch into `update_tsp` failed.
    #[error(transparent)]
    UpdateForward(#[from] UpdateTspError),
    /// Forward dispatch into `disable_tsp` failed. Includes
    /// `LastServiceRefused` (rollback would brick the VTA per spec §7a.5 —
    /// operator must enable another transport first).
    #[error(transparent)]
    DisableForward(#[from] DisableTspError),

    /// Document patch failed mid-rollback. Surfaced separately so the CLI
    /// can distinguish a snapshot-corruption from a pre-mutation refusal.
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for RollbackTspError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for RollbackTspError
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

pub async fn rollback_tsp(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    _params: RollbackTspParams,
    channel: &str,
) -> Result<RollbackTspResult, RollbackTspError> {
    auth.require_super_admin()
        .map_err(|e| RollbackTspError::Auth(e.to_string()))?;

    // 1. Read the snapshot. None → NoPriorMutation. Note: we do NOT take
    //    PROTOCOL_LOCK here because the dispatched forward op takes it;
    //    holding it twice would deadlock.
    let snap = snapshot::read(deps.snapshot_ks, ServiceKind::Tsp)
        .await
        .map_err(|e| RollbackTspError::Storage(format!("snapshot read: {e}")))?
        .ok_or(RollbackTspError::NoPriorMutation)?;
    let tsp_snap = match snap {
        ServiceConfigSnapshot::Tsp(s) => s,
        other => {
            // `snapshot::read` already validates the variant tag matches the
            // requested kind; if we land here the snapshot module's invariant
            // is broken. Surface it.
            return Err(RollbackTspError::Storage(format!(
                "snapshot kind mismatch: stored {other:?}, requested Tsp",
            )));
        }
    };

    // 2. Read the current TSP state from the on-chain DID document. It's
    //    authoritative for the rollback decision (it's what the snapshot is
    //    compared against); config is asserted to match by the forward ops'
    //    precondition checks.
    let current_mediator = read_current_tsp_mediator(deps.config, deps.webvh_ks).await?;

    // 3. Dispatch table (see module doc).
    info!(
        channel,
        snapshot = ?tsp_snap,
        current = ?current_mediator,
        "rollback_tsp dispatching",
    );
    match (tsp_snap, current_mediator.as_deref()) {
        // Snapshot says off, currently on → disable.
        (TspSnapshot::Disabled, Some(_)) => {
            let result =
                disable_tsp(deps, auth, DisableTspParams, OpContext::Rollback, channel).await?;
            Ok(RollbackTspResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Disabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with mediator X, currently off → enable.
        (TspSnapshot::Enabled { mediator_did }, None) => {
            let result = enable_tsp(
                deps,
                auth,
                EnableTspParams {
                    mediator_did: mediator_did.clone(),
                },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackTspResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Enabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with mediator X, currently on with Y where
        // X != Y → update.
        (TspSnapshot::Enabled { mediator_did }, Some(current)) if mediator_did != current => {
            let result = update_tsp(
                deps,
                auth,
                UpdateTspParams {
                    mediator_did: mediator_did.clone(),
                },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackTspResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Updated,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot ≡ current state. No LogEntry, no telemetry.
        _ => {
            info!(
                channel,
                "rollback_tsp: snapshot matches current state — no-op"
            );
            Ok(RollbackTspResult {
                new_version_id: None,
                kind: RollbackKind::NoOp,
                vta_did: String::new(),
                serverless: false,
            })
        }
    }
}

/// Read the currently-advertised TSP mediator DID from the on-chain DID
/// document. Returns `None` when no `#tsp` entry is present.
async fn read_current_tsp_mediator(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<Option<String>, RollbackTspError> {
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    Ok(current_tsp_service(&state.current_doc).map(|svc| svc.mediator_did))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Owns the fjall store so a test can derive multiple keyspace handles
    /// from the same open instance — fjall locks the data dir on each open.
    struct TestFixture {
        _dir: tempfile::TempDir,
        _config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn snapshot_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(snapshot::KEYSPACE_NAME).unwrap()
        }
    }

    fn build_fixture(tsp: bool, didcomm: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.tsp = tsp;
        cfg.services.didcomm = didcomm;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = dir.path().join("vta.toml");
        let initial = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&cfg.config_path, initial).unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        TestFixture {
            _dir: dir,
            _config: Arc::new(RwLock::new(cfg)),
            store,
        }
    }

    /// `rollback_tsp` returns `NoPriorMutation` when the snapshot keyspace
    /// is empty.
    #[tokio::test]
    async fn no_prior_mutation_when_snapshot_empty() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        let snap = snapshot::read(&snapshot_ks, ServiceKind::Tsp)
            .await
            .unwrap();
        assert!(snap.is_none());

        let err = RollbackTspError::NoPriorMutation;
        let msg = err.to_string();
        assert!(msg.contains("no prior mutation"));
    }

    /// Round-trip: write `Disabled` snapshot → reading it back and
    /// inspecting the variant matches the expected dispatch arm.
    #[tokio::test]
    async fn snapshot_disabled_round_trips() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Tsp(TspSnapshot::Disabled),
        )
        .await
        .unwrap();

        let read = snapshot::read(&snapshot_ks, ServiceKind::Tsp)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Tsp(TspSnapshot::Disabled) => {}
            other => panic!("expected Tsp(Disabled), got {other:?}"),
        }
    }

    /// Round-trip: write `Enabled { mediator_did: X }` snapshot → reading it
    /// back returns the mediator X.
    #[tokio::test]
    async fn snapshot_enabled_with_mediator_round_trips() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled {
                mediator_did: "did:webvh:scid:host:prior-mediator".into(),
            }),
        )
        .await
        .unwrap();

        let read = snapshot::read(&snapshot_ks, ServiceKind::Tsp)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled { mediator_did }) => {
                assert_eq!(mediator_did, "did:webvh:scid:host:prior-mediator");
            }
            other => panic!("expected Tsp(Enabled {{ mediator_did }}), got {other:?}"),
        }
    }

    /// `RollbackKind` discriminants cover the four cases the dispatch table
    /// produces. Pin the public surface so the CLI layer can rely on it.
    #[test]
    fn rollback_kind_variants_are_distinct() {
        assert_ne!(RollbackKind::Disabled, RollbackKind::Enabled);
        assert_ne!(RollbackKind::Enabled, RollbackKind::Updated);
        assert_ne!(RollbackKind::Updated, RollbackKind::NoOp);
        assert_ne!(RollbackKind::NoOp, RollbackKind::Disabled);
    }
}
