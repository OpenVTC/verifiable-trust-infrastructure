//! State fixtures for the spec §7a end-to-end matrix.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §7a.1.
//!
//! Three valid states under the §3.2 brick-prevention invariant:
//!
//! | State | REST | DIDComm |
//! |:-----:|:----:|:-------:|
//! | S1    | on   | off     |
//! | S2    | off  | on      |
//! | S3    | on   | on      |
//!
//! Plus the invariant-violating S0 (off, off) which the runtime
//! commands cannot reach (and is tested as a brick-attempt
//! rejection rather than a starting state).
//!
//! ## What each fixture sets up
//!
//! * Fresh fjall store with every keyspace populated (via the
//!   workspace's `vta_service::test_support::open_test_store`).
//! * `AppConfig` with `services.rest` / `services.didcomm` flags
//!   matching the target state.
//! * For DIDComm-on states (S2, S3): the snapshot store is
//!   pre-populated with a `DidcommSnapshot::Enabled` entry so
//!   rollback-from-this-state tests have something to fail-forward
//!   into. (The snapshot is the most-recent-mutation's pre-state;
//!   in test fixtures it's pre-populated to mirror what a sequence
//!   of forward operations would have produced.)
//! * For REST-on states (S1, S3): the snapshot store is
//!   pre-populated with a `RestSnapshot::Enabled` entry on the
//!   same principle.
//!
//! ## What each fixture deliberately does NOT set up
//!
//! * No published WebVH DID document. The §7a happy-path cells
//!   that publish a new LogEntry need a test WebVH host fixture
//!   which is out of scope for this PR. Tests that exercise the
//!   precondition-error cells (the bulk of §7a.2) work against
//!   these fixtures directly; tests that need real publication
//!   are marked `#[ignore = "needs-webvh-host-fixture"]`.
//! * No live mediator. Tests that need one wire up `TestMediator`
//!   from `tests/common/mod.rs` separately and pass its DID into
//!   the operations under test.

#![allow(dead_code)]

use std::sync::Arc;

use tokio::sync::RwLock;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use vta_service::config::{AppConfig, ServicesConfig};
use vta_service::didcomm_bridge::DIDCommBridge;
use vta_service::keys::seed_store::PlaintextSeedStore;
use vta_service::messaging::drain_sweeper::{DrainSweeper, teardown_channel};
use vta_service::messaging::registry::MediatorListenerRegistry;
use vta_service::operations::did_webvh::WebvhAuthLocks;
use vta_service::operations::protocol::ServiceOpDeps;
use vta_service::operations::protocol::snapshot::{
    self, DidcommSnapshot, RestSnapshot, ServiceConfigSnapshot,
};
use vta_service::test_support::{TestStore, open_test_store, test_app_config};
use vti_common::telemetry::{RingBufferTelemetry, SharedTelemetrySink};

/// Spec §7a.1 valid states. `S0` (off, off) is invariant-violating
/// and intentionally absent — runtime commands can never reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// REST-only.
    S1,
    /// DIDComm-only.
    S2,
    /// Both transports advertised.
    S3,
}

/// Test fixture for a VTA in a specific service state. Owns the
/// fjall store + AppConfig so the caller only has to keep
/// `StateFixture` alive across the test body.
pub struct StateFixture {
    pub state: ServiceState,
    pub store: TestStore,
    pub config: Arc<RwLock<AppConfig>>,
    /// Mediator DID assumed for DIDComm-on states. Tests that
    /// need a *live* mediator should override this by spawning a
    /// `TestMediator` and feeding its DID into the operation
    /// under test directly.
    pub assumed_mediator_did: String,
    /// REST URL assumed for REST-on states. Mirrors what
    /// `setup::build_vta_additional_services` would render.
    pub assumed_rest_url: String,
}

impl StateFixture {
    /// Convenience: returns `(rest_enabled, didcomm_enabled)`
    /// matching the configured state.
    pub fn flags(&self) -> (bool, bool) {
        match self.state {
            ServiceState::S1 => (true, false),
            ServiceState::S2 => (false, true),
            ServiceState::S3 => (true, true),
        }
    }
}

/// Build a fresh VTA fixture in the supplied state.
///
/// The fixture is suitable for tests that exercise the
/// *precondition-rejection* cells of the §7a.2 matrix — tests
/// that drive the operation layer to its check phase and assert
/// the typed `VtaError` (or per-op typed error) returned. Cells
/// that publish a new LogEntry need a separate WebVH-host fixture
/// (deferred — see module doc).
///
/// **Snapshot store starts empty** by default. Tests that need a
/// rollback target call [`StateFixture::with_snapshot`] after
/// fixture creation. Empty snapshot means rollback ops surface
/// `NoPriorMutation` — the §7a.5 starting state for history-
/// dependent dispatch tests.
pub async fn setup_vta_in_state(state: ServiceState) -> StateFixture {
    let store = open_test_store().await;
    let mut config = test_app_config(store.data_dir.clone());

    let (rest, didcomm) = match state {
        ServiceState::S1 => (true, false),
        ServiceState::S2 => (false, true),
        ServiceState::S3 => (true, true),
    };
    config.services = ServicesConfig {
        rest,
        didcomm,
        webauthn: false,
        tsp: false,
    };
    config.vta_did = Some("did:webvh:scid123:host:vta".into());

    let assumed_mediator_did = "did:peer:2.testmediator".to_string();
    let assumed_rest_url = "https://vta.test".to_string();

    StateFixture {
        state,
        store,
        config: Arc::new(RwLock::new(config)),
        assumed_mediator_did,
        assumed_rest_url,
    }
}

impl StateFixture {
    /// Pre-populate the per-kind snapshot store with the supplied
    /// pre-mutation state. Tests that exercise rollback dispatch
    /// (§7a.5) call this before invoking the rollback op so the
    /// dispatcher reads a meaningful snapshot.
    pub async fn with_snapshot(self, snapshot: ServiceConfigSnapshot) -> Self {
        snapshot::write(&self.store.snapshot_ks, snapshot)
            .await
            .expect("write snapshot");
        self
    }

    /// Convenience: pre-populate a `RestSnapshot::Enabled` snapshot
    /// with the assumed REST URL.
    pub async fn with_rest_snapshot_enabled(self) -> Self {
        let url = self.assumed_rest_url.clone();
        self.with_snapshot(ServiceConfigSnapshot::Rest(RestSnapshot::Enabled { url }))
            .await
    }

    /// Convenience: pre-populate a `RestSnapshot::Disabled`
    /// snapshot — the rollback target after a `services rest enable`.
    pub async fn with_rest_snapshot_disabled(self) -> Self {
        self.with_snapshot(ServiceConfigSnapshot::Rest(RestSnapshot::Disabled))
            .await
    }

    /// Convenience: pre-populate a `DidcommSnapshot::Enabled`
    /// snapshot with the assumed mediator DID.
    pub async fn with_didcomm_snapshot_enabled(self) -> Self {
        let mediator_did = self.assumed_mediator_did.clone();
        self.with_snapshot(ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did,
            routing_keys: vec![],
        }))
        .await
    }

    /// Convenience: pre-populate a `DidcommSnapshot::Disabled`
    /// snapshot — the rollback target after a `services didcomm
    /// enable`.
    pub async fn with_didcomm_snapshot_disabled(self) -> Self {
        self.with_snapshot(ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled))
            .await
    }
}

/// Owns the per-test infrastructure a runtime-service operation needs that
/// isn't part of the persisted [`StateFixture`] — seed store, DID resolver,
/// DIDComm bridge, telemetry sink, mediator registry, drain sweeper, and the
/// webvh auth locks. The protocol ops were consolidated onto a single borrowed
/// [`ServiceOpDeps`] bundle ([`mod@vta_service::operations::protocol`]), so a
/// caller builds this once and hands out [`OpInfra::deps`] per invocation.
///
/// Split from `StateFixture` because these are owned values the borrowed
/// `ServiceOpDeps` points at: keep both alive for the test body, then build
/// the bundle on demand. The registry/sweeper are only read by the DIDComm
/// family; REST ops ignore them but the shared bundle still carries them.
pub struct OpInfra {
    seed: PlaintextSeedStore,
    resolver: DIDCacheClient,
    bridge: Arc<DIDCommBridge>,
    telemetry: SharedTelemetrySink,
    registry: Arc<MediatorListenerRegistry>,
    sweeper: Arc<DrainSweeper>,
    locks: WebvhAuthLocks,
}

impl OpInfra {
    /// Build the infra against a fixture's drain keyspace (the sweeper needs
    /// it). The teardown receiver is dropped immediately — refusal-path tests
    /// bail before any drain is swept, so nothing is ever sent on it.
    pub async fn new(fx: &StateFixture) -> Self {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("DID resolver");
        let telemetry: SharedTelemetrySink = Arc::new(RingBufferTelemetry::new());
        let registry = Arc::new(MediatorListenerRegistry::new(Arc::clone(&telemetry)));
        let (tx, _rx) = teardown_channel(8);
        let sweeper = Arc::new(DrainSweeper::new(
            Arc::clone(&registry),
            fx.store.drains_ks.clone(),
            tx,
        ));
        Self {
            seed: PlaintextSeedStore::new(&fx.store.data_dir),
            resolver,
            bridge: Arc::new(DIDCommBridge::placeholder()),
            telemetry,
            registry,
            sweeper,
            locks: WebvhAuthLocks::new(),
        }
    }

    /// Borrow a [`ServiceOpDeps`] bundle pointing at the fixture's keyspaces +
    /// config and this infra's owned values. Both `self` and `fx` must outlive
    /// the returned bundle.
    pub fn deps<'a>(&'a self, fx: &'a StateFixture) -> ServiceOpDeps<'a> {
        ServiceOpDeps {
            config: &fx.config,
            keys_ks: &fx.store.keys_ks,
            imported_ks: &fx.store.imported_ks,
            contexts_ks: &fx.store.contexts_ks,
            webvh_ks: &fx.store.webvh_ks,
            audit_ks: &fx.store.audit_ks,
            snapshot_ks: &fx.store.snapshot_ks,
            service_state_ks: &fx.store.service_state_ks,
            drains_ks: &fx.store.drains_ks,
            seed_store: &self.seed,
            did_resolver: &self.resolver,
            didcomm_bridge: &self.bridge,
            telemetry: &self.telemetry,
            webvh_auth_locks: &self.locks,
            registry: &self.registry,
            sweeper: &self.sweeper,
        }
    }
}

/// Spec §7a.1 invariant — only S1, S2, S3 are valid. The matrix
/// must produce exactly these three.
#[cfg(test)]
mod tests {
    use super::*;
    use vta_service::operations::protocol::snapshot::ServiceKind;

    #[tokio::test]
    async fn s1_has_rest_only_flags() {
        let fx = setup_vta_in_state(ServiceState::S1).await;
        assert_eq!(fx.flags(), (true, false));
        let cfg = fx.config.read().await;
        assert!(cfg.services.rest);
        assert!(!cfg.services.didcomm);
    }

    #[tokio::test]
    async fn s2_has_didcomm_only_flags() {
        let fx = setup_vta_in_state(ServiceState::S2).await;
        assert_eq!(fx.flags(), (false, true));
        let cfg = fx.config.read().await;
        assert!(!cfg.services.rest);
        assert!(cfg.services.didcomm);
    }

    #[tokio::test]
    async fn s3_has_both_flags() {
        let fx = setup_vta_in_state(ServiceState::S3).await;
        assert_eq!(fx.flags(), (true, true));
        let cfg = fx.config.read().await;
        assert!(cfg.services.rest);
        assert!(cfg.services.didcomm);
    }

    /// Default fixture has empty snapshot store — rollback ops
    /// from any state surface NoPriorMutation. §7a.5 history
    /// tests opt in to a populated snapshot via
    /// `with_*_snapshot_*` builders.
    #[tokio::test]
    async fn default_fixture_has_empty_snapshot_store() {
        for state in [ServiceState::S1, ServiceState::S2, ServiceState::S3] {
            let fx = setup_vta_in_state(state).await;
            let rest = snapshot::read(&fx.store.snapshot_ks, ServiceKind::Rest)
                .await
                .unwrap();
            let didcomm = snapshot::read(&fx.store.snapshot_ks, ServiceKind::Didcomm)
                .await
                .unwrap();
            assert!(
                rest.is_none() && didcomm.is_none(),
                "fixture {state:?} must start with empty snapshot store",
            );
        }
    }

    #[tokio::test]
    async fn with_rest_snapshot_enabled_populates_correctly() {
        let fx = setup_vta_in_state(ServiceState::S1)
            .await
            .with_rest_snapshot_enabled()
            .await;
        let snap = snapshot::read(&fx.store.snapshot_ks, ServiceKind::Rest)
            .await
            .unwrap();
        match snap {
            Some(ServiceConfigSnapshot::Rest(RestSnapshot::Enabled { url })) => {
                assert_eq!(url, "https://vta.test");
            }
            other => panic!("expected Rest::Enabled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_didcomm_snapshot_enabled_populates_correctly() {
        let fx = setup_vta_in_state(ServiceState::S2)
            .await
            .with_didcomm_snapshot_enabled()
            .await;
        let snap = snapshot::read(&fx.store.snapshot_ks, ServiceKind::Didcomm)
            .await
            .unwrap();
        match snap {
            Some(ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
                mediator_did, ..
            })) => {
                assert_eq!(mediator_did, "did:peer:2.testmediator");
            }
            other => panic!("expected Didcomm::Enabled, got {other:?}"),
        }
    }

    /// VTA DID is configured in every fixture so precondition
    /// checks that gate on `cfg.vta_did.is_some()` pass.
    #[tokio::test]
    async fn every_fixture_has_vta_did_configured() {
        for state in [ServiceState::S1, ServiceState::S2, ServiceState::S3] {
            let fx = setup_vta_in_state(state).await;
            let cfg = fx.config.read().await;
            assert!(
                cfg.vta_did.is_some(),
                "fixture {state:?} must have vta_did set",
            );
        }
    }
}
