//! P1.1 — single `AppState` construction; `VtaState` shares the same Arcs.
//!
//! Before P1.1 the DIDComm router state (`VtaState`) was built with its *own*
//! `WebvhAuthLocks::new()` and its own `Arc<RwLock<AppConfig>>`, so the
//! per-server webvh auth-cache lock didn't serialize across transports and a
//! `PATCH /config` on the REST side left DIDComm reading stale config. These
//! tests pin the fix: `VtaState` is derived from the canonical `AppState`, so
//! both transports share one config `RwLock`, one `WebvhAuthLocks`, one
//! mediator registry, one drain sweeper, one telemetry sink, and one DIDComm
//! bridge.

use std::sync::Arc;

use vta_service::config::AppConfig;
use vta_service::messaging::router::VtaState;
use vta_service::server::{AppStateParts, build_app_state};
use vta_service::store::Store;
use vta_service::test_support::{TestSeedStore, init_jwt_provider, test_app_config};

async fn build_state() -> (AppConfig, vta_service::server::AppState, tempfile::TempDir) {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("temp dir");
    let config = test_app_config(dir.path().to_path_buf());
    let store = Store::open(&config.store).expect("open store");
    let seed_store: Arc<dyn vta_service::keys::seed_store::SeedStore> =
        Arc::new(TestSeedStore(vec![0xABu8; 32]));
    let (restart_tx, _rx) = tokio::sync::watch::channel(false);
    let app_state = build_app_state(
        config.clone(),
        &store,
        seed_store,
        None,
        None,
        restart_tx,
        AppStateParts::default(),
    )
    .await
    .expect("build app state");
    (config, app_state, dir)
}

/// The DIDComm-transport view shares the *same* config `RwLock` Arc as the
/// canonical `AppState` — so a runtime config mutation is visible to both
/// transports, not just the one that owns its own copy.
#[tokio::test]
async fn vta_state_shares_config_rwlock() {
    let (_config, app_state, _dir) = build_state().await;
    let vta_state = VtaState::from(&app_state);

    assert!(
        Arc::ptr_eq(&app_state.config, &vta_state.config),
        "VtaState must share AppState's config RwLock (P1.1), not clone a new one"
    );

    // Mutate config through the AppState handle; observe it through VtaState.
    {
        let mut guard = app_state.config.write().await;
        guard.vta_name = Some("patched-at-runtime".into());
    }
    let seen = vta_state.config.read().await;
    assert_eq!(
        seen.vta_name.as_deref(),
        Some("patched-at-runtime"),
        "config update on the AppState (REST) side must be visible via VtaState (DIDComm)"
    );
}

/// The mediator registry, drain sweeper, telemetry sink, and DIDComm bridge are
/// all the same Arc instances on both states — no divergent per-transport
/// wiring.
#[cfg(feature = "didcomm")]
#[tokio::test]
async fn vta_state_shares_shared_components() {
    let (_config, app_state, _dir) = build_state().await;
    let vta_state = VtaState::from(&app_state);

    assert!(
        Arc::ptr_eq(&app_state.telemetry, &vta_state.telemetry),
        "telemetry sink must be shared"
    );
    assert!(
        Arc::ptr_eq(&app_state.didcomm_bridge, &vta_state.didcomm_bridge),
        "DIDComm bridge must be shared"
    );

    #[cfg(feature = "webvh")]
    {
        assert!(
            Arc::ptr_eq(&app_state.mediator_registry, &vta_state.mediator_registry),
            "mediator registry must be shared"
        );
        assert!(
            Arc::ptr_eq(&app_state.drain_sweeper, &vta_state.drain_sweeper),
            "drain sweeper must be shared"
        );
    }
}

/// Drift guard for the `VtaState` constructor: the only place `VtaState` is
/// built in the running server is `From<&AppState>`. If someone reintroduces a
/// hand-rolled `VtaState { .. }` literal with its own `WebvhAuthLocks::new()` /
/// `RwLock::new(config)` (the original P1.1 divergence bug), this fails.
#[test]
fn router_does_not_reconstruct_divergent_state() {
    let src = include_str!("../src/messaging/router.rs");
    assert!(
        !src.contains("WebvhAuthLocks::new()"),
        "router.rs must not mint its own WebvhAuthLocks — share AppState's (P1.1)"
    );
    assert!(
        !src.contains("RwLock::new("),
        "router.rs must not mint its own config RwLock — share AppState's (P1.1)"
    );
}
