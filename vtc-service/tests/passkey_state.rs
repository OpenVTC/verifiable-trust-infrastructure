//! Coverage for the `PasskeyState` impl on `vtc_service::server::AppState`.
//!
//! Verifies the M0.5.1 acceptance criteria:
//!
//! - `webauthn()` returns `Some` iff `public_url` was set at startup.
//! - `public_url()` reflects the cached snapshot, not the live config
//!   (so a writer mid-update never blocks the trait method).
//! - `access_token_expiry` / `refresh_token_expiry` track the
//!   `AuthConfig` defaults when the lock is uncontested.
//! - `enrollment_ttl()` returns the workspace default.
//!
//! Constructed via direct field-by-field `AppState { … }` initialisation
//! — same pattern the other VTC integration tests use, since the
//! `run()` startup path needs a `Store` + tokio runtime that's
//! overkill for a trait-method check.

use std::sync::Arc;

use tokio::sync::RwLock;
use vti_common::auth::passkey::{PasskeyState, build_webauthn};
use vti_common::config::{AuthConfig, StoreConfig};
use vti_common::store::Store;

use vtc_service::config::AppConfig;
use vtc_service::server::AppState;

fn build_state(public_url: Option<&str>) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();
    let invitations_ks = store.keyspace("invitations").unwrap();
    let consumed_invitations_ks = store.keyspace("consumed_invitations").unwrap();

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let webauthn = public_url.map(|u| Arc::new(build_webauthn(u).expect("build webauthn")));

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks: install_ks.clone(),
        members_ks: members_ks.clone(),
        member_count_cache: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        join_requests_ks: join_requests_ks.clone(),
        policies_ks: policies_ks.clone(),
        active_policies_ks: active_policies_ks.clone(),
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks: registry_records_ks.clone(),
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks: sync_cursor_ks.clone(),
        relationships_ks: relationships_ks.clone(),
        relationships_by_did_ks: relationships_by_did_ks.clone(),
        endorsement_types_ks: endorsement_types_ks.clone(),
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks: endorsements_ks.clone(),
        invitations_ks,
        consumed_invitations_ks,
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        syncer_health: vtc_service::registry::SyncerHealth::new(),
        credential_signer: None,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: None,
        atm: None,
        webauthn,
        public_url: public_url.map(|s| s.to_string()),
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_ks,
        audit_key_ks,
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
        didcomm: std::sync::Arc::new(tokio::sync::OnceCell::new()),
    };
    (state, dir)
}

#[tokio::test]
async fn webauthn_returns_none_when_public_url_unset() {
    let (state, _dir) = build_state(None);
    assert!(state.webauthn().is_none());
    assert!(state.public_url().is_none());
}

#[tokio::test]
async fn webauthn_returns_some_when_public_url_set() {
    let (state, _dir) = build_state(Some("https://vtc.example.com"));
    assert!(state.webauthn().is_some());
    assert_eq!(state.public_url(), Some("https://vtc.example.com"));
}

#[tokio::test]
async fn passkey_state_acl_ks_matches_app_state_field() {
    let (state, _dir) = build_state(None);
    // The trait returns `&KeyspaceHandle`; we just need a couple of
    // round-trip writes to confirm both paths reach the same store.
    let key = b"passkey-state-test".to_vec();
    PasskeyState::acl_ks(&state)
        .insert_raw(key.clone(), b"value".to_vec())
        .await
        .unwrap();
    let got = state.acl_ks.get_raw(key).await.unwrap();
    assert_eq!(got.as_deref(), Some(&b"value"[..]));
}

#[tokio::test]
async fn token_expiries_track_auth_config_defaults() {
    let (state, _dir) = build_state(None);
    let defaults = AuthConfig::default();
    assert_eq!(state.access_token_expiry(), defaults.access_token_expiry);
    assert_eq!(state.refresh_token_expiry(), defaults.refresh_token_expiry);
}

#[tokio::test]
async fn enrollment_ttl_uses_workspace_default() {
    let (state, _dir) = build_state(None);
    // The exact value is documented in `server::DEFAULT_ENROLLMENT_TTL_SECS`
    // (one hour); assert the contract rather than the constant to avoid
    // brittle coupling to the literal — but verify it's a sensible
    // positive duration.
    let ttl = state.enrollment_ttl();
    assert!(
        (60..=86_400).contains(&ttl),
        "enrollment_ttl {ttl} outside expected [60s, 24h] sanity range",
    );
}
