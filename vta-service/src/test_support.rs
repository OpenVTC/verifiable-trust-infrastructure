//! Shared test-harness helpers — in-memory keyspaces, default
//! `AppConfig`, and a `bootstrap_test_vta` routine that provisions the
//! minimum VTA state `operations::provision_integration::provision_integration`
//! needs (active seed, `#key-0`, `#sealed-transfer-0`, DID resolver,
//! populated `vta_did`).
//!
//! Gated behind the `test-support` feature *and* `cfg(test)` for the
//! lib's own unit tests. Downstream integration tests (under
//! `tests/`) enable the feature via a `[dev-dependencies]` entry.
//!
//! Kept in the production crate rather than a separate
//! `vta-test-support` sibling because every helper here either returns
//! or closes over crate-private types (`KeyspaceHandle`, the seed-store
//! trait, `ProvisionIntegrationDeps`). A sibling crate would force
//! every one of them to be `pub` in the main API surface, which is the
//! opposite of what we want. Feature-flagging contains the test glue to
//! the build modes that actually need it.

#![cfg(any(test, feature = "test-support"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Duration;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use serde_json::Value;
use tokio::sync::RwLock;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::config::{AppConfig, StoreConfig};
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::PlaintextSeedStore;
use crate::keys::{KeyType as SdkKeyType, save_key_record};
use crate::operations::provision_integration::ProvisionIntegrationDeps;
use crate::store::{KeyspaceHandle, Store};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::provision_integration::{
    BootstrapAsk, BootstrapRequest, DidTemplateRef, TemplateBootstrapAsk, VerifiedBootstrapRequest,
};

/// A freshly-opened tempdir-backed store plus every keyspace the
/// `ProvisionIntegrationDeps` shape needs. Drops the tempdir on `Drop`
/// so tests never leak.
pub struct TestStore {
    // `_dir` has to outlive the store (it owns the on-disk backing), and
    // `_store` must outlive all keyspace handles (fjall's keyspace
    // handles are weak wrt the store's lifetime). Held here as fields
    // so the caller only has to keep `TestStore` alive.
    _dir: tempfile::TempDir,
    _store: Store,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    pub webvh_ks: KeyspaceHandle,
    pub sealed_nonces_ks: KeyspaceHandle,
    /// Persisted drain set for the runtime service-management
    /// surface. Required by `disable_didcomm` / `update_didcomm` /
    /// rollback ops.
    pub drains_ks: KeyspaceHandle,
    /// Per-kind previous-config snapshot store for fail-forward
    /// rollback (spec §3.5a). Required by every forward op + the
    /// rollback dispatchers.
    pub snapshot_ks: KeyspaceHandle,
    /// Persistent runtime state for service enable/disable
    /// (`operations::protocol::runtime_state`). Required by every
    /// forward + rollback op.
    pub service_state_ks: KeyspaceHandle,
    pub data_dir: PathBuf,
}

/// Open a fresh tempdir-backed `TestStore` with every keyspace wired.
pub async fn open_test_store() -> TestStore {
    let dir = tempfile::tempdir().expect("temp dir");
    let data_dir = dir.path().to_path_buf();
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.clone(),
    })
    .expect("open store");
    TestStore {
        contexts_ks: store.keyspace("contexts").expect("contexts ks"),
        did_templates_ks: store.keyspace("did_templates").expect("did_templates ks"),
        keys_ks: store.keyspace("keys").expect("keys ks"),
        acl_ks: store.keyspace("acl").expect("acl ks"),
        audit_ks: store.keyspace("audit").expect("audit ks"),
        imported_ks: store.keyspace("imported").expect("imported ks"),
        webvh_ks: store.keyspace("webvh").expect("webvh ks"),
        sealed_nonces_ks: store.keyspace("sealed_nonces").expect("nonces ks"),
        drains_ks: store.keyspace("drains").expect("drains ks"),
        snapshot_ks: store
            .keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)
            .expect("snapshot ks"),
        service_state_ks: store.keyspace("service_state").expect("service_state ks"),
        _dir: dir,
        _store: store,
        data_dir,
    }
}

/// A minimal `AppConfig` suitable for in-memory tests. All external
/// services (keyring, TEE, cloud secret managers, ...) are left at
/// their defaults.
pub fn test_app_config(data_dir: PathBuf) -> AppConfig {
    AppConfig {
        vta_did: None,
        vta_name: None,
        public_url: None,
        resolver_url: None,
        server: Default::default(),
        log: Default::default(),
        store: StoreConfig { data_dir },
        messaging: None,
        services: Default::default(),
        auth: Default::default(),
        audit: Default::default(),
        secrets: Default::default(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        config_path: PathBuf::new(),
    }
}

/// Build a `ProvisionIntegrationDeps` from a `TestStore`. The returned
/// deps have no DID resolver — use [`bootstrap_test_vta`] when the
/// full happy path is needed.
pub fn test_deps(ts: &TestStore) -> ProvisionIntegrationDeps {
    ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit_ks: ts.audit_ks.clone(),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(test_app_config(ts.data_dir.clone()))),
        did_resolver: None,
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
    }
}

/// Synthesise a super-admin `AuthClaims` for tests that bypass the
/// normal session/JWT gate.
pub fn super_admin_claims() -> AuthClaims {
    AuthClaims {
        did: "did:key:zTestAdmin".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        session_id: "test-session".into(),
        access_expires_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

/// Build + sign + verify a template-driven `BootstrapRequest` with no
/// admin rollover and no extra template vars.
pub async fn signed_request(template_name: &str, context_hint: &str) -> VerifiedBootstrapRequest {
    signed_request_with_vars(template_name, context_hint, BTreeMap::new()).await
}

/// Build + sign + verify a template-driven `BootstrapRequest` with the
/// given template vars (e.g. `URL`, `WEBVH_SERVER`).
pub async fn signed_request_with_vars(
    template_name: &str,
    context_hint: &str,
    vars: BTreeMap<String, Value>,
) -> VerifiedBootstrapRequest {
    let seed = [7u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pub_bytes: [u8; 32] = signing.verifying_key().to_bytes();
    let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

    let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
        context_hint: Some(context_hint.into()),
        template: DidTemplateRef {
            name: template_name.into(),
            vars,
        },
        admin_template: None,
        note: None,
    });

    let req = BootstrapRequest::sign(
        &seed,
        &client_did,
        [0u8; 16],
        Duration::minutes(10),
        None,
        ask,
    )
    .await
    .expect("sign bootstrap request");
    req.verify().expect("verify bootstrap request")
}

/// Build + sign + verify a `BootstrapAsk::AdminRotation` request — the
/// admin-only-rotation wire shape. Uses the same `[7u8; 32]` setup
/// seed as the TemplateBootstrap helpers so `bootstrap_test_vta`'s
/// pre-installed ACL row authenticates this request too.
pub async fn signed_admin_rotation_request(
    admin_template_name: &str,
    context_hint: &str,
) -> VerifiedBootstrapRequest {
    use vta_sdk::provision_integration::AdminRotationAsk;

    let seed = [7u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pub_bytes: [u8; 32] = signing.verifying_key().to_bytes();
    let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

    let ask = BootstrapAsk::AdminRotation(AdminRotationAsk {
        context_hint: Some(context_hint.into()),
        admin_template: DidTemplateRef {
            name: admin_template_name.into(),
            vars: BTreeMap::new(),
        },
        note: None,
    });

    let req = BootstrapRequest::sign(
        &seed,
        &client_did,
        [0u8; 16],
        Duration::minutes(10),
        None,
        ask,
    )
    .await
    .expect("sign bootstrap request");
    req.verify().expect("verify bootstrap request")
}

/// Provision the minimum VTA state a full `provision_integration()`
/// call needs: an active seed, the VTA's `{vta_did}#key-0` signing key
/// and `#sealed-transfer-0` producer-assertion key saved in the keystore,
/// a DID resolver that can resolve the VTA's own `did:key`, and an
/// `AppConfig` with `vta_did` populated.
///
/// Returns `(vta_did, deps_with_resolver)` — the caller plugs the
/// returned deps into `provision_integration()` instead of [`test_deps`].
pub async fn bootstrap_test_vta(ts: &TestStore) -> (String, ProvisionIntegrationDeps) {
    use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};

    // Deterministic 64-byte seed (BIP-32 wants ≥16 bytes; 64 mirrors
    // the mnemonic-derived seed shape used in production setup).
    let raw_seed = [0xC5u8; 64];
    let seed_store = PlaintextSeedStore::new(&ts.data_dir);
    crate::keys::seed_store::SeedStore::set(&seed_store, &raw_seed)
        .await
        .expect("write test seed to plaintext store");

    let now = chrono::Utc::now();
    save_seed_record(
        &ts.keys_ks,
        &SeedRecord {
            id: 0,
            seed_hex: None,
            created_at: now,
            retired_at: None,
        },
    )
    .await
    .expect("save seed record");
    set_active_seed_id(&ts.keys_ks, 0)
        .await
        .expect("set active seed id");

    // Derive a fresh Ed25519 key at a canonical VTA path, convert to
    // did:key, save a keystore record whose id matches the
    // `{vta_did}#key-0` convention `load_vta_vc_issuance_secret` looks up.
    let vta_base_path = "m/26'/1'/0'";
    let root = ExtendedSigningKey::from_seed(&raw_seed).expect("bip-32 root");
    let dp: DerivationPath = vta_base_path.parse().expect("derivation path");
    let derived = root.derive(&dp).expect("derive VTA key");
    let signing = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
    let pub_bytes = signing.verifying_key().to_bytes();
    let multibase = ed25519_multibase_pubkey(&pub_bytes);
    let vta_did = format!("did:key:{multibase}");
    let key_id = format!("{vta_did}#key-0");

    save_key_record(
        &ts.keys_ks,
        &key_id,
        vta_base_path,
        SdkKeyType::Ed25519,
        &multibase,
        "VTA signing key",
        None,
        Some(0),
    )
    .await
    .expect("save VTA key record");

    // Mirror the real VTA bootstrap: provision `#sealed-transfer-0`
    // (separate from `#key-0`, see review item 12) so
    // `provision_integration` can sign the producer assertion without
    // hitting the "re-bootstrap required" guard in
    // `load_vta_sealed_transfer_secret`.
    let st_base_path = "m/26'/1'/1'";
    let st_dp: DerivationPath = st_base_path.parse().expect("st derivation path");
    let st_derived = root.derive(&st_dp).expect("derive VTA sealed-transfer key");
    let st_signing = ed25519_dalek::SigningKey::from_bytes(st_derived.signing_key.as_bytes());
    let st_pub_bytes = st_signing.verifying_key().to_bytes();
    let st_multibase = ed25519_multibase_pubkey(&st_pub_bytes);
    save_key_record(
        &ts.keys_ks,
        &format!("{vta_did}#sealed-transfer-0"),
        st_base_path,
        SdkKeyType::Ed25519,
        &st_multibase,
        "VTA sealed-transfer producer-assertion key",
        None,
        Some(0),
    )
    .await
    .expect("save VTA sealed-transfer key record");

    let mut config = test_app_config(ts.data_dir.clone());
    config.vta_did = Some(vta_did.clone());
    config.public_url = Some("https://vta.test".into());

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("DID resolver");

    let deps = ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit_ks: ts.audit_ks.clone(),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(config)),
        did_resolver: Some(resolver),
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
    };
    (vta_did, deps)
}

// ---------------------------------------------------------------------------
// HTTP test scaffolding — shared by `tests/api_integration.rs` and any future
// route-level test crate. The `TestApp` type returned here owns the axum
// `Router` so the caller can `.oneshot(req)` against it directly.
//
// Pre-consolidation, every integration-test file built its own ~140 LoC
// `TestApp::new()` from scratch. That duplication scaled poorly and made
// the rate-limit / body-cap regression tests impractical to write. The
// helpers below collapse the common substrate to ~10 LoC at the call
// site.
// ---------------------------------------------------------------------------

/// Pin jsonwebtoken's default `CryptoProvider` to `aws_lc` once per
/// process. The workspace compiles `jsonwebtoken` with only the
/// `aws_lc_rs` backend (the `rust_crypto` bundle pulls in `rsa`,
/// exposed to RUSTSEC-2023-0071). When `cargo test --workspace`
/// unifies features and a sibling crate brings in a second provider,
/// `jsonwebtoken`'s auto-select panics; installing one explicitly
/// here avoids that. Idempotent — safe to call from every test file.
pub fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

/// In-memory seed store for tests that need a stable seed without touching
/// the filesystem-backed `PlaintextSeedStore`. The bytes are the seed; the
/// caller chooses the value.
pub struct TestSeedStore(pub Vec<u8>);

impl crate::keys::seed_store::SeedStore for TestSeedStore {
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, crate::error::AppError>>
                + Send
                + '_,
        >,
    > {
        let v = self.0.clone();
        Box::pin(async move { Ok(Some(v)) })
    }
    fn set(
        &self,
        _seed: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::error::AppError>> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

/// Bag of cloned references the integration test needs to mutate state
/// that the router otherwise owns (insert sessions / ACL rows / etc.).
/// Returned alongside [`build_test_app`] so tests don't have to re-open
/// the store to find these.
pub struct TestAppContext {
    pub jwt_keys: Arc<vti_common::auth::jwt::JwtKeys>,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub keys_ks: KeyspaceHandle,
    pub backup_bundles_ks: KeyspaceHandle,
    pub backup_blob_dir: std::path::PathBuf,
    pub config: Arc<RwLock<AppConfig>>,
    /// Owns the on-disk fjall data dir. When this drops, files are
    /// removed; the caller MUST keep it alive for the duration of the
    /// test (`TestAppContext` is normally bound to a `let _ctx = …`).
    pub _dir: tempfile::TempDir,
}

/// Spin up an in-memory router suitable for `tower::ServiceExt::oneshot`
/// HTTP testing. Uses [`TestSeedStore`] so no filesystem seed I/O,
/// `aws_lc` JWT provider via [`init_jwt_provider`], and the full
/// `routes::router()` + `routes::health_router()` merged together.
///
/// `vta_did` is `did:key:z6MkTestVTA` — a sentinel that resolves
/// nowhere but satisfies the routes that just compare it as a string.
/// `vta_name` and `public_url` are set so the JWT audience / DID
/// document construction don't take their None branches in tests.
pub async fn build_test_app() -> (axum::Router, TestAppContext) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
    use tokio::sync::watch;

    init_jwt_provider();

    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: dir.path().to_path_buf(),
    };
    let store = Store::open(&store_config).expect("open store");

    let keys_ks = store.keyspace("keys").unwrap();
    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let contexts_ks = store.keyspace("contexts").unwrap();
    // Seed a default `ctx1` context so route tests that reference
    // it in ACL entries or key derivations don't have to set up
    // contexts themselves. The ACL `create`/`update` operations
    // now refuse to reference unregistered contexts (see
    // `operations::acl::require_contexts_exist`).
    {
        use chrono::Utc;
        let now = Utc::now();
        crate::contexts::store_context(
            &contexts_ks,
            &crate::contexts::ContextRecord {
                id: "ctx1".into(),
                name: "ctx1".into(),
                did: None,
                description: None,
                base_path: "m/26'/2'/0'".into(),
                index: 0,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("seed ctx1");
    }
    let audit_ks = store.keyspace("audit").unwrap();
    let cache_ks = store.keyspace("cache").unwrap();
    let vault_ks = store.keyspace("vault").unwrap();
    let service_state_ks = store.keyspace("service_state").unwrap();
    let imported_ks = store.keyspace("imported_secrets").unwrap();
    let sealed_nonces_ks = store.keyspace("sealed_nonces").unwrap();
    let backup_bundles_ks = store.keyspace("backup_bundles").unwrap();
    let backup_blob_dir = dir.path().join("backups");
    let did_templates_ks = store.keyspace("did_templates").unwrap();
    #[cfg(feature = "webvh")]
    let webvh_ks = store.keyspace("webvh").unwrap();
    #[cfg(feature = "webvh")]
    let passkey_vms_ks = store.keyspace("passkey_vms").unwrap();
    #[cfg(feature = "webvh")]
    let drains_ks = store.keyspace("drains").unwrap();
    #[cfg(feature = "webvh")]
    let snapshot_ks = store
        .keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)
        .unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(
        vti_common::auth::jwt::JwtKeys::from_ed25519_bytes(&jwt_seed, "VTA").expect("jwt keys"),
    );

    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::new(TestSeedStore(vec![0xABu8; 32]));

    let mut config: AppConfig = toml::from_str(&format!(
        r#"
        vta_did = "did:key:z6MkTestVTA"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");
    config.config_path = dir.path().join("config.toml");

    let (restart_tx, _rx) = watch::channel(false);

    let telemetry: vti_common::telemetry::SharedTelemetrySink =
        Arc::new(vti_common::telemetry::RingBufferTelemetry::new());
    #[cfg(feature = "webvh")]
    let mediator_registry = Arc::new(crate::messaging::registry::MediatorListenerRegistry::new(
        Arc::clone(&telemetry),
    ));
    #[cfg(feature = "webvh")]
    let drain_sweeper = {
        let (tx, _rx) = crate::messaging::drain_sweeper::teardown_channel(8);
        Arc::new(crate::messaging::drain_sweeper::DrainSweeper::new(
            Arc::clone(&mediator_registry),
            drains_ks.clone(),
            tx,
        ))
    };

    let config = Arc::new(RwLock::new(config));

    let state = crate::server::AppState {
        keys_ks: keys_ks.clone(),
        sessions_ks: sessions_ks.clone(),
        acl_ks: acl_ks.clone(),
        contexts_ks,
        did_templates_ks,
        audit_ks,
        imported_ks,
        cache_ks,
        vault_ks,
        service_state_ks,
        sealed_nonces_ks,
        backup_bundles_ks: backup_bundles_ks.clone(),
        backup_blob_dir: backup_blob_dir.clone(),
        #[cfg(feature = "webvh")]
        webvh_ks,
        #[cfg(feature = "webvh")]
        passkey_vms_ks,
        #[cfg(feature = "webvh")]
        drains_ks,
        #[cfg(feature = "webvh")]
        snapshot_ks,
        #[cfg(feature = "webvh")]
        mediator_registry,
        #[cfg(feature = "webvh")]
        drain_sweeper,
        #[cfg(feature = "webvh")]
        webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
        telemetry,
        wrapping_cache: crate::keys::wrapping::WrappingKeyCache::new(),
        config: config.clone(),
        seed_store,
        did_resolver: DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .ok(),
        secrets_resolver: None,
        #[cfg(feature = "didcomm")]
        signing_vm_id: None,
        #[cfg(feature = "didcomm")]
        ka_vm_id: None,
        #[cfg(feature = "didcomm")]
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        tee: None,
        restart_tx,
        metrics_handle: None,
    };

    // Test harness uses `trust_xff = true` so the per-IP rate
    // limiter falls back to `X-Forwarded-For` when there's no
    // socket peer-IP (tower::oneshot doesn't carry one). The
    // existing rate-limit regression test
    // (`unauth_endpoint_rate_limit_returns_429_after_burst`)
    // sets `x-forwarded-for: 192.0.2.1` so all calls hash to the
    // same bucket and trip the burst within 20 requests.
    let router = crate::routes::router_with_cors(&[], true)
        .with_state(state.clone())
        .merge(crate::routes::health_router().with_state(state));

    let ctx = TestAppContext {
        jwt_keys,
        sessions_ks,
        acl_ks,
        keys_ks,
        backup_bundles_ks,
        backup_blob_dir,
        config,
        _dir: dir,
    };

    (router, ctx)
}

/// A **mock VTA** bound to an ephemeral local port — a real, listening HTTP
/// server a test harness can drive over the wire, with no setup ceremony.
///
/// Wraps [`build_test_app`] (ephemeral in-memory state — no TEE/KMS, no mediator,
/// no on-disk seed) and serves it on `127.0.0.1:<random-port>`. The server runs
/// in a background task and shuts down when the `MockVta` is dropped (or via
/// [`shutdown`](Self::shutdown)).
///
/// ```no_run
/// # async fn demo() {
/// use vta_service::test_support::MockVta;
/// let mock = MockVta::start().await;
/// let base = mock.base_url();              // e.g. http://127.0.0.1:54321
/// // … point a client at `base`, or seed ACL/sessions via `mock.ctx` …
/// mock.shutdown().await;
/// # }
/// ```
pub struct MockVta {
    base_url: String,
    /// The bootstrapped app context (keyspaces, JWT keys, config) so a harness
    /// can seed ACL rows / sessions before driving the API. Owns the temp data
    /// dir — kept alive for the lifetime of the `MockVta`.
    pub ctx: TestAppContext,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl MockVta {
    /// Start a mock VTA on a random loopback port and return once it is bound
    /// and serving.
    pub async fn start() -> MockVta {
        let (router, ctx) = build_test_app().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("resolve local addr");
        let base_url = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            // `ConnectInfo<SocketAddr>` is required — the unauth routes carry the
            // per-source-IP rate limiter, same as production.
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
        });

        MockVta {
            base_url,
            ctx,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// The base URL to point a client at (e.g. `http://127.0.0.1:54321`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Stop the server and wait for it to wind down gracefully.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for MockVta {
    fn drop(&mut self) {
        // Signal graceful shutdown; abort as a backstop if the task is still up.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
