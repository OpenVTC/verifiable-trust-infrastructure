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
        contexts_ks: store
            .keyspace(crate::keyspaces::CONTEXTS)
            .expect("contexts ks"),
        did_templates_ks: store
            .keyspace(crate::keyspaces::DID_TEMPLATES)
            .expect("did_templates ks"),
        keys_ks: store.keyspace(crate::keyspaces::KEYS).expect("keys ks"),
        acl_ks: store.keyspace(crate::keyspaces::ACL).expect("acl ks"),
        audit_ks: store.keyspace(crate::keyspaces::AUDIT).expect("audit ks"),
        imported_ks: store
            .keyspace(crate::keyspaces::IMPORTED_SECRETS)
            .expect("imported ks"),
        webvh_ks: store.keyspace(crate::keyspaces::WEBVH).expect("webvh ks"),
        sealed_nonces_ks: store
            .keyspace(crate::keyspaces::SEALED_NONCES)
            .expect("nonces ks"),
        drains_ks: store.keyspace(crate::keyspaces::DRAINS).expect("drains ks"),
        snapshot_ks: store
            .keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)
            .expect("snapshot ks"),
        service_state_ks: store
            .keyspace(crate::keyspaces::SERVICE_STATE)
            .expect("service_state ks"),
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
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
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
        unknown_keys: Vec::new(),
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
/// Provision the VTA's own signing identity into `keys_ks`: write a
/// deterministic active seed to a [`PlaintextSeedStore`] under `data_dir`,
/// derive the `{vta_did}#key-0` VC-issuance key and the `#sealed-transfer-0`
/// producer-assertion key, and persist their keystore records. Returns the
/// resulting `vta_did` (a real, self-resolving `did:key`) and the seed store
/// the keys were derived from.
///
/// Shared by [`bootstrap_test_vta`] (direct-call deps) and the provisionable
/// HTTP app ([`build_provisionable_test_app`] / [`MockVta::start_provisionable`]),
/// so both paths use the exact same identity wiring the real VTA bootstrap does.
async fn provision_vta_signing_identity(
    keys_ks: &KeyspaceHandle,
    data_dir: &std::path::Path,
) -> (String, Arc<PlaintextSeedStore>) {
    use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};

    // Deterministic 64-byte seed (BIP-32 wants ≥16 bytes; 64 mirrors
    // the mnemonic-derived seed shape used in production setup).
    let raw_seed = [0xC5u8; 64];
    let seed_store = PlaintextSeedStore::new(data_dir);
    crate::keys::seed_store::SeedStore::set(&seed_store, &raw_seed)
        .await
        .expect("write test seed to plaintext store");

    let now = chrono::Utc::now();
    save_seed_record(
        keys_ks,
        &SeedRecord {
            id: 0,
            seed_hex: None,
            seed_enc: None,
            created_at: now,
            retired_at: None,
        },
    )
    .await
    .expect("save seed record");
    set_active_seed_id(keys_ks, 0)
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
        keys_ks,
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
        keys_ks,
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

    (vta_did, Arc::new(PlaintextSeedStore::new(data_dir)))
}

pub async fn bootstrap_test_vta(ts: &TestStore) -> (String, ProvisionIntegrationDeps) {
    let (vta_did, _seed_store) = provision_vta_signing_identity(&ts.keys_ks, &ts.data_dir).await;

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
    pub vault_ks: KeyspaceHandle,
    pub backup_bundles_ks: KeyspaceHandle,
    pub backup_blob_dir: std::path::PathBuf,
    /// The webvh keyspace — exposed so a harness can seed a hosting server
    /// via [`seed_webvh_server`] before driving a DID-mint / join flow.
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    /// The VTA DID this app is configured with — the `did:key:z6MkTestVTA`
    /// sentinel for [`build_test_app`], or a real, self-resolving `did:key`
    /// for [`build_provisionable_test_app`]. A harness driving a URL-direct
    /// provision passes this as the `vta_did` argument.
    pub vta_did: String,
    pub config: Arc<RwLock<AppConfig>>,
    /// Owns the on-disk fjall data dir. When this drops, files are
    /// removed; the caller MUST keep it alive for the duration of the
    /// test (`TestAppContext` is normally bound to a `let _ctx = …`).
    pub _dir: tempfile::TempDir,
}

impl TestAppContext {
    /// Mint an access token for `did` with `role` + `contexts`, bypassing the
    /// live challenge-response handshake. The SDK's `challenge_response` packs a
    /// DIDComm envelope the server unpacks via ATM; a REST-only [`MockVta`] has
    /// no ATM, so authenticated-endpoint tests take this shortcut (the same one
    /// the route-integration suite uses): store an `Authenticated` session and
    /// encode a matching AAL1 JWT. An empty `contexts` vec is super-admin.
    pub async fn mint_token(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        use vti_common::auth::session::{Session, SessionState, store_session};
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let session = Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(&self.sessions_ks, &session)
            .await
            .expect("store session");
        let claims = self.jwt_keys.new_claims(
            did.to_string(),
            session_id,
            role.to_string(),
            contexts,
            900,
            false,
        );
        self.jwt_keys.encode(&claims).expect("encode jwt")
    }
}

/// Knobs for [`build_test_app_with`]. Defaults reproduce the historical
/// [`build_test_app`] behaviour exactly.
#[derive(Default)]
pub struct TestAppOptions {
    /// When `true`, provision a real VTA signing identity (active seed +
    /// `{vta_did}#key-0` + `#sealed-transfer-0`) via
    /// [`provision_vta_signing_identity`] and set `config.vta_did` to the
    /// derived, self-resolving `did:key` — so `provision_integration`
    /// round-trips (VC issuance + bundle sealing) actually succeed against
    /// the app. The default (`false`) keeps the cheap sentinel-DID app the
    /// bulk of route tests rely on (no seed I/O, no key derivation).
    pub provisionable_vta: bool,
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
///
/// For an app whose VTA DID is real and resolvable (needed to drive a full
/// `provision_integration` over HTTP), use [`build_provisionable_test_app`].
pub async fn build_test_app() -> (axum::Router, TestAppContext) {
    build_test_app_with(TestAppOptions::default()).await
}

/// [`build_test_app`] with a real, self-resolving `did:key` VTA identity and
/// the signing keys `provision_integration` needs — the build half of
/// [`MockVta::start_provisionable`].
pub async fn build_provisionable_test_app() -> (axum::Router, TestAppContext) {
    build_test_app_with(TestAppOptions {
        provisionable_vta: true,
    })
    .await
}

/// Backing builder for [`build_test_app`] / [`build_provisionable_test_app`].
pub async fn build_test_app_with(opts: TestAppOptions) -> (axum::Router, TestAppContext) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
    use tokio::sync::watch;

    init_jwt_provider();

    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: dir.path().to_path_buf(),
    };
    let store = Store::open(&store_config).expect("open store");

    let keys_ks = store.keyspace(crate::keyspaces::KEYS).unwrap();
    let sessions_ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();
    let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
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
                parent: None,
                base_path: "m/26'/2'/0'".into(),
                index: 0,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("seed ctx1");
    }
    let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
    let cache_ks = store.keyspace(crate::keyspaces::CACHE).unwrap();
    let vault_ks = store.keyspace(crate::keyspaces::VAULT).unwrap();
    let vault_ks_ctx = vault_ks.clone();
    let service_state_ks = store.keyspace(crate::keyspaces::SERVICE_STATE).unwrap();
    let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap();
    let sealed_nonces_ks = store.keyspace(crate::keyspaces::SEALED_NONCES).unwrap();
    let backup_bundles_ks = store.keyspace(crate::keyspaces::BACKUP_BUNDLES).unwrap();
    let backup_blob_dir = dir.path().join("backups");
    let did_templates_ks = store.keyspace(crate::keyspaces::DID_TEMPLATES).unwrap();
    #[cfg(feature = "webvh")]
    let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
    #[cfg(feature = "webvh")]
    let passkey_vms_ks = store.keyspace(crate::keyspaces::PASSKEY_VMS).unwrap();
    #[cfg(feature = "webvh")]
    let drains_ks = store.keyspace(crate::keyspaces::DRAINS).unwrap();
    #[cfg(feature = "webvh")]
    let snapshot_ks = store
        .keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)
        .unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(
        vti_common::auth::jwt::JwtKeys::from_ed25519_bytes(&jwt_seed, "VTA").expect("jwt keys"),
    );

    // Default: a cheap in-memory seed store + non-resolvable sentinel DID.
    // Provisionable: a real signing identity (active seed + `#key-0` +
    // `#sealed-transfer-0`) derived into `keys_ks`, and `vta_did` set to the
    // resulting self-resolving `did:key`.
    let (vta_did, seed_store): (String, Arc<dyn crate::keys::seed_store::SeedStore>) =
        if opts.provisionable_vta {
            let (did, ps) = provision_vta_signing_identity(&keys_ks, dir.path()).await;
            let store: Arc<dyn crate::keys::seed_store::SeedStore> = ps;
            (did, store)
        } else {
            let store: Arc<dyn crate::keys::seed_store::SeedStore> =
                Arc::new(TestSeedStore(vec![0xABu8; 32]));
            ("did:key:z6MkTestVTA".to_string(), store)
        };

    let mut config: AppConfig = toml::from_str(&format!(
        r#"
        vta_did = "{vta_did}"
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
        webvh_ks: webvh_ks.clone(),
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
        status_list_resolver: None,
        secrets_resolver: None,
        #[cfg(feature = "didcomm")]
        signing_vm_id: None,
        #[cfg(feature = "didcomm")]
        ka_vm_id: None,
        #[cfg(feature = "didcomm")]
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        #[cfg(feature = "didcomm")]
        didcomm_websocket_status: Arc::new(tokio::sync::RwLock::new(
            crate::server::DidcommWebsocketStatus::Disconnected,
        )),
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
        vault_ks: vault_ks_ctx,
        backup_bundles_ks,
        backup_blob_dir,
        #[cfg(feature = "webvh")]
        webvh_ks,
        vta_did,
        config,
        _dir: dir,
    };

    (router, ctx)
}

/// Seed a webvh hosting server directly into the registry keyspace, bypassing
/// the network DID-resolution validation that `operations::did_webvh::servers::
/// add_webvh_server` performs.
///
/// `build_test_app` / [`MockVta`] register no hosting server, so the join
/// DID-mint path (`list_webvh_servers` → pick first → `create_did_webvh`)
/// would otherwise hit an empty catalogue. Call this against
/// [`TestAppContext::webvh_ks`] (or [`MockVta::seed_webvh_server`]) to make
/// that first server resolvable to `list_webvh_servers`.
#[cfg(feature = "webvh")]
pub async fn seed_webvh_server(webvh_ks: &KeyspaceHandle, id: &str, server_did: &str) {
    use chrono::Utc;
    let now = Utc::now();
    let record = vta_sdk::webvh::WebvhServerRecord {
        id: id.to_string(),
        did: server_did.to_string(),
        label: Some(format!("test server {id}")),
        created_at: now,
        updated_at: now,
    };
    crate::webvh_store::store_server(webvh_ks, &record)
        .await
        .expect("seed webvh server");
}

/// Authorize `did` in the ACL so a URL-direct provision / authenticated call is
/// accepted instead of bouncing off the challenge gate with
/// `403 forbidden: DID not in ACL`. An empty `contexts` vec is super-admin.
///
/// Goes through the canonical [`store_acl_entry`](crate::acl::store_acl_entry)
/// so the internal `acl:{did}` key convention and `AclEntry` shape stay
/// encapsulated — callers don't touch the raw [`KeyspaceHandle`]. Counterpart
/// to [`seed_webvh_server`]; reach it ergonomically via
/// [`MockVta::authorize_did`] / [`MockVta::grant_super_admin`].
pub async fn seed_acl_entry(
    acl_ks: &KeyspaceHandle,
    did: &str,
    role: crate::acl::Role,
    contexts: Vec<String>,
) {
    let entry = crate::acl::AclEntry::new(did, role, "test-support").with_contexts(contexts);
    crate::acl::store_acl_entry(acl_ks, &entry)
        .await
        .expect("seed acl entry");
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
    /// and serving. Uses the cheap sentinel-DID app ([`build_test_app`]); the
    /// VTA DID is not resolvable. For an e2e that drives a full
    /// `provision_integration`, use [`start_provisionable`](Self::start_provisionable).
    pub async fn start() -> MockVta {
        Self::serve(build_test_app().await).await
    }

    /// Like [`start`](Self::start) but with a real, self-resolving `did:key`
    /// VTA identity and the signing keys `provision_integration` needs
    /// ([`build_provisionable_test_app`]).
    ///
    /// This is the seam for the full OpenVTC bootstrap→join e2e: the VTA DID
    /// isn't resolvable *back to the loopback URL*, but it doesn't need to be —
    /// drive provisioning **URL-direct** by passing [`base_url`](Self::base_url)
    /// and [`vta_did`](Self::vta_did) to
    /// [`vta_sdk::provision_client::provision_admin_rotated_via_rest`] (or the
    /// `FullSetup` `provision_via_rest`), which never re-resolves the DID. The
    /// VTA's own `did:key` is self-resolving, so VC issuance and bundle sealing
    /// succeed server-side.
    pub async fn start_provisionable() -> MockVta {
        Self::serve(build_provisionable_test_app().await).await
    }

    /// Bind an ephemeral loopback port, serve `router` in a background task,
    /// and return once bound. Shared by [`start`](Self::start) /
    /// [`start_provisionable`](Self::start_provisionable).
    async fn serve((router, ctx): (axum::Router, TestAppContext)) -> MockVta {
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

    /// The VTA DID this mock is configured with — pass alongside
    /// [`base_url`](Self::base_url) to a URL-direct provision entry point.
    pub fn vta_did(&self) -> &str {
        &self.ctx.vta_did
    }

    /// Seed a webvh hosting server so a DID-mint / join flow finds a server in
    /// the catalogue. Thin wrapper over [`seed_webvh_server`] against this
    /// mock's keyspace.
    #[cfg(feature = "webvh")]
    pub async fn seed_webvh_server(&self, id: &str, server_did: &str) {
        seed_webvh_server(&self.ctx.webvh_ks, id, server_did).await;
    }

    /// Authorize `did` in the ACL with `role` + `contexts` so a URL-direct
    /// provision / authenticated call against this mock is accepted (rather than
    /// 403ing at the challenge gate). An empty `contexts` vec is super-admin.
    /// Thin wrapper over [`seed_acl_entry`] against this mock's ACL keyspace;
    /// counterpart to [`seed_webvh_server`](Self::seed_webvh_server).
    pub async fn authorize_did(&self, did: &str, role: crate::acl::Role, contexts: Vec<String>) {
        seed_acl_entry(&self.ctx.acl_ks, did, role, contexts).await;
    }

    /// Convenience: authorize `did` as a super-admin (admin role, no context
    /// scope) — the common case for driving a URL-direct provision. Shorthand
    /// for [`authorize_did`](Self::authorize_did)`(did, Role::Admin, vec![])`.
    pub async fn grant_super_admin(&self, did: &str) {
        self.authorize_did(did, crate::acl::Role::Admin, Vec::new())
            .await;
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
