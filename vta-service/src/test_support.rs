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

/// Validates real dispatch output against published response schemas. See the
/// module docs for why it sits at the spine rather than in middleware.
pub mod response_conformance;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Duration;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use tokio::sync::RwLock;
use vti_common::slip10::{DerivationPath, ExtendedSigningKey};

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
    /// The sink over [`Self::audit_ks`] — tests that *write* audit rows take
    /// this, tests that read them back take the keyspace.
    pub audit: vta_audit::SharedAuditSink,
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
        audit: std::sync::Arc::new(vta_audit::KeyspaceAuditSink::new(
            store.keyspace(crate::keyspaces::AUDIT).expect("audit ks"),
        )),
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
        mediator_readiness: Default::default(),
        services: Default::default(),
        auth: Default::default(),
        audit: Default::default(),
        vault: Default::default(),
        app_state: Default::default(),
        policy: Default::default(),
        secrets: Default::default(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        hardened: Default::default(),
        config_path: PathBuf::new(),
        unknown_keys: Vec::new(),
        effective_config_digest: None,
        effective_config_view: None,
    }
}

/// Build a `ProvisionIntegrationDeps` from a `TestStore`. The returned
/// deps have no DID resolver — use [`bootstrap_test_vta`] when the
/// full happy path is needed.
pub fn test_deps(ts: &TestStore) -> ProvisionIntegrationDeps {
    ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit: std::sync::Arc::new(vta_audit::KeyspaceAuditSink::new(ts.audit_ks.clone())),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(test_app_config(ts.data_dir.clone()))),
        did_resolver: None,
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
    }
}

/// Synthesise a super-admin `AuthClaims` for tests that bypass the
/// normal session/JWT gate.
/// The test super-admin's identity — a **real** `did:key`, derived from a fixed
/// seed so it is stable across runs and reproducible from this constant alone.
///
/// It used to be the literal `"did:key:zTestAdmin"`, which is not a `did:key`
/// at all: nothing resolves it, and no document issued by it can carry a
/// verifiable proof. That was fine while the dispatcher accepted proofless
/// documents. It stopped being fine when the spine started enforcing SPEC §7.2
/// item 7 — 72 of the 109 dispatched specs declare `proof` REQUIRED, and a test
/// that cannot sign cannot exercise any of them.
pub const TEST_ADMIN_SEED: [u8; 32] = [0x7A; 32];

/// The test super-admin's `did:key`, and the verification method inside it.
///
/// `did:key` encodes the public key in the identifier, so the DID document is
/// derivable from the string — no network, no resolver cache, and the VTA
/// verifies a proof from it without any test-only resolution path.
pub fn test_admin_did() -> (String, String) {
    did_for_seed(TEST_ADMIN_SEED[0])
}

/// The `did:key` and verification method for a one-byte test seed.
///
/// One byte, not 32, because a test only ever needs identities to be *distinct*
/// and *reproducible*; naming them by a single number keeps a two-caller test
/// from having to invent two DID strings and keep them in step with two tokens.
pub fn did_for_seed(seed: u8) -> (String, String) {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(sk.verifying_key().as_bytes());
    let mb = multibase::encode(multibase::Base::Base58Btc, mc);
    let did = format!("did:key:{mb}");
    let vm = format!("{did}#{mb}");
    (did, vm)
}

/// Attach an `eddsa-jcs-2022` Data Integrity proof from the test super-admin.
///
/// Mirrors the producer side: the proof is taken over the document with any
/// existing `proof` removed, which is what `prepare_sign_input` expects and
/// what the VTA re-derives when it verifies.
pub fn sign_as_test_admin(doc: &mut trust_tasks_rs::TrustTask<serde_json::Value>) {
    sign_as(TEST_ADMIN_SEED[0], doc)
}

/// Attach an `eddsa-jcs-2022` proof from the identity `seed` names.
///
/// The document's `issuer` must be [`did_for_seed`] of the same seed: SPEC §7.2
/// item 6 rejects a document whose in-band issuer disagrees with the
/// transport-authenticated identity, so a test that mints a token for one DID
/// and signs with another is refused for that rather than for whatever it meant
/// to check.
pub fn sign_as(seed: u8, doc: &mut trust_tasks_rs::TrustTask<serde_json::Value>) {
    use affinidi_data_integrity::DataIntegrityProof;
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::prepare_sign_input;
    use ed25519_dalek::{Signer, SigningKey};

    let (_did, vm) = did_for_seed(seed);
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let mut di = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        vm,
        "assertionMethod".to_string(),
        None,
        Some(
            chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                .to_string(),
        ),
        None,
    );
    doc.proof = None;
    let input = prepare_sign_input(&*doc, &di, CryptoSuite::EddsaJcs2022)
        .expect("the test document prepares for signing");
    di.proof_value = Some(multibase::encode(
        multibase::Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(
        serde_json::from_value(serde_json::to_value(&di).expect("proof serialises"))
            .expect("proof round-trips into the framework type"),
    );
}

pub fn super_admin_claims() -> AuthClaims {
    AuthClaims {
        did: test_admin_did().0,
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
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
/// `vta_did_override` replaces the derived `did:key` as the identity the
/// keystore records are filed under (see [`TestAppOptions::vta_transport`]). The
/// signing key itself is seed-derived either way — only the record ids change.
async fn provision_vta_signing_identity(
    keys_ks: &KeyspaceHandle,
    data_dir: &std::path::Path,
    vta_did_override: Option<&str>,
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
    let vta_did = match vta_did_override {
        Some(did) => did.to_string(),
        None => format!("did:key:{multibase}"),
    };
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
    let (vta_did, _seed_store) =
        provision_vta_signing_identity(&ts.keys_ks, &ts.data_dir, None).await;

    let mut config = test_app_config(ts.data_dir.clone());
    config.vta_did = Some(vta_did.clone());
    config.public_url = Some("https://vta.test".into());

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("DID resolver");

    let deps = ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit: std::sync::Arc::new(vta_audit::KeyspaceAuditSink::new(ts.audit_ks.clone())),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(config)),
        did_resolver: Some(resolver),
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
    };
    (vta_did, deps)
}

/// Build a full [`crate::server::AppState`] whose VTA signing identity is
/// provisioned (active seed + `{vta_did}#key-0`), so handlers that **mint**
/// VTA-signed credentials (e.g. `trust_tasks::credentials::handle_issue`) can
/// load the issuer key and produce a real Data-Integrity proof.
///
/// Returns the `AppState` plus the owning `TempDir` (the caller must keep it
/// alive — dropping it removes the on-disk fjall store). Uses the canonical
/// [`build_app_state`](crate::server::build_app_state) constructor so the test
/// state can't diverge from production wiring.
pub async fn build_signing_test_app_state() -> (crate::server::AppState, tempfile::TempDir) {
    build_signing_test_app_state_with_sink(None).await
}

/// As [`build_signing_test_app_state`], with an audit sink installed.
///
/// Split out for the audit-coverage census, which needs to observe what a
/// dispatched task records. Everything else is identical, and the no-sink form
/// above delegates here so the two states cannot drift.
pub async fn build_signing_test_app_state_with_sink(
    audit_sink: Option<vta_audit::SharedAuditSink>,
) -> (crate::server::AppState, tempfile::TempDir) {
    use crate::server::{AppStateParts, build_app_state};
    use tokio::sync::watch;

    init_jwt_provider();
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    // Provision the VTA's `{vta_did}#key-0` VC-issuance key into the keystore
    // and point the config at the resulting self-resolving did:key.
    let keys_ks = store.keyspace(crate::keyspaces::KEYS).expect("keys ks");
    let (vta_did, seed_store) = provision_vta_signing_identity(&keys_ks, dir.path(), None).await;
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> = seed_store;

    let mut config = test_app_config(dir.path().to_path_buf());
    config.vta_did = Some(vta_did);
    config.public_url = Some("https://vta.test".into());

    let (restart_tx, _rx) = watch::channel(false);
    let state = build_app_state(
        config,
        &store,
        seed_store,
        None,
        None,
        restart_tx,
        // `..Default::default()` rather than default-then-assign: this is the
        // same crate, so the non-exhaustive struct literal is available here
        // even though `tests/audit_sink.rs` cannot use it from outside.
        AppStateParts {
            audit_sink,
            ..Default::default()
        },
    )
    .await
    .expect("build signing app state");
    (state, dir)
}

/// The context [`bootstrap_provisionable_test_vta`] registers and the one a
/// well-formed request should target (`context_hint` + the `context` param).
pub const PROVISIONABLE_CONTEXT: &str = "provisionable-ctx";

/// Like [`bootstrap_test_vta`] but the returned VTA can actually *succeed*: it
/// additionally registers a fresh target context ([`PROVISIONABLE_CONTEXT`]),
/// so a well-formed request reaches the high-value render → seal → issue path
/// instead of erroring at the context-existence precondition.
///
/// No template needs registering — the built-in `didcomm-mediator` /
/// `vta-admin` templates resolve via the SDK's embedded loader, so a request
/// naming one of those + a valid var set renders directly. Pair this with
/// [`provisionable_mediator_vars`] for a known-`Ok` baseline that a fuzz
/// campaign can mutate, e.g.:
///
/// ```ignore
/// let ts = open_test_store().await;
/// let (_vta_did, deps) = bootstrap_provisionable_test_vta(&ts).await;
/// let request = signed_request_with_vars(
///     "didcomm-mediator", PROVISIONABLE_CONTEXT, fuzzed_vars,
/// ).await;
/// let out = provision_integration(&deps, &super_admin_claims(), ProvisionIntegrationParams {
///     request, context: PROVISIONABLE_CONTEXT.into(),
///     assertion_mode: AssertionMode::PinnedOnly, vc_validity: None,
/// }).await;
/// ```
///
/// Both `AssertionMode::PinnedOnly` and `AssertionMode::DidSigned` return `Ok`
/// for a well-formed request (the `#sealed-transfer-0` producer key is
/// provisioned by [`bootstrap_test_vta`]); `Attested` needs Nitro material and
/// is out of scope here.
pub async fn bootstrap_provisionable_test_vta(
    ts: &TestStore,
) -> (String, ProvisionIntegrationDeps) {
    let (vta_did, deps) = bootstrap_test_vta(ts).await;
    crate::contexts::create_context(
        &ts.contexts_ks,
        PROVISIONABLE_CONTEXT,
        "Provisionable Context",
    )
    .await
    .expect("create provisionable context");
    (vta_did, deps)
}

/// A baseline well-formed variable set for the built-in `didcomm-mediator`
/// template — the known-`Ok` starting point a fuzz campaign mutates to drive
/// hostile variables through the real renderer/sealer/issuer.
pub fn provisionable_mediator_vars() -> BTreeMap<String, Value> {
    let mut vars = BTreeMap::new();
    vars.insert("URL".into(), Value::String("https://mediator.test".into()));
    vars.insert(
        "WS_URL".into(),
        Value::String("wss://mediator.test/ws".into()),
    );
    vars.insert("ROUTING_KEYS".into(), Value::Array(vec![]));
    vars
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
    /// The policy keyspace — exposed so an end-to-end harness can install the
    /// Rego a deployment would, rather than reach past the Policy Decision Point
    /// it is trying to exercise.
    pub policy_ks: KeyspaceHandle,
    /// The contexts keyspace — exposed so a harness can seed the trust context a
    /// DID mint requires, the way a provisioning flow would.
    pub contexts_ks: KeyspaceHandle,
    /// The VTA DID this app is configured with — the `did:key:z6MkTestVTA`
    /// sentinel for [`build_test_app`], or a real, self-resolving `did:key`
    /// for [`build_provisionable_test_app`]. A harness driving a URL-direct
    /// provision passes this as the `vta_did` argument.
    pub vta_did: String,
    pub config: Arc<RwLock<AppConfig>>,
    /// The durable messaging outbox keyspace. Exposed because
    /// [`crate::messaging::service::build_messaging`] requires one, and a
    /// mediator-backed harness has to build the listener itself.
    pub outbox_ks: KeyspaceHandle,
    /// The app's `AppState`. Exposed so a harness can run the **production**
    /// inbound loop against the very state the HTTP router serves — the same
    /// reason `vtc-service`'s `TestVtc` exposes its own.
    pub state: crate::server::AppState,
    /// Owns the on-disk fjall data dir. When this drops, files are
    /// removed; the caller MUST keep it alive for the duration of the
    /// test (`TestAppContext` is normally bound to a `let _ctx = …`).
    pub _dir: tempfile::TempDir,
}

impl TestAppContext {
    /// Mint a signing identity **and** a matching token, for a test that drives
    /// the VTA through `vta_sdk::VtaClient`.
    ///
    /// [`mint_token`](Self::mint_token) alone is no longer enough for those.
    /// The spine enforces SPEC §7.2, so a document needs an in-band `recipient`
    /// (item 5b, every dispatched spec) and a `proof` from the same identity
    /// the token authenticates (items 6 and 7a, 72 of them). A token names a
    /// DID; signing needs the key behind it, and `did:key` is the method where
    /// the two are derivable from one seed.
    ///
    /// `seed` selects the identity, so a test that wants two callers asks for
    /// two seeds rather than two unrelated strings.
    pub async fn mint_signing_identity(
        &self,
        seed: u8,
        role: &str,
        contexts: Vec<String>,
        vta_did: &str,
    ) -> (vta_sdk::client::ClientIdentity, String) {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(sk.verifying_key().as_bytes());
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, mc)
        );
        let token = self.mint_token(&did, role, contexts).await;
        // The private key travels as the multibase-encoded *seed*, which is what
        // `trust_task_sign::sign_in_place` decodes.
        let private_key_multibase =
            multibase::encode(multibase::Base::Base58Btc, sk.to_bytes().as_slice());
        (
            vta_sdk::client::ClientIdentity {
                client_did: did,
                private_key_multibase,
                vta_did: vta_did.to_string(),
                verification_method: None,
            },
            token,
        )
    }

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
            last_seen: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
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

    /// DID documents to pre-seed into the app's DID resolver cache as
    /// `(did, document-json)` pairs. `resolve()` is cache-first, so a seeded
    /// DID resolves in-process with no network — used to make a stub webvh
    /// hosting server's `did:webvh:<scid>:<domain>` resolve to a loopback
    /// `WebVHHosting` endpoint (see [`MockVta::start_with_webvh_host`]). The
    /// JSON deserializes into the resolver's `Document` type.
    pub preseed_did_docs: Vec<(String, serde_json::Value)>,

    /// webvh hosting servers to register in the registry keyspace as
    /// `(server_id, server_did)` — the equivalent of [`seed_webvh_server`]
    /// applied at build time, so `create_did_webvh` finds the server.
    #[cfg(feature = "webvh")]
    pub webvh_servers: Vec<(String, String)>,

    /// Optional messaging (ATM) handle to wire into `AppState.atm`. The
    /// default (`None`) leaves the app REST-only, so the DIDComm branch of
    /// `POST /auth/` short-circuits on "ATM not configured". Tests that need
    /// to exercise `atm.unpack` (e.g. the plaintext-forgery guard)
    /// build an offline ATM via [`build_offline_atm`] and pass it here.
    pub atm: Option<affinidi_tdk::messaging::ATM>,

    /// A pre-minted transport identity for the VTA, replacing the `did:key`
    /// [`provision_vta_signing_identity`] would derive. Set by
    /// [`MockVta::start_with_transports`] to a `did:peer:2` advertising
    /// `DIDCommMessaging` / `TSPTransport` — a `did:key` cannot carry a service
    /// block, so it can never tell a client which transports the VTA speaks.
    pub vta_transport: Option<VtaTransportIdentity>,
}

/// A mediator-backed transport identity for the mock VTA
/// ([`TestAppOptions::vta_transport`]).
///
/// The seed-derived `{vta_did}#key-0` / `#sealed-transfer-0` keystore records
/// are still provisioned against [`did`](Self::did); those ids are keystore
/// record *keys*, not verification methods resolved from the document, so the
/// DID method is free to be `did:peer`. The [`secrets`](Self::secrets) here are
/// the separate *transport* keys (`#key-1` Ed25519, `#key-2` X25519) that the
/// DIDComm/TSP packing paths resolve out of the document — the same split
/// `MockVtcDidcomm` uses.
#[derive(Clone)]
pub struct VtaTransportIdentity {
    /// The `did:peer:2` that becomes `config.vta_did`.
    pub did: String,
    /// Its `#key-1` (Ed25519) + `#key-2` (X25519) secrets.
    pub secrets: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
    /// The mediator both advertised services point at.
    pub mediator_did: String,
}

/// What [`build_transport_state`] hands back — a struct rather than a tuple so
/// the TSP slot can be `cfg`-gated (attributes are not allowed on tuple type
/// elements) and so the five `Option`s stay distinguishable at the call site.
#[derive(Default)]
struct TransportState {
    secrets_resolver: Option<Arc<affinidi_secrets_resolver::ThreadedSecretsResolver>>,
    signing_vm_id: Option<String>,
    ka_vm_id: Option<String>,
    atm: Option<affinidi_tdk::messaging::ATM>,
    #[cfg(feature = "tsp")]
    tsp_profile: Option<Arc<affinidi_tdk::messaging::profiles::ATMProfile>>,
}

/// Build the AppState transport slots from a pre-minted
/// [`VtaTransportIdentity`], or all-`None` when there isn't one (the REST-only
/// default every existing caller gets).
///
/// The verification-method ids are the fixed `did:peer:2` shape
/// `#key-1` (Ed25519) / `#key-2` (X25519) that
/// [`crate::operations::did_peer`] mints — read from the secrets rather than
/// re-derived, so a change in that shape surfaces here instead of silently
/// packing with the wrong key.
async fn build_transport_state(
    identity: Option<&VtaTransportIdentity>,
    did_resolver: Option<&DIDCacheClient>,
) -> TransportState {
    use affinidi_secrets_resolver::SecretsResolver as _;
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::config::ATMConfig;

    let Some(identity) = identity else {
        return TransportState::default();
    };

    let (secrets_resolver, _task) =
        affinidi_secrets_resolver::ThreadedSecretsResolver::new(None).await;
    secrets_resolver.insert_vec(&identity.secrets).await;

    // `#key-1` is Ed25519 (verification), `#key-2` X25519 (key agreement).
    let vm_id = |suffix: &str| -> Option<String> {
        identity
            .secrets
            .iter()
            .map(|s| s.id.clone())
            .find(|id| id.ends_with(suffix))
    };

    let mut builder = TDKConfig::builder().with_load_environment(false);
    if let Some(dr) = did_resolver {
        builder = builder.with_did_resolver(dr.clone());
    }
    let tdk = TDKSharedState::new(builder.build().expect("TDK config"))
        .await
        .expect("TDK shared state");
    for secret in &identity.secrets {
        tdk.secrets_resolver().insert(secret.clone()).await;
    }
    let atm = affinidi_tdk::messaging::ATM::new(
        ATMConfig::builder().build().expect("ATM config"),
        Arc::new(tdk),
    )
    .await
    .expect("transport ATM");

    #[cfg(feature = "tsp")]
    let tsp_profile = {
        let profile = affinidi_tdk::messaging::profiles::ATMProfile::new(
            &atm,
            Some("VTA".to_string()),
            identity.did.clone(),
            None,
        )
        .await
        .expect("build TSP profile");
        Some(
            atm.profile_add(&profile, false)
                .await
                .expect("register TSP profile"),
        )
    };

    TransportState {
        secrets_resolver: Some(Arc::new(secrets_resolver)),
        signing_vm_id: vm_id("#key-1"),
        ka_vm_id: vm_id("#key-2"),
        atm: Some(atm),
        #[cfg(feature = "tsp")]
        tsp_profile,
    }
}

/// Build a fully-offline [`ATM`](affinidi_tdk::messaging::ATM) suitable for
/// unit tests that need `atm.unpack` without a live mediator. No secrets and
/// no network mode are configured, so it can unpack a **plaintext** DIDComm
/// envelope (which needs no keys) but not decrypt a JWE. That's exactly what
/// the plaintext-forgery regression needs: prove the handler rejects an
/// unauthenticated envelope after unpack.
pub async fn build_offline_atm() -> affinidi_tdk::messaging::ATM {
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::config::ATMConfig;

    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("TDK config"))
        .await
        .expect("TDK shared state");
    affinidi_tdk::messaging::ATM::new(
        ATMConfig::builder().build().expect("ATM config"),
        Arc::new(tdk),
    )
    .await
    .expect("offline ATM")
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
        ..Default::default()
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
                context_policy: None,
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
    // Register any caller-requested webvh hosting servers up front so
    // `create_did_webvh` finds them in the catalogue.
    #[cfg(feature = "webvh")]
    for (id, did) in &opts.webvh_servers {
        seed_webvh_server(&webvh_ks, id, did).await;
    }
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
            let (did, ps) = provision_vta_signing_identity(
                &keys_ks,
                dir.path(),
                opts.vta_transport.as_ref().map(|t| t.did.as_str()),
            )
            .await;
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

    // Build the DID resolver and pre-seed any caller-supplied documents into its
    // cache. `resolve()` is cache-first, so a seeded `did:webvh:<scid>:<domain>`
    // resolves in-process (no network) to its loopback `WebVHHosting` endpoint.
    let did_resolver = {
        let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .ok();
        if let Some(client) = resolver.as_mut() {
            for (did, doc_json) in &opts.preseed_did_docs {
                let doc = serde_json::from_value(doc_json.clone())
                    .expect("preseed DID document must deserialize into a resolver Document");
                client.add_did_document(did, doc).await;
            }
        }
        resolver
    };

    // Transport wiring. Mirrors what `server::init_auth` does in production —
    // the VTA's own secrets in a resolver, its `#key-1`/`#key-2` verification
    // method ids, an ATM for `auth`'s unpack path, and (TSP) a registered
    // profile for `tsp-message` unseal.
    //
    // This ATM deliberately has NO websocket: `MockVta::start_with_transports`
    // gives the *listener* its own, and the mediator permits one socket per DID
    // — a second would be terminated as `w.websocket.duplicate-channel`. Same
    // split, and the same reason, as `MockVtcDidcomm`.
    let transport = build_transport_state(opts.vta_transport.as_ref(), did_resolver.as_ref()).await;

    let policy_ks = store.keyspace(crate::keyspaces::POLICY).unwrap();
    let state = crate::server::AppState {
        audit_sink: std::sync::Arc::new(vta_audit::KeyspaceAuditSink::new(
            store.keyspace(crate::keyspaces::AUDIT).unwrap(),
        )),
        internal_ks: store.keyspace(crate::keyspaces::INTERNAL_KEYS).unwrap(),
        idempotency_ks: store.keyspace(crate::keyspaces::IDEMPOTENCY).unwrap(),
        // Empty by default: a test VTA trusts no mdoc issuer until one is
        // configured, matching the fail-closed production default. A test that
        // needs mdoc receive builds its own anchors and swaps this out.
        mdoc_trust: std::sync::Arc::new(
            vta_vault::mdoc_trust::IacaTrustAnchors::from_pem(&[])
                .expect("an empty anchor set always parses"),
        ),
        keys_ks: keys_ks.clone(),
        sessions_ks: sessions_ks.clone(),
        acl_ks: acl_ks.clone(),
        contexts_ks: contexts_ks.clone(),
        did_templates_ks,
        audit_ks,
        imported_ks,
        cache_ks,
        vault_ks,
        consent_ks: store.keyspace(crate::keyspaces::CONSENT).unwrap(),
        consent_approvers_ks: store.keyspace(crate::keyspaces::CONSENT_APPROVERS).unwrap(),
        issued_credentials_ks: store
            .keyspace(crate::keyspaces::ISSUED_CREDENTIALS)
            .unwrap(),
        memory_ks: store.keyspace(crate::keyspaces::MEMORY).unwrap(),
        app_state_ks: store.keyspace(crate::keyspaces::APP_STATE).unwrap(),
        app_state_locks: crate::operations::app_state::NamespaceLocks::default(),
        policy_ks: policy_ks.clone(),
        task_consent_ks: store.keyspace(crate::keyspaces::TASK_CONSENT).unwrap(),
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
        did_resolver,
        status_list_resolver: None,
        secrets_resolver: transport.secrets_resolver,
        #[cfg(feature = "didcomm")]
        signing_vm_id: transport.signing_vm_id,
        #[cfg(feature = "didcomm")]
        ka_vm_id: transport.ka_vm_id,
        #[cfg(feature = "didcomm")]
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
        #[cfg(feature = "tsp")]
        tsp_reach: Arc::new(crate::messaging::tsp_reach::TspReachability::new()),
        jwt_keys: Some(jwt_keys.clone()),
        atm: transport.atm.or(opts.atm),
        #[cfg(feature = "tsp")]
        tsp_profile: transport.tsp_profile,
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
    let state_for_ctx = state.clone();
    let router = crate::routes::router_with_cors(
        &[],
        true,
        crate::routes::UNAUTH_INTERVAL_SECS,
        crate::routes::UNAUTH_BURST,
    )
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
        policy_ks,
        contexts_ks: contexts_ks.clone(),
        vta_did,
        config,
        outbox_ks: store.keyspace(crate::keyspaces::OUTBOX).unwrap(),
        state: state_for_ctx,
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
/// that first server appear in `list_webvh_servers`.
///
/// The `server_did` is stored verbatim and is **not** made resolvable — this
/// is enough for catalogue/listing tests, but a `create_did_webvh` *mint*
/// additionally needs the server DID to resolve to a reachable
/// `WebVHHosting` endpoint. For that, use
/// [`MockVta::start_with_webvh_host`], which stands up an in-process
/// [`StubWebvhHost`] and registers a resolvable server DID pointing at it.
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

/// The WebVH URL the [`StubWebvhHost`] hands back from `request_uri` — a
/// syntactically valid WebVH URL the VTA mints the persona DID from (same shape
/// the serverless `create_did_webvh` tests are known to mint against). The
/// resulting persona DID is `did:webvh:<scid>:webvh-host.test`.
#[cfg(feature = "webvh")]
pub const STUB_WEBVH_DID_URL: &str = "https://webvh-host.test/dids/persona/did.jsonl";

/// A minimal in-process stub of a **webvh hosting server** — just enough of the
/// REST API (`webvh_client.rs`) for the VTA's `create_did_webvh` server-managed
/// path to complete a round-trip: authenticate, reserve a path
/// (`request_uri`), and publish the signed `did.jsonl`.
///
/// It ignores the VTA's auth credentials (returns canned tokens) and persists
/// nothing — the actual DID minting happens VTA-side via `didwebvh-rs`; the host
/// only needs to hand back a valid WebVH URL and accept the publish. Pair it
/// with a resolver-seeded server DID (see [`MockVta::start_with_webvh_host`]).
/// Bound to a random loopback port; shuts down on drop.
#[cfg(feature = "webvh")]
pub struct StubWebvhHost {
    base_url: String,
    /// Number of upcoming `PUT /api/dids/{mnemonic}` publishes to fail with a
    /// 500 before accepting again — lets a test simulate a transient host
    /// outage and assert the VTA self-recovers. Shared with the route handler.
    fail_puts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "webvh")]
impl StubWebvhHost {
    /// Start the stub host on a random loopback port and return once bound.
    pub async fn start() -> StubWebvhHost {
        use axum::routing::post;
        use serde_json::json;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Shared publish-failure budget: the PUT handler fails while this is
        // > 0, decrementing each time, so a test can outage the host for N
        // publishes and watch the VTA recover afterwards.
        let fail_puts = Arc::new(AtomicUsize::new(0));

        /// Reject a request that arrives without an `Authorization: Bearer`
        /// header. The real hosting daemon returns 401 "missing or invalid
        /// Authorization header" here; the stub mirrors that so a test can
        /// prove the VTA's publish path actually authenticates (regression
        /// guard for the `from_server` → `from_server_authenticated` fix).
        fn require_bearer(headers: &axum::http::HeaderMap) -> Result<(), axum::http::StatusCode> {
            let ok = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("Bearer ") && v.len() > "Bearer ".len());
            if ok {
                Ok(())
            } else {
                Err(axum::http::StatusCode::UNAUTHORIZED)
            }
        }

        async fn tokens() -> axum::Json<serde_json::Value> {
            // Daemon's flat `AuthenticateResponse` — `{ session, tokens }`
            // with OAuth2-style *relative* expiries (`expiresIn` seconds).
            axum::Json(json!({
                "session": {
                    "id": "stub-session",
                    "subject": "did:webvh:stub:vta",
                    "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    "expiresAt": "2026-01-02T00:00:00Z",
                },
                "tokens": {
                    "accessToken": "stub-access-token",
                    "refreshToken": "stub-refresh-token",
                    "tokenType": "Bearer",
                    "expiresIn": 9_999_999u64,
                    "refreshExpiresIn": 9_999_999u64,
                }
            }))
        }

        let router = axum::Router::new()
            .route(
                "/api/auth/challenge",
                post(|| async {
                    // Daemon's flat `ChallengeResponse` shape —
                    // `{ challenge, sessionId, expiresAt }`, no `data`
                    // envelope. (The token endpoints below stay
                    // `{ sessionId, data }`, matching TokenResponseWire.)
                    axum::Json(json!({
                        "challenge": "stub-challenge-0000000000000000",
                        "sessionId": "stub-session",
                        "expiresAt": "2099-01-01T00:00:00Z"
                    }))
                }),
            )
            .route("/api/auth/", post(tokens))
            .route("/api/auth/refresh", post(tokens))
            // Agent names live on the *host*, not in the VTA — which is why
            // every `agent-name/*` task refuses a serverless DID. The host
            // takes one `update` verb carrying the target state (`bound`,
            // `parked`, …) rather than a verb per operation, so set / remove /
            // disable / enable all land here.
            .route(
                "/api/agent-names/update",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!({ "record": {} })))
                }),
            )
            // `remove` is its own verb, not an `update` state: releasing a name
            // returns it to the pool, which is a different act from parking it.
            .route(
                "/api/agent-names/remove",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!({ "record": {} })))
                }),
            )
            .route(
                "/api/agent-names/check",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    // Available and unreserved: the arm a caller checks before
                    // claiming, and the one whose shape the VTA relays.
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!({
                        "name": "coverage-agent",
                        "domain": "webvh-host.test",
                        "available": true,
                        "reserved": false,
                    })))
                }),
            )
            // `GET /api/dids?owner=…` — the host's view of the DIDs it holds
            // for one owner. `servers/{reconcile,retire-orphan}` both read it
            // to compare the host's list against the VTA's records.
            //
            // Answers with one slot the VTA has **no** record of. Reconcile's
            // job is to report the difference between two sets, so this makes
            // both arms non-empty at once: the slot below is `host_only`, and
            // the DID the test mints is `agent_only`. An empty list would prove
            // only one arm, and a list echoing the VTA's own records would
            // prove neither.
            //
            // It is also what makes `servers/retire-orphan` reachable — a slot
            // is retireable precisely when it is host-only.
            .route(
                "/api/dids",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!([{
                        "mnemonic": "cov-orphan-slot",
                        "domain": "webvh-host.test",
                        "disabled": false,
                        "updatedAt": 1_767_225_600u64,
                    }])))
                }),
            )
            // The caller-scoped domain listing. A real `did-hosting-control`
            // serves this so an operator can discover which tenant domains
            // their credential may mint into; the VTA proxies it for
            // `vta/webvh/servers/domains/0.1`. One domain is enough to exercise
            // the response shape, and `default: true` makes it the one a mint
            // with no explicit `--domain` resolves to.
            .route(
                "/api/me/domains",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(
                        // `name` / `defaultDomain` / `status` / `createdAt`,
                        // matching `vta_webvh::MyDomainEntry`. Two details a
                        // stub gets wrong by guessing: `createdAt` is **Unix
                        // seconds**, not RFC 3339 — the VTA converts when it
                        // relays into the canonical `DomainEntry`, which does
                        // want a string — and the canonical shape *requires*
                        // it, so omitting it fails the relayed schema rather
                        // than the decode.
                        json!({
                            "domains": [{
                                "name": "webvh-host.test",
                                "defaultDomain": true,
                                "status": "active",
                                "createdAt": 1_767_225_600u64,
                            }],
                            "default": "webvh-host.test",
                        }),
                    ))
                }),
            )
            .route(
                "/api/dids",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(
                        // camelCase `didUrl` — the real daemon
                        // (`did-hosting-common::RequestUriResponse`) serializes
                        // camelCase, and the client deserializes with
                        // `rename_all = "camelCase"`. Emitting snake_case here
                        // made the stub diverge from the wire shape it exists to
                        // imitate, so the round-trip failed to decode.
                        json!({ "didUrl": STUB_WEBVH_DID_URL, "mnemonic": "stub-mnemonic" }),
                    ))
                }),
            )
            .route(
                "/api/dids/register",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(
                        // camelCase `didUrl` — the real daemon
                        // (`did-hosting-common::RequestUriResponse`) serializes
                        // camelCase, and the client deserializes with
                        // `rename_all = "camelCase"`. Emitting snake_case here
                        // made the stub diverge from the wire shape it exists to
                        // imitate, so the round-trip failed to decode.
                        json!({ "didUrl": STUB_WEBVH_DID_URL, "mnemonic": "stub-mnemonic" }),
                    ))
                }),
            )
            .route(
                "/api/dids/check",
                post(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!({ "available": true })))
                }),
            )
            .route(
                // `GET` answers the DID's record, whose `agentNames` array is
                // what `agent-name/list` reads. `createdAt` is Unix seconds
                // here as it is on the domain listing — the wire type has a
                // custom deserializer for it, which is the tell.
                "/api/dids/{mnemonic}",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(json!({
                        "agentNames": [{
                            "name": "coverage-agent",
                            "enabled": true,
                            "createdAt": 1_767_225_600u64,
                        }],
                    })))
                })
                .put({
                    let fail_puts = fail_puts.clone();
                    move |headers: axum::http::HeaderMap| {
                        let fail_puts = fail_puts.clone();
                        async move {
                            require_bearer(&headers)?;
                            // Simulate a transient host outage while the budget
                            // lasts. The real daemon commits nothing on a 500,
                            // so this mirrors "the publish didn't land".
                            if fail_puts
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                    n.checked_sub(1)
                                })
                                .is_ok()
                            {
                                return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                            }
                            Ok::<_, axum::http::StatusCode>(axum::http::StatusCode::OK)
                        }
                    }
                })
                .delete(|headers: axum::http::HeaderMap| async move {
                    require_bearer(&headers)?;
                    Ok::<_, axum::http::StatusCode>(axum::http::StatusCode::OK)
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub webvh host port");
        let addr = listener.local_addr().expect("stub host local addr");
        let base_url = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });

        StubWebvhHost {
            base_url,
            fail_puts,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// The loopback base URL of the stub host (e.g. `http://127.0.0.1:54321`) —
    /// goes into the seeded server DID's `WebVHHosting` service endpoint.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fail the next `n` publishes (`PUT /api/dids/{mnemonic}`) with a 500,
    /// then accept again — a transient outage a test can recover from.
    pub fn fail_next_publishes(&self, n: usize) {
        self.fail_puts.store(n, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "webvh")]
impl Drop for StubWebvhHost {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
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
    /// A stub webvh hosting server kept alive for the mock's lifetime when
    /// started via [`start_with_webvh_host`](Self::start_with_webvh_host).
    /// Dropped (shut down) with the `MockVta`.
    #[cfg(feature = "webvh")]
    webvh_host: Option<StubWebvhHost>,
    /// Mediator-backed transports, present only for
    /// [`start_with_transports`](Self::start_with_transports).
    #[cfg(feature = "transport-harness")]
    transports: Option<MockVtaTransports>,
}

/// The mediator + inbound listener behind
/// [`MockVta::start_with_transports`](MockVta::start_with_transports).
#[cfg(feature = "transport-harness")]
struct MockVtaTransports {
    mediator: affinidi_messaging_test_mediator::TestMediatorHandle,
    /// The mediator both of the VTA's advertised services point at. The VTA's
    /// own `did:peer:2` is already on `ctx.vta_did`, so it is not repeated here.
    mediator_did: String,
    /// Cancels [`run_inbound_loop`](crate::messaging::service::run_inbound_loop).
    shutdown: tokio_util::sync::CancellationToken,
    loop_handle: Option<tokio::task::JoinHandle<()>>,
    /// The listener's ATM. Held so `shutdown` can stop its websocket: the
    /// mediator permits one socket per DID, and an abandoned one keeps
    /// auto-reconnecting (vta-sdk #830).
    atm: Arc<affinidi_tdk::messaging::ATM>,
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

    /// The webvh hosting server id registered by
    /// [`start_with_webvh_host`](Self::start_with_webvh_host).
    #[cfg(feature = "webvh")]
    pub const WEBVH_SERVER_ID: &'static str = "stub-webvh";

    /// Like [`start_provisionable`](Self::start_provisionable), but additionally
    /// stands up an in-process [`StubWebvhHost`] and registers a **resolvable**
    /// `did:webvh` hosting server pointing at it — so a server-managed
    /// `create_did_webvh` round-trips against the mock.
    ///
    /// Wiring: the stub host binds a loopback port; a `did:webvh:<scid>:<domain>`
    /// server DID is seeded into the resolver cache with a `WebVHHosting` service
    /// at the host's URL (resolution is in-process, no network); the server is
    /// registered under [`WEBVH_SERVER_ID`](Self::WEBVH_SERVER_ID). Drive a mint
    /// with `create_did_webvh { server_id: Some(MockVta::WEBVH_SERVER_ID), .. }`.
    #[cfg(feature = "webvh")]
    pub async fn start_with_webvh_host() -> MockVta {
        use serde_json::json;

        let host = StubWebvhHost::start().await;
        // A valid-format did:webvh (`<scid>:<domain>`); the domain is cosmetic
        // because resolution is served from the seeded cache, not the network.
        let server_did = "did:webvh:stubscid0000000000000000:webvh-host.test".to_string();
        let server_doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": server_did,
            "service": [{
                "id": format!("{server_did}#webvh"),
                "type": "WebVHHosting",
                "serviceEndpoint": host.base_url(),
            }]
        });

        let opts = TestAppOptions {
            provisionable_vta: true,
            preseed_did_docs: vec![(server_did.clone(), server_doc)],
            webvh_servers: vec![(Self::WEBVH_SERVER_ID.to_string(), server_did)],
            atm: None,
            vta_transport: None,
        };
        let mut mock = Self::serve(build_test_app_with(opts).await).await;
        mock.webvh_host = Some(host);
        mock
    }

    /// Like [`start_provisionable`](Self::start_provisionable), but reachable
    /// over **DIDComm and TSP** as well as REST.
    ///
    /// Stands up an embedded mediator, gives the VTA a `did:peer:2` that
    /// advertises `DIDCommMessaging` *and* `TSPTransport` at it, and runs the
    /// **production** inbound loop
    /// ([`run_inbound_loop`](crate::messaging::service::run_inbound_loop)) — so
    /// a Trust Task arriving on either transport reaches the same
    /// `dispatch_trust_task_core` spine the REST route uses. One websocket
    /// carries both protocols (ADR 0005), which is why this is one constructor
    /// rather than two.
    ///
    /// # Why `did:peer:2`
    ///
    /// The transport a client picks comes from the VTA's DID *document*, and a
    /// `did:key` (what [`start_provisionable`](Self::start_provisionable) uses)
    /// cannot carry a service block — so against that mock a client can only
    /// ever choose REST. A `did:peer:2` encodes its services in the identifier,
    /// so it resolves offline through the cache-sdk's built-in `PeerResolver`
    /// **in the consumer's own resolver**, with nothing seeded and no
    /// resolver-injection seam. That last part is the whole trick: seeding this
    /// mock's resolver would not help a caller in another process, which is the
    /// trap VTI #813 already hit.
    ///
    /// # The size budget
    ///
    /// A `did:peer:2` carries its services in the identifier, and every
    /// resolver refuses one over 1000 bytes. Embedding the mediator's own
    /// 540-byte DID in *both* services blows that (1685) and makes the VTA
    /// unresolvable everywhere, in ways that surface as a websocket timeout on
    /// one side and a `403` on the other. So only the DIDComm service embeds
    /// the mediator DID; `#tsp` points at the mediator's URL. See the
    /// `MAX_DID_BYTES` assertion in the body — it is the guard that keeps a
    /// future service addition from re-breaking this silently.
    ///
    /// ```no_run
    /// # async fn demo() {
    /// use vta_service::test_support::MockVta;
    /// let mock = MockVta::start_with_transports().await;
    /// // Drive discovery + provisioning the way the real bootstrap does —
    /// // `mock.vta_did()` resolves offline to the advertised transports.
    /// mock.shutdown().await;
    /// # }
    /// ```
    #[cfg(feature = "transport-harness")]
    pub async fn start_with_transports() -> MockVta {
        use affinidi_messaging_test_mediator::TestMediator;
        use affinidi_tdk::dids::{
            OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
        };

        affinidi_messaging_test_mediator::install_default_crypto_provider();

        // The mediator first: the VTA's DID embeds the mediator DID in its
        // service blocks, so it cannot be minted until the mediator has one.
        // `register_local_did` closes the resulting cycle — the VTA is
        // registered after it exists, rather than at builder time.
        let mediator = TestMediator::spawn().await.expect("spawn test mediator");
        let mediator_did = mediator.did().to_string();

        // The `accept` list is deliberately empty — see MAX_DID_BYTES below. It
        // costs 32 bytes of a budget that has 20 to spare, and DIDComm v2 is
        // the only thing either side speaks here anyway.
        let didcomm = crate::operations::did_peer::mediator_did_didcomm_service(
            &mediator_did,
            vec![],
            vec![],
        );
        // The TSP counterpart, pointing at the mediator's **URL** rather than
        // its DID. That is the one deviation from the workspace convention
        // (`#tsp`'s serviceEndpoint is the mediator's DID), and it is forced by
        // arithmetic, not preference: the mediator's own DID is 540 bytes, and
        // embedding it twice puts the VTA's `did:peer` at 1685 — past the
        // resolver limit below, unresolvable by anyone. Under that limit a
        // two-service peer can embed a mediator DID at most *once*. The short
        // URL form is what this mediator advertises for its own `#tsp` service,
        // so it is at least a convention already live in the ecosystem.
        //
        // Accepted deliberately, and scoped: this is a test harness, where the
        // point is exercising the dispatch spine over both transports, not
        // modelling how a production VTA advertises itself. A production VTA is
        // a `did:webvh` — services live in the document, there is no size
        // ceiling, and the mediator-DID convention holds there unchanged. Do
        // not read this as licence to emit a URL `#tsp` outside of tests.
        let tsp = PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: mediator.endpoint().to_string(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        };
        let (vta_did, secrets) = crate::operations::did_peer::mint_did_peer_with_services(
            didcomm.into_iter().chain(std::iter::once(tsp)).collect(),
        )
        .expect("mint VTA did:peer");

        // Every `DIDCacheClient` refuses to resolve a DID longer than
        // `max_did_size_in_bytes` (default 1000) — a guard applied *before* any
        // parsing, in `resolve_document`. It bites in two places here, and in
        // neither does it say so:
        //
        //   * our own auth against the mediator fails the whole websocket
        //     connect as a 30s `WebSocket isActive? command timed out`;
        //   * the mediator, resolving us to get our sender key, answers the
        //     challenge response `403 Forbidden` and logs `authcrypt requires
        //     sender public key for decryption`.
        //
        // Raising the limit locally is not a fix: the mediator's resolver is
        // built inside `affinidi-messaging-test-mediator`, which exposes no
        // knob for it, and a *consumer* in another process gets a stock
        // resolver — the offline-resolvability this whole harness exists to
        // provide. So the DID has to fit the stock limit. Assert it up front,
        // where the number is legible, rather than 30 seconds later as a
        // timeout.
        const MAX_DID_BYTES: usize = 1_000;
        assert!(
            vta_did.len() < MAX_DID_BYTES,
            "the VTA's did:peer is {} bytes, over the {MAX_DID_BYTES}-byte stock resolver limit \
             ({}-byte mediator DID). Nothing with a default resolver — this process, the \
             mediator, or a consumer — can resolve it. Shed service metadata, or embed the \
             mediator DID in fewer services.",
            vta_did.len(),
            mediator_did.len(),
        );

        mediator
            .register_local_did(&vta_did)
            .await
            .expect("register the VTA as a local mediator account");
        // The account's *default* ACL is enough to connect and go live —
        // verified by removing the `set_acl(ALLOW_ALL)` that used to sit here
        // and watching this test stay green. That grant was added while the
        // failure was misread as a permission problem; the real cause was the
        // DID size asserted above. `add_user` bundles register + ACL, but mints
        // its own DID; ours has to be minted first because it embeds the
        // mediator's DID.

        let (router, ctx) = build_test_app_with(TestAppOptions {
            provisionable_vta: true,
            vta_transport: Some(VtaTransportIdentity {
                did: vta_did.clone(),
                secrets: secrets.clone(),
                mediator_did: mediator_did.clone(),
            }),
            ..Default::default()
        })
        .await;

        // The listener's own ATM + websocket — separate from `AppState.atm`,
        // which has none (one socket per DID).
        let messaging = crate::messaging::service::build_messaging(
            secrets,
            &vta_did,
            &mediator_did,
            ctx.outbox_ks.clone(),
            ctx.state.did_resolver.as_ref(),
            None,
        )
        .await
        .expect("build VTA messaging over the test mediator");
        let atm = messaging.atm.clone();

        let shutdown = tokio_util::sync::CancellationToken::new();
        let loop_handle = tokio::spawn({
            let (messaging, state, vta_did, mediator_did, shutdown) = (
                Arc::new(messaging),
                ctx.state.clone(),
                vta_did.clone(),
                mediator_did.clone(),
                shutdown.clone(),
            );
            async move {
                crate::messaging::service::run_inbound_loop(
                    messaging,
                    state,
                    vta_did,
                    mediator_did,
                    shutdown,
                )
                .await;
            }
        });

        let mut mock = Self::serve((router, ctx)).await;
        mock.transports = Some(MockVtaTransports {
            mediator,
            mediator_did,
            shutdown,
            loop_handle: Some(loop_handle),
            atm,
        });
        mock
    }

    /// The embedded mediator's DID — both advertised services route through it.
    /// Only present for [`start_with_transports`](Self::start_with_transports).
    #[cfg(feature = "transport-harness")]
    pub fn mediator_did(&self) -> &str {
        &self
            .transports
            .as_ref()
            .expect("mediator_did() requires start_with_transports()")
            .mediator_did
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
            #[cfg(feature = "webvh")]
            webvh_host: None,
            #[cfg(feature = "transport-harness")]
            transports: None,
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

    /// A `VtaClient` that can produce documents this VTA accepts.
    ///
    /// `mint_token` alone stopped being enough once the spine enforced SPEC
    /// §7.2: every dispatched spec declares `recipient` REQUIRED (item 5b) and
    /// 72 of the 109 declare `proof` REQUIRED (item 7a), so a client needs the
    /// key behind the DID its token names. `seed` selects the identity, so a
    /// test wanting two callers asks for two seeds rather than two unrelated
    /// DID strings.
    pub async fn signing_client(
        &self,
        seed: u8,
        role: &str,
        contexts: Vec<String>,
    ) -> vta_sdk::client::VtaClient {
        let vta_did = self.vta_did().to_string();
        let (identity, token) = self
            .ctx
            .mint_signing_identity(seed, role, contexts, &vta_did)
            .await;
        let client = vta_sdk::client::VtaClient::new(self.base_url()).with_identity(identity);
        client.set_token_async(token).await;
        client
    }

    /// Fail the stub host's next `n` publishes with a 500 — simulate a
    /// transient outage so a test can assert the VTA recovers on retry.
    /// Only meaningful for a mock started via [`start_with_webvh_host`].
    #[cfg(feature = "webvh")]
    pub fn fail_next_publishes(&self, n: usize) {
        if let Some(host) = &self.webvh_host {
            host.fail_next_publishes(n);
        }
    }

    /// Test-only corruption: move a version's key handles to the `superseded:`
    /// prefix, reproducing the state a pre-#730 failed-publish loop left — the
    /// key the host's current entry still requires is no longer in the *active*
    /// prefix the resolver searches. Proves the seed-re-derivation recovery
    /// heals a DID the handle cache alone cannot.
    #[cfg(feature = "webvh")]
    pub async fn corrupt_supersede_keys(&self, scid: &str, version_id: &str) {
        crate::operations::did_webvh::webvh_keys::supersede_keys_for_version(
            &self.ctx.keys_ks,
            scid,
            version_id,
        )
        .await
        .expect("supersede keys for test corruption");
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
    ///
    /// For a [`start_with_transports`](Self::start_with_transports) mock this
    /// also stops the inbound loop, the listener's mediator websocket, and the
    /// mediator — **in that order, and not optionally**. Dropping an `ATM`
    /// abandons its websocket task rather than ending it, and an abandoned
    /// socket keeps auto-reconnecting for the rest of the test binary, with
    /// every test adding another (vta-sdk #830).
    pub async fn shutdown(mut self) {
        #[cfg(feature = "transport-harness")]
        if let Some(mut transports) = self.transports.take() {
            transports.shutdown.cancel();
            if let Some(handle) = transports.loop_handle.take() {
                let _ = handle.await;
            }
            transports.atm.graceful_shutdown().await;
            transports.mediator.shutdown();
        }
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
        #[cfg(feature = "transport-harness")]
        if let Some(mut transports) = self.transports.take() {
            // Best-effort only: `Drop` cannot await, so the ATM's websocket
            // cannot be stopped politely here. Cancelling ends the inbound loop
            // and shutting the mediator down makes the abandoned socket's
            // reconnects fail fast instead of looping against a live mediator.
            // Prefer `shutdown().await`, which does stop it properly.
            transports.shutdown.cancel();
            if let Some(handle) = transports.loop_handle.take() {
                handle.abort();
            }
            transports.mediator.shutdown();
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(all(test, feature = "transport-harness"))]
mod transport_harness_tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    /// The point of the whole harness: the mock's DID must advertise both
    /// transports **to a resolver it has never touched**.
    ///
    /// Deliberately resolves through a *fresh* `DIDCacheClient` rather than the
    /// app's own. A `did:peer:2` is self-describing, so the built-in
    /// `PeerResolver` decodes it offline anywhere — which is exactly what lets a
    /// consumer in another process (OpenVTC's bootstrap) discover these
    /// transports with nothing seeded. Seeding the *app's* resolver would prove
    /// nothing about that, and is the trap VTI #813 documented.
    ///
    /// Asserted on the raw document rather than `vta_sdk::provision_client`'s
    /// `resolve_vta` so a failure says whether the *encoding* broke or the
    /// SDK's matcher did.
    /// Encoding only: mint the two-service did:peer and resolve it, with no
    /// mediator, no app, and no websocket in the picture. Separates "the
    /// identifier encodes both services" from "a listener can connect as it",
    /// so a failure in the harness test above is attributable.
    #[tokio::test]
    async fn a_two_service_did_peer_encodes_both_transports() {
        use affinidi_tdk::dids::{
            OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
        };

        let mediator = "did:peer:2.Ez6LSmediator";
        let didcomm = crate::operations::did_peer::mediator_did_didcomm_service(
            mediator,
            vec!["didcomm/v2".to_string()],
            vec![],
        );
        let tsp = PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: mediator.to_string(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        };
        let (did, _secrets) = crate::operations::did_peer::mint_did_peer_with_services(
            didcomm.into_iter().chain(std::iter::once(tsp)).collect(),
        )
        .expect("mint two-service did:peer");

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let resolved = resolver.resolve(&did).await.expect("did:peer resolves");
        let types: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| s.type_.clone().into_iter().collect::<Vec<_>>().join(","))
            .collect();
        let ids: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| format!("{:?}", s.id))
            .collect();
        println!("service types: {types:?}");
        println!("service ids:   {ids:?}");
        assert!(
            types.iter().any(|t| t.contains("DIDCommMessaging")),
            "types {types:?}"
        );
        assert!(
            types.iter().any(|t| t.contains("TSPTransport")),
            "types {types:?}"
        );
    }

    #[tokio::test]
    async fn the_mock_advertises_both_transports_to_a_foreign_resolver() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let mock = MockVta::start_with_transports().await;

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let resolved = resolver
            .resolve(mock.vta_did())
            .await
            .expect("a did:peer resolves offline in any resolver");

        let types: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| s.type_.clone().into_iter().collect::<Vec<_>>().join(","))
            .collect();
        assert!(
            types.iter().any(|t| t.contains("DIDCommMessaging")),
            "expected a DIDCommMessaging service, got {types:?}"
        );
        assert!(
            types.iter().any(|t| t.contains("TSPTransport")),
            "expected a TSPTransport service, got {types:?}"
        );

        mock.shutdown().await;
    }
}

// ── Soft WebAuthn authenticator ──────────────────────────────────────────────

/// A WebAuthn authenticator in software, enough to complete a registration
/// ceremony against this VTA.
///
/// `vta/passkey-vms/enroll-submit` runs `finish_passkey_registration`, which is
/// full WebAuthn verification — the challenge, the RP-ID hash, the flags, and
/// the credential public key all have to line up. There is no way to reach that
/// handler with a hand-written fixture, which is why `enroll-submit` and
/// `revoke` (which needs a verification method that was really enrolled) sat
/// uncovered.
///
/// Attestation format is `none`: it carries no attestation statement, which is
/// what a platform authenticator sends when the RP asks for none, and what this
/// VTA's `finish_passkey_registration` is configured to accept. Producing a
/// packed or TPM statement would prove something about a certificate chain
/// rather than about this service.
pub struct SoftAuthenticator {
    signing_key: p256::ecdsa::SigningKey,
    credential_id: Vec<u8>,
}

/// The members a registration produces, in the shapes `enroll-submit` takes.
pub struct SoftRegistration {
    pub credential_id: String,
    pub public_key_multibase: String,
    pub cose_algorithm: i64,
    pub attestation_object: String,
    pub client_data_json: String,
    pub authenticator_data: String,
}

impl SoftAuthenticator {
    /// Deterministic from `seed`, so a test that wants two authenticators asks
    /// for two seeds and neither has to be written down.
    pub fn new(seed: u8) -> Self {
        let signing_key = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into())
            .expect("a fixed 32-byte scalar is a valid P-256 key");
        Self {
            signing_key,
            credential_id: vec![seed; 32],
        }
    }

    /// Complete a registration for `challenge` (base64url, as the challenge
    /// response carries it).
    pub fn register(&self, rp_id: &str, origin: &str, challenge: &str) -> SoftRegistration {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use sha2::{Digest, Sha256};

        // The COSE_Key the authenticator would have generated. Built as CBOR
        // rather than through a helper because the byte layout is the thing
        // under test: the VTA re-derives its Multikey from exactly these bytes.
        let point = self.signing_key.verifying_key().to_sec1_point(false);
        let cose = ciborium::value::Value::Map(vec![
            // kty: EC2
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            // alg: ES256
            (
                ciborium::value::Value::Integer(3.into()),
                ciborium::value::Value::Integer((-7).into()),
            ),
            // crv: P-256
            (
                ciborium::value::Value::Integer((-1).into()),
                ciborium::value::Value::Integer(1.into()),
            ),
            (
                ciborium::value::Value::Integer((-2).into()),
                ciborium::value::Value::Bytes(point.x().expect("uncompressed point").to_vec()),
            ),
            (
                ciborium::value::Value::Integer((-3).into()),
                ciborium::value::Value::Bytes(point.y().expect("uncompressed point").to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut cose_bytes).expect("COSE key serialises");

        // authData = rpIdHash | flags | signCount | attestedCredentialData
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        // UP (0x01) | UV (0x04) | AT (0x40). AT is what says an attested
        // credential follows; without it the VTA finds no public key at all.
        auth_data.push(0x45);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID: none, for `none` attestation
        auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&cose_bytes);

        let attestation = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".into()),
                ciborium::value::Value::Text("none".into()),
            ),
            (
                ciborium::value::Value::Text("attStmt".into()),
                ciborium::value::Value::Map(vec![]),
            ),
            (
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(auth_data.clone()),
            ),
        ]);
        let mut attestation_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut attestation_bytes)
            .expect("attestation object serialises");

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).expect("client data serialises");

        // Through the VTA's own converter, so the advisory value the producer
        // sends and the authoritative one the VTA re-derives cannot disagree
        // for want of two implementations.
        let (cose_algorithm, public_key_multibase) =
            crate::operations::passkey_vms::multikey::cose_key_to_multikey(&cose_bytes)
                .expect("the COSE key converts to a Multikey");

        SoftRegistration {
            credential_id: B64URL.encode(&self.credential_id),
            public_key_multibase,
            cose_algorithm,
            attestation_object: B64URL.encode(&attestation_bytes),
            client_data_json: B64URL.encode(&client_data_json),
            authenticator_data: B64URL.encode(&auth_data),
        }
    }
}

// ── Held credentials ─────────────────────────────────────────────────────────

/// Mint an SD-JWT-VC and receive it into the vault, as a holder would.
///
/// `credential-exchange/pending/approve` answers a deferred presentation, so it
/// needs a credential that actually satisfies the deferred query — it refuses
/// with "no held credential satisfies the deferred query" otherwise, which is
/// why that task sat uncovered. Seeding a stored row directly would skip the
/// receive path that decides how a credential is indexed, and the DCQL match
/// runs off that index; so this mints and receives rather than writing a row.
///
/// Returns the stored credential's id.
/// `subject_did` must be a holder key this VTA manages: presenting the
/// credential means signing as the holder, and the operation refuses a subject
/// whose key it does not hold. The VTA's own DID is the one a test fixture has.
pub async fn seed_held_credential(
    vault_ks: &KeyspaceHandle,
    vct: &str,
    disclosable_claim: &str,
    subject_did: &str,
) -> String {
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::signer::JwtSigner;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use vta_vault::mint::{MintRequest, mint_sd_jwt_vc};

    /// The issuer. A `did:key`, so the receive path can resolve it without a
    /// network or a resolver fixture.
    struct EddsaSigner {
        key: SigningKey,
        kid: String,
    }
    impl JwtSigner for EddsaSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn key_id(&self) -> Option<&str> {
            Some(&self.kid)
        }
        fn sign_jwt(
            &self,
            header: &serde_json::Value,
            payload: &serde_json::Value,
        ) -> Result<String, SdJwtError> {
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
            let input = format!("{h}.{p}");
            let sig = self.key.sign(input.as_bytes());
            Ok(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            ))
        }
    }

    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let issuer_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer_key.verifying_key().as_bytes());
    let signer = EddsaSigner {
        key: issuer_key,
        kid: format!("{issuer_did}#key-0"),
    };

    let compact = mint_sd_jwt_vc(
        &MintRequest {
            vct,
            issuer_did: &issuer_did,
            subject_did,
            claims: &serde_json::json!({ disclosable_claim: "Alice" }),
            disclosable: &[disclosable_claim],
            iat: 1_700_000_000,
            exp: Some(1_900_000_000),
        },
        &signer,
    )
    .expect("mint the SD-JWT-VC");

    // Nested under `credential_response`, which is where the issue message
    // carries it — a bare `credential` member is refused as "no credential".
    let body = serde_json::from_value(
        serde_json::json!({ "credential_response": { "credential": compact } }),
    )
    .expect("issue body deserialises");
    let cred = crate::operations::credential_exchange::receive_issued_credential(
        vault_ks,
        &body,
        None,
        None,
        chrono::Utc::now(),
    )
    .await
    .expect("receive the issued credential");
    cred.id
}

/// Seed a **holder** key this VTA manages, and return its `did:key`.
///
/// Distinct from the VTA's own signing identity, which is not a holder key:
/// presenting a credential means signing *as the subject*, and
/// `resolve_holder_keys` looks the subject up in the keys keyspace under
/// `{did:key}#{multibase}`. A test that uses `vta_did` as the subject is
/// refused with "holder key … is not managed by this VTA", correctly.
///
/// Derived from the app state's own seed at `derivation_path`, so the record
/// and the key material agree — a record whose public half did not match the
/// seed would resolve and then fail to sign.
pub async fn seed_holder_key(
    state: &crate::server::AppState,
    derivation_path: &str,
    context_id: Option<&str>,
) -> String {
    use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
    use vti_common::slip10::{DerivationPath, ExtendedSigningKey};

    let seed = state
        .seed_store
        .get()
        .await
        .expect("read the seed")
        .expect("an active seed");
    let bip32 = ExtendedSigningKey::from_seed(&seed).expect("seed is a valid BIP-32 root");
    let derived = bip32
        .derive(&derivation_path.parse::<DerivationPath>().expect("a path"))
        .expect("derive");
    let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
        derived.signing_key.verifying_key().as_bytes(),
    );
    let multibase = did.strip_prefix("did:key:").expect("a did:key");
    let key_id = format!("{did}#{multibase}");

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.to_string(),
        key_type: KeyType::Ed25519,
        status: KeyStatus::Active,
        public_key: multibase.to_string(),
        label: None,
        context_id: context_id.map(str::to_string),
        seed_id: None,
        origin: KeyOrigin::Derived,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    state
        .keys_ks
        .insert(crate::keys::store_key(&key_id), &record)
        .await
        .expect("store the holder key record");
    did
}
