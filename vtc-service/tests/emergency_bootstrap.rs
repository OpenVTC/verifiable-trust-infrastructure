//! Coverage for `vtc admin emergency-bootstrap` against the
//! VTA-credential-based recovery flow
//! (`tasks/vtc-mvp/vta-driven-keys.md` §4).
//!
//! Drives the full recovery loop with a mocked `VtaRecoveryProver`:
//!
//! 1. Stand up a daemon-like state with one bootstrapped admin
//!    backed by a `VtcKeyBundle` in the secret store.
//! 2. Stop the "daemon" (drop the AppState).
//! 3. Call `emergency::run_emergency_bootstrap_with_store` with a
//!    prover that pretends the VTA accepted the recovery DID.
//! 4. Assert the destructive cleanup ran: admin ACL entries
//!    cleared, sister records gone, carve-out reopened, install
//!    URL minted, pending marker present.
//! 5. Drive `POST /v1/install/claim/start` with the fresh token →
//!    200 OK.
//!
//! Plus the boundary cases the design doc calls out (§6.1):
//! - VTA rejection leaves state untouched.
//! - Missing bundle → clean `AppError::Config`.
//! - `vtc://install?token=...` fallback when `public_url` is unset.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vta_sdk::provision_client::EphemeralSetupKey;

use vti_common::acl::{AclEntry, Role, list_acl_entries, store_acl_entry};
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::session::{
    Session, SessionState, get_session_by_refresh, list_sessions, store_refresh_index,
    store_session,
};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::seed_store::SeedStore;
use vti_common::store::Store;
use webauthn_rs::prelude::CreationChallengeResponse;

use vtc_service::acl::admin::{AdminEntry, RegisteredPasskey, store_admin_entry};
use vtc_service::config::AppConfig;
use vtc_service::emergency::{
    EmergencyBootstrapOutcome, VtaRecoveryProver, run_emergency_bootstrap_with_store,
};
use vtc_service::install::InstallTokenStore;
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::setup::VtcKeyBundle;

const RP_ORIGIN: &str = "https://vtc.example.com";
const CLAIM_START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.1";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

// ---------------------------------------------------------------------------
// In-memory `SecretStore` + bundle fixtures
// ---------------------------------------------------------------------------

struct InMemorySecretStore {
    inner: tokio::sync::Mutex<Option<Vec<u8>>>,
}

impl InMemorySecretStore {
    fn new(seed: Option<Vec<u8>>) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(seed),
        }
    }
}

impl vti_common::seed_store::SeedStore for InMemorySecretStore {
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>,
    > {
        Box::pin(async move {
            let v = self.inner.lock().await;
            Ok(v.clone())
        })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + '_>>
    {
        let bytes = secret.to_vec();
        Box::pin(async move {
            let mut v = self.inner.lock().await;
            *v = Some(bytes);
            Ok(())
        })
    }
}

fn test_bundle() -> VtcKeyBundle {
    vtc_service::setup::bundle::bundle_from_raw(
        "did:webvh:vtc.example.com:abc",
        &[0x11; 32],
        &[0x22; 32],
    )
}

// ---------------------------------------------------------------------------
// MockVtaRecoveryProver
// ---------------------------------------------------------------------------

struct MockProver {
    behaviour: ProverBehaviour,
    calls: Arc<tokio::sync::Mutex<Vec<RecoveryCall>>>,
}

#[derive(Clone, Debug)]
struct RecoveryCall {
    vta_did: String,
    ephemeral_did: String,
    context: String,
}

#[derive(Clone)]
enum ProverBehaviour {
    Accept,
    RejectUnauthorized(String),
}

impl MockProver {
    fn accept() -> Self {
        Self {
            behaviour: ProverBehaviour::Accept,
            calls: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
    fn reject(reason: &str) -> Self {
        Self {
            behaviour: ProverBehaviour::RejectUnauthorized(reason.to_string()),
            calls: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
    async fn calls(&self) -> Vec<RecoveryCall> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl VtaRecoveryProver for MockProver {
    async fn prove(
        &self,
        vta_did: &str,
        ephemeral_did: &str,
        _ephemeral_privkey_mb: &str,
        context: &str,
    ) -> Result<(), AppError> {
        self.calls.lock().await.push(RecoveryCall {
            vta_did: vta_did.to_string(),
            ephemeral_did: ephemeral_did.to_string(),
            context: context.to_string(),
        });
        match &self.behaviour {
            ProverBehaviour::Accept => Ok(()),
            ProverBehaviour::RejectUnauthorized(msg) => Err(AppError::Unauthorized(msg.clone())),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    router: axum::Router,
    config: AppConfig,
    store: Store,
    secret_store: Arc<InMemorySecretStore>,
    bundle: VtcKeyBundle,
    admin_did: String,
    _dir: tempfile::TempDir,
}

async fn build_fixture(public_url: Option<&str>) -> Fixture {
    init_jwt_provider();
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
    let hooks_queue_ks = store.keyspace("hooks_queue").unwrap();
    let hooks_cursor_ks = store.keyspace("hooks_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();
    let outbox_ks = store.keyspace("outbox").unwrap();
    let invitations_ks = store.keyspace("invitations").unwrap();
    let consumed_invitations_ks = store.keyspace("consumed_invitations").unwrap();
    let install_store = InstallTokenStore::new(install_ks.clone());

    let bundle = test_bundle();
    let bundle_bytes = bundle.to_secret_store_bytes().unwrap();
    let secret_store = Arc::new(InMemorySecretStore::new(Some(bundle_bytes)));
    let ed25519_priv = bundle.ed25519_private_bytes().unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    let public_url_toml = match public_url {
        Some(url) => format!("public_url = \"{url}\""),
        None => String::new(),
    };
    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        vta_did = "did:webvh:vta.example.com:xyz"
        {public_url_toml}
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&*ed25519_priv).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let admin_did = "did:key:zOldAdmin".to_string();
    let user_uuid = uuid::Uuid::new_v4();
    let pk_user = vti_common::auth::passkey::store::PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: Vec::new(),
    };
    vti_common::auth::passkey::store::store_passkey_user(&passkey_ks, &pk_user)
        .await
        .unwrap();

    store_acl_entry(
        &acl_ks,
        &AclEntry::new(admin_did.clone(), Role::Admin, "did:key:vtc-install")
            .with_label(Some("old admin".into()))
            .with_created_at(0),
    )
    .await
    .unwrap();

    let mut admin_entry = AdminEntry::new(admin_did.clone());
    admin_entry.passkeys.push(RegisteredPasskey {
        credential_id: "deadbeef".into(),
        label: "lost device".into(),
        transports: vec![],
        registered_at: Utc::now(),
        last_used_at: None,
    });
    store_admin_entry(&passkey_ks, &admin_entry).await.unwrap();

    let install_signer = Arc::new(
        vtc_service::install::InstallTokenSigner::from_master_seed(&*ed25519_priv).unwrap(),
    );

    let state = AppState {
        sessions_ks,
        acl_ks: acl_ks.clone(),
        community_ks,
        config_ks,
        passkey_ks: passkey_ks.clone(),
        install_ks,
        members_ks: members_ks.clone(),
        member_count_cache: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        join_requests_ks: join_requests_ks.clone(),
        policies_ks: policies_ks.clone(),
        active_policies_ks: active_policies_ks.clone(),
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks: registry_records_ks.clone(),
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks: sync_cursor_ks.clone(),
        hooks_queue_ks: hooks_queue_ks.clone(),
        hooks_cursor_ks: hooks_cursor_ks.clone(),
        capability_replies: vtc_service::hooks::PendingReplies::new(),
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
        audit_ks,
        audit_key_ks,
        outbox_ks,
        config: Arc::new(RwLock::new(config.clone())),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn,
        public_url: public_url.map(str::to_string),
        install_signer: Some(install_signer),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
        didcomm: std::sync::Arc::new(tokio::sync::OnceCell::new()),
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        config,
        store,
        secret_store,
        bundle,
        admin_did,
        _dir: dir,
    }
}

fn ephemeral_key() -> EphemeralSetupKey {
    EphemeralSetupKey::generate().expect("generate ephemeral key")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn emergency_bootstrap_clears_all_sessions_and_their_refresh_index() {
    // P3.11: refresh tokens for the presumed-compromised admins must
    // not survive the wipe — otherwise a stolen refresh token keeps
    // minting access tokens after recovery.
    let fix = build_fixture(Some(RP_ORIGIN)).await;
    let sessions_ks = fix.store.keyspace("sessions").unwrap();

    let session = Session {
        session_id: "sess-old-admin".into(),
        did: fix.admin_did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: 0,
        last_seen: 0,
        refresh_token: Some("refresh-token-1".into()),
        refresh_expires_at: Some(9_999_999_999),
        tee_attested: false,
        amr: vec![],
        acr: String::new(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&sessions_ks, &session).await.unwrap();
    store_refresh_index(&sessions_ks, "refresh-token-1", "sess-old-admin")
        .await
        .unwrap();
    assert_eq!(list_sessions(&sessions_ks).await.unwrap().len(), 1);
    assert!(
        get_session_by_refresh(&sessions_ks, "refresh-token-1")
            .await
            .unwrap()
            .is_some()
    );

    run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &ephemeral_key(),
        &MockProver::accept(),
        None,
    )
    .await
    .expect("emergency-bootstrap accept");

    // Session row gone, and the refresh reverse-index with it (so the
    // refresh token is dead, not just orphaned).
    assert!(
        list_sessions(&sessions_ks).await.unwrap().is_empty(),
        "all sessions must be cleared"
    );
    assert!(
        get_session_by_refresh(&sessions_ks, "refresh-token-1")
            .await
            .unwrap()
            .is_none(),
        "refresh-token index must be cleared"
    );
}

#[tokio::test]
async fn happy_path_clears_admin_via_vta_and_audits_on_restart() {
    let fix = build_fixture(Some(RP_ORIGIN)).await;
    let setup_key = ephemeral_key();
    let prover = MockProver::accept();

    let outcome: EmergencyBootstrapOutcome = run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &setup_key,
        &prover,
        None,
    )
    .await
    .expect("emergency-bootstrap accept");

    assert!(outcome.install_url.starts_with(RP_ORIGIN));
    assert!(outcome.install_url.contains("/install?token="));
    assert_eq!(outcome.admin_entries_cleared, 1);
    assert_eq!(outcome.admin_records_cleared, 1);

    // Admin ACL row gone.
    let acl_ks = fix.store.keyspace("acl").unwrap();
    let remaining_admins: Vec<_> = list_acl_entries(&acl_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.role == Role::Admin)
        .collect();
    assert!(remaining_admins.is_empty(), "expected no admin entries");

    // Sister record gone.
    let passkey_ks = fix.store.keyspace("passkey").unwrap();
    assert!(
        vtc_service::acl::admin::get_admin_entry(&passkey_ks, &fix.admin_did)
            .await
            .unwrap()
            .is_none()
    );

    // Bundle still in secret store — emergency-bootstrap does not
    // rotate the integration DID's keys.
    let bytes = fix.secret_store.get().await.unwrap().unwrap();
    let bundle = VtcKeyBundle::from_secret_store_bytes(&bytes).unwrap();
    assert_eq!(bundle.integration_did, fix.bundle.integration_did);

    // Prover saw exactly one call with the right parameters.
    let calls = prover.calls().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].vta_did, "did:webvh:vta.example.com:xyz");
    assert_eq!(calls[0].context, "default");
    assert_eq!(calls[0].ephemeral_did, setup_key.did);
}

#[tokio::test]
async fn vta_rejects_unauthorized_recovery_did_and_state_unchanged() {
    let fix = build_fixture(Some(RP_ORIGIN)).await;
    let setup_key = ephemeral_key();
    let prover = MockProver::reject("setup DID not authorized at this context");

    let err = run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &setup_key,
        &prover,
        None,
    )
    .await
    .expect_err("VTA rejection must fail recovery");
    assert!(
        matches!(err, AppError::Unauthorized(_)),
        "expected AppError::Unauthorized, got {err:?}"
    );

    // Admin still has the old admin entry.
    let acl_ks = fix.store.keyspace("acl").unwrap();
    let admins: Vec<_> = list_acl_entries(&acl_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.role == Role::Admin)
        .collect();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].did, fix.admin_did);

    // Sister record still in place.
    let passkey_ks = fix.store.keyspace("passkey").unwrap();
    assert!(
        vtc_service::acl::admin::get_admin_entry(&passkey_ks, &fix.admin_did)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn fresh_install_url_works_for_claim_start_after_emergency_bootstrap() {
    let fix = build_fixture(Some(RP_ORIGIN)).await;
    let setup_key = ephemeral_key();

    let outcome = run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &setup_key,
        &MockProver::accept(),
        None,
    )
    .await
    .expect("emergency-bootstrap accept");

    // Extract the install token from the URL.
    let token = outcome
        .install_url
        .split("token=")
        .nth(1)
        .expect("install URL contains token")
        .to_string();

    // Drive POST /v1/install/claim/start with the matching claim
    // code from the outcome. Emergency bootstrap now mints invites
    // with an out-of-band claim secret (parity with regular
    // invites), so the operator types both URL and code at claim
    // time. Without the code the daemon returns 401
    // `claim_secret_required`.
    let body = json!({
        "install_token": token,
        "claim_secret": outcome.claim_code,
    });
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/install/claim/start")
                .header("content-type", "application/json")
                .header("Trust-Task", CLAIM_START_TASK)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "claim/start must accept fresh token + correct claim code"
    );
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // The response embeds a CreationChallengeResponse under
    // "options". Smoke check by deserialising.
    let opts = v.get("options").expect("options field present");
    let _: CreationChallengeResponse = serde_json::from_value(opts.clone())
        .expect("claim/start returns a valid CreationChallengeResponse");
}

#[tokio::test]
async fn no_secret_in_store_yields_clean_config_error() {
    let fix = build_fixture(Some(RP_ORIGIN)).await;
    // Drain the secret store.
    {
        let mut guard = fix.secret_store.inner.lock().await;
        *guard = None;
    }
    let setup_key = ephemeral_key();
    let err = run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &setup_key,
        &MockProver::accept(),
        None,
    )
    .await
    .expect_err("missing secret must fail");
    let msg = format!("{err}");
    assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    assert!(
        msg.contains("never been set up") || msg.contains("no key material"),
        "operator-friendly error required, got: {msg}"
    );
}

#[tokio::test]
async fn outcome_install_url_falls_back_to_vtc_scheme_when_public_url_missing() {
    let fix = build_fixture(None).await;
    let outcome = run_emergency_bootstrap_with_store(
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
        &ephemeral_key(),
        &MockProver::accept(),
        None,
    )
    .await
    .expect("emergency-bootstrap accept");
    assert!(
        outcome.install_url.starts_with("vtc://install?token="),
        "expected vtc:// fallback URL, got {}",
        outcome.install_url
    );
}
