//! Shared test-harness helpers for `vtc-service` — a tempdir-backed
//! [`AppState`], the full `routes::router()`, JWT/session minting, and a
//! [`MockVtc`] listening server a harness can drive over the wire.
//!
//! This is the VTC counterpart to `vta_service::test_support`. Pre-
//! consolidation every integration-test file under `tests/` hand-rolled
//! the same ~140-line fixture (open ~21 keyspaces → build `AppState` →
//! `routes::router().with_state(...)`). The [`TestVtc`] builder collapses
//! that to a few lines at the call site and is the single place a new
//! `AppState` field has to be wired for tests.
//!
//! Gated behind the `test-support` feature *and* `cfg(test)` for the
//! lib's own unit tests. Downstream integration tests (under `tests/`)
//! enable the feature via a `[dev-dependencies]` entry on `vtc-service`.
//!
//! Kept in the production crate (not a sibling `vtc-test-support`) for the
//! same reason as the VTA: every helper closes over crate-private types
//! (`AppState`, `KeyspaceHandle`, `InstallTokenStore`, `LocalSigner`). A
//! sibling crate would force all of them `pub` on the main API surface.

#![cfg(any(test, feature = "test-support"))]

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use tokio::sync::{RwLock, watch};

use crate::config::AppConfig;
use crate::credentials::LocalSigner;
use crate::install::{InstallTokenSigner, InstallTokenStore};
use crate::server::AppState;
use crate::store::Store;
use crate::supervisor::SupervisorKind;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;

/// The default `vtc_did` used by [`TestVtc`] — a sentinel that satisfies
/// the routes which only compare it as a string. Matches the value the
/// pre-consolidation fixtures hard-coded.
pub const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";

/// Deterministic 32-byte JWT signing seed. Stable across runs so tests
/// can pre-mint tokens without round-tripping the auth ceremony.
const JWT_SEED: [u8; 32] = [0x42u8; 32];

/// Deterministic 32-byte Ed25519 seed used to synthesise the credential /
/// install signers when a test opts in. Not the JWT seed — these sign
/// VMC/VEC/install material, JWT seed signs access tokens.
const SIGNER_SEED: [u8; 32] = [0xC5u8; 32];

/// Pin jsonwebtoken's default `CryptoProvider` to `aws_lc` once per
/// process. The workspace compiles `jsonwebtoken` with only the
/// `aws_lc_rs` backend; when `cargo test` unifies features across crates
/// the auto-select panics unless one provider is installed explicitly.
/// Idempotent — safe to call from every test file.
pub fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

/// Builder for a tempdir-backed in-process VTC under test.
///
/// Defaults give the minimal daemon the route tests assumed before this
/// module existed: `vtc_did` set, JWT keys present, no audit writer, no
/// credential/install signer, no `public_url` (so passkey/install routes
/// 503 — opt in via [`with_public_url`](Self::with_public_url)).
pub struct TestVtcBuilder {
    vtc_did: String,
    with_audit: bool,
    with_signers: bool,
    with_did_resolver: bool,
    credential_signer: Option<Arc<LocalSigner>>,
    install_signer: Option<Arc<InstallTokenSigner>>,
    public_url: Option<String>,
    supervisor: Option<SupervisorKind>,
    /// Messaging (ATM) handle wired into `AppState.atm` — lets the DIDComm
    /// credential-delivery push send over a (test) mediator.
    atm: Option<affinidi_tdk::messaging::ATM>,
    /// Mediator DID for `AppState.config.messaging` — paired with `atm` so the
    /// delivery path knows which mediator to forward issued credentials through.
    messaging_mediator: Option<String>,
}

impl Default for TestVtcBuilder {
    fn default() -> Self {
        TestVtcBuilder {
            vtc_did: TEST_VTC_DID.to_string(),
            with_audit: false,
            with_signers: false,
            with_did_resolver: false,
            credential_signer: None,
            install_signer: None,
            public_url: None,
            supervisor: None,
            atm: None,
            messaging_mediator: None,
        }
    }
}

impl TestVtcBuilder {
    /// Override the configured `vtc_did`.
    pub fn vtc_did(mut self, did: impl Into<String>) -> Self {
        self.vtc_did = did.into();
        self
    }

    /// Wire an [`AuditWriter`] so audit-emitting routes don't 503.
    pub fn with_audit(mut self, on: bool) -> Self {
        self.with_audit = on;
        self
    }

    /// Seed a [`LocalSigner`] (credential issuance) and an
    /// [`InstallTokenSigner`] (install ceremony) from a deterministic
    /// Ed25519 seed, so VMC/VEC/status-list and install routes work.
    /// This is the in-process equivalent of having bootstrapped the
    /// VTC's signing bundle from a VTA.
    pub fn with_signers(mut self, on: bool) -> Self {
        self.with_signers = on;
        self
    }

    /// Inject a specific [`LocalSigner`] as the credential signer —
    /// overriding the one [`with_signers`](Self::with_signers) would
    /// derive. Use when a test holds the signer and verifies issued
    /// credentials against it. Does not affect the install signer.
    pub fn with_credential_signer(mut self, signer: Arc<LocalSigner>) -> Self {
        self.credential_signer = Some(signer);
        self
    }

    /// Inject a specific [`InstallTokenSigner`] — overriding the one
    /// [`with_signers`](Self::with_signers) would derive. Use when a test
    /// mints install tokens with a signer it holds and the route must
    /// verify them with the same key.
    pub fn with_install_signer(mut self, signer: Arc<InstallTokenSigner>) -> Self {
        self.install_signer = Some(signer);
        self
    }

    /// Set `public_url`, which builds the WebAuthn relying-party handle
    /// (passkey/install routes need it).
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = Some(url.into());
        self
    }

    /// Attach a local `DIDCacheClient` resolver (the SIOP wallet-login
    /// and cross-community recognition paths resolve presented DIDs
    /// through it).
    pub fn with_did_resolver(mut self, on: bool) -> Self {
        self.with_did_resolver = on;
        self
    }

    /// Inject a cached supervisor probe result (the diagnostics /
    /// restart routes read it).
    pub fn supervisor(mut self, kind: Option<SupervisorKind>) -> Self {
        self.supervisor = kind;
        self
    }

    /// Wire a messaging (ATM) handle into `AppState.atm`, so the DIDComm
    /// handlers and the credential-delivery push (`push_to_holder`) can send
    /// over a mediator. Pair with [`messaging_mediator`](Self::messaging_mediator).
    pub fn with_atm(mut self, atm: affinidi_tdk::messaging::ATM) -> Self {
        self.atm = Some(atm);
        self
    }

    /// Set the mediator DID in `AppState.config.messaging`, so credential
    /// delivery knows which mediator the VTC forwards issued credentials
    /// through. Pair with [`with_atm`](Self::with_atm).
    pub fn messaging_mediator(mut self, mediator_did: impl Into<String>) -> Self {
        self.messaging_mediator = Some(mediator_did.into());
        self
    }

    /// Build the tempdir-backed [`TestVtc`].
    pub async fn build(self) -> TestVtc {
        init_jwt_provider();

        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");

        // Open every keyspace the daemon's `AppState` carries. Keep this
        // list in lockstep with `server::run`'s keyspace block; a missing
        // keyspace fails fast at `build()` (the `.expect` below), and the
        // `AppState { .. }` literal further down won't compile if a field
        // is dropped.
        let sessions_ks = store.keyspace("sessions").expect("sessions ks");
        let acl_ks = store.keyspace("acl").expect("acl ks");
        let community_ks = store.keyspace("community").expect("community ks");
        let config_ks = store.keyspace("config").expect("config ks");
        let passkey_ks = store.keyspace("passkey").expect("passkey ks");
        let install_ks = store.keyspace("install").expect("install ks");
        let members_ks = store.keyspace("members").expect("members ks");
        let join_requests_ks = store.keyspace("join_requests").expect("join_requests ks");
        let policies_ks = store.keyspace("policies").expect("policies ks");
        let active_policies_ks = store
            .keyspace("active_policies")
            .expect("active_policies ks");
        let status_lists_ks = store.keyspace("status_lists").expect("status_lists ks");
        let registry_records_ks = store
            .keyspace("registry_records")
            .expect("registry_records ks");
        let sync_queue_ks = store.keyspace("sync_queue").expect("sync_queue ks");
        let sync_cursor_ks = store.keyspace("sync_cursor").expect("sync_cursor ks");
        let relationships_ks = store.keyspace("relationships").expect("relationships ks");
        let relationships_by_did_ks = store
            .keyspace("relationships_by_did")
            .expect("relationships_by_did ks");
        let endorsement_types_ks = store
            .keyspace("endorsement_types")
            .expect("endorsement_types ks");
        let schemas_ks = store.keyspace("schemas").expect("schemas ks");
        let endorsements_ks = store.keyspace("endorsements").expect("endorsements ks");
        let audit_ks = store.keyspace("audit").expect("audit ks");
        let audit_key_ks = store.keyspace("audit_key").expect("audit_key ks");
        let consumed_invitations_ks = store
            .keyspace("consumed_invitations")
            .expect("consumed_invitations ks");
        let invitations_ks = store.keyspace("invitations").expect("invitations ks");

        let jwt_keys =
            Arc::new(JwtKeys::from_ed25519_bytes(&JWT_SEED, "VTC").expect("build VTC JWT keys"));

        let mut config: AppConfig = toml::from_str(&format!(
            r#"
            vtc_did = "{}"
            [store]
            data_dir = "{}"
            [auth]
            jwt_signing_key = "{}"
            "#,
            self.vtc_did,
            dir.path().display(),
            BASE64.encode(JWT_SEED),
        ))
        .expect("parse test config");
        if let Some(url) = &self.public_url {
            config.public_url = Some(url.clone());
        }
        if let Some(mediator_did) = &self.messaging_mediator {
            config.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: mediator_did.clone(),
                mediator_host: None,
            });
        }

        let audit_writer = if self.with_audit {
            let key_store = AuditKeyStore::new(audit_key_ks.clone());
            key_store
                .ensure_initial(&[0xAB; 64])
                .await
                .expect("init audit key");
            Some(AuditWriter::new(audit_ks.clone(), key_store))
        } else {
            None
        };

        let (mut credential_signer, mut install_signer) = if self.with_signers {
            let signer = Arc::new(LocalSigner::from_ed25519_seed(
                self.vtc_did.clone(),
                &SIGNER_SEED,
            ));
            let install = Arc::new(
                InstallTokenSigner::from_master_seed(&SIGNER_SEED)
                    .expect("derive install token signer"),
            );
            (Some(signer), Some(install))
        } else {
            (None, None)
        };
        // Explicitly-injected signers override the derived ones (used by
        // tests that verify issued credentials / install tokens against a
        // signer they hold).
        if let Some(sig) = self.credential_signer.clone() {
            credential_signer = Some(sig);
        }
        if let Some(sig) = self.install_signer.clone() {
            install_signer = Some(sig);
        }

        let webauthn = match &self.public_url {
            Some(url) => match vti_common::auth::passkey::build_webauthn(url) {
                Ok(w) => Some(Arc::new(w)),
                Err(e) => panic!("build_webauthn({url}): {e}"),
            },
            None => None,
        };

        let did_resolver = if self.with_did_resolver {
            use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .ok()
        } else {
            None
        };

        let install_store = InstallTokenStore::new(install_ks.clone());

        let member_count_cache = Arc::new(std::sync::atomic::AtomicU64::new(
            crate::members::list_members(&members_ks)
                .await
                .expect("seed member count")
                .len() as u64,
        ));

        let state = AppState {
            sessions_ks,
            acl_ks,
            community_ks,
            config_ks,
            passkey_ks,
            install_ks,
            members_ks,
            member_count_cache,
            join_requests_ks,
            policies_ks,
            active_policies_ks,
            status_lists_ks,
            registry_records_ks,
            sync_queue_ks,
            sync_cursor_ks,
            relationships_ks,
            relationships_by_did_ks,
            endorsement_types_ks,
            schemas_ks,
            endorsements_ks,
            audit_ks,
            audit_key_ks,
            consumed_invitations_ks,
            invitations_ks,
            registry_client: None,
            registry_health: crate::registry::RegistryHealth::new(),
            syncer_health: crate::registry::SyncerHealth::new(),
            config: Arc::new(RwLock::new(config)),
            did_resolver,
            secrets_resolver: None,
            jwt_keys: Some(jwt_keys.clone()),
            atm: self.atm,
            webauthn,
            public_url: self.public_url,
            install_signer,
            credential_signer,
            install_store,
            audit_writer,
            shutdown_tx: watch::channel(false).0,
            supervisor: self.supervisor,
            didcomm: Arc::new(tokio::sync::OnceCell::new()),
        };

        let router = crate::routes::router().with_state(state.clone());

        TestVtc {
            router,
            state,
            jwt_keys,
            _dir: dir,
        }
    }
}

/// A tempdir-backed VTC under test: the `routes::router()` (ready for
/// `tower::ServiceExt::oneshot`), the live [`AppState`] (so tests can
/// seed/inspect keyspaces directly), and the JWT keys (so tests can mint
/// their own tokens). Owns the temp data dir — keep it alive for the
/// duration of the test.
pub struct TestVtc {
    /// The assembled router. `tower::ServiceExt::oneshot` it directly, or
    /// rebuild a routing-config variant with `routes::router_with(...)
    /// .with_state(tv.state.clone())`.
    pub router: axum::Router,
    /// The live application state shared with `router`.
    pub state: AppState,
    /// JWT signing keys (audience `"VTC"`) for minting test tokens.
    pub jwt_keys: Arc<JwtKeys>,
    _dir: tempfile::TempDir,
}

impl TestVtc {
    /// Start building a customised VTC.
    pub fn builder() -> TestVtcBuilder {
        TestVtcBuilder::default()
    }

    /// The on-disk data directory backing the store (for tests that read
    /// or write files the daemon persists there, e.g. the `did.jsonl`
    /// publication path).
    pub fn data_dir(&self) -> &std::path::Path {
        self._dir.path()
    }

    /// Mint a bearer token for `did` with `role`, creating the backing
    /// `Authenticated` session row so the `AuthClaims` extractor (which
    /// re-checks session state on every request) accepts it.
    pub async fn token(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: "test".into(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(&self.state.sessions_ks, &session)
            .await
            .expect("store test session");
        let claims = self.jwt_keys.new_claims(
            did.to_string(),
            session_id,
            role.to_string(),
            contexts,
            900,
            false,
        );
        self.jwt_keys.encode(&claims).expect("encode test token")
    }

    /// Convenience: an admin token for the canonical test admin DID.
    pub async fn admin_token(&self) -> String {
        self.token("did:key:z6MkAdmin", "admin", Vec::new()).await
    }
}

/// Build a default tempdir-backed VTC under test (no audit, no signers,
/// no `public_url`). Equivalent to `TestVtc::builder().build()`.
pub async fn build_test_vtc() -> TestVtc {
    TestVtc::builder().build().await
}

/// A **mock VTC** bound to an ephemeral local port — a real, listening
/// HTTP server a harness can drive over the wire, with no setup ceremony.
///
/// Wraps a [`TestVtc`] (with signers + a `public_url` so credential and
/// install routes work) and serves its `routes::router()` on
/// `127.0.0.1:<random-port>`. The server runs in a background task and
/// shuts down when the `MockVtc` is dropped (or via
/// [`shutdown`](Self::shutdown)).
///
/// ```no_run
/// # async fn demo() {
/// use vtc_service::test_support::MockVtc;
/// let mock = MockVtc::start().await;
/// let base = mock.base_url();              // e.g. http://127.0.0.1:54321
/// // … point a client at `base`, or seed rows via `mock.vtc.state` …
/// mock.shutdown().await;
/// # }
/// ```
pub struct MockVtc {
    base_url: String,
    /// The bootstrapped VTC under test (state, keyspaces, JWT keys) so a
    /// harness can seed ACL/member/session rows before driving the API.
    /// Owns the temp data dir — kept alive for the `MockVtc`'s lifetime.
    pub vtc: TestVtc,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl MockVtc {
    /// Start a mock VTC on a random loopback port and return once it is
    /// bound and serving.
    pub async fn start() -> MockVtc {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .with_public_url("http://vtc.test")
            .build()
            .await;
        let router = vtc.router.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("resolve local addr");
        let base_url = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            // `ConnectInfo<SocketAddr>` is required — the unauth routes
            // carry the per-source-IP rate limiter, same as production.
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
        });

        MockVtc {
            base_url,
            vtc,
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

impl Drop for MockVtc {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(feature = "didcomm-harness")]
pub use didcomm_harness::{MockVtcDidcomm, ProblemReport, ReplyOutcome, TestJoinClient};

/// In-process DIDComm join-requests harness (#436).
///
/// [`MockVtcDidcomm`] stands up an embedded `affinidi-messaging-test-mediator`,
/// a VTC DIDComm responder bound to the **real** join-requests handlers, and a
/// ready-connected [`TestJoinClient`] applicant — all sharing the one mediator,
/// the way OpenVTC's e2e drives a community join. A test can then run a genuine
/// `submit → receipt → manifest → status → (admin approve) → VMC-over-DIDComm`
/// round-trip, exercising `submit_inner` / `manifest_inner` / `status_inner` and
/// the credential-delivery push rather than canned responses.
#[cfg(feature = "didcomm-harness")]
mod didcomm_harness {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle};
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::didcomm::Message;
    use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::secrets_resolver::SecretsResolver;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::{Value, json};
    use tokio::sync::{Mutex, oneshot};
    use uuid::Uuid;
    use vta_sdk::protocols::extract_problem_report;

    use crate::server::AppState;
    use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core};

    use super::TestVtc;

    /// Wrap a verb payload into a Trust Task **document** ready to ride a
    /// DIDComm message body: `type` = the verb URI, `issuer` = the authcrypt
    /// sender, `recipient` = the VTC DID (the framework recipient binding),
    /// and a far-future `expiresAt`. Over DIDComm the authcrypt sender
    /// authenticates the holder, so the document carries no `proof`.
    fn wrap_trust_task(typ: &str, issuer: &str, recipient: &str, payload: Value) -> Value {
        json!({
            "type": typ,
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "issuer": issuer,
            "recipient": recipient,
            "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "payload": payload,
        })
    }

    /// `true` if a reply message type names an error envelope — a DIDComm
    /// report-problem (legacy, non-join) or a framework `trust-task-error`
    /// document (the join ceremony's rejection shape).
    fn is_error_reply(typ: &str) -> bool {
        typ.contains("problem-report") || typ.contains("trust-task-error")
    }

    /// Extract `(code, detail)` from either an error envelope shape: a
    /// `trust-task-error` document (`payload.code` / `payload.message`) or a
    /// legacy DIDComm problem-report (`code` / `comment`).
    fn extract_error(typ: &str, body: &Value) -> (String, String) {
        if typ.contains("trust-task-error") {
            let code = body
                .pointer("/payload/code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let msg = body
                .pointer("/payload/message")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            (code, msg)
        } else {
            extract_problem_report(body)
        }
    }

    /// Two DIDComm verification methods: an Ed25519 authentication key and an
    /// X25519 key-agreement key — the shape an authcrypt counterparty needs.
    fn peer_key_roles() -> Vec<(PeerKeyRole, KeyType)> {
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ]
    }

    /// Build an ATM whose secrets resolver holds `secrets` (a `did:peer`'s keys).
    async fn build_atm(secrets: &[Secret]) -> ATM {
        let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("TDK config"))
            .await
            .expect("TDK shared state");
        for s in secrets {
            tdk.secrets_resolver().insert(s.clone()).await;
        }
        ATM::new(
            ATMConfig::builder().build().expect("ATM config"),
            Arc::new(tdk),
        )
        .await
        .expect("ATM init")
    }

    const POLL: Duration = Duration::from_millis(300);

    /// A message the client received but hasn't yet matched to a request.
    struct Received {
        thid: Option<String>,
        typ: String,
        body: Value,
    }

    /// An error envelope the VTC threaded back as a rejection (a framework
    /// `trust-task-error` document, or a legacy DIDComm problem-report), with
    /// its `code`/`comment` already parsed plus the raw body for finer
    /// assertions.
    #[derive(Debug, Clone)]
    pub struct ProblemReport {
        /// The problem-report `code` (e.g. `e.p.msg.bad-request`).
        pub code: String,
        /// The human-readable `comment`.
        pub comment: String,
        /// The raw problem-report body.
        pub body: Value,
    }

    /// The classified outcome of a [`TestJoinClient::try_request`] round trip —
    /// the three buckets a negative/fuzz campaign tells apart.
    #[derive(Debug, Clone)]
    pub enum ReplyOutcome {
        /// A threaded reply that is *not* a problem-report — the request was
        /// accepted; carries the reply body.
        Reply(Value),
        /// A threaded DIDComm problem-report — the VTC rejected the request
        /// cleanly (the expected, healthy behaviour for malformed input).
        Problem(ProblemReport),
        /// No threaded reply (nor problem-report) arrived within the timeout —
        /// the signal a fuzzer treats as a potential hang/crash.
        Timeout,
    }

    /// A DIDComm join applicant connected to the harness mediator.
    ///
    /// Sends authcrypt requests to the VTC and awaits the threaded reply;
    /// unsolicited inbound (e.g. a pushed credential) is buffered and drained via
    /// [`next_pushed`](Self::next_pushed).
    pub struct TestJoinClient {
        atm: ATM,
        profile: Arc<ATMProfile>,
        did: String,
        mediator_did: String,
        /// A standalone holder signing key for building demo `vp_token`s via
        /// `vta_sdk::vp` — its `id` is a `did:key`.
        holder_secret: Secret,
        inbox: Mutex<VecDeque<Received>>,
        /// When set (the default), [`recv_matching`](Self::recv_matching) panics
        /// on any inbound problem-report — the right ergonomics for a happy-path
        /// test, where an unexpected rejection should abort loudly. A
        /// negative/fuzz campaign clears it for the duration of a
        /// [`try_request`](Self::try_request) call so a clean rejection is
        /// *returned* (classified) instead of aborting the run.
        panic_on_problem_report: AtomicBool,
    }

    impl TestJoinClient {
        async fn connect(
            transport_secrets: &[Secret],
            did: String,
            mediator_did: String,
            holder_secret: Secret,
        ) -> Self {
            let atm = build_atm(transport_secrets).await;
            let profile = Arc::new(
                ATMProfile::new(&atm, None, did.clone(), Some(mediator_did.clone()))
                    .await
                    .expect("applicant ATM profile"),
            );
            atm.profile_enable_websocket(&profile)
                .await
                .expect("applicant websocket");
            TestJoinClient {
                atm,
                profile,
                did,
                mediator_did,
                holder_secret,
                inbox: Mutex::new(VecDeque::new()),
                panic_on_problem_report: AtomicBool::new(true),
            }
        }

        /// The applicant's DIDComm (`did:peer`) identity — the authcrypt sender
        /// the VTC sees as the join applicant.
        pub fn did(&self) -> &str {
            &self.did
        }

        /// A holder signing key (`did:key`) for assembling a `vp_token` from a
        /// manifest's DCQL via `vta_sdk::vp::build_vp_token`.
        pub fn holder_secret(&self) -> &Secret {
            &self.holder_secret
        }

        /// Send `body` as a `typ` DIDComm message to `vtc_did` (authcrypt,
        /// forwarded via the mediator) and return the threaded reply body.
        /// Panics on timeout *or* a problem-report — this is the happy-path
        /// helper. Use [`try_request`](Self::try_request) for a negative/fuzz
        /// campaign that needs to keep going past a (correct) rejection.
        pub async fn request(&self, vtc_did: &str, typ: &str, body: Value) -> Value {
            match self
                .try_request(vtc_did, typ, body, Duration::from_secs(15))
                .await
            {
                ReplyOutcome::Reply(body) => body,
                ReplyOutcome::Problem(p) => {
                    panic!("applicant received problem-report: {}", p.body)
                }
                ReplyOutcome::Timeout => panic!("no reply to `{typ}` within timeout"),
            }
        }

        /// Like [`request`](Self::request) but **non-panicking**: send `body` as
        /// a `typ` message and *classify* the threaded outcome into the three
        /// buckets a negative/fuzz campaign cares about — a clean accept
        /// ([`ReplyOutcome::Reply`]), a clean DIDComm rejection
        /// ([`ReplyOutcome::Problem`]), or no threaded reply within `timeout`
        /// ([`ReplyOutcome::Timeout`], the signal for a hang/crash). This lets a
        /// fuzzer run thousands of mutations per boot without aborting on the
        /// first (correct) problem-report.
        ///
        /// Both a normal reply and a problem-report are threaded to this
        /// request's id (the messaging framework's problem-report carries
        /// `thid = <request id>`), so the same thread-correlation predicate
        /// catches either; the reply `typ` is what distinguishes them.
        pub async fn try_request(
            &self,
            vtc_did: &str,
            typ: &str,
            body: Value,
            timeout: Duration,
        ) -> ReplyOutcome {
            let req_id = Uuid::new_v4().to_string();
            // Wrap the verb payload into a Trust Task document addressed to the
            // VTC; the DIDComm message `type` mirrors the document `type`.
            let doc = wrap_trust_task(typ, &self.did, vtc_did, body);
            let msg = Message::build(req_id.clone(), typ.to_string(), doc)
                .from(self.did.clone())
                .to(vtc_did.to_string())
                .finalize();
            self.send(&msg, vtc_did).await;

            // Suppress recv_matching's happy-path panic for this round trip so a
            // problem-report is buffered/matched like any reply and classified
            // below, then restore the prior setting for any later happy-path call
            // on this client.
            let prev = self.panic_on_problem_report.swap(false, Ordering::SeqCst);
            let received = self
                .recv_matching(|r| r.thid.as_deref() == Some(req_id.as_str()), timeout)
                .await;
            self.panic_on_problem_report.store(prev, Ordering::SeqCst);

            match received {
                Some(r) if is_error_reply(&r.typ) => {
                    let (code, comment) = extract_error(&r.typ, &r.body);
                    ReplyOutcome::Problem(ProblemReport {
                        code,
                        comment,
                        body: r.body,
                    })
                }
                Some(r) => ReplyOutcome::Reply(r.body),
                None => ReplyOutcome::Timeout,
            }
        }

        /// Await the next unsolicited inbound message (no thread correlation),
        /// e.g. a pushed `credential-exchange/issue`. `None` on timeout.
        pub async fn next_pushed(&self, timeout: Duration) -> Option<(String, Value)> {
            self.recv_matching(|r| r.thid.is_none(), timeout)
                .await
                .map(|r| (r.typ, r.body))
        }

        async fn send(&self, msg: &Message, to: &str) {
            let (jwe, _) = self
                .atm
                .pack_encrypted(msg, to, Some(&self.did), Some(&self.did))
                .await
                .expect("pack_encrypted");
            self.atm
                .forward_and_send_message(
                    &self.profile,
                    false,
                    &jwe,
                    Some(&msg.id),
                    &self.mediator_did,
                    to,
                    None,
                    None,
                    false,
                )
                .await
                .expect("forward_and_send_message");
        }

        /// Return the first message (buffered or freshly received) matching
        /// `pred`, buffering non-matches; `None` once `timeout` elapses.
        async fn recv_matching<F: Fn(&Received) -> bool>(
            &self,
            pred: F,
            timeout: Duration,
        ) -> Option<Received> {
            if let Some(found) = self.take_buffered(&pred).await {
                return Some(found);
            }
            let start = tokio::time::Instant::now();
            while start.elapsed() < timeout {
                let next = self
                    .atm
                    .message_pickup()
                    .live_stream_next(&self.profile, Some(POLL), true)
                    .await;
                if let Ok(Some((msg, _meta))) = next {
                    if is_error_reply(&msg.typ)
                        && self.panic_on_problem_report.load(Ordering::SeqCst)
                    {
                        // Happy-path ergonomics: surface the problem loudly rather
                        // than silently buffering it. `try_request` clears the flag
                        // so a negative/fuzz campaign classifies it instead.
                        panic!("applicant received problem-report: {}", msg.body);
                    }
                    let r = Received {
                        thid: msg.thid.clone(),
                        typ: msg.typ.clone(),
                        body: msg.body.clone(),
                    };
                    if pred(&r) {
                        return Some(r);
                    }
                    self.inbox.lock().await.push_back(r);
                }
            }
            None
        }

        async fn take_buffered<F: Fn(&Received) -> bool>(&self, pred: &F) -> Option<Received> {
            let mut inbox = self.inbox.lock().await;
            let pos = inbox.iter().position(pred)?;
            inbox.remove(pos)
        }
    }

    /// A mock VTC serving the join-requests protocol over DIDComm, plus a
    /// connected applicant client. See module docs.
    pub struct MockVtcDidcomm {
        mediator: TestMediatorHandle,
        vtc_did: String,
        /// The VTC under test (state + router): seed policies / status-lists /
        /// Accepts criteria and drive admin actions (e.g. approve) over REST.
        pub vtc: TestVtc,
        /// The connected applicant.
        pub client: TestJoinClient,
        shutdown_tx: Option<oneshot::Sender<()>>,
        loop_handle: Option<tokio::task::JoinHandle<()>>,
    }

    impl MockVtcDidcomm {
        /// Spin up the mediator, the DIDComm-listening VTC (signers + audit +
        /// messaging wired), and a connected applicant. Returns once everything
        /// is bound and the dispatch loop is running.
        pub async fn start() -> MockVtcDidcomm {
            // Transport identities. The applicant's is generated up front so it
            // can be registered LOCAL on the mediator (needed to open inbound).
            let (vtc_did, vtc_secrets) =
                DID::generate_did_peer(peer_key_roles(), None).expect("VTC did:peer");
            let (applicant_did, applicant_secrets) =
                DID::generate_did_peer(peer_key_roles(), None).expect("applicant did:peer");

            let mediator = TestMediator::builder()
                .local_did(vtc_did.clone())
                .local_did(applicant_did.clone())
                .spawn()
                .await
                .expect("spawn test mediator");
            let mediator_did = mediator.did().to_string();

            // VTC messaging side: an ATM holding the VTC transport keys, a
            // profile + inbound websocket on the shared mediator.
            let vtc_atm = build_atm(&vtc_secrets).await;
            let vtc_profile = Arc::new(
                ATMProfile::new(&vtc_atm, None, vtc_did.clone(), Some(mediator_did.clone()))
                    .await
                    .expect("VTC ATM profile"),
            );
            vtc_atm
                .profile_enable_websocket(&vtc_profile)
                .await
                .expect("VTC websocket");

            // VTC state: the transport did:peer is also the configured `vtc_did`
            // (so credential delivery packs from a resolvable sender), with the
            // ATM + mediator wired so `push_to_holder` can forward issued VMCs.
            let vtc = TestVtc::builder()
                .vtc_did(vtc_did.clone())
                .with_audit(true)
                .with_signers(true)
                .with_public_url("https://vtc.test")
                .messaging_mediator(mediator_did.clone())
                .with_atm(vtc_atm.clone())
                .build()
                .await;

            // A standalone did:key holder key for the applicant's VP demos.
            let holder_secret = generate_holder_secret();
            let client = TestJoinClient::connect(
                &applicant_secrets,
                applicant_did,
                mediator_did.clone(),
                holder_secret,
            )
            .await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let state = vtc.state.clone();
            let loop_did = vtc_did.clone();
            let loop_handle = tokio::spawn(async move {
                run_vtc_join_loop(
                    vtc_atm,
                    vtc_profile,
                    mediator_did,
                    loop_did,
                    state,
                    shutdown_rx,
                )
                .await;
            });

            MockVtcDidcomm {
                mediator,
                vtc_did,
                vtc,
                client,
                shutdown_tx: Some(shutdown_tx),
                loop_handle: Some(loop_handle),
            }
        }

        /// The VTC's DIDComm identity — address join messages here.
        pub fn vtc_did(&self) -> &str {
            &self.vtc_did
        }

        /// The shared mediator's DID.
        pub fn mediator_did(&self) -> &str {
            self.mediator.did()
        }

        /// Stop the dispatch loop + mediator and wait for a clean wind-down.
        pub async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = self.loop_handle.take() {
                let _ = handle.await;
            }
            self.mediator.shutdown();
            let _ = self.mediator.join().await;
        }
    }

    /// A `did:key` Ed25519 signing `Secret` (id = `did:key:z..#z..`) for the
    /// applicant to sign demo presentations with.
    fn generate_holder_secret() -> Secret {
        let mut secret = Secret::generate_ed25519(None, None);
        let pub_mb = secret
            .get_public_keymultibase()
            .expect("holder pubkey multibase");
        secret.id = format!("did:key:{pub_mb}#{pub_mb}");
        secret
    }

    /// The VTC dispatch loop: receive → call the real handler → reply, until
    /// shutdown. Mirrors the e2e responder's two-hop reply path (authcrypt the
    /// inner reply to the applicant, forward through the mediator).
    async fn run_vtc_join_loop(
        atm: ATM,
        profile: Arc<ATMProfile>,
        mediator_did: String,
        vtc_did: String,
        state: AppState,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }
            let next = atm
                .message_pickup()
                .live_stream_next(&profile, Some(POLL), true)
                .await;
            let Ok(Some((msg, _meta))) = next else {
                continue;
            };
            if msg.typ.contains("problem-report")
                || msg.typ == "https://didcomm.org/routing/2.0/forward"
            {
                continue;
            }
            let Some(sender) = msg.from.clone() else {
                continue;
            };

            // Drive the real Trust Task dispatcher: the message body is the
            // Trust Task document, the authcrypt sender is the proven holder.
            // The reply document is self-describing (its own `type` — a
            // `#response` or a `trust-task-error`).
            let Some((reply_type, reply_body)) = dispatch_join(&state, &sender, &msg).await else {
                continue;
            };

            let reply_id = Uuid::new_v4().to_string();
            let reply_msg = Message::build(reply_id.clone(), reply_type, reply_body)
                .from(vtc_did.clone())
                .to(sender.clone())
                .thid(msg.id.clone())
                .finalize();
            let Ok((inner_jwe, _)) = atm
                .pack_encrypted(&reply_msg, &sender, Some(&vtc_did), Some(&vtc_did))
                .await
            else {
                continue;
            };
            let _ = atm
                .forward_and_send_message(
                    &profile,
                    false,
                    &inner_jwe,
                    Some(&reply_id),
                    &mediator_did,
                    &sender,
                    None,
                    None,
                    false,
                )
                .await;
        }
        atm.graceful_shutdown().await;
    }

    /// Dispatch an inbound join Trust Task document through the **real**
    /// [`dispatch_trust_task_core`] (the same spine the production DIDComm
    /// handler uses) and return the `(reply_type, reply_document)` to thread
    /// back. The reply document is self-describing — a `#response` on success
    /// or a `trust-task-error` on rejection — so there is no separate error
    /// channel. `None` only if the reply document can't be parsed.
    async fn dispatch_join(
        state: &AppState,
        sender: &str,
        msg: &Message,
    ) -> Option<(String, Value)> {
        let bytes = serde_json::to_vec(&msg.body).ok()?;
        let ctx = JoinAuthCtx::didcomm(sender.to_string());
        let outcome = dispatch_trust_task_core(state, &ctx, &bytes).await;
        let doc: Value = serde_json::from_slice(&outcome.body).ok()?;
        let typ = doc
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("https://trusttasks.org/spec/trust-task-error/0.1")
            .to_string();
        Some((typ, doc))
    }
}
