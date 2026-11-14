//! The fixtures the key operations' tests share: an in-memory store, a seed,
//! and helpers that mint, export and sign as a given caller.

use super::*;
use crate::auth::AuthClaims;
use crate::contexts::create_context;
use crate::keys::seed_store::SeedStore;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use vti_common::acl::Role;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

/// A mock seed store backed by a Mutex so `set` actually persists.
pub(super) struct MockSeedStore(Mutex<Option<Vec<u8>>>);

impl SeedStore for MockSeedStore {
    fn get(
        &self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, crate::error::AppError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(self.0.lock().await.clone()) })
    }
    fn set(
        &self,
        seed: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), crate::error::AppError>> + Send + '_>>
    {
        let seed = seed.to_vec();
        Box::pin(async move {
            *self.0.lock().await = Some(seed);
            Ok(())
        })
    }
}

/// Helper: open a temp store and return the keyspace handles needed by key operations.
pub(super) struct TestHarness {
    pub(super) keys_ks: KeyspaceHandle,
    pub(super) contexts_ks: KeyspaceHandle,
    pub(super) audit: vta_audit::SharedAuditSink,
    pub(super) imported_ks: KeyspaceHandle,
    pub(super) internal_ks: KeyspaceHandle,
    pub(super) acl_ks: KeyspaceHandle,
    pub(super) sessions_ks: KeyspaceHandle,
    pub(super) seed_store: Arc<dyn SeedStore>,
    pub(super) _dir: tempfile::TempDir,
}

impl TestHarness {
    pub(super) async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&store_config).expect("open store");

        let keys_ks = store.keyspace(crate::keyspaces::KEYS).unwrap();
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        let audit: vta_audit::SharedAuditSink =
            vta_audit::shared_keyspace_sink(store.keyspace(crate::keyspaces::AUDIT).unwrap());
        let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap();
        let internal_ks = store.keyspace(crate::keyspaces::INTERNAL_KEYS).unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let sessions_ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();

        // 32-byte seed; will be expanded to 64 bytes by BIP-32 internally
        let seed_store: Arc<dyn SeedStore> =
            Arc::new(MockSeedStore(Mutex::new(Some(vec![0xABu8; 32]))));

        // Create a test context so create_key can resolve it
        create_context(&contexts_ks, "test-ctx", "Test Context")
            .await
            .expect("create context");

        Self {
            keys_ks,
            contexts_ks,
            audit,
            imported_ks,
            internal_ks,
            acl_ks,
            sessions_ks,
            seed_store,
            _dir: dir,
        }
    }

    /// Admin of `test-ctx` and nothing else — the entitlement that may
    /// impose the export restriction but must not be able to lift it.
    pub(super) fn context_admin_auth(&self) -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkCtxAdmin".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "ctx-admin-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    pub(super) fn super_admin_auth(&self) -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkTestAdmin".to_string(),
            role: Role::Admin,
            allowed_contexts: vec![], // empty = super admin
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }
}

// ── internal (non-extractable) keys ──────────────────────────────

/// An ordinary derived key in `test-ctx` — the scope `context_admin_auth`
/// administers, so the exportability tests exercise a real context admin
/// rather than borrowing super-admin authority.
pub(super) async fn mint_derived(h: &TestHarness, key_id: &str) -> KeyRecord {
    create_key(
        &h.keys_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.seed_store,
        &h.audit,
        &h.acl_ks,
        &h.super_admin_auth(),
        CreateKeyParams {
            internal: false,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: Some(key_id.to_string()),
            mnemonic: None,
            label: None,
            context_id: Some("test-ctx".to_string()),
        },
        "test",
    )
    .await
    .expect("mint derived key");
    h.keys_ks
        .get(keys::store_key(key_id))
        .await
        .expect("read back")
        .expect("the record exists")
}

pub(super) async fn mint_internal(h: &TestHarness, key_id: &str) -> CreateKeyResultBody {
    create_key(
        &h.keys_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.seed_store,
        &h.audit,
        &h.acl_ks,
        &h.super_admin_auth(),
        CreateKeyParams {
            internal: true,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: Some(key_id.to_string()),
            mnemonic: None,
            label: None,
            context_id: None,
        },
        "test",
    )
    .await
    .expect("mint internal key")
}

// ── the export and signing gates, on every channel ───────────────
//
// Phase 0 of the key-roles work: the `key-export` gate used to live in the
// `keys/export-secret` Trust-Task handler alone, so `GET /keys/{id}/secret`
// and DIDComm `get-key-secret` released keys to an admin narrowed without
// it; and `sign` was never checked anywhere. Both now live in the
// operation, and these tests hold them there for every channel a transport
// can state.

/// A sink that keeps what it is given — or refuses everything.
pub(super) struct RecordingSink {
    pub(super) rows: Mutex<Vec<vta_sdk::protocols::audit_management::list::AuditLogEntry>>,
    pub(super) refuse: bool,
}

#[async_trait::async_trait]
impl vta_audit::AuditSink for RecordingSink {
    async fn record(
        &self,
        entry: &vta_sdk::protocols::audit_management::list::AuditLogEntry,
    ) -> Result<(), AppError> {
        if self.refuse {
            return Err(AppError::Internal("audit sink unavailable".into()));
        }
        self.rows.lock().await.push(entry.clone());
        Ok(())
    }
}

pub(super) fn recording_sink(refuse: bool) -> Arc<RecordingSink> {
    Arc::new(RecordingSink {
        rows: Mutex::new(Vec::new()),
        refuse,
    })
}

/// Every channel a caller can state, with the audit name each records.
pub(super) fn every_channel() -> [ExportChannel<'static>; 4] {
    [
        ExportChannel::EndToEnd("didcomm"),
        ExportChannel::Sealed("provision-integration"),
        ExportChannel::Local("cli"),
        ExportChannel::HopByHop("rest"),
    ]
}

/// Store an ACL entry for `auth` — an admin of `test-ctx` narrowed to
/// `capabilities` — so the gates read it, as they do for every live caller.
pub(super) async fn store_narrowed(
    h: &TestHarness,
    auth: &AuthClaims,
    capabilities: Vec<Capability>,
) {
    vti_common::acl::store_acl_entry(
        &h.acl_ks,
        &vti_common::acl::AclEntry::new(&auth.did, auth.role.clone(), "did:key:zRoot")
            .with_contexts(auth.allowed_contexts.clone())
            .with_capabilities(capabilities),
    )
    .await
    .expect("store the caller's entry");
}

pub(super) async fn export(
    h: &TestHarness,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: ExportChannel<'_>,
) -> Result<GetKeySecretResultBody, AppError> {
    get_key_secret(
        &h.keys_ks,
        &h.imported_ks,
        &h.contexts_ks,
        &h.acl_ks,
        &h.seed_store,
        audit,
        auth,
        key_id,
        channel,
    )
    .await
}

pub(super) async fn sign_as(
    h: &TestHarness,
    auth: &AuthClaims,
    key_id: &str,
    domain: SigningDomain,
) -> Result<SignResultBody, AppError> {
    sign_payload(
        &h.keys_ks,
        &h.imported_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.acl_ks,
        &h.seed_store,
        &h.audit,
        auth,
        key_id,
        b"hello",
        &SignAlgorithm::EdDSA,
        domain,
        "test",
    )
    .await
}

// ── Keyring VTI-23: a manager's operations need a capability, not a role ──
//
// "Every operation a manager needs requires the admin role." Minting a key
// is `key-mint`, which an `initiator` holds; releasing one is `key-export`
// (VTI-VTA-003), which only an admin derives — an initiator acts as a key
// through the signing oracle instead (VTI-VTA-002).

/// A caller on `role` scoped to `test-ctx`, with its ACL entry stored so
/// the gates read the entry, as they do for every live caller.
pub(super) async fn scoped_caller(
    h: &TestHarness,
    did: &str,
    role: Role,
    capabilities: Vec<Capability>,
) -> AuthClaims {
    let auth = AuthClaims {
        did: did.to_string(),
        role: role.clone(),
        allowed_contexts: vec!["test-ctx".to_string()],
        session_id: format!("{did}-session"),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    };
    vti_common::acl::store_acl_entry(
        &h.acl_ks,
        &vti_common::acl::AclEntry::new(did, role, "did:key:zRoot")
            .with_contexts(auth.allowed_contexts.clone())
            .with_capabilities(capabilities),
    )
    .await
    .expect("store the caller's entry");
    auth
}

pub(super) async fn create_as(
    h: &TestHarness,
    auth: &AuthClaims,
    context_id: &str,
) -> Result<CreateKeyResultBody, AppError> {
    create_key(
        &h.keys_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.seed_store,
        &h.audit,
        &h.acl_ks,
        auth,
        CreateKeyParams {
            internal: false,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona".into()),
            context_id: Some(context_id.to_string()),
        },
        "test",
    )
    .await
}

// ── keys/sign-sshsig ───────────────────────────────────────────

/// An application of `test-ctx` narrowed to `sign-sshsig` alone — the
/// shape `did-git-sign` is provisioned with.
pub(super) async fn git_signer(h: &TestHarness) -> AuthClaims {
    let auth = AuthClaims {
        did: "did:key:z6MkGitSigner".to_string(),
        role: Role::Application,
        allowed_contexts: vec!["test-ctx".to_string()],
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    };
    store_narrowed(h, &auth, vec![Capability::SignSshsig]).await;
    auth
}

pub(super) async fn sshsig(
    h: &TestHarness,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    message_hash: &[u8],
) -> Result<SignResultBody, SshsigRefusal> {
    sign_sshsig(
        &h.keys_ks,
        &h.imported_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.acl_ks,
        &h.seed_store,
        audit,
        auth,
        key_id,
        &SignAlgorithm::EdDSA,
        "git",
        "sha512",
        64,
        message_hash,
        "test",
    )
    .await
}

// ── keys/sign-jws and keys/sign-csr ───────────────────────────────

pub(super) async fn mint_of_type(h: &TestHarness, key_id: &str, key_type: KeyType) -> KeyRecord {
    create_key(
        &h.keys_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.seed_store,
        &h.audit,
        &h.acl_ks,
        &h.super_admin_auth(),
        CreateKeyParams {
            internal: false,
            key_type,
            derivation_path: None,
            key_id: Some(key_id.to_string()),
            mnemonic: None,
            label: None,
            context_id: Some("test-ctx".to_string()),
        },
        "test",
    )
    .await
    .expect("mint key");
    h.keys_ks
        .get(keys::store_key(key_id))
        .await
        .unwrap()
        .unwrap()
}

/// A community server's verifier: an application of `test-ctx` narrowed
/// to `capabilities`.
pub(super) async fn verifier(h: &TestHarness, capabilities: Vec<Capability>) -> AuthClaims {
    let auth = AuthClaims {
        did: "did:key:z6MkVerifier".to_string(),
        role: Role::Application,
        allowed_contexts: vec!["test-ctx".to_string()],
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    };
    store_narrowed(h, &auth, capabilities).await;
    auth
}

pub(super) async fn jws(
    h: &TestHarness,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    header: serde_json::Value,
    payload: serde_json::Value,
) -> Result<(String, &'static str), ProtocolSignRefusal> {
    sign_jws(
        &h.keys_ks,
        &h.imported_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.acl_ks,
        &h.seed_store,
        audit,
        auth,
        key_id,
        header.as_object().unwrap(),
        crate::operations::sign_formats::JwsPayload::Json(payload.as_object().unwrap()),
        "test",
    )
    .await
}

pub(super) async fn csr(
    h: &TestHarness,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    request: serde_json::Value,
) -> Result<(String, String), ProtocolSignRefusal> {
    use vta_sdk::protocols::key_management::sign_csr::SignCsrPayload;
    let mut request = request;
    request["keyId"] = key_id.into();
    let req: SignCsrPayload = serde_json::from_value(request).expect("a schema-valid request");
    sign_csr(
        &h.keys_ks,
        &h.imported_ks,
        &h.internal_ks,
        &h.contexts_ks,
        &h.acl_ks,
        &h.seed_store,
        audit,
        auth,
        key_id,
        &req.subject,
        req.subject_alt_names.as_ref(),
        "test",
    )
    .await
}

pub(super) fn record_key(record: &KeyRecord) -> vta_sdk::jws::JwsKey {
    vta_sdk::jws::JwsKey::from_did_key(&format!("did:key:{}", record.public_key)).unwrap()
}

/// The SPKI of a VTA-held key, certified by a throwaway CA, as an `x5c`.
pub(super) fn x5c_for(record: &KeyRecord) -> String {
    use crate::operations::sign_formats::{CsrKey, subject_public_key_info};
    let spki = subject_public_key_info(&CsrKey::from_jws_key(&record_key(record)).unwrap());
    let spki = rcgen::SubjectPublicKeyInfo::from_der(&spki).unwrap();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .signed_by(&spki, &issuer)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(leaf.der())
}
