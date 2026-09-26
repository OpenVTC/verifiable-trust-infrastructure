//! Minimal in-memory test fixtures for the backup crate's unit tests.
//!
//! A slimmed copy of `vta-service`'s `test_support`, holding only the pieces
//! the backup tests need (the store/keyspaces the export/import path touches, a
//! default `AppConfig`, a super-admin `AuthClaims`, and a trivial `SeedStore`).
//! Kept here so the tests do not have to depend on `vta-service` (which would
//! be a dependency cycle).

use std::path::PathBuf;

use vta_config::AppConfig;
use vti_common::acl::Role;
use vti_common::auth::AuthClaims;
use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

/// A fresh tempdir-backed store with the keyspaces the backup path uses.
pub struct TestStore {
    // `_dir` owns the on-disk backing and must outlive `store`; `store` must
    // outlive the keyspace handles.
    _dir: tempfile::TempDir,
    pub store: Store,
    pub keys_ks: KeyspaceHandle,
    pub webvh_ks: KeyspaceHandle,
    pub data_dir: PathBuf,
}

/// Open a fresh tempdir-backed [`TestStore`].
pub async fn open_test_store() -> TestStore {
    let dir = tempfile::tempdir().expect("temp dir");
    let data_dir = dir.path().to_path_buf();
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.clone(),
    })
    .expect("open store");
    TestStore {
        keys_ks: store.keyspace(vta_keyspaces::KEYS).expect("keys ks"),
        webvh_ks: store.keyspace(vta_keyspaces::WEBVH).expect("webvh ks"),
        _dir: dir,
        store,
        data_dir,
    }
}

/// A minimal `AppConfig` suitable for in-memory tests. All external services
/// (keyring, TEE, cloud secret managers, …) are left at their defaults.
pub fn test_app_config(data_dir: PathBuf) -> AppConfig {
    AppConfig {
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
        vta_did: None,
        vta_name: None,
        public_url: None,
        resolver_url: None,
        did_cache: Default::default(),
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
        hardened: Default::default(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        config_path: PathBuf::new(),
        unknown_keys: Vec::new(),
        effective_config_digest: None,
        effective_config_view: None,
    }
}

/// Synthesise a super-admin `AuthClaims` for tests that bypass the normal
/// session/JWT gate.
pub fn super_admin_claims() -> AuthClaims {
    AuthClaims {
        did: "did:key:zTestAdmin".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

/// A trivial in-memory [`SeedStore`](vta_keys::seed_store::SeedStore) that
/// returns a fixed seed.
pub struct TestSeedStore(pub Vec<u8>);

impl vta_keys::seed_store::SeedStore for TestSeedStore {
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, vti_common::error::AppError>>
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
        Box<dyn std::future::Future<Output = Result<(), vti_common::error::AppError>> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

/// A [`SeedStore`](vta_keys::seed_store::SeedStore) that keeps what is `set`,
/// as a real secret store would — what a restore commits to.
pub struct MemSeedStore(pub std::sync::Mutex<Vec<u8>>);

impl MemSeedStore {
    pub fn new(seed: &[u8]) -> Self {
        Self(std::sync::Mutex::new(seed.to_vec()))
    }
    pub fn current(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl vta_keys::seed_store::SeedStore for MemSeedStore {
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, vti_common::error::AppError>>
                + Send
                + '_,
        >,
    > {
        let v = self.current();
        Box::pin(async move { Ok(Some(v)) })
    }

    fn set(
        &self,
        seed: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), vti_common::error::AppError>> + Send + '_>,
    > {
        *self.0.lock().unwrap() = seed.to_vec();
        Box::pin(async { Ok(()) })
    }
}
