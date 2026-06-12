//! End-to-end test for the TEE anti-rollback anchor (P0.2a manifest + P0.2b
//! external counter).
//!
//! Unit tests in `integrity::tests` exercise the global-free `verify_or_baseline`
//! / `reseal` paths. This file drives the **real** public API —
//! `boot_verify_and_install` (which installs the process-global sealer) and the
//! covered-mutation chokepoints (`store_acl_entry`, `counter::allocate_u32`)
//! that call `reseal_if_active`. It must live in its own integration-test binary
//! because it permanently installs the process-global sealer; co-locating it
//! with the unit tests would pollute their shared process.
//!
//! Flow: baseline (init counter) → mutate through a chokepoint (auto-reseals +
//! CAS-bumps the counter) → re-verify (clean) → tamper out-of-band (bypassing
//! the chokepoint) → re-verify (fails closed) → recover.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use vti_common::acl::{AclEntry, Role, delete_acl_entry, store_acl_entry};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::integrity::{AnchorCounter, BootOutcome, boot_verify_and_install, derive_mac_key};
use vti_common::store::{KeyspaceHandle, Store, counter};

/// In-memory anchor counter with real CAS semantics (mirrors the unit-test
/// mock; integration tests can't import the unit-test module).
struct MockCounter(Mutex<Option<u64>>);
impl MockCounter {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(None)))
    }
    fn current(&self) -> Option<u64> {
        *self.0.lock().unwrap()
    }
}
impl AnchorCounter for MockCounter {
    fn read(&self) -> Pin<Box<dyn Future<Output = Result<Option<u64>, AppError>> + Send + '_>> {
        let v = *self.0.lock().unwrap();
        Box::pin(async move { Ok(v) })
    }
    fn init(
        &self,
        version: u64,
        _digest: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let mut g = self.0.lock().unwrap();
        let r = if g.is_some() {
            Err(AppError::Conflict("exists".into()))
        } else {
            *g = Some(version);
            Ok(())
        };
        Box::pin(async move { r })
    }
    fn set(
        &self,
        expected: u64,
        new: u64,
        _digest: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let mut g = self.0.lock().unwrap();
        let r = if *g == Some(expected) {
            *g = Some(new);
            Ok(())
        } else {
            Err(AppError::Conflict("CAS".into()))
        };
        Box::pin(async move { r })
    }
}

struct Env {
    keys: KeyspaceHandle,
    bootstrap: KeyspaceHandle,
    acl: KeyspaceHandle,
    contexts: KeyspaceHandle,
    mac_key: [u8; 32],
    counter: Arc<MockCounter>,
    _dir: tempfile::TempDir,
}

fn open() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .unwrap();
    Env {
        keys: store.keyspace("keys").unwrap(),
        bootstrap: store.keyspace("bootstrap").unwrap(),
        acl: store.keyspace("acl").unwrap(),
        contexts: store.keyspace("contexts").unwrap(),
        mac_key: derive_mac_key(&[0x5Au8; 32]),
        counter: MockCounter::new(),
        _dir: dir,
    }
}

async fn boot(env: &Env, allow_init: bool) -> Result<BootOutcome, AppError> {
    boot_verify_and_install(
        env.mac_key,
        env.keys.clone(),
        env.bootstrap.clone(),
        env.acl.clone(),
        env.contexts.clone(),
        Some(env.counter.clone()),
        allow_init,
        false,
    )
    .await
}

#[tokio::test]
async fn anchor_end_to_end_through_chokepoints() {
    let env = open();

    // Seed pre-existing covered state, then baseline + init the counter.
    env.keys
        .insert_raw("tee:bootstrap-carveout-closed", b"closed".to_vec())
        .await
        .unwrap();
    counter::allocate_u32(&env.keys, "path_counter:m/26'/0'")
        .await
        .unwrap();
    assert_eq!(boot(&env, true).await.unwrap(), BootOutcome::Baselined);
    assert_eq!(env.counter.current(), Some(0), "counter initialized at v0");

    // The sealer is now installed (this process). Covered mutations flow through
    // the chokepoints, which reseal AND CAS-bump the counter (external-first).
    let alice = AclEntry::new("did:key:zAlice", Role::Admin, "test");
    store_acl_entry(&env.acl, &alice).await.unwrap(); // → v1
    counter::allocate_u32(&env.contexts, "ctx_counter")
        .await
        .unwrap(); // → v2
    assert_eq!(
        env.counter.current(),
        Some(2),
        "each covered mutation advanced the external counter"
    );

    // Re-boot against the resealed state: manifest v2 == counter v2 → clean.
    assert_eq!(boot(&env, false).await.unwrap(), BootOutcome::Verified);

    // Out-of-band tamper: delete the ACL row directly (bypassing the
    // chokepoint, so neither the manifest nor the counter moved). Caught by the
    // Layer-0 recompute (ACL root) before the version check is even reached.
    env.acl.remove("acl:did:key:zAlice").await.unwrap();
    let err = boot(&env, false)
        .await
        .expect_err("out-of-band ACL deletion must be detected at boot");
    let msg = format!("{err:?}");
    assert!(msg.contains("mismatch"), "{msg}");
    assert!(msg.contains("ACL root"), "{msg}");

    // Recover: a chokepoint write reseals + bumps, restoring consistency.
    delete_acl_entry(&env.acl, "did:key:zMissing")
        .await
        .unwrap(); // → v3
    assert_eq!(env.counter.current(), Some(3));
    assert_eq!(boot(&env, false).await.unwrap(), BootOutcome::Verified);
}
