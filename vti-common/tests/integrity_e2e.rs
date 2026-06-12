//! End-to-end test for the TEE integrity manifest (P0.2a).
//!
//! Unit tests in `integrity::tests` exercise the global-free `verify_or_baseline`
//! path. This file drives the **real** public API — `boot_verify_and_install`
//! (which installs the process-global sealer) and the covered-mutation
//! chokepoints (`store_acl_entry`, `counter::allocate_u32`) that call
//! `reseal_if_active`. It must live in its own integration-test binary because
//! it permanently installs the process-global sealer; co-locating it with the
//! unit tests would pollute their shared process.
//!
//! Flow: baseline → mutate through a chokepoint (auto-reseals) → re-verify
//! (clean) → tamper out-of-band (bypassing the chokepoint) → re-verify (fails
//! closed).

use vti_common::acl::{AclEntry, Role, delete_acl_entry, store_acl_entry};
use vti_common::config::StoreConfig;
use vti_common::integrity::{BootOutcome, boot_verify_and_install, derive_mac_key};
use vti_common::store::{KeyspaceHandle, Store, counter};

struct Env {
    keys: KeyspaceHandle,
    bootstrap: KeyspaceHandle,
    acl: KeyspaceHandle,
    contexts: KeyspaceHandle,
    mac_key: [u8; 32],
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
        _dir: dir,
    }
}

async fn boot(env: &Env, allow_init: bool) -> Result<BootOutcome, vti_common::error::AppError> {
    boot_verify_and_install(
        env.mac_key,
        env.keys.clone(),
        env.bootstrap.clone(),
        env.acl.clone(),
        env.contexts.clone(),
        allow_init,
    )
    .await
}

#[tokio::test]
async fn install_chokepoint_reseal_then_reverify_then_tamper() {
    let env = open();

    // Seed some pre-existing covered state, then baseline on first boot.
    env.keys
        .insert_raw("tee:bootstrap-carveout-closed", b"closed".to_vec())
        .await
        .unwrap();
    counter::allocate_u32(&env.keys, "path_counter:m/26'/0'")
        .await
        .unwrap();
    assert_eq!(boot(&env, true).await.unwrap(), BootOutcome::Baselined);

    // The sealer is now installed (this process). A legitimate ACL grant flows
    // through the chokepoint, which auto-reseals the manifest...
    let alice = AclEntry::new("did:key:zAlice", Role::Admin, "test");
    store_acl_entry(&env.acl, &alice).await.unwrap();
    // ...and a counter allocation likewise.
    counter::allocate_u32(&env.contexts, "ctx_counter")
        .await
        .unwrap();

    // A re-boot against the (chokepoint-resealed) state verifies cleanly: the
    // manifest tracked the mutations, so no false-positive fail-closed.
    assert_eq!(boot(&env, false).await.unwrap(), BootOutcome::Verified);

    // Now the parent tampers OUT OF BAND — deletes the ACL row directly,
    // bypassing the chokepoint (simulating an offline store edit). The next
    // boot must fail closed.
    env.acl.remove("acl:did:key:zAlice").await.unwrap();
    let err = boot(&env, false)
        .await
        .expect_err("out-of-band ACL deletion must be detected at boot");
    let msg = format!("{err:?}");
    assert!(msg.contains("mismatch"), "{msg}");
    assert!(msg.contains("ACL root"), "{msg}");

    // Re-sealing through the chokepoint (a legitimate revoke would do this)
    // re-establishes consistency, and the next boot is clean again.
    delete_acl_entry(&env.acl, "did:key:zMissing")
        .await
        .unwrap(); // any chokepoint write reseals
    assert_eq!(boot(&env, false).await.unwrap(), BootOutcome::Verified);
}
