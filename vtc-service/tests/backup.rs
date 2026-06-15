//! Full-state backup/restore round-trip (P3.9).
//!
//! The crypto, parameter-bounds, and `vtc_did`-guard unit tests live in
//! `src/backup.rs`. These integration tests exercise the real keyspace
//! census + replay against a `TestVtc`: populate every shape of state,
//! export, restore into a fresh VTC, and assert byte-identical rows —
//! plus that excluded keyspaces are *not* resurrected and the signing
//! key bundle survives. A `PlaintextSecretStore` stands in for the
//! configured secret backend (deterministic + keyring-free in CI).

use std::path::PathBuf;

use vtc_service::backup::{export_backup, import_backup};
use vtc_service::keys::seed_store::{PlaintextSecretStore, SecretStore};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const PW: &str = "twelve-char-pw!!";
const VTC_DID: &str = "did:key:z6MkBackupRoundTrip";

/// `cfg.save()` (run by import's config restore) writes `config_path` —
/// point it at a writable file in the test's temp dir.
async fn set_config_path(state: &AppState, path: PathBuf) {
    state.config.write().await.config_path = path;
}

#[tokio::test]
async fn full_state_roundtrip_restores_rows_and_bundle() {
    // ── source VTC: seed a representative slice of state + a bundle ──
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"signing-bundle-A").await.unwrap();

    a.state
        .acl_ks
        .insert_raw(
            b"acl:did:key:z6MkMember".to_vec(),
            br#"{"role":"member"}"#.to_vec(),
        )
        .await
        .unwrap();
    a.state
        .members_ks
        .insert_raw(b"m:1".to_vec(), b"member-row-1".to_vec())
        .await
        .unwrap();
    // a value with non-UTF8 bytes to prove base64 round-trips it
    a.state
        .status_lists_ks
        .insert_raw(b"sl:0".to_vec(), vec![0u8, 1, 2, 0xFF, 0x80])
        .await
        .unwrap();
    // an *excluded* keyspace row that must NOT survive the restore
    a.state
        .sessions_ks
        .insert_raw(b"sess:ephemeral".to_vec(), b"should-not-survive".to_vec())
        .await
        .unwrap();

    let envelope = export_backup(&a.state, &a_store, PW, true).await.unwrap();
    assert_eq!(envelope.format, "vtc-backup-v1");
    assert_eq!(envelope.source_did.as_deref(), Some(VTC_DID));

    // ── destination VTC: same identity, empty keyspaces + empty store ──
    let b = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());

    let result = import_backup(&b.state, &b_store, &envelope, PW, true)
        .await
        .unwrap();
    assert_eq!(result.status, "imported");

    // backed-up rows restored byte-identically
    let acl = b
        .state
        .acl_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].0, b"acl:did:key:z6MkMember");
    assert_eq!(acl[0].1, br#"{"role":"member"}"#.to_vec());

    let members = b
        .state
        .members_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].1, b"member-row-1");

    let sl = b
        .state
        .status_lists_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert_eq!(
        sl[0].1,
        vec![0u8, 1, 2, 0xFF, 0x80],
        "binary value must round-trip"
    );

    // excluded keyspace was NOT resurrected
    assert!(
        b.state
            .sessions_ks
            .prefix_iter_raw(Vec::<u8>::new())
            .await
            .unwrap()
            .is_empty(),
        "sessions are excluded from backup and must not be restored"
    );

    // signing key bundle restored into the destination's secret store
    assert_eq!(
        b_store.get().await.unwrap().unwrap(),
        b"signing-bundle-A",
        "the signing key bundle must survive the round-trip"
    );
}

#[tokio::test]
async fn preview_does_not_mutate() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"bundle").await.unwrap();
    a.state
        .acl_ks
        .insert_raw(b"acl:keep".to_vec(), b"keep".to_vec())
        .await
        .unwrap();
    let envelope = export_backup(&a.state, &a_store, PW, false).await.unwrap();

    let b = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());
    // seed a row that a real import would clear — preview must leave it.
    b.state
        .acl_ks
        .insert_raw(b"acl:pre-existing".to_vec(), b"untouched".to_vec())
        .await
        .unwrap();

    let result = import_backup(&b.state, &b_store, &envelope, PW, false)
        .await
        .unwrap();
    assert_eq!(result.status, "preview");

    let acl = b
        .state
        .acl_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert_eq!(acl.len(), 1, "preview must not clear or write keyspaces");
    assert_eq!(acl[0].0, b"acl:pre-existing");
}

#[tokio::test]
async fn import_rejects_foreign_vtc_did() {
    let a = TestVtc::builder()
        .vtc_did("did:key:z6MkSourceIdentity")
        .build()
        .await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"bundle").await.unwrap();
    let envelope = export_backup(&a.state, &a_store, PW, false).await.unwrap();

    // destination is a *different* configured identity → refuse.
    let b = TestVtc::builder()
        .vtc_did("did:key:z6MkRunningIdentity")
        .build()
        .await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());

    let err = import_backup(&b.state, &b_store, &envelope, PW, true)
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("vtc_did mismatch"),
        "expected identity-guard rejection, got: {err}"
    );
}

#[tokio::test]
async fn wrong_password_rejected() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"bundle").await.unwrap();
    let envelope = export_backup(&a.state, &a_store, PW, false).await.unwrap();

    let b = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());

    let err = import_backup(&b.state, &b_store, &envelope, "wrong-password!!", true)
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("incorrect backup password"),
        "{err}"
    );
}
