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

/// Must clear `MIN_BACKUP_PASSWORD_LEN` — every test below exports through
/// the real guard, so a short value here fails the whole file rather than the
/// one case under test. (The old name said "twelve"; the minimum is 15.)
const PW: &str = "backup-test-password";
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

/// `export_backup` rejects passwords shorter than 15 characters with a
/// `Validation` error. A password of exactly 15 characters must be accepted
/// (boundary). Import has no length check — old backups remain decryptable.
#[tokio::test]
async fn export_rejects_short_password() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());

    // 14 chars — one short of the minimum
    let err = export_backup(&a.state, &a_store, "14-char-passwo", false)
        .await
        .expect_err("export must reject a 14-character password");
    assert!(
        format!("{err}").contains("15 characters"),
        "error must mention the 15-character minimum, got: {err}"
    );

    // Exactly 15 chars — must be accepted (boundary)
    export_backup(&a.state, &a_store, "15-char-passwor", false)
        .await
        .expect("export must accept a 15-character password");
}

// ---------------------------------------------------------------------------
// Audit checkpoints (#708)
// ---------------------------------------------------------------------------

/// The audit log and its signed checkpoints must travel **together**.
///
/// Either half alone turns a legitimate restore into the exact finding
/// checkpoints exist to raise: checkpoints without their log attest to entries
/// that aren't there, and a log without its checkpoints is shorter than every
/// signed checkpoint claims. Both read as truncation to `cnm audit verify`.
#[tokio::test]
async fn audit_and_its_checkpoints_round_trip_together() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"signing-bundle-A").await.unwrap();

    a.state
        .audit_ks
        .insert_raw(b"2026-07-25T10:00:00Z:e1".to_vec(), b"envelope-1".to_vec())
        .await
        .unwrap();
    a.state
        .audit_checkpoint_ks
        .insert_raw(
            b"2026-07-25T10:05:00Z:c1".to_vec(),
            b"checkpoint-1".to_vec(),
        )
        .await
        .unwrap();

    let envelope = export_backup(&a.state, &a_store, PW, true).await.unwrap();

    let b = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());
    import_backup(&b.state, &b_store, &envelope, PW, true)
        .await
        .unwrap();

    let audit_rows = b.state.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let cp_rows = b
        .state
        .audit_checkpoint_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    assert_eq!(audit_rows.len(), 1, "audit log must be restored");
    assert_eq!(
        cp_rows.len(),
        1,
        "checkpoints must be restored alongside the log they attest to"
    );
}

/// `include_audit: false` must drop **both**. Carrying the checkpoints while
/// omitting the log would restore signed attestations to entries the restored
/// VTC does not have.
#[tokio::test]
async fn excluding_the_audit_log_also_excludes_its_checkpoints() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&a.state, a.data_dir().join("config.toml")).await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"signing-bundle-A").await.unwrap();

    a.state
        .audit_ks
        .insert_raw(b"2026-07-25T10:00:00Z:e1".to_vec(), b"envelope-1".to_vec())
        .await
        .unwrap();
    a.state
        .audit_checkpoint_ks
        .insert_raw(
            b"2026-07-25T10:05:00Z:c1".to_vec(),
            b"checkpoint-1".to_vec(),
        )
        .await
        .unwrap();

    let envelope = export_backup(&a.state, &a_store, PW, false).await.unwrap();

    let b = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&b.state, b.data_dir().join("config.toml")).await;
    let b_store = PlaintextSecretStore::new(b.data_dir());
    import_backup(&b.state, &b_store, &envelope, PW, true)
        .await
        .unwrap();

    assert!(
        b.state
            .audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "audit log was excluded"
    );
    assert!(
        b.state
            .audit_checkpoint_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "checkpoints must be excluded with the log — restoring them alone would \
         attest to entries that are not there"
    );
}

// ---------------------------------------------------------------------------
// The bearer routes refuse: a backup moves only over DIDComm or TSP. The codes
// `vtc/backup/{export,import}/0.1` declare are covered on the Trust Task door
// (`trust_tasks::backup_export_tests`, `trust_tasks::backup_tasks`).
// ---------------------------------------------------------------------------

async fn post_backup(
    vtc: &TestVtc,
    path: &str,
    task: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let token = vtc.admin_token().await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// A super-admin with a valid envelope and its password is still refused over
/// REST, for export and import alike, and nothing is imported.
#[tokio::test]
async fn backup_export_and_import_are_refused_over_rest() {
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    let a_store = PlaintextSecretStore::new(a.data_dir());
    a_store.set(b"signing-bundle").await.unwrap();
    let envelope =
        serde_json::to_value(export_backup(&a.state, &a_store, PW, false).await.unwrap()).unwrap();

    let (status, body) = post_backup(
        &a,
        "/v1/backup/export",
        "https://trusttasks.org/spec/vtc/backup/export/0.1",
        serde_json::json!({ "password": PW }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("DIDComm or TSP"), "{body}");

    for confirm in [false, true] {
        let (status, body) = post_backup(
            &a,
            "/v1/backup/import",
            "https://trusttasks.org/spec/vtc/backup/import/0.1",
            serde_json::json!({ "backup": envelope, "password": PW, "confirm": confirm }),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "confirm={confirm}: {body}"
        );
    }
}
