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
            // A pre-role (legacy) row: the import maps it onto the role-based
            // shape (`vtc-admin-roles.md` §9).
            br#"{"did":"did:key:z6MkMember","role":"member","created_at":0,"created_by":"test"}"#
                .to_vec(),
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

    // backed-up rows restored byte-identically — but for the ACL, whose
    // legacy rows the import migrates.
    let acl = b
        .state
        .acl_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].0, b"acl:did:key:z6MkMember");
    let migrated: vtc_service::acl::VtcAclEntry = serde_json::from_slice(&acl[0].1).unwrap();
    assert_eq!(migrated.did, "did:key:z6MkMember");
    assert_eq!(migrated.role, vtc_service::acl::VtcRole::Member);
    assert!(!migrated.is_administrator(), "a member holds no admin role");

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
        .insert_raw(
            b"acl:did:key:z6MkKeep".to_vec(),
            br#"{"did":"did:key:z6MkKeep","role":"member","created_at":0,"created_by":"test"}"#
                .to_vec(),
        )
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

/// A crash mid-import (sentinel stamped, never cleared — the destructive
/// replay never reached its final clear) must not wedge the VTC forever,
/// but it must also not auto-heal: the half-applied state (a partial ACL,
/// a partial member set, …) is exactly as unsafe to serve an hour later as
/// it is a second later. `import_in_progress` blocks boot regardless of
/// the sentinel's age; only the explicit `discard_interrupted_import`
/// recovery (`vtc admin discard-interrupted-import`) clears it.
#[tokio::test]
async fn a_set_sentinel_blocks_boot_regardless_of_age() {
    use chrono::{Duration as ChronoDuration, Utc};
    use vtc_service::backup::{import_in_progress, stamp_import_in_progress_for_test};

    let v = TestVtc::builder().vtc_did(VTC_DID).build().await;

    // No sentinel at all — boot proceeds.
    assert!(!import_in_progress(&v.state.config_ks).await.unwrap());

    // A crash *just now* blocks boot.
    stamp_import_in_progress_for_test(&v.state.config_ks, Utc::now())
        .await
        .unwrap();
    assert!(
        import_in_progress(&v.state.config_ks).await.unwrap(),
        "a fresh sentinel must refuse boot"
    );

    // A crash from a week ago blocks boot exactly the same way — there is
    // no TTL that quietly lets the daemon serve a half-restored keyspace
    // set just because nobody has looked at it in a while.
    stamp_import_in_progress_for_test(&v.state.config_ks, Utc::now() - ChronoDuration::days(7))
        .await
        .unwrap();
    assert!(
        import_in_progress(&v.state.config_ks).await.unwrap(),
        "an old sentinel must refuse boot exactly like a fresh one — no auto-expiry"
    );
}

/// `discard_interrupted_import` is the explicit, operator-invoked recovery
/// (`vtc admin discard-interrupted-import`) from an import a crash left
/// interrupted: wipe every backed-up keyspace back to empty and clear the
/// sentinel. After it runs, boot proceeds and a fresh import succeeds.
#[tokio::test]
async fn discard_interrupted_import_resets_and_clears_the_sentinel_so_a_new_import_succeeds() {
    use vtc_service::backup::{discard_interrupted_import, import_in_progress};

    let v = TestVtc::builder().vtc_did(VTC_DID).build().await;
    set_config_path(&v.state, v.data_dir().join("config.toml")).await;
    let v_store = PlaintextSecretStore::new(v.data_dir());
    v_store.set(b"bundle").await.unwrap();

    // Nothing to discard yet.
    assert_eq!(
        discard_interrupted_import(&v.store).await.unwrap(),
        None,
        "discard must be a no-op (and report so) when no import is in progress"
    );

    // Simulate a crash mid-import: some rows from a would-be replay are
    // already there (the clear ran, the replay was interrupted), and the
    // sentinel is set.
    v.state
        .acl_ks
        .insert_raw(b"acl:half-written".to_vec(), b"partial".to_vec())
        .await
        .unwrap();
    vtc_service::backup::stamp_import_in_progress_for_test(&v.state.config_ks, chrono::Utc::now())
        .await
        .unwrap();
    assert!(import_in_progress(&v.state.config_ks).await.unwrap());

    // Recover: wipe to empty, clear the sentinel.
    let since = discard_interrupted_import(&v.store).await.unwrap();
    assert!(since.is_some(), "discard must report the stamp it cleared");

    assert!(
        !import_in_progress(&v.state.config_ks).await.unwrap(),
        "boot must proceed once the operator has discarded the interrupted import"
    );
    let acl = v
        .state
        .acl_ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap();
    assert!(
        acl.is_empty(),
        "discard must wipe the partially-written row(s)"
    );

    // A brand-new import now succeeds — no restart required, no manual
    // sentinel surgery.
    let envelope = export_backup(&v.state, &v_store, PW, false).await.unwrap();
    let result = import_backup(&v.state, &v_store, &envelope, PW, true)
        .await
        .unwrap();
    assert_eq!(result.status, "imported");
    assert!(!import_in_progress(&v.state.config_ks).await.unwrap());
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
// There is no bearer route: a backup moves only over TSP or DIDComm. The codes
// `vtc/backup/{export,import}/0.1` declare are covered on the Trust Task door
// (`trust_tasks::backup_export_tests`, `trust_tasks::backup_tasks`).
// ---------------------------------------------------------------------------

/// The inline `/v1/backup/{export,import}` routes are gone, not refused, so a
/// super-admin's bearer request finds nothing to answer it.
#[tokio::test]
async fn the_inline_backup_routes_are_gone() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let a = TestVtc::builder().vtc_did(VTC_DID).build().await;
    let token = a.admin_token().await;
    for path in ["/v1/backup/export", "/v1/backup/import"] {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(
                serde_json::json!({ "password": PW }).to_string(),
            ))
            .unwrap();
        let res = a.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        // 405 where a GET route matches the same path: either way,
        // nothing answers a POST.
        assert!(
            status == axum::http::StatusCode::NOT_FOUND
                || status == axum::http::StatusCode::METHOD_NOT_ALLOWED,
            "{path}: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

// ---------------------------------------------------------------------------
// The code `vtc/backup/export/0.1` declares, on every end-to-end transport the
// harness offers. The same signed document goes through the same spine either
// way; only the carriage differs.
// ---------------------------------------------------------------------------

/// The end-to-end transports a backup is served on.
#[cfg(feature = "transport-harness")]
#[derive(Debug, Clone, Copy)]
enum Transport {
    DIDComm,
    #[cfg(feature = "tsp")]
    Tsp,
}

#[cfg(feature = "transport-harness")]
impl Transport {
    const ALL: &[Transport] = &[
        Transport::DIDComm,
        #[cfg(feature = "tsp")]
        Transport::Tsp,
    ];

    /// A VTC reachable on this transport.
    async fn start(self) -> vtc_service::test_support::MockVtcTransport {
        use vtc_service::test_support::MockVtcTransport;
        match self {
            Transport::DIDComm => MockVtcTransport::start().await,
            #[cfg(feature = "tsp")]
            Transport::Tsp => MockVtcTransport::start_with_tsp().await,
        }
    }

    /// A session to `mock` on this transport, as `did` holding `key`.
    async fn connect(
        self,
        mock: &vtc_service::test_support::MockVtcTransport,
        did: &str,
        key: &str,
    ) -> vta_sdk::client::VtaClient {
        use vta_sdk::client::VtaClient;
        let (vtc, mediator) = (mock.vtc_did(), mock.mediator_did());
        match self {
            Transport::DIDComm => VtaClient::connect_didcomm(did, key, vtc, mediator, None).await,
            #[cfg(feature = "tsp")]
            Transport::Tsp => VtaClient::connect_tsp(did, key, vtc, mediator, None).await,
        }
        .unwrap_or_else(|e| panic!("connect over {self:?}: {e}"))
    }
}

/// A deterministic `did:key` and its multibase private key.
#[cfg(feature = "transport-harness")]
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// The declared code a session reported a refusal under: the client surfaces
/// an undeclared-by-it code as `trust task failed [<code>]: <message>`.
#[cfg(feature = "transport-harness")]
fn tt_error_code(err: &vta_sdk::error::VtaError) -> Option<String> {
    let text = err.to_string();
    let rest = text.split_once("trust task failed [")?.1;
    Some(rest.split_once(']')?.0.to_string())
}

/// A super-admin's export with a password under the minimum is answered with
/// `vtc/backup/export:passwordTooShort` — the code its spec declares — on
/// every end-to-end transport, and nothing is exported.
#[cfg(feature = "transport-harness")]
#[tokio::test]
async fn the_export_task_answers_with_the_code_its_spec_declares() {
    use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
    use vtc_service::backup::EXPORT_ERR_PASSWORD_TOO_SHORT;

    let short = "x".repeat(vta_sdk::protocols::backup_management::MIN_BACKUP_PASSWORD_LEN - 1);
    for &transport in Transport::ALL {
        let mock = transport.start().await;
        {
            let mut config = mock.vtc.state.config.write().await;
            config.secrets.backend = Some(vtc_service::config::SecretBackend::Plaintext);
            config.config_path = mock.vtc.data_dir().join("config.toml");
            vtc_service::keys::seed_store::create_secret_store(&config)
                .expect("plaintext store")
                .set(b"signing-bundle")
                .await
                .expect("seed the store");
        }
        let (admin_did, admin_key) = did_key_from_seed(0x5c);
        store_acl_entry(
            &mock.vtc.state.acl_ks,
            &VtcAclEntry {
                did: admin_did.clone(),
                role: VtcRole::Admin,
                label: None,
                admin: VtcRole::Admin.implied_authority(),
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
                resource_grants: Vec::new(),
            },
        )
        .await
        .expect("seed the super-admin");
        mock.register_local_did(&admin_did).await;

        let client = transport.connect(&mock, &admin_did, &admin_key).await;
        let err = client
            .dispatch_trust_task(
                "https://trusttasks.org/spec/vtc/backup/export/0.1",
                serde_json::json!({ "password": short }),
                30,
            )
            .await
            .expect_err("a short password exports nothing");
        assert_eq!(
            tt_error_code(&err).as_deref(),
            Some(EXPORT_ERR_PASSWORD_TOO_SHORT),
            "over {transport:?}: {err}"
        );

        client.shutdown().await;
        mock.shutdown().await;
    }
}
