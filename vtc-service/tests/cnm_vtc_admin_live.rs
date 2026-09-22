//! The VTC admin paths `cnm vetting`, `cnm audit` and `cnm backup` take,
//! driven over HTTP against a live `MockVtc`.
//!
//! **The bug these hold.** All three used to authenticate with the community
//! profile's *VTA* session (`vta_sdk::session::SessionStore`), whose
//! challenge-response addresses the VTA's DID: the DIDComm authenticate
//! envelope is encrypted to the VTA's key-agreement key. A VTC holds only its
//! own keys, so it cannot open that envelope and refuses the login — every one
//! of those commands failed before reaching its route. They now authenticate
//! the way `cnm did-log install` does (#1632): `VtcClient::connect` with the
//! VTC's own DID as the audience, as the profile's DID, which needs a
//! super-admin row in the VTC's ACL.
//!
//! `cnm` is a binary, so these call the `VtcClient` methods it calls, with the
//! arguments it passes: `cnm_cli::vtc::connect` is `VtcClient::connect(base,
//! vtc_did, client_did, key)`, and `cnm audit verify` / `cnm backup` /
//! `cnm vetting vetters list` are `audit_verify` / `export_backup` +
//! `import_backup` / `list_vetter_grants` on the client it returns. The
//! audience of the document `cnm` signs is asserted in `cnm-cli/src/vtc.rs`.

use vtc_client::{VtcClient, VtcError};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{MockVtc, TestVtc};

const VTC_DID: &str = "did:webvh:QmCnmAdmin:vtc.example.com";
/// Clears `MIN_BACKUP_PASSWORD_LEN` (15).
const PASSWORD: &str = "cnm-backup-live-password";

/// A deterministic `did:key` + its multibase private key — the community
/// profile's identity.
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

/// The row `vtc acl add --did <did> --role admin` writes: admin, no contexts —
/// a super-admin, which backup and audit verify require.
async fn grant_super_admin(vtc: &TestVtc, did: &str) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: Some("cnm".into()),
            allowed_contexts: vec![],
            created_at: 1,
            created_by: "did:key:vtc-acl-cli".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed super-admin acl row");
}

async fn community() -> TestVtc {
    let vtc = TestVtc::builder()
        .vtc_did(VTC_DID)
        .with_audit(true)
        .with_signers(true)
        .with_public_url("http://vtc.test")
        .build()
        .await;
    // The backup routes open the configured secret store; the default is the
    // OS keyring, which a test must not touch.
    {
        let mut cfg = vtc.state.config.write().await;
        cfg.secrets.backend = Some(vtc_service::config::SecretBackend::Plaintext);
        cfg.config_path = vtc.data_dir().join("config.toml");
    }
    vtc
}

async fn connect_as_cnm(mock: &MockVtc, did: &str, key: &str) -> Result<VtcClient, VtcError> {
    VtcClient::connect(&format!("{}/v1", mock.base_url()), VTC_DID, did, key).await
}

/// `cnm audit verify`: authenticate with the VTC's DID as the audience, then
/// walk the chain.
#[tokio::test]
async fn cnm_audit_verify_authenticates_to_the_vtc() {
    let (did, key) = did_key_from_seed(0xa1);
    let vtc = community().await;
    grant_super_admin(&vtc, &did).await;
    let mock = MockVtc::start_with(vtc).await;

    let client = connect_as_cnm(&mock, &did, &key)
        .await
        .expect("cnm's identity authenticates to the VTC");
    let report = client.audit_verify().await.expect("audit verify");
    assert_eq!(report["verified"], true, "{report}");
    // Where `cnm audit verify` reads the signed half from (#1110 moved it under
    // `ext`; `cnm` read the old top-level place until this test).
    assert!(
        report["ext"]["org.openvtc"]["checkpoints"]["status"].is_string(),
        "{report}"
    );
    mock.shutdown().await;
}

/// `cnm backup export` then `cnm backup import --preview`: the saved file is
/// the envelope itself, and the VTC accepts it back.
#[tokio::test]
async fn cnm_backup_export_and_import_preview_authenticate_to_the_vtc() {
    let (did, key) = did_key_from_seed(0xa2);
    let vtc = community().await;
    grant_super_admin(&vtc, &did).await;
    let mock = MockVtc::start_with(vtc).await;

    let client = connect_as_cnm(&mock, &did, &key).await.expect("connect");
    let envelope = client.export_backup(PASSWORD, false).await.expect("export");
    // What `cnm backup export` writes to disk and prints: the envelope, not
    // the `{ envelope }` response around it.
    assert_eq!(envelope["format"], "vtc-backup-v1", "{envelope}");
    assert_eq!(envelope["sourceDid"], VTC_DID, "{envelope}");

    let preview = client
        .import_backup(&envelope, PASSWORD, false)
        .await
        .expect("import preview");
    assert!(preview["counts"].is_object(), "{preview}");
    assert_ne!(preview["status"], "imported", "a preview changes nothing");
    mock.shutdown().await;
}

/// `cnm vetting vetters list`, the first call every `cnm vetting` command
/// makes after connecting.
#[tokio::test]
async fn cnm_vetting_authenticates_to_the_vtc() {
    let (did, key) = did_key_from_seed(0xa3);
    let vtc = community().await;
    grant_super_admin(&vtc, &did).await;
    let mock = MockVtc::start_with(vtc).await;

    let client = connect_as_cnm(&mock, &did, &key).await.expect("connect");
    client
        .list_vetter_grants()
        .await
        .expect("list vetter grants");
    mock.shutdown().await;
}

/// With no ACL row the VTC refuses the login as an authentication error —
/// the case `cnm` answers with the `vtc acl add` that fixes it.
#[tokio::test]
async fn a_did_with_no_acl_row_is_refused_as_an_auth_error() {
    let (did, key) = did_key_from_seed(0xa4);
    let mock = MockVtc::start_with(community().await).await;

    let err = connect_as_cnm(&mock, &did, &key)
        .await
        .expect_err("a DID the VTC's ACL does not hold cannot sign in");
    assert!(
        matches!(&err, VtcError::Auth(e) if e.is_auth()),
        "cnm keys its ACL guidance on this shape: {err:?}"
    );
    mock.shutdown().await;
}

/// The path these commands used to take: the VTA session's challenge-response,
/// which encrypts the authenticate envelope to the *VTA's* DID. The VTC cannot
/// open it, so the login fails even for a DID its ACL holds — the bug.
#[tokio::test]
async fn the_vta_session_login_cannot_authenticate_to_a_vtc() {
    let (did, key) = did_key_from_seed(0xa5);
    // The community's VTA, as a DID that resolves offline.
    let (vta_did, _) = did_key_from_seed(0xa6);
    let vtc = TestVtc::builder()
        .vtc_did(VTC_DID)
        .with_atm(vtc_service::test_support::build_offline_atm().await)
        .build()
        .await;
    grant_super_admin(&vtc, &did).await;
    let mock = MockVtc::start_with(vtc).await;
    let base = format!("{}/v1", mock.base_url());

    let refused = vta_sdk::session::challenge_response(&base, &did, &key, &vta_did).await;
    assert!(
        refused.is_err(),
        "an envelope addressed to the VTA must not authenticate at the VTC"
    );
    // The same identity, with the VTC's DID as the audience, gets in.
    VtcClient::connect(&base, VTC_DID, &did, &key)
        .await
        .expect("the VTC-audience login succeeds");
    mock.shutdown().await;
}
