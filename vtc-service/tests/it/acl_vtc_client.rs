//! `vtc-client`'s `acl/*` calls, driven against the VTC over every transport
//! it serves: a TSP session and a DIDComm session through a real mediator to
//! the production listener, and a signed document posted to
//! `POST /v1/trust-tasks` over HTTPS.
//!
//! The same calls, on the same client methods, must answer alike whichever
//! transport the client was built for: a grant, a show that sees it, a
//! widening update, a refused narrowing whose specification code survives the
//! trip, and a revoke. Over a session the document is bound to its sender, so
//! a call whose key names another DID is refused before anything is sent —
//! the counterpart of `git_ns_vtc_client.rs`'s same check for `git-ns/*`.
//!
//! Requires `--features didcomm-harness` (and `tsp` for the TSP case); CI runs
//! it.

#![cfg(feature = "didcomm-harness")]

use vtc_client::acl::{AclGrant, AclUpdate};
use vtc_client::{HolderKey, VtcClient, VtcError};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::server::AppState;

/// A deterministic `did:key` and its multibase private key.
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

/// Make `did` a community administrator — the capability every `acl/*` write
/// needs (`actor.require_admin()`).
async fn seed(state: &AppState, did: &str) {
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed the community administrator");
}

/// Grant a `member` entry, show it, widen its scopes, refuse a narrowing
/// update, and revoke it — over whatever transport `client` was built for.
///
/// A `member` grant (not `admin`, and never community-wide) so none of this
/// needs the passkey gesture or admin-consent ceremony `acl/grant` and
/// `acl/update` ask for when the write confers administrator authority — that
/// ceremony is exercised by `cnm access`'s own tests, not the transport wiring
/// this file is for.
async fn grant_show_widen_refuse_revoke(client: &VtcClient, key: &HolderKey, over: &str) {
    let subject = format!("did:key:z6MkSubject{over}");

    let granted = client
        .acl_grant(
            &AclGrant {
                subject: subject.clone(),
                role: "member".into(),
                scopes: vec!["ctx-a".into()],
                label: Some("test".into()),
                expires_at: None,
                reason: None,
            },
            key,
        )
        .await
        .unwrap_or_else(|e| panic!("grant over {over}: {e}"));
    assert_eq!(granted.entry.subject, subject, "over {over}");
    assert_eq!(granted.entry.role, "member", "over {over}");
    assert_eq!(
        granted.entry.scopes,
        vec!["ctx-a".to_string()],
        "over {over}"
    );

    let shown = client
        .acl_show(&subject, key)
        .await
        .unwrap_or_else(|e| panic!("show over {over}: {e}"));
    let entry = shown
        .entry
        .unwrap_or_else(|| panic!("over {over}: no entry"));
    assert_eq!(entry.subject, subject, "over {over}");

    let widened = client
        .acl_update(
            &AclUpdate {
                subject: subject.clone(),
                label: None,
                scopes: Some(vec!["ctx-a".into(), "ctx-b".into()]),
                expires_at: None,
                reason: None,
            },
            key,
        )
        .await
        .unwrap_or_else(|e| panic!("widen over {over}: {e}"));
    assert_eq!(
        widened.entry.scopes,
        vec!["ctx-a".to_string(), "ctx-b".to_string()],
        "over {over}"
    );

    // A refusal carries the specification's code, and the whole
    // `trust-task-error` document, on every transport.
    let narrowed = client
        .acl_update(
            &AclUpdate {
                subject: subject.clone(),
                label: None,
                scopes: Some(vec!["ctx-a".into()]),
                expires_at: None,
                reason: None,
            },
            key,
        )
        .await
        .expect_err("a narrowing update is refused");
    assert!(
        narrowed
            .to_string()
            .contains("acl/update:narrowingNotPermitted"),
        "over {over}: {narrowed}"
    );

    let revoked = client
        .acl_revoke(&subject, None, None, key)
        .await
        .unwrap_or_else(|e| panic!("revoke over {over}: {e}"));
    assert!(revoked.entry.is_none(), "over {over}: {revoked:?}");

    // Gone for good: a show afterwards is refused, not a success with a null
    // entry, and the refusal names the subject on every transport.
    let missing = client
        .acl_show(&subject, key)
        .await
        .expect_err("a revoked subject holds no entry to show");
    assert!(
        missing.to_string().contains(&subject),
        "over {over}: {missing}"
    );
}

/// Over a session the VTC accepts a document only from the DID that signed
/// it, so a key for any other DID is refused by the client, unsent — the same
/// guard `git_ns_vtc_client.rs` checks for `git-ns/*`.
async fn another_signer_is_refused_on_a_session(client: &VtcClient, over: &str) {
    let (other_did, other_key) = did_key_from_seed(0x79);
    let other = HolderKey::from_did_key(&other_did, &other_key).unwrap();
    let err = client
        .acl_show("did:key:z6MkNobody", &other)
        .await
        .expect_err("a document signed as another DID does not ride this session");
    assert!(matches!(err, VtcError::Signing(_)), "over {over}: {err}");
}

#[cfg(feature = "tsp")]
#[tokio::test]
async fn acl_tasks_answer_over_tsp() {
    use vtc_service::test_support::MockVtcDidcomm;

    let mock = MockVtcDidcomm::start_with_tsp().await;
    let (did, key) = did_key_from_seed(0x71);
    seed(&mock.vtc.state, &did).await;
    mock.register_local_did(&did).await;
    let client = VtcClient::connect_tsp(&did, &key, mock.vtc_did(), mock.mediator_did(), None)
        .await
        .expect("connect over TSP");
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    grant_show_widen_refuse_revoke(&client, &holder, "TSP").await;
    another_signer_is_refused_on_a_session(&client, "TSP").await;

    client.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn acl_tasks_answer_over_didcomm() {
    use vtc_service::test_support::MockVtcDidcomm;

    let mock = MockVtcDidcomm::start().await;
    let (did, key) = did_key_from_seed(0x72);
    seed(&mock.vtc.state, &did).await;
    mock.register_local_did(&did).await;
    let client = VtcClient::connect_didcomm(&did, &key, mock.vtc_did(), mock.mediator_did(), None)
        .await
        .expect("connect over DIDComm");
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    grant_show_widen_refuse_revoke(&client, &holder, "DIDComm").await;
    another_signer_is_refused_on_a_session(&client, "DIDComm").await;

    client.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn acl_tasks_answer_over_https() {
    use vtc_service::test_support::{MockVtc, TEST_VTC_DID};

    let mock = MockVtc::start().await;
    let (did, key) = did_key_from_seed(0x73);
    seed(&mock.vtc.state, &did).await;
    // No session and no token: each task is signed with the key and posted.
    let client = VtcClient::anonymous(&format!("{}/v1", mock.base_url()), TEST_VTC_DID);
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    grant_show_widen_refuse_revoke(&client, &holder, "HTTPS").await;

    client.shutdown().await;
    mock.shutdown().await;
}
