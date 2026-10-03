//! P0.16 — a non-admin `VtcRole` ACL row must not 500 the unauthenticated
//! `auth/challenge/0.1` Trust Task or leak serde internals.
//!
//! Before the original fix, `check_acl` routed through
//! `vti_common::acl::check_acl_full`, which deserializes the `acl:<did>` row
//! into the VTA `Role` taxonomy and hard-errors on a VTC-only role string
//! (`moderator`/`issuer`/`member`/`custom:*`) → `AppError::Serialization` →
//! HTTP 500 whose body carried the serde text to an unauthenticated caller.
//! The fix decodes the row with the VTC decoder and maps `VtcRole → Role`.
//!
//! # Why these tests no longer assert 403
//!
//! They asserted the *mechanism* the fix happened to use, not the property it
//! protects. The property is that an unauthenticated caller learns nothing
//! from this endpoint — no serde internals, no role name, and (since
//! VTI-SES-007) nothing about the subject at all.
//!
//! A 403 for a moderator and a 200 for an admin discloses which subjects hold
//! an admissible role here, to anyone who can name a DID. So the challenge
//! endpoint now answers every caller identically and the refusal moves to
//! authenticate, which requires the subject's private key. These tests assert
//! that: the answer is the same for a non-admin row and for a DID this VTC has
//! never seen, and it still carries none of what the original bug leaked.
//!
//! # Transport
//!
//! `POST /v1/auth/challenge`'s dedicated, `Trust-Task`-header-gated REST mount
//! had no caller left once `vta_sdk::auth_light` switched to signing
//! `auth/challenge/0.1` documents against `POST /v1/trust-tasks` (#1858), so
//! these tests now post the same unsigned Trust Task the SDK builds — a
//! challenge names no identity to authorize, so it needs no proof (see
//! `trust_tasks::auth_tasks`'s module doc).

use reqwest::StatusCode;
use serde_json::Value;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;

fn entry(did: &str, role: VtcRole) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        admin: role.implied_authority(),
        delegated_by: None,
        role,
        label: None,
        created_at: 1,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

async fn vtc_did(mock: &MockVtc) -> String {
    mock.vtc
        .state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the mock VTC has a DID")
}

/// Post the unsigned `auth/challenge/0.1` document the SDK itself builds for
/// `subject`, to the shared `/v1/trust-tasks` door.
async fn challenge(base_url: &str, vta_did: &str, subject: &str) -> (StatusCode, String) {
    let doc = vta_sdk::auth_di::build_challenge_doc(subject, vta_did, subject)
        .expect("build challenge doc");
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/trust-tasks"))
        .header("content-type", "application/json")
        .body(doc)
        .send()
        .await
        .expect("POST /v1/trust-tasks");
    let status = resp.status();
    let body = resp.text().await.expect("read body");
    (status, body)
}

#[tokio::test]
async fn moderator_row_does_not_leak_at_challenge() {
    let mock = MockVtc::start().await;
    let did = "did:key:z6MkModerator";
    store_acl_entry(&mock.vtc.state.acl_ks, &entry(did, VtcRole::Moderator))
        .await
        .expect("seed moderator acl row");

    let vta_did = vtc_did(&mock).await;
    let (status, body) = challenge(mock.base_url(), &vta_did, did).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the challenge endpoint answers every caller identically (VTI-SES-007): {body}"
    );
    // The pre-fix bug leaked the serde error text. Neither it nor the role
    // name may reach an unauthenticated caller by any route.
    assert!(
        !body.contains("unknown variant") && !body.contains("moderator"),
        "challenge body must not leak serde internals or the role: {body}"
    );

    mock.shutdown().await;
}

/// The property, stated directly: a subject this VTC holds a non-admin row for
/// is indistinguishable, at this endpoint, from one it has never heard of.
#[tokio::test]
async fn a_non_admin_row_is_indistinguishable_from_an_unknown_subject() {
    let mock = MockVtc::start().await;
    let known = "did:key:z6MkModeratorTwo";
    store_acl_entry(&mock.vtc.state.acl_ks, &entry(known, VtcRole::Moderator))
        .await
        .expect("seed moderator acl row");

    let vta_did = vtc_did(&mock).await;
    let (known_status, known_body) = challenge(mock.base_url(), &vta_did, known).await;
    let (stranger_status, stranger_body) =
        challenge(mock.base_url(), &vta_did, "did:key:z6MkNeverSeenBefore").await;

    assert_eq!(known_status, stranger_status);

    let field_names = |body: &str| -> Vec<String> {
        let v: Value = serde_json::from_str(body).expect("challenge body is JSON");
        let mut keys: Vec<String> = v
            .as_object()
            .expect("challenge body is an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(
        field_names(&known_body),
        field_names(&stranger_body),
        "the two answers must have the same shape: {known_body} vs {stranger_body}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn no_vtc_role_leaks_at_challenge() {
    let mock = MockVtc::start().await;
    let cases = [
        ("did:key:z6MkIssuer", VtcRole::Issuer),
        ("did:key:z6MkMember", VtcRole::Member),
        ("did:key:z6MkCustom", VtcRole::custom("editor").unwrap()),
    ];
    for (did, role) in cases {
        store_acl_entry(&mock.vtc.state.acl_ks, &entry(did, role.clone()))
            .await
            .expect("seed acl row");
        let vta_did = vtc_did(&mock).await;
        let (status, body) = challenge(mock.base_url(), &vta_did, did).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{role} must be answered like every other caller, got {status}: {body}"
        );
        assert!(
            !body.contains("unknown variant"),
            "{role} challenge body must not leak serde internals: {body}"
        );
    }
    mock.shutdown().await;
}
