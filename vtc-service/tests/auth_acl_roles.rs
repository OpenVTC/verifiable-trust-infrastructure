//! P0.16 — a non-admin `VtcRole` ACL row must not 500 the unauthenticated
//! `POST /v1/auth/challenge` or leak serde internals.
//!
//! Before the fix, `check_acl` routed through `vti_common::acl::check_acl_full`,
//! which deserializes the `acl:<did>` row into the VTA `Role` taxonomy and
//! hard-errors on a VTC-only role string (`moderator`/`issuer`/`member`/
//! `custom:*`) → `AppError::Serialization` → HTTP 500 whose body carried the
//! serde text to an unauthenticated caller. The fix decodes the row with the
//! VTC decoder and maps `VtcRole → Role`, returning a clean 403 for
//! non-admin roles while the admin row still authenticates.

use reqwest::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;

fn entry(did: &str, role: VtcRole) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        role,
        label: None,
        allowed_contexts: vec![],
        created_at: 1,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

/// The canonical `/v1/auth/challenge` route is Trust-Task-gated (only the
/// `/wallet/auth/challenge` alias is exempt), so the flat-JSON client must
/// send the challenge task header.
const CHALLENGE_TASK: &str = "https://trusttasks.org/spec/auth/challenge/0.1";

async fn challenge(base_url: &str, did: &str) -> (StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/auth/challenge"))
        .header("Trust-Task", CHALLENGE_TASK)
        .json(&json!({ "did": did }))
        .send()
        .await
        .expect("POST /v1/auth/challenge");
    let status = resp.status();
    let body = resp.text().await.expect("read body");
    (status, body)
}

#[tokio::test]
async fn moderator_row_yields_clean_403_not_500_serde_leak() {
    let mock = MockVtc::start().await;
    let did = "did:key:z6MkModerator";
    store_acl_entry(&mock.vtc.state.acl_ks, &entry(did, VtcRole::Moderator))
        .await
        .expect("seed moderator acl row");

    let (status, body) = challenge(mock.base_url(), did).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "moderator must get a clean 403, not a 500: {body}"
    );
    // The pre-fix bug leaked the serde error text. Make sure none of it
    // (nor the role name) appears in the response to an unauth caller.
    assert!(
        !body.contains("unknown variant") && !body.contains("moderator"),
        "challenge 403 body must not leak serde internals or the role: {body}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn every_non_admin_vtc_role_is_cleanly_forbidden() {
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
        let (status, body) = challenge(mock.base_url(), did).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{role} must yield 403, got {status}: {body}"
        );
        assert!(
            !body.contains("unknown variant"),
            "{role} 403 body must not leak serde internals: {body}"
        );
    }
    mock.shutdown().await;
}

#[tokio::test]
async fn admin_row_still_authenticates() {
    let mock = MockVtc::start().await;
    let did = "did:key:z6MkAdminRow";
    store_acl_entry(&mock.vtc.state.acl_ks, &entry(did, VtcRole::Admin))
        .await
        .expect("seed admin acl row");

    let (status, body) = challenge(mock.base_url(), did).await;

    assert_eq!(status, StatusCode::OK, "admin must authenticate: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("challenge json");
    assert!(
        parsed["challenge"].as_str().is_some_and(|c| !c.is_empty()),
        "expected a challenge in the response: {body}"
    );
    assert!(
        parsed["sessionId"].as_str().is_some(),
        "expected a sessionId in the response: {body}"
    );

    mock.shutdown().await;
}
