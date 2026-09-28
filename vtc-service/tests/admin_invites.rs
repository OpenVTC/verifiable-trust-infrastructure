//! `vtc/admin/invites/{create,revoke}/0.1` as signed documents — the error
//! codes they declare (#1600), read from the generated bindings.

mod common;

use std::sync::Arc;

use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use common::signed::{call, error_code, party_with_role};
use vtc_service::acl::VtcRole;
use vtc_service::install::InstallTokenSigner;
use vtc_service::test_support::TestVtc;

const CREATE_TASK: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/admin/invites/revoke/0.1";

const CREATE_INVITE_ERR_TTL_TOO_LONG: &str =
    trust_tasks_rs::specs::vtc::admin::invites::create::v0_1::error_codes::TTL_TOO_LONG.code;
const REVOKE_INVITE_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::admin::invites::revoke::v0_1::error_codes::NOT_FOUND.code;

async fn build() -> (TestVtc, Party) {
    let vtc = TestVtc::builder()
        .with_public_url("https://vtc.example.com")
        .with_install_signer(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
        .build()
        .await;
    let admin = common::signed::admin(&vtc).await;
    // The invitee already holds a (scoped) admin entry, so these mints take the
    // path that writes no ACL entry. A mint that *creates* one confers
    // unrestricted admin and needs a passkey gesture and another admin's
    // consent (VTI-APV-014) — `unrestricted_admin_consent.rs` covers that.
    // These tests are about the error codes.
    common::signed::seed_role(&vtc, "did:key:z6MkInvitee", VtcRole::Admin, &["ctx-a"]).await;
    (vtc, admin)
}

/// The `code` of a `trust-task-error` reply, `None` on a success.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

/// The reply to `task` signed by `by`: its whole document.
async fn send(vtc: &TestVtc, by: &Party, task: &str, payload: Value) -> Value {
    call(vtc, by, task, payload).await.1
}

/// Over 24 hours is `ttlTooLong`; a zero TTL is the same 400 without a code,
/// because the specification declares only the upper bound. Statuses
/// unchanged (400, 400), and the 24-hour boundary itself still mints.
#[tokio::test]
async fn the_create_task_answers_with_the_code_its_spec_declares() {
    let (vtc, admin) = build().await;
    let create = |ttl: u64| json!({ "did": "did:key:z6MkInvitee", "ttlSeconds": ttl });

    let doc = send(&vtc, &admin, CREATE_TASK, create(24 * 60 * 60 + 1)).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(CREATE_INVITE_ERR_TTL_TOO_LONG),
        "{doc}"
    );

    // The schema's `ttlSeconds` is at least 1, so zero never reaches the
    // operation: it is malformed, not `ttlTooLong`.
    let doc = send(&vtc, &admin, CREATE_TASK, create(0)).await;
    assert_eq!(error_code(&doc), Some("malformedRequest"), "{doc}");

    let doc = send(&vtc, &admin, CREATE_TASK, create(24 * 60 * 60)).await;
    assert_eq!(error_code(&doc), None, "{doc}");
}

/// An unknown `jti` is `notFound`. A revoked invite is gone, so revoking it
/// again is the same `notFound`.
#[tokio::test]
async fn the_revoke_task_answers_with_the_code_its_spec_declares() {
    let (vtc, admin) = build().await;

    let doc = send(
        &vtc,
        &admin,
        REVOKE_TASK,
        json!({ "jti": uuid::Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(REVOKE_INVITE_ERR_NOT_FOUND),
        "{doc}"
    );

    let minted = send(
        &vtc,
        &admin,
        CREATE_TASK,
        json!({ "did": "did:key:z6MkInvitee" }),
    )
    .await;
    assert_eq!(error_code(&minted), None, "{minted}");
    let jti = minted["payload"]["jti"].as_str().unwrap().to_string();

    let doc = send(&vtc, &admin, REVOKE_TASK, json!({ "jti": jti })).await;
    assert_eq!(error_code(&doc), None, "{doc}");
    let doc = send(&vtc, &admin, REVOKE_TASK, json!({ "jti": jti })).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(REVOKE_INVITE_ERR_NOT_FOUND),
        "{doc}"
    );
}

/// An invite grants community-wide admin authority, so only a caller that
/// already holds it may send one (VTI-ACL-022, VTI-ACL-053). An administrator
/// of one context used to pass `AdminAuth` and could invite a DID it controls
/// into an unrestricted admin entry.
#[tokio::test]
async fn a_context_scoped_admin_cannot_invite_a_community_wide_admin() {
    let (vtc, _) = build().await;
    let scoped = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
    const INVITEE: &str = "did:key:z6MkWouldBeSuperAdmin";

    let doc = send(
        &vtc,
        &scoped,
        CREATE_TASK,
        json!({ "did": INVITEE, "ttlSeconds": 600 }),
    )
    .await;
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
    assert!(
        vtc_service::acl::get_acl_entry(&vtc.state.acl_ks, INVITEE)
            .await
            .unwrap()
            .is_none(),
        "no admin entry may be written for the invitee"
    );
}
