//! Integration coverage for the directory ceremony — the signed
//! `vtc/directory/query/0.1` document.
//!
//! Exercises the full decision pipeline through a real request: the spine's
//! proof check → facts-assembly (ACL + member reads) → evaluate (active
//! `directory.rego`) → invariant → decide → PII-bounded projection.
//!
//! The viewer is the document's signer, and the directory reads its
//! *community* role from the ACL keyspace. The member viewer getting a
//! member-level projection is the assertion that proves the role comes from
//! there.


use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{call, party_with_role, seed_role};
use vtc_service::acl::VtcRole;
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;

const RP_ORIGIN: &str = "https://vtc.example.com";
const DIRECTORY_TASK: &str = "https://trusttasks.org/spec/vtc/directory/query/0.1";

struct Fixture {
    vtc: TestVtc,
    admin: Party,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .build()
        .await;

    // The directory reads the active `directory` policy, so the bundled
    // defaults must be installed (server boot does this).
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .expect("install default policies");

    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    Fixture { vtc, admin }
}

/// Seed a member: an ACL row (community role) + a Member record.
async fn seed_member(fix: &Fixture, did: &str, role: VtcRole) {
    seed_role(&fix.vtc, did, role, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

/// The directory entry for `subject` as `viewer` sees it: the reply's status
/// and payload (the projected record, or the refusal).
async fn get_directory(fix: &Fixture, subject: &str, viewer: &Party) -> (StatusCode, Value) {
    let (status, doc) = call(
        &fix.vtc,
        viewer,
        DIRECTORY_TASK,
        json!({ "subject": subject }),
    )
    .await;
    (status, doc["payload"].clone())
}

/// An admin viewer sees the fuller projection (did, role, joined_at,
/// status) of a member subject.
#[tokio::test]
async fn admin_viewer_sees_full_record() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;

    let (status, body) = get_directory(&fix, "did:key:zSubject", &fix.admin).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["subject"], "did:key:zSubject");
    let fields = &body["fields"];
    assert_eq!(fields["did"], "did:key:zSubject");
    assert_eq!(fields["role"], "member");
    assert_eq!(fields["status"], "active");
    assert!(
        fields["joined_at"].is_string(),
        "joined_at present for admin: {body}"
    );
}

/// A community-member viewer sees only `did` + `role` — the PII boundary + the
/// member branch of the policy drop the rest.
#[tokio::test]
async fn member_viewer_sees_did_and_role_only() {
    let fix = build_fixture().await;
    let viewer = Party::new();
    seed_member(&fix, &viewer.did, VtcRole::Member).await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;

    let (status, body) = get_directory(&fix, "did:key:zSubject", &viewer).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let fields = &body["fields"];
    assert_eq!(fields["did"], "did:key:zSubject");
    assert_eq!(fields["role"], "member");
    // PII boundary: a member viewer never sees status / joined_at.
    assert!(
        fields.get("status").is_none(),
        "status must be hidden from member viewer: {body}"
    );
    assert!(
        fields.get("joined_at").is_none(),
        "joined_at must be hidden from member viewer: {body}"
    );
}

/// A signer the community holds no entry for is refused before the ceremony
/// runs.
#[tokio::test]
async fn a_stranger_is_rejected() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;

    let (_, body) = get_directory(&fix, "did:key:zSubject", &Party::new()).await;
    assert_eq!(body["code"], "permissionDenied", "{body}");
}

// ---------------------------------------------------------------------------
// #1600 — `vtc/directory/query:notFound`, read from the generated bindings.
// ---------------------------------------------------------------------------

const QUERY_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::directory::query::v0_1::error_codes::NOT_FOUND.code;

/// The error code carried by a `trust-task-error` payload.
fn tt_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

/// Make `source` the active `directory` policy.
async fn activate_directory_policy(fix: &Fixture, source: &str) {
    use sha2::{Digest, Sha256};
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Directory,
            rego_source: source.into(),
            sha256: Sha256::digest(source.as_bytes()).into(),
            activated_at: Some(now),
            author_did: fix.admin.did.clone(),
            created_at: now,
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(
        &fix.vtc.state.active_policies_ks,
        PolicyPurpose::Directory,
        id,
    )
    .await
    .unwrap();
}

/// A DID that is not a member is `notFound` — even to an admin, whose policy
/// branch allows the fullest projection. It used to answer 200 with the DID
/// echoed back and nothing else, an "empty projection" the specification
/// rules out.
#[tokio::test]
async fn a_subject_who_is_not_a_member_is_the_declared_not_found() {
    let fix = build_fixture().await;

    let (_, body) = get_directory(&fix, "did:key:zGhost", &fix.admin).await;
    assert_eq!(tt_error_code(&body), QUERY_ERR_NOT_FOUND, "{body}");
}

/// "Nothing visible to this caller" — a policy deny, or an allow that
/// projects no field — is the same `notFound` as a missing member, with the
/// same message, so a caller cannot tell "no such member" from "you may not
/// see them".
#[tokio::test]
async fn nothing_visible_is_indistinguishable_from_no_such_member() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;
    let (_, missing) = get_directory(&fix, "did:key:zGhost", &fix.admin).await;
    // The refusal as a caller can compare it: what it says, not which
    // document it answers.
    let said = |b: &Value| {
        (
            b["code"].clone(),
            b["message"].clone(),
            b["details"].clone(),
        )
    };

    for policy in [
        "package vtc.directory\nimport rego.v1\n\
         decision := {\"effect\": \"deny\", \"with\": {\"code\": \"not-a-member\"}}\n",
        "package vtc.directory\nimport rego.v1\n\
         decision := {\"effect\": \"allow\", \"with\": {\"fields\": []}}\n",
    ] {
        activate_directory_policy(&fix, policy).await;
        for subject in ["did:key:zSubject", "did:key:zGhost"] {
            let (_, body) = get_directory(&fix, subject, &fix.admin).await;
            assert_eq!(
                tt_error_code(&body),
                QUERY_ERR_NOT_FOUND,
                "{subject}: {body}"
            );
            assert_eq!(
                said(&body),
                said(&missing),
                "{subject}: the refusal must not differ"
            );
        }
    }
}
