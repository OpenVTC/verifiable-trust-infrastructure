//! Integration coverage for `vtc/members/renew/0.1`, a signed document only
//! (Phase 2 M2.13). Its bearer `POST /v1/members/me/renew` route was retired
//! once the signed-document spine covered it (`trust_tasks::member_tasks`),
//! so every request here goes through the signed door.
//!
//! Verifies:
//! - Happy path re-mints VMC + role VAC and stamps the new
//!   ids on the Member row.
//! - Renewal reuses the same status-list slot the member was
//!   allocated at join time.
//! - `proofRequired` for an unsigned document.
//! - The declared `notMember` for a caller whose ACL row is gone.
//! - Both signed VCs verify against the daemon's signer.


use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::http::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::VtcRole;
use vtc_service::credentials::LocalSigner;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

use vti_rooms_dtg::test_support::Party;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const RENEW_TASK: &str = "https://trusttasks.org/spec/vtc/members/renew/0.1";

struct Fixture {
    /// A member with a real key, signing the renewal document.
    member: Party,
    signer: Arc<LocalSigner>,
    members_ks: vti_common::store::KeyspaceHandle,
    status_lists_ks: vti_common::store::KeyspaceHandle,
    policies_ks: vti_common::store::KeyspaceHandle,
    active_policies_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves the router; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // The fixture verifies re-issued VMC/VAC against this signer, so the
    // AppState must issue with this exact instance.
    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(PUBLIC_URL)
        .with_credential_signer(signer.clone())
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");

    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    // Seed a Member ACL row + Member metadata row for a member with a real
    // key — the renewal document must carry a signature the spine can verify.
    let member = Party::new();
    crate::common::signed::seed_role(&vtc, &member.did, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();

    let members_ks = vtc.state.members_ks.clone();
    let status_lists_ks = vtc.state.status_lists_ks.clone();
    let policies_ks = vtc.state.policies_ks.clone();
    let active_policies_ks = vtc.state.active_policies_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();

    Fixture {
        member,
        signer,
        members_ks,
        status_lists_ks,
        policies_ks,
        active_policies_ks,
        audit_ks,
        _vtc: vtc,
    }
}

/// Renew, signed by `fix.member`: the reply's status and `#response` payload
/// (or a refusal's `{code, message}`).
async fn renew(fix: &Fixture) -> (StatusCode, Value) {
    let (status, doc) = crate::common::signed::call(&fix._vtc, &fix.member, RENEW_TASK, json!({})).await;
    (status, doc["payload"].clone())
}

#[tokio::test]
async fn renew_mints_fresh_vmc_and_role_vec() {
    let fix = build_fixture().await;
    let (status, body) = renew(&fix).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["did"], fix.member.did);
    assert_eq!(body["personhood"], false);
    assert_eq!(body["personhoodChanged"], false);

    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vac: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVac"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vac).expect("VAC verifies");

    // Member row updated with the new ids + the freshly-
    // allocated slot.
    let m = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    assert!(m.current_vmc_id.is_some());
    assert!(m.current_role_vac_id.is_some());
    assert!(m.status_list_index.is_some());
}

#[tokio::test]
async fn renew_reuses_existing_status_list_slot() {
    let fix = build_fixture().await;

    // Pre-allocate a slot for the member.
    let mut state = status_list::get_state(&fix.status_lists_ks, StatusPurpose::Revocation)
        .await
        .unwrap()
        .unwrap();
    let pinned_slot = status_list::allocate(&mut state).unwrap();
    status_list::store_state(&fix.status_lists_ks, &state)
        .await
        .unwrap();
    let mut m = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    m.status_list_index = Some(pinned_slot);
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, _) = renew(&fix).await;
    assert_eq!(status, StatusCode::OK);

    let m = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        m.status_list_index,
        Some(pinned_slot),
        "renewal must reuse the existing slot"
    );
}

/// An unsigned document has nothing to authorize a self-service renewal
/// with; the spine refuses it before `renew_inner` ever runs.
#[tokio::test]
async fn renew_without_a_proof_is_the_declared_proof_required() {
    let fix = build_fixture().await;
    let doc = crate::common::signed::unsigned(&fix.member, RENEW_TASK, json!({}));
    let (status, doc) = crate::common::signed::post(&fix._vtc, &doc).await;
    assert_eq!(
        crate::common::signed::error_code(&doc),
        Some("proofRequired"),
        "{doc}"
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{doc}");
}

// ─── Phase 4 M4.2.2: renewal personhood eval ─────────────

#[tokio::test]
async fn renew_preserves_personhood_when_already_asserted() {
    // Member.personhood = true, default policy preserves on
    // renewal. The new VMC should carry personhood: true.
    let fix = build_fixture().await;
    let mut m = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, body) = renew(&fix).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["personhood"], true);
    assert_eq!(body["personhoodChanged"], false);

    let m2 = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    assert!(m2.personhood);
    assert!(m2.personhood_asserted_at.is_some());
}

#[tokio::test]
async fn renew_default_downgrades_when_policy_drops_flag() {
    // Member.personhood = true but we activate a strict
    // policy that denies for everyone. With default
    // on_personhood_fail = Downgrade, renewal succeeds with
    // personhood: false; Member row flips + paired
    // PersonhoodRevoked envelope is emitted.
    //
    // The Refuse-mode arm is exercised by a Fixture variant
    // that takes a PersonhoodFailMode parameter — deferred
    // to PR-2 alongside the assert/revoke endpoints.
    use vti_common::audit::AuditEvent;

    let fix = build_fixture().await;

    let mut m = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    store_member(&fix.members_ks, &m).await.unwrap();

    // Activate a strict deny-all personhood policy via the
    // fixture's already-open keyspace handles (fjall is
    // single-process-locked; can't re-open the dir).
    let src = "package vtc.personhood\nimport rego.v1\ndefault allow := false\n";
    use sha2::{Digest, Sha256};
    let sha: [u8; 32] = Sha256::digest(src.as_bytes()).into();
    let id = uuid::Uuid::new_v4();
    let strict = vtc_service::policy::Policy {
        id,
        purpose: vtc_service::policy::PolicyPurpose::Personhood,
        rego_source: src.into(),
        sha256: sha,
        activated_at: Some(chrono::Utc::now()),
        author_did: "did:key:test".into(),
        created_at: chrono::Utc::now(),
        version: 1,
        name: None,
        description: None,
    };
    vtc_service::policy::store_policy(&fix.policies_ks, &strict)
        .await
        .unwrap();
    vtc_service::policy::set_active_policy_id(
        &fix.active_policies_ks,
        vtc_service::policy::PolicyPurpose::Personhood,
        id,
    )
    .await
    .unwrap();

    let (status, body) = renew(&fix).await;
    assert_eq!(status, StatusCode::OK, "downgrade must succeed: {body}");
    assert_eq!(body["personhood"], false, "downgraded");
    assert_eq!(body["personhoodChanged"], true);

    let m2 = get_member(&fix.members_ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    assert!(!m2.personhood);
    assert!(m2.personhood_asserted_at.is_none());

    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_revoked = false;
    for (_k, v) in pairs {
        let env: vti_common::audit::AuditEnvelope = serde_json::from_slice(&v).unwrap();
        if let AuditEvent::PersonhoodRevoked(data) = env.event
            && data.reason == "renewal-policy"
        {
            saw_revoked = true;
            break;
        }
    }
    assert!(
        saw_revoked,
        "downgrade path must emit PersonhoodRevoked with reason=renewal-policy"
    );
}

/// `vtc/members/renew:notMember`, read from the generated bindings (#1600).
const RENEW_ERR_NOT_MEMBER: &str =
    trust_tasks_rs::specs::vtc::members::renew::v0_1::error_codes::NOT_MEMBER.code;

/// The extended error code carried by a refusal's payload.
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

/// A caller whose session outlived their membership — the ACL entry is gone —
/// has nothing to renew. `self_signer` admits them regardless (an absent row
/// is not expired); `renew_inner` is what answers the declared `notMember`.
#[tokio::test]
async fn renew_by_a_caller_who_is_not_a_member_is_the_declared_not_member() {
    let fix = build_fixture().await;
    vtc_service::acl::delete_acl_entry(&fix._vtc.state.acl_ks, &fix.member.did)
        .await
        .unwrap();
    let (status, body) = renew(&fix).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), RENEW_ERR_NOT_MEMBER, "{body}");
}
