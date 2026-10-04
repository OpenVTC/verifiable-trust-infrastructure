//! Integration coverage for personhood (Phase 4 M4.3 + M4.4): the challenge,
//! the assertion and the revoke are all signed documents at
//! `POST /v1/trust-tasks` (`vtc/members/personhood/{challenge,assert,revoke}/0.1`)
//! — the revoke's bearer `DELETE /v1/members/{did}/personhood` route was
//! retired once the signed-document spine covered it
//! (`trust_tasks::member_tasks`).
//!
//! Covers:
//! - challenge mint happy path + non-member 404
//! - assert without challenge → 422
//! - assert without configured DID resolver → 500
//!   (daemon-misconfigured class)
//! - revoke admin path — flag flips + VMC re-mints + audit
//! - revoke self path — same outcome, `reason: "self"`
//! - revoke unauthorized (member-A → member-B) → 403
//! - revoke idempotent on already-false → 200 no-op without
//!   audit
//!
//! The assert happy path requires a live DID resolver to
//! verify the VP's `#key-0` proof; like the M3.10 recognise
//! integration tests, the route-level happy path is exercised
//! end-to-end via mocked credentials in the unit-test layer
//! (see `recognition::verify::tests`) — the integration
//! coverage here pins the failure-mode + audit surfaces.

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_common::audit::{AuditEnvelope, AuditEvent};

use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const CHALLENGE_TASK: &str = "https://trusttasks.org/spec/vtc/members/personhood/challenge/0.1";
const ASSERT_TASK: &str = "https://trusttasks.org/spec/vtc/members/personhood/assert/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/members/personhood/revoke/0.1";
/// A data-only subject: seeded as a member, but never a document signer —
/// stands in for "some other member" wherever a test names a subject it
/// does not need to sign as.
const OTHER_MEMBER_DID: &str = "did:key:zPerson2";

struct Fixture {
    router: axum::Router,
    /// A member with a real key, who signs the challenge, assert and
    /// self-revoke documents.
    person: Party,
    /// An administrator with a real key, who signs the admin-revoke
    /// documents.
    admin: Party,
    members_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(PUBLIC_URL)
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

    // Seed ACL + Member rows for the data-only "other member".
    let now = vti_common::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: OTHER_MEMBER_DID.into(),
            role: VtcRole::Member,
            label: None,
            admin: VtcRole::Member.implied_authority(),
            delegated_by: None,
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    store_member(&vtc.state.members_ks, &Member::fresh(OTHER_MEMBER_DID))
        .await
        .unwrap();

    let person = Party::new();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: person.did.clone(),
            role: VtcRole::Member,
            label: None,
            admin: VtcRole::Member.implied_authority(),
            delegated_by: None,
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    store_member(&vtc.state.members_ks, &Member::fresh(&person.did))
        .await
        .unwrap();

    let admin = Party::new();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: admin.did.clone(),
            role: VtcRole::Admin,
            label: None,
            admin: VtcRole::Admin.implied_authority(),
            delegated_by: None,
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();

    let members_ks = vtc.state.members_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        person,
        admin,
        members_ks,
        audit_ks,
        _vtc: vtc,
    }
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

/// `payload` as a document of `task`, signed by `from`; the reply's status and
/// payload.
async fn signed(fix: &Fixture, from: &Party, task: &str, payload: Value) -> (StatusCode, Value) {
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        task,
        payload,
        &from.did,
        vtc_service::test_support::TEST_VTC_DID,
    )
    .unwrap();
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    (status, body["payload"].clone())
}

/// Mint a challenge for the fixture's person.
async fn challenge(fix: &Fixture) -> String {
    let (status, v) = signed(
        fix,
        &fix.person,
        CHALLENGE_TASK,
        json!({ "did": fix.person.did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v["challengeId"].as_str().unwrap().to_string()
}

/// `vtc/members/personhood/revoke/0.1`, signed by `by`: the reply's status
/// and payload.
async fn revoke(fix: &Fixture, by: &Party, subject: &str) -> (StatusCode, Value) {
    signed(fix, by, REVOKE_TASK, json!({ "did": subject })).await
}

// ─── Challenge ─────────────────────────────────────────────

#[tokio::test]
async fn challenge_happy_path_returns_uuid_and_expiry() {
    let fix = build_fixture().await;
    let (status, v) = signed(
        &fix,
        &fix.person,
        CHALLENGE_TASK,
        json!({ "did": fix.person.did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["challengeId"].is_string());
    assert!(v["expiresAt"].is_string());
}

// ─── Assert (failure-mode coverage) ────────────────────────

#[tokio::test]
async fn assert_without_did_resolver_is_a_server_error() {
    let fix = build_fixture().await;
    // First mint a challenge so the early-exit on missing challenge doesn't
    // fire. Both copies of the challenge, so this reaches the resolver rather
    // than stopping at the signed-nonce check.
    let challenge_id = challenge(&fix).await;
    let (status, body) = post_assert(
        &fix,
        presentation_with(&fix.person.did, &challenge_id, &challenge_id),
    )
    .await;
    // Fixture has did_resolver: None.
    assert!(status.is_server_error(), "{status}: {body}");
}

/// A presentation by `holder` carrying the challenge in both required places.
/// `nonce` is the signed copy, `proof.challenge` the one the published task
/// names; see `assert_inner` step 1a for why both are demanded.
fn presentation_with(holder: &str, challenge: &str, nonce: &str) -> serde_json::Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder,
        "verifiableCredential": [],
        "nonce": nonce,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{holder}#key-0"),
            "challenge": challenge,
            "proofValue": "z00",
        }
    })
}

/// The fixture's person asserts `presentation` about themselves.
async fn post_assert(fix: &Fixture, presentation: serde_json::Value) -> (StatusCode, Value) {
    signed(
        fix,
        &fix.person,
        ASSERT_TASK,
        json!({ "did": fix.person.did, "presentation": presentation }),
    )
    .await
}

#[tokio::test]
async fn assert_with_unknown_challenge_is_refused() {
    let fix = build_fixture().await;
    let unknown = uuid::Uuid::new_v4().to_string();
    let (status, body) =
        post_assert(&fix, presentation_with(&fix.person.did, &unknown, &unknown)).await;
    assert!(status.is_client_error(), "{status}: {body}");
}

/// The replay defence. `proof.challenge` sits inside the proof block, which
/// `verify_vp_proof` strips before verifying — so it is not covered by the
/// holder's signature. A captured presentation could otherwise be replayed
/// against a freshly-minted challenge by swapping that one unsigned field.
///
/// Refusing a presentation with no signed `nonce` is what makes the
/// challenge an actual binding rather than a decoration.
#[tokio::test]
async fn assert_without_a_signed_nonce_is_refused() {
    let fix = build_fixture().await;
    let challenge_id = challenge(&fix).await;
    let mut presentation = presentation_with(&fix.person.did, &challenge_id, &challenge_id);
    presentation
        .as_object_mut()
        .expect("presentation object")
        .remove("nonce");

    let (status, body) = post_assert(&fix, presentation).await;
    assert!(
        status.is_client_error(),
        "a presentation whose challenge appears only in the unsigned proof block must be refused: {body}"
    );
}

/// The same defence from the other side: a captured presentation whose
/// unsigned `proof.challenge` has been swapped for a fresh one no longer
/// agrees with the signed `nonce` it was made with.
#[tokio::test]
async fn assert_with_mismatched_signed_and_unsigned_challenge_is_refused() {
    let fix = build_fixture().await;
    let swapped_challenge = challenge(&fix).await;
    let captured_nonce = uuid::Uuid::new_v4().to_string();

    let (status, body) = post_assert(
        &fix,
        presentation_with(&fix.person.did, &swapped_challenge, &captured_nonce),
    )
    .await;
    assert!(
        status.is_client_error(),
        "swapping the unsigned challenge on a captured presentation must be refused: {body}"
    );
}

// ─── Revoke ───────────────────────────────────────────────

#[tokio::test]
async fn revoke_admin_flips_member_row_and_emits_audit() {
    let fix = build_fixture().await;
    // Mark member as previously asserted.
    let mut m = get_member(&fix.members_ks, &fix.person.did)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(7); // pre-allocated for re-mint
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, v) = revoke(&fix, &fix.admin, &fix.person.did).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["personhood"], false);
    assert!(v["vmc"].is_object());

    // Member row flipped + timestamp cleared.
    let m2 = get_member(&fix.members_ks, &fix.person.did)
        .await
        .unwrap()
        .unwrap();
    assert!(!m2.personhood);
    assert!(m2.personhood_asserted_at.is_none());

    // Audit envelope carries reason: "admin".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(d) = env.event
            && d.reason == "admin"
        {
            saw = true;
            break;
        }
    }
    assert!(saw, "admin revoke must emit PersonhoodRevoked reason=admin");
}

#[tokio::test]
async fn revoke_self_emits_audit_reason_self() {
    let fix = build_fixture().await;
    let mut m = get_member(&fix.members_ks, &fix.person.did)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(8);
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, v) = revoke(&fix, &fix.person, &fix.person.did).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_self = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(d) = env.event
            && d.reason == "self"
        {
            saw_self = true;
            break;
        }
    }
    assert!(saw_self, "self-revoke must emit reason=self");
}

#[tokio::test]
async fn revoke_unauthorized_when_member_revokes_someone_else() {
    let fix = build_fixture().await;
    // Mark other_member as asserted; person tries to revoke
    // on their behalf — must 403.
    let mut m = get_member(&fix.members_ks, OTHER_MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(9);
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, v) = revoke(&fix, &fix.person, OTHER_MEMBER_DID).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
}

#[tokio::test]
async fn revoke_already_false_is_idempotent_noop() {
    let fix = build_fixture().await;
    // Member.personhood already false (default). Revoke
    // returns 200 + no VMC re-mint + no audit envelope.
    let (status, v) = revoke(&fix, &fix.person, &fix.person.did).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["personhood"], false);
    assert!(
        v.get("vmc").is_none_or(|x| x.is_null()),
        "no-op must omit vmc: {v}"
    );

    // No PersonhoodRevoked envelope.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(_) = env.event {
            saw = true;
            break;
        }
    }
    assert!(!saw, "idempotent no-op must not emit PersonhoodRevoked");
}

#[tokio::test]
async fn revoke_returns_the_declared_not_found_for_unknown_member() {
    let fix = build_fixture().await;
    let (status, v) = revoke(&fix, &fix.admin, "did:key:zStranger").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(rest_error_code(&v), REVOKE_ERR_NOT_FOUND, "{v}");
}

// ─── #1600: the codes the personhood tasks declare ─────────
//
// Read from the generated bindings, never spelled here.

use trust_tasks_rs::specs::vtc::members::personhood as personhood_spec;

const CHALLENGE_ERR_NOT_FOUND: &str = personhood_spec::challenge::v0_1::error_codes::NOT_FOUND.code;
const ASSERT_ERR_NOT_FOUND: &str = personhood_spec::assert::v0_1::error_codes::NOT_FOUND.code;
const ASSERT_ERR_CHALLENGE_EXPIRED: &str =
    personhood_spec::assert::v0_1::error_codes::CHALLENGE_EXPIRED.code;
const ASSERT_ERR_PRESENTATION_INVALID: &str =
    personhood_spec::assert::v0_1::error_codes::PRESENTATION_INVALID.code;
const REVOKE_ERR_NOT_FOUND: &str = personhood_spec::revoke::v0_1::error_codes::NOT_FOUND.code;

/// The extended error code carried by a refusal's payload.
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn personhood_challenge_and_revoke_for_a_non_member_are_the_declared_not_found() {
    let fix = build_fixture().await;
    let (status, body) = signed(
        &fix,
        &fix.person,
        CHALLENGE_TASK,
        json!({ "did": "did:key:zStranger" }),
    )
    .await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), CHALLENGE_ERR_NOT_FOUND, "{body}");

    let (status, body) = revoke(&fix, &fix.admin, "did:key:zStranger").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), REVOKE_ERR_NOT_FOUND, "{body}");
}

/// Every code `assert/0.1` declares. None of these reach the resolver, which
/// this fixture does not have: each refusal comes before it, as it should —
/// caller errors are not masked by daemon prerequisites.
#[tokio::test]
async fn the_personhood_assert_task_answers_with_the_codes_its_spec_declares() {
    let fix = build_fixture().await;

    // notFound: nobody by that DID — a stranger asserting about themselves.
    let stranger = Party::new();
    let unknown = uuid::Uuid::new_v4().to_string();
    let (status, body) = signed(
        &fix,
        &stranger,
        ASSERT_TASK,
        json!({
            "did": stranger.did,
            "presentation": presentation_with(&stranger.did, &unknown, &unknown),
        }),
    )
    .await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), ASSERT_ERR_NOT_FOUND, "{body}");

    // challengeExpired: a challenge the community never minted.
    let (status, body) =
        post_assert(&fix, presentation_with(&fix.person.did, &unknown, &unknown)).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(
        rest_error_code(&body),
        ASSERT_ERR_CHALLENGE_EXPIRED,
        "{body}"
    );

    // presentationInvalid: a real challenge, answered by a presentation whose
    // holder is somebody else.
    let challenge_id = challenge(&fix).await;
    let presentation = presentation_with(OTHER_MEMBER_DID, &challenge_id, &challenge_id);
    let (status, body) = post_assert(&fix, presentation).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(
        rest_error_code(&body),
        ASSERT_ERR_PRESENTATION_INVALID,
        "{body}"
    );
}
