//! Integration coverage for `/v1/members/{did}/personhood/*`
//! (Phase 4 M4.3 + M4.4).
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
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const CHALLENGE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/personhood/challenge/1.0";
const ASSERT_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/personhood/assert/1.0";
const MEMBER_DID: &str = "did:key:zPerson1";
const OTHER_MEMBER_DID: &str = "did:key:zPerson2";
const ADMIN_DID: &str = "did:key:zPersonAdmin";

struct Fixture {
    router: axum::Router,
    member_token: String,
    other_member_token: String,
    admin_token: String,
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

    // Seed ACL + Member rows for member, other-member, admin.
    let now = now_epoch();
    for (did, role) in [
        (MEMBER_DID, VtcRole::Member),
        (OTHER_MEMBER_DID, VtcRole::Member),
        (ADMIN_DID, VtcRole::Admin),
    ] {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                allowed_contexts: vec![],
                created_at: now,
                created_by: "did:key:vtc-install".into(),
                expires_at: None,
            },
        )
        .await
        .unwrap();
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    // Mint tokens with fixed session ids so the AuthClaims extractor's
    // session-state lookup succeeds (tee-attested, 1h TTL).
    let member_token = {
        let session_id = "sess-member";
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.into(),
                did: MEMBER_DID.into(),
                challenge: "test".into(),
                state: SessionState::Authenticated,
                created_at: now,
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: Vec::new(),
                acr: String::new(),
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        let claims = vtc.jwt_keys.new_claims(
            MEMBER_DID.into(),
            session_id.into(),
            "reader".into(),
            vec![],
            3600,
            true,
        );
        vtc.jwt_keys.encode(&claims).unwrap()
    };
    let other_member_token = {
        let session_id = "sess-other";
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.into(),
                did: OTHER_MEMBER_DID.into(),
                challenge: "test".into(),
                state: SessionState::Authenticated,
                created_at: now,
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: Vec::new(),
                acr: String::new(),
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        let claims = vtc.jwt_keys.new_claims(
            OTHER_MEMBER_DID.into(),
            session_id.into(),
            "reader".into(),
            vec![],
            3600,
            true,
        );
        vtc.jwt_keys.encode(&claims).unwrap()
    };
    let admin_token = {
        let session_id = "sess-admin";
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.into(),
                did: ADMIN_DID.into(),
                challenge: "test".into(),
                state: SessionState::Authenticated,
                created_at: now,
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: Vec::new(),
                acr: String::new(),
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        let claims = vtc.jwt_keys.new_claims(
            ADMIN_DID.into(),
            session_id.into(),
            "admin".into(),
            vec![],
            3600,
            true,
        );
        vtc.jwt_keys.encode(&claims).unwrap()
    };

    let members_ks = vtc.state.members_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        member_token,
        other_member_token,
        admin_token,
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

// ─── Challenge endpoint ────────────────────────────────────

#[tokio::test]
async fn challenge_happy_path_returns_uuid_and_expiry() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood/challenge"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["challengeId"].is_string());
    assert!(v["expiresAt"].is_string());
}

#[tokio::test]
async fn challenge_returns_404_for_non_member() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/did:key:zStranger/personhood/challenge")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Assert endpoint (failure-mode coverage) ───────────────

#[tokio::test]
async fn assert_without_did_resolver_returns_500() {
    let fix = build_fixture().await;
    // First mint a challenge so the early-exit on missing
    // challenge doesn't fire.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood/challenge"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (_, v) = body_value(resp).await;
    let challenge_id = v["challengeId"].as_str().unwrap().to_string();

    let body = json!({
        "presentation": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": MEMBER_DID,
            "verifiableCredential": [],
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{MEMBER_DID}#key-0"),
                "challenge": challenge_id,
                "proofValue": "z00".to_string(),
            }
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Fixture has did_resolver: None → 500.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn assert_with_unknown_challenge_returns_400() {
    let fix = build_fixture().await;
    let body = json!({
        "presentation": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": MEMBER_DID,
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{MEMBER_DID}#key-0"),
                "challenge": uuid::Uuid::new_v4().to_string(),
                "proofValue": "z00",
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // AppError::Validation → 400 in this workspace.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Revoke endpoint ───────────────────────────────────────

#[tokio::test]
async fn revoke_admin_flips_member_row_and_emits_audit() {
    let fix = build_fixture().await;
    // Mark member as previously asserted.
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(7); // pre-allocated for re-mint
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["personhood"], false);
    assert!(v["vmc"].is_object());

    // Member row flipped + timestamp cleared.
    let m2 = get_member(&fix.members_ks, MEMBER_DID)
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
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(8);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

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
    // Mark other_member as asserted; member tries to revoke
    // on their behalf — must 403.
    let mut m = get_member(&fix.members_ks, OTHER_MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(9);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{OTHER_MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_already_false_is_idempotent_noop() {
    let fix = build_fixture().await;
    // Member.personhood already false (default). Revoke
    // returns 200 + no VMC re-mint + no audit envelope.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
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
async fn revoke_returns_404_for_unknown_member() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/members/did:key:zStranger/personhood")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // Silence unused warning on other_member_token in this
    // test (used in revoke_unauthorized_*).
    let _ = &fix.other_member_token;
}
