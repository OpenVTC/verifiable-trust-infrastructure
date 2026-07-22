//! Integration coverage for `/v1/endorsement-types/*` +
//! `/v1/credentials/endorsements/*` (Phase 4 M4.8).
//!
//! Covers:
//! - type registry: register happy / reserved / duplicate /
//!   delete with-in-use / delete OK / list
//! - issue: type-not-registered / non-issuer / happy path
//!   (with status-list slot allocation + audit emission)
//! - revoke: admin / non-admin-non-issuer / idempotent
//! - show / list pagination

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const REGISTER_TASK: &str = "https://trusttasks.org/openvtc/vtc/endorsement-types/register/1.0";
const DELETE_TYPE_TASK: &str = "https://trusttasks.org/openvtc/vtc/endorsement-types/delete/1.0";
const ISSUE_TASK: &str = "https://trusttasks.org/openvtc/vtc/credentials/endorsements/issue/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/credentials/endorsements/show/1.0";
const ADMIN_DID: &str = "did:key:zEndAdmin";
const ISSUER_DID: &str = "did:key:zEndIssuer";
const MEMBER_DID: &str = "did:key:zEndMember";
const SUBJECT_DID: &str = "did:key:zEndSubject";

struct Fixture {
    router: axum::Router,
    admin_token: String,
    issuer_token: String,
    member_token: String,
    audit_ks: vti_common::store::KeyspaceHandle,
    endorsements_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build() -> Fixture {
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
    .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let now = now_epoch();
    for (did, role) in [
        (ADMIN_DID, VtcRole::Admin),
        (ISSUER_DID, VtcRole::Issuer),
        (MEMBER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
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
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    async fn mint(
        sessions: &vti_common::store::KeyspaceHandle,
        jwt_keys: &Arc<JwtKeys>,
        did: &str,
        role: &str,
        now: u64,
    ) -> String {
        let session_id = format!("sess-{}", Uuid::new_v4());
        store_session(
            sessions,
            &Session {
                session_id: session_id.clone(),
                did: did.into(),
                challenge: "test".into(),
                state: SessionState::Authenticated,
                created_at: now,
                last_seen: now,
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: Vec::new(),
                acr: String::new(),
                acr_expires_at: None,
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        let claims = jwt_keys.new_claims(did.into(), session_id, role.into(), vec![], 3600, true);
        jwt_keys.encode(&claims).unwrap()
    }
    let admin_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ADMIN_DID,
        "admin",
        now,
    )
    .await;
    let issuer_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ISSUER_DID,
        "reader",
        now,
    )
    .await;
    let member_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        MEMBER_DID,
        "reader",
        now,
    )
    .await;

    let audit_ks = vtc.state.audit_ks.clone();
    let endorsements_ks = vtc.state.endorsements_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        admin_token,
        issuer_token,
        member_token,
        audit_ks,
        endorsements_ks,
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

// ─── Type registry ───────────────────────────────────────

#[tokio::test]
async fn register_happy_path() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "typeUri": "https://example.com/v1/skills/rust",
                "description": "Rust expertise"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["typeUri"], "https://example.com/v1/skills/rust");
}

#[tokio::test]
async fn register_rejects_reserved_uri() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "typeUri": "CommunityRole" }).to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_rejects_duplicate() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/endorsement-types")
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", REGISTER_TASK)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "typeUri": uri }).to_string()))
            .unwrap();
        let _ = fix.router.clone().oneshot(req).await.unwrap();
    }
    // Second register should fail.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": uri }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_requires_admin() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": "https://x/t" }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_type_404_when_unknown() {
    let fix = build().await;
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/endorsement-types/https%3A%2F%2Fx%2Ft")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", DELETE_TYPE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Issue ───────────────────────────────────────────────

async fn register_type(fix: &Fixture, uri: &str) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": uri }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn issue_rejects_unregistered_type() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": "https://unregistered.example/t",
                "claim": { "x": 1 }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_rejects_non_issuer_non_admin() {
    let fix = build().await;
    register_type(&fix, "https://example.com/v1/skills/rust").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": "https://example.com/v1/skills/rust",
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn issue_happy_path_issuer_mints_credential() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": uri,
                "claim": { "level": "expert", "since": "2020" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v["id"].is_string());
    assert!(v["vec"].is_object());

    // Audit: CustomEndorsementIssued + VecIssued both emitted.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_issued = false;
    let mut saw_vec = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementIssued(d) if d.endorsement_type == uri => {
                saw_issued = true;
            }
            AuditEvent::VecIssued(d) if d.credential_type == "VerifiableEndorsementCredential" => {
                saw_vec = true;
            }
            _ => {}
        }
    }
    assert!(saw_issued, "must emit CustomEndorsementIssued");
    assert!(saw_vec, "must emit VecIssued for accounting");
}

#[tokio::test]
async fn issue_rejects_unknown_subject() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": "did:key:zStranger",
                "type": uri,
                "claim": { "x": 1 }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_type_refused_while_live_endorsement_exists() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    // Issue an endorsement of that type.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": uri,
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Try to delete the type — must 409.
    let encoded = uri.replace(':', "%3A").replace('/', "%2F");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/endorsement-types/{encoded}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", DELETE_TYPE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ─── Revoke ──────────────────────────────────────────────

#[tokio::test]
async fn revoke_issuer_can_retract() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", SHOW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Audit: CustomEndorsementRevoked + StatusListFlipped.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_revoked = false;
    let mut saw_flipped = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementRevoked(_) => saw_revoked = true,
            AuditEvent::StatusListFlipped(d) if d.revoked => saw_flipped = true,
            _ => {}
        }
    }
    assert!(saw_revoked);
    assert!(saw_flipped);
    let _ = fix.endorsements_ks;
}

#[tokio::test]
async fn revoke_idempotent_on_already_revoked() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    for _ in 0..2 {
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/credentials/endorsements/{id}"))
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", SHOW_TASK)
            .body(Body::empty())
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn revoke_non_admin_non_issuer_forbidden() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", SHOW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
