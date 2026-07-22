//! Integration coverage for `/v1/relationships*` (Phase 4
//! M4.6).
//!
//! The publish happy path needs a live DID resolver to verify
//! the VRC's data-integrity proof — same constraint as M3.10
//! recognise + M4.3 personhood assert. Integration tests here
//! cover:
//! - publish: caller != issuer → 403
//! - publish: missing resolver → 500
//! - revoke: issuer revokes own row (with hand-seeded state)
//! - revoke: subject (non-issuer) → 403
//! - revoke: admin revokes any row
//! - revoke: 404 on unknown id
//! - list: pagination + §12.3 strip on Purge-removed party

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

use vtc_service::acl::{VtcAclEntry, VtcRole, delete_acl_entry, store_acl_entry};
use vtc_service::members::{Member, delete_member, store_member};
use vtc_service::relationships::{Relationship, store_relationship};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const PUBLISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/publish/1.0";
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/list/1.0";
const REVOKE_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/revoke/1.0";
const ISSUER_DID: &str = "did:key:zVrcIssuer";
const SUBJECT_DID: &str = "did:key:zVrcSubject";
const STRANGER_DID: &str = "did:key:zStranger";
const ADMIN_DID: &str = "did:key:zVrcAdmin";

struct Fixture {
    router: axum::Router,
    issuer_token: String,
    subject_token: String,
    admin_token: String,
    relationships_ks: vti_common::store::KeyspaceHandle,
    relationships_by_did_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
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

    // Seed ACL + Member rows for issuer, subject, admin.
    let now = now_epoch();
    for (did, role) in [
        (ISSUER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
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

    let issuer_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ISSUER_DID,
        "reader",
        now,
    )
    .await;
    let subject_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        SUBJECT_DID,
        "reader",
        now,
    )
    .await;
    let admin_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ADMIN_DID,
        "admin",
        now,
    )
    .await;

    let relationships_ks = vtc.state.relationships_ks.clone();
    let relationships_by_did_ks = vtc.state.relationships_by_did_ks.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let members_ks = vtc.state.members_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        issuer_token,
        subject_token,
        admin_token,
        relationships_ks,
        relationships_by_did_ks,
        acl_ks,
        members_ks,
        audit_ks,
        _vtc: vtc,
    }
}

fn fake_vrc(issuer: &str, subject: &str) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "VerifiableRecognitionCredential"],
        "issuer": issuer,
        "credentialSubject": {
            "id": subject,
            "endorsement": { "type": "endorses" }
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofValue": "z00"
        }
    })
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ─── Publish ─────────────────────────────────────────────

#[tokio::test]
async fn publish_rejects_caller_not_issuer() {
    let fix = build_fixture().await;
    // Subject member tries to publish a VRC issued by someone else.
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_returns_500_when_resolver_unconfigured() {
    let fix = build_fixture().await;
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Caller passes the issuer == VC.issuer gate; resolver
    // path is next + the fixture has did_resolver: None.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn publish_rejects_malformed_vrc() {
    let fix = build_fixture().await;
    // No `issuer` field → 400 (Validation).
    let vrc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSubject": { "id": SUBJECT_DID }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Revoke ──────────────────────────────────────────────

async fn seed_relationship(fix: &Fixture, issuer: &str, subject: &str) -> Uuid {
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer.into(),
        subject_did: subject.into(),
        vrc_jsonld: fake_vrc(issuer, subject),
        vrc_sha256: format!("seed-{id}"),
        created_at: chrono::Utc::now(),
    };
    store_relationship(&fix.relationships_ks, &fix.relationships_by_did_ks, &rel)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn revoke_issuer_can_retract_own() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Row gone.
    let got = vtc_service::relationships::get_relationship(&fix.relationships_ks, id)
        .await
        .unwrap();
    assert!(got.is_none());

    // Audit envelope carries revoked_by: "issuer".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "issuer"
        {
            saw = true;
        }
    }
    assert!(saw, "issuer revoke must emit revoked_by=issuer");
}

#[tokio::test]
async fn revoke_subject_is_forbidden() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_admin_can_revoke_any() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Audit reason = "admin".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_admin = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "admin"
        {
            saw_admin = true;
        }
    }
    assert!(saw_admin);
}

#[tokio::test]
async fn revoke_404_on_unknown() {
    let fix = build_fixture().await;
    let id = Uuid::new_v4();
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── List ────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_issued_and_received_edges() {
    let fix = build_fixture().await;
    let r1 = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let r2 = seed_relationship(&fix, SUBJECT_DID, ISSUER_DID).await; // reverse
    // Stranger row that shouldn't appear for the issuer's list.
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: STRANGER_DID.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(STRANGER_DID))
        .await
        .unwrap();
    let _r3 = seed_relationship(&fix, STRANGER_DID, SUBJECT_DID).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2, "issuer's list = own issued + received");
    let ids: Vec<_> = items
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&r1.to_string()));
    assert!(ids.contains(&r2.to_string()));
}

#[tokio::test]
async fn list_strips_rows_where_other_party_purged() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Purge SUBJECT: delete ACL row + Member row.
    delete_acl_entry(&fix.acl_ks, SUBJECT_DID).await.unwrap();
    delete_member(&fix.members_ks, SUBJECT_DID).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert!(
        items.is_empty(),
        "Purge-removed subject must strip the edge: {v}"
    );
}

#[tokio::test]
async fn list_keeps_rows_for_tombstoned_other_party() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Tombstone SUBJECT: stamp removed_at on the Member row.
    let mut m = vtc_service::members::get_member(&fix.members_ks, SUBJECT_DID)
        .await
        .unwrap()
        .unwrap();
    m.tombstone();
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "Tombstoned subject keeps the edge visible: {v}"
    );
}
