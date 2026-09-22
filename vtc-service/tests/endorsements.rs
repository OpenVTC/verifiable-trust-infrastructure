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
const REGISTER_TASK: &str = "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1";
const LIST_TYPES_TASK: &str = "https://trusttasks.org/spec/vtc/endorsement-types/list/0.1";
const DELETE_TYPE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsement-types/delete/0.1";
const ISSUE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/issue/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
const SHOW_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/show/0.1";
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
    // `{endorsementType: …}` since #1059 — the row was returned bare until
    // the witness compared the handler with its own schema.
    assert_eq!(
        v["endorsementType"]["typeUri"],
        "https://example.com/v1/skills/rust"
    );
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
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), REGISTER_ERR_RESERVED, "{body}");
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
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), REGISTER_ERR_EXISTS, "{body}");
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
async fn list_types_enforces_its_own_task_per_method() {
    // GET + POST share `/endorsement-types`, but each verb now gates on its
    // own canonical task: the GET requires `list/0.1` and refuses the POST's
    // `register/0.1` header (the former shared-mount workaround is gone).
    let fix = build().await;
    let get = |task: &str| {
        Request::builder()
            .method("GET")
            .uri("/v1/endorsement-types")
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", task)
            .body(Body::empty())
            .unwrap()
    };
    let resp = fix
        .router
        .clone()
        .oneshot(get(LIST_TYPES_TASK))
        .await
        .unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let resp = fix
        .router
        .clone()
        .oneshot(get(REGISTER_TASK))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "GET must refuse the register task header"
    );
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
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_NOT_FOUND, "{body}");
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
                "typeUri": "https://unregistered.example/t",
                "claim": { "x": 1 }
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ISSUE_ERR_TYPE_NOT_REGISTERED,
        "{body}"
    );
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
                "typeUri": "https://example.com/v1/skills/rust",
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
                "typeUri": uri,
                "claim": { "level": "expert", "since": "2020" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v["endorsement"]["endorsementId"].is_string());
    // The row carries a *reference* — identifier and lifetime — and the
    // credential itself is a sibling that only this call returns. #1098 put
    // it inside the reference, which made every listing embed a signed
    // credential per row; trustoverip/dtgwg-trust-tasks-tf#262 split the two.
    let issued = &v["endorsement"]["issued"];
    assert!(
        issued["credential"].is_null(),
        "a read reference must not embed the credential: {v}"
    );
    assert!(v["credential"].is_object(), "got {v}");
    let cred_id = issued["credentialId"].as_str().expect("credentialId");
    assert!(cred_id.starts_with("urn:uuid:"), "got {cred_id}");
    // The reference names the credential returned beside it.
    assert_eq!(v["credential"]["id"], issued["credentialId"]);
    assert!(issued["expiresAt"].is_string(), "got {v}");

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
            AuditEvent::VecIssued(d) if d.credential_type == "EndorsementCredential" => {
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
                "typeUri": uri,
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
                "typeUri": uri,
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Try to delete the type — must 409 `inUse`.
    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_IN_USE, "{body}");
}

/// The symmetric partner of `register_accepts`' check that a criterion's
/// `statementType` is registered. Without this, deleting the type strands the
/// criterion in exactly the state registration forbids: it keeps advertising a
/// type the community no longer recognises, and can no longer be saved again.
#[tokio::test]
async fn delete_type_refused_while_a_criterion_names_it() {
    let fix = build().await;
    let uri = "https://example.com/v1/identity-vetting";
    register_type(&fix, uri).await;
    register_vetting_criterion(&fix, "kernel-developer", uri).await;

    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_IN_USE, "{body}");
    // The console renders this text verbatim, so the criterion must be named:
    // "it is in use" the operator cannot act on.
    let message = body.to_string();
    assert!(
        message.contains("kernel-developer"),
        "409 must name the criterion that blocks the delete: {message}"
    );

    // Removing the criterion releases the type — the guard is not sticky.
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/schemas/accepts/kernel-developer")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["typeUri"], uri);
}

/// `DELETE /v1/endorsement-types/{uri}`, percent-encoding the URI into the path.
async fn delete_type(fix: &Fixture, uri: &str) -> (StatusCode, Value) {
    let encoded = uri.replace(':', "%3A").replace('/', "%2F");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/endorsement-types/{encoded}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", DELETE_TYPE_TASK)
        .body(Body::empty())
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// A `credentialSchema` supplied by an admin must not make the service read a
/// local file (or fetch a URL) while compiling it.
///
/// The `jsonschema` crate enables `resolve-http`/`resolve-file` by default;
/// the workspace manifest turns both off, because every schema this service
/// compiles arrives from a caller. The referenced file really exists and is a
/// valid schema, so this registration would succeed if the resolver were on.
#[tokio::test]
async fn register_schema_refuses_an_external_ref() {
    let fix = build().await;

    let dir = tempfile::tempdir().expect("temp dir");
    let target = dir.path().join("ref-target.json");
    std::fs::write(&target, br#"{"type": "string"}"#).expect("write target");

    let req = Request::builder()
        .method("POST")
        .uri("/v1/schemas")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "typeUri": "https://example.test/ExternalRefCredential",
                "dtgType": "ExternalRefCredential",
                "kind": "issues",
                "credentialSchema": { "$ref": format!("file://{}", target.display()) },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a schema with a file:// $ref must be refused, not resolved: {body}"
    );
}

/// An Accepts criterion counting statements of `statement_type`. The DCQL
/// query references `EndorsementCredential`, so that per-type schema is
/// registered first — `store_accepts` refuses a dangling type reference.
async fn register_vetting_criterion(fix: &Fixture, id: &str, statement_type: &str) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/schemas")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "typeUri": "EndorsementCredential",
                "dtgType": "EndorsementCredential",
                "kind": "accepts",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/schemas/accepts")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": id,
                "description": "Two vetters, at least one in person",
                "query": { "credentials": [ { "id": "vetting", "format": "ldp_vc",
                           "meta": { "type_values": ["EndorsementCredential"] } } ] },
                "vetting": {
                    "version": "0.1",
                    "statementType": statement_type,
                    "minStatements": 2,
                    "minByMethod": { "inPerson": 1 },
                    "acceptedMethods": ["inPerson", "video"],
                    "maxStatementAge": "P120D",
                    "eligibleVetters": { "role": "vetter" },
                },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED, "register criterion: {body}");
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
            json!({ "subjectDid": SUBJECT_DID, "typeUri": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", REVOKE_TASK)
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

/// `vtc/endorsements/revoke/0.1` Conformance 3: re-revoking is
/// `alreadyRevoked` (409), and the bit is not re-flipped nor the revocation
/// re-audited. It used to answer 200 with the first receipt, which the
/// specification calls out as the pre-migration divergence to correct.
#[tokio::test]
async fn re_revoking_is_the_declared_already_revoked() {
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
            json!({ "subjectDid": SUBJECT_DID, "typeUri": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let revoke = || {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/credentials/endorsements/{id}"))
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", REVOKE_TASK)
            .body(Body::empty())
            .unwrap()
    };
    let (status, body) = body_value(fix.router.clone().oneshot(revoke()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let audit_rows = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();

    let (status, body) = body_value(fix.router.clone().oneshot(revoke()).await.unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), REVOKE_ERR_ALREADY_REVOKED, "{body}");
    assert_eq!(
        fix.audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .len(),
        audit_rows,
        "a refused re-revoke must not re-audit"
    );
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
            json!({ "subjectDid": SUBJECT_DID, "typeUri": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// `GET /credentials/endorsements/{id}` had **no test at all** before #1093,
/// which is how it returned the bare row past a published schema that wraps
/// it. Issue one, read it back, and assert the envelope — `endorsement` is
/// the member `vtc/endorsements/show/0.1` names.
#[tokio::test]
async fn show_wraps_the_row_in_an_endorsement_envelope() {
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
                "typeUri": uri,
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let (status, issued) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let id = issued["endorsement"]["endorsementId"].as_str().unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", SHOW_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The envelope, not the bare row: `v["id"]` must be absent precisely
    // because the row now sits one level down.
    assert!(v["id"].is_null(), "row must not be at the top level: {v}");
    assert_eq!(v["endorsement"]["endorsementId"], id);
    assert_eq!(v["endorsement"]["subjectDid"], SUBJECT_DID);
}

// ---------------------------------------------------------------------------
// #1600 — the codes the endorsement-type and endorsement tasks declare, read
// from the generated bindings.
// ---------------------------------------------------------------------------

use trust_tasks_rs::specs::vtc::endorsement_types as et_spec;
use trust_tasks_rs::specs::vtc::endorsements as end_spec;

const REGISTER_ERR_INVALID_URI: &str = et_spec::register::v0_1::error_codes::INVALID_URI.code;
const REGISTER_ERR_RESERVED: &str = et_spec::register::v0_1::error_codes::RESERVED.code;
const REGISTER_ERR_EXISTS: &str = et_spec::register::v0_1::error_codes::EXISTS.code;
const DELETE_ERR_NOT_FOUND: &str = et_spec::delete::v0_1::error_codes::NOT_FOUND.code;
const DELETE_ERR_IN_USE: &str = et_spec::delete::v0_1::error_codes::IN_USE.code;
const ISSUE_ERR_TYPE_NOT_REGISTERED: &str =
    end_spec::issue::v0_1::error_codes::TYPE_NOT_REGISTERED.code;
const ISSUE_ERR_CLAIM_TOO_LARGE: &str = end_spec::issue::v0_1::error_codes::CLAIM_TOO_LARGE.code;
const ISSUE_ERR_CLAIM_SCHEMA_VIOLATION: &str =
    end_spec::issue::v0_1::error_codes::CLAIM_SCHEMA_VIOLATION.code;
const ISSUE_ERR_STATUS_LIST_EXHAUSTED: &str =
    end_spec::issue::v0_1::error_codes::STATUS_LIST_EXHAUSTED.code;
const LIST_ERR_INVALID_CURSOR: &str = end_spec::list::v0_1::error_codes::INVALID_CURSOR.code;
const SHOW_ERR_NOT_FOUND: &str = end_spec::show::v0_1::error_codes::NOT_FOUND.code;
const REVOKE_ERR_NOT_FOUND: &str = end_spec::revoke::v0_1::error_codes::NOT_FOUND.code;
const REVOKE_ERR_ALREADY_REVOKED: &str = end_spec::revoke::v0_1::error_codes::ALREADY_REVOKED.code;

const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/list/0.1";

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

async fn register(fix: &Fixture, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

async fn issue(fix: &Fixture, type_uri: &str, claim: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "typeUri": type_uri, "claim": claim }).to_string(),
        ))
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

async fn admin_get_or_delete(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", task)
        .body(Body::empty())
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// An empty (or all-whitespace) `typeUri`, or one over 512 bytes, is
/// `invalidUri`; 400 unchanged. The 512-byte boundary itself registers.
#[tokio::test]
async fn an_empty_or_oversized_type_uri_is_the_declared_invalid_uri() {
    let fix = build().await;
    for uri in [
        "".to_string(),
        "   ".to_string(),
        format!("https://x/{}", "a".repeat(512)),
    ] {
        let (status, body) = register(&fix, json!({ "typeUri": uri })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(rest_error_code(&body), REGISTER_ERR_INVALID_URI, "{body}");
    }
    let at_cap = format!("https://x/{}", "a".repeat(512 - "https://x/".len()));
    let (status, body) = register(&fix, json!({ "typeUri": at_cap })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// A claim over 8 KiB is `claimTooLarge` (400, unchanged).
#[tokio::test]
async fn a_claim_over_the_cap_is_the_declared_claim_too_large() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/large";
    register_type(&fix, uri).await;
    let (status, body) = issue(&fix, uri, json!({ "blob": "x".repeat(8 * 1024) })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), ISSUE_ERR_CLAIM_TOO_LARGE, "{body}");
}

/// A type that declares a `claimSchema` binds its claims: one that fails it is
/// `claimSchemaViolation` (400) and issues nothing; one that satisfies it
/// issues. Before #1600 the schema was stored at registration and never read.
#[tokio::test]
async fn a_claim_failing_the_type_claim_schema_is_the_declared_violation() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/level";
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": uri,
            "claimSchema": {
                "type": "object",
                "required": ["level"],
                "properties": { "level": { "enum": ["novice", "expert"] } }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    for bad in [json!({ "level": "wizard" }), json!({ "other": 1 })] {
        let (status, body) = issue(&fix, uri, bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(
            rest_error_code(&body),
            ISSUE_ERR_CLAIM_SCHEMA_VIOLATION,
            "{bad}: {body}"
        );
    }
    assert!(
        fix.endorsements_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "a refused claim must not persist an endorsement"
    );

    let (status, body) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// With every revocation slot handed out, issuing is `statusListExhausted`
/// (retryable). The status stays the 500 it always was.
#[tokio::test]
async fn a_full_revocation_list_is_the_declared_status_list_exhausted() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/full";
    register_type(&fix, uri).await;
    status_list::with_locked(
        &fix._vtc.state.status_lists_ks,
        StatusPurpose::Revocation,
        |row| {
            row.assigned.iter_mut().for_each(|a| *a = true);
            Ok(())
        },
    )
    .await
    .unwrap();

    let (status, body) = issue(&fix, uri, json!({ "x": 1 })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ISSUE_ERR_STATUS_LIST_EXHAUSTED,
        "{body}"
    );
}

/// A cursor this community did not sign is `invalidCursor` (400, unchanged).
#[tokio::test]
async fn a_forged_cursor_is_the_declared_invalid_cursor() {
    let fix = build().await;
    let (status, body) = admin_get_or_delete(
        &fix,
        "GET",
        "/v1/credentials/endorsements?cursor=bm90LWEtY3Vyc29y",
        LIST_TASK,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), LIST_ERR_INVALID_CURSOR, "{body}");
}

/// An unknown endorsement id is `notFound` to show and to revoke (404,
/// unchanged). Revoke now checks the caller's capability first, so a member
/// who may not revoke gets 403 whether or not the id exists.
#[tokio::test]
async fn an_unknown_endorsement_is_the_declared_not_found() {
    let fix = build().await;
    let path = format!("/v1/credentials/endorsements/{}", Uuid::new_v4());

    let (status, body) = admin_get_or_delete(&fix, "GET", &path, SHOW_TASK).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(rest_error_code(&body), SHOW_ERR_NOT_FOUND, "{body}");

    let (status, body) = admin_get_or_delete(&fix, "DELETE", &path, REVOKE_TASK).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(rest_error_code(&body), REVOKE_ERR_NOT_FOUND, "{body}");

    let req = Request::builder()
        .method("DELETE")
        .uri(&path)
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the capability check precedes the lookup: {body}"
    );
}
