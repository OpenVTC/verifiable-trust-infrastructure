//! Integration coverage for `/v1/join-requests/*` (M1.7–M1.10).
//!
//! Exercises the REST surface end-to-end through `Router::oneshot`.
//! DIDComm twin is covered separately by unit-testing the
//! handler's `submit_inner` invocation pattern; an end-to-end
//! DIDComm round-trip needs the mediator harness and lives in
//! `vti-e2e-tests`.

mod common;

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent, CredentialIssuedData, MemberAddedData};
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::store::KeyspaceHandle;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::members::get_member;
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

/// Mirror of the constant in `vtc_service::routes::join_requests::submit`
/// — the route module is `pub(crate)` so we can't import it from a
/// test. Keeping a single-line copy here is cheaper than widening
/// the module's visibility for one test.
const RP_ORIGIN: &str = "https://vtc.example.com";
// The holder-facing verbs are now Trust Task **document** types (the `/spec/`
// canonical form the dispatcher routes on).
const SUBMIT_TASK: &str = "https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0";
const ACCEPT_TASK: &str = "https://trusttasks.org/openvtc/vtc/spec/join-requests/accept/1.0";
const MANIFEST_TASK: &str = "https://trusttasks.org/openvtc/vtc/spec/join-requests/manifest/1.0";
const STATUS_TASK: &str = "https://trusttasks.org/openvtc/vtc/spec/join-requests/status/1.0";
// The admin verbs remain header-gated REST routes (unchanged) — flat URIs.
// The admin GET list shares the submit mount, so it gates on the flat submit URI.
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/show/1.0";
const APPROVE_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0";
const REJECT_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/reject/1.0";
/// The VTC DID the fixture configures — the issuer of every VMC and the
/// community a reciprocal VC must acknowledge.
const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
/// Member seed shared by `applicant_pair` (so a `LocalSigner` over the
/// same seed signs reciprocal VCs that verify against the member did:key).
const MEMBER_SEED: [u8; 32] = [0xCD; 32];
const POLICY_UPLOAD_TASK: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const POLICY_ACTIVATE_TASK: &str = "https://trusttasks.org/spec/policy/activate/0.1";

const ADMIN_DID: &str = "did:key:zAdmin1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    admin_token: String,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    #[allow(dead_code)]
    join_requests_ks: KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // M2.12 credential signer — deterministic seed so the tests can
    // reconstruct it and verify issued VMC/VEC proofs against it.
    let credential_signer = Arc::new(vtc_service::credentials::LocalSigner::from_ed25519_seed(
        "did:webvh:vtc.example.com:abc".into(),
        &[0xCC; 32],
    ));
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .with_credential_signer(credential_signer)
        .build()
        .await;

    // Install workspace-shipped default policies the same way
    // `server::run` does at boot (M2.5). The submit handler evaluates
    // `join.rego` against every submission, so an empty active-policy set
    // would fail closed.
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");

    // M2.10 + M2.12: seed both status lists so the approve handler can
    // allocate a slot when issuing the VMC.
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        let url = format!("{RP_ORIGIN}/v1/status-lists/{purpose}");
        vtc_service::status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .expect("ensure_initial status list");
    }

    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("test admin".into()),
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

    let session_id = "test-admin-session";
    store_session(
        &vtc.state.sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: ADMIN_DID.into(),
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

    let admin_claims = vtc.jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        true,
    );
    let admin_token = vtc.jwt_keys.encode(&admin_claims).unwrap();

    let state = vtc.state.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let members_ks = vtc.state.members_ks.clone();
    let join_requests_ks = vtc.state.join_requests_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        state,
        admin_token,
        acl_ks,
        members_ks,
        join_requests_ks,
        _vtc: vtc,
    }
}

/// The single Trust Task document endpoint the holder-facing join verbs now
/// post to (routing is by the document `type`, not the URL).
const TRUST_TASKS_URI: &str = "/v1/trust-tasks";

/// Sign a Trust Task **document** (`type` = `typ`, `payload` = `payload`) with
/// the shared applicant key, producing the `eddsa-jcs-2022` holder proof the
/// REST path authenticates on. `recipient` = the test VTC DID (the replay
/// binding) and a far-future `expiresAt`. Returns `(applicant_did, document)`.
async fn signed_trust_task(typ: &str, payload: Value) -> (String, Value) {
    signed_trust_task_seed(&[0xCD; 32], typ, payload).await
}

/// As [`signed_trust_task`] but with an explicit Ed25519 seed — lets a test
/// sign as a *different* holder (e.g. to exercise the issuer/signer mismatch
/// rejection).
async fn signed_trust_task_seed(seed: &[u8; 32], typ: &str, payload: Value) -> (String, Value) {
    let mut secret = Secret::generate_ed25519(None, Some(seed));
    let pub_mb = secret
        .get_public_keymultibase()
        .expect("applicant pubkey multibase");
    let did = format!("did:key:{pub_mb}");
    // For did:key the verification method fragment is the multibase itself —
    // what `DidKeyResolver` resolves during proof verification.
    secret.id = format!("{did}#{pub_mb}");
    let mut doc = json!({
        "type": typ,
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "issuer": did,
        "recipient": vtc_service::test_support::TEST_VTC_DID,
        "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "payload": payload,
    });
    let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
        .await
        .expect("sign Trust Task document");
    doc.as_object_mut()
        .unwrap()
        .insert("proof".into(), serde_json::to_value(proof).unwrap());
    (did, doc)
}

/// A signed submit Trust Task document for `vp` (the common case:
/// `registryConsent = false`, no extensions).
async fn submit_doc(vp: &Value) -> (String, Value) {
    signed_trust_task(
        SUBMIT_TASK,
        json!({ "vp": vp, "registryConsent": false, "extensions": null }),
    )
    .await
}

/// POST a Trust Task document to the single `/v1/trust-tasks` endpoint. No
/// `Trust-Task` header — the document's own `type` is the verb.
async fn post_tt(router: &axum::Router, doc: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(TRUST_TASKS_URI)
        .header("content-type", "application/json")
        .body(Body::from(doc.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// The `payload` of a Trust Task `#response` document.
fn tt_payload(doc: &Value) -> Value {
    doc.get("payload")
        .cloned()
        .unwrap_or_else(|| panic!("Trust Task response has no payload: {doc}"))
}

/// The `verdict.effect` string of a submit `#response` document.
fn verdict_effect(doc: &Value) -> String {
    doc.pointer("/payload/verdict/effect")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("no verdict.effect in {doc}"))
        .to_string()
}

/// The framework error `code` of a `trust-task-error` document.
fn tt_error_code(doc: &Value) -> String {
    doc.pointer("/payload/code")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("no payload.code in {doc}"))
        .to_string()
}

fn applicant_pair() -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[0xCD; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
    (sk, did)
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Trust-Task", trust_task);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = router
        .clone()
        .oneshot(
            req.body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or(Body::empty()),
            )
            .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

// ---------------------------------------------------------------------------
// M1.8.1 — REST submit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rest_submit_happy_path_persists_pending() {
    let fix = build_fixture().await;
    let vp = json!({ "type": "VerifiablePresentation" });
    let (_did, doc) = submit_doc(&vp).await;

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    // The default policy refers the request to an admin (request persisted
    // Pending); the document proof authenticated the holder.
    assert_eq!(verdict_effect(&body), "refer");
    assert!(tt_payload(&body)["requestId"].is_string());
}

#[tokio::test]
async fn rest_submit_rejects_wrong_signer() {
    // The document proof verifies, but its signer (the real `did:key`) does not
    // match the document `issuer` — an impersonation attempt. The dispatcher
    // rejects it `permissionDenied` (403).
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc["issuer"] = json!("did:key:z6MkpwrongIssuerDidThatIsNotTheSigner");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {body}");
    assert_eq!(tt_error_code(&body), "permissionDenied");
}

#[tokio::test]
async fn rest_submit_rejects_missing_holder_proof() {
    // Over REST the holder is authenticated by the document proof; a document
    // with no proof has no proven holder and is rejected (403).
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc.as_object_mut().unwrap().remove("proof");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {body}");
    assert_eq!(tt_error_code(&body), "permissionDenied");
}

// P0.13 — replay / freshness / audience binding + per-applicant dedup.

#[tokio::test]
async fn rest_submit_dedups_an_open_request_for_the_same_applicant() {
    // A captured document replayed while a request is still open is refused, and
    // a second concurrent submit can't accumulate a second open row.
    let fix = build_fixture().await;
    let vp = json!({ "type": "VerifiablePresentation" });

    let (_did, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "refer");

    // Duplicate while the first request is still open → a business-rule
    // conflict, surfaced as the framework `taskFailed` reject (422).
    let (_did2, doc2) = submit_doc(&vp).await;
    let (status2, body2) = post_tt(&fix.router, doc2).await;
    assert_eq!(
        status2,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a second open request for one applicant must be a taskFailed conflict: {body2}"
    );
    assert_eq!(tt_error_code(&body2), "taskFailed");
}

#[tokio::test]
async fn rest_submit_rejects_a_foreign_recipient() {
    // The replay binding is the document `recipient`: a document addressed to a
    // different community is rejected `wrongRecipient` (403), replacing the
    // bespoke `audience` field.
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc["recipient"] = json!("did:webvh:other.example.com:xyz");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a document addressed to another community must be rejected: {body}"
    );
    assert_eq!(tt_error_code(&body), "wrongRecipient");
}

#[tokio::test]
async fn rest_submit_rejects_an_expired_document() {
    // Freshness is the document `expiresAt`: a stale (expired) document is
    // rejected `expired` (400), replacing the bespoke `created` window.
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc["expiresAt"] = json!("2000-01-01T00:00:00Z");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an expired document must be rejected: {body}"
    );
    assert_eq!(tt_error_code(&body), "expired");
}

// ---------------------------------------------------------------------------
// M1.9.1 — list + show
// ---------------------------------------------------------------------------

async fn submit_pending(fix: &Fixture) -> Uuid {
    let vp = json!({"a":"b"});
    let (_did, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "submit_pending: {body}");
    Uuid::parse_str(tt_payload(&body)["requestId"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn list_returns_pending_by_default() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/join-requests",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], id.to_string());
    assert_eq!(items[0]["status"], "pending");
}

#[tokio::test]
async fn show_returns_full_request_including_vp() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (status, body) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "pending");
    assert!(body["vp"].is_object());
}

// ---------------------------------------------------------------------------
// M1.10.1 — approve + reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_writes_acl_and_member_atomically() {
    let fix = build_fixture().await;
    let (_sk, applicant_did) = applicant_pair();
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = body["payload"]["requestId"].as_str().unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "approved");

    let acl = get_acl_entry(&fix.acl_ks, &applicant_did)
        .await
        .unwrap()
        .expect("ACL row written");
    assert_eq!(acl.role, VtcRole::Member);

    let member = get_member(&fix.members_ks, &applicant_did)
        .await
        .unwrap()
        .expect("Member row written");
    assert_eq!(member.did, applicant_did);

    // M2.12: approve now mints a VMC + role VEC and stamps the
    // pointers on the Member row.
    assert!(
        member.status_list_index.is_some(),
        "approve must allocate a status-list slot"
    );
    let vmc_id = member.current_vmc_id.as_deref().expect("VMC id stamped");
    let vec_id = member
        .current_role_vec_id
        .as_deref()
        .expect("VEC id stamped");
    assert!(vmc_id.starts_with("urn:uuid:"), "got {vmc_id}");
    assert!(vec_id.starts_with("urn:uuid:"), "got {vec_id}");

    // Response carries the signed VCs inline.
    let vmc = &body["vmc"];
    let role_vec = &body["roleVec"];
    assert_eq!(vmc["id"], vmc_id);
    assert_eq!(vec_id, role_vec["id"].as_str().unwrap());

    // VMC carries the credentialStatus block pointing at the
    // allocated slot.
    let slot = member.status_list_index.unwrap();
    let cs = &vmc["credentialStatus"];
    assert_eq!(cs["statusPurpose"], "revocation");
    assert_eq!(cs["statusListIndex"], slot.to_string());

    // Both VCs verify against the fixture's signer.
    let signer = vtc_service::credentials::LocalSigner::from_ed25519_seed(
        "did:webvh:vtc.example.com:abc".into(),
        &[0xCC; 32],
    );
    let vmc_vc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(vmc.clone()).expect("VMC parses");
    signer.verify(&vmc_vc).expect("VMC proof must verify");
    let vec_vc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(role_vec.clone()).expect("VEC parses");
    signer.verify(&vec_vc).expect("VEC proof must verify");
}

#[tokio::test]
async fn approve_409_when_duplicate_acl_exists() {
    let fix = build_fixture().await;
    let (_sk, applicant_did) = applicant_pair();
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = body["payload"]["requestId"].as_str().unwrap();

    // Pre-existing ACL row collides with the approve write.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: applicant_did.clone(),
            role: VtcRole::Member,
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

    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reject_leaves_no_acl_or_member_rows() {
    let fix = build_fixture().await;
    let (_sk, applicant_did) = applicant_pair();
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = body["payload"]["requestId"].as_str().unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/reject"),
        REJECT_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "policy says no" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "rejected");

    assert!(
        get_acl_entry(&fix.acl_ks, &applicant_did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_member(&fix.members_ks, &applicant_did)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn approve_404_for_unknown_id() {
    let fix = build_fixture().await;
    let id = Uuid::new_v4();
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_409_when_request_already_decided() {
    let fix = build_fixture().await;
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = body["payload"]["requestId"].as_str().unwrap();

    // First approve — succeeds.
    let _ = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    // Second approve — 409.
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reject_rejects_overlong_reason() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let huge = "x".repeat(1025);
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/reject"),
        REJECT_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": huge })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Auth gating sanity check
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// M2.6 — Policy step at submit time
// ---------------------------------------------------------------------------

/// Upload + activate a join policy. The active pointer is flipped
/// server-side; subsequent submits see the new policy's semantics.
async fn activate_join_policy(fix: &Fixture, source: &str) {
    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/policies",
        POLICY_UPLOAD_TASK,
        Some(&fix.admin_token),
        Some(json!({ "name": "join", "module": source, "ext": { "org.openvtc.purpose": "join" } })),
    )
    .await;
    // Canonical upsert: 201 when this is the first revision for the
    // purpose, 200 when it revises an existing one. Fixtures may have
    // seeded a policy already, so both are success here.
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "upload failed ({status}): {body}"
    );
    let id = body["policy"]["id"].as_str().unwrap();
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/policies/{id}/activate"),
        POLICY_ACTIVATE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate failed: {body}");
}

async fn activate_deny_all_join_policy(fix: &Fixture) {
    activate_join_policy(
        fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"closed\"}}\n",
    )
    .await;
}

/// An `allow` join policy auto-admits: the submit handler runs the
/// Admit effect, the row lands `approved`, the membership credentials
/// come back inline, and the applicant is now a member.
#[tokio::test]
async fn rest_submit_under_allow_policy_auto_admits() {
    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let (_sk, applicant_did) = applicant_pair();
    let vp = json!({ "type": "VerifiablePresentation" });
    let (_d, doc) = submit_doc(&vp).await;

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "allow", "allow policy auto-admits");
    let with = &tt_payload(&body)["verdict"]["with"];
    assert!(with["vmc"]["id"].is_string(), "VMC returned inline: {body}");
    assert!(
        with["roleVec"]["id"].is_string(),
        "role VEC returned: {body}"
    );

    // The applicant is now a member (ACL + Member rows exist).
    let acl = vtc_service::acl::get_acl_entry(&fix.acl_ks, &applicant_did)
        .await
        .unwrap()
        .expect("auto-admitted applicant has an ACL row");
    assert_eq!(acl.role, VtcRole::Member);
    assert!(
        vtc_service::members::get_member(&fix.members_ks, &applicant_did)
            .await
            .unwrap()
            .is_some(),
        "auto-admitted applicant has a Member row"
    );
}

/// The three audit envelopes an admit effect must emit, collected from the
/// audit keyspace.
#[derive(Default)]
struct AdmitAudit {
    member_added: Vec<MemberAddedData>,
    vmc_issued: Vec<CredentialIssuedData>,
    vec_issued: Vec<CredentialIssuedData>,
}

async fn collect_admit_audit(audit_ks: &KeyspaceHandle) -> AdmitAudit {
    let pairs = audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut out = AdmitAudit::default();
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::MemberAdded(d) => out.member_added.push(d),
            AuditEvent::VmcIssued(d) => out.vmc_issued.push(d),
            AuditEvent::VecIssued(d) => out.vec_issued.push(d),
            _ => {}
        }
    }
    out
}

/// Regression for the auto-admit audit gap: policy auto-admit runs the same
/// Admit effect as a manual approve (mints a VMC + role VEC, burns a status
/// slot), so it must emit the same `MemberAdded` + `VmcIssued` + `VecIssued`
/// envelopes. Before the shared `audit::emit_admit_audit` helper, the
/// auto-admit path emitted none of them — credentials were issued with no
/// audit trail.
#[tokio::test]
async fn auto_admit_emits_membership_issuance_audit() {
    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let vp = json!({ "type": "VerifiablePresentation" });
    let (_d, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "allow");

    let audit = collect_admit_audit(&fix.state.audit_ks).await;
    assert_eq!(
        audit.member_added.len(),
        1,
        "auto-admit must emit exactly one MemberAdded"
    );
    assert_eq!(audit.member_added[0].role, "member");
    assert!(
        audit.member_added[0].via_join_request_id.is_some(),
        "MemberAdded must link the originating join request"
    );
    assert_eq!(audit.vmc_issued.len(), 1, "auto-admit must emit VmcIssued");
    assert!(
        audit.vmc_issued[0].status_list_index.is_some(),
        "the VMC carries its allocated status-list slot"
    );
    assert_eq!(audit.vec_issued.len(), 1, "auto-admit must emit VecIssued");
    assert!(
        audit.vec_issued[0].status_list_index.is_none(),
        "the role VEC has no status-list slot"
    );
}

/// The manual-approve path emits the same admit-effect audit set, now via the
/// shared helper — pins parity with the auto-admit path so the two cannot drift
/// again.
#[tokio::test]
async fn manual_approve_emits_membership_issuance_audit() {
    let fix = build_fixture().await;
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = body["payload"]["requestId"].as_str().unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");

    let audit = collect_admit_audit(&fix.state.audit_ks).await;
    assert_eq!(audit.member_added.len(), 1, "approve emits one MemberAdded");
    assert_eq!(audit.member_added[0].role, "member");
    assert!(audit.member_added[0].via_join_request_id.is_some());
    assert_eq!(audit.vmc_issued.len(), 1, "approve emits VmcIssued");
    assert!(audit.vmc_issued[0].status_list_index.is_some());
    assert_eq!(audit.vec_issued.len(), 1, "approve emits VecIssued");
    assert!(audit.vec_issued[0].status_list_index.is_none());
}

/// With the default `policies.open` join policy the submit
/// handler routes through the policy step and lands the row as
/// Pending. The `vpClaims` projection is populated from the VP
/// on the request row.
#[tokio::test]
async fn rest_submit_under_default_join_policy_lands_pending_with_vp_claims() {
    let fix = build_fixture().await;
    let (_sk, applicant_did) = applicant_pair();
    let vp = json!({
        "type": "VerifiablePresentation",
        "holder": applicant_did,
        "verifiableCredential": [
            {
                "issuer": "did:key:zIssuerA",
                "type": ["VerifiableCredential", "EmailCredential"],
                "credentialSubject": { "email": "applicant@example.com" }
            }
        ]
    });
    let (_d, doc) = submit_doc(&vp).await;

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "refer");
    let id = body["payload"]["requestId"].as_str().unwrap();

    // Fetch via admin show — `vpClaims` is on the persisted row.
    let (status, row) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row["status"], "pending");
    assert!(
        row["policyDecision"].is_null(),
        "allow path must not populate policy_decision: {row}"
    );
    assert_eq!(row["vpClaims"]["holder"], applicant_did);
    let creds = row["vpClaims"]["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["issuer"], "did:key:zIssuerA");
    assert_eq!(
        creds[0]["credentialSubject"]["email"],
        "applicant@example.com"
    );
}

/// After activating a deny-all join policy, a fresh submission
/// lands as Rejected and `policy_decision` carries the regorus
/// QueryResults shape so admins can see why.
#[tokio::test]
async fn rest_submit_under_deny_all_policy_persists_rejected_with_decision() {
    let fix = build_fixture().await;
    activate_deny_all_join_policy(&fix).await;

    let vp = json!({ "type": "VerifiablePresentation" });
    let (_d, doc) = submit_doc(&vp).await;

    let (status, body) = post_tt(&fix.router, doc).await;
    // A policy `deny` is a verdict (not a framework error): the request reached
    // the policy and was refused. The reply is a `#response` (200) carrying a
    // `deny` Verdict, and the row persists Rejected.
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "deny");
    let id = body["payload"]["requestId"].as_str().unwrap();

    let (status, row) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row["status"], "rejected");
    // `policyDecision` now carries the four-valued verdict the policy
    // returned — a deny with the policy's code.
    assert_eq!(
        row["policyDecision"],
        json!({ "effect": "deny", "with": { "code": "closed" } }),
    );
}

/// Trying to re-approve a policy-rejected row fails the same way
/// admin-rejected ones do (409 already decided). Confirms the
/// policy-deny path uses the same JoinStatus::Rejected sink.
#[tokio::test]
async fn policy_rejected_row_cannot_be_approved() {
    let fix = build_fixture().await;
    activate_deny_all_join_policy(&fix).await;

    let vp = json!({ "type": "VerifiablePresentation" });
    let (_d, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "deny");
    let id = body["payload"]["requestId"].as_str().unwrap();

    let (status, _body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

// ---------------------------------------------------------------------------
// Auth gating sanity check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_requires_authentication() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "GET",
        "/v1/join-requests",
        LIST_TASK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Credential-exchange present → join decision (close-the-join-loop, part 2)
// ---------------------------------------------------------------------------

/// Build a real SD-JWT-VC `MembershipCredential` presentation bound to
/// `aud` + `nonce`, framed as an OID4VP DCQL `vp_token` map (keyed by
/// credential-query id) — exactly the shape `vta-service`'s `present_query`
/// emits. Returns `(holder_did, vp_token)`.
fn build_membership_vp_token(
    holder_seed: u8,
    aud: &str,
    nonce: &str,
    now_ts: i64,
) -> (String, Value) {
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};
    use affinidi_sd_jwt::signer::JwtSigner;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    struct SdSigner {
        key: SigningKey,
        kid: String,
    }
    impl JwtSigner for SdSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn key_id(&self) -> Option<&str> {
            Some(&self.kid)
        }
        fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
            let h = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(header).map_err(|e| SdJwtError::Verification(e.to_string()))?,
            );
            let p = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(payload).map_err(|e| SdJwtError::Verification(e.to_string()))?,
            );
            let input = format!("{h}.{p}");
            let sig = self.key.sign(input.as_bytes());
            Ok(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            ))
        }
    }

    let issuer = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
    let issuer_signer = SdSigner {
        key: SigningKey::from_bytes(&[9u8; 32]),
        kid: format!("{issuer_did}#key-0"),
    };

    let holder = SigningKey::from_bytes(&[holder_seed; 32]);
    let holder_vk = holder.verifying_key();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(holder_vk.as_bytes());
    let holder_signer = SdSigner {
        key: SigningKey::from_bytes(&[holder_seed; 32]),
        kid: format!(
            "{holder_did}#{}",
            holder_did.strip_prefix("did:key:").unwrap()
        ),
    };

    let vct = "https://openvtc.org/credentials/MembershipCredential";
    let claims = json!({
        "iss": issuer_did, "sub": holder_did, "vct": vct,
        "iat": now_ts, "exp": now_ts + 3600, "givenName": "Alice"
    });
    let frame = json!({ "_sd": ["givenName"] });
    let hasher = Sha256Hasher;
    let holder_jwk = json!({
        "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(holder_vk.to_bytes())
    });
    let sd =
        affinidi_sd_jwt::issuer::issue(&claims, &frame, &issuer_signer, &hasher, Some(&holder_jwk))
            .unwrap();
    let selected = select_disclosures(&sd, &["givenName"]);
    let kb = KbJwtInput {
        audience: aud,
        nonce,
        signer: &holder_signer,
        iat: now_ts as u64,
    };
    let presentation = present(&sd, &selected, Some(&kb), &hasher).unwrap();
    (
        holder_did,
        json!({ "membership": presentation.serialize() }),
    )
}

const VTC_AUD: &str = "did:webvh:vtc.example.com:abc";

/// A cryptographically-verified credential-exchange presentation drives the join
/// decision: under an `allow` policy the holder is auto-admitted and the
/// MembershipCredential is issued inline.
#[tokio::test]
async fn credential_exchange_present_auto_admits_under_allow_policy() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let now = chrono::Utc::now();
    let nonce = "vtc-issued-nonce-1";
    let (holder_did, vp_token) = build_membership_vp_token(0x42, VTC_AUD, nonce, now.timestamp());

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");

    assert_eq!(outcome.request.status, JoinStatus::Approved);
    assert!(
        outcome.admit.is_some(),
        "MembershipCredential issued on allow"
    );
    // The proven holder is now a member.
    let acl = vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
        .await
        .unwrap()
        .expect("auto-admitted holder has an ACL row");
    assert_eq!(acl.role, VtcRole::Member);
    assert!(
        vtc_service::members::get_member(&fix.members_ks, &holder_did)
            .await
            .unwrap()
            .is_some(),
        "auto-admitted holder has a Member row"
    );
}

/// Under the default join policy a verified presentation lands `pending` (the
/// decision pipeline routed it; no auto-admit).
#[tokio::test]
async fn credential_exchange_present_defers_under_default_policy() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    let now = chrono::Utc::now();
    let nonce = "n";
    let (_holder, vp_token) = build_membership_vp_token(0x43, VTC_AUD, nonce, now.timestamp());

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");

    assert_eq!(outcome.request.status, JoinStatus::Pending);
    assert!(outcome.admit.is_none());
}

/// A presentation bound to a different nonce than the verifier expects is
/// refused — no decision runs (replay / wrong-challenge protection at the
/// crypto layer).
#[tokio::test]
async fn credential_exchange_present_rejects_a_wrong_nonce() {
    use vtc_service::join::JoinTransport;
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    let now = chrono::Utc::now();
    let (_holder, vp_token) =
        build_membership_vp_token(0x44, VTC_AUD, "right-nonce", now.timestamp());

    let refused = matches!(
        present_and_decide_join(
            &fix.state,
            &vp_token,
            VTC_AUD,
            "wrong-nonce",
            JoinTransport::DIDComm,
            now,
        )
        .await,
        Err(vti_common::error::AppError::Validation(_))
    );
    assert!(
        refused,
        "a presentation bound to a different nonce must be refused"
    );
}

/// The wire freshness model end to end: the VTC issues a single-use challenge
/// (nonce keyed by the query's thread), the holder presents bound to it, the
/// `present` handler consumes the challenge and decides — and a replay on the
/// same thread is refused (single-use). Exercises the same path the
/// `credential-exchange/present` DIDComm handler drives.
#[tokio::test]
async fn credential_exchange_present_over_a_single_use_challenge_closes_the_loop() {
    use vtc_service::credentials::present_challenge::{DEFAULT_CHALLENGE_TTL, consume, issue};
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let now = chrono::Utc::now();
    let thread = "query-thread-1";

    // VTC issues the single-use challenge it sent with its DCQL query.
    let nonce = issue(
        &fix.state.join_requests_ks,
        thread,
        VTC_AUD,
        DEFAULT_CHALLENGE_TTL,
        now,
    )
    .await
    .expect("issue challenge");

    // Holder presents bound to (aud, nonce).
    let (holder_did, vp_token) = build_membership_vp_token(0x45, VTC_AUD, &nonce, now.timestamp());

    // Handler: consume the challenge (freshness/replay), then decide.
    let challenge = consume(&fix.state.join_requests_ks, thread, now)
        .await
        .expect("consume challenge");
    assert_eq!(challenge.nonce, nonce);
    assert_eq!(challenge.aud, VTC_AUD);

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        &challenge.aud,
        &challenge.nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");
    assert_eq!(outcome.request.status, JoinStatus::Approved);
    assert!(outcome.admit.is_some(), "VMC issued on allow");
    assert!(
        vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
            .await
            .unwrap()
            .is_some(),
        "admitted holder has an ACL row"
    );

    // Replay: the challenge for this thread is gone — single-use.
    assert!(
        consume(&fix.state.join_requests_ks, thread, now)
            .await
            .is_err(),
        "a replayed presentation finds no challenge"
    );
}

/// The query-send side: an admin asks the VTC to prepare a credential-exchange
/// query from a registered Accepts criterion. The VTC issues a single-use
/// challenge (bound to its own DID) and returns the DCQL `QueryBody` to deliver;
/// the challenge is then consumable on the returned thread.
#[tokio::test]
async fn admin_query_send_prepares_a_dcql_query_and_issues_a_challenge() {
    use vtc_service::credentials::present_challenge::consume;
    use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};

    let fix = build_fixture().await;

    // A `type_values` DCQL query references no `vct_values` types, so it stores
    // without registering schemas first.
    let criterion = AcceptsCriterion {
        id: "join-evidence".into(),
        query: json!({
            "credentials": [{
                "id": "membership",
                "format": "ldp_vc",
                "meta": { "type_values": ["MembershipCredential"] }
            }]
        }),
        description: Some("present a MembershipCredential to join".into()),
        created_at: chrono::Utc::now(),
        created_by_did: ADMIN_DID.into(),
    };
    store_accepts(&fix.state.schemas_ks, &criterion)
        .await
        .expect("store accepts criterion");

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        Some(&fix.admin_token),
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "join-evidence" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let thread_id = body["threadId"].as_str().expect("threadId").to_string();
    assert_eq!(body["holderDid"], "did:key:zHolder");
    assert!(
        body["query"]["dcql_query"]["credentials"].is_array(),
        "DCQL query present: {body}"
    );
    let nonce = body["query"]["nonce"].as_str().expect("nonce").to_string();
    assert_eq!(
        body["query"]["purpose"],
        "present a MembershipCredential to join"
    );
    // No mediator is configured in the fixture, so the DIDComm push is skipped —
    // the query is returned for relay delivery.
    assert_eq!(body["delivered"], false, "no mediator → not pushed: {body}");

    // The single-use challenge is consumable on that thread, bound to the VTC DID.
    let challenge = consume(&fix.state.join_requests_ks, &thread_id, chrono::Utc::now())
        .await
        .expect("consume challenge");
    assert_eq!(challenge.aud, VTC_AUD);
    assert_eq!(challenge.nonce, nonce);
}

/// An unregistered criterion id is a 404 (no challenge issued).
#[tokio::test]
async fn admin_query_send_404s_an_unknown_criterion() {
    let fix = build_fixture().await;
    let (status, _body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        Some(&fix.admin_token),
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "does-not-exist" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The query-send route is admin-gated.
#[tokio::test]
async fn admin_query_send_requires_admin() {
    let fix = build_fixture().await;
    let (status, _body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        None,
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "join-evidence" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Accept — reciprocal VMC (join-requests/accept/1.0)
// ---------------------------------------------------------------------------

/// Submit then admin-approve an applicant, returning
/// `(member sk, member_did, request_id, vmc_id)`.
async fn admit_member(fix: &Fixture) -> (SigningKey, String, Uuid, String) {
    let (sk, member_did) = applicant_pair();
    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    let id = Uuid::parse_str(body["payload"]["requestId"].as_str().unwrap()).unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve failed: {body}");
    let vmc_id = body["vmc"]["id"].as_str().unwrap().to_string();
    (sk, member_did, id, vmc_id)
}

/// Build + sign a member-issued reciprocal VC (the counter-signature).
async fn build_reciprocal_vc(
    member_did: &str,
    vmc_id: &str,
    community_did: &str,
    id: &str,
) -> Value {
    let signer = vtc_service::credentials::LocalSigner::from_ed25519_seed(
        member_did.to_string(),
        &MEMBER_SEED,
    );
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipAcknowledgement"],
        "id": id,
        "issuer": member_did,
        "credentialSubject": { "id": community_did, "reciprocates": vmc_id },
    });
    signer.sign_doc(&mut vc).await.expect("sign reciprocal vc");
    vc
}

/// POST an accept as a Trust Task document to `/v1/trust-tasks`, signed by the
/// member's holder key (`MEMBER_SEED`) so the proof's issuer is the member DID.
async fn post_accept(fix: &Fixture, id: Uuid, vmc_id: &str, vc: &Value) -> (StatusCode, Value) {
    post_accept_signed_by(fix, &MEMBER_SEED, id, vmc_id, vc).await
}

/// As [`post_accept`] but signed by `seed` — to exercise a wrong-holder proof.
async fn post_accept_signed_by(
    fix: &Fixture,
    seed: &[u8; 32],
    id: Uuid,
    vmc_id: &str,
    vc: &Value,
) -> (StatusCode, Value) {
    let (_did, doc) = signed_trust_task_seed(
        seed,
        ACCEPT_TASK,
        json!({ "requestId": id, "vmcId": vmc_id, "vc": vc }),
    )
    .await;
    post_tt(&fix.router, doc).await
}

#[tokio::test]
async fn accept_records_the_reciprocal_edge() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let recip_id = "urn:uuid:recip-1";
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, recip_id).await;

    let (status, body) = post_accept(&fix, id, &vmc_id, &vc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["payload"]["status"], "accepted");
    assert_eq!(body["payload"]["reciprocalVcId"], recip_id);

    let member = get_member(&fix.members_ks, &member_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.reciprocal_vc_id.as_deref(), Some(recip_id));
    assert!(member.accepted_at.is_some(), "accepted_at stamped");
}

#[tokio::test]
async fn accept_is_idempotent_for_the_same_vc() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;

    let (s1, _) = post_accept(&fix, id, &vmc_id, &vc).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, b2) = post_accept(&fix, id, &vmc_id, &vc).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "re-accept of the same VC is a no-op: {b2}"
    );
    assert_eq!(b2["payload"]["reciprocalVcId"], "urn:uuid:recip-1");
}

#[tokio::test]
async fn accept_conflicts_on_a_different_vc_after_reciprocation() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc1 = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    let (s1, _) = post_accept(&fix, id, &vmc_id, &vc1).await;
    assert_eq!(s1, StatusCode::OK);

    let vc2 = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-2").await;
    let (s2, _) = post_accept(&fix, id, &vmc_id, &vc2).await;
    assert_eq!(
        s2,
        StatusCode::UNPROCESSABLE_ENTITY,
        "conflict → taskFailed"
    );
}

#[tokio::test]
async fn accept_rejects_a_wrong_holder_signature() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;

    // Signed by a different holder than the admitted member → the proven holder
    // is not the request's applicant, so the accept is refused.
    let (status, _) = post_accept_signed_by(&fix, &[0xEE; 32], id, &vmc_id, &vc).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "wrong-holder accept rejected, got {status}"
    );
}

#[tokio::test]
async fn accept_conflicts_when_not_yet_approved() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (_sk, member_did) = applicant_pair();
    // No VMC exists yet; build a placeholder vc — the status guard fires first.
    let vc = build_reciprocal_vc(&member_did, "urn:uuid:none", VTC_DID, "urn:uuid:recip-1").await;

    let (status, _) = post_accept(&fix, id, "urn:uuid:none", &vc).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "not-yet-approved → taskFailed conflict"
    );
}

#[tokio::test]
async fn accept_conflicts_on_vmc_id_mismatch() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let wrong = "urn:uuid:not-the-current-vmc";
    let vc = build_reciprocal_vc(&member_did, wrong, VTC_DID, "urn:uuid:recip-1").await;

    let (status, _) = post_accept(&fix, id, wrong, &vc).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn accept_rejects_a_reciprocal_vc_for_another_community() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    // Subject acknowledges a different community than this VTC.
    let vc = build_reciprocal_vc(
        &member_did,
        &vmc_id,
        "did:web:evil.example",
        "urn:uuid:recip-1",
    )
    .await;

    let (status, _) = post_accept(&fix, id, &vmc_id, &vc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accept_rejects_a_tampered_reciprocal_vc() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let mut vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    // Mutate the signed `id` after signing — the issuer proof no longer covers it.
    vc["id"] = json!("urn:uuid:swapped");

    let (status, _) = post_accept(&fix, id, &vmc_id, &vc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Manifest — pre-submit discovery (join-requests/manifest/1.0)
// ---------------------------------------------------------------------------

async fn store_join_criterion(fix: &Fixture) {
    use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};
    let criterion = AcceptsCriterion {
        id: "join-evidence".into(),
        query: json!({
            "credentials": [{
                "id": "membership",
                "format": "ldp_vc",
                "meta": { "type_values": ["MembershipCredential"] }
            }]
        }),
        description: Some("present a MembershipCredential to join".into()),
        created_at: chrono::Utc::now(),
        created_by_did: ADMIN_DID.into(),
    };
    store_accepts(&fix.state.schemas_ks, &criterion)
        .await
        .expect("store accepts criterion");
}

#[tokio::test]
async fn manifest_lists_registered_criteria() {
    let fix = build_fixture().await;
    store_join_criterion(&fix).await;

    let (status, body) = post_tt(&fix.router, manifest_doc()).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["communityDid"], VTC_DID);
    let criteria = payload["criteria"].as_array().unwrap();
    assert_eq!(criteria.len(), 1);
    assert_eq!(criteria[0]["id"], "join-evidence");
    assert!(criteria[0]["presentationDefinition"]["credentials"].is_array());
    assert_eq!(
        criteria[0]["description"],
        "present a MembershipCredential to join"
    );
}

#[tokio::test]
async fn manifest_is_empty_when_no_criteria_registered() {
    let fix = build_fixture().await;
    let (status, body) = post_tt(&fix.router, manifest_doc()).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["communityDid"], VTC_DID);
    assert_eq!(payload["criteria"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Status — applicant poll (join-requests/status/1.0)
// ---------------------------------------------------------------------------

/// POST a status-poll Trust Task document signed by the applicant
/// (`MEMBER_SEED`, the same key `submit_doc`/`applicant_pair` use).
async fn post_status(fix: &Fixture, id: Uuid) -> (StatusCode, Value) {
    post_status_signed_by(fix, &[0xCD; 32], id).await
}

/// As [`post_status`] but signed by `seed` — to exercise a wrong-holder proof.
async fn post_status_signed_by(fix: &Fixture, seed: &[u8; 32], id: Uuid) -> (StatusCode, Value) {
    let (_did, doc) = signed_trust_task_seed(seed, STATUS_TASK, json!({ "requestId": id })).await;
    post_tt(&fix.router, doc).await
}

/// An unsigned (public) manifest Trust Task document — manifest is a public
/// read, so it carries no holder proof, only the recipient + expiry the
/// framework's `validate_basic` checks.
fn manifest_doc() -> Value {
    json!({
        "type": MANIFEST_TASK,
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "recipient": vtc_service::test_support::TEST_VTC_DID,
        "expiresAt": "2099-01-01T00:00:00Z",
        "payload": {},
    })
}

#[tokio::test]
async fn status_returns_pending_for_the_applicant() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let (status, body) = post_status(&fix, id).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["requestId"], id.to_string());
    assert_eq!(payload["status"], "pending");
    assert!(payload.get("needs").is_none() || payload["needs"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn status_rejects_a_wrong_signer() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    // Signed by a different holder than the applicant → the proven holder does
    // not match the request's applicant, so the poll is refused.
    let (status, _) = post_status_signed_by(&fix, &[0xEE; 32], id).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "wrong-holder status rejected, got {status}"
    );
}

#[tokio::test]
async fn status_taskfailed_for_an_unknown_request() {
    let fix = build_fixture().await;
    let unknown = Uuid::new_v4();

    // A not-found maps to the framework `taskFailed` reject (422) over the
    // Trust Task endpoint, not a bare 404.
    let (status, _) = post_status(&fix, unknown).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn status_deferred_returns_needs_and_presentation_definition() {
    let fix = build_fixture().await;
    // A join policy that defers, asking for more evidence.
    activate_join_policy(
        &fix,
        r#"
package vtc.join
import future.keywords.if
default decision := {"effect": "deny", "with": {"code": "closed"}}
decision := {"effect": "request_more", "with": {
    "needs": ["agreed:code-of-conduct"],
    "presentation_definition": {"id": "pd-coc"}
}} if { true }
"#,
    )
    .await;

    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        verdict_effect(&body),
        "request_more",
        "expected request_more verdict: {body}"
    );
    let id = Uuid::parse_str(body["payload"]["requestId"].as_str().unwrap()).unwrap();

    let (status, body) = post_status(&fix, id).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["status"], "deferred");
    assert_eq!(payload["needs"][0], "agreed:code-of-conduct");
    assert_eq!(payload["presentationDefinition"]["id"], "pd-coc");
}

// ---------------------------------------------------------------------------
// P0.5 — the unauthenticated join-request POSTs (submit / accept / status)
// must sit on the governed branch (5 rps + burst 10 per source IP), like the
// recognise route — they run attacker-driven crypto + Rego eval and were
// previously on the ungoverned 1 MiB main chain. The governor is the
// outermost layer, so a flood trips 429 before the handler runs; the admin
// GET list stays on the JWT-gated `api` chain (no governor).
// ---------------------------------------------------------------------------

/// Fire rapid requests at `uri` and report whether any returned 429 — proof
/// the endpoint sits behind the unauth governor. The governor (burst 10) trips
/// well within 40 sequential in-memory requests.
async fn floods_to_429(router: &axum::Router, method: &str, uri: &str, task: &str) -> bool {
    for _ in 0..40 {
        let (status, _) = send(router, method, uri, task, None, Some(json!({}))).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn trust_tasks_post_is_rate_limited() {
    // All holder-facing join verbs (submit/accept/manifest/status) arrive on the
    // single `POST /v1/trust-tasks` document endpoint, which must sit on the
    // governed branch — a flood trips 429 before the dispatcher runs.
    let fix = build_fixture().await;
    assert!(
        floods_to_429(&fix.router, "POST", "/v1/trust-tasks", SUBMIT_TASK).await,
        "POST /v1/trust-tasks must be on the governed branch (no 429 in 40 requests)"
    );
}

/// The admin GET list stays on the `api` chain (JWT-gated, no governor): 40
/// rapid unauthenticated GETs stay `401` and never trip `429`. This is the
/// other half of the split — the POST moved, the GET did not.
#[tokio::test]
async fn admin_list_get_is_not_rate_limited() {
    let fix = build_fixture().await;
    for _ in 0..40 {
        let (status, _) = send(
            &fix.router,
            "GET",
            "/v1/join-requests",
            LIST_TASK,
            None,
            None,
        )
        .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "the admin GET list must stay off the governor (got 429)"
        );
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "unauthenticated GET list should be 401, got {status}"
        );
    }
}
