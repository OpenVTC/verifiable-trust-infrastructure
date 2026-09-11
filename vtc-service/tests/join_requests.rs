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
const SUBMIT_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/submit/0.2";
// `accept` is retired — the join close-the-loop is `members/vmc` with a
// `requestId` (one credential-delivery path).
const VMC_TASK: &str = "https://trusttasks.org/spec/vtc/members/vmc/0.1";
const MANIFEST_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/manifest/0.1";
const STATUS_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/status/0.1";
// The admin verbs remain header-gated REST routes (unchanged) — flat URIs.
// The admin GET list shares the submit mount, so it gates on the flat submit URI.
const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const SHOW_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/show/0.1";
const DECIDE_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/decide/0.1";
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
    // different community is rejected `wrongRecipient` (422), replacing the
    // bespoke `audience` field.
    //
    // 422, not 403: the HTTPS binding spec §4 puts every "understood,
    // well-formed, and refused" code in one flat bucket, so a prober cannot
    // tell wrongRecipient from expired from proofInvalid by status line alone.
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc["recipient"] = json!("did:webvh:other.example.com:xyz");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a document addressed to another community must be rejected: {body}"
    );
    assert_eq!(tt_error_code(&body), "wrongRecipient");
}

#[tokio::test]
async fn rest_submit_rejects_an_expired_document() {
    // Freshness is the document `expiresAt`: a stale (expired) document is
    // rejected `expired` (422), replacing the bespoke `created` window. Same
    // flat bucket as `wrongRecipient` above — see that test for why.
    let fix = build_fixture().await;
    let vp = json!({});
    let (_did, mut doc) = submit_doc(&vp).await;
    doc["expiresAt"] = json!("2000-01-01T00:00:00Z");

    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
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
    // `show` wraps the row as `{request: …}` (#1093).
    let body = &body["request"];
    assert_eq!(body["status"], "pending");
    assert!(body["vp"].is_object());
}

// ---------------------------------------------------------------------------
// M1.10.1 — decide (approved / rejected); supersedes approve + reject
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "rejected", "reason": "policy says no" })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
    )
    .await;
    // Second approve — 409.
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "rejected", "reason": huge })),
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
    // `show` wraps the row as `{request: …}` (#1093).
    let row = &row["request"];
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
    // `show` wraps the row as `{request: …}` (#1093).
    let row = &row["request"];
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
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
fn build_vp_token(
    holder_seed: u8,
    aud: &str,
    nonce: &str,
    now_ts: i64,
    vct: &str,
    extra_claims: &[(&str, Value)],
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

    let mut claims = json!({
        "iss": issuer_did, "sub": holder_did, "vct": vct,
        "iat": now_ts, "exp": now_ts + 3600, "givenName": "Alice"
    });
    // Issuer-protected and always disclosed — `taskContext` rides here, not in
    // the `_sd` frame, because a selectively-disclosable binding is one the
    // holder can withhold from the verifier that has to enforce it.
    for (key, value) in extra_claims {
        claims[*key] = value.clone();
    }
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

/// The membership presentation every pre-existing test in this file uses.
fn build_membership_vp_token(
    holder_seed: u8,
    aud: &str,
    nonce: &str,
    now_ts: i64,
) -> (String, Value) {
    build_vp_token(
        holder_seed,
        aud,
        nonce,
        now_ts,
        "https://openvtc.org/credentials/MembershipCredential",
        &[],
    )
}

/// A `WitnessCredential` presentation, optionally carrying the `taskContext`
/// DTG Credentials marks REQUIRED on that type.
fn build_witness_vp_token(
    holder_seed: u8,
    aud: &str,
    nonce: &str,
    now_ts: i64,
    task_context: Option<&str>,
) -> (String, Value) {
    let extra: Vec<(&str, Value)> = task_context
        .map(|t| vec![("taskContext", json!(t))])
        .unwrap_or_default();
    build_vp_token(holder_seed, aud, nonce, now_ts, "WitnessCredential", &extra)
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
        "query-thread",
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
        "query-thread",
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
            "query-thread",
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
        thread,
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

// ── Trust Task Context Binding (#1065) ──────────────────────────────────────

/// A join policy that admits only on a credential issued **inside this
/// exchange**. This is what the ceremony facts have to make expressible: the
/// same credential, cryptographically identical, decides differently depending
/// on which exchange it came out of.
const SAME_EXCHANGE_ONLY_JOIN_REGO: &str = "package vtc.join\nimport rego.v1\n\n\
     default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"foreign-exchange\"}}\n\n\
     decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}} if {\n\
     \tsome c in input.evidence.presentation.credentials\n\
     \tc.task_context.state == \"sameExchange\"\n\
     }\n";

/// DTG Credentials marks `taskContext` REQUIRED on the VWC. A witness presented
/// without one is refused at receipt — and refused rather than defaulted to the
/// thread it happened to arrive on, which would manufacture the binding the
/// verifier exists to check. The `allow`-everything policy is deliberate: if the
/// refusal were happening in the policy rather than at receipt, this would admit.
#[tokio::test]
async fn credential_exchange_present_refuses_a_witness_with_no_task_context() {
    use vtc_service::join::JoinTransport;
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let now = chrono::Utc::now();
    let nonce = "n";
    let (holder_did, vp_token) =
        build_witness_vp_token(0x51, VTC_AUD, nonce, now.timestamp(), None);

    let err = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        "urn:uuid:this-exchange",
        JoinTransport::DIDComm,
        now,
    )
    .await
    .err()
    .expect("a witness with no taskContext must be refused");
    assert!(
        matches!(&err, vti_common::error::AppError::Validation(m) if m.contains("taskContext")),
        "{err:?}"
    );
    assert!(
        vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
            .await
            .unwrap()
            .is_none(),
        "the refusal must land before the decision, so nothing is admitted"
    );
}

/// The bound case: a witness naming this exchange satisfies a policy that
/// requires it.
#[tokio::test]
async fn a_witness_from_this_exchange_satisfies_a_same_exchange_policy() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(&fix, SAME_EXCHANGE_ONLY_JOIN_REGO).await;

    let now = chrono::Utc::now();
    let nonce = "n";
    let thread = "urn:uuid:this-exchange";
    let (holder_did, vp_token) =
        build_witness_vp_token(0x52, VTC_AUD, nonce, now.timestamp(), Some(thread));

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        thread,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");

    assert_eq!(outcome.request.status, JoinStatus::Approved);
    assert!(
        vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
            .await
            .unwrap()
            .is_some(),
        "a witness bound to this exchange admits under the same-exchange policy"
    );
}

/// Context collapse, and the whole point of #1065: the *same* well-formed,
/// signed, in-date witness — differing only in the exchange its `taskContext`
/// names — cannot satisfy the rule it satisfies above. Without the binding in
/// the facts these two presentations are indistinguishable to the policy.
#[tokio::test]
async fn a_witness_from_another_exchange_cannot_satisfy_this_one() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(&fix, SAME_EXCHANGE_ONLY_JOIN_REGO).await;

    let now = chrono::Utc::now();
    let nonce = "n";
    let (holder_did, vp_token) = build_witness_vp_token(
        0x53,
        VTC_AUD,
        nonce,
        now.timestamp(),
        Some("urn:uuid:some-other-exchange"),
    );

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        "urn:uuid:this-exchange",
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("a foreign taskContext is not a rejection at receipt — the policy decides");

    assert_eq!(
        outcome.request.status,
        JoinStatus::Rejected,
        "a witness from another exchange must not satisfy a same-exchange rule"
    );
    assert!(
        vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
            .await
            .unwrap()
            .is_none(),
        "and must not admit"
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
        vetting: None,
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
// Close-the-loop — `members/vmc` with `requestId` (supersedes the retired
// `join-requests/accept`): the admitted member delivers their member-issued
// MembershipCredential and names the approved request it reciprocates.
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
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "approved" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve failed: {body}");
    let vmc_id = body["vmc"]["id"].as_str().unwrap().to_string();
    (sk, member_did, id, vmc_id)
}

/// Build + sign a member-issued MembershipCredential (the member → community
/// half of the pair, and — when delivered with a `requestId` — the reciprocal
/// that closes the join).
async fn build_member_vmc(member_did: &str, community_did: &str, id: &str) -> Value {
    let signer = vtc_service::credentials::LocalSigner::from_ed25519_seed(
        member_did.to_string(),
        &MEMBER_SEED,
    );
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "id": id,
        "issuer": member_did,
        "credentialSubject": { "id": community_did },
    });
    signer.sign_doc(&mut vc).await.expect("sign member vmc");
    vc
}

/// POST a `members/vmc` Trust Task document (with a `requestId`) to
/// `/v1/trust-tasks`, signed by the member's holder key (`MEMBER_SEED`) so the
/// proof's issuer is the member DID.
async fn post_vmc(fix: &Fixture, id: Uuid, vc: &Value) -> (StatusCode, Value) {
    post_vmc_signed_by(fix, &MEMBER_SEED, id, vc).await
}

/// As [`post_vmc`] but signed by `seed` — to exercise a wrong-holder proof.
async fn post_vmc_signed_by(
    fix: &Fixture,
    seed: &[u8; 32],
    id: Uuid,
    vc: &Value,
) -> (StatusCode, Value) {
    let (_did, doc) =
        signed_trust_task_seed(seed, VMC_TASK, json!({ "requestId": id, "vc": vc })).await;
    post_tt(&fix.router, doc).await
}

#[tokio::test]
async fn vmc_with_request_id_records_the_reciprocal_edge() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let recip_id = "urn:uuid:recip-1";
    let vc = build_member_vmc(&member_did, VTC_DID, recip_id).await;

    let (status, body) = post_vmc(&fix, id, &vc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["payload"]["status"], "stored");
    assert_eq!(body["payload"]["vmcId"], recip_id);
    assert_eq!(body["payload"]["requestId"], id.to_string());

    let member = get_member(&fix.members_ks, &member_did)
        .await
        .unwrap()
        .unwrap();
    // The delivered credential is stored as the member's half of the pair AND
    // recorded as the reciprocal that closed the join.
    assert_eq!(member.member_vmc_id.as_deref(), Some(recip_id));
    assert_eq!(member.reciprocal_vc_id.as_deref(), Some(recip_id));
    assert!(member.accepted_at.is_some(), "accepted_at stamped");
}

#[tokio::test]
async fn vmc_with_request_id_is_idempotent_for_the_same_vc() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;

    let (s1, _) = post_vmc(&fix, id, &vc).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, b2) = post_vmc(&fix, id, &vc).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "re-delivery of the same VC is a no-op: {b2}"
    );
    assert_eq!(b2["payload"]["vmcId"], "urn:uuid:recip-1");
    assert_eq!(b2["payload"]["requestId"], id.to_string());
}

#[tokio::test]
async fn vmc_with_request_id_replaces_on_a_different_vc() {
    // The vmc task's renewal semantics carry over to the merged path: a
    // *different* credential re-delivered with the same requestId replaces
    // the stored half (the member rotated/reissued), it does not conflict
    // the way the retired accept task did.
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let vc1 = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;
    let (s1, _) = post_vmc(&fix, id, &vc1).await;
    assert_eq!(s1, StatusCode::OK);

    let vc2 = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-2").await;
    let (s2, _) = post_vmc(&fix, id, &vc2).await;
    assert_eq!(s2, StatusCode::OK, "renewal replaces the stored half");

    let member = get_member(&fix.members_ks, &member_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.member_vmc_id.as_deref(), Some("urn:uuid:recip-2"));
    assert_eq!(member.reciprocal_vc_id.as_deref(), Some("urn:uuid:recip-2"));
}

#[tokio::test]
async fn vmc_rejects_a_wrong_holder_signature() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;

    // Signed by a different holder than the admitted member → the proven
    // holder is not the credential's issuer, so the delivery is refused.
    let (status, _) = post_vmc_signed_by(&fix, &[0xEE; 32], id, &vc).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "wrong-holder delivery rejected, got {status}"
    );
}

#[tokio::test]
async fn vmc_conflicts_when_request_not_yet_approved() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (_sk, member_did) = applicant_pair();
    let vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;

    let (status, _) = post_vmc(&fix, id, &vc).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "not-yet-approved → taskFailed conflict"
    );
}

#[tokio::test]
async fn vmc_taskfailed_for_an_unknown_request_id() {
    let fix = build_fixture().await;
    let (_sk, member_did, _id, _vmc_id) = admit_member(&fix).await;
    let vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;

    let (status, _) = post_vmc(&fix, Uuid::new_v4(), &vc).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn vmc_rejects_a_credential_for_another_community() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    // Subject names a different community than this VTC.
    let vc = build_member_vmc(&member_did, "did:web:evil.example", "urn:uuid:recip-1").await;

    let (status, _) = post_vmc(&fix, id, &vc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn vmc_rejects_a_tampered_credential() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let mut vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;
    // Mutate the signed `id` after signing — the issuer proof no longer covers it.
    vc["id"] = json!("urn:uuid:swapped");

    let (status, _) = post_vmc(&fix, id, &vc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn retired_accept_type_is_no_longer_dispatched() {
    // Clean cutover: `join-requests/accept/0.1` is retired upstream and the
    // dispatcher no longer routes it — an accept document gets the framework
    // `UnsupportedType` reject, not a handler.
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc = build_member_vmc(&member_did, VTC_DID, "urn:uuid:recip-1").await;
    let (_did, doc) = signed_trust_task_seed(
        &MEMBER_SEED,
        "https://trusttasks.org/spec/vtc/join-requests/accept/0.1",
        json!({ "requestId": id, "vmcId": vmc_id, "vc": vc }),
    )
    .await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_ne!(status, StatusCode::OK, "accept must not dispatch: {body}");
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
        vetting: None,
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

/// Manifest 0.2 advertises a criterion's vetting requirements with a digest the
/// applicant can recompute from what it received; 0.1 keeps its own shape.
#[tokio::test]
async fn manifest_0_2_advertises_vetting_requirements_and_their_digest() {
    use vta_sdk::protocols::join_requests::JOIN_REQUEST_MANIFEST_0_2_TYPE;
    use vta_sdk::vetting::requirements::requirements_digest;
    use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};

    let fix = build_fixture().await;
    let criterion = AcceptsCriterion {
        id: "kernel-developer".into(),
        query: json!({
            "credentials": [{
                "id": "vetting",
                "format": "ldp_vc",
                "meta": { "type_values": ["EndorsementCredential"] }
            }]
        }),
        description: Some("Two vetters, one in person".into()),
        vetting: Some(
            serde_json::from_value(json!({
                "version": "0.1",
                "statementType": "https://firstperson.network/endorsements/identity-vetting/0.1",
                "minStatements": 2,
                "minByMethod": { "inPerson": 1 },
                "acceptedMethods": ["inPerson", "video"],
                "eligibleVetters": { "role": "vetter" }
            }))
            .unwrap(),
        ),
        created_at: chrono::Utc::now(),
        created_by_did: ADMIN_DID.into(),
    };
    store_accepts(&fix.state.schemas_ks, &criterion)
        .await
        .expect("store vetting criterion");

    let mut doc = manifest_doc();
    doc["type"] = json!(JOIN_REQUEST_MANIFEST_0_2_TYPE);
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let c = &tt_payload(&body)["criteria"][0];
    assert_eq!(c["vetting"]["minStatements"], 2);
    assert_eq!(c["vetting"]["minByMethod"]["inPerson"], 1);
    assert_eq!(
        c["requirementsDigest"]
            .as_str()
            .expect("0.2 carries a digest"),
        requirements_digest(c).unwrap(),
        "the applicant must be able to recompute the digest from the criterion it received"
    );

    let (status, body) = post_tt(&fix.router, manifest_doc()).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let c = &tt_payload(&body)["criteria"][0];
    assert!(c.get("vetting").is_none(), "0.1 keeps its shape: {c}");
    assert!(
        c.get("requirementsDigest").is_none(),
        "0.1 keeps its shape: {c}"
    );
}

// ---------------------------------------------------------------------------
// Peer identity vetting — statements counted at submit (OpenVTC vetting design §10)
// ---------------------------------------------------------------------------

/// A `did:key` secret from a fixed seed, as `signed_trust_task_seed` builds one.
fn did_key_secret(seed: [u8; 32]) -> (String, Secret) {
    let mut secret = Secret::generate_ed25519(None, Some(&seed));
    let pub_mb = secret.get_public_keymultibase().expect("pubkey multibase");
    let did = format!("did:key:{pub_mb}");
    secret.id = format!("{did}#{pub_mb}");
    (did, secret)
}

const VETTER_GRANT_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
const ENDORSEMENT_REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";

/// Name `did` a vetter through `POST /v1/vetting/vetters`, as the admin.
async fn grant_vetter(fix: &Fixture, did: &str) -> (StatusCode, Value) {
    send(
        &fix.router,
        "POST",
        "/v1/vetting/vetters",
        VETTER_GRANT_TASK,
        Some(&fix.admin_token),
        Some(json!({ "memberDid": did })),
    )
    .await
}

/// A community member the admin has named a vetter through a real grant.
/// Returns the grant's endorsement id.
async fn seed_vetter(fix: &Fixture, did: &str) -> String {
    seed_member(fix, did).await;
    let (status, body) = grant_vetter(fix, did).await;
    assert_eq!(status, StatusCode::CREATED, "grant vetter: {body}");
    body["endorsementId"]
        .as_str()
        .expect("endorsementId")
        .to_string()
}

/// The community's grant rows for `did`.
async fn grants_of(fix: &Fixture, did: &str) -> Vec<vtc_service::endorsements::Endorsement> {
    vtc_service::endorsements::endorsements_for_subject(
        &fix.state.endorsements_ks,
        did,
        vta_sdk::protocols::vetting::COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await
    .expect("read grants")
}

/// A community member, admitted a month ago. Holding no vetter grant.
async fn seed_member(fix: &Fixture, did: &str) {
    let mut member = vtc_service::members::Member::fresh(did);
    member.joined_at = chrono::Utc::now() - chrono::Duration::days(30);
    vtc_service::members::storage::store_member(&fix.members_ks, &member)
        .await
        .expect("store member");
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: ADMIN_DID.into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("store acl");
}

/// Two distinct eligible vetters, video or in person, `name.legal` verified.
async fn store_vetting_criterion(fix: &Fixture) {
    use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};
    store_accepts(
        &fix.state.schemas_ks,
        &AcceptsCriterion {
            id: "kernel-developer".into(),
            query: json!({
                "credentials": [{
                    "id": "vetting",
                    "format": "ldp_vc",
                    "meta": { "type_values": ["EndorsementCredential"] }
                }]
            }),
            description: Some("Two vetters".into()),
            vetting: Some(
                serde_json::from_value(json!({
                    "version": "0.1",
                    "statementType": vta_sdk::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE,
                    "minStatements": 2,
                    "acceptedMethods": ["inPerson", "video"],
                    "requiredClaims": ["name.legal"],
                    "eligibleVetters": { "role": "vetter" },
                    "independence": { "requireConsistentIdentityCommitment": true }
                }))
                .unwrap(),
            ),
            created_at: chrono::Utc::now(),
            created_by_did: ADMIN_DID.into(),
        },
    )
    .await
    .expect("store vetting criterion");
}

/// A Vetting Statement signed by `vetter` about `applicant`, valid from now —
/// after any grant the test made first.
async fn vetting_statement(vetter: &Secret, applicant: &str, n: u8) -> Value {
    vetting_statement_from(vetter, applicant, n, chrono::Utc::now()).await
}

/// As [`vetting_statement`], valid from `valid_from`.
async fn vetting_statement_from(
    vetter: &Secret,
    applicant: &str,
    n: u8,
    valid_from: chrono::DateTime<chrono::Utc>,
) -> Value {
    use vta_sdk::protocols::vetting::{
        DeclaredRelationship, IDENTITY_VETTING_ENDORSEMENT_TYPE, IdentityVettingEndorsement,
        VettingMethod,
    };
    use vta_sdk::vetting::statement::{StatementDraft, sign_statement};
    let now = valid_from;
    sign_statement(
        StatementDraft {
            id: format!("urn:uuid:statement-{n}"),
            issuer: vetter.id.split('#').next().unwrap().to_string(),
            subject: applicant.to_string(),
            endorsement: IdentityVettingEndorsement {
                endorsement_type: IDENTITY_VETTING_ENDORSEMENT_TYPE.into(),
                community: vtc_service::test_support::TEST_VTC_DID.into(),
                method: VettingMethod::Video,
                document_classes: vec!["passport".into()],
                claims_verified: vec!["name.legal".into()],
                liveness_confirmed: true,
                identity_commitment: "zSameIdentity".into(),
                card_digest_multibase: format!("zCard{n}"),
                declared_relationship: DeclaredRelationship::None,
                attestation_text_digest: None,
            },
            valid_from: now,
            valid_until: now + chrono::Duration::days(90),
            task_context: format!("urn:uuid:session-{n}"),
        },
        vetter,
    )
    .await
    .expect("sign vetting statement")
}

fn vetting_vp(applicant: &str, statements: Vec<Value>) -> Value {
    json!({
        "type": "VerifiablePresentation",
        "holder": applicant,
        "verifiableCredential": statements,
    })
}

#[tokio::test]
async fn vetted_applicant_with_two_eligible_vetters_is_admitted() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    seed_vetter(&fix, &carol).await;
    seed_vetter(&fix, &dave).await;

    let vp = vetting_vp(
        &applicant,
        vec![
            vetting_statement(&carol_key, &applicant, 1).await,
            vetting_statement(&dave_key, &applicant, 2).await,
        ],
    );
    let (_did, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "allow", "got {body}");
    assert!(
        get_member(&fix.members_ks, &applicant)
            .await
            .unwrap()
            .is_some(),
        "an allowed vetted join admits the applicant"
    );
}

#[tokio::test]
async fn one_statement_short_asks_for_exactly_what_is_missing() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    seed_vetter(&fix, &carol).await;

    let vp = vetting_vp(
        &applicant,
        vec![vetting_statement(&carol_key, &applicant, 1).await],
    );
    let (_did, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    // The wire spells the effect lowerCamelCase; Rego authors it `request_more`.
    assert_eq!(verdict_effect(&body), "requestMore", "got {body}");
    assert_eq!(
        body.pointer("/payload/verdict/with/needs"),
        Some(&json!(["vetting:statements:1"])),
        "the host expands the policy's generic need into the shortfall: {body}"
    );
    assert!(
        get_member(&fix.members_ks, &applicant)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_statement_from_a_member_who_is_not_a_vetter_does_not_count() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (erin, erin_key) = did_key_secret([0x33; 32]);
    seed_vetter(&fix, &carol).await;
    seed_member(&fix, &erin).await;

    let vp = vetting_vp(
        &applicant,
        vec![
            vetting_statement(&carol_key, &applicant, 1).await,
            vetting_statement(&erin_key, &applicant, 2).await,
        ],
    );
    let (_did, doc) = submit_doc(&vp).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    // The wire spells the effect lowerCamelCase; Rego authors it `request_more`.
    assert_eq!(verdict_effect(&body), "requestMore", "got {body}");
    assert_eq!(
        body.pointer("/payload/verdict/with/needs"),
        Some(&json!(["vetting:statements:1"])),
        "{body}"
    );
}

#[tokio::test]
async fn a_withdrawn_statement_stops_counting() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    seed_vetter(&fix, &carol).await;
    seed_vetter(&fix, &dave).await;
    let from_carol = vetting_statement(&carol_key, &applicant, 1).await;
    let from_dave = vetting_statement(&dave_key, &applicant, 2).await;

    let (status, body) = post_tt(&fix.router, withdrawal_doc([0x11; 32], &from_carol).await).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert!(tt_payload(&body)["recordedAt"].is_string(), "{body}");

    let (_did, doc) = submit_doc(&vetting_vp(&applicant, vec![from_carol, from_dave])).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "requestMore", "got {body}");
    assert_eq!(
        body.pointer("/payload/verdict/with/needs"),
        Some(&json!(["vetting:statements:1"])),
        "the withdrawn statement no longer counts: {body}"
    );
}

#[tokio::test]
async fn nobody_can_withdraw_a_statement_someone_else_signed() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    let (erin, _) = did_key_secret([0x33; 32]);
    seed_vetter(&fix, &carol).await;
    seed_vetter(&fix, &dave).await;
    seed_member(&fix, &erin).await;
    let from_carol = vetting_statement(&carol_key, &applicant, 1).await;
    let from_dave = vetting_statement(&dave_key, &applicant, 2).await;

    // Erin is a member, so the notice is accepted — and recorded under Erin,
    // where it matches no statement Erin signed.
    let (status, body) = post_tt(&fix.router, withdrawal_doc([0x33; 32], &from_carol).await).await;
    assert_eq!(status, StatusCode::OK, "got {body}");

    let (_did, doc) = submit_doc(&vetting_vp(&applicant, vec![from_carol, from_dave])).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(
        verdict_effect(&body),
        "allow",
        "Carol's statement still counts: {body}"
    );
}

#[tokio::test]
async fn a_non_member_cannot_send_a_withdrawal() {
    let fix = build_fixture().await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (_carol, carol_key) = did_key_secret([0x11; 32]);
    let statement = vetting_statement(&carol_key, &applicant, 1).await;
    let (status, body) = post_tt(&fix.router, withdrawal_doc([0x44; 32], &statement).await).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a stranger's notice must be refused: {body}"
    );
}

#[tokio::test]
async fn a_revoked_vetter_grant_stops_a_statement_counting() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    seed_vetter(&fix, &carol).await;
    let daves_grant = seed_vetter(&fix, &dave).await;
    let from_carol = vetting_statement(&carol_key, &applicant, 1).await;
    let from_dave = vetting_statement(&dave_key, &applicant, 2).await;

    // Withdrawn after Dave signed: revocation is read as it stands at submit.
    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/credentials/endorsements/{daves_grant}"),
        ENDORSEMENT_REVOKE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke grant: {body}");

    let (_did, doc) = submit_doc(&vetting_vp(&applicant, vec![from_carol, from_dave])).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "requestMore", "got {body}");
    assert_eq!(
        body.pointer("/payload/verdict/with/needs"),
        Some(&json!(["vetting:statements:1"])),
        "a statement from a vetter whose grant was revoked no longer counts: {body}"
    );
}

#[tokio::test]
async fn a_grant_made_after_a_statement_was_signed_does_not_count_it() {
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    seed_vetter(&fix, &carol).await;
    seed_member(&fix, &dave).await;
    let from_carol = vetting_statement(&carol_key, &applicant, 1).await;
    // Signed an hour before Dave was named a vetter.
    let from_dave = vetting_statement_from(
        &dave_key,
        &applicant,
        2,
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await;
    let (status, body) = grant_vetter(&fix, &dave).await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");

    let (_did, doc) = submit_doc(&vetting_vp(&applicant, vec![from_carol, from_dave])).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(verdict_effect(&body), "requestMore", "got {body}");
    assert_eq!(
        body.pointer("/payload/verdict/with/needs"),
        Some(&json!(["vetting:statements:1"])),
        "a grant does not reach back to a statement signed before it: {body}"
    );
}

#[tokio::test]
async fn a_non_member_cannot_be_named_a_vetter() {
    let fix = build_fixture().await;
    let (stranger, _) = did_key_secret([0x44; 32]);
    let (status, body) = grant_vetter(&fix, &stranger).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert!(grants_of(&fix, &stranger).await.is_empty());
}

/// The grant is also a Trust Task document. A member who is not an admin sends
/// one and is refused; nothing is issued.
#[tokio::test]
async fn only_an_admin_can_name_a_vetter() {
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    let (erin, _) = did_key_secret([0x33; 32]);
    seed_member(&fix, &carol).await;
    seed_member(&fix, &erin).await;
    let (_did, doc) = signed_trust_task_seed(
        &[0x33; 32],
        VETTER_GRANT_TASK,
        json!({ "memberDid": carol }),
    )
    .await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a member's grant must be refused: {body}"
    );
    assert!(grants_of(&fix, &carol).await.is_empty());
}

/// What the member receives: a vetter role credential with a revocation entry,
/// which they can present to an applicant who checks it offline with
/// `vta_sdk::vetting::eligibility`.
#[tokio::test]
async fn the_vetter_role_credential_is_revocable_and_verifies_for_an_applicant() {
    use vta_sdk::protocols::vetting::VetterGrantBody;
    use vta_sdk::trust_task_proof::TrustTaskVmResolver;
    use vta_sdk::vetting::eligibility::{
        EligibilityExpectations, build_eligibility_vp, verify_eligibility_vp,
    };

    // A did:key community, so the applicant's check resolves without a network.
    let (community, community_key) = did_key_secret([0xC0; 32]);
    let signer = Arc::new(vtc_service::credentials::LocalSigner::new(
        community.clone(),
        community_key,
    ));
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .with_credential_signer(signer)
        .build()
        .await;
    let purpose = affinidi_status_list::StatusPurpose::Revocation;
    vtc_service::status_list::ensure_initial(
        &vtc.state.status_lists_ks,
        purpose,
        format!("{RP_ORIGIN}/v1/status-lists/{purpose}"),
    )
    .await
    .expect("ensure_initial status list");
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    let (vetter, vetter_key) = did_key_secret([0x11; 32]);
    vtc_service::members::storage::store_member(
        &vtc.state.members_ks,
        &vtc_service::members::Member::fresh(&vetter),
    )
    .await
    .unwrap();

    let grant = vtc_service::vetting::vetters::grant(
        &vtc.state,
        ADMIN_DID,
        &VetterGrantBody {
            member_did: vetter.clone(),
            validity_seconds: Some(30 * 86_400),
            ext: None,
        },
    )
    .await
    .expect("grant");
    let credential = grant
        .credential
        .expect("a new grant carries its credential");
    assert_eq!(credential["id"], json!(grant.response.credential_id));
    assert_eq!(
        credential["credentialStatus"]["statusPurpose"],
        "revocation"
    );
    assert!(
        credential["credentialStatus"]["statusListIndex"].is_string(),
        "{credential}"
    );
    assert_eq!(
        credential["credentialSubject"]["endorsement"],
        json!({ "type": "CommunityRole", "role": "vetter", "communityDid": community })
    );
    assert_eq!(
        grant.response.valid_until - grant.response.valid_from,
        chrono::Duration::days(30)
    );

    // The vetter answers an applicant's `vetting/request`: `nonce` is that
    // request document's `id`, `domain` its `joinDid`.
    let (join_did, _) = did_key_secret(MEMBER_SEED);
    let request_id = "urn:uuid:3f1c9a52-8c1e-4f2b-9d7a-0b6e5c4d3a21";
    let vp = build_eligibility_vp(&vetter_key, vec![credential], request_id, &join_did)
        .await
        .expect("present");
    let verified = verify_eligibility_vp(
        &vp,
        &EligibilityExpectations {
            vetter: &vetter,
            community: &community,
            role: "vetter",
            challenge: request_id,
            domain: &join_did,
            now: chrono::Utc::now(),
        },
        &TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("the applicant's check accepts the community's credential");
    assert_eq!(
        verified.credential_id(),
        Some(grant.response.credential_id.as_str())
    );
    assert!(verified.credential_status().is_some());
}

#[tokio::test]
async fn naming_a_vetter_twice_returns_the_same_grant() {
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    seed_member(&fix, &carol).await;
    let (status, first) = grant_vetter(&fix, &carol).await;
    assert_eq!(status, StatusCode::CREATED, "got {first}");
    let (status, second) = grant_vetter(&fix, &carol).await;
    assert_eq!(status, StatusCode::OK, "a live grant is returned: {second}");
    assert_eq!(first["endorsementId"], second["endorsementId"]);
    assert_eq!(first["credentialId"], second["credentialId"]);
    assert_eq!(first["validUntil"], second["validUntil"]);
    assert_eq!(grants_of(&fix, &carol).await.len(), 1, "one slot, one row");
}

/// A member named a vetter in the same second they joined holds a live grant,
/// so naming them again returns it rather than issuing a duplicate.
///
/// The grant's recorded time is its credential's second-precision `validFrom`;
/// `joined_at` keeps sub-seconds. Compared as they were, a grant from the second
/// the member joined sorted before the membership and never read as live.
#[tokio::test]
async fn a_vetter_named_in_the_second_they_joined_is_not_granted_twice() {
    use chrono::{SubsecRound, Timelike};
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    seed_member(&fix, &carol).await;
    // Joined late in the current second: the grant that follows is stamped
    // with this second, and so sorts before a sub-second `joined_at`.
    let mut member = vtc_service::members::storage::get_member(&fix.members_ks, &carol)
        .await
        .unwrap()
        .expect("seeded member");
    member.joined_at = chrono::Utc::now()
        .trunc_subsecs(0)
        .with_nanosecond(999_999_999)
        .unwrap();
    vtc_service::members::storage::store_member(&fix.members_ks, &member)
        .await
        .unwrap();

    let (status, first) = grant_vetter(&fix, &carol).await;
    assert_eq!(status, StatusCode::CREATED, "got {first}");
    let (status, second) = grant_vetter(&fix, &carol).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the grant from the joining second is live and is returned: {second}"
    );
    assert_eq!(first["endorsementId"], second["endorsementId"]);
    assert_eq!(grants_of(&fix, &carol).await.len(), 1, "no duplicate grant");
}

/// A `vtc/vetting/revoke-statement/0.1` document for `statement`, signed by `seed`.
async fn withdrawal_doc(seed: [u8; 32], statement: &Value) -> Value {
    let digest = dtg_credentials::digest_multibase_json(statement).expect("statement digest");
    let (_did, doc) = signed_trust_task_seed(
        &seed,
        vta_sdk::protocols::vetting::VETTING_REVOKE_STATEMENT_TYPE,
        json!({
            "statementId": statement["id"],
            "statementDigestMultibase": digest,
            "reason": "mistake",
        }),
    )
    .await;
    doc
}

// ---------------------------------------------------------------------------
// The vetter registry: profiles, listing, resend, branding, automatic grants,
// and the admin views of vetting facts and withdrawals.
// ---------------------------------------------------------------------------

use vta_sdk::protocols::join_requests::JOIN_REQUEST_MANIFEST_0_2_TYPE;
use vta_sdk::protocols::vetting::{
    VETTING_VETTER_LIST_TYPE, VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE, VETTING_VETTER_PROFILE_TYPE,
    VETTING_VETTER_RESEND_ERR_NOT_GRANTED, VETTING_VETTER_RESEND_TYPE,
};

const RESEND_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.1";

/// An admin REST call to a route with no Trust Task binding: no `Trust-Task`
/// header at all.
async fn admin_rest(
    fix: &Fixture,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", fix.admin_token));
    let res = fix
        .router
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn day(offset: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::days(offset))
        .format("%Y-%m-%d")
        .to_string()
}

/// A profile with one event already over and one to come.
fn carols_profile(listed: bool) -> Value {
    json!({
        "listed": listed,
        "displayName": "Carol M.",
        "languages": ["en", "de-AT"],
        "location": { "country": "AT", "city": "Vienna" },
        "methods": ["inPerson", "video"],
        "acceptsDocumentation": ["passport", "none"],
        "contactHint": "Ask at the kernel-vtc table.",
        "events": [
            { "name": "Last Month's Meetup", "startDate": day(-40), "endDate": day(-38) },
            { "name": "Kernel Maintainers Meetup", "startDate": day(20), "endDate": day(22) }
        ]
    })
}

async fn publish_profile(fix: &Fixture, seed: [u8; 32], profile: Value) -> (StatusCode, Value) {
    let (_did, doc) = signed_trust_task_seed(&seed, VETTING_VETTER_PROFILE_TYPE, profile).await;
    post_tt(&fix.router, doc).await
}

/// List vetters as the applicant — not a member of the community.
async fn list_vetters(fix: &Fixture, filters: Value) -> Value {
    let (_did, doc) = signed_trust_task(VETTING_VETTER_LIST_TYPE, filters).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    tt_payload(&body)
}

fn listed_dids(page: &Value) -> Vec<String> {
    page["vetters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["vetterDid"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_vetter_publishes_a_profile_that_applicants_find_by_filter() {
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    seed_vetter(&fix, &carol).await;

    let (status, body) = publish_profile(&fix, [0x11; 32], carols_profile(true)).await;
    assert_eq!(status, StatusCode::OK, "publish: {body}");
    let stored = tt_payload(&body);
    assert_eq!(stored["listed"], true);
    assert!(stored["updatedAt"].is_string());

    let page = list_vetters(&fix, json!({})).await;
    assert_eq!(listed_dids(&page), vec![carol.clone()]);
    let entry = &page["vetters"][0];
    assert_eq!(entry["displayName"], "Carol M.");
    assert_eq!(entry["acceptsDocumentation"], json!(["passport", "none"]));
    assert!(entry["grantValidUntil"].is_string());
    assert_eq!(entry["updatedAt"], stored["updatedAt"]);
    let events = entry["events"].as_array().unwrap();
    assert_eq!(
        events.len(),
        1,
        "an event already over is not listed: {entry}"
    );
    assert_eq!(events[0]["name"], "Kernel Maintainers Meetup");
    assert!(entry.get("listed").is_none() && page.get("nextCursor").is_none());

    // One filtered request over the wire; the rest of the matrix straight
    // through the listing, since `/v1/trust-tasks` is rate limited per caller.
    assert!(listed_dids(&list_vetters(&fix, json!({ "language": "fr" })).await).is_empty());
    for (filters, found) in [
        (json!({ "language": "de" }), true),
        (json!({ "language": "DE-at" }), true),
        (
            json!({ "country": "AT", "city": "vienna", "method": "video" }),
            true,
        ),
        (json!({ "country": "DE" }), false),
        (json!({ "method": "priorAcquaintance" }), false),
        (
            json!({ "eventFrom": day(21), "eventName": "maintainers" }),
            true,
        ),
        (json!({ "eventFrom": day(-40), "eventTo": day(-38) }), false),
        (json!({ "eventName": "last month" }), false),
    ] {
        let body = serde_json::from_value(filters.clone()).unwrap();
        let page = vtc_service::vetting::profiles::list(&fix.state, &body)
            .await
            .unwrap();
        assert_eq!(
            !page.vetters.is_empty(),
            found,
            "filters {filters} gave {page:?}"
        );
    }

    // The admin view carries the profile summary.
    let (status, body) = admin_rest(&fix, "GET", "/v1/vetting/vetters", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let row = &body["vetters"][0];
    assert_eq!(row["memberDid"], carol);
    assert_eq!(row["origin"], "manual");
    assert_eq!(row["live"], true);
    assert_eq!(row["profile"]["displayName"], "Carol M.");
    assert_eq!(row["profile"]["eventCount"], 2);
}

#[tokio::test]
async fn listings_page_in_order_with_cursors_bound_to_their_filters() {
    let fix = build_fixture().await;
    let names = [
        ([0x41; 32], Some("Zed")),
        ([0x42; 32], None),
        ([0x43; 32], Some("Anna")),
    ];
    for (seed, name) in names {
        let (did, _) = did_key_secret(seed);
        seed_vetter(&fix, &did).await;
        let mut profile = carols_profile(true);
        match name {
            Some(n) => profile["displayName"] = json!(n),
            None => {
                profile.as_object_mut().unwrap().remove("displayName");
            }
        }
        let (status, body) = publish_profile(&fix, seed, profile).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (anna, _) = did_key_secret([0x43; 32]);
    let (zed, _) = did_key_secret([0x41; 32]);
    let (nameless, _) = did_key_secret([0x42; 32]);

    let first = list_vetters(&fix, json!({ "limit": 2 })).await;
    assert_eq!(listed_dids(&first), vec![anna, zed]);
    let cursor = first["nextCursor"]
        .as_str()
        .expect("a second page")
        .to_string();
    let second = list_vetters(&fix, json!({ "limit": 2, "cursor": cursor })).await;
    assert_eq!(listed_dids(&second), vec![nameless]);
    assert!(second.get("nextCursor").is_none());

    // The same cursor with other filters is refused.
    let (_did, doc) = signed_trust_task(
        VETTING_VETTER_LIST_TYPE,
        json!({ "language": "en", "cursor": cursor }),
    )
    .await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(tt_error_code(&body), "malformedRequest");
}

#[tokio::test]
async fn only_an_identified_caller_may_list_vetters() {
    let fix = build_fixture().await;
    let unsigned = json!({
        "type": VETTING_VETTER_LIST_TYPE,
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "recipient": vtc_service::test_support::TEST_VTC_DID,
        "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "payload": {},
    });
    let (status, body) = post_tt(&fix.router, unsigned).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(tt_error_code(&body), "permissionDenied", "{body}");
}

#[tokio::test]
async fn only_a_member_holding_a_live_grant_may_publish_a_profile() {
    let fix = build_fixture().await;
    let (erin, _) = did_key_secret([0x33; 32]);
    seed_member(&fix, &erin).await;
    let (status, body) = publish_profile(&fix, [0x33; 32], carols_profile(true)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        tt_error_code(&body),
        VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE
    );

    // A profile that breaks its bounds is malformed, grant or not.
    let (carol, _) = did_key_secret([0x11; 32]);
    seed_vetter(&fix, &carol).await;
    let mut too_long = carols_profile(true);
    too_long["events"][1]["endDate"] = json!(day(60));
    let (status, body) = publish_profile(&fix, [0x11; 32], too_long).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(tt_error_code(&body), "malformedRequest");
}

#[tokio::test]
async fn unlisting_hides_a_profile_and_revoking_the_grant_deletes_it() {
    use vtc_service::vetting::profiles::get_profile;
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    let grant = seed_vetter(&fix, &carol).await;

    publish_profile(&fix, [0x11; 32], carols_profile(false)).await;
    assert!(listed_dids(&list_vetters(&fix, json!({})).await).is_empty());
    assert!(
        get_profile(&fix.state.vetter_profiles_ks, &carol)
            .await
            .unwrap()
            .is_some(),
        "an unlisted profile is kept"
    );

    publish_profile(&fix, [0x11; 32], carols_profile(true)).await;
    assert_eq!(listed_dids(&list_vetters(&fix, json!({})).await).len(), 1);

    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/credentials/endorsements/{grant}"),
        ENDORSEMENT_REVOKE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke grant: {body}");
    assert!(
        get_profile(&fix.state.vetter_profiles_ks, &carol)
            .await
            .unwrap()
            .is_none(),
        "revoking the grant deletes the profile"
    );
    assert!(listed_dids(&list_vetters(&fix, json!({})).await).is_empty());
}

#[tokio::test]
async fn an_older_profile_document_does_not_replace_a_newer_one() {
    use vta_sdk::protocols::vetting::VetterProfileBody;
    use vtc_service::vetting::profiles::publish;
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    seed_vetter(&fix, &carol).await;
    let body: VetterProfileBody = serde_json::from_value(carols_profile(true)).unwrap();
    let now = chrono::Utc::now();

    publish(&fix.state, &carol, &body, Some(now)).await.unwrap();
    let stale = publish(
        &fix.state,
        &carol,
        &body,
        Some(now - chrono::Duration::hours(1)),
    )
    .await;
    assert!(
        matches!(stale, Err(vti_common::error::AppError::Validation(_))),
        "{stale:?}"
    );
    publish(
        &fix.state,
        &carol,
        &body,
        Some(now + chrono::Duration::hours(1)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_vetter_asks_for_the_grant_credential_again() {
    let fix = build_fixture().await;
    let (carol, _) = did_key_secret([0x11; 32]);
    let (erin, _) = did_key_secret([0x33; 32]);
    seed_vetter(&fix, &carol).await;
    seed_member(&fix, &erin).await;

    // Carol holds a grant; this test community has no messaging, so the
    // delivery cannot be handed to a transport.
    let (_did, doc) =
        signed_trust_task_seed(&[0x11; 32], VETTING_VETTER_RESEND_TYPE, json!({})).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(tt_error_code(&body), "unavailable");

    let (_did, doc) =
        signed_trust_task_seed(&[0x33; 32], VETTING_VETTER_RESEND_TYPE, json!({})).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(tt_error_code(&body), VETTING_VETTER_RESEND_ERR_NOT_GRANTED);

    let (_did, doc) = signed_trust_task_seed(
        &[0x11; 32],
        VETTING_VETTER_RESEND_TYPE,
        json!({ "memberDid": erin }),
    )
    .await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a resend names nobody: {body}"
    );

    // The admin route answers the same way.
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/vetting/vetters/{carol}/resend"),
        RESEND_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/vetting/vetters/{erin}/resend"),
        RESEND_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn branding_is_published_on_manifest_0_2_only() {
    let fix = build_fixture().await;
    let (status, body) = admin_rest(&fix, "GET", "/v1/community/branding", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({}));

    let (status, body) = admin_rest(
        &fix,
        "PUT",
        "/v1/community/branding",
        Some(json!({ "displayName": "Kernel", "accentColor": "#1A2B3C" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accentColor"], "#1a2b3c", "stored in lower case");

    let (status, body) = admin_rest(
        &fix,
        "PUT",
        "/v1/community/branding",
        Some(json!({ "logoUrl": "http://kernel.example/logo.svg" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (_did, doc) = signed_trust_task(JOIN_REQUEST_MANIFEST_0_2_TYPE, json!({})).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        tt_payload(&body)["branding"],
        json!({ "displayName": "Kernel", "accentColor": "#1a2b3c" })
    );
    let (_did, doc) = signed_trust_task(MANIFEST_TASK, json!({})).await;
    let (_status, body) = post_tt(&fix.router, doc).await;
    assert!(tt_payload(&body).get("branding").is_none(), "{body}");
}

/// Make `source` the active `vetterEligibility` policy.
async fn activate_vetter_policy(fix: &Fixture, source: &str) {
    use sha2::{Digest, Sha256};
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    store_policy(
        &fix.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::VetterEligibility,
            rego_source: source.into(),
            sha256: Sha256::digest(source.as_bytes()).into(),
            activated_at: Some(now),
            author_did: ADMIN_DID.into(),
            created_at: now,
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(
        &fix.state.active_policies_ks,
        PolicyPurpose::VetterEligibility,
        id,
    )
    .await
    .unwrap();
}

const DENY_ALL_VETTERS: &str =
    "package vtc.vetter_eligibility\nimport rego.v1\ndecision := {\"effect\": \"deny\"}\n";

#[tokio::test]
async fn the_sweep_grants_by_policy_and_revokes_only_its_own_grants() {
    use vtc_service::vetting::auto_grant::run_sweep;
    let fix = build_fixture().await;
    let (founder, _) = did_key_secret([0x51; 32]);
    let (dave, _) = did_key_secret([0x22; 32]);
    seed_member(&fix, &founder).await;
    seed_vetter(&fix, &dave).await;

    let (status, body) = admin_rest(
        &fix,
        "PUT",
        "/v1/vetting/auto-grant",
        Some(json!({ "enabled": true, "sweepMinutes": 5 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["sweepMinutes"], 5);
    assert_eq!(body["validitySeconds"], 31_536_000);
    assert!(body.get("lastSweep").is_none());
    let (status, _) = admin_rest(
        &fix,
        "PUT",
        "/v1/vetting/auto-grant",
        Some(json!({ "enabled": true, "sweepMinutes": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The shipped policy names genesis members; Dave already holds a grant.
    let sweep = run_sweep(&fix.state).await.expect("sweep");
    assert_eq!((sweep.granted, sweep.revoked, sweep.errors), (1, 0, 0));
    let grants = grants_of(&fix, &founder).await;
    assert_eq!(grants.len(), 1);
    assert!(grants[0].auto_granted);
    assert!(
        grants[0].credential.is_some(),
        "the credential is kept for resend"
    );
    let (_, body) = admin_rest(&fix, "GET", "/v1/vetting/vetters", None).await;
    let origin_of = |did: &str| {
        body["vetters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["memberDid"] == did)
            .map(|r| r["origin"].clone())
    };
    assert_eq!(origin_of(&founder), Some(json!("auto")));
    assert_eq!(origin_of(&dave), Some(json!("manual")));

    // A sweep that finds nothing to change changes nothing.
    let again = run_sweep(&fix.state).await.unwrap();
    assert_eq!((again.granted, again.revoked), (0, 0));

    activate_vetter_policy(&fix, DENY_ALL_VETTERS).await;
    let sweep = run_sweep(&fix.state).await.unwrap();
    assert_eq!((sweep.granted, sweep.revoked, sweep.errors), (0, 1, 0));
    assert!(grants_of(&fix, &founder).await[0].is_revoked());
    assert!(
        !grants_of(&fix, &dave).await[0].is_revoked(),
        "the sweep never revokes an admin's grant"
    );

    let (_, body) = admin_rest(&fix, "GET", "/v1/vetting/auto-grant", None).await;
    assert_eq!(body["lastSweep"]["revoked"], 1, "{body}");
    assert!(body["lastSweep"]["ranAt"].is_string());
}

#[tokio::test]
async fn an_admin_who_grants_an_automatic_vetter_adopts_the_grant() {
    use vtc_service::vetting::auto_grant::run_sweep;
    let fix = build_fixture().await;
    let (founder, _) = did_key_secret([0x51; 32]);
    seed_member(&fix, &founder).await;
    run_sweep(&fix.state).await.unwrap();
    let auto = grants_of(&fix, &founder).await;
    assert!(auto[0].auto_granted);

    let (status, body) = grant_vetter(&fix, &founder).await;
    assert_eq!(status, StatusCode::OK, "the live grant is returned: {body}");
    assert_eq!(body["endorsementId"], auto[0].id.to_string());
    assert!(!grants_of(&fix, &founder).await[0].auto_granted);

    activate_vetter_policy(&fix, DENY_ALL_VETTERS).await;
    let sweep = run_sweep(&fix.state).await.unwrap();
    assert_eq!(sweep.revoked, 0);
    assert!(!grants_of(&fix, &founder).await[0].is_revoked());
}

#[tokio::test]
async fn admins_see_the_vetting_facts_and_the_withdrawals_that_touch_a_membership() {
    use vtc_service::vetting::auto_grant::{AdmittedVia, eligibility_facts};
    let fix = build_fixture().await;
    store_vetting_criterion(&fix).await;
    let (applicant, _) = did_key_secret(MEMBER_SEED);
    let (carol, carol_key) = did_key_secret([0x11; 32]);
    let (dave, dave_key) = did_key_secret([0x22; 32]);
    seed_vetter(&fix, &carol).await;
    seed_vetter(&fix, &dave).await;
    let from_carol = vetting_statement(&carol_key, &applicant, 1).await;
    let from_dave = vetting_statement(&dave_key, &applicant, 2).await;

    let (_did, doc) =
        submit_doc(&vetting_vp(&applicant, vec![from_carol.clone(), from_dave])).await;
    let (status, body) = post_tt(&fix.router, doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(verdict_effect(&body), "allow", "{body}");
    let request_id = body["payload"]["requestId"].as_str().unwrap().to_string();

    let (status, facts) = admin_rest(
        &fix,
        "GET",
        &format!("/v1/join-requests/{request_id}/vetting"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{facts}");
    assert_eq!(facts["vetting"]["satisfied"], true, "{facts}");
    assert_eq!(facts["vetting"]["distinctCountedVetters"], 2);
    assert_eq!(facts["vetting"]["statements"][0]["withdrawnNow"], false);

    let member_facts = |all: Vec<vtc_service::vetting::auto_grant::EligibilityFacts>| {
        all.into_iter()
            .find(|f| f.did == applicant)
            .expect("the applicant is a member")
    };
    let admitted = member_facts(
        eligibility_facts(&fix.state, chrono::Utc::now())
            .await
            .unwrap(),
    );
    assert_eq!(admitted.admitted_via, AdmittedVia::Vetting);
    assert_eq!(admitted.depth, Some(1), "vetted by genesis members");
    assert!(!admitted.under_review);

    let (status, body) = post_tt(&fix.router, withdrawal_doc([0x11; 32], &from_carol).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = admin_rest(&fix, "GET", "/v1/vetting/revocations", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let notice = &body["revocations"][0];
    assert_eq!(notice["issuer"], carol);
    assert_eq!(notice["reviewState"], "needsReview");
    assert_eq!(notice["affectedMembers"], json!([applicant.clone()]));
    assert_eq!(notice["affectedJoinRequests"], json!([request_id.clone()]));

    let (_, facts) = admin_rest(
        &fix,
        "GET",
        &format!("/v1/join-requests/{request_id}/vetting"),
        None,
    )
    .await;
    let withdrawn: Vec<bool> = facts["vetting"]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["withdrawnNow"].as_bool().unwrap())
        .collect();
    assert!(withdrawn.contains(&true), "{facts}");
    let under_review = member_facts(
        eligibility_facts(&fix.state, chrono::Utc::now())
            .await
            .unwrap(),
    );
    assert!(under_review.under_review);

    let (status, _) = admin_rest(
        &fix,
        "GET",
        &format!("/v1/join-requests/{}/vetting", Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let _ = dave;
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
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
        // The policy at line 1737 authors `request_more` — Rego idiom — and
        // the wire publishes `requestMore`, per SPEC §4.10 rule 4. The two
        // vocabularies differ on purpose; `VerdictEffect` is the boundary.
        "requestMore",
        "expected requestMore verdict: {body}"
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
// #1052 — a rejected applicant can recover *why* from the poll.
//
// The correlated ceremony reply is the only place a `{code, reason}` ever
// reached an applicant, which makes it a one-shot delivery: a dropped socket,
// a lost reply, or a rejection an admin took hours later, and the reason was
// gone for good. The poll is the recovery path, and it was the one path that
// stripped the evidence — projecting `needs`/`presentationDefinition` for
// `deferred` and bare `{requestId, status}` for `rejected`.
//
// Both rejection paths are covered, because they source the refusal
// differently: the policy auto-deny has a verdict to quote, the admin reject
// has only the operator's words.
// ---------------------------------------------------------------------------

/// Auto-deny: the poll returns the policy's own `code` and `reason`.
#[tokio::test]
async fn status_rejected_by_policy_returns_the_deny_code_and_reason() {
    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        r#"
package vtc.join
import future.keywords.if
default decision := {"effect": "deny", "with": {
    "code": "membership-required",
    "reason": "this community admits members of did:web:parent.example only"
}}
"#,
    )
    .await;

    let (_d, doc) = submit_doc(&json!({})).await;
    let (_, body) = post_tt(&fix.router, doc).await;
    assert_eq!(verdict_effect(&body), "deny", "expected a deny: {body}");
    let id = Uuid::parse_str(body["payload"]["requestId"].as_str().unwrap()).unwrap();

    let (status, body) = post_status(&fix, id).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["status"], "rejected");
    assert_eq!(
        payload["code"], "membership-required",
        "the policy's refusal code must survive the poll: {payload}"
    );
    assert_eq!(
        payload["reason"], "this community admits members of did:web:parent.example only",
        "the policy's reason must survive the poll: {payload}"
    );
    assert!(
        payload["decidedAt"].is_string(),
        "a rejection must say when it was decided: {payload}"
    );
}

/// Admin reject: the poll returns the operator's reason under the stable
/// `admin-reject` code.
///
/// This is the path that was unrecoverable end to end — `reject_pending`
/// sends the applicant nothing, and the reason reached only the audit log,
/// which no applicant can read. A code distinct from any policy code is what
/// lets a client tell "the rules refused you, satisfy them and re-apply" from
/// "a human refused you, re-applying changes nothing".
#[tokio::test]
async fn status_rejected_by_admin_returns_the_operator_reason() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let (status, _body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({
            "decision": "rejected",
            "reason": "duplicate application — see request 4b1f",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_status(&fix, id).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let payload = tt_payload(&body);
    assert_eq!(payload["status"], "rejected");
    assert_eq!(
        payload["code"], "admin-reject",
        "an operator decision carries the admin code, not a policy one: {payload}"
    );
    assert_eq!(
        payload["reason"], "duplicate application — see request 4b1f",
        "the operator's reason must reach the applicant: {payload}"
    );
    assert!(
        payload["decidedAt"].is_string(),
        "a rejection must say when it was decided: {payload}"
    );
}

/// An admin who supplies no reason yields a code and no `reason` field —
/// never an empty string, which a client would render as a blank explanation.
#[tokio::test]
async fn status_rejected_by_admin_without_a_reason_omits_the_field() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let (status, _body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "rejected" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = post_status(&fix, id).await;
    let payload = tt_payload(&body);
    assert_eq!(payload["code"], "admin-reject");
    assert!(
        payload.get("reason").is_none(),
        "no reason given means the field is absent, not empty: {payload}"
    );
}

/// `decidedAt` is the decision's time, not the document's.
///
/// The two are indistinguishable on an auto-deny polled immediately, which is
/// exactly why asserting "they differ" would prove nothing. What separates
/// them is that one is fixed and the other is not: poll twice and `issuedAt`
/// moves — a fresh `#response` document each time — while `decidedAt` names
/// the same moment it always will. An admin reject makes the gap arbitrary;
/// the applicant may poll days later.
#[tokio::test]
async fn status_decided_at_is_the_decision_time_not_the_document_time() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let (status, _body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/decide"),
        DECIDE_TASK,
        Some(&fix.admin_token),
        Some(json!({ "decision": "rejected", "reason": "not this time" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, first) = post_status(&fix, id).await;
    // A measurable gap, so `issuedAt` cannot coincidentally match.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, second) = post_status(&fix, id).await;

    let decided_first = tt_payload(&first)["decidedAt"]
        .as_str()
        .unwrap()
        .to_string();
    let decided_second = tt_payload(&second)["decidedAt"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        decided_first, decided_second,
        "the decision happened once; every poll must report the same time"
    );

    let issued_first = first["issuedAt"].as_str().unwrap().to_string();
    let issued_second = second["issuedAt"].as_str().unwrap().to_string();
    assert_ne!(
        issued_first, issued_second,
        "each poll is a fresh document, so issuedAt must move — if it does \
         not, this test cannot tell the two timestamps apart"
    );
    assert_ne!(
        decided_second, issued_second,
        "decidedAt must not be an alias for the document's issuedAt"
    );
}

/// A non-rejected request carries no refusal fields at all — a `pending`
/// applicant must not be shown a code or reason.
#[tokio::test]
async fn status_pending_carries_no_refusal_fields() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let (_, body) = post_status(&fix, id).await;
    let payload = tt_payload(&body);
    assert_eq!(payload["status"], "pending");
    assert!(
        payload.get("code").is_none() && payload.get("reason").is_none(),
        "a pending request has not been refused: {payload}"
    );
    assert!(
        payload.get("decidedAt").is_none(),
        "a pending request has no decision to time: {payload}"
    );
}

// ---------------------------------------------------------------------------
// P0.5 — the unauthenticated join-request POSTs (submit / status)
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
    // All holder-facing join verbs (submit/manifest/status) arrive on the
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
