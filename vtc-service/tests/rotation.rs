//! Integration coverage for `POST /v1/members/me/rotate/*`
//! (Phase 2 M2.15.1, `did:key` path only).

mod common;

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde::Serialize;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_common::auth::session::{Session, SessionState, list_sessions, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::credentials::LocalSigner;
use vtc_service::members::{Member, get_member, store_member};
// `ROTATION_DOMAIN_TAG` from the rotate module is `pub(crate)`;
// duplicate the literal here so the integration test doesn't
// have to peek through the route layer's private modules.
const ROTATION_DOMAIN_TAG: &[u8] = b"vtc-did-rotation/v1\0";
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const CHALLENGE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/rotate-challenge/1.0";
const ROTATE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/rotate/1.0";

struct Fixture {
    router: axum::Router,
    member_token: String,
    member_signing: SigningKey,
    member_did: String,
    members_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
    sessions_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    signer: Arc<LocalSigner>,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // The fixture verifies re-issued VMC/VEC against this signer, so the
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
    .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }
    // Pre-allocate a slot for the member so rotation can
    // reuse it during credential re-issuance.
    let mut state_row =
        status_list::get_state(&vtc.state.status_lists_ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap();
    let slot = status_list::allocate(&mut state_row).unwrap();
    status_list::store_state(&vtc.state.status_lists_ks, &state_row)
        .await
        .unwrap();

    // Build a member with a deterministic Ed25519 key + matching did:key.
    let member_signing = SigningKey::from_bytes(&[0xAA; 32]);
    let member_pub = member_signing.verifying_key().to_bytes();
    let member_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&member_pub);

    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: member_did.clone(),
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
    let mut m = Member::fresh(&member_did);
    m.status_list_index = Some(slot);
    store_member(&vtc.state.members_ks, &m).await.unwrap();

    let session_id = "test-rot-session";
    store_session(
        &vtc.state.sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: member_did.clone(),
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

    let member_claims = vtc.jwt_keys.new_claims(
        member_did.clone(),
        session_id.into(),
        "reader".into(),
        vec![],
        3600,
        true,
    );
    let member_token = vtc.jwt_keys.encode(&member_claims).unwrap();

    let members_ks = vtc.state.members_ks.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let sessions_ks = vtc.state.sessions_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        member_token,
        member_signing,
        member_did,
        members_ks,
        acl_ks,
        sessions_ks,
        audit_ks,
        signer,
        _vtc: vtc,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let raw = String::from_utf8_lossy(&bytes);
        panic!("response body was not JSON ({e}): {raw}")
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    rotation_id: String,
    old_did: &'a str,
    new_did: &'a str,
    expires_at: i64,
}

fn signing_bytes(rotation_id: &str, old_did: &str, new_did: &str, expires_at: i64) -> Vec<u8> {
    let json = serde_json::to_vec(&CanonicalPayload {
        rotation_id: rotation_id.to_string(),
        old_did,
        new_did,
        expires_at,
    })
    .unwrap();
    let mut buf = Vec::with_capacity(ROTATION_DOMAIN_TAG.len() + json.len());
    buf.extend_from_slice(ROTATION_DOMAIN_TAG);
    buf.extend_from_slice(&json);
    buf
}

async fn mint_challenge(fix: &Fixture) -> (String, i64) {
    mint_challenge_with_reason(fix, None).await
}

/// `reason` mirrors the optional `ChallengeBody`. `None` sends no body
/// at all — the pre-existing wire shape, which must keep working.
async fn mint_challenge_with_reason(fix: &Fixture, reason: Option<&str>) -> (String, i64) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate/challenge")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK);
    let body = match reason {
        Some(r) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json!({ "reason": r }).to_string())
        }
        None => Body::empty(),
    };
    let req = builder.body(body).unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let id = body["rotationId"].as_str().unwrap().to_string();
    // expiresAt is RFC3339 — convert to epoch for the canonical
    // payload.
    let expires_at = chrono::DateTime::parse_from_rfc3339(body["expiresAt"].as_str().unwrap())
        .unwrap()
        .timestamp();
    (id, expires_at)
}

#[tokio::test]
async fn rotation_happy_path_swaps_acl_and_member() {
    let fix = build_fixture().await;

    // Pick a fresh did:key for the new identity.
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);

    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["newDid"], new_did);
    assert_eq!(body["method"], "did:key");

    // ACL + Member rows moved.
    assert!(
        get_acl_entry(&fix.acl_ks, &fix.member_did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_acl_entry(&fix.acl_ks, &new_did)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_member(&fix.members_ks, &fix.member_did)
            .await
            .unwrap()
            .is_none()
    );
    let new_member = get_member(&fix.members_ks, &new_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new_member.did, new_did);
    assert!(new_member.status_list_index.is_some(), "slot reused");

    // Sessions for the old DID revoked.
    let sessions = list_sessions(&fix.sessions_ks).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.did != fix.member_did),
        "old-DID sessions must be revoked"
    );

    // VMC + VEC inline + verifying.
    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vec: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVec"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vec).expect("VEC verifies");
}

/// M2.15.2: did:webvh rotation works, but only when the
/// daemon was booted with a DID resolver wired into
/// `AppState`. The rotation-test fixture leaves
/// `did_resolver: None` (no internet at test time), so a
/// did:webvh new-DID hits the "resolver not configured" 500
/// path. That's the realistic failure mode for daemons
/// running offline / in CI; the actual resolver walk is
/// exercised end-to-end by the recognition unit tests
/// (`recognition::verify::tests`), which share the same
/// `VerificationMethod::get_public_key_bytes()` upstream
/// helper.
#[tokio::test]
async fn rotation_did_webvh_requires_did_resolver() {
    let fix = build_fixture().await;
    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let new_did = "did:webvh:peer.example.com:abc";
    let payload = signing_bytes(&rotation_id, &fix.member_did, new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // 500 (Internal) because the daemon is misconfigured —
    // not 400 (caller's fault).
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn rotation_rejects_unknown_did_method() {
    let fix = build_fixture().await;
    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    // did:example isn't a method the rotation route knows
    // about — should 400 cleanly before any signature check.
    let new_did = "did:example:abc";
    let payload = signing_bytes(&rotation_id, &fix.member_did, new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotation_rejects_bad_new_signature() {
    let fix = build_fixture().await;
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    // Sign with a DIFFERENT key than the one whose pubkey is in
    // the new_did — verifier must reject.
    let wrong = SigningKey::from_bytes(&[0xDE; 32]);
    let bad_sig = hex::encode(wrong.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": bad_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotation_id_is_single_use() {
    let fix = build_fixture().await;
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/v1/members/me/rotate")
            .header("authorization", format!("Bearer {}", fix.member_token))
            .header("trust-task", ROTATE_TASK)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "rotationId": rotation_id,
                    "oldDid": fix.member_did,
                    "newDid": new_did,
                    "oldSignature": old_sig,
                    "newSignature": new_sig,
                })
                .to_string(),
            ))
            .unwrap()
    };

    let resp = fix.router.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first call succeeds");

    // Second call: rotation_id is consumed, and the old DID no
    // longer has a session (revoked in step 1). The endpoint
    // returns 401 because the AuthClaims extractor can't verify
    // the session. Either failure mode is acceptable; we
    // assert any non-2xx.
    let resp = fix.router.clone().oneshot(make_req()).await.unwrap();
    assert!(
        !resp.status().is_success(),
        "second call must not succeed, got {}",
        resp.status()
    );
}

/// The reason is declared at challenge time and must survive to the
/// `DidRotated` envelope — it is collected there, rather than on the
/// finish request, because the rotation signatures do not cover it.
#[tokio::test]
async fn rotation_reason_reaches_the_audit_envelope() {
    use vti_common::audit::{AuditEnvelope, AuditEvent, DidRotationReason};

    let fix = build_fixture().await;

    let new_signing = SigningKey::from_bytes(&[0xCC; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge_with_reason(&fix, Some("compromise")).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let raw = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .expect("read audit keyspace");
    let rotated: Vec<AuditEnvelope> = raw
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice::<AuditEnvelope>(v).ok())
        .filter(|e| matches!(e.event, AuditEvent::DidRotated(_)))
        .collect();
    assert_eq!(rotated.len(), 1, "one DidRotated envelope");
    let AuditEvent::DidRotated(data) = &rotated[0].event else {
        unreachable!()
    };
    assert_eq!(
        data.rotation_reason,
        Some(DidRotationReason::Compromise),
        "the reason declared at challenge time survives to the audit row"
    );
}

/// Omitting the body leaves the reason unset rather than defaulting to
/// something that reads as a claim the member never made.
#[tokio::test]
async fn rotation_without_a_reason_records_none() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build_fixture().await;

    let new_signing = SigningKey::from_bytes(&[0xDD; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        fix.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let raw = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let rotated: Vec<AuditEnvelope> = raw
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice::<AuditEnvelope>(v).ok())
        .filter(|e| matches!(e.event, AuditEvent::DidRotated(_)))
        .collect();
    assert_eq!(rotated.len(), 1);
    let AuditEvent::DidRotated(data) = &rotated[0].event else {
        unreachable!()
    };
    assert_eq!(data.rotation_reason, None);
}
