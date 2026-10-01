//! Integration coverage for `POST /v1/members/me/rotate/*`
//! (Phase 2 M2.15.1, `did:key` path only).


use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Value, json};
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
const CHALLENGE_TASK: &str = "https://trusttasks.org/spec/vtc/members/rotate-challenge/0.1";
const ROTATE_TASK: &str = "https://trusttasks.org/spec/vtc/members/rotate/0.1";

struct Fixture {
    /// The trust-task document signer — same key as `member_signing`, so it
    /// can sign both the enclosing document and the rotation payload.
    member: vti_rooms_dtg::test_support::Party,
    member_signing: SigningKey,
    member_did: String,
    members_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
    sessions_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    signer: Arc<LocalSigner>,
    // Owns the temp data dir + serves the router; must outlive them.
    _vtc: TestVtc,
}

/// A [`Party`](vti_rooms_dtg::test_support::Party) for `seed`'s Ed25519 key —
/// the fixed key `member_signing`/`member_did` also use, so this Party signs
/// the trust-task document with the same key that signs its rotation payload.
fn party_from_seed(seed: [u8; 32]) -> vti_rooms_dtg::test_support::Party {
    let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
        &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    );
    vti_rooms_dtg::test_support::Party {
        secret: vta_sdk::did_key::secrets_from_did_key(&did, &seed)
            .expect("build secrets")
            .signing,
        secret_multibase: multibase::encode(multibase::Base::Base58Btc, seed),
        did,
    }
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

    let member = party_from_seed([0xAA; 32]);
    assert_eq!(
        member.did, member_did,
        "party_from_seed must agree with the did:key helper above"
    );

    let members_ks = vtc.state.members_ks.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let sessions_ks = vtc.state.sessions_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();

    Fixture {
        member,
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

/// `reason` mirrors the optional `ChallengeBody`. `None` sends an empty
/// payload — the pre-existing wire shape, which must keep working.
async fn mint_challenge_with_reason(fix: &Fixture, reason: Option<&str>) -> (String, i64) {
    let payload = match reason {
        Some(r) => json!({ "reason": r }),
        None => json!({}),
    };
    let (status, doc) = crate::common::signed::call(&fix._vtc, &fix.member, CHALLENGE_TASK, payload).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let body = &doc["payload"];
    let id = body["rotationId"].as_str().unwrap().to_string();
    // expiresAt is RFC3339 — convert to epoch for the canonical
    // payload.
    let expires_at = chrono::DateTime::parse_from_rfc3339(body["expiresAt"].as_str().unwrap())
        .unwrap()
        .timestamp();
    (id, expires_at)
}

/// `vtc/members/rotate/0.1`, signed by `fix.member`: the reply's status and
/// `#response` payload (or a refusal's `{code, message}`).
async fn finish_rotate(fix: &Fixture, payload: Value) -> (StatusCode, Value) {
    let (status, doc) = crate::common::signed::call(&fix._vtc, &fix.member, ROTATE_TASK, payload).await;
    (status, doc["payload"].clone())
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

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
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

    // VMC + VAC inline + verifying.
    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vac: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVac"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vac).expect("VAC verifies");
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

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    // 500 (Internal) because the daemon is misconfigured —
    // not 400 (caller's fault).
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
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

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
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

    // `signatureInvalid` is a declared code, so it rides the framework's flat
    // 422 bucket for extended codes over the signed door (not the REST
    // route's old 400).
    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": bad_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
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

    let finish_payload = || {
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        })
    };

    let (status, body) = finish_rotate(&fix, finish_payload()).await;
    assert_eq!(status, StatusCode::OK, "first call succeeds: {body}");

    // Second call: rotation_id is consumed — the old DID's ACL row is also
    // gone by now, but `self_signer` admits an absent row regardless, so the
    // refusal is the operation's own `rotationExpired`, not an auth failure.
    let (status, body) = finish_rotate(&fix, finish_payload()).await;
    assert!(
        !status.is_success(),
        "second call must not succeed, got {status}: {body}"
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

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

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

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

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

// ---------------------------------------------------------------------------
// #1600 — the codes `rotate-challenge/0.1` and `rotate/0.1` declare, read from
// the generated bindings.
// ---------------------------------------------------------------------------

use trust_tasks_rs::specs::vtc::members::{rotate, rotate_challenge};

const ROTATE_CHALLENGE_ERR_NOT_MEMBER: &str = rotate_challenge::v0_1::error_codes::NOT_MEMBER.code;
const ROTATE_ERR_ROTATION_EXPIRED: &str = rotate::v0_1::error_codes::ROTATION_EXPIRED.code;
const ROTATE_ERR_SIGNATURE_INVALID: &str = rotate::v0_1::error_codes::SIGNATURE_INVALID.code;

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn a_rotation_challenge_for_a_non_member_is_the_declared_not_member() {
    let fix = build_fixture().await;
    vtc_service::acl::delete_acl_entry(&fix.acl_ks, &fix.member_did)
        .await
        .unwrap();
    let (status, doc) =
        crate::common::signed::call(&fix._vtc, &fix.member, CHALLENGE_TASK, json!({})).await;
    let body = doc["payload"].clone();
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ROTATE_CHALLENGE_ERR_NOT_MEMBER,
        "{body}"
    );
}

/// `rotationExpired` covers a rotation id the community never issued (or has
/// already spent); `signatureInvalid` covers either key failing to sign. Both
/// are declared codes, so both ride the framework's flat 422 bucket over the
/// signed door (not the REST route's old 400).
#[tokio::test]
async fn the_rotate_task_answers_with_the_codes_its_spec_declares() {
    let fix = build_fixture().await;
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": uuid::Uuid::new_v4().to_string(),
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": "00",
            "newSignature": "00",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ROTATE_ERR_ROTATION_EXPIRED,
        "{body}"
    );

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());
    // The *old* key's signature is the one that fails this time.
    let wrong = SigningKey::from_bytes(&[0xDE; 32]);
    let bad_old_sig = hex::encode(wrong.sign(&payload).to_bytes());
    let (status, body) = finish_rotate(
        &fix,
        json!({
            "rotationId": rotation_id,
            "oldDid": fix.member_did,
            "newDid": new_did,
            "oldSignature": bad_old_sig,
            "newSignature": new_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ROTATE_ERR_SIGNATURE_INVALID,
        "{body}"
    );
}
