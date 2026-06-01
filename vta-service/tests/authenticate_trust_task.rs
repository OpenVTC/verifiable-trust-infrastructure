//! Integration test for **authenticate via a DI-signed Trust Task over REST** —
//! the transport-agnostic `auth/authenticate/0.1` path.
//!
//! The holder posts a plain JSON `auth/authenticate/0.1` Trust Task whose
//! `eddsa-jcs-2022` Data-Integrity proof *is* the authentication — no DIDComm
//! packing / mediator required. Exercises the real route → DI-proof verify
//! (local `did:key` resolution) → canonical `handle_authenticate` →
//! session-state transition → token mint, end to end.
//!
//! Unlike the DIDComm `POST /auth/` round-trip (which needs a network DID
//! resolver and lives in the e2e suite), this path resolves `did:key` locally,
//! so the full sign-then-verify runs in-process here.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
use ed25519_dalek::{Signer, SigningKey};
use multibase::Base;
use trust_tasks_rs::{Proof, TrustTask};

use vta_service::test_support::{TestAppContext, build_test_app};

/// did:key + method-specific-id for an Ed25519 key (multicodec 0xed01).
fn did_key(sk: &SigningKey) -> (String, String) {
    let pk = sk.verifying_key();
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(pk.as_bytes());
    let mb = multibase::encode(Base::Base58Btc, mc);
    (format!("did:key:{mb}"), mb)
}

/// Grant `did` admin access so it clears the `/auth/challenge` ACL gate and the
/// authenticate role re-lookup.
async fn seed_admin_acl(ctx: &TestAppContext, did: &str) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

fn post(uri: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        // Stable client IP so the per-IP rate limiter doesn't throttle a
        // parallel `cargo test` run interleaving with the rate-limit test.
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from(body))
        .unwrap()
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
    (status, v)
}

/// Build a holder-signed `auth/authenticate/0.1` Trust Task document for the
/// given challenge + session, signed with `sk` (eddsa-jcs-2022).
fn signed_authenticate_doc(
    sk: &SigningKey,
    did: &str,
    vm: &str,
    challenge: &str,
    session_id: &str,
) -> TrustTask<Value> {
    let doc_json = json!({
        "id": "urn:uuid:authn-itest-1",
        "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": { "challenge": challenge, "sessionId": session_id },
    });
    let mut doc: TrustTask<Value> = serde_json::from_value(doc_json).unwrap();
    let mut di = DataIntegrityProof {
        type_: "DataIntegrityProof".to_string(),
        cryptosuite: CryptoSuite::EddsaJcs2022,
        // Safely in the past — DI verify rejects future-dated proofs, and the
        // wall clock sits right on the 2026-06-01 boundary.
        created: Some("2026-05-31T12:00:00Z".to_string()),
        verification_method: vm.to_string(),
        proof_purpose: "authentication".to_string(),
        proof_value: None,
        context: None,
    };
    let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
    di.proof_value = Some(multibase::encode(
        Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(serde_json::from_value::<Proof>(serde_json::to_value(&di).unwrap()).unwrap());
    doc
}

/// Run a real `/auth/challenge` for `did` and return `(session_id, challenge)`.
async fn obtain_challenge(router: &axum::Router, did: &str) -> (String, String) {
    let (status, body) = send(
        router,
        post(
            "/auth/challenge",
            json!({ "did": did }).to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge must issue: {body}");
    (
        body["sessionId"].as_str().unwrap().to_string(),
        body["challenge"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn di_signed_authenticate_issues_tokens() {
    let (router, ctx) = build_test_app().await;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let (did, mb) = did_key(&sk);
    let vm = format!("{did}#{mb}");
    seed_admin_acl(&ctx, &did).await;

    let (session_id, challenge) = obtain_challenge(&router, &did).await;
    let doc = signed_authenticate_doc(&sk, &did, &vm, &challenge, &session_id);

    let (status, body) = send(&router, post("/auth/", serde_json::to_vec(&doc).unwrap())).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "DI-signed authenticate must succeed: {body}"
    );
    // A TT request gets a TT `#response` document back (what the engine's
    // parse_authenticate_response consumes): tokens + session under `payload`.
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("/auth/authenticate/0.1#response")),
        "response is a TT #response doc: {body}"
    );
    assert_eq!(body["payload"]["session"]["subject"], did, "{body}");
    assert_eq!(
        body["payload"]["session"]["acr"], "aal1",
        "first factor is AAL1: {body}"
    );
    assert!(
        body["payload"]["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "an access token is issued: {body}"
    );

    // The session transitioned to Authenticated (so a replay can't re-auth).
    let stored = vti_common::auth::session::get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.state,
        vti_common::auth::session::SessionState::Authenticated
    );

    // Replay the exact same document: the session is no longer ChallengeSent.
    let (replay_status, _) = send(&router, post("/auth/", serde_json::to_vec(&doc).unwrap())).await;
    assert_ne!(
        replay_status,
        StatusCode::OK,
        "replaying the authenticate document must not re-authenticate"
    );
}

#[tokio::test]
async fn di_signed_authenticate_rejects_tampered_proof() {
    let (router, ctx) = build_test_app().await;
    let sk = SigningKey::from_bytes(&[8u8; 32]);
    let (did, mb) = did_key(&sk);
    let vm = format!("{did}#{mb}");
    seed_admin_acl(&ctx, &did).await;

    let (session_id, challenge) = obtain_challenge(&router, &did).await;
    let mut doc = signed_authenticate_doc(&sk, &did, &vm, &challenge, &session_id);

    // Corrupt the signature: flip a char near the START of the proofValue
    // (full 6 significant bits) so the tamper is never a no-op.
    let mut proof = serde_json::to_value(doc.proof.take().unwrap()).unwrap();
    let pv = proof["proofValue"].as_str().unwrap();
    let mut chars: Vec<char> = pv.chars().collect();
    // index 1 is the first base58 char after the multibase prefix 'z'.
    chars[1] = if chars[1] == 'A' { 'B' } else { 'A' };
    proof["proofValue"] = Value::String(chars.into_iter().collect());
    doc.proof = Some(serde_json::from_value(proof).unwrap());

    let (status, body) = send(&router, post("/auth/", serde_json::to_vec(&doc).unwrap())).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a tampered proof must be rejected: {body}"
    );

    // The session stays in ChallengeSent — no tokens were issued.
    let stored = vti_common::auth::session::get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.state,
        vti_common::auth::session::SessionState::ChallengeSent
    );
}

/// The challenge step also speaks Trust Tasks end-to-end: a TT
/// `auth/challenge/0.1` request returns a TT `#response` document the engine's
/// `parse_auth_challenge_response` consumes (payload `{challenge, sessionId,
/// expiresAt}`, addressed back to the holder).
#[tokio::test]
async fn tt_challenge_returns_tt_response_doc() {
    let (router, ctx) = build_test_app().await;
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let (did, _mb) = did_key(&sk);
    seed_admin_acl(&ctx, &did).await;

    let doc = json!({
        "id": "urn:uuid:challenge-itest-1",
        "type": "https://trusttasks.org/spec/auth/challenge/0.1",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": { "subject": did },
    });
    let (status, body) = send(
        &router,
        post("/auth/challenge", serde_json::to_vec(&doc).unwrap()),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "TT challenge must succeed: {body}");
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("/auth/challenge/0.1#response")),
        "response is a TT #response doc: {body}"
    );
    assert_eq!(
        body["recipient"], did,
        "addressed back to the holder: {body}"
    );
    assert!(
        body["payload"]["challenge"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "{body}"
    );
    assert!(
        body["payload"]["sessionId"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{body}"
    );
    assert!(body["payload"]["expiresAt"].as_str().is_some(), "{body}");
}
