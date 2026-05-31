//! Integration test for `auth/step-up/approve-response/0.1` — the full
//! HTTP round-trip: an AAL1 session holder POSTs a did-signed approve-response
//! to `/api/trust-tasks` and the VTA elevates their session to AAL2.
//!
//! Exercises the real route → bearer auth → trust-task dispatcher → step-up
//! handler → pending-store consume → did-signed gate verification → session
//! elevation → `#response` ack path end to end.

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

use vta_service::test_support::build_test_app;
use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};
use vti_common::auth::step_up::{new_pending_step_up, store_pending_step_up};

/// did:key + method-specific-id for an Ed25519 key (multicodec 0xed01).
fn did_key(sk: &SigningKey) -> (String, String) {
    let pk = sk.verifying_key();
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(pk.as_bytes());
    let mb = multibase::encode(Base::Base58Btc, mc);
    (format!("did:key:{mb}"), mb)
}

#[tokio::test]
async fn did_signed_approve_response_elevates_session_to_aal2() {
    let (router, ctx) = build_test_app().await;

    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let (did, mb) = did_key(&sk);
    let vm = format!("{did}#{mb}");
    let session_id = "sess-stepup-1".to_string();
    let challenge = "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ".to_string();

    // 1. An authenticated AAL1 session for the holder.
    let session = Session {
        session_id: session_id.clone(),
        did: did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    // 2. A bearer token for that session (the caller is the subject).
    let claims = ctx.jwt_keys.new_claims(
        did.clone(),
        session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    // 3. A pending step-up the relying party minted (challenge-bound).
    let pending = new_pending_step_up(
        challenge.clone(),
        session_id.clone(),
        did.clone(),
        "aal2",
        vec!["did-signed".to_string()],
        300,
    );
    store_pending_step_up(&ctx.sessions_ks, &pending)
        .await
        .unwrap();

    // 4. The approver's did-signed approve-response (recipient = the test
    //    VTA's vta_did from test_support).
    let doc_json = json!({
        "id": "approve-resp-itest-1",
        "type": "https://trusttasks.org/spec/auth/step-up/approve-response/0.1",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {
            "subject": did,
            "sessionId": session_id,
            "challenge": challenge,
            "decision": "approved",
            "grantedAcr": "aal2",
        },
    });
    let mut doc: TrustTask<Value> = serde_json::from_value(doc_json).unwrap();
    let mut di = DataIntegrityProof {
        type_: "DataIntegrityProof".to_string(),
        cryptosuite: CryptoSuite::EddsaJcs2022,
        created: Some("2026-05-31T00:00:00Z".to_string()),
        verification_method: vm,
        proof_purpose: "assertionMethod".to_string(),
        proof_value: None,
        context: None,
    };
    let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
    di.proof_value = Some(multibase::encode(
        Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(serde_json::from_value::<Proof>(serde_json::to_value(&di).unwrap()).unwrap());

    // 5. POST it.
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    // 6. The ack reports the elevated session.
    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {v}");
    assert_eq!(v["payload"]["status"], "elevated", "{v}");
    assert_eq!(v["payload"]["session"]["acr"], "aal2", "{v}");

    // 7. The stored session is elevated (so /auth/refresh re-mints at aal2).
    let stored = get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.acr, "aal2");
    assert!(stored.amr.iter().any(|m| m == "did"));

    // 8. The pending step-up was consumed (single use): a replay is unknown.
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let (status2, _) = {
        let resp = router.clone().oneshot(req2).await.unwrap();
        (resp.status(), ())
    };
    // The dispatcher returns the trust-task error document with a non-2xx
    // status (challenge_unknown — the pending step-up is gone).
    assert_ne!(status2, StatusCode::OK, "replay must not elevate again");
}
