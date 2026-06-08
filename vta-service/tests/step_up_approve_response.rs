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
        did.clone(), // self step-up: approver == subject
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

/// Dual-accept: the **0.2** approve-response carries the camelCase
/// `evidence.kind` (`didSigned`) and a `…/0.2` type URI. The VTA must accept
/// it, verify the approver's signature over the *0.2* bytes (the document is
/// never down-converted), elevate the session, and reply with a
/// `…/0.2#response`.
#[tokio::test]
async fn did_signed_approve_response_0_2_elevates_session_to_aal2() {
    let (router, ctx) = build_test_app().await;

    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let (did, mb) = did_key(&sk);
    let vm = format!("{did}#{mb}");
    let session_id = "sess-stepup-0-2".to_string();
    let challenge = "U3RlcFVwMHgyQ2hhbGxlbmdlVmFsdWVYWQ".to_string();

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

    let claims = ctx.jwt_keys.new_claims(
        did.clone(),
        session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let pending = new_pending_step_up(
        challenge.clone(),
        session_id.clone(),
        did.clone(),
        did.clone(), // self step-up: approver == subject
        "aal2",
        vec!["did-signed".to_string()],
        300,
    );
    store_pending_step_up(&ctx.sessions_ks, &pending)
        .await
        .unwrap();

    // 0.2 document: camelCase `evidence.kind` + the /0.2 type URI. The signature
    // covers THIS (0.2) form — the VTA must not mutate it before verifying.
    let doc_json = json!({
        "id": "approve-resp-itest-0-2",
        "type": "https://trusttasks.org/spec/auth/step-up/approve-response/0.2",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {
            "subject": did,
            "sessionId": session_id,
            "challenge": challenge,
            "decision": "approved",
            "grantedAcr": "aal2",
            "evidence": { "kind": "didSigned" },
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

    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {v}");
    // The response document echoes the 0.2 type with a #response fragment.
    assert_eq!(
        v["type"], "https://trusttasks.org/spec/auth/step-up/approve-response/0.2#response",
        "0.2 request must yield a 0.2 response: {v}"
    );
    assert_eq!(v["payload"]["status"], "elevated", "{v}");
    assert_eq!(v["payload"]["session"]["acr"], "aal2", "{v}");

    let stored = get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.acr, "aal2");
}

/// The trust-task analogue of the REST step-up `403`: an AAL1 caller invoking
/// an AAL2-gated trust-task operation (here `acl/create`) is rejected with a
/// reject that *carries the approve-request* in its `details`. The caller has
/// the required role (admin → `require_manage` passes), so this is the step-up
/// gate firing — not a permission denial — and it fires before payload parsing.
#[tokio::test]
async fn trust_task_acl_mutation_requires_step_up() {
    let (router, ctx) = build_test_app().await;

    // Opt into step-up enforcement (shipping default is disabled): a `*`
    // floor at AAL2 so the AAL1 trust-task mutation below is gated.
    {
        use vti_common::auth::step_up::{StepUpFloor, StepUpMode, StepUpPolicy};
        ctx.config.write().await.auth.step_up = StepUpPolicy {
            enabled: true,
            floors: vec![StepUpFloor {
                operation: "*".into(),
                mode: StepUpMode::SelfApprove,
                allow_aal1_if_non_escalating: false,
            }],
        };
    }

    let did = "did:key:z6MkAal1Admin".to_string();
    let session_id = "sess-stepup-tt-1".to_string();

    // An AAL1 admin session + bearer token: role passes, assurance level does not.
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
    let claims = ctx.jwt_keys.new_claims(
        did.clone(),
        session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    // A well-formed acl/create addressed to the test VTA. The step-up gate fires
    // before payload parsing, so the body need only route + pass the role check.
    let doc = json!({
        "id": "acl-create-itest-1",
        "type": "https://trusttasks.org/spec/vta/acl/create/1.0",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {
            "did": "did:key:z6MkSomeNewEntry",
            "role": "application",
            "allowed_contexts": ["ctx1"]
        },
    });
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

    // Rejected (not executed), carrying the step-up signal + approve-request.
    assert_ne!(
        status,
        StatusCode::OK,
        "AAL1 must not execute the mutation: {v}"
    );
    let details = &v["payload"]["details"];
    assert_eq!(
        details["requiredAcr"], "aal2",
        "step-up reject must carry requiredAcr: {v}"
    );
    assert_eq!(
        details["approveRequest"]["type"],
        "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
        "reject must carry the approve-request: {v}"
    );
    assert_eq!(details["approveRequest"]["recipient"], did, "{v}");
    assert_eq!(
        details["approveRequest"]["payload"]["targetAcr"], "aal2",
        "{v}"
    );
}

/// Delegated step-up: a distinct, authorized approver (`issuer != subject`)
/// ratifies and the *subject's* session elevates. Mirrors the VTA's
/// `mode: delegated` flow — the approve-request was addressed to the subject's
/// `AclEntry.stepUp.approver`, recorded on the pending step-up at mint. The
/// approver signs with its own key and authenticates as itself.
#[tokio::test]
async fn delegated_approve_response_elevates_the_subjects_session() {
    let (router, ctx) = build_test_app().await;

    // The subject: an AAL1 session being elevated (the requester).
    let subject = "did:key:z6MkDelegatedSubject".to_string();
    let session_id = "sess-delegated-1".to_string();
    let challenge = "RGVsZWdhdGVkU3RlcFVwQ2hhbGxlbmdlWFla".to_string();
    let subject_session = Session {
        session_id: session_id.clone(),
        did: subject.clone(),
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
    store_session(&ctx.sessions_ks, &subject_session)
        .await
        .unwrap();

    // The approver: a *different* principal with its own key, session, token.
    let approver_sk = SigningKey::from_bytes(&[21u8; 32]);
    let (approver_did, approver_mb) = did_key(&approver_sk);
    let approver_vm = format!("{approver_did}#{approver_mb}");
    let approver_session_id = "sess-approver-1".to_string();
    let approver_session = Session {
        session_id: approver_session_id.clone(),
        did: approver_did.clone(),
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
    store_session(&ctx.sessions_ks, &approver_session)
        .await
        .unwrap();
    let approver_claims = ctx.jwt_keys.new_claims(
        approver_did.clone(),
        approver_session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let approver_token = ctx.jwt_keys.encode(&approver_claims).unwrap();

    // Pending step-up: subject == requester, approver == the delegate.
    let pending = new_pending_step_up(
        challenge.clone(),
        session_id.clone(),
        subject.clone(),
        approver_did.clone(), // delegated: approver != subject
        "aal2",
        vec!["did-signed".to_string()],
        300,
    );
    store_pending_step_up(&ctx.sessions_ks, &pending)
        .await
        .unwrap();

    // The approver signs: issuer == approver, payload.subject == the requester.
    let doc_json = json!({
        "id": "approve-resp-delegated-1",
        "type": "https://trusttasks.org/spec/auth/step-up/approve-response/0.1",
        "issuer": approver_did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {
            "subject": subject,
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
        verification_method: approver_vm,
        proof_purpose: "assertionMethod".to_string(),
        proof_value: None,
        context: None,
    };
    let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
    di.proof_value = Some(multibase::encode(
        Base::Base58Btc,
        approver_sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(serde_json::from_value::<Proof>(serde_json::to_value(&di).unwrap()).unwrap());

    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {approver_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {v}");
    assert_eq!(v["payload"]["status"], "elevated", "{v}");
    assert_eq!(v["payload"]["session"]["acr"], "aal2", "{v}");
    // The elevated session is the SUBJECT's — not the approver's.
    assert_eq!(v["payload"]["session"]["subject"], subject, "{v}");

    let stored = get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.acr, "aal2");
    // The approver's own session is untouched by ratifying for someone else.
    let approver_stored = get_session(&ctx.sessions_ks, &approver_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approver_stored.acr, "aal1");
}

/// An approver the relying party did NOT authorize for the subject is rejected
/// (`approver_unauthorized`) and elevates nothing — even with a perfectly valid
/// signature over the document. The pending step-up records approver B; a
/// different valid signer C tries to ratify the subject's session.
#[tokio::test]
async fn unauthorized_approver_cannot_elevate() {
    let (router, ctx) = build_test_app().await;

    let subject = "did:key:z6MkUnauthSubject".to_string();
    let session_id = "sess-unauth-1".to_string();
    let challenge = "VW5hdXRob3JpemVkQXBwcm92ZXJDaGFsbFha".to_string();
    let subject_session = Session {
        session_id: session_id.clone(),
        did: subject.clone(),
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
    store_session(&ctx.sessions_ks, &subject_session)
        .await
        .unwrap();

    // The pending step-up authorizes a specific approver (B).
    let authorized = "did:key:z6MkAuthorizedApprover".to_string();
    let pending = new_pending_step_up(
        challenge.clone(),
        session_id.clone(),
        subject.clone(),
        authorized.clone(),
        "aal2",
        vec!["did-signed".to_string()],
        300,
    );
    store_pending_step_up(&ctx.sessions_ks, &pending)
        .await
        .unwrap();

    // A DIFFERENT signer (C) — valid key, session, token — attempts to ratify.
    let rogue_sk = SigningKey::from_bytes(&[33u8; 32]);
    let (rogue_did, rogue_mb) = did_key(&rogue_sk);
    let rogue_vm = format!("{rogue_did}#{rogue_mb}");
    let rogue_session_id = "sess-rogue-1".to_string();
    let rogue_session = Session {
        session_id: rogue_session_id.clone(),
        did: rogue_did.clone(),
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
    store_session(&ctx.sessions_ks, &rogue_session)
        .await
        .unwrap();
    let rogue_claims = ctx.jwt_keys.new_claims(
        rogue_did.clone(),
        rogue_session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let rogue_token = ctx.jwt_keys.encode(&rogue_claims).unwrap();

    // C signs its own well-formed approve-response for the subject's session.
    let doc_json = json!({
        "id": "approve-resp-rogue-1",
        "type": "https://trusttasks.org/spec/auth/step-up/approve-response/0.1",
        "issuer": rogue_did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {
            "subject": subject,
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
        verification_method: rogue_vm,
        proof_purpose: "assertionMethod".to_string(),
        proof_value: None,
        context: None,
    };
    let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
    di.proof_value = Some(multibase::encode(
        Base::Base58Btc,
        rogue_sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(serde_json::from_value::<Proof>(serde_json::to_value(&di).unwrap()).unwrap());

    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {rogue_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    // Rejected with the authorization failure; nothing elevated.
    assert_ne!(
        status,
        StatusCode::OK,
        "unauthorized approver must not elevate: {v}"
    );
    assert!(
        serde_json::to_string(&v)
            .unwrap()
            .contains("approver_unauthorized"),
        "expected approver_unauthorized, got: {v}"
    );
    let stored = get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.acr, "aal1", "subject session must remain AAL1");
}
