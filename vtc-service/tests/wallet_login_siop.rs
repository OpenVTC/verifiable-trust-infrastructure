//! VTA-wallet SIOP login integration tests.
//!
//! Drives the header-exempt wallet auth surface end-to-end exactly as
//! the browser wallet extension does:
//!
//! 1. `POST /v1/wallet/auth/challenge { did }` → `{ challenge, sessionId }`.
//! 2. The holder self-issues a SIOPv2 `id_token` (compact EdDSA JWS,
//!    `iss == sub == holder`, `aud == this VTC's DID`, `nonce == challenge`).
//! 3. `POST /v1/wallet/auth/` with `{ type, payload: { id_token, session_id } }`
//!    → `{ session, tokens }` bearer.
//!
//! No `Trust-Task` header is sent on either request — these aliases are
//! deliberately exempt so the generic wallet extension works unchanged.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vti_common::auth::session::now_epoch;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::TestVtc;

/// The RP (this VTC's) DID — only ever string-compared as the id_token
/// `aud`, so it need not be resolvable.
const VTC_DID: &str = "did:webvh:scidvtc:vtc.example.com";
const AUTH_TYPE: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

struct Fixture {
    router: axum::Router,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture(holder_did: &str) -> Fixture {
    // The SIOP wallet-login path resolves the presented holder DID through
    // a live `DIDCacheClient`.
    let vtc = TestVtc::builder()
        .vtc_did(VTC_DID)
        .with_did_resolver(true)
        .build()
        .await;

    // The holder must be an ACL admin: challenge issuance and the
    // authenticate step both gate on the ACL.
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: holder_did.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "test".into(),
            expires_at: None,
        },
    )
    .await
    .expect("acl insert");

    Fixture {
        router: vtc.router.clone(),
        _vtc: vtc,
    }
}

/// A fresh Ed25519 holder identity as a `did:key`, plus its
/// verification-method id (`did:key:z…#z…`).
fn holder_identity(seed: u8) -> (SigningKey, String, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xed, 0x01]);
    buf.extend_from_slice(&sk.verifying_key().to_bytes());
    let mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    let did = format!("did:key:{mb}");
    let kid = format!("{did}#{mb}");
    (sk, did, kid)
}

#[allow(clippy::too_many_arguments)]
fn sign_id_token(
    sk: &SigningKey,
    kid: &str,
    iss: &str,
    sub: &str,
    aud: &str,
    nonce: &str,
    iat: u64,
    exp: u64,
) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let payload =
        json!({ "iss": iss, "sub": sub, "aud": aud, "nonce": nonce, "iat": iat, "exp": exp });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

async fn post_json(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Run the challenge → return `(session_id, challenge)`.
async fn get_challenge(router: &axum::Router, holder: &str) -> (String, String) {
    let (status, body) = post_json(
        router,
        "/v1/wallet/auth/challenge",
        json!({ "did": holder }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge failed: {body}");
    let session_id = body["sessionId"].as_str().expect("sessionId").to_string();
    let challenge = body["challenge"].as_str().expect("challenge").to_string();
    (session_id, challenge)
}

#[tokio::test]
async fn wallet_login_happy_path_mints_bearer() {
    let (sk, holder, kid) = holder_identity(1);
    let fix = build_fixture(&holder).await;
    let (session_id, challenge) = get_challenge(&fix.router, &holder).await;

    let now = now_epoch();
    let id_token = sign_id_token(
        &sk,
        &kid,
        &holder,
        &holder,
        VTC_DID,
        &challenge,
        now,
        now + 300,
    );

    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "authenticate failed: {body}");
    assert!(
        body["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "expected a bearer access token, got {body}"
    );
    assert_eq!(body["session"]["subject"].as_str(), Some(holder.as_str()));
}

#[tokio::test]
async fn wallet_login_rejects_tampered_signature() {
    let (sk, holder, kid) = holder_identity(2);
    let fix = build_fixture(&holder).await;
    let (session_id, challenge) = get_challenge(&fix.router, &holder).await;

    let now = now_epoch();
    let mut id_token = sign_id_token(
        &sk,
        &kid,
        &holder,
        &holder,
        VTC_DID,
        &challenge,
        now,
        now + 300,
    );
    // Corrupt the signature. Flip a character at the START of the signature
    // segment, not the trailing char: a 64-byte Ed25519 signature base64url-
    // encodes to 86 chars whose final char carries only 2 significant bits, so
    // flipping it (e.g. 'A'->'B') decodes to the same signature bytes under a
    // lenient decoder and leaves the token validly signed (~25% of runs, since
    // the per-run challenge randomises the signature). A leading char carries a
    // full 6 bits, so the flip always changes the signature → reliably invalid.
    let sig_start = id_token.rfind('.').expect("jws has a signature segment") + 1;
    let replacement = if id_token.as_bytes()[sig_start] == b'A' {
        'B'
    } else {
        'A'
    };
    id_token.replace_range(sig_start..sig_start + 1, &replacement.to_string());

    let (status, _) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wallet_login_rejects_wrong_audience() {
    let (sk, holder, kid) = holder_identity(3);
    let fix = build_fixture(&holder).await;
    let (session_id, challenge) = get_challenge(&fix.router, &holder).await;

    let now = now_epoch();
    // aud is some other RP — must not authenticate against this VTC.
    let id_token = sign_id_token(
        &sk,
        &kid,
        &holder,
        &holder,
        "did:webvh:other:rp.example.com",
        &challenge,
        now,
        now + 300,
    );

    let (status, _) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wallet_login_rejects_nonce_not_matching_challenge() {
    let (sk, holder, kid) = holder_identity(4);
    let fix = build_fixture(&holder).await;
    let (session_id, _challenge) = get_challenge(&fix.router, &holder).await;

    let now = now_epoch();
    // Wrong nonce — a valid signature over the wrong challenge must
    // fail the session's challenge-match in handle_authenticate.
    let id_token = sign_id_token(
        &sk,
        &kid,
        &holder,
        &holder,
        VTC_DID,
        "not-the-challenge",
        now,
        now + 300,
    );

    let (status, _) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Phase 3: bearer → cookie bridge (`/v1/auth/admin-session`) ───

const ADMIN_SESSION_TASK: &str = "https://trusttasks.org/openvtc/vtc/auth/admin-session/1.0";
const WHOAMI_TASK: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

/// Run a full wallet login and return the minted bearer access token.
async fn wallet_login_bearer(fix: &Fixture, sk: &SigningKey, holder: &str, kid: &str) -> String {
    let (session_id, challenge) = get_challenge(&fix.router, holder).await;
    let now = now_epoch();
    let id_token = sign_id_token(sk, kid, holder, holder, VTC_DID, &challenge, now, now + 300);
    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["tokens"]["accessToken"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn admin_session_bridges_bearer_to_cookie_and_authenticates() {
    let (sk, holder, kid) = holder_identity(5);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;

    // Exchange the bearer for the SPA cookie session. Browser-style:
    // same-origin stamp carries CSRF, Trust-Task header satisfies the gate.
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/admin-session")
                .header("content-type", "application/json")
                .header("trust-task", ADMIN_SESSION_TASK)
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "accessToken": bearer })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // The session cookie must be set; capture it for the follow-up call.
    let set_cookies: Vec<String> = res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let session_cookie = set_cookies
        .iter()
        .find(|c| c.starts_with("vtc_admin_session="))
        .expect("vtc_admin_session cookie set");
    let cookie_pair = session_cookie.split(';').next().unwrap().to_string();

    // The cookie alone (no Authorization header) authenticates `whoami`.
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/auth/whoami")
                .header("trust-task", WHOAMI_TASK)
                .header("cookie", cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let who: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(who["did"].as_str(), Some(holder.as_str()));
}

#[tokio::test]
async fn admin_session_rejects_garbage_token() {
    let (_sk, holder, _kid) = holder_identity(6);
    let fix = build_fixture(&holder).await;

    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/admin-session")
                .header("content-type", "application/json")
                .header("trust-task", ADMIN_SESSION_TASK)
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "accessToken": "not.a.jwt" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // No cookie on rejection.
    assert!(res.headers().get(axum::http::header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn wallet_login_rejects_iss_not_matching_session() {
    // SSRF gate: a token whose `iss` differs from the DID the challenge
    // session was issued to is rejected before the verifier resolves `iss`.
    // `holder` got the challenge (and is ACL'd); `stranger` self-issued the
    // token. The mismatch must 401.
    let (_sk_h, holder, _kid_h) = holder_identity(7);
    let (sk_s, stranger, kid_s) = holder_identity(8);
    let fix = build_fixture(&holder).await;
    let (session_id, challenge) = get_challenge(&fix.router, &holder).await;

    let now = now_epoch();
    let id_token = sign_id_token(
        &sk_s,
        &kid_s,
        &stranger,
        &stranger,
        VTC_DID,
        &challenge,
        now,
        now + 300,
    );

    let (status, _) = post_json(
        &fix.router,
        "/v1/wallet/auth/",
        json!({ "type": AUTH_TYPE, "payload": { "id_token": id_token, "session_id": session_id } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
