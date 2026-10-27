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

use crate::common::signed::{assert_conforms, error_code, post_for_cookies, signed_to, unsigned};

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
            admin: VtcRole::Admin.implied_authority(),
            delegated_by: None,
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            group_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
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

// ─── Phase 3: bearer → cookie bridge (`vtc/auth/admin-session/0.2`) ───
//
// A signed document on `POST /v1/trust-tasks` since #1641's last batch: the
// specification declares `proof` REQUIRED, and the proof's signer must be the
// access token's subject (or a console key it enrolled). The bearer route
// `POST /v1/auth/admin-session` is gone.

const ADMIN_SESSION_TASK: &str = "https://trusttasks.org/spec/vtc/auth/admin-session/0.2";
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

/// The signing party for `holder_identity(seed)` — the same key, as the
/// document signer the shared helpers take.
fn holder_party(seed: u8) -> vti_rooms_dtg::test_support::Party {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    vti_rooms_dtg::test_support::Party {
        secret: vta_sdk::did_key::secrets_from_did_key(&did, &[seed; 32])
            .expect("build secrets")
            .signing,
        secret_multibase: multibase::encode(multibase::Base::Base58Btc, [seed; 32]),
        did,
    }
}

/// Send `vtc/auth/admin-session/0.2` for `access_token`, signed by `signer`.
async fn admin_session_signed_by(
    fix: &Fixture,
    signer: &vti_rooms_dtg::test_support::Party,
    access_token: &str,
) -> (StatusCode, Vec<String>, Value) {
    let doc = signed_to(
        signer,
        VTC_DID,
        ADMIN_SESSION_TASK,
        json!({ "accessToken": access_token }),
    )
    .await;
    post_for_cookies(&fix._vtc, &doc).await
}

#[tokio::test]
async fn admin_session_bridges_bearer_to_cookie_and_authenticates() {
    let (sk, holder, kid) = holder_identity(5);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;

    // Exchange the bearer for the SPA cookie session, the document signed by
    // the identity the token was issued to — as the console has the wallet
    // sign it after a SIOP sign-in — and naming the browser key the console
    // binds to the session.
    let browser = vti_rooms_dtg::test_support::Party::new();
    let doc = signed_to(
        &holder_party(5),
        VTC_DID,
        ADMIN_SESSION_TASK,
        json!({
            "accessToken": bearer,
            "ext": { "org.openvtc": { "sessionKey": browser.did } },
        }),
    )
    .await;
    let (status, set_cookies, doc) = post_for_cookies(&fix._vtc, &doc).await;
    // `{sessionId, expiresAt}` since #1059 — it was 204 with the result only
    // in `Set-Cookie`, which no non-browser caller could read.
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_conforms(ADMIN_SESSION_TASK, &doc);
    let session_id = doc["payload"]["sessionId"].as_str().unwrap().to_string();

    // The cookies ride the signed door's response, and authenticate the
    // console's access-token extractor.
    let session_cookie = set_cookies
        .iter()
        .find(|c| c.starts_with("vtc_admin_session="))
        .expect("vtc_admin_session cookie set");
    assert!(set_cookies.iter().any(|c| c.starts_with("csrf=")));
    let cookie_pair = session_cookie.split(';').next().unwrap().to_string();
    let (status, body) =
        crate::common::session_probe::probe(&fix._vtc, &[("cookie", cookie_pair)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // And the browser key is bound to that session: it signs `whoami`, which
    // answers with the session's subject.
    let whoami = signed_to(&browser, VTC_DID, WHOAMI_TASK, json!({})).await;
    let (status, _, who) = post_for_cookies(&fix._vtc, &whoami).await;
    assert_eq!(status, StatusCode::OK, "{who}");
    assert_eq!(
        who["payload"]["session"]["subject"].as_str(),
        Some(holder.as_str())
    );
    assert_eq!(
        who["payload"]["session"]["id"].as_str(),
        Some(session_id.as_str())
    );
}

/// A console key acts for its administrator, but does not take a session key
/// away from the subject's own client: only the subject's signature rebinds.
#[tokio::test]
async fn admin_session_lets_only_the_subject_rebind_a_session_key() {
    let (sk, holder, kid) = holder_identity(12);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;
    let first = vti_rooms_dtg::test_support::Party::new();
    let second = vti_rooms_dtg::test_support::Party::new();
    let console = vti_rooms_dtg::test_support::Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix._vtc.state.console_keys_ks,
        &fix._vtc.state.acl_ks,
        &console.did,
        &holder,
        None,
        None,
    )
    .await
    .unwrap();
    let with_key = |key: &str| json!({ "accessToken": bearer, "ext": { "org.openvtc": { "sessionKey": key } } });

    // The subject binds the first key.
    let doc = signed_to(
        &holder_party(12),
        VTC_DID,
        ADMIN_SESSION_TASK,
        with_key(&first.did),
    )
    .await;
    assert_eq!(post_for_cookies(&fix._vtc, &doc).await.0, StatusCode::OK);
    // A console key may not replace it…
    let doc = signed_to(&console, VTC_DID, ADMIN_SESSION_TASK, with_key(&second.did)).await;
    let (status, cookies, reply) = post_for_cookies(&fix._vtc, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(cookies.is_empty());
    // …the subject may.
    let doc = signed_to(
        &holder_party(12),
        VTC_DID,
        ADMIN_SESSION_TASK,
        with_key(&second.did),
    )
    .await;
    assert_eq!(post_for_cookies(&fix._vtc, &doc).await.0, StatusCode::OK);
    let whoami = signed_to(&second, VTC_DID, WHOAMI_TASK, json!({})).await;
    assert_eq!(post_for_cookies(&fix._vtc, &whoami).await.0, StatusCode::OK);
    let whoami = signed_to(&first, VTC_DID, WHOAMI_TASK, json!({})).await;
    assert_eq!(
        post_for_cookies(&fix._vtc, &whoami).await.0,
        StatusCode::FORBIDDEN,
        "the replaced key no longer speaks for the session"
    );
}

/// A session key that is not an Ed25519 `did:key` is refused, and sets nothing.
#[tokio::test]
async fn admin_session_refuses_a_session_key_that_is_not_an_ed25519_did_key() {
    let (sk, holder, kid) = holder_identity(13);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;
    let doc = signed_to(
        &holder_party(13),
        VTC_DID,
        ADMIN_SESSION_TASK,
        json!({ "accessToken": bearer, "ext": { "org.openvtc": { "sessionKey": "did:web:example.com" } } }),
    )
    .await;
    let (status, cookies, reply) = post_for_cookies(&fix._vtc, &doc).await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert!(cookies.is_empty());
}

/// VTI-OPS-020: the task declares `proof` REQUIRED, so an access token alone —
/// what the bearer route took — no longer opens a cookie session.
#[tokio::test]
async fn admin_session_refuses_an_unsigned_document() {
    let (sk, holder, kid) = holder_identity(9);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;

    let doc = unsigned(
        &holder_party(9),
        ADMIN_SESSION_TASK,
        json!({ "accessToken": bearer }),
    );
    let (status, cookies, reply) = post_for_cookies(&fix._vtc, &doc).await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert!(error_code(&reply).is_some(), "{reply}");
    assert!(cookies.is_empty(), "no cookie on refusal: {cookies:?}");
}

/// A token stolen from its subject cannot be turned into a cookie session by
/// whoever holds it: the document must be signed by the token's subject.
#[tokio::test]
async fn admin_session_refuses_a_signer_who_is_not_the_tokens_subject() {
    let (sk, holder, kid) = holder_identity(10);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;

    let thief = vti_rooms_dtg::test_support::Party::new();
    let (status, cookies, reply) = admin_session_signed_by(&fix, &thief, &bearer).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(error_code(&reply), Some("permissionDenied"), "{reply}");
    assert!(cookies.is_empty(), "no cookie on refusal: {cookies:?}");
}

/// A console key the subject enrolled speaks for the subject here, exactly as
/// it does for every administrator verb — and only while its delegation lasts.
#[tokio::test]
async fn admin_session_accepts_a_console_key_its_subject_enrolled() {
    let (sk, holder, kid) = holder_identity(11);
    let fix = build_fixture(&holder).await;
    let bearer = wallet_login_bearer(&fix, &sk, &holder, &kid).await;

    let console = vti_rooms_dtg::test_support::Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix._vtc.state.console_keys_ks,
        &fix._vtc.state.acl_ks,
        &console.did,
        &holder,
        Some("test browser".into()),
        None,
    )
    .await
    .unwrap();

    let (status, cookies, reply) = admin_session_signed_by(&fix, &console, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        cookies.iter().any(|c| c.starts_with("vtc_admin_session=")),
        "{cookies:?}"
    );

    // Revoked, it speaks for nobody.
    vtc_service::acl::console_key::revoke_delegation(
        &fix._vtc.state.console_keys_ks,
        &console.did,
        &holder,
    )
    .await
    .unwrap();
    let (status, cookies, reply) = admin_session_signed_by(&fix, &console, &bearer).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(cookies.is_empty(), "{cookies:?}");
}

#[tokio::test]
async fn admin_session_rejects_garbage_token() {
    let (_sk, holder, _kid) = holder_identity(6);
    let fix = build_fixture(&holder).await;

    let (status, cookies, reply) =
        admin_session_signed_by(&fix, &holder_party(6), "not.a.jwt").await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        error_code(&reply),
        Some(vtc_service::routes::auth::ADMIN_SESSION_ERR_INVALID_TOKEN),
        "{reply}"
    );
    // No cookie on rejection.
    assert!(cookies.is_empty(), "{cookies:?}");
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

// ---------------------------------------------------------------------------
// Mediator-less refresh (#783)
// ---------------------------------------------------------------------------
//
// The fixture above is built with **no ATM** (`TestVtc` defaults `atm: None`),
// which is what makes these tests load-bearing: before the REST fast-path,
// `POST /v1/auth/refresh` went straight to `atm.unpack` and every request here
// died on "ATM not configured". A REST-only wallet could log in without a
// mediator but could not spend the refresh token it was handed — so it re-ran
// the whole SIOP round-trip on each access-token expiry.

const REFRESH_TYPE: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

/// A canonical `auth/refresh/0.1` Trust Task document. `refreshToken` is
/// camelCase per the generated spec payload (R3.1) — deliberately *not* the
/// DIDComm body's snake_case `refresh_token`, so one document builder serves
/// both the VTA and the VTC over REST.
fn refresh_doc(refresh_token: &str) -> Value {
    json!({
        "id": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "type": REFRESH_TYPE,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "refreshToken": refresh_token },
    })
}

/// POST with an explicit `Trust-Task` header — the header-gated `/v1/auth/*`
/// surface used by CLI/SDK clients (the `/v1/wallet/*` aliases are exempt).
async fn post_with_task_header(
    router: &axum::Router,
    path: &str,
    task: &str,
    body: Value,
) -> (StatusCode, Value) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("Trust-Task", task)
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

/// Run a full wallet login and return the whole `{ session, tokens }` body.
async fn wallet_login_tokens(fix: &Fixture, sk: &SigningKey, holder: &str, kid: &str) -> Value {
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
    body
}

#[tokio::test]
async fn rest_only_login_then_refresh_needs_no_didcomm() {
    let (sk, holder, kid) = holder_identity(20);
    let fix = build_fixture(&holder).await;

    // Leg 1 — SIOP login over plain REST.
    let login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let refresh_token = login["tokens"]["refreshToken"]
        .as_str()
        .expect("login must issue a refresh token")
        .to_string();
    let first_access = login["tokens"]["accessToken"].as_str().unwrap().to_string();

    // Leg 2 — spend it on the header-exempt wallet alias. No mediator, no
    // DIDComm envelope, no `Trust-Task` header.
    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/refresh",
        refresh_doc(&refresh_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "REST refresh failed: {body}");
    let new_access = body["tokens"]["accessToken"]
        .as_str()
        .expect("refresh must mint an access token");
    assert!(!new_access.is_empty());
    assert_ne!(
        new_access, first_access,
        "refresh must mint a *new* access token, not echo the old one"
    );
    // The session survives rotation and still names the same subject.
    assert_eq!(body["session"]["subject"].as_str(), Some(holder.as_str()));
}

#[tokio::test]
async fn rest_refresh_rotates_and_the_old_token_is_dead() {
    // RFC 6749 §10.4: every successful refresh mints a new refresh token and
    // retires the presented one, so a token is worth exactly one rotation.
    //
    // "Retired" is not the same as "instantly refused". An immediate replay
    // still falls inside `refresh_reuse_grace` with the replacement unspent,
    // which is indistinguishable from a client retrying a rotation response
    // that was lost in flight, so it is answered idempotently with the *same*
    // pair. What it must never do is open a second, parallel chain.
    //
    // Once the chain moves on, the concession lapses and the spent token is
    // reuse: refused, and the whole session revoked with it (RFC 9700
    // §4.14.2). A replayed token then reads as "not found" — the same shape a
    // revoked token gives, so a leak is not distinguishable by probing.
    let (sk, holder, kid) = holder_identity(21);
    let fix = build_fixture(&holder).await;

    let login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let first = login["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&first)).await;
    assert_eq!(status, StatusCode::OK, "first refresh failed: {body}");
    let second = body["tokens"]["refreshToken"]
        .as_str()
        .expect("rotation must return a new refresh token")
        .to_string();
    assert_ne!(second, first, "refresh token must rotate");

    // Replay the spent token while the successor is still unspent: a retry.
    // It must re-serve the existing chain, never fork a new one.
    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&first)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an immediate retry is a lost response, not a compromise: {body}"
    );
    assert_eq!(
        body["tokens"]["refreshToken"].as_str(),
        Some(second.as_str()),
        "the retry must replay the same token, never mint a second live one",
    );

    // Advance the chain. Now the spent token cannot be a retry by anyone.
    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&second)).await;
    assert_eq!(status, StatusCode::OK, "second refresh failed: {body}");
    let third = body["tokens"]["refreshToken"]
        .as_str()
        .expect("rotation must return a new refresh token")
        .to_string();

    // Replaying the retired token is now unambiguous reuse.
    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&first)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a spent refresh token must not work once the chain has moved on: {body}"
    );

    // Detection revokes the session, so the descendant token dies with it —
    // the attacker's stolen chain and the victim's are the same chain.
    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&third)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reuse detection must revoke every token descended from the replayed one: {body}"
    );
}

#[tokio::test]
async fn a_second_login_retires_the_first_logins_refresh_token() {
    // The residual gap found in review of the reuse-detection work, driven
    // end to end against the real login and refresh routes.
    //
    // Rotation alone could not close it. Reuse detection fires when a token
    // is presented *twice*, and logging in again used to mint a second token
    // without retiring the first — two live chains on one account that never
    // shared a token, so no replay ever occurred and nothing ever fired. A
    // token stolen before a re-login kept working indefinitely, silently,
    // alongside its owner's. It also broke the one recovery step a user can
    // take unaided: logging in again did nothing to the thief's token.
    let (sk, holder, kid) = holder_identity(23);
    let fix = build_fixture(&holder).await;

    // First login. Treat this token as the one that gets stolen.
    let first_login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let stolen = first_login["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();

    // The owner logs in again — the recovery action.
    let second_login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let current = second_login["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(current, stolen, "a second login must mint its own token");

    // The pre-login token must be dead, not the head of a parallel chain.
    let (status, body) =
        post_json(&fix.router, "/v1/wallet/auth/refresh", refresh_doc(&stolen)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token from before the re-login must not still work: {body}"
    );

    // And because presenting it is a signal worth reporting but not a
    // reason to punish the live client, the session that replaced it
    // keeps working. The retired token is already dead; revoking on top
    // would sign out the device that is demonstrably current in order to
    // answer one whose token has already stopped working.
    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/refresh",
        refresh_doc(&current),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the newest login's token must survive a replay of the one it retired: {body}"
    );
}

#[tokio::test]
async fn a_second_login_leaves_the_account_usable() {
    // The other half of the fix: retiring the previous token must not break
    // the ordinary case of simply logging in again and carrying on.
    let (sk, holder, kid) = holder_identity(24);
    let fix = build_fixture(&holder).await;

    wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let second_login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let current = second_login["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/refresh",
        refresh_doc(&current),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the newest login's token must still refresh normally: {body}"
    );
}

#[tokio::test]
async fn rest_refresh_also_works_on_the_header_gated_route() {
    // The CLI/SDK surface. Same handler, same document — it just arrives on
    // `/v1/auth/refresh` behind the `Trust-Task` gate instead of the
    // header-exempt wallet alias.
    let (sk, holder, kid) = holder_identity(22);
    let fix = build_fixture(&holder).await;

    let login = wallet_login_tokens(&fix, &sk, &holder, &kid).await;
    let refresh_token = login["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = post_with_task_header(
        &fix.router,
        "/v1/auth/refresh",
        REFRESH_TYPE,
        refresh_doc(&refresh_token),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "header-gated REST refresh failed: {body}"
    );
    assert!(
        body["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "expected rotated tokens, got {body}"
    );
}

#[tokio::test]
async fn rest_refresh_rejects_an_unknown_token() {
    let (_sk, holder, _kid) = holder_identity(23);
    let fix = build_fixture(&holder).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/refresh",
        refresh_doc("rt_never-issued-by-this-vtc"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unissued refresh token must be rejected: {body}"
    );
}

#[tokio::test]
async fn rest_refresh_rejects_a_malformed_payload() {
    // The document *is* an `auth/refresh/0.1` Trust Task, so the fast-path
    // owns it and must fail loudly rather than fall through to the DIDComm
    // path and report the misleading "ATM not configured" / "failed to unpack".
    // `refresh::Payload` is `deny_unknown_fields`, so the snake_case spelling
    // is a hard error, not a silently-missing token.
    let (_sk, holder, _kid) = holder_identity(24);
    let fix = build_fixture(&holder).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/wallet/auth/refresh",
        json!({
            "id": "urn:uuid:99999999-9999-9999-9999-999999999999",
            "type": REFRESH_TYPE,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "refresh_token": "wrong-casing" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "got {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid refresh payload"),
        "the error must name the payload as the problem, got: {body}"
    );
}
