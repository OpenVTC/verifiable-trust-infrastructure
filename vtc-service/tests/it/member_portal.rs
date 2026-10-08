//! Member-portal sign-in (`/v1/member/*`, `crate::member_portal`).
//!
//! The properties that make the portal a separate application rather than the
//! console with a role check:
//!
//! - only an **active member** gets a session — not an administrator with no
//!   member record, not a removed member, not one removed mid-session;
//! - a member token is refused by the console (audience), and a console token
//!   by the portal;
//! - a member's refresh token cannot be spent at the console's
//!   `/v1/auth/refresh` (separate session keyspace) — even when the member is
//!   also an administrator.

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
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::test_support::TestVtc;

const VTC_DID: &str = "did:webvh:scidvtc:vtc.example.com";
const AUTH_TYPE: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";
const REFRESH_TYPE: &str = "https://trusttasks.org/spec/auth/refresh/0.1";
const WHOAMI_TASK: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

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

fn sign_id_token(sk: &SigningKey, kid: &str, did: &str, nonce: &str) -> String {
    let now = now_epoch();
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let payload = json!({
        "iss": did, "sub": did, "aud": VTC_DID, "nonce": nonce,
        "iat": now, "exp": now + 300,
    });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&payload).unwrap());
    let input = format!("{h}.{p}");
    let sig = sk.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

fn acl_entry(did: &str, role: VtcRole) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        admin: role.implied_authority(),
        role,
        label: None,
        delegated_by: None,
        created_at: now_epoch(),
        created_by: "test".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    }
}

async fn vtc() -> TestVtc {
    TestVtc::builder()
        .vtc_did(VTC_DID)
        .with_did_resolver(true)
        .build()
        .await
}

/// An ACL entry with `role`, and — when `member` — a live member record.
async fn enrol(vtc: &TestVtc, did: &str, role: VtcRole, member: bool) {
    store_acl_entry(&vtc.state.acl_ks, &acl_entry(did, role))
        .await
        .unwrap();
    if member {
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, Vec<String>) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&b).unwrap())
        }
        None => Body::empty(),
    };
    let res = router
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let cookies = res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookies,
    )
}

/// Wallet sign-in at `<base>`; returns the authenticate status and body.
async fn wallet_sign_in(
    router: &axum::Router,
    base: &str,
    sk: &SigningKey,
    did: &str,
    kid: &str,
) -> (StatusCode, Value) {
    let (status, body, _) = send(
        router,
        "POST",
        &format!("{base}/auth/challenge"),
        &[],
        Some(json!({ "did": did })),
    )
    .await;
    // Every caller gets a challenge (VTI-SES-007); a non-member's is unusable.
    assert_eq!(status, StatusCode::OK, "challenge: {body}");
    let session_id = body["sessionId"].as_str().unwrap().to_string();
    let challenge = body["challenge"].as_str().unwrap().to_string();
    let (status, body, _) = send(
        router,
        "POST",
        &format!("{base}/auth/"),
        &[],
        Some(json!({
            "type": AUTH_TYPE,
            "payload": { "id_token": sign_id_token(sk, kid, did, &challenge), "session_id": session_id },
        })),
    )
    .await;
    (status, body)
}

async fn member_sign_in(vtc: &TestVtc, sk: &SigningKey, did: &str, kid: &str) -> Value {
    let (status, body) = wallet_sign_in(&vtc.router, "/v1/member/wallet", sk, did, kid).await;
    assert_eq!(status, StatusCode::OK, "member sign-in: {body}");
    body
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn active_member_signs_in_and_reads_me() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(41);
    enrol(&vtc, &did, VtcRole::Member, true).await;

    let body = member_sign_in(&vtc, &sk, &did, &kid).await;
    let token = body["tokens"]["accessToken"].as_str().unwrap();

    let (status, me, _) = send(
        &vtc.router,
        "GET",
        "/v1/member/me",
        &[("authorization", &bearer(token))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["did"], did);
    assert_eq!(me["role"], "member");
    assert_eq!(
        me["canManagePasskeys"], true,
        "a wallet session proves the DID"
    );
}

#[tokio::test]
async fn member_token_is_refused_by_the_console_and_vice_versa() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(42);
    // An administrator who is also a member: the strongest case, since the
    // console would admit this DID on its own terms.
    enrol(&vtc, &did, VtcRole::Admin, true).await;

    let member = member_sign_in(&vtc, &sk, &did, &kid).await;
    let member_token = member["tokens"]["accessToken"].as_str().unwrap();
    let (status, _, _) = send(
        &vtc.router,
        "GET",
        "/v1/auth/whoami",
        &[
            ("authorization", &bearer(member_token)),
            ("trust-task", WHOAMI_TASK),
        ],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "member token reached the console"
    );

    let (status, admin) = wallet_sign_in(&vtc.router, "/v1/wallet", &sk, &did, &kid).await;
    assert_eq!(status, StatusCode::OK, "{admin}");
    let admin_token = admin["tokens"]["accessToken"].as_str().unwrap();
    let (status, _, _) = send(
        &vtc.router,
        "GET",
        "/v1/member/me",
        &[("authorization", &bearer(admin_token))],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "console token reached the portal"
    );
}

#[tokio::test]
async fn member_refresh_token_cannot_be_spent_at_the_console() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(43);
    enrol(&vtc, &did, VtcRole::Admin, true).await;

    let member = member_sign_in(&vtc, &sk, &did, &kid).await;
    let refresh = member["tokens"]["refreshToken"].as_str().unwrap();
    let doc = json!({
        "id": "urn:uuid:5b3c1f0e-8d1e-4d7e-9a43-2f1d6c0b7a11",
        "type": REFRESH_TYPE,
        "issuedAt": chrono::Utc::now().to_rfc3339(),
        "payload": { "refreshToken": refresh },
    });

    let (status, body, _) = send(
        &vtc.router,
        "POST",
        "/v1/wallet/auth/refresh",
        &[],
        Some(doc.clone()),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "console minted from a member refresh: {body}"
    );

    // It still works where it belongs.
    let (status, body, _) = send(
        &vtc.router,
        "POST",
        "/v1/member/wallet/auth/refresh",
        &[],
        Some(doc),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member refresh: {body}");
}

#[tokio::test]
async fn administrator_without_a_member_record_is_refused() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(44);
    enrol(&vtc, &did, VtcRole::Admin, false).await;
    let (status, _) = wallet_sign_in(&vtc.router, "/v1/member/wallet", &sk, &did, &kid).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stranger_and_application_entries_are_refused() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(45);
    let (status, _) = wallet_sign_in(&vtc.router, "/v1/member/wallet", &sk, &did, &kid).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no entry at all");

    let (sk, did, kid) = holder_identity(46);
    enrol(&vtc, &did, VtcRole::Application, true).await;
    let (status, _) = wallet_sign_in(&vtc.router, "/v1/member/wallet", &sk, &did, &kid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an application entry is not a membership"
    );
}

#[tokio::test]
async fn member_removed_mid_session_is_refused_on_the_next_request() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(47);
    enrol(&vtc, &did, VtcRole::Member, true).await;
    let body = member_sign_in(&vtc, &sk, &did, &kid).await;
    let token = body["tokens"]["accessToken"].as_str().unwrap().to_string();

    let mut m = get_member(&vtc.state.members_ks, &did)
        .await
        .unwrap()
        .unwrap();
    m.tombstone();
    store_member(&vtc.state.members_ks, &m).await.unwrap();

    let (status, _, _) = send(
        &vtc.router,
        "GET",
        "/v1/member/me",
        &[("authorization", &bearer(&token))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And a removed member cannot sign in again.
    let (status, _) = wallet_sign_in(&vtc.router, "/v1/member/wallet", &sk, &did, &kid).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_cookies_are_scoped_to_the_member_api() {
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(48);
    enrol(&vtc, &did, VtcRole::Member, true).await;
    let body = member_sign_in(&vtc, &sk, &did, &kid).await;

    let (status, resp, cookies) = send(
        &vtc.router,
        "POST",
        "/v1/member/session",
        &[("sec-fetch-site", "same-origin")],
        Some(json!({
            "accessToken": body["tokens"]["accessToken"],
            "refreshToken": body["tokens"]["refreshToken"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let find = |name: &str| {
        cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} not set: {cookies:?}"))
            .clone()
    };
    assert!(find("vtc_member_session").contains("Path=/v1/member;"));
    assert!(find("vtc_member_refresh").contains("Path=/v1/member;"));
    assert!(find("vtc_member_csrf").contains("Path=/;"));
    assert!(
        !cookies.iter().any(|c| c.starts_with("vtc_admin_session=")),
        "the portal must never set the console's cookie"
    );

    // The cookie alone authenticates `me`.
    let session = find("vtc_member_session");
    let pair = session.split(';').next().unwrap();
    let (status, me, _) = send(
        &vtc.router,
        "GET",
        "/v1/member/me",
        &[("cookie", pair)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
}

#[tokio::test]
async fn passkey_changes_require_a_wallet_proven_session() {
    // A passkey session cannot add passkeys; a wallet one gets past the gate
    // (and, in this harness with no WebAuthn configured, stops there).
    let vtc = vtc().await;
    let (sk, did, kid) = holder_identity(49);
    enrol(&vtc, &did, VtcRole::Member, true).await;
    let body = member_sign_in(&vtc, &sk, &did, &kid).await;
    let token = body["tokens"]["accessToken"].as_str().unwrap();
    let (status, resp, _) = send(
        &vtc.router,
        "POST",
        "/v1/member/passkeys/register/start",
        &[("authorization", &bearer(token))],
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "wallet session refused: {resp}"
    );
}

#[cfg(feature = "admin-ui")]
#[tokio::test]
async fn members_path_serves_the_portal_not_the_console_or_the_website() {
    let vtc = vtc().await;
    for path in ["/members/", "/members/some/deep/link"] {
        let res = vtc
            .router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("<title>VTC Members</title>"),
            "{path}: {html}"
        );
    }
}
