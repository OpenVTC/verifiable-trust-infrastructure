//! Integration tests for the VTA authentication flow.
//!
//! Pre-consolidation, this file held three "tests" that were actually
//! JSON serde round-trips and a `did.split('#')` tautology — none of
//! them touched the route layer. They were deleted in the same commit
//! that consolidated the integration-test scaffolding into
//! `vta_service::test_support`, and replaced with the real route-level
//! tests below.
//!
//! The pre-session auth family (`auth/challenge/0.1`,
//! `auth/authenticate/{0.2,0.3}`, `auth/refresh/0.2`) is Trust Tasks only
//! now, dispatched on `POST /trust-tasks` by a family-owned dispatch that
//! runs ahead of the ACL gate (see `trust_tasks::auth`) — the old
//! `/auth/challenge`, `/auth/` and `/auth/refresh` REST routes are gone.
//!
//! What's covered:
//! - `auth/challenge/0.1` issues a session_id + challenge for an
//!   ACL-permitted DID; the session is persisted under the returned
//!   session_id with the same challenge bytes.
//! - `auth/refresh/0.2` rejects malformed and unknown refresh
//!   tokens with 403 (`permissionDenied` — see `trust-tasks-https::
//!   status_for_code`; regression-pin against silent 500s).
//! - `TestAppContext` exposes the keyspaces auth tests need —
//!   surface check so future contributors don't have to grep.
//!
//! - The full challenge → DI-signed Trust Task → tokens round trip over
//!   plain HTTPS, driven by the *SDK's own* document builder. `did:key`
//!   resolution is local, so no network resolver is needed.
//!
//! What's NOT covered (intentional — needs real DID resolver):
//! - The same round trip over a DIDComm envelope, which needs a real
//!   mediator-backed ATM. That lives in the e2e suite.
//!
//! **The plaintext/forged-sender DIDComm envelope tests that used to live
//! here are gone, not merely moved.** They drove the old `/auth/` and
//! `/auth/refresh` REST handlers' own inline `atm.unpack` +
//! `bind_authcrypt_sender` guard directly with a crafted envelope — a
//! synchronous, offline-testable entry point. `POST /trust-tasks` has no
//! equivalent: it only ever reads a plain JSON Trust-Task envelope
//! (`ceremony::peek_type_uri`), never calls `atm.unpack`, and DIDComm-
//! transported Trust Tasks (including this auth family) now run through
//! the generic mediator-relay inbound pipeline
//! (`messaging::service::{inbound_gate, handle_didcomm}`), which is
//! inherently asynchronous and has no offline/in-process entry point here.
//! The security property itself is not untested: `inbound_gate` refuses
//! any frame that is not encrypted + transport-verified, for every Trust
//! Task alike (unit-tested in `messaging::service`, plus
//! `keyring_vti_27_gate`), the skid/apu sender-binding guard
//! (`vti_common::auth::bind_authcrypt_sender`) keeps its own unit tests and
//! its one remaining direct-unpack caller (vault unseal) is pinned by
//! `vault_unseal_authcrypt.rs` / `auth_authcrypt_sender_binding.rs`, and a
//! live-mediator authcrypt round trip lives in the e2e suite. What is gone
//! is the ability to drive *this specific* forged-sender battery
//! synchronously against the auth family from this test binary.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
    (status, json)
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        // Stamp a stable client IP so the per-IP rate limiter doesn't
        // throttle this test in a `cargo test --workspace` parallel
        // run that interleaves with the rate-limit test.
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// POST a raw string body (the `/auth/` handler reads `body: String`
/// directly, so the DIDComm envelope goes on the wire verbatim).
fn post_raw(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "text/plain")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(body))
        .unwrap()
}

/// A signed-nothing `auth/challenge/0.1` Trust Task for `subject`, addressed
/// to a recipient the VTA under test does not have to be.
fn challenge_doc(subject: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/challenge/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": subject,
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": { "subject": subject },
    })
}

/// A signed-nothing `auth/refresh/0.2` Trust Task carrying `refresh_token` —
/// unsigned by design, the opaque token is the sole credential.
fn refresh_doc(refresh_token: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/refresh/0.2",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": "did:key:z6MkRefresher",
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": { "refreshToken": refresh_token },
    })
}

/// `auth/challenge/0.1` (over `POST /trust-tasks`) returns a session_id +
/// challenge nonce and persists the challenge so the matching authenticate
/// document can look it up. Requires an ACL entry — the challenge endpoint is
/// gated on caller being in the ACL (otherwise an attacker could enumerate
/// session state by spamming challenge requests for arbitrary DIDs).
#[tokio::test]
async fn challenge_endpoint_issues_session_and_persists_it() {
    let (router, ctx) = build_test_app().await;

    let did = "did:key:z6MkChallengeTester";
    // Pre-grant the DID admin access so it passes the ACL check.
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

    let (status, body) = request(
        &router,
        post_json("/trust-tasks", challenge_doc(did)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "challenge issuance must succeed for an ACL-permitted DID; got body: {body}"
    );

    // Canonical wire shape: a TT `#response` document whose `payload` is
    // `{ challenge, sessionId, expiresAt }` per spec/auth/challenge/0.1#response.
    let payload = &body["payload"];
    let session_id = payload["sessionId"].as_str().expect("sessionId in response");
    let challenge = payload["challenge"].as_str().expect("challenge in response");
    assert!(
        payload["expiresAt"].as_str().is_some(),
        "canonical shape includes expiresAt: {body}"
    );
    assert!(!session_id.is_empty(), "session_id must be non-empty");
    assert!(!challenge.is_empty(), "challenge must be non-empty");

    // The session row must be persisted so the matching authenticate
    // document can later look it up. Read it back directly via the test
    // context; this is exactly what the auth handler does internally.
    let session_row = vti_common::auth::session::get_session(&ctx.sessions_ks, session_id)
        .await
        .expect("session lookup");
    let session = session_row.expect("session row was persisted");
    assert_eq!(
        session.did, did,
        "persisted session must record the DID that requested the challenge"
    );
    assert_eq!(
        session.challenge, challenge,
        "persisted challenge must match the one returned to the client (so authenticate can verify the signature against the same nonce the client signed)"
    );
}

/// A deterministic `did:key` + its multibase private key, as the SDK's
/// client-side helpers expect them.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    // Multicodec Ed25519 private-key prefix (0x1300 → varint 0x80 0x26).
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// The canonical HTTPS login, end to end: `auth/challenge/0.1` → a Trust Task
/// signed by the SDK's own builder → tokens, both over `POST /trust-tasks`.
/// No mediator, no ATM.
///
/// This is the pin for the regression that broke every REST client: the SDK's
/// `auth_light` tier packed an **anoncrypt** DIDComm envelope, and once the
/// authenticate route began requiring an authenticated sender (VTI #771) the
/// server answered "authenticate message must be an authenticated (authcrypt)
/// DIDComm envelope" to every one of them. Driving the server with the
/// *client's* own document — rather than a hand-rolled fixture — is what makes
/// this test able to catch that class: a builder that drifts out of what the
/// route accepts fails here.
#[tokio::test]
async fn di_signed_trust_task_authenticates_over_rest() {
    let (router, ctx) = build_test_app().await;

    let (did, private_key_multibase) = did_key_from_seed(0x5a);
    let entry = vti_common::acl::AclEntry::new(&did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

    let (status, challenge_body) =
        request(&router, post_json("/trust-tasks", challenge_doc(&did))).await;
    assert_eq!(status, StatusCode::OK, "challenge: {challenge_body}");
    let challenge = challenge_body["payload"]["challenge"].as_str().unwrap();
    let session_id = challenge_body["payload"]["sessionId"].as_str().unwrap();

    // The exact bytes `vta_sdk::auth_di::sign_authenticate_doc` puts on the
    // wire (an `auth/authenticate/0.2` Trust Task).
    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        &ctx.vta_did,
        challenge,
        session_id,
    )
    .await
    .expect("sign authenticate document");

    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(doc))
        .unwrap();
    let (status, body) = request(&router, req).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a DI-signed Trust Task must authenticate over plain HTTPS; got: {body}"
    );
    // The response is a Trust-Task `#response` document wrapping the tokens —
    // the shape the SDK unwraps in `auth_di::parse_auth_response`.
    let payload = &body["payload"];
    assert!(
        payload["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "response must carry an access token: {body}"
    );
    assert_eq!(
        payload["session"]["subject"], did,
        "the session must be bound to the proven signer: {body}"
    );
}

/// The proof is not decoration: the same document with a challenge the holder
/// never signed is rejected. Guards against a future "parse the payload, skip
/// the proof" shortcut on the HTTPS path.
#[tokio::test]
async fn di_signed_trust_task_with_tampered_challenge_is_rejected() {
    let (router, ctx) = build_test_app().await;

    let (did, private_key_multibase) = did_key_from_seed(0x5b);
    let entry = vti_common::acl::AclEntry::new(&did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

    let (_, challenge_body) =
        request(&router, post_json("/trust-tasks", challenge_doc(&did))).await;
    let session_id = challenge_body["payload"]["sessionId"].as_str().unwrap();

    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        &ctx.vta_did,
        "the-real-challenge",
        session_id,
    )
    .await
    .expect("sign");
    // Swap the challenge *after* signing — the proof no longer covers it.
    let mut tampered: Value = serde_json::from_str(&doc).unwrap();
    tampered["payload"]["challenge"] =
        json!(challenge_body["payload"]["challenge"].as_str().unwrap());

    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(tampered.to_string()))
        .unwrap();
    let (status, body) = request(&router, req).await;

    // `ProofInvalid` maps to 422, not 401 (`trust-tasks-https::status_for_code`).
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a post-signature edit must not authenticate; got: {body}"
    );
}

/// Regression pin for the forged-sender auth bypass: a remote unauthenticated
/// attacker must not be able to obtain an admin JWT by POSTing a
/// **plaintext** DIDComm message with a forged `from` field.
///
/// This used to drive the exploit straight at the retired `/auth/` REST
/// handler, which called `atm.unpack` inline and — pre-fix — trusted
/// `msg.from` as the proven signer. That handler, and the entry point that let
/// a test post a raw DIDComm envelope and get a synchronous answer, are both
/// gone: `POST /trust-tasks` only ever reads a plain JSON Trust-Task envelope
/// (`ceremony::peek_type_uri`) and never calls `atm.unpack`; a DIDComm-carried
/// Trust Task (the auth family included) now arrives only through the
/// mediator-relay inbound pipeline, which has no offline/in-process entry
/// point here (see the module doc above).
///
/// So this pins that the old path is gone rather than re-proving the guard: a
/// plaintext DIDComm envelope posted to the literal retired `/auth/` path hits
/// nothing but the did:webvh wildcard GET route (`setup` → `webvh`, on by
/// default) and 405s. The forged-sender property itself still holds — see the
/// module doc for where it is pinned now.
#[tokio::test]
async fn plaintext_didcomm_with_forged_sender_is_rejected() {
    let (router, _ctx) = build_test_app().await;

    let admin_did = "did:key:z6MkForgedAdminTarget";
    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
        "from": admin_did,
        "to": ["did:key:z6MkVtaServiceUnderTest"],
        "body": { "challenge": "whatever", "session_id": "whatever" },
    });

    let (status, body) = request(&router, post_raw("/auth/", forged.to_string())).await;

    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the retired /auth/ REST route must stay gone: {body}"
    );
}

/// `POST /auth/refresh` with a malformed refresh token returns 401, not
/// 500. Pre-fix-bundle, a parse-failure on the refresh token bubbled
/// up as an internal error; this used to pin the user-facing 401 so a
/// future refactor doesn't regress error mapping.
///
/// That REST route is gone; `auth/refresh/0.2` is now dispatched on
/// `POST /trust-tasks`, which folds every authentication/authorization
/// refusal into `permissionDenied` (HTTP 403 — see `trust-tasks-https::
/// status_for_code`), so this pins 403 rather than 401 now, but the same
/// underlying property: a parse failure surfaces as a clean client refusal,
/// never a 500.
#[tokio::test]
async fn refresh_endpoint_rejects_malformed_token_with_401() {
    let (router, _ctx) = build_test_app().await;

    let (status, _body) = request(
        &router,
        post_json("/trust-tasks", refresh_doc("not-a-real-refresh-token")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "malformed refresh token must surface as 403, not 500"
    );
}

/// `auth/refresh/0.2` with an unknown but well-shaped token also returns 403.
/// Confirms the lookup-miss path doesn't leak distinct error info.
#[tokio::test]
async fn refresh_endpoint_rejects_unknown_token_with_401() {
    let (router, _ctx) = build_test_app().await;

    // 32 bytes of base64url is the right shape for a refresh token but
    // refers to no stored session.
    let (status, _body) = request(
        &router,
        post_json(
            "/trust-tasks",
            refresh_doc("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unknown refresh token must surface as 403"
    );
}

/// Regression pin for the forged-sender auth bypass on the refresh path: a
/// plaintext DIDComm `auth/refresh` envelope must be rejected, not trusted.
///
/// As with `plaintext_didcomm_with_forged_sender_is_rejected` (see the module
/// doc), the entry point this drove — `/auth/refresh` accepting a raw DIDComm
/// envelope and answering synchronously — is gone, with no offline
/// replacement here. Pin that the retired path stays gone.
#[tokio::test]
async fn plaintext_didcomm_refresh_is_rejected() {
    let (router, _ctx) = build_test_app().await;

    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": "https://trusttasks.org/spec/auth/refresh/0.1",
        "from": "did:key:z6MkForgedAdminTarget",
        "to": ["did:key:z6MkVtaServiceUnderTest"],
        "body": { "refresh_token": "stolen-or-guessed-token" },
    });

    let (status, body) = request(&router, post_raw("/auth/refresh", forged.to_string())).await;

    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the retired /auth/refresh REST route must stay gone: {body}"
    );
}

/// Smoke check: `TestAppContext` exposes the keyspaces these tests need
/// so future auth-flow regressions can be added with similarly small
/// boilerplate.
#[tokio::test]
async fn test_app_context_exposes_required_keyspaces() {
    let (_router, ctx) = build_test_app().await;
    let _: &TestAppContext = &ctx;
    // The fields below are what auth tests need; if any of these
    // disappears from `TestAppContext`, this assertion forces an
    // explicit fix-up of the helper rather than a silent test failure
    // in a downstream file.
    let _sessions = ctx.sessions_ks.clone();
    let _acl = ctx.acl_ks.clone();
    let _jwt = ctx.jwt_keys.clone();
}

fn post_doc(doc: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(doc))
        .unwrap()
}

/// #1638, the relay: a signed authenticate document addressed to another
/// service is refused here (`wrongRecipient`) though its proof and challenge
/// are good, and the refusal leaves the session for the holder to use.
#[tokio::test]
async fn a_document_addressed_to_another_service_is_refused() {
    let (router, ctx) = build_test_app().await;
    let (did, key) = did_key_from_seed(0x5c);
    let entry = vti_common::acl::AclEntry::new(&did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .unwrap();
    let (_, ch) = request(&router, post_json("/trust-tasks", challenge_doc(&did))).await;
    let (challenge, session_id) = (
        ch["payload"]["challenge"].as_str().unwrap(),
        ch["payload"]["sessionId"].as_str().unwrap(),
    );

    let relayed = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &key,
        "did:key:z6MkSomeOtherService",
        challenge,
        session_id,
    )
    .await
    .unwrap();
    let (status, body) = request(&router, post_doc(relayed)).await;
    // The audience check surfaces as `AppError::Authentication`, which
    // `app_error_to_reject` folds into `permissionDenied` (HTTP 403 — see
    // `trust-tasks-https::status_for_code`), with `wrongRecipient` named in
    // the message rather than carried as its own standard code.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("wrongRecipient"), "{body}");
    assert!(body["payload"].get("tokens").is_none(), "{body}");

    let addressed =
        vta_sdk::auth_di::sign_authenticate_doc(&did, &key, &ctx.vta_did, challenge, session_id)
            .await
            .unwrap();
    let (status, body) = request(&router, post_doc(addressed)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the session survives the refusal: {body}"
    );
}

/// #1638: a signed authenticate document naming no `recipient` is valid at
/// every service, so it is refused as `malformedRequest` (SPEC §7.2 item 5).
#[tokio::test]
async fn a_document_with_no_recipient_is_malformed() {
    let (router, ctx) = build_test_app().await;
    let (did, key) = did_key_from_seed(0x5d);
    let entry = vti_common::acl::AclEntry::new(&did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .unwrap();
    let (_, ch) = request(&router, post_json("/trust-tasks", challenge_doc(&did))).await;

    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        "https://trusttasks.org/spec/auth/authenticate/0.2",
        json!({ "challenge": ch["payload"]["challenge"], "sessionId": ch["payload"]["sessionId"], "scope": [] }),
        &did,
        "unused",
    )
    .unwrap();
    doc.recipient = None;
    vta_sdk::trust_task_sign::sign_in_place(&mut doc, &did, &key)
        .await
        .unwrap();

    let (status, body) = request(&router, post_doc(serde_json::to_string(&doc).unwrap())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("malformedRequest"), "{body}");
}
