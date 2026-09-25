//! `POST /auth/` over a DIDComm authcrypt envelope binds the sender to the key
//! the key agreement actually used.
//!
//! An authcrypt JWE names its sender key twice: `skid` (the key a recipient
//! resolves for the key agreement) and `apu` (the PartyUInfo the derivation is
//! bound to, which the unpack metadata reports as `encrypted_from_kid`). A
//! conforming packer writes one key id into both. These tests hand the route
//! envelopes that split them — built by `vti_common`'s test-support builders —
//! and require that no token is minted for anybody but the holder of the key
//! used, while a genuine envelope still logs in.
//!
//! The ATM is offline (no mediator): it holds the VTA's key-agreement secret so
//! it can decrypt, and resolves the `did:key` senders locally.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, TestAppOptions, build_test_app_with};
use vti_common::auth::authcrypt_test_support::{
    DidKeyParty, Skid, anoncrypt_wrap, authcrypt_with_header, authenticate_plaintext,
    forge_authcrypt, genuine_authcrypt, offline_atm_with, refresh_plaintext,
};

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
    (status, json)
}

fn post(uri: &str, content_type: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type)
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from(body))
        .unwrap()
}

struct Fixture {
    router: axum::Router,
    ctx: TestAppContext,
    vta: DidKeyParty,
    victim: DidKeyParty,
    attacker: DidKeyParty,
}

/// A VTA whose offline ATM can decrypt envelopes addressed to `vta.kid`, with
/// `victim` enrolled as an admin. `attacker` is enrolled nowhere.
async fn fixture() -> Fixture {
    let vta = DidKeyParty::from_seed([0x51; 32]);
    let victim = DidKeyParty::from_seed([0x52; 32]);
    let attacker = DidKeyParty::from_seed([0x53; 32]);
    let atm = offline_atm_with(std::slice::from_ref(&vta.key_agreement)).await;
    let (router, ctx) = build_test_app_with(TestAppOptions {
        atm: Some(atm),
        ..Default::default()
    })
    .await;
    let entry = vti_common::acl::AclEntry::new(&victim.did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
    Fixture {
        router,
        ctx,
        vta,
        victim,
        attacker,
    }
}

/// Obtain a challenge for `did` (public; anyone may ask for an enrolled DID).
async fn challenge(f: &Fixture, did: &str) -> (String, String) {
    let (status, body) = request(
        &f.router,
        post(
            "/auth/challenge",
            "application/json",
            json!({ "did": did }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge issuance: {body}");
    (
        body["sessionId"].as_str().expect("sessionId").to_string(),
        body["challenge"].as_str().expect("challenge").to_string(),
    )
}

/// The refusal a case must produce — named, so a refusal from some other layer
/// cannot stand in for the one under test.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    /// `AuthcryptError::ApuMismatch`
    ApuMismatch,
    /// `AuthcryptError::InvalidSenderKeyId`
    InvalidSenderKeyId,
    /// `AuthcryptError::Mismatch`
    FromMismatch,
    /// `AuthcryptError::NotAuthcrypt`
    NotAuthcrypt,
    /// The messaging library refused the envelope during unpack, before the
    /// guard ran (the envelope does not decrypt or fails its own checks).
    Unpack,
}

impl Refusal {
    fn marker(self) -> &'static str {
        match self {
            Refusal::ApuMismatch => "does not encode skid",
            Refusal::InvalidSenderKeyId => "has no usable sender key id",
            Refusal::FromMismatch => "sender mismatch: plaintext from",
            Refusal::NotAuthcrypt => "must be an authenticated (authcrypt) DIDComm envelope",
            Refusal::Unpack => "failed to unpack message",
        }
    }
}

fn assert_refusal(what: &str, status: StatusCode, body: &Value, expected: Refusal) {
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{what} must be refused; got body: {body}"
    );
    assert!(
        !body.to_string().contains("accessToken"),
        "{what}: no token may be issued: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains(expected.marker()),
        "{what}: expected the {expected:?} refusal, got: {body}"
    );
}

async fn assert_refused(f: &Fixture, session_id: &str, jwe: String, what: &str, expected: Refusal) {
    let (status, body) = request(&f.router, post("/auth/", "text/plain", jwe)).await;
    assert_refusal(what, status, &body, expected);
    let session = vti_common::auth::session::get_session(&f.ctx.sessions_ks, session_id)
        .await
        .expect("session lookup")
        .expect("challenge session still present");
    assert_eq!(
        session.state,
        vti_common::auth::session::SessionState::ChallengeSent,
        "{what} must not authenticate the session"
    );
}

/// The forged-sender envelope: the attacker authcrypts with their own key
/// (`skid = attacker#k`) but sets `apu = victim#k` and `from = victim`,
/// answering a challenge issued for the victim. Refused, and the session stays
/// unauthenticated.
#[tokio::test]
async fn forged_apu_sender_is_refused() {
    let f = fixture().await;
    let (session_id, challenge) = challenge(&f, &f.victim.did).await;
    let plaintext = authenticate_plaintext(&f.victim.did, &f.vta.did, &challenge, &session_id);
    let vta_pub = f.vta.public();
    let forged = forge_authcrypt(
        &plaintext,
        &f.attacker,
        &f.victim.kid,
        (&f.vta.kid, &vta_pub),
    );
    assert_refused(
        &f,
        &session_id,
        forged,
        "a skid/apu-split envelope",
        Refusal::ApuMismatch,
    )
    .await;
}

/// Every other inconsistent sender-key header is refused too: `skid` absent,
/// `apu` absent, `apu` naming a different key of the right DID, and a bare-DID
/// `skid` (which names no specific key).
#[tokio::test]
async fn inconsistent_sender_key_headers_are_refused() {
    let f = fixture().await;
    let vta_pub = f.vta.public();
    let attacker_private = f.attacker.private();
    let victim_private = f.victim.private();

    // Missing `skid` or `apu` never decrypts or never passes the library's own
    // addressing check, so the library refuses those first.
    let cases: Vec<(&str, Skid<'_>, Option<Vec<u8>>, bool, Refusal)> = vec![
        (
            "missing skid",
            Skid::Absent,
            Some(f.victim.kid.clone().into_bytes()),
            false,
            Refusal::Unpack,
        ),
        (
            "missing apu",
            Skid::Str(&f.attacker.kid),
            None,
            false,
            Refusal::Unpack,
        ),
        (
            "victim-key skid, missing apu",
            Skid::Str(&f.victim.kid),
            None,
            true,
            Refusal::Unpack,
        ),
        (
            "bare-DID skid",
            Skid::Str(&f.victim.did),
            Some(f.victim.did.clone().into_bytes()),
            true,
            Refusal::InvalidSenderKeyId,
        ),
        (
            "apu naming another key of the sender DID",
            Skid::Str(&f.attacker.kid),
            Some(format!("{}#other", f.victim.did).into_bytes()),
            false,
            Refusal::ApuMismatch,
        ),
    ];
    for (what, skid, apu, as_victim, expected) in cases {
        let (session_id, challenge) = challenge(&f, &f.victim.did).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vta.did, &challenge, &session_id);
        let sender = if as_victim {
            &victim_private
        } else {
            &attacker_private
        };
        let jwe = authcrypt_with_header(
            &plaintext,
            skid,
            apu.as_deref(),
            sender,
            (&f.vta.kid, &vta_pub),
        );
        assert_refused(&f, &session_id, jwe, what, expected).await;
    }
}

/// An attacker authcrypting consistently with their own key, but claiming the
/// victim in `from`, is refused (the `from` binding).
#[tokio::test]
async fn consistent_attacker_key_with_victim_from_is_refused() {
    let f = fixture().await;
    let (session_id, challenge) = challenge(&f, &f.victim.did).await;
    let plaintext = authenticate_plaintext(&f.victim.did, &f.vta.did, &challenge, &session_id);
    let vta_pub = f.vta.public();
    let jwe = genuine_authcrypt(&plaintext, &f.attacker, (&f.vta.kid, &vta_pub));
    assert_refused(
        &f,
        &session_id,
        jwe,
        "attacker key with victim from",
        Refusal::FromMismatch,
    )
    .await;
}

/// The genuine flow: the victim's own key, consistent header → tokens.
#[tokio::test]
async fn genuine_authcrypt_login_succeeds() {
    let f = fixture().await;
    let (session_id, challenge) = challenge(&f, &f.victim.did).await;
    let plaintext = authenticate_plaintext(&f.victim.did, &f.vta.did, &challenge, &session_id);
    let vta_pub = f.vta.public();
    let jwe = genuine_authcrypt(&plaintext, &f.victim, (&f.vta.kid, &vta_pub));
    let (status, body) = request(&f.router, post("/auth/", "text/plain", jwe)).await;
    assert_eq!(status, StatusCode::OK, "genuine login: {body}");
    assert!(
        body.to_string().contains("accessToken") || body.to_string().contains("access_token"),
        "genuine login must mint tokens: {body}"
    );
}

/// Authcrypt hidden inside anoncrypt — here the forged envelope, which the
/// library itself accepts in that wrapping — is refused on the direct-unpack
/// route: the outer layer must be the sender binding.
#[tokio::test]
async fn anoncrypt_wrapped_authcrypt_is_refused() {
    let f = fixture().await;
    let vta_pub = f.vta.public();
    for (what, inner_sender) in [("forged", &f.attacker), ("genuine", &f.victim)] {
        let (session_id, challenge) = challenge(&f, &f.victim.did).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vta.did, &challenge, &session_id);
        let inner = if what == "forged" {
            forge_authcrypt(
                &plaintext,
                inner_sender,
                &f.victim.kid,
                (&f.vta.kid, &vta_pub),
            )
        } else {
            genuine_authcrypt(&plaintext, inner_sender, (&f.vta.kid, &vta_pub))
        };
        let wrapped = anoncrypt_wrap(&inner, (&f.vta.kid, &vta_pub));
        assert_refused(
            &f,
            &session_id,
            wrapped,
            &format!("anoncrypt({what} authcrypt)"),
            Refusal::NotAuthcrypt,
        )
        .await;
    }
}

/// `/auth/refresh` binds its sender with the same guard: the forged envelope
/// is refused before the refresh token is even read.
#[tokio::test]
async fn refresh_with_forged_apu_sender_is_refused() {
    let f = fixture().await;
    let vta_pub = f.vta.public();
    let plaintext = refresh_plaintext(&f.victim.did, &f.vta.did, "any-refresh-token");
    let forged = forge_authcrypt(
        &plaintext,
        &f.attacker,
        &f.victim.kid,
        (&f.vta.kid, &vta_pub),
    );
    let (status, body) = request(&f.router, post("/auth/refresh", "text/plain", forged)).await;
    assert_refusal("forged refresh", status, &body, Refusal::ApuMismatch);
}

/// Vault unseal (`vault/upsert` with a `didcomm-authcrypt` sealed secret)
/// refuses a secret sealed with the attacker's key while naming the caller in
/// `apu` and `from`.
#[tokio::test]
async fn vault_unseal_refuses_forged_apu_sender() {
    use vta_service::operations::vault::upsert::{UnsealError, unseal_secret};

    let vta = DidKeyParty::from_seed([0x54; 32]);
    let caller = DidKeyParty::from_seed([0x55; 32]);
    let attacker = DidKeyParty::from_seed([0x56; 32]);
    let atm = offline_atm_with(std::slice::from_ref(&vta.key_agreement)).await;
    let vta_pub = vta.public();
    let plaintext = vti_common::auth::authcrypt_test_support::plaintext_message(
        "https://trusttasks.org/spec/vault/_shared/0.1/vault-secret",
        &caller.did,
        &vta.did,
        json!({ "secret": "s3cr3t" }),
    );
    let forged = forge_authcrypt(&plaintext, &attacker, &caller.kid, (&vta.kid, &vta_pub));
    match unseal_secret(&atm, &caller.did, &forged).await {
        Err(UnsealError::UnpackFailed(msg)) => assert!(
            msg.contains(Refusal::ApuMismatch.marker()),
            "expected the ApuMismatch refusal, got: {msg}"
        ),
        Ok(_) => panic!("a forged sealed secret must not open"),
        Err(_) => panic!("a forged sealed secret must be refused by the sender guard"),
    }

    // The caller's own sealed secret still opens.
    let genuine = genuine_authcrypt(&plaintext, &caller, (&vta.kid, &vta_pub));
    match unseal_secret(&atm, &caller.did, &genuine).await {
        Err(UnsealError::UnpackFailed(msg)) => {
            panic!("the genuine sealed secret must pass the sender binding: {msg}")
        }
        Err(UnsealError::SenderMismatch { .. }) => {
            panic!("the genuine sealed secret must bind to its caller")
        }
        // Opened, or reached body deserialisation: past the binding either way.
        _ => {}
    }
}
