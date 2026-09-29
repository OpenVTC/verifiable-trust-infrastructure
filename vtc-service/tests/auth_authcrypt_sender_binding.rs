//! VTC `POST /v1/auth/` and `POST /v1/wallet/auth/` over a DIDComm authcrypt
//! envelope bind the sender to the key the key agreement actually used.
//!
//! The VTA twin of this file (`vta-service/tests/auth_authcrypt_sender_binding.rs`)
//! explains the envelope shapes. The ATM is offline: it holds the VTC's
//! key-agreement secret so it can decrypt, and resolves `did:key` senders
//! locally.

use reqwest::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;
use vti_common::auth::authcrypt_test_support::{
    DidKeyParty, Skid, anoncrypt_wrap, authcrypt_with_header, authenticate_plaintext,
    forge_authcrypt, genuine_authcrypt, offline_atm_with, refresh_plaintext,
};

const CHALLENGE_TASK: &str = "https://trusttasks.org/spec/auth/challenge/0.1";
const AUTHENTICATE_TASK: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

fn admin_entry(did: &str) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        role: VtcRole::Admin,
        label: None,
        allowed_contexts: vec![],
        created_at: 1,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

struct Fixture {
    mock: MockVtc,
    client: reqwest::Client,
    vtc: DidKeyParty,
    victim: DidKeyParty,
    attacker: DidKeyParty,
}

async fn fixture() -> Fixture {
    let vtc = DidKeyParty::from_seed([0x61; 32]);
    let victim = DidKeyParty::from_seed([0x62; 32]);
    let attacker = DidKeyParty::from_seed([0x63; 32]);
    let mock =
        MockVtc::start_with_atm(offline_atm_with(std::slice::from_ref(&vtc.key_agreement)).await)
            .await;
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&victim.did))
        .await
        .expect("seed admin acl row");
    Fixture {
        mock,
        client: reqwest::Client::new(),
        vtc,
        victim,
        attacker,
    }
}

async fn challenge(f: &Fixture, prefix: &str) -> (String, String) {
    let resp = f
        .client
        .post(format!("{}{prefix}/challenge", f.mock.base_url()))
        .header("Trust-Task", CHALLENGE_TASK)
        .json(&json!({ "did": f.victim.did }))
        .send()
        .await
        .expect("POST challenge");
    assert_eq!(resp.status(), StatusCode::OK, "{prefix}/challenge");
    let body: Value = resp.json().await.expect("challenge json");
    (
        body["sessionId"].as_str().expect("sessionId").to_string(),
        body["challenge"].as_str().expect("challenge").to_string(),
    )
}

async fn post_to(f: &Fixture, path: &str, task: &str, jwe: String) -> (StatusCode, Value) {
    let resp = f
        .client
        .post(format!("{}{path}", f.mock.base_url()))
        .header("Trust-Task", task)
        .header("content-type", "text/plain")
        .body(jwe)
        .send()
        .await
        .expect("POST");
    let status = resp.status();
    (status, resp.json().await.unwrap_or_else(|_| json!({})))
}

async fn post_auth(f: &Fixture, prefix: &str, jwe: String) -> (StatusCode, Value) {
    post_to(f, &format!("{prefix}/"), AUTHENTICATE_TASK, jwe).await
}

/// The refusal a case must produce — named, so a refusal from some other layer
/// cannot stand in for the one under test.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    /// The messaging library (didcomm 0.15.9+) bound the authcrypt sender to
    /// the key that encrypted the message and refused the envelope. It does so
    /// before the VTC's own guard runs, which stays as defence in depth.
    SenderBinding,
    /// The messaging library refused the envelope during unpack for another
    /// reason, before the guard ran.
    Unpack,
}

impl Refusal {
    fn marker(self) -> &'static str {
        match self {
            Refusal::SenderBinding => "authcrypt sender key binding failed",
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
        !body.to_string().contains("accessToken") && body.get("access_token").is_none(),
        "{what}: no token may be issued: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains(expected.marker()),
        "{what}: expected the {expected:?} refusal, got: {body}"
    );
}

async fn assert_refused(
    f: &Fixture,
    prefix: &str,
    session_id: &str,
    jwe: String,
    what: &str,
    expected: Refusal,
) {
    let (status, body) = post_auth(f, prefix, jwe).await;
    assert_refusal(&format!("{prefix}: {what}"), status, &body, expected);
    let session = vti_common::auth::session::get_session(&f.mock.vtc.state.sessions_ks, session_id)
        .await
        .expect("session lookup")
        .expect("challenge session still present");
    assert_eq!(
        session.state,
        vti_common::auth::session::SessionState::ChallengeSent,
        "{prefix}: {what} must not authenticate the session"
    );
}

const PREFIXES: [&str; 2] = ["/v1/auth", "/v1/wallet/auth"];

/// The forged-sender envelope (attacker key in `skid`, victim in `apu` and
/// `from`) is refused on both login routes.
#[tokio::test]
async fn forged_apu_sender_is_refused() {
    let f = fixture().await;
    let vtc_pub = f.vtc.public();
    for prefix in PREFIXES {
        let (session_id, challenge) = challenge(&f, prefix).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vtc.did, &challenge, &session_id);
        let forged = forge_authcrypt(
            &plaintext,
            &f.attacker,
            &f.victim.kid,
            (&f.vtc.kid, &vtc_pub),
        );
        assert_refused(
            &f,
            prefix,
            &session_id,
            forged,
            "a skid/apu-split envelope",
            Refusal::SenderBinding,
        )
        .await;
    }
    f.mock.shutdown().await;
}

/// Missing `skid`, missing `apu`, a bare-DID `skid`, and a consistent attacker
/// key claiming the victim's `from` are all refused.
#[tokio::test]
async fn inconsistent_sender_key_headers_are_refused() {
    for prefix in PREFIXES {
        // A fresh VTC per route: eight unauthenticated requests per route fit
        // the per-IP burst, sixteen on one instance do not.
        let f = fixture().await;
        let vtc_pub = f.vtc.public();
        let attacker_private = f.attacker.private();
        let victim_private = f.victim.private();
        let recipient = (f.vtc.kid.as_str(), &vtc_pub);
        for case in 0..4 {
            let (session_id, challenge) = challenge(&f, prefix).await;
            let plaintext =
                authenticate_plaintext(&f.victim.did, &f.vtc.did, &challenge, &session_id);
            let (what, jwe, expected) = match case {
                0 => (
                    "missing skid",
                    authcrypt_with_header(
                        &plaintext,
                        Skid::Absent,
                        Some(f.victim.kid.as_bytes()),
                        &attacker_private,
                        recipient,
                    ),
                    Refusal::Unpack,
                ),
                1 => (
                    "missing apu",
                    authcrypt_with_header(
                        &plaintext,
                        Skid::Str(&f.victim.kid),
                        None,
                        &victim_private,
                        recipient,
                    ),
                    Refusal::Unpack,
                ),
                2 => (
                    "bare-DID skid",
                    authcrypt_with_header(
                        &plaintext,
                        Skid::Str(&f.victim.did),
                        Some(f.victim.did.as_bytes()),
                        &victim_private,
                        recipient,
                    ),
                    Refusal::SenderBinding,
                ),
                _ => (
                    "attacker key with victim from",
                    genuine_authcrypt(&plaintext, &f.attacker, recipient),
                    // The messaging library's own addressing check refuses a
                    // consistent key whose DID is not `from`, first.
                    Refusal::Unpack,
                ),
            };
            assert_refused(&f, prefix, &session_id, jwe, what, expected).await;
        }
        f.mock.shutdown().await;
    }
}

/// Authcrypt hidden inside anoncrypt is refused on the direct-unpack routes.
#[tokio::test]
async fn anoncrypt_wrapped_authcrypt_is_refused() {
    let f = fixture().await;
    let vtc_pub = f.vtc.public();
    for prefix in PREFIXES {
        let (session_id, challenge) = challenge(&f, prefix).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vtc.did, &challenge, &session_id);
        let inner = forge_authcrypt(
            &plaintext,
            &f.attacker,
            &f.victim.kid,
            (&f.vtc.kid, &vtc_pub),
        );
        let wrapped = anoncrypt_wrap(&inner, (&f.vtc.kid, &vtc_pub));
        assert_refused(
            &f,
            prefix,
            &session_id,
            wrapped,
            "anoncrypt(authcrypt)",
            Refusal::SenderBinding,
        )
        .await;
    }
    f.mock.shutdown().await;
}

/// The refresh routes bind their sender with the same guard.
#[tokio::test]
async fn refresh_with_forged_apu_sender_is_refused() {
    const REFRESH_TASK: &str = "https://trusttasks.org/spec/auth/refresh/0.1";
    let f = fixture().await;
    let vtc_pub = f.vtc.public();
    for path in ["/v1/auth/refresh", "/v1/wallet/auth/refresh"] {
        let plaintext = refresh_plaintext(&f.victim.did, &f.vtc.did, "any-refresh-token");
        let forged = forge_authcrypt(
            &plaintext,
            &f.attacker,
            &f.victim.kid,
            (&f.vtc.kid, &vtc_pub),
        );
        let (status, body) = post_to(&f, path, REFRESH_TASK, forged).await;
        assert_refusal(path, status, &body, Refusal::SenderBinding);
    }
    f.mock.shutdown().await;
}

/// The genuine flow still logs in on both routes.
#[tokio::test]
async fn genuine_authcrypt_login_succeeds() {
    let f = fixture().await;
    let vtc_pub = f.vtc.public();
    for prefix in PREFIXES {
        let (session_id, challenge) = challenge(&f, prefix).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vtc.did, &challenge, &session_id);
        let jwe = genuine_authcrypt(&plaintext, &f.victim, (&f.vtc.kid, &vtc_pub));
        let (status, body) = post_auth(&f, prefix, jwe).await;
        assert_eq!(status, StatusCode::OK, "{prefix}: genuine login: {body}");
        assert!(
            body.to_string().contains("accessToken") || body.to_string().contains("access_token"),
            "{prefix}: genuine login must mint tokens: {body}"
        );
    }
    f.mock.shutdown().await;
}
