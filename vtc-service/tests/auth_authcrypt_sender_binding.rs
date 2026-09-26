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
    DidKeyParty, Skid, authcrypt_with_header, authenticate_plaintext, forge_authcrypt,
    genuine_authcrypt, offline_atm_with,
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

async fn post_auth(f: &Fixture, prefix: &str, jwe: String) -> (StatusCode, Value) {
    let resp = f
        .client
        .post(format!("{}{prefix}/", f.mock.base_url()))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "text/plain")
        .body(jwe)
        .send()
        .await
        .expect("POST auth");
    let status = resp.status();
    (status, resp.json().await.unwrap_or_else(|_| json!({})))
}

async fn assert_refused(f: &Fixture, prefix: &str, jwe: String, what: &str) {
    let (status, body) = post_auth(f, prefix, jwe).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{prefix}: {what} must be refused; got body: {body}"
    );
    assert!(
        !body.to_string().contains("accessToken") && body.get("access_token").is_none(),
        "{prefix}: {what}: no token may be issued: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        !err.contains("ATM not configured"),
        "{prefix}: {what}: {body}"
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
        assert_refused(&f, prefix, forged, "a skid/apu-split envelope").await;
    }
    f.mock.shutdown().await;
}

/// Missing `skid`, missing `apu`, a bare-DID `skid`, and a consistent attacker
/// key claiming the victim's `from` are all refused.
#[tokio::test]
async fn inconsistent_sender_key_headers_are_refused() {
    let f = fixture().await;
    let vtc_pub = f.vtc.public();
    let attacker_private = f.attacker.private();
    let victim_private = f.victim.private();
    for prefix in PREFIXES {
        let (session_id, challenge) = challenge(&f, prefix).await;
        let plaintext = authenticate_plaintext(&f.victim.did, &f.vtc.did, &challenge, &session_id);
        let recipient = (f.vtc.kid.as_str(), &vtc_pub);
        let cases = [
            (
                "missing skid",
                authcrypt_with_header(
                    &plaintext,
                    Skid::Absent,
                    Some(f.victim.kid.as_bytes()),
                    &attacker_private,
                    recipient,
                ),
            ),
            (
                "missing apu",
                authcrypt_with_header(
                    &plaintext,
                    Skid::Str(&f.victim.kid),
                    None,
                    &victim_private,
                    recipient,
                ),
            ),
            (
                "bare-DID skid",
                authcrypt_with_header(
                    &plaintext,
                    Skid::Str(&f.victim.did),
                    Some(f.victim.did.as_bytes()),
                    &victim_private,
                    recipient,
                ),
            ),
            (
                "attacker key with victim from",
                genuine_authcrypt(&plaintext, &f.attacker, recipient),
            ),
        ];
        for (what, jwe) in cases {
            assert_refused(&f, prefix, jwe, what).await;
        }
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
