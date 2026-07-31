//! The VTC's canonical REST login: a DI-signed `auth/authenticate/0.1` Trust
//! Task, driven by the *client's own* builder (`vta_sdk::auth_di`).
//!
//! **Why this exists.** The VTC accepted two login shapes — a VTA-wallet SIOP
//! envelope, and an authcrypt DIDComm envelope. A REST client holding a plain
//! `did:key` (no wallet to self-issue an `id_token`, no mediator to authcrypt
//! through) could satisfy neither, so `vtc-client::connect` could not log in at
//! all. `/auth/refresh` had already grown the Trust-Task path; login had not,
//! which left a client able to *rotate* a token it had no way to obtain.
//!
//! Every test here posts bytes produced by the real SDK builder rather than a
//! hand-written fixture, so a client/server drift — the defect class that made
//! this necessary — fails the build instead of an operator's setup run.

use reqwest::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;

const CHALLENGE_TASK: &str = "https://trusttasks.org/spec/auth/challenge/0.1";
const AUTHENTICATE_TASK: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";
const REFRESH_TASK: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

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

/// A deterministic `did:key` + its multibase private key, in the shape the
/// SDK's client helpers take.
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

/// Fetch a challenge for `did` from a running VTC.
async fn get_challenge(client: &reqwest::Client, base: &str, did: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/v1/auth/challenge"))
        .header("Trust-Task", CHALLENGE_TASK)
        .json(&json!({ "did": did }))
        .send()
        .await
        .expect("POST /v1/auth/challenge");
    assert_eq!(resp.status(), StatusCode::OK, "challenge issuance");
    let body: Value = resp.json().await.expect("challenge json");
    (
        body["challenge"].as_str().expect("challenge").to_string(),
        body["sessionId"].as_str().expect("sessionId").to_string(),
    )
}

/// The whole login: challenge → SDK-signed Trust Task → tokens. No mediator,
/// no ATM, no wallet — the holder key is the only credential involved.
#[tokio::test]
async fn di_signed_trust_task_authenticates_over_rest() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, private_key_multibase) = did_key_from_seed(0x7a);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let (challenge, session_id) = get_challenge(&client, &base, &did).await;

    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        "did:key:z6MkVtcUnderTest",
        &challenge,
        &session_id,
    )
    .await
    .expect("sign authenticate document");

    let resp = client
        .post(format!("{base}/v1/auth/"))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "application/json")
        .body(doc)
        .send()
        .await
        .expect("POST /v1/auth/");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status,
        StatusCode::OK,
        "a DI-signed Trust Task must authenticate against the VTC; got: {body}"
    );
    assert!(
        body["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "response must carry an access token: {body}"
    );
    assert_eq!(
        body["session"]["subject"], did,
        "the session must be bound to the proven signer: {body}"
    );

    mock.shutdown().await;
}

/// The token the DI login mints is usable, and the refresh token it carries
/// rotates through the Trust-Task refresh path — the two halves of the flow
/// that were previously unreachable together (refresh existed; login did not).
#[tokio::test]
async fn di_login_then_trust_task_refresh_round_trips() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, private_key_multibase) = did_key_from_seed(0x7b);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let (challenge, session_id) = get_challenge(&client, &base, &did).await;
    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        "did:key:z6MkVtcUnderTest",
        &challenge,
        &session_id,
    )
    .await
    .expect("sign");
    let body: Value = client
        .post(format!("{base}/v1/auth/"))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "application/json")
        .body(doc)
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("login json");

    let refresh_token = body["tokens"]["refreshToken"]
        .as_str()
        .expect("login must issue a refresh token")
        .to_string();

    let refresh_doc =
        vta_sdk::auth_di::build_refresh_doc(&did, "did:key:z6MkVtcUnderTest", &refresh_token)
            .expect("build refresh document");
    let resp = client
        .post(format!("{base}/v1/auth/refresh"))
        .header("Trust-Task", REFRESH_TASK)
        .header("content-type", "application/json")
        .body(refresh_doc)
        .send()
        .await
        .expect("POST /v1/auth/refresh");

    let status = resp.status();
    let refreshed: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status,
        StatusCode::OK,
        "the refresh token from a DI login must rotate: {refreshed}"
    );
    assert!(
        refreshed["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "rotation must return a fresh access token: {refreshed}"
    );

    mock.shutdown().await;
}

/// The proof is load-bearing: editing the challenge after signing must not
/// authenticate. Guards against a future "parse the payload, skip the proof"
/// shortcut on the VTC's REST path.
#[tokio::test]
async fn tampered_challenge_is_rejected() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, private_key_multibase) = did_key_from_seed(0x7c);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let (challenge, session_id) = get_challenge(&client, &base, &did).await;
    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        "did:key:z6MkVtcUnderTest",
        // Sign over a *different* challenge, then swap the real one in.
        "0000000000000000000000000000000000000000",
        &session_id,
    )
    .await
    .expect("sign");
    let mut tampered: Value = serde_json::from_str(&doc).expect("signed doc is JSON");
    tampered["payload"]["challenge"] = json!(challenge);

    let resp = client
        .post(format!("{base}/v1/auth/"))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "application/json")
        .body(tampered.to_string())
        .send()
        .await
        .expect("POST /v1/auth/");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a post-signature edit must not authenticate: {body}"
    );
    assert!(
        body.get("tokens").is_none(),
        "no token may be issued for a tampered document: {body}"
    );

    mock.shutdown().await;
}

/// An **unsigned** authenticate document must not be claimed by the DI path.
///
/// This is the discrimination rule that keeps the new path from shadowing the
/// SIOP envelope, which shares the Type URI: a body is only claimed when it
/// carries a `proof`. Without the rule, a SIOP login that happened to parse as
/// a Trust Task would be claimed here and rejected for a missing proof instead
/// of being verified as a SIOP token. An unsigned document therefore falls
/// through — and, finding no other path that accepts it, is refused.
#[tokio::test]
async fn unsigned_authenticate_document_is_not_claimed_by_the_di_path() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, _) = did_key_from_seed(0x7d);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let (challenge, session_id) = get_challenge(&client, &base, &did).await;
    let unsigned = json!({
        "id": "urn:uuid:unsigned-1",
        "type": AUTHENTICATE_TASK,
        "issuer": did,
        "payload": { "challenge": challenge, "sessionId": session_id },
    });

    let resp = client
        .post(format!("{base}/v1/auth/"))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "application/json")
        .body(unsigned.to_string())
        .send()
        .await
        .expect("POST /v1/auth/");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unsigned document must not mint tokens: {body}"
    );
    // Specifically NOT a DI-proof error — the DI path declined to claim it.
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        !err.contains("proof verification failed"),
        "the unsigned body must fall through, not be claimed and proof-rejected: {body}"
    );

    mock.shutdown().await;
}
