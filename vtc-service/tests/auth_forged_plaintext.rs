//! Regression pin for the forged-sender auth bypass, VTC side.
//!
//! The VTC's `POST /v1/auth/` handler shares the vulnerable pattern the VTA
//! had: it unpacks an incoming DIDComm envelope via `atm.unpack` and derives
//! the signer from `msg.from`. `atm.unpack` happily parses a **plaintext**
//! DIDComm message (a JSON with a `type` field but no JWE/JWS layer),
//! returning an attacker-controlled `from` with `authenticated: false`. If the
//! handler trusts that `from`, a remote unauthenticated caller can echo the
//! public challenge with `from: <admin DID>` and be minted an admin token.
//!
//! The fix rejects any envelope that isn't authenticated + encrypted
//! (legitimate clients authcrypt via `pack_encrypted`). This test wires a real
//! (offline) ATM so the request reaches `atm.unpack` and the new guard — not
//! the "ATM not configured" short-circuit — then drives the exact exploit and
//! asserts a 401 attributable to the guard.

use reqwest::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{MockVtc, build_offline_atm};

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

#[tokio::test]
async fn plaintext_didcomm_with_forged_sender_is_rejected() {
    let mock = MockVtc::start_with_atm(build_offline_atm().await).await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let admin_did = "did:key:z6MkVtcForgedAdminTarget";
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(admin_did))
        .await
        .expect("seed admin acl row");

    // Step 1 — obtain the public challenge + session_id for the target admin
    // DID (no secret involved; the endpoint is pre-auth, ACL-gated).
    let resp = client
        .post(format!("{base}/v1/auth/challenge"))
        .header("Trust-Task", CHALLENGE_TASK)
        .json(&json!({ "did": admin_did }))
        .send()
        .await
        .expect("POST /v1/auth/challenge");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "challenge issuance must succeed for the ACL-permitted admin DID"
    );
    let challenge_body: Value = resp.json().await.expect("challenge json");
    let session_id = challenge_body["sessionId"]
        .as_str()
        .expect("sessionId in challenge response");
    let challenge = challenge_body["challenge"]
        .as_str()
        .expect("challenge in challenge response");

    // Step 2 — craft a plaintext DIDComm message forging `from` = admin DID.
    // No encryption, no signature; `body` (not `payload`) means it is a
    // DIDComm envelope, not a SIOP/Trust-Task doc, so it reaches `atm.unpack`.
    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": AUTHENTICATE_TASK,
        "from": admin_did,
        "to": ["did:key:z6MkVtcServiceUnderTest"],
        "body": { "challenge": challenge, "session_id": session_id },
    });

    let resp = client
        .post(format!("{base}/v1/auth/"))
        .header("Trust-Task", AUTHENTICATE_TASK)
        .header("content-type", "text/plain")
        .body(forged.to_string())
        .send()
        .await
        .expect("POST /v1/auth/");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a plaintext DIDComm message with a forged sender must be rejected, not issued an admin JWT; got body: {body}"
    );
    // The 401 must come from the authcrypt guard, not the ATM-not-configured
    // short-circuit — otherwise the test would pass without exercising the fix.
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("authenticated (authcrypt) DIDComm envelope"),
        "401 must be attributable to the plaintext/authcrypt guard, got: {body}"
    );
    assert!(
        body.get("tokens").is_none() && body.get("access_token").is_none(),
        "no token may be issued for a forged plaintext message: {body}"
    );

    mock.shutdown().await;
}

/// Regression pin for the forged-sender auth bypass on the VTC refresh path. `POST
/// /v1/auth/refresh` unpacks a DIDComm envelope and binds `msg.from` to
/// the session DID (`signer_did`) inside `handle_refresh`. The opaque
/// refresh token is the primary credential, but a plaintext (forgeable)
/// `from` would defeat that binding, so the envelope must be authcrypt.
/// No valid refresh token is needed — the guard runs first.
#[tokio::test]
async fn plaintext_didcomm_refresh_is_rejected() {
    const REFRESH_TASK: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

    let mock = MockVtc::start_with_atm(build_offline_atm().await).await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": REFRESH_TASK,
        "from": "did:key:z6MkVtcForgedAdminTarget",
        "to": ["did:key:z6MkVtcServiceUnderTest"],
        "body": { "refresh_token": "stolen-or-guessed-token" },
    });

    let resp = client
        .post(format!("{base}/v1/auth/refresh"))
        .header("Trust-Task", REFRESH_TASK)
        .header("content-type", "text/plain")
        .body(forged.to_string())
        .send()
        .await
        .expect("POST /v1/auth/refresh");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a plaintext DIDComm refresh must be rejected by the authcrypt guard; got body: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("authenticated (authcrypt) DIDComm envelope"),
        "401 must be attributable to the refresh authcrypt guard, got: {body}"
    );
    assert!(
        body.get("tokens").is_none() && body.get("access_token").is_none(),
        "no token may be issued for a forged plaintext refresh: {body}"
    );

    mock.shutdown().await;
}
