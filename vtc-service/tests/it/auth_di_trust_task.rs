//! The VTC's canonical login: a DI-signed `auth/authenticate/0.2` Trust Task,
//! driven by the *client's own* builder (`vta_sdk::auth_di`), dispatched on
//! the shared `POST /v1/trust-tasks` door alongside every other verb.
//!
//! **Why this exists.** The VTC accepted two login shapes — a VTA-wallet SIOP
//! envelope, and an authcrypt DIDComm envelope. A REST client holding a plain
//! `did:key` (no wallet to self-issue an `id_token`, no mediator to authcrypt
//! through) could satisfy neither, so `vtc-client::connect` could not log in at
//! all. `auth/refresh` had already grown the Trust-Task path; login had not,
//! which left a client able to *rotate* a token it had no way to obtain.
//! `auth/challenge`, `auth/authenticate/{0.2,0.3}` and `auth/refresh/0.2` are
//! now dispatched pre-session on `/v1/trust-tasks`
//! (`trust_tasks::auth_tasks`) — the dedicated, `Trust-Task`-header-gated
//! REST mounts at `/v1/auth/{challenge,,refresh}` had no caller left once
//! `vta_sdk::auth_light` (the client both the VTA and the VTC-facing tooling
//! share) switched to it (#1858).
//!
//! Every test here posts bytes produced by the real SDK builder rather than a
//! hand-written fixture, so a client/server drift — the defect class that made
//! this necessary — fails the build instead of an operator's setup run.

use reqwest::StatusCode;
use serde_json::{Value, json};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;

/// The mock VTC's own DID. A signed authenticate document must name it as
/// `recipient` (#1638) — a placeholder here would be refused as addressed
/// to another service, which is exactly what the check is for.
async fn vtc_did(mock: &MockVtc) -> String {
    mock.vtc
        .state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the mock VTC has a DID")
}

const AUTHENTICATE_TASK: &str = "https://trusttasks.org/spec/auth/authenticate/0.2";

fn admin_entry(did: &str) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        role: VtcRole::Admin,
        label: None,
        admin: VtcRole::Admin.implied_authority(),
        delegated_by: None,
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

/// Post `doc` (already a JSON string) to `POST /v1/trust-tasks`.
async fn post_trust_task(client: &reqwest::Client, base: &str, doc: String) -> (StatusCode, Value) {
    let resp = client
        .post(format!("{base}/v1/trust-tasks"))
        .header("content-type", "application/json")
        .body(doc)
        .send()
        .await
        .expect("POST /v1/trust-tasks");
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

/// The declared error code inside a `trust-task-error` response payload, if
/// any — the spine's error shape, not the flat REST body the old handlers
/// answered with.
fn error_code(body: &Value) -> Option<&str> {
    body["payload"]["code"].as_str()
}

/// Fetch a challenge for `did` from a running VTC, over `/v1/trust-tasks`.
async fn get_challenge(
    client: &reqwest::Client,
    base: &str,
    vta_did: &str,
    did: &str,
) -> (String, String) {
    let doc =
        vta_sdk::auth_di::build_challenge_doc(did, vta_did, did).expect("build challenge doc");
    let (status, body) = post_trust_task(client, base, doc).await;
    assert_eq!(status, StatusCode::OK, "challenge issuance: {body}");
    let parsed =
        vta_sdk::auth_di::parse_challenge_response(&body.to_string()).expect("challenge response");
    (parsed.challenge, parsed.session_id)
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

    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;

    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        &vta_did,
        &challenge,
        &session_id,
    )
    .await
    .expect("sign authenticate document");

    let (status, body) = post_trust_task(&client, &base, doc).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a DI-signed Trust Task must authenticate against the VTC; got: {body}"
    );
    let parsed =
        vta_sdk::auth_di::parse_auth_response(&body.to_string()).expect("authenticate response");
    assert!(
        !parsed.tokens.access_token.is_empty(),
        "response must carry an access token"
    );
    assert_eq!(
        parsed.session.subject, did,
        "the session must be bound to the proven signer"
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

    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;
    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        &vta_did,
        &challenge,
        &session_id,
    )
    .await
    .expect("sign");
    let (status, body) = post_trust_task(&client, &base, doc).await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    let login = vta_sdk::auth_di::parse_auth_response(&body.to_string()).expect("login response");

    let refresh_token = login
        .tokens
        .refresh_token
        .clone()
        .expect("login must issue a refresh token");

    let refresh_doc = vta_sdk::auth_di::build_refresh_doc(&did, &vta_did, &refresh_token)
        .expect("build refresh document");
    let (status, refreshed) = post_trust_task(&client, &base, refresh_doc).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refresh token from a DI login must rotate: {refreshed}"
    );
    let refreshed =
        vta_sdk::auth_di::parse_auth_response(&refreshed.to_string()).expect("refresh response");
    assert!(
        !refreshed.tokens.access_token.is_empty(),
        "rotation must return a fresh access token"
    );

    mock.shutdown().await;
}

/// The proof is load-bearing: editing the challenge after signing must not
/// authenticate. Guards against a future "parse the payload, skip the proof"
/// shortcut on the VTC's dispatch path.
#[tokio::test]
async fn tampered_challenge_is_rejected() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, private_key_multibase) = did_key_from_seed(0x7c);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;
    let doc = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &private_key_multibase,
        &vta_did,
        // Sign over a *different* challenge, then swap the real one in.
        "0000000000000000000000000000000000000000",
        &session_id,
    )
    .await
    .expect("sign");
    let mut tampered: Value = serde_json::from_str(&doc).expect("signed doc is JSON");
    tampered["payload"]["challenge"] = json!(challenge);

    let (status, body) = post_trust_task(&client, &base, tampered.to_string()).await;
    // The proof no longer matches the (now-edited) payload — the spine's
    // generic proof-verification step refuses it before any handler runs, as
    // the standard `permissionDenied` code (403), not the extended
    // `proofInvalid` (422): a failed cryptographic check is a standard-code
    // refusal, not this family's declared error.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a post-signature edit must not authenticate: {body}"
    );
    assert_eq!(error_code(&body), Some("permissionDenied"), "{body}");

    mock.shutdown().await;
}

/// An **unsigned** `authenticate/0.2` document is refused before it is ever
/// routed to a handler — the spec declares a proof required, and the spine
/// enforces that generically (`dispatch_trust_task_core`), the same gate
/// every other proof-bearing verb gets.
#[tokio::test]
async fn unsigned_authenticate_document_is_not_claimed_by_the_di_path() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, _) = did_key_from_seed(0x7d);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;
    let unsigned = json!({
        "id": "urn:uuid:unsigned-1",
        "type": AUTHENTICATE_TASK,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": vta_did,
        "payload": { "challenge": challenge, "sessionId": session_id },
    });

    let (status, body) = post_trust_task(&client, &base, unsigned.to_string()).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unsigned document must not mint tokens: {body}"
    );
    assert_eq!(error_code(&body), Some("proofRequired"), "{body}");

    mock.shutdown().await;
}

/// #1638, the relay: a signed authenticate document addressed to another
/// service is refused here (`wrongRecipient`), however valid its proof and
/// challenge — and the refusal leaves the session intact, so the holder can
/// still sign in with a document addressed to this VTC.
#[tokio::test]
async fn a_document_addressed_to_another_service_is_refused() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();
    let (did, key) = did_key_from_seed(0x7e);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .unwrap();
    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;

    // Signed for a different service — what a relaying service would hold.
    let relayed = vta_sdk::auth_di::sign_authenticate_doc(
        &did,
        &key,
        "did:key:z6MkSomeOtherService",
        &challenge,
        &session_id,
    )
    .await
    .unwrap();
    let (status, body) = post_trust_task(&client, &base, relayed).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(error_code(&body), Some("wrongRecipient"), "{body}");
    assert!(body.get("tokens").is_none(), "{body}");

    // The session was not consumed by the refusal.
    let addressed =
        vta_sdk::auth_di::sign_authenticate_doc(&did, &key, &vta_did, &challenge, &session_id)
            .await
            .unwrap();
    let (status, body) = post_trust_task(&client, &base, addressed).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    mock.shutdown().await;
}

/// #1638: a signed authenticate document naming no `recipient` is valid at
/// every service, so it is refused as `malformedRequest` (SPEC §7.2 item 5).
#[tokio::test]
async fn a_document_with_no_recipient_is_malformed() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();
    let (did, key) = did_key_from_seed(0x7f);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .unwrap();
    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;

    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        AUTHENTICATE_TASK,
        json!({ "challenge": challenge, "sessionId": session_id, "scope": [] }),
        &did,
        "unused",
    )
    .unwrap();
    doc.recipient = None;
    vta_sdk::trust_task_sign::sign_in_place(&mut doc, &did, &key)
        .await
        .unwrap();

    let (status, body) =
        post_trust_task(&client, &base, serde_json::to_string(&doc).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(error_code(&body), Some("malformedRequest"), "{body}");
    assert!(body.get("tokens").is_none(), "{body}");

    mock.shutdown().await;
}

/// Sign `doc` **exactly as it stands** — the JSON a JavaScript producer sends —
/// with seed `seed`'s Ed25519 key under `vm`, for `purpose`, the proof's
/// `created` set to the string given, verbatim (VTI-45).
fn sign_received(doc: &mut Value, seed: u8, vm: &str, purpose: &str, created: &str) {
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
    use ed25519_dalek::Signer as _;
    let mut di = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        vm.to_string(),
        purpose.to_string(),
        None,
        Some(created.to_string()),
        None,
    );
    doc.as_object_mut().expect("an object").remove("proof");
    let input = prepare_sign_input(&*doc, &di, CryptoSuite::EddsaJcs2022).expect("sign input");
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    di.proof_value = Some(multibase::encode(
        multibase::Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc["proof"] = serde_json::to_value(&di).expect("proof serialises");
}

/// Now, on a whole second, as JavaScript's `toISOString()` writes it.
fn javascript_whole_second_now() -> String {
    format!("{}.000Z", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S"))
}

/// VTI-45, over HTTP: a login document as a JavaScript producer signs it on a
/// whole second — `.000Z` in `issuedAt` and in the proof's `created`, a `null`
/// `threadId` — authenticates. Before the fix the spine verified a typed
/// re-serialisation, which writes the timestamps without the fraction, and
/// answered `proofInvalid`.
#[tokio::test]
async fn vti_45_a_javascript_whole_second_authenticate_document_logs_in() {
    let mock = MockVtc::start().await;
    let base = mock.base_url().to_string();
    let client = reqwest::Client::new();

    let (did, _) = did_key_from_seed(0x45);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");
    let vta_did = vtc_did(&mock).await;
    let (challenge, session_id) = get_challenge(&client, &base, &vta_did, &did).await;

    let now = javascript_whole_second_now();
    let mb = did.trim_start_matches("did:key:");
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": AUTHENTICATE_TASK,
        "issuer": did,
        "recipient": vta_did,
        "issuedAt": now,
        "threadId": null,
        "payload": { "challenge": challenge, "sessionId": session_id },
    });
    sign_received(
        &mut doc,
        0x45,
        &format!("{did}#{mb}"),
        "authentication",
        &now,
    );

    let mut tampered = doc.clone();
    tampered["issuedAt"] = json!(now.replace(".000Z", "Z"));
    let (status, body) = post_trust_task(&client, &base, tampered.to_string()).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a re-spelled timestamp is not what was signed: {body}"
    );

    let (status, body) = post_trust_task(&client, &base, doc.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed =
        vta_sdk::auth_di::parse_auth_response(&body.to_string()).expect("authenticate response");
    assert_eq!(parsed.session.subject, did);

    mock.shutdown().await;
}
