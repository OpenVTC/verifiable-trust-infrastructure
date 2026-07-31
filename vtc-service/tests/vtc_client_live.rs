//! `vtc-client` driven against a live `MockVtc` — the pair, in one test.
//!
//! **Why this file exists.** `vtc-client` was broken on *every* route and
//! nothing noticed, because its own tests only exercised serde shapes and the
//! VTC's tests only exercised hand-written requests. Three independent faults
//! had accumulated:
//!
//! 1. `connect` posted an anoncrypt DIDComm envelope, which the VTC stopped
//!    accepting when `/auth/*` began requiring an authenticated sender (#771).
//! 2. Nothing sent the `Trust-Task` URL header the VTC gates every route on, so
//!    every call was a 400 before reaching a handler.
//! 3. `approve_join` / `reject_join` posted to `/approve` + `/reject` mounts
//!    that had been replaced by a single `/decide` endpoint, and `submit_join`
//!    posted to a route that is no longer mounted at all.
//!
//! Each is invisible to a test that stubs the other side. So these run the real
//! client against the real router: a regression in either direction fails here.

use vtc_client::VtcClient;
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtc;

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

/// Seed the join ceremony the way `server::run` does at boot: the default
/// policy set, so `join.rego` evaluates instead of the ceremony failing closed
/// with "no active join policy". A bare `MockVtc` has no policies — the join
/// tests that predate this file seed the same way.
async fn seed_join_policies(mock: &MockVtc) {
    let state = &mock.vtc.state;
    vtc_service::policy::default::install_defaults(&state.policies_ks, &state.active_policies_ks)
        .await
        .expect("install default policies");
}

/// A deterministic `did:key` + its multibase private key.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// `VtcClient::connect` authenticates against a real VTC, and the token it
/// returns drives an authenticated call.
///
/// This is the end-to-end pin for all three faults above: the login body must
/// be what the VTC accepts, and both the login and the follow-up call must
/// carry the Trust-Task header.
#[tokio::test]
async fn connect_then_list_members_round_trips() {
    let mock = MockVtc::start().await;
    let base = format!("{}/v1", mock.base_url());

    let (did, private_key_multibase) = did_key_from_seed(0x91);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let client = VtcClient::connect(
        &base,
        "did:key:z6MkVtcUnderTest",
        &did,
        &private_key_multibase,
    )
    .await
    .expect("connect must authenticate against a live VTC");

    // An authenticated admin read. A fresh community has no members; the point
    // is that the call is *accepted* — a missing Trust-Task header would be a
    // 400 and a stale token a 401.
    let members = client
        .list_members(None)
        .await
        .expect("list_members must be accepted by a live VTC");
    assert!(
        members.is_empty(),
        "a fresh community has no members, got {members:?}"
    );

    mock.shutdown().await;
}

/// The admin join queue is readable, and a decision on a non-existent request
/// reaches the handler rather than being refused at the router.
///
/// A 404/400-from-the-handler is the *success* condition for the decide half:
/// it proves the request got past the Trust-Task gate and hit the `/decide`
/// endpoint. The old client posted to `/approve`, which is unrouted — that is
/// indistinguishable from this at the status-code level, so the assertion is on
/// the error *not* being the router's Trust-Task rejection.
#[tokio::test]
async fn join_queue_reads_and_decide_reaches_the_handler() {
    let mock = MockVtc::start().await;
    let base = format!("{}/v1", mock.base_url());

    let (did, private_key_multibase) = did_key_from_seed(0x92);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&did))
        .await
        .expect("seed admin acl row");

    let client = VtcClient::connect(
        &base,
        "did:key:z6MkVtcUnderTest",
        &did,
        &private_key_multibase,
    )
    .await
    .expect("connect");

    let queue = client
        .list_join_requests(Some("pending"))
        .await
        .expect("list_join_requests must be accepted");
    assert!(queue.is_empty(), "fresh community, got {queue:?}");

    let err = client
        .approve_join("00000000-0000-0000-0000-000000000000")
        .await
        .expect_err("no such join request");
    match err {
        vtc_client::VtcError::Http { status, body } => {
            assert_ne!(
                status, 400,
                "a 400 here means the router refused the request (bad/missing \
                 Trust-Task URL), not that the handler ran: {body}"
            );
            assert!(
                !body.contains("Trust-Task"),
                "the failure must come from the handler, not the Trust-Task gate: {body}"
            );
        }
        other => panic!("expected an HTTP error from the decide handler, got {other:?}"),
    }

    mock.shutdown().await;
}

/// The applicant side, end to end: `submit_join` signs a
/// `join-requests/submit/0.1` document with the applicant's holder key, posts it
/// to the document endpoint with **no bearer token**, and gets the community's
/// verdict back.
///
/// This is the method that could not work at all before — it posted to
/// `POST /join-requests`, a route that is no longer mounted. Three separate
/// server-side gates have to be satisfied for this to pass, and each was a way
/// to get it wrong: the document's proof must verify under the `did:key`
/// resolver, its `issuer` must equal the proven signer, and its `recipient` must
/// equal *this* VTC's configured DID (the replay defence — a submit signed for
/// one community cannot be posted to another).
#[tokio::test]
async fn submit_join_signs_and_gets_a_verdict() {
    let mock = MockVtc::start().await;
    let base = format!("{}/v1", mock.base_url());

    seed_join_policies(&mock).await;
    let (applicant_did, applicant_key) = did_key_from_seed(0x94);

    // No token: an applicant is by definition not yet a member. The client is
    // built with the VTC's real DID because the document is addressed to it.
    let client = VtcClient::anonymous(&base, vtc_service::test_support::TEST_VTC_DID);

    let body = vtc_client::join_requests::JoinRequestSubmitBody {
        vp: serde_json::json!({
            "type": "VerifiablePresentation",
            "holder": applicant_did,
        }),
        registry_consent: false,
        extensions: serde_json::json!({}),
    };

    let verdict = client
        .submit_join(&body, &applicant_did, &applicant_key)
        .await
        .expect("a signed submit must be accepted");

    // The default policy refers the request to an admin rather than
    // auto-admitting — the point here is that the ceremony *ran*.
    assert_eq!(
        verdict.verdict.effect,
        vtc_client::join_requests::VerdictEffect::Refer,
        "default policy refers to an admin; got {:?}",
        verdict.verdict.effect
    );

    mock.shutdown().await;
}

/// The submitted request lands in the admin queue under the applicant's DID —
/// i.e. the server took the *proof's* signer as the applicant, not anything the
/// body claimed.
#[tokio::test]
async fn submitted_request_is_attributed_to_the_signing_did() {
    let mock = MockVtc::start().await;
    let base = format!("{}/v1", mock.base_url());

    seed_join_policies(&mock).await;
    let (applicant_did, applicant_key) = did_key_from_seed(0x95);
    let (admin_did, admin_key) = did_key_from_seed(0x96);
    store_acl_entry(&mock.vtc.state.acl_ks, &admin_entry(&admin_did))
        .await
        .expect("seed admin acl row");

    let applicant = VtcClient::anonymous(&base, vtc_service::test_support::TEST_VTC_DID);
    let body = vtc_client::join_requests::JoinRequestSubmitBody {
        vp: serde_json::json!({
            "type": "VerifiablePresentation",
            "holder": applicant_did,
        }),
        registry_consent: false,
        extensions: serde_json::json!({}),
    };
    applicant
        .submit_join(&body, &applicant_did, &applicant_key)
        .await
        .expect("submit");

    let admin = VtcClient::connect(
        &base,
        vtc_service::test_support::TEST_VTC_DID,
        &admin_did,
        &admin_key,
    )
    .await
    .expect("admin connect");
    let queue = admin
        .list_join_requests(Some("pending"))
        .await
        .expect("list join requests");

    assert_eq!(queue.len(), 1, "one pending request, got {queue:?}");
    assert_eq!(
        queue[0].applicant_did, applicant_did,
        "the request must be attributed to the DID that signed the document"
    );

    mock.shutdown().await;
}

/// A signature by a key other than the claimed `issuer` is refused — the
/// issuer↔signer cross-check, not just "some valid proof is present".
#[tokio::test]
async fn submit_with_mismatched_issuer_is_refused() {
    let mock = MockVtc::start().await;
    let base = format!("{}/v1", mock.base_url());

    let (victim_did, _) = did_key_from_seed(0x97);
    let (attacker_did, attacker_key) = did_key_from_seed(0x98);

    // Sign with the attacker's key but claim the victim as issuer.
    let payload = serde_json::json!({
        "vp": { "type": "VerifiablePresentation", "holder": victim_did },
        "registryConsent": false,
        "extensions": {},
    });
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        vtc_client::join_requests::JOIN_REQUEST_SUBMIT_TYPE,
        payload,
        &victim_did,
        vtc_service::test_support::TEST_VTC_DID,
    )
    .expect("build");
    vta_sdk::trust_task_sign::sign_in_place(&mut doc, &attacker_did, &attacker_key)
        .await
        .expect("sign with the attacker key");

    let resp = reqwest::Client::new()
        .post(format!("{base}/trust-tasks"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&doc).unwrap())
        .send()
        .await
        .expect("POST /trust-tasks");

    assert!(
        !resp.status().is_success(),
        "a document whose issuer is not the signer must be refused"
    );

    mock.shutdown().await;
}
