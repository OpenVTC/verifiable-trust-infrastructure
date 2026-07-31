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

/// Join submission is refused with a typed error naming its replacement,
/// instead of silently 404ing against an unrouted path.
#[tokio::test]
async fn submit_join_reports_where_it_moved() {
    let (did, private_key_multibase) = did_key_from_seed(0x93);
    let _ = private_key_multibase;
    let client = VtcClient::with_token("https://vtc.invalid/v1", &did, "unused-token");

    // Contents are irrelevant — the call is refused before any transport.
    let body =
        serde_json::from_value(serde_json::json!({ "vp": {} })).expect("minimal submit body");

    match client.submit_join(&body).await {
        Err(vtc_client::VtcError::Unsupported(msg)) => {
            assert!(
                msg.contains("/trust-tasks"),
                "the error must name the endpoint that replaced it: {msg}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
