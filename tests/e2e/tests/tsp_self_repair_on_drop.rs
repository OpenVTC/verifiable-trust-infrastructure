//! A TSP client self-heals when the VTA forgets its half of the §7.2.2
//! relationship (design note `tsp-relationship-recovery.md`, D4).
//!
//! ## Why this exists
//!
//! §7.2.2 is symmetric and silent: if the VTA loses its half of a relationship
//! (idle eviction, key rotation, a fresh redeploy) it *drops* the peer's next
//! frame with no reply. A **fresh** `pnm` process recovers on its own because it
//! re-invites every run (that is #1540). But a client whose relationship store
//! still reads "related" — a long-lived process, or a durable store — never
//! re-invites: `relate` short-circuits on the local state, so the send is
//! dropped and the call just times out, forever.
//!
//! D4 makes that self-repairing at the transport layer: a reply-timeout is
//! treated as a possible §7.2.2 drop, the stale relationship is reset to `None`
//! and re-invited (the VTA's answering arm accepts, and the D2 reconcile
//! transition makes the reset safe even if the peer had *not* actually
//! forgotten), and a **retry-safe** Trust Task is resent once. `acl/grant` is
//! classified `RetrySafe`, so this recovers in a single call.
//!
//! This test is inherently non-vacuous: without the self-repair the post-forget
//! grant below times out (the client never re-invites over a store that reads
//! "related"), so the `expect` fails.
//!
//! Hermetic — `MockVta::start_with_transports` embeds a `TestMediator`, and
//! `MockVta::forget_tsp_relationship` resets the VTA's local half to reproduce
//! the drop.

use ed25519_dalek::SigningKey;
use serde_json::Value;
use vta_sdk::client::{CreateAclRequest, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1;
use vta_service::test_support::MockVta;

mod common;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
/// Same helper as every other TSP binary in this crate.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

/// After the VTA forgets its half, a retry-safe Trust Task recovers in one call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_safe_task_recovers_when_the_vta_forgets_the_relationship() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x7e);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    // Multiplexed dual client (reference topology): connecting forms the
    // relationship on both sides.
    let client = VtaClient::connect_didcomm_with_tsp(
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("dual DIDComm+TSP client connects and forms its §7.2.2 relationship");

    // Baseline: a grant works while both halves are held. Confirms the
    // relationship really is established before we tear the VTA's half down.
    client
        .create_acl(CreateAclRequest::new("did:example:heal-baseline", "admin"))
        .await
        .expect("baseline grant succeeds with the relationship intact");

    // The VTA forgets its half — as if idle-evicted or redeployed. The client
    // still reads its own store as "related", so its next send is dropped at the
    // VTA's §7.2.2 gate with no reply.
    mock.forget_tsp_relationship(&client_did).await;

    // The recovering grant. A short timeout on purpose: the first attempt is
    // dropped and must time out before the self-repair runs, so a generous
    // budget would only make the test slow. `acl/grant` is `RetrySafe`, so the
    // self-repair re-forms the relationship and resends once — all inside this
    // one call.
    let payload =
        serde_json::to_value(CreateAclRequest::new("did:example:heal-recovered", "admin"))
            .expect("serialize the grant body");
    let reply: Value = client
        .dispatch_trust_task(TASK_ACL_GRANT_0_1, payload, 3)
        .await
        .expect(
            "the grant must recover: on the reply-timeout the client resets its stale \
             relationship, re-invites (the VTA accepts), and resends. A failure here is the \
             bare timeout this feature removes.",
        );

    client.shutdown().await;
    mock.shutdown().await;

    // `acl/grant/0.1` answers with `{ entry: { subject, role, … } }`.
    assert_eq!(
        reply.pointer("/entry/subject").and_then(Value::as_str),
        Some("did:example:heal-recovered"),
        "recovered grant returned the realized entry: {reply:#}"
    );
    assert_eq!(
        reply.pointer("/entry/role").and_then(Value::as_str),
        Some("admin")
    );
}
