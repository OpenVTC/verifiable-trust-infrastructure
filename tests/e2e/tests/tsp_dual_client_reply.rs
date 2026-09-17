//! A dual DIDComm+TSP `VtaClient` must receive the VTA's Trust-Task **reply**,
//! not just get its request dispatched.
//!
//! ## Why this exists
//!
//! `pnm acl create` against a VTA advertising both `#tsp` and `#vta-didcomm` on
//! one mediator (the reference topology) failed like this: the VTA logged the
//! grant as `outcome="success"` and `TSP trust-task dispatched status=200 OK`,
//! and the client then timed out — `tsp transport error: timed out waiting for
//! the TSP reply`, with `discarded: no relationship with did:key:…` (the
//! client's *own* VID) on the way past.
//!
//! The request landed and the reply was dropped, because Rev 3 §7.2.2 is
//! **symmetric**: an endpoint drops an application message from a VID it holds
//! no relationship with, and that includes the client dropping the VTA's reply.
//! The VTA still answered because its relationship store is *durable* and
//! remembered an earlier handshake; the client's is in-memory and starts at
//! `None` every process, so a run that never re-invited had no relationship for
//! the reply. `connect_didcomm_with_tsp` (and the session-layer `Auto` connect
//! it mirrors) must therefore form the relationship as part of connecting —
//! [`relate_trust_task_leg`], the shared step this test drives, is what admits
//! the reply.
//!
//! This is the join `tsp_vta_trust_task` covers only over a raw, explicitly-
//! related `TspSession`, and `tsp_dual_leg` covers only between two accounts
//! with no VTA: a **dual `VtaClient`** getting a real VTA reply back over its
//! multiplexed TSP leg was covered by neither.
//!
//! Hermetic — `MockVta::start_with_transports` embeds a `TestMediator` (built
//! with `local_direct_delivery(true, false)` so the relationship invite is
//! delivered), no network, no deployed VTA — so this runs in CI unignored.

use ed25519_dalek::SigningKey;
use vta_sdk::client::{CreateAclRequest, SurfaceTransport, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
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

/// A multiplexed dual client runs `acl/grant` over TSP and gets its reply back.
///
/// The assertion is the whole point: `create_acl` returns the realized entry
/// only if the VTA's reply was *admitted*. Before the relationship was formed on
/// the leg, the identical grant still ran server-side but `create_acl` timed out
/// on the dropped reply — the exact `pnm acl create` failure this guards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multiplexed_dual_client_receives_the_vta_trust_task_reply() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x7c);

    // The mediator decides who may connect and be routed to; the VTA decides
    // what they may ask for. An unrestricted admin grant is super-admin-only.
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    // Same mediator for `#tsp` and `#vta-didcomm` → Multiplexed: TSP rides the
    // DIDComm session's own socket. This is the reference topology operators
    // run, and so the one the bug lived on.
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

    // Per-surface transport: trust tasks on TSP, protocol messages on DIDComm.
    // If this were DIDComm the grant would never touch the leg under test.
    assert_eq!(client.trust_task_transport(), SurfaceTransport::Tsp);

    // The operator's exact command: `pnm acl create --did did:example:delete-me
    // --role admin`. It is an `acl/grant/0.1` Trust Task, so it rides TSP, and
    // awaiting its reply is what dropped under §7.2.2.
    let entry = client
        .create_acl(CreateAclRequest::new("did:example:delete-me", "admin"))
        .await
        .expect(
            "the VTA's acl/grant reply must come back over the multiplexed TSP leg. \
             Without the relationship the grant still succeeds server-side (the VTA's \
             durable store remembers an earlier handshake) while the client drops the \
             reply as `no relationship` and this call times out — the reported bug.",
        );

    client.shutdown().await;
    mock.shutdown().await;

    assert_eq!(entry.did, "did:example:delete-me");
    assert_eq!(entry.role, "admin");
}
