//! `VtaClient` over TSP forms the §7.2.2 relationship itself, and doing it
//! twice is not an error.
//!
//! ## Why this exists
//!
//! `VtaClient::connect_tsp` opened a `TspSession` and never related, so under
//! Rev 3 the VTA dropped every Trust Task the client sent — §7.2.2 says *drop*,
//! so the symptom was a client that timed out with nothing in any log on either
//! side. The relationship is a precondition of all traffic, not a courtesy, and
//! the client cannot function without it; forming it in the constructor is the
//! difference between an API that works and one that has a step callers must
//! remember.
//!
//! ## The case that nearly shipped broken
//!
//! `SendInvite` is a valid transition **only** from `RelationshipState::None`
//! (`affinidi-tsp::relationship::transition`), so an unconditional invite is an
//! `InvalidTransition` for a peer already related.
//!
//! That is invisible with the SDK's default relationship store, which is
//! ephemeral and in-memory: a fresh ATM per connect always starts at `None`, so
//! every invite is the first one and an unconditional relate looks correct. A
//! consumer that configures a durable store through
//! `ATMConfigBuilder::with_relationship_store` reconnects into `Pending` or
//! `Bidirectional` — and would have had its connect fail where it previously
//! worked. A silent-drop bug traded for a connect-time failure, and only for
//! the deployments careful enough to persist their relationships.
//!
//! `connect_tsp_on` is what makes that testable hermetically: every identity on
//! one `SessionHub` shares its ATM, and therefore its relationship store. Two
//! connects on the same hub reach the second one with a relationship already
//! held — the same state a durable store restores on reconnect, without needing
//! one.
//!
//! Hermetic: `MockVta::start_with_transports` embeds a `TestMediator`.

use ed25519_dalek::SigningKey;
use vta_sdk::client::VtaClient;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session_hub::SessionHub;
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

/// A second connect for the same identity, against a relationship store that
/// already holds the relationship, succeeds.
///
/// This is the regression guard for the idempotency flaw. Without it the fix
/// has no hermetic coverage at all, because the default store hides the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connecting_twice_on_one_hub_does_not_re_invite() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x7a);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    // One hub, so both connects share one ATM and one relationship store.
    let hub = SessionHub::new().await.expect("hub starts");

    let first = VtaClient::connect_tsp_on(
        &hub,
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("the first connect forms the relationship");
    first.shutdown().await;

    // The store now holds `Pending` (or `Bidirectional`, if the VTA's accept
    // has landed). Either way `SendInvite` is no longer a legal transition, so
    // a constructor that invites unconditionally fails exactly here.
    let second = VtaClient::connect_tsp_on(
        &hub,
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect(
        "the second connect must treat an existing relationship as a no-op; an unconditional \
         invite fails here with an InvalidTransition, which is what a consumer with a durable \
         relationship store would hit on every reconnect",
    );
    second.shutdown().await;

    mock.shutdown().await;
}

/// A client built through `connect_tsp` needs no explicit `relate` call.
///
/// The point of forming it in the constructor: a caller that has to remember a
/// step gets a client that times out, and §7.2.2's *drop* means neither side
/// logs why. `MockVta`'s mediator is built with `.local_direct_delivery(true,
/// false)` precisely so the invite can be delivered, so a regression here shows
/// up as a failure rather than a fixture quirk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_tsp_relates_without_being_asked() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x7b);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    let client = VtaClient::connect_tsp(
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("connect_tsp forms the relationship as part of connecting");

    client.shutdown().await;
    mock.shutdown().await;
}
