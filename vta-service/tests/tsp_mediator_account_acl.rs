//! The client's own mediator-account ACL, set over **TSP**, against a real
//! mediator.
//!
//! This is the one thing the TSP account pass could never be tested on until
//! now, and the reason it is worth a live mediator rather than a guard.
//!
//! The mediator's management dispatch used to be DIDComm-only: `MessageType::
//! process` → `trust_tasks::process` was `#[cfg(feature = "didcomm")]` and took
//! a DIDComm `Message`, so a TSP message addressed to the mediator was filed for
//! pickup rather than answered. There was no packet a TSP-only client could send
//! to open its own account. affinidi-tdk-rs#783 added the TSP wrapper (mediator
//! 0.22.3) and VTI #1312 the client half.
//!
//! **Why a live mediator is the only honest check.** Both halves of that pair
//! ship with source-level guards, and guards cannot see the thing that actually
//! goes wrong here: a mediator without the TSP arm accepts the frame, files it
//! as mail, and answers nothing. The send resolves `Ok` either way. Success and
//! silent failure are identical from the client — which is exactly why the
//! client is careful to log only what it *sent* — so the only way to know the
//! ACL was applied is to ask the mediator.
//!
//! The fixture therefore starts from a **restrictive** `global_acl_default`, so
//! a freshly authenticated account is genuinely closed. Against a mediator
//! predating the TSP arm, this test fails on the post-condition rather than
//! passing vacuously.

#![cfg(feature = "transport-harness")]

use affinidi_messaging_test_mediator::TestMediator;
use affinidi_messaging_test_mediator::acl;

/// The realistic restrictive default: an account that can connect and
/// authenticate, but is **closed for forwarded delivery** until something opens
/// it.
///
/// Not `acl::deny_all()`, which is the wrong shape for this test in an
/// instructive way: it sets `local = false` and clears `NotBlocked`, so the
/// client is refused at the websocket with a 403 and never authenticates. It
/// would never reach the code under test — and a deployment configured that way
/// has no clients at all, so it is not the case worth covering.
///
/// `receive_forwarded` off with everything else on *is* the case worth
/// covering: the client connects, gets an account, and still cannot receive a
/// forwarded reply until its `account/update` lands.
fn closed_for_forwarded() -> affinidi_messaging_test_mediator::MediatorACLSet {
    let mut acls = acl::allow_all();
    // (value, self_change, admin). `self_change = true` is the whole point: a
    // client opens its *own* account, so the flag has to be self-manageable.
    // With `false` the mediator answers
    // `e.p.authorization.acl.not_self_manageable` — correctly, and see
    // `a_default_that_forbids_self_management_refuses_the_client` below, which
    // pins that as behaviour rather than leaving it as a fixture footgun.
    acls.set_receive_forwarded(false, true, true)
        .expect("admin=true may always set this bit");
    acls
}

/// Mint a fresh Ed25519 `did:key` and its base58btc-encoded seed.
fn mint_did_key() -> (String, String) {
    // `rand` rather than `getrandom` directly: this crate already carries it,
    // and the key only has to be unique per test, not production-grade.
    let seed: [u8; 32] = rand::random();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
    );
    (did, multibase::encode(multibase::Base::Base58Btc, seed))
}

#[tokio::test]
async fn a_tsp_client_opens_its_own_mediator_account() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vta_sdk=debug".into()),
        )
        .with_test_writer()
        .try_init();
    affinidi_messaging_test_mediator::install_default_crypto_provider();

    // The default every new account inherits. Closed for forwarded delivery,
    // because a permissive default is indistinguishable from a successful
    // update — the test would pass against a mediator that ignored the request.
    let mediator = TestMediator::builder()
        .global_acl_default(closed_for_forwarded())
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();

    let (client_did, client_key) = mint_did_key();

    // Authenticating is what creates the account, carrying `global_acl_default`.
    // It is also the rotation path's reachability probe, so this mirrors the
    // real sequence rather than a contrived one.
    let session = vta_sdk::session::TspPingSession::new(&client_did, &client_key, &mediator_did)
        .await
        .expect("client reaches the mediator over TSP");

    // Pre-condition. If this is already open the assertion below proves nothing,
    // so state it rather than assume it.
    let before = mediator
        .get_acl(&client_did)
        .await
        .expect("read ACL")
        .expect("authenticating registers the account");
    assert!(
        !before.get_receive_forwarded().0,
        "fixture is wrong: a new account must start closed for forwarded delivery, \
         otherwise this test cannot distinguish a successful update from a mediator \
         that ignored the request"
    );

    // The thing under test: one `messaging/account/update/0.1`, over TSP,
    // addressed to the mediator itself.
    session.provision_client_acl("tsp-acl-e2e").await;
    session.shutdown().await;

    let after = mediator
        .get_acl(&client_did)
        .await
        .expect("read ACL")
        .expect("account still registered");

    assert!(
        after.get_receive_forwarded().0,
        "the mediator did not apply the ACL sent over TSP. On a mediator without the TSP \
         management arm (< 0.22.3) the request is filed as mail and answered with nothing, \
         which looks exactly like this — check the mediator version before the client."
    );
    assert!(
        after.get_receive_messages().0,
        "receive_messages must be open too — TSP delivery checks it via `delivery_decision`, \
         so an account without it is refused before `receive_forwarded` is ever consulted"
    );
}

/// The same DID, provisioned twice. The rotation path can retry, and a mediator
/// that refused a repeat would turn a safe retry into a failure.
#[tokio::test]
async fn provisioning_the_same_account_twice_is_harmless() {
    affinidi_messaging_test_mediator::install_default_crypto_provider();

    let mediator = TestMediator::builder()
        .global_acl_default(closed_for_forwarded())
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();
    let (client_did, client_key) = mint_did_key();

    for _ in 0..2 {
        let session =
            vta_sdk::session::TspPingSession::new(&client_did, &client_key, &mediator_did)
                .await
                .expect("client reaches the mediator over TSP");
        session.provision_client_acl("tsp-acl-e2e").await;
        session.shutdown().await;
    }

    let acls = mediator
        .get_acl(&client_did)
        .await
        .expect("read ACL")
        .expect("account registered");
    assert!(
        acls.get_receive_forwarded().0,
        "a second pass must leave the account open, not revert it"
    );
}

/// A `global_acl_default` that marks `receiveForwarded` **not self-manageable**
/// refuses the client's own update — and the client carries on regardless.
///
/// Found by getting the fixture above wrong, and worth keeping for two reasons.
///
/// It is a real deployment shape: an operator who wants forwarded delivery
/// granted only by an admin sets exactly this, and the effect is that
/// self-provisioning silently does nothing. The account stays closed, so a
/// rotated DID never receives a forwarded reply, and nothing in the client's
/// output says why — it is a `debug` line on a best-effort path.
///
/// And it pins the *client's* half of that contract: refusing must stay
/// non-fatal. This runs on the rotation path immediately before the key swap,
/// so propagating the error would turn "your mediator has a strict default"
/// into "your rotation failed", which is a much worse outcome than an account
/// that opens later.
#[tokio::test]
async fn a_default_that_forbids_self_management_refuses_the_client() {
    affinidi_messaging_test_mediator::install_default_crypto_provider();

    let mut acls = acl::allow_all();
    // Closed *and* admin-only — the difference from `closed_for_forwarded`.
    acls.set_receive_forwarded(false, false, true)
        .expect("admin=true may always set this bit");

    let mediator = TestMediator::builder()
        .global_acl_default(acls)
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();
    let (client_did, client_key) = mint_did_key();

    let session = vta_sdk::session::TspPingSession::new(&client_did, &client_key, &mediator_did)
        .await
        .expect("client reaches the mediator over TSP");

    // Must not panic, and must not propagate: the caller is mid-rotation.
    session.provision_client_acl("tsp-acl-e2e").await;
    session.shutdown().await;

    let acls = mediator
        .get_acl(&client_did)
        .await
        .expect("read ACL")
        .expect("account registered");
    assert!(
        !acls.get_receive_forwarded().0,
        "the mediator must refuse a self-update of a flag it marked admin-only — if this \
         starts passing, the mediator has stopped enforcing `not_self_manageable`"
    );
}
