//! What a host does when its mediator's DID will not fit inside its own.
//!
//! Run against a real mediator rather than a simulator, because the whole failure lives in
//! the size of an identifier the mediator hands out and a resolver refuses.
//!
//! # The trap
//!
//! A `did:peer:2` carries its services **inside** the identifier, so advertising a mediator
//! costs roughly the length of that mediator's DID, once per service. Against a `did:webvh`
//! mediator — what production uses, and what this host is normally pointed at — two services
//! come to about 460 bytes. Against a `did:peer` mediator they come to about 1685, and every
//! `DIDCacheClient` refuses a DID over 1000 before it even parses it.
//!
//! Neither end says so. The member fails its websocket connect as `isActive? command timed
//! out`, which reads as a hang; the mediator answers `403 authcrypt requires sender public
//! key`, which reads as a key problem. Only `affinidi_did_authentication` logs the real
//! reason, and only on one side. The workspace has been here before — see CHANGELOG, "Watch
//! the DID size" — and closed it the same way: assert the length at mint.
//!
//! So this asserts that a host **refuses to come up** rather than coming up unreachable. That
//! is the whole of what it can be: the failure is minting an identity nobody can resolve, and
//! a host that has refused to mint one has nothing left to round-trip.
#![cfg(feature = "didcomm")]

use affinidi_messaging_test_mediator::{TestMediator, acl};

/// A mediator whose DID is too long to embed refuses the host, and says why.
///
/// The `TestMediator` mints itself a `did:peer`, which is exactly the case that does not fit
/// — so this fixture cannot be used to exercise the listener's round trip, and that is a
/// property of the fixture rather than of the listener. What it *can* prove is that the
/// failure arrives at the party who can act on it, in words that name the cause.
#[tokio::test]
async fn a_host_refuses_to_mint_an_identity_no_member_could_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let mediator = TestMediator::builder()
        .global_acl_default(acl::allow_all())
        .spawn()
        .await
        .expect("spawn a test mediator");

    let refused = room_host::didcomm::HostIdentity::load_or_mint(dir.path(), mediator.did())
        .expect_err("a did:peer mediator does not fit inside a did:peer host");
    let said = refused.to_string();

    assert!(
        said.contains("1000-byte limit"),
        "the refusal must name the limit, because the symptom elsewhere is a timeout: {said}"
    );
    assert!(
        said.contains("did:webvh"),
        "and what to do about it: {said}"
    );
    assert!(
        !dir.path().join("host-identity.json").exists(),
        "nothing unusable should be left on disk to be loaded next time"
    );

    mediator.shutdown();
}

/// The ordinary case: a short mediator DID leaves room for both services.
///
/// `did:webvh` is what production mints and what the demo runs against. Asserted as a
/// *number* rather than "it worked", because the margin is the thing that erodes — a third
/// service, or a longer mediator name, and this is over.
#[tokio::test]
async fn a_webvh_mediator_leaves_a_host_comfortably_inside_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mediator =
        "did:webvh:QmTS3a3H9Dk4ZMPAZ8jNWGeyPbuKrPbrPZcSbg8CJ6yynD:webvh.example:mediator";

    let identity = room_host::didcomm::HostIdentity::load_or_mint(dir.path(), mediator)
        .expect("a did:webvh mediator fits");

    assert!(
        identity.did.len() < 1000,
        "a host advertising a did:webvh mediator must be resolvable: {} bytes",
        identity.did.len()
    );
    assert!(
        identity.did.contains("did:peer:2"),
        "and it is a did:peer, so its services resolve by computation: {}",
        identity.did
    );

    // The same identity comes back, because a member's saved address names it. A host that
    // minted a new one on restart would leave every kept link pointing at somebody else.
    let again = room_host::didcomm::HostIdentity::load_or_mint(dir.path(), mediator)
        .expect("the stored identity loads");
    assert_eq!(
        identity.did, again.did,
        "a host's address must survive a restart"
    );

    // Pointed somewhere else, it refuses rather than advertising where it no longer listens.
    let moved = room_host::didcomm::HostIdentity::load_or_mint(
        dir.path(),
        "did:webvh:QmOther:webvh.example:mediator",
    )
    .expect_err("a stored identity names one mediator forever");
    assert!(
        moved.to_string().contains("advertises"),
        "and says which: {moved}"
    );
}
