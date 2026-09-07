//! A room stays readable across a membership change.
//!
//! The regression these guard is that it did not. Records are sealed under the MLS exporter
//! for the epoch current when they were written, and `open_record` used the group's
//! *current* key — so the first add or remove made every record already in the room fail to
//! open, for every member including the one who wrote it. Every test in the crate sealed and
//! opened inside one epoch, so nothing caught it.
//!
//! Three directions, and all three have to hold together:
//!   1. an existing member reading their own record across a commit;
//!   2. a member added at epoch N reading a record sealed at epoch N-1;
//!   3. a *removed* member still unable to read what came after them.
//!
//! (3) is what stops (1) and (2) from being fixed the easy and wrong way. A chain that ran
//! forwards as well as backwards would satisfy the first two and quietly undo removal.
#![cfg(feature = "mls")]

use vti_rooms::mls::{IdentitySnapshot, RoomGroup};
use vti_rooms::sealed::SealedRoom;

const ROOM: &str = "did:webvh:zRoom";

/// Direction 1: the writer themself, across a commit they made.
#[test]
fn a_record_survives_a_membership_change_for_the_writer() {
    let mut alice = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").expect("group"));

    let sealed = alice.seal_record("k1", 1, b"the library").expect("seal");
    assert_eq!(
        alice.open_record("k1", 1, &sealed).expect("open at once"),
        b"the library",
        "sanity: it opens in the epoch it was sealed in"
    );

    // Add Bob. Every membership change is a commit, and every commit advances the epoch.
    let (_bob_snapshot, bob_kp) = IdentitySnapshot::mint("did:key:zBob").expect("mint bob");
    alice.add_member(&bob_kp).expect("add bob");

    let opened = alice
        .open_record("k1", 1, &sealed)
        .expect("a record written before the change must still open for its writer");
    assert_eq!(opened, b"the library");
}

/// Direction 2: a member added at epoch N reading what was there before them.
#[test]
fn a_new_member_can_read_what_was_already_in_the_room() {
    let mut alice = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").expect("group"));

    let sealed = alice.seal_record("k1", 1, b"the library").expect("seal");

    let (bob_snapshot, bob_kp) = IdentitySnapshot::mint("did:key:zBob").expect("mint bob");
    let change = alice.add_member(&bob_kp).expect("add bob");
    let welcome = change.welcome.expect("an add produces a welcome");

    let mut bob = SealedRoom::new(
        ROOM,
        RoomGroup::join_from_identity(&bob_snapshot, &welcome).expect("bob joins"),
    );

    // The Welcome carries epoch 2's key and nothing below it. Backfill is the links
    // travelling — from the owner, or from the host that holds them on the room's behalf.
    assert!(
        bob.open_record("k1", 1, &sealed).is_err(),
        "without the links a joiner reads only from their own epoch"
    );

    bob.add_links(alice.links());

    let opened = bob
        .open_record("k1", 1, &sealed)
        .expect("a member joining a room must be able to read the room");
    assert_eq!(opened, b"the library");
    assert_eq!(bob.earliest_readable_epoch().expect("chain resolves"), 1);
}

/// The other half of the trade: reading back is not reading forward.
#[test]
fn a_removed_member_still_cannot_read_what_came_after() {
    let mut alice = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").expect("group"));

    let (bob_snapshot, bob_kp) = IdentitySnapshot::mint("did:key:zBob").expect("mint bob");
    let change = alice.add_member(&bob_kp).expect("add bob");
    let mut bob = SealedRoom::new(
        ROOM,
        RoomGroup::join_from_identity(&bob_snapshot, &change.welcome.expect("welcome"))
            .expect("bob joins"),
    );
    bob.add_links(alice.links());

    let leaf = alice
        .group()
        .leaf_of("did:key:zBob")
        .expect("bob is a member");
    alice.remove_member(leaf).expect("remove bob");

    // Written after Bob was removed, under the epoch his key cannot reach.
    let after = alice.seal_record("k2", 2, b"after bob").expect("seal");

    assert!(
        bob.open_record("k2", 2, &after).is_err(),
        "the chain runs backwards only: removal must stay forward-only"
    );
}
