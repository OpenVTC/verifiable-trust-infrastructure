//! Sealing and opening records on the `attributed` and `private` tiers.
//!
//! This is where the MLS group layer and the room's task surface meet: a record is sealed
//! under the key [`super::mls::RoomGroup::storage_key`] derives for the current epoch, and
//! the host stores ciphertext it cannot read.
//!
//! # The binding is the interesting part
//!
//! Each record's AEAD associated data commits to `roomId | key | version | epoch`. A host
//! that relocates a sealed record — to another key, another version, another epoch, or
//! another room — produces an authentication failure rather than a readable record. It holds
//! every byte and still cannot move one, which is the property that makes an untrusted host
//! tolerable.
//!
//! This is the same class of defence `vti_common::store::encryption` already applies to
//! keyspace values by binding them to their `(keyspace, key)` location. Repeating it here is
//! deliberate: the reasoning was paid for once and should not have to be rediscovered.
//!
//! # Version is bound before it is known
//!
//! A record's version is assigned by the host, from the room's counter — so a writer does
//! not know it at sealing time. [`SealedRoom::seal_record`] therefore takes the version the
//! writer *intends*, and a caller that lets the host assign a different one will find the
//! record does not open. That is the correct failure: silently accepting whatever version
//! came back would mean the binding commits to nothing.
//!
//! The practical shape is create-only writes (`expected_version: Some(0)`) or a read of the
//! current version before a rewrite — both of which the task surface already supports.
//!
//! # What is deliberately not sealed
//!
//! The record's key, version and epoch travel in the clear: the host needs them to store and
//! serve the right ciphertext. Keys must therefore be **opaque** on these tiers — a key
//! reading `decision/acquire-northwind` defeats the encryption sitting beside it.
//! [`SealedRoom::opaque_key`] mints one.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::RoomKeyError;
use crate::mls::RoomGroup;
use crate::wire::SealedContent;

/// A room whose records are sealed, and the group state that seals them.
///
/// Holds the room's identifier and its [`RoomGroup`] — nothing about *credentials*. That
/// separation is deliberate and it is the reason this type moved out of the client: the
/// credentials a caller presents travel to the host on every request, and the keys never
/// travel anywhere. Pairing them in one struct made a client the only place a room could be
/// opened, which is wrong the moment a VTA has to open one on an agent's behalf.
///
/// The identifier is here because it is bound into every record's associated data, not
/// because this type does anything with it.
pub struct SealedRoom {
    room_id: String,
    group: RoomGroup,
}

impl SealedRoom {
    /// Pair a room identifier with its group.
    pub fn new(room_id: impl Into<String>, group: RoomGroup) -> Self {
        Self {
            room_id: room_id.into(),
            group,
        }
    }

    /// The room these keys are for.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// The group, for membership changes and epoch anchoring.
    pub fn group(&self) -> &RoomGroup {
        &self.group
    }

    /// Mutable access, for committing a membership change.
    pub fn group_mut(&mut self) -> &mut RoomGroup {
        &mut self.group
    }

    /// The room's current epoch, as the host records it.
    ///
    /// MLS epochs start at 0 and the room's start at 1, so this is the MLS epoch plus one.
    /// Kept in one place rather than at each call site: an off-by-one here would seal
    /// records under an epoch the host rejects, and the failure would look like a key
    /// problem rather than an arithmetic one.
    pub fn room_epoch(&self) -> u32 {
        (self.group.epoch() + 1) as u32
    }

    /// A random, opaque record key.
    ///
    /// Sealed tiers require these: a descriptive key is readable by the host and defeats the
    /// encryption beside it. Structured naming belongs *inside* the sealed body.
    pub fn opaque_key() -> String {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        B64.encode(bytes)
    }

    /// Seal `plaintext` for `key` at `version`.
    ///
    /// `version` is the version the writer intends the record to take — see the module docs
    /// on why it is bound before the host assigns it.
    pub fn seal_record(
        &self,
        key: &str,
        version: u64,
        plaintext: &[u8],
    ) -> Result<SealedContent, RoomKeyError> {
        let epoch = self.room_epoch();
        let storage_key = self.group.storage_key()?;
        let aad = associated_data(&self.room_id, key, version, epoch);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&storage_key));
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).expect("OS randomness unavailable");

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| RoomKeyError::Seal(format!("seal record: {e}")))?;

        Ok(SealedContent {
            ciphertext: B64.encode(ciphertext),
            nonce: B64.encode(nonce_bytes),
            epoch,
        })
    }

    /// Open a record the host returned.
    ///
    /// Fails rather than returning wrong bytes if the record was relocated, if the epoch was
    /// relabelled, or if the key for that epoch is not the one this member holds.
    pub fn open_record(
        &self,
        key: &str,
        version: u64,
        sealed: &SealedContent,
    ) -> Result<Vec<u8>, RoomKeyError> {
        let storage_key = self.group.storage_key()?;
        let aad = associated_data(&self.room_id, key, version, sealed.epoch);

        let ciphertext = B64
            .decode(&sealed.ciphertext)
            .map_err(|e| RoomKeyError::Seal(format!("decode ciphertext: {e}")))?;
        let nonce = B64
            .decode(&sealed.nonce)
            .map_err(|e| RoomKeyError::Seal(format!("decode nonce: {e}")))?;
        if nonce.len() != 12 {
            return Err(RoomKeyError::Seal(format!(
                "nonce is {} bytes, expected 12",
                nonce.len()
            )));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&storage_key));
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RoomKeyError::DidNotOpen)
    }

    /// The value to anchor in the room's witnessed DID log for this epoch.
    ///
    /// A host that forks the group shows different members different commit sequences.
    /// Comparing this against the anchored value is how a member finds out.
    pub fn epoch_anchor(&self) -> Vec<u8> {
        self.group.epoch_authenticator()
    }
}

/// `roomId | key | version | epoch`, the associated data a record is bound to.
///
/// Length-prefix-free but unambiguous by construction: `|` cannot appear in a base64url key
/// or in the decimal fields, and `roomId` is a DID. If any of those ever stops holding, this
/// needs length prefixes — the failure mode otherwise is two different records producing the
/// same associated data, which is exactly what the binding exists to prevent.
fn associated_data(room_id: &str, key: &str, version: u64, epoch: u32) -> Vec<u8> {
    format!("{room_id}|{key}|{version}|{epoch}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(did: &str) -> SealedRoom {
        let group = RoomGroup::create("did:key:zAlice").expect("group");
        SealedRoom::new(did, group)
    }

    #[test]
    fn a_record_round_trips_under_the_group_key() {
        let r = room("did:webvh:zRoom");
        let sealed = r.seal_record("k1", 1, b"a decision").expect("seal");
        let opened = r.open_record("k1", 1, &sealed).expect("open");
        assert_eq!(opened, b"a decision");
    }

    /// The property that makes an untrusted host tolerable: it holds every byte and still
    /// cannot move one.
    #[test]
    fn a_relocated_record_does_not_open() {
        let r = room("did:webvh:zRoom");
        let sealed = r.seal_record("k1", 1, b"a decision").expect("seal");

        assert!(
            r.open_record("k2", 1, &sealed).is_err(),
            "moving a record to another key must fail"
        );
        assert!(
            r.open_record("k1", 2, &sealed).is_err(),
            "moving it to another version must fail"
        );

        let mut relabelled = sealed.clone();
        relabelled.epoch += 1;
        assert!(
            r.open_record("k1", 1, &relabelled).is_err(),
            "relabelling the epoch must fail authentication, not decrypt wrongly"
        );

        let moved = SealedRoom::new(
            "did:webvh:zOther",
            RoomGroup::create("did:key:zAlice").unwrap(),
        );
        assert!(
            moved.open_record("k1", 1, &sealed).is_err(),
            "moving it to another room must fail"
        );
    }

    #[test]
    fn a_non_member_cannot_open_a_record() {
        let r = room("did:webvh:zRoom");
        let sealed = r.seal_record("k1", 1, b"members only").expect("seal");

        // A different group is a different key, however identical everything else looks.
        let outsider = SealedRoom::new(
            "did:webvh:zRoom",
            RoomGroup::create("did:key:zMallory").unwrap(),
        );
        assert!(outsider.open_record("k1", 1, &sealed).is_err());
    }

    #[test]
    fn the_room_epoch_is_the_mls_epoch_plus_one() {
        let r = room("did:webvh:zRoom");
        assert_eq!(r.group().epoch(), 0, "MLS starts at 0");
        assert_eq!(r.room_epoch(), 1, "the room's first epoch is 1");
    }

    #[test]
    fn opaque_keys_are_random_and_carry_no_meaning() {
        let a = SealedRoom::opaque_key();
        let b = SealedRoom::opaque_key();
        assert_ne!(a, b);
        assert!(
            !a.contains('/'),
            "url-safe, so it needs no escaping in a payload"
        );
    }

    /// Sealing twice must not reuse a nonce, or the AEAD's guarantee is gone.
    #[test]
    fn sealing_the_same_plaintext_twice_uses_a_fresh_nonce() {
        let r = room("did:webvh:zRoom");
        let a = r.seal_record("k1", 1, b"same").expect("seal");
        let b = r.seal_record("k1", 1, b"same").expect("seal again");
        assert_ne!(a.nonce, b.nonce, "a reused nonce breaks ChaCha20-Poly1305");
        assert_ne!(a.ciphertext, b.ciphertext);
        // Both still open.
        assert_eq!(r.open_record("k1", 1, &a).unwrap(), b"same");
        assert_eq!(r.open_record("k1", 1, &b).unwrap(), b"same");
    }
}
