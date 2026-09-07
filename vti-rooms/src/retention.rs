//! The epoch key chain: how a room stays readable across a membership change.
//!
//! # The problem this exists for
//!
//! A record is sealed under [`super::mls::RoomGroup::storage_key`], the MLS exporter for the
//! epoch current when it was written. Every membership change is a commit and every commit
//! advances the epoch, and MLS gives no way to derive an old epoch's exporter from a new one
//! — deliberately, because that is what makes removing a member mean something.
//!
//! Left there, adding one member makes every record already in the room unreadable to
//! *everyone*, the writer included. A room is a library, not a message stream: that is data
//! loss, not forward secrecy.
//!
//! # The chain
//!
//! At each commit the committer seals the outgoing epoch's storage key under the incoming
//! one, producing a [`EpochLink`]. The links form a chain a holder of the current key can
//! walk backwards:
//!
//! ```text
//!   epoch 4 key ──opens──▶ link(4) ──yields──▶ epoch 3 key
//!                                                  │
//!                                       ──opens──▶ link(3) ──yields──▶ epoch 2 key ...
//! ```
//!
//! Backwards only. A member holding epoch 2's key can derive nothing at epoch 3, so removal
//! stays forward-only and a removed member still reads nothing written after them.
//!
//! This is the upper tier of the retention system in the Encrypted Spaces architecture
//! whitepaper (§4.2, Orrù–Perrin–Trapp–Zaverucha, 2026) — "each rekey produces a new group
//! key that encrypts its predecessor" — reduced to the one shape our record model needs. We
//! have no directory hierarchy to align a lower tier to, so the chain is linear.
//!
//! # Cryptographic deletion
//!
//! Dropping link `K` severs the chain there: nobody who does not already hold a key below
//! `K` can ever reach one again, whatever the host still stores. That makes deleting records
//! before an epoch a *cryptographic* act rather than a promise by the host to erase bytes —
//! see [`super::storage::prune_epoch_links_before`].
//!
//! # What a host sees
//!
//! Ciphertext, and the fact that an epoch happened — which [`super::Room::epoch`] already
//! told it. The key that opens a link is the storage key of the epoch it names, and no host
//! ever holds one.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::RoomKeyError;
use crate::mls::STORAGE_KEY_LEN;
use crate::wire::EpochLink;

/// A storage key, as the chain passes them around.
pub type StorageKey = [u8; STORAGE_KEY_LEN];

/// `epoch-link|<epoch>|<epoch - 1>`, the associated data a link is bound to.
///
/// Binds a link to its position in the chain and to its direction. Without it a link lifted
/// from one rung would decrypt at another — every rung is a 32-byte key sealed under a
/// 32-byte key, so nothing about the ciphertext itself says where it belongs.
///
/// # Why the room is not in here, when it is in a record's binding
///
/// A record's associated data names its room ([`crate::sealed`]), and a reader comparing the
/// two will ask. The difference is what the key already separates: a record's key is shared
/// by every member of one room at one epoch, so a room identifier is what stops a host
/// re-filing one room's ciphertext under another. A *link* is sealed under a key derived
/// from one specific MLS group's exporter, and two rooms are two independent groups — so a
/// link served in the wrong room is being opened with an unrelated key and fails to decrypt
/// on its own. The binding would be belt-and-braces, and the cost is real: it would put a
/// room identifier into [`crate::mls::RoomGroup`], which deliberately does not know which
/// room it is for.
fn link_aad(epoch: u32) -> Vec<u8> {
    format!("epoch-link|{epoch}|{}", epoch.saturating_sub(1)).into_bytes()
}

/// Seal `predecessor` (epoch `epoch - 1`'s storage key) under `current` (epoch `epoch`'s).
///
/// Called at the moment of a commit, by the party making it — the only party holding both
/// keys at once.
pub fn seal_link(
    epoch: u32,
    current: &StorageKey,
    predecessor: &StorageKey,
) -> Result<EpochLink, RoomKeyError> {
    if epoch < 2 {
        // Epoch 1 is a room's first, and has no predecessor. A link claiming otherwise
        // would wrap something that is not an earlier epoch's key.
        return Err(RoomKeyError::Seal(format!(
            "epoch {epoch} has no predecessor to link to"
        )));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(current));
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).expect("OS randomness unavailable");

    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: predecessor.as_slice(),
                aad: &link_aad(epoch),
            },
        )
        .map_err(|e| RoomKeyError::Seal(format!("seal the epoch link: {e}")))?;

    Ok(EpochLink {
        epoch,
        wrapped: B64.encode(wrapped),
        nonce: B64.encode(nonce_bytes),
    })
}

/// Recover epoch `link.epoch - 1`'s storage key, given epoch `link.epoch`'s.
pub fn open_link(link: &EpochLink, current: &StorageKey) -> Result<StorageKey, RoomKeyError> {
    let wrapped = B64
        .decode(&link.wrapped)
        .map_err(|e| RoomKeyError::Seal(format!("decode the epoch link: {e}")))?;
    let nonce = B64
        .decode(&link.nonce)
        .map_err(|e| RoomKeyError::Seal(format!("decode the epoch link nonce: {e}")))?;
    if nonce.len() != 12 {
        return Err(RoomKeyError::Seal(format!(
            "epoch link nonce is {} bytes, expected 12",
            nonce.len()
        )));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(current));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &wrapped,
                aad: &link_aad(link.epoch),
            },
        )
        .map_err(|_| RoomKeyError::DidNotOpen)?;

    let key: StorageKey = plain
        .try_into()
        .map_err(|_| RoomKeyError::Seal("an epoch link did not wrap a storage key".into()))?;
    Ok(key)
}

/// The chain: the links, plus whatever keys have been walked out of them.
///
/// # The anchor is supplied, never stored
///
/// A chain cannot resolve anything until it is told the epoch its holder is at and that
/// epoch's key — [`EpochKeyChain::reanchor`], called from the group on every use. Holding an
/// anchor across a commit was the first design and it was wrong in a familiar way: the group
/// advanced, the stored anchor did not, and the chain silently answered from a key that was
/// no longer current. Deriving it fresh from the group each time makes the two impossible to
/// disagree.
///
/// Resolution is memoised, so opening a room's whole history walks each rung once rather
/// than once per record. Memoised keys survive re-anchoring: epoch 3's key is epoch 3's key
/// whatever epoch the group has since reached.
#[derive(Debug, Clone, Default)]
pub struct EpochKeyChain {
    anchor_epoch: u32,
    links: BTreeMap<u32, EpochLink>,
    resolved: BTreeMap<u32, StorageKey>,
}

impl EpochKeyChain {
    /// An empty chain: no links, no anchor, nothing resolvable until [`Self::reanchor`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the epoch this chain resolves *from*, and the key for it.
    ///
    /// Idempotent, and the caller is expected to do it on every use rather than once.
    pub fn reanchor(&mut self, epoch: u32, key: StorageKey) {
        self.resolved.insert(epoch, key);
        self.anchor_epoch = epoch;
    }

    /// Add the links a host or an owner served.
    ///
    /// Idempotent, and order-independent: a link is identified by the epoch it opens under,
    /// and the chain is walked on demand rather than on insert.
    pub fn add_links(&mut self, links: impl IntoIterator<Item = EpochLink>) {
        for link in links {
            self.links.insert(link.epoch, link);
        }
    }

    /// The epoch this chain's holder is at.
    pub fn anchor_epoch(&self) -> u32 {
        self.anchor_epoch
    }

    /// Every link this chain holds, ascending.
    ///
    /// What an owner serves to a joining member, and what a host stores. Links are
    /// ciphertext — handing them to a party who holds no epoch key gives them nothing, which
    /// is what lets a host keep them.
    pub fn links(&self) -> Vec<EpochLink> {
        self.links.values().cloned().collect()
    }

    /// The earliest epoch this chain can reach.
    pub fn earliest_reachable(&mut self) -> u32 {
        let mut epoch = self.anchor_epoch;
        while epoch > 1 && self.key_for(epoch - 1).is_ok() {
            epoch -= 1;
        }
        epoch
    }

    /// The storage key for `epoch`, walking the chain if it is not already resolved.
    ///
    /// Fails with [`RoomKeyError::EpochUnreachable`] when a link is missing — which is a
    /// different thing from a record that does not open, and says so: the record is intact
    /// and the key to it has been severed or was never delivered.
    pub fn key_for(&mut self, epoch: u32) -> Result<StorageKey, RoomKeyError> {
        if let Some(key) = self.resolved.get(&epoch) {
            return Ok(*key);
        }
        if epoch > self.anchor_epoch {
            // Ahead of us, not behind: the caller is missing a commit, not a link.
            return Err(RoomKeyError::EpochAhead {
                sealed: epoch,
                held: self.anchor_epoch,
            });
        }

        // Walk down from the lowest epoch we have already resolved that is above the target.
        let mut cursor = *self.resolved.range(epoch..).next().map(|(e, _)| e).ok_or(
            RoomKeyError::EpochUnreachable {
                sealed: epoch,
                earliest: epoch,
            },
        )?;

        while cursor > epoch {
            let key = *self
                .resolved
                .get(&cursor)
                .expect("the cursor only ever names a resolved epoch");
            let link = self
                .links
                .get(&cursor)
                .ok_or(RoomKeyError::EpochUnreachable {
                    sealed: epoch,
                    earliest: cursor,
                })?;
            let previous = open_link(link, &key)?;
            cursor -= 1;
            self.resolved.insert(cursor, previous);
        }

        Ok(*self
            .resolved
            .get(&epoch)
            .expect("the walk ends with the target resolved"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> StorageKey {
        [seed; STORAGE_KEY_LEN]
    }

    #[test]
    fn a_link_round_trips() {
        let current = key(2);
        let previous = key(1);
        let link = seal_link(2, &current, &previous).expect("seal");
        assert_eq!(open_link(&link, &current).expect("open"), previous);
    }

    /// A link is 32 sealed bytes like every other link. Only the binding says which rung it
    /// belongs to, so only the binding can refuse a lift.
    #[test]
    fn a_link_lifted_to_another_rung_does_not_open() {
        let current = key(2);
        let link = seal_link(2, &current, &key(1)).expect("seal");

        let mut moved = link.clone();
        moved.epoch = 3;
        assert!(
            open_link(&moved, &current).is_err(),
            "relabelling a link's epoch must fail authentication"
        );
    }

    #[test]
    fn the_wrong_key_does_not_open_a_link() {
        let link = seal_link(2, &key(2), &key(1)).expect("seal");
        assert!(open_link(&link, &key(9)).is_err());
    }

    #[test]
    fn the_first_epoch_has_no_predecessor() {
        assert!(seal_link(1, &key(1), &key(0)).is_err());
        assert!(seal_link(0, &key(1), &key(0)).is_err());
    }

    /// The property the whole module exists for.
    #[test]
    fn a_chain_walks_back_to_the_first_epoch() {
        let keys: Vec<StorageKey> = (1..=5).map(key).collect();
        let links: Vec<EpochLink> = (2..=5)
            .map(|e| seal_link(e, &keys[(e - 1) as usize], &keys[(e - 2) as usize]).expect("seal"))
            .collect();

        let mut chain = EpochKeyChain::new();
        chain.reanchor(5, keys[4]);
        chain.add_links(links);

        for epoch in 1..=5u32 {
            assert_eq!(
                chain.key_for(epoch).expect("every retained epoch resolves"),
                keys[(epoch - 1) as usize],
                "epoch {epoch} must resolve to the key it was sealed with"
            );
        }
        assert_eq!(chain.earliest_reachable(), 1);
    }

    /// Severing a rung is what cryptographic deletion *is*.
    #[test]
    fn a_severed_chain_reaches_no_further() {
        let keys: Vec<StorageKey> = (1..=4).map(key).collect();
        let links: Vec<EpochLink> = [3u32, 4]
            .iter()
            .map(|&e| seal_link(e, &keys[(e - 1) as usize], &keys[(e - 2) as usize]).expect("seal"))
            .collect();

        // link(2) is absent: everything below epoch 2 has been cryptographically deleted.
        let mut chain = EpochKeyChain::new();
        chain.reanchor(4, keys[3]);
        chain.add_links(links);

        assert_eq!(chain.key_for(2).expect("epoch 2 is retained"), keys[1]);
        assert!(
            matches!(chain.key_for(1), Err(RoomKeyError::EpochUnreachable { .. })),
            "a severed epoch must be unreachable, and say so as unreachable"
        );
        assert_eq!(chain.earliest_reachable(), 2);
    }

    /// Behind is not the same as severed, and the error must not say it is.
    #[test]
    fn an_epoch_ahead_is_reported_as_ahead() {
        let mut chain = EpochKeyChain::new();
        chain.reanchor(2, key(2));
        assert!(matches!(
            chain.key_for(5),
            Err(RoomKeyError::EpochAhead { sealed: 5, held: 2 })
        ));
    }

    #[test]
    fn re_anchoring_commit_by_commit_keeps_everything_below_reachable() {
        let mut chain = EpochKeyChain::new();
        chain.reanchor(1, key(1));
        for epoch in 2..=4u32 {
            let link = seal_link(epoch, &key(epoch as u8), &key((epoch - 1) as u8)).expect("seal");
            chain.add_links(Some(link));
            chain.reanchor(epoch, key(epoch as u8));
        }

        assert_eq!(chain.anchor_epoch(), 4);
        for epoch in 1..=4u32 {
            assert_eq!(chain.key_for(epoch).expect("resolves"), key(epoch as u8));
        }
        assert_eq!(chain.earliest_reachable(), 1);
    }

    /// Re-anchoring twice at the same epoch changes nothing, and a key already walked out
    /// stays walked out — the anchor is where resolution *starts*, not a rollback point.
    #[test]
    fn re_anchoring_is_idempotent() {
        let link = seal_link(2, &key(2), &key(1)).expect("seal");
        let mut chain = EpochKeyChain::new();
        chain.add_links(Some(link));

        chain.reanchor(2, key(2));
        assert_eq!(chain.key_for(1).expect("walks back"), key(1));
        chain.reanchor(2, key(2));
        assert_eq!(chain.key_for(1).expect("still resolves"), key(1));
    }

    /// Advancing without a link produces nothing new, and hands on nothing.
    ///
    /// In-session it does *not* forget what was already derived, and should not pretend to:
    /// a member who could read epoch 1 a moment ago still holds that key in memory, and
    /// dropping it from a map buys no secrecy against anyone. What an unlinked advance
    /// actually means is that the chain has nothing to give — [`EpochKeyChain::links`]
    /// returns nothing, so a member restoring their group state, or a member joining, gets
    /// the anchor and no history.
    #[test]
    fn advancing_without_a_link_hands_on_no_history() {
        let mut chain = EpochKeyChain::new();
        chain.reanchor(1, key(1));
        chain.reanchor(2, key(2)); // a commit arrived, and carried no link

        assert_eq!(chain.key_for(2).expect("the anchor resolves"), key(2));
        assert!(
            chain.links().is_empty(),
            "an unlinked advance must leave nothing to hand on"
        );

        // The state anyone else — or this member after a restart — actually receives.
        let mut rebuilt = EpochKeyChain::new();
        rebuilt.reanchor(2, key(2));
        rebuilt.add_links(chain.links());
        assert!(matches!(
            rebuilt.key_for(1),
            Err(RoomKeyError::EpochUnreachable { .. })
        ));
        assert_eq!(rebuilt.earliest_reachable(), 2);
    }
}
