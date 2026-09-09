//! The record commitment: a Merkle tree over a room's records.
//!
//! # What this is for
//!
//! A room's records are signed and room-bound, so a host cannot forge one,
//! alter one, or move it between rooms. **Silence is free**:
//! `rooms/records/list` returns a set and nothing says the set is complete, so a
//! host serving nine records from a room holding ten is indistinguishable from a
//! room holding nine. See `docs/05-design-notes/data-rooms-verified-reads.md`.
//!
//! This is the structure that closes it. The root is the room's **data
//! commitment**: a host that signs one and then serves a listing which does not
//! reconcile with it is caught by arithmetic rather than by suspicion.
//!
//! # Sorted, because completeness is a range property
//!
//! Leaves are ordered by record key, which is what makes *absence* provable. An
//! inclusion proof says "this record is here"; only the ordering lets a
//! consumer say "and there is nothing between these two keys". A tree over
//! unsorted leaves can prove everything it contains and nothing about what it
//! omits — which is the property being bought.
//!
//! # A leaf commits to the whole record
//!
//! Not to the body, and not to a chosen subset. A host that could flip `status`
//! from active to retracted, or move `pinned`, or rewrite `author` on an
//! attributed room, is a host that can rewrite the room's meaning without
//! touching a byte of ciphertext. Picking fields invites picking wrongly, so the
//! leaf commits to the record's canonical JSON (RFC 8785) — every member,
//! present or absent, in an order no refactor can change.
//!
//! **The plaintext is never involved.** On the sealed tiers the host holds
//! ciphertext and could not commit to a body if it wanted to; the leaf commits
//! to the ciphertext it stores, which is exactly what it is accountable for.
//!
//! # Domain separation, from RFC 6962
//!
//! Leaf hashes are prefixed `0x00` and internal nodes `0x01`, as Certificate
//! Transparency does. Without it an internal node's preimage can be presented as
//! a leaf, and a proof for one thing verifies for another — the second-preimage
//! attack every Merkle tree specification names first.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Record;

/// Prefix for a leaf hash (RFC 6962 §2.1).
const LEAF_PREFIX: u8 = 0x00;
/// Prefix for an internal node hash (RFC 6962 §2.1).
const NODE_PREFIX: u8 = 0x01;

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// Errors this module can produce.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    /// A record would not canonicalise — it holds something JSON cannot express.
    #[error("record `{key}` could not be canonicalised for commitment: {source}")]
    Canonicalise {
        key: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Hash one record into a leaf.
///
/// Canonical JSON per RFC 8785, so the leaf commits to what the record *means*
/// rather than to one serialiser's field order. A field added to [`Record`]
/// later is committed automatically, which is the point of not enumerating.
pub fn leaf_hash(record: &Record) -> Result<Hash, MerkleError> {
    let canonical =
        serde_json_canonicalizer::to_vec(record).map_err(|source| MerkleError::Canonicalise {
            key: record.key.clone(),
            source,
        })?;
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

/// Hash two child nodes into their parent.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The commitment for an **empty** room.
///
/// `SHA-256("")`, following RFC 6962 §2.1. A distinguished value rather than
/// zeroes: a root of all-zeroes is what an uninitialised buffer looks like, and
/// a room with no records is a real state a host must be able to commit to
/// honestly.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::new().finalize().into()
}

/// The data commitment over `records`.
///
/// `records` **MUST** be ordered by key — [`commit_records`] does that for the
/// caller, and this takes the ordered leaves so a caller that already has them
/// need not rebuild.
///
/// An odd node at any level is promoted unchanged rather than duplicated. RFC
/// 6962 does the same, and the reason is not aesthetics: duplicating the last
/// node makes a tree of `n` leaves collide with one of `n+1` where the last is
/// repeated, so two different rooms commit to the same root.
#[must_use]
pub fn root_of(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut pairs = level.chunks_exact(2);
        for pair in &mut pairs {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        // The promoted odd node — never duplicated, see above.
        if let [odd] = pairs.remainder() {
            next.push(*odd);
        }
        level = next;
    }
    level[0]
}

/// Sort `records` by key, hash them, and return the data commitment.
///
/// The sort is here rather than assumed of the caller because the ordering *is*
/// the completeness property: a root computed over records in storage order
/// proves membership and nothing about absence.
pub fn commit_records(records: &mut [Record]) -> Result<Hash, MerkleError> {
    records.sort_by(|a, b| a.key.cmp(&b.key));
    let leaves = records
        .iter()
        .map(leaf_hash)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(root_of(&leaves))
}

/// One step of an inclusion proof: a sibling and which side it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofStep {
    /// The sibling hash, hex-encoded on the wire.
    #[serde(with = "hex_hash")]
    pub sibling: Hash,
    /// Whether the sibling is the **left** child; the proven node is the other.
    pub sibling_is_left: bool,
}

/// The path from a leaf to the root.
pub type InclusionProof = Vec<ProofStep>;

/// Build the inclusion proof for the leaf at `index`.
///
/// Returns `None` for an index outside the tree, which is a caller bug rather
/// than a proof that fails to verify — the two should not be confused.
#[must_use]
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        // An odd node at the end is promoted with no sibling, so it contributes
        // no step — mirroring `root_of`, and the reason the two must be read
        // together when either changes.
        let has_sibling = !(idx == level.len() - 1 && level.len() % 2 == 1);
        if has_sibling {
            let sibling_is_left = idx % 2 == 1;
            let sibling_idx = if sibling_is_left { idx - 1 } else { idx + 1 };
            proof.push(ProofStep {
                sibling: level[sibling_idx],
                sibling_is_left,
            });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut pairs = level.chunks_exact(2);
        for pair in &mut pairs {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        if let [odd] = pairs.remainder() {
            next.push(*odd);
        }
        level = next;
        idx /= 2;
    }
    Some(proof)
}

/// Replay `proof` from `leaf` and report whether it reaches `root`.
///
/// This is the whole of what a consumer runs, and it needs nothing but hashing —
/// no tree, no host, no network.
#[must_use]
pub fn verify_inclusion(root: &Hash, leaf: &Hash, proof: &InclusionProof) -> bool {
    let mut current = *leaf;
    for step in proof {
        current = if step.sibling_is_left {
            node_hash(&step.sibling, &current)
        } else {
            node_hash(&current, &step.sibling)
        };
    }
    &current == root
}

/// Hex for the wire, because a commitment travels in JSON and bytes do not.
mod hex_hash {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &Hash, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = unhex(&text).ok_or_else(|| D::Error::custom("not a 32-byte hex digest"))?;
        Ok(bytes)
    }

    fn hex(bytes: &Hash) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Option<Hash> {
        if text.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(out)
    }
}

/// Hex-encode a commitment for the wire.
#[must_use]
pub fn to_hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordStatus;

    fn record(key: &str, version: u64) -> Record {
        Record {
            key: key.to_string(),
            version,
            epoch: Some(3),
            status: RecordStatus::Active,
            pinned: false,
            sealed: Some("Zm9v".into()),
            nonce: Some("YmFy".into()),
            cleartext: None,
            author: None,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn an_empty_room_commits_to_a_distinguished_value() {
        assert_eq!(root_of(&[]), empty_root());
        // Not zeroes — an uninitialised buffer must not read as a valid root.
        assert_ne!(empty_root(), [0u8; 32]);
    }

    /// The property the whole structure exists for: omit a record and the root
    /// moves. Without this the commitment is decoration.
    #[test]
    fn omitting_a_record_changes_the_commitment() {
        let mut all = vec![record("a", 1), record("b", 2), record("c", 3)];
        let mut fewer = vec![record("a", 1), record("c", 3)];

        let full = commit_records(&mut all).expect("commits");
        let short = commit_records(&mut fewer).expect("commits");
        assert_ne!(
            full, short,
            "a host could drop a record without moving the root"
        );
    }

    /// A host must not be able to rewrite a record's *standing* — flipping
    /// active to retracted rewrites what the room means without touching a byte
    /// of ciphertext.
    #[test]
    fn changing_any_field_changes_the_commitment() {
        let base = record("a", 1);
        let mut cases = vec![
            (
                "version",
                Record {
                    version: 2,
                    ..base.clone()
                },
            ),
            (
                "status",
                Record {
                    status: RecordStatus::Retracted,
                    ..base.clone()
                },
            ),
            (
                "pinned",
                Record {
                    pinned: true,
                    ..base.clone()
                },
            ),
            (
                "epoch",
                Record {
                    epoch: Some(4),
                    ..base.clone()
                },
            ),
            (
                "author",
                Record {
                    author: Some("did:example:someone".into()),
                    ..base.clone()
                },
            ),
            (
                "ciphertext",
                Record {
                    sealed: Some("YmF6".into()),
                    ..base.clone()
                },
            ),
            (
                "updated_at",
                Record {
                    updated_at: 1_700_000_001,
                    ..base.clone()
                },
            ),
        ];
        let original = leaf_hash(&base).expect("hashes");
        for (what, altered) in &mut cases {
            assert_ne!(
                leaf_hash(altered).expect("hashes"),
                original,
                "a host could change `{what}` without moving the leaf"
            );
        }
    }

    /// Ordering is what makes absence provable, so the commitment must not
    /// depend on the order records happened to be read in.
    #[test]
    fn the_commitment_does_not_depend_on_input_order() {
        let mut forwards = vec![record("a", 1), record("b", 2), record("c", 3)];
        let mut backwards = vec![record("c", 3), record("b", 2), record("a", 1)];
        assert_eq!(
            commit_records(&mut forwards).expect("commits"),
            commit_records(&mut backwards).expect("commits"),
        );
    }

    /// The second-preimage defence. Without RFC 6962's prefixes an internal
    /// node's preimage can be offered as a leaf.
    #[test]
    fn a_leaf_and_a_node_over_the_same_bytes_differ() {
        let a = leaf_hash(&record("a", 1)).expect("hashes");
        let b = leaf_hash(&record("b", 2)).expect("hashes");
        let parent = node_hash(&a, &b);

        let mut undomained = Sha256::new();
        undomained.update(a);
        undomained.update(b);
        let raw: Hash = undomained.finalize().into();
        assert_ne!(parent, raw, "internal nodes are not domain-separated");
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        for count in 1..=9usize {
            let mut records: Vec<Record> = (0..count)
                .map(|i| record(&format!("k{i:02}"), i as u64))
                .collect();
            let root = commit_records(&mut records).expect("commits");
            let leaves: Vec<Hash> = records
                .iter()
                .map(|r| leaf_hash(r).expect("hashes"))
                .collect();

            for (i, leaf) in leaves.iter().enumerate() {
                let proof = inclusion_proof(&leaves, i)
                    .unwrap_or_else(|| panic!("proof for {i} of {count}"));
                assert!(
                    verify_inclusion(&root, leaf, &proof),
                    "leaf {i} of {count} did not prove"
                );
            }
        }
    }

    /// Odd counts are where a promoted node lives, and where `root_of` and
    /// `inclusion_proof` must agree with each other. They are written as two
    /// functions and would drift silently.
    #[test]
    fn a_proof_for_a_record_not_in_the_tree_fails() {
        let mut records = vec![record("a", 1), record("b", 2), record("c", 3)];
        let root = commit_records(&mut records).expect("commits");
        let leaves: Vec<Hash> = records
            .iter()
            .map(|r| leaf_hash(r).expect("hashes"))
            .collect();
        let proof = inclusion_proof(&leaves, 0).expect("proof");

        let outsider = leaf_hash(&record("zzz", 99)).expect("hashes");
        assert!(
            !verify_inclusion(&root, &outsider, &proof),
            "a record the room does not hold proved against its root"
        );
    }

    #[test]
    fn a_tampered_proof_step_fails() {
        let mut records = vec![
            record("a", 1),
            record("b", 2),
            record("c", 3),
            record("d", 4),
        ];
        let root = commit_records(&mut records).expect("commits");
        let leaves: Vec<Hash> = records
            .iter()
            .map(|r| leaf_hash(r).expect("hashes"))
            .collect();
        let mut proof = inclusion_proof(&leaves, 1).expect("proof");

        proof[0].sibling[0] ^= 0xff;
        assert!(!verify_inclusion(&root, &leaves[1], &proof));

        let mut flipped = inclusion_proof(&leaves, 1).expect("proof");
        flipped[0].sibling_is_left = !flipped[0].sibling_is_left;
        assert!(
            !verify_inclusion(&root, &leaves[1], &flipped),
            "the side a sibling sits on is part of the proof"
        );
    }

    #[test]
    fn an_index_outside_the_tree_has_no_proof() {
        let leaves = [leaf_hash(&record("a", 1)).expect("hashes")];
        assert!(inclusion_proof(&leaves, 1).is_none());
        assert!(inclusion_proof(&[], 0).is_none());
    }

    #[test]
    fn a_step_round_trips_through_json() {
        let leaves: Vec<Hash> = ["a", "b", "c"]
            .iter()
            .map(|k| leaf_hash(&record(k, 1)).expect("hashes"))
            .collect();
        let proof = inclusion_proof(&leaves, 0).expect("proof");
        let json = serde_json::to_string(&proof).expect("serialises");
        let back: InclusionProof = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(proof, back);
    }
}
