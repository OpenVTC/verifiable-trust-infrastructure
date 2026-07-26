//! Signed audit checkpoints — tamper-evidence against a *store-level*
//! adversary.
//!
//! # What the hash chain does not solve
//!
//! [`super::envelope::verify_chain`] detects reordering, dropping,
//! duplication, and content edits. It does not detect a competent
//! adversary, because [`super::AuditEnvelope::chain_digest`] is an
//! **unkeyed** SHA-256: anyone who can write to the `audit` keyspace holds
//! everything needed to recompute it. Two attacks follow directly.
//!
//! 1. **Restamping.** Edit or insert an envelope, recompute its `entry_hash`,
//!    then walk forward restamping every successor. The result verifies
//!    cleanly. O(entries after the edit), no secret required.
//! 2. **Truncation.** Delete everything after some point. The remaining
//!    prefix is a *valid chain*, and nothing records how long the log should
//!    be — so a truncated log is indistinguishable from a community that went
//!    quiet.
//!
//! Truncation is the cheaper attack and the more serious one: it erases an
//! incident with no forgery at all.
//!
//! The actor/target HMAC does not help. It protects attribution (and enables
//! RTBF via key rotation), not sequence integrity — and the writer holds that
//! key anyway.
//!
//! # What a checkpoint adds
//!
//! A periodically-persisted, **signed** commitment to the chain head *and the
//! number of entries behind it*. [`AuditCheckpoint::entry_count`] is the
//! load-bearing field: a log shorter than a signed checkpoint claims is
//! truncation, and that check cannot be spoofed without the signing key.
//!
//! # Why the community Ed25519 key, not the audit HMAC key
//!
//! | | Audit HMAC key | Community Ed25519 key |
//! |---|---|---|
//! | Verifiable by | the daemon only | anyone with the community DID |
//! | Forgeable by a store-adversary | **yes** — it is in the same store | no |
//!
//! The HMAC key is rejected on both counts: it lives in the very store the
//! adversary is assumed to have reached, and symmetric verification means
//! whoever can *check* a checkpoint can also *forge* one — which reduces to
//! the status quo. Signing with the community key instead makes checkpoints
//! **externally** verifiable: an auditor holding only the community DID can
//! confirm the log has not been rewritten, with no shared secret and no daemon
//! access.
//!
//! Consequence accepted: verification depends on the community DID resolving,
//! and on key rotation being handled — a checkpoint signed under a retired key
//! must stay verifiable, which the `did:webvh` document history already
//! provides. [`AuditCheckpoint::verification_method`] records which key signed.
//!
//! # What this still does not protect against
//!
//! An adversary who *also* holds the community signing key. Closing that needs
//! the head published somewhere append-only (the community's own `did.jsonl`,
//! a transparency log, a peer VTC). Out of scope — the signature is the
//! prerequisite. See `docs/05-design-notes/vtc-audit-checkpoints.md`.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::envelope::{GENESIS_HASH, hash32_b64, hash32_opt_b64};

/// Domain separator for the bytes a checkpoint signature covers.
///
/// Distinct from the envelope chain's `vtc-audit-chain/v1\0` so a signature
/// over one can never be replayed as a signature over the other.
const CHECKPOINT_DOMAIN: &[u8] = b"vtc-audit-checkpoint/v1\0";

/// Domain separator for a checkpoint's *own* hash — the value the next
/// checkpoint's [`AuditCheckpoint::prev_checkpoint`] points at.
const CHECKPOINT_LINK_DOMAIN: &[u8] = b"vtc-audit-checkpoint-link/v1\0";

/// A signed commitment to the audit chain's state at a point in time.
///
/// Stored in the `audit_checkpoint` keyspace keyed by `<rfc3339>:<uuid>`,
/// matching the audit keyspace's convention so an ascending walk is
/// chronological.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditCheckpoint {
    /// Stable identifier for this checkpoint.
    pub checkpoint_id: Uuid,

    /// `entry_hash` of the newest chainable envelope at checkpoint time.
    #[serde(with = "hash32_b64")]
    pub head: [u8; 32],

    /// Total **chainable** (v2+) envelopes written up to and including
    /// [`Self::head`].
    ///
    /// This is the field that makes truncation detectable: a log holding
    /// fewer chainable entries than a signed checkpoint claims has lost
    /// entries, and no amount of restamping fixes that without the signing
    /// key. Counting only chainable envelopes matters — pre-v2 rows are
    /// skipped by the verifier, so including them would make the count
    /// disagree with what verification can actually recount.
    pub entry_count: u64,

    /// `event_id` of the envelope at [`Self::head`], so a verifier can locate
    /// the anchor point directly instead of recomputing the whole chain.
    pub head_event_id: Uuid,

    /// Wall-clock at checkpoint time.
    pub checkpoint_at: DateTime<Utc>,

    /// The previous checkpoint's own [`Self::link_hash`], or `None` for the
    /// first. Checkpoints chain too, so **deleting a checkpoint is itself
    /// detectable** — otherwise an adversary would simply drop the
    /// checkpoints that contradict a truncated log.
    #[serde(with = "hash32_opt_b64")]
    pub prev_checkpoint: Option<[u8; 32]>,

    /// `verificationMethod` URI of the key that signed this checkpoint (e.g.
    /// `did:webvh:…#key-0`). Recorded so a checkpoint stays verifiable across
    /// a key rotation: a verifier resolves *this* key from the community's DID
    /// document history rather than assuming the current one.
    pub verification_method: String,

    /// Ed25519 signature over [`Self::signing_payload`].
    #[serde(with = "sig_b64")]
    pub signature: Vec<u8>,
}

/// Everything a checkpoint commits to, except the signature itself.
///
/// Split out so [`AuditCheckpoint::sign`] and
/// [`AuditCheckpoint::verify_signature`] cannot disagree about what is signed
/// — the classic way a signature scheme ends up covering less than it appears
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointClaim {
    pub checkpoint_id: Uuid,
    pub head: [u8; 32],
    pub entry_count: u64,
    pub head_event_id: Uuid,
    pub checkpoint_at: DateTime<Utc>,
    pub prev_checkpoint: Option<[u8; 32]>,
    pub verification_method: String,
}

impl CheckpointClaim {
    /// The exact bytes an Ed25519 signature covers.
    ///
    /// Length-prefixed and domain-tagged rather than a JSON encoding: the
    /// signature must not depend on serializer field ordering or on a
    /// canonicalisation step that could differ between signer and verifier.
    /// Same reasoning as the envelope's `chain_digest`.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CHECKPOINT_DOMAIN);
        out.extend_from_slice(self.checkpoint_id.as_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.entry_count.to_be_bytes());
        out.extend_from_slice(self.head_event_id.as_bytes());
        let ts = self.checkpoint_at.to_rfc3339();
        out.extend_from_slice(&(ts.len() as u64).to_be_bytes());
        out.extend_from_slice(ts.as_bytes());
        match self.prev_checkpoint {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.verification_method.len() as u64).to_be_bytes());
        out.extend_from_slice(self.verification_method.as_bytes());
        out
    }
}

impl AuditCheckpoint {
    /// Build and sign a checkpoint with `signing_key`.
    ///
    /// `verification_method` must name the public key corresponding to
    /// `signing_key` in the community's DID document — a verifier resolves it
    /// to check the signature.
    #[must_use]
    pub fn sign(claim: CheckpointClaim, signing_key: &SigningKey) -> Self {
        let signature = signing_key
            .sign(&claim.signing_payload())
            .to_bytes()
            .to_vec();
        Self {
            checkpoint_id: claim.checkpoint_id,
            head: claim.head,
            entry_count: claim.entry_count,
            head_event_id: claim.head_event_id,
            checkpoint_at: claim.checkpoint_at,
            prev_checkpoint: claim.prev_checkpoint,
            verification_method: claim.verification_method,
            signature,
        }
    }

    /// The claim this checkpoint carries — the signed half of it.
    #[must_use]
    pub fn claim(&self) -> CheckpointClaim {
        CheckpointClaim {
            checkpoint_id: self.checkpoint_id,
            head: self.head,
            entry_count: self.entry_count,
            head_event_id: self.head_event_id,
            checkpoint_at: self.checkpoint_at,
            prev_checkpoint: self.prev_checkpoint,
            verification_method: self.verification_method.clone(),
        }
    }

    /// Verify the signature against `public_key` (32 raw Ed25519 bytes).
    ///
    /// Returns `false` for a malformed key or signature as well as a genuine
    /// mismatch — from the verifier's point of view those are the same
    /// finding: this checkpoint does not prove anything.
    #[must_use]
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        verifying
            .verify(
                &self.claim().signing_payload(),
                &Signature::from_bytes(&sig_bytes),
            )
            .is_ok()
    }

    /// This checkpoint's own hash — what the next one's
    /// [`Self::prev_checkpoint`] points at.
    ///
    /// Covers the signature as well as the claim, so swapping a valid
    /// signature for a different valid signature over the same claim still
    /// breaks the link.
    #[must_use]
    pub fn link_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CHECKPOINT_LINK_DOMAIN);
        h.update(self.claim().signing_payload());
        h.update((self.signature.len() as u64).to_be_bytes());
        h.update(&self.signature);
        h.finalize().into()
    }

    /// Storage key: `<rfc3339>:<checkpoint_id>`, so an ascending prefix walk
    /// is chronological (matching the audit keyspace's convention).
    #[must_use]
    pub fn storage_key(&self) -> Vec<u8> {
        format!("{}:{}", self.checkpoint_at.to_rfc3339(), self.checkpoint_id).into_bytes()
    }
}

/// Why a checkpoint chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointBreak {
    /// The signature does not verify under the resolved public key. The
    /// checkpoint was forged, altered, or signed by a different key than
    /// `verification_method` names.
    BadSignature { index: usize, checkpoint_id: Uuid },
    /// `prev_checkpoint` does not point at the previous checkpoint's
    /// `link_hash` — a checkpoint was reordered, dropped, or inserted.
    BrokenLink { index: usize, checkpoint_id: Uuid },
    /// `entry_count` went backwards. The audit log only grows, so a later
    /// checkpoint claiming fewer entries than an earlier one is a forgery or
    /// a replay of an older checkpoint under a later timestamp.
    CountWentBackwards {
        index: usize,
        checkpoint_id: Uuid,
        previous: u64,
        claimed: u64,
    },
}

/// Verify a checkpoint chain in ascending (chronological) order.
///
/// Checks each signature, the `prev_checkpoint` links, and that
/// `entry_count` is monotonically non-decreasing. Returns the newest
/// checkpoint on success, or `None` when `checkpoints` is empty (a community
/// that has not checkpointed yet — not an error).
///
/// `public_key_for` resolves a `verification_method` URI to raw Ed25519 public
/// bytes. It is a callback rather than a single key so a checkpoint signed
/// before a key rotation still verifies against the key that actually signed
/// it. Returning `None` fails that checkpoint as [`CheckpointBreak::BadSignature`]
/// — an unresolvable signing key proves nothing.
pub fn verify_checkpoints<F>(
    checkpoints: &[AuditCheckpoint],
    mut public_key_for: F,
) -> Result<Option<&AuditCheckpoint>, CheckpointBreak>
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut prev_link: Option<[u8; 32]> = None;
    let mut prev_count: u64 = 0;

    for (index, cp) in checkpoints.iter().enumerate() {
        let ok = public_key_for(&cp.verification_method).is_some_and(|pk| cp.verify_signature(&pk));
        if !ok {
            return Err(CheckpointBreak::BadSignature {
                index,
                checkpoint_id: cp.checkpoint_id,
            });
        }
        if cp.prev_checkpoint != prev_link {
            return Err(CheckpointBreak::BrokenLink {
                index,
                checkpoint_id: cp.checkpoint_id,
            });
        }
        if cp.entry_count < prev_count {
            return Err(CheckpointBreak::CountWentBackwards {
                index,
                checkpoint_id: cp.checkpoint_id,
                previous: prev_count,
                claimed: cp.entry_count,
            });
        }
        prev_link = Some(cp.link_hash());
        prev_count = cp.entry_count;
    }

    Ok(checkpoints.last())
}

/// How the audit log measured up against its newest signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointAudit {
    /// No checkpoints exist. Nothing is contradicted, but nothing is
    /// attested either — the log carries only unkeyed-chain assurance.
    NoCheckpoints,
    /// The log is consistent with the newest checkpoint.
    Consistent {
        checkpoint_at: DateTime<Utc>,
        attested_entries: u64,
        /// Chainable entries written *since* the checkpoint. These are
        /// covered by the hash chain but not by any signature — an
        /// adversary can still truncate this tail freely, so it is the
        /// residual exposure and worth surfacing.
        unattested_entries: u64,
    },
    /// **Truncation.** The log holds fewer chainable entries than the newest
    /// signed checkpoint attests to. This is the finding the whole mechanism
    /// exists for and cannot be produced without the signing key.
    Truncated { attested: u64, found: u64 },
    /// The envelope named by `head_event_id` is missing, or its `entry_hash`
    /// no longer matches the signed `head`. The attested anchor point has
    /// been removed or rewritten.
    HeadMismatch {
        head_event_id: Uuid,
        /// `false` when the envelope is absent entirely rather than altered.
        found: bool,
    },
}

// Base64 codec for the signature, matching the envelope's hash encodings so
// the whole audit surface serialises consistently.
mod sig_b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// A checkpoint over an empty log anchors at [`GENESIS_HASH`] with a zero
/// count — the same convention the envelope chain uses for its first link.
#[must_use]
pub fn genesis_claim(
    checkpoint_id: Uuid,
    checkpoint_at: DateTime<Utc>,
    verification_method: String,
) -> CheckpointClaim {
    CheckpointClaim {
        checkpoint_id,
        head: GENESIS_HASH,
        entry_count: 0,
        head_event_id: Uuid::nil(),
        checkpoint_at,
        prev_checkpoint: None,
        verification_method,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn claim(n: u64, prev: Option<[u8; 32]>) -> CheckpointClaim {
        CheckpointClaim {
            checkpoint_id: Uuid::from_u128(u128::from(n) + 1),
            head: [n as u8; 32],
            entry_count: n,
            head_event_id: Uuid::from_u128(u128::from(n) + 1000),
            checkpoint_at: DateTime::parse_from_rfc3339("2026-07-25T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            prev_checkpoint: prev,
            verification_method: "did:webvh:scid:vtc.example#key-0".into(),
        }
    }

    fn chain(sk: &SigningKey, counts: &[u64]) -> Vec<AuditCheckpoint> {
        let mut out: Vec<AuditCheckpoint> = Vec::new();
        for &n in counts {
            let prev = out.last().map(AuditCheckpoint::link_hash);
            out.push(AuditCheckpoint::sign(claim(n, prev), sk));
        }
        out
    }

    fn resolver(sk: &SigningKey) -> impl FnMut(&str) -> Option<Vec<u8>> + use<'_> {
        move |_vm: &str| Some(sk.verifying_key().to_bytes().to_vec())
    }

    #[test]
    fn a_signed_checkpoint_verifies_under_its_own_key() {
        let sk = key(1);
        let cp = AuditCheckpoint::sign(claim(10, None), &sk);
        assert!(cp.verify_signature(&sk.verifying_key().to_bytes()));
    }

    /// The point of signing: a store-level adversary holds the store but not
    /// the community key, so a checkpoint they mint does not verify.
    #[test]
    fn a_checkpoint_signed_by_a_different_key_is_rejected() {
        let real = key(1);
        let attacker = key(2);
        let forged = AuditCheckpoint::sign(claim(10, None), &attacker);
        assert!(!forged.verify_signature(&real.verifying_key().to_bytes()));
    }

    /// Editing any signed field invalidates the signature. `entry_count` is
    /// the one that matters — lowering it is how an adversary would try to
    /// make a truncated log look complete.
    #[test]
    fn lowering_entry_count_breaks_the_signature() {
        let sk = key(1);
        let mut cp = AuditCheckpoint::sign(claim(500, None), &sk);
        cp.entry_count = 3;
        assert!(!cp.verify_signature(&sk.verifying_key().to_bytes()));
    }

    #[test]
    fn head_cannot_be_swapped() {
        let sk = key(1);
        let mut cp = AuditCheckpoint::sign(claim(10, None), &sk);
        cp.head = [0xAB; 32];
        assert!(!cp.verify_signature(&sk.verifying_key().to_bytes()));
    }

    #[test]
    fn a_well_formed_chain_verifies() {
        let sk = key(1);
        let cps = chain(&sk, &[10, 25, 40]);
        let newest = verify_checkpoints(&cps, resolver(&sk)).expect("chain verifies");
        assert_eq!(newest.map(|c| c.entry_count), Some(40));
    }

    /// Checkpoints chain so that *deleting one* is detectable — otherwise an
    /// adversary would simply drop the checkpoints contradicting a truncated
    /// log, and the mechanism would protect nothing.
    #[test]
    fn deleting_a_checkpoint_breaks_the_chain() {
        let sk = key(1);
        let cps = chain(&sk, &[10, 25, 40]);
        let gapped = vec![cps[0].clone(), cps[2].clone()];
        assert!(matches!(
            verify_checkpoints(&gapped, resolver(&sk)),
            Err(CheckpointBreak::BrokenLink { index: 1, .. })
        ));
    }

    #[test]
    fn reordering_checkpoints_breaks_the_chain() {
        let sk = key(1);
        let cps = chain(&sk, &[10, 25]);
        let swapped = vec![cps[1].clone(), cps[0].clone()];
        assert!(matches!(
            verify_checkpoints(&swapped, resolver(&sk)),
            Err(CheckpointBreak::BrokenLink { .. })
        ));
    }

    /// A replayed older checkpoint re-linked under a later position would let
    /// an adversary lower the attested count without forging a signature.
    #[test]
    fn entry_count_may_not_go_backwards() {
        let sk = key(1);
        // Hand-build a chain whose second link is genuinely signed but claims
        // fewer entries than the first.
        let first = AuditCheckpoint::sign(claim(40, None), &sk);
        let second = AuditCheckpoint::sign(claim(10, Some(first.link_hash())), &sk);
        assert!(matches!(
            verify_checkpoints(&[first, second], resolver(&sk)),
            Err(CheckpointBreak::CountWentBackwards {
                previous: 40,
                claimed: 10,
                ..
            })
        ));
    }

    /// An unresolvable `verification_method` proves nothing, so it must fail
    /// rather than be skipped — skipping would let an adversary sign with a
    /// key they invented and name it something that does not resolve.
    #[test]
    fn an_unresolvable_signing_key_fails_verification() {
        let sk = key(1);
        let cps = chain(&sk, &[10]);
        assert!(matches!(
            verify_checkpoints(&cps, |_vm: &str| None),
            Err(CheckpointBreak::BadSignature { index: 0, .. })
        ));
    }

    #[test]
    fn an_empty_checkpoint_set_is_not_an_error() {
        let sk = key(1);
        assert_eq!(verify_checkpoints(&[], resolver(&sk)), Ok(None));
    }

    #[test]
    fn checkpoints_round_trip_through_json() {
        let sk = key(1);
        let cp = AuditCheckpoint::sign(claim(7, Some([9u8; 32])), &sk);
        let json = serde_json::to_vec(&cp).expect("serialize");
        let back: AuditCheckpoint = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(cp, back);
        assert!(back.verify_signature(&sk.verifying_key().to_bytes()));
    }

    /// The signature must not be replayable as an envelope-chain digest, nor
    /// a link hash confusable with a signing payload.
    #[test]
    fn link_hash_and_signing_payload_are_domain_separated() {
        let sk = key(1);
        let cp = AuditCheckpoint::sign(claim(10, None), &sk);
        assert_ne!(cp.link_hash().to_vec(), cp.claim().signing_payload());
    }

    /// Two checkpoints differing only in signature must not share a link
    /// hash — otherwise a signature swap would be invisible to the chain.
    #[test]
    fn link_hash_covers_the_signature() {
        let a = AuditCheckpoint::sign(claim(10, None), &key(1));
        let b = AuditCheckpoint::sign(claim(10, None), &key(2));
        assert_eq!(a.claim(), b.claim(), "same claim");
        assert_ne!(a.link_hash(), b.link_hash(), "different signature");
    }

    #[test]
    fn storage_key_sorts_chronologically() {
        let sk = key(1);
        let mut early = claim(1, None);
        early.checkpoint_at = DateTime::parse_from_rfc3339("2026-07-25T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let a = AuditCheckpoint::sign(early, &sk);
        let b = AuditCheckpoint::sign(claim(2, Some(a.link_hash())), &sk);
        assert!(a.storage_key() < b.storage_key());
    }
}
