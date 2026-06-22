//! [`AuditEnvelope`] — the wire-stable shape that wraps every
//! [`AuditEvent`].
//!
//! Carries:
//!
//! - the event id, timestamps, version stamps
//! - HMAC-hashed + plaintext pairs for actor + (optional) target
//!   identifiers
//! - the tagged event payload
//!
//! RTBF mechanics: nulling the `*_plain` field while retaining the
//! HMAC hash keeps the envelope correlatable across the audit log
//! without re-leaking the DID. Rotating the `audit_key` (see
//! [`super::key_store::AuditKeyStore`]) makes pre-rotation hashes
//! opaque to anyone who doesn't hold the prior key. See spec §11.1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::event::AuditEvent;
use super::key_store::KeyId;

/// Envelope schema version. Bumps **only** on a breaking-shape change
/// to [`AuditEnvelope`] itself. Phase 0 shipped v1; v2 adds the
/// tamper-evidence hash chain ([`AuditEnvelope::prev_hash`] /
/// [`AuditEnvelope::entry_hash`]).
pub const SCHEMA_VERSION: u32 = 2;

/// Domain-separation tag mixed into every [`AuditEnvelope::chain_digest`]
/// so a digest can never be confused with any other SHA-256 in the
/// system. Bump the suffix if the digest's covered-field set changes.
const CHAIN_DOMAIN: &[u8] = b"vtc-audit-chain/v1\0";

/// The all-zero hash that anchors the chain: the `prev_hash` of the
/// first chained envelope (and the `entry_hash` left on pre-v2
/// envelopes that predate the chain).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// serde `default` for the chain-hash fields so envelopes written
/// before SCHEMA_VERSION 2 (which lack the fields entirely) still
/// deserialize — they come back anchored at [`GENESIS_HASH`].
fn genesis_hash() -> [u8; 32] {
    GENESIS_HASH
}

/// Default event version, applied when an event variant doesn't pin
/// its own value. Per-variant overrides are added when an existing
/// variant's payload shape changes (callers bump just that variant
/// and bake the new version into the constructor).
pub const EVENT_VERSION: u32 = 1;

/// A persisted audit-log entry.
//
// Note: deliberately NOT `ToSchema`. The `AuditEvent` payload enum fans out
// into a large tree of variant-specific shapes; the single `/audit` read
// endpoint documents its response body as an opaque object rather than drag
// that whole surface into the OpenAPI components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEnvelope {
    /// Stable identifier for this specific event. Becomes the
    /// secondary-key component for cursor-based queries.
    pub event_id: Uuid,

    /// Variant-specific schema version. Bumped on a breaking change
    /// to a particular variant's payload; the envelope's
    /// [`SCHEMA_VERSION`] tracks the wrapper-shape version
    /// independently.
    pub event_version: u32,

    /// Envelope-shape version. See [`SCHEMA_VERSION`] for the
    /// semantics.
    pub schema_version: u32,

    /// Wall-clock at write time. Drives the primary `<timestamp>:<event_id>`
    /// audit-keyspace ordering.
    pub timestamp: DateTime<Utc>,

    /// Identifier of the audit_key used to compute the hashes below.
    /// Verifiers walk the key history newest-first; this lets them
    /// skip the search when they already know the right key.
    pub audit_key_id: KeyId,

    /// HMAC-SHA256 of the actor DID under [`Self::audit_key_id`].
    /// Always present so RTBF can null the plaintext without losing
    /// the correlation handle.
    #[serde(with = "hash32_b64")]
    pub actor_did_hash: [u8; 32],

    /// Plaintext actor DID. `None` after an RTBF override has redacted
    /// this row.
    pub actor_did_plain: Option<String>,

    /// HMAC-SHA256 of the target DID, if the event has one. `None`
    /// for events whose target is the community itself (e.g.
    /// `CommunityProfileUpdated`).
    #[serde(with = "hash32_opt_b64")]
    pub target_did_hash: Option<[u8; 32]>,

    /// Plaintext target DID. Same null-on-RTBF semantics as
    /// [`Self::actor_did_plain`].
    pub target_did_plain: Option<String>,

    /// Tamper-evidence chain: the [`Self::entry_hash`] of the
    /// immediately-preceding envelope, or [`GENESIS_HASH`] for the
    /// first one. Linking each entry to its predecessor makes a
    /// reorder/drop/duplicate of any envelope detectable by
    /// [`verify_chain`]. `default` keeps pre-v2 rows deserializable.
    #[serde(with = "hash32_b64", default = "genesis_hash")]
    pub prev_hash: [u8; 32],

    /// Tamper-evidence chain: SHA-256 commitment to this envelope's
    /// **immutable** content (see [`Self::chain_digest`]). Stamped at
    /// write time; the next envelope's [`Self::prev_hash`] points here.
    /// `default` keeps pre-v2 rows deserializable (they come back as
    /// [`GENESIS_HASH`], i.e. unchained).
    #[serde(with = "hash32_b64", default = "genesis_hash")]
    pub entry_hash: [u8; 32],

    /// The tagged event payload.
    pub event: AuditEvent,
}

impl AuditEnvelope {
    /// SHA-256 commitment over this envelope's **immutable** content,
    /// used to stamp [`Self::entry_hash`] at write time and to
    /// re-derive it during [`verify_chain`].
    ///
    /// Deliberately covers `prev_hash` (so the link is part of the
    /// commitment) but **excludes**:
    /// - `entry_hash` itself (it *is* this digest — self-reference),
    /// - `actor_did_plain` / `target_did_plain`, which RTBF nulls
    ///   after the fact. The HMAC *hashes* are covered, so attribution
    ///   stays chained while a redaction of the plaintext does not
    ///   break the chain.
    ///
    /// The `event` payload is hashed via its `serde_json` encoding,
    /// which is canonical in this workspace (maps serialize sorted,
    /// and the store round-trips through the same encoder).
    pub fn chain_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CHAIN_DOMAIN);
        h.update(self.prev_hash);
        h.update(self.event_id.as_bytes());
        h.update(self.event_version.to_be_bytes());
        h.update(self.schema_version.to_be_bytes());
        h.update(self.timestamp.to_rfc3339().as_bytes());
        h.update(self.audit_key_id.0.as_bytes());
        h.update(self.actor_did_hash);
        match self.target_did_hash {
            Some(t) => {
                h.update([1u8]);
                h.update(t);
            }
            None => h.update([0u8]),
        }
        let event_bytes = serde_json::to_vec(&self.event).expect("AuditEvent serializes");
        h.update((event_bytes.len() as u64).to_be_bytes());
        h.update(&event_bytes);
        h.finalize().into()
    }
}

/// A detected break in the audit hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// `envelopes[index].entry_hash` does not match a recompute of
    /// [`AuditEnvelope::chain_digest`] — the envelope's content was
    /// altered after it was written.
    TamperedEntry { index: usize, event_id: Uuid },
    /// `envelopes[index].prev_hash` does not point at the previous
    /// envelope's `entry_hash` — an entry was reordered, dropped, or
    /// inserted.
    BrokenLink { index: usize, event_id: Uuid },
}

/// Verify the tamper-evidence chain over `envelopes`, which must be in
/// ascending write order (the audit keyspace's `<timestamp>:<event_id>`
/// key order). Each v2+ envelope must (a) re-derive its own
/// `entry_hash` and (b) carry a `prev_hash` equal to the previous v2+
/// envelope's `entry_hash` (or [`GENESIS_HASH`] for the first link).
///
/// Pre-v2 envelopes (written before the chain existed) carry no hashes
/// and are skipped; the chain re-anchors at the first v2 envelope.
pub fn verify_chain(envelopes: &[AuditEnvelope]) -> Result<(), ChainBreak> {
    let mut prev: Option<[u8; 32]> = None;
    for (index, env) in envelopes.iter().enumerate() {
        if env.schema_version < 2 {
            // Predates the chain — nothing to verify, and it must not
            // become the predecessor of a v2 link.
            continue;
        }
        if env.chain_digest() != env.entry_hash {
            return Err(ChainBreak::TamperedEntry {
                index,
                event_id: env.event_id,
            });
        }
        let expected_prev = prev.unwrap_or(GENESIS_HASH);
        if env.prev_hash != expected_prev {
            return Err(ChainBreak::BrokenLink {
                index,
                event_id: env.event_id,
            });
        }
        prev = Some(env.entry_hash);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Serde helpers — base64url for 32-byte hashes
// ---------------------------------------------------------------------------

pub(crate) const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

mod hash32_b64 {
    use super::B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hash"))
    }
}

mod hash32_opt_b64 {
    use super::B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&B64.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => {
                let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
                let arr = v
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32-byte hash"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> AuditEnvelope {
        AuditEnvelope {
            event_id: Uuid::nil(),
            event_version: EVENT_VERSION,
            schema_version: SCHEMA_VERSION,
            timestamp: DateTime::parse_from_rfc3339("2026-05-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            audit_key_id: KeyId::nil(),
            actor_did_hash: [0xAB; 32],
            actor_did_plain: Some("did:key:z6Mk".into()),
            target_did_hash: Some([0xCD; 32]),
            target_did_plain: Some("did:key:z6Mk2".into()),
            prev_hash: GENESIS_HASH,
            entry_hash: GENESIS_HASH,
            event: AuditEvent::CommunityProfileUpdated(
                crate::audit::event::CommunityProfileUpdatedData {
                    fields_changed: vec!["name".into()],
                    ..Default::default()
                },
            ),
        }
    }

    /// Build a sample envelope whose `entry_hash` is correctly stamped
    /// from `prev`, as the writer does.
    fn chained_envelope(prev: [u8; 32], seed: u8) -> AuditEnvelope {
        let mut e = sample_envelope();
        e.event_id = Uuid::from_bytes([seed; 16]);
        e.actor_did_hash = [seed; 32];
        e.prev_hash = prev;
        e.entry_hash = e.chain_digest();
        e
    }

    #[test]
    fn envelope_roundtrips_through_serde() {
        let e = sample_envelope();
        let s = serde_json::to_string(&e).unwrap();
        let back: AuditEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn hashes_serialize_as_base64url_strings() {
        let e = sample_envelope();
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        // 32 bytes base64url-encoded with no padding = 43 chars
        let actor = v["actor_did_hash"].as_str().unwrap();
        assert_eq!(actor.len(), 43);
        // All-0xAB bytes encode deterministically.
        assert_eq!(actor, "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s");
        let target = v["target_did_hash"].as_str().unwrap();
        assert_eq!(target.len(), 43);
    }

    #[test]
    fn null_target_hash_omits_or_nulls_in_json() {
        let mut e = sample_envelope();
        e.target_did_hash = None;
        e.target_did_plain = None;
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert!(v["target_did_hash"].is_null());
        assert!(v["target_did_plain"].is_null());
    }

    #[test]
    fn rtbf_redaction_preserves_hashes() {
        let mut e = sample_envelope();
        // Simulate RTBF: null the plaintext, keep the hashes.
        e.actor_did_plain = None;
        e.target_did_plain = None;
        let s = serde_json::to_string(&e).unwrap();
        let back: AuditEnvelope = serde_json::from_str(&s).unwrap();
        assert!(back.actor_did_plain.is_none());
        assert!(back.target_did_plain.is_none());
        assert_eq!(back.actor_did_hash, [0xAB; 32]);
        assert_eq!(back.target_did_hash, Some([0xCD; 32]));
    }

    #[test]
    fn rtbf_redaction_does_not_break_the_chain() {
        // entry_hash excludes the plaintext fields, so nulling them
        // (RTBF) must leave the chain intact.
        let e = chained_envelope(GENESIS_HASH, 0x11);
        let mut redacted = e.clone();
        redacted.actor_did_plain = None;
        redacted.target_did_plain = None;
        assert_eq!(redacted.chain_digest(), e.entry_hash);
        assert!(verify_chain(&[redacted]).is_ok());
    }

    #[test]
    fn well_formed_chain_verifies() {
        let a = chained_envelope(GENESIS_HASH, 0x01);
        let b = chained_envelope(a.entry_hash, 0x02);
        let c = chained_envelope(b.entry_hash, 0x03);
        assert!(verify_chain(&[a, b, c]).is_ok());
    }

    #[test]
    fn tampered_entry_is_detected() {
        let a = chained_envelope(GENESIS_HASH, 0x01);
        let mut b = chained_envelope(a.entry_hash, 0x02);
        // Mutate covered content without restamping entry_hash.
        b.event =
            AuditEvent::CommunityProfileUpdated(crate::audit::event::CommunityProfileUpdatedData {
                fields_changed: vec!["logoUrl".into()],
                ..Default::default()
            });
        match verify_chain(&[a, b]) {
            Err(ChainBreak::TamperedEntry { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected TamperedEntry, got {other:?}"),
        }
    }

    #[test]
    fn dropped_entry_breaks_the_link() {
        let a = chained_envelope(GENESIS_HASH, 0x01);
        let b = chained_envelope(a.entry_hash, 0x02);
        let c = chained_envelope(b.entry_hash, 0x03);
        // Drop `b`: c.prev_hash now points at a missing predecessor.
        match verify_chain(&[a, c]) {
            Err(ChainBreak::BrokenLink { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected BrokenLink, got {other:?}"),
        }
    }

    #[test]
    fn reordered_entries_break_the_link() {
        let a = chained_envelope(GENESIS_HASH, 0x01);
        let b = chained_envelope(a.entry_hash, 0x02);
        match verify_chain(&[b, a]) {
            Err(ChainBreak::BrokenLink { index, .. }) => assert_eq!(index, 0),
            other => panic!("expected BrokenLink, got {other:?}"),
        }
    }

    #[test]
    fn pre_v2_envelopes_are_skipped_then_chain_reanchors() {
        // A legacy row (schema_version 1, no hashes) followed by a
        // fresh v2 chain that anchors at genesis.
        let mut legacy = sample_envelope();
        legacy.schema_version = 1;
        legacy.prev_hash = GENESIS_HASH;
        legacy.entry_hash = GENESIS_HASH;
        let a = chained_envelope(GENESIS_HASH, 0x01);
        let b = chained_envelope(a.entry_hash, 0x02);
        assert!(verify_chain(&[legacy, a, b]).is_ok());
    }

    #[test]
    fn pre_v2_envelope_deserializes_without_hash_fields() {
        // Old wire form: an envelope JSON object missing prev_hash /
        // entry_hash entirely must still parse (serde default).
        let mut v = serde_json::to_value(sample_envelope()).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("prev_hash");
        obj.remove("entry_hash");
        let back: AuditEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(back.prev_hash, GENESIS_HASH);
        assert_eq!(back.entry_hash, GENESIS_HASH);
    }
}
