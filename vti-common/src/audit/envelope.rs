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
use uuid::Uuid;

use super::event::AuditEvent;
use super::key_store::KeyId;

/// Envelope schema version. Bumps **only** on a breaking-shape change
/// to [`AuditEnvelope`] itself. Phase 0 ships v1.
pub const SCHEMA_VERSION: u32 = 1;

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

    /// The tagged event payload.
    pub event: AuditEvent,
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
            event: AuditEvent::CommunityProfileUpdated(
                crate::audit::event::CommunityProfileUpdatedData {
                    fields_changed: vec!["name".into()],
                },
            ),
        }
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
}
