//! Data rooms — storage, wire types, and authorization.
//!
//! A **data room** is a shared space whose access is governed by credentials the *room
//! itself* issues, not by anything this service stores. That single property is what the
//! rest of this module is arranged around, and it is worth stating before the types,
//! because it inverts the assumption every other keyspace here is built on.
//!
//! # What this module deliberately does not hold
//!
//! **There is no member list.** Not omitted for now — there must not be one. Authorization
//! is a presentation carrying a membership credential and an authority chain, verified
//! against the room's own identifier. The moment this service keeps a roster and consults
//! it, three things stop being true at once: the room can no longer move to another host
//! without reissuing credentials, this service has become part of the room's membership
//! definition, and a room whose contents we cannot read acquires a member list we can.
//!
//! So the row below carries an owner, a visibility, an epoch and a retention period, and
//! nothing about who belongs. See `docs/05-design-notes/data-rooms.md` §1 (invariant I5).
//!
//! # What this service can and cannot see
//!
//! Set by the room's [`Visibility`], fixed at creation:
//!
//! | | `Open` | `Attributed` | `Private` |
//! |---|---|---|---|
//! | Record content | cleartext | sealed | sealed |
//! | Which member acted | visible | visible | unlinkable proof |
//! | Owner | visible | visible | visible |
//!
//! The owner is visible at every tier on purpose. A room whose contents nobody here can
//! read still has a party answerable for it existing — for quota, for abuse, and for the
//! lifecycle notice in §9 of the design note.
//!
//! # Scope of this module
//!
//! # Why this is a crate and not part of a service
//!
//! A room's storage and its authorization need nothing from a community service. That is
//! not an accident of layering — it is invariant I5 restated as a dependency graph: because
//! a room is authorized by credentials the room itself issued, the code deciding a room
//! operation cannot need a roster, a policy engine, or a session store. So it does not have
//! one, and the compiler enforces that this crate depends on `vti-common` and nothing else.
//!
//! The concrete win is a second consumer. A **room host** — someone hosting their own rooms
//! on their own infrastructure, topology T1 of the design — stores ciphertext and verifies
//! presentations. Without this crate, doing that means shipping an entire community service:
//! member lifecycle, policy, credential issuance, a website, an admin SPA. With it, a room
//! host is this crate plus a dispatch surface.
//!
//! Three layers:
//!
//! - [`storage`] — the keyspaces and their invariants.
//! - [`wire`] — the Trust-Task payload types, hand-written against the schemas in
//!   `trustoverip/dtgwg-trust-tasks-tf#346` until the generated bindings publish.
//! - [`authz`] — deciding whether an operation is allowed, **without reading any host's ACL
//!   or roster**. The invariant the whole design rests on.
//!
//! The Trust-Task **handlers** are deliberately *not* here. Dispatch is a service's spine,
//! and a spine is not extractable — see `docs/05-design-notes/vta-service-decomposition.md`.
//! Each host writes its own thin handlers over these three layers.

pub mod authz;
pub mod storage;
pub mod wire;

use serde::{Deserialize, Serialize};

/// Keyspace holding one row per room.
///
/// Named here rather than in a host's registry because the *name* is part of the storage
/// contract: two hosts using different names could not serve the same room's data directory.
pub const ROOMS_KEYSPACE: &str = "rooms";

/// Keyspace holding room records.
pub const ROOM_RECORDS_KEYSPACE: &str = "room_records";

/// How much of a room this service can see.
///
/// **Immutable for the life of a room.** A downgrade cannot un-see cleartext, and an
/// upgrade would protect only what came after while presenting as though it protected
/// everything. To change the visibility of some material, make another room and move it
/// deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Records are cleartext: searchable here, and readable by whoever operates this
    /// service. Right for material where that is not a threat and losing search is a real
    /// cost.
    Open,
    /// Record content is sealed; the acting member is still disclosed. The tier for anyone
    /// under an obligation to produce per-member access logs.
    Attributed,
    /// Content is sealed and membership is presented in zero knowledge: this service
    /// verifies that *a* member acted without learning which.
    Private,
}

impl Visibility {
    /// Whether this service holds record content in the clear.
    ///
    /// The one place to ask. A caller testing `== Visibility::Open` in several places will
    /// eventually miss one, and the failure mode is storing a plaintext record on a tier
    /// that promised not to.
    pub fn stores_cleartext(&self) -> bool {
        matches!(self, Visibility::Open)
    }

    /// Whether a record's acting member is disclosed to this service.
    pub fn discloses_actor(&self) -> bool {
        matches!(self, Visibility::Open | Visibility::Attributed)
    }
}

/// A room, as this service holds it.
///
/// Note what is absent: no members, no keys, no credentials. This service is told the
/// epoch *number* so it can serve the right ciphertext, and never the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Room {
    /// The room's own identifier, minted by its owner before registration.
    ///
    /// This service does not assign one. A room identified by something its host chose
    /// could not move to another host without changing identity, and portability is what
    /// the whole design rests on.
    pub room_id: String,

    /// The accountable party: controller of the room's identifier, issuer of every
    /// credential in it, and the party addressed about quota, abuse and lifecycle.
    pub owner_did: String,

    /// Fixed at creation. See [`Visibility`].
    pub visibility: Visibility,

    /// The current key epoch. Advanced by the owner on removal; this service records the
    /// number and never learns the key.
    pub epoch: u32,

    /// The next record version to assign.
    ///
    /// Monotonic **per room**, not per record — one comparable number is what a
    /// `sinceVersion` watermark needs, and per-record counters are not comparable to each
    /// other. Learned the expensive way by the app-state store; see
    /// `docs/05-design-notes/appstate-store.md` §2.
    pub next_version: u64,

    /// How long this service holds the room after its epoch lapses without renewal.
    ///
    /// Stated at creation rather than discovered later: a reclamation that surprises a
    /// member is a failure of the design, not of the member.
    pub retention_days: u32,

    /// Unix-epoch seconds.
    pub created_at: u64,
    /// Unix-epoch seconds; bumped on epoch advance and on record writes.
    pub updated_at: u64,
}

/// Curation state of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    /// Normal.
    Active,
    /// Superseded but retained; a client demotes it in recall rather than hiding it.
    Deprecated,
    /// A tombstone. The body is gone; the key, version and epoch remain.
    ///
    /// Retained rather than deleted because incremental sync needs it: without a tombstone
    /// a puller learns of every create and update and never of a delete, so retracted
    /// records resurrect on the next full rebuild and disagree with peers that saw the
    /// retraction.
    Retracted,
}

/// One record.
///
/// On `Attributed` and `Private` rooms `sealed` carries the ciphertext and `cleartext` is
/// `None`; on `Open` it is the other way round. Enforced at the operations layer rather
/// than the type, because the invariant is per-room and the type is per-record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// The record's key within the room.
    ///
    /// On the sealed tiers this MUST be opaque — a random identifier, never a descriptive
    /// slug. A key reading `decision/acquire-northwind` defeats the encryption sitting
    /// beside it. Structured naming belongs inside the sealed body.
    pub key: String,

    /// Server-assigned, monotonic per room. Also the `sinceVersion` watermark.
    pub version: u64,

    /// The key epoch this record was sealed under. `None` on an `Open` room.
    pub epoch: Option<u32>,

    /// Curation state.
    pub status: RecordStatus,

    /// Sealed content, base64url. Present on the sealed tiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,

    /// AEAD nonce, base64url. Present with `sealed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Cleartext content. Present only on an `Open` room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleartext: Option<serde_json::Value>,

    /// The member who wrote it, where the tier discloses one.
    ///
    /// `None` on a `Private` room — there the author lives inside the sealed body, where
    /// only members can read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Unix-epoch seconds.
    pub updated_at: u64,
}

/// Unix seconds as an RFC 3339 timestamp.
///
/// A value beyond what a timestamp can express renders as the epoch rather than panicking:
/// a listing is a read path, and a corrupt stored time should not take the room down.
fn rfc3339(unix_seconds: u64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch is in range"))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Record {
    /// The metadata projection a listing returns.
    ///
    /// **Never the body.** Ranking happens on the client, and a service that returned every
    /// body would make a caller pay for the whole room on every listing — and on a sealed
    /// tier could not usefully rank them anyway.
    /// The schema types every optional member — `epoch` is `integer`, `author` is
    /// `string` — and sets `additionalProperties: false`, so an absent member has to be
    /// *absent*. Emitting `null` fails validation rather than reading as "not applicable",
    /// which is why this builds a map instead of one `json!` literal.
    pub fn metadata(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("key".into(), serde_json::json!(self.key));
        map.insert("version".into(), serde_json::json!(self.version));
        map.insert("status".into(), serde_json::json!(self.status));
        // RFC 3339, because that is what the published schema types it as
        // (`format: date-time`) and what every other timestamp on the wire already is.
        // Storage keeps unix seconds; only the projection renders.
        map.insert(
            "updatedAt".into(),
            serde_json::json!(rfc3339(self.updated_at)),
        );
        if let Some(epoch) = self.epoch {
            map.insert("epoch".into(), serde_json::json!(epoch));
        }
        if let Some(author) = &self.author {
            map.insert("author".into(), serde_json::json!(author));
        }
        // `title` and `description` are the open tier's, and live in the cleartext body.
        if let Some(cleartext) = &self.cleartext {
            for field in ["title", "description"] {
                if let Some(v) = cleartext.get(field).filter(|v| v.is_string()) {
                    map.insert(field.into(), v.clone());
                }
            }
        }
        serde_json::Value::Object(map)
    }
}
