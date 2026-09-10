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
//! - `storage` — the keyspaces and their invariants.
//! - [`wire`] — the Trust-Task payload types, hand-written against the schemas in
//!   `trustoverip/dtgwg-trust-tasks-tf#346` until the generated bindings publish.
//! - `authz` — deciding whether an operation is allowed, **without reading any host's ACL
//!   or roster**. The invariant the whole design rests on.
//!
//! # Two halves, and the feature that names them
//!
//! A room has a host and it has members, and they need disjoint code. The `host` feature
//! (on by default) carries `storage`, `authz` and `audit`; the `mls` feature carries the
//! member's group keys, sealing and the epoch chain. `wire`, `error` and `lifecycle` are
//! common to both.
//!
//! The division already existed and was simply unnamed — `vta-service` imports
//! `mls`/`sealed`/`wire` and nothing else, while `vtc-service`, `room-host` and
//! `vti-rooms-dtg` import `storage`/`authz`/`audit`. What naming it buys is that
//! **`vti-common` becomes optional**, and with it every server dependency it carries:
//! axum, fjall, tokio. `--no-default-features --features mls` therefore builds for
//! `wasm32-unknown-unknown`, which is what lets a browser hold a room's keys itself
//! instead of asking an agent to. See `docs/05-design-notes/data-rooms-demo-site.md`.
//!
//! That the member half needed **no source changes** to get there is a property of
//! [`error`], which deliberately does not use `vti_common::error::AppError`: key material
//! is not a service's concern, and a record that fails to open is an outcome rather than a
//! fault. That decision was made for its own reasons and paid for itself here.
//!
//! The Trust-Task **handlers** are deliberately *not* here. Dispatch is a service's spine,
//! and a spine is not extractable — see `docs/05-design-notes/vta-service-decomposition.md`.
//! Each host writes its own thin handlers over these three layers.

/// A room's audit trail, behind the `host` feature.
#[cfg(feature = "host")]
pub mod audit;
/// Deciding whether a room operation is allowed, behind the `host` feature.
#[cfg(feature = "host")]
pub mod authz;
pub mod error;
pub mod lifecycle;
/// The record commitment — a Merkle tree over a room's records, so a listing
/// that omits one can be caught.
///
/// See `docs/05-design-notes/data-rooms-verified-reads.md` for what it buys and
/// what it does not.
pub mod merkle;
/// The room's group-key layer (RFC 9420), behind the `mls` feature.
///
/// Off by default: a host that only stores ciphertext needs none of it, and OpenMLS is a
/// substantial dependency to make it carry.
#[cfg(feature = "mls")]
pub mod mls;
/// The epoch key chain that keeps a room readable across a membership change.
#[cfg(feature = "mls")]
pub mod retention;
#[cfg(feature = "mls")]
pub mod sealed;
/// The room and record keyspaces, behind the `host` feature.
#[cfg(feature = "host")]
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

/// Keyspace holding the epoch key chain — one wrapped key per epoch advance.
///
/// Held by the host as opaque ciphertext it cannot read. See [`wire::EpochLink`].
pub const ROOM_EPOCH_LINKS_KEYSPACE: &str = "room_epoch_links";

/// Whether a room keeps its history readable across a membership change.
///
/// **Immutable for the life of a room**, like [`Visibility`] and for the same reason: the
/// links either exist for an epoch or they do not, and a policy change cannot manufacture
/// key material that was never sealed or unseal what was already severed.
///
/// The choice is a real one and it is not obvious, so it is stated at creation rather than
/// defaulted silently. See [`wire::EpochLink`] for what each side costs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RetentionPolicy {
    /// Every member reads the room's whole retained history, however long they have been in
    /// it. A commit seals the outgoing epoch's key under the incoming one.
    ///
    /// What a **library** wants: joining a room means being able to read it. The cost is
    /// post-compromise security for record content — a compromised current key reaches every
    /// retained epoch.
    ///
    /// **The default on deserialisation**, which is a statement about what a room will *do*
    /// rather than what it already *has*. A room stored before the chain existed holds no
    /// rungs, and nothing can give it any for the epochs it has already left behind — but it
    /// can chain from here, and since this policy is immutable, defaulting it the other way
    /// would condemn it to keep losing its history at every membership change. Its
    /// unreachable early epochs are a fact about its past, not a policy about its future.
    #[default]
    Chained,

    /// A member reads only from the epoch their group state is at. No links are produced,
    /// so nothing carries history from one epoch to the next.
    ///
    /// What a **stream** wants, and what a room with strict forward-secrecy obligations
    /// wants. The cost is that a new member joins an empty-looking room, and that nobody —
    /// including the writer — can reread a record once their group state has moved past the
    /// epoch it was sealed under.
    ///
    /// Precisely: a member keeps whatever keys they have already derived *in that session*,
    /// because a key they have read is a key they have. What this policy withholds is the
    /// means to derive one again — after a restart, on another device, or on joining.
    ///
    /// Never reached by deserialisation, and not yet reachable over the wire: choosing it
    /// needs a member on `rooms/create`, which is a spec change. It exists so that
    /// [`links_epochs`](Self::links_epochs) has something to mean, and so a host that is one
    /// day told a room does not chain refuses rungs for it rather than storing them anyway.
    FromJoin,
}

impl RetentionPolicy {
    /// Whether a commit under this policy produces a link, and therefore whether a host
    /// **may store one**.
    ///
    /// A host that ignored this would give a room a chain it declared it would not have, and
    /// its members would be able to read history the room told them they could not. Silently
    /// — which is why the hosts refuse a rung here rather than dropping it: a client whose
    /// configuration disagrees with the room should be told, not quietly accommodated.
    pub fn links_epochs(&self) -> bool {
        matches!(self, RetentionPolicy::Chained)
    }
}

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

    /// What this room intends about anchoring its state in its own witnessed log.
    ///
    /// **A statement of intent, not a schedule anything enforces** — nothing here
    /// can make an owner anchor. It is stored and served so that a member knows
    /// what to expect, which is what makes **silence legible**: a room that says
    /// `Renewal` and has not anchored in ten epochs is telling a member
    /// something, and a member who did not know what to expect could not have
    /// noticed.
    ///
    /// Defaults to [`AnchorCadence::Manual`] on deserialisation, which draws no
    /// expectation and is the honest reading of a room stored before this
    /// existed.
    #[serde(default)]
    pub anchor_cadence: AnchorCadence,

    /// Fixed at creation. See [`RetentionPolicy`].
    ///
    /// Defaults to [`RetentionPolicy::FromJoin`] on deserialisation — the shape a room
    /// stored before the epoch key chain existed deserialises to, and an accurate
    /// description of it: such a room has no links, and no policy field can conjure the
    /// keys that were never sealed.
    #[serde(default)]
    pub retention_policy: RetentionPolicy,

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

    /// When the current epoch expires, in unix seconds. `None` never lapses.
    ///
    /// The clock the whole lifecycle hangs off — see [`lifecycle`]. Set when an epoch is
    /// minted, and moved by nothing else: a room that is being used renews itself in the
    /// course of being used, and one nobody has committed to in a year has said something
    /// real about itself.
    ///
    /// `None` is what a room stored before this field existed deserialises to, and it means
    /// *never lapses* rather than *already lapsed* — a migration should not turn every
    /// existing room read-only on deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_expires_at: Option<u64>,

    /// Where this room's write-primary is, when this host holds a **read mirror**
    /// rather than the room itself.
    ///
    /// `None` — the shape every room stored before this field existed
    /// deserialises to — means this host *is* the primary. `Some(url)` means it
    /// serves reads from a copy and refuses every write, pointing the caller at
    /// the primary instead (§7.3).
    ///
    /// A room has exactly one write-primary. MLS needs a single sequencer
    /// anyway, and multi-primary replication is a stated non-goal: replicated
    /// multi-writer room state needs state-resolution machinery whose failure
    /// modes took Matrix years to shake out. A mirror cannot tamper — records
    /// are signed and bound to `roomId | key | version | epoch` — so the only
    /// things it can be are **stale** or **silent**, and both are detectable by
    /// a client that watches the version watermark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_of: Option<String>,

    /// Unix-epoch seconds.
    pub created_at: u64,
    /// Unix-epoch seconds; bumped on epoch advance and on record writes.
    pub updated_at: u64,
}

impl Room {
    /// Whether this host holds a read mirror of a room primaried elsewhere.
    pub fn is_mirror(&self) -> bool {
        self.mirror_of.is_some()
    }

    /// The highest version this host has, which is the watermark a puller
    /// resumes from and the floor a client compares against.
    ///
    /// `next_version` is the *next* number to assign, so the highest assigned
    /// is one less — and zero on a room that has never held a record, which is
    /// why this saturates rather than wrapping.
    pub fn watermark(&self) -> u64 {
        self.next_version.saturating_sub(1)
    }
}

/// What a room intends about anchoring, as `rooms/create` records it.
///
/// Deliberately **not a duration**. A room that promised "daily" would be making
/// a claim its owner's availability cannot keep, and a member comparing against a
/// clock would read an owner's holiday as a host's misbehaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorCadence {
    /// No anchor is intended. Honest, and cheap: anchoring costs a witnessed
    /// update and a rotation of the room DID's update key each time.
    Never,
    /// One anchor per epoch change — the cadence §9's lifecycle already moves at.
    Renewal,
    /// The owner anchors when they decide to. A member should draw no freshness
    /// expectation from this at all, which is exactly what it is for: it is the
    /// honest answer where there is no rule, and so it is the default.
    #[default]
    Manual,
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

    /// Whether a curator has pinned this record.
    ///
    /// Orthogonal to [`Record::status`] — a pinned record is still active, deprecated or
    /// retracted — because pinning answers *what matters here* and status answers *is this
    /// still current*. A room may well want its superseded canonical decision kept in view.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,

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

    /// The **leaf preimage**: this record in the form the room's commitment
    /// covers.
    ///
    /// Not [`Record`] itself, and the difference is the whole point. Hashing
    /// the storage record made the commitment reproducible only by another copy
    /// of this crate: `updatedAt` is unix seconds here and RFC 3339 on the wire,
    /// `epoch` and `nonce` are flat here and inside `sealed` on the wire, and
    /// `epoch` serialises as `null` on an open room where the wire has it
    /// absent. Three ways for two honest implementations to disagree about a
    /// root, and nothing said which one counted.
    ///
    /// `sealed` is assembled only when all three of its parts are present. A
    /// ciphertext with no nonce or no epoch is a **corrupt store** —
    /// [`storage::put_record`] writes the three together or writes nothing — and
    /// it degrades to a body-less record rather than to a fabricated half of
    /// one, because a substituted epoch hands a reader a body whose AEAD open
    /// fails for a reason pointing at the wrong thing.
    #[must_use]
    pub fn committed(&self) -> wire::CommittedRecord {
        let sealed = match (&self.sealed, &self.nonce, self.epoch) {
            (Some(ciphertext), Some(nonce), Some(epoch)) => Some(wire::SealedContent {
                ciphertext: ciphertext.clone(),
                nonce: nonce.clone(),
                epoch,
            }),
            _ => None,
        };
        wire::CommittedRecord {
            key: self.key.clone(),
            version: self.version,
            status: self.status,
            updated_at: rfc3339(self.updated_at),
            pinned: self.pinned,
            author: self.author.clone(),
            sealed,
            cleartext: self.cleartext.clone(),
        }
    }

    /// Read a wire record back into a storage record — the inverse of
    /// [`Record::committed`].
    ///
    /// # Why this has to exist
    ///
    /// A mirror pulls records from its primary and stores them, and it used to
    /// do that with `serde_json::from_value::<Record>(response)` — which worked
    /// only because the response *was* the storage record. That coupling is
    /// what put a storage type on the wire in the first place, so removing one
    /// without the other breaks replication. The two functions are inverses and
    /// `a_record_round_trips_through_its_committed_form` says so, which is a
    /// property rather than the coincidence of their being one type.
    ///
    /// # One thing does not survive, deliberately
    ///
    /// A **retracted** record keeps its epoch in storage and has nowhere to put
    /// it on the wire: the epoch travels inside `sealed`, where the AEAD binds
    /// it, and a tombstone has no `sealed`. So a mirrored tombstone comes back
    /// with `epoch: None`.
    ///
    /// That is the right trade rather than a gap to plug. A top-level `epoch`
    /// beside `sealed` is a second place for the same value to live, which is
    /// the disagreement this whole type exists to end — and a tombstone's epoch
    /// is read nowhere: the only check against it (`storage::put_record`) runs
    /// on a write that a retracted record can never take again.
    pub fn from_wire(record: &wire::CommittedRecord) -> Result<Self, FromWireError> {
        let parsed = chrono::DateTime::parse_from_rfc3339(&record.updated_at).map_err(|_| {
            FromWireError::UpdatedAt {
                key: record.key.clone(),
                value: record.updated_at.clone(),
            }
        })?;
        let updated_at =
            u64::try_from(parsed.timestamp()).map_err(|_| FromWireError::UpdatedAt {
                key: record.key.clone(),
                value: record.updated_at.clone(),
            })?;
        Ok(Self {
            key: record.key.clone(),
            version: record.version,
            epoch: record.sealed.as_ref().map(|s| s.epoch),
            status: record.status,
            pinned: record.pinned,
            sealed: record.sealed.as_ref().map(|s| s.ciphertext.clone()),
            nonce: record.sealed.as_ref().map(|s| s.nonce.clone()),
            cleartext: record.cleartext.clone(),
            author: record.author.clone(),
            updated_at,
        })
    }
}

/// A wire record that could not be read back into a storage record.
#[derive(Debug, thiserror::Error)]
pub enum FromWireError {
    /// `updatedAt` was not an RFC 3339 timestamp, or named an instant before
    /// the epoch. Either way the record cannot be stored: a mirror that guessed
    /// a time would write a record whose age is fiction.
    #[error(
        "record `{key}` carries `updatedAt` = `{value}`, which is not a storable RFC 3339 timestamp"
    )]
    UpdatedAt { key: String, value: String },
}

#[cfg(test)]
mod retention_policy_tests {
    use super::*;

    /// The default is a statement about what a room will *do*, not what it already has.
    ///
    /// A room stored before the chain existed deserialises here. Defaulting it to
    /// `FromJoin` — which an earlier version of this enum did — would have been the more
    /// literal description of its contents and the wrong policy: the choice is immutable,
    /// so it would have condemned every pre-chain room to keep losing its history at every
    /// membership change, which is the defect the chain exists to fix.
    #[test]
    fn a_room_stored_before_the_chain_existed_chains_from_here() {
        let json = r#"{
            "roomId": "did:webvh:example.com:rooms:legacy",
            "ownerDid": "did:key:zOwner",
            "visibility": "attributed",
            "epoch": 4,
            "nextVersion": 9,
            "retentionDays": 90,
            "createdAt": 0,
            "updatedAt": 0
        }"#;
        let room: Room = serde_json::from_str(json).expect("a pre-chain room deserialises");
        assert_eq!(room.retention_policy, RetentionPolicy::Chained);
        assert!(
            room.retention_policy.links_epochs(),
            "a legacy room must be able to chain from here, whatever it lost before"
        );
    }

    /// The method exists so a host can refuse a rung for a room that does not chain. If this
    /// ever stops being consulted, the policy is documentation and the hosts store rungs for
    /// rooms that declared they would have none.
    #[test]
    fn only_a_chained_room_accepts_rungs() {
        assert!(RetentionPolicy::Chained.links_epochs());
        assert!(!RetentionPolicy::FromJoin.links_epochs());
    }
}
