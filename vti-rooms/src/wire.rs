//! Wire types for the `rooms/*` Trust Tasks.
//!
//! # Why these are hand-written, now that the generated ones exist
//!
//! They began as a mirror of schemas still in review upstream. Those schemas have since
//! published and `trust_tasks_rs::specs::rooms` carries generated bindings — so the earlier
//! instruction here, to replace these with the generated types on publication, has come due
//! and is **deliberately not being followed.**
//!
//! The reason is that the generated types are shaped for a different job. They use newtypes
//! and `NonZeroU64` where a storage layer wants plain `String` and `u64`, they are
//! `#[non_exhaustive]`, and they are built through builders — all correct for a client
//! constructing a request, all friction for a crate whose types are also its storage
//! records. Converting would push that friction into every handler and every host.
//!
//! What the original instruction was actually protecting against is two descriptions of one
//! wire format drifting apart, and that danger is real: a `snake_case` field where the
//! schema says `camelCase` is invisible to every Rust test, because both sides of a
//! round-trip use the same struct. So the protection is kept and the conversion is not:
//! `tests/schema_conformance.rs` validates what these types actually serialise to against
//! the published schemas. **Every type here must appear in that file.** Agreeing on the
//! wire is the requirement; agreeing on the Rust shape never was.
//!
//! # The one exemption, and it is temporary
//!
//! [`EpochLink`] is **not** in that file, because there is no published schema to check it
//! against: today it is a storage record, written by a member's own VTA and read back by it,
//! and the tasks that will put it on the wire are still upstream (design note §12.2). Named
//! here rather than left as an apparent oversight — the rule above is the kind that decays
//! the first time someone finds an unexplained gap in it and concludes it is advisory. When
//! `rooms/keys/chain` publishes, this paragraph goes and the type joins the census.
//!
//! Every struct is `camelCase` and `deny_unknown_fields`: these carry authorization
//! decisions, and an unknown member on one of those is a request that means something the
//! service did not understand.

use serde::{Deserialize, Serialize};

use crate::{Record, RecordStatus, Visibility};

/// `rooms/create/0.1`.
pub const ROOMS_CREATE_TYPE: &str = "https://trusttasks.org/spec/rooms/create/0.1";
/// `rooms/records/put/0.1`.
pub const ROOMS_RECORDS_PUT_TYPE: &str = "https://trusttasks.org/spec/rooms/records/put/0.1";
/// `rooms/records/get/0.1`.
pub const ROOMS_RECORDS_GET_TYPE: &str = "https://trusttasks.org/spec/rooms/records/get/0.1";
/// `rooms/records/list/0.1`.
pub const ROOMS_RECORDS_LIST_TYPE: &str = "https://trusttasks.org/spec/rooms/records/list/0.1";
/// `rooms/epoch/mint/0.1`.
pub const ROOMS_EPOCH_MINT_TYPE: &str = "https://trusttasks.org/spec/rooms/epoch/mint/0.1";
/// `rooms/epoch/chain/0.1`.
pub const ROOMS_EPOCH_CHAIN_TYPE: &str = "https://trusttasks.org/spec/rooms/epoch/chain/0.1";
/// `rooms/owner/transfer/0.1`.
pub const ROOMS_OWNER_TRANSFER_TYPE: &str = "https://trusttasks.org/spec/rooms/owner/transfer/0.1";
/// `rooms/owner/claim/0.1`.
pub const ROOMS_OWNER_CLAIM_TYPE: &str = "https://trusttasks.org/spec/rooms/owner/claim/0.1";
/// `rooms/records/curate/0.1`.
pub const ROOMS_RECORDS_CURATE_TYPE: &str = "https://trusttasks.org/spec/rooms/records/curate/0.1";

/// Every `rooms/*` URI this service dispatches.
pub const ROOMS_DISPATCHED_URIS: &[&str] = &[
    ROOMS_CREATE_TYPE,
    ROOMS_RECORDS_PUT_TYPE,
    ROOMS_RECORDS_GET_TYPE,
    ROOMS_RECORDS_LIST_TYPE,
    ROOMS_EPOCH_MINT_TYPE,
    ROOMS_EPOCH_CHAIN_TYPE,
    ROOMS_RECORDS_CURATE_TYPE,
    ROOMS_OWNER_TRANSFER_TYPE,
    ROOMS_OWNER_CLAIM_TYPE,
];

/// What a party presents to act on a room.
///
/// The whole authority chain travels here, **leaf first**, and this service never
/// dereferences a link's `parent` to fetch one it was not given. That is not an
/// optimisation: resolving over the network would make verification depend on availability,
/// turn an identifier into a request this service can be induced to make against an address
/// the *presenter* chooses, and signal credential use to whoever hosts that identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPresentation {
    /// The presenter's membership credential for this room, or a zero-knowledge
    /// presentation of it on a `private` room.
    pub membership: String,

    /// The authority chain, leaf first. The last element must be issued by the room.
    pub authority: Vec<String>,

    /// REQUIRED on a `private` room: proof that the membership credential and the chain's
    /// leaf describe the **same subject**.
    ///
    /// Without it two parties pool credentials — one contributes membership, the other
    /// authority — and the combination verifies as a single party holding both. Silent when
    /// wrong, which is why [`crate::authz`] refuses a private-room presentation that omits
    /// it rather than treating it as optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding: Option<String>,
}

/// Sealed record content, as it crosses the wire and is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedContent {
    /// The sealed record, base64url. AEAD-bound to `roomId|key|version|epoch`.
    pub ciphertext: String,
    /// AEAD nonce, base64url.
    pub nonce: String,
    /// The epoch it was sealed under.
    pub epoch: u32,
}

/// One rung of the epoch key chain: epoch `epoch - 1`'s storage key, sealed under
/// epoch `epoch`'s.
///
/// A host stores these and cannot read them — the key that opens one is the storage key of
/// the epoch it names, which no host ever holds. What a host learns from a link is that an
/// epoch happened, which it already knew from [`super::Room::epoch`].
///
/// # Why the chain points backwards
///
/// A record is sealed under the epoch current when it was written, and MLS deliberately
/// gives no way to derive an old epoch's exporter from a new one — that is forward secrecy,
/// and it is the property that makes removal mean something. Without a link, advancing the
/// epoch therefore makes every record already in the room unreadable *to everyone*,
/// including the member who wrote it.
///
/// The link is the one-way street run the other way: a member holding the current key can
/// walk back through the chain to any retained epoch, and a member holding an *old* key can
/// derive nothing forward. Removal stays forward-only; reading stays possible.
///
/// # What it costs
///
/// Post-compromise security for record content. Once the chain exists, a compromised
/// current key reaches every retained epoch. That is the trade a *library* makes and a
/// message stream does not, which is why it is [`super::RetentionPolicy`] and not a
/// constant. MLS's own post-compromise property is untouched: a compromised leaf still
/// heals at the next commit, and a removed member still reads nothing written after them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochLink {
    /// The epoch whose key opens this link. It wraps the key of `epoch - 1`.
    pub epoch: u32,
    /// The wrapped predecessor key, base64url. AEAD-bound to `epoch-link|epoch|epoch-1`.
    pub wrapped: String,
    /// AEAD nonce, base64url.
    pub nonce: String,
}

/// Cleartext record content. `open` rooms only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleartextContent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// `rooms/create/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRoomBody {
    /// The room's own identifier, minted by its owner. This service does not assign one:
    /// a room identified by something its host chose could not move to another host.
    pub room_id: String,
    pub visibility: Visibility,
    pub owner_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// `rooms/create/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoomResponse {
    pub room_id: String,
    pub epoch: u32,
}

/// `rooms/records/put/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutRecordBody {
    pub room_id: String,
    pub key: String,
    pub presentation: AuthorityPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleartext: Option<CleartextContent>,
}

/// `rooms/records/put/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordResponse {
    pub key: String,
    pub version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
}

/// `rooms/records/get/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetRecordBody {
    pub room_id: String,
    pub key: String,
    pub presentation: AuthorityPresentation,
}

/// `rooms/records/list/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListRecordsBody {
    pub room_id: String,
    pub presentation: AuthorityPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// **The leaf preimage of the record tree** — the object a host hashes into a
/// leaf and a reader reassembles to check a [`crate::merkle::InclusionProof`].
///
/// This is the wire's `CommittedRecord` (`rooms/_shared/0.1`), and it is
/// deliberately not [`Record`]. A commitment nobody but its author can
/// recompute is not a commitment, and hashing the *storage* record made it one:
/// `updatedAt` is unix seconds in the store and RFC 3339 on the wire, `epoch`
/// and `nonce` sit flat in the store and inside `sealed` on the wire, and
/// `epoch` serialises as `null` on an open room where the wire has it absent.
/// A second implementation reading only the specification could not reproduce
/// a single root.
///
/// **Absence carries meaning**, so every presence rule here is exact:
///
/// - `pinned` is serialised **only** when true. `false` is not a spelling of
///   this member; absent is. Two spellings would give one record two roots.
/// - `epoch` is not a member. It lives inside `sealed`, where the AEAD binds
///   it, and a top-level copy would be a second place for it to disagree with
///   itself.
/// - `sealed` on the sealed tiers, `cleartext` on `open`, and **neither** on a
///   `retracted` tombstone.
/// - `title`/`description` are not members: a listing lifts them out of an open
///   room's body, and committing to both would commit to the same bytes twice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedRecord {
    pub key: String,
    pub version: u64,
    pub status: RecordStatus,
    /// RFC 3339. The digest is over the **wire** form, never over the unix
    /// seconds the store keeps.
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleartext: Option<serde_json::Value>,
}

/// `rooms/records/get/0.1#response`.
///
/// # Why this type exists, having not existed
///
/// Both hosts answered a read by serialising [`Record`] — the *storage* record
/// — and adding `dataCommitment` to whatever came out. That is not this task's
/// response and never was. `sealed` is stored as a bare base64url string where
/// the schema types it as a `SealedRecord` object, and `epoch`, `nonce`,
/// `status`, `pinned`, `author` and `updatedAt` were emitted flat — so under the
/// response's `additionalProperties: false` a single read produced a type error
/// and six violations.
///
/// It survived because this module's rule — every wire type appears in
/// `tests/schema_conformance.rs` — can only be applied to types that *exist*.
/// A response with no type had no line to be missing from, and a storage record
/// reached the wire because nothing stood between them.
///
/// The consumer is not hypothetical: `@openvtc/pnm-core`'s `roomsRecordsGet` is
/// typed on the **generated** payload, so a caller reading `sealed.ciphertext`
/// got `undefined` from a live host — with a green type-check on both sides.
///
/// # The response *is* the leaf preimage, plus three members
///
/// Strip `dataCommitment`, `trace` and `ext` and what remains is exactly a
/// [`CommittedRecord`], which is why the flattened field is that type rather
/// than a repetition of it. A reader reassembles the preimage by **deletion**,
/// not reconstruction, and the ciphertext is never carried twice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRecordResponse {
    /// Everything the room's commitment covers.
    #[serde(flatten)]
    pub record: CommittedRecord,
    /// The room's data commitment, as a `DigestMultibase`.
    ///
    /// Optional for the same reason it is on a listing: a host that maintains
    /// no tree must not invent a root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_commitment: Option<String>,
    /// The path from this record's leaf to `data_commitment`.
    ///
    /// Served only with the commitment it reaches, and computed from the same
    /// snapshot: a trace is a statement about the tree it was cut from, and a
    /// room moves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<crate::merkle::InclusionProof>,
}

impl GetRecordResponse {
    /// The response for `record`, with whatever verification the host can
    /// offer.
    ///
    /// Built here rather than in each host so the two cannot answer a read
    /// differently — which is exactly how the shape above went wrong, in two
    /// files, for as long as the response had no type.
    #[must_use]
    pub fn of(
        record: &Record,
        data_commitment: Option<String>,
        trace: Option<crate::merkle::InclusionProof>,
    ) -> Self {
        Self {
            record: record.committed(),
            data_commitment,
            trace,
        }
    }
}

/// `rooms/records/list/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRecordsResponse {
    /// Metadata only — never bodies.
    pub records: Vec<serde_json::Value>,
    /// The room's data commitment, as a `DigestMultibase`.
    ///
    /// Optional on the wire because a host that maintains no tree must not
    /// invent a root: its absence honestly says "no completeness guarantee
    /// here", and a fabricated one would say the opposite while meaning less.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_commitment: Option<String>,
}

/// `rooms/records/curate/0.1` request.
///
/// Separate from [`PutRecordBody`] because a record's *standing* is not its content: on a
/// sealed tier a host cannot read what it stores, so "replace this with the same body,
/// marked deprecated" would make a member re-seal and re-upload bytes the host already
/// holds, to say something that is not about the bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurateRecordBody {
    pub room_id: String,
    pub key: String,
    /// Must confer `curate` — deliberately not implied by `write`. Deciding what a room's
    /// shared knowledge is worth is a different grant from being able to add to it.
    pub presentation: AuthorityPresentation,
    /// The standing to move to. Omit to change only `pinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<RecordStatus>,
    /// Whether to pin. Omit to leave unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    /// Why, for the room's audit trail. Member-authored free text — untrusted for both
    /// rendering and any agent that reads it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional precondition: the record's current version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
}

/// `rooms/records/curate/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurateRecordResponse {
    pub key: String,
    /// The version the curation assigned. A change others must converge on is a change like
    /// any other, and one that left the version alone would be invisible to every
    /// `sinceVersion` watermark in the room.
    pub version: u64,
    pub status: RecordStatus,
    pub pinned: bool,
}

/// `rooms/owner/transfer/0.1` request.
///
/// The deliberate handover, by an owner who is still present. Its counterpart
/// [`ClaimOwnerBody`] is what happens when they are not — two shapes because they are two
/// acts, differing in who initiates, what authorizes, and whether the room must have lapsed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferOwnerBody {
    pub room_id: String,
    /// The member taking ownership.
    ///
    /// **The host cannot check that they are one.** It holds no roster, and this party
    /// presents nothing — the obligation sits with the transferring owner, who can see the
    /// group. A host must not invent a check it has no basis for, nor treat its own
    /// ignorance as evidence: doing so would fail every transfer on a correct host.
    pub new_owner_did: String,
    /// Must confer `admin` — the same grant that mints epochs.
    pub presentation: AuthorityPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `rooms/owner/claim/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimOwnerBody {
    pub room_id: String,
    /// The succession credential the room issued to this claimant, serialized per the
    /// governing profile. The previous owner decided this in advance; a host checks a
    /// decision rather than making one.
    pub nomination: String,
    /// The claimant's own membership and authority.
    ///
    /// A host cannot see the MLS group, so this — the room's own statement that the claimant
    /// is a member — is the only membership signal available, and it is the same one every
    /// other room task presents.
    pub presentation: AuthorityPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `rooms/owner/{transfer,claim}/0.1#response`. One shape, because both end the same way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerResponse {
    pub room_id: String,
    pub owner_did: String,
}

/// `rooms/epoch/mint/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintEpochBody {
    pub room_id: String,
    pub epoch: u32,
    pub presentation: AuthorityPresentation,
    /// The rung this advance produces — see [`EpochLink`].
    ///
    /// Absent where the room does not keep its history readable, and necessarily absent for
    /// a room's first epoch. A host that receives one MUST refuse it unless its `epoch`
    /// matches, and MUST NOT replace a rung it already holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<EpochLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `rooms/epoch/chain/0.1` request.
///
/// A member asks a host for the room's epoch key chain, so records sealed before they
/// joined can still be opened. The chain is walked *downwards*, which is why this pages with
/// `from_epoch` rather than the `since_version` watermark its records sibling uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainBody {
    pub room_id: String,
    pub presentation: AuthorityPresentation,
    /// Return only rungs at or below this epoch. Absent means from the current epoch down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `rooms/epoch/chain/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainResponse {
    pub room_id: String,
    /// The rungs, highest epoch first and contiguous within the range returned.
    pub links: Vec<EpochLink>,
}

/// `rooms/epoch/mint/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintEpochResponse {
    pub room_id: String,
    pub epoch: u32,
}
