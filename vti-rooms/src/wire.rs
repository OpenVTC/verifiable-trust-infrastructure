//! Wire types for the `rooms/*` Trust Tasks.
//!
//! # Why these are hand-written
//!
//! They mirror the payload schemas proposed in
//! `trustoverip/dtgwg-trust-tasks-tf#346`, and are written here rather than taken from
//! `trust_tasks_rs::specs` because that PR is still in review — the generated bindings do
//! not exist yet. This is the same shape `vta_sdk::protocols::*` already uses for the VTA's
//! families: hand-written wire types beside the generated ones.
//!
//! **When #346 merges and `trust-tasks-rs` publishes, replace these with the generated
//! types rather than keeping both.** Two definitions of one wire format is how casing drift
//! gets in, and this workspace has paid for that before.
//!
//! Every struct is `camelCase` and `deny_unknown_fields`: these carry authorization
//! decisions, and an unknown member on one of those is a request that means something the
//! service did not understand.

use serde::{Deserialize, Serialize};

use crate::{RecordStatus, Visibility};

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
/// `rooms/records/curate/0.1`.
pub const ROOMS_RECORDS_CURATE_TYPE: &str = "https://trusttasks.org/spec/rooms/records/curate/0.1";

/// Every `rooms/*` URI this service dispatches.
pub const ROOMS_DISPATCHED_URIS: &[&str] = &[
    ROOMS_CREATE_TYPE,
    ROOMS_RECORDS_PUT_TYPE,
    ROOMS_RECORDS_GET_TYPE,
    ROOMS_RECORDS_LIST_TYPE,
    ROOMS_EPOCH_MINT_TYPE,
    ROOMS_RECORDS_CURATE_TYPE,
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

/// `rooms/records/list/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRecordsResponse {
    /// Metadata only — never bodies.
    pub records: Vec<serde_json::Value>,
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

/// `rooms/epoch/mint/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintEpochBody {
    pub room_id: String,
    pub epoch: u32,
    pub presentation: AuthorityPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `rooms/epoch/mint/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintEpochResponse {
    pub room_id: String,
    pub epoch: u32,
}
