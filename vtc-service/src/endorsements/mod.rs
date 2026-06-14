//! Custom endorsement credentials — Phase 4 M4.7 + M4.8.
//! Spec §6.1 "Custom endorsement" row.
//!
//! ## What this module owns
//!
//! - `Endorsement` — the persisted row recording a custom
//!   endorsement issued by an Issuer-role member (or admin)
//!   for a subject. Stored in the `endorsements:` keyspace
//!   keyed by UUID.
//! - Storage helpers: round-trip, list (paginated), mark
//!   revoked, find live-by-type.
//! - **Live-by-type check** is load-bearing for the type
//!   registry deletion path (M4.8.1) — operators can't drop a
//!   type while live endorsements still exist.
//!
//! Per planning-review D4, the *type registry* itself lives
//! in [`crate::endorsement_types`] — only registered URIs
//! are issuable. The endorsements module here trusts that
//! invariant; the route layer enforces it at issue time.

pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

pub use storage::{
    ENDORSEMENTS_PREFIX, count_live_by_type, delete_endorsement, get_endorsement,
    list_endorsements, mark_revoked, store_endorsement,
};

/// A stored custom endorsement. The accompanying VEC body
/// isn't persisted here — the route layer hands the signed
/// VC to the caller verbatim on issue; downstream consumers
/// (verifiers, list endpoints) re-mint or re-fetch from the
/// VEC's `id` field if they need the proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct Endorsement {
    /// Server-allocated UUID. Forms `vec_id`'s
    /// `urn:uuid:<id>` shape.
    pub id: Uuid,
    /// Operator-registered endorsement type URI. Must match
    /// a row in the `endorsement_types:` keyspace at issue
    /// time (route-layer invariant; storage trusts it).
    pub endorsement_type: String,
    /// The community DID (always `signer.issuer_did()` at
    /// issue time). Kept on the row so list responses don't
    /// need to re-look up the signer.
    pub issuer_did: String,
    pub subject_did: String,
    /// Free-form per-type claim body. JSON object only;
    /// route-layer enforces 8 KiB cap.
    pub claim: JsonValue,
    /// Allocated slot on the shared `Revocation` status list
    /// (D8 review — endorsements reuse the existing list).
    pub status_list_index: u32,
    /// The credential's top-level `id` field —
    /// `urn:uuid:<id>` by construction.
    pub vec_id: String,
    pub created_at: DateTime<Utc>,
    /// `Some(_)` once `DELETE /v1/credentials/endorsements/{id}`
    /// fires. The row stays in the keyspace for audit + list
    /// surfaces; only the status-list bit + `revoked_at` flip.
    /// (Mirrors the `Tombstone` / `Historical` Member-row
    /// pattern.)
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Endorsement {
    /// `true` once the row has been revoked. Used by the
    /// type-registry deletion path to count *live*
    /// endorsements only.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}
