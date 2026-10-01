//! Community-issued statement and grant records — Phase 4 M4.7 + M4.8.
//! Spec §6.1 "Custom endorsement" row.
//!
//! ## What this module owns
//!
//! - `Endorsement` — the persisted row recording a credential the community
//!   issued about a subject and can revoke through
//!   `vtc/endorsements/revoke/0.1`. Stored in the `endorsements:` keyspace
//!   keyed by UUID. The name is kept from when every such credential was an
//!   endorsement; `endorsement_type` says which kind of row it is:
//!   - a registered **predicate IRI** — a statement (VSC) minted by
//!     `vtc/endorsements/issue/0.1`: a VEC under `endorses/1`, or the
//!     community's own identity check under `vetted/1`;
//!   - `role:vetter` ([`VETTER_GRANT_ROW_TYPE`]) — a vetter role **VAC**
//!     issued by `vtc/vetting/vetters/grant/0.1`, which keeps its record
//!     here so the same revoke task withdraws it.
//!
//!   `role:vetter` is not a predicate IRI, so it cannot collide with a
//!   registered predicate. (Historical: rows typed
//!   `IdentityVerificationCredential` were written by releases that minted the
//!   community's identity check as a plain W3C VC; they still list and revoke.)
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

/// `endorsement_type` of a vetter-grant row: the VAC action the grant confers.
/// Not an absolute predicate IRI, so no registered predicate can equal it.
pub const VETTER_GRANT_ROW_TYPE: &str = vta_sdk::protocols::vetting::VETTER_ROLE_ACTION;

pub use storage::{
    ENDORSEMENTS_PREFIX, count_live_by_type, delete_endorsement, endorsements_by_type,
    endorsements_for_subject, get_endorsement, list_endorsements, list_endorsements_matching,
    mark_revoked, store_endorsement,
};

/// A stored community-issued credential record. The accompanying credential
/// body isn't persisted here for statements — the route layer hands the
/// signed VC to the caller verbatim on issue; downstream consumers (verifiers,
/// list endpoints) re-fetch from the credential's `id` if they need the proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct Endorsement {
    /// Server-allocated UUID. Forms `credential_id`'s
    /// `urn:uuid:<id>` shape.
    pub id: Uuid,
    /// What the row records: a registered predicate IRI (a statement, which
    /// must match a row in the `endorsement_types:` keyspace at issue time —
    /// route-layer invariant; storage trusts it), [`VETTER_GRANT_ROW_TYPE`]
    /// for a vetter grant, or — on rows older releases wrote — the retired
    /// identity-verification type. See the module docs. Wire
    /// `typeUri`.
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
    /// `urn:uuid:<id>` by construction. Stored as `vecId` on rows written
    /// before statements and grants stopped being endorsement credentials.
    #[serde(alias = "vecId")]
    pub credential_id: String,
    pub created_at: DateTime<Utc>,
    /// `Some(_)` once `DELETE /v1/credentials/endorsements/{id}`
    /// fires. The row stays in the keyspace for audit + list
    /// surfaces; only the status-list bit + `revoked_at` flip.
    /// (Mirrors the `Tombstone` / `Historical` Member-row
    /// pattern.)
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    /// The credential's `validUntil`. Absent on rows written before it was
    /// recorded; those rows' lifetime is unknown here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Issued by the automatic vetter-grant sweep rather than by an admin. The
    /// sweep revokes only rows that carry this. Absent (false) on every other
    /// row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_granted: bool,
    /// The signed credential, kept so it can be delivered again
    /// (`vtc/vetting/vetters/resend/0.1`). Recorded for vetter grants; absent
    /// on other endorsements and on rows written before it was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub credential: Option<JsonValue>,
}

impl Endorsement {
    /// `true` once the row has been revoked. Used by the
    /// type-registry deletion path to count *live*
    /// endorsements only.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}
