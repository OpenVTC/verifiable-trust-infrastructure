//! Operator-uploaded endorsement type registry — Phase 4
//! M4.8.0 (D4 planning review).
//!
//! ## Why a separate keyspace
//!
//! Per planning-review D4, only registered endorsement types
//! are issuable. The issuance path (M4.8.2) consults this
//! registry at every POST — refusing unknown types with a
//! `422 endorsement-type-not-registered`. The deletion path
//! (M4.8.1) refuses to drop a type while live endorsements
//! still reference it (`409 endorsement-type-in-use`).
//!
//! Workspace-reserved types — currently only `"CommunityRole"`
//! (VEC-managed; see [`crate::credentials::vec`]) — are
//! refused at registration time so they can never enter the
//! issuance path.

pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub use storage::{
    ENDORSEMENT_TYPES_PREFIX, delete_type, get_type, list_types, store_type, type_exists,
};

/// Reserved type URIs that operators cannot register because
/// they collide with workspace-managed semantics. Phase 4
/// only reserves `"CommunityRole"` — the VEC role-grant
/// type. Adding more reserved names is additive (the
/// registrar refuses; existing rows on disk that happen to
/// share a reserved name keep working — operators upgraded
/// across the reservation boundary aren't broken).
pub const RESERVED_TYPE_URIS: &[&str] = &["CommunityRole"];

/// The endorsement type the default `personhood.rego` accepts as
/// in-person vetting evidence.
///
/// Deliberately **not** in [`RESERVED_TYPE_URIS`]. Reserved means
/// "operators may not register this", and the whole flow depends on an
/// operator registering it: `vtc/endorsement-types/register/0.1` first,
/// then `vtc/endorsements/issue/0.1` to each vetted member. Reserving it
/// would make the issuance path refuse the very credential the policy
/// looks for.
///
/// It is a constant here so the Rust side, the default policy module and
/// the operator docs cannot drift apart — the failure mode of a
/// mismatched string is a community that vets members correctly and then
/// denies every assertion, with nothing in the logs naming the typo.
/// [`crate::policy::default`]'s tests pin the two together.
///
/// The name is the DTG spec's, not ours: §Identity Verification
/// Credentials defines an IDVC as any W3C VC meeting a community's
/// identity-proofing requirements, explicitly *not* a `DTGCredential`
/// subtype. Issuing it as an endorsement keeps it a plain W3C VC that
/// happens to be revocable through the community's existing status list.
pub const IDENTITY_VERIFICATION_TYPE_URI: &str = "IdentityVerification";

/// A registered endorsement type. Stored verbatim; the
/// registrar route enforces validation at insert time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct EndorsementType {
    /// The type URI. Primary key — URL-encoded into the
    /// keyspace key.
    pub type_uri: String,
    /// Optional JSON Schema for the claim body. Reserved for
    /// future per-type validation; the Phase 4 issuance path
    /// only checks "type is registered" without consulting
    /// the schema. Operators can read the schema from
    /// `GET /v1/endorsement-types/{uri}` and validate
    /// client-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_schema: Option<JsonValue>,
    /// Free-form description shown in admin UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Admin DID that registered the type. Carried for
    /// audit correlation against the
    /// `EndorsementTypeRegistered` envelope.
    pub created_by_did: String,
}

/// Maximum byte size of a `type_uri`. Bounds the keyspace key
/// length + protects against pathological inputs. Mirrors the
/// `endorsement.claim` body cap structure (smaller because
/// type URIs are short by convention).
pub const TYPE_URI_MAX_BYTES: usize = 512;
