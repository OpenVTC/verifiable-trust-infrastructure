//! VRC (Verifiable Relationship Credential) trust-graph
//! storage — Phase 4 M4.5. Spec §5.4 + §6.1.
//!
//! ## What this module owns
//!
//! - The `relationships:` keyspace: one row per VRC, keyed by
//!   `relationships:<uuid>`. The row stores the verified VC
//!   JSON-LD body verbatim plus metadata for list / revoke
//!   surfaces.
//! - The `relationships_by_did:` secondary-index keyspace: one
//!   row per (DID, VRC-id) pair, written for BOTH the issuer
//!   and the subject so per-DID list queries are O(prefix-scan)
//!   instead of O(full-table). Keys are
//!   `relationships_by_did:<did>:<vrc-id>` so a `prefix_iter`
//!   on `relationships_by_did:<did>:` returns just that DID's
//!   edges.
//!
//! ## Why two keyspaces
//!
//! The natural per-DID query is "list all VRCs where I'm
//! issuer OR subject". A single keyspace + filter would walk
//! every row. The secondary index keeps the per-DID list
//! pageable in O(matched-rows) — the same trade-off the
//! audit log uses for its actor index.
//!
//! Writes are CAS-paired: store the primary row, then both
//! secondary-index rows. Delete is the inverse. A crash
//! between the primary write and the index writes is
//! self-healing on the next list-for-did call (it walks the
//! index and the primary is fjall-durable; the index entries
//! are tolerant of an orphan). A crash between the index
//! writes is similarly recoverable — list-for-did returns
//! whatever index entries are present + the route layer
//! deals with the primary-row absent case (404 on subsequent
//! ops).
//!
//! ## Issuer = the member, not the community
//!
//! Per planning-review D1, the VTC never *mints* VRCs. The
//! issuer of every stored row is a current community member
//! (the route layer verifies caller-DID == VC.issuer + the
//! VC's data-integrity proof verifies against the member's
//! `#key-0`). The community signer is uninvolved.
//!
//! The same holds for the optional [`PersonaAnnotation`]: the
//! VPC is self-issued by the member under a persona DID, and the
//! VTC only verifies and stores it.

pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

pub use storage::{
    RELATIONSHIPS_BY_DID_PREFIX, RELATIONSHIPS_PREFIX, delete_relationship, find_by_hash,
    get_relationship, issuer_counterparties_besides, list_all, list_for_did, store_relationship,
};

/// A stored, verified VRC. Field order matches the spec §5.4
/// surface (issuer/subject DIDs + the credential body).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct Relationship {
    /// Server-allocated UUID. Surfaced as `urn:uuid:<id>` on
    /// the VRC's top-level `id` field at publish time when
    /// the caller didn't supply one.
    pub id: Uuid,
    /// The asserting member. By the publish-time auth check,
    /// this equals the caller's session DID.
    pub issuer_did: String,
    /// The other party the VRC names. Need not be a current
    /// community member at *list* time (the list path strips
    /// Purge-removed rows per §12.3) but must be a current
    /// member at *publish* time (default `relationships.rego`).
    pub subject_did: String,
    /// The VRC body verbatim — JSON-LD, including the
    /// data-integrity proof. Stored as `JsonValue` rather
    /// than a typed `VerifiableCredential` so future VRC
    /// shape extensions don't require a storage migration.
    pub vrc_jsonld: JsonValue,
    /// SHA-256 of `canonical_json(vrc_jsonld)`, hex-encoded.
    /// Used for idempotency: a second publish of an
    /// already-stored VRC returns the existing id (200)
    /// rather than creating a duplicate row.
    pub vrc_sha256: String,
    pub created_at: DateTime<Utc>,
    /// The persona (VPC) this edge's issuer has asserted on it,
    /// if any. Absent on every edge published before #1067 and
    /// on every edge whose issuer has not asserted a persona —
    /// which is why it is `#[serde(default)]`: existing rows
    /// decode unchanged.
    ///
    /// A VPC is an *annotation* credential (DTG Credentials
    /// §Annotation Credentials): it creates no graph structure,
    /// it attaches to structure that already exists. Storing it
    /// on the edge row rather than in a keyspace of its own is
    /// the direct expression of that — there is no persona
    /// record without an edge to hang it on, and deleting the
    /// edge deletes the annotation with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona: Option<PersonaAnnotation>,
}

/// A Verifiable Persona Credential (VPC) attached to one edge.
///
/// The VPC is issued by the *edge issuer* under a persona DID
/// (P-DID) and names the edge's counterparty as its subject. It
/// is the sanctioned mechanism for deliberate correlation: a
/// member who wants several of their pairwise edges to be
/// recognisable as one party asserts the same P-DID on each,
/// without ever putting their membership DID in a credential.
///
/// See `docs/05-design-notes/vpc-persona-annotation.md` for how
/// the annotation is bound to the edge, and for what upstream
/// (trustoverip/dtgwg-cred-spec#9) has not yet settled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PersonaAnnotation {
    /// The VPC's `issuer` — the P-DID. Denormalised out of
    /// `vpc_jsonld` so the graph view can group edges by persona
    /// without re-parsing every credential.
    pub persona_did: String,
    /// The VPC body verbatim, including its data-integrity
    /// proof, so a consumer of the row can re-verify the
    /// assertion rather than taking the VTC's word for it.
    pub vpc_jsonld: JsonValue,
    pub attached_at: DateTime<Utc>,
}
