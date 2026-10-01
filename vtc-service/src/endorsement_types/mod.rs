//! The community's **predicate accept list** — Phase 4 M4.8.0 (D4 planning
//! review), kept under its original name, `vtc/endorsement-types/*`.
//!
//! ## What an entry is
//!
//! A registered `typeUri` is a **predicate IRI** the community accepts: a
//! DTG VSC predicate registry IRI (`https://registry.trustoverip.org/dtg/vsc/
//! …/1`) or an IRI in a namespace the community controls, defined in the
//! registry's predicate definition format (vtc/_shared/0.1/endorsement-type).
//! A DTG statement carries its meaning in `credentialSubject.predicate`; the
//! registered set is what this community will honour:
//!
//! - **Issuance** (`vtc/endorsements/issue/0.1`) mints a VSC only under a
//!   registered predicate, refusing anything else with `typeNotRegistered`.
//! - **Verification** of presented statements fails closed through
//!   [`accept_list`], a `dtg_credentials::PredicateAcceptList` built from the
//!   registered set: a statement under an unlisted predicate is rejected,
//!   never processed as a generic statement.
//!
//! The deletion path (M4.8.1) refuses to drop a predicate while live
//! statements still reference it (`409 endorsement-type-in-use`).
//!
//! Roles are not endorsements and are never registered here: a role is
//! conferred by a VAC (vtc/vetting/vetters/grant/0.1). URIs the implementation
//! reserves for its own records ([`RESERVED_TYPE_URIS`]) are refused at
//! registration; so is anything that is not an absolute predicate IRI
//! (`invalidUri`).

pub mod storage;

use chrono::{DateTime, Utc};
use dtg_credentials::PredicateAcceptList;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

pub use storage::{
    ENDORSEMENT_TYPES_PREFIX, all_types, delete_type, get_type, list_types, store_type, type_exists,
};

/// `typeUri`s this implementation reserves for its own `endorsements:` rows,
/// refused at registration (`vtc/endorsement-types/register:reserved`): the
/// vetter-grant row type (`role:vetter`). It is not a predicate IRI, so the
/// IRI check would refuse it too; naming it here gives the operator the more
/// useful answer.
pub const RESERVED_TYPE_URIS: &[&str] = &[crate::endorsements::VETTER_GRANT_ROW_TYPE];

/// The predicates a fresh community accepts: the four core profiles of the
/// DTG VSC predicate registry. Seeded once, like the schema registry
/// defaults; an operator deletes what the community does not honour.
///
/// `vetted/1` is what a peer-vetting criterion counts (`statementType`),
/// `witnessed/1` what a witnessed relationship presents, `endorses/1` the
/// favourable-claim predicate `vtc/endorsements/issue/0.1` mints a VEC under,
/// and `presented/1` the witnessed-presentation counterpart.
pub const DEFAULT_ACCEPTED_PREDICATES: [&str; 4] = [
    dtg_credentials::ENDORSES_V1,
    dtg_credentials::WITNESSED_V1,
    dtg_credentials::VETTED_V1,
    dtg_credentials::PRESENTED_V1,
];

/// Build the community's fail-closed accept list from its registered
/// predicates.
///
/// A stored row whose `typeUri` is not a predicate IRI — one registered before
/// registration checked — is skipped rather than failing the whole list: it
/// can never match a statement's predicate, so leaving it out accepts nothing
/// it would have accepted, and one bad row must not make every statement
/// unverifiable. It is logged so the operator can delete it.
pub async fn accept_list(ks: &KeyspaceHandle) -> Result<PredicateAcceptList, AppError> {
    let iris: Vec<String> = all_types(ks)
        .await?
        .into_iter()
        .filter_map(
            |t| match dtg_credentials::check_predicate_iri(&t.type_uri) {
                Ok(()) => Some(t.type_uri),
                Err(e) => {
                    tracing::warn!(
                        type_uri = %t.type_uri,
                        error = %e,
                        "registered endorsement type is not a predicate IRI; it accepts nothing — \
                         delete it"
                    );
                    None
                }
            },
        )
        .collect();
    PredicateAcceptList::from_iris(iris)
        .map_err(|e| AppError::Internal(format!("predicate accept list: {e}")))
}

/// The marker recording that [`seed_defaults`] has run, so a default an
/// operator deleted does not come back on the next boot. Outside
/// [`ENDORSEMENT_TYPES_PREFIX`], so no listing sees it.
const SEEDED_MARKER: &[u8] = b"meta:predicates-seeded:v1";

/// The DID recorded as the registrant of a seeded default — the same
/// system author the schema registry's defaults carry.
const SEED_AUTHOR: &str = "did:vtc:system";

/// Seed [`DEFAULT_ACCEPTED_PREDICATES`] once, at community boot. Each default
/// already registered is left as the operator has it; after the first run the
/// marker keeps an operator's deletions deleted. Returns how many were added.
pub async fn seed_defaults(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    if ks.get_raw(SEEDED_MARKER.to_vec()).await?.is_some() {
        return Ok(0);
    }
    let now = Utc::now();
    let mut added = 0;
    for iri in DEFAULT_ACCEPTED_PREDICATES {
        if type_exists(ks, iri).await? {
            continue;
        }
        store_type(
            ks,
            &EndorsementType {
                type_uri: iri.to_string(),
                claim_schema: None,
                description: Some(
                    "DTG VSC predicate registry core profile (seeded default)".into(),
                ),
                created_at: now,
                created_by_did: SEED_AUTHOR.to_string(),
            },
        )
        .await?;
        added += 1;
    }
    ks.insert_raw(SEEDED_MARKER.to_vec(), now.to_rfc3339().into_bytes())
        .await?;
    Ok(added)
}

/// A registered predicate (historically "endorsement type"). Stored
/// verbatim; the registrar route enforces validation at insert time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct EndorsementType {
    /// The predicate IRI. Primary key — URL-encoded into the
    /// keyspace key.
    pub type_uri: String,
    // Binding since #1649: `vtc/endorsements/issue/0.1` validates the claim
    // against it and refuses a violation with `claimSchemaViolation`. It was
    // stored and never read before that, which is why registration did not
    // check it was a schema at all — and why a type registered with a
    // malformed one turned every later issuance into a 500. The registrar
    // refuses a `claimSchema` that will not compile
    // (`crate::schemas::check_schema`); rows written before that check are
    // reported at boot and named in the refusal issuance answers with.
    //
    // The doc comment below is rendered into `admin-ui/openapi.json` (and from
    // there into `wire.ts`), so it stays short and operator-facing; the history
    // is in this ordinary comment, which utoipa does not read.
    /// Optional JSON Schema every claim of this predicate must satisfy — the
    /// statement's `object.value`. Issuance validates the claim against it and
    /// refuses a violation.
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
