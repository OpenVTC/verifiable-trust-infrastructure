//! VTC schema store — the community's credential-type registry (task 2.2,
//! `docs/05-design-notes/vti-credential-architecture.md` §8).
//!
//! A community declares the credential types it deals in:
//!
//! - **Issues** — the types this VTC *mints* (Invitation, Membership, Role, and
//!   operator-defined endorsements), each bound to a DTG catalog type and an
//!   optional JSON Schema (`credentialSchema`). Issuance consults this registry,
//!   and issue-time validation (task 2.3) checks a minted credential against the
//!   schema.
//! - **Accepts** — the types/criteria the community recognises as *evidence*.
//!   The Accepts half is expressed as a DCQL query over this registry and lands
//!   in task 2.4.
//!
//! The store is one `schemas` keyspace, generalising the existing
//! [`endorsement_types`](crate::endorsement_types) registry (same key-encoding
//! discipline, broadened to every catalog type + an Issues/Accepts dimension).

pub mod storage;
pub mod validate;

pub use validate::{validate_instance, validate_issued};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

pub use storage::{
    SCHEMAS_PREFIX, delete_schema, get_schema, list_by_kind, list_schemas, schema_exists,
    store_schema,
};

/// Maximum byte size of a `type_uri` (bounds the keyspace key length). Mirrors
/// [`crate::endorsement_types::TYPE_URI_MAX_BYTES`].
pub const TYPE_URI_MAX_BYTES: usize = 512;

/// Whether a registered schema describes a credential type the community
/// **Issues** (mints) or **Accepts** (recognises as evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SchemaKind {
    /// The VTC mints this credential type.
    Issues,
    /// The VTC recognises this credential type as evidence (task 2.4).
    Accepts,
}

/// One registered credential-type schema in the community's schema store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaEntry {
    /// The credential type URI / `vct`. Primary key — URL-encoded into the key.
    pub type_uri: String,
    /// The DTG catalog type this binds to (a `DTGCredentialType` string, e.g.
    /// `"MembershipCredential"`). `None` for community-defined endorsement types
    /// that map onto the generic `EndorsementCredential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtg_type: Option<String>,
    /// The JSON Schema (W3C `credentialSchema`) an issued/accepted credential
    /// must conform to. Validated at issue time (task 2.3). `None` means
    /// "registered, but no schema constraint".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<JsonValue>,
    /// Issues (the VTC mints it) or Accepts (recognised as evidence).
    pub kind: SchemaKind,
    /// Free-form description shown in admin UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Admin DID that registered the schema (audit correlation).
    pub created_by_did: String,
}

impl SchemaEntry {
    /// True when this entry is an `Issues` registration.
    pub fn is_issues(&self) -> bool {
        self.kind == SchemaKind::Issues
    }
}

/// Whether `type_uri` is registered as an **Issues** type — the gate the
/// issuance path consults ("only registered types may be minted").
pub async fn is_issues_registered(ks: &KeyspaceHandle, type_uri: &str) -> Result<bool, AppError> {
    Ok(get_schema(ks, type_uri)
        .await?
        .is_some_and(|s| s.is_issues()))
}
