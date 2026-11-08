use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ContextRecord {
    /// The context's materialized path identifier — slash-separated segments
    /// (e.g. `acme/eng/team-a`). A top-level context is a single segment.
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    /// The parent context's id, or `None` for a top-level context. Together
    /// with [`id`](Self::id) this records the tree; absent on legacy (flat)
    /// records, which deserialize as top-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// BIP-32 derivation base for this context's keys. For a sub-context this
    /// nests under the parent's base (`{parent.base_path}/<child>'`).
    #[serde(alias = "base_path")]
    pub base_path: String,
    pub index: u32,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
    /// Per-context policy constraining what context-scoped actors may do within
    /// this context (see [`crate::context_policy::ContextPolicy`]). Absent on
    /// legacy records and by default, which imposes no constraints — enforcement
    /// resolves the policy across the whole ancestor chain, so a missing policy
    /// at any level simply contributes nothing.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "context_policy"
    )]
    pub context_policy: Option<crate::context_policy::ContextPolicy>,
    /// Key id, within this context, designated to sign credentials issued
    /// **as this context's DID**.
    ///
    /// Separate from "any key in the context": a context may hold many keys for
    /// many purposes, but a credential's `issuer` must be the DID whose
    /// verification method produced the proof, so exactly one of them is the
    /// issuing key. Naming it here is what lets a context-scoped caller issue
    /// without ever choosing a key — the caller states intent, the VTA resolves
    /// mechanism.
    ///
    /// Absent means this context cannot issue credentials, and
    /// `credentials/issue-in-context` **fails closed** rather than falling back
    /// to the VTA's own key, which would attribute the credential to the VTA
    /// instead of the context.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "issuer_key_id"
    )]
    pub issuer_key_id: Option<String>,
}
