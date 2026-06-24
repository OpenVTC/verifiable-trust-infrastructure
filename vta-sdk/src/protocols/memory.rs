//! Wire payloads for the agent-memory Trust Tasks
//! (`spec/vta/memory/{put,list,delete}/0.1`).
//!
//! A per-context key/value store for AI-agent memory: `put` upserts a value
//! under a `(contextId, key)` pair, `list` enumerates every entry in a context,
//! and `delete` removes one by key. The three request bodies carry
//! `deny_unknown_fields` as a forward-compat guard; all fields are camelCase on
//! the wire.
//!
//! Access is gated on **context** (not operator step-up like the issued-
//! credential slice): the caller must be permitted to act in `contextId` — the
//! same context-ACL check the context-scoped key tasks use
//! ([`AuthClaims::require_context`] server-side). This enforces per-domain
//! memory isolation: a context-A agent cannot read, write, or delete context-B
//! memory.

use serde::{Deserialize, Serialize};

/// `spec/vta/memory/put/0.1` request body. Upsert: re-putting the same
/// `(contextId, key)` replaces the stored value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryPutBody {
    /// The context the entry belongs to. The caller must have ACL access to it.
    pub context_id: String,
    /// The entry key (unique within the context).
    pub key: String,
    /// The value to store.
    pub value: String,
}

/// `spec/vta/memory/put/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryPutResponse {
    /// The key that was upserted.
    pub key: String,
}

/// `spec/vta/memory/list/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryListBody {
    /// The context whose entries to list. The caller must have ACL access to it.
    pub context_id: String,
}

/// A single stored memory entry returned by `spec/vta/memory/list/0.1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItem {
    /// The entry key.
    pub key: String,
    /// The stored value.
    pub value: String,
}

/// `spec/vta/memory/list/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryListResponse {
    /// Every entry in the context, in ascending key order.
    pub items: Vec<MemoryItem>,
}

/// `spec/vta/memory/delete/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryDeleteBody {
    /// The context the entry belongs to. The caller must have ACL access to it.
    pub context_id: String,
    /// The entry key to delete. `not_found` if absent.
    pub key: String,
}

/// `spec/vta/memory/delete/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryDeleteResponse {
    /// The key that was deleted.
    pub key: String,
}
