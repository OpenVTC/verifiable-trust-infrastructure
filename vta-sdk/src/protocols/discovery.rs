//! Capability discovery.
//!
//! One question, one answer: **which Trust Tasks does this agent serve?** —
//! `trust-task-discovery/0.1`, the published canonical family, answered from the
//! agent's own dispatch table.
//!
//! # What used to be here
//!
//! `vta/discovery/capabilities/1.0` and the `discovery/1.0/*` DIDComm protocol
//! beside it, both retired in #1043. Between them they carried five members, and
//! by the end not one of them was the best answer to its own question:
//!
//! - `features` / `services` — the DID document is authoritative for which
//!   protocols a party speaks, and these answered from `cfg!` flags and local
//!   config respectively, either of which could contradict it (#1039).
//! - `version` — `GET /health/details` already reports it, at the same auth
//!   level and from the same `env!`.
//! - `webvhServers` — `webvh/servers/list/1.0` returns a strict superset
//!   (`{id, did, label, createdAt, updatedAt}` against `{id, label}`) at the
//!   same auth level, and is what every production caller already used.
//! - `didCreationModes` — no consumer anywhere, and a vocabulary
//!   (`vta-built` / `template` / `final` / `user-specified-keys`) that existed
//!   nowhere else in the codebase. It predated `WebvhPathMode`, which is the
//!   axis DID creation actually turns on now.
//!
//! The lesson worth keeping is the shape rather than the members: a task called
//! "capabilities" attracts fields, because every deployment fact looks like a
//! capability from far enough away. Discovery answers one question; anything
//! else belongs to the subsystem that owns it.

use serde::{Deserialize, Serialize};

/// Response to `trust-task-discovery/0.1` — the Trust Task types an agent
/// serves.
///
/// Deliberately a local mirror of the framework crate's `Response` rather than a
/// re-export: the SDK's `client` feature does not otherwise pull the generated
/// spec types, and the shape is two members. Kept `deny_unknown_fields`-free so
/// a responder at a later framework revision — which MAY add members — still
/// decodes here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SupportedTasksResponse {
    /// The Type URIs this agent serves, matching the requested patterns.
    pub supported_types: Vec<String>,
    /// MAJOR.MINOR of the Trust Tasks framework spec the responder targets.
    ///
    /// Optional in 0.1 and RECOMMENDED afterwards, so absent is a legitimate
    /// answer from an older peer rather than a malformed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_version: Option<String>,
}
