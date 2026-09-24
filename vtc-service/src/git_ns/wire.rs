//! Records → the generated wire types.
//!
//! Every response a `git-ns/*` task returns is one of the types generated from
//! the specification (`trust_tasks_rs::specs::git_ns`). Each task module
//! carries its own copy of the shared definitions (`RepoSummary`,
//! `RightRecord`, …) and those types are `#[non_exhaustive]`, so they are
//! reached the one way that works for all of them: the JSON the shared schema
//! describes, deserialised into the task's own type. That deserialisation is
//! also a check — the generated types refuse a member the schema does not
//! know, and their newtypes refuse a value outside its pattern — so a record
//! that would put a non-conforming document on the wire fails here, loudly,
//! rather than at a peer.

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::model::{Namespace, Repo, Resource, RightRow};

/// Deserialise `value` into the generated type `T`.
pub fn into<T: DeserializeOwned>(value: Value) -> Result<T, AppError> {
    let type_name = std::any::type_name::<T>();
    serde_json::from_value(value).map_err(|e| {
        AppError::Internal(format!(
            "a git-ns record does not fit its wire type {type_name}: {e}"
        ))
    })
}

/// `GitNamespace` of the shared schema.
pub fn namespace(ns: &Namespace) -> Value {
    let mut v = json!({
        "id": ns.id,
        "forge": ns.forge,
        "owner": ns.owner,
        "mode": ns.mode.as_str(),
        "state": match ns.state {
            super::model::NamespaceState::Pending => "pending",
            super::model::NamespaceState::Bound => "bound",
        },
    });
    if let Some(kind) = ns.kind {
        v["kind"] = json!(kind.as_str());
    }
    v
}

/// `RepoSummary` of the shared schema. `owners` are the explicit owners —
/// "who owns a repository is visible to every member".
pub fn repo_summary(repo: &Repo, owners: &[String]) -> Value {
    let mut sync = json!({
        "state": repo.sync.state.as_str(),
        "drift": repo.sync.drift,
    });
    if let Some(at) = repo.sync.checked_at {
        sync["checkedAt"] = json!(at);
    }
    let mut v = json!({
        "resource": repo.resource,
        "visibility": repo.visibility.as_str(),
        "state": repo.state.as_str(),
        "owners": owners,
        "bootstrap": {
            "workflow": repo.bootstrap.workflow,
            "keyring": repo.bootstrap.keyring,
            "variables": repo.bootstrap.variables,
            "requiredCheck": repo.bootstrap.required_check,
        },
        "sync": sync,
    });
    if let Some(id) = &repo.forge_id {
        v["forgeId"] = json!(id);
    }
    v
}

/// `RightRecord` of the shared schema. `with_reason` is the view's gate:
/// the reason goes only to owners and admins of the resource.
pub fn right_record(row: &RightRow, resource: &Resource, with_reason: bool) -> Value {
    let mut v = json!({
        "subject": row.subject,
        "right": row.right.as_str(),
        "resource": resource.to_string(),
        "grantedBy": row.granted_by,
        "grantedAt": timestamp(row.granted_at),
    });
    if let Some(e) = row.expires_at {
        v["expiresAt"] = json!(timestamp(e));
    }
    if with_reason && let Some(r) = &row.reason {
        v["reason"] = json!(r);
    }
    v
}

/// RFC 3339 with whole seconds — what the specification's examples carry and
/// what every other member of a record is compared against.
pub fn timestamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
