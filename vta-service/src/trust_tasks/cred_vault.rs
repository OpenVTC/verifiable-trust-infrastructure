//! Credential-vault trust-task slice — store / query / fetch the W3C credentials
//! a holder **holds** (invitations, memberships, roles, …) in the VTA's
//! credential vault (`docs/05-design-notes/vti-credential-architecture.md` §5).
//!
//! Distinct from the password-manager vault ([`super::vault`]): both share the
//! `vault` keyspace but use disjoint key namespaces (`cred:` here, `vault:`
//! there). The credential body is a presentable VC (not a raw secret like a
//! password), so it travels as plain JSON — no sealed envelope.
//!
//! - **receive** (`VaultWrite`): verify + store a Data-Integrity VC, resolving
//!   the issuer key from its DID (the wire layer's job — the data plane takes a
//!   resolved key). `purpose` is inferred from the VC `type` (e.g.
//!   `InvitationCredential` → invite) so a stored VIC is findable by purpose.
//! - **query** (`VaultRead`): DCQL-shaped filtered search → body-free
//!   descriptors. The data plane refuses an unfiltered query (no-enumeration).
//! - **get** (`VaultRead`): fetch one credential's full body by id, for
//!   presentation. Not-found is conflated with permission-denied to deny
//!   enumeration.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;
use vti_common::acl::{Capability, role_has_capability};
use vti_common::vault::{LifecycleError, VaultStatus};

use crate::auth::AuthClaims;
use crate::server::AppState;
use crate::vault::model::{CredentialPurpose, CredentialStatus};
use crate::vault::query::{CredentialDescriptor, CredentialQuery, search};
use crate::vault::{di_verify, receive, storage};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Capability gate, mirroring [`super::vault::require_capability`] for the
/// credential-vault surface (kept local so the two vault slices stay
/// independent).
fn require_cap(
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
    action: &str,
) -> Result<(), TrustTaskOutcome> {
    if role_has_capability(&auth.role, cap) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "credential-vault {action} denied: role {} does not carry {cap:?}",
                    auth.role
                ),
            },
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiveBody {
    /// The credential to store — a Data-Integrity W3C VC (object form, with its
    /// own `proof`).
    credential: Value,
    /// Optional explicit storage id; defaults to the VC's top-level `id`, else a
    /// fresh `urn:uuid`.
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiveResponse {
    id: String,
    types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<CredentialPurpose>,
    status: CredentialStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryResponse {
    credentials: Vec<CredentialDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetBody {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetResponse {
    /// The stored credential's full body, for presentation.
    credential: Value,
}

/// Handler for `spec/vault/credentials/receive/0.1`.
pub(super) async fn handle_receive(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::VaultWrite, "receive") {
        return r;
    }
    let req: ReceiveBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let id = resolve_storage_id(req.id, &req.credential);

    // Resolve the issuer's signing key from the credential's DID (did:key
    // locally, did:webvh / did:web via the cache) — the data plane verifies the
    // proof against it.
    let issuer_pub = match di_verify::resolve_di_issuer_key(
        state.did_resolver.as_ref(),
        &req.credential,
    )
    .await
    {
        Ok(k) => k,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let body = match serde_json::to_vec(&req.credential) {
        Ok(b) => b,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("credential serialise: {e}"),
                },
            );
        }
    };

    let stored = match receive::receive_di_vc(
        &state.vault_ks,
        &id,
        &body,
        &issuer_pub,
        Some("vault/credentials/receive/0.1".to_string()),
        Utc::now(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    success_response(
        &doc,
        ReceiveResponse {
            id: stored.id,
            types: stored.types,
            purpose: stored.purpose,
            status: stored.status,
        },
    )
}

/// Handler for `spec/vault/credentials/query/0.1`.
pub(super) async fn handle_query(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::VaultRead, "query") {
        return r;
    }
    let query: CredentialQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(resp) => return resp,
    };
    match search(&state.vault_ks, &query).await {
        Ok(credentials) => success_response(&doc, QueryResponse { credentials }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// The storage id for a received credential: an explicit caller-supplied id
/// wins, else the VC's top-level `id`, else a fresh `urn:uuid`. Kept pure so the
/// fallback precedence is unit-testable without an `AppState`.
fn resolve_storage_id(explicit: Option<String>, credential: &Value) -> String {
    explicit
        .or_else(|| {
            credential
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()))
}

/// Handler for `spec/vault/credentials/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::VaultRead, "get") {
        return r;
    }
    let req: GetBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match storage::get(&state.vault_ks, &req.id).await {
        // An archived / soft-deleted credential's body must not be handed out
        // for presentation — conflate it with not-found (same enumeration
        // stance as a genuinely absent id).
        Ok(Some(stored)) if stored.is_active() => {
            match serde_json::from_slice::<Value>(&stored.body) {
                Ok(credential) => success_response(&doc, GetResponse { credential }),
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("stored credential body is not JSON: {e}"),
                    },
                ),
            }
        }
        // Conflate not-found (and not-active) with permission-denied to deny enumeration.
        Ok(_) => reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "credential not found".to_string(),
                details: None,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Shared request body for the credential archival lifecycle verbs
/// (`archive` / `unarchive` / `delete` / `restore` / `purge`). `reason` is
/// lifted into the audit row's `detail` by the dispatch spine; `force` is
/// honoured only by `delete` (skip the grace window → immediate hard delete).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredLifecycleBody {
    id: String,
    #[serde(default)]
    #[allow(dead_code)] // read generically by the spine for the audit `detail`
    reason: Option<String>,
    #[serde(default)]
    force: bool,
}

/// Post-transition view for archive / unarchive / delete / restore.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredLifecycleResponse {
    id: String,
    lifecycle: VaultStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    grace_until: Option<String>,
}

/// `not_found` rejection for a missing credential id on a lifecycle verb.
fn cred_not_found(doc: &TrustTask<Value>, verb: &str, id: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::TaskFailed {
            reason: format!("vault/credentials/{verb}:not_found — no credential at id {id}"),
            details: None,
        },
    )
}

/// Map a [`LifecycleError`] to a Trust-Task rejection with an operator hint.
fn cred_lifecycle_reject(
    doc: &TrustTask<Value>,
    verb: &str,
    id: &str,
    err: LifecycleError,
) -> TrustTaskOutcome {
    let hint = match err {
        LifecycleError::NotActive => "credential is not active (already archived or deleted)",
        LifecycleError::NotArchived => "credential is not archived",
        LifecycleError::AlreadyDeleted => {
            "credential is already in the trash — restore it or purge it"
        }
        LifecycleError::NotDeleted => "credential is not in the trash",
        LifecycleError::GraceExpired => {
            "the grace window has elapsed — the credential has been (or is about to be) purged"
        }
    };
    reject_with(
        doc,
        RejectReason::TaskFailed {
            reason: format!("vault/credentials/{verb}:{} — {hint} (id {id})", err.code()),
            details: None,
        },
    )
}

fn cred_lifecycle_response(cred: &crate::vault::model::StoredCredential) -> CredLifecycleResponse {
    CredLifecycleResponse {
        id: cred.id.clone(),
        lifecycle: cred.lifecycle,
        grace_until: cred.grace_until.clone(),
    }
}

/// Handler for `spec/vault/credentials/archive/0.1`. Auth: CredentialWrite.
pub(super) async fn handle_archive(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let now = Utc::now().to_rfc3339();
    cred_transition(state, auth, doc, "archive", move |cred| cred.archive(&now)).await
}

/// Handler for `spec/vault/credentials/unarchive/0.1`. Auth: CredentialWrite.
pub(super) async fn handle_unarchive(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    cred_transition(state, auth, doc, "unarchive", |cred| cred.unarchive()).await
}

/// Handler for `spec/vault/credentials/restore/0.1`. Auth: CredentialWrite.
pub(super) async fn handle_restore(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let now = Utc::now().to_rfc3339();
    cred_transition(state, auth, doc, "restore", move |cred| cred.restore(&now)).await
}

/// Shared load → transition → re-store body for archive / unarchive / restore.
/// `storage::put` re-indexes, so a status/lifecycle change never orphans an
/// index row. Credentials carry no optimistic-concurrency version, so (unlike
/// the password vault) there is no `expectedVersion` gate here.
async fn cred_transition(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    verb: &str,
    transition: impl FnOnce(&mut crate::vault::model::StoredCredential) -> Result<(), LifecycleError>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::CredentialWrite, verb) {
        return r;
    }
    let req: CredLifecycleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let mut cred = match storage::get(&state.vault_ks, &req.id).await {
        Ok(Some(c)) => c,
        Ok(None) => return cred_not_found(&doc, verb, &req.id),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    if let Err(e) = transition(&mut cred) {
        return cred_lifecycle_reject(&doc, verb, &req.id, e);
    }
    if let Err(e) = storage::put(&state.vault_ks, &cred).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(&doc, cred_lifecycle_response(&cred))
}

/// Handler for `spec/vault/credentials/delete/0.1`. Default: recoverable soft
/// delete (tombstone + grace window). `force: true` → immediate hard delete
/// (tears down the `idx:` index too). Auth: CredentialWrite.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::CredentialWrite, "delete") {
        return r;
    }
    let req: CredLifecycleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Forced hard delete bypasses the grace window entirely (and works even on
    // an absent id — idempotent, like the storage primitive).
    if req.force {
        if let Err(e) = storage::delete(&state.vault_ks, &req.id).await {
            return app_error_to_reject(&doc, e);
        }
        return success_response(
            &doc,
            CredLifecycleResponse {
                id: req.id,
                lifecycle: VaultStatus::Deleted,
                grace_until: None,
            },
        );
    }

    let mut cred = match storage::get(&state.vault_ks, &req.id).await {
        Ok(Some(c)) => c,
        Ok(None) => return cred_not_found(&doc, "delete", &req.id),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let now = Utc::now();
    let grace_days = state.config.read().await.vault.grace_days;
    let grace_until = (now + chrono::Duration::days(grace_days as i64)).to_rfc3339();
    if let Err(e) = cred.soft_delete(&now.to_rfc3339(), &grace_until) {
        return cred_lifecycle_reject(&doc, "delete", &req.id, e);
    }
    if let Err(e) = storage::put(&state.vault_ks, &cred).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(&doc, cred_lifecycle_response(&cred))
}

/// Handler for `spec/vault/credentials/purge/0.1` — irreversible hard delete
/// (record + all index rows). Auth: CredentialWrite.
pub(super) async fn handle_purge(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::CredentialWrite, "purge") {
        return r;
    }
    let req: CredLifecycleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // `storage::delete` is idempotent (absent id is a no-op); surface a
    // not_found only when there was genuinely nothing to purge.
    match storage::get(&state.vault_ks, &req.id).await {
        Ok(Some(_)) => {}
        Ok(None) => return cred_not_found(&doc, "purge", &req.id),
        Err(e) => return app_error_to_reject(&doc, e),
    }
    if let Err(e) = storage::delete(&state.vault_ks, &req.id).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(
        &doc,
        CredLifecycleResponse {
            id: req.id,
            lifecycle: VaultStatus::Deleted,
            grace_until: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn storage_id_prefers_explicit_then_vc_id_then_uuid() {
        let vc = json!({ "id": "urn:uuid:from-vc", "type": ["InvitationCredential"] });

        // Explicit id wins.
        assert_eq!(
            resolve_storage_id(Some("explicit-id".into()), &vc),
            "explicit-id"
        );
        // Else the VC's own id.
        assert_eq!(resolve_storage_id(None, &vc), "urn:uuid:from-vc");
        // Else a generated urn:uuid.
        let generated = resolve_storage_id(None, &json!({ "type": ["X"] }));
        assert!(
            generated.starts_with("urn:uuid:"),
            "fallback id is a urn:uuid: {generated}"
        );
    }

    #[test]
    fn receive_body_parses_with_and_without_id() {
        let with_id: ReceiveBody =
            serde_json::from_value(json!({ "credential": {"id": "x"}, "id": "y" })).unwrap();
        assert_eq!(with_id.id.as_deref(), Some("y"));
        let without: ReceiveBody =
            serde_json::from_value(json!({ "credential": {"id": "x"} })).unwrap();
        assert_eq!(without.id, None);
    }
}
