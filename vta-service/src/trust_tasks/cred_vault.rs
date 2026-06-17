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
        Ok(Some(stored)) => match serde_json::from_slice::<Value>(&stored.body) {
            Ok(credential) => success_response(&doc, GetResponse { credential }),
            Err(e) => reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("stored credential body is not JSON: {e}"),
                },
            ),
        },
        // Conflate not-found with permission-denied to deny enumeration.
        Ok(None) => reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "credential not found".to_string(),
                details: None,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
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
