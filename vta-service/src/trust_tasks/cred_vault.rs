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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;
use vti_common::acl::{Capability, role_has_capability};
use vti_common::vault::{LifecycleError, VaultStatus};

use crate::auth::AuthClaims;
use crate::error::AppError;
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
    ///
    /// Optional only so a binary format can arrive via [`Self::credential_base64`]
    /// instead. Exactly one of the two must be present; a body carrying neither,
    /// or both, is rejected. Existing clients send this field alone and are
    /// unaffected.
    #[serde(default)]
    credential: Option<Value>,
    /// A binary credential, base64url-no-pad. Required when `format` names a
    /// binary format (today: `mso_mdoc`, CBOR `IssuerSigned`), which cannot be
    /// carried as JSON.
    #[serde(default)]
    credential_base64: Option<String>,
    /// Wire format tag. Absent means a Data-Integrity W3C VC — the shape every
    /// existing client sends — so omitting it keeps the current behaviour
    /// exactly.
    #[serde(default)]
    format: Option<String>,
    /// Optional explicit storage id; defaults to the VC's top-level `id`, else a
    /// fresh `urn:uuid`.
    #[serde(default)]
    id: Option<String>,
    /// Optional custody context override — which context owns the credential
    /// (and whose `ContextPolicy` governs its disclosure). Must be a context the
    /// caller can access. When omitted, the credential auto-binds to the caller's
    /// context iff they have exactly one; a super-admin / multi-context caller
    /// stores it unscoped.
    #[serde(default)]
    context_id: Option<String>,
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

    // Resolve the custody context (which context owns the credential, governing
    // its disclosure via ContextPolicy).
    let custody_context = match resolve_custody_context(auth, req.context_id) {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let now = Utc::now();
    let provenance = Some("vault/credentials/receive/0.1".to_string());

    // Two wire shapes, one per credential family. The format tag decides;
    // absent means Data-Integrity, which is what every existing client sends.
    let mut stored = match req.format.as_deref() {
        None | Some("ldp_vc") => {
            let Some(credential) = req.credential else {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: "a Data-Integrity credential must be supplied as `credential`"
                            .to_string(),
                    },
                );
            };
            if req.credential_base64.is_some() {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: "supply exactly one of `credential` or `credentialBase64`"
                            .to_string(),
                    },
                );
            }

            let id = resolve_storage_id(req.id, &credential);

            // Resolve the issuer's signing key from the credential's DID
            // (did:key locally, did:webvh / did:web via the cache) — the data
            // plane verifies the proof against it.
            let issuer_pub =
                match di_verify::resolve_di_issuer_key(state.did_resolver.as_ref(), &credential)
                    .await
                {
                    Ok(k) => k,
                    Err(e) => return app_error_to_reject(&doc, e),
                };

            let body = match serde_json::to_vec(&credential) {
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

            match receive::receive_di_vc(&state.vault_ks, &id, &body, &issuer_pub, provenance, now)
                .await
            {
                Ok(s) => s,
                Err(e) => return app_error_to_reject(&doc, e),
            }
        }

        // ISO 18013-5 mdoc. The issuer is an X.509 Document Signer rather than
        // a resolvable DID, so the key comes from the configured IACA anchors
        // instead of the resolver — the one place the two families genuinely
        // diverge.
        Some("mso_mdoc") => {
            let Some(b64) = req.credential_base64 else {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: "an mdoc must be supplied as `credentialBase64` (CBOR \
                                 IssuerSigned), not `credential`"
                            .to_string(),
                    },
                );
            };
            if req.credential.is_some() {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: "supply exactly one of `credential` or `credentialBase64`"
                            .to_string(),
                    },
                );
            }

            let body = match URL_SAFE_NO_PAD.decode(b64.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    return reject_with(
                        &doc,
                        RejectReason::MalformedRequest {
                            reason: format!("`credentialBase64` is not base64url-no-pad: {e}"),
                        },
                    );
                }
            };

            // Parse before trusting: the x5chain has to be read out of the
            // credential to find out which issuer key to demand.
            let issued = match affinidi_mdoc::IssuerSigned::from_cbor_bytes(&body) {
                Ok(i) => i,
                Err(e) => {
                    return reject_with(
                        &doc,
                        RejectReason::MalformedRequest {
                            reason: format!("not a decodable mdoc IssuerSigned: {e}"),
                        },
                    );
                }
            };

            let issuer_pub = match state
                .mdoc_trust
                .resolve_issuer_key(&issued.issuer_auth, now)
            {
                Ok(k) => k,
                Err(e) => return app_error_to_reject(&doc, e),
            };

            // Holder binding. An mdoc is issued to a specific device key, and
            // only its private half can sign DeviceAuth — so a credential whose
            // device key this VTA does not hold could be stored but never
            // presented. Resolve it now and refuse if we cannot, rather than
            // letting the failure surface at presentation with nothing pointing
            // at the cause.
            let device_point = match vta_vault::mdoc_trust::mdoc_device_key_sec1(&issued.mso) {
                Ok(p) => p,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let device_mb =
                vta_keys::encode_public_multibase(&vta_sdk::keys::KeyType::P256, &device_point);
            let device_key = match crate::operations::keys::find_key_by_public_multibase(
                &state.keys_ks,
                &device_mb,
            )
            .await
            {
                Ok(Some(k)) => k,
                Ok(None) => {
                    return reject_with(
                        &doc,
                        RejectReason::MalformedRequest {
                            reason: "this VTA does not hold the mdoc's MSO deviceKey, so the \
                                     credential could never be presented with holder binding"
                                .to_string(),
                        },
                    );
                }
                Err(e) => return app_error_to_reject(&doc, e),
            };

            // Context gate on the *key*, not just the credential: binding an
            // mdoc to a key in a context the caller cannot act in would let one
            // tenant park a credential on another tenant's key.
            if let Some(ctx) = device_key.context_id.as_deref()
                && let Err(e) = auth.require_context(ctx)
            {
                return app_error_to_reject(&doc, e);
            }

            // An mdoc has no `id` of its own to fall back on, so an explicit id
            // or a fresh urn:uuid it is.
            let id = req
                .id
                .unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()));

            match receive::receive_mdoc(
                &state.vault_ks,
                &id,
                &body,
                &issuer_pub,
                &device_key.key_id,
                provenance,
                now,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => return app_error_to_reject(&doc, e),
            }
        }

        Some(other) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!(
                        "unsupported credential format `{other}` (expected `ldp_vc` or \
                         `mso_mdoc`)"
                    ),
                },
            );
        }
    };
    // Persist the custody binding (receive_di_vc stores it unscoped). Only an
    // extra write when a context was resolved.
    if custody_context.is_some() {
        stored.context_id = custody_context;
        if let Err(e) = storage::put(&state.vault_ks, &stored).await {
            return app_error_to_reject(&doc, e);
        }
    }

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
    // Custody gate: only credentials owned by a context the caller can act in
    // (plus unscoped/legacy rows). Applied inside `search`, where the full
    // record is in hand — the descriptor returned to the caller carries no
    // `context_id` to filter on out here.
    match search(&state.vault_ks, &query, &auth.act_scope()).await {
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

/// Resolve the custody context for a received credential — "auto with optional
/// override": an explicit `override_ctx` must be a context the caller can
/// access; otherwise auto-bind to the caller's context iff they have exactly one
/// (a super-admin / multi-context caller stores the credential unscoped). Kept
/// pure so the policy is unit-testable without an `AppState`.
fn resolve_custody_context(
    auth: &AuthClaims,
    override_ctx: Option<String>,
) -> Result<Option<String>, AppError> {
    match override_ctx {
        Some(ctx) => {
            if !auth.has_context_access(&ctx) {
                return Err(AppError::Forbidden(format!(
                    "caller cannot receive a credential into context {ctx}"
                )));
            }
            Ok(Some(ctx))
        }
        None if auth.allowed_contexts.len() == 1 => Ok(Some(auth.allowed_contexts[0].clone())),
        None => Ok(None),
    }
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
        // Custody gate first: a credential owned by another context is
        // conflated with not-found, exactly like an archived or absent one, so
        // the caller cannot probe for ids outside their contexts.
        Ok(Some(stored))
            if stored.is_active()
                && crate::vault::query::caller_may_access_custody(
                    &auth.act_scope(),
                    stored.context_id.as_deref(),
                ) =>
        {
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
    // Custody gate, same as the read paths: a credential owned by another
    // context is conflated with not-found. Mutating it would be worse than
    // reading it — an operator scoped to one context could archive or delete
    // another's credentials.
    if !crate::vault::query::caller_may_access_custody(
        &auth.act_scope(),
        cred.context_id.as_deref(),
    ) {
        return cred_not_found(&doc, verb, &req.id);
    }
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
    //
    // Custody must still be checked, which means loading the record first: this
    // path previously deleted by id without reading anything, so a caller
    // scoped to one context could destroy another context's credential outright.
    // An absent id stays idempotent-success (nothing to own); a present but
    // inaccessible one conflates to not-found, the same answer an absent id
    // gives, so nothing is disclosed.
    if req.force {
        match storage::get(&state.vault_ks, &req.id).await {
            Ok(Some(cred))
                if !crate::vault::query::caller_may_access_custody(
                    &auth.act_scope(),
                    cred.context_id.as_deref(),
                ) =>
            {
                return cred_not_found(&doc, "delete", &req.id);
            }
            Err(e) => return app_error_to_reject(&doc, e),
            _ => {}
        }
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
    if !crate::vault::query::caller_may_access_custody(
        &auth.act_scope(),
        cred.context_id.as_deref(),
    ) {
        return cred_not_found(&doc, "delete", &req.id);
    }
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
        Ok(Some(cred)) => {
            if !crate::vault::query::caller_may_access_custody(
                &auth.act_scope(),
                cred.context_id.as_deref(),
            ) {
                return cred_not_found(&doc, "purge", &req.id);
            }
        }
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

    // ── custody-context enforcement on the read paths ───────────────

    /// Store a credential owned by `context_id`, indexed so `search` can find
    /// it by purpose.
    async fn seed_credential(
        vault_ks: &crate::store::KeyspaceHandle,
        id: &str,
        context_id: Option<&str>,
    ) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        use vti_common::vault::VaultStatus;
        let cred = StoredCredential {
            id: id.into(),
            format: CredentialFormat::EddsaJcs2022,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: None,
            context_id: context_id.map(str::to_string),
            subject_did: None,
            issuer_did: Some("did:key:zIssuer".into()),
            purpose: None,
            status: CredentialStatus::Unknown,
            valid_from: None,
            valid_until: None,
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: serde_json::to_vec(&json!({"id": id})).unwrap(),
            lifecycle: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        };
        crate::vault::storage::put(vault_ks, &cred).await.unwrap();
    }

    fn get_doc(id: &str) -> TrustTask<Value> {
        let uri: trust_tasks_rs::TypeUri = vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_GET_0_1
            .parse()
            .expect("get uri");
        TrustTask::new("urn:uuid:test-get", uri, json!({ "id": id }))
    }

    fn query_doc() -> TrustTask<Value> {
        let uri: trust_tasks_rs::TypeUri = vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_QUERY_0_1
            .parse()
            .expect("query uri");
        TrustTask::new(
            "urn:uuid:test-query",
            uri,
            json!({ "issuerDid": "did:key:zIssuer" }),
        )
    }

    /// `context_id` is documented as the **custody** axis — "which context in
    /// *this* VTA owns the credential" — and the owning context's policy is
    /// meant to govern disclosure. A caller scoped to ctx-a must not be able to
    /// fetch a credential owned by ctx-b.
    #[tokio::test]
    async fn get_refuses_a_credential_owned_by_another_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-b", Some("ctx-b")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let outcome = handle_get(&state, &auth, get_doc("cred-in-ctx-b")).await;
        let body = String::from_utf8_lossy(&outcome.body).to_string();
        assert!(
            !body.contains("cred-in-ctx-b") || body.contains("not found"),
            "a ctx-a caller must not receive a ctx-b credential body; got {body}"
        );
    }

    /// The caller's own context still works — the gate must not deny everything.
    #[tokio::test]
    async fn get_allows_a_credential_owned_by_the_callers_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-a", Some("ctx-a")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let outcome = handle_get(&state, &auth, get_doc("cred-in-ctx-a")).await;
        let body = String::from_utf8_lossy(&outcome.body).to_string();
        assert!(
            body.contains("cred-in-ctx-a"),
            "the caller's own context must still be readable; got {body}"
        );
    }

    /// The query path is the bulk equivalent: a filtered search must not return
    /// another context's credentials.
    #[tokio::test]
    async fn query_excludes_credentials_owned_by_another_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-a", Some("ctx-a")).await;
        seed_credential(&state.vault_ks, "cred-in-ctx-b", Some("ctx-b")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let outcome = handle_query(&state, &auth, query_doc()).await;
        let body = String::from_utf8_lossy(&outcome.body).to_string();
        assert!(
            body.contains("cred-in-ctx-a"),
            "own-context credential must be returned; got {body}"
        );
        assert!(
            !body.contains("cred-in-ctx-b"),
            "another context's credential must not be returned; got {body}"
        );
    }

    /// A super-admin (no context restriction) still sees everything.
    #[tokio::test]
    async fn super_admin_still_reads_every_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-anywhere", Some("ctx-b")).await;

        let auth = auth_scoped(&[]);
        let outcome = handle_get(&state, &auth, get_doc("cred-anywhere")).await;
        let body = String::from_utf8_lossy(&outcome.body).to_string();
        assert!(
            body.contains("cred-anywhere"),
            "super admin must still read any context; got {body}"
        );
    }

    fn lifecycle_doc(task: &str, id: &str, force: bool) -> TrustTask<Value> {
        let uri: trust_tasks_rs::TypeUri = task.parse().expect("uri");
        TrustTask::new(
            "urn:uuid:test-lifecycle",
            uri,
            json!({ "id": id, "force": force }),
        )
    }

    /// Mutating another context's credential is worse than reading it. The
    /// lifecycle verbs shared the read paths' missing gate.
    #[tokio::test]
    async fn archive_refuses_a_credential_owned_by_another_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-b", Some("ctx-b")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let doc = lifecycle_doc(
            vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_ARCHIVE_0_1,
            "cred-in-ctx-b",
            false,
        );
        let _ = handle_archive(&state, &auth, doc).await;

        let after = crate::vault::storage::get(&state.vault_ks, "cred-in-ctx-b")
            .await
            .unwrap()
            .expect("credential must survive");
        assert!(
            after.is_active(),
            "a ctx-a caller must not archive a ctx-b credential"
        );
    }

    /// `delete --force` hard-deletes by id and previously never loaded the
    /// record, so custody could not be checked at all — a scoped caller could
    /// destroy another context's credential outright.
    #[tokio::test]
    async fn force_delete_refuses_a_credential_owned_by_another_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-b", Some("ctx-b")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let doc = lifecycle_doc(
            vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_DELETE_0_1,
            "cred-in-ctx-b",
            true,
        );
        let _ = handle_delete(&state, &auth, doc).await;

        assert!(
            crate::vault::storage::get(&state.vault_ks, "cred-in-ctx-b")
                .await
                .unwrap()
                .is_some(),
            "a ctx-a caller must not hard-delete a ctx-b credential"
        );
    }

    /// …and the caller's own context still works, so the gate is not a blanket
    /// denial.
    #[tokio::test]
    async fn force_delete_allows_the_callers_own_context() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        seed_credential(&state.vault_ks, "cred-in-ctx-a", Some("ctx-a")).await;

        let auth = auth_scoped(&["ctx-a"]);
        let doc = lifecycle_doc(
            vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_DELETE_0_1,
            "cred-in-ctx-a",
            true,
        );
        let _ = handle_delete(&state, &auth, doc).await;

        assert!(
            crate::vault::storage::get(&state.vault_ks, "cred-in-ctx-a")
                .await
                .unwrap()
                .is_none(),
            "the caller's own credential must still be deletable"
        );
    }

    fn auth_scoped(ctxs: &[&str]) -> AuthClaims {
        AuthClaims {
            role: crate::acl::Role::Admin,
            allowed_contexts: ctxs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn custody_auto_binds_to_callers_single_context() {
        let r = resolve_custody_context(&auth_scoped(&["acme"]), None).unwrap();
        assert_eq!(r.as_deref(), Some("acme"));
    }

    #[test]
    fn custody_unscoped_for_super_admin_and_multi_context() {
        // Super-admin (empty contexts) → unscoped.
        assert_eq!(
            resolve_custody_context(&auth_scoped(&[]), None).unwrap(),
            None
        );
        // Multiple contexts, no override → unscoped (ambiguous which owns it).
        assert_eq!(
            resolve_custody_context(&auth_scoped(&["a", "b"]), None).unwrap(),
            None
        );
    }

    #[test]
    fn custody_override_must_be_accessible() {
        // Accessible override wins over the auto default.
        let ok = resolve_custody_context(&auth_scoped(&["acme"]), Some("acme".into())).unwrap();
        assert_eq!(ok.as_deref(), Some("acme"));
        // A super-admin may target any context.
        let sa = resolve_custody_context(&auth_scoped(&[]), Some("acme".into())).unwrap();
        assert_eq!(sa.as_deref(), Some("acme"));
        // An override outside the caller's scope is refused.
        let err = resolve_custody_context(&auth_scoped(&["acme"]), Some("other".into()));
        assert!(matches!(err, Err(AppError::Forbidden(_))), "{err:?}");
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

#[cfg(test)]
mod receive_body_wire_tests {
    use super::*;
    use serde_json::json;

    /// The back-compatibility guarantee this change rests on: a body from an
    /// existing client — `credential` alone, no `format` — must still
    /// deserialize and still route to the Data-Integrity path. If this breaks,
    /// every deployed wallet breaks with it.
    #[test]
    fn a_pre_existing_body_still_deserializes_and_stays_on_the_di_path() {
        let body: ReceiveBody = serde_json::from_value(json!({
            "credential": {"id": "urn:uuid:abc", "type": ["VerifiableCredential"]},
            "id": "urn:uuid:abc"
        }))
        .expect("an existing client body must still parse");

        assert!(body.credential.is_some());
        assert!(body.credential_base64.is_none());
        assert!(
            body.format.is_none(),
            "absent format must stay absent — it is what selects the DI path"
        );
    }

    /// camelCase on the wire, per R3.1. A snake_case `credential_base64` must
    /// NOT bind, or a client that guesses wrong silently sends nothing.
    #[test]
    fn the_binary_field_is_camel_case_on_the_wire() {
        let ok: ReceiveBody = serde_json::from_value(json!({
            "credentialBase64": "AAAA",
            "format": "mso_mdoc"
        }))
        .expect("camelCase parses");
        assert_eq!(ok.credential_base64.as_deref(), Some("AAAA"));

        let wrong: ReceiveBody = serde_json::from_value(json!({
            "credential_base64": "AAAA",
            "format": "mso_mdoc"
        }))
        .expect("unknown fields are ignored today");
        assert!(
            wrong.credential_base64.is_none(),
            "snake_case must not bind — the wire contract is camelCase"
        );
    }

    /// `mso_mdoc` is the OpenID4VP spelling and the `CredentialFormat` serde
    /// tag. Pin it here too: this is the third place it has to agree.
    #[test]
    fn the_mdoc_format_tag_matches_the_stored_credential_format() {
        let body: ReceiveBody =
            serde_json::from_value(json!({"credentialBase64": "AA", "format": "mso_mdoc"}))
                .unwrap();
        let stored = serde_json::to_string(&vta_vault::model::CredentialFormat::MsoMdoc).unwrap();
        assert_eq!(
            format!("\"{}\"", body.format.unwrap()),
            stored,
            "the wire format tag and the stored format tag must be the same token"
        );
    }
}
