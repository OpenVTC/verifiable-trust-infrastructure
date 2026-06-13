// Each handler's `Result<…, Response>` Err variant is the boxed-axum
// `Response` (~128 bytes). Boxing the entire Result would buy nothing —
// the Response is owned-and-emitted on the same stack frame — so allow
// the lint at the slice level rather than per-fn.
#![allow(clippy::result_large_err)]

//! Vault slice trust-task handlers — M1 + M2A + M2B surface.
//!
//! Handles `spec/vault/{list,get,upsert,delete,release,proxy-login}/0.1`
//! per the canonical
//! [trust-tasks-tf](https://github.com/trustoverip/dtgwg-trust-tasks-tf) specs.
//! `proxy-login`'s DID-self-issued (SIOP) driver lands in M2B.2b; the
//! Password POST driver follows in M2B.5.
//!
//! Auth: gated on derived capabilities for the caller's role —
//! [`vti_common::acl::derived_capabilities_for_role`]. List/get require
//! `VaultRead`; upsert/delete require `VaultWrite`; release requires
//! `FillRelease`; proxy-login requires `ProxyLogin`. Admin/Initiator
//! carry the write capabilities; Application/Reader carry read-only;
//! Monitor carries none.

use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vti_common::acl::{Capability, role_has_capability};
use vti_common::vault::{
    SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultListFilter, VaultSecret,
    delete_vault_entry, get_stored_vault_entry, get_vault_entry,
    list_vault_entries as list_entries_store, put_stored_vault_entry,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, reject_with, success_response};
use trust_tasks_rs::RejectReason;

/// URIs handled by this slice. Aggregated by the dispatcher's parity
/// harness. `#[allow(deprecated)]`: the 0.1 URIs remain dual-accepted during
/// the migration (their 0.2 counterparts are edge-transformed in `wire_v0_2`).
#[allow(dead_code, deprecated)]
pub(super) const DISPATCHED_URIS: &[&str] = &[
    vta_sdk::trust_tasks::TASK_VAULT_LIST_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_GET_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_UPSERT_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_DELETE_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_RELEASE_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
    vta_sdk::trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1,
];

/// Request body for `vault/list/0.1`. Mirrors the canonical
/// `payload.schema.json` of the spec; field names are camelCase to match
/// the wire form Companions emit from `@openvtc/trust-tasks`.
///
/// Pagination is accepted but currently single-page — the maintainer
/// returns up to `page_size` entries with `truncated: false` and no cursor.
/// Real cursor-based pagination lands when the vault grows past a few
/// thousand entries; for M1 with hand-seeded test data it's overkill.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultListBody {
    context_id: Option<String>,
    target_origin_prefix: Option<String>,
    target_did: Option<String>,
    target_ios_bundle_id: Option<String>,
    target_android_package: Option<String>,
    secret_kind: Option<SecretKind>,
    tag: Option<String>,
    used_since: Option<String>,
    never_used: Option<bool>,
    expires_before: Option<String>,
    breached: Option<bool>,
    page_size: Option<u32>,
    // `cursor` accepted on the wire for forward-compat but ignored in M1.
    #[serde(default)]
    #[allow(dead_code)]
    cursor: Option<String>,
}

/// Response body for `vault/list/0.1`. Wraps the entries the
/// canonical schema declares under `$defs.Response`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultListResponseBody {
    entries: Vec<VaultEntry>,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultGetBody {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultGetResponseBody {
    entry: VaultEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_fields: Option<Vec<String>>,
}

/// Request body for `vault/upsert/0.1`. Mirrors the canonical
/// `payload.schema.json`; field names are camelCase per the wire spec.
///
/// Notes on semantics:
/// - `id` omitted → create with a maintainer-assigned ULID. Provided →
///   update (`expectedVersion` MUST match) or upsert-with-id when the row
///   doesn't yet exist (recommended for client-generated ids).
/// - `sealedSecret` REQUIRED on create except for the two reference kinds
///   (`did-self-issued`, `didcomm-peer`) — those carry only references to
///   maintainer-internal keys and have no extra secret bytes. On update,
///   omit to keep the existing secret; populate to rotate.
/// - `clearFields` distinguishes "don't touch" (field omitted from payload)
///   from "clear" (field listed here). Only safe-to-clear fields are
///   listable; `contextId`, `targets`, `label`, `secretKind` are not.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultUpsertBody {
    id: Option<String>,
    expected_version: Option<u32>,
    context_id: String,
    targets: Vec<SiteTarget>,
    label: String,
    secret_kind: SecretKind,
    #[serde(default)]
    tags: Vec<String>,
    notes: Option<String>,
    favicon: Option<String>,
    #[serde(default)]
    selectors: Vec<String>,
    #[serde(default)]
    custom_field_names: Vec<String>,
    expires_at: Option<String>,
    sealed_secret: Option<SealedEnvelope>,
    #[serde(default)]
    clear_fields: Vec<ClearableField>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultUpsertResponseBody {
    entry: VaultEntry,
    created: bool,
}

/// Wire form of `vault/_shared/0.1/sealed-envelope#/$defs/SealedEnvelope`
/// — the pluggable cipher envelope. M2A implements only the
/// `didcomm-authcrypt` variant; `hpke-armored` and `tsp-message` are
/// recognised on the wire (so the consumer gets a clean
/// `envelope_unsupported` reject) but not unsealable here yet.
#[derive(Debug, Deserialize)]
#[serde(tag = "envelope", rename_all = "kebab-case")]
enum SealedEnvelope {
    DidcommAuthcrypt {
        jwe: String,
    },
    HpkeArmored {
        #[serde(default)]
        #[allow(dead_code)]
        armored: String,
        #[serde(default)]
        #[allow(dead_code)]
        recipient_key_id: String,
    },
    TspMessage {
        #[serde(default)]
        #[allow(dead_code)]
        message: String,
    },
}

impl SealedEnvelope {
    fn kind_name(&self) -> &'static str {
        match self {
            SealedEnvelope::DidcommAuthcrypt { .. } => "didcomm-authcrypt",
            SealedEnvelope::HpkeArmored { .. } => "hpke-armored",
            SealedEnvelope::TspMessage { .. } => "tsp-message",
        }
    }
}

/// Subset of metadata fields the upsert spec lets the consumer null out
/// explicitly. `contextId` / `targets` / `label` / `secretKind` are
/// excluded — they're either immutable or always required.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum ClearableField {
    Notes,
    Favicon,
    ExpiresAt,
    Tags,
    Selectors,
    CustomFieldNames,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultDeleteBody {
    id: String,
    expected_version: Option<u32>,
    /// Human-readable rationale recorded in the audit trail. M2A.2 doesn't
    /// have audit-log wiring for vault yet, so this field is accepted but
    /// only echoed back; full audit landed when the audit module gains a
    /// vault.delete event type.
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultDeleteResponseBody {
    id: String,
    deleted_at: String,
    /// M2A.2 performs a hard delete (no multi-device sync clients exist
    /// yet, so there's nothing to fan tombstones to). `graceUntil ==
    /// deletedAt` indicates "no grace window". When sync (M5) lands, this
    /// gains a real grace window and the storage layer keeps a tombstone
    /// record until then.
    grace_until: String,
}

/// Request body for `vault/release/0.1`. Mirrors the canonical schema.
/// `target` / `consumerContext` / `stepUpProof` are accepted but only
/// consulted by the policy engine in M3; M2A.3's policy is "allow if
/// FillRelease capability".
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultReleaseBody {
    entry_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    target: Option<SiteTarget>,
    #[serde(default)]
    #[allow(dead_code)]
    consumer_context: Option<Value>,
    // (`step_up_proof` removed in P0.13: step-up is now enforced via the
    // session ACR gate `require_step_up(op::VAULT_RELEASE)`, not a dormant
    // body field. An incoming `stepUpProof` is harmlessly ignored — these
    // bodies don't `deny_unknown_fields`.)
    #[serde(default)]
    ttl_seconds_hint: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultReleaseResponseBody {
    /// Pluggable cipher envelope — M2A.3 emits only the `didcomm-authcrypt`
    /// variant. The cleartext inside the JWE is the VaultSecret JSON
    /// (see `vault/_shared/0.1/vault-secret`).
    sealed_secret: SealedEnvelopeWire,
    secret_kind: SecretKind,
    ttl_seconds: u32,
}

/// Wire form of `SealedEnvelope` we EMIT (subset of variants we currently
/// know how to produce). M2A.3 emits the `didcomm-authcrypt` variant only;
/// other variants land if/when those envelope kinds are needed for vault
/// release (e.g. an HPKE-armored airgap export).
#[derive(Debug, Serialize)]
#[serde(tag = "envelope", rename_all = "kebab-case")]
enum SealedEnvelopeWire {
    DidcommAuthcrypt { jwe: String },
}

/// Request body for `vault/proxy-login/0.1`. Mirrors the canonical schema.
/// `consumerContext` / `stepUpProof` are accepted but not yet consumed
/// (M3 policy engine will read consumerContext; step-up gating across
/// the proxy-login flow lands as a follow-up to step-up's release-flow
/// integration). `ttlSecondsHint` is accepted but capped by the
/// maintainer. `nonce` (M2B.4) is embedded verbatim in the SIOP
/// id_token's `nonce` claim — the canonical use is the wallet
/// threading the RP's `/auth/challenge` value through so the resulting
/// id_token passes the RP's nonce check.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultProxyLoginBody {
    entry_id: String,
    /// Optional target the wallet is asking the VTA to log in *against*.
    /// When omitted the maintainer picks the entry's first DID-shaped or
    /// web-origin target (in that order). For SIOP entries the audience
    /// is the relying party's DID; for Password POST (M2B.5) it's the
    /// site origin.
    #[serde(default)]
    target: Option<SiteTarget>,
    /// Free-form `consumer-context` per the shared schema — origin /
    /// page hints the wallet ships so the policy engine can decide
    /// whether to proceed. Accepted, ignored by M2B.2b (default-allow).
    #[serde(default)]
    #[allow(dead_code)]
    consumer_context: Option<Value>,
    // (`step_up_proof` removed in P0.13: step-up is now the
    // `require_step_up(op::VAULT_PROXY_LOGIN)` session-ACR gate above, which
    // an operator opts into via a `vault/proxy-login` policy floor — replacing
    // the dormant "forward-compatibility" body field this comment described.)
    /// Caller-supplied nonce — embedded verbatim as the SIOP id_token's
    /// `nonce` claim for the `did-self-issued` driver. Drivers without
    /// a nonce concept (Password POST, OAuth refresh — M2B.5+) ignore.
    /// Capped to the canonical schema's 512-char ceiling at the parse
    /// boundary; a longer string would fail JSON-Schema validation
    /// upstream but we double-check below to keep the SIOP token shape
    /// sane.
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    ttl_seconds_hint: Option<u32>,
}

/// Schema-level ceiling for `nonce` per `vault/proxy-login/0.1`. The
/// canonical payload schema enforces this; we re-check here so a
/// malformed-but-parseable request still gets a clean reject rather
/// than a multi-KB JWT.
const NONCE_MAX_LEN: usize = 512;

/// Response body for `vault/proxy-login/0.1`. The `sealedSessionBlob`
/// is the same pluggable cipher envelope shape used by `vault/release` —
/// M2B.2b emits only the `didcomm-authcrypt` variant.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultProxyLoginResponseBody {
    sealed_session_blob: SealedEnvelopeWire,
    /// Maintainer-assigned session id — opaque to the wallet, used by
    /// future `vault/session/{revoke, refresh}/0.1` calls. Same value
    /// as the `sessionId` inside the cleartext SessionBlob; exposed at
    /// the response root so the wallet can log / index it without
    /// having to unseal the envelope first (audit trail before
    /// decryption).
    session_id: String,
    /// Mirrors the cleartext SessionBlob's `expiresAt`. Exposed in the
    /// clear so the wallet's UI can show "session expires in N minutes"
    /// without unsealing. Discarding the wrapper at this time is the
    /// wallet's obligation.
    expires_at: String,
}

/// Reject the request unless the caller's role implies `VaultRead`. When
/// AclEntry-level explicit capabilities arrive (M4), this check upgrades
/// to consult the entry's `capabilities` Vec instead of deriving from role.
fn require_vault_read(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::VaultRead) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault read denied: role {} does not carry VaultRead capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Reject the request unless the caller's role implies `VaultWrite` —
/// Admin and Initiator pass; Application, Reader, Monitor do not. Used by
/// upsert + delete. Same role→capability fallback story as
/// [`require_vault_read`]; upgrades to explicit `capabilities` in M4.
fn require_vault_write(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::VaultWrite) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault write denied: role {} does not carry VaultWrite capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Reject the request unless the caller's role implies `FillRelease` —
/// Admin, Initiator, and Application pass; Reader and Monitor do not.
/// Used by release. Same role→capability fallback as the other
/// require_* helpers.
fn require_fill_release(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::FillRelease) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault release denied: role {} does not carry FillRelease capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Reject the request unless the caller's role implies `ProxyLogin` —
/// Admin, Initiator, and Application pass; Reader and Monitor do not.
/// Used by vault/proxy-login. ProxyLogin is the "VTA performs the login
/// for the consumer" capability; it's strictly more privileged than
/// FillRelease (the consumer never sees the long-term secret) so the
/// role→capability mapping carries it on the same roles as FillRelease.
fn require_proxy_login(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::ProxyLogin) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault proxy-login denied: role {} does not carry ProxyLogin capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Used by vault/sign-trust-task. Per-envelope signing on the entry's
/// principal DID — strictly more privileged than `Sign` (which is the
/// generic signing oracle), distinct from `ProxyLogin` (which mints a
/// session credential, not an arbitrary envelope). Splitting them lets
/// operators grant proxy-login without sign-trust-task to limit blast
/// radius on Service consumers.
fn require_sign_trust_task(auth: &AuthClaims, doc: &TrustTask<Value>) -> Result<(), Response> {
    if role_has_capability(&auth.role, Capability::SignTrustTask) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "vault sign-trust-task denied: role {} does not carry SignTrustTask capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Reject if the caller's `allowed_contexts` is non-empty AND `context_id`
/// (if supplied) is not in the allowed list. Empty allowed_contexts means
/// super-admin scope.
fn enforce_context_scope(
    auth: &AuthClaims,
    context_id: Option<&str>,
    doc: &TrustTask<Value>,
) -> Result<(), Response> {
    let Some(ctx) = context_id else {
        return Ok(()); // No context filter — caller's full visibility applies.
    };
    if auth.allowed_contexts.is_empty() {
        return Ok(()); // Super-admin (or unscoped) sees everything.
    }
    if auth.allowed_contexts.iter().any(|c| c == ctx) {
        return Ok(());
    }
    Err(reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: format!("vault scope denied: caller is not authorised for context {ctx}"),
        },
    ))
}

/// Handler for `spec/vault/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_read(auth, &doc) {
        return r;
    }

    let req: VaultListBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Reject mutually-exclusive filter combinations the spec calls out.
    if req.used_since.is_some() && req.never_used == Some(true) {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "vault/list: usedSince and neverUsed are mutually exclusive".into(),
            },
        );
    }

    if let Err(r) = enforce_context_scope(auth, req.context_id.as_deref(), &doc) {
        return r;
    }

    let filter = VaultListFilter {
        context_id: req.context_id.as_deref(),
        target_origin_prefix: req.target_origin_prefix.as_deref(),
        target_did: req.target_did.as_deref(),
        target_ios_bundle_id: req.target_ios_bundle_id.as_deref(),
        target_android_package: req.target_android_package.as_deref(),
        secret_kind: req.secret_kind,
        tag: req.tag.as_deref(),
        used_since: req.used_since.as_deref(),
        never_used: req.never_used,
        expires_before: req.expires_before.as_deref(),
        breached: req.breached,
    };

    let mut entries = match list_entries_store(&state.vault_ks, &filter).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // If the caller's role is scoped to a subset of contexts and they
    // queried without a `contextId` filter, narrow the result set to
    // visible contexts only. This is defence-in-depth in addition to
    // `enforce_context_scope` — that path covers the explicit-filter case;
    // this one covers the implicit-all-contexts case.
    if !auth.allowed_contexts.is_empty() && req.context_id.is_none() {
        entries.retain(|e| auth.allowed_contexts.iter().any(|c| c == &e.context_id));
    }

    // M1 pagination: single page. Apply page_size as a hard truncation.
    let page_size = req.page_size.unwrap_or(100) as usize;
    let truncated = entries.len() > page_size;
    entries.truncate(page_size);

    success_response(
        &doc,
        VaultListResponseBody {
            entries,
            truncated,
            cursor: None,
            redacted_fields: None,
        },
    )
}

/// Handler for `spec/vault/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_read(auth, &doc) {
        return r;
    }
    let req: VaultGetBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let entry = match get_vault_entry(&state.vault_ks, &req.id).await {
        Ok(Some(e)) => e,
        // Conflate not-found with permission-denied to deny enumeration.
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::NotFound(format!("vault entry {} not found", req.id)),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(r) = enforce_context_scope(auth, Some(&entry.context_id), &doc) {
        return r;
    }

    success_response(
        &doc,
        VaultGetResponseBody {
            entry,
            redacted_fields: None,
        },
    )
}

/// Handler for `spec/vault/upsert/0.1`. Create or update a vault entry;
/// secret material rides inside the pluggable `sealedSecret` envelope and
/// is unsealed server-side via [`unseal_secret`]. See the spec for the
/// full payload shape; this implementation honours every required field
/// and the spec's full error-code surface
/// (`context_not_found` is currently NOT enforced — the maintainer accepts
/// any contextId the consumer supplies; cross-checking against the
/// contexts keyspace lands in a follow-up).
pub(super) async fn handle_upsert(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_write(auth, &doc) {
        return r;
    }

    let req: VaultUpsertBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if let Err(r) = enforce_context_scope(auth, Some(&req.context_id), &doc) {
        return r;
    }

    // Load existing (if `id` supplied). Optimistic-concurrency check
    // happens after; we need the row for context-change-forbidden and
    // for the create-vs-update decision anyway.
    let existing: Option<StoredVaultEntry> = if let Some(id) = req.id.as_deref() {
        match get_stored_vault_entry(&state.vault_ks, id).await {
            Ok(e) => e,
            Err(e) => return app_error_to_reject(&doc, e),
        }
    } else {
        None
    };

    // An `expectedVersion` was supplied but there's no row at this id —
    // the client thinks it's updating something that doesn't exist.
    if existing.is_none() && req.expected_version.is_some() && req.id.is_some() {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/upsert:not_found — no entry at id {}",
                    req.id.as_deref().unwrap_or("(none)")
                ),
                details: None,
            },
        );
    }

    // Forbid changing the contextId of an existing entry.
    if let Some(e) = existing.as_ref()
        && e.entry.context_id != req.context_id
    {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/upsert:context_change_forbidden — entry {} is in context {}; cannot move to {}. Delete and recreate instead.",
                    e.entry.id, e.entry.context_id, req.context_id
                ),
                details: Some(serde_json::json!({
                    "currentContext": e.entry.context_id,
                    "requestedContext": req.context_id,
                })),
            },
        );
    }

    // Optimistic concurrency for updates.
    if let (Some(e), Some(v)) = (existing.as_ref(), req.expected_version)
        && e.entry.version != v
    {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/upsert:version_conflict — expectedVersion {v} != current version {}",
                    e.entry.version
                ),
                details: Some(serde_json::json!({ "currentVersion": e.entry.version })),
            },
        );
    }

    // Resolve the secret. Three cases:
    //   - sealed_secret supplied → unseal it.
    //   - no sealed_secret, existing entry → reuse existing secret.
    //   - no sealed_secret, create → secret_required.
    let secret: VaultSecret = match (&req.sealed_secret, existing.as_ref()) {
        (Some(env), _) => {
            // Envelope-variant check stays here (the route owns the
            // `SealedEnvelope` wire shape); the unpack + sender cross-check +
            // cleartext deserialise are the operations-layer crypto (P2.4).
            let jwe = match env {
                SealedEnvelope::DidcommAuthcrypt { jwe } => jwe,
                other => {
                    return reject_with(
                        &doc,
                        RejectReason::TaskFailed {
                            reason: format!(
                                "vault/upsert:envelope_unsupported — received {kind}; this maintainer accepts only didcomm-authcrypt in M2A",
                                kind = other.kind_name()
                            ),
                            details: Some(serde_json::json!({
                                "receivedEnvelope": other.kind_name(),
                                "supportedEnvelopes": ["didcomm-authcrypt"],
                            })),
                        },
                    );
                }
            };
            let atm = match state.atm.as_ref() {
                Some(atm) => atm,
                None => {
                    return reject_with(
                        &doc,
                        RejectReason::InternalError {
                            reason: "ATM not configured — server cannot unpack DIDComm envelopes"
                                .into(),
                        },
                    );
                }
            };
            use crate::operations::vault::upsert::UnsealError;
            match crate::operations::vault::upsert::unseal_secret(atm, &auth.did, jwe).await {
                Ok(s) => s,
                Err(UnsealError::SenderMismatch { sender, caller }) => {
                    return reject_with(
                        &doc,
                        RejectReason::PermissionDenied {
                            reason: format!(
                                "vault/upsert:sealed_secret_invalid — JWE sender {sender} does not match authenticated caller {caller}"
                            ),
                        },
                    );
                }
                Err(UnsealError::UnpackFailed(e)) => {
                    return reject_with(
                        &doc,
                        RejectReason::TaskFailed {
                            reason: format!(
                                "vault/upsert:sealed_secret_invalid — DIDComm unpack: {e}"
                            ),
                            details: Some(serde_json::json!({ "reason": "unpack_failed" })),
                        },
                    );
                }
                Err(UnsealError::MissingSender) => {
                    return reject_with(
                        &doc,
                        RejectReason::TaskFailed {
                            reason: "vault/upsert:sealed_secret_invalid — JWE has no sender (from)"
                                .into(),
                            details: Some(serde_json::json!({ "reason": "missing_sender" })),
                        },
                    );
                }
                Err(UnsealError::CleartextInvalid(e)) => {
                    return reject_with(
                        &doc,
                        RejectReason::TaskFailed {
                            reason: format!(
                                "vault/upsert:sealed_secret_invalid — cleartext not a VaultSecret: {e}"
                            ),
                            details: Some(
                                serde_json::json!({ "reason": "cleartext_schema_invalid" }),
                            ),
                        },
                    );
                }
            }
        }
        (None, Some(e)) => e.secret.clone(),
        (None, None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!(
                        "vault/upsert:secret_required — secretKind {:?} needs `sealedSecret` on create",
                        req.secret_kind
                    ),
                    details: None,
                },
            );
        }
    };

    if !secret.matches_kind(req.secret_kind) {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/upsert:sealed_secret_invalid — declared secretKind {:?} does not match secret variant {:?}",
                    req.secret_kind,
                    secret.kind()
                ),
                details: Some(serde_json::json!({
                    "declaredKind": serde_json::to_value(req.secret_kind).ok(),
                    "secretVariant": serde_json::to_value(secret.kind()).ok(),
                })),
            },
        );
    }

    // Build the resulting VaultEntry. Some fields come from `existing`
    // (immutable / sticky), some from the request, some are computed.
    let now = chrono::Utc::now().to_rfc3339();
    let is_create = existing.is_none();
    let secret_rotated_password =
        req.sealed_secret.is_some() && matches!(req.secret_kind, SecretKind::Password);

    let entry = VaultEntry {
        id: existing
            .as_ref()
            .map(|e| e.entry.id.clone())
            .or(req.id.clone())
            .unwrap_or_else(|| format!("vault_{}", Uuid::new_v4().simple())),
        context_id: req.context_id,
        targets: req.targets,
        label: req.label,
        secret_kind: req.secret_kind,
        tags: if req.clear_fields.contains(&ClearableField::Tags) {
            Vec::new()
        } else {
            req.tags
        },
        notes: if req.clear_fields.contains(&ClearableField::Notes) {
            None
        } else {
            req.notes
        },
        favicon: if req.clear_fields.contains(&ClearableField::Favicon) {
            None
        } else {
            req.favicon
        },
        selectors: if req.clear_fields.contains(&ClearableField::Selectors) {
            Vec::new()
        } else {
            req.selectors
        },
        custom_field_names: if req.clear_fields.contains(&ClearableField::CustomFieldNames) {
            Vec::new()
        } else {
            req.custom_field_names
        },
        // Attachments are not exposed on upsert — they round-trip from
        // existing rows untouched. Future task vault/attachments/*
        // manages them.
        attachments: existing
            .as_ref()
            .map(|e| e.entry.attachments.clone())
            .unwrap_or_default(),
        expires_at: if req.clear_fields.contains(&ClearableField::ExpiresAt) {
            None
        } else {
            req.expires_at
        },
        // Sticky from existing — maintainer-set fields.
        breached_at: existing.as_ref().and_then(|e| e.entry.breached_at.clone()),
        password_changed_at: if (is_create && matches!(req.secret_kind, SecretKind::Password))
            || secret_rotated_password
        {
            Some(now.clone())
        } else {
            existing
                .as_ref()
                .and_then(|e| e.entry.password_changed_at.clone())
        },
        created_at: existing
            .as_ref()
            .map(|e| e.entry.created_at.clone())
            .unwrap_or_else(|| now.clone()),
        created_by: existing
            .as_ref()
            .and_then(|e| e.entry.created_by.clone())
            .or_else(|| Some(auth.did.clone())),
        updated_at: now,
        updated_by: Some(auth.did.clone()),
        last_used_at: existing.as_ref().and_then(|e| e.entry.last_used_at.clone()),
        version: existing.as_ref().map(|e| e.entry.version + 1).unwrap_or(1),
        // Maintainer-derived from the canonical secret. Producer-supplied
        // values on the wire are intentionally ignored — the canonical
        // schema declares this field read-only and we recompute every
        // upsert + rotation. Stays in sync with the actual signing key
        // for did-self-issued / didcomm-peer entries.
        principal_did: VaultEntry::principal_did_from_secret(&secret),
    };

    let record = StoredVaultEntry {
        entry: entry.clone(),
        secret,
    };
    if let Err(e) = put_stored_vault_entry(&state.vault_ks, &record).await {
        return app_error_to_reject(&doc, e);
    }

    success_response(
        &doc,
        VaultUpsertResponseBody {
            entry,
            created: is_create,
        },
    )
}

/// Handler for `spec/vault/delete/0.1`.
///
/// M2A.2 performs a hard delete — the row is removed from the keyspace
/// and the secret bytes are zeroised by the keyspace handle's `remove`
/// implementation. There's no multi-device sync yet (M5 territory), so
/// no tombstone-with-grace machinery is needed. The response's
/// `graceUntil` field equals `deletedAt` to signal "no grace window";
/// callers that re-sync after M5 will see a real grace window.
///
/// Enumeration-resistance: a missing entry returns `not_found`
/// regardless of whether the consumer would actually have had read
/// access to it — the consumer can't probe id space by deleting.
///
/// Audit-log wiring for vault events lands when the audit module gains
/// a `vault.*` event variant. For M2A.2 the `reason` field is accepted
/// and ignored.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_vault_write(auth, &doc) {
        return r;
    }

    let req: VaultDeleteBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let existing = match get_stored_vault_entry(&state.vault_ks, &req.id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!("vault/delete:not_found — no entry at id {}", req.id),
                    details: None,
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Defence-in-depth: even with VaultWrite, narrow callers must be in
    // the entry's context. Same shape as the read path.
    if let Err(r) = enforce_context_scope(auth, Some(&existing.entry.context_id), &doc) {
        return r;
    }

    if let Some(v) = req.expected_version
        && v != existing.entry.version
    {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/delete:version_conflict — expectedVersion {v} != current version {}",
                    existing.entry.version
                ),
                details: Some(serde_json::json!({ "currentVersion": existing.entry.version })),
            },
        );
    }

    if let Err(e) = delete_vault_entry(&state.vault_ks, &req.id).await {
        return app_error_to_reject(&doc, e);
    }

    let now = chrono::Utc::now().to_rfc3339();
    success_response(
        &doc,
        VaultDeleteResponseBody {
            id: req.id,
            deleted_at: now.clone(),
            grace_until: now,
        },
    )
}

/// Handler for `spec/vault/release/0.1`. Releases the cleartext secret
/// material of an entry to the requesting consumer, wrapped in a
/// DIDComm-authcrypt envelope sealed to the caller's keyAgreement key.
///
/// M2A.3 flow:
/// 1. `require_fill_release` — Admin / Initiator / Application pass.
/// 2. Parse body, load entry by id (`not_found` if absent, conflated
///    with absence-of-read-access for enumeration resistance).
/// 3. `enforce_context_scope` against the entry's context.
/// 4. Default policy: allow (M3 swaps in `regorus`). Step-up demand
///    is not exercised in M2A.3 — the spec's `step_up_required`
///    error code lands when policy-driven decisions arrive.
/// 5. Cap TTL at 60 s (the maintainer-policy ceiling; client
///    `ttlSecondsHint` is honoured up to that cap).
/// 6. Build a DIDComm `Message` carrying the `VaultSecret` JSON as
///    body. Pack via `atm.pack_encrypted(msg, recipient=auth.did,
///    signer=vta_did, key_holder=vta_did)` — ATM resolves the
///    consumer's X25519 keyAgreement from their DID document
///    (cached on `state.did_resolver`) and signs with the VTA's
///    pre-loaded secrets resolver.
/// 7. Update the stored entry's `last_used_at` (NOT a version bump
///    — that's reserved for user-visible mutations; `last_used_at`
///    is server-managed metadata).
/// 8. Return the JWE inside a `SealedEnvelope { envelope:
///    "didcomm-authcrypt", jwe }` per the canonical schema.
///
/// Audit-log wiring for vault events lands when the audit module
/// gains a `vault.*` event variant — same hold as in M2A.2.
pub(super) async fn handle_release(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_fill_release(auth, &doc) {
        return r;
    }

    let req: VaultReleaseBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let stored = match get_stored_vault_entry(&state.vault_ks, &req.entry_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!("vault/release:not_found — no entry at id {}", req.entry_id),
                    details: None,
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(r) = enforce_context_scope(auth, Some(&stored.entry.context_id), &doc) {
        return r;
    }

    // Step-up gate (P0.13): honour an operator-configured `vault/release`
    // floor before disclosing a stored secret. Placed after the role + scope
    // checks so a caller lacking permission gets that error first, not a
    // step-up prompt. Inert under the shipping default (step-up disabled).
    if let Some(reject) =
        super::step_up::require_step_up(state, auth, super::step_up::op::VAULT_RELEASE, &doc).await
    {
        return reject;
    }

    // ATM + vta_did readiness — checked here so the error is clearly
    // "infrastructure not configured" rather than a packing failure mid-flow.
    let atm = match state.atm.as_ref() {
        Some(atm) => atm,
        None => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: "ATM not configured — server cannot pack DIDComm envelopes".into(),
                },
            );
        }
    };
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(d) => d,
        None => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: "vta_did not configured — server cannot identify itself as signer"
                        .into(),
                },
            );
        }
    };

    // Seal the secret to the holder (operations layer; P2.4).
    match crate::operations::vault::release::release_secret(
        atm,
        &state.vault_ks,
        &vta_did,
        &auth.did,
        stored,
        req.ttl_seconds_hint,
    )
    .await
    {
        Ok(out) => success_response(
            &doc,
            VaultReleaseResponseBody {
                sealed_secret: SealedEnvelopeWire::DidcommAuthcrypt { jwe: out.jwe },
                secret_kind: out.secret_kind,
                ttl_seconds: out.ttl_seconds,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vault/proxy-login/0.1`. Two drivers wired today:
///
/// - **`did-self-issued`** (M2B.2b): VTA mints a SIOPv2 id_token on
///   the entry's behalf, wraps it in a [`SessionBlob`] with a single
///   `Authorization: Bearer …` header. Long-term signing key never
///   leaves the VTA.
/// - **`password`** with a `loginConfig` (M2B.5): VTA performs an
///   HTTP POST against the configured login URL with the entry's
///   credentials, captures the resulting Set-Cookie headers, and
///   returns them in a [`SessionBlob`] for the consumer to inject
///   into its browser. Long-term password leaves the VTA only as
///   the body of one outbound HTTPS request.
///
/// `password` without a `loginConfig` rejects with `not_proxyable`
/// (consumer falls back to `vault/release` for browser-fill). Other
/// secret kinds (`passkey`, `oauth-tokens`, `didcomm-peer`,
/// `bearer-token`, `ssh-key`, `custom`) reject with
/// `not_implemented` — future drivers will light them up.
pub(super) async fn handle_proxy_login(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_proxy_login(auth, &doc) {
        return r;
    }

    let req: VaultProxyLoginBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Defense-in-depth nonce bounds check. The canonical schema
    // enforces `minLength: 1, maxLength: 512`; this guard handles
    // requests that bypassed schema validation (e.g. dispatcher
    // changes that disable schema-first parsing).
    if let Some(n) = req.nonce.as_deref()
        && (n.is_empty() || n.len() > NONCE_MAX_LEN)
    {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!(
                    "vault/proxy-login: nonce length {} outside [1, {NONCE_MAX_LEN}]",
                    n.len()
                ),
            },
        );
    }

    // Load entry — conflate not-found with permission-denied to deny
    // enumeration (matches handle_release).
    let stored = match get_stored_vault_entry(&state.vault_ks, &req.entry_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!(
                        "vault/proxy-login:not_found — no entry at id {}",
                        req.entry_id
                    ),
                    details: None,
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(r) = enforce_context_scope(auth, Some(&stored.entry.context_id), &doc) {
        return r;
    }

    // Step-up gate (P0.13): honour a `vault/proxy-login` floor before
    // minting a session credential for the site. Inert by default.
    if let Some(reject) =
        super::step_up::require_step_up(state, auth, super::step_up::op::VAULT_PROXY_LOGIN, &doc)
            .await
    {
        return reject;
    }

    // ATM + vta_did readiness — checked here so the error is clearly
    // "infrastructure not configured" rather than a packing failure mid-flow.
    let atm = match state.atm.as_ref() {
        Some(atm) => atm,
        None => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: "ATM not configured — server cannot pack DIDComm envelopes".into(),
                },
            );
        }
    };
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(d) => d,
        None => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: "vta_did not configured — server cannot identify itself as signer"
                        .into(),
                },
            );
        }
    };

    // Driver dispatch + session-blob sealing (operations layer; P2.4). The
    // typed `ProxyLoginError` maps back to the canonical spec reject codes.
    use crate::operations::vault::proxy_login::ProxyLoginError;
    match crate::operations::vault::proxy_login::proxy_login(
        atm,
        &state.vault_ks,
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &*state.seed_store,
        &vta_did,
        &auth.did,
        stored,
        req.target,
        req.nonce,
        req.ttl_seconds_hint,
    )
    .await
    {
        Ok(out) => success_response(
            &doc,
            VaultProxyLoginResponseBody {
                sealed_session_blob: SealedEnvelopeWire::DidcommAuthcrypt { jwe: out.jwe },
                session_id: out.session_id,
                expires_at: out.expires_at,
            },
        ),
        Err(ProxyLoginError::NoAudience { entry_targets }) => reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason:
                    "vault/proxy-login:no_audience — entry has no DID or web-origin target to use as SIOP audience"
                        .into(),
                details: Some(serde_json::json!({ "entryTargets": entry_targets })),
            },
        ),
        Err(ProxyLoginError::NotProxyable) => reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason:
                    "vault/proxy-login:not_proxyable — password entry has no loginConfig; use vault/release for browser-fill"
                        .into(),
                details: Some(serde_json::json!({
                    "secretKind": "password",
                    "remediation": "fall back to vault/release/0.1",
                })),
            },
        ),
        Err(ProxyLoginError::NotImplemented { kind }) => reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/proxy-login:not_implemented — entry secretKind {kind} has no proxy-login driver yet"
                ),
                details: Some(serde_json::json!({
                    "secretKind": kind,
                    "supportedKinds": ["did-self-issued", "password"],
                })),
            },
        ),
        #[cfg(feature = "webvh")]
        Err(ProxyLoginError::PasswordPost(e)) => {
            reject_with(&doc, password_post_error_to_reject(&e, &req.entry_id))
        }
        Err(ProxyLoginError::App(e)) => app_error_to_reject(&doc, e),
    }
}

// ─── vault/sign-trust-task/0.1 ─────────────────────────────────────

/// Request body for `vault/sign-trust-task/0.1`. Mirrors the canonical
/// schema. `consumerContext` / `stepUpProof` are accepted but not yet
/// consumed (M3 policy engine will read consumerContext; step-up gating
/// across sign-trust-task lands as a follow-up to the proxy-login wiring).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultSignTrustTaskBody {
    entry_id: String,
    unsigned_envelope: Value,
    #[serde(default)]
    #[allow(dead_code)]
    consumer_context: Option<Value>,
    // (`step_up_proof` removed in P0.13: enforced via the
    // `require_step_up(op::VAULT_SIGN_TRUST_TASK)` session-ACR gate above.)
}

/// Response body for `vault/sign-trust-task/0.1`. Same `unsigned_envelope`
/// the consumer submitted with a `proof` field attached.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultSignTrustTaskResponseBody {
    signed_envelope: Value,
}

/// Handler for `spec/vault/sign-trust-task/0.1`. Attaches an
/// `eddsa-jcs-2022` Data Integrity proof to a Trust Task envelope,
/// signing as the principal DID of a `did-self-issued` or
/// `didcomm-peer` vault entry.
///
/// The long-term signing key never leaves the maintainer. This is the
/// per-envelope-signing complement to `vault/proxy-login/0.1`: proxy-
/// login mints a session credential at session-start; sign-trust-task
/// signs individual follow-up tasks during that session so the proof
/// VM matches the authenticated session DID at the relying party.
///
/// Conformance check order matches the spec's error precedence:
/// `not_found` → `permission_denied` (cap) → context scope →
/// `not_signable` (entry kind) → `envelope_invalid` (structure) →
/// `envelope_already_proofed` → `envelope_issuer_mismatch` →
/// `envelope_expired` → sign.
pub(super) async fn handle_sign_trust_task(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(r) = require_sign_trust_task(auth, &doc) {
        return r;
    }
    let req: VaultSignTrustTaskBody = match parse_payload(&doc) {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Load entry — conflate not-found with permission-denied to deny
    // enumeration (matches handle_release / handle_proxy_login).
    let stored = match get_stored_vault_entry(&state.vault_ks, &req.entry_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!(
                        "vault/sign-trust-task:not_found — no entry at id {}",
                        req.entry_id
                    ),
                    details: None,
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(r) = enforce_context_scope(auth, Some(&stored.entry.context_id), &doc) {
        return r;
    }

    // Step-up gate (P0.13): honour a `vault/sign-trust-task` floor before
    // signing as the entry's principal DID. Inert by default.
    if let Some(reject) = super::step_up::require_step_up(
        state,
        auth,
        super::step_up::op::VAULT_SIGN_TRUST_TASK,
        &doc,
    )
    .await
    {
        return reject;
    }

    // Validate the envelope against the entry's principal identity and sign
    // (operations layer; P2.4). The typed `SignTrustTaskError` maps back to the
    // canonical spec reject codes.
    use crate::operations::vault::sign_trust_task::SignTrustTaskError;
    let signed = match crate::operations::vault::sign_trust_task::sign_envelope(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &*state.seed_store,
        &stored.secret,
        &req.unsigned_envelope,
    )
    .await
    {
        Ok(s) => s,
        Err(SignTrustTaskError::NotSignable { kind }) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!(
                        "vault/sign-trust-task:not_signable — entry kind '{kind}' has no DID-based signing identity"
                    ),
                    details: Some(serde_json::json!({ "secretKind": kind })),
                },
            );
        }
        Err(SignTrustTaskError::EnvelopeNotObject) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "vault/sign-trust-task:envelope_invalid — unsignedEnvelope must be a JSON object".into(),
                    details: None,
                },
            );
        }
        Err(SignTrustTaskError::EnvelopeMissingField { field }) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!(
                        "vault/sign-trust-task:envelope_invalid — missing required field '{field}'"
                    ),
                    details: Some(serde_json::json!({ "missing": field })),
                },
            );
        }
        Err(SignTrustTaskError::IssuerNotString) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "vault/sign-trust-task:envelope_invalid — issuer must be a string"
                        .into(),
                    details: None,
                },
            );
        }
        Err(SignTrustTaskError::AlreadyProofed) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "vault/sign-trust-task:envelope_already_proofed — strip the existing proof and resubmit".into(),
                    details: None,
                },
            );
        }
        Err(SignTrustTaskError::IssuerMismatch {
            envelope_issuer,
            expected,
        }) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "vault/sign-trust-task:envelope_issuer_mismatch — envelope.issuer must equal the entry's principalDid".into(),
                    details: Some(serde_json::json!({
                        "envelopeIssuer": envelope_issuer,
                        "expectedIssuer": expected,
                    })),
                },
            );
        }
        Err(SignTrustTaskError::ExpiresAtNotRfc3339 { value }) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "vault/sign-trust-task:envelope_invalid — expiresAt must be an RFC 3339 timestamp".into(),
                    details: Some(serde_json::json!({ "expiresAt": value })),
                },
            );
        }
        Err(SignTrustTaskError::Expired { value }) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason:
                        "vault/sign-trust-task:envelope_expired — envelope.expiresAt is in the past"
                            .into(),
                    details: Some(serde_json::json!({ "expiresAt": value })),
                },
            );
        }
        Err(SignTrustTaskError::App(e)) => return app_error_to_reject(&doc, e),
    };

    // Audit log — `{who, when, entryId, envelope: {id, type, recipient}}`.
    // Per the spec, payload is OMITTED (it may carry sensitive RP-side content).
    let str_field = |k: &str| {
        signed
            .signed
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    tracing::info!(
        actor = %auth.did,
        entry_id = %req.entry_id,
        envelope_id = %str_field("id"),
        envelope_type = %str_field("type"),
        envelope_recipient = %str_field("recipient"),
        principal_did = %signed.principal_did,
        "vault/sign-trust-task: signed"
    );

    success_response(
        &doc,
        VaultSignTrustTaskResponseBody {
            signed_envelope: signed.signed,
        },
    )
}

/// Translate a [`crate::operations::vault::password_post::PasswordPostError`]
/// into the canonical `vault/proxy-login/0.1` reject reason. Per the
/// spec: 4xx HTTP → `credential_rejected` (not retryable); 5xx HTTP +
/// transport failures → `target_unreachable` (retryable); bad config
/// → `malformed_request`; TOTP-not-supported → `not_implemented`.
#[cfg(feature = "webvh")]
fn password_post_error_to_reject(
    err: &crate::operations::vault::password_post::PasswordPostError,
    entry_id: &str,
) -> RejectReason {
    use crate::operations::vault::password_post::PasswordPostError;
    match err {
        PasswordPostError::NonSuccessStatus { status } if (400..500).contains(status) => {
            RejectReason::TaskFailed {
                reason: format!(
                    "vault/proxy-login:credential_rejected — third party returned HTTP {status} for entry {entry_id}"
                ),
                details: Some(serde_json::json!({
                    "status": status,
                    "remediation": "rotate the entry's password via vault/upsert/0.1",
                })),
            }
        }
        PasswordPostError::NonSuccessStatus { status } => RejectReason::TaskFailed {
            reason: format!(
                "vault/proxy-login:target_unreachable — third party returned HTTP {status}"
            ),
            details: Some(serde_json::json!({ "status": status, "retryable": true })),
        },
        PasswordPostError::Transport { url, source } => RejectReason::TaskFailed {
            reason: format!("vault/proxy-login:target_unreachable — {source} ({url})"),
            details: Some(serde_json::json!({ "url": url, "retryable": true })),
        },
        PasswordPostError::InvalidLoginUrl(msg) => RejectReason::MalformedRequest {
            reason: format!("vault/proxy-login:invalid_login_url — {msg}"),
        },
        PasswordPostError::TotpNotImplemented(msg) => RejectReason::TaskFailed {
            reason: format!("vault/proxy-login:not_implemented — {msg}"),
            details: None,
        },
        PasswordPostError::ResponseParse(msg) => RejectReason::InternalError {
            reason: format!("vault/proxy-login: response parse failure — {msg}"),
        },
    }
}
