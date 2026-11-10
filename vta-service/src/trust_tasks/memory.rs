//! Agent-memory trust-task slice: `vta/memory/{put,delete,list}/0.2`,
//! `vta/memory/get/0.1`, and `vta/memory/{put,list,delete}/0.1` on the same
//! versioned store (`crate::operations::memory`, #2115).
//!
//! Each handler is:
//! - **Capability-gated** — read tasks require [`Capability::MemoryRead`],
//!   mutating tasks require [`Capability::MemoryWrite`]. Until this pair
//!   existed the only gate was the context, which is binary: any DID that
//!   could reach a context could also write and delete every memory in it, so
//!   there was no way to grant an agent read-only access to your own memory.
//!   Legacy ACL rows carry no explicit capability set and fall back to
//!   [`derived_capabilities_for_role`], which grants both to `admin`,
//!   `initiator` and `application` (the role a memory agent runs as), read
//!   only to `reader`, and neither to `monitor`.
//! - **Context-gated** — the caller must be permitted to act in
//!   `payload.contextId`, enforced via [`AuthClaims::require_context`]. On
//!   failure that is the framework `permissionDenied`. This is the privilege
//!   boundary: a context-A agent cannot read, write, or delete context-B
//!   memory.
//! - **Audited** — `memory.put` / `memory.list` / `memory.delete` /
//!   `memory.get` via [`crate::audit::record`], with the context id and never
//!   a value.
//!
//! ## A conflict is a read
//!
//! `versionConflict` on a 0.2 `put` or `delete` carries the item's current
//! value, so the writer that lost can merge without a re-read. That hands a
//! stored value to a caller holding only [`Capability::MemoryWrite`] — an agent
//! allowed to record but not to recall. The specifications (`put/0.2`
//! *Authorization*) therefore require the value to be withheld from such a
//! caller, and [`memory_reject`] does that; the current version, which says
//! only that the item changed, is still sent.
//!
//! [`derived_capabilities_for_role`]: vti_common::acl::derived_capabilities_for_role

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask, TrustTaskCode};

use vta_sdk::protocols::app_state::AppStateRecord;
use vta_sdk::protocols::memory::{
    MemoryDeleteBody, MemoryDeleteResponse, MemoryListBody, MemoryListResponse, MemoryPutBody,
    MemoryPutResponse,
};
use vti_common::acl::{Capability, PurposeDecision};
use vti_specs::vta::memory as spec;

use crate::auth::AuthClaims;
use crate::operations::app_state::AppStateError;
use crate::operations::memory;
use crate::server::AppState;

use super::app_state::app_state_reject;
use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with,
    reject_with_code, success_response,
};

/// Capability gate for the memory surface, mirroring the vault slices'
/// [`super::vault::require_capability`].
///
/// Checked **before** the context gate so a caller who holds neither learns
/// only that the capability is missing — the narrower fact, and the one that
/// does not reveal whether a given context exists.
async fn require_cap(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
    action: &str,
) -> Result<(), TrustTaskOutcome> {
    super::helpers::require_capability(state, auth, doc, cap, &format!("memory {action}")).await
}

/// Both gates for the 0.2 tasks and `get`: the capability and the context.
/// Either refusal is the task's declared `contextForbidden`, as its
/// specification requires ("lacks write/read access to memory in the named
/// context" — a missing capability is exactly that), with one message for
/// both, so the answer never says which gate refused or whether the context
/// exists. 0.1 keeps answering `permissionDenied`, as it always has.
async fn admit(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
    action: &str,
    context_id: &str,
    forbidden: trust_tasks_rs::DeclaredErrorCode,
) -> Result<(), TrustTaskOutcome> {
    let allowed = crate::operations::acl::caller_has_capability(&state.acl_ks, auth, cap).await
        && auth.require_context(context_id).is_ok();
    if allowed {
        return Ok(());
    }
    Err(super::helpers::reject_declared(
        doc,
        forbidden,
        format!("not permitted to {action} memory in context `{context_id}`"),
    ))
}

// ─── Purpose of use (VTI-ACL-100 – 110) ──────────────────────────────────
//
// Every read of memory is purpose-bound (VTI-ACL-102): a get, a list that
// returns values, and a conflict that hands back the value it conflicted with.
// The caller's stored ACL entry states the purposes it may use what it reads
// for; a read is served only for one it grants, and its audit row carries the
// purpose, served or refused. The versions before `get/0.2` and the 0.3 family
// carry no `purpose` member, so they read as naming none: served under `any`
// (recorded as unstated) or under an entry listing exactly one, refused under
// an entry listing more.

/// The `purpose` a request named, if its version carries the member.
fn requested_purpose(doc: &TrustTask<Value>) -> Option<String> {
    doc.payload
        .get("purpose")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// `doc` without its `purpose`: a 0.3 request (get 0.2) is its predecessor's
/// payload plus that one member (`extends`), so the rest reads as the
/// predecessor's type.
fn without_purpose(doc: &TrustTask<Value>) -> TrustTask<Value> {
    let mut doc = doc.clone();
    if let Some(m) = doc.payload.as_object_mut() {
        m.remove("purpose");
    }
    doc
}

/// Judge `requested` against the caller's **stored** entry (VTI-ACL-103,
/// -104), never a token: a narrowing binds at the next read. A caller with no
/// readable entry is refused, never read as holding `any` (VTI-ACL-101).
async fn decide_purpose(
    state: &AppState,
    auth: &AuthClaims,
    requested: Option<&str>,
) -> PurposeDecision {
    match crate::acl::get_acl_entry(&state.acl_ks, &auth.did).await {
        Ok(Some(entry)) => entry.purposes.admit(requested),
        _ => match requested {
            Some(p) => PurposeDecision::NotGranted(p.to_string()),
            None => PurposeDecision::Unnamed,
        },
    }
}

/// Refuse a read whose purpose is not granted (VTI-ACL-104): the version's
/// `purposeNotGranted` where it declares one, else a `taskFailed` saying so —
/// either way distinct from the access refusal, and carrying no content.
fn purpose_refusal(
    doc: &TrustTask<Value>,
    decision: &PurposeDecision,
    code: Option<trust_tasks_rs::DeclaredErrorCode>,
) -> TrustTaskOutcome {
    let message = match decision {
        PurposeDecision::NotGranted(p) => {
            format!("this entry does not grant the purpose `{p}` (VTI-ACL-104)")
        }
        _ => "name the purpose you will use this memory for: this entry lists more than one \
              (VTI-ACL-103)"
            .to_string(),
    };
    let details = decision.refusal_details();
    match code {
        Some(c) => reject_with_code(
            doc,
            TrustTaskCode::Extended {
                slug: c.namespace().to_string(),
                local: c.local().to_string(),
            },
            message,
            details,
        ),
        None => reject_with(
            doc,
            RejectReason::TaskFailed {
                reason: format!("purposeNotGranted: {message}"),
                details,
            },
        ),
    }
}

/// What a version of a memory task declares for the two refusals a read can
/// meet: access, and purpose (absent before the version that added it).
#[derive(Clone, Copy)]
struct Codes {
    forbidden: trust_tasks_rs::DeclaredErrorCode,
    purpose: Option<trust_tasks_rs::DeclaredErrorCode>,
}

/// Hold a purpose-bound read to the caller's purposes, recording a refusal
/// (VTI-ACL-106). `Ok` carries the decision to record with the read.
async fn admit_purpose(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    action: &str,
    context_id: &str,
    requested: Option<&str>,
    code: Option<trust_tasks_rs::DeclaredErrorCode>,
) -> Result<PurposeDecision, TrustTaskOutcome> {
    let decision = decide_purpose(state, auth, requested).await;
    if decision.is_granted() {
        return Ok(decision);
    }
    audit_refused_read(state, action, auth, context_id, &decision).await;
    Err(purpose_refusal(doc, &decision, code))
}

/// The store's refusal on the wire, with a conflict's `currentValue` withheld
/// from a caller that may write the context but not read it (module docs), or
/// whose request's purpose is not granted (VTI-ACL-102). A conflict that does
/// carry the value is a read, and is recorded as one with its purpose.
async fn memory_reject(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    err: AppStateError,
) -> TrustTaskOutcome {
    memory_reject_for(state, auth, doc, err, None).await
}

/// [`memory_reject`] for a write that may conflict: the conflict's value is
/// disclosed only for a granted purpose, and recorded as a read of `item`.
async fn memory_reject_for(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    err: AppStateError,
    item: Option<(&str, &str, Option<&str>)>,
) -> TrustTaskOutcome {
    let err = match err {
        AppStateError::VersionConflict {
            reason,
            current_version,
            current_value,
            current_deleted,
        } => {
            let mut may_read = current_value.is_some()
                && crate::operations::acl::caller_has_capability(
                    &state.acl_ks,
                    auth,
                    Capability::MemoryRead,
                )
                .await;
            if may_read && let Some((context_id, key, requested)) = item {
                let decision = decide_purpose(state, auth, requested).await;
                may_read = decision.is_granted();
                if may_read {
                    audit_read(
                        state,
                        "memory.get",
                        auth,
                        context_id,
                        &[key],
                        ReadShape::EachItem,
                        Some(&decision),
                    )
                    .await;
                }
            }
            AppStateError::VersionConflict {
                reason,
                current_version,
                current_value: current_value.filter(|_| may_read),
                current_deleted,
            }
        }
        other => other,
    };
    app_state_reject(doc, err)
}

/// A generated response type from the JSON a handler built, or an internal
/// error if the two disagree — the schema is the authority on the shape.
fn respond<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

/// A stored item as `vta/_shared/0.1/memory-record`'s `MemoryRecord`: the
/// application-state record without its namespace, which memory does not have.
fn memory_record(r: &AppStateRecord) -> Value {
    let mut m = json!({
        "contextId": r.context_id,
        "key": r.key,
        "version": r.version,
        "deleted": r.deleted,
        "updatedAt": r.updated_at,
    });
    let o = m.as_object_mut().expect("just built an object");
    if let Some(v) = &r.value {
        o.insert("value".into(), v.clone());
    }
    if let Some(b) = r.value_bytes {
        o.insert("valueBytes".into(), json!(b));
    }
    if let Some(t) = &r.created_at {
        o.insert("createdAt".into(), json!(t));
    }
    if let Some(t) = &r.deleted_at {
        o.insert("deletedAt".into(), json!(t));
    }
    m
}

/// The tombstone retention this VTA reports to change-feed callers, `None`
/// when reaping is disabled (0 days).
async fn retention_seconds(state: &AppState) -> Option<u64> {
    let days = state.config.read().await.app_state.tombstone_retention_days;
    (days > 0).then(|| u64::from(days) * 24 * 60 * 60)
}

// ─── 0.1, on the versioned store ──────────────────────────────────────────

/// Handler for `spec/vta/memory/put/0.1`: an unconditional put.
pub(super) async fn handle_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(state, auth, &doc, Capability::MemoryWrite, "put").await {
        return r;
    }
    let req: MemoryPutBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    if let Err(e) = memory::put(
        &state.memory_ks,
        &state.memory_locks,
        &req.context_id,
        &req.key,
        &req.value,
        None,
    )
    .await
    {
        return memory_reject(state, auth, &doc, e).await;
    }
    audit_write(state, "memory.put", auth, &req.context_id, &req.key).await;
    success_response(&doc, MemoryPutResponse { key: req.key })
}

/// Handler for `spec/vta/memory/list/0.1`: every live item, unpaged.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(state, auth, &doc, Capability::MemoryRead, "list").await {
        return r;
    }
    let req: MemoryListBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    // Every 0.1 listing returns values, and names no purpose.
    let decision = match admit_purpose(
        state,
        auth,
        &doc,
        "memory.list",
        &req.context_id,
        None,
        None,
    )
    .await
    {
        Ok(d) => d,
        Err(r) => return r,
    };
    let items = match memory::list_all_live(&state.memory_ks, &req.context_id).await {
        Ok(items) => items,
        Err(e) => return memory_reject(state, auth, &doc, e).await,
    };
    let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
    audit_read(
        state,
        "memory.list",
        auth,
        &req.context_id,
        &keys,
        ReadShape::KeySet,
        Some(&decision),
    )
    .await;
    success_response(&doc, MemoryListResponse { items })
}

/// Handler for `spec/vta/memory/delete/0.1`. Leaves a tombstone, as 0.2 does,
/// so a 0.2 reader syncing the context converges; answers `notFound` when
/// nothing was live, as 0.1 always has.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(state, auth, &doc, Capability::MemoryWrite, "delete").await {
        return r;
    }
    let req: MemoryDeleteBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    match memory::delete(
        &state.memory_ks,
        &state.memory_locks,
        &req.context_id,
        &req.key,
        None,
    )
    .await
    {
        Ok(out) if out.existed => {}
        Ok(_) => {
            return super::helpers::reject_declared(
                &doc,
                spec::delete::v0_1::error_codes::NOT_FOUND,
                format!(
                    "memory entry `{}` not found in context `{}`",
                    req.key, req.context_id
                ),
            );
        }
        Err(e) => return memory_reject(state, auth, &doc, e).await,
    }
    audit_write(state, "memory.delete", auth, &req.context_id, &req.key).await;
    success_response(&doc, MemoryDeleteResponse { key: req.key })
}

// ─── 0.2 and get 0.1 ──────────────────────────────────────────────────────

/// Handler for `spec/vta/memory/put/0.2`.
#[allow(deprecated)] // superseded by 0.3, and still served: the plugin and pnm send 0.2
pub(super) async fn handle_put_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::put::v0_2 as t;
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: None,
    };
    put_v0_2(state, auth, doc, codes, None).await
}

/// Handler for `spec/vta/memory/put/0.3`: 0.2's, held to the purpose it names.
pub(super) async fn handle_put_v0_3(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::put::v0_3 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: Some(t::error_codes::PURPOSE_NOT_GRANTED),
    };
    let requested = requested_purpose(&doc);
    put_v0_2(state, auth, without_purpose(&doc), codes, requested).await
}

/// `put` 0.2 and 0.3. A write discloses nothing, so naming no purpose never
/// blocks it; one that names a purpose is held to it before anything is
/// written (`put/0.3` item 8).
#[allow(deprecated)] // the 0.2 payload type reads 0.3's too (`extends`)
async fn put_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    codes: Codes,
    requested: Option<String>,
) -> TrustTaskOutcome {
    use spec::put::v0_2 as t;
    let req = match parse_payload::<t::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context_id, key) = (req.context_id.to_string(), req.key.to_string());
    if let Err(r) = admit(
        state,
        auth,
        &doc,
        Capability::MemoryWrite,
        "put",
        &context_id,
        codes.forbidden,
    )
    .await
    {
        return r;
    }
    if let Some(p) = requested.as_deref() {
        let decision = decide_purpose(state, auth, Some(p)).await;
        if !decision.is_granted() {
            return purpose_refusal(&doc, &decision, codes.purpose);
        }
    }
    let out = match memory::put(
        &state.memory_ks,
        &state.memory_locks,
        &context_id,
        &key,
        &req.value.0,
        req.expected_version.map(|v| v.0),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            let item = Some((context_id.as_str(), key.as_str(), requested.as_deref()));
            return memory_reject_for(state, auth, &doc, e, item).await;
        }
    };
    audit_write(state, "memory.put", auth, &context_id, &key).await;
    respond::<t::Response>(
        &doc,
        json!({
            "contextId": context_id,
            "key": key,
            "version": out.version,
            "wasCreated": out.created,
            "updatedAt": out.updated_at,
            "valueBytes": out.value_bytes,
        }),
    )
}

/// Handler for `spec/vta/memory/delete/0.2`.
#[allow(deprecated)] // superseded by 0.3, and still served: the plugin and pnm send 0.2
pub(super) async fn handle_delete_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::delete::v0_2 as t;
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: None,
    };
    delete_v0_2(state, auth, doc, codes, None).await
}

/// Handler for `spec/vta/memory/delete/0.3`: 0.2's, held to the purpose it
/// names.
pub(super) async fn handle_delete_v0_3(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::delete::v0_3 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: Some(t::error_codes::PURPOSE_NOT_GRANTED),
    };
    let requested = requested_purpose(&doc);
    delete_v0_2(state, auth, without_purpose(&doc), codes, requested).await
}

/// `delete` 0.2 and 0.3, as [`put_v0_2`].
#[allow(deprecated)] // the 0.2 payload type reads 0.3's too (`extends`)
async fn delete_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    codes: Codes,
    requested: Option<String>,
) -> TrustTaskOutcome {
    use spec::delete::v0_2 as t;
    let req = match parse_payload::<t::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context_id, key) = (req.context_id.to_string(), req.key.to_string());
    if let Err(r) = admit(
        state,
        auth,
        &doc,
        Capability::MemoryWrite,
        "delete",
        &context_id,
        codes.forbidden,
    )
    .await
    {
        return r;
    }
    if let Some(p) = requested.as_deref() {
        let decision = decide_purpose(state, auth, Some(p)).await;
        if !decision.is_granted() {
            return purpose_refusal(&doc, &decision, codes.purpose);
        }
    }
    let out = match memory::delete(
        &state.memory_ks,
        &state.memory_locks,
        &context_id,
        &key,
        req.expected_version.map(|v| v.0.get()),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            let item = Some((context_id.as_str(), key.as_str(), requested.as_deref()));
            return memory_reject_for(state, auth, &doc, e, item).await;
        }
    };
    audit_write(state, "memory.delete", auth, &context_id, &key).await;
    let mut body = json!({ "contextId": context_id, "key": key, "existed": out.existed });
    let o = body.as_object_mut().expect("just built an object");
    if let Some(v) = out.version {
        o.insert("version".into(), json!(v));
    }
    if let Some(t) = out.deleted_at {
        o.insert("deletedAt".into(), json!(t));
    }
    respond::<t::Response>(&doc, body)
}

/// Handler for `spec/vta/memory/list/0.2`: a snapshot or the change feed.
#[allow(deprecated)] // superseded by 0.3, and still served: the plugin and pnm send 0.2
pub(super) async fn handle_list_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::list::v0_2 as t;
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: None,
    };
    list_v0_2(state, auth, doc, codes, None).await
}

/// Handler for `spec/vta/memory/list/0.3`: 0.2's, purpose-bound when it
/// returns values.
pub(super) async fn handle_list_v0_3(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::list::v0_3 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: Some(t::error_codes::PURPOSE_NOT_GRANTED),
    };
    let requested = requested_purpose(&doc);
    list_v0_2(state, auth, without_purpose(&doc), codes, requested).await
}

/// `list` 0.2 and 0.3. A listing with values is purpose-bound; one without
/// (`includeValues: false`) shows keys and versions only and is not
/// (`list/0.3` item 9).
#[allow(deprecated)] // the 0.2 payload type reads 0.3's too (`extends`)
async fn list_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    codes: Codes,
    requested: Option<String>,
) -> TrustTaskOutcome {
    use spec::list::v0_2 as t;
    let req = match parse_payload::<t::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let context_id = req.context_id.to_string();
    if let Err(r) = admit(
        state,
        auth,
        &doc,
        Capability::MemoryRead,
        "list",
        &context_id,
        codes.forbidden,
    )
    .await
    {
        return r;
    }
    // Values by default, as 0.1 always returned them (`list/0.2`).
    let include_values = req.include_values.unwrap_or(true);
    let decision = if include_values {
        match admit_purpose(
            state,
            auth,
            &doc,
            "memory.list",
            &context_id,
            requested.as_deref(),
            codes.purpose,
        )
        .await
        {
            Ok(d) => Some(d),
            Err(r) => return r,
        }
    } else {
        None
    };
    let prefix = req.prefix.as_ref().map(|p| p.to_string());
    let page = match memory::list(
        &state.memory_ks,
        &context_id,
        prefix.as_deref(),
        req.since_version,
        include_values,
        req.include_deleted,
        req.limit
            .map(|l| usize::try_from(l.get()).unwrap_or(usize::MAX)),
        req.cursor.as_deref(),
        retention_seconds(state).await,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return memory_reject(state, auth, &doc, e).await,
    };
    let keys: Vec<&str> = page.records.iter().map(|r| r.key.as_str()).collect();
    audit_read(
        state,
        "memory.list",
        auth,
        &context_id,
        &keys,
        ReadShape::KeySet,
        decision.as_ref(),
    )
    .await;
    let items: Vec<Value> = page.records.iter().map(memory_record).collect();
    let mut body = json!({
        "items": items,
        // Always present: the namespace is fixed, so there is always one
        // counter to report, 0 for a context never written.
        "highWatermark": page.high_watermark.unwrap_or(0),
    });
    let o = body.as_object_mut().expect("just built an object");
    if page.truncated
        && let Some(c) = page.cursor
    {
        o.insert("nextCursor".into(), json!(c));
    }
    if let Some(r) = page.tombstone_retention_seconds {
        o.insert("tombstoneRetentionSeconds".into(), json!(r));
    }
    respond::<t::Response>(&doc, body)
}

/// Handler for `spec/vta/memory/get/0.1`: named items, each answered once.
#[allow(deprecated)] // superseded by 0.2, and still served: the plugin and pnm send 0.1
pub(super) async fn handle_get_v0_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::get::v0_1 as t;
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: None,
    };
    get_v0_1(state, auth, doc, codes, None).await
}

/// Handler for `spec/vta/memory/get/0.2`: 0.1's, for a purpose the caller's
/// entry grants.
pub(super) async fn handle_get_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::get::v0_2 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    let codes = Codes {
        forbidden: t::error_codes::CONTEXT_FORBIDDEN,
        purpose: Some(t::error_codes::PURPOSE_NOT_GRANTED),
    };
    let requested = requested_purpose(&doc);
    get_v0_1(state, auth, without_purpose(&doc), codes, requested).await
}

/// `get` 0.1 and 0.2: every recall is purpose-bound.
#[allow(deprecated)] // the 0.1 payload type reads 0.2's too (`extends`)
async fn get_v0_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    codes: Codes,
    requested: Option<String>,
) -> TrustTaskOutcome {
    use spec::get::v0_1 as t;
    let req = match parse_payload::<t::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let context_id = req.context_id.to_string();
    if let Err(r) = admit(
        state,
        auth,
        &doc,
        Capability::MemoryRead,
        "get",
        &context_id,
        codes.forbidden,
    )
    .await
    {
        return r;
    }
    let decision = match admit_purpose(
        state,
        auth,
        &doc,
        "memory.get",
        &context_id,
        requested.as_deref(),
        codes.purpose,
    )
    .await
    {
        Ok(d) => d,
        Err(r) => return r,
    };
    let keys: Vec<String> = req.keys.iter().map(|k| k.to_string()).collect();
    let (found, missing, deferred) = match memory::get_many(
        &state.memory_ks,
        &context_id,
        &keys,
        req.include_deleted.unwrap_or(false),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return memory_reject(state, auth, &doc, e).await,
    };
    // The items returned — never the keys merely asked for, nor a deferred
    // key, which was not read (`get/0.1` *Retention*).
    let keys: Vec<&str> = found.iter().map(|r| r.key.as_str()).collect();
    audit_read(
        state,
        "memory.get",
        auth,
        &context_id,
        &keys,
        ReadShape::EachItem,
        Some(&decision),
    )
    .await;
    let items: Vec<Value> = found.iter().map(memory_record).collect();
    let mut body = json!({ "items": items, "missing": missing });
    if !deferred.is_empty() {
        body.as_object_mut()
            .expect("just built an object")
            .insert("deferred".into(), json!(deferred));
    }
    respond::<t::Response>(&doc, body)
}

// ─── Audit ────────────────────────────────────────────────────────────────
//
// A memory key names what an agent remembered — `contact/billing`, or a key
// naming a person, a condition, a dispute — so it is personal data, and an
// audit record must refer to it without embedding it (VTI-AUD-005): the trail
// is a hash chain, so anything written into it can never be erased. Records
// therefore carry a keyed commitment to each item (`AuditSink::commit`, under
// the audit key), never the key. That still answers "which agent saw what"
// (#2116): the VTA can recompute the commitment for a candidate key.

/// The value a memory item's commitment is taken over: the context and the
/// key, so one key in two contexts is two items.
fn item_reference_input(context_id: &str, key: &str) -> String {
    format!("vta/memory\0{context_id}\0{key}")
}

/// How a read records what it returned.
#[derive(Clone, Copy)]
enum ReadShape {
    /// `get`: a commitment to each item, so a later "was item X read?" is one
    /// comparison per record.
    EachItem,
    /// `list`: one commitment to the whole returned key set, which says whether
    /// two lists saw the same items without a line per item for a context of
    /// thousands (#2116).
    KeySet,
}

/// Record a `memory.put` / `memory.delete` row: the item by commitment as its
/// resource (best-effort; a failed write never fails the op).
async fn audit_write(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    context_id: &str,
    key: &str,
) {
    let reference = state
        .audit_sink
        .commit(&item_reference_input(context_id, key))
        .await;
    record(state, action, auth, context_id, reference.as_deref(), None).await;
}

/// Record a `memory.list` / `memory.get` row: how many items the caller was
/// shown, which, by commitment, and the purpose it was shown them for
/// (VTI-ACL-106) — absent only for a listing without values, which is not
/// purpose-bound.
async fn audit_read(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    context_id: &str,
    keys: &[&str],
    shape: ReadShape,
    purpose: Option<&PurposeDecision>,
) {
    let mut detail = format!("items={}", keys.len());
    match shape {
        ReadShape::EachItem => {
            let mut refs = Vec::with_capacity(keys.len());
            for k in keys {
                if let Some(r) = state
                    .audit_sink
                    .commit(&item_reference_input(context_id, k))
                    .await
                {
                    refs.push(r);
                }
            }
            if !refs.is_empty() {
                detail.push_str(&format!(" refs={}", refs.join(",")));
            }
        }
        ReadShape::KeySet if !keys.is_empty() => {
            let mut sorted: Vec<&str> = keys.to_vec();
            sorted.sort_unstable();
            let joined: Vec<String> = sorted
                .iter()
                .map(|k| item_reference_input(context_id, k))
                .collect();
            if let Some(r) = state.audit_sink.commit(&joined.join("\n")).await {
                detail.push_str(&format!(" keySet={r}"));
            }
        }
        ReadShape::KeySet => {}
    }
    if let Some(d) = purpose {
        detail.push_str(&format!(" purpose={}", d.audit_label()));
    }
    record(state, action, auth, context_id, None, Some(&detail)).await;
}

/// Record a read refused for its purpose (VTI-ACL-106): nothing was shown, so
/// the row names no item, only the purpose asked for.
async fn audit_refused_read(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    context_id: &str,
    decision: &PurposeDecision,
) {
    let detail = format!(
        "refused=purposeNotGranted purpose={}",
        decision.audit_label()
    );
    record_outcome(
        state,
        action,
        auth,
        context_id,
        None,
        Some(&detail),
        "denied",
    )
    .await;
}

async fn record(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    context_id: &str,
    resource: Option<&str>,
    detail: Option<&str>,
) {
    record_outcome(state, action, auth, context_id, resource, detail, "success").await;
}

async fn record_outcome(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    context_id: &str,
    resource: Option<&str>,
    detail: Option<&str>,
    outcome: &str,
) {
    if let Err(e) = vta_audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        resource,
        outcome,
        Some(TRANSPORT_TRUST_TASK),
        Some(context_id),
        detail,
    )
    .await
    {
        tracing::warn!(error = %e, action = %action, "audit record failed for memory task");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::build_signing_test_app_state;
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks::{
        TASK_VTA_MEMORY_DELETE_0_1, TASK_VTA_MEMORY_LIST_0_1, TASK_VTA_MEMORY_PUT_0_1,
    };

    /// Claims for `role`, scoped to exactly `ctx`.
    fn claims_for(role: Role, ctx: &str) -> AuthClaims {
        AuthClaims {
            did: format!("did:key:z{role}"),
            role,
            allowed_contexts: vec![ctx.to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    /// An admin whose ACL grants exactly `ctx` (not a super-admin — a
    /// super-admin's empty `allowed_contexts` would reach every context, which
    /// is what we must NOT do for the isolation test).
    fn admin_of(ctx: &str) -> AuthClaims {
        AuthClaims {
            did: "did:key:zCtxAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![ctx.to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    /// `auth` with an ACL entry stating exactly its role and contexts, as a
    /// real caller has (a token is minted only for a DID with an entry): the
    /// purpose check reads the stored entry, and refuses a caller with none
    /// (VTI-ACL-101).
    async fn seeded(state: &AppState, auth: AuthClaims) -> AuthClaims {
        crate::test_support::seed_acl_entry(
            &state.acl_ks,
            &auth.did,
            auth.role.clone(),
            auth.allowed_contexts.clone(),
        )
        .await;
        auth
    }

    fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().expect("memory uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn put_doc(ctx: &str, key: &str, value: &str) -> TrustTask<Value> {
        doc(
            TASK_VTA_MEMORY_PUT_0_1,
            json!({ "contextId": ctx, "key": key, "value": value }),
        )
    }
    fn list_doc(ctx: &str) -> TrustTask<Value> {
        doc(TASK_VTA_MEMORY_LIST_0_1, json!({ "contextId": ctx }))
    }
    fn delete_doc(ctx: &str, key: &str) -> TrustTask<Value> {
        doc(
            TASK_VTA_MEMORY_DELETE_0_1,
            json!({ "contextId": ctx, "key": key }),
        )
    }

    /// A framework rejection carrying `permission_denied`. The capability gate
    /// and the context gate both land here, which is the point of §the ordering
    /// test below.
    fn is_denied(out: &super::super::helpers::TrustTaskOutcome) -> bool {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        !out.status.is_success()
            || doc
                .get("payload")
                .and_then(|p| p.get("reason"))
                .and_then(Value::as_str)
                .is_some_and(|r| r.contains("denied"))
    }

    fn response_payload(out: &super::super::helpers::TrustTaskOutcome) -> Value {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        doc.get("payload").cloned().unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn put_then_list_returns_the_item() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        let out = handle_put(&state, &auth, put_doc("acme", "name", "Ada")).await;
        assert!(out.status.is_success(), "put should succeed");
        assert_eq!(
            response_payload(&out).get("key").and_then(Value::as_str),
            Some("name")
        );

        let list = handle_list(&state, &auth, list_doc("acme")).await;
        assert!(list.status.is_success());
        let items = response_payload(&list)
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("key").and_then(Value::as_str), Some("name"));
        assert_eq!(items[0].get("value").and_then(Value::as_str), Some("Ada"));
    }

    /// The point of the whole capability field: an entry narrowed to read
    /// cannot write, even though its role can — and the check reads the stored
    /// entry, so the narrowing binds the caller's *next* request rather than
    /// waiting for their token to expire.
    #[tokio::test]
    async fn a_narrowed_entry_loses_what_its_role_still_carries() {
        use vti_common::acl::{AclEntry, Capability, store_acl_entry};

        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");

        // Un-narrowed first: the write works, so the refusal below is the
        // narrowing and not some other gate.
        assert!(
            handle_put(&state, &auth, put_doc("acme", "before", "ok"))
                .await
                .status
                .is_success()
        );

        let narrowed = AclEntry::new(&auth.did, auth.role.clone(), "did:key:zAdmin")
            .with_contexts(vec!["acme".to_string()])
            .with_capabilities(vec![Capability::MemoryRead]);
        store_acl_entry(&state.acl_ks, &narrowed)
            .await
            .expect("store the narrowed entry");

        let refused = handle_put(&state, &auth, put_doc("acme", "after", "no")).await;
        assert!(
            !refused.status.is_success(),
            "a memory-read-only entry must not write"
        );
        assert!(
            handle_list(&state, &auth, list_doc("acme"))
                .await
                .status
                .is_success(),
            "…and must still read: narrowing removes one capability, not the entry"
        );
    }

    /// A capability the role does not carry cannot be recovered by naming it,
    /// which is what keeps the role an upper bound rather than a suggestion.
    #[tokio::test]
    async fn naming_a_capability_the_role_lacks_does_not_grant_it() {
        use vti_common::acl::{AclEntry, Capability, store_acl_entry};

        let (state, _dir) = build_signing_test_app_state().await;
        let auth = claims_for(Role::Reader, "acme");

        let entry = AclEntry::new(&auth.did, Role::Reader, "did:key:zAdmin")
            .with_contexts(vec!["acme".to_string()])
            .with_capabilities(vec![Capability::MemoryRead, Capability::MemoryWrite]);
        store_acl_entry(&state.acl_ks, &entry)
            .await
            .expect("store the entry");

        assert!(
            !handle_put(&state, &auth, put_doc("acme", "k", "v"))
                .await
                .status
                .is_success(),
            "a reader naming memory-write must still not write"
        );
        assert!(
            handle_list(&state, &auth, list_doc("acme"))
                .await
                .status
                .is_success(),
            "the capability the role does carry is unaffected"
        );
    }

    #[tokio::test]
    async fn put_same_key_twice_upserts() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        handle_put(&state, &auth, put_doc("acme", "name", "Ada")).await;
        handle_put(&state, &auth, put_doc("acme", "name", "Grace")).await;
        let list = handle_list(&state, &auth, list_doc("acme")).await;
        let items = response_payload(&list)
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(items.len(), 1, "re-put must replace, not append");
        assert_eq!(items[0].get("value").and_then(Value::as_str), Some("Grace"));
    }

    #[tokio::test]
    async fn delete_removes_then_unknown_is_not_found() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        handle_put(&state, &auth, put_doc("acme", "k", "v")).await;
        let del = handle_delete(&state, &auth, delete_doc("acme", "k")).await;
        assert!(del.status.is_success(), "delete of present key succeeds");
        assert!(
            handle_list(&state, &auth, list_doc("acme"))
                .await
                .status
                .is_success()
        );

        let again = handle_delete(&state, &auth, delete_doc("acme", "k")).await;
        assert!(!again.status.is_success(), "delete of absent key must fail");
        let body = String::from_utf8_lossy(&again.body);
        assert!(
            body.contains("not found"),
            "unknown key should report not-found, got: {body}"
        );
    }

    #[tokio::test]
    async fn caller_without_context_access_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        // Admin of `other` must not touch `acme` memory — the privilege boundary.
        let intruder = admin_of("other");
        let out = handle_put(&state, &intruder, put_doc("acme", "k", "v")).await;
        assert!(
            !out.status.is_success(),
            "a caller without access to the context must be refused"
        );
        let body = String::from_utf8_lossy(&out.body);
        assert!(
            body.contains("permissionDenied"),
            "context refusal should carry the permissionDenied reject code, got: {body}"
        );
        // And nothing was written: an authorised admin sees an empty context.
        let list = handle_list(&state, &admin_of("acme"), list_doc("acme")).await;
        let items = response_payload(&list)
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty(), "refused put must not have written");
    }

    #[tokio::test]
    async fn memory_in_context_a_is_not_listed_for_context_b() {
        let (state, _dir) = build_signing_test_app_state().await;
        handle_put(
            &state,
            &seeded(&state, admin_of("ctx-a")).await,
            put_doc("ctx-a", "secret", "a-only"),
        )
        .await;
        handle_put(
            &state,
            &seeded(&state, admin_of("ctx-b")).await,
            put_doc("ctx-b", "secret", "b-only"),
        )
        .await;

        let a = handle_list(
            &state,
            &seeded(&state, admin_of("ctx-a")).await,
            list_doc("ctx-a"),
        )
        .await;
        let items = response_payload(&a)
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(items.len(), 1, "context A lists only its own entry");
        assert_eq!(
            items[0].get("value").and_then(Value::as_str),
            Some("a-only")
        );
    }

    /// The gap this pair of capabilities closes: before it existed the only
    /// gate was the context, which is binary, so *any* role that could reach a
    /// context could rewrite every memory in it. A `reader` is a read-only
    /// consumer by definition.
    #[tokio::test]
    async fn a_reader_can_list_memory_but_not_write_it() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, claims_for(Role::Reader, "ctx-a")).await;

        let out = handle_list(&state, &auth, list_doc("ctx-a")).await;
        assert!(
            out.status.is_success(),
            "reader holds MemoryRead, so listing must succeed"
        );

        let out = handle_put(&state, &auth, put_doc("ctx-a", "user/name", "Ada")).await;
        assert!(
            is_denied(&out),
            "reader does not hold MemoryWrite, so put must be refused"
        );

        let out = handle_delete(&state, &auth, delete_doc("ctx-a", "user/name")).await;
        assert!(
            is_denied(&out),
            "reader does not hold MemoryWrite, so delete must be refused"
        );
    }

    /// `monitor` is the least-privileged role and the `Default` for
    /// `AuthClaims` — a fixture that leaks past its expected reach lands here.
    /// It must reach nothing, not "everything in whatever context it names".
    #[tokio::test]
    async fn a_monitor_reaches_no_memory_at_all() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = claims_for(Role::Monitor, "ctx-a");

        assert!(is_denied(
            &handle_list(&state, &auth, list_doc("ctx-a")).await
        ));
        assert!(is_denied(
            &handle_put(&state, &auth, put_doc("ctx-a", "user/name", "Ada")).await
        ));
    }

    /// `application` is what a memory agent runs as (`vta-agent-memory` grants
    /// exactly it). If this regresses, every existing install of that plugin
    /// stops being able to save.
    #[tokio::test]
    async fn an_application_keeps_full_memory_access() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, claims_for(Role::Application, "ctx-a")).await;

        assert!(
            handle_put(&state, &auth, put_doc("ctx-a", "user/name", "Ada"))
                .await
                .status
                .is_success()
        );
        assert!(
            handle_list(&state, &auth, list_doc("ctx-a"))
                .await
                .status
                .is_success()
        );
        assert!(
            handle_delete(&state, &auth, delete_doc("ctx-a", "user/name"))
                .await
                .status
                .is_success()
        );
    }

    /// The capability is checked before the context, so a caller missing it
    /// cannot use the error to probe which contexts exist.
    #[tokio::test]
    async fn the_capability_gate_runs_before_the_context_gate() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = claims_for(Role::Monitor, "ctx-a");
        let out = handle_list(&state, &auth, list_doc("ctx-they-cannot-reach")).await;
        assert!(
            is_denied(&out),
            "denied either way — the point is it is refused on the capability, \
             so the reason text never depends on whether that context exists"
        );
    }

    // ─── 0.2 and get 0.1 (#2115) ─────────────────────────────────────────

    use vta_sdk::trust_tasks::{
        TASK_VTA_MEMORY_DELETE_0_2, TASK_VTA_MEMORY_DELETE_0_3, TASK_VTA_MEMORY_GET_0_1,
        TASK_VTA_MEMORY_GET_0_2, TASK_VTA_MEMORY_LIST_0_2, TASK_VTA_MEMORY_LIST_0_3,
        TASK_VTA_MEMORY_PUT_0_2, TASK_VTA_MEMORY_PUT_0_3,
    };
    use vti_common::acl::PurposeScope;

    fn code(out: &TrustTaskOutcome) -> String {
        response_payload(out)
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn details(out: &TrustTaskOutcome) -> Value {
        response_payload(out)
            .get("details")
            .cloned()
            .unwrap_or(Value::Null)
    }

    async fn put2(state: &AppState, auth: &AuthClaims, payload: Value) -> TrustTaskOutcome {
        handle_put_v0_2(state, auth, doc(TASK_VTA_MEMORY_PUT_0_2, payload)).await
    }

    fn version_of(out: &TrustTaskOutcome) -> u64 {
        response_payload(out)["version"]
            .as_u64()
            .unwrap_or_else(|| panic!("no version: {}", String::from_utf8_lossy(&out.body)))
    }

    #[tokio::test]
    async fn a_put_returns_a_version_the_next_write_can_condition_on() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        let first = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "one"}),
        )
        .await;
        assert!(
            first.status.is_success(),
            "{}",
            String::from_utf8_lossy(&first.body)
        );
        assert_eq!(response_payload(&first)["wasCreated"], true);
        let v = version_of(&first);
        let second = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "two", "expectedVersion": v}),
        )
        .await;
        assert!(second.status.is_success());
        assert!(version_of(&second) > v);
    }

    /// The race #2115 is about: the loser is handed the winner's view.
    #[tokio::test]
    async fn a_stale_put_conflicts_and_carries_the_current_value() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        let first = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "one"}),
        )
        .await;
        let v = version_of(&first);
        put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "two"}),
        )
        .await;
        let lost = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "three", "expectedVersion": v}),
        )
        .await;
        assert_eq!(code(&lost), "vta/memory/put:versionConflict");
        let d = details(&lost);
        assert_eq!(d["reason"], "versionMismatch");
        assert_eq!(d["currentValue"], "two");
        assert!(d["currentVersion"].as_u64().unwrap() > v);
    }

    /// A conflict is a read. An entry that may write memory but not read it
    /// learns that the item changed, never what it now says.
    #[tokio::test]
    async fn a_write_only_caller_is_not_shown_the_value_in_a_conflict() {
        use vti_common::acl::{AclEntry, store_acl_entry};
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "secret"}),
        )
        .await;
        let write_only = AclEntry::new(&auth.did, auth.role.clone(), "did:key:zAdmin")
            .with_contexts(vec!["acme".to_string()])
            .with_capabilities(vec![Capability::MemoryWrite]);
        store_acl_entry(&state.acl_ks, &write_only).await.unwrap();
        let out = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "x", "expectedVersion": 0}),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/put:versionConflict");
        let d = details(&out);
        assert_eq!(d["reason"], "recordExists");
        assert!(d.get("currentValue").is_none(), "value leaked: {d}");
        assert!(d["currentVersion"].is_u64());
    }

    #[tokio::test]
    async fn a_stale_delete_conflicts_and_a_tombstone_reaches_the_change_feed() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        let w = put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "v"}),
        )
        .await;
        let v = version_of(&w);
        put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "v2"}),
        )
        .await;

        let stale = handle_delete_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_DELETE_0_2,
                json!({"contextId": "acme", "key": "k", "expectedVersion": v}),
            ),
        )
        .await;
        assert_eq!(code(&stale), "vta/memory/delete:versionConflict");
        assert_eq!(details(&stale)["currentValue"], "v2");

        let del = handle_delete_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_DELETE_0_2,
                json!({"contextId": "acme", "key": "k"}),
            ),
        )
        .await;
        assert_eq!(response_payload(&del)["existed"], true);

        let feed = handle_list_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_LIST_0_2,
                json!({"contextId": "acme", "sinceVersion": v}),
            ),
        )
        .await;
        let p = response_payload(&feed);
        let items = p["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{p}");
        assert_eq!(items[0]["deleted"], true);
        assert!(items[0].get("value").is_none());
        assert!(p["highWatermark"].as_u64().unwrap() > v);
        // And 0.1 reads the same store: the item is gone.
        let old = handle_list(&state, &auth, list_doc("acme")).await;
        assert!(
            response_payload(&old)["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_change_feed_that_excludes_tombstones_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_list_v0_2(
            &state,
            &seeded(&state, admin_of("acme")).await,
            doc(
                TASK_VTA_MEMORY_LIST_0_2,
                json!({"contextId": "acme", "sinceVersion": 0, "includeDeleted": false}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/list:filterConflict");
        assert_eq!(details(&out)["reason"], "changeFeedCannotExcludeDeleted");
    }

    #[tokio::test]
    async fn a_cursor_this_vta_did_not_issue_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_list_v0_2(
            &state,
            &seeded(&state, admin_of("acme")).await,
            doc(
                TASK_VTA_MEMORY_LIST_0_2,
                json!({"contextId": "acme", "cursor": "not-a-cursor"}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/list:cursorInvalid");
    }

    #[tokio::test]
    async fn a_watermark_older_than_the_reaped_tombstones_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "k", "value": "v"}),
        )
        .await;
        let del = handle_delete_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_DELETE_0_2,
                json!({"contextId": "acme", "key": "k"}),
            ),
        )
        .await;
        let tomb = version_of(&del);
        crate::operations::app_state::reap_tombstones_through(
            &state.memory_ks,
            &state.memory_locks,
            "acme",
            crate::operations::memory::NAMESPACE,
            tomb,
        )
        .await
        .unwrap();
        let out = handle_list_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_LIST_0_2,
                json!({"contextId": "acme", "sinceVersion": 0}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/list:watermarkTooOld");
    }

    /// A snapshot pages by cursor and narrows by prefix, and values come back
    /// by default, as 0.1 always returned them.
    #[tokio::test]
    async fn a_snapshot_pages_and_narrows_by_prefix() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        for k in ["contact/a", "contact/b", "contact/c", "pref/x"] {
            put2(
                &state,
                &auth,
                json!({"contextId": "acme", "key": k, "value": k}),
            )
            .await;
        }
        let page = |cursor: Option<String>| {
            let mut p = json!({"contextId": "acme", "prefix": "contact/", "limit": 2});
            if let Some(c) = cursor {
                p["cursor"] = json!(c);
            }
            doc(TASK_VTA_MEMORY_LIST_0_2, p)
        };
        let one = response_payload(&handle_list_v0_2(&state, &auth, page(None)).await);
        assert_eq!(one["items"].as_array().unwrap().len(), 2, "{one}");
        assert_eq!(one["items"][0]["value"], "contact/a");
        let next = one["nextCursor"]
            .as_str()
            .expect("more to come")
            .to_string();
        let two = response_payload(&handle_list_v0_2(&state, &auth, page(Some(next))).await);
        assert_eq!(two["items"].as_array().unwrap().len(), 1, "{two}");
        assert_eq!(two["items"][0]["key"], "contact/c");
        assert!(two.get("nextCursor").is_none());
    }

    /// Each key answered once, and an item 0.1 wrote reads back with its
    /// version — one store.
    #[tokio::test]
    async fn get_answers_every_key_once_including_items_0_1_wrote() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        handle_put(&state, &auth, put_doc("acme", "name", "Ada")).await;
        let out = handle_get_v0_1(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_GET_0_1,
                json!({"contextId": "acme", "keys": ["name", "absent"]}),
            ),
        )
        .await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let p = response_payload(&out);
        assert_eq!(p["items"][0]["value"], "Ada");
        assert!(p["items"][0]["version"].is_u64());
        assert_eq!(p["missing"], json!(["absent"]));
    }

    #[tokio::test]
    async fn get_refuses_a_duplicate_key() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_get_v0_1(
            &state,
            &seeded(&state, admin_of("acme")).await,
            doc(
                TASK_VTA_MEMORY_GET_0_1,
                json!({"contextId": "acme", "keys": ["a", "a"]}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/get:duplicateKey");
    }

    /// 0.2's refusal for a caller without access is the declared
    /// `contextForbidden`, for the context gate and the capability gate alike.
    #[tokio::test]
    async fn a_caller_without_access_gets_context_forbidden() {
        let (state, _dir) = build_signing_test_app_state().await;
        let get = handle_get_v0_1(
            &state,
            &admin_of("other"),
            doc(
                TASK_VTA_MEMORY_GET_0_1,
                json!({"contextId": "acme", "keys": ["k"]}),
            ),
        )
        .await;
        assert_eq!(code(&get), "vta/memory/get:contextForbidden");
        let reader_put = put2(
            &state,
            &claims_for(Role::Reader, "acme"),
            json!({"contextId": "acme", "key": "k", "value": "v"}),
        )
        .await;
        assert_eq!(code(&reader_put), "vta/memory/put:contextForbidden");
        let intruder = admin_of("other");
        let del = handle_delete_v0_2(
            &state,
            &intruder,
            doc(
                TASK_VTA_MEMORY_DELETE_0_2,
                json!({"contextId": "acme", "key": "k"}),
            ),
        )
        .await;
        assert_eq!(code(&del), "vta/memory/delete:contextForbidden");
        let list = handle_list_v0_2(
            &state,
            &intruder,
            doc(TASK_VTA_MEMORY_LIST_0_2, json!({"contextId": "acme"})),
        )
        .await;
        assert_eq!(code(&list), "vta/memory/list:contextForbidden");
    }

    /// #2116, under VTI-AUD-005: the trail says which items each read returned
    /// and which item each write touched — by keyed commitment, never by key,
    /// because a key is personal data and the chained trail can never erase it.
    #[tokio::test]
    async fn the_audit_trail_names_items_by_commitment_never_by_key() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = seeded(&state, admin_of("acme")).await;
        put2(
            &state,
            &auth,
            json!({"contextId": "acme", "key": "person/ada-lovelace", "value": "v"}),
        )
        .await;
        handle_get_v0_1(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_GET_0_1,
                json!({"contextId": "acme", "keys": ["person/ada-lovelace", "absent"]}),
            ),
        )
        .await;
        handle_list_v0_2(
            &state,
            &auth,
            doc(TASK_VTA_MEMORY_LIST_0_2, json!({"contextId": "acme"})),
        )
        .await;
        handle_delete_v0_2(
            &state,
            &auth,
            doc(
                TASK_VTA_MEMORY_DELETE_0_2,
                json!({"contextId": "acme", "key": "person/ada-lovelace"}),
            ),
        )
        .await;

        let rows: Vec<String> = state
            .audit_ks
            .prefix_iter_raw("log:")
            .await
            .unwrap()
            .into_iter()
            .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
            .collect();
        let memory_rows: Vec<&String> = rows.iter().filter(|r| r.contains("memory.")).collect();
        assert_eq!(memory_rows.len(), 4, "{memory_rows:#?}");
        for r in &rows {
            assert!(
                !r.contains("ada-lovelace"),
                "a memory key reached the trail: {r}"
            );
        }
        let one = |action: &str| {
            memory_rows
                .iter()
                .find(|r| r.contains(&format!("\"{action}\"")))
                .unwrap_or_else(|| panic!("no {action} row"))
                .to_string()
        };
        // Put and delete name the same item, by the same commitment.
        let reference = |row: &str| {
            let at = row.find("hmac-sha256:").expect("a commitment");
            row[at..at + "hmac-sha256:".len() + 36 + 1 + 32].to_string()
        };
        assert_eq!(
            reference(&one("memory.put")),
            reference(&one("memory.delete"))
        );
        // Get names exactly the item it returned, not the one it was asked for
        // and did not find.
        let get = one("memory.get");
        assert!(get.contains("items=1 refs="), "{get}");
        assert!(get.contains(&reference(&one("memory.put"))), "{get}");
        assert!(one("memory.list").contains("items=1 keySet=hmac-sha256:"));
    }

    // ─── Purpose of use (VTI-ACL-100 – 110) ──────────────────────────────

    /// An application acting in `ctx` whose entry states `purposes`.
    async fn agent_for(state: &AppState, ctx: &str, purposes: PurposeScope) -> AuthClaims {
        let auth = claims_for(Role::Application, ctx);
        let entry = crate::acl::AclEntry::new(&auth.did, Role::Application, "test")
            .with_contexts(vec![ctx.to_string()])
            .with_purposes(purposes);
        crate::acl::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
        auth
    }

    fn listed(ps: &[&str]) -> PurposeScope {
        PurposeScope::listed(ps.iter().copied()).unwrap()
    }

    async fn plant(state: &AppState, ctx: &str, key: &str, value: &str) -> u64 {
        let admin = seeded(state, admin_of(ctx)).await;
        version_of(
            &put2(
                state,
                &admin,
                json!({"contextId": ctx, "key": key, "value": value}),
            )
            .await,
        )
    }

    async fn get2(state: &AppState, auth: &AuthClaims, payload: Value) -> TrustTaskOutcome {
        handle_get_v0_2(state, auth, doc(TASK_VTA_MEMORY_GET_0_2, payload)).await
    }

    /// The audit rows a test wrote, as text.
    async fn audit_rows(state: &AppState) -> Vec<String> {
        state
            .audit_ks
            .prefix_iter_raw("log:")
            .await
            .unwrap()
            .into_iter()
            .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
            .filter(|r| r.contains("memory."))
            .collect()
    }

    /// VTI-ACL-103 / -104 / -106: a recall is served only for a purpose the
    /// entry grants, refused distinctly and without content otherwise, and
    /// audited with its purpose either way.
    #[tokio::test]
    async fn vti_acl_104_a_recall_is_served_only_for_a_granted_purpose() {
        let (state, _dir) = build_signing_test_app_state().await;
        plant(&state, "acme", "contact/billing", "billing@acme.example").await;
        let agent = agent_for(
            &state,
            "acme",
            listed(&["personalisation", "taskExecution"]),
        )
        .await;
        let ask = |purpose: Option<&str>| {
            let mut p = json!({"contextId": "acme", "keys": ["contact/billing"]});
            if let Some(x) = purpose {
                p["purpose"] = json!(x);
            }
            p
        };

        let out = get2(&state, &agent, ask(Some("personalisation"))).await;
        assert_eq!(
            response_payload(&out)["items"][0]["value"],
            "billing@acme.example",
            "a granted purpose is served"
        );

        let out = get2(&state, &agent, ask(Some("analytics"))).await;
        assert_eq!(code(&out), "vta/memory/get:purposeNotGranted");
        assert_eq!(
            details(&out),
            json!({"purposeNamed": true, "purpose": "analytics"})
        );
        assert!(
            !String::from_utf8_lossy(&out.body).contains("billing@acme.example"),
            "a refusal discloses nothing"
        );

        // More than one purpose listed: a request must name one.
        let out = get2(&state, &agent, ask(None)).await;
        assert_eq!(code(&out), "vta/memory/get:purposeNotGranted");
        assert_eq!(details(&out), json!({"purposeNamed": false}));

        // get/0.1 names none, so it is refused here too — as a task failure,
        // distinct from the access refusal (`contextForbidden`).
        let out = handle_get_v0_1(&state, &agent, doc(TASK_VTA_MEMORY_GET_0_1, ask(None))).await;
        assert_eq!(code(&out), "taskFailed");
        assert_eq!(details(&out), json!({"purposeNamed": false}));

        let rows = audit_rows(&state).await;
        assert!(
            rows.iter()
                .any(|r| r.contains("memory.get") && r.contains("purpose=personalisation")),
            "the served read carries its purpose: {rows:#?}"
        );
        assert!(
            rows.iter().any(|r| r.contains("memory.get")
                && r.contains("refused=purposeNotGranted purpose=analytics")),
            "the refused read is recorded too: {rows:#?}"
        );
    }

    /// VTI-ACL-103: an entry listing exactly one purpose reads a request naming
    /// none as naming it, so the versions before purposes keep working.
    #[tokio::test]
    async fn vti_acl_103_a_single_listed_purpose_applies_when_none_is_named() {
        let (state, _dir) = build_signing_test_app_state().await;
        plant(&state, "acme", "k", "v").await;
        let agent = agent_for(&state, "acme", listed(&["taskExecution"])).await;
        let out = handle_get_v0_1(
            &state,
            &agent,
            doc(
                TASK_VTA_MEMORY_GET_0_1,
                json!({"contextId": "acme", "keys": ["k"]}),
            ),
        )
        .await;
        assert_eq!(response_payload(&out)["items"][0]["value"], "v");
        assert!(
            audit_rows(&state)
                .await
                .iter()
                .any(|r| r.contains("memory.get") && r.contains("purpose=taskExecution"))
        );
    }

    /// VTI-ACL-105: `any` never grants model training; a request naming none
    /// under `any` is served and recorded as unstated.
    #[tokio::test]
    async fn vti_acl_105_any_does_not_grant_model_training() {
        let (state, _dir) = build_signing_test_app_state().await;
        plant(&state, "acme", "k", "v").await;
        let agent = agent_for(&state, "acme", PurposeScope::Any).await;
        let out = get2(
            &state,
            &agent,
            json!({"contextId": "acme", "keys": ["k"], "purpose": "modelTraining"}),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/get:purposeNotGranted");

        let out = get2(&state, &agent, json!({"contextId": "acme", "keys": ["k"]})).await;
        assert_eq!(response_payload(&out)["items"][0]["value"], "v");
        assert!(
            audit_rows(&state)
                .await
                .iter()
                .any(|r| r.contains("memory.get") && r.contains("purpose=unstated"))
        );
    }

    /// `list/0.3` items 9–10: a listing with values is purpose-bound; one
    /// without is not.
    #[tokio::test]
    async fn a_listing_with_values_is_held_to_its_purpose_and_one_without_is_not() {
        let (state, _dir) = build_signing_test_app_state().await;
        plant(&state, "acme", "k", "v").await;
        let agent = agent_for(&state, "acme", listed(&["personalisation"])).await;
        let list3 = |payload: Value| {
            handle_list_v0_3(&state, &agent, doc(TASK_VTA_MEMORY_LIST_0_3, payload))
        };

        let out = list3(json!({"contextId": "acme", "purpose": "analytics"})).await;
        assert_eq!(code(&out), "vta/memory/list:purposeNotGranted");

        let out = list3(json!({
            "contextId": "acme", "purpose": "analytics", "includeValues": false
        }))
        .await;
        assert_eq!(
            response_payload(&out)["items"][0]["key"],
            "k",
            "keys and versions disclose no content: {}",
            String::from_utf8_lossy(&out.body)
        );

        let out = list3(json!({"contextId": "acme"})).await;
        assert_eq!(
            response_payload(&out)["items"][0]["value"],
            "v",
            "the only listed purpose applies"
        );

        // list/0.2 and 0.1 name none: refused under an entry listing more than
        // one, as a task failure.
        let two = agent_for(&state, "acme", listed(&["personalisation", "analytics"])).await;
        let out = handle_list_v0_2(
            &state,
            &two,
            doc(TASK_VTA_MEMORY_LIST_0_2, json!({"contextId": "acme"})),
        )
        .await;
        assert_eq!(code(&out), "taskFailed");
        let out = handle_list(&state, &two, list_doc("acme")).await;
        assert_eq!(code(&out), "taskFailed");
    }

    /// `put/0.3` / `delete/0.3`: a write naming a purpose its entry does not
    /// grant is refused before anything is written; one naming none is not
    /// refused for it.
    #[tokio::test]
    async fn a_write_naming_an_ungranted_purpose_is_refused_before_writing() {
        let (state, _dir) = build_signing_test_app_state().await;
        let v = plant(&state, "acme", "k", "v").await;
        let agent = agent_for(&state, "acme", listed(&["personalisation"])).await;

        let out = handle_put_v0_3(
            &state,
            &agent,
            doc(
                TASK_VTA_MEMORY_PUT_0_3,
                json!({"contextId": "acme", "key": "k", "value": "w", "purpose": "analytics"}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/put:purposeNotGranted");
        let out = handle_delete_v0_3(
            &state,
            &agent,
            doc(
                TASK_VTA_MEMORY_DELETE_0_3,
                json!({"contextId": "acme", "key": "k", "purpose": "analytics"}),
            ),
        )
        .await;
        assert_eq!(code(&out), "vta/memory/delete:purposeNotGranted");

        let admin = seeded(&state, admin_of("acme")).await;
        let out = get2(&state, &admin, json!({"contextId": "acme", "keys": ["k"]})).await;
        let item = &response_payload(&out)["items"][0];
        assert_eq!(
            (item["value"].as_str(), item["version"].as_u64()),
            (Some("v"), Some(v))
        );

        let two = agent_for(&state, "acme", listed(&["personalisation", "analytics"])).await;
        let out = handle_put_v0_3(
            &state,
            &two,
            doc(
                TASK_VTA_MEMORY_PUT_0_3,
                json!({"contextId": "acme", "key": "k2", "value": "w"}),
            ),
        )
        .await;
        assert!(version_of(&out) > v, "a write naming no purpose is served");
    }

    /// `put/0.3` item 9 (VTI-ACL-102): a conflict carries the current value
    /// only for a granted purpose, and that disclosure is audited as a read.
    #[tokio::test]
    async fn a_conflict_discloses_the_current_value_only_for_a_granted_purpose() {
        let (state, _dir) = build_signing_test_app_state().await;
        plant(&state, "acme", "k", "current").await;
        let agent = agent_for(&state, "acme", listed(&["personalisation", "analytics"])).await;
        let stale = json!({"contextId": "acme", "key": "k", "value": "x", "expectedVersion": 0});

        let out = put2(&state, &agent, stale.clone()).await;
        assert_eq!(code(&out), "vta/memory/put:versionConflict");
        assert_eq!(
            details(&out)["currentValue"],
            Value::Null,
            "no purpose named under two: the value is withheld"
        );

        let mut named = stale.clone();
        named["purpose"] = json!("analytics");
        let out = handle_put_v0_3(&state, &agent, doc(TASK_VTA_MEMORY_PUT_0_3, named)).await;
        assert_eq!(code(&out), "vta/memory/put:versionConflict");
        assert_eq!(details(&out)["currentValue"], "current");
        assert!(
            audit_rows(&state)
                .await
                .iter()
                .any(|r| r.contains("memory.get") && r.contains("purpose=analytics")),
            "a disclosing conflict is recorded as a read"
        );
    }
}
