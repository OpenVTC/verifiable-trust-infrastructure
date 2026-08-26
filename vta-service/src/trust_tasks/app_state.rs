//! Application-state trust-task slice
//! (`spec/vta/app-state/{get,put,list,delete,get-many,put-many}/1.0`).
//!
//! Versioned, namespaced, per-context JSON an application owns and the VTA does
//! not interpret — the third store, beside the vault and agent memory. Each
//! handler is:
//!
//! - **Context-gated** — the caller must be permitted to act in
//!   `payload.contextId`, enforced via [`AuthClaims::require_context`], the
//!   same ACL gate the memory and context-scoped key tasks use. This is the
//!   privilege boundary. A **namespace is not** one: an application with write
//!   access to a context reaches every namespace in it, which is why both the
//!   `put` and `delete` specifications say in their `## Authorization` sections
//!   that mutually distrusting applications belong in separate contexts.
//! - **Audited** — `app_state.{get,put,list,delete,get_many,put_many}` via
//!   [`crate::audit::record`], with the context id. The value is deliberately
//!   **not** recorded: copying application data into the audit store would give
//!   it a second home under a different retention policy.
//!
//! ## Error taxonomy
//!
//! Failures map onto the published error codes: framework **standard** codes
//! where the framework already has one (`permissionDenied`, `malformedRequest`,
//! `internalError`), and **extended** `<task-slug>:<local>` codes for the
//! task-specific failures, each carrying the `details` shape its spec declares.
//!
//! The one that matters most is `versionConflict`. Its details carry the VTA's
//! **current version and current value**, not merely a rejection: a bare
//! rejection obliges the caller to re-read, and between the rejection and the
//! re-read the record can change again, so the pattern has no fixed point under
//! contention. Returning the winner's view removes the race rather than
//! narrowing it, and the specification makes that normative rather than a
//! courtesy.

use serde_json::{Value, json};
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask, TrustTaskCode};

use vta_sdk::protocols::app_state::{
    AppStateDeleteBody, AppStateDeleteResponse, AppStateGetBody, AppStateGetManyBody,
    AppStateGetManyResponse, AppStateGetResponse, AppStateListBody, AppStateListResponse,
    AppStatePutBody, AppStatePutManyBody, AppStatePutManyResponse, AppStatePutResponse,
};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::app_state as ops;
use crate::operations::app_state::AppStateError;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, error_response, parse_payload, reject_with, success_response,
};
use trust_tasks_rs::RejectReason;

/// The family namespace for codes shared by every task in the slice. A proper
/// path prefix of each task slug, which SPEC §8.5 permits precisely so a
/// family-wide meaning is defined once.
const FAMILY_SLUG: &str = "vta/app-state";

/// Task slug (`vta/app-state/<op>`) from the incoming document's type URI, so
/// an extended code is namespaced to whichever task raised it. Falls back to
/// the family slug if the shape is unexpected — the document arrived via
/// dispatch, so a known URI is the norm.
fn slug_from_doc(doc: &TrustTask<Value>) -> String {
    doc.type_uri
        .to_string()
        .strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| FAMILY_SLUG.to_string())
}

fn ext(slug: &str, local: &str) -> TrustTaskCode {
    TrustTaskCode::new_extended(slug, local).expect("app-state extended code is grammar-valid")
}

/// Render an [`AppStateError`] as a spec-taxonomy trust-task error response.
fn app_state_reject(
    doc: &TrustTask<Value>,
    err: AppStateError,
) -> super::helpers::TrustTaskOutcome {
    let slug = slug_from_doc(doc);
    let message = err.to_string();

    let (code, details): (TrustTaskCode, Option<Value>) = match err {
        AppStateError::NotFound => (ext(&slug, "notFound"), None),

        AppStateError::VersionConflict {
            reason,
            current_version,
            current_value,
            current_deleted,
        } => {
            let mut d = json!({ "reason": reason });
            let obj = d.as_object_mut().expect("just built an object");
            if let Some(v) = current_version {
                obj.insert("currentVersion".into(), json!(v));
            }
            // Present-and-null is meaningful here: it is the stored value.
            if let Some(v) = current_value {
                obj.insert("currentValue".into(), v);
            }
            if let Some(v) = current_deleted {
                obj.insert("currentDeleted".into(), json!(v));
            }
            (ext(&slug, "versionConflict"), Some(d))
        }

        AppStateError::ValueTooLarge {
            limit_bytes,
            actual_bytes,
        } => (
            ext(&slug, "valueTooLarge"),
            Some(json!({ "limitBytes": limit_bytes, "actualBytes": actual_bytes })),
        ),

        AppStateError::FilterConflict(reason) => (
            ext(&slug, "filterConflict"),
            Some(json!({ "reason": reason })),
        ),

        AppStateError::WatermarkTooOld {
            oldest_retained_version,
            high_watermark,
        } => (
            ext(&slug, "watermarkTooOld"),
            Some(json!({
                "oldestRetainedVersion": oldest_retained_version,
                "highWatermark": high_watermark,
            })),
        ),

        AppStateError::DuplicateKey(keys) => {
            (ext(&slug, "duplicateKey"), Some(json!({ "keys": keys })))
        }

        AppStateError::AtomicBatchRejected(results) => (
            ext(&slug, "atomicBatchRejected"),
            Some(json!({ "results": results })),
        ),

        AppStateError::BatchTooLarge {
            limit_bytes,
            actual_bytes,
        } => (
            ext(&slug, "batchTooLarge"),
            Some(json!({ "limitBytes": limit_bytes, "actualBytes": actual_bytes })),
        ),

        // A caller fault the schema did not catch. `malformedRequest` rather
        // than an extended code: the framework already names this failure, and
        // an extended synonym would downgrade the status a client switches on.
        AppStateError::Validation(_) => (StandardCode::MalformedRequest.into(), None),
        AppStateError::Internal(_) => (StandardCode::InternalError.into(), None),
    };

    let mut payload = ErrorPayload::new(code).with_message(message);
    if let Some(d) = details {
        payload = payload.with_details(d);
    }
    error_response(doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

/// The context-access gate, shared by every handler.
///
/// Emits the framework's **standard** `permissionDenied` rather than an
/// extended synonym: the framework already names this failure and maps it to
/// the right status, and a task-namespaced duplicate would tell a client that
/// switches on the standard code that something else went wrong.
fn require_context(
    doc: &TrustTask<Value>,
    auth: &AuthClaims,
    context_id: &str,
) -> Result<(), super::helpers::TrustTaskOutcome> {
    auth.require_context(context_id).map_err(|e| {
        reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: e.to_string(),
            },
        )
    })
}

/// Handler for `spec/vta/app-state/get/1.0`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStateGetBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    let record = match ops::get(
        &state.app_state_ks,
        &req.context_id,
        &req.namespace,
        &req.key,
        req.include_deleted.unwrap_or(false),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(state, "app_state.get", auth, &req.key, &req.context_id).await;
    success_response(&doc, AppStateGetResponse { record })
}

/// Handler for `spec/vta/app-state/put/1.0`.
pub(super) async fn handle_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStatePutBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    let outcome = match ops::put(
        &state.app_state_ks,
        &state.app_state_locks,
        &req.context_id,
        &req.namespace,
        &req.key,
        req.value.as_ref(),
        req.merge_patch.as_ref(),
        req.expected_version,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(state, "app_state.put", auth, &req.key, &req.context_id).await;
    success_response(
        &doc,
        AppStatePutResponse {
            context_id: req.context_id,
            namespace: req.namespace,
            key: req.key,
            version: outcome.version,
            created: outcome.created,
            updated_at: outcome.updated_at,
            value_bytes: Some(outcome.value_bytes),
        },
    )
}

/// Handler for `spec/vta/app-state/list/1.0`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStateListBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    // Report the window this VTA is actually configured for, not a constant.
    // A consumer schedules against this number, so advertising 30 days while
    // the operator reaps at 7 would strand exactly the clients that trusted it.
    // `0` days means reaping is off, and the feed then says nothing rather than
    // naming a window that never expires anything.
    let retention_days = state.config.read().await.app_state.tombstone_retention_days;
    let retention_seconds = (retention_days > 0).then(|| u64::from(retention_days) * 24 * 60 * 60);

    let page = match ops::list(
        &state.app_state_ks,
        &req.context_id,
        req.namespace.as_deref(),
        req.prefix.as_deref(),
        req.since_version,
        req.include_values.unwrap_or(false),
        req.include_deleted,
        req.page_size,
        req.cursor.as_deref(),
        retention_seconds,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(
        state,
        "app_state.list",
        auth,
        &req.context_id,
        &req.context_id,
    )
    .await;
    success_response(
        &doc,
        AppStateListResponse {
            records: page.records,
            truncated: page.truncated,
            cursor: page.cursor,
            high_watermark: page.high_watermark,
            tombstone_retention_seconds: page.tombstone_retention_seconds,
        },
    )
}

/// Handler for `spec/vta/app-state/delete/1.0`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStateDeleteBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    let outcome = match ops::delete(
        &state.app_state_ks,
        &state.app_state_locks,
        &req.context_id,
        &req.namespace,
        &req.key,
        req.expected_version,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(state, "app_state.delete", auth, &req.key, &req.context_id).await;
    success_response(
        &doc,
        AppStateDeleteResponse {
            context_id: req.context_id,
            namespace: req.namespace,
            key: req.key,
            existed: outcome.existed,
            version: outcome.version,
            deleted_at: outcome.deleted_at,
        },
    )
}

/// Handler for `spec/vta/app-state/get-many/1.0`.
pub(super) async fn handle_get_many(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStateGetManyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    let (records, missing, deferred) = match ops::get_many(
        &state.app_state_ks,
        &req.context_id,
        &req.namespace,
        &req.keys,
        req.include_deleted.unwrap_or(false),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(
        state,
        "app_state.get_many",
        auth,
        &req.context_id,
        &req.context_id,
    )
    .await;
    success_response(
        &doc,
        AppStateGetManyResponse {
            records,
            missing,
            // Omitted rather than empty when nothing deferred, so a consumer
            // reading `deferred` at all is reading a real partial batch.
            deferred: (!deferred.is_empty()).then_some(deferred),
        },
    )
}

/// Handler for `spec/vta/app-state/put-many/1.0`.
pub(super) async fn handle_put_many(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AppStatePutManyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_context(&doc, auth, &req.context_id) {
        return resp;
    }
    let mode = req.mode.unwrap_or_default();
    let (results, high_watermark) = match ops::put_many(
        &state.app_state_ks,
        &state.app_state_locks,
        &req.context_id,
        &req.namespace,
        &req.writes,
        mode,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_state_reject(&doc, e),
    };
    audit_app_state(
        state,
        "app_state.put_many",
        auth,
        &req.context_id,
        &req.context_id,
    )
    .await;
    success_response(
        &doc,
        AppStatePutManyResponse {
            mode,
            results,
            high_watermark: Some(high_watermark),
        },
    )
}

/// Record an `app_state.*` audit row (best-effort; a failed write never fails
/// the operation). `resource` is the record key for single-record tasks and the
/// context id for the enumerating ones — never the value, which would copy
/// application data into a store with a different retention policy.
async fn audit_app_state(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: &str,
    context_id: &str,
) {
    if let Err(e) = audit::record(
        &state.audit_sink,
        action,
        &auth.did,
        Some(resource),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        Some(context_id),
    )
    .await
    {
        tracing::warn!(error = %e, action = %action, "audit record failed for app-state task");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::build_signing_test_app_state;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks::{
        TASK_VTA_APP_STATE_DELETE_1_0, TASK_VTA_APP_STATE_GET_1_0, TASK_VTA_APP_STATE_GET_MANY_1_0,
        TASK_VTA_APP_STATE_LIST_1_0, TASK_VTA_APP_STATE_PUT_1_0, TASK_VTA_APP_STATE_PUT_MANY_1_0,
    };

    /// An admin whose ACL grants exactly `ctx` — not a super-admin, whose empty
    /// `allowed_contexts` would reach every context and defeat the isolation
    /// test.
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

    fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().expect("app-state uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn payload_of(out: &super::super::helpers::TrustTaskOutcome) -> Value {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        doc.get("payload").cloned().unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn put_then_get_round_trips_with_a_version() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        let put = handle_put(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({
                    "contextId": "acme", "namespace": "openvtc", "key": "community/a",
                    "value": { "label": "Acme" }
                }),
            ),
        )
        .await;
        assert!(
            put.status.is_success(),
            "{}",
            String::from_utf8_lossy(&put.body)
        );
        let version = payload_of(&put)
            .get("version")
            .and_then(Value::as_u64)
            .expect("version");
        assert_eq!(version, 1);
        assert_eq!(
            payload_of(&put).get("created").and_then(Value::as_bool),
            Some(true)
        );

        let got = handle_get(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_GET_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "community/a" }),
            ),
        )
        .await;
        assert!(got.status.is_success());
        let rec = payload_of(&got).get("record").cloned().expect("record");
        assert_eq!(rec.get("version").and_then(Value::as_u64), Some(1));
        assert_eq!(rec.get("value"), Some(&json!({ "label": "Acme" })));
    }

    #[tokio::test]
    async fn a_conflict_carries_the_current_value_on_the_wire() {
        // The property that removes the re-read race has to survive the
        // handler, not merely exist in the operations layer.
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        let base = json!({ "contextId": "acme", "namespace": "openvtc", "key": "k" });

        let mut first = base.clone();
        first["value"] = json!("original");
        handle_put(&state, &auth, doc(TASK_VTA_APP_STATE_PUT_1_0, first)).await;

        let mut second = base.clone();
        second["value"] = json!("winner");
        handle_put(&state, &auth, doc(TASK_VTA_APP_STATE_PUT_1_0, second)).await;

        let mut stale = base.clone();
        stale["value"] = json!("loser");
        stale["expectedVersion"] = json!(1);
        let out = handle_put(&state, &auth, doc(TASK_VTA_APP_STATE_PUT_1_0, stale)).await;

        assert!(!out.status.is_success());
        let p = payload_of(&out);
        assert_eq!(
            p.get("code").and_then(Value::as_str),
            Some("vta/app-state/put:versionConflict")
        );
        let details = p.get("details").expect("conflict carries details");
        assert_eq!(
            details.get("currentVersion").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            details.get("currentValue"),
            Some(&json!("winner")),
            "the loser must be handed the winner's value, not just a rejection"
        );
    }

    #[tokio::test]
    async fn delete_then_change_feed_reports_the_tombstone() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        handle_put(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "gone", "value": 1 }),
            ),
        )
        .await;
        let del = handle_delete(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_DELETE_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "gone" }),
            ),
        )
        .await;
        assert!(del.status.is_success());
        assert_eq!(
            payload_of(&del).get("existed").and_then(Value::as_bool),
            Some(true)
        );

        let feed = handle_list(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_LIST_1_0,
                json!({
                    "contextId": "acme", "namespace": "openvtc", "sinceVersion": 1
                }),
            ),
        )
        .await;
        assert!(feed.status.is_success());
        let p = payload_of(&feed);
        let records = p.get("records").and_then(Value::as_array).cloned().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("deleted").and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            p.get("highWatermark").and_then(Value::as_u64).is_some(),
            "a change feed must tell the consumer what to store as its next watermark"
        );
    }

    #[tokio::test]
    async fn a_change_feed_without_a_namespace_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_list(
            &state,
            &admin_of("acme"),
            doc(
                TASK_VTA_APP_STATE_LIST_1_0,
                json!({ "contextId": "acme", "sinceVersion": 0 }),
            ),
        )
        .await;
        assert!(!out.status.is_success());
        let p = payload_of(&out);
        assert_eq!(
            p.get("code").and_then(Value::as_str),
            Some("vta/app-state/list:filterConflict")
        );
        assert_eq!(
            p.get("details")
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str),
            Some("sinceVersionRequiresNamespace")
        );
    }

    #[tokio::test]
    async fn an_independent_batch_reports_per_record_outcomes() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        handle_put(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "b", "value": 1 }),
            ),
        )
        .await;

        let out = handle_put_many(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_MANY_1_0,
                json!({
                    "contextId": "acme", "namespace": "openvtc",
                    "writes": [
                        { "key": "a", "value": 1, "expectedVersion": 0 },
                        { "key": "b", "value": 2, "expectedVersion": 999 }
                    ]
                }),
            ),
        )
        .await;
        assert!(
            out.status.is_success(),
            "an independent batch with a conflict is still a success"
        );
        let results = payload_of(&out)
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap();
        assert_eq!(
            results[0].get("outcome").and_then(Value::as_str),
            Some("written")
        );
        assert_eq!(
            results[1].get("outcome").and_then(Value::as_str),
            Some("conflict")
        );
        assert_eq!(
            payload_of(&out).get("mode").and_then(Value::as_str),
            Some("independent"),
            "the applied mode is echoed so a caller relying on the default sees what it got"
        );
    }

    #[tokio::test]
    async fn a_rejected_atomic_batch_is_an_error_carrying_every_outcome() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        handle_put(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "index", "value": [] }),
            ),
        )
        .await;

        let out = handle_put_many(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_MANY_1_0,
                json!({
                    "contextId": "acme", "namespace": "openvtc", "mode": "atomic",
                    "writes": [
                        { "key": "member", "value": 1, "expectedVersion": 0 },
                        { "key": "index", "value": ["x"], "expectedVersion": 999 }
                    ]
                }),
            ),
        )
        .await;
        assert!(!out.status.is_success());
        let p = payload_of(&out);
        assert_eq!(
            p.get("code").and_then(Value::as_str),
            Some("vta/app-state/put-many:atomicBatchRejected")
        );
        let results = p
            .get("details")
            .and_then(|d| d.get("results"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap();
        assert_eq!(
            results[0].get("outcome").and_then(Value::as_str),
            Some("skipped"),
            "the write never attempted must say so, so a retry does not rewrite \
             its create-only precondition"
        );

        // And nothing landed.
        let got = handle_get(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_GET_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "member" }),
            ),
        )
        .await;
        assert!(
            !got.status.is_success(),
            "an atomic batch that failed wrote nothing"
        );
    }

    #[tokio::test]
    async fn get_many_accounts_for_every_key() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
        handle_put(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "a", "value": 1 }),
            ),
        )
        .await;
        let out = handle_get_many(
            &state,
            &auth,
            doc(
                TASK_VTA_APP_STATE_GET_MANY_1_0,
                json!({
                    "contextId": "acme", "namespace": "openvtc",
                    "keys": ["a", "missing"]
                }),
            ),
        )
        .await;
        assert!(out.status.is_success());
        let p = payload_of(&out);
        assert_eq!(p.get("records").and_then(Value::as_array).unwrap().len(), 1);
        assert_eq!(
            p.get("missing").and_then(Value::as_array).unwrap(),
            &vec![json!("missing")]
        );
    }

    #[tokio::test]
    async fn a_caller_without_context_access_is_refused_and_writes_nothing() {
        let (state, _dir) = build_signing_test_app_state().await;
        let intruder = admin_of("other");
        let out = handle_put(
            &state,
            &intruder,
            doc(
                TASK_VTA_APP_STATE_PUT_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc", "key": "k", "value": 1 }),
            ),
        )
        .await;
        assert!(!out.status.is_success());
        assert!(
            String::from_utf8_lossy(&out.body).contains("permissionDenied"),
            "context refusal should carry the framework's standard permissionDenied"
        );

        let listed = handle_list(
            &state,
            &admin_of("acme"),
            doc(
                TASK_VTA_APP_STATE_LIST_1_0,
                json!({ "contextId": "acme", "namespace": "openvtc" }),
            ),
        )
        .await;
        assert!(
            payload_of(&listed)
                .get("records")
                .and_then(Value::as_array)
                .unwrap()
                .is_empty(),
            "a refused put must not have written"
        );
    }

    #[tokio::test]
    async fn one_context_cannot_see_another_contexts_records() {
        let (state, _dir) = build_signing_test_app_state().await;
        for ctx in ["ctx-a", "ctx-b"] {
            handle_put(
                &state,
                &admin_of(ctx),
                doc(
                    TASK_VTA_APP_STATE_PUT_1_0,
                    json!({ "contextId": ctx, "namespace": "openvtc", "key": "k", "value": ctx }),
                ),
            )
            .await;
        }
        let a = handle_list(
            &state,
            &admin_of("ctx-a"),
            doc(
                TASK_VTA_APP_STATE_LIST_1_0,
                json!({ "contextId": "ctx-a", "namespace": "openvtc", "includeValues": true }),
            ),
        )
        .await;
        let records = payload_of(&a)
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get("value"), Some(&json!("ctx-a")));
    }
}
