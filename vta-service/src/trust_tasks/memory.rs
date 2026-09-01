//! Agent-memory trust-task slice (`spec/vta/memory/{put,list,delete}/0.1`).
//!
//! A per-context key/value store for AI-agent memory. Each handler is:
//! - **Capability-gated** — read tasks require [`Capability::MemoryRead`],
//!   mutating tasks require [`Capability::MemoryWrite`]. Until this pair
//!   existed the only gate was the context, which is binary: any DID that
//!   could reach a context could also write and delete every memory in it, so
//!   there was no way to grant an agent read-only access to your own memory.
//!   The published specification already assumed otherwise —
//!   `vta/memory/delete/0.1` reasons about "a VTA whose write capability is
//!   granted more freely than its read capability". Legacy ACL rows carry no
//!   explicit capability set and fall back to
//!   [`derived_capabilities_for_role`], which grants both to `admin`,
//!   `initiator` and `application` (the role a memory agent runs as), read
//!   only to `reader`, and neither to `monitor`.
//! - **Context-gated** — the caller must be permitted to act in
//!   `payload.contextId`, enforced via [`AuthClaims::require_context`], the
//!   exact ACL gate the context-scoped key tasks use
//!   (`operations::holder_keys::resolve_holder_keys` / `operations::keys`). On
//!   failure `require_context` returns [`AppError::Forbidden`], which
//!   [`app_error_to_reject`] maps to the framework `permission_denied`. This is
//!   the privilege boundary: a context-A agent cannot read, write, or delete
//!   context-B memory. **Not** operator step-up-gated (unlike the issued-
//!   credential slice).
//! - **Audited** — `memory.put` / `memory.list` / `memory.delete` via
//!   [`crate::audit::record`] (with the context id), mirroring the
//!   credentials/vault handlers.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use vta_sdk::protocols::memory::{
    MemoryDeleteBody, MemoryDeleteResponse, MemoryListBody, MemoryListResponse, MemoryPutBody,
    MemoryPutResponse,
};

use trust_tasks_rs::RejectReason;
use vti_common::acl::{Capability, role_has_capability};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::memory;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Capability gate for the memory surface, mirroring the vault slices'
/// [`super::vault::require_capability`].
///
/// Checked **before** the context gate so a caller who holds neither learns
/// only that the capability is missing — the narrower fact, and the one that
/// does not reveal whether a given context exists.
fn require_cap(
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
    action: &str,
) -> Result<(), super::helpers::TrustTaskOutcome> {
    if role_has_capability(&auth.role, cap) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "memory {action} denied: role {} does not carry {cap:?} capability",
                    auth.role
                ),
            },
        ))
    }
}

/// Handler for `spec/vta/memory/put/0.1`.
pub(super) async fn handle_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::MemoryWrite, "put") {
        return r;
    }
    let req: MemoryPutBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Context-access gate (per-domain isolation). Same `require_context` ACL
    // check the context-scoped key tasks use.
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    if let Err(e) = memory::put(&state.memory_ks, &req.context_id, &req.key, &req.value).await {
        return app_error_to_reject(&doc, e);
    }
    audit_memory(state, "memory.put", auth, &req.key, &req.context_id).await;
    success_response(&doc, MemoryPutResponse { key: req.key })
}

/// Handler for `spec/vta/memory/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::MemoryRead, "list") {
        return r;
    }
    let req: MemoryListBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    let items = match memory::list(&state.memory_ks, &req.context_id).await {
        Ok(items) => items,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    audit_memory(state, "memory.list", auth, &req.context_id, &req.context_id).await;
    success_response(&doc, MemoryListResponse { items })
}

/// Handler for `spec/vta/memory/delete/0.1`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::MemoryWrite, "delete") {
        return r;
    }
    let req: MemoryDeleteBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_context(&req.context_id) {
        return app_error_to_reject(&doc, e);
    }
    if let Err(e) = memory::delete(&state.memory_ks, &req.context_id, &req.key).await {
        return app_error_to_reject(&doc, e);
    }
    audit_memory(state, "memory.delete", auth, &req.key, &req.context_id).await;
    success_response(&doc, MemoryDeleteResponse { key: req.key })
}

/// Record a `memory.*` audit row (best-effort; a failed write never fails the
/// op). `resource` is the entry key (put/delete) or the context id (list).
async fn audit_memory(
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
        let auth = admin_of("acme");
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

    #[tokio::test]
    async fn put_same_key_twice_upserts() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = admin_of("acme");
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
        let auth = admin_of("acme");
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
            &admin_of("ctx-a"),
            put_doc("ctx-a", "secret", "a-only"),
        )
        .await;
        handle_put(
            &state,
            &admin_of("ctx-b"),
            put_doc("ctx-b", "secret", "b-only"),
        )
        .await;

        let a = handle_list(&state, &admin_of("ctx-a"), list_doc("ctx-a")).await;
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
        let auth = claims_for(Role::Reader, "ctx-a");

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
        let auth = claims_for(Role::Application, "ctx-a");

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
}
