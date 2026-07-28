//! Audit slice trust-task handlers.
//!
//! Auth (all enforced inside the operation functions, so every
//! transport gets the same gate): Admin for get-retention; Super-Admin
//! for update-retention; and for `audit/list`, an unrestricted admin
//! for the whole-log tail with a context-scoped admin confined to a
//! `contextId` inside their own scope.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::audit_management::list::ListAuditLogsBody;
use vta_sdk::protocols::audit_management::retention::{GetRetentionBody, UpdateRetentionBody};

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for canonical `audit/list/0.1`.
///
/// Auth: unrestricted admin for the whole-log tail; a context-scoped
/// admin must supply `contextId` within their own scope. The finer gate
/// lives in the operation, so every transport gets it.
pub(super) async fn handle_list_logs(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListAuditLogsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::list_audit_logs(&state.audit_ks, auth, &req, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/get-retention/1.0`. Admin only.
pub(super) async fn handle_get_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: GetRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::get_retention(&state.config, auth, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/update-retention/1.0`. Super-admin only.
pub(super) async fn handle_update_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::update_retention(
        &state.config,
        &state.audit_ks,
        auth,
        req.retention_days,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::specs::audit::list::v0_1 as canonical;
    use vta_sdk::protocols::audit_management::list::{
        AuditEnvelope, AuditLogEntry, ListAuditLogsResultBody,
    };

    /// The whole point of the fold: our wire shapes must be the
    /// canonical ones, not merely bound to the canonical URI.
    ///
    /// The generated canonical types carry `deny_unknown_fields` and
    /// the spec's required-field set, so deserializing our serialized
    /// form into them is a conformance check — it catches a member we
    /// named differently, one the spec forbids, and one the spec
    /// requires that we omit. The dispatch spine validates *requests*
    /// against the schema at runtime; nothing validates responses, so
    /// this is the only place the response shape is checked at all.
    #[test]
    fn request_and_response_conform_to_the_canonical_schema() {
        let req = ListAuditLogsBody {
            from: Some("2026-07-01T00:00:00Z".parse().unwrap()),
            to: Some("2026-07-28T00:00:00Z".parse().unwrap()),
            action: Some("acl.create".into()),
            actor: Some("did:key:z6MkActor".into()),
            outcome: Some("success".into()),
            context_id: Some("ctx1".into()),
            page_size: Some(25),
            cursor: Some("opaque".into()),
        };
        let json = serde_json::to_value(&req).expect("serialize request");
        serde_json::from_value::<canonical::Payload>(json.clone())
            .unwrap_or_else(|e| panic!("request is not canonical `audit/list/0.1`: {e}\n{json:#}"));

        // An all-defaults request must also be valid — every filter is
        // optional, and omitted members must be absent rather than null.
        let empty = serde_json::to_value(ListAuditLogsBody::default()).expect("serialize");
        assert_eq!(
            empty,
            serde_json::json!({}),
            "omitted filters must not serialize"
        );
        serde_json::from_value::<canonical::Payload>(empty).expect("empty request is canonical");

        let row = AuditLogEntry {
            id: "e1".into(),
            timestamp: 1_785_239_374,
            action: "acl.create".into(),
            actor: "did:key:z6MkActor".into(),
            resource: Some("did:key:z6MkSubject".into()),
            outcome: "success".into(),
            channel: Some("rest".into()),
            context_id: Some("ctx1".into()),
            detail: Some("because".into()),
        };
        let resp = ListAuditLogsResultBody {
            entries: vec![AuditEnvelope::from(&row)],
            truncated: true,
            cursor: Some("opaque".into()),
        };
        let json = serde_json::to_value(&resp).expect("serialize response");
        serde_json::from_value::<canonical::Response>(json.clone()).unwrap_or_else(|e| {
            panic!("response is not canonical `audit/list/0.1`: {e}\n{json:#}")
        });

        // Guard against a vacuous check: the canonical types must
        // actually reject a shape the spec forbids, or the assertions
        // above would pass for anything.
        let mut drifted = json;
        drifted["totalPages"] = serde_json::json!(3);
        assert!(
            serde_json::from_value::<canonical::Response>(drifted).is_err(),
            "the canonical Response must reject members the spec does not define"
        );
    }
}
