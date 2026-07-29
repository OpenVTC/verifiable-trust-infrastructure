//! Audit log methods on [`VtaClient`].

use super::VtaClient;
use crate::error::VtaError;

/// Percent-encode a query-parameter value.
///
/// Not optional for these params: an RFC 3339 timestamp ends in a `+`
/// offset (`…+00:00`), which a query-string decoder reads as a space —
/// so an unencoded `from`/`to` arrives as an unparseable datetime.
fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

impl VtaClient {
    /// List audit logs with optional filtering and pagination.
    pub async fn list_audit_logs(
        &self,
        params: &crate::protocols::audit_management::list::ListAuditLogsBody,
    ) -> Result<crate::protocols::audit_management::list::ListAuditLogsResultBody, VtaError> {
        // `ListAuditLogsBody` serializes to the canonical `audit/list/0.1`
        // payload (omitted filters are absent, not null) — conformance is
        // asserted server-side in `trust_tasks::audit::tests`.
        self.rpc_tt(
            crate::trust_tasks::TASK_AUDIT_LIST_0_1,
            serde_json::to_value(params)?,
            30,
            |c, url| {
                // Query-param names are the canonical camelCase ones the
                // route binds; a snake_case key here is silently dropped
                // by serde and the filter never applies.
                let mut qs: Vec<String> = Vec::new();
                if let Some(page_size) = params.page_size {
                    qs.push(format!("pageSize={page_size}"));
                }
                if let Some(from) = params.from {
                    qs.push(format!("from={}", enc(&from.to_rfc3339())));
                }
                if let Some(to) = params.to {
                    qs.push(format!("to={}", enc(&to.to_rfc3339())));
                }
                if let Some(ref action) = params.action {
                    qs.push(format!("action={}", enc(action)));
                }
                if let Some(ref actor) = params.actor {
                    qs.push(format!("actor={}", enc(actor)));
                }
                if let Some(ref outcome) = params.outcome {
                    qs.push(format!("outcome={}", enc(outcome)));
                }
                if let Some(ref ctx) = params.context_id {
                    qs.push(format!("contextId={}", enc(ctx)));
                }
                if let Some(ref cursor) = params.cursor {
                    qs.push(format!("cursor={}", enc(cursor)));
                }
                c.get(format!("{url}/audit/logs?{}", qs.join("&")))
            },
        )
        .await
    }

    /// Get the current audit log retention period.
    pub async fn get_audit_retention(
        &self,
    ) -> Result<crate::protocols::audit_management::retention::RetentionResultBody, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0,
            serde_json::json!({}),
            30,
            |c, url| c.get(format!("{url}/audit/retention")),
        )
        .await
    }

    /// Update the audit log retention period (super-admin only).
    pub async fn update_audit_retention(
        &self,
        retention_days: u32,
    ) -> Result<crate::protocols::audit_management::retention::RetentionResultBody, VtaError> {
        use crate::protocols::audit_management;
        let body = audit_management::retention::UpdateRetentionBody { retention_days };
        self.rpc_tt(
            crate::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0,
            serde_json::to_value(&body)?,
            30,
            |c, url| c.patch(format!("{url}/audit/retention")).json(&body),
        )
        .await
    }
}
