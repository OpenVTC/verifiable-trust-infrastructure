//! Audit log methods on [`VtaClient`].

use super::VtaClient;
use crate::error::VtaError;

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
        )
        .await
    }
}
