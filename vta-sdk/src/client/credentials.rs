//! Issued-credential lifecycle Trust Task client methods
//! (`spec/vta/credentials/{issue,revoke}/0.1`).
//!
//! Drives the issue / revoke slice through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there is no dedicated REST route. Both
//! operations are gated server-side by operator step-up (AAL2) + an admin
//! capability check; a stepped-up session is required for either to succeed.

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for issued-credential trust tasks.
const CREDENTIALS_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `vta/credentials/issue/0.1` — issue a scoped, time-boxed Verifiable
    /// Credential to `holder`. `claims` is merged into `credentialSubject`;
    /// `credential_type`, when present, is appended after `VerifiableCredential`
    /// in the VC `type`. Requires Admin + a stepped-up (AAL2) session.
    pub async fn issue_credential(
        &self,
        holder: &str,
        claims: Value,
        credential_type: Option<&str>,
        validity_seconds: u64,
        purpose: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({
            "holder": holder,
            "claims": claims,
            "validitySeconds": validity_seconds,
        });
        if let Some(ct) = credential_type {
            payload["credentialType"] = Value::String(ct.to_string());
        }
        if let Some(p) = purpose {
            payload["purpose"] = Value::String(p.to_string());
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_0_1,
            payload,
            CREDENTIALS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/credentials/revoke/0.1` — revoke a previously-issued credential by
    /// id. `reason`, when present, is recorded in the audit trail + revocation
    /// tombstone. Requires Admin + a stepped-up (AAL2) session.
    pub async fn revoke_credential(
        &self,
        credential_id: &str,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "credentialId": credential_id });
        if let Some(r) = reason {
            payload["reason"] = Value::String(r.to_string());
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_CREDENTIALS_REVOKE_0_1,
            payload,
            CREDENTIALS_TT_TIMEOUT,
        )
        .await
    }
}
