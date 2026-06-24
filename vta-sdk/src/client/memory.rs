//! Agent-memory Trust Task client methods
//! (`spec/vta/memory/{put,list,delete}/0.1`).
//!
//! Drives the memory slice through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there is no dedicated REST route. All
//! three operations are gated server-side on **context access**: the caller
//! must be permitted to act in `context_id`.

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for agent-memory trust tasks.
const MEMORY_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `vta/memory/put/0.1` — upsert `value` under `(context_id, key)`. Requires
    /// access to `context_id`.
    pub async fn memory_put(
        &self,
        context_id: &str,
        key: &str,
        value: &str,
    ) -> Result<Value, VtaError> {
        let payload = json!({
            "contextId": context_id,
            "key": key,
            "value": value,
        });
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_PUT_0_1,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/memory/list/0.1` — list every entry in `context_id`. Requires access
    /// to `context_id`.
    pub async fn memory_list(&self, context_id: &str) -> Result<Value, VtaError> {
        let payload = json!({ "contextId": context_id });
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_LIST_0_1,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/memory/delete/0.1` — remove the entry at `key` in `context_id`
    /// (`not_found` if absent). Requires access to `context_id`.
    pub async fn memory_delete(&self, context_id: &str, key: &str) -> Result<Value, VtaError> {
        let payload = json!({
            "contextId": context_id,
            "key": key,
        });
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_DELETE_0_1,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }
}
