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
    #[deprecated(
        note = "sends the superseded vta/memory 0.1, which the registry withdraws; use `memory_put_versioned` (0.2, #2115)"
    )]
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
    #[deprecated(
        note = "sends the superseded vta/memory 0.1, which the registry withdraws; use `memory_list_page` (0.2, #2115)"
    )]
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
    #[deprecated(
        note = "sends the superseded vta/memory 0.1, which the registry withdraws; use `memory_delete_versioned` (0.2, #2115)"
    )]
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

    /// `vta/memory/put/0.2` — store `value` at `(context_id, key)` and return
    /// the version it took.
    ///
    /// `expected_version` is the precondition: `Some(n)` requires the item to
    /// be at exactly version `n`, `Some(0)` that no live item exists, `None` an
    /// unconditional upsert. A failed precondition is
    /// `vta/memory/put:versionConflict`, whose details carry the current
    /// version and (to a caller that may read the context) the current value,
    /// so the caller can merge and re-issue without a re-read.
    pub async fn memory_put_versioned(
        &self,
        context_id: &str,
        key: &str,
        value: &str,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "contextId": context_id, "key": key, "value": value });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = json!(v);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_PUT_0_2,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/memory/delete/0.2` — forget `(context_id, key)`, leaving a
    /// tombstone the change feed carries. Deleting nothing succeeds with
    /// `existed: false`; a positive `expected_version` makes the delete
    /// conditional.
    pub async fn memory_delete_versioned(
        &self,
        context_id: &str,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "contextId": context_id, "key": key });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = json!(v);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_DELETE_0_2,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/memory/list/0.2` — one page of `context_id`'s memory. `query` is
    /// the rest of the payload as the specification names it (`prefix`,
    /// `sinceVersion`, `includeValues`, `includeDeleted`, `cursor`, `limit`);
    /// `contextId` is set from `context_id`. Store the response's
    /// `highWatermark` as the next `sinceVersion` only after the last page
    /// (no `nextCursor`).
    pub async fn memory_list_page(
        &self,
        context_id: &str,
        query: serde_json::Map<String, Value>,
    ) -> Result<Value, VtaError> {
        let mut payload = Value::Object(query);
        payload["contextId"] = json!(context_id);
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_LIST_0_2,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/memory/get/0.1` — recall up to 256 named items; each key comes back
    /// in exactly one of `items`, `missing` or `deferred`.
    pub async fn memory_get(&self, context_id: &str, keys: &[&str]) -> Result<Value, VtaError> {
        let payload = json!({ "contextId": context_id, "keys": keys });
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_MEMORY_GET_0_1,
            payload,
            MEMORY_TT_TIMEOUT,
        )
        .await
    }
}
