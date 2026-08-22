//! Application-state Trust Task client methods
//! (`spec/vta/app-state/{get,put,list,delete,get-many,put-many}/1.0`).
//!
//! Drives the slice through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there is no dedicated REST route. All
//! six operations are gated server-side on **context access**: the caller must
//! be permitted to act in `context_id`.
//!
//! Bodies are built from the typed [`protocols::app_state`] structs rather than
//! hand-rolled `json!` literals, so a schema change surfaces here as a compile
//! error rather than as a payload the VTA rejects at run time.

use serde_json::Value;

use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::app_state::{
    AppStateDeleteBody, AppStateGetBody, AppStateGetManyBody, AppStateListBody, AppStatePutBody,
    AppStatePutManyBody, AppStateWrite, PutManyMode,
};
use crate::trust_tasks;

/// Round-trip timeout (seconds) for application-state trust tasks. Matches the
/// memory slice; the batch operations are bounded by the VTA's own per-request
/// ceilings rather than by wall-clock, so they need no separate budget.
const APP_STATE_TT_TIMEOUT: u64 = 30;

/// Serialize a typed body, mapping the (unreachable in practice) failure into a
/// typed SDK error rather than panicking inside a client call.
fn body(value: impl serde::Serialize) -> Result<Value, VtaError> {
    serde_json::to_value(value)
        .map_err(|e| VtaError::Validation(format!("encode app-state payload: {e}")))
}

impl VtaClient {
    /// `vta/app-state/get/1.0` — read the record at
    /// `(context_id, namespace, key)`.
    ///
    /// `include_deleted` returns a tombstone as a record with `deleted: true`
    /// instead of reporting the address absent, which is what distinguishes
    /// "deleted, and here is the version that deleted it" from "never existed".
    pub async fn app_state_get(
        &self,
        context_id: &str,
        namespace: &str,
        key: &str,
        include_deleted: bool,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStateGetBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            key: key.to_string(),
            include_deleted: include_deleted.then_some(true),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_GET_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/put/1.0` — write `value` at
    /// `(context_id, namespace, key)`.
    ///
    /// `expected_version` is the optimistic-concurrency precondition: `Some(n)`
    /// requires the record to be at exactly version `n`, `Some(0)` requires
    /// that no live record exists ("create only" — what makes lease acquisition
    /// safe), and `None` is an unconditional upsert. A failed precondition
    /// comes back as `vta/app-state/put:versionConflict` carrying the VTA's
    /// current version *and* value, so a caller can merge and re-issue without
    /// a re-read — the re-read would race the next write.
    pub async fn app_state_put(
        &self,
        context_id: &str,
        namespace: &str,
        key: &str,
        value: Value,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStatePutBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            key: key.to_string(),
            value: Some(value),
            merge_patch: None,
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_PUT_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/put/1.0` with an RFC 7386 merge patch instead of a whole
    /// value.
    ///
    /// Cuts payload, and more usefully cuts *conflicts*: two instances patching
    /// different members of one record both succeed where two whole-value
    /// writes would have serialised behind `expected_version`. Requires a live
    /// record — a patch against an empty address is `notFound`.
    ///
    /// RFC 7386's sharp edge applies: a member set to `null` in `patch` is
    /// **removed**, and a patch cannot set a member to the JSON literal null.
    /// Send a whole value via [`Self::app_state_put`] when you need that.
    pub async fn app_state_patch(
        &self,
        context_id: &str,
        namespace: &str,
        key: &str,
        patch: Value,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStatePutBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            key: key.to_string(),
            value: None,
            merge_patch: Some(patch),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_PUT_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/list/1.0` — key-ordered snapshot of live records,
    /// optionally narrowed to a namespace and a key prefix.
    ///
    /// For incremental sync use [`Self::app_state_changes_since`] instead; this
    /// call deliberately cannot express a watermark, because a snapshot and a
    /// change feed differ in ordering, in tombstone handling, and in what the
    /// caller must persist afterwards.
    pub async fn app_state_list(
        &self,
        context_id: &str,
        namespace: Option<&str>,
        prefix: Option<&str>,
        include_values: bool,
        page_size: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStateListBody {
            context_id: context_id.to_string(),
            namespace: namespace.map(str::to_string),
            prefix: prefix.map(str::to_string),
            since_version: None,
            include_values: include_values.then_some(true),
            include_deleted: None,
            page_size,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_LIST_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/list/1.0` in change-feed mode — every record in
    /// `namespace` whose version exceeds `since_version`, **tombstones
    /// included**, in ascending version order.
    ///
    /// Pass `0` for a first full pull in change-feed form. Persist the
    /// response's `highWatermark` as the next `since_version` — **not** the
    /// maximum version among the returned records, which is wrong whenever a
    /// `prefix` filtered a later change out of the page and undefined when the
    /// page is empty. Do not advance the stored watermark until the final page
    /// has been drained.
    ///
    /// `vta/app-state/list:watermarkTooOld` means the watermark predates the
    /// oldest retained tombstone, so resuming would silently omit deletions:
    /// rebuild from [`Self::app_state_list`] rather than retrying.
    pub async fn app_state_changes_since(
        &self,
        context_id: &str,
        namespace: &str,
        since_version: u64,
        prefix: Option<&str>,
        include_values: bool,
        page_size: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStateListBody {
            context_id: context_id.to_string(),
            namespace: Some(namespace.to_string()),
            prefix: prefix.map(str::to_string),
            since_version: Some(since_version),
            include_values: include_values.then_some(true),
            include_deleted: None,
            page_size,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_LIST_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/delete/1.0` — remove the record at
    /// `(context_id, namespace, key)`, leaving a versioned tombstone.
    ///
    /// Deleting an address that holds nothing **succeeds** with
    /// `existed: false`; that is what makes the task safe to retry. Supply
    /// `expected_version` to refuse a delete that would discard an edit made
    /// since the caller last read.
    pub async fn app_state_delete(
        &self,
        context_id: &str,
        namespace: &str,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStateDeleteBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            key: key.to_string(),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_DELETE_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/get-many/1.0` — read up to 256 records from one namespace
    /// in a single round trip.
    ///
    /// Every requested key comes back in exactly one of `records`, `missing` or
    /// `deferred`, so a caller never diffs its request against the response.
    /// `deferred` names keys the VTA did not evaluate because the response
    /// reached its size budget — re-request exactly those.
    pub async fn app_state_get_many(
        &self,
        context_id: &str,
        namespace: &str,
        keys: &[String],
        include_deleted: bool,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStateGetManyBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            keys: keys.to_vec(),
            include_deleted: include_deleted.then_some(true),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_GET_MANY_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/app-state/put-many/1.0` — up to 64 writes to one namespace in a
    /// single round trip, each carrying its own precondition.
    ///
    /// [`PutManyMode::Independent`] (the default) applies each write on its own
    /// merits and returns per-record outcomes; a batch in which some writes
    /// conflicted is still a success, because the task did what it promised.
    /// [`PutManyMode::Atomic`] applies all or none and, when it does not apply,
    /// returns `vta/app-state/put-many:atomicBatchRejected` whose details carry
    /// the same per-record outcomes — including `skipped` for the writes that
    /// were never attempted.
    ///
    /// Reach for `Atomic` only when the records carry a joint invariant.
    /// Choosing it out of caution converts every independent conflict into a
    /// total failure.
    pub async fn app_state_put_many(
        &self,
        context_id: &str,
        namespace: &str,
        writes: Vec<AppStateWrite>,
        mode: PutManyMode,
    ) -> Result<Value, VtaError> {
        let payload = body(AppStatePutManyBody {
            context_id: context_id.to_string(),
            namespace: namespace.to_string(),
            mode: Some(mode),
            writes,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_APP_STATE_PUT_MANY_1_0,
            payload,
            APP_STATE_TT_TIMEOUT,
        )
        .await
    }
}
