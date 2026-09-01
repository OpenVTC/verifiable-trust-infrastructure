//! Wire payloads for the application-state Trust Tasks
//! (`spec/vta/app-state/{get,put,list,delete,get-many,put-many}/1.0`).
//!
//! A third store on the VTA, beside the secrets/credential vault
//! ([`crate::protocols::vault`]) and agent memory
//! ([`crate::protocols::memory`]): versioned, namespaced, per-context JSON that
//! an application owns and the VTA does not interpret.
//!
//! Records are addressed by `(contextId, namespace, key)`. Access is gated on
//! **context** — the same `require_context` ACL check the memory and
//! context-scoped key tasks use. A namespace is collision avoidance, not a
//! trust boundary: two applications with write access to one context can reach
//! each other's namespaces, and isolating them means separate contexts. The
//! address is shaped for a future per-namespace grant, which is why `namespace`
//! is a field rather than a convention on `key`.
//!
//! ## The version counter
//!
//! [`AppStateRecord::version`] is a monotonic counter maintained **per
//! `(contextId, namespace)`**, not per record. Every write in a namespace takes
//! the counter's next value, and a record's `version` is the value its most
//! recent write took.
//!
//! One number therefore serves two jobs that would otherwise need two: it is
//! the optimistic-concurrency token [`AppStatePutBody::expected_version`] is
//! compared against, and the watermark [`AppStateListBody::since_version`] is
//! compared against. A per-record counter could do the first but not the
//! second — two records' per-record counters are not comparable to each other,
//! so no single number could mean "everything changed after this point".
//!
//! The cost is that a record's version jumps between writes, by however many
//! values its neighbours consumed. Consumers must treat versions as opaque and
//! monotonic, never as an edit count.
//!
//! ## Not a secret store
//!
//! Values are stored as supplied and returned as stored — no sealing, no
//! release policy, no audit of the value itself. Secret material belongs in
//! `vault/*`. This boundary is stated in the published specification rather
//! than merely implied by the vault next door, because a boundary that is not
//! written down erodes.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Deserialize a present member into `Some`, including a present `null`.
///
/// serde's built-in `Option<T>` handling collapses a present `null` to `None`,
/// which would make "the application stored JSON null" indistinguishable from
/// "the VTA did not send a value". Paired with `#[serde(default)]` — which
/// covers the absent case — this keeps the two apart.
fn present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// A record as the VTA holds it.
///
/// `value` is absent in three distinct situations and a consumer must not
/// conflate them: the record is a tombstone (`deleted`); the caller asked for a
/// metadata-only view (`list` without `include_values`); or the stored value
/// genuinely is JSON `null`, in which case `value` is `Some(Value::Null)`.
/// That is why [`deleted`](Self::deleted) is a plain `bool` rather than
/// something a caller infers — a consumer that has to derive deletion from an
/// absent value gets the tombstone case wrong exactly when convergence depends
/// on it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppStateRecord {
    /// The context the record is scoped to; the isolation boundary.
    pub context_id: String,
    /// The application partition within the context.
    pub namespace: String,
    /// The application-chosen key. Opaque to the VTA.
    pub key: String,
    /// The namespace counter value this record's most recent write took.
    pub version: u64,
    /// True when this is a tombstone: the record was deleted, and this entry
    /// exists so an incremental consumer learns of the deletion.
    pub deleted: bool,
    /// The stored JSON, in whatever shape the owning application chose.
    /// Absent on a tombstone and in metadata-only views.
    ///
    /// `deserialize_with` is load-bearing rather than decorative: serde's
    /// default for `Option<Value>` maps a **present** `null` onto `None`, so an
    /// application that stores the JSON literal null would read it back
    /// indistinguishable from a metadata view or a tombstone. Because
    /// `deserialize_with` runs only when the member is present, and `default`
    /// supplies `None` when it is absent, this pair preserves exactly the
    /// three-way distinction this type's docs promise.
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<Value>,
    /// Size of the stored value in bytes as measured against the per-record
    /// cap. Present in metadata views so a consumer can decide what to fetch
    /// without fetching it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_bytes: Option<u64>,
    /// When the record was first created at this address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When the write that produced this `version` was applied.
    pub updated_at: String,
    /// When the record was deleted. Present only when `deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// `spec/vta/app-state/get/1.0` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStateGetBody {
    /// The context the record is scoped to. The caller must have ACL access.
    pub context_id: String,
    /// The application partition within the context.
    pub namespace: String,
    /// The record key.
    pub key: String,
    /// When true, a tombstone is returned as a record with `deleted: true`
    /// rather than reported absent. Lets a repair path distinguish "deleted,
    /// and here is the version that deleted it" from "never existed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_deleted: Option<bool>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/get/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateGetResponse {
    /// The record at the requested address.
    pub record: AppStateRecord,
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

/// `spec/vta/app-state/put/1.0` request body.
///
/// Exactly one of [`value`](Self::value) or [`merge_patch`](Self::merge_patch)
/// is supplied; the handler rejects both-or-neither rather than picking one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStatePutBody {
    /// The context the record is scoped to. The caller must have ACL access.
    pub context_id: String,
    /// The application partition within the context.
    pub namespace: String,
    /// The record key.
    pub key: String,
    /// The complete new value, replacing whatever the record held. Any JSON,
    /// including `null` — `Some(Value::Null)` stores the JSON literal null and
    /// is not the same as `None`. See [`AppStateRecord::value`] for why the
    /// custom deserializer is required to keep those apart.
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<Value>,
    /// An RFC 7386 JSON Merge Patch applied to the record's current value.
    /// Requires a live record. Note RFC 7386's sharp edge: a member set to
    /// `null` in the patch *removes* that member, and a patch cannot set a
    /// member to the JSON literal null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_patch: Option<Value>,
    /// Optional precondition. A positive value requires the record to be at
    /// exactly that version; `0` requires that no live record exists
    /// ("create only" — what makes lease acquisition safe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/put/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatePutResponse {
    /// Echoed from the request.
    pub context_id: String,
    /// Echoed from the request.
    pub namespace: String,
    /// Echoed from the request.
    pub key: String,
    /// The version this write took. Supply it as `expectedVersion` on the next
    /// write to chain conditional updates without an intervening read.
    pub version: u64,
    /// True when no live record existed beforehand — including when the
    /// address held a tombstone, which is not a live record.
    pub created: bool,
    /// When the write was applied.
    pub updated_at: String,
    /// Size of the stored value as measured against the per-record cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `spec/vta/app-state/list/1.0` request body.
///
/// Two modes, selected by whether [`since_version`](Self::since_version) is
/// supplied. Without it this is a key-ordered **snapshot** of live records.
/// With it this is a version-ordered **change feed** that always includes
/// tombstones — a feed that omitted deletions could not converge, so asking for
/// one (`include_deleted: Some(false)` alongside `since_version`) is refused as
/// a contradiction rather than honoured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStateListBody {
    /// The context to enumerate. The caller must have ACL access.
    pub context_id: String,
    /// Restrict to one namespace. Optional in snapshot mode; **required** in
    /// change-feed mode, because the counter `since_version` compares against
    /// is per `(contextId, namespace)` and a watermark spanning namespaces
    /// would name no single point in time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Restrict to keys beginning with this byte prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Watermark. Selects change-feed mode: only records whose version is
    /// strictly greater are returned, tombstones included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_version: Option<u64>,
    /// When true, each record carries its `value`. Defaults to false, which
    /// returns the metadata view so a prefix scan stays cheap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_values: Option<bool>,
    /// Snapshot mode only: include tombstones still inside the retention
    /// window. Ignored — and refused when explicitly false — in change-feed
    /// mode, where tombstones are always returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_deleted: Option<bool>,
    /// Caller's upper bound on records per page. The VTA applies its own
    /// ceiling and may return fewer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// Opaque continuation token from a previous response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/list/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateListResponse {
    /// Matching records — ascending key order in snapshot mode, ascending
    /// version order in change-feed mode so that applying them in order
    /// reaches the state the VTA holds.
    pub records: Vec<AppStateRecord>,
    /// True when more matching records exist beyond this page.
    pub truncated: bool,
    /// Opaque continuation token, present only when `truncated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// The namespace's current counter value, present whenever `namespace` was
    /// supplied.
    ///
    /// This — **not** the maximum version among `records` — is what an
    /// incremental consumer stores as its next `since_version`. The maximum is
    /// wrong whenever a `prefix` filtered a later change out of the page, and
    /// undefined when the page is empty. A paginating consumer must not adopt
    /// it until it has drained the final page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_watermark: Option<u64>,
    /// How long this VTA retains tombstones before reaping them, so a consumer
    /// can schedule syncs to stay inside the window rather than discovering it
    /// has fallen out of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_retention_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

/// `spec/vta/app-state/delete/1.0` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStateDeleteBody {
    /// The context the record is scoped to. The caller must have ACL access.
    pub context_id: String,
    /// The application partition within the context.
    pub namespace: String,
    /// The record key.
    pub key: String,
    /// Optional precondition. A positive value requires the live record to be
    /// at exactly that version, so a delete cannot discard an edit the caller
    /// never saw. `0` is meaningless on a delete and is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/delete/1.0` response body.
///
/// Deleting an address that holds nothing is a **success**, not an error —
/// which is what makes the task converge under replay, since a second delete
/// finds a tombstone and changes nothing further.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateDeleteResponse {
    /// Echoed from the request.
    pub context_id: String,
    /// Echoed from the request.
    pub namespace: String,
    /// Echoed from the request.
    pub key: String,
    /// True when a live record was removed by this request. False when the
    /// address already held a tombstone, or held nothing at all.
    pub existed: bool,
    /// The tombstone's version — the value this delete took, or the value the
    /// existing tombstone already held. Absent only when the address held
    /// nothing and no tombstone was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// When the deletion was recorded. Absent on the same terms as `version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

// ---------------------------------------------------------------------------
// get-many
// ---------------------------------------------------------------------------

/// `spec/vta/app-state/get-many/1.0` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStateGetManyBody {
    /// The context the records are scoped to. The caller must have ACL access.
    pub context_id: String,
    /// The application partition. Required — a key is only unique within one.
    pub namespace: String,
    /// The keys to read (1–256, distinct). Duplicates are refused rather than
    /// deduplicated, because a caller that sent one did not mean to.
    pub keys: Vec<String>,
    /// When true, a tombstone yields a record with `deleted: true` rather than
    /// appearing in `missing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_deleted: Option<bool>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/get-many/1.0` response body.
///
/// Every requested key appears in exactly one of `records`, `missing` or
/// `deferred`, so a caller never has to diff its request against the response
/// to discover what happened to a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateGetManyResponse {
    /// The records found, each with its value, in requested-key order.
    pub records: Vec<AppStateRecord>,
    /// Requested keys holding no record — and, unless `include_deleted` was
    /// set, keys holding only a tombstone.
    pub missing: Vec<String>,
    /// Requested keys not evaluated because the response reached its size
    /// budget. The caller re-requests exactly these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// put-many
// ---------------------------------------------------------------------------

/// How a [`AppStatePutManyBody`] batch treats a single failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum PutManyMode {
    /// Each write applies on its own merits, so one conflicted record does not
    /// block the other nine. The default, and what a flush of unrelated edits
    /// wants — an atomic default would let one stale record silently wedge an
    /// entire flush, and the caller could not tell a wedged flush from a slow
    /// one.
    #[default]
    Independent,
    /// All or none, for records carrying a joint invariant.
    Atomic,
}

/// One write within a [`AppStatePutManyBody`]. Shaped like an
/// [`AppStatePutBody`] minus the context and namespace, which the batch
/// supplies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStateWrite {
    /// The record key.
    pub key: String,
    /// The complete new value. Mutually exclusive with `merge_patch`.
    /// A present `null` stores the JSON literal null — see
    /// [`AppStateRecord::value`].
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<Value>,
    /// An RFC 7386 merge patch. Mutually exclusive with `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_patch: Option<Value>,
    /// This write's own precondition, evaluated independently of every other
    /// write in the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/app-state/put-many/1.0` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStatePutManyBody {
    /// The context the records are scoped to. The caller must have ACL access.
    pub context_id: String,
    /// The application partition. One namespace per batch — atomicity is only
    /// meaningful within the counter the writes take their versions from.
    pub namespace: String,
    /// What a single failure costs. Defaults to
    /// [`PutManyMode::Independent`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PutManyMode>,
    /// The writes to apply (1–64, distinct keys).
    pub writes: Vec<AppStateWrite>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// What happened to one write in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WriteOutcome {
    /// Applied; `version` carries the new value.
    Written,
    /// `expected_version` did not match; the `current_*` fields carry the
    /// VTA's view so the caller can resolve without a re-read.
    Conflict,
    /// The value exceeded the per-record cap.
    TooLarge,
    /// A `merge_patch` write named an address with no live record.
    NotFound,
    /// Atomic mode only: not attempted because another write in the batch
    /// failed.
    Skipped,
}

/// The outcome of one write within a batch. Per-record rather than per-batch,
/// because the default mode applies each write on its own merits: a caller
/// flushing ten unrelated edits needs to know which one conflicted, not merely
/// that something did.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResult {
    /// The key this result is for.
    pub key: String,
    /// What happened.
    pub outcome: WriteOutcome,
    /// The new version, on [`WriteOutcome::Written`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// On `Written`: true when no live record existed beforehand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    /// On `Conflict`: the version the VTA actually holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    /// On `Conflict`: the value the VTA actually holds, returned *with* the
    /// rejection. A bare rejection has no fixed point under contention —
    /// between the rejection and a re-read the record can change again — so
    /// returning the winner's view removes the race rather than narrowing it.
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_value: Option<Value>,
    /// On `Conflict`: true when the address holds a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_deleted: Option<bool>,
    /// On `TooLarge`: the per-record cap in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
    /// On `TooLarge`: the size of the rejected value in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_bytes: Option<u64>,
}

/// `spec/vta/app-state/put-many/1.0` response body (independent mode).
///
/// A batch in which some writes conflicted is a **success**: the task did what
/// it promised — applied each write on its own merits — and the per-record
/// outcomes are the answer rather than the failure. An `atomic` batch that does
/// not apply is a `trust-task-error` carrying
/// `vta/app-state/put-many:atomicBatchRejected` instead, whose details carry
/// the same per-record outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatePutManyResponse {
    /// The mode applied, echoed so a caller relying on the default sees what
    /// it got.
    pub mode: PutManyMode,
    /// One result per requested write, in request order.
    pub results: Vec<WriteResult>,
    /// The namespace's counter value after the batch, so a writer that is also
    /// a sync consumer can adopt it without a separate list call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_watermark: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The three-way distinction [`AppStateRecord::value`] promises must
    /// survive a wire round trip. serde's default `Option<Value>` handling does
    /// not give it — a present `null` comes back as `None` — so this pins the
    /// custom deserializer that does.
    #[test]
    fn a_stored_json_null_is_not_an_absent_value() {
        let with_null = json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k",
            "version": 1, "deleted": false, "value": null,
            "updatedAt": "2026-08-22T00:00:00Z"
        });
        let rec: AppStateRecord = serde_json::from_value(with_null).expect("parse");
        assert_eq!(
            rec.value,
            Some(Value::Null),
            "a present null is a stored value, not an absent one"
        );

        let without = json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k",
            "version": 1, "deleted": false,
            "updatedAt": "2026-08-22T00:00:00Z"
        });
        let rec: AppStateRecord = serde_json::from_value(without).expect("parse");
        assert_eq!(rec.value, None, "an absent member stays absent");
    }

    /// A `put` whose value genuinely is JSON null must not read as "neither
    /// value nor mergePatch supplied", which the handler refuses.
    #[test]
    fn put_with_a_null_value_still_counts_as_supplying_a_value() {
        let body: AppStatePutBody = serde_json::from_value(json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k", "value": null
        }))
        .expect("parse");
        assert_eq!(body.value, Some(Value::Null));
        assert!(body.merge_patch.is_none());
    }

    /// A tombstone carries no value, and `deleted` is what says so.
    #[test]
    fn a_tombstone_is_distinguished_by_deleted_not_by_an_absent_value() {
        let tomb: AppStateRecord = serde_json::from_value(json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k",
            "version": 9, "deleted": true,
            "updatedAt": "2026-08-22T00:00:00Z",
            "deletedAt": "2026-08-22T00:00:00Z"
        }))
        .expect("parse");
        assert!(tomb.deleted);
        assert!(tomb.value.is_none());
    }

    /// `mode` defaults to `independent`, and that default is the specification's
    /// central claim rather than a convenience — an atomic default would let one
    /// stale record silently wedge an entire flush.
    #[test]
    fn put_many_mode_defaults_to_independent() {
        assert_eq!(PutManyMode::default(), PutManyMode::Independent);
        let body: AppStatePutManyBody = serde_json::from_value(json!({
            "contextId": "ctx", "namespace": "openvtc",
            "writes": [{ "key": "k", "value": 1 }]
        }))
        .expect("parse");
        assert!(
            body.mode.is_none(),
            "an omitted mode stays absent on the wire rather than being materialised"
        );
        assert_eq!(body.mode.unwrap_or_default(), PutManyMode::Independent);
    }

    /// A conforming producer may send `ext` (SPEC §4.5.1), and the published
    /// payload schemas declare the slot — so `deny_unknown_fields` must not
    /// reject it. It must still reject a typo, which is what that clause is for.
    #[test]
    fn ext_is_accepted_but_a_typo_is_not() {
        let with_ext: AppStateGetBody = serde_json::from_value(json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k",
            "ext": { "org.example.tracing": { "traceId": "abc" } }
        }))
        .expect("a conforming producer's ext must be accepted");
        assert!(with_ext.ext.is_some());

        let typo = serde_json::from_value::<AppStateGetBody>(json!({
            "contextId": "ctx", "namespace": "openvtc", "key": "k",
            "includeDelted": true
        }));
        assert!(
            typo.is_err(),
            "a misspelled member must still be refused rather than silently ignored"
        );
    }

    /// Specification-defined enum values are lowerCamelCase (SPEC §4.10).
    #[test]
    fn wire_enums_are_lower_camel_case() {
        assert_eq!(
            serde_json::to_value(PutManyMode::Atomic).unwrap(),
            json!("atomic")
        );
        assert_eq!(
            serde_json::to_value(WriteOutcome::TooLarge).unwrap(),
            json!("tooLarge")
        );
        assert_eq!(
            serde_json::to_value(WriteOutcome::NotFound).unwrap(),
            json!("notFound")
        );
    }
}
