//! Idempotency for keyed Trust Tasks.
//!
//! The mechanism is [`vti_common::idempotency`] — the same store the VTC's
//! `Idempotency-Key` middleware uses. This module is only the *policy*: which
//! tasks get a record, where the key comes from, and how each claim outcome is
//! phrased as a Trust-Task rejection.
//!
//! # What this adds over [`super::replay`]
//!
//! That layer asks "have I seen this exact envelope before" and refuses it if
//! so — at-most-once, in memory, keyed on `(actor, envelope-id)`. It is right
//! for a cross-transport fallback re-sending byte-identical bytes, and it
//! cannot help with the case that actually hurts.
//!
//! A request times out. Usually it never arrived, so retrying is correct.
//! Sometimes the VTA processed it and only the reply was lost — and then the
//! retry produces a *second durable effect*. `webvh/dids/create` is the sharp
//! example: production callers use `WebvhPathMode::AutoAssign`, so the retry is
//! assigned a different path and the first DID stays published in the log with
//! nobody holding a reference to it.
//!
//! `replay` cannot catch that, because the retry is not the same envelope —
//! every SDK path mints a fresh `urn:uuid:` per attempt. What it needs is a key
//! stable *across* attempts of one logical operation, which is what
//! `idempotencyKey` is. The two layers are complementary and both stay.
//!
//! # Where the key lives, and why it is trustworthy
//!
//! A top-level `idempotencyKey` member on the Trust Task document. It lands in
//! `TrustTask::extra` (which is `#[serde(flatten)]`), so the upstream document
//! type needs no change — and because a Data-Integrity proof covers every
//! member but `proof`, **the key is signed**. A relayer cannot alter it to
//! split one operation into two or merge two into one.
//!
//! # Backwards compatibility
//!
//! A request with no `idempotencyKey` takes none of these paths and is
//! dispatched exactly as it is today. Nothing that works now can begin failing
//! because this module exists.

use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::retry_safety::{RetrySafety, retry_safety};
use vti_common::idempotency::{
    CacheEntry, ClaimOutcome, CompletedResponse, IdempotencyStore, Principal,
};

use super::helpers::{TrustTaskOutcome, reject_with};

/// The document member carrying the key.
pub(crate) const IDEMPOTENCY_KEY_MEMBER: &str = "idempotencyKey";

/// How long an in-flight claim is honoured before a retry may reclaim it.
///
/// Only reached when a process died between claiming and completing — a live
/// request is bounded by its own handler timeout, and the longest of those is
/// 60s. Too short and a slow-but-live operation gets double-dispatched, which
/// is the failure this module exists to prevent; too long and a genuine crash
/// blocks the retry that would have recovered from it.
const IN_FLIGHT_GRACE_MINS: i64 = 10;

/// Largest response body kept for replay, in bytes.
///
/// A cap, not a promise: the record's job is to stop the second durable effect,
/// and it does that whether or not the body fits. Without a cap, one large
/// listing response would let a caller size a dedup record with whatever it
/// asked for. Over the cap, the record degrades to the same answer a
/// secret-bearing task gets — it happened, the result is not retained.
const MAX_CACHED_BODY: usize = 64 * 1024;

/// Suggested wait before retrying a request whose first attempt is running.
const IN_FLIGHT_RETRY_AFTER_SECS: i64 = 2;

/// The class every keyed Trust Task is recorded under.
///
/// Always `NonDestructive`, including for tasks that destroy something. The
/// `Destructive` class exists for HTTP routes whose idempotency key *is* the
/// target's UUID, where a long TTL would silently no-op a later intentional
/// re-create under that same UUID. A Trust-Task key is per-attempt-group and
/// carries no resource identity, so re-creating the same resource later means a
/// new key and that hazard cannot arise. The 24h window is what serves the case
/// this exists for: an operator re-running a failed provisioning step.
const CLASS: vti_common::idempotency::IdempotencyClass =
    vti_common::idempotency::IdempotencyClass::NonDestructive;

/// The `idempotencyKey` a document carries, if any and if usable.
///
/// A malformed key reads as absent rather than as an error: the request is then
/// dispatched exactly as an unkeyed one, which is what it would have done
/// before this module existed. Rejecting it instead would break callers to
/// enforce a convenience.
pub(crate) fn key_of(doc: &TrustTask<serde_json::Value>) -> Option<String> {
    let raw = doc.extra.get(IDEMPOTENCY_KEY_MEMBER)?.as_str()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 255 {
        tracing::debug!(
            len = trimmed.len(),
            "ignoring unusable idempotencyKey (empty, or over 255 chars)"
        );
        return None;
    }
    Some(trimmed.to_string())
}

/// SHA-256 over the request payload.
///
/// `serde_json::Value` maps are `BTreeMap`s in this workspace (`preserve_order`
/// is off), so serialisation is already key-ordered and two encodings of the
/// same logical payload hash alike.
fn payload_hash(doc: &TrustTask<serde_json::Value>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // Bound the hash to the task as well as the payload, so one key cannot be
    // reused across two different operations that happen to share a body.
    h.update(doc.type_uri.to_string().as_bytes());
    h.update([0u8]);
    h.update(serde_json::to_vec(&doc.payload).unwrap_or_default());
    h.finalize().into()
}

/// What the dispatcher should do with a keyed request.
pub(crate) enum Claim {
    /// This attempt owns the key. Run the handler, then call
    /// [`record_outcome`].
    Proceed { key: String, safety: RetrySafety },
    /// Answer with this instead of dispatching.
    Answer(Box<TrustTaskOutcome>),
    /// Not keyed, not a task worth keying, or the store is unavailable.
    /// Dispatch normally and record nothing.
    Skip,
}

/// Claim `(actor, key)` for this request, or report what already happened to it.
///
/// A store error never blocks the request. Idempotency is an improvement on the
/// status quo, not a precondition for it — failing closed here would turn a
/// storage blip into an outage of every keyed operation, in order to prevent a
/// duplicate that only matters when a reply is *also* lost.
pub(crate) async fn claim(
    ks: &vti_common::store::KeyspaceHandle,
    actor: &str,
    doc: &TrustTask<serde_json::Value>,
) -> Claim {
    let type_uri = doc.type_uri.to_string();

    // `None` is an unknown task — the dispatcher rejects it on the type URI in
    // a moment, so there is nothing to claim. Not-keyed tasks are skipped
    // because a repeat is harmless, so a record would cost a write and buy
    // nothing.
    let Some(safety) = retry_safety(&type_uri).filter(|s| s.needs_key()) else {
        return Claim::Skip;
    };
    let Some(key) = key_of(doc) else {
        return Claim::Skip;
    };

    let store = IdempotencyStore::new(ks.clone());
    let principal = Principal::Did(actor.to_string()).hash();
    let grace = chrono::Duration::minutes(IN_FLIGHT_GRACE_MINS);

    let outcome = match store
        .claim(&principal, &key, payload_hash(doc), CLASS, grace)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, actor, key, "idempotency claim failed; dispatching unguarded");
            return Claim::Skip;
        }
    };

    match outcome {
        ClaimOutcome::Claimed => {
            tracing::debug!(actor, key, %type_uri, "idempotency key claimed");
            Claim::Proceed { key, safety }
        }
        ClaimOutcome::InFlight => {
            // Nobody knows the outcome yet, so the honest answer is "ask
            // again", not "duplicate".
            let retry_after =
                chrono::Utc::now() + chrono::Duration::seconds(IN_FLIGHT_RETRY_AFTER_SECS);
            Claim::Answer(Box::new(reject_with(
                doc,
                RejectReason::Unavailable {
                    retry_after: Some(retry_after),
                },
            )))
        }
        ClaimOutcome::Conflict => Claim::Answer(Box::new(reject_with(
            doc,
            RejectReason::TaskFailed {
                reason: "idempotency key reused for a different request".to_string(),
                details: Some(serde_json::json!({
                    "idempotencyKey": key,
                    "task": type_uri,
                    "reason": "this key was already used for a different task or payload; \
                               answering it from the first request's result would answer the \
                               wrong question. Use a fresh key, or re-send the original \
                               request unchanged",
                })),
            },
        ))),
        ClaimOutcome::Completed(entry) => {
            Claim::Answer(Box::new(replay(doc, &entry, &key, &type_uri)))
        }
    }
}

/// Answer a retry from a completed record.
fn replay(
    doc: &TrustTask<serde_json::Value>,
    entry: &CacheEntry,
    key: &str,
    type_uri: &str,
) -> TrustTaskOutcome {
    if !entry.has_replayable_response() {
        return reject_with(
            doc,
            RejectReason::TaskFailed {
                reason: "already performed; the result is not replayable".to_string(),
                details: Some(serde_json::json!({
                    "idempotencyKey": key,
                    "task": type_uri,
                    "completedAt": entry.created_at.to_rfc3339(),
                    "reason": "this request was already performed and its effect is not \
                               duplicated. The original response is deliberately not retained \
                               — it carried secret material, or exceeded the replay size cap \
                               — so retrieve the result with the corresponding read operation",
                })),
            },
        );
    }
    let Ok(status) = axum::http::StatusCode::from_u16(entry.response_status) else {
        return reject_with(
            doc,
            RejectReason::InternalError {
                reason: "recorded idempotent response has an unusable status".to_string(),
            },
        );
    };
    tracing::info!(key, %type_uri, "replaying recorded response");
    TrustTaskOutcome {
        status,
        body: entry.response_body.clone(),
    }
}

/// Record the outcome of a claimed request, so a later retry converges on it.
///
/// A failed outcome *releases* the claim rather than recording it: the effect
/// this exists to deduplicate never happened, so the retry should be allowed to
/// actually run. Caching failures would turn one transient error into a sticky
/// one for the lifetime of the record.
pub(crate) async fn record_outcome(
    ks: &vti_common::store::KeyspaceHandle,
    actor: &str,
    key: &str,
    safety: RetrySafety,
    outcome: &TrustTaskOutcome,
) {
    let store = IdempotencyStore::new(ks.clone());
    let principal = Principal::Did(actor.to_string()).hash();

    if !outcome.status.is_success() {
        if let Err(e) = store.release(&principal, key).await {
            tracing::warn!(error = %e, actor, key, "failed to release an idempotency claim after a failed task");
        }
        return;
    }

    let too_large = outcome.body.len() > MAX_CACHED_BODY;
    if too_large && safety.response_is_replayable() {
        tracing::debug!(
            actor,
            key,
            bytes = outcome.body.len(),
            cap = MAX_CACHED_BODY,
            "response too large to retain for replay; recording completion only"
        );
    }
    let response = (safety.response_is_replayable() && !too_large).then(|| CompletedResponse {
        status: outcome.status.as_u16(),
        // Trust-Task outcomes are status + body; the content type is fixed by
        // `TrustTaskOutcome::into_response`, so there is nothing to carry here.
        headers: Vec::new(),
        body: outcome.body.clone(),
    });

    if let Err(e) = store.complete(&principal, key, response).await {
        tracing::warn!(error = %e, actor, key, "failed to record an idempotent outcome; a retry may re-run this task");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks;

    fn doc_with(type_uri: &str, payload: Value, key: Option<&str>) -> TrustTask<Value> {
        let uri: TypeUri = type_uri.parse().expect("type uri");
        let mut d = TrustTask::new("urn:uuid:test", uri, payload);
        if let Some(k) = key {
            d.extra.insert(
                IDEMPOTENCY_KEY_MEMBER.to_string(),
                serde_json::json!(k.to_string()),
            );
        }
        d
    }

    #[test]
    fn the_key_is_read_from_the_flattened_extra_member() {
        let d = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({}),
            Some("abc"),
        );
        assert_eq!(key_of(&d).as_deref(), Some("abc"));
    }

    #[test]
    fn an_unusable_key_reads_as_absent_not_as_an_error() {
        for bad in ["", "   ", &"x".repeat(256)] {
            let d = doc_with(
                trust_tasks::TASK_KEYS_CREATE_0_1,
                serde_json::json!({}),
                Some(bad),
            );
            assert_eq!(key_of(&d), None, "{bad:?} should read as absent");
        }
        let none = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({}),
            None,
        );
        assert_eq!(key_of(&none), None);
    }

    /// The key has to be a top-level member for the proof to cover it. If it
    /// ever serialises inside `payload`, a relayer could rewrite it.
    #[test]
    fn the_key_survives_the_json_round_trip_it_takes_on_the_wire() {
        let d = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({"a": 1}),
            Some("k-1"),
        );
        let wire = serde_json::to_string(&d).expect("serialise");
        assert!(
            wire.contains(r#""idempotencyKey":"k-1""#),
            "key must be top-level so the proof covers it: {wire}"
        );
        let back: TrustTask<Value> = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(key_of(&back).as_deref(), Some("k-1"));
    }

    #[test]
    fn the_request_hash_is_stable_across_member_ordering() {
        let a = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap(),
            None,
        );
        let b = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap(),
            None,
        );
        assert_eq!(payload_hash(&a), payload_hash(&b));
    }

    #[test]
    fn the_request_hash_separates_different_payloads() {
        let a = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({"label": "one"}),
            None,
        );
        let b = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({"label": "two"}),
            None,
        );
        assert_ne!(payload_hash(&a), payload_hash(&b));
    }

    /// The same body under two different tasks must not hash alike, or one key
    /// could carry a `keys/create` answer to a `dids/create` retry.
    #[test]
    fn the_request_hash_separates_different_tasks() {
        let a = doc_with(
            trust_tasks::TASK_KEYS_CREATE_0_1,
            serde_json::json!({}),
            None,
        );
        let b = doc_with(
            trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
            serde_json::json!({}),
            None,
        );
        assert_ne!(payload_hash(&a), payload_hash(&b));
    }

    /// The classification decides whether a record is kept at all; this pins
    /// both ends so a table edit shows up here too.
    #[test]
    fn only_keyed_tasks_are_worth_a_record() {
        assert!(
            retry_safety(trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0)
                .expect("classified")
                .needs_key()
        );
        assert!(
            !retry_safety(trust_tasks::TASK_WEBVH_DIDS_LIST_1_0)
                .expect("classified")
                .needs_key()
        );
    }

    #[test]
    fn secret_bearing_tasks_are_never_recorded_with_a_body() {
        assert!(
            !retry_safety(trust_tasks::TASK_PROVISION_INTEGRATION_0_2)
                .expect("classified")
                .response_is_replayable()
        );
    }
}
