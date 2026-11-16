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

/// How long an in-flight claim is reported as running (`unavailable`, ask
/// again) before it is reported as abandoned (outcome unknown).
///
/// Past this the claiming attempt cannot still be running — a live request is
/// bounded by its own handler timeout, and the longest of those is 60s — so it
/// died. The key is still never reclaimed: the attempt may have committed its
/// effect before dying, and a re-run would be the second effect VTI-OPS-061
/// forbids (#2402). The grace only decides which answer the retry gets.
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

/// The class every keyed Trust Task is recorded under: the floor of its
/// retention. The record is kept longer when a document under the key is
/// acceptable for longer (VTI-OPS-066, see [`claim`]).
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
    // Canonical JSON (RFC 8785), not `serde_json::to_vec`: the same payload
    // with its members in another order is the same request, and serde_json
    // keeps insertion order whenever any crate in the build enables its
    // `preserve_order` feature.
    h.update(serde_json_canonicalizer::to_vec(&doc.payload).unwrap_or_default());
    h.finalize().into()
}

/// What the dispatcher should do with a keyed request.
pub(crate) enum Claim {
    /// This attempt owns the key. Run the handler, then call
    /// [`record_outcome`].
    Proceed { key: String, safety: RetrySafety },
    /// Answer with this instead of dispatching.
    Answer(Box<TrustTaskOutcome>),
    /// Not keyed, or not a task worth keying. Dispatch normally and record
    /// nothing.
    Skip,
}

/// Claim `(actor, key)` for this request, or report what already happened to it.
///
/// A store error answers `unavailable` rather than dispatching unguarded. A
/// keyed request is one whose repeat matters, and a node MUST perform it at
/// most once per key (VTI-OPS-061); without the claim nothing stops a retry
/// arriving after the store recovers from running it a second time. The
/// refusal is transient, so `VtaClient::idempotent` retries it under the same
/// key.
///
/// The record is kept until this document's acceptance end plus the skew, or
/// the class TTL if that is later, and a repeat under the key extends it to
/// the repeat's own acceptance end (**VTI-OPS-066**). The attempts at one
/// operation are separate documents, and one stating an `expiresAt` is
/// acceptable for up to thirty days (VTI-OPS-028): a record kept only for the
/// 24-hour TTL would let the attempt arriving on the second day perform the
/// operation again.
pub(crate) async fn claim(
    ks: &vti_common::store::KeyspaceHandle,
    actor: &str,
    doc: &TrustTask<serde_json::Value>,
) -> Claim {
    let type_uri = doc.type_uri.to_string();

    // Not-keyed tasks are skipped because a repeat is harmless, so a record
    // would cost a write and buy nothing.
    //
    // A task the table does not classify is keyed (VTI-OPS-062: "an operation
    // that is not classified MUST be treated as belonging to the third class").
    // That is not only the unknown task the dispatcher is about to refuse —
    // whose claim the refusal then releases — but every task served here that
    // is not in the VTA's own catalogue: the credential-exchange steps a
    // counterparty sends, `issue` among them, which deposits a second vault row
    // when it runs twice. Their producers carry a key across every attempt at
    // one step, new attempts included (`trust_task_push`), so skipping them
    // here would perform each attempt.
    let Some(key) = key_of(doc) else {
        return Claim::Skip;
    };
    let safety = retry_safety(&type_uri).unwrap_or(RetrySafety::Keyed);
    if !safety.needs_key() {
        return Claim::Skip;
    }

    let store = IdempotencyStore::new(ks.clone());
    let principal = Principal::Did(actor.to_string()).hash();
    let grace = chrono::Duration::minutes(IN_FLIGHT_GRACE_MINS);

    let retain_until = super::retain_until(doc, chrono::Utc::now());
    let outcome = match store
        .claim_retained(
            &principal,
            &key,
            payload_hash(doc),
            CLASS,
            grace,
            retain_until,
        )
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, actor, key, %type_uri, "idempotency claim failed; refusing the keyed request rather than running it unguarded");
            let retry_after =
                chrono::Utc::now() + chrono::Duration::seconds(IN_FLIGHT_RETRY_AFTER_SECS);
            return Claim::Answer(Box::new(reject_with(
                doc,
                RejectReason::Unavailable {
                    retry_after: Some(retry_after),
                },
            )));
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
        ClaimOutcome::Abandoned { claimed_at } => {
            // The attempt that claimed this key died without recording an
            // outcome, and may or may not have taken effect. Running it again
            // could be the duplicate the key exists to prevent, so the answer
            // is "unknown" — terminal, not transient: the same key can never
            // be answered differently while the record lives.
            tracing::warn!(
                actor,
                key,
                %type_uri,
                claimed_at = %claimed_at.to_rfc3339(),
                "keyed request's earlier attempt was abandoned with its outcome unknown; not re-running it"
            );
            Claim::Answer(Box::new(reject_with(
                doc,
                RejectReason::TaskFailed {
                    reason: "outcome unknown: an earlier attempt under this idempotency key \
                             did not finish"
                        .to_string(),
                    details: Some(serde_json::json!({
                        "idempotencyKey": key,
                        "task": type_uri,
                        "claimedAt": claimed_at.to_rfc3339(),
                        "reason": "an earlier attempt under this key was interrupted before \
                                   its outcome was recorded, so whether it took effect is \
                                   unknown, and it is not run again because that could \
                                   duplicate it. Check whether the effect exists with the \
                                   corresponding read operation; if it does not and is still \
                                   wanted, send the request under a new key",
                    })),
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
        // `ClaimOutcome` is non-exhaustive. An outcome this build does not
        // know is not a licence to run the task: refuse it.
        _ => Claim::Answer(Box::new(reject_with(
            doc,
            RejectReason::InternalError {
                reason: "unrecognised idempotency claim outcome".to_string(),
            },
        ))),
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
        restart: false,
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
        tracing::warn!(error = %e, actor, key, "failed to record an idempotent outcome; a retry under this key will be answered outcome-unknown");
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

    /// VTI-OPS-062: a task the catalogue does not classify is treated as keyed.
    /// `credential-exchange/issue` is one — a counterparty task, served here
    /// but not in `retry_safety` — and it deposits a vault row per execution,
    /// so a second attempt at one `issue` under the same key (the push engine's
    /// new attempt, past the acceptance window) must be answered, not run.
    #[tokio::test]
    async fn an_unclassified_task_carrying_a_key_is_performed_once_per_key() {
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let issue = vta_sdk::protocols::credential_exchange::ISSUE;
        assert!(
            retry_safety(issue).is_none(),
            "the premise: `issue` is not in the catalogue"
        );
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::IDEMPOTENCY).unwrap();
        let payload = serde_json::json!({ "credential": "x" });
        let first = doc_with(issue, payload.clone(), Some("urn:uuid:step-1"));

        let Claim::Proceed { key, safety } = claim(&ks, "did:example:issuer", &first).await else {
            panic!("the first attempt at an unclassified keyed task runs");
        };
        record_outcome(
            &ks,
            "did:example:issuer",
            &key,
            safety,
            &TrustTaskOutcome {
                status: axum::http::StatusCode::NO_CONTENT,
                body: Vec::new(),
                restart: false,
            },
        )
        .await;

        let mut second = doc_with(issue, payload, Some("urn:uuid:step-1"));
        second.id = "urn:uuid:a-new-attempt".into();
        assert!(
            matches!(
                claim(&ks, "did:example:issuer", &second).await,
                Claim::Answer(_)
            ),
            "a new attempt under the same key is answered, not performed again"
        );
    }

    /// **VTI-OPS-066.** The record of a key outlasts the latest acceptance end
    /// of any document accepted under it. The first attempt states a 20-day
    /// expiry, so its record lasts 20 days, not the 24-hour TTL; a new attempt
    /// stating 25 days extends it to that.
    #[tokio::test]
    async fn vti_ops_066_the_record_lasts_until_the_latest_acceptance_end() {
        use chrono::{SubsecRound, TimeDelta, Utc};
        use vti_common::config::StoreConfig;
        use vti_common::idempotency::{IdempotencyStore, Principal};
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::IDEMPOTENCY).unwrap();
        let actor = "did:example:caller";
        let key = "urn:uuid:long-lived";
        let now = Utc::now().trunc_subsecs(0);
        let attempt = |id: &str, days: i64| {
            let mut d = doc_with(
                trust_tasks::TASK_KEYS_CREATE_0_1,
                serde_json::json!({ "keyType": "ed25519" }),
                Some(key),
            );
            d.id = id.into();
            d.issued_at = Some(now);
            d.expires_at = Some(now + TimeDelta::days(days));
            d
        };
        let record = || async {
            IdempotencyStore::new(ks.clone())
                .get(&Principal::Did(actor.to_string()).hash(), key)
                .await
                .unwrap()
                .expect("the key has a record")
        };
        let skew = trust_tasks_rs::DEFAULT_SKEW;

        let Claim::Proceed { key: k, safety } =
            claim(&ks, actor, &attempt("urn:uuid:a1", 20)).await
        else {
            panic!("the first attempt runs");
        };
        assert_eq!(record().await.expires_at, now + TimeDelta::days(20) + skew);
        record_outcome(
            &ks,
            actor,
            &k,
            safety,
            &TrustTaskOutcome {
                status: axum::http::StatusCode::OK,
                body: b"{}".to_vec(),
                restart: false,
            },
        )
        .await;

        assert!(matches!(
            claim(&ks, actor, &attempt("urn:uuid:a2", 25)).await,
            Claim::Answer(_)
        ));
        assert_eq!(
            record().await.expires_at,
            now + TimeDelta::days(25) + skew,
            "the later attempt's acceptance end extends the record"
        );
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
            trust_tasks::TASK_WEBVH_DIDS_CREATE_1_2,
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
            retry_safety(trust_tasks::TASK_WEBVH_DIDS_CREATE_1_2)
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
            !retry_safety(trust_tasks::TASK_PROVISION_INTEGRATION_0_3)
                .expect("classified")
                .response_is_replayable()
        );
    }
}
