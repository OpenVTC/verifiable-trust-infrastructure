//! Structured audit logging for security-relevant operations.
//!
//! Audit events are:
//! 1. Emitted via `tracing` at a dedicated target (`audit`) for log shipping
//! 2. Persisted through an [`AuditSink`] — by default the `audit` fjall
//!    keyspace, which is what the retrieval API reads
//!
//! The `audit!` macro emits the tracing event. Persisting is done via
//! [`record`] / [`record_with_detail`], which should be called alongside the
//! macro in route/handler code.
//!
//! A call site that cannot propagate the error — most of them, since a failed
//! audit write must not fail the operation it records — should use
//! [`record_best_effort`] / [`record_with_detail_best_effort`] rather than
//! `let _ = record(..)`. They keep the same "never fails the caller" contract
//! and report the lost row instead of discarding it.
//!
//! The sink is an extension point, not a policy: see [`sink`] for why the write
//! path is pluggable while retention is not.

use vta_sdk::protocols::audit_management::list::AuditLogEntry;

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

pub mod sink;
pub use sink::{
    AUDIT_KEY_CREATED, AuditSink, ChainedKeyspaceAuditSink, FanOutAuditSink, KeyspaceAuditSink,
    SYSTEM_ACTOR, SharedAuditSink, shared_chained_sink, shared_keyspace_sink,
};

/// Emit a structured audit event to the tracing subsystem — **a log line, and
/// nothing else**.
///
/// This macro does **not** write to the [`AuditSink`]. Nothing it records
/// appears in `audit/list`, or in an operator's external sink, or anywhere a
/// later investigation would query. Persisting is [`record`] /
/// [`record_with_detail`], and a handler that needs a trail must call one of
/// those **as well as** this.
///
/// The emphasis is here because the call site does not carry it. A handler
/// containing `audit!("session.revoke", …)` three lines above its response
/// reads, on every measure a reviewer applies, as a handler that audits. It
/// compiles, it is named `audit`, it emits an event, and the row an operator
/// goes looking for is not there.
///
/// That is not hypothetical. `vta/management/reload-services` shipped with this
/// macro and no sink write, so restarting an agent — every open session
/// dropped, every counterparty disconnected — left nothing in the queryable
/// trail. It took a runtime census to notice, and the census could not see the
/// task at all until it was specified upstream (#1239). Two layers of checking
/// passed over a handler that looked audited and was not.
///
/// Uses `INFO` for successful outcomes and `ERROR` for failures (e.g. `denied:*`).
#[macro_export]
macro_rules! audit {
    ($action:expr, actor = $actor:expr, resource = $resource:expr, outcome = $outcome:expr) => {
        if $outcome.starts_with("success") {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::INFO,
                action = $action,
                actor = %$actor,
                resource = %$resource,
                outcome = $outcome,
            );
        } else {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::ERROR,
                action = $action,
                actor = %$actor,
                resource = %$resource,
                outcome = $outcome,
            );
        }
    };
    ($action:expr, actor = $actor:expr, outcome = $outcome:expr) => {
        if $outcome.starts_with("success") {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::INFO,
                action = $action,
                actor = %$actor,
                outcome = $outcome,
            );
        } else {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::ERROR,
                action = $action,
                actor = %$actor,
                outcome = $outcome,
            );
        }
    };
}

/// Persist an audit log entry through `sink`.
///
/// The default sink is the audit keyspace, which is what
/// [`cleanup_expired_logs`] prunes and what the retrieval API reads. A
/// deployment may install another; see [`sink`].
pub async fn record(
    sink: &SharedAuditSink,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
) -> Result<(), AppError> {
    record_with_detail(
        sink, action, actor, resource, outcome, channel, context_id, None,
    )
    .await
}

/// Tracing target for an audit write that did **not** land.
///
/// Deliberately not `audit`. That target carries the events themselves, and an
/// operator shipping it to a log sink is reading a stream of things that
/// happened; this carries the news that one of them is missing from the
/// queryable trail, which is a different kind of fact and worth routing (and
/// alerting) separately. Filtering still works from either end: EnvFilter
/// matches target prefixes, so `RUST_LOG=audit=error` picks this up too.
pub const AUDIT_WRITE_FAILURE_TARGET: &str = "audit.write_failure";

/// Counter incremented once per audit entry the sink refused, labelled by
/// `action`.
///
/// A log line is evidence for whoever is reading logs; a counter is what an
/// alert can be built on — and "the audit log stopped accepting writes" is
/// precisely the condition nobody notices by reading.
pub const AUDIT_WRITE_FAILURES: &str = "audit_sink_write_failures_total";

/// [`record`], with a failed write **reported** rather than discarded.
///
/// # Why this exists
///
/// Twenty-seven call sites in `vta-service` wrote `let _ = audit::record(..)`.
/// The intent was right and remains right: a failed audit write must not fail
/// the operation it records, because refusing to revoke a key on the grounds
/// that the log was full protects nobody. But `let _ =` implements "must not
/// fail the operation" as "must not be mentioned", and those are not the same
/// thing. The row was gone, the process knew, and it said nothing — so the
/// first symptom was an absence, which is the one thing nobody greps for.
///
/// That got worse when the VTA's log became a **hash chain** (#1420). A failed
/// append is then not one missing line: it is the point beyond which the chain
/// cannot be extended, and the person who finds out is whoever runs `verify`
/// weeks later, with no way to tell "the sink was unavailable on Tuesday" from
/// "somebody removed an entry" — the exact case the chain exists to detect.
/// A dropped error turns the tamper-evidence into a false positive generator.
///
/// So the write stays best-effort and the caller still cannot fail because of
/// it. What changes is that the failure leaves a trace: an `ERROR` on
/// [`AUDIT_WRITE_FAILURE_TARGET`] carrying enough of the row to reconstruct it
/// by hand, and [`AUDIT_WRITE_FAILURES`] for something to alert on.
///
/// Prefer this to `let _ = record(..)` at every call site that cannot
/// propagate. A site that *can* propagate should still use [`record`].
pub async fn record_best_effort(
    sink: &SharedAuditSink,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
) {
    record_with_detail_best_effort(
        sink, action, actor, resource, outcome, channel, context_id, None,
    )
    .await
}

/// [`record_with_detail`], with a failed write reported rather than discarded.
/// See [`record_best_effort`] for why.
#[allow(clippy::too_many_arguments)]
pub async fn record_with_detail_best_effort(
    sink: &SharedAuditSink,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
    detail: Option<&str>,
) {
    if let Err(e) = record_with_detail(
        sink, action, actor, resource, outcome, channel, context_id, detail,
    )
    .await
    {
        // The whole row, because reconstructing it by hand is what an operator
        // is left to do: the entry is not in the log and nothing retries it.
        // `detail` is omitted on purpose — it is operator free text, up to
        // `DETAIL_MAX_CHARS`, and this line goes to the ordinary log stream.
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            action,
            actor,
            resource = ?resource,
            outcome,
            channel = ?channel,
            context_id = ?context_id,
            error = %e,
            "audit sink rejected an entry; the operation it records still \
             succeeded, and this row is lost"
        );
        metrics::counter!(AUDIT_WRITE_FAILURES, "action" => action.to_string()).increment(1);
    }
}

/// How much operator-supplied `detail` an audit row keeps.
///
/// Framework 0.5.0 requires every free-text member to carry a bound, on the
/// reasoning that free text is "where personal data arrives in a task declaring
/// it ingests none, where a secret arrives pasted by someone asked for a
/// reason" — and it is unbounded cost. Here the cost is worse than wire bytes:
/// this row goes into a **hash-chained, append-only** log, so an oversized
/// `detail` is permanent. It cannot be trimmed later without breaking the
/// chain that makes the log evidence.
///
/// 4096 characters is generous for a `reason` a human typed and small against
/// the chain.
pub const DETAIL_MAX_CHARS: usize = 4096;

/// Truncate an over-long `detail`, marking that it was cut.
///
/// Truncated rather than rejected, deliberately. This function runs *after* the
/// operation it records has already happened, so refusing the row would trade
/// an over-long reason for **no audit record at all** — losing the evidence to
/// protect its formatting. Truncation keeps the row, the actor, the action and
/// the outcome, which is what the log is for.
///
/// Cut on a character boundary: slicing bytes would panic mid-codepoint on the
/// first operator who wrote a reason in a language this workspace did not
/// anticipate.
fn bound_detail(detail: &str) -> String {
    if detail.chars().count() <= DETAIL_MAX_CHARS {
        return detail.to_string();
    }
    const MARK: &str = "… [truncated]";
    let kept: String = detail
        .chars()
        .take(DETAIL_MAX_CHARS - MARK.chars().count())
        .collect();
    tracing::warn!(
        original_chars = detail.chars().count(),
        "audit detail exceeded {DETAIL_MAX_CHARS} characters and was truncated"
    );
    format!("{kept}{MARK}")
}

/// Like [`record`], but also persists an operator-supplied `detail` (e.g. the
/// `reason` on a `vault.delete`/`vault.archive`). Kept as a separate function
/// so the existing `record(...)` call sites stay untouched.
#[allow(clippy::too_many_arguments)]
pub async fn record_with_detail(
    sink: &SharedAuditSink,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
    detail: Option<&str>,
) -> Result<(), AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let id = uuid::Uuid::new_v4().to_string();

    let entry = AuditLogEntry {
        id,
        timestamp: now,
        action: action.to_string(),
        actor: actor.to_string(),
        resource: resource.map(String::from),
        outcome: outcome.to_string(),
        channel: channel.map(String::from),
        context_id: context_id.map(String::from),
        detail: detail.map(bound_detail),
    };

    // The storage key is the sink's business — a keyspace derives one, an
    // append-only or anchored backend has no use for it. See `sink`.
    sink.record(&entry).await
}

/// Best-effort audit write for the DTTE consent ceremony.
///
/// The consent gate and the approver-decision handler are security-relevant but
/// were entirely un-audited: a request raised, an approver's decision, a grant
/// minted/consumed, and every rejection left no durable trace, so a looped or
/// failed elevation was invisible after the fact. This records the whole chain
/// (`consent.required` → `consent.decision` → `consent.granted` →
/// `consent.consumed`) under stable action names.
///
/// A missing audit row must never change a gate/decision outcome — same contract
/// as the orchestrator's post-update emission — so errors are logged and
/// swallowed rather than propagated.
///
/// Emits to the `audit` tracing target *as well as* persisting to the keyspace.
/// [`record_with_detail`] alone only writes to storage — the log-stream line
/// comes from the [`audit!`] macro, which the other audit call sites invoke
/// alongside `record`. Without emitting here, `consent.*` rows were queryable
/// via the audit API but invisible in `RUST_LOG` output, so a live capture of a
/// consent loop showed no consent activity at all. Emit both.
pub async fn record_consent(
    sink: &SharedAuditSink,
    action: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    detail: Option<&str>,
) {
    // Emit to the `audit` target at a level that reflects the outcome: a denied
    // decision/consume is ERROR (like the `audit!` macro's failure arm), while
    // normal ceremony progress (pending raised, approval, grant, consume) is
    // INFO — a Destructive task requiring consent is expected, not an error.
    if outcome.starts_with("denied") {
        tracing::event!(
            target: "audit",
            tracing::Level::ERROR,
            action,
            actor,
            resource,
            outcome,
        );
    } else {
        tracing::event!(
            target: "audit",
            tracing::Level::INFO,
            action,
            actor,
            resource,
            outcome,
        );
    }
    if let Err(e) = record_with_detail(
        sink,
        action,
        actor,
        Some(resource),
        outcome,
        None,
        None,
        detail,
    )
    .await
    {
        tracing::warn!(
            action,
            actor,
            error = %e,
            "DTTE consent audit emission failed; ceremony outcome is unaffected"
        );
    }
}

/// Where the retention sweep has pruned to, so that verification can resume.
///
/// Deleting the oldest entries of a hash chain leaves the rest unverifiable:
/// the first surviving entry's `prev_hash` points at something that is gone,
/// which is **indistinguishable from an entry having been removed by an
/// attacker** — the case the chain exists to detect. Retention would therefore
/// break verification permanently, and the first person to run `verify` after
/// a sweep would get a failure that means nothing.
///
/// The watermark is what the sweep leaves behind: the hash it pruned through
/// and how many chained entries it removed, so a verifier resumes from that
/// point instead of expecting a chain back to genesis.
///
/// # What it is worth
///
/// It is stored in the same keyspace as the log, so it is exactly as
/// trustworthy as that store: an adversary who can delete entries can also
/// rewrite the watermark to match. It restores verification across an
/// *honest* sweep, and that is all it claims. Making a pruned prefix
/// verifiable against an adversary with store access needs the watermark
/// signed and published outside the store, which is what the VTC's signed
/// checkpoints do.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneWatermark {
    /// `entry_hash` of the newest chained entry the sweep removed — the
    /// `prev_hash` the oldest surviving entry points at.
    pub head: String,
    /// Chained entries removed by every sweep so far, so a break is still
    /// reported at its position in the whole log rather than in the remainder.
    pub pruned_entries: usize,
    /// When the most recent sweep ran.
    pub pruned_at: String,
}

/// Storage key of the watermark.
///
/// Outside the `log:` prefix on purpose: the sweep deletes by that prefix, so
/// a watermark stored under it would be pruned by the sweep that wrote it.
pub const PRUNE_WATERMARK_KEY: &str = "prune:watermark";

/// Read the retention sweep's watermark, if it has ever run.
pub async fn prune_watermark(
    audit_ks: &KeyspaceHandle,
) -> Result<Option<PruneWatermark>, AppError> {
    audit_ks.get(PRUNE_WATERMARK_KEY.to_string()).await
}

/// Remove audit log entries older than `retention_days`.
///
/// Records a [`PruneWatermark`] when it removes chained entries, so the
/// remainder still verifies. Without that, retention and tamper-evidence are
/// mutually exclusive.
pub async fn cleanup_expired_logs(
    audit_ks: &KeyspaceHandle,
    retention_days: u32,
) -> Result<u64, AppError> {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(retention_days as u64 * 86400);
    cleanup_logs_before(audit_ks, cutoff).await
}

/// [`cleanup_expired_logs`] with the cutoff supplied rather than derived from
/// the clock.
///
/// Separate so the sweep can be exercised against a known boundary: derived
/// from `now`, the only reachable boundaries in a test are "everything
/// written a whole day ago", which nothing in a test was, and "nothing".
pub async fn cleanup_logs_before(audit_ks: &KeyspaceHandle, cutoff: u64) -> Result<u64, AppError> {
    let cutoff_key = format!("log:{cutoff:020}:");
    let keys = audit_ks.prefix_keys("log:").await?;

    let mut removed = 0u64;
    let mut pruned_chained = 0usize;
    let mut last_chained_hash: Option<String> = None;

    for key in keys {
        let key_str = String::from_utf8_lossy(&key).into_owned();
        if key_str.as_str() < cutoff_key.as_str() {
            // Read before deleting: a chained entry carries the hash the
            // survivors will point back at, and once it is gone so is the
            // only copy of it.
            if let Ok(Some(raw)) = audit_ks.get_raw(key.clone()).await
                && let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&raw)
            {
                last_chained_hash = Some(hex::encode(env.entry_hash));
                pruned_chained += 1;
            }
            audit_ks.remove(key).await?;
            removed += 1;
        } else {
            // Keys are sorted — once we pass the cutoff, stop
            break;
        }
    }

    if let Some(head) = last_chained_hash {
        let previous = prune_watermark(audit_ks).await?;
        let watermark = PruneWatermark {
            head,
            pruned_entries: previous.map_or(0, |w| w.pruned_entries) + pruned_chained,
            pruned_at: chrono::Utc::now().to_rfc3339(),
        };
        audit_ks
            .insert(PRUNE_WATERMARK_KEY.to_string(), &watermark)
            .await?;
    }

    Ok(removed)
}

#[cfg(test)]
mod detail_bound {
    use super::*;

    #[test]
    fn a_short_detail_is_untouched() {
        assert_eq!(
            bound_detail("archived on operator request"),
            "archived on operator request"
        );
    }

    #[test]
    fn an_oversized_detail_is_truncated_and_marked() {
        let out = bound_detail(&"x".repeat(DETAIL_MAX_CHARS * 2));
        assert!(
            out.chars().count() <= DETAIL_MAX_CHARS,
            "{}",
            out.chars().count()
        );
        assert!(
            out.ends_with("… [truncated]"),
            "a silently shortened reason reads as the operator's own words: {out}"
        );
    }

    /// Cut on a character boundary, not a byte one.
    ///
    /// Slicing bytes panics mid-codepoint, and it would do so on the first
    /// operator who wrote a reason in a language this workspace did not
    /// anticipate — an audit path is the worst possible place to learn that.
    #[test]
    fn truncation_does_not_split_a_codepoint() {
        // Four bytes per character, so a byte-slice at any odd offset panics.
        let out = bound_detail(&"𝄞".repeat(DETAIL_MAX_CHARS * 2));
        assert!(out.chars().count() <= DETAIL_MAX_CHARS);
        assert!(out.starts_with('𝄞'));
    }
}

/// The property [`record_best_effort`] exists for: a refused write is still
/// best-effort for the caller, and no longer silent.
#[cfg(test)]
mod best_effort {
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::registry::Registry;

    use super::*;

    /// Refuses everything — the case the `let _ = record(..)` sites made
    /// invisible.
    struct Failing;

    #[async_trait]
    impl AuditSink for Failing {
        async fn record(&self, _entry: &AuditLogEntry) -> Result<(), AppError> {
            Err(AppError::Internal("sink is down".into()))
        }
    }

    struct Healthy;

    #[async_trait]
    impl AuditSink for Healthy {
        async fn record(&self, _entry: &AuditLogEntry) -> Result<(), AppError> {
            Ok(())
        }
    }

    type Events = Arc<Mutex<Vec<(String, tracing::Level, String)>>>;

    /// Collects `(target, level, rendered fields)` for every event emitted
    /// while it is installed.
    struct Capture(Events);

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            struct Render<'a>(&'a mut String);
            impl Visit for Render<'_> {
                // Every other `record_*` defaults to this one, so Display- and
                // Debug-formatted fields alike land here.
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, "{}={value:?} ", field.name());
                }
            }
            let mut rendered = String::new();
            event.record(&mut Render(&mut rendered));
            self.0.lock().unwrap().push((
                event.metadata().target().to_string(),
                *event.metadata().level(),
                rendered,
            ));
        }
    }

    /// Drive `f` to completion with the capturing subscriber installed.
    ///
    /// The runtime is built *inside* `with_default` deliberately:
    /// `with_default` is synchronous and sets the subscriber for the current
    /// thread, so holding its guard across an `.await` that might resume
    /// elsewhere would emit the event where nothing is listening — a test that
    /// passes for the wrong reason, in the one place where a false pass means
    /// the reporting silently is not there.
    fn captured<F: Future<Output = ()>>(f: F) -> Vec<(String, tracing::Level, String)> {
        let events: Events = Arc::default();
        let subscriber = Registry::default().with(Capture(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime")
                .block_on(f);
        });
        events.lock().unwrap().clone()
    }

    #[test]
    fn a_refused_write_is_reported_at_error_with_the_row_it_lost() {
        let events = captured(async {
            record_best_effort(
                &(Arc::new(Failing) as SharedAuditSink),
                "key.create.internal",
                "did:key:zActor",
                Some("key-1"),
                "success",
                Some("rest"),
                Some("acme/eng"),
            )
            .await;
        });

        let (_, level, fields) = events
            .iter()
            .find(|(target, ..)| target == AUDIT_WRITE_FAILURE_TARGET)
            .expect(
                "a refused audit write must be reported — that report is the \
                 entire difference from `let _ = record(..)`",
            );

        assert_eq!(
            *level,
            tracing::Level::ERROR,
            "a lost audit row in a hash-chained log is not a warning"
        );
        for expected in [
            "key.create.internal",
            "did:key:zActor",
            "key-1",
            "acme/eng",
            "sink is down",
        ] {
            assert!(
                fields.contains(expected),
                "the report has to carry enough to reconstruct the row by hand, \
                 because nothing retries it; {expected:?} is missing from \
                 {fields:?}"
            );
        }
    }

    /// The caller is not failed by a refused write. Asserted because the fix
    /// would be worthless if it had turned audit failures into operation
    /// failures — refusing to revoke a key because the log is full protects
    /// nobody.
    #[test]
    fn a_refused_write_still_returns_to_the_caller() {
        // `record_best_effort` returns `()`, so reaching the assertion below is
        // the assertion: it did not panic and there is no error to propagate.
        let events = captured(async {
            record_best_effort(
                &(Arc::new(Failing) as SharedAuditSink),
                "key.revoke",
                "did:key:zActor",
                None,
                "success",
                None,
                None,
            )
            .await;
        });
        assert!(!events.is_empty(), "the failure should have been reported");
    }

    #[test]
    fn a_healthy_write_reports_nothing() {
        let events = captured(async {
            record_best_effort(
                &(Arc::new(Healthy) as SharedAuditSink),
                "key.revoke",
                "did:key:zActor",
                None,
                "success",
                None,
                None,
            )
            .await;
        });

        assert!(
            !events
                .iter()
                .any(|(target, ..)| target == AUDIT_WRITE_FAILURE_TARGET),
            "nothing failed, so nothing should be reported: {events:?}"
        );
    }
}
