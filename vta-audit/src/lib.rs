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
//! The sink is an extension point, not a policy: see [`sink`] for why the write
//! path is pluggable while retention is not.

use vta_sdk::protocols::audit_management::list::AuditLogEntry;

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

pub mod sink;
pub use sink::{AuditSink, FanOutAuditSink, KeyspaceAuditSink, SharedAuditSink};

/// Emit a structured audit event to the tracing subsystem.
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

/// Remove audit log entries older than `retention_days`.
pub async fn cleanup_expired_logs(
    audit_ks: &KeyspaceHandle,
    retention_days: u32,
) -> Result<u64, AppError> {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(retention_days as u64 * 86400);

    let cutoff_key = format!("log:{:020}:", cutoff);
    let keys = audit_ks.prefix_keys("log:").await?;

    let mut removed = 0u64;
    for key in keys {
        let key_str = String::from_utf8_lossy(&key);
        if key_str.as_ref() < cutoff_key.as_str() {
            audit_ks.remove(key).await?;
            removed += 1;
        } else {
            // Keys are sorted — once we pass the cutoff, stop
            break;
        }
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
