//! Where audit entries go.
//!
//! The audit log records what happened; it cannot prove it. `AuditLogEntry` is
//! `{id, timestamp, action, actor, resource, outcome, channel, contextId,
//! detail}` — no signature, no hash chain — so a compromised VTA can rewrite
//! its own history. The canonical `AuditEnvelope` in
//! `vta_sdk::protocols::audit_management` already names the members that would
//! change that (`prevHash`, `entryHash`, `schemaVersion`) and says why this
//! maintainer omits them: its log is flat and unchained.
//!
//! This module does **not** add tamper-evidence, and that is deliberate (#1031).
//! It adds the seam. An operator who needs a stronger guarantee implements
//! [`AuditSink`] — an append-only file, a transparency log, a blockchain anchor,
//! a hash chain populating those three members — and installs it, without the
//! VTA committing to any particular scheme. The crypto decision moves out of the
//! protocol and becomes a deployment choice.
//!
//! Same shape as `vti_common::telemetry::TelemetrySink`, whose own docs already
//! name "append-only log, blockchain anchor" as the backends it exists to admit.
//! The two stay separate for the reason recorded there: telemetry is
//! high-volume and query-oriented, audit is security-relevant and durable.
//!
//! ## What is, and is not, behind the seam
//!
//! Writes go through the sink. **Reads and retention do not** —
//! [`crate::cleanup_expired_logs`] and the audit-list query still address the
//! fjall keyspace directly, and take a `KeyspaceHandle` rather than a sink.
//! That is not an oversight. A sink is free to be write-only and remote, and
//! for an append-only or anchored backend "delete rows older than N days" is
//! not an operation it can offer — the immutability is the point. So retention
//! stays a property of the local keyspace, which is also what the retention API
//! is documented to govern.
//!
//! A deployment that installs a remote sink therefore keeps writing locally too
//! if it wants the query API to work — compose the two with [`FanOutAuditSink`]
//! rather than replacing the keyspace sink outright.

use std::sync::Arc;

use async_trait::async_trait;
use vta_sdk::protocols::audit_management::list::AuditLogEntry;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// A destination for audit entries.
///
/// One method, taking the whole entry. The entry is the unit of meaning; how it
/// is keyed, framed, chained, or shipped is the implementation's business —
/// which is why the storage key format lives in [`KeyspaceAuditSink`] and not
/// in the caller.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Durably record `entry`.
    ///
    /// Returning `Err` propagates to the caller. Callers differ in what they do
    /// with it — the vault dispatch tail and the DTTE ceremony log and swallow,
    /// because a missing audit row must not change an operation's outcome,
    /// while other call sites propagate. An implementation should not assume
    /// either; it should assume only that returning `Err` is honest and
    /// swallowing internally is not.
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError>;
}

/// The shared handle every call site holds.
pub type SharedAuditSink = Arc<dyn AuditSink>;

/// The default sink: the `audit` fjall keyspace, exactly as before this trait
/// existed.
///
/// Owns the storage key format — `log:{timestamp:020}:{uuid}` — because that
/// format is a property of *this* backend. Zero-padding gives lexicographic
/// time ordering, which is what makes the retention sweep's early `break` and
/// the audit-list time-range scan prefix operations rather than full scans.
#[derive(Clone)]
pub struct KeyspaceAuditSink {
    keyspace: KeyspaceHandle,
}

impl KeyspaceAuditSink {
    pub fn new(keyspace: KeyspaceHandle) -> Self {
        Self { keyspace }
    }

    /// The keyspace behind this sink, for the read and retention paths that
    /// deliberately are not routed through [`AuditSink`] (see the module docs).
    pub fn keyspace(&self) -> &KeyspaceHandle {
        &self.keyspace
    }

    /// The storage key for `entry`. Public so a test — or an alternative
    /// keyspace-backed sink — can agree with the reader rather than restate the
    /// format and drift from it.
    pub fn storage_key(entry: &AuditLogEntry) -> String {
        format!("log:{:020}:{}", entry.timestamp, entry.id)
    }
}

#[async_trait]
impl AuditSink for KeyspaceAuditSink {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        self.keyspace.insert(Self::storage_key(entry), entry).await
    }
}

/// Write every entry to several sinks.
///
/// The composition an operator adding tamper-evidence actually needs: keep the
/// keyspace sink so the query and retention APIs go on working, and add the
/// append-only or anchored one beside it. Without this, installing a remote
/// sink would silently take `GET /audit/logs` with it.
///
/// **Every** sink is attempted, and the first error is returned after all of
/// them have run. Short-circuiting would make a failing sink hide the entry
/// from the ones after it in the list, which for an audit log is the failure
/// mode that matters: the row you cannot see is the one you needed.
pub struct FanOutAuditSink {
    sinks: Vec<SharedAuditSink>,
}

impl FanOutAuditSink {
    pub fn new(sinks: Vec<SharedAuditSink>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AuditSink for FanOutAuditSink {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        let mut first_err = None;
        for sink in &self.sinks {
            if let Err(e) = sink.record(entry).await {
                tracing::warn!(
                    action = %entry.action,
                    actor = %entry.actor,
                    error = %e,
                    "an audit sink rejected an entry; continuing with the rest"
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn entry(action: &str) -> AuditLogEntry {
        AuditLogEntry {
            id: "11111111-1111-4111-8111-111111111111".into(),
            timestamp: 1_700_000_000,
            action: action.into(),
            actor: "did:key:zTest".into(),
            resource: None,
            outcome: "success".into(),
            channel: None,
            context_id: None,
            detail: None,
        }
    }

    #[derive(Default)]
    struct Recording {
        seen: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl AuditSink for Recording {
        async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
            self.seen.lock().unwrap().push(entry.action.clone());
            if self.fail {
                return Err(AppError::Internal("sink refused".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn the_storage_key_sorts_lexicographically_by_time() {
        // The retention sweep stops at the first key past the cutoff, and the
        // list query is a prefix scan. Both are only correct while the key
        // sorts by time as a *string* — which is what the zero-padding buys.
        let mut early = entry("a");
        early.timestamp = 9;
        let mut late = entry("b");
        late.timestamp = 100;

        assert!(
            KeyspaceAuditSink::storage_key(&early) < KeyspaceAuditSink::storage_key(&late),
            "an earlier entry must sort first as a string, or the sweep's early \
             `break` skips live rows"
        );
    }

    #[tokio::test]
    async fn fan_out_reaches_every_sink_even_when_one_fails() {
        // The point of the composition is that a failing sink cannot hide an
        // entry from the sinks after it.
        let failing = Arc::new(Recording {
            fail: true,
            ..Default::default()
        });
        let healthy = Arc::new(Recording::default());
        let fan = FanOutAuditSink::new(vec![
            Arc::clone(&failing) as SharedAuditSink,
            Arc::clone(&healthy) as SharedAuditSink,
        ]);

        let result = fan.record(&entry("keys.create")).await;

        assert!(result.is_err(), "the failure must still be reported");
        assert_eq!(
            healthy.seen.lock().unwrap().as_slice(),
            ["keys.create"],
            "the sink after the failing one must still have received the entry"
        );
    }

    #[tokio::test]
    async fn fan_out_is_ok_when_every_sink_accepts() {
        let a = Arc::new(Recording::default());
        let b = Arc::new(Recording::default());
        let fan = FanOutAuditSink::new(vec![
            Arc::clone(&a) as SharedAuditSink,
            Arc::clone(&b) as SharedAuditSink,
        ]);

        assert!(fan.record(&entry("acl.grant")).await.is_ok());
        assert_eq!(a.seen.lock().unwrap().len(), 1);
        assert_eq!(b.seen.lock().unwrap().len(), 1);
    }
}
