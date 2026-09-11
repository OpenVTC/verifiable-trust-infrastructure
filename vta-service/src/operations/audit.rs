use std::sync::Arc;
use tokio::sync::RwLock;
use vta_sdk::protocols::audit_management::list::{
    AuditEnvelope, AuditLogEntry, ListAuditLogsBody, ListAuditLogsResultBody,
};
use vta_sdk::protocols::audit_management::retention::RetentionResultBody;
use vti_common::pagination::{Cursor, CursorKey, MAX_LIMIT};

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Page size used when the caller omits `pageSize`.
const DEFAULT_PAGE_SIZE: u64 = 50;

/// Does this stored row pass every supplied filter?
///
/// `action` and `outcome` match on **equality**, per canonical
/// `audit/list`. They previously matched on substring, which quietly
/// widened a query — asking for `action=vault.delete` also returned
/// `vault.delete_force` — so an operator reading the result could not
/// tell which rows they had actually asked for.
fn matches(params: &ListAuditLogsBody, entry: &AuditLogEntry) -> bool {
    if let Some(from) = params.from
        && (entry.timestamp as i64) < from.timestamp()
    {
        return false;
    }
    // Canonical: `to` is exclusive.
    if let Some(to) = params.to
        && (entry.timestamp as i64) >= to.timestamp()
    {
        return false;
    }
    if let Some(action) = &params.action
        && entry.action != *action
    {
        return false;
    }
    if let Some(actor) = &params.actor
        && entry.actor != *actor
    {
        return false;
    }
    if let Some(outcome) = &params.outcome
        && entry.outcome != *outcome
    {
        return false;
    }
    if let Some(ctx) = &params.context_id
        && entry.context_id.as_deref() != Some(ctx.as_str())
    {
        return false;
    }
    true
}

/// The bytes a cursor is bound to.
///
/// Canonical forbids changing the filters while paging — they are part
/// of the cursor's position — so they are folded into the cursor's
/// HMAC, and resuming under a different filter set fails verification.
/// The caller's DID is bound too, so a leaked cursor is not a
/// cross-principal read (canonical §"Cursor as a capability").
///
/// Length-prefixed so that `action="a&actor=b"` cannot collide with
/// `action="a", actor="b"`.
fn cursor_binding(params: &ListAuditLogsBody, caller_did: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |v: Option<&str>| {
        let bytes = v.unwrap_or("").as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(Some(caller_did));
    field(params.from.map(|t| t.to_rfc3339()).as_deref());
    field(params.to.map(|t| t.to_rfc3339()).as_deref());
    field(params.action.as_deref());
    field(params.actor.as_deref());
    field(params.outcome.as_deref());
    field(params.context_id.as_deref());
    out
}

/// Authorize an audit read.
///
/// The audit log is the whole agent's tail: it holds actor DIDs and
/// actions from **every** trust context. `require_admin` alone tests
/// only the role, so a context-scoped admin — an admin deliberately
/// confined to one context — could read every other context's
/// activity. Canonical states the gate directly: this is the tightest-
/// gated read a maintainer offers, and a context-scoped admin does not
/// qualify for the whole-log tail.
///
/// So: a super-admin reads anything; a scoped admin must name a
/// `contextId` inside their own scope, which the filter then confines
/// the results to.
///
/// Note this deliberately goes through `is_super_admin` /
/// `has_context_access` rather than testing `allowed_contexts`
/// directly — an empty context list means *unrestricted* for an admin
/// and *authorized nowhere* for every other role.
fn authorize(auth: &AuthClaims, params: &ListAuditLogsBody) -> Result<(), AppError> {
    auth.require_admin()?;

    if auth.is_super_admin() {
        return Ok(());
    }

    let Some(ctx) = params.context_id.as_deref() else {
        return Err(AppError::Forbidden(
            "reading the whole audit log requires an unrestricted admin; a context-scoped \
             admin must pass contextId to read that context's entries"
                .into(),
        ));
    };

    if !auth.has_context_access(ctx) {
        return Err(AppError::Forbidden(format!(
            "not authorized to read audit entries for context {ctx}"
        )));
    }

    Ok(())
}

/// List audit logs, newest first, with optional filters and opaque
/// cursor pagination — canonical `audit/list/0.1`.
/// Verify the audit log's chain, in storage order.
///
/// Reads ascending by key, which is write order, because the chain is a strict
/// left fold and verifying it in any other order reports breaks that are not
/// there.
pub use vta_sdk::protocols::audit_management::verify::{AuditChainBreak, AuditChainReport};

pub async fn verify_audit_chain(
    audit_ks: &vti_common::store::KeyspaceHandle,
) -> Result<AuditChainReport, AppError> {
    use vti_common::audit::envelope::{ChainBreak, ChainVerifier};

    let mut pairs = audit_ks.prefix_iter_raw("log:").await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b)); // ascending: write order

    // Retention deletes the oldest entries, so the oldest survivor points back
    // at something that is gone. Resuming from the sweep's watermark is what
    // tells an intact-but-pruned log apart from one an entry was removed from
    // — without it the two are the same failure.
    let watermark = vta_audit::prune_watermark(audit_ks).await?;
    let resumed = watermark.as_ref().and_then(|w| {
        let raw = hex::decode(&w.head).ok()?;
        let head: [u8; 32] = raw.try_into().ok()?;
        Some((head, w.pruned_entries))
    });
    let mut verifier = match resumed {
        Some((head, index)) => ChainVerifier::resume(head, index),
        None => ChainVerifier::new(),
    };
    let mut report = AuditChainReport {
        verified: true,
        rows_examined: pairs.len(),
        entries_verified: 0,
        pre_chain_rows: 0,
        unchained_after_open: 0,
        legacy_envelopes_skipped: 0,
        head: None,
        chain_break: None,
        resumed_from_prune: resumed.is_some(),
        pruned_entries: watermark.as_ref().map_or(0, |w| w.pruned_entries),
    };
    // A pruned log has no entry before the watermark, so the first survivor is
    // a continuation rather than an opening.
    let mut chain_opened = resumed.is_some();

    for (key, value) in &pairs {
        let env = match serde_json::from_slice::<vti_common::audit::AuditEnvelope>(value) {
            Ok(env) => env,
            Err(_) => {
                // Before the first envelope this is a row from before the
                // chain existed. After it, nothing this sink writes looks like
                // this, so something else put it there.
                if chain_opened {
                    report.unchained_after_open += 1;
                    tracing::warn!(
                        key = %String::from_utf8_lossy(key),
                        "audit row after the chain opened is not an envelope",
                    );
                } else {
                    report.pre_chain_rows += 1;
                }
                continue;
            }
        };
        chain_opened = true;

        if let Err(brk) = verifier.push(&env) {
            let (kind, index, event_id) = match brk {
                ChainBreak::TamperedEntry { index, event_id } => ("tamperedEntry", index, event_id),
                ChainBreak::BrokenLink { index, event_id } => ("brokenLink", index, event_id),
            };
            report.verified = false;
            report.chain_break = Some(AuditChainBreak {
                kind: kind.to_string(),
                index,
                event_id: event_id.to_string(),
            });
            break;
        }
    }

    report.entries_verified = verifier.verified();
    report.legacy_envelopes_skipped = verifier.skipped_legacy();
    report.head = verifier.head().map(hex::encode);
    Ok(report)
}

/// Read one stored row, in either shape the audit keyspace holds.
///
/// A VTA's audit keyspace holds rows written before the log was chained and
/// envelopes written since, under the same key format and interleaved by time.
/// A reader that knows only one shape does not fail loudly — it skips what it
/// cannot parse — so a reader that knew only the older shape would report a
/// log that stops at the moment chaining began.
fn read_row(value: &[u8]) -> Option<AuditLogEntry> {
    if let Ok(row) = serde_json::from_slice::<AuditLogEntry>(value) {
        return Some(row);
    }
    serde_json::from_slice::<vti_common::audit::AuditEnvelope>(value)
        .ok()
        .map(|env| flatten(&env))
}

/// An envelope in the shape the query and the response speak.
///
/// The actor is the plaintext where it is still there. A redacted row has
/// none, and the empty actor is the honest answer: the identifier was erased,
/// and what survives is a commitment that answers *was it this DID?* rather
/// than *who was it?* — which is what an erasure is supposed to leave behind.
fn flatten(env: &vti_common::audit::AuditEnvelope) -> AuditLogEntry {
    use vti_common::audit::event::AuditEvent;

    let (action, resource, outcome, channel, context_id, detail) = match &env.event {
        AuditEvent::VtaOperation(op) => (
            op.action.clone(),
            op.resource.clone(),
            op.outcome.clone(),
            op.channel.clone(),
            op.context_id.clone(),
            op.detail.clone(),
        ),
        other => (
            other.variant_name().to_string(),
            None,
            String::new(),
            None,
            None,
            None,
        ),
    };

    AuditLogEntry {
        id: env.event_id.to_string(),
        timestamp: u64::try_from(env.timestamp.timestamp()).unwrap_or(0),
        action,
        actor: env.actor_did_plain.clone().unwrap_or_default(),
        // A DID-shaped resource travels in the envelope's hashed members, so
        // it comes back from there rather than from the event.
        resource: resource.or_else(|| env.target_did_plain.clone()),
        outcome,
        channel,
        context_id,
        detail,
    }
}

pub async fn list_audit_logs(
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: &ListAuditLogsBody,
    _channel: &str,
) -> Result<ListAuditLogsResultBody, AppError> {
    authorize(auth, params)?;

    let limit = params
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_LIMIT as u64) as usize;

    let cursor_key = CursorKey::new(audit_ks.clone()).get().await?;
    let binding = cursor_binding(params, &auth.did);
    let resume_from = match &params.cursor {
        Some(wire) => Some(Cursor::decode_bound(wire, &cursor_key, &binding)?),
        None => None,
    };

    // The storage key is `log:{timestamp:020}:{uuid}`, so a
    // lexicographic walk is chronological and the key itself is a
    // stable cursor position — stable under concurrent appends in a
    // way an offset is not.
    //
    // This materialises the whole keyspace per page, as the offset
    // implementation it replaces also did — retention caps how large
    // that gets. The fix, when it is needed, is the cursor-aware
    // `prefix_iter_after` sketched in `vti_common::pagination`'s module
    // docs; it does not change the wire shape, because the cursor is
    // already the storage key this would seek to.
    let mut pairs = audit_ks.prefix_iter_raw("log:").await?;
    pairs.sort_by(|(a, _), (b, _)| b.cmp(a)); // newest first

    // Descending order means "the next page" is everything strictly
    // less than the last key already returned.
    let start = match &resume_from {
        Some(c) => pairs
            .iter()
            .position(|(k, _)| k.as_slice() < c.last_key.as_slice())
            .unwrap_or(pairs.len()),
        None => 0,
    };

    let mut entries: Vec<AuditEnvelope> = Vec::with_capacity(limit);
    let mut last_seen_key: Option<Vec<u8>> = None;
    let mut idx = start;
    while entries.len() < limit && idx < pairs.len() {
        let (key, value) = &pairs[idx];
        match read_row(value) {
            Some(row) => {
                if matches(params, &row) {
                    entries.push(AuditEnvelope::from(&row));
                    last_seen_key = Some(key.clone());
                }
            }
            None => {
                tracing::warn!(
                    key = %String::from_utf8_lossy(key),
                    "skipping unparseable audit row",
                );
            }
        }
        idx += 1;
    }

    // `truncated` must mean "more *matching* entries remain", not "more
    // rows remain": under a filter the tail may hold nothing that
    // matches, and handing back a cursor for an empty next page would
    // read as results being withheld. Scan ahead only as far as the
    // first further match.
    let mut more_matches = false;
    while idx < pairs.len() {
        if let Ok(row) = serde_json::from_slice::<AuditLogEntry>(&pairs[idx].1)
            && matches(params, &row)
        {
            more_matches = true;
            break;
        }
        idx += 1;
    }

    let cursor = if more_matches {
        last_seen_key
            .map(|k| Cursor::new(k, pairs.len() as u64).encode_bound(&cursor_key, &binding))
    } else {
        None
    };

    Ok(ListAuditLogsResultBody {
        entries,
        truncated: cursor.is_some(),
        cursor,
    })
}

/// Get the current audit retention period.
pub async fn get_retention(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    _channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_admin()?;
    let config = config.read().await;
    Ok(RetentionResultBody {
        retention_days: config.audit.retention_days,
    })
}

/// Update the audit retention period (super-admin only).
pub async fn update_retention(
    config: &Arc<RwLock<AppConfig>>,
    // The sink, not the keyspace: this only *writes* one row. Note that the
    // retention period it sets governs the keyspace, which an alternative sink
    // does not necessarily share — see `vta_audit::sink`.
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    retention_days: u32,
    channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_super_admin()?;

    if !(1..=365).contains(&retention_days) {
        return Err(AppError::Validation(
            "retention_days must be between 1 and 365".into(),
        ));
    }

    let (result, contents, path) = {
        let mut config = config.write().await;
        config.audit.retention_days = retention_days;
        let result = RetentionResultBody { retention_days };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Internal(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();
        (result, contents, path)
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;
    tracing::info!(channel, retention_days, "audit retention updated");
    audit!(
        "audit.retention_update",
        actor = &auth.did,
        resource = retention_days,
        outcome = "success"
    );
    let _ = audit::record(
        audit,
        "audit.retention_update",
        &auth.did,
        Some(&retention_days.to_string()),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod verify_tests_support {
    use vta_sdk::protocols::audit_management::list::AuditLogEntry;
    use vti_common::config::StoreConfig;
    use vti_common::store::{KeyspaceHandle, Store};

    pub(crate) fn keyspaces() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        (
            store.keyspace("audit").expect("audit"),
            store.keyspace("audit_key").expect("audit_key"),
            dir,
        )
    }

    pub(crate) fn entry(action: &str) -> AuditLogEntry {
        AuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: 1_700_000_000,
            action: action.to_string(),
            actor: "did:key:z6MkA".to_string(),
            resource: None,
            outcome: "success".to_string(),
            channel: None,
            context_id: None,
            detail: None,
        }
    }
}

#[cfg(test)]
mod verify_tests {
    use super::verify_tests_support::{entry, keyspaces};
    use super::*;
    use vta_audit::{AuditSink, ChainedKeyspaceAuditSink};

    /// A pre-chain row is expected and is not a finding: the VTA audited to
    /// this keyspace before its log was chained, and nothing committed to
    /// those rows at the time.
    #[tokio::test]
    async fn rows_written_before_the_chain_are_counted_not_faulted() {
        let (audit_ks, key_ks, _dir) = keyspaces();

        audit_ks
            .insert(
                format!(
                    "log:{:020}:11111111-1111-1111-1111-111111111111",
                    1_699_999_999u64
                ),
                &entry("auth.challenge"),
            )
            .await
            .expect("seed a pre-chain row");

        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);
        sink.record(&entry("acl.create")).await.expect("record");

        let report = verify_audit_chain(&audit_ks).await.expect("verify");

        assert!(report.verified, "the chain itself is intact");
        assert_eq!(report.pre_chain_rows, 1);
        assert_eq!(
            report.unchained_after_open, 0,
            "a row before the chain opened is not an insertion"
        );
        assert_eq!(
            report.entries_verified, 2,
            "the opening entry and the event"
        );
        assert!(report.head.is_some());
    }

    /// The same row after the chain has opened is a different fact. Nothing
    /// this sink writes looks like that, so something else put it there.
    #[tokio::test]
    async fn an_unchained_row_after_the_chain_opened_is_a_finding() {
        let (audit_ks, key_ks, _dir) = keyspaces();

        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);
        sink.record(&entry("acl.create")).await.expect("record");

        // Far in the future, so it sorts after everything the sink wrote.
        audit_ks
            .insert(
                format!(
                    "log:{:020}:22222222-2222-2222-2222-222222222222",
                    2_000_000_000u64
                ),
                &entry("acl.grant"),
            )
            .await
            .expect("insert a row the sink did not write");

        let report = verify_audit_chain(&audit_ks).await.expect("verify");

        assert_eq!(
            report.unchained_after_open, 1,
            "a non-envelope row after the chain opened is reported as a finding"
        );
        assert_eq!(report.pre_chain_rows, 0);
    }

    #[tokio::test]
    async fn a_tampered_entry_is_reported_with_where_it_broke() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);
        for i in 0..3 {
            sink.record(&entry(&format!("op.{i}")))
                .await
                .expect("record");
        }

        // Rewrite one entry's outcome in place, leaving its hashes alone.
        let pairs = audit_ks.prefix_iter_raw("log:").await.expect("scan");
        let (key, raw) = pairs
            .iter()
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .expect("a row");
        let mut env: vti_common::audit::AuditEnvelope =
            serde_json::from_slice(raw).expect("envelope");
        if let vti_common::audit::event::AuditEvent::VtaOperation(op) = &mut env.event {
            op.outcome = "failure".to_string();
        }
        audit_ks
            .insert(String::from_utf8(key.clone()).expect("utf8 key"), &env)
            .await
            .expect("rewrite the row");

        let report = verify_audit_chain(&audit_ks).await.expect("verify");

        assert!(!report.verified);
        let brk = report.chain_break.expect("a break is reported");
        assert_eq!(brk.kind, "tamperedEntry");
        assert_eq!(brk.event_id, env.event_id.to_string());
    }
}

#[cfg(test)]
mod retention_tests {
    use super::verify_tests_support::{entry, keyspaces};
    use super::*;
    use vta_audit::{AuditSink, ChainedKeyspaceAuditSink};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Retention and tamper-evidence have to coexist. A sweep deletes the
    /// oldest entries, so the oldest survivor points back at something that is
    /// gone — which is what a removed entry looks like. The watermark is what
    /// tells the two apart.
    #[tokio::test]
    async fn a_pruned_log_still_verifies() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);
        for i in 0..5 {
            sink.record(&entry(&format!("op.{i}")))
                .await
                .expect("record");
        }

        // A cutoff one second ahead of everything written so far, so the
        // sweep prunes all of it. Derived from `now`, the sweep's only
        // reachable boundaries in a test are a whole day ago and nothing.
        let cutoff = now_secs() + 1;
        let removed = vta_audit::cleanup_logs_before(&audit_ks, cutoff)
            .await
            .expect("sweep");
        assert!(removed > 0, "the sweep must actually have pruned something");

        sink.record(&entry("op.after-the-sweep"))
            .await
            .expect("record after sweep");

        let report = verify_audit_chain(&audit_ks).await.expect("verify");
        assert!(
            report.verified,
            "a pruned log must still verify: {:?}",
            report.chain_break
        );
        assert!(report.resumed_from_prune);
        assert_eq!(report.pruned_entries, removed as usize);
    }

    /// The watermark must not become a way to hide a removal. An entry taken
    /// out *after* the sweep still breaks the chain.
    #[tokio::test]
    async fn a_removal_after_the_sweep_is_still_caught() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);
        for i in 0..3 {
            sink.record(&entry(&format!("op.{i}")))
                .await
                .expect("record");
        }
        vta_audit::cleanup_logs_before(&audit_ks, now_secs() + 1)
            .await
            .expect("sweep");

        for i in 0..3 {
            sink.record(&entry(&format!("later.{i}")))
                .await
                .expect("record");
        }

        // Remove one of the survivors, which is exactly what the chain is for.
        let mut pairs = audit_ks.prefix_iter_raw("log:").await.expect("scan");
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        let victim = pairs[1].0.clone();
        audit_ks.remove(victim).await.expect("remove a survivor");

        let report = verify_audit_chain(&audit_ks).await.expect("verify");
        assert!(
            !report.verified,
            "removing an entry after the sweep must still break the chain"
        );
    }
}
