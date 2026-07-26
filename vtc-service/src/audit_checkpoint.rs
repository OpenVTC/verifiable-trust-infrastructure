//! Emitting and verifying signed audit checkpoints (#708).
//!
//! The type, its signature scheme, and the threat model live in
//! [`vti_common::audit::checkpoint`]. This module is the VTC-side wiring: the
//! periodic emitter that signs checkpoints with the community key, and the
//! verifier that measures the live audit log against the newest one.
//!
//! # Cadence
//!
//! **Time-based, default 15 minutes, configurable via
//! `[audit_checkpoints] interval_secs`.** The interval is the attacker's free
//! truncation window, so it sets the residual risk directly: entries written
//! after the last checkpoint are covered by the (unkeyed, forgeable) hash
//! chain but by no signature, and can still be truncated without detection.
//! `GET /v1/audit/verify` reports that tail as `unattestedEntries` rather than
//! leaving it implicit.
//!
//! Count-based triggering ("also checkpoint every N entries") was considered
//! and **deliberately not implemented**. Doing it honestly needs a running
//! entry counter maintained by `AuditWriter` in `vti-common`; approximating it
//! by polling more often would mean walking the whole audit keyspace every
//! poll, which is O(log size) work on a timer. A shorter interval is the
//! cheaper knob for a busy community, and it bounds the window in *time*
//! regardless of traffic — which is the property an incident responder
//! actually reasons about. Revisit if the counter lands.
//!
//! A tick with no new entries emits nothing: a quiet community should not
//! accumulate identical checkpoints.

use std::time::Duration;

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use vti_common::audit::{
    AuditCheckpoint, AuditEnvelope, CheckpointAudit, CheckpointClaim, GENESIS_HASH,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Signed-checkpoint settings, mounted at `[audit_checkpoints]`.
///
/// Deliberately **not** named `AuditConfig`: `vti_common::config::AuditConfig`
/// already exists (the VTA's audit *retention* settings). Two same-named
/// config types one crate apart is how an operator ends up editing the wrong
/// section, so this one says what it configures.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AuditCheckpointConfig {
    /// How often to sign a checkpoint, in seconds. `0` disables
    /// checkpointing entirely (the log keeps its unkeyed hash chain and
    /// nothing more).
    ///
    /// Clamped to a 60s floor when non-zero: each emission walks the audit
    /// keyspace, so a very short interval turns tamper-evidence into a
    /// self-inflicted load problem.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
}

fn default_interval_secs() -> u64 {
    900 // 15 minutes
}

impl Default for AuditCheckpointConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval_secs(),
        }
    }
}

/// The audit chain's current state, as measured by walking the keyspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// `entry_hash` of the newest chainable envelope.
    pub head: [u8; 32],
    /// `event_id` of that envelope.
    pub head_event_id: Uuid,
    /// Count of **chainable** (v2+) envelopes. Pre-v2 rows are excluded
    /// because the verifier skips them — counting them would make the
    /// attested number disagree with what a recount can produce.
    pub entry_count: u64,
}

impl ChainState {
    /// The state of an empty (or entirely pre-v2) log.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            head: GENESIS_HASH,
            head_event_id: Uuid::nil(),
            entry_count: 0,
        }
    }
}

/// Walk the audit keyspace in ascending (chronological) key order and measure
/// the chain.
///
/// O(log size). Called once per checkpoint interval and once per
/// `GET /v1/audit/verify`, matching what that endpoint already does. A
/// persisted head pointer would make this O(1); the checkpoint keyspace is the
/// natural place for one, and is a follow-up rather than a prerequisite.
///
/// Unparseable rows are counted, not fatal — one corrupt row must not stop the
/// daemon from checkpointing everything around it. They are reported so the
/// finding is visible.
pub async fn measure_chain(audit_ks: &KeyspaceHandle) -> Result<(ChainState, usize), AppError> {
    let mut pairs = audit_ks.prefix_iter_raw(Vec::new()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut state = ChainState::empty();
    let mut unparseable = 0usize;
    for (key, value) in &pairs {
        match serde_json::from_slice::<AuditEnvelope>(value) {
            Ok(env) => {
                if env.schema_version < 2 {
                    continue; // unchainable; the verifier skips these too
                }
                state.head = env.entry_hash;
                state.head_event_id = env.event_id;
                state.entry_count += 1;
            }
            Err(err) => {
                unparseable += 1;
                warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(key),
                    "skipping unparseable audit envelope while measuring the chain",
                );
            }
        }
    }
    Ok((state, unparseable))
}

/// Load every checkpoint in ascending (chronological) order.
pub async fn load_checkpoints(
    checkpoint_ks: &KeyspaceHandle,
) -> Result<Vec<AuditCheckpoint>, AppError> {
    let mut pairs = checkpoint_ks.prefix_iter_raw(Vec::new()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut out = Vec::with_capacity(pairs.len());
    for (key, value) in &pairs {
        match serde_json::from_slice::<AuditCheckpoint>(value) {
            Ok(cp) => out.push(cp),
            Err(err) => {
                // Deliberately an error, not a skip. An unparseable checkpoint
                // is not like an unparseable audit row: checkpoints are the
                // thing being trusted, so silently dropping one would let an
                // adversary erase an inconvenient attestation by corrupting it.
                return Err(AppError::Internal(format!(
                    "unparseable audit checkpoint at {}: {err}",
                    String::from_utf8_lossy(key)
                )));
            }
        }
    }
    Ok(out)
}

/// Sign and persist a checkpoint for the audit log's current state, unless
/// nothing has been written since the last one.
///
/// Returns the new checkpoint, or `None` when there was nothing new to attest.
pub async fn emit_checkpoint(
    audit_ks: &KeyspaceHandle,
    checkpoint_ks: &KeyspaceHandle,
    signing_key: &SigningKey,
    verification_method: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuditCheckpoint>, AppError> {
    let (state, _unparseable) = measure_chain(audit_ks).await?;
    let existing = load_checkpoints(checkpoint_ks).await?;
    let previous = existing.last();

    // Nothing new: a quiet community should not accumulate a checkpoint per
    // tick, each attesting to exactly the same head.
    if let Some(prev) = previous
        && prev.entry_count == state.entry_count
        && prev.head == state.head
    {
        return Ok(None);
    }

    // Never sign a claim that contradicts one we already signed. If the live
    // log holds fewer entries than the last checkpoint attests to, something
    // has already gone wrong — emitting a lower count would launder the
    // truncation into a freshly-signed "this is fine".
    if let Some(prev) = previous
        && state.entry_count < prev.entry_count
    {
        return Err(AppError::Internal(format!(
            "refusing to checkpoint: audit log holds {} chainable entries but the last \
             checkpoint attests to {}. This is the truncation signature — investigate \
             before checkpointing again.",
            state.entry_count, prev.entry_count
        )));
    }

    let claim = CheckpointClaim {
        checkpoint_id: Uuid::new_v4(),
        head: state.head,
        entry_count: state.entry_count,
        head_event_id: state.head_event_id,
        checkpoint_at: now,
        prev_checkpoint: previous.map(AuditCheckpoint::link_hash),
        verification_method: verification_method.to_string(),
    };
    let checkpoint = AuditCheckpoint::sign(claim, signing_key);

    checkpoint_ks
        .insert(checkpoint.storage_key(), &checkpoint)
        .await?;

    info!(
        entry_count = checkpoint.entry_count,
        checkpoint_id = %checkpoint.checkpoint_id,
        "signed audit checkpoint",
    );
    Ok(Some(checkpoint))
}

/// Measure the live audit log against the newest signed checkpoint.
///
/// `newest` is the last checkpoint from a **already-verified** chain — call
/// [`vti_common::audit::verify_checkpoints`] first. Passing an unverified
/// checkpoint here measures the log against something an adversary may have
/// written, which proves nothing.
pub async fn audit_against_checkpoint(
    audit_ks: &KeyspaceHandle,
    newest: Option<&AuditCheckpoint>,
    state: &ChainState,
) -> Result<CheckpointAudit, AppError> {
    let Some(cp) = newest else {
        return Ok(CheckpointAudit::NoCheckpoints);
    };

    // The finding this whole mechanism exists for. Checked before the head
    // lookup because it is the cheaper and more serious signal: a truncation
    // that removed the head envelope would otherwise surface as the vaguer
    // `HeadMismatch`.
    if state.entry_count < cp.entry_count {
        return Ok(CheckpointAudit::Truncated {
            attested: cp.entry_count,
            found: state.entry_count,
        });
    }

    // The attested anchor must still be present and unaltered. A genesis
    // checkpoint (empty log at the time) has no anchor to find.
    if cp.head != GENESIS_HASH {
        let found = find_entry_hash(audit_ks, cp.head_event_id).await?;
        match found {
            Some(hash) if hash == cp.head => {}
            other => {
                return Ok(CheckpointAudit::HeadMismatch {
                    head_event_id: cp.head_event_id,
                    found: other.is_some(),
                });
            }
        }
    }

    Ok(CheckpointAudit::Consistent {
        checkpoint_at: cp.checkpoint_at,
        attested_entries: cp.entry_count,
        unattested_entries: state.entry_count.saturating_sub(cp.entry_count),
    })
}

/// The `entry_hash` of the envelope with `event_id`, if it is still there.
///
/// The audit keyspace is keyed by `<timestamp>:<event_id>`, so there is no
/// direct lookup by id alone — this scans. Called once per verify request,
/// alongside a walk that is already O(n).
async fn find_entry_hash(
    audit_ks: &KeyspaceHandle,
    event_id: Uuid,
) -> Result<Option<[u8; 32]>, AppError> {
    let pairs = audit_ks.prefix_iter_raw(Vec::new()).await?;
    for (_key, value) in &pairs {
        if let Ok(env) = serde_json::from_slice::<AuditEnvelope>(value)
            && env.event_id == event_id
        {
            return Ok(Some(env.entry_hash));
        }
    }
    Ok(None)
}

/// Periodic checkpoint emitter, spawned at boot alongside the other
/// background tasks.
pub struct CheckpointEmitter;

impl CheckpointEmitter {
    /// Spawn the emitter. Returns `None` — without spawning — when
    /// checkpointing is disabled (`checkpoint_interval_secs = 0`).
    pub fn spawn(
        audit_ks: KeyspaceHandle,
        checkpoint_ks: KeyspaceHandle,
        signing_key: SigningKey,
        verification_method: String,
        config: AuditCheckpointConfig,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if config.interval_secs == 0 {
            warn!(
                "audit checkpointing is DISABLED (interval_secs = 0). The audit \
                 chain is unkeyed, so a store-level adversary can truncate or restamp it \
                 undetectably."
            );
            return None;
        }
        let interval = Duration::from_secs(config.interval_secs.max(60));

        Some(tokio::spawn(async move {
            info!(
                interval_secs = interval.as_secs(),
                "audit checkpoint emitter started"
            );
            // Checkpoint once at startup so a restart immediately re-anchors
            // whatever was written while the daemon was down, rather than
            // leaving that span unattested until the first tick.
            emit_and_log(
                &audit_ks,
                &checkpoint_ks,
                &signing_key,
                &verification_method,
            )
            .await;

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        // Final checkpoint on the way out: a clean shutdown
                        // should not leave its last span of entries unsigned.
                        emit_and_log(
                            &audit_ks,
                            &checkpoint_ks,
                            &signing_key,
                            &verification_method,
                        )
                        .await;
                        info!("audit checkpoint emitter shutting down");
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {
                        emit_and_log(
                            &audit_ks,
                            &checkpoint_ks,
                            &signing_key,
                            &verification_method,
                        )
                        .await;
                    }
                }
            }
        }))
    }
}

async fn emit_and_log(
    audit_ks: &KeyspaceHandle,
    checkpoint_ks: &KeyspaceHandle,
    signing_key: &SigningKey,
    verification_method: &str,
) {
    match emit_checkpoint(
        audit_ks,
        checkpoint_ks,
        signing_key,
        verification_method,
        Utc::now(),
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {}
        // WARN, not debug: a checkpoint that silently stops being emitted
        // leaves the log unattested while `verify` keeps reporting the last
        // good checkpoint as consistent.
        Err(e) => warn!(error = %e, "failed to emit audit checkpoint"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::audit::verify_checkpoints;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    const VM: &str = "did:webvh:scid:vtc.example#key-0";

    async fn ks(name: &str) -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let handle = store.keyspace(name).expect("keyspace");
        (handle, dir)
    }

    #[tokio::test]
    async fn an_empty_log_measures_as_genesis() {
        let (audit, _d) = ks("audit").await;
        let (state, unparseable) = measure_chain(&audit).await.expect("measure");
        assert_eq!(state, ChainState::empty());
        assert_eq!(unparseable, 0);
    }

    #[tokio::test]
    async fn a_checkpoint_over_an_empty_log_verifies_and_reports_no_truncation() {
        let (audit, _d1) = ks("audit").await;
        let (cps, _d2) = ks("audit_checkpoint").await;

        let cp = emit_checkpoint(&audit, &cps, &key(), VM, Utc::now())
            .await
            .expect("emit")
            .expect("a first checkpoint is emitted even for an empty log");
        assert_eq!(cp.entry_count, 0);

        let loaded = load_checkpoints(&cps).await.expect("load");
        let pk = key().verifying_key().to_bytes().to_vec();
        let newest = verify_checkpoints(&loaded, |_| Some(pk.clone())).expect("verifies");

        let (state, _) = measure_chain(&audit).await.expect("measure");
        let audit_result = audit_against_checkpoint(&audit, newest, &state)
            .await
            .expect("audit");
        assert!(matches!(
            audit_result,
            CheckpointAudit::Consistent {
                attested_entries: 0,
                unattested_entries: 0,
                ..
            }
        ));
    }

    /// A quiet community must not accumulate an identical checkpoint per tick.
    #[tokio::test]
    async fn a_second_tick_with_no_new_entries_emits_nothing() {
        let (audit, _d1) = ks("audit").await;
        let (cps, _d2) = ks("audit_checkpoint").await;

        assert!(
            emit_checkpoint(&audit, &cps, &key(), VM, Utc::now())
                .await
                .expect("first")
                .is_some()
        );
        assert!(
            emit_checkpoint(&audit, &cps, &key(), VM, Utc::now())
                .await
                .expect("second")
                .is_none(),
            "nothing was written between ticks",
        );
        assert_eq!(load_checkpoints(&cps).await.expect("load").len(), 1);
    }

    /// The emitter must not launder a truncation into a freshly-signed lower
    /// count — that would destroy the evidence it exists to preserve.
    #[tokio::test]
    async fn emitting_refuses_when_the_log_shrank_below_a_signed_checkpoint() {
        let (audit, _d1) = ks("audit").await;
        let (cps, _d2) = ks("audit_checkpoint").await;

        // Hand-place a checkpoint attesting to 5 entries over an empty log.
        let claim = CheckpointClaim {
            checkpoint_id: Uuid::new_v4(),
            head: [3u8; 32],
            entry_count: 5,
            head_event_id: Uuid::new_v4(),
            checkpoint_at: Utc::now(),
            prev_checkpoint: None,
            verification_method: VM.to_string(),
        };
        let cp = AuditCheckpoint::sign(claim, &key());
        cps.insert(cp.storage_key(), &cp).await.expect("insert");

        let err = emit_checkpoint(&audit, &cps, &key(), VM, Utc::now())
            .await
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("truncation"),
            "the error must name the finding: {err}"
        );
    }

    /// The core detection: a log shorter than its signed checkpoint claims.
    #[tokio::test]
    async fn a_shortened_log_reports_truncation() {
        let (audit, _d1) = ks("audit").await;

        let claim = CheckpointClaim {
            checkpoint_id: Uuid::new_v4(),
            head: [3u8; 32],
            entry_count: 100,
            head_event_id: Uuid::new_v4(),
            checkpoint_at: Utc::now(),
            prev_checkpoint: None,
            verification_method: VM.to_string(),
        };
        let cp = AuditCheckpoint::sign(claim, &key());

        let state = ChainState {
            head: [9u8; 32],
            head_event_id: Uuid::new_v4(),
            entry_count: 12,
        };
        let result = audit_against_checkpoint(&audit, Some(&cp), &state)
            .await
            .expect("audit");
        assert_eq!(
            result,
            CheckpointAudit::Truncated {
                attested: 100,
                found: 12
            }
        );
    }

    /// The head envelope is gone (or rewritten) even though the count still
    /// adds up — e.g. an entry was swapped rather than removed.
    #[tokio::test]
    async fn a_missing_head_envelope_is_reported() {
        let (audit, _d1) = ks("audit").await;

        let head_event_id = Uuid::new_v4();
        let claim = CheckpointClaim {
            checkpoint_id: Uuid::new_v4(),
            head: [3u8; 32],
            entry_count: 1,
            head_event_id,
            checkpoint_at: Utc::now(),
            prev_checkpoint: None,
            verification_method: VM.to_string(),
        };
        let cp = AuditCheckpoint::sign(claim, &key());

        let state = ChainState {
            head: [9u8; 32],
            head_event_id: Uuid::new_v4(),
            entry_count: 1,
        };
        let result = audit_against_checkpoint(&audit, Some(&cp), &state)
            .await
            .expect("audit");
        assert_eq!(
            result,
            CheckpointAudit::HeadMismatch {
                head_event_id,
                found: false
            }
        );
    }

    #[tokio::test]
    async fn no_checkpoints_is_reported_as_such_not_as_success() {
        let (audit, _d1) = ks("audit").await;
        let state = ChainState::empty();
        assert_eq!(
            audit_against_checkpoint(&audit, None, &state)
                .await
                .expect("audit"),
            CheckpointAudit::NoCheckpoints
        );
    }

    /// A corrupt checkpoint must fail loudly — silently skipping it would let
    /// an adversary erase an inconvenient attestation by corrupting the row.
    #[tokio::test]
    async fn an_unparseable_checkpoint_is_an_error_not_a_skip() {
        let (cps, _d) = ks("audit_checkpoint").await;
        cps.insert(
            b"2026-07-25T10:00:00Z:garbage".to_vec(),
            &"not a checkpoint",
        )
        .await
        .expect("insert");
        assert!(load_checkpoints(&cps).await.is_err());
    }

    #[test]
    fn disabled_config_is_representable_and_the_default_is_not_disabled() {
        assert_eq!(AuditCheckpointConfig::default().interval_secs, 900);
        let disabled = AuditCheckpointConfig { interval_secs: 0 };
        assert_eq!(disabled.interval_secs, 0);
    }
}
