//! Drain TTL sweeper.
//!
//! Holds one `tokio` task per draining mediator, each
//! `sleep_until(drains_until)` then signals the consumer (typically
//! the live `DIDCommService` owner) to tear the listener down.
//!
//! The sweeper does not know about `DIDCommService` directly. When a
//! drain fires, it:
//! 1. Calls
//!    [`MediatorListenerRegistry::record_expiries_persisted`] to
//!    drop the in-memory drain entry, remove it from the keyspace,
//!    and emit [`vti_common::telemetry::TelemetryKind::MediatorDrainExpire`].
//! 2. Sends the mediator DID over a `tokio::sync::mpsc` channel so
//!    whoever owns the delivery-layer service (the server bootstrap)
//!    can call `MessagingService::remove_transport` to drop the
//!    drained mediator's transport.
//!
//! This keeps the sweeper deterministically testable without standing
//! up the full DIDComm stack.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::error::AppError;
use crate::messaging::registry::{DrainEntry, MediatorListenerRegistry};
use crate::store::KeyspaceHandle;

/// One end of the teardown channel — the sweeper's view.
pub type TeardownSender = mpsc::Sender<String>;
/// The other end — the live `DIDCommService` owner consumes from this.
pub type TeardownReceiver = mpsc::Receiver<String>;

/// Reasonable default for the teardown channel capacity. The
/// channel only carries DID strings on TTL expiry, which is rare —
/// 64 is plenty.
pub const DEFAULT_TEARDOWN_CHANNEL_CAPACITY: usize = 64;

pub fn teardown_channel(capacity: usize) -> (TeardownSender, TeardownReceiver) {
    mpsc::channel(capacity)
}

/// Per-mediator TTL sweeper.
pub struct DrainSweeper {
    registry: Arc<MediatorListenerRegistry>,
    keyspace: KeyspaceHandle,
    teardown_tx: TeardownSender,
    tasks: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

impl DrainSweeper {
    pub fn new(
        registry: Arc<MediatorListenerRegistry>,
        keyspace: KeyspaceHandle,
        teardown_tx: TeardownSender,
    ) -> Self {
        Self {
            registry,
            keyspace,
            teardown_tx,
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Schedule a sweep for the named mediator at the given
    /// deadline. If a sweep was already scheduled for this mediator,
    /// it is aborted and replaced.
    pub async fn arm(&self, mediator_did: &str, drains_until: DateTime<Utc>) {
        let mut tasks = self.tasks.lock().await;
        if let Some(prev) = tasks.remove(mediator_did) {
            prev.abort();
        }
        let task = spawn_sweeper_task(
            mediator_did.to_string(),
            drains_until,
            Arc::clone(&self.registry),
            self.keyspace.clone(),
            self.teardown_tx.clone(),
            Arc::clone(&self.tasks),
        );
        tasks.insert(mediator_did.to_string(), task);
    }

    /// Cancel a scheduled sweep without firing it. Returns true if a
    /// task was active and aborted.
    pub async fn disarm(&self, mediator_did: &str) -> bool {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.remove(mediator_did) {
            task.abort();
            true
        } else {
            false
        }
    }

    /// Re-arm sweeps for every live drain in `entries`. Used at boot
    /// after [`MediatorListenerRegistry::replay_drains`] returns.
    pub async fn arm_all(&self, entries: &[DrainEntry]) {
        for entry in entries {
            self.arm(&entry.mediator_did, entry.drains_until).await;
        }
    }

    pub async fn armed_count(&self) -> usize {
        self.tasks.lock().await.len()
    }
}

fn spawn_sweeper_task(
    mediator_did: String,
    drains_until: DateTime<Utc>,
    registry: Arc<MediatorListenerRegistry>,
    keyspace: KeyspaceHandle,
    teardown_tx: TeardownSender,
    tasks: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        sleep_until_chrono(drains_until).await;
        if let Err(e) = fire_expiry(&registry, &keyspace, &teardown_tx).await {
            tracing::warn!(
                mediator = %mediator_did,
                error = %e,
                "drain sweeper: expiry handling failed"
            );
        }
        tasks.lock().await.remove(&mediator_did);
    })
}

async fn sleep_until_chrono(deadline: DateTime<Utc>) {
    let now = Utc::now();
    if deadline <= now {
        return;
    }
    let delta = deadline - now;
    let std_dur = match delta.to_std() {
        Ok(d) => d,
        // delta is negative (we just checked it's > 0) — defensive fallback.
        Err(_) => return,
    };
    tokio::time::sleep(std_dur).await;
}

async fn fire_expiry(
    registry: &MediatorListenerRegistry,
    keyspace: &KeyspaceHandle,
    teardown_tx: &TeardownSender,
) -> Result<(), AppError> {
    // The sweep is keyed on a single mediator's deadline; calling
    // `record_expiries_persisted` does a global sweep and naturally
    // includes any other entries whose deadlines have also passed.
    // That's harmless and saves a separate code path.
    let dropped = registry
        .record_expiries_persisted(keyspace, Utc::now())
        .await
        .map_err(|e| AppError::Internal(format!("drain expire failed: {e}")))?;

    for entry in dropped {
        // Best-effort: if the receiver has been closed (server shut
        // down), drop the message silently; the drain entry is
        // already gone from in-memory + keyspace.
        let _ = teardown_tx.send(entry.mediator_did).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::drain_store::{self, PersistedDrainEntry};
    use crate::store::Store;
    use chrono::Duration;
    use tempfile::tempdir;
    use vti_common::config::StoreConfig;
    use vti_common::telemetry::{
        RingBufferTelemetry, SharedTelemetrySink, TelemetryFilter, TelemetryKind,
    };

    async fn fresh_keyspace() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::DRAINS).unwrap();
        (dir, ks)
    }

    fn telemetry() -> SharedTelemetrySink {
        Arc::new(RingBufferTelemetry::with_capacity(64))
    }

    #[tokio::test]
    async fn arm_fires_at_deadline_and_signals_teardown() {
        let (_d, ks) = fresh_keyspace().await;
        let sink = telemetry();
        let reg = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        // Set up an active mediator and a drain so the registry has
        // a valid entry to expire.
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:B".into(),
            endpoint: "wss://B".into(),
        })
        .await;
        let deadline = Utc::now() + Duration::milliseconds(50);
        reg.record_drain("did:m:A", "wss://A".into(), deadline)
            .await
            .unwrap();
        // Mirror the in-memory state on disk.
        drain_store::store_drain(
            &ks,
            &PersistedDrainEntry {
                mediator_did: "did:m:A".into(),
                endpoint: "wss://A".into(),
                drains_until: deadline,
            },
        )
        .await
        .unwrap();

        let (tx, mut rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&reg), ks.clone(), tx);
        sweeper.arm("did:m:A", deadline).await;
        assert_eq!(sweeper.armed_count().await, 1);

        // Wait for the sweeper to fire.
        let signalled = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("teardown signal must arrive within timeout")
            .expect("channel closed unexpectedly");
        assert_eq!(signalled, "did:m:A");
        assert_eq!(reg.drain_count().await, 0);
        assert!(drain_store::list_drains(&ks).await.unwrap().is_empty());

        // Telemetry: a MediatorDrainExpire event must be present.
        let events = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::MediatorDrainExpire))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mediator_did.as_deref(), Some("did:m:A"));

        // Self-deregistration: the sweeper drops its own task entry.
        // Allow a short tick for the spawned task to remove itself.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(sweeper.armed_count().await, 0);
    }

    #[tokio::test]
    async fn disarm_aborts_pending_sweep() {
        let (_d, ks) = fresh_keyspace().await;
        let sink = telemetry();
        let reg = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:B".into(),
            endpoint: "wss://B".into(),
        })
        .await;
        let deadline = Utc::now() + Duration::seconds(60);
        reg.record_drain("did:m:A", "wss://A".into(), deadline)
            .await
            .unwrap();

        let (tx, mut rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&reg), ks, tx);
        sweeper.arm("did:m:A", deadline).await;
        let was_armed = sweeper.disarm("did:m:A").await;
        assert!(was_armed);
        assert_eq!(sweeper.armed_count().await, 0);

        // No teardown signal should arrive.
        let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "teardown channel must remain idle");
    }

    #[tokio::test]
    async fn disarm_unknown_mediator_returns_false() {
        let (_d, ks) = fresh_keyspace().await;
        let reg = Arc::new(MediatorListenerRegistry::new(telemetry()));
        let (tx, _rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(reg, ks, tx);
        assert!(!sweeper.disarm("did:m:unknown").await);
    }

    #[tokio::test]
    async fn arm_replaces_previous_task() {
        let (_d, ks) = fresh_keyspace().await;
        let sink = telemetry();
        let reg = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:B".into(),
            endpoint: "wss://B".into(),
        })
        .await;
        let far = Utc::now() + Duration::seconds(60);
        reg.record_drain("did:m:A", "wss://A".into(), far)
            .await
            .unwrap();

        let (tx, _rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&reg), ks, tx);
        sweeper.arm("did:m:A", far).await;
        sweeper
            .arm("did:m:A", Utc::now() + Duration::seconds(120))
            .await;
        assert_eq!(
            sweeper.armed_count().await,
            1,
            "second arm replaces the first"
        );
    }

    #[tokio::test]
    async fn arm_all_replays_multiple_entries() {
        let (_d, ks) = fresh_keyspace().await;
        let reg = Arc::new(MediatorListenerRegistry::new(telemetry()));
        // The replay path doesn't require the registry to be aware
        // of these entries — it just hands a slice to `arm_all`.
        let entries = vec![
            DrainEntry {
                mediator_did: "did:m:A".into(),
                endpoint: "wss://A".into(),
                drains_until: Utc::now() + Duration::seconds(60),
                generation: 1,
            },
            DrainEntry {
                mediator_did: "did:m:B".into(),
                endpoint: "wss://B".into(),
                drains_until: Utc::now() + Duration::seconds(120),
                generation: 2,
            },
        ];

        let (tx, _rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&reg), ks, tx);
        sweeper.arm_all(&entries).await;
        assert_eq!(sweeper.armed_count().await, 2);
    }

    #[tokio::test]
    async fn deadline_already_passed_fires_immediately() {
        let (_d, ks) = fresh_keyspace().await;
        let sink = telemetry();
        let reg = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(crate::messaging::registry::MediatorBinding {
            mediator_did: "did:m:B".into(),
            endpoint: "wss://B".into(),
        })
        .await;
        let past = Utc::now() - Duration::seconds(10);
        reg.record_drain("did:m:A", "wss://A".into(), past)
            .await
            .unwrap();
        drain_store::store_drain(
            &ks,
            &PersistedDrainEntry {
                mediator_did: "did:m:A".into(),
                endpoint: "wss://A".into(),
                drains_until: past,
            },
        )
        .await
        .unwrap();

        let (tx, mut rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&reg), ks, tx);
        sweeper.arm("did:m:A", past).await;

        let signalled = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("immediate fire expected for past deadline")
            .expect("channel closed");
        assert_eq!(signalled, "did:m:A");
    }
}
