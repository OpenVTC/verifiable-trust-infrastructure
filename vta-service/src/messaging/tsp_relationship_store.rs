//! The VTA's durable TSP relationship store.
//!
//! The generic adapter (`KeyspaceRelationshipKv`), the concrete store type and
//! the boot-enumerate / idle-eviction maintenance loop now live in
//! [`vti_common::relationship_store`], shared with the VTC. This module
//! re-exports them under their historical VTA names and keeps the VTA-specific
//! §7.2.2 drop-counter telemetry (D8), which has no VTC counterpart.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::warn;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

pub use vti_common::relationship_store::{
    KeyspaceRelationshipKv, KeyspaceRelationshipStore as VtaRelationshipStore, maintenance_loop,
};

/// How often the §7.2.2 drop counter is sampled into telemetry.
const DROP_TELEMETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Sample the §7.2.2 relationship-gate drop counter into the telemetry sink
/// (design note `tsp-relationship-recovery.md`, D8).
///
/// `drop_counter` is the monotonic counter the SDK gate increments (injected via
/// `ATMConfigBuilder::with_relationship_drop_counter`). Each interval this records
/// a [`TelemetryKind::TspRelationshipDropped`] event carrying the number dropped
/// since the previous sample, so a spike is a queryable operational alarm — a
/// peer arriving whose relationship this VTA has lost — rather than a scatter of
/// error logs. Spawn once at server startup, alongside the maintenance loop.
pub async fn drop_telemetry_loop(drop_counter: Arc<AtomicU64>, telemetry: SharedTelemetrySink) {
    let mut ticker = tokio::time::interval(DROP_TELEMETRY_INTERVAL);
    let mut last = 0u64;
    loop {
        ticker.tick().await;
        let total = drop_counter.load(Ordering::Relaxed);
        let delta = total.saturating_sub(last);
        last = total;
        if delta == 0 {
            continue;
        }
        let event = TelemetryEvent::new(TelemetryKind::TspRelationshipDropped)
            .with_field("count", serde_json::json!(delta));
        if let Err(e) = telemetry.record(event).await {
            warn!(error = %e, "could not record TSP relationship-drop telemetry");
        }
    }
}
