//! Pluggable telemetry sink for mediator-attribution events.
//!
//! Default impl is `RingBufferTelemetry` (in-memory, bounded). Other
//! backends (file rotation, append-only log, blockchain anchor, fjall
//! keyspace) can be added without changing call sites by implementing
//! `TelemetrySink`.
//!
//! This is intentionally separate from the `audit!` macro: the audit log
//! carries security-audit semantics (auth events, key operations) that
//! are append-only and durable, while this surface is higher-volume and
//! query-oriented for runtime reporting.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod ring;
pub use ring::RingBufferTelemetry;

#[async_trait]
pub trait TelemetrySink: Send + Sync {
    async fn record(&self, event: TelemetryEvent) -> Result<(), TelemetryError>;
    async fn query(&self, filter: &TelemetryFilter) -> Result<Vec<TelemetryEvent>, TelemetryError>;
}

pub type SharedTelemetrySink = Arc<dyn TelemetrySink>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub at: DateTime<Utc>,
    pub kind: TelemetryKind,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mediator_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sender_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message_type: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl TelemetryEvent {
    pub fn new(kind: TelemetryKind) -> Self {
        Self {
            at: Utc::now(),
            kind,
            mediator_did: None,
            sender_did: None,
            message_type: None,
            fields: serde_json::Map::new(),
        }
    }

    pub fn with_mediator(mut self, did: impl Into<String>) -> Self {
        self.mediator_did = Some(did.into());
        self
    }

    pub fn with_sender(mut self, did: impl Into<String>) -> Self {
        self.sender_did = Some(did.into());
        self
    }

    pub fn with_message_type(mut self, ty: impl Into<String>) -> Self {
        self.message_type = Some(ty.into());
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryKind {
    DidcommInbound,
    DidcommResponseDropped,
    MediatorHandshakeOk,
    MediatorHandshakeFailed,
    MediatorHandshakeBypassed,
    ServicesDidcommUpdate,
    MediatorDrainStart,
    MediatorDrainCancel,
    MediatorDrainExpire,
    ServicesDidcommEnable,
    ServicesDidcommDisable,
    ServicesRestEnable,
    ServicesRestUpdate,
    ServicesRestDisable,
    ServicesWebauthnEnable,
    ServicesWebauthnUpdate,
    ServicesWebauthnDisable,
    ServicesTspEnable,
    ServicesTspUpdate,
    ServicesTspDisable,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryFilter {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub kinds: Option<HashSet<TelemetryKind>>,
    pub mediator_did: Option<String>,
    pub sender_did: Option<String>,
}

impl TelemetryFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn since(mut self, t: DateTime<Utc>) -> Self {
        self.since = Some(t);
        self
    }

    pub fn until(mut self, t: DateTime<Utc>) -> Self {
        self.until = Some(t);
        self
    }

    pub fn kind(mut self, k: TelemetryKind) -> Self {
        self.kinds.get_or_insert_with(HashSet::new).insert(k);
        self
    }

    pub fn mediator(mut self, did: impl Into<String>) -> Self {
        self.mediator_did = Some(did.into());
        self
    }

    pub fn sender(mut self, did: impl Into<String>) -> Self {
        self.sender_did = Some(did.into());
        self
    }

    pub fn matches(&self, ev: &TelemetryEvent) -> bool {
        if let Some(t) = self.since
            && ev.at < t
        {
            return false;
        }
        if let Some(t) = self.until
            && ev.at > t
        {
            return false;
        }
        if let Some(ref ks) = self.kinds
            && !ks.contains(&ev.kind)
        {
            return false;
        }
        if let Some(ref m) = self.mediator_did
            && ev.mediator_did.as_deref() != Some(m.as_str())
        {
            return false;
        }
        if let Some(ref s) = self.sender_did
            && ev.sender_did.as_deref() != Some(s.as_str())
        {
            return false;
        }
        true
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry sink backend failed: {0}")]
    Backend(String),
}

#[cfg(test)]
mod swappability_tests {
    //! Spec criterion #17: a downstream impl of [`TelemetrySink`]
    //! must satisfy the same observable contract as
    //! [`RingBufferTelemetry`]. This module ships a minimal
    //! `Vec<Mutex<…>>` impl and runs a parametric test against
    //! both — proving the trait boundary holds.
    use super::*;
    use std::sync::Mutex;

    /// Stub [`TelemetrySink`] backed by an unbounded
    /// `Vec<TelemetryEvent>`. NOT used in production — exists only
    /// to prove `Arc<dyn TelemetrySink>` swappability.
    struct VecMutexSink {
        events: Mutex<Vec<TelemetryEvent>>,
    }

    impl VecMutexSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl TelemetrySink for VecMutexSink {
        async fn record(&self, event: TelemetryEvent) -> Result<(), TelemetryError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        async fn query(
            &self,
            filter: &TelemetryFilter,
        ) -> Result<Vec<TelemetryEvent>, TelemetryError> {
            let events = self.events.lock().unwrap();
            Ok(events
                .iter()
                .rev()
                .filter(|e| filter.matches(e))
                .cloned()
                .collect())
        }
    }

    /// Same scenario — different sink. Both impls must produce the
    /// same observable result for the same input.
    async fn exercise(sink: &dyn TelemetrySink) -> Vec<TelemetryEvent> {
        sink.record(
            TelemetryEvent::new(TelemetryKind::DidcommInbound)
                .with_mediator("did:m:A")
                .with_sender("did:peer:alice"),
        )
        .await
        .unwrap();
        sink.record(
            TelemetryEvent::new(TelemetryKind::ServicesDidcommUpdate).with_mediator("did:m:B"),
        )
        .await
        .unwrap();
        sink.record(
            TelemetryEvent::new(TelemetryKind::DidcommInbound)
                .with_mediator("did:m:B")
                .with_sender("did:peer:alice"),
        )
        .await
        .unwrap();
        sink.query(&TelemetryFilter::new().kind(TelemetryKind::DidcommInbound))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn ring_buffer_and_vec_mutex_produce_same_observable_results() {
        let ring = RingBufferTelemetry::new();
        let stub = VecMutexSink::new();
        let from_ring = exercise(&ring).await;
        let from_stub = exercise(&stub).await;
        // Both impls must surface the two DidcommInbound events
        // (filtered out of the three total recorded), in
        // newest-first order.
        assert_eq!(from_ring.len(), 2);
        assert_eq!(from_stub.len(), 2);
        for (a, b) in from_ring.iter().zip(from_stub.iter()) {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.mediator_did, b.mediator_did);
            assert_eq!(a.sender_did, b.sender_did);
        }
        // Order: newest first.
        assert_eq!(from_ring[0].mediator_did.as_deref(), Some("did:m:B"));
        assert_eq!(from_stub[0].mediator_did.as_deref(), Some("did:m:B"));
    }

    #[tokio::test]
    async fn arc_dyn_dispatch_swap_at_runtime() {
        let sinks: Vec<SharedTelemetrySink> = vec![
            Arc::new(RingBufferTelemetry::new()),
            Arc::new(VecMutexSink::new()),
        ];
        for sink in &sinks {
            sink.record(TelemetryEvent::new(TelemetryKind::DidcommInbound))
                .await
                .unwrap();
            let out = sink.query(&TelemetryFilter::new()).await.unwrap();
            assert_eq!(out.len(), 1);
        }
    }
}
