//! `mediator report` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! success criterion #9.
//!
//! Queries the [`vti_common::telemetry::TelemetrySink`] for inbound
//! DIDComm message events in a time window and returns:
//! - per-mediator inbound message counts + first/last-seen
//!   timestamps,
//! - per-sender last-seen mediator (so the operator can spot
//!   senders still using the prior mediator after a migrate).
//!
//! Read-only; does not take `PROTOCOL_LOCK`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use vti_common::telemetry::{
    SharedTelemetrySink, TelemetryError, TelemetryEvent, TelemetryFilter, TelemetryKind,
};

use crate::auth::AuthClaims;

#[derive(Debug, Clone)]
pub struct ReportParams {
    /// Lower bound on event timestamp. `None` = no lower bound.
    pub since: Option<DateTime<Utc>>,
    /// Upper bound. `None` = no upper bound (defaults to "now").
    pub until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MediatorStats {
    pub mediator_did: String,
    pub inbound_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SenderLastSeen {
    pub sender_did: String,
    pub last_seen_mediator: String,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MediatorReport {
    pub since: Option<DateTime<Utc>>,
    pub until: DateTime<Utc>,
    pub mediators: Vec<MediatorStats>,
    pub senders: Vec<SenderLastSeen>,
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("auth: {0}")]
    Auth(String),
    #[error("telemetry query failed: {0}")]
    Telemetry(#[from] TelemetryError),
}

pub async fn mediator_report(
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    params: ReportParams,
) -> Result<MediatorReport, ReportError> {
    auth.require_super_admin()
        .map_err(|e| ReportError::Auth(e.to_string()))?;

    // Apply `until` only when explicitly provided. The response
    // reports the wall-clock query time so consumers know when the
    // snapshot was taken — but the filter doesn't paper over
    // events that are slightly future-dated due to clock skew.
    let mut filter = TelemetryFilter::new().kind(TelemetryKind::DidcommInbound);
    if let Some(t) = params.since {
        filter = filter.since(t);
    }
    if let Some(t) = params.until {
        filter = filter.until(t);
    }
    let events = telemetry.query(&filter).await?;
    let (mediators, senders) = aggregate(&events);
    Ok(MediatorReport {
        since: params.since,
        until: params.until.unwrap_or_else(Utc::now),
        mediators,
        senders,
    })
}

/// Pure aggregation logic — public for unit-testability.
pub fn aggregate(events: &[TelemetryEvent]) -> (Vec<MediatorStats>, Vec<SenderLastSeen>) {
    let mut by_mediator: HashMap<String, MediatorStats> = HashMap::new();
    let mut by_sender: HashMap<String, SenderLastSeen> = HashMap::new();

    for ev in events {
        let Some(ref mediator) = ev.mediator_did else {
            continue;
        };
        by_mediator
            .entry(mediator.clone())
            .and_modify(|s| {
                s.inbound_count += 1;
                if ev.at < s.first_seen {
                    s.first_seen = ev.at;
                }
                if ev.at > s.last_seen {
                    s.last_seen = ev.at;
                }
            })
            .or_insert_with(|| MediatorStats {
                mediator_did: mediator.clone(),
                inbound_count: 1,
                first_seen: ev.at,
                last_seen: ev.at,
            });

        if let Some(ref sender) = ev.sender_did {
            by_sender
                .entry(sender.clone())
                .and_modify(|s| {
                    if ev.at > s.last_seen_at {
                        s.last_seen_at = ev.at;
                        s.last_seen_mediator = mediator.clone();
                    }
                })
                .or_insert_with(|| SenderLastSeen {
                    sender_did: sender.clone(),
                    last_seen_mediator: mediator.clone(),
                    last_seen_at: ev.at,
                });
        }
    }

    let mut mediators: Vec<MediatorStats> = by_mediator.into_values().collect();
    mediators.sort_by_key(|s| std::cmp::Reverse(s.inbound_count));
    let mut senders: Vec<SenderLastSeen> = by_sender.into_values().collect();
    senders.sort_by_key(|s| std::cmp::Reverse(s.last_seen_at));
    (mediators, senders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::sync::Arc;
    use vti_common::telemetry::RingBufferTelemetry;

    fn evt(at: DateTime<Utc>, mediator: &str, sender: Option<&str>) -> TelemetryEvent {
        let mut e = TelemetryEvent::new(TelemetryKind::DidcommInbound).with_mediator(mediator);
        e.at = at;
        if let Some(s) = sender {
            e = e.with_sender(s);
        }
        e
    }

    #[test]
    fn aggregate_empty_input() {
        let (m, s) = aggregate(&[]);
        assert!(m.is_empty());
        assert!(s.is_empty());
    }

    #[test]
    fn aggregate_counts_per_mediator() {
        let t0 = Utc::now();
        let events = vec![
            evt(t0, "did:m:A", Some("did:peer:alice")),
            evt(t0 + Duration::seconds(60), "did:m:A", Some("did:peer:bob")),
            evt(
                t0 + Duration::seconds(120),
                "did:m:B",
                Some("did:peer:alice"),
            ),
        ];
        let (m, _s) = aggregate(&events);
        assert_eq!(m.len(), 2);
        let by_did: HashMap<&str, &MediatorStats> =
            m.iter().map(|s| (s.mediator_did.as_str(), s)).collect();
        assert_eq!(by_did["did:m:A"].inbound_count, 2);
        assert_eq!(by_did["did:m:B"].inbound_count, 1);
        // Most-traffic-first ordering.
        assert_eq!(m[0].mediator_did, "did:m:A");
    }

    #[test]
    fn aggregate_first_and_last_seen() {
        let t0 = Utc::now();
        let events = vec![
            evt(t0 + Duration::seconds(60), "did:m:A", None),
            evt(t0, "did:m:A", None),
            evt(t0 + Duration::seconds(120), "did:m:A", None),
        ];
        let (m, _) = aggregate(&events);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].first_seen, t0);
        assert_eq!(m[0].last_seen, t0 + Duration::seconds(120));
    }

    #[test]
    fn aggregate_sender_last_seen_mediator_tracks_latest() {
        // Spec criterion #9 substance: per-sender last-seen
        // mediator must reflect the most recent inbound, so the
        // operator can spot senders still using the prior mediator.
        let t0 = Utc::now();
        let events = vec![
            evt(t0, "did:m:A", Some("did:peer:alice")),
            evt(
                t0 + Duration::seconds(60),
                "did:m:B",
                Some("did:peer:alice"),
            ),
            evt(t0 - Duration::seconds(60), "did:m:A", Some("did:peer:bob")),
        ];
        let (_m, senders) = aggregate(&events);
        let alice = senders
            .iter()
            .find(|s| s.sender_did == "did:peer:alice")
            .unwrap();
        // Alice's most recent inbound was via B at t0 + 60s.
        assert_eq!(alice.last_seen_mediator, "did:m:B");
        let bob = senders
            .iter()
            .find(|s| s.sender_did == "did:peer:bob")
            .unwrap();
        assert_eq!(bob.last_seen_mediator, "did:m:A");
    }

    #[test]
    fn aggregate_skips_events_without_mediator() {
        let t0 = Utc::now();
        let mut bad = TelemetryEvent::new(TelemetryKind::DidcommInbound);
        bad.at = t0;
        let events = vec![bad, evt(t0, "did:m:A", None)];
        let (m, _) = aggregate(&events);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].mediator_did, "did:m:A");
    }

    #[tokio::test]
    async fn mediator_report_round_trip() {
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let t0 = Utc::now();
        sink.record(evt(t0, "did:m:A", Some("did:peer:alice")))
            .await
            .unwrap();
        sink.record(evt(
            t0 + Duration::seconds(30),
            "did:m:A",
            Some("did:peer:bob"),
        ))
        .await
        .unwrap();
        sink.record(evt(
            t0 + Duration::seconds(60),
            "did:m:B",
            Some("did:peer:alice"),
        ))
        .await
        .unwrap();

        let auth = AuthClaims::unsafe_local_cli_super_admin("test");
        let report = mediator_report(
            &sink,
            &auth,
            ReportParams {
                since: None,
                until: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(report.mediators.len(), 2);
        assert_eq!(report.senders.len(), 2);
    }

    #[tokio::test]
    async fn report_filters_by_since() {
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let t0 = Utc::now();
        sink.record(evt(t0 - Duration::seconds(120), "did:m:A", None))
            .await
            .unwrap();
        sink.record(evt(t0, "did:m:B", None)).await.unwrap();

        let auth = AuthClaims::unsafe_local_cli_super_admin("test");
        let report = mediator_report(
            &sink,
            &auth,
            ReportParams {
                since: Some(t0 - Duration::seconds(60)),
                until: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(report.mediators.len(), 1);
        assert_eq!(report.mediators[0].mediator_did, "did:m:B");
    }
}
