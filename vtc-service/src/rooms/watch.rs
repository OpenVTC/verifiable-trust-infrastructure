//! `rooms/watch/0.1` and `0.2` (a live watch, trust-tasks-tf #1087) at this VTC as a
//! room's host, and the `rooms/changed/0.1` signal it sends ([`vti_rooms::watch`], which holds the rules both hosts share).
//!
//! The tasks are [`vti_rooms_host`]'s. This module lends the shared layer the one thing that
//! is this service's own: how a signal leaves. Over [`PeerTasks`] — the address's DID document read for its transports,
//! TSP before DIDComm, never REST — signed as this community, one-way, and never retried
//! (`rooms/changed/0.1` Producer item 5).

use serde_json::Value;

use crate::outbound::PeerTasks;

/// This VTC's outbound leg for watch signals.
pub(crate) struct VtcSignals {
    pub(crate) peers: PeerTasks,
}

#[async_trait::async_trait]
impl vti_rooms::watch::Signals for VtcSignals {
    async fn reachable(&self, address: &str) -> bool {
        self.peers.select(address).await.is_ok()
    }

    async fn send_changed(&self, address: &str, payload: Value) -> Result<(), String> {
        self.peers
            .send_one_way(address, vti_rooms::watch::CHANGED_TYPE, &payload)
            .await
            .map_err(|e| e.to_string())
    }
}
