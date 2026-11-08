//! `rooms/watch/0.1` at this VTC as a room's host, and the `rooms/changed/0.1` signal it
//! sends ([`vti_rooms::watch`], which holds the rules both hosts share).
//!
//! This module lends the shared layer the one thing that is this service's own: how a
//! signal leaves. Over [`PeerTasks`] — the address's DID document read for its transports,
//! TSP before DIDComm, never REST — signed as this community, one-way, and never retried
//! (`rooms/changed/0.1` Producer item 5).

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_rooms::authz::Action;

use super::files::{refused, render};
use super::handlers::RoomCtx;
use crate::outbound::PeerTasks;
use crate::trust_tasks::helpers::{TrustTaskOutcome, app_error_to_reject};
use vti_specs::rooms::watch::v0_1 as watch_spec;

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

/// `rooms/watch/0.1`: authorized exactly as a listing (`read`), then the shared layer arms,
/// re-arms or cancels the watch.
pub(crate) async fn handle_watch(
    doc: TrustTask<watch_spec::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match serde_json::to_value(&doc.payload) {
        Ok(p) => p,
        Err(e) => {
            return app_error_to_reject(&doc, &vti_common::error::AppError::Serialization(e));
        }
    };
    if let Err(r) = vti_rooms::watch::check_payload(&payload) {
        return refused(&doc, r);
    }
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = match vti_rooms::storage::get_room(&ctx.state.rooms_ks, room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(r) = vti_rooms::watch::presentation(&payload, &room) {
        return refused(&doc, r);
    }
    let (room, authorized) = match super::files::authorize(&doc, &ctx, &payload, Action::Read).await
    {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        ctx.state
            .room_watches
            .watch(&room, authorized, &payload, chrono::Utc::now())
            .await,
    )
}
