//! `rooms/changed/0.1` — a room's host telling a watch's address that the room moved past
//! the version its member had read to (trust-tasks-tf #1036).
//!
//! This VTA is an address only when its member armed a watch naming the VTA's own DID; the
//! watch is armed by a client of this VTA (`pnm rooms watch`), never by the VTA, so the VTA
//! keeps no record of which hosts and rooms its member watches. With no record to check a
//! signal against (`rooms/changed/0.1` Consumer item 1) and no consumer here that reads the
//! room in answer to one, a signal is **accepted and dropped**: checked against its schema,
//! logged at `debug`, and answered with nothing — the task is one-way, and a reply would tell
//! the host when the member's device woke. Nothing is stored and nothing is shown to anyone
//! on the strength of it (Consumer item 2).
//!
//! A counterparty task (`is_counterparty_task`): the host holds no ACL entry, so the signal
//! is dispatched on a zero-authority claim and charged to the bound for senders without
//! standing (VTI-TRN-029), never to this VTA's clients.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::auth::AuthClaims;

use super::helpers::{TrustTaskOutcome, parse_payload, silence};
use crate::server::AppState;

/// Whether `type_uri` is the signal: sent by a room's host, which holds no ACL entry.
pub(crate) fn is_counterparty_task(type_uri: &str) -> bool {
    type_uri == vta_sdk::trust_tasks::TASK_ROOMS_CHANGED_0_1
}

/// `rooms/changed/0.1`: checked, logged at `debug`, and answered with nothing.
pub(super) async fn handle_changed(
    _state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = parse_payload::<vti_specs::rooms::changed::v0_1::Payload>(&doc) {
        return r;
    }
    tracing::debug!(
        host = doc.issuer.as_deref().unwrap_or("?"),
        room = doc.payload["roomId"].as_str().unwrap_or("?"),
        latest_version = doc.payload["latestVersion"].as_u64().unwrap_or(0),
        "a room's host signalled that the room moved; nothing here reads it — dropped"
    );
    silence()
}
