//! `rooms/changed/0.1` — a room's host telling a watch's address that the room moved past
//! the version its member had read to (trust-tasks-tf #1036).
//!
//! A watch this VTA arms for a client (`rooms/keys/watch/0.1`) names an address of its own,
//! and the signal arrives on that address's own connection
//! (`messaging::watch_addresses`), never here. What reaches this handler is a signal
//! addressed to the VTA's own DID, which no watch it arms ever names (`rooms/keys/watch/0.1`
//! Recipient item 5) and no client may name either (`rooms/keys/act/0.12` Producer item 6).
//! It is matched like any other ([`super::room_key_watch::receive_document`]) — and so
//! dropped without a word: the task is one-way, and a reply would tell the host when the
//! member's device woke. Nothing is stored and nothing is shown to anyone on the strength
//! of it.
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

/// `rooms/changed/0.1`: checked, matched against the watches held, and answered with
/// nothing.
pub(super) async fn handle_changed(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = parse_payload::<vti_specs::rooms::changed::v0_1::Payload>(&doc) {
        return r;
    }
    let address = doc
        .recipient
        .as_ref()
        .map(|r| r.to_string())
        .or(state.config.read().await.vta_did.clone())
        .unwrap_or_default();
    if let Ok(received) = serde_json::to_value(&doc) {
        super::room_key_watch::receive_document(state, &address, &auth.did, &received).await;
    }
    silence()
}
