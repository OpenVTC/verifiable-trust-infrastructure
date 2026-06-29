//! TSP (Trust Spanning Protocol) inbound handler.
//!
//! [`VtaTspHandler`] receives TSP messages off the VTA's **single** mediator
//! websocket — the *same* socket the DIDComm listener uses — and feeds each one
//! into the shared [`dispatch_trust_task_core`](crate::trust_tasks) spine that
//! REST and DIDComm also use. TSP is the highest-preference transport
//! (TSP > DIDComm > REST); this is its receive side.
//!
//! ## One socket, multiplexed
//!
//! The mediator permits **one websocket per DID**. The DIDComm service
//! (`affinidi-messaging-didcomm-service`, ADR 0005 — `AffinidiMessageService`)
//! owns that socket, sniffs inbound frames, and routes TSP frames to a
//! [`TspHandler`]. The VTA registers `VtaTspHandler` via
//! `DIDCommService::start_with_tsp`. There is **no second websocket** — opening
//! one (as the earlier standalone loop did) made the mediator evict a
//! connection as `w.websocket.duplicate-channel`, flapping the VTA.
//!
//! ## V1 scope: inbound, one-way
//!
//! Each received Trust Task is dispatched and its outcome is logged. The
//! handler does **not** send a Trust-Task response back over TSP; returning a
//! response routes through the normal send path and is a documented follow-up.
//! See the `NOTE` in [`dispatch_one`].

use affinidi_messaging_didcomm_service::{DIDCommServiceError, HandlerContext, TspHandler};
use tracing::{info, warn};

use crate::messaging::auth::auth_from_did;
use crate::server::AppState;

/// Per-message bridge: turn one unpacked TSP message into a dispatched
/// Trust Task on the shared spine.
///
/// `sender_vid` is the **proven** sender DID returned by TSP `unpack_bytes`
/// (verification already happened inside the TSP stack), so this only needs
/// to resolve the sender's ACL grant — exactly like the DIDComm
/// `handle_trust_task` bridge resolves its authcrypt sender. `payload` is
/// the Trust-Task envelope bytes (identical to the REST `POST
/// /api/trust-tasks` body and the DIDComm message body).
///
/// On an unknown / unauthorized sender (no ACL entry, or an expired grant)
/// the message is logged and dropped — never silently authorized.
///
/// NOTE (V1, one-way): the dispatch outcome is logged but **not** returned
/// to the sender over TSP. Response-over-TSP routes through the normal send
/// path and is a documented follow-up; this loop is receive-only.
pub async fn dispatch_one(app_state: &AppState, payload: &[u8], sender_vid: &str) {
    match auth_from_did(sender_vid, &app_state.acl_ks).await {
        Ok(auth) => {
            let outcome =
                crate::trust_tasks::dispatch_trust_task_core(app_state, &auth, payload).await;
            // The outcome's HTTP `status` is the framework result code; on
            // the one-way TSP path we only log it (the self-describing
            // response document is dropped — see NOTE above).
            info!(
                sender = %sender_vid,
                status = %outcome.status,
                "TSP trust-task dispatched"
            );
        }
        Err(e) => {
            // Peer is not in this VTA's ACL (or grant expired). Drop the
            // message; do not respond.
            warn!(
                sender = %sender_vid,
                error = %e,
                "TSP message from unauthorized sender — dropped"
            );
        }
    }
}

/// TSP handler registered on the VTA's DIDComm service via
/// [`DIDCommService::start_with_tsp`](affinidi_messaging_didcomm_service::DIDCommService::start_with_tsp).
///
/// The service unpacks the TSP frame off the shared websocket (yielding the
/// cleartext payload + the cryptographically-authenticated `sender_vid`) and
/// invokes [`handle`](TspHandler::handle), which bridges to the shared spine via
/// [`dispatch_one`]. Inbound is one-way: the dispatch outcome is logged, not
/// returned over TSP (see the `NOTE` in [`dispatch_one`]).
pub struct VtaTspHandler {
    app_state: AppState,
}

impl VtaTspHandler {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }
}

#[async_trait::async_trait]
impl TspHandler for VtaTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<(), DIDCommServiceError> {
        dispatch_one(&self.app_state, &payload, &sender_vid).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, Role, store_acl_entry};
    use crate::test_support::build_signing_test_app_state;

    /// `dispatch_one` with a sender that has no ACL entry must log + drop
    /// without panicking (it returns `()`; the assertion is that it
    /// completes). Exercises the unauthorized-sender path.
    #[tokio::test]
    async fn dispatch_one_unknown_sender_drops_without_panic() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        // No ACL entry for this sender → auth_from_did errors → dispatch_one
        // logs a warning and returns without dispatching or panicking.
        dispatch_one(&app_state, b"{}", "did:key:zUnauthorizedTspSender").await;
    }

    /// An authorized sender reaches `dispatch_trust_task_core`. The empty
    /// body is rejected by the core's envelope parser, but the point under
    /// test is that the bridge resolves the ACL grant and drives the spine
    /// without panicking (one-way: the outcome is logged, not returned).
    #[tokio::test]
    async fn dispatch_one_authorized_sender_reaches_spine() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let did = "did:key:zAuthorizedTspSender";
        store_acl_entry(&app_state.acl_ks, &AclEntry::new(did, Role::Admin, "test"))
            .await
            .unwrap();

        dispatch_one(&app_state, b"{}", did).await;
    }
}
