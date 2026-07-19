//! TSP (Trust Spanning Protocol) inbound handling.
//!
//! [`dispatch_one`] receives TSP messages off the VTA's **single** mediator
//! websocket — the *same* socket the DIDComm listener uses — and feeds each one
//! into the shared [`dispatch_trust_task_core`](crate::trust_tasks) spine that
//! REST and DIDComm also use. TSP is the highest-preference transport
//! (TSP > DIDComm > REST); this is its receive side.
//!
//! ## One socket, multiplexed
//!
//! The mediator permits **one websocket per DID**. The delivery-layer
//! `DidCommTransport` (D2 P2a) owns that socket and its `inbound()` surfaces
//! BOTH DIDComm and TSP frames off it (`Inbound.message.protocol` tags which);
//! the inbound loop (`super::service::handle_tsp`) hands each TSP frame's
//! cleartext payload + proven `sender_vid` to [`dispatch_one`]. There is **no
//! second websocket** — opening one (as the earlier standalone loop did) made
//! the mediator evict a connection as `w.websocket.duplicate-channel`, flapping
//! the VTA.
//!
//! ## Round-trip: the reply routes back over the same socket
//!
//! Each received Trust Task is dispatched on the shared spine and its response
//! envelope is returned to the sender **over TSP** — the inbound loop seals the
//! returned bytes to the proven `sender_vid` and routes them back over the same
//! mediator socket (`atm.tsp().send_routed([mediator_did, sender_vid])`). This
//! mirrors the DIDComm `handle_trust_task` bridge, which returns the same
//! framework document as its reply, so TSP and DIDComm callers get
//! byte-identical round-trip semantics off the shared `dispatch_trust_task_core`.

use tracing::info;

use crate::messaging::auth::auth_from_did;
use crate::server::AppState;

/// Per-message bridge: turn one unpacked TSP message into a dispatched Trust
/// Task on the shared spine and return the framework response envelope bytes.
///
/// `sender_vid` is the **proven** sender DID returned by TSP `unpack_bytes`
/// (verification already happened inside the TSP stack), so this only needs
/// to resolve the sender's ACL grant — exactly like the DIDComm
/// `handle_trust_task` bridge resolves its authcrypt sender. `payload` is
/// the Trust-Task envelope bytes (identical to the REST `POST
/// /api/trust-tasks` body and the DIDComm message body).
///
/// The returned `Vec<u8>` is the self-describing framework trust-task document
/// (its own `type` + status `code`); the caller seals + routes it back to the
/// sender over TSP. On an unknown / unauthorized sender (no ACL entry, or an
/// expired grant) the reply is a Trust-Task `permission_denied` **envelope**,
/// not a drop — the sender VID is cryptographically proven, so there is no
/// enumeration exposure, and a conformant Trust-Task client only understands
/// binding envelopes (identical to the DIDComm path).
pub async fn dispatch_one(app_state: &AppState, payload: &[u8], sender_vid: &str) -> Vec<u8> {
    // Learn-from-inbound: this frame is proof `sender_vid` is reachable over TSP
    // right now (the VID is cryptographically proven by TSP unpack), so record it
    // — device-push then prefers TSP over DIDComm for this DID while the record
    // stays fresh. Recorded regardless of authorization: reachability is a
    // transport fact, and only DIDs we later push to are ever queried.
    app_state.tsp_reach.record(sender_vid);
    tracing::debug!(sender = %sender_vid, "recorded TSP reachability (learn-from-inbound)");
    let outcome = match auth_from_did(sender_vid, &app_state.acl_ks, &app_state.sessions_ks).await {
        Ok(auth) => crate::trust_tasks::dispatch_trust_task_core(app_state, &auth, payload).await,
        Err(e) => crate::trust_tasks::reject_trust_task(
            payload,
            trust_tasks_rs::RejectReason::PermissionDenied {
                reason: e.to_string(),
            },
        ),
    };
    info!(
        sender = %sender_vid,
        status = %outcome.status,
        "TSP trust-task dispatched"
    );
    outcome.body
}

// The delivery-layer inbound loop (`super::service::handle_tsp`) unpacks the
// TSP frame off the shared mediator websocket (via `DidCommTransport`) into a
// neutral `Inbound` with the proven `sender_vid`, calls [`dispatch_one`]
// directly, and seals + routes the reply back — so the framework
// `TspHandler`/`TspResponse` wrapper the old `start_with_tsp` path required is
// no longer needed.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, Role, store_acl_entry};
    use crate::test_support::build_signing_test_app_state;

    /// A sender with no ACL entry still gets a Trust-Task error **envelope**
    /// back (not a silent drop) — the sender VID is proven, so we reply like the
    /// DIDComm path. With this unparseable `{}` body the reject degrades to a
    /// `malformedRequest` envelope (a well-formed-but-unauthorized request would
    /// yield `permissionDenied`); either way the round-trip invariant under test
    /// holds: a non-empty error envelope is produced for the service to route
    /// back over TSP.
    #[tokio::test]
    async fn dispatch_one_unknown_sender_replies_with_error_envelope() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let body = dispatch_one(&app_state, b"{}", "did:key:zUnauthorizedTspSender").await;

        assert!(
            !body.is_empty(),
            "unauthorized sender must get a reply envelope"
        );
        let doc: serde_json::Value = serde_json::from_slice(&body).expect("reply is JSON");
        assert!(
            doc.get("type").is_some() && doc.get("payload").is_some(),
            "reply should be a trust-task error envelope, got: {doc}"
        );
    }

    /// An authorized sender reaches `dispatch_trust_task_core` and the bridge
    /// returns the framework response envelope bytes for the service to route
    /// back over TSP. The empty `{}` body is rejected by the core's envelope
    /// parser, but the point under test is that the ACL grant resolves and the
    /// spine produces a non-empty reply document.
    #[tokio::test]
    async fn dispatch_one_authorized_sender_returns_reply_envelope() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let did = "did:key:zAuthorizedTspSender";
        store_acl_entry(&app_state.acl_ks, &AclEntry::new(did, Role::Admin, "test"))
            .await
            .unwrap();

        let body = dispatch_one(&app_state, b"{}", did).await;

        assert!(
            !body.is_empty(),
            "authorized sender must get a reply envelope"
        );
        serde_json::from_slice::<serde_json::Value>(&body).expect("reply is JSON");
    }

    /// The learn-from-inbound hook: dispatching any inbound TSP frame records its
    /// **proven** `sender_vid` as TSP-reachable, so subsequent device-push
    /// prefers TSP for that DID. Reachability is a transport fact recorded
    /// regardless of the auth outcome, so an unknown sender (which still gets a
    /// reply envelope) is marked reachable just the same.
    #[tokio::test]
    async fn dispatch_one_records_sender_as_tsp_reachable() {
        let (app_state, _dir) = build_signing_test_app_state().await;
        let did = "did:key:zTspDevice";

        assert!(
            !app_state.tsp_reach.fresh(did),
            "a DID we've never seen over TSP is not reachable"
        );

        let _ = dispatch_one(&app_state, b"{}", did).await;

        assert!(
            app_state.tsp_reach.fresh(did),
            "an inbound TSP frame must mark its proven sender TSP-reachable"
        );
    }
}
