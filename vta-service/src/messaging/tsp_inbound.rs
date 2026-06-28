//! TSP (Trust Spanning Protocol) inbound message loop.
//!
//! Background task that receives raw-TSP messages off the mediator
//! websocket and feeds each one into the shared
//! [`dispatch_trust_task_core`](crate::trust_tasks) spine — the *same*
//! spine REST and DIDComm use. TSP is the highest-preference transport
//! (TSP > DIDComm > REST); this is its receive side.
//!
//! ## V1 scope: inbound, one-way
//!
//! Each received Trust Task is dispatched and its outcome is logged. This
//! loop does **not** send a Trust-Task response back over TSP. Returning a
//! response routes through the normal send path and is a documented
//! follow-up (see the workspace TSP enablement design note). See the
//! `NOTE` in [`dispatch_one`].
//!
//! ## Runtime verification
//!
//! The connect / recv loop cannot be unit-tested without a live mediator
//! (it needs a real websocket endpoint authenticated against a mediator
//! DID). [`dispatch_one`] — the per-message bridge — is unit-tested; the
//! connect/recv/reconnect machinery in [`run_tsp_inbound`] is only
//! compile-verified here and must be validated against a live mediator.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::messaging::auth::auth_from_did;
use crate::server::AppState;

/// Initial reconnect backoff. Mirrors the DIDComm listener's
/// `RestartPolicy::Always { initial_delay_secs: 5 }`.
const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
/// Maximum reconnect backoff. Mirrors the DIDComm listener's
/// `max_delay_secs: 60`.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

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

/// The TSP inbound loop: connect to the mediator's raw-TSP websocket,
/// receive frames, unpack + dispatch each, and reconnect with backoff on
/// disconnect.
///
/// Mirrors the DIDComm listener's restart spirit: backoff starts at
/// [`BACKOFF_INITIAL`] and doubles up to [`BACKOFF_MAX`], resetting on a
/// successful connect. A shutdown signal (`shutdown` flipped to `true`)
/// breaks promptly via `tokio::select!` at every await point. Never panics.
///
/// `profile` MUST be a mediator-bearing profile (built with
/// `Some(mediator_did)`); `connect_websocket` resolves the websocket
/// endpoint from the profile's mediator config. This is distinct from
/// `AppState.tsp_profile`, which carries no mediator and is for unpack only.
pub async fn run_tsp_inbound(
    app_state: AppState,
    atm: ATM,
    profile: Arc<ATMProfile>,
    mut shutdown: watch::Receiver<bool>,
) {
    info!("TSP inbound loop starting");
    let mut backoff = BACKOFF_INITIAL;

    loop {
        // Shutdown check before each connect attempt.
        if *shutdown.borrow() {
            info!("TSP inbound loop shutting down");
            return;
        }

        match atm.tsp().connect_websocket(&profile).await {
            Ok(mut ws) => {
                info!("TSP inbound websocket connected");
                // Successful connect resets the backoff.
                backoff = BACKOFF_INITIAL;

                // Inner receive loop — runs until the socket closes, errors,
                // or shutdown is signalled.
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                info!("TSP inbound loop shutting down");
                                return;
                            }
                        }
                        r = ws.recv() => match r {
                            Ok(Some(qb2)) => {
                                match atm.tsp().unpack_bytes(&profile, &qb2).await {
                                    Ok((payload, sender)) => {
                                        dispatch_one(&app_state, &payload, &sender).await;
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "TSP unpack failed — dropping frame");
                                    }
                                }
                            }
                            Ok(None) => {
                                info!("TSP inbound websocket closed — reconnecting");
                                break;
                            }
                            Err(e) => {
                                warn!(error = %e, "TSP inbound recv error — reconnecting");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "TSP inbound connect failed — backing off"
                );
                // Wait out the backoff, but wake promptly on shutdown.
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            info!("TSP inbound loop shutting down");
                            return;
                        }
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
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
