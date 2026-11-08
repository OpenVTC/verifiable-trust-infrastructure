//! The connections the VTA receives at for the watches it holds (`rooms/keys/watch/0.1`
//! Recipient item 5): one per watch's address, which is a DID nobody else holds.
//!
//! One supervisor ([`run`]) reconciles the connections with the watch records every
//! [`RECONCILE_INTERVAL`] and whenever a watch is armed, fires or is forgotten — opening
//! one for each record held and closing every other — and runs the watch sweep
//! (`trust_tasks::room_key_watch::sweep`) on the same pass, so a lapsed watch, or one whose
//! caller lost standing, stops receiving at once.
//!
//! Each connection is its own TDK and ATM holding only that address's two keys, one
//! profile and one websocket at the VTA's mediator, as the collector's are
//! (`messaging::collector`). The address advertises DIDComm alone, so a host signals over
//! DIDComm authcrypt, which proves its sender: a frame is passed to
//! `trust_tasks::room_key_watch::receive_signal` only when the transport proved who sent it,
//! and nothing is ever answered from an address (`rooms/changed` has no response).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_core::{Inbound, Protocol};
use affinidi_messaging_delivery::{InMemoryOutboxStore, MessagingService};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::operations::room_key_watch::{AddressSession, WatchRecord};
use crate::server::AppState;

/// How often the supervisor reconciles without being asked.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
/// How long an address's websocket may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest the supervisor waits before retrying an address whose connection would
/// not open.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(600);

/// One address's connection.
struct WatchAddressSession {
    atm: Arc<ATM>,
    cancel: CancellationToken,
}

impl AddressSession for WatchAddressSession {
    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.cancel.cancel();
            // `graceful_shutdown` is what stops the websocket; dropping the ATM would leave
            // it reconnecting at the mediator.
            self.atm.graceful_shutdown().await;
        })
    }
}

/// Run the supervisor until `shutdown`, then close every address's connection.
pub async fn run(state: AppState, shutdown: CancellationToken) {
    let mut retry: HashMap<String, (Instant, u32)> = HashMap::new();
    loop {
        if let Err(e) = crate::trust_tasks::room_key_watch::sweep(&state).await {
            warn!(error = %e, "room watch sweep failed; trying again on the next pass");
        }
        if let Err(e) = reconcile(&state, &shutdown, &mut retry).await {
            warn!(error = %e, "room watch addresses: reconcile failed; trying again on the next pass");
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = state.room_key_watches.changed() => {}
            _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
        }
    }
    state.room_key_watches.stop_all().await;
}

async fn reconcile(
    state: &AppState,
    shutdown: &CancellationToken,
    retry: &mut HashMap<String, (Instant, u32)>,
) -> Result<(), vti_common::error::AppError> {
    let watches = &state.room_key_watches;
    let now = chrono::Utc::now().timestamp();
    let held: Vec<WatchRecord> = watches
        .all()
        .await?
        .into_iter()
        .filter(|w| !w.lapsed(now))
        .collect();
    let wanted: HashSet<&str> = held.iter().map(|w| w.address.as_str()).collect();
    for address in watches.receiving() {
        if !wanted.contains(address.as_str()) {
            watches.stop(&address).await;
            debug!("stopped receiving at a forgotten watch's address");
        }
    }
    retry.retain(|k, _| wanted.contains(k.as_str()));
    let mediator = state
        .config
        .read()
        .await
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.clone());
    let Some(mediator) = mediator else {
        return Ok(());
    };
    for w in &held {
        if shutdown.is_cancelled() {
            break;
        }
        if watches.is_receiving(&w.address)
            || retry
                .get(&w.address)
                .is_some_and(|(at, _)| Instant::now() < *at)
        {
            continue;
        }
        match open_session(state, w, &mediator).await {
            Ok(session) => {
                retry.remove(&w.address);
                watches.insert_session(&w.address, session);
            }
            Err(e) => {
                let failures = retry.get(&w.address).map_or(0, |(_, n)| *n) + 1;
                let delay = RECONCILE_INTERVAL
                    .saturating_mul(1 << failures.min(5))
                    .min(MAX_RETRY_DELAY);
                retry.insert(w.address.clone(), (Instant::now() + delay, failures));
                warn!(error = %e, retry_in = ?delay, "could not open a watch address's connection");
            }
        }
    }
    Ok(())
}

/// Open the connection for `w`'s address at `mediator`. Every error after the ATM holds a
/// profile tears it down, so a failed attempt leaves no socket behind.
async fn open_session(
    state: &AppState,
    w: &WatchRecord,
    mediator: &str,
) -> Result<Arc<dyn AddressSession>, String> {
    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or("no DID resolver is configured")?;
    let tdk_config = TDKConfig::builder()
        .with_load_environment(false)
        .with_did_resolver(resolver.clone())
        .build()
        .map_err(|e| format!("build TDK config: {e}"))?;
    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| format!("create TDK state: {e}"))?;
    for s in w.secrets() {
        tdk.secrets_resolver().insert(s.clone()).await;
    }
    let atm = Arc::new(
        ATM::new(
            ATMConfig::builder()
                .with_delete_unprocessable(true)
                .build()
                .map_err(|e| format!("build ATM config: {e}"))?,
            Arc::new(tdk),
        )
        .await
        .map_err(|e| format!("create ATM: {e}"))?,
    );
    let profile = ATMProfile::new(&atm, None, w.address.clone(), Some(mediator.to_string()))
        .await
        .map_err(|e| format!("create profile: {e}"))?;
    let profile = match atm.profile_add(&profile, false).await {
        Ok(p) => p,
        Err(e) => {
            atm.graceful_shutdown().await;
            return Err(format!("register profile: {e}"));
        }
    };
    let transport = match connect(&atm, &profile).await {
        Ok(t) => t,
        Err(e) => {
            atm.graceful_shutdown().await;
            return Err(e);
        }
    };
    let service = Arc::new(MessagingService::new(
        transport,
        Arc::new(InMemoryOutboxStore::new()),
    ));
    let cancel = CancellationToken::new();
    tokio::spawn(inbound_loop(
        state.clone(),
        w.address.clone(),
        service,
        cancel.clone(),
    ));
    Ok(Arc::new(WatchAddressSession { atm, cancel }))
}

async fn connect(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
) -> Result<Arc<dyn affinidi_messaging_core::MessageTransport>, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, atm.profile_enable_websocket(profile)).await {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => return Err("timed out opening the mediator websocket".into()),
    }
    Ok(Arc::new(
        DidCommTransport::new((**atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind transport: {e}"))?,
    ))
}

async fn inbound_loop(
    state: AppState,
    address: String,
    service: Arc<MessagingService>,
    cancel: CancellationToken,
) {
    let mut stream = service.subscribe();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            next = stream.next() => {
                let Some(inbound) = next else { break };
                handle(&state, &address, inbound).await;
            }
        }
    }
}

/// One frame at an address: a Trust Task document from a proven sender goes to the
/// signal handler; anything else is dropped silently (Recipient item 8).
async fn handle(state: &AppState, address: &str, inbound: Inbound) {
    if inbound.message.protocol != Protocol::DIDComm {
        debug!("a frame at a watch address in a protocol it does not advertise — dropped");
        return;
    }
    let sender = match inbound.message.sender.as_deref() {
        Some(s) if inbound.message.encrypted && inbound.message.verified => s.to_string(),
        _ => {
            debug!("a frame at a watch address without a proven sender — dropped");
            return;
        }
    };
    let msg: affinidi_messaging_didcomm::Message =
        match serde_json::from_slice(&inbound.message.payload) {
            Ok(m) => m,
            Err(_) => return,
        };
    if msg.typ != trust_tasks_didcomm::ENVELOPE_TYPE {
        return;
    }
    let Ok(document) = serde_json::to_vec(&msg.body) else {
        return;
    };
    crate::trust_tasks::room_key_watch::receive_signal(state, address, &sender, &document).await;
}
