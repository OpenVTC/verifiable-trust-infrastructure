//! VTA-side DIDComm responder for SDK round-trip tests.
//!
//! [`TestVtaResponder`] spawns a `did:peer:2.*` identity, registers
//! itself as a LOCAL account on the supplied test mediator, opens a
//! WebSocket inbound stream, and dispatches each incoming message to a
//! caller-supplied handler. The handler returns either a typed result
//! payload (msg_type + body) or a problem-report code/comment, which
//! the responder packs as a DIDComm reply (with `thid` threaded back to
//! the requester) and sends through the mediator.
//!
//! This is the harness that lets the SDK's `Transport::DIDComm` arms
//! and `session::send_and_wait` success paths be exercised in a test
//! — without it the SDK can `pack_encrypted` and `send_message` but
//! never sees a matching response, so the entire response-handling
//! branch (problem-report decoding, type-check, deserialize) stays
//! uncovered.
//!
//! # Usage
//!
//! ```ignore
//! let mediator = TestMediator::builder()
//!     .local_did(client_did.clone())
//!     .spawn().await.unwrap();
//! let responder = TestVtaResponder::spawn(
//!     mediator.did(),
//!     |msg_type, _body| {
//!         if msg_type.ends_with("/list-keys") {
//!             ResponderReply::ok(
//!                 format!("{msg_type}-result"),
//!                 json!({"keys": [], "total": 0}),
//!             )
//!         } else {
//!             ResponderReply::problem_report(
//!                 "e.p.msg.not-found",
//!                 format!("no handler for {msg_type}"),
//!             )
//!         }
//!     },
//! ).await.unwrap();
//! // build a VtaClient via connect_didcomm(... responder.did(), mediator.did(), None)
//! ```

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde_json::Value;
use tokio::sync::oneshot;

/// Reply the responder builds for an inbound message.
pub enum ResponderReply {
    /// Successful result. `result_type` is the DIDComm `typ` field of
    /// the reply (typically the request `typ` with `-result` suffix);
    /// `body` is the JSON the SDK will deserialize into its `T`.
    Ok { result_type: String, body: Value },
    /// Problem report. The SDK maps `e.p.msg.{conflict,not-found,
    /// unauthorized,bad-request,internal-error}` to typed `VtaError`
    /// variants; everything else lands in `VtaError::DidcommRemote`.
    Problem { code: String, comment: String },
    /// No reply at all — used to test the `send_and_wait` timeout path.
    Drop,
}

impl ResponderReply {
    pub fn ok(result_type: impl Into<String>, body: Value) -> Self {
        Self::Ok {
            result_type: result_type.into(),
            body,
        }
    }

    pub fn problem_report(code: impl Into<String>, comment: impl Into<String>) -> Self {
        Self::Problem {
            code: code.into(),
            comment: comment.into(),
        }
    }
}

/// Errors from the responder fixture itself.
#[derive(Debug, thiserror::Error)]
pub enum ResponderError {
    #[error("did:peer generation failed: {0}")]
    DidGeneration(String),
    #[error("TDK init failed: {0}")]
    TdkInit(String),
    #[error("ATM init failed: {0}")]
    AtmInit(String),
    #[error("profile creation failed: {0}")]
    Profile(String),
    #[error("websocket enable failed: {0}")]
    Websocket(String),
}

/// A `did:peer:2`-identified DIDComm responder, listening on a
/// supplied test mediator. Drop or call [`Self::shutdown`] to tear it
/// down cleanly.
pub struct TestVtaResponder {
    pub did: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl TestVtaResponder {
    /// Spawn a responder that runs `handler` for every inbound DIDComm
    /// message until `shutdown` is called. The handler must be
    /// `Send + Sync + 'static` because it runs in a tokio task on the
    /// shared runtime.
    pub async fn spawn<F>(mediator_did: &str, handler: F) -> Result<Self, ResponderError>
    where
        F: Fn(&str, &Value) -> ResponderReply + Send + Sync + 'static,
    {
        // 1. Mint a fresh did:peer:2 identity.
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .map_err(|e| ResponderError::DidGeneration(e.to_string()))?;

        // 2. Stand up TDK + ATM + profile.
        let tdk = TDKSharedState::new(
            TDKConfig::builder()
                .build()
                .map_err(|e| ResponderError::TdkInit(format!("config: {e}")))?,
        )
        .await
        .map_err(|e| ResponderError::TdkInit(e.to_string()))?;
        for s in &secrets {
            tdk.secrets_resolver().insert(s.clone()).await;
        }

        let atm = ATM::new(
            ATMConfig::builder()
                .build()
                .map_err(|e| ResponderError::AtmInit(format!("config: {e}")))?,
            Arc::new(tdk),
        )
        .await
        .map_err(|e| ResponderError::AtmInit(e.to_string()))?;
        let atm = Arc::new(atm);

        let profile = ATMProfile::new(&atm, None, did.clone(), Some(mediator_did.to_string()))
            .await
            .map_err(|e| ResponderError::Profile(e.to_string()))?;
        // Registered so the dispatch loop's `graceful_shutdown` can actually
        // stop this socket — it stops websockets by iterating the ATM's profile
        // map, so an unregistered one outlives every teardown and keeps
        // reconnecting for the rest of the test binary (vta-sdk #830).
        let profile = atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| ResponderError::Profile(e.to_string()))?;

        // 3. Open inbound WebSocket so live_stream_next has a channel.
        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|e| ResponderError::Websocket(e.to_string()))?;

        // 4. Spawn the dispatch loop.
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let responder_did = did.clone();
        let atm_loop = atm.clone();
        let profile_loop = profile.clone();
        let join_handle = tokio::spawn(async move {
            run_dispatch_loop(
                atm_loop,
                profile_loop,
                responder_did,
                handler,
                &mut shutdown_rx,
            )
            .await;
        });

        Ok(Self {
            did,
            shutdown_tx: Some(shutdown_tx),
            join_handle,
        })
    }

    /// Convenience: spawn a responder that registers itself as
    /// `local_did` on a fresh `TestMediator`. `extra_local_dids` lets
    /// the caller register additional client DIDs (which also need
    /// the LOCAL bit to open WebSocket inbound to the same mediator)
    /// in one shot. Returns both handles so the test owns their
    /// lifetimes.
    pub async fn spawn_with_mediator<F>(
        extra_local_dids: Vec<String>,
        handler: F,
    ) -> Result<(TestMediatorHandle, Self), ResponderError>
    where
        F: Fn(&str, &Value) -> ResponderReply + Send + Sync + 'static,
    {
        // We need the responder DID *before* spawning the mediator so
        // we can register it as LOCAL. Generate it inline here, then
        // pass the secrets through to a dedicated constructor.
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .map_err(|e| ResponderError::DidGeneration(e.to_string()))?;

        let mut builder = TestMediator::builder().local_did(did.clone());
        for extra in &extra_local_dids {
            builder = builder.local_did(extra.clone());
        }
        let mediator = builder
            .spawn()
            .await
            .map_err(|e| ResponderError::AtmInit(format!("test mediator spawn: {e}")))?;

        let responder =
            Self::spawn_with_existing_identity(mediator.did(), did, secrets, handler).await?;

        Ok((mediator, responder))
    }

    async fn spawn_with_existing_identity<F>(
        mediator_did: &str,
        did: String,
        secrets: Vec<Secret>,
        handler: F,
    ) -> Result<Self, ResponderError>
    where
        F: Fn(&str, &Value) -> ResponderReply + Send + Sync + 'static,
    {
        let tdk = TDKSharedState::new(
            TDKConfig::builder()
                .build()
                .map_err(|e| ResponderError::TdkInit(format!("config: {e}")))?,
        )
        .await
        .map_err(|e| ResponderError::TdkInit(e.to_string()))?;
        for s in &secrets {
            tdk.secrets_resolver().insert(s.clone()).await;
        }

        let atm = ATM::new(
            ATMConfig::builder()
                .build()
                .map_err(|e| ResponderError::AtmInit(format!("config: {e}")))?,
            Arc::new(tdk),
        )
        .await
        .map_err(|e| ResponderError::AtmInit(e.to_string()))?;
        let atm = Arc::new(atm);

        let profile = ATMProfile::new(&atm, None, did.clone(), Some(mediator_did.to_string()))
            .await
            .map_err(|e| ResponderError::Profile(e.to_string()))?;
        // Registered so the dispatch loop's `graceful_shutdown` can actually
        // stop this socket — it stops websockets by iterating the ATM's profile
        // map, so an unregistered one outlives every teardown and keeps
        // reconnecting for the rest of the test binary (vta-sdk #830).
        let profile = atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| ResponderError::Profile(e.to_string()))?;

        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|e| ResponderError::Websocket(e.to_string()))?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let responder_did = did.clone();
        let atm_loop = atm.clone();
        let profile_loop = profile.clone();
        let join_handle = tokio::spawn(async move {
            run_dispatch_loop(
                atm_loop,
                profile_loop,
                responder_did,
                handler,
                &mut shutdown_rx,
            )
            .await;
        });

        Ok(Self {
            did,
            shutdown_tx: Some(shutdown_tx),
            join_handle,
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// Stop the dispatch loop and wait for the task to finish. Safe to
    /// call multiple times — subsequent calls are no-ops.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Fire-and-forget join; we tolerate errors (the dispatch loop
        // can exit on its own if the mediator drops the connection).
        let _ = self.join_handle.await;
    }
}

const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The dispatch loop: receive → handle → reply, until shutdown.
///
/// The mediator refuses direct delivery of inner messages, so the
/// reply path is two hops:
///   1. Pack the application reply encrypted to the requester (inner JWE).
///   2. Wrap the inner JWE in a `routing/2.0/forward` envelope addressed
///      to the mediator (with `next = requester_did`), pack that
///      anoncrypt to the mediator, and ship it.
///
/// The mediator unpacks the outer envelope, sees the `next` hop, and
/// queues the inner JWE for the requester's pickup.
async fn run_dispatch_loop<F>(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    responder_did: String,
    handler: Arc<F>,
    shutdown_rx: &mut oneshot::Receiver<()>,
) where
    F: Fn(&str, &Value) -> ResponderReply + Send + Sync + 'static,
{
    let mediator_did = profile
        .inner
        .mediator
        .as_ref()
        .as_ref()
        .map(|m| m.did.clone())
        .unwrap_or_default();

    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        let next = atm
            .message_pickup()
            .live_stream_next(&profile, Some(POLL_INTERVAL), true)
            .await;

        let Ok(Some((msg, _meta))) = next else {
            continue;
        };

        // Skip problem-reports — replying to them would feed the
        // mediator's policy back into the loop and spin.
        if msg.typ.contains("problem-report") || msg.typ.contains("report-problem") {
            continue;
        }

        // Skip forward envelopes that arrive un-unwrapped (defensive —
        // ATM's `unpack_forwards: true` should have unwrapped them
        // already, but if not, re-dispatch would treat the envelope as
        // an application message).
        if msg.typ == "https://didcomm.org/routing/2.0/forward" {
            continue;
        }

        let Some(sender) = msg.from.clone() else {
            continue;
        };

        let reply = handler(&msg.typ, &msg.body);
        let (result_type, body) = match reply {
            ResponderReply::Ok { result_type, body } => (result_type, body),
            ResponderReply::Problem { code, comment } => (
                "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
                serde_json::json!({ "code": code, "comment": comment }),
            ),
            ResponderReply::Drop => continue,
        };

        let reply_id = uuid::Uuid::new_v4().to_string();
        let reply_msg = Message::build(reply_id.clone(), result_type, body)
            .from(responder_did.clone())
            .to(sender.clone())
            .thid(msg.id.clone())
            .finalize();

        // Step 1: authcrypt the inner reply to the requester.
        let inner_jwe = match atm
            .pack_encrypted(
                &reply_msg,
                &sender,
                Some(&responder_did),
                Some(&responder_did),
            )
            .await
        {
            Ok((p, _)) => p,
            Err(_) => continue,
        };

        // Step 2: hand off to the SDK's forward+send helper, which
        // wraps the inner JWE in a `routing/2.0/forward` envelope and
        // authcrypts it to the mediator (matches the strict
        // `local_direct_delivery_allowed: false` policy).
        if mediator_did.is_empty() {
            continue;
        }
        let _ = atm
            .forward_and_send_message(
                &profile,
                false, // authcrypt the forward envelope
                &inner_jwe,
                Some(&reply_id),
                &mediator_did,
                &sender,
                None,
                None,
                false,
            )
            .await;
    }

    atm.graceful_shutdown().await;
}
