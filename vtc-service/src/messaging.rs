use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_core::{Inbound, MessageTransport};
use affinidi_messaging_delivery::{Delivery, MessagingService, OutboxStore};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use futures_util::StreamExt;
use tokio::sync::watch;
use tracing::{info, warn};

use serde_json::json;
use vti_common::error::AppError;
use vti_common::outbox_store::VtiOutboxStore;

use vta_sdk::protocols::credential_exchange::PRESENT as CREDENTIAL_PRESENT_TYPE;
use vta_sdk::protocols::credential_exchange::REQUEST as CREDENTIAL_REQUEST_TYPE;
use vta_sdk::protocols::credential_exchange::{
    ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody, PresentBody, RequestBody,
};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_ACCEPT_TYPE, JOIN_REQUEST_MANIFEST_TYPE, JOIN_REQUEST_STATUS_TYPE,
    JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, JOIN_REQUEST_SUBMIT_TYPE, JoinRequestSubmitReceiptBody,
    MEMBER_SELF_REMOVE_RECEIPT_TYPE, MEMBER_SELF_REMOVE_TYPE, SelfRemoveBody,
    SelfRemoveReceiptBody,
};
use vta_sdk::protocols::members::{
    MEMBER_VMC_RESPONSE_TYPE, MEMBER_VMC_TYPE, MemberVmcBody, MemberVmcReceiptBody,
};
use vta_sdk::protocols::{PROBLEM_REPORT_TYPE, problem_report_codes as codes};

use crate::ceremony::remove_inner;
use crate::config::AppConfig;
use crate::join::JoinTransport;
use crate::members::Disposition;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use crate::trust_tasks::{JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core};

/// DIDComm message types handled locally by the dispatcher rather than routed
/// to a protocol handler. These used to come from the
/// `affinidi-messaging-didcomm-service` framework; with that framework removed
/// (the delivery-layer cut-over, D2 P1a) we re-declare the two we act on.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
/// The high-frequency message-pickup status heartbeat. Dispatched as a no-op
/// (was the framework's `ignore_handler`) and never logged.
const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// The VTC's live messaging handle, published into
/// [`AppState::didcomm`](crate::server::AppState) once the listener starts.
///
/// Holds the delivery-layer [`MessagingService`] (the one inbound/outbound
/// chokepoint over the VTC's single mediator websocket), the [`ATM`] used to
/// authcrypt-pack outbound replies, and the VTC's own DID (the pack sender).
/// Every outbound `AppState::send_to_member` reads this so it reuses the one
/// connection — the mediator permits only one websocket per DID.
pub struct VtcMessaging {
    pub service: Arc<MessagingService>,
    pub atm: Arc<ATM>,
    pub vtc_did: String,
}

/// The VTC's signing + key-agreement verification-method ids, read from its
/// **own DID document** rather than assumed.
///
/// The VTC mints itself a `did:webvh` whose keys land at `#key-0` (signing)
/// and `#key-1` (key agreement) — `status.rs` assigns exactly those ids. But
/// that numbering is a property of *that minting path*, not of DIDs in
/// general: a `did:peer`, for instance, numbers from `#key-1` (Ed25519) and
/// `#key-2` (X25519). Hardcoding `#key-0`/`#key-1` meant a VTC on any other
/// method failed the secret lookup in [`run_didcomm_service`] and silently
/// ran with **messaging disabled** — an easy trap, since the only symptom is
/// a single warn line and outbound `send_to_member` failing forever after.
///
/// Resolution order: the document's first `authentication` relationship (then
/// any bare `verificationMethod`) for signing, and its first `keyAgreement`
/// for key agreement. The historical `#key-0`/`#key-1` convention remains the
/// fallback when no resolver is configured or the DID can't be resolved, so
/// the production `did:webvh` path is unchanged either way — a `did:webvh`
/// document lists those exact ids, so resolution returns them anyway.
async fn vtc_key_ids(
    did_resolver: Option<&DIDCacheClient>,
    vtc_did: &str,
) -> (String, Option<String>) {
    let conventional = || (format!("{vtc_did}#key-0"), Some(format!("{vtc_did}#key-1")));

    let Some(resolver) = did_resolver else {
        return conventional();
    };
    let resolved = match resolver.resolve(vtc_did).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                %vtc_did,
                error = %e,
                "could not resolve the VTC DID for its key ids — falling back to #key-0/#key-1",
            );
            return conventional();
        }
    };

    // A relationship id may be a bare fragment (`"#key-1"`) rather than an
    // absolute DID URL; the secrets resolver is keyed by the absolute id, so
    // re-attach the DID before looking it up.
    let absolutize = |id: &str| -> String {
        match id.strip_prefix('#') {
            Some(fragment) => format!("{vtc_did}#{fragment}"),
            None => id.to_string(),
        }
    };

    let doc = &resolved.doc;
    let signing = doc
        .authentication
        .first()
        .map(|vr| vr.get_id())
        .or_else(|| doc.verification_method.first().map(|vm| vm.id.as_str()))
        .map(&absolutize);
    let ka = doc.key_agreement.first().map(|vr| absolutize(vr.get_id()));

    match signing {
        Some(signing) => (signing, ka),
        // A document with no usable verification method at all — keep the old
        // behaviour so the failure surfaces as the existing "signing secret
        // not found" warn rather than some new path.
        None => conventional(),
    }
}

/// Build the delivery-layer [`MessagingService`] over a `DidCommTransport`
/// bound to the VTC's single mediator websocket.
///
/// Mirrors `vta-sdk::didcomm_session::connect_with_secrets`: a fresh TDK with
/// the VTC's secrets, an ATM, a profile against the mediator, then a
/// **bounded** `profile_enable_websocket` (the connect can hang) before the
/// transport is bound (`DidCommTransport::new` requires the websocket first).
/// The `outbox` keyspace backs `Guaranteed` sends durably (unused by P1a's
/// `BestEffort`-only sends, but `MessagingService::new` requires a store).
async fn build_messaging(
    secrets: Vec<Secret>,
    vtc_did: &str,
    mediator_did: &str,
    outbox_ks: KeyspaceHandle,
) -> Result<(Arc<MessagingService>, Arc<ATM>), String> {
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| format!("build TDK config: {e}"))?,
    )
    .await
    .map_err(|e| format!("create TDK shared state: {e}"))?;
    for secret in secrets {
        tdk.secrets_resolver().insert(secret).await;
    }

    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| format!("build ATM config: {e}"))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| format!("create ATM: {e}"))?;

    let profile = Arc::new(
        ATMProfile::new(
            &atm,
            None,
            vtc_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|e| format!("create ATM profile: {e}"))?,
    );

    // Bounded — a `did:webvh` mediator websocket connect can hang.
    match tokio::time::timeout(
        Duration::from_secs(30),
        atm.profile_enable_websocket(&profile),
    )
    .await
    {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => {
            return Err(
                "timeout enabling websocket to mediator after 30s — mediator may be unreachable"
                    .to_string(),
            );
        }
    }

    let atm = Arc::new(atm);
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind DidComm transport: {e}"))?,
    );
    let outbox: Arc<dyn OutboxStore> = Arc::new(VtiOutboxStore::new(outbox_ks));
    // P1a uses `new` (not `with_receipts`) — no layer-receipt emission yet.
    // Clone transport + outbox before `new` consumes them: the background
    // loops need their own handles.
    let service = Arc::new(MessagingService::new(transport.clone(), outbox.clone()));
    // Durable outbox: drain sends due entries + retries; outbox-drain confirms
    // Delivered on recipient pickup; confirmation sweep settles expired entries.
    tokio::spawn(affinidi_messaging_delivery::drain_loop(
        outbox.clone(),
        transport.clone(),
        std::time::Duration::from_secs(2),
    ));
    tokio::spawn(affinidi_messaging_delivery::outbox_drain_loop(
        transport.clone(),
        outbox.clone(),
        std::time::Duration::from_secs(10),
    ));
    tokio::spawn(affinidi_messaging_delivery::confirmation_loop(
        outbox.clone(),
        std::time::Duration::from_secs(30),
    ));
    Ok((service, atm))
}

/// Start the VTC messaging listener and block until shutdown.
///
/// Owns the VTC's single mediator websocket via the delivery-layer
/// [`MessagingService`] and drives inbound dispatch off
/// [`MessagingService::subscribe`]. Replies are packed authcrypt (the VTC's
/// keys) and sent `BestEffort` back to the request's sender.
///
/// `state` carries the keyspaces + audit writer the handlers write into (the
/// same shared `AppState` the REST surface holds) and the `didcomm` slot every
/// outbound `AppState::send_to_member` reads once this publishes it.
pub async fn run_didcomm_service(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mediator_did = match &config.messaging {
        Some(m) => m.mediator_did.clone(),
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Collect secrets for the profile, keyed by the verification-method ids
    // the VTC's own DID document actually declares (see `vtc_key_ids`).
    let (signing_id, ka_id) = vtc_key_ids(state.did_resolver.as_ref(), vtc_did).await;
    let mut secrets = Vec::new();
    if let Some(s) = secrets_resolver.get_secret(&signing_id).await {
        secrets.push(s);
    } else {
        warn!(%signing_id, "VTC signing secret not found — messaging disabled");
        let _ = shutdown_rx.changed().await;
        return;
    }
    if let Some(ka_id) = ka_id.as_deref()
        && let Some(s) = secrets_resolver.get_secret(ka_id).await
    {
        secrets.push(s);
    }

    info!(
        vtc_did = %vtc_did,
        mediator = %mediator_did,
        "starting VTC messaging listener"
    );

    let (service, atm) =
        match build_messaging(secrets, vtc_did, &mediator_did, state.outbox_ks.clone()).await {
            Ok(v) => v,
            Err(e) => {
                warn!("failed to start VTC messaging: {e}");
                let _ = shutdown_rx.changed().await;
                return;
            }
        };

    // Publish the handle so any VTC component can send to a member over this
    // one connection (`AppState::send_to_member`). Set-once; it persists across
    // reconnects (the transport reconnects internally).
    let messaging = Arc::new(VtcMessaging {
        service: service.clone(),
        atm: atm.clone(),
        vtc_did: vtc_did.to_string(),
    });
    if state.didcomm.set(messaging).is_err() {
        warn!("VTC messaging handle was already published — outbound sends use the existing one");
    }

    info!("VTC messaging connected to mediator — inbound messages will be processed");

    let vtc_did_owned = vtc_did.to_string();
    let mut stream = service.subscribe();

    loop {
        tokio::select! {
            maybe = stream.next() => {
                let Some(inbound) = maybe else {
                    warn!("VTC inbound stream ended — messaging dispatcher stopping");
                    break;
                };
                // The reply goes to whoever reached us: the authenticated sender
                // when present, else the plaintext `from` (the manifest public
                // read may arrive anoncrypt). Captured before `inbound` moves
                // into `dispatch`. NOTE: we do NOT ack — `MessagingService`'s
                // own dispatcher acks after handing the message to `subscribe`.
                let reply_to = inbound.message.sender.clone().or_else(|| {
                    serde_json::from_slice::<Message>(&inbound.message.payload)
                        .ok()
                        .and_then(|m| m.from)
                });

                if let Some(reply) = dispatch(inbound, &state).await {
                    let Some(to) = reply_to else {
                        warn!(
                            reply_type = %reply.type_,
                            "computed a DIDComm reply but the inbound message had no sender/from \
                             to reply to — dropping"
                        );
                        continue;
                    };
                    let reply_id = uuid::Uuid::new_v4().to_string();
                    let reply_msg = Message::build(reply_id, reply.type_, reply.body)
                        .from(vtc_did_owned.clone())
                        .to(to.clone())
                        .thid(reply.thid)
                        .finalize();
                    match atm
                        .pack_encrypted(&reply_msg, &to, Some(&vtc_did_owned), Some(&vtc_did_owned))
                        .await
                    {
                        Ok((packed, _)) => {
                            if let Err(e) = service
                                .send(&to, packed.into_bytes(), Delivery::BestEffort)
                                .await
                            {
                                warn!(recipient = %to, error = %e, "failed to send DIDComm reply");
                            }
                        }
                        Err(e) => warn!(recipient = %to, error = %e, "failed to pack DIDComm reply"),
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("VTC messaging stopping (shutdown signalled)");
                break;
            }
        }
    }

    info!("VTC messaging stopped");
}

/// A reply the dispatcher packs + sends back to the request's sender, threaded
/// to the request. Replaces the old framework's `DIDCommResponse`.
struct Reply {
    type_: String,
    body: serde_json::Value,
    thid: String,
}

/// Route one inbound message to its handler + emit the per-request log line.
///
/// Rehydrates the plaintext DIDComm [`Message`] from the neutral payload (the
/// full DIDComm plaintext — `typ`/`from`/`body`/`id` recoverable), computes the
/// **cryptographically-authenticated** sender, and dispatches on `msg.typ`.
///
/// The authenticated sender is `inbound.message.sender` filtered by `verified`:
/// SDK 0.18.56's `DidCommTransport` sets `sender` to the DID of the key that
/// actually authcrypted the envelope (or `None` for anonymous / spoofed
/// `from`), so the anti-spoof guarantee the old local `authenticated_sender_did`
/// enforced now lives in the transport. Handlers that need a proven caller use
/// this; the two public-read handlers (manifest, credential request/present)
/// use the plaintext `msg.from` and never authorize on it.
async fn dispatch(inbound: Inbound, state: &AppState) -> Option<Reply> {
    let msg: Message = serde_json::from_slice(&inbound.message.payload).ok()?;

    // Message-pickup status heartbeat: dispatch silently (was `ignore_handler`)
    // — no handler, no log line.
    if msg.typ == MESSAGE_PICKUP_STATUS_TYPE {
        return None;
    }

    // Capability write replies (git-trust/*, governance/capability/*): the
    // hook relay's writer registered a waiter keyed by the request document
    // id; complete it and reply nothing. A reply we don't recognise (no
    // matching waiter) is dropped here rather than problem-reported.
    if msg.typ == vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE {
        if let Some((_thid, doc)) =
            vti_common::capability_client::parse_envelope_document(&msg.body)
        {
            state.capability_replies.complete(doc);
        }
        return None;
    }

    let auth_sender = inbound
        .message
        .sender
        .clone()
        .filter(|_| inbound.message.verified);

    // Per-request observability (folds the old `log_request_middleware`): every
    // inbound message that is dispatched logs type / sender / outcome / latency
    // at `info!`, except the pickup-status heartbeat handled above.
    let start = std::time::Instant::now();
    let message_type = msg.typ.clone();
    let sender_log = auth_sender
        .clone()
        .or_else(|| msg.from.clone())
        .unwrap_or_else(|| "<anon>".to_string());

    let reply = route(&msg, auth_sender, state).await;

    info!(
        target: "didcomm_server::request",
        message_type = %message_type,
        sender = %sender_log,
        status = if reply.is_some() { "ok(response)" } else { "ok(empty)" },
        latency = ?start.elapsed(),
        "Request processed"
    );
    reply
}

/// The type-routed dispatch (was the framework `Router`). The `_` arm is the
/// old fallback: a problem-report is logged and never replied to (a reply would
/// loop); any other unsupported type gets a threaded BAD_REQUEST problem-report.
async fn route(msg: &Message, auth_sender: Option<String>, state: &AppState) -> Option<Reply> {
    match msg.typ.as_str() {
        TRUST_PING_TYPE => trust_ping_reply(msg, auth_sender.as_deref()),
        JOIN_REQUEST_SUBMIT_TYPE => join_request_submit_handler(msg, auth_sender, state).await,
        JOIN_REQUEST_ACCEPT_TYPE => join_request_accept_handler(msg, auth_sender, state).await,
        JOIN_REQUEST_MANIFEST_TYPE => join_request_manifest_handler(msg, state).await,
        JOIN_REQUEST_STATUS_TYPE => join_request_status_handler(msg, auth_sender, state).await,
        MEMBER_SELF_REMOVE_TYPE => member_self_remove_handler(msg, auth_sender, state).await,
        MEMBER_VMC_TYPE => member_vmc_handler(msg, auth_sender, state).await,
        CREDENTIAL_REQUEST_TYPE => credential_request_handler(msg, state).await,
        CREDENTIAL_PRESENT_TYPE => credential_present_handler(msg, state).await,
        _ => unhandled_message(msg),
    }
}

/// Local trust-ping responder (was the framework `trust_ping_handler`). Replies
/// a `trust-ping/2.0/ping-response` on the ping's thread unless the ping didn't
/// request a response or has no (authenticated) sender to reply to.
fn trust_ping_reply(msg: &Message, auth_sender: Option<&str>) -> Option<Reply> {
    #[derive(serde::Deserialize)]
    struct PingBody {
        #[serde(default = "default_true")]
        response_requested: bool,
    }
    fn default_true() -> bool {
        true
    }

    let body: PingBody = serde_json::from_value(msg.body.clone()).unwrap_or(PingBody {
        response_requested: true,
    });
    if !body.response_requested {
        return None;
    }
    // Only pong an authenticated ping (no reply to a spoofed/anonymous sender).
    auth_sender?;
    Some(Reply {
        type_: TRUST_PONG_TYPE.to_string(),
        body: serde_json::Value::Null,
        thid: msg.id.clone(),
    })
}

/// Build a threaded problem-report reply so a sender gets a typed code +
/// comment instead of a silent internal error (which often yields no reply).
fn problem_report(thid: String, code: &str, comment: impl Into<String>) -> Reply {
    Reply {
        type_: PROBLEM_REPORT_TYPE.to_string(),
        body: problem_report_body(code, comment),
        thid,
    }
}

/// The problem-report body shape — `{code, comment}`, matching
/// [`vta_sdk::protocols::extract_problem_report`] on the receiving side.
fn problem_report_body(code: &str, comment: impl Into<String>) -> serde_json::Value {
    json!({ "code": code, "comment": comment.into() })
}

/// Pull the human-facing detail out of an inbound DIDComm v2 problem-report
/// body — `code`, `comment` (which may carry `{1}`/`{2}` placeholders), and the
/// `args` that fill them — as display strings for logging the *cause* a peer
/// reported. Missing fields read as `<none>` so the log is explicit about what
/// the peer omitted rather than silently blank.
fn problem_report_details(body: &serde_json::Value) -> (String, String, String) {
    let field = |k: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string()
    };
    let args = match body.get("args").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => "<none>".to_string(),
    };
    (field("code"), field("comment"), args)
}

/// The problem-report `code` for a business-logic [`AppError`],
/// preserving the 4xx-equivalent distinction (forbidden / unauthorized
/// / not-found / conflict / bad-request) the same way the REST boundary
/// does — instead of collapsing every outcome into `internal-error`,
/// where the sender can't tell a permission failure from a real bug.
/// Genuine infra faults keep the `internal-error` code.
///
/// `pub(crate)` so the DIDComm test harness (`test_support::dispatch_join`)
/// maps handler errors through the *same* taxonomy the production responder
/// uses — otherwise the harness (and the fuzzer driving it) would see a
/// different, staler mapping than real callers. See #485.
pub(crate) fn app_error_code(err: &AppError) -> &'static str {
    match err {
        AppError::Forbidden(_) | AppError::StepUpRequired(_) => codes::FORBIDDEN,
        AppError::Unauthorized(_) | AppError::Authentication(_) => codes::UNAUTHORIZED,
        AppError::NotFound(_) => codes::NOT_FOUND,
        AppError::Conflict(_) | AppError::IdempotencyKeyConflict => codes::CONFLICT,
        AppError::Validation(_)
        | AppError::TrustTaskMalformed(_)
        | AppError::TrustTaskMissing
        | AppError::InvalidCursor => codes::BAD_REQUEST,
        _ => codes::INTERNAL,
    }
}

/// Map a business-logic [`AppError`] to a threaded problem-report reply.
fn app_error_report(thid: String, err: &AppError) -> Reply {
    problem_report(thid, app_error_code(err), err.to_string())
}

/// Fallback for an inbound DIDComm message whose `type` matches no handler.
///
/// An unexpected/unsupported message type — e.g. a protocol-version drift
/// between the client and this VTC — is logged at `warn!` (visible at the
/// default level) with the type + sender, and (for a genuine unsupported
/// request) returns a threaded problem-report so the sender isn't left hanging.
///
/// **Never reply to a problem-report.** Replying to one with our own
/// (unsupported-type) problem-report makes the peer reply to *that*, and so on —
/// an unbounded problem-report ping-pong (observed against the mediator). A
/// problem-report is a terminal notification: log it and stop. Mirrors the VTA's
/// `handle_unknown` (`vta-service` `messaging::handlers`).
fn unhandled_message(message: &Message) -> Option<Reply> {
    if message.typ.contains("problem-report") {
        let (code, comment, args) = problem_report_details(&message.body);
        warn!(
            from = message.from.as_deref().unwrap_or("<anon>"),
            thid = message.thid.as_deref().unwrap_or("<none>"),
            code = %code,
            comment = %comment,
            args = %args,
            // The full body too: we don't always know which fields a peer's
            // problem-report carries, so log the raw JSON so the *cause* is never
            // lost to a field-name mismatch.
            body = %message.body,
            id = %message.id,
            "received unhandled problem-report — not replying (a reply would loop)"
        );
        return None;
    }
    warn!(
        message_type = %message.typ,
        from = message.from.as_deref().unwrap_or("<anon>"),
        id = %message.id,
        "inbound DIDComm message has no matching handler — dropping (unsupported message type)"
    );
    Some(problem_report(
        message.id.clone(),
        codes::BAD_REQUEST,
        format!("unsupported message type: {}", message.typ),
    ))
}

/// Render a [`TrustTaskOutcome`] as a DIDComm reply: the response document
/// (self-describing — carries its own `type`, either a `#response` or a
/// `trust-task-error`) threaded to the request id.
fn tt_didcomm_reply(outcome: TrustTaskOutcome, thid: String) -> Option<Reply> {
    let doc: serde_json::Value = match serde_json::from_slice(&outcome.body) {
        Ok(d) => d,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("reply document parse: {e}"),
            ));
        }
    };
    let typ = doc
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("https://trusttasks.org/spec/trust-task-error/0.1")
        .to_string();
    Some(Reply {
        type_: typ,
        body: doc,
        thid,
    })
}

/// Serialise an inbound DIDComm message body (the Trust Task document) to the
/// bytes the dispatcher parses.
fn inbound_doc_bytes(message: &Message) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&message.body).map_err(|e| format!("serialise inbound document: {e}"))
}

/// Pull the framework reject `code` + human-readable `message` out of a
/// serialised `trust-task-error` document, for logging. The *reason* a Trust
/// Task was refused lives in the error document's `payload` (not the HTTP
/// status), so surfacing it at the dispatch boundary is what makes a refusal
/// diagnosable. #539 made join refusals loud; #541 moved the reason into the
/// document body without teaching the log to read it back out — this restores
/// that visibility. Returns `("<unparseable>", None)` if the bytes aren't a
/// recognisable error document.
fn error_doc_summary(body: &[u8]) -> (String, Option<String>) {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ("<unparseable error document>".to_string(), None);
    };
    let code = doc
        .pointer("/payload/code")
        .and_then(|c| c.as_str())
        .unwrap_or("<unknown>")
        .to_string();
    let message = doc
        .pointer("/payload/message")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    (code, message)
}

/// The threaded UNAUTHORIZED reply for a handler that requires a proven sender
/// but got none (anonymous / spoofed `from`). The transport already refused to
/// bind an unauthenticated sender; this is the wire-visible refusal.
fn unauthorized_reply(thid: String) -> Reply {
    problem_report(
        thid,
        codes::UNAUTHORIZED,
        "DIDComm message is not authcrypt-authenticated — sender cannot be trusted",
    )
}

/// `join-requests/submit/1.0` over DIDComm — the ceremony `request` verb.
///
/// The message body is the Trust Task document; the authcrypt sender is the
/// proven holder. Dispatches through the shared [`dispatch_trust_task_core`]
/// (the same spine REST uses) and replies with a `#response` (Verdict) or a
/// `trust-task-error` document.
async fn join_request_submit_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let Some(applicant_did) = auth_sender else {
        return Some(unauthorized_reply(thid));
    };
    let applicant_log = applicant_did.clone();
    // Entry log: the request logger only fires once the handler *returns*, so an
    // explicit log here distinguishes "join received + processing started" from
    // a handler that received the request but then stalled (no completion log).
    info!(
        applicant = %applicant_did,
        thid = %thid,
        has_credential = msg
            .body
            .pointer("/payload/vp/verifiableCredential")
            .is_some(),
        "received join-request submit (Trust Task) over DIDComm"
    );
    let body = match inbound_doc_bytes(msg) {
        Ok(b) => b,
        Err(e) => return Some(problem_report(thid, codes::INTERNAL, e)),
    };
    let ctx = JoinAuthCtx::didcomm(applicant_did);
    let outcome = dispatch_trust_task_core(state, &ctx, &body).await;
    // Outcome observability (preserved from #539): a refused join must be loud —
    // it replies with a `trust-task-error` and stores nothing, so without this
    // it would look like it "silently went nowhere"; a processed one logs at
    // info. The reply document carries the typed reject code + reason, which we
    // unpack so the *why* (expired / malformed / invalid VIC / duplicate) is in
    // the log, not just the status.
    if outcome.status.is_success() {
        info!(applicant = %applicant_log, thid = %thid, "join-request processed");
    } else {
        let (code, reason) = error_doc_summary(&outcome.body);
        warn!(
            applicant = %applicant_log,
            thid = %thid,
            status = outcome.status.as_u16(),
            code = %code,
            reason = reason.as_deref().unwrap_or("<none>"),
            "join-request refused — trust-task-error returned, no member or pending request created"
        );
    }
    tt_didcomm_reply(outcome, thid)
}

/// `join-requests/accept/1.0` over DIDComm — the reciprocal step. The
/// authcrypt sender is the proven member; the document payload carries the
/// `requestId`, `vmcId`, and the member-issued reciprocal `vc`.
async fn join_request_accept_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let Some(member_did) = auth_sender else {
        return Some(unauthorized_reply(thid));
    };
    let body = match inbound_doc_bytes(msg) {
        Ok(b) => b,
        Err(e) => return Some(problem_report(thid, codes::INTERNAL, e)),
    };
    let ctx = JoinAuthCtx::didcomm(member_did);
    let outcome = dispatch_trust_task_core(state, &ctx, &body).await;
    tt_didcomm_reply(outcome, thid)
}

/// `join-requests/manifest/1.0` over DIDComm — pre-submit discovery. A
/// public read; no sender authentication required (uses the plaintext `from`).
async fn join_request_manifest_handler(msg: &Message, state: &AppState) -> Option<Reply> {
    let thid = msg.id.clone();
    let body = match inbound_doc_bytes(msg) {
        Ok(b) => b,
        Err(e) => return Some(problem_report(thid, codes::INTERNAL, e)),
    };
    let ctx = JoinAuthCtx {
        transport: JoinTransport::DIDComm,
        sender_did: msg.from.clone(),
    };
    let outcome = dispatch_trust_task_core(state, &ctx, &body).await;
    tt_didcomm_reply(outcome, thid)
}

/// `join-requests/status/1.0` over DIDComm — applicant poll. The authcrypt
/// sender is the proven applicant; the document payload carries the
/// `requestId`.
async fn join_request_status_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let Some(applicant_did) = auth_sender else {
        return Some(unauthorized_reply(thid));
    };
    let body = match inbound_doc_bytes(msg) {
        Ok(b) => b,
        Err(e) => return Some(problem_report(thid, codes::INTERNAL, e)),
    };
    let ctx = JoinAuthCtx::didcomm(applicant_did);
    let outcome = dispatch_trust_task_core(state, &ctx, &body).await;
    tt_didcomm_reply(outcome, thid)
}

/// `members/self-remove/1.0` over DIDComm (M1.11.1 twin).
///
/// Caller's DID = the *authcrypt-authenticated* sender, not the plaintext
/// `from` — otherwise a spoofed `from` would self-remove the victim
/// (`remove_inner(&caller, &caller, …)` with actor == subject). Body optionally
/// carries the disposition; defaults match REST (Member's stored
/// `departure_preference`, then PolicyDefault→Tombstone).
async fn member_self_remove_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let Some(caller_did) = auth_sender else {
        return Some(unauthorized_reply(thid));
    };

    let body: SelfRemoveBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::BAD_REQUEST,
                format!("malformed self-remove body: {e}"),
            ));
        }
    };

    let disposition = match body
        .disposition
        .as_deref()
        .map(parse_disposition)
        .transpose()
    {
        Ok(d) => d,
        Err(e) => return Some(problem_report(thid, codes::BAD_REQUEST, e)),
    };

    // DIDComm self-leave — actor == subject. The leave decision policy
    // allows self-leave unconditionally (spec §10.2); the no-last-admin
    // invariant still applies in the effect stage.
    let outcome =
        match remove_inner(state, &caller_did, &caller_did, disposition, String::new()).await {
            Ok(o) => o,
            Err(e) => return Some(app_error_report(thid, &e)),
        };

    let receipt = SelfRemoveReceiptBody {
        did: outcome.did,
        disposition: outcome.disposition,
        removed: outcome.removed,
    };
    let body = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("receipt serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: MEMBER_SELF_REMOVE_RECEIPT_TYPE.to_string(),
        body,
        thid,
    })
}

/// `members/vmc/1.0` over DIDComm — a member submits their reciprocal VMC
/// (member → community half of the membership pair), prompted or unprompted.
///
/// The authcrypt sender is the proven member; the body carries the member-issued
/// VMC. [`receive_member_vmc_inner`](crate::members::inbound_vmc::receive_member_vmc_inner)
/// verifies the issuer / subject binding + the DI proof and stores it on the
/// member row. Replies with a receipt, or a threaded problem-report on failure.
async fn member_vmc_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let Some(member_did) = auth_sender else {
        return Some(unauthorized_reply(thid));
    };

    let body: MemberVmcBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::BAD_REQUEST,
                format!("malformed member-vmc body: {e}"),
            ));
        }
    };

    let outcome =
        match crate::members::inbound_vmc::receive_member_vmc_inner(state, member_did, body.vc)
            .await
        {
            Ok(o) => o,
            Err(e) => return Some(app_error_report(thid, &e)),
        };

    let receipt = MemberVmcReceiptBody {
        member_did: outcome.member_did,
        vmc_id: outcome.vmc_id,
        status: "stored".to_string(),
    };
    let body = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("receipt serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: MEMBER_VMC_RESPONSE_TYPE.to_string(),
        body,
        thid,
    })
}

/// `credential-exchange/request/1.0` over DIDComm (Phase 3, task 3.2 wire).
///
/// The holder redeems a pre-authorized offer: the body carries an OID4VCI
/// credential request with a key-binding proof. [`credentials::redeem`] looks
/// up the pending issuance by the proof `nonce` (the pre-authorized code),
/// verifies the proof binds the intended subject, and returns the credential —
/// which we wrap in a `credential-exchange/issue` reply (the same shape the VTA
/// holder-receive handler consumes). Single-use: the offer is consumed on
/// success only.
///
/// The DIDComm `from` (authcrypt sender) authenticates the *relayer*; the
/// **inner key-binding proof** authenticates the *holder*, and the credential
/// is released only to the proven subject — so a relayer ≠ holder is safe (it
/// can't satisfy the proof), mirroring the provision-integration onion.
async fn credential_request_handler(msg: &Message, state: &AppState) -> Option<Reply> {
    let thid = msg.id.clone();
    let body: RequestBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("malformed credential request: {e}"),
            ));
        }
    };

    let response = match crate::credentials::redeem(
        &state.join_requests_ks,
        &body.credential_request,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("credential issuance: {e}"),
            ));
        }
    };

    let issue = IssueBody {
        credential_response: Some(response),
        sealed: None,
    };
    let issue_body = match serde_json::to_value(&issue) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("issue serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: CREDENTIAL_ISSUE_TYPE.to_string(),
        body: issue_body,
        thid,
    })
}

/// `credential-exchange/present/1.0` over DIDComm (close-the-join-loop, part 3).
///
/// The holder answers the VTC's DCQL query with an OID4VP `vp_token`. The present
/// replies on the query's thread (`thid`); the VTC consumes the **single-use
/// presentation challenge** keyed by that thread
/// ([`crate::credentials::present_challenge`]) to recover the expected nonce +
/// audience (freshness / replay), cryptographically verifies the `vp_token`, runs
/// the join decision, and — on `allow` — admits the proven holder and issues the
/// MembershipCredential. Replies with a join receipt (request id + status).
///
/// The DIDComm `from` (authcrypt sender) authenticates the *relayer*; the
/// **holder kb-jwt** inside the `vp_token` authenticates the *holder* and binds
/// the verifier's nonce + audience — so a relayer ≠ holder is safe (it cannot
/// forge the kb-jwt), mirroring the request-handler onion.
async fn credential_present_handler(msg: &Message, state: &AppState) -> Option<Reply> {
    // The reply threads to the present's own id (not the query thread).
    let thid = msg.id.clone();
    let body: PresentBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("malformed present body: {e}"),
            ));
        }
    };

    // The present replies on the query's thread; the challenge is keyed by it.
    let thread_id = match msg.thid.clone() {
        Some(t) => t,
        None => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                "present carries no thread id (thid) to correlate its challenge",
            ));
        }
    };

    let now = chrono::Utc::now();
    let challenge = match crate::credentials::present_challenge::consume(
        &state.join_requests_ks,
        &thread_id,
        now,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("present challenge: {e}"),
            ));
        }
    };

    let outcome = match crate::routes::join_requests::present::present_and_decide_join(
        state,
        &body.vp_token,
        &challenge.aud,
        &challenge.nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("present decision: {e}"),
            ));
        }
    };

    // On auto-admit, deliver the issued MembershipCredential (+ role VEC) to the
    // proven holder's wallet over DIDComm — the holder only gets a receipt on the
    // reply thread, so without this the credential it just earned would never
    // reach it. Best-effort: the credential is already issued + persisted, so a
    // delivery failure is logged (the holder/admin can re-fetch), not fatal.
    if let Some(admit) = outcome.admit.as_deref() {
        let holder_did = outcome.request.applicant_did.clone();
        if let Err(e) =
            crate::credentials::delivery::deliver_membership_credentials(state, &holder_did, admit)
                .await
        {
            warn!(holder = %holder_did, request = %outcome.request.id, error = %e, "membership-credential delivery failed; credential is issued and can be re-delivered");
        } else {
            info!(holder = %holder_did, request = %outcome.request.id, "queued membership credentials for guaranteed delivery to holder");
        }
    }

    let status = serde_json::to_value(outcome.request.status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let receipt = JoinRequestSubmitReceiptBody {
        request_id: outcome.request.id,
        status,
    };
    let receipt_body = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("receipt serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: JOIN_REQUEST_SUBMIT_RECEIPT_TYPE.to_string(),
        body: receipt_body,
        thid,
    })
}

fn parse_disposition(s: &str) -> Result<Disposition, String> {
    match s.to_ascii_lowercase().as_str() {
        "purge" => Ok(Disposition::Purge),
        "tombstone" => Ok(Disposition::Tombstone),
        "historical" => Ok(Disposition::Historical),
        "policydefault" => Ok(Disposition::PolicyDefault),
        other => Err(format!(
            "unknown disposition '{other}' (expected purge|tombstone|historical|policydefault)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn problem_report_details_extracts_code_comment_and_args() {
        let (code, comment, args) = problem_report_details(&json!({
            "code": "e.p.xfer.cant-use-endpoint",
            "comment": "Unable to use the {1} endpoint for {2}.",
            "args": ["https://x.example/finance", "did:example:1234"],
        }));
        assert_eq!(code, "e.p.xfer.cant-use-endpoint");
        assert_eq!(comment, "Unable to use the {1} endpoint for {2}.");
        assert_eq!(args, "https://x.example/finance, did:example:1234");
    }

    #[test]
    fn problem_report_details_marks_missing_fields() {
        let (code, comment, args) = problem_report_details(&json!({}));
        assert_eq!(code, "<none>");
        assert_eq!(comment, "<none>");
        assert_eq!(args, "<none>");
    }

    #[test]
    fn app_error_maps_to_typed_problem_report_codes() {
        // 4xx-equivalent business outcomes get distinct codes instead
        // of collapsing into internal-error (P3.6 part 2).
        assert_eq!(
            app_error_code(&AppError::Forbidden("nope".into())),
            codes::FORBIDDEN
        );
        assert_eq!(
            app_error_code(&AppError::Unauthorized("nope".into())),
            codes::UNAUTHORIZED
        );
        assert_eq!(
            app_error_code(&AppError::NotFound("nope".into())),
            codes::NOT_FOUND
        );
        assert_eq!(
            app_error_code(&AppError::Conflict("dup".into())),
            codes::CONFLICT
        );
        assert_eq!(
            app_error_code(&AppError::Validation("bad".into())),
            codes::BAD_REQUEST
        );
        // Genuine infra faults stay internal.
        assert_eq!(
            app_error_code(&AppError::Internal("boom".into())),
            codes::INTERNAL
        );
    }

    #[test]
    fn problem_report_body_is_code_and_comment() {
        // The body shape must match `vta_sdk::protocols::extract_problem_report`.
        let body = problem_report_body(codes::BAD_REQUEST, "malformed body");
        let (code, comment) = vta_sdk::protocols::extract_problem_report(&body);
        assert_eq!(code, codes::BAD_REQUEST);
        assert_eq!(comment, "malformed body");
    }
}
