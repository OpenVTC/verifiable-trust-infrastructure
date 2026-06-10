use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, Extension,
    HandlerContext, ListenerConfig, ListenerEvent, MESSAGE_PICKUP_STATUS_TYPE, RestartPolicy,
    RetryConfig, Router, TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use vta_sdk::protocols::credential_exchange::PRESENT as CREDENTIAL_PRESENT_TYPE;
use vta_sdk::protocols::credential_exchange::REQUEST as CREDENTIAL_REQUEST_TYPE;
use vta_sdk::protocols::credential_exchange::{
    ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody, PresentBody, RequestBody,
};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_ACCEPT_RECEIPT_TYPE, JOIN_REQUEST_ACCEPT_TYPE,
    JOIN_REQUEST_MANIFEST_RESPONSE_TYPE, JOIN_REQUEST_MANIFEST_TYPE,
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_STATUS_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
    JOIN_REQUEST_SUBMIT_TYPE, JoinRequestAcceptBody, JoinRequestAcceptReceiptBody,
    JoinRequestStatusBody, JoinRequestSubmitBody, JoinRequestSubmitReceiptBody,
    MEMBER_SELF_REMOVE_RECEIPT_TYPE, MEMBER_SELF_REMOVE_TYPE, SelfRemoveBody,
    SelfRemoveReceiptBody,
};

use crate::config::AppConfig;
use crate::join::JoinTransport;
use crate::members::Disposition;
use crate::routes::join_requests::accept::accept_inner;
use crate::routes::join_requests::manifest::manifest_inner;
use crate::routes::join_requests::status::status_inner;
use crate::routes::join_requests::submit::submit_inner;
use crate::routes::members::remove::remove_inner;
use crate::server::AppState;

/// Start the DIDComm service and block until shutdown.
///
/// Uses `DIDCommService` for automatic mediator connection management,
/// reconnection with backoff, and typed message routing.
///
/// `state` is needed because the join-request handler writes
/// rows into the keyspaces + audit log — same shared
/// `AppState` the REST surface holds. Passed as a `Router`
/// extension so handlers extract it via `Extension<AppState>`.
pub async fn run_didcomm_service(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mediator_did = match &config.messaging {
        Some(m) => &m.mediator_did,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Collect secrets for the TDKProfile
    let signing_id = format!("{vtc_did}#key-0");
    let ka_id = format!("{vtc_did}#key-1");
    let mut secrets = Vec::new();
    if let Some(s) = secrets_resolver.get_secret(&signing_id).await {
        secrets.push(s);
    } else {
        warn!("VTC signing secret not found — messaging disabled");
        let _ = shutdown_rx.changed().await;
        return;
    }
    if let Some(s) = secrets_resolver.get_secret(&ka_id).await {
        secrets.push(s);
    }

    let profile = TDKProfile::new("VTC", vtc_did, Some(mediator_did), secrets);

    let service_config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "vtc-main".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig {
                    initial_delay_secs: 5,
                    max_delay_secs: 60,
                },
            },
            ..Default::default()
        }],
    };

    // Build the router: trust-ping + ignore-pickup-status + the
    // VTC's protocol surface. `Extension<AppState>` is how the
    // join-request handler reaches the keyspaces / audit writer.
    let router = match Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))
        .and_then(|r| r.route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler)))
        .and_then(|r| {
            r.route(
                JOIN_REQUEST_SUBMIT_TYPE,
                handler_fn(join_request_submit_handler),
            )
        })
        .and_then(|r| {
            r.route(
                JOIN_REQUEST_ACCEPT_TYPE,
                handler_fn(join_request_accept_handler),
            )
        })
        .and_then(|r| {
            r.route(
                JOIN_REQUEST_MANIFEST_TYPE,
                handler_fn(join_request_manifest_handler),
            )
        })
        .and_then(|r| {
            r.route(
                JOIN_REQUEST_STATUS_TYPE,
                handler_fn(join_request_status_handler),
            )
        })
        .and_then(|r| {
            r.route(
                MEMBER_SELF_REMOVE_TYPE,
                handler_fn(member_self_remove_handler),
            )
        })
        .and_then(|r| {
            r.route(
                CREDENTIAL_REQUEST_TYPE,
                handler_fn(credential_request_handler),
            )
        })
        .and_then(|r| {
            r.route(
                CREDENTIAL_PRESENT_TYPE,
                handler_fn(credential_present_handler),
            )
        }) {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to build DIDComm router: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    let shutdown_token = CancellationToken::new();
    let service = match DIDCommService::start(service_config, router, shutdown_token.clone()).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to start DIDComm service: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Wait for the mediator connection
    if let Err(e) = service
        .wait_connected("vtc-main", Duration::from_secs(30))
        .await
    {
        warn!("DIDComm listener not connected after 30s: {e}");
    }

    // Log lifecycle events in background
    let mut event_rx = service.subscribe();
    let event_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    info!(listener = %listener_id, "DIDComm listener connected");
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    warn!(
                        listener = %listener_id,
                        error = error.as_deref().unwrap_or("none"),
                        "DIDComm listener disconnected"
                    );
                }
                Ok(ListenerEvent::Restarting {
                    listener_id,
                    attempt,
                    delay,
                }) => {
                    info!(
                        listener = %listener_id,
                        attempt,
                        delay_secs = delay.as_secs(),
                        "DIDComm listener restarting"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "DIDComm event logger lagged");
                }
            }
        }
    });

    info!("DIDComm service started");

    // Block until shutdown
    let _ = shutdown_rx.changed().await;

    // Graceful shutdown
    service.shutdown().await;
    event_task.abort();
    info!("DIDComm service stopped");
}

/// `join-requests/submit/1.0` over DIDComm (M1.8.2).
///
/// The applicant DID is the DIDComm `from` field — the
/// authcrypt sender. No separate holder-binding signature
/// needed (the envelope IS the proof). Calls into the same
/// `submit_inner` the REST endpoint uses.
async fn join_request_submit_handler(
    message: Message,
    meta: UnpackMetadata,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let applicant_did = authenticated_sender_did(&message, &meta)?;
    let body: JoinRequestSubmitBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed join-request body: {e}")))?;

    let outcome = submit_inner(
        &state,
        applicant_did,
        body.vp,
        body.registry_consent,
        body.extensions,
        None,
        JoinTransport::DIDComm,
    )
    .await
    .map_err(|e| DIDCommServiceError::Internal(format!("submit failed: {e}")))?;

    // The DIDComm receipt carries the request id + status; a sealed
    // credential bundle for an auto-admitted applicant lands in a
    // follow-up DIDComm message.
    let receipt = JoinRequestSubmitReceiptBody {
        request_id: outcome.request.id,
        status: outcome.request.status.to_string(),
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, body).thid(message.id),
    ))
}

/// `join-requests/accept/1.0` over DIDComm — the reciprocal step.
///
/// The member DID is the DIDComm `from` field (authcrypt sender), so no
/// separate holder-binding signature is needed (`signature_hex = None`).
/// The body carries the `requestId` (no path over DIDComm), the `vmcId`,
/// and the member-issued reciprocal `vc`. Calls into the same
/// `accept_inner` the REST endpoint uses; replies with an accept receipt.
async fn join_request_accept_handler(
    message: Message,
    meta: UnpackMetadata,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let member_did = authenticated_sender_did(&message, &meta)?;
    let body: JoinRequestAcceptBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed join-accept body: {e}")))?;

    let outcome = accept_inner(
        &state,
        body.request_id,
        member_did,
        body.vmc_id,
        body.vc,
        None,
        JoinTransport::DIDComm,
    )
    .await
    .map_err(|e| DIDCommServiceError::Internal(format!("accept failed: {e}")))?;

    let receipt = JoinRequestAcceptReceiptBody {
        request_id: outcome.request_id,
        status: "accepted".to_string(),
        reciprocal_vc_id: outcome.reciprocal_vc_id,
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_ACCEPT_RECEIPT_TYPE, body).thid(message.id),
    ))
}

/// `join-requests/manifest/1.0` over DIDComm — pre-submit discovery.
///
/// A read: the empty request body returns the community's join evidence
/// requirements. No sender authentication needed (manifest is public).
async fn join_request_manifest_handler(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let manifest = manifest_inner(&state)
        .await
        .map_err(|e| DIDCommServiceError::Internal(format!("manifest failed: {e}")))?;
    let body = serde_json::to_value(&manifest)
        .map_err(|e| DIDCommServiceError::Internal(format!("manifest serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_MANIFEST_RESPONSE_TYPE, body).thid(message.id),
    ))
}

/// `join-requests/status/1.0` over DIDComm — applicant poll.
///
/// `applicantDid` is the DIDComm `from` field (authcrypt sender), so no
/// separate holder-binding signature is needed (`signature_hex = None`).
/// The body carries the `requestId`.
async fn join_request_status_handler(
    message: Message,
    meta: UnpackMetadata,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let applicant_did = authenticated_sender_did(&message, &meta)?;
    let body: JoinRequestStatusBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed status body: {e}")))?;

    let resp = status_inner(&state, body.request_id, applicant_did, None)
        .await
        .map_err(|e| DIDCommServiceError::Internal(format!("status failed: {e}")))?;
    let body = serde_json::to_value(&resp)
        .map_err(|e| DIDCommServiceError::Internal(format!("status serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_STATUS_RESPONSE_TYPE, body).thid(message.id),
    ))
}

/// `members/self-remove/1.0` over DIDComm (M1.11.1 twin).
///
/// Caller's DID = the DIDComm `from` field. Body optionally
/// carries the disposition; defaults match REST (Member's
/// stored `departure_preference`, then PolicyDefault→Tombstone).
async fn member_self_remove_handler(
    message: Message,
    meta: UnpackMetadata,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    // The caller's DID is the *authcrypt-authenticated* sender, not the
    // plaintext `from` — otherwise a spoofed `from` would self-remove the
    // victim (`remove_inner(&caller, &caller, …)` with actor == subject).
    let caller_did = authenticated_sender_did(&message, &meta)?;

    let body: SelfRemoveBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed self-remove body: {e}")))?;

    let disposition = body
        .disposition
        .as_deref()
        .map(parse_disposition)
        .transpose()
        .map_err(DIDCommServiceError::Internal)?;

    // DIDComm self-leave — actor == subject. The leave decision policy
    // allows self-leave unconditionally (spec §10.2); the no-last-admin
    // invariant still applies in the effect stage.
    let outcome = remove_inner(&state, &caller_did, &caller_did, disposition, String::new())
        .await
        .map_err(|e| DIDCommServiceError::Internal(format!("self-remove: {e}")))?;

    let receipt = SelfRemoveReceiptBody {
        did: outcome.did,
        disposition: outcome.disposition,
        removed: outcome.removed,
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(MEMBER_SELF_REMOVE_RECEIPT_TYPE, body).thid(message.id),
    ))
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
async fn credential_request_handler(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body: RequestBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed credential request: {e}")))?;

    let response = crate::credentials::redeem(
        &state.join_requests_ks,
        &body.credential_request,
        chrono::Utc::now(),
    )
    .await
    .map_err(|e| DIDCommServiceError::Internal(format!("credential issuance: {e}")))?;

    let issue = IssueBody {
        credential_response: Some(response),
        sealed: None,
    };
    let issue_body = serde_json::to_value(&issue)
        .map_err(|e| DIDCommServiceError::Internal(format!("issue serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(CREDENTIAL_ISSUE_TYPE, issue_body).thid(message.id),
    ))
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
async fn credential_present_handler(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body: PresentBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed present body: {e}")))?;

    // The present replies on the query's thread; the challenge is keyed by it.
    let thread_id = message.thid.clone().ok_or_else(|| {
        DIDCommServiceError::Internal(
            "present carries no thread id (thid) to correlate its challenge".into(),
        )
    })?;

    let now = chrono::Utc::now();
    let challenge =
        crate::credentials::present_challenge::consume(&state.join_requests_ks, &thread_id, now)
            .await
            .map_err(|e| DIDCommServiceError::Internal(format!("present challenge: {e}")))?;

    let outcome = crate::routes::join_requests::present::present_and_decide_join(
        &state,
        &body.vp_token,
        &challenge.aud,
        &challenge.nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .map_err(|e| DIDCommServiceError::Internal(format!("present decision: {e}")))?;

    // On auto-admit, deliver the issued MembershipCredential (+ role VEC) to the
    // proven holder's wallet over DIDComm — the holder only gets a receipt on the
    // reply thread, so without this the credential it just earned would never
    // reach it. Best-effort: the credential is already issued + persisted, so a
    // delivery failure is logged (the holder/admin can re-fetch), not fatal.
    if let Some(admit) = outcome.admit.as_deref() {
        let holder_did = outcome.request.applicant_did.clone();
        if let Err(e) =
            crate::credentials::delivery::deliver_membership_credentials(&state, &holder_did, admit)
                .await
        {
            warn!(holder = %holder_did, request = %outcome.request.id, error = %e, "membership-credential delivery failed; credential is issued and can be re-delivered");
        } else {
            info!(holder = %holder_did, request = %outcome.request.id, "delivered membership credentials to holder over DIDComm");
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
    let receipt_body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, receipt_body).thid(message.id),
    ))
}

/// Resolve the **authenticated** sender DID of an inbound DIDComm message.
///
/// The listener fills `ctx.sender_did` / `message.from` from the *plaintext*
/// `from` header, which the sender controls. An attacker can authcrypt a
/// message with their **own** key (so the unpack succeeds and
/// `meta.authenticated == true`) while setting `from` to a *victim's* DID —
/// yielding a message whose `from` (and thus `ctx.sender_did`) is the victim.
/// Handlers that trust `ctx.sender_did` as the proven sender would then act
/// *as the victim* (submit a join, self-remove the victim, …). The
/// `affinidi-messaging-sdk` unpack does not cross-check `from` against the
/// authcrypt sender key, and `MessagePolicy::require_authenticated` only
/// asserts *some* key authenticated the envelope — not *which* DID.
///
/// The cryptographically-authenticated identity is the DID of
/// `meta.encrypted_from_kid` (the key that actually encrypted the message).
/// This binds the two: the message must be authcrypt-authenticated (not
/// anoncrypt / plaintext) **and** its `from` must equal that DID, else the
/// sender is spoofed and we refuse.
fn authenticated_sender_did(
    message: &Message,
    meta: &UnpackMetadata,
) -> Result<String, DIDCommServiceError> {
    if !meta.authenticated || meta.anonymous_sender {
        return Err(DIDCommServiceError::Internal(
            "DIDComm message is not authcrypt-authenticated — sender cannot be trusted".into(),
        ));
    }
    let from = message.from.as_deref().ok_or_else(|| {
        DIDCommServiceError::Internal(
            "authenticated DIDComm message carries no `from` — sender cannot be trusted".into(),
        )
    })?;
    let skid = meta.encrypted_from_kid.as_deref().ok_or_else(|| {
        DIDCommServiceError::Internal(
            "authenticated DIDComm message exposes no sender key id — sender cannot be trusted"
                .into(),
        )
    })?;
    // `encrypted_from_kid` is a verificationMethod id (`<did>#<fragment>`);
    // the authenticated sender is its DID prefix. A DID never contains `#`,
    // so splitting on the first `#` recovers it.
    let authenticated_did = skid.split_once('#').map(|(did, _)| did).unwrap_or(skid);
    if authenticated_did != from {
        return Err(DIDCommServiceError::Internal(format!(
            "DIDComm sender spoofed: `from` ({from}) does not match the authcrypt sender key \
             ({authenticated_did})"
        )));
    }
    Ok(from.to_string())
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

    fn msg(from: Option<&str>) -> Message {
        let mut b = Message::build("id-1".to_string(), "test/1.0".to_string(), json!({}));
        if let Some(f) = from {
            b = b.from(f.to_string());
        }
        b.finalize()
    }

    fn meta(authenticated: bool, anonymous_sender: bool, skid: Option<&str>) -> UnpackMetadata {
        UnpackMetadata {
            encrypted: true,
            authenticated,
            anonymous_sender,
            encrypted_from_kid: skid.map(str::to_string),
            ..Default::default()
        }
    }

    const ALICE: &str = "did:key:z6MkAlice";
    const ALICE_SKID: &str = "did:key:z6MkAlice#z6MkAlice";

    #[test]
    fn accepts_authenticated_sender_whose_from_matches_the_authcrypt_key() {
        let got = authenticated_sender_did(&msg(Some(ALICE)), &meta(true, false, Some(ALICE_SKID)))
            .unwrap();
        assert_eq!(got, ALICE);
    }

    #[test]
    fn rejects_spoofed_from_authcrypted_with_a_different_key() {
        // The core impersonation attack: authcrypt with the attacker's key
        // (so `authenticated == true`) but set `from` to the victim. The
        // `from` must match the key that actually encrypted the message.
        let victim = "did:key:z6MkVictim";
        let attacker_skid = "did:key:z6MkAttacker#z6MkAttacker";
        let err =
            authenticated_sender_did(&msg(Some(victim)), &meta(true, false, Some(attacker_skid)))
                .unwrap_err();
        assert!(
            format!("{err}").contains("spoofed"),
            "expected spoof rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_unauthenticated_anoncrypt() {
        // anoncrypt — no proven sender at all.
        let err =
            authenticated_sender_did(&msg(Some(ALICE)), &meta(false, true, None)).unwrap_err();
        assert!(
            format!("{err}").contains("not authcrypt-authenticated"),
            "expected auth rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_authenticated_but_anonymous_sender() {
        let err = authenticated_sender_did(&msg(Some(ALICE)), &meta(true, true, Some(ALICE_SKID)))
            .unwrap_err();
        assert!(
            format!("{err}").contains("not authcrypt-authenticated"),
            "expected auth rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_authenticated_message_with_no_from() {
        let err =
            authenticated_sender_did(&msg(None), &meta(true, false, Some(ALICE_SKID))).unwrap_err();
        assert!(
            format!("{err}").contains("no `from`"),
            "expected missing-from rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_authenticated_message_with_no_sender_key_id() {
        let err =
            authenticated_sender_did(&msg(Some(ALICE)), &meta(true, false, None)).unwrap_err();
        assert!(
            format!("{err}").contains("no sender key id"),
            "expected missing-skid rejection, got: {err}"
        );
    }
}
