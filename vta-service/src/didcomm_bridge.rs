use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_delivery::{Delivery, MessagingService, MessagingStatus};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use tokio::sync::OnceCell;

use crate::error::{AppError, bad_gateway_error};
use vta_sdk::protocols::{PROBLEM_REPORT_TYPE, extract_problem_report};

/// Translate a remote peer's DIDComm problem-report into a typed [`AppError`].
///
/// Every problem report used to collapse into a 502, which made a remote's
/// "you sent an invalid path" indistinguishable from a genuine upstream
/// outage: both reached the operator as a 5xx, and the SDK maps *any* 5xx to
/// `VtaError::Server`, whose CLI hint reads "This is a VTA-side failure.
/// Check server logs or contact the operator." That is precisely the wrong
/// thing to tell someone whose request the *host* rejected for a reason they
/// can act on.
///
/// Codes are namespaced per protocol (`e.p.did.*`, `e.p.registration.*`,
/// `e.p.msg.*`) but the trailing segment is the shared vocabulary, so match
/// on that. The did-hosting service's `AppError::didcomm_code()` is the
/// authoritative producer for the `e.p.did.*` arm; this is its inverse.
///
/// Unrecognised codes — and every `internal-error` — stay a 502. A failure we
/// can't attribute to the caller *is* a gateway failure, and silently
/// re-labelling an upstream crash as a 400 would be a worse lie than the one
/// being fixed.
///
/// Remote auth denials map to [`AppError::Forbidden`] (403), never
/// `Unauthorized` (401): the caller's credential to *this* VTA is valid — it
/// is the VTA's own DID that lacks rights on the host. A 401 would make the
/// CLI print a misleading "token may be expired" hint (see the
/// `e.p.msg.forbidden` note in the workspace CLAUDE.md).
fn problem_report_to_app_error(code: &str, comment: &str) -> AppError {
    let detail = format!("remote peer rejected the request: {comment} [{code}]");
    match code.rsplit('.').next().unwrap_or_default() {
        "unauthorized" | "forbidden" => AppError::Forbidden(detail),
        "path-unavailable" | "conflict" => AppError::Conflict(detail),
        "mnemonic-not-found" | "not-found" => AppError::NotFound(detail),
        "path-invalid" | "invalid-log" | "witness-invalid" | "validation-error" | "bad-request"
        | "replay-detected" | "size-exceeded" | "quota-exceeded" => AppError::Validation(detail),
        _ => bad_gateway_error(detail),
    }
}

/// The live delivery-layer wiring the bridge sends through, published once the
/// [`MessagingService`] is built in `server::run`.
struct BridgeInner {
    /// The one delivery-layer service over the VTA's mediator websocket(s).
    /// Outbound `send`/`request` route through its current **primary**;
    /// `request_via` targets a named (candidate) transport for the mediator
    /// handshake.
    service: Arc<MessagingService>,
    /// The ATM used to authcrypt-pack outbound messages (pack sender = the
    /// VTA's DID).
    atm: ATM,
    /// The VTA's own DID — the `from` on every packed outbound message.
    vta_did: String,
}

/// Outbound DIDComm adapter over the reliable-messaging delivery layer.
///
/// **D2 P2a cut-over**: this used to wrap the
/// `affinidi-messaging-didcomm-service` framework's `DIDCommService` + a
/// thread-id pending-map. It now wraps the delivery-layer [`MessagingService`]:
/// `send_and_wait` → [`MessagingService::request`] (the outbound message id is
/// the correlation thread id), `send_guaranteed` → [`MessagingService::send`] with
/// [`Delivery::Guaranteed`], `send_and_wait_via` → [`MessagingService::request_via`]
/// (a named candidate transport, for the mediator handshake). The delivery
/// dispatcher owns thread-id correlation, so the old pending-map / `try_complete`
/// / `send_message_with_retry` are gone.
///
/// The public method surface is unchanged so the ~25 WebVH / provision / CLI /
/// test call-sites that thread `Arc<DIDCommBridge>` compile untouched;
/// [`placeholder`](Self::placeholder) stays free (offline CLI + tests never
/// send). The live wiring is published once via [`set_messaging`](Self::set_messaging).
pub struct DIDCommBridge {
    inner: OnceCell<BridgeInner>,
    /// The primary transport id (e.g. `"vta-main"`). Retained for parity with
    /// the old listener id; outbound always routes through the service's
    /// current primary regardless.
    #[allow(dead_code)]
    listener_id: String,
}

impl DIDCommBridge {
    /// Create a new bridge. Call [`set_messaging`](Self::set_messaging) after
    /// the delivery-layer `MessagingService` starts to enable outbound sends.
    pub fn new(listener_id: impl Into<String>) -> Self {
        Self {
            inner: OnceCell::new(),
            listener_id: listener_id.into(),
        }
    }

    /// Create a placeholder bridge for test/CLI contexts that never send.
    /// Attempting to send via a placeholder returns an error.
    pub fn placeholder() -> Self {
        Self::new("")
    }

    /// Publish the live delivery-layer wiring. Called once from `server::run`
    /// after the `MessagingService` is built over the mediator websocket.
    pub fn set_messaging(&self, service: Arc<MessagingService>, atm: ATM, vta_did: String) {
        let _ = self.inner.set(BridgeInner {
            service,
            atm,
            vta_did,
        });
    }

    /// The live [`MessagingService`] handle, or `None` before
    /// [`set_messaging`](Self::set_messaging). Used by the live mediator
    /// handshake prover, which drives `add_transport`/`request_via`/`promote`
    /// against it.
    pub fn messaging_handle(&self) -> Option<Arc<MessagingService>> {
        self.inner.get().map(|i| i.service.clone())
    }

    /// The ATM (for building a candidate transport's profile + packing during
    /// the mediator handshake), or `None` before the service is published.
    pub fn atm(&self) -> Option<ATM> {
        self.inner.get().map(|i| i.atm.clone())
    }

    /// The VTA's own DID, or `None` before the service is published.
    pub fn vta_did(&self) -> Option<String> {
        self.inner.get().map(|i| i.vta_did.clone())
    }

    /// The live, **non-latched** messaging status (R6.2), or `None` before the
    /// service is published. Read straight off [`MessagingService::status`],
    /// which reflects each transport's live connection signal and can go false
    /// again after boot.
    pub fn messaging_status_str(&self) -> Option<String> {
        self.inner.get().map(|i| {
            match i.service.status() {
                MessagingStatus::Connected => "connected",
                MessagingStatus::Degraded => "degraded",
                // `MessagingStatus` is `#[non_exhaustive]`; treat any other
                // (including `Disconnected`) as disconnected.
                _ => "disconnected",
            }
            .to_string()
        })
    }

    fn inner(&self) -> Result<&BridgeInner, AppError> {
        self.inner
            .get()
            .ok_or_else(|| AppError::Internal("DIDComm messaging not initialized".into()))
    }

    /// Authcrypt-pack `body` as a DIDComm message from the VTA to `recipient`.
    /// Returns `(message_id, packed_bytes)`; the id is the correlation thread
    /// id for a request/reply round trip.
    async fn pack(
        inner: &BridgeInner,
        recipient: &str,
        msg_type: &str,
        body: serde_json::Value,
        timeout_secs: Option<u64>,
    ) -> Result<(String, Vec<u8>), AppError> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut builder = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(inner.vta_did.clone())
            .to(recipient.to_string())
            .created_time(now);
        if let Some(secs) = timeout_secs {
            builder = builder.expires_time(now + secs);
        }
        let msg = builder.finalize();
        let (packed, _meta) = inner
            .atm
            .pack_encrypted(&msg, recipient, Some(&inner.vta_did), Some(&inner.vta_did))
            .await
            .map_err(|e| bad_gateway_error(format!("failed to pack message: {e}")))?;
        Ok((msg_id, packed.into_bytes()))
    }

    /// Durably enqueue `body` as a **Guaranteed** DIDComm push to
    /// `recipient_did`: written to the outbox and drained with exponential
    /// backoff so a websocket reconnect can no longer silently drop it (R1.1 —
    /// the exact failure a bare `BestEffort` send hid). The push hop-accepts to
    /// the mediator **once** (then it is `Sent`, never re-sent — only a *failed*
    /// hop retries), settling `Delivered` on §5a evidence or `Unconfirmed` when
    /// the `deliver_by` window passes; never a silent success.
    ///
    /// Used for the delegated step-up / task-consent pushes — the approver's
    /// device replies later via a separate out-of-thread call, so this is
    /// fire-and-forget from the request thread's point of view, but now
    /// delivery-durable. `idempotency_key` dedups re-enqueues of the same logical
    /// push (pass the request/thread id). Returns once durably **queued**, not
    /// once delivered. `_listener_id` is retained for call-site parity; outbound
    /// routes through the service's current primary transport.
    pub async fn send_guaranteed(
        &self,
        _listener_id: &str,
        recipient_did: &str,
        msg_type: &str,
        body: serde_json::Value,
        idempotency_key: Option<String>,
        deliver_by: Duration,
    ) -> Result<(), AppError> {
        let inner = self.inner()?;
        // No DIDComm `expires_time`: `deliver_by` bounds the outbox *hop-retry*
        // window (how long we retry reaching the mediator), NOT the message's
        // content validity. A held push must remain collectable until the
        // request's own `expiresAt` — a shorter message expiry could make the
        // mediator drop it before an offline device reconnects. (This preserves
        // the prior `send_oneway` behaviour, which set no expiry.)
        let (_msg_id, packed) = Self::pack(inner, recipient_did, msg_type, body, None).await?;
        inner
            .service
            .send(
                recipient_did,
                packed,
                Delivery::Guaranteed {
                    idempotency_key,
                    ordering_key: None,
                    deliver_by,
                },
            )
            .await
            .map_err(|e| bad_gateway_error(format!("failed to enqueue guaranteed push: {e}")))?;
        Ok(())
    }

    /// Send a DIDComm message and await the correlated reply, validating it
    /// against `expected_type` / `problem_report_type` exactly as before.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_and_wait(
        &self,
        server_did: &str,
        msg_type: &str,
        body: serde_json::Value,
        expected_type: &str,
        problem_report_type: &str,
        timeout_secs: u64,
    ) -> Result<Message, AppError> {
        let inner = self.inner()?;
        let (msg_id, packed) =
            Self::pack(inner, server_did, msg_type, body, Some(timeout_secs)).await?;
        // The outbound message id IS the correlation thread id: the reply
        // threads to it (`thid == request.id`), and the delivery dispatcher
        // demuxes the reply to this waiter by that thread id.
        let received = inner
            .service
            .request(
                server_did,
                packed,
                &msg_id,
                Duration::from_secs(timeout_secs),
            )
            .await
            .map_err(|e| bad_gateway_error(format!("failed to send message: {e}")))?;
        Self::validate_reply(received.payload, expected_type, problem_report_type)
    }

    /// Like [`send_and_wait`](Self::send_and_wait) but sends over a **named**
    /// (non-primary) installed transport — the candidate mediator being proven
    /// during a migration handshake — while still awaiting the correlated reply
    /// on the merged dispatcher.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_and_wait_via(
        &self,
        listener_id: &str,
        recipient_did: &str,
        msg_type: &str,
        body: serde_json::Value,
        expected_type: &str,
        problem_report_type: &str,
        timeout_secs: u64,
    ) -> Result<Message, AppError> {
        let inner = self.inner()?;
        let (msg_id, packed) =
            Self::pack(inner, recipient_did, msg_type, body, Some(timeout_secs)).await?;
        let received = inner
            .service
            .request_via(
                listener_id,
                recipient_did,
                packed,
                &msg_id,
                Duration::from_secs(timeout_secs),
            )
            .await
            .map_err(|e| bad_gateway_error(format!("failed to send message: {e}")))?;
        Self::validate_reply(received.payload, expected_type, problem_report_type)
    }

    /// Parse a delivery-layer reply payload (the full plaintext DIDComm message
    /// JSON) and validate it: a problem-report maps through
    /// [`problem_report_to_app_error`]; any non-`expected_type` reply is a 502.
    fn validate_reply(
        payload: Vec<u8>,
        expected_type: &str,
        problem_report_type: &str,
    ) -> Result<Message, AppError> {
        let response: Message = serde_json::from_slice(&payload)
            .map_err(|e| bad_gateway_error(format!("failed to parse DIDComm response: {e}")))?;

        if response.typ == problem_report_type || response.typ == PROBLEM_REPORT_TYPE {
            let (code, comment) = extract_problem_report(&response.body);
            return Err(problem_report_to_app_error(&code, &comment));
        }

        if response.typ != expected_type {
            return Err(bad_gateway_error(format!(
                "unexpected response type: expected {expected_type}, got {}",
                response.typ
            )));
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    /// The status the operator actually receives — drive the real
    /// `IntoResponse` rather than re-asserting the variant, so a future
    /// change to `AppError`'s status mapping can't quietly re-break this.
    fn status_of(code: &str) -> StatusCode {
        problem_report_to_app_error(code, "boom")
            .into_response()
            .status()
    }

    /// The did-hosting service's `AppError::didcomm_code()` is the
    /// authoritative producer of these codes; this pins our inverse of it.
    /// The bug this fixes: every one of these used to come back 502, and the
    /// SDK maps any 5xx to `VtaError::Server` → "This is a VTA-side failure",
    /// which is a lie when the *host* rejected an actionable request.
    #[test]
    fn remote_client_errors_keep_their_meaning() {
        // The exact code from the root-DID register failure.
        assert_eq!(status_of("e.p.did.path-invalid"), StatusCode::BAD_REQUEST);
        assert_eq!(status_of("e.p.did.invalid-log"), StatusCode::BAD_REQUEST);
        assert_eq!(
            status_of("e.p.did.witness-invalid"),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of("e.p.did.validation-error"),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status_of("e.p.did.quota-exceeded"), StatusCode::BAD_REQUEST);
        assert_eq!(status_of("e.p.did.size-exceeded"), StatusCode::BAD_REQUEST);
        assert_eq!(
            status_of("e.p.did.replay-detected"),
            StatusCode::BAD_REQUEST
        );

        // Slot taken → the operator needs `--force`, not a bug report.
        assert_eq!(status_of("e.p.did.path-unavailable"), StatusCode::CONFLICT);
        assert_eq!(
            status_of("e.p.did.mnemonic-not-found"),
            StatusCode::NOT_FOUND
        );
    }

    /// Remote auth denials are 403, never 401 — the caller's token for *this*
    /// VTA is fine; it's the VTA's DID that lacks rights on the host. A 401
    /// would make the CLI print a misleading "token may be expired" hint.
    #[test]
    fn remote_auth_denial_is_forbidden_not_unauthorized() {
        for code in [
            "e.p.did.unauthorized",
            "e.p.registration.unauthorized",
            "e.p.stats.unauthorized",
            "e.p.msg.forbidden",
        ] {
            assert_eq!(status_of(code), StatusCode::FORBIDDEN, "code {code}");
        }
    }

    /// A genuine upstream failure stays a 502. Re-labelling an upstream crash
    /// as a caller error would be a worse lie than the one being fixed.
    #[test]
    fn upstream_failures_and_unknown_codes_stay_bad_gateway() {
        for code in [
            "e.p.did.internal-error",
            "e.p.registration.internal-error",
            "e.p.did.some-code-we-have-never-seen",
            "",
        ] {
            assert_eq!(status_of(code), StatusCode::BAD_GATEWAY, "code {code}");
        }
    }

    /// The remote's comment and code both survive into the operator-visible
    /// message — without them the error is unactionable.
    #[test]
    fn detail_carries_remote_comment_and_code() {
        let err = problem_report_to_app_error(
            "e.p.did.path-invalid",
            "path segments must contain only lowercase letters, digits, and hyphens",
        );
        let msg = err.to_string();
        assert!(msg.contains("lowercase letters"), "lost comment: {msg}");
        assert!(msg.contains("e.p.did.path-invalid"), "lost code: {msg}");
    }
}
