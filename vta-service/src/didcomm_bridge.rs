use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::didcomm::Message;
use tokio::sync::oneshot;

use crate::error::{AppError, bad_gateway_error};
use vta_sdk::protocols::{PROBLEM_REPORT_TYPE, extract_problem_report};

/// Map of pending request IDs to oneshot senders for response routing.
pub type PendingMap = Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<Message>>>>;

/// Bridge between REST/DIDComm handlers and the DIDComm service's outbound
/// send capability.
///
/// Provides outbound request-response DIDComm messaging by registering
/// oneshot channels keyed by message ID. The [`BridgeHandler`] wrapper
/// calls [`try_complete`](Self::try_complete) on each inbound message to route responses
/// back to the waiting handler.
///
/// The bridge starts without a service reference. Call [`set_service`](Self::set_service)
/// after [`DIDCommService::start`] to enable outbound sends.
///
/// [`BridgeHandler`]: crate::messaging::router::BridgeHandler
pub struct DIDCommBridge {
    service: tokio::sync::OnceCell<DIDCommService>,
    pending: PendingMap,
    listener_id: String,
}

impl DIDCommBridge {
    /// Create a new bridge targeting a specific listener.
    ///
    /// Call [`set_service`](Self::set_service) after the DIDComm service starts to enable
    /// outbound sends.
    pub fn new(listener_id: impl Into<String>) -> Self {
        Self {
            service: tokio::sync::OnceCell::new(),
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
            listener_id: listener_id.into(),
        }
    }

    /// Create a placeholder bridge for test/CLI contexts that never send.
    ///
    /// Attempting to send via a placeholder will return an error.
    pub fn placeholder() -> Self {
        Self::new("")
    }

    /// Store the DIDComm service reference for outbound sends.
    ///
    /// Called once after [`DIDCommService::start`] completes.
    pub fn set_service(&self, service: DIDCommService) {
        let _ = self.service.set(service);
    }

    /// Best-effort accessor for the wrapped service. Returns
    /// `None` if [`set_service`](Self::set_service) hasn't been
    /// called (e.g. the bridge is a placeholder, or DIDComm
    /// hasn't started yet). Used by the live mediator handshake
    /// prover, which needs to call `add_listener` /
    /// `wait_connected` against a running service.
    pub fn try_get_service(&self) -> Option<DIDCommService> {
        self.service.get().cloned()
    }

    /// Fire-and-forget: pack `body` as a DIDComm message to `recipient_did` and
    /// send it via the mediator, **without** registering a pending reply. Used
    /// for the delegated step-up push — the approver's device replies later via
    /// a separate `approve-response` call, not as a DIDComm reply on this thread.
    pub async fn send_oneway(
        &self,
        listener_id: &str,
        recipient_did: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(), AppError> {
        let service = self
            .service
            .get()
            .ok_or_else(|| AppError::Internal("DIDComm service not initialized".into()))?;
        let vta_did = service.listener_did(listener_id).await.ok_or_else(|| {
            AppError::Internal(format!(
                "listener '{listener_id}' not found in DIDComm service"
            ))
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Message::build(uuid::Uuid::new_v4().to_string(), msg_type.to_string(), body)
            .from(vta_did)
            .to(recipient_did.to_string())
            .created_time(now)
            .finalize();
        service
            .send_message_with_retry(listener_id, msg, recipient_did, 3, Duration::from_secs(2))
            .await
            .map_err(|e| bad_gateway_error(format!("failed to send message: {e}")))?;
        Ok(())
    }

    /// Like [`send_and_wait`](Self::send_and_wait) but uses the
    /// caller-supplied `listener_id` instead of `self.listener_id`.
    /// Required when the VTA holds multiple listeners (e.g. during
    /// a mediator migration drain window) — outbound messages must
    /// be sent through a specific listener and the response routed
    /// back via the same listener's pending-map entry.
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
        let service = self
            .service
            .get()
            .ok_or_else(|| AppError::Internal("DIDComm service not initialized".into()))?;

        let vta_did = service.listener_did(listener_id).await.ok_or_else(|| {
            AppError::Internal(format!(
                "listener '{listener_id}' not found in DIDComm service",
            ))
        })?;

        let msg_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(vta_did.clone())
            .to(recipient_did.to_string())
            .created_time(now)
            .expires_time(now + timeout_secs)
            .finalize();

        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(msg_id.clone(), tx);

        service
            .send_message_with_retry(listener_id, msg, recipient_did, 3, Duration::from_secs(2))
            .await
            .map_err(|e| {
                self.pending.lock().unwrap().remove(&msg_id);
                bad_gateway_error(format!("failed to send message: {e}"))
            })?;

        let response = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
            .await
            .map_err(|_| {
                self.pending.lock().unwrap().remove(&msg_id);
                bad_gateway_error("timeout waiting for DIDComm response".to_string())
            })?
            .map_err(|_| bad_gateway_error("pending request channel dropped".to_string()))?;

        if response.typ == problem_report_type || response.typ == PROBLEM_REPORT_TYPE {
            let (code, comment) = extract_problem_report(&response.body);
            return Err(bad_gateway_error(format!("{code}: {comment}")));
        }

        if response.typ != expected_type {
            return Err(bad_gateway_error(format!(
                "unexpected response type: expected {expected_type}, got {}",
                response.typ
            )));
        }

        Ok(response)
    }

    /// Try to complete a pending outbound request. Returns true if the
    /// message was routed to a waiting [`Self::send_and_wait`] caller.
    pub fn try_complete(&self, msg: &Message) -> bool {
        if let Some(thid) = &msg.thid
            && let Some(tx) = self.pending.lock().unwrap().remove(thid)
        {
            let _ = tx.send(msg.clone());
            return true;
        }
        false
    }

    /// Send a DIDComm message and wait for a response matching the thread ID.
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
        let service = self
            .service
            .get()
            .ok_or_else(|| AppError::Internal("DIDComm service not initialized".into()))?;

        let vta_did = service
            .listener_did(&self.listener_id)
            .await
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "listener '{}' not found in DIDComm service",
                    self.listener_id
                ))
            })?;

        let msg_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(vta_did.clone())
            .to(server_did.to_string())
            .created_time(now)
            .expires_time(now + timeout_secs)
            .finalize();

        // Register pending before sending
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(msg_id.clone(), tx);

        // Send via the DIDComm service with retry on reconnect
        service
            .send_message_with_retry(
                &self.listener_id,
                msg,
                server_did,
                3,
                Duration::from_secs(2),
            )
            .await
            .map_err(|e| {
                self.pending.lock().unwrap().remove(&msg_id);
                bad_gateway_error(format!("failed to send message: {e}"))
            })?;

        // Wait for response with timeout
        let response = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
            .await
            .map_err(|_| {
                self.pending.lock().unwrap().remove(&msg_id);
                bad_gateway_error("timeout waiting for DIDComm response".to_string())
            })?
            .map_err(|_| bad_gateway_error("pending request channel dropped".to_string()))?;

        // Check for problem report
        if response.typ == problem_report_type || response.typ == PROBLEM_REPORT_TYPE {
            let (code, comment) = extract_problem_report(&response.body);
            return Err(bad_gateway_error(format!("{code}: {comment}")));
        }

        // Verify expected type
        if response.typ != expected_type {
            return Err(bad_gateway_error(format!(
                "unexpected response type: expected {expected_type}, got {}",
                response.typ
            )));
        }

        Ok(response)
    }
}
