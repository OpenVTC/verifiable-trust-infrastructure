//! What every handler does the same way: render a shared refusal or answer, verify the
//! room's chain, and charge the operation.

use axum::http::StatusCode;
use serde_json::Value;
use trust_tasks_rs::{ErrorPayload, RejectReason, TrustTask};
use vti_common::error::AppError;
use vti_rooms::Room;
use vti_rooms::authz::{self, Action, AuthorizedAction};
use vti_rooms::blob_tasks::{self, Refusal, TaskResult};
use vti_rooms::blobs::UploadCaller;
use vti_rooms::storage;
use vti_rooms::wire::AuthorityPresentation;
use vti_rooms_dtg::{DataIntegrityKeys, DtgChainVerifier};
use vti_trust_task_server::TrustTaskOutcome;
use vti_trust_task_server::reject::{error_response, extended_code, reject_with, success_response};

use crate::{RoomAudit, RoomCtx, RoomTraffic, now};

pub(crate) use vti_trust_task_server::reject::app_error_to_reject;

/// Refuse with a code the task's specification declares, `retryable` as it declares it.
fn declared<P>(
    doc: &TrustTask<P>,
    code: trust_tasks_rs::DeclaredErrorCode,
    message: String,
    details: Option<Value>,
) -> TrustTaskOutcome {
    let mut payload = ErrorPayload::new(extended_code(code.code))
        .with_message(message)
        .with_retryable(code.retryable);
    if let Some(d) = details {
        payload = payload.with_details(d);
    }
    error_response(doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

/// Render a shared refusal as a reply.
pub(crate) fn refused<P>(doc: &TrustTask<P>, refusal: Refusal) -> TrustTaskOutcome {
    match refusal {
        Refusal::Declared {
            code,
            message,
            details,
        } => declared(doc, code, message, details),
        Refusal::Malformed(reason) => reject_with(doc, RejectReason::MalformedRequest { reason }),
        Refusal::Unavailable { retry_after_secs } => reject_with(
            doc,
            RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            },
        ),
        Refusal::TaskFailed(reason) => reject_with(
            doc,
            RejectReason::TaskFailed {
                reason,
                details: None,
            },
        ),
        Refusal::App(e) => app_error_to_reject(doc, &e),
        Refusal::Internal(reason) => reject_with(doc, RejectReason::InternalError { reason }),
        // `Refusal` is `#[non_exhaustive]`: one this crate does not know yet is an internal
        // error.
        other => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{other:?}"),
            },
        ),
    }
}

/// Render a shared task's answer as a reply.
pub(crate) fn render<P>(doc: &TrustTask<P>, result: TaskResult) -> TrustTaskOutcome {
    match result {
        Ok(body) => success_response(doc, body),
        Err(r) => refused(doc, r),
    }
}

/// A `malformedRequest` for a payload that does not read as the body a handler takes.
pub(crate) fn malformed<P>(doc: &TrustTask<P>, e: impl std::fmt::Display) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::MalformedRequest {
            reason: e.to_string(),
        },
    )
}

/// The payload as JSON, for the shared layer, which reads it member by member.
pub(crate) fn payload_json<P: serde::Serialize>(
    doc: &TrustTask<P>,
) -> Result<Value, TrustTaskOutcome> {
    serde_json::to_value(&doc.payload)
        .map_err(|e| app_error_to_reject(doc, &AppError::Serialization(e)))
}

/// The 0.1 request a later one carries, read as the 0.1 body type.
pub(crate) fn as_v0_1<P, B: serde::de::DeserializeOwned>(
    doc: &TrustTask<P>,
    payload: Value,
) -> Result<B, TrustTaskOutcome> {
    serde_json::from_value(blob_tasks::as_v0_1(payload)).map_err(|e| malformed(doc, e))
}

impl RoomCtx {
    /// The verifier a room's chain is judged with, over this host's resolver.
    ///
    /// `without_zk`: no zero-knowledge profile for a private room's subject binding exists,
    /// and the verifier refuses those rather than serving a pooling defence nobody checked.
    pub(crate) fn verifier(&self) -> DtgChainVerifier {
        DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(self.host.resolver())))
    }

    /// Charge an operation the room has just authorized ([`crate::RoomHost::charge`]).
    pub(crate) fn charged(
        &self,
        room_id: &str,
        presenter: &str,
        traffic: RoomTraffic,
    ) -> Result<(), TrustTaskOutcome> {
        if self.host.charge(room_id, presenter, traffic) {
            Ok(())
        } else {
            Err(TrustTaskOutcome::empty(StatusCode::TOO_MANY_REQUESTS))
        }
    }

    /// Record a room operation ([`crate::RoomHost::audit`]).
    pub(crate) async fn audit(
        &self,
        room: &Room,
        authorized: &AuthorizedAction,
        operation: vti_rooms::audit::RoomOperation,
        record_key: Option<&str>,
    ) {
        self.host
            .audit(
                room,
                authorized,
                RoomAudit::Operation {
                    operation,
                    record_key,
                    purpose: None,
                },
            )
            .await;
    }
}

/// Read the presentation and room, verify the chain for `action`, charge the operation, and
/// return the room and the authorization.
///
/// A chain that does not confer `action` is the framework's standard `permissionDenied`, as
/// for every `rooms/*` task: the family declares no task-specific code that would shadow it.
pub(crate) async fn authorize<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    payload: &Value,
    action: Action,
) -> Result<(Room, AuthorizedAction), TrustTaskOutcome> {
    let presentation: AuthorityPresentation =
        serde_json::from_value(payload["presentation"].clone()).map_err(|e| {
            reject_with(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!("presentation: {e}"),
                },
            )
        })?;
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = storage::get_room(ctx.host.rooms(), room_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let authorized = authz::authorize(
        &room,
        &presentation,
        action,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        ctx.host.revocations(),
    )
    .await
    .map_err(|e| app_error_to_reject(doc, &e))?;
    ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation)?;
    Ok((room, authorized))
}

/// Hold a transfer step that presents nothing to the room's revocation list, returning the
/// room's gate for the step to commit under (`rooms/revocations/put`, *Enforcement* item 3).
pub(crate) async fn held_step<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    payload: &Value,
) -> Result<Option<vti_rooms::revocation::gate::Shared>, TrustTaskOutcome> {
    vti_rooms::revocation_tasks::hold_transfer_step(
        ctx.host.files(),
        ctx.host.rooms(),
        ctx.host.revocations(),
        payload,
    )
    .await
    .map_err(|r| refused(doc, r))
}

/// Charge a task authorized by owning a transfer (`uploadId` / `downloadId`) to the room
/// that transfer belongs to, once the presenter is shown to be the party that opened it.
///
/// Someone else's transfer, or one that is closed, is not charged here and goes on to be
/// refused `notFound` by the task itself.
pub(crate) async fn charge_transfer(
    ctx: &RoomCtx,
    payload: &Value,
    id_member: &str,
    traffic: RoomTraffic,
) -> Result<(), TrustTaskOutcome> {
    let Some(id) = payload[id_member].as_str() else {
        return Ok(());
    };
    match ctx.host.files().transfer_room(&ctx.presenter, id).await {
        Some(room_id) => ctx.charged(&room_id, &ctx.presenter, traffic),
        None => Ok(()),
    }
}

/// Charge a `0.2` upload document to the budget of the upload's **owner** in its room, once
/// its signer is shown to be the one the upload admits (its upload key, for a proxied
/// upload). An upload key is minted per upload; charged as itself it would be a fresh,
/// anonymous budget for every file, which is exactly what the per-presenter budget exists to
/// deny. Not admitted: not charged here, and refused `notFound` by the task.
pub(crate) async fn charge_upload_v2(
    ctx: &RoomCtx,
    payload: &Value,
    traffic: RoomTraffic,
) -> Result<(), TrustTaskOutcome> {
    let Some(id) = payload["uploadId"].as_str() else {
        return Ok(());
    };
    match ctx
        .host
        .files()
        .upload_owner_room(UploadCaller::V2(&ctx.presenter), id)
        .await
    {
        Some((room_id, owner)) => ctx.charged(&room_id, &owner, traffic),
        None => Ok(()),
    }
}
