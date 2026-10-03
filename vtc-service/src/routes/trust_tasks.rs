//! `POST /v1/trust-tasks` — the VTC's single Trust Task **document**
//! endpoint over REST.
//!
//! All Trust Tasks are identical at the transport boundary: the request body
//! is a `trust_tasks_rs::TrustTask` document and the response is a framework
//! `#response` or `trust-task-error` document. Routing to the right verb
//! handler happens *internally* by the document's `type`
//! ([`crate::trust_tasks::dispatch_trust_task_core`]) — so one unauthenticated
//! endpoint serves the whole holder/public-facing join ceremony (submit,
//! accept, manifest, status), with the holder authenticated by the document's
//! `eddsa-jcs-2022` proof.
//!
//! This mirrors the VTA's `POST /api/trust-tasks`. It sits on the unauth
//! chain but not behind its tower governor: a document is charged to the
//! per-address anonymous budget, or — when it claims a signer the community
//! knows — to that signer's own bucket once its proof verifies
//! ([`crate::routing::trust_task_admission`]). Each document type has its own size limit,
//! checked before the document is parsed
//! ([`crate::trust_tasks::size`]).
//!
//! ## "Unauthenticated" is about the transport, not about authority
//!
//! This endpoint reads no bearer token, and since #1641 phase 2 it does route
//! **admin verbs** — `vtc/members/{credentials,update,admin-remove,purge}`, and
//! more as the migration proceeds. That is not a privilege-escalation surface,
//! and the reason is the one VTI-OPS-020 states: a signed document carries its
//! own authentication. The spine refuses a document whose specification
//! declares `proof` REQUIRED and that carries none, verifies the proof against
//! the document's own `issuer`, binds the document to this VTC as recipient,
//! bounds its age, and records its `id`. The verb handler then reads the
//! **signer's ACL entry** for authority.
//!
//! So the gate is stronger than the bearer routes', not weaker: it is decided
//! from the ACL at execution time rather than from a claim copied into a JWT
//! when the session began. A `type` this dispatcher does not route is still
//! rejected `unsupportedType`.

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::admin_events::{StreamSlot, accepts_event_stream};
use crate::routing::trust_task_admission::{Admission, ClientAddress, TrustTaskLimits};
use crate::server::AppState;
use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core_admitted};

/// POST /trust-tasks — dispatch a Trust Task document. Public: the holder's
/// document proof (or, over DIDComm, the authcrypt sender) IS the auth.
///
/// No bearer token is read here. A document whose specification declares
/// `proof` REQUIRED must carry one, it must verify against the document's own
/// `issuer`, the document must name this community as `recipient`, its
/// `issuedAt` must fall inside the acceptance window, and its `id` is recorded
/// so a redelivery is answered rather than re-executed.
///
/// Administrator verbs are dispatched here too — their authority is the
/// verified signer's ACL entry, read when the document executes.
///
/// ## Streamed responses (HTTPS binding 0.3 §2.1)
///
/// A request sent with `Accept: text/event-stream` may be answered with a
/// stream — today only `vtc/admin/events/subscribe/0.1`
/// (`crate::admin_events`). The document runs through the whole pipeline
/// first; a refusal is the ordinary JSON `trust-task-error`, and only a
/// success opens `200 text/event-stream`, whose first event is the signed
/// `#response`. Every other task answers JSON whatever `Accept` says.
#[utoipa::path(
    post, path = "/trust-tasks", tag = "trust-tasks",
    request_body(
        content = String,
        description = "A Trust Task document (trust_tasks_rs::TrustTask JSON)",
    ),
    responses(
        (status = 200, description = "Trust Task #response document"),
        (status = 400, description = "Malformed document / payload, or a document larger than its type accepts (trust-task-error)"),
        (status = 403, description = "Holder auth / VIC verification failed (trust-task-error)"),
        (status = 422, description = "Task failed, e.g. duplicate request (trust-task-error)"),
    ),
)]
pub async fn dispatch(
    State(state): State<AppState>,
    Extension(ClientAddress(address)): Extension<ClientAddress>,
    Extension(limits): Extension<TrustTaskLimits>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let admission = match Admission::begin(&state, &limits, address, &body).await {
        Ok(admission) => admission,
        Err(limited) => return limited.into_response(),
    };
    let slot = StreamSlot::new(
        accepts_event_stream(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok())),
        headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    );
    let outcome = slot
        .scope(dispatch_trust_task_core_admitted(
            &state,
            &JoinAuthCtx::rest(),
            &body,
            &admission,
            address,
        ))
        .await;
    match admission.finish() {
        Ok(()) => match slot.take() {
            // A granted stream behind a success: the signed `#response` is
            // its first event. Dropping an unopened grant releases its place
            // under the stream caps.
            Some(grant) if outcome.status == StatusCode::OK => {
                crate::admin_events::respond(state, grant, outcome.body)
            }
            _ => outcome.into_response(),
        },
        Err(limited) => limited.into_response(),
    }
}
