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
//! This mirrors the VTA's `POST /api/trust-tasks`. It rides the governed
//! (rate-limited, 64 KiB) unauth chain.
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
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use crate::server::AppState;
use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core};

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
#[utoipa::path(
    post, path = "/trust-tasks", tag = "trust-tasks",
    request_body(
        content = String,
        description = "A Trust Task document (trust_tasks_rs::TrustTask JSON)",
    ),
    responses(
        (status = 200, description = "Trust Task #response document"),
        (status = 400, description = "Malformed document / payload (trust-task-error)"),
        (status = 403, description = "Holder auth / VIC verification failed (trust-task-error)"),
        (status = 422, description = "Task failed, e.g. duplicate request (trust-task-error)"),
    ),
)]
pub async fn dispatch(State(state): State<AppState>, body: Bytes) -> Response {
    dispatch_trust_task_core(&state, &JoinAuthCtx::rest(), &body)
        .await
        .into_response()
}
