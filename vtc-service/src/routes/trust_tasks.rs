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
//! (rate-limited, 64 KiB) unauth chain; admin-only verbs are not routed here
//! (an unknown/admin `type` is rejected `unsupportedType`), so there is no
//! privilege-escalation surface.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use crate::server::AppState;
use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core};

/// POST /trust-tasks — dispatch a Trust Task document. Public: the holder's
/// document proof (or, over DIDComm, the authcrypt sender) IS the auth.
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
