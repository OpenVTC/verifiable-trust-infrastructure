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
use crate::member_portal::oob::HttpContext;
use crate::routing::trust_task_admission::{Admission, ClientAddress, TrustTaskLimits};
use crate::server::AppState;
use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core_admitted};

/// Sent by the admin console on a document it posts while its operator is
/// interacting with it, and never on one a timer posts.
///
/// The console's reads and writes are signed documents, and this route reads
/// no session, so without this nothing an operator did in the console counted
/// toward the session's idle timeout (`auth.admin_idle_timeout`). Fifteen
/// minutes after the last cookie-authenticated request, the session could no
/// longer renew and the console signed out someone who was working.
///
/// Only the console can tell a click from a poll. Its action badge, counts and
/// banners post signed reads on timers, so counting every signed document
/// would keep an unattended tab signed in forever, which is the case the idle
/// timeout exists for. The header is the console's claim, accepted only for a
/// document that ran successfully, was verified as a known signer, and whose
/// principal (the signer, or the administrator its console key acts for) owns
/// the session named by the request's cookie. Anyone able to send it already
/// holds that session and could just click.
pub const USER_ACTIVITY_HEADER: &str = "x-vtc-user-activity";

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
    // What the `auth/oob` handlers read from the connection — the browser's
    // `Origin`, address and `User-Agent` — and the cookies a `redeem` sets
    // (`crate::member_portal::oob`). No other task reads it.
    let header = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let http = HttpContext::new(
        address,
        header(header::USER_AGENT),
        header(header::ORIGIN),
        header(header::HOST),
    );
    let outcome = HttpContext::scope(
        http.clone(),
        slot
            // Boxed: see `StreamSlot::scope` — inline, the task-local wrapper
            // would add the spine's whole future to this handler's poll frame.
            .scope(Box::pin(dispatch_trust_task_core_admitted(
                &state,
                &JoinAuthCtx::rest(),
                &body,
                &admission,
                address,
            ))),
    )
    .await;
    let set_cookies = http.take_cookies();
    if outcome.status == StatusCode::OK
        && headers.contains_key(USER_ACTIVITY_HEADER)
        && let Some(principal) = admission.verified_principal()
    {
        vti_common::auth::touch_cookie_session_for(&headers, &state, principal).await;
    }
    match admission.finish() {
        Ok(()) => match slot.take() {
            // A granted stream behind a success: the signed `#response` is
            // its first event. Dropping an unopened grant releases its place
            // under the stream caps.
            Some(grant) if outcome.status == StatusCode::OK => {
                crate::admin_events::respond(state, grant, outcome.body)
            }
            _ => {
                let mut response = outcome.into_response();
                // `auth/oob/*` responses carry a sign-in's state and, on
                // `redeem`, its session: never cached (base design §10).
                if is_oob_document(&body) {
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        header::HeaderValue::from_static("no-store"),
                    );
                }
                if !set_cookies.is_empty()
                    && let Err(e) =
                        crate::member_portal::cookies::append(response.headers_mut(), set_cookies)
                {
                    return e.into_response();
                }
                response
            }
        },
        Err(limited) => limited.into_response(),
    }
}

/// Whether `body` names an `auth/oob/*` type — read off the raw bytes, since
/// the spine has parsed and dropped the document by the time the response is
/// built. A false positive only adds `no-store`.
fn is_oob_document(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/auth/oob/"))
}
