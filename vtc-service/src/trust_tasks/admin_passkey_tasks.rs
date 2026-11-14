//! An administrator's own login passkeys on the signed-document spine —
//! `auth/passkey/list/0.1` and `auth/passkey/enroll/{start,finish}/0.2`. The
//! operations are [`crate::routes::admin::passkeys`]'s; this file decides only
//! who is asking. Revoking one is `auth/passkey/revoke/{start,finish}/0.2`,
//! one Type URI for both purposes, routed in [`super::step_up_passkey_tasks`].
//!
//! Each specification declares `proof` REQUIRED, so the spine refuses an
//! unsigned document before anything here runs (VTI-OPS-020). They were served
//! on bearer REST (`/v1/admin/passkeys/*`) until #1641's last batch; those
//! routes are gone, and this is the only door.
//!
//! | task | signed by | authority |
//! |---|---|---|
//! | `list` | an administrator, or a console key acting for one ([`admin_signer`]) | their ACL row |
//! | `enroll/start`, `enroll/finish` | the same | their ACL row, **and** a user-verified assertion from one of their existing passkeys, in the same ceremony |
//!
//! [`admin_signer`] admits exactly what the bearer routes' `AdminAuth` did — a
//! DID whose live ACL row makes it an administrator — read when the document
//! executes rather than when a session began. Every passkey named is the
//! **signer's own** (or, for a console key, its administrator's): nothing here
//! takes a subject from the payload. The in-request user verification is
//! unchanged, and is what keeps a console key — possession of a browser
//! profile, not a second factor (`vtc-console-signing.md` §6f) — from binding
//! or removing an authenticator by itself.
//!
//! Members' step-up passkeys are a different store; `revoke/{start,finish}/0.2`
//! covers both purposes and is dispatched by [`super::step_up_passkey_tasks`],
//! which hands a session credential back to [`crate::routes::admin::passkeys`].

use super::routing::{Routes, on};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_specs::auth::passkey::{
    enroll::finish::v0_2 as enroll_finish, enroll::start::v0_2 as enroll_start, list::v0_1 as list,
};

use super::helpers::{TrustTaskOutcome, success_response, task_error_to_reject};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::routes::admin::passkeys;
use crate::server::AppState;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, list::Payload => |state, ctx, doc| run(state, ctx, doc, Op::List));
    let routes = on!(routes, enroll_start::Payload => |state, ctx, doc| run(state, ctx, doc, Op::EnrollStart));
    on!(routes, enroll_finish::Payload => |state, ctx, doc| run(state, ctx, doc, Op::EnrollFinish))
}

/// Which of the family's tasks a document is.
#[derive(Clone, Copy)]
enum Op {
    List,
    EnrollStart,
    EnrollFinish,
}

async fn run(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    op: Op,
) -> TrustTaskOutcome {
    // Authority first, before the payload is read: an unknown or
    // non-administrator signer learns nothing about the shape it sent.
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let did = actor.did.as_str();
    match op {
        Op::List => match parse_spec_payload::<list::Payload>(&doc) {
            Err(reject) => reject,
            Ok(_) => answer(&doc, passkeys::list(state, did).await),
        },
        Op::EnrollStart => match parse_spec_payload::<enroll_start::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::register_start(state, did, &p).await),
        },
        Op::EnrollFinish => match parse_spec_payload::<enroll_finish::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::register_finish(state, did, &p).await),
        },
    }
}

fn answer<R: serde::Serialize>(
    doc: &TrustTask<Value>,
    result: Result<R, crate::error::TaskError>,
) -> TrustTaskOutcome {
    match result {
        Ok(response) => success_response(doc, response),
        Err(e) => task_error_to_reject(doc, &e),
    }
}
