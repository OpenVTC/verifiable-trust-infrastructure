//! An administrator's own login passkeys on the signed-document spine —
//! `auth/passkey/list/0.1`, `auth/passkey/enroll/{start,finish}/0.2` and
//! `auth/passkey/revoke/{start,finish}/0.1`. The operations are
//! [`crate::routes::admin::passkeys`]'s; this file decides only who is asking.
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
//! | `revoke/start`, `revoke/finish` | the same | their ACL row, **and** a user-verified assertion from one of their existing passkeys |
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
//! Members' step-up passkeys are a different store with a different door
//! (`auth/passkey/revoke/{start,finish}/0.2`, [`super::step_up_passkey_tasks`]).

use serde_json::Value;
use trust_tasks_rs::specs::auth::passkey::{
    enroll::finish::v0_2 as enroll_finish, enroll::start::v0_2 as enroll_start, list::v0_1 as list,
    revoke::finish::v0_1 as revoke_finish, revoke::start::v0_1 as revoke_start,
};
use trust_tasks_rs::{Payload, TrustTask};

use super::helpers::{TrustTaskOutcome, success_response, task_error_to_reject};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::routes::admin::passkeys;
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const ENROLL_START_TYPE: &str = <enroll_start::Payload as Payload>::TYPE_URI;
pub(crate) const ENROLL_FINISH_TYPE: &str = <enroll_finish::Payload as Payload>::TYPE_URI;
pub(crate) const REVOKE_START_TYPE: &str = <revoke_start::Payload as Payload>::TYPE_URI;
pub(crate) const REVOKE_FINISH_TYPE: &str = <revoke_finish::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    LIST_TYPE,
    ENROLL_START_TYPE,
    ENROLL_FINISH_TYPE,
    REVOKE_START_TYPE,
    REVOKE_FINISH_TYPE,
];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    // Authority first, before the payload is read: an unknown or
    // non-administrator signer learns nothing about the shape it sent.
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return Some(reject),
    };
    let did = actor.did.as_str();
    Some(match type_uri {
        LIST_TYPE => match parse_spec_payload::<list::Payload>(&doc) {
            Err(reject) => reject,
            Ok(_) => answer(&doc, passkeys::list(state, did).await),
        },
        ENROLL_START_TYPE => match parse_spec_payload::<enroll_start::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::register_start(state, did, &p).await),
        },
        ENROLL_FINISH_TYPE => match parse_spec_payload::<enroll_finish::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::register_finish(state, did, &p).await),
        },
        REVOKE_START_TYPE => match parse_spec_payload::<revoke_start::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::revoke_start(state, did, &p).await),
        },
        REVOKE_FINISH_TYPE => match parse_spec_payload::<revoke_finish::Payload>(&doc) {
            Err(reject) => reject,
            Ok(p) => answer(&doc, passkeys::revoke_finish(state, did, &p).await),
        },
        _ => return None,
    })
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
