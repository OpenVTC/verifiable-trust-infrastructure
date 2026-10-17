//! `auth/whoami/0.1` on the signed-document spine — "the proof on the
//! document identifies the subject".
//!
//! The decision on #1641 (2026-10-17): every console sign-in binds a browser
//! key to the session it mints (`Session::session_pubkey_b58btc` — the field
//! `auth/authenticate/0.2`'s `sessionKey` and `auth/oob/redeem`'s `K_b`
//! already fill), and whoami is answered for the key, never for a cookie.
//! The bearer route `GET /v1/auth/whoami` is gone.
//!
//! The signer is one of, in this order:
//!
//! 1. **The key bound to a live session.** The answer is that session — the
//!    most recent, if the key was bound to several.
//! 2. **A console key with an active delegation** (`acl::console_key`), for a
//!    signer with no ACL row of its own — resolved exactly as
//!    [`super::admin_signer`] resolves one. The answer is the delegating
//!    administrator's most recent live session.
//!
//! Anything else is `permissionDenied`, and so is a signer whose session has
//! ended: signed out (the row is deleted), past its refresh expiry or absolute
//! end, or idle past `auth.admin_idle_timeout` — the same idle rule
//! `auth/refresh` enforces, so a key cannot keep alive a session renewal
//! would refuse. The subject must still be an administrator, read from the
//! live ACL entry.
//!
//! A session is "live" only with a refresh expiry, as every sign-in writes
//! one. An intrinsic-sender session — DIDComm or TSP — has none, never has a
//! bound key, and is not answered here.

use serde_json::Value;
use trust_tasks_rs::specs::auth::whoami::v0_1 as whoami;
use trust_tasks_rs::{Payload, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::session::{Session, SessionState, list_sessions, now_epoch};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, reject_with, reject_with_code, success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::server::AppState;

pub(crate) const WHOAMI_TYPE: &str = <whoami::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[WHOAMI_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    if type_uri != WHOAMI_TYPE {
        return None;
    }
    Some(handle(state, ctx, doc).await)
}

fn refused(doc: &TrustTask<Value>, message: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        TrustTaskCode::Standard(StandardCode::PermissionDenied),
        message,
        None,
    )
}

async fn handle(state: &AppState, ctx: &JoinAuthCtx, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    if let Err(reject) = parse_spec_payload::<whoami::Payload>(&doc) {
        return reject;
    }
    let session = match session_for_signer(state, &signer).await {
        Ok(Some(s)) => s,
        // One answer for "not a key of any session" and "its session ended":
        // neither is a key this service will answer for.
        Ok(None) => {
            return refused(
                &doc,
                "the signer is not the key of a live session, nor a console key of one",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Still an administrator, read now — a row removed or demoted since the
    // session began answers nothing, as the bearer route's session would not
    // have renewed.
    let role = match crate::acl::resolve_auth_role(&state.acl_ks, &session.did).await {
        Ok((role, _)) => role,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let response = crate::routes::auth::whoami_for(state, &session, role).await;
    success_response(&doc, response)
}

/// The live session `signer` speaks for, per the module's two rules.
async fn session_for_signer(
    state: &AppState,
    signer: &str,
) -> Result<Option<Session>, crate::error::AppError> {
    let now = now_epoch();
    let idle_ttl = state.config.read().await.auth.admin_idle_timeout;
    let live: Vec<Session> = list_sessions(&state.sessions_ks)
        .await?
        .into_iter()
        .filter(|s| is_live(s, now, idle_ttl))
        .collect();
    let newest = |it: &mut dyn Iterator<Item = Session>| it.max_by_key(|s| s.created_at);

    // 1. The key bound to a live session.
    if let Some(multikey) = crate::member_portal::oob::did_key_multikey(signer)
        && let Some(s) = newest(
            &mut live
                .iter()
                .filter(|s| s.session_pubkey_b58btc.as_deref() == Some(multikey))
                .cloned(),
        )
    {
        return Ok(Some(s));
    }

    // 2. A console key acting for its administrator — only for a signer with
    //    no ACL row of its own, as `admin_signer` has it.
    if crate::acl::get_acl_entry(&state.acl_ks, signer)
        .await?
        .is_some()
    {
        return Ok(None);
    }
    let Some(delegation) =
        crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, signer).await?
    else {
        return Ok(None);
    };
    let found = newest(&mut live.into_iter().filter(|s| s.did == delegation.admin_did));
    if found.is_some() {
        crate::acl::console_key::touch_last_used(&state.console_keys_ks, &delegation).await;
    }
    Ok(found)
}

/// A REST session that `auth/refresh` would still renew: authenticated, inside
/// its refresh expiry and any absolute end, and not idle past `idle_ttl`.
fn is_live(s: &Session, now: u64, idle_ttl: u64) -> bool {
    if s.state != SessionState::Authenticated {
        return false;
    }
    let Some(refresh_end) = s.refresh_expires_at else {
        return false;
    };
    if now >= refresh_end || s.past_end(now) {
        return false;
    }
    let last_activity = if s.last_seen == 0 {
        s.created_at
    } else {
        s.last_seen
    };
    now.saturating_sub(last_activity) <= idle_ttl
}
