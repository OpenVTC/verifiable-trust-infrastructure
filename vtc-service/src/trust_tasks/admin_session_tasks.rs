//! `vtc/auth/admin-session/0.1` on the signed-document spine: the admin
//! console's bearer → cookie bridge, for a sign-in that ends with an access
//! token in hand (the VTA wallet's SIOP login).
//!
//! The specification declares `proof` REQUIRED (VTI-OPS-020), and the task was
//! served on a bearer REST route (`POST /v1/auth/admin-session`) that read no
//! proof at all until #1641's last batch removed it. Here:
//!
//! 1. The spine has verified the document's proof against its own `issuer`
//!    and bound it to this community as recipient.
//! 2. The access token is verified (signature, this VTC's audience, expiry);
//!    a bad one is `vtc/auth/admin-session:invalidToken`.
//! 3. **The proof's signer must be the token's subject** — the DID the token
//!    was issued to, signing (through the wallet that just signed in as it),
//!    or a console signing key that DID enrolled
//!    ([`crate::acl::console_key`]), resolved exactly as [`super::admin_signer`]
//!    resolves one: only for a signer with no ACL row of its own. Anyone else
//!    is `permissionDenied`, and nothing is set.
//!
//! Step 3 is what the proof adds. On the bearer route an access token was the
//! whole credential: whoever held one could turn it into a cookie session. Now
//! holding the token is not enough without the subject's key.
//!
//! The task sets cookies, so it is served only on the HTTPS door, which
//! supplies the [`HttpContext`] the cookies ride on (as `auth/oob/redeem`
//! does); every other transport is refused `permissionDenied`.

use serde_json::Value;
use trust_tasks_rs::specs::vtc::auth::admin_session::v0_1 as admin_session;
use trust_tasks_rs::{Payload, StandardCode, TrustTask, TrustTaskCode};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, reject_with, reject_with_code, success_response,
    task_error_to_reject,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::member_portal::oob::HttpContext;
use crate::routes::auth::{admin_session_cookies, decode_admin_session_token};
use crate::server::AppState;

pub(crate) const ADMIN_SESSION_TYPE: &str = <admin_session::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[ADMIN_SESSION_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    if type_uri != ADMIN_SESSION_TYPE {
        return None;
    }
    Some(handle(state, ctx, doc).await)
}

async fn handle(state: &AppState, ctx: &JoinAuthCtx, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let Some(signer) = ctx.verified_signer.clone() else {
        // The spine refuses an unsigned document of a proof-required type
        // before this runs; this is belt to that brace.
        return reject_with(&doc, trust_tasks_rs::RejectReason::ProofRequired);
    };
    let Some(http) = HttpContext::current() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "vtc/auth/admin-session is served only over HTTPS, where the session is set as cookies",
            None,
        );
    };
    let payload: admin_session::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let access_token = payload.access_token.as_str();
    let claims = match decode_admin_session_token(state, access_token) {
        Ok(c) => c,
        Err(e) => return task_error_to_reject(&doc, &e),
    };
    match signer_speaks_for(state, &signer, &claims.sub).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                signer = %signer,
                subject = %claims.sub,
                security_alert = true,
                "admin-session refused: the document's signer is not the access token's subject"
            );
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                "the document must be signed by the access token's subject, or by a console key it enrolled",
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // The refresh token rides in `ext`, which the generated payload keeps as
    // an opaque map; read it off the document as received.
    let refresh_token = crate::routes::auth::refresh_token_from_ext(doc.payload.get("ext"));
    let (response, cookies) =
        admin_session_cookies(state, access_token, &claims, refresh_token).await;
    http.set_cookies(cookies);
    success_response(&doc, response)
}

/// Whether `signer` may act as `subject`: it is `subject`, or — having no ACL
/// row of its own — it is a console key with an active delegation from
/// `subject`. The same rule [`super::admin_signer`] applies, so a key with a
/// row of its own is answered by that row alone and never by a delegation.
async fn signer_speaks_for(
    state: &AppState,
    signer: &str,
    subject: &str,
) -> Result<bool, crate::error::AppError> {
    if signer == subject {
        return Ok(true);
    }
    if crate::acl::get_acl_entry(&state.acl_ks, signer)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    Ok(
        crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, signer)
            .await?
            .is_some_and(|d| d.admin_did == subject),
    )
}
