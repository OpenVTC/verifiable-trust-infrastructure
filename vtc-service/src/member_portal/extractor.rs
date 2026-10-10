//! [`MemberAuth`]: the extractor every member-portal route authenticates with.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use tracing::warn;
use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, touch_last_seen};

use super::{ActiveMember, MEMBER_SESSION_COOKIE, member_jwt_keys, require_active_member};
use crate::error::AppError;
use crate::server::AppState;

/// An authenticated member-portal caller who is an active member *now*.
///
/// The token must be a member-audience access token (an administrator token is
/// refused on audience), its session must be live in `member_sessions` with a
/// matching `jti` pin, and the subject's records are re-read on every request —
/// a member removed or suspended mid-session is refused on their next call
/// (VTI-SES-021, -022).
#[derive(Debug, Clone)]
pub struct MemberAuth {
    pub did: String,
    pub session_id: String,
    pub access_expires_at: u64,
    pub amr: Vec<String>,
    pub acr: String,
    pub member: ActiveMember,
}

impl MemberAuth {
    /// Whether this session was established by proving control of the DID
    /// itself (the wallet's SIOPv2 sign-in) rather than by a portal passkey.
    ///
    /// Adding or removing a portal passkey requires it: the DID is the anchor,
    /// so a passkey — once stolen — cannot be used to enrol more of them or to
    /// remove the member's others.
    pub fn proved_did(&self) -> bool {
        self.amr.iter().any(|f| f == "did")
    }

    pub fn require_proved_did(&self) -> Result<(), AppError> {
        if self.proved_did() {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "sign in with your wallet to change your passkeys".into(),
            ))
        }
    }
}

/// Pull the member token: `Authorization: Bearer` first, then the portal
/// cookie. Never the console's cookie.
fn presented_token(parts: &Parts) -> Option<(String, bool)> {
    let bearer = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| (t.trim().to_string(), false));
    bearer.or_else(|| {
        crate::member_portal::cookies::cookie_value(&parts.headers, MEMBER_SESSION_COOKIE)
            .map(|t| (t, true))
    })
}

/// Decode and check a member access token against its live session. Shared by
/// the extractor and sign-out, which must find the session to end it.
pub(crate) async fn authenticate_member_token(
    state: &AppState,
    token: &str,
) -> Result<(vti_common::auth::jwt::Claims, Session), AppError> {
    let claims = member_jwt_keys(state)?.decode(token)?;
    let session = get_session(&state.member_sessions_ks, &claims.session_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("session not found".into()))?;
    if session.state != SessionState::Authenticated {
        return Err(AppError::Unauthorized("session not authenticated".into()));
    }
    if session.did != claims.sub {
        return Err(AppError::Unauthorized("session subject mismatch".into()));
    }
    if let Some(pinned) = &session.token_id
        && claims.jti != *pinned
    {
        return Err(AppError::Unauthorized("token superseded".into()));
    }
    Ok((claims, session))
}

impl FromRequestParts<AppState> for MemberAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some((token, from_cookie)) = presented_token(parts) else {
            return Err(AppError::Unauthorized("not signed in".into()));
        };
        let (claims, session) = authenticate_member_token(state, &token).await?;
        let member = require_active_member(state, &claims.sub).await?;

        // Browser activity is what the idle timeout measures; best-effort, as
        // on the console (a lost touch costs an early sign-out, nothing more).
        if from_cookie
            && let Err(e) = touch_last_seen(&state.member_sessions_ks, &session, now_epoch()).await
        {
            warn!(session_id = %session.session_id, error = %e, "failed to record member session activity");
        }

        Ok(Self {
            did: claims.sub,
            session_id: claims.session_id,
            access_expires_at: claims.exp,
            amr: claims.amr,
            acr: claims.acr,
            member,
        })
    }
}
