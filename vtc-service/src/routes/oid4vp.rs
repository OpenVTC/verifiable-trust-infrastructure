//! The two OpenID4VP 1.0 endpoints a wallet calls for a wallet session:
//! `request_uri` and `response_uri` (`docs/05-design-notes/oid4vp-wallet-verifier.md`).
//!
//! These are a declared foreign-protocol exception to "every remote operation
//! is a Trust Task" (VTI-OPS-095): a swiyu or EUDI wallet speaks OpenID4VP over
//! HTTPS and nothing else, and holds no DID key to sign a document with. The
//! session they act on is opened and read only through
//! `vtc/join-requests/wallet-session/{start,status}/0.1`. Both routes are
//! unauthenticated and sit on the governed chain: the session id is
//! unguessable and single-use, the response decrypts only under that session's
//! key, and the session closes in minutes.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::oid4vp::session;
use crate::oid4vp::wallet::{self, WalletAnswer};
use crate::server::AppState;

/// The media type of a signed request object (RFC 9101 §10.2).
const REQUEST_OBJECT_MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";

/// A session id is 32 base64url characters; anything else names no session.
fn plausible_session_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An OpenID4VP error body, `no-store` like every response here.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    no_store(
        (
            status,
            axum::Json(json!({ "error": error, "error_description": description })),
        )
            .into_response(),
    )
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /v1/oid4vp/request/{session}` — the session's signed request object,
/// answered once (`wallet-session/start/0.1` consumer rule 7).
#[utoipa::path(
    get, path = "/oid4vp/request/{session}", tag = "oid4vp",
    params(("session" = String, Path, description = "The wallet session id")),
    responses(
        (status = 200, description = "The signed request object (a JAR)", content_type = "application/oauth-authz-req+jwt", body = String),
        (status = 404, description = "No open session by that id, or its request object was already fetched"),
    ),
)]
pub async fn request_object(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Response {
    let not_found = || {
        oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request_uri",
            "no open request at this URI",
        )
    };
    if !plausible_session_id(&session_id) {
        return not_found();
    }
    match session::take_request_object(&state.oid4vp_sessions_ks, &session_id, chrono::Utc::now())
        .await
    {
        Ok(Some(jar)) => no_store(
            (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(REQUEST_OBJECT_MEDIA_TYPE),
                )],
                jar,
            )
                .into_response(),
        ),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, "wallet session request object could not be read");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the request object could not be read",
            )
        }
    }
}

/// `POST /v1/oid4vp/response/{session}` — the wallet's `direct_post.jwt`
/// answer. Accepted once; the body cap is `[oid4vp] max_response_bytes`.
#[utoipa::path(
    post, path = "/oid4vp/response/{session}", tag = "oid4vp",
    params(("session" = String, Path, description = "The wallet session id")),
    request_body(content = String, content_type = "application/x-www-form-urlencoded",
        description = "`response=<JWE>`, or OpenID4VP error parameters"),
    responses(
        (status = 200, description = "Received: the presentation verified, or the wallet's error was recorded"),
        (status = 400, description = "The session is unknown or closed, or the presentation was not accepted"),
        (status = 413, description = "The response is larger than this community accepts"),
    ),
)]
pub async fn response(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Body,
) -> Response {
    let closed = || {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this session is unknown or no longer takes a response",
        )
    };
    if !plausible_session_id(&session_id) {
        return closed();
    }
    let limit = state.config.read().await.oid4vp.max_response_bytes;
    let bytes = match axum::body::to_bytes(body, limit).await {
        Ok(b) => b,
        Err(_) => {
            return oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "the response is larger than this verifier accepts",
            );
        }
    };
    match wallet::receive(&state, &session_id, &bytes, chrono::Utc::now()).await {
        Ok(WalletAnswer::Presented | WalletAnswer::Declined) => {
            no_store((StatusCode::OK, axum::Json(json!({}))).into_response())
        }
        Ok(WalletAnswer::Refused(_)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the presentation was not accepted",
        ),
        Ok(WalletAnswer::NoSession) => closed(),
        Err(e) => {
            tracing::error!(error = %e, "wallet response could not be processed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the response could not be processed",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_base64url_token_of_session_length_is_looked_up() {
        assert!(plausible_session_id(&session::random_token(24)));
        assert!(!plausible_session_id("short"));
        assert!(!plausible_session_id("../../../../etc/passwd-padding-xx"));
        assert!(!plausible_session_id(&"a".repeat(129)));
    }
}
