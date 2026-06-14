//! `GET /auth/portal` — popup target for cross-origin WebAuthn flows.
//!
//! Serves a self-contained HTML page (`index.html`, baked in via
//! `include_str!`) that runs the passkey login or enrolment ceremony
//! same-origin with the VTA. On completion the page posts the result
//! back to its `window.opener` via `window.postMessage`.
//!
//! ## Why this exists
//!
//! WebAuthn requires the credential ceremony to happen at the RP ID's
//! own origin — the browser enforces this client-side regardless of
//! any server-side CORS configuration. A third-party app at
//! `https://app.example.com` that wants to authenticate against a VTA
//! at `https://vta.example.com` cannot run `navigator.credentials.get`
//! against credentials bound to `vta.example.com`. The standard
//! solution is a popup hosted at the VTA's domain, which is exactly
//! what this route serves.
//!
//! ## Security model
//!
//! - **`origin` query param** is validated against `server.cors_origins`
//!   before the HTML is served. A request from a non-allowed origin
//!   gets 403. This keeps the page from being deep-linked by random
//!   sites trying to phish operators.
//! - **`nonce` query param** is opaque to the server. The opener
//!   generates it and validates that the postMessage echoes the same
//!   value. Prevents replay across popups.
//! - **`postMessage` target** is the exact `origin` query param, never
//!   `'*'`. The browser ensures only that origin receives the result.
//! - **No state on the server** for this route. The HTML calls back
//!   into the existing `/auth/passkey-login/*` and
//!   `/did/verification-methods/passkey/*` endpoints, which carry
//!   their own session bookkeeping.
//!
//! See `docs/02-vta/passkey-verification-methods.md` for the wire
//! ceremony and `examples/vta-auth-demo/` for a parent-window
//! reference implementation.

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::server::AppState;

/// The baked-in portal page. One file, inline `<script>` + `<style>`
/// so we only need a single route — no separate asset paths to wire.
const PORTAL_HTML: &str = include_str!("index.html");

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PortalQuery {
    /// Parent-window origin, exact-match against `cors_origins`. The
    /// page uses this as the postMessage target so the result only
    /// flows back to a registered caller.
    pub origin: String,
    // Other params (mode, nonce, did, label) are consumed entirely
    // client-side. Listing them here would force serde to allow them;
    // omitting lets axum's `Query` ignore them. We accept them via
    // the URL but don't deserialise.
}

/// `GET /auth/portal` — return the auth-portal HTML if the caller's
/// `origin` is in `server.cors_origins`, otherwise 403. Also gated
/// at runtime on `services.webauthn` — returns 503 with a structured
/// `service_disabled` body when the WebAuthn service is currently
/// off, so the operator's CLI can show a useful error.
pub async fn portal_handler(
    State(state): State<AppState>,
    Query(query): Query<PortalQuery>,
) -> Response {
    let (allowed, webauthn_enabled) = {
        let config = state.config.read().await;
        (config.server.cors_origins.clone(), config.services.webauthn)
    };

    if !webauthn_enabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<!doctype html><meta charset=\"utf-8\"><title>VTA Auth Portal</title>\
             <body style=\"font-family:sans-serif;padding:2rem;color:#d65a5a;\">\
             <h1>503 — WebAuthn service disabled</h1>\
             <p>This VTA does not currently advertise a WebAuthn-RP surface. \
             The operator can re-enable with <code>pnm services webauthn enable --url &lt;url&gt;</code>.</p>\
             </body>",
        )
            .into_response();
    }

    if !allowed.iter().any(|o| o == &query.origin) {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "<!doctype html><meta charset=\"utf-8\"><title>VTA Auth Portal</title>\
                 <body style=\"font-family:sans-serif;padding:2rem;color:#d65a5a;\">\
                 <h1>403 — origin not allowed</h1>\
                 <p>The origin <code>{}</code> is not in this VTA's <code>server.cors_origins</code> \
                 allowlist. Ask the VTA operator to add it before retrying.</p>\
                 </body>",
                html_escape(&query.origin),
            ),
        )
            .into_response();
    }

    // Cache-Control: don't let proxies or browsers cache the portal —
    // future changes to the embedded HTML must take effect on the next
    // page load.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
        ],
        PORTAL_HTML,
    )
        .into_response()
}

/// Minimal HTML escape for the 403 error body. Only used for the
/// query-param string we echo back to the user; not on a hot path.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// Tighten the Response type — when assembling `(status, headers, body)`
// tuples axum can sometimes pick a default content-type if we forget to
// set one. Keep the HeaderValue type alive via this no-op so the
// import doesn't get stripped on no-default-features builds.
#[allow(dead_code)]
fn _hv_alive(_: HeaderValue) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_common_xss_chars() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;",
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn portal_html_contains_expected_anchors() {
        // The embedded HTML is the contract; pin a few invariants
        // that the demo's popup integration depends on so a future
        // edit doesn't silently break the wire shape.
        assert!(PORTAL_HTML.contains("vta-portal-result"));
        assert!(PORTAL_HTML.contains("vta-portal-ready"));
        assert!(PORTAL_HTML.contains("vta-portal-config"));
        assert!(PORTAL_HTML.contains("postMessage"));
        // Routes the portal calls into:
        assert!(PORTAL_HTML.contains("/auth/passkey-login/start"));
        assert!(PORTAL_HTML.contains("/auth/passkey-login/finish"));
        assert!(PORTAL_HTML.contains("/did/verification-methods/passkey"));
    }
}
