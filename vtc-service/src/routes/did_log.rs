//! `did:webvh` log publication route.
//!
//! The VTC's identity is a `did:webvh` provisioned by the VTA's
//! `vtc-host` template (see `tasks/vtc-mvp/vta-driven-keys.md` §10).
//! Every `did:webvh` resolver that wants to verify a VC the VTC
//! signs needs to fetch the canonical `did.jsonl` log; this route
//! serves it.
//!
//! ## Wire shape
//!
//! `GET /.well-known/did.jsonl` → `200 application/jsonl` with the
//! log content.
//!
//! This path is **not** arbitrary: a serverless VTC's DID is
//! `did:webvh:<scid>:<host>` (no path component), which by the
//! did:webvh resolution convention resolves to
//! `https://<host>/.well-known/did.jsonl`. Serving the log here is
//! what makes the VTC's own DID resolvable from the VTC itself — no
//! external hosting required. The route is mounted at the
//! parent-router root (above the `/v1` API nest) so the URL the DID
//! resolves to is the URL we serve, regardless of routing mode.
//!
//! Trust-Task-**exempt** because DID resolvers won't carry our
//! private extension header. Because the route lives on the bare
//! parent router (not the `TrustTaskRouter`), it carries no
//! Trust-Task gate to exempt in the first place.
//!
//! ## Storage
//!
//! Reads from `<config.store.data_dir>/did/<scid>.jsonl`, where
//! `<scid>` is the SCID of the VTC's own `config.vtc_did`. The setup
//! wizard wrote the file at first-boot when it opened the VTA's
//! `TemplateBootstrapPayload` — see
//! `vta_sdk::sealed_transfer::template_bootstrap::TemplateOutput`'s
//! `did.jsonl` entry.
//!
//! ## Filename
//!
//! The VTC hosts exactly one DID — its own. The setup wizard wrote
//! the log to `did/<label>.jsonl`, where `<label>` is the final
//! colon-separated component of `config.vtc_did`. For a serverless
//! `did:webvh:<scid>:<host>` that final component is the **host** (the
//! SCID is the *first* label — see the did:webvh spec and
//! `vta_sdk::session::url_from_did`, which reads the host as the 2nd
//! component). This route reads back the same name the wizard wrote,
//! so the derivation here mirrors the wizard's exactly. The label is
//! not interpreted as anything — it's only a storage key.
//!
//! ## Safety
//!
//! `config.vtc_did` is operator-controlled at setup, never request-
//! derived. Before the label reaches the filesystem it's checked for
//! path-traversal safety (no separators, no `..`), so a malformed
//! configured DID can't escape the `did/` directory. This is a
//! *path-safety* check, **not** an SCID-grammar check: a real label is
//! a hostname and legitimately contains dots — rejecting dots is the
//! bug that made the VTC's own DID unresolvable.

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;

use crate::server::AppState;

/// `GET /.well-known/did.jsonl`
pub async fn did_log(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config.read().await;

    // The VTC is not a general-purpose did:webvh host — it serves
    // exactly one DID, its own. Derive the on-disk log label from
    // `config.vtc_did` (the same way the setup wizard did when it wrote
    // the file); before setup has run (or for a non-webvh DID) there's
    // nothing to serve. `did_log_label` also rejects path-traversal, so
    // the filename below can't escape the `did/` directory.
    let label = match config.vtc_did.as_deref().and_then(did_log_label) {
        Some(label) => label,
        None => return (StatusCode::NOT_FOUND, "did log not found").into_response(),
    };

    let path = config
        .store
        .data_dir
        .join("did")
        .join(format!("{label}.jsonl"));
    drop(config);

    let body = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "did log not found").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "failed to read did log");
            return (StatusCode::INTERNAL_SERVER_ERROR, "did log read failed").into_response();
        }
    };

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jsonl"),
            ),
            // The log is served at the parent root, outside the
            // website sub-router's security-headers middleware, so set
            // nosniff here — a browser must not content-sniff the
            // jsonl into something executable.
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response()
}

/// True if `s` is safe to interpolate into `did/<s>.jsonl` without
/// escaping the directory. A legitimate label is a hostname or SCID,
/// so dots are allowed; only path separators, parent-directory refs,
/// and control characters are rejected.
fn is_safe_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s != "."
        && s != ".."
        && !s.contains("..")
        && !s.contains('/')
        && !s.contains('\\')
        && !s.chars().any(char::is_control)
}

/// Derive the on-disk log label from the VTC's own `did:webvh`. The
/// label is the **final** colon-separated component — the same value
/// the setup wizard used when it wrote `did/<label>.jsonl`. For a
/// serverless `did:webvh:<scid>:<host>` that's the host. Returns
/// `None` for a non-webvh DID or a label that isn't filesystem-safe.
fn did_log_label(did: &str) -> Option<String> {
    let suffix = did.strip_prefix("did:webvh:")?;
    let label = suffix.split(':').next_back()?;
    if is_safe_label(label) {
        Some(label.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_label_accepts_hostnames_and_scids() {
        // A serverless DID's label is the host — dots and all. This is
        // the case the old SCID-grammar check wrongly rejected.
        assert!(is_safe_label("vtc.example.com"));
        assert!(is_safe_label("abc123"));
        assert!(is_safe_label("zQmPLwUBtaqz3a"));
        assert!(is_safe_label("foo-bar_baz"));
    }

    #[test]
    fn safe_label_rejects_traversal_and_empty() {
        assert!(!is_safe_label(""));
        assert!(!is_safe_label("."));
        assert!(!is_safe_label(".."));
        assert!(!is_safe_label("foo/bar"));
        assert!(!is_safe_label("foo\\bar"));
        assert!(!is_safe_label("../etc/passwd"));
        assert!(!is_safe_label("a..b"));
    }

    #[test]
    fn did_log_label_takes_the_last_component() {
        // Real did:webvh — SCID first, host last. The label is the host.
        assert_eq!(
            did_log_label("did:webvh:abc123:vtc.example.com").as_deref(),
            Some("vtc.example.com")
        );
        // Hosted DID with a path tail — label is the final component.
        assert_eq!(
            did_log_label("did:webvh:abc123:vtc.example.com:v1").as_deref(),
            Some("v1")
        );
    }

    #[test]
    fn did_log_label_returns_none_for_non_webvh() {
        assert!(did_log_label("did:key:z6Mk…").is_none());
        assert!(did_log_label("not a did").is_none());
    }

    #[test]
    fn did_log_label_returns_none_when_last_component_unsafe() {
        assert!(did_log_label("did:webvh:abc123:../../etc/passwd").is_none());
    }
}
