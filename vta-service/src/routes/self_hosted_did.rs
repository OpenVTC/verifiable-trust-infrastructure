//! Public, unauthenticated serving of the VTA's **own** self-hosted
//! `did:webvh` log at the canonical resolver paths.
//!
//! These endpoints only return content when the VTA hosts its own DID
//! (serverless mode — `record.server_id == "serverless"`). A server-managed
//! VTA publishes its log to an external did-hosting backplane, so here it
//! returns 404. Self-hosting is therefore a *runtime* distinction (the
//! serverless→server-managed promotion is a runtime operation — see the
//! workspace `CLAUDE.md` "Promote a serverless DID to a server-managed one"),
//! which is why it rides the existing `webvh` feature like the rest of the
//! method rather than a separate compile flag. When other self-hosted DID
//! methods (e.g. `did:web`) arrive, their public-serving handlers belong
//! here alongside these.
//!
//! ## Security model
//!
//! World-readable by design (the `did:webvh` log model is public) and
//! rate-limited per client IP by the router's `did-log` limiter — its own
//! bucket, separate from the auth endpoints' (see `routes::rate_limit`).
//! Three deliberate properties:
//!
//! - **The request path is never used as a store key or filesystem path.** It
//!   is only ever compared for *equality* against the path derived from the
//!   *configured* VTA DID; the log bytes are read from the store keyed by that
//!   configured DID. A crafted request path can therefore neither traverse the
//!   store nor select a different DID's log.
//! - **Failure modes are opaque.** Every "not self-hosting / not found" reason
//!   collapses to a bare 404 with no body — byte-identical to axum's default
//!   fallback — so an unauthenticated prober cannot fingerprint the VTA's DID
//!   configuration (has-a-DID? is-webvh? root vs pathful?). Only a genuine
//!   storage error surfaces as 500, for operational visibility. The caching
//!   headers below are set on the 200 / 304 only, never on a 404.
//! - **Cacheable, briefly.** A 200 carries `Cache-Control: public, max-age=60`
//!   and a strong `ETag` over the log bytes; `If-None-Match` answers 304. See
//!   [`DID_LOG_MAX_AGE_SECS`] for why 60 s is safe for update propagation.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use didwebvh_rs::url::WebVHURL;
use sha2::{Digest, Sha256};

use crate::server::AppState;

/// Media type the did:webvh v1.0 spec SHOULDs for the log file
/// (DID-to-HTTPS Transformation §6).
const JSONL_CONTENT_TYPE: &str = "text/jsonl";

/// `max-age` for a served `did.jsonl`, in seconds.
///
/// Short on purpose. A did:webvh log is append-only, so a cached copy is never
/// *wrong* — at worst it lacks the newest entries — but a VTA that rotates keys
/// or changes its services wants resolvers to see the new entry promptly.
/// 60 s bounds that extra delay well inside the staleness resolvers already
/// accept: `affinidi-did-resolver-cache-sdk` (the resolver the mediator and the
/// VTA's clients go through) caches a resolved `did:webvh` document for 300 s
/// by default. So an HTTP cache in front of the VTA adds nothing a verifier
/// was not already tolerating, while a resolver or proxy that does honour it
/// can revalidate with `If-None-Match` for the cost of a 304 instead of a full
/// log transfer. The `ETag` makes revalidation after expiry cheap, so there is
/// no reason to push the window longer.
pub(super) const DID_LOG_MAX_AGE_SECS: u64 = 60;

/// `GET /.well-known/did.jsonl` — public, unauthenticated.
///
/// Serves the VTA's own `did:webvh` log at the standard resolver path for a
/// *root-style* DID (`did:webvh:SCID:domain`, no path segments). Returns an
/// opaque 404 for every other case — including a pathful VTA DID, whose log is
/// served by [`get_vta_canonical_did_log_handler`] instead.
#[utoipa::path(
    get, path = "/.well-known/did.jsonl", tag = "did-webvh",
    responses(
        (status = 200, description = "VTA did.jsonl log", content_type = "text/jsonl"),
        (status = 304, description = "Not modified: If-None-Match names the current ETag"),
        (status = 429, description = "Rate limited by the VTA (`x-rate-limit-source: vta`)"),
        (status = 404, description = "VTA has no self-hosted did:webvh identity at this path"),
    ),
)]
pub async fn get_vta_well_known_did_log_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    serve_canonical(&state, &headers, "/.well-known/did.jsonl").await
}

/// `GET /{*did_log_path}` — public, unauthenticated catch-all.
///
/// Serves the VTA's own `did:webvh` log when the configured VTA DID is
/// *pathful* (`did:webvh:SCID:domain:tenant:vta` → `/tenant/vta/did.jsonl`).
/// Every non-matching request returns a bare 404 (empty body), so mounting
/// this as the unauth catch-all does not change the response shape of
/// unrelated unknown GETs.
///
/// INVARIANT: this must remain the *only* root-level wildcard route in the
/// router. A second `/{*...}` or an overlapping `nest()` at the root would
/// conflict in axum's matcher. See the module docs for why the request path is
/// never used as a store key.
pub async fn get_vta_canonical_did_log_handler(
    State(state): State<AppState>,
    Path(did_log_path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_path = format!("/{}", did_log_path.trim_start_matches('/'));
    // Cheap pre-filter: reject anything that can't be a did.jsonl request
    // before taking the config lock, so the bulk of catch-all traffic
    // (unrelated unknown GETs) stays as cheap as axum's default 404.
    if !request_path.ends_with("/did.jsonl") {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_canonical(&state, &headers, &request_path).await
}

/// Serve the VTA's self-hosted `did.jsonl` iff `request_path` is exactly the
/// canonical resolver path of the configured VTA DID. See the module-level
/// security model for the equality-not-lookup and opaque-404 guarantees.
async fn serve_canonical(state: &AppState, headers: &HeaderMap, request_path: &str) -> Response {
    let Some((vta_did, expected_path)) = configured_canonical_path(state).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request_path != expected_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    match crate::webvh_store::get_did_log(&state.webvh_ks, &vta_did).await {
        Ok(Some(log)) => did_log_response(headers, log),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            // Genuine storage failure: keep it visible in logs but return an
            // opaque 500 (no internal detail in the body).
            tracing::warn!(error = %e, "failed to read VTA did.jsonl from store");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `(vta_did, canonical_request_path)` for the configured VTA DID, or `None`
/// if the VTA has no self-hosted `did:webvh` identity (no DID configured, the
/// DID isn't `did:webvh`, or it can't be parsed into a webvh URL). Collapses
/// every "not self-hosting" reason into `None` so callers emit a single opaque
/// 404.
async fn configured_canonical_path(state: &AppState) -> Option<(String, String)> {
    let vta_did = state.config.read().await.vta_did.clone()?;
    if !vta_did.starts_with("did:webvh:") {
        return None;
    }
    let parsed = WebVHURL::parse_did_url(&vta_did).ok()?;
    let path = parsed.path.trim_end_matches('/');
    Some((vta_did, format!("{path}/did.jsonl")))
}

/// Serve a public `did.jsonl`: a 200 with the log, or a 304 when the request's
/// `If-None-Match` already names this log's `ETag`. Shared by every public
/// DID-log route (self-hosted canonical paths, `/did/{did}/log`, TEE
/// `/attestation/did-log`) so they cache identically.
///
/// Built explicitly (rather than via a `String` body) so there is exactly one
/// `content-type` header — these endpoints sit at the router root, outside any
/// website-router security-headers middleware, so a browser must not be able
/// to content-sniff the jsonl into something executable. Mirrors the VTC's
/// `did_log` route.
///
/// Only ever called with a log in hand: a 404 never carries these headers, so
/// caching metadata cannot distinguish one "not found" reason from another.
pub(super) fn did_log_response(request_headers: &HeaderMap, log: String) -> Response {
    let etag = did_log_etag(log.as_bytes());
    let cache_control = format!("public, max-age={DID_LOG_MAX_AGE_SECS}");
    let not_modified = if_none_match_hits(request_headers, &etag);
    let builder = Response::builder()
        .status(if not_modified {
            StatusCode::NOT_MODIFIED
        } else {
            StatusCode::OK
        })
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, cache_control)
        .header("x-content-type-options", "nosniff");
    if not_modified {
        builder.body(Body::empty())
    } else {
        builder
            .header(header::CONTENT_TYPE, JSONL_CONTENT_TYPE)
            .body(Body::from(log))
    }
    .expect("static headers + owned body always build a valid response")
}

/// Strong entity tag over the exact log bytes: `"sha256-<hex>"`. Any change to
/// the log — including a new appended entry — changes the tag.
fn did_log_etag(log: &[u8]) -> HeaderValue {
    let digest = Sha256::digest(log);
    HeaderValue::from_str(&format!("\"sha256-{}\"", hex::encode(digest)))
        .expect("quoted hex is a valid header value")
}

/// Does `If-None-Match` match `etag`? RFC 9110 §13.1.2: `*` matches any current
/// representation, otherwise a comma-separated list compared with the *weak*
/// comparison function (a `W/` prefix is ignored). A malformed header simply
/// does not match, so the client gets the full 200.
fn if_none_match_hits(request_headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Ok(etag) = etag.to_str() else {
        return false;
    };
    request_headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
        })
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// GET `uri` against a freshly-built app configured with `vta_did` and an
    /// optional seeded `(did, log)` entry. Returns (status, content-type, body).
    async fn get(
        uri: &str,
        vta_did: Option<&str>,
        seed: Option<(&str, &str)>,
    ) -> (StatusCode, Option<String>, Vec<u8>) {
        let (status, headers, body) = get_with(uri, vta_did, seed, None).await;
        let content_type = headers
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        (status, content_type, body)
    }

    /// As [`get`], optionally sending `If-None-Match`, returning all headers.
    async fn get_with(
        uri: &str,
        vta_did: Option<&str>,
        seed: Option<(&str, &str)>,
        if_none_match: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let (app, ctx) = crate::test_support::build_test_app().await;
        ctx.config.write().await.vta_did = vta_did.map(str::to_string);
        if let Some((did, log)) = seed {
            crate::webvh_store::store_did_log(&ctx.webvh_ks, did, log)
                .await
                .expect("seed did log");
        }
        let mut req = Request::builder()
            .uri(uri)
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1");
        if let Some(tag) = if_none_match {
            req = req.header("if-none-match", tag);
        }
        let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    const ROOT_DID: &str = "did:webvh:QmSCID:example.com";
    const ROOT_LOG: &str = "{\"versionId\":\"1-abc\"}\n";

    #[tokio::test]
    async fn log_response_carries_strong_etag_and_short_public_max_age() {
        let (status, headers, _) = get_with(
            "/.well-known/did.jsonl",
            Some(ROOT_DID),
            Some((ROOT_DID, ROOT_LOG)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "public, max-age=60");
        let etag = headers["etag"].to_str().unwrap();
        assert!(
            etag.starts_with("\"sha256-") && etag.ends_with('"'),
            "strong quoted etag expected, got {etag}"
        );
        assert!(!etag.starts_with("W/"), "etag must be strong");
    }

    #[tokio::test]
    async fn if_none_match_with_current_etag_returns_304_without_body() {
        let (_, headers, _) = get_with(
            "/.well-known/did.jsonl",
            Some(ROOT_DID),
            Some((ROOT_DID, ROOT_LOG)),
            None,
        )
        .await;
        let etag = headers["etag"].to_str().unwrap().to_string();

        // Exact tag, a list containing it, its weak form, and `*` all match.
        for inm in [
            etag.clone(),
            format!("\"other\", {etag}"),
            format!("W/{etag}"),
            "*".to_string(),
        ] {
            let (status, h, body) = get_with(
                "/.well-known/did.jsonl",
                Some(ROOT_DID),
                Some((ROOT_DID, ROOT_LOG)),
                Some(&inm),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_MODIFIED, "If-None-Match: {inm}");
            assert!(body.is_empty(), "304 must have no body");
            assert_eq!(h["etag"].to_str().unwrap(), etag);
            assert_eq!(h["cache-control"], "public, max-age=60");
        }
    }

    #[tokio::test]
    async fn stale_etag_gets_the_full_log() {
        let (status, headers, body) = get_with(
            "/.well-known/did.jsonl",
            Some(ROOT_DID),
            Some((ROOT_DID, ROOT_LOG)),
            Some("\"sha256-00\""),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "text/jsonl");
        assert_eq!(body, ROOT_LOG.as_bytes());
    }

    #[tokio::test]
    async fn etag_changes_when_the_log_grows() {
        let (_, a, _) = get_with(
            "/.well-known/did.jsonl",
            Some(ROOT_DID),
            Some((ROOT_DID, ROOT_LOG)),
            None,
        )
        .await;
        let grown = format!("{ROOT_LOG}{{\"versionId\":\"2-def\"}}\n");
        let (_, b, _) = get_with(
            "/.well-known/did.jsonl",
            Some(ROOT_DID),
            Some((ROOT_DID, &grown)),
            None,
        )
        .await;
        assert_ne!(a["etag"], b["etag"]);
    }

    #[tokio::test]
    async fn not_found_carries_no_caching_headers_even_with_if_none_match() {
        // `*` would match any representation — but there is none, so this
        // must stay the opaque bare 404, with nothing that fingerprints why.
        for (uri, did) in [
            ("/.well-known/did.jsonl", None),
            (
                "/.well-known/did.jsonl",
                Some("did:webvh:QmSCID:example.com:t:vta"),
            ),
            ("/wrong/did.jsonl", Some(ROOT_DID)),
            ("/totally/unknown", Some(ROOT_DID)),
        ] {
            let (status, h, body) = get_with(uri, did, None, Some("*")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.is_empty(), "{uri}");
            assert!(h.get("etag").is_none(), "{uri}");
            assert!(h.get("cache-control").is_none(), "{uri}");
        }
    }

    #[tokio::test]
    async fn well_known_serves_root_webvh_log_with_spec_headers() {
        let did = "did:webvh:QmSCID:example.com";
        let log = r#"{"versionId":"1-abc","versionTime":"2025-01-01T00:00:00Z"}"#;
        let (status, ct, body) = get("/.well-known/did.jsonl", Some(did), Some((did, log))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct.as_deref(), Some("text/jsonl"));
        assert_eq!(body, log.as_bytes());
    }

    #[tokio::test]
    async fn well_known_404_for_pathful_did() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let (status, _, body) = get("/.well-known/did.jsonl", Some(did), Some((did, "{}\n"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "404 must be opaque (empty body)");
    }

    #[tokio::test]
    async fn canonical_path_serves_pathful_log() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let log = "{\"versionId\":\"1-abc\"}\n";
        let (status, ct, body) = get("/tenant/vta/did.jsonl", Some(did), Some((did, log))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct.as_deref(), Some("text/jsonl"));
        assert_eq!(body, log.as_bytes());
    }

    #[tokio::test]
    async fn catch_all_404_for_non_canonical_did_jsonl_path() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let (status, _, body) = get("/wrong/path/did.jsonl", Some(did), Some((did, "{}\n"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "non-canonical path must be opaque");
    }

    #[tokio::test]
    async fn catch_all_unknown_path_is_bare_404() {
        // An unrelated unknown GET must look exactly like axum's default 404
        // (empty body) — the catch-all must not change the 404 surface.
        let did = "did:webvh:QmSCID:example.com";
        let (status, _, body) = get("/totally/unknown/resource", Some(did), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn well_known_404_when_no_vta_did() {
        let (status, _, body) = get("/.well-known/did.jsonl", None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "must not reveal that no DID is configured");
    }

    #[tokio::test]
    async fn well_known_404_for_non_webvh_did() {
        // A did:key VTA must 404 opaquely — no fingerprinting the method.
        let (status, _, body) = get("/.well-known/did.jsonl", Some("did:key:z6Mkabc"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn catch_all_does_not_shadow_authed_route() {
        // GET /keys is a real authed route. Without a bearer it must be
        // rejected by its auth extractor (not swallowed into the catch-all's
        // 404), proving static routes keep precedence over the wildcard.
        let (app, _ctx) = crate::test_support::build_test_app().await;
        let req = Request::builder()
            .uri("/keys")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "real route must not be shadowed by the did.jsonl catch-all"
        );
    }
}
