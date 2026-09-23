//! `GET /community/did-qr.svg` — the community DID as a QR code.
//!
//! The default landing page shows it so a wallet (Keyring first) can add the
//! community by scanning instead of retyping a 70-character DID. It is rendered
//! here rather than in the page because the default site has no build step and
//! its CSP forbids inline script — and because an operator who replaces the site
//! (`website.root_dir`) then gets the same code with one `<img>` tag.
//!
//! The code carries the **bare DID** and nothing else: exactly what the page's
//! Copy button copies. A DID is already a URI (scheme `did`), so a phone's
//! camera can hand it to any app registered for that scheme; a `did://` wrapper
//! would be a second format every scanner has to unwrap. Nothing here is secret
//! — the same DID is served unauthenticated by `public-profile`, `/health` and
//! `/.well-known/did.jsonl`.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use vti_common::error::AppError;

use crate::community::profile::load_profile;
use crate::server::AppState;

/// Render `did` as a standalone SVG QR code, dark modules on white with the
/// four-module quiet zone scanners need.
///
/// Level M, as the Keyring enrolment offer uses: a did:webvh fits a version-5
/// code (37 modules), which stays easy to scan off a laptop screen.
pub(crate) fn did_qr_svg(did: &str) -> Result<String, AppError> {
    let code = QrCode::with_error_correction_level(did.as_bytes(), EcLevel::M)
        .map_err(|e| AppError::Internal(format!("community DID does not fit a QR code: {e}")))?;
    Ok(code
        .render::<svg::Color>()
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build())
}

/// GET /community/did-qr.svg — the community DID as a scannable QR code.
/// Public, unauthenticated.
#[utoipa::path(
    get, path = "/community/did-qr.svg", tag = "community",
    responses(
        (status = 200, description = "SVG QR code encoding the bare community DID",
            content_type = "image/svg+xml", body = String),
        (status = 404, description = "Community profile not initialised"),
    ),
)]
pub async fn get_did_qr(State(state): State<AppState>) -> Result<Response, AppError> {
    // Same source as `public-profile`'s `communityDid`, so the code and the
    // text beside it on the page cannot disagree.
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    let svg = did_qr_svg(&profile.community_did)?;
    Ok((
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            // The community DID is immutable once set, but a short lifetime
            // keeps a pre-setup placeholder from sticking in a cache.
            (header::CACHE_CONTROL, "public, max-age=300"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // Opened directly, the document still may run nothing.
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'"),
        ],
        svg,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_webvh_renders_as_a_standalone_svg() {
        let did =
            "did:webvh:QmXi1PZD4NEvcvjfErAzVoCGtBFEv7dhXZQJHvcFY4U83F:webvh.storm.ws:first-vtc";
        let svg = did_qr_svg(did).expect("a did:webvh fits");
        assert!(svg.contains("<svg"), "{svg}");
        assert!(svg.contains("viewBox"), "the page sizes it with CSS");
        assert!(!svg.contains("<script"), "nothing executable");
    }

    #[test]
    fn a_did_webvh_is_a_version_5_code() {
        // Level M, version 5 is 37 modules; with the 4-module quiet zone on
        // both sides and the renderer's default 8 px modules: (37 + 8) * 8.
        let did =
            "did:webvh:QmXi1PZD4NEvcvjfErAzVoCGtBFEv7dhXZQJHvcFY4U83F:webvh.storm.ws:first-vtc";
        let code = QrCode::with_error_correction_level(did.as_bytes(), EcLevel::M).unwrap();
        assert_eq!(code.width(), 37);
        assert!(did_qr_svg(did).unwrap().contains(r#"width="360""#));
    }
}
