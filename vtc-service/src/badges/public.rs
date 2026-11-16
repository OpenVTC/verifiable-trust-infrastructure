//! The public artefacts of a badge its holders may show outside (VTI-BDG-051): the
//! badge's Achievement document and its picture, at the stable locations the credential
//! names — `<public_url>/badges/<badgeId>` and `<public_url>/badges/<badgeId>/image`.
//!
//! Served over plain HTTPS to Open Badges verifiers, a foreign protocol, so these are
//! REST routes by design, mounted at the parent root beside the identity logs and let
//! through the surface gate on every host (`routing::host_dispatch`). Unauthenticated:
//! a verifier carries no credential. They name no holder and no count (VTI-BDG-071),
//! and answer only for a badge marked `shareableOutside`: the picture of a badge kept
//! inside the community is shown to active members only (VTI-BDG-050), through
//! `vtc/badges/images/get`.
//!
//! A holder's **share** of one award (`vtc/badges/awards/share`, VTI-BDG-070) is served
//! here too, at `<public_url>/badges/shared/<token>`: the credential exactly as issued to
//! an Open Badges verifier (any request not asking for HTML), or a page verifying it for a
//! person; and at `…/<token>/image.png`, the picture with that credential baked in. A token
//! whose share no longer stands answers the same `404` as one never issued.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::{Badge, share};
use crate::server::AppState;

/// The path segment under the public origin.
pub const BADGE_PATH: &str = "badges";

/// A badge identifier as the family spells it: `bdg_` and 16 to 64 base64url characters.
fn plain_badge_id(id: &str) -> bool {
    id.strip_prefix("bdg_").is_some_and(|rest| {
        (16..=64).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// Whether `path` is a badge artefact this service may serve: the surface gate lets it
/// through on every host, as it does an identity's log.
pub fn is_badge_artefact_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(&format!("/{BADGE_PATH}/")) else {
        return false;
    };
    if let Some(shared) = rest.strip_prefix("shared/") {
        let token = shared.strip_suffix("/image.png").unwrap_or(shared);
        return share::plain_token(token);
    }
    let id = rest.strip_suffix("/image").unwrap_or(rest);
    plain_badge_id(id)
}

/// The badge `id` names, where it is one its holders may show outside; `None` answers
/// `404` for an unknown, malformed or inside-only badge alike. `Err(())` is a store
/// failure, already logged, answered `500`.
async fn shareable(state: &AppState, id: &str) -> Result<Option<Badge>, ()> {
    if !plain_badge_id(id) {
        return Ok(None);
    }
    match super::get_badge(&state.badges_ks, id).await {
        Ok(Some(b)) if b.shareable_outside => Ok(Some(b)),
        Ok(_) => Ok(None),
        Err(e) => {
            tracing::warn!(error = %e, "could not read a badge for its public artefact");
            Err(())
        }
    }
}

fn unavailable() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "badge unavailable").into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "no such badge").into_response()
}

const CACHE: &str = "public, max-age=300";

/// `GET /badges/{id}` — the Achievement document of a badge its holders may show
/// outside, as its credentials name it. Kept at a stable location through the badge's
/// retirement, since credentials already issued name it.
pub async fn serve_achievement(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let badge = match shareable(&state, &id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(),
        Err(()) => return unavailable(),
    };
    let public_url = state.config.read().await.public_url.clone();
    let Ok(creator) = super::credential::load_community_profile(&state).await else {
        return unavailable();
    };
    let mut doc = super::credential::achievement(&creator, &badge, public_url.as_deref());
    doc["@context"] = json!(super::credential::OB_CONTEXT);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/ld+json; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
        ],
        doc.to_string(),
    )
        .into_response()
}

/// `GET /badges/{id}/image` — the picture of a badge its holders may show outside: the
/// community's own re-encoding, as `vtc/badges/images/get` answers members.
pub async fn serve_image(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let badge = match shareable(&state, &id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(),
        Err(()) => return unavailable(),
    };
    let Some(sha) = crate::directory::images::sha_of(&badge.image) else {
        return not_found();
    };
    match crate::directory::images::get(&state.badge_images_ks, sha).await {
        Ok(Some((meta, bytes))) => {
            let media = HeaderValue::from_str(&meta.media_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, media),
                    (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
                ],
                bytes,
            )
                .into_response()
        }
        Ok(None) => not_found(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read a badge's picture for its public artefact");
            (StatusCode::INTERNAL_SERVER_ERROR, "picture unavailable").into_response()
        }
    }
}

/// The share `token` names, where it still stands; `None` answers `404` alike for a
/// token never issued and one whose share has stopped.
async fn shared(
    state: &AppState,
    token: &str,
) -> Result<Option<(super::Award, Badge, serde_json::Value)>, ()> {
    share::resolve(&state.badges_ks, token).await.map_err(|e| {
        tracing::warn!(error = %e, "could not read a badge share");
    })
}

/// Whether the request asks for a page rather than the credential: a browser's `Accept`.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

/// What the community can say of the credential it serves, for the page: whether its slot
/// in the community's revocation list is set, and whether it is in its validity period.
struct Verification {
    revoked: Option<bool>,
    valid_now: bool,
    valid_until: Option<String>,
}

async fn verify(state: &AppState, credential: &serde_json::Value) -> Verification {
    let now = chrono::Utc::now();
    let valid_until = credential["validUntil"].as_str().map(str::to_string);
    let in_period = |key: &str, after: bool| {
        credential[key]
            .as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .is_none_or(|t| if after { now >= t } else { now < t })
    };
    let valid_now = in_period("validFrom", true) && in_period("validUntil", false);
    let index = credential["credentialStatus"]["statusListIndex"]
        .as_str()
        .and_then(|i| i.parse::<usize>().ok());
    let revoked = match index {
        Some(i) => crate::status_list::get_state(
            &state.status_lists_ks,
            affinidi_status_list::StatusPurpose::Revocation,
        )
        .await
        .ok()
        .flatten()
        .map(|row| row.is_set(i)),
        None => None,
    };
    Verification {
        revoked,
        valid_now,
        valid_until,
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The share page: the badge, who issued it, and what the community verifies of the
/// credential — never another holder or a count (VTI-BDG-071).
fn page(badge: &Badge, credential: &serde_json::Value, v: &Verification, image: &str) -> String {
    let issuer = credential["issuer"]["name"]
        .as_str()
        .or_else(|| credential["issuer"]["id"].as_str())
        .unwrap_or("");
    let (verdict, class) = match (v.revoked, v.valid_now) {
        (Some(true), _) => (
            "Revoked: the community no longer stands behind this badge.",
            "bad",
        ),
        (_, false) => (
            "Expired: this credential is outside its validity period.",
            "bad",
        ),
        (None, true) => ("Issued by the community and in its validity period.", "ok"),
        (Some(false), true) => (
            "Verified: issued by the community, in force and not revoked.",
            "ok",
        ),
    };
    let until = v
        .valid_until
        .as_deref()
        .map(|u| format!("<p class=\"meta\">Valid until {}</p>", esc(u)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{name} — badge</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1c1f24}}
main{{max-width:34rem;margin:3rem auto;padding:0 1rem}}
.card{{background:#fff;border-radius:12px;padding:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}}
img{{width:160px;height:160px;object-fit:contain}}
h1{{font-size:1.4rem;margin:.75rem 0 .25rem}}
.meta{{color:#5b6270;font-size:.9rem;margin:.25rem 0}}
.verdict{{margin:1rem 0 0;padding:.6rem .8rem;border-radius:8px;font-size:.95rem}}
.ok{{background:#e7f6ec;color:#1d6b38}} .bad{{background:#fdecec;color:#9b1c1c}}
@media (prefers-color-scheme:dark){{body{{background:#14161a;color:#e6e8eb}}.card{{background:#1d2026}}.meta{{color:#a3a9b5}}}}
</style></head>
<body><main><div class="card">
<img src="{image}" alt="">
<h1>{name}</h1>
<p>{description}</p>
<p class="meta">Issued by {issuer}</p>
{until}
<p class="verdict {class}">{verdict}</p>
</div>
<p class="meta">An Open Badges 3.0 credential. Verifiers fetch it from this address without asking for HTML.</p>
</main></body></html>
"#,
        name = esc(&badge.name),
        description = esc(&badge.description),
        issuer = esc(issuer),
        image = esc(image),
    )
}

const SHARED_CSP: &str = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; \
                          base-uri 'none'; frame-ancestors 'none'";

/// `GET /badges/shared/{token}` — a holder's share (`vtc/badges/awards/share` item 5): the
/// credential exactly as issued, or, to a browser, a page verifying it. Cached for a
/// minute at most, so a stopped share soon stops answering anywhere.
pub async fn serve_shared(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (_award, badge, credential) = match shared(&state, &token).await {
        Ok(Some(x)) => x,
        Ok(None) => return not_found(),
        Err(()) => return unavailable(),
    };
    let cache = HeaderValue::from_static("public, max-age=60");
    if wants_html(&headers) {
        let public_url = state.config.read().await.public_url.clone();
        let image =
            super::credential::public_image_url(&badge, public_url.as_deref()).unwrap_or_default();
        let v = verify(&state, &credential).await;
        return (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (header::CACHE_CONTROL, cache),
                (
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(SHARED_CSP),
                ),
            ],
            page(&badge, &credential, &v, &image),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/vc+ld+json; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, cache),
        ],
        credential.to_string(),
    )
        .into_response()
}

/// `GET /badges/shared/{token}/image.png` — the badge's picture with the shared credential
/// baked in (`share` item 6).
pub async fn serve_shared_image(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let (_award, badge, credential) = match shared(&state, &token).await {
        Ok(Some(x)) => x,
        Ok(None) => return not_found(),
        Err(()) => return unavailable(),
    };
    let Some(sha) = crate::directory::images::sha_of(&badge.image) else {
        return not_found();
    };
    let bytes = match crate::directory::images::get(&state.badge_images_ks, sha).await {
        Ok(Some((_, bytes))) => bytes,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read a badge's picture to bake");
            return unavailable();
        }
    };
    match share::bake_png(&bytes, &credential) {
        Ok(baked) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=60"),
                ),
            ],
            baked,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "could not bake a shared badge credential");
            unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_surface_gate_lets_badge_artefacts_through_and_nothing_else() {
        assert!(is_badge_artefact_path("/badges/bdg_W5k2N8xRb3Qz7TpLAAAAAA"));
        assert!(is_badge_artefact_path(
            "/badges/bdg_W5k2N8xRb3Qz7TpLAAAAAA/image"
        ));
        assert!(!is_badge_artefact_path("/badges/bdg_short"));
        assert!(!is_badge_artefact_path("/badges/../etc"));
        assert!(!is_badge_artefact_path(
            "/badges/bdg_W5k2N8xRb3Qz7TpLAAAAAA/other"
        ));
        assert!(!is_badge_artefact_path("/badges/"));
        assert!(!is_badge_artefact_path("/badge/bdg_W5k2N8xRb3Qz7TpLAAAAAA"));
        let token = "A".repeat(43);
        assert!(is_badge_artefact_path(&format!("/badges/shared/{token}")));
        assert!(is_badge_artefact_path(&format!(
            "/badges/shared/{token}/image.png"
        )));
        assert!(!is_badge_artefact_path("/badges/shared/short"));
        assert!(!is_badge_artefact_path(&format!(
            "/badges/shared/{token}/other"
        )));
    }
}
