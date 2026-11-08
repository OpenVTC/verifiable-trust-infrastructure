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

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::Badge;
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
    let (community_did, public_url) = {
        let config = state.config.read().await;
        (
            config.vtc_did.clone().unwrap_or_default(),
            config.public_url.clone(),
        )
    };
    let mut doc = super::credential::achievement(
        &community_did,
        &badge,
        public_url.as_deref(),
        badge.endorsement.as_ref(),
    );
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
    }
}
