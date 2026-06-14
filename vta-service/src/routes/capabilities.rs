use axum::Json;
use axum::extract::State;

use vta_sdk::protocols::discovery::{
    CapabilitiesResponse, FeaturesInfo, ServicesInfo, WebvhServerInfo,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// GET /capabilities — Discover VTA features, services, and WebVH servers.
///
/// Requires authentication — prevents leaking implementation details to
/// unauthenticated callers. Any authenticated role (including Reader) can access.
#[utoipa::path(
    get,
    path = "/capabilities",
    tag = "discovery",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "VTA capabilities, features, and WebVH servers", body = CapabilitiesResponse),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn capabilities(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<CapabilitiesResponse>, AppError> {
    let config = state.config.read().await;

    // Detect compiled features at build time
    let features = FeaturesInfo {
        webvh: cfg!(feature = "webvh"),
        didcomm: cfg!(feature = "didcomm"),
        tee: cfg!(feature = "tee"),
        rest: cfg!(feature = "rest"),
    };

    let services = ServicesInfo {
        rest: config.services.rest,
        didcomm: config.services.didcomm,
    };

    // List configured WebVH servers (if feature enabled)
    #[cfg(feature = "webvh")]
    let webvh_servers = {
        let servers = crate::webvh_store::list_servers(&state.webvh_ks).await?;
        servers
            .into_iter()
            .map(|s| WebvhServerInfo {
                id: s.id,
                label: s.label,
            })
            .collect()
    };
    #[cfg(not(feature = "webvh"))]
    let webvh_servers: Vec<WebvhServerInfo> = vec![];

    // Supported DID creation modes
    let mut did_creation_modes = vec!["vta-built".to_string()];
    if cfg!(feature = "webvh") {
        did_creation_modes.push("template".to_string());
        did_creation_modes.push("final".to_string());
        did_creation_modes.push("user-specified-keys".to_string());
    }

    Ok(Json(CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        services,
        webvh_servers,
        did_creation_modes,
    }))
}
