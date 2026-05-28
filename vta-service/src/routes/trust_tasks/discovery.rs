//! Discovery slice trust-task handler.
//!
//! Single URI (`spec/vta/discovery/capabilities/1.0`); any authenticated
//! caller. Mirrors the inline logic in `routes::capabilities::
//! capabilities`. If that grows beyond trivial it should move to
//! `operations::discovery`.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::discovery::{
    CapabilitiesBody, CapabilitiesResponse, FeaturesInfo, ServicesInfo, WebvhServerInfo,
};

use crate::auth::AuthClaims;
use crate::server::AppState;

// `app_error_to_reject` is only reachable when the `webvh` feature is
// on (the only branch that produces an `AppError`). Gate the import
// alongside to avoid an "unused import" lint in non-webvh combos.
#[cfg(feature = "webvh")]
use super::helpers::app_error_to_reject;
use super::helpers::{parse_payload, success_response};

/// URIs handled by this slice. Aggregated by the dispatcher's parity
/// harness — see the feature-gating convention in
/// `docs/05-design-notes/trust-task-feature-gating.md`.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
pub(super) const DISPATCHED_URIS: &[&str] =
    &[vta_sdk::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0];

/// Handler for `spec/vta/discovery/capabilities/1.0`.
pub(super) async fn handle_capabilities(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let _req: CapabilitiesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let config = state.config.read().await;

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

    #[cfg(feature = "webvh")]
    let webvh_servers = match crate::webvh_store::list_servers(&state.webvh_ks).await {
        Ok(servers) => servers
            .into_iter()
            .map(|s| WebvhServerInfo {
                id: s.id,
                label: s.label,
            })
            .collect(),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    #[cfg(not(feature = "webvh"))]
    let webvh_servers: Vec<WebvhServerInfo> = vec![];

    let mut did_creation_modes = vec!["vta-built".to_string()];
    if cfg!(feature = "webvh") {
        did_creation_modes.push("template".to_string());
        did_creation_modes.push("final".to_string());
        did_creation_modes.push("user-specified-keys".to_string());
    }

    let body = CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        services,
        webvh_servers,
        did_creation_modes,
    };
    success_response(&doc, body)
}
