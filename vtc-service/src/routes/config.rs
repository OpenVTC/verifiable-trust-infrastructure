//! `GET / PATCH /v1/config` — the legacy community-config surface.
//!
//! P1.1 makes this a **safe, non-divergent** surface rather than a third
//! uncoordinated config-write path:
//!
//! - **Identity is immutable at runtime.** `vtc_did` / `vta_did` are set at
//!   `vtc setup`; a PATCH carrying either returns 409 and `config.toml` is left
//!   untouched. (Previously a PATCH could rewrite them → next-boot auth-dead or
//!   recovery-authority re-pointed.)
//! - **`CommunityProfile` is the sole owner of name/description.** A PATCH's
//!   `vtc_name` / `vtc_description` are applied to the profile, and
//!   `GET /v1/config` reads them back from the profile — so there is one write
//!   path per field, not two diverging copies.
//! - **`public_url` is canonical in the `config_store` overlay** (P1.1 part 2b).
//!   It is the operational RP origin the WebAuthn handle + status-list URLs
//!   derive from at boot, so it's `requires_restart`: a PATCH writes it to the
//!   db-overlay (not `config.toml`) and `config_store::apply_overrides` folds it
//!   onto `AppConfig` at the next boot. Both this surface and
//!   `PATCH /v1/admin/config` now write the same place — one canonical store,
//!   no `config.toml` round-trip. The response flags it under `pending_restart`.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::community::{CommunityProfileUpdate, load_profile, store_profile};
use crate::config_store::ConfigStore;
use crate::error::AppError;
use crate::server::AppState;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConfigResponse {
    pub vtc_did: Option<String>,
    pub vtc_name: Option<String>,
    pub vtc_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

/// Response for `PATCH /v1/config`: the resolved view plus any boot-stable keys
/// that were stored but need a restart to take effect.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpdateConfigResponse {
    #[serde(flatten)]
    pub config: ConfigResponse,
    pub pending_restart: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateConfigRequest {
    pub vtc_did: Option<String>,
    /// Recovery-authority DID. Like `vtc_did`, set at setup and rejected here.
    pub vta_did: Option<String>,
    pub vtc_name: Option<String>,
    pub vtc_description: Option<String>,
    pub public_url: Option<String>,
}

/// Resolve the name/description pair: the `CommunityProfile` is authoritative
/// once it exists; pre-profile (fresh install) we fall back to the TOML values.
async fn resolved_name_description(
    state: &AppState,
) -> Result<(Option<String>, Option<String>), AppError> {
    if let Some(profile) = load_profile(&state.community_ks).await? {
        Ok((Some(profile.name), Some(profile.description)))
    } else {
        let config = state.config.read().await;
        Ok((config.vtc_name.clone(), config.vtc_description.clone()))
    }
}

/// Resolve the effective `public_url` — the value in force, or pending after
/// a restart: `env > db-overlay > in-memory (toml/boot)`. After a PATCH the
/// db-overlay carries the new value, so GET reflects it even though it is
/// `requires_restart` and not yet live. Mirrors `config_store`'s precedence.
async fn resolved_public_url(state: &AppState) -> Result<Option<String>, AppError> {
    if let Ok(v) = std::env::var("VTC_PUBLIC_URL") {
        return Ok(Some(v));
    }
    let store = ConfigStore::new(state.config_ks.clone());
    if let Some(v) = store.get("public_url").await? {
        return Ok(v.as_str().map(str::to_string));
    }
    Ok(state.config.read().await.public_url.clone())
}

/// GET /config — resolved community config view. Auth: any session.
#[utoipa::path(
    get, path = "/config", tag = "config",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Resolved config view", body = ConfigResponse),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn get_config(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, AppError> {
    let (vtc_name, vtc_description) = resolved_name_description(&state).await?;
    let public_url = resolved_public_url(&state).await?;
    let vtc_did = state.config.read().await.vtc_did.clone();
    info!(caller = %auth.did, "config retrieved");
    Ok(Json(ConfigResponse {
        vtc_did,
        vtc_name,
        vtc_description,
        public_url,
    }))
}

/// PATCH /config — update mutable community config. Auth: Super-admin.
#[utoipa::path(
    patch, path = "/config", tag = "config",
    security(("bearer_jwt" = [])),
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Updated config view", body = UpdateConfigResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 409, description = "Attempt to rewrite immutable identity (vtc_did / vta_did)"),
    ),
)]
pub async fn update_config(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<UpdateConfigResponse>, AppError> {
    // Identity is set at `vtc setup` and never rewriteable at runtime — a
    // mistaken PATCH must not strand the daemon auth-dead or re-point the
    // recovery authority. `config.toml` is left untouched on this path.
    if req.vtc_did.is_some() || req.vta_did.is_some() {
        return Err(AppError::Conflict(
            "vtc_did / vta_did are set at `vtc setup` and cannot be changed at runtime; \
             refusing to rewrite community identity"
                .into(),
        ));
    }

    let mut pending_restart = Vec::new();

    // name/description → the CommunityProfile (sole owner). One write path.
    if req.vtc_name.is_some() || req.vtc_description.is_some() {
        let mut profile = load_profile(&state.community_ks).await?.ok_or_else(|| {
            AppError::Conflict(
                "community profile not initialised — set name/description at setup or via \
                 `PUT /v1/community/profile` first"
                    .into(),
            )
        })?;
        let patch = CommunityProfileUpdate {
            name: req.vtc_name.clone(),
            description: req.vtc_description.clone(),
            ..CommunityProfileUpdate::default()
        };
        let changed = patch.apply(&mut profile)?;
        if !changed.is_empty() {
            store_profile(&state.community_ks, &profile).await?;
        }
    }

    // public_url → the `config_store` db-overlay (canonical, P1.1 part 2b). It
    // is the operational RP origin (WebAuthn + status-list URLs derive from it
    // at boot), so it's `requires_restart`: stored now, folded onto `AppConfig`
    // at the next boot by `apply_overrides`. We deliberately do NOT touch the
    // in-memory value — mutating it would diverge the live derived state (the
    // already-built WebAuthn RP) from the stored config.
    if let Some(public_url) = req.public_url.clone() {
        let store = ConfigStore::new(state.config_ks.clone());
        store
            .put("public_url", &serde_json::Value::String(public_url))
            .await?;
        pending_restart.push("public_url".into());
    }

    let (vtc_name, vtc_description) = resolved_name_description(&state).await?;
    let public_url = resolved_public_url(&state).await?;
    let vtc_did = state.config.read().await.vtc_did.clone();
    info!(caller = %auth.0.did, ?pending_restart, "config updated");
    Ok(Json(UpdateConfigResponse {
        config: ConfigResponse {
            vtc_did,
            vtc_name,
            vtc_description,
            public_url,
        },
        pending_restart,
    }))
}

// Behavioural coverage lives in `tests/config_legacy.rs` — the
// `public_url` write path now stores to the `config_store` db-overlay
// (canonical, P1.1 part 2b) rather than rewriting `config.toml`, so the
// round-trip is exercised through the full router stack there. Per-key
// overlay precedence is unit-tested in `crate::config_store::tests`.
