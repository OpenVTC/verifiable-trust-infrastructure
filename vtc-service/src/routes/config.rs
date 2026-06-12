use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::server::AppState;

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub vtc_did: Option<String>,
    pub vtc_name: Option<String>,
    pub vtc_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub vtc_did: Option<String>,
    pub vtc_name: Option<String>,
    pub vtc_description: Option<String>,
    pub public_url: Option<String>,
}

pub async fn get_config(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, AppError> {
    let config = state.config.read().await;
    info!(caller = %_auth.did, "config retrieved");
    Ok(Json(ConfigResponse {
        vtc_did: config.vtc_did.clone(),
        vtc_name: config.vtc_name.clone(),
        vtc_description: config.vtc_description.clone(),
        public_url: config.public_url.clone(),
    }))
}

pub async fn update_config(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<ConfigResponse>, AppError> {
    let (response, contents, path) = {
        let mut config = state.config.write().await;

        if let Some(vtc_did) = req.vtc_did {
            config.vtc_did = Some(vtc_did);
        }
        if let Some(vtc_name) = req.vtc_name {
            config.vtc_name = Some(vtc_name);
        }
        if let Some(vtc_description) = req.vtc_description {
            config.vtc_description = Some(vtc_description);
        }
        if let Some(public_url) = req.public_url {
            config.public_url = Some(public_url);
        }

        let response = ConfigResponse {
            vtc_did: config.vtc_did.clone(),
            vtc_name: config.vtc_name.clone(),
            vtc_description: config.vtc_description.clone(),
            public_url: config.public_url.clone(),
        };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();

        (response, contents, path)
    }; // write lock released here

    std::fs::write(&path, contents).map_err(AppError::Io)?;
    // Re-harden after every rewrite: config.toml holds the JWT signing key
    // (and, under the config-secret backend, the key bundle).
    crate::secure_file::restrict_file_to_owner(&path).map_err(AppError::Io)?;

    info!(caller = %_auth.0.did, "config updated");
    Ok(Json(response))
}
