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
//! - **`public_url` is persisted env-safely + atomically.** It is the
//!   operational RP origin the WebAuthn handle + status-list URLs derive from at
//!   boot, so it stays in `config.toml`; the write re-reads the on-disk TOML as
//!   its base (ephemeral `VTC_*` env overlays never leak in), writes
//!   tempfile-then-rename, and re-restricts perms. It is boot-stable, so the
//!   response flags it under `pending_restart`.
//!
//! Migrating `public_url` into the `config_store` overlay as a
//! `requires_restart` key (so it shares the canonical PATCH surface) is the
//! follow-up increment — it needs the boot path to apply `config_store`
//! overrides, which it does not yet.

use std::path::Path;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::community::{CommunityProfileUpdate, load_profile, store_profile};
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

/// Response for `PATCH /v1/config`: the resolved view plus any boot-stable keys
/// that were stored but need a restart to take effect.
#[derive(Debug, Serialize)]
pub struct UpdateConfigResponse {
    #[serde(flatten)]
    pub config: ConfigResponse,
    pub pending_restart: Vec<String>,
}

#[derive(Debug, Deserialize)]
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

pub async fn get_config(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, AppError> {
    let (vtc_name, vtc_description) = resolved_name_description(&state).await?;
    let config = state.config.read().await;
    info!(caller = %auth.did, "config retrieved");
    Ok(Json(ConfigResponse {
        vtc_did: config.vtc_did.clone(),
        vtc_name,
        vtc_description,
        public_url: config.public_url.clone(),
    }))
}

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

    // public_url → the operational RP origin (WebAuthn + status-list URLs derive
    // from it at boot). Persist env-safely + atomically; restart required.
    if let Some(public_url) = req.public_url.clone() {
        let path = {
            let mut config = state.config.write().await;
            config.public_url = Some(public_url.clone());
            config.config_path.clone()
        };
        persist_public_url(&path, Some(&public_url))?;
        pending_restart.push("public_url".into());
    }

    let (vtc_name, vtc_description) = resolved_name_description(&state).await?;
    let config = state.config.read().await;
    info!(caller = %auth.0.did, ?pending_restart, "config updated");
    Ok(Json(UpdateConfigResponse {
        config: ConfigResponse {
            vtc_did: config.vtc_did.clone(),
            vtc_name,
            vtc_description,
            public_url: config.public_url.clone(),
        },
        pending_restart,
    }))
}

/// Persist `public_url` into `config.toml` **env-safely** and **atomically**.
///
/// Re-reads the on-disk TOML as the base so the ephemeral `VTC_*` env overlays
/// folded into the in-memory `AppConfig` are never baked into the file (P1.1) —
/// only the single `public_url` key is touched. Writes tempfile-then-rename for
/// atomicity and re-restricts the file to its owner (it holds the JWT signing
/// key, and under the config-secret backend the key bundle).
fn persist_public_url(path: &Path, public_url: Option<&str>) -> Result<(), AppError> {
    let existing = std::fs::read_to_string(path).map_err(AppError::Io)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;
    match public_url {
        Some(url) => {
            doc.insert("public_url".into(), toml::Value::String(url.to_string()));
        }
        None => {
            doc.remove("public_url");
        }
    }
    let contents = toml::to_string_pretty(&doc)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.toml");
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".{file_name}.tmp"));

    std::fs::write(&tmp, contents).map_err(AppError::Io)?;
    // Harden the temp file *before* the rename so the published file is never
    // briefly world-readable.
    crate::secure_file::restrict_file_to_owner(&tmp).map_err(AppError::Io)?;
    std::fs::rename(&tmp, path).map_err(AppError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn persist_public_url_is_env_safe_and_atomic() {
        // The on-disk base has no env-sourced values; updating public_url must
        // leave every other key exactly as written (no env-overlay bake-in).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "vtc_did = \"did:webvh:vtc.example\"\n\
             [server]\nhost = \"127.0.0.1\"\nport = 8200\n"
        )
        .unwrap();
        drop(f);

        persist_public_url(&path, Some("https://vtc.example.com")).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let doc: toml::Table = toml::from_str(&written).unwrap();
        assert_eq!(
            doc.get("public_url").and_then(|v| v.as_str()),
            Some("https://vtc.example.com")
        );
        // Untouched keys survive verbatim.
        assert_eq!(
            doc.get("vtc_did").and_then(|v| v.as_str()),
            Some("did:webvh:vtc.example")
        );
        let server = doc.get("server").and_then(|v| v.as_table()).unwrap();
        assert_eq!(
            server.get("host").and_then(|v| v.as_str()),
            Some("127.0.0.1")
        );
        assert_eq!(server.get("port").and_then(|v| v.as_integer()), Some(8200));

        // No leftover temp file.
        assert!(!dir.path().join(".config.toml.tmp").exists());
    }

    #[test]
    fn persist_public_url_none_removes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "public_url = \"https://old.example\"\n").unwrap();
        persist_public_url(&path, None).unwrap();
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(doc.get("public_url").is_none());
    }
}
