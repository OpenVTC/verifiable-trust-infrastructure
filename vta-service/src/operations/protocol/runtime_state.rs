//! Persistent runtime state for service enable/disable.
//!
//! Previously the answer to "is REST/DIDComm currently enabled?" lived in
//! `config.toml` under `[services]`, and `pnm services {kind} {enable,disable}`
//! rewrote the whole config file on every flip. That made the on-disk config a
//! mutable runtime store, which it shouldn't be — config is for operator
//! intent, fjall is for runtime state.
//!
//! This module owns the runtime view. Boot, `pnm services list`, the REST
//! capabilities surface, and the DIDComm discovery surface all read from here;
//! enable/disable ops write here. The legacy `config.services.{rest,didcomm}`
//! fields are consulted only once by [`migrate_from_config`] on first boot
//! after upgrade, so a deployed VTA that had a service disabled doesn't
//! silently re-enable on restart.

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

const REST_KEY: &str = "runtime-state:service:rest";
const DIDCOMM_KEY: &str = "runtime-state:service:didcomm";
const TSP_KEY: &str = "runtime-state:service:tsp";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceState {
    enabled: bool,
}

/// True if REST should be active (advertised + serving). Defaults to enabled
/// when no state has been written yet, so a freshly-built VTA with REST
/// compiled in comes up serving REST without explicit configuration.
pub async fn is_rest_enabled(ks: &KeyspaceHandle) -> Result<bool, AppError> {
    Ok(ks
        .get::<ServiceState>(REST_KEY.to_string())
        .await?
        .map(|s| s.enabled)
        .unwrap_or(true))
}

/// True if DIDComm should be active (advertised + bridged to a mediator).
/// See [`is_rest_enabled`] for the default-on rationale.
pub async fn is_didcomm_enabled(ks: &KeyspaceHandle) -> Result<bool, AppError> {
    Ok(ks
        .get::<ServiceState>(DIDCOMM_KEY.to_string())
        .await?
        .map(|s| s.enabled)
        .unwrap_or(true))
}

/// True if TSP should be active (advertised + bridged to a mediator).
/// Defaults to **disabled** when no state has been written yet — TSP is
/// additive and off-by-default while it rolls out gated (see
/// `docs/05-design-notes/tsp-enablement.md`), so a freshly-built VTA does
/// not advertise TSP until the operator enables it explicitly.
pub async fn is_tsp_enabled(ks: &KeyspaceHandle) -> Result<bool, AppError> {
    Ok(ks
        .get::<ServiceState>(TSP_KEY.to_string())
        .await?
        .map(|s| s.enabled)
        .unwrap_or(false))
}

pub async fn set_rest_enabled(ks: &KeyspaceHandle, enabled: bool) -> Result<(), AppError> {
    ks.insert(REST_KEY.to_string(), &ServiceState { enabled })
        .await
}

pub async fn set_didcomm_enabled(ks: &KeyspaceHandle, enabled: bool) -> Result<(), AppError> {
    ks.insert(DIDCOMM_KEY.to_string(), &ServiceState { enabled })
        .await
}

pub async fn set_tsp_enabled(ks: &KeyspaceHandle, enabled: bool) -> Result<(), AppError> {
    ks.insert(TSP_KEY.to_string(), &ServiceState { enabled })
        .await
}

/// One-shot migration from the legacy `[services]` block in `config.toml`. If
/// fjall has no record for a service yet (first boot post-upgrade), seed it
/// from `config.services.{rest,didcomm}`. Subsequent boots find the fjall
/// record and ignore the legacy fields entirely. Idempotent — safe to call on
/// every boot.
pub async fn migrate_from_config(ks: &KeyspaceHandle, config: &AppConfig) -> Result<(), AppError> {
    if ks
        .get::<ServiceState>(REST_KEY.to_string())
        .await?
        .is_none()
    {
        set_rest_enabled(ks, config.services.rest).await?;
    }
    if ks
        .get::<ServiceState>(DIDCOMM_KEY.to_string())
        .await?
        .is_none()
    {
        set_didcomm_enabled(ks, config.services.didcomm).await?;
    }
    if ks.get::<ServiceState>(TSP_KEY.to_string()).await?.is_none() {
        set_tsp_enabled(ks, config.services.tsp).await?;
    }
    Ok(())
}
