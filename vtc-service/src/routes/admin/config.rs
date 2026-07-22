//! `GET / PATCH /v1/admin/config` handlers.
//!
//! Implements **M0.8.2** of the VTC MVP Phase 0 plan.
//!
//! - **GET**: returns the four-layer-merged [`EffectiveConfig`].
//! - **PATCH**: writes overrides to the db-layer (`config` keyspace),
//!   returning `{ applied, pending_restart, rejected }` so the
//!   caller can tell which keys took effect immediately, which
//!   require a daemon restart (M0.8.3), and which were rejected
//!   (and why).
//!
//! Every mutating handler emits an audit event keyed to the calling
//! admin's real DID (the `AdminAuth` extractor's `did`). Sensitive
//! values are run through `vti_common::audit::ConfigChange::redact_if`
//! before the `ConfigChanged` event is persisted. Audit is
//! fail-closed: a mutation that produces a change but cannot be
//! recorded (no `AuditWriter` configured) returns 503 rather than
//! applying silently.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::community::{CommunityProfile, CommunityProfileUpdate, load_profile, store_profile};
use crate::config_store::{
    ConfigStore, EffectiveConfig, compute_effective_config, lookup, validate_value,
};
use crate::server::AppState;
#[allow(unused_imports)]
use crate::supervisor::SupervisorKind;
use vti_common::audit::{
    AuditEvent, AuditWriter, CommunityProfileUpdatedData, ConfigChange, ConfigChangedData,
    ConfigReloadedData, ConfigSource, RestartRequestedData,
};

/// PATCH request body: a `key → value` map under `overrides`. Keys not in
/// [`crate::config_store::REGISTRY`] are reported back under
/// `rejected` rather than silently dropped.
///
/// The map is wrapped (rather than `#[serde(flatten)]`ed to the top level) to
/// match canonical `spec/config/patch/0.1`, whose envelope is
/// `additionalProperties: false` around a single `overrides` object.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchRequest {
    pub overrides: HashMap<String, Value>,
}

/// PATCH response body. Lists which keys took effect immediately,
/// which await restart, and which were rejected.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PatchResponse {
    pub applied: Vec<String>,
    pub pending_restart: Vec<String>,
    pub rejected: Vec<RejectedKey>,
}

/// One rejected key + the reason. Surfaced to the caller so the
/// admin UX can present a meaningful error inline.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RejectedKey {
    pub key: String,
    pub reason: String,
}

/// GET handler.
#[utoipa::path(
    get, path = "/admin/config", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Four-layer-merged effective config", body = EffectiveConfig),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn get_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<EffectiveConfig>, AppError> {
    let cfg = state.config.read().await;
    let store = ConfigStore::new(state.config_ks.clone());
    let eff = compute_effective_config(&cfg, &store).await?;
    Ok(Json(eff))
}

/// PATCH handler.
#[utoipa::path(
    patch, path = "/admin/config", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = PatchRequest,
    responses(
        (status = 200, description = "Applied / pending-restart / rejected keys", body = PatchResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn patch_config(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<PatchRequest>,
) -> Result<(StatusCode, Json<PatchResponse>), AppError> {
    let store = ConfigStore::new(state.config_ks.clone());
    // Snapshot the current db-layer overrides up front so each applied
    // key's audit record carries its real `old_value` + source.
    let current = store.snapshot().await?;
    let mut applied = Vec::new();
    let mut pending_restart = Vec::new();
    let mut rejected = Vec::new();
    let mut audit_changes: Vec<ConfigChange> = Vec::new();
    let mut requires_restart = false;

    for (key, value) in req.overrides {
        let Some(def) = lookup(&key) else {
            rejected.push(RejectedKey {
                key,
                reason: "unknown config key (not in registry)".into(),
            });
            continue;
        };

        if let Err(e) = validate_value(def, &value) {
            rejected.push(RejectedKey {
                key,
                reason: format!("validation failed: {e}"),
            });
            continue;
        }

        let old_value = current.get(&key).cloned();

        if let Err(e) = store.put(&key, &value).await {
            rejected.push(RejectedKey {
                key,
                reason: format!("persistence failed: {e}"),
            });
            continue;
        }

        info!(
            key = %key,
            requires_restart = def.requires_restart,
            sensitive = def.sensitive,
            "admin config PATCH applied"
        );

        let mut change = ConfigChange {
            key: key.clone(),
            old_value: old_value.clone(),
            new_value: value,
            // The db-overlay is the only PATCH-writable layer, so a
            // prior db value was `Db`; absence means the resolved
            // value came from a lower (env/toml/default) layer — we
            // record `Default` to match the import path's convention.
            source_before: if old_value.is_some() {
                ConfigSource::Db
            } else {
                ConfigSource::Default
            },
        };
        change.redact_if(|k| matches!(lookup(k), Some(d) if d.sensitive));
        audit_changes.push(change);

        if def.requires_restart {
            requires_restart = true;
            pending_restart.push(key);
        } else {
            applied.push(key);
        }
    }

    // Fail-closed: a config mutation that can't be audited is refused
    // (matches reload/restart/import). No applied changes → nothing to
    // audit, so a rejects-only or empty PATCH never needs the writer.
    if !audit_changes.is_empty() {
        let audit_writer = require_audit_writer(&state)?;
        audit_writer
            .write(
                &admin.0.did,
                None,
                AuditEvent::ConfigChanged(ConfigChangedData {
                    changes: audit_changes,
                    requires_restart,
                }),
            )
            .await?;
    }

    Ok((
        StatusCode::OK,
        Json(PatchResponse {
            applied,
            pending_restart,
            rejected,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

/// `restart.drain_timeout` default (seconds). Hardcoded for Phase 0
/// — surfaces in the `RestartRequested` audit event and bounds the
/// graceful-shutdown wait in `run_rest_thread`. A future
/// `restart.drain_timeout` config key plugs in here.
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

/// `POST /v1/admin/config/reload` response. Lists the keys whose
/// **db-layer** values were applied in-memory by this call. Keys
/// flagged `requires_restart` never appear here — they re-apply on
/// the next restart.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ReloadResponse {
    pub keys_reloaded: Vec<String>,
}

/// `POST /v1/admin/config/reload` handler. Re-reads the
/// `EffectiveConfig` and diffs against the live in-memory config;
/// for each hot-reloadable key whose effective value differs, the
/// in-memory `AppConfig` is updated. Emits `ConfigReloaded` listing
/// the keys that actually changed.
///
/// **Phase 0 limitation**: only the Phase-0 registry's
/// hot-reloadable keys (`log.level` today) are propagated. Future
/// runtime-state subscribers (tracing subscriber filter handle,
/// session-cleanup interval, etc.) will plug into the same diff
/// loop.
#[utoipa::path(
    post, path = "/admin/config/reload", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Keys re-applied in-memory", body = ReloadResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn reload_config(
    admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ReloadResponse>, AppError> {
    let audit_writer = require_audit_writer(&state)?;

    let store = ConfigStore::new(state.config_ks.clone());

    // Snapshot the live in-memory config so we can diff against what
    // the four-layer overlay currently says. Read the latest
    // effective view first, then mutate the in-memory copy under a
    // write lock so concurrent reads see a single atomic flip per
    // key.
    let new_effective = {
        let cfg = state.config.read().await;
        compute_effective_config(&cfg, &store).await?
    };

    // Compare per-key effective values against `EffectiveConfig`'s
    // serialised snapshot of the same `AppConfig` shape. For Phase 0
    // the registry has three keys (`server.host`, `server.port`,
    // `log.level`). Server keys are `requires_restart` so they
    // never re-apply here.
    let mut keys_reloaded = Vec::new();
    {
        let mut cfg = state.config.write().await;
        for def in crate::config_store::REGISTRY {
            if def.requires_restart {
                continue;
            }
            let new_value = new_effective
                .fields
                .iter()
                .find(|f| f.key == def.key)
                .map(|f| f.value.clone())
                .unwrap_or(Value::Null);
            let live_value = lookup_live(&cfg, def.key);
            if new_value != live_value && apply_to_live(&mut cfg, def.key, &new_value) {
                keys_reloaded.push(def.key.to_string());
            }
        }
    }

    audit_writer
        .write(
            &admin.0.did,
            None,
            AuditEvent::ConfigReloaded(ConfigReloadedData {
                keys_reloaded: keys_reloaded.clone(),
            }),
        )
        .await?;

    info!(?keys_reloaded, "config reloaded");

    Ok(Json(ReloadResponse { keys_reloaded }))
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

/// `POST /v1/admin/config/restart` response when the supervisor
/// check passes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RestartResponse {
    /// Which supervisor the daemon detected (so the operator's
    /// admin UX can echo it back).
    pub supervisor: SupervisorKind,
    /// `drain_timeout` (seconds) the daemon will use for graceful
    /// shutdown. Mirrors `RestartRequestedData.drain_timeout_seconds`.
    pub drain_timeout_seconds: u64,
}

/// `POST /v1/admin/config/restart` handler.
///
/// Refuses (`412 Precondition Failed`,
/// `SupervisorRequired`) unless a supervisor is detected — restart
/// without an external supervisor is just "kill the process" and a
/// caller asking for `restart` likely means "have the daemon come
/// back up afterwards". Detection lives in
/// [`crate::supervisor::detect_supervisor`].
///
/// On success the handler emits `RestartRequested` to the audit
/// log *before* signalling shutdown — so the row survives even if
/// the drain wedges.
#[utoipa::path(
    post, path = "/admin/config/restart", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Restart requested", body = RestartResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn restart_config(
    admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RestartResponse>, AppError> {
    let audit_writer = require_audit_writer(&state)?;

    let supervisor = state.supervisor.ok_or_else(|| AppError::ServiceError {
        status: StatusCode::PRECONDITION_FAILED,
        message: "SupervisorRequired: refusing to restart without a process supervisor \
            (set VTC_SUPERVISED=1 or run under systemd / kubernetes)"
            .into(),
    })?;

    audit_writer
        .write(
            &admin.0.did,
            None,
            AuditEvent::RestartRequested(RestartRequestedData {
                drain_timeout_seconds: DEFAULT_DRAIN_TIMEOUT_SECS,
            }),
        )
        .await?;

    info!(?supervisor, "restart requested");

    // Flip the shared graceful-shutdown channel. The REST thread
    // observes this via `with_graceful_shutdown` and stops accepting
    // new connections; the storage thread flushes; supervisor
    // restarts the process. We send AFTER audit emission so a wedged
    // drain still leaves the row behind.
    let _ = state.shutdown_tx.send(true);

    Ok(Json(RestartResponse {
        supervisor,
        drain_timeout_seconds: DEFAULT_DRAIN_TIMEOUT_SECS,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_audit_writer(state: &AppState) -> Result<&AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })
}

/// Read the live in-memory value for `key` out of an `AppConfig`.
/// Phase-0 keys only; unknown keys return `Value::Null`.
fn lookup_live(cfg: &crate::config::AppConfig, key: &str) -> Value {
    match key {
        "server.host" => Value::String(cfg.server.host.clone()),
        "server.port" => Value::Number(cfg.server.port.into()),
        "log.level" => Value::String(cfg.log.level.clone()),
        _ => Value::Null,
    }
}

/// Apply `value` to the live in-memory `AppConfig` for `key`.
/// Returns `true` if the field changed (it should; the caller has
/// already diffed). Phase-0 keys only; unknown keys are a no-op.
///
/// **Phase 0 limitation**: this updates the field but does NOT
/// notify downstream subscribers (e.g., `tracing-subscriber`'s
/// reload Handle for `log.level`). Plumbing those subscribers is
/// a Phase-1 follow-up; for now the new value sticks for any
/// future reads of `state.config`, and `requires_restart`-flagged
/// keys (`server.*`) keep behaving correctly because they're never
/// touched here.
fn apply_to_live(cfg: &mut crate::config::AppConfig, key: &str, value: &Value) -> bool {
    // server.host / server.port are requires_restart and never reach
    // this function. Future hot-reloadable keys plug in alongside
    // `log.level` with their own arms.
    if key == "log.level"
        && let Some(s) = value.as_str()
    {
        cfg.log.level = s.to_string();
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Schema version for the export/import envelope. Bumped on any
/// breaking shape change so the import handler can refuse old
/// exports cleanly. Phase 0 ships v1.
pub const EXPORT_SCHEMA_VERSION: u32 = 1;

/// Wire payload for `POST /v1/admin/config/{export,import}`.
///
/// `community_profile` is `None` when the community hasn't been
/// initialised yet (pre-bootstrap). `config_overrides` carries
/// *only* the db-layer keys — env-layer and toml-layer values stay
/// per-host and aren't portable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ConfigExport {
    pub schema_version: u32,
    pub exported_at: DateTime<Utc>,
    pub community_profile: Option<CommunityProfile>,
    pub config_overrides: HashMap<String, Value>,
}

#[utoipa::path(
    post, path = "/admin/config/export", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Portable config + community-profile export", body = ConfigExport),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn export_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ConfigExport>, AppError> {
    let community_profile = load_profile(&state.community_ks).await?;
    let store = ConfigStore::new(state.config_ks.clone());
    let config_overrides = store.snapshot().await?;

    Ok(Json(ConfigExport {
        schema_version: EXPORT_SCHEMA_VERSION,
        exported_at: Utc::now(),
        community_profile,
        config_overrides,
    }))
}

// ---------------------------------------------------------------------------
// Import (diff-and-confirm)
// ---------------------------------------------------------------------------

/// Query string for `POST /v1/admin/config/import`. Default is
/// `confirm=false` (dry-run / diff). The operator UX shows the diff,
/// then re-submits with `?confirm=true` to apply.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ImportQuery {
    #[serde(default)]
    pub confirm: bool,
}

/// A single field's worth of import diff. `oldValue` is `None`
/// when the key isn't currently set (either no profile yet, or no
/// db-layer override). `newValue` is `None` when the import omits
/// the field — which `import` interprets as "leave the live value
/// alone", not "clear it".
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct FieldDiff {
    pub key: String,
    pub old_value: Option<Value>,
    pub new_value: Option<Value>,
}

/// `POST /v1/admin/config/import` response. The shape is the same
/// regardless of `confirm`: `applied` is empty on dry-run; on
/// confirm it lists the keys that actually persisted.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ImportResponse {
    /// Was the request a dry-run? Mirrors the inbound `?confirm`
    /// flag so an admin UX caching the response can render the
    /// banner correctly.
    pub confirmed: bool,
    /// Profile-field-level diffs against the current profile.
    /// Empty when import omits `communityProfile` or when no
    /// fields differ.
    pub community_profile_diff: Vec<FieldDiff>,
    /// Config-override-level diffs. One entry per registry key
    /// that the import would change.
    pub config_overrides_diff: Vec<FieldDiff>,
    /// On apply: the profile fields that were written. Empty on
    /// dry-run or when no change.
    pub community_profile_applied: Vec<String>,
    /// On apply: the override keys that were written. Empty on
    /// dry-run.
    pub config_overrides_applied: Vec<String>,
    /// Keys rejected by validation (unknown registry key, type
    /// mismatch, value-out-of-range, oversized extensions blob).
    pub rejected: Vec<RejectedKey>,
}

#[utoipa::path(
    post, path = "/admin/config/import", tag = "admin",
    security(("bearer_jwt" = [])),
    params(("confirm" = Option<bool>, Query, description = "Apply the import (true) or dry-run diff (false, default)")),
    request_body = ConfigExport,
    responses(
        (status = 200, description = "Import diff (dry-run) or applied keys", body = ImportResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn import_config(
    admin: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ImportQuery>,
    Json(req): Json<ConfigExport>,
) -> Result<(StatusCode, Json<ImportResponse>), AppError> {
    if req.schema_version != EXPORT_SCHEMA_VERSION {
        return Err(AppError::Validation(format!(
            "unsupported export schemaVersion: got {}, expected {EXPORT_SCHEMA_VERSION}",
            req.schema_version
        )));
    }

    // community_did mismatch is a 409 — refuse to clobber a
    // different community's profile with this import. A
    // freshly-installed VTC with no profile accepts any
    // community_did from the import.
    let current_profile = load_profile(&state.community_ks).await?;
    if let (Some(current), Some(incoming)) = (&current_profile, &req.community_profile)
        && current.community_did != incoming.community_did
    {
        return Err(AppError::Conflict(format!(
            "communityDid mismatch: current is {}, import carries {}",
            current.community_did, incoming.community_did
        )));
    }

    let store = ConfigStore::new(state.config_ks.clone());
    let current_overrides = store.snapshot().await?;

    // --- diff ---------------------------------------------------------
    let mut profile_diff: Vec<FieldDiff> = Vec::new();
    let mut overrides_diff: Vec<FieldDiff> = Vec::new();
    let mut rejected: Vec<RejectedKey> = Vec::new();

    if let Some(incoming) = &req.community_profile {
        for (key, old, new) in
            crate::community::profile::profile_field_pairs(current_profile.as_ref(), incoming)
        {
            if old != new {
                profile_diff.push(FieldDiff {
                    key: key.into(),
                    old_value: old,
                    new_value: new,
                });
            }
        }
    }

    for (key, new_value) in &req.config_overrides {
        let Some(def) = lookup(key) else {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: "unknown config key (not in registry)".into(),
            });
            continue;
        };
        if let Err(e) = validate_value(def, new_value) {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: format!("validation failed: {e}"),
            });
            continue;
        }
        let old = current_overrides.get(key).cloned();
        if old.as_ref() != Some(new_value) {
            overrides_diff.push(FieldDiff {
                key: key.clone(),
                old_value: old,
                new_value: Some(new_value.clone()),
            });
        }
    }

    // --- dry-run? -----------------------------------------------------
    if !query.confirm {
        return Ok((
            StatusCode::OK,
            Json(ImportResponse {
                confirmed: false,
                community_profile_diff: profile_diff,
                config_overrides_diff: overrides_diff,
                community_profile_applied: Vec::new(),
                config_overrides_applied: Vec::new(),
                rejected,
            }),
        ));
    }

    // --- apply --------------------------------------------------------
    // Profile first so a partial failure on overrides doesn't leave
    // half a profile applied. Overrides are persisted one key at a
    // time, so a fjall-side error mid-loop reports back via
    // `rejected` rather than aborting.
    let audit_writer = require_audit_writer(&state)?;

    let community_profile_applied = if let Some(incoming) = req.community_profile.clone() {
        apply_profile_import(&state, incoming, current_profile.as_ref()).await?
    } else {
        Vec::new()
    };

    let mut config_overrides_applied: Vec<String> = Vec::new();
    let mut audit_changes: Vec<ConfigChange> = Vec::new();
    let mut requires_restart = false;
    for FieldDiff {
        key,
        old_value,
        new_value,
    } in &overrides_diff
    {
        let Some(def) = lookup(key) else { continue };
        let new_value = match new_value {
            Some(v) => v.clone(),
            None => continue,
        };
        if let Err(e) = store.put(key, &new_value).await {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: format!("persistence failed: {e}"),
            });
            continue;
        }
        config_overrides_applied.push(key.clone());
        let mut change = ConfigChange {
            key: key.clone(),
            old_value: old_value.clone(),
            new_value,
            source_before: if old_value.is_some() {
                ConfigSource::Db
            } else {
                ConfigSource::Default
            },
        };
        change.redact_if(|k| matches!(lookup(k), Some(d) if d.sensitive));
        audit_changes.push(change);
        if def.requires_restart {
            requires_restart = true;
        }
    }

    if !audit_changes.is_empty() {
        audit_writer
            .write(
                &admin.0.did,
                None,
                AuditEvent::ConfigChanged(ConfigChangedData {
                    changes: audit_changes,
                    requires_restart,
                }),
            )
            .await?;
    }
    if !community_profile_applied.is_empty() {
        audit_writer
            .write(
                &admin.0.did,
                None,
                AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
                    fields_changed: community_profile_applied.clone(),
                    // Reuse the diff already computed above for the
                    // import preview — each FieldDiff is a before/after.
                    changes: profile_diff
                        .iter()
                        .map(|d| vti_common::audit::FieldChange {
                            field: d.key.clone(),
                            old: d.old_value.clone(),
                            new: d.new_value.clone(),
                        })
                        .collect(),
                }),
            )
            .await?;
    }

    info!(
        profile_changed = community_profile_applied.len(),
        overrides_applied = config_overrides_applied.len(),
        rejected = rejected.len(),
        "config imported"
    );

    Ok((
        StatusCode::OK,
        Json(ImportResponse {
            confirmed: true,
            community_profile_diff: profile_diff,
            config_overrides_diff: overrides_diff,
            community_profile_applied,
            config_overrides_applied,
            rejected,
        }),
    ))
}

/// Apply the incoming profile to `community_ks`. Returns the list of
/// field names that changed (driving the
/// `CommunityProfileUpdated.fieldsChanged` audit payload).
///
/// If no profile exists yet the incoming profile is stored as-is
/// (and **all** populated fields are reported as changed, matching
/// `CommunityProfileUpdate::apply`'s contract).
async fn apply_profile_import(
    state: &AppState,
    incoming: CommunityProfile,
    current: Option<&CommunityProfile>,
) -> Result<Vec<String>, AppError> {
    let Some(current) = current else {
        // Fresh install — store the import verbatim and report every
        // non-default-shaped field as changed.
        let mut changed = Vec::new();
        if !incoming.name.is_empty() {
            changed.push("name".into());
        }
        if !incoming.description.is_empty() {
            changed.push("description".into());
        }
        if incoming.logo_url.is_some() {
            changed.push("logoUrl".into());
        }
        if incoming.public_url.is_some() {
            changed.push("publicUrl".into());
        }
        if incoming.contact_email.is_some() {
            changed.push("contactEmail".into());
        }
        if incoming.language != "en" {
            changed.push("language".into());
        }
        if !incoming.extensions.is_null() {
            changed.push("extensions".into());
        }
        store_profile(&state.community_ks, &incoming).await?;
        return Ok(changed);
    };

    // Existing profile — build a `CommunityProfileUpdate` from the
    // import and let it diff + apply. This reuses the existing
    // extension-size guard.
    let patch = CommunityProfileUpdate {
        name: Some(incoming.name),
        description: Some(incoming.description),
        logo_url: Some(incoming.logo_url),
        public_url: Some(incoming.public_url),
        contact_email: Some(incoming.contact_email),
        language: Some(incoming.language),
        extensions: Some(incoming.extensions),
    };
    let mut updated = current.clone();
    let changed = patch.apply(&mut updated)?;
    if !changed.is_empty() {
        store_profile(&state.community_ks, &updated).await?;
    }
    Ok(changed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Behavioural coverage lives in `tests/admin_config.rs` — those
    // exercise the full router stack (Trust-Task header, AdminAuth
    // extractor, JSON body, three-layer effective view) via
    // `Router::oneshot`. Unit tests for the overlay + validation
    // semantics live in `crate::config_store::tests`.
}
