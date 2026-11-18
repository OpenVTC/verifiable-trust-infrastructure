//! The community profile's read and edit — the bodies of
//! `vtc/community/profile/show/0.1` and `vtc/community/profile/update/0.1`.
//!
//! The edit rejects changes to `community_did` (immutable) and emits a
//! `CommunityProfileUpdated` audit event listing only the field names that
//! actually changed. The unauthenticated public read is a route
//! (`routes::community::profile`).

use axum::http::StatusCode;
use serde::Serialize;
use tracing::info;
use vtc_audit::{AuditEvent, CommunityProfileUpdatedData};
use vti_common::error::AppError;

use crate::community::{CommunityProfile, CommunityProfileUpdate, load_profile, store_profile};
use crate::registry::HealthStatus;
use crate::server::AppState;

/// GET response shape.
///
/// Wraps the persisted [`CommunityProfile`] + adds the live
/// `registryStatus` field surfaced by Phase 3 M3.2.
/// `registry_status` is read from `AppState` at request time,
/// not persisted on the profile row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CommunityProfileResponse {
    /// Nested, because `vtc/community/profile/show/0.1` requires a
    /// `profile` member and is `additionalProperties: false`. This was
    /// `#[serde(flatten)]` until #1094, which put every profile field at the
    /// top level — where the schema permits none of them.
    pub profile: ProfileWithStatus,
}

/// The persisted profile plus the one field that is computed per request.
///
/// `registryStatus` sits *inside* the profile object rather than beside it,
/// because that is where the canonical `CommunityProfile` component defines
/// it ("Populated on reads; not settable"). Un-flattening alone would have
/// left it a sibling of `profile`, which the response schema forbids.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ProfileWithStatus {
    #[serde(flatten)]
    pub profile: CommunityProfile,
    /// Trust-registry reachability — `"active"` when the last
    /// health probe succeeded, `"degraded"` otherwise (probe
    /// never ran, last probe failed, or `registry.url` is
    /// unset). Spec §8.1.
    pub registry_status: HealthStatus,
}

/// GET handler. Returns the singleton profile + the live
/// trust-registry status.
/// GET /community/profile — full community profile + live registry status.
/// Auth: any authenticated session.
/// `vtc/community/profile/show/0.1` — the profile and registry status. A
/// signed document served by the spine (`trust_tasks::community_tasks`).
pub(crate) async fn show_profile(state: &AppState) -> Result<CommunityProfileResponse, AppError> {
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    let registry_status = state.registry_health.status().await;
    Ok(CommunityProfileResponse {
        profile: ProfileWithStatus {
            profile,
            registry_status,
        },
    })
}

/// PUT response shape — echoes the updated profile + the list of
/// fields that actually changed (operator-friendly + powers the
/// audit event emitter that lands alongside this in a follow-up).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UpdateProfileResponse {
    pub profile: CommunityProfile,
    pub fields_changed: Vec<String>,
}

/// `vtc/community/profile/update:validationFailed` — a supplied field failed
/// validation.
pub const PROFILE_UPDATE_ERR_VALIDATION_FAILED: &str =
    vti_specs::vtc::community::profile::update::v0_1::error_codes::VALIDATION_FAILED.code;

/// Apply a profile patch on behalf of `actor_did` — the whole of the
/// operation, with no transport in it.
///
/// Both doors call this: the bearer REST route below, and the signed-document
/// arm in [`crate::trust_tasks`] (#1641 phase 2). Keeping the body here is what
/// stops the two answering differently — the field validation, the no-op
/// short-circuit, the fail-closed audit and the persisted row are decided once.
///
/// Audit is fail-closed: a change that can't be recorded (no `AuditWriter`)
/// returns 503 rather than persisting silently — matching the
/// `/v1/admin/config` doors so auditability doesn't depend on which surface the
/// admin used.
pub(crate) async fn update_profile_inner(
    state: &AppState,
    actor_did: &str,
    update: CommunityProfileUpdate,
) -> Result<UpdateProfileResponse, crate::error::TaskError> {
    use crate::error::TaskError;
    let mut profile = load_profile(&state.community_ks).await?.ok_or_else(|| {
        AppError::NotFound("community profile not initialised — cannot PUT before bootstrap".into())
    })?;

    let prior = profile.clone();
    // Every refusal `apply` makes is a field failing validation.
    let fields_changed = update.apply(&mut profile).map_err(|e| match e {
        e @ AppError::Validation(_) => TaskError::declared(PROFILE_UPDATE_ERR_VALIDATION_FAILED, e),
        e => TaskError::App(e),
    })?;

    if fields_changed.is_empty() {
        // Nothing changed — return 200 with the existing profile.
        // PUT semantics tolerate idempotent no-ops.
        return Ok(UpdateProfileResponse {
            profile,
            fields_changed,
        });
    }

    // Fail-closed: refuse to persist a change we can't audit.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;

    store_profile(&state.community_ks, &profile).await?;
    info!(
        community_did = %profile.community_did,
        fields_changed = ?fields_changed,
        "community profile updated"
    );

    audit_writer
        .write(
            actor_did,
            None,
            AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
                fields_changed: fields_changed.clone(),
                changes: crate::community::profile::profile_changes(Some(&prior), &profile),
            }),
        )
        .await?;

    Ok(UpdateProfileResponse {
        profile,
        fields_changed,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Behavioural coverage lives in `tests/community_profile.rs` — those
    // exercise the full router stack (Trust-Task header, AdminAuth
    // extractor, JSON body) via `Router::oneshot`. Unit tests for the
    // underlying storage + patch semantics live in
    // `crate::community::profile::tests`.
}
