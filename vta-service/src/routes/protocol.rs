//! REST routes for DIDComm protocol management.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `POST /services/didcomm/enable`. The remaining
//! routes (`/services/didcomm/disable`, `/services`, `/mediators/*`)
//! are added by Phase 4 verticals.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth::SuperAdminAuth;
use crate::messaging::handshake::{AlwaysOkProver, HandshakeError, HandshakeStage};
use crate::operations::protocol::disable_didcomm::DisableTransport as DidcommTransport;
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommError, DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::disable_rest::{
    DisableRestError, DisableRestParams, disable_rest,
};
use crate::operations::protocol::disable_webauthn::{
    DisableWebauthnError, DisableWebauthnParams, disable_webauthn,
};
use crate::operations::protocol::enable_didcomm::{
    EnableDidcommError, EnableDidcommParams, enable_didcomm,
};
use crate::operations::protocol::enable_rest::{EnableRestError, EnableRestParams, enable_rest};
use crate::operations::protocol::enable_webauthn::{
    EnableWebauthnError, EnableWebauthnParams, enable_webauthn,
};
use crate::operations::protocol::rollback_didcomm::{
    RollbackDidcommError, RollbackDidcommParams, RollbackKind as DidcommRollbackKind,
    rollback_didcomm,
};
use crate::operations::protocol::rollback_rest::{
    RollbackKind as RestRollbackKind, RollbackRestError, RollbackRestParams, rollback_rest,
};
use crate::operations::protocol::rollback_webauthn::{
    RollbackKind as WebauthnRollbackKind, RollbackWebauthnError, RollbackWebauthnParams,
    rollback_webauthn,
};
use crate::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommError, UpdateDidcommParams, update_didcomm,
};
use crate::operations::protocol::update_rest::{UpdateRestError, UpdateRestParams, update_rest};
use crate::operations::protocol::update_webauthn::{
    UpdateWebauthnError, UpdateWebauthnParams, update_webauthn,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::server::AppState;
use vta_sdk::protocol::DidcommStatusResponse;

/// Default trust-ping round-trip timeout for first-enable when the
/// caller doesn't specify `handshake_timeout_secs`. Spec default 10s.
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Deserialize)]
pub struct EnableDidcommRequest {
    pub mediator_did: String,
    /// Optional: skip steps 2-5 of the handshake (DID resolution
    /// always runs). The route emits a `MediatorHandshakeBypassed`
    /// telemetry event when this is set.
    #[serde(default)]
    pub force: bool,
    /// Optional: trust-ping round-trip timeout in seconds. Spec
    /// default: 10s.
    #[serde(default)]
    pub handshake_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EnableDidcommResponse {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
    /// The VTA's own DID — subject of the LogEntry this enable
    /// wrote. Lets the CLI emit a "fetch did.jsonl + redeploy"
    /// hint without an extra round-trip. Wire-aligned with
    /// `vta_sdk::protocol::EnableDidcommResponse`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted (`server_id =
    /// "serverless"`); the new LogEntry was persisted locally
    /// but not published.
    #[serde(default)]
    pub serverless: bool,
}

/// `POST /services/didcomm/enable` — enable DIDComm on a REST-only
/// VTA. Auth: super-admin only. Refuses if DIDComm is already
/// enabled (operator should use `migrate` instead).
///
/// **First-enable handshake limitation:** the live mediator
/// handshake (steps 2-5) requires a running `DIDCommService`, which
/// doesn't exist yet at first-enable time. This route uses a
/// transient handshake (`try_run_first_enable_handshake`) for steps
/// 2-5, then [`AlwaysOkProver`] inside the operation itself. The
/// live-prover path through `update_didcomm` (where DIDComm is
/// already running) covers the steady-state case.
pub async fn enable_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<EnableDidcommRequest>,
) -> Result<Json<EnableDidcommResponse>, EnableDidcommHttpError> {
    if state.config.read().await.services.didcomm {
        return Err(EnableDidcommHttpError::AlreadyEnabled {
            mediator_did: current_didcomm_mediator_did(&state).await,
        });
    }

    let bridge = Arc::clone(&state.didcomm_bridge);
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(EnableDidcommHttpError::DidResolverUnavailable)?
        .clone();

    let timeout = Duration::from_secs(
        req.handshake_timeout_secs
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
    );

    // Try to run the full handshake against the new mediator
    // BEFORE publishing the LogEntry. Spins up a transient
    // DIDCommService just for the round-trip. Best-effort: if
    // the secrets/vm_ids aren't available (early-boot fixture,
    // etc.), fall through to the operation's AlwaysOkProver path
    // — the caller still gets DID resolution + service-shape
    // validation via the operation's own handshake invocation.
    if !req.force
        && let Err(e) =
            try_run_first_enable_handshake(&state, &did_resolver, &req.mediator_did, timeout).await
    {
        return Err(EnableDidcommHttpError::Op(
            crate::operations::protocol::enable_didcomm::EnableDidcommError::Handshake(e),
        ));
    }

    let prover = AlwaysOkProver;

    let result = match enable_didcomm(
        &state.config,
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.snapshot_ks,
        &state.service_state_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.telemetry,
        &prover,
        &auth.0,
        EnableDidcommParams {
            mediator_did: req.mediator_did,
            force: req.force,
            handshake_timeout: timeout,
        },
        OpContext::Direct,
        &state.webvh_auth_locks,
        "rest",
    )
    .await
    {
        Ok(result) => result,
        Err(EnableDidcommError::DidcommAlreadyEnabled) => {
            return Err(EnableDidcommHttpError::AlreadyEnabled {
                mediator_did: current_didcomm_mediator_did(&state).await,
            });
        }
        Err(e) => return Err(EnableDidcommHttpError::Op(e)),
    };

    Ok(Json(EnableDidcommResponse {
        new_version_id: result.new_version_id,
        mediator_did: result.mediator_did,
        mediator_endpoint: result.mediator_endpoint,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `GET /services/didcomm` — current DIDComm runtime status. Auth: super-admin,
/// for parity with `GET /services` (`list_services`), which exposes the same
/// `mediator_did`. Gating both the same way avoids a reader-role caller learning
/// the mediator DID here that it cannot obtain from the sibling list endpoint.
pub async fn get_didcomm_status_handler(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Json<DidcommStatusResponse> {
    let (configured, mediator_did) = {
        let config = state.config.read().await;
        (
            config.services.didcomm,
            config
                .messaging
                .as_ref()
                .map(|m| m.mediator_did.clone())
                .filter(|did| !did.is_empty()),
        )
    };

    // DIDComm is "enabled" only when the feature is compiled in, the config
    // flag is set, AND a mediator is registered — consistent with GET /services.
    #[cfg(feature = "didcomm")]
    let enabled = configured && mediator_did.is_some();
    #[cfg(not(feature = "didcomm"))]
    let enabled = false;

    if !enabled {
        return Json(DidcommStatusResponse {
            enabled: false,
            mediator_did: None,
            websocket_status: None,
        });
    }

    #[cfg(feature = "didcomm")]
    let websocket_status = Some(
        state
            .didcomm_websocket_status
            .read()
            .await
            .as_str()
            .to_string(),
    );
    #[cfg(not(feature = "didcomm"))]
    let websocket_status: Option<String> = None;

    Json(DidcommStatusResponse {
        enabled: true,
        mediator_did,
        websocket_status,
    })
}

async fn current_didcomm_mediator_did(state: &AppState) -> Option<String> {
    state
        .config
        .read()
        .await
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.clone())
        .filter(|did| !did.is_empty())
}

/// HTTP error wrapper for `EnableDidcommError` that maps each typed
/// variant to an appropriate status code + suggested-fix body.
#[derive(Debug)]
pub enum EnableDidcommHttpError {
    Op(EnableDidcommError),
    AlreadyEnabled { mediator_did: Option<String> },
    DidResolverUnavailable,
}

impl From<EnableDidcommError> for EnableDidcommHttpError {
    fn from(value: EnableDidcommError) -> Self {
        Self::Op(value)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediator_did: Option<String>,
    /// Operator-facing suggested fix. Per CLAUDE.md, we surface the
    /// corrected command rather than just the HTTP status.
    #[serde(skip_serializing_if = "Option::is_none")]
    suggested_fix: Option<String>,
    /// Failing handshake stage when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'static str>,
}

impl IntoResponse for EnableDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::AlreadyEnabled { mediator_did } => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_already_enabled",
                    message: "DIDComm is already enabled.".into(),
                    mediator_did,
                    suggested_fix: Some(
                        "Use `pnm services didcomm update --mediator-did <did>` to change the active mediator."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::DidcommAlreadyEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_already_enabled",
                    message: "DIDComm is already enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services didcomm update --mediator-did <did>` to change the active mediator."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidRecordMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_record_missing",
                    message: format!("VTA DID `{did}` has no webvh record on disk."),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidLogMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_missing",
                    message: format!("VTA DID `{did}` has no published log."),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::EmptyLog) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_empty",
                    message: "VTA DID log is empty.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Handshake(HandshakeError::Failed { stage, cause })) => (
                StatusCode::BAD_GATEWAY,
                ErrorBody {
                    error: "mediator_handshake_failed",
                    message: format!("mediator handshake failed: {cause}"),
                    mediator_did: None,
                    suggested_fix: Some(match stage {
                        HandshakeStage::Resolve =>
                            "Check the mediator DID is correct and reachable from this VTA.".into(),
                        _ =>
                            "Inspect the mediator's logs; or retry with `--force` if you've validated reachability out-of-band."
                                .into(),
                    }),
                    stage: Some(stage_str(stage)),
                },
            ),
            Self::Op(EnableDidcommError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::ConfigPersistence(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "config_persistence_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some(
                        "Check the VTA's config file is writable; the LogEntry was published \
                         but config persistence failed — fix permissions and retry."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Registry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "registry_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Storage(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver is not initialised on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Configure `resolver_url` or run with the local resolver.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

fn stage_str(stage: HandshakeStage) -> &'static str {
    match stage {
        HandshakeStage::Resolve => "resolve",
        HandshakeStage::Connect => "connect",
        HandshakeStage::Authenticate => "authenticate",
        HandshakeStage::Register => "register",
        HandshakeStage::TrustPing => "trust-ping",
    }
}

// ────────────────────────────────────────────────────────────────────
// disable_didcomm
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DisableDidcommRequest {
    /// Drain TTL in seconds. 0 = immediate teardown (REST only;
    /// over DIDComm transport, minimum 1h is enforced).
    #[serde(default)]
    pub drain_ttl_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct DisableDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(rfc3339)` when the listener entered drain state;
    /// `None` when it was torn down immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drains_until: Option<String>,
    /// The VTA's own DID. See [`EnableDidcommResponse::vta_did`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. See
    /// [`EnableDidcommResponse::serverless`].
    #[serde(default)]
    pub serverless: bool,
}

/// `POST /services/didcomm/disable` — disable DIDComm. Auth:
/// super-admin. The route uses `DisableTransport::Rest` since this
/// handler IS the REST transport. The 1h-min-TTL guard applies only
/// when called over the DIDComm transport (Phase 4.2 and beyond).
pub async fn disable_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<DisableDidcommRequest>,
) -> Result<Json<DisableDidcommResponse>, DisableDidcommHttpError> {
    let bridge = Arc::clone(&state.didcomm_bridge);
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(DisableDidcommHttpError::DidResolverUnavailable)?
        .clone();

    let result = disable_didcomm(
        &state.config,
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &state.service_state_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        &auth.0,
        DisableDidcommParams {
            drain_ttl: Duration::from_secs(req.drain_ttl_secs),
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        &state.webvh_auth_locks,
        "rest",
    )
    .await?;

    Ok(Json(DisableDidcommResponse {
        new_version_id: result.new_version_id,
        prior_mediator_did: result.prior_mediator_did,
        drains_until: result.drains_until.map(|t| t.to_rfc3339()),
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

#[derive(Debug)]
pub enum DisableDidcommHttpError {
    Op(DisableDidcommError),
    DidResolverUnavailable,
}

impl From<DisableDidcommError> for DisableDidcommHttpError {
    fn from(value: DisableDidcommError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for DisableDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(DisableDidcommError::DidcommNotEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_not_enabled",
                    message: "DIDComm is not currently enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Enable DIDComm first: `pnm services didcomm enable --mediator-did <did>` \
                         (online) or `vta services didcomm enable --mediator-did <did>` \
                         (offline, daemon stopped)."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::NoProtocolRemaining) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "no_protocol_remaining",
                    message: "Cannot disable DIDComm — REST is also disabled. The VTA would have no protocol surface left.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Enable REST first: `pnm services rest enable --url <url>` (online) \
                         or `vta services rest enable --url <url>` (offline, daemon stopped). \
                         Then retry."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            }) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "drain_ttl_out_of_bounds",
                    message: format!(
                        "drain ttl {requested}s outside allowed range [{min}s, {max}s]"
                    ),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Either retry over REST transport (`--transport rest`) for a sub-1h TTL, or pick a TTL within bounds (1h–30d).".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidRecordMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_record_missing",
                    message: format!("VTA DID `{did}` has no webvh record on disk."),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidLogMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_missing",
                    message: format!("VTA DID `{did}` has no published log."),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::EmptyLog) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_empty",
                    message: "VTA DID log is empty.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::NoActiveMediator) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "no_active_mediator",
                    message: "DIDComm is enabled but the DID document has no `#vta-didcomm` service entry.".into(),
                    mediator_did: None,
                    suggested_fix: Some("On-disk state is inconsistent — re-run `vta setup`.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::ConfigPersistence(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "config_persistence_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some(
                        "Check the VTA's config file is writable and retry.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Registry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "registry_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Storage(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver is not initialised on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Configure `resolver_url` or run with the local resolver.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ────────────────────────────────────────────────────────────────────
// update_didcomm
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateDidcommRequest {
    pub new_mediator_did: String,
    pub drain_ttl_secs: u64,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub handshake_timeout_secs: Option<u64>,
    /// Distinguish forward migrate from rollback in telemetry.
    #[serde(default)]
    pub rollback: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdateDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    pub active_mediator_did: String,
    pub active_mediator_endpoint: String,
    pub drains_until: String,
    /// The VTA's own DID. See [`EnableDidcommResponse::vta_did`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. See
    /// [`EnableDidcommResponse::serverless`].
    #[serde(default)]
    pub serverless: bool,
}

/// `POST /services/didcomm/update` — change the active mediator. Auth:
/// super-admin. Runs the full pre-promotion handshake against the
/// new mediator. Uses the live `DIDCommServiceProver` when the
/// upstream DIDComm service is running and the VTA's secrets
/// resolver + verification-method ids are available; otherwise
/// falls back to [`AlwaysOkProver`]. The fallback path is hit
/// when DIDComm hasn't started yet or when secrets aren't
/// configured (e.g. mock test fixtures).
pub async fn update_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateDidcommRequest>,
) -> Result<Json<UpdateDidcommResponse>, UpdateDidcommHttpError> {
    let bridge = Arc::clone(&state.didcomm_bridge);
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(UpdateDidcommHttpError::DidResolverUnavailable)?
        .clone();

    // Try to assemble a live prover. Falls back to AlwaysOk if
    // any of the required pieces (running DIDComm service,
    // secrets resolver, verification-method ids, vta_did)
    // aren't ready.
    let live_prover = build_live_prover(&state, &bridge).await;
    let timeout = Duration::from_secs(
        req.handshake_timeout_secs
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
    );
    let audit_kind = if req.rollback {
        MigrateAuditKind::Rollback
    } else {
        MigrateAuditKind::Forward
    };

    // The update_didcomm op takes a `&dyn ListenerProver` so
    // both branches need to materialize a concrete reference
    // before the call.
    let always_ok = AlwaysOkProver;
    let prover_ref: &(dyn crate::messaging::handshake::ListenerProver + Send + Sync) =
        match live_prover.as_ref() {
            Some(p) => p,
            None => &always_ok,
        };

    let result = update_didcomm(
        &state.config,
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &state.service_state_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        prover_ref,
        &auth.0,
        UpdateDidcommParams {
            new_mediator_did: req.new_mediator_did,
            drain_ttl: Duration::from_secs(req.drain_ttl_secs),
            force: req.force,
            handshake_timeout: timeout,
            audit_kind,
            transport: crate::operations::protocol::disable_didcomm::DisableTransport::Rest,
        },
        OpContext::Direct,
        &state.webvh_auth_locks,
        "rest",
    )
    .await?;

    Ok(Json(UpdateDidcommResponse {
        new_version_id: result.new_version_id,
        prior_mediator_did: result.prior_mediator_did,
        active_mediator_did: result.active_mediator_did,
        active_mediator_endpoint: result.active_mediator_endpoint,
        drains_until: result.drains_until.to_rfc3339(),
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

#[derive(Debug)]
pub enum UpdateDidcommHttpError {
    Op(UpdateDidcommError),
    DidResolverUnavailable,
}

impl From<UpdateDidcommError> for UpdateDidcommHttpError {
    fn from(value: UpdateDidcommError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for UpdateDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(UpdateDidcommError::DidcommNotEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_not_enabled",
                    message:
                        "DIDComm is not currently enabled — there is no active mediator to migrate from."
                            .into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services didcomm enable --mediator-did <did>` first.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            }) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "drain_ttl_out_of_bounds",
                    message: format!(
                        "drain ttl {requested}s outside allowed range [{min}s, {max}s]"
                    ),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Pick a TTL within bounds (1h–30d over DIDComm transport, 0s–30d over REST).".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::SameAsActive(did)) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "same_as_active",
                    message: format!("`{did}` is already the active mediator — nothing to migrate."),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::AlreadyDraining(did)) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "already_draining",
                    message: format!("`{did}` is currently in drain state."),
                    mediator_did: None,
                    suggested_fix: Some(format!(
                        "Run `pnm services didcomm drain cancel --mediator-did {did}` first, or use `pnm services didcomm rollback` to fail-forward to a state where `{did}` is active."
                    )),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `vta setup` to configure the VTA's DID first.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::VtaDidRecordMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_record_missing",
                    message: format!("VTA DID `{did}` has no webvh record on disk."),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Re-run `vta setup` — local state appears corrupted.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::VtaDidLogMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_missing",
                    message: format!("VTA DID `{did}` has no published log."),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Re-run `vta setup` — local state appears corrupted.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::EmptyLog) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_empty",
                    message: "VTA DID log is empty.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Re-run `vta setup` — local state appears corrupted.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::NoActiveMediator) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "no_active_mediator",
                    message:
                        "DIDComm is enabled but the DID document has no `#vta-didcomm` service entry."
                            .into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "On-disk state is inconsistent — re-run `vta setup`.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::Handshake(HandshakeError::Failed { stage, cause })) => {
                (
                    StatusCode::BAD_GATEWAY,
                    ErrorBody {
                        error: "mediator_handshake_failed",
                        message: format!("mediator handshake failed: {cause}"),
                        mediator_did: None,
                        suggested_fix: Some(match stage {
                            HandshakeStage::Resolve => {
                                "Check the mediator DID is correct and reachable.".into()
                            }
                            _ => {
                                "Inspect the mediator's logs; or retry with `--force` if you've validated reachability out-of-band."
                                    .into()
                            }
                        }),
                        stage: Some(stage_str(stage)),
                    },
                )
            }
            Self::Op(UpdateDidcommError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::ConfigPersistence(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "config_persistence_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some(
                        "Check the VTA's config file is writable; the LogEntry was published. Fix permissions and retry."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::Registry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "registry_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some(
                        "This operation requires super-admin privileges.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(UpdateDidcommError::Storage(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_failed",
                    message: e,
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver is not initialised on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Configure `resolver_url` or run with the local resolver.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ────────────────────────────────────────────────────────────────────
// drain_cancel
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DrainCancelRequest {
    pub mediator_did: String,
}

#[derive(Debug, Serialize)]
pub struct DrainCancelResponse {
    pub mediator_did: String,
}

pub async fn drain_cancel_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<DrainCancelRequest>,
) -> Result<Json<DrainCancelResponse>, DrainCancelHttpError> {
    use crate::operations::protocol::drain_cancel::{DrainCancelParams, drain_cancel};
    let result = drain_cancel(
        &state.config,
        &state.drains_ks,
        &state.mediator_registry,
        &state.telemetry,
        &auth.0,
        DrainCancelParams {
            mediator_did: req.mediator_did,
        },
        "rest",
    )
    .await?;
    Ok(Json(DrainCancelResponse {
        mediator_did: result.mediator_did,
    }))
}

#[derive(Debug)]
pub enum DrainCancelHttpError {
    Op(crate::operations::protocol::drain_cancel::DrainCancelError),
}

impl From<crate::operations::protocol::drain_cancel::DrainCancelError> for DrainCancelHttpError {
    fn from(value: crate::operations::protocol::drain_cancel::DrainCancelError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for DrainCancelHttpError {
    fn into_response(self) -> Response {
        use crate::operations::protocol::drain_cancel::DrainCancelError;
        let (status, body) = match self {
            Self::Op(DrainCancelError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(DrainCancelError::Registry(e)) => {
                use crate::messaging::registry::RegistryError;
                let (code, fix) = match &e {
                    RegistryError::CannotCancelActive(_) => (
                        "cannot_cancel_active",
                        Some(
                            "Use `pnm services didcomm disable` to disable the active mediator instead.".to_string(),
                        ),
                    ),
                    RegistryError::NotRegistered(_) => (
                        "not_registered",
                        Some(
                            "List drains with `pnm services didcomm drain list` to see what's currently in drain state.".to_string(),
                        ),
                    ),
                    _ => ("registry_failed", None),
                };
                (
                    StatusCode::CONFLICT,
                    ErrorBody {
                        error: code,
                        message: e.to_string(),
                        mediator_did: None,
                        suggested_fix: fix,
                        stage: None,
                    },
                )
            }
        };
        (status, Json(body)).into_response()
    }
}

// ────────────────────────────────────────────────────────────────────
// mediator report
// ────────────────────────────────────────────────────────────────────

use axum::extract::Query;

#[derive(Debug, Deserialize)]
pub struct MediatorReportQuery {
    /// Lower bound (RFC 3339).
    #[serde(default)]
    pub since: Option<String>,
    /// Upper bound (RFC 3339).
    #[serde(default)]
    pub until: Option<String>,
}

pub async fn mediator_report_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Query(q): Query<MediatorReportQuery>,
) -> Result<Json<crate::operations::protocol::report::MediatorReport>, MediatorReportHttpError> {
    use crate::operations::protocol::report::{ReportParams, mediator_report};
    let since = parse_rfc3339(q.since.as_deref())?;
    let until = parse_rfc3339(q.until.as_deref())?;
    let report = mediator_report(&state.telemetry, &auth.0, ReportParams { since, until }).await?;
    Ok(Json(report))
}

fn parse_rfc3339(
    s: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, MediatorReportHttpError> {
    use chrono::{DateTime, Utc};
    match s {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|d| Some(d.with_timezone(&Utc)))
            .map_err(|e| MediatorReportHttpError::BadTimestamp(e.to_string())),
    }
}

#[derive(Debug)]
pub enum MediatorReportHttpError {
    Op(crate::operations::protocol::report::ReportError),
    BadTimestamp(String),
}

impl From<crate::operations::protocol::report::ReportError> for MediatorReportHttpError {
    fn from(value: crate::operations::protocol::report::ReportError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for MediatorReportHttpError {
    fn into_response(self) -> Response {
        use crate::operations::protocol::report::ReportError;
        let (status, body) = match self {
            Self::Op(ReportError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    mediator_did: None,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(ReportError::Telemetry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "telemetry_query_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::BadTimestamp(e) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "bad_timestamp",
                    message: format!("invalid RFC 3339 timestamp: {e}"),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use RFC 3339 / ISO 8601 like `2026-04-29T15:00:00Z`.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// Best-effort assembly of a live `DIDCommServiceProver`.
/// Returns `None` (so the route falls back to `AlwaysOkProver`)
/// when any of these pieces aren't ready:
/// - DIDComm service hasn't been started yet (the bridge's
///   service slot is empty),
/// - the VTA hasn't been fully configured (no `vta_did`),
/// - the secrets resolver hasn't been initialised, or
/// - the verification-method ids haven't been computed
///   (`init_auth` left them `None` because there's no `vta_did`
///   yet).
///
/// The fallback isn't a code-quality cop-out — it's the
/// intended behaviour when DIDComm isn't running. The live prover
/// is only meaningful for `update_didcomm` and `services didcomm
/// rollback`, where DIDComm is by definition already up.
async fn build_live_prover(
    state: &AppState,
    bridge: &Arc<crate::didcomm_bridge::DIDCommBridge>,
) -> Option<crate::messaging::live_prover::DIDCommServiceProver> {
    let vta_did = {
        let cfg = state.config.read().await;
        cfg.vta_did.clone()?
    };
    crate::messaging::live_prover::try_build_from_parts(
        bridge,
        &vta_did,
        state.secrets_resolver.as_ref()?,
        state.signing_vm_id.as_ref()?,
        state.ka_vm_id.as_ref()?,
    )
    .await
}

/// Run the transient first-enable handshake against the new
/// mediator if the VTA has the prerequisites (secrets resolver,
/// signing/ka vm ids, vta_did). Returns `Ok(())` if the handshake
/// succeeded OR if the prerequisites aren't available (the caller
/// then falls back to the operation's AlwaysOkProver path).
/// Returns `Err(HandshakeError::Failed)` only when the handshake
/// actually ran and failed.
async fn try_run_first_enable_handshake(
    state: &AppState,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    mediator_did: &str,
    timeout: std::time::Duration,
) -> Result<(), crate::messaging::handshake::HandshakeError> {
    use crate::messaging::handshake::HandshakeOptions;
    use crate::messaging::transient_handshake::{
        TransientHandshakeContext, run_transient_handshake,
    };
    use affinidi_tdk::secrets_resolver::SecretsResolver;

    let Some(secrets_resolver) = state.secrets_resolver.as_ref() else {
        return Ok(());
    };
    let Some(signing_vm_id) = state.signing_vm_id.as_ref() else {
        return Ok(());
    };
    let Some(ka_vm_id) = state.ka_vm_id.as_ref() else {
        return Ok(());
    };
    let vta_did = {
        let cfg = state.config.read().await;
        match cfg.vta_did.clone() {
            Some(d) => d,
            None => return Ok(()),
        }
    };

    let mut secrets = Vec::with_capacity(2);
    if let Some(s) = secrets_resolver.get_secret(signing_vm_id).await {
        secrets.push(s);
    }
    if let Some(s) = secrets_resolver.get_secret(ka_vm_id).await {
        secrets.push(s);
    }
    if secrets.is_empty() {
        return Ok(());
    }

    run_transient_handshake(
        TransientHandshakeContext {
            vta_did,
            secrets,
            tdk_config: None,
        },
        resolver,
        &state.telemetry,
        mediator_did,
        HandshakeOptions {
            timeout,
            force: false,
        },
    )
    .await
    .map(|_| ())
}

// ── REST service-management handlers (spec §3.4) ──────────────────
//
// `POST /services/rest/{enable,update,disable}` and (in T3.4)
// `/services/rest/rollback`. The wire types are reused directly
// from `vta_sdk::protocol::services` rather than redefined locally
// — the SDK types are the canonical wire contract; redefining them
// here would just duplicate that contract.
//
// Response shape is the SDK's shared `ServiceMutationResponse` for
// every mutation across REST and DIDComm (spec §4). REST mutations
// always set `drain_until: None`; DIDComm ops in T2.x will populate
// it when scheduling a drain.

/// `POST /services/rest/enable` — add a `#vta-rest` service entry
/// to the VTA's DID document. Auth: super-admin. Refused with
/// `ServiceAlreadyEnabled` if REST is already advertised.
pub async fn enable_rest_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<vta_sdk::protocol::services::EnableRestRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, RestServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(RestServiceHttpError::DidResolverUnavailable)?
        .clone();

    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = enable_rest(
        &deps,
        &auth.0,
        EnableRestParams { url: req.url },
        OpContext::Direct,
        "rest",
    )
    .await?;

    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/rest/update` — replace the URL on the existing
/// `#vta-rest` entry. Auth: super-admin. Refused with
/// `ServiceNotPresent` if REST isn't currently advertised.
pub async fn update_rest_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<vta_sdk::protocol::services::UpdateRestRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, RestServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(RestServiceHttpError::DidResolverUnavailable)?
        .clone();

    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = update_rest(
        &deps,
        &auth.0,
        UpdateRestParams { url: req.url },
        OpContext::Direct,
        "rest",
    )
    .await?;

    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/rest/disable` — remove the `#vta-rest` entry.
/// Auth: super-admin. Refused with `LastServiceRefused` when
/// DIDComm is also disabled (spec §3.2 — no `--force` escape).
pub async fn disable_rest_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(_req): Json<vta_sdk::protocol::services::DisableRestRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, RestServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(RestServiceHttpError::DidResolverUnavailable)?
        .clone();

    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = disable_rest(&deps, &auth.0, DisableRestParams, OpContext::Direct, "rest").await?;

    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// Unified HTTP error type for the three REST service-management
/// routes. Each operation has its own typed error enum, but the
/// HTTP-level concerns (status code + error body shape) overlap
/// enough that one `IntoResponse` covers them all.
#[derive(Debug)]
pub enum RestServiceHttpError {
    Enable(EnableRestError),
    Update(UpdateRestError),
    Disable(DisableRestError),
    DidResolverUnavailable,
}

impl From<EnableRestError> for RestServiceHttpError {
    fn from(value: EnableRestError) -> Self {
        Self::Enable(value)
    }
}
impl From<UpdateRestError> for RestServiceHttpError {
    fn from(value: UpdateRestError) -> Self {
        Self::Update(value)
    }
}
impl From<DisableRestError> for RestServiceHttpError {
    fn from(value: DisableRestError) -> Self {
        Self::Disable(value)
    }
}

impl IntoResponse for RestServiceHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            // ── Enable ────────────────────────────────────────────
            Self::Enable(EnableRestError::ServiceAlreadyEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "service_already_enabled",
                    message: "REST is already enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services rest update --url <url>` to change the URL.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Enable(EnableRestError::Validation(msg)) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "invalid_url",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some(
                        "URL must be https://, parsable, with no fragment or userinfo.".into(),
                    ),
                    stage: None,
                },
            ),

            // ── Update ────────────────────────────────────────────
            Self::Update(UpdateRestError::ServiceNotPresent) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "service_not_present",
                    message: "REST is not currently enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `pnm services rest enable --url <url>` first.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Update(UpdateRestError::Validation(msg)) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "invalid_url",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some(
                        "URL must be https://, parsable, with no fragment or userinfo.".into(),
                    ),
                    stage: None,
                },
            ),

            // ── Disable ───────────────────────────────────────────
            Self::Disable(DisableRestError::ServiceNotPresent) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "service_not_present",
                    message: "REST is not currently enabled — nothing to disable.".into(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Disable(DisableRestError::LastServiceRefused) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "last_service_refused",
                    message: "Refusing to disable REST — DIDComm is also off, so the VTA would have no advertised services.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `pnm services didcomm enable --mediator-did <did>` first, then retry."
                            .into(),
                    ),
                    stage: None,
                },
            ),

            // ── Shared per-op errors (auth / VTA-DID / publish /
            //    storage) — each variant routes to the same status
            //    + a per-op error tag. Match arms grouped by the
            //    underlying concept.
            Self::Enable(EnableRestError::Auth(msg))
            | Self::Update(UpdateRestError::Auth(msg))
            | Self::Disable(DisableRestError::Auth(msg)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "auth",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some(
                        "Super-admin role required for service-management operations.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Enable(EnableRestError::VtaDidNotConfigured)
            | Self::Update(UpdateRestError::VtaDidNotConfigured)
            | Self::Disable(DisableRestError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Enable(EnableRestError::WebVHUpdate(e))
            | Self::Update(UpdateRestError::WebVHUpdate(e))
            | Self::Disable(DisableRestError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Enable(EnableRestError::DocumentPatch(e))
            | Self::Update(UpdateRestError::DocumentPatch(e))
            | Self::Disable(DisableRestError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),

            // ── Storage / persistence / log-corruption catch-alls.
            //    Same shape across ops; collapse to a single arm.
            Self::Enable(
                EnableRestError::VtaDidRecordMissing(_)
                | EnableRestError::VtaDidLogMissing(_)
                | EnableRestError::EmptyLog
                | EnableRestError::ConfigPersistence(_)
                | EnableRestError::Storage(_),
            )
            | Self::Update(
                UpdateRestError::VtaDidRecordMissing(_)
                | UpdateRestError::VtaDidLogMissing(_)
                | UpdateRestError::EmptyLog
                | UpdateRestError::Storage(_),
            )
            | Self::Disable(
                DisableRestError::VtaDidRecordMissing(_)
                | DisableRestError::VtaDidLogMissing(_)
                | DisableRestError::EmptyLog
                | DisableRestError::ConfigPersistence(_)
                | DisableRestError::Storage(_),
            ) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_error",
                    message: "Internal storage / log-replay failure.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Re-run `vta setup` if local state appears corrupted.".into(),
                    ),
                    stage: None,
                },
            ),

            Self::DidResolverUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver not available on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Confirm the resolver is configured and running, then retry.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ── Fail-forward rollback handlers (T3.4) ─────────────────────────
//
// `POST /services/{rest,didcomm}/rollback` — read the per-kind
// snapshot store and dispatch into the appropriate forward op.
// Spec §3.5a. The dispatched op publishes its own LogEntry; this
// handler just routes the snapshot read + forwards the operator's
// drain TTL where applicable.
//
// No-op rollbacks (snapshot ≡ current state) return a 200 with an
// empty `log_entry_version_id` and a `kind` field set to "no_op".
// CLIs surface this as "nothing to do" without raising an error.

/// `POST /services/rest/rollback` — fail-forward the most recent
/// REST mutation. Auth: super-admin. Refused with `NoPriorMutation`
/// when no snapshot is recorded.
pub async fn rollback_rest_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(_req): Json<vta_sdk::protocol::services::RollbackRestRequest>,
) -> Result<Json<RollbackResponse>, RollbackRestHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(RollbackRestHttpError::DidResolverUnavailable)?
        .clone();

    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = rollback_rest(&deps, &auth.0, RollbackRestParams, "rest").await?;

    Ok(Json(RollbackResponse {
        log_entry_version_id: result.new_version_id.unwrap_or_default(),
        effective_at: chrono::Utc::now().to_rfc3339(),
        kind: rest_kind_str(result.kind).into(),
        drain_until: None,
        draining_mediator: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/didcomm/rollback` — fail-forward the most recent
/// DIDComm mutation. Auth: super-admin. Threads drain_ttl through
/// to the dispatched forward op for the disable / update arms.
pub async fn rollback_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RollbackDidcommHttpRequest>,
) -> Result<Json<RollbackResponse>, RollbackDidcommHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(RollbackDidcommHttpError::DidResolverUnavailable)?
        .clone();
    let bridge = Arc::clone(&state.didcomm_bridge);

    // Rollback dispatches into a forward op (update or disable). When
    // it dispatches into `update_didcomm` to re-promote a previously-
    // active mediator, the new active needs to handshake before we
    // commit the LogEntry. Use the live prover when available so a
    // dead re-promotion target fails at handshake instead of
    // silently bricking the VTA. Falls back to `AlwaysOkProver`
    // only when DIDComm isn't currently running (the rollback then
    // can only meaningfully dispatch into `enable_didcomm` /
    // `disable_didcomm` arms, neither of which exercises the
    // prover).
    let live_prover = build_live_prover(&state, &bridge).await;
    let always_ok = AlwaysOkProver;
    let prover_ref: &(dyn crate::messaging::handshake::ListenerProver + Send + Sync) =
        match live_prover.as_ref() {
            Some(p) => p,
            None => &always_ok,
        };

    let drain_ttl = Duration::from_secs(req.drain_ttl_secs.unwrap_or(86_400));

    let result = rollback_didcomm(
        &state.config,
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &state.service_state_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        prover_ref,
        &auth.0,
        RollbackDidcommParams {
            drain_ttl,
            transport: DidcommTransport::Rest,
        },
        &state.webvh_auth_locks,
        "rest",
    )
    .await?;

    Ok(Json(RollbackResponse {
        log_entry_version_id: result.new_version_id.unwrap_or_default(),
        effective_at: chrono::Utc::now().to_rfc3339(),
        kind: didcomm_kind_str(result.kind).into(),
        drain_until: None,
        draining_mediator: result.draining_mediator,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// REST handler request body for didcomm rollback. The drain_ttl
/// is optional — server applies the spec §3.6 default (24h) when
/// omitted.
#[derive(Debug, Deserialize)]
pub struct RollbackDidcommHttpRequest {
    #[serde(default)]
    pub drain_ttl_secs: Option<u64>,
}

/// Unified rollback response shape used by both REST handlers.
/// Wider than `ServiceMutationResponse` because rollback adds two
/// concepts: a `kind` discriminator (so the CLI can print
/// "rolled back to enabled at https://x.example.com" vs.
/// "rollback was a no-op") and a `draining_mediator` field
/// for the DIDComm update / disable arms.
#[derive(Debug, Serialize)]
pub struct RollbackResponse {
    /// New WebVH LogEntry version-id. Empty string when the
    /// rollback was a no-op (snapshot ≡ current state).
    pub log_entry_version_id: String,
    pub effective_at: String,
    /// One of: `disabled`, `enabled`, `updated`, `no_op`.
    pub kind: String,
    /// `Some(rfc3339)` when the rollback scheduled a drain on
    /// the previously-active mediator (DIDComm update / disable
    /// arms). `None` for REST and for the DIDComm enable / no-op
    /// arms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
    /// Mediator DID currently being drained by this rollback's
    /// dispatched op. `None` for REST and DIDComm enable / no-op
    /// arms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draining_mediator: Option<String>,
    /// The VTA's own DID — subject of the LogEntry this rollback
    /// wrote. Empty in `no_op` responses where no LogEntry was
    /// written. Aligned with
    /// `vta_sdk::protocol::services::RollbackResponse::vta_did`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. `false` on no-op
    /// rollbacks (no follow-up redeploy needed).
    #[serde(default)]
    pub serverless: bool,
}

fn rest_kind_str(k: RestRollbackKind) -> &'static str {
    match k {
        RestRollbackKind::Disabled => "disabled",
        RestRollbackKind::Enabled => "enabled",
        RestRollbackKind::Updated => "updated",
        RestRollbackKind::NoOp => "no_op",
    }
}

fn didcomm_kind_str(k: DidcommRollbackKind) -> &'static str {
    match k {
        DidcommRollbackKind::Disabled => "disabled",
        DidcommRollbackKind::Enabled => "enabled",
        DidcommRollbackKind::Updated => "updated",
        DidcommRollbackKind::NoOp => "no_op",
    }
}

#[derive(Debug)]
pub enum RollbackRestHttpError {
    Op(RollbackRestError),
    DidResolverUnavailable,
}

impl From<RollbackRestError> for RollbackRestHttpError {
    fn from(value: RollbackRestError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for RollbackRestHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(RollbackRestError::NoPriorMutation) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "no_prior_mutation",
                    message: "No prior REST mutation to roll back from.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services rest enable / update / disable` directly instead."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(RollbackRestError::DisableForward(DisableRestError::LastServiceRefused)) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "last_service_refused",
                    message:
                        "Rolling back this REST mutation would leave the VTA with no advertised \
                         services. Enable DIDComm first and retry."
                            .into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `pnm services didcomm enable --mediator-did <did>`, then retry rollback."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(other) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "rollback_failed",
                    message: other.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver not available on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[derive(Debug)]
pub enum RollbackDidcommHttpError {
    Op(RollbackDidcommError),
    DidResolverUnavailable,
}

impl From<RollbackDidcommError> for RollbackDidcommHttpError {
    fn from(value: RollbackDidcommError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for RollbackDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(RollbackDidcommError::NoPriorMutation) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "no_prior_mutation",
                    message: "No prior DIDComm mutation to roll back from.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services didcomm enable / update / disable` directly instead."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(RollbackDidcommError::DisableForward(
                DisableDidcommError::NoProtocolRemaining,
            )) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "last_service_refused",
                    message:
                        "Rolling back this DIDComm mutation would leave the VTA with no advertised \
                         services. Enable REST first and retry."
                            .into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `pnm services rest enable --url <url>`, then retry rollback.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(other) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "rollback_failed",
                    message: other.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver not available on this VTA.".into(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ── List handler (T4.2) ───────────────────────────────────────────
//
// `GET /services` — read-only inspection of the VTA's currently
// advertised transport services. Auth: super-admin (matches the
// other service-management ops; the operator's view of service
// state is operational info we keep gated).

use crate::operations::protocol::list::{ListServicesError, list_services};

pub async fn list_services_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<vta_sdk::protocol::services::ServicesListResponse>, ListServicesHttpError> {
    let response = list_services(&state.config, &state.webvh_ks, &auth.0).await?;
    Ok(Json(response))
}

#[derive(Debug)]
pub enum ListServicesHttpError {
    Op(ListServicesError),
}

impl From<ListServicesError> for ListServicesHttpError {
    fn from(value: ListServicesError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for ListServicesHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(ListServicesError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Op(ListServicesError::Auth(msg)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "auth",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some("Super-admin role required for service inspection.".into()),
                    stage: None,
                },
            ),
            Self::Op(other) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "list_failed",
                    message: other.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ── List drain handler (T5/list_drain) ────────────────────────────

use crate::operations::protocol::list_drain::{ListDrainError, list_drain};

pub async fn list_drain_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<vta_sdk::protocol::services::DrainListResponse>, ListDrainHttpError> {
    let response = list_drain(&state.config, &state.drains_ks, &auth.0).await?;
    Ok(Json(response))
}

#[derive(Debug)]
pub enum ListDrainHttpError {
    Op(ListDrainError),
}

impl From<ListDrainError> for ListDrainHttpError {
    fn from(value: ListDrainError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for ListDrainHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(ListDrainError::Auth(msg)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "auth",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some("Super-admin role required for service inspection.".into()),
                    stage: None,
                },
            ),
            Self::Op(other) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "list_drain_failed",
                    message: other.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ─── WebAuthn-service handlers ────────────────────────────────────────

/// `POST /services/webauthn/enable` — add a `#vta-webauthn` service
/// entry to the VTA's DID document. Auth: super-admin.
pub async fn enable_webauthn_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<vta_sdk::protocol::services::EnableWebauthnRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, WebauthnServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(WebauthnServiceHttpError::DidResolverUnavailable)?
        .clone();
    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = enable_webauthn(
        &deps,
        &auth.0,
        EnableWebauthnParams { url: req.url },
        OpContext::Direct,
        "rest",
    )
    .await?;
    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/webauthn/update` — replace the URL.
pub async fn update_webauthn_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<vta_sdk::protocol::services::UpdateWebauthnRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, WebauthnServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(WebauthnServiceHttpError::DidResolverUnavailable)?
        .clone();
    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = update_webauthn(
        &deps,
        &auth.0,
        UpdateWebauthnParams { url: req.url },
        OpContext::Direct,
        "rest",
    )
    .await?;
    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/webauthn/disable` — remove the `#vta-webauthn`
/// entry **and** strip passkey VMs from every DID this VTA
/// controls. Auth: super-admin.
pub async fn disable_webauthn_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(_req): Json<vta_sdk::protocol::services::DisableWebauthnRequest>,
) -> Result<Json<vta_sdk::protocol::services::ServiceMutationResponse>, WebauthnServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(WebauthnServiceHttpError::DidResolverUnavailable)?
        .clone();
    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = disable_webauthn(
        &deps,
        &auth.0,
        DisableWebauthnParams::default(),
        OpContext::Direct,
        "rest",
    )
    .await?;
    Ok(Json(vta_sdk::protocol::services::ServiceMutationResponse {
        log_entry_version_id: result.new_version_id,
        effective_at: chrono::Utc::now().to_rfc3339(),
        drain_until: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

/// `POST /services/webauthn/rollback` — fail-forward dispatch.
pub async fn rollback_webauthn_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(_req): Json<vta_sdk::protocol::services::RollbackWebauthnRequest>,
) -> Result<Json<vta_sdk::protocol::services::RollbackResponse>, WebauthnServiceHttpError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(WebauthnServiceHttpError::DidResolverUnavailable)?
        .clone();
    let deps = ServiceOpDeps::from_app_state(&state, &did_resolver);
    let result = rollback_webauthn(&deps, &auth.0, RollbackWebauthnParams, "rest").await?;
    let kind_str = match result.kind {
        WebauthnRollbackKind::Disabled => "disabled",
        WebauthnRollbackKind::Enabled => "enabled",
        WebauthnRollbackKind::Updated => "updated",
        WebauthnRollbackKind::NoOp => "no_op",
    };
    Ok(Json(vta_sdk::protocol::services::RollbackResponse {
        log_entry_version_id: result.new_version_id.unwrap_or_default(),
        effective_at: chrono::Utc::now().to_rfc3339(),
        kind: kind_str.into(),
        drain_until: None,
        draining_mediator: None,
        vta_did: result.vta_did,
        serverless: result.serverless,
    }))
}

#[derive(Debug)]
pub enum WebauthnServiceHttpError {
    Enable(EnableWebauthnError),
    Update(UpdateWebauthnError),
    Disable(DisableWebauthnError),
    Rollback(RollbackWebauthnError),
    DidResolverUnavailable,
}
impl From<EnableWebauthnError> for WebauthnServiceHttpError {
    fn from(value: EnableWebauthnError) -> Self {
        Self::Enable(value)
    }
}
impl From<UpdateWebauthnError> for WebauthnServiceHttpError {
    fn from(value: UpdateWebauthnError) -> Self {
        Self::Update(value)
    }
}
impl From<DisableWebauthnError> for WebauthnServiceHttpError {
    fn from(value: DisableWebauthnError) -> Self {
        Self::Disable(value)
    }
}
impl From<RollbackWebauthnError> for WebauthnServiceHttpError {
    fn from(value: RollbackWebauthnError) -> Self {
        Self::Rollback(value)
    }
}
impl IntoResponse for WebauthnServiceHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Enable(EnableWebauthnError::ServiceAlreadyEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "service_already_enabled",
                    message: "WebAuthn is already enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Use `pnm services webauthn update --url <url>` to change it.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Enable(EnableWebauthnError::Validation(msg))
            | Self::Update(UpdateWebauthnError::Validation(msg)) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "invalid_url",
                    message: msg,
                    mediator_did: None,
                    suggested_fix: Some("URL must be https://, parsable, with no fragment.".into()),
                    stage: None,
                },
            ),
            Self::Update(UpdateWebauthnError::ServiceNotPresent)
            | Self::Disable(DisableWebauthnError::ServiceNotPresent) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "service_not_present",
                    message: "WebAuthn is not currently enabled.".into(),
                    mediator_did: None,
                    suggested_fix: Some(
                        "Run `pnm services webauthn enable --url <url>` first.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Disable(DisableWebauthnError::LastServiceRefused)
            | Self::Rollback(RollbackWebauthnError::DisableForward(
                DisableWebauthnError::LastServiceRefused,
            )) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "last_service_refused",
                    message: "Refusing — at least one transport must remain advertised.".into(),
                    mediator_did: None,
                    suggested_fix: Some("Enable REST or DIDComm before disabling WebAuthn.".into()),
                    stage: None,
                },
            ),
            Self::Rollback(RollbackWebauthnError::NoPriorMutation) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "no_prior_mutation",
                    message: "No prior `services webauthn` mutation to roll back.".into(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver not configured.".into(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Enable(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "enable_webauthn_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Update(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "update_webauthn_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Disable(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "disable_webauthn_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Rollback(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "rollback_webauthn_failed",
                    message: e.to_string(),
                    mediator_did: None,
                    suggested_fix: None,
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}
