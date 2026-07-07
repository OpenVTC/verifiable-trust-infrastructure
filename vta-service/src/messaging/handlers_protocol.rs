//! DIDComm handlers for protocol-management operations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Each handler is a thin adapter: parse the body, call the
//! existing operation function with `DisableTransport::Didcomm`
//! when applicable so the spec's 1h-min-TTL guard fires (criterion
//! #12), and return a typed response.
//!
//! `enable` is intentionally NOT exposed over DIDComm — DIDComm
//! isn't running yet at first-enable time, so the request couldn't
//! arrive over this transport in the first place.

#![cfg(feature = "webvh")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use vta_sdk::protocols::protocol_management;

use super::router::VtaState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::handshake::AlwaysOkProver;
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::disable_rest::{DisableRestParams, disable_rest};
use crate::operations::protocol::disable_tsp::{DisableTspParams, disable_tsp};
use crate::operations::protocol::drain_cancel::{DrainCancelParams, drain_cancel};
use crate::operations::protocol::enable_rest::{EnableRestParams, enable_rest};
use crate::operations::protocol::enable_tsp::{EnableTspParams, enable_tsp};
use crate::operations::protocol::report::{ReportParams, mediator_report};
use crate::operations::protocol::rollback_didcomm::{RollbackDidcommParams, rollback_didcomm};
use crate::operations::protocol::rollback_rest::{RollbackRestParams, rollback_rest};
use crate::operations::protocol::rollback_tsp::{RollbackTspParams, rollback_tsp};
use crate::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommParams, update_didcomm,
};
use crate::operations::protocol::update_rest::{UpdateRestParams, update_rest};
use crate::operations::protocol::update_tsp::{UpdateTspParams, update_tsp};
use crate::operations::protocol::{OpContext, ServiceOpDeps};

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Best-effort assembly of a live `DIDCommServiceProver` from this
/// handler's `VtaState`. Mirrors `routes::protocol::build_live_prover`
/// — both transports use the same shared
/// `messaging::live_prover::try_build_from_parts` helper so the
/// rollback dispatcher's re-promotion handshake runs against the
/// real mediator regardless of which transport invoked it. Returns
/// `None` (caller falls back to `AlwaysOkProver`) when
/// secrets-resolver / vm-ids haven't been threaded through yet.
async fn build_live_prover_from_vta_state(
    state: &VtaState,
) -> Option<crate::messaging::live_prover::DIDCommServiceProver> {
    let vta_did = {
        let cfg = state.config.read().await;
        cfg.vta_did.clone()?
    };
    crate::messaging::live_prover::try_build_from_parts(
        &state.didcomm_bridge,
        &vta_did,
        state.secrets_resolver.as_ref()?,
        state.signing_vm_id.as_ref()?,
        state.ka_vm_id.as_ref()?,
    )
    .await
}

fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

fn response<T: serde::Serialize>(msg_type: &str, result: &T) -> HandlerResult {
    let body = serde_json::to_value(result).map_err(handler_err)?;
    Ok(Some(DIDCommResponse::new(msg_type, body)))
}

fn problem_report_unauthorized(msg: impl Into<String>) -> DIDCommResponse {
    DIDCommResponse::problem_report(ProblemReport::unauthorized(msg.into()))
}

/// Authenticate the authcrypt sender, or early-return the byte-identical
/// `unauthorized` problem-report. Every protocol-management handler runs this
/// first; making it a macro keeps the early-return at the call site (so a
/// handler cannot accidentally proceed unauthenticated) while removing the
/// 4-line `match` each one repeated.
macro_rules! protocol_auth {
    ($state:expr, $message:expr) => {
        match auth_from_message(&$message, &$state.acl_ks, &$state.sessions_ks).await {
            Ok(a) => a,
            Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
        }
    };
}

/// Maps a protocol-management operation's typed error to its DIDComm
/// [`ProblemReport`]. Folds the per-handler `match result { Err(...) => ... }`
/// tails (which hand-rolled the same `Auth → unauthorized` / catch-all →
/// `internal-error` shape plus a few op-specific `conflict`/`bad-request`
/// arms) into one impl per error type. The emitted codes + comments are
/// byte-identical to the prior inline matches. Returns the `ProblemReport`
/// (not a wrapped `DIDCommResponse`) so the code/comment contract is
/// unit-testable on its public fields.
trait ToProblemReport {
    fn to_problem_report(self) -> ProblemReport;
}

impl ToProblemReport for crate::operations::protocol::disable_didcomm::DisableDidcommError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::disable_didcomm::DisableDidcommError as E;
        match self {
            E::DidcommNotEnabled => ProblemReport::conflict("DIDComm is not currently enabled"),
            E::NoProtocolRemaining => {
                ProblemReport::conflict("cannot disable DIDComm — REST is also disabled")
            }
            E::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            } => ProblemReport::bad_request(format!(
                "drain ttl {requested}s outside allowed range [{min}s, {max}s]"
            )),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::update_didcomm::UpdateDidcommError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::update_didcomm::UpdateDidcommError as E;
        match self {
            E::DidcommNotEnabled => ProblemReport::conflict("DIDComm is not currently enabled"),
            E::SameAsActive(did) => {
                ProblemReport::conflict(format!("{did} is already the active mediator"))
            }
            E::AlreadyDraining(did) => ProblemReport::conflict(format!(
                "{did} is currently in drain state — cancel or rollback first"
            )),
            E::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            } => ProblemReport::bad_request(format!(
                "drain ttl {requested}s outside allowed range [{min}s, {max}s]"
            )),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::drain_cancel::DrainCancelError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::messaging::registry::RegistryError;
        use crate::operations::protocol::drain_cancel::DrainCancelError as E;
        match self {
            E::Auth(e) => ProblemReport::unauthorized(e),
            E::Registry(RegistryError::CannotCancelActive(did)) => ProblemReport::conflict(
                format!("{did} is the active mediator — use disable instead"),
            ),
            E::Registry(RegistryError::NotRegistered(did)) => {
                ProblemReport::conflict(format!("{did} is not registered (no drain entry)"))
            }
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::report::ReportError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::report::ReportError as E;
        match self {
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::enable_rest::EnableRestError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::enable_rest::EnableRestError as E;
        match self {
            E::ServiceAlreadyEnabled => ProblemReport::conflict("REST is already enabled"),
            E::Validation(e) => ProblemReport::bad_request(e),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::update_rest::UpdateRestError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::update_rest::UpdateRestError as E;
        match self {
            E::ServiceNotPresent => ProblemReport::conflict("REST is not currently enabled"),
            E::Validation(e) => ProblemReport::bad_request(e),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::disable_rest::DisableRestError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::disable_rest::DisableRestError as E;
        match self {
            E::ServiceNotPresent => {
                ProblemReport::conflict("REST is not currently enabled — nothing to disable")
            }
            E::LastServiceRefused => ProblemReport::conflict(
                "refusing operation: would leave the VTA with no advertised services",
            ),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::rollback_rest::RollbackRestError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::rollback_rest::RollbackRestError as E;
        match self {
            E::NoPriorMutation => {
                ProblemReport::conflict("no prior REST mutation to roll back from")
            }
            E::DisableForward(
                crate::operations::protocol::disable_rest::DisableRestError::LastServiceRefused,
            ) => ProblemReport::conflict(
                "rolling back this REST mutation would leave the VTA with no advertised services",
            ),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::enable_tsp::EnableTspError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::enable_tsp::EnableTspError as E;
        match self {
            E::ServiceAlreadyEnabled => ProblemReport::conflict("TSP is already enabled"),
            E::Validation(e) => ProblemReport::bad_request(e),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::update_tsp::UpdateTspError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::update_tsp::UpdateTspError as E;
        match self {
            E::ServiceNotPresent => ProblemReport::conflict("TSP is not currently enabled"),
            E::Validation(e) => ProblemReport::bad_request(e),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::disable_tsp::DisableTspError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::disable_tsp::DisableTspError as E;
        match self {
            E::ServiceNotPresent => {
                ProblemReport::conflict("TSP is not currently enabled — nothing to disable")
            }
            E::LastServiceRefused => ProblemReport::conflict(
                "refusing operation: would leave the VTA with no advertised services",
            ),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::rollback_tsp::RollbackTspError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::rollback_tsp::RollbackTspError as E;
        match self {
            E::NoPriorMutation => {
                ProblemReport::conflict("no prior TSP mutation to roll back from")
            }
            E::DisableForward(
                crate::operations::protocol::disable_tsp::DisableTspError::LastServiceRefused,
            ) => ProblemReport::conflict(
                "rolling back this TSP mutation would leave the VTA with no advertised services",
            ),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::rollback_didcomm::RollbackDidcommError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::rollback_didcomm::RollbackDidcommError as E;
        match self {
            E::NoPriorMutation => {
                ProblemReport::conflict("no prior DIDComm mutation to roll back from")
            }
            E::DisableForward(
                crate::operations::protocol::disable_didcomm::DisableDidcommError::NoProtocolRemaining,
            ) => ProblemReport::conflict(
                "rolling back this DIDComm mutation would leave the VTA with no advertised services",
            ),
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::list::ListServicesError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::list::ListServicesError as E;
        match self {
            E::Auth(e) => ProblemReport::unauthorized(e),
            E::VtaDidNotConfigured => ProblemReport::conflict("VTA DID is not configured"),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

impl ToProblemReport for crate::operations::protocol::list_drain::ListDrainError {
    fn to_problem_report(self) -> ProblemReport {
        use crate::operations::protocol::list_drain::ListDrainError as E;
        match self {
            E::Auth(e) => ProblemReport::unauthorized(e),
            other => ProblemReport::internal_error(other.to_string()),
        }
    }
}

// ── disable_didcomm over DIDComm ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DisableDidcommBody {
    #[serde(default)]
    drain_ttl_secs: u64,
}

pub async fn handle_disable_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let body: DisableDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = disable_didcomm(
        &deps,
        &auth,
        DisableDidcommParams {
            drain_ttl: Duration::from_secs(body.drain_ttl_secs),
            // Critical: this is the DIDComm transport, so the
            // 1h-min-TTL guard fires (spec criterion #12).
            transport: DisableTransport::Didcomm,
        },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::DISABLE_DIDCOMM_RESULT,
            &serde_json::json!({
                "new_version_id": r.new_version_id,
                "prior_mediator_did": r.prior_mediator_did,
                "drains_until": r.drains_until.map(|t| t.to_rfc3339()),
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── update_didcomm over DIDComm ───────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateDidcommBody {
    new_mediator_did: String,
    drain_ttl_secs: u64,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    handshake_timeout_secs: Option<u64>,
    #[serde(default)]
    rollback: bool,
}

pub async fn handle_update_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let body: UpdateDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;

    // For DIDComm transport we use AlwaysOkProver — see comment in
    // routes/protocol.rs::build_live_prover. Same fallback rationale
    // applies: building a live prover from a DIDComm handler context
    // requires plumbing secrets/vm_ids through VtaState in the same
    // way the route layer does it. Tracked as a follow-up.
    let prover = AlwaysOkProver;
    let timeout = Duration::from_secs(body.handshake_timeout_secs.unwrap_or(10));
    let audit_kind = if body.rollback {
        MigrateAuditKind::Rollback
    } else {
        MigrateAuditKind::Forward
    };

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = update_didcomm(
        &deps,
        &prover,
        &auth,
        UpdateDidcommParams {
            new_mediator_did: body.new_mediator_did,
            drain_ttl: Duration::from_secs(body.drain_ttl_secs),
            force: body.force,
            handshake_timeout: timeout,
            audit_kind,
            transport: crate::operations::protocol::disable_didcomm::DisableTransport::Didcomm,
        },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::UPDATE_DIDCOMM_RESULT,
            &serde_json::json!({
                "new_version_id": r.new_version_id,
                "prior_mediator_did": r.prior_mediator_did,
                "active_mediator_did": r.active_mediator_did,
                "active_mediator_endpoint": r.active_mediator_endpoint,
                "drains_until": r.drains_until.to_rfc3339(),
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── drain_cancel over DIDComm ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DrainCancelBody {
    mediator_did: String,
}

pub async fn handle_drain_cancel(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);
    let body: DrainCancelBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let result = drain_cancel(
        &state.config,
        &state.drains_ks,
        &state.mediator_registry,
        &state.telemetry,
        &auth,
        DrainCancelParams {
            mediator_did: body.mediator_did,
        },
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::DRAIN_CANCEL_RESULT,
            &serde_json::json!({ "mediator_did": r.mediator_did }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── mediator_report over DIDComm ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MediatorReportBody {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
}

pub async fn handle_mediator_report(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);
    let body: MediatorReportBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let parse_ts = |s: Option<String>| -> Result<Option<DateTime<Utc>>, DIDCommServiceError> {
        match s {
            None => Ok(None),
            Some(s) => DateTime::parse_from_rfc3339(&s)
                .map(|d| Some(d.with_timezone(&Utc)))
                .map_err(handler_err),
        }
    };
    let since = parse_ts(body.since)?;
    let until = parse_ts(body.until)?;

    let result = mediator_report(&state.telemetry, &auth, ReportParams { since, until }).await;
    match result {
        Ok(r) => response(protocol_management::MEDIATOR_REPORT_RESULT, &r),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── REST service-management handlers (T1.5) ─────────────────────────
//
// Each handler is a thin adapter mirroring `handle_disable_didcomm`:
// authenticate the message, parse the body, call the existing
// operation function, and emit either a typed result or a problem-
// report. All three REST ops are reachable over DIDComm — REST is
// always running per spec §3.2, so unlike `enable_didcomm` (which
// can't arrive over a transport that isn't running yet) there's no
// chicken-and-egg constraint here.

fn body_str_field(message: &Message, key: &str) -> Result<String, DIDCommServiceError> {
    message
        .body
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| handler_err(format!("missing or non-string `{key}` in body")))
}

pub async fn handle_enable_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let url = body_str_field(&message, "url")?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = enable_rest(
        &deps,
        &auth,
        EnableRestParams { url },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::ENABLE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "url": r.url,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

pub async fn handle_update_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let url = body_str_field(&message, "url")?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = update_rest(
        &deps,
        &auth,
        UpdateRestParams { url },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::UPDATE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_url": r.prior_url,
                "url": r.url,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

pub async fn handle_disable_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = disable_rest(
        &deps,
        &auth,
        DisableRestParams,
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::DISABLE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_url": r.prior_url,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── TSP service management over DIDComm ────────────────────────────
//
// Symmetric with the REST handlers above, but the wire field is
// `mediator_did` (a DID, the VTA's TSP VID) instead of `url`. Unlike
// `enable_didcomm`, TSP enable IS reachable over DIDComm — DIDComm is
// always running when REST is.

pub async fn handle_enable_tsp(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let mediator_did = body_str_field(&message, "mediator_did")?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = enable_tsp(
        &deps,
        &auth,
        EnableTspParams { mediator_did },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::ENABLE_TSP_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "mediator_did": r.mediator_did,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

pub async fn handle_update_tsp(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let mediator_did = body_str_field(&message, "mediator_did")?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = update_tsp(
        &deps,
        &auth,
        UpdateTspParams { mediator_did },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::UPDATE_TSP_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_mediator_did": r.prior_mediator_did,
                "mediator_did": r.mediator_did,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

pub async fn handle_disable_tsp(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = disable_tsp(&deps, &auth, DisableTspParams, OpContext::Direct, "didcomm").await;

    match result {
        Ok(r) => response(
            protocol_management::DISABLE_TSP_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_mediator_did": r.prior_mediator_did,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── Fail-forward rollback over DIDComm (T3.4) ──────────────────────

pub async fn handle_rollback_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = rollback_rest(&deps, &auth, RollbackRestParams, "didcomm").await;

    match result {
        Ok(r) => response(
            protocol_management::ROLLBACK_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id.unwrap_or_default(),
                "effective_at": Utc::now().to_rfc3339(),
                "kind": match r.kind {
                    crate::operations::protocol::rollback_rest::RollbackKind::Disabled => "disabled",
                    crate::operations::protocol::rollback_rest::RollbackKind::Enabled => "enabled",
                    crate::operations::protocol::rollback_rest::RollbackKind::Updated => "updated",
                    crate::operations::protocol::rollback_rest::RollbackKind::NoOp => "no_op",
                },
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

pub async fn handle_rollback_tsp(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = rollback_tsp(&deps, &auth, RollbackTspParams, "didcomm").await;

    match result {
        Ok(r) => response(
            protocol_management::ROLLBACK_TSP_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id.unwrap_or_default(),
                "effective_at": Utc::now().to_rfc3339(),
                "kind": match r.kind {
                    crate::operations::protocol::rollback_tsp::RollbackKind::Disabled => "disabled",
                    crate::operations::protocol::rollback_tsp::RollbackKind::Enabled => "enabled",
                    crate::operations::protocol::rollback_tsp::RollbackKind::Updated => "updated",
                    crate::operations::protocol::rollback_tsp::RollbackKind::NoOp => "no_op",
                },
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

#[derive(Debug, Deserialize)]
struct RollbackDidcommBody {
    #[serde(default)]
    drain_ttl_secs: Option<u64>,
}

pub async fn handle_rollback_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let body: RollbackDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;
    let drain_ttl = std::time::Duration::from_secs(body.drain_ttl_secs.unwrap_or(86_400));

    // Try to assemble a live prover; fall back to AlwaysOkProver
    // when the secrets / vm-ids haven't been threaded through yet
    // (e.g. early-boot fixture). Mirrors the REST handler.
    let live_prover = build_live_prover_from_vta_state(&state).await;
    let always_ok = AlwaysOkProver;
    let prover_ref: &(dyn crate::messaging::handshake::ListenerProver + Send + Sync) =
        match live_prover.as_ref() {
            Some(p) => p,
            None => &always_ok,
        };

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("did_resolver unavailable"))?;
    let deps = ServiceOpDeps::from_vta_state(&state, did_resolver);
    let result = rollback_didcomm(
        &deps,
        prover_ref,
        &auth,
        RollbackDidcommParams {
            drain_ttl,
            // The rollback request arrived over DIDComm transport,
            // so the MIN_DRAIN_TTL_OVER_DIDCOMM floor applies if
            // the dispatch ends up in disable_didcomm.
            transport: DisableTransport::Didcomm,
        },
        "didcomm",
    )
    .await;

    match result {
        Ok(r) => response(
            protocol_management::ROLLBACK_DIDCOMM_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id.unwrap_or_default(),
                "effective_at": Utc::now().to_rfc3339(),
                "kind": match r.kind {
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Disabled => "disabled",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Enabled => "enabled",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Updated => "updated",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::NoOp => "no_op",
                },
                "draining_mediator": r.draining_mediator,
                "vta_did": r.vta_did,
                "serverless": r.serverless,
            }),
        ),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── List services over DIDComm (T4.2) ─────────────────────────────

pub async fn handle_list_services(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);

    let result =
        crate::operations::protocol::list::list_services(&state.config, &state.webvh_ks, &auth)
            .await;

    match result {
        Ok(r) => response(protocol_management::LIST_SERVICES_RESULT, &r),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

// ── List drain over DIDComm ──────────────────────────────────────

pub async fn handle_list_drain(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = protocol_auth!(state, message);
    let result =
        crate::operations::protocol::list_drain::list_drain(&state.config, &state.drains_ks, &auth)
            .await;

    match result {
        Ok(r) => response(protocol_management::LIST_DRAIN_RESULT, &r),
        Err(e) => Ok(Some(DIDCommResponse::problem_report(e.to_problem_report()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::registry::RegistryError;
    use crate::operations::protocol::disable_didcomm::DisableDidcommError;
    use crate::operations::protocol::disable_rest::DisableRestError;
    use crate::operations::protocol::disable_tsp::DisableTspError;
    use crate::operations::protocol::drain_cancel::DrainCancelError;
    use crate::operations::protocol::enable_rest::EnableRestError;
    use crate::operations::protocol::enable_tsp::EnableTspError;
    use crate::operations::protocol::list::ListServicesError;
    use crate::operations::protocol::rollback_rest::RollbackRestError;
    use crate::operations::protocol::rollback_tsp::RollbackTspError;
    use vta_sdk::protocols::problem_report_codes as codes;

    /// Pins the protocol-management error → `e.p.msg.*` problem-report contract
    /// that the `ToProblemReport` impls centralize. Covers each code path
    /// (conflict / bad-request / unauthorized / catch-all internal) across
    /// several error types — a regression would change the code/comment SDK
    /// clients depend on. Codes + comments are byte-identical to the prior
    /// per-handler inline matches.
    #[test]
    fn protocol_errors_map_to_byte_identical_problem_reports() {
        let did_disabled = DisableDidcommError::DidcommNotEnabled.to_problem_report();
        assert_eq!(did_disabled.code, codes::CONFLICT);
        assert_eq!(did_disabled.comment, "DIDComm is not currently enabled");

        let ttl = DisableDidcommError::DrainTtlOutOfBounds {
            min: 3600,
            max: 2_592_000,
            requested: 1,
        }
        .to_problem_report();
        assert_eq!(ttl.code, codes::BAD_REQUEST);
        assert_eq!(
            ttl.comment,
            "drain ttl 1s outside allowed range [3600s, 2592000s]"
        );

        let auth = DisableDidcommError::Auth("nope".into()).to_problem_report();
        assert_eq!(auth.code, codes::UNAUTHORIZED);
        assert_eq!(auth.comment, "nope");

        // Catch-all → internal-error (uses the variant's Display as comment).
        let internal = DisableDidcommError::Storage("disk gone".into()).to_problem_report();
        assert_eq!(internal.code, codes::INTERNAL);

        let already = EnableRestError::ServiceAlreadyEnabled.to_problem_report();
        assert_eq!(already.code, codes::CONFLICT);
        assert_eq!(already.comment, "REST is already enabled");

        let validation = EnableRestError::Validation("bad url".into()).to_problem_report();
        assert_eq!(validation.code, codes::BAD_REQUEST);
        assert_eq!(validation.comment, "bad url");

        let no_vta = ListServicesError::VtaDidNotConfigured.to_problem_report();
        assert_eq!(no_vta.code, codes::CONFLICT);
        assert_eq!(no_vta.comment, "VTA DID is not configured");

        let not_registered =
            DrainCancelError::Registry(RegistryError::NotRegistered("did:m:x".into()))
                .to_problem_report();
        assert_eq!(not_registered.code, codes::CONFLICT);
        assert_eq!(
            not_registered.comment,
            "did:m:x is not registered (no drain entry)"
        );

        // Fail-forward rollback that would brick the VTA → conflict with the
        // dedicated message (not the inner DisableRest message).
        let last_service = RollbackRestError::DisableForward(DisableRestError::LastServiceRefused)
            .to_problem_report();
        assert_eq!(last_service.code, codes::CONFLICT);
        assert_eq!(
            last_service.comment,
            "rolling back this REST mutation would leave the VTA with no advertised services"
        );

        // ── TSP analogs (mediator_did, not url) ──────────────────────
        let tsp_already = EnableTspError::ServiceAlreadyEnabled.to_problem_report();
        assert_eq!(tsp_already.code, codes::CONFLICT);
        assert_eq!(tsp_already.comment, "TSP is already enabled");

        let tsp_validation = EnableTspError::Validation("bad did".into()).to_problem_report();
        assert_eq!(tsp_validation.code, codes::BAD_REQUEST);
        assert_eq!(tsp_validation.comment, "bad did");

        let tsp_last_service =
            RollbackTspError::DisableForward(DisableTspError::LastServiceRefused)
                .to_problem_report();
        assert_eq!(tsp_last_service.code, codes::CONFLICT);
        assert_eq!(
            tsp_last_service.comment,
            "rolling back this TSP mutation would leave the VTA with no advertised services"
        );
    }
}
