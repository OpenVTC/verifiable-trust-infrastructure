//! Services slice trust-task handlers — `vta/services/*`.
//!
//! The transports the agent advertises in its own did:webvh document. Every
//! mutation here edits that document and republishes the signed log, so none of
//! them is a runtime flag flip: **the log entry is the change**.
//!
//! ## One task per verb, not per transport
//!
//! `service` names the transport and `config` carries its settings, so these
//! eight handlers cover what twenty `/services/*` REST routes did. The fan-out
//! onto the per-transport operations happens here rather than on the wire,
//! which is what keeps a fifth transport to a config variant instead of four
//! new specs.
//!
//! The operations are untouched — `operations::protocol::*` already implements
//! each transport, and this module is the parameterised door onto them.
//!
//! ## The state shape is mapped, not forwarded
//!
//! `vta_sdk::protocol::services::ServiceState` is an internally-tagged enum
//! whose members serialize snake_case (`mediator_did`); the published schema is
//! a flat object with camelCase members. They are close enough to look
//! interchangeable and are not, so every response here is built explicitly
//! against the generated type. Forwarding the SDK value would put
//! `mediator_did` on the wire under a schema that says `mediatorDid`, and the
//! dispatch spine's `validate_payload` would reject it on arrival.

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, success_response,
};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vta::services as spec;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::protocol::list::ListServicesError;
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::server::AppState;

use vta_sdk::protocol::services::ServiceState as SdkState;

/// The DID resolver, or a refusal.
///
/// Every mutation needs it: publishing a log entry means resolving the agent's
/// own DID first, and an agent that cannot do that must not claim it changed
/// what the world can see.
fn resolver(state: &AppState) -> Result<affinidi_did_resolver_cache_sdk::DIDCacheClient, AppError> {
    state
        .did_resolver
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))
}

/// Map one SDK state record onto the published shape.
///
/// `drains_until` has no SDK counterpart on the state record — a drain is
/// reported by `vta/services/drain/list`, which reads a different store — so it
/// is left absent here rather than guessed.
fn state(s: &SdkState) -> spec::list::v1_0::ServiceState {
    use spec::list::v1_0::{ServiceKind as K, ServiceState as Out};
    let (kind, enabled, mediator_did, url) = match s {
        SdkState::Tsp {
            enabled,
            mediator_did,
        } => (K::Tsp, *enabled, mediator_did.clone(), None),
        SdkState::Rest { enabled, url } => (K::Rest, *enabled, None, url.clone()),
        SdkState::Didcomm {
            enabled,
            mediator_did,
            ..
        } => (K::Didcomm, *enabled, mediator_did.clone(), None),
        SdkState::Webauthn { enabled, url } => (K::Webauthn, *enabled, None, url.clone()),
    };
    Out {
        kind,
        enabled,
        mediator_did,
        url,
        drains_until: None,
        ext: None,
    }
}

fn kind_of(s: &SdkState) -> spec::list::v1_0::ServiceKind {
    state(s).kind
}

/// Classify a listing failure the way the REST route does.
///
/// Mirrored rather than collapsed to `Internal`: an agent whose DID is not yet
/// configured is a conflict the operator can fix, and telling them so is the
/// difference between "run `vta setup`" and "something broke". A refusal is
/// forbidden, not internal, for the same reason.
fn list_error(e: ListServicesError) -> AppError {
    match e {
        ListServicesError::Auth(msg) => AppError::Forbidden(msg),
        ListServicesError::VtaDidNotConfigured => {
            AppError::Conflict("VTA DID is not configured — run `vta setup` first".into())
        }
        other => AppError::Internal(other.to_string()),
    }
}

// ── list / get ──────────────────────────────────────────────────────

pub(super) async fn handle_list(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: spec::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // The operation enforces super-admin itself; letting it do so keeps one
    // authorization decision rather than two that can drift apart.
    match crate::operations::protocol::list::list_services(&state_.config, &state_.webvh_ks, auth)
        .await
    {
        Ok(body) => success_response(
            &doc,
            spec::list::v1_0::Response {
                services: body.services.iter().map(state).collect(),
                ext: None,
            },
        ),
        Err(e) => app_error_to_reject(&doc, list_error(e)),
    }
}

pub(super) async fn handle_get(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::get::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match crate::operations::protocol::list::list_services(&state_.config, &state_.webvh_ks, auth)
        .await
    {
        Ok(body) => {
            // `get` narrows `list` rather than having its own operation: the
            // agent holds one state record per transport, so querying twice
            // could disagree with itself.
            let want = match req.service {
                spec::get::v1_0::ServiceKind::Didcomm => spec::list::v1_0::ServiceKind::Didcomm,
                spec::get::v1_0::ServiceKind::Rest => spec::list::v1_0::ServiceKind::Rest,
                spec::get::v1_0::ServiceKind::Tsp => spec::list::v1_0::ServiceKind::Tsp,
                spec::get::v1_0::ServiceKind::Webauthn => spec::list::v1_0::ServiceKind::Webauthn,
            };
            match body.services.iter().find(|s| kind_of(s) == want) {
                Some(found) => success_response(
                    &doc,
                    spec::get::v1_0::Response {
                        state: serde_json::from_value(
                            serde_json::to_value(state(found)).unwrap_or(Value::Null),
                        )
                        .expect("the two generated ServiceState shapes are identical"),
                        ext: None,
                    },
                ),
                // Absent means never configured — distinct from configured and
                // disabled, which comes back with `enabled: false`. Answering
                // an empty success here would erase that distinction, which is
                // the only reason to call `get` over `list`.
                None => app_error_to_reject(
                    &doc,
                    crate::error::AppError::NotFound(format!(
                        "no {:?} transport is configured on this agent",
                        req.service
                    )),
                ),
            }
        }
        Err(e) => app_error_to_reject(&doc, list_error(e)),
    }
}

// ── the mutating verbs ──────────────────────────────────────────────
//
// Each fans out on `service`. The three uniform transports take the same
// `(deps, auth, params, ctx, channel)` shape; `didcomm` differs because it
// carries a mediator handshake and a drain, which is the whole reason the
// spec's `config` is a discriminated union rather than one flat object.

use crate::operations::protocol::disable_didcomm::{
    DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::disable_rest::{DisableRestParams, disable_rest};
use crate::operations::protocol::disable_tsp::{DisableTspParams, disable_tsp};
use crate::operations::protocol::disable_webauthn::{DisableWebauthnParams, disable_webauthn};
use crate::operations::protocol::drain_cancel::{DrainCancelParams, drain_cancel};
use crate::operations::protocol::enable_rest::{EnableRestParams, enable_rest};
use crate::operations::protocol::enable_tsp::{EnableTspParams, enable_tsp};
use crate::operations::protocol::enable_webauthn::{EnableWebauthnParams, enable_webauthn};
use crate::operations::protocol::list_drain::list_drain;
use crate::operations::protocol::rollback_rest::{RollbackRestParams, rollback_rest};
use crate::operations::protocol::rollback_tsp::{RollbackTspParams, rollback_tsp};
use crate::operations::protocol::rollback_webauthn::{RollbackWebauthnParams, rollback_webauthn};
use crate::operations::protocol::update_rest::{UpdateRestParams, update_rest};
use crate::operations::protocol::update_tsp::{UpdateTspParams, update_tsp};
use crate::operations::protocol::update_webauthn::{UpdateWebauthnParams, update_webauthn};

/// Which transport this task arrived over, for the drain guard.
///
/// The dispatch spine records confidentiality, not binding: DIDComm and TSP are
/// both `EndToEnd`, and it cannot tell them apart. So `EndToEnd` maps to
/// `Didcomm` here, which **over-applies** the 1-hour drain floor to a
/// TSP-carried disable that does not strictly need it.
///
/// That asymmetry is deliberate. Under-applying the floor tears down the
/// mediator a request arrived through and discards the reply to the very task
/// asking for it; over-applying only delays a teardown the operator can repeat.
/// A bounded delay is the cheaper mistake, so the ambiguous case takes it.
fn arrival_transport() -> DisableTransport {
    match super::transport::current() {
        super::transport::TransportConfidentiality::EndToEnd => DisableTransport::Didcomm,
        super::transport::TransportConfidentiality::HopByHop => DisableTransport::Rest,
    }
}

/// `config.url`, or a validation refusal naming the member that is missing.
fn need_url(url: Option<String>) -> Result<String, AppError> {
    url.ok_or_else(|| AppError::Conflict("this service needs `config.url`; none was sent".into()))
}

fn need_mediator(mediator_did: Option<String>) -> Result<String, AppError> {
    mediator_did.ok_or_else(|| {
        AppError::Conflict("this service needs `config.mediatorDid`; none was sent".into())
    })
}

/// The shared success shape, stamped with the instant the change took effect.
///
/// The operations return the log-entry id but not the time; the REST routes
/// stamp it at the boundary and so does this, so both surfaces agree.
fn mutation(
    log_entry_version_id: String,
    vta_did: String,
    serverless: bool,
    drain_until: Option<chrono::DateTime<chrono::Utc>>,
    draining_mediator: Option<String>,
) -> Result<spec::enable::v1_0::ServiceMutationResult, AppError> {
    Ok(spec::enable::v1_0::ServiceMutationResult {
        log_entry_version_id: log_entry_version_id
            .try_into()
            .map_err(|_| AppError::Internal("operation returned an empty log entry id".into()))?,
        effective_at: chrono::Utc::now(),
        drain_until,
        draining_mediator,
        vta_did: (!vta_did.is_empty()).then_some(vta_did),
        serverless,
        ext: None,
    })
}

/// Re-type an identically-shaped generated value for a sibling family.
///
/// `enable`, `update` and `disable` each get their own `ServiceMutationResult`
/// from codegen: same members, distinct types. Rather than hand-copy the
/// members three times — and drift when one gains a field — go through the wire
/// form, which is the representation all of them agree on by construction.
fn retype<T: serde::de::DeserializeOwned>(v: impl serde::Serialize) -> Result<T, AppError> {
    serde_json::to_value(v)
        .and_then(serde_json::from_value)
        .map_err(|e| AppError::Internal(format!("service result re-type: {e}")))
}

/// Await a service operation, boxing its future.
///
/// Not a style choice. These handlers fan out to four operations, each with a
/// sizeable future of its own, and the dispatch spine awaits the handler inside
/// a match that already carries every other task's state machine. Inlining them
/// grew that frame past the default 8 MiB thread stack and aborted an unrelated
/// mock_vta test with a stack overflow — which reads as infinite recursion and
/// is not. Boxing moves each operation's state to the heap and keeps the
/// enclosing future flat.
macro_rules! op {
    ($doc:expr, $call:expr) => {
        match Box::pin($call).await {
            Ok(r) => r,
            Err(e) => return app_error_to_reject($doc, AppError::Conflict(e.to_string())),
        }
    };
}

pub(super) async fn handle_enable(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: spec::enable::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let resolver = match resolver(state_) {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let deps = ServiceOpDeps::from_app_state(state_, &resolver);
    use spec::enable::v1_0::ServiceKind as K;

    let result = match req.service {
        K::Rest => {
            let url = match need_url(req.config.url.clone().map(String::from)) {
                Ok(u) => u,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let r = op!(
                &doc,
                enable_rest(
                    &deps,
                    auth,
                    EnableRestParams { url },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Webauthn => {
            let url = match need_url(req.config.url.clone().map(String::from)) {
                Ok(u) => u,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let r = op!(
                &doc,
                enable_webauthn(
                    &deps,
                    auth,
                    EnableWebauthnParams { url },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Tsp => {
            let mediator_did =
                match need_mediator(req.config.mediator_did.clone().map(String::from)) {
                    Ok(m) => m,
                    Err(e) => return app_error_to_reject(&doc, e),
                };
            let r = op!(
                &doc,
                enable_tsp(
                    &deps,
                    auth,
                    EnableTspParams { mediator_did },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Didcomm => {
            // `AlwaysOkProver` for the same reason the REST enable route uses
            // it: the handshake's steps 2-5 need a running `DIDCommService`,
            // and at first-enable there is not one yet. The steady-state case
            // — where DIDComm is already up — goes through `update`, which
            // builds a live prover.
            let mediator_did =
                match need_mediator(req.config.mediator_did.clone().map(String::from)) {
                    Ok(m) => m,
                    Err(e) => return app_error_to_reject(&doc, e),
                };
            let params = crate::operations::protocol::enable_didcomm::EnableDidcommParams {
                mediator_did,
                force: req.config.force.unwrap_or(false),
                handshake_timeout: std::time::Duration::from_secs(
                    req.config.handshake_timeout_secs.map_or(10, u64::from),
                ),
            };
            let prover = crate::messaging::handshake::AlwaysOkProver;
            let r = op!(
                &doc,
                crate::operations::protocol::enable_didcomm::enable_didcomm(
                    &deps,
                    &prover,
                    auth,
                    params,
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
    };
    match result {
        Ok(result) => success_response(&doc, spec::enable::v1_0::Response { result, ext: None }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

pub(super) async fn handle_update(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: spec::update::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let resolver = match resolver(state_) {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let deps = ServiceOpDeps::from_app_state(state_, &resolver);
    use spec::update::v1_0::ServiceKind as K;

    let result = match req.service {
        K::Rest => {
            let url = match need_url(req.config.url.clone().map(String::from)) {
                Ok(u) => u,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let r = op!(
                &doc,
                update_rest(
                    &deps,
                    auth,
                    UpdateRestParams { url },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Webauthn => {
            let url = match need_url(req.config.url.clone().map(String::from)) {
                Ok(u) => u,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let r = op!(
                &doc,
                update_webauthn(
                    &deps,
                    auth,
                    UpdateWebauthnParams { url },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Tsp => {
            let mediator_did =
                match need_mediator(req.config.mediator_did.clone().map(String::from)) {
                    Ok(m) => m,
                    Err(e) => return app_error_to_reject(&doc, e),
                };
            let r = op!(
                &doc,
                update_tsp(
                    &deps,
                    auth,
                    UpdateTspParams { mediator_did },
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Didcomm => {
            // Replacing the mediator drains the old one, so this carries the
            // same arrival-transport guard as `disable`: swapping the mediator
            // a request arrived through must not cut its reply.
            let mediator_did =
                match need_mediator(req.config.mediator_did.clone().map(String::from)) {
                    Ok(m) => m,
                    Err(e) => return app_error_to_reject(&doc, e),
                };
            let prover = crate::messaging::handshake::AlwaysOkProver;
            let params = crate::operations::protocol::update_didcomm::UpdateDidcommParams {
                new_mediator_did: mediator_did,
                drain_ttl: crate::operations::protocol::disable_didcomm::MIN_DRAIN_TTL_OVER_DIDCOMM,
                force: req.config.force.unwrap_or(false),
                handshake_timeout: std::time::Duration::from_secs(
                    req.config.handshake_timeout_secs.map_or(10, u64::from),
                ),
                audit_kind: crate::operations::protocol::update_didcomm::MigrateAuditKind::Forward,
                transport: arrival_transport(),
            };
            let r = op!(
                &doc,
                crate::operations::protocol::update_didcomm::update_didcomm(
                    &deps,
                    &prover,
                    auth,
                    params,
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(
                r.new_version_id,
                r.vta_did,
                r.serverless,
                Some(r.drains_until),
                Some(r.prior_mediator_did),
            )
        }
    };
    match result {
        Ok(result) => match retype(result) {
            Ok(result) => {
                success_response(&doc, spec::update::v1_0::Response { result, ext: None })
            }
            Err(e) => app_error_to_reject(&doc, e),
        },
        Err(e) => app_error_to_reject(&doc, e),
    }
}

pub(super) async fn handle_disable(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: spec::disable::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let resolver = match resolver(state_) {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let deps = ServiceOpDeps::from_app_state(state_, &resolver);
    use spec::disable::v1_0::ServiceKind as K;

    let result = match req.service {
        K::Rest => {
            let r = op!(
                &doc,
                disable_rest(
                    &deps,
                    auth,
                    DisableRestParams,
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Webauthn => {
            let r = op!(
                &doc,
                disable_webauthn(
                    &deps,
                    auth,
                    DisableWebauthnParams {},
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Tsp => {
            let r = op!(
                &doc,
                disable_tsp(
                    &deps,
                    auth,
                    DisableTspParams,
                    OpContext::Direct,
                    TRANSPORT_TRUST_TASK
                )
            );
            mutation(r.new_version_id, r.vta_did, r.serverless, None, None)
        }
        K::Didcomm => {
            // `drainTtlSecs` is a REQUEST, not an instruction — the operation
            // raises it to the 1h floor when `transport` says the task arrived
            // end-to-end. The spec says so, and the result's `drainUntil` is
            // what a caller must read to learn what actually happened.
            let params = DisableDidcommParams {
                drain_ttl: std::time::Duration::from_secs(req.drain_ttl_secs.unwrap_or(0)),
                transport: arrival_transport(),
            };
            let r = op!(
                &doc,
                disable_didcomm(&deps, auth, params, OpContext::Direct, TRANSPORT_TRUST_TASK)
            );
            let draining = r.drains_until.map(|_| r.prior_mediator_did.clone());
            mutation(
                r.new_version_id,
                r.vta_did,
                r.serverless,
                r.drains_until,
                draining,
            )
        }
    };
    match result {
        Ok(result) => match retype(result) {
            Ok(result) => {
                success_response(&doc, spec::disable::v1_0::Response { result, ext: None })
            }
            Err(e) => app_error_to_reject(&doc, e),
        },
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Map a forward-op rollback kind onto the published one.
///
/// Each transport's rollback module declares its own `RollbackKind` with the
/// same four variants, so this takes the enum path rather than one type. They
/// are parallel by convention, not by a shared definition, and a macro that
/// names the variants keeps a divergence a compile error rather than a silent
/// mismatch.
macro_rules! rollback_kind {
    ($m:ident, $k:expr) => {{
        use crate::operations::protocol::$m::RollbackKind as K;
        use spec::rollback::v1_0::RollbackResultKind as Out;
        match $k {
            K::Disabled => Out::Disabled,
            K::Enabled => Out::Enabled,
            K::Updated => Out::Updated,
            K::NoOp => Out::NoOp,
        }
    }};
}

/// Build the rollback result.
///
/// `logEntryVersionId` is optional here and required on `ServiceMutationResult`,
/// which is the whole reason rollback has its own shape: when the previous
/// state already equals the current one nothing is written, and `kind: noOp`
/// says so. That is a **success** — the requested state holds — so reporting it
/// as a failure would be wrong, and inventing a log entry id would be worse.
fn rollback_result(
    kind: spec::rollback::v1_0::RollbackResultKind,
    new_version_id: Option<String>,
    vta_did: String,
    serverless: bool,
    draining_mediator: Option<String>,
) -> spec::rollback::v1_0::RollbackResult {
    let wrote_an_entry = new_version_id.is_some();
    spec::rollback::v1_0::RollbackResult {
        kind,
        log_entry_version_id: new_version_id,
        effective_at: wrote_an_entry.then(chrono::Utc::now),
        drain_until: None,
        draining_mediator,
        vta_did: (!vta_did.is_empty()).then_some(vta_did),
        serverless,
        ext: None,
    }
}

pub(super) async fn handle_rollback(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: spec::rollback::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let resolver = match resolver(state_) {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let deps = ServiceOpDeps::from_app_state(state_, &resolver);
    use spec::rollback::v1_0::ServiceKind as K;

    let result = match req.service {
        K::Rest => {
            let r = op!(
                &doc,
                rollback_rest(&deps, auth, RollbackRestParams, TRANSPORT_TRUST_TASK)
            );
            rollback_result(
                rollback_kind!(rollback_rest, r.kind),
                r.new_version_id,
                r.vta_did,
                r.serverless,
                None,
            )
        }
        K::Webauthn => {
            let r = op!(
                &doc,
                rollback_webauthn(&deps, auth, RollbackWebauthnParams, TRANSPORT_TRUST_TASK)
            );
            rollback_result(
                rollback_kind!(rollback_webauthn, r.kind),
                r.new_version_id,
                r.vta_did,
                r.serverless,
                None,
            )
        }
        K::Tsp => {
            let r = op!(
                &doc,
                rollback_tsp(&deps, auth, RollbackTspParams, TRANSPORT_TRUST_TASK)
            );
            rollback_result(
                rollback_kind!(rollback_tsp, r.kind),
                r.new_version_id,
                r.vta_did,
                r.serverless,
                None,
            )
        }
        K::Didcomm => {
            // Rolling DIDComm back can leave the superseded mediator draining,
            // so it takes the same arrival guard as disable.
            let params = crate::operations::protocol::rollback_didcomm::RollbackDidcommParams {
                drain_ttl: crate::operations::protocol::disable_didcomm::MIN_DRAIN_TTL_OVER_DIDCOMM,
                transport: arrival_transport(),
            };
            // Rolling back re-runs the forward op, so it needs a prover for
            // the same reason enable does — and `AlwaysOkProver` for the same
            // reason: the restored mediator's handshake cannot depend on a
            // DIDComm service that the rollback may itself be turning off.
            let prover = crate::messaging::handshake::AlwaysOkProver;
            let r = op!(
                &doc,
                crate::operations::protocol::rollback_didcomm::rollback_didcomm(
                    &deps,
                    &prover,
                    auth,
                    params,
                    TRANSPORT_TRUST_TASK
                )
            );
            let draining = r.draining_mediator.clone();
            rollback_result(
                rollback_kind!(rollback_didcomm, r.kind),
                r.new_version_id,
                r.vta_did,
                r.serverless,
                draining,
            )
        }
    };
    success_response(&doc, spec::rollback::v1_0::Response { result, ext: None })
}

// ── drain ───────────────────────────────────────────────────────────

pub(super) async fn handle_drain_list(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let _req: spec::drain::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match list_drain(&state_.config, &state_.drains_ks, auth).await {
        Ok(body) => {
            let entries = body
                .entries
                .into_iter()
                .map(|e| {
                    Ok(spec::drain::list::v1_0::DrainEntry {
                        mediator_did: e.mediator_did.try_into().map_err(|_| {
                            AppError::Internal("drain entry has an empty mediator did".into())
                        })?,
                        endpoint: e.endpoint,
                        drains_until: e.drains_until.parse().map_err(|_| {
                            AppError::Internal("drain entry has an unparseable deadline".into())
                        })?,
                        ext: None,
                    })
                })
                .collect::<Result<Vec<_>, AppError>>();
            match entries {
                Ok(entries) => success_response(
                    &doc,
                    spec::drain::list::v1_0::Response { entries, ext: None },
                ),
                Err(e) => app_error_to_reject(&doc, e),
            }
        }
        Err(e) => app_error_to_reject(&doc, AppError::Conflict(e.to_string())),
    }
}

pub(super) async fn handle_drain_cancel(
    state_: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: spec::drain::cancel::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Destructive: whatever is still in flight through that mediator is lost,
    // which is exactly what the drain window existed to prevent. The operation
    // refuses when the mediator is the active one, so an operator cannot strand
    // the route the agent depends on by hand.
    let params = DrainCancelParams {
        mediator_did: req.mediator_did.to_string(),
    };
    match drain_cancel(
        &state_.config,
        &state_.drains_ks,
        &state_.mediator_registry,
        &state_.telemetry,
        auth,
        params,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        // `mediatorDid` is a plain String in this family — no newtype to
        // fall through, so there is nothing to validate here beyond what
        // the operation already guaranteed.
        Ok(r) => success_response(
            &doc,
            spec::drain::cancel::v1_0::Response {
                mediator_did: r.mediator_did,
                ext: None,
            },
        ),
        Err(e) => app_error_to_reject(&doc, AppError::Conflict(e.to_string())),
    }
}
