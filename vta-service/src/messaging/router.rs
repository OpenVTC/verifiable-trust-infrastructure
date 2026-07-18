//! DIDComm message dispatch for the delivery-layer inbound loop.
//!
//! **D2 P2a cut-over**: this used to build an
//! `affinidi-messaging-didcomm-service` `Router` (type-routed handler table +
//! `MessagePolicy` middleware) wrapped in a `BridgeHandler`. That framework is
//! gone. [`dispatch`] is now a plain `msg.typ` match that calls the same ~50
//! handler functions directly — they are unchanged, taking
//! `(HandlerContext, Message, Extension<T>)` from [`crate::messaging::shim`].
//! The [`crate::server`] inbound loop drives it off
//! [`affinidi_messaging_delivery::MessagingService::subscribe`].
//!
//! The `MessagePolicy` auth gate (`require_encrypted` + verified-sender-or-none)
//! now lives in the inbound loop, which sets `Message::from` to the
//! cryptographically-authenticated sender before calling [`dispatch`] (the
//! `#620` anti-spoof guarantee), so every handler's `auth_from_message` /
//! `ctx.sender_did` sees only a proven sender.

use std::sync::Arc;

use affinidi_messaging_didcomm::Message;
use tokio::sync::RwLock;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::SeedStore;
use crate::messaging::shim::{DIDCommResponse, DIDCommServiceError, HandlerContext, ProblemReport};
#[cfg(feature = "didcomm")]
use crate::messaging::shim::{Extension, ServiceProblemReport};
use crate::server::AppState;
use crate::store::KeyspaceHandle;

#[cfg(feature = "didcomm")]
use super::handlers;

#[cfg(all(feature = "tee", feature = "didcomm"))]
use vta_sdk::protocols::attestation_management;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
use vta_sdk::protocols::did_management;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
use vta_sdk::protocols::protocol_management;
// `provision-integration` is unconditionally enabled via the
// `vta-sdk` feature list in vta-service's Cargo.toml — no cfg gate.
#[cfg(all(feature = "webvh", feature = "didcomm"))]
use vta_sdk::protocols::provision_integration_management;
#[cfg(feature = "didcomm")]
use vta_sdk::protocols::{
    self, acl_management, audit_management, context_management, credential_exchange,
    key_management, seed_management, vta_management,
};

/// Trust-ping protocol identifiers (was the framework's `TRUST_PING_TYPE` /
/// `TRUST_PONG_TYPE`). Re-declared locally now the framework is gone.
#[cfg(feature = "didcomm")]
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
#[cfg(feature = "didcomm")]
const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
/// The high-frequency message-pickup status heartbeat (was the framework's
/// `MESSAGE_PICKUP_STATUS_TYPE`, routed to `ignore_handler`). Dispatched as a
/// silent no-op.
pub(crate) const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// Shared state injected into all DIDComm handlers via `Extension<Arc<VtaState>>`.
#[derive(Clone)]
pub struct VtaState {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    /// Sessions keyspace — mirrored from `AppState` so intrinsic-sender
    /// (DIDComm/TSP) auth can resolve + elevate the caller's canonical
    /// DID-keyed session, exactly as the REST path does.
    pub sessions_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    /// Persistent runtime state for service enable/disable
    /// (`operations::protocol::runtime_state`). Mirrored from `AppState`.
    pub service_state_ks: KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    /// Anti-replay log for sealed-bootstrap `bundle_id`s — required by
    /// the DIDComm provision-integration handler so it can drive the
    /// same shared library function the REST handler does.
    pub sealed_nonces_ks: KeyspaceHandle,
    /// Persisted drain set for the protocol-management feature
    /// (`docs/05-design-notes/didcomm-protocol-management.md`).
    /// Accessible from DIDComm handlers so disable/migrate over
    /// DIDComm transport land in the same drain bookkeeping as
    /// the REST path.
    #[cfg(feature = "webvh")]
    pub drains_ks: KeyspaceHandle,
    /// Per-kind previous-config snapshot store for fail-forward
    /// rollback (spec §3.5a). Mirrored from `AppState` so REST and
    /// DIDComm transport handlers feed the same snapshot.
    #[cfg(feature = "webvh")]
    pub snapshot_ks: KeyspaceHandle,
    /// In-process registry of active + draining mediator listeners.
    #[cfg(feature = "webvh")]
    pub mediator_registry: Arc<crate::messaging::registry::MediatorListenerRegistry>,
    /// Per-mediator TTL sweeper.
    #[cfg(feature = "webvh")]
    pub drain_sweeper: Arc<crate::messaging::drain_sweeper::DrainSweeper>,
    /// Per-webvh-server async mutex registry. Mirrored from
    /// `AppState` so DIDComm-transport handlers serialise the same
    /// daemon-REST auth-cache reads as REST handlers.
    #[cfg(feature = "webvh")]
    pub webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks,
    /// Pluggable telemetry sink — driven by both REST and DIDComm
    /// transport handlers so `mediator report` is consistent
    /// regardless of which transport posted the inbound event.
    pub telemetry: vti_common::telemetry::SharedTelemetrySink,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    /// DIDComm bridge for outbound WebVH server communication.
    pub didcomm_bridge: Arc<DIDCommBridge>,
    /// Secrets resolver — present iff DIDComm is configured. Used
    /// (alongside `signing_vm_id` / `ka_vm_id`) by service-management
    /// rollback over DIDComm transport to assemble a live
    /// `ListenerProver` for re-promotion handshakes.
    #[cfg(feature = "didcomm")]
    pub secrets_resolver: Option<Arc<affinidi_tdk::secrets_resolver::ThreadedSecretsResolver>>,
    /// VM id of the VTA's signing key. Threaded through to the live
    /// prover for service-management ops dispatched over DIDComm.
    #[cfg(feature = "didcomm")]
    pub signing_vm_id: Option<String>,
    /// VM id of the VTA's key-agreement key.
    #[cfg(feature = "didcomm")]
    pub ka_vm_id: Option<String>,
    #[cfg(feature = "tee")]
    pub tee_state: Option<crate::tee::TeeState>,
    /// Send `true` to trigger a soft restart.
    pub restart_tx: tokio::sync::watch::Sender<bool>,
}

// Gated on `webvh`: provision-integration mints WebVH DIDs, so the op (and the
// DIDComm handler/route that drive it, below) only exist in webvh builds —
// matching the REST side (`routes::bootstrap`'s `#[cfg(feature = "webvh")] mod
// provision`). Without this gate the impl had to fill the cfg-gated
// `VtaState::webvh_ks` with a `panic!()` arm in non-webvh builds — a runtime
// landmine inside a `From`. Gating the impl removes it: a non-webvh build
// simply doesn't expose DIDComm provision-integration.
#[cfg(feature = "webvh")]
impl From<&VtaState> for crate::operations::provision_integration::ProvisionIntegrationDeps {
    fn from(state: &VtaState) -> Self {
        Self {
            keys_ks: state.keys_ks.clone(),
            acl_ks: state.acl_ks.clone(),
            audit_ks: state.audit_ks.clone(),
            contexts_ks: state.contexts_ks.clone(),
            did_templates_ks: state.did_templates_ks.clone(),
            imported_ks: state.imported_ks.clone(),
            webvh_ks: state.webvh_ks.clone(),
            sealed_nonces_ks: state.sealed_nonces_ks.clone(),
            seed_store: state.seed_store.clone(),
            config: state.config.clone(),
            did_resolver: state.did_resolver.clone(),
            didcomm_bridge: state.didcomm_bridge.clone(),
            webvh_auth_locks: state.webvh_auth_locks.clone(),
        }
    }
}

/// Derive the DIDComm-transport view of shared state from the canonical
/// [`AppState`].
///
/// `VtaState` is a strict subset of `AppState` — every field is a cheap clone
/// of the corresponding `AppState` field (an `Arc`, a `KeyspaceHandle`, or the
/// `Arc`-backed [`WebvhAuthLocks`]). Building it this way is what guarantees the
/// REST front-end and the DIDComm router share the *same* config `RwLock`,
/// `WebvhAuthLocks`, mediator registry, drain sweeper, and telemetry sink
/// (P1.1): a `PATCH /config` on the REST side is visible to DIDComm handlers,
/// and the per-server webvh auth-cache lock serialises across both transports.
/// Constructing `VtaState` with a freshly-minted webvh auth-lock registry or a
/// freshly-wrapped config lock was a live divergence bug — don't reintroduce
/// it; always derive from the canonical `AppState`.
impl From<&AppState> for VtaState {
    fn from(state: &AppState) -> Self {
        Self {
            keys_ks: state.keys_ks.clone(),
            acl_ks: state.acl_ks.clone(),
            sessions_ks: state.sessions_ks.clone(),
            contexts_ks: state.contexts_ks.clone(),
            did_templates_ks: state.did_templates_ks.clone(),
            audit_ks: state.audit_ks.clone(),
            imported_ks: state.imported_ks.clone(),
            service_state_ks: state.service_state_ks.clone(),
            #[cfg(feature = "webvh")]
            webvh_ks: state.webvh_ks.clone(),
            sealed_nonces_ks: state.sealed_nonces_ks.clone(),
            #[cfg(feature = "webvh")]
            drains_ks: state.drains_ks.clone(),
            #[cfg(feature = "webvh")]
            snapshot_ks: state.snapshot_ks.clone(),
            #[cfg(feature = "webvh")]
            mediator_registry: Arc::clone(&state.mediator_registry),
            #[cfg(feature = "webvh")]
            drain_sweeper: Arc::clone(&state.drain_sweeper),
            #[cfg(feature = "webvh")]
            webvh_auth_locks: state.webvh_auth_locks.clone(),
            telemetry: Arc::clone(&state.telemetry),
            seed_store: state.seed_store.clone(),
            config: Arc::clone(&state.config),
            did_resolver: state.did_resolver.clone(),
            didcomm_bridge: Arc::clone(&state.didcomm_bridge),
            #[cfg(feature = "didcomm")]
            secrets_resolver: state.secrets_resolver.clone(),
            #[cfg(feature = "didcomm")]
            signing_vm_id: state.signing_vm_id.clone(),
            #[cfg(feature = "didcomm")]
            ka_vm_id: state.ka_vm_id.clone(),
            #[cfg(feature = "tee")]
            tee_state: state.tee.as_ref().map(|tc| tc.state.clone()),
            restart_tx: state.restart_tx.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Type-routed dispatch (was the framework `Router` + `BridgeHandler`)
// ---------------------------------------------------------------------------

/// The handler return shape (unchanged from the framework): a reply, no reply,
/// or a handler error the dispatch renders as an `internal-error`
/// problem-report.
#[cfg(feature = "didcomm")]
type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Fold a handler's `Result` into the reply the loop sends. A handler `Err`
/// becomes a threaded `internal-error` problem-report (was the framework's
/// `DefaultErrorHandler::on_error`).
#[cfg(feature = "didcomm")]
fn finish(result: HandlerResult) -> Option<DIDCommResponse> {
    match result {
        Ok(opt) => opt,
        Err(e) => Some(DIDCommResponse::problem_report(
            ProblemReport::internal_error(e.to_string()),
        )),
    }
}

/// Local trust-ping responder (was the framework `trust_ping_handler`). Replies
/// a `trust-ping/2.0/ping-response` on the ping's thread unless the ping didn't
/// request a response or has no authenticated sender to reply to.
#[cfg(feature = "didcomm")]
fn trust_ping_reply(msg: &Message, sender_did: Option<&str>) -> Option<DIDCommResponse> {
    #[derive(serde::Deserialize)]
    struct PingBody {
        #[serde(default = "default_true")]
        response_requested: bool,
    }
    fn default_true() -> bool {
        true
    }
    let body: PingBody = serde_json::from_value(msg.body.clone()).unwrap_or(PingBody {
        response_requested: true,
    });
    if !body.response_requested {
        return None;
    }
    // Only pong an authenticated ping (no reply to a spoofed/anonymous sender).
    sender_did?;
    Some(DIDCommResponse::new(TRUST_PONG_TYPE, serde_json::Value::Null).thid(msg.id.clone()))
}

/// Route one inbound (authenticated-sender-stamped) DIDComm message to its
/// handler, mirroring the framework route list (same URIs, same feature gates).
///
/// `ctx.sender_did` and `msg.from` are the cryptographically-authenticated
/// sender (or `None`); handlers authorize on those, never on the raw wire
/// `from`. The `_` arm is the fallback (`handle_unknown`).
#[cfg(feature = "didcomm")]
pub async fn dispatch(
    msg: Message,
    ctx: HandlerContext,
    vta_state: Arc<VtaState>,
    app_state: AppState,
) -> Option<DIDCommResponse> {
    let t = msg.typ.clone();
    let t = t.as_str();

    // Message-pickup status heartbeat: silent no-op (was `ignore_handler`).
    if t == MESSAGE_PICKUP_STATUS_TYPE {
        return None;
    }
    // Trust-ping (was the built-in `trust_ping_handler`).
    if t == TRUST_PING_TYPE {
        return trust_ping_reply(&msg, ctx.sender_did.as_deref());
    }

    // ── Trust-Tasks envelope (AppState) ──────────────────────────────
    if t == handlers::TRUST_TASK_ENVELOPE_TYPE {
        return finish(handlers::handle_trust_task(ctx, msg, Extension(app_state)).await);
    }

    // ── Key management ───────────────────────────────────────────────
    if t == key_management::CREATE_KEY {
        return finish(handlers::handle_create_key(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::GET_KEY {
        return finish(handlers::handle_get_key(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::LIST_KEYS {
        return finish(handlers::handle_list_keys(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::RENAME_KEY {
        return finish(handlers::handle_rename_key(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::REVOKE_KEY {
        return finish(handlers::handle_revoke_key(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::GET_KEY_SECRET {
        return finish(handlers::handle_get_key_secret(ctx, msg, Extension(vta_state)).await);
    }
    if t == key_management::SIGN_REQUEST {
        return finish(handlers::handle_sign_request(ctx, msg, Extension(vta_state)).await);
    }

    // ── Seed management ──────────────────────────────────────────────
    if t == seed_management::LIST_SEEDS {
        return finish(handlers::handle_list_seeds(ctx, msg, Extension(vta_state)).await);
    }
    if t == seed_management::ROTATE_SEED {
        return finish(handlers::handle_rotate_seed(ctx, msg, Extension(vta_state)).await);
    }

    // ── Context management ───────────────────────────────────────────
    if t == context_management::CREATE_CONTEXT {
        return finish(handlers::handle_create_context(ctx, msg, Extension(vta_state)).await);
    }
    if t == context_management::GET_CONTEXT {
        return finish(handlers::handle_get_context(ctx, msg, Extension(vta_state)).await);
    }
    if t == context_management::LIST_CONTEXTS {
        return finish(handlers::handle_list_contexts(ctx, msg, Extension(vta_state)).await);
    }
    if t == context_management::UPDATE_CONTEXT {
        return finish(handlers::handle_update_context(ctx, msg, Extension(vta_state)).await);
    }
    if t == context_management::UPDATE_CONTEXT_DID {
        return finish(handlers::handle_update_context_did(ctx, msg, Extension(vta_state)).await);
    }
    if t == context_management::PREVIEW_DELETE_CONTEXT {
        return finish(
            handlers::handle_preview_delete_context(ctx, msg, Extension(vta_state)).await,
        );
    }
    if t == context_management::DELETE_CONTEXT {
        return finish(handlers::handle_delete_context(ctx, msg, Extension(vta_state)).await);
    }

    // ── ACL management ───────────────────────────────────────────────
    if t == acl_management::CREATE_ACL {
        return finish(handlers::handle_create_acl(ctx, msg, Extension(vta_state)).await);
    }
    if t == acl_management::GET_ACL {
        return finish(handlers::handle_get_acl(ctx, msg, Extension(vta_state)).await);
    }
    if t == acl_management::LIST_ACL {
        return finish(handlers::handle_list_acl(ctx, msg, Extension(vta_state)).await);
    }
    if t == acl_management::UPDATE_ACL {
        return finish(handlers::handle_update_acl(ctx, msg, Extension(vta_state)).await);
    }
    if t == acl_management::DELETE_ACL {
        return finish(handlers::handle_delete_acl(ctx, msg, Extension(vta_state)).await);
    }
    // Legacy FPN-private `swap-acl` + canonical Trust Task `acl/swap-key/0.1`
    // both route to the same handler (dispatches on the incoming type).
    if t == acl_management::SWAP_ACL || t == acl_management::ACL_SWAP_KEY {
        return finish(handlers::handle_swap_acl(ctx, msg, Extension(vta_state)).await);
    }

    // ── Audit management ─────────────────────────────────────────────
    if t == audit_management::LIST_LOGS {
        return finish(handlers::handle_list_logs(ctx, msg, Extension(vta_state)).await);
    }
    if t == audit_management::GET_RETENTION {
        return finish(handlers::handle_get_retention(ctx, msg, Extension(vta_state)).await);
    }
    if t == audit_management::UPDATE_RETENTION {
        return finish(handlers::handle_update_retention(ctx, msg, Extension(vta_state)).await);
    }

    // ── VTA management ───────────────────────────────────────────────
    if t == vta_management::GET_CONFIG {
        return finish(handlers::handle_get_config(ctx, msg, Extension(vta_state)).await);
    }
    if t == vta_management::UPDATE_CONFIG {
        return finish(handlers::handle_update_config(ctx, msg, Extension(vta_state)).await);
    }
    if t == protocols::PROBLEM_REPORT_TYPE {
        return finish(handlers::handle_problem_report(ctx, msg).await);
    }
    if t == vta_management::RESTART {
        return finish(handlers::handle_restart(ctx, msg, Extension(vta_state)).await);
    }
    if t == protocols::backup_management::EXPORT_BACKUP {
        return finish(handlers::handle_backup_export(ctx, msg, Extension(vta_state)).await);
    }
    if t == protocols::backup_management::IMPORT_BACKUP {
        return finish(handlers::handle_backup_import(ctx, msg, Extension(vta_state)).await);
    }

    // ── Credential exchange (AppState) ───────────────────────────────
    if t == credential_exchange::ISSUE {
        return finish(handlers::handle_credential_issue(ctx, msg, Extension(app_state)).await);
    }
    if t == credential_exchange::QUERY {
        return finish(handlers::handle_credential_query(ctx, msg, Extension(app_state)).await);
    }
    if t == credential_exchange::OFFER {
        return finish(handlers::handle_credential_offer(ctx, msg, Extension(app_state)).await);
    }

    // ── DID WebVH management (webvh) ─────────────────────────────────
    #[cfg(feature = "webvh")]
    {
        if t == did_management::CREATE_DID_WEBVH {
            return finish(handlers::handle_create_did_webvh(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::GET_DID_WEBVH {
            return finish(handlers::handle_get_did_webvh(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::GET_DID_WEBVH_LOG {
            return finish(
                handlers::handle_get_did_webvh_log(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::LIST_DIDS_WEBVH {
            return finish(handlers::handle_list_dids_webvh(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::DELETE_DID_WEBVH {
            return finish(handlers::handle_delete_did_webvh(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::ADD_WEBVH_SERVER {
            return finish(handlers::handle_add_webvh_server(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::LIST_WEBVH_SERVERS {
            return finish(
                handlers::handle_list_webvh_servers(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::LIST_WEBVH_SERVER_DOMAINS {
            return finish(
                handlers::handle_list_webvh_server_domains(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::UPDATE_WEBVH_SERVER {
            return finish(
                handlers::handle_update_webvh_server(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::REMOVE_WEBVH_SERVER {
            return finish(
                handlers::handle_remove_webvh_server(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::UPDATE_DID_WEBVH {
            return finish(handlers::handle_update_did_webvh(ctx, msg, Extension(vta_state)).await);
        }
        if t == did_management::ROTATE_DID_WEBVH_KEYS {
            return finish(
                handlers::handle_rotate_did_webvh_keys(ctx, msg, Extension(vta_state)).await,
            );
        }
        if t == did_management::REGISTER_DID_WITH_SERVER {
            return finish(
                handlers::handle_register_did_with_server(ctx, msg, Extension(vta_state)).await,
            );
        }
    }

    // ── Protocol management over DIDComm (webvh) ─────────────────────
    #[cfg(feature = "webvh")]
    {
        use super::handlers_protocol as hp;
        if t == protocol_management::DISABLE_DIDCOMM {
            return finish(hp::handle_disable_didcomm(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::ENABLE_REST {
            return finish(hp::handle_enable_rest(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::UPDATE_REST {
            return finish(hp::handle_update_rest(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::DISABLE_REST {
            return finish(hp::handle_disable_rest(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::ROLLBACK_REST {
            return finish(hp::handle_rollback_rest(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::ENABLE_TSP {
            return finish(hp::handle_enable_tsp(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::UPDATE_TSP {
            return finish(hp::handle_update_tsp(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::DISABLE_TSP {
            return finish(hp::handle_disable_tsp(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::ROLLBACK_TSP {
            return finish(hp::handle_rollback_tsp(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::UPDATE_DIDCOMM {
            return finish(hp::handle_update_didcomm(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::ROLLBACK_DIDCOMM {
            return finish(hp::handle_rollback_didcomm(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::LIST_SERVICES {
            return finish(hp::handle_list_services(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::LIST_DRAIN {
            return finish(hp::handle_list_drain(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::DRAIN_CANCEL {
            return finish(hp::handle_drain_cancel(ctx, msg, Extension(vta_state)).await);
        }
        if t == protocol_management::MEDIATOR_REPORT {
            return finish(hp::handle_mediator_report(ctx, msg, Extension(vta_state)).await);
        }
    }

    // ── Provision-integration (webvh) ────────────────────────────────
    #[cfg(feature = "webvh")]
    {
        if t == provision_integration_management::CANONICAL_PROVISION_INTEGRATION
            || t == provision_integration_management::CANONICAL_PROVISION_INTEGRATION_0_2
        {
            return finish(
                handlers::handle_provision_integration(ctx, msg, Extension(vta_state)).await,
            );
        }
    }

    // ── Step-up approval (always) ────────────────────────────────────
    if t == handlers::STEP_UP_APPROVE_REQUEST_TYPE
        || t == handlers::STEP_UP_APPROVE_REQUEST_CANONICAL
    {
        return finish(handlers::handle_step_up_approve(ctx, msg, Extension(vta_state)).await);
    }

    // ── TEE attestation (tee) ────────────────────────────────────────
    #[cfg(feature = "tee")]
    {
        if t == attestation_management::GET_TEE_STATUS {
            return finish(handlers::handle_tee_status(ctx, msg, Extension(vta_state)).await);
        }
        if t == attestation_management::REQUEST_ATTESTATION {
            return finish(
                handlers::handle_request_attestation(ctx, msg, Extension(vta_state)).await,
            );
        }
    }

    // ── Discovery (no auth) ──────────────────────────────────────────
    if t == protocols::discovery::DISCOVER_CAPABILITIES {
        return finish(
            handlers::handle_discover_capabilities(ctx, msg, Extension(vta_state)).await,
        );
    }

    // ── Fallback ─────────────────────────────────────────────────────
    finish(handlers::handle_unknown(ctx, msg).await)
}
