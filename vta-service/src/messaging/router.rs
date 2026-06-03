//! DIDComm message router built on `affinidi-messaging-didcomm-service`.
//!
//! Replaces the manual `dispatch_message()` match statement with a typed
//! Router that maps message types to handler functions. Shared state is
//! injected via `Extension<Arc<VtaState>>`.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, MESSAGE_PICKUP_STATUS_TYPE, MessagePolicy, RequestLogging, Router,
    TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use tokio::sync::RwLock;
use tracing::debug;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::SeedStore;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

use super::handlers;

#[cfg(feature = "tee")]
use vta_sdk::protocols::attestation_management;
#[cfg(feature = "webvh")]
use vta_sdk::protocols::did_management;
#[cfg(feature = "webvh")]
use vta_sdk::protocols::protocol_management;
// `provision-integration` is unconditionally enabled via the
// `vta-sdk` feature list in vta-service's Cargo.toml — no cfg gate.
use vta_sdk::protocols::provision_integration_management;
use vta_sdk::protocols::{
    self, acl_management, audit_management, context_management, credential_exchange,
    key_management, seed_management, vta_management,
};

/// Shared state injected into all DIDComm handlers via `Extension<Arc<VtaState>>`.
#[derive(Clone)]
pub struct VtaState {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
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

impl From<&VtaState> for crate::operations::provision_integration::ProvisionIntegrationDeps {
    fn from(state: &VtaState) -> Self {
        Self {
            keys_ks: state.keys_ks.clone(),
            acl_ks: state.acl_ks.clone(),
            audit_ks: state.audit_ks.clone(),
            contexts_ks: state.contexts_ks.clone(),
            did_templates_ks: state.did_templates_ks.clone(),
            imported_ks: state.imported_ks.clone(),
            #[cfg(feature = "webvh")]
            webvh_ks: state.webvh_ks.clone(),
            #[cfg(not(feature = "webvh"))]
            webvh_ks: panic!(
                "provision-integration requires the webvh feature; rebuild vta-service with --features webvh"
            ),
            sealed_nonces_ks: state.sealed_nonces_ks.clone(),
            seed_store: state.seed_store.clone(),
            config: state.config.clone(),
            did_resolver: state.did_resolver.clone(),
            didcomm_bridge: state.didcomm_bridge.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeHandler — wraps the Router to intercept outbound-response routing
// ---------------------------------------------------------------------------

/// Handler wrapper that bridges the DIDComm listener's ATM to the
/// outbound [`DIDCommBridge`].
///
/// On every inbound message this handler:
/// 1. Captures the listener's ATM/profile so the bridge can reuse the
///    same mediator connection for outbound sends.
/// 2. Checks if the message completes a pending outbound request
///    (via [`DIDCommBridge::try_complete`]). If so, the message is
///    consumed and not dispatched to the inner Router.
/// 3. Otherwise delegates to the inner Router for normal handler dispatch.
pub struct BridgeHandler {
    inner: Router,
    bridge: Arc<DIDCommBridge>,
}

#[async_trait::async_trait]
impl affinidi_messaging_didcomm_service::DIDCommHandler for BridgeHandler {
    async fn handle(
        &self,
        ctx: affinidi_messaging_didcomm_service::HandlerContext,
        message: affinidi_messaging_didcomm::Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
    ) -> Result<Option<affinidi_messaging_didcomm_service::DIDCommResponse>, DIDCommServiceError>
    {
        // Route responses to pending outbound requests before normal dispatch.
        if self.bridge.try_complete(&message) {
            return Ok(None);
        }

        // Log unmatched responses (likely stale messages from a previous session)
        if message.thid.is_some() {
            debug!(
                msg_type = %message.typ,
                thid = message.thid.as_deref().unwrap_or(""),
                from = message.from.as_deref().unwrap_or("unknown"),
                "unmatched response — no pending request for thread (stale message)"
            );
        }

        self.inner.handle(ctx, message, meta).await
    }
}

/// Build the DIDComm message handler with all VTA protocol handlers.
///
/// Returns a [`BridgeHandler`] that wraps the Router and integrates
/// outbound request-response routing via the shared [`DIDCommBridge`].
pub fn build_handler(
    state: Arc<VtaState>,
    app_state: AppState,
    bridge: Arc<DIDCommBridge>,
) -> Result<BridgeHandler, DIDCommServiceError> {
    let mut router = Router::new()
        .extension(state)
        // Full REST `AppState`, injected so the generic trust-task
        // handler can drive the shared `dispatch_trust_task_core`
        // (which needs keyspaces not mirrored onto `VtaState`).
        .extension(app_state)
        // Built-in protocol handlers
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        // Trust-Tasks: one binding envelope type carries every slice's
        // `TrustTask<P>` in its body; the handler dispatches on the
        // inner envelope's own `type` via the shared REST dispatcher.
        .route(
            handlers::TRUST_TASK_ENVELOPE_TYPE,
            handler_fn(handlers::handle_trust_task),
        )?
        // Key management
        .route(
            key_management::CREATE_KEY,
            handler_fn(handlers::handle_create_key),
        )?
        .route(
            key_management::GET_KEY,
            handler_fn(handlers::handle_get_key),
        )?
        .route(
            key_management::LIST_KEYS,
            handler_fn(handlers::handle_list_keys),
        )?
        .route(
            key_management::RENAME_KEY,
            handler_fn(handlers::handle_rename_key),
        )?
        .route(
            key_management::REVOKE_KEY,
            handler_fn(handlers::handle_revoke_key),
        )?
        .route(
            key_management::GET_KEY_SECRET,
            handler_fn(handlers::handle_get_key_secret),
        )?
        .route(
            key_management::SIGN_REQUEST,
            handler_fn(handlers::handle_sign_request),
        )?
        // Seed management
        .route(
            seed_management::LIST_SEEDS,
            handler_fn(handlers::handle_list_seeds),
        )?
        .route(
            seed_management::ROTATE_SEED,
            handler_fn(handlers::handle_rotate_seed),
        )?
        // Context management
        .route(
            context_management::CREATE_CONTEXT,
            handler_fn(handlers::handle_create_context),
        )?
        .route(
            context_management::GET_CONTEXT,
            handler_fn(handlers::handle_get_context),
        )?
        .route(
            context_management::LIST_CONTEXTS,
            handler_fn(handlers::handle_list_contexts),
        )?
        .route(
            context_management::UPDATE_CONTEXT,
            handler_fn(handlers::handle_update_context),
        )?
        .route(
            context_management::UPDATE_CONTEXT_DID,
            handler_fn(handlers::handle_update_context_did),
        )?
        .route(
            context_management::PREVIEW_DELETE_CONTEXT,
            handler_fn(handlers::handle_preview_delete_context),
        )?
        .route(
            context_management::DELETE_CONTEXT,
            handler_fn(handlers::handle_delete_context),
        )?
        // ACL management
        .route(
            acl_management::CREATE_ACL,
            handler_fn(handlers::handle_create_acl),
        )?
        .route(
            acl_management::GET_ACL,
            handler_fn(handlers::handle_get_acl),
        )?
        .route(
            acl_management::LIST_ACL,
            handler_fn(handlers::handle_list_acl),
        )?
        .route(
            acl_management::UPDATE_ACL,
            handler_fn(handlers::handle_update_acl),
        )?
        .route(
            acl_management::DELETE_ACL,
            handler_fn(handlers::handle_delete_acl),
        )?
        .route(
            acl_management::SWAP_ACL,
            handler_fn(handlers::handle_swap_acl),
        )?
        // Canonical Trust Task URI for the same operation — dual-registered
        // during the deprecation window. Handler dispatches on incoming type.
        .route(
            acl_management::ACL_SWAP_KEY,
            handler_fn(handlers::handle_swap_acl),
        )?
        // Audit management
        .route(
            audit_management::LIST_LOGS,
            handler_fn(handlers::handle_list_logs),
        )?
        .route(
            audit_management::GET_RETENTION,
            handler_fn(handlers::handle_get_retention),
        )?
        .route(
            audit_management::UPDATE_RETENTION,
            handler_fn(handlers::handle_update_retention),
        )?
        // VTA management
        .route(
            vta_management::GET_CONFIG,
            handler_fn(handlers::handle_get_config),
        )?
        .route(
            vta_management::UPDATE_CONFIG,
            handler_fn(handlers::handle_update_config),
        )?
        // Problem reports
        .route(
            protocols::PROBLEM_REPORT_TYPE,
            handler_fn(handlers::handle_problem_report),
        )?
        // VTA management — restart
        .route(
            vta_management::RESTART,
            handler_fn(handlers::handle_restart),
        )?
        // Backup management
        .route(
            protocols::backup_management::EXPORT_BACKUP,
            handler_fn(handlers::handle_backup_export),
        )?
        .route(
            protocols::backup_management::IMPORT_BACKUP,
            handler_fn(handlers::handle_backup_import),
        )?
        // Credential exchange — holder-side receive of an issued credential
        // (spec §6 / task 3.3). Uses `AppState` for the credential vault.
        .route(
            credential_exchange::ISSUE,
            handler_fn(handlers::handle_credential_issue),
        )?;

    // WebVH handlers (feature-gated)
    #[cfg(feature = "webvh")]
    {
        router = router
            .route(
                did_management::CREATE_DID_WEBVH,
                handler_fn(handlers::handle_create_did_webvh),
            )?
            .route(
                did_management::GET_DID_WEBVH,
                handler_fn(handlers::handle_get_did_webvh),
            )?
            .route(
                did_management::GET_DID_WEBVH_LOG,
                handler_fn(handlers::handle_get_did_webvh_log),
            )?
            .route(
                did_management::LIST_DIDS_WEBVH,
                handler_fn(handlers::handle_list_dids_webvh),
            )?
            .route(
                did_management::DELETE_DID_WEBVH,
                handler_fn(handlers::handle_delete_did_webvh),
            )?
            .route(
                did_management::ADD_WEBVH_SERVER,
                handler_fn(handlers::handle_add_webvh_server),
            )?
            .route(
                did_management::LIST_WEBVH_SERVERS,
                handler_fn(handlers::handle_list_webvh_servers),
            )?
            .route(
                did_management::LIST_WEBVH_SERVER_DOMAINS,
                handler_fn(handlers::handle_list_webvh_server_domains),
            )?
            .route(
                did_management::UPDATE_WEBVH_SERVER,
                handler_fn(handlers::handle_update_webvh_server),
            )?
            .route(
                did_management::REMOVE_WEBVH_SERVER,
                handler_fn(handlers::handle_remove_webvh_server),
            )?
            .route(
                did_management::UPDATE_DID_WEBVH,
                handler_fn(handlers::handle_update_did_webvh),
            )?
            .route(
                did_management::ROTATE_DID_WEBVH_KEYS,
                handler_fn(handlers::handle_rotate_did_webvh_keys),
            )?
            .route(
                did_management::REGISTER_DID_WITH_SERVER,
                handler_fn(handlers::handle_register_did_with_server),
            )?;

        // Protocol management over DIDComm. `enable` is REST-only
        // by nature so it has no DIDComm route; the rest go through
        // the same operation functions as the REST handlers.
        // Spec: docs/05-design-notes/didcomm-protocol-management.md.
        router = router
            .route(
                protocol_management::DISABLE_DIDCOMM,
                handler_fn(super::handlers_protocol::handle_disable_didcomm),
            )?
            .route(
                protocol_management::ENABLE_REST,
                handler_fn(super::handlers_protocol::handle_enable_rest),
            )?
            .route(
                protocol_management::UPDATE_REST,
                handler_fn(super::handlers_protocol::handle_update_rest),
            )?
            .route(
                protocol_management::DISABLE_REST,
                handler_fn(super::handlers_protocol::handle_disable_rest),
            )?
            .route(
                protocol_management::ROLLBACK_REST,
                handler_fn(super::handlers_protocol::handle_rollback_rest),
            )?
            .route(
                protocol_management::UPDATE_DIDCOMM,
                handler_fn(super::handlers_protocol::handle_update_didcomm),
            )?
            .route(
                protocol_management::ROLLBACK_DIDCOMM,
                handler_fn(super::handlers_protocol::handle_rollback_didcomm),
            )?
            .route(
                protocol_management::LIST_SERVICES,
                handler_fn(super::handlers_protocol::handle_list_services),
            )?
            .route(
                protocol_management::LIST_DRAIN,
                handler_fn(super::handlers_protocol::handle_list_drain),
            )?
            .route(
                protocol_management::DRAIN_CANCEL,
                handler_fn(super::handlers_protocol::handle_drain_cancel),
            )?
            .route(
                protocol_management::MEDIATOR_REPORT,
                handler_fn(super::handlers_protocol::handle_mediator_report),
            )?;
    }

    // Provision-integration — always available; vta-service depends
    // on vta-sdk with the `provision-integration` feature enabled.
    //
    // Both the legacy FPN-private URI and the canonical Trust Task URI
    // route to the same handler; the handler reads the inbound `typ`
    // and emits the matching response URI (`…-result` for the legacy
    // shape, `#response` fragment for the canonical shape). Existing
    // clients on the FPN URI keep working unchanged; new clients can
    // target the canonical registry without coordinating a URI flip.
    router = router
        .route(
            provision_integration_management::PROVISION_INTEGRATION,
            handler_fn(handlers::handle_provision_integration),
        )?
        .route(
            provision_integration_management::CANONICAL_PROVISION_INTEGRATION,
            handler_fn(handlers::handle_provision_integration),
        )?;

    // Step-up approval — the VTA vouches (signs as itself) that a holder
    // may step up their session at a relying party. Always available.
    router = router.route(
        handlers::STEP_UP_APPROVE_REQUEST_TYPE,
        handler_fn(handlers::handle_step_up_approve),
    )?;

    // TEE attestation handlers (feature-gated)
    #[cfg(feature = "tee")]
    {
        router = router
            .route(
                attestation_management::GET_TEE_STATUS,
                handler_fn(handlers::handle_tee_status),
            )?
            .route(
                attestation_management::REQUEST_ATTESTATION,
                handler_fn(handlers::handle_request_attestation),
            )?;
    }

    // Discovery (no auth required — the handler doesn't call auth_from_message)
    router = router.route(
        protocols::discovery::DISCOVER_CAPABILITIES,
        handler_fn(handlers::handle_discover_capabilities),
    )?;

    // Fallback, middleware, error handling
    router = router
        .fallback(handler_fn(handlers::handle_unknown))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_authenticated(true)
                .allow_anonymous_sender(false),
        )
        .layer(RequestLogging);

    Ok(BridgeHandler {
        inner: router,
        bridge,
    })
}
