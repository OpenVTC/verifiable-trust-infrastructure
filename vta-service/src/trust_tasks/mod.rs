//! `POST /api/trust-tasks` — the VTA-side trust-task dispatcher.
//!
//! Mirrors `affinidi-webvh-service`'s `did-hosting-control` dispatcher
//! (`routes/trust_tasks.rs`) — body shape, error envelope, and routing
//! semantics are byte-equivalent.
//!
//! ## Module layout
//!
//! - [`helpers`]: shared wire-shape helpers (`parse_payload`,
//!   `reject_with`, `success_response`, `app_error_to_reject`, etc.)
//!   used by every slice's handler module. `pub(super)` only.
//! - One module per Phase 3 slice (`auth`, `acl`, `contexts`, `keys`,
//!   `seeds`, `audit`, `discovery`, …). Each module's handler
//!   functions are `pub(super) async fn handle_<op>(state, auth, doc)
//!   -> Response`. The dispatcher's match arms call them.
//! - The cross-crate URI parity harness lives in the test module
//!   below; it asserts every URI declared in `vta-sdk::trust_tasks`
//!   is either dispatched or on the `REST_ROUTED` allowlist.
//!
//! ## Adding a new URI
//!
//! 1. Add the `TASK_*` const to `vta-sdk::trust_tasks` and extend its
//!    `ALL_URIS` array.
//! 2. Add a `handle_*` function in the appropriate slice module
//!    (create a new one if no slice fits).
//! 3. Add one line to the [`dispatch_table!`] invocation: `TASK_* =>
//!    slice::handle_*`. That single declaration generates **both** the
//!    `dispatch_typed` match arm **and** the parity-harness entry — they
//!    can't drift, so there is no separate test array to update.
//!
//! ## Body-parse failures emit framework-conformant errors
//!
//! Like the webvh-service dispatcher, we accept the body as
//! `axum::body::Bytes` and parse to `TrustTask<Value>` by hand so a
//! malformed body produces a `trust-task-error` document (per
//! framework SPEC §8.5) instead of axum's plain-text 400 default.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

mod acl;
mod app_state;
mod audit;
mod auth;
mod backup;
/// The ceremony-task predicate + the zero-authority claim an unenrolled
/// approver is dispatched under. Shared by the PDP gate and every
/// intrinsic-sender transport, so the two gates in front of a handler cannot
/// disagree about what a ceremony task is.
pub(crate) mod ceremony;
mod config;
#[cfg(test)]
mod conformance;
mod consent;
mod consent_request;
mod contexts;
mod cred_vault;
mod credential_exchange;
mod credentials;
mod device;
mod did_templates;
mod discovery;
mod helpers;
mod idempotency;
mod keys;
mod management;
mod memory;
mod messaging;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
mod passkey_vms;
pub(crate) mod planner;
mod policy;
mod policy_gate;
#[cfg(feature = "webvh")]
mod provision_integration;
mod replay;
mod seeds;
// `operations::protocol` — every service operation these handlers call — is
// `#[cfg(feature = "webvh")]`, because advertising a transport means editing
// the agent's did:webvh document. Without webvh there is no document to edit,
// so the whole family goes with it.
#[cfg(feature = "webvh")]
mod services;
mod task_consent;
pub(crate) mod transport;
// The step-up *ceremony*: minting an approve-request and consuming the
// approve-response that elevates a session. What decides a ceremony is needed
// is [`policy_gate`] and nothing else — the `RequireStepUp` extractor and its
// per-route op markers are gone with the config floors they read.
pub(crate) mod step_up;
// The PDP gate, callable from the REST routes. In-handler by necessity: the
// consent digest and the planner both need the parsed payload, which an axum
// extractor does not have.
pub(crate) use policy_gate::rest_gate;
mod vault;
#[cfg(feature = "webvh")]
pub(crate) mod webvh;
pub(crate) mod wire_v0_2;

/// The transport-neutral dispatch result — see [`helpers::TrustTaskOutcome`].
/// Re-exported so both transports (`routes`-mounted REST handler + DIDComm
/// `messaging::handlers::handle_trust_task`) can name `crate::trust_tasks::
/// TrustTaskOutcome`.
pub(crate) use helpers::TrustTaskOutcome;
use helpers::{body_parse_error_response, method_not_found, reject_with};
// Used unconditionally by the replay-dedup reject + `reject_trust_task`, not just
// the didcomm path — keep the import ungated (previously `#[cfg(feature =
// "didcomm")]`, which broke `--features rest` without `didcomm`).
use trust_tasks_rs::RejectReason;

/// URIs that the VTA exposes through dedicated unauth REST routes
/// rather than the authenticated `/api/trust-tasks` dispatcher.
///
/// The canonical list lives in the SDK
/// ([`vta_sdk::trust_tasks::REST_ROUTED_URIS`]) so the dispatcher's parity
/// harness and any generic client catalog (e.g. the `vta-mcp` `vta_call`
/// gateway, which advertises [`vta_sdk::trust_tasks::dispatch_routed_uris`])
/// can't drift. Handlers live in `routes::auth` (passkey login, legacy
/// challenge/authenticate/refresh) and `routes::attestation` (TEE status /
/// report).
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
const REST_ROUTED: &[&str] = vta_sdk::trust_tasks::REST_ROUTED_URIS;

/// URIs that vta-sdk declares but the dispatcher may not wire in
/// every build because they depend on `vta-service` feature flags
/// (e.g. `webvh`, `didcomm`, `tee`).
///
/// When their feature is **on**, the [`dispatch_table!`] entry is compiled, so
/// `dispatched_uris()` lists them. When the feature is **off**, the entry's
/// `#[cfg(...)]` excludes it from both the match and the parity list — so only
/// this allowlist keeps the parity harness from failing on them.
///
/// Adding a URI here is a deliberate act: it says "this URI's
/// dispatch lives behind a feature flag and may be unreachable in
/// some builds, but the URI is canonically declared in vta-sdk."
///
/// All entries are unconditional (don't change per cfg). They're
/// just statements that the dispatcher knows about them.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
const KNOWN_FEATURE_GATED_URIS: &[&str] = &[
    // Passkey-VMs slice — requires `webvh` + `didcomm` features. The
    // `dispatch_table!` entries list the same URIs and are tracked by the
    // parity harness when both features are on; this allowlist covers builds
    // where either feature is off.
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
    // Provision-integration — requires `webvh`.
    vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_0_2,
    // WebVH-DID-lifecycle slice — requires `webvh`. The `dispatch_table!`
    // entries list the same URIs and are tracked by the parity harness when
    // `webvh` is on; this allowlist covers builds where `webvh` is off.
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REGISTER_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0,
    // did-management Trust-Task spec URIs — declared in vta-sdk by
    // PR #139 ("PR 1 of N") as the shared vocabulary for the
    // cross-repo did-management migration (vta-sdk + vta-service +
    // affinidi-webvh-service all reference these). They are
    // **outbound producer URIs** — VTA's `webvh_didcomm.rs` sends
    // requests with these URIs to did-hosting, then matches
    // `<uri>#response` on the way back. They are not consumed by any
    // vta-service inbound dispatcher arm, so the parity harness
    // treats them like the feature-gated URIs above (declared
    // canonically, intentionally not in `DISPATCHED_URIS`). Removing
    // an entry here without a corresponding dispatcher addition will
    // surface as a parity-harness failure pointing back at this list.
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_PUBLISH_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_DELETE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_ENABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_DISABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_LIST_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_INFO_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_CHECK_NAME_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_CHANGE_OWNER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_ROLLBACK_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_PROBLEM_REPORT_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_CREATE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UPDATE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_DISABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_PURGE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_SET_DEFAULT_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_ASSIGN_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UNASSIGN_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_HEALTH_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_STATS_SYNC_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_ADMIN_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_DEREGISTER_0_1,
];

/// URIs this dispatcher serves that the published Trust-Tasks registry does
/// NOT yet spec — the implementation→registry drift tracked by issue #854.
///
/// The forward parity harness below asserts every vta-sdk URI is served; the
/// reverse harness (`every_served_uri_has_a_published_spec_or_is_tracked_debt`)
/// asserts every *served* URI resolves in the published registry, using the
/// generated `trust_tasks_rs::schema_index` as the registry's vendored index
/// (the same source `validate_payload` consults at dispatch time, and the same
/// one the workspace-wide census in `vtc-service/tests/trust_task_manifest.rs`
/// checks against — that census counts per *family*; this list is per *URI*,
/// scoped to what this dispatcher actually serves).
///
/// Every entry is acknowledged debt with a disposition recorded in
/// `docs/05-design-notes/registry-drift-triage.md` (and the programme doc
/// `canonical-task-reduction.md`). The harness enforces monotonicity in both
/// directions: serving a NEW unspecced URI fails (add the spec upstream — do
/// not grow this list), and once a spec is published upstream the entry MUST
/// be removed (a stale entry also fails).
///
/// Tracking issue: OpenVTC/verifiable-trust-infrastructure#854.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
const UNSPECCED_DISPATCHED_URIS: &[&str] = &[
    // ─ vta/seeds/* — keep-and-spec under `vta/` (reduction plan §E).
    "https://trusttasks.org/spec/vta/seeds/list/1.0",
    "https://trusttasks.org/spec/vta/seeds/rotate/1.0",
    "https://trusttasks.org/spec/vta/seeds/export-mnemonic/1.0",
    // ─ vta/audit retention pair — candidate `audit/retention/{show,update}`.
    "https://trusttasks.org/spec/vta/audit/get-retention/1.0",
    "https://trusttasks.org/spec/vta/audit/update-retention/1.0",
    // ─ Management singleton — diff against canonical first.
    // (`vta/discovery/capabilities/1.0` was here until #1043 retired the task;
    // its debt is discharged by deletion rather than by a spec.)
    "https://trusttasks.org/spec/vta/management/reload-services/1.0",
    // ─ vta/backup/* — author top-level `backup/*` (reduction plan §D).
    "https://trusttasks.org/spec/vta/backup/initiate-export/1.0",
    "https://trusttasks.org/spec/vta/backup/complete-export/1.0",
    "https://trusttasks.org/spec/vta/backup/initiate-import/1.0",
    "https://trusttasks.org/spec/vta/backup/finalize-import/1.0",
    "https://trusttasks.org/spec/vta/backup/abort/1.0",
    // ─ vta/attestation/* (REST-routed, unauthenticated) — keep-and-spec.
    "https://trusttasks.org/spec/vta/attestation/status/1.0",
    "https://trusttasks.org/spec/vta/attestation/report/1.0",
    // ─ vta/webvh/** — two-ends-of-one-wire decision pending (plan §B).
    //   `dids/update` is published; the rest are not.
    // ─ Vault archival lifecycle (#540) — generalise with a store
    //   discriminator instead of publishing twelve (reduction plan §C).
    "https://trusttasks.org/spec/vault/archive/0.1",
    "https://trusttasks.org/spec/vault/unarchive/0.1",
    "https://trusttasks.org/spec/vault/restore/0.1",
    "https://trusttasks.org/spec/vault/purge/0.1",
    "https://trusttasks.org/spec/vault/credentials/receive/0.1",
    "https://trusttasks.org/spec/vault/credentials/query/0.1",
    "https://trusttasks.org/spec/vault/credentials/get/0.1",
    "https://trusttasks.org/spec/vault/credentials/archive/0.1",
    "https://trusttasks.org/spec/vault/credentials/unarchive/0.1",
    "https://trusttasks.org/spec/vault/credentials/delete/0.1",
    "https://trusttasks.org/spec/vault/credentials/restore/0.1",
    "https://trusttasks.org/spec/vault/credentials/purge/0.1",
];

/// Declarative Trust-Task dispatch table.
///
/// Each entry is `URI(s) => slice::handler`. From one list the macro generates
/// **both** [`dispatch_typed`]'s `match` arms **and** (test-only) the
/// `dispatched_uris()` parity list — so a handler and its parity entry are the
/// same declaration and cannot drift. Adding a slice is one line.
///
/// Supported per entry:
/// - `#[cfg(...)]` attributes (feature-gated arms contribute to the parity
///   list only when their cfg is active — mirrors the prior per-slice consts;
///   the URI must also sit in [`KNOWN_FEATURE_GATED_URIS`] for builds with the
///   feature off);
/// - `A | B => handler` for dual-accepted URIs sharing one handler.
///
/// Every handler has the uniform `(&AppState, &AuthClaims, TrustTask<Value>)
/// -> Response` signature; the dispatcher spine ([`dispatch_trust_task_core`])
/// keeps `validate_basic` + the 0.2 down/up-convert.
macro_rules! dispatch_table {
    (
        $(
            $(#[$meta:meta])*
            $($uri:path)|+ => $handler:path
                [ $se:ident $disc:ident $acts:literal ]
        ),+ $(,)?
    ) => {
        /// Type-dispatch over the inbound document's `type` URI; generated by
        /// [`dispatch_table!`]. Unknown URIs fall through to `method_not_found`
        /// (`unsupported_type` per the framework's status table).
        ///
        /// `#[allow(deprecated)]`: arms match deprecated `*_0_1` URI constants
        /// on purpose — the VTA keeps serving 0.1 during the migration; 0.2
        /// counterparts arrive pre-down-converted (see `wire_v0_2`).
        #[allow(deprecated)]
        async fn dispatch_typed(
            state: &AppState,
            auth: &AuthClaims,
            doc: TrustTask<Value>,
        ) -> TrustTaskOutcome {
            let type_uri = doc.type_uri.to_string();
            match type_uri.as_str() {
                $(
                    $(#[$meta])*
                    $($uri)|+ => $handler(state, auth, doc).await,
                )+
                // A client mistakenly sending a REST-routed URI through the
                // envelope path gets `unsupported_type` here — correct from the
                // dispatcher's POV; the operation lives elsewhere.
                _ => method_not_found(doc, &type_uri),
            }
        }

        /// The authoritative SPEC §7.3 side-effect + exposure class of a
        /// dispatched task, declared inline next to its handler in the
        /// `[ SideEffect Disclose actsAsSubject ]` clause. This — NOT the
        /// published registry — is what the Policy Decision Point feeds into
        /// `PolicyInput`, so registry control cannot lower the consent bar
        /// (SPEC §7.3 items 13–14). `None` for a URI the dispatcher does not
        /// own; callers apply the fail-safe floor (treat as at least
        /// `mutating` / secret-disclosing act-as-subject).
        ///
        /// Every dispatch entry MUST carry a class — the macro grammar makes
        /// omission a compile error, so a new handler cannot be added without
        /// a deliberate classification.
        #[allow(deprecated, dead_code)]
        pub(crate) fn class_for(type_uri: &str) -> Option<$crate::policy::TaskClass> {
            match type_uri {
                $(
                    $(#[$meta])*
                    $($uri)|+ => Some($crate::policy::TaskClass::new(
                        $crate::policy::SideEffectLevel::$se,
                        $crate::policy::Discloses::$disc,
                        $acts,
                    )),
                )+
                _ => None,
            }
        }

        /// URIs wired into [`dispatch_typed`], collected from the same
        /// declarations that generate the match arms. Feature-gated arms
        /// contribute only when their cfg is active.
        ///
        /// Available at runtime, not just under `cfg(test)`, because
        /// `trust-task-discovery/0.1` answers with exactly this set. Deriving
        /// the answer from the dispatch table is the whole point: a
        /// hand-maintained list of "what we support" is a second source of
        /// truth, and it goes stale the first time someone adds a handler
        /// without remembering it exists. A discovery response that overstates
        /// the server is worse than none — a client believes a task is
        /// available and finds out otherwise on a live call.
        #[allow(deprecated)]
        pub(crate) fn dispatched_uris() -> Vec<&'static str> {
            let mut v: Vec<&'static str> = Vec::new();
            $(
                $(#[$meta])*
                v.extend([$($uri),+]);
            )+
            v
        }
    };
}

/// `POST /api/trust-tasks` handler.
///
/// Bearer-auth'd via [`AuthClaims`]; the caller's DID is the
/// transport-authenticated peer for SPEC.md §4.8.1 precedence inside
/// each typed handler.
///
/// Body is accepted as raw bytes so a parse failure surfaces as a
/// `trust-task-error` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (the workspace-wide 1 MB cap applies).
pub async fn dispatch_trust_task(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // REST is hop-by-hop by construction: TLS terminates at whatever the
    // operator put in front of this process, and the plaintext exists there.
    Ok(dispatch_trust_task_core(
        &state,
        &auth,
        &body,
        transport::TransportConfidentiality::HopByHop,
    )
    .await
    .into_response())
}

/// Transport-agnostic trust-task dispatch core.
///
/// Parses the envelope bytes and dispatches by `type` URI, returning a
/// typed [`TrustTaskOutcome`] — the framework result/error document bytes
/// plus the status code from the framework's status table. Shared by:
/// - the REST route [`dispatch_trust_task`], which renders it via
///   `IntoResponse`, and
/// - the DIDComm trust-task handler
///   (`crate::messaging::handlers::handle_trust_task`), which reads
///   `outcome.body` straight as the reply envelope — no round-trip through
///   an `axum::Response` to re-extract the JSON.
///
/// `body` is the full `TrustTask<Value>` envelope JSON — the HTTP POST
/// body on REST, the DIDComm message body on DIDComm.
/// Validate `doc.payload` against the published schema for its Type URI.
///
/// `Some(outcome)` rejects; `None` proceeds.
///
/// Ceremony tasks are exempt for the same reason the policy gate exempts them:
/// they are the mechanism, not the operation, and a `task-consent/decision` that
/// could not be delivered because its own payload failed a check would strand
/// every task waiting on it.
async fn validate_payload(
    state: &AppState,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    let Some(schema) = trust_tasks_rs::schema_index::schema_for(type_uri) else {
        // No published spec for this task. Many of the tasks this VTA dispatches
        // are in that position, so refusing them outright would break them — but
        // the gap is real, and an operator may prefer to fail closed.
        if state.config.read().await.policy.require_payload_schema {
            return Some(helpers::reject_with(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!(
                        "no payload schema is known for `{type_uri}`, and this VTA is configured \
                         to refuse tasks it cannot validate"
                    ),
                },
            ));
        }
        tracing::debug!(
            type_uri,
            "no payload schema known — dispatching unvalidated (set \
             policy.require_payload_schema to refuse instead)"
        );
        return None;
    };

    match trust_tasks_rs::validate::against_schema(schema, &doc.payload) {
        Ok(()) => None,
        Err(e) => {
            tracing::info!(type_uri, error = %e, "payload failed schema validation");
            Some(helpers::reject_with(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!("payload does not conform to {type_uri}: {e}"),
                },
            ))
        }
    }
}

pub(crate) async fn dispatch_trust_task_core(
    state: &AppState,
    auth: &AuthClaims,
    body: &[u8],
    confidentiality: transport::TransportConfidentiality,
) -> TrustTaskOutcome {
    let outcome = transport::with_confidentiality(confidentiality, async move {
        dispatch_trust_task_inner(state, auth, body).await
    })
    .await;
    // Observe the real response against the schema its own `type` names. Here
    // rather than in the REST route because REST is one of three transports
    // through this function — DIDComm and TSP read `outcome.body` directly, and
    // an HTTP-layer check would be blind to both. Compiled out of production
    // builds; see `test_support::response_conformance`.
    #[cfg(any(test, feature = "test-support"))]
    let outcome =
        match crate::test_support::response_conformance::observe(outcome.status, &outcome.body) {
            Some(body) => TrustTaskOutcome {
                status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                body,
            },
            None => outcome,
        };
    outcome
}

/// The dispatch spine proper. Split from [`dispatch_trust_task_core`] only so
/// the transport scope wraps every path out of it, including the early
/// rejections — a handler that reads the transport must never see a scope that
/// was skipped because the envelope failed validation first.
///
/// This layer parses the envelope and attaches the superseded-task signal; the
/// checks and dispatch are in [`dispatch_trust_task_validated`], for the same
/// wrap-every-exit reason.
async fn dispatch_trust_task_inner(
    state: &AppState,
    auth: &AuthClaims,
    body: &[u8],
) -> TrustTaskOutcome {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        // No `type` to attribute the request to, so nothing to count and no
        // successor to name. The one exit that legitimately carries no
        // deprecation signal.
        Err(e) => return body_parse_error_response(&e.to_string()),
    };

    // Superseded-task signalling wraps everything below, for the same reason
    // `mark_superseded` is a layer rather than a call inside each of the 56
    // REST handlers: [`dispatch_trust_task_validated`] has a dozen early
    // returns — expiry, wrong recipient, replay, schema validation, the policy
    // gate — and a signal applied at only some of them is worse than none.
    // Removal is gated on this counter reading zero; a URI that goes quiet
    // because its callers are all being rejected before the hook would read as
    // "nobody sends this any more" and be deleted out from under them.
    //
    // Read from the URI as it *arrived*, before the 0.2 down-convert rewrites
    // `doc.type_uri`: what is being measured is what the client sent, and
    // reading it after the rewrite would count every 0.2 caller as a 0.1 one
    // and hold the metric off zero permanently.
    let superseded = crate::deprecation::superseded_task(&doc.type_uri.to_string());

    // `Box::pin` rather than a bare `.await`: the callee's state machine
    // inlines every handler's future through `dispatch_typed`, so awaiting it
    // by value would nest that whole thing inside this frame as well. It does
    // not fit — a debug build of `--workspace` (where feature unification turns
    // on `tee` and the rest) overflowed the test-thread stack in
    // `tests/mock_vta.rs` the moment this split was introduced. Boxing puts the
    // large half on the heap and leaves a pointer here.
    let mut outcome = Box::pin(dispatch_trust_task_validated(state, auth, doc)).await;

    if let Some(task) = superseded {
        // Whatever the outcome. A superseded task that was *rejected* is still
        // a client sending a URI we want to stop serving, and a client about to
        // retry is the one most in need of knowing what to retry onto.
        crate::deprecation::note_superseded_task(task);
        crate::deprecation::annotate_superseded(&mut outcome.body, task);
    }

    outcome
}

/// Everything after the envelope parses: framework checks, replay, schema
/// validation, idempotency, the policy gate, and typed dispatch.
///
/// Split from [`dispatch_trust_task_inner`] so the deprecation signal there
/// wraps every exit path out of this function, not just the last one.
/// How far ahead of this consumer's own clock an `issuedAt` may sit.
///
/// Sixty seconds: the bound SPEC §4.2 sanctions, the same window this
/// workspace already enforces on a DIDComm envelope's `created_time`, and the
/// same value `trust_tasks_rs::freshness::DEFAULT_SKEW` uses. A producer sees
/// one skew budget across every surface rather than several to discover.
const MAX_ISSUED_AT_SKEW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Framework 0.5.0 Consumer Requirements item 13.
///
/// # This is a stand-in for `trust_tasks_rs::freshness`, and should be deleted
///
/// `trust-tasks-rs` 0.12.0 (dtgwg-trust-tasks-tf#274) ships
/// `FreshnessPolicy` + `TrustTask::validate_freshness`, which implement these
/// two rules identically — same 60s skew — and add the `max_age` acceptance
/// window and the `ReplayGuard` that item 11 actually needs. That is where
/// this belongs, and re-implementing it here is the "prefer existing SDKs"
/// rule in CLAUDE.md pointed the wrong way.
///
/// **The 0.12 bump is blocked on an external crate, not on this workspace.**
/// `affinidi-messaging-sdk` 0.19.12 pins `trust-tasks-rs ^0.11`, and
/// `vta_sdk::acl_setup` hands it a generated `MediatorAcl`. Two
/// `trust-tasks-rs` nodes in one graph therefore fail to compile with
/// `expected MediatorAcl, found a different MediatorAcl` — the exact
/// two-version hazard the workspace CLAUDE.md describes. When that SDK
/// publishes against 0.12, delete this function and its constant and call
/// `doc.validate_freshness(now, &policy)` instead; the tests below are written
/// against behaviour, not this implementation, so they should survive the
/// swap unchanged and are the check that it was faithful.
///
/// Two refusals, both `malformedRequest` and **not** `expired`. That
/// distinction is the point of the rule rather than a detail of it: `expired`
/// names a document that was once acceptable and no longer is, so returning it
/// here would tell the producer to *wait*, when what the producer must do is
/// reissue. Neither of these documents was ever acceptable.
///
/// The rule exists to make Consumer Requirements item 11 — the duplicate-
/// execution record — implementable at all. That record is only bounded if
/// every accepted document can be placed in a window, and each of these two
/// shapes escapes every window while still looking acceptable:
///
/// - an `issuedAt` in the consumer's future sits in a window that has not
///   opened, and re-enters it as the clock advances;
/// - an `expiresAt` at or before its `issuedAt` describes a validity interval
///   that never contained an instant, so whether the document is "expired"
///   depends only on which member the consumer happened to consult.
///
/// Neither refusal judges the producer: a skewed clock produces the first
/// routinely.
fn check_freshness_bounds(
    doc: &TrustTask<Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), RejectReason> {
    let Some(issued_at) = doc.issued_at else {
        // Item 13 bounds the timestamps a document carries; it does not
        // require one. `issuedAt` is SHOULD at the framework level, and the
        // obligation to require it falls on the specification of a
        // consequential task (Specification Requirements item 17), which is
        // enforced by that task's own schema rather than here.
        return Ok(());
    };
    if issued_at > now + MAX_ISSUED_AT_SKEW {
        return Err(RejectReason::MalformedRequest {
            reason: format!(
                "issuedAt {} is more than {}s ahead of this consumer's clock",
                issued_at.to_rfc3339(),
                MAX_ISSUED_AT_SKEW.num_seconds(),
            ),
        });
    }
    if let Some(expires_at) = doc.expires_at
        && expires_at <= issued_at
    {
        return Err(RejectReason::MalformedRequest {
            reason: format!(
                "expiresAt {} is at or before issuedAt {}, so the document was \
                 valid at no instant",
                expires_at.to_rfc3339(),
                issued_at.to_rfc3339(),
            ),
        });
    }
    Ok(())
}

async fn dispatch_trust_task_validated(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // 2. Framework §7.2 items 4 + 5 — expiry + recipient
    //    enforcement. Closes L5 from the May 2026 security
    //    review: the hand-rolled dispatcher previously skipped
    //    these, so a Trust-Task envelope addressed at a
    //    different recipient would be silently accepted and an
    //    expired envelope would be honoured.
    //
    //    Audience binding (proof + recipient required for non-
    //    bearer specs, framework §7.2 item 8) is typed —
    //    `enforce_audience_binding` needs `P: Payload`, so each
    //    slice's typed handler runs it after `parse_payload`.
    {
        let now = chrono::Utc::now();
        // Framework 0.5.0 Consumer Requirements item 13 — freshness bounds.
        // Checked before `validate_basic` because both are decided from the
        // document alone, before any resolution, verification or execution
        // work, and because one of them changes how the *other* member reads.
        if let Err(reason) = check_freshness_bounds(&doc, now) {
            return reject_with(&doc, reason);
        }
        let vta_did = state.config.read().await.vta_did.clone();
        if let Some(my_vid) = vta_did.as_deref()
            && let Err(reason) = doc.validate_basic(now, my_vid)
        {
            return reject_with(&doc, reason);
        }
        // No vta_did configured → service is in setup; skip
        // the recipient check (no identity to bind against).
        // Production VTAs always have vta_did set by `vta setup`.
    }

    // 2b. Replay dedup. Reject a re-submitted `(actor, envelope-id)` within the
    //     dedup window so a retry — including a client's cross-transport
    //     fallback — cannot double-apply a mutating task. Ids are unique per
    //     request, so this only fires on a genuine resubmission of the same
    //     envelope. Record-before-dispatch = at-most-once (see `replay`).
    if !replay::check_and_record(&auth.did, &doc.id) {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "duplicate".to_string(),
                details: Some(serde_json::json!({
                    "id": doc.id,
                    "reason": "this request id was already submitted; the prior submission is \
                               authoritative — do not retry with the same id",
                })),
            },
        );
    }

    // 3. Session-pubkey binding pre-check.
    //
    // Once `AuthClaims` carries `session_pubkey_b58btc` (Phase 3 work,
    // mirrors `webvh-service`'s pattern) the dispatcher will enforce
    // that the proof's `verificationMethod` matches the JWT-bound
    // pubkey before any handler runs. Phase 2 scaffold elides this —
    // no passkey-bound sessions exist yet on the VTA side.
    let _ = auth;

    // 4. Dispatch by type URI.
    //
    // 0.2 dual-accept: bearer-authed specs whose only 0.1→0.2 delta is
    // enum-value casing are down-converted to their canonical 0.1 form,
    // dispatched through the existing 0.1 handler, and the response
    // up-converted back to 0.2 (see `wire_v0_2`). Signed-payload specs are NOT
    // routed here — they have typed 0.2 arms in `dispatch_typed`.
    // The negotiated wire version is scoped around `dispatch_typed` via a
    // `task_local` so the two JWE-sealing handlers (`vault/release`,
    // `vault/proxy-login`) can serialise the *sealed* cleartext in the right
    // casing — the edge transform can't reach inside ciphertext. Every other
    // handler ignores it.
    use wire_v0_2::{WIRE_VERSION, WireVersion};
    let type_uri = doc.type_uri.to_string();

    // Name every inbound trust task at the one point all three transports (TSP,
    // DIDComm, REST) converge, after the envelope parses. Without this the
    // per-transport dispatch logs report only sender + status, so you cannot
    // tell a `dids/update` submit from a `task-consent/decision` — which made a
    // consent loop (requester re-submits pile up, the approver's decision never
    // arrives) impossible to distinguish from the log alone.
    tracing::info!(
        type_uri = %type_uri,
        actor = %auth.did,
        id = %doc.id,
        "trust-task received"
    );

    // Blanket vault audit: capture the audit context BEFORE `doc` is moved
    // into dispatch. Every password-vault and credential-vault task — read or
    // write, success or denied — produces exactly one persisted audit row here
    // (the one place that sees the type URI, the authenticated actor, and the
    // final outcome). Non-vault tasks audit through their own handlers/ops.
    let vault_audit = vault_audit_action(&type_uri).map(|action| {
        let resource = vault_audit_resource(&doc.payload);
        let context_id = doc
            .payload
            .get("contextId")
            .and_then(Value::as_str)
            .map(str::to_string);
        // Operator-supplied rationale (the `reason` field that delete/archive/
        // restore/purge carry) — persisted so "audit the reason" is satisfied.
        let detail = doc
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string);
        (action, resource, context_id, detail)
    });

    // Payload schema validation — before the policy gate, and deliberately not
    // behind `policy.enforcement`.
    //
    // This is not a policy decision. It is the question of whether the document
    // means what its sender thinks it means, and it has to be answered before
    // anything else reads the payload: before the class is derived from it, before
    // a policy is evaluated on it, before a handler is dry-run against it to tell
    // a human what it will do.
    //
    // The bug that put this here: a caller sent `expectedVersionId` — the
    // optimistic-concurrency precondition — and the handler's type expected
    // `expected_version_id`. Serde matched no field, nothing rejected the unknown
    // member, and the precondition simply never applied. Updates published with no
    // lost-update protection while the caller's own source read as though the
    // danger were handled. The member was not *wrong*; it was **unrecognised**,
    // and nothing was watching for that.
    //
    // A silently-ignored member is worse than a rejected one. A rejected one you
    // find out about.
    if let Some(reject) = validate_payload(state, &type_uri, &doc).await {
        return reject;
    }

    // Idempotency claim. Only bites when the document carries an
    // `idempotencyKey` *and* the task is one where a second execution leaves a
    // second durable artefact (`vta_sdk::retry_safety`) — everything else
    // returns `Skip` and dispatches exactly as before.
    //
    // Placed after payload validation so a malformed request never consumes a
    // key, and before the policy gate so a *denied* request releases its claim
    // through the same `record_outcome` path every other failure takes. The
    // claim is written before the handler runs, which is what makes two
    // concurrent attempts safe: `insert_if_absent` is atomic, so one proceeds
    // and the other is told to wait rather than both passing a check.
    //
    // This is the layer `replay` (2b above) cannot be. That one keys on the
    // envelope id and so only catches a byte-identical resubmission; every SDK
    // path mints a fresh `urn:uuid:` per attempt, so a genuine retry sails past
    // it. The key here is stable across attempts of the same logical operation.
    let idem_claim = match idempotency::claim(&state.idempotency_ks, &auth.did, &doc).await {
        idempotency::Claim::Answer(outcome) => return *outcome,
        idempotency::Claim::Proceed { key, safety } => Some((key, safety)),
        idempotency::Claim::Skip => None,
    };

    // Policy Decision Point gate — evaluated before dispatch. A no-op unless
    // `config.policy.enforcement` is on; when a policy denies (or demands
    // step-up/consent), the task is rejected here and never reaches its handler.
    // A rejected task still flows through the audit tail below.
    // Filled by the gate only when a consumed consent grant *delegated* authority
    // the requester's own token lacked. When non-empty, this dispatch — and only
    // this dispatch — runs under the requester's identity widened to full admin
    // over the delegated context (`with_delegated_authority`), because the grant
    // authorizes the exact bound task in full. This is what lets a purely
    // unprivileged requester execute a task an approver blessed; the widening is
    // never written back to the session.
    let mut delegated_contexts: Vec<String> = Vec::new();
    let outcome =
        match policy_gate::policy_gate(state, auth, &type_uri, &doc, &mut delegated_contexts).await
        {
            Some(reject_outcome) => reject_outcome,
            None => {
                let delegated_auth = (!delegated_contexts.is_empty())
                    .then(|| auth.with_delegated_authority(&delegated_contexts));
                let auth = delegated_auth.as_ref().unwrap_or(auth);
                if let Some(spec) = wire_v0_2::lookup_0_2(&type_uri) {
                    let mut doc = doc;
                    wire_v0_2::downconvert_request(&mut doc.payload, spec);
                    if let Ok(uri_0_1) = spec.uri_0_1.parse() {
                        doc.type_uri = uri_0_1;
                    }
                    let outcome = WIRE_VERSION
                        .scope(WireVersion::V0_2, dispatch_typed(state, auth, doc))
                        .await;
                    wire_v0_2::upconvert_response(outcome, spec)
                } else {
                    WIRE_VERSION
                        .scope(WireVersion::V0_1, dispatch_typed(state, auth, doc))
                        .await
                }
            }
        };

    // Record what happened, so a retry carrying the same key converges on it.
    // A failed outcome *releases* the claim instead of recording it — the
    // effect this exists to deduplicate never happened, so the retry should be
    // allowed to actually run.
    if let Some((key, safety)) = idem_claim {
        idempotency::record_outcome(&state.idempotency_ks, &auth.did, &key, safety, &outcome).await;
    }

    if let Some((action, resource, context_id, detail)) = vault_audit {
        let label = vault_audit_outcome_label(&outcome);
        if let Err(e) = crate::audit::record_with_detail(
            &state.audit_sink,
            &action,
            &auth.did,
            resource.as_deref(),
            &label,
            Some(helpers::TRANSPORT_TRUST_TASK),
            context_id.as_deref(),
            detail.as_deref(),
        )
        .await
        {
            // Audit is best-effort: a failed write must never fail the op.
            tracing::warn!(error = %e, action = %action, "vault audit record failed");
        }
    }

    outcome
}

/// Audit action string for a vault-family Trust Task, or `None` for any task
/// outside the vault family (those audit through their own handlers/ops).
///
/// `…/spec/vault/<verb>/<ver>` → `vault.<verb>` (e.g. `vault.delete`);
/// `…/spec/vault/credentials/<verb>/<ver>` → `vault.cred.<verb>`. Version is
/// ignored, so a 0.2 password-vault URI and its 0.1 form audit identically.
fn vault_audit_action(type_uri: &str) -> Option<String> {
    let rest = type_uri.split("/spec/vault/").nth(1)?;
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["credentials", verb, ..] => Some(format!("vault.cred.{verb}")),
        [verb, ..] => Some(format!("vault.{verb}")),
        _ => None,
    }
}

/// Best-effort resource id for the audit row, pulled generically from the
/// request payload (`id` / `entryId` / `credentialId`). `None` for list/query
/// tasks that carry no single-entry id.
fn vault_audit_resource(payload: &Value) -> Option<String> {
    for key in ["id", "entryId", "credentialId"] {
        if let Some(v) = payload.get(key).and_then(Value::as_str) {
            return Some(v.to_string());
        }
    }
    None
}

/// Map a dispatch outcome to an audit outcome label: `"success"` on a 2xx,
/// otherwise `"denied:<code>"` with the framework reject code lifted from the
/// error document (falling back to `"denied"` if it can't be read). The audit
/// sink keys INFO vs ERROR on the `"success"` prefix.
fn vault_audit_outcome_label(outcome: &TrustTaskOutcome) -> String {
    if outcome.status.is_success() {
        return "success".to_string();
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&outcome.body)
        && let Some(code) = v
            .get("payload")
            .and_then(|p| p.get("code"))
            .and_then(Value::as_str)
    {
        return format!("denied:{code}");
    }
    "denied".to_string()
}

/// Build a Trust-Task rejection `Response` for a request whose envelope
/// bytes are in `body`, WITHOUT dispatching it.
///
/// The DIDComm trust-task handler uses this when it can't authorize the
/// transport peer (no ACL entry), so the reply is still a proper
/// Trust-Task error document — not a DIDComm problem-report, which a
/// conformant Trust-Task client can't read. (On REST the JWT extractor
/// rejects unauthenticated callers before dispatch, so this gap is
/// DIDComm-only — hence the feature gate.)
// Either inbound transport rejects malformed work the same way — TSP frames
// arrive on the same mediator socket and go through the same spine.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub(crate) fn reject_trust_task(body: &[u8], reason: RejectReason) -> TrustTaskOutcome {
    match serde_json::from_slice::<TrustTask<Value>>(body) {
        Ok(doc) => reject_with(&doc, reason),
        Err(e) => body_parse_error_response(&e.to_string()),
    }
}

// Note: `passkey-login-{start,finish}/1.0`, `challenge/1.0`,
// `authenticate/1.0`, and `refresh/1.0` are NOT in this table. They are
// UNAUTHENTICATED operations served as dedicated REST routes (`/auth/*`) — the
// user has no session JWT, so they can't pass `AuthClaims` through the
// dispatcher's extractor. The parity harness's `REST_ROUTED` allowlist tracks
// them.
dispatch_table! {
    // ─── Auth slice (authenticated operations) ───────────────────
    vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_1 => auth::handle_revoke_session
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1 => auth::handle_whoami
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1 => auth::handle_sessions_list
        [ None Metadata false ],
    // Dual-accept: both versions route to the same typed handler, which
    // normalises the `evidence.kind` discriminator on a copy (the signed
    // document is never mutated). Not edge-transformed in `wire_v0_2` because
    // the payload carries the approver's signature.
    vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1
        | vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2
        => step_up::handle_approve_response
        [ Mutating None false ],
    // ─── Policy slice (runtime PDP management) ────────────────────
    // Deliberately NOT exempt from the gate: an operator who wants two-person
    // control over changes to the gate itself writes a consent rule for
    // `policy/upsert`. The lockout that risks is answered by the offline
    // break-glass, not by making this surface ungateable.
    vta_sdk::trust_tasks::TASK_POLICY_LIST_0_2 => policy::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_POLICY_GET_0_1 => policy::handle_get
        [ None Metadata false ],
    // Destructive: rewriting policy can remove every gate on this VTA.
    vta_sdk::trust_tasks::TASK_POLICY_UPSERT_0_2 => policy::handle_upsert
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_POLICY_DELETE_0_1 => policy::handle_delete
        [ Destructive None false ],
    // ─── Consent slice ────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_CONSENT_REQUEST_1_0 => consent::handle_request
        [ None None false ],
    vta_sdk::trust_tasks::TASK_CONSENT_DECISION_1_0 => consent::handle_decision
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONSENT_REVOKE_1_0 => consent::handle_revoke
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONSENT_LIST_1_0 => consent::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONSENT_APPROVER_SET_1_0 => consent::handle_approver_set
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONSENT_APPROVER_LIST_1_0 => consent::handle_approver_list
        [ None Metadata false ],
    // Task-execution consent decision (PDP requireConsent). Records approver
    // signatures; the gate exempts it from re-gating (see policy_gate) so
    // approving a task can't itself require consent.
    vta_sdk::trust_tasks::TASK_TASK_CONSENT_DECISION_0_1 => task_consent::handle_decision
        [ Mutating None false ],
    // ─── ACL slice ────────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_ACL_LIST_0_1 => acl::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1 => acl::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_SHOW_0_1 => acl::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_ACL_UPDATE_0_1 => acl::handle_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_CHANGE_ROLE_0_1 => acl::handle_change_role
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_REVOKE_0_1 => acl::handle_delete
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_SWAP_KEY_0_1 => acl::handle_swap_key
        [ Destructive None false ],
    // ─── Device slice ─────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_DEVICE_REGISTER_0_1 => device::handle_register
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DEVICE_HEARTBEAT_0_1 => device::handle_heartbeat
        [ None None false ],
    vta_sdk::trust_tasks::TASK_DEVICE_LIST_0_1 => device::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_DEVICE_DISABLE_0_1 => device::handle_disable
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DEVICE_WIPE_0_1 => device::handle_wipe
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_DEVICE_SET_WAKE_0_1 => device::handle_set_wake
        [ Mutating None false ],
    // ─── Messaging slice ──────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_MESSAGING_PING_0_1 => messaging::handle_ping
        [ None None false ],
    // ─── Services slice ──────────────────────────────────────────
    //
    // Metadata mirrors what each verb actually does to the agent's DID
    // document. `drain/cancel` is Destructive rather than Mutating: it discards
    // messages still in flight through the mediator, which is precisely what
    // the drain window existed to prevent.
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_LIST_1_0 => services::handle_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_GET_1_0 => services::handle_get
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0 => services::handle_enable
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0 => services::handle_update
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0 => services::handle_disable
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_ROLLBACK_1_0 => services::handle_rollback
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_DRAIN_LIST_1_0 => services::handle_drain_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_SERVICES_DRAIN_CANCEL_1_0 => services::handle_drain_cancel
        [ Destructive None false ],
    // ─── Contexts slice ──────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0 => contexts::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0 => contexts::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0 => contexts::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0 => contexts::handle_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0 => contexts::handle_update_did
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0 => contexts::handle_preview_delete
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0 => contexts::handle_delete
        [ Destructive None false ],
    // ─── Keys slice ──────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_KEYS_LIST_0_1 => keys::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1 => keys::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_KEYS_IMPORT_0_1 => keys::handle_import
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_KEYS_SHOW_0_1 => keys::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_KEYS_RENAME_0_1 => keys::handle_rename
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_KEYS_REVOKE_0_1 => keys::handle_revoke
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_KEYS_SIGN_0_1 => keys::handle_sign
        [ None None true ],
    vta_sdk::trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_0_1 => keys::handle_derive_and_sign
        [ Mutating None true ],
    vta_sdk::trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_0_1 => keys::handle_derive_and_sign_document
        [ Mutating None true ],
    // ─── Seeds slice ─────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0 => seeds::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0 => seeds::handle_rotate
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 => seeds::handle_export_mnemonic
        [ None Secret false ],
    // ─── Audit slice ─────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1 => audit::handle_list_logs
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0 => audit::handle_get_retention
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0 => audit::handle_update_retention
        [ Mutating None false ],
    // ─── Discovery ───────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_TRUST_TASK_DISCOVERY_0_1 => discovery::handle_trust_task_discovery
        [ None None false ],
    // ─── Credential-exchange: deferred-presentation approval ─────
    //
    // The holder operator's out-of-band surface over deferred presentations.
    // The `credential-exchange/*` family keeps its URIs in
    // `vta_sdk::protocols::credential_exchange`, not the central `trust_tasks`
    // registry — so these sit outside the `ALL_URIS` parity harness (like the
    // `query`/`present` message types), but are still tracked by
    // `dispatched_uris()` (harmless extra entries).
    vta_sdk::protocols::credential_exchange::PENDING_LIST
        => credential_exchange::handle_pending_list
        [ None Metadata false ],
    vta_sdk::protocols::credential_exchange::PENDING_APPROVE
        => credential_exchange::handle_pending_approve
        [ Mutating None true ],
    vta_sdk::protocols::credential_exchange::PENDING_DENY
        => credential_exchange::handle_pending_deny
        [ Mutating None false ],
    // ─── Vault slice (public 0.1 spec) ──────────────────────────
    vta_sdk::trust_tasks::TASK_VAULT_LIST_0_1 => vault::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VAULT_GET_0_1 => vault::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VAULT_UPSERT_0_1 => vault::handle_upsert
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_DELETE_0_1 => vault::handle_delete
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_VAULT_RELEASE_0_1 => vault::handle_release
        [ Mutating Secret false ],
    vta_sdk::trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1 => vault::handle_proxy_login
        [ Mutating Secret true ],
    vta_sdk::trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1 => vault::handle_sign_trust_task
        [ Mutating None true ],
    // Vault archival lifecycle (openvtc extension). `delete` above is now soft.
    vta_sdk::trust_tasks::TASK_VAULT_ARCHIVE_0_1 => vault::handle_archive
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_UNARCHIVE_0_1 => vault::handle_unarchive
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_RESTORE_0_1 => vault::handle_restore
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_PURGE_0_1 => vault::handle_purge
        [ Destructive None false ],

    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_RECEIVE_0_1 => cred_vault::handle_receive
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_QUERY_0_1 => cred_vault::handle_query
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_GET_0_1 => cred_vault::handle_get
        [ None Metadata false ],
    // Credential archival lifecycle (openvtc extension; CredentialWrite-gated).
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_ARCHIVE_0_1 => cred_vault::handle_archive
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_UNARCHIVE_0_1 => cred_vault::handle_unarchive
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_DELETE_0_1 => cred_vault::handle_delete
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_RESTORE_0_1 => cred_vault::handle_restore
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VAULT_CREDENTIALS_PURGE_0_1 => cred_vault::handle_purge
        [ Destructive None false ],
    // ─── Issued-credential lifecycle (spec/vta/credentials/*) ────
    // Mint + revoke VTA-signed VCs; Admin-gated + operator step-up (AAL2).
    vta_sdk::trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_0_1 => credentials::handle_issue
        [ Mutating None true ],
    vta_sdk::trust_tasks::TASK_VTA_CREDENTIALS_REVOKE_0_1 => credentials::handle_revoke
        [ Destructive None false ],
    // ─── Agent-memory slice (spec/vta/memory/*) ──────────────────
    // Per-context key/value store; gated on context access (require_context),
    // NOT operator step-up.
    vta_sdk::trust_tasks::TASK_VTA_MEMORY_PUT_0_1 => memory::handle_put
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VTA_MEMORY_LIST_0_1 => memory::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VTA_MEMORY_DELETE_0_1 => memory::handle_delete
        [ Mutating None false ],
    // ─── Application-state slice (spec/vta/app-state/*) ──────────
    // Versioned, namespaced per-context JSON the VTA stores but never
    // interprets. Gated on context access (require_context), NOT operator
    // step-up — same boundary as the memory slice. `discloses: Metadata` on
    // the reads because the values are application data rather than secrets;
    // secret material belongs in the vault, and the published specs say so
    // normatively. `delete` is Destructive: the value goes immediately and,
    // once the tombstone is reaped, nothing records the record ever existed.
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_GET_1_0 => app_state::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_PUT_1_0 => app_state::handle_put
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_LIST_1_0 => app_state::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_DELETE_1_0 => app_state::handle_delete
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_GET_MANY_1_0 => app_state::handle_get_many
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_VTA_APP_STATE_PUT_MANY_1_0 => app_state::handle_put_many
        [ Mutating None false ],
    // ─── Config slice ────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_CONFIG_SHOW_0_1 => config::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONFIG_PATCH_0_1 => config::handle_update
        [ Mutating None false ],
    // ─── Management slice ────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_MANAGEMENT_RELOAD_SERVICES_1_0 => management::handle_reload_services
        [ Mutating None false ],
    // ─── Backup slice (descriptor pattern) ───────────────────────
    vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0 => backup::handle_initiate_export
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0 => backup::handle_complete_export
        [ Mutating Secret false ],
    vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0 => backup::handle_initiate_import
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_0 => backup::handle_finalize_import
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_BACKUP_ABORT_1_0 => backup::handle_abort
        [ Mutating None false ],
    // ─── DID-templates slice (2.0 — optional contextId selects the
    // scope; the twelve retired 1.0 URIs now get UnsupportedType) ──
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_2_0 => did_templates::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0 => did_templates::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0 => did_templates::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0 => did_templates::handle_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0 => did_templates::handle_delete
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0 => did_templates::handle_render
        [ None Metadata false ],
    // ─── Passkey-VMs slice (feature-gated: webvh + didcomm) ─────
    //
    // Canonical 0.1 only — the pre-spec 1.0 aliases were removed (the browser
    // plugin migrated to 0.1; a 1.0 doc now gets UnsupportedType).
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1
        => passkey_vms::handle_enroll_challenge
        [ None None false ],
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1 => passkey_vms::handle_enroll_submit
        [ Mutating None false ],
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1 => passkey_vms::handle_list
        [ None Metadata false ],
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1 => passkey_vms::handle_revoke
        [ Destructive None false ],
    // ─── Provision-integration (feature-gated: webvh) ────────────
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_0_2
        => provision_integration::handle_request
        [ Mutating Secret false ],
    // ─── WebVH-DID-lifecycle slice (feature-gated: webvh) ────────
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0 => webvh::handle_servers_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REGISTER_1_0 => webvh::handle_servers_register
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0 => webvh::handle_servers_remove
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_DOMAINS_0_1 => webvh::handle_servers_domains
        [ None Metadata false ],
    // Reads two listings and compares them — no side effects, same class as
    // the domains read beside it.
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_RECONCILE_0_1 => webvh::handle_servers_reconcile
        [ None Metadata false ],
    // Destructive rather than Mutating: it stops a published identifier
    // resolving, with no undo, and every relying party that held the DID sees
    // it go — they cannot distinguish retirement from compromise or an outage.
    // Reconcile above it is the read that finds these; this is the only write
    // in the pair, and the asymmetry in class is the point.
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_RETIRE_ORPHAN_0_1 => webvh::handle_servers_retire_orphan
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0 => webvh::handle_dids_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0 => webvh::handle_dids_create
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_1_0 => webvh::handle_dids_get
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0 => webvh::handle_dids_delete
        [ Destructive None false ],
    // Destructive, not mutating — and the line below is why. A document update
    // ROTATES the DID's update key: the key that could authorize changes before
    // this entry cannot afterwards. SPEC §7.3 item 13 names exactly that —
    // "rotation of a sole controlling key" — as authority-shifting, and
    // authority-shifting is destructive.
    //
    // `dids/rotate-keys` two lines down has always been Destructive. It rotates
    // the same key. Classing an update as merely `Mutating` said that the same
    // effect was destructive when you asked for it and recoverable when you got
    // it as a side effect, which is precisely backwards: the side effect is the
    // dangerous one, because it is the one nobody asked for.
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0 => webvh::handle_dids_update
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0 => webvh::handle_dids_rotate_keys
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0
        => webvh::handle_dids_register_with_server
        [ Mutating None false ],
    // Agent-name bind/release/park/resume. All four publish a new signed
    // version (and so rotate the update key exactly like any update), and all
    // four change a public name binding — Destructive, like `dids/update`,
    // per the rationale above. Classifying them Destructive is what makes the
    // wallet force a cross-device type-to-confirm, which is the elevation
    // for these ops (the hosting endpoint is deliberately not step-up-gated
    // — the VTA can't hold an aal2 session).
    //
    // `remove` earns the classification most directly: it releases the name
    // for anyone to reclaim, so unlike `disable` it is not recoverable by
    // this DID alone.
    // Read-only: no side effect, metadata-class. A parked name is invisible
    // in the DID document, so `list` is the only way to see one — and `check`
    // is what lets a client report a collision before it signs a new version.
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0 => webvh::handle_agent_name_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0 => webvh::handle_agent_name_check
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0 => webvh::handle_agent_name_set
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0 => webvh::handle_agent_name_remove
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0 => webvh::handle_agent_name_disable
        [ Destructive None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0 => webvh::handle_agent_name_enable
        [ Destructive None false ],
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the dispatcher's wire-shape contracts + the
    //! cross-crate URI parity harness. Each arm's actual handler
    //! logic is tested in its owning operations module (or by the
    //! Phase 5 integration suite once full AppState scaffolding is
    //! in place).

    use trust_tasks_rs::TrustTask;

    use super::*;

    /// The macro-generated `class_for` returns the authoritative §7.3
    /// classification declared inline next to each handler — the value the PDP
    /// feeds into PolicyInput, independent of the published registry. An
    /// unknown URI is unclassified so callers apply the fail-safe floor.
    #[test]
    #[allow(deprecated)]
    fn class_for_carries_authoritative_classification() {
        use crate::policy::{Discloses, SideEffectLevel};

        let release = class_for(vta_sdk::trust_tasks::TASK_VAULT_RELEASE_0_1)
            .expect("vault/release is classified");
        assert_eq!(release.side_effects, SideEffectLevel::Mutating);
        assert_eq!(release.exposure.discloses, Discloses::Secret);
        assert!(!release.exposure.acts_as_subject);

        let proxy = class_for(vta_sdk::trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1)
            .expect("proxy-login is classified");
        assert!(
            proxy.exposure.acts_as_subject,
            "proxy-login acts as the subject"
        );

        let seed = class_for(vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0)
            .expect("seed export is classified");
        assert_eq!(
            seed.exposure.discloses,
            Discloses::Secret,
            "exporting the mnemonic discloses a secret"
        );

        assert!(
            class_for("https://trusttasks.org/spec/does-not-exist/9.9").is_none(),
            "an unknown URI is unclassified — caller applies the floor"
        );
    }

    #[test]
    fn body_parse_error_wire_shape() {
        let resp = body_parse_error_response("expected `,`");
        // Function returns; full HTTP-shape assertions live in the
        // Phase 5 integration tests once the route is reachable
        // through a real router setup.
        let _ = resp;
    }

    /// Pins the framework's current `TypeUri::from_str` constraint:
    /// the wire-format `type` field MUST use the canonical
    /// `/spec/<slug>/<major.minor>` shape. Flat URIs are rejected.
    ///
    /// If the framework parser relaxes (accepts both), the test fails
    /// on the flat-rejection assert and we know Phase 3 can simplify.
    #[test]
    fn framework_requires_canonical_uri_in_wire_type_field() {
        // Canonical form parses — with HIERARCHICAL slug
        // (`vta/auth/revoke-session`) per SPEC.md slug grammar.
        let canonical = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/spec/auth/revoke-session/0.1",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_ok(),
            "canonical URI must parse: {:?}",
            parsed.err()
        );

        // Flat form is rejected.
        let flat = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/vta/auth/revoke-session/1.0",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&flat).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_err(),
            "flat URI must NOT parse — if this changes, the framework \
             relaxed its parser and Phase 3 design can simplify"
        );
    }

    #[test]
    #[allow(deprecated)] // names the dual-accepted passkey-login 0.1 URIs on purpose
    fn phase_2_uri_registry_present() {
        // Compile-time check: every URI we route in `dispatch_typed`
        // is declared in `vta-sdk::trust_tasks`. If a URI gets renamed
        // or removed in vta-sdk, this stops compiling.
        let _ = vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1;
    }

    /// Cross-crate URI parity harness (mirrors webvh-service's T9
    /// invariant). Every URI declared in `vta-sdk::trust_tasks` must
    /// either:
    ///
    /// 1. Be tracked by `dispatched_uris()` (i.e. have a
    ///    [`dispatch_table!`] entry wiring its handler into `dispatch_typed`), OR
    /// 2. Be on the `REST_ROUTED` allowlist (served by dedicated
    ///    unauth REST handlers — passkey login, legacy challenge/
    ///    authenticate/refresh, TEE attestation), OR
    /// 3. Be on the `KNOWN_FEATURE_GATED_URIS` allowlist (feature-
    ///    flagged in vta-service and not compiled in this build).
    ///
    /// See `docs/05-design-notes/trust-task-feature-gating.md` for
    /// the full convention.
    ///
    /// Adding a new URI to `vta-sdk::trust_tasks::ALL_URIS` without
    /// doing one of these three fails this test loudly with the
    /// offending URI in the message.
    #[test]
    fn dispatcher_handles_every_vta_sdk_uri() {
        let dispatched = dispatched_uris();

        for declared in vta_sdk::trust_tasks::ALL_URIS {
            let in_dispatched = dispatched.contains(declared);
            let in_rest_routed = REST_ROUTED.contains(declared);
            let in_feature_gated = KNOWN_FEATURE_GATED_URIS.contains(declared);
            // 0.2 dual-accept URIs are served via the `wire_v0_2` edge
            // transform (down-convert → 0.1 handler → up-convert), not a
            // dedicated `dispatch_typed` arm, so they're tracked here.
            let in_wire_v0_2 = wire_v0_2::WIRE_V0_2_URIS.contains(declared);

            assert!(
                in_dispatched || in_rest_routed || in_feature_gated || in_wire_v0_2,
                "vta-sdk declares URI `{declared}` but it is not tracked in this dispatcher — \
                 either (a) add a `dispatch_table!` entry (`URI => slice::handler`), \
                 (b) add it to `REST_ROUTED` if it lives on a dedicated REST route, \
                 (c) add it to `KNOWN_FEATURE_GATED_URIS` with a comment explaining the gating, or \
                 (d) register it in `wire_v0_2::WIRE_V0_2_URIS` if it's an edge-transformed 0.2 URI"
            );
        }
    }

    /// Every `SUPERSEDED_TASKS` row must name a URI this spine dispatches.
    ///
    /// The table exists so a task can be retired on an observed zero, and the
    /// counter only moves when the spine sees the URI. A row for something the
    /// spine never routes — a REST-routed URI, a typo, a task already deleted —
    /// reads zero forever, which is precisely the "safe to delete" signal,
    /// produced about something that is already gone. That is the route-table
    /// defect from #1042 in the other half of the mechanism, and it is why the
    /// row and the handler have to be pinned to each other rather than each
    /// maintained by hand.
    ///
    /// Fixing a failure: if the task was retired, drop its row (the whole
    /// point of the row has been served). If the URI is a typo, correct it. If
    /// the operation is served by a dedicated REST route rather than the
    /// dispatcher, it belongs in `deprecation::SUPERSEDED` — the route table —
    /// not here.
    #[test]
    fn superseded_tasks_are_dispatched() {
        let dispatched = dispatched_uris();

        for task in crate::deprecation::superseded_tasks_table() {
            let served = dispatched.contains(&task.uri)
                // Feature-gated arms drop out of `dispatched_uris()` when their
                // cfg is off; the allowlist is where the parity harness tracks
                // them, so it is the right second source here too.
                || KNOWN_FEATURE_GATED_URIS.contains(&task.uri);
            assert!(
                served,
                "`{}` is marked superseded but nothing dispatches it, so its counter \
                 reads zero forever and would report the task as safe to retire when \
                 it has already been retired. Drop the row if the task is gone; fix \
                 the URI if it is a typo; move it to `deprecation::SUPERSEDED` if the \
                 operation is served by a REST route rather than this dispatcher.",
                task.uri
            );
        }
    }

    /// A successor must be something the client can actually send instead.
    ///
    /// A row pointing at a URI this VTA does not serve tells a client to
    /// migrate onto a 404 — worse than saying nothing, because the client acts
    /// on it. `REST_ROUTED` counts: the operation is reachable, just not
    /// through this dispatcher.
    #[test]
    fn superseded_task_successors_are_served() {
        let dispatched = dispatched_uris();

        for task in crate::deprecation::superseded_tasks_table() {
            let served = dispatched.contains(&task.successor)
                || KNOWN_FEATURE_GATED_URIS.contains(&task.successor)
                || REST_ROUTED.contains(&task.successor)
                || wire_v0_2::WIRE_V0_2_URIS.contains(&task.successor);
            assert!(
                served,
                "`{}` is advertised as the successor to `{}`, but this VTA does not \
                 serve it — the notice would send a migrating client onto an \
                 unsupported type",
                task.successor, task.uri
            );
        }
    }

    /// The two 0.1→0.2 tables must agree.
    ///
    /// `wire_v0_2::WIRE_SPECS_V0_2` is where a spec is declared dual-accepted;
    /// `deprecation::SUPERSEDED_TASKS` is where the 0.1 form is declared on its
    /// way out. They are separate because only the second carries a reason and
    /// only the first carries the enum paths — but a 0.2 form added without the
    /// matching deprecation row is a task nothing is measuring, which is the
    /// state #1045 exists to end. Adding one entry now requires the other.
    #[test]
    fn every_dual_accepted_spec_marks_its_0_1_form_superseded() {
        for spec in wire_v0_2::WIRE_SPECS_V0_2 {
            let row = crate::deprecation::superseded_task(spec.uri_0_1).unwrap_or_else(|| {
                panic!(
                    "`{}` is dual-accepted at `{}` but its 0.1 form is not in \
                     `deprecation::SUPERSEDED_TASKS`, so nothing counts the callers \
                     still on it and it can never be retired on evidence",
                    spec.uri_0_1, spec.uri_0_2
                )
            });
            assert_eq!(
                row.successor, spec.uri_0_2,
                "`{}` is down-converted from `{}` but its deprecation row points \
                 somewhere else",
                spec.uri_0_1, spec.uri_0_2
            );
        }
    }

    /// Reverse parity harness (#854) — the opposite direction of
    /// [`dispatcher_handles_every_vta_sdk_uri`]. Every URI this service
    /// *serves* — dispatched, REST-routed, feature-gated, or accepted via the
    /// `wire_v0_2` edge transform — must resolve to a published spec in the
    /// Trust-Tasks registry, as vendored by the generated
    /// `trust_tasks_rs::schema_index` this build validates payloads against.
    ///
    /// A URI with no published spec is a live wire contract with no schema,
    /// no registry page, no generated bindings, and no discovery entry. The
    /// known ones are acknowledged per-URI in [`UNSPECCED_DISPATCHED_URIS`]
    /// with their disposition recorded in
    /// `docs/05-design-notes/registry-drift-triage.md`; anything else fails
    /// here, so NEW drift cannot land silently.
    ///
    /// The allowlist is also checked for staleness in both directions: an
    /// entry whose spec has since been published upstream must be removed
    /// (the debt shrinks monotonically), and an entry no longer served is
    /// dead and must be removed too.
    #[test]
    fn every_served_uri_has_a_published_spec_or_is_tracked_debt() {
        let mut served: std::collections::BTreeSet<&str> = dispatched_uris().into_iter().collect();
        served.extend(REST_ROUTED);
        served.extend(KNOWN_FEATURE_GATED_URIS);
        served.extend(wire_v0_2::WIRE_V0_2_URIS);

        let unspecced: Vec<&&str> = served
            .iter()
            .filter(|uri| {
                trust_tasks_rs::schema_index::schema_for(uri).is_none()
                    && !UNSPECCED_DISPATCHED_URIS.contains(uri)
            })
            .collect();
        assert!(
            unspecced.is_empty(),
            "this service serves URIs the published registry (trust-tasks-rs) \
             has no spec for, and they are not acknowledged in \
             UNSPECCED_DISPATCHED_URIS:\n  {}\n\n\
             Author the spec upstream in trustoverip/dtgwg-trust-tasks-tf and \
             bump trust-tasks-rs — growing the allowlist is the wrong fix \
             (see issue #854 and docs/05-design-notes/registry-drift-triage.md).",
            unspecced
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join("\n  ")
        );

        for uri in UNSPECCED_DISPATCHED_URIS {
            assert!(
                trust_tasks_rs::schema_index::schema_for(uri).is_none(),
                "`{uri}` is now published in the registry — remove it from \
                 UNSPECCED_DISPATCHED_URIS so the debt shrinks monotonically"
            );
            assert!(
                served.contains(uri),
                "`{uri}` is in UNSPECCED_DISPATCHED_URIS but this service no \
                 longer serves it — remove the stale entry"
            );
        }
    }

    /// Passkey-VMs: the canonical `…/0.1` URIs are dispatched. The pre-spec
    /// `…/1.0` aliases were removed (the browser plugin migrated to 0.1), so a
    /// 1.0 document now falls through to `UnsupportedType`.
    #[test]
    fn passkey_vms_0_1_dispatched() {
        let dispatched = dispatched_uris();
        let tracked = |u: &&str| dispatched.contains(u) || KNOWN_FEATURE_GATED_URIS.contains(u);
        for v0_1 in [
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
        ] {
            assert!(tracked(&v0_1), "canonical 0.1 URI not dispatched: {v0_1}");
            assert!(v0_1.ends_with("/0.1"), "version-label mismatch for {v0_1}");
        }
    }

    /// Defensive guard against double-tracking. A URI should appear in
    /// exactly one of (`dispatched_uris()`, `REST_ROUTED`,
    /// `KNOWN_FEATURE_GATED_URIS`) — except that `KNOWN_FEATURE_GATED_URIS`
    /// redundantly mirrors a feature-gated `dispatch_table!` entry's URIs when
    /// the feature is on. That redundancy is allowed (the harness tolerates
    /// it); other overlaps would indicate confusion about which transport a URI
    /// uses.
    ///
    /// Specifically: a URI MUST NOT be in BOTH `dispatched_uris()`
    /// AND `REST_ROUTED`. That'd mean two handlers compete for it.
    #[test]
    fn no_uri_is_both_dispatched_and_rest_routed() {
        let dispatched = dispatched_uris();
        for uri in REST_ROUTED {
            assert!(
                !dispatched.contains(uri),
                "URI `{uri}` is in REST_ROUTED but also in a `dispatch_table!` entry — \
                 a URI must live on exactly one transport"
            );
        }
    }
}

#[cfg(all(test, feature = "webvh"))]
mod payload_validation_tests {
    //! Payload schema validation at the gate.
    //!
    //! The defect that put this here: a caller sent `expectedVersionId` — the
    //! optimistic-concurrency precondition — and the handler's type expected
    //! `expected_version_id`. Serde matched no field, nothing rejected the unknown
    //! member, and the precondition never applied. DID updates published with no
    //! lost-update protection, while the caller's own source read as though the
    //! danger were handled.
    //!
    //! The member was not *wrong*. It was **unrecognised**, and nothing was
    //! watching for that.

    use serde_json::{Value, json};
    use trust_tasks_rs::TrustTask;

    const WEBVH_UPDATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

    fn doc(payload: Value) -> TrustTask<Value> {
        serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000042",
            "type": WEBVH_UPDATE,
            "issuer": "did:key:zTestAdmin",
            "recipient": "did:example:vta",
            "issuedAt": "2026-07-14T00:00:00Z",
            "payload": payload,
        }))
        .expect("valid trust task")
    }

    /// The bug, pinned. A safety precondition in the wrong case is now REFUSED,
    /// where before it was silently dropped.
    #[tokio::test]
    async fn a_precondition_in_the_wrong_case_is_refused_not_ignored() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let d = doc(json!({
            "did": "did:webvh:QmScid:example.com:acme",
            "expected_version_id": "3-QmPrior"
        }));

        let reject = super::validate_payload(&state, WEBVH_UPDATE, &d)
            .await
            .expect("an unrecognised member must be refused");

        let body: Value = serde_json::from_slice(&reject.body).unwrap();
        let msg = body.to_string();
        assert!(
            msg.contains("does not conform"),
            "expected a schema-conformance refusal, got: {msg}"
        );
    }

    /// The correct casing passes — the fix must refuse the typo without breaking
    /// the thing it was a typo of.
    #[tokio::test]
    async fn the_correct_casing_passes() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let d = doc(json!({
            "did": "did:webvh:QmScid:example.com:acme",
            "document": { "id": "did:webvh:QmScid:example.com:acme" },
            "expectedVersionId": "3-QmPrior"
        }));
        assert!(
            super::validate_payload(&state, WEBVH_UPDATE, &d)
                .await
                .is_none()
        );
    }

    /// The relay stamps the browser-attested origin into `payload.ext`. A closed
    /// payload that refused the framework's own extension slot would break it.
    #[tokio::test]
    async fn the_ext_slot_the_relay_stamps_an_origin_into_is_permitted() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let d = doc(json!({
            "did": "did:webvh:QmScid:example.com:acme",
            "ext": { "openvtc.origin": "https://control.example.com" }
        }));
        assert!(
            super::validate_payload(&state, WEBVH_UPDATE, &d)
                .await
                .is_none(),
            "closed payloads must still admit `ext`, or the relay cannot stamp an origin"
        );
    }

    /// The payload the CLI actually sends for a partial edit must validate.
    ///
    /// Built by **serialising the real wire type**, not by hand-writing the
    /// JSON. A literal here would only ever encode what the author believed
    /// the type emits, and the defect this pins was precisely a gap between
    /// those two: `UpdateDidWebvhBody` serialised every unset `Option` as an
    /// explicit `null`, and the schema types each member by what it holds —
    /// object, string, integer, array — with none of them nullable. So
    /// `pnm did-mgmt dids edit --label resync` was refused with one complaint
    /// per unset field, and no combination of flags helped: each one removed a
    /// single null and left the others.
    ///
    /// Every sibling body in `did_management` already skipped its `None`s.
    /// This one did not, which made the whole documented CLI edit path
    /// unusable over the trust-task transport.
    #[tokio::test]
    async fn a_partial_edit_from_the_cli_validates() {
        use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;

        // `--label resync --no-confirm`, exactly as the CLI builds it.
        let body = UpdateDidWebvhBody {
            label: Some("resync".into()),
            ..Default::default()
        };
        let mut payload = serde_json::to_value(&body).expect("serialises");
        // `UpdateDidWithDid` flattens the body alongside `did`.
        payload
            .as_object_mut()
            .expect("object")
            .insert("did".into(), json!("did:webvh:QmScid:example.com:acme"));

        assert!(
            !payload.to_string().contains("null"),
            "the CLI's own payload must carry no nulls: {payload}"
        );

        let reject = super::validate_payload(&state, WEBVH_UPDATE, &doc(payload.clone())).await;
        assert!(
            reject.is_none(),
            "a label-only edit must validate, got: {:?}",
            reject.map(|r| String::from_utf8_lossy(&r.body).into_owned())
        );
    }

    /// The same payload with the nulls put back is refused — so the test above
    /// pins the serialisation rather than passing incidentally.
    #[tokio::test]
    async fn the_null_form_that_broke_the_cli_is_still_refused() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let d = doc(json!({
            "did": "did:webvh:QmScid:example.com:acme",
            "document": Value::Null,
            "preRotationCount": Value::Null,
            "witnesses": Value::Null,
            "watchers": Value::Null,
            "ttl": Value::Null,
            "label": "resync",
            "expectedVersionId": Value::Null,
        }));
        assert!(
            super::validate_payload(&state, WEBVH_UPDATE, &d)
                .await
                .is_some(),
            "an explicit null is not a valid member value — if this passes, the \
             schema stopped typing its members and the fix above proves nothing"
        );
    }

    #[tokio::test]
    async fn an_invented_member_is_refused() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let d = doc(json!({ "did": "did:webvh:x", "skipApproval": true }));
        assert!(
            super::validate_payload(&state, WEBVH_UPDATE, &d)
                .await
                .is_some()
        );
    }

    /// A task with no published spec dispatches unvalidated by default — many do —
    /// but an operator can choose to fail closed.
    #[tokio::test]
    async fn an_unspecced_task_proceeds_by_default_and_can_be_refused() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        // No published spec — one of the remaining few, and the set keeps
        // shrinking. This fixture named `vta/webvh/dids/create/1.0` until
        // trust-tasks #240 specified it and trust-tasks-rs 0.11 made the schema
        // resolvable, at which point the task validated and the fail-closed
        // half of this test stopped proving anything. That is the growth the
        // comment here has always pointed at, arriving.
        //
        // So the fixture is now *derived* rather than named: whatever is still
        // unspecced at run time. Naming one is what rotted twice, and the fix
        // both times was to name a different one — which only sets the next
        // failure. Deriving it means the test follows the debt down instead of
        // breaking each time a spec lands, and the assertion never weakens.
        let Some(unspecced) = super::UNSPECCED_DISPATCHED_URIS
            .iter()
            .copied()
            .find(|u| trust_tasks_rs::schema_index::schema_for(u).is_none())
        else {
            // Every dispatched task is specced. That is the goal, and when it
            // arrives this test has nothing left to say — delete it, and the
            // `require_payload_schema` escape hatch it exercises with it.
            return;
        };
        // Payload shape is irrelevant: the task is unvalidatable by definition,
        // which is the property under test.
        let d = doc(json!({}));

        assert!(
            super::validate_payload(&state, unspecced, &d)
                .await
                .is_none(),
            "by default an unvalidatable task still dispatches — refusing it would \
             break the many tasks that have no spec yet"
        );

        state.config.write().await.policy.require_payload_schema = true;
        assert!(
            super::validate_payload(&state, unspecced, &d)
                .await
                .is_some(),
            "an operator who would rather fail closed can"
        );
    }
}

#[cfg(test)]
mod superseded_task_dispatch_tests {
    //! The Trust-Task deprecation signal, end to end through the spine.
    //!
    //! `deprecation.rs` covers the table and the annotation in isolation. What
    //! those cannot show is that the spine *reaches* them — and a signal that
    //! is silently not attached reads exactly like "nobody sends this any
    //! more", which is the reading the whole mechanism exists to trust. That is
    //! why the REST half has `superseded_route_advertises_its_trust_task_successor`
    //! against a live router rather than a unit test of `superseded()`.

    use serde_json::{Value, json};

    use crate::deprecation::DEPRECATION_MEMBER;
    use crate::test_support::{build_signing_test_app_state, super_admin_claims};
    use crate::trust_tasks::transport::TransportConfidentiality;

    /// Dispatch `type_uri` with `payload` and return the response document.
    async fn dispatch(type_uri: &str, payload: Value) -> Value {
        let (state, _dir) = build_signing_test_app_state().await;
        let vta_did = state
            .config
            .read()
            .await
            .vta_did
            .clone()
            .expect("the signing test state configures a vta_did");
        let body = serde_json::to_vec(&json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": "did:key:zTestAdmin",
            "recipient": vta_did,
            "issuedAt": "2026-08-22T00:00:00Z",
            "payload": payload,
        }))
        .unwrap();

        let outcome = super::dispatch_trust_task_core(
            &state,
            &super_admin_claims(),
            &body,
            TransportConfidentiality::HopByHop,
        )
        .await;
        serde_json::from_slice(&outcome.body).expect("a response document")
    }

    #[tokio::test]
    #[allow(deprecated)] // sends a deprecated URI on purpose — that is the subject
    async fn a_superseded_task_names_its_successor_in_the_response() {
        let uri = vta_sdk::trust_tasks::TASK_DEVICE_LIST_0_1;
        let doc = dispatch(uri, json!({})).await;

        // Non-vacuity: a rejection document would also carry the notice (that
        // is deliberate — see the spine), but then this test would be
        // asserting nothing about the case that matters, which is a task that
        // still works and is on its way out.
        assert_eq!(
            doc["type"],
            format!("{uri}#response"),
            "expected a success response to annotate, got: {doc}"
        );

        let notice = &doc[DEPRECATION_MEMBER];
        assert_eq!(
            notice["supersededBy"],
            vta_sdk::trust_tasks::TASK_DEVICE_LIST_0_2,
            "the response must name what to send instead, so a client can act \
             rather than guess; got document: {doc}"
        );
        assert!(
            notice["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "the notice must say why, got: {notice}"
        );
    }

    #[tokio::test]
    #[allow(deprecated)] // sends a deprecated URI on purpose — that is the subject
    async fn a_rejected_superseded_task_still_names_its_successor() {
        // A client whose request was refused is the client most in need of the
        // successor: it is about to retry, and it can retry onto the right URI.
        // `device/register/0.1` requires members an empty payload does not
        // carry, so this is a schema rejection, not a handler failure.
        let uri = vta_sdk::trust_tasks::TASK_DEVICE_REGISTER_0_1;
        let doc = dispatch(uri, json!({})).await;

        assert_eq!(
            doc["payload"]["code"], "malformedRequest",
            "expected a rejection to annotate, got: {doc}"
        );
        assert_eq!(
            doc[DEPRECATION_MEMBER]["supersededBy"],
            vta_sdk::trust_tasks::TASK_DEVICE_REGISTER_0_2,
            "a rejection must carry the successor too: {doc}"
        );
    }

    #[tokio::test]
    async fn a_current_task_carries_no_notice() {
        // The counterpart the route table learned to need: a signal attached to
        // everything is a signal about nothing. `auth/whoami/0.1` is current.
        let doc = dispatch(vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1, json!({})).await;
        assert!(
            doc.get(DEPRECATION_MEMBER).is_none(),
            "a task that is not superseded must not be advertised as one: {doc}"
        );
    }

    #[tokio::test]
    async fn the_payload_is_untouched_by_the_notice() {
        // The notice rides the document top level precisely so the payload
        // stays exactly what the spec says it is — every published payload
        // schema is `additionalProperties: false` and the generated `Response`
        // types are `deny_unknown_fields`. Assert it on a real dispatch, not
        // just on the annotation helper.
        #[allow(deprecated)]
        let uri = vta_sdk::trust_tasks::TASK_DEVICE_LIST_0_1;
        let doc = dispatch(uri, json!({})).await;

        let payload = doc.get("payload").expect("a response carries a payload");
        assert!(
            payload.get(DEPRECATION_MEMBER).is_none() && payload.get("ext").is_none(),
            "the notice must not reach the payload: {payload}"
        );
    }
}

/// Framework 0.5.0 Consumer Requirements item 13 — the freshness bounds.
#[cfg(test)]
mod freshness_bounds {
    use super::*;
    use chrono::{TimeDelta, Utc};
    use serde_json::json;

    fn doc(issued_at: Option<&str>, expires_at: Option<&str>) -> TrustTask<Value> {
        let mut v = json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1,
            "issuer": "did:key:zTestAdmin",
            "payload": {},
        });
        if let Some(i) = issued_at {
            v["issuedAt"] = json!(i);
        }
        if let Some(e) = expires_at {
            v["expiresAt"] = json!(e);
        }
        serde_json::from_value(v).expect("a document")
    }

    #[test]
    fn a_document_inside_the_skew_window_is_accepted() {
        let now = Utc::now();
        let soon = (now + TimeDelta::seconds(30)).to_rfc3339();
        assert!(
            check_freshness_bounds(&doc(Some(&soon), None), now).is_ok(),
            "a modestly fast producer clock is the ordinary case, not a defect"
        );
    }

    #[test]
    fn a_future_dated_document_is_malformed_not_expired() {
        let now = Utc::now();
        let far = (now + TimeDelta::seconds(600)).to_rfc3339();
        let err = check_freshness_bounds(&doc(Some(&far), None), now)
            .expect_err("beyond the skew tolerance must be refused");
        assert!(
            matches!(err, RejectReason::MalformedRequest { .. }),
            "it must be malformed, never expired: `expired` names a document \
             that was once acceptable and tells the producer to wait, when \
             what it must do is reissue. Got {err:?}"
        );
    }

    #[test]
    fn an_expiry_at_or_before_issuance_is_malformed() {
        let now = Utc::now();
        let issued = now.to_rfc3339();
        for expiry in [now, now - TimeDelta::seconds(1)] {
            let err = check_freshness_bounds(&doc(Some(&issued), Some(&expiry.to_rfc3339())), now)
                .expect_err("a validity interval containing no instant is malformed");
            assert!(
                matches!(err, RejectReason::MalformedRequest { .. }),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn a_document_without_issued_at_is_not_refused_here() {
        // Item 13 bounds the timestamps a document carries; it does not
        // require one. Requiring `issuedAt` is the *specification's* job for a
        // consequential task, enforced by that task's schema.
        assert!(check_freshness_bounds(&doc(None, None), Utc::now()).is_ok());
    }
}

/// Exercise the happy path of tasks the suite otherwise never reaches.
///
/// These are not tests of handler *logic* — every arm has that in its owning
/// operations module. They exist so the response-conformance gate in
/// `test_support::response_conformance` gets to look at each task's real
/// success response at all.
///
/// The gap they close is the one `scripts/trust-task-coverage.sh` measures: the
/// gate was validating 29 of 109 checkable tasks, and the seventy-odd it had
/// never seen included the signing oracle. A gate that has never observed
/// `keys/sign` is not evidence about `keys/sign`.
///
/// Each test asserts a success document came back and lets the layer do the
/// schema work — a violation replaces the response, so the `type` assertion
/// below is what fails when a shape drifts.
#[cfg(test)]
mod response_coverage {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    use vta_sdk::trust_tasks as t;

    use crate::test_support::build_signing_test_app_state;

    /// Dispatch as a super-admin and require a success document back.
    ///
    /// Returns the response `payload` so a test can chain (e.g. take a key id
    /// out of `keys/create` and sign with it).
    async fn ok(state: &crate::server::AppState, uri: &str, payload: Value) -> Value {
        let vta_did = state.config.read().await.vta_did.clone().expect("vta_did");
        let body = serde_json::to_vec(&json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": uri,
            "issuer": "did:key:zTestAdmin",
            "recipient": vta_did,
            "issuedAt": "2026-08-26T00:00:00Z",
            "payload": payload,
        }))
        .expect("envelope serialises");

        let outcome = super::dispatch_trust_task_core(
            state,
            &crate::test_support::super_admin_claims(),
            &body,
            transport::TransportConfidentiality::HopByHop,
        )
        .await;
        let doc: Value = serde_json::from_slice(&outcome.body).expect("a response document");
        assert_eq!(
            doc["type"],
            format!("{uri}#response"),
            "expected a success response from {uri}, got: {doc}"
        );
        doc["payload"].clone()
    }

    /// Mint a key and return its id, so the read/sign/rename paths have a real
    /// subject rather than the VTA's own signing key (which they must not
    /// rename or revoke).
    async fn a_key(state: &crate::server::AppState, label: &str) -> String {
        let p = ok(
            state,
            t::TASK_KEYS_CREATE_0_1,
            json!({ "keyType": "ed25519", "derivationPath": "m/26'/2'/0'/0'", "label": label }),
        )
        .await;
        p["key"]["keyId"]
            .as_str()
            .or_else(|| p["keyId"].as_str())
            .unwrap_or_else(|| panic!("keys/create must name the key it made: {p}"))
            .to_owned()
    }

    /// A context to hang scoped state off. Also covers
    /// `vta/contexts/create/1.0`.
    async fn a_context(state: &crate::server::AppState, id: &str) {
        ok(
            state,
            t::TASK_CONTEXTS_CREATE_1_0,
            json!({ "id": id, "name": id }),
        )
        .await;
    }

    /// The context family's read and write paths.
    #[tokio::test]
    async fn contexts_lifecycle() {
        let (state, _dir) = build_signing_test_app_state().await;
        a_context(&state, "cov-contexts").await;
        ok(&state, t::TASK_CONTEXTS_LIST_1_0, json!({})).await;
        ok(
            &state,
            t::TASK_CONTEXTS_GET_1_0,
            json!({ "id": "cov-contexts" }),
        )
        .await;
        ok(
            &state,
            t::TASK_CONTEXTS_UPDATE_1_0,
            json!({ "id": "cov-contexts", "name": "renamed" }),
        )
        .await;
        // Preview before delete: the pair exists so an operator can see what a
        // delete would take with it, so cover them in that order.
        ok(
            &state,
            t::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
            json!({ "id": "cov-contexts" }),
        )
        .await;
        ok(
            &state,
            t::TASK_CONTEXTS_DELETE_1_0,
            json!({ "id": "cov-contexts" }),
        )
        .await;
    }

    /// The app-state key/value family, single and batch.
    #[tokio::test]
    async fn app_state_lifecycle() {
        let (state, _dir) = build_signing_test_app_state().await;
        a_context(&state, "cov-appstate").await;
        let base = json!({ "contextId": "cov-appstate", "namespace": "cov", "key": "k1" });

        let mut put = base.clone();
        put["value"] = json!({ "hello": "world" });
        ok(&state, t::TASK_VTA_APP_STATE_PUT_1_0, put).await;
        ok(&state, t::TASK_VTA_APP_STATE_GET_1_0, base.clone()).await;
        ok(
            &state,
            t::TASK_VTA_APP_STATE_LIST_1_0,
            json!({ "contextId": "cov-appstate", "includeValues": true }),
        )
        .await;
        ok(
            &state,
            t::TASK_VTA_APP_STATE_PUT_MANY_1_0,
            json!({
                "contextId": "cov-appstate",
                "namespace": "cov",
                // `writes`, not `entries` — and each write is a put payload
                // minus the context and namespace the batch supplies.
                "writes": [{ "key": "k2", "value": {"n": 1} }],
            }),
        )
        .await;
        ok(
            &state,
            t::TASK_VTA_APP_STATE_GET_MANY_1_0,
            json!({ "contextId": "cov-appstate", "namespace": "cov", "keys": ["k1", "k2"] }),
        )
        .await;
        ok(&state, t::TASK_VTA_APP_STATE_DELETE_1_0, base).await;
    }

    /// The agent-memory family.
    #[tokio::test]
    async fn memory_lifecycle() {
        let (state, _dir) = build_signing_test_app_state().await;
        a_context(&state, "cov-memory").await;
        ok(
            &state,
            t::TASK_VTA_MEMORY_PUT_0_1,
            json!({ "contextId": "cov-memory", "key": "m1", "value": "remembered" }),
        )
        .await;
        ok(
            &state,
            t::TASK_VTA_MEMORY_LIST_0_1,
            json!({ "contextId": "cov-memory" }),
        )
        .await;
        ok(
            &state,
            t::TASK_VTA_MEMORY_DELETE_0_1,
            json!({ "contextId": "cov-memory", "key": "m1" }),
        )
        .await;
    }

    #[tokio::test]
    async fn keys_show_and_sign() {
        let (state, _dir) = build_signing_test_app_state().await;
        let key_id = a_key(&state, "coverage-show-sign").await;

        ok(&state, t::TASK_KEYS_SHOW_0_1, json!({ "keyId": key_id })).await;

        // The signing oracle. `payload` is base64url without padding, and the
        // maintainer signs those bytes verbatim.
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"coverage");
        ok(
            &state,
            t::TASK_KEYS_SIGN_0_1,
            json!({ "keyId": key_id, "payload": payload, "algorithm": "EdDSA" }),
        )
        .await;
    }

    /// An internal key is actually internal.
    ///
    /// This is the assertion whose absence let `pnm keys create --internal`
    /// lie. The CLI prints a non-recoverable-key warning, requires the operator
    /// to type "i understand this key cannot be recovered", and then called a
    /// client that built its wire body with `internal: None` hardcoded — so the
    /// operator was handed an ordinary seed-derived key that *is* in backups
    /// and *is* exportable, believing the opposite.
    ///
    /// It could not have worked even if the client had forwarded the flag:
    /// `keys/create/0.1` was `additionalProperties: false` with no `internal`
    /// member, so the dispatch spine rejected the document. The capability
    /// existed at both ends and was unreachable over the wire, which is what
    /// dtgwg-trust-tasks-tf#269 fixed.
    ///
    /// `origin` is the check that matters, and it is the one the CLI already
    /// makes: a maintainer that ignored the member returns `derived`, and that
    /// difference is the only reliable signal the request was honoured.
    #[tokio::test]
    async fn an_internal_key_is_actually_internal() {
        let (state, _dir) = build_signing_test_app_state().await;
        let p = ok(
            &state,
            t::TASK_KEYS_CREATE_0_1,
            json!({ "keyType": "ed25519", "internal": true, "label": "unexportable" }),
        )
        .await;
        let record = p.get("key").unwrap_or(&p);
        assert_eq!(
            record["origin"], "internal",
            "the key must come back marked internal — a `derived` here is \
             exactly the silent downgrade the operator was warned about and \
             did not get: {p}"
        );
        // An internal key derives from no seed, and the shared `KeyRecord`
        // component says `derivationPath` is the path "the key was derived at,
        // when `origin` is `derived`", absent otherwise. This service instead
        // records the sentinel string `"internal"`, with a comment saying it
        // "names the origin instead, so a reader cannot mistake it for
        // something re-derivable" — reasoning that predates `origin` gaining
        // an `internal` value (dtgwg-trust-tasks-tf#269), which now carries
        // that fact properly.
        //
        // Asserted as-is rather than fixed here: making `KeyRecord`'s
        // `derivation_path` an `Option` touches 84 construction sites and is
        // its own change. Worth knowing that the response-conformance gate
        // cannot catch this — the schema types the member `string`, so a
        // sentinel validates cleanly. It is a semantic divergence, and only a
        // reader notices.
        assert_eq!(
            record["derivationPath"], "internal",
            "the sentinel is the current behaviour; when `derivationPath` \
             becomes optional this should assert absence instead: {p}"
        );
    }

    /// A create with no `derivationPath` succeeds.
    ///
    /// The spec says "omitting it leaves the choice to the custodian", and the
    /// operation layer has always auto-derived from the context. Only the wire
    /// type disagreed, so a conforming client that omitted it got
    /// `malformedRequest` — and the SDK hid that by sending `""`.
    #[tokio::test]
    async fn a_create_without_a_derivation_path_succeeds() {
        let (state, _dir) = build_signing_test_app_state().await;
        // The context has to exist: with no path *and* no context there is
        // nothing for the custodian to derive from, which the operation layer
        // refuses on its own terms. Creating it also covers
        // `vta/contexts/create/1.0`.
        ok(
            &state,
            t::TASK_CONTEXTS_CREATE_1_0,
            json!({ "id": "coverage-ctx", "name": "Coverage" }),
        )
        .await;
        ok(
            &state,
            t::TASK_KEYS_CREATE_0_1,
            json!({ "keyType": "ed25519", "contextId": "coverage-ctx" }),
        )
        .await;
    }

    #[tokio::test]
    async fn keys_rename_then_revoke() {
        let (state, _dir) = build_signing_test_app_state().await;
        let key_id = a_key(&state, "coverage-rename").await;

        // `newKeyId` is an identifier, not a path — `/` is rejected, and the
        // key id defaults to the derivation path, so it cannot be reused here.
        let renamed = "coverage-renamed-key".to_string();
        ok(
            &state,
            t::TASK_KEYS_RENAME_0_1,
            json!({ "keyId": key_id, "newKeyId": renamed }),
        )
        .await;

        // Revoke last: it is terminal, and revoking under the new id also
        // proves the rename took on the record rather than only in the reply.
        ok(
            &state,
            t::TASK_KEYS_REVOKE_0_1,
            json!({ "keyId": renamed, "reason": "coverage" }),
        )
        .await;
    }
}
