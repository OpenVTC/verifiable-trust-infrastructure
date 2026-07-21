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
//! malformed body produces a `trust-task-error/0.1` document (per
//! framework SPEC §8.5) instead of axum's plain-text 400 default.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

mod acl;
mod audit;
mod auth;
mod backup;
mod config;
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
mod keys;
mod management;
mod memory;
mod messaging;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
mod passkey_vms;
pub(crate) mod planner;
mod policy_gate;
#[cfg(feature = "webvh")]
mod provision_integration;
mod replay;
mod seeds;
mod task_consent;
// `pub(crate)` so the REST routes (`routes::acl`, `routes::contexts`) can
// reach the `RequireStepUp` extractor + op markers. The step-up *engine* lives
// in `operations::step_up` (P2.4); this module holds only the transport
// wrappers (the trust-task `require_step_up`/`handle_approve_response` and the
// REST `RequireStepUp` extractor) over it.
pub(crate) mod step_up;
mod step_up_policy;
pub(crate) use step_up::{
    AclChangeRoleOp, AclGrantOp, AclRevokeOp, AclSwapKeyOp, ContextDeleteOp, RequireStepUp,
};
mod vault;
#[cfg(feature = "webvh")]
mod webvh;
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
    vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_REQUEST_1_0,
    // WebVH-DID-lifecycle slice — requires `webvh`. The `dispatch_table!`
    // entries list the same URIs and are tracked by the parity harness when
    // `webvh` is on; this allowlist covers builds where `webvh` is off.
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_ADD_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_UPDATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_LOG_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
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
        #[cfg(test)]
        #[allow(deprecated)]
        fn dispatched_uris() -> Vec<&'static str> {
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
/// `trust-task-error/0.1` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (the workspace-wide 1 MB cap applies).
pub async fn dispatch_trust_task(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    Ok(dispatch_trust_task_core(&state, &auth, &body)
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
) -> TrustTaskOutcome {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => return body_parse_error_response(&e.to_string()),
    };

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
        let vta_did = state.config.read().await.vta_did.clone();
        if let Some(my_vid) = vta_did.as_deref()
            && let Err(reason) = doc.validate_basic(chrono::Utc::now(), my_vid)
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

    if let Some((action, resource, context_id, detail)) = vault_audit {
        let label = vault_audit_outcome_label(&outcome);
        if let Err(e) = crate::audit::record_with_detail(
            &state.audit_ks,
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
#[cfg(feature = "didcomm")]
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
    vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_POLICY_0_2 => step_up_policy::handle_set_step_up_policy
        [ Mutating None false ],
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
    vta_sdk::trust_tasks::TASK_ACL_LIST_1_0 => acl::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0 => acl::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_GET_1_0 => acl::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0 => acl::handle_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0 => acl::handle_delete
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_ACL_SWAP_KEY_1_0 => acl::handle_swap_key
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
    vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0 => keys::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0 => keys::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_KEYS_GET_1_0 => keys::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0 => keys::handle_rename
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0 => keys::handle_revoke
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0 => keys::handle_sign
        [ None None true ],
    vta_sdk::trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_1_0 => keys::handle_derive_and_sign
        [ Mutating None true ],
    vta_sdk::trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_1_0 => keys::handle_derive_and_sign_document
        [ Mutating None true ],
    // ─── Seeds slice ─────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0 => seeds::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0 => seeds::handle_rotate
        [ Destructive None false ],
    vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 => seeds::handle_export_mnemonic
        [ None Secret false ],
    // ─── Audit slice ─────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_AUDIT_LIST_LOGS_1_0 => audit::handle_list_logs
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0 => audit::handle_get_retention
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0 => audit::handle_update_retention
        [ Mutating None false ],
    // ─── Discovery ───────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0 => discovery::handle_capabilities
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
    // ─── Config slice ────────────────────────────────────────────
    vta_sdk::trust_tasks::TASK_CONFIG_GET_1_0 => config::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONFIG_UPDATE_1_0 => config::handle_update
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
    // ─── DID-templates slice (global) ────────────────────────────
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_1_0 => did_templates::handle_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_1_0 => did_templates::handle_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_1_0 => did_templates::handle_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_UPDATE_1_0 => did_templates::handle_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_DELETE_1_0 => did_templates::handle_delete
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_1_0 => did_templates::handle_render
        [ None Metadata false ],
    // ─── DID-templates slice (context-scoped) ────────────────────
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_LIST_1_0 => did_templates::handle_context_list
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_CREATE_1_0
        => did_templates::handle_context_create
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_GET_1_0 => did_templates::handle_context_get
        [ None Metadata false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_UPDATE_1_0
        => did_templates::handle_context_update
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_DELETE_1_0
        => did_templates::handle_context_delete
        [ Mutating None false ],
    vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_RENDER_1_0
        => did_templates::handle_context_render
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
    vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_REQUEST_1_0
        => provision_integration::handle_request
        [ Mutating Secret false ],
    // ─── WebVH-DID-lifecycle slice (feature-gated: webvh) ────────
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0 => webvh::handle_servers_list
        [ None Metadata false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_ADD_1_0 => webvh::handle_servers_add
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_UPDATE_1_0 => webvh::handle_servers_update
        [ Mutating None false ],
    #[cfg(feature = "webvh")]
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0 => webvh::handle_servers_remove
        [ Mutating None false ],
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
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_LOG_1_0 => webvh::handle_dids_get_log
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
    // Agent-name park/resume. Both publish a new signed version (and so
    // rotate the update key exactly like any update), and both change a
    // public name binding — Destructive, like `dids/update`, per the
    // rationale above. Classifying them Destructive is what makes the
    // wallet force a cross-device type-to-confirm, which is the elevation
    // for these ops (the hosting endpoint is deliberately not step-up-gated
    // — the VTA can't hold an aal2 session).
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
        // No published spec — one of many. (`vta/memory/list` HAS one, which is
        // itself the point: the set of validatable tasks is growing.)
        const UNSPECCED: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.0";
        let d = doc(json!({ "contextId": "default" }));

        assert!(
            super::validate_payload(&state, UNSPECCED, &d)
                .await
                .is_none(),
            "by default an unvalidatable task still dispatches — refusing it would \
             break the many tasks that have no spec yet"
        );

        state.config.write().await.policy.require_payload_schema = true;
        assert!(
            super::validate_payload(&state, UNSPECCED, &d)
                .await
                .is_some(),
            "an operator who would rather fail closed can"
        );
    }
}
