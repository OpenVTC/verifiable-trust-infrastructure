//! The administrator's operational verbs on the signed-document spine: the
//! trust-registry reconciler, the audit log, the runtime configuration, admin
//! onboarding invites, and the auth service's sessions.
//!
//! | task | signed by | authority (the signer's ACL row, read now) |
//! |---|---|---|
//! | `vtc/registry/diagnostics/0.1` | an administrator | `Admin` |
//! | `vtc/registry/sync-jobs/{list,retry,discard}/0.1` | an administrator | `Admin` |
//! | `vtc/registry/records/list/0.1` | an administrator | `Admin` |
//! | `audit/list/0.1`, `audit/verify/0.1` | an unrestricted administrator | `Admin`, no context scope |
//! | `config/{show,patch,reload,restart}/0.1` | an administrator | `Admin` |
//! | `vtc/admin/invites/{list,revoke}/0.1` | an administrator | `Admin` |
//! | `vtc/admin/invites/create/0.1` | an unrestricted administrator | `Admin`, no context scope; writing the invitee's unrestricted entry also takes the inviter's passkey gesture bound to this invite, and another unrestricted admin's consent |
//! | `auth/sessions/list/0.1` | any member | their own sessions, and those of every subject whose access they could withdraw |
//! | `auth/revoke-session/0.2` | any member | the same rule |
//!
//! Every one arrives here the same way over TSP, DIDComm or HTTPS. None of
//! them has a REST route except `audit/verify`, whose bearer route stays while
//! `vtc-client`'s `audit_verify` calls it.
//!
//! # Where the authority comes from
//!
//! The bearer routes these replaced took the caller's session: `AdminAuth`,
//! `SuperAdminAuth`, `ManageAuth`. A document has no session, so each arm reads
//! the **verified signer's** ACL row at execution time
//! ([`super::admin_signer`], which also honours a console-key delegation) and
//! asks the same question the extractor asked. Where a route read a session's
//! step-up (the admin invite that writes an unrestricted entry), the gesture is
//! instead bound to this one document ([`crate::acl::bound_step_up`]).

use serde_json::Value;
use trust_tasks_rs::specs::audit::{list::v0_1 as audit_list, verify::v0_1 as audit_verify};
use trust_tasks_rs::specs::auth::revoke_session::v0_2 as revoke_session;
use trust_tasks_rs::specs::auth::sessions::list::v0_1 as sessions_list;
use trust_tasks_rs::specs::config::{
    patch::v0_1 as config_patch, reload::v0_1 as config_reload, restart::v0_1 as config_restart,
    show::v0_1 as config_show,
};
use trust_tasks_rs::specs::vtc::admin::invites::{
    create::v0_1 as invite_create, list::v0_1 as invite_list, revoke::v0_1 as invite_revoke,
};
use trust_tasks_rs::specs::vtc::registry::{
    diagnostics::v0_1 as diagnostics, records::list::v0_1 as records_list,
    sync_jobs::discard::v0_1 as sync_discard, sync_jobs::list::v0_1 as sync_list,
    sync_jobs::retry::v0_1 as sync_retry,
};
use trust_tasks_rs::{Payload, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::extractor::AuthClaims;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

pub(crate) const DIAGNOSTICS_TYPE: &str = <diagnostics::Payload as Payload>::TYPE_URI;
pub(crate) const SYNC_JOBS_LIST_TYPE: &str = <sync_list::Payload as Payload>::TYPE_URI;
pub(crate) const SYNC_JOBS_RETRY_TYPE: &str = <sync_retry::Payload as Payload>::TYPE_URI;
pub(crate) const SYNC_JOBS_DISCARD_TYPE: &str = <sync_discard::Payload as Payload>::TYPE_URI;
pub(crate) const RECORDS_LIST_TYPE: &str = <records_list::Payload as Payload>::TYPE_URI;
pub(crate) const AUDIT_LIST_TYPE: &str = <audit_list::Payload as Payload>::TYPE_URI;
pub(crate) const AUDIT_VERIFY_TYPE: &str = <audit_verify::Payload as Payload>::TYPE_URI;
pub(crate) const CONFIG_SHOW_TYPE: &str = <config_show::Payload as Payload>::TYPE_URI;
pub(crate) const CONFIG_PATCH_TYPE: &str = <config_patch::Payload as Payload>::TYPE_URI;
pub(crate) const CONFIG_RELOAD_TYPE: &str = <config_reload::Payload as Payload>::TYPE_URI;
pub(crate) const CONFIG_RESTART_TYPE: &str = <config_restart::Payload as Payload>::TYPE_URI;
pub(crate) const INVITES_LIST_TYPE: &str = <invite_list::Payload as Payload>::TYPE_URI;
pub(crate) const INVITES_CREATE_TYPE: &str = <invite_create::Payload as Payload>::TYPE_URI;
pub(crate) const INVITES_REVOKE_TYPE: &str = <invite_revoke::Payload as Payload>::TYPE_URI;
pub(crate) const SESSIONS_LIST_TYPE: &str = <sessions_list::Payload as Payload>::TYPE_URI;
pub(crate) const REVOKE_SESSION_TYPE: &str = <revoke_session::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    DIAGNOSTICS_TYPE,
    SYNC_JOBS_LIST_TYPE,
    SYNC_JOBS_RETRY_TYPE,
    SYNC_JOBS_DISCARD_TYPE,
    RECORDS_LIST_TYPE,
    AUDIT_LIST_TYPE,
    AUDIT_VERIFY_TYPE,
    CONFIG_SHOW_TYPE,
    CONFIG_PATCH_TYPE,
    CONFIG_RELOAD_TYPE,
    CONFIG_RESTART_TYPE,
    INVITES_LIST_TYPE,
    INVITES_CREATE_TYPE,
    INVITES_REVOKE_TYPE,
    SESSIONS_LIST_TYPE,
    REVOKE_SESSION_TYPE,
];

/// Tasks whose response carries a bearer secret: an admin invite's claim code
/// and install URL. The duplicate-execution record keeps no copy of these, so
/// the secret does not sit in `accepted_ids` for the acceptance window.
pub(crate) const SECRET_RESPONSES: &[&str] = &[INVITES_CREATE_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        DIAGNOSTICS_TYPE => handle_diagnostics(state, ctx, doc).await,
        SYNC_JOBS_LIST_TYPE => handle_sync_jobs_list(state, ctx, doc).await,
        SYNC_JOBS_RETRY_TYPE => handle_sync_jobs_retry(state, ctx, doc).await,
        SYNC_JOBS_DISCARD_TYPE => handle_sync_jobs_discard(state, ctx, doc).await,
        RECORDS_LIST_TYPE => handle_records_list(state, ctx, doc).await,
        AUDIT_LIST_TYPE => handle_audit_list(state, ctx, doc).await,
        AUDIT_VERIFY_TYPE => handle_audit_verify(state, ctx, doc).await,
        CONFIG_SHOW_TYPE => handle_config_show(state, ctx, doc).await,
        CONFIG_PATCH_TYPE => handle_config_patch(state, ctx, doc).await,
        CONFIG_RELOAD_TYPE => handle_config_reload(state, ctx, doc).await,
        CONFIG_RESTART_TYPE => handle_config_restart(state, ctx, doc).await,
        INVITES_LIST_TYPE => handle_invites_list(state, ctx, doc).await,
        INVITES_CREATE_TYPE => handle_invites_create(state, ctx, doc).await,
        INVITES_REVOKE_TYPE => handle_invites_revoke(state, ctx, doc).await,
        SESSIONS_LIST_TYPE => handle_sessions_list(state, ctx, doc).await,
        REVOKE_SESSION_TYPE => handle_revoke_session(state, ctx, doc).await,
        _ => return None,
    })
}

/// The signer as an administrator (the bearer routes' `AdminAuth`), and its
/// payload validated against the published schema.
async fn admin_with<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(AuthClaims, P), TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = admin_signer(state, ctx, doc).await?;
    let payload = parse_spec_payload::<P>(doc)?;
    Ok((actor, payload))
}

/// As [`admin_with`], for an **unrestricted** administrator (the bearer
/// routes' `SuperAdminAuth`): an admin scoped to some contexts is refused.
async fn super_admin_with<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(AuthClaims, P), TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = admin_signer(state, ctx, doc).await?;
    actor
        .require_super_admin()
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let payload = parse_spec_payload::<P>(doc)?;
    Ok((actor, payload))
}

/// Who is asking about sessions: an administrator exactly as
/// [`admin_signer`] resolves one, or any other signer holding a live ACL row,
/// who may manage only their own sessions. A signer the community holds no
/// entry for is refused, as the bearer session it would need was.
async fn session_actor(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<AuthClaims, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };
    if let Ok(admin) = admin_signer(state, ctx, doc).await {
        return Ok(admin);
    }
    let entry = crate::acl::get_acl_entry(&state.acl_ks, &signer)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    match entry {
        Some(entry) if !entry.is_expired(crate::auth::session::now_epoch()) => Ok(AuthClaims {
            did: signer,
            role: Role::Reader,
            ..Default::default()
        }),
        _ => Err(app_error_to_reject(
            doc,
            &AppError::Forbidden("the signer holds no entry in this community".into()),
        )),
    }
}

// ─── the trust-registry reconciler ───────────────────────────────────────

async fn handle_diagnostics(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<diagnostics::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::health::diagnostics(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_sync_jobs_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<sync_list::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::registry_admin::sync_jobs_list(state, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_sync_jobs_retry(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<sync_retry::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::registry_admin::sync_jobs_retry(state, &actor.did, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_sync_jobs_discard(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<sync_discard::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::registry_admin::sync_jobs_discard(state, &actor.did, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_records_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<records_list::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::registry_admin::records_list(state, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the audit log ───────────────────────────────────────────────────────

/// `audit/list/0.1`. Unrestricted administrators only: the envelopes carry
/// plaintext actor and target DIDs, the audit keyspace's own tier.
async fn handle_audit_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _checked) = match super_admin_with::<audit_list::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // The route's own query type: its filters, its cursor binding and its
    // refusal of the filters this maintainer does not implement.
    let query: crate::routes::audit::AuditQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match crate::routes::audit::list_audit(state, &actor.did, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_audit_verify(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _) = match super_admin_with::<audit_verify::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::audit::verify_audit_chain_inner(state, &actor.did).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the runtime configuration ───────────────────────────────────────────

async fn handle_config_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<config_show::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let keys: Option<Vec<String>> = payload
        .keys
        .map(|keys| keys.into_iter().map(|k| k.to_string()).collect());
    match crate::routes::admin::config::get_config(state, keys.as_deref()).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_config_patch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<config_patch::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let request = crate::routes::admin::config::PatchRequest {
        overrides: payload.overrides.into_iter().collect(),
    };
    match crate::routes::admin::config::patch_config(state, &actor.did, request).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_config_reload(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _) = match admin_with::<config_reload::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::admin::config::reload_config(state, &actor.did).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_config_restart(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _) = match admin_with::<config_restart::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::admin::config::restart_config(state, &actor.did).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── admin onboarding invites ────────────────────────────────────────────

async fn handle_invites_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<invite_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::admin::invites::list_invites(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/admin/invites/create/0.1`. Every check that decides the invite runs
/// first ([`crate::routes::admin::invites::check_invite`]). An invite for a DID
/// the community holds no entry for writes an **unrestricted** admin entry, so
/// it costs what an unrestricted `acl/grant` costs on this door: the
/// inviter's passkey gesture bound to this document, then another
/// unrestricted admin's consent. Without the gesture the answer is
/// `permissionDenied` with the ceremony inline as `details.stepUpRequest`, and
/// the identical document succeeds once it is recorded.
async fn handle_invites_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::acl::admin_consent::{self, Operation, SignedGate};

    // The schema bounds `ttlSeconds` at 24 hours as well, and the task
    // declares its own code for exceeding it; answer with the code rather
    // than the schema's generic refusal, as the operation does.
    // The authority check still comes first: a stranger learns nothing.
    if doc.payload["ttlSeconds"]
        .as_u64()
        .is_some_and(|ttl| ttl > crate::routes::admin::invites::MAX_TTL_SECONDS)
    {
        if let Err(reject) = admin_signer(state, ctx, &doc).await {
            return reject;
        }
        return task_error_to_reject(
            &doc,
            &crate::error::TaskError::declared(
                crate::routes::admin::invites::CREATE_INVITE_ERR_TTL_TOO_LONG,
                AppError::Validation(format!(
                    "ttl_seconds must be between 1 and {}",
                    crate::routes::admin::invites::MAX_TTL_SECONDS
                )),
            ),
        );
    }
    let (actor, _checked) = match admin_with::<invite_create::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let request: crate::routes::admin::invites::CreateInviteRequest = match parse_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let plan = match crate::routes::admin::invites::check_invite(state, &actor, &request).await {
        Ok(p) => p,
        Err(e) => return task_error_to_reject(&doc, &e),
    };
    if plan.grants_admin {
        let type_uri = doc.type_uri.to_string();
        let gate = admin_consent::gesture_then_consent(
            state,
            &actor.did,
            &request.did,
            Operation {
                type_uri: &type_uri,
                payload: &doc.payload,
            },
            &format!(
                "Invite {} to become an unrestricted administrator of this community",
                request.did
            ),
            &crate::routes::acl::unrestricted_grant_summary(&request.did),
        )
        .await;
        let ready = match gate {
            Ok(SignedGate::Ready(ready)) => ready,
            Ok(SignedGate::StepUpRequired(request)) => {
                return reject_with_code(
                    &doc,
                    TrustTaskCode::Standard(StandardCode::PermissionDenied),
                    "a passkey gesture bound to this invite is required",
                    Some(crate::acl::bound_step_up::refusal_details(&request)),
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if let Err(e) = ready.spend(state).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    match crate::routes::admin::invites::commit_invite(state, &actor, request, plan).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_invites_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<invite_revoke::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::admin::invites::revoke_invite(state, &actor.did, &payload.jti).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── sessions ────────────────────────────────────────────────────────────

/// `auth/sessions/list/0.1` — `{ sessions }`, the live sessions the signer may
/// see ([`crate::routes::auth::list_sessions_for`]).
async fn handle_sessions_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match session_actor(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<sessions_list::Payload>(&doc) {
        return reject;
    }
    match crate::routes::auth::list_sessions_for(state, &actor).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `auth/revoke-session/0.2` — exactly one of `sessionId`, `all: true` or
/// `subject`. `all: false` targets nothing and is `malformedRequest`
/// (consumer item 1); `all: true` is `subject` naming the producer.
async fn handle_revoke_session(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::auth::RevokeTarget;

    let actor = match session_actor(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let payload: revoke_session::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let malformed = |reason: &str| {
        reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: reason.to_string(),
            },
        )
    };
    let target = match (&payload.session_id, payload.all, &payload.subject) {
        (Some(id), None, None) => RevokeTarget::Session(id.to_string()),
        (None, Some(true), None) => RevokeTarget::Subject(actor.did.clone()),
        (None, None, Some(subject)) => RevokeTarget::Subject(subject.to_string()),
        (None, Some(false), None) => return malformed("`all: false` targets nothing"),
        _ => return malformed("name exactly one of `sessionId`, `all: true` or `subject`"),
    };
    let reason = payload.reason.map(|r| r.to_string());
    match crate::routes::auth::revoke_sessions_task(state, &actor, target, reason).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
