//! The `git-ns/*` Trust Task handlers — the dispatch surface over [`super::ops`].
//!
//! Registered on an [`AsyncDispatcher`] keyed on each task's generated
//! payload type, exactly as the `rooms/*` family is: the URI comes from the
//! type, so a task cannot be served under a URI nobody publishes, and
//! [`served_uris`] is the routing table itself rather than a list kept beside
//! it. The dispatcher also enforces each task's declared proof requirement
//! before a handler runs.
//!
//! # Who is acting
//!
//! The actor is the DID the dispatch spine verified the document's proof
//! against — never a payload member. Every task a member or an administrator
//! sends declares the proof REQUIRED, and the spine refuses it without one,
//! except two reads: `git-ns/view` and
//! `git-ns/account/link-status` declare it RECOMMENDED ("a read … transport
//! integrity suffices where the transport already authenticates the
//! caller"), so for those two the transport's authenticated sender stands in
//! when there is no proof. Over REST with neither, there is nobody to answer
//! for, and the read is refused.

use serde_json::Value;
use trust_tasks_rs::specs::git_ns::account::{
    link::v0_1 as link, link_status::v0_1 as link_status, unlink::v0_1 as unlink,
};
use trust_tasks_rs::specs::git_ns::bridge::{
    event::v0_1 as event, event::v0_2 as event2, event::v0_3 as event3, result::v0_1 as result,
};
use trust_tasks_rs::specs::git_ns::drift::resolve::{
    v0_1 as drift_resolve, v0_3 as drift_resolve3,
};
use trust_tasks_rs::specs::git_ns::namespace::{
    bind::v0_1 as bind, reseat::v0_3 as reseat, unbind::v0_1 as unbind,
};
use trust_tasks_rs::specs::git_ns::repo::{
    adopt::v0_1 as adopt, archive::v0_1 as archive, create::v0_3 as create,
    transfer::v0_1 as transfer,
};
use trust_tasks_rs::specs::git_ns::right::{
    break_glass::v0_1 as break_glass, grant::v0_3 as grant, ratify::v0_1 as ratify,
    revoke::v0_3 as revoke,
};
use trust_tasks_rs::specs::git_ns::roles::reproject::v0_1 as reproject;
use trust_tasks_rs::specs::git_ns::view::{v0_1 as view, v0_2 as view2, v0_4 as view4};
use trust_tasks_rs::{AsyncDispatcher, RejectReason, StandardCode, TrustTask, TrustTaskCode};

use crate::server::AppState;
use crate::trust_tasks::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};

use super::ops::{self, OpError};
use super::store::Snapshot;

static GIT_NS: std::sync::LazyLock<AsyncDispatcher<GitNsCtx, TrustTaskOutcome>> =
    std::sync::LazyLock::new(dispatcher);

/// Does this service dispatch `type_uri` as a `git-ns/*` task?
#[must_use]
pub(crate) fn serves(type_uri: &str) -> bool {
    GIT_NS.registered_uris().contains(&type_uri)
}

/// Every URI this family serves. Public so `tests/trust_task_manifest.rs`
/// can check the admin console's signed-document types against it.
#[must_use]
pub fn served_uris() -> Vec<&'static str> {
    GIT_NS.registered_uris()
}

/// What a handler needs that is not in the document.
#[derive(Clone)]
pub(crate) struct GitNsCtx {
    pub state: AppState,
    /// The verified signer of the document's proof.
    pub signer: Option<String>,
    /// The transport's authenticated sender, used only by the two tasks whose
    /// proof is RECOMMENDED.
    pub sender: Option<String>,
}

pub(crate) async fn dispatch(
    state: &AppState,
    doc: TrustTask<Value>,
    signer: Option<&str>,
    sender: Option<&str>,
) -> TrustTaskOutcome {
    let ctx = GitNsCtx {
        state: state.clone(),
        signer: signer.map(str::to_string),
        sender: sender.map(str::to_string),
    };
    match GIT_NS
        .dispatch_or_reject(doc, ctx, format!("urn:uuid:{}", uuid::Uuid::new_v4()))
        .await
    {
        Ok(outcome) => outcome,
        Err(err_doc) => crate::trust_tasks::helpers::error_response(err_doc),
    }
}

pub(crate) fn dispatcher() -> AsyncDispatcher<GitNsCtx, TrustTaskOutcome> {
    AsyncDispatcher::new()
        .on_async(handle_bind)
        .on_async(handle_unbind)
        .on_async(handle_create)
        .on_async(handle_adopt)
        .on_async(handle_transfer)
        .on_async(handle_archive)
        .on_async(handle_grant)
        .on_async(handle_revoke)
        .on_async(handle_break_glass)
        .on_async(handle_ratify)
        .on_async(handle_view)
        .on_async(handle_view_v2)
        .on_async(handle_view_v4)
        .on_async(handle_drift_resolve)
        .on_async(handle_drift_resolve_v3)
        .on_async(handle_reseat)
        .on_async(handle_reproject)
        .on_async(handle_link)
        .on_async(handle_link_status)
        .on_async(handle_unlink)
        .on_async(handle_result)
        .on_async(handle_event)
        .on_async(handle_event_v2)
        .on_async(handle_event_v3)
}

/// Render an operation's outcome.
fn respond<P, R: serde::Serialize>(doc: &TrustTask<P>, r: Result<R, OpError>) -> TrustTaskOutcome {
    match r {
        Ok(body) => success_response(doc, body),
        Err(OpError::Declared { code, message }) => {
            reject_with_code(doc, extended_code(code), message, None)
        }
        Err(OpError::PermissionDenied(reason)) => {
            reject_with(doc, RejectReason::PermissionDenied { reason })
        }
        Err(OpError::Malformed(reason)) => {
            reject_with(doc, RejectReason::MalformedRequest { reason })
        }
        Err(OpError::StepUpRequired { message, request }) => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            message,
            Some(crate::acl::bound_step_up::refusal_details(&request)),
        ),
        Err(OpError::Unavailable(message)) => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            message,
            None,
        ),
        Err(OpError::UnsupportedVersion(message)) => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::UnsupportedVersion),
            message,
            None,
        ),
        Err(OpError::Internal(e)) => app_error_to_reject(doc, &e),
    }
}

/// The verified signer, for a task whose proof is REQUIRED. The spine has
/// already refused a document without one; this is the belt to that brace,
/// kept because an absent signer must never become an empty actor.
fn signer<P>(doc: &TrustTask<P>, ctx: &GitNsCtx) -> Result<String, TrustTaskOutcome> {
    ctx.signer
        .clone()
        .ok_or_else(|| reject_with(doc, RejectReason::ProofRequired))
}

/// The caller, for a task whose proof is RECOMMENDED.
fn caller<P>(doc: &TrustTask<P>, ctx: &GitNsCtx) -> Result<String, TrustTaskOutcome> {
    ctx.signer
        .clone()
        .or_else(|| ctx.sender.clone())
        .ok_or_else(|| {
            reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason:
                        "nobody identified: sign the document, or send it over a transport that \
                         authenticates you"
                            .into(),
                },
            )
        })
}

/// The DID a member-facing task acts as.
///
/// Usually the signer. The exception is a **console signing key** (#1684,
/// #1692): a `did:key` the admin console enrolled as a credential of the
/// operator's admin DID. A signer with no ACL row of its own and a live
/// delegation acts as the delegating admin DID — whose ACL row and whose git
/// rights are then read, at execution time, exactly as for a signer who used
/// their own key. The same resolution, and the same rule, as the admin verbs'
/// `admin_signer`: the fall-through is only for a signer with *no row at
/// all*, so a delegation can never route around a row that refuses; a revoked
/// or expired delegation resolves to the signer itself, who holds nothing. A
/// delegation carries no role and no right of its own (VTI-OPS-050: it is not
/// self-promotion).
///
/// Never applied to `git-ns/bridge/*`: a bridge is identified by its own DID
/// and nothing else.
async fn acting_as(state: &AppState, signer: &str) -> Result<String, OpError> {
    if crate::acl::get_acl_entry(&state.acl_ks, signer)
        .await?
        .is_some()
    {
        return Ok(signer.to_string());
    }
    match crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, signer).await? {
        Some(delegation) => {
            crate::acl::console_key::touch_last_used(&state.console_keys_ks, &delegation).await;
            tracing::info!(
                console_did = %signer,
                admin_did = %delegation.admin_did,
                "authorizing a git-ns document under a console-key delegation"
            );
            Ok(delegation.admin_did)
        }
        None => Ok(signer.to_string()),
    }
}

macro_rules! signed_handler {
    ($name:ident, $payload:ty, $op:path) => {
        pub(crate) async fn $name(doc: TrustTask<$payload>, ctx: GitNsCtx) -> TrustTaskOutcome {
            let signer = match signer(&doc, &ctx) {
                Ok(a) => a,
                Err(r) => return r,
            };
            let actor = match acting_as(&ctx.state, &signer).await {
                Ok(a) => a,
                Err(e) => return respond::<_, ()>(&doc, Err(e)),
            };
            let r = $op(&ctx.state, &actor, doc.payload.clone()).await;
            respond(&doc, r)
        }
    };
}

/// As [`signed_handler`], for the bridge's tasks: the signer is the actor,
/// with no delegation — only the namespace's own bridge DID is accepted.
macro_rules! bridge_handler {
    ($name:ident, $payload:ty, $op:path) => {
        pub(crate) async fn $name(doc: TrustTask<$payload>, ctx: GitNsCtx) -> TrustTaskOutcome {
            let actor = match signer(&doc, &ctx) {
                Ok(a) => a,
                Err(r) => return r,
            };
            let r = $op(&ctx.state, &actor, doc.payload.clone()).await;
            respond(&doc, r)
        }
    };
}

signed_handler!(handle_bind, bind::Payload, ops::bind);
signed_handler!(handle_unbind, unbind::Payload, ops::unbind);
signed_handler!(handle_create, create::Payload, ops::repo_create);
signed_handler!(handle_adopt, adopt::Payload, ops::repo_adopt);
signed_handler!(handle_transfer, transfer::Payload, ops::repo_transfer);
signed_handler!(handle_archive, archive::Payload, ops::repo_archive);
signed_handler!(handle_grant, grant::Payload, ops::right_grant);
signed_handler!(handle_revoke, revoke::Payload, ops::right_revoke);
signed_handler!(
    handle_break_glass,
    break_glass::Payload,
    super::break_glass::right_break_glass
);
signed_handler!(
    handle_ratify,
    ratify::Payload,
    super::break_glass::right_ratify
);
signed_handler!(handle_link, link::Payload, ops::account_link);
signed_handler!(handle_unlink, unlink::Payload, ops::account_unlink);
bridge_handler!(handle_result, result::Payload, super::bridge::handle_result);
signed_handler!(
    handle_drift_resolve,
    drift_resolve::Payload,
    super::drift::drift_resolve_v1
);
signed_handler!(
    handle_drift_resolve_v3,
    drift_resolve3::Payload,
    super::drift::drift_resolve
);
// `git-ns/namespace/reseat/0.3` — the only reseat version served (0.1 and
// 0.2 queued a namespace-level forge projection that no longer exists).
signed_handler!(handle_reseat, reseat::Payload, ops::namespace_reseat);
signed_handler!(
    handle_reproject,
    reproject::Payload,
    super::reproject::roles_reproject
);

/// `git-ns/bridge/event` 0.1 and 0.2, read as 0.3. The three share every
/// event type but 0.3's `roleMapReported`, and 0.2 changed only what the VTC
/// does with a transfer, a reused name and a resource outside the namespace —
/// rules this VTC applies to a 0.1 event too. So an older payload is carried
/// as 0.3 (which it is a valid instance of) into the one handler, and its
/// acknowledgement goes back in the version it was sent.
async fn event_as_v3<P, R>(
    state: &crate::server::AppState,
    issuer: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    p: P,
) -> Result<R, OpError>
where
    P: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let v3: event3::Payload = serde_json::from_value(
        serde_json::to_value(&p).map_err(vti_common::error::AppError::from)?,
    )
    .map_err(|e| OpError::Malformed(format!("bridge/event payload: {e}")))?;
    let ack = super::bridge::handle_event(state, issuer, issued_at, v3).await?;
    Ok(serde_json::from_value(
        serde_json::to_value(&ack).map_err(vti_common::error::AppError::from)?,
    )
    .map_err(vti_common::error::AppError::from)?)
}
async fn event_v1(
    state: &crate::server::AppState,
    issuer: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    p: event::Payload,
) -> Result<event::Response, OpError> {
    event_as_v3(state, issuer, issued_at, p).await
}
async fn event_v2(
    state: &crate::server::AppState,
    issuer: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    p: event2::Payload,
) -> Result<event2::Response, OpError> {
    event_as_v3(state, issuer, issued_at, p).await
}

/// As [`bridge_handler`], passing the document's `issuedAt` too: it orders
/// role-map reports (`git-ns/bridge/event/0.3`, request step 5.2). The spine
/// refuses a document without one before any handler runs.
macro_rules! event_handler {
    ($name:ident, $payload:ty, $op:path) => {
        pub(crate) async fn $name(doc: TrustTask<$payload>, ctx: GitNsCtx) -> TrustTaskOutcome {
            let actor = match signer(&doc, &ctx) {
                Ok(a) => a,
                Err(r) => return r,
            };
            let r = match doc.issued_at {
                Some(at) => $op(&ctx.state, &actor, at, doc.payload.clone()).await,
                None => Err(OpError::Malformed(
                    "a bridge event carries `issuedAt`".into(),
                )),
            };
            respond(&doc, r)
        }
    };
}
event_handler!(handle_event, event::Payload, event_v1);
event_handler!(handle_event_v2, event2::Payload, event_v2);
event_handler!(
    handle_event_v3,
    event3::Payload,
    super::bridge::handle_event
);

/// `git-ns/view/0.1` — any member, what they may see.
pub(crate) async fn handle_view(doc: TrustTask<view::Payload>, ctx: GitNsCtx) -> TrustTaskOutcome {
    let who = match caller(&doc, &ctx) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let r = async {
        let who = acting_as(&ctx.state, &who).await?;
        let standing = ops::standing(&ctx.state, &who).await?;
        if !standing.member {
            return Err(OpError::PermissionDenied(
                "git-ns/view answers members of this community".into(),
            ));
        }
        let filter = match &doc.payload.resource {
            Some(r) => Some(super::model::Resource::parse(r).map_err(OpError::Malformed)?),
            None => None,
        };
        let snap = Snapshot::load(&ctx.state.git_ns.ks).await?;
        Ok(super::view::for_member(&snap, &who, filter.as_ref())?)
    }
    .await;
    respond(&doc, r)
}

/// `git-ns/view/0.2` — 0.1's answer, plus the caller's own linked accounts.
pub(crate) async fn handle_view_v2(
    doc: TrustTask<view2::Payload>,
    ctx: GitNsCtx,
) -> TrustTaskOutcome {
    let who = match caller(&doc, &ctx) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let r = async {
        let who = acting_as(&ctx.state, &who).await?;
        let standing = ops::standing(&ctx.state, &who).await?;
        if !standing.member {
            return Err(OpError::PermissionDenied(
                "git-ns/view answers members of this community".into(),
            ));
        }
        let filter = match &doc.payload.resource {
            Some(r) => Some(super::model::Resource::parse(r).map_err(OpError::Malformed)?),
            None => None,
        };
        let snap = Snapshot::load(&ctx.state.git_ns.ks).await?;
        let member = crate::members::get_member(&ctx.state.members_ks, &who).await?;
        Ok(super::view::for_member_v2(
            &snap,
            &who,
            filter.as_ref(),
            member.as_ref(),
        )?)
    }
    .await;
    respond(&doc, r)
}

/// `git-ns/view/0.4` — 0.2's answer, with every record's `breakGlass`, and
/// every unratified break-glass record to every administrator it concerns.
pub(crate) async fn handle_view_v4(
    doc: TrustTask<view4::Payload>,
    ctx: GitNsCtx,
) -> TrustTaskOutcome {
    let who = match caller(&doc, &ctx) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let r = async {
        let who = acting_as(&ctx.state, &who).await?;
        let standing = ops::standing(&ctx.state, &who).await?;
        if !standing.member {
            return Err(OpError::PermissionDenied(
                "git-ns/view answers members of this community".into(),
            ));
        }
        let filter = match &doc.payload.resource {
            Some(r) => Some(super::model::Resource::parse(r).map_err(OpError::Malformed)?),
            None => None,
        };
        let snap = Snapshot::load(&ctx.state.git_ns.ks).await?;
        let member = crate::members::get_member(&ctx.state.members_ks, &who).await?;
        Ok(super::view::for_member_v4(
            &snap,
            &who,
            standing.community_admin,
            filter.as_ref(),
            member.as_ref(),
        )?)
    }
    .await;
    respond(&doc, r)
}

/// `git-ns/account/link-status/0.1` — the member who began the link.
pub(crate) async fn handle_link_status(
    doc: TrustTask<link_status::Payload>,
    ctx: GitNsCtx,
) -> TrustTaskOutcome {
    let who = match caller(&doc, &ctx) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let r = match acting_as(&ctx.state, &who).await {
        Ok(who) => ops::account_link_status(&ctx.state, &who, doc.payload.clone()).await,
        Err(e) => Err(e),
    };
    respond(&doc, r)
}
