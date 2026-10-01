//! The administrator's community verbs on the signed-document spine: the
//! community's own reads, the member roster and the join queue, the
//! relationship graph, directory lookups, recognition checks, and the
//! invitation credentials an inviter issues.
//!
//! | task | authority (the signer's ACL row, read now) |
//! |---|---|
//! | `vtc/community/profile/show/0.1` | any entry |
//! | `vtc/ceremonies/list/0.1` | any entry |
//! | `vtc/directory/query/0.1` | any entry, as the viewer the directory policy projects for |
//! | `vtc/endorsement-types/list/0.1` | `Admin` |
//! | `vtc/recognition/check/0.1` | `Admin` |
//! | `vtc/members/{list,removed,show,solicit-vmc}/0.1` | `Admin` |
//! | `vtc/join-requests/{list,show}/0.1` | `Admin` |
//! | `vtc/relationships/graph/0.2` | `Admin` |
//! | `vtc/invitations/{issue,list,revoke,deliver}/0.1` | `Admin`, `Moderator` or `Issuer`; below `Admin`, only the invitations the signer issued, and no role conferred by invitation |
//!
//! Every one arrives here the same way over TSP, DIDComm or HTTPS. None of
//! them has a REST route.
//!
//! # Where the authority comes from
//!
//! The bearer routes took the caller's session (`AdminAuth`, or any
//! `AuthClaims` where the handler read the ACL row itself). A document has no
//! session, so each arm reads the **verified signer's** ACL row at execution
//! time — [`super::admin_signer`] for the administrator's verbs, and
//! [`super::admin_tasks::member_signer`] where any entry is enough — and asks
//! the question the route asked. A VTC bearer session was minted only for an
//! administrator, so the reads any entry may make (the profile, the
//! ceremonies, the directory) and the inviter verbs a `Moderator` or `Issuer`
//! may send are reachable by those members for the first time; each is the
//! party its handler already admitted.

use serde_json::Value;
use trust_tasks_rs::specs::vtc::ceremonies::list::v0_1 as ceremonies_list;
use trust_tasks_rs::specs::vtc::community::profile::show::v0_1 as profile_show;
use trust_tasks_rs::specs::vtc::directory::query::v0_1 as directory_query;
use trust_tasks_rs::specs::vtc::endorsement_types::list::v0_1 as endorsement_types_list;
use trust_tasks_rs::specs::vtc::invitations::{
    deliver::v0_1 as invitation_deliver, issue::v0_1 as invitation_issue,
    list::v0_1 as invitation_list, revoke::v0_1 as invitation_revoke,
};
use trust_tasks_rs::specs::vtc::join_requests::{
    list::v0_1 as join_requests_list, show::v0_1 as join_requests_show,
};
use trust_tasks_rs::specs::vtc::members::{
    list::v0_1 as members_list, removed::v0_1 as members_removed, show::v0_1 as members_show,
    solicit_vmc::v0_1 as members_solicit_vmc,
};
use trust_tasks_rs::specs::vtc::recognition::check::v0_1 as recognition_check;
use trust_tasks_rs::specs::vtc::relationships::graph::v0_2 as relationships_graph;
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::auth::extractor::AuthClaims;

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, success_response,
    task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::server::AppState;

pub(crate) const PROFILE_SHOW_TYPE: &str = <profile_show::Payload as Payload>::TYPE_URI;
pub(crate) const CEREMONIES_LIST_TYPE: &str = <ceremonies_list::Payload as Payload>::TYPE_URI;
pub(crate) const DIRECTORY_QUERY_TYPE: &str = <directory_query::Payload as Payload>::TYPE_URI;
pub(crate) const ENDORSEMENT_TYPES_LIST_TYPE: &str =
    <endorsement_types_list::Payload as Payload>::TYPE_URI;
pub(crate) const RECOGNITION_CHECK_TYPE: &str = <recognition_check::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_LIST_TYPE: &str = <members_list::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_REMOVED_TYPE: &str = <members_removed::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_SHOW_TYPE: &str = <members_show::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_SOLICIT_VMC_TYPE: &str =
    <members_solicit_vmc::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_REQUESTS_LIST_TYPE: &str = <join_requests_list::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_REQUESTS_SHOW_TYPE: &str = <join_requests_show::Payload as Payload>::TYPE_URI;
pub(crate) const RELATIONSHIPS_GRAPH_TYPE: &str =
    <relationships_graph::Payload as Payload>::TYPE_URI;
pub(crate) const INVITATIONS_ISSUE_TYPE: &str = <invitation_issue::Payload as Payload>::TYPE_URI;
pub(crate) const INVITATIONS_LIST_TYPE: &str = <invitation_list::Payload as Payload>::TYPE_URI;
pub(crate) const INVITATIONS_REVOKE_TYPE: &str = <invitation_revoke::Payload as Payload>::TYPE_URI;
pub(crate) const INVITATIONS_DELIVER_TYPE: &str =
    <invitation_deliver::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    PROFILE_SHOW_TYPE,
    CEREMONIES_LIST_TYPE,
    DIRECTORY_QUERY_TYPE,
    ENDORSEMENT_TYPES_LIST_TYPE,
    RECOGNITION_CHECK_TYPE,
    MEMBERS_LIST_TYPE,
    MEMBERS_REMOVED_TYPE,
    MEMBERS_SHOW_TYPE,
    MEMBERS_SOLICIT_VMC_TYPE,
    JOIN_REQUESTS_LIST_TYPE,
    JOIN_REQUESTS_SHOW_TYPE,
    RELATIONSHIPS_GRAPH_TYPE,
    INVITATIONS_ISSUE_TYPE,
    INVITATIONS_LIST_TYPE,
    INVITATIONS_REVOKE_TYPE,
    INVITATIONS_DELIVER_TYPE,
];

/// Tasks whose response carries a bearer secret: an issued invitation
/// credential, and a delivery's offer code. The duplicate-execution record
/// keeps no copy of these.
pub(crate) const SECRET_RESPONSES: &[&str] = &[INVITATIONS_ISSUE_TYPE, INVITATIONS_DELIVER_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        PROFILE_SHOW_TYPE => handle_profile_show(state, ctx, doc).await,
        CEREMONIES_LIST_TYPE => handle_ceremonies_list(state, ctx, doc).await,
        DIRECTORY_QUERY_TYPE => handle_directory_query(state, ctx, doc).await,
        ENDORSEMENT_TYPES_LIST_TYPE => handle_endorsement_types_list(state, ctx, doc).await,
        RECOGNITION_CHECK_TYPE => handle_recognition_check(state, ctx, doc).await,
        MEMBERS_LIST_TYPE => handle_members_list(state, ctx, doc).await,
        MEMBERS_REMOVED_TYPE => handle_members_removed(state, ctx, doc).await,
        MEMBERS_SHOW_TYPE => handle_members_show(state, ctx, doc).await,
        MEMBERS_SOLICIT_VMC_TYPE => handle_members_solicit_vmc(state, ctx, doc).await,
        JOIN_REQUESTS_LIST_TYPE => handle_join_requests_list(state, ctx, doc).await,
        JOIN_REQUESTS_SHOW_TYPE => handle_join_requests_show(state, ctx, doc).await,
        RELATIONSHIPS_GRAPH_TYPE => handle_relationships_graph(state, ctx, doc).await,
        INVITATIONS_ISSUE_TYPE => handle_invitations_issue(state, ctx, doc).await,
        INVITATIONS_LIST_TYPE => handle_invitations_list(state, ctx, doc).await,
        INVITATIONS_REVOKE_TYPE => handle_invitations_revoke(state, ctx, doc).await,
        INVITATIONS_DELIVER_TYPE => handle_invitations_deliver(state, ctx, doc).await,
        _ => return None,
    })
}

/// The signer as an administrator, and its payload validated against the
/// published schema.
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

/// Any signer the community holds an entry for, and its payload validated
/// against the published schema.
async fn member_with<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(AuthClaims, P), TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = member_signer(state, ctx, doc).await?;
    let payload = parse_spec_payload::<P>(doc)?;
    Ok((actor, payload))
}

// ─── the community's own reads ───────────────────────────────────────────

async fn handle_profile_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = member_with::<profile_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::community::profile::show_profile(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_ceremonies_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = member_with::<ceremonies_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    success_response(&doc, crate::routes::ceremonies::list())
}

/// `vtc/directory/query/0.1` — the subject's record as the directory policy
/// projects it for the signer. "No such member" and "nothing visible to you"
/// are the one `notFound`, as on the route this replaced.
async fn handle_directory_query(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (viewer, payload) = match member_with::<directory_query::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::directory::query(
        state,
        &viewer,
        payload.subject.to_string(),
        payload.fields.map(|f| f.to_string()),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_endorsement_types_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<endorsement_types_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let query: crate::routes::endorsement_types::ListQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match crate::routes::endorsement_types::list(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_recognition_check(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<recognition_check::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let query = crate::routes::recognition_admin::CheckQuery {
        did: payload.did.to_string(),
    };
    match crate::routes::recognition_admin::check(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the member roster ───────────────────────────────────────────────────

async fn handle_members_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<members_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let query: crate::routes::members::read::ListMembersQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match crate::routes::members::read::list_members_inner(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_members_removed(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<members_removed::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::members::read::list_removed(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_members_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<members_show::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::members::read::show_member(state, payload.did.as_str()).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/solicit-vmc/0.1` — ask an active member to issue and send the
/// member-to-community half of the membership pair.
async fn handle_members_solicit_vmc(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<members_solicit_vmc::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let body = crate::routes::members::request_vmc::RequestVmcBody {
        reason: payload.reason.map(|r| r.to_string()),
    };
    match crate::routes::members::request_vmc::request_vmc(
        state,
        payload.member_did.to_string(),
        body,
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the join queue ──────────────────────────────────────────────────────

async fn handle_join_requests_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<join_requests_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let query: crate::routes::join_requests::read::ListJoinRequestsQuery = match parse_payload(&doc)
    {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match crate::routes::join_requests::read::list_join_requests_inner(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_join_requests_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<join_requests_show::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let Ok(id) = uuid::Uuid::parse_str(&payload.id) else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "id is not a join-request identifier".into(),
            },
        );
    };
    match crate::routes::join_requests::read::show_join_request(state, id).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the relationship graph ──────────────────────────────────────────────

async fn handle_relationships_graph(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<relationships_graph::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::relationships::graph(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── invitation credentials ──────────────────────────────────────────────
//
// The operations read the signer's ACL row themselves (`Admin`, `Moderator`
// or `Issuer`); the arms only establish who signed. The bearer routes were
// reachable by an administrator's session only, so the operations also bound
// what a `Moderator` or `Issuer` may do now that it can sign: list, revoke
// and deliver only the invitations it issued, and invite members only.

async fn handle_invitations_issue(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _checked) = match member_with::<invitation_issue::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let body: crate::routes::invitations::IssueInvitationBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::invitations::issue(state, &actor.did, body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_invitations_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _) = match member_with::<invitation_list::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::invitations::list(state, &actor.did).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_invitations_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match member_with::<invitation_revoke::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::invitations::revoke(state, &actor.did, payload.id.to_string()).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_invitations_deliver(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match member_with::<invitation_deliver::Payload>(state, ctx, &doc).await
    {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::invitations::deliver(state, &actor.did, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &crate::error::TaskError::from(e)),
    }
}
