//! A community's side of Verifiable Trust Network membership — `vtc/networks/*/0.2`, and
//! `vtc/networks/deliver/0.1`
//! ([`crate::networks`]).
//!
//! | task | signed by | authority (read now) |
//! |---|---|---|
//! | `list`, `show`, `preview` | an administrator | `vtc.config.admin` |
//! | `join`, `repudiate`, `leave`, `groups/register` | an administrator | `vtc.config.admin`, plus the requester's step-up bound to the document |
//! | `evidence` | anyone verified | answers only for groups the signer is an active member of |
//! | `deliver` | a network | the signer is a network this community acknowledged, delivering for a role it registered a group for |
//!
//! `vtc/networks/notice/0.1` is sent, never served: the community pushes it to a group's
//! members when a network's `deliver` arrives ([`crate::networks::deliver`]).
//!
//! # Why the writes take a bound step-up
//!
//! Each makes the community sign a statement to a third party, the network: an
//! acknowledgement, a repudiation, a group registration. The statement commits the
//! community to a curator's governance framework, or withdraws it, and discloses its
//! groups' DIDs. The requester's gesture is bound to the digest of the one document
//! ([`crate::acl::bound_step_up`], VTI-APV-015), as for enabling a capability module, so a
//! stolen or delegated signing key alone cannot do any of it.

use serde_json::{Value, json};
use trust_tasks_rs::{Payload, StandardCode, TrustTask, TrustTaskCode};
use vti_common::error::AppError;
use vti_specs::vtc::networks::{
    deliver::v0_1 as deliver, evidence::v0_2 as evidence, groups::register::v0_2 as register,
    join::v0_2 as join, leave::v0_2 as leave, list::v0_2 as list, preview::v0_1 as preview,
    repudiate::v0_2 as repudiate, show::v0_2 as show,
};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with_code, task_error_to_reject,
};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::error::TaskError;
use crate::networks::{self, NetError};
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <show::Payload as Payload>::TYPE_URI;
pub(crate) const PREVIEW_TYPE: &str = <preview::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_TYPE: &str = <join::Payload as Payload>::TYPE_URI;
pub(crate) const REPUDIATE_TYPE: &str = <repudiate::Payload as Payload>::TYPE_URI;
pub(crate) const LEAVE_TYPE: &str = <leave::Payload as Payload>::TYPE_URI;
pub(crate) const REGISTER_TYPE: &str = <register::Payload as Payload>::TYPE_URI;
pub(crate) const EVIDENCE_TYPE: &str = <evidence::Payload as Payload>::TYPE_URI;
pub(crate) const DELIVER_TYPE: &str = <deliver::Payload as Payload>::TYPE_URI;

/// Every URI [`dispatch`] routes. `super::DISPATCHED_URIS` names each of these and
/// `dispatcher_routes_every_dispatched_uri` holds the two in step.
pub(crate) const URIS: &[&str] = &[
    LIST_TYPE,
    SHOW_TYPE,
    PREVIEW_TYPE,
    JOIN_TYPE,
    REPUDIATE_TYPE,
    LEAVE_TYPE,
    REGISTER_TYPE,
    EVIDENCE_TYPE,
    DELIVER_TYPE,
];

/// The extended codes these tasks declare, each the value the generated
/// `error_codes::*` constant carries (the error-code census checks they agree).
pub(crate) const JOIN_ERR_NOT_LISTED: &str = "vtc/networks/join:notListed";
pub(crate) const JOIN_ERR_NETWORK_MISMATCH: &str = "vtc/networks/join:networkMismatch";
pub(crate) const JOIN_ERR_ROLE_UNASSIGNED: &str = "vtc/networks/join:roleUnassigned";
pub(crate) const JOIN_ERR_UNKNOWN_GROUP: &str = "vtc/networks/join:unknownGroup";
pub(crate) const JOIN_ERR_NETWORK_REFUSED: &str = "vtc/networks/join:networkRefused";
pub(crate) const REPUDIATE_ERR_NOT_LISTED: &str = "vtc/networks/repudiate:notListed";
pub(crate) const REPUDIATE_ERR_NETWORK_MISMATCH: &str = "vtc/networks/repudiate:networkMismatch";
pub(crate) const REPUDIATE_ERR_IS_MEMBER: &str = "vtc/networks/repudiate:isMember";
pub(crate) const REPUDIATE_ERR_NETWORK_REFUSED: &str = "vtc/networks/repudiate:networkRefused";
pub(crate) const LEAVE_ERR_NOT_MEMBER: &str = "vtc/networks/leave:notMember";
pub(crate) const LEAVE_ERR_NETWORK_REFUSED: &str = "vtc/networks/leave:networkRefused";
pub(crate) const REGISTER_ERR_NOT_MEMBER: &str = "vtc/networks/groups/register:notMember";
pub(crate) const REGISTER_ERR_UNKNOWN_GROUP: &str = "vtc/networks/groups/register:unknownGroup";
pub(crate) const REGISTER_ERR_NETWORK_REFUSED: &str = "vtc/networks/groups/register:networkRefused";
pub(crate) const DELIVER_ERR_NOT_MEMBER: &str = "vtc/networks/deliver:notMember";
pub(crate) const DELIVER_ERR_ROLE_UNREGISTERED: &str = "vtc/networks/deliver:roleUnregistered";
pub(crate) const DELIVER_ERR_ENVELOPE_INVALID: &str = "vtc/networks/deliver:envelopeInvalid";
pub(crate) const PREVIEW_ERR_NETWORK_UNREACHABLE: &str = "vtc/networks/preview:networkUnreachable";
pub(crate) const PREVIEW_ERR_NETWORK_MISMATCH: &str = "vtc/networks/preview:networkMismatch";

const DECLARED: &[&str] = &[
    JOIN_ERR_NOT_LISTED,
    JOIN_ERR_NETWORK_MISMATCH,
    JOIN_ERR_ROLE_UNASSIGNED,
    JOIN_ERR_UNKNOWN_GROUP,
    JOIN_ERR_NETWORK_REFUSED,
    REPUDIATE_ERR_NOT_LISTED,
    REPUDIATE_ERR_NETWORK_MISMATCH,
    REPUDIATE_ERR_IS_MEMBER,
    REPUDIATE_ERR_NETWORK_REFUSED,
    LEAVE_ERR_NOT_MEMBER,
    LEAVE_ERR_NETWORK_REFUSED,
    REGISTER_ERR_NOT_MEMBER,
    REGISTER_ERR_UNKNOWN_GROUP,
    REGISTER_ERR_NETWORK_REFUSED,
    DELIVER_ERR_NOT_MEMBER,
    DELIVER_ERR_ROLE_UNREGISTERED,
    DELIVER_ERR_ENVELOPE_INVALID,
    PREVIEW_ERR_NETWORK_UNREACHABLE,
    PREVIEW_ERR_NETWORK_MISMATCH,
];

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;

/// Route one of [`URIS`]; `None` for any other URI.
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        PREVIEW_TYPE => handle_preview(state, ctx, doc).await,
        JOIN_TYPE => handle_join(state, ctx, doc).await,
        REPUDIATE_TYPE => handle_repudiate(state, ctx, doc).await,
        LEAVE_TYPE => handle_leave(state, ctx, doc).await,
        REGISTER_TYPE => handle_register(state, ctx, doc).await,
        EVIDENCE_TYPE => handle_evidence(state, ctx, doc).await,
        DELIVER_TYPE => handle_deliver(state, ctx, doc).await,
        _ => return None,
    })
}

// Answer with `body` held to the generated `#response` type and its schema
// (an `internalError` when it is not: the mismatch is this service's fault).
use vti_trust_task_server::typed::respond;

fn membership_json(m: &networks::Membership) -> Value {
    serde_json::to_value(m).unwrap_or(Value::Null)
}

/// The spec's error code for `e`, if the task (`slug`) declares one; otherwise the
/// standard code the framework gives the same failure.
fn refuse(doc: &TrustTask<Value>, slug: &str, e: NetError) -> TrustTaskOutcome {
    let extended = |local: &str, details: Option<Value>| {
        let code = format!("{slug}:{local}");
        DECLARED
            .iter()
            .find(|c| **c == code)
            .map(|c| reject_with_code(doc, extended_code(c), e.to_string(), details))
    };
    let declared_answer = match &e {
        NetError::NotListed(_) => extended("notListed", None),
        NetError::Mismatch(_) => extended("networkMismatch", None),
        NetError::RoleUnassigned(role) => extended("roleUnassigned", Some(json!({ "role": role }))),
        NetError::UnknownGroup(_) => extended("unknownGroup", None),
        NetError::Refused(message) => {
            extended("networkRefused", Some(json!({ "message": message })))
        }
        NetError::NotMember => extended("notMember", None),
        NetError::IsMember => extended("isMember", None),
        NetError::RoleUnregistered(_) => extended("roleUnregistered", None),
        NetError::Rejected(message) => {
            extended("envelopeInvalid", Some(json!({ "message": message })))
        }
        _ => None,
    };
    if let Some(answer) = declared_answer {
        return answer;
    }
    match e {
        NetError::AlreadyMember => app_error_to_reject(doc, &AppError::Conflict(e.to_string())),
        NetError::NotFound | NetError::NotMember => {
            app_error_to_reject(doc, &AppError::NotFound(e.to_string()))
        }
        NetError::Unavailable(m) => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            m,
            None,
        ),
        NetError::App(err) => app_error_to_reject(doc, &err),
        other => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::TaskFailed),
            other.to_string(),
            None,
        ),
    }
}

/// The requester's gesture bound to this document.
async fn bound_step_up(
    state: &AppState,
    actor: &str,
    doc: &TrustTask<Value>,
    reason: &str,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::bound_step_up::{self, Gate};
    match bound_step_up::redeem_or_request(
        state,
        actor,
        &doc.type_uri.to_string(),
        &doc.payload,
        reason,
    )
    .await
    {
        Ok(Gate::Satisfied) => Ok(()),
        Ok(Gate::Required(request)) => Err(task_error_to_reject(doc, &TaskError::step_up(request))),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

fn require_audit(state: &AppState, doc: &TrustTask<Value>) -> Result<(), TrustTaskOutcome> {
    if state.audit_writer.is_some() {
        return Ok(());
    }
    Err(reject_with_code(
        doc,
        TrustTaskCode::Standard(StandardCode::Unavailable),
        "the audit log is not configured; a network membership change is refused rather than \
         made unaudited",
        None,
    ))
}

// ─── reads ────────────────────────────────────────────────────────────────

async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        return reject;
    }
    let _checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let state_filter = doc.payload["state"].as_str();
    let cursor = doc.payload["cursor"].as_str();
    let limit = doc.payload["limit"]
        .as_u64()
        .map_or(DEFAULT_LIMIT, |l| (l as usize).clamp(1, MAX_LIMIT));
    let all = match networks::list(state).await {
        Ok(all) => all,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let matching: Vec<_> = all
        .iter()
        .filter(|m| state_filter.is_none_or(|s| membership_json(m)["state"] == s))
        .filter(|m| cursor.is_none_or(|c| m.network.as_str() > c))
        .collect();
    let page: Vec<Value> = matching
        .iter()
        .take(limit)
        .map(|m| membership_json(m))
        .collect();
    let mut body = json!({ "items": page });
    if matching.len() > limit {
        body["nextCursor"] = json!(matching[limit - 1].network);
    }
    respond::<list::Response>(&doc, body)
}

async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        return reject;
    }
    let checked: show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match networks::load(state, &checked.network).await {
        Ok(Some(m)) => {
            respond::<show::Response>(&doc, json!({ "membership": membership_json(&m) }))
        }
        Ok(None) => refuse(&doc, "vtc/networks/show", NetError::NotFound),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/networks/preview`: the network at `url`, and where the community stands with it,
/// for the console to show before a join. A read: no step-up, and nothing is signed to the
/// network but the community's own read of its entry.
async fn handle_preview(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        return reject;
    }
    let checked: preview::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let expected = checked.network.as_ref().map(|n| n.to_string());
    match networks::preview(state, checked.url.as_str(), expected.as_deref()).await {
        Ok(found) => respond::<preview::Response>(&doc, preview_json(&found)),
        Err(NetError::Mismatch(m)) => {
            reject_with_code(&doc, extended_code(PREVIEW_ERR_NETWORK_MISMATCH), m, None)
        }
        Err(NetError::Unavailable(m) | NetError::Refused(m)) => reject_with_code(
            &doc,
            extended_code(PREVIEW_ERR_NETWORK_UNREACHABLE),
            m.clone(),
            Some(json!({ "message": m })),
        ),
        Err(e) => refuse(&doc, "vtc/networks/preview", e),
    }
}

/// The `vtc/networks/preview` answer: the network's own profile, then where the community
/// stands. An entry state outside the published ones is not reported.
fn preview_json(found: &networks::Preview) -> Value {
    let profile = &found.profile["profile"];
    let mut out = json!({
        "network": found.network,
        "url": found.url,
        "name": profile["name"].as_str().unwrap_or_default(),
        "roles": found.profile["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| {
                let name = r["name"].as_str()?;
                let mut role = json!({ "name": name, "required": r["required"] == true });
                if let Some(d) = r["description"].as_str() {
                    role["description"] = json!(d);
                }
                Some(role)
            })
            .collect::<Vec<_>>(),
        "listed": found.listing.is_ok(),
    });
    for key in ["description", "owner"] {
        if let Some(v) = profile[key].as_str() {
            out[key] = json!(v);
        }
    }
    let fw = &profile["framework"];
    if let (Some(iri), Some(version)) = (fw["iri"].as_str(), fw["version"].as_str()) {
        out["framework"] = json!({ "iri": iri, "version": version });
    }
    match &found.listing {
        Ok(entry_state)
            if ["listed", "acknowledged", "repudiated", "suspended"]
                .contains(&entry_state.as_str()) =>
        {
            out["entryState"] = json!(entry_state);
        }
        Ok(_) => {}
        Err(why) => out["notListedReason"] = json!(why.chars().take(1024).collect::<String>()),
    }
    if let Some(m) = found.membership {
        out["membershipState"] = serde_json::to_value(m).unwrap_or(Value::Null);
    }
    out
}

// ─── writes ───────────────────────────────────────────────────────────────

async fn handle_join(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    const SLUG: &str = "vtc/networks/join";
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: join::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    let assignments: Vec<(String, String)> = checked
        .groups
        .iter()
        .map(|g| (g.role.to_string(), g.group_id.to_string()))
        .collect();
    // Everything that would refuse the join, before the gesture (`networks::join_preflight`).
    if let Err(e) =
        networks::join_preflight(state, &checked.url, &checked.network, &assignments).await
    {
        return refuse(&doc, SLUG, e);
    }
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Join the network {}", checked.network.as_str()),
    )
    .await
    {
        return reject;
    }
    match networks::join(
        state,
        &actor.did,
        &checked.url,
        &checked.network,
        &assignments,
    )
    .await
    {
        Ok(m) => respond::<join::Response>(&doc, json!({ "membership": membership_json(&m) })),
        Err(e) => refuse(&doc, SLUG, e),
    }
}

async fn handle_repudiate(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    const SLUG: &str = "vtc/networks/repudiate";
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: repudiate::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    if let Err(e) = networks::repudiate_preflight(state, &checked.url, &checked.network).await {
        return refuse(&doc, SLUG, e);
    }
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!(
            "Repudiate the network {}'s listing",
            checked.network.as_str()
        ),
    )
    .await
    {
        return reject;
    }
    let reason = checked.reason.as_ref().map(|r| r.to_string());
    match networks::repudiate(state, &actor.did, &checked.url, &checked.network, reason).await {
        Ok(m) => respond::<repudiate::Response>(&doc, json!({ "membership": membership_json(&m) })),
        Err(e) => refuse(&doc, SLUG, e),
    }
}

async fn handle_leave(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    const SLUG: &str = "vtc/networks/leave";
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: leave::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    if let Err(e) = networks::leave_preflight(state, &checked.network).await {
        return refuse(&doc, SLUG, e);
    }
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Leave the network {}", checked.network.as_str()),
    )
    .await
    {
        return reject;
    }
    let reason = checked.reason.as_ref().map(|r| r.to_string());
    match networks::leave(state, &actor.did, &checked.network, reason).await {
        Ok(m) => respond::<leave::Response>(&doc, json!({ "membership": membership_json(&m) })),
        Err(e) => refuse(&doc, SLUG, e),
    }
}

async fn handle_register(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    const SLUG: &str = "vtc/networks/groups/register";
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: register::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!(
            "Register the group {} for the role {} in the network {}",
            checked.group_id.as_str(),
            checked.role.as_str(),
            checked.network.as_str()
        ),
    )
    .await
    {
        return reject;
    }
    match networks::register_group(
        state,
        &actor.did,
        &checked.network,
        &checked.role,
        &checked.group_id,
    )
    .await
    {
        Ok(m) => respond::<register::Response>(&doc, json!({ "membership": membership_json(&m) })),
        Err(e) => refuse(&doc, SLUG, e),
    }
}

// ─── member: evidence ─────────────────────────────────────────────────────

async fn handle_evidence(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let Some(caller) = ctx.verified_signer.clone() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::ProofRequired),
            "evidence is released only to a verified member of the group",
            None,
        );
    };
    let checked: evidence::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let group = checked.group_id.as_ref().map(|g| g.to_string());
    let network = checked.network.as_ref().map(|n| n.to_string());
    match networks::evidence(state, &caller, group.as_deref(), network.as_deref()).await {
        Ok(links) => respond::<evidence::Response>(&doc, json!({ "links": links })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── a network: deliver ───────────────────────────────────────────────────

async fn handle_deliver(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    const SLUG: &str = "vtc/networks/deliver";
    let Some(deliverer) = ctx.verified_signer.clone() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::ProofRequired),
            "a delivery is signed by the network that delivers it",
            None,
        );
    };
    let checked: deliver::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let envelope: vti_vtn::relay::Envelope =
        match serde_json::to_value(&checked.envelope).and_then(serde_json::from_value) {
            Ok(e) => e,
            Err(e) => {
                return refuse(
                    &doc,
                    SLUG,
                    NetError::Rejected(format!("unreadable envelope: {e}")),
                );
            }
        };
    match networks::deliver(state, &deliverer, checked.role.as_ref(), envelope).await {
        Ok(status) => respond::<deliver::Response>(&doc, status),
        Err(e) => refuse(&doc, SLUG, e),
    }
}
