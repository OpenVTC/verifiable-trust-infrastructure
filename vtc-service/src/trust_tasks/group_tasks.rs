//! The community's groups on the signed-document spine (`vtc/groups/*`;
//! [`crate::groups`]).
//!
//! | task | authority (read now) |
//! |---|---|
//! | `create/0.1` | `vtc.groups.manage` unqualified, then the `groups` policy |
//! | `update/0.1`, `delete/0.1` | `vtc.groups.manage` for the group, unqualified or `group:<groupId>` |
//! | `list/0.1`, `show/0.1` | an active member or an administrator, each group as their standing lets them see it |
//! | `members/{add,remove}/0.1` | a manager of the group |
//! | `members/list/0.1` | anyone the group shows its members to |
//! | `join/0.1`, `leave/0.1` | an active member, for themselves |
//! | `requests/list/0.1`, `requests/decide/0.1` | a manager of the request's group; nobody decides their own |
//! | `managers/add/0.1` | a manager of the group, who covers the grant they write |
//! | `managers/remove/0.1` | the manager themselves, or `vtc.groups.manage` unqualified |
//! | `bindings/{add,remove}/0.1` | a manager of the group, after their bound gesture: holding `vtc.rooms.manage` for a room; for grants, holding what it confers, and with consent where that confers authority (VTI-DIR-104) |
//! | `bindings/list/0.1` | a manager of the group |
//!
//! None has a REST route. A group the caller may not see answers `notFound`
//! exactly as one that does not exist, on every task.
//!
//! Only static groups are served. A dynamic group's rule is checked, then the
//! create is refused `kindNotServed`: nothing computes its membership yet.

use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::groups::{
    bindings::{
        add::v0_1 as bindings_add, list::v0_1 as bindings_list, remove::v0_1 as bindings_remove,
    },
    create::v0_1 as group_create,
    delete::v0_1 as group_delete,
    join::v0_1 as group_join,
    leave::v0_1 as group_leave,
    list::v0_1 as group_list,
    managers::{add::v0_1 as managers_add, remove::v0_1 as managers_remove},
    members::{
        add::v0_1 as members_add, list::v0_1 as members_list, remove::v0_1 as members_remove,
    },
    requests::{decide::v0_1 as requests_decide, list::v0_1 as requests_list},
    show::v0_1 as group_show,
    update::v0_1 as group_update,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, GroupChangedData, GroupMembershipChangedData};
use vti_common::error::AppError;
use vti_common::pagination::Cursor;

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::acl::admin_consent::{self, Act};
use crate::acl::{CapRef, VtcAclEntry, get_acl_entry};
use crate::error::TaskError;
use crate::groups::identity::{self, Failure};
use crate::groups::policy::{self as group_policy, Facts, GroupFacts};
use crate::groups::{self, Audience, Group, JoinPolicy, JoinRequest, Membership, Standing};
use crate::rooms::community::HolderError;
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <group_create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <group_update::Payload as Payload>::TYPE_URI;
pub(crate) const DELETE_TYPE: &str = <group_delete::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <group_list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <group_show::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_ADD_TYPE: &str = <members_add::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_REMOVE_TYPE: &str = <members_remove::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_LIST_TYPE: &str = <members_list::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_TYPE: &str = <group_join::Payload as Payload>::TYPE_URI;
pub(crate) const LEAVE_TYPE: &str = <group_leave::Payload as Payload>::TYPE_URI;
pub(crate) const REQUESTS_LIST_TYPE: &str = <requests_list::Payload as Payload>::TYPE_URI;
pub(crate) const REQUESTS_DECIDE_TYPE: &str = <requests_decide::Payload as Payload>::TYPE_URI;
pub(crate) const MANAGERS_ADD_TYPE: &str = <managers_add::Payload as Payload>::TYPE_URI;
pub(crate) const MANAGERS_REMOVE_TYPE: &str = <managers_remove::Payload as Payload>::TYPE_URI;
pub(crate) const BINDINGS_ADD_TYPE: &str = <bindings_add::Payload as Payload>::TYPE_URI;
pub(crate) const BINDINGS_REMOVE_TYPE: &str = <bindings_remove::Payload as Payload>::TYPE_URI;
pub(crate) const BINDINGS_LIST_TYPE: &str = <bindings_list::Payload as Payload>::TYPE_URI;

/// Every type this module serves.
pub(crate) const URIS: &[&str] = &[
    CREATE_TYPE,
    UPDATE_TYPE,
    DELETE_TYPE,
    LIST_TYPE,
    SHOW_TYPE,
    MEMBERS_ADD_TYPE,
    MEMBERS_REMOVE_TYPE,
    MEMBERS_LIST_TYPE,
    JOIN_TYPE,
    LEAVE_TYPE,
    REQUESTS_LIST_TYPE,
    REQUESTS_DECIDE_TYPE,
    MANAGERS_ADD_TYPE,
    MANAGERS_REMOVE_TYPE,
    BINDINGS_ADD_TYPE,
    BINDINGS_REMOVE_TYPE,
    BINDINGS_LIST_TYPE,
];

macro_rules! codes {
    ($($name:ident = $module:ident :: $code:ident;)*) => {
        $(pub(crate) const $name: &str = $module::error_codes::$code.code;)*
    };
}

codes! {
    CREATE_ERR_RULE_INVALID = group_create::RULE_INVALID;
    CREATE_ERR_KIND_NOT_SERVED = group_create::KIND_NOT_SERVED;
    CREATE_ERR_SETTINGS_INVALID = group_create::SETTINGS_INVALID;
    CREATE_ERR_POLICY_REFUSED = group_create::POLICY_REFUSED;
    CREATE_ERR_NO_KEY_HOLDER = group_create::NO_KEY_HOLDER;
    CREATE_ERR_KEY_HOLDER_UNAVAILABLE = group_create::KEY_HOLDER_UNAVAILABLE;
    CREATE_ERR_KEY_HOLDER_REFUSED = group_create::KEY_HOLDER_REFUSED;
    UPDATE_ERR_NOT_FOUND = group_update::NOT_FOUND;
    UPDATE_ERR_RULE_INVALID = group_update::RULE_INVALID;
    UPDATE_ERR_SETTINGS_INVALID = group_update::SETTINGS_INVALID;
    UPDATE_ERR_AUTHORITY_GROUP_LOCKED = group_update::AUTHORITY_GROUP_LOCKED;
    DELETE_ERR_NOT_FOUND = group_delete::NOT_FOUND;
    LIST_ERR_CURSOR_INVALID = group_list::CURSOR_INVALID;
    SHOW_ERR_NOT_FOUND = group_show::NOT_FOUND;
    ADD_ERR_NOT_FOUND = members_add::NOT_FOUND;
    ADD_ERR_ENTRY_NOT_FOUND = members_add::ENTRY_NOT_FOUND;
    ADD_ERR_ALREADY_MEMBER = members_add::ALREADY_MEMBER;
    ADD_ERR_EXCEEDS_ROLE_CEILING = members_add::EXCEEDS_ROLE_CEILING;
    ADD_ERR_KEY_HOLDER_UNAVAILABLE = members_add::KEY_HOLDER_UNAVAILABLE;
    ADD_ERR_KEY_HOLDER_REFUSED = members_add::KEY_HOLDER_REFUSED;
    REMOVE_ERR_NOT_FOUND = members_remove::NOT_FOUND;
    REMOVE_ERR_NOT_IN_GROUP = members_remove::NOT_IN_GROUP;
    MEMBERS_LIST_ERR_NOT_FOUND = members_list::NOT_FOUND;
    MEMBERS_LIST_ERR_CURSOR_INVALID = members_list::CURSOR_INVALID;
    JOIN_ERR_NOT_FOUND = group_join::NOT_FOUND;
    JOIN_ERR_NOT_JOINABLE = group_join::NOT_JOINABLE;
    JOIN_ERR_ALREADY_MEMBER = group_join::ALREADY_MEMBER;
    JOIN_ERR_REQUEST_PENDING = group_join::REQUEST_PENDING;
    JOIN_ERR_POLICY_REFUSED = group_join::POLICY_REFUSED;
    JOIN_ERR_KEY_HOLDER_UNAVAILABLE = group_join::KEY_HOLDER_UNAVAILABLE;
    JOIN_ERR_KEY_HOLDER_REFUSED = group_join::KEY_HOLDER_REFUSED;
    LEAVE_ERR_NOT_FOUND = group_leave::NOT_FOUND;
    LEAVE_ERR_NOT_IN_GROUP = group_leave::NOT_IN_GROUP;
    REQUESTS_LIST_ERR_NOT_FOUND = requests_list::NOT_FOUND;
    REQUESTS_LIST_ERR_CURSOR_INVALID = requests_list::CURSOR_INVALID;
    DECIDE_ERR_NOT_FOUND = requests_decide::NOT_FOUND;
    DECIDE_ERR_ALREADY_DECIDED = requests_decide::ALREADY_DECIDED;
    DECIDE_ERR_SELF_DECISION = requests_decide::SELF_DECISION;
    DECIDE_ERR_KEY_HOLDER_UNAVAILABLE = requests_decide::KEY_HOLDER_UNAVAILABLE;
    DECIDE_ERR_KEY_HOLDER_REFUSED = requests_decide::KEY_HOLDER_REFUSED;
    MANAGERS_ADD_ERR_NOT_FOUND = managers_add::NOT_FOUND;
    MANAGERS_ADD_ERR_ENTRY_NOT_FOUND = managers_add::ENTRY_NOT_FOUND;
    MANAGERS_ADD_ERR_ALREADY_MANAGER = managers_add::ALREADY_MANAGER;
    MANAGERS_REMOVE_ERR_NOT_FOUND = managers_remove::NOT_FOUND;
    MANAGERS_REMOVE_ERR_NOT_MANAGER = managers_remove::NOT_MANAGER;
    BINDINGS_ADD_ERR_NOT_FOUND = bindings_add::NOT_FOUND;
    BINDINGS_ADD_ERR_ROOM_NOT_FOUND = bindings_add::ROOM_NOT_FOUND;
    BINDINGS_ADD_ERR_BINDING_EXISTS = bindings_add::BINDING_EXISTS;
    BINDINGS_ADD_ERR_TOO_MANY_BINDINGS = bindings_add::TOO_MANY_BINDINGS;
    BINDINGS_ADD_ERR_GROUP_NOT_ELIGIBLE = bindings_add::GROUP_NOT_ELIGIBLE;
    BINDINGS_ADD_ERR_UNKNOWN_CAPABILITY = bindings_add::UNKNOWN_CAPABILITY;
    BINDINGS_ADD_ERR_UNKNOWN_ROLE = bindings_add::UNKNOWN_ROLE;
    BINDINGS_ADD_ERR_EXCEEDS_BINDER_AUTHORITY = bindings_add::EXCEEDS_BINDER_AUTHORITY;
    BINDINGS_REMOVE_ERR_NOT_FOUND = bindings_remove::NOT_FOUND;
    BINDINGS_REMOVE_ERR_BINDING_NOT_FOUND = bindings_remove::BINDING_NOT_FOUND;
    BINDINGS_LIST_ERR_NOT_FOUND = bindings_list::NOT_FOUND;
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        UPDATE_TYPE => handle_update(state, ctx, doc).await,
        DELETE_TYPE => handle_delete(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        MEMBERS_ADD_TYPE => handle_members_add(state, ctx, doc).await,
        MEMBERS_REMOVE_TYPE => handle_members_remove(state, ctx, doc).await,
        MEMBERS_LIST_TYPE => handle_members_list(state, ctx, doc).await,
        JOIN_TYPE => handle_join(state, ctx, doc).await,
        LEAVE_TYPE => handle_leave(state, ctx, doc).await,
        REQUESTS_LIST_TYPE => handle_requests_list(state, ctx, doc).await,
        REQUESTS_DECIDE_TYPE => handle_requests_decide(state, ctx, doc).await,
        MANAGERS_ADD_TYPE => handle_managers_add(state, ctx, doc).await,
        MANAGERS_REMOVE_TYPE => handle_managers_remove(state, ctx, doc).await,
        BINDINGS_ADD_TYPE => handle_bindings_add(state, ctx, doc).await,
        BINDINGS_REMOVE_TYPE => handle_bindings_remove(state, ctx, doc).await,
        BINDINGS_LIST_TYPE => handle_bindings_list(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ───────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

fn declared_with(
    doc: &TrustTask<Value>,
    code: &str,
    message: impl Into<String>,
    details: Value,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, Some(details))
}

fn denied(doc: &TrustTask<Value>, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

/// The requester's gesture bound to `doc`, then the consent of the other
/// holders of `stake` (VTI-DIR-104 through [`admin_consent`]): parked as `act`
/// on `subject` and answered with the held action, or — on its execution, or
/// in single-administrator mode — spent here. Call it last before the write.
#[allow(clippy::too_many_arguments)]
async fn consent_gate(
    state: &AppState,
    requester: &str,
    doc: &TrustTask<Value>,
    act: admin_consent::Act,
    stake: &[CapRef],
    subject: &str,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<(), TrustTaskOutcome> {
    use admin_consent::{Operation, SignedGate};
    let type_uri = doc.type_uri.to_string();
    let gate = admin_consent::gesture_then_consent_for(
        state,
        act,
        stake,
        requester,
        subject,
        Operation {
            type_uri: &type_uri,
            payload: &doc.payload,
        },
        gesture_reason,
        consent_summary,
    )
    .await;
    match gate {
        Ok(SignedGate::Ready(ready)) => ready
            .spend(state)
            .await
            .map_err(|e| app_error_to_reject(doc, &e)),
        Ok(SignedGate::StepUpRequired(request)) => {
            Err(task_error_to_reject(doc, &TaskError::step_up(request)))
        }
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// The gate on withdrawing a group's authority from every member at once —
/// removing its `grants` or `role` binding `binding_id`, or (`None`) deleting
/// the group: each member's loss is a reduction (VTI-DIR-104, VTI-APV-019;
/// bindings/remove item 3, delete item 5). Where a member other than the
/// requester loses an authority-conferring capability, it is held for the
/// consent of a holder of what is lost who is in the group neither as
/// requester nor as a member ([`Act::ReduceGroupAuthority`]); where nobody is
/// left who could consent, the requester's gesture suffices and the reduction
/// is recorded `Critical` per member once it lands — the entries returned,
/// for [`admin_consent::record_unopposed_reduction`]. It has no cooling-off:
/// a cooling-off suspends its one subject, and this reduction has many.
async fn group_reduction_gate(
    state: &AppState,
    who: &Standing,
    doc: &TrustTask<Value>,
    group: &Group,
    binding_id: Option<&str>,
    gesture_reason: &str,
) -> Result<Vec<VtcAclEntry>, TrustTaskOutcome> {
    let now = vti_common::auth::session::now_epoch();
    let mut lost: Vec<CapRef> = Vec::new();
    let mut affected = Vec::new();
    let dids = groups::member_dids(state, &group.group_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    for did in dids.iter().filter(|d| **d != who.did) {
        let Some(prior) = get_acl_entry(&state.acl_ks, did)
            .await
            .map_err(|e| app_error_to_reject(doc, &e))?
        else {
            continue;
        };
        let after = groups::authority::without(&prior, &group.group_id, binding_id);
        let theirs = admin_consent::lost_conferring(&prior, Some(&after), now);
        if theirs.is_empty() {
            continue;
        }
        for c in theirs {
            if !lost.contains(&c) {
                lost.push(c);
            }
        }
        affected.push(prior);
    }
    if lost.is_empty() {
        crate::trust_tasks::community_room_tasks::bound_step_up(
            state,
            &who.did,
            doc,
            gesture_reason,
        )
        .await?;
        return Ok(Vec::new());
    }
    let subject = admin_consent::group_subject(&group.group_id);
    let third = if admin_consent::single_admin_mode(state).await {
        0
    } else {
        admin_consent::approvers_for(
            state,
            Act::ReduceGroupAuthority,
            &lost,
            &who.did,
            &subject,
            now,
        )
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
        .len()
    };
    if third > 0 || crate::admin_actions::executing().is_some() {
        consent_gate(
            state,
            &who.did,
            doc,
            Act::ReduceGroupAuthority,
            &lost,
            &subject,
            gesture_reason,
            &format!(
                "Take {} away from the members of the group “{}” who hold it through the group",
                lost.iter()
                    .map(CapRef::display)
                    .collect::<Vec<_>>()
                    .join(", "),
                group.name
            ),
        )
        .await?;
        return Ok(Vec::new());
    }
    crate::trust_tasks::community_room_tasks::bound_step_up(state, &who.did, doc, gesture_reason)
        .await?;
    tracing::warn!(
        requester = %who.did,
        group = %group.group_id,
        members = affected.len(),
        "taking a group's authority from its members with nobody else left to consent \
         (VTI-APV-019): the requester's step-up is the only gate"
    );
    Ok(affected)
}

/// Record each unopposed reduction [`group_reduction_gate`] let through, once
/// the write has landed.
async fn record_unopposed(
    state: &AppState,
    who: &Standing,
    doc: &TrustTask<Value>,
    affected: &[VtcAclEntry],
) {
    let task = doc.type_uri.to_string();
    for prior in affected {
        if let Err(e) =
            admin_consent::record_unopposed_reduction(state, &who.did, prior, &task).await
        {
            tracing::warn!(error = %e, "an unopposed group reduction could not be recorded");
        }
    }
}

/// The signer's standing: a portal sign-in key the member delegated
/// `vtc/groups` to as that member, a console key as the administrator it acts
/// for, anyone else as themselves.
async fn standing(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Standing, TrustTaskOutcome> {
    let delegated = match ctx.verified_signer.as_deref() {
        Some(signer) => crate::member_portal::delegation::member_for(
            &state.member_sessions_ks,
            signer,
            &doc.type_uri.to_string(),
        )
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?,
        None => None,
    };
    let did = match delegated {
        Some(member) => member,
        None => member_signer(state, ctx, doc).await?.did,
    };
    Standing::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// The group a manager acts on: `notFound` where the caller may not see it,
/// `permissionDenied` where they may but do not manage it (update and delete
/// item 1).
async fn managed_group(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Standing,
    group_id: &str,
    not_found: &str,
) -> Result<Group, TrustTaskOutcome> {
    let group = groups::get(state.directory.ks(), group_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    match group {
        Some(g) if who.manages(&g.group_id) => Ok(g),
        Some(g) if who.sees(&g) => Err(denied(doc, "you do not manage this group")),
        _ => Err(declared(
            doc,
            not_found,
            "No group you may manage has this identifier.",
        )),
    }
}

/// A directory write is never unaudited.
async fn audit(state: &AppState, actor: &str, event: AuditEvent) -> Result<(), AppError> {
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: group changes are refused rather than made \
                      unaudited"
                .into(),
        })?;
    writer.write(actor, None, event).await.map(drop)
}

fn reason_of(doc: &TrustTask<Value>) -> Option<String> {
    doc.payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn audience(doc: &TrustTask<Value>, member: &str) -> Option<Audience> {
    doc.payload
        .get(member)
        .and_then(Value::as_str)
        .and_then(Audience::parse)
}

/// `showMembers` wider than `visibility` (create item 3).
fn settings_invalid(visibility: Audience, show_members: Audience) -> bool {
    show_members > visibility
}

fn holder_refusal(
    doc: &TrustTask<Value>,
    unavailable: &str,
    refused: Option<&str>,
    e: HolderError,
    group_did: Option<String>,
) -> TrustTaskOutcome {
    match e {
        HolderError::Unavailable(why) => {
            let details = group_did.map(|d| json!({ "groupDid": d }));
            match details {
                Some(d) => declared_with(doc, unavailable, why, d),
                None => declared(doc, unavailable, why),
            }
        }
        HolderError::Refused { code, message } => match refused {
            Some(refused) => declared_with(
                doc,
                refused,
                format!("the community's VTA refused: {code} {message}"),
                HolderError::refused_details(&code, &message),
            ),
            None => declared(
                doc,
                unavailable,
                format!("the community's VTA refused: {code} {message}"),
            ),
        },
    }
}

// ─── create ───────────────────────────────────────────────────────────────

/// `create/0.1` (items 1 – 7).
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    // Item 1: only an unqualified manager creates.
    if !who.manages_all {
        return denied(
            &doc,
            "creating a group takes vtc.groups.manage at the community",
        );
    }
    if let Err(reject) = parse_spec_payload::<group_create::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let dynamic = p.get("kind").and_then(Value::as_str) == Some("dynamic");
    let rule = p.get("rule");
    let (Some(visibility), Some(show_members)) =
        (audience(&doc, "visibility"), audience(&doc, "showMembers"))
    else {
        return app_error_to_reject(&doc, &AppError::Validation("unreadable audiences".into()));
    };

    // Item 2: the rule.
    match (dynamic, rule) {
        (false, Some(_)) => {
            return declared(&doc, CREATE_ERR_RULE_INVALID, "A static group has no rule.");
        }
        (true, None) => {
            return declared(
                &doc,
                CREATE_ERR_RULE_INVALID,
                "A dynamic group needs a rule.",
            );
        }
        (true, Some(rule)) => {
            let schema = match crate::directory::fields::schema(state.directory.ks()).await {
                Ok(s) => s,
                Err(e) => return app_error_to_reject(&doc, &e),
            };
            if let Err(e) = groups::check_rule(rule, &schema) {
                let mut details = json!({ "reason": e.reason.clone() });
                if let Some(f) = &e.field {
                    details["field"] = json!(f);
                }
                return declared_with(&doc, CREATE_ERR_RULE_INVALID, e.reason, details);
            }
        }
        (false, None) => {}
    }
    // Item 3: the settings.
    if dynamic && p.get("joinPolicy").is_some() {
        return declared(
            &doc,
            CREATE_ERR_SETTINGS_INVALID,
            "A dynamic group has no join policy: its rule decides who is in it.",
        );
    }
    if settings_invalid(visibility, show_members) {
        return declared(
            &doc,
            CREATE_ERR_SETTINGS_INVALID,
            "showMembers is never wider than visibility.",
        );
    }
    if dynamic {
        return declared(
            &doc,
            CREATE_ERR_KIND_NOT_SERVED,
            "This community serves only static groups.",
        );
    }
    let join_policy = p
        .get("joinPolicy")
        .and_then(Value::as_str)
        .and_then(JoinPolicy::parse)
        .unwrap_or(JoinPolicy::Closed);
    let issues_credentials = p
        .get("issuesCredentials")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    // Item 1, second half: the policy.
    let role = who
        .administrator
        .then_some("admin")
        .or(who.active_member.then_some("member"));
    let facts = Facts {
        operation: "create",
        now: Utc::now(),
        actor_did: &who.did,
        actor_role: role,
        actor_member: who.active_member,
        actor_manager: true,
        group: GroupFacts {
            group_id: "",
            join_policy: join_policy.as_str(),
            visibility: visibility.as_str(),
            show_members: show_members.as_str(),
            issues_credentials,
            member_count: 0,
        },
    };
    match group_policy::decide(state, &facts).await {
        Ok(None) => {}
        Ok(Some(why)) => return declared(&doc, CREATE_ERR_POLICY_REFUSED, why),
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    // Item 4: the key holder, then remote first.
    let setup = match identity::setup(state).await {
        Ok(s) => s,
        Err(why) => return declared(&doc, CREATE_ERR_NO_KEY_HOLDER, why),
    };
    let minted = match identity::mint(state, &setup, issues_credentials).await {
        Ok(m) => m,
        Err(Failure::Local(e)) => return app_error_to_reject(&doc, &e),
        Err(Failure::Holder(e, did)) => {
            return holder_refusal(
                &doc,
                CREATE_ERR_KEY_HOLDER_UNAVAILABLE,
                Some(CREATE_ERR_KEY_HOLDER_REFUSED),
                e,
                did,
            );
        }
    };
    let now = Utc::now();
    let (authority, authority_credential) = match minted.authority {
        Some((a, c)) => (Some(a), Some(c)),
        None => (None, None),
    };
    // Item 6: no members, no bindings.
    let group = Group {
        group_id: groups::new_group_id(),
        group_did: minted.group_did,
        signing_key_id: minted.signing_key_id,
        name: p
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        description: p
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        join_policy,
        visibility,
        show_members,
        issues_credentials,
        authority,
        authority_credential,
        did_log_path: minted.did_log_path,
        created_at: now,
        created_by: who.entry_id.clone(),
        updated_at: now,
    };
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "created".into(),
            fields: Vec::new(),
            reason: reason_of(&doc),
        }),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Step 3: only now is the group stored.
    if let Err(e) = groups::put(state.directory.ks(), &group).await {
        return app_error_to_reject(&doc, &e);
    }
    match groups::wire(state, &group, &who).await {
        Ok(g) => success_response(&doc, json!({ "group": g })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── update ───────────────────────────────────────────────────────────────

/// `update/0.1` (items 1 – 6).
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<group_update::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let before = match managed_group(state, &doc, &who, group_id, UPDATE_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    // Item 2: a static group never takes a rule.
    if p.get("rule").is_some() {
        return declared(&doc, UPDATE_ERR_RULE_INVALID, "A static group has no rule.");
    }
    let mut next = before.clone();
    let mut changed = Vec::new();
    if let Some(n) = p.get("name").and_then(Value::as_str)
        && n != next.name
    {
        next.name = n.to_string();
        changed.push("name".to_string());
    }
    if let Some(d) = p.get("description").and_then(Value::as_str)
        && next.description.as_deref() != Some(d)
    {
        next.description = Some(d.to_string());
        changed.push("description".to_string());
    }
    if let Some(j) = p
        .get("joinPolicy")
        .and_then(Value::as_str)
        .and_then(JoinPolicy::parse)
        && j != next.join_policy
    {
        // Item 3: a group carrying authority stays closed (VTI-DIR-103).
        match groups::authority::carries_authority(state, &before.group_id).await {
            Ok(true) if j != JoinPolicy::Closed => {
                return declared(
                    &doc,
                    UPDATE_ERR_AUTHORITY_GROUP_LOCKED,
                    "The group carries authority and must stay closed: only its managers add \
                     members.",
                );
            }
            Ok(_) => {}
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        next.join_policy = j;
        changed.push("joinPolicy".to_string());
    }
    if let Some(v) = audience(&doc, "visibility")
        && v != next.visibility
    {
        next.visibility = v;
        changed.push("visibility".to_string());
    }
    if let Some(s) = audience(&doc, "showMembers")
        && s != next.show_members
    {
        next.show_members = s;
        changed.push("showMembers".to_string());
    }
    if settings_invalid(next.visibility, next.show_members) {
        return declared(
            &doc,
            UPDATE_ERR_SETTINGS_INVALID,
            "showMembers is never wider than visibility.",
        );
    }
    if let Some(issues) = p.get("issuesCredentials").and_then(Value::as_bool)
        && issues != next.issues_credentials
    {
        next.issues_credentials = issues;
        changed.push("issuesCredentials".to_string());
        // Item 5: the authority is issued before the change is recorded.
        if issues && next.authority.is_none() {
            let setup = match identity::setup(state).await {
                Ok(s) => s,
                Err(why) => {
                    return app_error_to_reject(
                        &doc,
                        &AppError::ServiceError {
                            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            message: why,
                        },
                    );
                }
            };
            match identity::issue_authority(state, &setup, &next.group_did, Utc::now(), None).await
            {
                Ok((a, c)) => {
                    next.authority = Some(a);
                    next.authority_credential = Some(c);
                }
                Err(Failure::Local(e)) => return app_error_to_reject(&doc, &e),
                Err(Failure::Holder(e, _)) => {
                    let why = match e {
                        HolderError::Unavailable(m) => m,
                        HolderError::Refused { code, message } => {
                            format!("the community's VTA refused: {code} {message}")
                        }
                    };
                    return app_error_to_reject(
                        &doc,
                        &AppError::ServiceError {
                            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            message: why,
                        },
                    );
                }
            }
        }
    }
    if changed.is_empty() {
        return match groups::wire(state, &before, &who).await {
            Ok(g) => success_response(&doc, json!({ "group": g })),
            Err(e) => app_error_to_reject(&doc, &e),
        };
    }
    next.updated_at = Utc::now();
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: next.group_id.clone(),
            change: "updated".into(),
            fields: changed,
            reason: reason_of(&doc),
        }),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Item 4: a narrowing applies at once — every read decides from the record.
    if let Err(e) = groups::put(state.directory.ks(), &next).await {
        return app_error_to_reject(&doc, &e);
    }
    match groups::wire(state, &next, &who).await {
        Ok(g) => success_response(&doc, json!({ "group": g })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── delete ───────────────────────────────────────────────────────────────

/// `delete/0.1` (items 1 – 5). Room bindings go into removal with the group;
/// what a group carrying authority conferred is a reduction of every member
/// ([`group_reduction_gate`]), withdrawn before the answer.
async fn handle_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<group_delete::Payload>(&doc) {
        return reject;
    }
    let group_id = doc
        .payload
        .get("groupId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let group = match managed_group(state, &doc, &who, &group_id, DELETE_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    // Item 5: deleting a group carrying authority takes it from every member,
    // a reduction of each (VTI-DIR-104).
    let carries = match groups::authority::carries_authority(state, &group.group_id).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let members = match groups::member_dids(state, &group.group_id).await {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let unopposed = if carries {
        match group_reduction_gate(
            state,
            &who,
            &doc,
            &group,
            None,
            &format!(
                "Delete the group “{}”, taking away what it gives its members",
                group.name
            ),
        )
        .await
        {
            Ok(a) => a,
            Err(reject) => return reject,
        }
    } else {
        Vec::new()
    };
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "deleted".into(),
            fields: Vec::new(),
            reason: reason_of(&doc),
        }),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Item 3: members' credentials stop renewing with the membership records;
    // the group's own authority is revoked in the community's list.
    if let Some(a) = &group.authority
        && let Err(e) = identity::revoke_authority(state, a).await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Nobody manages a group that is gone.
    if let Err(e) = groups::managers::withdraw_all(state, &group.group_id).await {
        return app_error_to_reject(&doc, &e);
    }
    let bindings_removed =
        match groups::bindings::of_group(state.directory.ks(), &group.group_id).await {
            Ok(b) => b.len(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    let members_removed = match groups::remove(state.directory.ks(), &group.group_id).await {
        Ok(n) => n,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 3: what it conferred goes before the answer, as its records did.
    if carries {
        for did in &members {
            if let Err(e) = groups::authority::provision(state, did).await {
                return app_error_to_reject(&doc, &e);
            }
        }
        if let Err(e) = groups::authority::forget_removed(state).await {
            return app_error_to_reject(&doc, &e);
        }
        record_unopposed(state, &who, &doc, &unopposed).await;
    }
    success_response(
        &doc,
        json!({
            "groupId": group.group_id,
            "state": "deleted",
            "membersRemoved": members_removed,
            "bindingsRemoved": bindings_removed,
        }),
    )
}

// ─── list, show ───────────────────────────────────────────────────────────

async fn cursor_key(state: &AppState) -> Result<Option<[u8; 32]>, AppError> {
    Ok(match state.audit_writer.as_ref() {
        Some(w) => Some(w.active_key().await?.key),
        None => None,
    })
}

/// `list/0.1` (items 1 – 4).
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if !who.may_read() {
        return denied(
            &doc,
            "groups are read by this community's active members and administrators",
        );
    }
    let payload = match parse_spec_payload::<group_list::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let mine = payload.mine.unwrap_or(false);
    let joinable = payload.joinable.unwrap_or(false);
    // Item 2: only the groups the caller may see, then the filters.
    let all: Vec<Group> = match groups::all(state.directory.ks()).await {
        Ok(g) => g
            .into_iter()
            .filter(|g| who.sees(g))
            .filter(|g| !mine || who.member_of.contains(&g.group_id))
            .filter(|g| {
                !joinable
                    || (matches!(g.join_policy, JoinPolicy::Open | JoinPolicy::Request)
                        && who.my_membership(&g.group_id) == "none")
            })
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 4: the cursor is bound to the caller and the filters.
    let key = match cursor_key(state).await {
        Ok(k) => k,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!("groups/list|{}|{mine}|{joinable}", who.did);
    let start = match (payload.cursor.as_ref().map(|c| c.to_string()), &key) {
        (Some(wire), Some(k)) => match Cursor::decode_bound(&wire, k, binding.as_bytes()) {
            Ok(c) => all
                .iter()
                .position(|g| g.group_id.as_bytes() > c.last_key.as_slice())
                .unwrap_or(all.len()),
            Err(_) => {
                return declared(
                    &doc,
                    LIST_ERR_CURSOR_INVALID,
                    "This cursor is not this caller's for these filters.",
                );
            }
        },
        (Some(_), None) => {
            return declared(
                &doc,
                LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for these filters.",
            );
        }
        (None, _) => 0,
    };
    let limit = payload.limit.map_or(50, |l| l.get() as usize).clamp(1, 200);
    let page: Vec<&Group> = all[start..].iter().take(limit).collect();
    let mut items = Vec::with_capacity(page.len());
    for g in &page {
        match groups::wire(state, g, &who).await {
            Ok(w) => {
                items.push(json!({ "group": w, "myMembership": who.my_membership(&g.group_id) }))
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut body = json!({ "items": items });
    if let (Some(k), true, Some(last)) = (&key, start + page.len() < all.len(), page.last()) {
        body["nextCursor"] = json!(
            Cursor::new(last.group_id.as_bytes().to_vec(), all.len() as u64)
                .encode_bound(k, binding.as_bytes())
        );
    }
    success_response(&doc, body)
}

/// `show/0.1` (items 1 – 3).
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if !who.may_read() {
        return denied(
            &doc,
            "groups are read by this community's active members and administrators",
        );
    }
    if let Err(reject) = parse_spec_payload::<group_show::Payload>(&doc) {
        return reject;
    }
    let group_id = doc
        .payload
        .get("groupId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Item 2: absent and invisible answer alike.
    let group = match groups::get(state.directory.ks(), group_id).await {
        Ok(Some(g)) if who.sees(&g) => g,
        Ok(_) => {
            return declared(
                &doc,
                SHOW_ERR_NOT_FOUND,
                "No group you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match groups::wire(state, &group, &who).await {
        Ok(g) => success_response(
            &doc,
            json!({ "group": g, "myMembership": who.my_membership(&group.group_id) }),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── membership ───────────────────────────────────────────────────────────

/// The caller's own directory entry: every member has a card (`card/show`
/// item 3), so one is made now for a member who has never opened theirs.
async fn own_entry(state: &AppState, who: &Standing) -> Result<String, AppError> {
    if let Some(e) = &who.entry_id {
        return Ok(e.clone());
    }
    let dir = &state.directory;
    let own = crate::acl::get_acl_entry(&state.acl_ks, &who.did)
        .await?
        .filter(|e| e.label_set_by_subject)
        .and_then(|e| e.label);
    Ok(
        crate::directory::cards::ensure(dir.ks(), &who.did, &dir.settings(), own.as_deref())
            .await?
            .entry_id,
    )
}

/// An active member's DID, by directory entry — `None` for an entry with no
/// active member behind it.
async fn active_entry(state: &AppState, entry_id: &str) -> Result<Option<String>, AppError> {
    let Some(card) = crate::directory::cards::get(state.directory.ks(), entry_id).await? else {
        return Ok(None);
    };
    Ok(
        crate::member_portal::active::active_member(state, &card.did)
            .await?
            .map(|_| card.did),
    )
}

async fn audit_membership(
    state: &AppState,
    actor: &str,
    group_id: &str,
    entry_id: &str,
    change: &str,
    reason: Option<String>,
) -> Result<(), AppError> {
    audit(
        state,
        actor,
        AuditEvent::GroupMembershipChanged(GroupMembershipChangedData {
            group_id: group_id.to_string(),
            entry_id: entry_id.to_string(),
            change: change.to_string(),
            reason,
        }),
    )
    .await
}

/// Admit `did` (at `entry_id`) to `group` (`members/add` items 3 – 4): where
/// the group issues credentials, its credential is issued and offered
/// **before** the membership is recorded. A membership that appeared while the
/// VTA was asked — a racing admission — is answered as it stands.
async fn admit(
    state: &AppState,
    group: &Group,
    did: &str,
    entry_id: &str,
    source: &str,
) -> Result<Membership, Failure> {
    let issued = if group.issues_credentials {
        Some(groups::credential::issue(state, group, did).await?)
    } else {
        None
    };
    if let Some(i) = &issued {
        groups::credential::offer(state, group, did, i).await;
    }
    let ks = state.directory.ks();
    let _guard = crate::directory::WRITE_LOCK.lock().await;
    if let Some(existing) = groups::membership(ks, &group.group_id, entry_id)
        .await
        .map_err(Failure::Local)?
    {
        return Ok(existing);
    }
    let m = Membership {
        group_id: group.group_id.clone(),
        entry_id: entry_id.to_string(),
        source: source.to_string(),
        since: Utc::now(),
        state: "active".into(),
        credential_id: issued.as_ref().map(|i| i.credential_id.clone()),
        credential_valid_until: issued.as_ref().map(|i| i.valid_until),
    };
    groups::put_membership(ks, &m)
        .await
        .map_err(Failure::Local)?;
    Ok(m)
}

/// `doc`'s answer to a key holder that did not issue a member's credential.
fn admit_refusal(
    doc: &TrustTask<Value>,
    failure: Failure,
    unavailable: &str,
    refused: &str,
) -> TrustTaskOutcome {
    match failure {
        Failure::Local(e) => app_error_to_reject(doc, &e),
        Failure::Holder(e, _) => holder_refusal(doc, unavailable, Some(refused), e, None),
    }
}

/// `members/add/0.1` (items 1 – 5).
async fn handle_members_add(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<members_add::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let entry_id = p.get("entryId").and_then(Value::as_str).unwrap_or_default();
    let group = match managed_group(state, &doc, &who, group_id, ADD_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    // Item 2.
    let did = match active_entry(state, entry_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return declared(
                &doc,
                ADD_ERR_ENTRY_NOT_FOUND,
                "No active member has this entry.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let ks = state.directory.ks();
    match groups::membership(ks, &group.group_id, entry_id).await {
        Ok(Some(_)) => {
            return declared(
                &doc,
                ADD_ERR_ALREADY_MEMBER,
                "The member already belongs to the group.",
            );
        }
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Item 5, and VTI-DIR-104: joining a group carrying authority is a grant.
    if let Err(reject) = authority_admission_gate(state, &who, &did, &group, &doc).await {
        return reject;
    }
    let m = match admit(state, &group, &did, entry_id, "added").await {
        Ok(m) => m,
        Err(f) => {
            return admit_refusal(
                &doc,
                f,
                ADD_ERR_KEY_HOLDER_UNAVAILABLE,
                ADD_ERR_KEY_HOLDER_REFUSED,
            );
        }
    };
    // A request the manager has now answered by adding them is settled.
    if let Ok(Some(mut r)) = groups::pending_request(ks, &group.group_id, entry_id).await {
        r.state = "approved".into();
        r.decided_at = Some(Utc::now());
        r.decided_by = Some(who.did.clone());
        let _ = groups::put_request(ks, &r).await;
    }
    if let Err(e) = audit_membership(
        state,
        &who.did,
        &group.group_id,
        entry_id,
        "added",
        reason_of(&doc),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    // What the group confers is theirs now, not at the reconciler's next pass.
    if let Err(e) = groups::authority::provision(state, &did).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(
        &doc,
        json!({
            "member": groups::member_wire(&m, &who, None),
            "credentialId": m.credential_id,
        }),
    )
}

/// The gate on admitting `did` to `group` when it carries authority
/// (`members/add` item 5, VTI-DIR-104): every grant it would provision must lie
/// inside the member's role ceiling (`exceedsRoleCeiling`), and admitting them
/// is a grant of what it confers — held for the consent of its other holders
/// when that is authority-conferring ([`Act::GroupAuthority`]), else the
/// requester's gesture bound to this document. `Ok` when the group carries
/// none.
async fn authority_admission_gate(
    state: &AppState,
    who: &Standing,
    did: &str,
    group: &Group,
    doc: &TrustTask<Value>,
) -> Result<(), TrustTaskOutcome> {
    let carries = groups::authority::carries_authority(state, &group.group_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    if !carries {
        return Ok(());
    }
    let Some(entry) = get_acl_entry(&state.acl_ks, did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
    else {
        return Ok(());
    };
    let rows = groups::authority::rows_for(state, &entry, group, Utc::now())
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let mut outside: Vec<String> = Vec::new();
    for r in &rows {
        let shown = r.cap_ref().display();
        if !entry.admin.ceiling_admits(&r.cap_ref()) && !outside.contains(&shown) {
            outside.push(shown);
        }
    }
    if !outside.is_empty() {
        outside.truncate(32);
        return Err(declared_with(
            doc,
            ADD_ERR_EXCEEDS_ROLE_CEILING,
            format!(
                "The group confers {}, which the member's administrative role does not admit: a \
                 group confers capabilities within a role's ceiling, never the ceiling \
                 (VTI-DIR-105).",
                outside.join(", ")
            ),
            json!({ "capabilities": outside }),
        ));
    }
    if rows.is_empty() {
        return Ok(());
    }
    let after = groups::authority::with(&entry, &rows);
    let stake = admin_consent::newly_conferred(
        Some(&entry),
        &after,
        vti_common::auth::session::now_epoch(),
    );
    let gesture = format!(
        "Add a member to the group “{}”, giving them what it confers",
        group.name
    );
    if stake.is_empty() {
        return crate::trust_tasks::community_room_tasks::bound_step_up(
            state, &who.did, doc, &gesture,
        )
        .await;
    }
    consent_gate(
        state,
        &who.did,
        doc,
        Act::GroupAuthority,
        &stake,
        did,
        &gesture,
        &format!(
            "Give {did} {} through the group “{}”",
            stake
                .iter()
                .map(CapRef::display)
                .collect::<Vec<_>>()
                .join(", "),
            group.name
        ),
    )
    .await
}

/// `members/remove/0.1` (items 1 – 5): what the group conferred goes with the
/// membership, a reduction where it was authority ([`authority_removal_gate`]).
async fn handle_members_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<members_remove::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let entry_id = p.get("entryId").and_then(Value::as_str).unwrap_or_default();
    let group = match managed_group(state, &doc, &who, group_id, REMOVE_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    // VTI-DIR-104: removing a member from a group carrying authority is a
    // reduction of what it gave them, on the terms of any reduction.
    let reduced = match authority_removal_gate(state, &who, &group, entry_id, &doc).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let outcome = end_membership(
        state,
        &doc,
        &who,
        &group,
        entry_id,
        "removed",
        REMOVE_ERR_NOT_IN_GROUP,
    )
    .await;
    if let Some((prior, agreement)) = reduced {
        let after = get_acl_entry(&state.acl_ks, &prior.did)
            .await
            .ok()
            .flatten();
        if let Err(e) = admin_consent::after_reduction(
            state,
            &who.did,
            &prior,
            after.as_ref(),
            agreement,
            &doc.type_uri.to_string(),
            reason_of(&doc).as_deref(),
            true,
        )
        .await
        {
            tracing::warn!(error = %e, "a group member's reduction could not be recorded");
        }
    }
    outcome
}

/// The gate on removing `entry_id` from `group` when the group gave them
/// something (VTI-DIR-104, VTI-APV-019): [`admin_consent::settle_reduction_as`]
/// over their entry as it is and as it will be, parked as
/// [`Act::ReduceGroupAuthority`]. `Ok(None)` when the group gave them nothing,
/// or the reduction needs nothing beyond what it took.
async fn authority_removal_gate(
    state: &AppState,
    who: &Standing,
    group: &Group,
    entry_id: &str,
    doc: &TrustTask<Value>,
) -> Result<Option<(VtcAclEntry, admin_consent::Agreement)>, TrustTaskOutcome> {
    let Some(card) = crate::directory::cards::get(state.directory.ks(), entry_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
    else {
        return Ok(None);
    };
    let Some(prior) = get_acl_entry(&state.acl_ks, &card.did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
    else {
        return Ok(None);
    };
    if !prior
        .group_grants
        .iter()
        .any(|g| g.group_id == group.group_id)
    {
        return Ok(None);
    }
    let after = groups::authority::without(&prior, &group.group_id, None);
    let type_uri = doc.type_uri.to_string();
    match admin_consent::settle_reduction_as(
        state,
        Act::ReduceGroupAuthority,
        &who.did,
        &prior,
        Some(&after),
        admin_consent::Operation {
            type_uri: &type_uri,
            payload: &doc.payload,
        },
        &format!(
            "Remove a member from the group “{}”, taking away what it gave them",
            group.name
        ),
        &format!(
            "Take away what the group “{}” gives {}",
            group.name, prior.did
        ),
    )
    .await
    {
        Ok(Some(agreement)) => Ok(Some((prior, agreement))),
        Ok(None) => Ok(None),
        Err(e) => Err(task_error_to_reject(doc, &e)),
    }
}

/// End `entry_id`'s membership of `group` (`members/remove` items 3 – 5):
/// renewal of its credential stops with the record.
async fn end_membership(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Standing,
    group: &Group,
    entry_id: &str,
    change: &str,
    not_in_group: &str,
) -> TrustTaskOutcome {
    let ks = state.directory.ks();
    let m = {
        let _guard = crate::directory::WRITE_LOCK.lock().await;
        match groups::membership(ks, &group.group_id, entry_id).await {
            Ok(Some(m)) => {
                if let Err(e) = groups::remove_membership(ks, &group.group_id, entry_id).await {
                    return app_error_to_reject(doc, &e);
                }
                m
            }
            Ok(None) => {
                return declared(doc, not_in_group, "The entry does not belong to the group.");
            }
            Err(e) => return app_error_to_reject(doc, &e),
        }
    };
    if let Err(e) = audit_membership(
        state,
        &who.did,
        &group.group_id,
        entry_id,
        change,
        reason_of(doc),
    )
    .await
    {
        return app_error_to_reject(doc, &e);
    }
    // Item 5: what the group conferred goes with the membership, at once.
    match crate::directory::cards::get(ks, entry_id).await {
        Ok(Some(card)) => {
            if let Err(e) = groups::authority::provision(state, &card.did).await {
                return app_error_to_reject(doc, &e);
            }
        }
        Ok(None) => {}
        Err(e) => return app_error_to_reject(doc, &e),
    }
    let state_word = if change == "left" { "left" } else { "removed" };
    let mut body = json!({
        "groupId": group.group_id,
        "entryId": entry_id,
        "state": state_word,
    });
    if change == "left" {
        body = json!({ "groupId": group.group_id, "state": state_word });
    }
    if let Some(u) = m.credential_valid_until {
        body["credentialValidUntil"] = json!(u);
    }
    success_response(doc, body)
}

/// Bind and read a list cursor: `Ok(start)`, or `Err(())` for one this caller
/// and these filters were not given.
async fn cursor_start<T>(
    state: &AppState,
    wire: Option<String>,
    binding: &str,
    items: &[T],
    key_of: impl Fn(&T) -> &[u8],
) -> Result<(usize, Option<[u8; 32]>), Result<(), AppError>> {
    let key = cursor_key(state).await.map_err(Err)?;
    let start = match (wire, &key) {
        (Some(w), Some(k)) => match Cursor::decode_bound(&w, k, binding.as_bytes()) {
            Ok(c) => items
                .iter()
                .position(|i| key_of(i) > c.last_key.as_slice())
                .unwrap_or(items.len()),
            Err(_) => return Err(Ok(())),
        },
        (Some(_), None) => return Err(Ok(())),
        (None, _) => 0,
    };
    Ok((start, key))
}

/// `members/list/0.1` (items 1 – 4).
async fn handle_members_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if !who.may_read() {
        return denied(
            &doc,
            "groups are read by this community's active members and administrators",
        );
    }
    let payload = match parse_spec_payload::<members_list::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let group_id = payload.group_id.to_string();
    let ks = state.directory.ks();
    // Item 1.
    let group = match groups::get(ks, &group_id).await {
        Ok(Some(g)) if who.sees(&g) => g,
        Ok(_) => {
            return declared(
                &doc,
                MEMBERS_LIST_ERR_NOT_FOUND,
                "No group you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !who.sees_members(&group) {
        return denied(&doc, "this group does not show its members to you");
    }
    let manager = who.manages(&group.group_id);
    let members: Vec<Membership> = match groups::members_of(ks, &group.group_id).await {
        // Item 3: pending members to managers only.
        Ok(m) => m
            .into_iter()
            .filter(|m| manager || m.state == "active")
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!("groups/members/list|{}|{}", who.did, group.group_id);
    let (start, key) = match cursor_start(
        state,
        payload.cursor.as_ref().map(|c| c.to_string()),
        &binding,
        &members,
        |m| m.entry_id.as_bytes(),
    )
    .await
    {
        Ok(s) => s,
        Err(Ok(())) => {
            return declared(
                &doc,
                MEMBERS_LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for this group.",
            );
        }
        Err(Err(e)) => return app_error_to_reject(&doc, &e),
    };
    let limit = payload.limit.map_or(50, |l| l.get() as usize).clamp(1, 200);
    let page: Vec<&Membership> = members[start..].iter().take(limit).collect();
    // Item 2: each member's fields exactly as entries/show projects them.
    let viewer = match crate::directory::read::viewer(state, &who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut items = Vec::with_capacity(page.len());
    for m in &page {
        items.push(groups::member_wire(
            m,
            &who,
            projected_fields(state, &viewer, &m.entry_id).await,
        ));
    }
    let mut body = json!({ "items": items });
    if let (Some(k), true, Some(last)) = (&key, start + page.len() < members.len(), page.last()) {
        body["nextCursor"] = json!(
            Cursor::new(last.entry_id.as_bytes().to_vec(), members.len() as u64)
                .encode_bound(k, binding.as_bytes())
        );
    }
    success_response(&doc, body)
}

/// An entry's fields as `vtc/directory/entries/show` projects them for
/// `viewer`; `None` where it shows them none.
async fn projected_fields(
    state: &AppState,
    viewer: &crate::directory::project::Viewer,
    entry_id: &str,
) -> Option<Value> {
    use crate::directory::read::{ShowBy, show};
    match show(state, viewer, &ShowBy::Entry(entry_id.to_string())).await {
        Ok(entry) => entry
            .get("fields")
            .filter(|f| f.as_object().is_some_and(|o| !o.is_empty()))
            .cloned(),
        Err(_) => None,
    }
}

/// `join/0.1` (items 1 – 5) for a static group.
async fn handle_join(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let mut who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if !who.active_member {
        return denied(&doc, "groups are joined by this community's active members");
    }
    if let Err(reject) = parse_spec_payload::<group_join::Payload>(&doc) {
        return reject;
    }
    let group_id = doc
        .payload
        .get("groupId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ks = state.directory.ks();
    let group = match groups::get(ks, group_id).await {
        Ok(Some(g)) if who.sees(&g) => g,
        Ok(_) => {
            return declared(
                &doc,
                JOIN_ERR_NOT_FOUND,
                "No group you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let entry_id = match own_entry(state, &who).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    who.entry_id = Some(entry_id.clone());
    // Item 2.
    if group.join_policy == JoinPolicy::Closed {
        return declared(
            &doc,
            JOIN_ERR_NOT_JOINABLE,
            "This group is closed: its managers add its members.",
        );
    }
    if who.member_of.contains(&group.group_id) || who.pending_in.contains(&group.group_id) {
        return declared(
            &doc,
            JOIN_ERR_ALREADY_MEMBER,
            "You already belong to this group.",
        );
    }
    match groups::pending_request(ks, &group.group_id, &entry_id).await {
        Ok(Some(_)) => {
            return declared(
                &doc,
                JOIN_ERR_REQUEST_PENDING,
                "You already asked to join this group.",
            );
        }
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let operation = if group.join_policy == JoinPolicy::Open {
        "join"
    } else {
        "request"
    };
    let member_count = groups::members_of(ks, &group.group_id)
        .await
        .map(|m| m.iter().filter(|m| m.state == "active").count())
        .unwrap_or(0);
    let facts = Facts {
        operation,
        now: Utc::now(),
        actor_did: &who.did,
        actor_role: Some("member"),
        actor_member: true,
        actor_manager: who.manages(&group.group_id),
        group: GroupFacts {
            group_id: &group.group_id,
            join_policy: group.join_policy.as_str(),
            visibility: group.visibility.as_str(),
            show_members: group.show_members.as_str(),
            issues_credentials: group.issues_credentials,
            member_count,
        },
    };
    match group_policy::decide(state, &facts).await {
        Ok(None) => {}
        Ok(Some(why)) => return declared(&doc, JOIN_ERR_POLICY_REFUSED, why),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if group.join_policy == JoinPolicy::Request {
        // Item 5.
        let r = JoinRequest {
            request_id: groups::new_request_id(),
            group_id: group.group_id.clone(),
            entry_id: entry_id.clone(),
            message: doc
                .payload
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
            created_at: Utc::now(),
            state: "pending".into(),
            decided_at: None,
            decided_by: None,
            reason: None,
        };
        if let Err(e) = audit_membership(
            state,
            &who.did,
            &group.group_id,
            &entry_id,
            "requested",
            None,
        )
        .await
        {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = groups::put_request(ks, &r).await {
            return app_error_to_reject(&doc, &e);
        }
        return success_response(
            &doc,
            json!({
                "groupId": group.group_id,
                "outcome": "requested",
                "request": r.wire(false),
                "credentialId": null,
            }),
        );
    }
    // Item 4.
    let m = match admit(state, &group, &who.did, &entry_id, "joined").await {
        Ok(m) => m,
        Err(f) => {
            return admit_refusal(
                &doc,
                f,
                JOIN_ERR_KEY_HOLDER_UNAVAILABLE,
                JOIN_ERR_KEY_HOLDER_REFUSED,
            );
        }
    };
    if let Err(e) =
        audit_membership(state, &who.did, &group.group_id, &entry_id, "joined", None).await
    {
        return app_error_to_reject(&doc, &e);
    }
    success_response(
        &doc,
        json!({
            "groupId": group.group_id,
            "outcome": "joined",
            "member": groups::member_wire(&m, &who, None),
            "credentialId": m.credential_id,
        }),
    )
}

/// `leave/0.1` (items 1 – 4) for a static group: withdraw a pending request,
/// else end the membership.
async fn handle_leave(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let mut who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if !who.active_member {
        return denied(&doc, "groups are left by this community's active members");
    }
    if let Err(reject) = parse_spec_payload::<group_leave::Payload>(&doc) {
        return reject;
    }
    let group_id = doc
        .payload
        .get("groupId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ks = state.directory.ks();
    let group = match groups::get(ks, group_id).await {
        Ok(Some(g)) if who.sees(&g) => g,
        Ok(_) => {
            return declared(
                &doc,
                LEAVE_ERR_NOT_FOUND,
                "No group you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let entry_id = match own_entry(state, &who).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    who.entry_id = Some(entry_id.clone());
    if let Ok(Some(mut r)) = groups::pending_request(ks, &group.group_id, &entry_id).await {
        r.state = "withdrawn".into();
        r.decided_at = Some(Utc::now());
        if let Err(e) = audit_membership(
            state,
            &who.did,
            &group.group_id,
            &entry_id,
            "withdrawn",
            None,
        )
        .await
        {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = groups::put_request(ks, &r).await {
            return app_error_to_reject(&doc, &e);
        }
        return success_response(
            &doc,
            json!({ "groupId": group.group_id, "state": "requestWithdrawn" }),
        );
    }
    end_membership(
        state,
        &doc,
        &who,
        &group,
        &entry_id,
        "left",
        LEAVE_ERR_NOT_IN_GROUP,
    )
    .await
}

/// `requests/list/0.1` (items 1 – 3).
async fn handle_requests_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let payload = match parse_spec_payload::<requests_list::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let only = payload.group_id.as_ref().map(|g| g.to_string());
    let wanted = payload
        .state
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "pending".into());
    let ks = state.directory.ks();
    // Item 1.
    if let Some(g) = &only {
        match groups::get(ks, g).await {
            Ok(Some(group)) if who.manages(&group.group_id) => {}
            Ok(_) => {
                return declared(
                    &doc,
                    REQUESTS_LIST_ERR_NOT_FOUND,
                    "No group you manage has this identifier.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut all: Vec<JoinRequest> = match groups::all_requests(ks).await {
        Ok(r) => r
            .into_iter()
            .filter(|r| r.state == wanted)
            .filter(|r| only.as_ref().is_none_or(|g| &r.group_id == g))
            .filter(|r| who.manages(&r.group_id))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // The cursor compares request identifiers, so pages are in their order.
    all.sort_by(|a, b| a.request_id.cmp(&b.request_id));
    // Item 3.
    let binding = format!(
        "groups/requests/list|{}|{}|{wanted}",
        who.did,
        only.as_deref().unwrap_or("")
    );
    let (start, key) = match cursor_start(
        state,
        payload.cursor.as_ref().map(|c| c.to_string()),
        &binding,
        &all,
        |r| r.request_id.as_bytes(),
    )
    .await
    {
        Ok(s) => s,
        Err(Ok(())) => {
            return declared(
                &doc,
                REQUESTS_LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for these filters.",
            );
        }
        Err(Err(e)) => return app_error_to_reject(&doc, &e),
    };
    let limit = payload.limit.map_or(50, |l| l.get() as usize).clamp(1, 200);
    let page: Vec<&JoinRequest> = all[start..].iter().take(limit).collect();
    let viewer = match crate::directory::read::viewer(state, &who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut items = Vec::with_capacity(page.len());
    for r in &page {
        let mut item = json!({ "request": r.wire(true) });
        if let Some(f) = projected_fields(state, &viewer, &r.entry_id).await {
            item["fields"] = f;
        }
        items.push(item);
    }
    let mut body = json!({ "items": items });
    if let (Some(k), true, Some(last)) = (&key, start + page.len() < all.len(), page.last()) {
        body["nextCursor"] = json!(
            Cursor::new(last.request_id.as_bytes().to_vec(), all.len() as u64)
                .encode_bound(k, binding.as_bytes())
        );
    }
    success_response(&doc, body)
}

/// `requests/decide/0.1` (items 1 – 3).
async fn handle_requests_decide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<requests_decide::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let request_id = p
        .get("requestId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let approve = p.get("decision").and_then(Value::as_str) == Some("approve");
    let ks = state.directory.ks();
    // Item 1.
    let mut r = match groups::get_request(ks, request_id).await {
        Ok(Some(r)) if who.manages(&r.group_id) => r,
        Ok(_) => {
            return declared(
                &doc,
                DECIDE_ERR_NOT_FOUND,
                "No request to a group you manage has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if r.state != "pending" {
        return declared(
            &doc,
            DECIDE_ERR_ALREADY_DECIDED,
            "This request is no longer pending.",
        );
    }
    if who.entry_id.as_deref() == Some(r.entry_id.as_str()) {
        return declared(
            &doc,
            DECIDE_ERR_SELF_DECISION,
            "Nobody decides their own request.",
        );
    }
    let group = match groups::get(ks, &r.group_id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return declared(
                &doc,
                DECIDE_ERR_NOT_FOUND,
                "No request to a group you manage has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut member = None;
    if approve {
        // Item 2: re-checked now. A requester who has left, or a group that no
        // longer takes requests, ends the request declined.
        let did = match active_entry(state, &r.entry_id).await {
            Ok(d) => d,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        match did {
            Some(did) if group.join_policy == JoinPolicy::Request => {
                match admit(state, &group, &did, &r.entry_id, "requestApproved").await {
                    Ok(m) => member = Some(m),
                    Err(f) => {
                        return admit_refusal(
                            &doc,
                            f,
                            DECIDE_ERR_KEY_HOLDER_UNAVAILABLE,
                            DECIDE_ERR_KEY_HOLDER_REFUSED,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    r.state = if member.is_some() {
        "approved"
    } else {
        "declined"
    }
    .into();
    r.decided_at = Some(Utc::now());
    r.decided_by = Some(who.did.clone());
    r.reason = reason_of(&doc);
    if let Err(e) = audit_membership(
        state,
        &who.did,
        &r.group_id,
        &r.entry_id,
        &r.state.clone(),
        None,
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = groups::put_request(ks, &r).await {
        return app_error_to_reject(&doc, &e);
    }
    let mut body = json!({ "request": r.wire(true) });
    if let Some(m) = &member {
        body["member"] = groups::member_wire(m, &who, None);
        body["credentialId"] = json!(m.credential_id);
    }
    success_response(&doc, body)
}

// ─── managers ─────────────────────────────────────────────────────────────

/// `managers/add/0.1` (items 1 – 7).
async fn handle_managers_add(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<managers_add::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let entry_id = p.get("entryId").and_then(Value::as_str).unwrap_or_default();
    // Items 1 and 4: managing the group is covering the grant.
    let group = match managed_group(state, &doc, &who, group_id, MANAGERS_ADD_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    let did = match active_entry(state, entry_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return declared(
                &doc,
                MANAGERS_ADD_ERR_ENTRY_NOT_FOUND,
                "No active member has this entry.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 2: by a grant to this group, or by managing every group.
    let already = match crate::acl::get_acl_entry(&state.acl_ks, &did).await {
        Ok(Some(e)) => {
            groups::managers::appointed(&e, &group.group_id)
                || e.can(crate::acl::Capability::GroupsManage, None)
        }
        Ok(None) => false,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if already {
        return declared(
            &doc,
            MANAGERS_ADD_ERR_ALREADY_MANAGER,
            "This member already manages the group.",
        );
    }
    // Item 7.
    if let Err(e) = audit_membership(
        state,
        &who.did,
        &group.group_id,
        entry_id,
        "managerAppointed",
        None,
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Item 3.
    if let Err(e) =
        groups::managers::appoint(state, &who.did, &did, &group.group_id, reason_of(&doc)).await
    {
        return app_error_to_reject(&doc, &e);
    }
    match groups::managers(state, &group.group_id).await {
        Ok(m) => success_response(&doc, json!({ "groupId": group.group_id, "managers": m })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `managers/remove/0.1` (items 1 – 4).
async fn handle_managers_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<managers_remove::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let entry_id = p.get("entryId").and_then(Value::as_str).unwrap_or_default();
    let group =
        match managed_group(state, &doc, &who, group_id, MANAGERS_REMOVE_ERR_NOT_FOUND).await {
            Ok(g) => g,
            Err(reject) => return reject,
        };
    // Item 2: managers of one group do not remove one another.
    let own = who.entry_id.as_deref() == Some(entry_id);
    if !own && !who.manages_all {
        return denied(
            &doc,
            "only an administrator who manages every group removes another manager",
        );
    }
    let not_manager = || {
        declared(
            &doc,
            MANAGERS_REMOVE_ERR_NOT_MANAGER,
            "This entry holds no appointment to manage the group.",
        )
    };
    let did = match crate::directory::cards::get(state.directory.ks(), entry_id).await {
        Ok(Some(card)) => card.did,
        Ok(None) => return not_manager(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 3: the capability held unqualified is no appointment.
    match groups::managers::withdraw(state, &did, &group.group_id).await {
        Ok(true) => {}
        Ok(false) => return not_manager(),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Err(e) = audit_membership(
        state,
        &who.did,
        &group.group_id,
        entry_id,
        "managerRemoved",
        reason_of(&doc),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    match groups::managers(state, &group.group_id).await {
        Ok(m) => success_response(&doc, json!({ "groupId": group.group_id, "managers": m })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── bindings ─────────────────────────────────────────────────────────────

/// `bindings/add/0.1`. A grants or role binding is
/// [`bindings_add_authority`]'s.
///
/// A room binding admits every member of the group to the room, as
/// `vtc/rooms/community/members/add` admits one, so it takes the same
/// authority — `vtc.rooms.manage` beside managing the group — and the same
/// gesture bound to this document, and is not parked: community room changes
/// never are (the specification's SHOULD on holding a `curate` binding for
/// consent is met by that gesture, as for a direct admission with `curate`).
async fn handle_bindings_add(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::groups::bindings::{self, Binding, RoomBinding};
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<bindings_add::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let spec = p.get("binding").cloned().unwrap_or(Value::Null);
    let reason = reason_of(&doc).unwrap_or_default();
    // Item 1.
    let group = match managed_group(state, &doc, &who, group_id, BINDINGS_ADD_ERR_NOT_FOUND).await {
        Ok(g) => g,
        Err(reject) => return reject,
    };
    if groups::authority::confers_authority(&spec) {
        return bindings_add_authority(state, &doc, &who, &group, spec, reason).await;
    }
    let Some(rb) = RoomBinding::from_spec(&spec) else {
        return app_error_to_reject(
            &doc,
            &AppError::Validation(
                "the room binding's validFor is not a whole number of days".into(),
            ),
        );
    };
    // Item 2.
    let room = match state.community_rooms.room(&rb.room_id).await {
        Ok(Some(room)) if who.can(crate::acl::Capability::RoomsManage) => room,
        Ok(_) => {
            return declared(
                &doc,
                BINDINGS_ADD_ERR_ROOM_NOT_FOUND,
                "The community owns no room with this identifier that you may manage.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let ks = state.directory.ks();
    let existing = match bindings::of_group(ks, &group.group_id).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if existing
        .iter()
        .any(|b| b.binding == spec && b.state == Binding::ACTIVE)
    {
        return declared(
            &doc,
            BINDINGS_ADD_ERR_BINDING_EXISTS,
            "An equal binding already exists.",
        );
    }
    if existing.len() >= bindings::MAX_BINDINGS {
        return declared(
            &doc,
            BINDINGS_ADD_ERR_TOO_MANY_BINDINGS,
            format!("The group already has {} bindings.", bindings::MAX_BINDINGS),
        );
    }
    if let Err(reject) = crate::trust_tasks::community_room_tasks::bound_step_up(
        state,
        &who.did,
        &doc,
        &format!(
            "Admit every member of the group “{}” to the community room “{}”",
            group.name, room.label
        ),
    )
    .await
    {
        return reject;
    }
    // Item 4: recorded, then the reconciler offers each member admission.
    let b = Binding {
        binding_id: bindings::new_binding_id(),
        group_id: group.group_id.clone(),
        binding: spec,
        state: Binding::ACTIVE.into(),
        created_at: Utc::now(),
        created_by: who.did.clone(),
        reason: reason.clone(),
        delegated_by: None,
    };
    if let Err(e) = bindings::put(ks, &b).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "bindingAdded".into(),
            fields: vec![b.binding_id.clone()],
            reason: Some(reason),
        }),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "binding": b.wire() }))
}

/// `bindings/add/0.1` for a `grants` or `role` binding (items 3 – 5, 8):
/// the group must be static and closed (`groupNotEligible`), every capability
/// one this community recognises (`unknownCapability`) or a defined role's
/// (`unknownRole`), and held by the requester themselves, never through a
/// group (`exceedsBinderAuthority`, VTI-ACL-071). Binding an
/// authority-conferring capability is granting it (VTI-DIR-104): held for the
/// consent of its other holders ([`Act::GroupAuthority`]) and recorded only
/// when that executes, re-checked then. A binding of capabilities that confer
/// none takes the requester's gesture bound to this document. Once recorded,
/// every member's entry is provisioned before the answer.
async fn bindings_add_authority(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Standing,
    group: &Group,
    spec: Value,
    reason: String,
) -> TrustTaskOutcome {
    use crate::groups::authority::{self, AuthorityBinding};
    use crate::groups::bindings::{self, Binding};
    // Item 3.
    if group.join_policy != JoinPolicy::Closed {
        return declared(
            doc,
            BINDINGS_ADD_ERR_GROUP_NOT_ELIGIBLE,
            "A group carrying authority is static and closed: only its managers add members \
             (VTI-DIR-103). Close the group first.",
        );
    }
    let caps = match spec.get("kind").and_then(Value::as_str) {
        Some("grants") => match authority::parse_grants(&spec) {
            Ok(c) => c,
            Err(mut unknown) => {
                unknown.truncate(32);
                return declared_with(
                    doc,
                    BINDINGS_ADD_ERR_UNKNOWN_CAPABILITY,
                    format!(
                        "This community's capability registry has no {}.",
                        unknown.join(", ")
                    ),
                    json!({ "capabilities": unknown }),
                );
            }
        },
        _ => {
            let name = spec.get("role").and_then(Value::as_str).unwrap_or_default();
            match authority::role_capabilities(state, name).await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    return declared(
                        doc,
                        BINDINGS_ADD_ERR_UNKNOWN_ROLE,
                        format!("No role named “{name}” is defined."),
                    );
                }
                Err(e) => return app_error_to_reject(doc, &e),
            }
        }
    };
    if AuthorityBinding::from_spec(&spec).is_none() {
        return app_error_to_reject(
            doc,
            &AppError::Validation("the binding names no grant set".into()),
        );
    }
    let binder = match get_acl_entry(&state.acl_ks, &who.did).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let mut beyond: Vec<String> = caps
        .iter()
        .filter(|c| {
            !binder
                .as_ref()
                .is_some_and(|b| authority::binder_holds(b, c))
        })
        .map(CapRef::display)
        .collect();
    if !beyond.is_empty() {
        beyond.truncate(32);
        return declared_with(
            doc,
            BINDINGS_ADD_ERR_EXCEEDS_BINDER_AUTHORITY,
            format!(
                "You do not hold {} yourself, other than through a group, so you cannot bind it \
                 (VTI-ACL-071).",
                beyond.join(", ")
            ),
            json!({ "capabilities": beyond }),
        );
    }
    let ks = state.directory.ks();
    let existing = match bindings::of_group(ks, &group.group_id).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if existing
        .iter()
        .any(|b| b.binding == spec && b.state == Binding::ACTIVE)
    {
        return declared(
            doc,
            BINDINGS_ADD_ERR_BINDING_EXISTS,
            "An equal binding already exists.",
        );
    }
    if existing.len() >= bindings::MAX_BINDINGS {
        return declared(
            doc,
            BINDINGS_ADD_ERR_TOO_MANY_BINDINGS,
            format!("The group already has {} bindings.", bindings::MAX_BINDINGS),
        );
    }
    let stake: Vec<CapRef> = caps
        .iter()
        .filter(|c| c.is_authority_conferring())
        .cloned()
        .collect();
    let shown = caps
        .iter()
        .map(CapRef::display)
        .collect::<Vec<_>>()
        .join(", ");
    let gesture = format!(
        "Give every member of the group “{}” {shown}, through the group",
        group.name
    );
    let gate = if stake.is_empty() {
        crate::trust_tasks::community_room_tasks::bound_step_up(state, &who.did, doc, &gesture)
            .await
    } else {
        consent_gate(
            state,
            &who.did,
            doc,
            Act::GroupAuthority,
            &stake,
            &admin_consent::group_subject(&group.group_id),
            &gesture,
            &format!(
                "Give {shown} to every member of the group “{}” whose role admits it — now, and \
                 to each member added later",
                group.name
            ),
        )
        .await
    };
    if let Err(reject) = gate {
        return reject;
    }
    // Item 4: recorded, then every member provisioned.
    let b = Binding {
        binding_id: bindings::new_binding_id(),
        group_id: group.group_id.clone(),
        binding: spec,
        state: Binding::ACTIVE.into(),
        created_at: Utc::now(),
        created_by: who.did.clone(),
        reason: reason.clone(),
        delegated_by: None,
    };
    if let Err(e) = bindings::put(ks, &b).await {
        return app_error_to_reject(doc, &e);
    }
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "bindingAdded".into(),
            fields: vec![b.binding_id.clone()],
            reason: Some(reason),
        }),
    )
    .await
    {
        return app_error_to_reject(doc, &e);
    }
    if let Err(e) = authority::provision_group(state, &group.group_id).await {
        tracing::warn!(group = %group.group_id, error = %e,
            "a new binding's grants were not all provisioned; the reconciler finishes it");
    }
    success_response(doc, json!({ "binding": b.wire() }))
}

/// `bindings/remove/0.1`: the binding goes into removal, and the reconciler
/// withdraws each admission only it covered, then deletes it (item 2). One that
/// covered nobody is deleted at once.
async fn handle_bindings_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::groups::bindings::{self, Binding};
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<bindings_remove::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let group_id = p.get("groupId").and_then(Value::as_str).unwrap_or_default();
    let binding_id = p
        .get("bindingId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let reason = reason_of(&doc).unwrap_or_default();
    let group =
        match managed_group(state, &doc, &who, group_id, BINDINGS_REMOVE_ERR_NOT_FOUND).await {
            Ok(g) => g,
            Err(reject) => return reject,
        };
    let ks = state.directory.ks();
    let mut b = match bindings::get(ks, &group.group_id, binding_id).await {
        Ok(Some(b)) if b.state != Binding::REMOVING => b,
        Ok(_) => {
            return declared(
                &doc,
                BINDINGS_REMOVE_ERR_BINDING_NOT_FOUND,
                "The group has no binding with this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if groups::authority::confers_authority(&b.binding) {
        return bindings_remove_authority(state, &doc, &who, &group, b, reason).await;
    }
    let room_label = match b.room() {
        Some(rb) => {
            if !who.can(crate::acl::Capability::RoomsManage) {
                return denied(&doc, "removing a room binding takes vtc.rooms.manage");
            }
            match state.community_rooms.room(&rb.room_id).await {
                Ok(r) => r.map(|r| r.label).unwrap_or(rb.room_id),
                Err(e) => return app_error_to_reject(&doc, &e),
            }
        }
        None => String::new(),
    };
    if let Err(reject) = crate::trust_tasks::community_room_tasks::bound_step_up(
        state,
        &who.did,
        &doc,
        &format!(
            "Stop admitting the members of the group “{}” to the community room “{}”",
            group.name, room_label
        ),
    )
    .await
    {
        return reject;
    }
    let named = match b.room() {
        Some(rb) => match state.community_rooms.members(&rb.room_id).await {
            Ok(m) => m.iter().any(|r| {
                r.state != crate::rooms::community::MemberRecord::REMOVED
                    && r.sources.contains(&b.binding_id)
            }),
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => false,
    };
    let outcome = if named {
        b.state = Binding::REMOVING.into();
        bindings::put(ks, &b).await.map(|()| "removing")
    } else {
        bindings::delete(ks, &b.group_id, &b.binding_id)
            .await
            .map(|()| "removed")
    };
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "bindingRemoved".into(),
            fields: vec![b.binding_id.clone()],
            reason: Some(reason),
        }),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "bindingId": b.binding_id, "state": outcome }))
}

/// `bindings/remove/0.1` for a `grants` or `role` binding (items 2 – 4): every
/// member's loss is a reduction ([`group_reduction_gate`]); then the binding
/// goes into removal, each member's rows from it are withdrawn before the
/// answer, and the binding, named by nothing, is deleted.
async fn bindings_remove_authority(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Standing,
    group: &Group,
    mut b: crate::groups::bindings::Binding,
    reason: String,
) -> TrustTaskOutcome {
    use crate::groups::bindings::{self, Binding};
    let unopposed = match group_reduction_gate(
        state,
        who,
        doc,
        group,
        Some(&b.binding_id),
        &format!(
            "Stop giving the members of the group “{}” what this binding confers",
            group.name
        ),
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let ks = state.directory.ks();
    b.state = Binding::REMOVING.into();
    if let Err(e) = bindings::put(ks, &b).await {
        return app_error_to_reject(doc, &e);
    }
    if let Err(e) = groups::authority::provision_group(state, &group.group_id).await {
        return app_error_to_reject(doc, &e);
    }
    let outcome = match bindings::get(ks, &group.group_id, &b.binding_id).await {
        Ok(None) => "removed",
        Ok(Some(_)) => "removing",
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(e) = audit(
        state,
        &who.did,
        AuditEvent::GroupChanged(GroupChangedData {
            group_id: group.group_id.clone(),
            change: "bindingRemoved".into(),
            fields: vec![b.binding_id.clone()],
            reason: Some(reason),
        }),
    )
    .await
    {
        return app_error_to_reject(doc, &e);
    }
    record_unopposed(state, who, doc, &unopposed).await;
    success_response(doc, json!({ "bindingId": b.binding_id, "state": outcome }))
}

/// `bindings/list/0.1`: to managers of the group only, and `notFound` alike for
/// a group that does not exist and one the caller may not manage.
async fn handle_bindings_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match standing(state, ctx, &doc).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<bindings_list::Payload>(&doc) {
        return reject;
    }
    let group_id = doc
        .payload
        .get("groupId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ks = state.directory.ks();
    match groups::get(ks, group_id).await {
        Ok(Some(g)) if who.manages(&g.group_id) => {}
        Ok(_) => {
            return declared(
                &doc,
                BINDINGS_LIST_ERR_NOT_FOUND,
                "No group you may manage has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match crate::groups::bindings::of_group(ks, group_id).await {
        Ok(b) => success_response(
            &doc,
            json!({ "items": b.iter().map(|b| b.wire()).collect::<Vec<_>>() }),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
