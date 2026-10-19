//! The community's groups on the signed-document spine (`vtc/groups/*`;
//! [`crate::groups`]).
//!
//! | task | authority (read now) |
//! |---|---|
//! | `create/0.1` | `vtc.groups.manage` unqualified, then the `groups` policy |
//! | `update/0.1`, `delete/0.1` | `vtc.groups.manage` for the group, unqualified or `group:<groupId>` |
//! | `list/0.1`, `show/0.1` | an active member or an administrator, each group as their standing lets them see it |
//!
//! None has a REST route. A group the caller may not see answers `notFound`
//! exactly as one that does not exist, on every task.
//!
//! Only static groups are served. A dynamic group's rule is checked, then the
//! create is refused `kindNotServed`: nothing computes its membership yet.

use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::groups::{
    create::v0_1 as group_create, delete::v0_1 as group_delete, list::v0_1 as group_list,
    show::v0_1 as group_show, update::v0_1 as group_update,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, GroupChangedData};
use vti_common::error::AppError;
use vti_common::pagination::Cursor;

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::groups::identity::{self, Failure};
use crate::groups::policy::{self as group_policy, Facts, GroupFacts};
use crate::groups::{self, Audience, Group, JoinPolicy, Standing};
use crate::rooms::community::HolderError;
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <group_create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <group_update::Payload as Payload>::TYPE_URI;
pub(crate) const DELETE_TYPE: &str = <group_delete::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <group_list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <group_show::Payload as Payload>::TYPE_URI;

/// Every type this module serves.
pub(crate) const URIS: &[&str] = &[CREATE_TYPE, UPDATE_TYPE, DELETE_TYPE, LIST_TYPE, SHOW_TYPE];

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
    DELETE_ERR_NOT_FOUND = group_delete::NOT_FOUND;
    LIST_ERR_CURSOR_INVALID = group_list::CURSOR_INVALID;
    SHOW_ERR_NOT_FOUND = group_show::NOT_FOUND;
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

/// The signer's standing: a console key as the administrator it acts for,
/// anyone else as themselves.
async fn standing(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Standing, TrustTaskOutcome> {
    let did = member_signer(state, ctx, doc).await?.did;
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
            match identity::issue_authority(state, &setup, &next.group_did, Utc::now()).await {
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

/// `delete/0.1` (items 1 – 5). Nothing to withdraw yet: no binding is served,
/// so the group carries no room admission and no grant.
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
    let members_removed = match groups::remove(state.directory.ks(), &group.group_id).await {
        Ok(n) => n,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(
        &doc,
        json!({
            "groupId": group.group_id,
            "state": "deleted",
            "membersRemoved": members_removed,
            "bindingsRemoved": 0,
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
