//! Custom administrative roles on the signed-document spine —
//! `vtc/roles/{define,list,show,delete}/0.1` (`docs/05-design-notes/
//! vtc-admin-roles.md` §6.2, §7; [`crate::acl::roles`]).
//!
//! - **Reads** (`list`, `show`) answer any administrator: every grant and
//!   approval is judged against the vocabulary, so every administrator may
//!   see it (`vtc/roles/list/0.1` item 1).
//! - **Writes** (`define`, `delete`) administer the authority vocabulary. They
//!   take `vtc.roles.assign` **and** `vtc.approvals.admin`, the requester's
//!   passkey gesture bound to the document, and the N-of-M consent of the
//!   other holders of both (**VTI-APV-018**) — parked in the action list and
//!   executed on the N-th approval ([`super::acl_tasks::settle_consent_gate`]).
//!   A definition's ceiling is bounded by what its defining administrators —
//!   requester and approvers, each read from their stored entry — hold and
//!   may approve (**VTI-ACL-042**, **VTI-ACL-071**). Built-in roles are never
//!   defined, replaced or deleted.

use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::roles::{
    define::v0_1 as define, delete::v0_1 as delete, list::v0_1 as list, show::v0_1 as show,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AdminRoleChangeData, AuditEvent};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::admin_consent::Act;
use crate::acl::roles::{self, DefinitionError, RoleDefinition};
use crate::acl::{AdminRole, CapRef, Capability};
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::routes::acl::conform;
use crate::server::AppState;

pub(crate) const DEFINE_TYPE: &str = <define::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <show::Payload as Payload>::TYPE_URI;
pub(crate) const DELETE_TYPE: &str = <delete::Payload as Payload>::TYPE_URI;

/// Every URI this module routes.
pub(crate) const URIS: &[&str] = &[DEFINE_TYPE, LIST_TYPE, SHOW_TYPE, DELETE_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        DEFINE_TYPE => handle_define(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        DELETE_TYPE => handle_delete(state, ctx, doc).await,
        _ => return None,
    })
}

fn refuse(
    doc: &TrustTask<Value>,
    code: &str,
    message: impl Into<String>,
    details: Option<Value>,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, details)
}

fn respond<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Value,
) -> TrustTaskOutcome {
    match conform::<R>(body) {
        Ok(r) => success_response(doc, r),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The acting administrator's live entry, held to the two capabilities that
/// administer the authority vocabulary (`vtc-admin-roles.md` §6.2).
async fn vocabulary_administrator(
    state: &AppState,
    doc: &TrustTask<Value>,
    did: &str,
) -> Result<crate::acl::VtcAclEntry, TrustTaskOutcome> {
    for cap in [Capability::RolesAssign, Capability::ApprovalsAdmin] {
        if let Err(e) = crate::acl::require_capability(&state.acl_ks, did, cap, None).await {
            return Err(app_error_to_reject(doc, &e));
        }
    }
    match crate::acl::get_acl_entry(&state.acl_ks, did).await {
        Ok(Some(e)) => Ok(e),
        Ok(None) => Err(app_error_to_reject(
            doc,
            &crate::acl::capability_refusal(did, Capability::RolesAssign, None),
        )),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

// ─── reads ───────────────────────────────────────────────────────────────

/// `vtc/roles/list/0.1` — every role, built-in (unless `includeBuiltIn` is
/// false) and custom, each with the ceilings it is enforced by.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_signer(state, ctx, &doc).await {
        return reject;
    }
    let checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let custom = match roles::list(&state.acl_ks).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut out: Vec<Value> = Vec::new();
    if checked.include_built_in {
        out.extend(AdminRole::BUILT_IN.iter().map(roles::render_built_in));
    }
    out.extend(custom.iter().map(roles::render));
    respond::<list::Response>(&doc, json!({ "roles": out }))
}

/// `vtc/roles/show/0.1` — one role, with the count of entries holding it
/// (the set `vtc/roles/delete` counts).
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_signer(state, ctx, &doc).await {
        return reject;
    }
    let checked: show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let name = checked.name.as_str();
    let role = if let Some(built_in) = AdminRole::BUILT_IN.iter().find(|r| r.as_str() == name) {
        (roles::render_built_in(built_in), built_in.clone())
    } else {
        match roles::get(&state.acl_ks, name).await {
            Ok(Some(def)) => (roles::render(&def), AdminRole::Custom(def.name)),
            Ok(None) => {
                return refuse(
                    &doc,
                    show::error_codes::NOT_FOUND.code,
                    format!("this community has no role named '{name}'"),
                    None,
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    };
    let holders = match crate::acl::list_acl_entries(&state.acl_ks).await {
        Ok(entries) => entries
            .iter()
            .filter(|e| e.admin.admin_role.as_ref() == Some(&role.1))
            .count(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    respond::<show::Response>(&doc, json!({ "role": role.0, "holders": holders }))
}

// ─── define ──────────────────────────────────────────────────────────────

fn refuse_definition(doc: &TrustTask<Value>, e: DefinitionError) -> TrustTaskOutcome {
    use define::error_codes as c;
    match e {
        DefinitionError::UnknownCapability(caps) => refuse(
            doc,
            c::UNKNOWN_CAPABILITY.code,
            format!(
                "{} {} not in this community's capability registry (VTI-ACL-032)",
                caps.join(", "),
                if caps.len() == 1 { "is" } else { "are" }
            ),
            Some(json!({ "capabilities": caps })),
        ),
        DefinitionError::AdditiveCapability(caps) => refuse(
            doc,
            c::ADDITIVE_CAPABILITY.code,
            format!(
                "{} {} additive — held only as an additive grant beside a role, never in a \
                 ceiling (VTI-ACL-033)",
                caps.join(", "),
                if caps.len() == 1 { "is" } else { "are" }
            ),
            Some(json!({ "capabilities": caps })),
        ),
        DefinitionError::Malformed(reason) => {
            reject_with(doc, RejectReason::MalformedRequest { reason })
        }
    }
}

fn exceeds(doc: &TrustTask<Value>, who: &str, caps: Vec<String>) -> TrustTaskOutcome {
    refuse(
        doc,
        define::error_codes::EXCEEDS_DEFINER_AUTHORITY.code,
        format!(
            "{who} does not hold, or may not approve, {} — a role cannot name authority its \
             defining administrators do not hold themselves (VTI-ACL-042, VTI-ACL-071)",
            caps.join(", ")
        ),
        Some(json!({ "capabilities": caps })),
    )
}

/// `vtc/roles/define/0.1` — create or replace a custom role.
async fn handle_define(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use define::error_codes as c;
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    // Unknown capabilities are named under their own code (VTI-ACL-032), read
    // before the schema's generic refusal could fire.
    for member in ["ceiling", "approveScope"] {
        if let Some(v) = doc.payload.get(member)
            && let Err(e @ DefinitionError::UnknownCapability(_)) = roles::parse_refs(v)
        {
            return refuse_definition(&doc, e);
        }
    }
    let checked: define::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let name = checked.name.as_str().to_string();
    if roles::is_reserved(&name) {
        return refuse(
            &doc,
            c::BUILT_IN_ROLE.code,
            format!("{name} is a built-in role and cannot be defined, changed or replaced"),
            None,
        );
    }
    let (ceiling, approve) = match roles::parse_refs(&doc.payload["ceiling"])
        .and_then(|c| roles::parse_refs(&doc.payload["approveScope"]).map(|a| (c, a)))
        .and_then(|(c, a)| roles::check_ceiling(&c).map(|()| (c, a)))
    {
        Ok(pair) => pair,
        Err(e) => return refuse_definition(&doc, e),
    };
    let replaces = checked.replaces.unwrap_or(false);
    let existing = match roles::get(&state.acl_ks, &name).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Some(reject) = presence_refusal(&doc, &name, existing.is_some(), replaces) {
        return reject;
    }

    // The defining administrators' authority (item 4): the requester's own,
    // and — when an approved action is executing this — every approver's,
    // each read from its stored entry now.
    let entry = match vocabulary_administrator(state, &doc, &actor.did).await {
        Ok(e) => e,
        Err(reject) => return reject,
    };
    let over = roles::exceeding(&entry, &ceiling, &approve);
    if !over.is_empty() {
        return exceeds(&doc, &actor.did, over);
    }
    let approvers = crate::admin_actions::executing_approvers(state).await;
    for approver in &approvers {
        let over = match crate::acl::get_acl_entry(&state.acl_ks, approver).await {
            Ok(Some(e)) => roles::exceeding(&e, &ceiling, &approve),
            Ok(None) => ceiling.iter().map(CapRef::display).collect(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if !over.is_empty() {
            return exceeds(&doc, &format!("approver {approver}"), over);
        }
    }

    let verb = if replaces { "Replace" } else { "Define" };
    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeRoles,
        &name,
        &format!("{verb} the administrative role {name}"),
        &format!("{verb} the administrative role {name}"),
    )
    .await
    {
        return reject;
    }

    // The write, under the lock grants of a custom role commit under, so a
    // grant racing a replacement sees one definition or the other.
    let now = now_epoch();
    let guard = crate::ceremony::lock_admin_set().await;
    let existing = match roles::get(&state.acl_ks, &name).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Some(reject) = presence_refusal(&doc, &name, existing.is_some(), replaces) {
        return reject;
    }
    let holders = match roles::holders(&state.acl_ks, &name).await {
        Ok(h) => h,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let narrowed = existing
        .as_ref()
        .is_some_and(|old| roles::narrows(old, &ceiling, &approve));
    let def = RoleDefinition {
        name: name.clone(),
        description: checked.description.as_ref().map(|d| d.to_string()),
        ceiling,
        approve_scope: approve,
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now),
        created_by: existing
            .as_ref()
            .map(|e| e.created_by.clone())
            .unwrap_or_else(|| actor.did.clone()),
        updated_at: existing.is_some().then_some(now),
        updated_by: existing.is_some().then(|| actor.did.clone()),
    };
    if let Err(e) = roles::put(&state.acl_ks, &def).await {
        return app_error_to_reject(&doc, &e);
    }
    crate::admin_actions::record_effect(state).await;
    drop(guard);

    // A narrowed role binds every holder now: their sessions go, as any other
    // privilege reduction's do (`vtc/roles/define/0.1` item 6).
    if narrowed && let Ok(entries) = crate::acl::list_acl_entries(&state.acl_ks).await {
        for e in entries
            .iter()
            .filter(|e| e.admin.admin_role == Some(AdminRole::Custom(name.clone())))
        {
            let _ = crate::routes::auth::revoke_sessions_for_did(&state.sessions_ks, &e.did).await;
        }
    }
    audit(
        state,
        &actor.did,
        AuditEvent::AdminRoleDefined(AdminRoleChangeData {
            name: name.clone(),
            ceiling: def.ceiling.iter().map(CapRef::display).collect(),
            approve_scope: def.approve_scope.iter().map(CapRef::display).collect(),
            replaced: existing.is_some(),
            narrowed,
            holders,
            approvers,
        }),
    )
    .await;
    tracing::info!(
        role = %name,
        replaced = existing.is_some(),
        narrowed,
        holders,
        "custom administrative role defined"
    );
    respond::<define::Response>(
        &doc,
        json!({
            "role": roles::render(&def),
            // How many entries the definition applies to now
            // (`vtc/roles/define/0.1` item 6).
            "ext": { "org.openvtc": { "affectedEntries": holders } },
        }),
    )
}

/// `exists` for a create of a name already defined, `notFound` for a replace
/// of one that is not.
fn presence_refusal(
    doc: &TrustTask<Value>,
    name: &str,
    present: bool,
    replaces: bool,
) -> Option<TrustTaskOutcome> {
    use define::error_codes as c;
    match (present, replaces) {
        (true, false) => Some(refuse(
            doc,
            c::EXISTS.code,
            format!(
                "a custom role named {name} already exists — send `replaces: true` to change it"
            ),
            None,
        )),
        (false, true) => Some(refuse(
            doc,
            c::NOT_FOUND.code,
            format!(
                "there is no custom role named {name} to replace — omit `replaces` to create it"
            ),
            None,
        )),
        _ => None,
    }
}

// ─── delete ──────────────────────────────────────────────────────────────

/// `vtc/roles/delete/0.1` — remove a custom role nobody holds.
async fn handle_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use delete::error_codes as c;
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: delete::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let name = checked.name.as_str().to_string();
    if roles::is_reserved(&name) {
        return refuse(
            &doc,
            c::BUILT_IN_ROLE.code,
            format!("{name} is a built-in role and cannot be deleted"),
            None,
        );
    }
    match roles::get(&state.acl_ks, &name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return refuse(
                &doc,
                c::NOT_FOUND.code,
                format!("there is no custom role named {name}"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Err(reject) = vocabulary_administrator(state, &doc, &actor.did).await {
        return reject;
    }
    match in_use(state, &name).await {
        Ok(0) => {}
        Ok(n) => return in_use_refusal(&doc, &name, n),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeRoles,
        &name,
        &format!("Delete the administrative role {name}"),
        &format!("Delete the administrative role {name}"),
    )
    .await
    {
        return reject;
    }

    // Counted and deleted under the lock a grant of the role commits under
    // (item 3): a racing grant either landed first, and is counted here, or
    // finds the role gone and is refused `roleNotRecognized`.
    let guard = crate::ceremony::lock_admin_set().await;
    match in_use(state, &name).await {
        Ok(0) => {}
        Ok(n) => return in_use_refusal(&doc, &name, n),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Err(e) = roles::remove(&state.acl_ks, &name).await {
        return app_error_to_reject(&doc, &e);
    }
    crate::admin_actions::record_effect(state).await;
    drop(guard);

    let approvers = crate::admin_actions::executing_approvers(state).await;
    audit(
        state,
        &actor.did,
        AuditEvent::AdminRoleDeleted(AdminRoleChangeData {
            name: name.clone(),
            ceiling: Vec::new(),
            approve_scope: Vec::new(),
            replaced: false,
            narrowed: false,
            holders: 0,
            approvers,
        }),
    )
    .await;
    tracing::info!(role = %name, "custom administrative role deleted");
    respond::<delete::Response>(&doc, json!({ "deleted": name }))
}

/// Entries holding `name` — expired ones too — plus grants of it waiting in
/// the action list (`vtc/roles/delete/0.1` item 2).
async fn in_use(state: &AppState, name: &str) -> Result<u32, AppError> {
    Ok(roles::holders(&state.acl_ks, name).await?
        + crate::admin_actions::pending_role_grants(state, name).await?)
}

fn in_use_refusal(doc: &TrustTask<Value>, name: &str, holders: u32) -> TrustTaskOutcome {
    refuse(
        doc,
        delete::error_codes::IN_USE.code,
        format!(
            "{holders} ACL entr{} hold {name}, or wait to be granted it — move each holder to \
             another role (acl/change-role) or revoke it first; a held role is never deleted \
             out from under its holders",
            if holders == 1 { "y" } else { "ies" }
        ),
        Some(json!({ "holders": holders })),
    )
}

async fn audit(state: &AppState, actor: &str, event: AuditEvent) {
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer.write(actor, None, event).await
    {
        tracing::warn!(error = %e, "could not audit a custom-role change");
    }
}
