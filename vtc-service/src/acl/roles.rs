//! Custom administrative roles — `docs/05-design-notes/vtc-admin-roles.md`
//! §6.2; `vtc/roles/{define,list,show,delete}/0.1`.
//!
//! A custom role is a **record in the ACL model**: a name, a ceiling and an
//! approve ceiling (`vtc/roles/_shared/0.1` `RoleDefinition`). It is stored in
//! the `acl` keyspace under `role:<name>`, beside the `acl:<did>` rows it
//! bounds, so a backup carries it with them (the keyspace is `BACKED_UP`, and
//! the backup import passes every non-`acl:` row through verbatim).
//!
//! ## How a definition reaches an entry
//!
//! An entry names its role; it never carries the role's ceiling. Every read of
//! an entry ([`super::storage`]) and every planned write ([`resolve`]) resolves
//! a custom role against the definition stored **now** onto
//! [`super::AdminAuthority::custom`]. Nothing else sets it, and it is never
//! serialised. So:
//!
//! - replacing a role changes what every holder may do at its next
//!   authorization decision (`vtc/roles/define/0.1` item 6), and
//! - an entry naming a role with no definition — deleted out from under it by
//!   a restore, or written by hand — confers nothing (**VTI-ACL-011**), since
//!   an unresolved custom role has an empty ceiling.
//!
//! ## Who may define one
//!
//! Defining, replacing and deleting are authority-defining: every grant of the
//! role later hands out part of what its ceiling names. So the handler
//! (`trust_tasks::role_tasks`) takes `vtc.roles.assign` **and**
//! `vtc.approvals.admin`, parks the operation for the N-of-M consent of their
//! other holders (**VTI-APV-018**, `vtc-admin-roles.md` §7), and bounds the
//! ceiling by what the defining administrators — requester and approvers —
//! hold and may approve themselves (**VTI-ACL-042**, **VTI-ACL-071**,
//! [`exceeding`]). Policy can neither define nor widen a role
//! (**VTI-VTC-022**): this is host code over host records.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::capability::{AdminRole, CapRef, Capability, RoleCeilings};
use super::{VtcAclEntry, list_acl_entries};

/// The declared error codes of `vtc/roles/*`, read off the generated
/// specifications — what the tests that witness each one compare against.
pub mod codes {
    use trust_tasks_rs::specs::vtc::roles as r;

    pub const DEFINE_BUILT_IN_ROLE: &str = r::define::v0_1::error_codes::BUILT_IN_ROLE.code;
    pub const DEFINE_EXISTS: &str = r::define::v0_1::error_codes::EXISTS.code;
    pub const DEFINE_NOT_FOUND: &str = r::define::v0_1::error_codes::NOT_FOUND.code;
    pub const DEFINE_UNKNOWN_CAPABILITY: &str =
        r::define::v0_1::error_codes::UNKNOWN_CAPABILITY.code;
    pub const DEFINE_ADDITIVE_CAPABILITY: &str =
        r::define::v0_1::error_codes::ADDITIVE_CAPABILITY.code;
    pub const DEFINE_EXCEEDS_DEFINER_AUTHORITY: &str =
        r::define::v0_1::error_codes::EXCEEDS_DEFINER_AUTHORITY.code;
    pub const DELETE_BUILT_IN_ROLE: &str = r::delete::v0_1::error_codes::BUILT_IN_ROLE.code;
    pub const DELETE_NOT_FOUND: &str = r::delete::v0_1::error_codes::NOT_FOUND.code;
    pub const DELETE_IN_USE: &str = r::delete::v0_1::error_codes::IN_USE.code;
    pub const SHOW_NOT_FOUND: &str = r::show::v0_1::error_codes::NOT_FOUND.code;
}

const ROLE_PREFIX: &str = "role:";

fn key(name: &str) -> String {
    format!("{ROLE_PREFIX}{name}")
}

/// A custom role as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What an entry holding the role may hold.
    pub ceiling: Vec<CapRef>,
    /// What an entry holding the role may approve.
    pub approve_scope: Vec<CapRef>,
    pub created_at: u64,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

impl RoleDefinition {
    /// The two ceilings an entry is resolved against.
    pub fn ceilings(&self) -> RoleCeilings {
        RoleCeilings {
            ceiling: self.ceiling.clone(),
            approve: self.approve_scope.clone(),
        }
    }
}

/// The stored definition of custom role `name`.
pub async fn get(ks: &KeyspaceHandle, name: &str) -> Result<Option<RoleDefinition>, AppError> {
    let Some(raw) = ks.get_raw(key(name)).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| AppError::Internal(format!("custom role '{name}' does not decode: {e}")))
}

/// Every stored custom role, by name. A row that does not decode is skipped
/// (and so confers nothing), never guessed at.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<RoleDefinition>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(ROLE_PREFIX.as_bytes().to_vec()).await? {
        match serde_json::from_slice::<RoleDefinition>(&raw) {
            Ok(d) => out.push(d),
            Err(e) => tracing::warn!(error = %e, "skipping an unreadable custom role"),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Store (create or replace) a definition.
pub async fn put(ks: &KeyspaceHandle, def: &RoleDefinition) -> Result<(), AppError> {
    ks.insert(key(&def.name), def).await
}

/// Remove a definition. Idempotent.
pub async fn remove(ks: &KeyspaceHandle, name: &str) -> Result<(), AppError> {
    ks.remove(key(name)).await
}

/// Resolve `entry`'s custom role, if it holds one, against the definition
/// stored now. An entry naming a role with no definition is left unresolved,
/// and so confers nothing (**VTI-ACL-011**).
pub async fn resolve(ks: &KeyspaceHandle, entry: &mut VtcAclEntry) -> Result<(), AppError> {
    entry.admin.custom = None;
    if let Some(AdminRole::Custom(name)) = entry.admin.admin_role.as_ref() {
        entry.admin.custom = get(ks, name).await?.map(|d| Arc::new(d.ceilings()));
    }
    Ok(())
}

/// [`resolve`] for many entries, reading the definitions once.
pub async fn resolve_all(ks: &KeyspaceHandle, entries: &mut [VtcAclEntry]) -> Result<(), AppError> {
    if !entries
        .iter()
        .any(|e| matches!(e.admin.admin_role, Some(AdminRole::Custom(_))))
    {
        return Ok(());
    }
    let defs: HashMap<String, Arc<RoleCeilings>> = list(ks)
        .await?
        .into_iter()
        .map(|d| (d.name.clone(), Arc::new(d.ceilings())))
        .collect();
    for e in entries {
        e.admin.custom = match e.admin.admin_role.as_ref() {
            Some(AdminRole::Custom(name)) => defs.get(name).cloned(),
            _ => None,
        };
    }
    Ok(())
}

/// How many ACL entries hold `name` — every stored entry, expired ones too
/// (`vtc/roles/delete/0.1` item 2: the same set `show` counts).
pub async fn holders(ks: &KeyspaceHandle, name: &str) -> Result<u32, AppError> {
    Ok(list_acl_entries(ks)
        .await?
        .iter()
        .filter(|e| matches!(e.admin.admin_role.as_ref(), Some(AdminRole::Custom(n)) if n == name))
        .count() as u32)
}

/// Whether `name` is reserved: a built-in role, or `member` — the 0.2 wire's
/// "no administrative role" (`acl/_shared/0.2`).
pub fn is_reserved(name: &str) -> bool {
    name == crate::routes::acl::NO_ADMIN_ROLE
        || AdminRole::BUILT_IN.iter().any(|r| r.as_str() == name)
}

fn epoch_rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A built-in role as a `RoleDefinition` (`builtIn: true`): its ceilings
/// enumerated, with no provenance.
pub fn render_built_in(role: &AdminRole) -> Value {
    json!({
        "name": role.as_str(),
        "builtIn": true,
        "ceiling": role.ceiling_refs(),
        "approveScope": role.approve_ceiling_refs(),
    })
}

/// A custom role as a `RoleDefinition` (`builtIn: false`).
pub fn render(def: &RoleDefinition) -> Value {
    let mut v = json!({
        "name": def.name,
        "builtIn": false,
        "ceiling": def.ceiling,
        "approveScope": def.approve_scope,
        "createdAt": epoch_rfc3339(def.created_at),
        "createdBy": def.created_by,
    });
    if let Some(d) = def.description.as_ref() {
        v["description"] = json!(d);
    }
    if let (Some(at), Some(by)) = (def.updated_at, def.updated_by.as_ref()) {
        v["updatedAt"] = json!(epoch_rfc3339(at));
        v["updatedBy"] = json!(by);
    }
    v
}

/// Why a definition is refused before anyone's authority is weighed —
/// `vtc/roles/define/0.1`'s codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionError {
    /// `unknownCapability`.
    UnknownCapability(Vec<String>),
    /// `additiveCapability`.
    AdditiveCapability(Vec<String>),
    /// A qualifier its capability cannot carry, or a malformed reference.
    Malformed(String),
}

/// Read a `CapabilityRef[]` off the wire. Unknown capabilities are named, all
/// of them, never dropped (VTI-ACL-032).
pub fn parse_refs(v: &Value) -> Result<Vec<CapRef>, DefinitionError> {
    let items = v
        .as_array()
        .ok_or_else(|| DefinitionError::Malformed("a capability list is an array".into()))?;
    let unknown: Vec<String> = items
        .iter()
        .filter_map(|i| i.get("capability").and_then(Value::as_str))
        .filter(|c| c.parse::<Capability>().is_err())
        .map(str::to_string)
        .collect();
    if !unknown.is_empty() {
        return Err(DefinitionError::UnknownCapability(unknown));
    }
    let mut out: Vec<CapRef> = Vec::with_capacity(items.len());
    for i in items {
        let r: CapRef = serde_json::from_value(i.clone())
            .map_err(|e| DefinitionError::Malformed(format!("capability reference: {e}")))?;
        if let Some(res) = r.resource.as_ref()
            && !r.capability.admits(res)
        {
            return Err(DefinitionError::Malformed(format!(
                "{} cannot be qualified by {res}",
                r.capability
            )));
        }
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok(out)
}

/// Refuse an additive capability in a ceiling (`additiveCapability`): one no
/// role implies, so naming it in a ceiling would let a granter without
/// unrestricted authority confer it (**VTI-ACL-033**).
pub fn check_ceiling(ceiling: &[CapRef]) -> Result<(), DefinitionError> {
    let additive: Vec<String> = ceiling
        .iter()
        .filter(|c| c.capability.is_registry_additive())
        .map(CapRef::display)
        .collect();
    if additive.is_empty() {
        Ok(())
    } else {
        Err(DefinitionError::AdditiveCapability(additive))
    }
}

/// What `definer` could not have put in this role itself: ceiling entries it
/// does not hold at a qualifier at least as wide, and approve entries it may
/// not approve (**VTI-ACL-042**, **VTI-ACL-071**; `vtc/roles/define/0.1` item
/// 4). Empty: the definer's authority covers the role. Evaluated against the
/// definer's **stored** entry, read by the caller now.
pub fn exceeding(definer: &VtcAclEntry, ceiling: &[CapRef], approve: &[CapRef]) -> Vec<String> {
    ceiling
        .iter()
        .filter(|c| !definer.holds(c))
        .chain(approve.iter().filter(|c| !definer.can_approve(c)))
        .map(CapRef::display)
        .collect()
}

/// Whether moving a role from `old` to `new` takes anything away from its
/// holders — a ceiling or approve item no longer covered. Every holder's
/// privilege is then reduced (`vtc/roles/define/0.1` item 6).
pub fn narrows(old: &RoleDefinition, ceiling: &[CapRef], approve: &[CapRef]) -> bool {
    old.ceiling
        .iter()
        .any(|o| !ceiling.iter().any(|n| n.covers(o)))
        || old
            .approve_scope
            .iter()
            .any(|o| !approve.iter().any(|n| n.covers(o)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, VtcRole};

    fn refs(items: &[&str]) -> Vec<CapRef> {
        items.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn unknown_capabilities_are_named_all_of_them() {
        let v = json!([
            {"capability": "vtc.surface.admin"},
            {"capability": "vtc.everything"},
            {"capability": "vtc.nothing"},
        ]);
        assert_eq!(
            parse_refs(&v),
            Err(DefinitionError::UnknownCapability(vec![
                "vtc.everything".into(),
                "vtc.nothing".into()
            ]))
        );
    }

    #[test]
    fn an_additive_capability_never_sits_in_a_ceiling() {
        assert!(check_ceiling(&refs(&["vtc.surface.admin"])).is_ok());
        assert_eq!(
            check_ceiling(&refs(&["git.commit.sign@git-ns:github.com/acme"])),
            Err(DefinitionError::AdditiveCapability(vec![
                "git.commit.sign@git-ns:github.com/acme".into()
            ]))
        );
    }

    /// VTI-ACL-042 / -071: a definer cannot put in a role what it does not
    /// hold, nor approve scope it may not approve itself.
    #[test]
    fn vti_acl_071_a_role_cannot_exceed_its_definer() {
        let mut moderator_ish = AdminAuthority::community_admin();
        moderator_ish.capabilities = crate::acl::CapabilityScope::listed(
            refs(&[
                "vtc.roles.assign",
                "vtc.approvals.admin",
                "vtc.surface.admin",
            ])
            .into_iter()
            .map(Into::into)
            .collect(),
        )
        .unwrap();
        let definer = VtcAclEntry::new("did:key:zD", VtcRole::Admin, moderator_ish, "x");
        assert!(exceeding(&definer, &refs(&["vtc.surface.admin"]), &[]).is_empty());
        assert_eq!(
            exceeding(
                &definer,
                &refs(&["vtc.surface.admin", "vtc.audit.read"]),
                &[]
            ),
            vec!["vtc.audit.read".to_string()]
        );
        // A community-admin approves everything, so any approve scope is in
        // reach; one with approve none reaches none.
        let mut no_approve = definer.clone();
        no_approve.admin.approve = crate::acl::VtcActScope::None;
        assert_eq!(
            exceeding(&no_approve, &[], &refs(&["vtc.surface.admin"])),
            vec!["vtc.surface.admin".to_string()]
        );
    }

    #[test]
    fn a_replacement_that_drops_or_narrows_anything_narrows() {
        let old = RoleDefinition {
            name: "events-team".into(),
            description: None,
            ceiling: refs(&["vtc.surface.admin", "git.repo.manage"]),
            approve_scope: refs(&["vtc.surface.admin"]),
            created_at: 0,
            created_by: "did:key:zA".into(),
            updated_at: None,
            updated_by: None,
        };
        assert!(!narrows(&old, &old.ceiling, &old.approve_scope));
        assert!(narrows(
            &old,
            &refs(&[
                "vtc.surface.admin",
                "git.repo.manage@git-ns:github.com/acme"
            ]),
            &old.approve_scope
        ));
        assert!(narrows(&old, &old.ceiling, &[]));
        assert!(!narrows(
            &old,
            &refs(&["vtc.surface.admin", "git.repo.manage", "vtc.audit.read"]),
            &old.approve_scope
        ));
    }

    #[test]
    fn built_in_and_member_names_are_reserved() {
        for r in AdminRole::BUILT_IN {
            assert!(is_reserved(r.as_str()));
        }
        assert!(is_reserved("member"));
        assert!(!is_reserved("events-team"));
    }
}
