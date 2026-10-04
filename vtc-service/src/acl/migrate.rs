//! Bringing an ACL row from before role-based administration into the
//! role-based shape — `docs/05-design-notes/vtc-admin-roles.md` §9.
//!
//! A row in the old shape (`allowed_contexts`, no explicit `act`) reaches a
//! node two ways, and both map it here, with one mapping:
//!
//! - **in place, at boot** ([`migrate_on_boot`]): a VTC upgraded over its own
//!   store rewrites every legacy row before anything is authorized, so no
//!   administrator is locked out by an upgrade;
//! - **on backup import** (`crate::backup`).
//!
//! The mapping:
//!
//! - an **unrestricted admin** (role `admin`, no contexts) becomes a
//!   `community-admin` with the full ceiling, act `all`;
//! - a **context-scoped admin** gets **no administrative role**. Its community
//!   role is kept, and the import report lists it for re-grant: a context label
//!   never meant anything at a VTC (**VTI-VTC-010**), so mapping it onto a role
//!   would invent authority;
//! - `moderator` and `issuer` keep their community role and also get the
//!   matching administrative role (`moderator`, `credential-officer`), because
//!   the permission matrix before roles gave them exactly those powers;
//! - `member` and `custom:*` keep their community role and get no
//!   administrative role.
//!
//! A row already in the new shape is taken as it is.

use serde::Deserialize;
use serde_json::Value;
use vti_common::error::AppError;

use super::{AdminAuthority, VtcAclEntry, VtcRole, store_acl_entry};
use crate::server::AppState;

/// What one migrated row became, for the import report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migrated {
    /// Already in the role-based shape; taken unchanged.
    Current,
    /// Mapped onto the administrative role its community role implies (or
    /// onto none).
    Mapped,
    /// A context-scoped admin: no administrative role now; re-grant it.
    NeedsRegrant { contexts: Vec<String> },
}

/// The pre-role row shape.
#[derive(Debug, Deserialize)]
struct LegacyEntry {
    did: String,
    role: VtcRole,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    allowed_contexts: Vec<String>,
    created_at: u64,
    created_by: String,
    #[serde(default)]
    updated_at: Option<u64>,
    #[serde(default)]
    updated_by: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}

/// Map one stored ACL row (its JSON value bytes) onto the role-based shape.
pub fn migrate_row(bytes: &[u8]) -> Result<(VtcAclEntry, Migrated), AppError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| AppError::Validation(format!("backup: ACL row is not JSON: {e}")))?;
    if value.get("act").is_some() {
        let entry: VtcAclEntry = serde_json::from_value(value)
            .map_err(|e| AppError::Validation(format!("backup: ACL row does not decode: {e}")))?;
        return Ok((entry, Migrated::Current));
    }
    let legacy: LegacyEntry = serde_json::from_value(value).map_err(|e| {
        AppError::Validation(format!("backup: legacy ACL row does not decode: {e}"))
    })?;

    // The pre-role convention: an admin's empty scope list meant the whole
    // community; a non-empty one named contexts the VTC never had.
    let (admin, outcome) = match (&legacy.role, legacy.allowed_contexts.is_empty()) {
        (VtcRole::Admin, false) => (
            AdminAuthority::none(),
            Migrated::NeedsRegrant {
                contexts: legacy.allowed_contexts.clone(),
            },
        ),
        (role, _) => (role.implied_authority(), Migrated::Mapped),
    };
    Ok((
        VtcAclEntry {
            did: legacy.did,
            role: legacy.role,
            label: legacy.label,
            admin,
            delegated_by: None,
            created_at: legacy.created_at,
            created_by: legacy.created_by,
            updated_at: legacy.updated_at,
            updated_by: legacy.updated_by,
            expires_at: legacy.expires_at,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
        outcome,
    ))
}

/// What a boot migration did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BootMigration {
    /// Rows rewritten in the role-based shape.
    pub migrated: u32,
    /// Of those, rows that came across holding an administrative role.
    pub administrators: u32,
    /// Context-scoped administrators that came across with **no**
    /// administrative role, sorted.
    pub lost_admin_authority: Vec<String>,
}

/// The acknowledge item a boot migration raises is keyed on this marker plus
/// the subjects that lost authority, so a re-run raises it once.
const MIGRATION_MARKER: &str = "acl-migration";

/// Rewrite every pre-role ACL row in place, before anything is authorized
/// (`vtc-admin-roles.md` §9).
///
/// - Every row is mapped before any is written, and each write is one put of
///   its own key: a crash part-way leaves every row either old (and migrated
///   on the next boot) or new, never half of one.
/// - Idempotent: a row already in the role-based shape is left alone, so a
///   second boot does nothing.
/// - A row that cannot be mapped refuses the boot, naming the DID and the fix.
///   It is never dropped: a silently missing row is an administrator locked
///   out with nothing saying why.
/// - Anything migrated is audited once (`AclMigrated`, naming the counts and
///   the context-scoped administrators that lost authority). Those losses are
///   raised as an `acknowledge` item for the remaining community
///   administrators (**VTI-VTC-023**), who re-grant with `acl/update` or let
///   them go.
pub async fn migrate_on_boot(state: &AppState) -> Result<BootMigration, AppError> {
    // Map every row first and write only when all of them map: a refusal
    // leaves the store exactly as the upgrade found it.
    let mut planned = Vec::new();
    for (key, value) in state.acl_ks.prefix_iter_raw(b"acl:".to_vec()).await? {
        let did = String::from_utf8_lossy(&key[b"acl:".len()..]).into_owned();
        let refuse = |why: String| {
            AppError::Config(format!(
                "the ACL row for {did} predates role-based administration and cannot be \
                 migrated ({why}). Nothing was changed. With the daemon stopped, rewrite the \
                 entry — `vtc acl remove --did {did}`, then `vtc acl add --did {did} --role \
                 <role> [--admin-role <role>]` — and start it again; or reinstall and restore \
                 the community from a backup taken before the upgrade (`cnm backup import`), \
                 which maps the same rows"
            ))
        };
        let (entry, how) = migrate_row(&value).map_err(|e| refuse(e.to_string()))?;
        if how == Migrated::Current {
            continue;
        }
        if entry.did != did {
            return Err(refuse(format!(
                "the row names {} but is stored under {did}",
                entry.did
            )));
        }
        planned.push((entry, how));
    }

    let mut out = BootMigration::default();
    for (entry, how) in planned {
        store_acl_entry(&state.acl_ks, &entry).await?;
        out.migrated += 1;
        if entry.is_administrator() {
            out.administrators += 1;
        }
        if let Migrated::NeedsRegrant { contexts } = how {
            tracing::warn!(
                did = %entry.did,
                contexts = ?contexts,
                "a context-scoped administrator came across the ACL migration with no \
                 administrative role; re-grant it with acl/update if it should keep any"
            );
            out.lost_admin_authority.push(entry.did);
        }
    }
    if out.migrated == 0 {
        return Ok(out);
    }
    out.lost_admin_authority.sort();
    tracing::info!(
        migrated = out.migrated,
        administrators = out.administrators,
        lost = out.lost_admin_authority.len(),
        "migrated pre-role ACL rows to role-based administration"
    );
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                "did:key:vtc-boot",
                None,
                vti_common::audit::AuditEvent::AclMigrated(vti_common::audit::AclMigratedData {
                    migrated: out.migrated,
                    administrators: out.administrators,
                    lost_admin_authority: out.lost_admin_authority.clone(),
                }),
            )
            .await?;
    }
    if !out.lost_admin_authority.is_empty() {
        let now = crate::auth::session::now_epoch();
        let acknowledgers: Vec<String> = super::list_acl_entries(&state.acl_ks)
            .await?
            .into_iter()
            .filter(|e| !e.is_expired(now) && e.is_community_admin())
            .map(|e| e.did)
            .collect();
        let write = crate::admin_actions::OperatorWrite {
            marker: format!("{MIGRATION_MARKER}:{}", out.lost_admin_authority.join(",")),
            command: format!(
                "the boot migration to role-based administration, which left {} with no \
                 administrative role",
                out.lost_admin_authority.join(", ")
            ),
            action: "aclMigration".into(),
            dids: out.lost_admin_authority.clone(),
            operator_host: gethostname::gethostname().to_string_lossy().into_owned(),
            invoked_at: chrono::Utc::now(),
            acknowledgers: (!acknowledgers.is_empty()).then_some(acknowledgers),
        };
        crate::admin_actions::raise_operator_item(state, &write).await?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminRole, Capability};
    use serde_json::json;

    fn legacy(role: &str, contexts: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "did": "did:key:zLegacy",
            "role": role,
            "label": "x",
            "allowed_contexts": contexts,
            "created_at": 7,
            "created_by": "did:key:zInstall",
        }))
        .unwrap()
    }

    /// `vtc-admin-roles.md` §9, row by row.
    #[test]
    fn a_backup_row_maps_onto_the_role_its_community_role_implied() {
        let (e, m) = migrate_row(&legacy("admin", &[])).unwrap();
        assert_eq!(m, Migrated::Mapped);
        assert_eq!(e.admin, AdminAuthority::community_admin());
        assert!(e.can(Capability::RolesAssign, None));
        assert_eq!(e.role, VtcRole::Admin);
        assert_eq!(e.created_at, 7);

        let (e, m) = migrate_row(&legacy("admin", &["ctx-a"])).unwrap();
        assert_eq!(
            m,
            Migrated::NeedsRegrant {
                contexts: vec!["ctx-a".into()]
            }
        );
        assert_eq!(
            e.admin,
            AdminAuthority::none(),
            "a label never meant anything"
        );
        assert_eq!(e.role, VtcRole::Admin, "the community role is kept");

        let (e, _) = migrate_row(&legacy("moderator", &[])).unwrap();
        assert_eq!(e.admin.admin_role, Some(AdminRole::Moderator));
        assert_eq!(e.role, VtcRole::Moderator);

        let (e, _) = migrate_row(&legacy("issuer", &[])).unwrap();
        assert_eq!(e.admin.admin_role, Some(AdminRole::CredentialOfficer));

        for role in ["member", "custom:editor"] {
            let (e, m) = migrate_row(&legacy(role, &[])).unwrap();
            assert_eq!(m, Migrated::Mapped);
            assert_eq!(e.admin, AdminAuthority::none(), "{role}");
        }
    }

    #[test]
    fn a_current_row_is_taken_unchanged() {
        let entry = VtcAclEntry::new(
            "did:key:zNew",
            VtcRole::Member,
            AdminAuthority::for_role(AdminRole::Auditor),
            "did:key:zAdmin",
        );
        let (e, m) = migrate_row(&serde_json::to_vec(&entry).unwrap()).unwrap();
        assert_eq!(m, Migrated::Current);
        assert_eq!(e, entry);
    }
}
