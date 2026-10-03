//! Moving the git-namespace rights store onto the ACL entries — phase C3 of
//! `docs/05-design-notes/vtc-admin-roles.md` (§9), **VTI-VTC-020**.
//!
//! Before C3 every right lived in a `rights:<scope>` row of the `git_ns`
//! keyspace, a second authority model beside the ACL. Now each is a resource
//! grant on its holder's entry ([`crate::acl::resource_grant`]). A store from
//! before C3 reaches a node two ways, and both are mapped here, with one
//! mapping:
//!
//! - **in place, at boot** ([`migrate_on_boot`]), after the ACL's own
//!   migration and before anything is authorized;
//! - **on backup import** (`crate::backup`), right after the replay, so an
//!   imported community does not wait for a restart to authorize from its
//!   entries.
//!
//! The mapping, row by row:
//!
//! - a right on a namespace or repository whose record exists, held by a
//!   subject with an entry, becomes that grant on the entry — with its granter
//!   (`delegatedBy`), time, expiry, reason, membership flags and any
//!   break-glass mark;
//! - a non-elevated right (`git.commit.sign`, `git.repo.maintain`) held by a
//!   subject with **no** entry — the bridge's service grant, an external
//!   signer — becomes an entry of the `application` community role holding it
//!   (Appendix F's open question: the bridge must have an entry);
//! - an elevated right held by a subject with no member entry, or a right on a
//!   namespace or repository with no record, maps onto nothing that would
//!   confer it. It is **kept, inert**, under `rights-unmapped:<scope>`, and
//!   raised as an acknowledge item for the community administrators — never
//!   silently dropped, never granted.
//!
//! Each legacy row is removed once its rights are written, and a grant
//! already on the entry is not written twice, so a crash part-way is finished
//! by the next run and a second run does nothing. The rights store is
//! **removed**, not kept read-only: nothing reads `rights:*` after this, and a
//! store that two code paths could read is the second authority model this
//! phase exists to retire.

use serde_json::json;
use tracing::{info, warn};
use vti_common::error::AppError;

use super::model::{RightsSet, Scope};
use super::ops::{Audit, audit};
use super::store::{self, RIGHTS_PREFIX, list_prefix};
use crate::acl::resource_grant::{self as rg, ResourceGrant};
use crate::server::AppState;

const UNMAPPED_PREFIX: &str = "rights-unmapped:";

/// What a migration did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RightsMigration {
    /// Rights written onto entries.
    pub migrated: u32,
    /// `application` entries created for non-members holding rights.
    pub applications: u32,
    /// What could not be mapped, as `right@resource-or-scope → subject`.
    pub unmappable: Vec<String>,
}

/// Rebuild the grant-holder index, then move any rights left in the old
/// store onto the entries. Run at boot, after `acl::migrate::migrate_on_boot`.
pub async fn migrate_on_boot(state: &AppState) -> Result<RightsMigration, AppError> {
    rg::rebuild_holder_index(&state.acl_ks).await?;
    migrate_rights(state, "the boot migration").await
}

/// Move every `rights:*` row onto the ACL entries (module docs). Idempotent.
pub async fn migrate_rights(state: &AppState, how: &str) -> Result<RightsMigration, AppError> {
    let _guard = store::write_lock().await;
    let legacy = list_prefix::<RightsSet>(&state.git_ns.ks, RIGHTS_PREFIX).await?;
    let mut out = RightsMigration::default();
    if legacy.is_empty() {
        return Ok(out);
    }
    for (key, set) in legacy {
        let rest = &key[RIGHTS_PREFIX.len()..];
        let scope = if let Some(id) = rest.strip_prefix("ns:") {
            Scope::Namespace(id.to_string())
        } else if let Some(id) = rest.strip_prefix("repo:") {
            Scope::Repo(id.to_string())
        } else {
            warn!(key, "a rights row with an unknown scope: kept, unmapped");
            move_unmapped(state, &key, rest, &set).await?;
            out.unmappable.push(format!("{rest} (unknown scope)"));
            continue;
        };
        let qualifier = store::scope_qualifier(&state.git_ns.ks, &scope).await?;
        let mut unmapped = RightsSet::default();
        for row in &set.rows {
            let Some(q) = qualifier.clone() else {
                out.unmappable
                    .push(format!("{}@{} → {}", row.right, scope.key(), row.subject));
                unmapped.rows.push(row.clone());
                continue;
            };
            let grant = store::grant_of(row, q);
            let entry = crate::acl::get_acl_entry(&state.acl_ks, &row.subject).await?;
            let mut entry = match entry {
                Some(e) if !(e.is_application() && row.right.is_elevated()) => e,
                Some(_) | None if row.right.is_elevated() => {
                    out.unmappable.push(format!(
                        "{} → {} (no member entry)",
                        grant.display(),
                        row.subject
                    ));
                    unmapped.rows.push(row.clone());
                    continue;
                }
                _ => {
                    out.applications += 1;
                    let mut e = crate::acl::VtcAclEntry::new(
                        row.subject.clone(),
                        crate::acl::VtcRole::Application,
                        crate::acl::AdminAuthority::none(),
                        row.granted_by.clone(),
                    );
                    e.label = Some("holds git rights without membership".into());
                    e
                }
            };
            if !holds(&entry.resource_grants, &grant) {
                entry.resource_grants.push(grant);
                out.migrated += 1;
            }
            crate::acl::store_acl_entry(&state.acl_ks, &entry).await?;
        }
        if !unmapped.rows.is_empty() {
            move_unmapped(state, &key, rest, &unmapped).await?;
        } else {
            state.git_ns.ks.remove(key.clone()).await?;
        }
    }
    out.unmappable.sort();
    info!(
        migrated = out.migrated,
        applications = out.applications,
        unmappable = out.unmappable.len(),
        "moved git-namespace rights onto the ACL entries (phase C3)"
    );
    let vtc = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "did:key:vtc-boot".into());
    audit(
        state,
        &vtc,
        None,
        Audit {
            action: "gitNs.rights.migrated",
            namespace: None,
            resource: None,
            right: None,
            policy_version: None,
            detail: Some(
                json!({
                    "migrated": out.migrated,
                    "applications": out.applications,
                    "unmappable": out.unmappable.len(),
                    "by": how,
                })
                .to_string(),
            ),
        },
    )
    .await;
    if !out.unmappable.is_empty() {
        raise_unmappable(state, &out.unmappable).await?;
    }
    Ok(out)
}

/// Whether `grants` already holds `g` (same capability, resource and grade):
/// what keeps a re-run from writing a grant twice.
fn holds(grants: &[ResourceGrant], g: &ResourceGrant) -> bool {
    grants
        .iter()
        .any(|h| h.capability == g.capability && h.resource == g.resource && h.grade == g.grade)
}

/// Keep rows nothing could take, inert, out of the rights namespace.
async fn move_unmapped(
    state: &AppState,
    key: &str,
    rest: &str,
    set: &RightsSet,
) -> Result<(), AppError> {
    state
        .git_ns
        .ks
        .insert(format!("{UNMAPPED_PREFIX}{rest}"), set)
        .await?;
    state.git_ns.ks.remove(key.to_string()).await
}

/// Tell the community administrators what the migration could not carry
/// across (**VTI-VTC-023**: nothing changes authority unseen).
async fn raise_unmappable(state: &AppState, unmappable: &[String]) -> Result<(), AppError> {
    let now = crate::auth::session::now_epoch();
    let acknowledgers: Vec<String> = crate::acl::list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| !e.is_expired(now) && e.is_community_admin())
        .map(|e| e.did)
        .collect();
    let dids: Vec<String> = unmappable
        .iter()
        .filter_map(|u| u.split(" → ").nth(1))
        .map(|d| d.split(' ').next().unwrap_or(d).to_string())
        .collect();
    let write = crate::admin_actions::OperatorWrite {
        marker: format!("git-rights-migration:{}", unmappable.join(",")),
        command: format!(
            "the migration of git-namespace rights onto ACL entries, which could not carry {} \
             across — kept inert under rights-unmapped:*; grant them again with \
             git-ns/right/grant if they should stand: {}",
            unmappable.len(),
            unmappable.join("; ")
        ),
        action: "aclMigration".into(),
        dids: if dids.is_empty() {
            vec!["did:key:vtc-boot".into()]
        } else {
            dids
        },
        operator_host: gethostname::gethostname().to_string_lossy().into_owned(),
        invoked_at: chrono::Utc::now(),
        acknowledgers: (!acknowledgers.is_empty()).then_some(acknowledgers),
    };
    crate::admin_actions::raise_operator_item(state, &write).await?;
    Ok(())
}
