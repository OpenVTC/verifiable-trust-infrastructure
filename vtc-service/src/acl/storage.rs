//! CRUD helpers for [`super::VtcAclEntry`].
//!
//! Mirrors the shape of `vti_common::acl`'s helper set but speaks
//! the VTC's role taxonomy. The on-disk key prefix (`acl:`) is
//! unchanged, so a vtc-service binary built against this module
//! can read rows that Phase 0 wrote via `vti_common::acl::*`
//! without an explicit migration.
//!
//! ## What's intentionally missing
//!
//! - `check_acl` / `check_acl_full` — those return a
//!   `vti_common::acl::Role`. Auth-time role checks still flow
//!   through those helpers; vtc-service's PR-1 keeps consuming
//!   them as-is and only the storage path reshapes. Phase-2
//!   tightens the auth helpers to use `VtcRole` once the
//!   downstream session / passkey code is ready for the shift.
//! - `validate_role_assignment` — same reason. Phase-2.
//!
//! ## Pagination
//!
//! [`list_acl_entries_paginated`] returns a
//! [`vti_common::pagination::Paginated`] for the GET-list
//! endpoints under §M1.4. The unpaginated
//! [`list_acl_entries`] keeps the call sites that walked the
//! full keyspace (audit, emergency-bootstrap cleanup) working
//! without rewriting them.

use vtc_audit::AuditKey;
use vti_common::acl::Role;
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::{Batch, KeyspaceHandle};

use super::entry::{Suspension, VtcAclEntry, decode, iter};

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Map a stored entry to the `vti_common::acl::Role` the JWT/session layer
/// understands.
///
/// **Any administrative role** signs in (`vtc-admin-roles.md` §6): a
/// moderator, an auditor or an approver reaches the console as well as a
/// community administrator. What each may then *do* is never read from the
/// session — every gate asks the entry's capabilities at execution time
/// ([`super::VtcAclEntry::can`], [`require_capability`]). So the session role
/// is only "an administrator of some kind", and is `Admin` for all of them.
///
/// An entry with no administrative role is refused with a clean `Forbidden`,
/// whatever its community role — `member`, `issuer` and the community role
/// `admin` with no administrative authority alike. Fails closed, and the
/// message carries neither serde internals nor the role name (this is consumed
/// on the unauthenticated `/auth/challenge` path).
pub fn auth_role_for(entry: &VtcAclEntry) -> Result<Role, AppError> {
    if entry.admin.is_administrator() {
        Ok(Role::Admin)
    } else {
        Err(AppError::Forbidden(
            "DID is not permitted to authenticate on this VTC".into(),
        ))
    }
}

/// VTC analogue of `vti_common::acl::check_acl_full`: resolve a DID's auth
/// role from the VTC ACL.
///
/// **Use this — not `vti_common::acl::check_acl[_full]` — for every
/// auth-time ACL gate on the VTC store.** This decoder never 500s on a VTC
/// role; it returns a clean `Forbidden` for absent / expired / non-administrator
/// rows. P0.16.
///
/// The context list it returns is always empty: a VTC entry holds no contexts
/// (**VTI-VTC-010**). That makes every administrator's session claims read as
/// unscoped to the shared `vti_common` helpers — which is why **no gate in this
/// service may be a claims check**. Each operation asks the capability it needs
/// of the signer's live entry ([`require_capability`]).
pub async fn resolve_auth_role(
    acl_ks: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::Forbidden(format!("DID not in ACL: {did}")))?;
    if entry.is_expired(now_epoch()) {
        return Err(AppError::Forbidden(format!("ACL entry expired: {did}")));
    }
    let role = auth_role_for(&entry)?;
    Ok((role, Vec::new()))
}

/// Read `did`'s live entry and require it to hold `cap` at `resource`
/// (`None` = community-wide). **The** gate every administrative operation
/// goes through (**VTI-ACL-030**, **-034**, **-036**): read now, never from a
/// session or credential summarising it.
///
/// A missing, expired or insufficient entry is `Forbidden`, naming the
/// capability so the operator knows which grant is missing.
pub async fn require_capability(
    acl_ks: &KeyspaceHandle,
    did: &str,
    cap: super::Capability,
    resource: Option<&super::ResourceQualifier>,
) -> Result<VtcAclEntry, AppError> {
    let entry = get_acl_entry(acl_ks, did).await?;
    match entry {
        Some(e) if e.can(cap, resource) => Ok(e),
        Some(VtcAclEntry {
            suspension: Some(s),
            ..
        }) => Err(s.refusal(did)),
        _ => Err(capability_refusal(did, cap, resource)),
    }
}

/// [`require_capability`] at any qualifier.
pub async fn require_any_capability(
    acl_ks: &KeyspaceHandle,
    did: &str,
    cap: super::Capability,
) -> Result<VtcAclEntry, AppError> {
    let entry = get_acl_entry(acl_ks, did).await?;
    match entry {
        Some(e) if e.can_any(cap) => Ok(e),
        Some(VtcAclEntry {
            suspension: Some(s),
            ..
        }) => Err(s.refusal(did)),
        _ => Err(capability_refusal(did, cap, None)),
    }
}

/// The refusal for a missing capability.
pub fn capability_refusal(
    did: &str,
    cap: super::Capability,
    resource: Option<&super::ResourceQualifier>,
) -> AppError {
    let at = resource.map(|r| format!(" at {r}")).unwrap_or_default();
    AppError::Forbidden(format!(
        "{did} does not hold {cap}{at} — this operation needs it (VTI-ACL-030). An \
         administrator holding vtc.roles.assign can grant it with acl/update"
    ))
}

/// Retrieve an ACL entry by DID. `Ok(None)` if absent.
///
/// A suspension pending a cooling-off reduction is read beside the row
/// ([`get_suspension`]) and set on the entry, so every authorization question
/// asked of it answers as the suspension requires (`vtc-action-list.md` §8.2).
pub async fn get_acl_entry(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<VtcAclEntry>, AppError> {
    let key = acl_key(did);
    let raw = ks.get_raw(key.as_bytes()).await?;
    match raw {
        Some(bytes) => {
            let mut entry = decode(&bytes)?;
            // A custom role's ceiling is its definition as stored now
            // (VTI-ACL-011: none stored, nothing conferred).
            super::roles::resolve(ks, &mut entry).await?;
            entry.suspension = get_suspension(ks, did).await?;
            Ok(Some(entry))
        }
        None => Ok(None),
    }
}

// ---------- suspension markers ----------

/// `suspended:<did>` → the [`Suspension`] an open cooling-off reduction holds
/// on that subject (`vtc-action-list.md` §8.2). Kept in the ACL keyspace so
/// that every read of an entry finds it beside the row.
///
/// The action list is the source of truth and writes these
/// ([`crate::admin_actions`]): a marker is written **before** the action
/// record that holds it and removed **after** the record closes, so a crash
/// between the two leaves a marker with no open action — the entry
/// over-restricted, never an open reduction whose subject still acts — and
/// [`crate::admin_actions::reconcile_suspensions`] settles it at the next
/// start and every sweep.
const SUSPENSION_PREFIX: &str = "suspended:";

fn suspension_key(did: &str) -> String {
    format!("{SUSPENSION_PREFIX}{did}")
}

/// The suspension held on `did`, if any.
pub async fn get_suspension(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<Suspension>, AppError> {
    ks.get(suspension_key(did)).await
}

/// Record that `did` is suspended by `s`.
pub async fn put_suspension(
    ks: &KeyspaceHandle,
    did: &str,
    s: &Suspension,
) -> Result<(), AppError> {
    ks.insert(suspension_key(did), s).await?;
    // Authority moved: open console streams re-check their callers.
    crate::admin_events::notify_authority();
    Ok(())
}

/// Lift the suspension on `did`.
pub async fn remove_suspension(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(suspension_key(did)).await?;
    crate::admin_events::notify_authority();
    Ok(())
}

/// Every suspension marker, by subject DID.
pub async fn list_suspensions(
    ks: &KeyspaceHandle,
) -> Result<std::collections::HashMap<String, Suspension>, AppError> {
    let mut out = std::collections::HashMap::new();
    for (k, v) in ks
        .prefix_iter_raw(SUSPENSION_PREFIX.as_bytes().to_vec())
        .await?
    {
        let did = String::from_utf8_lossy(&k[SUSPENSION_PREFIX.len()..]).into_owned();
        match serde_json::from_slice::<Suspension>(&v) {
            Ok(s) => {
                out.insert(did, s);
            }
            Err(e) => tracing::warn!(%did, error = %e, "unreadable suspension marker"),
        }
    }
    Ok(out)
}

/// Resolve entries read raw from the keyspace as [`get_acl_entry`] resolves
/// one: each custom role's stored definition, and any suspension held on it.
pub(crate) async fn resolve_entries(
    ks: &KeyspaceHandle,
    entries: &mut [VtcAclEntry],
) -> Result<(), AppError> {
    super::roles::resolve_all(ks, entries).await?;
    apply_suspensions(ks, entries).await
}

async fn apply_suspensions(
    ks: &KeyspaceHandle,
    entries: &mut [VtcAclEntry],
) -> Result<(), AppError> {
    let mut marks = list_suspensions(ks).await?;
    if marks.is_empty() {
        return Ok(());
    }
    for e in entries.iter_mut() {
        e.suspension = marks.remove(&e.did);
    }
    Ok(())
}

// ---------- the authority index ----------

/// `acladmin:<did>` — the entries that hold any authority beyond membership:
/// an administrative role or any act / approve scope
/// ([`super::AdminAuthority`]), a resource grant or a group grant. Every
/// question of the form "who may decide / approve / acknowledge / manage …"
/// is answered from these entries alone, so it reads them through this index
/// instead of decoding the whole ACL, which holds one row per member (#2602).
///
/// The rule is on the **stored** fields only ([`holds_authority`]), never on
/// anything resolved at read time (a custom role's definition, a suspension),
/// so a write of the entry alone decides its row. Every writer of an entry
/// writes the row in the same store batch as the entry ([`store_acl_entry`],
/// [`delete_acl_entry`], [`move_acl_entry`]), and boot and a restore rebuild
/// it ([`rebuild_authority_index`]) for rows written before it existed.
///
/// A superset is harmless — a reader re-checks [`holds_authority`] on the
/// entry it reads, and a DID with no entry contributes nothing. A subset is
/// not: an administrator missing here would be left out of an approver count
/// (VTI-APV-009), so nothing may write an entry without its row.
const AUTHORITY_PREFIX: &str = "acladmin:";

fn authority_key(did: &str) -> String {
    format!("{AUTHORITY_PREFIX}{did}")
}

/// Whether `entry`, as stored, holds any authority beyond membership — the
/// rule for its `acladmin:` row. Deliberately wide: an administrative role of
/// any kind, any act or approve scope written beside none, any resource
/// grant, any group grant. What each confers is the reader's to decide.
pub fn holds_authority(entry: &VtcAclEntry) -> bool {
    use super::capability::{CapabilityScope, VtcActScope};
    let a = &entry.admin;
    a.admin_role.is_some()
        || a.act != VtcActScope::None
        || a.capabilities != CapabilityScope::None
        || a.approve != VtcActScope::None
        || a.approve_capabilities != CapabilityScope::None
        || !entry.resource_grants.is_empty()
        || !entry.group_grants.is_empty()
}

/// Put `entry`'s index rows (authority and git grant holder) into `batch`
/// beside the entry itself.
fn index_rows(batch: &mut Batch, entry: &VtcAclEntry) {
    if holds_authority(entry) {
        batch.insert_raw(authority_key(&entry.did), b"1".to_vec());
    } else {
        batch.remove(authority_key(&entry.did));
    }
    if !entry.resource_grants.is_empty() {
        batch.insert_raw(super::resource_grant::holder_key(&entry.did), b"1".to_vec());
    }
}

/// Every entry that holds authority beyond membership ([`holds_authority`]),
/// read through the `acladmin:` index and resolved as [`list_acl_entries`]
/// resolves them (custom role ceilings, suspensions).
///
/// The answer for every caller that keeps only administrators, approvers or
/// grant holders out of [`list_acl_entries`]: the same entries, at a cost in
/// the number of authority holders rather than the number of members.
pub async fn list_authority_entries(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    let mut entries = Vec::new();
    for key in ks.prefix_keys(AUTHORITY_PREFIX.as_bytes().to_vec()).await? {
        let did = String::from_utf8_lossy(&key[AUTHORITY_PREFIX.len()..]).into_owned();
        let Some(raw) = ks.get_raw(acl_key(&did).into_bytes()).await? else {
            continue;
        };
        match decode(&raw) {
            Ok(entry) if holds_authority(&entry) => entries.push(entry),
            Ok(_) => {}
            Err(err) => tracing::warn!(%did, error = %err, "skipping unparseable acl entry"),
        }
    }
    super::roles::resolve_all(ks, &mut entries).await?;
    apply_suspensions(ks, &mut entries).await?;
    Ok(entries)
}

/// Rebuild the `acladmin:` index from every entry — at boot and after a
/// restore, so rows written before the index existed, or restored without it,
/// are indexed before anything is authorized from it. Removes rows naming a
/// DID that no longer holds authority. Returns how many entries are indexed.
pub async fn rebuild_authority_index(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    let holders: std::collections::BTreeSet<String> = iter(ks)
        .await?
        .into_iter()
        .filter(holds_authority)
        .map(|e| e.did)
        .collect();
    let mut batch = Batch::new();
    for key in ks.prefix_keys(AUTHORITY_PREFIX.as_bytes().to_vec()).await? {
        let did = String::from_utf8_lossy(&key[AUTHORITY_PREFIX.len()..]).into_owned();
        if !holders.contains(&did) {
            batch.remove(key);
        }
    }
    for did in &holders {
        batch.insert_raw(authority_key(did), b"1".to_vec());
    }
    if !batch.is_empty() {
        ks.apply_batch(batch).await?;
    }
    Ok(holders.len())
}

/// Move `old_did`'s entry to `successor.did` (a key rotation) with its index
/// rows, as one conditional store batch: applied only while `old_did`'s row is
/// present — and, with `expected`, still exactly those bytes — and
/// `successor.did` has no entry. The authority and grant-holder rows move with
/// the entry, so a rotated administrator is never missing from either index.
pub async fn move_acl_entry(
    ks: &KeyspaceHandle,
    old_did: &str,
    expected: Option<Vec<u8>>,
    successor: &VtcAclEntry,
) -> Result<vti_common::store::MoveOutcome, AppError> {
    use vti_common::store::{BatchOutcome, MoveOutcome};
    let old_key = acl_key(old_did);
    let new_key = acl_key(&successor.did);
    let mut batch = Batch::new();
    // Check 0: the source is there.
    batch.require_present(old_key.clone());
    // Check 1 (with `expected`): it is unchanged.
    let changed_check = expected.is_some();
    if let Some(expected) = expected {
        batch.require_unchanged(old_key.clone(), expected);
    }
    // The last check: the target is free.
    let target_check = if changed_check { 2 } else { 1 };
    batch.require_absent(new_key.clone());
    batch.insert(new_key, successor)?;
    batch.remove(old_key);
    batch.remove(authority_key(old_did));
    batch.remove(super::resource_grant::holder_key(old_did));
    index_rows(&mut batch, successor);
    let outcome = match ks.apply_batch(batch).await? {
        BatchOutcome::Applied => MoveOutcome::Moved,
        BatchOutcome::Refused { check: 0 } => MoveOutcome::SourceMissing,
        BatchOutcome::Refused { check } if check == target_check => MoveOutcome::TargetExists,
        BatchOutcome::Refused { .. } => MoveOutcome::SourceChanged,
    };
    if outcome == MoveOutcome::Moved {
        crate::admin_events::notify_authority();
    }
    Ok(outcome)
}

/// Store (create or overwrite) an ACL entry.
///
/// The entry and its index rows — the git grant-holder index and the
/// authority index ([`list_authority_entries`]) — are one store batch, so a
/// crash can never leave an entry its index rows disagree with.
pub async fn store_acl_entry(ks: &KeyspaceHandle, entry: &VtcAclEntry) -> Result<(), AppError> {
    let mut batch = Batch::new();
    batch.insert(acl_key(&entry.did), entry)?;
    index_rows(&mut batch, entry);
    ks.apply_batch(batch).await?;
    // Authority moved: open console streams re-check their callers' readable
    // topics before their next byte (`crate::admin_events`).
    crate::admin_events::notify_authority();
    Ok(())
}

/// How many times [`delete_acl_entry`] re-reads the rows it changes after
/// another writer changed one between its read and its conditional write.
const DELETE_ATTEMPTS: usize = 64;

/// Delete an ACL entry by DID. Idempotent — `Ok(())` whether the
/// row existed or not.
///
/// The resource grants the entry held go with it — they confer nothing
/// without a live entry (**VTI-ACL-037**) — and are kept aside for the
/// git-namespace lifecycle, which records each revocation and orphans what the
/// subject owned alone ([`super::resource_grant::keep_departed`]).
///
/// The removal, the kept grants and the holder index are one conditional store
/// batch, applied only while the entry (and any grants already kept) are still
/// what was read. Written separately, a crash between them lost the departed
/// grants or left them kept for an entry still in place, and a concurrent
/// rewrite of the entry could have its grants dropped unrecorded.
pub async fn delete_acl_entry(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    let key = acl_key(did);
    let departed_key = super::resource_grant::departed_key(did);
    for _ in 0..DELETE_ATTEMPTS {
        let mut batch = Batch::new();
        match ks.get_raw(key.as_bytes()).await? {
            Some(bytes) => {
                let grants = decode(&bytes)
                    .map(|e| e.resource_grants)
                    .unwrap_or_default();
                batch.require_unchanged(key.clone(), bytes);
                if !grants.is_empty() {
                    let kept_raw = ks.get_raw(departed_key.as_bytes()).await?;
                    let mut kept: Vec<super::resource_grant::ResourceGrant> = match &kept_raw {
                        Some(raw) => serde_json::from_slice(raw)?,
                        None => Vec::new(),
                    };
                    match kept_raw {
                        Some(raw) => batch.require_unchanged(departed_key.clone(), raw),
                        None => batch.require_absent(departed_key.clone()),
                    };
                    kept.extend(grants);
                    batch.insert(departed_key.clone(), &kept)?;
                }
                batch.remove(key.clone());
            }
            // Nothing to remove but a stale index row — and only while no entry
            // has appeared, or this would strip a fresh entry's index.
            None => {
                batch.require_absent(key.clone());
            }
        }
        batch.remove(super::resource_grant::holder_key(did));
        batch.remove(authority_key(did));
        if ks.apply_batch(batch).await?.is_applied() {
            crate::admin_events::notify_authority();
            return Ok(());
        }
    }
    Err(AppError::Conflict(format!(
        "ACL entry for {did} kept changing while it was being deleted"
    )))
}

/// Return every ACL entry in the keyspace. Unbounded — intended
/// for whole-keyspace operations like audit emission +
/// emergency-bootstrap cleanup, not for user-facing list
/// endpoints. Use [`list_acl_entries_paginated`] for those.
pub async fn list_acl_entries(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    let mut entries = iter(ks).await?;
    super::roles::resolve_all(ks, &mut entries).await?;
    apply_suspensions(ks, &mut entries).await?;
    Ok(entries)
}

/// Paginated list. Signs the cursor under `audit_key` so it can't
/// be forged across communities.
///
/// Seeks to the cursor and reads one row past the page (to know whether
/// another follows), so a page costs its own size whatever the ACL holds —
/// not a scan and sort of every entry, which made walking the whole list
/// quadratic in the member count (#2601). The cursor is the same one
/// `paginate` issues (the last key returned), so a cursor from before this
/// change resumes where it left off.
pub async fn list_acl_entries_paginated(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<VtcAclEntry>, AppError> {
    let limit = limit.clamp(1, vti_common::pagination::MAX_LIMIT);
    let mut opts = vti_common::store::ScanOpts::new(b"acl:".to_vec(), limit + 1);
    if let Some(c) = cursor {
        opts = opts.after(c.last_key.clone());
    }
    let pairs = ks.scan_raw(opts).await?;
    // The page as `paginate` cuts it from the rows read; with no cursor of its
    // own (the seek already applied it) it ends where the rows run out.
    let mut page = paginate(pairs, None, limit, &audit_key.key, 0, decode)?;
    super::roles::resolve_all(ks, &mut page.items).await?;
    apply_suspensions(ks, &mut page.items).await?;
    Ok(page)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, VtcRole};
    use vtc_audit::AuditKeyStore;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let ks = store.keyspace("acl").expect("ks");
        (ks, dir)
    }

    fn entry(did: &str, role: VtcRole) -> VtcAclEntry {
        VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            admin: AdminAuthority::none(),
            delegated_by: None,
            created_at: 1,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            group_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        }
    }

    #[tokio::test]
    async fn store_then_get_round_trip() {
        let (ks, _dir) = temp_ks().await;
        let e = entry("did:key:zMember1", VtcRole::Member);
        store_acl_entry(&ks, &e).await.unwrap();
        let got = get_acl_entry(&ks, "did:key:zMember1")
            .await
            .unwrap()
            .expect("entry present");
        assert_eq!(got, e);
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_did() {
        let (ks, _dir) = temp_ks().await;
        assert!(
            get_acl_entry(&ks, "did:key:zNobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn entry_with_grant(did: &str) -> VtcAclEntry {
        let (capability, grade) =
            crate::acl::resource_grant::capability_for(crate::git_ns::model::Right::NsAdmin);
        let mut e = entry(did, VtcRole::Member);
        e.resource_grants = vec![crate::acl::resource_grant::ResourceGrant {
            capability,
            resource: "git-ns:github.com/acme".parse().unwrap(),
            grade,
            delegated_by: "did:key:zG".into(),
            granted_at: chrono::Utc::now(),
            expires_at: None,
            reason: None,
            subject_was_member: true,
            granter_was_member: true,
            break_glass: None,
            review: None,
            single_admin: None,
        }];
        e
    }

    /// An entry and its holder index (and, on removal, its kept grants) are
    /// one journal record, so a crash cannot split them.
    #[tokio::test]
    async fn an_entry_and_its_index_commit_as_one_journal_record() {
        let (ks, _dir) = temp_ks().await;
        let seq = || ks.journal_seqno().unwrap();
        let before = seq();
        store_acl_entry(&ks, &entry_with_grant("did:key:zJ"))
            .await
            .unwrap();
        assert_eq!(seq() - before, 1, "store_acl_entry");
        let before = seq();
        delete_acl_entry(&ks, "did:key:zJ").await.unwrap();
        assert_eq!(seq() - before, 1, "delete_acl_entry");
    }

    /// Deletes racing on one entry keep its resource grants for the git
    /// lifecycle exactly once. Read-then-append let each delete that read the
    /// entry append its grants again (or overwrite another's append).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn racing_deletes_keep_departed_grants_exactly_once() {
        let (ks, _dir) = temp_ks().await;
        for round in 0..40 {
            let did = format!("did:key:zDeparting{round}");
            store_acl_entry(&ks, &entry_with_grant(&did)).await.unwrap();
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let (ks, barrier, did) = (ks.clone(), barrier.clone(), did.clone());
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    delete_acl_entry(&ks, &did).await.unwrap();
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
            let kept: usize = crate::acl::resource_grant::departed(&ks)
                .await
                .unwrap()
                .into_iter()
                .filter(|(d, _)| *d == did)
                .map(|(_, g)| g.len())
                .sum();
            assert_eq!(kept, 1, "one deleted entry's grant kept {kept} times");
        }
    }

    /// Stores and deletes racing on one entry leave the holder index naming
    /// it exactly when it holds resource grants.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn the_holder_index_tracks_the_entry_under_races() {
        let (ks, _dir) = temp_ks().await;
        for round in 0..40 {
            let did = format!("did:key:zIndexed{round}");
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
            let mut tasks = Vec::new();
            for i in 0..8 {
                let (ks, barrier, did) = (ks.clone(), barrier.clone(), did.clone());
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    if i % 2 == 0 {
                        store_acl_entry(&ks, &entry_with_grant(&did)).await.unwrap();
                    } else {
                        delete_acl_entry(&ks, &did).await.unwrap();
                    }
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
            let held = get_acl_entry(&ks, &did)
                .await
                .unwrap()
                .is_some_and(|e| !e.resource_grants.is_empty());
            let indexed = crate::acl::resource_grant::indexed_holders(&ks)
                .await
                .unwrap()
                .contains(&did);
            assert_eq!(
                held, indexed,
                "entry holds grants: {held}, indexed: {indexed}"
            );
        }
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        let e = entry("did:key:zDelete", VtcRole::Member);
        store_acl_entry(&ks, &e).await.unwrap();
        delete_acl_entry(&ks, "did:key:zDelete").await.unwrap();
        // Second delete on an absent row.
        delete_acl_entry(&ks, "did:key:zDelete").await.unwrap();
        assert!(
            get_acl_entry(&ks, "did:key:zDelete")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_acl_entries_returns_every_row() {
        let (ks, _dir) = temp_ks().await;
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_acl_entry(&ks, &entry(did, VtcRole::Member))
                .await
                .unwrap();
        }
        let listed = list_acl_entries(&ks).await.unwrap();
        assert_eq!(listed.len(), 3);
    }

    #[tokio::test]
    async fn paginated_walks_the_keyspace() {
        let (ks, _dir) = temp_ks().await;
        let dir = tempfile::tempdir().unwrap();
        let store2 = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let audit_key_ks = store2.keyspace("audit_key").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        let audit_key = key_store.ensure_initial(&[0xAB; 32]).await.unwrap();

        // Seed 5 members.
        for did in [
            "did:key:zA",
            "did:key:zB",
            "did:key:zC",
            "did:key:zD",
            "did:key:zE",
        ] {
            store_acl_entry(&ks, &entry(did, VtcRole::Member))
                .await
                .unwrap();
        }

        // First page (limit 2).
        let page1 = list_acl_entries_paginated(&ks, &audit_key, None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        assert_eq!(page1.items[0].did, "did:key:zA");
        assert_eq!(page1.items[1].did, "did:key:zB");

        // Decode the wire cursor + walk the next page.
        let cursor1 =
            Cursor::decode(page1.next_cursor.as_deref().unwrap(), &audit_key.key).unwrap();
        let page2 = list_acl_entries_paginated(&ks, &audit_key, Some(&cursor1), 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        assert_eq!(page2.items[0].did, "did:key:zC");
        assert_eq!(page2.items[1].did, "did:key:zD");

        // Last page (no further cursor).
        let cursor2 =
            Cursor::decode(page2.next_cursor.as_deref().unwrap(), &audit_key.key).unwrap();
        let page3 = list_acl_entries_paginated(&ks, &audit_key, Some(&cursor2), 2)
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert_eq!(page3.items[0].did, "did:key:zE");
        assert!(page3.next_cursor.is_none());
    }

    // ---- P0.16: entry → auth Role resolution ----

    /// Console sign-in admits any administrative role, not only a community
    /// administrator (`vtc-admin-roles.md` §6).
    #[test]
    fn any_administrative_role_maps_to_the_admin_session_role() {
        use crate::acl::capability::AdminRole;
        for role in AdminRole::BUILT_IN {
            let mut e = entry("did:key:zA", VtcRole::Member);
            e.admin = AdminAuthority::for_role(role.clone());
            assert_eq!(auth_role_for(&e).unwrap(), Role::Admin, "{role}");
        }
    }

    #[test]
    fn entries_without_an_administrative_role_are_cleanly_forbidden() {
        use axum::response::IntoResponse;
        for role in [
            VtcRole::Admin,
            VtcRole::Moderator,
            VtcRole::Issuer,
            VtcRole::Member,
            VtcRole::custom("editor").unwrap(),
        ] {
            let err = auth_role_for(&entry("did:key:zA", role.clone()))
                .expect_err("no administrative role must not map to an auth role");
            // 403, not 500 — the whole point of P0.16.
            assert_eq!(
                err.into_response().status(),
                axum::http::StatusCode::FORBIDDEN,
                "{role} must yield 403"
            );
        }
    }

    #[test]
    fn forbidden_message_carries_no_serde_internals_or_role_name() {
        let AppError::Forbidden(msg) =
            auth_role_for(&entry("did:key:zA", VtcRole::Moderator)).unwrap_err()
        else {
            panic!("expected Forbidden");
        };
        assert!(!msg.contains("variant"), "must not leak serde text: {msg}");
        assert!(
            !msg.contains("moderator"),
            "must not enumerate the role to an unauth caller: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_auth_role_admits_an_administrator_with_no_contexts() {
        let (ks, _dir) = temp_ks().await;
        let mut e = entry("did:key:zAdmin", VtcRole::Member);
        e.admin = AdminAuthority::for_role(crate::acl::capability::AdminRole::Auditor);
        store_acl_entry(&ks, &e).await.unwrap();

        let (role, contexts) = resolve_auth_role(&ks, "did:key:zAdmin").await.unwrap();
        assert_eq!(role, Role::Admin);
        assert_eq!(
            contexts,
            Vec::<String>::new(),
            "a VTC entry holds no contexts"
        );
    }

    #[tokio::test]
    async fn require_capability_reads_the_live_entry() {
        use crate::acl::Capability;
        let (ks, _dir) = temp_ks().await;
        let mut e = entry("did:key:zAud", VtcRole::Member);
        e.admin = AdminAuthority::for_role(crate::acl::capability::AdminRole::Auditor);
        store_acl_entry(&ks, &e).await.unwrap();
        assert!(
            require_capability(&ks, "did:key:zAud", Capability::AuditRead, None)
                .await
                .is_ok()
        );
        assert!(matches!(
            require_capability(&ks, "did:key:zAud", Capability::ConfigAdmin, None).await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            require_capability(&ks, "did:key:zNobody", Capability::AuditRead, None).await,
            Err(AppError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn resolve_auth_role_forbids_non_admin_absent_and_expired() {
        let (ks, _dir) = temp_ks().await;

        // No administrative role → clean Forbidden.
        store_acl_entry(&ks, &entry("did:key:zMod", VtcRole::Moderator))
            .await
            .unwrap();
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zMod").await,
            Err(AppError::Forbidden(_))
        ));

        // Absent DID → Forbidden.
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zNobody").await,
            Err(AppError::Forbidden(_))
        ));

        // Expired admin row → Forbidden (expiry honoured).
        let mut expired = entry("did:key:zStale", VtcRole::Admin);
        expired.admin = AdminAuthority::community_admin();
        expired.expires_at = Some(1); // long past
        store_acl_entry(&ks, &expired).await.unwrap();
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zStale").await,
            Err(AppError::Forbidden(_))
        ));
    }

    fn admin(did: &str) -> VtcAclEntry {
        VtcAclEntry {
            admin: AdminAuthority::community_admin(),
            ..entry(did, VtcRole::Admin)
        }
    }

    async fn indexed(ks: &KeyspaceHandle) -> Vec<String> {
        let mut dids: Vec<String> = list_authority_entries(ks)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.did)
            .collect();
        dids.sort();
        dids
    }

    /// What the index answers is what filtering the whole ACL answers.
    async fn agrees_with_a_full_scan(ks: &KeyspaceHandle) {
        let mut full: Vec<String> = list_acl_entries(ks)
            .await
            .unwrap()
            .into_iter()
            .filter(holds_authority)
            .map(|e| e.did)
            .collect();
        full.sort();
        assert_eq!(indexed(ks).await, full);
    }

    /// #2602: the authority index is written in the entry's own batch, so it
    /// follows every write — a grant, a demotion, a removal.
    #[tokio::test]
    async fn the_authority_index_follows_every_write() {
        let (ks, _dir) = temp_ks().await;
        store_acl_entry(&ks, &admin("did:key:zAdmin"))
            .await
            .unwrap();
        store_acl_entry(&ks, &entry("did:key:zMember", VtcRole::Member))
            .await
            .unwrap();
        assert_eq!(indexed(&ks).await, vec!["did:key:zAdmin".to_string()]);
        agrees_with_a_full_scan(&ks).await;

        // Promoted, then demoted: in, then out.
        store_acl_entry(&ks, &admin("did:key:zMember"))
            .await
            .unwrap();
        agrees_with_a_full_scan(&ks).await;
        store_acl_entry(&ks, &entry("did:key:zMember", VtcRole::Member))
            .await
            .unwrap();
        assert_eq!(indexed(&ks).await, vec!["did:key:zAdmin".to_string()]);

        // A member holding a resource grant decides what it covers.
        store_acl_entry(&ks, &entry_with_grant("did:key:zHolder"))
            .await
            .unwrap();
        agrees_with_a_full_scan(&ks).await;

        delete_acl_entry(&ks, "did:key:zAdmin").await.unwrap();
        assert_eq!(indexed(&ks).await, vec!["did:key:zHolder".to_string()]);
        assert!(
            ks.get_raw(authority_key("did:key:zAdmin").into_bytes())
                .await
                .unwrap()
                .is_none(),
            "a removed entry's index row goes in the same batch"
        );
    }

    /// #2602: a rotation moves the index row with the entry, one journal
    /// record, and refuses as `move_if_unchanged` did.
    #[tokio::test]
    async fn a_moved_entry_keeps_its_index_row() {
        use vti_common::store::MoveOutcome;
        let (ks, _dir) = temp_ks().await;
        store_acl_entry(&ks, &admin("did:key:zOld")).await.unwrap();
        let expected = ks
            .get_raw(acl_key("did:key:zOld").into_bytes())
            .await
            .unwrap();
        let successor = admin("did:key:zNew");

        // A stale `expected` changes nothing.
        assert_eq!(
            move_acl_entry(&ks, "did:key:zOld", Some(b"{}".to_vec()), &successor)
                .await
                .unwrap(),
            MoveOutcome::SourceChanged
        );
        let before = ks.journal_seqno().unwrap();
        assert_eq!(
            move_acl_entry(&ks, "did:key:zOld", expected, &successor)
                .await
                .unwrap(),
            MoveOutcome::Moved
        );
        assert_eq!(ks.journal_seqno().unwrap(), before + 1, "one batch");
        assert_eq!(indexed(&ks).await, vec!["did:key:zNew".to_string()]);
        agrees_with_a_full_scan(&ks).await;

        assert_eq!(
            move_acl_entry(&ks, "did:key:zOld", None, &successor)
                .await
                .unwrap(),
            MoveOutcome::SourceMissing
        );
        store_acl_entry(&ks, &admin("did:key:zThird"))
            .await
            .unwrap();
        assert_eq!(
            move_acl_entry(&ks, "did:key:zNew", None, &admin("did:key:zThird"))
                .await
                .unwrap(),
            MoveOutcome::TargetExists
        );
    }

    /// #2602: entries written before the index existed (raw rows, as an older
    /// version or a restore wrote them) are indexed by the boot rebuild, and a
    /// row naming a DID that holds nothing is dropped.
    #[tokio::test]
    async fn the_rebuild_backfills_rows_written_without_the_index() {
        let (ks, _dir) = temp_ks().await;
        for e in [
            admin("did:key:zA"),
            admin("did:key:zB"),
            entry("did:key:zM", VtcRole::Member),
        ] {
            ks.insert(acl_key(&e.did), &e).await.unwrap();
        }
        ks.insert_raw(authority_key("did:key:zM").into_bytes(), b"1".to_vec())
            .await
            .unwrap();
        assert_eq!(rebuild_authority_index(&ks).await.unwrap(), 2);
        assert_eq!(
            indexed(&ks).await,
            vec!["did:key:zA".to_string(), "did:key:zB".to_string()]
        );
        assert!(
            ks.get_raw(authority_key("did:key:zM").into_bytes())
                .await
                .unwrap()
                .is_none()
        );
        agrees_with_a_full_scan(&ks).await;
    }
}
