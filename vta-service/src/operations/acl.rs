use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use tracing::info;

use crate::audit::{self, audit};
use vta_sdk::protocols::acl_management::{
    create::CreateAclResultBody, delete::DeleteAclResultBody, list::ListAclResultBody,
    swap::AclSwapPresentation,
};

use crate::acl::{
    AclEntry, ApproveScope, Role, delete_acl_entry, get_acl_entry, is_acl_entry_visible,
    list_acl_entries, store_acl_entry, validate_acl_modification, validate_approve_scope_grant,
    validate_role_assignment,
};
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::contexts::get_context;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use vti_common::auth::step_up::StepUpMode;

pub struct UpdateAclParams {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
    /// `Some` sets the delegated step-up approver; `None` leaves it unchanged.
    pub step_up_approver: Option<String>,
    /// `Some` sets the per-entry step-up override (empty string clears); `None`
    /// leaves it unchanged.
    pub step_up_require: Option<String>,
}

/// Parse a wire `stepUp.require` value into a [`StepUpMode`]. Only `self` and
/// `delegated` are valid per-entry overrides (the spec's enum); an override is
/// additive and a per-subject relaxation to `delegated-any` is not meaningful.
/// `None`/empty ⇒ no override.
pub fn parse_step_up_require(s: Option<&str>) -> Result<Option<StepUpMode>, AppError> {
    match s.map(str::trim) {
        None | Some("") => Ok(None),
        Some("self") => Ok(Some(StepUpMode::SelfApprove)),
        Some("delegated") => Ok(Some(StepUpMode::Delegated)),
        Some(other) => Err(AppError::Validation(format!(
            "invalid stepUp.require '{other}': must be 'self' or 'delegated'"
        ))),
    }
}

/// Build an [`ApproveScope`] from the two wire fields. `all` wins over an
/// explicit context list; both absent ⇒ [`ApproveScope::None`] (confers
/// nothing, the default).
pub fn approve_scope_from_wire(all: bool, contexts: Vec<String>) -> ApproveScope {
    if all {
        ApproveScope::All
    } else if !contexts.is_empty() {
        ApproveScope::Contexts(contexts)
    } else {
        ApproveScope::None
    }
}

/// Render a stored [`StepUpMode`] override as its wire token for echo in
/// responses (`self` / `delegated`).
fn step_up_require_to_wire(m: Option<StepUpMode>) -> Option<String> {
    m.map(|m| {
        match m {
            StepUpMode::SelfApprove => "self",
            StepUpMode::Delegated => "delegated",
            StepUpMode::DelegatedAny => "delegated-any",
            StepUpMode::None => "none",
        }
        .to_string()
    })
}

/// Compute the symmetric difference of two context lists — every
/// element that appears in one but not the other. Used by `update_acl`
/// to enforce that a context-admin can only add or remove contexts
/// they themselves admin: removing a context the caller has no scope
/// over would otherwise silently evict the target from a context the
/// caller can't see.
///
/// Order doesn't matter; duplicates within a list are ignored. The
/// resulting Vec is deduped but unordered (a HashSet would do, but
/// the caller wants to iterate + format errors, so Vec is friendlier).
fn symmetric_difference_contexts(old: &[String], new: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let old_set: HashSet<&str> = old.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new.iter().map(String::as_str).collect();
    old_set
        .symmetric_difference(&new_set)
        .map(|s| (*s).to_string())
        .collect()
}

/// Reject ACL entries that reference contexts which don't exist in
/// the contexts keyspace. Without this check a super-admin's typo
/// (`ctx-prod-1` instead of `ctx-prod1`) silently creates a grant
/// against a non-existent realm; if `ctx-prod-1` is later created,
/// the dangling grant springs to life unauthorized. The fix is
/// symmetric to the cascade in `delete_context`, which prunes ACL
/// entries when their context goes away.
///
/// Empty `contexts` (super-admin-shaped entry) is accepted — the
/// loop short-circuits and the empty-shape guard lives in
/// `validate_acl_modification`.
async fn require_contexts_exist(
    contexts_ks: &KeyspaceHandle,
    contexts: &[String],
) -> Result<(), AppError> {
    for ctx in contexts {
        if get_context(contexts_ks, ctx).await?.is_none() {
            return Err(AppError::NotFound(format!(
                "context '{ctx}' is not registered on this VTA — create it first via \
                 'vta contexts create --id {ctx}' (offline) or 'pnm contexts create' (online)"
            )));
        }
    }
    Ok(())
}

fn to_result_body(e: &AclEntry) -> CreateAclResultBody {
    let (approve_all_contexts, approve_contexts) = match &e.approve_scope {
        ApproveScope::All => (true, Vec::new()),
        ApproveScope::Contexts(cs) => (false, cs.clone()),
        ApproveScope::None => (false, Vec::new()),
    };
    CreateAclResultBody {
        did: e.did.clone(),
        role: e.role.to_string(),
        label: e.label.clone(),
        allowed_contexts: e.allowed_contexts.clone(),
        created_at: e.created_at,
        created_by: e.created_by.clone(),
        expires_at: e.expires_at,
        step_up_approver: e.step_up_approver.clone(),
        step_up_require: step_up_require_to_wire(e.step_up_require),
        approve_all_contexts,
        approve_contexts,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    role: Role,
    label: Option<String>,
    allowed_contexts: Vec<String>,
    expires_at: Option<u64>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
    approve_scope: ApproveScope,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;
    validate_role_assignment(auth, &role)?;
    validate_acl_modification(auth, &allowed_contexts)?;
    // Granting approve-authority is its own privilege check: `all` is
    // super-admin-only, a scoped grant requires the caller to hold each context.
    validate_approve_scope_grant(auth, &approve_scope)?;
    require_contexts_exist(contexts_ks, &allowed_contexts).await?;
    if let ApproveScope::Contexts(cs) = &approve_scope {
        require_contexts_exist(contexts_ks, cs).await?;
    }
    let step_up_require = parse_step_up_require(step_up_require.as_deref())?;

    if get_acl_entry(acl_ks, did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {did}"
        )));
    }

    let entry = AclEntry::new(did, role, auth.did.clone())
        .with_label(label)
        .with_contexts(allowed_contexts)
        .with_expires_at(expires_at)
        .with_step_up_approver(step_up_approver)
        .with_step_up_require(step_up_require)
        .with_approve_scope(approve_scope);

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, caller = %auth.did, did = %entry.did, role = %entry.role, "ACL entry created");
    audit!(
        "acl.create",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.create",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(to_result_body(&entry))
}

pub async fn get_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(channel, did = %did, "ACL entry retrieved");
    Ok(to_result_body(&entry))
}

pub async fn list_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_filter: Option<&str>,
    channel: &str,
) -> Result<ListAclResultBody, AppError> {
    auth.require_manage()?;

    let all_entries = list_acl_entries(acl_ks).await?;
    let entries: Vec<CreateAclResultBody> = all_entries
        .iter()
        .filter(|e| is_acl_entry_visible(auth, e))
        .filter(|e| match context_filter {
            Some(ctx) => e.allowed_contexts.contains(&ctx.to_string()),
            None => true,
        })
        .map(to_result_body)
        .collect();
    info!(channel, caller = %auth.did, count = entries.len(), "ACL listed");
    Ok(ListAclResultBody { entries })
}

pub async fn update_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    params: UpdateAclParams,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    // Modifying an ACL entry can downgrade an existing admin's role or
    // shrink their `allowed_contexts`. That's a privilege-tamper surface
    // — narrow it to Admin callers (creation still accepts Initiator via
    // `require_manage` so operators can grant Reader/Application access).
    auth.require_admin()?;

    let mut entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    if let Some(ref role) = params.role {
        validate_role_assignment(auth, role)?;
        entry.role = role.clone();
    }
    if let Some(label) = params.label {
        entry.label = Some(label);
    }
    if let Some(approver) = params.step_up_approver {
        entry.step_up_approver = Some(approver);
    }
    if let Some(require) = params.step_up_require {
        // Empty string clears the override; otherwise parse + validate.
        entry.step_up_require = if require.trim().is_empty() {
            None
        } else {
            parse_step_up_require(Some(&require))?
        };
    }
    if let Some(allowed_contexts) = params.allowed_contexts {
        // Validate the *symmetric difference* of (old, new), not just
        // the new set. A ctx-A-admin updating an entry whose existing
        // `allowed_contexts` is `[ctx-A, ctx-B]` would otherwise be
        // allowed to PATCH it down to `[ctx-A]` — silently evicting
        // the target from ctx-B, which the caller has no admin over.
        // Validating only the new set treats removal as a free
        // operation; symmetric difference forces every context being
        // added *or* removed to be in caller scope. Super admins
        // short-circuit inside `validate_acl_modification`, so they
        // remain unaffected.
        let changes = symmetric_difference_contexts(&entry.allowed_contexts, &allowed_contexts);
        if !changes.is_empty() {
            // Validate the *changes* against caller scope. The
            // empty-target carve-out in `validate_acl_modification`
            // (which forbids non-super-admins from creating
            // unrestricted entries) doesn't apply here — we're
            // validating a delta, not a final shape — so call
            // `require_context` directly per changed context.
            if !auth.is_super_admin() {
                for ctx in &changes {
                    auth.require_context(ctx)?;
                }
            }
        }
        // Also keep the original full-shape check so the
        // empty-`allowed_contexts` super-admin-only invariant is
        // preserved on the *resulting* entry (a context admin can't
        // produce an unrestricted entry by edit any more than by
        // create).
        validate_acl_modification(auth, &allowed_contexts)?;
        // Validate only the *added* contexts. Removals are fine
        // (they only narrow scope); pre-existing contexts were
        // already validated at their original insertion point and
        // re-checking them would cause spurious failures if the
        // contexts keyspace evolved underneath in some other path.
        let old_set: std::collections::HashSet<&str> =
            entry.allowed_contexts.iter().map(String::as_str).collect();
        let added: Vec<String> = allowed_contexts
            .iter()
            .filter(|c| !old_set.contains(c.as_str()))
            .cloned()
            .collect();
        require_contexts_exist(contexts_ks, &added).await?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, did = %did, "ACL entry updated");
    audit!(
        "acl.update",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.update",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(to_result_body(&entry))
}

pub async fn delete_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<DeleteAclResultBody, AppError> {
    auth.require_manage()?;

    if auth.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    // Caller must be at least as privileged as the entry they are
    // deleting; otherwise an Initiator whose `allowed_contexts`
    // overlaps an Admin entry could remove that Admin. `update_acl`
    // is already protected by `require_admin()` at its top so this
    // shape concern is exclusive to the delete path. Visibility
    // alone is not sufficient — a context-admin / Initiator may
    // legitimately *see* an Admin ACL entry without being allowed
    // to mutate it.
    validate_role_assignment(auth, &entry.role)?;

    delete_acl_entry(acl_ks, did).await?;

    info!(channel, caller = %auth.did, did = %did, "ACL entry deleted");
    audit!(
        "acl.delete",
        actor = &auth.did,
        resource = did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.delete",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(DeleteAclResultBody {
        did: did.to_string(),
        deleted: true,
    })
}

/// Atomic self-service key rotation. The authenticated caller (`auth.did` =
/// the "old" DID) presents a VP-JWT proving control of a "new" DID; we verify
/// it, then move the caller's ACL entry (same role + contexts) onto the new
/// DID and delete the old one.
///
/// Self-service by design: no `require_manage()` — the caller only moves their
/// *own* authorization to a new key, copying the existing role/contexts, so
/// there's no privilege escalation. The new DID is proven (VP-JWT) rather than
/// asserted, and the audience is bound to this VTA. Ordering is create-new →
/// delete-old, so a failure after the first write leaves the old DID valid
/// (never a lockout).
#[allow(clippy::too_many_arguments)]
pub async fn swap_acl(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    presentation: &str,
    did_resolver: &DIDCacheClient,
    vta_did: &str,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    // Resolve the *claimed* new DID so we can verify the proof was made by a
    // key in its document. The claim is untrusted until `verify` succeeds.
    let pres = AclSwapPresentation::new(presentation);
    let claimed = pres
        .peek_holder()
        .map_err(|e| AppError::Authentication(format!("swap presentation: {e}")))?;
    let resolved = did_resolver
        .resolve(&claimed)
        .await
        .map_err(|e| AppError::Validation(format!("resolve new DID {claimed}: {e}")))?;
    let doc = serde_json::to_value(&resolved.doc)?;

    let now = now_epoch();
    let verified = pres
        .verify(&doc, vta_did, now)
        .map_err(|e| AppError::Authentication(format!("swap presentation: {e}")))?;
    let new_did = verified.holder().to_string();

    if new_did == auth.did {
        return Err(AppError::Conflict(
            "new DID equals current DID; nothing to swap".into(),
        ));
    }

    // The caller's own entry is what gets moved.
    let old = get_acl_entry(acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no ACL entry for caller: {}", auth.did)))?;
    if get_acl_entry(acl_ks, &new_did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {new_did}"
        )));
    }

    // DO NOT inherit `expires_at` from the ephemeral. The swap
    // expresses the operator's intent to hand off authority to the
    // long-term DID — preserving the ephemeral's TTL would silently
    // expire the long-term entry on the same clock (typically 1 h,
    // since onboarding scripts set --expires 1h on the ephemeral by
    // design). The acl_sweeper would then physically delete the
    // long-term entry an hour later, and /auth/challenge would
    // start returning "DID not in ACL" with no audit-log trace of
    // the create→swap→sweep chain. Operators who genuinely want a
    // time-limited long-term entry can `acl change-role --expires
    // …` afterwards. See PR fixing this and the parallel
    // acl_sweeper change that audit-logs every deletion.
    let entry = AclEntry::new(new_did.clone(), old.role.clone(), auth.did.clone())
        .with_label(old.label.clone())
        .with_contexts(old.allowed_contexts.clone())
        .with_created_at(now)
        .with_kind(old.kind.clone())
        .with_capabilities(old.capabilities.clone())
        .with_device(old.device.clone());

    // Create new before deleting old: a crash between the two leaves the old
    // DID authoritative (stale, not locked out).
    store_acl_entry(acl_ks, &entry).await?;
    delete_acl_entry(acl_ks, &auth.did).await?;

    info!(
        channel,
        old = %auth.did,
        new = %new_did,
        role = %entry.role,
        old_expires_at = ?old.expires_at,
        new_expires_at = ?entry.expires_at,
        "ACL entry swapped; long-term entry is permanent (ephemeral TTL not inherited)"
    );
    audit!(
        "acl.swap",
        actor = &auth.did,
        resource = &new_did,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "acl.swap",
        &auth.did,
        Some(&new_did),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(to_result_body(&entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, store_acl_entry};
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    async fn fresh_store() -> (
        Store,
        KeyspaceHandle,
        KeyspaceHandle,
        KeyspaceHandle,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        (store, acl_ks, audit_ks, contexts_ks, dir)
    }

    /// Seed `ContextRecord`s for the given ids so `require_contexts_exist`
    /// has something to find. Index/base_path are arbitrary — the
    /// existence check only looks at presence.
    async fn seed_contexts(contexts_ks: &KeyspaceHandle, ids: &[&str]) {
        use crate::contexts::{ContextRecord, store_context};
        use chrono::Utc;
        for (i, id) in ids.iter().enumerate() {
            let now = Utc::now();
            store_context(
                contexts_ks,
                &ContextRecord {
                    id: (*id).into(),
                    name: (*id).into(),
                    did: None,
                    description: None,
                    parent: None,
                    base_path: format!("m/26'/2'/{i}'"),
                    index: i as u32,
                    created_at: now,
                    updated_at: now,
                    context_policy: None,
                },
            )
            .await
            .unwrap();
        }
    }

    fn ctx_admin(did: &str, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    async fn seed_target(acl_ks: &KeyspaceHandle, did: &str, contexts: &[&str]) {
        store_acl_entry(
            acl_ks,
            &AclEntry::new(did, Role::Admin, "seed")
                .with_contexts(contexts.iter().map(|s| s.to_string()).collect()),
        )
        .await
        .unwrap();
    }

    #[test]
    fn parse_step_up_require_accepts_self_and_delegated_only() {
        assert_eq!(parse_step_up_require(None).unwrap(), None);
        assert_eq!(parse_step_up_require(Some("")).unwrap(), None);
        assert_eq!(parse_step_up_require(Some("  ")).unwrap(), None);
        assert_eq!(
            parse_step_up_require(Some("self")).unwrap(),
            Some(StepUpMode::SelfApprove)
        );
        assert_eq!(
            parse_step_up_require(Some("delegated")).unwrap(),
            Some(StepUpMode::Delegated)
        );
        // `delegated-any` / `none` / junk are not valid per-entry overrides.
        assert!(parse_step_up_require(Some("delegated-any")).is_err());
        assert!(parse_step_up_require(Some("none")).is_err());
        assert!(parse_step_up_require(Some("nope")).is_err());
    }

    #[test]
    fn step_up_require_round_trips_to_wire() {
        assert_eq!(step_up_require_to_wire(None), None);
        assert_eq!(
            step_up_require_to_wire(Some(StepUpMode::SelfApprove)).as_deref(),
            Some("self")
        );
        assert_eq!(
            step_up_require_to_wire(Some(StepUpMode::Delegated)).as_deref(),
            Some("delegated")
        );
    }

    #[test]
    fn symmetric_difference_handles_typical_cases() {
        let s = symmetric_difference_contexts(&["a".into(), "b".into()], &["a".into(), "c".into()]);
        let mut s = s;
        s.sort();
        assert_eq!(s, vec!["b".to_string(), "c".to_string()]);

        // Identity: empty diff.
        assert!(
            symmetric_difference_contexts(&["a".into(), "b".into()], &["b".into(), "a".into()])
                .is_empty()
        );

        // All adds, no removes.
        let s = symmetric_difference_contexts(&[], &["x".into()]);
        assert_eq!(s, vec!["x".to_string()]);

        // All removes, no adds.
        let s = symmetric_difference_contexts(&["x".into()], &[]);
        assert_eq!(s, vec!["x".to_string()]);
    }

    #[test]
    fn to_result_body_echoes_approve_scope() {
        let base = AclEntry::new("did:key:zA", Role::Reader, "did:key:zC");

        let scoped = base
            .clone()
            .with_approve_scope(ApproveScope::Contexts(vec!["openvtc".into()]));
        let body = to_result_body(&scoped);
        assert!(!body.approve_all_contexts);
        assert_eq!(body.approve_contexts, vec!["openvtc"]);

        let all = base.clone().with_approve_scope(ApproveScope::All);
        let body = to_result_body(&all);
        assert!(body.approve_all_contexts);
        assert!(body.approve_contexts.is_empty());

        // The default (a non-approver entry) echoes nothing.
        let body = to_result_body(&base);
        assert!(!body.approve_all_contexts);
        assert!(body.approve_contexts.is_empty());
    }

    /// Regression test for the eviction-via-shrink bug.
    ///
    /// A context-A admin must NOT be able to PATCH a target whose
    /// existing scope is `[ctx-A, ctx-B]` down to `[ctx-A]` — that
    /// removes the target from ctx-B silently, even though the caller
    /// has no admin rights over ctx-B. Pre-fix `update_acl` accepted
    /// this because it only validated the *new* set against caller
    /// scope; the new symmetric-diff check rejects it.
    #[tokio::test]
    async fn update_acl_rejects_shrink_across_caller_scope() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zTarget";
        seed_target(&acl_ks, target, &["ctx-a", "ctx-b"]).await;

        let caller = ctx_admin("did:key:zCallerA", &["ctx-a"]);
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                step_up_approver: None,
                step_up_require: None,
                allowed_contexts: Some(vec!["ctx-a".into()]),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// A context-admin shrinking *within their own scope* must still
    /// succeed — e.g. ctx-A-admin removing ctx-A from a target that
    /// has both ctx-A and ctx-B is the natural "I'm done with this
    /// integration in my context" operation, and the admin of ctx-B
    /// retains their independent grant.
    #[tokio::test]
    async fn update_acl_allows_remove_within_caller_scope() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zTarget2";
        seed_target(&acl_ks, target, &["ctx-a", "ctx-b"]).await;

        // Caller admins both ctx-a and ctx-b → the symmetric diff
        // (just `ctx-b`) is in scope, so the shrink is allowed.
        let caller = ctx_admin("did:key:zCallerAB", &["ctx-a", "ctx-b"]);
        let body = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                step_up_approver: None,
                step_up_require: None,
                allowed_contexts: Some(vec!["ctx-a".into()]),
            },
            "test",
        )
        .await
        .unwrap();
        assert_eq!(body.allowed_contexts, vec!["ctx-a".to_string()]);
    }

    /// Adding a new context the caller doesn't admin is also rejected
    /// (this case the pre-fix code already caught via the full-shape
    /// `validate_acl_modification` call — pin it so the symmetric-diff
    /// refactor doesn't accidentally regress it).
    #[tokio::test]
    async fn update_acl_rejects_add_outside_caller_scope() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zTarget3";
        seed_target(&acl_ks, target, &["ctx-a"]).await;

        let caller = ctx_admin("did:key:zCallerA", &["ctx-a"]);
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                step_up_approver: None,
                step_up_require: None,
                allowed_contexts: Some(vec!["ctx-a".into(), "ctx-b".into()]),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// Regression test: creating an ACL entry referencing a context
    /// that doesn't exist in the contexts keyspace must be rejected.
    /// Before this guard, a super-admin's typo silently created a
    /// dangling grant that would spring into life if a context with
    /// that id was later registered.
    #[tokio::test]
    async fn create_acl_rejects_unknown_context() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-real"]).await;

        // Super-admin caller — privileged enough to pass the scope
        // checks, so the test pins the existence check specifically.
        let caller = AuthClaims {
            did: "did:key:zSuper".into(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let err = create_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            "did:key:zNewAdmin",
            Role::Admin,
            None,
            vec!["ctx-typo".into()],
            None,
            None,
            None,
            ApproveScope::None,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    /// Existing contexts in the contexts keyspace are accepted.
    #[tokio::test]
    async fn create_acl_accepts_known_context() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-real"]).await;

        let caller = AuthClaims {
            did: "did:key:zSuper".into(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let body = create_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            "did:key:zNewAdmin",
            Role::Admin,
            None,
            vec!["ctx-real".into()],
            None,
            None,
            None,
            ApproveScope::None,
            "test",
        )
        .await
        .unwrap();
        assert_eq!(body.allowed_contexts, vec!["ctx-real".to_string()]);
    }

    /// Regression test: an Initiator whose `allowed_contexts` overlaps
    /// an Admin ACL entry must not be able to delete that entry. Pre-fix
    /// `delete_acl` only checked `require_manage` (admits Initiator) and
    /// visibility — both of which the Initiator satisfies on a shared
    /// context — leaving the deletion unguarded. The new
    /// `validate_role_assignment(auth, &entry.role)` check rejects this.
    #[tokio::test]
    async fn delete_acl_rejects_initiator_deleting_admin() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-shared"]).await;

        let admin_target = "did:key:zAdminTarget";
        seed_target(&acl_ks, admin_target, &["ctx-shared"]).await;

        let caller = AuthClaims {
            did: "did:key:zInitiator".into(),
            role: Role::Initiator,
            allowed_contexts: vec!["ctx-shared".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let err = delete_acl(&acl_ks, &audit_ks, &caller, admin_target, "test")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }

    /// Sanity check: an Admin caller can still delete an Admin entry —
    /// the new role-floor check refuses lower-priv callers, not peers.
    #[tokio::test]
    async fn delete_acl_admin_can_delete_admin_entry() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-shared"]).await;

        let admin_target = "did:key:zAdminTarget2";
        seed_target(&acl_ks, admin_target, &["ctx-shared"]).await;

        let caller = ctx_admin("did:key:zCallerAdmin", &["ctx-shared"]);
        let body = delete_acl(&acl_ks, &audit_ks, &caller, admin_target, "test")
            .await
            .expect("admin-on-admin delete succeeds");
        assert_eq!(body.did, admin_target);
        assert!(body.deleted);
    }

    /// Updating an ACL entry to add a context that doesn't exist
    /// must be rejected. Same rationale as the create-side check —
    /// no path may produce a grant whose scope references an
    /// unregistered context.
    #[tokio::test]
    async fn update_acl_rejects_adding_unknown_context() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;
        let target = "did:key:zTargetUnknown";
        seed_target(&acl_ks, target, &["ctx-a"]).await;

        // Super-admin caller bypasses the scope checks so we
        // isolate the existence check.
        let caller = AuthClaims {
            did: "did:key:zSuper".into(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                step_up_approver: None,
                step_up_require: None,
                allowed_contexts: Some(vec!["ctx-a".into(), "ctx-ghost".into()]),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
