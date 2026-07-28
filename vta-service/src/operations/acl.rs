use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use tracing::info;

use crate::audit::{self, audit};
use vta_sdk::protocols::acl_management::{
    create::{CreateAclResponseBody, CreateAclResultBody},
    delete::DeleteAclResultBody,
    get::GetAclResultBody,
    list::ListAclResultBody,
    swap::AclSwapPresentation,
};

use crate::acl::{
    AclEntry, ApproveScope, ContextDirection, Role, acl_entry_matches_context, delete_acl_entry,
    get_acl_entry, is_acl_entry_auditable, is_acl_entry_visible, list_acl_entries, store_acl_entry,
    validate_acl_modification, validate_approve_scope_grant, validate_role_assignment,
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
    /// `Some` sets the approve scope to exactly that value; `None` leaves it
    /// unchanged.
    ///
    /// The patch-semantics question this settles: **clear is
    /// `Some(ApproveScope::None)`, not absence.** Reusing the wire enum rather
    /// than mirroring create's `approve_all_contexts: bool` +
    /// `approve_contexts: Vec<String>` pair is what makes that expressible —
    /// with two independent fields there is no way to distinguish "revoke this
    /// approver's authority" from "don't touch it", and revoking is the case
    /// that matters most.
    pub approve_scope: Option<ApproveScope>,
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

/// Whether this ACL entry can **confer** authority over `ctx` in a consented
/// delegation — either an explicit approve-scope covering it, or admin standing
/// over it. Set *membership* alone is deliberately not enough: being in an
/// approver set lets a holder *approve*, but conferring the authority the task
/// actually needs requires holding it. This is the single predicate behind both
/// the consent gate's fail-fast pre-check (is this task even satisfiable?) and
/// grant-time `compute_delegated_contexts` (did the actual approvers confer it?),
/// so the two can never diverge.
pub(crate) fn acl_entry_can_confer(entry: &AclEntry, ctx: &str) -> bool {
    if entry.approve_scope.covers(ctx) {
        return true;
    }
    let claims = AuthClaims {
        did: entry.did.clone(),
        role: entry.role.clone(),
        allowed_contexts: entry.allowed_contexts.clone(),
        ..Default::default()
    };
    claims.role == Role::Admin && claims.has_context_access(ctx)
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

/// Error for a mutation the caller may not perform on `entry`.
///
/// Conflates to `NotFound` in the normal case — a caller who cannot see an
/// entry must not learn it exists by watching the error change. But an entry
/// that is *auditable* (it confers into a context the caller administers) is
/// already readable by this caller through `acl get` / `acl list`, so there is
/// nothing left to conceal, and "not found" would be a lie about a row they
/// can list. Those get a `Forbidden` naming why managing it is a different
/// question from seeing it.
fn not_manageable(auth: &AuthClaims, entry: &AclEntry, did: &str, verb: &str) -> AppError {
    if is_acl_entry_auditable(auth, entry) {
        AppError::Forbidden(format!(
            "{did} is visible to you because it may confer in a context you administer, \
             but it acts outside your contexts — only an admin of the contexts it acts in \
             can {verb} it"
        ))
    } else {
        AppError::NotFound(format!("ACL entry not found for DID: {did}"))
    }
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
    validate_acl_modification(auth, &role, &allowed_contexts)?;
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
    // Read path: an entry that can *confer* into a context the caller
    // administers is authority in that context, so its admin can audit it.
    if !is_acl_entry_auditable(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(channel, did = %did, "ACL entry retrieved");
    Ok(to_result_body(&entry))
}

/// List the ACL entries the caller may audit, optionally filtered to one
/// context.
///
/// `direction` says which way `context_filter` reads along the hierarchy;
/// it is inert without a context, and supplying one there is an error rather
/// than a silent no-op — a caller that asked for a subtree sweep and got the
/// unfiltered ACL back would believe it had swept.
pub async fn list_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_filter: Option<&str>,
    direction: ContextDirection,
    channel: &str,
) -> Result<Vec<CreateAclResultBody>, AppError> {
    auth.require_manage()?;

    if context_filter.is_none() && direction != ContextDirection::default() {
        return Err(AppError::Validation(format!(
            "`direction={direction}` filters a context and there is no context to filter — \
             pass a context as well, or drop the direction to list every visible entry"
        )));
    }

    let all_entries = list_acl_entries(acl_ks).await?;
    let entries: Vec<CreateAclResultBody> = all_entries
        .iter()
        .filter(|e| is_acl_entry_auditable(auth, e))
        // Shared with the offline `vta acl list` so the two surfaces cannot
        // answer the same question differently. The previous `contains()`
        // omitted super-admin entries, which do hold every context — an
        // operator auditing "who can reach context X" never saw them — and
        // missed entries scoped to an ancestor of X.
        //
        // The direction is what makes the question answerable at all: the
        // ancestor-or-self reading cannot express "what is granted beneath
        // this context", and a sweep asking that with this filter got back the
        // entries it was *not* revoking (#822).
        .filter(|e| match context_filter {
            Some(ctx) => acl_entry_matches_context(e, ctx, direction),
            None => true,
        })
        .map(to_result_body)
        .collect();
    info!(
        channel,
        caller = %auth.did,
        context = context_filter.unwrap_or("-"),
        direction = %direction,
        count = entries.len(),
        "ACL listed"
    );
    Ok(entries)
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
        return Err(not_manageable(auth, &entry, did, "update"));
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
        // Also keep the full-shape check so the *resulting* entry is one
        // the caller could have created directly: `entry.role` is the
        // post-patch role, so an admin+empty result stays super-admin-only
        // while a non-admin+empty (acts-nowhere) result is allowed — the same
        // rule as create.
        validate_acl_modification(auth, &entry.role, &allowed_contexts)?;
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

    if let Some(scope) = params.approve_scope {
        // The same grant check `create` applies, unchanged: `All` stays
        // super-admin-only and a scoped grant still requires the caller to hold
        // each context. Nothing about reaching this by update rather than by
        // create relaxes who may confer what.
        validate_approve_scope_grant(auth, &scope)?;
        // Contexts named in an approve scope must exist, as on create — a scope
        // naming a context that was never provisioned confers nothing and reads
        // as though it does.
        if let ApproveScope::Contexts(ref cs) = scope {
            require_contexts_exist(contexts_ks, cs).await?;
        }
        entry.approve_scope = scope;
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
) -> Result<(), AppError> {
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
        return Err(not_manageable(auth, &entry, did, "delete"));
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
    Ok(())
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

// ---------------------------------------------------------------------------
// Canonical `acl/*` adapters (#840 phase A)
// ---------------------------------------------------------------------------
//
// The functions above take the maintainer's internal argument shape and are
// unchanged by the fold; these adapt the canonical wire types onto them.
//
// Keeping the mapping in one place rather than in each transport's handler is
// deliberate: REST, DIDComm and the trust-task dispatcher all reach the same
// operation, and three copies of "which wire member becomes which argument" is
// three chances for them to disagree about, say, whether an absent `approve`
// confers nothing.

// Aliased: `AclEntry` is already the *stored* type in this module. The wire
// form and the stored form are deliberately different shapes, so keeping both
// names visible stops one being mistaken for the other.
use vta_sdk::protocols::acl_management::entry::{AclEntry as WireAclEntry, to_epoch};

/// `acl/grant/0.1` → [`create_acl`].
pub async fn grant_from_entry(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    entry: WireAclEntry,
    channel: &str,
) -> Result<CreateAclResponseBody, AppError> {
    let role = Role::parse(&entry.role)
        .map_err(|_| AppError::Validation(format!("invalid role: {}", entry.role)))?;
    let stored = create_acl(
        acl_ks,
        audit_ks,
        contexts_ks,
        auth,
        &entry.subject,
        role,
        entry.label.clone(),
        entry.scopes.clone(),
        entry.expires_at.map(to_epoch),
        entry.step_up_approver(),
        entry.step_up_require(),
        entry.approve_scope(),
        channel,
    )
    .await?;
    Ok(CreateAclResponseBody {
        entry: WireAclEntry::from_result(&stored),
    })
}

/// `acl/show/0.1` → [`get_acl`].
pub async fn show_by_subject(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    subject: &str,
    channel: &str,
) -> Result<GetAclResultBody, AppError> {
    let stored = get_acl(acl_ks, auth, subject, channel).await?;
    Ok(GetAclResultBody {
        entry: WireAclEntry::from_result(&stored),
        // Nothing is withheld from a caller already authorized to read the
        // entry, so the list is empty rather than absent — an explicit "we
        // redacted nothing" beats leaving the caller to infer it.
        redacted_fields: Vec::new(),
    })
}

/// `acl/list/0.1` → [`list_acl`].
pub async fn list_entries(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    scope: Option<&str>,
    direction: ContextDirection,
    channel: &str,
) -> Result<ListAclResultBody, AppError> {
    let stored = list_acl(acl_ks, auth, scope, direction, channel).await?;
    Ok(ListAclResultBody {
        entries: stored.iter().map(WireAclEntry::from_result).collect(),
        // This maintainer returns every matching entry in one response, so the
        // page is never partial. Saying so explicitly is the point of the
        // member: a caller must never have to infer completeness from length,
        // which is how a truncated revocation sweep reads as a finished one.
        truncated: false,
        cursor: None,
        redacted_fields: Vec::new(),
    })
}

/// `acl/update/0.1` → [`update_acl`].
pub async fn update_from_params(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    subject: &str,
    params: UpdateAclParams,
    channel: &str,
) -> Result<CreateAclResponseBody, AppError> {
    let stored = update_acl(
        acl_ks,
        audit_ks,
        contexts_ks,
        auth,
        subject,
        params,
        channel,
    )
    .await?;
    Ok(CreateAclResponseBody {
        entry: WireAclEntry::from_result(&stored),
    })
}

/// `acl/revoke/0.1` → [`delete_acl`].
///
/// Canonical revoke has a scope-reduction mode (`scopes` lists what to
/// withdraw, the entry survives). This maintainer implements full removal
/// only, and **refuses** a scoped request rather than treating it as a full
/// removal — silently taking the whole entry when the caller asked to withdraw
/// one scope removes far more authority than was requested, which is not a
/// direction to guess in.
pub async fn revoke_by_subject(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    subject: &str,
    scopes: Option<Vec<String>>,
    channel: &str,
) -> Result<DeleteAclResultBody, AppError> {
    if let Some(scopes) = scopes.filter(|s| !s.is_empty()) {
        return Err(AppError::Validation(format!(
            "scope reduction is not supported by this maintainer — `scopes` named {} entr{}, \
             but only full revocation is implemented. Omit `scopes` to remove the entry.",
            scopes.len(),
            if scopes.len() == 1 { "y" } else { "ies" }
        )));
    }
    // Read before removing so the response carries what was actually
    // withdrawn. Canonical revoke returns the entry, not a boolean: a bare
    // `deleted: true` cannot tell an auditor what authority was lost.
    let stored = get_acl(acl_ks, auth, subject, channel).await?;
    delete_acl(acl_ks, audit_ks, auth, subject, channel).await?;
    Ok(DeleteAclResultBody {
        entry: WireAclEntry::from_result(&stored),
    })
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

    /// Admin with no context restriction — `is_super_admin` is exactly that
    /// pair, which is the whole subject of #746.
    fn super_admin(did: &str) -> AuthClaims {
        ctx_admin(did, &[])
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

    // ── read/manage split ───────────────────────────────────────────

    /// Seed the escalation-shaped entry: it *administers* ctx-b while
    /// *conferring* into ctx-a. A ctx-a admin must be able to read it and must
    /// not be able to mutate it.
    async fn seed_foreign_admin_conferring_into(
        acl_ks: &KeyspaceHandle,
        did: &str,
        admins: &[&str],
        confers: &[&str],
    ) {
        store_acl_entry(
            acl_ks,
            &AclEntry::new(did, Role::Admin, "seed")
                .with_contexts(admins.iter().map(|s| s.to_string()).collect())
                .with_approve_scope(ApproveScope::Contexts(
                    confers.iter().map(|s| s.to_string()).collect(),
                )),
        )
        .await
        .unwrap();
    }

    /// The audit gap: a least-privilege approver conferring into the caller's
    /// context is now readable by that context's admin.
    #[tokio::test]
    async fn get_acl_surfaces_an_approver_conferring_into_callers_context() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;
        let target = "did:key:zApproverRead";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(target, Role::Reader, "seed")
                .with_approve_scope(ApproveScope::Contexts(vec!["ctx-a".into()])),
        )
        .await
        .unwrap();

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let body = get_acl(&acl_ks, &caller, target, "test")
            .await
            .expect("an approver in my context must be auditable");
        assert_eq!(body.did, target);
        let _ = (audit_ks, contexts_ks);
    }

    /// …and appears in the listing, which is where an operator actually audits.
    #[tokio::test]
    async fn list_acl_includes_an_approver_conferring_into_callers_context() {
        let (_store, acl_ks, _audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zApproverList", Role::Reader, "seed")
                .with_approve_scope(ApproveScope::All),
        )
        .await
        .unwrap();

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let body = list_acl(&acl_ks, &caller, None, ContextDirection::default(), "test")
            .await
            .unwrap();
        assert!(
            body.iter().any(|e| e.did == "did:key:zApproverList"),
            "an approve-all holder must be auditable by every context admin"
        );
    }

    // ── context-filter direction (#822) ─────────────────────────────

    /// Seed the layout the issue describes: a tenant unit with a
    /// per-purpose leaf per principal, plus a unit-wide admin above them.
    async fn seed_tenant_subtree(acl_ks: &KeyspaceHandle) {
        seed_target(acl_ks, "did:key:zUnitAdmin", &["acme/eng"]).await;
        seed_target(acl_ks, "did:key:zTenantAdmin", &["acme"]).await;
        seed_target(acl_ks, "did:key:zGateway", &["acme/eng/attestation"]).await;
        seed_target(acl_ks, "did:key:zSigner", &["acme/eng/signing"]).await;
        seed_target(acl_ks, "did:key:zOps", &["acme/ops/keys"]).await;
    }

    async fn dids_for(
        acl_ks: &KeyspaceHandle,
        caller: &AuthClaims,
        ctx: &str,
        direction: ContextDirection,
    ) -> Vec<String> {
        let body = list_acl(acl_ks, caller, Some(ctx), direction, "test")
            .await
            .unwrap();
        let mut dids: Vec<String> = body.into_iter().map(|e| e.did).collect();
        dids.sort();
        dids
    }

    /// The bug: sweeping `acme/eng` to revoke it returned the ancestors that
    /// keep their authority and none of the leaf grants the sweep exists to
    /// cut. Both directions are now askable, and they answer differently.
    #[tokio::test]
    async fn a_subtree_listing_returns_the_leaves_an_act_in_listing_omits() {
        let (_store, acl_ks, _audit_ks, _contexts_ks, _dir) = fresh_store().await;
        seed_tenant_subtree(&acl_ks).await;
        let caller = super_admin("did:key:zRoot");

        assert_eq!(
            dids_for(&acl_ks, &caller, "acme/eng", ContextDirection::ActingIn).await,
            ["did:key:zTenantAdmin", "did:key:zUnitAdmin"],
            "act-in: authority over the unit, which is not what a sweep revokes"
        );
        assert_eq!(
            dids_for(&acl_ks, &caller, "acme/eng", ContextDirection::Subtree).await,
            ["did:key:zGateway", "did:key:zSigner", "did:key:zUnitAdmin"],
            "subtree: every grant inside the unit, and nothing from acme/ops"
        );
        assert_eq!(
            dids_for(&acl_ks, &caller, "acme/eng", ContextDirection::Any).await,
            [
                "did:key:zGateway",
                "did:key:zSigner",
                "did:key:zTenantAdmin",
                "did:key:zUnitAdmin"
            ],
            "any: the union — the auditor's question"
        );
    }

    /// Absent parameter ⇒ pre-#822 behaviour, entry for entry.
    #[tokio::test]
    async fn the_default_direction_is_the_historical_filter() {
        let (_store, acl_ks, _audit_ks, _contexts_ks, _dir) = fresh_store().await;
        seed_tenant_subtree(&acl_ks).await;
        let caller = super_admin("did:key:zRoot");
        assert_eq!(
            dids_for(&acl_ks, &caller, "acme/eng", ContextDirection::default()).await,
            dids_for(&acl_ks, &caller, "acme/eng", ContextDirection::ActingIn).await,
        );
    }

    /// Visibility is applied before the filter in every direction — the new
    /// direction must not become a way to enumerate entries a context admin
    /// could not otherwise see.
    #[tokio::test]
    async fn a_subtree_listing_does_not_widen_what_a_context_admin_can_see() {
        let (_store, acl_ks, _audit_ks, _contexts_ks, _dir) = fresh_store().await;
        seed_tenant_subtree(&acl_ks).await;
        // Admin of a sibling unit only.
        let caller = ctx_admin("did:key:zOpsAdmin", &["acme/ops"]);
        for direction in ContextDirection::ALL {
            let dids = dids_for(&acl_ks, &caller, "acme/eng", direction).await;
            assert!(
                dids.is_empty(),
                "{direction} leaked acme/eng entries to an acme/ops admin: {dids:?}"
            );
        }
    }

    /// A direction with nothing to point at is refused rather than ignored:
    /// silently listing the whole ACL to a caller that asked to sweep a
    /// branch is the failure this issue is about, one level up.
    #[tokio::test]
    async fn a_direction_without_a_context_is_refused() {
        let (_store, acl_ks, _audit_ks, _contexts_ks, _dir) = fresh_store().await;
        seed_tenant_subtree(&acl_ks).await;
        let caller = super_admin("did:key:zRoot");

        let err = list_acl(&acl_ks, &caller, None, ContextDirection::Subtree, "test")
            .await
            .expect_err("a direction needs a context");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");

        list_acl(&acl_ks, &caller, None, ContextDirection::default(), "test")
            .await
            .expect("the default direction with no context is just an unfiltered list");
    }

    /// The escalation the split exists to prevent: reading an entry that
    /// confers into your context must not let you delete it when it
    /// administers someone else's.
    #[tokio::test]
    async fn delete_acl_refuses_an_entry_that_acts_outside_callers_contexts() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zForeignAdmin";
        seed_foreign_admin_conferring_into(&acl_ks, target, &["ctx-b"], &["ctx-a"]).await;

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        // Readable…
        get_acl(&acl_ks, &caller, target, "test")
            .await
            .expect("confers into ctx-a, so ctx-a's admin may read it");
        // …but not deletable, and the error says why rather than lying.
        let err = delete_acl(&acl_ks, &audit_ks, &caller, target, "test")
            .await
            .expect_err("ctx-a admin must not delete an entry that administers ctx-b");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden (the row is already readable), got {err:?}"
        );
    }

    /// An entry the caller cannot read at all still conflates to `NotFound` —
    /// the split must not turn the enumeration guard into an oracle.
    #[tokio::test]
    async fn delete_acl_still_conflates_a_wholly_invisible_entry_to_not_found() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zInvisible";
        seed_target(&acl_ks, target, &["ctx-b"]).await;

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let err = delete_acl(&acl_ks, &audit_ks, &caller, target, "test")
            .await
            .expect_err("not visible, not auditable");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound so existence is not disclosed, got {err:?}"
        );
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

    /// `acl_entry_can_confer` — the single predicate behind the consent gate's
    /// fail-fast and grant-time delegation. Locks in the exact production bug: an
    /// approver whose approve-scope is `[openvtc]` cannot confer `openvtc-glenn`,
    /// so a consent for a DID in `openvtc-glenn` completes but confers nothing and
    /// loops. `openvtc` is not an ancestor of `openvtc-glenn` — distinct segments.
    #[test]
    fn acl_entry_can_confer_matches_scope_and_admin_but_not_a_sibling_context() {
        // Approve-scope for `openvtc` covers `openvtc`, not the sibling `openvtc-glenn`.
        let scoped = AclEntry::new("did:key:zApprover", Role::Reader, "seed")
            .with_approve_scope(ApproveScope::Contexts(vec!["openvtc".into()]));
        assert!(acl_entry_can_confer(&scoped, "openvtc"));
        assert!(
            !acl_entry_can_confer(&scoped, "openvtc-glenn"),
            "approve-scope `openvtc` must NOT confer the distinct context `openvtc-glenn`"
        );

        // `ApproveScope::All` confers any context.
        let all = AclEntry::new("did:key:zAll", Role::Reader, "seed")
            .with_approve_scope(ApproveScope::All);
        assert!(acl_entry_can_confer(&all, "openvtc-glenn"));

        // A context admin confers via admin standing (no approve-scope needed).
        let ctx_admin = AclEntry::new("did:key:zAdmin", Role::Admin, "seed")
            .with_contexts(vec!["openvtc-glenn".into()]);
        assert!(acl_entry_can_confer(&ctx_admin, "openvtc-glenn"));
        assert!(!acl_entry_can_confer(&ctx_admin, "some-other-context"));

        // A super-admin (Admin + empty contexts) confers anywhere.
        let super_admin = AclEntry::new("did:key:zSuper", Role::Admin, "seed");
        assert!(acl_entry_can_confer(&super_admin, "openvtc-glenn"));

        // A plain reader with no approve-scope confers nothing — set membership
        // alone is not authority.
        let reader = AclEntry::new("did:key:zReader", Role::Reader, "seed");
        assert!(!acl_entry_can_confer(&reader, "openvtc-glenn"));
    }

    /// Regression test for the eviction-via-shrink bug.
    ///
    /// A context-A admin must NOT be able to PATCH a target whose
    /// existing scope is `[ctx-A, ctx-B]` down to `[ctx-A]` — that
    /// removes the target from ctx-B silently, even though the caller
    /// has no admin rights over ctx-B. Pre-fix `update_acl` accepted
    /// this because it only validated the *new* set against caller
    /// scope; the new symmetric-diff check rejects it.
    /// #744: before this, `approve_scope` was settable only at create time,
    /// so narrowing or revoking an approver meant delete-and-recreate — and a
    /// failed recreate leaves the DID with no ACL entry at all.
    #[tokio::test]
    async fn update_acl_sets_and_revokes_approve_scope() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zApprover";
        seed_target(&acl_ks, target, &["ctx-a"]).await;

        let admin = super_admin("did:key:zRoot");
        let set = |scope| UpdateAclParams {
            role: None,
            label: None,
            allowed_contexts: None,
            step_up_approver: None,
            step_up_require: None,
            approve_scope: Some(scope),
        };

        // Narrow: All -> a single context, without touching the entry.
        update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &admin,
            target,
            set(ApproveScope::All),
            "test",
        )
        .await
        .expect("super admin may grant approve-all");
        assert_eq!(
            get_acl_entry(&acl_ks, target)
                .await
                .unwrap()
                .unwrap()
                .approve_scope,
            ApproveScope::All
        );

        update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &admin,
            target,
            set(ApproveScope::Contexts(vec!["ctx-b".into()])),
            "test",
        )
        .await
        .expect("narrowing to a scoped grant");
        assert_eq!(
            get_acl_entry(&acl_ks, target)
                .await
                .unwrap()
                .unwrap()
                .approve_scope,
            ApproveScope::Contexts(vec!["ctx-b".into()])
        );

        // Revoke — the case that has to be expressible, and is `Some(None)`
        // rather than absence.
        update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &admin,
            target,
            set(ApproveScope::None),
            "test",
        )
        .await
        .expect("revoking confers nothing");
        assert_eq!(
            get_acl_entry(&acl_ks, target)
                .await
                .unwrap()
                .unwrap()
                .approve_scope,
            ApproveScope::None
        );
    }

    /// Omitting the field leaves the existing scope alone — the distinction
    /// that made a flat bool/list pair unusable for this.
    #[tokio::test]
    async fn update_acl_leaves_approve_scope_alone_when_absent() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;
        let target = "did:key:zApprover";
        seed_target(&acl_ks, target, &["ctx-a"]).await;
        let admin = super_admin("did:key:zRoot");

        update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &admin,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: Some(ApproveScope::All),
            },
            "test",
        )
        .await
        .unwrap();

        // A label-only edit must not disturb the scope.
        update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &admin,
            target,
            UpdateAclParams {
                role: None,
                label: Some("renamed".into()),
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: None,
            },
            "test",
        )
        .await
        .unwrap();

        let entry = get_acl_entry(&acl_ks, target).await.unwrap().unwrap();
        assert_eq!(entry.label.as_deref(), Some("renamed"));
        assert_eq!(
            entry.approve_scope,
            ApproveScope::All,
            "scope must survive an unrelated edit"
        );
    }

    /// The grant check is the same one `create` applies — reaching it by
    /// update does not relax who may confer what.
    #[tokio::test]
    async fn update_acl_applies_the_same_approve_grant_check_as_create() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;
        let target = "did:key:zApprover";
        seed_target(&acl_ks, target, &["ctx-a"]).await;

        let ctx_admin_a = ctx_admin("did:key:zCallerA", &["ctx-a"]);
        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &ctx_admin_a,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: Some(ApproveScope::All),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "approve-all is super-admin only: {err:?}"
        );

        let err = update_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &ctx_admin_a,
            target,
            UpdateAclParams {
                role: None,
                label: None,
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: Some(ApproveScope::Contexts(vec!["ctx-b".into()])),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "cannot confer a context it lacks: {err:?}"
        );
    }

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
                approve_scope: None,
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
                approve_scope: None,
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
                approve_scope: None,
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

    /// The acts-nowhere widening, end to end: a context admin can now mint a
    /// least-privilege approver for its own context — a reader that acts
    /// nowhere and confers `ctx-a` via `approve_scope`. Both privilege gates
    /// pass: the act scope is `None` (grants nothing to act), and the approve
    /// scope names only a context the caller administers.
    #[tokio::test]
    async fn context_admin_can_mint_a_least_privilege_approver() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let body = create_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            "did:key:zApprover",
            Role::Reader,
            None,
            Vec::new(), // acts nowhere
            None,
            None,
            None,
            ApproveScope::Contexts(vec!["ctx-a".into()]),
            "test",
        )
        .await
        .expect("a context admin may create a least-privilege approver for its own context");
        assert!(
            body.allowed_contexts.is_empty(),
            "the approver acts nowhere"
        );
        assert!(body.approve_contexts.contains(&"ctx-a".to_string()));
    }

    /// …but the conferral half is still gated: the same caller cannot mint an
    /// approver for a context it does not administer.
    #[tokio::test]
    async fn context_admin_cannot_confer_a_foreign_context_via_the_approver() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a", "ctx-b"]).await;

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let err = create_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            "did:key:zApprover",
            Role::Reader,
            None,
            Vec::new(),
            None,
            None,
            None,
            ApproveScope::Contexts(vec!["ctx-b".into()]),
            "test",
        )
        .await
        .expect_err("conferring ctx-b requires administering it");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// …and the unrestricted case stays closed: a context admin still cannot
    /// create an admin with no contexts (a super-admin).
    #[tokio::test]
    async fn context_admin_still_cannot_mint_a_super_admin() {
        let (_store, acl_ks, audit_ks, contexts_ks, _dir) = fresh_store().await;
        seed_contexts(&contexts_ks, &["ctx-a"]).await;

        let caller = ctx_admin("did:key:zCtxAdminA", &["ctx-a"]);
        let err = create_acl(
            &acl_ks,
            &audit_ks,
            &contexts_ks,
            &caller,
            "did:key:zWouldBeSuper",
            Role::Admin,
            None,
            Vec::new(), // admin + empty = super-admin
            None,
            None,
            None,
            ApproveScope::None,
            "test",
        )
        .await
        .expect_err("a context admin must not mint a super-admin");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
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
        // `delete_acl` is the internal removal; the canonical response body is
        // built by `revoke_by_subject`, which reads the entry first so the
        // caller learns what was withdrawn.
        delete_acl(&acl_ks, &audit_ks, &caller, admin_target, "test")
            .await
            .expect("admin-on-admin delete succeeds");
        assert!(
            get_acl_entry(&acl_ks, admin_target)
                .await
                .unwrap()
                .is_none(),
            "the entry is gone after a delete"
        );
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
                approve_scope: None,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
