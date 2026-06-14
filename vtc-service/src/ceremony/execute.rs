//! The Effects executor — apply an [`EffectPlan`] against `AppState`
//! (ceremony-pipeline design §5, the "apply" half of the effect
//! stage).
//!
//! [`super::effects::plan`] produced a typed *intent*; this is where
//! that intent becomes state. It is the **only** stage that mutates
//! community state, and it is driven solely by the verdict-derived
//! plan. The pure decision spine (verify → evaluate → invariant →
//! decide → plan) is all testable without I/O; this module is the
//! single I/O seam.
//!
//! ## Single entry point, shared by the bespoke flow
//!
//! [`apply`] is the one executor. The MVP's manual join-approve route
//! ([`crate::routes::join_requests::decide::approve`]) is refactored
//! to go through it too — it builds an [`EffectPlan::Admit`] and calls
//! [`apply`], so the pipeline genuinely supersedes the bespoke write
//! path rather than duplicating it. The approve route's integration
//! tests therefore exercise the [`EffectPlan::Admit`] arm end-to-end.
//!
//! ## What's wired
//!
//! - **Admit** (join) — write the ACL row + Member record, issue the
//!   VMC + role VEC, flip the status-list slot. Fully wired; the
//!   manual approve route goes through it.
//! - **Depart** (leave) — enforce the no-last-admin invariant, delete
//!   the ACL row, apply the disposition to the Member row, and revoke
//!   the credential (flip the revocation bit). Fully wired; the
//!   `DELETE /v1/members/{me,did}` removal routes go through it.
//! - **Remint** (role-change) — change the ACL role in place + re-mint
//!   the role VEC, enforcing no-last-admin on demotion. Fully wired;
//!   the `PATCH /v1/members/{did}` role change goes through it.
//! - **NoStateChange** (deny / refer / request_more) — no-op.
//! - **Project** (directory) — not handled here: the directory route
//!   serializes the projection into its HTTP response inline, so a
//!   `Project` plan reaching the executor is a caller bug.

use std::sync::LazyLock;

use affinidi_status_list::StatusPurpose;
use affinidi_vc::VerifiableCredential;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use vti_common::error::AppError;

use super::effects::EffectPlan;
use crate::acl::{
    VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::auth::session::now_epoch;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::members::{Disposition, Member, delete_member, get_member, store_member};
use crate::server::AppState;
use crate::status_list;

/// Process-wide mutex serialising member-state mutations — admit,
/// depart, and role-change — so each check-then-write is one atomic
/// critical section. Departures can't both pass the "would this leave
/// zero admins?" check and both delete; admits can't both pass the
/// "no existing ACL row" check and both mint a VMC + burn a status-list
/// slot (P0.15). (fjall isn't multi-process safe regardless, so a
/// process-wide lock is the right grain.)
static LAST_ADMIN_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// What the executor did. Carries back whatever the caller needs to
/// audit + respond — currently the credentials minted on admit.
#[derive(Debug)]
pub enum EffectOutcome {
    /// A member was admitted; carries the issued credentials so the
    /// caller can audit them and hand them to the applicant. Boxed —
    /// the two VCs make this variant far larger than the others.
    Admitted(Box<AdmitOutcome>),
    /// A member departed; carries the applied disposition + the
    /// revocation slot that was flipped (for the caller's audit).
    Departed(DepartOutcome),
    /// A member's role was changed in place; carries the previous role
    /// + the re-minted role VEC. Boxed — the VC makes it large.
    Reminted(Box<RemintOutcome>),
    /// No state was changed (the verdict was deny / refer /
    /// request_more).
    None,
}

/// The credentials minted when a member is admitted.
#[derive(Debug)]
pub struct AdmitOutcome {
    pub vmc: VerifiableCredential,
    pub role_vec: VerifiableCredential,
    pub status_list_index: u32,
}

/// The result of an in-place role change.
#[derive(Debug)]
pub struct RemintOutcome {
    /// The role the subject held before the change (for the caller's
    /// `RoleChanged` audit).
    pub previous_role: VtcRole,
    /// The role VEC re-minted at the new role. The DID + VMC are
    /// unchanged; only the role assertion is re-issued.
    pub role_vec: VerifiableCredential,
}

/// The result of a member departure.
#[derive(Debug)]
pub struct DepartOutcome {
    /// The disposition that was applied to the Member row (resolved to
    /// a concrete value — never `PolicyDefault`).
    pub disposition: Disposition,
    /// The revocation status-list slot that was flipped, if the member
    /// held one and the flip succeeded. `None` if there was no slot or
    /// the best-effort flip failed (the ACL/Member removal still
    /// committed — a failed flip is logged, not unwound).
    pub revoked_slot: Option<u32>,
}

/// Apply an effect plan.
///
/// `actor_did` is the authenticated initiator (the admin on the manual
/// approve path, the relayer/holder on a ceremony path) — recorded as
/// the ACL row's `created_by`. The caller owns audit + the HTTP
/// response; this function owns the writes.
pub async fn apply(
    state: &AppState,
    plan: EffectPlan,
    actor_did: &str,
) -> Result<EffectOutcome, AppError> {
    match plan {
        EffectPlan::Admit {
            subject,
            role,
            // Obligations (e.g. `reciprocate_vmc` to form the
            // bidirectional membership edge) are not yet discharged —
            // the reciprocal-VMC handshake lands with the join
            // ceremony route.
            obligations: _,
        } => {
            let role = parse_role(&role)?;
            let outcome = admit(state, &subject, role, actor_did).await?;
            Ok(EffectOutcome::Admitted(Box::new(outcome)))
        }
        EffectPlan::Depart {
            subject,
            disposition,
        } => {
            let disposition = parse_disposition(disposition.as_deref());
            let outcome = depart(state, &subject, disposition, actor_did).await?;
            Ok(EffectOutcome::Departed(outcome))
        }
        EffectPlan::Remint { subject, role } => {
            let role = parse_role(&role)?;
            let outcome = remint(state, &subject, role).await?;
            Ok(EffectOutcome::Reminted(Box::new(outcome)))
        }
        EffectPlan::NoStateChange => Ok(EffectOutcome::None),
        EffectPlan::Project { .. } => Err(AppError::Internal(
            "directory projection is applied by the route, not the effect executor".into(),
        )),
    }
}

/// Parse the policy-granted role string into a [`VtcRole`]. The
/// privilege ceiling already rejected an `admin` grant on join before
/// the plan was built, so this is the final wire-form parse.
fn parse_role(role: &str) -> Result<VtcRole, AppError> {
    role.parse::<VtcRole>()
        .map_err(|_| AppError::Validation(format!("effect plan carries an unknown role: {role}")))
}

/// Admit a DID as a member: write the ACL row + Member record, issue
/// the VMC + role VEC, flip the status-list slot.
///
/// Writes the ACL first (the auth-gating truth), then the Member row,
/// then issues credentials and stamps their ids back onto the member.
/// A failure partway leaves the safer state (auth path works; metadata
/// reconcilable by the next admin action).
///
/// The existence check + writes run under [`LAST_ADMIN_LOCK`], matching
/// `depart`/`remint` — without it two concurrent admits for the same DID
/// (two approved `Pending`s, or a submit auto-admit racing an approve)
/// both observe "no ACL row" and both proceed, minting two VMCs and
/// burning two status-list slots (P0.15). With the lock, the loser sees
/// the row the winner wrote and gets a `Conflict`.
async fn admit(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
    actor_did: &str,
) -> Result<AdmitOutcome, AppError> {
    let _guard = LAST_ADMIN_LOCK.lock().await;

    if get_acl_entry(&state.acl_ks, subject_did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "{subject_did} already has an ACL row; refusing to admit a duplicate membership"
        )));
    }

    let acl = VtcAclEntry {
        did: subject_did.to_string(),
        role: role.clone(),
        label: None,
        allowed_contexts: vec![],
        created_at: now_epoch(),
        created_by: actor_did.to_string(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &acl).await?;

    let mut member = Member::fresh(subject_did);
    store_member(&state.members_ks, &member).await?;

    let (vmc, role_vec, status_list_index) =
        issue_member_credentials(state, subject_did, role).await?;
    member.status_list_index = Some(status_list_index);
    member.current_vmc_id = top_level_id(&vmc);
    member.current_role_vec_id = top_level_id(&role_vec);
    store_member(&state.members_ks, &member).await?;

    // A new member row exists; keep the cached count in step (still under
    // LAST_ADMIN_LOCK, so it's serialised with the duplicate-admit guard).
    state.member_count_inc();

    Ok(AdmitOutcome {
        vmc,
        role_vec,
        status_list_index,
    })
}

/// Allocate a revocation-list slot, mint the VMC + role VEC at `role`,
/// persist the updated status-list state. Returns the signed VCs + the
/// allocated index.
///
/// The status-list state is stored only *after* both VCs build
/// successfully, so a build failure doesn't permanently burn a slot.
async fn issue_member_credentials(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
) -> Result<(VerifiableCredential, VerifiableCredential, u32), AppError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot mint VMC (run setup first)".into(),
        )
    })?;

    // Hold the status-list write lock across the whole allocate → build →
    // store sequence (P0.1). The raw guard (not `with_locked`) is needed
    // because the VMC/VEC build sits between the allocate and the store —
    // see the doc comment above: the row is persisted only after both VCs
    // build, so a build failure doesn't burn the slot. The guard keeps a
    // concurrent writer from clobbering this allocation in that window.
    let _sl_guard = status_list::lock().await;
    let mut row = status_list::get_state(&state.status_lists_ks, StatusPurpose::Revocation)
        .await?
        .ok_or_else(|| {
            AppError::Internal(
                "revocation status list not provisioned — set `public_url` + restart".into(),
            )
        })?;

    let slot = status_list::allocate(&mut row).ok_or_else(|| {
        AppError::Internal(format!(
            "revocation status list exhausted (capacity = {})",
            row.capacity
        ))
    })?;

    let status_ref = CredentialStatusRef::revocation(row.list_credential_id.clone(), slot);

    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(subject_did)
            .with_id(vmc_id)
            .with_status_ref(status_ref)
            .with_personhood(false),
    )
    .await?;

    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(subject_did, role).with_id(vec_id),
    )
    .await?;

    // Issue-time schema validation: if the operator registered a credentialSchema
    // for these catalog types, the minted credentials must conform before the
    // slot is committed. No-op when no schema is registered (seeded defaults
    // carry none), so this is inert until an operator opts in.
    let to_value = |vc| {
        serde_json::to_value(vc)
            .map_err(|e| AppError::Internal(format!("credential -> value: {e}")))
    };
    crate::schemas::validate_issued(&state.schemas_ks, &to_value(&vmc)?).await?;
    crate::schemas::validate_issued(&state.schemas_ks, &to_value(&role_vec)?).await?;

    status_list::store_state(&state.status_lists_ks, &row).await?;
    status_list::maybe_emit_occupancy_warning(&row);

    Ok((vmc, role_vec, slot))
}

/// Change a member's role in place: update the ACL row and re-mint the
/// role VEC at the new role. The DID + VMC are unchanged.
///
/// Enforces the no-last-admin invariant on **demotion** (an admin
/// being changed to a non-admin role) — host-enforced under
/// [`LAST_ADMIN_LOCK`], so a demotion that would leave zero admins is
/// refused (`Conflict` → 409) before any write. The privilege ceiling
/// / step-up-for-admin invariant is enforced earlier, in
/// [`super::invariant::enforce`], before the plan is built.
async fn remint(
    state: &AppState,
    subject_did: &str,
    new_role: VtcRole,
) -> Result<RemintOutcome, AppError> {
    let _guard = LAST_ADMIN_LOCK.lock().await;

    let mut acl = get_acl_entry(&state.acl_ks, subject_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {subject_did}")))?;
    let previous_role = acl.role.clone();

    // No-last-admin on demotion: refuse to demote the community's only
    // admin (the inverse of the leave guard).
    if matches!(previous_role, VtcRole::Admin) && !matches!(new_role, VtcRole::Admin) {
        let other_admins = list_acl_entries(&state.acl_ks)
            .await?
            .iter()
            .filter(|e| e.did != subject_did && matches!(e.role, VtcRole::Admin))
            .count();
        if other_admins == 0 {
            return Err(AppError::Conflict(format!(
                "refusing to demote the last admin ({subject_did}) — promote another \
                 member to admin first"
            )));
        }
    }

    acl.role = new_role.clone();
    store_acl_entry(&state.acl_ks, &acl).await?;

    // Re-mint the role VEC at the new role + repoint the member.
    let role_vec = issue_role_vec(state, subject_did, new_role).await?;
    if let Some(mut member) = get_member(&state.members_ks, subject_did).await? {
        member.current_role_vec_id = top_level_id(&role_vec);
        store_member(&state.members_ks, &member).await?;
    }

    Ok(RemintOutcome {
        previous_role,
        role_vec,
    })
}

/// Mint a role VEC at `role` for `subject_did`. Used by role-change to
/// re-issue the role assertion; the VMC + status list are untouched.
async fn issue_role_vec(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
) -> Result<VerifiableCredential, AppError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot re-mint role VEC (run setup first)".into(),
        )
    })?;
    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    build_role_vec(
        signer,
        RoleVecParams::new(subject_did, role).with_id(vec_id),
    )
    .await
}

/// Parse the plan's disposition string into a concrete
/// [`Disposition`]. An absent or unrecognized disposition (and
/// `policydefault`) falls back to [`Disposition::Tombstone`] — the
/// safe middle ground. The caller's decide stage is expected to have
/// already resolved `PolicyDefault` against the policy; this is the
/// final, never-`PolicyDefault` value the effect applies.
fn parse_disposition(disposition: Option<&str>) -> Disposition {
    match disposition {
        Some("purge") => Disposition::Purge,
        Some("historical") => Disposition::Historical,
        // tombstone / policydefault / unknown / absent → tombstone.
        _ => Disposition::Tombstone,
    }
}

/// Remove a member: enforce the no-last-admin invariant, delete the
/// ACL row, apply the disposition to the Member row, and best-effort
/// flip the revocation bit.
///
/// The whole no-last-admin check + ACL delete runs under
/// [`LAST_ADMIN_LOCK`] so concurrent departures can't both pass the
/// "still has an admin" check and both delete. The invariant is
/// host-enforced here (pipeline §5: a policy can never authorize
/// leaving zero admins) — on violation nothing is written and a
/// [`AppError::Conflict`] surfaces (→ 409).
async fn depart(
    state: &AppState,
    subject_did: &str,
    disposition: Disposition,
    _actor_did: &str,
) -> Result<DepartOutcome, AppError> {
    let _guard = LAST_ADMIN_LOCK.lock().await;

    // No-last-admin invariant — checked before any write so a refusal
    // leaves the community untouched.
    if let Some(acl) = get_acl_entry(&state.acl_ks, subject_did).await?
        && matches!(acl.role, VtcRole::Admin)
    {
        let other_admins = list_acl_entries(&state.acl_ks)
            .await?
            .iter()
            .filter(|e| e.did != subject_did && matches!(e.role, VtcRole::Admin))
            .count();
        if other_admins == 0 {
            return Err(AppError::Conflict(format!(
                "refusing to remove the last admin ({subject_did}) — promote another \
                 member to admin first"
            )));
        }
    }

    let member = get_member(&state.members_ks, subject_did).await?;
    // Capture the revocation slot before the disposition path mutates
    // (purge deletes the row) or clears it.
    let slot = member.as_ref().and_then(|m| m.status_list_index);

    delete_acl_entry(&state.acl_ks, subject_did).await?;

    match (disposition, member) {
        (Disposition::Purge, existed) => {
            delete_member(&state.members_ks, subject_did).await?;
            // Only a purge removes the row; tombstone/historical keep it, so
            // they leave `list_members().len()` (and the cache) unchanged. Guard
            // on prior existence so a purge of an already-absent member doesn't
            // under-count.
            if existed.is_some() {
                state.member_count_dec();
            }
        }
        (Disposition::Tombstone, Some(mut m)) => {
            m.tombstone();
            store_member(&state.members_ks, &m).await?;
        }
        (Disposition::Historical, Some(mut m)) => {
            m.mark_historical();
            store_member(&state.members_ks, &m).await?;
        }
        // No Member row — Tombstone/Historical are trivially satisfied.
        (Disposition::Tombstone | Disposition::Historical, None) => {}
        (Disposition::PolicyDefault, _) => {
            // parse_disposition never yields PolicyDefault; this arm
            // exists only to keep the match total.
            unreachable!("disposition must be concrete before depart");
        }
    }

    // Revoke the member's credentials by flipping the revocation bit.
    // Best-effort: the ACL + Member rows are already gone, so a flip
    // failure is logged, not unwound — the caller can re-flip.
    let revoked_slot = match slot {
        Some(slot) => match flip_revocation(state, slot).await {
            Ok(()) => Some(slot),
            Err(e) => {
                warn!(
                    error = %e,
                    slot,
                    target = subject_did,
                    "failed to flip revocation bit on departure — ACL/Member already \
                     removed; operator must reflip manually"
                );
                None
            }
        },
        None => None,
    };

    Ok(DepartOutcome {
        disposition,
        revoked_slot,
    })
}

/// Flip the revocation bit at `slot` to `revoked`. Raw write, no
/// audit — the caller emits the `StatusListFlipped` event from the
/// returned [`DepartOutcome`].
async fn flip_revocation(state: &AppState, slot: u32) -> Result<(), AppError> {
    // Locked RMW: the flip must not be clobbered by a concurrent
    // allocate/flip on the same row (P0.1).
    status_list::with_locked(&state.status_lists_ks, StatusPurpose::Revocation, |row| {
        status_list::flip(row, slot, true)
            .map_err(|e| AppError::Internal(format!("flip revocation slot {slot}: {e}")))
    })
    .await
}

/// Pull the top-level `id` field off a signed VC. The upstream
/// `VerifiableCredential` type doesn't expose it directly — issuance
/// splices it onto the wire form via JSON, so reading it back requires
/// a JSON round-trip. Shared with the approve route's audit helper.
pub(crate) fn top_level_id(vc: &VerifiableCredential) -> Option<String> {
    serde_json::to_value(vc)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str().map(str::to_string)))
}
