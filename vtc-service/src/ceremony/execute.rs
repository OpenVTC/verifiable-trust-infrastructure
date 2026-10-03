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
//! ([`crate::routes::join_requests::decide::decide`]) is refactored
//! to go through it too — it builds an [`EffectPlan::Admit`] and calls
//! [`apply`], so the pipeline genuinely supersedes the bespoke write
//! path rather than duplicating it. The approve route's integration
//! tests therefore exercise the [`EffectPlan::Admit`] arm end-to-end.
//!
//! ## What's wired
//!
//! - **Admit** (join) — write the ACL row + Member record, issue the
//!   VMC + role VAC, flip the status-list slot. Fully wired; the
//!   manual approve route goes through it.
//! - **Depart** (leave) — enforce the no-last-admin invariant, delete
//!   the ACL row, apply the disposition to the Member row, and revoke
//!   the credential (flip the revocation bit). Fully wired; the
//!   `DELETE /v1/members/{me,did}` removal routes go through it.
//! - **Remint** (role-change) — change the ACL role in place + re-mint
//!   the role VAC, enforcing no-last-admin on demotion. Fully wired;
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
use crate::acl::{VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::credentials::{
    CredentialStatusRef, RoleVacParams, VmcParams, build_role_vac, build_vmc,
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

/// Take [`LAST_ADMIN_LOCK`] for a write that can end an admin outside this
/// executor — `acl/revoke`, an `acl/grant` rewrite — so it serialises with
/// `depart` and `remint` and the admin-set checks they all make
/// (`crate::acl::admin_consent::check_attrition`) see one another's writes.
pub(crate) async fn lock_admin_set() -> tokio::sync::MutexGuard<'static, ()> {
    LAST_ADMIN_LOCK.lock().await
}

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
    /// + the re-minted role VAC. Boxed — the VC makes it large.
    Reminted(Box<RemintOutcome>),
    /// No state was changed (the verdict was deny / refer /
    /// request_more).
    None,
}

/// The credentials minted when a member is admitted.
#[derive(Debug)]
pub struct AdmitOutcome {
    pub vmc: VerifiableCredential,
    pub role_vac: VerifiableCredential,
    pub status_list_index: u32,
}

/// The result of an in-place role change.
#[derive(Debug)]
pub struct RemintOutcome {
    /// The role the subject held before the change (for the caller's
    /// `RoleChanged` audit).
    pub previous_role: VtcRole,
    /// The role VAC re-minted at the new role. The DID + VMC are
    /// unchanged; only the role assertion is re-issued.
    ///
    /// `None` when the subject holds an ACL entry but **no member row** — an
    /// integration or operator DID reached through `acl/change-role`. A role
    /// VAC asserts community membership at a role; there is nobody to assert
    /// it about and nothing to repoint, and minting one anyway would make an
    /// ACL role change impossible on a VTC without a credential signer.
    pub role_vac: Option<VerifiableCredential>,
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
    /// Community role grants (vetter grants) the member held, now revoked:
    /// slot flipped and row marked. The caller audits each. Best effort, like
    /// the flip above — a grant that could not be revoked is logged.
    pub revoked_grants: Vec<crate::endorsements::Endorsement>,
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
            publish_consent,
        } => {
            let role = parse_role(&role)?;
            let outcome = admit(state, &subject, role, publish_consent, actor_did).await?;
            Ok(EffectOutcome::Admitted(Box::new(outcome)))
        }
        EffectPlan::Depart {
            subject,
            disposition,
        } => {
            let disposition = parse_disposition(disposition.as_deref());
            let outcome = depart(state, &subject, disposition, actor_did).await?;
            crate::admin_actions::record_effect(state).await;
            Ok(EffectOutcome::Departed(outcome))
        }
        EffectPlan::Remint { subject, role } => {
            let role = parse_role(&role)?;
            let outcome = remint(state, &subject, role).await?;
            crate::admin_actions::record_effect(state).await;
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
    let parsed = role.parse::<VtcRole>().map_err(|_| {
        AppError::Validation(format!("effect plan carries an unknown role: {role}"))
    })?;
    parsed.refuse_unassignable()?;
    Ok(parsed)
}

/// Admit a DID as a member: write the ACL row + Member record, issue
/// the VMC + role VAC, flip the status-list slot.
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
///
/// `publish_consent` is the applicant's `registryConsent`, written onto the
/// Member row in its *first* store, so no reader ever sees the new row without
/// it. The same guard means
/// admission never overwrites a live member's consent (a live member holds an
/// ACL row, so the admit is a `Conflict`); a re-admission follows a departure,
/// whose tombstone already cleared the old consent, and the new application's
/// answer is the only one that applies to the new membership.
async fn admit(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
    publish_consent: bool,
    actor_did: &str,
) -> Result<AdmitOutcome, AppError> {
    let _guard = LAST_ADMIN_LOCK.lock().await;

    // A non-member's `application` entry — held only for the git rights it
    // carries (the bridge, an external signer) — is not a membership: joining
    // turns it into one and keeps those grants. Anything else is a member.
    let _git = crate::git_ns::store::write_lock().await;
    let prior_grants = match get_acl_entry(&state.acl_ks, subject_did).await? {
        Some(e) if e.is_application() => e.resource_grants,
        Some(_) => {
            return Err(AppError::Conflict(format!(
                "{subject_did} already has an ACL row; refusing to admit a duplicate membership"
            )));
        }
        None => Vec::new(),
    };

    let acl = VtcAclEntry {
        did: subject_did.to_string(),
        role: role.clone(),
        label: None,
        // The authority an invitation's role implies; an invitation naming a
        // role that implies any was bounded by its inviter's own when it was
        // issued (`routes::invitations`, vtc-admin-roles.md §6.3).
        admin: role.implied_authority(),
        delegated_by: None,
        created_at: now_epoch(),
        created_by: actor_did.to_string(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: prior_grants,
    };
    store_acl_entry(&state.acl_ks, &acl).await?;
    drop(_git);

    let mut member = Member::fresh(subject_did);
    member.publish_consent = publish_consent;
    {
        let _edit = crate::members::storage::edit_lock().await;
        store_member(&state.members_ks, &member).await?;
    }

    let (vmc, role_vac, status_list_index) =
        issue_member_credentials(state, subject_did, role).await?;
    // Keep the bodies, not just the ids: the member's acknowledgement carries a
    // digest of the grant, and an id cannot be digested. See
    // [`crate::members::Member::current_vmc`].
    let vmc_value = serde_json::to_value(&vmc)
        .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
    let role_vac_value = serde_json::to_value(&role_vac)
        .map_err(|e| AppError::Internal(format!("serialise role VAC: {e}")))?;
    crate::members::storage::edit_member(&state.members_ks, subject_did, |m| {
        m.status_list_index = Some(status_list_index);
        m.record_issued_credentials(vmc_value, role_vac_value);
        true
    })
    .await?
    .ok_or_else(|| AppError::Conflict("the member left while this was in progress".into()))?;

    // A new member row exists; keep the cached count in step (still under
    // LAST_ADMIN_LOCK, so it's serialised with the duplicate-admit guard).
    state.member_count_inc();

    Ok(AdmitOutcome {
        vmc,
        role_vac,
        status_list_index,
    })
}

/// Allocate a revocation-list slot, mint the VMC + role VAC at `role`,
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
    // because the VMC/VAC build sits between the allocate and the store —
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

    let vac_id = format!("urn:uuid:{}", Uuid::new_v4());
    let role_vac = build_role_vac(
        signer,
        RoleVacParams::new(subject_did, role).with_id(vac_id),
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
    crate::schemas::validate_issued(&state.schemas_ks, &to_value(&role_vac)?).await?;

    status_list::store_state(&state.status_lists_ks, &row).await?;
    status_list::maybe_emit_occupancy_warning(&row);

    Ok((vmc, role_vac, slot))
}

/// Change a member's role in place: update the ACL row and re-mint the
/// role VAC at the new role. The DID + VMC are unchanged.
///
/// An entry whose administrative authority is what its community role implies
/// follows the role (the `acl/*/0.1` convention); one whose authority is stated
/// on its own keeps it. The move is bounded and gated before the plan is built
/// ([`super::orchestrate`]); here the attrition invariant runs under
/// [`LAST_ADMIN_LOCK`]: a move that would leave nobody holding
/// `vtc.roles.assign` is refused (`Conflict` → 409) before any write
/// (VTI-APV-009).
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
    let now = crate::auth::session::now_epoch();
    let mut next = acl.clone();
    next.role = new_role.clone();
    if crate::routes::acl::expressible_in_v0_1(&acl) {
        next.admin = new_role.implied_authority();
    }

    if crate::acl::admin_consent::is_live_role_assigner(&acl, now)
        && !crate::acl::admin_consent::is_live_role_assigner(&next, now)
    {
        crate::acl::admin_consent::check_attrition(state, subject_did).await?;
    }

    acl = next;
    store_acl_entry(&state.acl_ks, &acl).await?;

    // Re-mint the role VAC at the new role + repoint the member — only where
    // there *is* a member. An ACL-only subject has no role assertion to
    // re-issue (see `RemintOutcome::role_vac`).
    let role_vac = match get_member(&state.members_ks, subject_did).await? {
        Some(_) => {
            let role_vac = issue_role_vec(state, subject_did, new_role).await?;
            let role_vac_value = serde_json::to_value(&role_vac)
                .map_err(|e| AppError::Internal(format!("serialise role VAC: {e}")))?;
            // The grant is untouched by a role change, so the member's
            // acknowledgement of it still stands — only the VAC is repointed.
            crate::members::storage::edit_member(&state.members_ks, subject_did, |m| {
                m.record_role_vec(role_vac_value);
                true
            })
            .await?;
            Some(role_vac)
        }
        None => None,
    };

    Ok(RemintOutcome {
        previous_role,
        role_vac,
    })
}

/// Mint a role VAC at `role` for `subject_did`. Used by role-change to
/// re-issue the role assertion; the VMC + status list are untouched.
async fn issue_role_vec(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
) -> Result<VerifiableCredential, AppError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot re-mint role VAC (run setup first)".into(),
        )
    })?;
    let vac_id = format!("urn:uuid:{}", Uuid::new_v4());
    build_role_vac(
        signer,
        RoleVacParams::new(subject_did, role).with_id(vac_id),
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
    actor_did: &str,
) -> Result<DepartOutcome, AppError> {
    let _guard = LAST_ADMIN_LOCK.lock().await;

    // Attrition — checked before any write so a refusal leaves the community
    // untouched: removing a holder of `vtc.roles.assign` must not leave nobody
    // able to grant or consent to authority (VTI-APV-009).
    let acl = get_acl_entry(&state.acl_ks, subject_did).await?;
    if let Some(acl) = acl.as_ref()
        && crate::acl::admin_consent::is_live_role_assigner(acl, crate::auth::session::now_epoch())
    {
        crate::acl::admin_consent::check_attrition(state, subject_did).await?;
    }

    let member = get_member(&state.members_ks, subject_did).await?;
    // Capture the revocation slot before the disposition path mutates
    // (purge deletes the row) or clears it.
    let slot = member.as_ref().and_then(|m| m.status_list_index);

    delete_acl_entry(&state.acl_ks, subject_did).await?;
    // The departed member's own grants go to review (vtc-admin-roles.md §6.3).
    crate::acl::delegation::clear(state, subject_did).await?;
    crate::acl::delegation::on_granter_changed(state, subject_did, None).await?;

    match (disposition, member) {
        (Disposition::Purge, existed) => {
            // Under the members edit lock: a writer that read the row before
            // the delete must not write it back after.
            {
                let _edit = crate::members::storage::edit_lock().await;
                delete_member(&state.members_ks, subject_did).await?;
            }
            // Free any personhood pseudonym this member held. Purge is the
            // *only* departure that does — tombstone and historical keep the
            // member row, and the person is still here. Releasing on those
            // would let one-membership-per-person be defeated by leaving and
            // rejoining under a fresh DID.
            //
            // Best-effort, deliberately: the member row is already gone, and
            // failing the purge over a stale uniqueness claim would leave the
            // community in a worse state than a claim nobody can spend. The
            // operator can re-run it.
            match crate::members::pseudonym::release_for_member(&state.members_ks, subject_did)
                .await
            {
                Ok(0) => {}
                Ok(freed) => {
                    tracing::info!(
                        subject = %subject_did,
                        freed,
                        "released personhood pseudonym claims on purge"
                    );
                }
                Err(e) => tracing::warn!(
                    subject = %subject_did,
                    error = %e,
                    "could not release personhood pseudonym claims — this person may be \
                     refused if they rejoin"
                ),
            }
            // Only a purge removes the row; tombstone/historical keep it, so
            // they leave `list_members().len()` (and the cache) unchanged. Guard
            // on prior existence so a purge of an already-absent member doesn't
            // under-count.
            if existed.is_some() {
                state.member_count_dec();
            }
        }
        (Disposition::Tombstone, Some(_)) => {
            crate::members::storage::edit_member(&state.members_ks, subject_did, |m| {
                m.tombstone();
                true
            })
            .await?;
        }
        (Disposition::Historical, Some(_)) => {
            crate::members::storage::edit_member(&state.members_ks, subject_did, |m| {
                m.mark_historical();
                true
            })
            .await?;
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

    // A departed member is no vetter. Eligibility already requires a current
    // member, but a grant left live would count again if this DID rejoined.
    let revoked_grants =
        crate::vetting::vetters::revoke_on_departure(state, actor_did, subject_did).await;

    Ok(DepartOutcome {
        disposition,
        revoked_slot,
        revoked_grants,
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
        .as_ref()
        .and_then(crate::members::top_level_id)
}
