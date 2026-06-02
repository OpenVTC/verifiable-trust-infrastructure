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
//!   VMC + role VEC, flip the status-list slot. Fully wired.
//! - **NoStateChange** (deny / refer / request_more) — no-op.
//! - **Project** (directory) — not handled here: the directory route
//!   serializes the projection into its HTTP response inline, so a
//!   `Project` plan reaching the executor is a caller bug.
//! - **Depart** (leave) / **Remint** (role-change) — not yet wired:
//!   their ceremonies (routes + facts assembly + the no-last-admin
//!   invariant) don't exist yet, so wiring their executors now would
//!   be untested speculation. They return a clear error until then.

use affinidi_status_list::StatusPurpose;
use affinidi_vc::VerifiableCredential;
use uuid::Uuid;
use vti_common::error::AppError;

use super::effects::EffectPlan;
use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::members::{Member, store_member};
use crate::server::AppState;
use crate::status_list;

/// What the executor did. Carries back whatever the caller needs to
/// audit + respond — currently the credentials minted on admit.
#[derive(Debug)]
pub enum EffectOutcome {
    /// A member was admitted; carries the issued credentials so the
    /// caller can audit them and hand them to the applicant. Boxed —
    /// the two VCs make this variant far larger than the others.
    Admitted(Box<AdmitOutcome>),
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
        EffectPlan::NoStateChange => Ok(EffectOutcome::None),
        EffectPlan::Project { .. } => Err(AppError::Internal(
            "directory projection is applied by the route, not the effect executor".into(),
        )),
        EffectPlan::Depart { .. } | EffectPlan::Remint { .. } => Err(AppError::Internal(
            "leave / role-change effect executor is not yet wired".into(),
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
async fn admit(
    state: &AppState,
    subject_did: &str,
    role: VtcRole,
    actor_did: &str,
) -> Result<AdmitOutcome, AppError> {
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

    status_list::store_state(&state.status_lists_ks, &row).await?;
    status_list::maybe_emit_occupancy_warning(&row);

    Ok((vmc, role_vec, slot))
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
