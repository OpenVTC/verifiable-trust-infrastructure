//! `POST /v1/members/me/renew` — VMC + role VEC renewal
//! (M2.13). Spec §6.3.
//!
//! The renewal flow is **unconditional on ACL membership**: no
//! expiry check, no grace window. Spec §3-F + §6.3 — the VMC
//! `validUntil` is an external-verifier concern. Inside the
//! community, the ACL is the authoritative source of "are you
//! a member?", and the ACL doesn't have an expiry on Phase 2's
//! member rows.
//!
//! On renew:
//!
//! 1. Look up the caller's ACL row (404 if removed, 401 if
//!    session unauthenticated).
//! 2. Look up the Member row to recover the existing
//!    `status_list_index` — renewal **reuses the same slot**
//!    so external chains stay coherent across the renewal
//!    boundary (spec §6.2).
//! 3. Re-evaluate `personhood.rego` per spec §6.3 step 3. The
//!    Phase 2 default ships deny-all so the new VMC always
//!    carries `personhood: false`; if the prior VMC had a
//!    different flag, the audit envelope records
//!    `personhood_changed: true`.
//! 4. Mint VMC + role VEC.
//! 5. Update the Member row with the new VMC + VEC ids.
//! 6. Emit `MembershipRenewed` audit.

use affinidi_status_list::StatusPurpose;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, MembershipRenewedData};
use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::members::{get_member, store_member};
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};
use crate::server::AppState;
use crate::status_list;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewResponse {
    pub did: String,
    pub vmc: JsonValue,
    pub role_vec: JsonValue,
    /// `personhood.rego` re-eval outcome for the new VMC.
    /// Phase 2's deny-all default keeps this `false`; the
    /// field exists from day one so Phase 4's
    /// assert/revoke endpoints don't break the wire shape.
    pub personhood: bool,
    /// `true` when the personhood flag flipped from the prior
    /// VMC. Surfaced separately from `personhood` itself so
    /// callers can light up a "your personhood status
    /// changed" notification.
    pub personhood_changed: bool,
}

pub async fn renew(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<RenewResponse>), AppError> {
    let caller_did = auth.did.clone();
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // 1. Verify the caller has an active ACL row (spec §6.3 —
    // no expiry / grace window).
    let _acl = get_acl_entry(&state.acl_ks, &caller_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no ACL row for {caller_did} — not a member")))?;

    // 2. Recover the prior Member row for the status-list slot
    // + the prior VMC's personhood flag (audit context).
    let mut member = get_member(&state.members_ks, &caller_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no Member row for {caller_did}")))?;

    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot renew (run setup first)".into(),
        )
    })?;

    let status_list_state =
        status_list::get_state(&state.status_lists_ks, StatusPurpose::Revocation)
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "revocation status list not provisioned — set `public_url` + restart".into(),
                )
            })?;

    // Slot: renewal reuses the same slot the member was
    // allocated at join time. A member without a slot somehow
    // (mid-Phase-1 row that pre-dates M2.12) gets a fresh
    // allocation — this keeps renewal idempotent for
    // grandfathered rows without forcing the operator to
    // reseed.
    let slot = match member.status_list_index {
        Some(s) => s,
        // Locked RMW (P0.1) — and `with_locked` re-reads the row inside
        // the lock, so the allocation can't be lost to (or built on a
        // stale copy clobbered by) a concurrent writer.
        None => {
            status_list::with_locked(&state.status_lists_ks, StatusPurpose::Revocation, |row| {
                status_list::allocate(row).ok_or_else(|| {
                    AppError::Internal(format!(
                        "revocation status list exhausted (capacity = {})",
                        row.capacity
                    ))
                })
            })
            .await?
        }
    };

    let status_ref =
        CredentialStatusRef::revocation(status_list_state.list_credential_id.clone(), slot);

    // 3. Re-evaluate `personhood.rego` against the Member's
    //    persisted state (Phase 4 M4.2.2).
    let prior_personhood = member.personhood;
    let policy_allow = evaluate_personhood(&state, &member).await?;

    // M4.2.2: when the policy flips a previously-asserted
    // member's flag to `false`, branch on the operator's
    // configured `on_personhood_fail` mode.
    let fail_mode = state.config.read().await.renewal.on_personhood_fail;
    let (personhood, downgrade_audit) = if prior_personhood && !policy_allow {
        match fail_mode {
            crate::config::PersonhoodFailMode::Refuse => {
                // No state change, no audit, no VMC re-mint.
                return Err(AppError::Validation(
                    "personhood-renewal-refused: active personhood.rego \
                         no longer permits this member; re-assert via \
                         POST /v1/members/{did}/personhood/assert before \
                         retrying renewal"
                        .into(),
                ));
            }
            crate::config::PersonhoodFailMode::Downgrade => (false, true),
        }
    } else {
        (policy_allow, false)
    };

    let personhood_changed = prior_personhood != personhood;

    // 4. Build VMC + role VEC.
    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(&caller_did)
            .with_id(vmc_id.clone())
            .with_status_ref(status_ref)
            .with_personhood(personhood),
    )
    .await?;

    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let role_vec_acl = get_acl_entry(&state.acl_ks, &caller_did)
        .await?
        .ok_or_else(|| AppError::Internal("ACL row disappeared mid-renewal".into()))?;
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(&caller_did, role_vec_acl.role.clone()).with_id(vec_id.clone()),
    )
    .await?;

    // 5. Update the Member row.
    member.status_list_index = Some(slot);
    member.current_vmc_id = Some(vmc_id.clone());
    member.current_role_vec_id = Some(vec_id.clone());
    if downgrade_audit {
        // Renewal-policy downgrade clears the asserted-at
        // timestamp alongside the flag. The member must
        // re-assert (M4.3) to reinstate.
        member.personhood = false;
        member.personhood_asserted_at = None;
    }
    store_member(&state.members_ks, &member).await?;

    // 6. Audit. `MembershipRenewed` always fires; paired
    //    `PersonhoodRevoked { reason: "renewal-policy" }` only
    //    on the downgrade arm.
    audit_writer
        .write(
            &caller_did,
            Some(&caller_did),
            AuditEvent::MembershipRenewed(MembershipRenewedData {
                vmc_id: vmc_id.clone(),
                role_vec_id: vec_id.clone(),
                personhood_changed,
            }),
        )
        .await?;
    if downgrade_audit {
        let vtc_did = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_else(|| "did:key:vtc-unknown".into());
        audit_writer
            .write(
                &vtc_did,
                Some(&caller_did),
                AuditEvent::PersonhoodRevoked(vti_common::audit::PersonhoodRevokedData {
                    vmc_id: Some(vmc_id.clone()),
                    reason: "renewal-policy".into(),
                }),
            )
            .await?;
    }

    info!(
        did = %caller_did,
        slot,
        personhood,
        personhood_changed,
        "membership renewed"
    );

    Ok((
        StatusCode::OK,
        Json(RenewResponse {
            did: caller_did,
            vmc: serde_json::to_value(&vmc)
                .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
            role_vec: serde_json::to_value(&role_vec)
                .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
            personhood,
            personhood_changed,
        }),
    ))
}

/// Run the active `personhood.rego` against the renewal-time
/// canonical input (Phase 4 M4.2.2):
///
/// ```json
/// {
///   "applicant_did": "<did>",
///   "current_personhood": <bool>,
///   "asserted_at_seconds_ago": <int | null>,
///   "vp_claims": { "holder": "<did>", "credentials": [] }
/// }
/// ```
///
/// Evidence (the VP) is **not persisted** on the Member row
/// per planning-review D2 — the policy sees the current
/// flag + the assert age, not the original evidence. Operators
/// wanting richer renewal-time eval upload a custom rego that
/// consults additional inputs (e.g. live trust-registry).
///
/// Fail-closed: any error path yields `false`.
async fn evaluate_personhood(
    state: &AppState,
    member: &crate::members::Member,
) -> Result<bool, AppError> {
    let active = get_active_policy_id(&state.active_policies_ks, PolicyPurpose::Personhood).await?;
    let Some(id) = active else {
        return Ok(false);
    };
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal(format!("active personhood policy {id} not found")))?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;
    let asserted_at_seconds_ago: JsonValue = match member.personhood_asserted_at {
        Some(t) => json!((chrono::Utc::now() - t).num_seconds().max(0)),
        None => JsonValue::Null,
    };
    let input = json!({
        "applicant_did": member.did,
        "current_personhood": member.personhood,
        "asserted_at_seconds_ago": asserted_at_seconds_ago,
        "vp_claims": { "holder": member.did, "credentials": [] },
    });
    let result = evaluate_policy(&compiled, "data.vtc.personhood.allow", input)?;
    Ok(result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}
