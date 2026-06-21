//! Receive + verify a member-issued **VMC** (member → community half of the
//! membership pair) and record it on the member's row.
//!
//! The VTC issues a `VerifiableMembershipCredential` to each member at
//! admission; this is the reciprocal the member issues back, naming the
//! community as its `credentialSubject`. The `eddsa-jcs-2022` issuer proof (key
//! under the member's DID, resolved via [`DidVmResolver`] so `did:webvh`
//! personas verify, not just `did:key`) IS the authentication of the
//! credential. Over DIDComm the authcrypt sender independently authenticates
//! `member_did`; the two must agree.
//!
//! Shared by the DIDComm `members/vmc/1.0` handler (the only transport today —
//! members speak DIDComm).

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use serde_json::Value as JsonValue;
use tracing::info;

use vti_common::error::AppError;

use vta_sdk::protocols::members::VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE;

use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
use crate::members::{get_member, store_member};
use crate::server::AppState;

/// What [`receive_member_vmc_inner`] recorded.
pub struct MemberVmcOutcome {
    pub member_did: String,
    pub vmc_id: String,
    /// `false` when the same VMC was already stored (idempotent re-send) — the
    /// caller skips re-auditing / re-logging the store.
    pub recorded: bool,
}

/// Verify a member-issued VMC and store it on the member's row.
///
/// Checks: the member exists and is active; `vc.issuer == member_did`; `type`
/// includes [`VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE`];
/// `credentialSubject.id == <this VTC's DID>`; the issuer DI proof's
/// `verificationMethod` is under the member and verifies against the resolved
/// key. Idempotent: re-sending the same `id` is a no-op.
pub async fn receive_member_vmc_inner(
    state: &AppState,
    member_did: String,
    vc: JsonValue,
) -> Result<MemberVmcOutcome, AppError> {
    // The community DID the member's VMC must name as its subject.
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            AppError::Internal("VTC DID not configured — cannot accept a member VMC".into())
        })?;

    let vmc_id = verify_member_vmc(state, &vc, &member_did, &community_did).await?;

    // The member must exist and be active.
    let mut member = get_member(&state.members_ks, &member_did)
        .await?
        .filter(|m| !m.is_removed())
        .ok_or_else(|| AppError::NotFound(format!("no active member: {member_did}")))?;

    // Idempotency: the same VMC re-sent is a no-op; a *different* VMC replaces
    // the stored one (a renewal — the member rotated/reissued their half).
    if member.member_vmc_id.as_deref() == Some(vmc_id.as_str()) {
        return Ok(MemberVmcOutcome {
            member_did,
            vmc_id,
            recorded: false,
        });
    }

    member.record_member_vmc(vmc_id.clone(), vc);
    store_member(&state.members_ks, &member).await?;

    info!(
        member = %member_did,
        vmc_id = %vmc_id,
        "stored member-issued VMC (member → community half of the pair)"
    );

    Ok(MemberVmcOutcome {
        member_did,
        vmc_id,
        recorded: true,
    })
}

/// Verify the member-issued VMC and return its top-level `id`.
async fn verify_member_vmc(
    state: &AppState,
    vc: &JsonValue,
    member_did: &str,
    community_did: &str,
) -> Result<String, AppError> {
    let obj = vc
        .as_object()
        .ok_or_else(|| AppError::Validation("member vmc is not a JSON object".into()))?;

    // Issuer must be the member (the authcrypt sender / proof signer).
    let issuer = match obj.get("issuer") {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Object(o)) => o
            .get("id")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };
    if issuer != member_did {
        return Err(AppError::Validation(format!(
            "member vmc issuer `{issuer}` is not the member `{member_did}`"
        )));
    }

    // Type discriminator.
    let has_type = obj
        .get("type")
        .and_then(JsonValue::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(JsonValue::as_str)
                .any(|t| t == VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE)
        });
    if !has_type {
        return Err(AppError::Validation(format!(
            "member vmc `type` must include `{VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE}`"
        )));
    }

    // Subject must be THIS community.
    let subject_id = obj
        .get("credentialSubject")
        .and_then(JsonValue::as_object)
        .and_then(|s| s.get("id"))
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if subject_id != community_did {
        return Err(AppError::Validation(format!(
            "member vmc subject `{subject_id}` is not this community `{community_did}`"
        )));
    }

    // Cryptographic issuer proof: key under the member, resolved (did:key +
    // did:webvh) and verified.
    let proof_value = obj
        .get("proof")
        .ok_or_else(|| AppError::Validation("member vmc has no issuer `proof`".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone()).map_err(|e| {
        AppError::Validation(format!("member vmc proof is not Data-Integrity: {e}"))
    })?;
    check_issuer_binding(&proof.verification_method, member_did)?;

    let resolver = DidVmResolver::new(state.did_resolver.clone());
    let mut unsigned = vc.clone();
    if let Some(o) = unsigned.as_object_mut() {
        o.remove("proof");
    }
    proof
        .verify(&unsigned, &resolver, VerifyOptions::new())
        .await
        .map_err(|e| {
            AppError::Validation(format!("member vmc issuer proof did not verify: {e}"))
        })?;

    obj.get("id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::Validation("member vmc has no top-level `id`".into()))
}
