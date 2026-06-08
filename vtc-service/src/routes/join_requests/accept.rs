//! `POST /v1/join-requests/{id}/accept` — the reciprocal step
//! (`join-requests/accept/1.0`) + a shared `accept_inner` the DIDComm
//! handler calls into.
//!
//! A join `allow` issues the community → member half of the membership
//! edge (the VMC). `accept` carries the member's counter-assertion — a
//! member-issued **reciprocal VC** — back to the VTC, which verifies it
//! and records the bidirectional DTG edge, discharging the
//! `reciprocate_vmc` obligation. Membership (ACL + VMC) is already
//! effective at admit; this completes the edge.
//!
//! ## Auth
//!
//! Unauthenticated trigger; the reciprocal VC + the request binding ARE
//! the auth (spec §Authentication), mirroring `submit`:
//! - REST carries an Ed25519 holder-binding `signature` over the
//!   canonical body (domain tag [`JOIN_ACCEPT_DOMAIN_TAG`]).
//! - DIDComm omits it — the authcrypt sender binds `memberDid`
//!   (`signature_hex = None`).
//!
//! The reciprocal VC itself is a DI VC self-issued by the member
//! (`did:key`, Phase 1) — its `eddsa-jcs-2022` issuer proof IS the
//! counter-signature, verified directly against the member's `did:key`.

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, MembershipReciprocatedData};
use vti_common::error::AppError;

use crate::join::{JoinStatus, JoinTransport, get_join_request};
use crate::members::{get_member, store_member};
use crate::server::AppState;

/// Domain tag prefixing the REST holder-binding signature payload.
/// Distinct from `submit`'s tag so an accept signature can never be
/// replayed as a submission.
pub const JOIN_ACCEPT_DOMAIN_TAG: &[u8] = b"vtc-join-accept/v1\0";

/// `type` array value the reciprocal VC must carry.
const RECIPROCAL_VC_TYPE: &str = "MembershipAcknowledgement";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptRequestBody {
    pub member_did: String,
    pub vmc_id: String,
    /// Member-issued reciprocal VC (DI VC; issuer = `memberDid`).
    pub vc: JsonValue,
    /// Hex-encoded Ed25519 signature over the canonical body.
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptResponse {
    pub request_id: Uuid,
    pub status: String,
    pub reciprocal_vc_id: String,
}

/// What [`accept_inner`] recorded.
pub struct AcceptOutcome {
    pub request_id: Uuid,
    pub reciprocal_vc_id: String,
    /// `false` when the edge was already recorded with this same VC —
    /// the call was a no-op (idempotent re-accept), so the caller skips
    /// re-auditing.
    pub recorded: bool,
}

pub async fn accept(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<AcceptRequestBody>,
) -> Result<(StatusCode, Json<AcceptResponse>), AppError> {
    let outcome = accept_inner(
        &state,
        id,
        body.member_did,
        body.vmc_id,
        body.vc,
        Some(&body.signature),
        JoinTransport::Rest,
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(AcceptResponse {
            request_id: outcome.request_id,
            status: "accepted".to_string(),
            reciprocal_vc_id: outcome.reciprocal_vc_id,
        }),
    ))
}

/// Shared decide → record spine for REST + DIDComm.
///
/// `signature_hex` is `Some` for REST (explicit holder binding) and
/// `None` for DIDComm (the authcrypt sender already authenticated
/// `member_did`).
pub async fn accept_inner(
    state: &AppState,
    id: Uuid,
    member_did: String,
    vmc_id: String,
    vc: JsonValue,
    signature_hex: Option<&str>,
    transport: JoinTransport,
) -> Result<AcceptOutcome, AppError> {
    // 1. Holder binding (REST only).
    if let Some(hex_sig) = signature_hex {
        verify_holder_signature(&member_did, &vmc_id, &vc, hex_sig)?;
    }

    // 2. The join request must exist and have an issued membership to
    // reciprocate (verdict was `allow`/approve → status Approved).
    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Approved {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}; only an Approved request has a VMC to reciprocate",
            req.status
        )));
    }
    if req.applicant_did != member_did {
        return Err(AppError::Validation(format!(
            "memberDid does not match the join request applicant ({})",
            req.applicant_did
        )));
    }

    // 3. The member must exist and `vmcId` must name their current VMC.
    let mut member = get_member(&state.members_ks, &member_did)
        .await?
        .filter(|m| !m.is_removed())
        .ok_or_else(|| AppError::NotFound(format!("no active member: {member_did}")))?;
    if member.current_vmc_id.as_deref() != Some(vmc_id.as_str()) {
        return Err(AppError::Conflict(format!(
            "vmcId does not match the member's current VMC ({:?})",
            member.current_vmc_id
        )));
    }

    // 4. Verify the reciprocal VC (the counter-signature itself). The
    // community DID the member acknowledges is this VTC's DID — the
    // issuer of the VMC being reciprocated.
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            AppError::Internal("VTC DID not configured — cannot bind a reciprocal VC".into())
        })?;
    let reciprocal_vc_id = verify_reciprocal_vc(&vc, &member_did, &vmc_id, &community_did)?;

    // 5. Idempotency: a re-accept with the same VC is a no-op; a
    // different VC for an already-reciprocated VMC is a conflict.
    if let Some(existing) = member.reciprocal_vc_id.as_deref() {
        if existing == reciprocal_vc_id {
            return Ok(AcceptOutcome {
                request_id: id,
                reciprocal_vc_id,
                recorded: false,
            });
        }
        return Err(AppError::Conflict(format!(
            "membership already reciprocated with a different VC ({existing})"
        )));
    }

    // 6. Record the bidirectional edge.
    member.record_reciprocation(reciprocal_vc_id.clone());
    store_member(&state.members_ks, &member).await?;

    // 7. Audit.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    audit_writer
        .write(
            &member_did,
            Some(&member_did),
            AuditEvent::MembershipReciprocated(MembershipReciprocatedData {
                request_id: id.to_string(),
                vmc_id: vmc_id.clone(),
                reciprocal_vc_id: reciprocal_vc_id.clone(),
            }),
        )
        .await?;

    info!(
        request_id = %id,
        member = %member_did,
        vmc_id = %vmc_id,
        reciprocal_vc_id = %reciprocal_vc_id,
        transport = transport.as_str(),
        "membership reciprocated"
    );

    Ok(AcceptOutcome {
        request_id: id,
        reciprocal_vc_id,
        recorded: true,
    })
}

/// Verify the member-issued reciprocal VC and return its top-level `id`.
///
/// Checks: `issuer == member_did`; `type` includes
/// [`RECIPROCAL_VC_TYPE`]; `credentialSubject.id == community_did`;
/// `credentialSubject.reciprocates == vmc_id`; and the
/// `eddsa-jcs-2022` issuer proof (purpose `assertionMethod`, key bound
/// to `member_did`) verifies against the member's `did:key`.
fn verify_reciprocal_vc(
    vc: &JsonValue,
    member_did: &str,
    vmc_id: &str,
    community_did: &str,
) -> Result<String, AppError> {
    let obj = vc
        .as_object()
        .ok_or_else(|| AppError::Validation("reciprocal vc is not a JSON object".into()))?;

    // Issuer must be the member (self-issued counter-signature).
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
            "reciprocal vc issuer `{issuer}` is not the member `{member_did}`"
        )));
    }

    // Type discriminator.
    let has_type = obj
        .get("type")
        .and_then(JsonValue::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(JsonValue::as_str)
                .any(|t| t == RECIPROCAL_VC_TYPE)
        });
    if !has_type {
        return Err(AppError::Validation(format!(
            "reciprocal vc `type` must include `{RECIPROCAL_VC_TYPE}`"
        )));
    }

    // Subject: acknowledges THIS community + the specific VMC.
    let subject = obj.get("credentialSubject").and_then(JsonValue::as_object);
    let subject_id = subject
        .and_then(|s| s.get("id"))
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if subject_id != community_did {
        return Err(AppError::Validation(format!(
            "reciprocal vc subject `{subject_id}` is not this community `{community_did}`"
        )));
    }
    let reciprocates = subject
        .and_then(|s| s.get("reciprocates"))
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if reciprocates != vmc_id {
        return Err(AppError::Validation(format!(
            "reciprocal vc `reciprocates` ({reciprocates}) does not name the member's VMC ({vmc_id})"
        )));
    }

    // Cryptographic counter-signature: the member's issuer proof.
    let proof_val = obj
        .get("proof")
        .ok_or_else(|| AppError::Validation("reciprocal vc has no issuer `proof`".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_val.clone()).map_err(|e| {
        AppError::Validation(format!("reciprocal vc proof is not Data-Integrity: {e}"))
    })?;
    if proof.proof_purpose != "assertionMethod" {
        return Err(AppError::Validation(format!(
            "reciprocal vc proof purpose is `{}`, expected `assertionMethod`",
            proof.proof_purpose
        )));
    }
    if proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
        != member_did
    {
        return Err(AppError::Validation(format!(
            "reciprocal vc proof verificationMethod `{}` is not under the member `{member_did}`",
            proof.verification_method
        )));
    }

    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(member_did)
        .map_err(|e| AppError::Validation(format!("member_did is not a parseable did:key: {e}")))?;
    let mut unsigned = vc.clone();
    if let Some(o) = unsigned.as_object_mut() {
        o.remove("proof");
    }
    proof
        .verify_with_public_key(&unsigned, &pub_bytes, VerifyOptions::new())
        .map_err(|e| {
            AppError::Validation(format!("reciprocal vc issuer proof did not verify: {e}"))
        })?;

    obj.get("id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::Validation("reciprocal vc is missing a top-level `id`".into()))
}

/// Verify the Ed25519 holder-binding signature over the canonical body
/// (`memberDid` + `vmcId` + `vc`), domain-tagged. Mirrors `submit`.
fn verify_holder_signature(
    member_did: &str,
    vmc_id: &str,
    vc: &JsonValue,
    signature_hex: &str,
) -> Result<(), AppError> {
    let pubkey_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(member_did)
        .map_err(|e| AppError::Validation(format!("member_did is not a parseable did:key: {e}")))?;
    let verifying = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| AppError::Validation(format!("member_did decodes to an invalid key: {e}")))?;

    let payload = canonical_payload(member_did, vmc_id, vc)?;
    let signing_bytes = signing_bytes(&payload);

    let raw_sig = hex::decode(signature_hex)
        .map_err(|e| AppError::Validation(format!("signature is not hex: {e}")))?;
    let signature = Signature::from_slice(&raw_sig).map_err(|e| {
        AppError::Validation(format!("signature is not a 64-byte Ed25519 value: {e}"))
    })?;

    verifying
        .verify(&signing_bytes, &signature)
        .map_err(|e| AppError::Validation(format!("holder-binding signature failed: {e}")))?;
    Ok(())
}

/// Canonical signing payload — typed struct, field order pinned by the
/// derive (both sides build it identically).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    member_did: &'a str,
    vmc_id: &'a str,
    vc: &'a JsonValue,
}

fn canonical_payload(member_did: &str, vmc_id: &str, vc: &JsonValue) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        member_did,
        vmc_id,
        vc,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}

fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JOIN_ACCEPT_DOMAIN_TAG.len() + payload.len());
    buf.extend_from_slice(JOIN_ACCEPT_DOMAIN_TAG);
    buf.extend_from_slice(payload);
    buf
}
