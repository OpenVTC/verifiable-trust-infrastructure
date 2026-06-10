//! `/v1/members/{did}/personhood/{challenge,assert}` + revoke
//! — personhood lifecycle endpoints (Phase 4 M4.3 + M4.4).
//! Spec §6.3 + planning-review D2 (VP-only assert).
//!
//! ## Three endpoints, three Trust Tasks
//!
//! 1. `POST .../personhood/challenge` — mints a single-use
//!    nonce + 10-min TTL. The assert body's `presentation.proof.
//!    challenge` field must match. Single-use → consumed on
//!    successful assert. Reuses the rotation-challenge storage
//!    pattern: `passkey_ks` keyspace, `personhood_chal:` prefix.
//!
//! 2. `POST .../personhood/assert` — accepts a VP signed by the
//!    member's `#key-0`. Flow:
//!    - Consume the challenge (single-use; refuses on missing /
//!      expired / wrong-DID).
//!    - Verify the VP's `DataIntegrityProof` against the
//!      member's resolved `#key-0`.
//!    - Verify each embedded VC's proof against its issuer's
//!      `#key-0` (best-effort: missing-proof VCs surface in the
//!      `vp_claims` projection but skip verification — operators
//!      who want stricter VC verification upload a custom rego
//!      that consults `vp_claims.credentials[*].proof` directly).
//!    - Run `extract_vp_claims` (Phase 2 M2.6) → policy input.
//!    - Eval `personhood.rego` (Phase 4 M4.2.1 default). On
//!      `deny` → 403 with stable reason `personhood-policy-denied`.
//!    - Flip `Member.personhood = true`,
//!      `personhood_asserted_at = now`. Per D2 review, the VP
//!      itself is **not persisted** — verified then discarded.
//!    - Re-mint VMC with `personhood: true` (reuse status-list
//!      slot, mirror M2.13 renewal's pattern).
//!    - Emit `PersonhoodAsserted { vmc_id, asserted_at }`.
//!
//! 3. `DELETE .../personhood` — admin or self revoke. Idempotent
//!    no-op if already `false`. Flips flag + clears
//!    asserted_at + re-mints VMC with `personhood: false` +
//!    emits `PersonhoodRevoked { vmc_id, reason: "admin"|"self" }`.
//!
//! ## Auth model
//!
//! - **Challenge**: any authenticated session. The challenge is
//!   bound to the path-DID; downstream assert checks the bind.
//! - **Assert**: any authenticated session. Both admin and the
//!   subject member can mint a challenge + send the assert
//!   (operators who want stricter "only admin can assert"
//!   semantics layer this in `personhood.rego`).
//! - **Revoke**: Admin OR caller's session DID matches path DID.
//!   Self-revoke is canonical (RTBF-style "I no longer want this
//!   claim asserted").

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_vc::VerifiableCredential;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::audit::{AuditEvent, PersonhoodAssertedData, PersonhoodRevokedData};
use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::members::{get_member, store_member};
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy,
    extract::extract_vp_claims, get_active_policy_id, get_policy,
};
use crate::server::AppState;
use crate::status_list;

/// Challenge TTL — 10 minutes. Matches the rotation flow.
const CHALLENGE_TTL_SECS: i64 = 10 * 60;

/// Storage prefix for personhood challenge rows in
/// `passkey_ks`. Co-tenanting with the passkey keyspace
/// avoids a separate AppState field for short-lived state
/// (same pattern as rotation challenges).
const CHALLENGE_PREFIX: &[u8] = b"personhood_chal:";

// ---------------------------------------------------------------------------
// Persisted challenge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersonhoodChallenge {
    id: Uuid,
    /// Bound to the path-DID at mint time. The assert handler
    /// refuses if the path-DID on the assert URL doesn't match.
    member_did: String,
    expires_at: DateTime<Utc>,
}

fn challenge_key(id: Uuid) -> Vec<u8> {
    let mut k = CHALLENGE_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

async fn store_challenge(
    state: &AppState,
    challenge: &PersonhoodChallenge,
) -> Result<(), AppError> {
    let key = String::from_utf8(challenge_key(challenge.id))
        .map_err(|e| AppError::Internal(format!("personhood key encoding broke: {e}")))?;
    state.passkey_ks.insert(key, challenge).await
}

async fn take_challenge(
    state: &AppState,
    id: Uuid,
) -> Result<Option<PersonhoodChallenge>, AppError> {
    let key = challenge_key(id);
    let raw = state.passkey_ks.get_raw(key.clone()).await?;
    let Some(bytes) = raw else { return Ok(None) };
    let challenge: PersonhoodChallenge = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("PersonhoodChallenge decode: {e}")))?;
    state.passkey_ks.remove(key).await?;
    Ok(Some(challenge))
}

// ---------------------------------------------------------------------------
// Challenge endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

pub async fn challenge(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
) -> Result<(StatusCode, Json<ChallengeResponse>), AppError> {
    // Member must exist — minting a challenge for a non-member
    // is operator-confusing and serves no purpose.
    let _ = get_acl_entry(&state.acl_ks, &member_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no ACL row for {member_did}")))?;

    let id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
    let chal = PersonhoodChallenge {
        id,
        member_did: member_did.clone(),
        expires_at,
    };
    store_challenge(&state, &chal).await?;

    info!(
        member_did = %member_did,
        challenge_id = %id,
        "personhood challenge minted"
    );

    Ok((
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge_id: id,
            expires_at,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Assert endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AssertBody {
    /// W3C Verifiable Presentation. `holder` must equal the
    /// path-DID; `proof.challenge` must equal a fresh challenge
    /// id from `POST .../personhood/challenge`.
    pub presentation: JsonValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertResponse {
    pub did: String,
    pub personhood: bool,
    pub vmc: JsonValue,
    pub role_vec: JsonValue,
}

pub async fn assert(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
    Json(body): Json<AssertBody>,
) -> Result<(StatusCode, Json<AssertResponse>), AppError> {
    // Load Member row first — `404` for an unknown subject
    // is the most actionable failure mode.
    let mut member = get_member(&state.members_ks, &member_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no Member row for {member_did}")))?;

    // 1. Extract + consume the challenge before any daemon-
    //    config checks so malformed callers can't observe a
    //    500 (which would otherwise mask their own bad input).
    let proof = body
        .presentation
        .get("proof")
        .ok_or_else(|| AppError::Validation("presentation missing proof block".into()))?;
    let challenge_str = proof
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("proof.challenge missing or not a string".into()))?;
    let challenge_id: Uuid = challenge_str
        .parse()
        .map_err(|e| AppError::Validation(format!("proof.challenge not a UUID: {e}")))?;
    let chal = take_challenge(&state, challenge_id)
        .await?
        .ok_or_else(|| AppError::Validation("challenge not found or already consumed".into()))?;
    if chal.member_did != member_did {
        return Err(AppError::Validation(format!(
            "challenge was minted for {}, not {}",
            chal.member_did, member_did
        )));
    }
    if Utc::now() > chal.expires_at {
        return Err(AppError::Validation("challenge expired".into()));
    }

    // 2. Verify the VP's holder field matches.
    let holder = body
        .presentation
        .get("holder")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("presentation missing holder".into()))?;
    if holder != member_did {
        return Err(AppError::Validation(format!(
            "presentation holder ({holder}) != path-DID ({member_did})"
        )));
    }

    // Daemon-side prerequisites now that caller input is
    // validated. 500-class failures (resolver / signer /
    // audit_writer absent) only fire after we know the
    // request itself is well-formed.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
        AppError::Internal("DID resolver not configured — personhood assert requires it".into())
    })?;

    // 3. Verify the VP's data-integrity proof against the
    //    member's resolved #key-0.
    verify_vp_proof(&body.presentation, &member_did, &resolver)
        .await
        .map_err(|e| AppError::Forbidden(format!("personhood-proof-invalid: {e}")))?;

    // 5. Extract vp_claims for policy input. (Per D2 review,
    //    embedded-VC proofs are surfaced to the policy via
    //    extract but not verified at the route — operators
    //    wanting strict VC verification upload custom rego.)
    let vp_claims = extract_vp_claims(&body.presentation);

    // 6. Run personhood.rego.
    let allow = evaluate_personhood_assert(&state, &member_did, &vp_claims).await?;
    if !allow {
        return Err(AppError::Forbidden(
            "personhood-policy-denied: active personhood.rego rejected the assertion".into(),
        ));
    }

    // 7. Allocate/reuse status-list slot + mint a fresh VMC. The
    //    `list_credential_id` read here is immutable; the allocation goes
    //    through `with_locked` (P0.1) which re-reads the row under the
    //    lock so it can't be lost to a concurrent writer.
    let sl_state = status_list::get_state(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
    )
    .await?
    .ok_or_else(|| AppError::Internal("revocation status list not initialised".into()))?;
    let slot = match member.status_list_index {
        Some(s) => s,
        None => {
            status_list::with_locked(
                &state.status_lists_ks,
                affinidi_status_list::StatusPurpose::Revocation,
                |row| {
                    status_list::allocate(row).ok_or_else(|| {
                        AppError::Internal(
                            "revocation status list is full — cannot allocate slot".into(),
                        )
                    })
                },
            )
            .await?
        }
    };
    let status_ref = CredentialStatusRef::revocation(sl_state.list_credential_id.clone(), slot);

    let now = Utc::now();
    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(&member_did)
            .with_id(vmc_id.clone())
            .with_status_ref(status_ref)
            .with_personhood(true),
    )
    .await?;
    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let acl_row = get_acl_entry(&state.acl_ks, &member_did)
        .await?
        .ok_or_else(|| AppError::Internal("ACL row disappeared mid-assert".into()))?;
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(&member_did, acl_row.role.clone()).with_id(vec_id.clone()),
    )
    .await?;

    // 8. Update Member row.
    member.personhood = true;
    member.personhood_asserted_at = Some(now);
    member.status_list_index = Some(slot);
    member.current_vmc_id = Some(vmc_id.clone());
    member.current_role_vec_id = Some(vec_id.clone());
    store_member(&state.members_ks, &member).await?;

    // 9. Audit.
    audit_writer
        .write(
            &member_did,
            Some(&member_did),
            AuditEvent::PersonhoodAsserted(PersonhoodAssertedData {
                vmc_id: vmc_id.clone(),
                asserted_at: rfc3339(now),
            }),
        )
        .await?;

    info!(member_did = %member_did, "personhood asserted");

    Ok((
        StatusCode::OK,
        Json(AssertResponse {
            did: member_did,
            personhood: true,
            vmc: serde_json::to_value(&vmc)
                .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
            role_vec: serde_json::to_value(&role_vec)
                .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Revoke endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponse {
    pub did: String,
    pub personhood: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

pub async fn revoke(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    // Auth: AdminAuth-equivalent (role == admin) OR self.
    let is_self = auth.did == member_did;
    let is_admin = auth.role == vti_common::acl::Role::Admin;
    if !is_self && !is_admin {
        return Err(AppError::Forbidden(
            "only an admin or the subject member can revoke personhood".into(),
        ));
    }
    let reason = if is_self { "self" } else { "admin" };

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    let mut member = get_member(&state.members_ks, &member_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no Member row for {member_did}")))?;

    // Idempotent no-op if already false.
    if !member.personhood {
        return Ok((
            StatusCode::OK,
            Json(RevokeResponse {
                did: member_did,
                personhood: false,
                vmc: None,
                role_vec: None,
            }),
        ));
    }

    // Mint a fresh VMC + role VEC carrying personhood: false.
    let slot = member
        .status_list_index
        .ok_or_else(|| AppError::Internal("Member row has no status_list_index".into()))?;
    let sl_state = status_list::get_state(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
    )
    .await?
    .ok_or_else(|| AppError::Internal("revocation status list not initialised".into()))?;
    let status_ref = CredentialStatusRef::revocation(sl_state.list_credential_id.clone(), slot);

    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(&member_did)
            .with_id(vmc_id.clone())
            .with_status_ref(status_ref)
            .with_personhood(false),
    )
    .await?;
    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let acl_row = get_acl_entry(&state.acl_ks, &member_did)
        .await?
        .ok_or_else(|| AppError::Internal("ACL row disappeared mid-revoke".into()))?;
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(&member_did, acl_row.role.clone()).with_id(vec_id.clone()),
    )
    .await?;

    member.personhood = false;
    member.personhood_asserted_at = None;
    member.current_vmc_id = Some(vmc_id.clone());
    member.current_role_vec_id = Some(vec_id.clone());
    store_member(&state.members_ks, &member).await?;

    audit_writer
        .write(
            &auth.did,
            Some(&member_did),
            AuditEvent::PersonhoodRevoked(PersonhoodRevokedData {
                vmc_id: Some(vmc_id),
                reason: reason.into(),
            }),
        )
        .await?;

    info!(member_did = %member_did, reason, "personhood revoked");

    Ok((
        StatusCode::OK,
        Json(RevokeResponse {
            did: member_did,
            personhood: false,
            vmc: Some(
                serde_json::to_value(&vmc)
                    .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
            ),
            role_vec: Some(
                serde_json::to_value(&role_vec)
                    .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
            ),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verify the VP's data-integrity proof against the holder's
/// resolved `#key-0`. Mirrors the recognition::verify pattern
/// (the cross-community recognition flow does the same dance).
async fn verify_vp_proof(
    vp: &JsonValue,
    holder_did: &str,
    resolver: &DIDCacheClient,
) -> Result<(), String> {
    let proof_value = vp
        .get("proof")
        .ok_or_else(|| "missing proof block".to_string())?;
    let proof: DataIntegrityProof =
        serde_json::from_value(proof_value.clone()).map_err(|e| format!("parse proof: {e}"))?;

    // Strip the proof for verification (data-integrity
    // canonicalises over the doc-without-proof).
    let mut vp_without_proof = vp.clone();
    if let Some(obj) = vp_without_proof.as_object_mut() {
        obj.remove("proof");
    }

    // Resolve `{did}#key-0` (or whatever verificationMethod
    // the proof names) to public bytes.
    let verification_method = proof_value
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "proof missing verificationMethod".to_string())?;

    let resolved = resolver
        .resolve(holder_did)
        .await
        .map_err(|e| format!("DID resolve: {e}"))?;
    let vm = resolved
        .doc
        .verification_method
        .iter()
        .find(|m| m.id.as_str() == verification_method)
        .ok_or_else(|| format!("verificationMethod {verification_method} not on {holder_did}"))?;
    let pubkey = vm
        .get_public_key_bytes()
        .map_err(|e| format!("extract pubkey: {e}"))?;

    proof
        .verify_with_public_key(&vp_without_proof, &pubkey, VerifyOptions::new())
        .map_err(|e| format!("verify: {e}"))?;
    Ok(())
}

/// Eval the active `personhood.rego` with the assert-path
/// input shape:
///
/// ```json
/// { "applicant_did": "<did>", "vp_claims": <projection> }
/// ```
///
/// Fail-closed: any error path yields `false`.
async fn evaluate_personhood_assert(
    state: &AppState,
    applicant_did: &str,
    vp_claims: &JsonValue,
) -> Result<bool, AppError> {
    let Some(id) =
        get_active_policy_id(&state.active_policies_ks, PolicyPurpose::Personhood).await?
    else {
        warn!("no active personhood policy — assert rejected");
        return Ok(false);
    };
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal(format!("active personhood policy {id} not found")))?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;
    let input = json!({
        "applicant_did": applicant_did,
        "vp_claims": vp_claims,
    });
    let result = evaluate_policy(&compiled, "data.vtc.personhood.allow", input)?;
    Ok(result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// Suppress unused-import warning for `VerifiableCredential` —
// imported to allow Phase 5 expansion of the assert response
// to surface parsed VCs without a churn-y import change.
#[allow(dead_code)]
type _PhantomVc = (VerifiableCredential, Arc<()>);
