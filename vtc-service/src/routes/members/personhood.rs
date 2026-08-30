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
//!      expired / wrong-DID). The challenge must appear **both** at
//!      `proof.challenge` (what the published task names) and at
//!      top-level `nonce` (what the holder's signature actually
//!      covers) — see step 1a in [`assert_inner`] for why one
//!      without the other is not a binding at all.
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
//!
//! ## Not only REST
//!
//! `challenge` and `assert` are also routed by the messaging Trust
//! Task dispatcher (`crate::trust_tasks`), so a member client that
//! speaks DIDComm or TSP and holds no bearer token — `openvtc` — can
//! run the ceremony. Both transports call the same
//! [`challenge_inner`] / [`assert_inner`]; only the caller-identity
//! gate differs, because a session and a proven sender are different
//! things. See the handlers there for what each one checks.

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
use crate::members::{get_member, match_code, store_member};
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
#[derive(utoipa::ToSchema)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub expires_at: DateTime<Utc>,
    /// Vendor-namespaced extension members (SPEC §4.5.1). Carries
    /// [`match_code::MATCH_CODE_EXT_KEY`] — the eight characters the
    /// admin and the member read to each other to confirm they are
    /// looking at the same ceremony. See [`crate::members::match_code`]
    /// for why the code rides here rather than as a top-level field.
    pub ext: JsonValue,
}

/// POST /members/{did}/personhood/challenge — mint a personhood challenge.
/// Auth: any authenticated session.
#[utoipa::path(
    post, path = "/members/{did}/personhood/challenge",
    operation_id = "personhoodChallenge", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    responses(
        (status = 200, description = "Personhood challenge minted", body = ChallengeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn challenge(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
) -> Result<(StatusCode, Json<ChallengeResponse>), AppError> {
    Ok((
        StatusCode::OK,
        Json(challenge_inner(&state, &member_did).await?),
    ))
}

/// Mint a personhood challenge for `member_did`.
///
/// Transport-free so both front ends share one implementation: the REST
/// route above, and the `members/personhood/challenge` Trust Task the
/// messaging dispatcher routes. A member on DIDComm or TSP is running
/// the same ceremony as a member on REST, and a divergence between the
/// two would be a security difference nothing tests.
pub(crate) async fn challenge_inner(
    state: &AppState,
    member_did: &str,
) -> Result<ChallengeResponse, AppError> {
    vti_common::identifier::validate_did("did", member_did)?;
    // Member must exist — minting a challenge for a non-member
    // is operator-confusing and serves no purpose.
    let _ = get_acl_entry(&state.acl_ks, member_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no ACL row for {member_did}")))?;

    let id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
    let chal = PersonhoodChallenge {
        id,
        member_did: member_did.to_string(),
        expires_at,
    };
    store_challenge(state, &chal).await?;

    // Derived, not stored: any holder of the challenge id computes the
    // same code, so there is nothing here to persist or to check later.
    let code = match_code::derive(id);

    info!(
        member_did = %member_did,
        challenge_id = %id,
        // The code is a function of the challenge id, which is already
        // on this line — logging it leaks nothing further, and an
        // operator reading the journal can see what the member was
        // asked to confirm.
        match_code = %code,
        "personhood challenge minted"
    );

    Ok(ChallengeResponse {
        challenge_id: id,
        expires_at,
        ext: json!({ match_code::MATCH_CODE_EXT_KEY: code }),
    })
}

// ---------------------------------------------------------------------------
// Assert endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssertBody {
    /// W3C Verifiable Presentation. `holder` must equal the
    /// path-DID; `proof.challenge` must equal a fresh challenge
    /// id from `POST .../personhood/challenge`.
    pub presentation: JsonValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct AssertResponse {
    pub did: String,
    pub personhood: bool,
    pub vmc: JsonValue,
    pub role_vec: JsonValue,
}

/// POST /members/{did}/personhood — assert personhood via a VP.
/// Auth: any authenticated session.
#[utoipa::path(
    post, path = "/members/{did}/personhood", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = AssertBody,
    responses(
        (status = 200, description = "Personhood asserted", body = AssertResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Personhood proof invalid / policy denied"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn assert(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
    Json(body): Json<AssertBody>,
) -> Result<(StatusCode, Json<AssertResponse>), AppError> {
    Ok((
        StatusCode::OK,
        Json(assert_inner(&state, &member_did, &body.presentation).await?),
    ))
}

/// Verify a personhood presentation and, if the active policy allows it,
/// set the flag and re-issue the member's credentials.
///
/// Transport-free, for the same reason as [`challenge_inner`]: the REST
/// route and the `members/personhood/assert` Trust Task must be the same
/// ceremony, not two implementations that agree today.
///
/// Note what is deliberately *not* a parameter — the caller's identity.
/// `assert/0.1` §Authorization makes the presentation the gate: holder
/// equality binds the assertion to the party it is about, and the
/// single-use challenge binds it to this exchange. Neither is a claim
/// about who delivered the bytes, so a relaying transport does not get a
/// say here.
pub(crate) async fn assert_inner(
    state: &AppState,
    member_did: &str,
    presentation: &JsonValue,
) -> Result<AssertResponse, AppError> {
    vti_common::identifier::validate_did("did", member_did)?;
    // Load Member row first — `404` for an unknown subject
    // is the most actionable failure mode.
    let mut member = get_member(&state.members_ks, member_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no Member row for {member_did}")))?;

    // 1. Extract + consume the challenge before any daemon-
    //    config checks so malformed callers can't observe a
    //    500 (which would otherwise mask their own bad input).
    let proof = presentation
        .get("proof")
        .ok_or_else(|| AppError::Validation("presentation missing proof block".into()))?;
    let challenge_str = proof
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("proof.challenge missing or not a string".into()))?;
    let challenge_id: Uuid = challenge_str
        .parse()
        .map_err(|e| AppError::Validation(format!("proof.challenge not a UUID: {e}")))?;

    // 1a. The challenge must also appear **inside the signed body**.
    //
    // `assert/0.1` §Authorization says the challenge binding "establishes
    // that this presentation was made for this exchange, and is what stops
    // one captured and replayed into another". W3C Data Integrity gets that
    // by canonicalising the proof options alongside the document, so
    // `challenge` is signed — but `affinidi_data_integrity`'s
    // `DataIntegrityProof` has no `challenge` field, and
    // [`verify_vp_proof`] verifies over the VP with the whole `proof` block
    // removed. So `proof.challenge` alone is **unsigned**: anyone holding a
    // captured VP could mint a fresh challenge for that member, swap the
    // value in, and replay it — the signature would still verify, because
    // it never covered the challenge.
    //
    // Requiring the same value at top-level `nonce` closes that. `nonce` is
    // outside the proof block, so it *is* covered by the holder's
    // signature, and it is the field `vta_sdk::vp::build_di_vp` already
    // emits. A presentation is now bound to its exchange by something the
    // holder actually signed.
    let nonce = presentation
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::Validation(
                "presentation missing `nonce` — the challenge must appear inside the signed \
                 body, not only in the unsigned proof block"
                    .into(),
            )
        })?;
    if nonce != challenge_str {
        return Err(AppError::Validation(format!(
            "presentation nonce ({nonce}) != proof.challenge ({challenge_str}) — the signed \
             and unsigned copies of the challenge disagree"
        )));
    }
    let chal = take_challenge(state, challenge_id)
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

    // 2. Verify the VP's holder field matches. `assert/0.1`
    //    §Authorization: holder equality is what establishes that the
    //    assertion is about the party making it, and it does not
    //    substitute for the challenge binding above — a consumer
    //    checking only one of the two accepts either replays or
    //    assertions made on someone else's behalf.
    let holder = presentation
        .get("holder")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("presentation missing holder".into()))?;
    if holder != member_did {
        return Err(AppError::Validation(format!(
            "presentation holder ({holder}) != subject DID ({member_did})"
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
    verify_vp_proof(presentation, member_did, &resolver)
        .await
        .map_err(|e| AppError::Forbidden(format!("personhood-proof-invalid: {e}")))?;

    // 5. Extract vp_claims for policy input. (Per D2 review,
    //    embedded-VC proofs are surfaced to the policy via
    //    extract but not verified at the route — operators
    //    wanting strict VC verification upload custom rego.)
    let vp_claims = extract_vp_claims(presentation);

    // 6. Run personhood.rego.
    let allow =
        evaluate_personhood_assert(state, member_did, signer.issuer_did(), &vp_claims).await?;
    if !allow {
        return Err(AppError::Forbidden(
            "personhood-policy-denied: active personhood.rego rejected the assertion".into(),
        ));
    }

    // 6a. One membership per person, when this community's governance says so.
    //
    // The switch is the community's own `personhood.singleMembership`
    // declaration, which is deliberate: the declaration and the enforcement
    // are the same flag, so a community cannot publish the claim without the
    // daemon starting to check it. DTG Credentials makes PHC status a
    // governance determination; this makes the governance determination
    // load-bearing rather than decorative.
    //
    // Runs after the policy, not before. The policy decides whether the
    // evidence is acceptable at all, and asking "has this person been here
    // before" about evidence that was about to be rejected would leak whether
    // a pseudonym is claimed to anyone who can present anything.
    enforce_single_membership(state, member_did, signer.issuer_did(), &vp_claims).await?;

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
        VmcParams::new(member_did)
            .with_id(vmc_id.clone())
            .with_status_ref(status_ref)
            .with_personhood(true),
    )
    .await?;
    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let acl_row = get_acl_entry(&state.acl_ks, member_did)
        .await?
        .ok_or_else(|| AppError::Internal("ACL row disappeared mid-assert".into()))?;
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(member_did, acl_row.role.clone()).with_id(vec_id.clone()),
    )
    .await?;

    // 8. Update Member row.
    member.personhood = true;
    member.personhood_asserted_at = Some(now);
    member.status_list_index = Some(slot);
    // Keep the bodies, not just the ids — see [`crate::members::Member::current_vmc`].
    // Asserting or revoking personhood re-mints the grant (the flag is a claim on
    // it), so the digest changes and the acknowledgement bound to the previous
    // grant no longer matches: `record_issued_credentials` drops it, leaving the
    // member visibly owing a fresh one.
    let vmc_value = serde_json::to_value(&vmc)
        .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
    let role_vec_value = serde_json::to_value(&role_vec)
        .map_err(|e| AppError::Internal(format!("serialise role VEC: {e}")))?;
    member.record_issued_credentials(vmc_value, role_vec_value);
    store_member(&state.members_ks, &member).await?;

    // 9. Audit.
    audit_writer
        .write(
            member_did,
            Some(member_did),
            AuditEvent::PersonhoodAsserted(PersonhoodAssertedData {
                vmc_id: vmc_id.clone(),
                asserted_at: rfc3339(now),
            }),
        )
        .await?;

    info!(member_did = %member_did, "personhood asserted");

    Ok(AssertResponse {
        did: member_did.to_string(),
        personhood: true,
        vmc: serde_json::to_value(&vmc)
            .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
        role_vec: serde_json::to_value(&role_vec)
            .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
    })
}

// ---------------------------------------------------------------------------
// Revoke endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeResponse {
    pub did: String,
    pub personhood: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

/// DELETE /members/{did}/personhood — revoke personhood. Auth: Admin or self.
#[utoipa::path(
    delete, path = "/members/{did}/personhood",
    operation_id = "personhoodRevoke", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    responses(
        (status = 200, description = "Personhood revoked", body = RevokeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is neither admin nor the subject member"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn revoke(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    vti_common::identifier::validate_did("did", &member_did)?;
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
    // Keep the bodies, not just the ids — see [`crate::members::Member::current_vmc`].
    // Asserting or revoking personhood re-mints the grant (the flag is a claim on
    // it), so the digest changes and the acknowledgement bound to the previous
    // grant no longer matches: `record_issued_credentials` drops it, leaving the
    // member visibly owing a fresh one.
    let vmc_value = serde_json::to_value(&vmc)
        .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
    let role_vec_value = serde_json::to_value(&role_vec)
        .map_err(|e| AppError::Internal(format!("serialise role VEC: {e}")))?;
    member.record_issued_credentials(vmc_value, role_vec_value);
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
/// Enforce one-membership-per-person, if this community's governance claims it.
///
/// A no-op when `personhood.singleMembership` is unset, which is every
/// community that has not published the claim. When it *is* set, the assertion
/// must carry a pseudonym from a provider the community accepts, and that
/// pseudonym must not already belong to somebody else.
///
/// ## Why absence is a refusal
///
/// A community that publishes `singleMembership: true` is telling verifiers
/// its VMCs are PHCs. If an assertion with no pseudonym were allowed through,
/// that member would hold a credential asserting a property nobody checked —
/// and the community would have no way to know which of its members were
/// covered. Refusing is the only outcome that keeps the published claim true.
///
/// The error names the missing thing, because an operator hitting this has
/// almost certainly turned the flag on before arranging an IDVP, and
/// "personhood-policy-denied" would send them to the wrong file.
async fn enforce_single_membership(
    state: &AppState,
    member_did: &str,
    community_did: &str,
    vp_claims: &JsonValue,
) -> Result<(), AppError> {
    let governance = crate::community::load_profile(&state.community_ks)
        .await?
        .map(|p| p.personhood)
        .unwrap_or_default();
    if !governance.single_membership {
        return Ok(());
    }

    let pseudonyms = crate::members::pseudonym::extract(vp_claims, &governance.accepted_idvps);
    if pseudonyms.is_empty() {
        return Err(AppError::Forbidden(
            "personhood-pseudonym-missing: this community enforces one membership per person, \
             so an assertion must carry a pseudonym from an accepted identity-verification \
             provider (see the community profile's personhood.acceptedIdvps)"
                .into(),
        ));
    }

    // Every presented pseudonym is claimed, not just the first. A member may
    // legitimately present two accepted IDVCs; if either names a person
    // already here, they are that person.
    for pseudonym in &pseudonyms {
        crate::members::pseudonym::claim(&state.members_ks, community_did, pseudonym, member_did)
            .await?;
    }
    Ok(())
}

/// Evaluate the active `personhood.rego` over the presented claims.
///
/// `community_did` is the DID the community signs its own credentials
/// with. It is passed in — rather than left for the policy to hardcode —
/// because the default policy's identity-verification rule has to
/// distinguish "this community vetted the applicant" from "*somebody*
/// issued a credential that says `IdentityVerification`". Without the
/// comparison, any issuer in the world could mint the endorsement that
/// unlocks personhood here.
async fn evaluate_personhood_assert(
    state: &AppState,
    applicant_did: &str,
    community_did: &str,
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
        "community_did": community_did,
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

#[cfg(test)]
mod single_membership_tests {
    use super::*;
    use crate::community::{CommunityProfile, PersonhoodGovernance, store_profile};
    use crate::test_support::TestVtc;

    const COMMUNITY: &str = "did:webvh:acme.example";
    const IDVP: &str = "did:webvh:idvp.example";
    const ALICE: &str = "did:key:zAlice";
    const BOB: &str = "did:key:zBob";

    /// A VTC whose governance carries `governance`.
    async fn vtc_with(governance: PersonhoodGovernance) -> TestVtc {
        let vtc = TestVtc::builder().build().await;
        let mut profile = CommunityProfile::new(COMMUNITY, "Acme");
        profile.personhood = governance;
        store_profile(&vtc.state.community_ks, &profile)
            .await
            .expect("seed profile");
        vtc
    }

    fn claims_with_pseudonym(issuer: &str, pseudonym: &str) -> JsonValue {
        json!({
            "holder": ALICE,
            "credentials": [{
                "issuer": issuer,
                "credentialSubject": { "id": ALICE, "pseudonym": pseudonym },
            }]
        })
    }

    fn enforcing() -> PersonhoodGovernance {
        PersonhoodGovernance {
            real_human: true,
            single_membership: true,
            accepted_idvps: vec![IDVP.into()],
            governance_framework_url: None,
        }
    }

    /// **The property that ties the two halves together.** A community that
    /// has not published the claim is not silently policed — every existing
    /// deployment keeps working exactly as before, with no pseudonym anywhere
    /// in sight.
    #[tokio::test]
    async fn a_community_that_claims_nothing_enforces_nothing() {
        let vtc = vtc_with(PersonhoodGovernance::default()).await;

        enforce_single_membership(
            &vtc.state,
            ALICE,
            COMMUNITY,
            &json!({ "holder": ALICE, "credentials": [] }),
        )
        .await
        .expect("no claim, no enforcement");
    }

    /// And the converse: publishing the claim turns the check on. The
    /// declaration *is* the switch, so a community cannot advertise PHC
    /// status to verifiers while quietly not checking it.
    #[tokio::test]
    async fn publishing_the_claim_turns_enforcement_on() {
        let vtc = vtc_with(enforcing()).await;

        let err = enforce_single_membership(
            &vtc.state,
            ALICE,
            COMMUNITY,
            &json!({ "holder": ALICE, "credentials": [] }),
        )
        .await
        .expect_err("an enforcing community must refuse evidence it cannot check");

        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        assert!(
            err.to_string().contains("personhood-pseudonym-missing"),
            "the operator needs to be sent to acceptedIdvps, not to the rego: {err}"
        );
    }

    /// The happy path: an accepted provider's pseudonym is claimed.
    #[tokio::test]
    async fn an_accepted_pseudonym_is_claimed() {
        let vtc = vtc_with(enforcing()).await;

        enforce_single_membership(
            &vtc.state,
            ALICE,
            COMMUNITY,
            &claims_with_pseudonym(IDVP, "person-1"),
        )
        .await
        .expect("first assertion");

        let held = crate::members::pseudonym::holder(&vtc.state.members_ks, COMMUNITY, "person-1")
            .await
            .expect("read")
            .expect("claimed");
        assert_eq!(held.member_did, ALICE);
    }

    /// The whole point: the same person, a second DID, refused.
    #[tokio::test]
    async fn the_same_person_cannot_join_twice() {
        let vtc = vtc_with(enforcing()).await;
        let claims = claims_with_pseudonym(IDVP, "person-1");

        enforce_single_membership(&vtc.state, ALICE, COMMUNITY, &claims)
            .await
            .expect("first");

        let err = enforce_single_membership(&vtc.state, BOB, COMMUNITY, &claims)
            .await
            .expect_err("one membership per person");
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
    }

    /// Asserting again as the same member is not a duplicate — a second
    /// challenge or a renewed credential is the same human.
    #[tokio::test]
    async fn the_same_member_may_assert_again() {
        let vtc = vtc_with(enforcing()).await;
        let claims = claims_with_pseudonym(IDVP, "person-1");

        enforce_single_membership(&vtc.state, ALICE, COMMUNITY, &claims)
            .await
            .expect("first");
        enforce_single_membership(&vtc.state, ALICE, COMMUNITY, &claims)
            .await
            .expect("re-asserting is not a second person");
    }

    /// A pseudonym from an issuer the community has not published is not
    /// evidence of anything. Without this, anyone could mint themselves an
    /// unclaimed pseudonym and uniqueness would be decorative.
    #[tokio::test]
    async fn an_unaccepted_issuer_cannot_establish_uniqueness() {
        let vtc = vtc_with(enforcing()).await;

        let err = enforce_single_membership(
            &vtc.state,
            ALICE,
            COMMUNITY,
            &claims_with_pseudonym("did:key:zStranger", "person-1"),
        )
        .await
        .expect_err("an unaccepted issuer proves nothing");
        assert!(
            err.to_string().contains("personhood-pseudonym-missing"),
            "an unaccepted pseudonym is absent, not present-and-rejected: {err}"
        );
    }
}
