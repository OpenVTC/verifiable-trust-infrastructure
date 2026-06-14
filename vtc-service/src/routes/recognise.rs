//! `POST /v1/auth/recognise` — cross-community session mint.
//!
//! Phase 3 M3.10. Spec §8.4.
//!
//! The caller presents a foreign community's (`VEC`, `VMC`) pair **inside a
//! holder-signed W3C Verifiable Presentation**, the route runs the M3.9
//! verifier, evaluates `cross_community_roles.rego` to map the foreign role
//! onto a local role, and mints a session JWT with TTL clamped to
//! `min(jwt_default, vec.validUntil - now, vmc.validUntil - now)`.
//!
//! ## Holder proof-of-possession (P0.2 part 2)
//!
//! A VEC + VMC are bearer artifacts: anyone who captures the pair (a relayed
//! join, an audit log, a compromised member device) holds everything the old
//! `{vec, vmc}` body needed. Minting a session straight off them made the pair
//! a **replayable impersonation token** for the subject — no proof the caller
//! controls the subject's key, no replay nonce, no audience binding.
//!
//! The flow is now two-step and proof-of-possession bound:
//! 1. `POST /v1/auth/recognise/challenge` issues a single-use, TTL'd `nonce`
//!    bound to this VTC's DID (see [`crate::recognition::challenge`]).
//! 2. `POST /v1/auth/recognise` carries a **VP** whose holder
//!    `eddsa-jcs-2022` proof (`proofPurpose: authentication`) commits to that
//!    `nonce` (freshness/replay) + this VTC's DID as `domain` (audience), and
//!    embeds the VEC + VMC. The handler consumes the challenge, verifies the
//!    holder proof (proves possession of the subject key) plus each embedded
//!    credential's issuer proof, and refuses unless the **VP holder is the
//!    credential subject**. Only then does it run the recognition gate + mint.
//!
//! A captured VEC + VMC is now inert: the attacker can't produce the holder
//! signature over a fresh challenge, and a replayed VP finds its single-use
//! nonce already consumed.
//!
//! ## No refresh path
//!
//! Spec §8.4 + plan D5: cross-community sessions **never**
//! refresh. The standard `POST /v1/auth/refresh` route doesn't
//! carry the foreign credentials needed to re-run the
//! recognition check, so re-issuing a token without
//! re-verifying would defeat the "peer community removed
//! mid-session loses access" invariant. The session simply
//! expires when its clamped TTL elapses; the caller mints a
//! fresh one with the latest credentials.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::audit::{AuditEvent, CrossCommunitySessionMintedData};

use crate::auth::session::{Session, SessionState, now_epoch, store_session};
use crate::credentials::exchange::verify_vp_token;
use crate::error::AppError;
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};
use affinidi_data_integrity::VerificationMethodResolver;

use crate::credentials::vm_resolver::DidVmResolver;
use crate::recognition::{
    HttpStatusListFetcher, RecognitionError, VerifiedForeignCredential, challenge,
    verify_foreign_vec,
};
use crate::server::AppState;
use affinidi_vc::VerifiableCredential;

/// Request body for `POST /v1/auth/recognise`. The caller supplies a
/// holder-signed W3C Verifiable Presentation that embeds the foreign VEC and
/// VMC in `verifiableCredential` and binds the challenge `nonce` (top-level)
/// plus this VTC's DID as the `domain`. The route verifies the holder proof,
/// the embedded issuer proofs, the status list, and the registry recognition
/// itself.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RecogniseRequest {
    /// A W3C Data-Integrity VP, holder-signed with
    /// `proofPurpose: authentication`.
    pub presentation: JsonValue,
}

/// Response body for `POST /v1/auth/recognise/challenge`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RecogniseChallengeResponse {
    /// Single-use nonce the holder must bind into the VP's top-level `nonce`.
    pub nonce: String,
    /// Unix-epoch seconds at which the challenge expires.
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RecogniseResponse {
    pub session_id: String,
    pub data: RecogniseData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RecogniseData {
    /// Minted JWT. Carries the *mapped local* role, not the
    /// foreign one.
    pub access_token: String,
    pub access_expires_at: u64,
    /// Foreign issuer DID, surfaced so the caller can correlate
    /// the response with their request (the route doesn't echo
    /// the credentials).
    pub foreign_issuer_did: String,
    /// Local role the foreign role mapped to.
    pub mapped_role: String,
}

/// `POST /v1/auth/recognise/challenge` — issue a single-use, TTL'd nonce the
/// holder binds into their recognise VP. Bound to this VTC's DID as the
/// audience, so the resulting VP can't be replayed against a different VTC.
#[utoipa::path(
    post, path = "/auth/recognise/challenge", tag = "recognise",
    responses(
        (status = 200, description = "Single-use recognition nonce", body = RecogniseChallengeResponse),
    ),
)]
pub async fn recognise_challenge(
    State(state): State<AppState>,
) -> Result<Json<RecogniseChallengeResponse>, AppError> {
    let vtc_did = vtc_did(&state).await?;
    let now = Utc::now();
    let nonce = challenge::issue(
        &state.join_requests_ks,
        &vtc_did,
        challenge::DEFAULT_CHALLENGE_TTL,
        now,
    )
    .await?;
    let expires_at = (now + challenge::DEFAULT_CHALLENGE_TTL).timestamp() as u64;
    Ok(Json(RecogniseChallengeResponse { nonce, expires_at }))
}

/// `POST /v1/auth/recognise` — cross-community session mint from a
/// holder-signed VP embedding a foreign VEC + VMC.
#[utoipa::path(
    post, path = "/auth/recognise", tag = "recognise",
    request_body = RecogniseRequest,
    responses(
        (status = 200, description = "Minted cross-community session", body = RecogniseResponse),
        (status = 403, description = "Holder-binding, recognition gate, or role-mapping denied"),
    ),
)]
pub async fn recognise(
    State(state): State<AppState>,
    Json(req): Json<RecogniseRequest>,
) -> Result<Json<RecogniseResponse>, AppError> {
    // Pre-flight: the route depends on optional state. Refuse cleanly when a
    // piece is missing rather than 500ing mid-handler. The `resolver` is
    // needed immediately (VP holder + issuer proof verification); the
    // `registry_client` is acquired later, just before the recognition gate
    // that needs it, so the cheap caller-input + holder-binding checks
    // fail-fast first. `jwt_keys` is re-checked inside
    // `mint_recognised_session`, checked here only to surface a config issue
    // before any real verification runs.
    let resolver = state
        .did_resolver
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::Internal("DID resolver not configured".into()))?;
    state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    let now = Utc::now();

    // 1. Consume the challenge the holder bound into the VP. The nonce is read
    //    from the *unverified* VP purely to look it up; the holder signature
    //    over that same nonce is verified in step 2. Single-use + TTL: a
    //    replayed VP finds its nonce already consumed; a stale nonce is gone.
    let nonce = req
        .presentation
        .get("nonce")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            AppError::Validation("presentation carries no top-level `nonce` to consume".into())
        })?
        .to_string();
    let consumed = challenge::consume(&state.join_requests_ks, &nonce, now).await?;

    // 2. Verify the holder proof (proof-of-possession of the subject key) and
    //    bind freshness (`nonce`) + audience (`domain == consumed.aud`, this
    //    VTC's DID). `verify_vp_token` also verifies each embedded credential's
    //    issuer `eddsa-jcs-2022` proof + temporal validity. `did:key` holders
    //    and issuers resolve locally.
    //
    //    `verify_vp_token` reads a DCQL `vp_token` (a map keyed by query id) or
    //    a bare SD-JWT-VC string; recognise carries a single W3C DI VP, so wrap
    //    it in a one-entry map before handing it over.
    let vp_token = serde_json::json!({ "recognise": req.presentation });
    let verified_vp = verify_vp_token(
        &vp_token,
        &consumed.aud,
        &nonce,
        state.did_resolver.as_ref(),
        now,
    )
    .await?;
    let holder_did = verified_vp.holder;

    // 3. Pull the raw VEC + VMC back out of the (now holder-bound) VP so the
    //    recognition gate can run its status-list / registry / role checks.
    let (vec, vmc) = extract_vec_vmc(&req.presentation)?;

    // 4. Holder-binding (the headline of P0.2 part 2). The proven VP holder
    //    MUST be the credential subject — otherwise a captured VEC + VMC,
    //    re-wrapped in a VP signed by the *attacker's own* holder key, would
    //    still verify in step 2 and mint a session to the victim subject.
    //    Cheap (no network) and fail-fast, so it gates before the recognition
    //    HTTP calls. `verify_foreign_vec` independently binds
    //    `vmc.subject == vec.subject` (part 1), making this transitive to the
    //    returned `verified.subject_did`.
    let vec_subject = vc_subject_id(&vec)
        .ok_or_else(|| AppError::Validation("foreign VEC has no credentialSubject.id".into()))?;
    if holder_did != vec_subject {
        let err = RecognitionError::Malformed(format!(
            "VP holder `{holder_did}` is not the credential subject `{vec_subject}`"
        ));
        emit_denied_audit(&state, &holder_did, None, "holder-binding", None, &err).await;
        return Err(AppError::Forbidden(
            "presentation holder is not the foreign credential subject".into(),
        ));
    }

    let registry = state.registry_client.as_ref().cloned().ok_or_else(|| {
        AppError::Validation("trust-registry client not configured on this VTC".into())
    })?;
    let key_resolver: Arc<dyn VerificationMethodResolver> =
        Arc::new(DidVmResolver::new(Some(resolver)));
    // Verify the foreign status list's own issuer signature (bound to the
    // VEC/VMC issuer) before trusting it — the same key resolver the proof check
    // uses.
    let status_fetcher = HttpStatusListFetcher::with_issuer_verification(key_resolver.clone());

    // 5. Run the M3.9 recognition gate. Failures are mapped to `denied` audit
    //    envelopes (actor = the cryptographically-proven VP holder) + a 403.
    let verified = match verify_foreign_vec(
        &vec,
        &vmc,
        key_resolver.as_ref(),
        &status_fetcher,
        Arc::clone(&registry),
        now,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            emit_denied_audit(&state, &holder_did, None, e.reason_code(), None, &e).await;
            return Err(map_recognition_error(e));
        }
    };

    mint_recognised_session(&state, verified).await
}

/// This VTC's own DID — the audience a recognise challenge is bound to and the
/// `domain` the holder's VP must name.
async fn vtc_did(state: &AppState) -> Result<String, AppError> {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .ok_or_else(|| AppError::Validation("VTC DID not configured".into()))
}

/// Pull the foreign VEC + VMC out of a VP's `verifiableCredential`, classifying
/// by `type`. Both must be present exactly once. Accepts either a single object
/// or an array (the W3C VP shape).
fn extract_vec_vmc(
    presentation: &JsonValue,
) -> Result<(VerifiableCredential, VerifiableCredential), AppError> {
    let raw = presentation
        .get("verifiableCredential")
        .ok_or_else(|| AppError::Validation("presentation has no `verifiableCredential`".into()))?;
    let entries: Vec<&JsonValue> = match raw {
        JsonValue::Array(items) => items.iter().collect(),
        other => vec![other],
    };

    let mut vec_cred: Option<VerifiableCredential> = None;
    let mut vmc_cred: Option<VerifiableCredential> = None;
    for entry in entries {
        let cred: VerifiableCredential = serde_json::from_value(entry.clone()).map_err(|e| {
            AppError::Validation(format!("embedded credential is not a valid VC: {e}"))
        })?;
        // Route the credential to its slot by type. Other credential types are
        // ignored — the recognition gate only acts on the VEC + VMC pair.
        let (slot, label) = if cred
            .types
            .iter()
            .any(|t| t == "VerifiableEndorsementCredential")
        {
            (&mut vec_cred, "VerifiableEndorsementCredential")
        } else if cred
            .types
            .iter()
            .any(|t| t == "VerifiableMembershipCredential")
        {
            (&mut vmc_cred, "VerifiableMembershipCredential")
        } else {
            continue;
        };
        if slot.replace(cred).is_some() {
            return Err(AppError::Validation(format!(
                "presentation carries more than one {label}"
            )));
        }
    }

    let vec = vec_cred.ok_or_else(|| {
        AppError::Validation("presentation has no VerifiableEndorsementCredential".into())
    })?;
    let vmc = vmc_cred.ok_or_else(|| {
        AppError::Validation("presentation has no VerifiableMembershipCredential".into())
    })?;
    Ok((vec, vmc))
}

/// Read a credential's `credentialSubject.id`. `None` if absent or
/// id-less (a VEC the recognition gate would reject anyway).
fn vc_subject_id(vc: &VerifiableCredential) -> Option<String> {
    use affinidi_vc::SubjectValue;
    let subj = match &vc.credential_subject {
        SubjectValue::Single(m) => Some(m),
        SubjectValue::Multiple(v) => v.first(),
    }?;
    subj.get("id").and_then(|v| v.as_str()).map(str::to_string)
}

/// Post-verification half of the recognise flow — exposed at
/// `pub(crate)` so integration tests can exercise it without
/// faking a DID resolver. Production goes through
/// [`recognise`] which runs the verifier first; tests
/// hand-build a [`VerifiedForeignCredential`] (typestate
/// proof of "this credential passed the four checks") and
/// drive only the route-level concerns: role-mapping policy,
/// TTL clamp, session mint, audit emission.
pub async fn mint_recognised_session(
    state: &AppState,
    verified: VerifiedForeignCredential,
) -> Result<Json<RecogniseResponse>, AppError> {
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Run cross_community_roles.rego to map the foreign role
    // onto a local role. Deny is encoded as either:
    //   - `data.vtc.cross_community_roles.allow = false`, or
    //   - missing/null `mapped_role`.
    let mapped_role = match map_foreign_role(state, &verified).await? {
        Some(r) => r,
        None => {
            emit_denied_audit(
                state,
                &verified.subject_did,
                Some(verified.foreign_issuer_did.as_str()),
                "role-mapping-denied",
                Some(verified.foreign_role.as_str()),
                &RecognitionError::Malformed("policy denied role mapping".into()),
            )
            .await;
            return Err(AppError::Forbidden(format!(
                "cross_community_roles.rego denied mapping for foreign role '{}'",
                verified.foreign_role
            )));
        }
    };

    // Clamp the TTL to `min(jwt_default, vec.validUntil - now,
    // vmc.validUntil - now)`. The verifier already exposed the
    // *earliest* validUntil; we just compare to the configured
    // access-token TTL.
    let config = state.config.read().await;
    let jwt_default = config.auth.access_token_expiry;
    drop(config);

    let now = Utc::now();
    let creds_window_secs = (verified.earliest_valid_until - now).num_seconds().max(0) as u64;
    let access_expiry = jwt_default.min(creds_window_secs);
    if access_expiry == 0 {
        // Credentials expire before the next clock tick. Treat
        // as denied — minting a JWT that expires the same
        // instant it's issued is operator-hostile.
        emit_denied_audit(
            state,
            &verified.subject_did,
            Some(verified.foreign_issuer_did.as_str()),
            "validity-window",
            Some(verified.foreign_role.as_str()),
            &RecognitionError::ValidityWindow("credentials expire immediately".into()),
        )
        .await;
        return Err(AppError::Forbidden(
            "foreign credentials expire too soon to mint a session".into(),
        ));
    }

    // Mint the session. Mirror the existing
    // `authenticate` path: store a Session row + emit a JWT.
    // Skip the refresh token (cross-community sessions don't
    // refresh — see module docs). AAL is `did/aal1`: the foreign
    // VEC verification is a single-factor proof of the subject
    // DID; passkey or VTA step-up is not part of the recognise
    // flow.
    let session_id = format!("xc-{}", Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: verified.subject_did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&state.sessions_ks, &session).await?;

    let claims = jwt_keys
        .new_claims(
            verified.subject_did.clone(),
            session_id.clone(),
            mapped_role.clone(),
            Vec::new(),
            access_expiry,
            false,
        )
        .with_aal(vec!["did".to_string()], "aal1");
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    // Audit: minted.
    if let Some(writer) = state.audit_writer.as_ref() {
        let payload = CrossCommunitySessionMintedData {
            outcome: "minted".into(),
            foreign_issuer_did: verified.foreign_issuer_did.clone(),
            foreign_role: Some(verified.foreign_role.clone()),
            mapped_role: Some(mapped_role.clone()),
            ttl_seconds: Some(access_expiry),
            reason: None,
        };
        if let Err(e) = writer
            .write(
                &verified.subject_did,
                Some(&verified.subject_did),
                AuditEvent::CrossCommunitySessionMinted(payload),
            )
            .await
        {
            warn!(error = %e, "failed to emit CrossCommunitySessionMinted (minted) envelope");
        }
    }

    info!(
        subject = %verified.subject_did,
        issuer = %verified.foreign_issuer_did,
        mapped_role = %mapped_role,
        ttl = access_expiry,
        "cross-community session minted"
    );

    Ok(Json(RecogniseResponse {
        session_id,
        data: RecogniseData {
            access_token,
            access_expires_at,
            foreign_issuer_did: verified.foreign_issuer_did,
            mapped_role,
        },
    }))
}

/// Run `cross_community_roles.rego` against the verified
/// credential pair. Returns `Ok(Some(mapped_role))` on policy
/// allow, `Ok(None)` on deny. Errors propagate as
/// `AppError::Internal` because they indicate a workspace bug
/// (no policy, compile failure, etc.) — the operator has the
/// fallback "default deny" stub from M2.5.
async fn map_foreign_role(
    state: &AppState,
    verified: &VerifiedForeignCredential,
) -> Result<Option<String>, AppError> {
    let active_id = get_active_policy_id(
        &state.active_policies_ks,
        PolicyPurpose::CrossCommunityRoles,
    )
    .await?
    .ok_or_else(|| AppError::Internal("no active cross_community_roles policy".into()))?;
    let policy = get_policy(&state.policies_ks, active_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "active cross_community_roles policy {active_id} not found"
            ))
        })?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;

    let input = serde_json::json!({
        "foreign_vec": {
            "issuer": verified.foreign_issuer_did,
            "role": verified.foreign_role,
            "subject_did": verified.subject_did,
        },
        "action": "mint_session",
    });

    let allow = evaluate_policy(
        &compiled,
        "data.vtc.cross_community_roles.allow",
        input.clone(),
    )?;
    let allow = allow
        .pointer("/result/0/expressions/0/value")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if !allow {
        return Ok(None);
    }

    // Policy passed the allow gate; now read mapped_role.
    let mapped = evaluate_policy(
        &compiled,
        "data.vtc.cross_community_roles.mapped_role",
        input,
    )?;
    let mapped = mapped
        .pointer("/result/0/expressions/0/value")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    Ok(mapped)
}

fn map_recognition_error(e: RecognitionError) -> AppError {
    match e {
        RecognitionError::RegistryUnreachable(msg) => {
            AppError::Internal(format!("trust registry unreachable: {msg}"))
        }
        // All other variants are caller-driven rejection
        // signals → 403 Forbidden.
        other => AppError::Forbidden(other.to_string()),
    }
}

async fn emit_denied_audit(
    state: &AppState,
    actor_did: &str,
    foreign_issuer_did: Option<&str>,
    reason: &str,
    foreign_role: Option<&str>,
    _err: &RecognitionError,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let payload = CrossCommunitySessionMintedData {
        outcome: "denied".into(),
        foreign_issuer_did: foreign_issuer_did.unwrap_or("<unknown>").to_string(),
        foreign_role: foreign_role.map(str::to_string),
        mapped_role: None,
        ttl_seconds: None,
        reason: Some(reason.to_string()),
    };
    if let Err(e) = writer
        .write(
            actor_did,
            None,
            AuditEvent::CrossCommunitySessionMinted(payload),
        )
        .await
    {
        warn!(error = %e, "failed to emit CrossCommunitySessionMinted (denied) envelope");
    }
}
