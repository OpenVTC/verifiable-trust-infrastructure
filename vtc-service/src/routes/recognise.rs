//! `POST /v1/auth/recognise` — cross-community session mint.
//!
//! Phase 3 M3.10. Spec §8.4.
//!
//! The route accepts a foreign community's (`VEC`, `VMC`) pair,
//! runs the M3.9 verifier, evaluates `cross_community_roles.rego`
//! to map the foreign role onto a local role, and mints a session
//! JWT with TTL clamped to
//! `min(jwt_default, vec.validUntil - now, vmc.validUntil - now)`.
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
use crate::error::AppError;
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};
use crate::recognition::{
    DidResolverKeyResolver, ForeignIssuerKeyResolver, HttpStatusListFetcher, RecognitionError,
    VerifiedForeignCredential, verify_foreign_vec,
};
use crate::server::AppState;
use affinidi_vc::VerifiableCredential;

/// Request body for `POST /v1/auth/recognise`. The caller
/// supplies the foreign VEC + VMC verbatim — the route
/// resolves the issuer's key + status list itself.
#[derive(Debug, Deserialize)]
pub struct RecogniseRequest {
    pub vec: VerifiableCredential,
    pub vmc: VerifiableCredential,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecogniseResponse {
    pub session_id: String,
    pub data: RecogniseData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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

pub async fn recognise(
    State(state): State<AppState>,
    Json(req): Json<RecogniseRequest>,
) -> Result<Json<RecogniseResponse>, AppError> {
    // Pre-flight: the route depends on three pieces of optional
    // state. Refuse cleanly when any is missing rather than
    // 500ing inside the handler.
    let registry = state.registry_client.as_ref().cloned().ok_or_else(|| {
        AppError::Validation("trust-registry client not configured on this VTC".into())
    })?;
    let resolver = state
        .did_resolver
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::Internal("DID resolver not configured".into()))?;
    // JWT-keys availability is re-checked inside
    // `mint_recognised_session` — but bail early when the
    // verifier hasn't been wired either, so the response is
    // shaped by config issues rather than running a real
    // verification first.
    state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    let key_resolver: Arc<dyn ForeignIssuerKeyResolver> =
        Arc::new(DidResolverKeyResolver::new(resolver));
    // Verify the foreign status list's own issuer signature (bound to the
    // VEC/VMC issuer) before trusting it — the same key resolver the proof check
    // uses.
    let status_fetcher = HttpStatusListFetcher::with_issuer_verification(
        reqwest::Client::new(),
        key_resolver.clone(),
    );

    let actor_did_for_audit = req.vec.credential_subject_id_for_audit();

    // Run the M3.9 verifier. Failures are mapped to `denied`
    // audit envelopes + a 403 response.
    let verified = match verify_foreign_vec(
        &req.vec,
        &req.vmc,
        key_resolver.as_ref(),
        &status_fetcher,
        Arc::clone(&registry),
        Utc::now(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            emit_denied_audit(
                &state,
                &actor_did_for_audit,
                None,
                e.reason_code(),
                None,
                &e,
            )
            .await;
            return Err(map_recognition_error(e));
        }
    };

    mint_recognised_session(&state, verified).await
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

// Helper trait — extracts the subject DID from the VEC even
// when verification hasn't run yet, so audit envelopes for the
// `denied` arm can still name an actor when possible.
trait CredentialSubjectIdAccessor {
    fn credential_subject_id_for_audit(&self) -> String;
}

impl CredentialSubjectIdAccessor for VerifiableCredential {
    fn credential_subject_id_for_audit(&self) -> String {
        use affinidi_vc::SubjectValue;
        let subj_map = match &self.credential_subject {
            SubjectValue::Single(m) => Some(m.clone()),
            SubjectValue::Multiple(v) => v.first().cloned(),
        };
        subj_map
            .and_then(|m| m.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .unwrap_or_else(|| "<unknown-subject>".into())
    }
}
