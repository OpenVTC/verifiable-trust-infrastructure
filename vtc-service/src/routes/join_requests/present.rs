//! Credential-exchange `present` → join decision (close-the-join-loop, part 2).
//!
//! The VTA holder answers a verifier's DCQL query with an OID4VP `vp_token`
//! (the map keyed by `credential_query_id` that
//! `vta-service`'s `present_query` produces). This module is the VTC verifier's
//! decision path: it **cryptographically verifies** the `vp_token`
//! ([`crate::credentials::verify_vp_token`]), projects the verified set into the
//! ceremony [`Presentation`] evidence shape, runs the active **join** policy, and
//! realizes the verdict — auto-admitting (issuing the MembershipCredential) on
//! `allow`, else queuing / rejecting like the VP submit path.
//!
//! Unlike the VP submit path (whose `presentation.verified` rests on a
//! route-layer hex signature), here `verified` rests on the holder `kb-jwt` /
//! DI holder proof binding the verifier's `nonce` + audience — real VP
//! cryptography. [`present_and_decide_join`] takes the expected audience + nonce
//! as parameters so it is transport-agnostic; the DIDComm
//! `credential-exchange/present` handler (`messaging.rs`) sources them from the
//! single-use presentation challenge it consumes.
//!
//! This module also hosts the **query send side** ([`prepare_join_query`] +
//! [`send_query`]): the VTC issues the challenge and builds the DCQL query (from
//! a registered Accepts criterion) the holder answers.

use affinidi_openid4vp::DcqlQuery;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::QueryBody;

use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::ceremony::{Credential, CredentialStatus, Presentation};
use crate::credentials::present_challenge::{self, DEFAULT_CHALLENGE_TTL};
use crate::credentials::{VerifiedPresentationSet, verify_vp_token};
use crate::join::JoinTransport;
use crate::schemas::accepts::get_accepts;
use crate::server::AppState;

use super::submit::{JoinSubmitOutcome, decide_join, realize_join_verdict};

/// Verify a presented OID4VP `vp_token`, run the join decision, and realize it.
///
/// `expected_aud` is this VTC's identity (the `domain`/`aud` the holder bound
/// into the kb-jwt); `expected_nonce` is the single-use freshness value the VTC
/// issued with its query. On success the applicant is the **proven holder** of
/// the presentation. On `allow` the MembershipCredential is issued inline (the
/// returned [`JoinSubmitOutcome::admit`]).
pub async fn present_and_decide_join(
    state: &AppState,
    vp_token: &JsonValue,
    expected_aud: &str,
    expected_nonce: &str,
    transport: JoinTransport,
    now: DateTime<Utc>,
) -> Result<JoinSubmitOutcome, AppError> {
    // 1. Cryptographically verify every presentation in the vp_token. The holder
    //    is proven (kb-jwt / DI holder proof) and consistent across the set.
    //    did:webvh / did:web issuers + holders resolve through the DID cache.
    let set = verify_vp_token(
        vp_token,
        expected_aud,
        expected_nonce,
        state.did_resolver.as_ref(),
        now,
    )
    .await?;
    let applicant_did = set.holder.clone();

    // 2. Project the verified set into the ceremony evidence shape.
    let presentation = presentation_from_verified_set(&set);

    // 3 + 4. Decide under the active join policy, then realize the verdict.
    let verdict = decide_join(state, &applicant_did, presentation).await?;
    let vp_claims = vp_claims_from_set(&set);
    realize_join_verdict(
        state,
        &applicant_did,
        vp_token.clone(),
        vp_claims,
        false,
        JsonValue::Null,
        verdict,
        transport,
    )
    .await
}

// ---------------------------------------------------------------------------
// Query send side (close-the-join-loop, part B): the VTC issues the challenge
// and builds the DCQL query the holder answers.
// ---------------------------------------------------------------------------

/// Prepare a `credential-exchange/query` for a join: load the registered Accepts
/// DCQL criterion `criterion_id` (Phase 2 — the community's acceptance rule),
/// issue a **single-use presentation challenge** keyed by `thread_id` and bound
/// to the VTC's own DID, and assemble the [`QueryBody`] (the DCQL query + the
/// freshness nonce + a purpose shown to the holder).
///
/// The holder presents on this `thread_id`; the
/// `credential-exchange/present` handler consumes the challenge to recover the
/// nonce + audience and verify the presentation.
pub async fn prepare_join_query(
    state: &AppState,
    thread_id: &str,
    criterion_id: &str,
    now: DateTime<Utc>,
) -> Result<QueryBody, AppError> {
    let vtc_did = state.config.read().await.vtc_did.clone().ok_or_else(|| {
        AppError::Internal("VTC DID not configured — cannot bind a presentation challenge".into())
    })?;

    let criterion = get_accepts(&state.schemas_ks, criterion_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("no Accepts criterion `{criterion_id}` registered"))
        })?;
    let dcql_query = DcqlQuery::from_json(&criterion.query).map_err(|e| {
        AppError::Internal(format!(
            "registered Accepts criterion `{criterion_id}` is not a valid DCQL query: {e}"
        ))
    })?;

    let nonce = present_challenge::issue(
        &state.join_requests_ks,
        thread_id,
        &vtc_did,
        DEFAULT_CHALLENGE_TTL,
        now,
    )
    .await?;

    let purpose = criterion
        .description
        .unwrap_or_else(|| format!("join: present credentials satisfying `{criterion_id}`"));
    Ok(QueryBody {
        dcql_query,
        nonce,
        purpose,
    })
}

/// `POST /v1/join-requests/query` request — ask the VTC to prepare a join query
/// for `holderDid` from the named Accepts criterion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendQueryRequest {
    /// The holder the query is for (delivered to it over DIDComm by the VTC or a
    /// relayer — relayer ≠ holder is supported; the holder still proves binding).
    pub holder_did: String,
    /// The registered Accepts criterion whose DCQL query to send.
    pub criterion_id: String,
}

/// `POST /v1/join-requests/query` response — the prepared query to deliver, and
/// the thread the holder presents on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendQueryResponse {
    /// The DIDComm thread id the holder must reply on (the challenge is keyed by
    /// it; the `present` handler consumes it).
    pub thread_id: String,
    /// Echoed for the caller's correlation.
    pub holder_did: String,
    /// The `credential-exchange/query` body to deliver to the holder.
    pub query: QueryBody,
}

/// `POST /v1/join-requests/query` (admin) — prepare a `credential-exchange/query`
/// for `holderDid` from the Accepts criterion `criterionId`: issue the single-use
/// challenge and return the [`QueryBody`] to deliver. The VTC relays it over
/// DIDComm (or an out-of-band relayer delivers it — relayer ≠ holder is
/// supported); the holder presents on the returned `threadId`, and the
/// `credential-exchange/present` handler consumes the challenge.
pub async fn send_query(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<SendQueryRequest>,
) -> Result<Json<SendQueryResponse>, AppError> {
    let thread_id = Uuid::new_v4().to_string();
    let query = prepare_join_query(&state, &thread_id, &body.criterion_id, Utc::now()).await?;
    Ok(Json(SendQueryResponse {
        thread_id,
        holder_did: body.holder_did,
        query,
    }))
}

/// Project a [`VerifiedPresentationSet`] into the verified ceremony
/// [`Presentation`]. Crypto is already resolved, so `verified: true`. Issuer
/// trust (TRQP) and status-list resolution stay `false` / `Valid` — both are
/// follow-ups (the structured shape is what the policy decides over); the
/// credential `type` is the SD-JWT-VC `vct`.
fn presentation_from_verified_set(set: &VerifiedPresentationSet) -> Presentation {
    let credentials = set
        .presentations
        .iter()
        .map(|p| Credential {
            credential_type: p
                .vct
                .clone()
                .unwrap_or_else(|| "VerifiableCredential".to_string()),
            issuer: p.issuer_did.clone(),
            issuer_trusted: false,
            status: CredentialStatus::Valid,
            claims: p.claims.clone(),
            // SD-JWT-VC carries expiry in `exp` (epoch seconds).
            valid_until: p
                .claims
                .get("exp")
                .and_then(JsonValue::as_i64)
                .and_then(|s| DateTime::from_timestamp(s, 0)),
        })
        .collect();

    Presentation {
        verified: true,
        holder: set.holder.clone(),
        credentials,
    }
}

/// The lossy `vp_claims` admin-display projection (mirrors the VP path's
/// `extract_vp_claims`): the holder + a credential summary, persisted on the
/// join-request row for the admin show.
fn vp_claims_from_set(set: &VerifiedPresentationSet) -> JsonValue {
    let credentials: Vec<JsonValue> = set
        .presentations
        .iter()
        .map(|p| {
            json!({
                "issuer": p.issuer_did,
                "type": p.vct,
                "credentialSubject": p.claims,
            })
        })
        .collect();
    json!({ "holder": set.holder, "credentials": credentials })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_a_verified_set_into_ceremony_presentation() {
        use crate::credentials::VerifiedPresentation;

        let set = VerifiedPresentationSet {
            holder: "did:key:zHolder".into(),
            presentations: vec![VerifiedPresentation {
                issuer_did: "did:key:zIssuer".into(),
                holder_did: "did:key:zHolder".into(),
                vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
                claims: json!({ "givenName": "Alice", "exp": 1_900_000_000 }),
            }],
        };

        let p = presentation_from_verified_set(&set);
        assert!(p.verified);
        assert_eq!(p.holder, "did:key:zHolder");
        assert_eq!(p.credentials.len(), 1);
        assert_eq!(
            p.credentials[0].credential_type,
            "https://openvtc.org/credentials/MembershipCredential"
        );
        assert_eq!(p.credentials[0].issuer, "did:key:zIssuer");
        assert!(!p.credentials[0].issuer_trusted);
        assert_eq!(p.credentials[0].status, CredentialStatus::Valid);
        assert!(p.credentials[0].valid_until.is_some());
        assert_eq!(p.credentials[0].claims["givenName"], "Alice");
    }
}
