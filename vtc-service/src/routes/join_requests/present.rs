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
//! route-layer hex signature), here `verified` rests on the holder `kb-jwt`
//! binding the verifier's `nonce` + audience — real VP cryptography.
//!
//! The DIDComm `credential-exchange/present` wire handler + the single-use
//! presentation-challenge store (freshness / replay) that sources
//! `expected_nonce` are the next slice; this operation takes the expected
//! audience + nonce as parameters so it is transport-agnostic and testable.

use chrono::{DateTime, Utc};
use serde_json::{Value as JsonValue, json};

use vti_common::error::AppError;

use crate::ceremony::{Credential, CredentialStatus, Presentation};
use crate::credentials::{VerifiedPresentationSet, verify_vp_token};
use crate::join::JoinTransport;
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
