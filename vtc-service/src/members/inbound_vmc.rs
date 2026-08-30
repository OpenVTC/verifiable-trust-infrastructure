//! Receive + verify a member-issued **VMC** (member → community half of the
//! membership pair) and record it on the member's row.
//!
//! The VTC issues a `MembershipCredential` to each member at
//! admission; this is the reciprocal the member issues back, naming the
//! community as its `credentialSubject`. The `eddsa-jcs-2022` issuer proof (key
//! under the member's DID, resolved via [`DidVmResolver`] so `did:webvh`
//! personas verify, not just `did:key`) IS the authentication of the
//! credential. Over DIDComm the authcrypt sender independently authenticates
//! `member_did`; the two must agree.
//!
//! Shared by the DIDComm `members/vmc/1.0` handler and the Trust Task
//! document dispatcher (REST/TSP).
//!
//! With `vtc/members/vmc/0.1`'s optional `requestId`, this path also closes an
//! **approved join request**: the delivered credential doubles as the member's
//! reciprocal half of the join, superseding the retired
//! `join-requests/accept/0.1` task (one credential-delivery path, not two).

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, MembershipReciprocatedData};
use vti_common::error::AppError;

use vta_sdk::protocols::members::MEMBERSHIP_CREDENTIAL_TYPE;

use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
use crate::join::{JoinStatus, get_join_request};
use crate::members::{get_member, store_member};
use crate::server::AppState;

/// What [`receive_member_vmc_inner`] recorded.
pub struct MemberVmcOutcome {
    pub member_did: String,
    pub vmc_id: String,
    /// `false` when the same VMC was already stored (idempotent re-send) — the
    /// caller skips re-auditing / re-logging the store.
    pub recorded: bool,
    /// The join request this delivery closed, echoed into the receipt.
    /// `None` when the submission carried no `requestId`.
    pub request_id: Option<Uuid>,
}

/// Verify a member-issued VMC and store it on the member's row.
///
/// Checks: the member exists and is active; `vc.issuer == member_did`; `type`
/// includes [`MEMBERSHIP_CREDENTIAL_TYPE`];
/// `credentialSubject.id == <this VTC's DID>`; the issuer DI proof's
/// `verificationMethod` is under the member and verifies against the resolved
/// key. Idempotent: re-sending the same `id` is a no-op.
///
/// When `request_id` is `Some`, the named join request must exist, be
/// `Approved`, and belong to `member_did`; on success the stored credential is
/// additionally recorded as the reciprocal half of that join
/// (`Member::record_reciprocation`) and the reciprocation audited. Re-sending
/// the same credential with the same `request_id` stays a no-op.
pub async fn receive_member_vmc_inner(
    state: &AppState,
    member_did: String,
    vc: JsonValue,
    request_id: Option<Uuid>,
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

    // Credential-level verification first, so a malformed or wrongly-signed
    // credential is reported as exactly that. Reading the member row ahead of
    // it would turn a wrong-signer delivery into "no such member", which names
    // the wrong failure (R6.4).
    let vmc_id = verify_member_vmc(state, &vc, &member_did, &community_did).await?;

    // Resolve + validate the join request BEFORE any write, so a bad
    // `requestId` can't half-apply the delivery.
    if let Some(req_id) = request_id {
        let req = get_join_request(&state.join_requests_ks, req_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("join request not found: {req_id}")))?;
        if req.applicant_did != member_did {
            return Err(AppError::Validation(format!(
                "join request {req_id} does not belong to the delivering member"
            )));
        }
        if req.status != JoinStatus::Approved {
            return Err(AppError::Conflict(format!(
                "join request {req_id} is {:?}; only an Approved request has a membership to reciprocate",
                req.status
            )));
        }
    }

    // The member must exist and be active.
    let mut member = get_member(&state.members_ks, &member_did)
        .await?
        .filter(|m| !m.is_removed())
        .ok_or_else(|| AppError::NotFound(format!("no active member: {member_did}")))?;

    // Does this acknowledgement bind to the grant we issued? DTG Core
    // Credentials: "A member-issued VMC whose `digest` does not match a valid
    // community-issued VMC MUST NOT be treated as completing a membership
    // edge." A mismatch is refused outright; an *absent* digest is stored but
    // leaves the edge incomplete — see [`check_acknowledgement_binding`].
    //
    // Ahead of the idempotency check below, not after it: once the grant has
    // been re-issued, an acknowledgement that used to bind no longer does, and
    // a re-send of it should be refused rather than quietly no-oped.
    let bound = check_acknowledgement_binding(&vc, member.current_vmc.as_ref(), &member_did)?;

    // Idempotency: the same VMC re-sent is a no-op; a *different* VMC replaces
    // the stored one (a renewal — the member rotated/reissued their half).
    if member.member_vmc_id.as_deref() == Some(vmc_id.as_str()) {
        // A repeat delivery that repeats the same `requestId` is equally a
        // no-op — the reciprocation is already recorded below.
        return Ok(MemberVmcOutcome {
            member_did,
            vmc_id,
            recorded: false,
            request_id,
        });
    }

    member.record_member_vmc(vmc_id.clone(), vc, bound);
    // Closing a join request: the delivered credential IS the reciprocal half
    // of the join, so the edge is marked reciprocated with the same id.
    if request_id.is_some() {
        member.record_reciprocation(vmc_id.clone());
    }
    store_member(&state.members_ks, &member).await?;

    if let Some(req_id) = request_id {
        let audit_writer = state
            .audit_writer
            .as_ref()
            .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
        audit_writer
            .write(
                &member_did,
                Some(&member_did),
                AuditEvent::MembershipReciprocated(MembershipReciprocatedData {
                    request_id: req_id.to_string(),
                    vmc_id: vmc_id.clone(),
                    reciprocal_vc_id: vmc_id.clone(),
                }),
            )
            .await?;
    }

    info!(
        member = %member_did,
        vmc_id = %vmc_id,
        closed_request = ?request_id,
        "stored member-issued VMC (member → community half of the pair)"
    );

    Ok(MemberVmcOutcome {
        member_did,
        vmc_id,
        recorded: true,
        request_id,
    })
}

/// Verify the member-issued VMC and return its top-level `id`.
/// Does this acknowledgement bind to the grant the community issued?
///
/// Returns whether the edge is **complete**: `true` only when the
/// acknowledgement carries a `digest` and it matches the stored grant.
///
/// # Three outcomes, not two
///
/// A mismatch is an error — the member acknowledged *something*, and it was not
/// this membership. Storing it would leave the community able to show an
/// acknowledgement that does not answer the grant it holds, which is precisely
/// the unconsented-membership claim the pair exists to prevent.
///
/// An acknowledgement with **no** `digest` is not an error but does not
/// complete the edge either. Two populations reach here without one: members on
/// clients that predate the digest requirement, and members whose grant this
/// service issued before it kept credential bodies (`current_vmc` is `None`, so
/// there is nothing to check against). Refusing them would unmake memberships
/// that were validly formed under the rules in force when they were made.
/// Storing them unbound keeps the credential visible to the operator while
/// leaving the edge honestly incomplete — which is what
/// `POST /v1/members/{did}/request-vmc` exists to resolve.
///
/// Deliberate asymmetry, and the reason it is safe: an unbound acknowledgement
/// claims *less* than a bound one, so admitting it grants nothing. A
/// mismatched one claims something false.
fn check_acknowledgement_binding(
    vc: &JsonValue,
    grant: Option<&JsonValue>,
    member_did: &str,
) -> Result<bool, AppError> {
    let claimed = vc
        .get("credentialSubject")
        .and_then(JsonValue::as_object)
        .and_then(|s| s.get("digest"))
        .and_then(JsonValue::as_str);

    let (Some(claimed), Some(grant)) = (claimed, grant) else {
        // R6.3: say which of the two is missing, so an operator looking at an
        // incomplete edge can tell "the member's client is old" from "we never
        // kept the grant to check against".
        tracing::warn!(
            member = %member_did,
            digest_present = claimed.is_some(),
            grant_stored = grant.is_some(),
            "member VMC stored without a verified digest — the membership edge is \
             not complete; ask the member to re-issue with `request-vmc`"
        );
        return Ok(false);
    };

    let expected = crate::credentials::ingress::dtg_credential_digest(grant)?;
    if claimed != expected {
        return Err(AppError::Validation(format!(
            "member vmc `credentialSubject.digest` does not match the membership \
             credential this community issued to {member_did} — it acknowledges a \
             different grant. Re-issue against the current one."
        )));
    }

    Ok(true)
}

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
                .any(|t| t == MEMBERSHIP_CREDENTIAL_TYPE)
        });
    if !has_type {
        return Err(AppError::Validation(format!(
            "member vmc `type` must include `{MEMBERSHIP_CREDENTIAL_TYPE}`"
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

#[cfg(test)]
mod binding_tests {
    use super::*;

    /// A grant and the acknowledgement built from it, in the wire form each
    /// side actually holds. Built through `dtg_credentials` rather than
    /// hand-rolled, so the fixture is what the catalog mints — a literal here
    /// could agree with this module while disagreeing with every real client.
    fn pair() -> (JsonValue, JsonValue) {
        use chrono::TimeZone;
        let valid_from = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

        let grant = dtg_credentials::DTGCredential::new_vmc(
            "did:web:community.example".to_string(),
            "did:key:zMember".to_string(),
            valid_from,
            None,
            false,
        )
        .with_id("urn:uuid:grant-1");

        let ack = dtg_credentials::DTGCredential::new_member_vmc(&grant, valid_from, None)
            .expect("acknowledgement builds")
            .with_id("urn:uuid:ack-1");

        (
            serde_json::to_value(grant.credential()).expect("grant serialises"),
            serde_json::to_value(ack.credential()).expect("ack serialises"),
        )
    }

    /// The happy path, and the one that matters most: a digest computed by
    /// `dtg-credentials` must verify against one computed here, over the wire
    /// form. Two implementations, one definition — this is the assertion that
    /// catches either side drifting.
    #[test]
    fn an_acknowledgement_of_our_grant_binds() {
        let (grant, ack) = pair();
        assert!(
            check_acknowledgement_binding(&ack, Some(&grant), "did:key:zMember").unwrap(),
            "the catalog's digest must verify against this service's"
        );
    }

    /// The community re-signing a grant must not invalidate consent already
    /// given — the digest covers claims, not the proof.
    #[test]
    fn a_re_signed_grant_still_satisfies_an_existing_acknowledgement() {
        let (mut grant, ack) = pair();
        grant["proof"] = serde_json::json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofValue": "zSomeOtherSignatureEntirely"
        });

        assert!(check_acknowledgement_binding(&ack, Some(&grant), "did:key:zMember").unwrap());
    }

    /// A member who acknowledges some other grant has consented to something,
    /// but not to this membership. Refused rather than stored: an
    /// acknowledgement that does not answer the grant we hold would let the
    /// community show consent it does not have.
    #[test]
    fn an_acknowledgement_of_a_different_grant_is_refused() {
        use chrono::TimeZone;
        let (_, ack) = pair();

        // Same parties, different grant — a renewal, say.
        let renewed = dtg_credentials::DTGCredential::new_vmc(
            "did:web:community.example".to_string(),
            "did:key:zMember".to_string(),
            chrono::Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            None,
            false,
        )
        .with_id("urn:uuid:grant-2");
        let renewed = serde_json::to_value(renewed.credential()).expect("serialises");

        let err = check_acknowledgement_binding(&ack, Some(&renewed), "did:key:zMember")
            .expect_err("a mismatched digest must be refused");
        assert!(
            format!("{err:?}").contains("acknowledges a different grant"),
            "unexpected error: {err:?}"
        );
    }

    /// Two populations arrive without a digest: clients that predate the
    /// requirement, and members whose grant this service issued before it kept
    /// bodies. Both are stored and neither completes an edge. Refusing them
    /// would unmake memberships validly formed under the rules then in force.
    #[test]
    fn an_acknowledgement_without_a_digest_is_stored_unbound() {
        let (grant, _) = pair();
        let legacy = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
            "id": "urn:uuid:legacy-ack",
            "issuer": "did:key:zMember",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:web:community.example" }
        });

        assert!(
            !check_acknowledgement_binding(&legacy, Some(&grant), "did:key:zMember").unwrap(),
            "no digest to check, so nothing was verified"
        );
    }

    /// No stored grant means nothing to check against — not a reason to refuse
    /// a credential the member issued correctly.
    #[test]
    fn an_acknowledgement_with_no_stored_grant_is_stored_unbound() {
        let (_, ack) = pair();
        assert!(!check_acknowledgement_binding(&ack, None, "did:key:zMember").unwrap());
    }
}
