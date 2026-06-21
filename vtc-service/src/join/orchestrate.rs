//! The join-submit orchestration spine — holder-binding verification, the
//! decide -> auto-admit-effect -> audit pipeline, and the join-request
//! persistence — moved out of `routes/join_requests/submit.rs` (P2.1) so it
//! lives beside the join lifecycle it drives (`crate::join`) and is shared by
//! every entry point (REST submit, DIDComm, credential-exchange present)
//! without a `crate::routes::...` back-reference. The route handler keeps only
//! the wire body/response types + auth extraction.
//!
//! Also hosts `emit_admit_audit` (the `MemberAdded` + `VmcIssued` + `VecIssued`
//! envelopes a member admission records) — shared with the manual-approve route
//! (`routes::join_requests::decide::approve`).

use serde::Serialize;
use serde_json::Value as JsonValue;
use tracing::{info, warn};
use uuid::Uuid;

use affinidi_vc::VerifiableCredential;
use vti_common::audit::{
    AuditEvent, AuditWriter, CredentialIssuedData, JoinRequestData, JoinRequestRejectedData,
    MemberAddedData,
};
use vti_common::error::AppError;

use crate::ceremony::execute::{self, AdmitOutcome, top_level_id};
use crate::ceremony::facts::Invitation;
use crate::ceremony::{
    Credential, CredentialStatus, EffectOutcome, EffectPlan, Evidence, Facts, FactsInputs,
    Presentation, Purpose, Verdict, VerifiedFacts, assemble_facts,
};
use crate::credentials::invitation_verify::{
    ConsumedInvitation, mark_consumed, verify_presented_invitation,
};
use crate::credentials::vec::VEC_TYPE;
use crate::credentials::vmc::VMC_TYPE;
use crate::join::{JoinRequest, JoinStatus, JoinTransport, list_join_requests, store_join_request};
use crate::policy::{PolicyPurpose, extract::extract_vp_claims, load_active_compiled};
use crate::server::AppState;

pub const JOIN_REQUEST_SUBMIT_DOMAIN_TAG: &[u8] = b"vtc-join-request/v1\0";

/// How old a join-submit holder signature's `created` may be (seconds).
/// Bounds replay of a captured body to this window; the per-applicant
/// open-request dedup closes the in-window concurrent-replay gap (P0.13).
const JOIN_SUBMIT_FRESHNESS_SECS: i64 = 300;
/// Tolerated clock skew for a `created` slightly in the future.
const JOIN_SUBMIT_FUTURE_SKEW_SECS: i64 = 60;
/// The REST holder-binding inputs threaded into [`submit_inner`]. `None` on the
/// DIDComm path, where the authcrypt envelope authenticates the sender (and is
/// addressed to this VTC), so no separate signed audience/freshness is needed.
pub struct HolderBinding<'a> {
    pub signature_hex: &'a str,
    pub audience: &'a str,
    pub created: i64,
}
/// What [`submit_inner`] produced: the persisted request + the
/// credentials minted if the policy auto-admitted (verdict `allow`).
pub struct JoinSubmitOutcome {
    pub request: JoinRequest,
    pub admit: Option<Box<AdmitOutcome>>,
}
/// Shared inner implementation called by both REST and the DIDComm
/// handler — the join ceremony's decide → effect spine.
///
/// `signature` is `Some` for REST (where the wire must carry an
/// explicit holder-binding signature) and `None` for DIDComm (where
/// the DIDComm envelope's authcrypt sender already authenticates
/// `applicant_did`).
///
/// The active `join` decision policy classifies the verified
/// submission:
/// - `allow` → **auto-admit** via the [`EffectPlan::Admit`] executor;
///   the request lands `Approved` and the credentials are returned.
/// - `refer` → `Pending` (queued for admin review → the approve route).
/// - `request_more` → `Deferred` (more evidence needed).
/// - `deny` → `Rejected`, with the verdict stored on `policy_decision`.
pub async fn submit_inner(
    state: &AppState,
    applicant_did: String,
    vp: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    binding: Option<HolderBinding<'_>>,
    transport: JoinTransport,
) -> Result<JoinSubmitOutcome, AppError> {
    // 1. Holder binding (REST only): audience + freshness + signature. The
    // DIDComm path (`binding == None`) is authenticated + addressed by the
    // authcrypt envelope, so it skips this.
    if let Some(b) = binding.as_ref() {
        // Audience: the signed payload must name THIS VTC, so a body captured
        // for another community can't be replayed here (P0.13).
        let vtc_did = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .ok_or_else(|| AppError::Internal("vtc_did not configured".into()))?;
        if b.audience != vtc_did {
            return Err(AppError::Validation(format!(
                "join-request audience ({}) does not match this VTC ({vtc_did})",
                b.audience
            )));
        }
        // Freshness: a stale captured body is rejected; small future skew ok.
        let now = crate::auth::session::now_epoch() as i64;
        if b.created < now - JOIN_SUBMIT_FRESHNESS_SECS
            || b.created > now + JOIN_SUBMIT_FUTURE_SKEW_SECS
        {
            return Err(AppError::Validation(
                "join-request `created` is outside the freshness window — re-sign and resubmit"
                    .into(),
            ));
        }
        verify_holder_signature(
            &applicant_did,
            &vp,
            registry_consent,
            &extensions,
            b.audience,
            b.created,
            b.signature_hex,
        )?;
    }

    // 2. Dedup: at most one open (Pending/Deferred) request per applicant
    // (P0.13). Blocks replay of a captured body while a request is open and
    // caps unbounded accumulation. An already-admitted applicant is caught
    // later by the admit duplicate-ACL guard.
    if let Some(existing) = find_open_request(&state.join_requests_ks, &applicant_did).await? {
        return Err(AppError::Conflict(format!(
            "an open join request already exists for {applicant_did} (id {existing}); \
             withdraw or await its decision before resubmitting"
        )));
    }

    // 3. The lossy `vp_claims` projection is still stored on the row
    // for the admin show + the approve path; the decision pipeline
    // reads structured Facts instead (assembled below).
    let vp_claims = extract_vp_claims(&vp);

    // 4. Invitation (VIC): if the VP carries an InvitationCredential, verify it
    // (proof + holder-binding + validity + revocation). A present-but-invalid
    // invitation is a hard Forbidden here, before policy. A verified invitation
    // becomes a policy fact, with `consumed` resolved from the single-use ledger
    // so the policy (`has_valid_invitation`) can reject a redeemed invite. The
    // VIC `id` is kept so an auto-admit can burn it (step 6).
    let invitation_fact = match verify_presented_invitation(state, &applicant_did, &vp).await? {
        Some(vi) => {
            let consumed = crate::credentials::invitation_verify::is_consumed(
                &state.consumed_invitations_ks,
                &vi.id,
            )
            .await?;
            Some((vi.id.clone(), vi.to_fact(consumed)))
        }
        None => None,
    };
    let consume_invitation_id = invitation_fact.as_ref().map(|(id, _)| id.clone());
    let invitation = invitation_fact.map(|(_, fact)| fact);

    // Diagnostic: "my VIC-bearing join is still pending" almost always comes down
    // to one of the three policy facts below. The default `join.rego` auto-admits
    // only on `verified && issuer_trusted && !consumed`; a verified invitation
    // that still refers failed `issuer_trusted` (issuer ≠ this VTC's own DID and
    // not registry-recognised) or `consumed` (single-use, already redeemed). Log
    // the facts + the issuer-vs-own-DID comparison so the cause is in the record,
    // not inferred. A VP that carried `verifiableCredential` but produced no
    // invitation fact is logged too — the credential wasn't an InvitationCredential.
    match &invitation {
        Some(inv) => {
            let own_did = state.config.read().await.vtc_did.clone();
            info!(
                applicant = %applicant_did,
                vic_issuer = %inv.issuer,
                vtc_own_did = own_did.as_deref().unwrap_or("<unset>"),
                verified = inv.verified,
                issuer_trusted = inv.issuer_trusted,
                consumed = inv.consumed,
                "join: invitation presented — auto-admit needs verified && issuer_trusted && !consumed"
            );
        }
        None => {
            if let Some(vc) = vp.get("verifiableCredential") {
                // Dump the shape + each credential's `type` so a VIC that wasn't
                // recognised is self-explanatory: a missing `InvitationCredential`
                // tag, a non-array `verifiableCredential`, or the lossy `vp_claims`
                // projection mistakenly sent as the VP all show up here.
                let cred_types: Vec<String> = vc
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|c| {
                                c.get("type")
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "<no type>".to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                info!(
                    applicant = %applicant_did,
                    is_array = vc.is_array(),
                    credential_types = ?cred_types,
                    "join: VP carried `verifiableCredential` but no InvitationCredential was \
                     extracted — auto-admit-on-invitation cannot fire"
                );
            }
        }
    }

    // 5. Decide: assemble verified Facts (the route-layer holder-binding
    // makes this presentation `verified`) and run the active join policy.
    let presentation = presentation_from_vp(&applicant_did, &vp);
    let verdict = decide_join(state, &applicant_did, presentation, invitation).await?;

    // 6. Realize the verdict (store + audit + auto-admit on allow). On an
    // invitation-driven admit the VIC is burned in the single-use ledger.
    realize_join_verdict(
        state,
        &applicant_did,
        vp,
        vp_claims,
        registry_consent,
        extensions,
        verdict,
        transport,
        consume_invitation_id,
    )
    .await
}

/// Assemble verified join [`Facts`] from a `presentation` and run the active
/// join policy, returning the [`Verdict`]. The caller supplies a `presentation`
/// it has already established as `verified` (route-layer holder-binding for the
/// VP path; cryptographic `vp_token` verification for the credential-exchange
/// path).
pub async fn decide_join(
    state: &AppState,
    applicant_did: &str,
    presentation: Presentation,
    invitation: Option<Invitation>,
) -> Result<Verdict, AppError> {
    let facts = assemble_join_facts(state, applicant_did, presentation, invitation).await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Join,
    )
    .await?;
    crate::ceremony::decide(&verified, &policy)
}

/// Realize a join [`Verdict`]: build + persist the [`JoinRequest`], auto-admit on
/// `allow` (the [`EffectPlan::Admit`] executor issues the VMC), and write the
/// audit event. Shared by the VP submit and the credential-exchange present path.
#[allow(clippy::too_many_arguments)]
pub async fn realize_join_verdict(
    state: &AppState,
    applicant_did: &str,
    vp: JsonValue,
    vp_claims: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    verdict: Verdict,
    transport: JoinTransport,
    consume_invitation_id: Option<String>,
) -> Result<JoinSubmitOutcome, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut request = JoinRequest::new(applicant_did.to_string(), vp);
    request.vp_claims = vp_claims;
    request.registry_consent = registry_consent;
    request.extensions = extensions;

    let mut admit: Option<Box<AdmitOutcome>> = None;
    let rejected = matches!(verdict, Verdict::Deny(_));
    match &verdict {
        Verdict::Allow(allow) => {
            // Auto-admit: the join effect (admit + issue VMC) runs now.
            // A duplicate ACL (re-submit by an existing member) surfaces
            // as the executor's `Conflict` → 409.
            let role = allow.role.clone().unwrap_or_else(|| "member".to_string());
            let plan = EffectPlan::Admit {
                subject: applicant_did.to_string(),
                role: role.clone(),
                obligations: allow.obligations.clone(),
            };
            if let EffectOutcome::Admitted(creds) =
                execute::apply(state, plan, applicant_did).await?
            {
                // Deliver the issued VMC + role VEC to the applicant's wallet
                // over DIDComm — mirrors the approve path. Best-effort: the
                // credentials are already issued (and returned inline on the
                // REST path), so a delivery failure (no mediator, unreachable
                // holder) is logged, not fatal. This closes the gap where a
                // DIDComm auto-admit issued credentials but never sent them —
                // the receipt only carries the request id + status.
                if let Err(e) = crate::credentials::delivery::deliver_membership_credentials(
                    state,
                    applicant_did,
                    &creds,
                )
                .await
                {
                    warn!(
                        applicant = %applicant_did,
                        error = %e,
                        "membership-credential delivery failed on auto-admit; credentials issued",
                    );
                }
                // Record the admit effect's audit envelopes (MemberAdded +
                // VmcIssued + VecIssued) — the same set the manual-approve path
                // emits. Policy auto-admit has no human approver, so the
                // applicant (whose submission triggered the admission) is the
                // actor. Closes the gap where auto-admitted credentials were
                // issued with no audit trail.
                emit_admit_audit(
                    audit_writer,
                    applicant_did,
                    applicant_did,
                    &creds,
                    &role,
                    Some(request.id.to_string()),
                )
                .await?;
                admit = Some(creds);

                // Burn a single-use invitation now that the admit succeeded. The
                // `consumed` ledger row blocks a later re-redeem (e.g. re-join
                // after leaving); best-effort — the member is already admitted,
                // so a ledger write failure is logged, not fatal.
                if let Some(vic_id) = consume_invitation_id.as_deref() {
                    let record = ConsumedInvitation {
                        applicant: applicant_did.to_string(),
                        consumed_at: chrono::Utc::now(),
                        via_join_request_id: request.id.to_string(),
                    };
                    match mark_consumed(&state.consumed_invitations_ks, vic_id, &record).await {
                        Ok(true) => {}
                        Ok(false) => warn!(
                            vic_id = %vic_id,
                            applicant = %applicant_did,
                            "invitation was already consumed at admit time (concurrent redeem)",
                        ),
                        Err(e) => warn!(
                            vic_id = %vic_id,
                            error = %e,
                            "failed to record invitation consumption; member admitted",
                        ),
                    }

                    // Flag the freshly-admitted member as invitation-joined so
                    // the admin UI can badge them. Best-effort metadata patch —
                    // the member + credentials already exist.
                    match crate::members::get_member(&state.members_ks, applicant_did).await {
                        Ok(Some(mut m)) => {
                            m.joined_via_invitation = true;
                            if let Err(e) =
                                crate::members::store_member(&state.members_ks, &m).await
                            {
                                warn!(
                                    applicant = %applicant_did,
                                    error = %e,
                                    "failed to flag member joined_via_invitation",
                                );
                            }
                        }
                        Ok(None) => warn!(
                            applicant = %applicant_did,
                            "admitted member row missing when flagging joined_via_invitation",
                        ),
                        Err(e) => warn!(
                            applicant = %applicant_did,
                            error = %e,
                            "failed to load member to flag joined_via_invitation",
                        ),
                    }
                }
            }
            request.status = JoinStatus::Approved;
        }
        Verdict::Refer(_) => request.status = JoinStatus::Pending,
        Verdict::RequestMore(_) => {
            request.status = JoinStatus::Deferred;
            request.policy_decision = Some(serde_json::to_value(&verdict)?);
        }
        Verdict::Deny(_) => {
            request.status = JoinStatus::Rejected;
            request.policy_decision = Some(serde_json::to_value(&verdict)?);
        }
    }
    store_join_request(&state.join_requests_ks, &request).await?;

    // Audit — Rejected for a policy deny; Submitted otherwise.
    if rejected {
        audit_writer
            .write(
                applicant_did,
                None,
                AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                    request_id: request.id.to_string(),
                    reason: "policy denied".into(),
                }),
            )
            .await?;
    } else {
        audit_writer
            .write(
                applicant_did,
                None,
                AuditEvent::JoinRequestSubmitted(JoinRequestData {
                    request_id: request.id.to_string(),
                    transport: transport.as_str().to_string(),
                }),
            )
            .await?;
    }

    info!(
        request_id = %request.id,
        applicant = %applicant_did,
        transport = transport.as_str(),
        verdict = verdict.effect(),
        "join request realized"
    );
    Ok(JoinSubmitOutcome { request, admit })
}

// ---------------------------------------------------------------------------
// Join facts assembly (decision-pipeline input)
// ---------------------------------------------------------------------------

/// Assemble purpose-`join` [`Facts`] from a verified submission. The
/// applicant is the actor + subject (self-join); the VP becomes the
/// verified presentation the policy decides over.
async fn assemble_join_facts(
    state: &AppState,
    applicant_did: &str,
    presentation: Presentation,
    invitation: Option<Invitation>,
) -> Result<Facts, AppError> {
    // The applicant proved holder-binding (route-layer for the VP path,
    // cryptographic kb-jwt for the credential-exchange path) but is not (yet) a
    // member, so they carry no community role and no subject member-state. The
    // `invitation` slot is populated when the applicant presented a verified VIC
    // (see `verify_presented_invitation`); the policy decides over it.
    assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::Join,
            actor_did: applicant_did.to_string(),
            actor_role: None,
            subject_did: applicant_did.to_string(),
            subject_member: None,
            evidence: Evidence {
                invitation,
                presentation: Some(presentation),
                request: None,
            },
        },
    )
    .await
}

/// Project the VP into the [`Presentation`] the policy reads.
///
/// `verified: true` reflects the **presentation-level** holder-binding the
/// route already checked (`verify_holder_signature` over the canonical
/// payload) — the applicant proved control of `applicant_did`. It does **not**
/// mean the *embedded VCs* were verified: this raw-VP path performs no
/// per-credential proof / issuer / status resolution (that is the
/// `vp_token` / credential-exchange `present` path). So each projected
/// credential is fail-safe — `issuer_trusted: false`, `holder_bound: false`,
/// `status: unknown` (not `valid` — its status list was never read), and
/// **`claims: null`** so a policy that branches on credential claims cannot be
/// fooled into auto-admitting on a forged VC presented under a verified
/// holder-binding (P0.12). The raw claims are still surfaced for the admin
/// show / approve UI via the request row's separate `vp_claims` projection.
fn presentation_from_vp(applicant_did: &str, vp: &JsonValue) -> Presentation {
    let holder = vp
        .get("holder")
        .and_then(|h| match h {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Object(o) => o.get("id").and_then(|i| i.as_str()).map(str::to_string),
            _ => None,
        })
        .unwrap_or_else(|| applicant_did.to_string());

    let credentials = vp
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(credential_from_vc).collect())
        .unwrap_or_default();

    Presentation {
        verified: true,
        holder,
        credentials,
    }
}

/// Pull one VC into a [`Credential`]. JWT-encoded VCs (bare strings)
/// are skipped — full JWT-VP support lands with VP verification.
fn credential_from_vc(vc: &JsonValue) -> Option<Credential> {
    let obj = vc.as_object()?;
    let credential_type = obj
        .get("type")
        .and_then(|t| match t {
            JsonValue::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str())
                .find(|s| *s != "VerifiableCredential")
                .map(str::to_string),
            JsonValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "VerifiableCredential".to_string());
    let issuer = match obj.get("issuer") {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Object(o)) => o
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };
    Some(Credential {
        credential_type,
        issuer,
        issuer_trusted: false,
        // The raw-VP submit path verifies NOTHING about the embedded VC — not
        // its issuer proof, not its holder-key binding (no `kb-jwt` / holder
        // proof / pseudonym check like the vp_token path), and not its
        // status-list state. So every trust signal is fail-safe: `unknown`
        // status (the list was never read — not `valid`), `issuer_trusted` /
        // `holder_bound` false, and **null claims** so a claims-reading policy
        // cannot auto-admit on attacker-supplied claim values (P0.12). A policy
        // that needs the claims must run the verifying `present` path.
        status: CredentialStatus::Unknown,
        holder_bound: false,
        claims: JsonValue::Null,
        valid_until: None,
    })
}

/// Verify the Ed25519 signature over the canonical signing
/// payload (see module docs).
#[allow(clippy::too_many_arguments)]
fn verify_holder_signature(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    audience: &str,
    created: i64,
    signature_hex: &str,
) -> Result<(), AppError> {
    let payload = canonical_payload(
        applicant_did,
        vp,
        registry_consent,
        extensions,
        audience,
        created,
    )?;
    crate::holder_signature::verify_domain_signed(
        applicant_did,
        JOIN_REQUEST_SUBMIT_DOMAIN_TAG,
        &payload,
        signature_hex,
    )
    .map_err(AppError::Validation)
}

/// Canonical signing payload — a typed struct serialised via
/// `serde_json::to_vec` with the field order pinned by the
/// derive. Both sides build this identically by going through the
/// same struct.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    applicant_did: &'a str,
    vp: &'a JsonValue,
    registry_consent: bool,
    extensions: &'a JsonValue,
    /// P0.13 audience + freshness binding.
    audience: &'a str,
    created: i64,
}

fn canonical_payload(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    audience: &str,
    created: i64,
) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        applicant_did,
        vp,
        registry_consent,
        extensions,
        audience,
        created,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}

/// Find an applicant's open (Pending/Deferred) join request, if any. Used to
/// dedup / cap open requests per applicant (P0.13).
async fn find_open_request(
    ks: &vti_common::store::KeyspaceHandle,
    applicant_did: &str,
) -> Result<Option<Uuid>, AppError> {
    let all = list_join_requests(ks).await?;
    Ok(all
        .into_iter()
        .find(|r| {
            r.applicant_did == applicant_did
                && matches!(r.status, JoinStatus::Pending | JoinStatus::Deferred)
        })
        .map(|r| r.id))
}

pub async fn emit_admit_audit(
    audit_writer: &AuditWriter,
    actor_did: &str,
    subject_did: &str,
    creds: &AdmitOutcome,
    role: &str,
    via_join_request_id: Option<String>,
) -> Result<(), AppError> {
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::MemberAdded(MemberAddedData {
                role: role.to_string(),
                via_join_request_id,
            }),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VmcIssued(credential_issued_data(
                &creds.vmc,
                Some(creds.status_list_index),
            )?),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VecIssued(credential_issued_data(&creds.role_vec, None)?),
        )
        .await?;
    Ok(())
}

/// Build a [`CredentialIssuedData`] payload from a signed VC.
pub(crate) fn credential_issued_data(
    vc: &VerifiableCredential,
    status_list_index: Option<u32>,
) -> Result<CredentialIssuedData, AppError> {
    let id = top_level_id(vc).ok_or_else(|| {
        AppError::Internal("credential is missing top-level `id` — issuance dropped it".into())
    })?;
    let credential_type = vc
        .types
        .iter()
        .find(|t| *t == VMC_TYPE || *t == VEC_TYPE)
        .cloned()
        .ok_or_else(|| AppError::Internal("credential carries neither VMC nor VEC type".into()))?;
    let valid_from = vc
        .valid_from
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validFrom".into()))?;
    let valid_until = vc
        .valid_until
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validUntil".into()))?;
    Ok(CredentialIssuedData {
        credential_id: id,
        credential_type,
        valid_from,
        valid_until,
        status_list_index,
    })
}

/// Domain-tag prefixed bytes the signer hashes over. Verification goes
/// through [`crate::holder_signature::verify_domain_signed`]; this
/// remains for the round-trip tests that must *produce* the same bytes.
#[cfg(test)]
fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JOIN_REQUEST_SUBMIT_DOMAIN_TAG.len() + payload.len());
    buf.extend_from_slice(JOIN_REQUEST_SUBMIT_DOMAIN_TAG);
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// Tests — signing primitive + sign-then-verify round trip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn pair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xAB; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (sk, did)
    }

    const AUD: &str = "did:key:zThisVtc";
    const CREATED: i64 = 1_900_000_000;

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"placeholder"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        verify_holder_signature(&did, &vp, false, &JsonValue::Null, AUD, CREATED, &sig_hex)
            .unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let (_a_sk, a_did) = pair();
        let other = SigningKey::from_bytes(&[0xCD; 32]);
        let vp = serde_json::json!({});
        let payload =
            canonical_payload(&a_did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = other.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err =
            verify_holder_signature(&a_did, &vp, false, &JsonValue::Null, AUD, CREATED, &sig_hex)
                .expect_err("wrong signer must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"original"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        // Same signature, different VP body.
        let tampered = serde_json::json!({"vp":"changed"});
        let err = verify_holder_signature(
            &did,
            &tampered,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            &sig_hex,
        )
        .expect_err("tampered VP must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_audience() {
        // P0.13: the audience is part of the signed payload, so re-pointing it
        // (cross-community replay) breaks the signature.
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"x"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err = verify_holder_signature(
            &did,
            &vp,
            false,
            &JsonValue::Null,
            "did:key:zOtherVtc",
            CREATED,
            &sig_hex,
        )
        .expect_err("re-pointed audience must fail the signature");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_garbage_signature() {
        let (_sk, did) = pair();
        let err = verify_holder_signature(
            &did,
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            "not-hex",
        )
        .expect_err("garbage sig must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_non_did_key_applicant() {
        let err = verify_holder_signature(
            "did:web:example.com",
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            "00",
        )
        .expect_err("non-did:key must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    // ── P0.12: embedded VCs on the raw-VP submit path are fail-safe ──

    #[test]
    fn presentation_from_vp_does_not_present_unverified_vc_claims() {
        // A forged VC with attacker-chosen claims, presented under a
        // (separately-verified) holder binding. The raw-VP path verifies none
        // of the embedded VC, so its claims/status/trust signals must be
        // fail-safe — otherwise a policy reading `credentials[].claims` would
        // auto-admit on forged content.
        let applicant = "did:key:zApplicant";
        let vp = serde_json::json!({
            "type": "VerifiablePresentation",
            "holder": applicant,
            "verifiableCredential": [
                {
                    "issuer": "did:key:zForgedIssuer",
                    "type": ["VerifiableCredential", "EmailCredential"],
                    "credentialSubject": { "email": "ceo@acme.com" }
                }
            ]
        });

        let p = presentation_from_vp(applicant, &vp);

        // Presentation-level holder-binding is the route's verdict; the policy
        // gate (assemble) still passes so a legitimate submit lands pending.
        assert!(p.verified, "holder-binding is verified at the route");
        assert_eq!(p.holder, applicant);
        assert_eq!(p.credentials.len(), 1);

        let c = &p.credentials[0];
        // Structural metadata is fine to surface…
        assert_eq!(c.credential_type, "EmailCredential");
        assert_eq!(c.issuer, "did:key:zForgedIssuer");
        // …but every trust signal must be fail-safe.
        assert!(!c.issuer_trusted, "issuer not vetted on the raw path");
        assert!(!c.holder_bound, "no per-credential holder proof checked");
        assert_eq!(
            c.status,
            CredentialStatus::Unknown,
            "status list was never read — must not claim `valid`"
        );
        assert_eq!(
            c.claims,
            JsonValue::Null,
            "unverified VC claims must NOT be surfaced to the policy"
        );
    }

    #[test]
    fn presentation_from_vp_with_no_embedded_vcs_is_holder_binding_only() {
        // The common case: a bare holder-binding VP (no credentials). The
        // presentation is verified (so the submit lands pending) and carries
        // no credentials for a policy to (mis)trust.
        let applicant = "did:key:zApplicant";
        let vp = serde_json::json!({ "type": "VerifiablePresentation", "holder": applicant });
        let p = presentation_from_vp(applicant, &vp);
        assert!(p.verified);
        assert!(p.credentials.is_empty());
    }
}
