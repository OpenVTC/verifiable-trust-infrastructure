//! The community's minting half: vetter enrolment and the attestation-token drip.
//!
//! [`crate::vetting::pcs`] verifies what comes back; this is where it comes from. Two
//! exchanges, both blind — the community signs a commitment it cannot open, so it learns
//! nothing it could use later to recognise the holder:
//!
//! - **Enrolment** ([`enrol`]) — once per member per class label. What the vetter unblinds is a
//!   credential for `vetter/<period>`; what the community keeps is a row saying that this
//!   member enrolled, and which PCS identifier they are bound to.
//! - **The drip** ([`drip`]) — at most the published rate per tick, whether or not the vetter
//!   has vetted anyone. Constant by design (§5.1): a fetch that happened only when someone was
//!   busy would announce that they were busy.
//!
//! # The checks live here, not in the keys
//!
//! [`vti_vetting_pcs::issuer::Issuer`] holds keys and signs. Every question about *whether to
//! sign* is a question about this community's records — does this member hold the role, have
//! they already enrolled under this label, have they already been served this tick — and the
//! answers belong in the store, where they survive a restart. An in-memory set is not a rule; it
//! is a rule until the process exits.
//!
//! # Where the keys come from
//!
//! Derived from the same master secret the credential signer uses, through HKDF with an info
//! string of their own, exactly as the storage, install-token and audit keys are. There is no
//! second secret to provision, back up, or leak. The consequence is stated in
//! [`vti_vetting_pcs::issuer`]: the master secret *is* the vetter class, so [`issuer`] refuses
//! to mint anything if the derived helper key is not the one the community published.

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vti_common::audit::{AuditEvent, HiddenVetterEnrolledData, HiddenVetterTokensIssuedData};
use vti_common::error::AppError;

use vti_vetting_pcs::{
    issuer::{
        DripOrder, Issuer, RootCredentialWire, RootRequestWire, TokenBatchRequestWire,
        TokenBatchWire,
    },
    scheme::{Base, E, point_from_text},
    token::TokenVerifier,
};

use super::pcs::HiddenVettingConfig;
use crate::server::AppState;

/// HKDF info for the PCS issuer secret. Versioned: changing it rotates every community's
/// vetter class, which is a deliberate act and never a side effect.
const KEY_INFO: &[u8] = b"vtc-vetting-pcs-secret/v1";

/// What the community recorded when a member enrolled. One row per member, covering every
/// label they have ever enrolled under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrolmentRecord {
    /// The PCS identifier this member is bound to, from their first enrolment. A member who
    /// came back with a different one would hold two class credentials and count twice in one
    /// proof (§13 C2).
    pub id: String,
    /// Class labels this member already holds a credential under, with when it was issued.
    pub labels: Vec<(String, DateTime<Utc>)>,
}

/// What the community recorded when it served a tick of the drip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DripRecord {
    pub issued: usize,
    pub issued_at: DateTime<Utc>,
}

fn enrol_key(member_did: &str) -> Vec<u8> {
    format!("pcs-enrol:{member_did}").into_bytes()
}

/// How many members hold an enrolment under each of `labels` (`vetter/<period>`).
///
/// A count, never a list: which members can vet anonymously under a label is exactly what the
/// enrolment table must not hand out (design §18). An administrator needs the number to know
/// whether a label has enough vetters for a proof of `k` to be possible at all.
///
/// # Errors
///
/// Whatever the store returns.
pub async fn enrolled_counts(
    state: &AppState,
    labels: &[String],
) -> Result<std::collections::HashMap<String, usize>, AppError> {
    let mut counts: std::collections::HashMap<String, usize> =
        labels.iter().map(|l| (l.clone(), 0)).collect();
    for key in state
        .vetting_pcs_issue_ks
        .prefix_keys(b"pcs-enrol:".to_vec())
        .await?
    {
        let Some(record) = state
            .vetting_pcs_issue_ks
            .get::<EnrolmentRecord>(key)
            .await?
        else {
            continue;
        };
        for (label, _) in &record.labels {
            if let Some(n) = counts.get_mut(label) {
                *n += 1;
            }
        }
    }
    Ok(counts)
}

fn drip_key(member_did: &str, label: &str, tick: u32) -> Vec<u8> {
    // Length-framed, so a member DID ending in digits cannot read as part of a tick.
    format!(
        "pcs-drip:{}:{member_did}:{}:{label}:{tick}",
        member_did.len(),
        label.len()
    )
    .into_bytes()
}

/// This community's issuer, derived from the master secret. Checks nothing about what was
/// published — [`issuer`] is the one to call before minting.
///
/// # Errors
///
/// [`AppError::Internal`] if no credential signer is configured (the same precondition VMC
/// issuance has, because it is the same key) or if the derivation fails.
pub fn derive_issuer(state: &AppState, community_did: &str) -> Result<Issuer, AppError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot derive the hidden-vetting keys \
             (run setup first)"
                .into(),
        )
    })?;
    let master = signer.ed25519_signing_key().ok_or_else(|| {
        AppError::Internal("the credential signer holds no Ed25519 key to derive from".into())
    })?;
    let mut secret = [0u8; 32];
    Hkdf::<Sha256>::new(None, &master.to_bytes())
        .expand(KEY_INFO, &mut secret)
        .map_err(|e| AppError::Internal(format!("derive hidden-vetting secret: {e}")))?;

    Issuer::derive(community_did, &secret)
        .map_err(|e| AppError::Internal(format!("hidden-vetting keys: {e}")))
}

/// The parameters a community publishes in its criterion's `vetting.ext`, built from the keys
/// it will actually mint under. This is where a deployment's `hvk` and `tvk` come from — an
/// operator publishes what this returns, and never types a key in.
///
/// # Errors
///
/// As [`derive_issuer`], plus [`AppError::Internal`] if a key cannot be encoded.
pub fn publish(
    state: &AppState,
    community_did: &str,
    live_periods: Vec<String>,
    live_token_labels: Vec<String>,
    drip_per_tick: usize,
) -> Result<HiddenVettingConfig, AppError> {
    let (hvk, tvk) = derive_issuer(state, community_did)?
        .public_text()
        .map_err(|e| AppError::Internal(format!("encode hidden-vetting keys: {e}")))?;
    Ok(HiddenVettingConfig {
        suite: vti_vetting_pcs::wire::SUITE.to_string(),
        hvk,
        tvk,
        live_periods,
        live_token_labels,
        drip_per_tick,
        tick_length: super::pcs::DEFAULT_TICK_LENGTH.to_string(),
        // None. Event mode is the exception a community adds to a criterion it is already
        // running (§5.1), never a state it is published into.
        events: Vec::new(),
    })
}

/// This community's issuer, derived and then checked against what it published.
///
/// # Errors
///
/// - As [`derive_issuer`].
/// - [`AppError::Internal`] if the derived keys are not the published ones. That means the
///   master secret changed under a deployment that has already issued class credentials, and
///   minting more would hand out credentials nobody can verify. It is a stop, not a warning.
pub fn issuer(
    state: &AppState,
    community_did: &str,
    config: &HiddenVettingConfig,
) -> Result<Issuer, AppError> {
    let issuer = derive_issuer(state, community_did)?;
    let (hvk, tvk) = issuer
        .public_text()
        .map_err(|e| AppError::Internal(format!("encode hidden-vetting keys: {e}")))?;
    if hvk != config.hvk || tvk != config.tvk {
        return Err(AppError::Internal(
            "the derived hidden-vetting keys are not the ones this community published — \
             the master secret has changed, and issuing under the new one would produce \
             credentials no submission can verify against the published parameters"
                .into(),
        ));
    }
    Ok(issuer)
}

/// Issue a vetter their root credential for the current class label.
///
/// The order is: is this member a vetter *now*, is this the label we are issuing, have they
/// enrolled under it already, is this the identifier they are bound to — and only then a
/// signature. The record is written **after** the signature is produced, so a signing failure
/// does not consume the member's one enrolment; the window in between can only lose an
/// issuance, never duplicate one, because a lost record is a re-enrolment the vetter asks for.
///
/// # Errors
///
/// - [`AppError::Forbidden`] if the member holds no live vetter grant.
/// - [`AppError::Validation`] if the label is not this community's current one, if the member
///   has already enrolled under it, or if they present a different PCS identifier than the one
///   they are bound to.
/// - [`AppError::Internal`] if the request does not verify, or the store fails.
pub async fn enrol(
    state: &AppState,
    community_did: &str,
    config: &HiddenVettingConfig,
    member_did: &str,
    request: &RootRequestWire,
    now: DateTime<Utc>,
) -> Result<RootCredentialWire, AppError> {
    if !super::vetter_eligible(state, member_did, "vetter", now).await? {
        return Err(AppError::Forbidden(format!(
            "{member_did} holds no live vetter grant in this community"
        )));
    }
    let period = config.live_periods.first().ok_or_else(|| {
        AppError::Internal("this community has no live vetter class label".into())
    })?;
    let label = format!("vetter/{period}");
    if request.label != label {
        return Err(AppError::Validation(format!(
            "this community is issuing `{label}`, not `{}`",
            request.label
        )));
    }

    let mut record: EnrolmentRecord = state
        .vetting_pcs_issue_ks
        .get(enrol_key(member_did))
        .await?
        .unwrap_or_default();
    if record.labels.iter().any(|(l, _)| *l == label) {
        return Err(AppError::Validation(format!(
            "{member_did} already holds a credential under `{label}`"
        )));
    }
    if !record.id.is_empty() && record.id != request.id {
        return Err(AppError::Validation(format!(
            "{member_did} is bound to another PCS identifier; a member holds one"
        )));
    }

    let id = point_from_text(&request.id)
        .map_err(|e| AppError::Validation(format!("PCS identifier: {e}")))?;
    let parsed = serde_json::from_value(request.request.clone())
        .map_err(|e| AppError::Validation(format!("root request: {e}")))?;
    let pre = issuer(state, community_did, config)?
        .issue_root(
            period,
            &id,
            &parsed,
            &mut vti_vetting_pcs::rand::rngs::OsRng,
        )
        .map_err(|e| AppError::Validation(format!("root request does not verify: {e}")))?;
    let pre_credential = vti_vetting_pcs::scheme::enc::<
        <Base as predicate_credential_system::cred::CredentialBase>::PreCredential,
    >(&pre)
    .map_err(|e| AppError::Internal(format!("encode pre-credential: {e}")))?;

    let rotation = !record.labels.is_empty();
    record.id = request.id.clone();
    record.labels.push((label.clone(), now));
    state
        .vetting_pcs_issue_ks
        .insert(enrol_key(member_did), &record)
        .await?;

    // Audited after the record, so the log never claims an issuance the store did not keep.
    // The payload carries the label, never the identifier: the enrolment row is already one
    // half of a future deanonymisation (design §18) and the audit log holds no second copy.
    audit(state)?
        .write(
            community_did,
            Some(member_did),
            AuditEvent::HiddenVetterEnrolled(HiddenVetterEnrolledData {
                label: label.clone(),
                rotation,
            }),
        )
        .await?;

    Ok(RootCredentialWire {
        label,
        pre_credential,
    })
}

/// The audit writer, or a refusal. Minting without one would leave a community unable to say
/// what it signed, which is the question an incident review asks first.
fn audit(state: &AppState) -> Result<&vti_common::audit::AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))
}

/// Serve one tick of the drip: at most the published rate, once per member per label per tick.
///
/// # Errors
///
/// - [`AppError::Forbidden`] if the member holds no live vetter grant.
/// - [`AppError::Validation`] if the label is not live, if this member has already been served
///   for this tick, or if more than the published rate was asked for.
/// - [`AppError::Internal`] if a request does not verify, or the store fails.
pub async fn drip(
    state: &AppState,
    community_did: &str,
    config: &HiddenVettingConfig,
    member_did: &str,
    batch: &TokenBatchRequestWire,
    now: DateTime<Utc>,
) -> Result<TokenBatchWire, AppError> {
    if !super::vetter_eligible(state, member_did, "vetter", now).await? {
        return Err(AppError::Forbidden(format!(
            "{member_did} holds no live vetter grant in this community"
        )));
    }
    if !config.live_token_labels.contains(&batch.label) {
        return Err(AppError::Validation(format!(
            "`{}` is not a live token label",
            batch.label
        )));
    }
    // An event label carries a higher rate and a smaller anonymity set, so it has four more
    // conditions than a monthly one — approved, not self-approved, over the floor, and inside its
    // window — and a member who never asked to be in the event is not in it
    // ([`super::pcs_event::gate`]).
    super::pcs_event::gate(state, config, member_did, &batch.label, now).await?;

    // A tick is a window of time, not a counter the vetter chooses (pcs-tokens/0.1): without
    // this, a vetter could draw ticks 0, 1, 2, … back to back and the drip would cap nothing.
    // Earlier ticks not yet served stay drawable once each, so a device that was off catches
    // up — never ahead.
    match config.current_tick(&batch.label, now) {
        Some(current) if u64::from(batch.tick) <= current => {}
        Some(current) => {
            return Err(AppError::Validation(format!(
                "tick {} of `{}` has not begun: it is tick {current} now, and each lasts {}",
                batch.tick, batch.label, config.tick_length
            )));
        }
        None => {
            return Err(AppError::Validation(format!(
                "tick {} of `{}` has not begun: the label's first tick is still to come",
                batch.tick, batch.label
            )));
        }
    }

    let key = drip_key(member_did, &batch.label, batch.tick);
    if let Some(row) = state
        .vetting_pcs_issue_ks
        .get::<DripRecord>(key.clone())
        .await?
    {
        return Err(AppError::Validation(format!(
            "{member_did} was already served {} token(s) under `{}` for tick {} at {}",
            row.issued, batch.label, batch.tick, row.issued_at
        )));
    }

    let requests = batch
        .requests
        .iter()
        .map(|r| r.to_request())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::Validation(format!("token request: {e}")))?;

    // The quota is the tier this member asked for at this event, or the community's ordinary
    // rate for every other label. It is the community's cap either way — never the asker's.
    let quota = super::pcs_event::quota(state, config, member_did, &batch.label).await?;

    let issuer = issuer(state, community_did, config)?;
    let verifier = TokenVerifier::new(
        community_did,
        issuer.tvk().clone(),
        config.live_token_labels.clone(),
    )
    .map_err(|e| AppError::Internal(format!("token parameters: {e}")))?;
    let pres = issuer
        .issue_tokens(
            &verifier,
            DripOrder {
                member: member_did,
                tick: batch.tick,
                label: &batch.label,
                requests: &requests,
                quota,
            },
            &mut vti_vetting_pcs::rand::rngs::OsRng,
        )
        .map_err(|e| AppError::Validation(format!("drip refused: {e}")))?;

    let pre_credentials =
        pres.iter()
            .map(
                vti_vetting_pcs::scheme::enc::<
                    predicate_credential_system::cred::ps::PSPreCredential<E>,
                >,
            )
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(format!("encode token: {e}")))?;

    // Recorded after signing, for the same reason enrolment is: losing the row costs the
    // community a repeated tick, never a vetter their quota. A concurrent second request for
    // the same tick is caught by the issuer's own served set within a process, and by this row
    // across one.
    state
        .vetting_pcs_issue_ks
        .insert(
            key,
            &DripRecord {
                issued: pre_credentials.len(),
                issued_at: now,
            },
        )
        .await?;

    // A constant drip says nothing about activity — that is the point of it — so this row
    // accounts for what was signed and reveals nothing about who was vetted.
    audit(state)?
        .write(
            community_did,
            Some(member_did),
            AuditEvent::HiddenVetterTokensIssued(HiddenVetterTokensIssuedData {
                label: batch.label.clone(),
                tick: batch.tick,
                issued: pre_credentials.len(),
            }),
        )
        .await?;

    Ok(TokenBatchWire {
        label: batch.label.clone(),
        tick: batch.tick,
        pre_credentials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use predicate_credential_system::pcs::PredicateCredentialSystem;
    use serde_json::json;
    use uuid::Uuid;
    use vti_vetting_pcs::rand::{SeedableRng, rngs::StdRng};
    use vti_vetting_pcs::{
        issuer::TokenRequestWire,
        scheme::{point_text, vetter_predicate},
        token::TokenWallet,
    };

    use crate::endorsements::VETTER_GRANT_ROW_TYPE;
    use crate::endorsements::{Endorsement, store_endorsement};
    use crate::members::{Member, store_member};
    use crate::test_support::TestVtc;

    const COMMUNITY: &str = "did:webvh:QmScid:kernel.example";
    const PERIOD: &str = "2026-09";
    const TOKEN_LABEL: &str = "token/2026-09";
    const VETTER: &str = "did:key:z6MkVetter";
    const STRANGER: &str = "did:key:z6MkStranger";

    /// A member of this community holding a live vetter grant — the community's own record,
    /// which is what the minting half reads instead of a list of its own.
    async fn grant_vetter(state: &AppState, did: &str) {
        let mut member = Member::fresh(did);
        member.joined_at = Utc::now() - chrono::Duration::days(1);
        store_member(&state.members_ks, &member).await.unwrap();
        let row = Endorsement {
            id: Uuid::new_v4(),
            endorsement_type: VETTER_GRANT_ROW_TYPE.to_string(),
            issuer_did: COMMUNITY.to_string(),
            subject_did: did.to_string(),
            claim: json!({ "role": "vetter" }),
            status_list_index: 0,
            credential_id: format!("urn:uuid:{}", Uuid::new_v4()),
            created_at: Utc::now() - chrono::Duration::hours(1),
            revoked_at: None,
            valid_until: None,
            auto_granted: false,
            credential: None,
        };
        store_endorsement(&state.endorsements_ks, &row)
            .await
            .unwrap();
    }

    /// The vetter's half of enrolment: a key of its own, and a blinded request for the label.
    /// (`VetterEngine` on the openvtc branch does exactly this; here it is inline, because the
    /// member side does not live in this workspace.)
    struct VetterSide {
        wire: RootRequestWire,
        id: vti_vetting_pcs::scheme::G1,
        usk: predicate_credential_system::pcs::UserSecretKey<E>,
        blinding: predicate_credential_system::pcs::IssuanceState<E, Base>,
    }

    impl VetterSide {
        /// A request for `period` from a key the vetter already has — what a rotation looks
        /// like from the member's side: same `usk`, same identifier, new label.
        fn again(
            issuer: &Issuer,
            period: &str,
            id: vti_vetting_pcs::scheme::G1,
            usk: predicate_credential_system::pcs::UserSecretKey<E>,
            rng: &mut StdRng,
        ) -> Self {
            let f = vetter_predicate(period);
            let (request, blinding) = issuer
                .open()
                .root_request(issuer.hvk(), &f, &id, &usk, rng)
                .unwrap();
            Self {
                wire: RootRequestWire {
                    label: format!("vetter/{period}"),
                    id: point_text(&id).unwrap(),
                    request: serde_json::to_value(&request).unwrap(),
                },
                id,
                usk,
                blinding,
            }
        }
    }

    fn root_request(issuer: &Issuer, period: &str, rng: &mut StdRng) -> VetterSide {
        let (id, usk) = issuer.open().user_keygen(rng).unwrap();
        VetterSide::again(issuer, period, id, usk, rng)
    }

    /// The whole minting half, against the real store: who may enrol, once per label, one
    /// identifier per member; and a drip that is capped, once a tick, and unblinds.
    #[tokio::test]
    async fn a_vetter_enrols_once_and_draws_its_quota() {
        // `with_signers` is the in-process equivalent of a VTC that has been bootstrapped:
        // the master key the hidden-vetting keys derive from is the credential signer's.
        let tv = TestVtc::builder()
            .vtc_did(COMMUNITY)
            .with_signers(true)
            .with_audit(true)
            .build()
            .await;
        let state = tv.state;
        let mut rng = StdRng::seed_from_u64(0x2026_0924);
        let config = publish(
            &state,
            COMMUNITY,
            vec![PERIOD.to_string()],
            vec![TOKEN_LABEL.to_string()],
            3,
        )
        .expect("the community publishes the keys it mints under");
        let issuer = issuer(&state, COMMUNITY, &config).expect("derived keys match published");

        // A member who is not a vetter is refused before any crypto happens.
        grant_vetter(&state, VETTER).await;
        let mut stranger_member = Member::fresh(STRANGER);
        stranger_member.joined_at = Utc::now() - chrono::Duration::days(1);
        store_member(&state.members_ks, &stranger_member)
            .await
            .unwrap();
        let vetter = root_request(&issuer, PERIOD, &mut rng);
        let req = &vetter.wire;
        let err = enrol(&state, COMMUNITY, &config, STRANGER, req, Utc::now())
            .await
            .expect_err("not a vetter");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");

        // The vetter enrols, and unblinds a credential the community has never seen.
        let answer = enrol(&state, COMMUNITY, &config, VETTER, req, Utc::now())
            .await
            .expect("a granted vetter enrols");
        assert_eq!(answer.label, format!("vetter/{PERIOD}"));
        // The real exchange, against the published specification: the conformance witness
        // for this task is a hand-built fixture, so only here does the library's own encoding
        // of a root request meet the schema.
        {
            use trust_tasks_rs::specs::vtc::vetting::vetters::pcs_root::v0_1 as spec;
            use trust_tasks_rs::validate::ValidatedPayload;
            spec::Payload::validate_value(&serde_json::to_value(req).unwrap())
                .expect("a vetter's root request is what the specification describes");
            spec::Response::validate_value(&serde_json::to_value(&answer).unwrap())
                .expect("the community's answer is what the specification describes");
        }
        let pre = vti_vetting_pcs::scheme::dec(&answer.pre_credential).unwrap();
        issuer
            .open()
            .unblind(
                issuer.hvk(),
                &vetter.usk,
                &vetter_predicate(PERIOD),
                &pre,
                &vetter.blinding,
            )
            .expect("what the community signed unblinds into a usable credential");

        // Twice under one label is the rule that makes distinct tags distinct people.
        let err = enrol(&state, COMMUNITY, &config, VETTER, req, Utc::now())
            .await
            .expect_err("already enrolled");
        assert!(
            format!("{err}").contains("already holds a credential"),
            "{err}"
        );

        // Next period, the same member may enrol again — and only with the identifier they
        // were bound to. A second identifier would hold two class credentials at once and
        // count twice in one proof (§13 C2).
        const NEXT: &str = "2026-10";
        let rotated = publish(
            &state,
            COMMUNITY,
            vec![NEXT.to_string(), PERIOD.to_string()],
            vec![TOKEN_LABEL.to_string()],
            3,
        )
        .unwrap();
        let stranger_key = root_request(&issuer, NEXT, &mut rng);
        let err = enrol(
            &state,
            COMMUNITY,
            &rotated,
            VETTER,
            &stranger_key.wire,
            Utc::now(),
        )
        .await
        .expect_err("a member holds one identifier");
        assert!(
            format!("{err}").contains("bound to another PCS identifier"),
            "{err}"
        );
        let same_key = VetterSide::again(&issuer, NEXT, vetter.id, vetter.usk, &mut rng);
        enrol(
            &state,
            COMMUNITY,
            &rotated,
            VETTER,
            &same_key.wire,
            Utc::now(),
        )
        .await
        .expect("a rotation re-issues to the same identifier");

        // The drip: the published rate, once a tick, and what comes back unblinds.
        let mut wallet = TokenWallet::new(COMMUNITY).unwrap();
        let requests = wallet
            .prepare(issuer.tvk(), TOKEN_LABEL, VETTER, 1, 3, &mut rng)
            .unwrap();
        let batch = TokenBatchRequestWire {
            label: TOKEN_LABEL.to_string(),
            tick: 1,
            requests: requests
                .iter()
                .map(|r| TokenRequestWire::of(r).unwrap())
                .collect(),
        };
        let served = drip(&state, COMMUNITY, &config, VETTER, &batch, Utc::now())
            .await
            .expect("a tick of the drip");
        assert_eq!(served.pre_credentials.len(), 3);
        {
            use trust_tasks_rs::specs::vtc::vetting::vetters::pcs_tokens::v0_1 as spec;
            use trust_tasks_rs::validate::ValidatedPayload;
            spec::Payload::validate_value(&serde_json::to_value(&batch).unwrap())
                .expect("a vetter's token batch is what the specification describes");
            spec::Response::validate_value(&serde_json::to_value(&served).unwrap())
                .expect("the served batch is what the specification describes");
        }
        let pres = served
            .pre_credentials
            .iter()
            .map(|p| vti_vetting_pcs::scheme::dec(p).unwrap())
            .collect::<Vec<_>>();
        wallet
            .receive(issuer.tvk(), &pres)
            .expect("the tokens unblind under the published key");
        assert_eq!(wallet.free(), 3);

        // The same tick again is refused — the row, not a memory, is what says so.
        let err = drip(&state, COMMUNITY, &config, VETTER, &batch, Utc::now())
            .await
            .expect_err("once a tick");
        assert!(format!("{err}").contains("already served"), "{err}");

        // And more than the published rate is refused, whatever the vetter asks for.
        let greedy = wallet
            .prepare(issuer.tvk(), TOKEN_LABEL, VETTER, 2, 9, &mut rng)
            .unwrap();
        let err = drip(
            &state,
            COMMUNITY,
            &config,
            VETTER,
            &TokenBatchRequestWire {
                label: TOKEN_LABEL.to_string(),
                tick: 2,
                requests: greedy
                    .iter()
                    .map(|r| TokenRequestWire::of(r).unwrap())
                    .collect(),
            },
            Utc::now(),
        )
        .await
        .expect_err("over the drip rate");
        assert!(format!("{err}").contains("drips 3 a tick"), "{err}");
    }

    /// The stop that protects a deployment whose master secret changed under it.
    #[tokio::test]
    async fn minting_stops_if_the_derived_keys_are_not_the_published_ones() {
        let tv = TestVtc::builder()
            .vtc_did(COMMUNITY)
            .with_signers(true)
            .build()
            .await;
        let mut config = publish(
            &tv.state,
            COMMUNITY,
            vec![PERIOD.to_string()],
            vec![TOKEN_LABEL.to_string()],
            3,
        )
        .unwrap();
        config.hvk = "zSomeOtherCommunitysHelperKey".into();
        let err = issuer(&tv.state, COMMUNITY, &config).expect_err("published a different key");
        assert!(
            format!("{err}").contains("not the ones this community published"),
            "{err}"
        );
    }

    #[test]
    fn drip_keys_separate_members_labels_and_ticks() {
        let a = drip_key("did:key:zAlice", "token/2026-09", 1);
        assert_ne!(a, drip_key("did:key:zBob", "token/2026-09", 1));
        assert_ne!(a, drip_key("did:key:zAlice", "token/2026-10", 1));
        assert_ne!(a, drip_key("did:key:zAlice", "token/2026-09", 2));
        assert_eq!(a, drip_key("did:key:zAlice", "token/2026-09", 1));
        // The framing stops a member DID's tail from reading as the head of a label.
        assert_ne!(
            drip_key("did:key:zA", "lice:token/2026-09", 1),
            drip_key("did:key:zAlice", "token/2026-09", 1)
        );
    }
}
