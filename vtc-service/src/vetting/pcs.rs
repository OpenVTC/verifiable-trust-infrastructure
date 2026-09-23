//! Hidden-vetter admission (ZKP), development branch `zkp-pcs`.
//!
//! The applicant proves that `k` distinct vetters of this community vetted them, and the VTC
//! learns nothing about which. This module turns such a proof into the same
//! [`StatementFacts`](vta_sdk::vetting::requirements::StatementFacts) the named path produces,
//! with each vetter's tag where the vetter's DID used to be, so `evaluate` and `join.rego` are
//! untouched.
//!
//! Design: `docs/design/vetting-hidden-vetters-pcs.md` on the openvtc `zkp-pcs` branch.
//!
//! **Spending tokens against an async store.** Verification is synchronous, the keyspace is
//! not, so a submission is handled in three steps: read the rows for the serials it presents,
//! decide against those, then commit the spends with `insert_raw_if_absent`. A serial another
//! request took in between fails the commit, and the whole submission is refused rather than
//! counted on a token somebody else spent (fail closed).
//!
//! What is here: verification and counting. The minting half — vetter enrolment and the token
//! drip — is [`super::pcs_issue`], and the challenge a submission is bound to is
//! [`super::pcs_challenge`]. [`HiddenVettingConfig`] carries public values only; the keys
//! behind them are derived where they are used.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_vetting_pcs::{
    ProtoError,
    token::{SpendOutcome, SpentLedger, TokenVerifier},
    verifier::{Decision, Submission, Verifier, VerifierParams},
    wire::SubmissionWire,
};

use crate::server::AppState;

/// Domain separation for spent-token keys.
const KEY_DOMAIN: &[u8] = b"vtc-vetting-pcs-spent/v1\0";

/// What a community publishes so that applicants can build a hidden submission and the VTC can
/// check one. Public values only: the helper verification key, the token verification key, and
/// which labels are live.
///
/// It hangs off the stored criterion. It does NOT reach the 0.2 manifest — `Criterion` is a
/// generated `deny_unknown_fields` type and `VettingRequirements` drops members it does not
/// name — so a client gets these out of band until the spec carries them (design §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenVettingConfig {
    /// `ps-ddh-bls12381`, the only suite this branch implements.
    pub suite: String,
    /// The helper verification key `hvk`, multibase.
    pub hvk: String,
    /// The token verification key `tvk`, multibase. Never the same key as `hvk` (§5.1).
    pub tvk: String,
    /// Live vetter class labels, current first: `["2026-10", "2026-09"]` (§13 C1).
    pub live_periods: Vec<String>,
    /// Live token labels: `["token/2026-10", "token/event/summit"]`.
    pub live_token_labels: Vec<String>,
    /// How many attestation tokens a vetter may draw per tick — the community's published drip
    /// rate (§5.1). It is public because it is a parameter of the deployment, not a secret: a
    /// vetter has to know what to ask for, and an applicant may want to know how many
    /// attestations a month can carry.
    ///
    /// Enforced by the issuer, never by the asker. `default` covers a criterion stored before
    /// the minting half existed.
    #[serde(default = "default_drip_per_tick")]
    pub drip_per_tick: usize,
}

/// Three a tick: enough for a vetter who meets people, small enough that a compromised vetter
/// cannot flood a community before the next rotation.
fn default_drip_per_tick() -> usize {
    3
}

/// A spent token, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpentToken {
    /// The applicant identifier it was spent for.
    id: String,
    /// The attesting vetter's tag for that identifier.
    tag: String,
    spent_at: DateTime<Utc>,
}

fn spent_key(label: &str, serial: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(KEY_DOMAIN);
    for part in [label, serial] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().to_vec()
}

/// The rows already on disk for the serials one submission presents, plus the spends the
/// verifier made against them. Synchronous, because verification is.
#[derive(Default)]
struct PreloadedLedger {
    known: HashMap<(String, String), SpentToken>,
    /// What the verifier took this time, to be committed afterwards.
    taken: Vec<(String, String, SpentToken)>,
}

impl SpentLedger for PreloadedLedger {
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn record(
        &mut self,
        label: &str,
        serial: &str,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError> {
        let key = (label.to_string(), serial.to_string());
        if let Some(existing) = self.known.get(&key) {
            // Same applicant, same vetter: a resubmission after `requestMore`; it counts once.
            return Ok(if existing.id == id && existing.tag == tag {
                SpendOutcome::AlreadyCounted
            } else {
                SpendOutcome::DoubleSpend
            });
        }
        let row = SpentToken {
            id: id.to_string(),
            tag: tag.to_string(),
            spent_at: Utc::now(),
        };
        self.known.insert(key.clone(), row.clone());
        self.taken.push((key.0, key.1, row));
        Ok(SpendOutcome::Fresh)
    }

    /// A closed label's rows could be swept; they are left in place, because a row that
    /// outlives its label is harmless and losing one is not.
    fn forget_label(&mut self, _label: &str) {}
}

/// Verify the `hiddenVetting` member of a submission's `extensions` and count it.
///
/// `Ok(None)` when the member is absent: that is every submission of a community that does not
/// run hidden mode, and every named-path submission in one that does.
pub async fn decide(
    state: &AppState,
    community_did: &str,
    applicant_did: &str,
    requirements: &vta_sdk::protocols::vetting::VettingRequirements,
    requirements_digest: &str,
    config: &HiddenVettingConfig,
    extensions: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<Option<Decision>, ProtoError> {
    use predicate_credential_system::serialization::{from_bytes, from_multibase};

    let Some(wire) = SubmissionWire::from_extensions(extensions)? else {
        return Ok(None);
    };
    if config.suite != vti_vetting_pcs::wire::SUITE {
        return Err(ProtoError::Serialization(format!(
            "unknown hidden-vetting suite {}",
            config.suite
        )));
    }
    let submission: Submission = wire.to_submission()?;

    // 0. Spend the challenge. A proof is bound to one, and the binding means nothing unless the
    //    community issued it and accepts it once: the same submission replayed carries the same
    //    challenge, and finds it gone. Before the token reads, so a replay costs nothing.
    super::pcs_challenge::consume(
        &state.join_requests_ks,
        applicant_did,
        &submission.challenge,
        now,
    )
    .await
    .map_err(|e| ProtoError::Serialization(e.to_string()))?;

    // 1. Read what is already spent, for exactly the serials this submission presents.
    let mut ledger = PreloadedLedger::default();
    for (_, token) in &submission.statements {
        let serial = vti_vetting_pcs::scheme::scalar_text(&token.serial)?;
        let key = spent_key(&token.label, &serial);
        let row = state
            .vetting_pcs_spent_ks
            .get_raw(key)
            .await
            .map_err(|e| ProtoError::Serialization(format!("spent-token store: {e}")))?;
        if let Some(bytes) = row {
            let row: SpentToken = serde_json::from_slice(&bytes)
                .map_err(|e| ProtoError::Serialization(e.to_string()))?;
            ledger.known.insert((token.label.clone(), serial), row);
        }
    }

    // 2. Decide against those.
    let hvk = from_bytes(&from_multibase(&config.hvk)?)?;
    let tvk = from_bytes(&from_multibase(&config.tvk)?)?;
    let tokens = TokenVerifier::new(community_did, tvk, config.live_token_labels.clone())?;
    let mut verifier = Verifier::new(
        VerifierParams {
            community: community_did.to_string(),
            audience: community_did.to_string(),
            requirements: requirements.clone(),
            requirements_digest: requirements_digest.to_string(),
        },
        hvk,
        tokens,
        config.live_periods.clone(),
    )?;
    // The ledger moves into the verifier for the call and comes back with what it took.
    let ledger = Box::new(ledger);
    verifier.tokens.set_ledger(ledger);
    let decision = verifier.submit(&submission, now)?;
    let taken = verifier
        .tokens
        .take_ledger()
        .downcast::<PreloadedLedger>()
        .map(|l| l.taken)
        .unwrap_or_default();

    // 3. Commit. A serial another request took in between loses the race, and the submission is
    //    refused rather than counted on a token somebody else spent.
    for (label, serial, row) in taken {
        let bytes =
            serde_json::to_vec(&row).map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let inserted = state
            .vetting_pcs_spent_ks
            .insert_raw_if_absent(spent_key(&label, &serial), bytes)
            .await
            .map_err(|e| ProtoError::Serialization(format!("spent-token store: {e}")))?;
        if !inserted {
            return Err(ProtoError::Serialization(format!(
                "token {serial} under {label} was spent concurrently; the submission is refused"
            )));
        }
    }
    Ok(Some(decision))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The submission the openvtc client produced, which `vti-vetting-pcs`'s own fixture test
    /// reads back with the verifier. Here it drives the *service* path: the store, the
    /// challenge, the spend commit.
    const FIXTURE: &str = include_str!("../../../vti-vetting-pcs/tests/fixtures/submission.json");

    /// End to end on the service: a VTC-issued challenge is spent by the submission that was
    /// bound to it, and the same submission replayed finds nothing to spend.
    ///
    /// This is the half that was missing while the client minted its own challenge — the proof
    /// verified then too, and it verified just as well the second time.
    #[tokio::test]
    async fn a_submission_spends_the_challenge_the_community_issued() {
        use crate::test_support::TestVtc;
        use chrono::Duration;

        let f: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
        let community = f["community"].as_str().unwrap();
        let requirements = serde_json::from_value(f["requirements"].clone()).unwrap();
        let digest = f["requirementsDigest"].as_str().unwrap();
        let now: DateTime<Utc> = f["now"].as_str().unwrap().parse().unwrap();
        let extensions = f["extensions"].clone();
        let hidden = &extensions["hiddenVetting"];
        let applicant = hidden["joinDid"].as_str().unwrap();
        let challenge = hidden["challenge"].as_str().unwrap();
        let config = HiddenVettingConfig {
            suite: f["extensions"]["hiddenVetting"]["suite"]
                .as_str()
                .unwrap()
                .to_string(),
            hvk: f["hvk"].as_str().unwrap().to_string(),
            tvk: f["tvk"].as_str().unwrap().to_string(),
            live_periods: serde_json::from_value(f["livePeriods"].clone()).unwrap(),
            live_token_labels: serde_json::from_value(f["liveTokenLabels"].clone()).unwrap(),
            drip_per_tick: default_drip_per_tick(),
        };

        let tv = TestVtc::builder().vtc_did(community).build().await;

        // No challenge yet: the proof verifies, and it is refused anyway.
        let err = decide(
            &tv.state,
            community,
            applicant,
            &requirements,
            digest,
            &config,
            &extensions,
            now,
        )
        .await
        .expect_err("this community issued no challenge");
        assert!(
            format!("{err}").contains("no open hidden-vetting challenge"),
            "{err}"
        );

        // With the challenge recorded, the same submission is counted.
        super::super::pcs_challenge::record(
            &tv.state.join_requests_ks,
            applicant,
            challenge,
            Duration::minutes(15),
            now,
        )
        .await
        .unwrap();
        let decision = decide(
            &tv.state,
            community,
            applicant,
            &requirements,
            digest,
            &config,
            &extensions,
            now,
        )
        .await
        .expect("the proof verifies under the published parameters")
        .expect("the submission carries a hidden-vetting proof");
        assert!(decision.evaluation.satisfied(), "{:?}", decision.evaluation);
        assert_eq!(
            decision.evaluation.distinct_vetters(),
            f["expect"]["distinctVetters"].as_u64().unwrap() as usize
        );
        // And the facts carry tags, not DIDs.
        for s in &decision.statements {
            assert!(s.issuer.starts_with('z'), "{}", s.issuer);
            assert_ne!(s.issuer, applicant);
        }

        // Replayed: the challenge was spent by the first one.
        let err = decide(
            &tv.state,
            community,
            applicant,
            &requirements,
            digest,
            &config,
            &extensions,
            now,
        )
        .await
        .expect_err("the challenge is gone");
        assert!(format!("{err}").contains("already used"), "{err}");
    }

    #[test]
    fn spent_keys_separate_labels_and_serials() {
        let a = spent_key("token/2026-09", "zSerial");
        assert_ne!(a, spent_key("token/2026-10", "zSerial"));
        assert_ne!(a, spent_key("token/2026-09", "zOther"));
        assert_eq!(a, spent_key("token/2026-09", "zSerial"));
        // The length framing stops a label's tail from reading as a serial's head.
        assert_ne!(
            spent_key("token/2026-09z", "Serial"),
            spent_key("token/2026-09", "zSerial")
        );
    }

    #[test]
    fn a_preloaded_row_for_another_applicant_is_a_double_spend() {
        let mut ledger = PreloadedLedger::default();
        ledger.known.insert(
            ("token/2026-09".into(), "zSerial".into()),
            SpentToken {
                id: "zAlice".into(),
                tag: "zTagA".into(),
                spent_at: Utc::now(),
            },
        );
        assert_eq!(
            ledger
                .record("token/2026-09", "zSerial", "zBob", "zTagA")
                .unwrap(),
            SpendOutcome::DoubleSpend
        );
        // The same (id, tag) is a resubmission, and takes nothing new.
        assert_eq!(
            ledger
                .record("token/2026-09", "zSerial", "zAlice", "zTagA")
                .unwrap(),
            SpendOutcome::AlreadyCounted
        );
        assert!(ledger.taken.is_empty());
        // A serial nobody has spent is taken, once, and queued for the commit.
        assert_eq!(
            ledger
                .record("token/2026-09", "zFresh", "zAlice", "zTagB")
                .unwrap(),
            SpendOutcome::Fresh
        );
        assert_eq!(ledger.taken.len(), 1);
    }
}
