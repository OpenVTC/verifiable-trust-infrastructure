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

use chrono::{DateTime, NaiveDate, Utc};
use hkdf::Hkdf;
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

/// HKDF info for the tag-masking key. Versioned: changing it makes every stored pseudonym
/// unlinkable from every earlier one, which is a migration, not a config change.
const MASK_KEY_INFO: &[u8] = b"vtc-vetting-pcs-tagmask/v1";

/// A tag, as this community stores it.
///
/// A tag is `usk·H₀(id)`. A quantum adversary takes one discrete log from it, recovers the
/// vetter's key, and — with the community's own enrolment table — puts a name to every tag that
/// vetter ever produced. The proof itself leaks nothing (it is simulatable), and the issuance
/// transcript hides the identifier unconditionally; **the tag is the part worth not keeping**.
///
/// So nothing downstream keeps the group element. What is stored is `HKDF(key, salt =
/// applicant, info = tag)` under a key derived from this community's master secret: stable for
/// one applicant, so distinctness and a resubmission still compare equal, and worthless on its
/// own to anybody holding a copy of the rows.
///
/// It is not a cure. A community that keeps both the key and the applicant DID can recompute
/// the mask, so this raises the cost of a future deanonymisation rather than removing it. What
/// removes it is retention: see `docs/design/vetting-hidden-vetters-pcs.md` §18.
fn mask(key: &[u8; 32], applicant_did: &str, tag: &str) -> Result<String, ProtoError> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(applicant_did.as_bytes()), key)
        .expand(tag.as_bytes(), &mut out)
        .map_err(|e| ProtoError::Serialization(format!("mask a tag: {e}")))?;
    Ok(multibase::encode(multibase::Base::Base58Btc, out))
}

/// The masking key for this community, from the same master secret every other derived key
/// comes from.
///
/// Absent when no credential signer is configured. That is not a reason to fall back to storing
/// the raw tag — a deployment without a signer cannot admit anyone anyway — so the caller
/// treats it as a failure.
fn mask_key(state: &AppState) -> Result<[u8; 32], ProtoError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        ProtoError::Serialization("credential signer not initialised — cannot mask tags".into())
    })?;
    let master = signer.ed25519_signing_key().ok_or_else(|| {
        ProtoError::Serialization("the credential signer holds no Ed25519 key".into())
    })?;
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &master.to_bytes())
        .expand(MASK_KEY_INFO, &mut key)
        .map_err(|e| ProtoError::Serialization(format!("derive the tag-mask key: {e}")))?;
    Ok(key)
}

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
    /// Events this community is running, if any (§5.1). Empty is the ordinary case — event mode
    /// is the exception, not the setting.
    #[serde(default)]
    pub events: Vec<HiddenVettingEvent>,
}

/// An event this community publishes, with the rates a vetter may ask for and the dates the
/// label it unlocks will be accepted.
///
/// The event is **not** live because it is listed here. It is live when an approver has named
/// themselves in `approved_by`, enough vetters have asked to be in it, and the day is inside its
/// window — three conditions checked where tokens are served, not where they are configured,
/// because a configuration edit is exactly what a coerced approver would be asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenVettingEvent {
    /// The community's name for the gathering. It is the anonymity set for every token spent
    /// under this event, so it names something people attend — never one desk or one shift.
    pub event_id: String,
    /// First day of the event, inclusive.
    pub start_date: NaiveDate,
    /// Last day of the event, inclusive.
    pub end_date: NaiveDate,
    /// Days after `end_date` the label keeps being accepted, so an applicant met on the last day
    /// still has time to submit. It is short by design: the event key exists to make a burst of
    /// tokens die with the event (§5.1).
    #[serde(default = "default_event_grace_days")]
    pub grace_days: u32,
    /// The smallest group this community will open the label for. A one-vetter event is an event
    /// key with one holder, which is a name.
    #[serde(default = "default_group_floor")]
    pub group_floor: usize,
    /// The published menu of rates. A vetter picks a tier rather than naming a number, so that a
    /// requested rate is not itself a distinguishing detail.
    pub tiers: Vec<HiddenVettingTier>,
    /// Who approved the event. `None` means nobody has, and the label is not live whatever else
    /// is true. A member who asked to be in the event may not be the one who approved it —
    /// raising your own cap is what a coerced vetter would be made to do.
    #[serde(default)]
    pub approved_by: Option<String>,
}

impl HiddenVettingEvent {
    /// The token label this event unlocks.
    #[must_use]
    pub fn label(&self) -> String {
        format!("token/event/{}", self.event_id)
    }

    /// The last day tokens under this event's label are issued or accepted.
    #[must_use]
    pub fn closes_after(&self) -> NaiveDate {
        self.end_date + chrono::Duration::days(i64::from(self.grace_days))
    }

    /// The tier by name, if this event publishes one.
    #[must_use]
    pub fn tier(&self, name: &str) -> Option<&HiddenVettingTier> {
        self.tiers.iter().find(|t| t.name == name)
    }
}

/// One rate on an event's published menu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenVettingTier {
    /// How the menu names it: `desk`, `busy-desk`.
    pub name: String,
    /// How many tokens a tick under this tier yields.
    pub drip_per_tick: usize,
}

/// Fourteen days: long enough that someone met on the closing afternoon can still submit, short
/// enough that a three-day burst at twenty a day does not outlive the month it was drawn in.
fn default_event_grace_days() -> u32 {
    14
}

/// Three, the same floor §5.1 names. Two is a coin flip.
fn default_group_floor() -> usize {
    3
}

/// Three a tick: enough for a vetter who meets people, small enough that a compromised vetter
/// cannot flood a community before the next rotation.
fn default_drip_per_tick() -> usize {
    3
}

/// The `vetting.ext` namespace a community publishes its hidden-vetting parameters under.
///
/// The same string the client reads (`openvtc_core::vetting::hidden::HIDDEN_VETTING_NS`). It is
/// a namespace rather than a member of the manifest because the manifest's own schema does not
/// enumerate these — `ext` is the framework's answer to exactly that, and a namespaced key is
/// what lets a client that does not implement this carry on without it.
pub const HIDDEN_VETTING_NS: &str = "org.openvtc.hidden-vetting";

impl HiddenVettingConfig {
    /// This community's parameters in the shape a client reads.
    ///
    /// **Not `serde_json::to_value(self)`, and the difference is the point.** What is stored is
    /// what the community mints with; what is published is what an applicant and a vetter need
    /// in order to talk to it. Three differences, each deliberate:
    ///
    /// - The keys are named for their role on the wire (`helperKey`, `tokenKey`) rather than for
    ///   their symbols in the scheme (`hvk`, `tvk`). A client implementing this from the
    ///   specification should not have to read the paper to find the right member.
    /// - Class labels are published whole (`vetter/2026-09`), not as the bare period the store
    ///   keeps. The label is what a request names, so publishing the period would make every
    ///   client reconstruct the same string and one of them get it wrong.
    /// - **`approvedBy` is dropped.** Who approved an event is the community's record of its own
    ///   decision; publishing it would name a member in a document every applicant receives, to
    ///   no purpose a vetter could act on. `graceDays` goes with it — a vetter is told
    ///   `closesAfter` when its request is approved, which is the same fact at the point it
    ///   matters.
    #[must_use]
    pub fn published(&self) -> serde_json::Value {
        serde_json::json!({
            "suite": self.suite,
            "helperKey": self.hvk,
            "tokenKey": self.tvk,
            "vetterLabels": self
                .live_periods
                .iter()
                .map(|p| format!("vetter/{p}"))
                .collect::<Vec<_>>(),
            "tokenLabels": self.live_token_labels,
            "dripPerTick": self.drip_per_tick,
            "events": self
                .events
                .iter()
                .map(|e| serde_json::json!({
                    "eventId": e.event_id,
                    "startDate": e.start_date,
                    "endDate": e.end_date,
                    "groupFloor": e.group_floor,
                    "tiers": e
                        .tiers
                        .iter()
                        .map(|t| serde_json::json!({
                            "name": t.name,
                            "dripPerTick": t.drip_per_tick,
                        }))
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// The token labels a submission may spend under, now.
///
/// Every live label, minus any event label whose grace period has run out. That deadline is the
/// community's own rather than an operator remembering to edit a list, and it is the second half
/// of the rule the separate event key exists for (§5.1): tokens drawn at an event's rate die
/// shortly after the event. Stop issuing under the label but keep accepting spends, and a
/// three-day burst at twenty a day is still spendable for as long as nobody tidies up.
///
/// A label naming no event this community runs is left alone — that is every ordinary monthly
/// label, and a stale event label with no configuration behind it, which has nothing to expire
/// against.
#[must_use]
fn accepted_token_labels(config: &HiddenVettingConfig, now: DateTime<Utc>) -> Vec<String> {
    let today = now.date_naive();
    config
        .live_token_labels
        .iter()
        .filter(|label| {
            super::pcs_event::event_of(config, label).is_none_or(|e| today <= e.closes_after())
        })
        .cloned()
        .collect()
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
///
/// The verifier hands it raw tags; what it stores are masked ones ([`mask`]). Equality is all
/// this ledger needs — "same applicant, same vetter" for a resubmission — and equality survives
/// the mask, so the row keeps what it has to and not the group element.
struct PreloadedLedger {
    known: HashMap<(String, String), SpentToken>,
    /// What the verifier took this time, to be committed afterwards.
    taken: Vec<(String, String, SpentToken)>,
    key: [u8; 32],
    applicant: String,
}

impl PreloadedLedger {
    fn new(key: [u8; 32], applicant: &str) -> Self {
        Self {
            known: HashMap::new(),
            taken: Vec::new(),
            key,
            applicant: applicant.to_string(),
        }
    }
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
        let id = mask(&self.key, &self.applicant, id)?;
        let tag = mask(&self.key, &self.applicant, tag)?;
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
            id,
            tag,
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
    let mask_key = mask_key(state)?;
    let mut ledger = PreloadedLedger::new(mask_key, applicant_did);
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
    let tokens = TokenVerifier::new(community_did, tvk, accepted_token_labels(config, now))?;
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
    let mut decision = verifier.submit(&submission, now)?;
    // What leaves this function is what gets stored and shown. The tag does not leave.
    for statement in &mut decision.statements {
        statement.issuer = mask(&mask_key, applicant_did, &statement.issuer)?;
    }
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
            events: Vec::new(),
        };

        // A signer, because masking a tag derives from the same master secret credential
        // issuance does — a community that cannot sign cannot admit anyone either.
        let tv = TestVtc::builder()
            .vtc_did(community)
            .with_signers(true)
            .build()
            .await;

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
        // The facts carry masked tags — never a DID, never the group element — and distinct
        // vetters still read as distinct, which is the only property the counting rule needs.
        let issuers: std::collections::HashSet<&str> = decision
            .statements
            .iter()
            .map(|s| s.issuer.as_str())
            .collect();
        assert_eq!(issuers.len(), decision.statements.len(), "{issuers:?}");
        let key = mask_key(&tv.state).unwrap();
        for s in &decision.statements {
            assert!(s.issuer.starts_with('z'), "{}", s.issuer);
            assert_ne!(s.issuer, applicant);
            // Masked under this community's key and this applicant: re-masking is a no-op on
            // an already-masked value, so the stored form is not the tag.
            assert_ne!(s.issuer, mask(&key, applicant, &s.issuer).unwrap());
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

    /// The mask has to be a pseudonym, not an encoding: stable where equality is needed, and
    /// different everywhere else.
    #[test]
    fn a_masked_tag_is_stable_per_applicant_and_nowhere_else() {
        let a = mask(&MASK_KEY, APPLICANT, "zTagA").unwrap();
        assert_eq!(a, mask(&MASK_KEY, APPLICANT, "zTagA").unwrap());
        assert!(a.starts_with('z'), "{a}");
        // The raw tag is not recoverable from, or present in, what is stored.
        assert!(!a.contains("zTagA"));
        // Another vetter, another applicant, another community's key: all different.
        assert_ne!(a, mask(&MASK_KEY, APPLICANT, "zTagB").unwrap());
        assert_ne!(
            a,
            mask(&MASK_KEY, "did:key:z6MkSomeoneElse", "zTagA").unwrap()
        );
        assert_ne!(a, mask(&[8u8; 32], APPLICANT, "zTagA").unwrap());
    }

    /// `vetting::HIDDEN_VETTING_MEMBER` is spelled by hand so that redaction works with the
    /// feature off. This is the pin that keeps the two spellings one spelling.
    #[test]
    fn the_extensions_member_matches_the_crates_own() {
        assert_eq!(
            super::super::HIDDEN_VETTING_MEMBER,
            vti_vetting_pcs::wire::EXTENSIONS_MEMBER
        );
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

    const MASK_KEY: [u8; 32] = [9u8; 32];
    const APPLICANT: &str = "did:key:z6MkBobsJoinDid";

    #[test]
    fn a_preloaded_row_for_another_applicant_is_a_double_spend() {
        let mut ledger = PreloadedLedger::new(MASK_KEY, APPLICANT);
        // A stored row holds masked values, which is what the ledger compares against.
        ledger.known.insert(
            ("token/2026-09".into(), "zSerial".into()),
            SpentToken {
                id: mask(&MASK_KEY, APPLICANT, "zAlice").unwrap(),
                tag: mask(&MASK_KEY, APPLICANT, "zTagA").unwrap(),
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

    fn config_with(events: Vec<HiddenVettingEvent>, labels: &[&str]) -> HiddenVettingConfig {
        HiddenVettingConfig {
            suite: vti_vetting_pcs::wire::SUITE.into(),
            hvk: "zHvk".into(),
            tvk: "zTvk".into(),
            live_periods: vec!["2026-09".into()],
            live_token_labels: labels.iter().map(|s| (*s).to_string()).collect(),
            drip_per_tick: 3,
            events,
        }
    }

    fn event(id: &str, ends: chrono::NaiveDate, grace: u32) -> HiddenVettingEvent {
        HiddenVettingEvent {
            event_id: id.into(),
            start_date: ends - chrono::Duration::days(2),
            end_date: ends,
            grace_days: grace,
            group_floor: 3,
            tiers: vec![HiddenVettingTier {
                name: "desk".into(),
                drip_per_tick: 20,
            }],
            approved_by: Some("did:key:zApprover".into()),
        }
    }

    /// The second half of the rule the separate event key exists for (§5.1). An operator who
    /// forgets to prune `liveTokenLabels` must not thereby leave a conference's worth of tokens
    /// spendable for the rest of the month — the community's own deadline is what closes it.
    #[test]
    fn an_event_label_stops_being_accepted_when_its_grace_runs_out() {
        let today = chrono::Utc::now().date_naive();
        let config = config_with(
            vec![
                event("open-summit", today, 14),
                event("last-years-summit", today - chrono::Duration::days(30), 14),
            ],
            &[
                "token/2026-09",
                "token/event/open-summit",
                "token/event/last-years-summit",
            ],
        );
        let accepted = accepted_token_labels(&config, chrono::Utc::now());
        assert_eq!(
            accepted,
            vec![
                "token/2026-09".to_string(),
                "token/event/open-summit".to_string()
            ],
            "the closed event's label is dropped though the operator still lists it"
        );
    }

    /// The last day is inclusive on both counts: the event's own end, and the grace after it.
    #[test]
    fn the_grace_period_includes_its_last_day() {
        let today = chrono::Utc::now().date_naive();
        // Ended 14 days ago with 14 days of grace: today is exactly `closesAfter`.
        let closing = config_with(
            vec![event("summit", today - chrono::Duration::days(14), 14)],
            &["token/event/summit"],
        );
        assert_eq!(
            accepted_token_labels(&closing, chrono::Utc::now()),
            vec!["token/event/summit".to_string()],
        );
        // One day further on, it is shut.
        let closed = config_with(
            vec![event("summit", today - chrono::Duration::days(15), 14)],
            &["token/event/summit"],
        );
        assert!(accepted_token_labels(&closed, chrono::Utc::now()).is_empty());
    }

    /// A label that names no event this community runs has nothing to expire against, and is
    /// left alone rather than guessed at.
    #[test]
    fn a_label_with_no_event_behind_it_is_left_alone() {
        let config = config_with(Vec::new(), &["token/2026-09", "token/event/who-knows"]);
        assert_eq!(
            accepted_token_labels(&config, chrono::Utc::now()).len(),
            2,
            "an event label with no configuration behind it is not silently dropped"
        );
    }
}
