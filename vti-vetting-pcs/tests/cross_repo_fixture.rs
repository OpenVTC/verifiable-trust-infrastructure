//! The VTC's verifier against a submission built by the openvtc client.
//!
//! `tests/fixtures/submission.json` is generated on the openvtc `zkp-pcs` branch by
//! `openvtc-vetting-pcs/tests/wire_fixture.rs` and copied here verbatim. Nothing in this test
//! shares code with the producer beyond the mirrored modules: if the two copies of the wire
//! format, the contexts or the token encoding ever drift, this fails.
//!
//! It is also the only end-to-end evidence on this branch that the VTC learns no vetter.

use chrono::{DateTime, Utc};
use predicate_credential_system::serialization::{from_bytes, from_multibase};
use vta_sdk::protocols::vetting::VettingRequirements;
use vti_vetting_pcs::{
    token::TokenVerifier,
    verifier::{Verifier, VerifierParams},
    wire::SubmissionWire,
};

const FIXTURE: &str = include_str!("fixtures/submission.json");

struct Fixture {
    verifier: Verifier,
    submission: vti_vetting_pcs::verifier::Submission,
    now: DateTime<Utc>,
    satisfied: bool,
    distinct: usize,
}

fn load() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let community = f["community"].as_str().unwrap().to_string();
    let requirements: VettingRequirements =
        serde_json::from_value(f["requirements"].clone()).expect("requirements parse");
    let hvk = from_bytes(&from_multibase(f["hvk"].as_str().unwrap()).unwrap()).unwrap();
    let tvk = from_bytes(&from_multibase(f["tvk"].as_str().unwrap()).unwrap()).unwrap();
    let live_periods: Vec<String> = f["livePeriods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let live_token_labels: Vec<String> = f["liveTokenLabels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let tokens = TokenVerifier::new(&community, tvk, live_token_labels).unwrap();
    let verifier = Verifier::new(
        VerifierParams {
            community: community.clone(),
            audience: community,
            requirements,
            requirements_digest: f["requirementsDigest"].as_str().unwrap().to_string(),
        },
        hvk,
        tokens,
        live_periods,
    )
    .unwrap();
    let wire = SubmissionWire::from_extensions(&f["extensions"])
        .expect("extensions decode")
        .expect("the hiddenVetting member is present");
    Fixture {
        verifier,
        submission: wire.to_submission().expect("submission decodes"),
        now: DateTime::parse_from_rfc3339(f["now"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc),
        satisfied: f["expect"]["satisfied"].as_bool().unwrap(),
        distinct: f["expect"]["distinctVetters"].as_u64().unwrap() as usize,
    }
}

#[test]
fn the_vtc_accepts_a_submission_built_by_the_openvtc_client() {
    let mut f = load();
    let decision = f
        .verifier
        .submit(&f.submission, f.now)
        .expect("the proof verifies under the published parameters");
    assert_eq!(decision.evaluation.satisfied(), f.satisfied);
    assert_eq!(decision.evaluation.distinct_vetters(), f.distinct);
    assert!(decision.statements.iter().all(|s| s.counted));
}

#[test]
fn the_facts_the_policy_sees_name_no_vetter() {
    let mut f = load();
    let decision = f.verifier.submit(&f.submission, f.now).unwrap();
    let facts = serde_json::to_string(&decision.statements).unwrap();
    // Every issuer is a tag (multibase), never a DID.
    for s in &decision.statements {
        assert!(
            s.issuer.starts_with('z'),
            "issuer {} is not a tag",
            s.issuer
        );
    }
    assert!(!facts.contains("did:"), "a DID reached the facts: {facts}");
}

#[test]
fn a_replayed_submission_spends_its_tokens_once() {
    let mut f = load();
    let first = f.verifier.submit(&f.submission, f.now).unwrap();
    assert_eq!(first.evaluation.distinct_vetters(), f.distinct);
    // The same submission again: the serials are already spent under the same (id, tag), which
    // is the `requestMore` resubmission case, so it counts the same and raises no anomaly.
    let again = f.verifier.submit(&f.submission, f.now).unwrap();
    assert_eq!(again.evaluation.distinct_vetters(), f.distinct);
    assert!(f.verifier.tokens.anomalies.is_empty());
}

#[test]
fn a_tampered_statement_breaks_the_proof() {
    let mut f = load();
    // Claim a different method for the first statement: `ctx_j` covers the metadata, so the
    // attestation no longer verifies and the whole proof is refused.
    f.submission.statements[0].0.method = vta_sdk::protocols::vetting::VettingMethod::Video;
    let err = f
        .verifier
        .submit(&f.submission, f.now)
        .expect_err("a rewritten statement must not verify");
    assert!(
        matches!(err, vti_vetting_pcs::ProtoError::ProofRejected(_)),
        "unexpected error: {err}"
    );
}
