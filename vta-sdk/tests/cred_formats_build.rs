//! Dependency-wiring build/link check for the adopted TDK credential crates
//! that are not the near-term path (vti-credential-architecture §0.2 —
//! "the new deps build cleanly").
//!
//! SD-JWT-VC (the near-term format) has its own functional smoke test in
//! `sd_jwt_vc_smoke.rs`. This file pins that the *rest* of the adopted set —
//! `affinidi-bbs`, the `bbs-2023` Data Integrity cryptosuite, and
//! `affinidi-openid4vp` — compile and link inside the workspace and that their
//! key entry points are reachable. It is intentionally light on behaviour:
//! BBS+ and OID4VP/DCQL integration are later-phase, audit-gated work.

/// The `affinidi-data-integrity` `bbs-2023` feature must activate the BBS+
/// Data Integrity cryptosuite. Naming the (feature-gated) variant proves the
/// feature is wired through the workspace dependency.
#[test]
fn bbs_2023_cryptosuite_is_wired() {
    use affinidi_data_integrity::crypto_suites::CryptoSuite;

    let suite = CryptoSuite::try_from("bbs-2023").expect("bbs-2023 cryptosuite must resolve");
    assert!(matches!(suite, CryptoSuite::Bbs2023));
}

/// `affinidi-bbs` must link and round-trip: keygen → sign → verify, then a
/// zero-knowledge selective-disclosure proof over a subset of messages. This
/// is the unlinkable-disclosure primitive the credential plane will later use;
/// here it just confirms the crate is usable from the workspace.
#[test]
fn bbs_sign_verify_and_selective_disclosure_round_trip() {
    // Deterministic key material (>= 32 bytes) keeps the test reproducible.
    let sk = affinidi_bbs::keygen(&[9u8; 32], b"vti-cred-0.2-smoke").expect("bbs keygen");
    let pk = affinidi_bbs::sk_to_pk(&sk);

    let header = b"vti-smoke-header";
    let messages: [&[u8]; 3] = [b"community", b"member_handle", b"tier"];

    let sig = affinidi_bbs::sign(&sk, &pk, header, &messages).expect("bbs sign");
    assert!(
        affinidi_bbs::verify(&pk, &sig, header, &messages).expect("bbs verify"),
        "freshly-signed BBS signature must verify"
    );

    // Disclose only message index 0 ("community"); keep the rest hidden.
    let presentation_header = b"verifier-nonce";
    let disclosed_indexes = [0usize];
    let disclosed_messages: [&[u8]; 1] = [messages[0]];

    let proof = affinidi_bbs::proof_gen(
        &pk,
        &sig,
        header,
        presentation_header,
        &messages,
        &disclosed_indexes,
    )
    .expect("bbs proof_gen");

    assert!(
        affinidi_bbs::proof_verify(
            &pk,
            &proof,
            header,
            presentation_header,
            &disclosed_messages,
            &disclosed_indexes,
        )
        .expect("bbs proof_verify"),
        "selective-disclosure proof for the disclosed subset must verify"
    );
}

/// `affinidi-openid4vp` must link and its presentation-exchange types must be
/// constructable / serializable. (DCQL is the one net-new TDK gap and lands in
/// a later task; this just pins that the published base is wired in.)
#[test]
fn openid4vp_types_are_reachable() {
    use affinidi_openid4vp::types::PresentationDefinition;

    let pd = PresentationDefinition {
        id: "vti-cred-0.2-smoke".to_string(),
        name: None,
        purpose: None,
        input_descriptors: Vec::new(),
        submission_requirements: None,
        format: None,
    };
    let json = serde_json::to_string(&pd).expect("serialize PresentationDefinition");
    assert!(json.contains("vti-cred-0.2-smoke"));
}
