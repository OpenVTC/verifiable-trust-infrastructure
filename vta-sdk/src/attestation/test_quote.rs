//! Synthetic AWS Nitro attestation quotes for deterministic verifier tests +
//! differential parity against the upstream `nitro_attest` crate (issue #449).
//!
//! Real Nitro quotes can only be produced by a live enclave, so to exercise the
//! *accept* path (and failure modes around it) deterministically we assemble a
//! structurally-faithful quote rooted at a **synthetic** trust anchor:
//!
//!  1. `nitro_attest::builder::chain()` mints a 5-cert root→leaf P-384 chain;
//!  2. we build the CBOR `AttestationDoc` (leaf as `certificate`, the rest as
//!     `cabundle`, root-first) via the public nsm-api constructor; and
//!  3. wrap it in a COSE_Sign1 signed by the leaf key (ES384, empty AAD) —
//!     exactly the envelope a real NSM emits.
//!
//! Our [`NitroVerifier`] accepts it under `TrustAnchor::RootFingerprint(<that
//! synthetic root>)`; the upstream verifier rejects it (its baked anchor is the
//! real AWS root) — which is itself the lever the anchor-parity test pulls to
//! read upstream's baked fingerprint and confirm ours matches.

use std::collections::BTreeMap;

use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest as NsmDigest};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair};
use time::{Duration, OffsetDateTime};

use super::verify::{NitroVerifier, TrustAnchor};

/// A synthetic quote plus everything needed to verify it deterministically.
pub(crate) struct SyntheticQuote {
    /// Serialized COSE_Sign1 attestation quote bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the synthetic root cert's DER — the trust anchor to inject.
    pub root_fingerprint: [u8; 32],
    /// An instant inside every cert's validity window (certs span ±lifetime/2
    /// around generation; the leaf's ±1.5h is the tightest).
    pub valid_now: OffsetDateTime,
    /// PCR0 / PCR8 values embedded (non-zero so they survive extraction).
    pub pcr0: Vec<u8>,
    pub pcr8: Vec<u8>,
    pub module_id: String,
}

impl SyntheticQuote {
    pub(crate) fn verifier(&self) -> NitroVerifier {
        NitroVerifier {
            anchor: TrustAnchor::RootFingerprint(self.root_fingerprint),
            now: self.valid_now,
        }
    }
}

/// Build a valid synthetic quote committing to `user_data`.
pub(crate) fn build(user_data: Vec<u8>) -> SyntheticQuote {
    build_inner(user_data, None, true)
}

/// Build a valid synthetic quote committing to `user_data` AND binding `nonce`
/// — the shape the `/attestation/config-report` endpoint emits.
pub(crate) fn build_with_nonce(user_data: Vec<u8>, nonce: Vec<u8>) -> SyntheticQuote {
    build_inner(user_data, Some(nonce), true)
}

/// Build a synthetic quote whose COSE signature is invalid (signed over a
/// different payload than the one carried), to exercise the signature path.
pub(crate) fn build_with_bad_signature(user_data: Vec<u8>) -> SyntheticQuote {
    build_inner(user_data, None, false)
}

fn build_inner(user_data: Vec<u8>, nonce: Option<Vec<u8>>, good_signature: bool) -> SyntheticQuote {
    let chain = nitro_attest::builder::chain(); // [root, l1, l2, l3, leaf]
    let der: Vec<Vec<u8>> = chain
        .iter()
        .map(|c| c.cert.der().as_ref().to_vec())
        .collect();
    let root_fingerprint: [u8; 32] = digest(&SHA256, &der[0])
        .as_ref()
        .try_into()
        .expect("sha256 is 32 bytes");

    let leaf_der = der.last().expect("chain has a leaf").clone();
    let cabundle: Vec<Vec<u8>> = der[..der.len() - 1].to_vec(); // root-first, no leaf

    let module_id = "i-synthetic-enclave".to_string();
    let pcr0 = vec![0x11u8; 48];
    let pcr8 = vec![0x88u8; 48];
    let mut pcrs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    pcrs.insert(0, pcr0.clone());
    pcrs.insert(8, pcr8.clone());
    // 2020-01-01T00:00:00Z in ms — value is not validity-checked by the verifier.
    let timestamp_ms: u64 = 1_577_836_800_000;

    let doc = AttestationDoc::new(
        module_id.clone(),
        NsmDigest::SHA384,
        timestamp_ms,
        pcrs,
        leaf_der,
        cabundle,
        Some(user_data),
        nonce.clone(),
        None,
    );
    let payload = doc.to_binary();

    // Sign the COSE_Sign1 with the leaf key (ES384). For the bad-signature
    // case, sign over a corrupted payload but carry the real one, so the chain
    // walk still passes and only the COSE signature check fails.
    let leaf_keypair = &chain.last().expect("leaf").keys;
    let pkcs8 = leaf_keypair.serialize_der();
    let rng = SystemRandom::new();
    let signing_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &pkcs8, &rng)
        .expect("leaf PKCS#8 loads into ring");

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |tbs| {
            let to_sign = if good_signature {
                tbs.to_vec()
            } else {
                let mut corrupted = tbs.to_vec();
                corrupted[0] ^= 0xff;
                corrupted
            };
            signing_key
                .sign(&rng, &to_sign)
                .expect("ring ES384 sign")
                .as_ref()
                .to_vec()
        })
        .build();
    let bytes = sign1.to_vec().expect("COSE_Sign1 serializes");

    SyntheticQuote {
        bytes,
        root_fingerprint,
        valid_now: OffsetDateTime::now_utc(),
        pcr0,
        pcr8,
        module_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::parse::parse_nitro_quote;
    use crate::attestation::verify::{
        AWS_NITRO_ROOT_G1_FINGERPRINT, AWS_NITRO_ROOT_G1_PEM, NitroVerifyError,
    };
    use crate::hex::lower as hex_lower;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64STD;

    // --- parse-only entry point (acceptance box 1) ---------------------------

    #[test]
    fn parse_extracts_fields_without_verifying() {
        let q = build(b"commitment".to_vec());
        let parsed = parse_nitro_quote(&q.bytes).expect("synthetic quote parses");
        assert_eq!(parsed.module_id, q.module_id);
        assert_eq!(parsed.user_data.as_deref(), Some(b"commitment".as_ref()));
        assert_eq!(parsed.pcrs.get(&0), Some(&q.pcr0));
        assert_eq!(parsed.pcrs.get(&8), Some(&q.pcr8));
    }

    #[test]
    fn parse_is_total_on_garbage() {
        // The fuzz invariant: no input panics, all rejected as a typed error.
        for bytes in [
            vec![],
            vec![0u8; 64],
            vec![0xff; 1024],
            b"not cbor at all".to_vec(),
        ] {
            assert!(parse_nitro_quote(&bytes).is_err());
        }
    }

    // --- injectable anchor + clock (acceptance box 2) ------------------------

    #[test]
    fn verifier_accepts_with_matching_anchor_and_clock() {
        let q = build(b"ud".to_vec());
        let parsed = q.verifier().verify(&q.bytes).expect("verifies");
        assert_eq!(parsed.module_id, q.module_id);
    }

    #[test]
    fn verifier_rejects_wrong_anchor() {
        let q = build(b"ud".to_vec());
        let v = NitroVerifier {
            anchor: TrustAnchor::RootFingerprint([0u8; 32]),
            now: q.valid_now,
        };
        assert!(matches!(
            v.verify(&q.bytes),
            Err(NitroVerifyError::RootFingerprintMismatch { .. })
        ));
    }

    #[test]
    fn verifier_rejects_aws_anchor_for_synthetic_chain() {
        // The synthetic root is not the AWS root, so the production anchor must
        // reject it — the property that keeps a fake chain from ever verifying.
        let q = build(b"ud".to_vec());
        let v = NitroVerifier::aws_production(q.valid_now);
        assert!(matches!(
            v.verify(&q.bytes),
            Err(NitroVerifyError::RootFingerprintMismatch { .. })
        ));
    }

    #[test]
    fn verifier_rejects_expired_and_not_yet_valid() {
        let q = build(b"ud".to_vec());
        // Leaf window is ±1.5h around generation; ±2h falls outside it.
        let expired = NitroVerifier {
            anchor: TrustAnchor::RootFingerprint(q.root_fingerprint),
            now: q.valid_now + Duration::hours(2),
        };
        assert!(matches!(
            expired.verify(&q.bytes),
            Err(NitroVerifyError::CertExpired { .. })
        ));
        let early = NitroVerifier {
            anchor: TrustAnchor::RootFingerprint(q.root_fingerprint),
            now: q.valid_now - Duration::hours(2),
        };
        assert!(matches!(
            early.verify(&q.bytes),
            Err(NitroVerifyError::CertNotYetValid { .. })
        ));
    }

    #[test]
    fn verifier_rejects_bad_cose_signature() {
        let q = build_with_bad_signature(b"ud".to_vec());
        assert!(matches!(
            q.verifier().verify(&q.bytes),
            Err(NitroVerifyError::CoseSignatureInvalid)
        ));
    }

    // --- differential parity vs upstream nitro_attest ------------------------

    #[test]
    fn aws_anchor_fingerprint_matches_vendored_pem() {
        // Our embedded constant must equal SHA-256 of the vendored root cert's
        // DER body (the value AWS publishes), independent of any hardcoding.
        let der = pem_to_der(AWS_NITRO_ROOT_G1_PEM);
        let computed: [u8; 32] = digest(&SHA256, &der).as_ref().try_into().unwrap();
        assert_eq!(computed, AWS_NITRO_ROOT_G1_FINGERPRINT);
        assert_eq!(
            hex_lower(&AWS_NITRO_ROOT_G1_FINGERPRINT),
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
    }

    #[test]
    fn aws_anchor_fingerprint_matches_upstream_baked_value() {
        // Feed a synthetic quote to upstream: it rejects at the root-fingerprint
        // check, surfacing its baked AWS fingerprint in `want`. Assert ours ==
        // theirs, so the two verifiers can never disagree on the trust anchor.
        let q = build(b"ud".to_vec());
        let err = nitro_attest::UnparsedAttestationDoc::from(q.bytes.as_slice())
            .parse_and_verify(q.valid_now)
            .expect_err("synthetic root is not the AWS root");
        match err {
            nitro_attest::Error::CertificateRootInvalid { want, .. } => {
                assert_eq!(want, hex_lower(&AWS_NITRO_ROOT_G1_FINGERPRINT));
            }
            other => panic!("expected CertificateRootInvalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_failure_implies_upstream_verify_failure() {
        // Differential invariant runnable on arbitrary bytes (also the fuzz
        // oracle): if our structural parse fails, upstream's parse_and_verify —
        // which must parse before it can verify — fails too.
        let now = OffsetDateTime::now_utc();
        for bytes in [
            vec![],
            vec![0u8; 32],
            vec![0xab; 200],
            b"\x84garbage".to_vec(),
        ] {
            if parse_nitro_quote(&bytes).is_err() {
                assert!(
                    nitro_attest::UnparsedAttestationDoc::from(bytes.as_slice())
                        .parse_and_verify(now)
                        .is_err(),
                    "upstream accepted bytes our parser rejected: {bytes:?}"
                );
            }
        }
    }

    // --- full public API with injected verifier ------------------------------

    #[test]
    fn verify_nitro_quote_with_end_to_end() {
        use crate::attestation::verify_nitro_quote_with;
        use crate::sealed_transfer::AttestationQuoteAssertion;

        // Commitment = SHA256(client_ed || nonce || producer_ed).
        let client_ed = [7u8; 32];
        let nonce = [9u8; 16];
        let (_sk, producer_ed) = crate::sealed_transfer::generate_ed25519_keypair();
        let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed);

        let mut h = ring::digest::Context::new(&SHA256);
        h.update(&client_ed);
        h.update(&nonce);
        h.update(&producer_ed);
        let commitment = h.finish().as_ref().to_vec();

        let q = build(commitment);
        let assertion = AttestationQuoteAssertion {
            format: "nitro".into(),
            quote_b64: B64STD.encode(&q.bytes),
        };

        let verified =
            verify_nitro_quote_with(&assertion, &client_ed, &nonce, &producer_did, &q.verifier())
                .expect("end-to-end verify");
        assert_eq!(verified.module_id, q.module_id);
        assert_eq!(verified.pcr0_hex, hex_lower(&q.pcr0));
        assert_eq!(verified.pcr8_hex, hex_lower(&q.pcr8));

        // Same (validly-signed) quote, but a different client key → the
        // recomputed commitment no longer matches the embedded user_data, so
        // the binding check rejects it (chain + signature still pass).
        let wrong_client = [8u8; 32];
        assert!(matches!(
            verify_nitro_quote_with(
                &assertion,
                &wrong_client,
                &nonce,
                &producer_did,
                &q.verifier()
            ),
            Err(crate::attestation::AttestationVerifyError::UserDataMismatch)
        ));
    }

    // --- config-report verifier (issue: un-baked config attestation gate) -----

    #[test]
    fn verify_config_attestation_with_end_to_end() {
        use crate::attestation::{ConfigAttestationVerifyError, verify_config_attestation_with};
        use sha2::{Digest, Sha384};

        // The endpoint returns the canonical secret-free config VIEW and commits
        // SHA-384(view) as user_data. The verifier hashes the returned view and
        // matches it against the signed user_data, then PINS tee.kms.key_arn.
        let key_arn = "arn:aws:kms:us-east-1:111122223333:key/abcd";
        let view = format!(r#"{{"tee":{{"kms":{{"key_arn":"{key_arn}"}}}}}}"#).into_bytes();
        let digest = Sha384::digest(&view).to_vec();
        let nonce = b"caller-nonce-1234".to_vec();
        let q = build_with_nonce(digest.clone(), nonce.clone());
        let evidence = B64STD.encode(&q.bytes);
        let view_b64 = B64STD.encode(&view);
        let pcr0 = hex_lower(&q.pcr0);
        let pcr8 = hex_lower(&q.pcr8);

        // Happy path: view→digest binding, nonce, PCR0/PCR8 pins, and the
        // MANDATORY key_arn pin all verify.
        let verified = verify_config_attestation_with(
            &evidence,
            &view_b64,
            &nonce,
            &pcr0,
            Some(&pcr8),
            key_arn,
            &q.verifier(),
        )
        .expect("config attestation verifies end-to-end");
        assert_eq!(verified.config_digest_sha384(), digest.as_slice());
        assert_eq!(verified.nonce(), nonce.as_slice());
        assert_eq!(verified.pcr0_hex(), pcr0);
        assert_eq!(verified.pcr8_hex(), pcr8);
        assert_eq!(verified.key_arn(), key_arn);
        assert_eq!(verified.config_view_json(), view.as_slice());

        // A tampered/mismatched view → SHA-384(view) no longer equals the signed
        // user_data, so a swapped config is caught.
        let other_view =
            br#"{"tee":{"kms":{"key_arn":"arn:aws:kms:us-east-1:111122223333:key/EVIL"}}}"#;
        assert!(matches!(
            verify_config_attestation_with(
                &evidence,
                &B64STD.encode(other_view),
                &nonce,
                &pcr0,
                None,
                key_arn,
                &q.verifier()
            ),
            Err(ConfigAttestationVerifyError::ConfigViewDigestMismatch)
        ));

        // A stale/replayed nonce is rejected (freshness).
        assert!(matches!(
            verify_config_attestation_with(
                &evidence,
                &view_b64,
                b"different-nonce",
                &pcr0,
                None,
                key_arn,
                &q.verifier()
            ),
            Err(ConfigAttestationVerifyError::NonceMismatch)
        ));

        // A wrong image pin (PCR0) is rejected even though the quote is genuine.
        assert!(matches!(
            verify_config_attestation_with(
                &evidence,
                &view_b64,
                &nonce,
                "deadbeef",
                None,
                key_arn,
                &q.verifier()
            ),
            Err(ConfigAttestationVerifyError::Pcr(_))
        ));

        // An unexpected key_arn (parent bound the enclave to a key we did not
        // approve) is rejected, even though the view is authentic. This is the
        // seed-exfiltration mitigation — and it is NOT skippable.
        assert!(matches!(
            verify_config_attestation_with(
                &evidence,
                &view_b64,
                &nonce,
                &pcr0,
                None,
                "arn:aws:kms:us-east-1:111122223333:key/NOT-MINE",
                &q.verifier()
            ),
            Err(ConfigAttestationVerifyError::KeyArnMismatch { .. })
        ));
    }

    #[test]
    fn authenticate_does_not_approve_policy_but_exposes_the_view() {
        use crate::attestation::authenticate_config_attestation_with;
        use sha2::{Digest, Sha384};

        // The weaker `authenticate_*` path proves the view is AUTHENTIC (chain +
        // PCR0 + nonce + digest binding) WITHOUT pinning key_arn — so it must NOT
        // be confusable with the verified onboarding result. It returns the
        // parent-chosen key_arn for the caller to inspect/pin itself.
        let parent_key = "arn:aws:kms:us-east-1:999988887777:key/parent-owned";
        let view = format!(r#"{{"tee":{{"kms":{{"key_arn":"{parent_key}"}}}}}}"#).into_bytes();
        let digest = Sha384::digest(&view).to_vec();
        let nonce = b"n2".to_vec();
        let q = build_with_nonce(digest, nonce.clone());

        let authed = authenticate_config_attestation_with(
            &B64STD.encode(&q.bytes),
            &B64STD.encode(&view),
            &nonce,
            &hex_lower(&q.pcr0),
            None,
            &q.verifier(),
        )
        .expect("authenticate succeeds on a genuine (approved-image) quote");
        // The authenticated view surfaces the parent's key so the caller can
        // detect it — authentication alone does not endorse it.
        assert_eq!(authed.key_arn(), Some(parent_key));
        assert_eq!(authed.config_view_json(), view.as_slice());

        // A wrong image pin still fails even on the authenticate-only path.
        assert!(
            authenticate_config_attestation_with(
                &B64STD.encode(&q.bytes),
                &B64STD.encode(&view),
                &nonce,
                "deadbeef",
                None,
                &q.verifier(),
            )
            .is_err()
        );
    }

    #[test]
    fn verify_config_attestation_rejects_synthetic_chain_under_aws_anchor() {
        use crate::attestation::{ConfigAttestationVerifyError, verify_config_attestation_with};
        use sha2::{Digest, Sha384};
        // The production anchor must reject a synthetic-root quote — the property
        // that stops a fabricated config report from ever verifying.
        let key_arn = "arn:aws:kms:us-east-1:111122223333:key/abcd";
        let view = format!(r#"{{"tee":{{"kms":{{"key_arn":"{key_arn}"}}}}}}"#).into_bytes();
        let digest = Sha384::digest(&view).to_vec();
        let nonce = b"n".to_vec();
        let q = build_with_nonce(digest, nonce.clone());
        let evidence = B64STD.encode(&q.bytes);
        let err = verify_config_attestation_with(
            &evidence,
            &B64STD.encode(&view),
            &nonce,
            &hex_lower(&q.pcr0),
            None,
            key_arn,
            &NitroVerifier::aws_production(q.valid_now),
        )
        .expect_err("synthetic root must not verify under the AWS anchor");
        assert!(matches!(err, ConfigAttestationVerifyError::QuoteInvalid(_)));
    }

    #[test]
    fn wire_report_verify_cross_checks_echoed_metadata() {
        use crate::attestation::ConfigAttestationVerifyError;
        use crate::attestation_report::ConfigAttestationReport;
        use sha2::{Digest, Sha384};

        let key_arn = "arn:aws:kms:us-east-1:111122223333:key/abcd";
        let view = format!(r#"{{"tee":{{"kms":{{"key_arn":"{key_arn}"}}}}}}"#).into_bytes();
        let digest = Sha384::digest(&view).to_vec();
        let nonce = b"caller-nonce-1234".to_vec();
        let q = build_with_nonce(digest.clone(), nonce.clone());
        let pcr0 = hex_lower(&q.pcr0);

        let good = |report_digest: String, report_nonce: String| ConfigAttestationReport {
            config_digest_sha384: report_digest,
            config_view: B64STD.encode(&view),
            nonce: report_nonce,
            tee_type: "nitro".into(),
            evidence: B64STD.encode(&q.bytes),
            generated_at: 0,
        };

        // Faithful outer metadata verifies through the wire-form method.
        let report = good(B64STD.encode(&digest), hex_lower(&nonce));
        let verified = report
            .verify_with(&nonce, &pcr0, None, key_arn, &q.verifier())
            .expect("faithful report verifies");
        assert_eq!(verified.key_arn(), key_arn);
        assert_eq!(verified.config_digest_sha384(), digest.as_slice());

        // A parent that tampers the echoed digest is rejected even though the
        // signed evidence is otherwise valid.
        let tampered_digest = good(B64STD.encode([0u8; 48]), hex_lower(&nonce));
        assert!(matches!(
            tampered_digest.verify_with(&nonce, &pcr0, None, key_arn, &q.verifier()),
            Err(ConfigAttestationVerifyError::OuterDigestMismatch)
        ));

        // A tampered echoed nonce is likewise rejected.
        let tampered_nonce = good(B64STD.encode(&digest), hex_lower(b"other-nonce"));
        assert!(matches!(
            tampered_nonce.verify_with(&nonce, &pcr0, None, key_arn, &q.verifier()),
            Err(ConfigAttestationVerifyError::OuterNonceMismatch)
        ));
    }

    /// Full accept-path byte-parity against upstream on a **real** AWS-signed
    /// quote. Synthetic quotes can't exercise this (they use a synthetic root
    /// upstream rejects by design), so it needs a captured fixture and is
    /// `#[ignore]`d until one is committed. To activate: drop a real quote at
    /// `vta-sdk/tests/fixtures/nitro-quote.cose` and run
    /// `cargo test -p vta-sdk --features attest-verify -- --ignored`.
    #[test]
    #[ignore = "requires a real AWS Nitro quote fixture (live enclave)"]
    fn real_quote_field_parity_with_upstream() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/nitro-quote.cose"
        );
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("no fixture at {path}; drop a captured quote there to run this");
            return;
        };

        // Evaluate both verifiers at the quote's own creation time, which is
        // inside the cert validity windows by construction.
        let parsed = parse_nitro_quote(&bytes).expect("real quote parses");
        let now = OffsetDateTime::from_unix_timestamp((parsed.timestamp_ms / 1000) as i64)
            .expect("valid timestamp");

        let ours = NitroVerifier::aws_production(now)
            .verify(&bytes)
            .expect("our verifier accepts the real quote");
        let theirs = nitro_attest::UnparsedAttestationDoc::from(bytes.as_slice())
            .parse_and_verify(now)
            .expect("upstream accepts the real quote");

        assert_eq!(ours.module_id, theirs.module_id);
        assert_eq!(
            ours.user_data.as_deref(),
            theirs.user_data.as_ref().map(|b| b.as_ref())
        );
        assert_eq!(
            ours.timestamp_ms / 1000,
            theirs.timestamp.unix_timestamp() as u64
        );
        for (idx, digest) in &theirs.pcrs {
            assert_eq!(
                ours.pcrs.get(&(*idx as usize)).map(Vec::as_slice),
                Some(digest.value.as_slice()),
                "PCR{idx} differs"
            );
        }
    }

    /// Emit a valid synthetic quote into the fuzz seed corpus
    /// (`fuzz/seeds/nitro-quote/`). Coverage-guided fuzzers mutate from valid
    /// inputs, so the `fuzz_nitro_quote` target starts from a real COSE/CBOR
    /// document. `#[ignore]`d like the sibling seed generators; run with
    /// `cargo test -p vta-sdk --features attest-verify gen_nitro_fuzz_seed -- --ignored`.
    /// The keys are fresh each run — a seed need only be *valid*, not stable.
    #[test]
    #[ignore = "seed-corpus generator; run explicitly with --ignored"]
    fn gen_nitro_fuzz_seed() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fuzz/seeds/nitro-quote");
        std::fs::create_dir_all(dir).expect("create seed dir");
        let q = build(b"fuzz-seed-commitment".to_vec());
        // Sanity-check the seed actually verifies before we write it.
        q.verifier().verify(&q.bytes).expect("seed quote verifies");
        let path = format!("{dir}/synthetic.cose");
        std::fs::write(&path, &q.bytes).expect("write seed");
        println!("wrote {} ({} bytes)", path, q.bytes.len());
    }

    /// Decode a single-certificate PEM to its DER body using the base64 crate
    /// (no x509 PEM-feature dependency).
    fn pem_to_der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        B64STD.decode(body.trim()).expect("valid PEM base64")
    }
}
