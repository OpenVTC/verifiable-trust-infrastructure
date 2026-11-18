//! `keys/sign-document/0.1`: an `eddsa-jcs-2022` Data Integrity proof over a
//! JSON document.
//!
//! The signer builds the proof configuration and the hash data itself, so the
//! 64 bytes it signs are two SHA-256 digests the cryptosuite defines as its
//! own domain separation, never bytes a caller chose.
//!
//! As for a JWS, the proof is made in phases so the VTA (which signs through its
//! gates) and a service that holds its key build the same bytes:
//! [`prepare_document`], the signature, then [`finish_document`]; and
//! [`sign_document`] is the three in one call.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, check_i_json};
use crate::{Algorithm, FormatRefusal, PublicKey, SignError, Signer, VerifyError};

/// The proof configuration `keys/sign-document` builds (*The proof* item 1),
/// without `proofValue`.
pub fn document_proof_config(
    document: &Value,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Value {
    let mut config = Map::new();
    if let Some(context) = document.get("@context") {
        config.insert("@context".into(), context.clone());
    }
    config.insert("type".into(), "DataIntegrityProof".into());
    config.insert("cryptosuite".into(), "eddsa-jcs-2022".into());
    config.insert("created".into(), created.into());
    config.insert("verificationMethod".into(), verification_method.into());
    config.insert("proofPurpose".into(), proof_purpose.into());
    if let Some(c) = challenge {
        config.insert("challenge".into(), c.into());
    }
    if let Some(d) = domain {
        config.insert("domain".into(), d.into());
    }
    Value::Object(config)
}

/// `eddsa-jcs-2022` hash data: `SHA-256(JCS(config)) || SHA-256(JCS(document))`.
pub fn eddsa_jcs_2022_hash_data(document: &Value, config: &Value) -> Result<[u8; 64], String> {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&Sha256::digest(canonicalize(config)?.as_bytes()));
    out[32..].copy_from_slice(&Sha256::digest(canonicalize(document)?.as_bytes()));
    Ok(out)
}

/// The finished proof: `config` with `proofValue` set to `signature`, as the
/// multibase base58btc string `eddsa-jcs-2022` carries.
pub fn finish_proof(mut config: Value, signature: &[u8]) -> Value {
    config["proofValue"] = multibase::encode(multibase::Base::Base58Btc, signature).into();
    config
}

/// A document, its proof configuration and the 64 bytes to sign: what is signed,
/// before it is.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentSigningInput {
    document: Value,
    config: Value,
    hash_data: [u8; 64],
}

impl DocumentSigningInput {
    /// The bytes to sign.
    pub fn bytes(&self) -> &[u8; 64] {
        &self.hash_data
    }

    /// The proof configuration, without `proofValue`.
    pub fn config(&self) -> &Value {
        &self.config
    }
}

/// A document and the proof that secures it.
#[derive(Debug, Clone, PartialEq)]
pub struct Secured {
    /// The document with `proof` added.
    pub document: Value,
    /// The proof alone.
    pub proof: Value,
}

/// Build the proof configuration and the hash data for `document`. The
/// document must not already carry a proof, and every number in it must survive
/// RFC 8785 exactly. Nothing is signed; a refusal here means nothing ever will
/// be.
pub fn prepare_document(
    document: &Value,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Result<DocumentSigningInput, FormatRefusal> {
    if document.get("proof").is_some() {
        return Err(FormatRefusal::ProofPresent);
    }
    check_i_json(document).map_err(|_| FormatRefusal::DocumentInvalid("notCanonicalizable"))?;
    let config = document_proof_config(
        document,
        verification_method,
        proof_purpose,
        created,
        challenge,
        domain,
    );
    let hash_data = eddsa_jcs_2022_hash_data(document, &config)
        .map_err(|_| FormatRefusal::DocumentInvalid("notCanonicalizable"))?;
    Ok(DocumentSigningInput {
        document: document.clone(),
        config,
        hash_data,
    })
}

/// The secured document: `input`'s document with the proof `signature` makes.
///
/// Takes the input by value: the document it holds becomes the secured one,
/// so a document is copied once between preparing and finishing, not twice.
pub fn finish_document(input: DocumentSigningInput, signature: &[u8]) -> Secured {
    let DocumentSigningInput {
        mut document,
        config,
        ..
    } = input;
    let proof = finish_proof(config, signature);
    document["proof"] = proof.clone();
    Secured { document, proof }
}

/// An `eddsa-jcs-2022` proof over `document` by `signer`, which must sign with
/// Ed25519.
pub fn sign_document(
    signer: &dyn Signer,
    document: &Value,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Result<Secured, SignError> {
    if signer.algorithm() != Algorithm::EdDsa {
        return Err(SignError::Algorithm {
            expected: Algorithm::EdDsa,
            got: signer.algorithm(),
        });
    }
    let input = prepare_document(
        document,
        verification_method,
        proof_purpose,
        created,
        challenge,
        domain,
    )?;
    let signature = signer.sign(input.bytes())?;
    Ok(finish_document(input, &signature))
}

/// Verify the `eddsa-jcs-2022` proof of `secured` against `key`.
///
/// The hash data is built from every member of the proof except `proofValue`,
/// `challenge` and `domain` included: a proof bound to a challenge must not
/// verify as one that is not.
pub fn verify_document(secured: &Value, key: &PublicKey) -> Result<(), VerifyError> {
    let malformed = |m: &str| VerifyError::Malformed(m.to_string());
    let Some(Value::Object(proof)) = secured.get("proof") else {
        return Err(malformed("the document has no single proof object"));
    };
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
        return Err(malformed("the proof is not a Data Integrity proof"));
    }
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
        return Err(malformed("the proof is not an eddsa-jcs-2022 proof"));
    }
    if key.algorithm() != Algorithm::EdDsa {
        return Err(VerifyError::Algorithm {
            expected: Algorithm::EdDsa,
            got: key.algorithm().jose_name().to_string(),
        });
    }
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("the proof has no proofValue"))?;
    // eddsa-jcs-2022 carries the signature as base58btc (`z`), and only that:
    // a proof whose value is the same bytes in another base is not one.
    let (base, signature) =
        multibase::decode(proof_value).map_err(|_| malformed("the proofValue is not multibase"))?;
    if base != multibase::Base::Base58Btc {
        return Err(malformed("the proofValue is not base58btc multibase"));
    }
    let mut options = proof.clone();
    options.remove("proofValue");
    let mut unsecured = secured.clone();
    if let Some(members) = unsecured.as_object_mut() {
        members.remove("proof");
    }
    let hash_data = eddsa_jcs_2022_hash_data(&unsecured, &Value::Object(options))
        .map_err(|_| malformed("the document cannot be canonicalised"))?;
    key.verify(&hash_data, &signature)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::SigningSecret;

    const VM: &str = "did:key:z6MkExample#z6MkExample";

    fn document() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:z6MkExample",
            "credentialSubject": { "id": "did:example:agent" }
        })
    }

    fn sign(secret: &SigningSecret) -> Secured {
        sign_document(
            secret,
            &document(),
            VM,
            "assertionMethod",
            "2026-11-11T00:00:00Z",
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn the_proof_configuration_carries_what_the_cryptosuite_signs_over() {
        let config = document_proof_config(
            &document(),
            VM,
            "assertionMethod",
            "2026-11-11T00:00:00Z",
            Some("c"),
            Some("d"),
        );

        assert_eq!(
            config,
            json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2026-11-11T00:00:00Z",
                "verificationMethod": VM,
                "proofPurpose": "assertionMethod",
                "challenge": "c",
                "domain": "d"
            })
        );
        let bare = document_proof_config(&json!({"a": 1}), VM, "authentication", "t", None, None);
        assert!(
            bare.get("@context").is_none()
                && bare.get("challenge").is_none()
                && bare.get("domain").is_none()
        );
    }

    #[test]
    fn the_hash_data_is_the_two_digests_in_the_order_the_cryptosuite_defines() {
        let document = json!({"b": 1, "a": 2});
        let config = json!({"z": 1});

        let hash_data = eddsa_jcs_2022_hash_data(&document, &config).unwrap();

        assert_eq!(&hash_data[..32], Sha256::digest(br#"{"z":1}"#).as_slice());
        assert_eq!(
            &hash_data[32..],
            Sha256::digest(br#"{"a":2,"b":1}"#).as_slice()
        );
    }

    #[test]
    fn a_signed_document_verifies_and_carries_a_multibase_proof_value() {
        let secret = SigningSecret::ed25519([4; 32]);

        let secured = sign(&secret);

        assert_eq!(secured.document["proof"], secured.proof);
        assert!(
            secured.proof["proofValue"]
                .as_str()
                .unwrap()
                .starts_with('z')
        );
        assert_eq!(
            verify_document(&secured.document, &secret.public_key()),
            Ok(())
        );
    }

    #[test]
    fn making_the_signature_yourself_gives_the_same_proof_as_signing_in_one_call() {
        let secret = SigningSecret::ed25519([4; 32]);

        let input = prepare_document(
            &document(),
            VM,
            "assertionMethod",
            "2026-11-11T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let in_phases = {
            let signature = secret.sign_message(input.bytes());
            finish_document(input, &signature)
        };

        assert_eq!(in_phases, sign(&secret));
        assert_eq!(
            sign(&secret),
            sign(&secret),
            "the same inputs make the same proof"
        );
    }

    #[test]
    fn a_proof_does_not_verify_after_the_document_or_the_proof_changes_or_under_another_key() {
        let secret = SigningSecret::ed25519([4; 32]);
        let secured = sign(&secret).document;

        let mut tampered_document = secured.clone();
        tampered_document["credentialSubject"]["id"] = "did:example:other".into();
        let mut tampered_proof = secured.clone();
        tampered_proof["proof"]["created"] = "2026-11-12T00:00:00Z".into();

        for tampered in [tampered_document, tampered_proof] {
            assert_eq!(
                verify_document(&tampered, &secret.public_key()),
                Err(VerifyError::Signature)
            );
        }
        assert_eq!(
            verify_document(&secured, &SigningSecret::ed25519([5; 32]).public_key()),
            Err(VerifyError::Signature)
        );
    }

    /// A proof bound to a challenge and a domain verifies only with them: both
    /// are part of the signed configuration.
    #[test]
    fn a_challenge_and_a_domain_are_signed_and_cannot_be_dropped_or_swapped() {
        let secret = SigningSecret::ed25519([4; 32]);
        let secured = sign_document(
            &secret,
            &document(),
            VM,
            "authentication",
            "2026-11-11T00:00:00Z",
            Some("nonce-1"),
            Some("example.com"),
        )
        .unwrap()
        .document;
        assert_eq!(verify_document(&secured, &secret.public_key()), Ok(()));

        for edit in [
            |p: &mut Value| {
                p.as_object_mut().unwrap().remove("challenge");
            },
            |p: &mut Value| {
                p["challenge"] = "nonce-2".into();
            },
            |p: &mut Value| {
                p.as_object_mut().unwrap().remove("domain");
            },
            |p: &mut Value| {
                p["domain"] = "evil.example".into();
            },
        ] {
            let mut changed = secured.clone();
            edit(&mut changed["proof"]);
            assert_eq!(
                verify_document(&changed, &secret.public_key()),
                Err(VerifyError::Signature)
            );
        }
    }

    #[test]
    fn a_document_that_already_carries_a_proof_is_refused() {
        let mut signed = document();
        signed["proof"] = json!({});

        assert_eq!(
            prepare_document(&signed, VM, "assertionMethod", "t", None, None),
            Err(FormatRefusal::ProofPresent)
        );
    }

    #[test]
    fn a_number_a_double_cannot_hold_is_refused_rather_than_signed_as_another_value() {
        let big = json!({"issuer": "did:key:z6MkExample", "n": 9_007_199_254_740_993u64});

        assert_eq!(
            prepare_document(&big, VM, "assertionMethod", "t", None, None),
            Err(FormatRefusal::DocumentInvalid("notCanonicalizable"))
        );
    }

    #[test]
    fn only_an_ed25519_key_makes_this_proof() {
        let p256 = SigningSecret::p256_from_slice(&[5; 32]).unwrap();

        assert_eq!(
            sign_document(&p256, &document(), VM, "assertionMethod", "t", None, None),
            Err(SignError::Algorithm {
                expected: Algorithm::EdDsa,
                got: Algorithm::Es256
            })
        );
        assert!(matches!(
            verify_document(
                &sign(&SigningSecret::ed25519([4; 32])).document,
                &p256.public_key()
            ),
            Err(VerifyError::Algorithm { .. })
        ));
    }

    #[test]
    fn a_document_without_a_usable_proof_is_malformed_not_unverified() {
        let key = SigningSecret::ed25519([4; 32]).public_key();
        let mut other_suite = sign(&SigningSecret::ed25519([4; 32])).document;
        other_suite["proof"]["cryptosuite"] = "ecdsa-jcs-2019".into();

        for bad in [document(), json!({"proof": []}), other_suite] {
            assert!(
                matches!(verify_document(&bad, &key), Err(VerifyError::Malformed(_))),
                "{bad}"
            );
        }
    }

    /// eddsa-jcs-2022 carries `proofValue` as base58btc; the same signature
    /// in another multibase base is malformed, not a proof.
    #[test]
    fn a_proof_value_in_another_base_is_malformed() {
        let secret = SigningSecret::ed25519([4; 32]);
        let mut secured = sign(&secret).document;
        let (_, signature) =
            multibase::decode(secured["proof"]["proofValue"].as_str().unwrap()).unwrap();
        for base in [multibase::Base::Base64, multibase::Base::Base16Lower] {
            secured["proof"]["proofValue"] = multibase::encode(base, &signature).into();
            assert!(
                matches!(
                    verify_document(&secured, &secret.public_key()),
                    Err(VerifyError::Malformed(_))
                ),
                "{base:?}"
            );
        }
    }
}
