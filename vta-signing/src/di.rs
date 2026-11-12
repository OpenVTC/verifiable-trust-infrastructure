//! `keys/sign-document/0.1`: an `eddsa-jcs-2022` Data Integrity proof over a
//! JSON document.
//!
//! The signer builds the proof configuration and the hash data itself, so the
//! 64 bytes it signs are two SHA-256 digests the cryptosuite defines as its
//! own domain separation, never bytes a caller chose.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, check_i_json};
use crate::{Algorithm, FormatRefusal, SigningSecret};

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

/// A document and the proof that secures it.
#[derive(Debug, Clone, PartialEq)]
pub struct Secured {
    /// The document with `proof` added.
    pub document: Value,
    /// The proof alone.
    pub proof: Value,
}

/// An `eddsa-jcs-2022` proof over `document` by `secret`, which must be an
/// Ed25519 key. The document must not already carry a proof, and every number
/// in it must survive RFC 8785 exactly.
pub fn sign_eddsa_jcs_2022(
    secret: &SigningSecret,
    document: &Value,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Result<Secured, FormatRefusal> {
    if secret.algorithm() != Algorithm::EdDsa {
        return Err(FormatRefusal::InvalidArgument(
            "eddsa-jcs-2022 needs an Ed25519 key".into(),
        ));
    }
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
    let proof = finish_proof(config, &secret.sign(&hash_data));
    let mut document = document.clone();
    document["proof"] = proof.clone();
    Ok(Secured { document, proof })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as _;
    use serde_json::json;

    use super::*;

    const VM: &str = "did:key:z6MkExample#z6MkExample";

    fn document() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:z6MkExample",
            "credentialSubject": { "id": "did:example:agent" }
        })
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
    fn a_signed_document_verifies_over_its_own_hash_data() {
        let secret = SigningSecret::ed25519([4; 32]);

        let secured = sign_eddsa_jcs_2022(
            &secret,
            &document(),
            VM,
            "assertionMethod",
            "2026-11-11T00:00:00Z",
            None,
            None,
        )
        .unwrap();

        assert_eq!(secured.document["proof"], secured.proof);
        let mut config = secured.proof.clone();
        let proof_value = config
            .as_object_mut()
            .unwrap()
            .remove("proofValue")
            .unwrap();
        let hash_data = eddsa_jcs_2022_hash_data(&document(), &config).unwrap();
        let (_, signature) = multibase::decode(proof_value.as_str().unwrap()).unwrap();
        let public: [u8; 32] = secret.public_key().try_into().unwrap();
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify(
                    &hash_data,
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap()
                )
                .is_ok()
        );
        assert!(
            proof_value.as_str().unwrap().starts_with('z'),
            "multibase base58btc"
        );
    }

    #[test]
    fn a_document_that_already_carries_a_proof_is_refused() {
        let mut signed = document();
        signed["proof"] = json!({});

        assert_eq!(
            sign_eddsa_jcs_2022(
                &SigningSecret::ed25519([4; 32]),
                &signed,
                VM,
                "assertionMethod",
                "t",
                None,
                None
            ),
            Err(FormatRefusal::ProofPresent)
        );
    }

    #[test]
    fn a_number_a_double_cannot_hold_is_refused_rather_than_signed_as_another_value() {
        let big = json!({"issuer": "did:key:z6MkExample", "n": 9_007_199_254_740_993u64});

        assert_eq!(
            sign_eddsa_jcs_2022(
                &SigningSecret::ed25519([4; 32]),
                &big,
                VM,
                "assertionMethod",
                "t",
                None,
                None
            ),
            Err(FormatRefusal::DocumentInvalid("notCanonicalizable"))
        );
    }

    #[test]
    fn only_an_ed25519_key_makes_this_proof() {
        let p256 = SigningSecret::p256_from_slice(&[5; 32]).unwrap();

        assert!(matches!(
            sign_eddsa_jcs_2022(&p256, &document(), VM, "assertionMethod", "t", None, None),
            Err(FormatRefusal::InvalidArgument(_))
        ));
    }

    #[test]
    fn the_same_inputs_make_the_same_proof() {
        let secret = SigningSecret::ed25519([4; 32]);
        let make = || {
            sign_eddsa_jcs_2022(&secret, &document(), VM, "assertionMethod", "t", None, None)
                .unwrap()
        };

        assert_eq!(make(), make());
    }
}
