//! Shared Data Integrity proof construction for DID-signed Trust Tasks.
//!
//! The holder key never enters Rust: `affinidi-data-integrity`'s
//! `prepare_sign_input` does the `eddsa-jcs-2022` canonicalization, the native
//! [`Signer`] signs the result, and we assemble the proof. Used by the step-up
//! DID-signed gate ([`crate::stepup`]) and VTA `authenticate` ([`crate::session`]).

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
use multibase::Base;
use serde::Serialize;
use trust_tasks_rs::{Proof, TrustTask};

use crate::error::FfiError;
use crate::keys::Signer;

/// Build an `eddsa-jcs-2022` Data Integrity proof over `doc` (which MUST NOT yet
/// carry a proof), signed via the native `signer`, and attach it. `created` is
/// an RFC 3339 timestamp.
pub(crate) fn attach_did_signed_proof<P: Serialize>(
    doc: &mut TrustTask<P>,
    signer: &dyn Signer,
    created: &str,
) -> Result<(), FfiError> {
    let mut proof_config = DataIntegrityProof {
        type_: "DataIntegrityProof".to_string(),
        cryptosuite: CryptoSuite::EddsaJcs2022,
        created: Some(created.to_string()),
        verification_method: did_key_vm(&signer.did())?,
        proof_purpose: "assertionMethod".to_string(),
        proof_value: None,
        context: None,
    };

    // Library does eddsa-jcs-2022 canonicalization + hashing of (document, proof
    // config); the native enclave signs the result.
    let signing_input = prepare_sign_input(&*doc, &proof_config, CryptoSuite::EddsaJcs2022)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("failed to canonicalize for signing: {e}"),
        })?;
    let signature = signer.sign(signing_input)?;
    proof_config.proof_value = Some(multibase::encode(Base::Base58Btc, signature));

    let proof_json = serde_json::to_value(&proof_config).map_err(|e| FfiError::InvalidInput {
        reason: format!("proof serialize: {e}"),
    })?;
    doc.proof =
        Some(
            serde_json::from_value::<Proof>(proof_json).map_err(|e| FfiError::InvalidInput {
                reason: format!("proof shape: {e}"),
            })?,
        );
    Ok(())
}

/// Derive the verification-method URI for a `did:key` holder. The mobile holder
/// key is a `did:key`, whose verification method is `<did>#<method-specific-id>`.
pub(crate) fn did_key_vm(did: &str) -> Result<String, FfiError> {
    let suffix = did
        .strip_prefix("did:key:")
        .ok_or_else(|| FfiError::InvalidInput {
            reason: format!("the DID-signed gate requires a did:key holder; got {did}"),
        })?;
    Ok(format!("{did}#{suffix}"))
}
