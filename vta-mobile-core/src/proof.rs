//! Shared Data Integrity proof construction **and verification** for
//! DID-signed Trust Tasks.
//!
//! Construction: the holder key never enters Rust — `affinidi-data-integrity`'s
//! `prepare_sign_input` does the `eddsa-jcs-2022` canonicalization, the native
//! [`Signer`] signs the result, and we assemble the proof. Used by the step-up
//! DID-signed gate ([`crate::stepup`]) and VTA `authenticate` ([`crate::session`]).
//!
//! Verification: [`verify_signed_request`] is the gate every inbound approval
//! request passes before its content may be shown to the operator (the
//! task-consent request in [`crate::consent`], the step-up approve-request in
//! [`crate::task`]). Any failure is [`FfiError::UntrustedIssuer`] — the typed
//! "do not prompt" refusal.

use std::sync::Arc;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions, prepare_sign_input};
use multibase::Base;
use serde::Serialize;
use trust_tasks_proof::affinidi::CachedDidResolver;
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
    // `DataIntegrityProof` is `#[non_exhaustive]` as of affinidi-data-integrity
    // 0.7.6 — build via `new` (the in-process `sign` would require the holder
    // key in Rust, which this flow deliberately avoids). `proof_value` is filled
    // in below after the native signer produces the signature.
    let mut proof_config = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        did_key_vm(&signer.did())?,
        "assertionMethod".to_string(),
        None,
        Some(created.to_string()),
        None,
    );

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

/// Verify the `eddsa-jcs-2022` Data Integrity proof on an inbound approval
/// request and return the **proven** issuer DID.
///
/// This is the consumer side of the spec's `untrusted_issuer` rule (task-consent
/// request 0.1, consumer rule 1): *"Verify the `proof` and that the `issuer` is
/// an executor it is enrolled with. An unverifiable request → `untrusted_issuer`;
/// the device MUST NOT prompt."* Every failure maps to
/// [`FfiError::UntrustedIssuer`] so the native layer has exactly one variant
/// meaning "drop this, never prompt".
///
/// Enforced, in order:
/// 1. the document carries an `issuer` and a `proof`;
/// 2. the proof is a Data Integrity proof with `proofPurpose:assertionMethod`;
/// 3. the DID of `proof.verificationMethod` **is** the document `issuer` (a
///    valid signature only proves *some* key signed; authenticity additionally
///    requires that key to be the declared issuer's);
/// 4. the issuer is in `trusted_issuers` — the enrolled-executor allowlist the
///    native layer holds (the enrolled VTA DID plus any granted executor DIDs).
///    Checked **before** any DID resolution so the device never performs
///    network I/O on behalf of a DID it is not enrolled with;
/// 5. the signature verifies (`eddsa-jcs-2022` only) against key material
///    resolved from the issuer's DID document, via the crate's shared resolver
///    cache (`did:key` offline; `did:web` / `did:webvh` over the network).
///
/// Verification runs over the **raw** JSON document (`proof` removed), not a
/// typed round-trip — so it is byte-faithful to what the executor signed, extra
/// wire fields included.
pub(crate) async fn verify_signed_request(
    raw: &serde_json::Value,
    trusted_issuers: &[String],
) -> Result<String, FfiError> {
    let refuse = |reason: String| FfiError::UntrustedIssuer { reason };

    let issuer = raw
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| refuse("request carries no issuer to bind the proof to".into()))?;

    let proof_value = raw
        .get("proof")
        .ok_or_else(|| refuse("request carries no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| refuse(format!("proof is not a Data Integrity proof: {e}")))?;

    if proof.proof_purpose != "assertionMethod" {
        return Err(refuse(format!(
            "proof purpose is `{}`, not `assertionMethod`",
            proof.proof_purpose
        )));
    }

    let vm_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default();
    if vm_did.is_empty() || vm_did != issuer {
        return Err(refuse(format!(
            "proof verificationMethod is controlled by `{vm_did}`, not the document issuer `{issuer}`"
        )));
    }

    if !trusted_issuers.iter().any(|t| t == issuer) {
        return Err(refuse(format!(
            "issuer {issuer} is not an executor this device is enrolled with"
        )));
    }

    // eddsa-jcs-2022 verifies the document with the proof member removed.
    let mut unsigned = raw.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }

    let resolver = CachedDidResolver::new(Arc::new(crate::resolver::client().await?.clone()));
    proof
        .verify(
            &unsigned,
            &resolver,
            VerifyOptions::new().with_allowed_suites(vec![CryptoSuite::EddsaJcs2022]),
        )
        .await
        .map_err(|e| refuse(format!("proof verification failed: {e}")))?;

    Ok(issuer.to_string())
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

/// Deterministic executor keys + the production sign path, for the request
/// verification tests in [`crate::consent`] and [`crate::task`]. Mirrors the
/// VTA's `mint_signed_requests` (`vta-service` `consent_request.rs`): sign the
/// proofless document with `eddsa-jcs-2022` / `assertionMethod`, attach the
/// proof. `did:key` issuers resolve offline, so the tests exercise the full
/// verify path without touching the network.
#[cfg(test)]
pub(crate) mod test_support {
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use ed25519_dalek::SigningKey;

    /// The `did:key` of the deterministic Ed25519 key seeded from `seed`.
    pub(crate) fn did_for(seed: u8) -> String {
        affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn secret_for(seed: u8) -> affinidi_secrets_resolver::secrets::Secret {
        let did = did_for(seed);
        let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
        affinidi_secrets_resolver::secrets::Secret::generate_ed25519(Some(&vm), Some(&[seed; 32]))
    }

    /// Sign `doc` (which must not yet carry a proof) as the `seed` executor and
    /// attach the proof, exactly as the VTA signs an outbound request.
    pub(crate) async fn sign_as(doc: &mut serde_json::Value, seed: u8) {
        let proof = DataIntegrityProof::sign(
            &*doc,
            &secret_for(seed),
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("test signing cannot fail");
        doc["proof"] = serde_json::to_value(&proof).expect("proof serializes");
    }
}
