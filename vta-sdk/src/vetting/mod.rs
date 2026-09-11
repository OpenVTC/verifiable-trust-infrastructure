//! Building, signing and verifying the peer-vetting artifacts (feature
//! `vetting`).
//!
//! The wire shapes live in [`crate::protocols::vetting`]; this module is what
//! gives them meaning:
//!
//! - [`card`] — the Vetting Card an applicant signs for one vetter, and the
//!   verification a vetter's client runs before showing it.
//! - [`statement`] — the Vetting Statement (a DTG `EndorsementCredential`) a
//!   vetter signs, and its verification.
//! - [`requirements`] — the `requirementsDigest`, and the evaluation of a set
//!   of statements against a community's [`VettingRequirements`]. The applicant's
//!   client uses it to show progress; the community uses the same counting to
//!   build the facts its policy decides on.
//! - [`match_code`] — the code two people read to each other to confirm they
//!   are in the same session.
//!
//! Every verification returns a distinct `Verified*` type (workspace typestate
//! rule): code that needs a verified card or statement cannot be handed an
//! unverified one.
//!
//! [`VettingRequirements`]: crate::protocols::vetting::VettingRequirements

pub mod card;
pub mod match_code;
pub mod requirements;
pub mod statement;

use affinidi_data_integrity::DataIntegrityProof;
use serde_json::Value;

use crate::trust_task_proof::TrustTaskVmResolver;

/// Why building or verifying a vetting artifact failed.
///
/// [`Display`](std::fmt::Display) is safe to show a counterparty; verifier
/// internals are only reachable through [`VettingError::cause`], in the same
/// way as [`crate::trust_task_proof::DiProofError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VettingError {
    /// The artifact does not parse as its type.
    #[error("malformed {what}")]
    Malformed {
        /// Which artifact.
        what: &'static str,
        /// Parser detail, for the log.
        detail: String,
    },
    /// A binding member does not match what the verifier expects.
    #[error("{0} does not match this session")]
    Binding(&'static str),
    /// Outside the validity window.
    #[error("{0} is outside its validity window")]
    Expired(&'static str),
    /// Signed by (or to be signed by) someone other than the named party.
    #[error("{what} is not signed by its {role}")]
    WrongSigner {
        /// Which artifact.
        what: &'static str,
        /// `publisher` or `issuer`.
        role: &'static str,
    },
    /// No proof, or the proof does not verify.
    #[error("{what} proof verification failed")]
    Proof {
        /// Which artifact.
        what: &'static str,
        /// Verifier detail, for the log.
        detail: String,
    },
    /// The identity commitment does not recompute from the card.
    #[error("identity commitment does not recompute from the card")]
    Commitment,
    /// A required claim is absent.
    #[error("required claim `{0}` is missing")]
    MissingClaim(String),
    /// Signing failed.
    #[error("signing failed")]
    Sign(String),
    /// Digest computation failed.
    #[error("digest computation failed")]
    Digest(String),
    /// Randomness was unavailable.
    #[error("no randomness available")]
    Random(String),
}

impl VettingError {
    /// Underlying detail for the operator's log. Never put this on the wire.
    #[must_use]
    pub fn cause(&self) -> Option<&str> {
        match self {
            Self::Malformed { detail, .. }
            | Self::Proof { detail, .. }
            | Self::Sign(detail)
            | Self::Digest(detail)
            | Self::Random(detail) => Some(detail),
            _ => None,
        }
    }
}

/// The DID before `#` in a verification method or secret id.
pub(crate) fn did_of(vm: &str) -> &str {
    vm.split('#').next().unwrap_or_default()
}

/// Verify the Data Integrity proof on `signed` and return the proof's signer
/// DID, which the caller binds to the party the artifact names.
pub(crate) async fn verify_attached_proof(
    what: &'static str,
    signed: &Value,
    expected_purpose: &str,
    resolver: &TrustTaskVmResolver,
) -> Result<String, VettingError> {
    let proof_value = signed.get("proof").ok_or(VettingError::Proof {
        what,
        detail: "no proof".into(),
    })?;
    let proof: DataIntegrityProof =
        serde_json::from_value(proof_value.clone()).map_err(|e| VettingError::Proof {
            what,
            detail: format!("not a Data Integrity proof: {e}"),
        })?;
    if proof.proof_purpose != expected_purpose {
        return Err(VettingError::Proof {
            what,
            detail: format!(
                "proofPurpose `{}`, expected `{expected_purpose}`",
                proof.proof_purpose
            ),
        });
    }
    let mut unsigned = signed.clone();
    if let Some(map) = unsigned.as_object_mut() {
        map.remove("proof");
    }
    proof
        .verify(
            &unsigned,
            resolver,
            affinidi_data_integrity::VerifyOptions::new(),
        )
        .await
        .map_err(|e| VettingError::Proof {
            what,
            detail: e.to_string(),
        })?;
    Ok(did_of(&proof.verification_method).to_string())
}

/// `digestMultibase` per DTG Credentials §Digest Encoding (JCS without the
/// top-level `proof`, SHA-256 multihash, base58btc).
pub(crate) fn digest(value: &Value) -> Result<String, VettingError> {
    dtg_credentials::digest_multibase_json(value).map_err(|e| VettingError::Digest(e.to_string()))
}

#[cfg(test)]
pub(crate) mod test_support {
    use affinidi_secrets_resolver::secrets::Secret;

    /// A `did:key` Ed25519 secret from a fixed seed, `id` = `<did>#<multibase>`.
    pub fn secret(seed_byte: u8) -> Secret {
        let seed = [seed_byte; 32];
        let mut secret = Secret::generate_ed25519(None, Some(&seed));
        let public = secret.get_public_keymultibase().unwrap();
        secret.id = format!("did:key:{public}#{public}");
        secret
    }

    pub fn did(secret: &Secret) -> String {
        super::did_of(&secret.id).to_string()
    }
}
